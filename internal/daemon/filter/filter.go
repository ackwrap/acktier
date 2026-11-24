package filter

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/acktier/acktier/internal/daemon/pktutil"
	"github.com/acktier/acktier/pkg/types"
)

const (
	conntrackTTL        = 3 * time.Minute
	maxConntrackEntries = 8192
)

type flowKey struct {
	proto   uint8
	srcIP   netip.Addr
	srcPort uint16
	dstIP   netip.Addr
	dstPort uint16
}

// Engine enforces compiled NetMap ACL FilterRules with stateful return-traffic connection tracking.
type Engine struct {
	mu      sync.RWMutex
	rules   []types.FilterRule
	ctMu    sync.Mutex
	flows   map[flowKey]time.Time

	droppedIn  atomic.Uint64
	droppedOut atomic.Uint64
}

func New() *Engine {
	return &Engine{
		flows: make(map[flowKey]time.Time),
	}
}

func (f *Engine) SetRules(rules []types.FilterRule) {
	cp := make([]types.FilterRule, len(rules))
	copy(cp, rules)
	f.mu.Lock()
	f.rules = cp
	f.mu.Unlock()
}

func (f *Engine) Stats() (activeRules int, droppedInbound, droppedOutbound uint64) {
	f.mu.RLock()
	activeRules = len(f.rules)
	f.mu.RUnlock()
	return activeRules, f.droppedIn.Load(), f.droppedOut.Load()
}

// AllowOutbound checks whether an outbound L3 packet is permitted and records reverse conntrack state.
func (f *Engine) AllowOutbound(raw []byte) bool {
	f.mu.RLock()
	rules := f.rules
	f.mu.RUnlock()
	if len(rules) == 0 {
		return true
	}

	pkt, err := pktutil.Parse(raw)
	if err != nil {
		f.droppedOut.Add(1)
		return false
	}

	if f.matchConntrack(pkt, false) {
		return true
	}
	if evalRules(rules, pkt) {
		f.recordReverseConntrack(pkt)
		return true
	}
	f.droppedOut.Add(1)
	return false
}

// AllowInbound checks whether an inbound decrypted L3 packet matches an established conntrack flow or an explicit accept ACL rule.
func (f *Engine) AllowInbound(raw []byte) bool {
	f.mu.RLock()
	rules := f.rules
	f.mu.RUnlock()
	if len(rules) == 0 {
		return true
	}

	pkt, err := pktutil.Parse(raw)
	if err != nil {
		f.droppedIn.Add(1)
		return false
	}

	if f.matchConntrack(pkt, true) {
		return true
	}
	if evalRules(rules, pkt) {
		f.recordReverseConntrack(pkt)
		return true
	}
	f.droppedIn.Add(1)
	return false
}

func (f *Engine) matchConntrack(pkt pktutil.ParsedPacket, isInbound bool) bool {
	key, ok := buildLookupKey(pkt, isInbound)
	if !ok {
		return false
	}
	now := time.Now()
	f.ctMu.Lock()
	defer f.ctMu.Unlock()
	exp, exists := f.flows[key]
	if !exists {
		return false
	}
	if now.After(exp) {
		delete(f.flows, key)
		return false
	}
	f.flows[key] = now.Add(conntrackTTL)
	return true
}

func (f *Engine) recordReverseConntrack(pkt pktutil.ParsedPacket) {
	revKey, ok := buildReverseKey(pkt)
	if !ok {
		return
	}
	now := time.Now()
	f.ctMu.Lock()
	defer f.ctMu.Unlock()
	if len(f.flows) >= maxConntrackEntries {
		for k, exp := range f.flows {
			if now.After(exp) || len(f.flows) >= maxConntrackEntries {
				delete(f.flows, k)
				if len(f.flows) < maxConntrackEntries*3/4 {
					break
				}
			}
		}
	}
	f.flows[revKey] = now.Add(conntrackTTL)
}

func buildReverseKey(pkt pktutil.ParsedPacket) (flowKey, bool) {
	switch pkt.Proto {
	case pktutil.ProtoTCP, pktutil.ProtoUDP:
		return flowKey{
			proto:   pkt.Proto,
			srcIP:   pkt.DstIP,
			srcPort: pkt.DstPort,
			dstIP:   pkt.SrcIP,
			dstPort: pkt.SrcPort,
		}, true
	case pktutil.ProtoICMPv4:
		if pkt.ICMPType == 8 { // Echo Request -> expect Echo Reply (type 0)
			return flowKey{proto: pkt.Proto, srcIP: pkt.DstIP, srcPort: pkt.ICMPID, dstIP: pkt.SrcIP, dstPort: 0}, true
		}
	case pktutil.ProtoICMPv6:
		if pkt.ICMPType == 128 {
			return flowKey{proto: pkt.Proto, srcIP: pkt.DstIP, srcPort: pkt.ICMPID, dstIP: pkt.SrcIP, dstPort: 0}, true
		}
	}
	return flowKey{}, false
}

func buildLookupKey(pkt pktutil.ParsedPacket, _ bool) (flowKey, bool) {
	switch pkt.Proto {
	case pktutil.ProtoTCP, pktutil.ProtoUDP:
		return flowKey{
			proto:   pkt.Proto,
			srcIP:   pkt.SrcIP,
			srcPort: pkt.SrcPort,
			dstIP:   pkt.DstIP,
			dstPort: pkt.DstPort,
		}, true
	case pktutil.ProtoICMPv4:
		if pkt.ICMPType == 0 { // Echo Reply
			return flowKey{proto: pkt.Proto, srcIP: pkt.SrcIP, srcPort: pkt.ICMPID, dstIP: pkt.DstIP, dstPort: 0}, true
		}
	case pktutil.ProtoICMPv6:
		if pkt.ICMPType == 129 { // Echo Reply v6
			return flowKey{proto: pkt.Proto, srcIP: pkt.SrcIP, srcPort: pkt.ICMPID, dstIP: pkt.DstIP, dstPort: 0}, true
		}
	}
	return flowKey{}, false
}

func evalRules(rules []types.FilterRule, pkt pktutil.ParsedPacket) bool {
	for _, r := range rules {
		if r.IPProto != 0 && r.IPProto != pkt.Proto {
			continue
		}
		if !prefixSliceContains(r.SrcPrefixes, pkt.SrcIP) || !prefixSliceContains(r.DstPrefixes, pkt.DstIP) {
			continue
		}
		if (pkt.Proto == pktutil.ProtoTCP || pkt.Proto == pktutil.ProtoUDP) && (r.DstPortStart != 0 || r.DstPortEnd != 0) {
			if pkt.DstPort < r.DstPortStart || pkt.DstPort > r.DstPortEnd {
				continue
			}
		}
		return r.Action == types.FilterAccept
	}
	return false
}

func prefixSliceContains(pfxs []netip.Prefix, ip netip.Addr) bool {
	for _, p := range pfxs {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

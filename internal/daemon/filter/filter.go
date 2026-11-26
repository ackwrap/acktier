package filter

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ackwrap/acktier/internal/daemon/pktutil"
	"github.com/ackwrap/acktier/pkg/types"
)

const (
	conntrackTTL        = 3 * time.Minute
	maxConntrackEntries = 8192
)

type flowKey struct {
	inbound bool
	proto   uint8
	srcIP   netip.Addr
	srcPort uint16
	dstIP   netip.Addr
	dstPort uint16
}

type conntrackEntry struct {
	expiresAt time.Time
	origPkt   pktutil.ParsedPacket
}

// Engine enforces compiled NetMap ACL FilterRules with stateful return-traffic connection tracking
// and immediate conntrack re-validation whenever policies change.
type Engine struct {
	mu    sync.RWMutex
	rules []types.FilterRule
	flows map[flowKey]conntrackEntry

	droppedIn  atomic.Uint64
	droppedOut atomic.Uint64
}

func New() *Engine {
	return &Engine{
		flows: make(map[flowKey]conntrackEntry),
	}
}

// SetRules atomically replaces active FilterRules and immediately purges any established conntrack
// entries whose originating packet is no longer authorized by the updated policy!
func (f *Engine) SetRules(rules []types.FilterRule) {
	cp := make([]types.FilterRule, len(rules))
	copy(cp, rules)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules = cp
	if len(cp) == 0 {
		clear(f.flows)
		return
	}
	now := time.Now()
	for k, entry := range f.flows {
		if now.After(entry.expiresAt) || !evalRules(cp, entry.origPkt) {
			delete(f.flows, k)
		}
	}
}

// Reset flushes all rules and connection-tracking state (e.g. on `acktier down`).
func (f *Engine) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules = nil
	clear(f.flows)
}

// AllowsTuple checks whether a 5-tuple originating packet is permitted under current ACL rules
// (used to evict revoked Gateway NAT sessions upon live ACL updates).
func (f *Engine) AllowsTuple(srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16, proto uint8) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if len(f.rules) == 0 {
		return true
	}
	v := uint8(4)
	if srcIP.Is6() || dstIP.Is6() {
		v = 6
	}
	return evalRules(f.rules, pktutil.ParsedPacket{
		Version: v,
		Proto:   proto,
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
	})
}

func (f *Engine) Stats() (activeRules int, droppedInbound, droppedOutbound uint64) {
	f.mu.RLock()
	activeRules = len(f.rules)
	f.mu.RUnlock()
	return activeRules, f.droppedIn.Load(), f.droppedOut.Load()
}

// AllowOutbound checks whether an outbound L3 packet is well-formed, uses a supported L4 protocol,
// is permitted by ACLs, and records reverse conntrack state.
func (f *Engine) AllowOutbound(raw []byte) bool {
	if f.allowPacket(raw, false) {
		return true
	}
	f.droppedOut.Add(1)
	return false
}

// AllowInbound checks whether an inbound decrypted L3 packet is well-formed, uses a supported L4 protocol,
// and matches an established conntrack flow or an explicit accept ACL rule.
func (f *Engine) AllowInbound(raw []byte) bool {
	if f.allowPacket(raw, true) {
		return true
	}
	f.droppedIn.Add(1)
	return false
}

func (f *Engine) allowPacket(raw []byte, inbound bool) bool {
	// Parse even without ACLs so unsupported or fragmented packets still fail closed.
	pkt, err := pktutil.Parse(raw)
	if err != nil {
		return false
	}

	// Authorization and conntrack are one transaction: packets evaluated
	// before SetRules cannot repopulate entries after it has purged them.
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.rules) == 0 {
		return true
	}

	if f.matchConntrackLocked(pkt, inbound) {
		return true
	}
	if evalRules(f.rules, pkt) {
		f.recordReverseConntrackLocked(pkt, !inbound)
		return true
	}
	return false
}

func (f *Engine) matchConntrackLocked(pkt pktutil.ParsedPacket, inbound bool) bool {
	key, ok := buildLookupKey(pkt)
	if !ok {
		return false
	}
	key.inbound = inbound
	now := time.Now()
	entry, exists := f.flows[key]
	if !exists {
		return false
	}
	if now.After(entry.expiresAt) {
		delete(f.flows, key)
		return false
	}
	entry.expiresAt = now.Add(conntrackTTL)
	f.flows[key] = entry
	return true
}

func (f *Engine) recordReverseConntrackLocked(pkt pktutil.ParsedPacket, inbound bool) {
	revKey, ok := buildReverseKey(pkt)
	if !ok {
		return
	}
	revKey.inbound = inbound
	origMeta := pkt
	origMeta.Payload = nil // Do not retain packet payload buffer in conntrack!
	now := time.Now()
	if len(f.flows) >= maxConntrackEntries {
		for k, entry := range f.flows {
			if now.After(entry.expiresAt) || len(f.flows) >= maxConntrackEntries {
				delete(f.flows, k)
				if len(f.flows) < maxConntrackEntries*3/4 {
					break
				}
			}
		}
	}
	f.flows[revKey] = conntrackEntry{
		expiresAt: now.Add(conntrackTTL),
		origPkt:   origMeta,
	}
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

func buildLookupKey(pkt pktutil.ParsedPacket) (flowKey, bool) {
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

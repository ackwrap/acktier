package engine

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/acktier/acktier/internal/daemon/dns"
	"github.com/acktier/acktier/internal/daemon/pktutil"
	"github.com/acktier/acktier/internal/daemon/state"
	"github.com/acktier/acktier/pkg/types"
)

const (
	exitFlowTTL  = 3 * time.Minute
	maxExitFlows = 4096
)

type exitFlowKey struct {
	exitPeer types.PublicKey
	proto    uint8
	extIP    netip.Addr
	extPort  uint16
	locIP    netip.Addr
	locPort  uint16
}

type exitFlowTracker struct {
	mu    sync.Mutex
	flows map[exitFlowKey]time.Time
}

func newExitFlowTracker() *exitFlowTracker {
	return &exitFlowTracker{flows: make(map[exitFlowKey]time.Time)}
}

func (et *exitFlowTracker) Reset() {
	et.mu.Lock()
	et.flows = make(map[exitFlowKey]time.Time)
	et.mu.Unlock()
}

func (et *exitFlowTracker) RetainOnlyPeer(exitPeer types.PublicKey) {
	et.mu.Lock()
	for k := range et.flows {
		if k.exitPeer != exitPeer {
			delete(et.flows, k)
		}
	}
	et.mu.Unlock()
}

func (et *exitFlowTracker) RecordOutbound(exitPeer types.PublicKey, raw []byte) {
	pkt, err := pktutil.Parse(raw)
	if err != nil {
		return
	}
	var key exitFlowKey
	switch pkt.Proto {
	case pktutil.ProtoTCP, pktutil.ProtoUDP:
		key = exitFlowKey{
			exitPeer: exitPeer,
			proto:    pkt.Proto,
			extIP:    pkt.DstIP.Unmap(),
			extPort:  pkt.DstPort,
			locIP:    pkt.SrcIP.Unmap(),
			locPort:  pkt.SrcPort,
		}
	case pktutil.ProtoICMPv4:
		if pkt.ICMPType != 8 {
			return
		}
		key = exitFlowKey{
			exitPeer: exitPeer,
			proto:    pkt.Proto,
			extIP:    pkt.DstIP.Unmap(),
			extPort:  pkt.ICMPID,
			locIP:    pkt.SrcIP.Unmap(),
		}
	case pktutil.ProtoICMPv6:
		if pkt.ICMPType != 128 {
			return
		}
		key = exitFlowKey{
			exitPeer: exitPeer,
			proto:    pkt.Proto,
			extIP:    pkt.DstIP.Unmap(),
			extPort:  pkt.ICMPID,
			locIP:    pkt.SrcIP.Unmap(),
		}
	default:
		return
	}

	now := time.Now()
	et.mu.Lock()
	if len(et.flows) >= maxExitFlows {
		for k, exp := range et.flows {
			if now.After(exp) || len(et.flows) >= maxExitFlows {
				delete(et.flows, k)
				if len(et.flows) < maxExitFlows*3/4 {
					break
				}
			}
		}
	}
	et.flows[key] = now.Add(exitFlowTTL)
	et.mu.Unlock()
}

func (et *exitFlowTracker) MatchInbound(exitPeer types.PublicKey, pkt pktutil.ParsedPacket) bool {
	var key exitFlowKey
	switch pkt.Proto {
	case pktutil.ProtoTCP, pktutil.ProtoUDP:
		key = exitFlowKey{
			exitPeer: exitPeer,
			proto:    pkt.Proto,
			extIP:    pkt.SrcIP.Unmap(),
			extPort:  pkt.SrcPort,
			locIP:    pkt.DstIP.Unmap(),
			locPort:  pkt.DstPort,
		}
	case pktutil.ProtoICMPv4:
		if pkt.ICMPType != 0 {
			return false
		}
		key = exitFlowKey{
			exitPeer: exitPeer,
			proto:    pkt.Proto,
			extIP:    pkt.SrcIP.Unmap(),
			extPort:  pkt.ICMPID,
			locIP:    pkt.DstIP.Unmap(),
		}
	case pktutil.ProtoICMPv6:
		if pkt.ICMPType != 129 {
			return false
		}
		key = exitFlowKey{
			exitPeer: exitPeer,
			proto:    pkt.Proto,
			extIP:    pkt.SrcIP.Unmap(),
			extPort:  pkt.ICMPID,
			locIP:    pkt.DstIP.Unmap(),
		}
	default:
		return false
	}

	now := time.Now()
	et.mu.Lock()
	defer et.mu.Unlock()
	exp, ok := et.flows[key]
	if !ok {
		return false
	}
	if now.After(exp) {
		delete(et.flows, key)
		return false
	}
	et.flows[key] = now.Add(exitFlowTTL)
	return true
}

// SetExitNode dynamically switches or clears ("none" / "") the client's active global Exit Node.
func (e *Engine) SetExitNode(target string) error {
	e.sessionMu.Lock()
	defer e.sessionMu.Unlock()
	target = strings.TrimSpace(target)
	if strings.EqualFold(target, "none") || strings.EqualFold(target, "off") {
		target = ""
	}
	if err := e.stateMgr.Update(func(s *state.ConfigState) {
		s.ExitNode = target
	}); err != nil {
		return err
	}
	e.mu.RLock()
	nm := e.netMap
	e.mu.RUnlock()
	if nm.Self.ID != 0 && e.isRunning() {
		e.applyNetMap(nm, false)
	}
	if target != "" {
		e.mu.RLock()
		hasExit := e.exitNodePeer != nil
		e.mu.RUnlock()
		if !hasExit {
			return fmt.Errorf("peer %q not found or has no approved 0.0.0.0/0 exit route", target)
		}
	}
	return nil
}

func (e *Engine) isHostManagementOrLocalIP(dstIP netip.Addr) bool {
	ip := dstIP.Unmap()
	for _, lip := range localInterfaceIPs() {
		if lip == ip {
			return true
		}
	}
	if e.localAPIAddr != "" {
		if h, _, err := net.SplitHostPort(e.localAPIAddr); err == nil {
			if apiIP, pErr := netip.ParseAddr(h); pErr == nil && apiIP.Unmap() == ip {
				return true
			}
		}
	}
	e.mu.RLock()
	ctrlHost := e.activeControlHost
	e.mu.RUnlock()
	if ctrlHost != "" {
		if ctrlIP, pErr := netip.ParseAddr(ctrlHost); pErr == nil && ctrlIP.Unmap() == ip {
			return true
		}
	}
	return false
}

func (e *Engine) isSelfApprovedDestination(dst netip.Addr) bool {
	if types.IsOverlayAddr(dst) || types.IsSpecialNonRoutableAddr(dst) {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, pfx := range e.selfApprovedRoutes {
		if pfx.Contains(dst) {
			return true
		}
	}
	return false
}

// validateInboundPeerSource strictly separates destination routing from source-IP authorization:
//  1. Overlay IPs (100.64.0.0/10, fd7a:115c:a1e0::/48) are ONLY valid if they equal `pr`'s own assigned IPv4/IPv6.
//  2. Non-overlay subnet IPs are valid ONLY if covered by a non-default, non-overlay ApprovedRoute of `pr`.
//  3. External Internet source IPs via Exit Node are valid ONLY if `pr` is our actively selected Exit Node
//     AND the packet matches an established outbound flow tracked in `e.exitFlows`!
func (e *Engine) validateInboundPeerSource(pr *peerRuntime, plainIP []byte) (pktutil.ParsedPacket, bool) {
	var zero pktutil.ParsedPacket
	if pr == nil {
		return zero, false
	}
	pkt, err := pktutil.Parse(plainIP)
	if err != nil || !pkt.SrcIP.IsValid() || !pkt.DstIP.IsValid() {
		return zero, false
	}
	srcIP := pkt.SrcIP.Unmap()
	if types.IsSpecialNonRoutableAddr(srcIP) || srcIP == dns.MagicDNSIPv4 || srcIP == dns.MagicDNSIPv6 {
		return zero, false
	}

	pr.mu.RLock()
	peerKey := pr.meta.NodeKey
	peerV4 := pr.meta.IPv4
	peerV6 := pr.meta.IPv6
	subnets := pr.nonDefaultSubnets
	hasExitV4 := pr.hasExitV4
	hasExitV6 := pr.hasExitV6
	pr.mu.RUnlock()

	// Case 1: Overlay address space — ONLY the peer's exact assigned node IP is ever valid!
	if types.IsOverlayAddr(srcIP) {
		if srcIP == peerV4 || srcIP == peerV6 {
			return pkt, true
		}
		return zero, false
	}

	// Case 2: Approved non-default, non-overlay subnet route owned by `pr`
	for _, pfx := range subnets {
		if pfx.Contains(srcIP) {
			return pkt, true
		}
	}

	// Case 3: External Internet return traffic from the locally SELECTED Exit Node matching an outbound flow!
	e.mu.RLock()
	isSelectedExit := e.exitNodePeer == pr
	e.mu.RUnlock()
	if isSelectedExit && ((srcIP.Is4() && hasExitV4) || (srcIP.Is6() && hasExitV6)) {
		if e.exitFlows.MatchInbound(peerKey, pkt) {
			return pkt, true
		}
	}

	return zero, false
}

package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/acktier/acktier/internal/daemon/mesh"
	"github.com/acktier/acktier/internal/daemon/nat"
	"github.com/acktier/acktier/pkg/protocol"
	"github.com/acktier/acktier/pkg/types"
)

const centerRelayPenaltyMs = 6.0

type peerRuntime struct {
	mu                   sync.RWMutex
	meta                 types.PeerNode
	lastHandshake        time.Time
	lastPunch            time.Time
	lastDirectChallenge  time.Time
	lastInboundPingWin   time.Time
	inboundPingCount     int
	lastPeerRelayRx      time.Time
	lastRTTMicros        int64
	lastCenterRelayRTTUs int64
	hasExitV4            bool
	hasExitV6            bool
	nonDefaultSubnets    []netip.Prefix
	rxBytes              atomic.Uint64
	txBytes              atomic.Uint64
}

type routeEntry struct {
	prefix netip.Prefix
	peer   *peerRuntime
}

func (e *Engine) getPeerRuntime(key types.PublicKey) *peerRuntime {
	e.mu.RLock()
	pr := e.peersByKey[key]
	e.mu.RUnlock()
	return pr
}

// lookupPeerByDstIP resolves the target peer for outbound packet dst and reports whether it matched via Exit Node.
func (e *Engine) lookupPeerByDstIP(dst netip.Addr) (target *peerRuntime, viaExit bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if dst == e.netMap.Self.IPv4 || dst == e.netMap.Self.IPv6 {
		return nil, false
	}
	if pr, ok := e.peersByIP[dst]; ok {
		return pr, false
	}
	if types.IsOverlayAddr(dst) || types.IsSpecialNonRoutableAddr(dst) {
		// Unknown overlay IPs and loopback/link-local/multicast NEVER fall through to Subnet or Exit routes!
		return nil, false
	}
	var best *peerRuntime
	bestBits := -1
	for _, re := range e.routeTable {
		if re.prefix.Contains(dst) && re.prefix.Bits() > bestBits {
			best = re.peer
			bestBits = re.prefix.Bits()
		}
	}
	if best != nil {
		return best, false
	}
	if e.exitNodePeer != nil {
		e.exitNodePeer.mu.RLock()
		okFamily := (dst.Is4() && e.exitNodePeer.hasExitV4) || (dst.Is6() && e.exitNodePeer.hasExitV6)
		e.exitNodePeer.mu.RUnlock()
		if okFamily {
			return e.exitNodePeer, true
		}
	}
	return nil, false
}

func (e *Engine) recomputeMeshRoutes() {
	links := e.collectDirectLinks()
	e.mu.RLock()
	peers := make([]types.PeerNode, len(e.netMap.Peers))
	copy(peers, e.netMap.Peers)
	e.mu.RUnlock()
	e.meshRouter.Recompute(links, peers)
}

func (e *Engine) collectDirectLinks() []types.PeerLink {
	e.mu.RLock()
	keys := make([]types.PublicKey, 0, len(e.peersByKey))
	for k := range e.peersByKey {
		keys = append(keys, k)
	}
	e.mu.RUnlock()

	var out []types.PeerLink
	for _, k := range keys {
		if q, ok := e.selector.BestQuality(k); ok {
			if e.disableUDP && q.Endpoint.Proto == types.ProtoUDP {
				continue
			}
			rttMs := q.RTTMillis
			if rttMs <= 0 {
				rttMs = 5.0
			}
			out = append(out, types.PeerLink{
				Target:       k,
				RTTMillis:    rttMs,
				JitterMillis: q.JitterMillis,
				LossRate:     q.LossRate,
				Proto:        q.Endpoint.Proto,
			})
		}
	}
	return out
}

type pathDecisionKind uint8

const (
	pathDecisionNone pathDecisionKind = iota
	pathDecisionDirect
	pathDecisionPeerMesh
	pathDecisionCenterRelay
)

func (e *Engine) estimateCenterRelayCostMs(pr *peerRuntime) (rttMs float64, costMs float64, ok bool) {
	if !e.relayCli.Connected() {
		return 0, 0, false
	}
	if pr != nil {
		pr.mu.RLock()
		peerRelayUs := pr.lastCenterRelayRTTUs
		pr.mu.RUnlock()
		if peerRelayUs > 0 {
			rttMs = float64(peerRelayUs) / 1000.0
			return rttMs, rttMs + centerRelayPenaltyMs, true
		}
	}
	srvRTT := e.relayCli.RTTMillis()
	if srvRTT > 0 {
		rttMs = srvRTT * 2.0
	} else {
		rttMs = 15.0
	}
	return rttMs, rttMs + centerRelayPenaltyMs, true
}

func (e *Engine) selectPathDecision(pr *peerRuntime, peerKey types.PublicKey) (pathDecisionKind, types.Endpoint, mesh.Route, float64) {
	bestQ, hasDirect := e.selector.BestQuality(peerKey)
	if hasDirect && e.disableUDP && bestQ.Endpoint.Proto == types.ProtoUDP {
		hasDirect = false
	}

	meshRt, hasPeerRelay := e.meshRouter.LookupRelay(peerKey)
	centerRTT, centerCost, hasCenter := e.estimateCenterRelayCostMs(pr)

	bestRelayKind := pathDecisionNone
	bestRelayCost := 0.0
	bestRelayRTT := 0.0
	if hasPeerRelay && hasCenter {
		if centerCost < meshRt.TotalCostMs {
			bestRelayKind = pathDecisionCenterRelay
			bestRelayCost = centerCost
			bestRelayRTT = centerRTT
		} else {
			bestRelayKind = pathDecisionPeerMesh
			bestRelayCost = meshRt.TotalCostMs
			bestRelayRTT = meshRt.TotalCostMs
		}
	} else if hasPeerRelay {
		bestRelayKind = pathDecisionPeerMesh
		bestRelayCost = meshRt.TotalCostMs
		bestRelayRTT = meshRt.TotalCostMs
	} else if hasCenter {
		bestRelayKind = pathDecisionCenterRelay
		bestRelayCost = centerCost
		bestRelayRTT = centerRTT
	}

	if hasDirect {
		if hasPeerRelay && pr != nil {
			pr.mu.RLock()
			peerPrefersMesh := !pr.lastPeerRelayRx.IsZero() && time.Since(pr.lastPeerRelayRx) < 15*time.Second
			pr.mu.RUnlock()
			if peerPrefersMesh {
				return pathDecisionPeerMesh, types.Endpoint{}, meshRt, meshRt.TotalCostMs
			}
		}
		if bestRelayKind != pathDecisionNone && bestQ.EffectiveCostMs > 0 && bestRelayCost+10.0 < bestQ.EffectiveCostMs {
			return bestRelayKind, types.Endpoint{}, meshRt, bestRelayRTT
		}
		return pathDecisionDirect, bestQ.Endpoint, mesh.Route{}, bestQ.RTTMillis
	}

	if bestRelayKind != pathDecisionNone {
		return bestRelayKind, types.Endpoint{}, meshRt, bestRelayRTT
	}
	return pathDecisionNone, types.Endpoint{}, mesh.Route{}, 0
}

func (e *Engine) sendWireToPeer(pr *peerRuntime, wirePkt []byte) {
	if !e.isRunning() {
		return
	}
	pr.mu.RLock()
	peerKey := pr.meta.NodeKey
	pr.mu.RUnlock()

	decision, bestEp, _, _ := e.selectPathDecision(pr, peerKey)

	switch decision {
	case pathDecisionDirect:
		if err := e.sendPeerPacket(context.Background(), bestEp, wirePkt); err == nil {
			if e.selector.RecordTx(peerKey, bestEp) {
				e.probePeerCandidates(peerKey, []types.Endpoint{bestEp})
			}
			return
		}

	case pathDecisionPeerMesh:
		if e.sendViaPeerMesh(peerKey, wirePkt) == nil {
			return
		}

	case pathDecisionCenterRelay:
		if e.relayCli.Send(peerKey, wirePkt) == nil {
			e.triggerCoordinatedHolePunch(pr)
			return
		}
	}

	if e.sendViaPeerMesh(peerKey, wirePkt) == nil {
		e.triggerCoordinatedHolePunch(pr)
		return
	}
	_ = e.relayCli.Send(peerKey, wirePkt)
	e.triggerCoordinatedHolePunch(pr)
}

func (e *Engine) forwardMeshRelayFrame(frame protocol.MeshForward) bool {
	if frame.Target != frame.Previous && frame.Target != frame.Source {
		if e.sendMeshHop(frame.Target, frame) == nil {
			return true
		}
	}
	if rt, ok := e.meshRouter.Lookup(frame.Target); ok && rt.NextHop != frame.Source && rt.NextHop != frame.Previous {
		return e.sendMeshHop(rt.NextHop, frame) == nil
	}
	return false
}

func (e *Engine) sendMeshHop(next types.PublicKey, frame protocol.MeshForward) error {
	ep, _, ok := e.selector.BestEndpoint(next)
	if !ok {
		return errors.New("next-hop direct endpoint unavailable")
	}
	frame.Previous = e.cryptoMgr.LocalPublicKey()
	frame.SentAt = time.Now().Unix()
	frame.Sequence = e.meshSeq.Add(1)
	signed, err := protocol.EncodeMeshForward(frame, next, func(pkt []byte) ([protocol.ControlAuthTagSize]byte, error) {
		return e.cryptoMgr.SignControl(next, pkt)
	})
	if err != nil {
		return err
	}
	return e.sendPeerPacket(context.Background(), ep, signed)
}

func (e *Engine) sendViaPeerMesh(dstPeer types.PublicKey, innerPkt []byte) error {
	rt, ok := e.meshRouter.LookupRelay(dstPeer)
	if !ok {
		return errors.New("no multi-hop peer route available")
	}
	return e.sendMeshHop(rt.NextHop, protocol.MeshForward{
		TTL: protocol.DefaultHopTTL, Source: e.cryptoMgr.LocalPublicKey(), Target: dstPeer, Inner: innerPkt,
	})
}

func (e *Engine) sendReplyOverMeshOrRelay(dstPeer types.PublicKey, innerPkt []byte, preferred incomingSource) {
	if preferred == sourcePeerRelay {
		if e.sendViaPeerMesh(dstPeer, innerPkt) == nil {
			return
		}
	}
	if e.relayCli.Send(dstPeer, innerPkt) == nil {
		return
	}
	_ = e.sendViaPeerMesh(dstPeer, innerPkt)
}

func isPublicRoutableIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if types.IsOverlayAddr(ip) {
		return false
	}
	return true
}

func (e *Engine) effectiveCanRelay() bool {
	st := e.stateMgr.Get()
	switch st.RelayMode {
	case types.RelayModeOff:
		return false
	case types.RelayModeOn:
		return true
	}
	if st.CanRelay && st.RelayMode == "" {
		return true
	}
	if kind, _, _, _ := e.natDetector.Snapshot(); kind == nat.KindPublic {
		return true
	}
	if len(e.portMapper.MappedEndpoints()) > 0 {
		return true
	}
	for _, proto := range []types.TransportProto{types.ProtoUDP, types.ProtoTCP, types.ProtoQUIC, types.ProtoWSS} {
		if drv := e.hub.Driver(proto); drv != nil {
			if host, _, err := net.SplitHostPort(drv.LocalAddr()); err == nil {
				if ip, pErr := netip.ParseAddr(host); pErr == nil && isPublicRoutableIP(ip) {
					return true
				}
			}
		}
	}
	if len(e.hub.LocalPorts()) > 0 {
		for _, ip := range localInterfaceIPs() {
			if isPublicRoutableIP(ip) {
				return true
			}
		}
	}
	return false
}

func (e *Engine) allowRelayBandwidth(nBytes int) bool {
	maxMbps := e.stateMgr.Get().MaxRelayMbps
	if maxMbps <= 0 {
		return true
	}
	rateBytesPerSec := maxMbps * 125000.0
	burst := rateBytesPerSec * 0.25
	if burst < 65536 {
		burst = 65536
	}

	now := time.Now()
	e.rlMu.Lock()
	defer e.rlMu.Unlock()

	if e.rlLastRefill.IsZero() {
		e.rlTokens = burst
		e.rlLastRefill = now
	} else {
		elapsed := now.Sub(e.rlLastRefill).Seconds()
		if elapsed > 0 {
			e.rlTokens += elapsed * rateBytesPerSec
			if e.rlTokens > burst {
				e.rlTokens = burst
			}
			e.rlLastRefill = now
		}
	}

	need := float64(nBytes)
	if e.rlTokens < need {
		return false
	}
	e.rlTokens -= need
	return true
}

package engine

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/acktier/acktier/internal/daemon/nat"
	"github.com/acktier/acktier/internal/daemon/transport"
	"github.com/acktier/acktier/pkg/protocol"
	"github.com/acktier/acktier/pkg/types"
)

type stunProbeEntry struct {
	serverAddr string
	sentAt     time.Time
}

func cryptoRandUint64() uint64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	v := binary.LittleEndian.Uint64(b[:])
	if v == 0 {
		return 1
	}
	return v
}

// NotifyNetworkChange immediately refreshes STUN/port-mappings, pushes a new Heartbeat to Control,
// and actively sends roaming probes to all online peers when the host switches Wi-Fi / cellular networks.
func (e *Engine) NotifyNetworkChange() {
	if !e.isRunning() {
		return
	}
	e.mu.RLock()
	peers := make([]*peerRuntime, 0, len(e.peersByKey))
	for _, pr := range e.peersByKey {
		peers = append(peers, pr)
	}
	e.mu.RUnlock()

	e.natDetector.ResetObservations()
	e.selector.OnLocalNetworkChange()
	e.sendSTUNProbes()
	e.relayCli.SendServerPing()

	go func() {
		time.Sleep(50 * time.Millisecond)
		e.requestImmediateHeartbeat()

		for _, pr := range peers {
			pr.mu.Lock()
			online := pr.meta.Online
			peerKey := pr.meta.NodeKey
			pr.lastPunch = time.Time{} // bypass punch cooldown on local network switch
			pr.mu.Unlock()
			if !online {
				continue
			}
			e.triggerCoordinatedHolePunch(pr)
			e.probePeerCandidates(peerKey, e.selector.AllCandidates(peerKey))
		}
	}()
}

func (e *Engine) triggerCoordinatedHolePunch(pr *peerRuntime) {
	pr.mu.Lock()
	if time.Since(pr.lastPunch) < 2*time.Second {
		pr.mu.Unlock()
		return
	}
	pr.lastPunch = time.Now()
	peerKey := pr.meta.NodeKey
	pr.mu.Unlock()

	go func() {
		kind, step, _, _ := e.natDetector.Snapshot()
		myEps := e.collectLocalEndpoints()
		coordPkt, err := protocol.EncodeAuthPunchCoord(e.cryptoMgr.LocalPublicKey(), peerKey, false, byte(kind), step, time.Now().UnixNano(), myEps, func(data []byte) ([protocol.ControlAuthTagSize]byte, error) {
			return e.cryptoMgr.SignControl(peerKey, data)
		})
		if err == nil {
			if e.relayCli.Send(peerKey, coordPkt) != nil {
				_ = e.sendViaPeerMesh(peerKey, coordPkt)
			}
		}

		cands := e.selector.AllCandidates(peerKey)
		e.executePunchBurst(peerKey, cands, nat.KindUnknown, 0)
	}()
}

func (e *Engine) executePunchBurst(peerKey types.PublicKey, cands []types.Endpoint, peerKind nat.Kind, peerStep int16) {
	if !e.isRunning() {
		return
	}
	cands = e.safePeerCandidates(cands)
	if !e.disableUDP && e.hub.HasProto(types.ProtoUDP) {
		udpTargets := nat.BuildUDPPunchTargets(cands, peerKind, peerStep)
		if len(udpTargets) > 12 {
			udpTargets = udpTargets[:12]
		}
		for round := 0; round < 3; round++ {
			now := time.Now().UnixNano()
			for _, addr := range udpTargets {
				ep := types.Endpoint{Proto: types.ProtoUDP, Addr: addr}
				probeID := cryptoRandUint64()
				e.selector.RecordProbeSent(peerKey, ep, probeID)
				probe, err := e.buildAuthProbe(protocol.PacketPing, peerKey, probeID, now, "")
				if err == nil {
					_ = e.sendPeerPacket(context.Background(), ep, probe)
				}
			}
			if round < 2 && len(udpTargets) > 0 {
				time.Sleep(40 * time.Millisecond)
			}
		}
	}

	e.probePeerCandidates(peerKey, cands)
}

func (e *Engine) buildAuthProbe(pktType protocol.PacketType, peerKey types.PublicKey, probeID uint64, txNano int64, obs string) ([]byte, error) {
	return protocol.EncodeAuthProbePacket(pktType, e.cryptoMgr.LocalPublicKey(), peerKey, probeID, txNano, obs, func(data []byte) ([protocol.ControlAuthTagSize]byte, error) {
		return e.cryptoMgr.SignControl(peerKey, data)
	})
}

// onAuthenticatedInboundDirectRx refreshes LastRx if srcEp is ALREADY round-trip verified;
// otherwise it dispatches an immediate bound Ping probe so dynamic NAT pinholes verify in 1 RTT without trusting spoofed source IPs!
func (e *Engine) onAuthenticatedInboundDirectRx(pr *peerRuntime, peerKey types.PublicKey, srcEp types.Endpoint) {
	srcEp, ok := e.selector.SanitizeEndpoint(srcEp)
	if !ok || pr == nil {
		return
	}
	if e.selector.RefreshVerifiedRx(peerKey, srcEp) {
		return
	}
	pr.mu.Lock()
	canChallenge := time.Since(pr.lastDirectChallenge) >= 250*time.Millisecond
	if canChallenge {
		pr.lastDirectChallenge = time.Now()
	}
	pr.mu.Unlock()
	if canChallenge {
		// Send first bound challenge probe synchronously for instant 1-RTT verification, then calibrate!
		if !(srcEp.Proto == types.ProtoUDP && e.disableUDP) && e.hub.HasProto(srcEp.Proto) {
			probeID := cryptoRandUint64()
			e.selector.RecordProbeSent(peerKey, srcEp, probeID)
			if probe, err := e.buildAuthProbe(protocol.PacketPing, peerKey, probeID, time.Now().UnixNano(), ""); err == nil {
				_ = e.sendPeerPacket(context.Background(), srcEp, probe)
			}
		}
		go e.probePeerCalibrationBurst(peerKey, []types.Endpoint{srcEp})
	}
}

func (e *Engine) allowInboundPeerPing(pr *peerRuntime) bool {
	now := time.Now()
	pr.mu.Lock()
	defer pr.mu.Unlock()
	if now.Sub(pr.lastInboundPingWin) >= time.Second {
		pr.lastInboundPingWin = now
		pr.inboundPingCount = 1
		return true
	}
	if pr.inboundPingCount >= 32 {
		return false
	}
	pr.inboundPingCount++
	return true
}

func (e *Engine) probePeerCalibrationBurst(peerKey types.PublicKey, cands []types.Endpoint) {
	for i := 0; i < 6; i++ {
		if !e.isRunning() {
			return
		}
		e.probePeerCandidates(peerKey, cands)
		if i < 5 {
			time.Sleep(35 * time.Millisecond)
		}
	}
	time.Sleep(270 * time.Millisecond)
	if e.isRunning() {
		e.recomputeMeshRoutes()
		e.requestImmediateHeartbeat()
	}
}

func (e *Engine) probePeerCandidates(peerKey types.PublicKey, cands []types.Endpoint) {
	if !e.isRunning() {
		return
	}
	for _, ep := range e.safePeerCandidates(cands) {
		if ep.Proto == types.ProtoUDP && e.disableUDP {
			continue
		}
		if !e.hub.HasProto(ep.Proto) {
			continue
		}
		go func(targetEp types.Endpoint) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			probeID := cryptoRandUint64()
			e.selector.RecordProbeSent(peerKey, targetEp, probeID)
			probe, err := e.buildAuthProbe(protocol.PacketPing, peerKey, probeID, time.Now().UnixNano(), "")
			if err == nil {
				_ = e.sendPeerPacket(ctx, targetEp, probe)
			}
		}(ep)
	}
}

func (e *Engine) sendControlOrProbeToPeer(pr *peerRuntime, pkt []byte) {
	pr.mu.RLock()
	peerKey := pr.meta.NodeKey
	pr.mu.RUnlock()

	cands := e.selector.AllCandidates(peerKey)
	for _, ep := range cands {
		if ep.Proto == types.ProtoUDP && e.disableUDP {
			continue
		}
		if !e.hub.HasProto(ep.Proto) {
			continue
		}
		go func(targetEp types.Endpoint) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = e.sendPeerPacket(ctx, targetEp, pkt)
		}(ep)
	}
	_ = e.sendViaPeerMesh(peerKey, pkt)
	_ = e.relayCli.Send(peerKey, pkt)
}

func (e *Engine) safePeerCandidates(in []types.Endpoint) []types.Endpoint {
	out := make([]types.Endpoint, 0, min(len(in), transport.MaxCandidatesPerPeer))
	seen := make(map[types.Endpoint]bool)
	for _, raw := range in {
		if ep, ok := e.selector.SanitizeEndpoint(raw); ok && !seen[ep] {
			seen[ep] = true
			out = append(out, ep)
			if len(out) >= transport.MaxCandidatesPerPeer {
				break
			}
		}
	}
	return out
}

// All peer-directed packets pass the same address policy, including sends
// triggered directly by NAT coordination and replies to observed endpoints.
// Control-server STUN addresses are handled separately.
func (e *Engine) sendPeerPacket(ctx context.Context, raw types.Endpoint, pkt []byte) error {
	if !e.isRunning() {
		return errors.New("data plane is not authorized")
	}
	ep, ok := e.selector.SanitizeEndpoint(raw)
	if !ok || (e.disableUDP && ep.Proto == types.ProtoUDP) {
		return errors.New("invalid or disabled peer endpoint")
	}
	return e.hub.Send(ctx, ep, pkt)
}

func (e *Engine) collectLocalEndpoints() []types.Endpoint {
	var extra []types.Endpoint
	if !e.disableUDP {
		_, _, stunPub, _ := e.natDetector.Snapshot()
		if stunPub != "" {
			extra = append(extra, types.Endpoint{Proto: types.ProtoUDP, Addr: stunPub})
		}
	}
	extra = append(extra, e.portMapper.MappedEndpoints()...)

	all := e.hub.LocalEndpoints(e.tunDev.Name(), extra)
	if !e.disableUDP {
		return all
	}
	filtered := make([]types.Endpoint, 0, len(all))
	for _, ep := range all {
		if ep.Proto != types.ProtoUDP {
			filtered = append(filtered, ep)
		}
	}
	return filtered
}

func (e *Engine) recordPendingSTUN(probeID uint64, serverAddr string) {
	now := time.Now()
	e.stunMu.Lock()
	for k, v := range e.pendingSTUN {
		if now.Sub(v.sentAt) > 5*time.Second {
			delete(e.pendingSTUN, k)
		}
	}
	if len(e.pendingSTUN) < 64 {
		e.pendingSTUN[probeID] = stunProbeEntry{serverAddr: serverAddr, sentAt: now}
	}
	e.stunMu.Unlock()
}

func (e *Engine) consumePendingSTUN(probeID uint64, fromAddr string) (time.Duration, bool) {
	now := time.Now()
	e.stunMu.Lock()
	defer e.stunMu.Unlock()
	ent, ok := e.pendingSTUN[probeID]
	if !ok {
		return 0, false
	}
	delete(e.pendingSTUN, probeID)
	age := now.Sub(ent.sentAt)
	if age < 0 || age > 5*time.Second || ent.serverAddr != fromAddr {
		return 0, false
	}
	return age, true
}

func (e *Engine) sendSTUNProbes() {
	if e.disableUDP || !e.hub.HasProto(types.ProtoUDP) {
		return
	}
	e.mu.RLock()
	relays := e.netMap.Relays
	e.mu.RUnlock()
	if len(relays) == 0 {
		return
	}
	r0 := relays[0]
	for _, addr := range []string{r0.STUNAddr, r0.STUNAltAddr} {
		if addr == "" {
			continue
		}
		probeID := cryptoRandUint64()
		e.recordPendingSTUN(probeID, addr)
		pkt := protocol.EncodeProbePacket(protocol.PacketPing, e.cryptoMgr.LocalPublicKey(), probeID, time.Now().UnixNano(), "")
		_ = e.hub.Send(context.Background(), types.Endpoint{Proto: types.ProtoUDP, Addr: addr}, pkt)
	}
}

func (e *Engine) refreshPortMappings(ctx context.Context) {
	ports := e.hub.LocalPorts()
	uPort, _ := strconv.Atoi(ports[types.ProtoUDP])
	tPort, _ := strconv.Atoi(ports[types.ProtoTCP])
	var lanIP net.IP
	for _, ip := range localInterfaceIPs() {
		if ip.Is4() && ip.IsPrivate() {
			a4 := ip.As4()
			lanIP = net.IPv4(a4[0], a4[1], a4[2], a4[3])
			break
		}
	}
	if lanIP != nil {
		mapCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		e.portMapper.Refresh(mapCtx, lanIP, uint16(uPort), uint16(tPort))
		cancel()
	}
}

func localInterfaceIPs() []netip.Addr {
	var out []netip.Addr
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			if ipNet, ok := a.(*net.IPNet); ok {
				if ip, ok2 := netip.AddrFromSlice(ipNet.IP); ok2 {
					out = append(out, ip.Unmap())
				}
			}
		}
	}
	return out
}

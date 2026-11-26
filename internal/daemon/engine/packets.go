package engine

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/ackwrap/acktier/internal/daemon/nat"
	"github.com/ackwrap/acktier/internal/daemon/tun"
	"github.com/ackwrap/acktier/pkg/protocol"
	"github.com/ackwrap/acktier/pkg/types"
)

type incomingSource byte

const (
	sourceDirect incomingSource = iota
	sourcePeerRelay
	sourceCenterRelay
)

func (e *Engine) tunReadLoop() {
	buf := make([]byte, 65535)
	for {
		n, err := e.tunDev.ReadPacket(buf)
		if err != nil {
			select {
			case <-e.closedCh:
				return
			default:
			}
			if errors.Is(err, io.EOF) {
				return
			}
			continue
		}
		if n < 20 || !e.isRunning() {
			continue
		}
		pkt := buf[:n]

		// 1. Intercept local MagicDNS queries & pings to 100.100.100.100!
		if dnsReply, handled := e.dnsResolver.TryHandleTUNPacket(pkt); handled {
			if len(dnsReply) > 0 {
				_ = e.tunDev.WritePacket(dnsReply)
			}
			continue
		}

		// 2. Enforce outbound Zero-Trust ACL & record stateful conntrack entry
		if !e.pktFilter.AllowOutbound(pkt) {
			continue
		}

		dstIP, ok := tun.ExtractDstIP(pkt)
		if !ok {
			continue
		}
		pr, viaExit := e.lookupPeerByDstIP(dstIP)
		if pr == nil {
			continue
		}
		if viaExit {
			pr.mu.RLock()
			ek := pr.meta.NodeKey
			pr.mu.RUnlock()
			e.exitFlows.RecordOutbound(ek, pkt)
		}
		e.encryptAndDispatchToPeer(pr, pkt)
	}
}

// sendPlainPacketToOverlay is invoked by the userspace Subnet/Exit Gateway to return reply L3 packets to overlay peers.
func (e *Engine) sendPlainPacketToOverlay(plainPkt []byte) {
	if !e.isRunning() {
		return
	}
	dstIP, ok := tun.ExtractDstIP(plainPkt)
	if !ok {
		return
	}
	e.mu.RLock()
	pr := e.peersByIP[dstIP]
	e.mu.RUnlock()
	if pr == nil {
		return
	}
	if !e.pktFilter.AllowOutbound(plainPkt) {
		return
	}
	e.encryptAndDispatchToPeer(pr, plainPkt)
}

func (e *Engine) encryptAndDispatchToPeer(pr *peerRuntime, pkt []byte) {
	pr.mu.RLock()
	peerKey := pr.meta.NodeKey
	pr.mu.RUnlock()

	wirePkt, err := e.cryptoMgr.SealPacket(peerKey, pkt)
	if err == nil {
		pr.txBytes.Add(uint64(len(pkt)))
		e.sendWireToPeer(pr, wirePkt)
		return
	}

	e.cryptoMgr.QueuePendingPacket(peerKey, pkt)
	pr.mu.Lock()
	shouldInit := time.Since(pr.lastHandshake) > 800*time.Millisecond
	if shouldInit {
		pr.lastHandshake = time.Now()
	}
	pr.mu.Unlock()

	if shouldInit {
		e.triggerCoordinatedHolePunch(pr)
		if initPkt, hsErr := e.cryptoMgr.InitiateHandshake(peerKey); hsErr == nil {
			e.sendControlOrProbeToPeer(pr, initPkt)
		}
	}
}

func (e *Engine) flushQueuedPackets(pr *peerRuntime, peerKey types.PublicKey, queued [][]byte) {
	for _, ipPkt := range queued {
		if !e.isRunning() || !e.pktFilter.AllowOutbound(ipPkt) {
			continue
		}
		if wirePkt, err := e.cryptoMgr.SealPacket(peerKey, ipPkt); err == nil {
			pr.txBytes.Add(uint64(len(ipPkt)))
			e.sendWireToPeer(pr, wirePkt)
		}
	}
}

// OnTransportPacket is the unified PacketHandler callback passed to all transport.Driver instances.
func (e *Engine) OnTransportPacket(pkt []byte, srcEp types.Endpoint) {
	if !e.isRunning() {
		return
	}
	if e.disableUDP && srcEp.Proto == types.ProtoUDP {
		return
	}
	e.handleIncomingWirePacket(pkt, srcEp, sourceDirect, types.PublicKey{})
}

func (e *Engine) handleCenterRelayedPacket(src types.PublicKey, inner []byte) {
	if !e.isRunning() {
		return
	}
	cp := make([]byte, len(inner))
	copy(cp, inner)
	e.handleIncomingWirePacket(cp, types.Endpoint{}, sourceCenterRelay, src)
}

func (e *Engine) handleIncomingWirePacket(pkt []byte, srcEp types.Endpoint, srcMode incomingSource, relaySrc types.PublicKey) {
	if !e.isRunning() {
		return
	}
	pType, _, _, err := protocol.ParseHeader(pkt)
	if err != nil {
		return
	}

	switch pType {
	case protocol.PacketMeshForward:
		if srcMode != sourceDirect {
			return
		}
		localPub := e.cryptoMgr.LocalPublicKey()
		frame, err := protocol.DecodeAndVerifyMeshForward(pkt, localPub, e.cryptoMgr.VerifyControl)
		if err != nil {
			return
		}
		hop := e.getPeerRuntime(frame.Previous)
		if hop == nil || e.getPeerRuntime(frame.Source) == nil ||
			!e.cryptoMgr.AcceptMeshHop(frame.Previous, frame.SentAt, frame.Sequence) {
			return
		}
		e.onAuthenticatedInboundDirectRx(hop, frame.Previous, srcEp)
		if frame.Target == localPub {
			e.handleIncomingWirePacket(frame.Inner, types.Endpoint{}, sourcePeerRelay, frame.Source)
			return
		}
		if frame.TTL <= 1 || !e.effectiveCanRelay() || e.getPeerRuntime(frame.Target) == nil {
			return
		}
		if !e.allowRelayBandwidth(len(pkt)) {
			return
		}
		frame.TTL--
		if e.forwardMeshRelayFrame(frame) {
			e.peerRelayedFrames.Add(1)
			e.peerRelayedBytes.Add(uint64(len(pkt)))
		}

	case protocol.PacketHandshakeInit:
		if srcMode != sourceDirect && !handshakeMatchesRelay(pkt, relaySrc) {
			return
		}
		peerKey, ackPkt, queued, err := e.cryptoMgr.HandleHandshakeInit(pkt)
		if err != nil {
			return
		}
		pr := e.getPeerRuntime(peerKey)
		if pr == nil {
			return
		}
		if srcMode == sourceDirect && srcEp.Addr != "" {
			_ = e.sendPeerPacket(context.Background(), srcEp, ackPkt)
			e.onAuthenticatedInboundDirectRx(pr, peerKey, srcEp)
		} else {
			if srcMode == sourcePeerRelay {
				pr.mu.Lock()
				pr.lastPeerRelayRx = time.Now()
				pr.mu.Unlock()
			}
			e.sendReplyOverMeshOrRelay(peerKey, ackPkt, srcMode)
		}
		e.flushQueuedPackets(pr, peerKey, queued)

	case protocol.PacketHandshakeAck:
		if srcMode != sourceDirect && !handshakeMatchesRelay(pkt, relaySrc) {
			return
		}
		peerKey, queued, err := e.cryptoMgr.HandleHandshakeAck(pkt)
		if err != nil {
			return
		}
		pr := e.getPeerRuntime(peerKey)
		if pr == nil {
			return
		}
		if srcMode == sourceDirect && srcEp.Addr != "" {
			// HandshakeAck consumed our ephemeral `pending` secret -> proves round-trip reachability!
			_, _, hadBefore := e.selector.BestEndpoint(peerKey)
			e.selector.RecordRx(peerKey, srcEp, 0)
			if !hadBefore {
				e.recomputeMeshRoutes()
				e.requestImmediateHeartbeat()
				go e.probePeerCalibrationBurst(peerKey, []types.Endpoint{srcEp})
			}
		}
		e.flushQueuedPackets(pr, peerKey, queued)

	case protocol.PacketData:
		peerKey, plainIP, err := e.cryptoMgr.OpenPacket(pkt)
		if err != nil || (srcMode != sourceDirect && relaySrc != peerKey) {
			return
		}
		pr := e.getPeerRuntime(peerKey)
		if pr == nil {
			return
		}
		parsedPkt, okSrc := e.validateInboundPeerSource(pr, plainIP)
		if !okSrc {
			return // Drop spoofed overlay IP, unapproved subnet IP, or unsolicited Exit Node packet!
		}

		pr.rxBytes.Add(uint64(len(plainIP)))
		if srcMode == sourceDirect && srcEp.Addr != "" {
			e.onAuthenticatedInboundDirectRx(pr, peerKey, srcEp)
		} else if srcMode == sourcePeerRelay {
			pr.mu.Lock()
			pr.lastPeerRelayRx = time.Now()
			pr.mu.Unlock()
		}

		if !e.pktFilter.AllowInbound(plainIP) {
			return
		}

		e.mu.RLock()
		isSelf := parsedPkt.DstIP == e.netMap.Self.IPv4 || parsedPkt.DstIP == e.netMap.Self.IPv6
		e.mu.RUnlock()

		if isSelf {
			_ = e.tunDev.WritePacket(plainIP)
			return
		}
		if e.isSelfApprovedDestination(parsedPkt.DstIP) {
			e.gateway.HandlePacket(plainIP)
		}

	case protocol.PacketPunchCoord:
		// PunchCoord is ONLY accepted over Relay/Mesh AND MUST carry a valid per-peer HMAC + fresh monotonic timestamp!
		if srcMode == sourceDirect {
			return
		}
		localPub := e.cryptoMgr.LocalPublicKey()
		sender, isReply, peerNATKind, peerStep, txNano, peerEps, err := protocol.DecodeAndVerifyPunchCoord(pkt, localPub, e.cryptoMgr.VerifyControl)
		if err != nil || relaySrc != sender {
			return
		}
		pr := e.getPeerRuntime(sender)
		if pr == nil || !e.cryptoMgr.AcceptPunchCoordTimestamp(sender, txNano) {
			return
		}

		e.selector.SyncCandidates(sender, peerEps)
		if !isReply {
			kind, step, _, _ := e.natDetector.Snapshot()
			myEps := e.collectLocalEndpoints()
			replyCoord, err := protocol.EncodeAuthPunchCoord(localPub, sender, true, byte(kind), step, time.Now().UnixNano(), myEps, func(data []byte) ([protocol.ControlAuthTagSize]byte, error) {
				return e.cryptoMgr.SignControl(sender, data)
			})
			if err == nil {
				e.sendReplyOverMeshOrRelay(sender, replyCoord, srcMode)
			}
		}

		pr.mu.Lock()
		canBurst := time.Since(pr.lastPunch) >= 1500*time.Millisecond
		if canBurst {
			pr.lastPunch = time.Now()
		}
		pr.mu.Unlock()
		if canBurst {
			go e.executePunchBurst(sender, peerEps, nat.Kind(peerNATKind), peerStep)
		}

	case protocol.PacketPing:
		localPub := e.cryptoMgr.LocalPublicKey()
		_, sender, probeID, txNano, _, authOK, err := protocol.DecodeAndVerifyProbePacket(pkt, localPub, e.cryptoMgr.VerifyControl)
		if err != nil || !authOK {
			// Silently drop unauthenticated Ping packets to prevent amplification and state pollution!
			return
		}
		if srcMode != sourceDirect && relaySrc != sender {
			return
		}
		msgAge := time.Since(time.Unix(0, txNano))
		if msgAge > 30*time.Second || msgAge < -30*time.Second {
			return
		}
		pr := e.getPeerRuntime(sender)
		if pr == nil || !e.allowInboundPeerPing(pr) {
			return
		}

		obs := ""
		if srcMode == sourceDirect && srcEp.Addr != "" {
			obs = srcEp.Addr
			e.onAuthenticatedInboundDirectRx(pr, sender, srcEp)
		}
		pong, err := e.buildAuthProbe(protocol.PacketPong, sender, probeID, txNano, obs)
		if err != nil {
			return
		}
		if srcMode == sourceDirect && srcEp.Addr != "" {
			_ = e.sendPeerPacket(context.Background(), srcEp, pong)
		} else if !relaySrc.IsZero() {
			e.sendReplyOverMeshOrRelay(sender, pong, srcMode)
		}

	case protocol.PacketPong:
		localPub := e.cryptoMgr.LocalPublicKey()
		_, sender, probeID, txNano, obs, authOK, err := protocol.DecodeAndVerifyProbePacket(pkt, localPub, e.cryptoMgr.VerifyControl)
		if err != nil {
			return
		}

		// Case A: Unauthenticated STUN Server Pong — ONLY accepted if probeID & srcEp.Addr match an unconsumed STUN probe!
		if !authOK {
			if srcMode == sourceDirect && sender == localPub && obs != "" {
				if rtt, ok := e.consumePendingSTUN(probeID, srcEp.Addr); ok {
					wasRelay := e.effectiveCanRelay()
					_, _, prevWAN, _ := e.natDetector.Snapshot()
					e.natDetector.RecordObservation(srcEp.Addr, obs, rtt, localInterfaceIPs())
					_, _, newWAN, _ := e.natDetector.Snapshot()
					if newWAN != prevWAN || (!wasRelay && e.effectiveCanRelay()) {
						e.requestImmediateHeartbeat()
					}
				}
			}
			return
		}

		// Case B: HMAC-Authenticated Peer Pong — MUST bind to an active outbound probeID!
		if srcMode != sourceDirect && relaySrc != sender {
			return
		}
		pr := e.getPeerRuntime(sender)
		if pr == nil {
			return
		}

		rtt := time.Since(time.Unix(0, txNano))
		if rtt < 0 || rtt > 15*time.Second {
			return
		}

		if srcMode == sourceDirect && srcEp.Addr != "" {
			_, hadBefore := e.selector.BestQuality(sender)
			boundRTT, validProbe := e.selector.ValidateAndRecordProbeRx(sender, srcEp, probeID, 15*time.Second)
			if !validProbe {
				return // Reject unsolicited or replayed Pong that does not match an outbound probe!
			}
			pr.mu.Lock()
			pr.lastRTTMicros = boundRTT.Microseconds()
			pr.mu.Unlock()

			e.recomputeMeshRoutes()
			if !hadBefore {
				e.requestImmediateHeartbeat()
			}
		} else {
			// Relayed Pong: verify it matches an active PingPeer waiter for `sender`!
			e.pingMu.Lock()
			w, hasWaiter := e.pingWaiters[probeID]
			e.pingMu.Unlock()
			if !hasWaiter || w.peerKey != sender {
				return
			}
			pr.mu.Lock()
			pr.lastRTTMicros = rtt.Microseconds()
			if srcMode == sourceCenterRelay {
				sampleUs := rtt.Microseconds()
				if sampleUs < 50 {
					sampleUs = 50
				}
				if pr.lastCenterRelayRTTUs <= 0 {
					pr.lastCenterRelayRTTUs = sampleUs
				} else {
					pr.lastCenterRelayRTTUs = (pr.lastCenterRelayRTTUs*3 + sampleUs) / 4
				}
			}
			pr.mu.Unlock()
		}

		via := "relay"
		ep := "relay"
		if srcMode == sourceDirect && srcEp.Addr != "" {
			via = "direct-" + string(srcEp.Proto)
			ep = srcEp.Addr
		} else if srcMode == sourcePeerRelay {
			via = "peer-relay"
			if rt, ok := e.meshRouter.Lookup(sender); ok && len(rt.Hops) > 0 {
				_, names := e.meshRouter.AllRoutes()
				ep = formatHopNames(rt.Hops, names)
			} else {
				ep = "mesh"
			}
		}
		e.pingMu.Lock()
		w, ok := e.pingWaiters[probeID]
		e.pingMu.Unlock()
		if ok && w.peerKey == sender {
			select {
			case w.ch <- pingReply{via: via, ep: ep}:
			default:
			}
		}
	}
}

func handshakeMatchesRelay(pkt []byte, relaySrc types.PublicKey) bool {
	_, sender, _, _, _, err := protocol.DecodeHandshakePacket(pkt)
	return err == nil && sender == relaySrc
}

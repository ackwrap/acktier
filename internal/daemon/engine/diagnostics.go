package engine

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/ackwrap/acktier/internal/daemon/nat"
	"github.com/ackwrap/acktier/pkg/protocol"
	"github.com/ackwrap/acktier/pkg/types"
)

// PeerStatus summarizes live connectivity and traffic telemetry for CLI / GUI display.
type PeerStatus struct {
	ID              types.NodeID   `json:"id"`
	Name            string         `json:"name"`
	Hostname        string         `json:"hostname"`
	OS              string         `json:"os"`
	NodeKey         string         `json:"nodeKey"`
	IPv4            string         `json:"ipv4"`
	IPv6            string         `json:"ipv6"`
	Online          bool           `json:"online"`
	CanRelay        bool           `json:"canRelay,omitempty"`
	ActivePath      string         `json:"activePath"` // "direct-*" | "peer-relay" | "relay" | "idle"
	DirectAddr      string         `json:"directAddr,omitempty"`
	MeshHops        string         `json:"meshHops,omitempty"`
	RTTMillis       float64        `json:"rttMillis,omitempty"`
	LossRate        float64        `json:"lossRate,omitempty"`
	EffectiveCostMs float64        `json:"effectiveCostMs,omitempty"`
	RxBytes         uint64         `json:"rxBytes"`
	TxBytes         uint64         `json:"txBytes"`
	AllowedIPs      []netip.Prefix `json:"allowedIPs,omitempty"`
	ApprovedRoutes  []netip.Prefix `json:"approvedRoutes,omitempty"`
}

// StatusResponse represents the full local daemon status returned over LocalAPI.
type StatusResponse struct {
	State              string                          `json:"state"` // "Running" | "Stopped"
	TUNName            string                          `json:"tunName"`
	SelfName           string                          `json:"selfName,omitempty"`
	SelfNodeKey        string                          `json:"selfNodeKey"`
	IPv4               string                          `json:"ipv4,omitempty"`
	IPv6               string                          `json:"ipv6,omitempty"`
	ServerURL          string                          `json:"serverUrl,omitempty"`
	ExitNode           string                          `json:"exitNode,omitempty"`
	RelayMode          types.RelayMode                 `json:"relayMode"`
	CanRelay           bool                            `json:"canRelay"`
	MaxRelayMbps       float64                         `json:"maxRelayMbps,omitempty"`
	RelayConnected     bool                            `json:"relayConnected"`
	CenterRelayRTTMs   float64                         `json:"centerRelayRttMs,omitempty"`
	PeerRelayedFrames  uint64                          `json:"peerRelayedFrames"`
	PeerRelayedBytes   uint64                          `json:"peerRelayedBytes"`
	GatewayProxiedPkts uint64                          `json:"gatewayProxiedPkts"`
	ACLActiveRules     int                             `json:"aclActiveRules"`
	ACLDroppedIn       uint64                          `json:"aclDroppedIn"`
	ACLDroppedOut      uint64                          `json:"aclDroppedOut"`
	NATType            string                          `json:"natType"`
	ActiveProtocols    map[types.TransportProto]string `json:"activeProtocols,omitempty"`
	MagicDNSSuffix     string                          `json:"magicDNSSuffix,omitempty"`
	Revision           uint64                          `json:"revision"`
	Peers              []PeerStatus                    `json:"peers"`
}

// MeshRouteInfo describes a single entry in the computed Smart Mesh routing table.
type MeshRouteInfo struct {
	TargetName   string   `json:"targetName"`
	TargetIPv4   string   `json:"targetIpv4"`
	Mode         string   `json:"mode"` // "direct" | "peer-relay"
	NextHopName  string   `json:"nextHopName"`
	HopChain     []string `json:"hopChain"`
	EstRTTMillis float64  `json:"estRttMillis"`
}

// MeshStatusReport summarizes local transit relay counters and Dijkstra mesh routing table.
type MeshStatusReport struct {
	CanRelay          bool            `json:"canRelay"`
	PeerRelayedFrames uint64          `json:"peerRelayedFrames"`
	PeerRelayedBytes  uint64          `json:"peerRelayedBytes"`
	Routes            []MeshRouteInfo `json:"routes"`
}

// NetCheckReport returns comprehensive NAT, STUN, UPnP/NAT-PMP, Relay, and Multi-Transport diagnostics.
type NetCheckReport struct {
	NAT              nat.Summary                     `json:"nat"`
	RelayConnected   bool                            `json:"relayConnected"`
	CenterRelayRTTMs float64                         `json:"centerRelayRttMs,omitempty"`
	LocalTransports  map[types.TransportProto]string `json:"localTransports"`
	CandidateCount   int                             `json:"candidateCount"`
	Candidates       []types.Endpoint                `json:"candidates"`
}

// PingResult reports overlay probe latency and transport route.
type PingResult struct {
	TargetName string  `json:"targetName"`
	TargetIP   string  `json:"targetIP"`
	RTTMillis  float64 `json:"rttMillis"`
	Via        string  `json:"via"` // "direct-*" | "peer-relay" | "relay"
	Endpoint   string  `json:"endpoint,omitempty"`
}

type pingWaiter struct {
	peerKey types.PublicKey
	ch      chan pingReply
}

type pingReply struct {
	via string
	ep  string
}

// LookupDNS resolves a MagicDNS hostname to its overlay IPv4/IPv6 addresses.
func (e *Engine) LookupDNS(name string) (ipv4, ipv6 string, fqdn string, ok bool) {
	v4, v6, full, found := e.dnsResolver.LookupHost(name)
	if !found {
		return "", "", "", false
	}
	if v4.IsValid() {
		ipv4 = v4.String()
	}
	if v6.IsValid() {
		ipv6 = v6.String()
	}
	return ipv4, ipv6, full, true
}

func (e *Engine) Status() StatusResponse {
	st := e.stateMgr.Get()
	natKind, _, _, _ := e.natDetector.Snapshot()
	_, namesMap := e.meshRouter.AllRoutes()

	e.mu.RLock()
	running := e.running
	authorized := running && time.Now().Before(e.controlUntil)
	nm := e.netMap
	peers := make([]PeerStatus, 0, len(nm.Peers))
	for _, p := range nm.Peers {
		pr := e.peersByKey[p.NodeKey]
		ps := PeerStatus{
			ID:             p.ID,
			Name:           p.Name,
			Hostname:       p.Hostname,
			OS:             p.OS,
			NodeKey:        p.NodeKey.ShortString(),
			Online:         p.Online,
			CanRelay:       p.CanRelay,
			AllowedIPs:     p.AllowedIPs,
			ApprovedRoutes: p.ApprovedRoutes,
			ActivePath:     "idle",
		}
		if p.IPv4.IsValid() {
			ps.IPv4 = p.IPv4.String()
		}
		if p.IPv6.IsValid() {
			ps.IPv6 = p.IPv6.String()
		}
		if pr != nil {
			mode, bestEp, meshRt, effRTT := e.selectPathDecision(pr, p.NodeKey)
			switch mode {
			case pathDecisionPeerMesh:
				ps.ActivePath = "peer-relay"
				ps.MeshHops = formatHopNames(meshRt.Hops, namesMap)
				ps.RTTMillis = effRTT
				ps.EffectiveCostMs = meshRt.TotalCostMs
			case pathDecisionDirect:
				ps.ActivePath = "direct-" + string(bestEp.Proto)
				ps.DirectAddr = bestEp.Addr
				ps.RTTMillis = effRTT
				if bq, ok := e.selector.BestQuality(p.NodeKey); ok {
					ps.LossRate = bq.LossRate
					ps.EffectiveCostMs = bq.EffectiveCostMs
				}
			case pathDecisionCenterRelay:
				if e.cryptoMgr.HasActiveSession(p.NodeKey) {
					ps.ActivePath = "relay"
					ps.RTTMillis = effRTT
				}
			}
			pr.mu.RLock()
			if ps.RTTMillis == 0 && pr.lastRTTMicros > 0 {
				ps.RTTMillis = float64(pr.lastRTTMicros) / 1000.0
			}
			pr.mu.RUnlock()
			ps.RxBytes = pr.rxBytes.Load()
			ps.TxBytes = pr.txBytes.Load()
		}
		peers = append(peers, ps)
	}
	e.mu.RUnlock()

	stateStr := "Stopped"
	if authorized {
		stateStr = "Running"
	} else if running {
		stateStr = "WaitingForControl"
	}
	gwPkts, _ := e.gateway.Stats()
	aclRules, aclDropIn, aclDropOut := e.pktFilter.Stats()
	relayMode := st.RelayMode
	if relayMode == "" {
		relayMode = types.RelayModeAuto
	}
	res := StatusResponse{
		State:              stateStr,
		TUNName:            e.tunDev.Name(),
		SelfName:           nm.Self.Name,
		SelfNodeKey:        st.NodeKey.Public().ShortString(),
		ServerURL:          st.ServerURL,
		ExitNode:           st.ExitNode,
		RelayMode:          relayMode,
		CanRelay:           e.effectiveCanRelay(),
		MaxRelayMbps:       st.MaxRelayMbps,
		RelayConnected:     authorized && e.relayCli.Connected(),
		CenterRelayRTTMs:   e.relayCli.RTTMillis(),
		PeerRelayedFrames:  e.peerRelayedFrames.Load(),
		PeerRelayedBytes:   e.peerRelayedBytes.Load(),
		GatewayProxiedPkts: gwPkts,
		ACLActiveRules:     aclRules,
		ACLDroppedIn:       aclDropIn,
		ACLDroppedOut:      aclDropOut,
		NATType:            natKind.String(),
		ActiveProtocols:    e.hub.LocalPorts(),
		MagicDNSSuffix:     nm.DNS.MagicDNSSuffix,
		Revision:           nm.Revision,
		Peers:              peers,
	}
	if nm.Self.IPv4.IsValid() {
		res.IPv4 = nm.Self.IPv4.String()
	}
	if nm.Self.IPv6.IsValid() {
		res.IPv6 = nm.Self.IPv6.String()
	}
	return res
}

// MeshStatus returns the computed Dijkstra multi-hop routing table and local transit statistics.
func (e *Engine) MeshStatus() MeshStatusReport {
	routes, names := e.meshRouter.AllRoutes()

	e.mu.RLock()
	ipByKey := make(map[types.PublicKey]string, len(e.netMap.Peers))
	for _, p := range e.netMap.Peers {
		if p.IPv4.IsValid() {
			ipByKey[p.NodeKey] = p.IPv4.String()
		}
	}
	e.mu.RUnlock()

	infos := make([]MeshRouteInfo, 0, len(routes))
	for _, rt := range routes {
		mode := "direct"
		if rt.IsPeerRelayed {
			mode = "peer-relay"
		}
		chain := make([]string, 0, len(rt.Hops))
		for _, hk := range rt.Hops {
			if n := names[hk]; n != "" {
				chain = append(chain, n)
			} else {
				chain = append(chain, hk.ShortString())
			}
		}
		nextName := names[rt.NextHop]
		if nextName == "" {
			nextName = rt.NextHop.ShortString()
		}
		targetName := names[rt.Destination]
		if targetName == "" {
			targetName = rt.Destination.ShortString()
		}
		infos = append(infos, MeshRouteInfo{
			TargetName:   targetName,
			TargetIPv4:   ipByKey[rt.Destination],
			Mode:         mode,
			NextHopName:  nextName,
			HopChain:     chain,
			EstRTTMillis: rt.TotalCostMs,
		})
	}
	return MeshStatusReport{
		CanRelay:          e.effectiveCanRelay(),
		PeerRelayedFrames: e.peerRelayedFrames.Load(),
		PeerRelayedBytes:  e.peerRelayedBytes.Load(),
		Routes:            infos,
	}
}

// NetCheck executes active STUN probes and compiles a local network & NAT diagnostic report.
func (e *Engine) NetCheck(ctx context.Context) NetCheckReport {
	e.sendSTUNProbes()
	e.relayCli.SendServerPing()
	select {
	case <-ctx.Done():
	case <-time.After(250 * time.Millisecond):
	}
	if !e.disableUDP && e.hub.HasProto(types.ProtoUDP) {
		kind, _, _, _ := e.natDetector.Snapshot()
		if kind == nat.KindUnknown {
			e.mu.RLock()
			hasSTUN := len(e.netMap.Relays) > 0 && e.netMap.Relays[0].STUNAddr != ""
			e.mu.RUnlock()
			if hasSTUN {
				e.natDetector.MarkUDPBlockedIfNoObservation()
			}
		}
	}
	uUDP, uTCP := e.portMapper.MappedAddrs()
	cands := e.collectLocalEndpoints()
	return NetCheckReport{
		NAT:              e.natDetector.FullSummary(uUDP, uTCP),
		RelayConnected:   e.relayCli.Connected(),
		CenterRelayRTTMs: e.relayCli.RTTMillis(),
		LocalTransports:  e.hub.LocalPorts(),
		CandidateCount:   len(cands),
		Candidates:       cands,
	}
}

// PingPeer sends an HMAC-authenticated overlay probe to target (server-assigned name, IP, or nodekey) and measures RTT.
func (e *Engine) PingPeer(ctx context.Context, target string) (*PingResult, error) {
	if !e.isRunning() {
		return nil, errors.New("engine is stopped")
	}
	target = strings.TrimSpace(strings.ToLower(target))
	pr, err := e.resolvePeer(target)
	if err != nil {
		return nil, err
	}

	pr.mu.RLock()
	peerKey := pr.meta.NodeKey
	pr.mu.RUnlock()

	probeID := cryptoRandUint64()
	replyCh := make(chan pingReply, 1)
	e.pingMu.Lock()
	e.pingWaiters[probeID] = pingWaiter{peerKey: peerKey, ch: replyCh}
	e.pingMu.Unlock()
	defer func() {
		e.pingMu.Lock()
		delete(e.pingWaiters, probeID)
		e.pingMu.Unlock()
	}()

	start := time.Now()
	pkt, err := e.buildAuthProbe(protocol.PacketPing, peerKey, probeID, start.UnixNano(), "")
	if err != nil {
		return nil, err
	}

	// 1. Probe direct candidate transports first (recording probeID so Pong is cryptographically bound!)
	cands := e.selector.AllCandidates(peerKey)
	for _, ep := range cands {
		if ep.Proto == types.ProtoUDP {
			if !e.disableUDP && e.hub.HasProto(types.ProtoUDP) {
				e.selector.RecordProbeSent(peerKey, ep, probeID)
				_ = e.sendPeerPacket(ctx, ep, pkt)
			}
			continue
		}
		if e.hub.HasProto(ep.Proto) {
			e.selector.RecordProbeSent(peerKey, ep, probeID)
			go func(targetEp types.Endpoint) {
				sCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				_ = e.sendPeerPacket(sCtx, targetEp, pkt)
			}(ep)
		}
	}

	meshTimer := time.NewTimer(40 * time.Millisecond)
	defer meshTimer.Stop()
	relayTimer := time.NewTimer(95 * time.Millisecond)
	defer relayTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-meshTimer.C:
			_ = e.sendViaPeerMesh(peerKey, pkt)
		case <-relayTimer.C:
			_ = e.relayCli.Send(peerKey, pkt)
			e.triggerCoordinatedHolePunch(pr)
		case w := <-replyCh:
			rtt := time.Since(start)
			pr.mu.Lock()
			pr.lastRTTMicros = rtt.Microseconds()
			meta := pr.meta
			pr.mu.Unlock()
			return &PingResult{
				TargetName: meta.Name,
				TargetIP:   meta.IPv4.String(),
				RTTMillis:  float64(rtt.Microseconds()) / 1000.0,
				Via:        w.via,
				Endpoint:   w.ep,
			}, nil
		}
	}
}

func (e *Engine) resolvePeer(target string) (*peerRuntime, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if ip, err := netip.ParseAddr(target); err == nil {
		if pr, ok := e.peersByIP[ip]; ok {
			return pr, nil
		}
	}
	suffix := "." + strings.ToLower(e.netMap.DNS.MagicDNSSuffix)
	cleanName := strings.TrimSuffix(target, suffix)
	for _, pr := range e.peersByKey {
		pr.mu.RLock()
		// Match ONLY server-assigned unique Name or NodeKey (never untrusted self-reported Hostname!)
		match := strings.EqualFold(pr.meta.Name, cleanName) ||
			strings.HasPrefix(strings.ToLower(pr.meta.NodeKey.String()), target)
		pr.mu.RUnlock()
		if match {
			return pr, nil
		}
	}
	return nil, fmt.Errorf("peer %q not found in NetMap", target)
}

func formatHopNames(hops []types.PublicKey, names map[types.PublicKey]string) string {
	parts := make([]string, 0, len(hops))
	for _, k := range hops {
		if n := names[k]; n != "" {
			parts = append(parts, n)
		} else {
			parts = append(parts, k.ShortString())
		}
	}
	return strings.Join(parts, " -> ")
}

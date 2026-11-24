package engine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/acktier/acktier/internal/daemon/crypto"
	"github.com/acktier/acktier/internal/daemon/nat"
	"github.com/acktier/acktier/internal/daemon/state"
	"github.com/acktier/acktier/internal/daemon/transport"
	"github.com/acktier/acktier/internal/daemon/tun"
	"github.com/acktier/acktier/pkg/protocol"
	"github.com/acktier/acktier/pkg/types"
)

// Options configures external transports, NAT helpers, and virtual NIC dependencies for Engine.
type Options struct {
	State              *state.Manager
	TUN                tun.Device
	Hub                *transport.Hub // Optional multi-transport hub (UDP/TCP/QUIC/WSS)
	UDPConn            net.PacketConn // Optional legacy/single UDP socket (auto-registered in Hub if Hub is nil)
	HTTPClient         *http.Client   // Optional HTTP client for Control Plane
	RelayDial          DialFunc       // Optional stream dialer for Relay Plane
	DisableUDP         bool           // Force disable direct UDP (testing / strict firewall simulation)
	EnableLANDiscovery bool           // Broadcast/listen for L2 LAN peer discovery beacons
	EnablePortMap      bool           // Attempt UPnP IGD / NAT-PMP automatic router port mapping
}

type peerRuntime struct {
	mu            sync.RWMutex
	meta          types.PeerNode
	lastHandshake time.Time
	lastPunch     time.Time
	lastRTTMicros int64
	rxBytes       atomic.Uint64
	txBytes       atomic.Uint64
}

// PeerStatus summarizes live connectivity and traffic telemetry for CLI / GUI display.
type PeerStatus struct {
	ID         types.NodeID   `json:"id"`
	Name       string         `json:"name"`
	Hostname   string         `json:"hostname"`
	OS         string         `json:"os"`
	NodeKey    string         `json:"nodeKey"`
	IPv4       string         `json:"ipv4"`
	IPv6       string         `json:"ipv6"`
	Online     bool           `json:"online"`
	ActivePath string         `json:"activePath"` // "direct-udp" | "direct-quic" | "direct-tcp" | "direct-wss" | "relay" | "idle"
	DirectAddr string         `json:"directAddr,omitempty"`
	RTTMillis  float64        `json:"rttMillis,omitempty"`
	RxBytes    uint64         `json:"rxBytes"`
	TxBytes    uint64         `json:"txBytes"`
	AllowedIPs []netip.Prefix `json:"allowedIPs,omitempty"`
}

// StatusResponse represents the full local daemon status returned over LocalAPI.
type StatusResponse struct {
	State           string                         `json:"state"` // "Running" | "Stopped"
	TUNName         string                         `json:"tunName"`
	SelfName        string                         `json:"selfName,omitempty"`
	SelfNodeKey     string                         `json:"selfNodeKey"`
	IPv4            string                         `json:"ipv4,omitempty"`
	IPv6            string                         `json:"ipv6,omitempty"`
	ServerURL       string                         `json:"serverUrl,omitempty"`
	RelayConnected  bool                           `json:"relayConnected"`
	NATType         string                         `json:"natType"`
	ActiveProtocols map[types.TransportProto]string `json:"activeProtocols,omitempty"`
	MagicDNSSuffix  string                         `json:"magicDNSSuffix,omitempty"`
	Revision        uint64                         `json:"revision"`
	Peers           []PeerStatus                   `json:"peers"`
}

// NetCheckReport returns comprehensive NAT, STUN, UPnP/NAT-PMP, Relay, and Multi-Transport diagnostics.
type NetCheckReport struct {
	NAT            nat.Summary                    `json:"nat"`
	RelayConnected bool                           `json:"relayConnected"`
	LocalTransports map[types.TransportProto]string `json:"localTransports"`
	CandidateCount int                            `json:"candidateCount"`
	Candidates     []types.Endpoint               `json:"candidates"`
}

// UpRequest parameters for bringing up the AckTier overlay network.
type UpRequest struct {
	ServerURL        string         `json:"serverUrl"`
	AuthKey          string         `json:"authKey,omitempty"`
	Hostname         string         `json:"hostname,omitempty"`
	AdvertisedRoutes []netip.Prefix `json:"advertisedRoutes,omitempty"`
	CanRelay         bool           `json:"canRelay,omitempty"`
}

// PingResult reports overlay probe latency and transport route.
type PingResult struct {
	TargetName string  `json:"targetName"`
	TargetIP   string  `json:"targetIP"`
	RTTMillis  float64 `json:"rttMillis"`
	Via        string  `json:"via"` // "direct-udp" | "direct-quic" | "direct-tcp" | "direct-wss" | "relay"
	Endpoint   string  `json:"endpoint,omitempty"`
}

type pingWaiter struct {
	via string
	ep  string
}

// Engine coordinates Control Plane sync, E2EE Crypto sessions, Multi-Transport selection, NAT Traversal, and TUN I/O.
type Engine struct {
	stateMgr           *state.Manager
	tunDev             tun.Device
	hub                *transport.Hub
	selector           *transport.Selector
	natDetector        *nat.Detector
	portMapper         *nat.PortMapper
	httpClient         *http.Client
	cryptoMgr          *crypto.Manager
	relayCli           *RelayClient
	disableUDP         bool
	enableLANDiscovery bool
	enablePortMap      bool

	mu         sync.RWMutex
	running    bool
	runCancel  context.CancelFunc
	netMap     types.NetMap
	peersByKey map[types.PublicKey]*peerRuntime
	peersByIP  map[netip.Addr]*peerRuntime
	routeTable []routeEntry

	probeSeq    atomic.Uint64
	pingMu      sync.Mutex
	pingWaiters map[uint64]chan pingWaiter

	closeOnce sync.Once
	closedCh  chan struct{}
}

type routeEntry struct {
	prefix netip.Prefix
	peer   *peerRuntime
}

func New(opts Options) (*Engine, error) {
	if opts.State == nil || opts.TUN == nil {
		return nil, errors.New("engine: State and TUN are required")
	}
	st := opts.State.Get()
	httpCli := opts.HTTPClient
	if httpCli == nil {
		httpCli = &http.Client{}
	}

	e := &Engine{
		stateMgr:           opts.State,
		tunDev:             opts.TUN,
		hub:                opts.Hub,
		selector:           transport.NewSelector(),
		natDetector:        nat.NewDetector(),
		portMapper:         nat.NewPortMapper(),
		httpClient:         httpCli,
		cryptoMgr:          crypto.NewManager(st.NodeKey),
		disableUDP:         opts.DisableUDP,
		enableLANDiscovery: opts.EnableLANDiscovery,
		enablePortMap:      opts.EnablePortMap,
		peersByKey:         make(map[types.PublicKey]*peerRuntime),
		peersByIP:          make(map[netip.Addr]*peerRuntime),
		pingWaiters:        make(map[uint64]chan pingWaiter),
		closedCh:           make(chan struct{}),
	}

	if e.hub == nil {
		e.hub = transport.NewHub()
	}
	if opts.UDPConn != nil && !opts.DisableUDP && !e.hub.HasProto(types.ProtoUDP) {
		e.hub.Register(transport.NewUDPDriver(opts.UDPConn, e.OnTransportPacket))
	}

	e.relayCli = NewRelayClient(opts.RelayDial, st.NodeKey.Public(), e.handleRelayedPacket)

	go e.tunReadLoop()
	return e, nil
}

// OnTransportPacket is the unified PacketHandler callback passed to all transport.Driver instances.
func (e *Engine) OnTransportPacket(pkt []byte, srcEp types.Endpoint) {
	if e.disableUDP && srcEp.Proto == types.ProtoUDP {
		return
	}
	e.handleIncomingWirePacket(pkt, srcEp, false, types.PublicKey{})
}

// Up authenticates with acktier-server, configures the virtual NIC, and starts background topology, NAT, & relay loops.
func (e *Engine) Up(ctx context.Context, req UpRequest) (*types.NetMap, error) {
	cur := e.stateMgr.Get()
	serverURL := strings.TrimRight(strings.TrimSpace(req.ServerURL), "/")
	if serverURL == "" {
		serverURL = cur.ServerURL
	}
	if serverURL == "" {
		return nil, errors.New("serverUrl is required")
	}
	hostname := strings.TrimSpace(req.Hostname)
	if hostname == "" {
		hostname = cur.Hostname
	}
	routes := req.AdvertisedRoutes
	if routes == nil {
		routes = cur.AdvertisedRoutes
	}

	if e.enablePortMap {
		e.refreshPortMappings(ctx)
	}

	endpoints := e.collectLocalEndpoints()
	regReq := types.RegisterRequest{
		MachineKey:       cur.MachineKey.Public(),
		NodeKey:          cur.NodeKey.Public(),
		AuthKey:          strings.TrimSpace(req.AuthKey),
		Hostname:         hostname,
		OS:               runtime.GOOS,
		Endpoints:        endpoints,
		AdvertisedRoutes: routes,
		CanRelay:         req.CanRelay,
	}

	bodyBytes, _ := json.Marshal(regReq)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/v1/node/register", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if cur.NodeToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+cur.NodeToken)
	}

	resp, err := e.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("register with %s: %w", serverURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("register failed (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var regResp types.RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return nil, fmt.Errorf("decode register response: %w", err)
	}

	_ = e.stateMgr.Update(func(s *state.ConfigState) {
		s.ServerURL = serverURL
		s.NodeToken = regResp.NodeToken
		s.Hostname = hostname
		s.AdvertisedRoutes = routes
		s.CanRelay = req.CanRelay
		s.WantRunning = true
	})

	e.Down()
	e.applyNetMap(regResp.NetMap)

	runCtx, cancel := context.WithCancel(context.Background())
	e.mu.Lock()
	e.running = true
	e.runCancel = cancel
	e.mu.Unlock()

	if len(regResp.NetMap.Relays) > 0 {
		r0 := regResp.NetMap.Relays[0]
		e.natDetector.SetSTUNServers(r0.STUNAddr, r0.STUNAltAddr)
		if r0.RelayAddr != "" {
			go e.relayCli.Run(runCtx, r0.RelayAddr, regResp.NodeToken)
		}
	}
	if e.enableLANDiscovery {
		ld := nat.NewLANDiscovery(cur.NodeKey.Public(), e.hub.LocalPorts, func(peerKey types.PublicKey, eps []types.Endpoint) {
			if e.getPeerRuntime(peerKey) != nil {
				e.selector.SetCandidates(peerKey, eps)
				e.probePeerCandidates(peerKey, eps)
			}
		})
		go ld.Run(runCtx)
	}
	go e.mapStreamLoop(runCtx, serverURL, regResp.NodeToken)
	go e.maintenanceLoop(runCtx, serverURL, regResp.NodeToken)

	return &regResp.NetMap, nil
}

// Down disconnects control stream and relay sessions while keeping the daemon alive.
func (e *Engine) Down() {
	e.mu.Lock()
	cancel := e.runCancel
	e.runCancel = nil
	e.running = false
	e.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	_ = e.stateMgr.Update(func(s *state.ConfigState) {
		s.WantRunning = false
	})
}

func (e *Engine) Close() error {
	e.Down()
	e.closeOnce.Do(func() {
		close(e.closedCh)
		_ = e.hub.Close()
		_ = e.tunDev.Close()
	})
	return nil
}

func (e *Engine) Status() StatusResponse {
	st := e.stateMgr.Get()
	natKind, _, _, _ := e.natDetector.Snapshot()

	e.mu.RLock()
	running := e.running
	nm := e.netMap
	peers := make([]PeerStatus, 0, len(nm.Peers))
	for _, p := range nm.Peers {
		pr := e.peersByKey[p.NodeKey]
		ps := PeerStatus{
			ID:         p.ID,
			Name:       p.Name,
			Hostname:   p.Hostname,
			OS:         p.OS,
			NodeKey:    p.NodeKey.ShortString(),
			Online:     p.Online,
			AllowedIPs: p.AllowedIPs,
			ActivePath: "idle",
		}
		if p.IPv4.IsValid() {
			ps.IPv4 = p.IPv4.String()
		}
		if p.IPv6.IsValid() {
			ps.IPv6 = p.IPv6.String()
		}
		if pr != nil {
			if bestEp, bestRTT, ok := e.selector.BestEndpoint(p.NodeKey); ok {
				ps.ActivePath = "direct-" + string(bestEp.Proto)
				ps.DirectAddr = bestEp.Addr
				if bestRTT > 0 {
					ps.RTTMillis = bestRTT
				}
			} else if e.cryptoMgr.HasActiveSession(p.NodeKey) && e.relayCli.Connected() {
				ps.ActivePath = "relay"
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
	if running {
		stateStr = "Running"
	}
	res := StatusResponse{
		State:           stateStr,
		TUNName:         e.tunDev.Name(),
		SelfName:        nm.Self.Name,
		SelfNodeKey:     st.NodeKey.Public().ShortString(),
		ServerURL:       st.ServerURL,
		RelayConnected:  e.relayCli.Connected(),
		NATType:         natKind.String(),
		ActiveProtocols: e.hub.LocalPorts(),
		MagicDNSSuffix:  nm.DNS.MagicDNSSuffix,
		Revision:        nm.Revision,
		Peers:           peers,
	}
	if nm.Self.IPv4.IsValid() {
		res.IPv4 = nm.Self.IPv4.String()
	}
	if nm.Self.IPv6.IsValid() {
		res.IPv6 = nm.Self.IPv6.String()
	}
	return res
}

// NetCheck executes active STUN probes and compiles a local network & NAT diagnostic report.
func (e *Engine) NetCheck(ctx context.Context) NetCheckReport {
	e.sendSTUNProbes()
	select {
	case <-ctx.Done():
	case <-time.After(250 * time.Millisecond):
	}
	if !e.disableUDP && e.hub.HasProto(types.ProtoUDP) {
		kind, _, _, _ := e.natDetector.Snapshot()
		if kind == nat.KindUnknown {
			// Check if STUN server was configured; if so and no reply arrived, mark UDP blocked
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
		NAT:             e.natDetector.FullSummary(uUDP, uTCP),
		RelayConnected:  e.relayCli.Connected(),
		LocalTransports: e.hub.LocalPorts(),
		CandidateCount:  len(cands),
		Candidates:      cands,
	}
}

// PingPeer sends an authenticated overlay probe to target (name or IP) and measures round-trip latency.
func (e *Engine) PingPeer(ctx context.Context, target string) (*PingResult, error) {
	target = strings.TrimSpace(strings.ToLower(target))
	pr, err := e.resolvePeer(target)
	if err != nil {
		return nil, err
	}

	probeID := e.probeSeq.Add(1)
	waitCh := make(chan pingWaiter, 1)
	e.pingMu.Lock()
	e.pingWaiters[probeID] = waitCh
	e.pingMu.Unlock()
	defer func() {
		e.pingMu.Lock()
		delete(e.pingWaiters, probeID)
		e.pingMu.Unlock()
	}()

	start := time.Now()
	st := e.stateMgr.Get()
	pkt := protocol.EncodeProbePacket(protocol.PacketPing, st.NodeKey.Public(), probeID, start.UnixNano(), "")

	pr.mu.RLock()
	peerKey := pr.meta.NodeKey
	pr.mu.RUnlock()

	// 1. Probe direct candidate transports first (UDP synchronously for zero-goroutine-lag, stream protos concurrently)
	cands := e.selector.AllCandidates(peerKey)
	for _, ep := range cands {
		if ep.Proto == types.ProtoUDP {
			if !e.disableUDP && e.hub.HasProto(types.ProtoUDP) {
				_ = e.hub.Send(ctx, ep, pkt)
			}
			continue
		}
		if e.hub.HasProto(ep.Proto) {
			go func(targetEp types.Endpoint) {
				sCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				_ = e.hub.Send(sCtx, targetEp, pkt)
			}(ep)
		}
	}

	// Give direct paths a brief 80ms head start before falling back to Relay probe
	relayTimer := time.NewTimer(80 * time.Millisecond)
	defer relayTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-relayTimer.C:
			_ = e.relayCli.Send(peerKey, pkt)
			e.triggerCoordinatedHolePunch(pr)
		case w := <-waitCh:
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
		match := strings.EqualFold(pr.meta.Name, cleanName) ||
			strings.EqualFold(pr.meta.Hostname, cleanName) ||
			strings.HasPrefix(strings.ToLower(pr.meta.NodeKey.String()), target)
		pr.mu.RUnlock()
		if match {
			return pr, nil
		}
	}
	return nil, fmt.Errorf("peer %q not found in NetMap", target)
}

func (e *Engine) applyNetMap(nm types.NetMap) {
	authKeys := make([]types.PublicKey, 0, len(nm.Peers))
	for _, p := range nm.Peers {
		authKeys = append(authKeys, p.NodeKey)
	}
	e.cryptoMgr.SetAuthorizedPeers(authKeys)

	var extraRoutes []netip.Prefix

	e.mu.Lock()
	prevPeers := e.peersByKey
	newByKey := make(map[types.PublicKey]*peerRuntime, len(nm.Peers))
	newByIP := make(map[netip.Addr]*peerRuntime, len(nm.Peers)*2)
	var newRoutes []routeEntry

	for _, p := range nm.Peers {
		pr, exists := prevPeers[p.NodeKey]
		if !exists {
			pr = &peerRuntime{}
		}
		pr.mu.Lock()
		pr.meta = p
		pr.mu.Unlock()

		e.selector.SetCandidates(p.NodeKey, p.Endpoints)

		newByKey[p.NodeKey] = pr
		if p.IPv4.IsValid() {
			newByIP[p.IPv4] = pr
		}
		if p.IPv6.IsValid() {
			newByIP[p.IPv6] = pr
		}
		for _, rt := range p.ApprovedRoutes {
			newRoutes = append(newRoutes, routeEntry{prefix: rt, peer: pr})
			extraRoutes = append(extraRoutes, rt)
		}
	}

	prevSelfV4 := e.netMap.Self.IPv4
	e.netMap = nm
	e.peersByKey = newByKey
	e.peersByIP = newByIP
	e.routeTable = newRoutes
	e.mu.Unlock()

	if len(nm.Relays) > 0 {
		e.natDetector.SetSTUNServers(nm.Relays[0].STUNAddr, nm.Relays[0].STUNAltAddr)
	}

	if nm.Self.IPv4.IsValid() && nm.Self.IPv4 != prevSelfV4 {
		v4Pfx := netip.PrefixFrom(nm.Self.IPv4, 10)
		var v6Pfx netip.Prefix
		if nm.Self.IPv6.IsValid() {
			v6Pfx = netip.PrefixFrom(nm.Self.IPv6, 48)
		}
		if err := e.tunDev.Configure(v4Pfx, v6Pfx, extraRoutes); err != nil {
			log.Printf("[engine] warning configuring TUN %s: %v", e.tunDev.Name(), err)
		}
	}
}

func (e *Engine) lookupPeerByDstIP(dst netip.Addr) *peerRuntime {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if pr, ok := e.peersByIP[dst]; ok {
		return pr
	}
	var best *peerRuntime
	bestBits := -1
	for _, re := range e.routeTable {
		if re.prefix.Contains(dst) && re.prefix.Bits() > bestBits {
			best = re.peer
			bestBits = re.prefix.Bits()
		}
	}
	return best
}

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
		if n < 20 {
			continue
		}
		pkt := buf[:n]
		dstIP, ok := tun.ExtractDstIP(pkt)
		if !ok {
			continue
		}
		pr := e.lookupPeerByDstIP(dstIP)
		if pr == nil {
			continue
		}
		pr.mu.RLock()
		peerKey := pr.meta.NodeKey
		pr.mu.RUnlock()

		wirePkt, err := e.cryptoMgr.SealPacket(peerKey, pkt)
		if err == nil {
			pr.txBytes.Add(uint64(len(pkt)))
			e.sendWireToPeer(pr, wirePkt)
			continue
		}

		// Session not yet established: queue packet, coordinate hole-punch, and send 1-RTT Noise handshake
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
}

func (e *Engine) handleRelayedPacket(src types.PublicKey, inner []byte) {
	cp := make([]byte, len(inner))
	copy(cp, inner)
	e.handleIncomingWirePacket(cp, types.Endpoint{}, true, src)
}

func (e *Engine) handleIncomingWirePacket(pkt []byte, srcEp types.Endpoint, viaRelay bool, relaySrc types.PublicKey) {
	pType, _, _, err := protocol.ParseHeader(pkt)
	if err != nil {
		return
	}

	switch pType {
	case protocol.PacketHandshakeInit:
		peerKey, ackPkt, queued, err := e.cryptoMgr.HandleHandshakeInit(pkt)
		if err != nil {
			return
		}
		pr := e.getPeerRuntime(peerKey)
		if pr == nil {
			return
		}
		if !viaRelay && srcEp.Addr != "" {
			e.selector.RecordRx(peerKey, srcEp, 0)
			_ = e.hub.Send(context.Background(), srcEp, ackPkt)
		} else if viaRelay {
			_ = e.relayCli.Send(peerKey, ackPkt)
		}
		e.flushQueuedPackets(pr, peerKey, queued)

	case protocol.PacketHandshakeAck:
		peerKey, queued, err := e.cryptoMgr.HandleHandshakeAck(pkt)
		if err != nil {
			return
		}
		pr := e.getPeerRuntime(peerKey)
		if pr == nil {
			return
		}
		if !viaRelay && srcEp.Addr != "" {
			e.selector.RecordRx(peerKey, srcEp, 0)
		}
		e.flushQueuedPackets(pr, peerKey, queued)

	case protocol.PacketData:
		peerKey, plainIP, err := e.cryptoMgr.OpenPacket(pkt)
		if err != nil {
			return
		}
		if pr := e.getPeerRuntime(peerKey); pr != nil {
			pr.rxBytes.Add(uint64(len(plainIP)))
			if !viaRelay && srcEp.Addr != "" {
				e.selector.RecordRx(peerKey, srcEp, 0)
			}
		}
		_ = e.tunDev.WritePacket(plainIP)

	case protocol.PacketPunchCoord:
		sender, isReply, peerNATKind, peerStep, peerEps, err := protocol.DecodePunchCoord(pkt)
		if err != nil {
			return
		}
		if viaRelay && relaySrc != sender {
			return // Prevent spoofed sender inside RelayForward
		}
		if e.getPeerRuntime(sender) == nil {
			return
		}
		e.selector.SetCandidates(sender, peerEps)
		// Exchange our own freshest STUN/local endpoints back to initiator so BOTH stateful NATs punch simultaneously!
		if !isReply {
			kind, step, _, _ := e.natDetector.Snapshot()
			myEps := e.collectLocalEndpoints()
			replyCoord := protocol.EncodePunchCoord(e.cryptoMgr.LocalPublicKey(), true, byte(kind), step, myEps)
			_ = e.relayCli.Send(sender, replyCoord)
		}
		go e.executePunchBurst(sender, peerEps, nat.Kind(peerNATKind), peerStep)

	case protocol.PacketPing:
		_, sender, probeID, txNano, _, err := protocol.DecodeProbePacket(pkt)
		if err != nil {
			return
		}
		st := e.stateMgr.Get()
		obs := ""
		if !viaRelay {
			obs = srcEp.Addr
		}
		pong := protocol.EncodeProbePacket(protocol.PacketPong, st.NodeKey.Public(), probeID, txNano, obs)
		if !viaRelay && srcEp.Addr != "" {
			_ = e.hub.Send(context.Background(), srcEp, pong)
		} else if viaRelay && !relaySrc.IsZero() {
			_ = e.relayCli.Send(sender, pong)
		}

	case protocol.PacketPong:
		_, sender, probeID, txNano, obs, err := protocol.DecodeProbePacket(pkt)
		if err != nil {
			return
		}
		rtt := time.Since(time.Unix(0, txNano))
		// STUN reflection response from server
		if sender == e.cryptoMgr.LocalPublicKey() && obs != "" {
			e.natDetector.RecordObservation(srcEp.Addr, obs, rtt, localInterfaceIPs())
			return
		}

		pr := e.getPeerRuntime(sender)
		if pr != nil {
			pr.mu.Lock()
			pr.lastRTTMicros = rtt.Microseconds()
			pr.mu.Unlock()
			if !viaRelay && srcEp.Addr != "" {
				e.selector.RecordRx(sender, srcEp, rtt)
			}
		}

		via := "relay"
		ep := "relay"
		if !viaRelay && srcEp.Addr != "" {
			via = "direct-" + string(srcEp.Proto)
			ep = srcEp.Addr
		}
		e.pingMu.Lock()
		ch, ok := e.pingWaiters[probeID]
		e.pingMu.Unlock()
		if ok {
			select {
			case ch <- pingWaiter{via: via, ep: ep}:
			default:
			}
		}
	}
}

func (e *Engine) flushQueuedPackets(pr *peerRuntime, peerKey types.PublicKey, queued [][]byte) {
	for _, ipPkt := range queued {
		if wirePkt, err := e.cryptoMgr.SealPacket(peerKey, ipPkt); err == nil {
			pr.txBytes.Add(uint64(len(ipPkt)))
			e.sendWireToPeer(pr, wirePkt)
		}
	}
}

func (e *Engine) getPeerRuntime(key types.PublicKey) *peerRuntime {
	e.mu.RLock()
	pr := e.peersByKey[key]
	e.mu.RUnlock()
	return pr
}

// sendWireToPeer dispatches encrypted data over the highest-scoring verified direct transport,
// or falls back immediately to Relay while triggering background coordinated hole-punching & multi-transport probing.
func (e *Engine) sendWireToPeer(pr *peerRuntime, wirePkt []byte) {
	pr.mu.RLock()
	peerKey := pr.meta.NodeKey
	pr.mu.RUnlock()

	if bestEp, _, ok := e.selector.BestEndpoint(peerKey); ok {
		if !(e.disableUDP && bestEp.Proto == types.ProtoUDP) {
			if err := e.hub.Send(context.Background(), bestEp, wirePkt); err == nil {
				return
			}
		}
	}

	// Zero-wait Relay fallback + background path discovery
	_ = e.relayCli.Send(peerKey, wirePkt)
	e.triggerCoordinatedHolePunch(pr)
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
		coordPkt := protocol.EncodePunchCoord(e.cryptoMgr.LocalPublicKey(), false, byte(kind), step, myEps)
		_ = e.relayCli.Send(peerKey, coordPkt)

		cands := e.selector.AllCandidates(peerKey)
		e.executePunchBurst(peerKey, cands, nat.KindUnknown, 0)
	}()
}

func (e *Engine) executePunchBurst(peerKey types.PublicKey, cands []types.Endpoint, peerKind nat.Kind, peerStep int16) {
	localPub := e.cryptoMgr.LocalPublicKey()

	// 1. Multi-round UDP Hole-Punch burst (allows bilateral NAT pinhole overlap even across ~80ms Relay RTT)
	if !e.disableUDP && e.hub.HasProto(types.ProtoUDP) {
		udpTargets := nat.BuildUDPPunchTargets(cands, peerKind, peerStep)
		for round := 0; round < 3; round++ {
			now := time.Now().UnixNano()
			for _, addr := range udpTargets {
				probe := protocol.EncodeProbePacket(protocol.PacketPing, localPub, e.probeSeq.Add(1), now, "")
				_ = e.hub.Send(context.Background(), types.Endpoint{Proto: types.ProtoUDP, Addr: addr}, probe)
			}
			if round < 2 && len(udpTargets) > 0 {
				time.Sleep(40 * time.Millisecond)
			}
		}
	}

	// 2. Probe alternative protocols (QUIC, TCP, WSS) in parallel
	e.probePeerCandidates(peerKey, cands)
}

func (e *Engine) probePeerCandidates(_ types.PublicKey, cands []types.Endpoint) {
	localPub := e.cryptoMgr.LocalPublicKey()
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
			probe := protocol.EncodeProbePacket(protocol.PacketPing, localPub, e.probeSeq.Add(1), time.Now().UnixNano(), "")
			_ = e.hub.Send(ctx, targetEp, probe)
		}(ep)
	}
}

// sendControlOrProbeToPeer dispatches handshakes and CLI pings across all candidate transports + Relay simultaneously.
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
			_ = e.hub.Send(ctx, targetEp, pkt)
		}(ep)
	}
	_ = e.relayCli.Send(peerKey, pkt)
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

func (e *Engine) mapStreamLoop(ctx context.Context, serverURL, token string) {
	st := e.stateMgr.Get()
	streamURL := fmt.Sprintf("%s/api/v1/node/map/stream?nodeKey=%s", serverURL, st.NodeKey.Public().String())

	backoff := 300 * time.Millisecond
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, streamURL, nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := e.httpClient.Do(req)
			if err == nil && resp.StatusCode == http.StatusOK {
				backoff = 300 * time.Millisecond
				scanner := bufio.NewScanner(resp.Body)
				scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
				for scanner.Scan() {
					var ev types.MapStreamEvent
					if json.Unmarshal(scanner.Bytes(), &ev) == nil && ev.Type == "netmap" && ev.NetMap != nil {
						e.applyNetMap(*ev.NetMap)
					}
				}
				_ = resp.Body.Close()
			} else if resp != nil {
				_ = resp.Body.Close()
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 5*time.Second {
			backoff *= 2
		}
	}
}

func (e *Engine) maintenanceLoop(ctx context.Context, serverURL, token string) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	e.sendSTUNProbes()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.sendSTUNProbes()
			if e.enablePortMap {
				e.refreshPortMappings(ctx)
			}
			// Re-probe online peers to keep EWMA RTT fresh and upgrade Relay -> Direct automatically
			e.mu.RLock()
			peers := make([]types.PublicKey, 0, len(e.peersByKey))
			for k, pr := range e.peersByKey {
				pr.mu.RLock()
				online := pr.meta.Online
				pr.mu.RUnlock()
				if online {
					peers = append(peers, k)
				}
			}
			e.mu.RUnlock()
			for _, pk := range peers {
				e.probePeerCandidates(pk, e.selector.AllCandidates(pk))
			}

			st := e.stateMgr.Get()
			hb := types.HeartbeatRequest{
				NodeKey:          st.NodeKey.Public(),
				Endpoints:        e.collectLocalEndpoints(),
				AdvertisedRoutes: st.AdvertisedRoutes,
				CanRelay:         st.CanRelay,
			}
			raw, _ := json.Marshal(hb)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/v1/node/heartbeat", bytes.NewReader(raw))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+token)
			if resp, err := e.httpClient.Do(req); err == nil {
				_ = resp.Body.Close()
			}
		}
	}
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
		pkt := protocol.EncodeProbePacket(protocol.PacketPing, e.cryptoMgr.LocalPublicKey(), e.probeSeq.Add(1), time.Now().UnixNano(), "")
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

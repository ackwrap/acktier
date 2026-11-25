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
	"github.com/acktier/acktier/internal/daemon/dns"
	"github.com/acktier/acktier/internal/daemon/filter"
	"github.com/acktier/acktier/internal/daemon/mesh"
	"github.com/acktier/acktier/internal/daemon/nat"
	"github.com/acktier/acktier/internal/daemon/netstack"
	"github.com/acktier/acktier/internal/daemon/state"
	"github.com/acktier/acktier/internal/daemon/transport"
	"github.com/acktier/acktier/internal/daemon/tun"
	"github.com/acktier/acktier/pkg/protocol"
	"github.com/acktier/acktier/pkg/types"
)

type incomingSource byte

const (
	sourceDirect incomingSource = iota
	sourcePeerRelay
	sourceCenterRelay
)

// Options configures external transports, NAT helpers, and virtual NIC dependencies for Engine.
type Options struct {
	State              *state.Manager
	TUN                tun.Device
	Hub                *transport.Hub // Optional multi-transport hub (UDP/TCP/QUIC/WSS)
	UDPConn            net.PacketConn          // Optional single UDP socket (auto-registered in Hub if Hub is nil)
	HTTPClient         *http.Client            // Optional HTTP client for Control Plane
	RelayDial          DialFunc                // Optional stream dialer for Relay Plane
	GatewayTCPDial     netstack.DialStreamFunc // Optional outbound TCP dialer for Subnet Router / Exit Node
	GatewayUDPDial     netstack.DialPacketFunc // Optional outbound UDP dialer for Subnet Router / Exit Node
	DisableUDP          bool                    // Force disable direct UDP (testing / strict firewall simulation)
	EnableLANDiscovery  bool                    // Broadcast/listen for L2 LAN peer discovery beacons
	EnablePortMap       bool                    // Attempt UPnP IGD / NAT-PMP automatic router port mapping
	EnableNetMonitor    bool                    // Watch host NIC/IP changes for instant roaming notification
	BlackholeProbeAfter time.Duration           // Active-tx unanswered duration before fast probe (default 2.5s)
	BlackholeTimeout    time.Duration           // Active-tx unanswered duration before declaring direct path dead (default 4.5s)
	NetMonitorInterval  time.Duration           // Interface change poll interval (default 1.5s)
}

const centerRelayPenaltyMs = 6.0

type peerRuntime struct {
	mu                   sync.RWMutex
	meta                 types.PeerNode
	lastHandshake        time.Time
	lastPunch            time.Time
	lastPeerRelayRx      time.Time // Symmetric stepping-stone return stickiness when peer routes to us via Peer Relay
	lastRTTMicros        int64
	lastCenterRelayRTTUs int64
	rxBytes              atomic.Uint64
	txBytes              atomic.Uint64
}

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
	TargetName    string   `json:"targetName"`
	TargetIPv4    string   `json:"targetIpv4"`
	Mode          string   `json:"mode"` // "direct" | "peer-relay"
	NextHopName   string   `json:"nextHopName"`
	HopChain      []string `json:"hopChain"`
	EstRTTMillis  float64  `json:"estRttMillis"`
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

// UpRequest parameters for bringing up the AckTier overlay network.
type UpRequest struct {
	ServerURL        string          `json:"serverUrl"`
	AuthKey          string          `json:"authKey,omitempty"`
	Hostname         string          `json:"hostname,omitempty"`
	AdvertisedRoutes []netip.Prefix  `json:"advertisedRoutes,omitempty"`
	ExitNode         string          `json:"exitNode,omitempty"`
	RelayMode        types.RelayMode `json:"relayMode,omitempty"` // "auto" (default) | "on" | "off"
	MaxRelayMbps     float64         `json:"maxRelayMbps,omitempty"`
	CanRelay         bool            `json:"canRelay,omitempty"`
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
	via string
	ep  string
}

// Engine coordinates Control Plane sync, E2EE Crypto sessions, Multi-Transport, NAT Traversal, Smart Mesh Relay, and TUN I/O.
type Engine struct {
	stateMgr           *state.Manager
	tunDev             tun.Device
	hub                *transport.Hub
	selector           *transport.Selector
	meshRouter         *mesh.Router
	natDetector        *nat.Detector
	portMapper         *nat.PortMapper
	pktFilter          *filter.Engine
	dnsResolver        *dns.Resolver
	gateway            *netstack.Gateway
	httpClient         *http.Client
	cryptoMgr          *crypto.Manager
	relayCli           *RelayClient
	disableUDP         bool
	enableLANDiscovery bool
	enablePortMap      bool
	enableNetMonitor   bool
	netMonInterval     time.Duration

	mu                 sync.RWMutex
	running            bool
	runCancel          context.CancelFunc
	netMap             types.NetMap
	peersByKey         map[types.PublicKey]*peerRuntime
	peersByIP          map[netip.Addr]*peerRuntime
	routeTable         []routeEntry
	exitNodePeer       *peerRuntime
	selfApprovedRoutes []netip.Prefix

	hbTriggerCh       chan struct{}
	peerRelayedFrames atomic.Uint64
	peerRelayedBytes  atomic.Uint64
	rlMu              sync.Mutex
	rlTokens          float64
	rlLastRefill      time.Time

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
		meshRouter:         mesh.NewRouter(st.NodeKey.Public()),
		natDetector:        nat.NewDetector(),
		portMapper:         nat.NewPortMapper(),
		pktFilter:          filter.New(),
		dnsResolver:        dns.NewResolver(),
		httpClient:         httpCli,
		cryptoMgr:          crypto.NewManager(st.NodeKey),
		disableUDP:         opts.DisableUDP,
		enableLANDiscovery: opts.EnableLANDiscovery,
		enablePortMap:      opts.EnablePortMap,
		enableNetMonitor:   opts.EnableNetMonitor,
		netMonInterval:     opts.NetMonitorInterval,
		peersByKey:         make(map[types.PublicKey]*peerRuntime),
		peersByIP:          make(map[netip.Addr]*peerRuntime),
		hbTriggerCh:        make(chan struct{}, 1),
		pingWaiters:        make(map[uint64]chan pingWaiter),
		closedCh:           make(chan struct{}),
	}

	if opts.BlackholeProbeAfter > 0 || opts.BlackholeTimeout > 0 {
		e.selector.SetBlackholeThresholds(opts.BlackholeProbeAfter, opts.BlackholeTimeout)
	}
	if e.hub == nil {
		e.hub = transport.NewHub()
	}
	if opts.UDPConn != nil && !opts.DisableUDP && !e.hub.HasProto(types.ProtoUDP) {
		e.hub.Register(transport.NewUDPDriver(opts.UDPConn, e.OnTransportPacket))
	}

	e.gateway = netstack.NewGateway(opts.GatewayTCPDial, opts.GatewayUDPDial, e.sendPlainPacketToOverlay)
	e.relayCli = NewRelayClient(opts.RelayDial, st.NodeKey.Public(), e.handleCenterRelayedPacket)

	go e.tunReadLoop()
	return e, nil
}

// OnTransportPacket is the unified PacketHandler callback passed to all transport.Driver instances.
func (e *Engine) OnTransportPacket(pkt []byte, srcEp types.Endpoint) {
	if e.disableUDP && srcEp.Proto == types.ProtoUDP {
		return
	}
	e.handleIncomingWirePacket(pkt, srcEp, sourceDirect, types.PublicKey{})
}

// Up authenticates with acktier-server, configures the virtual NIC, and starts background topology, NAT, & mesh loops.
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

	relayMode := req.RelayMode
	if relayMode == "" {
		if req.CanRelay {
			relayMode = types.RelayModeOn
		} else if cur.RelayMode != "" {
			relayMode = cur.RelayMode
		} else if cur.CanRelay {
			relayMode = types.RelayModeOn
		} else {
			relayMode = types.RelayModeAuto
		}
	}
	maxMbps := req.MaxRelayMbps
	if maxMbps == 0 && cur.MaxRelayMbps > 0 {
		maxMbps = cur.MaxRelayMbps
	}

	if e.enablePortMap {
		e.refreshPortMappings(ctx)
	}

	_ = e.stateMgr.Update(func(s *state.ConfigState) {
		s.RelayMode = relayMode
		s.MaxRelayMbps = maxMbps
		s.CanRelay = (relayMode == types.RelayModeOn)
	})

	endpoints := e.collectLocalEndpoints()
	canRelay := e.effectiveCanRelay()
	regReq := types.RegisterRequest{
		MachineKey:       cur.MachineKey.Public(),
		NodeKey:          cur.NodeKey.Public(),
		AuthKey:          strings.TrimSpace(req.AuthKey),
		Hostname:         hostname,
		OS:               runtime.GOOS,
		Endpoints:        endpoints,
		AdvertisedRoutes: routes,
		CanRelay:         canRelay,
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
		if req.ExitNode != "" {
			if req.ExitNode == "none" {
				s.ExitNode = ""
			} else {
				s.ExitNode = req.ExitNode
			}
		}
		s.RelayMode = relayMode
		s.MaxRelayMbps = maxMbps
		s.CanRelay = canRelay
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
	if e.enableNetMonitor {
		nmMon := nat.NewNetMonitor(e.tunDev.Name(), e.netMonInterval, func(prev, curr string) {
			log.Printf("[engine] host network change detected (%s -> %s); roaming endpoints...", prev, curr)
			e.NotifyNetworkChange()
		})
		go nmMon.Run(runCtx)
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
		_ = e.gateway.Close()
		_ = e.hub.Close()
		_ = e.tunDev.Close()
	})
	return nil
}

// SetExitNode dynamically switches or clears ("none" / "") the client's active global Exit Node.
func (e *Engine) SetExitNode(target string) error {
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
	if nm.Self.ID != 0 {
		e.applyNetMap(nm)
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

// NotifyNetworkChange immediately refreshes STUN/port-mappings, pushes a new Heartbeat to Control,
// and actively sends roaming probes to all online peers when the host switches Wi-Fi / cellular networks.
func (e *Engine) NotifyNetworkChange() {
	e.mu.RLock()
	running := e.running
	peers := make([]*peerRuntime, 0, len(e.peersByKey))
	for _, pr := range e.peersByKey {
		peers = append(peers, pr)
	}
	e.mu.RUnlock()
	if !running {
		return
	}

	e.natDetector.ResetObservations()
	e.selector.OnLocalNetworkChange()
	e.sendSTUNProbes()
	e.relayCli.SendServerPing()

	go func() {
		// Allow brief window for STUN Pong to record new WAN IP:Port before advertising
		time.Sleep(50 * time.Millisecond)
		e.requestImmediateHeartbeat()

		for _, pr := range peers {
			pr.mu.Lock()
			online := pr.meta.Online
			peerKey := pr.meta.NodeKey
			pr.lastPunch = time.Time{} // bypass 2s punch cooldown on network switch!
			pr.mu.Unlock()
			if !online {
				continue
			}
			e.triggerCoordinatedHolePunch(pr)
			e.probePeerCandidates(peerKey, e.selector.AllCandidates(peerKey))
		}
	}()
}

func (e *Engine) Status() StatusResponse {
	st := e.stateMgr.Get()
	natKind, _, _, _ := e.natDetector.Snapshot()
	_, namesMap := e.meshRouter.AllRoutes()

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
			CanRelay:   p.CanRelay,
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
	if running {
		stateStr = "Running"
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
		RelayConnected:     e.relayCli.Connected(),
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

	// 1. Probe direct candidate transports first (UDP synchronously, stream protos concurrently)
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

	// 2. If a verified Peer-Relay mesh path exists and no direct link is verified yet, probe via Peer Mesh after 40ms
	meshTimer := time.NewTimer(40 * time.Millisecond)
	defer meshTimer.Stop()
	// 3. Fallback to Center Relay after 95ms
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
	e.pktFilter.SetRules(nm.PacketFilter)
	e.dnsResolver.UpdateNetMap(nm)

	wantExit := strings.ToLower(strings.TrimSpace(e.stateMgr.Get().ExitNode))
	var extraRoutes []netip.Prefix
	var newlyAddedPeers []types.PeerNode

	e.mu.Lock()
	prevPeers := e.peersByKey
	newByKey := make(map[types.PublicKey]*peerRuntime, len(nm.Peers))
	newByIP := make(map[netip.Addr]*peerRuntime, len(nm.Peers)*2)
	var newRoutes []routeEntry
	var selectedExit *peerRuntime

	for _, p := range nm.Peers {
		pr, exists := prevPeers[p.NodeKey]
		if !exists {
			pr = &peerRuntime{}
			if p.Online {
				newlyAddedPeers = append(newlyAddedPeers, p)
			}
		}
		pr.mu.Lock()
		pr.meta = p
		pr.mu.Unlock()

		e.selector.SyncCandidates(p.NodeKey, p.Endpoints)

		newByKey[p.NodeKey] = pr
		if p.IPv4.IsValid() {
			newByIP[p.IPv4] = pr
		}
		if p.IPv6.IsValid() {
			newByIP[p.IPv6] = pr
		}
		hasDefaultRoute := false
		for _, rt := range p.ApprovedRoutes {
			if rt.Bits() == 0 {
				hasDefaultRoute = true
				continue // Default route (Exit Node) only activates when explicitly selected by client!
			}
			newRoutes = append(newRoutes, routeEntry{prefix: rt, peer: pr})
			extraRoutes = append(extraRoutes, rt)
		}
		if hasDefaultRoute && wantExit != "" {
			if strings.EqualFold(p.Name, wantExit) || strings.EqualFold(p.Hostname, wantExit) || p.IPv4.String() == wantExit {
				selectedExit = pr
			}
		}
	}

	prevSelfV4 := e.netMap.Self.IPv4
	e.netMap = nm
	e.peersByKey = newByKey
	e.peersByIP = newByIP
	e.routeTable = newRoutes
	e.exitNodePeer = selectedExit
	e.selfApprovedRoutes = append([]netip.Prefix(nil), nm.Self.ApprovedRoutes...)
	e.mu.Unlock()

	e.recomputeMeshRoutes()

	if len(nm.Relays) > 0 {
		e.natDetector.SetSTUNServers(nm.Relays[0].STUNAddr, nm.Relays[0].STUNAltAddr)
	}

	// Proactively run a multi-sample calibration burst on newly discovered peers so RTT, Jitter, & Loss converge fast!
	for _, np := range newlyAddedPeers {
		go e.probePeerCalibrationBurst(np.NodeKey, np.Endpoints)
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

func (e *Engine) requestImmediateHeartbeat() {
	select {
	case e.hbTriggerCh <- struct{}{}:
	default:
	}
}

func (e *Engine) lookupPeerByDstIP(dst netip.Addr) *peerRuntime {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if dst == e.netMap.Self.IPv4 || dst == e.netMap.Self.IPv6 {
		return nil
	}
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
	if best != nil {
		return best
	}
	return e.exitNodePeer
}

func (e *Engine) isSelfApprovedDestination(dst netip.Addr) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, pfx := range e.selfApprovedRoutes {
		if pfx.Contains(dst) {
			return true
		}
	}
	return false
}

func validatePeerAllowedSource(pr *peerRuntime, srcIP netip.Addr) bool {
	if pr == nil || !srcIP.IsValid() {
		return false
	}
	pr.mu.RLock()
	allowed := pr.meta.AllowedIPs
	pr.mu.RUnlock()
	for _, pfx := range allowed {
		if pfx.Contains(srcIP) {
			return true
		}
	}
	return false
}

// sendPlainPacketToOverlay is invoked by the userspace Subnet/Exit Gateway to return reply L3 packets to overlay peers.
func (e *Engine) sendPlainPacketToOverlay(plainPkt []byte) {
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
		pr := e.lookupPeerByDstIP(dstIP)
		if pr == nil {
			continue
		}
		e.encryptAndDispatchToPeer(pr, pkt)
	}
}

func (e *Engine) handleCenterRelayedPacket(src types.PublicKey, inner []byte) {
	cp := make([]byte, len(inner))
	copy(cp, inner)
	e.handleIncomingWirePacket(cp, types.Endpoint{}, sourceCenterRelay, src)
}

func (e *Engine) recordDirectLinkRx(peerKey types.PublicKey, srcEp types.Endpoint, rtt time.Duration) {
	_, _, hadBefore := e.selector.BestEndpoint(peerKey)
	e.selector.RecordRx(peerKey, srcEp, rtt)
	if !hadBefore {
		// Newly verified direct neighbor (e.g. inbound NAT client)! Calibrate RTT/Loss & publish link-state.
		e.recomputeMeshRoutes()
		e.requestImmediateHeartbeat()
		go e.probePeerCalibrationBurst(peerKey, []types.Endpoint{srcEp})
	}
}

func (e *Engine) handleIncomingWirePacket(pkt []byte, srcEp types.Endpoint, srcMode incomingSource, relaySrc types.PublicKey) {
	pType, _, _, err := protocol.ParseHeader(pkt)
	if err != nil {
		return
	}

	switch pType {
	case protocol.PacketRelayForward:
		// EasyTier-style Peer-to-Peer Multi-Hop Ciphertext Relay!
		if srcMode != sourceDirect {
			return
		}
		ttl, origSrc, finalDst, inner, err := protocol.DecodeRelayForward(pkt)
		if err != nil {
			return
		}
		// Keep direct return NAT mapping alive for 1st-hop sender (symmetric bidirectional CN2 return path!)
		if ttl == protocol.DefaultHopTTL && srcEp.Addr != "" && e.getPeerRuntime(origSrc) != nil {
			e.recordDirectLinkRx(origSrc, srcEp, 0)
		}
		localPub := e.cryptoMgr.LocalPublicKey()
		if finalDst == localPub {
			e.handleIncomingWirePacket(inner, types.Endpoint{}, sourcePeerRelay, origSrc)
			return
		}
		// We are an intermediate Peer Relay node: enforce effectiveCanRelay, rate limit, TTL, and network auth!
		if ttl <= 1 || !e.effectiveCanRelay() {
			return
		}
		if e.getPeerRuntime(origSrc) == nil || e.getPeerRuntime(finalDst) == nil {
			return
		}
		if !e.allowRelayBandwidth(len(pkt)) {
			return
		}
		fwdFrame := protocol.EncodeRelayForward(ttl-1, origSrc, finalDst, inner)
		if e.forwardMeshRelayFrame(origSrc, finalDst, fwdFrame) {
			e.peerRelayedFrames.Add(1)
			e.peerRelayedBytes.Add(uint64(len(fwdFrame)))
		}

	case protocol.PacketHandshakeInit:
		peerKey, ackPkt, queued, err := e.cryptoMgr.HandleHandshakeInit(pkt)
		if err != nil {
			return
		}
		pr := e.getPeerRuntime(peerKey)
		if pr == nil {
			return
		}
		if srcMode == sourceDirect && srcEp.Addr != "" {
			e.recordDirectLinkRx(peerKey, srcEp, 0)
			_ = e.hub.Send(context.Background(), srcEp, ackPkt)
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
		peerKey, queued, err := e.cryptoMgr.HandleHandshakeAck(pkt)
		if err != nil {
			return
		}
		pr := e.getPeerRuntime(peerKey)
		if pr == nil {
			return
		}
		if srcMode == sourceDirect && srcEp.Addr != "" {
			e.recordDirectLinkRx(peerKey, srcEp, 0)
		}
		e.flushQueuedPackets(pr, peerKey, queued)

	case protocol.PacketData:
		peerKey, plainIP, err := e.cryptoMgr.OpenPacket(pkt)
		if err != nil {
			return
		}
		pr := e.getPeerRuntime(peerKey)
		if pr == nil {
			return
		}
		srcIP, okSrc := tun.ExtractSrcIP(plainIP)
		dstIP, okDst := tun.ExtractDstIP(plainIP)
		if !okSrc || !okDst || !validatePeerAllowedSource(pr, srcIP) {
			return // Reject spoofed inner source IP!
		}

		pr.rxBytes.Add(uint64(len(plainIP)))
		if srcMode == sourceDirect && srcEp.Addr != "" {
			e.recordDirectLinkRx(peerKey, srcEp, 0)
		} else if srcMode == sourcePeerRelay {
			pr.mu.Lock()
			pr.lastPeerRelayRx = time.Now()
			pr.mu.Unlock()
		}

		// Enforce inbound Zero-Trust ACL + Stateful Conntrack return-traffic allowance
		if !e.pktFilter.AllowInbound(plainIP) {
			return
		}

		e.mu.RLock()
		isSelf := dstIP == e.netMap.Self.IPv4 || dstIP == e.netMap.Self.IPv6
		e.mu.RUnlock()

		if isSelf {
			_ = e.tunDev.WritePacket(plainIP)
			return
		}
		// Foreign destination IP: handle via Userspace Subnet Router / Exit Node Gateway if approved!
		if e.isSelfApprovedDestination(dstIP) {
			e.gateway.HandlePacket(plainIP)
		}

	case protocol.PacketPunchCoord:
		sender, isReply, peerNATKind, peerStep, peerEps, err := protocol.DecodePunchCoord(pkt)
		if err != nil {
			return
		}
		if srcMode != sourceDirect && relaySrc != sender {
			return
		}
		if e.getPeerRuntime(sender) == nil {
			return
		}
		e.selector.SyncCandidates(sender, peerEps)
		if !isReply {
			kind, step, _, _ := e.natDetector.Snapshot()
			myEps := e.collectLocalEndpoints()
			replyCoord := protocol.EncodePunchCoord(e.cryptoMgr.LocalPublicKey(), true, byte(kind), step, myEps)
			e.sendReplyOverMeshOrRelay(sender, replyCoord, srcMode)
		}
		go e.executePunchBurst(sender, peerEps, nat.Kind(peerNATKind), peerStep)

	case protocol.PacketPing:
		_, sender, probeID, txNano, _, err := protocol.DecodeProbePacket(pkt)
		if err != nil {
			return
		}
		st := e.stateMgr.Get()
		obs := ""
		if srcMode == sourceDirect {
			obs = srcEp.Addr
			if e.getPeerRuntime(sender) != nil && srcEp.Addr != "" {
				e.recordDirectLinkRx(sender, srcEp, 0)
			}
		}
		pong := protocol.EncodeProbePacket(protocol.PacketPong, st.NodeKey.Public(), probeID, txNano, obs)
		if srcMode == sourceDirect && srcEp.Addr != "" {
			_ = e.hub.Send(context.Background(), srcEp, pong)
		} else if !relaySrc.IsZero() {
			e.sendReplyOverMeshOrRelay(sender, pong, srcMode)
		}

	case protocol.PacketPong:
		_, sender, probeID, txNano, obs, err := protocol.DecodeProbePacket(pkt)
		if err != nil {
			return
		}
		rtt := time.Since(time.Unix(0, txNano))
		if sender == e.cryptoMgr.LocalPublicKey() && obs != "" {
			wasRelay := e.effectiveCanRelay()
			e.natDetector.RecordObservation(srcEp.Addr, obs, rtt, localInterfaceIPs())
			if !wasRelay && e.effectiveCanRelay() {
				// STUN just proved we are open-public -> advertise auto-enabled CanRelay immediately!
				e.requestImmediateHeartbeat()
			}
			return
		}

		pr := e.getPeerRuntime(sender)
		if pr != nil {
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
			if srcMode == sourceDirect && srcEp.Addr != "" {
				_, _, hadBefore := e.selector.BestEndpoint(sender)
				e.selector.RecordProbeRx(sender, srcEp, probeID, rtt)
				e.recomputeMeshRoutes()
				if !hadBefore {
					e.requestImmediateHeartbeat()
				}
			}
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

// forwardMeshRelayFrame forwards an already-wrapped PacketRelayForward frame toward finalDst via direct or next mesh hop.
func (e *Engine) forwardMeshRelayFrame(origSrc, finalDst types.PublicKey, fwdFrame []byte) bool {
	// 1. Direct link to finalDst?
	if bestEp, _, ok := e.selector.BestEndpoint(finalDst); ok {
		if !(e.disableUDP && bestEp.Proto == types.ProtoUDP) {
			if e.hub.Send(context.Background(), bestEp, fwdFrame) == nil {
				return true
			}
		}
	}
	// 2. Multi-hop mesh route to finalDst (with split-horizon check NextHop != origSrc)?
	if rt, ok := e.meshRouter.Lookup(finalDst); ok && rt.NextHop != origSrc {
		if nextEp, _, ok2 := e.selector.BestEndpoint(rt.NextHop); ok2 {
			if !(e.disableUDP && nextEp.Proto == types.ProtoUDP) {
				if e.hub.Send(context.Background(), nextEp, fwdFrame) == nil {
					return true
				}
			}
		}
	}
	return false
}

// sendViaPeerMesh encapsulates innerPkt in PacketRelayForward and dispatches to the computed Dijkstra stepping-stone NextHop.
func (e *Engine) sendViaPeerMesh(dstPeer types.PublicKey, innerPkt []byte) error {
	rt, ok := e.meshRouter.LookupRelay(dstPeer)
	if !ok {
		return errors.New("no multi-hop peer route available")
	}
	nextEp, _, ok := e.selector.BestEndpoint(rt.NextHop)
	if !ok || (e.disableUDP && nextEp.Proto == types.ProtoUDP) {
		return errors.New("next-hop direct endpoint unavailable")
	}
	fwdFrame := protocol.EncodeRelayForward(protocol.DefaultHopTTL, e.cryptoMgr.LocalPublicKey(), dstPeer, innerPkt)
	return e.hub.Send(context.Background(), nextEp, fwdFrame)
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

type pathDecisionKind uint8

const (
	pathDecisionNone pathDecisionKind = iota
	pathDecisionDirect
	pathDecisionPeerMesh
	pathDecisionCenterRelay
)

// estimateCenterRelayCostMs returns the estimated E2E RTT + penalty via Center Relay, if connected.
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
		rttMs = srvRTT * 2.0 // Self->Server + Server->Peer symmetric estimate
	} else {
		rttMs = 15.0
	}
	return rttMs, rttMs + centerRelayPenaltyMs, true
}

// selectPathDecision runs unified quality-adjusted cost comparison across Direct, Multi-Hop Peer Relay, and Center Relay.
func (e *Engine) selectPathDecision(pr *peerRuntime, peerKey types.PublicKey) (pathDecisionKind, types.Endpoint, mesh.Route, float64) {
	bestQ, hasDirect := e.selector.BestQuality(peerKey)
	if hasDirect && e.disableUDP && bestQ.Endpoint.Proto == types.ProtoUDP {
		hasDirect = false
	}

	meshRt, hasPeerRelay := e.meshRouter.LookupRelay(peerKey)
	centerRTT, centerCost, hasCenter := e.estimateCenterRelayCostMs(pr)

	// Pick the better Relay between Peer Multi-Hop Mesh (e.g. CN2 stepping-stone!) and Center Relay
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
		// Symmetric Stepping-Stone Return Path: if peer is actively sending data to us via Peer-Relay
		// (because peer detected direct congestion/loss), return traffic symmetrically via Peer-Relay too!
		if hasPeerRelay && pr != nil {
			pr.mu.RLock()
			peerPrefersMesh := !pr.lastPeerRelayRx.IsZero() && time.Since(pr.lastPeerRelayRx) < 15*time.Second
			pr.mu.RUnlock()
			if peerPrefersMesh {
				return pathDecisionPeerMesh, types.Endpoint{}, meshRt, meshRt.TotalCostMs
			}
		}
		// Bypass lossy/jittery/high-RTT Direct path (e.g. congested US-West 163) if CN2 Peer Relay or Center Relay beats Direct EffectiveCost by > 10ms!
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

// sendWireToPeer dispatches encrypted data using unified 3-tier cost selection + active-tx fast blackhole probing.
func (e *Engine) sendWireToPeer(pr *peerRuntime, wirePkt []byte) {
	pr.mu.RLock()
	peerKey := pr.meta.NodeKey
	pr.mu.RUnlock()

	decision, bestEp, _, _ := e.selectPathDecision(pr, peerKey)

	switch decision {
	case pathDecisionDirect:
		if err := e.hub.Send(context.Background(), bestEp, wirePkt); err == nil {
			// Track unanswered outbound traffic; if >= 2.5s without rx, fire immediate fast probe!
			if e.selector.RecordTx(peerKey, bestEp) {
				e.probePeerCandidates(peerKey, []types.Endpoint{bestEp})
			}
			return
		}
		// Stream write error -> immediate fallback below!

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

	// Fallback cascade if primary chosen path errored
	if e.sendViaPeerMesh(peerKey, wirePkt) == nil {
		e.triggerCoordinatedHolePunch(pr)
		return
	}
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
		if e.relayCli.Send(peerKey, coordPkt) != nil {
			_ = e.sendViaPeerMesh(peerKey, coordPkt)
		}

		cands := e.selector.AllCandidates(peerKey)
		e.executePunchBurst(peerKey, cands, nat.KindUnknown, 0)
	}()
}

func (e *Engine) executePunchBurst(peerKey types.PublicKey, cands []types.Endpoint, peerKind nat.Kind, peerStep int16) {
	localPub := e.cryptoMgr.LocalPublicKey()

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

	e.probePeerCandidates(peerKey, cands)
}

func (e *Engine) probePeerCalibrationBurst(peerKey types.PublicKey, cands []types.Endpoint) {
	for i := 0; i < 6; i++ {
		select {
		case <-e.closedCh:
			return
		default:
		}
		e.probePeerCandidates(peerKey, cands)
		if i < 5 {
			time.Sleep(35 * time.Millisecond)
		}
	}
	// Allow probeLossGrace (250ms) to settle so dropped probes are reflected in LossRate before publishing Links
	time.Sleep(270 * time.Millisecond)
	e.recomputeMeshRoutes()
	e.requestImmediateHeartbeat()
}

func (e *Engine) probePeerCandidates(peerKey types.PublicKey, cands []types.Endpoint) {
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
			probeID := e.probeSeq.Add(1)
			e.selector.RecordProbeSent(peerKey, targetEp, probeID)
			probe := protocol.EncodeProbePacket(protocol.PacketPing, localPub, probeID, time.Now().UnixNano(), "")
			_ = e.hub.Send(ctx, targetEp, probe)
		}(ep)
	}
}

// sendControlOrProbeToPeer dispatches handshakes across candidate direct transports, Peer Mesh, and Center Relay.
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
	_ = e.sendViaPeerMesh(peerKey, pkt)
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

func (e *Engine) sendHeartbeatOnce(ctx context.Context, serverURL, token string) {
	e.recomputeMeshRoutes()
	st := e.stateMgr.Get()
	hb := types.HeartbeatRequest{
		NodeKey:          st.NodeKey.Public(),
		Endpoints:        e.collectLocalEndpoints(),
		Links:            e.collectDirectLinks(),
		AdvertisedRoutes: st.AdvertisedRoutes,
		CanRelay:         e.effectiveCanRelay(),
	}
	raw, _ := json.Marshal(hb)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/v1/node/heartbeat", bytes.NewReader(raw))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	if resp, err := e.httpClient.Do(req); err == nil {
		_ = resp.Body.Close()
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
		case <-e.hbTriggerCh:
			// Debounce rapid link-state discoveries (e.g. multiple direct peers coming up together)
			select {
			case <-ctx.Done():
				return
			case <-time.After(45 * time.Millisecond):
			}
			// Drain any queued trigger
			select {
			case <-e.hbTriggerCh:
			default:
			}
			e.sendHeartbeatOnce(ctx, serverURL, token)

		case <-ticker.C:
			e.sendSTUNProbes()
			if e.enablePortMap {
				e.refreshPortMappings(ctx)
			}
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
			e.sendHeartbeatOnce(ctx, serverURL, token)
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

var cgnatRange = netip.MustParsePrefix("100.64.0.0/10")

func isPublicRoutableIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if ip.Is4() && cgnatRange.Contains(ip) {
		return false
	}
	return true
}

// effectiveCanRelay resolves RelayMode ("auto" | "on" | "off"):
// In "auto" mode (default), nodes with a public IP, STUN open-public NAT, or active UPnP port map
// automatically become stepping-stone relays, while private NAT leaf devices stay false!
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
	// Auto-detect public reachability!
	if kind, _, _, _ := e.natDetector.Snapshot(); kind == nat.KindPublic {
		return true
	}
	if len(e.portMapper.MappedEndpoints()) > 0 {
		return true
	}
	// Check explicitly bound public transport IPs
	for _, proto := range []types.TransportProto{types.ProtoUDP, types.ProtoTCP, types.ProtoQUIC, types.ProtoWSS} {
		if drv := e.hub.Driver(proto); drv != nil {
			if host, _, err := net.SplitHostPort(drv.LocalAddr()); err == nil {
				if ip, pErr := netip.ParseAddr(host); pErr == nil && isPublicRoutableIP(ip) {
					return true
				}
			}
		}
	}
	// If at least one transport listens on 0.0.0.0 / ::, check if host NIC owns a public IP
	if len(e.hub.LocalPorts()) > 0 {
		for _, ip := range localInterfaceIPs() {
			if isPublicRoutableIP(ip) {
				return true
			}
		}
	}
	return false
}

// allowRelayBandwidth enforces optional MaxRelayMbps token-bucket rate limiting on transit packets.
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

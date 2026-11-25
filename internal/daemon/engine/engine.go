package engine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
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
	"github.com/acktier/acktier/internal/daemon/pktutil"
	"github.com/acktier/acktier/internal/daemon/state"
	"github.com/acktier/acktier/internal/daemon/transport"
	"github.com/acktier/acktier/internal/daemon/tun"
	"github.com/acktier/acktier/internal/securehttp"
	"github.com/acktier/acktier/pkg/protocol"
	"github.com/acktier/acktier/pkg/types"
)

type incomingSource byte

const (
	sourceDirect incomingSource = iota
	sourcePeerRelay
	sourceCenterRelay
)

const (
	centerRelayPenaltyMs = 6.0
	exitFlowTTL          = 3 * time.Minute
	maxExitFlows         = 4096
)

// Options configures external transports, TLS verification, NAT helpers, and virtual NIC dependencies for Engine.
type Options struct {
	State               *state.Manager
	TUN                 tun.Device
	Hub                 *transport.Hub          // Optional multi-transport hub (UDP/TCP/QUIC/WSS)
	UDPConn             net.PacketConn          // Optional single UDP socket (auto-registered in Hub if Hub is nil)
	HTTPClient          *http.Client            // Optional HTTP client for Control Plane
	RelayDial           DialFunc                // Optional stream dialer for Relay Plane
	GatewayTCPDial      netstack.DialStreamFunc // Optional outbound TCP dialer for Subnet Router / Exit Node
	GatewayUDPDial      netstack.DialPacketFunc // Optional outbound UDP dialer for Subnet Router / Exit Node
	TLSCAFile           string                  // Optional custom Root CA PEM path for Control & Center Relay TLS verification
	AllowInsecureHTTP   bool                    // Explicitly allow plaintext HTTP/Relay to non-loopback servers (lab testing only)
	LocalAPIAddr        string                  // Optional LocalAPI bind address protected from Gateway SSRF
	DisableUDP          bool                    // Force disable direct UDP (testing / strict firewall simulation)
	EnableLANDiscovery  bool                    // Broadcast/listen for L2 LAN peer discovery beacons
	EnablePortMap       bool                    // Attempt UPnP IGD / NAT-PMP automatic router port mapping
	EnableNetMonitor    bool                    // Watch host NIC/IP changes for instant roaming notification
	BlackholeProbeAfter time.Duration           // Active-tx unanswered duration before fast probe (default 2.5s)
	BlackholeTimeout    time.Duration           // Active-tx unanswered duration before declaring direct path dead (default 4.5s)
	NetMonitorInterval  time.Duration           // Interface change poll interval (default 1.5s)
	ControlLeaseTTL     time.Duration           // Stale NetMap grace period (0 uses the default; minimum 1m)
}

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

type stunProbeEntry struct {
	serverAddr string
	sentAt     time.Time
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

// UpRequest parameters for bringing up the AckTier overlay network.
type UpRequest struct {
	ServerURL         string          `json:"serverUrl"`
	AuthKey           string          `json:"authKey,omitempty"`
	Hostname          string          `json:"hostname,omitempty"`
	AdvertisedRoutes  []netip.Prefix  `json:"advertisedRoutes,omitempty"`
	ExitNode          string          `json:"exitNode,omitempty"`
	RelayMode         types.RelayMode `json:"relayMode,omitempty"` // "auto" (default) | "on" | "off"
	MaxRelayMbps      float64         `json:"maxRelayMbps,omitempty"`
	CanRelay          bool            `json:"canRelay,omitempty"`
	AllowInsecureHTTP bool            `json:"allowInsecureHttp,omitempty"`
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
	exitFlows          *exitFlowTracker
	httpClient         *http.Client
	customHTTP         bool
	customRelayDial    bool
	rootCAs            *x509.CertPool
	allowInsecureHTTP  bool
	localAPIAddr       string
	cryptoMgr          *crypto.Manager
	relayCli           *RelayClient
	disableUDP         bool
	enableLANDiscovery bool
	enablePortMap      bool
	enableNetMonitor   bool
	netMonInterval     time.Duration
	controlLeaseTTL    time.Duration

	sessionMu          sync.Mutex // Serializes session changes and NetMap installation.
	sessionEpoch       uint64
	controlCtx         context.Context
	mu                 sync.RWMutex
	running            bool
	runCancel          context.CancelFunc
	controlUntil       time.Time
	activeControlHost  string
	netMap             types.NetMap
	peersByKey         map[types.PublicKey]*peerRuntime
	peersByIP          map[netip.Addr]*peerRuntime
	routeTable         []routeEntry
	exitNodePeer       *peerRuntime
	selfApprovedRoutes []netip.Prefix

	hbTriggerCh       chan struct{}
	peerRelayedFrames atomic.Uint64
	peerRelayedBytes  atomic.Uint64
	meshSeq           atomic.Uint64
	rlMu              sync.Mutex
	rlTokens          float64
	rlLastRefill      time.Time

	stunMu      sync.Mutex
	pendingSTUN map[uint64]stunProbeEntry

	pingMu      sync.Mutex
	pingWaiters map[uint64]pingWaiter

	closeOnce sync.Once
	closedCh  chan struct{}
}

type routeEntry struct {
	prefix netip.Prefix
	peer   *peerRuntime
}

func loadCertPool(caFile string) (*x509.CertPool, error) {
	if strings.TrimSpace(caFile) == "" {
		return nil, nil // nil instructs crypto/tls to use the OS system root store
	}
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read TLS CA file %s: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("TLS CA file %s contains no valid PEM certificates", caFile)
	}
	return pool, nil
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

func New(opts Options) (*Engine, error) {
	if opts.State == nil || opts.TUN == nil {
		return nil, errors.New("engine: State and TUN are required")
	}
	leaseTTL := opts.ControlLeaseTTL
	if leaseTTL == 0 {
		leaseTTL = DefaultControlLeaseTTL
	}
	if leaseTTL < controlStreamIdleTimeout {
		return nil, fmt.Errorf("engine: control lease TTL must be at least %s (0 uses the default)", controlStreamIdleTimeout)
	}
	rootPool, err := loadCertPool(opts.TLSCAFile)
	if err != nil {
		return nil, err
	}

	st := opts.State.Get()
	httpCli := opts.HTTPClient
	customHTTP := httpCli != nil
	if httpCli == nil {
		httpCli = &http.Client{
			Transport: &http.Transport{
				DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 15 * time.Second,
				IdleConnTimeout:       90 * time.Second,
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
					RootCAs:    rootPool,
				},
			},
		}
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
		exitFlows:          newExitFlowTracker(),
		httpClient:         securehttp.NoRedirects(httpCli),
		customHTTP:         customHTTP,
		customRelayDial:    opts.RelayDial != nil,
		rootCAs:            rootPool,
		allowInsecureHTTP:  opts.AllowInsecureHTTP,
		localAPIAddr:       opts.LocalAPIAddr,
		cryptoMgr:          crypto.NewManager(st.NodeKey),
		disableUDP:         opts.DisableUDP,
		enableLANDiscovery: opts.EnableLANDiscovery,
		enablePortMap:      opts.EnablePortMap,
		enableNetMonitor:   opts.EnableNetMonitor,
		netMonInterval:     opts.NetMonitorInterval,
		controlLeaseTTL:    leaseTTL,
		peersByKey:         make(map[types.PublicKey]*peerRuntime),
		peersByIP:          make(map[netip.Addr]*peerRuntime),
		hbTriggerCh:        make(chan struct{}, 1),
		pendingSTUN:        make(map[uint64]stunProbeEntry),
		pingWaiters:        make(map[uint64]pingWaiter),
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
	e.gateway.SetHostProtectedIPCheck(e.isHostManagementOrLocalIP)
	e.relayCli = NewRelayClient(opts.RelayDial, st.NodeKey.Public(), e.handleCenterRelayedPacket)

	go e.tunReadLoop()
	return e, nil
}

// LocalAPIToken returns the persistent owner-only LocalAPI bearer token managed by State.
func (e *Engine) LocalAPIToken() string {
	return e.stateMgr.Get().LocalAPIToken
}

func (e *Engine) isRunning() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.running && time.Now().Before(e.controlUntil)
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

func validateControlServerURL(rawURL string, requireTLS bool) (*url.URL, bool, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, false, fmt.Errorf("invalid serverUrl %q (expected https://host:port or http://127.0.0.1:port)", rawURL)
	}
	host := u.Hostname()
	isLoop := strings.EqualFold(host, "localhost")
	if ip, pErr := netip.ParseAddr(host); pErr == nil && ip.IsLoopback() {
		isLoop = true
	}
	if u.Scheme == "http" && !isLoop && requireTLS {
		return nil, false, fmt.Errorf("refusing plaintext http:// control URL %q over non-loopback network; use https:// (or pass --insecure-http for isolated lab testing)", rawURL)
	}
	return u, isLoop, nil
}

// Up authenticates with acktier-server, configures the virtual NIC, and starts background topology, NAT, & mesh loops.
func (e *Engine) Up(ctx context.Context, req UpRequest) (*types.NetMap, error) {
	e.sessionMu.Lock()
	e.sessionEpoch++
	epoch := e.sessionEpoch
	e.sessionMu.Unlock()
	cur := e.stateMgr.Get()
	serverURL := strings.TrimRight(strings.TrimSpace(req.ServerURL), "/")
	if serverURL == "" {
		serverURL = cur.ServerURL
	}
	if serverURL == "" {
		return nil, errors.New("serverUrl is required")
	}

	allowInsecure := e.allowInsecureHTTP || req.AllowInsecureHTTP
	parsedURL, isLoopbackCtrl, err := validateControlServerURL(serverURL, !e.customHTTP && !allowInsecure)
	if err != nil {
		return nil, err
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

	// A loopback control URL alone may be a local proxy for a remote control
	// server. Require an explicitly loopback-bound peer transport as well.
	hasLoopTransport := false
	for _, proto := range []types.TransportProto{types.ProtoUDP, types.ProtoTCP, types.ProtoQUIC, types.ProtoWSS} {
		if drv := e.hub.Driver(proto); drv != nil && isLoopbackHostPort(drv.LocalAddr()) {
			hasLoopTransport = true
			break
		}
	}
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

	// Origin-scoped token lookup: NEVER send a saved NodeToken to a different control server!
	originToken := e.stateMgr.TokenForServer(serverURL)

	bodyBytes, _ := json.Marshal(regReq)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/v1/node/register", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if originToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+originToken)
	}

	resp, err := e.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("register with %s: %w", serverURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return nil, fmt.Errorf("register failed (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var regResp types.RegisterResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4*1024*1024)).Decode(&regResp); err != nil {
		return nil, fmt.Errorf("decode register response: %w", err)
	}
	if regResp.NodeToken == "" || !e.isOwnNetMap(regResp.NetMap) {
		return nil, errors.New("control server did not authorize this node")
	}

	e.sessionMu.Lock()
	defer e.sessionMu.Unlock()
	if epoch != e.sessionEpoch {
		return nil, errors.New("node registration superseded by another session change")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-e.closedCh:
		return nil, net.ErrClosed
	default:
	}

	normOrigin := state.NormalizeServerOrigin(serverURL)
	if err := e.stateMgr.Update(func(s *state.ConfigState) {
		s.ServerURL = serverURL
		if normOrigin != "" && regResp.NodeToken != "" {
			s.NodeTokens[normOrigin] = regResp.NodeToken
		}
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
	}); err != nil {
		return nil, fmt.Errorf("persist node registration: %w", err)
	}

	e.stopSessionLocked()
	e.selector.SetAllowLoopback(isLoopbackCtrl && hasLoopTransport)

	runCtx, cancel := context.WithCancel(context.Background())
	e.controlCtx = runCtx
	e.mu.Lock()
	e.running = true
	e.runCancel = cancel
	e.activeControlHost = parsedURL.Hostname()
	e.mu.Unlock()

	e.applyNetMap(regResp.NetMap, true)

	if len(regResp.NetMap.Relays) > 0 {
		r0 := regResp.NetMap.Relays[0]
		e.natDetector.SetSTUNServers(r0.STUNAddr, r0.STUNAltAddr)
		if r0.RelayAddr != "" {
			useRelayTLS := r0.UseTLS || strings.EqualFold(parsedURL.Scheme, "https")
			sni := r0.Host
			if sni == "" {
				sni = parsedURL.Hostname()
			}
			go e.relayCli.Run(runCtx, r0.RelayAddr, regResp.NodeToken, RelayTLSConfig{
				UseTLS:            useRelayTLS,
				ServerName:        sni,
				RootCAs:           e.rootCAs,
				EnforceNonLoopTLS: !e.customRelayDial && !allowInsecure,
			})
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
	go e.watchControlLease(runCtx)
	go e.maintenanceLoop(runCtx, serverURL, regResp.NodeToken)

	return &regResp.NetMap, nil
}

// Down disconnects control stream, Center Relay, AND immediately tears down all E2EE sessions,
// direct peer stream connections, routing state, conntrack entries, and Gateway proxy flows!
func (e *Engine) Down() {
	e.sessionMu.Lock()
	defer e.sessionMu.Unlock()
	e.sessionEpoch++
	e.stopSessionLocked()
	_ = e.stateMgr.Update(func(s *state.ConfigState) {
		s.WantRunning = false
	})
}

func (e *Engine) stopSessionLocked() {
	e.controlCtx = nil
	e.mu.Lock()
	cancel := e.runCancel
	e.runCancel = nil
	e.running = false
	e.activeControlHost = ""
	e.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	e.relayCli.CloseCurrent()
	e.clearAuthorizationLocked()
}

func (e *Engine) Close() error {
	e.sessionMu.Lock()
	defer e.sessionMu.Unlock()
	e.closeOnce.Do(func() {
		close(e.closedCh)
		e.sessionEpoch++
		e.stopSessionLocked()
		_ = e.stateMgr.Update(func(s *state.ConfigState) {
			s.WantRunning = false
		})
		_ = e.gateway.Close()
		_ = e.hub.Close()
		_ = e.tunDev.Close()
	})
	return nil
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

func (e *Engine) buildAuthProbe(pktType protocol.PacketType, peerKey types.PublicKey, probeID uint64, txNano int64, obs string) ([]byte, error) {
	return protocol.EncodeAuthProbePacket(pktType, e.cryptoMgr.LocalPublicKey(), peerKey, probeID, txNano, obs, func(data []byte) ([protocol.ControlAuthTagSize]byte, error) {
		return e.cryptoMgr.SignControl(peerKey, data)
	})
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

// applyNetMap is called under sessionMu.
func (e *Engine) applyNetMap(nm types.NetMap, refreshLease bool) {
	nm.Peers = activeMapPeers(nm.Peers)
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

		var hasDefaultV4, hasDefaultV6 bool
		var cleanSubnets []netip.Prefix
		for _, rt := range p.ApprovedRoutes {
			masked := rt.Masked()
			if masked.Bits() == 0 {
				if masked.Addr().Is4() {
					hasDefaultV4 = true
				} else {
					hasDefaultV6 = true
				}
				continue
			}
			// Never allow approved subnet routes to shadow overlay IPs or loopback/link-local/multicast!
			if types.OverlapsOverlayOrSpecial(masked) {
				continue
			}
			cleanSubnets = append(cleanSubnets, masked)
			newRoutes = append(newRoutes, routeEntry{prefix: masked, peer: pr})
			extraRoutes = append(extraRoutes, masked)
		}

		pr.mu.Lock()
		pr.meta = p
		pr.hasExitV4 = hasDefaultV4
		pr.hasExitV6 = hasDefaultV6
		pr.nonDefaultSubnets = cleanSubnets
		pr.mu.Unlock()

		e.selector.SyncCandidates(p.NodeKey, p.Endpoints)

		newByKey[p.NodeKey] = pr
		if p.IPv4.IsValid() {
			newByIP[p.IPv4] = pr
		}
		if p.IPv6.IsValid() {
			newByIP[p.IPv6] = pr
		}
		if (hasDefaultV4 || hasDefaultV6) && wantExit != "" {
			// Match ONLY server-assigned unique Name, IP, or NodeKey (not self-reported Hostname)
			if strings.EqualFold(p.Name, wantExit) || p.IPv4.String() == wantExit || p.IPv6.String() == wantExit || strings.EqualFold(p.NodeKey.String(), wantExit) {
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
	if refreshLease {
		e.controlUntil = time.Now().Add(e.controlLeaseTTL)
	}
	e.mu.Unlock()

	if selectedExit != nil {
		selectedExit.mu.RLock()
		ek := selectedExit.meta.NodeKey
		selectedExit.mu.RUnlock()
		e.exitFlows.RetainOnlyPeer(ek)
	} else {
		e.exitFlows.Reset()
	}

	// Immediately evict any Gateway NAT proxy flows whose peer was removed, route unapproved, or ACL revoked!
	e.gateway.RevalidateFlows(func(srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16, proto uint8) bool {
		e.mu.RLock()
		_, validPeer := e.peersByIP[srcIP]
		e.mu.RUnlock()
		if !validPeer || !e.isSelfApprovedDestination(dstIP) {
			return false
		}
		return e.pktFilter.AllowsTuple(srcIP, srcPort, dstIP, dstPort, proto)
	})

	e.recomputeMeshRoutes()

	if len(nm.Relays) > 0 {
		e.natDetector.SetSTUNServers(nm.Relays[0].STUNAddr, nm.Relays[0].STUNAltAddr)
	}

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

func (e *Engine) handleCenterRelayedPacket(src types.PublicKey, inner []byte) {
	if !e.isRunning() {
		return
	}
	cp := make([]byte, len(inner))
	copy(cp, inner)
	e.handleIncomingWirePacket(cp, types.Endpoint{}, sourceCenterRelay, src)
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

		streamCtx, cancel := context.WithCancel(ctx)
		silence := time.AfterFunc(controlStreamIdleTimeout, cancel)
		req, err := http.NewRequestWithContext(streamCtx, http.MethodGet, streamURL, nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := e.httpClient.Do(req)
			if err == nil && resp.StatusCode == http.StatusOK {
				backoff = 300 * time.Millisecond
				scanner := bufio.NewScanner(resp.Body)
				scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
				for scanner.Scan() {
					if streamCtx.Err() != nil {
						break
					}
					var ev types.MapStreamEvent
					if json.Unmarshal(scanner.Bytes(), &ev) != nil || !e.acceptControlEvent(ctx, ev) {
						break
					}
					silence.Reset(controlStreamIdleTimeout)
				}
				_ = resp.Body.Close()
			} else if resp != nil {
				e.handleControlRejection(ctx, resp.StatusCode)
				_ = resp.Body.Close()
			}
		}
		silence.Stop()
		cancel()

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
	if !e.isRunning() {
		return
	}
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
		e.handleControlRejection(ctx, resp.StatusCode)
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
			select {
			case <-ctx.Done():
				return
			case <-time.After(45 * time.Millisecond):
			}
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

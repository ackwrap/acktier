package engine

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"github.com/acktier/acktier/internal/owner"
	"github.com/acktier/acktier/internal/securehttp"
	"github.com/acktier/acktier/pkg/types"
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
	OwnerTrustFile      string                  // Out-of-band public trust configuration.
	RequireOwner        bool                    // Refuse to start without a pinned owner.
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
	ownerTrust         *owner.Trust
	ownerNetworkID     string

	sessionMu          sync.Mutex // Serializes session changes and NetMap installation.
	sessionEpoch       uint64
	controlCtx         context.Context
	ownerRelay         types.RelayNode  // sessionMu
	ownerInstalled     owner.Checkpoint // sessionMu
	mu                 sync.RWMutex
	running            bool
	runCancel          context.CancelFunc
	controlUntil       time.Time
	ownerExpiresAt     time.Time
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
	trust, err := opts.State.ConfigureOwner(opts.OwnerTrustFile)
	if err != nil {
		return nil, err
	}
	if opts.RequireOwner && trust == nil {
		return nil, errors.New("no owner configured: provision the selected owner's trust.json with -owner-trust")
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
		ownerTrust:         trust,
		peersByKey:         make(map[types.PublicKey]*peerRuntime),
		peersByIP:          make(map[netip.Addr]*peerRuntime),
		hbTriggerCh:        make(chan struct{}, 1),
		pendingSTUN:        make(map[uint64]stunProbeEntry),
		pingWaiters:        make(map[uint64]pingWaiter),
		closedCh:           make(chan struct{}),
	}
	if trust != nil {
		e.ownerNetworkID = trust.NetworkID()
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
		OwnerNetworkID:   e.ownerNetworkID,
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
	if regResp.NodeToken == "" {
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
	var verified *owner.Verified
	var trustedRelay types.RelayNode
	if e.ownerTrust != nil {
		trustedRelay = ownerRelayForControl(parsedURL)
		nm, v, err := e.verifyOwnerMapLocked(regResp.NetMap, trustedRelay)
		if err != nil {
			if errors.Is(err, errAwaitingOwner) {
				if v != nil {
					e.clearAuthorizationLocked()
				}
				if err := e.persistPendingOwnerToken(normOrigin, serverURL, regResp.NodeToken); err != nil {
					return nil, err
				}
			}
			return nil, err
		}
		verified = v
		regResp.NetMap = nm
	} else if regResp.NetMap.OwnerNetworkID != "" || regResp.NetMap.OwnerAuthorization != nil || !e.isOwnNetMap(regResp.NetMap) {
		return nil, errors.New("control server did not authorize this node in the configured trust mode")
	}
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

	if verified != nil {
		e.ownerRelay = trustedRelay
		e.installOwnerMapLocked(regResp.NetMap, verified)
	} else {
		e.applyNetMap(regResp.NetMap, true)
	}

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

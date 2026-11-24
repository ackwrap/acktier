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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/acktier/acktier/internal/daemon/crypto"
	"github.com/acktier/acktier/internal/daemon/state"
	"github.com/acktier/acktier/internal/daemon/tun"
	"github.com/acktier/acktier/pkg/protocol"
	"github.com/acktier/acktier/pkg/types"
)

const (
	directActiveWindow = 45 * time.Second
)

// Options configures external transports and virtual NIC dependencies for Engine.
type Options struct {
	State      *state.Manager
	TUN        tun.Device
	UDPConn    net.PacketConn    // Optional injected UDP socket
	HTTPClient *http.Client      // Optional injected HTTP client for Control Plane
	RelayDial  DialFunc          // Optional injected stream dialer for Relay Plane
	DisableUDP bool              // Force relay-only path (useful for testing & strict networks)
}

type peerRuntime struct {
	mu             sync.RWMutex
	meta           types.PeerNode
	directUDPAddr  *net.UDPAddr
	lastDirectRx   time.Time
	lastHandshake  time.Time
	lastRTTMicros  int64
	rxBytes        atomic.Uint64
	txBytes        atomic.Uint64
}

// PeerStatus summarizes live connectivity and traffic telemetry for CLI / GUI display.
type PeerStatus struct {
	ID            types.NodeID   `json:"id"`
	Name          string         `json:"name"`
	Hostname      string         `json:"hostname"`
	OS            string         `json:"os"`
	NodeKey       string         `json:"nodeKey"`
	IPv4          string         `json:"ipv4"`
	IPv6          string         `json:"ipv6"`
	Online        bool           `json:"online"`
	ActivePath    string         `json:"activePath"` // "direct-udp" | "relay" | "idle"
	DirectAddr    string         `json:"directAddr,omitempty"`
	RTTMillis     float64        `json:"rttMillis,omitempty"`
	RxBytes       uint64         `json:"rxBytes"`
	TxBytes       uint64         `json:"txBytes"`
	AllowedIPs    []netip.Prefix `json:"allowedIPs,omitempty"`
}

// StatusResponse represents the full local daemon status returned over LocalAPI.
type StatusResponse struct {
	State          string       `json:"state"` // "Running" | "Stopped"
	TUNName        string       `json:"tunName"`
	SelfName       string       `json:"selfName,omitempty"`
	SelfNodeKey    string       `json:"selfNodeKey"`
	IPv4           string       `json:"ipv4,omitempty"`
	IPv6           string       `json:"ipv6,omitempty"`
	ServerURL      string       `json:"serverUrl,omitempty"`
	RelayConnected bool         `json:"relayConnected"`
	MagicDNSSuffix string       `json:"magicDNSSuffix,omitempty"`
	Revision       uint64       `json:"revision"`
	Peers          []PeerStatus `json:"peers"`
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
	Via        string  `json:"via"` // "direct-udp" | "relay"
	Endpoint   string  `json:"endpoint,omitempty"`
}

type pingWaiter struct {
	via string
	ep  string
}

// Engine coordinates Control Plane synchronization, E2EE Crypto sessions, UDP Direct, Relay Fallback, and TUN I/O.
type Engine struct {
	stateMgr   *state.Manager
	tunDev     tun.Device
	udpConn    net.PacketConn
	httpClient *http.Client
	cryptoMgr  *crypto.Manager
	relayCli   *RelayClient
	disableUDP bool

	mu         sync.RWMutex
	running    bool
	runCancel  context.CancelFunc
	netMap     types.NetMap
	peersByKey map[types.PublicKey]*peerRuntime
	peersByIP  map[netip.Addr]*peerRuntime
	routeTable []routeEntry
	stunObservedAddr string

	probeSeq   atomic.Uint64
	pingMu     sync.Mutex
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
		stateMgr:    opts.State,
		tunDev:      opts.TUN,
		udpConn:     opts.UDPConn,
		httpClient:  httpCli,
		cryptoMgr:   crypto.NewManager(st.NodeKey),
		disableUDP:  opts.DisableUDP,
		peersByKey:  make(map[types.PublicKey]*peerRuntime),
		peersByIP:   make(map[netip.Addr]*peerRuntime),
		pingWaiters: make(map[uint64]chan pingWaiter),
		closedCh:    make(chan struct{}),
	}
	e.relayCli = NewRelayClient(opts.RelayDial, st.NodeKey.Public(), e.handleRelayedPacket)

	go e.tunReadLoop()
	if e.udpConn != nil && !e.disableUDP {
		go e.udpReadLoop()
	}
	return e, nil
}

// Up authenticates with acktier-server, configures the virtual NIC, and starts background topology & relay loops.
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

	// Stop previous session loops if restarting
	e.Down()

	e.applyNetMap(regResp.NetMap)

	runCtx, cancel := context.WithCancel(context.Background())
	e.mu.Lock()
	e.running = true
	e.runCancel = cancel
	e.mu.Unlock()

	if len(regResp.NetMap.Relays) > 0 && regResp.NetMap.Relays[0].RelayAddr != "" {
		relayAddr := regResp.NetMap.Relays[0].RelayAddr
		go e.relayCli.Run(runCtx, relayAddr, regResp.NodeToken)
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
		if e.udpConn != nil {
			_ = e.udpConn.Close()
		}
		_ = e.tunDev.Close()
	})
	return nil
}

func (e *Engine) Status() StatusResponse {
	st := e.stateMgr.Get()
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
			pr.mu.RLock()
			if pr.directUDPAddr != nil && time.Since(pr.lastDirectRx) < directActiveWindow {
				ps.ActivePath = "direct-udp"
				ps.DirectAddr = pr.directUDPAddr.String()
			} else if e.cryptoMgr.HasActiveSession(p.NodeKey) && e.relayCli.Connected() {
				ps.ActivePath = "relay"
			}
			if pr.lastRTTMicros > 0 {
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
		State:          stateStr,
		TUNName:        e.tunDev.Name(),
		SelfName:       nm.Self.Name,
		SelfNodeKey:    st.NodeKey.Public().ShortString(),
		ServerURL:      st.ServerURL,
		RelayConnected: e.relayCli.Connected(),
		MagicDNSSuffix: nm.DNS.MagicDNSSuffix,
		Revision:       nm.Revision,
		Peers:          peers,
	}
	if nm.Self.IPv4.IsValid() {
		res.IPv4 = nm.Self.IPv4.String()
	}
	if nm.Self.IPv6.IsValid() {
		res.IPv6 = nm.Self.IPv6.String()
	}
	return res
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
	e.sendControlOrProbeToPeer(pr, pkt)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
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
		// Seed initial UDP candidate if none learned yet
		if pr.directUDPAddr == nil && !e.disableUDP {
			for _, ep := range p.Endpoints {
				if ep.Proto == types.ProtoUDP {
					if uaddr, err := net.ResolveUDPAddr("udp", ep.Addr); err == nil {
						pr.directUDPAddr = uaddr
						break
					}
				}
			}
		}
		pr.mu.Unlock()

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

		// Session not yet established: buffer packet and trigger 1-RTT Noise-style handshake
		e.cryptoMgr.QueuePendingPacket(peerKey, pkt)
		pr.mu.Lock()
		shouldInit := time.Since(pr.lastHandshake) > 800*time.Millisecond
		if shouldInit {
			pr.lastHandshake = time.Now()
		}
		pr.mu.Unlock()

		if shouldInit {
			if initPkt, hsErr := e.cryptoMgr.InitiateHandshake(peerKey); hsErr == nil {
				e.sendControlOrProbeToPeer(pr, initPkt)
			}
		}
	}
}

func (e *Engine) udpReadLoop() {
	buf := make([]byte, 65535)
	for {
		n, raddr, err := e.udpConn.ReadFrom(buf)
		if err != nil {
			select {
			case <-e.closedCh:
				return
			default:
			}
			return
		}
		uaddr, _ := raddr.(*net.UDPAddr)
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		e.handleIncomingWirePacket(pkt, uaddr, false, types.PublicKey{})
	}
}

func (e *Engine) handleRelayedPacket(src types.PublicKey, inner []byte) {
	cp := make([]byte, len(inner))
	copy(cp, inner)
	e.handleIncomingWirePacket(cp, nil, true, src)
}

func (e *Engine) handleIncomingWirePacket(pkt []byte, fromUDP *net.UDPAddr, viaRelay bool, relaySrc types.PublicKey) {
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
		if fromUDP != nil {
			pr.mu.Lock()
			pr.directUDPAddr = fromUDP
			pr.lastDirectRx = time.Now()
			pr.mu.Unlock()
			_, _ = e.udpConn.WriteTo(ackPkt, fromUDP)
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
		if fromUDP != nil {
			pr.mu.Lock()
			pr.directUDPAddr = fromUDP
			pr.lastDirectRx = time.Now()
			pr.mu.Unlock()
		}
		e.flushQueuedPackets(pr, peerKey, queued)

	case protocol.PacketData:
		peerKey, plainIP, err := e.cryptoMgr.OpenPacket(pkt)
		if err != nil {
			return
		}
		if pr := e.getPeerRuntime(peerKey); pr != nil {
			pr.rxBytes.Add(uint64(len(plainIP)))
			if fromUDP != nil {
				pr.mu.Lock()
				pr.directUDPAddr = fromUDP
				pr.lastDirectRx = time.Now()
				pr.mu.Unlock()
			}
		}
		_ = e.tunDev.WritePacket(plainIP)

	case protocol.PacketPing:
		_, sender, probeID, txNano, _, err := protocol.DecodeProbePacket(pkt)
		if err != nil {
			return
		}
		st := e.stateMgr.Get()
		obs := ""
		if fromUDP != nil {
			obs = fromUDP.String()
		}
		pong := protocol.EncodeProbePacket(protocol.PacketPong, st.NodeKey.Public(), probeID, txNano, obs)
		if fromUDP != nil && e.udpConn != nil && !e.disableUDP {
			_, _ = e.udpConn.WriteTo(pong, fromUDP)
		} else if viaRelay && !relaySrc.IsZero() {
			_ = e.relayCli.Send(sender, pong)
		}

	case protocol.PacketPong:
		_, sender, probeID, txNano, obs, err := protocol.DecodeProbePacket(pkt)
		if err != nil {
			return
		}
		// STUN reflection response from server
		if sender == e.cryptoMgr.LocalPublicKey() && obs != "" {
			e.mu.Lock()
			e.stunObservedAddr = obs
			e.mu.Unlock()
			return
		}
		pr := e.getPeerRuntime(sender)
		if pr != nil {
			rtt := time.Since(time.Unix(0, txNano))
			pr.mu.Lock()
			pr.lastRTTMicros = rtt.Microseconds()
			if fromUDP != nil {
				pr.directUDPAddr = fromUDP
				pr.lastDirectRx = time.Now()
			}
			pr.mu.Unlock()
		}
		via := "relay"
		ep := "relay"
		if fromUDP != nil {
			via = "direct-udp"
			ep = fromUDP.String()
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

// sendWireToPeer sends data packets over verified direct UDP if active, else falls back to Relay + UDP probe.
func (e *Engine) sendWireToPeer(pr *peerRuntime, wirePkt []byte) {
	pr.mu.RLock()
	uaddr := pr.directUDPAddr
	directActive := uaddr != nil && time.Since(pr.lastDirectRx) < directActiveWindow
	peerKey := pr.meta.NodeKey
	pr.mu.RUnlock()

	if !e.disableUDP && e.udpConn != nil && directActive {
		_, _ = e.udpConn.WriteTo(wirePkt, uaddr)
		return
	}

	// Not yet verified direct: send over Relay for zero-wait delivery AND try direct UDP candidates
	_ = e.relayCli.Send(peerKey, wirePkt)
	if !e.disableUDP && e.udpConn != nil && uaddr != nil {
		_, _ = e.udpConn.WriteTo(wirePkt, uaddr)
	}
}

// sendControlOrProbeToPeer sends handshakes and pings across all candidate UDP endpoints + Relay simultaneously.
func (e *Engine) sendControlOrProbeToPeer(pr *peerRuntime, pkt []byte) {
	pr.mu.RLock()
	meta := pr.meta
	uaddr := pr.directUDPAddr
	pr.mu.RUnlock()

	if !e.disableUDP && e.udpConn != nil {
		sent := make(map[string]bool)
		if uaddr != nil {
			_, _ = e.udpConn.WriteTo(pkt, uaddr)
			sent[uaddr.String()] = true
		}
		for _, ep := range meta.Endpoints {
			if ep.Proto == types.ProtoUDP && !sent[ep.Addr] {
				if cand, err := net.ResolveUDPAddr("udp", ep.Addr); err == nil {
					_, _ = e.udpConn.WriteTo(pkt, cand)
					sent[ep.Addr] = true
				}
			}
		}
	}
	_ = e.relayCli.Send(meta.NodeKey, pkt)
}

func (e *Engine) collectLocalEndpoints() []types.Endpoint {
	if e.disableUDP || e.udpConn == nil {
		return nil
	}
	_, portStr, err := net.SplitHostPort(e.udpConn.LocalAddr().String())
	if err != nil || portStr == "0" {
		return nil
	}

	var out []types.Endpoint
	seen := make(map[string]bool)

	e.mu.RLock()
	stunObs := e.stunObservedAddr
	e.mu.RUnlock()
	if stunObs != "" && !seen[stunObs] {
		out = append(out, types.Endpoint{Proto: types.ProtoUDP, Addr: stunObs})
		seen[stunObs] = true
	}

	// If UDP socket bound to a specific IP (e.g. 127.0.0.1 in local tests), include it directly
	if host, _, err := net.SplitHostPort(e.udpConn.LocalAddr().String()); err == nil {
		if ip, parseErr := netip.ParseAddr(host); parseErr == nil && !ip.IsUnspecified() {
			addr := net.JoinHostPort(ip.String(), portStr)
			if !seen[addr] {
				out = append(out, types.Endpoint{Proto: types.ProtoUDP, Addr: addr, IsLAN: true})
				seen[addr] = true
			}
		}
	}

	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Name == e.tunDev.Name() {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipNet.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if ip.IsLinkLocalUnicast() || ip.IsLoopback() {
				continue
			}
			epStr := net.JoinHostPort(ip.String(), portStr)
			if !seen[epStr] {
				out = append(out, types.Endpoint{Proto: types.ProtoUDP, Addr: epStr, IsLAN: ip.IsPrivate()})
				seen[epStr] = true
			}
		}
	}
	return out
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

	e.sendSTUNProbe()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.sendSTUNProbe()
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

func (e *Engine) sendSTUNProbe() {
	if e.disableUDP || e.udpConn == nil {
		return
	}
	e.mu.RLock()
	relays := e.netMap.Relays
	e.mu.RUnlock()
	if len(relays) == 0 || relays[0].STUNAddr == "" {
		return
	}
	uaddr, err := net.ResolveUDPAddr("udp", relays[0].STUNAddr)
	if err != nil {
		return
	}
	pkt := protocol.EncodeProbePacket(protocol.PacketPing, e.cryptoMgr.LocalPublicKey(), e.probeSeq.Add(1), time.Now().UnixNano(), "")
	_, _ = e.udpConn.WriteTo(pkt, uaddr)
}

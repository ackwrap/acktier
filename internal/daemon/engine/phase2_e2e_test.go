package engine_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ackwrap/acktier/internal/daemon/engine"
	"github.com/ackwrap/acktier/internal/daemon/state"
	"github.com/ackwrap/acktier/internal/daemon/transport"
	"github.com/ackwrap/acktier/internal/daemon/tun"
	"github.com/ackwrap/acktier/internal/server/control"
	"github.com/ackwrap/acktier/internal/server/relay"
	"github.com/ackwrap/acktier/internal/server/store"
)

// --- Stateful Port-Restricted Cone NAT Fabric ---
// Simulates public UDP internet + private NAT gateways where inbound UDP from R -> NAT(L)
// is DROPPED unless L has previously transmitted an outbound UDP packet to R!

type natInternet struct {
	mu        sync.RWMutex
	publicMap map[string]*natEndpointConn // publicIP:port -> conn
}

func newNATInternet() *natInternet {
	return &natInternet{publicMap: make(map[string]*natEndpointConn)}
}

type natEndpointConn struct {
	inet        *natInternet
	localLAN    *net.UDPAddr
	publicWAN   *net.UDPAddr
	enforceNAT  bool
	allowedMu   sync.RWMutex
	allowedPeer map[string]bool // remote public addr allowed through stateful firewall
	rxCh        chan udpDatagram
	closed      chan struct{}
	once        sync.Once
}

func (ni *natInternet) BindPublicServer(pubAddr string) *natEndpointConn {
	u, _ := net.ResolveUDPAddr("udp", pubAddr)
	c := &natEndpointConn{
		inet:        ni,
		localLAN:    u,
		publicWAN:   u,
		enforceNAT:  false,
		allowedPeer: make(map[string]bool),
		rxCh:        make(chan udpDatagram, 256),
		closed:      make(chan struct{}),
	}
	ni.mu.Lock()
	ni.publicMap[u.String()] = c
	ni.mu.Unlock()
	return c
}

func (ni *natInternet) BindBehindConeNAT(lanAddr, wanMappedAddr string) *natEndpointConn {
	lAddr, _ := net.ResolveUDPAddr("udp", lanAddr)
	wAddr, _ := net.ResolveUDPAddr("udp", wanMappedAddr)
	c := &natEndpointConn{
		inet:        ni,
		localLAN:    lAddr,
		publicWAN:   wAddr,
		enforceNAT:  true,
		allowedPeer: make(map[string]bool),
		rxCh:        make(chan udpDatagram, 256),
		closed:      make(chan struct{}),
	}
	ni.mu.Lock()
	ni.publicMap[wAddr.String()] = c
	ni.mu.Unlock()
	return c
}

func (c *natEndpointConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case dg := <-c.rxCh:
		return copy(p, dg.data), dg.from, nil
	}
}

func (c *natEndpointConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	dstAddr := addr.String()
	// Outbound packet opens stateful Port-Restricted Cone NAT pinhole for dstAddr!
	if c.enforceNAT {
		c.allowedMu.Lock()
		c.allowedPeer[dstAddr] = true
		c.allowedMu.Unlock()
	}

	c.inet.mu.RLock()
	dst := c.inet.publicMap[dstAddr]
	c.inet.mu.RUnlock()
	if dst == nil {
		return len(p), nil // Unroutable private LAN IP or non-existent host -> silently dropped
	}

	// Check destination stateful NAT pinhole!
	if dst.enforceNAT {
		dst.allowedMu.RLock()
		permitted := dst.allowedPeer[c.publicWAN.String()]
		dst.allowedMu.RUnlock()
		if !permitted {
			// Blocked by stateful NAT firewall because dst hasn't punched to c.publicWAN yet!
			return len(p), nil
		}
	}

	cp := make([]byte, len(p))
	copy(cp, p)
	select {
	case dst.rxCh <- udpDatagram{from: c.publicWAN, data: cp}:
	default:
	}
	return len(p), nil
}

func (c *natEndpointConn) Close() error                       { c.once.Do(func() { close(c.closed) }); return nil }
func (c *natEndpointConn) LocalAddr() net.Addr                { return c.localLAN }
func (c *natEndpointConn) SetDeadline(_ time.Time) error      { return nil }
func (c *natEndpointConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *natEndpointConn) SetWriteDeadline(_ time.Time) error { return nil }

// --- Stream Switch for Multi-Protocol Failover E2E Test ---

type e2eMemAddr string

func (a e2eMemAddr) Network() string { return "tcp" }
func (a e2eMemAddr) String() string  { return string(a) }

type e2ePipeConn struct {
	net.Conn
	l, r net.Addr
}

func (p *e2ePipeConn) LocalAddr() net.Addr  { return p.l }
func (p *e2ePipeConn) RemoteAddr() net.Addr { return p.r }

type e2eListener struct {
	addr   e2eMemAddr
	accept chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func (l *e2eListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	case c := <-l.accept:
		return c, nil
	}
}
func (l *e2eListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *e2eListener) Addr() net.Addr { return l.addr }

type e2eStreamSwitch struct {
	mu   sync.RWMutex
	lns  map[string]*e2eListener
	port atomic.Uint32
}

func newE2EStreamSwitch() *e2eStreamSwitch {
	s := &e2eStreamSwitch{lns: make(map[string]*e2eListener)}
	s.port.Store(45000)
	return s
}

func (s *e2eStreamSwitch) Listen(addr string) net.Listener {
	l := &e2eListener{addr: e2eMemAddr(addr), accept: make(chan net.Conn, 32), closed: make(chan struct{})}
	s.mu.Lock()
	s.lns[addr] = l
	s.mu.Unlock()
	return l
}

func (s *e2eStreamSwitch) DialFrom(host string) transport.StreamDialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		s.mu.RLock()
		l := s.lns[addr]
		s.mu.RUnlock()
		if l == nil {
			return nil, errors.New("refused")
		}
		cAddr := e2eMemAddr(fmt.Sprintf("%s:%d", host, s.port.Add(1)))
		sAddr := e2eMemAddr(addr)
		// The WSS receive callback can reply synchronously. A TCP socket
		// buffers those replies even when both peers write at the same time.
		loopback, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		defer loopback.Close()
		var dialer net.Dialer
		c, err := dialer.DialContext(ctx, "tcp4", loopback.Addr().String())
		if err != nil {
			return nil, err
		}
		srv, err := loopback.Accept()
		if err != nil {
			_ = c.Close()
			return nil, err
		}
		select {
		case l.accept <- &e2ePipeConn{Conn: srv, l: sAddr, r: cAddr}:
			return &e2ePipeConn{Conn: c, l: cAddr, r: sAddr}, nil
		case <-ctx.Done():
			_ = c.Close()
			_ = srv.Close()
			return nil, ctx.Err()
		}
	}
}

func TestPhase2StatefulNATHolePunchAndWSSMultiTransport(t *testing.T) {
	tmp := t.TempDir()
	st, _ := store.NewFileStore("")
	pak, _ := st.CreatePreAuthKey("p2", true, false, nil, time.Hour)

	inet := newNATInternet()
	stun1 := inet.BindPublicServer("203.0.113.1:3478")
	defer stun1.Close()
	stun2 := inet.BindPublicServer("203.0.113.1:3479")
	defer stun2.Close()
	go relay.ServeSTUNLoop(stun1)
	go relay.ServeSTUNLoop(stun2)

	ctrlSrv := control.NewServer(control.Config{
		AdminToken:  "adm",
		PublicHost:  "203.0.113.1",
		RelayAddr:   "203.0.113.1:8080",
		STUNAddr:    "203.0.113.1:3478",
		STUNAltAddr: "203.0.113.1:3479",
	}, st)

	httpCli := &http.Client{Transport: &memRoundTripper{handler: ctrlSrv.Handler()}}
	relayDial := makeRelayDialer(ctrlSrv.Relay())

	// =========================================================================
	// Scenario 1: Two Nodes Behind Separate Stateful Port-Restricted Cone NATs!
	// Neither can reach the other's private IP (10.1.0.2 / 10.2.0.2), and inbound
	// packets to their WAN NAT ports (198.51.100.10:61001 / 192.0.2.20:62002)
	// are DROPPED until CallMeMaybe triggers simultaneous bidirectional punching!
	// =========================================================================
	stA, _ := state.LoadOrCreate(filepath.Join(tmp, "natA.json"))
	tunA := tun.NewMemoryDevice("ack0", tun.DefaultMTU)
	engA, _ := engine.New(engine.Options{
		State:      stA,
		TUN:        tunA,
		UDPConn:    inet.BindBehindConeNAT("10.1.0.2:51820", "198.51.100.10:61001"),
		HTTPClient: httpCli,
		RelayDial:  relayDial,
	})
	defer engA.Close()

	stB, _ := state.LoadOrCreate(filepath.Join(tmp, "natB.json"))
	tunB := tun.NewMemoryDevice("ack0", tun.DefaultMTU)
	engB, _ := engine.New(engine.Options{
		State:      stB,
		TUN:        tunB,
		UDPConn:    inet.BindBehindConeNAT("10.2.0.2:51820", "192.0.2.20:62002"),
		HTTPClient: httpCli,
		RelayDial:  relayDial,
	})
	defer engB.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	nmA, err := engA.Up(ctx, engine.UpRequest{ServerURL: "http://acktier.test", AuthKey: pak.Key, Hostname: "cone-a"})
	if err != nil {
		t.Fatalf("cone-a Up: %v", err)
	}
	nmB, err := engB.Up(ctx, engine.UpRequest{ServerURL: "http://acktier.test", AuthKey: pak.Key, Hostname: "cone-b"})
	if err != nil {
		t.Fatalf("cone-b Up: %v", err)
	}

	// Wait for Relay connection + NetCheck STUN classification on both nodes
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if engA.Status().RelayConnected && engB.Status().RelayConnected && len(engA.Status().Peers) >= 1 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	ncA := engA.NetCheck(ctx)
	ncB := engB.NetCheck(ctx)
	if ncA.NAT.NATType != "cone" || ncA.NAT.PublicUDPAddr != "198.51.100.10:61001" {
		t.Fatalf("expected cone-a NetCheck to detect cone NAT 198.51.100.10:61001, got %+v", ncA.NAT)
	}
	if ncB.NAT.NATType != "cone" || ncB.NAT.PublicUDPAddr != "192.0.2.20:62002" {
		t.Fatalf("expected cone-b NetCheck to detect cone NAT 192.0.2.20:62002, got %+v", ncB.NAT)
	}

	// Send first L3 packet: triggers CallMeMaybe over Relay -> simultaneous UDP hole punch!
	pkt1 := buildDummyIPv4Packet(nmA.Self.IPv4, nmB.Self.IPv4, []byte("punch-and-deliver-1"))
	_ = tunA.InjectOutbound(pkt1)
	select {
	case got := <-tunB.ReceiveInbound():
		if !bytes.Equal(got, pkt1) {
			t.Fatalf("corrupted packet 1")
		}
	case <-ctx.Done():
		t.Fatalf("timeout waiting for initial packet delivery")
	}

	// Wait briefly for CallMeMaybe punch burst Pong to complete, then verify path upgraded to direct-udp!
	upgraded := false
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		pr, pErr := engA.PingPeer(ctx, "cone-b")
		if pErr == nil && pr.Via == "direct-udp" {
			upgraded = true
			break
		}
		time.Sleep(60 * time.Millisecond)
	}
	if !upgraded {
		t.Fatalf("expected stateful Cone NAT nodes to punch holes and upgrade from relay -> direct-udp!")
	}

	// =========================================================================
	// Scenario 2: UDP Completely Blocked -> Direct WSS (WebSocket/TLS) Tunneling!
	// =========================================================================
	streamSw := newE2EStreamSwitch()

	stW1, _ := state.LoadOrCreate(filepath.Join(tmp, "wss1.json"))
	tunW1 := tun.NewMemoryDevice("ack0", tun.DefaultMTU)
	hubW1 := transport.NewHub()
	engW1, _ := engine.New(engine.Options{
		State:      stW1,
		TUN:        tunW1,
		Hub:        hubW1,
		HTTPClient: httpCli,
		RelayDial:  relayDial,
		DisableUDP: true,
	})
	defer engW1.Close()
	wssDrv1, _ := transport.NewWSSDriver(streamSw.Listen("172.16.0.10:8443"), streamSw.DialFrom("172.16.0.10"), engW1.OnTransportPacket)
	hubW1.Register(wssDrv1)

	stW2, _ := state.LoadOrCreate(filepath.Join(tmp, "wss2.json"))
	tunW2 := tun.NewMemoryDevice("ack0", tun.DefaultMTU)
	hubW2 := transport.NewHub()
	engW2, _ := engine.New(engine.Options{
		State:      stW2,
		TUN:        tunW2,
		Hub:        hubW2,
		HTTPClient: httpCli,
		RelayDial:  relayDial,
		DisableUDP: true,
	})
	defer engW2.Close()
	wssDrv2, _ := transport.NewWSSDriver(streamSw.Listen("172.16.0.20:8443"), streamSw.DialFrom("172.16.0.20"), engW2.OnTransportPacket)
	hubW2.Register(wssDrv2)

	nmW1, err := engW1.Up(ctx, engine.UpRequest{ServerURL: "http://acktier.test", AuthKey: pak.Key, Hostname: "corp-wss-1"})
	if err != nil {
		t.Fatalf("corp-wss-1 Up: %v", err)
	}
	nmW2, err := engW2.Up(ctx, engine.UpRequest{ServerURL: "http://acktier.test", AuthKey: pak.Key, Hostname: "corp-wss-2"})
	if err != nil {
		t.Fatalf("corp-wss-2 Up: %v", err)
	}

	// A first probe can get a relay reply while the peer map or WSS handshake
	// settles. Require an authenticated direct WSS reply within the deadline.
	wssCtx, cancelWSS := context.WithTimeout(ctx, 3*time.Second)
	defer cancelWSS()
	var lastPath string
	for {
		ping, err := engW1.PingPeer(wssCtx, "corp-wss-2")
		if err == nil {
			lastPath = ping.Via
			if lastPath == "direct-wss" {
				break
			}
		}
		select {
		case <-wssCtx.Done():
			t.Fatalf("expected direct-wss transport when UDP is disabled, last path %q: %v", lastPath, err)
		case <-time.After(25 * time.Millisecond):
		}
	}

	// Verify encrypted L3 IPv4 tunnel packet rides over Direct WSS!
	wssPkt := buildDummyIPv4Packet(nmW1.Self.IPv4, nmW2.Self.IPv4, []byte("corporate-firewall-traversed-via-wss-tls13"))
	_ = tunW1.InjectOutbound(wssPkt)
	select {
	case got := <-tunW2.ReceiveInbound():
		if !bytes.Equal(got, wssPkt) {
			t.Fatalf("corrupted L3 packet over WSS")
		}
	case <-ctx.Done():
		t.Fatalf("timeout waiting for L3 packet over Direct WSS")
	}
}

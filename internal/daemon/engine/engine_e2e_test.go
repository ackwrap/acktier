package engine_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/acktier/acktier/internal/daemon/engine"
	"github.com/acktier/acktier/internal/daemon/state"
	"github.com/acktier/acktier/internal/daemon/tun"
	"github.com/acktier/acktier/internal/server/control"
	"github.com/acktier/acktier/internal/server/relay"
	"github.com/acktier/acktier/internal/server/store"
)

// --- In-memory HTTP streaming RoundTripper (zero OS sockets needed) ---

type pipeResponseWriter struct {
	header     http.Header
	statusCh   chan int
	pw         *io.PipeWriter
	wroteHdr   bool
	mu         sync.Mutex
}

func (w *pipeResponseWriter) Header() http.Header { return w.header }

func (w *pipeResponseWriter) WriteHeader(code int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.wroteHdr {
		w.wroteHdr = true
		w.statusCh <- code
	}
}

func (w *pipeResponseWriter) Write(p []byte) (int, error) {
	w.WriteHeader(http.StatusOK)
	return w.pw.Write(p)
}

func (w *pipeResponseWriter) Flush() {}

type memRoundTripper struct {
	handler http.Handler
}

func (rt *memRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	pr, pw := io.Pipe()
	rw := &pipeResponseWriter{
		header:   make(http.Header),
		statusCh: make(chan int, 1),
		pw:       pw,
	}

	go func() {
		rt.handler.ServeHTTP(rw, req)
		rw.WriteHeader(http.StatusOK)
		_ = pw.Close()
	}()

	select {
	case <-req.Context().Done():
		_ = pr.Close()
		_ = pw.Close()
		return nil, req.Context().Err()
	case code := <-rw.statusCh:
		return &http.Response{
			StatusCode: code,
			Status:     fmt.Sprintf("%d %s", code, http.StatusText(code)),
			Header:     rw.header.Clone(),
			Body:       pr,
			Request:    req,
		}, nil
	}
}

// --- In-memory virtual UDP switch ---

type memUDPSwitch struct {
	mu    sync.RWMutex
	conns map[string]*memUDPConn
}

func newMemUDPSwitch() *memUDPSwitch {
	return &memUDPSwitch{conns: make(map[string]*memUDPConn)}
}

func (sw *memUDPSwitch) Listen(addrStr string) *memUDPConn {
	uaddr, _ := net.ResolveUDPAddr("udp", addrStr)
	c := &memUDPConn{
		sw:     sw,
		local:  uaddr,
		rxCh:   make(chan udpDatagram, 256),
		closed: make(chan struct{}),
	}
	sw.mu.Lock()
	sw.conns[uaddr.String()] = c
	sw.mu.Unlock()
	return c
}

type udpDatagram struct {
	from *net.UDPAddr
	data []byte
}

type memUDPConn struct {
	sw        *memUDPSwitch
	local     *net.UDPAddr
	rxCh      chan udpDatagram
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *memUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case dg := <-c.rxCh:
		n := copy(p, dg.data)
		return n, dg.from, nil
	}
}

func (c *memUDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	uaddr, err := net.ResolveUDPAddr("udp", addr.String())
	if err != nil {
		return 0, err
	}
	c.sw.mu.RLock()
	dst := c.sw.conns[uaddr.String()]
	c.sw.mu.RUnlock()
	if dst != nil {
		cp := make([]byte, len(p))
		copy(cp, p)
		select {
		case dst.rxCh <- udpDatagram{from: c.local, data: cp}:
		default:
		}
	}
	return len(p), nil
}

func (c *memUDPConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *memUDPConn) LocalAddr() net.Addr                { return c.local }
func (c *memUDPConn) SetDeadline(_ time.Time) error      { return nil }
func (c *memUDPConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *memUDPConn) SetWriteDeadline(_ time.Time) error { return nil }

func makeRelayDialer(relaySrv *relay.Server) engine.DialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		cConn, sConn := net.Pipe()
		go func() {
			br := bufio.NewReader(sConn)
			reqLine, err := br.ReadString('\n')
			if err != nil || !strings.Contains(reqLine, "/relay") {
				_ = sConn.Close()
				return
			}
			for {
				line, err := br.ReadString('\n')
				if err != nil || line == "\r\n" || line == "\n" {
					break
				}
			}
			_, _ = sConn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: acktier-relay\r\nConnection: Upgrade\r\n\r\n"))
			relaySrv.ServeConn(sConn)
		}()
		return cConn, nil
	}
}

// buildDummyIPv4Packet crafts a minimal valid 20-byte IPv4 header + payload.
func buildDummyIPv4Packet(src, dst netip.Addr, payload []byte) []byte {
	total := 20 + len(payload)
	pkt := make([]byte, total)
	pkt[0] = 0x45 // IPv4, IHL=5 (20 bytes)
	pkt[2] = byte(total >> 8)
	pkt[3] = byte(total)
	pkt[8] = 64 // TTL
	pkt[9] = 1  // ICMP
	s4 := src.As4()
	d4 := dst.As4()
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	copy(pkt[20:], payload)
	return pkt
}

func TestEndToEndDirectUDPAndRelayFallback(t *testing.T) {
	tmp := t.TempDir()
	st, err := store.NewFileStore(filepath.Join(tmp, "server.json"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	pak, err := st.CreatePreAuthKey("e2e-key", true, false, nil, time.Hour)
	if err != nil {
		t.Fatalf("create key: %v", err)
	}

	ctrlSrv := control.NewServer(control.Config{
		AdminToken: "adm_test",
		PublicHost: "10.0.0.100",
		RelayAddr:  "10.0.0.100:8080",
	}, st)

	httpCli := &http.Client{Transport: &memRoundTripper{handler: ctrlSrv.Handler()}}
	relayDial := makeRelayDialer(ctrlSrv.Relay())
	udpSwitch := newMemUDPSwitch()

	// =========================================================================
	// Part 1: Direct UDP P2P Encrypted Tunnel between Node Alpha & Node Beta
	// =========================================================================
	stateA, _ := state.LoadOrCreate(filepath.Join(tmp, "alpha.json"))
	tunA := tun.NewMemoryDevice("ack0", tun.DefaultMTU)
	engA, err := engine.New(engine.Options{
		State:      stateA,
		TUN:        tunA,
		UDPConn:    udpSwitch.Listen("198.51.100.11:51820"),
		HTTPClient: httpCli,
		RelayDial:  relayDial,
	})
	if err != nil {
		t.Fatalf("new engine A: %v", err)
	}
	defer engA.Close()

	stateB, _ := state.LoadOrCreate(filepath.Join(tmp, "beta.json"))
	tunB := tun.NewMemoryDevice("ack0", tun.DefaultMTU)
	engB, err := engine.New(engine.Options{
		State:      stateB,
		TUN:        tunB,
		UDPConn:    udpSwitch.Listen("198.51.100.22:51820"),
		HTTPClient: httpCli,
		RelayDial:  relayDial,
	})
	if err != nil {
		t.Fatalf("new engine B: %v", err)
	}
	defer engB.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	nmA, err := engA.Up(ctx, engine.UpRequest{ServerURL: "http://acktier.test", AuthKey: pak.Key, Hostname: "alpha-node"})
	if err != nil {
		t.Fatalf("Alpha Up: %v", err)
	}
	nmB, err := engB.Up(ctx, engine.UpRequest{ServerURL: "http://acktier.test", AuthKey: pak.Key, Hostname: "beta-node"})
	if err != nil {
		t.Fatalf("Beta Up: %v", err)
	}

	// Wait until Alpha receives Beta in its NetMap via live NDJSON stream
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(engA.Status().Peers) >= 1 && len(engB.Status().Peers) >= 1 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if len(engA.Status().Peers) < 1 {
		t.Fatalf("Alpha did not receive Beta via live NetMap stream")
	}

	// Verify Direct UDP Ping
	pingRes, err := engA.PingPeer(ctx, "beta-node")
	if err != nil {
		t.Fatalf("PingPeer beta-node failed: %v", err)
	}
	if pingRes.Via != "direct-udp" {
		t.Fatalf("expected direct-udp path, got %s", pingRes.Via)
	}

	// Inject L3 IPv4 packet from Alpha -> Beta and verify E2EE handshake + delivery
	msgAB := []byte("hello-beta-over-e2ee-direct-udp")
	pktAB := buildDummyIPv4Packet(nmA.Self.IPv4, nmB.Self.IPv4, msgAB)
	if err := tunA.InjectOutbound(pktAB); err != nil {
		t.Fatalf("InjectOutbound A: %v", err)
	}

	select {
	case gotPkt := <-tunB.ReceiveInbound():
		if !bytes.Equal(gotPkt, pktAB) {
			t.Fatalf("Beta received corrupted L3 packet")
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timeout waiting for Beta TUN to receive decrypted direct UDP packet")
	}

	// =========================================================================
	// Part 2: Strict Firewall (UDP Blocked) -> Automatic Center Relay Fallback
	// =========================================================================
	stateC, _ := state.LoadOrCreate(filepath.Join(tmp, "gamma.json"))
	tunC := tun.NewMemoryDevice("ack0", tun.DefaultMTU)
	engC, err := engine.New(engine.Options{
		State:      stateC,
		TUN:        tunC,
		HTTPClient: httpCli,
		RelayDial:  relayDial,
		DisableUDP: true,
	})
	if err != nil {
		t.Fatalf("new engine C: %v", err)
	}
	defer engC.Close()

	stateD, _ := state.LoadOrCreate(filepath.Join(tmp, "delta.json"))
	tunD := tun.NewMemoryDevice("ack0", tun.DefaultMTU)
	engD, err := engine.New(engine.Options{
		State:      stateD,
		TUN:        tunD,
		HTTPClient: httpCli,
		RelayDial:  relayDial,
		DisableUDP: true,
	})
	if err != nil {
		t.Fatalf("new engine D: %v", err)
	}
	defer engD.Close()

	nmC, err := engC.Up(ctx, engine.UpRequest{ServerURL: "http://acktier.test", AuthKey: pak.Key, Hostname: "gamma-node"})
	if err != nil {
		t.Fatalf("Gamma Up: %v", err)
	}
	nmD, err := engD.Up(ctx, engine.UpRequest{ServerURL: "http://acktier.test", AuthKey: pak.Key, Hostname: "delta-node"})
	if err != nil {
		t.Fatalf("Delta Up: %v", err)
	}

	// Wait for both Gamma and Delta to bind to Relay & sync NetMap
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		stC := engC.Status()
		stD := engD.Status()
		if stC.RelayConnected && stD.RelayConnected && len(stC.Peers) >= 3 && len(stD.Peers) >= 3 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !engC.Status().RelayConnected || !engD.Status().RelayConnected {
		t.Fatalf("Gamma/Delta failed to connect to Relay server")
	}

	relayPing, err := engC.PingPeer(ctx, "delta-node")
	if err != nil {
		t.Fatalf("PingPeer delta-node over relay failed: %v", err)
	}
	if relayPing.Via != "relay" {
		t.Fatalf("expected relay path when UDP is blocked, got %s", relayPing.Via)
	}

	msgCD := []byte("hello-delta-over-encrypted-relay-fallback")
	pktCD := buildDummyIPv4Packet(nmC.Self.IPv4, nmD.Self.IPv4, msgCD)
	if err := tunC.InjectOutbound(pktCD); err != nil {
		t.Fatalf("InjectOutbound C: %v", err)
	}

	select {
	case gotRelayed := <-tunD.ReceiveInbound():
		if !bytes.Equal(gotRelayed, pktCD) {
			t.Fatalf("Delta received corrupted L3 packet via relay")
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timeout waiting for Delta TUN to receive decrypted relayed packet")
	}

	_, frames, _ := ctrlSrv.Relay().Stats()
	if frames == 0 {
		t.Fatalf("expected relay server forwardedFrames > 0")
	}
}

package acknet_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/acktier/acktier/internal/server/control"
	"github.com/acktier/acktier/internal/server/relay"
	"github.com/acktier/acktier/internal/server/store"
	"github.com/acktier/acktier/pkg/acknet"
	"github.com/acktier/acktier/pkg/client"
)

// --- Sandbox-friendly in-memory HTTP & UDP helpers ---

type pipeRespWriter struct {
	hdr      http.Header
	statusCh chan int
	pw       *io.PipeWriter
	once     sync.Once
}

func (w *pipeRespWriter) Header() http.Header { return w.hdr }
func (w *pipeRespWriter) WriteHeader(code int) {
	w.once.Do(func() { w.statusCh <- code })
}
func (w *pipeRespWriter) Write(p []byte) (int, error) {
	w.WriteHeader(http.StatusOK)
	return w.pw.Write(p)
}
func (w *pipeRespWriter) Flush() {}

type memHTTP struct{ h http.Handler }

func (m *memHTTP) RoundTrip(req *http.Request) (*http.Response, error) {
	pr, pw := io.Pipe()
	rw := &pipeRespWriter{hdr: make(http.Header), statusCh: make(chan int, 1), pw: pw}
	go func() {
		m.h.ServeHTTP(rw, req)
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
			Status:     fmt.Sprintf("%d OK", code),
			Header:     rw.hdr.Clone(),
			Body:       pr,
			Request:    req,
		}, nil
	}
}

type memUDPHub struct {
	mu    sync.RWMutex
	conns map[string]*memUDP
}

type memUDP struct {
	hub    *memUDPHub
	local  *net.UDPAddr
	rx     chan struct {
		from *net.UDPAddr
		b    []byte
	}
	closed chan struct{}
	once   sync.Once
}

func newMemUDPHub() *memUDPHub { return &memUDPHub{conns: make(map[string]*memUDP)} }

func (h *memUDPHub) Bind(addr string) *memUDP {
	u, _ := net.ResolveUDPAddr("udp", addr)
	c := &memUDP{
		hub:   h,
		local: u,
		rx: make(chan struct {
			from *net.UDPAddr
			b    []byte
		}, 512),
		closed: make(chan struct{}),
	}
	h.mu.Lock()
	h.conns[u.String()] = c
	h.mu.Unlock()
	return c
}

func (c *memUDP) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case m := <-c.rx:
		return copy(p, m.b), m.from, nil
	}
}

func (c *memUDP) WriteTo(p []byte, addr net.Addr) (int, error) {
	u, err := net.ResolveUDPAddr("udp", addr.String())
	if err != nil {
		return 0, err
	}
	c.hub.mu.RLock()
	dst := c.hub.conns[u.String()]
	c.hub.mu.RUnlock()
	if dst != nil {
		cp := make([]byte, len(p))
		copy(cp, p)
		select {
		case dst.rx <- struct {
			from *net.UDPAddr
			b    []byte
		}{from: c.local, b: cp}:
		default:
		}
	}
	return len(p), nil
}

func (c *memUDP) Close() error                       { c.once.Do(func() { close(c.closed) }); return nil }
func (c *memUDP) LocalAddr() net.Addr                { return c.local }
func (c *memUDP) SetDeadline(_ time.Time) error      { return nil }
func (c *memUDP) SetReadDeadline(_ time.Time) error  { return nil }
func (c *memUDP) SetWriteDeadline(_ time.Time) error { return nil }

func makePipeRelayDialer(rs *relay.Server) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		c, s := net.Pipe()
		go func() {
			br := bufio.NewReader(s)
			for {
				line, err := br.ReadString('\n')
				if err != nil || line == "\r\n" || line == "\n" {
					break
				}
			}
			_, _ = s.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: acktier-relay\r\nConnection: Upgrade\r\n\r\n"))
			rs.ServeConn(s)
		}()
		return c, nil
	}
}

func TestSDK_AckNetHTTP_UDP_SOCKS5_And_EmbeddedClientInterop(t *testing.T) {
	st, err := store.NewFileStore("")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	ctrlSrv := control.NewServer(control.Config{
		AdminToken: "adm_sdk_token",
		PublicHost: "10.0.0.1",
		RelayAddr:  "10.0.0.1:8080",
	}, st)
	ctrlHTTP := &http.Client{Transport: &memHTTP{h: ctrlSrv.Handler()}}
	relayDial := makePipeRelayDialer(ctrlSrv.Relay())
	udpHub := newMemUDPHub()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Test AdminClient SDK: create a reusable PreAuthKey programmatically
	admin := client.NewAdminClient("http://acktier.sdk", "adm_sdk_token", ctrlHTTP)
	pak, err := admin.CreatePreAuthKey(ctx, client.CreateKeyOptions{
		Label:    "sdk-key",
		Reusable: true,
	})
	if err != nil {
		t.Fatalf("AdminClient.CreatePreAuthKey: %v", err)
	}

	// 2. Start embedded `acknet.Server` #1 ("payment-api") hosting a standard Go `http.Server` + UDP Echo!
	srvAPI := &acknet.Server{
		Hostname:           "payment-api",
		ControlURL:         "http://acktier.sdk",
		AuthKey:            pak.Key,
		DisableDefaultBind: true,
		CustomUDPConn:      udpHub.Bind("172.30.0.11:51820"),
		HTTPClientOverride: ctrlHTTP,
		RelayDial:          relayDial,
	}
	defer srvAPI.Close()

	tcpLn, err := srvAPI.Listen("tcp", ":8080")
	if err != nil {
		t.Fatalf("srvAPI.Listen tcp: %v", err)
	}
	defer tcpLn.Close()

	// 24 KB payload exercises multi-segment TCP MSS splitting (1240B * ~20 segments) & sliding-window ACKs!
	largeBanner := bytes.Repeat([]byte("ACKNET-SDK-STREAM-OK-"), 1150)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/large", func(w http.ResponseWriter, r *http.Request) {
		reqBytes, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Client-Echo", string(reqBytes))
		_, _ = w.Write(largeBanner)
	})
	httpServer := &http.Server{Handler: mux}
	defer httpServer.Close()
	go func() { _ = httpServer.Serve(tcpLn) }()

	udpEchoConn, err := srvAPI.ListenPacket("udp", ":9090")
	if err != nil {
		t.Fatalf("srvAPI.ListenPacket udp: %v", err)
	}
	defer udpEchoConn.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, raddr, err := udpEchoConn.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = udpEchoConn.WriteTo(append([]byte("udp-ack:"), buf[:n]...), raddr)
		}
	}()

	// 3. Start embedded `acknet.Server` #2 ("web-caller") and call `payment-api.ack.internal:8080` via HTTPClient()!
	srvCaller := &acknet.Server{
		Hostname:           "web-caller",
		ControlURL:         "http://acktier.sdk",
		AuthKey:            pak.Key,
		DisableDefaultBind: true,
		CustomUDPConn:      udpHub.Bind("172.30.0.22:51820"),
		HTTPClientOverride: ctrlHTTP,
		RelayDial:          relayDial,
	}
	defer srvCaller.Close()
	if _, err := srvCaller.Up(ctx); err != nil {
		t.Fatalf("srvCaller.Up: %v", err)
	}

	resp, err := srvCaller.HTTPClient().Post(
		"http://payment-api.ack.internal:8080/v1/large",
		"text/plain",
		strings.NewReader("hello-from-sdk"),
	)
	if err != nil {
		t.Fatalf("srvCaller.HTTPClient().Post over MagicDNS failed: %v", err)
	}
	gotBody, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP status=%d read err=%v", resp.StatusCode, err)
	}
	if resp.Header.Get("X-Client-Echo") != "hello-from-sdk" || !bytes.Equal(gotBody, largeBanner) {
		t.Fatalf("HTTP payload mismatch: got %d bytes, want %d bytes", len(gotBody), len(largeBanner))
	}

	// 4. Test `srvCaller.Dial("udp", "payment-api.ack.internal:9090")`
	uConn, err := srvCaller.Dial(ctx, "udp", "payment-api.ack.internal:9090")
	if err != nil {
		t.Fatalf("srvCaller.Dial udp: %v", err)
	}
	defer uConn.Close()
	_ = uConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _ = uConn.Write([]byte("ping-dgram"))
	uBuf := make([]byte, 256)
	uN, err := uConn.Read(uBuf)
	if err != nil || string(uBuf[:uN]) != "udp-ack:ping-dgram" {
		t.Fatalf("unexpected UDP echo: err=%v data=%q", err, string(uBuf[:uN]))
	}

	// 5. Test `srvCaller.ServeSOCKS5` with MagicDNS ATYP=0x03 domain name!
	socksClientConn, socksServerConn := net.Pipe()
	socksLn := &singleConnListener{conn: socksServerConn, done: make(chan struct{})}
	go func() { _ = srvCaller.ServeSOCKS5(socksLn) }()

	// Perform RFC 1928 SOCKS5 handshake for "payment-api.ack.internal:8080"
	_, _ = socksClientConn.Write([]byte{0x05, 0x01, 0x00})
	var greetAck [2]byte
	if _, err := io.ReadFull(socksClientConn, greetAck[:]); err != nil || greetAck != [2]byte{0x05, 0x00} {
		t.Fatalf("SOCKS5 greeting failed: %v %v", err, greetAck)
	}
	dom := "payment-api.ack.internal"
	socksReq := make([]byte, 0, 7+len(dom))
	socksReq = append(socksReq, 0x05, 0x01, 0x00, 0x03, byte(len(dom)))
	socksReq = append(socksReq, []byte(dom)...)
	socksReq = binary.BigEndian.AppendUint16(socksReq, 8080)
	_, _ = socksClientConn.Write(socksReq)

	var socksReply [10]byte
	if _, err := io.ReadFull(socksClientConn, socksReply[:]); err != nil || socksReply[1] != 0x00 {
		t.Fatalf("SOCKS5 CONNECT failed: err=%v reply=%v", err, socksReply)
	}
	_, _ = socksClientConn.Write([]byte("POST /v1/large HTTP/1.1\r\nHost: payment-api.ack.internal:8080\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsocks5"))
	socksHTTPResp, err := http.ReadResponse(bufio.NewReader(socksClientConn), nil)
	if err != nil || socksHTTPResp.Header.Get("X-Client-Echo") != "socks5" {
		t.Fatalf("HTTP over SOCKS5 failed: err=%v", err)
	}
	_ = socksHTTPResp.Body.Close()
	_ = socksClientConn.Close()

	// 6. Test Interop between `acknet.Server` and `client.Node` (Subnet Router + DaemonClient SDK!)
	gwNodeCfg := client.NodeConfig{
		Hostname:      "intranet-gw",
		TUNMode:       client.TUNMemory,
		CustomUDPConn: udpHub.Bind("172.30.0.33:51820"),
		HTTPClient:    ctrlHTTP,
		RelayDial:     relayDial,
		GatewayTCPDial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != "192.168.88.5:6379" {
				return nil, errors.New("refused")
			}
			c, s := net.Pipe()
			go func() {
				defer s.Close()
				_, _ = s.Write([]byte("+PONG-FROM-SUBNET-REDIS\r\n"))
			}()
			return c, nil
		},
	}
	gwNode, err := client.NewNode(gwNodeCfg)
	if err != nil {
		t.Fatalf("client.NewNode: %v", err)
	}
	defer gwNode.Close()

	// Control gwNode via `client.DaemonClient` over its authenticated LocalAPIHandler!
	daemonCLI := client.NewDaemonClient("http://local.daemon", &http.Client{
		Transport: &memHTTP{h: gwNode.LocalAPIHandler()},
	})
	daemonCLI.SetToken(gwNode.LocalAPIToken())
	subnetPfx := netip.MustParsePrefix("192.168.88.0/24")
	nmGW, err := daemonCLI.Up(ctx, client.UpOptions{
		ServerURL:        "http://acktier.sdk",
		AuthKey:          pak.Key,
		Hostname:         "intranet-gw",
		AdvertisedRoutes: []netip.Prefix{subnetPfx},
	})
	if err != nil {
		t.Fatalf("DaemonClient.Up: %v", err)
	}

	// Approve route via AdminClient SDK!
	if _, err := admin.ApproveRoutes(ctx, nmGW.Self.ID, []netip.Prefix{subnetPfx}); err != nil {
		t.Fatalf("AdminClient.ApproveRoutes: %v", err)
	}

	// Wait for route propagation to srvCaller
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		stCaller := srvCaller.Node().Status()
		if len(stCaller.Peers) >= 2 {
			foundRoute := false
			for _, p := range stCaller.Peers {
				if p.Name == "intranet-gw" && len(p.AllowedIPs) >= 3 {
					foundRoute = true
				}
			}
			if foundRoute {
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}

	// Zero-privilege `acknet.Server` dials `192.168.88.5:6379` across the encrypted mesh into `client.Node` Subnet Router!
	redisConn, err := srvCaller.Dial(ctx, "tcp", "192.168.88.5:6379")
	if err != nil {
		t.Fatalf("srvCaller.Dial subnet 192.168.88.5:6379 failed: %v", err)
	}
	defer redisConn.Close()
	line, err := bufio.NewReader(redisConn).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "+PONG-FROM-SUBNET-REDIS" {
		t.Fatalf("unexpected Subnet Router Redis banner: err=%v line=%q", err, line)
	}
}

type singleConnListener struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *singleConnListener) Close() error   { close(l.done); return nil }
func (l *singleConnListener) Addr() net.Addr { return &net.TCPAddr{} }

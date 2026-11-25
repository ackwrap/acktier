package engine_test

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acktier/acktier/internal/daemon/engine"
	"github.com/acktier/acktier/internal/daemon/state"
	"github.com/acktier/acktier/internal/daemon/tun"
	"github.com/acktier/acktier/internal/server/control"
	"github.com/acktier/acktier/internal/server/relay"
	"github.com/acktier/acktier/internal/server/store"
)

// roamingUDPFabric supports dynamic blackhole injection AND live WAN IP:Port roaming (Wi-Fi -> Hotspot handoff).
type roamingUDPFabric struct {
	mu          sync.RWMutex
	connsByWAN  map[string]*roamingConn
	blackholed  atomic.Bool // When true, non-STUN peer-to-peer UDP packets are silently dropped!
	stunAddrs   map[string]bool
	peerLatency time.Duration
}

func newRoamingUDPFabric() *roamingUDPFabric {
	return &roamingUDPFabric{
		connsByWAN: make(map[string]*roamingConn),
		stunAddrs:  make(map[string]bool),
	}
}

type roamingConn struct {
	fab       *roamingUDPFabric
	mu        sync.RWMutex
	localAddr *net.UDPAddr
	wanAddr   *net.UDPAddr
	rxCh      chan udpDatagram
	closed    chan struct{}
	once      sync.Once
}

func (f *roamingUDPFabric) Bind(localStr, wanStr string, isSTUN bool) *roamingConn {
	l, _ := net.ResolveUDPAddr("udp", localStr)
	w, _ := net.ResolveUDPAddr("udp", wanStr)
	c := &roamingConn{
		fab:       f,
		localAddr: l,
		wanAddr:   w,
		rxCh:      make(chan udpDatagram, 512),
		closed:    make(chan struct{}),
	}
	f.mu.Lock()
	f.connsByWAN[w.String()] = c
	if isSTUN {
		f.stunAddrs[w.String()] = true
	}
	f.mu.Unlock()
	return c
}

// RebindWAN simulates the laptop switching from Wi-Fi WAN IP to 5G Hotspot WAN IP!
func (c *roamingConn) RebindWAN(newLocalStr, newWANStr string) {
	newL, _ := net.ResolveUDPAddr("udp", newLocalStr)
	newW, _ := net.ResolveUDPAddr("udp", newWANStr)

	c.mu.Lock()
	oldW := c.wanAddr.String()
	c.localAddr = newL
	c.wanAddr = newW
	c.mu.Unlock()

	c.fab.mu.Lock()
	delete(c.fab.connsByWAN, oldW)
	c.fab.connsByWAN[newW.String()] = c
	c.fab.mu.Unlock()
}

func (c *roamingConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case dg := <-c.rxCh:
		return copy(p, dg.data), dg.from, nil
	}
}

func (c *roamingConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	dstStr := addr.String()
	c.mu.RLock()
	srcWAN := c.wanAddr
	c.mu.RUnlock()

	c.fab.mu.RLock()
	isSTUN := c.fab.stunAddrs[dstStr] || c.fab.stunAddrs[srcWAN.String()]
	dst := c.fab.connsByWAN[dstStr]
	lat := c.fab.peerLatency
	c.fab.mu.RUnlock()

	// Silent blackhole: WriteTo returns success (len(p), nil) with ZERO OS error, but packet vanishes in transit!
	if !isSTUN && c.fab.blackholed.Load() {
		return len(p), nil
	}
	if dst == nil {
		return len(p), nil
	}

	cp := make([]byte, len(p))
	copy(cp, p)
	deliver := func() {
		select {
		case <-dst.closed:
		case dst.rxCh <- udpDatagram{from: srcWAN, data: cp}:
		default:
		}
	}
	if !isSTUN && lat > 0 {
		time.AfterFunc(lat, deliver)
	} else {
		deliver()
	}
	return len(p), nil
}

func (c *roamingConn) Close() error { c.once.Do(func() { close(c.closed) }); return nil }
func (c *roamingConn) LocalAddr() net.Addr {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.localAddr
}
func (c *roamingConn) SetDeadline(_ time.Time) error      { return nil }
func (c *roamingConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *roamingConn) SetWriteDeadline(_ time.Time) error { return nil }

func TestFastBlackholeFailover_CenterRelayCostComparison_And_InstantRoaming(t *testing.T) {
	tmp := t.TempDir()
	st, _ := store.NewFileStore("")
	pak, _ := st.CreatePreAuthKey("polish", true, false, nil, time.Hour)

	fab := newRoamingUDPFabric()
	stunSrv := fab.Bind("203.0.113.1:3478", "203.0.113.1:3478", true)
	defer stunSrv.Close()
	go relay.ServeSTUNLoop(stunSrv)

	ctrlSrv := control.NewServer(control.Config{
		AdminToken: "adm",
		PublicHost: "203.0.113.1",
		RelayAddr:  "203.0.113.1:8080",
		STUNAddr:   "203.0.113.1:3478",
	}, st)
	httpCli := &http.Client{Transport: &memRoundTripper{handler: ctrlSrv.Handler()}}
	relayDial := makeRelayDialer(ctrlSrv.Relay())

	connMobile := fab.Bind("198.51.100.50:51820", "198.51.100.50:51820", false)
	connServer := fab.Bind("203.0.113.99:51820", "203.0.113.99:51820", false)

	stMobile, _ := state.LoadOrCreate(filepath.Join(tmp, "mobile.json"))
	tunMobile := tun.NewMemoryDevice("ack0", tun.DefaultMTU)
	engMobile, _ := engine.New(engine.Options{
		State:               stMobile,
		TUN:                 tunMobile,
		UDPConn:             connMobile,
		HTTPClient:          httpCli,
		RelayDial:           relayDial,
		BlackholeProbeAfter: 120 * time.Millisecond,
		BlackholeTimeout:    280 * time.Millisecond,
	})
	defer engMobile.Close()

	stServer, _ := state.LoadOrCreate(filepath.Join(tmp, "server.json"))
	tunServer := tun.NewMemoryDevice("ack0", tun.DefaultMTU)
	engServer, _ := engine.New(engine.Options{
		State:               stServer,
		TUN:                 tunServer,
		UDPConn:             connServer,
		HTTPClient:          httpCli,
		RelayDial:           relayDial,
		BlackholeProbeAfter: 120 * time.Millisecond,
		BlackholeTimeout:    280 * time.Millisecond,
	})
	defer engServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	nmMobile, err := engMobile.Up(ctx, engine.UpRequest{ServerURL: "http://acktier.test", AuthKey: pak.Key, Hostname: "mobile-laptop"})
	if err != nil {
		t.Fatalf("mobile Up: %v", err)
	}
	nmServer, err := engServer.Up(ctx, engine.UpRequest{ServerURL: "http://acktier.test", AuthKey: pak.Key, Hostname: "core-server"})
	if err != nil {
		t.Fatalf("server Up: %v", err)
	}

	// Wait for Relay connection + direct UDP verification
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if engMobile.Status().RelayConnected && engServer.Status().RelayConnected && len(engMobile.Status().Peers) >= 1 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	// Verify initial Direct-UDP connectivity & CenterRelayRTTMs > 0
	p0, err := engMobile.PingPeer(ctx, "core-server")
	if err != nil || p0.Via != "direct-udp" {
		t.Fatalf("expected initial direct-udp, got err=%v res=%+v", err, p0)
	}
	if engMobile.Status().CenterRelayRTTMs <= 0 {
		t.Fatalf("expected CenterRelayRTTMs to be measured > 0, got %f", engMobile.Status().CenterRelayRTTMs)
	}
	// Establish E2EE data session while direct-udp is healthy
	initData := buildDummyIPv4Packet(nmMobile.Self.IPv4, nmServer.Self.IPv4, []byte("warmup-direct"))
	_ = tunMobile.InjectOutbound(initData)
	select {
	case <-tunServer.ReceiveInbound():
	case <-ctx.Done():
		t.Fatalf("warmup packet failed")
	}

	// =========================================================================
	// 1. Silent UDP Blackhole -> Fast Failover to Relay (in ~300ms, NOT 45s!)
	// =========================================================================
	fab.blackholed.Store(true)

	// Send outbound packets across the blackhole window to trigger UnansweredTxSince -> FastProbe -> Failover!
	deliveredOverRelay := false
	startBlackhole := time.Now()
	for time.Since(startBlackhole) < 1200*time.Millisecond {
		probePayload := []byte("survived-silent-udp-blackhole")
		pkt := buildDummyIPv4Packet(nmMobile.Self.IPv4, nmServer.Self.IPv4, probePayload)
		_ = tunMobile.InjectOutbound(pkt)
		select {
		case got := <-tunServer.ReceiveInbound():
			if bytes.Equal(got, pkt) {
				deliveredOverRelay = true
			}
		case <-time.After(60 * time.Millisecond):
		}
		if deliveredOverRelay && engMobile.Status().Peers[0].ActivePath == "relay" {
			break
		}
	}
	if !deliveredOverRelay {
		t.Fatalf("traffic failed to automatically fail over to Relay during silent UDP blackhole!")
	}
	if gotPath := engMobile.Status().Peers[0].ActivePath; gotPath != "relay" {
		t.Fatalf("expected ActivePath to downgrade to 'relay' after silent blackhole, got %q", gotPath)
	}

	// Lift UDP blackhole -> verify automatic recovery back to direct-udp!
	fab.blackholed.Store(false)
	pRecover, err := engMobile.PingPeer(ctx, "core-server")
	if err != nil || pRecover.Via != "direct-udp" {
		t.Fatalf("expected automatic recovery back to direct-udp once blackhole cleared, got err=%v res=%+v", err, pRecover)
	}

	// =========================================================================
	// 2. Host Network Handoff (Wi-Fi -> 5G Hotspot) Instant Roaming!
	// =========================================================================
	connMobile.RebindWAN("172.20.10.4:55111", "192.0.2.88:60123")
	engMobile.NotifyNetworkChange()

	// Wait briefly (<800ms) for instant STUN + Heartbeat + Roaming probes to update core-server!
	roamed := false
	deadline = time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		srvPeers := engServer.Status().Peers
		if len(srvPeers) > 0 && srvPeers[0].DirectAddr == "192.0.2.88:60123" {
			roamed = true
			break
		}
		time.Sleep(35 * time.Millisecond)
	}
	if !roamed {
		t.Fatalf("expected core-server to immediately roam mobile-laptop DirectAddr to 192.0.2.88:60123, got %+v", engServer.Status().Peers)
	}

	// Verify E2EE packet from core-server -> mobile-laptop's NEW Hotspot IP arrives immediately!
	roamPkt := buildDummyIPv4Packet(nmServer.Self.IPv4, nmMobile.Self.IPv4, []byte("welcome-to-5g-hotspot"))
	_ = tunServer.InjectOutbound(roamPkt)
	select {
	case gotRoam := <-tunMobile.ReceiveInbound():
		if !bytes.Equal(gotRoam, roamPkt) {
			t.Fatalf("corrupted packet after 5G roaming")
		}
	case <-ctx.Done():
		t.Fatalf("timeout delivering packet to roamed 5G hotspot address")
	}

	// =========================================================================
	// 3. Center Relay RTT Beats High-Latency Multi-Hop Peer Relay!
	// =========================================================================
	segFab := newSegmentedFabric()
	// Slow edge peer relay: EdgeA <-> SlowRelay (90ms) + SlowRelay <-> EdgeB (90ms) => ~181.5ms total!
	// Center Relay RTT is < 2ms (+ 6ms penalty = ~8ms) => Center Relay MUST beat SlowRelay!
	segFab.ConnectBidirectional("10.80.1.1:51820", "10.80.2.1:51820", 90*time.Millisecond)
	segFab.ConnectBidirectional("10.80.2.1:51820", "10.80.3.1:51820", 90*time.Millisecond)

	spawnSeg := func(name, addr string, canRelay bool) (*engine.Engine, *tun.MemoryDevice) {
		sm, _ := state.LoadOrCreate(filepath.Join(tmp, name+".json"))
		td := tun.NewMemoryDevice("ack0", tun.DefaultMTU)
		eng, _ := engine.New(engine.Options{
			State:      sm,
			TUN:        td,
			UDPConn:    segFab.Bind(addr),
			HTTPClient: httpCli,
			RelayDial:  relayDial,
		})
		return eng, td
	}

	engEdgeA, tunEdgeA := spawnSeg("edge-a", "10.80.1.1:51820", false)
	defer engEdgeA.Close()
	engSlowRelay, _ := spawnSeg("slow-home-relay", "10.80.2.1:51820", true)
	defer engSlowRelay.Close()
	engEdgeB, tunEdgeB := spawnSeg("edge-b", "10.80.3.1:51820", false)
	defer engEdgeB.Close()

	nmEdgeA, _ := engEdgeA.Up(ctx, engine.UpRequest{ServerURL: "http://acktier.test", AuthKey: pak.Key, Hostname: "edge-a"})
	_, _ = engSlowRelay.Up(ctx, engine.UpRequest{ServerURL: "http://acktier.test", AuthKey: pak.Key, Hostname: "slow-home-relay", CanRelay: true})
	nmEdgeB, _ := engEdgeB.Up(ctx, engine.UpRequest{ServerURL: "http://acktier.test", AuthKey: pak.Key, Hostname: "edge-b"})

	// Allow both Peer-Relay mesh graph (~181ms) and Center Relay (~8ms) to establish
	time.Sleep(450 * time.Millisecond)

	// Send E2EE session + data between EdgeA and EdgeB
	fastCenterPkt := buildDummyIPv4Packet(nmEdgeA.Self.IPv4, nmEdgeB.Self.IPv4, []byte("prefer-fast-center-relay-over-180ms-home-hop"))
	_ = tunEdgeA.InjectOutbound(fastCenterPkt)
	select {
	case got := <-tunEdgeB.ReceiveInbound():
		if !bytes.Equal(got, fastCenterPkt) {
			t.Fatalf("corrupted packet")
		}
	case <-ctx.Done():
		t.Fatalf("timeout delivering packet over preferred Center Relay")
	}

	// Verify EdgeA selected "relay" (fast ~1ms Center Relay) instead of 180ms "peer-relay"!
	for _, p := range engEdgeA.Status().Peers {
		if p.Name == "edge-b" && p.ActivePath != "relay" {
			t.Fatalf("expected Center Relay (~8ms cost) to beat 180ms Peer Relay, but ActivePath=%q", p.ActivePath)
		}
	}
}

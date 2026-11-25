package engine_test

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"path/filepath"
	"strings"
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
	"github.com/acktier/acktier/pkg/types"
)

type wanLinkSpec struct {
	oneWayDelay time.Duration
	dropEveryN  uint64
	seq         *atomic.Uint64 // Per-direction packet counter so Ping & Pong don't resonate on shared global counter!
}

type transpacificFabric struct {
	mu    sync.RWMutex
	byWAN map[string]*tpConn
	specs map[[2]string]wanLinkSpec
}

func newTranspacificFabric() *transpacificFabric {
	return &transpacificFabric{
		byWAN: make(map[string]*tpConn),
		specs: make(map[[2]string]wanLinkSpec),
	}
}

func (f *transpacificFabric) SetLink(wanA, wanB string, delay time.Duration, dropEveryN uint64) {
	uA, _ := net.ResolveUDPAddr("udp", wanA)
	uB, _ := net.ResolveUDPAddr("udp", wanB)
	f.mu.Lock()
	f.specs[[2]string{uA.String(), uB.String()}] = wanLinkSpec{oneWayDelay: delay, dropEveryN: dropEveryN, seq: &atomic.Uint64{}}
	f.specs[[2]string{uB.String(), uA.String()}] = wanLinkSpec{oneWayDelay: delay, dropEveryN: dropEveryN, seq: &atomic.Uint64{}}
	f.mu.Unlock()
}

type tpConn struct {
	fab    *transpacificFabric
	local  *net.UDPAddr
	wan    *net.UDPAddr
	rxCh   chan udpDatagram
	closed chan struct{}
	once   sync.Once
}

func (f *transpacificFabric) Bind(localAddrStr, wanAddrStr string) *tpConn {
	l, _ := net.ResolveUDPAddr("udp", localAddrStr)
	w, _ := net.ResolveUDPAddr("udp", wanAddrStr)
	c := &tpConn{
		fab:    f,
		local:  l,
		wan:    w,
		rxCh:   make(chan udpDatagram, 512),
		closed: make(chan struct{}),
	}
	f.mu.Lock()
	f.byWAN[w.String()] = c
	f.mu.Unlock()
	return c
}

func (c *tpConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case dg := <-c.rxCh:
		return copy(p, dg.data), dg.from, nil
	}
}

func (c *tpConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	dstAddr, err := net.ResolveUDPAddr("udp", addr.String())
	if err != nil {
		return 0, err
	}
	srcW := c.wan.String()
	dstW := dstAddr.String()

	c.fab.mu.RLock()
	dst := c.fab.byWAN[dstW]
	spec, hasSpec := c.fab.specs[[2]string{srcW, dstW}]
	c.fab.mu.RUnlock()

	if dst == nil || !hasSpec {
		return len(p), nil
	}
	if spec.dropEveryN > 0 {
		seq := spec.seq.Add(1)
		if seq%spec.dropEveryN == 0 {
			return len(p), nil // Simulated peak-hour 163 packet loss!
		}
	}

	cp := make([]byte, len(p))
	copy(cp, p)
	deliver := func() {
		select {
		case <-dst.closed:
		case dst.rxCh <- udpDatagram{from: c.wan, data: cp}:
		default:
		}
	}
	if spec.oneWayDelay > 0 {
		time.AfterFunc(spec.oneWayDelay, deliver)
	} else {
		deliver()
	}
	return len(p), nil
}

func (c *tpConn) Close() error                       { c.once.Do(func() { close(c.closed) }); return nil }
func (c *tpConn) LocalAddr() net.Addr                { return c.local }
func (c *tpConn) SetDeadline(_ time.Time) error      { return nil }
func (c *tpConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *tpConn) SetWriteDeadline(_ time.Time) error { return nil }

func TestUSWestCN2AutoSteppingStoneOverLossyOrdinaryRoute(t *testing.T) {
	tmp := t.TempDir()
	st, _ := store.NewFileStore("")
	pak, _ := st.CreatePreAuthKey("cn2-demo", true, false, nil, time.Hour)

	fab := newTranspacificFabric()
	const (
		stunWAN  = "203.0.113.1:3478"
		homeLAN  = "10.88.1.50:51820"  // Private RFC1918 NAT leaf!
		homeWAN  = "198.18.0.50:61000" // Public NAT mapped IP
		cn2Pub   = "203.0.113.10:51820" // Public IP directly on US-West CN2 NIC!
		ordPub   = "198.51.100.20:51820" // Public IP directly on US-West Ordinary 163 NIC!
	)

	stunConn := fab.Bind(stunWAN, stunWAN)
	defer stunConn.Close()
	go relay.ServeSTUNLoop(stunConn)

	// STUN reachable by all
	fab.SetLink(homeWAN, stunWAN, 2*time.Millisecond, 0)
	fab.SetLink(cn2Pub, stunWAN, 2*time.Millisecond, 0)
	fab.SetLink(ordPub, stunWAN, 2*time.Millisecond, 0)

	// Transpacific link physics:
	// 1) Home <-> US-West CN2: 15ms one-way (30ms RTT), 0% packet loss!
	fab.SetLink(homeWAN, cn2Pub, 15*time.Millisecond, 0)
	// 2) US-West CN2 <-> US-West Ordinary 163 (same-region LA peering!): 1ms one-way (2ms RTT), 0% loss!
	fab.SetLink(cn2Pub, ordPub, 1*time.Millisecond, 0)
	// 3) Home <-> US-West Ordinary 163: 17ms one-way (34ms RTT — almost identical RTT to CN2!),
	//    BUT 33% per-leg packet loss (dropEveryN=3 -> some Pongs succeed with 34ms RTT, while loss penalty adds >100ms)!
	fab.SetLink(homeWAN, ordPub, 17*time.Millisecond, 3)

	// Center Relay disabled so routing is purely P2P Direct vs CN2 Stepping-Stone!
	ctrlSrv := control.NewServer(control.Config{
		AdminToken: "adm",
		PublicHost: "203.0.113.1",
		STUNAddr:   stunWAN,
	}, st)
	httpCli := &http.Client{Transport: &memRoundTripper{handler: ctrlSrv.Handler()}}

	spawn := func(name, localBind, wanBind string) (*engine.Engine, *tun.MemoryDevice) {
		sm, _ := state.LoadOrCreate(filepath.Join(tmp, name+".json"))
		td := tun.NewMemoryDevice("ack0", tun.DefaultMTU)
		eng, err := engine.New(engine.Options{
			State:      sm,
			TUN:        td,
			UDPConn:    fab.Bind(localBind, wanBind),
			HTTPClient: httpCli,
		})
		if err != nil {
			t.Fatalf("new engine %s: %v", name, err)
		}
		return eng, td
	}

	engHome, tunHome := spawn("cn-home", homeLAN, homeWAN)
	defer engHome.Close()
	engCN2, _ := spawn("us-west-cn2", cn2Pub, cn2Pub)
	defer engCN2.Close()
	engOrd, tunOrd := spawn("us-west-163", ordPub, ordPub)
	defer engOrd.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Notice: ZERO `CanRelay: true` flags passed anywhere! Everything runs with default `RelayMode: "auto"`!
	nmHome, err := engHome.Up(ctx, engine.UpRequest{ServerURL: "http://acktier.test", AuthKey: pak.Key, Hostname: "cn-home"})
	if err != nil {
		t.Fatalf("cn-home Up: %v", err)
	}
	if _, err := engCN2.Up(ctx, engine.UpRequest{ServerURL: "http://acktier.test", AuthKey: pak.Key, Hostname: "us-west-cn2"}); err != nil {
		t.Fatalf("us-west-cn2 Up: %v", err)
	}
	nmOrd, err := engOrd.Up(ctx, engine.UpRequest{ServerURL: "http://acktier.test", AuthKey: pak.Key, Hostname: "us-west-163"})
	if err != nil {
		t.Fatalf("us-west-163 Up: %v", err)
	}

	// 1. Verify Zero-Config Auto-Relay classification:
	//    - cn-home (10.88.1.50 behind NAT) MUST stay CanRelay == false!
	//    - us-west-cn2 (203.0.113.10 public IP) MUST automatically enable CanRelay == true!
	if engHome.Status().CanRelay {
		t.Fatalf("expected private NAT leaf cn-home to stay CanRelay=false in auto mode")
	}
	if !engCN2.Status().CanRelay {
		t.Fatalf("expected public IP node us-west-cn2 to automatically enable CanRelay=true in auto mode!")
	}

	// Wait for STUN + 5-probe calibration bursts to measure loss on us-west-163 and converge on CN2 stepping-stone!
	// Also run NetCheck on cn-home so cn-home advertises its WAN NAT address to peers.
	_ = engHome.NetCheck(ctx)
	selectedCN2 := false
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		for _, p := range engHome.Status().Peers {
			if p.Name == "us-west-163" && p.ActivePath == "peer-relay" && strings.Contains(p.MeshHops, "us-west-cn2") {
				selectedCN2 = true
				break
			}
		}
		if selectedCN2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !selectedCN2 {
		t.Fatalf("expected cn-home to automatically select us-west-cn2 stepping-stone over lossy us-west-163 direct link! peers=%+v mesh=%+v",
			engHome.Status().Peers, engHome.MeshStatus().Routes)
	}

	// 2. Send 12 consecutive bidirectional E2EE packets: ALL 12 MUST arrive with 0% loss via us-west-cn2!
	for i := 0; i < 12; i++ {
		msg := []byte("lossless-via-cn2-stepping-stone")
		pktOut := buildDummyIPv4Packet(nmHome.Self.IPv4, nmOrd.Self.IPv4, msg)
		_ = tunHome.InjectOutbound(pktOut)
		select {
		case got := <-tunOrd.ReceiveInbound():
			if !bytes.Equal(got, pktOut) {
				t.Fatalf("packet #%d corrupted", i)
			}
		case <-time.After(1500 * time.Millisecond):
			t.Fatalf("packet #%d cn-home -> us-west-163 dropped/timed out!", i)
		}

		pktReply := buildDummyIPv4Packet(nmOrd.Self.IPv4, nmHome.Self.IPv4, []byte("symmetric-cn2-return"))
		_ = tunOrd.InjectOutbound(pktReply)
		select {
		case gotR := <-tunHome.ReceiveInbound():
			if !bytes.Equal(gotR, pktReply) {
				t.Fatalf("return packet #%d corrupted", i)
			}
		case <-time.After(1500 * time.Millisecond):
			t.Fatalf("return packet #%d us-west-163 -> cn-home dropped/timed out!", i)
		}
	}

	if engCN2.Status().PeerRelayedFrames < 20 {
		t.Fatalf("expected us-west-cn2 to relay bidirectional traffic frames, got %d", engCN2.Status().PeerRelayedFrames)
	}

	// 3. Verify `--relay-mode=off` override disables relaying even on a Public IP VPS (metered traffic protection)
	if _, err := engCN2.Up(ctx, engine.UpRequest{
		ServerURL: "http://acktier.test",
		Hostname:  "us-west-cn2",
		RelayMode: types.RelayModeOff,
	}); err != nil {
		t.Fatalf("re-up with RelayModeOff: %v", err)
	}
	if engCN2.Status().CanRelay {
		t.Fatalf("expected RelayModeOff to force CanRelay=false on public VPS")
	}
}

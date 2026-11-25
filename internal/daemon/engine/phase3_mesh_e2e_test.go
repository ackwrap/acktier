package engine_test

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/acktier/acktier/internal/daemon/engine"
	"github.com/acktier/acktier/internal/daemon/state"
	"github.com/acktier/acktier/internal/daemon/tun"
	"github.com/acktier/acktier/internal/server/control"
	"github.com/acktier/acktier/internal/server/store"
)

// segmentedFabric simulates isolated L3 network islands where UDP packets can only pass
// between explicitly connected pairs (adjacency matrix), with optional link latency.
type segmentedFabric struct {
	mu    sync.RWMutex
	conns map[string]*segUDPConn
	links map[[2]string]time.Duration // [src, dst] -> delay
}

func newSegmentedFabric() *segmentedFabric {
	return &segmentedFabric{
		conns: make(map[string]*segUDPConn),
		links: make(map[[2]string]time.Duration),
	}
}

func (f *segmentedFabric) ConnectBidirectional(addrA, addrB string, delay time.Duration) {
	uA, _ := net.ResolveUDPAddr("udp", addrA)
	uB, _ := net.ResolveUDPAddr("udp", addrB)
	f.mu.Lock()
	f.links[[2]string{uA.String(), uB.String()}] = delay
	f.links[[2]string{uB.String(), uA.String()}] = delay
	f.mu.Unlock()
}

type segUDPConn struct {
	fab    *segmentedFabric
	local  *net.UDPAddr
	rxCh   chan udpDatagram
	closed chan struct{}
	once   sync.Once
}

func (f *segmentedFabric) Bind(addr string) *segUDPConn {
	u, _ := net.ResolveUDPAddr("udp", addr)
	c := &segUDPConn{
		fab:    f,
		local:  u,
		rxCh:   make(chan udpDatagram, 512),
		closed: make(chan struct{}),
	}
	f.mu.Lock()
	f.conns[u.String()] = c
	f.mu.Unlock()
	return c
}

func (c *segUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case dg := <-c.rxCh:
		return copy(p, dg.data), dg.from, nil
	}
}

func (c *segUDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	u, err := net.ResolveUDPAddr("udp", addr.String())
	if err != nil {
		return 0, err
	}
	srcStr := c.local.String()
	dstStr := u.String()

	c.fab.mu.RLock()
	delay, reachable := c.fab.links[[2]string{srcStr, dstStr}]
	dst := c.fab.conns[dstStr]
	c.fab.mu.RUnlock()

	if !reachable || dst == nil {
		return len(p), nil // Unreachable across isolated network islands!
	}

	cp := make([]byte, len(p))
	copy(cp, p)
	deliver := func() {
		select {
		case <-dst.closed:
		case dst.rxCh <- udpDatagram{from: c.local, data: cp}:
		default:
		}
	}
	if delay > 0 {
		time.AfterFunc(delay, deliver)
	} else {
		deliver()
	}
	return len(p), nil
}

func (c *segUDPConn) Close() error                       { c.once.Do(func() { close(c.closed) }); return nil }
func (c *segUDPConn) LocalAddr() net.Addr                { return c.local }
func (c *segUDPConn) SetDeadline(_ time.Time) error      { return nil }
func (c *segUDPConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *segUDPConn) SetWriteDeadline(_ time.Time) error { return nil }

func TestPhase3ThreeHopPeerRelayAndSelfHealingReroute(t *testing.T) {
	tmp := t.TempDir()
	st, _ := store.NewFileStore("")
	pak, _ := st.CreatePreAuthKey("mesh", true, false, nil, time.Hour)

	// Center Relay is intentionally DISABLED (RelayAddr: "") so ONLY Peer-to-Peer Mesh Relay can bridge islands!
	ctrlSrv := control.NewServer(control.Config{
		AdminToken: "adm",
		PublicHost: "203.0.113.1",
		RelayAddr:  "",
	}, st)
	httpCli := &http.Client{Transport: &memRoundTripper{handler: ctrlSrv.Handler()}}

	fab := newSegmentedFabric()
	const (
		addrWest   = "10.10.0.1:51820"
		addrT1     = "10.20.0.1:51820"
		addrT2     = "10.30.0.1:51820"
		addrBackup = "10.40.0.1:51820"
		addrEast   = "10.50.0.1:51820"
	)

	// Primary 3-hop fast path: Edge-West <-> Transit-1 <-> Transit-2 <-> Edge-East
	fab.ConnectBidirectional(addrWest, addrT1, 0)
	fab.ConnectBidirectional(addrT1, addrT2, 0)
	fab.ConnectBidirectional(addrT2, addrEast, 0)

	// Backup higher-latency bridge: Edge-West <-> Transit-Backup <-> Edge-East (25ms each way)
	fab.ConnectBidirectional(addrWest, addrBackup, 25*time.Millisecond)
	fab.ConnectBidirectional(addrBackup, addrEast, 25*time.Millisecond)

	spawnNode := func(name, udpBind string, canRelay bool) (*engine.Engine, *tun.MemoryDevice) {
		sm, err := state.LoadOrCreate(filepath.Join(tmp, name+".json"))
		if err != nil {
			t.Fatalf("state %s: %v", name, err)
		}
		td := tun.NewMemoryDevice("ack0", tun.DefaultMTU)
		eng, err := engine.New(engine.Options{
			State:      sm,
			TUN:        td,
			UDPConn:    fab.Bind(udpBind),
			HTTPClient: httpCli,
		})
		if err != nil {
			t.Fatalf("engine %s: %v", name, err)
		}
		return eng, td
	}

	engWest, tunWest := spawnNode("edge-west", addrWest, false)
	defer engWest.Close()
	engT1, _ := spawnNode("transit-1", addrT1, true)
	defer engT1.Close()
	engT2, _ := spawnNode("transit-2", addrT2, true)
	defer engT2.Close()
	engEast, tunEast := spawnNode("edge-east", addrEast, false)
	defer engEast.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	nmWest, err := engWest.Up(ctx, engine.UpRequest{ServerURL: "http://acktier.test", AuthKey: pak.Key, Hostname: "edge-west"})
	if err != nil {
		t.Fatalf("edge-west Up: %v", err)
	}
	if _, err := engT1.Up(ctx, engine.UpRequest{ServerURL: "http://acktier.test", AuthKey: pak.Key, Hostname: "transit-1", CanRelay: true}); err != nil {
		t.Fatalf("transit-1 Up: %v", err)
	}
	if _, err := engT2.Up(ctx, engine.UpRequest{ServerURL: "http://acktier.test", AuthKey: pak.Key, Hostname: "transit-2", CanRelay: true}); err != nil {
		t.Fatalf("transit-2 Up: %v", err)
	}
	nmEast, err := engEast.Up(ctx, engine.UpRequest{ServerURL: "http://acktier.test", AuthKey: pak.Key, Hostname: "edge-east"})
	if err != nil {
		t.Fatalf("edge-east Up: %v", err)
	}

	// Wait for link-state advertisements to converge into a 3-hop route on Edge-West -> Edge-East
	converged := false
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		ms := engWest.MeshStatus()
		for _, r := range ms.Routes {
			if r.TargetName == "edge-east" && r.Mode == "peer-relay" && len(r.HopChain) == 3 {
				converged = true
				break
			}
		}
		if converged {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	if !converged {
		t.Fatalf("3-hop Dijkstra mesh route did not converge on edge-west; routes=%+v", engWest.MeshStatus().Routes)
	}

	// 1. Verify Ping over 3-hop Peer Relay Mesh (`transit-1 -> transit-2 -> edge-east`)
	ping1, err := engWest.PingPeer(ctx, "edge-east")
	if err != nil {
		t.Fatalf("PingPeer edge-east over 3-hop mesh failed: %v", err)
	}
	if ping1.Via != "peer-relay" || !strings.Contains(ping1.Endpoint, "transit-1 -> transit-2 -> edge-east") {
		t.Fatalf("expected 3-hop peer-relay via transit-1 -> transit-2 -> edge-east, got via=%s ep=%s", ping1.Via, ping1.Endpoint)
	}

	// 2. Verify E2EE L3 IPv4 bidirectional tunneling across both Transit-1 and Transit-2
	payloadWE := []byte("e2ee-payload-across-3-hop-smart-mesh")
	pktWE := buildDummyIPv4Packet(nmWest.Self.IPv4, nmEast.Self.IPv4, payloadWE)
	if err := tunWest.InjectOutbound(pktWE); err != nil {
		t.Fatalf("InjectOutbound West: %v", err)
	}
	select {
	case got := <-tunEast.ReceiveInbound():
		if !bytes.Equal(got, pktWE) {
			t.Fatalf("East received corrupted packet over 3-hop mesh")
		}
	case <-ctx.Done():
		t.Fatalf("timeout waiting for East TUN to receive 3-hop mesh packet")
	}

	if engT1.Status().PeerRelayedFrames == 0 || engT2.Status().PeerRelayedFrames == 0 {
		t.Fatalf("expected both transit-1 (%d) and transit-2 (%d) to forward ciphertext frames",
			engT1.Status().PeerRelayedFrames, engT2.Status().PeerRelayedFrames)
	}

	// =========================================================================
	// 3. Dynamic Link-Failure Self-Healing:
	// Bring up Transit-Backup, then shut down Transit-1 -> traffic must reroute
	// automatically via `transit-backup -> edge-east` with zero session loss!
	// =========================================================================
	engBackup, _ := spawnNode("transit-backup", addrBackup, true)
	defer engBackup.Close()
	if _, err := engBackup.Up(ctx, engine.UpRequest{ServerURL: "http://acktier.test", AuthKey: pak.Key, Hostname: "transit-backup", CanRelay: true}); err != nil {
		t.Fatalf("transit-backup Up: %v", err)
	}

	// Wait briefly for backup links to establish, then kill Transit-1!
	time.Sleep(200 * time.Millisecond)
	engT1.Down()

	rerouted := false
	deadline = time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		ms := engWest.MeshStatus()
		for _, r := range ms.Routes {
			if r.TargetName == "edge-east" && r.NextHopName == "transit-backup" {
				rerouted = true
				break
			}
		}
		if rerouted {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	if !rerouted {
		t.Fatalf("expected mesh router to self-heal via transit-backup after transit-1 went down; got %+v", engWest.MeshStatus().Routes)
	}

	// Send another L3 IPv4 packet over the already-established E2EE session -> must arrive via Transit-Backup!
	pktReroute := buildDummyIPv4Packet(nmWest.Self.IPv4, nmEast.Self.IPv4, []byte("survived-node-outage-via-backup-mesh-hop"))
	_ = tunWest.InjectOutbound(pktReroute)
	select {
	case got2 := <-tunEast.ReceiveInbound():
		if !bytes.Equal(got2, pktReroute) {
			t.Fatalf("corrupted rerouted packet")
		}
	case <-ctx.Done():
		t.Fatalf("timeout waiting for self-healed rerouted packet via transit-backup")
	}

	if engBackup.Status().PeerRelayedFrames == 0 {
		t.Fatalf("expected transit-backup to forward self-healed ciphertext frames")
	}
}

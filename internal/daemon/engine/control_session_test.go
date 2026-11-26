package engine

import (
	"context"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ackwrap/acktier/internal/daemon/state"
	"github.com/ackwrap/acktier/internal/daemon/transport"
	"github.com/ackwrap/acktier/internal/daemon/tun"
	"github.com/ackwrap/acktier/pkg/types"
)

type recordingUDP struct {
	targets []string
}

func (*recordingUDP) Proto() types.TransportProto { return types.ProtoUDP }
func (*recordingUDP) LocalAddr() string           { return "0.0.0.0:51820" }
func (*recordingUDP) Close() error                { return nil }
func (d *recordingUDP) Send(_ context.Context, addr string, _ []byte) error {
	d.targets = append(d.targets, addr)
	return nil
}

func TestPeerSendValidatesTheActualDestination(t *testing.T) {
	driver := &recordingUDP{}
	hub := transport.NewHub()
	hub.Register(driver)
	e := Engine{hub: hub, selector: transport.NewSelector(), running: true, controlUntil: time.Now().Add(time.Minute)}
	for _, addr := range []string{"host.example.test:9", "[::ffff:127.0.0.1]:9", "100.64.0.10:9", "169.254.0.1:9"} {
		if err := e.sendPeerPacket(t.Context(), types.Endpoint{Proto: types.ProtoUDP, Addr: addr}, nil); err == nil {
			t.Errorf("unsafe endpoint %q was sent", addr)
		}
	}
	if err := e.sendPeerPacket(t.Context(), types.Endpoint{Proto: types.ProtoUDP, Addr: "[::ffff:192.168.1.2]:51820"}, nil); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(driver.targets, []string{"192.168.1.2:51820"}) {
		t.Fatalf("unexpected transport destinations: %v", driver.targets)
	}
}

func TestControlLeaseRequiresCurrentSessionAndRevision(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st, err := state.LoadOrCreate("")
		if err != nil {
			t.Fatal(err)
		}
		e, err := New(Options{State: st, TUN: tun.NewMemoryDevice("test", 0), ControlLeaseTTL: 2 * time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		defer e.Close()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		e.controlCtx = ctx
		e.mu.Lock()
		e.running = true
		e.mu.Unlock()
		go e.watchControlLease(ctx)

		nm := types.NetMap{Revision: 42, Self: types.PeerNode{ID: 1, NodeKey: st.Get().NodeKey.Public()}}
		ev := types.MapStreamEvent{Type: "netmap", NetMap: &nm}
		if e.acceptControlEvent(t.Context(), ev) || e.isRunning() {
			t.Fatal("a different control session enabled the data plane")
		}
		if !e.acceptControlEvent(ctx, ev) || !e.isRunning() {
			t.Fatal("authorized snapshot did not enable the data plane")
		}
		time.Sleep(time.Minute)
		if e.acceptControlEvent(ctx, types.MapStreamEvent{Type: "keepalive", Revision: 43}) {
			t.Fatal("keepalive renewed an obsolete map")
		}
		if !e.acceptControlEvent(ctx, types.MapStreamEvent{Type: "keepalive", Revision: 42}) {
			t.Fatal("current keepalive did not renew its map")
		}
		time.Sleep(time.Minute + time.Second)
		if !e.isRunning() {
			t.Fatal("data plane expired before the renewed deadline")
		}
		time.Sleep(time.Minute)
		synctest.Wait()
		if got := e.Status(); got.State != "WaitingForControl" || got.Revision != 0 {
			t.Fatalf("expiration did not clear the snapshot: state=%s rev=%d", got.State, got.Revision)
		}
		if !e.acceptControlEvent(ctx, ev) || !e.isRunning() {
			t.Fatal("fresh snapshot did not restore connectivity")
		}
	})
}

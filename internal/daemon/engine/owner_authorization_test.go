package engine

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ackwrap/acktier/internal/daemon/state"
	"github.com/ackwrap/acktier/internal/daemon/tun"
	"github.com/ackwrap/acktier/internal/owner"
	"github.com/ackwrap/acktier/pkg/types"
)

func TestOwnerKeepaliveCannotRenewSignedExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir := t.TempDir()
		st, err := state.LoadOrCreate(filepath.Join(dir, "node.json"))
		if err != nil {
			t.Fatal(err)
		}
		pub, key, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		trust := owner.NewTrust(pub, 1)
		trustFile := filepath.Join(dir, "trust.json")
		raw, _ := json.Marshal(trust)
		if err := os.WriteFile(trustFile, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		e, err := New(Options{State: st, TUN: tun.NewMemoryDevice("test", 0), OwnerTrustFile: trustFile, RequireOwner: true})
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

		now := time.Now()
		s := owner.Snapshot{
			Version: 1, ExpiresAt: now.Add(time.Minute), PacketFilter: []types.FilterRule{owner.DenyAll()},
			Members: []owner.Member{{ID: 42, NodeKey: st.Get().NodeKey.Public(), Name: "test", IPv4: netip.MustParseAddr("100.64.0.5")}},
		}
		env, err := owner.Sign(s, key, now)
		if err != nil {
			t.Fatal(err)
		}
		nm := types.NetMap{OwnerNetworkID: trust.NetworkID(), Revision: 5, OwnerAuthorization: &env}
		if !e.acceptControlEvent(ctx, types.MapStreamEvent{Type: "netmap", NetMap: &nm}) || !e.isRunning() {
			t.Fatal("signed authorization was not installed")
		}
		e.handleControlRejection(ctx, http.StatusUnauthorized)
		e.handleControlRejection(ctx, http.StatusForbidden)
		unsigned := nm
		unsigned.OwnerAuthorization = nil
		if e.acceptControlEvent(ctx, types.MapStreamEvent{Type: "netmap", NetMap: &unsigned}) || !e.isRunning() {
			t.Fatal("unsigned update or HTTP refusal affected installed authorization")
		}
		time.Sleep(59 * time.Second)
		if !e.acceptControlEvent(ctx, types.MapStreamEvent{Type: "keepalive", Revision: 5}) {
			t.Fatal("matching heartbeat rejected before expiry")
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if e.isRunning() || e.Status().Revision != 0 {
			t.Fatal("signed authorization survived past its expiry")
		}
	})
}

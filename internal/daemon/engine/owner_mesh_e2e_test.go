package engine_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/acktier/acktier/internal/daemon/engine"
	"github.com/acktier/acktier/internal/daemon/pktutil"
	"github.com/acktier/acktier/internal/daemon/state"
	"github.com/acktier/acktier/internal/daemon/tun"
	"github.com/acktier/acktier/internal/owner"
	"github.com/acktier/acktier/internal/server/control"
	"github.com/acktier/acktier/internal/server/store"
	"github.com/acktier/acktier/pkg/client"
	"github.com/acktier/acktier/pkg/types"
)

func TestOwnerLockedEnrollmentAndRevocation(t *testing.T) {
	temp := t.TempDir()
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	trust := owner.NewTrust(pub, 1)
	trustFile := filepath.Join(temp, "trust.json")
	trustJSON, _ := json.Marshal(trust)
	if err := os.WriteFile(trustFile, trustJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.NewFileStore("")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ConfigureOwner(trust); err != nil {
		t.Fatal(err)
	}
	const serverURL = "http://127.0.0.1:8080"
	ctrl := control.NewServer(control.Config{AdminToken: "test-admin"}, st)
	httpCli := &http.Client{Transport: &memRoundTripper{handler: ctrl.Handler()}}
	admin := client.NewAdminClient(serverURL, "test-admin", httpCli)
	switchUDP := newMemUDPSwitch()
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()

	newNode := func(name, endpoint string) (*engine.Engine, *tun.MemoryDevice, types.PublicKey) {
		t.Helper()
		pak, err := st.CreatePreAuthKey(name, false, false, nil, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		stMgr, err := state.LoadOrCreate(filepath.Join(temp, name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		dev := tun.NewMemoryDevice(name, 0)
		e, err := engine.New(engine.Options{
			State: stMgr, TUN: dev, OwnerTrustFile: trustFile, RequireOwner: true, HTTPClient: httpCli,
			UDPConn: switchUDP.Listen(endpoint), RelayDial: makeRelayDialer(ctrl.Relay()),
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = e.Close() })
		nm, err := e.Up(ctx, engine.UpRequest{ServerURL: serverURL, AuthKey: pak.Key, Hostname: name})
		if err == nil || !strings.Contains(err.Error(), "waiting for owner approval") || nm != nil || e.Status().State == "Running" {
			t.Fatalf("pre-auth key enabled the data plane or did not queue enrollment: nm=%+v err=%v", nm, err)
		}
		if stMgr.TokenForServer(serverURL) == "" {
			t.Fatal("pending registration did not save its coordination token")
		}
		return e, dev, stMgr.Get().NodeKey.Public()
	}
	a, tunA, pubA := newNode("request-a", "127.0.0.1:51920")
	b, tunB, pubB := newNode("request-b", "127.0.0.1:51921")

	pending, err := admin.OwnerJoinRequests(ctx)
	if err != nil || len(pending) != 2 || pending[0].NodeKey != pubA || pending[1].NodeKey != pubB {
		t.Fatalf("unexpected pending requests: %+v (%v)", pending, err)
	}
	if _, err := admin.SetACL(ctx, types.ACLPolicy{}); err == nil {
		t.Fatal("center admin token could change ACL without owner signature")
	}
	if _, err := admin.PublishOwnerAuthorization(ctx, types.OwnerAuthorization{}); err == nil {
		t.Fatal("center accepted an unsigned publication")
	}

	ipA, ipB := netip.MustParseAddr("100.64.0.31"), netip.MustParseAddr("100.64.0.32")
	snapshot := owner.Snapshot{
		Version: 1, ExpiresAt: time.Now().Add(time.Hour),
		Members: []owner.Member{
			{ID: 101, Name: "signed-a", NodeKey: pubA, IPv4: ipA},
			{ID: 102, Name: "signed-b", NodeKey: pubB, IPv4: ipB},
		},
		PacketFilter: []types.FilterRule{{
			Action: types.FilterAccept, IPProto: pktutil.ProtoUDP,
			SrcPrefixes: []netip.Prefix{netip.PrefixFrom(ipA, 32)}, DstPrefixes: []netip.Prefix{netip.PrefixFrom(ipB, 32)},
			DstPortStart: 8080, DstPortEnd: 8080,
		}},
		DNS: types.DNSConfig{EnableMagicDNS: true, MagicDNSSuffix: "ack.internal"},
	}
	approve := func(s owner.Snapshot) types.OwnerAuthorization {
		t.Helper()
		env, err := owner.Sign(s, key, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if v, err := admin.PublishOwnerAuthorization(ctx, env); err != nil || v != s.Version {
			t.Fatalf("publish v%d: got v%d, err %v", s.Version, v, err)
		}
		return env
	}
	first := approve(snapshot)
	for i, e := range []*engine.Engine{a, b} {
		nm, err := e.Up(ctx, engine.UpRequest{}) // No fresh pre-auth key; reuse the saved token.
		want := snapshot.Members[i]
		if err != nil || nm.Self.Name != want.Name || nm.Self.ID != want.ID || nm.Self.IPv4 != want.IPv4 {
			t.Fatalf("approved node did not get its signed identity: nm=%+v err=%v", nm, err)
		}
	}
	pkt := pktutil.BuildUDPPacket(ipA, ipB, 50001, 8080, []byte("authorized packet"))
	if err := tunA.InjectOutbound(pkt); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-tunB.ReceiveInbound():
		if !bytes.Equal(got, pkt) {
			t.Fatal("unexpected packet in owner network")
		}
	case <-ctx.Done():
		t.Fatal("authorized packet did not arrive")
	}

	snapshot.Version++
	snapshot.Members = snapshot.Members[:1]
	snapshot.PacketFilter = []types.FilterRule{owner.DenyAll()}
	approve(snapshot)
	tick := time.NewTicker(15 * time.Millisecond)
	defer tick.Stop()
	for b.Status().State != "WaitingForControl" || len(a.Status().Peers) != 0 {
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal("signed revocation did not clear old member on both nodes")
		}
	}
	if _, err := admin.PublishOwnerAuthorization(ctx, first); err == nil {
		t.Fatal("server allowed publication rollback")
	}
	reopened, err := state.LoadOrCreate(filepath.Join(temp, "request-b.json"))
	if err != nil {
		t.Fatal(err)
	}
	saved, err := reopened.ConfigureOwner("")
	if err != nil || saved == nil || *saved != trust {
		t.Fatalf("node did not retain owner pin: %v (%v)", saved, err)
	}
	v, err := owner.Verify(trust, first)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.RecordOwnerAuthorization(v.Checkpoint); !errors.Is(err, owner.ErrRollback) {
		t.Fatalf("persisted node accepted old authorization after restart: %v", err)
	}
}

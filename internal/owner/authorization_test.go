package owner

import (
	"crypto/ed25519"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ackwrap/acktier/pkg/types"
)

func TestOwnerProjectionOnlyUsesSignedPermissions(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	trust := NewTrust(pub, 1)
	self, peer, unknown := types.PublicKey{1}, types.PublicKey{2}, types.PublicKey{3}
	now := time.Now()
	snapshot := Snapshot{
		Version: 1, ExpiresAt: now.Add(time.Hour),
		Members: []Member{
			{ID: 1, NodeKey: self, Name: "workstation", IPv4: netip.MustParseAddr("100.64.0.10")},
			{ID: 2, NodeKey: peer, Name: "nas", IPv4: netip.MustParseAddr("100.64.0.20")},
		},
		PacketFilter: []types.FilterRule{DenyAll()},
		DNS:          types.DNSConfig{EnableMagicDNS: true, MagicDNSSuffix: "ack.internal"},
	}
	env, err := Sign(snapshot, key, now)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Verify(trust, env)
	if err != nil {
		t.Fatal(err)
	}
	hints := types.NetMap{
		Self: types.PeerNode{NodeKey: self, Name: "unsigned-self", ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}},
		Peers: []types.PeerNode{
			{NodeKey: unknown, ID: 2, Name: "nas", IPv4: snapshot.Members[1].IPv4},
			{NodeKey: peer, ID: 7, Name: "renamed", IPv4: netip.MustParseAddr("100.64.0.30"),
				ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
				Endpoints:      []types.Endpoint{{Proto: types.ProtoUDP, Addr: "192.0.2.1:51820"}}},
		},
		DNS:    types.DNSConfig{MagicDNSSuffix: "other.test"},
		Relays: []types.RelayNode{{RelayAddr: "other.test:443"}},
	}
	nm := v.Project(hints, self, types.RelayNode{RelayAddr: "control.test:443"})
	if nm.Self.Name != "workstation" || len(nm.Self.ApprovedRoutes) != 0 ||
		len(nm.Peers) != 1 || nm.Peers[0].NodeKey != peer || nm.Peers[0].Name != "nas" ||
		nm.Peers[0].IPv4 != snapshot.Members[1].IPv4 || len(nm.Peers[0].ApprovedRoutes) != 0 {
		t.Fatalf("unsigned fields changed identity or routes: %+v", nm)
	}
	if len(nm.PacketFilter) != 1 || nm.PacketFilter[0].Action != types.FilterDrop ||
		nm.DNS.MagicDNSSuffix != "ack.internal" || nm.Relays[0].RelayAddr != "control.test:443" ||
		len(nm.Peers[0].Endpoints) != 1 {
		t.Fatalf("projection did not preserve the authority/hint boundary: %+v", nm)
	}

	env.Payload[0] ^= 1
	if _, err := Verify(trust, env); err == nil {
		t.Fatal("modified payload passed verification")
	}
}

func TestOwnerVersionAndDefaultDeny(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s := Snapshot{Version: 2, ExpiresAt: now.Add(time.Hour)}
	if _, err := Sign(s, key, now); err == nil {
		t.Fatal("an empty filter would enable the legacy allow-all")
	}
	s.PacketFilter = []types.FilterRule{DenyAll()}
	signed := func(s Snapshot) *Verified {
		t.Helper()
		env, err := Sign(s, key, now)
		if err != nil {
			t.Fatal(err)
		}
		v, err := Verify(NewTrust(pub, 1), env)
		if err != nil {
			t.Fatal(err)
		}
		other, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(NewTrust(other, 1), env); err == nil {
			t.Fatal("authorization passed under an unrelated root")
		}
		return v
	}
	current := signed(s).Checkpoint
	if err := current.Check(current, 2); err != nil {
		t.Fatal(err)
	}
	s.ExpiresAt = s.ExpiresAt.Add(time.Hour)
	if err := current.Check(signed(s).Checkpoint, 1); !errors.Is(err, ErrRollback) {
		t.Fatalf("accepted different payload with reused version: %v", err)
	}
	s.Version = 1
	if err := current.Check(signed(s).Checkpoint, 1); !errors.Is(err, ErrRollback) {
		t.Fatalf("accepted old authorization: %v", err)
	}
	if err := (Checkpoint{}).Check(current, 3); !errors.Is(err, ErrRollback) {
		t.Fatalf("accepted an authorization below the provisioning floor: %v", err)
	}
}

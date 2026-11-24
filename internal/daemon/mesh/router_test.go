package mesh_test

import (
	"testing"

	"github.com/acktier/acktier/internal/daemon/mesh"
	"github.com/acktier/acktier/pkg/types"
)

func TestDijkstraMultiHopAndCanRelayEnforcement(t *testing.T) {
	kSelf := types.PublicKey{1}
	kR1 := types.PublicKey{2}   // CanRelay = true
	kR2 := types.PublicKey{3}   // CanRelay = true
	kNoRelay := types.PublicKey{4} // CanRelay = false!
	kTarget := types.PublicKey{5}

	r := mesh.NewRouter(kSelf)

	// Self has direct links to R1 (8ms) and NoRelay (2ms).
	// NoRelay has a fast 2ms link to Target, BUT CanRelay=false so it MUST NOT transit!
	// R1 -> R2 (6ms), R2 -> Target (7ms) => 3-hop path Self -> R1 -> R2 -> Target!
	selfLinks := []types.PeerLink{
		{Target: kR1, RTTMillis: 8.0},
		{Target: kNoRelay, RTTMillis: 2.0},
	}
	peers := []types.PeerNode{
		{
			NodeKey:  kR1,
			Name:     "relay-hop-1",
			Online:   true,
			CanRelay: true,
			Links:    []types.PeerLink{{Target: kR2, RTTMillis: 6.0}},
		},
		{
			NodeKey:  kR2,
			Name:     "relay-hop-2",
			Online:   true,
			CanRelay: true,
			Links:    []types.PeerLink{{Target: kTarget, RTTMillis: 7.0}},
		},
		{
			NodeKey:  kNoRelay,
			Name:     "leaf-no-relay",
			Online:   true,
			CanRelay: false, // Must not forward traffic!
			Links:    []types.PeerLink{{Target: kTarget, RTTMillis: 2.0}},
		},
		{
			NodeKey: kTarget,
			Name:    "dst-target",
			Online:  true,
		},
	}

	r.Recompute(selfLinks, peers)

	rt, ok := r.Lookup(kTarget)
	if !ok {
		t.Fatalf("expected multi-hop route to kTarget")
	}
	if !rt.IsPeerRelayed || len(rt.Hops) != 3 {
		t.Fatalf("expected 3-hop route [R1, R2, Target], got %+v", rt)
	}
	if rt.NextHop != kR1 || rt.Hops[1] != kR2 || rt.Hops[2] != kTarget {
		t.Fatalf("unexpected hop sequence: %+v", rt.Hops)
	}

	// Now suppose a degraded 180ms direct link exists to Target:
	// 3-hop mesh cost is 8 + (6+1.5) + (7+1.5) = 24.0ms << 180ms, so Smart Mesh MUST prefer R1->R2->Target!
	selfLinksWithSlowDirect := append(selfLinks, types.PeerLink{Target: kTarget, RTTMillis: 180.0})
	r.Recompute(selfLinksWithSlowDirect, peers)
	rt2, ok := r.Lookup(kTarget)
	if !ok || !rt2.IsPeerRelayed || rt2.NextHop != kR1 {
		t.Fatalf("expected Smart Mesh to prefer 24ms multi-hop over 180ms degraded direct link, got %+v", rt2)
	}
}

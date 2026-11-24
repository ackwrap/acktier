package nat_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/acktier/acktier/internal/daemon/nat"
	"github.com/acktier/acktier/pkg/types"
)

func TestNATDetectorClassificationAndPortPrediction(t *testing.T) {
	localIPs := []netip.Addr{netip.MustParseAddr("192.168.1.50")}

	// 1. Cone NAT: same external port across primary and alt STUN servers
	dCone := nat.NewDetector()
	dCone.SetSTUNServers("203.0.113.1:3478", "203.0.113.1:3479")
	dCone.RecordObservation("203.0.113.1:3478", "198.51.100.77:54321", 12*time.Millisecond, localIPs)
	dCone.RecordObservation("203.0.113.1:3479", "198.51.100.77:54321", 11*time.Millisecond, localIPs)
	kind, step, pub, _ := dCone.Snapshot()
	if kind != nat.KindCone || step != 0 || pub != "198.51.100.77:54321" {
		t.Fatalf("expected Cone NAT, got kind=%s step=%d pub=%s", kind, step, pub)
	}

	// 2. Symmetric NAT: port increments by +2 on alt STUN server
	dSym := nat.NewDetector()
	dSym.SetSTUNServers("203.0.113.1:3478", "203.0.113.1:3479")
	dSym.RecordObservation("203.0.113.1:3478", "198.51.100.88:41000", 15*time.Millisecond, localIPs)
	dSym.RecordObservation("203.0.113.1:3479", "198.51.100.88:41002", 15*time.Millisecond, localIPs)
	kindSym, stepSym, _, _ := dSym.Snapshot()
	if kindSym != nat.KindSymmetric || stepSym != 2 {
		t.Fatalf("expected Symmetric NAT with step=+2, got kind=%s step=%d", kindSym, stepSym)
	}

	// Verify adjacent port prediction includes 41002, 41004, 41006...
	targets := nat.BuildUDPPunchTargets([]types.Endpoint{
		{Proto: types.ProtoUDP, Addr: "198.51.100.88:41000"},
	}, kindSym, stepSym)
	if len(targets) < 5 {
		t.Fatalf("expected predicted ports for Symmetric NAT, got %v", targets)
	}
	found41004 := false
	for _, addr := range targets {
		if addr == "198.51.100.88:41004" {
			found41004 = true
		}
	}
	if !found41004 {
		t.Fatalf("expected predicted port 198.51.100.88:41004 in %v", targets)
	}

	// 3. Open Public IP: observed STUN IP matches local interface IP
	dPub := nat.NewDetector()
	dPub.SetSTUNServers("203.0.113.1:3478", "203.0.113.1:3479")
	dPub.RecordObservation("203.0.113.1:3478", "192.168.1.50:51820", 2*time.Millisecond, localIPs)
	kindPub, _, _, _ := dPub.Snapshot()
	if kindPub != nat.KindPublic {
		t.Fatalf("expected open-public, got %s", kindPub)
	}
}

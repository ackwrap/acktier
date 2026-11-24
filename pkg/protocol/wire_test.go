package protocol_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/acktier/acktier/pkg/protocol"
	"github.com/acktier/acktier/pkg/types"
)

func TestWireRoundTrip(t *testing.T) {
	privA, err := types.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("gen key A: %v", err)
	}
	privB, err := types.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("gen key B: %v", err)
	}
	pubA := privA.Public()
	pubB := privB.Public()

	// Verify ECDH symmetry
	secA, err := privA.SharedSecret(pubB)
	if err != nil {
		t.Fatalf("ecdh A: %v", err)
	}
	secB, err := privB.SharedSecret(pubA)
	if err != nil {
		t.Fatalf("ecdh B: %v", err)
	}
	if secA != secB {
		t.Fatalf("shared secrets mismatch")
	}

	// Test DataPacket + RelayForward + Stream Frame
	inner := protocol.EncodeDataPacket(pubA, 42, []byte("ciphertext-payload"))
	relayed := protocol.EncodeRelayForward(protocol.DefaultHopTTL, pubA, pubB, inner)

	var stream bytes.Buffer
	if err := protocol.WriteFrame(&stream, relayed); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	gotFrame, err := protocol.ReadFrame(&stream)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}

	ttl, src, dst, gotInner, err := protocol.DecodeRelayForward(gotFrame)
	if err != nil {
		t.Fatalf("decode relay forward: %v", err)
	}
	if ttl != protocol.DefaultHopTTL || src != pubA || dst != pubB {
		t.Fatalf("unexpected relay metadata: ttl=%d src=%s dst=%s", ttl, src, dst)
	}

	prefix, counter, ct, err := protocol.DecodeDataPacket(gotInner)
	if err != nil {
		t.Fatalf("decode data packet: %v", err)
	}
	if counter != 42 || string(ct) != "ciphertext-payload" {
		t.Fatalf("unexpected data payload: counter=%d ct=%q", counter, ct)
	}
	var wantPrefix [8]byte
	copy(wantPrefix[:], pubA[:8])
	if prefix != wantPrefix {
		t.Fatalf("prefix mismatch")
	}

	// Test ProbePacket
	now := time.Now().UnixNano()
	probe := protocol.EncodeProbePacket(protocol.PacketPong, pubB, 99, now, "203.0.113.10:51820")
	pType, sender, probeID, txNano, obs, err := protocol.DecodeProbePacket(probe)
	if err != nil {
		t.Fatalf("decode probe: %v", err)
	}
	if pType != protocol.PacketPong || sender != pubB || probeID != 99 || txNano != now || obs != "203.0.113.10:51820" {
		t.Fatalf("unexpected probe decoded values")
	}
}

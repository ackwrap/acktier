package protocol_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/ackwrap/acktier/pkg/protocol"
	"github.com/ackwrap/acktier/pkg/types"
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

func TestMeshFrameAuthenticatesThePreviousHopAndRecipient(t *testing.T) {
	previous := types.PublicKey{1}
	recipient := types.PublicKey{2}
	target := types.PublicKey{3}
	sign := func(data []byte) ([protocol.ControlAuthTagSize]byte, error) {
		mac := hmac.New(sha256.New, []byte("test only"))
		_, _ = mac.Write(data)
		return [protocol.ControlAuthTagSize]byte(mac.Sum(nil)), nil
	}
	verify := func(hop types.PublicKey, frame []byte, tag [protocol.ControlAuthTagSize]byte) bool {
		expected, _ := sign(frame)
		return hop == previous && hmac.Equal(expected[:], tag[:])
	}
	want := protocol.MeshForward{
		TTL: protocol.DefaultHopTTL, Previous: previous, Source: previous, Target: target,
		SentAt: time.Now().Unix(), Sequence: 1, Inner: []byte("opaque"),
	}
	pkt, err := protocol.EncodeMeshForward(want, recipient, sign)
	if err != nil {
		t.Fatal(err)
	}
	got, err := protocol.DecodeAndVerifyMeshForward(pkt, recipient, verify)
	if err != nil || got.Previous != previous || got.Source != want.Source || got.Target != target || !bytes.Equal(got.Inner, want.Inner) {
		t.Fatalf("mesh frame did not round trip: %v", err)
	}
	if _, err := protocol.DecodeAndVerifyMeshForward(pkt, target, verify); err == nil {
		t.Fatal("frame was accepted by a different recipient")
	}
	pkt[3]--
	if _, err := protocol.DecodeAndVerifyMeshForward(pkt, recipient, verify); err == nil {
		t.Fatal("TTL modification was not detected")
	}
}

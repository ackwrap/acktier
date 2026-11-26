package crypto_test

import (
	"bytes"
	"testing"

	"github.com/ackwrap/acktier/internal/daemon/crypto"
	"github.com/ackwrap/acktier/pkg/types"
)

func TestHandshakeAndAEADSession(t *testing.T) {
	privA, _ := types.GeneratePrivateKey()
	privB, _ := types.GeneratePrivateKey()
	pubA := privA.Public()
	pubB := privB.Public()

	mgrA := crypto.NewManager(privA)
	mgrB := crypto.NewManager(privB)

	mgrA.SetAuthorizedPeers([]types.PublicKey{pubB})
	mgrB.SetAuthorizedPeers([]types.PublicKey{pubA})

	mgrA.QueuePendingPacket(pubB, []byte("queued-first-packet"))

	initPkt, err := mgrA.InitiateHandshake(pubB)
	if err != nil {
		t.Fatalf("InitiateHandshake: %v", err)
	}

	gotPeerA, ackPkt, _, err := mgrB.HandleHandshakeInit(initPkt)
	if err != nil {
		t.Fatalf("HandleHandshakeInit: %v", err)
	}
	if gotPeerA != pubA {
		t.Fatalf("expected peer A, got %s", gotPeerA)
	}

	// Replay of same HandshakeInit must be rejected
	if _, _, _, err := mgrB.HandleHandshakeInit(initPkt); err == nil {
		t.Fatalf("expected replay of HandshakeInit to fail")
	}

	gotPeerB, queued, err := mgrA.HandleHandshakeAck(ackPkt)
	if err != nil {
		t.Fatalf("HandleHandshakeAck: %v", err)
	}
	if gotPeerB != pubB || len(queued) != 1 || string(queued[0]) != "queued-first-packet" {
		t.Fatalf("unexpected ack result: peer=%s queued=%d", gotPeerB, len(queued))
	}

	// Bidirectional encrypted traffic + anti-replay check
	wire1, err := mgrA.SealPacket(pubB, []byte("hello-from-A"))
	if err != nil {
		t.Fatalf("SealPacket A->B: %v", err)
	}
	sender, plain, err := mgrB.OpenPacket(wire1)
	if err != nil {
		t.Fatalf("OpenPacket B: %v", err)
	}
	if sender != pubA || !bytes.Equal(plain, []byte("hello-from-A")) {
		t.Fatalf("unexpected decrypted payload: %q", plain)
	}

	// Replay of wire1 must fail
	if _, _, err := mgrB.OpenPacket(wire1); err == nil {
		t.Fatalf("expected packet replay to be rejected")
	}

	// B -> A
	wire2, err := mgrB.SealPacket(pubA, []byte("reply-from-B"))
	if err != nil {
		t.Fatalf("SealPacket B->A: %v", err)
	}
	senderB, plainB, err := mgrA.OpenPacket(wire2)
	if err != nil || senderB != pubB || string(plainB) != "reply-from-B" {
		t.Fatalf("OpenPacket A failed: err=%v plain=%q", err, plainB)
	}
}

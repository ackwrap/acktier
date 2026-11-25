package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/acktier/acktier/pkg/protocol"
	"github.com/acktier/acktier/pkg/types"
)

const (
	handshakeInitLabel = "ACKTIER-HS-INIT-V1"
	handshakeAckLabel  = "ACKTIER-HS-ACK-V1"
	maxClockSkew       = 5 * time.Minute
	sessionRekeyAge    = 2 * time.Hour
)

var (
	ErrUnknownPeer     = errors.New("crypto: unknown peer public key")
	ErrHandshakeReplay = errors.New("crypto: stale or replayed handshake")
	ErrNoActiveSession = errors.New("crypto: session not established yet")
	ErrReplayPacket    = errors.New("crypto: replayed or out-of-window packet")
)

type replayWindow struct {
	mu      sync.Mutex
	highest uint64
	bitmap  uint64
}

func (rw *replayWindow) checkAndAccept(counter uint64) bool {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if counter == 0 {
		return false // counter starts at 1
	}
	if counter > rw.highest {
		shift := counter - rw.highest
		if shift >= 64 {
			rw.bitmap = 1
		} else {
			rw.bitmap = (rw.bitmap << shift) | 1
		}
		rw.highest = counter
		return true
	}
	diff := rw.highest - counter
	if diff >= 64 {
		return false
	}
	mask := uint64(1) << diff
	if rw.bitmap&mask != 0 {
		return false
	}
	rw.bitmap |= mask
	return true
}

type activeCipher struct {
	txAEAD      cipher.AEAD
	rxAEAD      cipher.AEAD
	txCounter   atomic.Uint64
	replay      replayWindow
	established time.Time
}

type pendingHandshake struct {
	ephPriv   types.PrivateKey
	ephPub    types.PublicKey
	createdAt time.Time
}

type peerEntry struct {
	hsMu        sync.Mutex   // Serializes handshake init/ack state transitions to eliminate race windows
	mu          sync.RWMutex // Guards active cipher, pending handshake pointer, and queued packets
	peerPub     types.PublicKey
	ctrlKey     [32]byte
	hasCtrlKey  bool
	lastInitTs  int64
	lastCoordTs int64
	meshReplay  map[int64]*replayWindow
	pending     *pendingHandshake
	active      *activeCipher
	pendingPkts [][]byte
}

// Manager manages Noise-style X25519 + HKDF-SHA256 + AES-256-GCM E2EE sessions
// and static-key HMAC authentication for control/probe packets with all authorized peers.
type Manager struct {
	localPriv types.PrivateKey
	localPub  types.PublicKey

	mu       sync.RWMutex
	peers    map[types.PublicKey]*peerEntry
	byPrefix map[[8]byte]*peerEntry
}

func NewManager(localPriv types.PrivateKey) *Manager {
	return &Manager{
		localPriv: localPriv,
		localPub:  localPriv.Public(),
		peers:     make(map[types.PublicKey]*peerEntry),
		byPrefix:  make(map[[8]byte]*peerEntry),
	}
}

func (m *Manager) LocalPublicKey() types.PublicKey {
	return m.localPub
}

// SetAuthorizedPeers synchronizes the allowed peer public keys from the latest NetMap.
// Removed peers have their session keys and pending handshakes destroyed immediately.
func (m *Manager) SetAuthorizedPeers(peerKeys []types.PublicKey) {
	allowed := make(map[types.PublicKey]bool, len(peerKeys))
	for _, k := range peerKeys {
		if !k.IsZero() && k != m.localPub {
			allowed[k] = true
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for k, pe := range m.peers {
		if !allowed[k] {
			pe.mu.Lock()
			pe.active = nil
			pe.pending = nil
			pe.pendingPkts = nil
			pe.mu.Unlock()
			var pfx [8]byte
			copy(pfx[:], pe.peerPub[:8])
			delete(m.byPrefix, pfx)
			delete(m.peers, k)
		}
	}

	for k := range allowed {
		if _, exists := m.peers[k]; !exists {
			pe := &peerEntry{peerPub: k}
			if ck, err := derivePeerControlKey(m.localPriv, m.localPub, k); err == nil {
				pe.ctrlKey = ck
				pe.hasCtrlKey = true
			}
			m.peers[k] = pe
			var pfx [8]byte
			copy(pfx[:], k[:8])
			m.byPrefix[pfx] = pe
		}
	}
}

// ResetSessions wipes all active E2EE sessions, pending handshakes, and peer authorizations (e.g. on `acktier down`).
func (m *Manager) ResetSessions() {
	m.SetAuthorizedPeers(nil)
}

// SignControl computes a 128-bit HMAC-SHA256 tag authenticating a control/probe packet to peerPub.
func (m *Manager) SignControl(peerPub types.PublicKey, data []byte) ([protocol.ControlAuthTagSize]byte, error) {
	var tag [protocol.ControlAuthTagSize]byte
	m.mu.RLock()
	pe := m.peers[peerPub]
	m.mu.RUnlock()
	if pe == nil || !pe.hasCtrlKey {
		return tag, ErrUnknownPeer
	}
	mac := hmac.New(sha256.New, pe.ctrlKey[:])
	_, _ = mac.Write(data)
	sum := mac.Sum(nil)
	copy(tag[:], sum[:protocol.ControlAuthTagSize])
	return tag, nil
}

// VerifyControl validates a 128-bit HMAC-SHA256 tag from an authorized peer in constant time.
func (m *Manager) VerifyControl(senderPub types.PublicKey, data []byte, tag [protocol.ControlAuthTagSize]byte) bool {
	m.mu.RLock()
	pe := m.peers[senderPub]
	m.mu.RUnlock()
	if pe == nil || !pe.hasCtrlKey {
		return false
	}
	mac := hmac.New(sha256.New, pe.ctrlKey[:])
	_, _ = mac.Write(data)
	sum := mac.Sum(nil)
	return hmac.Equal(sum[:protocol.ControlAuthTagSize], tag[:])
}

// AcceptPunchCoordTimestamp enforces freshness and anti-replay monotonicity on authenticated PunchCoord messages.
func (m *Manager) AcceptPunchCoordTimestamp(senderPub types.PublicKey, txNano int64) bool {
	msgTime := time.Unix(0, txNano)
	if diff := time.Since(msgTime); diff > 30*time.Second || diff < -30*time.Second {
		return false
	}
	m.mu.RLock()
	pe := m.peers[senderPub]
	m.mu.RUnlock()
	if pe == nil {
		return false
	}
	pe.mu.Lock()
	defer pe.mu.Unlock()
	if txNano <= pe.lastCoordTs {
		return false
	}
	pe.lastCoordTs = txNano
	return true
}

// AcceptMeshHop is called only after the hop MAC has been validated. The
// window accepts reordering within a timestamp bucket without allowing an
// authenticated frame to be forwarded repeatedly.
func (m *Manager) AcceptMeshHop(sender types.PublicKey, second int64, seq uint64) bool {
	const maxSkew = 30 // seconds
	now := time.Now().Unix()
	if second < now-maxSkew || second > now+maxSkew || seq == 0 {
		return false
	}
	m.mu.RLock()
	pe := m.peers[sender]
	m.mu.RUnlock()
	if pe == nil {
		return false
	}
	pe.mu.Lock()
	defer pe.mu.Unlock()
	window := pe.meshReplay[second]
	if window == nil {
		if pe.meshReplay == nil {
			pe.meshReplay = make(map[int64]*replayWindow)
		}
		for ts := range pe.meshReplay {
			if ts < now-maxSkew || ts > now+maxSkew {
				delete(pe.meshReplay, ts)
			}
		}
		window = &replayWindow{}
		pe.meshReplay[second] = window
	}
	return window.checkAndAccept(seq)
}

// HasActiveSession reports whether an active AEAD session exists with peerPub.
func (m *Manager) HasActiveSession(peerPub types.PublicKey) bool {
	m.mu.RLock()
	pe := m.peers[peerPub]
	m.mu.RUnlock()
	if pe == nil {
		return false
	}
	pe.mu.RLock()
	ok := pe.active != nil && time.Since(pe.active.established) < sessionRekeyAge
	pe.mu.RUnlock()
	return ok
}

// QueuePendingPacket buffers an outbound plaintext IP packet while handshake completes (up to 32 packets).
func (m *Manager) QueuePendingPacket(peerPub types.PublicKey, ipPkt []byte) {
	m.mu.RLock()
	pe := m.peers[peerPub]
	m.mu.RUnlock()
	if pe == nil {
		return
	}
	pktCopy := make([]byte, len(ipPkt))
	copy(pktCopy, ipPkt)
	pe.mu.Lock()
	if len(pe.pendingPkts) >= 32 {
		pe.pendingPkts = pe.pendingPkts[1:]
	}
	pe.pendingPkts = append(pe.pendingPkts, pktCopy)
	pe.mu.Unlock()
}

// InitiateHandshake generates a forward-secret HandshakeInit packet for peerPub.
func (m *Manager) InitiateHandshake(peerPub types.PublicKey) ([]byte, error) {
	m.mu.RLock()
	pe := m.peers[peerPub]
	m.mu.RUnlock()
	if pe == nil {
		return nil, ErrUnknownPeer
	}

	pe.hsMu.Lock()
	defer pe.hsMu.Unlock()

	ephPriv, err := types.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	ephPub := ephPriv.Public()

	ssStatic, err := m.localPriv.SharedSecret(peerPub)
	if err != nil {
		return nil, err
	}
	ssInit, err := ephPriv.SharedSecret(peerPub)
	if err != nil {
		return nil, err
	}

	tsNano := time.Now().UnixNano()
	hk, err := deriveHandshakeInitKey(ssStatic, ssInit, m.localPub, peerPub, ephPub)
	if err != nil {
		return nil, err
	}
	aead, err := newAESGCM(hk)
	if err != nil {
		return nil, err
	}
	var nonce [12]byte
	aad := buildHandshakeAAD(m.localPub, ephPub, tsNano)
	sealed := aead.Seal(nil, nonce[:], []byte(handshakeInitLabel), aad)

	pe.mu.Lock()
	pe.pending = &pendingHandshake{
		ephPriv:   ephPriv,
		ephPub:    ephPub,
		createdAt: time.Now(),
	}
	pe.mu.Unlock()

	return protocol.EncodeHandshakePacket(protocol.PacketHandshakeInit, m.localPub, ephPub, tsNano, sealed), nil
}

// HandleHandshakeInit validates an incoming HandshakeInit, installs responder session keys, and returns HandshakeAck + queued packets.
func (m *Manager) HandleHandshakeInit(pkt []byte) (peerPub types.PublicKey, ackPkt []byte, queuedPlain [][]byte, err error) {
	pType, initPub, initEphPub, tsNano, sealed, err := protocol.DecodeHandshakePacket(pkt)
	if err != nil || pType != protocol.PacketHandshakeInit {
		return peerPub, nil, nil, errors.New("crypto: malformed handshake init")
	}

	m.mu.RLock()
	pe := m.peers[initPub]
	m.mu.RUnlock()
	if pe == nil {
		return peerPub, nil, nil, ErrUnknownPeer
	}

	msgTime := time.Unix(0, tsNano)
	if diff := time.Since(msgTime); diff > maxClockSkew || diff < -maxClockSkew {
		return peerPub, nil, nil, ErrHandshakeReplay
	}

	pe.hsMu.Lock()
	defer pe.hsMu.Unlock()

	pe.mu.RLock()
	staleTs := tsNano <= pe.lastInitTs
	pe.mu.RUnlock()
	if staleTs {
		return peerPub, nil, nil, ErrHandshakeReplay
	}

	ssStatic, err := m.localPriv.SharedSecret(initPub)
	if err != nil {
		return peerPub, nil, nil, err
	}
	ssInit, err := m.localPriv.SharedSecret(initEphPub)
	if err != nil {
		return peerPub, nil, nil, err
	}
	hk, err := deriveHandshakeInitKey(ssStatic, ssInit, initPub, m.localPub, initEphPub)
	if err != nil {
		return peerPub, nil, nil, err
	}
	initAEAD, err := newAESGCM(hk)
	if err != nil {
		return peerPub, nil, nil, err
	}
	var zeroNonce [12]byte
	aad := buildHandshakeAAD(initPub, initEphPub, tsNano)
	plain, err := initAEAD.Open(nil, zeroNonce[:], sealed, aad)
	if err != nil || string(plain) != handshakeInitLabel {
		return peerPub, nil, nil, errors.New("crypto: handshake init authentication failed")
	}

	// Generate Responder ephemeral keypair for Forward Secrecy
	respEphPriv, err := types.GeneratePrivateKey()
	if err != nil {
		return peerPub, nil, nil, err
	}
	respEphPub := respEphPriv.Public()

	ssEph, err := respEphPriv.SharedSecret(initEphPub)
	if err != nil {
		return peerPub, nil, nil, err
	}
	ssResp, err := respEphPriv.SharedSecret(initPub)
	if err != nil {
		return peerPub, nil, nil, err
	}

	keyInitToResp, keyRespToInit, ackKey, err := deriveSessionKeys(ssStatic, ssInit, ssEph, ssResp, initPub, m.localPub, initEphPub, respEphPub)
	if err != nil {
		return peerPub, nil, nil, err
	}

	txAEAD, err := newAESGCM(keyRespToInit)
	if err != nil {
		return peerPub, nil, nil, err
	}
	rxAEAD, err := newAESGCM(keyInitToResp)
	if err != nil {
		return peerPub, nil, nil, err
	}
	ackAEAD, err := newAESGCM(ackKey)
	if err != nil {
		return peerPub, nil, nil, err
	}

	ackTs := time.Now().UnixNano()
	ackAAD := buildHandshakeAAD(m.localPub, respEphPub, ackTs)
	ackProof := ackAEAD.Seal(nil, zeroNonce[:], []byte(handshakeAckLabel), ackAAD)
	ackPkt = protocol.EncodeHandshakePacket(protocol.PacketHandshakeAck, m.localPub, respEphPub, ackTs, ackProof)

	pe.mu.Lock()
	if tsNano <= pe.lastInitTs {
		pe.mu.Unlock()
		return peerPub, nil, nil, ErrHandshakeReplay
	}
	pe.lastInitTs = tsNano
	pe.active = &activeCipher{
		txAEAD:      txAEAD,
		rxAEAD:      rxAEAD,
		established: time.Now(),
	}
	queuedPlain = pe.pendingPkts
	pe.pendingPkts = nil
	pe.mu.Unlock()

	return initPub, ackPkt, queuedPlain, nil
}

// HandleHandshakeAck validates HandshakeAck, atomically consumes pending handshake state once,
// installs initiator session keys without ever resetting txCounter on duplicate ACKs, and drains queued packets.
func (m *Manager) HandleHandshakeAck(pkt []byte) (peerPub types.PublicKey, queuedPlain [][]byte, err error) {
	pType, respPub, respEphPub, ackTs, ackProof, err := protocol.DecodeHandshakePacket(pkt)
	if err != nil || pType != protocol.PacketHandshakeAck {
		return peerPub, nil, errors.New("crypto: malformed handshake ack")
	}

	msgTime := time.Unix(0, ackTs)
	if diff := time.Since(msgTime); diff > maxClockSkew || diff < -maxClockSkew {
		return peerPub, nil, ErrHandshakeReplay
	}

	m.mu.RLock()
	pe := m.peers[respPub]
	m.mu.RUnlock()
	if pe == nil {
		return peerPub, nil, ErrUnknownPeer
	}

	// Serialize handshake processing per peer AND verify single-consumption of `pend` inside `pe.mu.Lock()`!
	pe.hsMu.Lock()
	defer pe.hsMu.Unlock()

	pe.mu.RLock()
	pend := pe.pending
	pe.mu.RUnlock()
	if pend == nil || time.Since(pend.createdAt) > 30*time.Second {
		return peerPub, nil, ErrHandshakeReplay
	}

	ssStatic, err := m.localPriv.SharedSecret(respPub)
	if err != nil {
		return peerPub, nil, err
	}
	ssInit, err := pend.ephPriv.SharedSecret(respPub)
	if err != nil {
		return peerPub, nil, err
	}
	ssEph, err := pend.ephPriv.SharedSecret(respEphPub)
	if err != nil {
		return peerPub, nil, err
	}
	ssResp, err := m.localPriv.SharedSecret(respEphPub)
	if err != nil {
		return peerPub, nil, err
	}

	keyInitToResp, keyRespToInit, ackKey, err := deriveSessionKeys(ssStatic, ssInit, ssEph, ssResp, m.localPub, respPub, pend.ephPub, respEphPub)
	if err != nil {
		return peerPub, nil, err
	}

	ackAEAD, err := newAESGCM(ackKey)
	if err != nil {
		return peerPub, nil, err
	}
	var zeroNonce [12]byte
	ackAAD := buildHandshakeAAD(respPub, respEphPub, ackTs)
	plain, err := ackAEAD.Open(nil, zeroNonce[:], ackProof, ackAAD)
	if err != nil || string(plain) != handshakeAckLabel {
		return peerPub, nil, errors.New("crypto: handshake ack authentication failed")
	}

	txAEAD, err := newAESGCM(keyInitToResp)
	if err != nil {
		return peerPub, nil, err
	}
	rxAEAD, err := newAESGCM(keyRespToInit)
	if err != nil {
		return peerPub, nil, err
	}

	pe.mu.Lock()
	// CRITICAL NONCE-REUSE GUARD: verify `pe.pending` is still the exact unconsumed `pend` instance!
	if pe.pending != pend {
		pe.mu.Unlock()
		return peerPub, nil, ErrHandshakeReplay
	}
	pe.pending = nil
	pe.active = &activeCipher{
		txAEAD:      txAEAD,
		rxAEAD:      rxAEAD,
		established: time.Now(),
	}
	queuedPlain = pe.pendingPkts
	pe.pendingPkts = nil
	pe.mu.Unlock()

	return respPub, queuedPlain, nil
}

// SealPacket encrypts an outbound IP packet into a wire PacketData frame.
func (m *Manager) SealPacket(peerPub types.PublicKey, plainIPPkt []byte) ([]byte, error) {
	m.mu.RLock()
	pe := m.peers[peerPub]
	m.mu.RUnlock()
	if pe == nil {
		return nil, ErrUnknownPeer
	}

	pe.mu.RLock()
	ac := pe.active
	pe.mu.RUnlock()
	if ac == nil {
		return nil, ErrNoActiveSession
	}

	counter := ac.txCounter.Add(1)
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:12], counter)

	var aad [16]byte
	copy(aad[0:8], m.localPub[:8])
	binary.BigEndian.PutUint64(aad[8:16], counter)

	ct := ac.txAEAD.Seal(nil, nonce[:], plainIPPkt, aad[:])
	return protocol.EncodeDataPacket(m.localPub, counter, ct), nil
}

// OpenPacket authenticates, checks anti-replay window, and decrypts an incoming wire PacketData frame.
func (m *Manager) OpenPacket(wirePkt []byte) (senderPub types.PublicKey, plainIPPkt []byte, err error) {
	prefix, counter, ct, err := protocol.DecodeDataPacket(wirePkt)
	if err != nil {
		return senderPub, nil, err
	}

	m.mu.RLock()
	pe := m.byPrefix[prefix]
	m.mu.RUnlock()
	if pe == nil {
		return senderPub, nil, ErrUnknownPeer
	}

	pe.mu.RLock()
	ac := pe.active
	pe.mu.RUnlock()
	if ac == nil {
		return senderPub, nil, ErrNoActiveSession
	}

	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:12], counter)
	var aad [16]byte
	copy(aad[0:8], prefix[:])
	binary.BigEndian.PutUint64(aad[8:16], counter)

	plain, err := ac.rxAEAD.Open(nil, nonce[:], ct, aad[:])
	if err != nil {
		return senderPub, nil, fmt.Errorf("crypto: aead open failed: %w", err)
	}
	if !ac.replay.checkAndAccept(counter) {
		return senderPub, nil, ErrReplayPacket
	}
	return pe.peerPub, plain, nil
}

func newAESGCM(key [32]byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func buildHandshakeAAD(staticPub, ephPub types.PublicKey, tsNano int64) []byte {
	out := make([]byte, 32+32+8)
	copy(out[0:32], staticPub[:])
	copy(out[32:64], ephPub[:])
	binary.BigEndian.PutUint64(out[64:72], uint64(tsNano))
	return out
}

func derivePeerControlKey(localPriv types.PrivateKey, localPub, peerPub types.PublicKey) ([32]byte, error) {
	var out [32]byte
	ss, err := localPriv.SharedSecret(peerPub)
	if err != nil {
		return out, err
	}
	var info [64]byte
	if bytes.Compare(localPub[:], peerPub[:]) <= 0 {
		copy(info[0:32], localPub[:])
		copy(info[32:64], peerPub[:])
	} else {
		copy(info[0:32], peerPub[:])
		copy(info[32:64], localPub[:])
	}
	raw, err := hkdf.Key(sha256.New, ss[:], []byte("acktier-ctrl-mac-salt-v1"), string(info[:]), 32)
	if err != nil {
		return out, err
	}
	copy(out[:], raw)
	return out, nil
}

func deriveHandshakeInitKey(ssStatic, ssInit [32]byte, initPub, respPub, initEph types.PublicKey) ([32]byte, error) {
	var ikm [64]byte
	copy(ikm[0:32], ssStatic[:])
	copy(ikm[32:64], ssInit[:])

	var info [96]byte
	copy(info[0:32], initPub[:])
	copy(info[32:64], respPub[:])
	copy(info[64:96], initEph[:])

	raw, err := hkdf.Key(sha256.New, ikm[:], []byte("acktier-hs-init-salt-v1"), string(info[:]), 32)
	var out [32]byte
	if err != nil {
		return out, err
	}
	copy(out[:], raw)
	return out, nil
}

func deriveSessionKeys(ssStatic, ssInit, ssEph, ssResp [32]byte, initPub, respPub, initEph, respEph types.PublicKey) (initToResp, respToInit, ackKey [32]byte, err error) {
	var ikm [128]byte
	copy(ikm[0:32], ssStatic[:])
	copy(ikm[32:64], ssInit[:])
	copy(ikm[64:96], ssEph[:])
	copy(ikm[96:128], ssResp[:])

	var info [128]byte
	copy(info[0:32], initPub[:])
	copy(info[32:64], respPub[:])
	copy(info[64:96], initEph[:])
	copy(info[96:128], respEph[:])

	raw, err := hkdf.Key(sha256.New, ikm[:], []byte("acktier-session-keys-v1"), string(info[:]), 96)
	if err != nil {
		return initToResp, respToInit, ackKey, err
	}
	copy(initToResp[:], raw[0:32])
	copy(respToInit[:], raw[32:64])
	copy(ackKey[:], raw[64:96])
	return initToResp, respToInit, ackKey, nil
}

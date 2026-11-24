package types

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	KeySize = 32

	privKeyPrefix = "privkey:"
	pubKeyPrefix  = "nodekey:"
)

// PrivateKey represents an X25519 private key used as MachineKey or NodeKey.
type PrivateKey [KeySize]byte

// PublicKey represents an X25519 public key identifying a machine or node.
type PublicKey [KeySize]byte

// GeneratePrivateKey creates a new cryptographically random X25519 private key.
func GeneratePrivateKey() (PrivateKey, error) {
	curve := ecdh.X25519()
	k, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return PrivateKey{}, fmt.Errorf("generate x25519 key: %w", err)
	}
	var out PrivateKey
	copy(out[:], k.Bytes())
	return out, nil
}

// IsZero reports whether the private key is all zeroes.
func (k PrivateKey) IsZero() bool {
	return k == PrivateKey{}
}

// Public derives the corresponding X25519 public key.
func (k PrivateKey) Public() PublicKey {
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(k[:])
	if err != nil {
		return PublicKey{}
	}
	var pub PublicKey
	copy(pub[:], priv.PublicKey().Bytes())
	return pub
}

// SharedSecret computes the X25519 ECDH shared secret with peer.
func (k PrivateKey) SharedSecret(peer PublicKey) ([KeySize]byte, error) {
	var secret [KeySize]byte
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(k[:])
	if err != nil {
		return secret, fmt.Errorf("invalid private key: %w", err)
	}
	pub, err := curve.NewPublicKey(peer[:])
	if err != nil {
		return secret, fmt.Errorf("invalid peer public key: %w", err)
	}
	raw, err := priv.ECDH(pub)
	if err != nil {
		return secret, fmt.Errorf("ecdh failed: %w", err)
	}
	copy(secret[:], raw)
	return secret, nil
}

func (k PrivateKey) String() string {
	return privKeyPrefix + hex.EncodeToString(k[:])
}

func ParsePrivateKey(s string) (PrivateKey, error) {
	var k PrivateKey
	s = strings.TrimPrefix(strings.TrimSpace(s), privKeyPrefix)
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != KeySize {
		return k, errors.New("invalid private key hex")
	}
	copy(k[:], b)
	return k, nil
}

func (k PrivateKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.String())
}

func (k *PrivateKey) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		*k = PrivateKey{}
		return nil
	}
	parsed, err := ParsePrivateKey(s)
	if err != nil {
		return err
	}
	*k = parsed
	return nil
}

// IsZero reports whether the public key is all zeroes.
func (p PublicKey) IsZero() bool {
	return p == PublicKey{}
}

func (p PublicKey) String() string {
	return pubKeyPrefix + hex.EncodeToString(p[:])
}

// ShortString returns a compact human-readable identifier for logs and CLI tables.
func (p PublicKey) ShortString() string {
	if p.IsZero() {
		return "nodekey:00000000"
	}
	return pubKeyPrefix + hex.EncodeToString(p[:4])
}

func ParsePublicKey(s string) (PublicKey, error) {
	var p PublicKey
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, pubKeyPrefix)
	s = strings.TrimPrefix(s, "mkey:")
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != KeySize {
		return p, errors.New("invalid public key hex")
	}
	copy(p[:], b)
	return p, nil
}

func (p PublicKey) MarshalJSON() ([]byte, error) {
	if p.IsZero() {
		return json.Marshal("")
	}
	return json.Marshal(p.String())
}

func (p *PublicKey) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		*p = PublicKey{}
		return nil
	}
	parsed, err := ParsePublicKey(s)
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}

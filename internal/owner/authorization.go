// Package owner verifies and projects authorization issued independently of the control server.
package owner

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ackwrap/acktier/pkg/types"
)

const (
	// MaxPayload leaves room for the base64 envelope and dynamic connection hints.
	MaxPayload  = 512 * 1024
	MaxEnvelope = 1024 * 1024
	MaxTrust    = 4 * 1024
	signDomain  = "AckTier owner authorization v1\x00"
)

var ErrRollback = errors.New("owner authorization version was rolled back or reused")

// Trust is provisioned out of band. MinimumVersion also protects a new node,
// which otherwise has no locally recorded version to detect a replay.
type Trust struct {
	PublicKey      string `json:"publicKey"` // Hex-encoded Ed25519 public key, not a NodeKey.
	MinimumVersion uint64 `json:"minimumVersion"`
}

func NewTrust(key ed25519.PublicKey, minimumVersion uint64) Trust {
	return Trust{PublicKey: hex.EncodeToString(key), MinimumVersion: minimumVersion}
}

func (t Trust) key() (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(t.PublicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize || t.PublicKey != hex.EncodeToString(raw) ||
		bytes.Equal(raw, make([]byte, ed25519.PublicKeySize)) || t.MinimumVersion == 0 {
		return nil, errors.New("owner trust requires a lowercase hex Ed25519 public key and a positive minimumVersion")
	}
	return ed25519.PublicKey(raw), nil
}

func (t Trust) Validate() error {
	_, err := t.key()
	return err
}

// NetworkID identifies a network by the SHA-256 fingerprint of its owner key.
func (t Trust) NetworkID() string {
	raw, _ := hex.DecodeString(t.PublicKey)
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}

func LoadTrust(path string) (Trust, error) {
	var t Trust
	if err := ReadJSON(path, MaxTrust, &t); err != nil {
		return t, err
	}
	return t, t.Validate()
}

// Checkpoint is a locally persisted high-water mark, independent of NetMap.Revision.
type Checkpoint struct {
	Version uint64 `json:"version"`
	Digest  string `json:"digest"`
}

func (p Checkpoint) Check(next Checkpoint, floor uint64) error {
	if next.Version < floor || next.Version < p.Version || (next.Version == p.Version && next.Digest != p.Digest) {
		return ErrRollback
	}
	return nil
}

func (p Checkpoint) Validate() error {
	if p == (Checkpoint{}) {
		return nil
	}
	raw, err := hex.DecodeString(p.Digest)
	if p.Version == 0 || err != nil || len(raw) != sha256.Size || p.Digest != hex.EncodeToString(raw) {
		return errors.New("invalid owner authorization checkpoint")
	}
	return nil
}

// Sign is used by the owner's local CLI, never by the control server.
func Sign(s Snapshot, key ed25519.PrivateKey, now time.Time) (types.OwnerAuthorization, error) {
	var out types.OwnerAuthorization
	if len(key) != ed25519.PrivateKeySize {
		return out, errors.New("invalid owner signing key")
	}
	s.NetworkID = NewTrust(key.Public().(ed25519.PublicKey), 1).NetworkID()
	if err := s.validate(); err != nil {
		return out, err
	}
	if !now.Before(s.ExpiresAt) {
		return out, errors.New("owner authorization must expire in the future")
	}
	payload, err := json.Marshal(s)
	if err != nil {
		return out, err
	}
	if len(payload) > MaxPayload {
		return out, errors.New("owner authorization payload is too large")
	}
	return types.OwnerAuthorization{Payload: payload, Signature: ed25519.Sign(key, signatureInput(payload))}, nil
}

type Verified struct {
	Snapshot   Snapshot
	Checkpoint Checkpoint
	members    map[types.PublicKey]struct{}
}

func (v *Verified) Contains(key types.PublicKey) bool {
	_, ok := v.members[key]
	return ok
}

// Verify authenticates the snapshot even if it has expired. Consumers must
// enforce ExpiresAt separately: an authentic expired newer version must
// never make an older authorization eligible again.
func Verify(t Trust, env types.OwnerAuthorization) (*Verified, error) {
	key, err := t.key()
	if err != nil {
		return nil, err
	}
	if len(env.Payload) == 0 || len(env.Payload) > MaxPayload || len(env.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(key, signatureInput(env.Payload), env.Signature) {
		return nil, errors.New("invalid owner authorization signature")
	}
	var s Snapshot
	if err := DecodeJSON(bytes.NewReader(env.Payload), &s); err != nil {
		return nil, fmt.Errorf("invalid signed payload: %w", err)
	}
	if s.NetworkID != t.NetworkID() {
		return nil, errors.New("owner authorization belongs to a different network")
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(env.Payload)
	return &Verified{
		Snapshot:   s,
		Checkpoint: Checkpoint{Version: s.Version, Digest: hex.EncodeToString(digest[:])},
		members:    memberKeys(s.Members),
	}, nil
}

func signatureInput(payload []byte) []byte {
	return append([]byte(signDomain), payload...)
}

func memberKeys(members []Member) map[types.PublicKey]struct{} {
	out := make(map[types.PublicKey]struct{}, len(members))
	for _, m := range members {
		out[m.NodeKey] = struct{}{}
	}
	return out
}

func DecodeJSON(r io.Reader, dst any) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return errors.New("expected exactly one JSON value")
	}
	return nil
}

func ReadJSON(path string, limit int64, dst any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return err
	}
	if int64(len(raw)) > limit {
		return fmt.Errorf("file %s is too large", path)
	}
	if err := DecodeJSON(bytes.NewReader(raw), dst); err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	return nil
}

func isDNSName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch == '-' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9') {
				return false
			}
		}
	}
	return true
}

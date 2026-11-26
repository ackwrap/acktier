package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ackwrap/acktier/internal/owner"
)

func validCredentialHash(value string) bool {
	if len(value) != hex.EncodedLen(sha256.Size) {
		return false
	}
	raw, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(raw) == value
}

func (s *FileStore) validatePersistentState() error {
	d := &s.data
	if d.NextNodeID == 0 {
		return errors.New("missing or invalid next node ID")
	}
	for id, n := range d.Nodes {
		if id == 0 || id >= d.NextNodeID || n.Node.NodeKey.IsZero() || n.Node.MachineKey.IsZero() ||
			!validCredentialHash(n.TokenHash) {
			return errors.New("invalid stored node identity or credentials")
		}
		// A persisted node isn't online until it contacts this process.
		n.Node.Online = false
		d.Nodes[id] = n
	}
	for id, key := range d.PreAuthKeys {
		if id == "" || key.ID != id || key.Key != "" || !validCredentialHash(key.KeyHash) {
			return errors.New("invalid enrollment key record")
		}
	}
	for k, inv := range d.Inventory {
		if inv.NodeKey.IsZero() || k != inv.NodeKey.String() {
			return errors.New("invalid node inventory record")
		}
	}
	for id, draft := range d.Drafts {
		if id == "" || draft.ID != id {
			return errors.New("invalid draft record")
		}
	}
	if d.AdminPassword != nil && !d.AdminPassword.valid() {
		return errors.New("invalid administrator password record")
	}
	if d.Delegation != nil && d.Delegation.Enabled {
		key, err := hex.DecodeString(d.Delegation.PublicKey)
		if err != nil || len(key) != 32 || bytes.Equal(key, make([]byte, 32)) ||
			d.Owner == nil || d.Delegation.PublicKey == d.Owner.Trust.PublicKey {
			return errors.New("invalid controller delegation record")
		}
	}
	if err := s.restoreOwner(); err != nil {
		return fmt.Errorf("restore owner authorization: %w", err)
	}
	return s.verifyPublicationHistory()
}

func (s *FileStore) verifyPublicationHistory() error {
	var latest uint64
	for _, rec := range s.data.Publications {
		if s.data.Owner == nil || rec.Version <= latest {
			return errors.New("invalid publication history order or owner")
		}
		verified, err := owner.Verify(s.data.Owner.Trust, rec.Envelope)
		if err != nil || verified.Checkpoint.Version != rec.Version || verified.Checkpoint.Digest != rec.Digest ||
			!verified.Snapshot.ExpiresAt.Equal(rec.ExpiresAt) || len(verified.Snapshot.Members) != rec.Members ||
			len(verified.Snapshot.PacketFilter) != rec.Rules {
			return fmt.Errorf("invalid signed publication history at version %d", rec.Version)
		}
		latest = rec.Version
	}
	if v := s.owner.verified; v != nil {
		if latest != v.Checkpoint.Version || s.data.Publications[len(s.data.Publications)-1].Digest != v.Checkpoint.Digest {
			return errors.New("active publication does not match the signed history high water mark")
		}
	} else if latest != 0 && s.data.Owner.Trust.MinimumVersion <= latest {
		return errors.New("active publication or version high water mark has been lost")
	}
	return nil
}

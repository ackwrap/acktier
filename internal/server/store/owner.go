package store

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/acktier/acktier/internal/owner"
	"github.com/acktier/acktier/pkg/types"
)

var (
	ErrOwnerNotConfigured = errors.New("owner trust is not configured")
	ErrOwnerAlreadySet    = errors.New("owner trust has already been configured")
	ErrOwnerInvalid       = errors.New("invalid owner authorization")
)

type storedOwner struct {
	Trust         owner.Trust               `json:"trust"`
	Authorization *types.OwnerAuthorization `json:"authorization,omitempty"`
}

// Stored and verified publications are immutable once installed.
type ownerPublication struct {
	envelope *types.OwnerAuthorization
	verified *owner.Verified
}

func (s *FileStore) restoreOwner() error {
	pinned := s.data.Owner
	if pinned == nil {
		return nil
	}
	if err := pinned.Trust.Validate(); err != nil {
		return err
	}
	if pinned.Authorization == nil {
		return nil
	}
	verified, err := owner.Verify(pinned.Trust, *pinned.Authorization)
	if err != nil {
		return err
	}
	if err := (owner.Checkpoint{}).Check(verified.Checkpoint, pinned.Trust.MinimumVersion); err != nil {
		return err
	}
	s.owner = ownerPublication{envelope: pinned.Authorization, verified: verified}
	return nil
}

// ConfigureOwner pins a public key supplied by the local operator, or raises
// the minimum version for an existing pin. It does not replace the key.
func (s *FileStore) ConfigureOwner(trust owner.Trust) error {
	return s.configureOwner(trust, false)
}

// InitializeOwner pins a public key exactly once. The Web installer cannot
// replace a root or change its minimum version after installation.
func (s *FileStore) InitializeOwner(trust owner.Trust, audit ...AuditEntry) error {
	return s.configureOwner(trust, true, audit...)
}

func (s *FileStore) configureOwner(trust owner.Trust, firstOnly bool, audit ...AuditEntry) error {
	if err := trust.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, publication := s.data.Owner, s.owner
	next := &storedOwner{Trust: trust}
	if prev != nil {
		if firstOnly {
			return ErrOwnerAlreadySet
		}
		if prev.Trust.PublicKey != trust.PublicKey {
			return errors.New("configured owner key does not match the pinned server state")
		}
		if trust.MinimumVersion <= prev.Trust.MinimumVersion {
			return nil
		}
		if publication.verified != nil && publication.verified.Checkpoint.Version >= trust.MinimumVersion {
			next.Authorization = prev.Authorization
		}
	}
	s.data.Owner = next
	if err := s.commitLocked(stateChange{owner: true}, audit...); err != nil {
		s.data.Owner = prev
		return err
	}
	if next.Authorization == nil {
		s.owner = ownerPublication{}
	}
	return nil
}

func (s *FileStore) OwnerTrust() (owner.Trust, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.data.Owner == nil {
		return owner.Trust{}, false
	}
	return s.data.Owner.Trust, true
}

// OwnerTopology returns a consistent publication and its coordination records.
// Callers must treat returned snapshots as read-only.
func (s *FileStore) OwnerTopology() (*types.OwnerAuthorization, *owner.Verified, []StoredNode) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.owner.envelope, s.owner.verified, s.listNodesLocked()
}

func (s *FileStore) OwnerAllowsRelay(key types.PublicKey, now time.Time) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := s.owner.verified
	return s.data.Owner == nil || (v != nil && now.Before(v.Snapshot.ExpiresAt) && v.Contains(key))
}

// PublishOwner validates and persists before the control server may distribute
// a new snapshot. Returns keys that should be disconnected from center relay.
func (s *FileStore) PublishOwner(env types.OwnerAuthorization, now time.Time, audit ...AuditEntry) (uint64, []types.PublicKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pinned := s.data.Owner
	if pinned == nil {
		return 0, nil, ErrOwnerNotConfigured
	}
	next, err := owner.Verify(pinned.Trust, env)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %v", ErrOwnerInvalid, err)
	}
	var mark owner.Checkpoint
	prev := s.owner
	if prev.verified != nil {
		mark = prev.verified.Checkpoint
	}
	if err := mark.Check(next.Checkpoint, pinned.Trust.MinimumVersion); err != nil {
		return 0, nil, err
	}
	if !now.Before(next.Snapshot.ExpiresAt) {
		return 0, nil, fmt.Errorf("%w: snapshot has expired", ErrOwnerInvalid)
	}
	idempotent := mark == next.Checkpoint
	audit = slices.Clone(audit)
	for i := range audit {
		audit[i].Target = fmt.Sprintf("v%d", next.Checkpoint.Version)
		audit[i].Detail = next.Checkpoint.Digest[:16]
		if idempotent {
			audit[i].Detail += " (幂等重传)"
		}
	}
	if idempotent {
		if len(audit) != 0 {
			if err := s.commitLocked(stateChange{}, audit...); err != nil {
				return 0, nil, err
			}
		}
		return mark.Version, nil, nil
	}
	copyEnv := &types.OwnerAuthorization{Payload: slices.Clone(env.Payload), Signature: slices.Clone(env.Signature)}
	pinned.Authorization = copyEnv
	prevHistory := s.data.Publications
	record := publicationRecord(copyEnv, next, now)
	change := stateChange{owner: true, publication: &record}
	s.data.Publications = append(slices.Clone(prevHistory), record)
	if over := len(s.data.Publications) - maxPublications; over > 0 {
		change.prunedVersion = s.data.Publications[over-1].Version
		s.data.Publications = slices.Delete(s.data.Publications, 0, over)
	}
	if err := s.commitLocked(change, audit...); err != nil {
		pinned.Authorization = prev.envelope
		s.data.Publications = prevHistory
		return 0, nil, err
	}
	s.owner = ownerPublication{envelope: copyEnv, verified: next}
	var removed []types.PublicKey
	if prev.verified != nil {
		for _, member := range prev.verified.Snapshot.Members {
			if !next.Contains(member.NodeKey) {
				removed = append(removed, member.NodeKey)
			}
		}
	}
	return next.Checkpoint.Version, removed, nil
}

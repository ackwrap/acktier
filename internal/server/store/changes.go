package store

import (
	"slices"
	"time"

	"github.com/acktier/acktier/pkg/types"
)

// stateChange names the rows changed by a store mutation. Keep registration's
// node, enrollment code, ID allocation, and audit record in the same commit.
type stateChange struct {
	node                                                types.NodeID
	key, retiredKey, draft, inventory                   string
	nextID, unsignedPolicy, owner, password, delegation bool
	publication                                         *PublicationRecord
	prunedVersion                                       uint64
	audit                                               []AuditEntry
}

func (s *FileStore) commitLocked(change stateChange, audit ...AuditEntry) error {
	prev := s.data.Audit
	if len(audit) != 0 {
		change.audit = slices.Clone(audit)
		for i := range change.audit {
			if change.audit[i].At.IsZero() {
				change.audit[i].At = time.Now().UTC()
			}
		}
		s.data.Audit = append(slices.Clone(prev), change.audit...)
		if over := len(s.data.Audit) - maxAuditEntries; over > 0 {
			s.data.Audit = slices.Delete(s.data.Audit, 0, over)
		}
	}
	if err := s.saveLocked(change); err != nil {
		s.data.Audit = prev
		return err
	}
	return nil
}

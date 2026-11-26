package store

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"time"

	"github.com/ackwrap/acktier/internal/owner"
	"github.com/ackwrap/acktier/pkg/types"
)

const (
	MaxDrafts       = 32
	maxPublications = 20
	maxAuditEntries = 500
)

var ErrTooManyDrafts = errors.New("store: too many drafts; delete unused drafts first")

// Draft is an unsigned policy source kept by the center for review and export.
// Drafts never affect traffic; only a signed publication does.
type Draft struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Note        string       `json:"note,omitempty"`
	BaseVersion uint64       `json:"baseVersion"`
	Policy      owner.Policy `json:"policy"`
	CreatedAt   time.Time    `json:"createdAt"`
	UpdatedAt   time.Time    `json:"updatedAt"`
}

// PublicationRecord keeps the exact signed bytes of a published version.
type PublicationRecord struct {
	Version     uint64                   `json:"version"`
	Digest      string                   `json:"digest"`
	ExpiresAt   time.Time                `json:"expiresAt"`
	PublishedAt time.Time                `json:"publishedAt"`
	Members     int                      `json:"members"`
	Rules       int                      `json:"rules"`
	Envelope    types.OwnerAuthorization `json:"envelope"`
}

// AuditEntry never contains passwords, cookies, private keys or key plaintext.
type AuditEntry struct {
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target,omitempty"`
	Result string    `json:"result"`
	Detail string    `json:"detail,omitempty"`
}

// InventoryTransport is a manually imported listening transport.
type InventoryTransport struct {
	Proto types.TransportProto `json:"proto"`
	Port  uint16               `json:"port"`
}

// Inventory is operator-imported capability data used only for review. It is
// never distributed in NetMaps and never changes ACLs or routes.
type Inventory struct {
	NodeKey    types.PublicKey      `json:"nodeKey"`
	Transports []InventoryTransport `json:"transports,omitempty"`
	Endpoints  []types.Endpoint     `json:"endpoints,omitempty"`
	Routes     []netip.Prefix       `json:"routes,omitempty"`
	Note       string               `json:"note,omitempty"`
	ImportedAt time.Time            `json:"importedAt"`
}

// ControllerDelegation configures optional delegated access to /api/v1/admin/*
// on the management listener for a specific Ed25519 controller public key.
type ControllerDelegation struct {
	Enabled   bool      `json:"enabled"`
	PublicKey string    `json:"publicKey,omitempty"`
	Label     string    `json:"label,omitempty"`
	UpdatedAt time.Time `json:"updatedAt,omitzero"`
}

func (s *FileStore) ControllerDelegation() ControllerDelegation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.data.Delegation == nil {
		return ControllerDelegation{}
	}
	return *s.data.Delegation
}

func (s *FileStore) EnableControllerDelegation(ct owner.ControllerTrust) (ControllerDelegation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Owner == nil {
		return ControllerDelegation{}, ErrOwnerNotConfigured
	}
	if _, err := ct.Verify(s.data.Owner.Trust); err != nil {
		return ControllerDelegation{}, err
	}
	next := &ControllerDelegation{
		Enabled:   true,
		PublicKey: ct.PublicKey,
		Label:     ct.Label,
		UpdatedAt: time.Now().UTC(),
	}
	prev := s.data.Delegation
	s.data.Delegation = next
	if err := s.saveLocked(stateChange{delegation: true}); err != nil {
		s.data.Delegation = prev
		return ControllerDelegation{}, err
	}
	return *next, nil
}

func (s *FileStore) DisableControllerDelegation() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.data.Delegation
	s.data.Delegation = &ControllerDelegation{Enabled: false, UpdatedAt: time.Now().UTC()}
	if err := s.saveLocked(stateChange{delegation: true}); err != nil {
		s.data.Delegation = prev
		return err
	}
	return nil
}

func cloneDraft(d Draft) Draft {
	d.Policy.Members = slices.Clone(d.Policy.Members)
	d.Policy.ACL.ACLs = slices.Clone(d.Policy.ACL.ACLs)
	return d
}

// ListDrafts returns drafts, most recently updated first.
func (s *FileStore) ListDrafts() []Draft {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Draft, 0, len(s.data.Drafts))
	for _, d := range s.data.Drafts {
		out = append(out, cloneDraft(d))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out
}

func (s *FileStore) GetDraft(id string) (Draft, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.data.Drafts[id]
	if !ok {
		return Draft{}, ErrNotFound
	}
	return cloneDraft(d), nil
}

// SaveDraft creates a draft when d.ID is empty, otherwise replaces an existing one.
func (s *FileStore) SaveDraft(d Draft) (Draft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Drafts == nil {
		s.data.Drafts = make(map[string]Draft)
	}
	now := time.Now().UTC()
	prev, existed := s.data.Drafts[d.ID]
	if d.ID == "" {
		if len(s.data.Drafts) >= MaxDrafts {
			return Draft{}, ErrTooManyDrafts
		}
		for d.ID == "" || s.data.Drafts[d.ID].ID != "" {
			d.ID = "draft_" + randomHex(6)
		}
		d.CreatedAt = now
	} else if !existed {
		return Draft{}, ErrNotFound
	} else {
		d.CreatedAt = prev.CreatedAt
	}
	d.UpdatedAt = now
	d = cloneDraft(d)
	s.data.Drafts[d.ID] = d
	if err := s.saveLocked(stateChange{draft: d.ID}); err != nil {
		if existed {
			s.data.Drafts[d.ID] = prev
		} else {
			delete(s.data.Drafts, d.ID)
		}
		return Draft{}, err
	}
	return cloneDraft(d), nil
}

func (s *FileStore) DeleteDraft(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.data.Drafts[id]
	if !ok {
		return ErrNotFound
	}
	delete(s.data.Drafts, id)
	if err := s.saveLocked(stateChange{draft: id}); err != nil {
		s.data.Drafts[id] = prev
		return err
	}
	return nil
}

// Publications returns the signed history, newest first.
func (s *FileStore) Publications() []PublicationRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := slices.Clone(s.data.Publications)
	slices.Reverse(out)
	return out
}

func publicationRecord(env *types.OwnerAuthorization, v *owner.Verified, at time.Time) PublicationRecord {
	return PublicationRecord{
		Version: v.Checkpoint.Version, Digest: v.Checkpoint.Digest,
		ExpiresAt: v.Snapshot.ExpiresAt, PublishedAt: at.UTC(),
		Members: len(v.Snapshot.Members), Rules: len(v.Snapshot.PacketFilter),
		Envelope: types.OwnerAuthorization{Payload: slices.Clone(env.Payload), Signature: slices.Clone(env.Signature)},
	}
}

// PreviewOwner performs every publication check without persisting anything.
// It reports whether the envelope is identical to the current publication.
func (s *FileStore) PreviewOwner(env types.OwnerAuthorization, now time.Time) (*owner.Verified, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pinned := s.data.Owner
	if pinned == nil {
		return nil, false, ErrOwnerNotConfigured
	}
	next, err := owner.Verify(pinned.Trust, env)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %v", ErrOwnerInvalid, err)
	}
	var mark owner.Checkpoint
	if s.owner.verified != nil {
		mark = s.owner.verified.Checkpoint
	}
	if err := mark.Check(next.Checkpoint, pinned.Trust.MinimumVersion); err != nil {
		return next, false, err
	}
	if !now.Before(next.Snapshot.ExpiresAt) {
		return next, false, fmt.Errorf("%w: snapshot has expired", ErrOwnerInvalid)
	}
	return next, mark == next.Checkpoint, nil
}

// AppendAudit records an outcome not already covered by a state transaction.
func (s *FileStore) AppendAudit(e AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commitLocked(stateChange{}, e)
}

// Audit returns audit entries, newest first.
func (s *FileStore) Audit() []AuditEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := slices.Clone(s.data.Audit)
	slices.Reverse(out)
	return out
}

func (s *FileStore) Inventory(key types.PublicKey) (Inventory, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	inv, ok := s.data.Inventory[key.String()]
	return inv, ok
}

func (s *FileStore) ListInventory() map[types.PublicKey]Inventory {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[types.PublicKey]Inventory, len(s.data.Inventory))
	for _, inv := range s.data.Inventory {
		out[inv.NodeKey] = inv
	}
	return out
}

func (s *FileStore) SetInventory(inv Inventory) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Inventory == nil {
		s.data.Inventory = make(map[string]Inventory)
	}
	k := inv.NodeKey.String()
	prev, existed := s.data.Inventory[k]
	inv.ImportedAt = time.Now().UTC()
	s.data.Inventory[k] = inv
	if err := s.saveLocked(stateChange{inventory: k}); err != nil {
		if existed {
			s.data.Inventory[k] = prev
		} else {
			delete(s.data.Inventory, k)
		}
		return err
	}
	return nil
}

func (s *FileStore) DeleteInventory(key types.PublicKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key.String()
	prev, ok := s.data.Inventory[k]
	if !ok {
		return ErrNotFound
	}
	delete(s.data.Inventory, k)
	if err := s.saveLocked(stateChange{inventory: k}); err != nil {
		s.data.Inventory[k] = prev
		return err
	}
	return nil
}

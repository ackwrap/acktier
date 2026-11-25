package state

import (
	"errors"
	"fmt"

	"github.com/acktier/acktier/internal/owner"
)

// OwnerState persists the pin and monotonic authorization watermark together.
type OwnerState struct {
	Trust      owner.Trust      `json:"trust"`
	Checkpoint owner.Checkpoint `json:"checkpoint"`
}

// ConfigureOwner uses the saved pin when the flag is omitted. Replacing it
// requires explicitly provisioning a new state, never a control response.
func (m *Manager) ConfigureOwner(trustFile string) (*owner.Trust, error) {
	var input owner.Trust
	if trustFile != "" {
		var err error
		input, err = owner.LoadTrust(trustFile)
		if err != nil {
			return nil, fmt.Errorf("load owner trust: %w", err)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	prev := m.state.Owner
	if prev == nil && trustFile == "" {
		return nil, nil
	}
	if m.path == "" {
		return nil, errors.New("owner-locked mode requires persistent node state")
	}
	next := OwnerState{Trust: input}
	if prev != nil {
		if err := prev.Trust.Validate(); err != nil {
			return nil, err
		}
		if err := prev.Checkpoint.Validate(); err != nil {
			return nil, err
		}
		next = *prev
		if trustFile != "" {
			if input.PublicKey != prev.Trust.PublicKey {
				return nil, errors.New("configured owner key does not match the pinned node state")
			}
			next.Trust.MinimumVersion = max(next.Trust.MinimumVersion, input.MinimumVersion)
		}
	}
	if prev == nil || next != *prev {
		m.state.Owner = &next
		if err := m.saveLocked(); err != nil {
			m.state.Owner = prev
			return nil, fmt.Errorf("persist owner trust: %w", err)
		}
	}
	result := next.Trust
	return &result, nil
}

// RecordOwnerAuthorization persists a verified version before it may authorize
// traffic or revoke the previous snapshot. Identical updates require no I/O.
func (m *Manager) RecordOwnerAuthorization(next owner.Checkpoint) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	pinned := m.state.Owner
	if pinned == nil {
		return errors.New("owner trust is not configured")
	}
	if err := pinned.Checkpoint.Check(next, pinned.Trust.MinimumVersion); err != nil {
		return err
	}
	if pinned.Checkpoint == next {
		return nil
	}
	prev := pinned.Checkpoint
	pinned.Checkpoint = next
	if err := m.saveLocked(); err != nil {
		pinned.Checkpoint = prev
		return fmt.Errorf("persist owner authorization version: %w", err)
	}
	return nil
}

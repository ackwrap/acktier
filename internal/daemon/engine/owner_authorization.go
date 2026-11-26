package engine

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/ackwrap/acktier/internal/daemon/state"
	"github.com/ackwrap/acktier/internal/owner"
	"github.com/ackwrap/acktier/pkg/types"
)

var errAwaitingOwner = errors.New("waiting for owner approval; retry 'acktier up' after the owner publishes authorization")

// ownerRelayForControl routes relay credentials only to the configured origin,
// never to a host or TLS name taken from unsigned hints.
func ownerRelayForControl(u *url.URL) types.RelayNode {
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return types.RelayNode{
		ID: "default", Host: u.Hostname(), RelayAddr: net.JoinHostPort(u.Hostname(), port), UseTLS: u.Scheme == "https",
	}
}

// verifyOwnerMapLocked accepts only permissions covered by the pinned owner's
// signature. Record the checkpoint before interpreting a signed revocation.
// A non-nil verified result with errAwaitingOwner means a signed withdrawal or expiry.
func (e *Engine) verifyOwnerMapLocked(hints types.NetMap, relay types.RelayNode) (types.NetMap, *owner.Verified, error) {
	if hints.OwnerNetworkID != e.ownerNetworkID {
		return types.NetMap{}, nil, errors.New("control response does not match the pinned owner network")
	}
	if hints.OwnerAuthorization == nil {
		return types.NetMap{}, nil, errAwaitingOwner
	}
	v, err := owner.Verify(*e.ownerTrust, *hints.OwnerAuthorization)
	if err != nil {
		return types.NetMap{}, nil, err
	}
	if err := e.stateMgr.RecordOwnerAuthorization(v.Checkpoint); err != nil {
		return types.NetMap{}, nil, err
	}
	local := e.cryptoMgr.LocalPublicKey()
	if !time.Now().Before(v.Snapshot.ExpiresAt) || !v.Contains(local) {
		return types.NetMap{}, v, errAwaitingOwner
	}
	return v.Project(hints, local, relay), v, nil
}

func (e *Engine) installOwnerMapLocked(nm types.NetMap, v *owner.Verified) {
	if e.ownerInstalled != v.Checkpoint || !e.isRunning() {
		// Don't combine credentials, conntrack or routes from different
		// authorization versions, even if some members remain unchanged.
		e.clearAuthorizationLocked()
	}
	e.ownerInstalled = v.Checkpoint
	e.mu.Lock()
	e.ownerExpiresAt = v.Snapshot.ExpiresAt
	e.mu.Unlock()
	e.applyNetMap(nm, true)
}

func (e *Engine) acceptOwnerMapLocked(hints *types.NetMap) bool {
	if hints == nil {
		return false
	}
	nm, v, err := e.verifyOwnerMapLocked(*hints, e.ownerRelay)
	if err != nil {
		if v != nil && errors.Is(err, errAwaitingOwner) {
			e.clearAuthorizationLocked()
			return true
		}
		return false // Invalid hints never replace current authorization.
	}
	e.installOwnerMapLocked(nm, v)
	return true
}

// controlDeadlineLocked is called with e.mu held.
func (e *Engine) controlDeadlineLocked(now time.Time) time.Time {
	until := now.Add(e.controlLeaseTTL)
	if e.ownerTrust != nil && e.ownerExpiresAt.Before(until) {
		until = e.ownerExpiresAt
	}
	return until
}

func (e *Engine) persistPendingOwnerToken(origin, serverURL, token string) error {
	if err := e.stateMgr.Update(func(s *state.ConfigState) {
		if s.ServerURL == "" {
			s.ServerURL = serverURL
		}
		s.NodeTokens[origin] = token
	}); err != nil {
		return fmt.Errorf("persist pending registration: %w", err)
	}
	return nil
}

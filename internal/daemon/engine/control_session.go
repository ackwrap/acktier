package engine

import (
	"context"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"github.com/acktier/acktier/pkg/types"
)

const (
	// Reopen a silent stream promptly without treating silence as a revocation.
	controlStreamIdleTimeout = time.Minute

	// DefaultControlLeaseTTL bounds how long the last authorized NetMap can be
	// used when control is unreachable.
	DefaultControlLeaseTTL = 4 * time.Hour
)

func activeMapPeers(peers []types.PeerNode) []types.PeerNode {
	revoked := func(p types.PeerNode) bool { return p.KeyRevoked }
	if slices.ContainsFunc(peers, revoked) {
		return slices.DeleteFunc(slices.Clone(peers), revoked)
	}
	return peers
}

func (e *Engine) isOwnNetMap(nm types.NetMap) bool {
	return nm.Self.ID != 0 && !nm.Self.KeyRevoked && nm.Self.NodeKey == e.cryptoMgr.LocalPublicKey()
}

func (e *Engine) acceptControlEvent(ctx context.Context, ev types.MapStreamEvent) bool {
	e.sessionMu.Lock()
	defer e.sessionMu.Unlock()
	if e.controlCtx != ctx || ctx.Err() != nil {
		return false
	}
	switch ev.Type {
	case "netmap":
		if ev.NetMap == nil || !e.isOwnNetMap(*ev.NetMap) {
			e.clearAuthorizationLocked()
			return false
		}
		if !e.isRunning() {
			e.clearAuthorizationLocked()
		}
		e.applyNetMap(*ev.NetMap, true)
		return true
	case "keepalive":
		e.mu.Lock()
		defer e.mu.Unlock()
		// A heartbeat cannot renew a stale or missing snapshot.
		now := time.Now()
		if ev.Revision == 0 || ev.Revision != e.netMap.Revision || !now.Before(e.controlUntil) {
			return false
		}
		e.controlUntil = now.Add(e.controlLeaseTTL)
		return true
	default:
		return false
	}
}

func (e *Engine) handleControlRejection(ctx context.Context, status int) {
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		e.invalidateControlLease(ctx, false)
	}
}

func (e *Engine) watchControlLease(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.invalidateControlLease(ctx, true)
		}
	}
}

func (e *Engine) invalidateControlLease(ctx context.Context, onlyExpired bool) {
	e.sessionMu.Lock()
	defer e.sessionMu.Unlock()
	if e.controlCtx != ctx {
		return
	}
	e.mu.RLock()
	until := e.controlUntil
	e.mu.RUnlock()
	if !until.IsZero() && (!onlyExpired || !time.Now().Before(until)) {
		e.clearAuthorizationLocked()
	}
}

// clearAuthorizationLocked leaves the control stream free to reconnect, but
// closes the data plane until an authenticated, current snapshot is installed.
func (e *Engine) clearAuthorizationLocked() {
	e.mu.Lock()
	e.controlUntil = time.Time{}
	e.peersByKey = make(map[types.PublicKey]*peerRuntime)
	e.peersByIP = make(map[netip.Addr]*peerRuntime)
	e.routeTable = nil
	e.exitNodePeer = nil
	e.selfApprovedRoutes = nil
	e.netMap = types.NetMap{}
	e.mu.Unlock()

	e.cryptoMgr.ResetSessions()
	e.selector.Reset()
	e.hub.ResetConnections()
	e.pktFilter.Reset()
	e.dnsResolver.UpdateNetMap(types.NetMap{})
	e.gateway.ResetFlows()
	e.exitFlows.Reset()
	e.meshRouter.Recompute(nil, nil)
}

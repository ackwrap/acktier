package control

import (
	"errors"
	"net/http"
	"time"

	"github.com/ackwrap/acktier/internal/owner"
	"github.com/ackwrap/acktier/internal/server/store"
	"github.com/ackwrap/acktier/pkg/types"
)

func (s *Server) ownerSetupPending() bool {
	if !s.cfg.RequireOwner {
		return false
	}
	_, pinned := s.store.OwnerTrust()
	return !pinned
}

func (s *Server) afterOwnerSetup(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.ownerSetupPending() {
			writeError(w, http.StatusServiceUnavailable, "center setup is required; configure the owner in /admin/")
			return
		}
		next(w, r)
	}
}

func (s *Server) checkOwnerNetwork(w http.ResponseWriter, got string) bool {
	trust, locked := s.store.OwnerTrust()
	want := ""
	if locked {
		want = trust.NetworkID()
	}
	if got != want {
		writeError(w, http.StatusForbidden, "client must be provisioned for this control server's owner mode")
		return false
	}
	return true
}

func (s *Server) legacyPolicyOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, locked := s.store.OwnerTrust(); locked || s.cfg.RequireOwner {
			writeError(w, http.StatusForbidden, "publish an owner-signed authorization to change network policy")
			return
		}
		next(w, r)
	}
}

func sanitizeTransportPorts(in types.TransportPorts) types.TransportPorts {
	var out types.TransportPorts
	for _, proto := range []types.TransportProto{types.ProtoUDP, types.ProtoTCP, types.ProtoQUIC, types.ProtoWSS} {
		if port := in[proto]; port != 0 {
			if out == nil {
				out = make(types.TransportPorts, 4)
			}
			out[proto] = port
		}
	}
	return out
}

func transportPortsEqual(a, b types.TransportPorts) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// Keep a stream available to the coordination identity even after the owner
// withdraws its membership, so it can learn the signed revocation.
func (s *Server) buildOwnerNetMap(selfID types.NodeID, networkID string, revision uint64) (types.NetMap, bool) {
	env, verified, nodes := s.store.OwnerTopology()
	nm := types.NetMap{
		OwnerNetworkID: networkID, OwnerAuthorization: env,
		Revision: revision, UpdatedAt: time.Now().UTC(),
	}
	for _, sn := range nodes {
		n := sn.Node
		if n.KeyRevoked {
			continue
		}
		if n.ID == selfID {
			nm.Self = types.PeerNode{ID: n.ID, NodeKey: n.NodeKey}
		} else if verified != nil && verified.Contains(n.NodeKey) {
			nm.Peers = append(nm.Peers, types.PeerNode{
				NodeKey: n.NodeKey, Endpoints: n.Endpoints, Links: n.Links,
				Online: n.Online, CanRelay: n.CanRelay,
			})
		}
	}
	return nm, nm.Self.ID != 0
}

func (s *Server) handleOwnerRequests(w http.ResponseWriter, r *http.Request) {
	if _, locked := s.store.OwnerTrust(); !locked {
		writeError(w, http.StatusConflict, "owner mode is not configured")
		return
	}
	_, verified, nodes := s.store.OwnerTopology()
	writeJSON(w, http.StatusOK, ownerRequests(verified, nodes))
}

func ownerRequests(verified *owner.Verified, nodes []store.StoredNode) []types.OwnerJoinRequest {
	out := make([]types.OwnerJoinRequest, 0)
	for _, sn := range nodes {
		n := sn.Node
		if n.KeyRevoked || (verified != nil && verified.Contains(n.NodeKey)) {
			continue
		}
		out = append(out, types.OwnerJoinRequest{
			NodeKey: n.NodeKey, Hostname: n.Hostname, OS: n.OS, LastSeen: n.LastSeen,
			TransportPorts: n.TransportPorts, Endpoints: n.Endpoints, AdvertisedRoutes: n.AdvertisedRoutes,
		})
	}
	return out
}

func ownerMembers(verified *owner.Verified, records []store.StoredNode) []types.PeerNode {
	out := make([]types.PeerNode, 0)
	if verified == nil {
		return out
	}
	hints := make(map[types.PublicKey]types.PeerNode, len(records))
	for _, record := range records {
		if !record.Node.KeyRevoked {
			hints[record.Node.NodeKey] = record.Node
		}
	}
	for _, member := range verified.Snapshot.Members {
		n := member.Peer()
		hint := hints[n.NodeKey]
		n.Hostname, n.OS, n.Online, n.LastSeen = hint.Hostname, hint.OS, hint.Online, hint.LastSeen
		n.Endpoints, n.Links, n.CanRelay = hint.Endpoints, hint.Links, hint.CanRelay
		n.TransportPorts, n.AdvertisedRoutes = hint.TransportPorts, hint.AdvertisedRoutes
		out = append(out, n)
	}
	return out
}

func (s *Server) handleGetOwnerPublication(w http.ResponseWriter, r *http.Request) {
	env, _, _ := s.store.OwnerTopology()
	if env == nil {
		writeError(w, http.StatusNotFound, "no owner authorization published")
		return
	}
	writeJSON(w, http.StatusOK, env)
}

func (s *Server) handleOwnerPublication(w http.ResponseWriter, r *http.Request) {
	s.serveOwnerPublication(w, r, "")
}

func (s *Server) serveOwnerPublication(w http.ResponseWriter, r *http.Request, actor string) {
	var env types.OwnerAuthorization
	body := http.MaxBytesReader(w, r.Body, owner.MaxEnvelope)
	if err := owner.DecodeJSON(body, &env); err != nil {
		writeError(w, http.StatusBadRequest, "invalid or oversized owner authorization")
		return
	}
	var audit []store.AuditEntry
	if actor != "" {
		audit = []store.AuditEntry{{Actor: actor, Action: "authorization.publish", Result: "success"}}
	}
	version, err := s.publishOwner(env, audit...)
	if err != nil && actor != "" {
		_, code, _ := explainPublishError(err)
		s.audit(actor, "authorization.publish", "", "failure", code)
	}
	switch {
	case errors.Is(err, owner.ErrRollback), errors.Is(err, store.ErrOwnerNotConfigured):
		writeError(w, http.StatusConflict, err.Error())
		return
	case errors.Is(err, store.ErrOwnerInvalid):
		writeError(w, http.StatusBadRequest, err.Error())
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "could not persist owner authorization")
		return
	}
	writeJSON(w, http.StatusOK, map[string]uint64{"version": version})
}

func (s *Server) publishOwner(env types.OwnerAuthorization, audit ...store.AuditEntry) (uint64, error) {
	version, removed, err := s.store.PublishOwner(env, time.Now(), audit...)
	if err != nil {
		return 0, err
	}
	for _, key := range removed {
		s.relay.Disconnect(key)
	}
	s.broadcastTopologyChange()
	return version, nil
}

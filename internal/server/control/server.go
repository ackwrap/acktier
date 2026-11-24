package control

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/acktier/acktier/internal/server/ipam"
	"github.com/acktier/acktier/internal/server/relay"
	"github.com/acktier/acktier/internal/server/store"
	"github.com/acktier/acktier/pkg/types"
)

// Config configures the AckTier Control & Relay Server.
type Config struct {
	AdminToken  string
	PublicHost  string // Hostname or IP advertised in RelayNode
	RelayAddr   string // host:port advertised for TCP/HTTP relay
	STUNAddr    string // Primary UDP STUN address host:port
	STUNAltAddr string // Secondary UDP STUN address host:port for Cone/Symmetric classification
}

type subscriber struct {
	nodeID types.NodeID
	ch     chan types.NetMap
}

// Server coordinates authentication, IPAM, NetMap distribution, Admin API, and Relay upgrades.
type Server struct {
	cfg      Config
	store    *store.FileStore
	ipam     *ipam.Allocator
	relay    *relay.Server
	revision atomic.Uint64

	subMu       sync.RWMutex
	subscribers map[uint64]*subscriber
	nextSubID   uint64
}

func NewServer(cfg Config, st *store.FileStore) *Server {
	alloc := ipam.NewAllocator(ipam.DefaultIPv4Prefix, ipam.DefaultIPv6Prefix)
	for _, sn := range st.ListNodes() {
		alloc.Reserve(sn.Node.IPv4)
	}

	s := &Server{
		cfg:         cfg,
		store:       st,
		ipam:        alloc,
		subscribers: make(map[uint64]*subscriber),
	}
	s.revision.Store(1)
	s.relay = relay.NewServer(s.authenticateNodeToken)
	return s
}

func (s *Server) Relay() *relay.Server {
	return s.relay
}

func (s *Server) authenticateNodeToken(nodeKey types.PublicKey, token string) bool {
	if token == "" {
		return false
	}
	sn, ok := s.store.FindByNodeKey(nodeKey)
	return ok && sn.NodeToken == token
}

// Handler returns the root HTTP mux serving Admin API, Node Control API, and `/relay` Upgrade.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public health check
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "revision": s.revision.Load()})
	})

	// Relay connection upgrade endpoint (single-port friendly!)
	mux.HandleFunc("GET /relay", s.handleRelayUpgrade)

	// Node Control Plane endpoints
	mux.HandleFunc("POST /api/v1/node/register", s.handleNodeRegister)
	mux.HandleFunc("POST /api/v1/node/heartbeat", s.handleNodeHeartbeat)
	mux.HandleFunc("GET /api/v1/node/map/stream", s.handleNodeMapStream)

	// Admin API endpoints
	mux.HandleFunc("GET /api/v1/admin/status", s.requireAdmin(s.handleAdminStatus))
	mux.HandleFunc("GET /api/v1/admin/nodes", s.requireAdmin(s.handleAdminListNodes))
	mux.HandleFunc("DELETE /api/v1/admin/nodes/{id}", s.requireAdmin(s.handleAdminDeleteNode))
	mux.HandleFunc("POST /api/v1/admin/nodes/{id}/routes/approve", s.requireAdmin(s.handleAdminApproveRoutes))
	mux.HandleFunc("GET /api/v1/admin/keys", s.requireAdmin(s.handleAdminListKeys))
	mux.HandleFunc("POST /api/v1/admin/keys", s.requireAdmin(s.handleAdminCreateKey))
	mux.HandleFunc("DELETE /api/v1/admin/keys/{id}", s.requireAdmin(s.handleAdminRevokeKey))

	return mux
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if s.cfg.AdminToken == "" || auth != s.cfg.AdminToken {
			writeError(w, http.StatusUnauthorized, "invalid admin token")
			return
		}
		next(w, r)
	}
}

func extractBearer(r *http.Request) string {
	return strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
}

func sanitizeNodeName(hostname string, id types.NodeID) string {
	name := strings.ToLower(strings.TrimSpace(hostname))
	var b strings.Builder
	for _, ch := range name {
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' {
			b.WriteRune(ch)
		} else if ch == '_' || ch == ' ' || ch == '.' {
			b.WriteByte('-')
		}
	}
	res := strings.Trim(b.String(), "-")
	if res == "" {
		return fmt.Sprintf("node-%d", id)
	}
	return res
}

func buildAllowedIPs(n types.PeerNode) []netip.Prefix {
	var out []netip.Prefix
	if n.IPv4.IsValid() {
		out = append(out, netip.PrefixFrom(n.IPv4, 32))
	}
	if n.IPv6.IsValid() {
		out = append(out, netip.PrefixFrom(n.IPv6, 128))
	}
	out = append(out, n.ApprovedRoutes...)
	return out
}

func (s *Server) buildNetMapFor(selfID types.NodeID) (types.NetMap, bool) {
	all := s.store.ListNodes()
	var self types.PeerNode
	found := false
	peers := make([]types.PeerNode, 0, len(all))
	for _, sn := range all {
		n := sn.Node
		n.AllowedIPs = buildAllowedIPs(n)
		if n.ID == selfID {
			self = n
			found = true
		} else {
			peers = append(peers, n)
		}
	}
	if !found {
		return types.NetMap{}, false
	}

	dnsCfg, rules := s.store.GetDNSAndFilters()
	var relays []types.RelayNode
	if s.cfg.RelayAddr != "" {
		relays = append(relays, types.RelayNode{
			ID:          "default",
			Region:      "primary",
			Host:        s.cfg.PublicHost,
			RelayAddr:   s.cfg.RelayAddr,
			STUNAddr:    s.cfg.STUNAddr,
			STUNAltAddr: s.cfg.STUNAltAddr,
		})
	}

	return types.NetMap{
		Revision:     s.revision.Load(),
		Self:         self,
		Peers:        peers,
		Relays:       relays,
		PacketFilter: rules,
		DNS:          dnsCfg,
		UpdatedAt:    time.Now().UTC(),
	}, true
}

func (s *Server) broadcastTopologyChange() {
	s.revision.Add(1)
	s.subMu.RLock()
	subs := make([]*subscriber, 0, len(s.subscribers))
	for _, sub := range s.subscribers {
		subs = append(subs, sub)
	}
	s.subMu.RUnlock()

	for _, sub := range subs {
		nm, ok := s.buildNetMapFor(sub.nodeID)
		if !ok {
			continue
		}
		select {
		case sub.ch <- nm:
		default:
			// Replace stale unread snapshot with latest
			select {
			case <-sub.ch:
			default:
			}
			select {
			case sub.ch <- nm:
			default:
			}
		}
	}
}

func (s *Server) handleNodeRegister(w http.ResponseWriter, r *http.Request) {
	var req types.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.MachineKey.IsZero() || req.NodeKey.IsZero() {
		writeError(w, http.StatusBadRequest, "machineKey and nodeKey are required")
		return
	}

	now := time.Now().UTC()
	existing, exists := s.store.FindByMachineKey(req.MachineKey)
	if exists {
		bearer := extractBearer(r)
		if bearer != existing.NodeToken {
			// Allow re-auth with a valid PreAuthKey
			if req.AuthKey == "" {
				writeError(w, http.StatusUnauthorized, "node token or authKey required")
				return
			}
			if _, err := s.store.ConsumePreAuthKey(req.AuthKey); err != nil {
				writeError(w, http.StatusUnauthorized, err.Error())
				return
			}
		}
		existing.Node.NodeKey = req.NodeKey
		if req.Hostname != "" {
			existing.Node.Hostname = req.Hostname
			existing.Node.Name = sanitizeNodeName(req.Hostname, existing.Node.ID)
		}
		if req.OS != "" {
			existing.Node.OS = req.OS
		}
		if len(req.Endpoints) > 0 {
			existing.Node.Endpoints = req.Endpoints
		}
		if req.AdvertisedRoutes != nil {
			existing.Node.AdvertisedRoutes = req.AdvertisedRoutes
		}
		existing.Node.CanRelay = req.CanRelay
		existing.Node.PreferredRelayID = req.PreferredRelayID
		existing.Node.Online = true
		existing.Node.LastSeen = now
		if err := s.store.UpsertNode(existing); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.broadcastTopologyChange()
		nm, _ := s.buildNetMapFor(existing.Node.ID)
		writeJSON(w, http.StatusOK, types.RegisterResponse{
			NodeToken: existing.NodeToken,
			NetMap:    nm,
		})
		return
	}

	// New machine registration requires PreAuthKey
	pak, err := s.store.ConsumePreAuthKey(req.AuthKey)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "valid pre-auth key required for new node")
		return
	}

	v4, v6, err := s.ipam.Allocate()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	id := s.store.NextID()
	node := types.PeerNode{
		ID:               id,
		Name:             sanitizeNodeName(req.Hostname, id),
		Hostname:         req.Hostname,
		OS:               req.OS,
		MachineKey:       req.MachineKey,
		NodeKey:          req.NodeKey,
		IPv4:             v4,
		IPv6:             v6,
		Endpoints:        req.Endpoints,
		AdvertisedRoutes: req.AdvertisedRoutes,
		CanRelay:         req.CanRelay,
		PreferredRelayID: req.PreferredRelayID,
		Tags:             pak.Tags,
		Online:           true,
		LastSeen:         now,
		CreatedAt:        now,
	}
	node.AllowedIPs = buildAllowedIPs(node)
	sn := store.StoredNode{Node: node}
	if err := s.store.UpsertNode(sn); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	saved, _ := s.store.GetNode(id)
	log.Printf("[control] registered node #%d (%s) -> %s", id, node.Name, v4)

	s.broadcastTopologyChange()
	nm, _ := s.buildNetMapFor(id)
	writeJSON(w, http.StatusOK, types.RegisterResponse{
		NodeToken: saved.NodeToken,
		NetMap:    nm,
	})
}

func (s *Server) handleNodeHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req types.HeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	sn, ok := s.store.FindByNodeKey(req.NodeKey)
	if !ok || sn.NodeToken != extractBearer(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized node")
		return
	}

	changed := !sn.Node.Online ||
		sn.Node.CanRelay != req.CanRelay ||
		sn.Node.PreferredRelayID != req.PreferredRelayID ||
		!endpointsEqual(sn.Node.Endpoints, req.Endpoints)

	sn.Node.Endpoints = req.Endpoints
	if req.AdvertisedRoutes != nil {
		sn.Node.AdvertisedRoutes = req.AdvertisedRoutes
	}
	sn.Node.CanRelay = req.CanRelay
	sn.Node.PreferredRelayID = req.PreferredRelayID
	sn.Node.Online = true
	sn.Node.LastSeen = time.Now().UTC()
	_ = s.store.UpsertNode(sn)

	if changed {
		s.broadcastTopologyChange()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "revision": s.revision.Load()})
}

func endpointsEqual(a, b []types.Endpoint) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (s *Server) handleNodeMapStream(w http.ResponseWriter, r *http.Request) {
	nodeKeyStr := r.URL.Query().Get("nodeKey")
	nodeKey, err := types.ParsePublicKey(nodeKeyStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid nodeKey query parameter")
		return
	}
	sn, ok := s.store.FindByNodeKey(nodeKey)
	if !ok || sn.NodeToken != extractBearer(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized node")
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	// Mark node online upon stream connect
	if !sn.Node.Online {
		sn.Node.Online = true
		sn.Node.LastSeen = time.Now().UTC()
		_ = s.store.UpsertNode(sn)
		s.broadcastTopologyChange()
	}

	sub := &subscriber{
		nodeID: sn.Node.ID,
		ch:     make(chan types.NetMap, 2),
	}
	s.subMu.Lock()
	s.nextSubID++
	subID := s.nextSubID
	s.subscribers[subID] = sub
	s.subMu.Unlock()

	defer func() {
		s.subMu.Lock()
		delete(s.subscribers, subID)
		stillConnected := false
		for _, other := range s.subscribers {
			if other.nodeID == sn.Node.ID {
				stillConnected = true
				break
			}
		}
		s.subMu.Unlock()

		if !stillConnected {
			if cur, exists := s.store.GetNode(sn.Node.ID); exists && cur.Node.Online {
				cur.Node.Online = false
				cur.Node.LastSeen = time.Now().UTC()
				_ = s.store.UpsertNode(cur)
				s.broadcastTopologyChange()
			}
		}
	}()

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	enc := json.NewEncoder(w)
	if initMap, ok := s.buildNetMapFor(sn.Node.ID); ok {
		_ = enc.Encode(types.MapStreamEvent{
			Type:   "netmap",
			NetMap: &initMap,
			SentAt: time.Now().UnixMilli(),
		})
		flusher.Flush()
	}

	keepalive := time.NewTicker(20 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case nm := <-sub.ch:
			if err := enc.Encode(types.MapStreamEvent{
				Type:   "netmap",
				NetMap: &nm,
				SentAt: time.Now().UnixMilli(),
			}); err != nil {
				return
			}
			flusher.Flush()
		case <-keepalive.C:
			if err := enc.Encode(types.MapStreamEvent{
				Type:   "keepalive",
				SentAt: time.Now().UnixMilli(),
			}); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Server) handleRelayUpgrade(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "acktier-relay") {
		writeError(w, http.StatusUpgradeRequired, "expected Upgrade: acktier-relay")
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		writeError(w, http.StatusInternalServerError, "hijacking not supported")
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: acktier-relay\r\nConnection: Upgrade\r\n\r\n")
	_ = rw.Flush()

	// If bufio.Reader buffered any bytes after the HTTP request, wrap conn
	if rw.Reader.Buffered() > 0 {
		s.relay.ServeConn(&bufferedConn{Conn: conn, r: rw.Reader})
		return
	}
	s.relay.ServeConn(conn)
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (bc *bufferedConn) Read(p []byte) (int, error) {
	return bc.r.Read(p)
}

// --- Admin Handlers ---

func (s *Server) handleAdminStatus(w http.ResponseWriter, r *http.Request) {
	nodes := s.store.ListNodes()
	onlineCount := 0
	for _, n := range nodes {
		if n.Node.Online {
			onlineCount++
		}
	}
	relayClients, relayFrames, relayBytes := s.relay.Stats()
	writeJSON(w, http.StatusOK, map[string]any{
		"totalNodes":          len(nodes),
		"onlineNodes":         onlineCount,
		"revision":            s.revision.Load(),
		"relayConnectedNodes": relayClients,
		"relayForwardedFrames": relayFrames,
		"relayForwardedBytes":  relayBytes,
	})
}

func (s *Server) handleAdminListNodes(w http.ResponseWriter, r *http.Request) {
	stored := s.store.ListNodes()
	nodes := make([]types.PeerNode, 0, len(stored))
	for _, sn := range stored {
		n := sn.Node
		n.AllowedIPs = buildAllowedIPs(n)
		nodes = append(nodes, n)
	}
	writeJSON(w, http.StatusOK, nodes)
}

func (s *Server) handleAdminDeleteNode(w http.ResponseWriter, r *http.Request) {
	idNum, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid node id")
		return
	}
	deleted, err := s.store.DeleteNode(types.NodeID(idNum))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "node not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.ipam.Release(deleted.Node.IPv4)
	s.broadcastTopologyChange()
	writeJSON(w, http.StatusOK, map[string]any{"deleted": idNum})
}

func (s *Server) handleAdminApproveRoutes(w http.ResponseWriter, r *http.Request) {
	idNum, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid node id")
		return
	}
	var req struct {
		Routes []netip.Prefix `json:"routes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	sn, ok := s.store.GetNode(types.NodeID(idNum))
	if !ok {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	sn.Node.ApprovedRoutes = req.Routes
	_ = s.store.UpsertNode(sn)
	s.broadcastTopologyChange()
	writeJSON(w, http.StatusOK, sn.Node)
}

func (s *Server) handleAdminListKeys(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.store.ListPreAuthKeys())
}

func (s *Server) handleAdminCreateKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Label      string   `json:"label"`
		Reusable   bool     `json:"reusable"`
		Ephemeral  bool     `json:"ephemeral"`
		Tags       []string `json:"tags"`
		TTLSeconds int64    `json:"ttlSeconds"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	ttl := 24 * time.Hour
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	pak, err := s.store.CreatePreAuthKey(req.Label, req.Reusable, req.Ephemeral, req.Tags, ttl)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, pak)
}

func (s *Server) handleAdminRevokeKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.RevokePreAuthKey(id); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": id})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

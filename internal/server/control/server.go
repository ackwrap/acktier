package control

import (
	"bufio"
	"crypto/subtle"
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

	"github.com/acktier/acktier/internal/server/acl"
	"github.com/acktier/acktier/internal/server/ipam"
	"github.com/acktier/acktier/internal/server/relay"
	"github.com/acktier/acktier/internal/server/store"
	"github.com/acktier/acktier/pkg/types"
)

const (
	maxControlJSONBytes = 64 * 1024
	maxACLJSONBytes     = 256 * 1024
	maxEndpointsPerNode = 32
	maxLinksPerNode     = 256
	maxRoutesPerNode    = 64
	maxHostnameChars    = 63
)

// Config configures the AckTier Control & Relay Server.
type Config struct {
	AdminToken  string
	PublicHost  string // Hostname or IP advertised in RelayNode
	RelayAddr   string // host:port advertised for TCP/HTTPS relay
	STUNAddr    string // Primary UDP STUN address host:port
	STUNAltAddr string // Secondary UDP STUN address host:port for Cone/Symmetric classification
	UseTLS      bool   // Advertise TLS requirement for Relay connections
}

type subscriber struct {
	nodeID  types.NodeID
	nodeKey types.PublicKey
	ch      chan types.NetMap
	done    chan struct{}
	once    sync.Once
}

func (sub *subscriber) close() {
	sub.once.Do(func() {
		close(sub.done)
	})
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

func secretEqual(a, b string) bool {
	if a == "" || b == "" || len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (s *Server) authenticateNodeToken(nodeKey types.PublicKey, token string) bool {
	if nodeKey.IsZero() || token == "" {
		return false
	}
	sn, ok := s.store.FindByNodeKey(nodeKey)
	return ok && secretEqual(sn.NodeToken, token)
}

// Handler returns the root HTTP mux serving Admin API, Node Control API, and `/relay` Upgrade.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public health check
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "revision": s.revision.Load()})
	})

	// Relay connection upgrade endpoint
	mux.HandleFunc("GET /relay", s.handleRelayUpgrade)

	// Node Control Plane endpoints
	mux.HandleFunc("POST /api/v1/node/register", s.handleNodeRegister)
	mux.HandleFunc("POST /api/v1/node/heartbeat", s.handleNodeHeartbeat)
	mux.HandleFunc("GET /api/v1/node/map/stream", s.handleNodeMapStream)

	// Admin API endpoints
	mux.HandleFunc("GET /api/v1/admin/status", s.requireAdmin(s.handleAdminStatus))
	mux.HandleFunc("GET /api/v1/admin/nodes", s.requireAdmin(s.handleAdminListNodes))
	mux.HandleFunc("DELETE /api/v1/admin/nodes/{id}", s.requireAdmin(s.handleAdminDeleteNode))
	mux.HandleFunc("POST /api/v1/admin/nodes/{id}/rekey", s.requireAdmin(s.handleAdminRekeyNode))
	mux.HandleFunc("POST /api/v1/admin/nodes/{id}/rename", s.requireAdmin(s.handleAdminRenameNode))
	mux.HandleFunc("POST /api/v1/admin/nodes/{id}/routes/approve", s.requireAdmin(s.handleAdminApproveRoutes))
	mux.HandleFunc("GET /api/v1/admin/keys", s.requireAdmin(s.handleAdminListKeys))
	mux.HandleFunc("POST /api/v1/admin/keys", s.requireAdmin(s.handleAdminCreateKey))
	mux.HandleFunc("DELETE /api/v1/admin/keys/{id}", s.requireAdmin(s.handleAdminRevokeKey))
	mux.HandleFunc("GET /api/v1/admin/acl", s.requireAdmin(s.handleAdminGetACL))
	mux.HandleFunc("PUT /api/v1/admin/acl", s.requireAdmin(s.handleAdminPutACL))
	mux.HandleFunc("PUT /api/v1/admin/dns", s.requireAdmin(s.handleAdminPutDNS))

	return mux
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := extractBearer(r)
		if !secretEqual(s.cfg.AdminToken, auth) {
			writeError(w, http.StatusUnauthorized, "invalid admin token")
			return
		}
		next(w, r)
	}
}

func extractBearer(r *http.Request) string {
	hdr := r.Header.Get("Authorization")
	if len(hdr) < 7 || !strings.EqualFold(hdr[:7], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(hdr[7:])
}

func decodeBoundedJSON(w http.ResponseWriter, r *http.Request, limit int64, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	return dec.Decode(dst)
}

// buildAllowedIPs computes ONLY authorized source-IP prefixes for a peer.
// Default routes (0.0.0.0/0, ::/0) and any prefix overlapping overlay/special space are NEVER added to AllowedIPs!
func buildAllowedIPs(n types.PeerNode) []netip.Prefix {
	var out []netip.Prefix
	if n.IPv4.IsValid() {
		out = append(out, netip.PrefixFrom(n.IPv4, 32))
	}
	if n.IPv6.IsValid() {
		out = append(out, netip.PrefixFrom(n.IPv6, 128))
	}
	for _, rt := range n.ApprovedRoutes {
		if rt.Bits() > 0 && !types.OverlapsOverlayOrSpecial(rt) {
			out = append(out, rt.Masked())
		}
	}
	return out
}

func sanitizeEndpoints(in []types.Endpoint) []types.Endpoint {
	if len(in) == 0 {
		return nil
	}
	if len(in) > maxEndpointsPerNode {
		in = in[:maxEndpointsPerNode]
	}
	out := make([]types.Endpoint, 0, len(in))
	for _, ep := range in {
		switch ep.Proto {
		case types.ProtoUDP, types.ProtoTCP, types.ProtoQUIC, types.ProtoWSS:
		default:
			continue
		}
		host, portStr, err := net.SplitHostPort(strings.TrimSpace(ep.Addr))
		if err != nil {
			continue
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			continue
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			continue // Only literal IP endpoints allowed (no DNS SSRF/amplification)
		}
		ip = ip.Unmap()
		if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || types.IsOverlayAddr(ip) {
			continue
		}
		out = append(out, types.Endpoint{
			Proto: ep.Proto,
			Addr:  net.JoinHostPort(ip.String(), strconv.Itoa(port)),
			IsLAN: ep.IsLAN && ip.IsPrivate(),
		})
	}
	return out
}

func sanitizeHostnameMeta(h string) string {
	h = strings.TrimSpace(h)
	if len(h) > maxHostnameChars {
		h = h[:maxHostnameChars]
	}
	return h
}

func (s *Server) disconnectNodeSessions(nodeID types.NodeID, nodeKey types.PublicKey) {
	if !nodeKey.IsZero() {
		s.relay.Disconnect(nodeKey)
	}
	s.subMu.Lock()
	var targets []*subscriber
	for id, sub := range s.subscribers {
		if sub.nodeID == nodeID || (!nodeKey.IsZero() && sub.nodeKey == nodeKey) {
			targets = append(targets, sub)
			delete(s.subscribers, id)
		}
	}
	s.subMu.Unlock()
	for _, sub := range targets {
		sub.close()
	}
}

func (s *Server) buildNetMapFor(selfID types.NodeID) (types.NetMap, bool) {
	all := s.store.ListNodes()
	var self types.PeerNode
	found := false
	peers := make([]types.PeerNode, 0, len(all))
	allPeerNodes := make([]types.PeerNode, 0, len(all))
	for _, sn := range all {
		n := sn.Node
		n.AllowedIPs = buildAllowedIPs(n)
		allPeerNodes = append(allPeerNodes, n)
		if n.ID == selfID {
			self = n
			found = true
		} else {
			// Never expose another node's MachineKey to peers!
			n.MachineKey = types.PublicKey{}
			peers = append(peers, n)
		}
	}
	if !found {
		return types.NetMap{}, false
	}

	dnsCfg, staticRules := s.store.GetDNSAndFilters()
	pol := s.store.GetACLPolicy()
	compiledRules := acl.CompileForNode(pol, self, allPeerNodes)
	if len(compiledRules) > 0 {
		staticRules = compiledRules
	}
	var relays []types.RelayNode
	if s.cfg.RelayAddr != "" {
		relays = append(relays, types.RelayNode{
			ID:          "default",
			Region:      "primary",
			Host:        s.cfg.PublicHost,
			RelayAddr:   s.cfg.RelayAddr,
			STUNAddr:    s.cfg.STUNAddr,
			STUNAltAddr: s.cfg.STUNAltAddr,
			UseTLS:      s.cfg.UseTLS,
		})
	}

	return types.NetMap{
		Revision:     s.revision.Load(),
		Self:         self,
		Peers:        peers,
		Relays:       relays,
		PacketFilter: staticRules,
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
	if err := decodeBoundedJSON(w, r, maxControlJSONBytes, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid or oversized json body")
		return
	}
	if req.MachineKey.IsZero() || req.NodeKey.IsZero() {
		writeError(w, http.StatusBadRequest, "machineKey and nodeKey are required")
		return
	}
	if len(req.AdvertisedRoutes) > maxRoutesPerNode {
		req.AdvertisedRoutes = req.AdvertisedRoutes[:maxRoutesPerNode]
	}
	cleanEps := sanitizeEndpoints(req.Endpoints)
	cleanHost := sanitizeHostnameMeta(req.Hostname)

	// Prevent NodeKey collision across distinct machines.
	if otherByNK, nkTaken := s.store.FindByNodeKey(req.NodeKey); nkTaken && otherByNK.Node.MachineKey != req.MachineKey {
		writeError(w, http.StatusConflict, "nodeKey is already registered to another device")
		return
	}

	now := time.Now().UTC()
	existing, exists := s.store.FindByMachineKey(req.MachineKey)
	if exists {
		// SECURITY INVARIANT: Existing nodes can ONLY re-authenticate or rotate NodeKey using their valid NodeToken.
		// PreAuthKeys are strictly for creating new nodes and CANNOT take over an existing MachineKey!
		bearer := extractBearer(r)
		if !secretEqual(existing.NodeToken, bearer) {
			writeError(w, http.StatusForbidden, "machine already registered; valid node token required (pre-auth keys cannot take over existing nodes)")
			return
		}

		oldNodeKey := existing.Node.NodeKey
		existing.Node.NodeKey = req.NodeKey
		if cleanHost != "" {
			existing.Node.Hostname = cleanHost
			// Note: existing.Node.Name is server-assigned and immutable by the node itself!
		}
		if req.OS != "" {
			existing.Node.OS = sanitizeHostnameMeta(req.OS)
		}
		if cleanEps != nil {
			existing.Node.Endpoints = cleanEps
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
		if oldNodeKey != req.NodeKey {
			s.disconnectNodeSessions(existing.Node.ID, oldNodeKey)
		}
		s.broadcastTopologyChange()
		nm, _ := s.buildNetMapFor(existing.Node.ID)
		writeJSON(w, http.StatusOK, types.RegisterResponse{
			NodeToken: existing.NodeToken,
			NetMap:    nm,
		})
		return
	}

	// New machine registration requires a valid PreAuthKey.
	pak, err := s.store.ConsumePreAuthKey(strings.TrimSpace(req.AuthKey))
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
	uniqueName := s.store.AllocateUniqueName(cleanHost, id)
	node := types.PeerNode{
		ID:               id,
		Name:             uniqueName,
		Hostname:         cleanHost,
		OS:               sanitizeHostnameMeta(req.OS),
		MachineKey:       req.MachineKey,
		NodeKey:          req.NodeKey,
		IPv4:             v4,
		IPv6:             v6,
		Endpoints:        cleanEps,
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
	log.Printf("[control] registered node #%d (%s) -> %s", id, saved.Node.Name, v4)

	s.broadcastTopologyChange()
	nm, _ := s.buildNetMapFor(id)
	writeJSON(w, http.StatusOK, types.RegisterResponse{
		NodeToken: saved.NodeToken,
		NetMap:    nm,
	})
}

func (s *Server) handleNodeHeartbeat(w http.ResponseWriter, r *http.Request) {
	// Reject unauthenticated callers BEFORE decoding large request bodies if header is absent!
	bearer := extractBearer(r)
	if bearer == "" {
		writeError(w, http.StatusUnauthorized, "missing bearer token")
		return
	}
	var req types.HeartbeatRequest
	if err := decodeBoundedJSON(w, r, maxControlJSONBytes, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid or oversized json")
		return
	}
	sn, ok := s.store.FindByNodeKey(req.NodeKey)
	if !ok || !secretEqual(sn.NodeToken, bearer) {
		writeError(w, http.StatusUnauthorized, "unauthorized node")
		return
	}

	cleanEps := sanitizeEndpoints(req.Endpoints)
	links := req.Links
	if len(links) > maxLinksPerNode {
		links = links[:maxLinksPerNode]
	}
	routes := req.AdvertisedRoutes
	if len(routes) > maxRoutesPerNode {
		routes = routes[:maxRoutesPerNode]
	}

	changed := !sn.Node.Online ||
		sn.Node.CanRelay != req.CanRelay ||
		sn.Node.PreferredRelayID != req.PreferredRelayID ||
		!endpointsEqual(sn.Node.Endpoints, cleanEps) ||
		!linksMeaningfullyChanged(sn.Node.Links, links)

	sn.Node.Endpoints = cleanEps
	if links != nil {
		sn.Node.Links = links
	}
	if routes != nil {
		sn.Node.AdvertisedRoutes = routes
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

// linksMeaningfullyChanged returns false when neighbor sets match and quality-adjusted costs differ by < 20%.
func linksMeaningfullyChanged(oldLinks, newLinks []types.PeerLink) bool {
	if newLinks == nil {
		return true
	}
	if len(oldLinks) != len(newLinks) {
		return false
	}
	oldMap := make(map[types.PublicKey]float64, len(oldLinks))
	for _, l := range oldLinks {
		oldMap[l.Target] = l.EffectiveCostMs()
	}
	for _, nl := range newLinks {
		oldCost, ok := oldMap[nl.Target]
		if !ok {
			return false
		}
		newCost := nl.EffectiveCostMs()
		diff := newCost - oldCost
		if diff < 0 {
			diff = -diff
		}
		if oldCost > 0 && diff/oldCost > 0.20 && diff > 2.0 {
			return false
		}
	}
	return true
}

func (s *Server) handleNodeMapStream(w http.ResponseWriter, r *http.Request) {
	bearer := extractBearer(r)
	if bearer == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized node")
		return
	}
	nodeKeyStr := r.URL.Query().Get("nodeKey")
	nodeKey, err := types.ParsePublicKey(nodeKeyStr)
	if err != nil || nodeKey.IsZero() {
		writeError(w, http.StatusBadRequest, "invalid nodeKey query parameter")
		return
	}
	sn, ok := s.store.FindByNodeKey(nodeKey)
	if !ok || !secretEqual(sn.NodeToken, bearer) {
		writeError(w, http.StatusUnauthorized, "unauthorized node")
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	if !sn.Node.Online {
		sn.Node.Online = true
		sn.Node.LastSeen = time.Now().UTC()
		_ = s.store.UpsertNode(sn)
		s.broadcastTopologyChange()
	}

	sub := &subscriber{
		nodeID:  sn.Node.ID,
		nodeKey: sn.Node.NodeKey,
		ch:      make(chan types.NetMap, 2),
		done:    make(chan struct{}),
	}
	s.subMu.Lock()
	s.nextSubID++
	subID := s.nextSubID
	s.subscribers[subID] = sub
	s.subMu.Unlock()

	defer func() {
		sub.close()
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
		case <-sub.done:
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
		"totalNodes":           len(nodes),
		"onlineNodes":          onlineCount,
		"revision":             s.revision.Load(),
		"relayConnectedNodes":  relayClients,
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
	// Immediately kick active Relay and MapStream connections for the revoked node!
	s.disconnectNodeSessions(deleted.Node.ID, deleted.Node.NodeKey)
	s.ipam.Release(deleted.Node.IPv4)
	s.broadcastTopologyChange()
	writeJSON(w, http.StatusOK, map[string]any{"deleted": idNum})
}

// handleAdminRekeyNode provides an administrator-authenticated recovery flow to rotate a node's NodeToken
// (and optionally replace its NodeKey/MachineKey) without allowing ordinary PreAuthKeys to hijack nodes.
func (s *Server) handleAdminRekeyNode(w http.ResponseWriter, r *http.Request) {
	idNum, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid node id")
		return
	}
	var req struct {
		MachineKey types.PublicKey `json:"machineKey,omitempty"`
		NodeKey    types.PublicKey `json:"nodeKey,omitempty"`
	}
	if r.ContentLength != 0 {
		if err := decodeBoundedJSON(w, r, maxControlJSONBytes, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json")
			return
		}
	}

	sn, ok := s.store.GetNode(types.NodeID(idNum))
	if !ok {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	if !req.NodeKey.IsZero() {
		if other, taken := s.store.FindByNodeKey(req.NodeKey); taken && other.Node.ID != sn.Node.ID {
			writeError(w, http.StatusConflict, "nodeKey already registered to another device")
			return
		}
	}
	if !req.MachineKey.IsZero() {
		if other, taken := s.store.FindByMachineKey(req.MachineKey); taken && other.Node.ID != sn.Node.ID {
			writeError(w, http.StatusConflict, "machineKey already registered to another device")
			return
		}
	}

	oldNodeKey := sn.Node.NodeKey
	if !req.MachineKey.IsZero() {
		sn.Node.MachineKey = req.MachineKey
	}
	if !req.NodeKey.IsZero() {
		sn.Node.NodeKey = req.NodeKey
	}
	sn.NodeToken = store.GenerateNodeToken()
	sn.Node.Online = false
	if err := s.store.UpsertNode(sn); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.disconnectNodeSessions(sn.Node.ID, oldNodeKey)
	s.broadcastTopologyChange()
	writeJSON(w, http.StatusOK, map[string]any{
		"nodeId":    sn.Node.ID,
		"nodeToken": sn.NodeToken,
		"node":      sn.Node,
	})
}

func (s *Server) handleAdminRenameNode(w http.ResponseWriter, r *http.Request) {
	idNum, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid node id")
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := decodeBoundedJSON(w, r, maxControlJSONBytes, &req); err != nil || strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "valid name is required")
		return
	}
	sn, err := s.store.RenameNode(types.NodeID(idNum), req.Name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "node not found")
			return
		}
		if errors.Is(err, store.ErrNameConflict) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.broadcastTopologyChange()
	writeJSON(w, http.StatusOK, sn.Node)
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
	if err := decodeBoundedJSON(w, r, maxControlJSONBytes, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if len(req.Routes) > maxRoutesPerNode {
		writeError(w, http.StatusBadRequest, "too many routes")
		return
	}
	normalized := make([]netip.Prefix, 0, len(req.Routes))
	for _, rt := range req.Routes {
		if !rt.IsValid() {
			writeError(w, http.StatusBadRequest, "invalid route prefix")
			return
		}
		masked := rt.Masked()
		if masked.Bits() > 0 && types.OverlapsOverlayOrSpecial(masked) {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("route %s overlaps protected overlay, loopback, link-local, or multicast space", masked))
			return
		}
		normalized = append(normalized, masked)
	}

	sn, ok := s.store.GetNode(types.NodeID(idNum))
	if !ok {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	sn.Node.ApprovedRoutes = normalized
	sn.Node.AllowedIPs = buildAllowedIPs(sn.Node)
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
	if r.ContentLength != 0 {
		if err := decodeBoundedJSON(w, r, maxControlJSONBytes, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json")
			return
		}
	}
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

func (s *Server) handleAdminGetACL(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.store.GetACLPolicy())
}

func (s *Server) handleAdminPutACL(w http.ResponseWriter, r *http.Request) {
	var pol types.ACLPolicy
	if err := decodeBoundedJSON(w, r, maxACLJSONBytes, &pol); err != nil {
		writeError(w, http.StatusBadRequest, "invalid or oversized acl policy json")
		return
	}
	if err := acl.Validate(pol); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.SetACLPolicy(pol); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.broadcastTopologyChange()
	writeJSON(w, http.StatusOK, pol)
}

func (s *Server) handleAdminPutDNS(w http.ResponseWriter, r *http.Request) {
	var cfg types.DNSConfig
	if err := decodeBoundedJSON(w, r, maxControlJSONBytes, &cfg); err != nil {
		writeError(w, http.StatusBadRequest, "invalid dns config json")
		return
	}
	if cfg.MagicDNSSuffix == "" {
		cfg.MagicDNSSuffix = "ack.internal"
	}
	if err := s.store.SetDNSConfig(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.broadcastTopologyChange()
	writeJSON(w, http.StatusOK, cfg)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

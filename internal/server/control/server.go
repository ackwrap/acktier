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

	broadcastMu sync.Mutex
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
	_, ok := s.store.AuthenticateNode(nodeKey, token)
	return ok
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

func (s *Server) disconnectNodeSessions(nodeKey types.PublicKey) {
	s.relay.Disconnect(nodeKey)
	s.subMu.Lock()
	var targets []*subscriber
	for id, sub := range s.subscribers {
		if sub.nodeKey == nodeKey {
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
	revision := s.revision.Load()
	all, dnsCfg, staticRules, pol := s.store.TopologySnapshot()
	var self types.PeerNode
	found := false
	peers := make([]types.PeerNode, 0, len(all))
	allPeerNodes := make([]types.PeerNode, 0, len(all))
	for _, sn := range all {
		n := sn.Node
		if n.KeyRevoked {
			continue
		}
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
		Revision:     revision,
		Self:         self,
		Peers:        peers,
		Relays:       relays,
		PacketFilter: staticRules,
		DNS:          dnsCfg,
		UpdatedAt:    time.Now().UTC(),
	}, true
}

func (s *Server) broadcastTopologyChange() {
	s.broadcastMu.Lock()
	defer s.broadcastMu.Unlock()
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
	req.Endpoints = sanitizeEndpoints(req.Endpoints)
	req.Hostname = sanitizeHostnameMeta(req.Hostname)
	req.OS = sanitizeHostnameMeta(req.OS)
	req.AuthKey = strings.TrimSpace(req.AuthKey)
	sn, oldKey, err := s.store.RegisterNode(req, extractBearer(r), s.ipam.Allocate, s.ipam.Release)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNodeAuth), errors.Is(err, store.ErrKeyRequired):
			writeError(w, http.StatusForbidden, err.Error())
		case errors.Is(err, store.ErrKeyConflict):
			writeError(w, http.StatusConflict, err.Error())
		case errors.Is(err, store.ErrInvalidAuthKey):
			writeError(w, http.StatusUnauthorized, "valid pre-auth key required for new node")
		case errors.Is(err, ipam.ErrPoolExhausted):
			writeError(w, http.StatusServiceUnavailable, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "could not persist node registration")
		}
		return
	}
	if !oldKey.IsZero() {
		s.disconnectNodeSessions(oldKey)
	}
	log.Printf("[control] registered node #%d (%s) -> %s", sn.Node.ID, sn.Node.Name, sn.Node.IPv4)

	s.broadcastTopologyChange()
	nm, ok := s.buildNetMapFor(sn.Node.ID)
	if !ok || nm.Self.NodeKey != req.NodeKey {
		writeError(w, http.StatusForbidden, "node registration no longer current")
		return
	}
	writeJSON(w, http.StatusOK, types.RegisterResponse{
		NodeToken: sn.NodeToken,
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
	cleanEps := sanitizeEndpoints(req.Endpoints)
	links := req.Links
	if len(links) > maxLinksPerNode {
		links = links[:maxLinksPerNode]
	}
	routes := req.AdvertisedRoutes
	if len(routes) > maxRoutesPerNode {
		routes = routes[:maxRoutesPerNode]
	}

	var changed bool
	err := s.store.UpdateAuthenticatedNode(req.NodeKey, bearer, func(node *types.PeerNode) bool {
		changed = !node.Online || node.CanRelay != req.CanRelay ||
			node.PreferredRelayID != req.PreferredRelayID ||
			!endpointsEqual(node.Endpoints, cleanEps) || !linksMeaningfullyChanged(node.Links, links)
		node.Endpoints = cleanEps
		if links != nil {
			node.Links = links
		}
		if routes != nil {
			node.AdvertisedRoutes = routes
		}
		node.CanRelay = req.CanRelay
		node.PreferredRelayID = req.PreferredRelayID
		node.Online = true
		node.LastSeen = time.Now().UTC()
		return true
	})
	if err != nil {
		if errors.Is(err, store.ErrNodeAuth) {
			writeError(w, http.StatusUnauthorized, "unauthorized node")
		} else {
			writeError(w, http.StatusInternalServerError, "could not persist heartbeat")
		}
		return
	}

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
	if r.ContentLength != 0 {
		writeError(w, http.StatusBadRequest, "map stream does not accept a request body")
		return
	}
	_, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	// Only the response is streamed. Keep the server's request-body
	// timeout for other handlers without using it as a stream deadline.
	rc := http.NewResponseController(w)
	if err := rc.SetReadDeadline(time.Time{}); err != nil && !errors.Is(err, http.ErrNotSupported) {
		writeError(w, http.StatusInternalServerError, "could not clear stream read deadline")
		return
	}

	// Serialize admission with disconnectNodeSessions. Revalidate against the
	// store while holding subMu so obsolete keys cannot attach after a kick.
	s.subMu.Lock()
	sn, ok := s.store.AuthenticateNode(nodeKey, bearer)
	if !ok {
		s.subMu.Unlock()
		writeError(w, http.StatusUnauthorized, "unauthorized node")
		return
	}
	var cameOnline bool
	err = s.store.UpdateAuthenticatedNode(nodeKey, bearer, func(node *types.PeerNode) bool {
		cameOnline = !node.Online
		if cameOnline {
			node.Online = true
			node.LastSeen = time.Now().UTC()
		}
		return cameOnline
	})
	if err != nil {
		s.subMu.Unlock()
		if errors.Is(err, store.ErrNodeAuth) {
			writeError(w, http.StatusUnauthorized, "unauthorized node")
		} else {
			writeError(w, http.StatusInternalServerError, "could not persist node state")
		}
		return
	}
	sub := &subscriber{
		nodeID:  sn.Node.ID,
		nodeKey: sn.Node.NodeKey,
		ch:      make(chan types.NetMap, 2),
		done:    make(chan struct{}),
	}
	s.nextSubID++
	subID := s.nextSubID
	s.subscribers[subID] = sub
	s.subMu.Unlock()
	if cameOnline {
		s.broadcastTopologyChange()
	}

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
		var wentOffline bool
		if !stillConnected {
			err := s.store.UpdateAuthenticatedNode(nodeKey, bearer, func(node *types.PeerNode) bool {
				wentOffline = node.Online
				node.Online = false
				node.LastSeen = time.Now().UTC()
				return wentOffline
			})
			wentOffline = wentOffline && err == nil
		}
		s.subMu.Unlock()
		if wentOffline {
			s.broadcastTopologyChange()
		}
	}()

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	enc := json.NewEncoder(w)
	writeEvent := func(ev types.MapStreamEvent) bool {
		if !s.authenticateNodeToken(nodeKey, bearer) {
			return false
		}
		_ = rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := enc.Encode(ev); err != nil {
			return false
		}
		if err := rc.Flush(); err != nil {
			return false
		}
		_ = rc.SetWriteDeadline(time.Time{})
		return true
	}
	initMap, ok := s.buildNetMapFor(sn.Node.ID)
	if !ok || !writeEvent(types.MapStreamEvent{
		Type:   "netmap",
		NetMap: &initMap,
		SentAt: time.Now().UnixMilli(),
	}) {
		return
	}
	sentRevision := initMap.Revision

	keepalive := time.NewTicker(20 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-sub.done:
			return
		case nm := <-sub.ch:
			if nm.Revision <= sentRevision {
				continue
			}
			if !writeEvent(types.MapStreamEvent{
				Type:   "netmap",
				NetMap: &nm,
				SentAt: time.Now().UnixMilli(),
			}) {
				return
			}
			sentRevision = nm.Revision
		case <-keepalive.C:
			if !writeEvent(types.MapStreamEvent{
				Type:     "keepalive",
				Revision: s.revision.Load(),
				SentAt:   time.Now().UnixMilli(),
			}) {
				return
			}
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
	s.disconnectNodeSessions(deleted.Node.NodeKey)
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

	sn, oldKey, err := s.store.RekeyNode(types.NodeID(idNum), req.MachineKey, req.NodeKey)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusNotFound, "node not found")
		case errors.Is(err, store.ErrKeyConflict):
			writeError(w, http.StatusConflict, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "could not persist node rekey")
		}
		return
	}
	s.disconnectNodeSessions(oldKey)
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
		if types.OverlapsOverlayOrSpecial(rt) {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("route %s is mapped or overlaps protected address space", rt))
			return
		}
		normalized = append(normalized, rt.Masked())
	}

	sn, err := s.store.SetApprovedRoutes(types.NodeID(idNum), normalized)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "node not found")
		} else {
			writeError(w, http.StatusInternalServerError, "could not persist route approvals")
		}
		return
	}
	sn.Node.AllowedIPs = buildAllowedIPs(sn.Node)
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

package control

import (
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ackwrap/acktier/internal/owner"
	"github.com/ackwrap/acktier/internal/server/store"
	"github.com/ackwrap/acktier/pkg/types"
)

func (a *webAdmin) mountConsoleAPI(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/api/overview", a.pinned(a.overview))
	mux.HandleFunc("GET /admin/api/requests", a.pinned(a.requests))
	mux.HandleFunc("GET /admin/api/nodes", a.pinned(a.nodes))
	mux.HandleFunc("GET /admin/api/nodes/{key}", a.pinned(a.nodeDetail))
	mux.HandleFunc("PUT /admin/api/nodes/{key}/inventory", a.pinned(a.putInventory))
	mux.HandleFunc("DELETE /admin/api/nodes/{key}/inventory", a.pinned(a.deleteInventory))
	mux.HandleFunc("GET /admin/api/keys", a.pinned(a.listKeys))
	mux.HandleFunc("POST /admin/api/keys", a.pinned(a.createKey))
	mux.HandleFunc("POST /admin/api/keys/{id}/revoke", a.pinned(a.revokeKey))
	mux.HandleFunc("GET /admin/api/delegation", a.pinned(a.getDelegation))
	mux.HandleFunc("PUT /admin/api/delegation", a.pinned(a.putDelegation))
	mux.HandleFunc("DELETE /admin/api/delegation", a.pinned(a.deleteDelegation))
	mux.HandleFunc("GET /admin/api/audit", a.auth(a.auditLog))
}

type authorizationMeta struct {
	Version   uint64    `json:"version"`
	Digest    string    `json:"digest"`
	ExpiresAt time.Time `json:"expiresAt"`
	Expired   bool      `json:"expired"`
	Members   int       `json:"members"`
	Rules     int       `json:"rules"`
}

func authMeta(v *owner.Verified, now time.Time) *authorizationMeta {
	if v == nil {
		return nil
	}
	return &authorizationMeta{
		Version: v.Checkpoint.Version, Digest: v.Checkpoint.Digest, ExpiresAt: v.Snapshot.ExpiresAt,
		Expired: !now.Before(v.Snapshot.ExpiresAt), Members: len(v.Snapshot.Members), Rules: len(v.Snapshot.PacketFilter),
	}
}

type topoNode struct {
	Key      string `json:"key"`
	Name     string `json:"name"`
	IP       string `json:"ip"`
	Online   bool   `json:"online"`
	CanRelay bool   `json:"canRelay"`
}

type topoLink struct {
	A       string  `json:"a"`
	B       string  `json:"b"`
	RTTMs   float64 `json:"rttMs"`
	Loss    float64 `json:"loss"`
	Proto   string  `json:"proto,omitempty"`
	CostMs  float64 `json:"costMs"`
	Reverse bool    `json:"-"`
}

func (a *webAdmin) overview(w http.ResponseWriter, r *http.Request, s webSession) {
	st := a.server.store
	trust, _ := st.OwnerTrust()
	_, verified, records := st.OwnerTopology()
	now := time.Now()
	members := ownerMembers(verified, records)
	online := 0
	nodes := make([]topoNode, 0, len(members))
	inTopo := make(map[types.PublicKey]bool, len(members))
	for _, m := range members {
		if m.Online {
			online++
		}
		inTopo[m.NodeKey] = true
		nodes = append(nodes, topoNode{Key: m.NodeKey.String(), Name: m.Name, IP: m.IPv4.String(), Online: m.Online, CanRelay: m.CanRelay})
	}
	links := make([]topoLink, 0)
	seen := make(map[[2]string]bool)
	for _, m := range members {
		for _, l := range m.Links {
			if !inTopo[l.Target] {
				continue
			}
			ka, kb := m.NodeKey.String(), l.Target.String()
			pair := [2]string{min(ka, kb), max(ka, kb)}
			if seen[pair] {
				continue
			}
			seen[pair] = true
			links = append(links, topoLink{A: ka, B: kb, RTTMs: l.RTTMillis, Loss: l.LossRate, Proto: string(l.Proto), CostMs: l.EffectiveCostMs()})
		}
	}
	activeKeys := 0
	for _, k := range st.ListPreAuthKeys() {
		if keyState(k, now) == "active" {
			activeKeys++
		}
	}
	relayClients, frames, bytes := a.server.relay.Stats()
	audit := st.Audit()
	if len(audit) > 6 {
		audit = audit[:6]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"networkId":      trust.NetworkID(),
		"minimumVersion": trust.MinimumVersion,
		"authorization":  authMeta(verified, now),
		"counts": map[string]int{
			"requests": len(ownerRequests(verified, records)), "members": len(members), "membersOnline": online,
			"records": len(records), "drafts": len(st.ListDrafts()), "keysActive": activeKeys,
		},
		"relay":       map[string]any{"clients": relayClients, "frames": frames, "bytes": bytes},
		"revision":    a.server.revision.Load(),
		"topology":    map[string]any{"nodes": nodes, "links": links},
		"recentAudit": audit,
		"serverTime":  now.UTC(),
	})
}

type nodeRow struct {
	NodeKey        string               `json:"nodeKey"`
	Status         string               `json:"status"` // member | request | revoked
	Name           string               `json:"name,omitempty"`
	MemberID       uint64               `json:"memberId,omitempty"`
	IPv4           string               `json:"ipv4,omitempty"`
	Tags           []string             `json:"tags,omitempty"`
	Hostname       string               `json:"hostname,omitempty"`
	OS             string               `json:"os,omitempty"`
	Online         bool                 `json:"online"`
	Reported       bool                 `json:"reported"`
	LastSeen       time.Time            `json:"lastSeen,omitzero"`
	TransportPorts types.TransportPorts `json:"transportPorts,omitempty"`
	Transports     []string             `json:"transports"`
	Endpoints      int                  `json:"endpoints"`
	Routes         []string             `json:"advertisedRoutes,omitempty"`
	Inventory      bool                 `json:"inventory"`
}

func transportsOf(eps []types.Endpoint, ports types.TransportPorts) []string {
	out := make([]string, 0, 4)
	for _, ep := range eps {
		if p := string(ep.Proto); !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	for proto, port := range ports {
		if port != 0 && !slices.Contains(out, string(proto)) {
			out = append(out, string(proto))
		}
	}
	slices.Sort(out)
	return out
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}

func (a *webAdmin) nodeRows() []nodeRow {
	_, verified, records := a.server.store.OwnerTopology()
	inv := a.server.store.ListInventory()
	byKey := make(map[types.PublicKey]types.PeerNode, len(records))
	out := make([]nodeRow, 0, len(records))
	for _, rec := range records {
		byKey[rec.Node.NodeKey] = rec.Node
	}
	fill := func(row *nodeRow, n types.PeerNode) {
		row.Reported, row.Hostname, row.OS, row.Online = true, n.Hostname, n.OS, n.Online
		row.LastSeen, row.TransportPorts = n.LastSeen, n.TransportPorts
		row.Transports, row.Endpoints = transportsOf(n.Endpoints, n.TransportPorts), len(n.Endpoints)
		row.Routes = prefixStrings(n.AdvertisedRoutes)
	}
	listed := make(map[types.PublicKey]bool)
	if verified != nil {
		for _, m := range verified.Snapshot.Members {
			row := nodeRow{NodeKey: m.NodeKey.String(), Status: "member", Name: m.Name, MemberID: uint64(m.ID),
				IPv4: m.IPv4.String(), Tags: m.Tags, Transports: []string{}}
			if n, ok := byKey[m.NodeKey]; ok && !n.KeyRevoked {
				fill(&row, n)
			}
			_, row.Inventory = inv[m.NodeKey]
			listed[m.NodeKey] = true
			out = append(out, row)
		}
	}
	for _, rec := range records {
		n := rec.Node
		if listed[n.NodeKey] || n.NodeKey.IsZero() {
			continue
		}
		row := nodeRow{NodeKey: n.NodeKey.String(), Status: "request", Transports: []string{}}
		if n.KeyRevoked {
			row.Status = "revoked"
		}
		fill(&row, n)
		_, row.Inventory = inv[n.NodeKey]
		out = append(out, row)
	}
	return out
}

func matchesQuery(row nodeRow, q string) bool {
	if q == "" {
		return true
	}
	for _, f := range []string{row.Name, row.Hostname, row.OS, row.NodeKey, row.IPv4} {
		if strings.Contains(strings.ToLower(f), q) {
			return true
		}
	}
	return false
}

func paginate[T any](r *http.Request, items []T) map[string]any {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	size, _ := strconv.Atoi(r.URL.Query().Get("size"))
	page = max(page, 1)
	if size <= 0 || size > 200 {
		size = 25
	}
	start := len(items)
	if page-1 <= len(items)/size {
		start = (page - 1) * size
	}
	end := start + min(size, len(items)-start)
	return map[string]any{"items": items[start:end], "total": len(items), "page": page, "size": size}
}

func (a *webAdmin) filteredRows(r *http.Request, keep func(nodeRow) bool) []nodeRow {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	rows := a.nodeRows()
	out := make([]nodeRow, 0, len(rows))
	for _, row := range rows {
		if keep(row) && matchesQuery(row, q) {
			out = append(out, row)
		}
	}
	return out
}

func (a *webAdmin) requests(w http.ResponseWriter, r *http.Request, s webSession) {
	rows := a.filteredRows(r, func(row nodeRow) bool { return row.Status == "request" })
	slices.SortFunc(rows, func(x, y nodeRow) int { return y.LastSeen.Compare(x.LastSeen) })
	writeJSON(w, http.StatusOK, paginate(r, rows))
}

func (a *webAdmin) nodes(w http.ResponseWriter, r *http.Request, s webSession) {
	status := r.URL.Query().Get("status")
	rows := a.filteredRows(r, func(row nodeRow) bool { return status == "" || row.Status == status })
	writeJSON(w, http.StatusOK, paginate(r, rows))
}

type linkView struct {
	Target     string  `json:"target"`
	TargetName string  `json:"targetName,omitempty"`
	RTTMs      float64 `json:"rttMs"`
	JitterMs   float64 `json:"jitterMs"`
	Loss       float64 `json:"loss"`
	Proto      string  `json:"proto,omitempty"`
}

type reportedView struct {
	Hostname         string               `json:"hostname"`
	OS               string               `json:"os"`
	Online           bool                 `json:"online"`
	KeyRevoked       bool                 `json:"keyRevoked"`
	LastSeen         time.Time            `json:"lastSeen,omitzero"`
	CreatedAt        time.Time            `json:"createdAt,omitzero"`
	CanRelay         bool                 `json:"canRelay"`
	TransportPorts   types.TransportPorts `json:"transportPorts,omitempty"`
	Endpoints        []types.Endpoint     `json:"endpoints"`
	Transports       []string             `json:"transports"`
	AdvertisedRoutes []string             `json:"advertisedRoutes"`
	Links            []linkView           `json:"links"`
}

func parseKeyParam(r *http.Request) (types.PublicKey, bool) {
	raw := r.PathValue("key")
	if !strings.HasPrefix(raw, "nodekey:") {
		raw = "nodekey:" + raw
	}
	k, err := types.ParsePublicKey(raw)
	return k, err == nil && !k.IsZero()
}

func (a *webAdmin) knownKey(k types.PublicKey) bool {
	_, verified, records := a.server.store.OwnerTopology()
	if verified != nil && verified.Contains(k) {
		return true
	}
	return slices.ContainsFunc(records, func(sn store.StoredNode) bool { return sn.Node.NodeKey == k })
}

func (a *webAdmin) nodeDetail(w http.ResponseWriter, r *http.Request, s webSession) {
	key, ok := parseKeyParam(r)
	if !ok {
		apiError(w, http.StatusBadRequest, "bad_key", "节点公钥格式不正确。")
		return
	}
	_, verified, records := a.server.store.OwnerTopology()
	now := time.Now()
	names := make(map[types.PublicKey]string)
	var signed *owner.Member
	if verified != nil {
		for _, m := range verified.Snapshot.Members {
			names[m.NodeKey] = m.Name
			if m.NodeKey == key {
				signed = &m
			}
		}
	}
	var reported *reportedView
	for _, rec := range records {
		n := rec.Node
		if n.NodeKey != key {
			continue
		}
		rv := reportedView{
			Hostname: n.Hostname, OS: n.OS, Online: n.Online, KeyRevoked: n.KeyRevoked, LastSeen: n.LastSeen,
			CreatedAt: n.CreatedAt, CanRelay: n.CanRelay, TransportPorts: n.TransportPorts,
			Endpoints: n.Endpoints, Transports: transportsOf(n.Endpoints, n.TransportPorts),
			AdvertisedRoutes: prefixStrings(n.AdvertisedRoutes), Links: []linkView{},
		}
		if rv.Endpoints == nil {
			rv.Endpoints = []types.Endpoint{}
		}
		for _, l := range n.Links {
			rv.Links = append(rv.Links, linkView{Target: l.Target.String(), TargetName: names[l.Target],
				RTTMs: l.RTTMillis, JitterMs: l.JitterMillis, Loss: l.LossRate, Proto: string(l.Proto)})
		}
		reported = &rv
	}
	if signed == nil && reported == nil {
		apiError(w, http.StatusNotFound, "not_found", "中心没有这个节点的记录。")
		return
	}
	var inventory *store.Inventory
	if inv, ok := a.server.store.Inventory(key); ok {
		inventory = &inv
	}
	var unapproved, unadvertised []string
	if signed != nil && reported != nil {
		for _, rt := range reported.AdvertisedRoutes {
			if !slices.ContainsFunc(signed.Routes, func(p netip.Prefix) bool { return p.String() == rt }) {
				unapproved = append(unapproved, rt)
			}
		}
		for _, p := range signed.Routes {
			if p.Bits() > 0 && !slices.Contains(reported.AdvertisedRoutes, p.String()) {
				unadvertised = append(unadvertised, p.String())
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"nodeKey": key.String(), "signed": signed, "reported": reported, "inventory": inventory,
		"authorization": authMeta(verified, now),
		"flags": map[string]any{
			"missingReport": reported == nil, "offline": reported != nil && !reported.Online,
			"revoked": reported != nil && reported.KeyRevoked, "notMember": signed == nil,
			"authorizationExpired": verified != nil && !now.Before(verified.Snapshot.ExpiresAt),
			"unapprovedRoutes":     unapproved, "unadvertisedRoutes": unadvertised,
		},
	})
}

type inventoryRequest struct {
	Transports []store.InventoryTransport `json:"transports"`
	Endpoints  []types.Endpoint           `json:"endpoints"`
	Routes     []string                   `json:"routes"`
	Note       string                     `json:"note"`
}

func validateInventory(key types.PublicKey, req inventoryRequest) (store.Inventory, error) {
	inv := store.Inventory{NodeKey: key, Note: strings.TrimSpace(req.Note)}
	if len(req.Transports) > 8 || len(req.Endpoints) > 32 || len(req.Routes) > 64 {
		return inv, errors.New("条目过多：最多 8 个传输、32 个候选地址、64 个网段")
	}
	if utf8.RuneCountInString(inv.Note) > 200 {
		return inv, errors.New("备注最多 200 个字符")
	}
	validProto := func(p types.TransportProto) bool {
		return p == types.ProtoUDP || p == types.ProtoTCP || p == types.ProtoQUIC || p == types.ProtoWSS
	}
	for _, t := range req.Transports {
		if !validProto(t.Proto) || t.Port == 0 {
			return inv, errors.New("传输必须是 udp、tcp、quic 或 wss，端口 1–65535")
		}
		inv.Transports = append(inv.Transports, t)
	}
	for _, ep := range req.Endpoints {
		ap, err := netip.ParseAddrPort(strings.TrimSpace(ep.Addr))
		if !validProto(ep.Proto) || err != nil || ap.Port() == 0 || ap.Addr().Zone() != "" {
			return inv, errors.New("候选地址必须是字面量 IP:端口，并指定 udp、tcp、quic 或 wss")
		}
		inv.Endpoints = append(inv.Endpoints, types.Endpoint{Proto: ep.Proto, Addr: net.JoinHostPort(ap.Addr().Unmap().String(), strconv.Itoa(int(ap.Port())))})
	}
	for _, raw := range req.Routes {
		p, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil || p != p.Masked() {
			return inv, errors.New("网段必须是规范的 CIDR，例如 192.168.1.0/24")
		}
		inv.Routes = append(inv.Routes, p)
	}
	return inv, nil
}

func (a *webAdmin) putInventory(w http.ResponseWriter, r *http.Request, s webSession) {
	key, ok := parseKeyParam(r)
	if !ok || !a.knownKey(key) {
		apiError(w, http.StatusNotFound, "not_found", "只能为中心已知的节点公钥导入能力清单。")
		return
	}
	var req inventoryRequest
	if err := readStrict(w, r, adminJSONLimit, &req); err != nil {
		apiError(w, http.StatusBadRequest, "bad_request", "能力清单必须是 JSON，且只包含 transports、endpoints、routes、note。")
		return
	}
	inv, err := validateInventory(key, req)
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid_inventory", err.Error())
		return
	}
	if err := a.server.store.SetInventory(inv); err != nil {
		log.Printf("[web-admin] save inventory: %v", err)
		apiError(w, http.StatusInternalServerError, "storage", "保存失败，请检查中心的存储。")
		return
	}
	a.server.audit(actor(s), "inventory.import", key.String(), "success", "")
	saved, _ := a.server.store.Inventory(key)
	writeJSON(w, http.StatusOK, saved)
}

func (a *webAdmin) deleteInventory(w http.ResponseWriter, r *http.Request, s webSession) {
	key, ok := parseKeyParam(r)
	if !ok {
		apiError(w, http.StatusBadRequest, "bad_key", "节点公钥格式不正确。")
		return
	}
	if err := a.server.store.DeleteInventory(key); errors.Is(err, store.ErrNotFound) {
		apiError(w, http.StatusNotFound, "not_found", "该节点没有人工导入的清单。")
		return
	} else if err != nil {
		apiError(w, http.StatusInternalServerError, "storage", "删除失败，请检查中心的存储。")
		return
	}
	a.server.audit(actor(s), "inventory.delete", key.String(), "success", "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type keyRow struct {
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	State     string    `json:"state"` // active | used | expired | revoked
	Reusable  bool      `json:"reusable"`
	UsedCount int       `json:"usedCount"`
	ExpiresAt time.Time `json:"expiresAt"`
	CreatedAt time.Time `json:"createdAt"`
}

func keyState(k types.PreAuthKey, now time.Time) string {
	switch {
	case k.Revoked:
		return "revoked"
	case !now.Before(k.ExpiresAt):
		return "expired"
	case !k.Reusable && k.UsedCount > 0:
		return "used"
	}
	return "active"
}

func keyRowOf(k types.PreAuthKey, now time.Time) keyRow {
	return keyRow{ID: k.ID, Label: k.Label, State: keyState(k, now), Reusable: k.Reusable,
		UsedCount: k.UsedCount, ExpiresAt: k.ExpiresAt, CreatedAt: k.CreatedAt}
}

func (a *webAdmin) listKeys(w http.ResponseWriter, r *http.Request, s webSession) {
	now := time.Now()
	keys := a.server.store.ListPreAuthKeys()
	out := make([]keyRow, 0, len(keys))
	for i := len(keys) - 1; i >= 0; i-- {
		out = append(out, keyRowOf(keys[i], now))
	}
	writeJSON(w, http.StatusOK, out)
}

type createEnrollmentRequest struct {
	Label    string `json:"label"`
	TTLHours int    `json:"ttlHours"`
	Reusable bool   `json:"reusable"`
}

func (req *createEnrollmentRequest) validate() (code, message string) {
	req.Label = strings.TrimSpace(req.Label)
	if req.Label == "" || utf8.RuneCountInString(req.Label) > 64 {
		return "bad_label", "请输入 1 到 64 个字符的备注。"
	}
	if req.TTLHours == 0 {
		req.TTLHours = 24
	}
	if req.TTLHours < 1 || req.TTLHours > 720 {
		return "bad_ttl", "有效期需在 1 到 720 小时之间。"
	}
	return "", ""
}

func (s *Server) issueEnrollmentKey(req createEnrollmentRequest, actor string) (types.PreAuthKey, error) {
	detail := "单次"
	if req.Reusable {
		detail = "可重复"
	}
	return s.store.CreatePreAuthKey(req.Label, req.Reusable, false, nil, time.Duration(req.TTLHours)*time.Hour,
		store.AuditEntry{Actor: actor, Action: "key.create", Result: "success", Detail: detail + " · " + strconv.Itoa(req.TTLHours) + "h"})
}

func (a *webAdmin) createKey(w http.ResponseWriter, r *http.Request, s webSession) {
	var req createEnrollmentRequest
	if err := readStrict(w, r, 8<<10, &req); err != nil {
		apiError(w, http.StatusBadRequest, "bad_request", "无法读取请求。")
		return
	}
	if code, message := req.validate(); code != "" {
		apiError(w, http.StatusBadRequest, code, message)
		return
	}
	key, err := a.server.issueEnrollmentKey(req, actor(s))
	if err != nil {
		log.Printf("[web-admin] create preauth key: %v", err)
		apiError(w, http.StatusInternalServerError, "storage", "无法保存申请码，请检查中心的存储。")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"key": key.Key, "row": keyRowOf(key, time.Now())})
}

func (a *webAdmin) revokeKey(w http.ResponseWriter, r *http.Request, s webSession) {
	id := r.PathValue("id")
	if err := a.server.store.RevokePreAuthKey(id, store.AuditEntry{
		Actor: actor(s), Action: "key.revoke", Target: id, Result: "success",
	}); errors.Is(err, store.ErrNotFound) {
		apiError(w, http.StatusNotFound, "not_found", "找不到此申请码。")
		return
	} else if err != nil {
		apiError(w, http.StatusInternalServerError, "storage", "无法保存吊销记录，请检查中心的存储。")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *webAdmin) auditLog(w http.ResponseWriter, r *http.Request, s webSession) {
	entries := a.server.store.Audit()
	if q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q"))); q != "" {
		entries = slices.DeleteFunc(entries, func(e store.AuditEntry) bool {
			return !strings.Contains(strings.ToLower(e.Action+" "+e.Actor+" "+e.Target+" "+e.Detail+" "+e.Result), q)
		})
	}
	writeJSON(w, http.StatusOK, paginate(r, entries))
}

package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ackwrap/acktier/internal/owner"
	"github.com/ackwrap/acktier/internal/server/acl"
	"github.com/ackwrap/acktier/internal/server/store"
	"github.com/ackwrap/acktier/pkg/types"
)

const delegatedPolicyPath = "/api/v1/admin/policy"

type policyHandler func(http.ResponseWriter, *http.Request, string)

func (a *webAdmin) mountPolicyAPI(mux *http.ServeMux) {
	a.mountPolicyRoutes(mux, "/admin/api/policy", "/admin/api", func(handler policyHandler) http.HandlerFunc {
		return a.pinned(func(w http.ResponseWriter, r *http.Request, session webSession) {
			handler(w, r, actor(session))
		})
	})
	a.mountPolicyRoutes(mux, delegatedPolicyPath, delegatedPolicyPath, func(handler policyHandler) http.HandlerFunc {
		return a.server.requireDelegatedController(func(w http.ResponseWriter, r *http.Request) {
			handler(w, r, a.server.controllerActor())
		})
	})
}

func (a *webAdmin) mountPolicyRoutes(mux *http.ServeMux, policyPath, resourcePath string, protect func(policyHandler) http.HandlerFunc) {
	mux.HandleFunc("GET "+policyPath+"/active", protect(a.activePolicy))
	mux.HandleFunc("POST "+policyPath+"/validate", protect(a.validatePolicyStateless))

	drafts := resourcePath + "/drafts"
	mux.HandleFunc("GET "+drafts, protect(a.listDrafts))
	mux.HandleFunc("POST "+drafts, protect(a.createDraft))
	mux.HandleFunc("GET "+drafts+"/{id}", protect(a.getDraft))
	mux.HandleFunc("PUT "+drafts+"/{id}", protect(a.updateDraft))
	mux.HandleFunc("DELETE "+drafts+"/{id}", protect(a.deleteDraft))
	mux.HandleFunc("POST "+drafts+"/{id}/acl", protect(a.applyDraftACL))
	mux.HandleFunc("POST "+drafts+"/{id}/members", protect(a.addDraftMember))
	mux.HandleFunc("DELETE "+drafts+"/{id}/members/{key}", protect(a.removeDraftMember))
	mux.HandleFunc("GET "+drafts+"/{id}/export", protect(a.exportDraft))

	authorization := resourcePath + "/authorization"
	mux.HandleFunc("POST "+authorization+"/preview", protect(a.previewAuthorization))
	mux.HandleFunc("POST "+authorization, protect(a.publishAuthorization))
	mux.HandleFunc("GET "+authorization+"/history", protect(a.authorizationHistory))
	mux.HandleFunc("GET "+authorization+"/history/{version}", protect(a.authorizationByVersion))
}

func (a *webAdmin) activePolicy(w http.ResponseWriter, r *http.Request, _ string) {
	_, verified, _ := a.server.store.OwnerTopology()
	now := time.Now()
	if verified == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"hasActive":     false,
			"authorization": nil,
			"snapshot":      nil,
			"rules":         []ruleView{},
		})
		return
	}
	snap := verified.Snapshot
	writeJSON(w, http.StatusOK, map[string]any{
		"hasActive":     true,
		"authorization": authMeta(verified, now),
		"snapshot":      snap,
		"rules":         renderRules(snap.PacketFilter, snap.Members),
	})
}

func (a *webAdmin) validatePolicyStateless(w http.ResponseWriter, r *http.Request, _ string) {
	var req struct {
		Policy      owner.Policy `json:"policy"`
		BaseVersion uint64       `json:"baseVersion"`
	}
	if err := readStrict(w, r, adminPolicyLimit, &req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_json", "策略 JSON 格式无效或包含未知字段："+err.Error())
		return
	}
	_, verified, records := a.server.store.OwnerTopology()
	if req.BaseVersion == 0 && verified != nil {
		req.BaseVersion = verified.Checkpoint.Version
	}
	writeJSON(w, http.StatusOK, analyzePolicy(req.Policy, req.BaseVersion, verified, records))
}

type draftSummary struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Note        string    `json:"note,omitempty"`
	BaseVersion uint64    `json:"baseVersion"`
	BaseStale   bool      `json:"baseStale"`
	Valid       bool      `json:"valid"`
	Members     int       `json:"members"`
	ACLRules    int       `json:"aclRules"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

func summarizeDraft(d store.Draft, active *owner.Verified, records []store.StoredNode) draftSummary {
	an := analyzePolicy(d.Policy, d.BaseVersion, active, records)
	return draftSummary{
		ID: d.ID, Name: d.Name, Note: d.Note, BaseVersion: d.BaseVersion,
		BaseStale: an.BaseStale, Valid: an.Valid,
		Members: len(d.Policy.Members), ACLRules: len(d.Policy.ACL.ACLs),
		CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt,
	}
}

func (a *webAdmin) listDrafts(w http.ResponseWriter, r *http.Request, _ string) {
	_, verified, records := a.server.store.OwnerTopology()
	drafts := a.server.store.ListDrafts()
	out := make([]draftSummary, 0, len(drafts))
	for _, d := range drafts {
		out = append(out, summarizeDraft(d, verified, records))
	}
	writeJSON(w, http.StatusOK, out)
}

func defaultLiteralIPPort(addr string) string {
	ap, err := netip.ParseAddrPort(strings.TrimSpace(addr))
	if err != nil || ap.Port() == 0 || ap.Addr().IsUnspecified() || ap.Addr().Zone() != "" || ap.Addr().Is4In6() {
		return ""
	}
	return ap.String()
}

func activePolicySource(active owner.Snapshot, drafts []store.Draft) (owner.Policy, bool) {
	for _, d := range drafts {
		candidate, err := d.Policy.Snapshot(active.Version, active.ExpiresAt)
		if err != nil {
			continue
		}
		candidate.NetworkID = active.NetworkID
		if sameJSON(candidate, active) {
			return d.Policy, true
		}
	}
	return owner.Policy{}, false
}

func (a *webAdmin) initialPolicy() owner.Policy {
	return owner.Policy{
		Members:     []owner.Member{},
		ACL:         types.ACLPolicy{ACLs: []types.ACLGrantEntry{}},
		DNS:         types.DNSConfig{EnableMagicDNS: true, MagicDNSSuffix: "ack.internal"},
		STUNAddr:    defaultLiteralIPPort(a.server.cfg.STUNAddr),
		STUNAltAddr: defaultLiteralIPPort(a.server.cfg.STUNAltAddr),
	}
}

func sanitizeDraftMeta(name, note string) (string, string, error) {
	name = strings.TrimSpace(name)
	note = strings.TrimSpace(note)
	if name == "" {
		name = "策略草稿 " + time.Now().UTC().Format("01-02 15:04")
	}
	if utf8.RuneCountInString(name) > 64 {
		return "", "", errors.New("草稿名称最多 64 个字符")
	}
	if utf8.RuneCountInString(note) > 240 {
		return "", "", errors.New("草稿备注最多 240 个字符")
	}
	return name, note, nil
}

func normalizePolicySlices(p *owner.Policy) {
	if p.Members == nil {
		p.Members = []owner.Member{}
	}
	if p.ACL.ACLs == nil {
		p.ACL.ACLs = []types.ACLGrantEntry{}
	}
}

func (a *webAdmin) createDraft(w http.ResponseWriter, r *http.Request, actorID string) {
	var req struct {
		Name       string        `json:"name"`
		Note       string        `json:"note"`
		FromActive bool          `json:"fromActive"`
		Policy     *owner.Policy `json:"policy"`
	}
	if err := readStrict(w, r, adminPolicyLimit, &req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_json", "草稿请求或 policy.json 格式不正确："+err.Error())
		return
	}
	name, note, err := sanitizeDraftMeta(req.Name, req.Note)
	if err != nil {
		apiError(w, http.StatusBadRequest, "bad_meta", err.Error())
		return
	}
	_, verified, records := a.server.store.OwnerTopology()
	var baseVer uint64
	if verified != nil {
		baseVer = verified.Checkpoint.Version
	}
	var pol owner.Policy
	if req.Policy != nil {
		pol = *req.Policy
	} else if verified == nil {
		pol = a.initialPolicy()
	} else {
		var found bool
		if req.FromActive {
			pol, found = activePolicySource(verified.Snapshot, a.server.store.ListDrafts())
		}
		if !found {
			apiError(w, http.StatusConflict, "policy_source_required",
				"中心没有与当前签名快照相符的策略源文件。请导入所有者当时签发用的完整 policy.json，再修改或加入节点。")
			return
		}
	}
	normalizePolicySlices(&pol)

	saved, err := a.server.store.SaveDraft(store.Draft{
		Name: name, Note: note, BaseVersion: baseVer, Policy: pol,
	})
	if errors.Is(err, store.ErrTooManyDrafts) {
		apiError(w, http.StatusConflict, "too_many_drafts", "草稿数量已达上限（32 份），请先删除不再使用的草稿。")
		return
	} else if err != nil {
		log.Printf("[web-admin] create draft: %v", err)
		apiError(w, http.StatusInternalServerError, "storage", "保存草稿失败，请检查中心的存储。")
		return
	}
	a.server.audit(actorID, "draft.create", saved.ID, "success", fmt.Sprintf("base=v%d", saved.BaseVersion))
	writeJSON(w, http.StatusCreated, map[string]any{
		"draft":    saved,
		"analysis": analyzePolicy(saved.Policy, saved.BaseVersion, verified, records),
	})
}

func (a *webAdmin) getDraft(w http.ResponseWriter, r *http.Request, _ string) {
	d, err := a.server.store.GetDraft(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		apiError(w, http.StatusNotFound, "not_found", "找不到该草稿。")
		return
	} else if err != nil {
		apiError(w, http.StatusInternalServerError, "storage", "读取草稿失败。")
		return
	}
	_, verified, records := a.server.store.OwnerTopology()
	writeJSON(w, http.StatusOK, map[string]any{
		"draft":    d,
		"analysis": analyzePolicy(d.Policy, d.BaseVersion, verified, records),
	})
}

func policyDraftRevision(w http.ResponseWriter, r *http.Request) (time.Time, bool) {
	raw := r.URL.Query().Get("revision")
	if raw == "" {
		return time.Time{}, true
	}
	revision, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil || revision.IsZero() {
		apiError(w, http.StatusBadRequest, "bad_revision", "草稿版本无效，请刷新后重试。")
		return time.Time{}, false
	}
	return revision, true
}

func writePolicyDraftError(w http.ResponseWriter, action string, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		apiError(w, http.StatusNotFound, "not_found", "找不到该草稿。")
	case errors.Is(err, store.ErrDraftChanged):
		apiError(w, http.StatusConflict, "draft_changed", "草稿已经更新，请刷新并核对最新内容后重试。")
	default:
		log.Printf("[web-admin] %s draft: %v", action, err)
		apiError(w, http.StatusInternalServerError, "storage", "草稿操作失败，请检查中心的存储。")
	}
}

func (a *webAdmin) draftAtRevision(w http.ResponseWriter, r *http.Request) (store.Draft, bool) {
	revision, ok := policyDraftRevision(w, r)
	if !ok {
		return store.Draft{}, false
	}
	draft, err := a.server.store.GetDraft(r.PathValue("id"))
	if err == nil && !revision.IsZero() && !revision.Equal(draft.UpdatedAt) {
		err = store.ErrDraftChanged
	}
	if err != nil {
		writePolicyDraftError(w, "read", err)
	}
	return draft, err == nil
}

func (a *webAdmin) updateDraft(w http.ResponseWriter, r *http.Request, actorID string) {
	existing, ok := a.draftAtRevision(w, r)
	if !ok {
		return
	}
	var req struct {
		Name        string        `json:"name"`
		Note        string        `json:"note"`
		Rebase      bool          `json:"rebase"`
		RequireSafe bool          `json:"requireValid"`
		Policy      *owner.Policy `json:"policy"`
	}
	if err := readStrict(w, r, adminPolicyLimit, &req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_json", "策略 JSON 格式无效或包含未知字段："+err.Error())
		return
	}
	if req.Name != "" {
		existing.Name = req.Name
	}
	existing.Note = req.Note
	name, note, err := sanitizeDraftMeta(existing.Name, existing.Note)
	if err != nil {
		apiError(w, http.StatusBadRequest, "bad_meta", err.Error())
		return
	}
	existing.Name, existing.Note = name, note
	if req.Policy != nil {
		existing.Policy = *req.Policy
		normalizePolicySlices(&existing.Policy)
	}
	_, verified, records := a.server.store.OwnerTopology()
	if req.Rebase && verified != nil {
		existing.BaseVersion = verified.Checkpoint.Version
	}
	analysis := analyzePolicy(existing.Policy, existing.BaseVersion, verified, records)
	if req.RequireSafe && !analysis.Valid {
		msg := "策略校验未通过"
		for _, is := range analysis.Issues {
			if is.Level == "error" {
				msg = is.Message
				break
			}
		}
		apiError(w, http.StatusBadRequest, "invalid_policy", msg)
		return
	}
	saved, err := a.server.store.UpdateDraft(existing)
	if err != nil {
		writePolicyDraftError(w, "update", err)
		return
	}
	a.server.audit(actorID, "draft.update", saved.ID, "success", fmt.Sprintf("base=v%d valid=%t", saved.BaseVersion, analysis.Valid))
	writeJSON(w, http.StatusOK, map[string]any{"draft": saved, "analysis": analysis})
}

func (a *webAdmin) deleteDraft(w http.ResponseWriter, r *http.Request, actorID string) {
	revision, ok := policyDraftRevision(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if err := a.server.store.DeleteDraftAt(id, revision); err != nil {
		writePolicyDraftError(w, "delete", err)
		return
	}
	a.server.audit(actorID, "draft.delete", id, "success", "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// applyDraftACL replaces ONLY the ACL section of an existing draft without
// clearing members, DNS, or approved routes (CENTER_REQUIREMENTS §4.2.1).
func (a *webAdmin) applyDraftACL(w http.ResponseWriter, r *http.Request, actorID string) {
	d, ok := a.draftAtRevision(w, r)
	if !ok {
		return
	}
	var pol types.ACLPolicy
	if err := readStrict(w, r, maxACLJSONBytes, &pol); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_acl_json", "ACL JSON 格式无效（仅允许 groups、hosts、acls 字段）："+err.Error())
		return
	}
	if err := acl.Validate(pol); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_acl", friendlyPolicyError(err))
		return
	}
	if pol.ACLs == nil {
		pol.ACLs = []types.ACLGrantEntry{}
	}
	d.Policy.ACL = pol
	saved, err := a.server.store.UpdateDraft(d)
	if err != nil {
		writePolicyDraftError(w, "update", err)
		return
	}
	_, verified, records := a.server.store.OwnerTopology()
	analysis := analyzePolicy(saved.Policy, saved.BaseVersion, verified, records)
	a.server.audit(actorID, "draft.acl", saved.ID, "success", fmt.Sprintf("rules=%d", len(pol.ACLs)))
	writeJSON(w, http.StatusOK, map[string]any{"draft": saved, "analysis": analysis})
}

type addMemberRequest struct {
	ID      types.NodeID `json:"id"`
	NodeKey string       `json:"nodeKey"`
	Name    string       `json:"name"`
	IPv4    string       `json:"ipv4"`
	IPv6    string       `json:"ipv6"`
	Tags    []string     `json:"tags"`
	Routes  []string     `json:"routes"`
}

func (a *webAdmin) addDraftMember(w http.ResponseWriter, r *http.Request, actorID string) {
	d, ok := a.draftAtRevision(w, r)
	if !ok {
		return
	}
	var req addMemberRequest
	if err := readStrict(w, r, adminJSONLimit, &req); err != nil {
		apiError(w, http.StatusBadRequest, "bad_request", "成员参数格式不正确。")
		return
	}
	rawKey := strings.TrimSpace(req.NodeKey)
	if !strings.HasPrefix(rawKey, "nodekey:") && rawKey != "" {
		rawKey = "nodekey:" + rawKey
	}
	nk, err := types.ParsePublicKey(rawKey)
	if err != nil || nk.IsZero() {
		apiError(w, http.StatusBadRequest, "bad_key", "请提供有效的节点公钥。")
		return
	}
	cand := owner.Member{ID: req.ID, NodeKey: nk, Name: strings.ToLower(strings.TrimSpace(req.Name))}
	if s4 := strings.TrimSpace(req.IPv4); s4 != "" {
		ip4, pErr := netip.ParseAddr(s4)
		if pErr != nil || !ip4.Is4() {
			apiError(w, http.StatusBadRequest, "bad_ipv4", "虚拟 IPv4 地址无效。")
			return
		}
		cand.IPv4 = ip4
	}
	if s6 := strings.TrimSpace(req.IPv6); s6 != "" {
		ip6, pErr := netip.ParseAddr(s6)
		if pErr != nil || !ip6.Is6() || ip6.Is4In6() {
			apiError(w, http.StatusBadRequest, "bad_ipv6", "虚拟 IPv6 地址无效。")
			return
		}
		cand.IPv6 = ip6
	}
	for _, t := range req.Tags {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if !strings.HasPrefix(t, "tag:") || len(strings.TrimPrefix(t, "tag:")) == 0 {
			apiError(w, http.StatusBadRequest, "bad_tag", "标签必须以 tag: 开头，例如 tag:server。")
			return
		}
		cand.Tags = append(cand.Tags, t)
	}
	for _, rt := range req.Routes {
		rt = strings.TrimSpace(rt)
		if rt == "" {
			continue
		}
		p, pErr := netip.ParsePrefix(rt)
		if pErr != nil || p != p.Masked() || types.OverlapsOverlayOrSpecial(p) {
			apiError(w, http.StatusBadRequest, "bad_route", fmt.Sprintf("子网或出口路由 %q 不合法。", rt))
			return
		}
		cand.Routes = append(cand.Routes, p)
	}

	_, verified, records := a.server.store.OwnerTopology()
	var recNode *types.PeerNode
	for i := range records {
		if records[i].Node.NodeKey == nk && !records[i].Node.KeyRevoked {
			recNode = &records[i].Node
			break
		}
	}
	member, err := nextMember(d.Policy, verified, recNode, cand)
	if err != nil {
		apiError(w, http.StatusConflict, "member_conflict", err.Error())
		return
	}
	testPol := d.Policy
	testPol.Members = append(append([]owner.Member(nil), d.Policy.Members...), member)
	if err := testPol.Check(); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_member", friendlyPolicyError(err))
		return
	}
	d.Policy.Members = testPol.Members
	saved, err := a.server.store.UpdateDraft(d)
	if err != nil {
		writePolicyDraftError(w, "update", err)
		return
	}
	a.server.audit(actorID, "draft.add_member", saved.ID, "success", fmt.Sprintf("%s (%s)", member.Name, shortKey(nk.String())))
	writeJSON(w, http.StatusOK, map[string]any{
		"draft":    saved,
		"member":   member,
		"analysis": analyzePolicy(saved.Policy, saved.BaseVersion, verified, records),
	})
}

func (a *webAdmin) removeDraftMember(w http.ResponseWriter, r *http.Request, actorID string) {
	d, ok := a.draftAtRevision(w, r)
	if !ok {
		return
	}
	nk, ok := parseKeyParam(r)
	if !ok {
		apiError(w, http.StatusBadRequest, "bad_key", "节点公钥格式不正确。")
		return
	}
	before := len(d.Policy.Members)
	kept := make([]owner.Member, 0, before)
	for _, m := range d.Policy.Members {
		if m.NodeKey != nk {
			kept = append(kept, m)
		}
	}
	if len(kept) == before {
		apiError(w, http.StatusNotFound, "not_found", "草稿中不存在该成员。")
		return
	}
	d.Policy.Members = kept
	saved, err := a.server.store.UpdateDraft(d)
	if err != nil {
		writePolicyDraftError(w, "remove member", err)
		return
	}
	_, verified, records := a.server.store.OwnerTopology()
	a.server.audit(actorID, "draft.remove_member", saved.ID, "success", shortKey(nk.String()))
	writeJSON(w, http.StatusOK, map[string]any{
		"draft":    saved,
		"analysis": analyzePolicy(saved.Policy, saved.BaseVersion, verified, records),
	})
}

func (a *webAdmin) exportDraft(w http.ResponseWriter, r *http.Request, actorID string) {
	d, ok := a.draftAtRevision(w, r)
	if !ok {
		return
	}
	_, verified, records := a.server.store.OwnerTopology()
	analysis := analyzePolicy(d.Policy, d.BaseVersion, verified, records)
	if !analysis.Valid {
		apiError(w, http.StatusConflict, "invalid_draft", "草稿存在校验错误，请先修复后再导出待签 policy.json。")
		return
	}
	raw, err := json.MarshalIndent(d.Policy, "", "  ")
	if err != nil {
		apiError(w, http.StatusInternalServerError, "encode", "序列化草稿失败。")
		return
	}
	a.server.audit(actorID, "draft.export", d.ID, "success", fmt.Sprintf("base=v%d members=%d", d.BaseVersion, len(d.Policy.Members)))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-policy.json"`, d.ID))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(raw, '\n'))
}

func explainPublishError(err error) (int, string, string) {
	switch {
	case errors.Is(err, store.ErrOwnerNotConfigured):
		return http.StatusConflict, "setup_required", "中心尚未绑定所有者公钥。"
	case errors.Is(err, owner.ErrRollback):
		return http.StatusConflict, "rollback", "拒绝发布：版本低于当前最低水位，或与已发布的同版本内容不一致（禁止降级或篡改重签）。"
	case errors.Is(err, store.ErrOwnerInvalid):
		msg := err.Error()
		switch {
		case strings.Contains(msg, "different network"):
			return http.StatusBadRequest, "wrong_network", "拒绝发布：该授权属于其他组网（networkId 与本中心绑定的所有者公钥指纹不匹配）。"
		case strings.Contains(msg, "expired"):
			return http.StatusBadRequest, "expired", "拒绝发布：该签名快照已过期，请在所有者电脑重新签发。"
		case strings.Contains(msg, "signature"):
			return http.StatusBadRequest, "bad_signature", "拒绝发布：Ed25519 签名校验失败（非绑定所有者签发或载荷已被改动）。"
		default:
			return http.StatusBadRequest, "invalid_snapshot", "拒绝发布：签名快照格式或内容不合法（" + msg + "）。"
		}
	default:
		return http.StatusInternalServerError, "storage", "保存签名授权失败，请检查中心的存储。"
	}
}

func (a *webAdmin) previewAuthorization(w http.ResponseWriter, r *http.Request, _ string) {
	var env types.OwnerAuthorization
	if err := readStrict(w, r, owner.MaxEnvelope, &env); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_envelope", "文件不是合法的 authorization.json（请勿上传 signer.json 或未签名的草稿）。")
		return
	}
	_, active, _ := a.server.store.OwnerTopology()
	now := time.Now()
	next, idempotent, err := a.server.store.PreviewOwner(env, now)
	resp := map[string]any{
		"valid":      err == nil,
		"idempotent": idempotent,
	}
	if err != nil {
		_, code, reason := explainPublishError(err)
		resp["errorCode"] = code
		resp["reason"] = reason
	}
	if next != nil {
		resp["authorization"] = authMeta(next, now)
		resp["snapshot"] = next.Snapshot
		resp["rules"] = renderRules(next.Snapshot.PacketFilter, next.Snapshot.Members)
		resp["diff"] = snapshotDiff(active, next.Snapshot)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *webAdmin) publishAuthorization(w http.ResponseWriter, r *http.Request, actorID string) {
	var env types.OwnerAuthorization
	if err := readStrict(w, r, owner.MaxEnvelope, &env); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_envelope", "文件不是合法的 authorization.json。")
		return
	}
	now := time.Now()
	next, idempotent, err := a.server.store.PreviewOwner(env, now)
	if err != nil {
		status, code, reason := explainPublishError(err)
		target := ""
		if next != nil {
			target = fmt.Sprintf("v%d", next.Checkpoint.Version)
		}
		a.server.audit(actorID, "authorization.publish", target, "failure", code)
		apiError(w, status, code, reason)
		return
	}
	version, err := a.server.publishOwner(env, store.AuditEntry{
		Actor: actorID, Action: "authorization.publish", Result: "success",
	})
	if err != nil {
		status, code, reason := explainPublishError(err)
		a.server.audit(actorID, "authorization.publish", fmt.Sprintf("v%d", next.Checkpoint.Version), "failure", code)
		apiError(w, status, code, reason)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":       version,
		"idempotent":    idempotent,
		"authorization": authMeta(next, now),
	})
}

type publicationSummary struct {
	Version     uint64    `json:"version"`
	Digest      string    `json:"digest"`
	ExpiresAt   time.Time `json:"expiresAt"`
	Expired     bool      `json:"expired"`
	PublishedAt time.Time `json:"publishedAt"`
	Members     int       `json:"members"`
	Rules       int       `json:"rules"`
	Active      bool      `json:"active"`
}

func (a *webAdmin) authorizationHistory(w http.ResponseWriter, r *http.Request, _ string) {
	_, active, _ := a.server.store.OwnerTopology()
	var activeVer uint64
	if active != nil {
		activeVer = active.Checkpoint.Version
	}
	now := time.Now()
	recs := a.server.store.Publications()
	out := make([]publicationSummary, 0, len(recs))
	for _, rec := range recs {
		out = append(out, publicationSummary{
			Version: rec.Version, Digest: rec.Digest,
			ExpiresAt: rec.ExpiresAt, Expired: !now.Before(rec.ExpiresAt),
			PublishedAt: rec.PublishedAt, Members: rec.Members, Rules: rec.Rules,
			Active: rec.Version == activeVer,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *webAdmin) authorizationByVersion(w http.ResponseWriter, r *http.Request, _ string) {
	ver, err := strconv.ParseUint(r.PathValue("version"), 10, 64)
	if err != nil || ver == 0 {
		apiError(w, http.StatusBadRequest, "bad_version", "版本号无效。")
		return
	}
	_, active, _ := a.server.store.OwnerTopology()
	for _, rec := range a.server.store.Publications() {
		if rec.Version != ver {
			continue
		}
		var snap owner.Snapshot
		if err := owner.DecodeJSON(bytes.NewReader(rec.Envelope.Payload), &snap); err != nil {
			apiError(w, http.StatusInternalServerError, "corrupt", "无法解码历史快照。")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"version":     rec.Version,
			"digest":      rec.Digest,
			"publishedAt": rec.PublishedAt,
			"expiresAt":   rec.ExpiresAt,
			"expired":     !time.Now().Before(rec.ExpiresAt),
			"active":      active != nil && active.Checkpoint.Version == rec.Version,
			"snapshot":    snap,
			"rules":       renderRules(snap.PacketFilter, snap.Members),
		})
		return
	}
	apiError(w, http.StatusNotFound, "not_found", "找不到该历史版本。")
}

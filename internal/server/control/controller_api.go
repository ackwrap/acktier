package control

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/acktier/acktier/internal/owner"
	"github.com/acktier/acktier/internal/server/store"
)

const (
	controllerChallengeTTL = time.Minute
	maxUsedChallenges      = 4096
	challengeDataSize      = 8 + 16
	challengeSize          = challengeDataSize + sha256.Size
)

type controllerAuth struct {
	started time.Time
	secret  [32]byte
	mu      sync.Mutex
	used    map[[challengeDataSize]byte]uint64
}

func newControllerAuth() *controllerAuth {
	a := &controllerAuth{started: time.Now(), used: make(map[[challengeDataSize]byte]uint64)}
	_, _ = rand.Read(a.secret[:])
	return a
}

func (a *controllerAuth) now() uint64 {
	return uint64(time.Since(a.started))
}

func (a *controllerAuth) issue() string {
	var raw [challengeSize]byte
	data := raw[:challengeDataSize]
	binary.BigEndian.PutUint64(data, a.now()+uint64(controllerChallengeTTL))
	_, _ = rand.Read(data[8:])
	mac := hmac.New(sha256.New, a.secret[:])
	_, _ = mac.Write(data)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(data))
}

func (a *controllerAuth) check(encoded string) (data [challengeDataSize]byte, ok bool) {
	var raw [challengeSize]byte
	b64 := base64.RawURLEncoding.Strict()
	if len(encoded) != b64.EncodedLen(len(raw)) {
		return data, false
	}
	if n, err := base64.RawURLEncoding.Strict().Decode(raw[:], []byte(encoded)); err != nil || n != len(raw) {
		return data, false
	}
	copy(data[:], raw[:challengeDataSize])
	if binary.BigEndian.Uint64(data[:]) <= a.now() {
		return data, false
	}
	mac := hmac.New(sha256.New, a.secret[:])
	_, _ = mac.Write(data[:])
	return data, hmac.Equal(mac.Sum(nil), raw[challengeDataSize:])
}

func (a *controllerAuth) consume(data [challengeDataSize]byte) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	deadline := binary.BigEndian.Uint64(data[:])
	if deadline <= now {
		return false
	}
	for used, expires := range a.used {
		if expires <= now {
			delete(a.used, used)
		}
	}
	if _, exists := a.used[data]; exists || len(a.used) >= maxUsedChallenges {
		return false
	}
	a.used[data] = deadline
	return true
}

func (s *Server) mountDelegatedControllerAPI(mux *http.ServeMux) {
	mux.HandleFunc("GET "+owner.AdminChallengePath, s.handleControllerChallenge)
	mux.HandleFunc("GET /api/v1/admin/status", s.requireDelegatedController(s.handleAdminStatus))
	mux.HandleFunc("GET /api/v1/admin/nodes", s.requireDelegatedController(s.handleAdminListNodes))
	mux.HandleFunc("GET /api/v1/admin/owner/requests", s.requireDelegatedController(s.handleOwnerRequests))
	mux.HandleFunc("GET /api/v1/admin/owner/authorization", s.requireDelegatedController(s.handleGetOwnerPublication))
	mux.HandleFunc("PUT /api/v1/admin/owner/authorization", s.requireDelegatedController(s.handleControllerPublication))
	mux.HandleFunc("GET /api/v1/admin/keys", s.requireDelegatedController(s.handleAdminListKeys))
	mux.HandleFunc("POST /api/v1/admin/keys", s.requireDelegatedController(s.handleControllerCreateKey))
	mux.HandleFunc("DELETE /api/v1/admin/keys/{id}", s.requireDelegatedController(s.handleControllerRevokeKey))
	mux.HandleFunc("GET /api/v1/admin/drafts", s.requireDelegatedController(s.handleControllerListDrafts))
	mux.HandleFunc("POST /api/v1/admin/drafts", s.requireDelegatedController(s.handleControllerCreateDraft))
	mux.HandleFunc("GET /api/v1/admin/drafts/{id}", s.requireDelegatedController(s.handleControllerGetDraft))
	mux.HandleFunc("PUT /api/v1/admin/drafts/{id}", s.requireDelegatedController(s.handleControllerPutDraft))
	mux.HandleFunc("DELETE /api/v1/admin/drafts/{id}", s.requireDelegatedController(s.handleControllerDeleteDraft))
}

func (s *Server) handleControllerChallenge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !adminTransportOK(r) {
		writeError(w, http.StatusForbidden, "management API requires HTTPS or local loopback HTTP")
		return
	}
	trust, pinned := s.store.OwnerTrust()
	if !pinned {
		writeError(w, http.StatusServiceUnavailable, "bind the owner in /admin/ before using the management API")
		return
	}
	deleg := s.store.ControllerDelegation()
	if !deleg.Enabled || deleg.PublicKey == "" {
		writeError(w, http.StatusForbidden, "controller API delegation is disabled")
		return
	}
	writeJSON(w, http.StatusOK, owner.AdminChallenge{
		Challenge: s.controller.issue(),
		NetworkID: trust.NetworkID(),
	})
}

func (s *Server) requireDelegatedController(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !adminTransportOK(r) {
			writeError(w, http.StatusForbidden, "management API requires HTTPS or local loopback HTTP")
			return
		}
		trust, pinned := s.store.OwnerTrust()
		if !pinned {
			writeError(w, http.StatusServiceUnavailable, "owner setup is required")
			return
		}
		deleg := s.store.ControllerDelegation()
		if !deleg.Enabled || deleg.PublicKey == "" {
			writeError(w, http.StatusForbidden, "controller API delegation is disabled")
			return
		}
		proof, parsed := owner.ParseAdminProof(r.Header.Get("Authorization"))
		challenge, valid := s.controller.check(proof.Challenge)
		if !parsed || !valid || !proof.Verify(deleg.PublicKey, trust.NetworkID(), r.Method, r.URL.RequestURI()) {
			writeError(w, http.StatusUnauthorized, "a fresh request signature from the delegated controller is required")
			return
		}
		limit := int64(adminPolicyLimit)
		if r.URL.Path == "/api/v1/admin/owner/authorization" {
			limit = owner.MaxEnvelope
		}
		var raw []byte
		if r.Body != nil && r.Body != http.NoBody {
			body := http.MaxBytesReader(w, r.Body, limit)
			var err error
			raw, err = io.ReadAll(body)
			_ = body.Close()
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid or oversized signed request body")
				return
			}
		}
		if sha256.Sum256(raw) != proof.BodyHash || !s.controller.consume(challenge) {
			writeError(w, http.StatusUnauthorized, "invalid request body or expired or replayed challenge")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		next(w, r)
	}
}

func (s *Server) controllerActor() string {
	deleg := s.store.ControllerDelegation()
	if len(deleg.PublicKey) >= 12 {
		return "controller:" + deleg.PublicKey[:12]
	}
	return "controller"
}

func (s *Server) handleControllerPublication(w http.ResponseWriter, r *http.Request) {
	s.serveOwnerPublication(w, r, s.controllerActor())
}

func (s *Server) handleControllerCreateKey(w http.ResponseWriter, r *http.Request) {
	var req createEnrollmentRequest
	if err := readStrict(w, r, 8<<10, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid enrollment key request")
		return
	}
	if code, message := req.validate(); code != "" {
		writeError(w, http.StatusBadRequest, message)
		return
	}
	key, err := s.issueEnrollmentKey(req, s.controllerActor())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not save enrollment key")
		return
	}
	writeJSON(w, http.StatusCreated, key)
}

func (s *Server) handleControllerRevokeKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.RevokePreAuthKey(id, store.AuditEntry{
		Actor: s.controllerActor(), Action: "key.revoke", Target: id, Result: "success",
	}); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "enrollment key not found")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "could not revoke enrollment key")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"revoked": id})
}

func (s *Server) handleControllerListDrafts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.store.ListDrafts())
}

func (s *Server) handleControllerCreateDraft(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string       `json:"name"`
		Note   string       `json:"note"`
		Policy owner.Policy `json:"policy"`
	}
	if err := owner.DecodeJSON(http.MaxBytesReader(w, r.Body, adminPolicyLimit), &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid draft JSON")
		return
	}
	name, note, err := sanitizeDraftMeta(req.Name, req.Note)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_, verified, _ := s.store.OwnerTopology()
	var base uint64
	if verified != nil {
		base = verified.Checkpoint.Version
	}
	normalizePolicySlices(&req.Policy)
	saved, err := s.store.SaveDraft(store.Draft{Name: name, Note: note, BaseVersion: base, Policy: req.Policy})
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	s.audit(s.controllerActor(), "draft.create", saved.ID, "success", fmt.Sprintf("base=v%d", base))
	writeJSON(w, http.StatusCreated, saved)
}

func (s *Server) handleControllerGetDraft(w http.ResponseWriter, r *http.Request) {
	d, err := s.store.GetDraft(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "draft not found")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read draft")
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) handleControllerPutDraft(w http.ResponseWriter, r *http.Request) {
	d, err := s.store.GetDraft(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "draft not found")
		return
	}
	var req struct {
		Name   string        `json:"name"`
		Note   string        `json:"note"`
		Policy *owner.Policy `json:"policy"`
	}
	if err := owner.DecodeJSON(http.MaxBytesReader(w, r.Body, adminPolicyLimit), &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid draft JSON")
		return
	}
	if req.Name != "" {
		d.Name = req.Name
	}
	d.Note = req.Note
	if name, note, mErr := sanitizeDraftMeta(d.Name, d.Note); mErr == nil {
		d.Name, d.Note = name, note
	}
	if req.Policy != nil {
		d.Policy = *req.Policy
		normalizePolicySlices(&d.Policy)
	}
	saved, err := s.store.SaveDraft(d)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not save draft")
		return
	}
	s.audit(s.controllerActor(), "draft.update", saved.ID, "success", "")
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) handleControllerDeleteDraft(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteDraft(id); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "draft not found")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "could not delete draft")
		return
	}
	s.audit(s.controllerActor(), "draft.delete", id, "success", "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- Web Console Delegation Management (/admin/api/delegation) ---

func (a *webAdmin) getDelegation(w http.ResponseWriter, r *http.Request, s webSession) {
	writeJSON(w, http.StatusOK, a.server.store.ControllerDelegation())
}

func (a *webAdmin) putDelegation(w http.ResponseWriter, r *http.Request, s webSession) {
	var ct owner.ControllerTrust
	if err := readStrict(w, r, owner.MaxTrust, &ct); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_controller_trust",
			"只接受控制端导出的 controller-trust.json（包含 networkId、独立管理公钥与私钥持有证明）。")
		return
	}
	if utf8.RuneCountInString(ct.Label) > 64 {
		apiError(w, http.StatusBadRequest, "bad_label", "备注最多 64 个字符。")
		return
	}
	saved, err := a.server.store.EnableControllerDelegation(ct)
	if err != nil {
		a.server.audit(actor(s), "delegation.enable", shortKey(ct.PublicKey), "failure", err.Error())
		apiError(w, http.StatusBadRequest, "invalid_delegation", "无法启用委托："+err.Error())
		return
	}
	a.server.audit(actor(s), "delegation.enable", shortKey(saved.PublicKey), "success", saved.Label)
	writeJSON(w, http.StatusOK, saved)
}

func (a *webAdmin) deleteDelegation(w http.ResponseWriter, r *http.Request, s webSession) {
	prev := a.server.store.ControllerDelegation()
	if err := a.server.store.DisableControllerDelegation(); err != nil {
		apiError(w, http.StatusInternalServerError, "storage", "无法保存取消委托设置。")
		return
	}
	a.server.audit(actor(s), "delegation.disable", shortKey(prev.PublicKey), "success", "原控制端 API 凭据已立即失效")
	writeJSON(w, http.StatusOK, a.server.store.ControllerDelegation())
}

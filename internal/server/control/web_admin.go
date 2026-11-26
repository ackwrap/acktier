package control

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/acktier/acktier/internal/owner"
	"github.com/acktier/acktier/internal/server/store"
)

const (
	adminURL         = "/admin/"
	adminAPIPrefix   = "/admin/api/"
	adminJSONLimit   = 64 << 10
	adminPolicyLimit = owner.MaxPayload
	csrfHeader       = "X-CSRF-Token"
)

//go:embed web
var adminAssets embed.FS

var errAdminBody = errors.New("invalid request body")

type webAdmin struct {
	server   *Server
	sessions webSessions
	logins   loginLimiter
}

type adminHandler func(http.ResponseWriter, *http.Request, webSession)

// AdminHandler serves the browser console and its session API. It is meant
// for a separate, loopback-by-default listener; the node listener never
// mounts these routes.
func (s *Server) AdminHandler() http.Handler {
	a := &webAdmin{server: s, sessions: webSessions{live: make(map[string]webSession)}}
	mux := http.NewServeMux()
	assets, _ := fs.Sub(adminAssets, "web/assets")
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, adminURL, http.StatusFound)
	})
	mux.HandleFunc("GET /admin/{$}", a.index)
	mux.Handle("GET /admin/assets/", http.StripPrefix("/admin/assets/", http.FileServerFS(assets)))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ownerSetupRequired": s.ownerSetupPending()})
	})

	mux.HandleFunc("GET /admin/api/session", a.session)
	mux.HandleFunc("POST /admin/api/login", a.login)
	mux.HandleFunc("POST /admin/api/logout", a.auth(a.logout))
	mux.HandleFunc("POST /admin/api/password", a.auth(a.changePassword))
	mux.HandleFunc("POST /admin/api/setup/preview", a.auth(a.setupPreview))
	mux.HandleFunc("POST /admin/api/setup", a.auth(a.setup))

	a.mountConsoleAPI(mux)
	a.mountPolicyAPI(mux)
	s.mountDelegatedControllerAPI(mux)
	mux.HandleFunc("/admin/api/", func(w http.ResponseWriter, r *http.Request) {
		apiError(w, http.StatusNotFound, "not_found", "接口不存在。")
	})

	protected := http.NewCrossOriginProtection().Handler(mux)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setAdminHeaders(w)
		if !adminTransportOK(r) {
			http.Error(w, "Web management requires HTTPS or local loopback HTTP", http.StatusForbidden)
			return
		}
		protected.ServeHTTP(w, r)
	})
}

func setAdminHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
		"connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	h.Set("Cache-Control", "no-store")
	h.Set("Vary", "Sec-Fetch-Site, Origin, Cookie")
}

func (a *webAdmin) index(w http.ResponseWriter, r *http.Request) {
	page, err := adminAssets.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "console assets missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(page)
}

type apiErrorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func apiError(w http.ResponseWriter, status int, code, message string) {
	var body apiErrorBody
	body.Error.Code, body.Error.Message = code, message
	writeJSON(w, status, body)
}

// readBody reads a bounded request body.
func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		return nil, errAdminBody
	}
	return raw, nil
}

// readStrict decodes exactly one JSON value and rejects unknown fields.
func readStrict(w http.ResponseWriter, r *http.Request, limit int64, dst any) error {
	raw, err := readBody(w, r, limit)
	if err != nil {
		return err
	}
	if err := owner.DecodeJSON(bytes.NewReader(raw), dst); err != nil {
		return err
	}
	return nil
}

func (a *webAdmin) currentSession(r *http.Request) (webSession, bool) {
	return a.sessions.get(adminSessionID(r), time.Now(), a.server.store.AdminPasswordUpdatedAt())
}

// auth requires a live session and, for state changes, the session's CSRF
// token in a request header in addition to same-origin protection.
func (a *webAdmin) auth(next adminHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, ok := a.currentSession(r)
		if !ok {
			apiError(w, http.StatusUnauthorized, "unauthenticated", "请先登录管理台。")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !secretEqual(session.csrf, r.Header.Get(csrfHeader)) {
			apiError(w, http.StatusForbidden, "csrf", "页面已失效，请刷新后重试。")
			return
		}
		next(w, r, session)
	}
}

// pinned additionally requires a bound owner.
func (a *webAdmin) pinned(next adminHandler) http.HandlerFunc {
	return a.auth(func(w http.ResponseWriter, r *http.Request, s webSession) {
		if _, ok := a.server.store.OwnerTrust(); !ok {
			apiError(w, http.StatusConflict, "setup_required", "请先绑定所有者。")
			return
		}
		next(w, r, s)
	})
}

func actor(s webSession) string {
	return "web@" + clientKey(s.remote)
}

func (s *Server) audit(actor, action, target, result, detail string) {
	if err := s.store.AppendAudit(store.AuditEntry{Actor: actor, Action: action, Target: target, Result: result, Detail: detail}); err != nil {
		log.Printf("[audit] persist entry %s: %v", action, err)
	}
}

type sessionInfo struct {
	Authenticated      bool   `json:"authenticated"`
	SetupPending       bool   `json:"setupPending"`
	PasswordConfigured bool   `json:"passwordConfigured"`
	CSRF               string `json:"csrf,omitempty"`
	ExpiresAt          string `json:"expiresAt,omitempty"`
}

func (a *webAdmin) info(session *webSession) sessionInfo {
	_, pinned := a.server.store.OwnerTrust()
	out := sessionInfo{SetupPending: !pinned, PasswordConfigured: a.server.store.HasAdminPassword()}
	if session != nil {
		out.Authenticated, out.CSRF = true, session.csrf
		out.ExpiresAt = session.expires.UTC().Format(time.RFC3339)
	}
	return out
}

func (a *webAdmin) session(w http.ResponseWriter, r *http.Request) {
	if s, ok := a.currentSession(r); ok {
		writeJSON(w, http.StatusOK, a.info(&s))
		return
	}
	writeJSON(w, http.StatusOK, a.info(nil))
}

func (a *webAdmin) startSession(w http.ResponseWriter, r *http.Request, passwordAt time.Time) webSession {
	a.sessions.revoke(adminSessionID(r))
	id, session := a.sessions.create(time.Now(), passwordAt, r.RemoteAddr)
	c := adminCookie(r)
	c.Value = id
	c.Expires = session.expires
	http.SetCookie(w, &c)
	return session
}

func (a *webAdmin) reservePasswordWork(w http.ResponseWriter, r *http.Request) bool {
	if !a.logins.reserve(r.RemoteAddr, time.Now()) {
		w.Header().Set("Retry-After", "60")
		apiError(w, http.StatusTooManyRequests, "rate_limited", "密码验证繁忙，请稍后重试。")
		return false
	}
	return true
}

func (a *webAdmin) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if err := readStrict(w, r, 8<<10, &req); err != nil {
		apiError(w, http.StatusBadRequest, "bad_request", "无法读取登录信息。")
		return
	}
	if !a.server.store.HasAdminPassword() {
		apiError(w, http.StatusServiceUnavailable, "no_password", "中心尚未设置管理员密码，请在中心主机上使用 -reset-admin-password 设置。")
		return
	}
	if !a.reservePasswordWork(w, r) {
		return
	}
	passwordAt, matched := a.server.store.CheckAdminPassword(req.Password)
	a.logins.release()
	if !matched {
		a.server.audit("web@"+clientKey(r.RemoteAddr), "login", "", "failure", "")
		apiError(w, http.StatusUnauthorized, "bad_password", "管理员密码不正确。")
		return
	}
	if !passwordAt.Equal(a.server.store.AdminPasswordUpdatedAt()) {
		apiError(w, http.StatusUnauthorized, "password_changed", "密码已更新，请使用新密码登录。")
		return
	}
	session := a.startSession(w, r, passwordAt)
	a.server.audit(actor(session), "login", "", "success", "")
	writeJSON(w, http.StatusOK, a.info(&session))
}

func (a *webAdmin) logout(w http.ResponseWriter, r *http.Request, s webSession) {
	a.sessions.revoke(adminSessionID(r))
	c := adminCookie(r)
	c.MaxAge = -1
	http.SetCookie(w, &c)
	a.server.audit(actor(s), "logout", "", "success", "")
	writeJSON(w, http.StatusOK, a.info(nil))
}

func (a *webAdmin) changePassword(w http.ResponseWriter, r *http.Request, s webSession) {
	var req struct {
		Current string `json:"current"`
		Next    string `json:"next"`
	}
	if err := readStrict(w, r, 8<<10, &req); err != nil {
		apiError(w, http.StatusBadRequest, "bad_request", "无法读取请求。")
		return
	}
	if !a.reservePasswordWork(w, r) {
		return
	}
	defer a.logins.release()
	passwordAt, matched := a.server.store.CheckAdminPassword(req.Current)
	if !matched {
		a.server.audit(actor(s), "password.change", "", "failure", "当前密码错误")
		apiError(w, http.StatusForbidden, "bad_password", "当前密码不正确。")
		return
	}
	if !passwordAt.Equal(s.passwordAt) {
		apiError(w, http.StatusUnauthorized, "password_changed", "密码已更新，请重新登录。")
		return
	}
	nextAt, err := a.server.store.RotateAdminPassword(req.Next, passwordAt, store.AuditEntry{
		Actor: actor(s), Action: "password.change", Result: "success", Detail: "已撤销其他会话",
	})
	if errors.Is(err, store.ErrWeakPassword) {
		apiError(w, http.StatusBadRequest, "weak_password", "新密码至少 12 个字符，最多 256 字节。")
		return
	} else if errors.Is(err, store.ErrPasswordChanged) {
		apiError(w, http.StatusUnauthorized, "password_changed", "密码已更新，请重新登录。")
		return
	} else if err != nil {
		log.Printf("[web-admin] persist password: %v", err)
		apiError(w, http.StatusInternalServerError, "storage", "保存密码失败，请检查中心的存储。")
		return
	}
	session := a.startSession(w, r, nextAt)
	writeJSON(w, http.StatusOK, a.info(&session))
}

type trustPreview struct {
	NetworkID      string `json:"networkId"`
	PublicKey      string `json:"publicKey"`
	MinimumVersion uint64 `json:"minimumVersion"`
}

func decodeTrust(raw []byte) (owner.Trust, error) {
	var trust owner.Trust
	if len(raw) > owner.MaxTrust {
		return trust, errAdminBody
	}
	if err := owner.DecodeJSON(bytes.NewReader(raw), &trust); err != nil {
		return trust, err
	}
	return trust, trust.Validate()
}

const trustOnlyMessage = "只接受所有者导出的公钥文件 trust.json。不要上传 signer.json。"

func (a *webAdmin) setupPreview(w http.ResponseWriter, r *http.Request, s webSession) {
	raw, err := readBody(w, r, owner.MaxTrust+1)
	trust, err2 := decodeTrust(raw)
	if err != nil || err2 != nil {
		apiError(w, http.StatusBadRequest, "invalid_trust", trustOnlyMessage)
		return
	}
	writeJSON(w, http.StatusOK, trustPreview{trust.NetworkID(), trust.PublicKey, trust.MinimumVersion})
}

func (a *webAdmin) setup(w http.ResponseWriter, r *http.Request, s webSession) {
	var req struct {
		Trust   json.RawMessage `json:"trust"`
		Confirm bool            `json:"confirm"`
	}
	if err := readStrict(w, r, 16<<10, &req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_trust", trustOnlyMessage)
		return
	}
	trust, err := decodeTrust(req.Trust)
	if err != nil {
		apiError(w, http.StatusBadRequest, "invalid_trust", trustOnlyMessage)
		return
	}
	if !req.Confirm {
		apiError(w, http.StatusBadRequest, "unconfirmed", "请先确认公钥文件来自你选定的所有者客户端。")
		return
	}
	switch err := a.server.store.InitializeOwner(trust, store.AuditEntry{
		Actor: actor(s), Action: "owner.bind", Target: trust.NetworkID(), Result: "success",
	}); {
	case errors.Is(err, store.ErrOwnerAlreadySet):
		a.server.audit(actor(s), "owner.bind", trust.NetworkID(), "failure", "已绑定")
		apiError(w, http.StatusConflict, "already_bound", "中心已经绑定所有者，不能通过 Web 更换。")
		return
	case err != nil:
		log.Printf("[web-admin] persist initial owner: %v", err)
		a.server.audit(actor(s), "owner.bind", trust.NetworkID(), "failure", "写入失败")
		apiError(w, http.StatusInternalServerError, "storage", "保存所有者配置失败，请检查中心的存储。中心仍处于待初始化状态。")
		return
	}
	writeJSON(w, http.StatusOK, trustPreview{trust.NetworkID(), trust.PublicKey, trust.MinimumVersion})
}

func shortKey(k string) string {
	k = strings.TrimPrefix(k, "nodekey:")
	if len(k) > 16 {
		return k[:16] + "…"
	}
	return k
}

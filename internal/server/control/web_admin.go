package control

import (
	"bytes"
	"embed"
	"errors"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/acktier/acktier/internal/owner"
	"github.com/acktier/acktier/internal/server/store"
	"github.com/acktier/acktier/pkg/types"
)

const (
	adminURL         = "/admin/"
	adminFormLimit   = 8 << 10
	adminUploadExtra = 16 << 10 // Multipart framing and the CSRF field.
)

//go:embed web/admin.html web/admin.css
var adminAssets embed.FS

var (
	adminTemplate = template.Must(template.ParseFS(adminAssets, "web/admin.html"))
	errAdminCSRF  = errors.New("invalid form token")
)

type webAdmin struct {
	server   *Server
	sessions webSessions
}

func (s *Server) mountWebAdmin(root *http.ServeMux) {
	a := &webAdmin{server: s, sessions: webSessions{live: make(map[string]webSession)}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/{$}", a.home)
	mux.HandleFunc("GET /admin/style.css", a.style)
	mux.HandleFunc("POST /admin/login", a.login)
	mux.HandleFunc("POST /admin/logout", a.requireSession(a.logout))
	mux.HandleFunc("POST /admin/setup", a.requireSession(a.setup))
	mux.HandleFunc("POST /admin/authorization", a.requireSession(a.publish))
	mux.HandleFunc("POST /admin/keys", a.requireSession(a.createKey))
	mux.HandleFunc("POST /admin/keys/{id}/revoke", a.requireSession(a.revokeKey))
	csrf := http.NewCrossOriginProtection().Handler(mux)
	root.Handle(adminURL, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setAdminHeaders(w)
		if !adminTransportOK(r) {
			http.Error(w, "Web management requires HTTPS or local loopback HTTP", http.StatusForbidden)
			return
		}
		csrf.ServeHTTP(w, r)
	}))
	root.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, adminURL, http.StatusFound)
	})
}

func setAdminHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	h.Set("Cache-Control", "no-store")
	h.Set("Vary", "Sec-Fetch-Site, Origin")
}

type adminPage struct {
	Title     string
	Problem   string
	Notice    string
	Login     bool
	Setup     bool
	CSRF      string
	NetworkID string
	Version   uint64
	Expires   string
	Expired   bool
	Requests  []types.OwnerJoinRequest
	Members   []types.PeerNode
	Keys      []adminKeyRow
	NewKey    string
}

func renderAdmin(w http.ResponseWriter, code int, p adminPage) {
	var page bytes.Buffer
	if err := adminTemplate.Execute(&page, p); err != nil {
		log.Printf("[web-admin] render page: %v", err)
		http.Error(w, "could not render dashboard", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_, _ = page.WriteTo(w)
}

func (a *webAdmin) style(w http.ResponseWriter, r *http.Request) {
	css, err := adminAssets.ReadFile("web/admin.css")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write(css)
}

func (a *webAdmin) home(w http.ResponseWriter, r *http.Request) {
	session, ok := a.sessions.get(adminSessionID(r), time.Now())
	if !ok {
		renderAdmin(w, http.StatusOK, a.loginPage(""))
		return
	}
	p := a.page(session)
	switch r.URL.Query().Get("result") {
	case "setup":
		if !p.Setup {
			p.Notice = "已绑定所有者，可以接收入网申请。"
		}
	case "publication":
		if p.Version != 0 {
			p.Notice = "签名授权已验证并发布。"
		}
	case "revoked-key":
		p.Notice = "申请码已吊销。此前签发的节点授权不受影响。"
	}
	renderAdmin(w, http.StatusOK, p)
}

func (a *webAdmin) loginPage(problem string) adminPage {
	return adminPage{Title: "管理登录", Login: true, Setup: a.server.ownerSetupPending(), Problem: problem}
}

func (a *webAdmin) page(session webSession) adminPage {
	p := adminPage{Title: "组网管理", CSRF: session.csrf}
	trust, pinned := a.server.store.OwnerTrust()
	if !pinned {
		p.Title, p.Setup = "首次初始化", true
		return p
	}
	p.NetworkID = trust.NetworkID()
	_, verified, records := a.server.store.OwnerTopology()
	p.Requests = ownerRequests(verified, records)
	p.Members = ownerMembers(verified, records)
	now := time.Now()
	if verified != nil {
		p.Version = verified.Checkpoint.Version
		p.Expires = verified.Snapshot.ExpiresAt.UTC().Format(time.RFC3339)
		p.Expired = !now.Before(verified.Snapshot.ExpiresAt)
	}
	p.Keys = adminKeyRows(a.server.store.ListPreAuthKeys(), now)
	return p
}

func (a *webAdmin) problem(w http.ResponseWriter, session webSession, code int, text string) {
	p := a.page(session)
	p.Problem = text
	renderAdmin(w, code, p)
}

func (a *webAdmin) login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, adminFormLimit)
	if err := r.ParseForm(); err != nil {
		renderAdmin(w, http.StatusBadRequest, a.loginPage("无法读取登录表单，请重试。"))
		return
	}
	if !secretEqual(a.server.cfg.AdminToken, strings.TrimSpace(r.PostForm.Get("adminToken"))) {
		renderAdmin(w, http.StatusUnauthorized, a.loginPage("管理令牌无效。请检查中心的凭据文件。"))
		return
	}

	a.sessions.revoke(adminSessionID(r))
	id, session := a.sessions.create(time.Now())
	c := adminCookie(r)
	c.Value = id
	c.Expires = session.expires
	http.SetCookie(w, &c)
	http.Redirect(w, r, adminURL, http.StatusSeeOther)
}

type adminAction func(http.ResponseWriter, *http.Request, webSession)

func (a *webAdmin) requireSession(next adminAction) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, ok := a.sessions.get(adminSessionID(r), time.Now())
		if !ok {
			renderAdmin(w, http.StatusUnauthorized, a.loginPage("请先登录管理台。"))
			return
		}
		next(w, r, session)
	}
}

func (a *webAdmin) checkForm(w http.ResponseWriter, r *http.Request, session webSession) bool {
	r.Body = http.MaxBytesReader(w, r.Body, adminFormLimit)
	if err := r.ParseForm(); err != nil {
		a.problem(w, session, http.StatusBadRequest, "无法读取表单，请重试。")
		return false
	}
	if !secretEqual(session.csrf, r.PostForm.Get("csrf")) {
		a.problem(w, session, http.StatusForbidden, "表单已失效，请刷新后重试。")
		return false
	}
	return true
}

func (a *webAdmin) logout(w http.ResponseWriter, r *http.Request, session webSession) {
	if !a.checkForm(w, r, session) {
		return
	}
	a.sessions.revoke(adminSessionID(r))
	c := adminCookie(r)
	c.MaxAge = -1
	http.SetCookie(w, &c)
	http.Redirect(w, r, adminURL, http.StatusSeeOther)
}

func adminUpload(w http.ResponseWriter, r *http.Request, session webSession, limit int64, target any) error {
	// The in-memory multipart budget is larger than the whole request. A
	// mistaken upload of a private file is never written to a temp file.
	bodyLimit := limit + adminUploadExtra
	r.Body = http.MaxBytesReader(w, r.Body, bodyLimit)
	if err := r.ParseMultipartForm(bodyLimit); err != nil {
		return err
	}
	defer r.MultipartForm.RemoveAll()
	if !secretEqual(session.csrf, r.PostForm.Get("csrf")) {
		return errAdminCSRF
	}
	if len(r.MultipartForm.File) != 1 || len(r.MultipartForm.File["file"]) != 1 {
		return errors.New("expected one uploaded file")
	}
	f, head, err := r.FormFile("file")
	if err != nil {
		return err
	}
	defer f.Close()
	if head.Size > limit {
		return errors.New("file is too large")
	}
	return owner.DecodeJSON(f, target)
}

func (a *webAdmin) setup(w http.ResponseWriter, r *http.Request, session webSession) {
	var trust owner.Trust
	if err := adminUpload(w, r, session, owner.MaxTrust, &trust); errors.Is(err, errAdminCSRF) {
		a.problem(w, session, http.StatusForbidden, "表单已失效，请刷新后重试。")
		return
	} else if err != nil || trust.Validate() != nil {
		a.problem(w, session, http.StatusBadRequest, "只接受所有者导出的公钥文件 trust.json。不要上传 signer.json。")
		return
	}
	if r.PostForm.Get("confirm") != "yes" {
		a.problem(w, session, http.StatusBadRequest, "请先确认公钥文件来自你选定的客户端。")
		return
	}
	if err := a.server.store.InitializeOwner(trust); errors.Is(err, store.ErrOwnerAlreadySet) {
		a.problem(w, session, http.StatusConflict, "中心已经绑定所有者，不能通过 Web 更换。")
		return
	} else if err != nil {
		log.Printf("[web-admin] persist initial owner: %v", err)
		a.problem(w, session, http.StatusInternalServerError, "保存所有者配置失败，请检查中心的存储。")
		return
	}
	http.Redirect(w, r, adminURL+"?result=setup", http.StatusSeeOther)
}

func (a *webAdmin) publish(w http.ResponseWriter, r *http.Request, session webSession) {
	var env types.OwnerAuthorization
	if err := adminUpload(w, r, session, owner.MaxEnvelope, &env); errors.Is(err, errAdminCSRF) {
		a.problem(w, session, http.StatusForbidden, "表单已失效，请刷新后重试。")
		return
	} else if err != nil {
		a.problem(w, session, http.StatusBadRequest, "上传文件无效或过大。请上传本地签发的 authorization.json。")
		return
	}
	if _, err := a.server.publishOwner(env); err != nil {
		switch {
		case errors.Is(err, store.ErrOwnerNotConfigured):
			a.problem(w, session, http.StatusConflict, "请先绑定所有者。")
		case errors.Is(err, owner.ErrRollback):
			a.problem(w, session, http.StatusConflict, "不能发布旧版本或同一版本的不同授权。")
		case errors.Is(err, store.ErrOwnerInvalid):
			a.problem(w, session, http.StatusBadRequest, "授权无效或已过期。请在当前所有者电脑重新核对并签发。")
		default:
			log.Printf("[web-admin] persist publication: %v", err)
			a.problem(w, session, http.StatusInternalServerError, "保存签名授权失败，请检查中心的存储。")
		}
		return
	}
	http.Redirect(w, r, adminURL+"?result=publication", http.StatusSeeOther)
}

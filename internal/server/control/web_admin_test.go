package control_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/acktier/acktier/internal/owner"
	"github.com/acktier/acktier/internal/server/control"
	"github.com/acktier/acktier/internal/server/store"
	"github.com/acktier/acktier/pkg/types"
)

const webAdminTestToken = "test-admin-token"

type adminBrowser struct {
	t      *testing.T
	h      http.Handler
	cookie *http.Cookie
}

func (b *adminBrowser) newRequest(method, path, contentType string, body []byte) *http.Request {
	r := httptest.NewRequest(method, "https://center.test"+path, bytes.NewReader(body))
	r.Header.Set("Content-Type", contentType)
	if b.cookie != nil {
		r.AddCookie(b.cookie)
	}
	return r
}

func (b *adminBrowser) serve(r *http.Request, want int) *httptest.ResponseRecorder {
	b.t.Helper()
	w := httptest.NewRecorder()
	b.h.ServeHTTP(w, r)
	if w.Code != want {
		b.t.Fatalf("%s %s: got %d, want %d\n%s", r.Method, r.URL.Path, w.Code, want, w.Body.String())
	}
	return w
}

func (b *adminBrowser) request(method, path, contentType string, body []byte, want int) *httptest.ResponseRecorder {
	b.t.Helper()
	return b.serve(b.newRequest(method, path, contentType, body), want)
}

func (b *adminBrowser) form(path string, values url.Values, want int) *httptest.ResponseRecorder {
	b.t.Helper()
	return b.request(http.MethodPost, path, "application/x-www-form-urlencoded", []byte(values.Encode()), want)
}

func (b *adminBrowser) newUpload(path, csrf string, raw []byte, confirm bool) *http.Request {
	b.t.Helper()
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	if err := form.WriteField("csrf", csrf); err != nil {
		b.t.Fatal(err)
	}
	if confirm {
		if err := form.WriteField("confirm", "yes"); err != nil {
			b.t.Fatal(err)
		}
	}
	file, err := form.CreateFormFile("file", "document.json")
	if err != nil {
		b.t.Fatal(err)
	}
	if _, err := file.Write(raw); err != nil {
		b.t.Fatal(err)
	}
	if err := form.Close(); err != nil {
		b.t.Fatal(err)
	}
	return b.newRequest(http.MethodPost, path, form.FormDataContentType(), body.Bytes())
}

func (b *adminBrowser) upload(path, csrf string, doc any, want int) {
	b.t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		b.t.Fatal(err)
	}
	b.serve(b.newUpload(path, csrf, raw, true), want)
}

var adminCSRFPattern = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (b *adminBrowser) csrf() string {
	b.t.Helper()
	page := b.request(http.MethodGet, "/admin/", "", nil, http.StatusOK)
	match := adminCSRFPattern.FindStringSubmatch(page.Body.String())
	if len(match) != 2 {
		b.t.Fatal("authenticated page did not include a form token")
	}
	return match[1]
}

func (b *adminBrowser) login() {
	b.t.Helper()
	w := b.form("/admin/login", url.Values{"adminToken": {webAdminTestToken}}, http.StatusSeeOther)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly ||
		cookies[0].SameSite != http.SameSiteLaxMode || cookies[0].Name != "__Host-acktier-admin" ||
		cookies[0].Path != "/" || cookies[0].Value == webAdminTestToken {
		b.t.Fatal("expected a secure, host-only session cookie, not the admin token")
	}
	b.cookie = cookies[0]
}

func TestWebAdminFirstSetupAndSignedPublication(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "center.json")
	st, err := store.NewFileStore(statePath)
	if err != nil {
		t.Fatal(err)
	}
	h := control.NewServer(control.Config{AdminToken: webAdminTestToken, RequireOwner: true}, st).Handler()
	b := &adminBrowser{t: t, h: h}

	if w := b.request(http.MethodGet, "/", "", nil, http.StatusFound); w.Header().Get("Location") != "/admin/" {
		t.Fatalf("unexpected setup redirect: %s", w.Header().Get("Location"))
	}
	page := b.request(http.MethodGet, "/admin/", "", nil, http.StatusOK)
	if html := page.Body.String(); !strings.Contains(html, "等待初始化") || strings.Contains(html, `action="/admin/setup"`) {
		t.Fatal("first run must offer login without exposing the setup form")
	}
	if page.Header().Get("Cache-Control") != "no-store" ||
		!strings.Contains(page.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatal("management pages are missing required security headers")
	}
	if w := b.request(http.MethodGet, "/admin/style.css", "", nil, http.StatusOK); !strings.HasPrefix(w.Header().Get("Content-Type"), "text/css") {
		t.Fatal("the embedded stylesheet is not served as CSS")
	}

	for _, endpoint := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/node/register"},
		{http.MethodPost, "/api/v1/node/heartbeat"},
		{http.MethodGet, "/api/v1/node/map/stream"},
		{http.MethodGet, "/relay"},
	} {
		b.request(endpoint.method, endpoint.path, "", nil, http.StatusServiceUnavailable)
	}
	bearerOnly := b.newRequest(http.MethodPost, "/admin/setup", "", nil)
	bearerOnly.Header.Set("Authorization", "Bearer "+webAdminTestToken)
	b.serve(bearerOnly, http.StatusUnauthorized)
	b.form("/admin/login", url.Values{"adminToken": {"wrong-token"}}, http.StatusUnauthorized)
	b.login()
	csrf := b.csrf()
	b.request(http.MethodGet, "/api/v1/admin/nodes", "", nil, http.StatusUnauthorized)

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	trust := owner.NewTrust(pub, 1)
	raw, err := json.Marshal(trust)
	if err != nil {
		t.Fatal(err)
	}
	b.upload("/admin/setup", "", trust, http.StatusForbidden)
	b.serve(b.newUpload("/admin/setup", csrf, raw, false), http.StatusBadRequest)
	b.serve(b.newUpload("/admin/setup", csrf, append(bytes.Repeat([]byte(" "), owner.MaxTrust), raw...), true), http.StatusBadRequest)
	b.upload("/admin/setup", csrf, map[string]any{"seed": priv.Seed(), "lastVersion": 0}, http.StatusBadRequest)
	if _, ok := st.OwnerTrust(); ok {
		t.Fatal("invalid forms changed the owner")
	}
	b.upload("/admin/setup", csrf, trust, http.StatusSeeOther)
	b.upload("/admin/setup", csrf, owner.NewTrust(pub, 2), http.StatusConflict)
	reopened, err := store.NewFileStore(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if got, pinned := reopened.OwnerTrust(); !pinned || got != trust {
		t.Fatalf("owner binding was not persisted unchanged: %+v", got)
	}

	reg := types.RegisterRequest{
		OwnerNetworkID: trust.NetworkID(),
		NodeKey:        types.PublicKey{1}, MachineKey: types.PublicKey{2},
		Hostname: "<laptop>",
	}
	keyPage := b.form("/admin/keys", url.Values{"csrf": {csrf}, "label": {"new laptop"}}, http.StatusCreated)
	keys := st.ListPreAuthKeys()
	if len(keys) != 1 || keys[0].Reusable || !strings.Contains(keyPage.Body.String(), keys[0].Key) {
		t.Fatal("Web management must issue and display a single-use application key")
	}
	reg.AuthKey = keys[0].Key
	legacy := reg
	legacy.OwnerNetworkID = ""
	body, _ := json.Marshal(legacy)
	b.request(http.MethodPost, "/api/v1/node/register", "application/json", body, http.StatusForbidden)
	body, _ = json.Marshal(reg)
	pending := b.request(http.MethodPost, "/api/v1/node/register", "application/json", body, http.StatusOK)
	var registration types.RegisterResponse
	if err := json.Unmarshal(pending.Body.Bytes(), &registration); err != nil {
		t.Fatal(err)
	}
	if registration.NetMap.OwnerAuthorization != nil || registration.NetMap.Self.IPv4.IsValid() {
		t.Fatal("an application key alone granted membership")
	}
	page = b.request(http.MethodGet, "/admin/", "", nil, http.StatusOK)
	if html := page.Body.String(); !strings.Contains(html, "&lt;laptop&gt;") ||
		!strings.Contains(html, reg.NodeKey.String()) || strings.Contains(html, reg.AuthKey) {
		t.Fatal("dashboard did not show the pending request safely")
	}

	b.upload("/admin/authorization", csrf, types.OwnerAuthorization{}, http.StatusBadRequest)
	now := time.Now()
	snapshot := owner.Snapshot{
		Version: 2, ExpiresAt: now.Add(time.Hour),
		Members:      []owner.Member{{ID: 7, NodeKey: reg.NodeKey, Name: "approved-laptop", IPv4: netip.MustParseAddr("100.64.0.30")}},
		PacketFilter: []types.FilterRule{owner.DenyAll()},
	}
	env, err := owner.Sign(snapshot, priv, now)
	if err != nil {
		t.Fatal(err)
	}
	env.Signature[0] ^= 1
	b.upload("/admin/authorization", csrf, env, http.StatusBadRequest)
	env.Signature[0] ^= 1
	b.upload("/admin/authorization", csrf, env, http.StatusSeeOther)
	page = b.request(http.MethodGet, "/admin/", "", nil, http.StatusOK)
	if html := page.Body.String(); !strings.Contains(html, "approved-laptop") || !strings.Contains(html, "100.64.0.30") ||
		!strings.Contains(html, "v2") || strings.Contains(html, "&lt;laptop&gt;") {
		t.Fatal("dashboard did not show the signed identity after publication")
	}
	snapshot.Version--
	old, err := owner.Sign(snapshot, priv, now)
	if err != nil {
		t.Fatal(err)
	}
	b.upload("/admin/authorization", csrf, old, http.StatusConflict)
	b.form("/admin/keys", url.Values{"csrf": {csrf}, "label": {"unused"}}, http.StatusCreated)
	var unused types.PreAuthKey
	for _, key := range st.ListPreAuthKeys() {
		if key.Label == "unused" {
			unused = key
			break
		}
	}
	if unused.ID == "" {
		t.Fatal("new application key was not saved")
	}
	b.form("/admin/keys/"+unused.ID+"/revoke", url.Values{"csrf": {csrf}}, http.StatusSeeOther)
	reg.NodeKey, reg.MachineKey, reg.AuthKey = types.PublicKey{3}, types.PublicKey{4}, unused.Key
	body, _ = json.Marshal(reg)
	b.request(http.MethodPost, "/api/v1/node/register", "application/json", body, http.StatusUnauthorized)
	b.form("/admin/logout", url.Values{"csrf": {csrf}}, http.StatusSeeOther)
	b.form("/admin/keys", url.Values{"csrf": {csrf}, "label": {"old session"}}, http.StatusUnauthorized)
}

func TestWebAdminConcurrentSetupPinsOnlyOneOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "center.json")
	st, err := store.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	h := control.NewServer(control.Config{AdminToken: webAdminTestToken, RequireOwner: true}, st).Handler()

	type result struct {
		trust owner.Trust
		code  int
	}
	var requests [2]*http.Request
	var trusts [len(requests)]owner.Trust
	for i := range requests {
		b := &adminBrowser{t: t, h: h}
		b.login()
		pub, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		trusts[i] = owner.NewTrust(pub, 1)
		raw, err := json.Marshal(trusts[i])
		if err != nil {
			t.Fatal(err)
		}
		requests[i] = b.newUpload("/admin/setup", b.csrf(), raw, true)
	}
	start := make(chan struct{})
	results := make(chan result, len(requests))
	for i, r := range requests {
		go func() {
			<-start
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			results <- result{trusts[i], w.Code}
		}()
	}
	close(start)
	first, second := <-results, <-results
	if first.code != http.StatusSeeOther {
		first, second = second, first
	}
	if first.code != http.StatusSeeOther || second.code != http.StatusConflict {
		t.Fatalf("expected one successful setup and one conflict, got %d and %d", first.code, second.code)
	}
	reopened, err := store.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, pinned := reopened.OwnerTrust(); !pinned || got != first.trust {
		t.Fatal("the successful request was not the persisted owner")
	}
}

func TestWebAdminFailedSetupKeepsAdmissionPaused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "center.json")
	st, err := store.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	// A directory at the file path causes the atomic rename to fail.
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	h := control.NewServer(control.Config{AdminToken: webAdminTestToken, RequireOwner: true}, st).Handler()
	b := &adminBrowser{t: t, h: h}
	b.login()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	trust, csrf := owner.NewTrust(pub, 1), b.csrf()
	b.upload("/admin/setup", csrf, trust, http.StatusInternalServerError)
	b.request(http.MethodPost, "/api/v1/node/register", "", nil, http.StatusServiceUnavailable)
	if _, pinned := st.OwnerTrust(); pinned {
		t.Fatal("failed write exposed an in-memory owner binding")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	b.upload("/admin/setup", csrf, trust, http.StatusSeeOther)
}

func TestWebAdminRejectsCrossOriginAndRemotePlainHTTP(t *testing.T) {
	st, err := store.NewFileStore("")
	if err != nil {
		t.Fatal(err)
	}
	h := control.NewServer(control.Config{RequireOwner: true, AdminToken: webAdminTestToken}, st).Handler()
	form := url.Values{"adminToken": {webAdminTestToken}}.Encode()
	r := httptest.NewRequest(http.MethodPost, "https://center.test/admin/login", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://other.test")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("cross-origin login created an admin session")
	}

	for _, tc := range []struct {
		addr string
		host string
		want int
	}{
		{"192.0.2.4:12345", "127.0.0.1:8080", http.StatusForbidden},
		{"127.0.0.1:12345", "center.test", http.StatusForbidden},
		{"127.0.0.1:12345", "127.0.0.1:8080", http.StatusOK},
	} {
		r := httptest.NewRequest(http.MethodGet, "http://"+tc.host+"/admin/", nil)
		r.RemoteAddr = tc.addr
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Errorf("admin transport %s to %s: got %d, want %d", tc.addr, tc.host, w.Code, tc.want)
		}
	}
}

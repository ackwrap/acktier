package control_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/acktier/acktier/internal/owner"
	"github.com/acktier/acktier/internal/server/control"
	"github.com/acktier/acktier/internal/server/store"
	"github.com/acktier/acktier/pkg/client"
	"github.com/acktier/acktier/pkg/types"
)

const testWebAdminPassword = "correct-horse-admin-pw"

type adminSessionClient struct {
	t      *testing.T
	h      http.Handler
	cookie *http.Cookie
	csrf   string
}

func (c *adminSessionClient) newRequest(method, path string, body []byte, withCSRF bool) *http.Request {
	c.t.Helper()
	r := httptest.NewRequest(method, "https://center.test"+path, bytes.NewReader(body))
	if len(body) > 0 {
		r.Header.Set("Content-Type", "application/json")
	}
	if c.cookie != nil {
		r.AddCookie(c.cookie)
	}
	if withCSRF && c.csrf != "" {
		r.Header.Set("X-CSRF-Token", c.csrf)
	}
	return r
}

func (c *adminSessionClient) doJSON(method, path string, reqBody any, wantStatus int, respOut any) *httptest.ResponseRecorder {
	c.t.Helper()
	var raw []byte
	if reqBody != nil {
		var err error
		raw, err = json.Marshal(reqBody)
		if err != nil {
			c.t.Fatal(err)
		}
	}
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, c.newRequest(method, path, raw, method != http.MethodGet))
	if w.Code != wantStatus {
		c.t.Fatalf("%s %s: got %d, want %d\nbody: %s", method, path, w.Code, wantStatus, w.Body.String())
	}
	if respOut != nil {
		if err := json.Unmarshal(w.Body.Bytes(), respOut); err != nil {
			c.t.Fatalf("decode %s %s: %v\nbody: %s", method, path, err, w.Body.String())
		}
	}
	return w
}

func (c *adminSessionClient) login(password string, wantStatus int) *httptest.ResponseRecorder {
	c.t.Helper()
	var out struct {
		Authenticated bool   `json:"authenticated"`
		SetupPending  bool   `json:"setupPending"`
		CSRF          string `json:"csrf"`
	}
	raw, _ := json.Marshal(map[string]string{"password": password})
	r := httptest.NewRequest(http.MethodPost, "https://center.test/admin/api/login", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, r)
	if w.Code != wantStatus {
		c.t.Fatalf("login: got %d, want %d\n%s", w.Code, wantStatus, w.Body.String())
	}
	if wantStatus == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			c.t.Fatal(err)
		}
		cookies := w.Result().Cookies()
		if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly ||
			cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Name != "__Host-acktier-admin" ||
			cookies[0].Value == password || out.CSRF == "" {
			c.t.Fatalf("unexpected session cookie or CSRF: cookies=%+v csrf=%q", cookies, out.CSRF)
		}
		c.cookie = cookies[0]
		c.csrf = out.CSRF
	}
	return w
}

type handlerTransport struct {
	h     http.Handler
	https bool
}

func (ht *handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	if ht.https {
		clone.URL.Scheme = "https"
		clone.TLS = &tls.ConnectionState{}
	} else {
		clone.RemoteAddr = "127.0.0.1:44444"
	}
	rec := httptest.NewRecorder()
	ht.h.ServeHTTP(rec, clone)
	return rec.Result(), nil
}

func TestWebAdminIsolationPasswordSetupInventoryAndDraftWorkflow(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "center", "state.sqlite")
	st, err := store.NewFileStore(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := control.NewServer(control.Config{AdminToken: "legacy-token-not-accepted", RequireOwner: true}, st)
	nodeH := srv.Handler()
	adminH := srv.AdminHandler()

	// 1. Default isolation: node listener MUST NOT serve /admin/ or /api/v1/admin/* (returns 404).
	for _, p := range []string{"/admin/", "/admin/api/session", "/api/v1/admin/status", "/api/v1/admin/nodes", "/api/v1/admin/owner/requests"} {
		r := httptest.NewRequest(http.MethodGet, "https://node.test"+p, nil)
		r.Header.Set("Authorization", "Bearer legacy-token-not-accepted")
		w := httptest.NewRecorder()
		nodeH.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Fatalf("node listener exposed %s: got %d, want 404", p, w.Code)
		}
	}

	// 2. SPA assets and security headers on AdminHandler.
	cli := &adminSessionClient{t: t, h: adminH}
	if w := cli.doJSON(http.MethodGet, "/", nil, http.StatusFound, nil); w.Header().Get("Location") != "/admin/" {
		t.Fatalf("expected / -> /admin/, got %s", w.Header().Get("Location"))
	}
	indexW := cli.doJSON(http.MethodGet, "/admin/", nil, http.StatusOK, nil)
	if csp := indexW.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") ||
		!strings.Contains(csp, "style-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") ||
		indexW.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("missing strict CSP or Cache-Control headers: csp=%q", csp)
	}
	for _, asset := range []string{"/admin/assets/icons.css", "/admin/assets/base.css", "/admin/assets/components.css", "/admin/assets/app.js"} {
		cli.doJSON(http.MethodGet, asset, nil, http.StatusOK, nil)
	}

	// 3. Password checks: no password -> 503; set Argon2id password -> wrong password -> 401; login -> 200.
	cli.login(testWebAdminPassword, http.StatusServiceUnavailable)
	if err := st.SetAdminPassword("short"); err == nil {
		t.Fatal("accepted weak <12 char password")
	}
	if err := st.SetAdminPassword(testWebAdminPassword); err != nil {
		t.Fatal(err)
	}
	cli.login("wrong-password-attempt", http.StatusUnauthorized)
	cli.login(testWebAdminPassword, http.StatusOK)

	// Missing CSRF header on state-changing call must be rejected (403).
	noCSRF := cli.newRequest(http.MethodPost, "/admin/api/logout", nil, false)
	wNoCSRF := httptest.NewRecorder()
	adminH.ServeHTTP(wNoCSRF, noCSRF)
	if wNoCSRF.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF header should fail with 403, got %d", wNoCSRF.Code)
	}

	// Local host password reset invalidates existing Web sessions immediately!
	time.Sleep(5 * time.Millisecond)
	const rotatedPw = "rotated-admin-password-99"
	if err := st.SetAdminPassword(rotatedPw); err != nil {
		t.Fatal(err)
	}
	cli.doJSON(http.MethodPost, "/admin/api/logout", nil, http.StatusUnauthorized, nil)
	cli.login(rotatedPw, http.StatusOK)

	// 4. Node endpoints are paused (503) before owner binding.
	for _, ep := range []struct{ m, p string }{
		{http.MethodPost, "/api/v1/node/register"},
		{http.MethodPost, "/api/v1/node/heartbeat"},
		{http.MethodGet, "/api/v1/node/map/stream"},
		{http.MethodGet, "/relay"},
	} {
		r := httptest.NewRequest(ep.m, "https://node.test"+ep.p, nil)
		w := httptest.NewRecorder()
		nodeH.ServeHTTP(w, r)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s %s before owner setup: got %d, want 503", ep.m, ep.p, w.Code)
		}
	}

	// 5. Setup preview & owner binding (rejects signer.json, requires confirm=true, allows only once).
	ownerPub, ownerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	trust := owner.NewTrust(ownerPub, 1)
	cli.doJSON(http.MethodPost, "/admin/api/setup/preview", map[string]any{"seed": ownerPriv.Seed(), "lastVersion": 0}, http.StatusBadRequest, nil)
	var preview struct {
		NetworkID string `json:"networkId"`
		PublicKey string `json:"publicKey"`
	}
	cli.doJSON(http.MethodPost, "/admin/api/setup/preview", trust, http.StatusOK, &preview)
	if preview.NetworkID != trust.NetworkID() || preview.PublicKey != trust.PublicKey {
		t.Fatalf("unexpected trust preview: %+v", preview)
	}
	cli.doJSON(http.MethodPost, "/admin/api/setup", map[string]any{"trust": trust, "confirm": false}, http.StatusBadRequest, nil)
	cli.doJSON(http.MethodPost, "/admin/api/setup", map[string]any{"trust": trust, "confirm": true}, http.StatusOK, nil)
	cli.doJSON(http.MethodPost, "/admin/api/setup", map[string]any{"trust": owner.NewTrust(ownerPub, 2), "confirm": true}, http.StatusConflict, nil)

	// 6. Issue single-use key via Web API, register node with >=2 transports, verify heartbeat updates & manual inventory isolation.
	var createdKey struct {
		Key string `json:"key"`
		Row struct {
			ID string `json:"id"`
		} `json:"row"`
	}
	cli.doJSON(http.MethodPost, "/admin/api/keys", map[string]any{"label": "nas-enroll", "ttlHours": 12}, http.StatusCreated, &createdKey)
	if createdKey.Key == "" {
		t.Fatal("expected one-time key plaintext on creation")
	}

	nodeKeyA := types.PublicKey{11}
	regBody, _ := json.Marshal(types.RegisterRequest{
		OwnerNetworkID:   trust.NetworkID(),
		MachineKey:       types.PublicKey{12},
		NodeKey:          nodeKeyA,
		AuthKey:          createdKey.Key,
		Hostname:         "<nas-box>",
		OS:               "linux",
		TransportPorts:   types.TransportPorts{types.ProtoUDP: 51820, types.ProtoQUIC: 51821},
		Endpoints:        []types.Endpoint{{Proto: types.ProtoUDP, Addr: "198.51.100.10:51820"}, {Proto: types.ProtoQUIC, Addr: "198.51.100.10:51821"}},
		AdvertisedRoutes: []netip.Prefix{netip.MustParsePrefix("192.168.88.0/24")},
	})
	regRec := httptest.NewRecorder()
	nodeH.ServeHTTP(regRec, httptest.NewRequest(http.MethodPost, "https://node.test/api/v1/node/register", bytes.NewReader(regBody)))
	if regRec.Code != http.StatusOK {
		t.Fatalf("node register failed: %d %s", regRec.Code, regRec.Body.String())
	}
	var regResp types.RegisterResponse
	_ = json.Unmarshal(regRec.Body.Bytes(), &regResp)

	// Heartbeat updates TransportPorts
	hbBody, _ := json.Marshal(types.HeartbeatRequest{
		OwnerNetworkID: trust.NetworkID(),
		NodeKey:        nodeKeyA,
		TransportPorts: types.TransportPorts{types.ProtoUDP: 51820, types.ProtoQUIC: 51821, types.ProtoWSS: 8443},
		Endpoints:      []types.Endpoint{{Proto: types.ProtoUDP, Addr: "198.51.100.10:51820"}, {Proto: types.ProtoWSS, Addr: "198.51.100.10:8443"}},
	})
	hbReq := httptest.NewRequest(http.MethodPost, "https://node.test/api/v1/node/heartbeat", bytes.NewReader(hbBody))
	hbReq.Header.Set("Authorization", "Bearer "+regResp.NodeToken)
	hbRec := httptest.NewRecorder()
	nodeH.ServeHTTP(hbRec, hbReq)
	if hbRec.Code != http.StatusOK {
		t.Fatalf("heartbeat failed: %d %s", hbRec.Code, hbRec.Body.String())
	}

	// Import manual inventory (reject invalid data, accept valid data, confirm reported vs manual remain distinct).
	cli.doJSON(http.MethodPut, "/admin/api/nodes/"+nodeKeyA.String()+"/inventory", map[string]any{
		"transports": []map[string]any{{"proto": "invalid", "port": 80}},
	}, http.StatusBadRequest, nil)
	cli.doJSON(http.MethodPut, "/admin/api/nodes/"+nodeKeyA.String()+"/inventory", map[string]any{
		"transports": []map[string]any{{"proto": "wss", "port": 443}},
		"endpoints":  []map[string]any{{"proto": "wss", "addr": "203.0.113.99:443"}},
		"routes":     []string{"10.10.0.0/16"},
		"note":       "ops-sheet",
	}, http.StatusOK, nil)

	var detail struct {
		Reported struct {
			TransportPorts map[string]uint16 `json:"transportPorts"`
		} `json:"reported"`
		Inventory struct {
			Note string `json:"note"`
		} `json:"inventory"`
	}
	cli.doJSON(http.MethodGet, "/admin/api/nodes/"+nodeKeyA.String(), nil, http.StatusOK, &detail)
	if detail.Reported.TransportPorts["wss"] != 8443 || detail.Inventory.Note != "ops-sheet" {
		t.Fatalf("node detail did not preserve separate reported vs manual inventory: %+v", detail)
	}

	// 7. Draft creation, member addition, ACL-only upload (preserving members/DNS), validation, export, preview & publish!
	var draftCreated struct {
		Draft store.Draft `json:"draft"`
	}
	cli.doJSON(http.MethodPost, "/admin/api/drafts", map[string]any{"name": "initial-rollout", "fromActive": true}, http.StatusCreated, &draftCreated)
	did := draftCreated.Draft.ID

	cli.doJSON(http.MethodPost, "/admin/api/drafts/"+did+"/members", map[string]any{
		"nodeKey": nodeKeyA.String(),
		"name":    "nas",
		"ipv4":    "100.64.0.10",
		"tags":    []string{"tag:storage"},
		"routes":  []string{"192.168.88.0/24"},
	}, http.StatusOK, nil)

	// Reject untrusted hostname selector and transport-layer proto="quic" in ACL upload!
	cli.doJSON(http.MethodPost, "/admin/api/drafts/"+did+"/acl", types.ACLPolicy{
		ACLs: []types.ACLGrantEntry{{Action: "accept", Proto: "tcp", Src: []string{"nas"}, Dst: []string{"nas:443"}}},
	}, http.StatusBadRequest, nil)
	cli.doJSON(http.MethodPost, "/admin/api/drafts/"+did+"/acl", types.ACLPolicy{
		ACLs: []types.ACLGrantEntry{{Action: "accept", Proto: "quic", Src: []string{"*"}, Dst: []string{"*:443"}}},
	}, http.StatusBadRequest, nil)

	// Valid ACL-only upload MUST NOT wipe members, DNS, or approved routes!
	var afterACL struct {
		Draft store.Draft `json:"draft"`
	}
	cli.doJSON(http.MethodPost, "/admin/api/drafts/"+did+"/acl", types.ACLPolicy{
		ACLs: []types.ACLGrantEntry{{Action: "accept", Proto: "tcp", Src: []string{"node:1"}, Dst: []string{"tag:storage:443"}}},
	}, http.StatusOK, &afterACL)
	if len(afterACL.Draft.Policy.Members) != 1 || len(afterACL.Draft.Policy.Members[0].Routes) != 1 || !afterACL.Draft.Policy.DNS.EnableMagicDNS {
		t.Fatalf("ACL-only upload wiped draft members, routes, or DNS: %+v", afterACL.Draft.Policy)
	}

	expW := cli.doJSON(http.MethodGet, "/admin/api/drafts/"+did+"/export", nil, http.StatusOK, nil)
	var exported owner.Policy
	if err := owner.DecodeJSON(bytes.NewReader(expW.Body.Bytes()), &exported); err != nil {
		t.Fatalf("exported policy.json invalid: %v", err)
	}

	// Sign offline with owner key, preview, and publish!
	snap, err := exported.Snapshot(1, time.Now().UTC().Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	signedEnv, err := owner.Sign(snap, ownerPriv, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	var prevOK struct {
		Valid bool `json:"valid"`
	}
	cli.doJSON(http.MethodPost, "/admin/api/authorization/preview", signedEnv, http.StatusOK, &prevOK)
	if !prevOK.Valid {
		t.Fatal("expected valid authorization preview")
	}
	cli.doJSON(http.MethodPost, "/admin/api/authorization", signedEnv, http.StatusOK, nil)
	// Idempotent re-submission of identical signed envelope succeeds:
	var idem struct {
		Idempotent bool `json:"idempotent"`
	}
	cli.doJSON(http.MethodPost, "/admin/api/authorization", signedEnv, http.StatusOK, &idem)
	if !idem.Idempotent {
		t.Fatal("expected identical re-upload to report idempotent=true")
	}

	// Ensure audit never leaked password or PreAuthKey plaintext!
	auditW := cli.doJSON(http.MethodGet, "/admin/api/audit", nil, http.StatusOK, nil)
	if body := auditW.Body.String(); strings.Contains(body, rotatedPw) || strings.Contains(body, createdKey.Key) || strings.Contains(body, cli.cookie.Value) {
		t.Fatal("audit log leaked sensitive credential or session secret")
	}
}

func TestControllerDelegationPrivilegeSeparation(t *testing.T) {
	st, err := store.NewFileStore("")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetAdminPassword(testWebAdminPassword); err != nil {
		t.Fatal(err)
	}
	ownerPub, ownerPriv, _ := ed25519.GenerateKey(nil)
	trust := owner.NewTrust(ownerPub, 1)
	if err := st.InitializeOwner(trust); err != nil {
		t.Fatal(err)
	}

	srv := control.NewServer(control.Config{RequireOwner: true}, st)
	adminH := srv.AdminHandler()
	webCli := &adminSessionClient{t: t, h: adminH}
	webCli.login(testWebAdminPassword, http.StatusOK)

	_, ctlPriv, _ := ed25519.GenerateKey(nil)
	httpCli := &http.Client{Transport: &handlerTransport{h: adminH, https: true}}
	ctl := client.NewControllerClient("https://center.test", trust.NetworkID(), ctlPriv, httpCli)
	ctx := context.Background()

	// 1. Before enabling delegation, controller requests are rejected (403).
	if _, err := ctl.OwnerJoinRequests(ctx); err == nil {
		t.Fatal("controller API succeeded while delegation was disabled")
	}

	// 2. Reusing the owner's policy-signing key as controller key MUST be rejected!
	if _, err := owner.NewControllerTrust(trust, ownerPriv, "bad"); err == nil {
		t.Fatal("allowed owner policy-signing key to be reused as controller API key")
	}

	// 3. Enable delegation with dedicated controller key + private-key possession proof.
	ct, err := owner.NewControllerTrust(trust, ctlPriv, "ops-laptop")
	if err != nil {
		t.Fatal(err)
	}
	webCli.doJSON(http.MethodPut, "/admin/api/delegation", ct, http.StatusOK, nil)

	// 4. Web cookies, bearer passwords, node tokens, and PreAuthKeys MUST all fail on /api/v1/admin/* (401)!
	for _, hdr := range []string{
		"Bearer " + testWebAdminPassword,
		"Bearer ntok_fake123456",
		"Bearer ackkey-fake123456",
	} {
		r := httptest.NewRequest(http.MethodGet, "https://center.test/api/v1/admin/owner/requests", nil)
		r.Header.Set("Authorization", hdr)
		r.AddCookie(webCli.cookie)
		w := httptest.NewRecorder()
		adminH.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("credential %q was not rejected on controller API: got %d", hdr, w.Code)
		}
	}

	// 5. Delegated controller succeeds with fresh signed challenge, and challenge replay is rejected!
	if _, err := ctl.OwnerJoinRequests(ctx); err != nil {
		t.Fatalf("delegated controller request failed: %v", err)
	}
	pak, err := ctl.CreateKey(ctx, "from-controller", false, 6)
	if err != nil || pak.Key == "" {
		t.Fatalf("delegated controller CreateKey failed: %v", err)
	}
	if remaining := time.Until(pak.ExpiresAt); remaining < 5*time.Hour || remaining > 6*time.Hour {
		t.Fatalf("delegated enrollment key did not use requested six-hour TTL: %v", remaining)
	}
	keys, err := ctl.ListPreAuthKeys(ctx)
	if err != nil || len(keys) != 1 || keys[0].ID != pak.ID || keys[0].Key != "" {
		t.Fatalf("delegated API did not return metadata without plaintext: count=%d err=%v", len(keys), err)
	}

	// Replay check: capture one challenge and submit the exact signed request twice concurrently/sequentially.
	var ch owner.AdminChallenge
	chRec := httptest.NewRecorder()
	adminH.ServeHTTP(chRec, httptest.NewRequest(http.MethodGet, "https://center.test"+owner.AdminChallengePath, nil))
	_ = json.Unmarshal(chRec.Body.Bytes(), &ch)
	proofHdr, err := owner.FormatAdminProof(ctlPriv, trust.NetworkID(), ch.Challenge, http.MethodGet, "/api/v1/admin/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	sendSigned := func() int {
		r := httptest.NewRequest(http.MethodGet, "https://center.test/api/v1/admin/status", nil)
		r.Header.Set("Authorization", proofHdr)
		w := httptest.NewRecorder()
		adminH.ServeHTTP(w, r)
		return w.Code
	}
	if c1, c2 := sendSigned(), sendSigned(); c1 != http.StatusOK || c2 != http.StatusUnauthorized {
		t.Fatalf("challenge replay check failed: first=%d second=%d", c1, c2)
	}

	// 6. Disabling delegation revokes controller access immediately without disturbing published state!
	webCli.doJSON(http.MethodDelete, "/admin/api/delegation", nil, http.StatusOK, nil)
	if _, err := ctl.OwnerJoinRequests(ctx); err == nil {
		t.Fatal("controller API still succeeded after delegation was disabled")
	}
}

func TestWebAdminConcurrentSetupAndRemotePlainHTTPBlocked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "center", "state.sqlite")
	st, err := store.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_ = st.SetAdminPassword(testWebAdminPassword)
	h := control.NewServer(control.Config{RequireOwner: true}, st).AdminHandler()

	// Cross-origin login blocked
	rawLogin, _ := json.Marshal(map[string]string{"password": testWebAdminPassword})
	cross := httptest.NewRequest(http.MethodPost, "https://center.test/admin/api/login", bytes.NewReader(rawLogin))
	cross.Header.Set("Content-Type", "application/json")
	cross.Header.Set("Origin", "https://evil.example")
	cross.Header.Set("Sec-Fetch-Site", "cross-site")
	cw := httptest.NewRecorder()
	h.ServeHTTP(cw, cross)
	if cw.Code != http.StatusForbidden || cw.Header().Get("Set-Cookie") != "" {
		t.Fatalf("cross-origin login not blocked: code=%d", cw.Code)
	}

	// Non-loopback plain HTTP blocked
	for _, tc := range []struct {
		addr, host string
		want       int
	}{
		{"192.0.2.4:12345", "127.0.0.1:8081", http.StatusForbidden},
		{"127.0.0.1:12345", "center.test:8081", http.StatusForbidden},
		{"127.0.0.1:12345", "127.0.0.1:8081", http.StatusOK},
	} {
		r := httptest.NewRequest(http.MethodGet, "http://"+tc.host+"/admin/", nil)
		r.RemoteAddr = tc.addr
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Errorf("plain HTTP %s -> %s: got %d, want %d", tc.addr, tc.host, w.Code, tc.want)
		}
	}

	// Concurrent first-run setup pins exactly one owner
	type res struct {
		trust owner.Trust
		code  int
	}
	var reqs [2]*http.Request
	var trusts [2]owner.Trust
	for i := range reqs {
		c := &adminSessionClient{t: t, h: h}
		c.login(testWebAdminPassword, http.StatusOK)
		pub, _, _ := ed25519.GenerateKey(nil)
		trusts[i] = owner.NewTrust(pub, 1)
		body, _ := json.Marshal(map[string]any{"trust": trusts[i], "confirm": true})
		reqs[i] = c.newRequest(http.MethodPost, "/admin/api/setup", body, true)
	}
	start := make(chan struct{})
	out := make(chan res, 2)
	for i, r := range reqs {
		go func() {
			<-start
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			out <- res{trusts[i], w.Code}
		}()
	}
	close(start)
	a, b := <-out, <-out
	if a.code != http.StatusOK {
		a, b = b, a
	}
	if a.code != http.StatusOK || b.code != http.StatusConflict {
		t.Fatalf("concurrent setup expected 200 and 409, got %d and %d", a.code, b.code)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got, ok := reopened.OwnerTrust(); !ok || got != a.trust {
		t.Fatalf("persisted owner mismatch: %+v", got)
	}
}

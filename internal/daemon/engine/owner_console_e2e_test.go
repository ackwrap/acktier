package engine_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ackwrap/acktier/internal/daemon/engine"
	"github.com/ackwrap/acktier/internal/daemon/pktutil"
	"github.com/ackwrap/acktier/internal/daemon/state"
	"github.com/ackwrap/acktier/internal/daemon/tun"
	"github.com/ackwrap/acktier/internal/owner"
	"github.com/ackwrap/acktier/internal/server/control"
	"github.com/ackwrap/acktier/internal/server/store"
	"github.com/ackwrap/acktier/pkg/types"
)

// TestConsoleDraftSignPublishAndLiveACL exercises the complete production separation:
// Web admin session on AdminHandler -> Setup -> PreAuthKey -> 2 memory-TUN nodes submit applications ->
// Web draft adds members & ACL -> Export policy.json -> Offline owner signs -> Web preview & publish ->
// Nodes verify signature, enforce TCP/UDP port ACLs, and immediately drop sessions upon signed revocation.
func TestConsoleDraftSignPublishAndLiveACL(t *testing.T) {
	temp := t.TempDir()
	ownerPub, ownerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	trust := owner.NewTrust(ownerPub, 1)
	trustPath := filepath.Join(temp, "trust.json")
	trustBytes, _ := json.Marshal(trust)
	if err := os.WriteFile(trustPath, trustBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	st, err := store.NewFileStore(filepath.Join(temp, "center", "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const adminPw = "console-e2e-password-2026"
	if err := st.SetAdminPassword(adminPw); err != nil {
		t.Fatal(err)
	}

	ctrl := control.NewServer(control.Config{RequireOwner: true}, st)
	nodeH := ctrl.Handler()
	adminH := ctrl.AdminHandler()

	// Helper to call Web session API over simulated HTTPS
	var cookie *http.Cookie
	var csrf string
	webCall := func(method, path string, reqBody any, want int, out any) []byte {
		t.Helper()
		var raw []byte
		if reqBody != nil {
			raw, _ = json.Marshal(reqBody)
		}
		r := httptest.NewRequest(method, "https://admin.local"+path, bytes.NewReader(raw))
		if len(raw) > 0 {
			r.Header.Set("Content-Type", "application/json")
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if method != http.MethodGet && csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		w := httptest.NewRecorder()
		adminH.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %s: got %d, want %d (%s)", method, path, w.Code, want, w.Body.String())
		}
		if cs := w.Result().Cookies(); len(cs) > 0 && cs[0].MaxAge >= 0 {
			cookie = cs[0]
		}
		if out != nil {
			if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
				t.Fatalf("decode %s: %v", path, err)
			}
		}
		return w.Body.Bytes()
	}

	// 1. Web login & bind owner trust.json
	var loginResp struct {
		CSRF string `json:"csrf"`
	}
	webCall(http.MethodPost, "/admin/api/login", map[string]string{"password": adminPw}, http.StatusOK, &loginResp)
	csrf = loginResp.CSRF
	webCall(http.MethodPost, "/admin/api/setup", map[string]any{"trust": trust, "confirm": true}, http.StatusOK, nil)

	// 2. Create 2 single-use enrollment keys via Web console
	issueKey := func(label string) string {
		var k struct {
			Key string `json:"key"`
		}
		webCall(http.MethodPost, "/admin/api/keys", map[string]any{"label": label, "ttlHours": 1}, http.StatusCreated, &k)
		return k.Key
	}

	const nodeServerURL = "http://127.0.0.1:8080"
	nodeHTTP := &http.Client{Transport: &memRoundTripper{handler: nodeH}}
	switchUDP := newMemUDPSwitch()
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()

	startPendingNode := func(name, ep string) (*engine.Engine, *tun.MemoryDevice, types.PublicKey) {
		t.Helper()
		stMgr, err := state.LoadOrCreate(filepath.Join(temp, name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		dev := tun.NewMemoryDevice(name, 0)
		e, err := engine.New(engine.Options{
			State: stMgr, TUN: dev, OwnerTrustFile: trustPath, RequireOwner: true,
			HTTPClient: nodeHTTP, UDPConn: switchUDP.Listen(ep), RelayDial: makeRelayDialer(ctrl.Relay()),
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = e.Close() })
		_, err = e.Up(ctx, engine.UpRequest{ServerURL: nodeServerURL, AuthKey: issueKey(name), Hostname: name})
		if err == nil || !strings.Contains(err.Error(), "waiting for owner approval") {
			t.Fatalf("expected waiting for owner approval, got %v", err)
		}
		return e, dev, stMgr.Get().NodeKey.Public()
	}

	engA, tunA, keyA := startPendingNode("client-a", "127.0.0.1:52920")
	engB, tunB, keyB := startPendingNode("server-b", "127.0.0.1:52921")

	// 3. Create policy draft in Web console, add both pending nodes & upload ACL-only JSON.
	var draftWrap struct {
		Draft store.Draft `json:"draft"`
	}
	webCall(http.MethodPost, "/admin/api/drafts", map[string]any{"name": "prod-v1", "fromActive": true}, http.StatusCreated, &draftWrap)
	draftID := draftWrap.Draft.ID

	ipA := netip.MustParseAddr("100.64.0.41")
	ipB := netip.MustParseAddr("100.64.0.42")
	webCall(http.MethodPost, "/admin/api/drafts/"+draftID+"/members", map[string]any{
		"nodeKey": keyA.String(), "name": "client-a", "ipv4": ipA.String(), "tags": []string{"tag:client"},
	}, http.StatusOK, nil)
	webCall(http.MethodPost, "/admin/api/drafts/"+draftID+"/members", map[string]any{
		"nodeKey": keyB.String(), "name": "server-b", "ipv4": ipB.String(), "tags": []string{"tag:backend"},
	}, http.StatusOK, nil)

	webCall(http.MethodPost, "/admin/api/drafts/"+draftID+"/acl", types.ACLPolicy{
		ACLs: []types.ACLGrantEntry{
			{Action: "accept", Proto: "udp", Src: []string{"tag:client"}, Dst: []string{"tag:backend:9000"}},
		},
	}, http.StatusOK, nil)

	// Unsigned draft alone MUST NOT allow nodes onto the data plane!
	if _, err := engA.Up(ctx, engine.UpRequest{}); err == nil {
		t.Fatal("unsigned draft allowed node A onto data plane")
	}

	// 4. Export policy.json from Web console, sign offline on owner side (no owner daemon stays running!), and publish via Web!
	exportedRaw := webCall(http.MethodGet, "/admin/api/drafts/"+draftID+"/export", nil, http.StatusOK, nil)
	var exported owner.Policy
	if err := owner.DecodeJSON(bytes.NewReader(exportedRaw), &exported); err != nil {
		t.Fatal(err)
	}
	snapV1, err := exported.Snapshot(1, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	envV1, err := owner.Sign(snapV1, ownerPriv, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	webCall(http.MethodPost, "/admin/api/authorization", envV1, http.StatusOK, nil)

	// 5. Bring both nodes up and verify UDP:9000 passes while UDP:9001 is dropped by ACL!
	if _, err := engA.Up(ctx, engine.UpRequest{}); err != nil {
		t.Fatalf("node A Up after signed publish: %v", err)
	}
	if _, err := engB.Up(ctx, engine.UpRequest{}); err != nil {
		t.Fatalf("node B Up after signed publish: %v", err)
	}

	blocked := pktutil.BuildUDPPacket(ipA, ipB, 40001, 9001, []byte("forbidden"))
	_ = tunA.InjectOutbound(blocked)
	allowed := pktutil.BuildUDPPacket(ipA, ipB, 40002, 9000, []byte("allowed-by-signed-acl"))
	_ = tunA.InjectOutbound(allowed)

	select {
	case got := <-tunB.ReceiveInbound():
		if !bytes.Equal(got, allowed) {
			t.Fatalf("received unexpected packet (forbidden port leaked?): len=%d", len(got))
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for allowed packet")
	}

	// 6. Publish v2 removing server-b -> immediate live revocation!
	exported.Members = exported.Members[:1]
	snapV2, err := exported.Snapshot(2, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	envV2, err := owner.Sign(snapV2, ownerPriv, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	webCall(http.MethodPost, "/admin/api/authorization", envV2, http.StatusOK, nil)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if engB.Status().State == "WaitingForControl" && len(engA.Status().Peers) == 0 {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("live revocation did not clear node B: statusB=%s peersA=%d", engB.Status().State, len(engA.Status().Peers))
}

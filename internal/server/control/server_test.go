package control_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ackwrap/acktier/internal/server/control"
	"github.com/ackwrap/acktier/internal/server/store"
	"github.com/ackwrap/acktier/pkg/types"
)

func registerTestNode(t *testing.T, handler http.Handler, authKey, hostname string) types.RegisterResponse {
	t.Helper()
	mk, _ := types.GeneratePrivateKey()
	nk, _ := types.GeneratePrivateKey()
	reqBody, _ := json.Marshal(types.RegisterRequest{
		MachineKey: mk.Public(),
		NodeKey:    nk.Public(),
		AuthKey:    authKey,
		Hostname:   hostname,
		OS:         "windows",
		Endpoints:  []types.Endpoint{{Proto: types.ProtoUDP, Addr: "192.0.2.1:51820"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/node/register", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("register %s status=%d body=%s", hostname, rec.Code, rec.Body.String())
	}
	var out types.RegisterResponse
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatalf("decode register response: %v", err)
	}
	return out
}

func TestControlRegisterAndNetMap(t *testing.T) {
	st, err := store.NewFileStore(filepath.Join(t.TempDir(), "center", "state.sqlite"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer st.Close()
	pak, err := st.CreatePreAuthKey("test", true, false, []string{"tag:dev"}, time.Hour)
	if err != nil {
		t.Fatalf("create key: %v", err)
	}

	srv := control.NewServer(control.Config{
		AdminToken: "adm_secret",
		PublicHost: "127.0.0.1",
		RelayAddr:  "127.0.0.1:8080",
	}, st)
	handler := srv.Handler()

	regA := registerTestNode(t, handler, pak.Key, "Alpha-PC")
	regB := registerTestNode(t, handler, pak.Key, "Beta-Server")

	if regA.NetMap.Self.IPv4.String() != "100.64.0.1" {
		t.Fatalf("expected 100.64.0.1, got %s", regA.NetMap.Self.IPv4)
	}
	if regB.NetMap.Self.IPv4.String() != "100.64.0.2" {
		t.Fatalf("expected 100.64.0.2, got %s", regB.NetMap.Self.IPv4)
	}
	if len(regB.NetMap.Peers) != 1 || regB.NetMap.Peers[0].Name != "alpha-pc" {
		t.Fatalf("expected Beta NetMap to include peer alpha-pc, got %+v", regB.NetMap.Peers)
	}

	// Verify Admin status endpoint
	adminReq := httptest.NewRequest(http.MethodGet, "/api/v1/admin/status", nil)
	adminReq.Header.Set("Authorization", "Bearer adm_secret")
	adminRec := httptest.NewRecorder()
	handler.ServeHTTP(adminRec, adminReq)
	if adminRec.Code != http.StatusOK {
		t.Fatalf("admin status failed: %d", adminRec.Code)
	}
}

func TestNetMapStreamOutlivesReadTimeout(t *testing.T) {
	const readTimeout = 300 * time.Millisecond
	for _, version := range []int{1, 2} {
		t.Run(fmt.Sprintf("HTTP%d", version), func(t *testing.T) {
			st, err := store.NewFileStore("")
			if err != nil {
				t.Fatal(err)
			}
			pak, err := st.CreatePreAuthKey("test", true, false, nil, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			handler := control.NewServer(control.Config{AdminToken: "adm_test"}, st).Handler()
			reg := registerTestNode(t, handler, pak.Key, "original")

			srv := httptest.NewUnstartedServer(handler)
			srv.Config.ReadHeaderTimeout = 2 * time.Second
			srv.Config.ReadTimeout = readTimeout
			if version == 2 {
				srv.EnableHTTP2 = true
				srv.StartTLS()
			} else {
				srv.Start()
			}
			defer srv.Close()

			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/node/map/stream?nodeKey="+reg.NetMap.Self.NodeKey.String(), nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+reg.NodeToken)
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK || resp.ProtoMajor != version {
				t.Fatalf("unexpected stream response: %s %s", resp.Proto, resp.Status)
			}
			dec := json.NewDecoder(resp.Body)
			var initial types.MapStreamEvent
			if err := dec.Decode(&initial); err != nil || initial.NetMap == nil || initial.NetMap.Self.Name != "original" {
				t.Fatalf("initial map missing: %v", err)
			}

			// The GET is now idle well beyond the configured request timeout.
			// An update must still arrive on this same response body.
			time.Sleep(2 * readTimeout)
			rename := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/admin/nodes/%d/rename", reg.NetMap.Self.ID), strings.NewReader(`{"name":"renamed"}`))
			rename.Header.Set("Authorization", "Bearer adm_test")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, rename)
			if rec.Code != http.StatusOK {
				t.Fatalf("rename status=%d body=%s", rec.Code, rec.Body)
			}
			var next types.MapStreamEvent
			if err := dec.Decode(&next); err != nil || next.NetMap == nil || next.NetMap.Revision <= initial.NetMap.Revision || next.NetMap.Self.Name != "renamed" {
				t.Fatalf("updated map missing on original stream: %v", err)
			}
		})
	}
}

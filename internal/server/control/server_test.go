package control_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/acktier/acktier/internal/server/control"
	"github.com/acktier/acktier/internal/server/store"
	"github.com/acktier/acktier/pkg/types"
)

func TestControlRegisterAndNetMap(t *testing.T) {
	st, err := store.NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
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

	registerNode := func(hostname string) types.RegisterResponse {
		mk, _ := types.GeneratePrivateKey()
		nk, _ := types.GeneratePrivateKey()
		reqBody, _ := json.Marshal(types.RegisterRequest{
			MachineKey: mk.Public(),
			NodeKey:    nk.Public(),
			AuthKey:    pak.Key,
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
			t.Fatalf("decode response: %v", err)
		}
		return out
	}

	regA := registerNode("Alpha-PC")
	regB := registerNode("Beta-Server")

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

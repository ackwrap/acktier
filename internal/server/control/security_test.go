package control_test

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ackwrap/acktier/internal/server/control"
	"github.com/ackwrap/acktier/internal/server/relay"
	"github.com/ackwrap/acktier/internal/server/store"
	"github.com/ackwrap/acktier/pkg/protocol"
	"github.com/ackwrap/acktier/pkg/types"
)

func TestSecurity_PreAuthKeyTakeoverBlocked_UniqueNames_ACL_And_RouteBounds(t *testing.T) {
	st, err := store.NewFileStore("")
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	pak1, _ := st.CreatePreAuthKey("init", true, false, []string{"tag:prod"}, time.Hour)
	pak2, _ := st.CreatePreAuthKey("ordinary-join", true, false, []string{"tag:guest"}, time.Hour)

	srv := control.NewServer(control.Config{
		AdminToken: "adm_sec_token",
		PublicHost: "127.0.0.1",
		RelayAddr:  "127.0.0.1:8080",
	}, st)
	h := srv.Handler()

	mkVictim, _ := types.GeneratePrivateKey()
	nkVictim, _ := types.GeneratePrivateKey()

	// 1. Register Victim Node ("prod-db")
	doReg := func(req types.RegisterRequest, bearer string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(req)
		httpReq := httptest.NewRequest(http.MethodPost, "/api/v1/node/register", bytes.NewReader(raw))
		httpReq.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			httpReq.Header.Set("Authorization", "Bearer "+bearer)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httpReq)
		return rec
	}

	rec1 := doReg(types.RegisterRequest{
		MachineKey: mkVictim.Public(),
		NodeKey:    nkVictim.Public(),
		AuthKey:    pak1.Key,
		Hostname:   "prod-db",
		OS:         "linux",
	}, "")
	if rec1.Code != http.StatusOK {
		t.Fatalf("initial register failed: %d %s", rec1.Code, rec1.Body.String())
	}
	var regVictim types.RegisterResponse
	_ = json.NewDecoder(rec1.Body).Decode(&regVictim)

	// 2. Register Attacker Node ALSO claiming Hostname="prod-db"!
	// Verify: (a) Victim's MachineKey is stripped from Attacker's NetMap.Peers,
	// and (b) Attacker gets unique server-assigned name "prod-db-2" (cannot shadow "prod-db"!).
	mkAttacker, _ := types.GeneratePrivateKey()
	nkAttacker, _ := types.GeneratePrivateKey()
	rec2 := doReg(types.RegisterRequest{
		MachineKey: mkAttacker.Public(),
		NodeKey:    nkAttacker.Public(),
		AuthKey:    pak2.Key,
		Hostname:   "prod-db",
		OS:         "linux",
	}, "")
	if rec2.Code != http.StatusOK {
		t.Fatalf("attacker register failed: %d %s", rec2.Code, rec2.Body.String())
	}
	var regAttacker types.RegisterResponse
	_ = json.NewDecoder(rec2.Body).Decode(&regAttacker)

	if regAttacker.NetMap.Self.Name != "prod-db-2" {
		t.Fatalf("expected colliding hostname to be assigned unique 'prod-db-2', got %q", regAttacker.NetMap.Self.Name)
	}
	if len(regAttacker.NetMap.Peers) != 1 || !regAttacker.NetMap.Peers[0].MachineKey.IsZero() {
		t.Fatalf("peer MachineKey MUST be redacted in NetMap.Peers, got %s", regAttacker.NetMap.Peers[0].MachineKey)
	}

	// 3. Even if Attacker knows Victim's MachineKey and presents a valid PreAuthKey (pak2),
	// takeover / NodeKey replacement MUST be rejected with HTTP 403!
	nkHijack, _ := types.GeneratePrivateKey()
	hijackRec := doReg(types.RegisterRequest{
		MachineKey: mkVictim.Public(),
		NodeKey:    nkHijack.Public(),
		AuthKey:    pak2.Key,
		Hostname:   "hijacked",
	}, "")
	if hijackRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden on PreAuthKey takeover of existing MachineKey, got %d (%s)", hijackRec.Code, hijackRec.Body.String())
	}

	// 4. Attempting to register a brand-new MachineKey with Victim's active NodeKey MUST fail with HTTP 409!
	mkFresh, _ := types.GeneratePrivateKey()
	dupNKRec := doReg(types.RegisterRequest{
		MachineKey: mkFresh.Public(),
		NodeKey:    nkVictim.Public(),
		AuthKey:    pak2.Key,
		Hostname:   "clone",
	}, "")
	if dupNKRec.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict when reusing another device's NodeKey, got %d", dupNKRec.Code)
	}

	// 5. Re-registering Victim WITH its legitimate NodeToken succeeds, but self-reported Hostname cannot alter server Name!
	nkRotated, _ := types.GeneratePrivateKey()
	legitRec := doReg(types.RegisterRequest{
		MachineKey: mkVictim.Public(),
		NodeKey:    nkRotated.Public(),
		Hostname:   "prod-db-2", // trying to collide with node 2
	}, regVictim.NodeToken)
	if legitRec.Code != http.StatusOK {
		t.Fatalf("legitimate NodeToken rekey failed: %d %s", legitRec.Code, legitRec.Body.String())
	}
	var legitResp types.RegisterResponse
	_ = json.NewDecoder(legitRec.Body).Decode(&legitResp)
	if legitResp.NetMap.Self.Name != "prod-db" {
		t.Fatalf("expected server-assigned Name 'prod-db' to stay immutable on self re-register, got %q", legitResp.NetMap.Self.Name)
	}

	// 6. Admin recovery `/api/v1/admin/nodes/1/rekey` rotates NodeToken and invalidates previous NodeToken!
	rekeyReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/nodes/1/rekey", bytes.NewReader([]byte(`{}`)))
	rekeyReq.Header.Set("Authorization", "Bearer adm_sec_token")
	rekeyRec := httptest.NewRecorder()
	h.ServeHTTP(rekeyRec, rekeyReq)
	if rekeyRec.Code != http.StatusOK {
		t.Fatalf("admin rekey failed: %d %s", rekeyRec.Code, rekeyRec.Body.String())
	}
	staleCheck := doReg(types.RegisterRequest{
		MachineKey: mkVictim.Public(),
		NodeKey:    nkRotated.Public(),
	}, regVictim.NodeToken)
	if staleCheck.Code != http.StatusForbidden {
		t.Fatalf("expected revoked NodeToken after admin rekey to return 403, got %d", staleCheck.Code)
	}

	// 7. Oversized unauthenticated body (> 64 KiB) on `/api/v1/node/register` is rejected cleanly!
	giant := `{"hostname":"` + strings.Repeat("A", 80*1024) + `"}`
	giantReq := httptest.NewRequest(http.MethodPost, "/api/v1/node/register", strings.NewReader(giant))
	giantRec := httptest.NewRecorder()
	h.ServeHTTP(giantRec, giantReq)
	if giantRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 BadRequest on oversized register payload, got %d", giantRec.Code)
	}

	// 8. ACL Policy MUST reject untrusted bare node names ("prod-db"), while accepting `tag:*` and `node:<id>`!
	badACL, _ := json.Marshal(types.ACLPolicy{
		ACLs: []types.ACLGrantEntry{{Action: "accept", Src: []string{"prod-db"}, Dst: []string{"*:*"}}},
	})
	aclReq1 := httptest.NewRequest(http.MethodPut, "/api/v1/admin/acl", bytes.NewReader(badACL))
	aclReq1.Header.Set("Authorization", "Bearer adm_sec_token")
	aclRec1 := httptest.NewRecorder()
	h.ServeHTTP(aclRec1, aclReq1)
	if aclRec1.Code != http.StatusBadRequest {
		t.Fatalf("expected ACL referencing untrusted node name 'prod-db' to be rejected with 400, got %d", aclRec1.Code)
	}

	goodACL, _ := json.Marshal(types.ACLPolicy{
		ACLs: []types.ACLGrantEntry{{Action: "accept", Src: []string{"node:1"}, Proto: "tcp", Dst: []string{"tag:prod:443"}}},
	})
	aclReq2 := httptest.NewRequest(http.MethodPut, "/api/v1/admin/acl", bytes.NewReader(goodACL))
	aclReq2.Header.Set("Authorization", "Bearer adm_sec_token")
	aclRec2 := httptest.NewRecorder()
	h.ServeHTTP(aclRec2, aclReq2)
	if aclRec2.Code != http.StatusOK {
		t.Fatalf("expected ACL with node:1 and tag:prod:443 to succeed, got %d: %s", aclRec2.Code, aclRec2.Body.String())
	}

	// 9. Route approval MUST reject subnet CIDRs overlapping overlay (100.64.0.0/10) or loopback (127.0.0.0/8)!
	for _, badCIDR := range []string{"100.64.0.0/24", "127.0.0.0/8", "169.254.0.0/16"} {
		body, _ := json.Marshal(map[string]any{"routes": []netip.Prefix{netip.MustParsePrefix(badCIDR)}})
		rReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/nodes/1/routes/approve", bytes.NewReader(body))
		rReq.Header.Set("Authorization", "Bearer adm_sec_token")
		rRec := httptest.NewRecorder()
		h.ServeHTTP(rRec, rReq)
		if rRec.Code != http.StatusBadRequest {
			t.Fatalf("expected route %s overlapping protected space to be rejected with 400, got %d", badCIDR, rRec.Code)
		}
	}
}

func TestSecurity_RelayConcurrentCloseAndForwardNoPanic(t *testing.T) {
	rs := relay.NewServer(func(nk types.PublicKey, tok string) bool { return tok == "ok" })
	kA := types.PublicKey{0xAA}
	kB := types.PublicKey{0xBB}

	bindClient := func(k types.PublicKey) net.Conn {
		c, s := net.Pipe()
		go rs.ServeConn(s)
		_ = protocol.WriteFrame(c, protocol.EncodeRelayBind(k, "ok"))
		_, _ = protocol.ReadFrame(c)
		go func() {
			for {
				if _, err := protocol.ReadFrame(c); err != nil {
					return
				}
			}
		}()
		return c
	}

	connA := bindClient(kA)
	defer connA.Close()

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Sender goroutines hammering PacketRelayForward from kA -> kB
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fwd := protocol.EncodeRelayForward(8, kA, kB, []byte("stress-payload"))
			for {
				select {
				case <-stop:
					return
				default:
					_ = protocol.WriteFrame(connA, fwd)
				}
			}
		}()
	}

	// Churn kB connect + replace + Disconnect concurrently to exercise session teardown race
	for i := 0; i < 40; i++ {
		cB := bindClient(kB)
		rs.Disconnect(kB)
		_ = cB.Close()
	}

	close(stop)
	_ = connA.Close()
	wg.Wait()
}

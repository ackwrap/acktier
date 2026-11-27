package control_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ackwrap/acktier/internal/owner"
	"github.com/ackwrap/acktier/internal/server/control"
	"github.com/ackwrap/acktier/internal/server/store"
	"github.com/ackwrap/acktier/pkg/client"
	"github.com/ackwrap/acktier/pkg/types"
)

func TestDelegatedPolicyWorkflow(t *testing.T) {
	st, err := store.NewFileStore("")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SetAdminPassword(testWebAdminPassword); err != nil {
		t.Fatal(err)
	}
	pub, signingKey, _ := ed25519.GenerateKey(nil)
	trust := owner.NewTrust(pub, 1)
	if err := st.InitializeOwner(trust); err != nil {
		t.Fatal(err)
	}
	srv := control.NewServer(control.Config{RequireOwner: true}, st)
	admin := srv.AdminHandler()
	session := &adminSessionClient{t: t, h: admin}
	session.login(testWebAdminPassword, http.StatusOK)
	_, delegate, _ := ed25519.GenerateKey(nil)
	httpClient := &http.Client{Transport: &handlerTransport{h: admin, https: true}}
	ctl := client.NewControllerClient("https://center.test", trust.NetworkID(), delegate, httpClient)
	ctx := context.Background()
	if _, err := ctl.Policy(ctx, client.PolicyListDrafts, nil, ""); err == nil {
		t.Fatal("policy API accepted disabled delegation")
	}
	delegation, err := owner.NewControllerTrust(trust, delegate, "fixture-controller")
	if err != nil {
		t.Fatal(err)
	}
	session.doJSON(http.MethodPut, "/admin/api/delegation", delegation, http.StatusOK, nil)
	session.doJSON(http.MethodGet, client.ControllerPolicyPath+"/drafts", nil, http.StatusUnauthorized, nil)
	nodeRequest := httptest.NewRequest(http.MethodGet, "https://node.test"+client.ControllerPolicyPath+"/drafts", nil)
	nodeResponse := httptest.NewRecorder()
	srv.Handler().ServeHTTP(nodeResponse, nodeRequest)
	if nodeResponse.Code != http.StatusNotFound {
		t.Fatalf("node listener exposed the policy API: %d", nodeResponse.Code)
	}

	call := func(out any, op client.ControllerPolicyOperation, body any, revision string, params ...string) {
		t.Helper()
		var raw json.RawMessage
		if body != nil {
			var err error
			raw, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		result, err := ctl.Policy(ctx, op, raw, revision, params...)
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		if out != nil {
			if err := json.Unmarshal(result, out); err != nil {
				t.Fatalf("decode %s: %v", op, err)
			}
		}
	}
	var draft struct {
		Draft    store.Draft `json:"draft"`
		Analysis struct {
			Valid bool              `json:"valid"`
			Rules []json.RawMessage `json:"rules"`
		} `json:"analysis"`
	}
	call(&draft, client.PolicyCreateDraft, map[string]string{"name": "fixture"}, "")
	id := draft.Draft.ID
	nodeKey := types.PublicKey{11}
	const memberID = types.NodeID(9007199254740993)
	call(&draft, client.PolicyAddMember, map[string]any{
		"id": memberID, "nodeKey": nodeKey.String(), "name": "nas", "ipv4": "100.64.0.10",
		"routes": []string{"192.168.88.0/24"}, "tags": []string{"tag:storage"},
	}, draft.Draft.UpdatedAt.Format(time.RFC3339Nano), id)
	previousRevision := draft.Draft.UpdatedAt.Format(time.RFC3339Nano)
	aclBody := types.ACLPolicy{
		ACLs: []types.ACLGrantEntry{{Action: "accept", Proto: "tcp", Src: []string{"*"}, Dst: []string{"tag:storage:22,443"}}},
	}
	call(&draft, client.PolicySaveACL, aclBody, previousRevision, id)
	revision := draft.Draft.UpdatedAt.Format(time.RFC3339Nano)
	if !draft.Analysis.Valid || len(draft.Analysis.Rules) < 2 || revision == previousRevision {
		t.Fatal("ACL was not compiled with the updated draft revision")
	}
	for _, op := range []client.ControllerPolicyOperation{client.PolicySaveACL, client.PolicyExportDraft} {
		var body json.RawMessage
		if op == client.PolicySaveACL {
			body = json.RawMessage(`{"acls":[]}`)
		}
		if _, err := ctl.Policy(ctx, op, body, previousRevision, id); err == nil || !strings.Contains(err.Error(), "draft_changed") {
			t.Fatalf("stale %s was not rejected", op)
		}
	}
	var exported owner.Policy
	call(&exported, client.PolicyExportDraft, nil, revision, id)
	if len(exported.Members) != 1 || exported.Members[0].ID != memberID || len(exported.Members[0].Routes) != 1 ||
		!exported.DNS.EnableMagicDNS || len(exported.ACL.ACLs) != 1 {
		t.Fatal("export lost members, routes, DNS, or the saved ACL")
	}
	var analysis struct{ Valid bool }
	call(&analysis, client.PolicyValidate, map[string]owner.Policy{"policy": exported}, "")
	if !analysis.Valid {
		t.Fatal("exported policy failed validation")
	}
	snap, err := exported.Snapshot(1, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := owner.Sign(snap, signingKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var preview struct{ Valid bool }
	badEnvelope := envelope
	badEnvelope.Signature = append([]byte(nil), envelope.Signature...)
	badEnvelope.Signature[0] ^= 1
	call(&preview, client.PolicyPreviewPublication, badEnvelope, "")
	if preview.Valid {
		t.Fatal("preview accepted a modified owner signature")
	}
	call(&preview, client.PolicyPreviewPublication, envelope, "")
	if !preview.Valid || len(st.Publications()) != 0 {
		t.Fatal("preview either failed verification or wrote a publication")
	}
	call(nil, client.PolicyPublish, envelope, "")
	var history []struct{ Version uint64 }
	call(&history, client.PolicyPublicationHistory, nil, "")
	if len(history) != 1 || history[0].Version != 1 {
		t.Fatal("signed authorization is missing from history")
	}
	call(nil, client.PolicyGetPublication, nil, "", "1")
	call(&draft, client.PolicyCreateDraft, map[string]bool{"fromActive": true}, "")
	if draft.Draft.BaseVersion != 1 || len(draft.Draft.Policy.ACL.ACLs) != 1 {
		t.Fatal("active draft did not retain the policy source")
	}
	call(&draft, client.PolicyRemoveMember, nil, draft.Draft.UpdatedAt.Format(time.RFC3339Nano), draft.Draft.ID, nodeKey.String())
	if len(draft.Draft.Policy.Members) != 0 || len(st.Publications()) != 1 {
		t.Fatal("removing a draft member changed the published authorization")
	}
	call(nil, client.PolicyDeleteDraft, nil, draft.Draft.UpdatedAt.Format(time.RFC3339Nano), draft.Draft.ID)
	session.doJSON(http.MethodDelete, "/admin/api/delegation", nil, http.StatusOK, nil)
	if _, err := ctl.Policy(ctx, client.PolicyListDrafts, nil, ""); err == nil {
		t.Fatal("policy API accepted revoked delegation")
	}
}

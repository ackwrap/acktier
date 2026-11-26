package store

import (
	"bytes"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/acktier/acktier/internal/owner"
	"github.com/acktier/acktier/internal/secfile"
	"github.com/acktier/acktier/internal/server/ipam"
	"github.com/acktier/acktier/pkg/types"
)

func openTestSQLite(t *testing.T, path string) *FileStore {
	t.Helper()
	st, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Error(err)
		}
	})
	return st
}

func authorizedEnvelope(t *testing.T, key ed25519.PrivateKey, version uint64, now time.Time) types.OwnerAuthorization {
	t.Helper()
	env, err := owner.Sign(owner.Snapshot{
		Version: version, ExpiresAt: now.Add(time.Hour), PacketFilter: []types.FilterRule{owner.DenyAll()},
	}, key, now)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestSQLitePersistsCenterStateWithoutPlaintextCredentials(t *testing.T) {
	db := filepath.Join(t.TempDir(), "private # sqlite", "server.sqlite")
	st := openTestSQLite(t, db)
	if _, pinned := st.OwnerTrust(); pinned || st.HasAdminPassword() || len(st.ListNodes()) != 0 {
		t.Fatal("a new database must start unbound and without nodes or credentials")
	}
	pub, ownerKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, ctl, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	const pass = "initial-test-password"
	trust := owner.NewTrust(pub, 1)
	if err := st.ConfigureOwner(trust); err != nil {
		t.Fatal(err)
	}
	if err := st.SetAdminPassword(pass); err != nil {
		t.Fatal(err)
	}
	ctlTrust, err := owner.NewControllerTrust(trust, ctl, "control laptop")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.EnableControllerDelegation(ctlTrust); err != nil {
		t.Fatal(err)
	}
	draft, err := st.SaveDraft(Draft{Name: "first draft", BaseVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	latest := authorizedEnvelope(t, ownerKey, 3, now)
	for _, env := range []types.OwnerAuthorization{authorizedEnvelope(t, ownerKey, 2, now), latest} {
		if _, _, err := st.PublishOwner(env, now); err != nil {
			t.Fatal(err)
		}
	}
	requestKey, err := st.CreatePreAuthKey("already used", false, false, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	idleKey, err := st.CreatePreAuthKey("still valid", false, false, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	revokedKey, err := st.CreatePreAuthKey("revoked", false, false, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RevokePreAuthKey(revokedKey.ID); err != nil {
		t.Fatal(err)
	}
	pool := ipam.NewAllocator(ipam.DefaultIPv4Prefix, ipam.DefaultIPv6Prefix)
	nodeKey := types.PublicKey{11}
	req := types.RegisterRequest{MachineKey: types.PublicKey{12}, NodeKey: nodeKey, AuthKey: requestKey.Key}
	node, _, err := st.RegisterNode(req, "", pool.Allocate, pool.Release)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetInventory(Inventory{NodeKey: nodeKey, Note: "test inventory"}); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendAudit(AuditEntry{Action: "test.persist", Result: "success"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	image, err := os.ReadFile(db)
	if err != nil || !bytes.HasPrefix(image, []byte("SQLite format 3\x00")) {
		t.Fatalf("not an SQLite database: %v", err)
	}
	for _, secret := range []string{pass, requestKey.Key, idleKey.Key, revokedKey.Key, node.NodeToken} {
		if secret == "" || bytes.Contains(image, []byte(secret)) {
			t.Fatal("credential missing or stored in plaintext")
		}
	}

	st = openTestSQLite(t, db)
	if got, ok := st.OwnerTrust(); !ok || got != trust || !st.VerifyAdminPassword(pass) || st.ControllerDelegation().PublicKey != ctlTrust.PublicKey {
		t.Fatal("lost owner trust, admin password, or controller identity after restart")
	}
	got, ok := st.AuthenticateNode(nodeKey, node.NodeToken)
	if !ok || got.Node.ID != node.Node.ID || got.Node.IPv4 != node.Node.IPv4 || got.Node.Online {
		t.Fatal("restart did not preserve node identity and token, or restored a stale online flag")
	}
	renewed, _, err := st.RegisterNode(req, node.NodeToken, pool.Allocate, pool.Release)
	if err != nil || renewed.NodeToken != node.NodeToken {
		t.Fatal("existing registration did not keep its bearer token")
	}
	if d, err := st.GetDraft(draft.ID); err != nil || d.Name != draft.Name {
		t.Fatal("lost draft after restart")
	}
	if inv, ok := st.Inventory(nodeKey); !ok || inv.Note != "test inventory" {
		t.Fatal("lost manual inventory after restart")
	}
	history := st.Publications()
	if len(history) != 2 || history[0].Version != 3 || !bytes.Equal(history[0].Envelope.Payload, latest.Payload) ||
		!bytes.Equal(history[0].Envelope.Signature, latest.Signature) {
		t.Fatal("lost signed history or changed signed bytes")
	}
	if audit := st.Audit(); len(audit) != 2 || audit[0].Action != "test.persist" {
		t.Fatal("lost audit entries after restart")
	}
	keys := st.ListPreAuthKeys()
	if len(keys) != 3 {
		t.Fatal("lost enrollment keys after restart")
	}
	for _, key := range keys {
		if key.Key != "" || (key.ID == revokedKey.ID && !key.Revoked) || (key.ID == requestKey.ID && key.UsedCount != 1) {
			t.Fatal("lost key state or exposed plaintext")
		}
	}
	req = types.RegisterRequest{MachineKey: types.PublicKey{13}, NodeKey: types.PublicKey{14}}
	for _, k := range []types.PreAuthKey{requestKey, revokedKey} {
		req.AuthKey = k.Key
		if _, _, err := st.RegisterNode(req, "", pool.Allocate, pool.Release); !errors.Is(err, ErrInvalidAuthKey) {
			t.Fatalf("used or revoked key unexpectedly accepted after restart: %v", err)
		}
	}
	req.AuthKey = idleKey.Key
	fresh, _, err := st.RegisterNode(req, "", pool.Allocate, pool.Release)
	if err != nil || fresh.Node.ID != node.Node.ID+1 {
		t.Fatalf("unused key stopped working or ID allocation was lost after restart: %v", err)
	}
	if _, _, err := st.PublishOwner(authorizedEnvelope(t, ownerKey, 2, now), now); !errors.Is(err, owner.ErrRollback) {
		t.Fatalf("rollback accepted after restart: %v", err)
	}
}

func TestSQLiteRefusesInvalidState(t *testing.T) {
	root := t.TempDir()
	db := filepath.Join(root, "private", "center.db")
	if st, err := OpenExistingFileStore(db); err == nil {
		_ = st.Close()
		t.Fatal("opened a nonexistent center database for offline reset")
	}
	if _, err := os.Stat(db); !os.IsNotExist(err) {
		t.Fatal("offline reset created a new database")
	}
	for _, data := range []string{"", "not an SQLite database"} {
		if err := secfile.EnsurePrivateDir(filepath.Dir(db)); err != nil {
			t.Fatal(err)
		}
		if err := secfile.WritePrivate(db, []byte(data)); err != nil {
			t.Fatal(err)
		}
		if st, err := NewFileStore(db); err == nil {
			_ = st.Close()
			t.Fatal("invalid database was silently replaced")
		}
		if raw, err := os.ReadFile(db); err != nil || string(raw) != data {
			t.Fatal("invalid database was modified")
		}
	}
}

func TestSQLiteRegistrationAndAuditRollbackTogether(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "center.db")
	st := openTestSQLite(t, path)
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ConfigureOwner(owner.NewTrust(pub, 1)); err != nil {
		t.Fatal(err)
	}
	key, err := st.CreatePreAuthKey("single", false, false, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	trigger := func(sqlText string) {
		t.Helper()
		if err := st.sqlite.transact(func(tx *sql.Tx) error {
			_, err := tx.Exec(sqlText)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	trigger(`CREATE TRIGGER audit_unavailable BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'test storage failure'); END`)
	pool := ipam.NewAllocator(ipam.DefaultIPv4Prefix, ipam.DefaultIPv6Prefix)
	req := types.RegisterRequest{MachineKey: types.PublicKey{1}, NodeKey: types.PublicKey{2}, AuthKey: key.Key}
	if _, _, err := st.RegisterNode(req, "", pool.Allocate, pool.Release); err == nil {
		t.Fatal("registration succeeded without its audit row")
	}
	if len(st.ListNodes()) != 0 || len(st.Audit()) != 0 || st.ListPreAuthKeys()[0].UsedCount != 0 {
		t.Fatal("failed registration left partial in-memory state")
	}
	trigger("DROP TRIGGER audit_unavailable")
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st = openTestSQLite(t, path)
	if len(st.ListNodes()) != 0 || len(st.Audit()) != 0 || st.ListPreAuthKeys()[0].UsedCount != 0 {
		t.Fatal("failed registration left partial SQLite rows")
	}
	var wg sync.WaitGroup
	results := make(chan error, 4)
	for i := range cap(results) {
		wg.Go(func() {
			r := req
			r.MachineKey, r.NodeKey = types.PublicKey{byte(10 + i)}, types.PublicKey{byte(20 + i)}
			_, _, err := st.RegisterNode(r, "", pool.Allocate, pool.Release)
			results <- err
		})
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrInvalidAuthKey) {
			t.Fatal(err)
		}
	}
	if successes != 1 || len(st.Audit()) != 1 || st.ListPreAuthKeys()[0].UsedCount != 1 {
		t.Fatal("single-use key consumption was not atomic")
	}
}

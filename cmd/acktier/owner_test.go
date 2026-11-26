package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ackwrap/acktier/internal/owner"
	"github.com/ackwrap/acktier/pkg/types"
)

func TestLocalOwnerSigningWorkflow(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "owner")
	if err := initOwner(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, trustFile)
	initial, err := owner.LoadTrust(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := initOwner(dir); err == nil {
		t.Fatal("initialization could overwrite the selected owner")
	}
	policy := filepath.Join(tmp, "policy.json")
	if err := os.WriteFile(policy, []byte(`{"members":[],"acl":{"acls":[]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for want := uint64(1); want <= 2; want++ {
		if got, err := signOwner(dir, policy, time.Hour); err != nil || got != want {
			t.Fatalf("signing version: got %d, want %d (%v)", got, want, err)
		}
		current, err := owner.LoadTrust(path)
		if err != nil || current.PublicKey != initial.PublicKey || current.MinimumVersion != want {
			t.Fatalf("trust export does not match the release: %+v (%v)", current, err)
		}
		var signed types.OwnerAuthorization
		if err := owner.ReadJSON(filepath.Join(dir, publicationFile), owner.MaxEnvelope, &signed); err != nil {
			t.Fatal(err)
		}
		v, err := owner.Verify(initial, signed)
		if err != nil || v.Snapshot.Version != want || len(v.Snapshot.PacketFilter) != 1 ||
			v.Snapshot.PacketFilter[0].Action != types.FilterDrop {
			t.Fatalf("empty policy did not issue a deny-by-default authorization: %+v (%v)", v, err)
		}
	}
}

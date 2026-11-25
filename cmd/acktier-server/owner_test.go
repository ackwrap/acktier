package main

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/acktier/acktier/internal/owner"
	"github.com/acktier/acktier/internal/server/store"
)

func TestStartupLeavesWebSetupAvailableWithoutOwnerFlag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")
	st, err := store.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := configureOwner(st, ""); err != nil {
		t.Fatal(err)
	}
	if _, pinned := st.OwnerTrust(); pinned {
		t.Fatal("unprovisioned center selected an owner automatically")
	}
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	want := owner.NewTrust(pub, 1)
	raw, _ := json.Marshal(want)
	trustPath := filepath.Join(dir, "trust.json")
	if err := os.WriteFile(trustPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := configureOwner(st, trustPath); err != nil {
		t.Fatal(err)
	}
	st, err = store.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := configureOwner(st, ""); err != nil {
		t.Fatal(err)
	}
	if got, pinned := st.OwnerTrust(); !pinned || got != want {
		t.Fatalf("restart did not retain owner: %+v", got)
	}
}

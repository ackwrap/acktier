package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/acktier/acktier/internal/owner"
	"github.com/acktier/acktier/internal/server/store"
)

func TestStartupLeavesWebSetupAvailableWithoutOwnerFlag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "center", "state.sqlite")
	st, err := store.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
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
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = store.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := configureOwner(st, ""); err != nil {
		t.Fatal(err)
	}
	if got, pinned := st.OwnerTrust(); !pinned || got != want {
		t.Fatalf("restart did not retain owner: %+v", got)
	}
}

func TestResetPasswordRequiresStoppedCenter(t *testing.T) {
	if len(os.Args) > 2 && os.Args[2] == "--" {
		runResetPasswordCLI(os.Args[3:])
		return
	}
	t.Setenv("ACKTIER_ADMIN_PASSWORD", "")
	dir := t.TempDir()
	statePath := filepath.Join(dir, "center", "state.sqlite")
	st, err := store.NewFileStore(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	genPw, changed, err := provisionAdminPassword(st, "", false, nil)
	if err != nil || !changed || genPw == "" || !st.VerifyAdminPassword(genPw) {
		t.Fatalf("expected generated initial password to verify: changed=%t err=%v", changed, err)
	}
	pwFile := filepath.Join(dir, "pw.txt")
	const nextPw = "explicit-local-reset-pw"
	if err := os.WriteFile(pwFile, []byte(nextPw+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runReset := func() ([]byte, error) {
		cmd := exec.CommandContext(t.Context(), bin, "-test.run=^TestResetPasswordRequiresStoppedCenter$", "--",
			"-data", statePath, "-admin-password-file", pwFile)
		return cmd.CombinedOutput()
	}
	if out, err := runReset(); err == nil || !strings.Contains(string(out), "stop the running center") {
		t.Fatalf("reset command did not reject live center: %v, %s", err, out)
	}
	if !st.VerifyAdminPassword(genPw) {
		t.Fatal("live password changed after rejected reset")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(statePath)
	if err != nil || bytes.Contains(raw, []byte(genPw)) {
		t.Fatalf("could not verify absence of plaintext admin password on disk: %v", err)
	}
	if out, err := runReset(); err != nil {
		t.Fatalf("offline reset failed: %v, %s", err, out)
	}
	reopened, err := store.NewFileStore(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.VerifyAdminPassword(genPw) || !reopened.VerifyAdminPassword(nextPw) {
		t.Fatal("offline reset did not persist the new password")
	}
}

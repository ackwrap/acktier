package store

import (
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/acktier/acktier/internal/owner"
	"github.com/acktier/acktier/pkg/types"
)

func TestOwnerPublicationAndPinSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "center.sqlite")
	st := openTestSQLite(t, path)
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	trust := owner.NewTrust(pub, 1)
	if err := st.ConfigureOwner(trust); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	makePublication := func(v uint64) types.OwnerAuthorization {
		t.Helper()
		env, err := owner.Sign(owner.Snapshot{
			Version: v, ExpiresAt: now.Add(time.Hour), PacketFilter: []types.FilterRule{owner.DenyAll()},
		}, key, now)
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	if _, _, err := st.PublishOwner(makePublication(2), now); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openTestSQLite(t, path)
	if got, ok := reopened.OwnerTrust(); !ok || got != trust {
		t.Fatalf("owner pin not persisted: %+v", got)
	}
	if _, v, _ := reopened.OwnerTopology(); v == nil || v.Checkpoint.Version != 2 {
		t.Fatal("verified authorization not restored")
	}
	if _, _, err := reopened.PublishOwner(makePublication(1), now); !errors.Is(err, owner.ErrRollback) {
		t.Fatalf("server accepted old authorization after restart: %v", err)
	}
	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.ConfigureOwner(owner.NewTrust(other, 1)); err == nil {
		t.Fatal("server allowed replacement of pinned owner")
	}
	if err := reopened.ConfigureOwner(owner.NewTrust(pub, 3)); err != nil {
		t.Fatal(err)
	}
	if _, v, _ := reopened.OwnerTopology(); v != nil {
		t.Fatal("locally raised floor did not retire older publication")
	}
}

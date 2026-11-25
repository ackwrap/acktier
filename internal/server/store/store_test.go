package store_test

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acktier/acktier/internal/server/ipam"
	"github.com/acktier/acktier/internal/server/store"
	"github.com/acktier/acktier/pkg/types"
)

func newPublicKey(t *testing.T) types.PublicKey {
	t.Helper()
	key, err := types.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key.Public()
}

func TestNodeRecoveryAndRetirement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := store.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	allocator := ipam.NewAllocator(ipam.DefaultIPv4Prefix, ipam.DefaultIPv6Prefix)
	key, err := st.CreatePreAuthKey("test", true, false, []string{"tag:test"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	req := types.RegisterRequest{MachineKey: newPublicKey(t), NodeKey: newPublicKey(t), AuthKey: key.Key}
	original, _, err := st.RegisterNode(req, "", allocator.Allocate, allocator.Release)
	if err != nil {
		t.Fatal(err)
	}
	rotated, retired, err := st.RekeyNode(original.Node.ID, types.PublicKey{}, types.PublicKey{})
	if err != nil || !rotated.Node.KeyRevoked || rotated.NodeToken == original.NodeToken || retired != req.NodeKey {
		t.Fatalf("token-only recovery did not retire the old key: %v", err)
	}
	if err := st.UpdateAuthenticatedNode(retired, original.NodeToken, func(*types.PeerNode) bool {
		t.Error("metadata update was authorized with a revoked credential")
		return true
	}); !errors.Is(err, store.ErrNodeAuth) {
		t.Fatalf("old credential update: %v", err)
	}
	if _, _, err := st.RegisterNode(req, rotated.NodeToken, allocator.Allocate, allocator.Release); !errors.Is(err, store.ErrKeyRequired) {
		t.Fatalf("recovery without a new node key: %v", err)
	}

	req.NodeKey = newPublicKey(t)
	recovered, _, err := st.RegisterNode(req, rotated.NodeToken, allocator.Allocate, allocator.Release)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Node.KeyRevoked || recovered.Node.ID != original.Node.ID || recovered.Node.IPv4 != original.Node.IPv4 {
		t.Fatal("recovery did not restore the original node with the replacement key")
	}
	if _, err := st.DeleteNode(recovered.Node.ID); err != nil {
		t.Fatal(err)
	}

	reopened, err := store.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.AuthenticateNode(req.NodeKey, rotated.NodeToken); ok {
		t.Fatal("deleted node still authenticated after reopening store")
	}
	for _, nodeKey := range []types.PublicKey{retired, req.NodeKey} {
		fresh := types.RegisterRequest{MachineKey: newPublicKey(t), NodeKey: nodeKey, AuthKey: key.Key}
		if _, _, err := reopened.RegisterNode(fresh, "", allocator.Allocate, allocator.Release); !errors.Is(err, store.ErrKeyConflict) {
			t.Fatalf("retired key was not reserved after restart: %v", err)
		}
	}
}

func TestConcurrentEnrollmentKeepsUniqueIdentity(t *testing.T) {
	st, err := store.NewFileStore("")
	if err != nil {
		t.Fatal(err)
	}
	pak, err := st.CreatePreAuthKey("test", true, false, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	allocator := ipam.NewAllocator(ipam.DefaultIPv4Prefix, ipam.DefaultIPv6Prefix)
	req := types.RegisterRequest{MachineKey: newPublicKey(t), NodeKey: newPublicKey(t), AuthKey: pak.Key}
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			_, _, err := st.RegisterNode(req, "", allocator.Allocate, allocator.Release)
			switch {
			case err == nil:
				admitted.Add(1)
			case errors.Is(err, store.ErrNodeAuth):
			default:
				t.Errorf("register: %v", err)
			}
		})
	}
	wg.Wait()
	if admitted.Load() != 1 || len(st.ListNodes()) != 1 || st.ListPreAuthKeys()[0].UsedCount != 1 {
		t.Fatal("concurrent registration was not a single transaction")
	}
}

func TestApplicationKeyChangesRequirePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")
	st, err := store.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	key, err := st.CreatePreAuthKey("existing", false, false, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, filepath.Join(dir, "backup.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreatePreAuthKey("unsaved", false, false, nil, time.Hour); err == nil {
		t.Fatal("created an application key without saving it")
	}
	if err := st.RevokePreAuthKey(key.ID); err == nil {
		t.Fatal("revoked an application key without saving it")
	}
	if keys := st.ListPreAuthKeys(); len(keys) != 1 || keys[0].ID != key.ID || keys[0].Revoked {
		t.Fatal("failed file writes changed the application key list")
	}
}

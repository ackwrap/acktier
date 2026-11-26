package control

import (
	"crypto/ed25519"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/acktier/acktier/internal/owner"
	"github.com/acktier/acktier/internal/server/store"
	"github.com/acktier/acktier/pkg/types"
)

func TestPolicyAnalysisStopsAtInvalidGroups(t *testing.T) {
	p := owner.Policy{ACL: types.ACLPolicy{
		Groups: map[string][]string{"group:invalid": {"group:invalid"}},
		ACLs:   []types.ACLGrantEntry{{Action: "accept", Src: []string{"group:invalid"}, Dst: []string{"*:443"}}},
	}}
	an := analyzePolicy(p, 0, nil, nil)
	if an.Valid || len(an.Rules) != 0 || len(an.Issues) != 1 || an.Issues[0].Level != "error" {
		t.Fatalf("invalid group should return validation errors without expanding selectors: %+v", an)
	}
}

func TestActivePolicySourcePreservesACL(t *testing.T) {
	p := owner.Policy{
		Members: []owner.Member{
			{ID: 1, Name: "laptop", NodeKey: types.PublicKey{1}, IPv4: netip.MustParseAddr("100.64.0.1")},
			{ID: 2, Name: "nas", NodeKey: types.PublicKey{2}, IPv4: netip.MustParseAddr("100.64.0.2")},
		},
		ACL: types.ACLPolicy{ACLs: []types.ACLGrantEntry{
			{Action: "accept", Proto: "tcp", Src: []string{"node:1"}, Dst: []string{"node:2:8443"}},
		}},
	}
	now := time.Now().UTC()
	active, err := p.Snapshot(2, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	active.NetworkID = owner.NewTrust(key.Public().(ed25519.PublicKey), 1).NetworkID()
	incomplete := p
	incomplete.ACL = types.ACLPolicy{}
	older := store.Draft{ID: "unrelated", Policy: incomplete}
	if _, found := activePolicySource(active, []store.Draft{older}); found {
		t.Fatal("matched a draft that would erase active ACL rules")
	}
	src, found := activePolicySource(active, []store.Draft{older, {ID: "matching", Policy: p}})
	if !found || !sameJSON(src.ACL, p.ACL) {
		t.Fatal("matching source policy did not preserve active ACL")
	}
}

func TestLoginAttemptsReservedBeforePasswordWork(t *testing.T) {
	var limiter loginLimiter
	now := time.Now()
	var wg sync.WaitGroup
	start := make(chan struct{})
	admitted := make(chan bool, 16)
	for i := range cap(admitted) {
		wg.Go(func() {
			<-start
			admitted <- limiter.reserve(fmt.Sprintf("192.0.2.%d:1001", i+1), now)
		})
	}
	close(start)
	wg.Wait()
	close(admitted)
	count := 0
	for ok := range admitted {
		if ok {
			count++
			limiter.release()
		}
	}
	if count != maxPasswordWorkers {
		t.Fatalf("admitted %d simultaneous verifications, want %d", count, maxPasswordWorkers)
	}
	for range loginAttemptsAllowed {
		if !limiter.reserve("198.51.100.1:1001", now) {
			t.Fatal("valid attempt was unexpectedly blocked")
		}
		limiter.release()
	}
	if limiter.reserve("198.51.100.1:1002", now) {
		t.Fatal("per-IP limit did not carry over to a new connection")
	}
	if !limiter.reserve("198.51.100.1:1002", now.Add(loginWindow)) {
		t.Fatal("IP did not recover after its limit window")
	}
	limiter.release()
}

func TestSessionCannotBeMadeCurrentWithOlderPasswordGeneration(t *testing.T) {
	sessions := webSessions{live: make(map[string]webSession)}
	now := time.Now()
	oldPassword := now.Add(-time.Hour)
	newPassword := now.Add(-time.Minute)
	id, _ := sessions.create(now, oldPassword, "127.0.0.1:1000")
	if _, ok := sessions.get(id, now, newPassword); ok {
		t.Fatal("session created after rotation could use the old password generation")
	}
}

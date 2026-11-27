package acl

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/ackwrap/acktier/pkg/types"
)

func TestSelectorResolutionAccountsForGroupMembers(t *testing.T) {
	policy := types.ACLPolicy{Groups: map[string][]string{
		"group:office": {"192.0.2.1", "192.0.2.2"},
	}}
	resolver := selectorResolver{policy: policy, work: 5}
	var accepted prefixSet
	if err := resolver.addSelector(&accepted, "group:office", true); err != nil || len(accepted.prefixes) != 2 {
		t.Fatalf("valid group resolved to %v, error %v", accepted.prefixes, err)
	}

	resolver.work = 4
	var limited prefixSet
	if err := resolver.addSelector(&limited, "group:office", true); !errors.Is(err, ErrTooComplex) || len(limited.prefixes) != 1 {
		t.Fatalf("limited group resolved to %v, error %v", limited.prefixes, err)
	}
}

func TestPrefixSetStopsAtLimit(t *testing.T) {
	set := prefixSet{prefixes: make([]netip.Prefix, maxCompiledPrefixes)}
	if err := set.add(netip.MustParsePrefix("192.0.2.0/24")); !errors.Is(err, ErrTooComplex) ||
		len(set.prefixes) != maxCompiledPrefixes {
		t.Fatalf("over-limit prefix changed the set to %d entries, error %v", len(set.prefixes), err)
	}
}

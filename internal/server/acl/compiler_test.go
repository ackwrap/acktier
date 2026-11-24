package acl_test

import (
	"net/netip"
	"testing"

	"github.com/acktier/acktier/internal/server/acl"
	"github.com/acktier/acktier/pkg/types"
)

func TestACLCompileTagsGroupsAndSubnets(t *testing.T) {
	nodes := []types.PeerNode{
		{
			ID:   1,
			Name: "dev-laptop",
			IPv4: netip.MustParseAddr("100.64.0.1"),
			Tags: []string{"tag:dev"},
		},
		{
			ID:             2,
			Name:           "prod-gw",
			IPv4:           netip.MustParseAddr("100.64.0.2"),
			IPv6:           netip.MustParseAddr("fd7a:115c:a1e0::2"),
			Tags:           []string{"tag:gateway"},
			ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("192.168.50.0/24")},
		},
	}

	pol := types.ACLPolicy{
		Groups: map[string][]string{
			"group:eng": {"tag:dev"},
		},
		ACLs: []types.ACLGrantEntry{
			{
				Action: "accept",
				Src:    []string{"group:eng"},
				Proto:  "tcp",
				Dst:    []string{"tag:gateway:80,8000-8090", "fd7a:115c:a1e0::2"},
			},
		},
	}

	if err := acl.Validate(pol); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	rules := acl.CompileForNode(pol, nodes[0], nodes)
	if len(rules) < 3 {
		t.Fatalf("expected compiled accept rules + trailing drop sentinel, got %d rules", len(rules))
	}
	if rules[0].DstPortStart != 80 || rules[1].DstPortStart != 8000 || rules[1].DstPortEnd != 8090 {
		t.Fatalf("unexpected compiled port ranges: %+v", rules)
	}
}

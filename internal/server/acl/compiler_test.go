package acl_test

import (
	"net/netip"
	"testing"

	"github.com/ackwrap/acktier/internal/server/acl"
	"github.com/ackwrap/acktier/pkg/types"
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

func TestInternetGrantExcludesOverlayPrivateAndApprovedRoutes(t *testing.T) {
	nodes := []types.PeerNode{{ApprovedRoutes: []netip.Prefix{
		netip.MustParsePrefix("1.1.1.0/24"), netip.MustParsePrefix("2606:4700:4700::/48"),
		netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"),
	}}}
	pol := types.ACLPolicy{ACLs: []types.ACLGrantEntry{
		{Action: "accept", Proto: "tcp", Src: []string{"*"}, Dst: []string{"autogroup:internet:443"}},
	}}
	if err := acl.Validate(pol); err != nil {
		t.Fatal(err)
	}
	rules := acl.CompileForNode(pol, types.PeerNode{}, nodes)
	if len(rules) != 2 || rules[0].DstPortStart != 443 {
		t.Fatalf("unexpected Internet policy: %d rules", len(rules))
	}
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"8.8.8.8", true}, {"1.1.2.1", true}, {"2001:4860:4860::8888", true},
		{"100.64.0.1", false}, {"10.20.30.40", false}, {"172.16.0.1", false},
		{"192.168.0.1", false}, {"169.254.169.254", false}, {"224.0.0.1", false}, {"127.0.0.1", false},
		{"192.0.2.1", false}, {"198.18.0.1", false}, {"198.51.100.1", false}, {"203.0.113.1", false},
		{"fd7a:115c:a1e0::1", false}, {"fe80::1", false}, {"::1", false}, {"2001:db8::1", false}, {"64:ff9b::1", false},
		{"1.1.1.1", false}, {"2606:4700:4700::1111", false},
	} {
		addr := netip.MustParseAddr(tc.addr)
		got := false
		for _, p := range rules[0].DstPrefixes {
			got = got || p.Contains(addr)
		}
		if got != tc.want {
			t.Errorf("Internet grant covers %v = %t, want %t", addr, got, tc.want)
		}
	}
}

func TestLabRangesCanBeGrantedExplicitly(t *testing.T) {
	pol := types.ACLPolicy{ACLs: []types.ACLGrantEntry{{
		Action: "accept",
		Proto:  "tcp",
		Src:    []string{"*"},
		Dst:    []string{"198.18.0.0/15:443", "203.0.113.0/24:443"},
	}}}
	if err := acl.Validate(pol); err != nil {
		t.Fatal(err)
	}
	rules := acl.CompileForNode(pol, types.PeerNode{}, nil)
	for _, addr := range []string{"198.18.0.1", "203.0.113.1"} {
		ip := netip.MustParseAddr(addr)
		found := false
		for _, rule := range rules {
			if rule.Action == "accept" && rule.DstPortStart == 443 && rule.DstPortEnd == 443 {
				for _, p := range rule.DstPrefixes {
					found = found || p.Contains(ip)
				}
			}
		}
		if !found {
			t.Errorf("explicit lab grant did not cover %s:443", ip)
		}
	}
}

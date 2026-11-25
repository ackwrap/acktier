package acl

import (
	"net/netip"

	"github.com/acktier/acktier/pkg/types"
)

var nonInternet = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	types.OverlayIPv4Prefix,
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/3"), // Multicast, reserved space, and limited broadcast.
	netip.MustParsePrefix("2001::/23"),   // Special-purpose assignments, conservatively excluded.
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

// Compile exclusions into the CIDRs themselves so older packet filters
// cannot accidentally interpret an Internet grant as a wildcard.
func internetPrefixes(nodes []types.PeerNode) []netip.Prefix {
	// Start IPv6 at the current global unicast allocation, not ::/0, which
	// would include unallocated space and special-purpose translation prefixes.
	prefixes := []netip.Prefix{allIPv4, netip.MustParsePrefix("2000::/3")}
	exclude := func(block netip.Prefix) {
		block = block.Masked()
		var next []netip.Prefix
		for _, p := range prefixes {
			next = subtractPrefix(next, p, block)
		}
		prefixes = next
	}
	for _, block := range nonInternet {
		exclude(block)
	}
	for _, n := range nodes {
		for _, route := range n.ApprovedRoutes {
			if route.Bits() > 0 {
				exclude(route)
			}
		}
	}
	return prefixes
}

func subtractPrefix(out []netip.Prefix, p, block netip.Prefix) []netip.Prefix {
	if !p.Overlaps(block) {
		return append(out, p)
	}
	if p.Bits() >= block.Bits() {
		return out
	}
	bit := p.Bits()
	right := p.Addr().AsSlice()
	right[bit/8] |= byte(0x80 >> (bit % 8))
	rightAddr, _ := netip.AddrFromSlice(right)
	out = subtractPrefix(out, netip.PrefixFrom(p.Addr(), bit+1), block)
	return subtractPrefix(out, netip.PrefixFrom(rightAddr, bit+1), block)
}

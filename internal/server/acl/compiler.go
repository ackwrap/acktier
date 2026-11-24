package acl

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/acktier/acktier/pkg/types"
)

var (
	allIPv4 = netip.MustParsePrefix("0.0.0.0/0")
	allIPv6 = netip.MustParsePrefix("::/0")
)

type portRange struct {
	start uint16
	end   uint16
}

// Validate checks syntax of an ACLPolicy before saving it to the store.
func Validate(pol types.ACLPolicy) error {
	for i, entry := range pol.ACLs {
		act := strings.ToLower(strings.TrimSpace(entry.Action))
		if act != "" && act != "accept" && act != "drop" {
			return fmt.Errorf("acl rule #%d: invalid action %q", i+1, entry.Action)
		}
		if len(entry.Src) == 0 || len(entry.Dst) == 0 {
			return fmt.Errorf("acl rule #%d: src and dst cannot be empty", i+1)
		}
		if _, err := parseProtos(entry.Proto); err != nil {
			return fmt.Errorf("acl rule #%d: %w", i+1, err)
		}
		for _, d := range entry.Dst {
			if _, _, err := splitDstAndPorts(d); err != nil {
				return fmt.Errorf("acl rule #%d dst %q: %w", i+1, d, err)
			}
		}
	}
	return nil
}

// CompileForNode compiles the global ACLPolicy into minimal FilterRules relevant to targetNode.
// When pol.ACLs is empty, returns nil (signaling default allow-all overlay mode).
// When pol.ACLs is non-empty, Zero-Trust default-deny applies unless an explicit rule matches!
func CompileForNode(pol types.ACLPolicy, self types.PeerNode, allNodes []types.PeerNode) []types.FilterRule {
	if len(pol.ACLs) == 0 {
		return nil
	}

	var out []types.FilterRule
	for _, entry := range pol.ACLs {
		action := types.FilterAccept
		if strings.EqualFold(strings.TrimSpace(entry.Action), "drop") {
			action = types.FilterDrop
		}

		protos, err := parseProtos(entry.Proto)
		if err != nil {
			continue
		}

		var srcPfx []netip.Prefix
		for _, s := range entry.Src {
			srcPfx = append(srcPfx, resolveSelector(s, pol, allNodes, true)...)
		}
		srcPfx = dedupPrefixes(srcPfx)
		if len(srcPfx) == 0 {
			continue
		}

		for _, rawDst := range entry.Dst {
			sel, pRanges, err := splitDstAndPorts(rawDst)
			if err != nil {
				continue
			}
			dstPfx := dedupPrefixes(resolveSelector(sel, pol, allNodes, false))
			if len(dstPfx) == 0 {
				continue
			}
			for _, proto := range protos {
				for _, pr := range pRanges {
					out = append(out, types.FilterRule{
						Action:       action,
						SrcPrefixes:  srcPfx,
						DstPrefixes:  dstPfx,
						IPProto:      proto,
						DstPortStart: pr.start,
						DstPortEnd:   pr.end,
					})
				}
			}
		}
	}

	// Ensure explicit trailing default-drop sentinel when ACLs are active so even if every rule matched
	// another node, the client knows ACL enforcement is enabled (non-empty slice).
	out = append(out, types.FilterRule{
		Action:      types.FilterDrop,
		SrcPrefixes: []netip.Prefix{allIPv4, allIPv6},
		DstPrefixes: []netip.Prefix{allIPv4, allIPv6},
	})
	return out
}

func parseProtos(p string) ([]uint8, error) {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "", "*", "any":
		return []uint8{0}, nil
	case "tcp":
		return []uint8{6}, nil
	case "udp":
		return []uint8{17}, nil
	case "icmp":
		return []uint8{1, 58}, nil
	default:
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return nil, fmt.Errorf("unsupported proto %q", p)
		}
		return []uint8{uint8(n)}, nil
	}
}

func splitDstAndPorts(raw string) (selector string, ranges []portRange, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "*" || raw == "*:*" {
		return "*", []portRange{{0, 65535}}, nil
	}
	// If the whole string is a bare IP address or CIDR (notably unbracketed IPv6), there is no port suffix.
	if _, aErr := netip.ParseAddr(raw); aErr == nil {
		return raw, []portRange{{0, 65535}}, nil
	}
	if _, pErr := netip.ParsePrefix(raw); pErr == nil {
		return raw, []portRange{{0, 65535}}, nil
	}
	idx := strings.LastIndex(raw, ":")
	if idx <= 0 {
		return raw, []portRange{{0, 65535}}, nil
	}
	selector = strings.Trim(raw[:idx], "[]")
	portSpec := strings.TrimSpace(raw[idx+1:])
	if portSpec == "*" || portSpec == "" {
		return selector, []portRange{{0, 65535}}, nil
	}

	for _, part := range strings.Split(portSpec, ",") {
		part = strings.TrimSpace(part)
		if dash := strings.IndexByte(part, '-'); dash > 0 {
			p1, e1 := strconv.Atoi(part[:dash])
			p2, e2 := strconv.Atoi(part[dash+1:])
			if e1 != nil || e2 != nil || p1 < 1 || p2 > 65535 || p1 > p2 {
				return "", nil, fmt.Errorf("invalid port range %q", part)
			}
			ranges = append(ranges, portRange{uint16(p1), uint16(p2)})
		} else {
			p, e := strconv.Atoi(part)
			if e != nil || p < 1 || p > 65535 {
				return "", nil, fmt.Errorf("invalid port %q", part)
			}
			ranges = append(ranges, portRange{uint16(p), uint16(p)})
		}
	}
	return selector, ranges, nil
}

func resolveSelector(sel string, pol types.ACLPolicy, nodes []types.PeerNode, isSrc bool) []netip.Prefix {
	sel = strings.TrimSpace(sel)
	if sel == "*" || strings.EqualFold(sel, "autogroup:internet") && !isSrc {
		return []netip.Prefix{allIPv4, allIPv6}
	}

	// Named host alias?
	if hostVal, ok := pol.Hosts[sel]; ok {
		return parseIPOrPrefix(hostVal)
	}

	// Group expansion?
	if strings.HasPrefix(sel, "group:") {
		members := pol.Groups[sel]
		var out []netip.Prefix
		for _, m := range members {
			if !strings.HasPrefix(m, "group:") {
				out = append(out, resolveSelector(m, pol, nodes, isSrc)...)
			}
		}
		return out
	}

	// Tag selector?
	if strings.HasPrefix(sel, "tag:") {
		var out []netip.Prefix
		for _, n := range nodes {
			if hasTag(n.Tags, sel) {
				out = append(out, nodePrefixes(n, !isSrc)...)
			}
		}
		return out
	}

	// Direct IP or CIDR?
	if pfxs := parseIPOrPrefix(sel); len(pfxs) > 0 {
		return pfxs
	}

	// Node name or hostname match
	var out []netip.Prefix
	for _, n := range nodes {
		if strings.EqualFold(n.Name, sel) || strings.EqualFold(n.Hostname, sel) {
			out = append(out, nodePrefixes(n, !isSrc)...)
		}
	}
	return out
}

func nodePrefixes(n types.PeerNode, includeApprovedSubnets bool) []netip.Prefix {
	var out []netip.Prefix
	if n.IPv4.IsValid() {
		out = append(out, netip.PrefixFrom(n.IPv4, 32))
	}
	if n.IPv6.IsValid() {
		out = append(out, netip.PrefixFrom(n.IPv6, 128))
	}
	if includeApprovedSubnets {
		out = append(out, n.ApprovedRoutes...)
	}
	return out
}

func parseIPOrPrefix(s string) []netip.Prefix {
	if pfx, err := netip.ParsePrefix(s); err == nil {
		return []netip.Prefix{pfx.Masked()}
	}
	if ip, err := netip.ParseAddr(s); err == nil {
		bits := 32
		if ip.Is6() {
			bits = 128
		}
		return []netip.Prefix{netip.PrefixFrom(ip, bits)}
	}
	return nil
}

func hasTag(tags []string, target string) bool {
	for _, t := range tags {
		if strings.EqualFold(t, target) {
			return true
		}
	}
	return false
}

func dedupPrefixes(in []netip.Prefix) []netip.Prefix {
	seen := make(map[netip.Prefix]bool, len(in))
	out := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		if p.IsValid() && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

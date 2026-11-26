package acl

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/ackwrap/acktier/pkg/types"
)

var (
	allIPv4 = netip.MustParsePrefix("0.0.0.0/0")
	allIPv6 = netip.MustParsePrefix("::/0")
)

type portRange struct {
	start uint16
	end   uint16
}

// Validate checks syntax and security invariants of an ACLPolicy before saving it to the store.
// Self-reported node names / hostnames are rejected: ACLs must reference immutable node IDs, nodekeys,
// admin-assigned tags, admin-defined groups/hosts, or explicit IPs/CIDRs.
func Validate(pol types.ACLPolicy) error {
	for alias, val := range pol.Hosts {
		if strings.TrimSpace(alias) == "" {
			return fmt.Errorf("acl hosts: empty host alias")
		}
		if len(parseIPOrPrefix(strings.TrimSpace(val))) == 0 {
			return fmt.Errorf("acl hosts[%q]: invalid IP or CIDR %q", alias, val)
		}
	}
	for grp, members := range pol.Groups {
		if !strings.HasPrefix(grp, "group:") || len(strings.TrimPrefix(grp, "group:")) == 0 {
			return fmt.Errorf("acl groups: group name %q must start with 'group:'", grp)
		}
		for _, m := range members {
			if strings.HasPrefix(strings.TrimSpace(m), "group:") {
				return fmt.Errorf("acl groups[%q]: nested group reference %q is not allowed", grp, m)
			}
			if err := validatePrincipalSelector(m, pol, true); err != nil {
				return fmt.Errorf("acl groups[%q] member %q: %w", grp, m, err)
			}
		}
	}

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
		for _, s := range entry.Src {
			if err := validatePrincipalSelector(s, pol, true); err != nil {
				return fmt.Errorf("acl rule #%d src %q: %w", i+1, s, err)
			}
		}
		for _, d := range entry.Dst {
			sel, _, err := splitDstAndPorts(d)
			if err != nil {
				return fmt.Errorf("acl rule #%d dst %q: %w", i+1, d, err)
			}
			if err := validatePrincipalSelector(sel, pol, false); err != nil {
				return fmt.Errorf("acl rule #%d dst %q: %w", i+1, d, err)
			}
		}
	}
	return nil
}

func validatePrincipalSelector(sel string, pol types.ACLPolicy, isSrc bool) error {
	sel = strings.TrimSpace(sel)
	if sel == "*" {
		return nil
	}
	if strings.EqualFold(sel, "autogroup:internet") {
		if isSrc {
			return fmt.Errorf("autogroup:internet cannot be used as src")
		}
		return nil
	}
	if _, ok := pol.Hosts[sel]; ok {
		return nil
	}
	if strings.HasPrefix(sel, "group:") {
		if _, ok := pol.Groups[sel]; !ok {
			return fmt.Errorf("undefined group %q", sel)
		}
		return nil
	}
	if strings.HasPrefix(sel, "tag:") {
		if len(strings.TrimSpace(strings.TrimPrefix(sel, "tag:"))) == 0 {
			return fmt.Errorf("empty tag selector")
		}
		return nil
	}
	if _, ok := parseNodeIDSelector(sel); ok {
		return nil
	}
	if strings.HasPrefix(sel, "nodekey:") {
		pk, err := types.ParsePublicKey(sel)
		if err != nil || pk.IsZero() {
			return fmt.Errorf("invalid nodekey selector %q", sel)
		}
		return nil
	}
	if len(parseIPOrPrefix(sel)) > 0 {
		return nil
	}
	return fmt.Errorf("untrusted node-name selector %q is not allowed; use tag:<name>, node:<id>, nodekey:<hex>, group:<name>, hosts alias, or IP/CIDR", sel)
}

func parseNodeIDSelector(sel string) (types.NodeID, bool) {
	lower := strings.ToLower(strings.TrimSpace(sel))
	var rawID string
	if strings.HasPrefix(lower, "node:") {
		rawID = strings.TrimPrefix(lower, "node:")
	} else if strings.HasPrefix(lower, "id:") {
		rawID = strings.TrimPrefix(lower, "id:")
	} else {
		return 0, false
	}
	id, err := strconv.ParseUint(strings.TrimSpace(rawID), 10, 64)
	if err != nil || id == 0 {
		return 0, false
	}
	return types.NodeID(id), true
}

// CompileForNode compiles the global ACLPolicy into minimal FilterRules relevant to targetNode.
// When pol.ACLs is empty, returns nil (signaling default allow-all overlay mode).
// When pol.ACLs is non-empty, Zero-Trust default-deny applies unless an explicit rule matches!
func CompileForNode(pol types.ACLPolicy, _ types.PeerNode, allNodes []types.PeerNode) []types.FilterRule {
	if len(pol.ACLs) == 0 {
		return nil
	}

	var out []types.FilterRule
	internet := sync.OnceValue(func() []netip.Prefix { return internetPrefixes(allNodes) })
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
			srcPfx = append(srcPfx, resolveSelector(s, pol, allNodes, true, internet)...)
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
			dstPfx := dedupPrefixes(resolveSelector(sel, pol, allNodes, false, internet))
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

	// Trailing default-drop sentinel ensures Zero-Trust default-deny whenever ACLs are active.
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
	// Check if raw without port is `node:<id>` or `tag:<name>` without port (e.g. "tag:dev" or "node:2")
	// Note: "tag:dev" has idx=3, raw[idx+1:]="dev" which is NOT a port! Wait: in ACL Dst syntax,
	// "tag:dev:80" has LastIndex(':') at ":80"; what if someone writes Dst=["tag:dev"] or Dst=["node:2"]?
	// Let's handle bare principal selectors without a trailing port cleanly!
	portSpec := strings.TrimSpace(raw[idx+1:])
	prefixPart := raw[:idx]
	if !strings.Contains(prefixPart, ":") && (strings.EqualFold(prefixPart, "tag") || strings.EqualFold(prefixPart, "group") || strings.EqualFold(prefixPart, "node") || strings.EqualFold(prefixPart, "id") || strings.EqualFold(prefixPart, "nodekey") || strings.EqualFold(prefixPart, "autogroup")) {
		// Entire string is e.g. "tag:dev", "node:1", "autogroup:internet" with no `:port` suffix!
		return raw, []portRange{{0, 65535}}, nil
	}

	selector = strings.Trim(prefixPart, "[]")
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

func resolveSelector(sel string, pol types.ACLPolicy, nodes []types.PeerNode, isSrc bool, internet func() []netip.Prefix) []netip.Prefix {
	sel = strings.TrimSpace(sel)
	if sel == "*" {
		return []netip.Prefix{allIPv4, allIPv6}
	}
	if strings.EqualFold(sel, "autogroup:internet") {
		if isSrc {
			return nil
		}
		return internet()
	}

	if hostVal, ok := pol.Hosts[sel]; ok {
		return parseIPOrPrefix(strings.TrimSpace(hostVal))
	}

	if strings.HasPrefix(sel, "group:") {
		members := pol.Groups[sel]
		var out []netip.Prefix
		for _, m := range members {
			if !strings.HasPrefix(m, "group:") {
				out = append(out, resolveSelector(m, pol, nodes, isSrc, internet)...)
			}
		}
		return out
	}

	if strings.HasPrefix(sel, "tag:") {
		var out []netip.Prefix
		for _, n := range nodes {
			if hasTag(n.Tags, sel) {
				out = append(out, nodePrefixes(n, !isSrc)...)
			}
		}
		return out
	}

	if targetID, ok := parseNodeIDSelector(sel); ok {
		for _, n := range nodes {
			if n.ID == targetID {
				return nodePrefixes(n, !isSrc)
			}
		}
		return nil
	}

	if strings.HasPrefix(strings.ToLower(sel), "nodekey:") {
		if pk, err := types.ParsePublicKey(sel); err == nil && !pk.IsZero() {
			for _, n := range nodes {
				if n.NodeKey == pk {
					return nodePrefixes(n, !isSrc)
				}
			}
		}
		return nil
	}

	if pfxs := parseIPOrPrefix(sel); len(pfxs) > 0 {
		return pfxs
	}

	// Self-reported node names / hostnames are intentionally never matched here.
	return nil
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
		for _, rt := range n.ApprovedRoutes {
			// Default routes (0.0.0.0/0, ::/0) represent Exit Node capability and require explicit `*` or `autogroup:internet` ACLs.
			if rt.Bits() > 0 && !types.OverlapsOverlayOrSpecial(rt) {
				out = append(out, rt)
			}
		}
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

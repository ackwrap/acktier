package acl

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/ackwrap/acktier/pkg/types"
)

const (
	MaxRules = 4096
	// A signable snapshot fits in a 512 KiB payload; its serialized prefixes
	// cannot approach this count, even at their shortest representation.
	maxCompiledPrefixes = 128 * 1024
	maxCompileWork      = 1 << 20
)

var ErrTooComplex = errors.New("ACL expansion exceeds the compilation limit")

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

// Compile returns the ordered packet filter shared by all nodes. An empty ACL
// returns nil so callers can choose the default for their authorization mode.
// Overly complex policies return an error without exposing a partial filter.
func Compile(pol types.ACLPolicy, allNodes []types.PeerNode) ([]types.FilterRule, error) {
	if len(pol.ACLs) == 0 {
		return nil, nil
	}

	var out []types.FilterRule
	resolver := selectorResolver{policy: pol, nodes: allNodes, work: maxCompileWork}
	resolver.internet = sync.OnceValues(func() ([]netip.Prefix, error) {
		return internetPrefixes(allNodes, &resolver.work)
	})
	prefixesLeft := maxCompiledPrefixes - 4 // Reserve the final default-drop rule's prefixes.
	for _, entry := range pol.ACLs {
		if !resolver.work.take(1) {
			return nil, ErrTooComplex
		}
		action := types.FilterAccept
		if strings.EqualFold(strings.TrimSpace(entry.Action), "drop") {
			action = types.FilterDrop
		}

		protos, err := parseProtos(entry.Proto)
		if err != nil {
			return nil, err
		}

		var src prefixSet
		for _, s := range entry.Src {
			if err := resolver.addSelector(&src, s, true); err != nil {
				return nil, err
			}
		}
		if len(src.prefixes) == 0 {
			continue
		}

		for _, rawDst := range entry.Dst {
			sel, pRanges, err := splitDstAndPorts(rawDst)
			if err != nil {
				return nil, err
			}
			var dst prefixSet
			if err := resolver.addSelector(&dst, sel, false); err != nil {
				return nil, err
			}
			if len(dst.prefixes) == 0 {
				continue
			}
			if len(pRanges) > (MaxRules-1-len(out))/len(protos) {
				return nil, ErrTooComplex
			}
			nRules := len(pRanges) * len(protos)
			prefixesPerRule := len(src.prefixes) + len(dst.prefixes)
			if nRules > prefixesLeft/prefixesPerRule {
				return nil, ErrTooComplex
			}
			prefixesLeft -= nRules * prefixesPerRule
			for _, proto := range protos {
				for _, pr := range pRanges {
					out = append(out, types.FilterRule{
						Action:       action,
						SrcPrefixes:  src.prefixes,
						DstPrefixes:  dst.prefixes,
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
	return out, nil
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

	for part := range strings.SplitSeq(portSpec, ",") {
		if len(ranges) == MaxRules-1 {
			return "", nil, ErrTooComplex
		}
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

// compileWork also covers selectors that match nothing and duplicates that
// never become output rules.
type compileWork int

func (w *compileWork) take(steps int) bool {
	if steps > int(*w) {
		return false
	}
	*w -= compileWork(steps)
	return true
}

type prefixSet struct {
	prefixes []netip.Prefix
	seen     map[netip.Prefix]struct{}
}

func (s *prefixSet) add(p netip.Prefix) error {
	if _, seen := s.seen[p]; seen || !p.IsValid() {
		return nil
	}
	if len(s.prefixes) == maxCompiledPrefixes {
		return ErrTooComplex
	}
	if s.seen == nil {
		s.seen = make(map[netip.Prefix]struct{})
	}
	s.seen[p] = struct{}{}
	s.prefixes = append(s.prefixes, p)
	return nil
}

type selectorResolver struct {
	policy   types.ACLPolicy
	nodes    []types.PeerNode
	work     compileWork
	internet func() ([]netip.Prefix, error)
}

func (r *selectorResolver) addAll(out *prefixSet, prefixes []netip.Prefix) error {
	if !r.work.take(len(prefixes)) {
		return ErrTooComplex
	}
	for _, p := range prefixes {
		if err := out.add(p); err != nil {
			return err
		}
	}
	return nil
}

func (r *selectorResolver) addSelector(out *prefixSet, sel string, isSrc bool) error {
	if !r.work.take(1 + len(sel)/64) {
		return ErrTooComplex
	}
	sel = strings.TrimSpace(sel)
	if sel == "*" {
		return r.addAll(out, []netip.Prefix{allIPv4, allIPv6})
	}
	if strings.EqualFold(sel, "autogroup:internet") {
		if isSrc {
			return nil
		}
		prefixes, err := r.internet()
		if err != nil {
			return err
		}
		return r.addAll(out, prefixes)
	}

	if hostVal, ok := r.policy.Hosts[sel]; ok {
		return r.addAll(out, parseIPOrPrefix(strings.TrimSpace(hostVal)))
	}

	if strings.HasPrefix(sel, "group:") {
		for _, member := range r.policy.Groups[sel] {
			if strings.HasPrefix(strings.TrimSpace(member), "group:") {
				return errors.New("nested ACL groups are not allowed")
			}
			if err := r.addSelector(out, member, isSrc); err != nil {
				return err
			}
		}
		return nil
	}

	if strings.HasPrefix(sel, "tag:") {
		if !r.work.take(len(r.nodes)) {
			return ErrTooComplex
		}
		for _, n := range r.nodes {
			for _, tag := range n.Tags {
				if !r.work.take(1 + min(len(tag), len(sel))/64) {
					return ErrTooComplex
				}
				if strings.EqualFold(tag, sel) {
					if err := r.addNode(out, n, isSrc); err != nil {
						return err
					}
					break
				}
			}
		}
		return nil
	}

	if targetID, ok := parseNodeIDSelector(sel); ok {
		if !r.work.take(len(r.nodes)) {
			return ErrTooComplex
		}
		for _, n := range r.nodes {
			if n.ID == targetID {
				return r.addNode(out, n, isSrc)
			}
		}
		return nil
	}

	if strings.HasPrefix(strings.ToLower(sel), "nodekey:") {
		if pk, err := types.ParsePublicKey(sel); err == nil && !pk.IsZero() {
			if !r.work.take(len(r.nodes)) {
				return ErrTooComplex
			}
			for _, n := range r.nodes {
				if n.NodeKey == pk {
					return r.addNode(out, n, isSrc)
				}
			}
		}
		return nil
	}

	// Self-reported node names / hostnames are intentionally never matched here.
	return r.addAll(out, parseIPOrPrefix(sel))
}

func (r *selectorResolver) addNode(out *prefixSet, n types.PeerNode, isSrc bool) error {
	if n.IPv4.IsValid() {
		if err := out.add(netip.PrefixFrom(n.IPv4, 32)); err != nil {
			return err
		}
	}
	if n.IPv6.IsValid() {
		if err := out.add(netip.PrefixFrom(n.IPv6, 128)); err != nil {
			return err
		}
	}
	if !isSrc {
		if !r.work.take(len(n.ApprovedRoutes)) {
			return ErrTooComplex
		}
		for _, rt := range n.ApprovedRoutes {
			// Exit routes require an explicit wildcard or Internet grant.
			if rt.Bits() > 0 && !types.OverlapsOverlayOrSpecial(rt) {
				if err := out.add(rt); err != nil {
					return err
				}
			}
		}
	}
	return nil
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

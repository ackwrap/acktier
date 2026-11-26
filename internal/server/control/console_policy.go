package control

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ackwrap/acktier/internal/owner"
	"github.com/ackwrap/acktier/internal/server/store"
	"github.com/ackwrap/acktier/pkg/types"
)

// ruleView is a human-readable rendering of one compiled filter rule.
type ruleView struct {
	Action string   `json:"action"`
	Proto  string   `json:"proto"`
	Src    []string `json:"src"`
	Dst    []string `json:"dst"`
	Ports  string   `json:"ports"`
}

type aclEntryView struct {
	Index  int      `json:"index"`
	Action string   `json:"action"`
	Proto  string   `json:"proto"`
	Src    []string `json:"src"`
	Dst    []string `json:"dst"`
}

type issue struct {
	Level   string `json:"level"` // "error" | "warning"
	Message string `json:"message"`
}

type memberChange struct {
	Member owner.Member `json:"member"`
	Fields []string     `json:"fields"`
}

type policyDiff struct {
	Added       []owner.Member `json:"added"`
	Removed     []owner.Member `json:"removed"`
	Changed     []memberChange `json:"changed"`
	RulesBefore int            `json:"rulesBefore"`
	RulesAfter  int            `json:"rulesAfter"`
	RulesSame   bool           `json:"rulesSame"`
	DNSChanged  bool           `json:"dnsChanged"`
	STUNChanged bool           `json:"stunChanged"`
	HasActive   bool           `json:"hasActive"`
}

type policyAnalysis struct {
	Valid      bool           `json:"valid"`
	Issues     []issue        `json:"issues"`
	Rules      []ruleView     `json:"rules"`
	ACLEntries []aclEntryView `json:"aclEntries"`
	Diff       policyDiff     `json:"diff"`
	BaseStale  bool           `json:"baseStale"`
}

func protoName(p uint8) string {
	switch p {
	case 0:
		return "any"
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	}
	return strconv.Itoa(int(p))
}

func portsLabel(start, end uint16) string {
	switch {
	case start == 0 && (end == 0 || end == 65535):
		return "*"
	case start == end:
		return strconv.Itoa(int(start))
	}
	return fmt.Sprintf("%d-%d", start, end)
}

// memberLabels maps a member's host prefixes to its signed name.
func memberLabels(members []owner.Member) map[netip.Prefix]string {
	out := make(map[netip.Prefix]string, len(members)*2)
	for _, m := range members {
		if m.IPv4.IsValid() {
			out[netip.PrefixFrom(m.IPv4, 32)] = m.Name
		}
		if m.IPv6.IsValid() {
			out[netip.PrefixFrom(m.IPv6, 128)] = m.Name
		}
		for _, rt := range m.Routes {
			if rt.Bits() > 0 {
				out[rt] = m.Name + " 子网"
			}
		}
	}
	return out
}

func prefixLabels(prefixes []netip.Prefix, names map[netip.Prefix]string) []string {
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		switch {
		case p.Bits() == 0:
			out = append(out, p.String()+"（全部）")
		case names[p] != "":
			out = append(out, names[p]+" · "+p.String())
		default:
			out = append(out, p.String())
		}
	}
	return out
}

func renderRules(rules []types.FilterRule, members []owner.Member) []ruleView {
	names := memberLabels(members)
	out := make([]ruleView, 0, len(rules))
	for _, r := range rules {
		out = append(out, ruleView{
			Action: string(r.Action), Proto: protoName(r.IPProto),
			Src: prefixLabels(r.SrcPrefixes, names), Dst: prefixLabels(r.DstPrefixes, names),
			Ports: portsLabel(r.DstPortStart, r.DstPortEnd),
		})
	}
	return out
}

func sameJSON(a, b any) bool {
	ra, errA := json.Marshal(a)
	rb, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(ra) == string(rb)
}

func diffMembers(before, after []owner.Member) (added, removed []owner.Member, changed []memberChange) {
	old := make(map[types.PublicKey]owner.Member, len(before))
	for _, m := range before {
		old[m.NodeKey] = m
	}
	seen := make(map[types.PublicKey]bool, len(after))
	for _, m := range after {
		seen[m.NodeKey] = true
		prev, ok := old[m.NodeKey]
		if !ok {
			added = append(added, m)
			continue
		}
		var fields []string
		if prev.ID != m.ID {
			fields = append(fields, "ID")
		}
		if prev.Name != m.Name {
			fields = append(fields, "名称")
		}
		if prev.IPv4 != m.IPv4 || prev.IPv6 != m.IPv6 {
			fields = append(fields, "地址")
		}
		if !slices.Equal(prev.Routes, m.Routes) {
			fields = append(fields, "子网/出口")
		}
		if !slices.Equal(prev.Tags, m.Tags) {
			fields = append(fields, "标签")
		}
		if len(fields) > 0 {
			changed = append(changed, memberChange{Member: m, Fields: fields})
		}
	}
	for _, m := range before {
		if !seen[m.NodeKey] {
			removed = append(removed, m)
		}
	}
	return added, removed, changed
}

func snapshotDiff(active *owner.Verified, next owner.Snapshot) policyDiff {
	d := policyDiff{RulesAfter: len(next.PacketFilter)}
	if active == nil {
		d.Added = next.Members
		return d
	}
	cur := active.Snapshot
	d.HasActive = true
	d.Added, d.Removed, d.Changed = diffMembers(cur.Members, next.Members)
	d.RulesBefore = len(cur.PacketFilter)
	d.RulesSame = sameJSON(cur.PacketFilter, next.PacketFilter)
	d.DNSChanged = !sameJSON(cur.DNS, next.DNS)
	d.STUNChanged = cur.STUNAddr != next.STUNAddr || cur.STUNAltAddr != next.STUNAltAddr
	return d
}

func friendlyPolicyError(err error) string {
	msg := err.Error()
	lower := strings.ToLower(msg)
	if strings.Contains(lower, `proto "quic"`) || strings.Contains(lower, `proto "wss"`) {
		return msg + "（QUIC/WSS 是传输方式，不是 ACL 协议；业务端口请使用 tcp 或 udp）"
	}
	return msg
}

// analyzePolicy validates a draft exactly as the owner's CLI would and adds
// review hints. It never signs or changes the active publication.
func analyzePolicy(p owner.Policy, baseVersion uint64, active *owner.Verified, records []store.StoredNode) policyAnalysis {
	a := policyAnalysis{Issues: []issue{}, Rules: []ruleView{}, ACLEntries: []aclEntryView{}}
	errorf := func(format string, args ...any) {
		a.Issues = append(a.Issues, issue{"error", fmt.Sprintf(format, args...)})
	}
	warnf := func(format string, args ...any) {
		a.Issues = append(a.Issues, issue{"warning", fmt.Sprintf(format, args...)})
	}
	for i, e := range p.ACL.ACLs {
		act := strings.ToLower(strings.TrimSpace(e.Action))
		if act == "" {
			act = "accept"
		}
		proto := strings.TrimSpace(e.Proto)
		if proto == "" {
			proto = "any"
		}
		a.ACLEntries = append(a.ACLEntries, aclEntryView{Index: i + 1, Action: act, Proto: proto, Src: e.Src, Dst: e.Dst})
	}

	if active != nil {
		a.BaseStale = baseVersion != active.Checkpoint.Version
		if a.BaseStale {
			warnf("草稿基于 v%d，当前生效的是 v%d。导出前请确认没有覆盖他人的变更。", baseVersion, active.Checkpoint.Version)
		}
	}

	snap, err := p.Snapshot(1, time.Now().UTC().Add(24*time.Hour))
	if err != nil {
		errorf("%s", friendlyPolicyError(err))
		return a // Never expand selectors from an invalid policy.
	}
	a.Rules = renderRules(snap.PacketFilter, p.Members)
	a.Diff = snapshotDiff(active, snap)

	if len(p.ACL.ACLs) == 0 {
		warnf("ACL 为空：签发后成员之间的所有业务流量都会被默认拒绝。")
	}
	ids := make(map[types.NodeID]bool, len(p.Members))
	keys := make(map[types.PublicKey]bool, len(p.Members))
	tags := make(map[string]bool)
	hasExit := false
	for _, m := range p.Members {
		ids[m.ID], keys[m.NodeKey] = true, true
		for _, t := range m.Tags {
			tags[strings.ToLower(t)] = true
		}
		for _, rt := range m.Routes {
			if rt.Bits() == 0 {
				hasExit = true
			}
		}
	}
	for _, e := range p.ACL.ACLs {
		for _, sel := range append(slices.Clone(e.Src), e.Dst...) {
			checkSelector(sel, p.ACL, ids, keys, tags, hasExit, true, warnf)
		}
		if strings.EqualFold(strings.TrimSpace(e.Action), "drop") {
			continue
		}
		if slices.Contains(e.Src, "*") && (slices.Contains(e.Dst, "*") || slices.Contains(e.Dst, "*:*")) {
			warnf("有规则允许任意来源访问任意目标和端口，相当于关闭 ACL。")
		}
	}

	reported := make(map[types.PublicKey]types.PeerNode, len(records))
	for _, r := range records {
		if !r.Node.KeyRevoked {
			reported[r.Node.NodeKey] = r.Node
		}
	}
	for _, m := range p.Members {
		node, ok := reported[m.NodeKey]
		if !ok {
			warnf("成员 %s 的公钥没有出现在中心的申请或连接记录里，请通过可信渠道核对。", m.Name)
			continue
		}
		for _, rt := range m.Routes {
			if rt.Bits() > 0 && !slices.Contains(node.AdvertisedRoutes, rt) {
				warnf("成员 %s 被批准了它没有申报的网段 %s。", m.Name, rt)
			}
		}
	}
	if len(a.Diff.Removed) > 0 {
		names := make([]string, 0, len(a.Diff.Removed))
		for _, m := range a.Diff.Removed {
			names = append(names, m.Name)
		}
		warnf("签发后将移除成员：%s。它们会失去组网权限。", strings.Join(names, "、"))
	}
	a.Valid = true
	return a
}

func checkSelector(raw string, pol types.ACLPolicy, ids map[types.NodeID]bool, keys map[types.PublicKey]bool,
	tags map[string]bool, hasExit, expandGroup bool, warnf func(string, ...any),
) {
	sel := strings.TrimSpace(raw)
	lower := strings.ToLower(sel)
	// Strip a trailing port list for dst selectors such as node:2:443.
	for _, prefix := range []string{"node:", "id:", "tag:", "autogroup:"} {
		if strings.HasPrefix(lower, prefix) {
			rest := sel[len(prefix):]
			if i := strings.IndexByte(rest, ':'); i >= 0 {
				sel = sel[:len(prefix)+i]
				lower = strings.ToLower(sel)
			}
		}
	}
	switch {
	case strings.HasPrefix(lower, "node:") || strings.HasPrefix(lower, "id:"):
		raw := sel[strings.IndexByte(sel, ':')+1:]
		if id, err := strconv.ParseUint(raw, 10, 64); err == nil && !ids[types.NodeID(id)] {
			warnf("选择器 %s 引用了不在成员表里的节点。", sel)
		}
	case strings.HasPrefix(lower, "tag:"):
		if !tags[lower] {
			warnf("没有成员带有标签 %s。", sel)
		}
	case strings.HasPrefix(lower, "nodekey:"):
		if k, err := types.ParsePublicKey(sel); err == nil && !keys[k] {
			warnf("选择器引用的节点公钥不在成员表里。")
		}
	case lower == "autogroup:internet":
		if !hasExit {
			warnf("规则引用了 autogroup:internet，但没有成员被批准为出口（0.0.0.0/0 或 ::/0）。")
		}
	case expandGroup && strings.HasPrefix(lower, "group:"):
		for _, m := range pol.Groups[sel] {
			// Groups may contain principals but never other groups.
			checkSelector(m, pol, ids, keys, tags, hasExit, false, warnf)
		}
	}
}

// nextMember assigns an ID, name and addresses that are free in the draft.
// It prefers the coordination record's addresses so peers keep stable IPs.
func nextMember(p owner.Policy, active *owner.Verified, rec *types.PeerNode, req owner.Member) (owner.Member, error) {
	usedIDs := make(map[types.NodeID]bool)
	usedNames := make(map[string]bool)
	usedIPs := make(map[netip.Addr]bool)
	var maxID types.NodeID
	consider := func(m owner.Member) {
		usedIDs[m.ID], usedNames[m.Name], usedIPs[m.IPv4] = true, true, true
		if m.IPv6.IsValid() {
			usedIPs[m.IPv6] = true
		}
		maxID = max(maxID, m.ID)
	}
	for _, m := range p.Members {
		if m.NodeKey == req.NodeKey {
			return owner.Member{}, fmt.Errorf("该公钥已在草稿成员表中")
		}
		consider(m)
	}
	if active != nil {
		for _, m := range active.Snapshot.Members {
			maxID = max(maxID, m.ID)
			if m.NodeKey == req.NodeKey && req.ID == 0 && !usedIDs[m.ID] {
				req.ID = m.ID // Keep a previously signed identity for this key.
			}
		}
	}
	m := req
	if m.ID == 0 {
		m.ID = maxID + 1
	} else if usedIDs[m.ID] {
		return owner.Member{}, fmt.Errorf("成员 ID %d 已被占用", m.ID)
	}
	if m.Name == "" {
		hint := ""
		if rec != nil {
			hint = rec.Hostname
		}
		base := store.SanitizeDNSLabel(hint, m.ID)
		m.Name = base
		for i := 2; usedNames[m.Name]; i++ {
			m.Name = fmt.Sprintf("%s-%d", base, i)
		}
	} else if usedNames[m.Name] {
		return owner.Member{}, fmt.Errorf("名称 %s 已被占用", m.Name)
	}
	if !m.IPv4.IsValid() {
		if rec != nil && types.OverlayIPv4Prefix.Contains(rec.IPv4) && !usedIPs[rec.IPv4] {
			m.IPv4 = rec.IPv4
		} else {
			ip := types.OverlayIPv4Prefix.Addr().Next()
			for ; types.OverlayIPv4Prefix.Contains(ip); ip = ip.Next() {
				if !usedIPs[ip] && ip != netip.MustParseAddr("100.100.100.100") {
					break
				}
			}
			m.IPv4 = ip
		}
	} else if usedIPs[m.IPv4] {
		return owner.Member{}, fmt.Errorf("地址 %s 已被占用", m.IPv4)
	}
	if !m.IPv6.IsValid() && rec != nil && types.OverlayIPv6Prefix.Contains(rec.IPv6) && !usedIPs[rec.IPv6] {
		m.IPv6 = rec.IPv6
	}
	return m, nil
}

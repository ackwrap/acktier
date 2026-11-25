package owner

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/acktier/acktier/pkg/types"
)

// Member is an owner-approved identity, not a copy of untrusted PeerNode metadata.
type Member struct {
	ID      types.NodeID    `json:"id"`
	NodeKey types.PublicKey `json:"nodeKey"`
	Name    string          `json:"name"`
	IPv4    netip.Addr      `json:"ipv4"`
	IPv6    netip.Addr      `json:"ipv6,omitempty"`
	Routes  []netip.Prefix  `json:"routes,omitempty"`
	Tags    []string        `json:"tags,omitempty"`
}

// Snapshot is the entire authorization for one network, signed independently
// of dynamic candidate endpoints, link costs and the transport's revision.
type Snapshot struct {
	NetworkID    string             `json:"networkId"`
	Version      uint64             `json:"version"`
	ExpiresAt    time.Time          `json:"expiresAt"`
	Members      []Member           `json:"members"`
	PacketFilter []types.FilterRule `json:"packetFilter"`
	DNS          types.DNSConfig    `json:"dns"`
	STUNAddr     string             `json:"stunAddr,omitempty"`
	STUNAltAddr  string             `json:"stunAltAddr,omitempty"`
}

// Peer builds the authorized identity and allowed source prefixes.
func (m Member) Peer() types.PeerNode {
	n := types.PeerNode{
		ID: m.ID, Name: m.Name, NodeKey: m.NodeKey, IPv4: m.IPv4, IPv6: m.IPv6,
		ApprovedRoutes: m.Routes, Tags: m.Tags,
	}
	if m.IPv4.IsValid() {
		n.AllowedIPs = append(n.AllowedIPs, netip.PrefixFrom(m.IPv4, 32))
	}
	if m.IPv6.IsValid() {
		n.AllowedIPs = append(n.AllowedIPs, netip.PrefixFrom(m.IPv6, 128))
	}
	for _, rt := range m.Routes {
		if rt.Bits() > 0 {
			n.AllowedIPs = append(n.AllowedIPs, rt)
		}
	}
	return n
}

func DenyAll() types.FilterRule {
	all := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	return types.FilterRule{Action: types.FilterDrop, SrcPrefixes: all, DstPrefixes: all}
}

func (s Snapshot) validate() error {
	if s.Version == 0 || s.ExpiresAt.IsZero() || len(s.Members) > 512 || len(s.PacketFilter) > 4096 {
		return errors.New("invalid authorization version, expiry, or size")
	}
	if len(s.PacketFilter) == 0 { // An empty filter in the legacy engine would allow all.
		return errors.New("owner authorization must contain a nonempty packet filter")
	}
	for _, f := range s.PacketFilter {
		if f.Action != types.FilterAccept && f.Action != types.FilterDrop {
			return errors.New("invalid authorization filter action")
		}
		if !validPrefixes(f.SrcPrefixes) || !validPrefixes(f.DstPrefixes) || f.DstPortEnd < f.DstPortStart {
			return errors.New("invalid authorization filter prefixes or ports")
		}
	}
	if s.DNS.MagicDNSSuffix != "" && !isDNSName(s.DNS.MagicDNSSuffix) {
		return errors.New("invalid MagicDNS suffix")
	}
	for _, addr := range []string{s.STUNAddr, s.STUNAltAddr} {
		if addr == "" {
			continue
		}
		ap, err := netip.ParseAddrPort(addr)
		if err != nil || ap.Port() == 0 || ap.Addr().Zone() != "" || ap.Addr().Is4In6() {
			return errors.New("signed STUN addresses must be literal IP:port values")
		}
	}
	keys := make(map[types.PublicKey]bool)
	ids := make(map[types.NodeID]bool)
	names := make(map[string]bool)
	ips := make(map[netip.Addr]bool)
	magicV4 := netip.MustParseAddr("100.100.100.100")
	magicV6 := netip.MustParseAddr("fd7a:115c:a1e0::53")
	for _, m := range s.Members {
		if m.ID == 0 || m.NodeKey.IsZero() || keys[m.NodeKey] || ids[m.ID] || names[m.Name] ||
			!isDNSName(m.Name) || strings.Contains(m.Name, ".") || m.Name == "localhost" {
			return fmt.Errorf("invalid or duplicate authorization member %q", m.Name)
		}
		if !types.OverlayIPv4Prefix.Contains(m.IPv4) || m.IPv4 == magicV4 || ips[m.IPv4] {
			return fmt.Errorf("invalid or duplicate member IPv4 for %q", m.Name)
		}
		if m.IPv6.IsValid() {
			if !types.OverlayIPv6Prefix.Contains(m.IPv6) || m.IPv6 == magicV6 || ips[m.IPv6] {
				return fmt.Errorf("invalid or duplicate member IPv6 for %q", m.Name)
			}
			ips[m.IPv6] = true
		}
		keys[m.NodeKey], ids[m.ID], names[m.Name], ips[m.IPv4] = true, true, true, true
		if len(m.Routes) > 64 {
			return fmt.Errorf("too many routes for %q", m.Name)
		}
		for _, p := range m.Routes {
			if p != p.Masked() || types.OverlapsOverlayOrSpecial(p) {
				return fmt.Errorf("invalid approved route %s for %q", p, m.Name)
			}
		}
	}
	return nil
}

func validPrefixes(prefixes []netip.Prefix) bool {
	if len(prefixes) == 0 {
		return false
	}
	for _, p := range prefixes {
		if !p.IsValid() || p.Addr().Is4In6() || p != p.Masked() {
			return false
		}
	}
	return true
}

// Project builds a NetMap from verified authority. Only explicitly listed
// transport fields from a dynamic map may influence it, and only by key.
func (v *Verified) Project(hints types.NetMap, self types.PublicKey, relay types.RelayNode) types.NetMap {
	candidates := make(map[types.PublicKey]types.PeerNode)
	for _, p := range hints.Peers {
		if v.Contains(p.NodeKey) {
			candidates[p.NodeKey] = p
		}
	}
	relay.STUNAddr, relay.STUNAltAddr = v.Snapshot.STUNAddr, v.Snapshot.STUNAltAddr
	nm := types.NetMap{
		OwnerNetworkID: v.Snapshot.NetworkID,
		Revision:       hints.Revision, UpdatedAt: hints.UpdatedAt,
		PacketFilter: v.Snapshot.PacketFilter, DNS: v.Snapshot.DNS,
		Relays: []types.RelayNode{relay},
	}
	for _, m := range v.Snapshot.Members {
		p := m.Peer()
		if p.NodeKey == self {
			nm.Self = p
			continue
		}
		hint := candidates[p.NodeKey]
		p.Online, p.CanRelay = hint.Online, hint.CanRelay
		p.Endpoints = hint.Endpoints
		for _, link := range hint.Links {
			if v.Contains(link.Target) {
				p.Links = append(p.Links, link)
			}
		}
		nm.Peers = append(nm.Peers, p)
	}
	return nm
}

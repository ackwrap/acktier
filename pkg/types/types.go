package types

import (
	"net/netip"
	"time"
)

// NodeID uniquely identifies a registered node in the control plane.
type NodeID uint64

// TransportProto identifies the underlying transport protocol of an endpoint.
type TransportProto string

const (
	ProtoUDP  TransportProto = "udp"
	ProtoTCP  TransportProto = "tcp"
	ProtoQUIC TransportProto = "quic"
	ProtoWSS  TransportProto = "wss"
)

// Endpoint describes a reachable network address and transport protocol for a peer.
type Endpoint struct {
	Proto TransportProto `json:"proto"`
	Addr  string         `json:"addr"` // host:port or ip:port
	IsLAN bool           `json:"isLan,omitempty"`
}

// RelayMode controls whether a node acts as a peer-to-peer ciphertext relay (stepping-stone) for other nodes.
type RelayMode string

const (
	RelayModeAuto RelayMode = "auto" // Default: auto-enable CanRelay when public IP / open-public STUN / UPnP is detected
	RelayModeOn   RelayMode = "on"   // Force enable peer relay regardless of NAT type
	RelayModeOff  RelayMode = "off"  // Never relay transit traffic for other peers (e.g. metered VPS)
)

// PeerLink reports a verified direct L4/L7 link, smoothed RTT, jitter, and packet loss rate to a neighbor peer.
type PeerLink struct {
	Target       PublicKey      `json:"target"`
	RTTMillis    float64        `json:"rttMillis"`
	JitterMillis float64        `json:"jitterMillis,omitempty"`
	LossRate     float64        `json:"lossRate,omitempty"` // 0.0 .. 1.0
	Proto        TransportProto `json:"proto,omitempty"`
}

// EffectiveCostMs computes the quality-adjusted link cost in ms (penalizing jitter and packet loss).
func (pl PeerLink) EffectiveCostMs() float64 {
	rtt := pl.RTTMillis
	if rtt <= 0 {
		rtt = 10.0
	}
	return rtt + 2.0*pl.JitterMillis + 300.0*pl.LossRate
}

// Overlay & special IP ranges used to separate destination routing from source-IP authorization.
var (
	OverlayIPv4Prefix   = netip.MustParsePrefix("100.64.0.0/10")
	OverlayIPv6Prefix   = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	loopbackIPv4Prefix  = netip.MustParsePrefix("127.0.0.0/8")
	loopbackIPv6Prefix  = netip.MustParsePrefix("::1/128")
	linkLocalIPv4Prefix = netip.MustParsePrefix("169.254.0.0/16")
	linkLocalIPv6Prefix = netip.MustParsePrefix("fe80::/10")
	multicastIPv4Prefix = netip.MustParsePrefix("224.0.0.0/4")
	multicastIPv6Prefix = netip.MustParsePrefix("ff00::/8")
	thisNetIPv4Prefix   = netip.MustParsePrefix("0.0.0.0/8")
)

// IsOverlayAddr reports whether ip belongs to AckTier's virtual CGNAT or ULA address space.
func IsOverlayAddr(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	if ip.Is4() {
		return OverlayIPv4Prefix.Contains(ip)
	}
	return OverlayIPv6Prefix.Contains(ip)
}

// IsSpecialNonRoutableAddr reports whether ip is loopback, unspecified, link-local, multicast, or broadcast.
func IsSpecialNonRoutableAddr(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return true
	}
	if ip.Is4() {
		a4 := ip.As4()
		if a4[0] == 0 || (a4[0] == 255 && a4[1] == 255 && a4[2] == 255 && a4[3] == 255) {
			return true
		}
	}
	return false
}

// OverlapsOverlayOrSpecial reports whether a non-default CIDR (pfx.Bits() > 0) overlaps overlay,
// loopback, link-local, unspecified, or multicast space and therefore must not be approved as a subnet route.
func OverlapsOverlayOrSpecial(pfx netip.Prefix) bool {
	if !pfx.IsValid() {
		return true
	}
	if pfx.Addr().Is4In6() {
		return true // Reject ambiguous mapped routes; use a native IPv4 CIDR.
	}
	pfx = pfx.Masked()
	if pfx.Bits() == 0 {
		return false
	}
	if pfx.Addr().Is4() {
		return pfx.Overlaps(OverlayIPv4Prefix) ||
			pfx.Overlaps(loopbackIPv4Prefix) ||
			pfx.Overlaps(linkLocalIPv4Prefix) ||
			pfx.Overlaps(multicastIPv4Prefix) ||
			pfx.Overlaps(thisNetIPv4Prefix)
	}
	return pfx.Overlaps(OverlayIPv6Prefix) ||
		pfx.Overlaps(loopbackIPv6Prefix) ||
		pfx.Overlaps(linkLocalIPv6Prefix) ||
		pfx.Overlaps(multicastIPv6Prefix)
}

// PeerNode represents a device in the AckTier overlay network.
type PeerNode struct {
	ID               NodeID         `json:"id"`
	Name             string         `json:"name"`
	Hostname         string         `json:"hostname"`
	OS               string         `json:"os"`
	MachineKey       PublicKey      `json:"machineKey,omitempty"`
	NodeKey          PublicKey      `json:"nodeKey"`
	IPv4             netip.Addr     `json:"ipv4"`
	IPv6             netip.Addr     `json:"ipv6"`
	Endpoints        []Endpoint     `json:"endpoints,omitempty"`
	Links            []PeerLink     `json:"links,omitempty"`
	AllowedIPs       []netip.Prefix `json:"allowedIPs,omitempty"`
	AdvertisedRoutes []netip.Prefix `json:"advertisedRoutes,omitempty"`
	ApprovedRoutes   []netip.Prefix `json:"approvedRoutes,omitempty"`
	CanRelay         bool           `json:"canRelay,omitempty"`
	PreferredRelayID string         `json:"preferredRelayId,omitempty"`
	Tags             []string       `json:"tags,omitempty"`
	Online           bool           `json:"online"`
	KeyRevoked       bool           `json:"keyRevoked,omitempty"` // Admin view: excluded from NetMaps until recovery with a new key.
	LastSeen         time.Time      `json:"lastSeen"`
	CreatedAt        time.Time      `json:"createdAt"`
}

// FilterAction defines whether a matched packet is accepted or dropped.
type FilterAction string

const (
	FilterAccept FilterAction = "accept"
	FilterDrop   FilterAction = "drop"
)

// FilterRule represents a compiled packet filter rule enforced on the client data plane.
type FilterRule struct {
	Action       FilterAction   `json:"action"`
	SrcPrefixes  []netip.Prefix `json:"srcPrefixes"`
	DstPrefixes  []netip.Prefix `json:"dstPrefixes"`
	IPProto      uint8          `json:"ipProto,omitempty"` // 0=any, 1=ICMP, 6=TCP, 17=UDP, 58=ICMPv6
	DstPortStart uint16         `json:"dstPortStart,omitempty"`
	DstPortEnd   uint16         `json:"dstPortEnd,omitempty"`
}

// ACLGrantEntry defines one human-readable access rule in the central Zero-Trust ACL policy.
// Example: Action="accept", Src=["tag:dev", "alpha-node"], Proto="tcp", Dst=["tag:prod:80,443", "192.168.10.0/24:8000-9000"]
type ACLGrantEntry struct {
	Action string   `json:"action"`          // "accept" | "drop" (default "accept")
	Src    []string `json:"src"`             // "*", "tag:name", "group:name", node-name, IP, or CIDR
	Proto  string   `json:"proto,omitempty"` // "", "*", "tcp", "udp", "icmp"
	Dst    []string `json:"dst"`             // "<selector>:<port|start-end|*>"
}

// ACLPolicy represents the centralized Zero-Trust Access Control Policy managed on acktier-server.
type ACLPolicy struct {
	Groups map[string][]string `json:"groups,omitempty"` // "group:ops": ["admin-pc", "tag:admin"]
	Hosts  map[string]string   `json:"hosts,omitempty"`  // "corp-lan": "192.168.10.0/24"
	ACLs   []ACLGrantEntry     `json:"acls"`             // If empty, default allow-all within overlay
}

// RelayNode describes an official or self-hosted relay & STUN server.
type RelayNode struct {
	ID          string `json:"id"`
	Region      string `json:"region"`
	Host        string `json:"host"`
	RelayAddr   string `json:"relayAddr"`             // TCP/HTTP/TLS relay address host:port
	STUNAddr    string `json:"stunAddr"`              // Primary UDP STUN address host:port
	STUNAltAddr string `json:"stunAltAddr,omitempty"` // Secondary UDP STUN port for Cone vs Symmetric NAT detection
	UseTLS      bool   `json:"useTLS,omitempty"`
}

// DNSConfig holds MagicDNS and split-DNS settings distributed by the control server.
type DNSConfig struct {
	EnableMagicDNS bool     `json:"enableMagicDNS"`
	MagicDNSSuffix string   `json:"magicDNSSuffix"` // e.g., "ack.internal"
	Nameservers    []string `json:"nameservers,omitempty"`
}

// NetMap is the complete topological and security snapshot pushed to a specific node.
type NetMap struct {
	Revision     uint64       `json:"revision"`
	Self         PeerNode     `json:"self"`
	Peers        []PeerNode   `json:"peers"`
	Relays       []RelayNode  `json:"relays"`
	PacketFilter []FilterRule `json:"packetFilter,omitempty"`
	DNS          DNSConfig    `json:"dns"`
	UpdatedAt    time.Time    `json:"updatedAt"`
}

// PreAuthKey allows unattended or automated node registration onto the control plane.
type PreAuthKey struct {
	ID        string    `json:"id"`
	Key       string    `json:"key"`
	Label     string    `json:"label,omitempty"`
	Reusable  bool      `json:"reusable"`
	Ephemeral bool      `json:"ephemeral"`
	Revoked   bool      `json:"revoked"`
	UsedCount int       `json:"usedCount"`
	Tags      []string  `json:"tags,omitempty"`
	ExpiresAt time.Time `json:"expiresAt"`
	CreatedAt time.Time `json:"createdAt"`
}

// RegisterRequest is sent by acktierd to register or authenticate a node.
type RegisterRequest struct {
	MachineKey       PublicKey      `json:"machineKey"`
	NodeKey          PublicKey      `json:"nodeKey"`
	AuthKey          string         `json:"authKey,omitempty"`
	Hostname         string         `json:"hostname"`
	OS               string         `json:"os"`
	Endpoints        []Endpoint     `json:"endpoints,omitempty"`
	AdvertisedRoutes []netip.Prefix `json:"advertisedRoutes,omitempty"`
	CanRelay         bool           `json:"canRelay,omitempty"`
	PreferredRelayID string         `json:"preferredRelayId,omitempty"`
}

// RegisterResponse returns the node token and initial NetMap upon registration.
type RegisterResponse struct {
	NodeToken string `json:"nodeToken"`
	NetMap    NetMap `json:"netMap"`
}

// HeartbeatRequest updates dynamic endpoint, link-state RTT, and routing state of an authenticated node.
type HeartbeatRequest struct {
	NodeKey          PublicKey      `json:"nodeKey"`
	Endpoints        []Endpoint     `json:"endpoints,omitempty"`
	Links            []PeerLink     `json:"links,omitempty"`
	AdvertisedRoutes []netip.Prefix `json:"advertisedRoutes,omitempty"`
	CanRelay         bool           `json:"canRelay,omitempty"`
	PreferredRelayID string         `json:"preferredRelayId,omitempty"`
}

// MapStreamEvent is streamed over NDJSON from acktier-server to acktierd.
type MapStreamEvent struct {
	Type     string  `json:"type"` // "netmap" | "keepalive"
	NetMap   *NetMap `json:"netMap,omitempty"`
	Revision uint64  `json:"revision,omitempty"` // current topology revision on keepalives
	SentAt   int64   `json:"sentAt"`
}

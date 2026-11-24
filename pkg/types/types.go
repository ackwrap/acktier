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

// PeerNode represents a device in the AckTier overlay network.
type PeerNode struct {
	ID               NodeID         `json:"id"`
	Name             string         `json:"name"`
	Hostname         string         `json:"hostname"`
	OS               string         `json:"os"`
	MachineKey       PublicKey      `json:"machineKey"`
	NodeKey          PublicKey      `json:"nodeKey"`
	IPv4             netip.Addr     `json:"ipv4"`
	IPv6             netip.Addr     `json:"ipv6"`
	Endpoints        []Endpoint     `json:"endpoints,omitempty"`
	AllowedIPs       []netip.Prefix `json:"allowedIPs,omitempty"`
	AdvertisedRoutes []netip.Prefix `json:"advertisedRoutes,omitempty"`
	ApprovedRoutes   []netip.Prefix `json:"approvedRoutes,omitempty"`
	CanRelay         bool           `json:"canRelay,omitempty"`
	PreferredRelayID string         `json:"preferredRelayId,omitempty"`
	Tags             []string       `json:"tags,omitempty"`
	Online           bool           `json:"online"`
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

// HeartbeatRequest updates dynamic endpoint and routing state of an authenticated node.
type HeartbeatRequest struct {
	NodeKey          PublicKey      `json:"nodeKey"`
	Endpoints        []Endpoint     `json:"endpoints,omitempty"`
	AdvertisedRoutes []netip.Prefix `json:"advertisedRoutes,omitempty"`
	CanRelay         bool           `json:"canRelay,omitempty"`
	PreferredRelayID string         `json:"preferredRelayId,omitempty"`
}

// MapStreamEvent is streamed over NDJSON from acktier-server to acktierd.
type MapStreamEvent struct {
	Type   string  `json:"type"` // "netmap" | "keepalive"
	NetMap *NetMap `json:"netMap,omitempty"`
	SentAt int64   `json:"sentAt"`
}

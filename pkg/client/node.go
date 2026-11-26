// Package client provides the public Go SDK for embedding an AckTier overlay node,
// controlling a local acktierd daemon over LocalAPI, or managing an acktier-server control plane.
package client

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/ackwrap/acktier/internal/daemon/engine"
	"github.com/ackwrap/acktier/internal/daemon/localapi"
	"github.com/ackwrap/acktier/internal/daemon/state"
	"github.com/ackwrap/acktier/internal/daemon/transport"
	"github.com/ackwrap/acktier/internal/daemon/tun"
	"github.com/ackwrap/acktier/pkg/types"
)

// TUNMode specifies how an embedded Node attaches its L3 virtual interface.
type TUNMode string

const (
	TUNAuto   TUNMode = "auto"   // Try OS virtual NIC (Wintun/TUN/utun), fallback to memory NIC
	TUNSystem TUNMode = "os"     // Require OS virtual NIC (Administrator/root privileges)
	TUNMemory TUNMode = "memory" // Pure userspace in-memory NIC (no privileges required)
	TUNCustom TUNMode = "custom" // Caller supplies a custom PacketDevice (e.g. Android/iOS VPN fd or acknet stack)
)

// DefaultControlLeaseTTL is how long a node keeps its last authorized NetMap while control is unreachable.
const DefaultControlLeaseTTL = engine.DefaultControlLeaseTTL

// PacketDevice allows SDK consumers to plug in a custom L3 packet interface (such as mobile VPN fds or userspace stacks).
type PacketDevice = tun.Device

// Re-export core status & diagnostic structs so SDK consumers never touch internal packages.
type (
	StatusResponse   = engine.StatusResponse
	PeerStatus       = engine.PeerStatus
	MeshStatusReport = engine.MeshStatusReport
	MeshRouteInfo    = engine.MeshRouteInfo
	NetCheckReport   = engine.NetCheckReport
	PingResult       = engine.PingResult
	UpOptions        = engine.UpRequest
)

// EventType describes lifecycle notifications emitted to SDK subscribers.
type EventType string

const (
	EventUp          EventType = "up"
	EventDown        EventType = "down"
	EventExitChanged EventType = "exit_node_changed"
)

// Event is delivered to callbacks registered via Node.Subscribe.
type Event struct {
	Type   EventType
	Status StatusResponse
}

// NodeConfig configures an embedded AckTier client node.
type NodeConfig struct {
	// StatePath persists MachineKey, NodeKey, and session token. Leave empty for ephemeral in-memory identity.
	StatePath string
	Hostname  string

	TUNMode       TUNMode
	InterfaceName string // System TUN name on Linux/Windows (empty uses "acktier"); macOS assigns utunN.
	MTU           int
	CustomTUN     PacketDevice

	// Multi-protocol listen addresses (e.g. "0.0.0.0:0" to auto-bind, or "" to disable a protocol).
	UDPListenAddr  string
	TCPListenAddr  string
	QUICListenAddr string
	WSSListenAddr  string

	EnableUPnP          bool
	EnableLANDiscovery  bool
	EnableNetMonitor    bool
	DisableUDP          bool
	TLSCAFile           string
	AllowInsecureHTTP   bool
	LocalAPIAddr        string
	BlackholeProbeAfter time.Duration
	BlackholeTimeout    time.Duration
	NetMonitorInterval  time.Duration
	ControlLeaseTTL     time.Duration // Stale NetMap grace period (0 uses DefaultControlLeaseTTL; minimum 1m).
	OwnerTrustFile      string        // Out-of-band public trust configuration; pin is retained in StatePath.
	RequireOwner        bool          // Refuse to start without a pinned owner.

	// Optional custom dialers/transports for custom host environments or sandboxed testing.
	CustomUDPConn  net.PacketConn
	HTTPClient     *http.Client
	RelayDial      func(ctx context.Context, network, address string) (net.Conn, error)
	GatewayTCPDial func(ctx context.Context, network, address string) (net.Conn, error)
	GatewayUDPDial func(ctx context.Context, network, address string) (net.Conn, error)
}

// DefaultNodeConfig returns production-ready defaults with all four transports (UDP/TCP/QUIC/WSS) enabled.
func DefaultNodeConfig(statePath string) NodeConfig {
	return NodeConfig{
		StatePath:          statePath,
		TUNMode:            TUNAuto,
		InterfaceName:      tun.DefaultInterfaceName,
		MTU:                tun.DefaultMTU,
		UDPListenAddr:      "0.0.0.0:0",
		TCPListenAddr:      "0.0.0.0:0",
		QUICListenAddr:     "0.0.0.0:0",
		WSSListenAddr:      "0.0.0.0:0",
		EnableUPnP:         true,
		EnableLANDiscovery: true,
		EnableNetMonitor:   true,
		ControlLeaseTTL:    DefaultControlLeaseTTL,
	}
}

// Node is an embeddable AckTier overlay client instance that can run inside any Go application or custom GUI.
type Node struct {
	eng      *engine.Engine
	stateMgr *state.Manager
	tunDev   tun.Device
	hub      *transport.Hub

	subMu       sync.RWMutex
	subscribers map[uint64]func(Event)
	nextSubID   uint64
}

// NewNode constructs and initializes a new embedded AckTier client Node.
func NewNode(cfg NodeConfig) (*Node, error) {
	stMgr, err := state.LoadOrCreate(cfg.StatePath)
	if err != nil {
		return nil, fmt.Errorf("client: load state: %w", err)
	}
	if cfg.Hostname != "" {
		_ = stMgr.Update(func(s *state.ConfigState) {
			s.Hostname = cfg.Hostname
		})
	}

	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = tun.DefaultMTU
	}

	var tunDev tun.Device
	switch cfg.TUNMode {
	case TUNCustom:
		if cfg.CustomTUN == nil {
			return nil, fmt.Errorf("client: CustomTUN is required when TUNMode is TUNCustom")
		}
		tunDev = cfg.CustomTUN
	case TUNMemory:
		tunDev = tun.NewMemoryDevice("acktier-mem0", mtu)
	case TUNSystem:
		tunDev, err = tun.CreateOSDevice(cfg.InterfaceName, mtu)
		if err != nil {
			return nil, err
		}
	default: // TUNAuto
		tunDev, err = tun.CreateOSDevice(cfg.InterfaceName, mtu)
		if err != nil {
			tunDev = tun.NewMemoryDevice("acktier-mem0", mtu)
		}
	}

	hub := transport.NewHub()
	eng, err := engine.New(engine.Options{
		State:               stMgr,
		TUN:                 tunDev,
		Hub:                 hub,
		HTTPClient:          cfg.HTTPClient,
		RelayDial:           cfg.RelayDial,
		GatewayTCPDial:      cfg.GatewayTCPDial,
		GatewayUDPDial:      cfg.GatewayUDPDial,
		TLSCAFile:           cfg.TLSCAFile,
		AllowInsecureHTTP:   cfg.AllowInsecureHTTP,
		LocalAPIAddr:        cfg.LocalAPIAddr,
		DisableUDP:          cfg.DisableUDP,
		EnableLANDiscovery:  cfg.EnableLANDiscovery,
		EnablePortMap:       cfg.EnableUPnP,
		EnableNetMonitor:    cfg.EnableNetMonitor,
		BlackholeProbeAfter: cfg.BlackholeProbeAfter,
		BlackholeTimeout:    cfg.BlackholeTimeout,
		NetMonitorInterval:  cfg.NetMonitorInterval,
		ControlLeaseTTL:     cfg.ControlLeaseTTL,
		OwnerTrustFile:      cfg.OwnerTrustFile,
		RequireOwner:        cfg.RequireOwner,
	})
	if err != nil {
		_ = tunDev.Close()
		return nil, err
	}

	if cfg.CustomUDPConn != nil && !cfg.DisableUDP {
		hub.Register(transport.NewUDPDriver(cfg.CustomUDPConn, eng.OnTransportPacket))
	} else if cfg.UDPListenAddr != "" && !cfg.DisableUDP {
		if uConn, uErr := net.ListenPacket("udp", cfg.UDPListenAddr); uErr == nil {
			hub.Register(transport.NewUDPDriver(uConn, eng.OnTransportPacket))
		}
	}
	if cfg.TCPListenAddr != "" {
		if tLn, tErr := net.Listen("tcp", cfg.TCPListenAddr); tErr == nil {
			hub.Register(transport.NewTCPDriver(tLn, nil, eng.OnTransportPacket))
		}
	}
	if cfg.QUICListenAddr != "" && !cfg.DisableUDP {
		if qConn, qErr := net.ListenPacket("udp", cfg.QUICListenAddr); qErr == nil {
			if qDrv, dErr := transport.NewQUICDriver(qConn, eng.OnTransportPacket); dErr == nil {
				hub.Register(qDrv)
			} else {
				_ = qConn.Close()
			}
		}
	}
	if cfg.WSSListenAddr != "" {
		if wLn, wErr := net.Listen("tcp", cfg.WSSListenAddr); wErr == nil {
			if wDrv, dErr := transport.NewWSSDriver(wLn, nil, eng.OnTransportPacket); dErr == nil {
				hub.Register(wDrv)
			} else {
				_ = wLn.Close()
			}
		}
	}

	return &Node{
		eng:         eng,
		stateMgr:    stMgr,
		tunDev:      tunDev,
		hub:         hub,
		subscribers: make(map[uint64]func(Event)),
	}, nil
}

// AttachUDPConn registers an existing net.PacketConn as the UDP direct transport on this Node.
func (n *Node) AttachUDPConn(conn net.PacketConn) {
	if conn != nil {
		n.hub.Register(transport.NewUDPDriver(conn, n.eng.OnTransportPacket))
	}
}

// AttachTCPListener registers an existing net.Listener and optional dialer as the TCP direct transport on this Node.
func (n *Node) AttachTCPListener(ln net.Listener, dial func(ctx context.Context, network, addr string) (net.Conn, error)) {
	n.hub.Register(transport.NewTCPDriver(ln, dial, n.eng.OnTransportPacket))
}

// Up authenticates with the control plane and joins the AckTier mesh network.
func (n *Node) Up(ctx context.Context, opts UpOptions) (*types.NetMap, error) {
	nm, err := n.eng.Up(ctx, opts)
	if err != nil {
		return nil, err
	}
	n.emit(EventUp)
	return nm, nil
}

// Down disconnects the overlay session without destroying the Node instance.
func (n *Node) Down() {
	n.eng.Down()
	n.emit(EventDown)
}

// Close shuts down all transports, background workers, and the underlying TUN device.
func (n *Node) Close() error {
	return n.eng.Close()
}

func (n *Node) Status() StatusResponse                      { return n.eng.Status() }
func (n *Node) MeshStatus() MeshStatusReport                { return n.eng.MeshStatus() }
func (n *Node) NetCheck(ctx context.Context) NetCheckReport { return n.eng.NetCheck(ctx) }
func (n *Node) Ping(ctx context.Context, peer string) (*PingResult, error) {
	return n.eng.PingPeer(ctx, peer)
}

// LookupDNS resolves a node name or MagicDNS FQDN into its virtual IPv4 and IPv6 addresses.
func (n *Node) LookupDNS(host string) (ipv4, ipv6 netip.Addr, fqdn string, ok bool) {
	v4Str, v6Str, full, found := n.eng.LookupDNS(host)
	if !found {
		return netip.Addr{}, netip.Addr{}, "", false
	}
	v4, _ := netip.ParseAddr(v4Str)
	v6, _ := netip.ParseAddr(v6Str)
	return v4, v6, full, true
}

// SetExitNode dynamically enables or clears ("none" / "") global Exit Node routing.
func (n *Node) SetExitNode(peer string) error {
	if err := n.eng.SetExitNode(peer); err != nil {
		return err
	}
	n.emit(EventExitChanged)
	return nil
}

// NotifyNetworkChange immediately triggers STUN refresh, control heartbeat, and peer roaming probes
// (ideal when mobile/desktop OS hooks detect Wi-Fi / cellular handoff).
func (n *Node) NotifyNetworkChange() {
	n.eng.NotifyNetworkChange()
}

// LocalAPIToken returns the owner-only bearer token required to authenticate with LocalAPIHandler.
func (n *Node) LocalAPIToken() string {
	return n.eng.LocalAPIToken()
}

// LocalAPIHandler returns an authenticated http.Handler exposing the `/local/v1/*` IPC endpoints.
func (n *Node) LocalAPIHandler() http.Handler {
	return localapi.NewServer(n.eng, n.eng.LocalAPIToken()).Handler()
}

// Subscribe registers an event listener for node state transitions and returns an unsubscribe function.
func (n *Node) Subscribe(fn func(Event)) func() {
	n.subMu.Lock()
	n.nextSubID++
	id := n.nextSubID
	n.subscribers[id] = fn
	n.subMu.Unlock()

	return func() {
		n.subMu.Lock()
		delete(n.subscribers, id)
		n.subMu.Unlock()
	}
}

func (n *Node) emit(evType EventType) {
	st := n.eng.Status()
	n.subMu.RLock()
	subs := make([]func(Event), 0, len(n.subscribers))
	for _, fn := range n.subscribers {
		subs = append(subs, fn)
	}
	n.subMu.RUnlock()

	ev := Event{Type: evType, Status: st}
	for _, fn := range subs {
		fn(ev)
	}
}

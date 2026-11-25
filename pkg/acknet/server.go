// Package acknet provides a zero-privilege, embeddable virtual network SDK (inspired by Tailscale tsnet).
// Third-party Go applications can join an AckTier mesh network and expose or dial standard `net.Listener`,
// `net.Conn`, `net.PacketConn`, `*http.Client`, and SOCKS5 proxies without root/Administrator rights or OS TUN drivers.
package acknet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"sync"
	"time"

	"github.com/acktier/acktier/pkg/client"
	"github.com/acktier/acktier/pkg/types"
)

// Server represents an in-process AckTier virtual node backed by a userspace TCP/UDP/ICMP stack.
type Server struct {
	// Hostname registers the node's MagicDNS name on the overlay network (e.g. "order-api").
	Hostname string
	// ControlURL is the base URL of acktier-server (e.g. "http://127.0.0.1:8080").
	ControlURL string
	// AuthKey is an optional PreAuthKey for automatic headless registration.
	AuthKey string
	// StateDir optionally persists MachineKey, NodeKey, and session token on disk. Empty = ephemeral in-memory node.
	StateDir string

	CanRelay           bool
	RelayMode          types.RelayMode // "auto" (default) | "on" | "off"
	MaxRelayMbps       float64         // Optional transit bandwidth cap in Mbps
	AdvertisedRoutes   []netip.Prefix
	ExitNode           string
	EnableUPnP         bool
	EnableLANDiscovery bool
	DisableUDP         bool
	DisableDefaultBind bool // Skip binding default OS sockets (for custom transport injection)

	// Optional transport/gateway overrides for custom environments or testing.
	CustomUDPConn      net.PacketConn
	HTTPClientOverride *http.Client
	RelayDial          func(ctx context.Context, network, address string) (net.Conn, error)
	GatewayTCPDial     func(ctx context.Context, network, address string) (net.Conn, error)
	GatewayUDPDial     func(ctx context.Context, network, address string) (net.Conn, error)

	mu      sync.Mutex
	started bool
	closed  bool
	ustack  *UserspaceStack
	node    *client.Node
}

func (s *Server) ensureNodeLocked() error {
	if s.closed {
		return ErrStackClosed
	}
	if s.node != nil {
		return nil
	}

	s.ustack = newUserspaceStack(0)
	var statePath string
	if s.StateDir != "" {
		statePath = filepath.Join(s.StateDir, "acknet-state.json")
	}

	cfg := client.NodeConfig{
		StatePath:          statePath,
		Hostname:           s.Hostname,
		TUNMode:            client.TUNCustom,
		CustomTUN:          s.ustack,
		EnableUPnP:         s.EnableUPnP,
		EnableLANDiscovery: s.EnableLANDiscovery,
		DisableUDP:         s.DisableUDP,
		CustomUDPConn:      s.CustomUDPConn,
		HTTPClient:         s.HTTPClientOverride,
		RelayDial:          s.RelayDial,
		GatewayTCPDial:     s.GatewayTCPDial,
		GatewayUDPDial:     s.GatewayUDPDial,
	}
	if !s.DisableDefaultBind {
		if !s.DisableUDP {
			cfg.UDPListenAddr = "0.0.0.0:0"
			cfg.QUICListenAddr = "0.0.0.0:0"
		}
		cfg.TCPListenAddr = "0.0.0.0:0"
		cfg.WSSListenAddr = "0.0.0.0:0"
	}

	nd, err := client.NewNode(cfg)
	if err != nil {
		_ = s.ustack.Close()
		return err
	}
	s.node = nd
	return nil
}

// Init initializes the underlying client.Node without connecting yet (useful if registering custom transports before Up).
func (s *Server) Init() (*client.Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureNodeLocked(); err != nil {
		return nil, err
	}
	return s.node, nil
}

// Up connects the embedded Server to the AckTier control plane and joins the encrypted mesh.
// Calling Up multiple times is safe and idempotent once started.
func (s *Server) Up(ctx context.Context) (*types.NetMap, error) {
	s.mu.Lock()
	if err := s.ensureNodeLocked(); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if s.started {
		nd := s.node
		s.mu.Unlock()
		st := nd.Status()
		v4, _ := netip.ParseAddr(st.IPv4)
		v6, _ := netip.ParseAddr(st.IPv6)
		return &types.NetMap{Self: types.PeerNode{Name: st.SelfName, IPv4: v4, IPv6: v6}}, nil
	}
	nd := s.node
	opts := client.UpOptions{
		ServerURL:        s.ControlURL,
		AuthKey:          s.AuthKey,
		Hostname:         s.Hostname,
		AdvertisedRoutes: s.AdvertisedRoutes,
		ExitNode:         s.ExitNode,
		RelayMode:        s.RelayMode,
		MaxRelayMbps:     s.MaxRelayMbps,
		CanRelay:         s.CanRelay,
	}
	s.mu.Unlock()

	nm, err := nd.Up(ctx, opts)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.started = true
	s.mu.Unlock()
	return nm, nil
}

// Node returns the underlying *client.Node for diagnostics, status events, Ping, MeshStatus, or NetCheck.
func (s *Server) Node() *client.Node {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.ensureNodeLocked()
	return s.node
}

// LocalIPs returns the assigned overlay IPv4 and IPv6 addresses of this Server.
func (s *Server) LocalIPs() (ipv4, ipv6 netip.Addr) {
	s.mu.Lock()
	us := s.ustack
	s.mu.Unlock()
	if us == nil {
		return netip.Addr{}, netip.Addr{}
	}
	return us.LocalIPs()
}

// Resolve resolves an IP literal, short node name ("db-prod"), or MagicDNS FQDN ("db-prod.ack.internal") to an IP.
func (s *Server) Resolve(ctx context.Context, host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap(), nil
	}
	if _, err := s.Up(ctx); err != nil {
		return netip.Addr{}, err
	}
	// Poll briefly if peer registration is still propagating via live NetMap stream
	deadline := time.Now().Add(2 * time.Second)
	for {
		v4, v6, _, ok := s.node.LookupDNS(host)
		if ok {
			if v4.IsValid() {
				return v4, nil
			}
			if v6.IsValid() {
				return v6, nil
			}
		}
		if !time.Now().Before(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return netip.Addr{}, ctx.Err()
		case <-time.After(30 * time.Millisecond):
		}
	}
	return netip.Addr{}, fmt.Errorf("acknet: MagicDNS could not resolve %q", host)
}

// Listen announces on the Server's virtual AckTier IP (network must be "tcp", "tcp4", or "tcp6").
func (s *Server) Listen(network, address string) (net.Listener, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("acknet: unsupported Listen network %q", network)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := s.Up(ctx); err != nil {
		return nil, err
	}
	_, port, err := fmtPort(address)
	if err != nil {
		return nil, err
	}
	return s.ustack.ListenTCP(port)
}

// ListenPacket listens for UDP datagrams on the Server's virtual AckTier IP ("udp", "udp4", "udp6").
func (s *Server) ListenPacket(network, address string) (net.PacketConn, error) {
	switch network {
	case "udp", "udp4", "udp6":
	default:
		return nil, fmt.Errorf("acknet: unsupported ListenPacket network %q", network)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := s.Up(ctx); err != nil {
		return nil, err
	}
	_, port, err := fmtPort(address)
	if err != nil {
		return nil, err
	}
	return s.ustack.ListenUDP(port)
}

// Dial connects to `address` ("host:port" or "ip:port") over the encrypted AckTier overlay network.
// Supports "tcp", "tcp4", "tcp6", "udp", "udp4", and "udp6", with built-in MagicDNS name resolution!
func (s *Server) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if _, err := s.Up(ctx); err != nil {
		return nil, err
	}
	host, port, err := fmtPort(address)
	if err != nil {
		return nil, err
	}
	if port == 0 {
		return nil, errors.New("acknet: destination port cannot be 0")
	}
	dstIP, err := s.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}

	switch network {
	case "tcp", "tcp4", "tcp6":
		return s.ustack.DialTCP(ctx, dstIP, port)
	case "udp", "udp4", "udp6":
		pc, err := s.ustack.ListenUDP(0)
		if err != nil {
			return nil, err
		}
		return &connectedUDPConn{
			ustackUDPConn: pc.(*ustackUDPConn),
			remote:        &net.UDPAddr{IP: dstIP.AsSlice(), Port: int(port)},
		}, nil
	default:
		return nil, fmt.Errorf("acknet: unsupported Dial network %q", network)
	}
}

// HTTPClient returns a standard *http.Client pre-configured to resolve MagicDNS names and dial over AckTier.
func (s *Server) HTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: s.Dial,
		},
	}
}

// Close gracefully tears down all virtual sockets, transports, and control plane sessions.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	nd := s.node
	us := s.ustack
	s.mu.Unlock()

	if us != nil {
		_ = us.Close()
	}
	if nd != nil {
		return nd.Close()
	}
	return nil
}

package tun

import (
	"errors"
	"io"
	"net/netip"
	"sync"
)

const DefaultMTU = 1280 // Fits within a 1500-byte IPv6/UDP packet after AEAD and authenticated mesh wrapping.

// DefaultInterfaceName is the default system TUN name on Linux and Windows.
const DefaultInterfaceName = "acktier"

func interfaceNameOrDefault(name string) string {
	if name == "" {
		return DefaultInterfaceName
	}
	return name
}

// Device abstracts an OS virtual network interface (Wintun, Linux /dev/net/tun, macOS utun) or in-memory test NIC.
type Device interface {
	Name() string
	MTU() int
	ReadPacket(buf []byte) (int, error)
	WritePacket(pkt []byte) error
	Configure(ipv4 netip.Prefix, ipv6 netip.Prefix, routes []netip.Prefix) error
	Close() error
}

// ExtractDstIP extracts the destination IPv4 or IPv6 address from a raw L3 IP packet.
func ExtractDstIP(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 20 {
		return netip.Addr{}, false
	}
	version := pkt[0] >> 4
	switch version {
	case 4:
		var dst [4]byte
		copy(dst[:], pkt[16:20])
		return netip.AddrFrom4(dst), true
	case 6:
		if len(pkt) < 40 {
			return netip.Addr{}, false
		}
		var dst [16]byte
		copy(dst[:], pkt[24:40])
		return netip.AddrFrom16(dst), true
	default:
		return netip.Addr{}, false
	}
}

// ExtractSrcIP extracts the source IPv4 or IPv6 address from a raw L3 IP packet.
func ExtractSrcIP(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 20 {
		return netip.Addr{}, false
	}
	version := pkt[0] >> 4
	switch version {
	case 4:
		var src [4]byte
		copy(src[:], pkt[12:16])
		return netip.AddrFrom4(src), true
	case 6:
		if len(pkt) < 40 {
			return netip.Addr{}, false
		}
		var src [16]byte
		copy(src[:], pkt[8:24])
		return netip.AddrFrom16(src), true
	default:
		return netip.Addr{}, false
	}
}

// MemoryDevice implements Device entirely in memory for unprivileged testing and userspace netstack bridging.
type MemoryDevice struct {
	name       string
	mtu        int
	txToEngine chan []byte // OS/App -> Engine (ReadPacket reads from here)
	rxFromNet  chan []byte // Engine -> OS/App (WritePacket writes to here)

	mu        sync.RWMutex
	ipv4      netip.Prefix
	ipv6      netip.Prefix
	routes    []netip.Prefix
	closed    bool
	closeOnce sync.Once
	doneCh    chan struct{}
}

func NewMemoryDevice(name string, mtu int) *MemoryDevice {
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	return &MemoryDevice{
		name:       name,
		mtu:        mtu,
		txToEngine: make(chan []byte, 512),
		rxFromNet:  make(chan []byte, 512),
		doneCh:     make(chan struct{}),
	}
}

func (m *MemoryDevice) Name() string { return m.name }
func (m *MemoryDevice) MTU() int     { return m.mtu }

func (m *MemoryDevice) Configure(ipv4 netip.Prefix, ipv6 netip.Prefix, routes []netip.Prefix) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ipv4 = ipv4
	m.ipv6 = ipv6
	m.routes = append([]netip.Prefix(nil), routes...)
	return nil
}

func (m *MemoryDevice) ReadPacket(buf []byte) (int, error) {
	select {
	case <-m.doneCh:
		return 0, io.EOF
	case pkt := <-m.txToEngine:
		if len(pkt) > len(buf) {
			return 0, errors.New("tun: buffer too small")
		}
		copy(buf, pkt)
		return len(pkt), nil
	}
}

func (m *MemoryDevice) WritePacket(pkt []byte) error {
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	select {
	case <-m.doneCh:
		return io.ErrClosedPipe
	case m.rxFromNet <- cp:
		return nil
	default:
		return nil
	}
}

// InjectOutbound injects a simulated application L3 packet into the local virtual NIC (to be encrypted and sent).
func (m *MemoryDevice) InjectOutbound(pkt []byte) error {
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	select {
	case <-m.doneCh:
		return io.ErrClosedPipe
	case m.txToEngine <- cp:
		return nil
	}
}

// ReceiveInbound returns the channel of decrypted L3 packets delivered to this local virtual NIC.
func (m *MemoryDevice) ReceiveInbound() <-chan []byte {
	return m.rxFromNet
}

func (m *MemoryDevice) Close() error {
	m.closeOnce.Do(func() {
		close(m.doneCh)
	})
	return nil
}

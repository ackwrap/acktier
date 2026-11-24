package ipam

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
)

var (
	DefaultIPv4Prefix = netip.MustParsePrefix("100.64.0.0/10")
	DefaultIPv6Prefix = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	MagicDNSIPv4      = netip.MustParseAddr("100.100.100.100")

	ErrPoolExhausted = errors.New("ipam: address pool exhausted")
)

// Allocator manages IPv4 (CGNAT 100.64.0.0/10) and IPv6 (ULA) allocations.
type Allocator struct {
	mu       sync.Mutex
	v4Prefix netip.Prefix
	v6Prefix netip.Prefix
	usedV4   map[netip.Addr]bool
	nextHost uint32
}

func NewAllocator(v4Prefix, v6Prefix netip.Prefix) *Allocator {
	return &Allocator{
		v4Prefix: v4Prefix.Masked(),
		v6Prefix: v6Prefix.Masked(),
		usedV4: map[netip.Addr]bool{
			MagicDNSIPv4: true,
		},
		nextHost: 1,
	}
}

// Reserve marks existing IPv4 allocation as in-use during store recovery.
func (a *Allocator) Reserve(v4 netip.Addr) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if v4.IsValid() {
		a.usedV4[v4] = true
	}
}

// Release frees an IPv4 address back into the pool.
func (a *Allocator) Release(v4 netip.Addr) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if v4 != MagicDNSIPv4 {
		delete(a.usedV4, v4)
	}
}

// Allocate assigns the next available IPv4 and deterministic IPv6 pair.
func (a *Allocator) Allocate() (netip.Addr, netip.Addr, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	base4 := a.v4Prefix.Addr().As4()
	baseUint := binary.BigEndian.Uint32(base4[:])
	hostBits := 32 - a.v4Prefix.Bits()
	maxHosts := uint32((1 << hostBits) - 2) // exclude network & broadcast

	for i := uint32(0); i < maxHosts; i++ {
		offset := ((a.nextHost - 1 + i) % maxHosts) + 1
		candUint := baseUint + offset
		var candBytes [4]byte
		binary.BigEndian.PutUint32(candBytes[:], candUint)
		candV4 := netip.AddrFrom4(candBytes)
		if !a.v4Prefix.Contains(candV4) || a.usedV4[candV4] {
			continue
		}
		// Skip .0 and .255 octets for maximum OS TUN driver compatibility
		if candBytes[3] == 0 || candBytes[3] == 255 {
			continue
		}

		a.usedV4[candV4] = true
		a.nextHost = offset + 1

		v6Bytes := a.v6Prefix.Addr().As16()
		binary.BigEndian.PutUint32(v6Bytes[12:16], offset)
		candV6 := netip.AddrFrom16(v6Bytes)
		return candV4, candV6, nil
	}

	return netip.Addr{}, netip.Addr{}, ErrPoolExhausted
}

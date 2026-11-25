package transport

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/acktier/acktier/pkg/types"
)

// Hub aggregates multiple protocol Drivers (UDP, TCP, QUIC, WSS) under a single dispatch API.
type Hub struct {
	mu      sync.RWMutex
	drivers map[types.TransportProto]Driver
}

func NewHub() *Hub {
	return &Hub{
		drivers: make(map[types.TransportProto]Driver),
	}
}

func (h *Hub) Register(d Driver) {
	if d == nil {
		return
	}
	h.mu.Lock()
	h.drivers[d.Proto()] = d
	h.mu.Unlock()
}

func (h *Hub) Driver(proto types.TransportProto) Driver {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.drivers[proto]
}

func (h *Hub) HasProto(proto types.TransportProto) bool {
	h.mu.RLock()
	_, ok := h.drivers[proto]
	h.mu.RUnlock()
	return ok
}

func (h *Hub) Send(ctx context.Context, ep types.Endpoint, pkt []byte) error {
	h.mu.RLock()
	d := h.drivers[ep.Proto]
	h.mu.RUnlock()
	if d == nil {
		return fmt.Errorf("transport: protocol %q not enabled", ep.Proto)
	}
	return d.Send(ctx, ep.Addr, pkt)
}

// LocalPorts returns a map of active transport protocol -> bound local port string.
func (h *Hub) LocalPorts() map[types.TransportProto]string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make(map[types.TransportProto]string, len(h.drivers))
	for proto, d := range h.drivers {
		addr := d.LocalAddr()
		if _, port, err := net.SplitHostPort(addr); err == nil && port != "0" && port != "" {
			out[proto] = port
		}
	}
	return out
}

// LocalEndpoints enumerates host IP addresses combined with every active transport driver's listening port.
func (h *Hub) LocalEndpoints(excludeIfName string, extraPublic []types.Endpoint) []types.Endpoint {
	h.mu.RLock()
	drivers := make([]Driver, 0, len(h.drivers))
	for _, d := range h.drivers {
		drivers = append(drivers, d)
	}
	h.mu.RUnlock()

	var out []types.Endpoint
	seen := make(map[types.Endpoint]bool)
	add := func(ep types.Endpoint) {
		if ep.Addr != "" && !seen[ep] {
			seen[ep] = true
			out = append(out, ep)
		}
	}

	for _, ep := range extraPublic {
		add(ep)
	}

	// Collect bound explicit IPs (e.g. 127.0.0.1 in tests)
	for _, d := range drivers {
		host, port, err := net.SplitHostPort(d.LocalAddr())
		if err != nil || port == "0" || port == "" {
			continue
		}
		if ip, pErr := netip.ParseAddr(host); pErr == nil && !ip.IsUnspecified() {
			add(types.Endpoint{
				Proto: d.Proto(),
				Addr:  net.JoinHostPort(ip.String(), port),
				IsLAN: ip.IsPrivate(),
			})
		}
	}

	// Enumerate active non-loopback OS network interfaces across all enabled protocols
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Name == excludeIfName {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipNet.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if ip.IsLinkLocalUnicast() || ip.IsLoopback() {
				continue
			}
			for _, d := range drivers {
				_, port, err := net.SplitHostPort(d.LocalAddr())
				if err != nil || port == "0" || port == "" {
					continue
				}
				add(types.Endpoint{
					Proto: d.Proto(),
					Addr:  net.JoinHostPort(ip.String(), port),
					IsLAN: ip.IsPrivate(),
				})
			}
		}
	}
	return out
}

// ResetConnections closes active peer stream sessions across all drivers without closing bound listeners/sockets.
func (h *Hub) ResetConnections() {
	type resetter interface {
		ResetConnections()
	}
	h.mu.RLock()
	drivers := make([]Driver, 0, len(h.drivers))
	for _, d := range h.drivers {
		drivers = append(drivers, d)
	}
	h.mu.RUnlock()
	for _, d := range drivers {
		if r, ok := d.(resetter); ok {
			r.ResetConnections()
		}
	}
}

func (h *Hub) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	for k, d := range h.drivers {
		_ = d.Close()
		delete(h.drivers, k)
	}
	return nil
}

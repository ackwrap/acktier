package nat

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

const defaultNetMonitorInterval = 1500 * time.Millisecond

// NetMonitor watches local OS network interfaces and IP addresses, invoking onChange
// immediately whenever Wi-Fi, Ethernet, cellular hotspot, or DHCP leases change.
type NetMonitor struct {
	excludeIfName string
	interval      time.Duration
	onChange      func(prevFingerprint, newFingerprint string)
}

func NewNetMonitor(excludeIfName string, interval time.Duration, onChange func(prev, curr string)) *NetMonitor {
	if interval <= 0 {
		interval = defaultNetMonitorInterval
	}
	return &NetMonitor{
		excludeIfName: excludeIfName,
		interval:      interval,
		onChange:      onChange,
	}
}

func (nm *NetMonitor) Run(ctx context.Context) {
	lastFP := SnapshotInterfaceFingerprint(nm.excludeIfName)
	ticker := time.NewTicker(nm.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			currFP := SnapshotInterfaceFingerprint(nm.excludeIfName)
			if currFP != lastFP {
				prev := lastFP
				lastFP = currFP
				if nm.onChange != nil {
					nm.onChange(prev, currFP)
				}
			}
		}
	}
}

// SnapshotInterfaceFingerprint builds a deterministic sorted signature of active host interfaces and IPs.
func SnapshotInterfaceFingerprint(excludeIfName string) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var items []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if excludeIfName != "" && iface.Name == excludeIfName {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
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
			items = append(items, iface.Name+"="+ip.String())
		}
	}
	sort.Strings(items)
	return strings.Join(items, ";")
}

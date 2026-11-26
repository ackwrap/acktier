package nat

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/huin/goupnp/dcps/internetgateway1"
	"github.com/huin/goupnp/dcps/internetgateway2"
	natpmp "github.com/jackpal/go-nat-pmp"

	"github.com/ackwrap/acktier/pkg/types"
)

const mappingLeaseSec = 3600

// PortMapper manages automatic external port mappings via UPnP IGDv1/v2 and NAT-PMP.
type PortMapper struct {
	mu        sync.RWMutex
	mappedUDP string
	mappedTCP string
}

func NewPortMapper() *PortMapper {
	return &PortMapper{}
}

func (pm *PortMapper) MappedAddrs() (udpAddr, tcpAddr string) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.mappedUDP, pm.mappedTCP
}

func (pm *PortMapper) MappedEndpoints() []types.Endpoint {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	var out []types.Endpoint
	if pm.mappedUDP != "" {
		out = append(out, types.Endpoint{Proto: types.ProtoUDP, Addr: pm.mappedUDP})
	}
	if pm.mappedTCP != "" {
		out = append(out, types.Endpoint{Proto: types.ProtoTCP, Addr: pm.mappedTCP})
	}
	return out
}

// Refresh attempts UPnP IGDv2, UPnP IGDv1, and NAT-PMP mappings for localUDPPort and localTCPPort.
func (pm *PortMapper) Refresh(ctx context.Context, localIP net.IP, localUDPPort, localTCPPort uint16) {
	if localIP == nil || (localUDPPort == 0 && localTCPPort == 0) {
		return
	}
	extIP, udpOK, tcpOK := tryUPnP(ctx, localIP.String(), localUDPPort, localTCPPort)
	if extIP == "" {
		extIP, udpOK, tcpOK = tryNATPMP(localIP, localUDPPort, localTCPPort)
	}
	if extIP == "" {
		return
	}

	pm.mu.Lock()
	if udpOK && localUDPPort > 0 {
		pm.mappedUDP = net.JoinHostPort(extIP, strconv.Itoa(int(localUDPPort)))
	}
	if tcpOK && localTCPPort > 0 {
		pm.mappedTCP = net.JoinHostPort(extIP, strconv.Itoa(int(localTCPPort)))
	}
	pm.mu.Unlock()
}

func tryUPnP(ctx context.Context, internalClient string, udpPort, tcpPort uint16) (extIP string, udpOK, tcpOK bool) {
	// Try IGDv2 WANIPConnection2
	if clients, _, err := internetgateway2.NewWANIPConnection2ClientsCtx(ctx); err == nil {
		for _, c := range clients {
			ip, err := c.GetExternalIPAddressCtx(ctx)
			if err != nil || ip == "" || ip == "0.0.0.0" {
				continue
			}
			if udpPort > 0 {
				if c.AddPortMappingCtx(ctx, "", udpPort, "UDP", udpPort, internalClient, true, "AckTier-UDP", mappingLeaseSec) == nil {
					udpOK = true
				}
			}
			if tcpPort > 0 {
				if c.AddPortMappingCtx(ctx, "", tcpPort, "TCP", tcpPort, internalClient, true, "AckTier-TCP", mappingLeaseSec) == nil {
					tcpOK = true
				}
			}
			if udpOK || tcpOK {
				return ip, udpOK, tcpOK
			}
		}
	}

	// Fallback to IGDv1 WANIPConnection1
	if clients, _, err := internetgateway1.NewWANIPConnection1ClientsCtx(ctx); err == nil {
		for _, c := range clients {
			ip, err := c.GetExternalIPAddressCtx(ctx)
			if err != nil || ip == "" || ip == "0.0.0.0" {
				continue
			}
			if udpPort > 0 {
				if c.AddPortMappingCtx(ctx, "", udpPort, "UDP", udpPort, internalClient, true, "AckTier-UDP", mappingLeaseSec) == nil {
					udpOK = true
				}
			}
			if tcpPort > 0 {
				if c.AddPortMappingCtx(ctx, "", tcpPort, "TCP", tcpPort, internalClient, true, "AckTier-TCP", mappingLeaseSec) == nil {
					tcpOK = true
				}
			}
			if udpOK || tcpOK {
				return ip, udpOK, tcpOK
			}
		}
	}
	return "", false, false
}

func tryNATPMP(localIP net.IP, udpPort, tcpPort uint16) (extIP string, udpOK, tcpOK bool) {
	ip4 := localIP.To4()
	if ip4 == nil {
		return "", false, false
	}
	// Probe standard SOHO gateway .1 on the same /24 subnet
	gw := net.IPv4(ip4[0], ip4[1], ip4[2], 1)
	client := natpmp.NewClientWithTimeout(gw, 800_000_000) // 800ms timeout
	res, err := client.GetExternalAddress()
	if err != nil {
		return "", false, false
	}
	ext := net.IP(res.ExternalIPAddress[:]).String()
	if ext == "0.0.0.0" {
		return "", false, false
	}
	if udpPort > 0 {
		if _, err := client.AddPortMapping("udp", int(udpPort), int(udpPort), mappingLeaseSec); err == nil {
			udpOK = true
		}
	}
	if tcpPort > 0 {
		if _, err := client.AddPortMapping("tcp", int(tcpPort), int(tcpPort), mappingLeaseSec); err == nil {
			tcpOK = true
		}
	}
	if !udpOK && !tcpOK {
		return "", false, false
	}
	return fmt.Sprintf("%s", ext), udpOK, tcpOK
}

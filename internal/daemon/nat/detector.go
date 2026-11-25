package nat

import (
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// Kind represents the classified NAT mapping behavior of the local network.
type Kind byte

const (
	KindUnknown    Kind = 0
	KindPublic     Kind = 1 // Public IP directly on local interface
	KindCone       Kind = 2 // Endpoint-Independent Mapping (Full / Restricted / Port-Restricted Cone)
	KindSymmetric  Kind = 3 // Endpoint-Dependent Mapping (Symmetric NAT)
	KindUDPBlocked Kind = 4 // Outbound UDP probes blocked
)

func (k Kind) String() string {
	switch k {
	case KindPublic:
		return "open-public"
	case KindCone:
		return "cone"
	case KindSymmetric:
		return "symmetric"
	case KindUDPBlocked:
		return "udp-blocked"
	default:
		return "unknown"
	}
}

// Summary describes the latest local NAT & STUN diagnostic snapshot (for `acktier netcheck`).
type Summary struct {
	NATType          string  `json:"natType"`
	PublicUDPAddr    string  `json:"publicUdpAddr,omitempty"`
	AltPublicUDPAddr string  `json:"altPublicUdpAddr,omitempty"`
	PortStep         int16   `json:"portStep,omitempty"`
	STUNLatencyMs    float64 `json:"stunLatencyMs,omitempty"`
	UPnPMappedUDP    string  `json:"upnpMappedUdp,omitempty"`
	UPnPMappedTCP    string  `json:"upnpMappedTcp,omitempty"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

// Detector tracks dual-endpoint STUN observations to classify Cone vs Symmetric NAT and port step delta.
type Detector struct {
	mu               sync.RWMutex
	primarySTUN      string
	altSTUN          string
	observedPrimary  string
	observedAlt      string
	stunRTT          time.Duration
	kind             Kind
	portStep         int16
	updatedAt        time.Time
}

func NewDetector() *Detector {
	return &Detector{kind: KindUnknown}
}

func (d *Detector) SetSTUNServers(primary, alt string) {
	d.mu.Lock()
	d.primarySTUN = primary
	d.altSTUN = alt
	d.mu.Unlock()
}

// ResetObservations clears cached WAN observations when the host switches network interfaces (e.g. Wi-Fi -> Hotspot).
func (d *Detector) ResetObservations() {
	d.mu.Lock()
	d.observedPrimary = ""
	d.observedAlt = ""
	d.kind = KindUnknown
	d.portStep = 0
	d.mu.Unlock()
}

// RecordObservation updates NAT classification when a STUN Pong arrives from fromSTUNAddr.
func (d *Detector) RecordObservation(fromSTUNAddr, observedAddr string, rtt time.Duration, localIPs []netip.Addr) {
	if observedAddr == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	d.updatedAt = time.Now()
	if rtt > 0 {
		d.stunRTT = rtt
	}

	if d.altSTUN != "" && fromSTUNAddr == d.altSTUN {
		d.observedAlt = observedAddr
	} else {
		d.observedPrimary = observedAddr
	}

	// Check if observed IP matches one of the host's own interface IPs
	obsHost, obsPortStr, err := net.SplitHostPort(d.observedPrimary)
	if err != nil {
		return
	}
	if obsIP, pErr := netip.ParseAddr(obsHost); pErr == nil {
		for _, lip := range localIPs {
			if lip.Unmap() == obsIP.Unmap() {
				d.kind = KindPublic
				d.portStep = 0
				return
			}
		}
	}

	if d.observedPrimary != "" && d.observedAlt != "" {
		_, altPortStr, err2 := net.SplitHostPort(d.observedAlt)
		if err2 == nil {
			p1, _ := strconv.Atoi(obsPortStr)
			p2, _ := strconv.Atoi(altPortStr)
			if p1 > 0 && p2 > 0 {
				if p1 == p2 {
					d.kind = KindCone
					d.portStep = 0
				} else {
					d.kind = KindSymmetric
					diff := p2 - p1
					if diff >= -64 && diff <= 64 {
						d.portStep = int16(diff)
					} else {
						d.portStep = 1
					}
				}
				return
			}
		}
	}

	if d.observedPrimary != "" && d.kind == KindUnknown {
		d.kind = KindCone
	}
}

func (d *Detector) MarkUDPBlockedIfNoObservation() {
	d.mu.Lock()
	if d.observedPrimary == "" && d.observedAlt == "" {
		d.kind = KindUDPBlocked
	}
	d.mu.Unlock()
}

func (d *Detector) Snapshot() (Kind, int16, string, float64) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.kind, d.portStep, d.observedPrimary, float64(d.stunRTT.Microseconds()) / 1000.0
}

func (d *Detector) FullSummary(upnpUDP, upnpTCP string) Summary {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return Summary{
		NATType:          d.kind.String(),
		PublicUDPAddr:    d.observedPrimary,
		AltPublicUDPAddr: d.observedAlt,
		PortStep:         d.portStep,
		STUNLatencyMs:    float64(d.stunRTT.Microseconds()) / 1000.0,
		UPnPMappedUDP:    upnpUDP,
		UPnPMappedTCP:    upnpTCP,
		UpdatedAt:        d.updatedAt,
	}
}

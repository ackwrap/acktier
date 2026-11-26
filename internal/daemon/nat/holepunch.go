package nat

import (
	"net"
	"strconv"

	"github.com/ackwrap/acktier/pkg/types"
)

const maxPredictedPorts = 8

// BuildUDPPunchTargets constructs the ordered list of UDP addresses to punch for a peer,
// appending adjacent predicted ports if the peer is behind a Symmetric NAT with predictable port stepping.
func BuildUDPPunchTargets(candidates []types.Endpoint, peerKind Kind, portStep int16) []string {
	seen := make(map[string]bool)
	var out []string
	var primaryPublicHost string
	var primaryPublicPort int

	for _, ep := range candidates {
		if ep.Proto != types.ProtoUDP || ep.Addr == "" {
			continue
		}
		if !seen[ep.Addr] {
			seen[ep.Addr] = true
			out = append(out, ep.Addr)
		}
		if !ep.IsLAN && primaryPublicHost == "" {
			if h, pStr, err := net.SplitHostPort(ep.Addr); err == nil {
				if p, pErr := strconv.Atoi(pStr); pErr == nil && p > 1024 && p < 65520 {
					primaryPublicHost = h
					primaryPublicPort = p
				}
			}
		}
	}

	// Symmetric NAT port prediction burst (bounded strictly to maxPredictedPorts)
	if peerKind == KindSymmetric && primaryPublicHost != "" && primaryPublicPort > 0 {
		step := int(portStep)
		if step == 0 {
			step = 1
		}
		added := 0
		for k := 1; k <= 6 && added < maxPredictedPorts; k++ {
			candPort := primaryPublicPort + k*step
			if candPort <= 1024 || candPort >= 65535 {
				continue
			}
			addr := net.JoinHostPort(primaryPublicHost, strconv.Itoa(candPort))
			if !seen[addr] {
				seen[addr] = true
				out = append(out, addr)
				added++
			}
		}
		// Also probe ±1 neighbor in case port step jittered
		for _, delta := range []int{1, -1} {
			if added >= maxPredictedPorts {
				break
			}
			candPort := primaryPublicPort + delta
			if candPort > 1024 && candPort < 65535 {
				addr := net.JoinHostPort(primaryPublicHost, strconv.Itoa(candPort))
				if !seen[addr] {
					seen[addr] = true
					out = append(out, addr)
					added++
				}
			}
		}
	}

	return out
}

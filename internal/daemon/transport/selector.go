package transport

import (
	"math"
	"net"
	"sync"
	"time"

	"github.com/acktier/acktier/pkg/types"
)

const (
	PathActiveTTL            = 45 * time.Second
	DefaultFastProbeAfter    = 2500 * time.Millisecond
	DefaultBlackholeTimeout  = 4500 * time.Millisecond
	fastProbeMinInterval     = 700 * time.Millisecond
)

// PathMetrics tracks live latency, active-tx blackhole state, and reachability for a single (Peer, Endpoint) tuple.
type PathMetrics struct {
	Endpoint          types.Endpoint
	SmoothedRTTMicros int64
	LastRx            time.Time
	LastProbeTx       time.Time
	UnansweredTxSince time.Time // Non-zero when packets were sent since LastRx with zero inbound response
	RxPackets         uint64
}

// Score computes a composite path cost in milliseconds (lower is better), marking paths dead
// either when idle > PathActiveTTL OR when active outbound traffic goes unanswered >= blackholeTimeout!
func (pm *PathMetrics) Score(now time.Time, blackholeTimeout time.Duration) (float64, bool) {
	if pm.LastRx.IsZero() || now.Sub(pm.LastRx) > PathActiveTTL {
		return math.MaxFloat64, false
	}
	if blackholeTimeout > 0 && !pm.UnansweredTxSince.IsZero() && now.Sub(pm.UnansweredTxSince) >= blackholeTimeout {
		return math.MaxFloat64, false
	}
	rttMs := float64(pm.SmoothedRTTMicros) / 1000.0
	if rttMs <= 0 {
		rttMs = 15.0 // default optimistic initial estimate upon first data/handshake rx
	}
	var penalty float64
	switch pm.Endpoint.Proto {
	case types.ProtoUDP:
		penalty = 0.0
	case types.ProtoQUIC:
		penalty = 1.0
	case types.ProtoTCP:
		penalty = 3.0
	case types.ProtoWSS:
		penalty = 5.0
	}
	if pm.Endpoint.IsLAN {
		penalty -= 4.0 // Favor direct L2 LAN links
	}
	return rttMs + penalty, true
}

// Selector maintains multi-protocol candidate endpoints per peer and dynamically chooses the lowest-cost active path.
type Selector struct {
	mu               sync.RWMutex
	peers            map[types.PublicKey]map[types.Endpoint]*PathMetrics
	fastProbeAfter   time.Duration
	blackholeTimeout time.Duration
}

func NewSelector() *Selector {
	return &Selector{
		peers:            make(map[types.PublicKey]map[types.Endpoint]*PathMetrics),
		fastProbeAfter:   DefaultFastProbeAfter,
		blackholeTimeout: DefaultBlackholeTimeout,
	}
}

// SetBlackholeThresholds customizes the active-tx fast-probe trigger and silent blackhole failover timeout.
func (s *Selector) SetBlackholeThresholds(fastProbeAfter, blackholeTimeout time.Duration) {
	s.mu.Lock()
	if fastProbeAfter > 0 {
		s.fastProbeAfter = fastProbeAfter
	}
	if blackholeTimeout > 0 {
		s.blackholeTimeout = blackholeTimeout
	}
	s.mu.Unlock()
}

// SyncCandidates updates a peer's candidate list from an authoritative NetMap or CallMeMaybe announcement,
// immediately evicting stale endpoints whose host IP the peer no longer owns (instant Wi-Fi -> 5G roaming!),
// while preserving dynamically punched ports on IPs the peer still advertises.
func (s *Selector) SyncCandidates(peer types.PublicKey, authoritative []types.Endpoint) {
	activeHosts := make(map[string]bool, len(authoritative))
	for _, ep := range authoritative {
		if h, _, err := net.SplitHostPort(ep.Addr); err == nil && h != "" {
			activeHosts[h] = true
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.peers[peer]
	if m == nil {
		m = make(map[types.Endpoint]*PathMetrics)
		s.peers[peer] = m
	}

	if len(activeHosts) > 0 {
		for ep := range m {
			if h, _, err := net.SplitHostPort(ep.Addr); err == nil && !activeHosts[h] {
				delete(m, ep)
			}
		}
	}

	for _, ep := range authoritative {
		if ep.Addr == "" || ep.Proto == "" {
			continue
		}
		if existing, ok := m[ep]; !ok {
			m[ep] = &PathMetrics{Endpoint: ep}
		} else {
			existing.Endpoint.IsLAN = ep.IsLAN
		}
	}
}

// SetCandidates merges additional (e.g. LAN-discovered) candidate endpoints without evicting existing ones.
func (s *Selector) SetCandidates(peer types.PublicKey, endpoints []types.Endpoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.peers[peer]
	if m == nil {
		m = make(map[types.Endpoint]*PathMetrics)
		s.peers[peer] = m
	}
	for _, ep := range endpoints {
		if ep.Addr == "" || ep.Proto == "" {
			continue
		}
		if existing, ok := m[ep]; !ok {
			m[ep] = &PathMetrics{Endpoint: ep}
		} else if ep.IsLAN {
			existing.Endpoint.IsLAN = true
		}
	}
}

// RecordTx records an outbound data transmission on ep and returns shouldFastProbe=true when
// continuous outbound traffic has gone unanswered for >= fastProbeAfter (soliciting an immediate Pong!).
func (s *Selector) RecordTx(peer types.PublicKey, ep types.Endpoint) (shouldFastProbe bool) {
	if ep.Addr == "" || ep.Proto == "" {
		return false
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.peers[peer]
	if m == nil {
		return false
	}
	pm := m[ep]
	if pm == nil {
		return false
	}
	if pm.UnansweredTxSince.IsZero() {
		pm.UnansweredTxSince = now
		return false
	}
	if now.Sub(pm.UnansweredTxSince) >= s.fastProbeAfter && now.Sub(pm.LastProbeTx) >= fastProbeMinInterval {
		pm.LastProbeTx = now
		return true
	}
	return false
}

// RecordRx marks an endpoint as verified-alive upon receiving an authenticated packet and clears blackhole timers.
func (s *Selector) RecordRx(peer types.PublicKey, ep types.Endpoint, rttSample time.Duration) {
	if ep.Addr == "" || ep.Proto == "" {
		return
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.peers[peer]
	if m == nil {
		m = make(map[types.Endpoint]*PathMetrics)
		s.peers[peer] = m
	}
	pm, ok := m[ep]
	if !ok {
		pm = &PathMetrics{Endpoint: ep}
		m[ep] = pm
	}
	pm.LastRx = now
	pm.UnansweredTxSince = time.Time{}
	pm.RxPackets++
	if rttSample > 0 {
		sampleUs := rttSample.Microseconds()
		if sampleUs < 50 {
			sampleUs = 50
		}
		if pm.SmoothedRTTMicros == 0 {
			pm.SmoothedRTTMicros = sampleUs
		} else {
			pm.SmoothedRTTMicros = (pm.SmoothedRTTMicros*3 + sampleUs) / 4
		}
	}
}

// OnLocalNetworkChange accelerates path re-verification when the local host switches Wi-Fi / hotspot interfaces.
func (s *Selector) OnLocalNetworkChange() {
	now := time.Now()
	s.mu.Lock()
	for _, m := range s.peers {
		for _, pm := range m {
			if !pm.LastRx.IsZero() && pm.UnansweredTxSince.IsZero() {
				// Start unanswered timer at fastProbe threshold so next tx immediately verifies path!
				pm.UnansweredTxSince = now.Add(-s.fastProbeAfter)
			}
		}
	}
	s.mu.Unlock()
}

// BestEndpoint returns the lowest-score verified direct endpoint for peer, if any is currently alive and non-blackholed.
func (s *Selector) BestEndpoint(peer types.PublicKey) (types.Endpoint, float64, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := s.peers[peer]
	if len(m) == 0 {
		return types.Endpoint{}, 0, false
	}
	now := time.Now()
	bestScore := math.MaxFloat64
	var bestPM *PathMetrics
	for _, pm := range m {
		score, alive := pm.Score(now, s.blackholeTimeout)
		if alive && score < bestScore {
			bestScore = score
			bestPM = pm
		}
	}
	if bestPM == nil {
		return types.Endpoint{}, 0, false
	}
	return bestPM.Endpoint, float64(bestPM.SmoothedRTTMicros) / 1000.0, true
}

// AllCandidates returns all known candidate endpoints for peer (for probing & hole punching).
func (s *Selector) AllCandidates(peer types.PublicKey) []types.Endpoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := s.peers[peer]
	out := make([]types.Endpoint, 0, len(m))
	for ep := range m {
		out = append(out, ep)
	}
	return out
}

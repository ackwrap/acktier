package transport

import (
	"math"
	"sync"
	"time"

	"github.com/acktier/acktier/pkg/types"
)

const PathActiveTTL = 45 * time.Second

// PathMetrics tracks live latency and reachability for a single (Peer, Endpoint) tuple.
type PathMetrics struct {
	Endpoint          types.Endpoint
	SmoothedRTTMicros int64
	LastRx            time.Time
	LastProbeTx       time.Time
	RxPackets         uint64
}

// Score computes a composite path cost in milliseconds (lower is better).
func (pm *PathMetrics) Score(now time.Time) (float64, bool) {
	if pm.LastRx.IsZero() || now.Sub(pm.LastRx) > PathActiveTTL {
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
	mu    sync.RWMutex
	peers map[types.PublicKey]map[types.Endpoint]*PathMetrics
}

func NewSelector() *Selector {
	return &Selector{
		peers: make(map[types.PublicKey]map[types.Endpoint]*PathMetrics),
	}
}

// SetCandidates merges control-plane or LAN-discovered candidate endpoints for a peer.
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

// RecordRx marks an endpoint as verified-alive upon receiving an authenticated packet.
func (s *Selector) RecordRx(peer types.PublicKey, ep types.Endpoint, rttSample time.Duration) {
	if ep.Addr == "" || ep.Proto == "" {
		return
	}
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
	pm.LastRx = time.Now()
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

// BestEndpoint returns the lowest-score verified direct endpoint for peer, if any is currently alive.
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
		score, alive := pm.Score(now)
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

package transport

import (
	"math"
	"net"
	"sync"
	"time"

	"github.com/acktier/acktier/pkg/types"
)

const (
	PathActiveTTL           = 45 * time.Second
	DefaultFastProbeAfter   = 2500 * time.Millisecond
	DefaultBlackholeTimeout = 4500 * time.Millisecond
	fastProbeMinInterval    = 700 * time.Millisecond
	probeLossGrace          = 250 * time.Millisecond
)

type endpointKey struct {
	proto types.TransportProto
	addr  string
}

func keyFor(ep types.Endpoint) endpointKey {
	return endpointKey{proto: ep.Proto, addr: ep.Addr}
}

// PathQuality summarizes RTT, jitter, packet loss rate, and composite cost for a verified direct endpoint.
type PathQuality struct {
	Endpoint        types.Endpoint
	RTTMillis       float64
	JitterMillis    float64
	LossRate        float64 // 0.0 .. 1.0 over sliding 32-probe window
	EffectiveCostMs float64 // RTT + 2*Jitter + 300*LossRate + ProtoPenalty + LANBonus
}

type probeSlot struct {
	id     uint64
	sentAt time.Time
	acked  bool
}

// PathMetrics tracks live latency, jitter, 16-slot RTT-aware probe loss, and blackhole state for a (Peer, Endpoint).
type PathMetrics struct {
	Endpoint          types.Endpoint
	SmoothedRTTMicros int64
	JitterMicros      int64
	LastRx            time.Time
	LastProbeTx       time.Time
	UnansweredTxSince time.Time
	RxPackets         uint64

	probeSlots [16]probeSlot
	probeIdx   uint8
}

func (pm *PathMetrics) lossRateLocked(now time.Time) float64 {
	grace := probeLossGrace
	if rttGrace := time.Duration(pm.SmoothedRTTMicros*3) * time.Microsecond; rttGrace > grace {
		grace = rttGrace
	}
	eligible := 0
	acked := 0
	for i := range pm.probeSlots {
		sl := pm.probeSlots[i]
		if sl.id == 0 {
			continue
		}
		if sl.acked {
			eligible++
			acked++
		} else if now.Sub(sl.sentAt) >= grace {
			eligible++
		}
	}
	if eligible == 0 || acked >= eligible {
		return 0
	}
	return float64(eligible-acked) / float64(eligible)
}

// Quality computes quality-adjusted path cost (RTT + 2*Jitter + 300ms*LossRate + ProtoPenalty + LANBonus).
func (pm *PathMetrics) Quality(now time.Time, blackholeTimeout time.Duration) (PathQuality, bool) {
	if pm.LastRx.IsZero() || now.Sub(pm.LastRx) > PathActiveTTL {
		return PathQuality{}, false
	}
	if blackholeTimeout > 0 && !pm.UnansweredTxSince.IsZero() && now.Sub(pm.UnansweredTxSince) >= blackholeTimeout {
		return PathQuality{}, false
	}
	rttMs := float64(pm.SmoothedRTTMicros) / 1000.0
	if rttMs <= 0 {
		rttMs = 15.0
	}
	jitterMs := float64(pm.JitterMicros) / 1000.0
	loss := pm.lossRateLocked(now)

	var protoAdjust float64
	switch pm.Endpoint.Proto {
	case types.ProtoUDP:
		protoAdjust = 0.0
	case types.ProtoQUIC:
		protoAdjust = 1.0
	case types.ProtoTCP:
		protoAdjust = 3.0
	case types.ProtoWSS:
		protoAdjust = 5.0
	}
	if pm.Endpoint.IsLAN {
		protoAdjust -= 4.0
	}

	effCost := rttMs + 2.0*jitterMs + 300.0*loss + protoAdjust
	return PathQuality{
		Endpoint:        pm.Endpoint,
		RTTMillis:       rttMs,
		JitterMillis:    jitterMs,
		LossRate:        loss,
		EffectiveCostMs: effCost,
	}, true
}

// Selector maintains multi-protocol candidate endpoints per peer and dynamically chooses the lowest-cost active path.
type Selector struct {
	mu               sync.RWMutex
	peers            map[types.PublicKey]map[endpointKey]*PathMetrics
	fastProbeAfter   time.Duration
	blackholeTimeout time.Duration
}

func NewSelector() *Selector {
	return &Selector{
		peers:            make(map[types.PublicKey]map[endpointKey]*PathMetrics),
		fastProbeAfter:   DefaultFastProbeAfter,
		blackholeTimeout: DefaultBlackholeTimeout,
	}
}

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
// immediately evicting stale endpoints whose host IP the peer no longer owns.
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
		m = make(map[endpointKey]*PathMetrics)
		s.peers[peer] = m
	}

	if len(activeHosts) > 0 {
		for k := range m {
			if h, _, err := net.SplitHostPort(k.addr); err == nil && !activeHosts[h] {
				delete(m, k)
			}
		}
	}

	for _, ep := range authoritative {
		if ep.Addr == "" || ep.Proto == "" {
			continue
		}
		k := keyFor(ep)
		if existing, ok := m[k]; !ok {
			m[k] = &PathMetrics{Endpoint: ep}
		} else if ep.IsLAN {
			existing.Endpoint.IsLAN = true
		}
	}
}

// SetCandidates merges additional (e.g. LAN-discovered) candidate endpoints without evicting existing ones.
func (s *Selector) SetCandidates(peer types.PublicKey, endpoints []types.Endpoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.peers[peer]
	if m == nil {
		m = make(map[endpointKey]*PathMetrics)
		s.peers[peer] = m
	}
	for _, ep := range endpoints {
		if ep.Addr == "" || ep.Proto == "" {
			continue
		}
		k := keyFor(ep)
		if existing, ok := m[k]; !ok {
			m[k] = &PathMetrics{Endpoint: ep}
		} else if ep.IsLAN {
			existing.Endpoint.IsLAN = true
		}
	}
}

// RecordProbeSent tracks an outbound Ping probe ID so unanswered probes are factored into packet loss rate!
func (s *Selector) RecordProbeSent(peer types.PublicKey, ep types.Endpoint, probeID uint64) {
	if ep.Addr == "" || ep.Proto == "" || probeID == 0 {
		return
	}
	now := time.Now()
	k := keyFor(ep)
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.peers[peer]
	if m == nil {
		m = make(map[endpointKey]*PathMetrics)
		s.peers[peer] = m
	}
	pm := m[k]
	if pm == nil {
		pm = &PathMetrics{Endpoint: ep}
		m[k] = pm
	}
	pm.probeSlots[pm.probeIdx%16] = probeSlot{
		id:     probeID,
		sentAt: now,
		acked:  false,
	}
	pm.probeIdx++
}

// RecordTx records an outbound data transmission on ep and returns shouldFastProbe=true when
// continuous outbound traffic has gone unanswered for >= fastProbeAfter.
func (s *Selector) RecordTx(peer types.PublicKey, ep types.Endpoint) (shouldFastProbe bool) {
	if ep.Addr == "" || ep.Proto == "" {
		return false
	}
	now := time.Now()
	k := keyFor(ep)
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.peers[peer]
	if m == nil {
		return false
	}
	pm := m[k]
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

func (s *Selector) RecordRx(peer types.PublicKey, ep types.Endpoint, rttSample time.Duration) {
	s.RecordProbeRx(peer, ep, 0, rttSample)
}

func (s *Selector) RecordProbeRx(peer types.PublicKey, ep types.Endpoint, probeID uint64, rttSample time.Duration) {
	if ep.Addr == "" || ep.Proto == "" {
		return
	}
	now := time.Now()
	k := keyFor(ep)
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.peers[peer]
	if m == nil {
		m = make(map[endpointKey]*PathMetrics)
		s.peers[peer] = m
	}
	pm, ok := m[k]
	if !ok {
		pm = &PathMetrics{Endpoint: ep}
		m[k] = pm
	}
	if ep.IsLAN {
		pm.Endpoint.IsLAN = true
	}
	pm.LastRx = now
	pm.UnansweredTxSince = time.Time{}
	pm.RxPackets++

	if probeID != 0 {
		for i := range pm.probeSlots {
			if pm.probeSlots[i].id == probeID {
				pm.probeSlots[i].acked = true
				break
			}
		}
	}

	if rttSample > 0 {
		sampleUs := rttSample.Microseconds()
		if sampleUs < 50 {
			sampleUs = 50
		}
		if pm.SmoothedRTTMicros == 0 {
			pm.SmoothedRTTMicros = sampleUs
		} else {
			diff := sampleUs - pm.SmoothedRTTMicros
			if diff < 0 {
				diff = -diff
			}
			pm.JitterMicros = (pm.JitterMicros*3 + diff) / 4
			pm.SmoothedRTTMicros = (pm.SmoothedRTTMicros*3 + sampleUs) / 4
		}
	}
}

func (s *Selector) OnLocalNetworkChange() {
	now := time.Now()
	s.mu.Lock()
	for _, m := range s.peers {
		for _, pm := range m {
			if !pm.LastRx.IsZero() && pm.UnansweredTxSince.IsZero() {
				pm.UnansweredTxSince = now.Add(-s.fastProbeAfter)
			}
		}
	}
	s.mu.Unlock()
}

// BestQuality returns the lowest-cost verified direct PathQuality for peer.
func (s *Selector) BestQuality(peer types.PublicKey) (PathQuality, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := s.peers[peer]
	if len(m) == 0 {
		return PathQuality{}, false
	}
	now := time.Now()
	bestCost := math.MaxFloat64
	var bestQ PathQuality
	found := false
	for _, pm := range m {
		q, alive := pm.Quality(now, s.blackholeTimeout)
		if alive && q.EffectiveCostMs < bestCost {
			bestCost = q.EffectiveCostMs
			bestQ = q
			found = true
		}
	}
	return bestQ, found
}

func (s *Selector) BestEndpoint(peer types.PublicKey) (types.Endpoint, float64, bool) {
	q, ok := s.BestQuality(peer)
	if !ok {
		return types.Endpoint{}, 0, false
	}
	return q.Endpoint, q.RTTMillis, true
}

func (s *Selector) AllCandidates(peer types.PublicKey) []types.Endpoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := s.peers[peer]
	out := make([]types.Endpoint, 0, len(m))
	for _, pm := range m {
		out = append(out, pm.Endpoint)
	}
	return out
}

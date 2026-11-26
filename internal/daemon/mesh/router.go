package mesh

import (
	"container/heap"
	"math"
	"sync"

	"github.com/ackwrap/acktier/pkg/types"
)

const (
	MaxMeshHops    = 4
	HopPenaltyMs   = 1.5  // Per-hop transit overhead penalty in ms
	DefaultLinkRTT = 10.0 // Fallback RTT in ms if verified link has 0ms sample
)

// Route describes the computed optimal multi-hop or direct mesh path to a destination peer.
type Route struct {
	Destination   types.PublicKey   `json:"destination"`
	NextHop       types.PublicKey   `json:"nextHop"`
	Hops          []types.PublicKey `json:"hops"` // Excluding Self, ending at Destination (len=1 is direct, len>=2 is peer-relay)
	TotalCostMs   float64           `json:"totalCostMs"`
	IsPeerRelayed bool              `json:"isPeerRelayed"`
}

type edge struct {
	to     types.PublicKey
	costMs float64
}

// Router computes loop-free shortest-delay multi-hop routes across CanRelay-enabled mesh peers using Dijkstra.
type Router struct {
	mu          sync.RWMutex
	selfKey     types.PublicKey
	routes      map[types.PublicKey]Route
	relayRoutes map[types.PublicKey]Route // Best stepping-stone route with len(Hops) >= 2
	names       map[types.PublicKey]string
}

func NewRouter(selfKey types.PublicKey) *Router {
	return &Router{
		selfKey:     selfKey,
		routes:      make(map[types.PublicKey]Route),
		relayRoutes: make(map[types.PublicKey]Route),
		names:       make(map[types.PublicKey]string),
	}
}

// Recompute rebuilds the link-state graph from self's live direct links and peers' advertised PeerLinks,
// then runs bounded-hop Dijkstra to find the minimum-latency path to every peer.
func (r *Router) Recompute(selfDirect []types.PeerLink, peers []types.PeerNode) {
	adj := make(map[types.PublicKey][]edge, len(peers)+1)
	canTransit := make(map[types.PublicKey]bool, len(peers))
	names := make(map[types.PublicKey]string, len(peers))

	peerOnline := make(map[types.PublicKey]bool, len(peers))
	for _, p := range peers {
		names[p.NodeKey] = p.Name
		if p.Online {
			peerOnline[p.NodeKey] = true
			if p.CanRelay {
				canTransit[p.NodeKey] = true
			}
		}
	}

	addDirectedEdge := func(u, v types.PublicKey, rttMs float64) {
		if u == v || u.IsZero() || v.IsZero() {
			return
		}
		if rttMs <= 0 {
			rttMs = DefaultLinkRTT
		}
		// Deduplicate / keep minimum cost edge
		list := adj[u]
		for i := range list {
			if list[i].to == v {
				if rttMs < list[i].costMs {
					list[i].costMs = rttMs
				}
				return
			}
		}
		adj[u] = append(adj[u], edge{to: v, costMs: rttMs})
	}

	// Build lookup of peer-reported cost back to Self so asymmetric uncalibrated links inherit known path loss!
	peerCostToSelf := make(map[types.PublicKey]float64)
	for _, p := range peers {
		if !p.Online {
			continue
		}
		for _, lk := range p.Links {
			if lk.Target == r.selfKey {
				peerCostToSelf[p.NodeKey] = lk.EffectiveCostMs()
			}
		}
	}

	// 1. Add Self's live verified direct links (weighted by max of Self & Peer quality-adjusted cost!)
	for _, lk := range selfDirect {
		if peerOnline[lk.Target] {
			cost := lk.EffectiveCostMs()
			if revCost := peerCostToSelf[lk.Target]; revCost > cost {
				cost = revCost
			}
			addDirectedEdge(r.selfKey, lk.Target, cost)
		}
	}

	// 2. Add peer-to-peer links from online peers
	// Note: If peer U (CanRelay) reports a link to V, or V reports a link to U (where U is CanRelay),
	// treat verified L4/L7 tunnels as bidirectional symmetric links when one side hasn't flushed heartbeat yet.
	for _, p := range peers {
		if !p.Online {
			continue
		}
		for _, lk := range p.Links {
			if lk.Target != r.selfKey && !peerOnline[lk.Target] {
				continue
			}
			cost := lk.EffectiveCostMs()
			addDirectedEdge(p.NodeKey, lk.Target, cost)
			// Never let a remote peer's report forge or override Self's own outbound direct link measurement!
			if lk.Target != r.selfKey {
				addDirectedEdge(lk.Target, p.NodeKey, cost)
			}
		}
	}

	// 3. Bounded-hop Dijkstra from r.selfKey
	type stateKey struct {
		node types.PublicKey
		hops int
	}
	bestDist := make(map[types.PublicKey]float64, len(peers)+1)
	bestPath := make(map[types.PublicKey][]types.PublicKey, len(peers))
	bestRelayDist := make(map[types.PublicKey]float64, len(peers))
	bestRelayPath := make(map[types.PublicKey][]types.PublicKey, len(peers))
	bestDist[r.selfKey] = 0

	pq := &dijkstraHeap{{node: r.selfKey, cost: 0, path: nil}}
	heap.Init(pq)

	visitedAtHop := make(map[stateKey]float64)

	for pq.Len() > 0 {
		cur := heap.Pop(pq).(dijkstraItem)
		if len(cur.path) >= MaxMeshHops {
			continue
		}
		// Only Self or CanRelay peers may forward traffic to a further hop!
		if cur.node != r.selfKey && !canTransit[cur.node] {
			continue
		}

		for _, e := range adj[cur.node] {
			if e.to == r.selfKey || containsKey(cur.path, e.to) {
				continue
			}
			nextHops := len(cur.path) + 1
			penalty := 0.0
			if nextHops > 1 {
				penalty = HopPenaltyMs
			}
			newCost := cur.cost + e.costMs + penalty

			sk := stateKey{node: e.to, hops: nextHops}
			if prev, seen := visitedAtHop[sk]; seen && prev <= newCost {
				continue
			}
			visitedAtHop[sk] = newCost

			newPath := make([]types.PublicKey, nextHops)
			copy(newPath, cur.path)
			newPath[nextHops-1] = e.to

			if prevBest, ok := bestDist[e.to]; !ok || newCost < prevBest {
				bestDist[e.to] = newCost
				bestPath[e.to] = newPath
			}
			if nextHops >= 2 {
				if prevRelayBest, ok := bestRelayDist[e.to]; !ok || newCost < prevRelayBest {
					bestRelayDist[e.to] = newCost
					bestRelayPath[e.to] = newPath
				}
			}

			if nextHops < MaxMeshHops && canTransit[e.to] {
				heap.Push(pq, dijkstraItem{
					node: e.to,
					cost: newCost,
					path: newPath,
				})
			}
		}
	}

	computed := make(map[types.PublicKey]Route, len(bestPath))
	for dst, path := range bestPath {
		if len(path) == 0 {
			continue
		}
		computed[dst] = Route{
			Destination:   dst,
			NextHop:       path[0],
			Hops:          path,
			TotalCostMs:   math.Round(bestDist[dst]*100) / 100,
			IsPeerRelayed: len(path) > 1,
		}
	}

	computedRelay := make(map[types.PublicKey]Route, len(bestRelayPath))
	for dst, path := range bestRelayPath {
		if len(path) >= 2 {
			computedRelay[dst] = Route{
				Destination:   dst,
				NextHop:       path[0],
				Hops:          path,
				TotalCostMs:   math.Round(bestRelayDist[dst]*100) / 100,
				IsPeerRelayed: true,
			}
		}
	}

	r.mu.Lock()
	r.routes = computed
	r.relayRoutes = computedRelay
	r.names = names
	r.mu.Unlock()
}

// Lookup returns the optimal computed route to dst (direct or multi-hop peer relay).
func (r *Router) Lookup(dst types.PublicKey) (Route, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rt, ok := r.routes[dst]
	return rt, ok
}

// LookupRelay returns the lowest-cost multi-hop Peer-Relay stepping-stone route (len(Hops) >= 2) to dst.
func (r *Router) LookupRelay(dst types.PublicKey) (Route, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rt, ok := r.relayRoutes[dst]
	return rt, ok
}

// AllRoutes returns a snapshot of all computed mesh routes and node display names.
func (r *Router) AllRoutes() ([]Route, map[types.PublicKey]string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Route, 0, len(r.routes))
	for _, rt := range r.routes {
		out = append(out, rt)
	}
	nm := make(map[types.PublicKey]string, len(r.names))
	for k, v := range r.names {
		nm[k] = v
	}
	return out, nm
}

func containsKey(list []types.PublicKey, target types.PublicKey) bool {
	for _, k := range list {
		if k == target {
			return true
		}
	}
	return false
}

type dijkstraItem struct {
	node types.PublicKey
	cost float64
	path []types.PublicKey
}

type dijkstraHeap []dijkstraItem

func (h dijkstraHeap) Len() int            { return len(h) }
func (h dijkstraHeap) Less(i, j int) bool  { return h[i].cost < h[j].cost }
func (h dijkstraHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *dijkstraHeap) Push(x any)         { *h = append(*h, x.(dijkstraItem)) }
func (h *dijkstraHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

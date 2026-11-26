package engine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/acktier/acktier/pkg/types"
)

// applyNetMap is called under sessionMu.
func (e *Engine) applyNetMap(nm types.NetMap, refreshLease bool) {
	nm.Peers = activeMapPeers(nm.Peers)
	authKeys := make([]types.PublicKey, 0, len(nm.Peers))
	for _, p := range nm.Peers {
		authKeys = append(authKeys, p.NodeKey)
	}
	e.cryptoMgr.SetAuthorizedPeers(authKeys)
	e.pktFilter.SetRules(nm.PacketFilter)
	e.dnsResolver.UpdateNetMap(nm)

	wantExit := strings.ToLower(strings.TrimSpace(e.stateMgr.Get().ExitNode))
	var extraRoutes []netip.Prefix
	var newlyAddedPeers []types.PeerNode

	e.mu.Lock()
	prevPeers := e.peersByKey
	newByKey := make(map[types.PublicKey]*peerRuntime, len(nm.Peers))
	newByIP := make(map[netip.Addr]*peerRuntime, len(nm.Peers)*2)
	var newRoutes []routeEntry
	var selectedExit *peerRuntime

	for _, p := range nm.Peers {
		pr, exists := prevPeers[p.NodeKey]
		if !exists {
			pr = &peerRuntime{}
			if p.Online {
				newlyAddedPeers = append(newlyAddedPeers, p)
			}
		}

		var hasDefaultV4, hasDefaultV6 bool
		var cleanSubnets []netip.Prefix
		for _, rt := range p.ApprovedRoutes {
			masked := rt.Masked()
			if masked.Bits() == 0 {
				if masked.Addr().Is4() {
					hasDefaultV4 = true
				} else {
					hasDefaultV6 = true
				}
				continue
			}
			// Never allow approved subnet routes to shadow overlay IPs or loopback/link-local/multicast!
			if types.OverlapsOverlayOrSpecial(masked) {
				continue
			}
			cleanSubnets = append(cleanSubnets, masked)
			newRoutes = append(newRoutes, routeEntry{prefix: masked, peer: pr})
			extraRoutes = append(extraRoutes, masked)
		}

		pr.mu.Lock()
		pr.meta = p
		pr.hasExitV4 = hasDefaultV4
		pr.hasExitV6 = hasDefaultV6
		pr.nonDefaultSubnets = cleanSubnets
		pr.mu.Unlock()

		e.selector.SyncCandidates(p.NodeKey, p.Endpoints)

		newByKey[p.NodeKey] = pr
		if p.IPv4.IsValid() {
			newByIP[p.IPv4] = pr
		}
		if p.IPv6.IsValid() {
			newByIP[p.IPv6] = pr
		}
		if (hasDefaultV4 || hasDefaultV6) && wantExit != "" {
			// Match ONLY server-assigned unique Name, IP, or NodeKey (not self-reported Hostname)
			if strings.EqualFold(p.Name, wantExit) || p.IPv4.String() == wantExit || p.IPv6.String() == wantExit || strings.EqualFold(p.NodeKey.String(), wantExit) {
				selectedExit = pr
			}
		}
	}

	prevSelfV4 := e.netMap.Self.IPv4
	e.netMap = nm
	e.peersByKey = newByKey
	e.peersByIP = newByIP
	e.routeTable = newRoutes
	e.exitNodePeer = selectedExit
	e.selfApprovedRoutes = append([]netip.Prefix(nil), nm.Self.ApprovedRoutes...)
	if refreshLease {
		e.controlUntil = e.controlDeadlineLocked(time.Now())
	}
	e.mu.Unlock()

	if selectedExit != nil {
		selectedExit.mu.RLock()
		ek := selectedExit.meta.NodeKey
		selectedExit.mu.RUnlock()
		e.exitFlows.RetainOnlyPeer(ek)
	} else {
		e.exitFlows.Reset()
	}

	// Immediately evict any Gateway NAT proxy flows whose peer was removed, route unapproved, or ACL revoked!
	e.gateway.RevalidateFlows(func(srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16, proto uint8) bool {
		e.mu.RLock()
		_, validPeer := e.peersByIP[srcIP]
		e.mu.RUnlock()
		if !validPeer || !e.isSelfApprovedDestination(dstIP) {
			return false
		}
		return e.pktFilter.AllowsTuple(srcIP, srcPort, dstIP, dstPort, proto)
	})

	e.recomputeMeshRoutes()

	if len(nm.Relays) > 0 {
		e.natDetector.SetSTUNServers(nm.Relays[0].STUNAddr, nm.Relays[0].STUNAltAddr)
	}

	for _, np := range newlyAddedPeers {
		go e.probePeerCalibrationBurst(np.NodeKey, np.Endpoints)
	}

	if nm.Self.IPv4.IsValid() && nm.Self.IPv4 != prevSelfV4 {
		v4Pfx := netip.PrefixFrom(nm.Self.IPv4, 10)
		var v6Pfx netip.Prefix
		if nm.Self.IPv6.IsValid() {
			v6Pfx = netip.PrefixFrom(nm.Self.IPv6, 48)
		}
		if err := e.tunDev.Configure(v4Pfx, v6Pfx, extraRoutes); err != nil {
			log.Printf("[engine] warning configuring TUN %s: %v", e.tunDev.Name(), err)
		}
	}
}

func (e *Engine) mapStreamLoop(ctx context.Context, serverURL, token string) {
	st := e.stateMgr.Get()
	streamURL := fmt.Sprintf("%s/api/v1/node/map/stream?nodeKey=%s", serverURL, st.NodeKey.Public().String())
	if e.ownerNetworkID != "" {
		streamURL += "&ownerNetworkId=" + e.ownerNetworkID
	}

	backoff := 300 * time.Millisecond
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		streamCtx, cancel := context.WithCancel(ctx)
		silence := time.AfterFunc(controlStreamIdleTimeout, cancel)
		req, err := http.NewRequestWithContext(streamCtx, http.MethodGet, streamURL, nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := e.httpClient.Do(req)
			if err == nil && resp.StatusCode == http.StatusOK {
				backoff = 300 * time.Millisecond
				scanner := bufio.NewScanner(resp.Body)
				scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
				for scanner.Scan() {
					if streamCtx.Err() != nil {
						break
					}
					var ev types.MapStreamEvent
					if json.Unmarshal(scanner.Bytes(), &ev) != nil || !e.acceptControlEvent(ctx, ev) {
						break
					}
					silence.Reset(controlStreamIdleTimeout)
				}
				_ = resp.Body.Close()
			} else if resp != nil {
				e.handleControlRejection(ctx, resp.StatusCode)
				_ = resp.Body.Close()
			}
		}
		silence.Stop()
		cancel()

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 5*time.Second {
			backoff *= 2
		}
	}
}

func (e *Engine) requestImmediateHeartbeat() {
	select {
	case e.hbTriggerCh <- struct{}{}:
	default:
	}
}

func (e *Engine) sendHeartbeatOnce(ctx context.Context, serverURL, token string) {
	if !e.isRunning() {
		return
	}
	e.recomputeMeshRoutes()
	st := e.stateMgr.Get()
	hb := types.HeartbeatRequest{
		NodeKey:          st.NodeKey.Public(),
		TransportPorts:   e.collectLocalTransportPorts(),
		Endpoints:        e.collectLocalEndpoints(),
		Links:            e.collectDirectLinks(),
		AdvertisedRoutes: st.AdvertisedRoutes,
		CanRelay:         e.effectiveCanRelay(),
		OwnerNetworkID:   e.ownerNetworkID,
	}
	raw, _ := json.Marshal(hb)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/v1/node/heartbeat", bytes.NewReader(raw))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	if resp, err := e.httpClient.Do(req); err == nil {
		e.handleControlRejection(ctx, resp.StatusCode)
		_ = resp.Body.Close()
	}
}

func (e *Engine) maintenanceLoop(ctx context.Context, serverURL, token string) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	e.sendSTUNProbes()
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.hbTriggerCh:
			select {
			case <-ctx.Done():
				return
			case <-time.After(45 * time.Millisecond):
			}
			select {
			case <-e.hbTriggerCh:
			default:
			}
			e.sendHeartbeatOnce(ctx, serverURL, token)

		case <-ticker.C:
			e.sendSTUNProbes()
			if e.enablePortMap {
				e.refreshPortMappings(ctx)
			}
			e.mu.RLock()
			peers := make([]types.PublicKey, 0, len(e.peersByKey))
			for k, pr := range e.peersByKey {
				pr.mu.RLock()
				online := pr.meta.Online
				pr.mu.RUnlock()
				if online {
					peers = append(peers, k)
				}
			}
			e.mu.RUnlock()
			for _, pk := range peers {
				e.probePeerCandidates(pk, e.selector.AllCandidates(pk))
			}
			e.sendHeartbeatOnce(ctx, serverURL, token)
		}
	}
}

package nat

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/acktier/acktier/pkg/types"
)

const (
	lanBeaconPort     = 41921
	lanPeerMinGap     = 5 * time.Second
	maxTrackedLANPeer = 256
)

type lanBeacon struct {
	Magic   string                          `json:"m"`
	NodeKey types.PublicKey                 `json:"k"`
	Ports   map[types.TransportProto]string `json:"p"`
}

// LANDiscovery broadcasts and listens for local L2 subnet peer beacons so devices
// on the same Wi-Fi/Ethernet switch discover candidate LAN endpoints (which must still pass
// cryptographic HMAC Ping/Pong verification before carrying traffic).
type LANDiscovery struct {
	localKey types.PublicKey
	getPorts func() map[types.TransportProto]string
	onPeer   func(peerKey types.PublicKey, endpoints []types.Endpoint)

	mu       sync.Mutex
	lastSeen map[types.PublicKey]time.Time
}

func NewLANDiscovery(localKey types.PublicKey, getPorts func() map[types.TransportProto]string, onPeer func(types.PublicKey, []types.Endpoint)) *LANDiscovery {
	return &LANDiscovery{
		localKey: localKey,
		getPorts: getPorts,
		onPeer:   onPeer,
		lastSeen: make(map[types.PublicKey]time.Time),
	}
}

func (ld *LANDiscovery) Run(ctx context.Context) {
	conn, err := net.ListenPacket("udp4", ":41921")
	if err != nil {
		conn, err = net.ListenPacket("udp4", ":0")
		if err != nil {
			return
		}
	}
	defer conn.Close()

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	go ld.readLoop(conn)

	ld.broadcastOnce(conn)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ld.broadcastOnce(conn)
		}
	}
}

func (ld *LANDiscovery) broadcastOnce(conn net.PacketConn) {
	ports := ld.getPorts()
	if len(ports) == 0 {
		return
	}
	raw, err := json.Marshal(lanBeacon{
		Magic:   "acktier-lan-v1",
		NodeKey: ld.localKey,
		Ports:   ports,
	})
	if err != nil {
		return
	}
	bcastAddr := &net.UDPAddr{IP: net.IPv4bcast, Port: lanBeaconPort}
	_, _ = conn.WriteTo(raw, bcastAddr)
}

func (ld *LANDiscovery) allowPeerBeacon(peer types.PublicKey) bool {
	now := time.Now()
	ld.mu.Lock()
	defer ld.mu.Unlock()
	if last, ok := ld.lastSeen[peer]; ok && now.Sub(last) < lanPeerMinGap {
		return false
	}
	if len(ld.lastSeen) >= maxTrackedLANPeer {
		for k, ts := range ld.lastSeen {
			if now.Sub(ts) > time.Minute {
				delete(ld.lastSeen, k)
			}
		}
	}
	if len(ld.lastSeen) >= maxTrackedLANPeer {
		return false
	}
	ld.lastSeen[peer] = now
	return true
}

func (ld *LANDiscovery) readLoop(conn net.PacketConn) {
	buf := make([]byte, 1024)
	for {
		n, raddr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		if n > 512 {
			continue
		}
		var b lanBeacon
		if json.Unmarshal(buf[:n], &b) != nil || b.Magic != "acktier-lan-v1" || b.NodeKey == ld.localKey || b.NodeKey.IsZero() {
			continue
		}
		host, _, err := net.SplitHostPort(raddr.String())
		if err != nil || host == "" {
			continue
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Unmap().IsPrivate() || types.IsOverlayAddr(ip) {
			continue
		}
		if !ld.allowPeerBeacon(b.NodeKey) {
			continue
		}
		var eps []types.Endpoint
		for _, proto := range []types.TransportProto{types.ProtoUDP, types.ProtoQUIC, types.ProtoTCP, types.ProtoWSS} {
			portStr := b.Ports[proto]
			port, pErr := strconv.Atoi(portStr)
			if pErr == nil && port > 0 && port <= 65535 {
				eps = append(eps, types.Endpoint{
					Proto: proto,
					Addr:  net.JoinHostPort(ip.Unmap().String(), strconv.Itoa(port)),
					IsLAN: true,
				})
			}
		}
		if len(eps) > 0 && ld.onPeer != nil {
			ld.onPeer(b.NodeKey, eps)
		}
	}
}

package nat

import (
	"context"
	"encoding/json"
	"net"
	"time"

	"github.com/acktier/acktier/pkg/types"
)

const lanBeaconPort = 41921

type lanBeacon struct {
	Magic   string                         `json:"m"`
	NodeKey types.PublicKey                `json:"k"`
	Ports   map[types.TransportProto]string `json:"p"`
}

// LANDiscovery broadcasts and listens for local L2 subnet peer beacons so devices
// on the same Wi-Fi/Ethernet switch establish sub-millisecond direct paths immediately.
type LANDiscovery struct {
	localKey types.PublicKey
	getPorts func() map[types.TransportProto]string
	onPeer   func(peerKey types.PublicKey, endpoints []types.Endpoint)
}

func NewLANDiscovery(localKey types.PublicKey, getPorts func() map[types.TransportProto]string, onPeer func(types.PublicKey, []types.Endpoint)) *LANDiscovery {
	return &LANDiscovery{
		localKey: localKey,
		getPorts: getPorts,
		onPeer:   onPeer,
	}
}

func (ld *LANDiscovery) Run(ctx context.Context) {
	conn, err := net.ListenPacket("udp4", ":41921")
	if err != nil {
		// Port already bound by another local instance; bind ephemeral port for broadcast tx only
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

func (ld *LANDiscovery) readLoop(conn net.PacketConn) {
	buf := make([]byte, 2048)
	for {
		n, raddr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		var b lanBeacon
		if json.Unmarshal(buf[:n], &b) != nil || b.Magic != "acktier-lan-v1" || b.NodeKey == ld.localKey || b.NodeKey.IsZero() {
			continue
		}
		host, _, err := net.SplitHostPort(raddr.String())
		if err != nil || host == "" {
			continue
		}
		var eps []types.Endpoint
		for proto, port := range b.Ports {
			if port != "" && port != "0" {
				eps = append(eps, types.Endpoint{
					Proto: proto,
					Addr:  net.JoinHostPort(host, port),
					IsLAN: true,
				})
			}
		}
		if len(eps) > 0 && ld.onPeer != nil {
			ld.onPeer(b.NodeKey, eps)
		}
	}
}

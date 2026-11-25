package engine

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/acktier/acktier/pkg/protocol"
	"github.com/acktier/acktier/pkg/types"
)

// DialFunc dials a stream connection (allows injecting in-memory pipes in tests).
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// RelayClient maintains a persistent upgraded TCP stream to an acktier-server `/relay` endpoint
// and continuously measures server relay RTT for global path cost comparison.
type RelayClient struct {
	dial      DialFunc
	nodeKey   types.PublicKey
	nodeToken string
	onRecv    func(src types.PublicKey, inner []byte)

	mu        sync.RWMutex
	writeMu   sync.Mutex
	relayAddr string
	conn      net.Conn
	connected atomic.Bool
	rttMicros atomic.Int64
	probeSeq  atomic.Uint64
}

func NewRelayClient(dial DialFunc, nodeKey types.PublicKey, onRecv func(src types.PublicKey, inner []byte)) *RelayClient {
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}
	return &RelayClient{
		dial:    dial,
		nodeKey: nodeKey,
		onRecv:  onRecv,
	}
}

func (rc *RelayClient) Connected() bool {
	return rc.connected.Load()
}

// RTTMillis returns the smoothed EWMA round-trip latency (in ms) between this node and the Center Relay server.
func (rc *RelayClient) RTTMillis() float64 {
	us := rc.rttMicros.Load()
	if us <= 0 {
		return 0
	}
	return float64(us) / 1000.0
}

func (rc *RelayClient) Run(ctx context.Context, relayAddr, nodeToken string) {
	rc.mu.Lock()
	rc.relayAddr = relayAddr
	rc.nodeToken = nodeToken
	rc.mu.Unlock()

	backoff := 200 * time.Millisecond
	for {
		select {
		case <-ctx.Done():
			rc.closeCurrent()
			return
		default:
		}

		err := rc.connectAndServe(ctx, relayAddr, nodeToken)
		rc.connected.Store(false)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 5*time.Second {
				backoff *= 2
			}
		} else {
			backoff = 200 * time.Millisecond
		}
	}
}

func (rc *RelayClient) connectAndServe(ctx context.Context, addr, token string) error {
	dialCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	conn, err := rc.dial(dialCtx, "tcp", addr)
	cancel()
	if err != nil {
		return err
	}
	defer func() {
		rc.connected.Store(false)
		_ = conn.Close()
	}()

	reqStr := fmt.Sprintf("GET /relay HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: acktier-relay\r\n\r\n", addr)
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write([]byte(reqStr)); err != nil {
		return err
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.Contains(statusLine, "101") {
		return fmt.Errorf("relay upgrade rejected: %s", strings.TrimSpace(statusLine))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	if err := protocol.WriteFrame(conn, protocol.EncodeRelayBind(rc.nodeKey, token)); err != nil {
		return err
	}
	ackFrame, err := protocol.ReadFrame(br)
	if err != nil {
		return err
	}
	ok, msg, err := protocol.DecodeRelayBindAck(ackFrame)
	if err != nil || !ok {
		return fmt.Errorf("relay bind failed: %s (%v)", msg, err)
	}
	_ = conn.SetDeadline(time.Time{})

	rc.mu.Lock()
	rc.conn = conn
	rc.mu.Unlock()
	rc.connected.Store(true)

	// Measure initial Relay Server RTT right away & keepalive every 15s
	rc.SendServerPing()

	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				_ = conn.Close()
				return
			case <-stopWatch:
				return
			case <-ticker.C:
				rc.SendServerPing()
			}
		}
	}()

	for {
		frame, err := protocol.ReadFrame(br)
		if err != nil {
			return err
		}
		pType, _, _, err := protocol.ParseHeader(frame)
		if err != nil {
			continue
		}
		switch pType {
		case protocol.PacketPong:
			_, sender, _, txNano, _, err := protocol.DecodeProbePacket(frame)
			if err == nil && sender == rc.nodeKey {
				sampleUs := time.Since(time.Unix(0, txNano)).Microseconds()
				if sampleUs < 50 {
					sampleUs = 50
				}
				prev := rc.rttMicros.Load()
				if prev <= 0 {
					rc.rttMicros.Store(sampleUs)
				} else {
					rc.rttMicros.Store((prev*3 + sampleUs) / 4)
				}
			}
		case protocol.PacketRelayForward:
			_, src, dst, inner, err := protocol.DecodeRelayForward(frame)
			if err == nil && dst == rc.nodeKey && rc.onRecv != nil {
				rc.onRecv(src, inner)
			}
		}
	}
}

// SendServerPing transmits a lightweight probe frame to measure RTT to the Center Relay server.
func (rc *RelayClient) SendServerPing() {
	rc.mu.RLock()
	conn := rc.conn
	rc.mu.RUnlock()
	if conn == nil || !rc.connected.Load() {
		return
	}
	ping := protocol.EncodeProbePacket(protocol.PacketPing, rc.nodeKey, rc.probeSeq.Add(1), time.Now().UnixNano(), "")
	rc.writeMu.Lock()
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_ = protocol.WriteFrame(conn, ping)
	rc.writeMu.Unlock()
}

func (rc *RelayClient) Send(dst types.PublicKey, inner []byte) error {
	rc.mu.RLock()
	conn := rc.conn
	rc.mu.RUnlock()
	if conn == nil || !rc.connected.Load() {
		return errors.New("relay not connected")
	}
	frame := protocol.EncodeRelayForward(protocol.DefaultHopTTL, rc.nodeKey, dst, inner)
	rc.writeMu.Lock()
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	err := protocol.WriteFrame(conn, frame)
	rc.writeMu.Unlock()
	return err
}

func (rc *RelayClient) closeCurrent() {
	rc.mu.Lock()
	if rc.conn != nil {
		_ = rc.conn.Close()
		rc.conn = nil
	}
	rc.mu.Unlock()
	rc.connected.Store(false)
}

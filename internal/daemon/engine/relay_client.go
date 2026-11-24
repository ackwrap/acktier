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

// RelayClient maintains a persistent upgraded TCP stream to an acktier-server `/relay` endpoint.
type RelayClient struct {
	dial      DialFunc
	nodeKey   types.PublicKey
	nodeToken string
	onRecv    func(src types.PublicKey, inner []byte)

	mu        sync.RWMutex
	relayAddr string
	conn      net.Conn
	connected atomic.Bool
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

	// Perform HTTP/1.1 Upgrade to /relay
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
	// Consume remaining HTTP response headers until blank line
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	// Send RelayBind frame
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

	// Watch context cancellation to unblock ReadFrame immediately
	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stopWatch:
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
		if pType == protocol.PacketRelayForward {
			_, src, dst, inner, err := protocol.DecodeRelayForward(frame)
			if err == nil && dst == rc.nodeKey && rc.onRecv != nil {
				rc.onRecv(src, inner)
			}
		}
	}
}

func (rc *RelayClient) Send(dst types.PublicKey, inner []byte) error {
	rc.mu.RLock()
	conn := rc.conn
	rc.mu.RUnlock()
	if conn == nil || !rc.connected.Load() {
		return errors.New("relay not connected")
	}
	frame := protocol.EncodeRelayForward(protocol.DefaultHopTTL, rc.nodeKey, dst, inner)
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return protocol.WriteFrame(conn, frame)
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

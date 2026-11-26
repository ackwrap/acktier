package engine

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ackwrap/acktier/pkg/protocol"
	"github.com/ackwrap/acktier/pkg/types"
)

// DialFunc dials a stream connection (allows injecting in-memory pipes in tests).
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// RelayTLSConfig controls certificate-verified TLS wrapping on the Center Relay stream.
type RelayTLSConfig struct {
	UseTLS            bool
	ServerName        string
	RootCAs           *x509.CertPool
	EnforceNonLoopTLS bool // Reject plaintext TCP to non-loopback RelayAddr when UseTLS is false
}

// RelayClient maintains a persistent upgraded TLS/TCP stream to an acktier-server `/relay` endpoint
// and continuously measures server relay RTT for global path cost comparison.
type RelayClient struct {
	dial    DialFunc
	nodeKey types.PublicKey
	onRecv  func(src types.PublicKey, inner []byte)

	mu         sync.RWMutex
	writeMu    sync.Mutex
	run        context.Context
	conn       net.Conn
	connected  atomic.Bool
	rttMicros  atomic.Int64
	lastPingID atomic.Uint64
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

func isLoopbackHostPort(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func (rc *RelayClient) Run(ctx context.Context, relayAddr, nodeToken string, tlsOpts RelayTLSConfig) {
	rc.mu.Lock()
	if ctx.Err() != nil {
		rc.mu.Unlock()
		return
	}
	rc.run = ctx
	rc.mu.Unlock()

	backoff := 200 * time.Millisecond
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		err := rc.connectAndServe(ctx, relayAddr, nodeToken, tlsOpts)
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

func (rc *RelayClient) connectAndServe(ctx context.Context, addr, token string, tlsOpts RelayTLSConfig) error {
	if !tlsOpts.UseTLS && tlsOpts.EnforceNonLoopTLS && !isLoopbackHostPort(addr) {
		return fmt.Errorf("refusing to transmit relay token in cleartext to non-loopback %s; enable HTTPS/TLS on acktier-server", addr)
	}

	dialCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	rawConn, err := rc.dial(dialCtx, "tcp", addr)
	if err != nil {
		cancel()
		return err
	}
	stopClose := context.AfterFunc(ctx, func() { _ = rawConn.Close() })
	defer stopClose()

	conn := rawConn
	if tlsOpts.UseTLS {
		sni := strings.TrimSpace(tlsOpts.ServerName)
		if sni == "" {
			if h, _, sErr := net.SplitHostPort(addr); sErr == nil && h != "" {
				sni = h
			} else {
				sni = addr
			}
		}
		tCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: sni,
			RootCAs:    tlsOpts.RootCAs,
		}
		tlsConn := tls.Client(rawConn, tCfg)
		if err := tlsConn.HandshakeContext(dialCtx); err != nil {
			cancel()
			_ = rawConn.Close()
			return fmt.Errorf("relay TLS certificate verification failed: %w", err)
		}
		conn = tlsConn
	}
	cancel()

	defer func() {
		rc.mu.Lock()
		if rc.conn == conn {
			rc.conn = nil
			rc.connected.Store(false)
		}
		rc.mu.Unlock()
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
	if rc.run != ctx || ctx.Err() != nil {
		rc.mu.Unlock()
		return context.Canceled
	}
	rc.conn = conn
	rc.connected.Store(true)
	rc.mu.Unlock()

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
		if err := ctx.Err(); err != nil {
			return err
		}
		pType, _, _, err := protocol.ParseHeader(frame)
		if err != nil {
			continue
		}
		switch pType {
		case protocol.PacketPong:
			_, sender, probeID, txNano, _, err := protocol.DecodeProbePacket(frame)
			if err == nil && sender == rc.nodeKey && probeID != 0 && rc.lastPingID.CompareAndSwap(probeID, 0) {
				sampleUs := time.Since(time.Unix(0, txNano)).Microseconds()
				if sampleUs >= 0 && sampleUs < 10_000_000 {
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
			}
		case protocol.PacketRelayForward:
			_, src, dst, inner, err := protocol.DecodeRelayForward(frame)
			if err == nil && dst == rc.nodeKey && rc.onRecv != nil {
				rc.onRecv(src, inner)
			}
		}
	}
}

// SendServerPing transmits a CSPRNG-tagged probe frame to measure RTT to the Center Relay server.
func (rc *RelayClient) SendServerPing() {
	rc.mu.RLock()
	conn := rc.conn
	rc.mu.RUnlock()
	if conn == nil || !rc.connected.Load() {
		return
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	pid := binary.LittleEndian.Uint64(b[:])
	if pid == 0 {
		pid = 1
	}
	rc.lastPingID.Store(pid)
	ping := protocol.EncodeProbePacket(protocol.PacketPing, rc.nodeKey, pid, time.Now().UnixNano(), "")
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

func (rc *RelayClient) CloseCurrent() {
	rc.mu.Lock()
	conn := rc.conn
	rc.conn = nil
	rc.run = nil
	rc.connected.Store(false)
	rc.rttMicros.Store(0)
	rc.lastPingID.Store(0)
	rc.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

package relay

import (
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/acktier/acktier/pkg/protocol"
	"github.com/acktier/acktier/pkg/types"
)

const relayIdleReadTimeout = 90 * time.Second

// AuthFunc validates whether a nodeKey and nodeToken may bind to the relay.
type AuthFunc func(nodeKey types.PublicKey, nodeToken string) bool

type clientSession struct {
	nodeKey   types.PublicKey
	conn      net.Conn
	sendCh    chan []byte
	done      chan struct{}
	closeOnce sync.Once
}

func (cs *clientSession) close() {
	cs.closeOnce.Do(func() {
		close(cs.done)
		_ = cs.conn.Close()
	})
}

// enqueue safely delivers frame without ever closing sendCh, eliminating send-on-closed-channel races.
func (cs *clientSession) enqueue(frame []byte) bool {
	select {
	case <-cs.done:
		return false
	default:
	}
	select {
	case <-cs.done:
		return false
	case cs.sendCh <- frame:
		return true
	default:
		// Drop under congestion rather than blocking sender
		return false
	}
}

// Server provides encrypted frame relaying (DERP-like fallback) and UDP STUN endpoint reflection.
type Server struct {
	auth            AuthFunc
	mu              sync.RWMutex
	sessions        map[types.PublicKey]*clientSession
	forwardedFrames atomic.Uint64
	forwardedBytes  atomic.Uint64
}

func NewServer(auth AuthFunc) *Server {
	return &Server{
		auth:     auth,
		sessions: make(map[types.PublicKey]*clientSession),
	}
}

func (s *Server) Stats() (connectedClients int, frames uint64, bytes uint64) {
	s.mu.RLock()
	connectedClients = len(s.sessions)
	s.mu.RUnlock()
	return connectedClients, s.forwardedFrames.Load(), s.forwardedBytes.Load()
}

// Disconnect immediately terminates any active Center Relay session for nodeKey (e.g. on node deletion or rekey).
func (s *Server) Disconnect(nodeKey types.PublicKey) {
	s.mu.Lock()
	sess, ok := s.sessions[nodeKey]
	if ok {
		delete(s.sessions, nodeKey)
	}
	s.mu.Unlock()
	if ok && sess != nil {
		sess.close()
	}
}

// ServeConn handles an upgraded TLS/TCP stream from an acktierd client.
func (s *Server) ServeConn(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	bindPkt, err := protocol.ReadFrame(conn)
	if err != nil {
		_ = conn.Close()
		return
	}
	nodeKey, token, err := protocol.DecodeRelayBind(bindPkt)
	if err != nil || nodeKey.IsZero() {
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_ = protocol.WriteFrame(conn, protocol.EncodeRelayBindAck(false, "unauthorized"))
		_ = conn.Close()
		return
	}
	sess := &clientSession{
		nodeKey: nodeKey,
		conn:    conn,
		sendCh:  make(chan []byte, 256),
		done:    make(chan struct{}),
	}

	s.mu.Lock()
	// A bind and Disconnect must agree on ordering. Revocation updates the
	// store before disconnecting, so no already-revoked bind can attach later.
	if s.auth != nil && !s.auth(nodeKey, token) {
		s.mu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_ = protocol.WriteFrame(conn, protocol.EncodeRelayBindAck(false, "unauthorized"))
		_ = conn.Close()
		return
	}
	old := s.sessions[nodeKey]
	s.sessions[nodeKey] = sess
	s.mu.Unlock()
	if old != nil {
		old.close()
	}

	defer func() {
		s.mu.Lock()
		if cur, ok := s.sessions[nodeKey]; ok && cur == sess {
			delete(s.sessions, nodeKey)
		}
		s.mu.Unlock()
		sess.close()
	}()
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := protocol.WriteFrame(conn, protocol.EncodeRelayBindAck(true, "ok")); err != nil {
		return
	}
	_ = conn.SetWriteDeadline(time.Time{})

	// Writer goroutine exits cleanly via sess.done without closing sendCh.
	go func() {
		for {
			select {
			case <-sess.done:
				return
			case frame := <-sess.sendCh:
				_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := protocol.WriteFrame(conn, frame); err != nil {
					sess.close()
					return
				}
			}
		}
	}()

	// Reader loop with rolling idle deadline to prevent half-open socket exhaustion.
	for {
		_ = conn.SetReadDeadline(time.Now().Add(relayIdleReadTimeout))
		frame, err := protocol.ReadFrame(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				select {
				case <-sess.done:
				default:
					log.Printf("[relay] read from %s closed: %v", nodeKey.ShortString(), err)
				}
			}
			return
		}
		pType, _, _, err := protocol.ParseHeader(frame)
		if err != nil {
			continue
		}
		switch pType {
		case protocol.PacketPing:
			_, sender, probeID, txNano, _, err := protocol.DecodeProbePacket(frame)
			if err == nil && sender == nodeKey {
				pong := protocol.EncodeProbePacket(protocol.PacketPong, nodeKey, probeID, txNano, conn.RemoteAddr().String())
				sess.enqueue(pong)
			}
		case protocol.PacketRelayForward:
			ttl, src, dst, inner, err := protocol.DecodeRelayForward(frame)
			if err != nil || ttl == 0 || src != nodeKey {
				continue
			}
			s.mu.RLock()
			target := s.sessions[dst]
			s.mu.RUnlock()
			if target == nil {
				continue
			}
			outFrame := protocol.EncodeRelayForward(ttl-1, src, dst, inner)
			if target.enqueue(outFrame) {
				s.forwardedFrames.Add(1)
				s.forwardedBytes.Add(uint64(len(outFrame)))
			}
		}
	}
}

// ServeSTUNLoop processes UDP STUN-like Probe packets and reflects the caller's public IP:Port.
func ServeSTUNLoop(conn net.PacketConn) {
	buf := make([]byte, 2048)
	for {
		n, raddr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		if n > 160 {
			continue // Reject oversized amplification attempts
		}
		pType, sender, probeID, txNano, obsIn, err := protocol.DecodeProbePacket(buf[:n])
		if err != nil || pType != protocol.PacketPing || obsIn != "" || sender.IsZero() {
			continue
		}
		pong := protocol.EncodeProbePacket(protocol.PacketPong, sender, probeID, txNano, raddr.String())
		_, _ = conn.WriteTo(pong, raddr)
	}
}

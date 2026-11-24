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

// AuthFunc validates whether a nodeKey and nodeToken may bind to the relay.
type AuthFunc func(nodeKey types.PublicKey, nodeToken string) bool

type clientSession struct {
	nodeKey types.PublicKey
	conn    net.Conn
	sendCh  chan []byte
	closeOnce sync.Once
}

func (cs *clientSession) close() {
	cs.closeOnce.Do(func() {
		close(cs.sendCh)
		_ = cs.conn.Close()
	})
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

// ServeConn handles an upgraded or raw TCP stream from an acktierd client.
func (s *Server) ServeConn(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	bindPkt, err := protocol.ReadFrame(conn)
	if err != nil {
		_ = conn.Close()
		return
	}
	nodeKey, token, err := protocol.DecodeRelayBind(bindPkt)
	if err != nil || (s.auth != nil && !s.auth(nodeKey, token)) {
		_ = protocol.WriteFrame(conn, protocol.EncodeRelayBindAck(false, "unauthorized"))
		_ = conn.Close()
		return
	}
	if err := protocol.WriteFrame(conn, protocol.EncodeRelayBindAck(true, "ok")); err != nil {
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	sess := &clientSession{
		nodeKey: nodeKey,
		conn:    conn,
		sendCh:  make(chan []byte, 256),
	}

	s.mu.Lock()
	if old, exists := s.sessions[nodeKey]; exists {
		old.close()
	}
	s.sessions[nodeKey] = sess
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		if cur, ok := s.sessions[nodeKey]; ok && cur == sess {
			delete(s.sessions, nodeKey)
		}
		s.mu.Unlock()
		sess.close()
	}()

	// Writer goroutine
	go func() {
		for frame := range sess.sendCh {
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := protocol.WriteFrame(conn, frame); err != nil {
				_ = conn.Close()
				return
			}
		}
	}()

	// Reader loop
	for {
		frame, err := protocol.ReadFrame(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Printf("[relay] read from %s closed: %v", nodeKey.ShortString(), err)
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
				select {
				case sess.sendCh <- pong:
				default:
				}
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
			select {
			case target.sendCh <- outFrame:
				s.forwardedFrames.Add(1)
				s.forwardedBytes.Add(uint64(len(outFrame)))
			default:
				// Drop under congestion rather than blocking sender
			}
		}
	}
}

// ServeSTUNPacket processes UDP STUN-like Probe packets and reflects the caller's public IP:Port.
func ServeSTUNLoop(conn net.PacketConn) {
	buf := make([]byte, 2048)
	for {
		n, raddr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		pType, sender, probeID, txNano, _, err := protocol.DecodeProbePacket(buf[:n])
		if err != nil || pType != protocol.PacketPing {
			continue
		}
		pong := protocol.EncodeProbePacket(protocol.PacketPong, sender, probeID, txNano, raddr.String())
		_, _ = conn.WriteTo(pong, raddr)
	}
}

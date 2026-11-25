package transport

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/acktier/acktier/pkg/protocol"
	"github.com/acktier/acktier/pkg/types"
)

const quicDatagramMaxPayload = 1100

type quicPeerConn struct {
	addr     string
	conn     *quic.Conn
	streamMu sync.Mutex
	txStream *quic.SendStream
}

func (qc *quicPeerConn) send(ctx context.Context, pkt []byte) error {
	// Fast path: small packets (probes, handshakes, ACKs) ride RFC 9221 unreliable datagrams (zero HOL blocking)
	if len(pkt) <= quicDatagramMaxPayload {
		if err := qc.conn.SendDatagram(pkt); err == nil {
			return nil
		}
	}

	// Large MTU packets fallback to a pooled unidirectional stream with length-prefix framing
	qc.streamMu.Lock()
	defer qc.streamMu.Unlock()
	if qc.txStream == nil {
		openCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		st, err := qc.conn.OpenUniStreamSync(openCtx)
		cancel()
		if err != nil {
			return err
		}
		qc.txStream = st
	}
	_ = qc.txStream.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := protocol.WriteFrame(qc.txStream, pkt); err != nil {
		_ = qc.txStream.Close()
		qc.txStream = nil
		return err
	}
	return nil
}

// QUICDriver multiplexes wire frames over QUIC v1 (RFC 9000 + RFC 9221 Datagrams + UniStream MTU fallback).
type QUICDriver struct {
	tr        *quic.Transport
	ln        *quic.Listener
	serverTLS *tls.Config
	clientTLS *tls.Config
	quicCfg   *quic.Config
	onRecv    PacketHandler

	mu        sync.RWMutex
	conns     map[string]*quicPeerConn
	closeOnce sync.Once
	closed    chan struct{}
}

func NewQUICDriver(pconn net.PacketConn, onRecv PacketHandler) (*QUICDriver, error) {
	sTLS, err := GenerateEphemeralTLSConfig(alpnQUIC)
	if err != nil {
		return nil, err
	}
	cTLS, err := GenerateEphemeralTLSConfig(alpnQUIC)
	if err != nil {
		return nil, err
	}
	qCfg := &quic.Config{
		HandshakeIdleTimeout:    5 * time.Second,
		MaxIdleTimeout:          45 * time.Second,
		KeepAlivePeriod:         15 * time.Second,
		EnableDatagrams:         true,
		DisablePathMTUDiscovery: false,
	}

	tr := &quic.Transport{Conn: pconn}
	ln, err := tr.Listen(sTLS, qCfg)
	if err != nil {
		_ = tr.Close()
		return nil, err
	}

	qd := &QUICDriver{
		tr:        tr,
		ln:        ln,
		serverTLS: sTLS,
		clientTLS: cTLS,
		quicCfg:   qCfg,
		onRecv:    onRecv,
		conns:     make(map[string]*quicPeerConn),
		closed:    make(chan struct{}),
	}
	go qd.acceptLoop()
	return qd, nil
}

func (d *QUICDriver) Proto() types.TransportProto { return types.ProtoQUIC }

func (d *QUICDriver) LocalAddr() string {
	if d.tr == nil || d.tr.Conn == nil || d.tr.Conn.LocalAddr() == nil {
		return ""
	}
	return d.tr.Conn.LocalAddr().String()
}

func (d *QUICDriver) Send(ctx context.Context, addr string, pkt []byte) error {
	d.mu.RLock()
	existing := d.conns[addr]
	d.mu.RUnlock()

	if existing != nil {
		if err := existing.send(ctx, pkt); err == nil {
			return nil
		}
		d.removeConn(addr, existing)
	}

	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	dialCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	conn, err := d.tr.Dial(dialCtx, uaddr, d.clientTLS, d.quicCfg)
	cancel()
	if err != nil {
		return err
	}

	qc := d.registerConn(addr, conn)
	if err := qc.send(ctx, pkt); err != nil {
		d.removeConn(addr, qc)
		return err
	}
	return nil
}

func (d *QUICDriver) acceptLoop() {
	for {
		conn, err := d.ln.Accept(context.Background())
		if err != nil {
			select {
			case <-d.closed:
				return
			default:
				return
			}
		}
		d.registerConn(conn.RemoteAddr().String(), conn)
	}
}

func (d *QUICDriver) registerConn(addr string, conn *quic.Conn) *quicPeerConn {
	qc := &quicPeerConn{addr: addr, conn: conn}
	d.mu.Lock()
	if old, ok := d.conns[addr]; ok {
		_ = old.conn.CloseWithError(0, "replaced")
	}
	d.conns[addr] = qc
	d.mu.Unlock()

	go d.readDatagramLoop(qc)
	go d.acceptUniStreamLoop(qc)
	return qc
}

func (d *QUICDriver) readDatagramLoop(qc *quicPeerConn) {
	defer d.removeConn(qc.addr, qc)
	for {
		dg, err := qc.conn.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		if d.onRecv != nil && len(dg) > 0 {
			d.onRecv(dg, types.Endpoint{
				Proto: types.ProtoQUIC,
				Addr:  qc.addr,
			})
		}
	}
}

func (d *QUICDriver) acceptUniStreamLoop(qc *quicPeerConn) {
	for {
		st, err := qc.conn.AcceptUniStream(context.Background())
		if err != nil {
			return
		}
		go func(rs *quic.ReceiveStream) {
			for {
				frame, err := protocol.ReadFrame(rs)
				if err != nil {
					return
				}
				if d.onRecv != nil {
					d.onRecv(frame, types.Endpoint{
						Proto: types.ProtoQUIC,
						Addr:  qc.addr,
					})
				}
			}
		}(st)
	}
}

func (d *QUICDriver) removeConn(addr string, qc *quicPeerConn) {
	_ = qc.conn.CloseWithError(0, "closed")
	d.mu.Lock()
	if cur, ok := d.conns[addr]; ok && cur == qc {
		delete(d.conns, addr)
	}
	d.mu.Unlock()
}

// ResetConnections terminates all active QUIC peer sessions while keeping the listener bound.
func (d *QUICDriver) ResetConnections() {
	d.mu.Lock()
	for k, qc := range d.conns {
		_ = qc.conn.CloseWithError(0, "reset")
		delete(d.conns, k)
	}
	d.mu.Unlock()
}

func (d *QUICDriver) Close() error {
	d.closeOnce.Do(func() {
		close(d.closed)
		if d.ln != nil {
			_ = d.ln.Close()
		}
		d.mu.Lock()
		for k, qc := range d.conns {
			_ = qc.conn.CloseWithError(0, "shutdown")
			delete(d.conns, k)
		}
		d.mu.Unlock()
		if d.tr != nil {
			if d.tr.Conn != nil {
				_ = d.tr.Conn.Close()
			}
			_ = d.tr.Close()
		}
	})
	return nil
}

package transport

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/acktier/acktier/pkg/protocol"
	"github.com/acktier/acktier/pkg/types"
)

// StreamDialFunc dials a stream connection (TCP or in-memory test pipe).
type StreamDialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

type tcpPeerConn struct {
	addr    string
	conn    net.Conn
	writeMu sync.Mutex
}

func (tc *tcpPeerConn) send(pkt []byte) error {
	tc.writeMu.Lock()
	defer tc.writeMu.Unlock()
	_ = tc.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return protocol.WriteFrame(tc.conn, pkt)
}

// TCPDriver multiplexes length-prefixed wire frames over pooled full-duplex TCP connections.
type TCPDriver struct {
	ln     net.Listener
	dial   StreamDialFunc
	onRecv PacketHandler

	mu        sync.RWMutex
	conns     map[string]*tcpPeerConn
	closeOnce sync.Once
	closed    chan struct{}
}

func NewTCPDriver(ln net.Listener, dial StreamDialFunc, onRecv PacketHandler) *TCPDriver {
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}
	td := &TCPDriver{
		ln:     ln,
		dial:   dial,
		onRecv: onRecv,
		conns:  make(map[string]*tcpPeerConn),
		closed: make(chan struct{}),
	}
	if ln != nil {
		go td.acceptLoop()
	}
	return td
}

func (d *TCPDriver) Proto() types.TransportProto { return types.ProtoTCP }

func (d *TCPDriver) LocalAddr() string {
	if d.ln == nil || d.ln.Addr() == nil {
		return ""
	}
	return d.ln.Addr().String()
}

func (d *TCPDriver) Send(ctx context.Context, addr string, pkt []byte) error {
	d.mu.RLock()
	existing := d.conns[addr]
	d.mu.RUnlock()

	if existing != nil {
		if err := existing.send(pkt); err == nil {
			return nil
		}
		d.removeConn(addr, existing)
	}

	dialCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	conn, err := d.dial(dialCtx, "tcp", addr)
	cancel()
	if err != nil {
		return err
	}

	tc := d.registerConn(addr, conn)
	if err := tc.send(pkt); err != nil {
		d.removeConn(addr, tc)
		return err
	}
	return nil
}

func (d *TCPDriver) acceptLoop() {
	for {
		conn, err := d.ln.Accept()
		if err != nil {
			select {
			case <-d.closed:
				return
			default:
				continue
			}
		}
		d.registerConn(conn.RemoteAddr().String(), conn)
	}
}

func (d *TCPDriver) registerConn(addr string, conn net.Conn) *tcpPeerConn {
	tc := &tcpPeerConn{addr: addr, conn: conn}
	d.mu.Lock()
	if old, ok := d.conns[addr]; ok {
		_ = old.conn.Close()
	}
	d.conns[addr] = tc
	d.mu.Unlock()

	go d.readConnLoop(tc)
	return tc
}

func (d *TCPDriver) readConnLoop(tc *tcpPeerConn) {
	defer d.removeConn(tc.addr, tc)
	for {
		frame, err := protocol.ReadFrame(tc.conn)
		if err != nil {
			return
		}
		if d.onRecv != nil {
			d.onRecv(frame, types.Endpoint{
				Proto: types.ProtoTCP,
				Addr:  tc.addr,
			})
		}
	}
}

func (d *TCPDriver) removeConn(addr string, tc *tcpPeerConn) {
	_ = tc.conn.Close()
	d.mu.Lock()
	if cur, ok := d.conns[addr]; ok && cur == tc {
		delete(d.conns, addr)
	}
	d.mu.Unlock()
}

func (d *TCPDriver) Close() error {
	d.closeOnce.Do(func() {
		close(d.closed)
		if d.ln != nil {
			_ = d.ln.Close()
		}
		d.mu.Lock()
		for k, tc := range d.conns {
			_ = tc.conn.Close()
			delete(d.conns, k)
		}
		d.mu.Unlock()
	})
	return nil
}

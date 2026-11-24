package transport_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acktier/acktier/internal/daemon/transport"
	"github.com/acktier/acktier/pkg/protocol"
	"github.com/acktier/acktier/pkg/types"
)

// --- In-memory Stream Switch (for TCP and TLS/WSS without OS sockets) ---

type memAddr string

func (a memAddr) Network() string { return "tcp" }
func (a memAddr) String() string  { return string(a) }

type pipeConn struct {
	net.Conn
	local  net.Addr
	remote net.Addr
}

func (p *pipeConn) LocalAddr() net.Addr  { return p.local }
func (p *pipeConn) RemoteAddr() net.Addr { return p.remote }

type memListener struct {
	addr   memAddr
	accept chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func (l *memListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	case c := <-l.accept:
		return c, nil
	}
}

func (l *memListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *memListener) Addr() net.Addr { return l.addr }

type memStreamSwitch struct {
	mu        sync.RWMutex
	listeners map[string]*memListener
	ephemPort atomic.Uint32
}

func newMemStreamSwitch() *memStreamSwitch {
	sw := &memStreamSwitch{listeners: make(map[string]*memListener)}
	sw.ephemPort.Store(50000)
	return sw
}

func (sw *memStreamSwitch) Listen(addr string) net.Listener {
	ln := &memListener{
		addr:   memAddr(addr),
		accept: make(chan net.Conn, 64),
		closed: make(chan struct{}),
	}
	sw.mu.Lock()
	sw.listeners[addr] = ln
	sw.mu.Unlock()
	return ln
}

func (sw *memStreamSwitch) DialFrom(clientIP string) transport.StreamDialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		sw.mu.RLock()
		ln := sw.listeners[addr]
		sw.mu.RUnlock()
		if ln == nil {
			return nil, errors.New("connection refused")
		}
		p := sw.ephemPort.Add(1)
		cAddr := memAddr(fmt.Sprintf("%s:%d", clientIP, p))
		sAddr := memAddr(addr)
		cRaw, sRaw := net.Pipe()
		cConn := &pipeConn{Conn: cRaw, local: cAddr, remote: sAddr}
		sConn := &pipeConn{Conn: sRaw, local: sAddr, remote: cAddr}
		select {
		case <-ln.closed:
			_ = cRaw.Close()
			_ = sRaw.Close()
			return nil, net.ErrClosed
		case ln.accept <- sConn:
			return cConn, nil
		case <-ctx.Done():
			_ = cRaw.Close()
			_ = sRaw.Close()
			return nil, ctx.Err()
		}
	}
}

// --- In-memory Packet Switch (for UDP and QUIC v1) ---

type memPktSwitch struct {
	mu    sync.RWMutex
	conns map[string]*memPktConn
}

func newMemPktSwitch() *memPktSwitch {
	return &memPktSwitch{conns: make(map[string]*memPktConn)}
}

type memPkt struct {
	from *net.UDPAddr
	data []byte
}

type memPktConn struct {
	sw     *memPktSwitch
	local  *net.UDPAddr
	rx     chan memPkt
	closed chan struct{}
	once   sync.Once
}

func (sw *memPktSwitch) Listen(addr string) *memPktConn {
	u, _ := net.ResolveUDPAddr("udp", addr)
	c := &memPktConn{
		sw:     sw,
		local:  u,
		rx:     make(chan memPkt, 512),
		closed: make(chan struct{}),
	}
	sw.mu.Lock()
	sw.conns[u.String()] = c
	sw.mu.Unlock()
	return c
}

func (c *memPktConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case m := <-c.rx:
		return copy(p, m.data), m.from, nil
	}
}

func (c *memPktConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	u, err := net.ResolveUDPAddr("udp", addr.String())
	if err != nil {
		return 0, err
	}
	c.sw.mu.RLock()
	dst := c.sw.conns[u.String()]
	c.sw.mu.RUnlock()
	if dst != nil {
		cp := make([]byte, len(p))
		copy(cp, p)
		select {
		case dst.rx <- memPkt{from: c.local, data: cp}:
		default:
		}
	}
	return len(p), nil
}

func (c *memPktConn) Close() error                       { c.once.Do(func() { close(c.closed) }); return nil }
func (c *memPktConn) LocalAddr() net.Addr                { return c.local }
func (c *memPktConn) SetDeadline(_ time.Time) error      { return nil }
func (c *memPktConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *memPktConn) SetWriteDeadline(_ time.Time) error { return nil }

func TestTCPWSSAndQUICDriversBidirectional(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	streamSw := newMemStreamSwitch()
	pktSw := newMemPktSwitch()

	// 1. Test TCPDriver bidirectional reuse
	tcpRxB := make(chan types.Endpoint, 1)
	tcpRxA := make(chan []byte, 1)
	tcpA := transport.NewTCPDriver(streamSw.Listen("10.0.0.1:9001"), streamSw.DialFrom("10.0.0.1"), func(pkt []byte, src types.Endpoint) {
		tcpRxA <- pkt
	})
	defer tcpA.Close()
	var tcpB *transport.TCPDriver
	tcpB = transport.NewTCPDriver(streamSw.Listen("10.0.0.2:9001"), streamSw.DialFrom("10.0.0.2"), func(pkt []byte, src types.Endpoint) {
		tcpRxB <- src
		_ = tcpB.Send(ctx, src.Addr, []byte("tcp-pong"))
	})
	defer tcpB.Close()

	if err := tcpA.Send(ctx, "10.0.0.2:9001", []byte("tcp-ping")); err != nil {
		t.Fatalf("TCP Send A->B: %v", err)
	}
	select {
	case <-tcpRxB:
	case <-ctx.Done():
		t.Fatalf("TCP B did not receive packet")
	}
	select {
	case reply := <-tcpRxA:
		if string(reply) != "tcp-pong" {
			t.Fatalf("unexpected TCP reply: %q", reply)
		}
	case <-ctx.Done():
		t.Fatalf("TCP A did not receive reverse reply on pooled socket")
	}

	// 2. Test WSSDriver (TLS 1.3 + WebSocket binary frames)
	wssRxA := make(chan []byte, 1)
	wssA, err := transport.NewWSSDriver(streamSw.Listen("10.0.0.1:9443"), streamSw.DialFrom("10.0.0.1"), func(pkt []byte, src types.Endpoint) {
		wssRxA <- pkt
	})
	if err != nil {
		t.Fatalf("NewWSSDriver A: %v", err)
	}
	defer wssA.Close()

	var wssB *transport.WSSDriver
	wssB, err = transport.NewWSSDriver(streamSw.Listen("10.0.0.2:9443"), streamSw.DialFrom("10.0.0.2"), func(pkt []byte, src types.Endpoint) {
		_ = wssB.Send(ctx, src.Addr, append([]byte("wss-echo:"), pkt...))
	})
	if err != nil {
		t.Fatalf("NewWSSDriver B: %v", err)
	}
	defer wssB.Close()

	if err := wssA.Send(ctx, "10.0.0.2:9443", []byte("hello-wss")); err != nil {
		t.Fatalf("WSS Send A->B: %v", err)
	}
	select {
	case got := <-wssRxA:
		if string(got) != "wss-echo:hello-wss" {
			t.Fatalf("unexpected WSS reply: %q", got)
		}
	case <-ctx.Done():
		t.Fatalf("timeout waiting for WSS echo")
	}

	// 3. Test QUICDriver (both small Datagram <= 1100B AND large 1400B UniStream frame!)
	quicRxB := make(chan []byte, 4)
	quicA, err := transport.NewQUICDriver(pktSw.Listen("10.0.0.1:9500"), func(pkt []byte, src types.Endpoint) {})
	if err != nil {
		t.Fatalf("NewQUICDriver A: %v", err)
	}
	defer quicA.Close()

	quicB, err := transport.NewQUICDriver(pktSw.Listen("10.0.0.2:9500"), func(pkt []byte, src types.Endpoint) {
		quicRxB <- pkt
	})
	if err != nil {
		t.Fatalf("NewQUICDriver B: %v", err)
	}
	defer quicB.Close()

	smallPkt := protocol.EncodeDataPacket(types.PublicKey{1}, 1, []byte("small-quic-datagram"))
	largePayload := bytes.Repeat([]byte{0xAB}, 1350)
	largePkt := protocol.EncodeDataPacket(types.PublicKey{1}, 2, largePayload)

	if err := quicA.Send(ctx, "10.0.0.2:9500", smallPkt); err != nil {
		t.Fatalf("QUIC Send small: %v", err)
	}
	if err := quicA.Send(ctx, "10.0.0.2:9500", largePkt); err != nil {
		t.Fatalf("QUIC Send large MTU: %v", err)
	}

	gotSmall, gotLarge := false, false
	for i := 0; i < 2; i++ {
		select {
		case p := <-quicRxB:
			if bytes.Equal(p, smallPkt) {
				gotSmall = true
			} else if bytes.Equal(p, largePkt) {
				gotLarge = true
			}
		case <-ctx.Done():
			t.Fatalf("timeout waiting for QUIC packets (small=%v large=%v)", gotSmall, gotLarge)
		}
	}
	if !gotSmall || !gotLarge {
		t.Fatalf("expected both datagram and stream QUIC frames (small=%v large=%v)", gotSmall, gotLarge)
	}
}

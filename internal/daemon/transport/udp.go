package transport

import (
	"context"
	"net"

	"github.com/ackwrap/acktier/pkg/types"
)

// PacketHandler is invoked whenever a wire packet arrives over any transport protocol.
type PacketHandler func(pkt []byte, src types.Endpoint)

// Driver abstracts a concrete L4/L7 wire packet transport (UDP, TCP, QUIC, WSS).
type Driver interface {
	Proto() types.TransportProto
	LocalAddr() string
	Send(ctx context.Context, addr string, pkt []byte) error
	Close() error
}

// UDPDriver transports wire frames as raw connectionless UDP datagrams.
type UDPDriver struct {
	conn   net.PacketConn
	onRecv PacketHandler
	closed chan struct{}
}

func NewUDPDriver(conn net.PacketConn, onRecv PacketHandler) *UDPDriver {
	d := &UDPDriver{
		conn:   conn,
		onRecv: onRecv,
		closed: make(chan struct{}),
	}
	go d.readLoop()
	return d
}

func (d *UDPDriver) Proto() types.TransportProto { return types.ProtoUDP }

func (d *UDPDriver) LocalAddr() string {
	if d.conn == nil || d.conn.LocalAddr() == nil {
		return ""
	}
	return d.conn.LocalAddr().String()
}

func (d *UDPDriver) Send(_ context.Context, addr string, pkt []byte) error {
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	_, err = d.conn.WriteTo(pkt, uaddr)
	return err
}

func (d *UDPDriver) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, raddr, err := d.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		if d.onRecv == nil || n == 0 {
			continue
		}
		cp := make([]byte, n)
		copy(cp, buf[:n])
		d.onRecv(cp, types.Endpoint{
			Proto: types.ProtoUDP,
			Addr:  raddr.String(),
		})
	}
}

func (d *UDPDriver) Close() error {
	select {
	case <-d.closed:
		return nil
	default:
		close(d.closed)
		if d.conn != nil {
			return d.conn.Close()
		}
		return nil
	}
}

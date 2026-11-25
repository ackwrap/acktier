package acknet

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// ServeSOCKS5 accepts RFC 1928 SOCKS5 TCP CONNECT requests on ln and proxies them into the AckTier mesh
// (including remote MagicDNS resolution via SOCKS5 ATYP=0x03 domain names!).
func (s *Server) ServeSOCKS5(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleSOCKS5Conn(conn)
	}
}

// ListenSOCKS5 binds a local TCP port (e.g. "127.0.0.1:1080") and starts a background SOCKS5 proxy into AckTier.
func (s *Server) ListenSOCKS5(localBindAddr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", localBindAddr)
	if err != nil {
		return nil, err
	}
	go func() { _ = s.ServeSOCKS5(ln) }()
	return ln, nil
}

func (s *Server) handleSOCKS5Conn(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))

	// 1. Greeting: VER(1)=0x05, NMETHODS(1), METHODS(...)
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil || hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	// No-auth (0x00)
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 2. Request: VER(1)=0x05, CMD(1)=0x01(CONNECT), RSV(1), ATYP(1)
	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil || req[0] != 0x05 || req[1] != 0x01 {
		_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var host string
	switch req[3] {
	case 0x01: // IPv4
		var ip4 [4]byte
		if _, err := io.ReadFull(c, ip4[:]); err != nil {
			return
		}
		host = net.IP(ip4[:]).String()
	case 0x03: // Domain name (MagicDNS friendly!)
		var nLen [1]byte
		if _, err := io.ReadFull(c, nLen[:]); err != nil {
			return
		}
		dom := make([]byte, int(nLen[0]))
		if _, err := io.ReadFull(c, dom); err != nil {
			return
		}
		host = string(dom)
	case 0x04: // IPv6
		var ip6 [16]byte
		if _, err := io.ReadFull(c, ip6[:]); err != nil {
			return
		}
		host = net.IP(ip6[:]).String()
	default:
		return
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(c, portBuf[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf[:])
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	remote, err := s.Dial(ctx, "tcp", target)
	cancel()
	if err != nil {
		_, _ = c.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()

	// Success reply
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(remote, c)
		_ = remote.Close()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(c, remote)
		_ = c.Close()
		done <- struct{}{}
	}()
	<-done
	_ = fmt.Sprint()
}

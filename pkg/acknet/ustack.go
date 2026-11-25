package acknet

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/acktier/acktier/internal/daemon/pktutil"
	"github.com/acktier/acktier/internal/daemon/tun"
)

const (
	ustackMSS        = tun.DefaultMTU - 60 // IPv6 and TCP headers.
	maxInFlightBytes = 32 * 1024
	retransmitTick   = 120 * time.Millisecond
)

var (
	ErrAddrInUse   = errors.New("acknet: address already in use")
	ErrConnRefused = errors.New("acknet: connection refused")
	ErrStackClosed = errors.New("acknet: userspace stack closed")
)

type tcpKey struct {
	localPort  uint16
	remoteIP   netip.Addr
	remotePort uint16
}

// UserspaceStack implements client.PacketDevice entirely in memory, translating L3 IPv4/IPv6 packets
// into standard Go `net.Listener`, `net.Conn`, and `net.PacketConn` sockets with zero OS privileges.
type UserspaceStack struct {
	mtu        int
	txToEngine chan []byte

	mu       sync.RWMutex
	selfIPv4 netip.Addr
	selfIPv6 netip.Addr

	ephemNext atomic.Uint32

	tcpListeners map[uint16]*ustackTCPListener
	tcpConns     map[tcpKey]*ustackTCPConn
	udpSockets   map[uint16]*ustackUDPConn

	closeOnce sync.Once
	closedCh  chan struct{}
}

func newUserspaceStack(mtu int) *UserspaceStack {
	if mtu <= 0 {
		mtu = tun.DefaultMTU
	}
	s := &UserspaceStack{
		mtu:          mtu,
		txToEngine:   make(chan []byte, 1024),
		tcpListeners: make(map[uint16]*ustackTCPListener),
		tcpConns:     make(map[tcpKey]*ustackTCPConn),
		udpSockets:   make(map[uint16]*ustackUDPConn),
		closedCh:     make(chan struct{}),
	}
	s.ephemNext.Store(40000)
	go s.retransmitLoop()
	return s
}

func (s *UserspaceStack) Name() string { return "acknet-userspace0" }
func (s *UserspaceStack) MTU() int     { return s.mtu }

func (s *UserspaceStack) Configure(ipv4 netip.Prefix, ipv6 netip.Prefix, _ []netip.Prefix) error {
	s.mu.Lock()
	if ipv4.IsValid() {
		s.selfIPv4 = ipv4.Addr()
	}
	if ipv6.IsValid() {
		s.selfIPv6 = ipv6.Addr()
	}
	s.mu.Unlock()
	return nil
}

func (s *UserspaceStack) LocalIPs() (v4, v6 netip.Addr) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.selfIPv4, s.selfIPv6
}

func (s *UserspaceStack) localIPFor(dst netip.Addr) (netip.Addr, error) {
	s.mu.RLock()
	v4, v6 := s.selfIPv4, s.selfIPv6
	s.mu.RUnlock()
	if dst.Is6() {
		if !v6.IsValid() {
			return netip.Addr{}, errors.New("acknet: node has no IPv6 address yet")
		}
		return v6, nil
	}
	if !v4.IsValid() {
		return netip.Addr{}, errors.New("acknet: node has no IPv4 address yet")
	}
	return v4, nil
}

func (s *UserspaceStack) ReadPacket(buf []byte) (int, error) {
	select {
	case <-s.closedCh:
		return 0, io.EOF
	case pkt := <-s.txToEngine:
		if len(pkt) > len(buf) {
			return 0, errors.New("acknet: buffer too small")
		}
		return copy(buf, pkt), nil
	}
}

func (s *UserspaceStack) emitL3(pkt []byte) {
	select {
	case <-s.closedCh:
	case s.txToEngine <- pkt:
	default:
	}
}

func (s *UserspaceStack) WritePacket(raw []byte) error {
	pkt, err := pktutil.Parse(raw)
	if err != nil {
		return nil
	}
	switch pkt.Proto {
	case pktutil.ProtoICMPv4, pktutil.ProtoICMPv6:
		if reply, ok := pktutil.BuildICMPEchoReply(pkt); ok {
			s.emitL3(reply)
		}
	case pktutil.ProtoUDP:
		s.handleInboundUDP(pkt)
	case pktutil.ProtoTCP:
		s.handleInboundTCP(pkt)
	}
	return nil
}

func (s *UserspaceStack) allocEphemeralTCPPortLocked(dstIP netip.Addr, dstPort uint16) (uint16, error) {
	for i := 0; i < 20000; i++ {
		p := uint16(40000 + (s.ephemNext.Add(1) % 20000))
		if _, busyLn := s.tcpListeners[p]; busyLn {
			continue
		}
		if _, busyConn := s.tcpConns[tcpKey{localPort: p, remoteIP: dstIP, remotePort: dstPort}]; !busyConn {
			return p, nil
		}
	}
	return 0, errors.New("acknet: ephemeral TCP ports exhausted")
}

func (s *UserspaceStack) allocEphemeralUDPPortLocked() (uint16, error) {
	for i := 0; i < 20000; i++ {
		p := uint16(40000 + (s.ephemNext.Add(1) % 20000))
		if _, busy := s.udpSockets[p]; !busy {
			return p, nil
		}
	}
	return 0, errors.New("acknet: ephemeral UDP ports exhausted")
}

// --- Userspace UDP Implementation ---

type udpDgram struct {
	src  *net.UDPAddr
	data []byte
}

type ustackUDPConn struct {
	stack     *UserspaceStack
	port      uint16
	rxCh      chan udpDgram
	readDead  atomic.Int64
	closed    chan struct{}
	closeOnce sync.Once
}

func (s *UserspaceStack) ListenUDP(port uint16) (net.PacketConn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.closedCh:
		return nil, ErrStackClosed
	default:
	}
	if port == 0 {
		var err error
		port, err = s.allocEphemeralUDPPortLocked()
		if err != nil {
			return nil, err
		}
	} else if _, exists := s.udpSockets[port]; exists {
		return nil, ErrAddrInUse
	}
	uc := &ustackUDPConn{
		stack:  s,
		port:   port,
		rxCh:   make(chan udpDgram, 256),
		closed: make(chan struct{}),
	}
	s.udpSockets[port] = uc
	return uc, nil
}

func (s *UserspaceStack) handleInboundUDP(pkt pktutil.ParsedPacket) {
	s.mu.RLock()
	uc := s.udpSockets[pkt.DstPort]
	s.mu.RUnlock()
	if uc == nil {
		return
	}
	cp := make([]byte, len(pkt.Payload))
	copy(cp, pkt.Payload)
	srcAddr := &net.UDPAddr{IP: pkt.SrcIP.AsSlice(), Port: int(pkt.SrcPort)}
	select {
	case uc.rxCh <- udpDgram{src: srcAddr, data: cp}:
	default:
	}
}

func (u *ustackUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	var timerCh <-chan time.Time
	if dl := u.readDead.Load(); dl > 0 {
		rem := time.Until(time.Unix(0, dl))
		if rem <= 0 {
			return 0, nil, os.ErrDeadlineExceeded
		}
		t := time.NewTimer(rem)
		defer t.Stop()
		timerCh = t.C
	}
	select {
	case <-u.closed:
		return 0, nil, net.ErrClosed
	case <-u.stack.closedCh:
		return 0, nil, net.ErrClosed
	case <-timerCh:
		return 0, nil, os.ErrDeadlineExceeded
	case dg := <-u.rxCh:
		return copy(p, dg.data), dg.src, nil
	}
}

func (u *ustackUDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-u.closed:
		return 0, net.ErrClosed
	default:
	}
	uaddr, err := net.ResolveUDPAddr("udp", addr.String())
	if err != nil {
		return 0, err
	}
	dstIP, ok := netip.AddrFromSlice(uaddr.IP)
	if !ok {
		return 0, errors.New("invalid destination IP")
	}
	dstIP = dstIP.Unmap()
	srcIP, err := u.stack.localIPFor(dstIP)
	if err != nil {
		return 0, err
	}
	l3 := pktutil.BuildUDPPacket(srcIP, dstIP, u.port, uint16(uaddr.Port), p)
	u.stack.emitL3(l3)
	return len(p), nil
}

func (u *ustackUDPConn) LocalAddr() net.Addr {
	v4, _ := u.stack.LocalIPs()
	return &net.UDPAddr{IP: v4.AsSlice(), Port: int(u.port)}
}

func (u *ustackUDPConn) Close() error {
	u.closeOnce.Do(func() {
		close(u.closed)
		u.stack.mu.Lock()
		if cur, ok := u.stack.udpSockets[u.port]; ok && cur == u {
			delete(u.stack.udpSockets, u.port)
		}
		u.stack.mu.Unlock()
	})
	return nil
}

func (u *ustackUDPConn) SetDeadline(t time.Time) error {
	return u.SetReadDeadline(t)
}

func (u *ustackUDPConn) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		u.readDead.Store(0)
	} else {
		u.readDead.Store(t.UnixNano())
	}
	return nil
}

func (u *ustackUDPConn) SetWriteDeadline(_ time.Time) error { return nil }

// connectedUDPConn adapts a bound ustackUDPConn + remote UDPAddr to net.Conn.
type connectedUDPConn struct {
	*ustackUDPConn
	remote *net.UDPAddr
}

func (c *connectedUDPConn) Read(b []byte) (int, error) {
	n, _, err := c.ReadFrom(b)
	return n, err
}

func (c *connectedUDPConn) Write(b []byte) (int, error) {
	return c.WriteTo(b, c.remote)
}

func (c *connectedUDPConn) RemoteAddr() net.Addr { return c.remote }

// --- Reliable Userspace TCP Implementation ---

type tcpState uint8

const (
	tcpSynSent tcpState = iota
	tcpSynRcvd
	tcpEstablished
	tcpClosed
)

type unackedSeg struct {
	seq      uint32
	flags    uint8
	payload  []byte
	lastSent time.Time
}

type ustackTCPListener struct {
	stack     *UserspaceStack
	port      uint16
	acceptCh  chan *ustackTCPConn
	closed    chan struct{}
	closeOnce sync.Once
}

func (s *UserspaceStack) ListenTCP(port uint16) (net.Listener, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.closedCh:
		return nil, ErrStackClosed
	default:
	}
	if port == 0 {
		var err error
		port, err = s.allocEphemeralTCPPortLocked(netip.Addr{}, 0)
		if err != nil {
			return nil, err
		}
	} else if _, exists := s.tcpListeners[port]; exists {
		return nil, ErrAddrInUse
	}
	ln := &ustackTCPListener{
		stack:    s,
		port:     port,
		acceptCh: make(chan *ustackTCPConn, 64),
		closed:   make(chan struct{}),
	}
	s.tcpListeners[port] = ln
	return ln, nil
}

func (l *ustackTCPListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	case <-l.stack.closedCh:
		return nil, net.ErrClosed
	case c := <-l.acceptCh:
		return c, nil
	}
}

func (l *ustackTCPListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closed)
		l.stack.mu.Lock()
		if cur, ok := l.stack.tcpListeners[l.port]; ok && cur == l {
			delete(l.stack.tcpListeners, l.port)
		}
		l.stack.mu.Unlock()
	})
	return nil
}

func (l *ustackTCPListener) Addr() net.Addr {
	v4, _ := l.stack.LocalIPs()
	return &net.TCPAddr{IP: v4.AsSlice(), Port: int(l.port)}
}

type ustackTCPConn struct {
	stack   *UserspaceStack
	key     tcpKey
	localIP netip.Addr

	mu        sync.Mutex
	cond      *sync.Cond
	state     tcpState
	sndUna    uint32
	sndNxt    uint32
	rcvNxt    uint32
	unacked   []unackedSeg
	rxBuf     bytes.Buffer
	oooMap    map[uint32][]byte
	peerEOF   bool
	localFIN  bool
	resetErr  error
	readDead  time.Time
	writeDead time.Time

	readyCh   chan struct{}
	readyOnce sync.Once
}

func newTCPConn(s *UserspaceStack, key tcpKey, localIP netip.Addr, st tcpState) *ustackTCPConn {
	var rnd [4]byte
	_, _ = rand.Read(rnd[:])
	iss := binary.BigEndian.Uint32(rnd[:])
	c := &ustackTCPConn{
		stack:   s,
		key:     key,
		localIP: localIP,
		state:   st,
		sndUna:  iss,
		sndNxt:  iss + 1,
		oooMap:  make(map[uint32][]byte),
		readyCh: make(chan struct{}),
	}
	c.cond = sync.NewCond(&c.mu)
	return c
}

func (c *ustackTCPConn) markReady() {
	c.readyOnce.Do(func() { close(c.readyCh) })
}

func (s *UserspaceStack) DialTCP(ctx context.Context, dstIP netip.Addr, dstPort uint16) (net.Conn, error) {
	localIP, err := s.localIPFor(dstIP)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	localPort, err := s.allocEphemeralTCPPortLocked(dstIP, dstPort)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	key := tcpKey{localPort: localPort, remoteIP: dstIP, remotePort: dstPort}
	c := newTCPConn(s, key, localIP, tcpSynSent)
	c.mu.Lock()
	synSeq := c.sndUna
	c.unacked = append(c.unacked, unackedSeg{
		seq:      synSeq,
		flags:    pktutil.TCPFlagSYN,
		lastSent: time.Now(),
	})
	c.mu.Unlock()
	s.tcpConns[key] = c
	s.mu.Unlock()

	s.emitL3(pktutil.BuildTCPPacket(localIP, dstIP, localPort, dstPort, synSeq, 0, pktutil.TCPFlagSYN, 65535, nil))

	select {
	case <-ctx.Done():
		_ = c.Close()
		return nil, ctx.Err()
	case <-s.closedCh:
		return nil, ErrStackClosed
	case <-c.readyCh:
		c.mu.Lock()
		rErr := c.resetErr
		c.mu.Unlock()
		if rErr != nil {
			return nil, rErr
		}
		return c, nil
	}
}

func (s *UserspaceStack) handleInboundTCP(pkt pktutil.ParsedPacket) {
	key := tcpKey{localPort: pkt.DstPort, remoteIP: pkt.SrcIP, remotePort: pkt.SrcPort}

	s.mu.RLock()
	c := s.tcpConns[key]
	ln := s.tcpListeners[pkt.DstPort]
	s.mu.RUnlock()

	// New inbound SYN to a listening port
	if c == nil {
		if (pkt.TCPFlags&pktutil.TCPFlagSYN) != 0 && (pkt.TCPFlags&pktutil.TCPFlagACK) == 0 && ln != nil {
			localIP := pkt.DstIP
			c = newTCPConn(s, key, localIP, tcpSynRcvd)
			c.rcvNxt = pkt.SeqNum + 1
			synAckSeq := c.sndUna
			c.unacked = append(c.unacked, unackedSeg{
				seq:      synAckSeq,
				flags:    pktutil.TCPFlagSYN | pktutil.TCPFlagACK,
				lastSent: time.Now(),
			})

			s.mu.Lock()
			if existing, ok := s.tcpConns[key]; ok {
				c = existing
				s.mu.Unlock()
			} else {
				s.tcpConns[key] = c
				s.mu.Unlock()
				s.emitL3(pktutil.BuildTCPPacket(localIP, pkt.SrcIP, pkt.DstPort, pkt.SrcPort, synAckSeq, c.rcvNxt, pktutil.TCPFlagSYN|pktutil.TCPFlagACK, 65535, nil))
				c.markReady()
				select {
				case ln.acceptCh <- c:
				default:
					_ = c.Close()
				}
			}
			return
		}
		// Unknown flow -> reply RST
		if (pkt.TCPFlags & pktutil.TCPFlagRST) == 0 {
			s.emitL3(pktutil.BuildTCPPacket(pkt.DstIP, pkt.SrcIP, pkt.DstPort, pkt.SrcPort, pkt.AckNum, pkt.SeqNum+1, pktutil.TCPFlagRST|pktutil.TCPFlagACK, 0, nil))
		}
		return
	}

	c.onSegment(pkt)
}

func (c *ustackTCPConn) onSegment(pkt pktutil.ParsedPacket) {
	c.mu.Lock()

	if (pkt.TCPFlags & pktutil.TCPFlagRST) != 0 {
		if c.state == tcpSynSent {
			c.resetErr = ErrConnRefused
		} else {
			c.resetErr = io.ErrUnexpectedEOF
		}
		c.state = tcpClosed
		c.unacked = nil
		c.cond.Broadcast()
		c.mu.Unlock()
		c.markReady()
		c.removeFromStack()
		return
	}

	// SYN_SENT awaiting SYN|ACK
	if c.state == tcpSynSent {
		if (pkt.TCPFlags&pktutil.TCPFlagSYN) != 0 && (pkt.TCPFlags&pktutil.TCPFlagACK) != 0 && pkt.AckNum == c.sndNxt {
			c.sndUna = pkt.AckNum
			c.rcvNxt = pkt.SeqNum + 1
			c.state = tcpEstablished
			c.pruneAckedLocked(pkt.AckNum)
			ackPkt := pktutil.BuildTCPPacket(c.localIP, c.key.remoteIP, c.key.localPort, c.key.remotePort, c.sndNxt, c.rcvNxt, pktutil.TCPFlagACK, 65535, nil)
			c.cond.Broadcast()
			c.mu.Unlock()
			c.stack.emitL3(ackPkt)
			c.markReady()
			return
		}
		c.mu.Unlock()
		return
	}

	// Process cumulative ACK
	if (pkt.TCPFlags & pktutil.TCPFlagACK) != 0 {
		if seqAfter(pkt.AckNum, c.sndUna) && !seqAfter(pkt.AckNum, c.sndNxt) {
			c.sndUna = pkt.AckNum
			c.pruneAckedLocked(pkt.AckNum)
			if c.state == tcpSynRcvd {
				c.state = tcpEstablished
			}
			c.cond.Broadcast()
		}
	}

	needAck := false
	if len(pkt.Payload) > 0 {
		if pkt.SeqNum == c.rcvNxt {
			c.rxBuf.Write(pkt.Payload)
			c.rcvNxt += uint32(len(pkt.Payload))
			// Drain contiguous out-of-order segments
			for {
				nextChunk, ok := c.oooMap[c.rcvNxt]
				if !ok {
					break
				}
				delete(c.oooMap, c.rcvNxt)
				c.rxBuf.Write(nextChunk)
				c.rcvNxt += uint32(len(nextChunk))
			}
			needAck = true
			c.cond.Broadcast()
		} else if seqAfter(pkt.SeqNum, c.rcvNxt) && len(c.oooMap) < 64 {
			cp := make([]byte, len(pkt.Payload))
			copy(cp, pkt.Payload)
			c.oooMap[pkt.SeqNum] = cp
			needAck = true
		} else {
			// Duplicate segment -> re-ACK current rcvNxt
			needAck = true
		}
	}

	if (pkt.TCPFlags & pktutil.TCPFlagFIN) != 0 {
		finSeq := pkt.SeqNum + uint32(len(pkt.Payload))
		if finSeq == c.rcvNxt && !c.peerEOF {
			c.rcvNxt++
			c.peerEOF = true
			needAck = true
			c.cond.Broadcast()
		} else if c.peerEOF {
			needAck = true
		}
	}

	var outAck []byte
	if needAck {
		outAck = pktutil.BuildTCPPacket(c.localIP, c.key.remoteIP, c.key.localPort, c.key.remotePort, c.sndNxt, c.rcvNxt, pktutil.TCPFlagACK, 65535, nil)
	}
	fullyDone := c.peerEOF && c.localFIN && len(c.unacked) == 0
	if fullyDone {
		c.state = tcpClosed
	}
	c.mu.Unlock()

	if outAck != nil {
		c.stack.emitL3(outAck)
	}
	if fullyDone {
		c.removeFromStack()
	}
}

func (c *ustackTCPConn) pruneAckedLocked(ackNum uint32) {
	kept := c.unacked[:0]
	for _, seg := range c.unacked {
		segLen := uint32(len(seg.payload))
		if (seg.flags&pktutil.TCPFlagSYN) != 0 || (seg.flags&pktutil.TCPFlagFIN) != 0 {
			segLen = 1
		}
		if seqAfter(seg.seq+segLen, ackNum) {
			kept = append(kept, seg)
		}
	}
	c.unacked = kept
}

func (c *ustackTCPConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for c.rxBuf.Len() == 0 {
		if c.resetErr != nil {
			return 0, c.resetErr
		}
		if c.peerEOF || c.state == tcpClosed {
			return 0, io.EOF
		}
		if !c.readDead.IsZero() && !time.Now().Before(c.readDead) {
			return 0, os.ErrDeadlineExceeded
		}
		c.cond.Wait()
	}
	return c.rxBuf.Read(p)
}

func (c *ustackTCPConn) Write(p []byte) (int, error) {
	select {
	case <-c.readyCh:
	case <-c.stack.closedCh:
		return 0, ErrStackClosed
	}

	total := 0
	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > ustackMSS {
			chunkSize = ustackMSS
		}
		chunk := make([]byte, chunkSize)
		copy(chunk, p[:chunkSize])

		c.mu.Lock()
		for int(c.sndNxt-c.sndUna) >= maxInFlightBytes && c.state != tcpClosed && !c.localFIN && c.resetErr == nil {
			if !c.writeDead.IsZero() && !time.Now().Before(c.writeDead) {
				c.mu.Unlock()
				return total, os.ErrDeadlineExceeded
			}
			c.cond.Wait()
		}
		if c.resetErr != nil {
			err := c.resetErr
			c.mu.Unlock()
			return total, err
		}
		if c.state == tcpClosed || c.localFIN {
			c.mu.Unlock()
			return total, net.ErrClosed
		}

		seq := c.sndNxt
		ack := c.rcvNxt
		c.sndNxt += uint32(chunkSize)
		c.unacked = append(c.unacked, unackedSeg{
			seq:      seq,
			flags:    pktutil.TCPFlagPSH | pktutil.TCPFlagACK,
			payload:  chunk,
			lastSent: time.Now(),
		})
		c.mu.Unlock()

		seg := pktutil.BuildTCPPacket(c.localIP, c.key.remoteIP, c.key.localPort, c.key.remotePort, seq, ack, pktutil.TCPFlagPSH|pktutil.TCPFlagACK, 65535, chunk)
		c.stack.emitL3(seg)

		p = p[chunkSize:]
		total += chunkSize
	}
	return total, nil
}

func (c *ustackTCPConn) Close() error {
	c.mu.Lock()
	if c.state == tcpClosed || c.localFIN {
		c.mu.Unlock()
		return nil
	}
	c.localFIN = true
	finSeq := c.sndNxt
	ack := c.rcvNxt
	c.sndNxt++
	c.unacked = append(c.unacked, unackedSeg{
		seq:      finSeq,
		flags:    pktutil.TCPFlagFIN | pktutil.TCPFlagACK,
		lastSent: time.Now(),
	})
	c.cond.Broadcast()
	c.mu.Unlock()

	c.stack.emitL3(pktutil.BuildTCPPacket(c.localIP, c.key.remoteIP, c.key.localPort, c.key.remotePort, finSeq, ack, pktutil.TCPFlagFIN|pktutil.TCPFlagACK, 65535, nil))
	return nil
}

func (c *ustackTCPConn) removeFromStack() {
	c.stack.mu.Lock()
	if cur, ok := c.stack.tcpConns[c.key]; ok && cur == c {
		delete(c.stack.tcpConns, c.key)
	}
	c.stack.mu.Unlock()
}

func (c *ustackTCPConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: c.localIP.AsSlice(), Port: int(c.key.localPort)}
}

func (c *ustackTCPConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: c.key.remoteIP.AsSlice(), Port: int(c.key.remotePort)}
}

func (c *ustackTCPConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *ustackTCPConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDead = t
	c.cond.Broadcast()
	c.mu.Unlock()
	if !t.IsZero() {
		if d := time.Until(t); d > 0 {
			time.AfterFunc(d, func() {
				c.mu.Lock()
				c.cond.Broadcast()
				c.mu.Unlock()
			})
		}
	}
	return nil
}

func (c *ustackTCPConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDead = t
	c.cond.Broadcast()
	c.mu.Unlock()
	if !t.IsZero() {
		if d := time.Until(t); d > 0 {
			time.AfterFunc(d, func() {
				c.mu.Lock()
				c.cond.Broadcast()
				c.mu.Unlock()
			})
		}
	}
	return nil
}

func (s *UserspaceStack) retransmitLoop() {
	ticker := time.NewTicker(retransmitTick)
	defer ticker.Stop()
	for {
		select {
		case <-s.closedCh:
			return
		case <-ticker.C:
			now := time.Now()
			s.mu.RLock()
			conns := make([]*ustackTCPConn, 0, len(s.tcpConns))
			for _, c := range s.tcpConns {
				conns = append(conns, c)
			}
			s.mu.RUnlock()

			for _, c := range conns {
				var rexmit [][]byte
				c.mu.Lock()
				for i := range c.unacked {
					if now.Sub(c.unacked[i].lastSent) >= retransmitTick {
						c.unacked[i].lastSent = now
						ack := c.rcvNxt
						if (c.unacked[i].flags&pktutil.TCPFlagSYN) != 0 && (c.unacked[i].flags&pktutil.TCPFlagACK) == 0 {
							ack = 0
						}
						rexmit = append(rexmit, pktutil.BuildTCPPacket(
							c.localIP, c.key.remoteIP, c.key.localPort, c.key.remotePort,
							c.unacked[i].seq, ack, c.unacked[i].flags, 65535, c.unacked[i].payload,
						))
					}
				}
				c.mu.Unlock()
				for _, pkt := range rexmit {
					s.emitL3(pkt)
				}
			}
		}
	}
}

func (s *UserspaceStack) Close() error {
	s.closeOnce.Do(func() {
		close(s.closedCh)
		s.mu.Lock()
		conns := make([]*ustackTCPConn, 0, len(s.tcpConns))
		for _, c := range s.tcpConns {
			conns = append(conns, c)
		}
		s.tcpConns = make(map[tcpKey]*ustackTCPConn)
		s.tcpListeners = make(map[uint16]*ustackTCPListener)
		s.udpSockets = make(map[uint16]*ustackUDPConn)
		s.mu.Unlock()

		for _, c := range conns {
			c.mu.Lock()
			c.state = tcpClosed
			c.cond.Broadcast()
			c.mu.Unlock()
			c.markReady()
		}
	})
	return nil
}

func seqAfter(a, b uint32) bool {
	return int32(a-b) > 0
}

func fmtPort(address string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, err
	}
	var p int
	_, err = fmt.Sscanf(portStr, "%d", &p)
	if err != nil || p < 0 || p > 65535 {
		return "", 0, fmt.Errorf("acknet: invalid port %q", portStr)
	}
	return host, uint16(p), nil
}

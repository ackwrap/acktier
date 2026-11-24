package netstack

import (
	"context"
	"encoding/binary"
	"crypto/rand"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/acktier/acktier/internal/daemon/pktutil"
)

const (
	tcpProxyMSS      = 1260
	natFlowIdleTTL   = 2 * time.Minute
)

// DialStreamFunc dials an outbound TCP connection on the Subnet Router / Exit Node host.
type DialStreamFunc func(ctx context.Context, network, address string) (net.Conn, error)

// DialPacketFunc dials a connected UDP socket on the Subnet Router / Exit Node host.
type DialPacketFunc func(ctx context.Context, network, address string) (net.Conn, error)

type flowTuple struct {
	srcIP   netip.Addr
	srcPort uint16
	dstIP   netip.Addr
	dstPort uint16
}

type tcpFlow struct {
	mu         sync.Mutex
	tuple      flowTuple
	conn       net.Conn
	serverSeq  uint32
	clientNext uint32
	established bool
	closed     bool
	lastActive time.Time
}

type udpFlow struct {
	tuple      flowTuple
	conn       net.Conn
	lastActive atomic.Int64
	closeOnce  sync.Once
}

// Gateway implements a zero-config Userspace L3->L4 NAT Gateway for Subnet Routers and Exit Nodes.
// It translates raw overlay IPv4/IPv6 TCP, UDP, and ICMP packets into host-outbound sockets
// without requiring OS kernel IP forwarding, iptables, or Windows NAT rules!
type Gateway struct {
	dialTCP DialStreamFunc
	dialUDP DialPacketFunc
	sendBack func(l3ReplyPkt []byte) // Sends return L3 packet back into the encrypted overlay tunnel

	tcpMu    sync.RWMutex
	tcpFlows map[flowTuple]*tcpFlow

	udpMu    sync.RWMutex
	udpFlows map[flowTuple]*udpFlow

	proxiedPkts  atomic.Uint64
	proxiedBytes atomic.Uint64
	closed       chan struct{}
	closeOnce    sync.Once
}

func NewGateway(dialTCP DialStreamFunc, dialUDP DialPacketFunc, sendBack func(l3ReplyPkt []byte)) *Gateway {
	if dialTCP == nil {
		var d net.Dialer
		dialTCP = d.DialContext
	}
	if dialUDP == nil {
		var d net.Dialer
		dialUDP = d.DialContext
	}
	g := &Gateway{
		dialTCP:  dialTCP,
		dialUDP:  dialUDP,
		sendBack: sendBack,
		tcpFlows: make(map[flowTuple]*tcpFlow),
		udpFlows: make(map[flowTuple]*udpFlow),
		closed:   make(chan struct{}),
	}
	go g.gcLoop()
	return g
}

func (g *Gateway) Stats() (packets, bytes uint64) {
	return g.proxiedPkts.Load(), g.proxiedBytes.Load()
}

// HandlePacket processes an inbound decrypted L3 packet addressed to an approved subnet or Exit Node destination.
func (g *Gateway) HandlePacket(raw []byte) bool {
	pkt, err := pktutil.Parse(raw)
	if err != nil {
		return false
	}
	g.proxiedPkts.Add(1)
	g.proxiedBytes.Add(uint64(len(raw)))

	switch pkt.Proto {
	case pktutil.ProtoICMPv4, pktutil.ProtoICMPv6:
		if reply, ok := pktutil.BuildICMPEchoReply(pkt); ok && g.sendBack != nil {
			g.sendBack(reply)
		}
		return true

	case pktutil.ProtoUDP:
		g.handleUDP(pkt)
		return true

	case pktutil.ProtoTCP:
		g.handleTCP(pkt)
		return true
	}
	return false
}

func (g *Gateway) handleUDP(pkt pktutil.ParsedPacket) {
	ft := flowTuple{
		srcIP:   pkt.SrcIP,
		srcPort: pkt.SrcPort,
		dstIP:   pkt.DstIP,
		dstPort: pkt.DstPort,
	}

	g.udpMu.RLock()
	uf := g.udpFlows[ft]
	g.udpMu.RUnlock()

	if uf == nil {
		targetAddr := net.JoinHostPort(pkt.DstIP.String(), strconv.Itoa(int(pkt.DstPort)))
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		conn, err := g.dialUDP(ctx, "udp", targetAddr)
		cancel()
		if err != nil {
			return
		}
		uf = &udpFlow{tuple: ft, conn: conn}
		uf.lastActive.Store(time.Now().UnixNano())

		g.udpMu.Lock()
		if existing, ok := g.udpFlows[ft]; ok {
			_ = conn.Close()
			uf = existing
		} else {
			g.udpFlows[ft] = uf
			go g.readUDPLoop(uf)
		}
		g.udpMu.Unlock()
	}

	uf.lastActive.Store(time.Now().UnixNano())
	_ = uf.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = uf.conn.Write(pkt.Payload)
}

func (g *Gateway) readUDPLoop(uf *udpFlow) {
	defer func() {
		uf.closeOnce.Do(func() { _ = uf.conn.Close() })
		g.udpMu.Lock()
		if cur, ok := g.udpFlows[uf.tuple]; ok && cur == uf {
			delete(g.udpFlows, uf.tuple)
		}
		g.udpMu.Unlock()
	}()

	buf := make([]byte, 65535)
	for {
		_ = uf.conn.SetReadDeadline(time.Now().Add(natFlowIdleTTL))
		n, err := uf.conn.Read(buf)
		if err != nil {
			return
		}
		uf.lastActive.Store(time.Now().UnixNano())
		if g.sendBack != nil && n > 0 {
			reply := pktutil.BuildUDPPacket(uf.tuple.dstIP, uf.tuple.srcIP, uf.tuple.dstPort, uf.tuple.srcPort, buf[:n])
			g.sendBack(reply)
		}
	}
}

func (g *Gateway) handleTCP(pkt pktutil.ParsedPacket) {
	ft := flowTuple{
		srcIP:   pkt.SrcIP,
		srcPort: pkt.SrcPort,
		dstIP:   pkt.DstIP,
		dstPort: pkt.DstPort,
	}

	// New TCP SYN handshake!
	if (pkt.TCPFlags&pktutil.TCPFlagSYN) != 0 && (pkt.TCPFlags&pktutil.TCPFlagACK) == 0 {
		go g.acceptTCPSyn(ft, pkt.SeqNum)
		return
	}

	g.tcpMu.RLock()
	tf := g.tcpFlows[ft]
	g.tcpMu.RUnlock()
	if tf == nil {
		if (pkt.TCPFlags & pktutil.TCPFlagRST) == 0 && g.sendBack != nil {
			rst := pktutil.BuildTCPPacket(ft.dstIP, ft.srcIP, ft.dstPort, ft.srcPort, pkt.AckNum, pkt.SeqNum+1, pktutil.TCPFlagRST|pktutil.TCPFlagACK, 0, nil)
			g.sendBack(rst)
		}
		return
	}

	if (pkt.TCPFlags & pktutil.TCPFlagRST) != 0 {
		g.closeTCPFlow(ft, tf)
		return
	}

	tf.mu.Lock()
	tf.lastActive = time.Now()
	if !tf.established && (pkt.TCPFlags&pktutil.TCPFlagACK) != 0 {
		tf.established = true
	}

	// Deliver in-order payload to outbound TCP socket
	if len(pkt.Payload) > 0 && pkt.SeqNum == tf.clientNext {
		_ = tf.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		n, err := tf.conn.Write(pkt.Payload)
		if n > 0 {
			tf.clientNext += uint32(n)
		}
		ackPkt := pktutil.BuildTCPPacket(ft.dstIP, ft.srcIP, ft.dstPort, ft.srcPort, tf.serverSeq, tf.clientNext, pktutil.TCPFlagACK, 65535, nil)
		tf.mu.Unlock()
		if g.sendBack != nil {
			g.sendBack(ackPkt)
		}
		if err != nil {
			g.closeTCPFlow(ft, tf)
		}
		return
	} else if len(pkt.Payload) > 0 && pkt.SeqNum < tf.clientNext {
		// Retransmission of already ACKed segment -> re-ACK current clientNext
		ackPkt := pktutil.BuildTCPPacket(ft.dstIP, ft.srcIP, ft.dstPort, ft.srcPort, tf.serverSeq, tf.clientNext, pktutil.TCPFlagACK, 65535, nil)
		tf.mu.Unlock()
		if g.sendBack != nil {
			g.sendBack(ackPkt)
		}
		return
	}

	if (pkt.TCPFlags & pktutil.TCPFlagFIN) != 0 {
		if pkt.SeqNum == tf.clientNext {
			tf.clientNext++
		}
		ackPkt := pktutil.BuildTCPPacket(ft.dstIP, ft.srcIP, ft.dstPort, ft.srcPort, tf.serverSeq, tf.clientNext, pktutil.TCPFlagFIN|pktutil.TCPFlagACK, 65535, nil)
		tf.serverSeq++
		tf.mu.Unlock()
		if g.sendBack != nil {
			g.sendBack(ackPkt)
		}
		g.closeTCPFlow(ft, tf)
		return
	}
	tf.mu.Unlock()
}

func (g *Gateway) acceptTCPSyn(ft flowTuple, clientISN uint32) {
	targetAddr := net.JoinHostPort(ft.dstIP.String(), strconv.Itoa(int(ft.dstPort)))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := g.dialTCP(ctx, "tcp", targetAddr)
	cancel()
	if err != nil {
		if g.sendBack != nil {
			rst := pktutil.BuildTCPPacket(ft.dstIP, ft.srcIP, ft.dstPort, ft.srcPort, 0, clientISN+1, pktutil.TCPFlagRST|pktutil.TCPFlagACK, 0, nil)
			g.sendBack(rst)
		}
		return
	}

	var rnd [4]byte
	_, _ = rand.Read(rnd[:])
	serverISN := binary.BigEndian.Uint32(rnd[:])

	tf := &tcpFlow{
		tuple:      ft,
		conn:       conn,
		serverSeq:  serverISN + 1,
		clientNext: clientISN + 1,
		lastActive: time.Now(),
	}

	g.tcpMu.Lock()
	if old, ok := g.tcpFlows[ft]; ok {
		_ = old.conn.Close()
	}
	g.tcpFlows[ft] = tf
	g.tcpMu.Unlock()

	// Send SYN-ACK back to peer!
	if g.sendBack != nil {
		synAck := pktutil.BuildTCPPacket(ft.dstIP, ft.srcIP, ft.dstPort, ft.srcPort, serverISN, clientISN+1, pktutil.TCPFlagSYN|pktutil.TCPFlagACK, 65535, nil)
		g.sendBack(synAck)
	}

	go g.readTCPLoop(tf)
}

func (g *Gateway) readTCPLoop(tf *tcpFlow) {
	buf := make([]byte, tcpProxyMSS)
	for {
		n, err := tf.conn.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])

			tf.mu.Lock()
			seq := tf.serverSeq
			ack := tf.clientNext
			tf.serverSeq += uint32(n)
			tf.lastActive = time.Now()
			tf.mu.Unlock()

			if g.sendBack != nil {
				seg := pktutil.BuildTCPPacket(tf.tuple.dstIP, tf.tuple.srcIP, tf.tuple.dstPort, tf.tuple.srcPort, seq, ack, pktutil.TCPFlagPSH|pktutil.TCPFlagACK, 65535, chunk)
				g.sendBack(seg)
			}
		}
		if err != nil {
			if err == io.EOF {
				tf.mu.Lock()
				seq := tf.serverSeq
				ack := tf.clientNext
				tf.serverSeq++
				tf.mu.Unlock()
				if g.sendBack != nil {
					finSeg := pktutil.BuildTCPPacket(tf.tuple.dstIP, tf.tuple.srcIP, tf.tuple.dstPort, tf.tuple.srcPort, seq, ack, pktutil.TCPFlagFIN|pktutil.TCPFlagACK, 65535, nil)
					g.sendBack(finSeg)
				}
			}
			g.closeTCPFlow(tf.tuple, tf)
			return
		}
	}
}

func (g *Gateway) closeTCPFlow(ft flowTuple, tf *tcpFlow) {
	tf.mu.Lock()
	if !tf.closed {
		tf.closed = true
		_ = tf.conn.Close()
	}
	tf.mu.Unlock()

	g.tcpMu.Lock()
	if cur, ok := g.tcpFlows[ft]; ok && cur == tf {
		delete(g.tcpFlows, ft)
	}
	g.tcpMu.Unlock()
}

func (g *Gateway) gcLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-g.closed:
			return
		case <-ticker.C:
			now := time.Now()
			g.tcpMu.Lock()
			for ft, tf := range g.tcpFlows {
				tf.mu.Lock()
				idle := now.Sub(tf.lastActive) > natFlowIdleTTL
				tf.mu.Unlock()
				if idle {
					_ = tf.conn.Close()
					delete(g.tcpFlows, ft)
				}
			}
			g.tcpMu.Unlock()
		}
	}
}

func (g *Gateway) Close() error {
	g.closeOnce.Do(func() {
		close(g.closed)
		g.tcpMu.Lock()
		for k, tf := range g.tcpFlows {
			_ = tf.conn.Close()
			delete(g.tcpFlows, k)
		}
		g.tcpMu.Unlock()

		g.udpMu.Lock()
		for k, uf := range g.udpFlows {
			uf.closeOnce.Do(func() { _ = uf.conn.Close() })
			delete(g.udpFlows, k)
		}
		g.udpMu.Unlock()
	})
	return nil
}

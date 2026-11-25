package pktutil

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	ProtoHopByHop   uint8 = 0
	ProtoICMPv4     uint8 = 1
	ProtoTCP        uint8 = 6
	ProtoUDP        uint8 = 17
	ProtoIPv6Route  uint8 = 43
	ProtoIPv6Frag   uint8 = 44
	ProtoICMPv6     uint8 = 58
	ProtoIPv6NoNext uint8 = 59
	ProtoIPv6Dest   uint8 = 60

	maxIPv6ExtHeaders = 4

	TCPFlagFIN uint8 = 0x01
	TCPFlagSYN uint8 = 0x02
	TCPFlagRST uint8 = 0x04
	TCPFlagPSH uint8 = 0x08
	TCPFlagACK uint8 = 0x10
)

var (
	ErrFragmentedPacket  = errors.New("pktutil: fragmented IP packets are rejected by policy")
	ErrUnsupportedHeader = errors.New("pktutil: unsupported IP extension header or L4 protocol")
)

// ParsedPacket holds decoded L3 (IPv4/IPv6) and L4 (TCP/UDP/ICMP) metadata and payload slice.
type ParsedPacket struct {
	Version  uint8
	Proto    uint8
	SrcIP    netip.Addr
	DstIP    netip.Addr
	SrcPort  uint16
	DstPort  uint16
	TCPFlags uint8
	SeqNum   uint32
	AckNum   uint32
	ICMPType uint8
	ICMPCode uint8
	ICMPID   uint16
	ICMPSeq  uint16
	Payload  []byte
}

// Parse decodes an L3 IPv4 or IPv6 packet, safely traverses supported IPv6 extension headers,
// rejects fragmented or unsupported headers/protocols (default-deny), and extracts the L4 header.
func Parse(raw []byte) (ParsedPacket, error) {
	var p ParsedPacket
	if len(raw) < 20 {
		return p, errors.New("packet too short")
	}
	p.Version = raw[0] >> 4
	var l4 []byte

	switch p.Version {
	case 4:
		ihl := int(raw[0]&0x0f) * 4
		totalLen := int(binary.BigEndian.Uint16(raw[2:4]))
		if ihl < 20 || len(raw) < ihl {
			return p, errors.New("invalid ipv4 header length")
		}
		if totalLen < ihl || totalLen > len(raw) {
			return p, errors.New("invalid ipv4 total length")
		}
		raw = raw[:totalLen]
		// Reject IPv4 fragments (MoreFragments=0x2000 or FragmentOffset=0x1fff) to prevent L4 port-filter bypass!
		flagsFrag := binary.BigEndian.Uint16(raw[6:8])
		if (flagsFrag & 0x3fff) != 0 {
			return p, ErrFragmentedPacket
		}
		p.Proto = raw[9]
		if p.Proto != ProtoTCP && p.Proto != ProtoUDP && p.Proto != ProtoICMPv4 {
			return p, ErrUnsupportedHeader
		}
		var s4, d4 [4]byte
		copy(s4[:], raw[12:16])
		copy(d4[:], raw[16:20])
		p.SrcIP = netip.AddrFrom4(s4)
		p.DstIP = netip.AddrFrom4(d4)
		l4 = raw[ihl:]

	case 6:
		if len(raw) < 40 {
			return p, errors.New("invalid ipv6 header length")
		}
		payloadLen := int(binary.BigEndian.Uint16(raw[4:6]))
		if 40+payloadLen > len(raw) {
			return p, errors.New("truncated ipv6 payload")
		}
		raw = raw[:40+payloadLen]
		nextHdr := raw[6]
		var s6, d6 [16]byte
		copy(s6[:], raw[8:24])
		copy(d6[:], raw[24:40])
		p.SrcIP = netip.AddrFrom16(s6)
		p.DstIP = netip.AddrFrom16(d6)
		l4 = raw[40:]

		// Walk benign IPv6 extension headers; reject Fragment, active Routing, AH/ESP, or unknown headers!
		for extCount := 0; ; extCount++ {
			switch nextHdr {
			case ProtoHopByHop, ProtoIPv6Dest:
				if extCount >= maxIPv6ExtHeaders || len(l4) < 8 {
					return p, ErrUnsupportedHeader
				}
				hdrLen := (int(l4[1]) + 1) * 8
				if len(l4) < hdrLen {
					return p, errors.New("truncated ipv6 extension header")
				}
				nextHdr = l4[0]
				l4 = l4[hdrLen:]
				continue

			case ProtoIPv6Route:
				if extCount >= maxIPv6ExtHeaders || len(l4) < 8 {
					return p, ErrUnsupportedHeader
				}
				segmentsLeft := l4[3]
				if segmentsLeft != 0 {
					// Source-routed IPv6 packets with remaining segments can rewrite DstIP!
					return p, ErrUnsupportedHeader
				}
				hdrLen := (int(l4[1]) + 1) * 8
				if len(l4) < hdrLen {
					return p, errors.New("truncated ipv6 routing header")
				}
				nextHdr = l4[0]
				l4 = l4[hdrLen:]
				continue

			case ProtoIPv6Frag:
				return p, ErrFragmentedPacket

			case ProtoTCP, ProtoUDP, ProtoICMPv6:
				p.Proto = nextHdr

			default:
				return p, ErrUnsupportedHeader
			}
			break
		}

	default:
		return p, errors.New("unsupported ip version")
	}

	switch p.Proto {
	case ProtoTCP:
		if len(l4) < 20 {
			return p, errors.New("short tcp header")
		}
		p.SrcPort = binary.BigEndian.Uint16(l4[0:2])
		p.DstPort = binary.BigEndian.Uint16(l4[2:4])
		p.SeqNum = binary.BigEndian.Uint32(l4[4:8])
		p.AckNum = binary.BigEndian.Uint32(l4[8:12])
		dataOff := int(l4[12]>>4) * 4
		p.TCPFlags = l4[13] & 0x3f
		if dataOff < 20 || len(l4) < dataOff {
			return p, errors.New("invalid tcp data offset")
		}
		p.Payload = l4[dataOff:]

	case ProtoUDP:
		if len(l4) < 8 {
			return p, errors.New("short udp header")
		}
		p.SrcPort = binary.BigEndian.Uint16(l4[0:2])
		p.DstPort = binary.BigEndian.Uint16(l4[2:4])
		p.Payload = l4[8:]

	case ProtoICMPv4, ProtoICMPv6:
		if len(l4) < 4 {
			return p, errors.New("short icmp header")
		}
		p.ICMPType = l4[0]
		p.ICMPCode = l4[1]
		if len(l4) >= 8 {
			p.ICMPID = binary.BigEndian.Uint16(l4[4:6])
			p.ICMPSeq = binary.BigEndian.Uint16(l4[6:8])
			p.Payload = l4[8:]
		}
	default:
		return p, ErrUnsupportedHeader
	}
	return p, nil
}

// BuildUDPPacket constructs a complete L3+UDP packet with valid IPv4/IPv6 + UDP checksums.
func BuildUDPPacket(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	udpSeg := make([]byte, udpLen)
	binary.BigEndian.PutUint16(udpSeg[0:2], srcPort)
	binary.BigEndian.PutUint16(udpSeg[2:4], dstPort)
	binary.BigEndian.PutUint16(udpSeg[4:6], uint16(udpLen))
	copy(udpSeg[8:], payload)

	csum := pseudoHeaderChecksum(srcIP, dstIP, ProtoUDP, udpSeg)
	if csum == 0 {
		csum = 0xffff
	}
	binary.BigEndian.PutUint16(udpSeg[6:8], csum)
	return wrapL3(srcIP, dstIP, ProtoUDP, udpSeg)
}

// BuildTCPPacket constructs a complete L3+TCP segment with valid IPv4/IPv6 + TCP checksums.
func BuildTCPPacket(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, seq, ack uint32, flags uint8, window uint16, payload []byte) []byte {
	tcpLen := 20 + len(payload)
	tcpSeg := make([]byte, tcpLen)
	binary.BigEndian.PutUint16(tcpSeg[0:2], srcPort)
	binary.BigEndian.PutUint16(tcpSeg[2:4], dstPort)
	binary.BigEndian.PutUint32(tcpSeg[4:8], seq)
	binary.BigEndian.PutUint32(tcpSeg[8:12], ack)
	tcpSeg[12] = 5 << 4 // 20-byte header
	tcpSeg[13] = flags
	if window == 0 {
		window = 65535
	}
	binary.BigEndian.PutUint16(tcpSeg[14:16], window)
	copy(tcpSeg[20:], payload)

	csum := pseudoHeaderChecksum(srcIP, dstIP, ProtoTCP, tcpSeg)
	binary.BigEndian.PutUint16(tcpSeg[16:18], csum)
	return wrapL3(srcIP, dstIP, ProtoTCP, tcpSeg)
}

// BuildICMPEchoReply constructs an ICMPv4 or ICMPv6 Echo Reply from a parsed Echo Request.
func BuildICMPEchoReply(req ParsedPacket) ([]byte, bool) {
	if req.Proto == ProtoICMPv4 && req.ICMPType == 8 {
		icmpSeg := make([]byte, 8+len(req.Payload))
		icmpSeg[0] = 0 // Echo Reply
		icmpSeg[1] = 0
		binary.BigEndian.PutUint16(icmpSeg[4:6], req.ICMPID)
		binary.BigEndian.PutUint16(icmpSeg[6:8], req.ICMPSeq)
		copy(icmpSeg[8:], req.Payload)
		binary.BigEndian.PutUint16(icmpSeg[2:4], checksum(0, icmpSeg))
		return wrapL3(req.DstIP, req.SrcIP, ProtoICMPv4, icmpSeg), true
	}
	if req.Proto == ProtoICMPv6 && req.ICMPType == 128 {
		icmpSeg := make([]byte, 8+len(req.Payload))
		icmpSeg[0] = 129 // Echo Reply v6
		icmpSeg[1] = 0
		binary.BigEndian.PutUint16(icmpSeg[4:6], req.ICMPID)
		binary.BigEndian.PutUint16(icmpSeg[6:8], req.ICMPSeq)
		copy(icmpSeg[8:], req.Payload)
		binary.BigEndian.PutUint16(icmpSeg[2:4], pseudoHeaderChecksum(req.DstIP, req.SrcIP, ProtoICMPv6, icmpSeg))
		return wrapL3(req.DstIP, req.SrcIP, ProtoICMPv6, icmpSeg), true
	}
	return nil, false
}

func wrapL3(srcIP, dstIP netip.Addr, proto uint8, l4 []byte) []byte {
	if srcIP.Is4() && dstIP.Is4() {
		total := 20 + len(l4)
		out := make([]byte, total)
		out[0] = 0x45
		binary.BigEndian.PutUint16(out[2:4], uint16(total))
		out[6] = 0x40 // Don't Fragment
		out[8] = 64   // TTL
		out[9] = proto
		s4 := srcIP.As4()
		d4 := dstIP.As4()
		copy(out[12:16], s4[:])
		copy(out[16:20], d4[:])
		binary.BigEndian.PutUint16(out[10:12], checksum(0, out[:20]))
		copy(out[20:], l4)
		return out
	}

	out := make([]byte, 40+len(l4))
	out[0] = 0x60
	binary.BigEndian.PutUint16(out[4:6], uint16(len(l4)))
	out[6] = proto
	out[7] = 64
	s6 := srcIP.As16()
	d6 := dstIP.As16()
	copy(out[8:24], s6[:])
	copy(out[24:40], d6[:])
	copy(out[40:], l4)
	return out
}

func pseudoHeaderChecksum(srcIP, dstIP netip.Addr, proto uint8, l4 []byte) uint16 {
	var sum uint32
	if srcIP.Is4() && dstIP.Is4() {
		s4 := srcIP.As4()
		d4 := dstIP.As4()
		sum += uint32(binary.BigEndian.Uint16(s4[0:2])) + uint32(binary.BigEndian.Uint16(s4[2:4]))
		sum += uint32(binary.BigEndian.Uint16(d4[0:2])) + uint32(binary.BigEndian.Uint16(d4[2:4]))
		sum += uint32(proto) + uint32(len(l4))
	} else {
		s6 := srcIP.As16()
		d6 := dstIP.As16()
		for i := 0; i < 16; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(s6[i : i+2]))
			sum += uint32(binary.BigEndian.Uint16(d6[i : i+2]))
		}
		sum += uint32(len(l4)) + uint32(proto)
	}
	return checksum(sum, l4)
}

func checksum(initial uint32, b []byte) uint16 {
	sum := initial
	n := len(b)
	for i := 0; i+1 < n; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if n%2 == 1 {
		sum += uint32(b[n-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

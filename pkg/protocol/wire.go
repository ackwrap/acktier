package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/acktier/acktier/pkg/types"
)

const (
	MagicByte          byte = 0xAC
	ProtoVersion       byte = 0x01
	HeaderMinSize           = 4 // Magic(1) + Version(1) + PacketType(1) + Flags(1)
	MaxFrameSize            = 65535
	DefaultHopTTL      byte = 8
	ControlAuthTagSize      = 16

	FlagPunchReply  byte = 0x01
	FlagControlAuth byte = 0x02
)

// PacketType identifies the wire message kind across direct and relayed transports.
type PacketType byte

const (
	PacketHandshakeInit PacketType = 0x01
	PacketHandshakeAck  PacketType = 0x02
	PacketData          PacketType = 0x03
	PacketPing          PacketType = 0x04
	PacketPong          PacketType = 0x05
	PacketPunchCoord    PacketType = 0x06 // CallMeMaybe synchronized hole-punch request

	PacketRelayBind    PacketType = 0x10
	PacketRelayBindAck PacketType = 0x11
	PacketRelayForward PacketType = 0x12
	PacketMeshForward  PacketType = 0x13 // Authenticated peer hop; never used on the center relay stream.
)

var (
	ErrShortPacket   = errors.New("protocol: packet too short")
	ErrBadMagic      = errors.New("protocol: invalid magic byte")
	ErrBadVersion    = errors.New("protocol: unsupported protocol version")
	ErrFrameTooLarge = errors.New("protocol: frame exceeds max size")
	ErrControlUnauth = errors.New("protocol: control packet missing or invalid authentication tag")
)

// ParseHeader validates the 4-byte common wire header and returns PacketType, Flags, and body slice.
func ParseHeader(pkt []byte) (PacketType, byte, []byte, error) {
	if len(pkt) < HeaderMinSize {
		return 0, 0, nil, ErrShortPacket
	}
	if pkt[0] != MagicByte {
		return 0, 0, nil, ErrBadMagic
	}
	if pkt[1] != ProtoVersion {
		return 0, 0, nil, ErrBadVersion
	}
	return PacketType(pkt[2]), pkt[3], pkt[4:], nil
}

// WriteHeader writes the 4-byte common wire header into dst[0:4].
func WriteHeader(dst []byte, pktType PacketType, flags byte) {
	dst[0] = MagicByte
	dst[1] = ProtoVersion
	dst[2] = byte(pktType)
	dst[3] = flags
}

// DataPacket represents an encrypted tunnel packet header + AEAD payload.
// Wire layout: Header(4) + SenderKeyPrefix(8) + NonceCounter(8) + Ciphertext(...)
const DataHeaderSize = HeaderMinSize + 8 + 8

func EncodeDataPacket(sender types.PublicKey, counter uint64, ciphertext []byte) []byte {
	out := make([]byte, DataHeaderSize+len(ciphertext))
	WriteHeader(out, PacketData, 0)
	copy(out[4:12], sender[:8])
	binary.BigEndian.PutUint64(out[12:20], counter)
	copy(out[20:], ciphertext)
	return out
}

func DecodeDataPacket(pkt []byte) (senderPrefix [8]byte, counter uint64, ciphertext []byte, err error) {
	pType, _, body, err := ParseHeader(pkt)
	if err != nil {
		return senderPrefix, 0, nil, err
	}
	if pType != PacketData || len(body) < 16 {
		return senderPrefix, 0, nil, ErrShortPacket
	}
	copy(senderPrefix[:], body[:8])
	counter = binary.BigEndian.Uint64(body[8:16])
	return senderPrefix, counter, body[16:], nil
}

// HandshakePacket carries key-agreement material authenticated with X25519 + AEAD.
// Wire layout: Header(4) + SenderStaticPub(32) + EphemeralPub(32) + TimestampUnixNano(8) + SealedTag(16+)
const HandshakeMinSize = HeaderMinSize + 32 + 32 + 8

func EncodeHandshakePacket(pktType PacketType, staticPub, ephPub types.PublicKey, tsNano int64, sealedProof []byte) []byte {
	out := make([]byte, HandshakeMinSize+len(sealedProof))
	WriteHeader(out, pktType, 0)
	copy(out[4:36], staticPub[:])
	copy(out[36:68], ephPub[:])
	binary.BigEndian.PutUint64(out[68:76], uint64(tsNano))
	copy(out[76:], sealedProof)
	return out
}

func DecodeHandshakePacket(pkt []byte) (pktType PacketType, staticPub, ephPub types.PublicKey, tsNano int64, sealedProof []byte, err error) {
	pType, _, body, err := ParseHeader(pkt)
	if err != nil {
		return 0, staticPub, ephPub, 0, nil, err
	}
	if (pType != PacketHandshakeInit && pType != PacketHandshakeAck) || len(body) < 72 {
		return 0, staticPub, ephPub, 0, nil, ErrShortPacket
	}
	copy(staticPub[:], body[0:32])
	copy(ephPub[:], body[32:64])
	tsNano = int64(binary.BigEndian.Uint64(body[64:72]))
	return pType, staticPub, ephPub, tsNano, body[72:], nil
}

// ProbePacket is used for STUN/Relay RTT measurement (unauthenticated) and Peer Ping/Pong (HMAC-authenticated).
// Wire layout: Header(4) + SenderPub(32) + ProbeID(8) + TxUnixNano(8) + ObservedAddrLen(1) + ObservedAddr(...) [+ AuthTag(16)]
func EncodeProbePacket(pktType PacketType, sender types.PublicKey, probeID uint64, txNano int64, observedAddr string) []byte {
	if len(observedAddr) > 255 {
		observedAddr = observedAddr[:255]
	}
	out := make([]byte, HeaderMinSize+32+8+8+1+len(observedAddr))
	WriteHeader(out, pktType, 0)
	copy(out[4:36], sender[:])
	binary.BigEndian.PutUint64(out[36:44], probeID)
	binary.BigEndian.PutUint64(out[44:52], uint64(txNano))
	out[52] = byte(len(observedAddr))
	copy(out[53:], observedAddr)
	return out
}

// EncodeAuthProbePacket encodes a peer-to-peer Ping/Pong packet authenticated with a 128-bit per-peer HMAC bound to targetPub.
func EncodeAuthProbePacket(pktType PacketType, sender, targetPub types.PublicKey, probeID uint64, txNano int64, observedAddr string, sign func(data []byte) ([ControlAuthTagSize]byte, error)) ([]byte, error) {
	if len(observedAddr) > 255 {
		observedAddr = observedAddr[:255]
	}
	baseLen := HeaderMinSize + 32 + 8 + 8 + 1 + len(observedAddr)
	out := make([]byte, baseLen+ControlAuthTagSize)
	WriteHeader(out, pktType, FlagControlAuth)
	copy(out[4:36], sender[:])
	binary.BigEndian.PutUint64(out[36:44], probeID)
	binary.BigEndian.PutUint64(out[44:52], uint64(txNano))
	out[52] = byte(len(observedAddr))
	copy(out[53:baseLen], observedAddr)

	macInput := buildControlAuthInput(targetPub, out[:baseLen])
	tag, err := sign(macInput)
	if err != nil {
		return nil, err
	}
	copy(out[baseLen:], tag[:])
	return out, nil
}

func DecodeProbePacket(pkt []byte) (pktType PacketType, sender types.PublicKey, probeID uint64, txNano int64, observedAddr string, err error) {
	pType, flags, body, err := ParseHeader(pkt)
	if err != nil {
		return 0, sender, 0, 0, "", err
	}
	if flags&FlagControlAuth != 0 {
		if len(body) < 49+ControlAuthTagSize {
			return 0, sender, 0, 0, "", ErrShortPacket
		}
		body = body[:len(body)-ControlAuthTagSize]
	}
	if (pType != PacketPing && pType != PacketPong) || len(body) < 49 {
		return 0, sender, 0, 0, "", ErrShortPacket
	}
	copy(sender[:], body[0:32])
	probeID = binary.BigEndian.Uint64(body[32:40])
	txNano = int64(binary.BigEndian.Uint64(body[40:48]))
	addrLen := int(body[48])
	if len(body) != 49+addrLen {
		return 0, sender, 0, 0, "", ErrShortPacket
	}
	observedAddr = string(body[49 : 49+addrLen])
	return pType, sender, probeID, txNano, observedAddr, nil
}

// DecodeAndVerifyProbePacket decodes a ProbePacket and, if FlagControlAuth is set, verifies its HMAC bound to localPub.
func DecodeAndVerifyProbePacket(pkt []byte, localPub types.PublicKey, verify func(sender types.PublicKey, data []byte, tag [ControlAuthTagSize]byte) bool) (pktType PacketType, sender types.PublicKey, probeID uint64, txNano int64, observedAddr string, authenticated bool, err error) {
	pType, flags, _, err := ParseHeader(pkt)
	if err != nil {
		return 0, sender, 0, 0, "", false, err
	}
	if pType != PacketPing && pType != PacketPong {
		return 0, sender, 0, 0, "", false, ErrShortPacket
	}
	if flags&FlagControlAuth == 0 {
		pType, sender, probeID, txNano, observedAddr, err = DecodeProbePacket(pkt)
		return pType, sender, probeID, txNano, observedAddr, false, err
	}
	if len(pkt) < HeaderMinSize+49+ControlAuthTagSize {
		return 0, sender, 0, 0, "", false, ErrShortPacket
	}
	baseLen := len(pkt) - ControlAuthTagSize
	pType, sender, probeID, txNano, observedAddr, err = DecodeProbePacket(pkt)
	if err != nil {
		return 0, sender, 0, 0, "", false, err
	}
	var tag [ControlAuthTagSize]byte
	copy(tag[:], pkt[baseLen:])
	if verify == nil || !verify(sender, buildControlAuthInput(localPub, pkt[:baseLen]), tag) {
		return 0, sender, 0, 0, "", false, ErrControlUnauth
	}
	return pType, sender, probeID, txNano, observedAddr, true, nil
}

// EncodeAuthPunchCoord encodes an HMAC-authenticated CallMeMaybe hole-punch coordination packet with replay timestamp.
// Wire layout: Header(4, flags) + SenderPub(32) + TxUnixNano(8) + NATKind(1) + PortStep(2) + EpCount(1) + Endpoints... + AuthTag(16)
func EncodeAuthPunchCoord(sender, targetPub types.PublicKey, isReply bool, natKind byte, portStep int16, txNano int64, endpoints []types.Endpoint, sign func(data []byte) ([ControlAuthTagSize]byte, error)) ([]byte, error) {
	if len(endpoints) > 16 {
		endpoints = endpoints[:16]
	}
	size := HeaderMinSize + 32 + 8 + 1 + 2 + 1
	for _, ep := range endpoints {
		pLen := len(ep.Proto)
		if pLen > 16 {
			pLen = 16
		}
		aLen := len(ep.Addr)
		if aLen > 128 {
			aLen = 128
		}
		size += 1 + pLen + 1 + aLen
	}
	flags := FlagControlAuth
	if isReply {
		flags |= FlagPunchReply
	}
	out := make([]byte, size+ControlAuthTagSize)
	WriteHeader(out, PacketPunchCoord, flags)
	copy(out[4:36], sender[:])
	binary.BigEndian.PutUint64(out[36:44], uint64(txNano))
	out[44] = natKind
	binary.BigEndian.PutUint16(out[45:47], uint16(portStep))
	out[47] = byte(len(endpoints))
	off := 48
	for _, ep := range endpoints {
		pStr := string(ep.Proto)
		if len(pStr) > 16 {
			pStr = pStr[:16]
		}
		aStr := ep.Addr
		if len(aStr) > 128 {
			aStr = aStr[:128]
		}
		out[off] = byte(len(pStr))
		off++
		copy(out[off:], pStr)
		off += len(pStr)
		out[off] = byte(len(aStr))
		off++
		copy(out[off:], aStr)
		off += len(aStr)
	}
	macInput := buildControlAuthInput(targetPub, out[:off])
	tag, err := sign(macInput)
	if err != nil {
		return nil, err
	}
	copy(out[off:off+ControlAuthTagSize], tag[:])
	return out[:off+ControlAuthTagSize], nil
}

// DecodeAndVerifyPunchCoord decodes and cryptographically verifies an authenticated PacketPunchCoord message.
func DecodeAndVerifyPunchCoord(pkt []byte, localPub types.PublicKey, verify func(sender types.PublicKey, data []byte, tag [ControlAuthTagSize]byte) bool) (sender types.PublicKey, isReply bool, natKind byte, portStep int16, txNano int64, endpoints []types.Endpoint, err error) {
	pType, flags, _, err := ParseHeader(pkt)
	if err != nil {
		return sender, false, 0, 0, 0, nil, err
	}
	if pType != PacketPunchCoord {
		return sender, false, 0, 0, 0, nil, ErrShortPacket
	}
	if flags&FlagControlAuth == 0 {
		return sender, false, 0, 0, 0, nil, ErrControlUnauth
	}
	if len(pkt) < HeaderMinSize+44+ControlAuthTagSize {
		return sender, false, 0, 0, 0, nil, ErrShortPacket
	}
	baseLen := len(pkt) - ControlAuthTagSize
	body := pkt[HeaderMinSize:baseLen]
	copy(sender[:], body[0:32])
	txNano = int64(binary.BigEndian.Uint64(body[32:40]))
	natKind = body[40]
	portStep = int16(binary.BigEndian.Uint16(body[41:43]))
	count := int(body[43])
	if count > 16 {
		return sender, false, 0, 0, 0, nil, ErrFrameTooLarge
	}
	off := 44
	endpoints = make([]types.Endpoint, 0, count)
	for i := 0; i < count; i++ {
		if off >= len(body) {
			return sender, false, 0, 0, 0, nil, ErrShortPacket
		}
		pLen := int(body[off])
		off++
		if off+pLen >= len(body) {
			return sender, false, 0, 0, 0, nil, ErrShortPacket
		}
		proto := types.TransportProto(body[off : off+pLen])
		off += pLen
		aLen := int(body[off])
		off++
		if off+aLen > len(body) {
			return sender, false, 0, 0, 0, nil, ErrShortPacket
		}
		addr := string(body[off : off+aLen])
		off += aLen
		endpoints = append(endpoints, types.Endpoint{Proto: proto, Addr: addr})
	}
	if off != len(body) {
		return sender, false, 0, 0, 0, nil, ErrShortPacket
	}
	var tag [ControlAuthTagSize]byte
	copy(tag[:], pkt[baseLen:])
	if verify == nil || !verify(sender, buildControlAuthInput(localPub, pkt[:baseLen]), tag) {
		return sender, false, 0, 0, 0, nil, ErrControlUnauth
	}
	return sender, (flags & FlagPunchReply) != 0, natKind, portStep, txNano, endpoints, nil
}

func buildControlAuthInput(targetPub types.PublicKey, rawPkt []byte) []byte {
	out := make([]byte, 32+len(rawPkt))
	copy(out[0:32], targetPub[:])
	copy(out[32:], rawPkt)
	return out
}

// RelayBindPacket binds a client's NodeKey on a stream connection to a Relay server.
// Wire layout: Header(4) + NodeKey(32) + TokenLen(2) + Token(...)
func EncodeRelayBind(nodeKey types.PublicKey, nodeToken string) []byte {
	out := make([]byte, HeaderMinSize+32+2+len(nodeToken))
	WriteHeader(out, PacketRelayBind, 0)
	copy(out[4:36], nodeKey[:])
	binary.BigEndian.PutUint16(out[36:38], uint16(len(nodeToken)))
	copy(out[38:], nodeToken)
	return out
}

func DecodeRelayBind(pkt []byte) (nodeKey types.PublicKey, nodeToken string, err error) {
	pType, _, body, err := ParseHeader(pkt)
	if err != nil {
		return nodeKey, "", err
	}
	if pType != PacketRelayBind || len(body) < 34 {
		return nodeKey, "", ErrShortPacket
	}
	copy(nodeKey[:], body[0:32])
	tokenLen := int(binary.BigEndian.Uint16(body[32:34]))
	if len(body) < 34+tokenLen {
		return nodeKey, "", ErrShortPacket
	}
	return nodeKey, string(body[34 : 34+tokenLen]), nil
}

func EncodeRelayBindAck(ok bool, msg string) []byte {
	flags := byte(0)
	if ok {
		flags = 1
	}
	out := make([]byte, HeaderMinSize+len(msg))
	WriteHeader(out, PacketRelayBindAck, flags)
	copy(out[4:], msg)
	return out
}

func DecodeRelayBindAck(pkt []byte) (ok bool, msg string, err error) {
	pType, flags, body, err := ParseHeader(pkt)
	if err != nil {
		return false, "", err
	}
	if pType != PacketRelayBindAck {
		return false, "", fmt.Errorf("protocol: expected RelayBindAck, got 0x%x", pType)
	}
	return flags == 1, string(body), nil
}

// RelayForwardPacket wraps an opaque inner end-to-end encrypted packet for single-hop or multi-hop relay.
// Wire layout: Header(4, flags=TTL) + SrcNodeKey(32) + DstNodeKey(32) + InnerPacket(...)
const RelayForwardHeaderSize = HeaderMinSize + 32 + 32

func EncodeRelayForward(ttl byte, src, dst types.PublicKey, inner []byte) []byte {
	out := make([]byte, RelayForwardHeaderSize+len(inner))
	WriteHeader(out, PacketRelayForward, ttl)
	copy(out[4:36], src[:])
	copy(out[36:68], dst[:])
	copy(out[68:], inner)
	return out
}

func DecodeRelayForward(pkt []byte) (ttl byte, src, dst types.PublicKey, inner []byte, err error) {
	pType, flags, body, err := ParseHeader(pkt)
	if err != nil {
		return 0, src, dst, nil, err
	}
	if pType != PacketRelayForward || len(body) < 64 {
		return 0, src, dst, nil, ErrShortPacket
	}
	copy(src[:], body[0:32])
	copy(dst[:], body[32:64])
	return flags, src, dst, body[64:], nil
}

const meshForwardHeaderSize = HeaderMinSize + 3*types.KeySize + 2*8

// MeshForward carries an opaque end-to-end frame plus authenticated hop
// metadata. Each relay verifies the incoming hop and signs a new wrapper.
type MeshForward struct {
	TTL                      byte
	Previous, Source, Target types.PublicKey
	SentAt                   int64
	Sequence                 uint64
	Inner                    []byte
}

func EncodeMeshForward(frame MeshForward, next types.PublicKey, sign func([]byte) ([ControlAuthTagSize]byte, error)) ([]byte, error) {
	if len(frame.Inner) > MaxFrameSize-meshForwardHeaderSize-ControlAuthTagSize {
		return nil, ErrFrameTooLarge
	}
	bodyLen := meshForwardHeaderSize + len(frame.Inner)
	out := make([]byte, bodyLen+ControlAuthTagSize)
	WriteHeader(out, PacketMeshForward, frame.TTL)
	copy(out[4:36], frame.Previous[:])
	copy(out[36:68], frame.Source[:])
	copy(out[68:100], frame.Target[:])
	binary.BigEndian.PutUint64(out[100:108], uint64(frame.SentAt))
	binary.BigEndian.PutUint64(out[108:116], frame.Sequence)
	copy(out[meshForwardHeaderSize:bodyLen], frame.Inner)
	tag, err := sign(buildControlAuthInput(next, out[:bodyLen]))
	if err != nil {
		return nil, err
	}
	copy(out[bodyLen:], tag[:])
	return out, nil
}

func DecodeAndVerifyMeshForward(pkt []byte, local types.PublicKey, verify func(types.PublicKey, []byte, [ControlAuthTagSize]byte) bool) (MeshForward, error) {
	var frame MeshForward
	pType, ttl, _, err := ParseHeader(pkt)
	if err != nil {
		return frame, err
	}
	if pType != PacketMeshForward || ttl == 0 || ttl > DefaultHopTTL ||
		len(pkt) < meshForwardHeaderSize+HeaderMinSize+ControlAuthTagSize || len(pkt) > MaxFrameSize {
		return frame, ErrShortPacket
	}
	frame.TTL = ttl
	copy(frame.Previous[:], pkt[4:36])
	copy(frame.Source[:], pkt[36:68])
	copy(frame.Target[:], pkt[68:100])
	if frame.Previous.IsZero() || frame.Source.IsZero() || frame.Target.IsZero() ||
		(ttl == DefaultHopTTL && frame.Previous != frame.Source) {
		return frame, ErrControlUnauth
	}
	end := len(pkt) - ControlAuthTagSize
	tag := [ControlAuthTagSize]byte(pkt[end:])
	if verify == nil || !verify(frame.Previous, buildControlAuthInput(local, pkt[:end]), tag) {
		return frame, ErrControlUnauth
	}
	frame.SentAt = int64(binary.BigEndian.Uint64(pkt[100:108]))
	frame.Sequence = binary.BigEndian.Uint64(pkt[108:116])
	frame.Inner = pkt[meshForwardHeaderSize:end]
	return frame, nil
}

// WriteFrame writes a length-prefixed wire packet to a stream (TCP / WebSocket / Relay).
func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxFrameSize {
		return ErrFrameTooLarge
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame reads a length-prefixed wire packet from a stream.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 {
		return nil, ErrShortPacket
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

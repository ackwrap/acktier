package dns

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/ackwrap/acktier/internal/daemon/pktutil"
	"github.com/ackwrap/acktier/pkg/types"
)

var (
	MagicDNSIPv4 = netip.MustParseAddr("100.100.100.100")
	MagicDNSIPv6 = netip.MustParseAddr("fd7a:115c:a1e0::53")
)

type hostRecord struct {
	fqdn string
	ipv4 netip.Addr
	ipv6 netip.Addr
}

// Resolver serves MagicDNS A, AAAA, and PTR records on 100.100.100.100 and optionally forwards external queries.
type Resolver struct {
	mu          sync.RWMutex
	enabled     bool
	suffix      string // lowercase without leading/trailing dot, e.g. "ack.internal"
	nameservers []string
	byName      map[string]hostRecord // shortname and fqdn (without trailing dot) -> record
	byIP        map[netip.Addr]string // IP -> fqdn with trailing dot
}

func NewResolver() *Resolver {
	return &Resolver{
		enabled: true,
		suffix:  "ack.internal",
		byName:  make(map[string]hostRecord),
		byIP:    make(map[netip.Addr]string),
	}
}

// UpdateNetMap refreshes MagicDNS host tables from the latest NetMap.
func (r *Resolver) UpdateNetMap(nm types.NetMap) {
	sfx := strings.Trim(strings.ToLower(strings.TrimSpace(nm.DNS.MagicDNSSuffix)), ".")
	if sfx == "" {
		sfx = "ack.internal"
	}

	byName := make(map[string]hostRecord, len(nm.Peers)*2+2)
	byIP := make(map[netip.Addr]string, len(nm.Peers)*2+2)

	addNode := func(n types.PeerNode) {
		short := strings.ToLower(strings.TrimSpace(n.Name))
		if short == "" {
			return
		}
		fqdnNoDot := short + "." + sfx
		fqdnDot := fqdnNoDot + "."
		rec := hostRecord{
			fqdn: fqdnDot,
			ipv4: n.IPv4,
			ipv6: n.IPv6,
		}
		// Only register server-assigned unique Node.Name (never untrusted self-reported Hostname),
		// and refuse overwriting existing entries as defense-in-depth.
		if _, exists := byName[short]; !exists {
			byName[short] = rec
		}
		if _, exists := byName[fqdnNoDot]; !exists {
			byName[fqdnNoDot] = rec
		}
		if n.IPv4.IsValid() {
			byIP[n.IPv4] = fqdnDot
		}
		if n.IPv6.IsValid() {
			byIP[n.IPv6] = fqdnDot
		}
	}

	addNode(nm.Self)
	for _, p := range nm.Peers {
		addNode(p)
	}

	r.mu.Lock()
	r.enabled = nm.DNS.EnableMagicDNS
	r.suffix = sfx
	r.nameservers = append([]string(nil), nm.DNS.Nameservers...)
	r.byName = byName
	r.byIP = byIP
	r.mu.Unlock()
}

// LookupHost resolves a node name or FQDN directly for CLI (`acktier dns lookup`) and LocalAPI.
func (r *Resolver) LookupHost(name string) (ipv4, ipv6 netip.Addr, fqdn string, ok bool) {
	key := strings.Trim(strings.ToLower(strings.TrimSpace(name)), ".")
	r.mu.RLock()
	rec, exists := r.byName[key]
	r.mu.RUnlock()
	if !exists {
		return netip.Addr{}, netip.Addr{}, "", false
	}
	return rec.ipv4, rec.ipv6, strings.TrimSuffix(rec.fqdn, "."), true
}

// TryHandleTUNPacket intercepts outbound L3 packets addressed to 100.100.100.100 / fd7a:115c:a1e0::53
// and returns the crafted L3 response packet to inject directly back into the local TUN!
func (r *Resolver) TryHandleTUNPacket(raw []byte) (replyL3 []byte, handled bool) {
	pkt, err := pktutil.Parse(raw)
	if err != nil {
		return nil, false
	}
	if pkt.DstIP != MagicDNSIPv4 && pkt.DstIP != MagicDNSIPv6 {
		return nil, false
	}

	// Support `ping 100.100.100.100`
	if pkt.Proto == pktutil.ProtoICMPv4 || pkt.Proto == pktutil.ProtoICMPv6 {
		if echoReply, ok := pktutil.BuildICMPEchoReply(pkt); ok {
			return echoReply, true
		}
		return nil, true
	}

	// Intercept UDP/53 DNS queries
	if pkt.Proto == pktutil.ProtoUDP && pkt.DstPort == 53 {
		respWire, err := r.HandleDNSQuery(pkt.Payload)
		if err != nil || len(respWire) == 0 {
			return nil, true
		}
		return pktutil.BuildUDPPacket(pkt.DstIP, pkt.SrcIP, 53, pkt.SrcPort, respWire), true
	}

	return nil, true
}

// HandleDNSQuery parses a wire-format DNS query and builds an authoritative MagicDNS response (or forwards upstream).
func (r *Resolver) HandleDNSQuery(queryBytes []byte) ([]byte, error) {
	var parser dnsmessage.Parser
	hdr, err := parser.Start(queryBytes)
	if err != nil {
		return nil, err
	}
	q, err := parser.Question()
	if err != nil {
		return nil, err
	}

	qNameLower := strings.TrimSuffix(strings.ToLower(q.Name.String()), ".")

	r.mu.RLock()
	enabled := r.enabled
	sfx := r.suffix
	rec, foundHost := r.byName[qNameLower]
	upstreams := append([]string(nil), r.nameservers...)
	var ptrTarget string
	isPTR := q.Type == dnsmessage.TypePTR
	if isPTR {
		if ip, ok := parseReverseArpaIPv4(qNameLower); ok {
			ptrTarget = r.byIP[ip]
		}
	}
	r.mu.RUnlock()

	if enabled {
		if isPTR && ptrTarget != "" {
			return buildPTRResponse(hdr.ID, q, ptrTarget)
		}
		if foundHost {
			return buildHostResponse(hdr.ID, q, rec)
		}
		// Authoritative NXDOMAIN for unknown names inside our MagicDNS suffix or single-label names
		if !strings.Contains(qNameLower, ".") || strings.HasSuffix(qNameLower, "."+sfx) {
			return buildEmptyResponse(hdr.ID, q, dnsmessage.RCodeNameError)
		}
	}

	// Forward external domain queries to configured upstream nameservers if available
	for _, ns := range upstreams {
		if !strings.Contains(ns, ":") {
			ns = net.JoinHostPort(ns, "53")
		}
		conn, err := net.DialTimeout("udp", ns, 1500*time.Millisecond)
		if err != nil {
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
		_, wErr := conn.Write(queryBytes)
		if wErr == nil {
			buf := make([]byte, 4096)
			if n, rErr := conn.Read(buf); rErr == nil && n > 0 {
				_ = conn.Close()
				return buf[:n], nil
			}
		}
		_ = conn.Close()
	}

	return buildEmptyResponse(hdr.ID, q, dnsmessage.RCodeNameError)
}

func buildHostResponse(id uint16, q dnsmessage.Question, rec hostRecord) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 id,
		Response:           true,
		Authoritative:      true,
		RecursionAvailable: true,
		RCode:              dnsmessage.RCodeSuccess,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	resHdr := dnsmessage.ResourceHeader{
		Name:  q.Name,
		Class: dnsmessage.ClassINET,
		TTL:   60,
	}
	switch q.Type {
	case dnsmessage.TypeA:
		if rec.ipv4.IsValid() {
			resHdr.Type = dnsmessage.TypeA
			_ = b.AResource(resHdr, dnsmessage.AResource{A: rec.ipv4.As4()})
		}
	case dnsmessage.TypeAAAA:
		if rec.ipv6.IsValid() {
			resHdr.Type = dnsmessage.TypeAAAA
			_ = b.AAAAResource(resHdr, dnsmessage.AAAAResource{AAAA: rec.ipv6.As16()})
		}
	}
	return b.Finish()
}

func buildPTRResponse(id uint16, q dnsmessage.Question, ptrFQDN string) ([]byte, error) {
	targetName, err := dnsmessage.NewName(ptrFQDN)
	if err != nil {
		return nil, fmt.Errorf("invalid ptr target %q: %w", ptrFQDN, err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 id,
		Response:           true,
		Authoritative:      true,
		RecursionAvailable: true,
		RCode:              dnsmessage.RCodeSuccess,
	})
	_ = b.StartQuestions()
	_ = b.Question(q)
	_ = b.StartAnswers()
	_ = b.PTRResource(dnsmessage.ResourceHeader{
		Name:  q.Name,
		Type:  dnsmessage.TypePTR,
		Class: dnsmessage.ClassINET,
		TTL:   60,
	}, dnsmessage.PTRResource{PTR: targetName})
	return b.Finish()
}

func buildEmptyResponse(id uint16, q dnsmessage.Question, rcode dnsmessage.RCode) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 id,
		Response:           true,
		Authoritative:      true,
		RecursionAvailable: true,
		RCode:              rcode,
	})
	_ = b.StartQuestions()
	_ = b.Question(q)
	return b.Finish()
}

func parseReverseArpaIPv4(qNameLower string) (netip.Addr, bool) {
	const sfx = ".in-addr.arpa"
	if !strings.HasSuffix(qNameLower, sfx) {
		return netip.Addr{}, false
	}
	parts := strings.Split(strings.TrimSuffix(qNameLower, sfx), ".")
	if len(parts) != 4 {
		return netip.Addr{}, false
	}
	ipStr := fmt.Sprintf("%s.%s.%s.%s", parts[3], parts[2], parts[1], parts[0])
	ip, err := netip.ParseAddr(ipStr)
	return ip, err == nil
}

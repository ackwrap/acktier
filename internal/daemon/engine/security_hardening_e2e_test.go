package engine_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ackwrap/acktier/internal/daemon/crypto"
	"github.com/ackwrap/acktier/internal/daemon/engine"
	"github.com/ackwrap/acktier/internal/daemon/localapi"
	"github.com/ackwrap/acktier/internal/daemon/pktutil"
	"github.com/ackwrap/acktier/internal/daemon/state"
	"github.com/ackwrap/acktier/internal/daemon/tun"
	"github.com/ackwrap/acktier/internal/server/control"
	"github.com/ackwrap/acktier/internal/server/store"
	"github.com/ackwrap/acktier/pkg/client"
	"github.com/ackwrap/acktier/pkg/protocol"
	"github.com/ackwrap/acktier/pkg/types"
)

// 1. Concurrent HandshakeAck Nonce-Reuse Prevention & Unauthenticated Probe/Punch Rejection
func TestSecurity_ConcurrentHandshakeAckNoNonceReuse_And_UnauthProbesBlocked(t *testing.T) {
	privA, _ := types.GeneratePrivateKey()
	privB, _ := types.GeneratePrivateKey()
	mgrA := crypto.NewManager(privA)
	mgrB := crypto.NewManager(privB)
	mgrA.SetAuthorizedPeers([]types.PublicKey{privB.Public()})
	mgrB.SetAuthorizedPeers([]types.PublicKey{privA.Public()})

	initPkt, err := mgrA.InitiateHandshake(privB.Public())
	if err != nil {
		t.Fatalf("InitiateHandshake: %v", err)
	}
	_, ackPkt, _, err := mgrB.HandleHandshakeInit(initPkt)
	if err != nil {
		t.Fatalf("HandleHandshakeInit: %v", err)
	}

	// Hammer HandleHandshakeAck concurrently across 16 goroutines while sealing packets in parallel!
	var ackWins atomic.Int32
	var wg sync.WaitGroup
	wireCh := make(chan []byte, 256)

	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := mgrA.HandleHandshakeAck(ackPkt); err == nil {
				ackWins.Add(1)
			}
			for i := 0; i < 8; i++ {
				if w, sErr := mgrA.SealPacket(privB.Public(), []byte("01234567890123456789")); sErr == nil {
					wireCh <- w
				}
			}
		}()
	}
	wg.Wait()
	close(wireCh)

	if ackWins.Load() != 1 {
		t.Fatalf("expected pending handshake to be consumed AT MOST ONCE, got %d successful HandleHandshakeAck calls!", ackWins.Load())
	}

	seenCounters := make(map[uint64]bool)
	for w := range wireCh {
		_, ctr, _, err := protocol.DecodeDataPacket(w)
		if err != nil {
			t.Fatalf("DecodeDataPacket: %v", err)
		}
		if seenCounters[ctr] {
			t.Fatalf("CRITICAL AES-GCM NONCE REUSE DETECTED: duplicate packet counter %d!", ctr)
		}
		seenCounters[ctr] = true
	}
	if len(seenCounters) == 0 {
		t.Fatalf("expected encrypted packets after handshake ack")
	}

	// Verify Engine silently drops unauthenticated Ping, Pong, and direct/unauthenticated PunchCoord!
	stSrv, _ := store.NewFileStore("")
	pak, _ := stSrv.CreatePreAuthKey("k", true, false, nil, time.Hour)
	ctrl := control.NewServer(control.Config{AdminToken: "adm", PublicHost: "10.0.0.1", RelayAddr: "10.0.0.1:8080"}, stSrv)
	httpCli := &http.Client{Transport: &memRoundTripper{handler: ctrl.Handler()}}
	relayDial := makeRelayDialer(ctrl.Relay())
	udpSw := newMemUDPSwitch()

	st1, _ := state.LoadOrCreate("")
	eng1, _ := engine.New(engine.Options{
		State:      st1,
		TUN:        tun.NewMemoryDevice("ack0", 1420),
		UDPConn:    udpSw.Listen("198.51.100.10:51820"),
		HTTPClient: httpCli,
		RelayDial:  relayDial,
	})
	defer eng1.Close()

	st2, _ := state.LoadOrCreate("")
	eng2, _ := engine.New(engine.Options{
		State:      st2,
		TUN:        tun.NewMemoryDevice("ack0", 1420),
		UDPConn:    udpSw.Listen("198.51.100.20:51820"),
		HTTPClient: httpCli,
		RelayDial:  relayDial,
	})
	defer eng2.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = eng1.Up(ctx, engine.UpRequest{ServerURL: "http://acktier.test", AuthKey: pak.Key, Hostname: "n1"})
	_, _ = eng2.Up(ctx, engine.UpRequest{ServerURL: "http://acktier.test", AuthKey: pak.Key, Hostname: "n2"})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(eng1.Status().Peers) == 0 {
		time.Sleep(20 * time.Millisecond)
	}

	// Attacker binds 203.0.113.99:6666 and sends forged unauthenticated Ping & Pong impersonating Node 2's NodeKey!
	evilConn := udpSw.Listen("203.0.113.99:6666")
	defer evilConn.Close()
	peer2Pub := st2.Get().NodeKey.Public()

	forgedPing := protocol.EncodeProbePacket(protocol.PacketPing, peer2Pub, 9999, time.Now().UnixNano(), "")
	forgedPong := protocol.EncodeProbePacket(protocol.PacketPong, peer2Pub, 1, time.Now().UnixNano(), "198.51.100.10:51820")
	targetAddr, _ := net.ResolveUDPAddr("udp", "198.51.100.10:51820")
	_, _ = evilConn.WriteTo(forgedPing, targetAddr)
	_, _ = evilConn.WriteTo(forgedPong, targetAddr)
	time.Sleep(80 * time.Millisecond)

	// Verify: (a) zero amplification response sent to evilConn, and (b) DirectAddr was NOT hijacked to 203.0.113.99:6666!
	select {
	case dg := <-evilConn.rxCh:
		t.Fatalf("amplification vulnerability: node replied (%d bytes) to unauthenticated Ping from %s!", len(dg.data), dg.from)
	default:
	}
	for _, p := range eng1.Status().Peers {
		if strings.Contains(p.DirectAddr, "203.0.113.99") {
			t.Fatalf("path hijack vulnerability: unauthenticated probe mutated DirectAddr to %s!", p.DirectAddr)
		}
	}
}

// 2. Approved Exit Node Source-IP Spoofing Prevention (Overlay IP Spoofing + Unsolicited External Flow)
func TestSecurity_ExitNodeSourceIPSpoofingBlocked(t *testing.T) {
	stSrv, _ := store.NewFileStore("")
	pakTrusted, _ := stSrv.CreatePreAuthKey("trusted", false, false, []string{"tag:trusted"}, time.Hour)
	pakVictim, _ := stSrv.CreatePreAuthKey("victim", false, false, []string{"tag:victim"}, time.Hour)
	pakEvilExit, _ := stSrv.CreatePreAuthKey("exit", false, false, []string{"tag:untrusted-exit"}, time.Hour)

	ctrl := control.NewServer(control.Config{AdminToken: "adm", PublicHost: "10.0.0.1", RelayAddr: "10.0.0.1:8080"}, stSrv)
	httpCli := &http.Client{Transport: &memRoundTripper{handler: ctrl.Handler()}}
	relayDial := makeRelayDialer(ctrl.Relay())
	udpSw := newMemUDPSwitch()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	// Node 1: Victim (`100.64.0.1`)
	stVictim, _ := state.LoadOrCreate("")
	tunVictim := tun.NewMemoryDevice("ack0", 1420)
	engVictim, _ := engine.New(engine.Options{State: stVictim, TUN: tunVictim, UDPConn: udpSw.Listen("198.51.100.1:51820"), HTTPClient: httpCli, RelayDial: relayDial})
	defer engVictim.Close()
	nmVictim, _ := engVictim.Up(ctx, engine.UpRequest{ServerURL: "http://acktier.test", AuthKey: pakVictim.Key, Hostname: "victim"})

	// Node 2: Trusted Peer (`100.64.0.2`)
	stTrusted, _ := state.LoadOrCreate("")
	tunTrusted := tun.NewMemoryDevice("ack0", 1420)
	engTrusted, _ := engine.New(engine.Options{State: stTrusted, TUN: tunTrusted, UDPConn: udpSw.Listen("198.51.100.2:51820"), HTTPClient: httpCli, RelayDial: relayDial})
	defer engTrusted.Close()
	nmTrusted, _ := engTrusted.Up(ctx, engine.UpRequest{ServerURL: "http://acktier.test", AuthKey: pakTrusted.Key, Hostname: "trusted"})

	// Node 3: Approved Exit Node (`100.64.0.3`, approved `0.0.0.0/0` & `::/0`), with direct access to its TUN to inject spoofed packets!
	stEvil, _ := state.LoadOrCreate("")
	tunEvil := tun.NewMemoryDevice("ack0", 1420)
	engEvil, _ := engine.New(engine.Options{State: stEvil, TUN: tunEvil, UDPConn: udpSw.Listen("198.51.100.3:51820"), HTTPClient: httpCli, RelayDial: relayDial})
	defer engEvil.Close()
	_, _ = engEvil.Up(ctx, engine.UpRequest{
		ServerURL:        "http://acktier.test",
		AuthKey:          pakEvilExit.Key,
		Hostname:         "evil-exit",
		AdvertisedRoutes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
	})

	admin := client.NewAdminClient("http://acktier.test", "adm", httpCli)
	if _, err := admin.ApproveRoutes(ctx, 3, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}); err != nil {
		t.Fatalf("ApproveRoutes: %v", err)
	}
	// Configure ACL: ONLY `tag:trusted` (100.64.0.2) may reach `tag:victim:22`!
	if _, err := admin.SetACL(ctx, types.ACLPolicy{
		ACLs: []types.ACLGrantEntry{
			{Action: "accept", Src: []string{"tag:trusted"}, Proto: "tcp", Dst: []string{"tag:victim:22"}},
			{Action: "accept", Src: []string{"tag:victim"}, Proto: "tcp", Dst: []string{"autogroup:internet:443"}},
		},
	}); err != nil {
		t.Fatalf("SetACL: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if engVictim.Status().ACLActiveRules > 0 && len(engVictim.Status().Peers) == 2 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	// Establish legitimate E2EE session between EvilExit and Victim by crafting raw encrypted wire packet
	// using a standalone crypto.Manager holding stEvil's NodeKey? No, tunEvil has outbound ACL, so let's build a
	// second raw crypto.Manager with EvilExit's exact NodeKey to simulate a fully compromised/malicious Exit Node binary
	// that bypasses its OWN local outbound filter!
	engEvil.Close() // Free 198.51.100.3:51820 so our malicious node binary takes over EvilExit's socket & keys!
	evilRawUDP := udpSw.Listen("198.51.100.3:51820")
	defer evilRawUDP.Close()
	evilCrypto := crypto.NewManager(stEvil.Get().NodeKey)
	victimPub := stVictim.Get().NodeKey.Public()
	evilCrypto.SetAuthorizedPeers([]types.PublicKey{victimPub})

	victimUDPAddr, _ := net.ResolveUDPAddr("udp", "198.51.100.1:51820")
	hsInit, _ := evilCrypto.InitiateHandshake(victimPub)
	_, _ = evilRawUDP.WriteTo(hsInit, victimUDPAddr)

	// Read HandshakeAck from Victim
	hsDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(hsDeadline) {
		select {
		case dg := <-evilRawUDP.rxCh:
			pType, _, _, _ := protocol.ParseHeader(dg.data)
			if pType == protocol.PacketHandshakeAck {
				_, _, _ = evilCrypto.HandleHandshakeAck(dg.data)
				goto handshakeEstablished
			}
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatalf("compromised exit node failed to complete E2EE handshake with victim")

handshakeEstablished:
	// Attack A: Victim has NOT selected evil-exit. Compromised Exit Node sends a packet spoofing Trusted Peer's IP (100.64.0.2 -> 100.64.0.1:22)!
	spoofTrusted := pktutil.BuildTCPPacket(nmTrusted.Self.IPv4, nmVictim.Self.IPv4, 55555, 22, 1, 0, pktutil.TCPFlagSYN, 65535, []byte("SSH-2.0-EVIL"))
	wireA, _ := evilCrypto.SealPacket(victimPub, spoofTrusted)
	_, _ = evilRawUDP.WriteTo(wireA, victimUDPAddr)

	// Attack B: Compromised Exit Node sends unsolicited external packet (8.8.8.8:443 -> 100.64.0.1:50000) without Victim selecting Exit Node!
	spoofExt := pktutil.BuildTCPPacket(netip.MustParseAddr("8.8.8.8"), nmVictim.Self.IPv4, 443, 50000, 10, 20, pktutil.TCPFlagSYN|pktutil.TCPFlagACK, 65535, []byte("unsolicited"))
	wireB, _ := evilCrypto.SealPacket(victimPub, spoofExt)
	_, _ = evilRawUDP.WriteTo(wireB, victimUDPAddr)

	// Attack C: Now Victim DOES select `evil-exit` as its active Exit Node!
	// Compromised Exit Node AGAIN tries to spoof Trusted Peer (`100.64.0.2`) AND tries an unsolicited external IP (`1.1.1.1:443`)!
	if err := engVictim.SetExitNode("evil-exit"); err != nil {
		t.Fatalf("SetExitNode: %v", err)
	}
	wireC1, _ := evilCrypto.SealPacket(victimPub, spoofTrusted)
	_, _ = evilRawUDP.WriteTo(wireC1, victimUDPAddr)

	spoofUnsolicitedFlow := pktutil.BuildTCPPacket(netip.MustParseAddr("1.1.1.1"), nmVictim.Self.IPv4, 443, 60000, 99, 99, pktutil.TCPFlagPSH|pktutil.TCPFlagACK, 65535, []byte("inject"))
	wireC2, _ := evilCrypto.SealPacket(victimPub, spoofUnsolicitedFlow)
	_, _ = evilRawUDP.WriteTo(wireC2, victimUDPAddr)

	time.Sleep(120 * time.Millisecond)
	select {
	case leaked := <-tunVictim.ReceiveInbound():
		p, _ := pktutil.Parse(leaked)
		t.Fatalf("CRITICAL SOURCE-IP SPOOFING BYPASS: Victim accepted packet from compromised exit node: %+v", p)
	default:
	}
}

// 3. LocalAPI Auth, Origin-Scoped Token Isolation, and Exit Gateway Loopback/IMDS SSRF Block
func TestSecurity_LocalAPIAuth_OriginTokenIsolation_And_GatewaySSRFBlocked(t *testing.T) {
	tmp := t.TempDir()
	stNode, err := state.LoadOrCreate(filepath.Join(tmp, "node-state.json"))
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	var dialedAddrs sync.Map
	gwDial := func(ctx context.Context, network, address string) (net.Conn, error) {
		dialedAddrs.Store(address, true)
		return nil, errors.New("refused")
	}

	tunNode := tun.NewMemoryDevice("ack0", 1420)
	engNode, err := engine.New(engine.Options{
		State:          stNode,
		TUN:            tunNode,
		LocalAPIAddr:   "127.0.0.1:41920",
		GatewayTCPDial: gwDial,
	})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	defer engNode.Close()

	// Part A: LocalAPI rejects unauthenticated callers AND rejects browser Origin headers even with valid token!
	apiHandler := localapi.NewServer(engNode, "").Handler()

	unauthReq := httptest.NewRequest(http.MethodGet, "/local/v1/status", nil)
	unauthRec := httptest.NewRecorder()
	apiHandler.ServeHTTP(unauthRec, unauthReq)
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized on LocalAPI without token, got %d", unauthRec.Code)
	}

	csrfReq := httptest.NewRequest(http.MethodPost, "/local/v1/down", bytes.NewReader([]byte(`{}`)))
	csrfReq.Header.Set("Authorization", "Bearer "+engNode.LocalAPIToken())
	csrfReq.Header.Set("Origin", "http://malicious.site")
	csrfRec := httptest.NewRecorder()
	apiHandler.ServeHTTP(csrfRec, csrfReq)
	if csrfRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden on LocalAPI request with browser Origin header, got %d", csrfRec.Code)
	}

	authReq := httptest.NewRequest(http.MethodGet, "/local/v1/status", nil)
	authReq.Header.Set("Authorization", "Bearer "+engNode.LocalAPIToken())
	authRec := httptest.NewRecorder()
	apiHandler.ServeHTTP(authRec, authReq)
	if authRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK with valid LocalAPIToken, got %d", authRec.Code)
	}

	// Part B: Control Server Origin Isolation — switching ServerURL MUST NOT leak Server 1's NodeToken to Server 2!
	stSrv1, _ := store.NewFileStore("")
	pak1, _ := stSrv1.CreatePreAuthKey("s1", true, false, nil, time.Hour)
	srv1 := control.NewServer(control.Config{AdminToken: "a1", PublicHost: "10.1.0.1"}, stSrv1)

	stSrv2, _ := store.NewFileStore("")
	pak2, _ := stSrv2.CreatePreAuthKey("s2", true, false, nil, time.Hour)
	srv2 := control.NewServer(control.Config{AdminToken: "a2", PublicHost: "10.2.0.1"}, stSrv2)

	var srv2SawAuthHeader atomic.Value
	srv2SawAuthHeader.Store("")
	muxRouter := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(r.Host, "ctrl-two.test") {
			if r.URL.Path == "/api/v1/node/register" {
				srv2SawAuthHeader.Store(r.Header.Get("Authorization"))
			}
			srv2.Handler().ServeHTTP(w, r)
			return
		}
		srv1.Handler().ServeHTTP(w, r)
	})

	multiHTTP := &http.Client{Transport: &memRoundTripper{handler: muxRouter}}
	udpSw := newMemUDPSwitch()
	engIso, _ := engine.New(engine.Options{
		State:          stNode,
		TUN:            tun.NewMemoryDevice("ack0", 1420),
		UDPConn:        udpSw.Listen("172.16.0.10:51820"),
		HTTPClient:     multiHTTP,
		LocalAPIAddr:   "127.0.0.1:41920",
		GatewayTCPDial: gwDial,
	})
	defer engIso.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	if _, err := engIso.Up(ctx, engine.UpRequest{ServerURL: "http://ctrl-one.test", AuthKey: pak1.Key, Hostname: "roamer"}); err != nil {
		t.Fatalf("Up on ctrl-one: %v", err)
	}
	tok1 := stNode.TokenForServer("http://ctrl-one.test")
	if tok1 == "" {
		t.Fatalf("expected saved token for ctrl-one.test")
	}

	// Switch to ctrl-two.test!
	if _, err := engIso.Up(ctx, engine.UpRequest{ServerURL: "http://ctrl-two.test", AuthKey: pak2.Key, Hostname: "roamer", AdvertisedRoutes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}); err != nil {
		t.Fatalf("Up on ctrl-two: %v", err)
	}
	leakedHdr := srv2SawAuthHeader.Load().(string)
	if leakedHdr != "" {
		t.Fatalf("CRITICAL TOKEN LEAK: switching ControlURL sent Authorization %q from old server to new server!", leakedHdr)
	}

	// Part C: Gateway SSRF Protection — remote peer tries to dial 127.0.0.1:41920 (LocalAPI) and 169.254.169.254:80 (IMDS) via Exit Node!
	admin2 := client.NewAdminClient("http://ctrl-two.test", "a2", multiHTTP)
	_, _ = admin2.ApproveRoutes(ctx, 1, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})

	stCaller, _ := state.LoadOrCreate("")
	tunCaller := tun.NewMemoryDevice("ack0", 1420)
	engCaller, _ := engine.New(engine.Options{
		State:      stCaller,
		TUN:        tunCaller,
		UDPConn:    udpSw.Listen("172.16.0.20:51820"),
		HTTPClient: multiHTTP,
	})
	defer engCaller.Close()
	nmCaller, _ := engCaller.Up(ctx, engine.UpRequest{ServerURL: "http://ctrl-two.test", AuthKey: pak2.Key, Hostname: "caller", ExitNode: "roamer"})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(engCaller.Status().Peers) == 0 {
		time.Sleep(20 * time.Millisecond)
	}

	for _, forbiddenIP := range []string{"127.0.0.1", "169.254.169.254", "100.64.0.1"} {
		syn := pktutil.BuildTCPPacket(nmCaller.Self.IPv4, netip.MustParseAddr(forbiddenIP), 54000, 41920, 1, 0, pktutil.TCPFlagSYN, 65535, nil)
		_ = tunCaller.InjectOutbound(syn)
	}
	time.Sleep(120 * time.Millisecond)

	dialedAddrs.Range(func(key, _ any) bool {
		t.Fatalf("CRITICAL GATEWAY SSRF: Exit Node dialed forbidden host/metadata target %v!", key)
		return false
	})
}

// 4. IPv6 Extension Header Bypass Prevention, Live ACL Conntrack Revocation, Thorough Down(), and Verified TLS Relay
func TestSecurity_IPv6ExtHeaderACL_LiveRevocation_DownCleanup_And_VerifiedTLSRelay(t *testing.T) {
	// Part A: Craft IPv6 packets with extension headers against a TCP:22 drop + wildcard accept policy!
	src6 := netip.MustParseAddr("fd7a:115c:a1e0::1")
	dst6 := netip.MustParseAddr("fd7a:115c:a1e0::2")

	// Build inner TCP segment targeting port 22
	baseTCPv6 := pktutil.BuildTCPPacket(src6, dst6, 51000, 22, 100, 0, pktutil.TCPFlagSYN, 65535, nil)
	tcpSeg := baseTCPv6[40:]

	// Wrap TCP:22 inside an 8-byte IPv6 Destination Options Extension Header (NextHeader = 60 -> inner NextHeader = 6 TCP)
	extHdr := []byte{pktutil.ProtoTCP, 0, 0, 0, 0, 0, 0, 0} // 8 bytes total ((0+1)*8)
	ipv6WithDestOpts := make([]byte, 40+len(extHdr)+len(tcpSeg))
	copy(ipv6WithDestOpts[:40], baseTCPv6[:40])
	binary.BigEndian.PutUint16(ipv6WithDestOpts[4:6], uint16(len(extHdr)+len(tcpSeg)))
	ipv6WithDestOpts[6] = pktutil.ProtoIPv6Dest // NextHeader = 60!
	copy(ipv6WithDestOpts[40:48], extHdr)
	copy(ipv6WithDestOpts[48:], tcpSeg)

	parsed, err := pktutil.Parse(ipv6WithDestOpts)
	if err != nil || parsed.Proto != pktutil.ProtoTCP || parsed.DstPort != 22 {
		t.Fatalf("expected IPv6 Destination Options header to unwrap to TCP:22, got err=%v proto=%d port=%d", err, parsed.Proto, parsed.DstPort)
	}

	// Wrap inside an IPv6 Fragment Header (NextHeader = 44) -> MUST default-reject!
	fragHdr := []byte{pktutil.ProtoTCP, 0, 0, 1, 0, 0, 0, 1}
	ipv6Frag := make([]byte, 40+len(fragHdr)+len(tcpSeg))
	copy(ipv6Frag[:40], baseTCPv6[:40])
	binary.BigEndian.PutUint16(ipv6Frag[4:6], uint16(len(fragHdr)+len(tcpSeg)))
	ipv6Frag[6] = pktutil.ProtoIPv6Frag
	copy(ipv6Frag[40:48], fragHdr)
	copy(ipv6Frag[48:], tcpSeg)
	if _, err := pktutil.Parse(ipv6Frag); err == nil {
		t.Fatalf("expected IPv6 Fragment header packet to be rejected by default")
	}

	// Part B: End-to-End TLS-Verified Control Plane + TLS-Verified Center Relay + Live ACL Revocation + Down() Session Wipe!
	tmp := t.TempDir()
	caPEM, srvTLS, rogueTLS := generateTestPKI(t, "ctrl.acktier.internal")
	caFile := filepath.Join(tmp, "root-ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}

	stSrv, _ := store.NewFileStore("")
	pak, _ := stSrv.CreatePreAuthKey("tls", true, false, []string{"tag:node"}, time.Hour)
	ctrl := control.NewServer(control.Config{
		AdminToken: "adm_tls",
		PublicHost: "ctrl.acktier.internal",
		RelayAddr:  "ctrl.acktier.internal:8443",
		UseTLS:     true,
	}, stSrv)

	// TLS alerts and HTTP hijacking both rely on socket deadline semantics.
	// Use in-process loopback sockets rather than an unbuffered or mock pipe.
	serveTLS := func(activeTLS *tls.Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		httpSrv := &http.Server{Handler: ctrl.Handler(), ReadHeaderTimeout: 2 * time.Second}
		go func() { _ = httpSrv.Serve(tls.NewListener(ln, activeTLS)) }()
		t.Cleanup(func() { _ = httpSrv.Close(); _ = ln.Close() })
		return func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp4", ln.Addr().String())
		}
	}

	validDial := serveTLS(srvTLS)
	rogueDial := serveTLS(rogueTLS)

	rootPool := x509.NewCertPool()
	rootPool.AppendCertsFromPEM(caPEM)

	makeHTTPSClient := func(dial func(context.Context, string, string) (net.Conn, error)) *http.Client {
		return &http.Client{
			Transport: &http.Transport{
				DialContext:         dial,
				TLSHandshakeTimeout: 2 * time.Second,
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
					RootCAs:    rootPool,
				},
			},
		}
	}

	// 1. Verify Rogue untrusted TLS server is REJECTED by client certificate verification!
	stRogueTest, _ := state.LoadOrCreate("")
	engRogue, _ := engine.New(engine.Options{
		State:      stRogueTest,
		TUN:        tun.NewMemoryDevice("ack0", 1420),
		HTTPClient: makeHTTPSClient(rogueDial),
		RelayDial:  rogueDial,
		TLSCAFile:  caFile,
		DisableUDP: true,
	})
	defer engRogue.Close()
	badCtx, stopBad := context.WithTimeout(context.Background(), 2*time.Second)
	_, badErr := engRogue.Up(badCtx, engine.UpRequest{ServerURL: "https://ctrl.acktier.internal:8443", AuthKey: pak.Key, Hostname: "rogue-check"})
	stopBad()
	var untrusted x509.UnknownAuthorityError
	if !errors.As(badErr, &untrusted) {
		t.Fatalf("expected a certificate verification error from Control Plane, got %v", badErr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	// Also verify valid Control Plane + ROGUE Relay server is rejected by RelayClient TLS handshake!
	stRelayMITM, _ := state.LoadOrCreate("")
	engMITM, _ := engine.New(engine.Options{
		State:      stRelayMITM,
		TUN:        tun.NewMemoryDevice("ack0", 1420),
		HTTPClient: makeHTTPSClient(validDial),
		RelayDial:  rogueDial, // MITM on Center Relay port!
		TLSCAFile:  caFile,
		DisableUDP: true,
	})
	defer engMITM.Close()
	if _, err := engMITM.Up(ctx, engine.UpRequest{ServerURL: "https://ctrl.acktier.internal:8443", AuthKey: pak.Key, Hostname: "mitm-test"}); err != nil {
		t.Fatalf("expected trusted control server to connect: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	if engMITM.Status().RelayConnected {
		t.Fatalf("CRITICAL RELAY TLS BYPASS: RelayClient connected to untrusted TLS certificate!")
	}
	engMITM.Down()

	// 2. Now connect Node A & Node B over VALID verified HTTPS + TLS Center Relay (UDP disabled so 100% of traffic uses TLS Relay)!
	stA, _ := state.LoadOrCreate("")
	tunA := tun.NewMemoryDevice("ack0", 1420)
	engA, _ := engine.New(engine.Options{
		State:      stA,
		TUN:        tunA,
		HTTPClient: makeHTTPSClient(validDial),
		RelayDial:  validDial,
		TLSCAFile:  caFile,
		DisableUDP: true,
	})
	defer engA.Close()

	stB, _ := state.LoadOrCreate("")
	tunB := tun.NewMemoryDevice("ack0", 1420)
	engB, _ := engine.New(engine.Options{
		State:      stB,
		TUN:        tunB,
		HTTPClient: makeHTTPSClient(validDial),
		RelayDial:  validDial,
		TLSCAFile:  caFile,
		DisableUDP: true,
	})
	defer engB.Close()

	nmA, err := engA.Up(ctx, engine.UpRequest{ServerURL: "https://ctrl.acktier.internal:8443", AuthKey: pak.Key, Hostname: "tls-a"})
	if err != nil {
		t.Fatalf("engA Up over HTTPS: %v", err)
	}
	nmB, err := engB.Up(ctx, engine.UpRequest{ServerURL: "https://ctrl.acktier.internal:8443", AuthKey: pak.Key, Hostname: "tls-b"})
	if err != nil {
		t.Fatalf("engB Up over HTTPS: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if engA.Status().RelayConnected && engB.Status().RelayConnected && len(engA.Status().Peers) >= 2 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !engA.Status().RelayConnected || !engB.Status().RelayConnected {
		t.Fatalf("expected both nodes to connect to TLS-verified Center Relay")
	}

	// Set initial ACL allowing A -> B TCP:8080 (so conntrack records reverse B:8080 -> A:40000!)
	admin := client.NewAdminClient("https://ctrl.acktier.internal:8443", "adm_tls", makeHTTPSClient(validDial))
	_, err = admin.SetACL(ctx, types.ACLPolicy{
		ACLs: []types.ACLGrantEntry{
			{Action: "drop", Src: []string{"*"}, Proto: "tcp", Dst: []string{"*:22"}},
			{Action: "accept", Src: []string{"tag:node"}, Proto: "tcp", Dst: []string{"tag:node:8080"}},
		},
	})
	if err != nil {
		t.Fatalf("SetACL initial: %v", err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && (engA.Status().ACLActiveRules == 0 || engB.Status().ACLActiveRules == 0) {
		time.Sleep(20 * time.Millisecond)
	}

	// Establish flow A:40000 -> B:8080 and verify B's SYN-ACK return packet passes conntrack!
	syn8080 := pktutil.BuildTCPPacket(nmA.Self.IPv4, nmB.Self.IPv4, 40000, 8080, 1, 0, pktutil.TCPFlagSYN, 65535, nil)
	_ = tunA.InjectOutbound(syn8080)
	select {
	case <-tunB.ReceiveInbound():
	case <-ctx.Done():
		t.Fatalf("timeout waiting for A->B SYN over TLS relay")
	}
	synAck8080 := pktutil.BuildTCPPacket(nmB.Self.IPv4, nmA.Self.IPv4, 8080, 40000, 50, 2, pktutil.TCPFlagSYN|pktutil.TCPFlagACK, 65535, nil)
	_ = tunB.InjectOutbound(synAck8080)
	select {
	case <-tunA.ReceiveInbound():
	case <-ctx.Done():
		t.Fatalf("timeout waiting for B->A conntrack SYN-ACK")
	}

	// Now REVOKE port 8080 in ACL (only allow port 9090)! Conntrack for 8080 MUST be purged immediately!
	prevRev := engA.Status().Revision
	_, err = admin.SetACL(ctx, types.ACLPolicy{
		ACLs: []types.ACLGrantEntry{
			{Action: "accept", Src: []string{"tag:node"}, Proto: "tcp", Dst: []string{"tag:node:9090"}},
		},
	})
	if err != nil {
		t.Fatalf("SetACL revoke: %v", err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && (engA.Status().Revision <= prevRev || engB.Status().Revision <= prevRev) {
		time.Sleep(20 * time.Millisecond)
	}

	// B tries to send another packet on the previously-tracked 8080 -> 40000 flow: MUST be dropped!
	pshRevoked := pktutil.BuildTCPPacket(nmB.Self.IPv4, nmA.Self.IPv4, 8080, 40000, 51, 2, pktutil.TCPFlagPSH|pktutil.TCPFlagACK, 65535, []byte("after-revoke"))
	_ = tunB.InjectOutbound(pshRevoked)
	time.Sleep(100 * time.Millisecond)
	select {
	case leaked := <-tunA.ReceiveInbound():
		t.Fatalf("stale conntrack bypass: packet on revoked ACL flow still arrived (%d bytes)!", len(leaked))
	default:
	}

	// Token-only rekey revokes B's existing data-plane identity. Even without
	// a replacement key, live peers must stop authorizing it.
	rekey, err := admin.RekeyNode(ctx, nmB.Self.ID, types.PublicKey{}, types.PublicKey{})
	if err != nil || !rekey.Node.KeyRevoked {
		t.Fatalf("rekey did not withdraw the old node key: %v", err)
	}
	aStillSeesB := func() bool {
		for _, peer := range engA.Status().Peers {
			if peer.ID == nmB.Self.ID {
				return true
			}
		}
		return false
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && (engB.Status().State != "WaitingForControl" || aStillSeesB()) {
		time.Sleep(20 * time.Millisecond)
	}
	if aStillSeesB() {
		t.Fatal("active peer still sees the withdrawn key")
	}
	if got := engB.Status(); got.State != "WaitingForControl" || got.RelayConnected {
		t.Fatalf("revoked node remained active: state=%s relay=%t", got.State, got.RelayConnected)
	}

	// An explicit Down() also tears down the remaining session.
	engA.Down()
	if engA.Status().State != "Stopped" || engA.Status().RelayConnected || len(engA.Status().Peers) != 0 {
		t.Fatalf("expected Down() to clear RelayConnected and Peers, got %+v", engA.Status())
	}
}

func generateTestPKI(t *testing.T, dnsName string) (caPEM []byte, validServerTLS *tls.Config, rogueServerTLS *tls.Config) {
	t.Helper()
	makeCAAndLeaf := func() ([]byte, *tls.Config) {
		caPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		caTpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "AckTier Test Root CA"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caPriv.PublicKey, caPriv)
		if err != nil {
			t.Fatalf("create CA: %v", err)
		}
		caCert, _ := x509.ParseCertificate(caDER)

		leafPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		leafTpl := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: dnsName},
			DNSNames:     []string{dnsName},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafPriv.PublicKey, caPriv)
		if err != nil {
			t.Fatalf("create leaf: %v", err)
		}

		caBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
		tlsCert := tls.Certificate{
			Certificate: [][]byte{leafDER},
			PrivateKey:  leafPriv,
		}
		return caBlock, &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{tlsCert},
		}
	}

	caBytes, validCfg := makeCAAndLeaf()
	_, rogueCfg := makeCAAndLeaf() // Signed by an unrelated untrusted CA!
	return caBytes, validCfg, rogueCfg
}

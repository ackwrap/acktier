package engine_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/acktier/acktier/internal/daemon/dns"
	"github.com/acktier/acktier/internal/daemon/engine"
	"github.com/acktier/acktier/internal/daemon/pktutil"
	"github.com/acktier/acktier/internal/daemon/state"
	"github.com/acktier/acktier/internal/daemon/tun"
	"github.com/acktier/acktier/internal/server/control"
	"github.com/acktier/acktier/internal/server/store"
	"github.com/acktier/acktier/pkg/types"
)

func buildDNSQueryPacket(srcIP netip.Addr, qName string, qType dnsmessage.Type) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
	_ = b.StartQuestions()
	name, _ := dnsmessage.NewName(qName)
	_ = b.Question(dnsmessage.Question{Name: name, Type: qType, Class: dnsmessage.ClassINET})
	wire, _ := b.Finish()
	return pktutil.BuildUDPPacket(srcIP, dns.MagicDNSIPv4, 53000, 53, wire)
}

func TestPhase4MagicDNSStatefulACLSubnetRouterAndExitNode(t *testing.T) {
	tmp := t.TempDir()
	st, _ := store.NewFileStore(filepath.Join(tmp, "srv.json"))
	keyDev, _ := st.CreatePreAuthKey("dev", true, false, []string{"tag:dev"}, time.Hour)
	keyGW, _ := st.CreatePreAuthKey("gw", true, false, []string{"tag:gateway"}, time.Hour)

	ctrlSrv := control.NewServer(control.Config{
		AdminToken: "adm_secret",
		PublicHost: "10.0.0.1",
		RelayAddr:  "10.0.0.1:8080",
	}, st)
	httpCli := &http.Client{Transport: &memRoundTripper{handler: ctrlSrv.Handler()}}
	relayDial := makeRelayDialer(ctrlSrv.Relay())
	udpSw := newMemUDPSwitch()

	// Simulated internal corporate LAN server (192.168.50.10:8080) & public Internet host (93.184.216.34:80)
	// reachable ONLY from the Gateway node's host network!
	gwDialTCP := func(ctx context.Context, network, address string) (net.Conn, error) {
		switch address {
		case "192.168.50.10:8080":
			c, s := net.Pipe()
			go func() {
				defer s.Close()
				buf := make([]byte, 1024)
				n, err := s.Read(buf)
				if err == nil && n > 0 {
					_, _ = s.Write([]byte("LAN-HTTP-200:" + string(buf[:n])))
				}
			}()
			return c, nil
		case "93.184.216.34:80":
			c, s := net.Pipe()
			go func() {
				defer s.Close()
				buf := make([]byte, 1024)
				n, err := s.Read(buf)
				if err == nil && n > 0 {
					_, _ = s.Write([]byte("EXIT-INTERNET-200:" + string(buf[:n])))
				}
			}()
			return c, nil
		default:
			return nil, errors.New("connection refused")
		}
	}

	// 1. Bring up Client Node (tag:dev) & Gateway Node (tag:gateway, advertising 192.168.50.0/24 + Exit Node 0.0.0.0/0)
	stClient, _ := state.LoadOrCreate(filepath.Join(tmp, "client.json"))
	tunClient := tun.NewMemoryDevice("ack0", tun.DefaultMTU)
	engClient, _ := engine.New(engine.Options{
		State:      stClient,
		TUN:        tunClient,
		UDPConn:    udpSw.Listen("172.20.0.10:51820"),
		HTTPClient: httpCli,
		RelayDial:  relayDial,
	})
	defer engClient.Close()

	stGW, _ := state.LoadOrCreate(filepath.Join(tmp, "gw.json"))
	tunGW := tun.NewMemoryDevice("ack0", tun.DefaultMTU)
	engGW, _ := engine.New(engine.Options{
		State:          stGW,
		TUN:            tunGW,
		UDPConn:        udpSw.Listen("172.20.0.20:51820"),
		HTTPClient:     httpCli,
		RelayDial:      relayDial,
		GatewayTCPDial: gwDialTCP,
	})
	defer engGW.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	nmClient, err := engClient.Up(ctx, engine.UpRequest{
		ServerURL: "http://acktier.test",
		AuthKey:   keyDev.Key,
		Hostname:  "laptop-dev",
	})
	if err != nil {
		t.Fatalf("client Up: %v", err)
	}

	subnetCIDR := netip.MustParsePrefix("192.168.50.0/24")
	exitCIDR := netip.MustParsePrefix("0.0.0.0/0")
	nmGW, err := engGW.Up(ctx, engine.UpRequest{
		ServerURL:        "http://acktier.test",
		AuthKey:          keyGW.Key,
		Hostname:         "hq-gateway",
		AdvertisedRoutes: []netip.Prefix{subnetCIDR, exitCIDR},
	})
	if err != nil {
		t.Fatalf("gw Up: %v", err)
	}

	// Admin approves Gateway's Subnet Route (192.168.50.0/24) and Exit Node Route (0.0.0.0/0)!
	approveBody, _ := json.Marshal(map[string]any{"routes": []netip.Prefix{subnetCIDR, exitCIDR}})
	appReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://acktier.test/api/v1/admin/nodes/2/routes/approve", bytes.NewReader(approveBody))
	appReq.Header.Set("Authorization", "Bearer adm_secret")
	appResp, err := httpCli.Do(appReq)
	if err != nil || appResp.StatusCode != http.StatusOK {
		t.Fatalf("approve routes failed: err=%v", err)
	}
	_ = appResp.Body.Close()

	// Wait for live NetMap stream to push approved routes to laptop-dev
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		st := engClient.Status()
		if len(st.Peers) == 1 && len(st.Peers[0].AllowedIPs) >= 4 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	// =========================================================================
	// Test A: MagicDNS (100.100.100.100) L3 TUN Query for `hq-gateway.ack.internal.`
	// =========================================================================
	dnsReqPkt := buildDNSQueryPacket(nmClient.Self.IPv4, "hq-gateway.ack.internal.", dnsmessage.TypeA)
	_ = tunClient.InjectOutbound(dnsReqPkt)

	select {
	case dnsReplyRaw := <-tunClient.ReceiveInbound():
		parsedDNS, err := pktutil.Parse(dnsReplyRaw)
		if err != nil || parsedDNS.SrcIP != dns.MagicDNSIPv4 {
			t.Fatalf("expected MagicDNS reply from 100.100.100.100, got err=%v pkt=%+v", err, parsedDNS)
		}
		var dp dnsmessage.Parser
		if _, err := dp.Start(parsedDNS.Payload); err != nil {
			t.Fatalf("parse dns wire: %v", err)
		}
		_ = dp.SkipAllQuestions()
		ansHdr, err := dp.AnswerHeader()
		if err != nil || ansHdr.Type != dnsmessage.TypeA {
			t.Fatalf("expected TypeA answer, got %v", err)
		}
		aRec, _ := dp.AResource()
		resolvedIP := netip.AddrFrom4(aRec.A)
		if resolvedIP != nmGW.Self.IPv4 {
			t.Fatalf("MagicDNS resolved %s, expected %s", resolvedIP, nmGW.Self.IPv4)
		}
	case <-ctx.Done():
		t.Fatalf("timeout waiting for MagicDNS L3 response")
	}

	// =========================================================================
	// Test B: Zero-Trust Stateful ACL Enforcement!
	// Allow `tag:dev` -> `tag:gateway:8080` and `93.184.216.34:80` (TCP only),
	// BLOCK port 22 (SSH), and BLOCK unsolicited `tag:gateway` -> `tag:dev:9000`!
	// =========================================================================
	aclPol := types.ACLPolicy{
		ACLs: []types.ACLGrantEntry{
			{
				Action: "accept",
				Src:    []string{"tag:dev"},
				Proto:  "tcp",
				Dst:    []string{"tag:gateway:8080", "93.184.216.34:80"},
			},
		},
	}
	aclRaw, _ := json.Marshal(aclPol)
	aclReq, _ := http.NewRequestWithContext(ctx, http.MethodPut, "http://acktier.test/api/v1/admin/acl", bytes.NewReader(aclRaw))
	aclReq.Header.Set("Authorization", "Bearer adm_secret")
	aclResp, err := httpCli.Do(aclReq)
	if err != nil || aclResp.StatusCode != http.StatusOK {
		t.Fatalf("put ACL failed: err=%v", err)
	}
	_ = aclResp.Body.Close()

	// Wait until both nodes receive active ACL rules
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if engClient.Status().ACLActiveRules > 0 && engGW.Status().ACLActiveRules > 0 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	// 1) Forbidden port 22 packet from laptop-dev -> hq-gateway MUST be dropped by ACL!
	blockedSSH := pktutil.BuildTCPPacket(nmClient.Self.IPv4, nmGW.Self.IPv4, 41000, 22, 100, 0, pktutil.TCPFlagSYN, 65535, nil)
	_ = tunClient.InjectOutbound(blockedSSH)
	// 2) Unsolicited reverse TCP SYN from hq-gateway -> laptop-dev:9000 MUST also be dropped!
	blockedRev := pktutil.BuildTCPPacket(nmGW.Self.IPv4, nmClient.Self.IPv4, 42000, 9000, 200, 0, pktutil.TCPFlagSYN, 65535, nil)
	_ = tunGW.InjectOutbound(blockedRev)
	time.Sleep(80 * time.Millisecond)
	if engClient.Status().ACLDroppedOut == 0 || engGW.Status().ACLDroppedOut == 0 {
		t.Fatalf("expected forbidden TCP SYN packets to be dropped by Zero-Trust ACL (clientDropOut=%d gwDropOut=%d)",
			engClient.Status().ACLDroppedOut, engGW.Status().ACLDroppedOut)
	}

	// =========================================================================
	// Test C: Userspace Subnet Router (192.168.50.10:8080) Full TCP Handshake + Data!
	// Also proves Stateful Conntrack permits return SYN-ACK & PSH-ACK from 192.168.50.10:8080!
	// =========================================================================
	lanTarget := netip.MustParseAddr("192.168.50.10")
	clientTCPFlow := func(dstIP netip.Addr, srcPort, dstPort uint16, reqPayload string) string {
		t.Helper()
		var isn uint32 = 1000
		// Send TCP SYN
		synPkt := pktutil.BuildTCPPacket(nmClient.Self.IPv4, dstIP, srcPort, dstPort, isn, 0, pktutil.TCPFlagSYN, 65535, nil)
		_ = tunClient.InjectOutbound(synPkt)

		// Expect SYN-ACK from Userspace Gateway
		var serverSeq uint32
		for {
			select {
			case raw := <-tunClient.ReceiveInbound():
				p, err := pktutil.Parse(raw)
				if err == nil && p.SrcIP == dstIP && p.SrcPort == dstPort && (p.TCPFlags&pktutil.TCPFlagSYN) != 0 {
					serverSeq = p.SeqNum + 1
					goto gotSynAck
				}
			case <-ctx.Done():
				t.Fatalf("timeout waiting for TCP SYN-ACK from %s:%d", dstIP, dstPort)
			}
		}
	gotSynAck:
		// Send ACK + HTTP request payload
		pshPkt := pktutil.BuildTCPPacket(nmClient.Self.IPv4, dstIP, srcPort, dstPort, isn+1, serverSeq, pktutil.TCPFlagPSH|pktutil.TCPFlagACK, 65535, []byte(reqPayload))
		_ = tunClient.InjectOutbound(pshPkt)

		// Wait for PSH-ACK response data from target server
		for {
			select {
			case raw := <-tunClient.ReceiveInbound():
				p, err := pktutil.Parse(raw)
				if err == nil && p.SrcIP == dstIP && p.SrcPort == dstPort && len(p.Payload) > 0 {
					return string(p.Payload)
				}
			case <-ctx.Done():
				t.Fatalf("timeout waiting for TCP response payload from %s:%d", dstIP, dstPort)
			}
		}
	}

	subnetReply := clientTCPFlow(lanTarget, 50101, 8080, "GET /intranet")
	if subnetReply != "LAN-HTTP-200:GET /intranet" {
		t.Fatalf("unexpected Subnet Router TCP response: %q", subnetReply)
	}

	// =========================================================================
	// Test D: Global Exit Node (`SetExitNode("hq-gateway")`) Routing 93.184.216.34:80!
	// =========================================================================
	if err := engClient.SetExitNode("hq-gateway"); err != nil {
		t.Fatalf("SetExitNode hq-gateway failed: %v", err)
	}
	exitReply := clientTCPFlow(netip.MustParseAddr("93.184.216.34"), 50102, 80, "GET /world")
	if exitReply != "EXIT-INTERNET-200:GET /world" {
		t.Fatalf("unexpected Exit Node TCP response: %q", exitReply)
	}
}

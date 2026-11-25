package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/acktier/acktier/pkg/client"
	"github.com/acktier/acktier/pkg/types"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	apiBase := os.Getenv("ACKTIER_API")
	if apiBase == "" {
		apiBase = client.DefaultLocalAPIURL
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "up":
		runUp(apiBase, args)
	case "down":
		runDown(apiBase)
	case "status":
		runStatus(apiBase, args)
	case "mesh":
		runMesh(apiBase, args)
	case "netcheck":
		runNetCheck(apiBase, args)
	case "dns":
		runDNS(apiBase, args)
	case "exit-node":
		runExitNode(apiBase, args)
	case "ping":
		runPing(apiBase, args)
	case "key":
		runAdminKey(args)
	case "route":
		runAdminRoute(args)
	case "acl":
		runAdminACL(args)
	case "owner":
		runOwner(args)
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`AckTier CLI - Next-Gen Overlay Mesh Networking

Usage:
  acktier up --server <https-url> [--auth-key <key>] [--hostname <name>] [--relay-mode auto|on|off] [--advertise-routes <cidr,...>] [--advertise-exit-node] [--exit-node <peer>]
  acktier down
  acktier status [--json]
  acktier mesh [--json]
  acktier netcheck [--json]
  acktier dns <hostname>
  acktier exit-node <peer-name-or-none>
  acktier ping <peer-name-or-ip> [-c <count>]
  acktier key create --server <https-url> --admin-token <token> [--tls-ca <ca.pem>] [--reusable] [--label <name>]
  acktier route approve --server <https-url> --admin-token <token> [--tls-ca <ca.pem>] --node <id> --routes <cidr,...>
  acktier acl set --server <https-url> --admin-token <token> [--tls-ca <ca.pem>] --file <policy.json>
  acktier owner init|node-key|requests|sign|publish [flags]`)
}

func runUp(apiBase string, args []string) {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	apiFlag := fs.String("api", apiBase, "LocalAPI base URL")
	serverURL := fs.String("server", "", "AckTier Control Server URL (https:// required for non-loopback)")
	authKey := fs.String("auth-key", "", "PreAuthKey for new node registration")
	hostname := fs.String("hostname", "", "Desired node hostname")
	routesCSV := fs.String("advertise-routes", "", "Comma-separated subnet CIDRs to advertise")
	advExit := fs.Bool("advertise-exit-node", false, "Offer this node as a global Exit Node (0.0.0.0/0, ::/0)")
	exitNode := fs.String("exit-node", "", "Select peer name or IP as global Exit Node (or 'none')")
	relayMode := fs.String("relay-mode", "auto", "Peer relay mode: auto (public IP auto-enables) | on | off")
	maxRelayMbps := fs.Float64("relay-max-mbps", 0, "Optional transit relay bandwidth limit in Mbps")
	canRelay := fs.Bool("can-relay", false, "Force enable peer relay (alias for --relay-mode=on)")
	insecureHTTP := fs.Bool("insecure-http", false, "Allow plaintext HTTP/Relay to non-loopback server (lab testing only)")
	_ = fs.Parse(args)

	var routes []netip.Prefix
	if *routesCSV != "" {
		for _, part := range strings.Split(*routesCSV, ",") {
			pfx, err := netip.ParsePrefix(strings.TrimSpace(part))
			if err != nil {
				fatalf("invalid route CIDR %q: %v", part, err)
			}
			routes = append(routes, pfx)
		}
	}
	if *advExit {
		routes = append(routes, netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"))
	}

	dc := client.NewDaemonClient(*apiFlag, nil)
	nm, err := dc.Up(context.Background(), client.UpOptions{
		ServerURL:         *serverURL,
		AuthKey:           *authKey,
		Hostname:          *hostname,
		AdvertisedRoutes:  routes,
		ExitNode:          *exitNode,
		RelayMode:         types.RelayMode(*relayMode),
		MaxRelayMbps:      *maxRelayMbps,
		CanRelay:          *canRelay,
		AllowInsecureHTTP: *insecureHTTP,
	})
	if err != nil {
		fatalf("%v", err)
	}
	fmt.Printf("AckTier is UP!\n  Node Name : %s\n  IPv4      : %s\n  IPv6      : %s\n  Peers     : %d\n",
		nm.Self.Name, nm.Self.IPv4, nm.Self.IPv6, len(nm.Peers))
}

func runDown(apiBase string) {
	dc := client.NewDaemonClient(apiBase, nil)
	if err := dc.Down(context.Background()); err != nil {
		fatalf("%v", err)
	}
	fmt.Println("AckTier network disconnected (all sessions and flows cleared).")
}

func runStatus(apiBase string, args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	apiFlag := fs.String("api", apiBase, "LocalAPI base URL")
	asJSON := fs.Bool("json", false, "Output raw JSON")
	_ = fs.Parse(args)

	dc := client.NewDaemonClient(*apiFlag, nil)
	st, err := dc.Status(context.Background())
	if err != nil {
		fatalf("%v", err)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(st)
		return
	}

	fmt.Printf("State: %s | TUN: %s | NAT: %s | AutoRelay: %v (%s) | Relay Connected: %v\n",
		st.State, st.TUNName, st.NATType, st.CanRelay, st.RelayMode, st.RelayConnected)
	if st.IPv4 != "" {
		fmt.Printf("Self : %-15s %-20s (%s)\n\n", st.IPv4, st.SelfName, st.SelfNodeKey)
	}
	if len(st.Peers) == 0 {
		fmt.Println("No peers in network yet.")
		return
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "IPV4\tNAME\tOS\tSTATUS\tPATH\tRTT\tRX/TX")
	for _, p := range st.Peers {
		onlineStr := "offline"
		if p.Online {
			onlineStr = "online"
		}
		pathStr := p.ActivePath
		if p.DirectAddr != "" {
			pathStr = fmt.Sprintf("%s (%s)", p.ActivePath, p.DirectAddr)
		} else if p.MeshHops != "" {
			pathStr = fmt.Sprintf("%s (%s)", p.ActivePath, p.MeshHops)
		}
		rttStr := "-"
		if p.RTTMillis > 0 {
			rttStr = fmt.Sprintf("%.2fms", p.RTTMillis)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%dB / %dB\n",
			p.IPv4, p.Name, p.OS, onlineStr, pathStr, rttStr, p.RxBytes, p.TxBytes)
	}
	_ = tw.Flush()
}

func runMesh(apiBase string, args []string) {
	fs := flag.NewFlagSet("mesh", flag.ExitOnError)
	apiFlag := fs.String("api", apiBase, "LocalAPI base URL")
	asJSON := fs.Bool("json", false, "Output raw JSON")
	_ = fs.Parse(args)

	dc := client.NewDaemonClient(*apiFlag, nil)
	rep, err := dc.Mesh(context.Background())
	if err != nil {
		fatalf("%v", err)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		return
	}

	fmt.Printf("Peer Relay Enabled: %v | Forwarded: %d frames (%d bytes)\n\n",
		rep.CanRelay, rep.PeerRelayedFrames, rep.PeerRelayedBytes)
	if len(rep.Routes) == 0 {
		fmt.Println("No mesh routes computed yet.")
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "TARGET\tIPV4\tMODE\tNEXT HOP\tEST RTT\tHOP CHAIN")
	for _, r := range rep.Routes {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%.2fms\t%s\n",
			r.TargetName, r.TargetIPv4, r.Mode, r.NextHopName, r.EstRTTMillis, strings.Join(r.HopChain, " -> "))
	}
	_ = tw.Flush()
}

func runNetCheck(apiBase string, args []string) {
	fs := flag.NewFlagSet("netcheck", flag.ExitOnError)
	apiFlag := fs.String("api", apiBase, "LocalAPI base URL")
	asJSON := fs.Bool("json", false, "Output raw JSON")
	_ = fs.Parse(args)

	dc := client.NewDaemonClient(*apiFlag, nil)
	rep, err := dc.NetCheck(context.Background())
	if err != nil {
		fatalf("%v", err)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		return
	}

	fmt.Println("AckTier NetCheck Report")
	fmt.Println("------------------------------------------------")
	fmt.Printf("  NAT Type          : %s\n", rep.NAT.NATType)
	if rep.NAT.PublicUDPAddr != "" {
		fmt.Printf("  STUN Public UDP   : %s (RTT %.2f ms)\n", rep.NAT.PublicUDPAddr, rep.NAT.STUNLatencyMs)
	}
	if rep.NAT.AltPublicUDPAddr != "" {
		fmt.Printf("  STUN Alt UDP      : %s (Port Step %+d)\n", rep.NAT.AltPublicUDPAddr, rep.NAT.PortStep)
	}
	if rep.NAT.UPnPMappedUDP != "" || rep.NAT.UPnPMappedTCP != "" {
		fmt.Printf("  UPnP / NAT-PMP    : UDP=%s TCP=%s\n", rep.NAT.UPnPMappedUDP, rep.NAT.UPnPMappedTCP)
	}
	fmt.Printf("  Relay Connected   : %v\n", rep.RelayConnected)
	fmt.Printf("  Bound Transports  : %v\n", rep.LocalTransports)
	fmt.Printf("  Advertised Cand.  : %d endpoints\n", rep.CandidateCount)
}

func runPing(apiBase string, args []string) {
	fs := flag.NewFlagSet("ping", flag.ExitOnError)
	apiFlag := fs.String("api", apiBase, "LocalAPI base URL")
	count := fs.Int("c", 4, "Number of probes to send")
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fatalf("usage: acktier ping <peer-name-or-ip>")
	}
	target := fs.Arg(0)
	dc := client.NewDaemonClient(*apiFlag, nil)

	for i := 0; i < *count; i++ {
		res, err := dc.Ping(context.Background(), target, 3*time.Second)
		if err != nil {
			fmt.Printf("ping %s: %v\n", target, err)
		} else {
			fmt.Printf("pong from %s (%s) via %s [%s] time=%.2f ms\n",
				res.TargetName, res.TargetIP, res.Via, res.Endpoint, res.RTTMillis)
		}
		if i+1 < *count {
			time.Sleep(500 * time.Millisecond)
		}
	}
}

func runDNS(apiBase string, args []string) {
	if len(args) == 0 {
		fatalf("usage: acktier dns <hostname>")
	}
	dc := client.NewDaemonClient(apiBase, nil)
	res, err := dc.LookupDNS(context.Background(), args[0])
	if err != nil {
		fatalf("%v", err)
	}
	fmt.Printf("FQDN : %s\nIPv4 : %s\nIPv6 : %s\n", res.FQDN, res.IPv4, res.IPv6)
}

func runExitNode(apiBase string, args []string) {
	if len(args) == 0 {
		fatalf("usage: acktier exit-node <peer-name-or-none>")
	}
	dc := client.NewDaemonClient(apiBase, nil)
	if err := dc.SetExitNode(context.Background(), args[0]); err != nil {
		fatalf("%v", err)
	}
	fmt.Printf("Active Exit Node updated to: %s\n", args[0])
}

func buildAdminClient(serverURL, token, tlsCA string, insecureHTTP bool) *client.AdminClient {
	ac := client.NewAdminClient(serverURL, token, nil)
	if err := ac.ConfigureTLS(tlsCA, insecureHTTP); err != nil {
		fatalf("%v", err)
	}
	return ac
}

func runAdminKey(args []string) {
	if len(args) == 0 || args[0] != "create" {
		fatalf("usage: acktier key create --server <url> --admin-token <token> [--tls-ca <ca.pem>] [--reusable] [--label <name>]")
	}
	fs := flag.NewFlagSet("key create", flag.ExitOnError)
	serverURL := fs.String("server", "http://127.0.0.1:8080", "Control Server URL")
	token := fs.String("admin-token", os.Getenv("ACKTIER_ADMIN_TOKEN"), "Admin Bearer Token")
	tlsCA := fs.String("tls-ca", os.Getenv("ACKTIER_TLS_CA"), "Optional Root CA PEM file")
	insecureHTTP := fs.Bool("insecure-http", false, "Allow plaintext HTTP on non-loopback server (lab testing only)")
	reusable := fs.Bool("reusable", true, "Allow multiple nodes to use this key")
	label := fs.String("label", "cli-key", "Key label")
	_ = fs.Parse(args[1:])

	ac := buildAdminClient(*serverURL, *token, *tlsCA, *insecureHTTP)
	pak, err := ac.CreatePreAuthKey(context.Background(), client.CreateKeyOptions{
		Label:    *label,
		Reusable: *reusable,
	})
	if err != nil {
		fatalf("%v", err)
	}
	fmt.Printf("Created PreAuthKey:\n  ID       : %s\n  Key      : %s\n  Reusable : %v\n  Expires  : %s\n",
		pak.ID, pak.Key, pak.Reusable, pak.ExpiresAt.Format(time.RFC3339))
}

func runAdminRoute(args []string) {
	if len(args) == 0 || args[0] != "approve" {
		fatalf("usage: acktier route approve --server <url> --admin-token <token> [--tls-ca <ca.pem>] --node <id> --routes <cidr,...>")
	}
	fs := flag.NewFlagSet("route approve", flag.ExitOnError)
	serverURL := fs.String("server", "http://127.0.0.1:8080", "Control Server URL")
	token := fs.String("admin-token", os.Getenv("ACKTIER_ADMIN_TOKEN"), "Admin Bearer Token")
	tlsCA := fs.String("tls-ca", os.Getenv("ACKTIER_TLS_CA"), "Optional Root CA PEM file")
	insecureHTTP := fs.Bool("insecure-http", false, "Allow plaintext HTTP on non-loopback server (lab testing only)")
	nodeID := fs.Uint64("node", 0, "Target Node ID")
	routesCSV := fs.String("routes", "", "Comma-separated CIDRs to approve")
	_ = fs.Parse(args[1:])
	if *nodeID == 0 {
		fatalf("--node <id> is required")
	}
	var pfxs []netip.Prefix
	if *routesCSV != "" {
		for _, p := range strings.Split(*routesCSV, ",") {
			pfx, err := netip.ParsePrefix(strings.TrimSpace(p))
			if err != nil {
				fatalf("invalid CIDR %q: %v", p, err)
			}
			pfxs = append(pfxs, pfx)
		}
	}
	ac := buildAdminClient(*serverURL, *token, *tlsCA, *insecureHTTP)
	if _, err := ac.ApproveRoutes(context.Background(), types.NodeID(*nodeID), pfxs); err != nil {
		fatalf("%v", err)
	}
	fmt.Printf("Approved routes %v on node #%d.\n", pfxs, *nodeID)
}

func runAdminACL(args []string) {
	if len(args) == 0 || args[0] != "set" {
		fatalf("usage: acktier acl set --server <url> --admin-token <token> [--tls-ca <ca.pem>] --file <policy.json>")
	}
	fs := flag.NewFlagSet("acl set", flag.ExitOnError)
	serverURL := fs.String("server", "http://127.0.0.1:8080", "Control Server URL")
	token := fs.String("admin-token", os.Getenv("ACKTIER_ADMIN_TOKEN"), "Admin Bearer Token")
	tlsCA := fs.String("tls-ca", os.Getenv("ACKTIER_TLS_CA"), "Optional Root CA PEM file")
	insecureHTTP := fs.Bool("insecure-http", false, "Allow plaintext HTTP on non-loopback server (lab testing only)")
	filePath := fs.String("file", "", "Path to ACL policy JSON file")
	_ = fs.Parse(args[1:])
	raw, err := os.ReadFile(*filePath)
	if err != nil {
		fatalf("read policy file: %v", err)
	}
	var pol types.ACLPolicy
	if err := json.Unmarshal(raw, &pol); err != nil {
		fatalf("parse policy json: %v", err)
	}
	ac := buildAdminClient(*serverURL, *token, *tlsCA, *insecureHTTP)
	if _, err := ac.SetACL(context.Background(), pol); err != nil {
		fatalf("%v", err)
	}
	fmt.Println("Zero-Trust ACL Policy applied and pushed to all connected nodes!")
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

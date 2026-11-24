package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/acktier/acktier/internal/daemon/engine"
	"github.com/acktier/acktier/internal/daemon/localapi"
	"github.com/acktier/acktier/pkg/types"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	apiBase := os.Getenv("ACKTIER_API")
	if apiBase == "" {
		apiBase = "http://" + localapi.DefaultAddr
	}
	apiBase = strings.TrimRight(apiBase, "/")

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "up":
		runUp(apiBase, args)
	case "down":
		runDown(apiBase)
	case "status":
		runStatus(apiBase, args)
	case "netcheck":
		runNetCheck(apiBase, args)
	case "ping":
		runPing(apiBase, args)
	case "key":
		runAdminKey(args)
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`AckTier CLI - Next-Gen Overlay Mesh Networking

Usage:
  acktier up --server <url> [--auth-key <key>] [--hostname <name>] [--advertise-routes <cidr,...>]
  acktier down
  acktier status [--json]
  acktier netcheck [--json]
  acktier ping <peer-name-or-ip> [-c <count>]
  acktier key create --server <url> --admin-token <token> [--reusable] [--label <name>]`)
}

func runUp(apiBase string, args []string) {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	apiFlag := fs.String("api", apiBase, "LocalAPI base URL")
	serverURL := fs.String("server", "", "AckTier Control Server URL")
	authKey := fs.String("auth-key", "", "PreAuthKey for registration")
	hostname := fs.String("hostname", "", "Custom node hostname")
	routesCSV := fs.String("advertise-routes", "", "Comma-separated subnet CIDRs to advertise")
	canRelay := fs.Bool("can-relay", false, "Allow this node to act as a peer relay")
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

	reqBody, _ := json.Marshal(engine.UpRequest{
		ServerURL:        *serverURL,
		AuthKey:          *authKey,
		Hostname:         *hostname,
		AdvertisedRoutes: routes,
		CanRelay:         *canRelay,
	})
	resp, err := http.Post(strings.TrimRight(*apiFlag, "/")+"/local/v1/up", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		fatalf("cannot reach acktierd LocalAPI (%s): %v", *apiFlag, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		fatalf("acktier up failed: %s", strings.TrimSpace(string(raw)))
	}
	var nm types.NetMap
	_ = json.NewDecoder(resp.Body).Decode(&nm)
	fmt.Printf("AckTier is UP!\n  Node Name : %s\n  IPv4      : %s\n  IPv6      : %s\n  Peers     : %d\n",
		nm.Self.Name, nm.Self.IPv4, nm.Self.IPv6, len(nm.Peers))
}

func runDown(apiBase string) {
	resp, err := http.Post(apiBase+"/local/v1/down", "application/json", strings.NewReader("{}"))
	if err != nil {
		fatalf("cannot reach acktierd: %v", err)
	}
	defer resp.Body.Close()
	fmt.Println("AckTier network disconnected.")
}

func runStatus(apiBase string, args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	apiFlag := fs.String("api", apiBase, "LocalAPI base URL")
	asJSON := fs.Bool("json", false, "Output raw JSON")
	_ = fs.Parse(args)

	resp, err := http.Get(strings.TrimRight(*apiFlag, "/") + "/local/v1/status")
	if err != nil {
		fatalf("cannot reach acktierd (%s): %v", *apiFlag, err)
	}
	defer resp.Body.Close()

	var st engine.StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		fatalf("decode status: %v", err)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(st)
		return
	}

	fmt.Printf("State: %s | TUN: %s | NAT: %s | Relay Connected: %v\n", st.State, st.TUNName, st.NATType, st.RelayConnected)
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

func runNetCheck(apiBase string, args []string) {
	fs := flag.NewFlagSet("netcheck", flag.ExitOnError)
	apiFlag := fs.String("api", apiBase, "LocalAPI base URL")
	asJSON := fs.Bool("json", false, "Output raw JSON")
	_ = fs.Parse(args)

	resp, err := http.Get(strings.TrimRight(*apiFlag, "/") + "/local/v1/netcheck")
	if err != nil {
		fatalf("cannot reach acktierd (%s): %v", *apiFlag, err)
	}
	defer resp.Body.Close()

	var rep engine.NetCheckReport
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
		fatalf("decode netcheck: %v", err)
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

	for i := 0; i < *count; i++ {
		raw, _ := json.Marshal(map[string]any{"target": target, "timeoutMs": 3000})
		resp, err := http.Post(strings.TrimRight(*apiFlag, "/")+"/local/v1/ping", "application/json", bytes.NewReader(raw))
		if err != nil {
			fatalf("cannot reach acktierd: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			msg, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			fmt.Printf("ping %s: timeout/error (%s)\n", target, strings.TrimSpace(string(msg)))
		} else {
			var res engine.PingResult
			_ = json.NewDecoder(resp.Body).Decode(&res)
			_ = resp.Body.Close()
			fmt.Printf("pong from %s (%s) via %s [%s] time=%.2f ms\n",
				res.TargetName, res.TargetIP, res.Via, res.Endpoint, res.RTTMillis)
		}
		if i+1 < *count {
			time.Sleep(500 * time.Millisecond)
		}
	}
}

func runAdminKey(args []string) {
	if len(args) == 0 || args[0] != "create" {
		fatalf("usage: acktier key create --server <url> --admin-token <token> [--reusable] [--label <name>]")
	}
	fs := flag.NewFlagSet("key create", flag.ExitOnError)
	serverURL := fs.String("server", "http://127.0.0.1:8080", "Control Server URL")
	token := fs.String("admin-token", os.Getenv("ACKTIER_ADMIN_TOKEN"), "Admin Bearer Token")
	reusable := fs.Bool("reusable", true, "Allow multiple nodes to use this key")
	label := fs.String("label", "cli-key", "Key label")
	_ = fs.Parse(args[1:])

	raw, _ := json.Marshal(map[string]any{
		"label":    *label,
		"reusable": *reusable,
	})
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(*serverURL, "/")+"/api/v1/admin/keys", bytes.NewReader(raw))
	if err != nil {
		fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+*token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fatalf("admin request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		fatalf("failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var pak types.PreAuthKey
	_ = json.NewDecoder(resp.Body).Decode(&pak)
	fmt.Printf("Created PreAuthKey:\n  ID       : %s\n  Key      : %s\n  Reusable : %v\n  Expires  : %s\n",
		pak.ID, pak.Key, pak.Reusable, pak.ExpiresAt.Format(time.RFC3339))
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ackwrap/acktier/internal/daemon/localapi"
	"github.com/ackwrap/acktier/pkg/client"
	"github.com/ackwrap/acktier/pkg/types"
)

func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func main() {
	var (
		statePath         = flag.String("state", "./data/acktierd-state.json", "Path to node persistent state")
		apiAddr           = flag.String("api", localapi.DefaultAddr, "Loopback LocalAPI listen address for CLI & Desktop GUI")
		allowRemoteAPI    = flag.Bool("insecure-remote-api", false, "Allow binding LocalAPI on non-loopback address (UNSAFE)")
		udpAddr           = flag.String("udp", "0.0.0.0:0", "UDP direct data-plane bind address (empty to disable)")
		tcpAddr           = flag.String("tcp", "0.0.0.0:0", "TCP direct data-plane bind address (empty to disable)")
		quicAddr          = flag.String("quic", "0.0.0.0:0", "QUIC v1 direct data-plane bind address (empty to disable)")
		wssAddr           = flag.String("wss", "0.0.0.0:0", "WebSocket over TLS (WSS) bind address (empty to disable)")
		enableUPnP        = flag.Bool("upnp", true, "Enable UPnP IGD & NAT-PMP automatic port mapping")
		enableLANDis      = flag.Bool("lan-discovery", true, "Enable L2 LAN peer discovery beacons")
		tunMode           = flag.String("tun", "auto", "TUN device mode: auto | os | memory")
		ifName            = flag.String("ifname", "", "Custom virtual network interface name")
		relayMode         = flag.String("relay-mode", "auto", "Peer relay mode: auto (public IP auto-enables) | on | off")
		maxRelayMbps      = flag.Float64("relay-max-mbps", 0, "Optional transit relay bandwidth limit in Mbps (0 = unlimited)")
		canRelay          = flag.Bool("can-relay", false, "Force enable peer relay (alias for -relay-mode=on)")
		serverURL         = flag.String("server", "", "Optional Control Server URL for immediate auto-up")
		authKey           = flag.String("auth-key", "", "Optional PreAuthKey for unattended registration")
		tlsCAFile         = flag.String("tls-ca", os.Getenv("ACKTIER_TLS_CA"), "Optional Root CA PEM file for verifying Control & Relay TLS")
		allowInsecureHTTP = flag.Bool("insecure-http", false, "Allow plaintext HTTP/Relay to non-loopback server (lab testing only)")
		controlLeaseTTL   = flag.Duration("control-lease-ttl", client.DefaultControlLeaseTTL, "How long to keep the last authorized NetMap without control updates (minimum 1m)")
		ownerTrust        = flag.String("owner-trust", "", "Owner trust.json received from the selected owner (required unless already pinned)")
	)
	flag.Parse()

	if !isLoopbackAddr(*apiAddr) && !*allowRemoteAPI {
		log.Fatalf("refusing to bind LocalAPI on non-loopback address %s; bind 127.0.0.1 / ::1", *apiAddr)
	}

	cfg := client.DefaultNodeConfig(*statePath)
	cfg.TUNMode = client.TUNMode(*tunMode)
	cfg.InterfaceName = *ifName
	cfg.UDPListenAddr = *udpAddr
	cfg.TCPListenAddr = *tcpAddr
	cfg.QUICListenAddr = *quicAddr
	cfg.WSSListenAddr = *wssAddr
	cfg.EnableUPnP = *enableUPnP
	cfg.EnableLANDiscovery = *enableLANDis
	cfg.TLSCAFile = *tlsCAFile
	cfg.AllowInsecureHTTP = *allowInsecureHTTP
	cfg.ControlLeaseTTL = *controlLeaseTTL
	cfg.OwnerTrustFile = *ownerTrust
	cfg.RequireOwner = true
	cfg.LocalAPIAddr = *apiAddr

	node, err := client.NewNode(cfg)
	if err != nil {
		log.Fatalf("failed to initialize AckTier node: %v", err)
	}
	defer node.Close()

	tokFile, tokErr := localapi.WriteTokenFile(*apiAddr, node.LocalAPIToken())
	if tokErr != nil {
		log.Printf("[acktierd] warning: failed to write LocalAPI token file: %v", tokErr)
	}

	st := node.Status()
	fmt.Println("============================================================")
	fmt.Printf(" AckTier Daemon (acktierd)\n")
	fmt.Printf(" NodeKey     : %s\n", st.SelfNodeKey)
	fmt.Printf(" TUN Device  : %s\n", st.TUNName)
	fmt.Printf(" Transports  : %v\n", st.ActiveProtocols)
	fmt.Printf(" LocalAPI    : http://%s (Bearer token required)\n", *apiAddr)
	if tokFile != "" {
		fmt.Printf(" Token File  : %s (owner-only permissions)\n", tokFile)
	}
	fmt.Println("============================================================")

	if *serverURL != "" || st.ServerURL != "" {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			nm, err := node.Up(ctx, client.UpOptions{
				ServerURL:         *serverURL,
				AuthKey:           *authKey,
				RelayMode:         types.RelayMode(*relayMode),
				MaxRelayMbps:      *maxRelayMbps,
				CanRelay:          *canRelay,
				AllowInsecureHTTP: *allowInsecureHTTP,
			})
			if err != nil {
				log.Printf("[acktierd] auto-up failed: %v", err)
				return
			}
			log.Printf("[acktierd] connected! Virtual IPv4: %s", nm.Self.IPv4)
		}()
	}

	apiSrv := &http.Server{
		Addr:              *apiAddr,
		Handler:           node.LocalAPIHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 15,
	}
	go func() {
		if err := apiSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("LocalAPI listen error: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Println("shutting down acktierd...")
	_ = apiSrv.Close()
}

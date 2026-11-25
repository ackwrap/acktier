package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/acktier/acktier/internal/daemon/localapi"
	"github.com/acktier/acktier/pkg/client"
	"github.com/acktier/acktier/pkg/types"
)

func main() {
	var (
		statePath    = flag.String("state", "./data/acktierd-state.json", "Path to node persistent state")
		apiAddr      = flag.String("api", localapi.DefaultAddr, "LocalAPI listen address for CLI & Desktop GUI")
		udpAddr      = flag.String("udp", "0.0.0.0:0", "UDP direct data-plane bind address (empty to disable)")
		tcpAddr      = flag.String("tcp", "0.0.0.0:0", "TCP direct data-plane bind address (empty to disable)")
		quicAddr     = flag.String("quic", "0.0.0.0:0", "QUIC v1 direct data-plane bind address (empty to disable)")
		wssAddr      = flag.String("wss", "0.0.0.0:0", "WebSocket over TLS (WSS) bind address (empty to disable)")
		enableUPnP   = flag.Bool("upnp", true, "Enable UPnP IGD & NAT-PMP automatic port mapping")
		enableLANDis = flag.Bool("lan-discovery", true, "Enable L2 LAN peer discovery beacons")
		tunMode      = flag.String("tun", "auto", "TUN device mode: auto | os | memory")
		ifName       = flag.String("ifname", "", "Custom virtual network interface name")
		relayMode    = flag.String("relay-mode", "auto", "Peer relay mode: auto (public IP auto-enables) | on | off")
		maxRelayMbps = flag.Float64("relay-max-mbps", 0, "Optional transit relay bandwidth limit in Mbps (0 = unlimited)")
		canRelay     = flag.Bool("can-relay", false, "Force enable peer relay (alias for -relay-mode=on)")
		serverURL    = flag.String("server", "", "Optional Control Server URL for immediate auto-up")
		authKey      = flag.String("auth-key", "", "Optional PreAuthKey for unattended registration")
	)
	flag.Parse()

	cfg := client.DefaultNodeConfig(*statePath)
	cfg.TUNMode = client.TUNMode(*tunMode)
	cfg.InterfaceName = *ifName
	cfg.UDPListenAddr = *udpAddr
	cfg.TCPListenAddr = *tcpAddr
	cfg.QUICListenAddr = *quicAddr
	cfg.WSSListenAddr = *wssAddr
	cfg.EnableUPnP = *enableUPnP
	cfg.EnableLANDiscovery = *enableLANDis

	node, err := client.NewNode(cfg)
	if err != nil {
		log.Fatalf("failed to initialize AckTier node: %v", err)
	}
	defer node.Close()

	st := node.Status()
	fmt.Println("============================================================")
	fmt.Printf(" AckTier Daemon (acktierd)\n")
	fmt.Printf(" NodeKey     : %s\n", st.SelfNodeKey)
	fmt.Printf(" TUN Device  : %s\n", st.TUNName)
	fmt.Printf(" Transports  : %v\n", st.ActiveProtocols)
	fmt.Printf(" LocalAPI    : http://%s\n", *apiAddr)
	fmt.Println("============================================================")

	if *serverURL != "" || st.ServerURL != "" {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			nm, err := node.Up(ctx, client.UpOptions{
				ServerURL:    *serverURL,
				AuthKey:      *authKey,
				RelayMode:    types.RelayMode(*relayMode),
				MaxRelayMbps: *maxRelayMbps,
				CanRelay:     *canRelay,
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

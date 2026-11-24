package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/acktier/acktier/internal/daemon/engine"
	"github.com/acktier/acktier/internal/daemon/localapi"
	"github.com/acktier/acktier/internal/daemon/state"
	"github.com/acktier/acktier/internal/daemon/transport"
	"github.com/acktier/acktier/internal/daemon/tun"
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
		serverURL    = flag.String("server", "", "Optional Control Server URL for immediate auto-up")
		authKey      = flag.String("auth-key", "", "Optional PreAuthKey for unattended registration")
	)
	flag.Parse()

	stMgr, err := state.LoadOrCreate(*statePath)
	if err != nil {
		log.Fatalf("failed to load state %s: %v", *statePath, err)
	}

	var tunDev tun.Device
	switch *tunMode {
	case "memory":
		tunDev = tun.NewMemoryDevice("acktier-mem0", tun.DefaultMTU)
	case "os":
		tunDev, err = tun.CreateOSDevice(*ifName, tun.DefaultMTU)
		if err != nil {
			log.Fatalf("failed to create OS TUN device: %v", err)
		}
	default:
		tunDev, err = tun.CreateOSDevice(*ifName, tun.DefaultMTU)
		if err != nil {
			log.Printf("[acktierd] OS TUN unavailable (%v); falling back to userspace memory TUN", err)
			tunDev = tun.NewMemoryDevice("acktier-mem0", tun.DefaultMTU)
		}
	}

	hub := transport.NewHub()
	eng, err := engine.New(engine.Options{
		State:              stMgr,
		TUN:                tunDev,
		Hub:                hub,
		EnableLANDiscovery: *enableLANDis,
		EnablePortMap:      *enableUPnP,
	})
	if err != nil {
		log.Fatalf("failed to initialize engine: %v", err)
	}
	defer eng.Close()

	// Bind enabled multi-protocol transports
	if *udpAddr != "" {
		if uConn, err := net.ListenPacket("udp", *udpAddr); err == nil {
			hub.Register(transport.NewUDPDriver(uConn, eng.OnTransportPacket))
		} else {
			log.Printf("[acktierd] warning: UDP bind %s failed: %v", *udpAddr, err)
		}
	}
	if *tcpAddr != "" {
		if tLn, err := net.Listen("tcp", *tcpAddr); err == nil {
			hub.Register(transport.NewTCPDriver(tLn, nil, eng.OnTransportPacket))
		} else {
			log.Printf("[acktierd] warning: TCP bind %s failed: %v", *tcpAddr, err)
		}
	}
	if *quicAddr != "" {
		if qConn, err := net.ListenPacket("udp", *quicAddr); err == nil {
			if qDrv, qErr := transport.NewQUICDriver(qConn, eng.OnTransportPacket); qErr == nil {
				hub.Register(qDrv)
			} else {
				_ = qConn.Close()
				log.Printf("[acktierd] warning: QUIC init failed: %v", qErr)
			}
		}
	}
	if *wssAddr != "" {
		if wLn, err := net.Listen("tcp", *wssAddr); err == nil {
			if wDrv, wErr := transport.NewWSSDriver(wLn, nil, eng.OnTransportPacket); wErr == nil {
				hub.Register(wDrv)
			} else {
				_ = wLn.Close()
				log.Printf("[acktierd] warning: WSS init failed: %v", wErr)
			}
		}
	}

	apiSrv := &http.Server{
		Addr:              *apiAddr,
		Handler:           localapi.NewServer(eng).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	cur := stMgr.Get()
	fmt.Println("============================================================")
	fmt.Printf(" AckTier Daemon (acktierd)\n")
	fmt.Printf(" NodeKey     : %s\n", cur.NodeKey.Public().ShortString())
	fmt.Printf(" TUN Device  : %s (MTU %d)\n", tunDev.Name(), tunDev.MTU())
	fmt.Printf(" Transports  : %v\n", hub.LocalPorts())
	fmt.Printf(" LocalAPI    : http://%s\n", *apiAddr)
	fmt.Println("============================================================")

	if *serverURL != "" || (cur.WantRunning && cur.ServerURL != "") {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			nm, err := eng.Up(ctx, engine.UpRequest{
				ServerURL: *serverURL,
				AuthKey:   *authKey,
			})
			if err != nil {
				log.Printf("[acktierd] auto-up failed: %v", err)
				return
			}
			log.Printf("[acktierd] connected! Virtual IPv4: %s", nm.Self.IPv4)
		}()
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

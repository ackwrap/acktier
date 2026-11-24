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
	"github.com/acktier/acktier/internal/daemon/tun"
)

func main() {
	var (
		statePath = flag.String("state", "./data/acktierd-state.json", "Path to node persistent state")
		apiAddr   = flag.String("api", localapi.DefaultAddr, "LocalAPI listen address for CLI & Desktop GUI")
		udpAddr   = flag.String("udp", "0.0.0.0:0", "UDP data-plane bind address")
		tunMode   = flag.String("tun", "auto", "TUN device mode: auto | os | memory")
		ifName    = flag.String("ifname", "", "Custom virtual network interface name")
		serverURL = flag.String("server", "", "Optional Control Server URL for immediate auto-up")
		authKey   = flag.String("auth-key", "", "Optional PreAuthKey for unattended registration")
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
	default: // "auto"
		tunDev, err = tun.CreateOSDevice(*ifName, tun.DefaultMTU)
		if err != nil {
			log.Printf("[acktierd] OS TUN unavailable (%v); falling back to userspace memory TUN", err)
			tunDev = tun.NewMemoryDevice("acktier-mem0", tun.DefaultMTU)
		}
	}

	udpConn, err := net.ListenPacket("udp", *udpAddr)
	if err != nil {
		log.Fatalf("failed to bind UDP socket %s: %v", *udpAddr, err)
	}

	eng, err := engine.New(engine.Options{
		State:   stMgr,
		TUN:     tunDev,
		UDPConn: udpConn,
	})
	if err != nil {
		log.Fatalf("failed to initialize engine: %v", err)
	}
	defer eng.Close()

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
	fmt.Printf(" UDP Socket  : %s\n", udpConn.LocalAddr().String())
	fmt.Printf(" LocalAPI    : http://%s\n", *apiAddr)
	fmt.Println("============================================================")

	// Auto-connect if flags provided or previously running
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

package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/acktier/acktier/internal/server/control"
	"github.com/acktier/acktier/internal/server/relay"
	"github.com/acktier/acktier/internal/server/store"
)

func main() {
	var (
		listenAddr = flag.String("listen", "0.0.0.0:8080", "HTTP control & relay listen address")
		stunAddr   = flag.String("stun", "0.0.0.0:3478", "UDP STUN listen address (empty to disable)")
		publicHost = flag.String("public-host", "127.0.0.1", "Public host/IP advertised to clients for Relay & STUN")
		dataPath   = flag.String("data", "./data/server-state.json", "Path to persistent server state file")
		adminToken = flag.String("admin-token", os.Getenv("ACKTIER_ADMIN_TOKEN"), "Admin API bearer token (auto-generated if empty)")
	)
	flag.Parse()

	if *adminToken == "" {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		*adminToken = "adm_" + hex.EncodeToString(b)
	}

	st, err := store.NewFileStore(*dataPath)
	if err != nil {
		log.Fatalf("failed to open store: %v", err)
	}

	// Ensure at least one reusable bootstrap PreAuthKey exists on fresh setup
	var bootstrapKey string
	if len(st.ListPreAuthKeys()) == 0 {
		pak, err := st.CreatePreAuthKey("bootstrap-default", true, false, nil, 30*24*time.Hour)
		if err == nil {
			bootstrapKey = pak.Key
		}
	}

	_, httpPort, _ := net.SplitHostPort(*listenAddr)
	if httpPort == "" {
		httpPort = "8080"
	}
	advRelayAddr := net.JoinHostPort(*publicHost, httpPort)

	var advSTUNAddr string
	var stunConn net.PacketConn
	if *stunAddr != "" {
		uConn, err := net.ListenPacket("udp", *stunAddr)
		if err != nil {
			log.Fatalf("failed to bind STUN UDP %s: %v", *stunAddr, err)
		}
		stunConn = uConn
		_, sPort, _ := net.SplitHostPort(uConn.LocalAddr().String())
		advSTUNAddr = net.JoinHostPort(*publicHost, sPort)
		go relay.ServeSTUNLoop(stunConn)
	}

	ctrl := control.NewServer(control.Config{
		AdminToken: *adminToken,
		PublicHost: *publicHost,
		RelayAddr:  advRelayAddr,
		STUNAddr:   advSTUNAddr,
	}, st)

	httpSrv := &http.Server{
		Addr:              *listenAddr,
		Handler:           ctrl.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	fmt.Println("============================================================")
	fmt.Printf(" AckTier Control & Relay Server\n")
	fmt.Printf(" Listen HTTP/Relay : %s (advertised: %s)\n", *listenAddr, advRelayAddr)
	if advSTUNAddr != "" {
		fmt.Printf(" Listen UDP STUN   : %s (advertised: %s)\n", *stunAddr, advSTUNAddr)
	}
	fmt.Printf(" Admin Token       : %s\n", *adminToken)
	if bootstrapKey != "" {
		fmt.Printf(" Bootstrap AuthKey : %s\n", bootstrapKey)
	}
	fmt.Println("============================================================")

	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server error: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Println("shutting down acktier-server...")
	if stunConn != nil {
		_ = stunConn.Close()
	}
	_ = httpSrv.Close()
}

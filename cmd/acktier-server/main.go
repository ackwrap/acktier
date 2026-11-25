package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/acktier/acktier/internal/owner"
	"github.com/acktier/acktier/internal/secfile"
	"github.com/acktier/acktier/internal/server/control"
	"github.com/acktier/acktier/internal/server/relay"
	"github.com/acktier/acktier/internal/server/store"
)

func isLoopbackListenAddr(addr string) bool {
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

func redactSecret(s string) string {
	if len(s) <= 10 {
		return "[redacted]"
	}
	return s[:10] + "...[redacted]"
}

func defaultCredentialsPath(dataPath string) string {
	if dataPath != "" {
		return filepath.Join(filepath.Dir(dataPath), "server-credentials.json")
	}
	if cfgDir, err := os.UserConfigDir(); err == nil && cfgDir != "" {
		return filepath.Join(cfgDir, "acktier", "server-credentials.json")
	}
	return "./data/server-credentials.json"
}

func main() {
	var (
		listenAddr   = flag.String("listen", "127.0.0.1:8080", "Control & relay listen address (non-loopback requires -tls-cert/-tls-key)")
		stunAddr     = flag.String("stun", "0.0.0.0:3478", "Primary UDP STUN listen address (empty to disable)")
		stunAltAddr  = flag.String("stun-alt", "0.0.0.0:3479", "Secondary UDP STUN listen address for NAT type detection")
		publicHost   = flag.String("public-host", "127.0.0.1", "Public host/IP advertised to clients for Relay & STUN")
		dataPath     = flag.String("data", "./data/server-state.json", "Path to persistent server state file")
		adminToken   = flag.String("admin-token", os.Getenv("ACKTIER_ADMIN_TOKEN"), "Admin API bearer token (auto-generated and saved if empty)")
		tlsCert      = flag.String("tls-cert", "", "TLS server certificate PEM file (enables HTTPS + TLS Relay)")
		tlsKey       = flag.String("tls-key", "", "TLS server private key PEM file")
		insecureHTTP = flag.Bool("insecure-http", false, "Allow plaintext HTTP on non-loopback interfaces (UNSAFE for production)")
		credsFile    = flag.String("credentials-file", "", "Owner-only file path to write generated AdminToken / bootstrap PreAuthKey")
		printCreds   = flag.Bool("print-credentials", false, "Print full generated credentials to stdout (local debugging only)")
		ownerTrust   = flag.String("owner-trust", "", "Preconfigure the selected owner's public trust JSON instead of using Web setup")
	)
	flag.Parse()

	useTLS := *tlsCert != "" || *tlsKey != ""
	if useTLS && (*tlsCert == "" || *tlsKey == "") {
		log.Fatalf("both -tls-cert and -tls-key must be provided when TLS is enabled")
	}
	if !useTLS && !isLoopbackListenAddr(*listenAddr) && !*insecureHTTP {
		log.Fatalf("refusing to serve plaintext HTTP/Relay on non-loopback %s; provide -tls-cert and -tls-key (or bind 127.0.0.1, or pass -insecure-http for isolated lab testing)", *listenAddr)
	}

	generatedAdmin := false
	if *adminToken == "" {
		b := make([]byte, 24)
		_, _ = rand.Read(b)
		*adminToken = "adm_" + hex.EncodeToString(b)
		generatedAdmin = true
	}

	st, err := store.NewFileStore(*dataPath)
	if err != nil {
		log.Fatalf("failed to open store: %v", err)
	}
	if err := configureOwner(st, *ownerTrust); err != nil {
		log.Fatal(err)
	}

	var bootstrapKey string
	if len(st.ListPreAuthKeys()) == 0 {
		pak, err := st.CreatePreAuthKey("bootstrap-default", true, false, nil, 30*24*time.Hour)
		if err == nil {
			bootstrapKey = pak.Key
		}
	}

	// Persist generated secrets to an owner-only file rather than leaking full credentials in stdout/logs.
	var savedCredsPath string
	if generatedAdmin || bootstrapKey != "" {
		targetCreds := *credsFile
		if targetCreds == "" {
			targetCreds = defaultCredentialsPath(*dataPath)
		}
		payload := map[string]string{
			"adminToken": *adminToken,
			"updatedAt":  time.Now().UTC().Format(time.RFC3339),
		}
		if bootstrapKey != "" {
			payload["bootstrapAuthKey"] = bootstrapKey
		}
		if raw, mErr := json.MarshalIndent(payload, "", "  "); mErr == nil {
			if wErr := secfile.WritePrivate(targetCreds, raw); wErr == nil {
				savedCredsPath = targetCreds
			} else {
				log.Printf("[security] warning: failed to write private credentials file %s: %v", targetCreds, wErr)
			}
		}
	}

	_, httpPort, _ := net.SplitHostPort(*listenAddr)
	if httpPort == "" {
		httpPort = "8080"
	}
	advRelayAddr := net.JoinHostPort(*publicHost, httpPort)

	var advSTUNAddr, advSTUNAltAddr string
	var stunConn, stunAltConn net.PacketConn
	if *stunAddr != "" {
		uConn, err := net.ListenPacket("udp", *stunAddr)
		if err != nil {
			log.Fatalf("failed to bind primary STUN UDP %s: %v", *stunAddr, err)
		}
		stunConn = uConn
		_, sPort, _ := net.SplitHostPort(uConn.LocalAddr().String())
		advSTUNAddr = net.JoinHostPort(*publicHost, sPort)
		go relay.ServeSTUNLoop(stunConn)
	}
	if *stunAltAddr != "" {
		uAlt, err := net.ListenPacket("udp", *stunAltAddr)
		if err == nil {
			stunAltConn = uAlt
			_, sAltPort, _ := net.SplitHostPort(uAlt.LocalAddr().String())
			advSTUNAltAddr = net.JoinHostPort(*publicHost, sAltPort)
			go relay.ServeSTUNLoop(stunAltConn)
		}
	}

	ctrl := control.NewServer(control.Config{
		AdminToken:   *adminToken,
		PublicHost:   *publicHost,
		RelayAddr:    advRelayAddr,
		STUNAddr:     advSTUNAddr,
		STUNAltAddr:  advSTUNAltAddr,
		UseTLS:       useTLS,
		RequireOwner: true,
	}, st)

	httpSrv := &http.Server{
		Addr:              *listenAddr,
		Handler:           ctrl.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second, // Bound request bodies; the NetMap stream clears its read deadline.
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	fmt.Println("============================================================")
	fmt.Printf(" AckTier Control & Relay Server\n")
	fmt.Printf(" Listen %s/Relay : %s (advertised: %s, tls=%v)\n", strings.ToUpper(scheme), *listenAddr, advRelayAddr, useTLS)
	fmt.Printf(" Admin console      : %s://%s/admin/\n", scheme, *listenAddr)
	if trust, pinned := st.OwnerTrust(); pinned {
		fmt.Printf(" Owner network      : %s\n", trust.NetworkID())
	} else {
		fmt.Println(" Owner network      : awaiting Web setup (node admission is paused)")
	}
	if advSTUNAddr != "" {
		fmt.Printf(" Listen UDP STUN    : %s / alt %s\n", advSTUNAddr, advSTUNAltAddr)
	}
	if *printCreds {
		fmt.Printf(" Admin Token        : %s\n", *adminToken)
		if bootstrapKey != "" {
			fmt.Printf(" Bootstrap AuthKey  : %s\n", bootstrapKey)
		}
	} else {
		fmt.Printf(" Admin Token        : %s\n", redactSecret(*adminToken))
		if bootstrapKey != "" {
			fmt.Printf(" Bootstrap AuthKey  : %s\n", redactSecret(bootstrapKey))
		}
		if savedCredsPath != "" {
			fmt.Printf(" Credentials File   : %s (owner-only permissions)\n", savedCredsPath)
		}
	}
	fmt.Println("============================================================")

	go func() {
		var serveErr error
		if useTLS {
			serveErr = httpSrv.ListenAndServeTLS(*tlsCert, *tlsKey)
		} else {
			serveErr = httpSrv.ListenAndServe()
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			log.Fatalf("server listen error: %v", serveErr)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Println("shutting down acktier-server...")
	if stunConn != nil {
		_ = stunConn.Close()
	}
	if stunAltConn != nil {
		_ = stunAltConn.Close()
	}
	_ = httpSrv.Close()
}

func configureOwner(st *store.FileStore, trustPath string) error {
	if trustPath == "" {
		return nil // The Web console handles first-run setup.
	}
	trust, err := owner.LoadTrust(trustPath)
	if err != nil {
		return fmt.Errorf("read owner trust: %w", err)
	}
	if err := st.ConfigureOwner(trust); err != nil {
		return fmt.Errorf("pin owner trust: %w", err)
	}
	return nil
}

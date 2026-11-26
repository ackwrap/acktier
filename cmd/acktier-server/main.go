package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
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

	"github.com/ackwrap/acktier/internal/owner"
	"github.com/ackwrap/acktier/internal/secfile"
	"github.com/ackwrap/acktier/internal/server/control"
	"github.com/ackwrap/acktier/internal/server/relay"
	"github.com/ackwrap/acktier/internal/server/store"
)

const defaultAdminListenAddr = "127.0.0.1:8081"

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
	if filepath.Clean(dataPath) == filepath.Clean(defaultCenterDB) {
		return "./data/server-credentials.json"
	}
	if dataPath != "" {
		return filepath.Join(filepath.Dir(dataPath), "server-credentials.json")
	}
	if cfgDir, err := os.UserConfigDir(); err == nil && cfgDir != "" {
		return filepath.Join(cfgDir, "acktier", "server-credentials.json")
	}
	return "./data/server-credentials.json"
}

func readPasswordSource(passwordFile string) (string, error) {
	if strings.TrimSpace(passwordFile) != "" {
		raw, err := os.ReadFile(passwordFile)
		if err != nil {
			return "", fmt.Errorf("read admin password file: %w", err)
		}
		pw := strings.TrimRight(string(raw), "\r\n")
		if pw == "" {
			return "", errors.New("admin password file is empty")
		}
		return pw, nil
	}
	if envPw := os.Getenv("ACKTIER_ADMIN_PASSWORD"); envPw != "" {
		return envPw, nil
	}
	return "", nil
}

func provisionAdminPassword(st *store.FileStore, passwordFile string, forceReset bool, deliverGenerated func(string) error) (generatedPassword string, changed bool, err error) {
	if st.HasAdminPassword() && !forceReset {
		return "", false, nil
	}
	explicitPw, err := readPasswordSource(passwordFile)
	if err != nil {
		return "", false, err
	}
	targetPw := explicitPw
	if targetPw == "" {
		b := make([]byte, 18)
		_, _ = rand.Read(b)
		targetPw = "admpw_" + hex.EncodeToString(b)
		generatedPassword = targetPw
		if deliverGenerated != nil {
			if err := deliverGenerated(generatedPassword); err != nil {
				return "", false, err
			}
		}
	}
	action := "password.init"
	if forceReset {
		action = "password.reset"
	}
	if err := st.SetAdminPassword(targetPw, store.AuditEntry{
		Actor: "local-host", Action: action, Result: "success",
	}); err != nil {
		return "", false, err
	}
	return generatedPassword, true, nil
}

func runResetPasswordCLI(args []string) {
	fs := flag.NewFlagSet("reset-password", flag.ExitOnError)
	dataPath := fs.String("data", defaultCenterDB, "Path to the stopped center's SQLite database")
	passwordFile := fs.String("admin-password-file", "", "Owner-only file containing the new Web admin password")
	credsFile := fs.String("credentials-file", "", "Owner-only file to write a generated password if no password file/env is supplied")
	_ = fs.Parse(args)

	targetCreds := *credsFile
	if targetCreds == "" {
		targetCreds = defaultCredentialsPath(*dataPath)
	}
	if err := distinctStatePaths(*dataPath, targetCreds, *passwordFile); err != nil {
		log.Fatal(err)
	}
	st, err := store.OpenExistingFileStore(*dataPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()
	genPw, _, err := provisionAdminPassword(st, *passwordFile, true, func(password string) error {
		return saveInitialCredentials(targetCreds, password, "")
	})
	if err != nil {
		log.Fatalf("reset admin password: %v", err)
	}
	if genPw != "" {
		fmt.Printf("Admin password reset and written to private file: %s\n", targetCreds)
		return
	}
	fmt.Println("Admin password reset successfully. Start the center and log in with the new password.")
}

func saveInitialCredentials(path, password, bootstrapKey string) error {
	payload := map[string]string{"updatedAt": time.Now().UTC().Format(time.RFC3339)}
	if password != "" {
		payload["adminPassword"] = password
	}
	if bootstrapKey != "" {
		payload["bootstrapAuthKey"] = bootstrapKey
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err == nil {
		err = secfile.WritePrivate(path, append(raw, '\n'))
	}
	return err
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "reset-password" {
		runResetPasswordCLI(os.Args[2:])
		return
	}

	var (
		listenAddr         = flag.String("listen", "127.0.0.1:8080", "Node control & relay listen address (non-loopback requires -tls-cert/-tls-key)")
		adminListenAddr    = flag.String("admin-listen", defaultAdminListenAddr, "Separate Web console & management API listen address (empty disables; non-loopback always requires TLS)")
		stunAddr           = flag.String("stun", "0.0.0.0:3478", "Primary UDP STUN listen address (empty to disable)")
		stunAltAddr        = flag.String("stun-alt", "0.0.0.0:3479", "Secondary UDP STUN listen address for NAT type detection")
		publicHost         = flag.String("public-host", "127.0.0.1", "Public host/IP advertised to clients for Relay & STUN")
		dataPath           = flag.String("data", defaultCenterDB, "Path to persistent SQLite center state (empty for in-memory testing)")
		passwordFile       = flag.String("admin-password-file", "", "Owner-only file containing the Web admin password (overrides ACKTIER_ADMIN_PASSWORD)")
		resetPassword      = flag.Bool("reset-admin-password", false, "Reset the Web admin password on startup and invalidate prior sessions")
		delegateController = flag.String("delegate-controller", "", "Optional controller-trust.json file to enable signed controller API delegation")
		tlsCert            = flag.String("tls-cert", "", "TLS server certificate PEM file (enables HTTPS + TLS Relay)")
		tlsKey             = flag.String("tls-key", "", "TLS server private key PEM file")
		insecureHTTP       = flag.Bool("insecure-http", false, "Allow plaintext HTTP on non-loopback node listener (NEVER enables remote plaintext Web admin)")
		credsFile          = flag.String("credentials-file", "", "Owner-only file path to write generated initial credentials")
		printCreds         = flag.Bool("print-credentials", false, "Print generated bootstrap AuthKey to stdout (local debugging only; passwords are never printed)")
		ownerTrust         = flag.String("owner-trust", "", "Preconfigure the selected owner's public trust JSON instead of using Web setup")
	)
	flag.Parse()

	useTLS := *tlsCert != "" || *tlsKey != ""
	if useTLS && (*tlsCert == "" || *tlsKey == "") {
		log.Fatalf("both -tls-cert and -tls-key must be provided when TLS is enabled")
	}
	if !useTLS && !isLoopbackListenAddr(*listenAddr) && !*insecureHTTP {
		log.Fatalf("refusing to serve plaintext HTTP/Relay on non-loopback %s; provide -tls-cert and -tls-key (or bind 127.0.0.1, or pass -insecure-http for isolated lab testing)", *listenAddr)
	}
	if *adminListenAddr != "" {
		if strings.EqualFold(strings.TrimSpace(*adminListenAddr), strings.TrimSpace(*listenAddr)) {
			log.Fatalf("-admin-listen (%s) must use a separate address/port from node -listen (%s)", *adminListenAddr, *listenAddr)
		}
		// Never allow -insecure-http on the node port to expose remote plaintext Web management!
		if !useTLS && !isLoopbackListenAddr(*adminListenAddr) {
			log.Fatalf("refusing to serve Web management on non-loopback %s without TLS; bind 127.0.0.1 (e.g. via SSH tunnel) or configure -tls-cert and -tls-key", *adminListenAddr)
		}
	}

	targetCreds := *credsFile
	if targetCreds == "" {
		targetCreds = defaultCredentialsPath(*dataPath)
	}
	if err := distinctStatePaths(*dataPath, targetCreds, *passwordFile); err != nil {
		log.Fatal(err)
	}

	st, err := store.NewFileStore(*dataPath)
	if err != nil {
		log.Fatalf("failed to open store: %v", err)
	}
	defer st.Close()
	if *adminListenAddr == "" {
		if _, pinned := st.OwnerTrust(); !pinned && *ownerTrust == "" {
			log.Fatal("an unbound center with Web management disabled needs -owner-trust")
		}
	}
	if err := configureOwner(st, *ownerTrust); err != nil {
		log.Fatal(err)
	}
	if *delegateController != "" {
		if err := configureDelegation(st, *delegateController); err != nil {
			log.Fatal(err)
		}
	}

	generatedAdminPw, _, err := provisionAdminPassword(st, *passwordFile, *resetPassword, func(password string) error {
		return saveInitialCredentials(targetCreds, password, "")
	})
	if err != nil {
		log.Fatalf("failed to configure Web admin password: %v", err)
	}

	var bootstrapKey string
	if len(st.ListPreAuthKeys()) == 0 {
		pak, err := st.CreatePreAuthKey("bootstrap-default", false, false, nil, 24*time.Hour)
		if err == nil {
			bootstrapKey = pak.Key
		}
	}

	var savedCredsPath string
	if generatedAdminPw != "" || bootstrapKey != "" {
		if generatedAdminPw != "" {
			savedCredsPath = targetCreds
		}
		if bootstrapKey != "" {
			if err := saveInitialCredentials(targetCreds, generatedAdminPw, bootstrapKey); err == nil {
				savedCredsPath = targetCreds
			} else {
				log.Printf("[security] failed to write bootstrap credentials file %s: %v", targetCreds, err)
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
		PublicHost:   *publicHost,
		RelayAddr:    advRelayAddr,
		STUNAddr:     advSTUNAddr,
		STUNAltAddr:  advSTUNAltAddr,
		UseTLS:       useTLS,
		RequireOwner: true,
	}, st)

	newHTTPServer := func(addr string, handler http.Handler) *http.Server {
		return &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       20 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    1 << 16,
			TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		}
	}

	nodeSrv := newHTTPServer(*listenAddr, ctrl.Handler())
	var adminSrv *http.Server
	if *adminListenAddr != "" {
		adminSrv = newHTTPServer(*adminListenAddr, ctrl.AdminHandler())
	}

	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	fmt.Println("============================================================")
	fmt.Printf(" AckTier Control & Relay Server\n")
	fmt.Printf(" Node %s/Relay  : %s (advertised: %s, tls=%v)\n", strings.ToUpper(scheme), *listenAddr, advRelayAddr, useTLS)
	if *dataPath != "" {
		fmt.Printf(" SQLite state      : %s\n", *dataPath)
	}
	if adminSrv != nil {
		fmt.Printf(" Admin Console     : %s://%s/admin/\n", scheme, *adminListenAddr)
	} else {
		fmt.Println(" Admin Console     : disabled (-admin-listen=)")
	}
	if trust, pinned := st.OwnerTrust(); pinned {
		fmt.Printf(" Owner Network     : %s\n", trust.NetworkID())
	} else {
		fmt.Println(" Owner Network     : awaiting Web setup (node admission is paused)")
	}
	if advSTUNAddr != "" {
		fmt.Printf(" Listen UDP STUN   : %s / alt %s\n", advSTUNAddr, advSTUNAltAddr)
	}
	if bootstrapKey != "" {
		if *printCreds {
			fmt.Printf(" Bootstrap AuthKey : %s\n", bootstrapKey)
		} else {
			fmt.Printf(" Bootstrap AuthKey : %s\n", redactSecret(bootstrapKey))
		}
	}
	if savedCredsPath != "" {
		fmt.Printf(" Credentials File  : %s (owner-only permissions)\n", savedCredsPath)
	}
	fmt.Println("============================================================")

	serve := func(name string, srv *http.Server) {
		var serveErr error
		if useTLS {
			serveErr = srv.ListenAndServeTLS(*tlsCert, *tlsKey)
		} else {
			serveErr = srv.ListenAndServe()
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			log.Fatalf("%s listen error: %v", name, serveErr)
		}
	}
	go serve("node server", nodeSrv)
	if adminSrv != nil {
		go serve("admin server", adminSrv)
	}

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
	if adminSrv != nil {
		_ = adminSrv.Close()
	}
	_ = nodeSrv.Close()
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

func configureDelegation(st *store.FileStore, path string) error {
	var ct owner.ControllerTrust
	if err := owner.ReadJSON(path, owner.MaxTrust, &ct); err != nil {
		return fmt.Errorf("read controller trust: %w", err)
	}
	if _, err := st.EnableControllerDelegation(ct); err != nil {
		return fmt.Errorf("enable controller delegation: %w", err)
	}
	return nil
}

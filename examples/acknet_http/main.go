package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/acktier/acktier/pkg/acknet"
)

func main() {
	mode := flag.String("mode", "server", "Run mode: server | client")
	ctrlURL := flag.String("server", "http://127.0.0.1:8080", "AckTier Control Server URL")
	authKey := flag.String("auth-key", "", "PreAuthKey from acktier-server")
	trust := flag.String("owner-trust", "", "Public trust file from the network owner")
	stateDir := flag.String("state-dir", "", "Persistent node state directory (defaults to a separate directory per mode)")
	target := flag.String("target", "http://demo-http-srv.ack.internal:8080/ping", "Target URL for client mode")
	flag.Parse()
	if *mode != "server" && *mode != "client" {
		log.Fatal("mode must be server or client")
	}
	if *stateDir == "" {
		*stateDir = "./data/acknet-http-" + *mode
	}

	if *mode == "server" {
		srv := &acknet.Server{
			Hostname:       "demo-http-srv",
			ControlURL:     *ctrlURL,
			AuthKey:        *authKey,
			StateDir:       *stateDir,
			OwnerTrustFile: *trust,
			RequireOwner:   true,
		}
		defer srv.Close()

		ln, err := srv.Listen("tcp", ":8080")
		if err != nil {
			log.Fatalf("acknet Listen failed: %v", err)
		}
		v4, _ := srv.LocalIPs()
		log.Printf("acknet HTTP server listening on %s:8080 (demo-http-srv.ack.internal:8080)", v4)

		mux := http.NewServeMux()
		mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "acknet-pong from %s (peer=%s)\n", v4, r.RemoteAddr)
		})
		log.Fatal(http.Serve(ln, mux))
	}

	cli := &acknet.Server{
		Hostname:       "demo-http-cli",
		ControlURL:     *ctrlURL,
		AuthKey:        *authKey,
		StateDir:       *stateDir,
		OwnerTrustFile: *trust,
		RequireOwner:   true,
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := cli.Up(ctx); err != nil {
		log.Fatalf("acknet Up failed: %v", err)
	}

	resp, err := cli.HTTPClient().Get(*target)
	if err != nil {
		log.Fatalf("HTTP GET over acknet failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Response [%d]: %s", resp.StatusCode, string(body))
}

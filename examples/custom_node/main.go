package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/acktier/acktier/pkg/client"
)

func main() {
	ctrlURL := flag.String("server", "http://127.0.0.1:8080", "AckTier Control Server URL")
	authKey := flag.String("auth-key", "", "PreAuthKey")
	flag.Parse()

	cfg := client.DefaultNodeConfig("") // Empty StatePath = ephemeral in-memory identity
	cfg.Hostname = "sdk-embedded-node"
	cfg.TUNMode = client.TUNMemory

	node, err := client.NewNode(cfg)
	if err != nil {
		log.Fatalf("NewNode: %v", err)
	}
	defer node.Close()

	unsub := node.Subscribe(func(ev client.Event) {
		fmt.Printf("[SDK Event] %s -> state=%s ip=%s\n", ev.Type, ev.Status.State, ev.Status.IPv4)
	})
	defer unsub()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	nm, err := node.Up(ctx, client.UpOptions{
		ServerURL: *ctrlURL,
		AuthKey:   *authKey,
		CanRelay:  true,
	})
	if err != nil {
		log.Fatalf("node.Up: %v", err)
	}
	fmt.Printf("Embedded node online! Virtual IPv4=%s, Peers=%d\n", nm.Self.IPv4, len(nm.Peers))
}

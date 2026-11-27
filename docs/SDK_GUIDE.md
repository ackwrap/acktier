# AckTier Go SDK guide

AckTier provides two public Go packages for integrating encrypted overlay networking into services, multiplayer tools, and custom clients.

| Package | Interface | Privileges or driver | Use case |
| :--- | :--- | :--- | :--- |
| `github.com/ackwrap/acktier/pkg/acknet` | Similar to Tailscale `tsnet` | None. Runs in userspace. | Use `Listen`, `Dial`, `HTTPClient`, or `SOCKS5` from an application. |
| `github.com/ackwrap/acktier/pkg/client` | Embedded node and control SDK | Depends on the system TUN, custom TUN, or memory mode | Embed a desktop or mobile node using a `PacketDevice`, control `acktierd`, or administer a center. |

## 1. Embed userspace networking with `pkg/acknet`

An AckTier application gets an overlay IP such as `100.64.x.y`, end-to-end encryption, UDP/TCP/QUIC/WSS transport, multi-hop relaying, and MagicDNS. This package keeps networking in userspace and can run without Wintun, elevated privileges, or host route changes.

To join an existing center, obtain an authentic `trust.json` and submit a join request. Keep persistent node state. `AuthKey` permits a request and the owner signs the approval. See the [owner guide](OWNER_CONTROL.md).

### 1.1 Listen for HTTP or RPC traffic

```go
package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/ackwrap/acktier/pkg/acknet"
)

func main() {
	srv := &acknet.Server{
		Hostname:       "order-service",
		ControlURL:     "http://127.0.0.1:8080",
		AuthKey:        "ackkey-your-preauth-key",
		StateDir:       "./data/order-service",
		OwnerTrustFile: "./trust.json",
		RequireOwner:   true,
	}
	defer srv.Close()

	// Create a standard net.Listener on port 8080 of the overlay address.
	ln, err := srv.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello from AckTier MagicDNS node! Remote=%s\n", r.RemoteAddr)
	})

	log.Fatal(http.Serve(ln, mux))
}
```

### 1.2 Reach peers and routed subnets

```go
cliNode := &acknet.Server{
	Hostname:       "api-caller",
	ControlURL:     "http://127.0.0.1:8080",
	AuthKey:        "ackkey-your-preauth-key",
	StateDir:       "./data/api-caller",
	OwnerTrustFile: "./trust.json",
	RequireOwner:   true,
}
defer cliNode.Close()

// 1. Use the built-in HTTP client with a MagicDNS name or a routed subnet address.
resp, err := cliNode.HTTPClient().Get("http://order-service.ack.internal:8080/hello")

// 2. Use a standard net.Conn for a service such as a database, SSH, or game server.
conn, err := cliNode.Dial(ctx, "tcp", "192.168.50.10:5432")

// 3. Expose a local SOCKS5 proxy for browsers or other processes.
socksLn, err := cliNode.ListenSOCKS5("127.0.0.1:1080")
```

## 2. Embed or manage an AckTier node with `pkg/client`

### 2.1 Embed a full node with `client.NewNode`

```go
cfg := client.DefaultNodeConfig("./data/my-client.json")
cfg.Hostname = "my-workstation"
cfg.TUNMode = client.TUNAuto // Try Wintun, TUN, or utun, then fall back to memory.
cfg.OwnerTrustFile = "./trust.json"
cfg.RequireOwner = true

node, err := client.NewNode(cfg)
if err != nil {
	log.Fatal(err)
}
defer node.Close()

// Subscribe to state changes for live updates, such as in a desktop client.
unsub := node.Subscribe(func(ev client.Event) {
	log.Printf("Event=%s State=%s IP=%s", ev.Type, ev.Status.State, ev.Status.IPv4)
})
defer unsub()

nm, err := node.Up(ctx, client.UpOptions{
	ServerURL: "http://127.0.0.1:8080",
	AuthKey:   "ackkey-...",
	CanRelay:  true,
})
```

After state pins the owner public key, `OwnerTrustFile` is optional and owner verification remains required. If coordination is temporarily unavailable, by default the node keeps its last verified authorization for at most four hours and only until its signed expiry. Set `ControlLeaseTTL` to tune the lease (`0` uses the default, and the minimum is `time.Minute`). Signed revocations take effect on receipt. Center `401` and `403` responses deny coordination.

### 2.2 Control a local `acktierd` with `client.DaemonClient`

```go
dc := client.NewDaemonClient(client.DefaultLocalAPIURL, nil)
status, _ := dc.Status(ctx)
meshRoutes, _ := dc.Mesh(ctx)
netReport, _ := dc.NetCheck(ctx)
pingRes, _ := dc.Ping(ctx, "order-service", 3*time.Second)
```

### 2.3 Administer a center with `client.AdminClient`

```go
admin := client.NewAdminClient("http://127.0.0.1:8080", "adm_token", nil)
key, _ := admin.CreatePreAuthKey(ctx, client.CreateKeyOptions{Label: "ci-worker", Reusable: true})
requests, _ := admin.OwnerJoinRequests(ctx) // Verify each device's public key before signing.
// env is a types.OwnerAuthorization loaded from the owner's signed authorization.json.
version, err := admin.PublishOwnerAuthorization(ctx, env)
```

# AckTier Go SDK 接入指南

AckTier 将全部客户端能力封装为两个对外公开、零 `internal` 泄漏的标准 Go SDK 包，方便任何第三方业务系统、微服务、游戏联机工具或自研桌面客户端直接 `import` 集成：

| SDK 包路径 | 对标模型 | 是否需要管理员/网卡驱动 | 适用场景 |
| :--- | :--- | :--- | :--- |
| `github.com/acktier/acktier/pkg/acknet` | Tailscale `tsnet` | **不需要**（100% 纯用户态） | 在任意 Go 服务内直接 `Listen` / `Dial` / `HTTPClient` / `SOCKS5` 接入加密组网 |
| `github.com/acktier/acktier/pkg/client` | 嵌入式节点 + 控制 SDK | 可选（支持系统网卡、自定义 TUN、内存态） | 自研桌面 GUI、移动 VPN 壳（传入自定义 `PacketDevice` fd）、控制 `acktierd` 或管理控制端 |

---

## 1. `pkg/acknet`：免特权应用内虚拟网络 SDK（推荐）

无需安装 `Wintun` 驱动、无需 `sudo`/管理员权限、不修改宿主机路由表，几行代码即可让普通 Go 程序获得专属虚拟 IP（`100.64.x.y`）、端到端加密、多协议抗封锁传输（UDP/TCP/QUIC/WSS）、智能多跳中继与 MagicDNS 解析能力：

加入已部署的中心时，先按[所有者架构](OWNER_CONTROL.md)取得可信的 `trust.json` 并提交申请。SDK 节点需要持久状态；`AuthKey` 只允许提交申请，不代替签名批准。

### 1.1 在组网内暴露 HTTP / RPC 服务 (`srv.Listen`)

```go
package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/acktier/acktier/pkg/acknet"
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

	// 直接在虚拟 IP 的 8080 端口创建标准 net.Listener
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

### 1.2 通过 MagicDNS 访问对端节点或内网子网 (`srv.HTTPClient` / `srv.Dial`)

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

// 1. 直接使用内置 *http.Client 请求 MagicDNS 域名或 Subnet Router 内网地址
resp, err := cliNode.HTTPClient().Get("http://order-service.ack.internal:8080/hello")

// 2. 或获取标准 net.Conn 访问任意 TCP / UDP 服务（如数据库、SSH、游戏服）
conn, err := cliNode.Dial(ctx, "tcp", "192.168.50.10:5432")

// 3. 一键在本机开启 SOCKS5 代理桥接（供浏览器或非 Go 进程免网卡接入组网）
socksLn, err := cliNode.ListenSOCKS5("127.0.0.1:1080")
```

---

## 2. `pkg/client`：完整节点嵌入、守护进程 IPC 与控制端管理 SDK

### 2.1 在自研客户端中直接嵌入完整虚拟网卡节点 (`client.NewNode`)

```go
cfg := client.DefaultNodeConfig("./data/my-client.json")
cfg.Hostname = "my-workstation"
cfg.TUNMode = client.TUNAuto // 自动尝试系统 Wintun/TUN/utun，无权限时回退内存网卡
cfg.OwnerTrustFile = "./trust.json"
cfg.RequireOwner = true

node, err := client.NewNode(cfg)
if err != nil {
	log.Fatal(err)
}
defer node.Close()

// 订阅状态变更事件（非常适合桌面 GUI 实时刷新界面）
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

节点状态已固定公钥后可省略 `OwnerTrustFile`，不能自动退回无签名模式。控制端暂时失联时，默认保留最后确认的授权最多 4 小时，且不超过签名有效期。可以通过 `ControlLeaseTTL` 调整（`0` 使用默认值，最短 `time.Minute`）。所有者签名撤权会立即生效；中心 `401` / `403` 不属于签名撤权。

### 2.2 控制本地 `acktierd` 守护进程 (`client.DaemonClient`)

```go
dc := client.NewDaemonClient(client.DefaultLocalAPIURL, nil)
status, _ := dc.Status(ctx)
meshRoutes, _ := dc.Mesh(ctx)
netReport, _ := dc.NetCheck(ctx)
pingRes, _ := dc.Ping(ctx, "order-service", 3*time.Second)
```

### 2.3 编程化管理 `acktier-server` 控制端 (`client.AdminClient`)

```go
admin := client.NewAdminClient("http://127.0.0.1:8080", "adm_token", nil)
key, _ := admin.CreatePreAuthKey(ctx, client.CreateKeyOptions{Label: "ci-worker", Reusable: true})
requests, _ := admin.OwnerJoinRequests(ctx) // 核对公钥，不要按名字盲签
// env 是从所有者本地签发的 authorization.json 读取的 types.OwnerAuthorization。
version, err := admin.PublishOwnerAuthorization(ctx, env)
```

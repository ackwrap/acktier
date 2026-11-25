# AckTier

**AckTier** 是一款基于 **Go** 构建的跨平台新一代异地组网（Overlay Mesh SD-WAN）系统，融合 **Tailscale** 的集中控制与零信任治理体验，以及 **EasyTier** 的多协议抗封锁传输与对等节点多跳智能中继能力。

完整架构设计与分阶段路线图详见 [docs/PROJECT_PLAN.md](docs/PROJECT_PLAN.md)；系统能力矩阵与自动切换/自动中继机制详见 [docs/CAPABILITIES.md](docs/CAPABILITIES.md)；Go SDK 接入示例详见 [docs/SDK_GUIDE.md](docs/SDK_GUIDE.md)。

## 核心组件与公开 Go SDK

- `pkg/acknet`：**免管理员权限/免网卡驱动的应用内嵌虚拟网络 SDK**（对标 Tailscale `tsnet`，提供标准 `Listen`、`Dial`、`ListenPacket`、`HTTPClient`、`ListenSOCKS5`）
- `pkg/client`：**客户端完整节点嵌入、守护进程控制 (`DaemonClient`) 与管理端 (`AdminClient`) Go SDK**（详见 [docs/SDK_GUIDE.md](docs/SDK_GUIDE.md)）
- `cmd/acktier-server`：中心控制端（设备鉴权、IPAM 地址池、NetMap 实时快照推送、零信任 ACL 编译器、内置双端口 STUN 与加密帧 Relay 服务）
- `cmd/acktierd`：客户端后台守护进程（跨平台虚拟网卡 TUN、X25519 + AES-256-GCM 端到端加密、UDP/TCP/QUIC/WSS 多协议传输、对等多跳网格中继、MagicDNS、Subnet Router / Exit Node）
- `cmd/acktier`：跨平台命令行管理工具（`up`、`down`、`status`、`mesh`、`netcheck`、`dns`、`exit-node`、`ping`、`route`、`acl`）

## 快速开始 (开发预览)

```bash
# 1. 编译全部核心组件
go build -o bin/ ./cmd/...

# 2. 启动本机控制端 (生成的凭据见 ./data/server-credentials.json，日志默认脱敏)
./bin/acktier-server -listen 127.0.0.1:8080 -stun 127.0.0.1:3478 -stun-alt 127.0.0.1:3479

# 3. 在本机用回环 UDP 联调（多实例各用独立的 -state 和 -api）
./bin/acktierd -state ./data/node1.json -tun memory -upnp=false -lan-discovery=false \
  -udp 127.0.0.1:0 -tcp= -quic= -wss=
./bin/acktier up --server http://127.0.0.1:8080 --auth-key <PRE_AUTH_KEY>

# 4. 查看组网状态与对等节点
./bin/acktier status
```

### 安全配置与升级

- 非回环控制/中心中继连接使用证书验证的 TLS。服务端配置 `-tls-cert`、`-tls-key`，并让 `-public-host` 与证书匹配；使用私有 CA 时，客户端指定 `-tls-ca`。不要在生产使用 `-insecure-http` 或 `-insecure-remote-api`。
- 管理员调用 `AdminClient.RekeyNode` 会撤销旧数据面公钥。可直接指定新公钥；仅换令牌时，节点会退出拓扑，直到使用新令牌和新公钥完成恢复。
- 控制流无消息满 1 分钟会重连，不会因此清空数据面。客户端默认可继续使用最后确认的拓扑和 ACL 最多 4 小时；可用 `acktierd -control-lease-ttl` 调整（最低 1 分钟）。失联期间收不到撤权更新；收到当前会话的 `401` / `403` 则立即撤权，不等租约到期。
- ACL 的 `autogroup:internet` 不包含组网、私网、获批子网、文档网段和基准测试网段。测试地址或 Fake-IP 需要单独按目标和端口授权，例如 `198.18.0.10:443`。
- 对等多跳中继的新帧与旧节点不互通，升级时请同步更新控制端和节点。
- 将状态和凭据文件存放在非授权用户不可写的目录中。已经进入旧版日志或经明文传输的令牌、入网密钥需要另行轮换。

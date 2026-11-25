# AckTier

**AckTier** 是一款基于 **Go** 构建的跨平台新一代异地组网（Overlay Mesh SD-WAN）系统，融合 **Tailscale** 的集中控制与零信任治理体验，以及 **EasyTier** 的多协议抗封锁传输与对等节点多跳智能中继能力。

完整架构设计与分阶段路线图详见 [docs/PROJECT_PLAN.md](docs/PROJECT_PLAN.md)；系统能力矩阵与自动切换/自动中继机制详见 [docs/CAPABILITIES.md](docs/CAPABILITIES.md)；Go SDK 接入示例详见 [docs/SDK_GUIDE.md](docs/SDK_GUIDE.md)。

## 核心组件与公开 Go SDK

- `pkg/acknet`：**免管理员权限/免网卡驱动的应用内嵌虚拟网络 SDK**（对标 Tailscale `tsnet`，提供标准 `Listen`、`Dial`、`ListenPacket`、`HTTPClient`、`ListenSOCKS5`）
- `pkg/client`：**客户端完整节点嵌入、守护进程控制 (`DaemonClient`) 与管理端 (`AdminClient`) Go SDK**（详见 [docs/SDK_GUIDE.md](docs/SDK_GUIDE.md)）
- `cmd/acktier-server`：中心控制端（设备鉴权、IPAM 地址池、NetMap 实时增量推送、零信任 ACL 编译器、内置双端口 STUN 与加密帧 Relay 服务）
- `cmd/acktierd`：客户端后台守护进程（跨平台虚拟网卡 TUN、X25519 + AES-256-GCM 端到端加密、UDP/TCP/QUIC/WSS 多协议传输、对等多跳网格中继、MagicDNS、Subnet Router / Exit Node）
- `cmd/acktier`：跨平台命令行管理工具（`up`、`down`、`status`、`mesh`、`netcheck`、`dns`、`exit-node`、`ping`、`route`、`acl`）

## 快速开始 (开发预览)

```bash
# 1. 编译全部核心组件
go build -o bin/ ./cmd/...

# 2. 启动中心控制端 (首次启动会自动输出 Admin Token 与初始 PreAuthKey)
./bin/acktier-server -listen 127.0.0.1:8080 -stun 127.0.0.1:3478

# 3. 启动客户端守护进程并加入组网
./bin/acktierd -state ./data/node1.json
./bin/acktier up --server http://127.0.0.1:8080 --auth-key <PRE_AUTH_KEY>

# 4. 查看组网状态与对等节点
./bin/acktier status
```

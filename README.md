# AckTier

**AckTier** 是一款基于 **Go** 构建的跨平台新一代异地组网（Overlay Mesh SD-WAN）系统，融合 **Tailscale** 的集中控制与零信任治理体验，以及 **EasyTier** 的多协议抗封锁传输与对等节点多跳智能中继能力。

完整架构设计与分阶段路线图详见 [docs/PROJECT_PLAN.md](docs/PROJECT_PLAN.md)。

## 核心组件

- `cmd/acktier-server`：中心控制端（设备鉴权、IPAM 地址池、NetMap 实时增量推送、内置 STUN 与加密帧 Relay 兜底服务、管理 API）
- `cmd/acktierd`：客户端后台守护进程（跨平台虚拟网卡 TUN、X25519 + AEAD 端到端加密、UDP 直连与智能中继路由、LocalAPI 服务）
- `cmd/acktier`：跨平台命令行管理工具（管理本地 `acktierd` 状态、节点列表、组网启停与控制端密钥管理）

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

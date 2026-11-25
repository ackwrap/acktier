# AckTier

**AckTier** 是一款基于 **Go** 构建的跨平台新一代异地组网（Overlay Mesh SD-WAN）系统，融合 **Tailscale** 的集中控制与零信任治理体验，以及 **EasyTier** 的多协议抗封锁传输与对等节点多跳智能中继能力。

完整架构设计与分阶段路线图详见 [docs/PROJECT_PLAN.md](docs/PROJECT_PLAN.md)；系统能力矩阵与自动切换/自动中继机制详见 [docs/CAPABILITIES.md](docs/CAPABILITIES.md)；Go SDK 接入示例详见 [docs/SDK_GUIDE.md](docs/SDK_GUIDE.md)。

## 核心组件与公开 Go SDK

- `pkg/acknet`：**免管理员权限/免网卡驱动的应用内嵌虚拟网络 SDK**（对标 Tailscale `tsnet`，提供标准 `Listen`、`Dial`、`ListenPacket`、`HTTPClient`、`ListenSOCKS5`）
- `pkg/client`：**客户端完整节点嵌入、守护进程控制 (`DaemonClient`) 与管理端 (`AdminClient`) Go SDK**（详见 [docs/SDK_GUIDE.md](docs/SDK_GUIDE.md)）
- `cmd/acktier-server`：中心协调端（Web 初始化与管理、入网申请、签名授权与连接提示分发、STUN、中继）
- `cmd/acktierd`：客户端后台守护进程（跨平台虚拟网卡 TUN、X25519 + AES-256-GCM 端到端加密、UDP/TCP/QUIC/WSS 多协议传输、对等多跳网格中继、MagicDNS、Subnet Router / Exit Node）
- `cmd/acktier`：跨平台命令行管理工具（节点操作与诊断、`owner` 本地签发和发布）

## 快速开始 (开发预览)

```bash
# 1. 编译全部核心组件
go build -o bin/ ./cmd/...

# 2. 启动本机中心（凭据见 ./data/server-credentials.json，日志默认脱敏）
./bin/acktier-server -listen 127.0.0.1:8080 -stun= -stun-alt=

# 3. 在选定的所有者电脑初始化。打开 http://127.0.0.1:8080/admin/，
#    用凭据文件中的 adminToken 登录，只上传 trust.json 完成绑定
./bin/acktier owner init --dir ./data/owner
```

绑定后，在管理台生成一个入网申请码。下面以同机联调为例；生产节点应从所有者处独立取得 `trust.json`。

```bash
# 4. 在另一个终端启动本机节点；多实例各用独立的 -state 和 -api
./bin/acktierd -owner-trust ./data/owner/trust.json -state ./data/node1.json -tun memory -upnp=false -lan-discovery=false \
  -udp 127.0.0.1:0 -tcp= -quic= -wss=

# 5. 提交申请（未签发时会提示等待所有者批准）
./bin/acktier up --server http://127.0.0.1:8080 --auth-key "<PRE_AUTH_KEY>"
```

在管理台查看申请；在所有者电脑核对公钥并签发，然后回到管理台上传 `authorization.json`。节点再运行 `acktier up`。完整步骤和策略样例见[所有者架构](docs/OWNER_CONTROL.md)。

### 安全配置与升级

- 非回环控制/中心中继连接使用证书验证的 TLS。服务端配置 `-tls-cert`、`-tls-key`，节点使用与证书匹配的控制端 URL；使用私有 CA 时指定 `-tls-ca`。不要在生产使用 `-insecure-http` 或 `-insecure-remote-api`。
- 中心首次启动即提供 `/admin/`，但绑定所有者前暂停节点入网和中继。管理台只允许 HTTPS 或本机回环 HTTP；也可用 `-owner-trust` 自动配置。中心失陷仍可能阻断连接或扣住更新，但不能伪造入网、换钥、ACL 或路由授权。敏感服务仍应使用独立的应用层认证。
- 控制流无消息满 1 分钟会重连。失联后节点默认最多沿用现有授权 4 小时（`-control-lease-ttl` 可调），且不能超过签名到期时间；收到已签撤权会立即生效。
- ACL 的 `autogroup:internet` 不包含组网、私网、获批子网、文档网段和基准测试网段。测试地址或 Fake-IP 需要单独按目标和端口授权，例如 `198.18.0.10:443`。
- 对等多跳中继的新帧与旧节点不互通，升级时请同步更新控制端和节点。
- 将状态和凭据文件存放在非授权用户不可写的目录中。已经进入旧版日志或经明文传输的令牌、入网密钥需要另行轮换。

# AckTier

**AckTier** 是一款基于 **Go** 构建的跨平台新一代异地组网（Overlay Mesh SD-WAN）系统，融合 **Tailscale** 的集中控制与零信任治理体验，以及 **EasyTier** 的多协议抗封锁传输与对等节点多跳智能中继能力。

项目仓库：[ackwrap/acktier](https://github.com/ackwrap/acktier)。Go 模块路径：`github.com/ackwrap/acktier`。

完整架构设计与分阶段路线图详见 [docs/PROJECT_PLAN.md](docs/PROJECT_PLAN.md)；系统能力矩阵与自动切换/自动中继机制详见 [docs/CAPABILITIES.md](docs/CAPABILITIES.md)；Go SDK 接入示例详见 [docs/SDK_GUIDE.md](docs/SDK_GUIDE.md)。

## 核心组件与公开 Go SDK

- `pkg/acknet`：**免管理员权限/免网卡驱动的应用内嵌虚拟网络 SDK**（对标 Tailscale `tsnet`，提供标准 `Listen`、`Dial`、`ListenPacket`、`HTTPClient`、`ListenSOCKS5`）
- `pkg/client`：**客户端完整节点嵌入、守护进程控制 (`DaemonClient`) 与管理端 (`AdminClient`) Go SDK**（详见 [docs/SDK_GUIDE.md](docs/SDK_GUIDE.md)）
- `cmd/acktier-server`：中心协调端（Web 初始化与管理、入网申请、签名授权与连接提示分发、STUN、中继）
- `cmd/acktierd`：客户端后台守护进程（跨平台虚拟网卡 TUN、X25519 + AES-256-GCM 端到端加密、UDP/TCP/QUIC/WSS 多协议传输、对等多跳网格中继、MagicDNS、Subnet Router / Exit Node）
- `cmd/acktier`：跨平台命令行管理工具（节点操作与诊断、`owner` 本地签发和发布）

## 预编译包安装

中心与客户端分别提供 Windows、Linux 的 x86（32 位）、x86-64 和 ARM64 安装包。中心包提供 `acktier-server` 和所有者签发工具，客户端包提供 `acktierd` 和节点命令行，Windows 客户端包附有官方 Wintun。

从 [GitHub Releases](https://github.com/ackwrap/acktier/releases) 下载对应版本，按照[安装与运维手册](docs/INSTALL.md)校验、解压、部署中心或加入已有组网。手册也包含自启、升级和卸载步骤。

### 构建与发布

在 GitHub 的 Actions 页面手动运行 **AckTier packages** 可获取测试包。每个系统和架构的 Actions 产物包含一份中心包和一份客户端包。

正式发布前，将该版本的英文发布说明提交到 `.github/release-notes/`，例如 `.github/release-notes/v1.2.3.md`。将已验证的提交合入 `main`，再给该提交打标签并推送。以下以发布当前远端 `main` 的 `v1.2.3` 为例。

```sh
git fetch origin main
git tag -a v1.2.3 FETCH_HEAD -m "AckTier v1.2.3"
git push origin refs/tags/v1.2.3
```

工作流在测试和打包全部通过后创建 GitHub Release，并上传 `SHA256SUMS.txt`。`v1.2.3-rc.1` 这类标签会发布为预发行版本。

## 管理台前端 Mock 预览

只改前端时，用 Node.js 22+ 从仓库根目录运行（无需安装 npm 依赖或启动 Go 中心）：

```sh
node scripts/center-mock.mjs
```

打开 [http://127.0.0.1:18081/admin/](http://127.0.0.1:18081/admin/)。默认直接进入管理台，有模拟的拓扑、入网申请、节点能力、ACL 草稿、发布历史和审计数据。编辑 [`internal/server/control/web/`](internal/server/control/web/) 后刷新即可看到变化；样例数据在 [`scripts/center-mock/fixtures.mjs`](scripts/center-mock/fixtures.mjs)。

- 可用 `--scenario empty`、`--scenario expired`、`--scenario setup` 或 `--scenario login` 预览空库、授权过期、首次绑定或登录；登录场景只用演示密码 `mock-preview`。
- 草稿、清单和申请码操作只改变 Mock 进程的内存，重启恢复样例。可从 `/mock/trust.json`、`/mock/authorization.json`、`/mock/controller-trust.json` 下载演示文件；它们不能用于真实中心。请勿输入真实密码或上传私钥。
- `--port 18082` 可换端口；测试命令为 `node --test scripts/center-mock/server.test.mjs`。

## 快速开始 (真实中心)

```bash
# 1. 编译全部核心组件
go build -o bin/ ./cmd/...

# 2. 启动本机中心（节点协调监听 :8080，Web 管理台独立监听回环 :8081；初始密码见 ./data/server-credentials.json）
./bin/acktier-server -listen 127.0.0.1:8080 -admin-listen 127.0.0.1:8081 -stun= -stun-alt=

# 3. 在选定的所有者电脑初始化。打开 http://127.0.0.1:8081/admin/，
#    用凭据文件中的 adminPassword 登录，预览指纹并上传 trust.json 完成绑定
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

Linux 和 Windows 创建的系统虚拟网卡默认名为 `acktier`，可用 `-ifname` 覆盖。同机运行多个系统网卡实例时，为各实例指定不同名称。macOS 使用系统分配的 `utunN`；`-tun memory` 不创建系统网卡。

### 安全配置与升级

- 非回环控制/中心中继连接使用证书验证的 TLS。服务端配置 `-tls-cert`、`-tls-key`，节点使用与证书匹配的控制端 URL；使用私有 CA 时指定 `-tls-ca`。不要在生产使用 `-insecure-http` 或 `-insecure-remote-api`。
- 中心首次启动即提供 `/admin/`，但绑定所有者前暂停节点入网和中继。管理台只允许 HTTPS 或本机回环 HTTP；也可用 `-owner-trust` 自动配置。中心失陷仍可能阻断连接或扣住更新，但不能伪造入网、换钥、ACL 或路由授权。敏感服务仍应使用独立的应用层认证。
- 中心默认使用 `./data/center/server.sqlite`，首次启动直接建库并等待绑定所有者。自定义路径、备份和离线密码重置见[中心存储与备份](docs/OWNER_CONTROL.md#中心存储与备份)。
- 控制流无消息满 1 分钟会重连。失联后节点默认最多沿用现有授权 4 小时（`-control-lease-ttl` 可调），且不能超过签名到期时间；收到已签撤权会立即生效。
- ACL 的 `autogroup:internet` 不包含组网、私网、获批子网、文档网段和基准测试网段。测试地址或 Fake-IP 需要单独按目标和端口授权，例如 `198.18.0.10:443`。
- 对等多跳中继的新帧与旧节点不互通，升级时请同步更新控制端和节点。
- 将状态和凭据文件存放在非授权用户不可写的目录中。已经进入旧版日志或经明文传输的令牌、入网密钥需要另行轮换。

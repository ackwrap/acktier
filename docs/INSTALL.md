# AckTier 安装与运维

从 [AckTier Releases](https://github.com/ackwrap/acktier/releases) 下载与设备和用途匹配的安装包。首次部署依次完成中心启动、所有者绑定、节点入网和授权验收。已有中心时，可直接从[安装客户端](#安装客户端)开始。

## 选择安装包

| 用途 | 包名开头 | 包内程序 |
| --- | --- | --- |
| 部署中心、访问管理台 | `acktier-center-` | `acktier-server`、`acktier` |
| 将 Windows 或 Linux 设备接入组网 | `acktier-client-` | `acktierd`、`acktier`。Windows 包同时提供匹配架构的 `wintun.dll` 和许可证。 |

| 下载项后缀 | 系统 | 处理器 |
| --- | --- | --- |
| `windows-amd64.zip`、`linux-amd64.tar.gz` | Windows、Linux | Intel 或 AMD 64 位（x86-64） |
| `windows-arm64.zip`、`linux-arm64.tar.gz` | Windows、Linux | ARM 64 位（AArch64） |
| `windows-386.zip`、`linux-386.tar.gz` | Windows、Linux | 32 位 x86 |

Windows 在「设置 → 系统 → 系统信息」查看系统类型。Linux 可用 `uname -m` 查看架构，`x86_64`、`aarch64`、`i386` 至 `i686` 分别对应 `amd64`、`arm64`、`386`。压缩包含独立可执行文件，部署机无需安装 Go。

以下命令以 `v1.2.3`、`amd64` 和 `mesh.example.com` 为例。按下载的版本、系统架构和实际中心地址替换，分别在各自设备上操作。

### 校验和解压

把安装包与同一版本的 `SHA256SUMS.txt` 放在同一目录。Windows PowerShell 中计算 SHA-256，与清单中对应文件的值比对。确认一致后，用管理员 PowerShell 将包解压到 `Program Files`。

```powershell
$Version = 'v1.2.3'
$Role = 'client'  # 安装中心时替换为 center
$Name = "acktier-$Role-$Version-windows-amd64"
Get-FileHash -Algorithm SHA256 -LiteralPath ".\$Name.zip"
Select-String -SimpleMatch "$Name.zip" -LiteralPath .\SHA256SUMS.txt
$InstallRoot = Join-Path $env:ProgramFiles 'AckTier'
Expand-Archive -LiteralPath ".\$Name.zip" -DestinationPath $InstallRoot
$Bin = Join-Path $InstallRoot $Name
```

Linux 可以直接校验已下载的对应文件。校验成功后再执行解压命令。

```sh
version=v1.2.3
role=client  # 安装中心时替换为 center
name="acktier-$role-$version-linux-amd64"
sha256sum --ignore-missing --check SHA256SUMS.txt
sudo install -d -m 0755 /opt/acktier
sudo tar -xzf "$name.tar.gz" -C /opt/acktier
bin="/opt/acktier/$name"
```

每个版本进入独立目录。凭据和运行状态应保存在仅允许对应运行账号或管理员访问的目录。后续示例中的 `$Bin` 或 `$bin` 指对应角色的解压目录，新终端需要重新设置。

## 安装中心

### 启动并绑定所有者

在中心主机上先用回环地址启动，部署账号可使用普通权限。服务首次创建中心数据库，向指定凭据文件写入初始 `adminPassword`。文件中的凭据应妥善保管，避免发到聊天、工单或日志中。

**Windows（PowerShell）**

```powershell
$CenterData = Join-Path $env:LOCALAPPDATA 'AckTier\center\private'
$CenterArgs = @(
    '-data', (Join-Path $CenterData 'server.sqlite')
    '-credentials-file', (Join-Path $CenterData 'server-credentials.json')
    '-listen', '127.0.0.1:8080'
    '-admin-listen', '127.0.0.1:8081'
    '-stun=', '-stun-alt='
)
& (Join-Path $Bin 'acktier-server.exe') @CenterArgs
```

**Linux**

```sh
center_data="$HOME/.local/state/acktier-center/private"
"$bin/acktier-server" -data "$center_data/server.sqlite" \
  -credentials-file "$center_data/server-credentials.json" \
  -listen 127.0.0.1:8080 -admin-listen 127.0.0.1:8081 -stun= -stun-alt=
```

在负责签发的可信电脑上解压中心包，用该电脑上的 CLI 初始化。将 `$Bin` 或 `$bin` 设置为该电脑上的解压路径。

```powershell
$OwnerDir = Join-Path $env:LOCALAPPDATA 'AckTier\owner\private'
& (Join-Path $Bin 'acktier.exe') owner init --dir $OwnerDir
```

```sh
owner_dir="$HOME/.local/state/acktier-owner/private"
"$bin/acktier" owner init --dir "$owner_dir"
```

1. 在中心主机浏览器打开 `http://127.0.0.1:8081/admin/`，使用初始密码登录。在初始化页上传上述目录生成的 `trust.json`，按可信来源核对文件和页面显示的公钥指纹后绑定。
2. 在管理台生成入网申请码。通过可信渠道把申请码和所有者的 `trust.json` 发给对应设备。签名私钥文件 `signer.json` 只保留在所有者侧，并作安全备份。

### 开放远程入网

为中心配置公网或内网可达的 DNS，以及匹配该域名的服务器证书。停止回环测试进程，沿用原来的数据库和凭据文件，用以下参数重启。Windows 使用实际证书路径，把参数加到 `$CenterArgs` 中并替换监听地址及关闭 STUN 的参数。

```sh
"$bin/acktier-server" -data "$center_data/server.sqlite" \
  -credentials-file "$center_data/server-credentials.json" \
  -listen 0.0.0.0:8443 -public-host mesh.example.com \
  -admin-listen 127.0.0.1:8081 \
  -tls-cert /etc/acktier/tls/fullchain.pem -tls-key /etc/acktier/tls/privkey.pem
```

| 端口（上例） | 用途及开放范围 |
| --- | --- |
| `8443/TCP` | 节点协调和中心中继，向需要组网的节点开放。节点使用 `https://mesh.example.com:8443` 入网。 |
| `3478/UDP`、`3479/UDP` | 默认 STUN。使用中心 STUN 时向节点开放，并保留两个 UDP 监听。 |
| `8081/TCP` | 管理台与管理 API。默认绑定回环，保留在本机或受控的管理网络。 |

启用 TLS 后，管理台也使用 HTTPS。管理入口须使用与证书匹配的主机名。管理台留在回环时，可通过受控运维通道接入，并将证书域名解析至该通道的本地入口。节点使用私有 CA 时，在 `acktierd` 启动命令里加 `-tls-ca` 和受信任的 CA PEM 文件路径。

## 安装客户端

从所有者处取得可信的 `trust.json`，保存为下文的 `owner-trust.json`。系统 TUN 模式会创建名为 `acktier` 的虚拟网卡。需要另起名称时可用 `-ifname`。安装和入网应使用同一运行账号。

### Windows

以管理员身份打开 PowerShell。检查客户端目录中的 `acktierd.exe` 和同架构 `wintun.dll` 在同一目录。将所有者提供的信任文件复制到受保护的安装目录，由守护进程首次启动时创建私有状态目录。

```powershell
$NodeData = Join-Path $env:ProgramData 'AckTier\client\private'
$Trust = Join-Path (Split-Path -Parent $Bin) 'client-owner-trust.json'
Copy-Item -LiteralPath .\trust.json -Destination $Trust
& (Join-Path $Bin 'acktierd.exe') -tun os -state (Join-Path $NodeData 'state.json') -owner-trust $Trust
```

保持守护进程运行，用同一账号另开管理员 PowerShell 提交申请。把引号内的占位文字换成实际申请码。申请码是凭据，操作时避免录屏、共享终端和保留含申请码的命令历史。

```powershell
& (Join-Path $Bin 'acktier.exe') up --server https://mesh.example.com:8443 --auth-key '<入网申请码>'
```

### Linux

确认 `test -c /dev/net/tun` 成功，且 `ip` 命令可用。系统网卡需要具备 `CAP_NET_ADMIN`，下例通过 `sudo` 运行。创建私有状态目录并安装公钥信任文件后启动守护进程。

```sh
sudo install -d -m 0700 /var/lib/acktier/node-private
sudo install -m 0600 ./trust.json /var/lib/acktier/node-private/owner-trust.json
sudo "$bin/acktierd" -tun os -state /var/lib/acktier/node-private/state.json \
  -owner-trust /var/lib/acktier/node-private/owner-trust.json
```

另开终端，用同一权限和客户端目录提交申请。

```sh
sudo "$bin/acktier" up --server https://mesh.example.com:8443 --auth-key '<入网申请码>'
```

### 批准入网并验收

1. 出现等待批准提示后，在中心管理台「入网申请」核对设备公钥与来源，把待批准设备加入策略草稿。使用实际业务需要的 ACL 源、目的和端口。
2. 从管理台导出完整 `policy.json`，复制到所有者电脑的当前目录。沿用所有者初始化时的变量，在 Windows 执行 `& (Join-Path $Bin 'acktier.exe') owner sign --dir $OwnerDir --policy .\policy.json`，在 Linux 执行 `"$bin/acktier" owner sign --dir "$owner_dir" --policy ./policy.json`。在管理台「签名发布」上传所有者目录中生成的 `authorization.json`。更详细的 ACL 和授权流程见[所有者与策略指南](https://github.com/ackwrap/acktier/blob/main/docs/OWNER_CONTROL.md)。
3. 节点用同一个状态文件重新执行 `acktier up --server https://mesh.example.com:8443`。首次申请的注册凭据保存成功后可直接复用。运行 `acktier status` 查看在线状态及组网地址，用 `acktier ping <节点名或组网 IP>` 验证对端连通，再访问一项 ACL 已授权的实际服务。Windows 使用 `acktier.exe`，Linux 沿用 `sudo`。

## 设置自启

先验证前台启动和入网，再切换为后台运行。客户端已入网后，用相同的 `-state` 启动并传入 `-server https://mesh.example.com:8443` 即可自动连接。保留已有信任文件、TLS 参数和状态路径，避免将入网申请码写入服务配置。

**Windows** 在任务计划程序创建「启动时」任务。程序填写绝对路径的 `acktierd.exe` 或 `acktier-server.exe`，参数填写前面已验证的参数，包含绝对路径的状态、信任和证书文件。选择原运行账号并配置为无需登录即可运行。节点勾选「使用最高权限运行」，中心沿用普通部署账号。在「最后运行结果」确认启动后，从管理台或 `acktier status` 验证。

**Linux** 在 `/etc/systemd/system/acktierd.service` 写入以下示例，替换解压路径和中心地址。沿用前面创建的状态文件与信任文件。

```ini
[Unit]
Description=AckTier node
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=/opt/acktier/acktier-client-v1.2.3-linux-amd64/acktierd -tun=os -state=/var/lib/acktier/node-private/state.json -owner-trust=/var/lib/acktier/node-private/owner-trust.json -server=https://mesh.example.com:8443
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

先停止前台守护进程，再执行以下命令，查看状态及日志。

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now acktierd
sudo systemctl status acktierd
sudo journalctl -u acktierd -n 50
```

中心也可用相同结构创建 `acktier-server.service`。把 `ExecStart` 换成已验证的中心启动命令和绝对路径，在 `[Service]` 中用 `User=` 指定现有的部署账号。该账号需要数据库目录的读写权限，以及 TLS 私钥的读取权限。用 `systemctl enable --now acktier-server` 启动。

## 升级、卸载与故障排查

- **升级**。停止要升级的服务。备份中心 SQLite 数据库和存在的同名日志文件、节点状态，以及所有者签名目录。校验并解压新版，更新服务的程序路径，沿用原状态目录及启动参数。重启后检查管理台、节点在线状态和业务连通。涉及协议变化时按版本说明协调升级中心及节点。
- **卸载**。节点先用 `acktier down` 断开组网，再停止、禁用自启并删除对应安装目录。确认不再使用设备时，在中心通过新签名策略撤销该节点授权。若同时要删除数据，先完成备份或迁移，再单独处理对应的状态目录。
- **中心不可达**。确认节点使用的是协调端口，上例为 `8443`。检查 DNS、证书主机名、系统时间和防火墙。私有 CA 环境核对节点的 `-tls-ca` 路径。
- **节点等待批准**。确认新授权已签名发布并包含该设备的公钥。节点保留首次申请时使用的状态文件，再执行 `acktier up`。
- **系统网卡无法启动**。Windows 检查管理员权限、DLL 路径及架构。Linux 检查 `/dev/net/tun`、`ip` 和 `CAP_NET_ADMIN`。切换到系统服务后仍要使用原来的运行账号和状态路径。
- **节点在线但无法访问业务**。先验证组网连通，再检查目标服务监听地址、防火墙及到目标端口的 ACL。

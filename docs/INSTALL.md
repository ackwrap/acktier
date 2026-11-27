# Install and operate AckTier

Download the bundle that matches your platform and role from [AckTier Releases](https://github.com/ackwrap/acktier/releases). A new deployment starts with the center and owner binding, followed by node enrollment and authorization. If a center is already running, start with [installing a client](#install-a-client).

## Choose a package

| Role | Filename prefix | Contents |
| --- | --- | --- |
| Run a center and its admin console | `acktier-center-` | `acktier-server` and `acktier` |
| Join a Windows or Linux device to the network | `acktier-client-` | `acktierd` and `acktier`. Windows bundles also include the matching `wintun.dll` and its license. |

| Filename suffixes | Operating systems | Architecture |
| --- | --- | --- |
| `windows-amd64.zip`, `linux-amd64.tar.gz` | Windows and Linux | 64-bit Intel or AMD (x86-64) |
| `windows-arm64.zip`, `linux-arm64.tar.gz` | Windows and Linux | 64-bit ARM (AArch64) |
| `windows-386.zip`, `linux-386.tar.gz` | Windows and Linux | 32-bit x86 |

On Windows, check **Settings > System > About** for the system type. On Linux, run `uname -m`. `x86_64` maps to `amd64`, `aarch64` to `arm64`, and `i386` through `i686` to `386`. The packages contain standalone executables and require no Go installation.

The examples use `v1.2.3`, `amd64`, and `mesh.example.com`. Substitute your downloaded version, architecture, and center address as you run each command on its intended host.

### Verify and extract

Put the package and `SHA256SUMS.txt` from the same release in one directory. In PowerShell, compute the package's SHA-256 and compare it with the corresponding line in the checksum file. After they match, use an elevated PowerShell to extract the package to `Program Files`.

```powershell
$Version = 'v1.2.3'
$Role = 'client'  # Use center for a center installation.
$Name = "acktier-$Role-$Version-windows-amd64"
Get-FileHash -Algorithm SHA256 -LiteralPath ".\$Name.zip"
Select-String -SimpleMatch "$Name.zip" -LiteralPath .\SHA256SUMS.txt
$InstallRoot = Join-Path $env:ProgramFiles 'AckTier'
Expand-Archive -LiteralPath ".\$Name.zip" -DestinationPath $InstallRoot
$Bin = Join-Path $InstallRoot $Name
```

On Linux, verify the downloaded packages with `sha256sum` before extracting.

```sh
version=v1.2.3
role=client  # Use center for a center installation.
name="acktier-$role-$version-linux-amd64"
sha256sum --ignore-missing --check SHA256SUMS.txt
sudo install -d -m 0755 /opt/acktier
sudo tar -xzf "$name.tar.gz" -C /opt/acktier
bin="/opt/acktier/$name"
```

Each version has its own directory. Keep credentials and run state in a protected directory accessible to the service account or administrators. In the following commands, `$Bin` or `$bin` refers to the extracted directory for the current role. Set it again in each new terminal.

## Install the center

### Start the center and bind the owner

Start with loopback listeners on the center host. A regular deployment account can run the center. On first start, it creates the database and writes the initial `adminPassword` to the specified credentials file. Keep those credentials out of chats, tickets, and logs.

**Windows PowerShell**

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

Extract the center bundle on the trusted computer that will sign authorizations. Set `$Bin` or `$bin` to the extracted path on that computer and initialize the owner.

```powershell
$OwnerDir = Join-Path $env:LOCALAPPDATA 'AckTier\owner\private'
& (Join-Path $Bin 'acktier.exe') owner init --dir $OwnerDir
```

```sh
owner_dir="$HOME/.local/state/acktier-owner/private"
"$bin/acktier" owner init --dir "$owner_dir"
```

1. Open `http://127.0.0.1:8081/admin/` on the center host and sign in with the initial password. Upload the generated `trust.json` on the setup screen. Verify its source and the public key fingerprint before binding.
2. Create an enrollment key in the console. Deliver the key and the owner's `trust.json` to the intended device through a trusted channel. Keep `signer.json` on the owner computer and back it up securely.

### Enable remote enrollment

Set up DNS for a name the nodes can reach and obtain a server certificate for that name. Stop the loopback process, then restart the center with the same database and credentials file and the options below. On Windows, use the actual certificate paths in `$CenterArgs` and replace the loopback listener and STUN overrides as shown.

```sh
"$bin/acktier-server" -data "$center_data/server.sqlite" \
  -credentials-file "$center_data/server-credentials.json" \
  -listen 0.0.0.0:8443 -public-host mesh.example.com \
  -admin-listen 127.0.0.1:8081 \
  -tls-cert /etc/acktier/tls/fullchain.pem -tls-key /etc/acktier/tls/privkey.pem
```

| Port in the example | Purpose and access |
| --- | --- |
| `8443/TCP` | Node coordination and center relay. Allow access from participating nodes, which use `https://mesh.example.com:8443`. |
| `3478/UDP` and `3479/UDP` | Default STUN ports. Keep both listeners and allow access from nodes when using the center's STUN service. |
| `8081/TCP` | Admin console and API. Keep this loopback listener local or place the management endpoint on a restricted network. |

After enabling TLS, the admin console also uses HTTPS. Access it using the certificate hostname. For a loopback-only management listener, connect through an authorized tunnel and resolve the certificate name to the tunnel's local endpoint. For a private CA, pass `-tls-ca` and the trusted CA PEM path to `acktierd`.

## Install a client

Obtain the owner's authentic `trust.json`. System TUN mode creates a virtual interface named `acktier`. Use `-ifname` to set a different name when needed. Use the same operating-system account to run the daemon and enroll the node.

### Windows

Open an elevated PowerShell. Check that `acktierd.exe` and the matching architecture's `wintun.dll` are in the same directory. Copy the trust file to the protected installation tree. The daemon creates its private state directory when it starts.

```powershell
$NodeData = Join-Path $env:ProgramData 'AckTier\client\private'
$Trust = Join-Path (Split-Path -Parent $Bin) 'client-owner-trust.json'
Copy-Item -LiteralPath .\trust.json -Destination $Trust
& (Join-Path $Bin 'acktierd.exe') -tun os -state (Join-Path $NodeData 'state.json') -owner-trust $Trust
```

Leave the daemon running and use a second elevated PowerShell under the same account to join. Substitute the actual enrollment key. Keep it out of shared terminals, screen recordings, and persistent shell history.

```powershell
& (Join-Path $Bin 'acktier.exe') up --server https://mesh.example.com:8443 --auth-key '<ENROLLMENT_KEY>'
```

### Linux

Verify that `test -c /dev/net/tun` succeeds and that `ip` is available. System TUN requires `CAP_NET_ADMIN`. The example uses `sudo`. Create the private state directory and install the trust file before starting the daemon.

```sh
sudo install -d -m 0700 /var/lib/acktier/node-private
sudo install -m 0600 ./trust.json /var/lib/acktier/node-private/owner-trust.json
sudo "$bin/acktierd" -tun os -state /var/lib/acktier/node-private/state.json \
  -owner-trust /var/lib/acktier/node-private/owner-trust.json
```

Open a second terminal and submit the request with the same privileges and client directory.

```sh
sudo "$bin/acktier" up --server https://mesh.example.com:8443 --auth-key '<ENROLLMENT_KEY>'
```

### Approve the node and verify connectivity

1. When the node reports that approval is pending, open **Join requests** in the center console. Verify the public key and its source, then add the requester to a draft. Use ACL sources, destinations, and ports appropriate for the services it needs.
2. Export the complete `policy.json` and copy it to the current directory on the owner computer. Reuse the variables from owner setup. On Windows, run `& (Join-Path $Bin 'acktier.exe') owner sign --dir $OwnerDir --policy .\policy.json`. On Linux, run `"$bin/acktier" owner sign --dir "$owner_dir" --policy ./policy.json`. Open **Publish authorization** in the console and upload `authorization.json` from the owner directory. See the [owner and policy guide](https://github.com/ackwrap/acktier/blob/main/docs/OWNER_CONTROL.md) for details.
3. Using the original state file, run `acktier up --server https://mesh.example.com:8443` again on the node. It can reuse persisted registration credentials. Run `acktier status` to check the connection and overlay address. Use `acktier ping <node-name-or-overlay-IP>` to test a peer, then access a service allowed by the ACL. Use `acktier.exe` on Windows and `sudo` as shown on Linux.

## Start automatically

Verify that the node starts and can join in the foreground before configuring a service. Once enrolled, start with the same `-state` and add `-server https://mesh.example.com:8443` to connect automatically. Keep the trust and TLS settings and omit the enrollment key from service configuration.

**Windows.** In Task Scheduler, create an **At startup** task. Use the absolute path to `acktierd.exe` or `acktier-server.exe`. Supply the verified arguments and absolute paths to state, trust, and certificate files. Run the task as the original account even when it is logged out. Select **Run with highest privileges** for a node and use the regular deployment account for a center. Check **Last Run Result**, then verify the console or run `acktier status`.

**Linux.** Write the following example to `/etc/systemd/system/acktierd.service`. Replace the executable path and center URL. Use the state and trust files created above.

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

Stop the foreground daemon, enable the service, and check its status and logs.

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now acktierd
sudo systemctl status acktierd
sudo journalctl -u acktierd -n 50
```

For the center, use the same structure in `acktier-server.service`. Set `ExecStart` to the verified start command with absolute paths and add `User=` under `[Service]` for the existing deployment account. The account needs write access to the database directory and read access to the TLS private key. Run `systemctl enable --now acktier-server` to start it.

## Upgrade, remove, and troubleshoot

- **Upgrade.** Stop the service you intend to upgrade. Back up the center SQLite database with any companion journal files, the node state, and the owner signing directory. Verify and extract the new package, then update the service executable path. Reuse the original state and options. After restarting, check the console, node status, and service traffic. Follow the release notes for coordinated center and node upgrades when protocols change.
- **Remove.** Run `acktier down` to disconnect a node. Stop the process, disable automatic startup, and remove the corresponding version's program directory. For a decommissioned device, publish a signed policy revoking its membership. Back up or migrate any retained data before removing the state directory.
- **Center unreachable.** Confirm that the node uses the coordination port, which is `8443` in the example. Check DNS, the TLS certificate name, the system clock, and firewalls. For a private CA, confirm the node's `-tls-ca` path.
- **Waiting for approval.** Verify that the active signed authorization contains the device's public key. Reuse the state file from the initial request and run `acktier up` again.
- **System TUN fails to start.** On Windows, check elevation, DLL location, and architecture. On Linux, check `/dev/net/tun`, `ip`, and `CAP_NET_ADMIN`. Keep the service account and state path consistent when moving to a service.
- **Node is online but a service is unreachable.** Verify overlay connectivity, then check the target service's bind address, firewall, and ACL for the target port.

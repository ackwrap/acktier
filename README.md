# AckTier

**AckTier** is a cross-platform overlay mesh network written in Go. It combines centralized coordination and owner-signed access policy with multiprotocol peer connections and automatic multi-hop relays.

The repository is [ackwrap/acktier](https://github.com/ackwrap/acktier). The Go module is `github.com/ackwrap/acktier`.

See the [architecture and roadmap](docs/PROJECT_PLAN.md), [capability matrix and failover behavior](docs/CAPABILITIES.md), and [Go SDK guide](docs/SDK_GUIDE.md).

## Components and Go SDKs

- `pkg/acknet` embeds an unprivileged, userspace virtual network in an application. It provides `Listen`, `Dial`, `ListenPacket`, `HTTPClient`, and `ListenSOCKS5`.
- `pkg/client` embeds full nodes and provides SDKs for the local daemon (`DaemonClient`) and center administration (`AdminClient`). See the [Go SDK guide](docs/SDK_GUIDE.md).
- `cmd/acktier-server` provides the center, including Web setup and administration, join requests, distribution of signed authorizations and connection hints, STUN, and relaying.
- `cmd/acktierd` runs the node daemon. It supports system TUN devices, X25519 and AES-256-GCM end-to-end encryption, UDP/TCP/QUIC/WSS, multi-hop peer relays, MagicDNS, subnet routing, and exit nodes.
- `cmd/acktier` provides node control and diagnostics as well as the `owner` commands for local signing and publication.

## Install prebuilt packages

Center and client bundles are available for Windows and Linux on x86 (32-bit), x86-64, and ARM64. The center bundle includes `acktier-server` and the owner CLI. The client bundle includes `acktierd` and the node CLI. Windows client bundles also include the official Wintun DLL.

Download the appropriate bundle from [GitHub Releases](https://github.com/ackwrap/acktier/releases). The [installation and operations guide](docs/INSTALL.md) covers verification, center setup, joining a network, services, upgrades, and removal.

### Build and release

Run **AckTier packages** from the GitHub Actions tab to get test bundles. The artifact for each operating system and architecture contains one center bundle and one client bundle.

For a release, commit English notes for that version to `.github/release-notes/`. For example, use `.github/release-notes/v1.2.3.md` for `v1.2.3`. Merge the validated commit to `main`, then create and push its version tag. These commands tag the current remote `main` as `v1.2.3`.

```sh
git fetch origin main
git tag -a v1.2.3 FETCH_HEAD -m "AckTier v1.2.3"
git push origin refs/tags/v1.2.3
```

Once tests and packaging pass, the workflow creates the GitHub Release and uploads `SHA256SUMS.txt`. Tags such as `v1.2.3-rc.1` create prereleases.

## Preview the center console

Run the mock console from the repository root with Node.js 22 or later. It needs no npm dependencies or running Go center.

```sh
node scripts/center-mock.mjs
```

Open [http://127.0.0.1:18081/admin/](http://127.0.0.1:18081/admin/). The default scenario shows example topology, join requests, node capabilities, ACL drafts, release history, and audit records. Refresh to see changes to [the Web UI](internal/server/control/web/). The [fixtures](scripts/center-mock/fixtures.mjs) define the example data.

The console defaults to English. Use the **Language** selector on the sign-in, setup, or management screen to switch between English and Simplified Chinese. The browser remembers your choice.

- Use `--scenario empty`, `--scenario expired`, `--scenario setup`, or `--scenario login` to preview an empty center, expired authorization, first-time setup, or sign-in. Use `mock-preview` as the demonstration password in the sign-in scenario.
- Changes to drafts, inventories, and enrollment keys are held in memory. Restart the mock to restore its initial data. The files at `/mock/trust.json`, `/mock/authorization.json`, and `/mock/controller-trust.json` are for the mock only. Keep production passwords and private keys out of the preview.
- Use `--port 18082` to select another port. Run `node --test scripts/center-mock/server.test.mjs` to test the mock.

## Quick start with a real center

```bash
# 1. Build the three executables.
go build -o bin/ ./cmd/...

# 2. Start the center with separate loopback listeners for nodes and the console.
#    The initial password is in ./data/server-credentials.json.
./bin/acktier-server -listen 127.0.0.1:8080 -admin-listen 127.0.0.1:8081 -stun= -stun-alt=

# 3. Initialize the selected owner. Open http://127.0.0.1:8081/admin/.
#    Sign in with adminPassword from the credentials file, verify the fingerprint,
#    and upload trust.json to bind the owner.
./bin/acktier owner init --dir ./data/owner
```

After binding the owner, create an enrollment key in the console. This example runs on a single host. Production nodes should obtain `trust.json` directly from the owner over a trusted channel.

```bash
# 4. Start a node in a separate terminal. Give each instance its own -state and -api.
./bin/acktierd -owner-trust ./data/owner/trust.json -state ./data/node1.json -tun memory -upnp=false -lan-discovery=false \
  -udp 127.0.0.1:0 -tcp= -quic= -wss=

# 5. Submit a join request and wait for the owner to approve it.
./bin/acktier up --server http://127.0.0.1:8080 --auth-key "<PRE_AUTH_KEY>"
```

Review the join request in the console. Verify the node public key and sign the authorization on the owner's computer, then upload `authorization.json` to the center. Run `acktier up` again on the node. See the [owner and center guide](docs/OWNER_CONTROL.md) for the full procedure and a policy example.

The default system interface name is `acktier` on Linux and Windows. Use `-ifname` to assign a different name to each instance on the same host. macOS assigns a `utunN` interface. With `-tun memory`, the daemon uses an in-memory device.

### Security and upgrades

- Use verified TLS for control and center relay connections outside loopback. Configure `-tls-cert` and `-tls-key` on the server and use a center URL that matches the certificate. Pass `-tls-ca` for a private CA. Reserve `-insecure-http` and `-insecure-remote-api` for testing.
- The center serves `/admin/` on first start and enables enrollment and relaying after the owner is bound. The console requires HTTPS or loopback HTTP. Use `-owner-trust` for automated setup. A compromised center can disrupt connections or withhold updates. Only the owner can sign approvals, key rotations, ACLs, and routes. Use independent application-layer authentication for sensitive services.
- The center creates `./data/center/server.sqlite` on first start. See [center storage and backups](docs/OWNER_CONTROL.md#center-storage-and-backups) for alternate paths, backups, and offline password resets.
- A silent control stream reconnects after one minute. During disconnection, a node retains the current authorization for at most four hours by default (`-control-lease-ttl`), capped by the signature expiry. A received signed revocation takes effect immediately.
- The ACL selector `autogroup:internet` excludes overlay addresses, private networks, approved subnets, and documentation and benchmark ranges. Give test or fake IP addresses explicit destination and port rules, such as `198.18.0.10:443`.
- The current peer relay frame requires matching versions on participating nodes. Coordinate center and node upgrades.
- Keep state and credentials in protected directories. Rotate any enrollment keys or tokens exposed in older logs or sent over plaintext connections.

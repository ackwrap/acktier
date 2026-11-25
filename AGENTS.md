# AckTier

## File length

- Keep new files at 1,000 lines or fewer. If a change would push an existing file over 1,000 lines, split it into focused files that each meet the limit.
- Existing files already over 1,000 lines are grandfathered. Do not edit or split them solely to meet this limit. For future additions, use a separate file or split the oversized file rather than growing it.

## Build and test

- Use Go 1.25.0 or newer from the module root. `go build -o bin/ ./cmd/...` emits all three binaries; `go build ./cmd/...` checks compilation without overwriting `bin/`.
- Run `go test -count=1 ./...`; for SDK work, `go test -count=1 ./pkg/acknet` also exercises `pkg/client`. Most E2Es inject in-memory devices and transports; TLS/Upgrade and HTTP stream deadline tests use ephemeral loopback TCP listeners. No daemon or TUN driver is needed; `-short` does not skip E2Es.
- The CN2 simulation has timed out in the full suite on an unchanged checkout on Windows. Rerun it in isolation: `go test -count=5 -run '^TestUSWestCN2AutoSteppingStoneOverLossyOrdinaryRoute$' ./internal/daemon/engine`.
- On Windows, standalone `go vet ./...` reports two existing `unsafe.Pointer` warnings in `internal/daemon/tun/tun_windows.go`.

## Where to make changes

- `cmd/acktier` uses `pkg/client.DaemonClient` against `internal/daemon/localapi` (`/local/v1` over loopback HTTP with a bearer token, not pipes or Unix sockets). The `key`, `route`, and `acl` commands instead use `pkg/client.AdminClient` against `internal/server/control`.
- `cmd/acktierd` and `pkg/acknet` share `client.Node` and `internal/daemon/engine`. `acknet.Server` plugs in its userspace stack as a `TUNCustom` device for application sockets; `internal/daemon/netstack` is the separate subnet/exit-node gateway.
- `pkg/types` defines the shared control messages; `pkg/protocol/wire.go` defines the binary data-plane framing. NDJSON NetMaps are full snapshots; matching keepalives renew the data-plane lease (4h by default). A silent stream reconnects after 1m without clearing data-plane state. Peer-hop framing is authenticated and distinct from center-relay framing; deploy matching node versions.
- `internal/owner` verifies owner-signed identities and policy independently of the coordinator. Registration and streamed maps must both use the pinned owner key and persisted version; unsigned map fields are connection hints only.
- The embedded center console is served at `/admin/` from `internal/server/control/web`. It can bind the initial public key and publish signed artifacts, but never signs. Keep its session authentication separate from the bearer-token JSON API.

## Local smoke checks

- Use `acktierd -tun memory -upnp=false -lan-discovery=false` for unprivileged checks; the default `-tun auto` attempts a real device first. Use `acktier ping`, not host `ping`, with memory TUN.
- To test same-host direct UDP using loopback candidates, use a loopback control URL and add `-udp 127.0.0.1:0 -tcp= -quic= -wss=` to both daemons. Wildcard transport binds do not opt into loopback candidates.
- A fresh center starts in setup mode. Run `acktier owner init` on the selected owner, sign in at `/admin/`, and upload only `trust.json`; `-owner-trust` also works for noninteractive installs. Nodes need the same trust file from a trusted channel; see `docs/OWNER_CONTROL.md`.
- Give each daemon its own persistent `-state` file and loopback `-api` address. Set the CLI's `ACKTIER_API` to the matching HTTP URL (default `http://127.0.0.1:41920`).
- `acktier-server` defaults HTTP to loopback but binds both STUN sockets on all interfaces. For isolated smoke runs bind both STUN listeners to loopback or disable them with `-stun= -stun-alt=`. `-data=` makes the store ephemeral, not the credentials file; set `-credentials-file` to an isolated path for temporary runs.

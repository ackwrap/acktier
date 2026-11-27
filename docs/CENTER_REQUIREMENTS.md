# AckTier center requirements and acceptance criteria

This document defines the center's development requirements and acceptance criteria. See [deployment and storage](OWNER_CONTROL.md#center-storage-and-backups) for database paths, backups, and offline password resets. The management listener defaults to loopback. Signing belongs to the owner.

## 1. Responsibilities and permissions

`acktier-server` coordinates nodes, manages requests, distributes signed authorizations, provides STUN and relaying, and hosts the admin console. During setup, the administrator explicitly selects a trusted owner client. Its signing key stays local, and the computer can be offline while its authorizations remain valid.

| Role | Responsibilities | Limits |
| --- | --- | --- |
| Center Web administrator | Sign in with the admin password, bind the owner once, view nodes and requests, manage enrollment keys and drafts, and upload signed authorizations | Signing and policy approval belong to the owner. The Web console can bind the owner once. |
| Controller (selected owner client) | Verify and sign authorization locally. When delegated, use its own device credential to call the management API. | Keep the signing key on the owner computer. Only local owner actions can initiate signing. |
| Node, including an approved member | Submit requests with an enrollment key, register and report with its node credential, receive NetMaps, and verify signed policy locally | Node credentials authorize node operations only. |
| Center service | Verify and persist public trust and signed snapshots. Maintain untrusted connection hints. | The center handles public trust only. Changes to membership, keys, ACL, routes, and validity require a new owner signature. |

The Web password, controller API credential, enrollment key, and node token have distinct purposes. Node registration, IP addresses, and signed member keys confer no management privileges.

## 2. Startup, network separation, and sign-in

- **Separate listener.** By default, serve `/admin/` only on loopback at `127.0.0.1:8081`. Use a different listener and routes for node control and relaying. The node listener returns `404` for the console and management API by default. Configure any management exposure explicitly.
- **Remote access.** Operators can reach the loopback console with an SSH tunnel. Direct remote management requires an explicit listen address and HTTPS. Bind to a restricted management network where possible. Allowing plaintext node traffic for lab testing leaves HTTPS mandatory for remote administration.
- **Dedicated administrator password.** Use a password set locally during deployment or generated into a private credentials file. Each center stores a salted Argon2id hash. A local reset requires the service to stop and invalidates prior sessions on restart. A Web password change invalidates other sessions immediately. Keep passwords out of URLs, logs, and node configuration.
- **Session security.** Enforce permissions on the server. Use random session IDs with sign-out and expiry. Use `HttpOnly`, a suitable `SameSite` policy, and `Secure` over HTTPS. State changes require CSRF and same-origin checks. Limit sign-in attempts and request sizes, deny embedding, disable caching for sensitive responses, and omit submitted credentials from errors.
- **Setup before binding.** Authenticated administrators can use the setup wizard and health checks can report setup pending. Registration, heartbeats, NetMaps, and relaying require a bound owner.

## 3. Owner binding and controller API

1. Run `acktier owner init` on the selected computer. Transfer its public `trust.json` over a trusted channel. Keep `signer.json` on that computer. The signing key and a node's `NodeKey` are separate.
2. Sign in, upload `trust.json`, verify the network fingerprint and public key, and confirm its provenance. Persist its minimum acceptable authorization version with the public key. The UI need not show the number. Only open node registration after a successful commit. Concurrent setup attempts can succeed once, and a failed write leaves setup pending. Keep `-owner-trust` available for automated setup. A bound root remains pinned across restarts.
3. Nodes must obtain the owner key independently through a trusted channel. If the controller joins the data plane, the owner must sign its `NodeKey` into the member list too.
4. The management API is private by default. Explicit delegation can authorize a selected controller on the separate management listener. Bind its management public key or client certificate and verify possession of the corresponding private key. Keep Web and node credentials separate from controller API authentication.
5. A delegated controller can read requests, members, capabilities, and active authorization, manage enrollment keys and drafts, and upload signed files. If using mTLS, pin the client public key. If signing requests, bind a short-lived, single-use challenge to the network or service, HTTP method, target, and body digest. Prevent concurrent replay. Use separate keys or domain separation for API proof and policy signing. Revoking delegation immediately invalidates the credential while published authorizations stay active. Root replacement and signing require local owner operations.

## 4. Console pages and workflows

| Page | Required behavior |
| --- | --- |
| Sign-in and setup | Authenticate with the dedicated password, show the setup wizard before binding, accept public `trust.json`, preview the fingerprint, and distinguish unconfigured, bound, and persistence failure states. |
| Overview | Show the network fingerprint, active authorization version and expiry, draft and request counts, signed membership, reporting times, and relay status. Distinguish root binding, signature state, and online presence. |
| Join requests | Search and paginate. Show name, OS, node public key, latest report, transports, and advertised subnets. Provide an action to add a verified request to a draft. |
| Node details | Compare **signed identity** (name, addresses, tags, approved subnets and exits) with **node reports** (listeners, candidates, advertised routes, and latest report). Identify missing, offline, revoked, and expired states and allow importing an inventory for review. |
| ACL and policy | Use a rule table and forms to add, edit, reorder, and delete rules. Show source, destination, protocol, ports, and action. Support importing and editing ACL or complete policy JSON, comparing with active policy, and exporting for signing. |
| Publish authorization | Upload `authorization.json`, show signature verification, version, expiry, and change summary, and report specific rejection reasons. Show history and audit without offering rollback. |
| Credentials and audit | Create expiration-limited enrollment keys, with single use by default. Show the plaintext once, then display only the note, expiry, and use status. Support revocation and show controller delegation and audit events. |

Use real lists, details, upload checks, empty states, and errors. Forms must work from the keyboard and tables must fit small screens. A server-rendered fallback for basic administration is optional. Audit at least the timestamp, actor, action, target, result, and relevant version or digest. Keep passwords, private keys, cookies, and plaintext enrollment keys out of audit records.

### 4.1 Transports, ports, and capabilities

During registration and authenticated heartbeats, nodes report enabled `udp`, `tcp`, `quic`, or `wss` transports, bind ports, external IP and port candidates, and advertised routes. The console can also import an inventory attached to a specific node public key. Preview it before saving. Display reports and imports side by side with their update times. Mark missing data from older clients as unreported.

| Concept | Example | Use |
| --- | --- | --- |
| Transport listener | QUIC `41000` or WSS `443` | Describes how the node listens for transport connections. |
| Candidate address | `203.0.113.15:45000` over UDP | Suggests a dial target. NAT may map a different external port. |
| ACL service port | `node:2:8443` over TCP | Grants overlay service access through signed policy. |

Validate the supported protocols, ports `1–65535`, literal IPs, IPv6 format, and limits on addresses and CIDRs. Inventory uploads are for review only. Keep probing, firewall changes, route approvals, and ACL grants out of the import flow. NetMaps use the existing bounded reporting path. Nodes may update their own inventory only.

### 4.2 Draft, sign, and activate ACL policy

1. Edit the selected draft through forms, import standalone ACL JSON, or upload a complete `policy.json` with `members`, `acl`, DNS, routes, and optional STUN settings. Rules use first match. Require an explicit save, preserve the signed base version, and keep members, DNS, and routes when editing ACL only. Saving a draft leaves active policy unchanged.
2. Validate the schema, actions, selectors, protocol, ports, groups, host aliases, routes, and member conflicts. Trust selectors require authorized identities. Preview broad grants, unknown nodes, removals, and default denial. Match application ports with TCP or UDP. QUIC and WSS remain transport options.
3. Export the complete `policy.json`. The owner verifies device public keys and policy changes through the device or another trusted channel, then runs `acktier owner sign` locally. The center and console have no signing endpoint.
4. Upload `authorization.json` in the console or through a delegated API. Verify the pinned signature, network ID, expiry, version, and digest. Reject earlier versions, conflicting content at the same version, bad signatures, expiry, and malformed snapshots. Identical valid snapshots can be accepted idempotently. Verify the original signed bytes.
5. Distribute only committed snapshots. Nodes verify and persist the version locally before using the membership, ACL, DNS, routes, and revocations. Removing a member takes a signed policy. Revoking an enrollment key prevents future requests with that key. While the owner is offline, administrators can prepare drafts and distribute existing signed artifacts.

## 5. SQLite persistence

**SQLite is the center's persistent state store.** It is created on first run. Node state and the signing directory remain on their respective devices. Use `-data=` for a temporary in-memory store. Keep cross-platform build support.

| Data | Minimum requirements |
| --- | --- |
| Owner binding, admin password, and delegation | One owner root with its minimum authorization version, password hash, and the selected controller's management key or certificate state |
| Nodes, requests, and capabilities | Stable IDs, public keys, state, and node token digests. Distinguish requests, signed members, reported inventory, and imported inventory. |
| Enrollment keys | Digest, purpose, expiry, use count, and revocation marker |
| Drafts and policy | Draft revision and base version, validation state, original signed payload bytes, signature, digest, version, expiry, and active pointer |
| Audit | Time-queryable key operation records |

- Define unique constraints and indexes. Commit owner binding, enrollment key consumption with node registration, signed version advancement, and revocation with audit atomically. Update in-memory or published state after commit. Heartbeats write only relevant records.
- Restrict the database, journals, WAL, and backups to the center service account and authorized operators. Use locking and timeouts for a single center process. Use a consistent SQLite backup method or stop the center before copying files.
- Report database read or commit errors and preserve the existing state. On restart, reverify the active snapshot and signed history and enforce the signed high-water mark.

## 6. Interface boundaries and acceptance

Retain `/api/v1/node/register`, `/api/v1/node/heartbeat`, `/api/v1/node/map/stream`, and `/relay`. Browser sessions use the console routes beneath `/admin/`. Controllers use separately authenticated `/api/v1/admin/` endpoints. The two surfaces can share implementation code while using separate credentials. Owner signatures govern changes that legacy `acl set`, `route approve`, and `rekey` commands once applied directly. Keep other nodes' information, uploaded content, and secrets out of request and authentication errors.

| Check | Pass condition |
| --- | --- |
| Default isolation | Loopback limits Web access. The node port serves no management routes. Remote Web administration requires explicit TLS configuration. |
| Passwords | Valid credentials can sign in and out. Missing, wrong, or expired credentials and cross-site posts fail. Local reset invalidates old sessions and keeps secrets out of logs. |
| First setup | An empty database starts with node registration, heartbeat, streams, and relaying paused. Explicit binding enables them. Private keys and repeated or racing binds fail. Restart preserves the binding. |
| Permission separation | With delegation enabled, the selected controller can use its credential. Members, enrollment keys, node tokens, Web passwords, and sessions cannot authenticate to its API. Revocation takes effect immediately. |
| Capability inventory | Test nodes report at least two transports and ports and can update them in heartbeats. The UI previews and displays valid imports and rejects invalid files. ACL and routes remain governed by the signed policy. |
| ACL workflow | Upload and preview rules, export for local signing, and publish. Verify a draft alone has no data-plane effect and the signed version applies. Tampered, foreign, expired, and rollback snapshots fail. |
| Persistence | Restarting preserves binding, nodes, drafts, signatures, and counts. Faults leave transactions intact. Only one submission can consume a single-use key. Offline password reset requires the database lock. |
| End to end | Exercise sign-in, binding, capability import, policy upload, and publication in a browser. Two memory TUN nodes can submit requests, verify the signed policy, communicate, and lose access upon revocation. The owner can go offline between signing operations. |

From the repository root, run `go test -count=1 ./...`, `go test -race -count=1 ./...`, and `go build ./cmd/...`. See the [owner architecture](OWNER_CONTROL.md) and [project plan](PROJECT_PLAN.md).

Run the browser regression with Node.js 22 or later and Chrome or Chromium.

```bash
go build -o bin/ ./cmd/...
node scripts/check-admin-browser.mjs bin /path/to/chrome
```

# Owner and center architecture

The first owner-signed implementation is available. A new center opens the Web setup screen and accepts enrollments after you choose an owner and bind its public key. The owner can use a regular computer and only needs to be online when signing or administering the network.

## Trust boundaries

| Role | Responsibilities | Trust boundary |
| --- | --- | --- |
| Owner client | Keeps the local Ed25519 private key, verifies node public keys, and signs node identity, address, ACL, DNS, subnet, and exit authorization | The private key stays on the owner computer. Signing is local. |
| Center | Receives requests, maintains connection hints, verifies and distributes signed snapshots, and provides STUN and relaying | Membership, key rotations, ACL grants, and routes require the owner's signature. |
| Node | Pins the owner public key, verifies signatures, rejects rollback, and handles traffic using signed policy | Center admin tokens, `PreAuthKey`, and TLS certificates provide separate transport or enrollment credentials. |

The built-in **`/admin/`** console binds the owner, creates or revokes enrollment keys, displays join requests and members, and uploads signed authorizations. Signing happens on the owner computer.

## Initial setup and enrollment

### 1. Start the center and bind an owner

For a loopback test, start the center without an existing owner binding.

```bash
acktier-server -listen 127.0.0.1:8080 -admin-listen 127.0.0.1:8081 -stun= -stun-alt=
```

Open [http://127.0.0.1:8081/admin/](http://127.0.0.1:8081/admin/) and sign in with the dedicated Web administrator password. The generated initial password is stored as `adminPassword` in the private `./data/server-credentials.json` file. The database stores an Argon2id hash. To recover access, **stop the center**, run `acktier-server reset-password` locally with the same `-data`, then restart. A running center holds an exclusive SQLite lock. The console and management API use the separate `-admin-listen` listener, which defaults to loopback. Use an SSH tunnel or explicitly configure an HTTPS management listener for remote access.

On the selected owner computer, initialize its key.

```bash
acktier owner init --dir ./data/owner
```

- `trust.json` holds the owner public key and the minimum acceptable authorization version. Deliver it to the center and nodes over a trusted channel independent of the center.
- `signer.json` holds the private seed and latest signed version. **Keep it on the owner computer.** Back it up to encrypted offline media and protect the signing directory from unauthorized writes.
- The owner's signing key and a node's `NodeKey` have separate roles. If the owner computer also joins the data plane, include its own `NodeKey` in the signed member list.

In setup, select `trust.json`, verify its provenance and fingerprint, and choose **Bind owner**. The console is available before binding. Node registration, heartbeats, control streams, and center relay open after the binding has persisted. The Web console can bind the owner once. For automated setups, use `-owner-trust ./trust.json`.

Keep a persistent `-data` path in production. Running with `-data=` uses memory storage and requires fresh initialization on each start.

### 2. Submit a join request

Obtain `trust.json` independently and verify the public key with the owner. Generate or display the node key on the node.

```bash
acktier owner node-key --state ./data/nas.json
```

Start the daemon with that same state file and submit a request.

```bash
acktierd -state ./data/nas.json -owner-trust ./trust.json -tun memory -upnp=false -lan-discovery=false
acktier up --server http://127.0.0.1:8080 --auth-key "<PRE_AUTH_KEY>" --hostname nas
```

Create an enrollment key in the console. It permits submitting a join request. Until approval, `up` reports that the owner must approve the request. The node saves its coordination token for its next registration. The TUN address, peer keys, ACL, and routes are installed only once signed approval is available.

### 3. Review, sign, and distribute authorization

In **Join requests**, review the node public key, transports, and advertised routes. Add the verified requester to an ACL policy draft and export the complete `policy.json`. For API delegation, run `acktier owner controller-init --dir ./data/owner` on the owner computer and upload `controller-trust.json` under **Credentials and audit**. The command `acktier owner requests --server http://127.0.0.1:8081 --dir ./data/owner` can then query requests using a one-time signed challenge.

Use `pkg/client.ControllerClient.Policy` to call `/api/v1/admin/policy/…` on the management listener. These endpoints share the console's operations for active policy, drafts and members, ACL validation and compilation, export, signed preview, publication, and history. Pass the last read `updatedAt` when modifying, deleting, or exporting a draft to catch concurrent edits. The center returns `409 draft_changed` if the draft was updated. Publication requires an `authorization.json` signed on the owner device.

When creating a draft from the active signed snapshot, the center copies a source policy that compiles to that snapshot. If it has no match, import the complete `policy.json` that the owner signed. In **ACL rules**, edit rules, change their matching order, or import ACL JSON. Saving updates the draft. Publication activates signed rules.

Treat join requests as **unverified information supplied by the center**. Confirm each device's public key from the node or another trusted channel before signing. The owner can prepare or export a full `policy.json` like the following, with both placeholders replaced by verified keys.

```json
{
  "members": [
    {"id": 1, "name": "laptop", "nodeKey": "<LAPTOP_PUBLIC_KEY>", "ipv4": "100.64.0.1"},
    {"id": 2, "name": "nas", "nodeKey": "<NAS_PUBLIC_KEY>", "ipv4": "100.64.0.2"}
  ],
  "acl": {
    "acls": [{"action": "accept", "proto": "tcp", "src": ["node:1"], "dst": ["node:2:443"]}]
  },
  "dns": {"enableMagicDNS": true, "magicDNSSuffix": "ack.internal"}
}
```

- The signed snapshot assigns `id`, `name`, virtual addresses, and `nodeKey`. `ipv6`, `tags`, and `routes` are optional. To authorize an exit, include `0.0.0.0/0` or `::/0` in the node's `routes` and configure the ACL. Each client selects its exit node separately. An empty ACL denies application traffic by default.
- For NAT probing, set `stunAddr` and `stunAltAddr` to literal IP and port pairs in the signed policy. The node connects to the center relay at its locally configured control address. A NetMap cannot redirect relay tokens to an alternate host.
- Each issuance replaces the **complete authorization**. To revoke a member, remove it. For key rotation, the node generates a key with a new state file and submits a request. After verifying it, the owner replaces the old public key and can keep the signed address. Reissue after ACL, DNS, or route changes and for renewal.

Sign on the owner computer. This step can run offline.

```bash
acktier owner sign --dir ./data/owner --policy ./policy.json --valid-for 168h
```

In **Publish authorization**, upload `authorization.json` to preview its signature and the changes. When controller API delegation is enabled, you can also publish from the CLI.

```bash
acktier owner publish --server http://127.0.0.1:8081 --dir ./data/owner --file ./data/owner/authorization.json
```

After first approval, run `acktier up` again. It can normally reuse the saved token. Online nodes receive newer signed snapshots through the current control stream. Installing a new authorization clears existing sessions and connection tracking so the data plane can reconnect. Each issuance exports a `trust.json` with the same public key and an updated minimum version. For **new nodes**, distribute the file corresponding to a successfully published version.

## Protocol and persistence

- **Authorization.** The snapshot includes the network ID (SHA-256 fingerprint of the owner public key), version, expiry, full member list, the packet filter compiled by the owner CLI, and DNS and STUN settings. Ed25519 signs raw JSON bytes with an AckTier-specific prefix. The wire payload and signature are Base64, and verification uses the original bytes.
- **Connection hints.** The center distributes the same signed snapshot plus candidates and observations such as link quality. Nodes use hints only for keys listed in the signed snapshot. They disregard unsigned authorization fields. `NetMap.Revision` tracks stream synchronization independently of the owner version.
- **Rollback protection.** Before installing policy, the node persists the verified version and digest. It enforces the configured minimum version and rejects older snapshots and different content under the same version. Both registration and streamed NetMaps require the same verification.
- **Management API.** `GET /api/v1/admin/owner/requests` lists requests. `GET` or `PUT /api/v1/admin/owner/authorization` reads or publishes an authorization. Delegation requires proof of possession of its dedicated controller key. Plaintext enrollment keys are returned only at creation. Owner mode disables the legacy endpoints that directly change keys, ACLs, routes, and DNS.
- **Web sign-in and setup.** Console sessions expire and browser forms use cross-site request protection. Initial binding succeeds once. Provision the initial trust file on nodes through an independent channel.
- **Storage.** The center uses SQLite for public keys, signed snapshots and versions, requests, nodes, password hashes, drafts, delegation, and audit. Node state and the owner directory stay in their original locations. Enrollment keys and node tokens are stored as validation digests.

## Center storage and backups

- The first run creates `./data/center/server.sqlite`. Use `-data /path/to/private/server.sqlite` to change the path. Use `-data=` only for temporary tests.
- Store the database in a **local private directory controlled by the service account**. On Unix, directories and files default to `0700` and `0600`. On Windows, only the service account, SYSTEM, and Administrators may access the directory and its files. Startup creates a missing final directory and preserves the permissions of existing directories. Give each center an exclusive local database.
- Stop the center to back up its database. Keep any SQLite journal files with it for recovery. Restore the latest trusted backup and verify the owner's current authorization version. If needed, raise the minimum with a trusted `trust.json` and upload the latest signed authorization.

You can change the password while signed in. If it is forgotten, stop the center, run `acktier-server reset-password` on the host, and restart it. Supply the same `-data` for a custom path. Supply a replacement via `-admin-password-file` or use the generated password written to the private credentials file.

## Outages, compromise, and recovery

- **Owner offline.** Nodes continue communicating under a valid authorization. Renew before it expires. The default signing lifetime is seven days and can be tuned to the required revocation window. Creating new grants requires the owner.
- **Center unavailable.** Existing reachable peer links continue until the control lease expires (four hours by default) or the signed authorization expires, whichever is earlier. Heartbeats cannot extend the signature expiry. A center `401` or `403` denies coordination only. Signed policy governs revocation.
- **Center compromised.** The center can block connections, withhold updates, and observe network metadata. Key replacement and ACL grants require the owner's signature. A received signed revocation applies immediately. An authorization withheld by the center expires at its signed deadline. Protect sensitive services with independent application authentication.
- **Upgrade and recovery.** When upgrading from an older center without owner mode, bind the owner in `/admin/` and provision the trusted owner key on each node. Keep node state and registration tokens if desired. Verify and reissue the members, addresses, ACL, and routes. Keep the latest signing version with key backups to prevent version reuse. Replacing a lost or compromised root that cannot be recovered requires provisioning a new trust root on the center and nodes through an independent channel. The current release supports one owner root and local reconfiguration.

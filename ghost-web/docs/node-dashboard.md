# Node Dashboard

*Monitor your node and manage its settings through a web-based dashboard.*

## Overview

Every Ghost node includes a local web dashboard for monitoring and configuration. The dashboard is:

- **Local-only by default** — No public internet exposure
- **Real-time** — Live updates via WebSocket
- **Responsive** — Works on desktop and mobile
- **Secure** — JWT authentication, no external dependencies

:::warning Security First
The dashboard binds only to localhost (127.0.0.1). It's never exposed to the public internet. You access it through SSH tunnel or VPN.
:::

## Access Methods

Three ways to access your dashboard remotely:

| Method | Best For | Setup |
| --- | --- | --- |
| SSH Tunnel | Technical users, no extra software | Easy |
| Tailscale VPN | Best UX, mobile access | Easy |
| Local Network | Home users on same LAN | Trivial |

## SSH Tunnel (Recommended)

### SSH Port Forwarding

Forward your local port through an encrypted SSH connection. No additional software needed.

### Quick Connect

```bash
# Install ghost CLI (one time)
$ npm install -g @ghost-pool/cli

# Connect to your node
$ ghost connect your-server.com

# Output:
→ Establishing SSH tunnel...
→ Dashboard available at http://localhost:3000
→ Opening browser...
✓ Connected to ghost-usa-west-42
```

### Manual SSH

```bash
# Forward port 3000 (dashboard) and 8080 (API)
$ ssh -L 3000:localhost:3000 -L 8080:localhost:8080 ghost@your-server.com

# Then open in browser:
http://localhost:3000
```

### Persistent Tunnel

Add to your `~/.ssh/config`:

```bash
Host ghost-node
    HostName your-server.com
    User ghost
    LocalForward 3000 localhost:3000
    LocalForward 8080 localhost:8080
    ServerAliveInterval 60
```

Then just: `ssh ghost-node`

## Tailscale VPN

### Tailscale Mesh VPN

Zero-config VPN that creates a private network between your devices. Best UX for mobile access.

### Server Setup

```bash
# Install Tailscale on your Ghost node
$ curl -fsSL https://tailscale.com/install.sh | sh
$ sudo tailscale up

# Authenticate in browser when prompted

# Note your Tailscale IP (e.g., 100.64.0.42)
$ tailscale ip -4
```

### Client Setup

```bash
# Install Tailscale on your laptop/phone
# Download from: https://tailscale.com/download

# Authenticate with same account

# Access dashboard directly:
http://100.64.0.42:3000
```

### Configuration

During Ghost install, if you chose Tailscale, the dashboard binds to your Tailscale IP:

```bash
# /etc/ghost/node.conf
dashboard:
  bind: "100.64.0.42:3000"  # Tailscale IP
```

:::info Why Tailscale?
Tailscale uses WireGuard under the hood for encrypted connections. It handles NAT traversal automatically, so you can access your node from anywhere without port forwarding. Great for mobile access.
:::

## Dashboard Features

The dashboard is built for the node pool. Its node pool pages:

| Page | Shows |
| --- | --- |
| **Overview** (`/`) | Node pool health: the pool service answering, relay peers, settlement caught up, provisional and mismatched blocks, anchors waiting for their batch. The Bitcoin node's sync, the share-chain tip and anchor height, the fee address, and where the share chain starts (genesis anchor and height, genesis tier, table digest, pinned digest). |
| **Miners** (`/miners`) | Every open channel with its payout address, worker, slot class (how many miner outputs its jobs carry), sensed firmware model, sensing state and any firmware warning. Per payout address: hashrate, shares in the last 24 hours, ledger balance, queue position and expected wait. Each address links to its own page. |
| **Miner** (`/miners/{address}`) | Workers on this node, the ledger balance, its rank in the oldest and largest queues, what the next block would pay it at each slot class, its payouts (settled or provisional, confirmations, spendable) and its recent credited shares. |
| **Pool Blocks** (`/blocks`) | Recent pool blocks: subsidy, what each paid to miners and to whom, the treasury base (`S/200`), the change sent to the treasury, and whether settlement matched the block or retired it provisionally. Settlement counters since start. |
| **Share Chain** (`/share-chain`) | The tip, cumulative work and `T_net`, loose shares and anchors waiting for their batch, the relay's counters since start, the checkpoint depth, pruning on or off, and the stored checkpoints. |
| **Connect Miners** (`/mining`) | This node's stratum ports, the SV2 authority key and the username rule (`<payout-address>.<worker>`; P2SH, P2WPKH, P2WSH and P2TR only). |

**Settings** shows the fee address read-only. It is a money destination, so the dashboard never
writes it: re-run the installer with `--fee-address`, or edit `fee_address` under `[node_pool]` in
`/etc/ghost/pool-config.toml` and restart pool_sv2. Alerts (including the webhook) are set under
Settings, Alerts.

The Bitcoin node, privacy, transaction filtering, storage and system pages are unchanged. Pages
for elders, capabilities, checkpoints, votes, node rewards, Wraith, Ghost Pay, Tap and L2 are
gone, as are the old mesh's pool, geo, capacity and peers pages.

:::info Honest readings
Where the node does not report a value, the dashboard says **unknown**; where a call fails, it says
**unavailable** with the reason. It never fills a gap with zero or with a healthy state. Hashrate,
shares and worker status are this node's own (only the node a miner is connected to sees its
shares); balances, queue positions and payouts are the share chain's and are the same on every
node.
:::

## API Access

The dashboard is powered by a REST API that you can also use directly:

Note which service you are talking to. Port `8080` is the **node backend**
(`ghost-verification`), a different process from the dashboard on port `3000`.
The dashboard's authentication does not apply to it, and never did — the
examples below work because these particular backend routes are unauthenticated
in their own right, not because of any localhost exemption.

```bash
# Against the node backend on :8080 (not the dashboard):

# The node pool's status: share chain, peers, settlement, blocks, miners
$ curl http://localhost:8080/api/v1/node-pool/status

# One miner's ledger: balance, queue position, shares, payouts
$ curl http://localhost:8080/api/v1/ledger/<address>

# One miner's workers on this node and its expected wait
$ curl http://localhost:8080/api/v1/miner/<address>
```

These three are forwarded to pool_sv2, which builds them on its loopback monitoring listener; if
pool_sv2 does not answer, the backend says so with a `503`. Routes of removed features answer
`410 Gone` with the feature's name.

The dashboard's own API (port `3000`, including the `/api/v1/*` proxy) is a
different matter: it requires a session on **every** request, including from
localhost. Authenticate at `/login` with the configured `DASHBOARD_PASSWORD` to
receive the `ghost-session` JWT cookie; subsequent requests include the cookie
automatically. A request without one is redirected to `/login` (pages) or
answered `401` (API) — there is no local exemption.

### Operator-signed fleet control

Two routes on the node backend act on the node itself, and both demand a command
signed with the **operator's** Ed25519 key. The node holds only the public half,
in `GHOST_OPERATOR_PUBKEY` (64 hex chars); without it both routes answer `501`.

| Route | `action` | Effect |
|---|---|---|
| `POST /api/v1/swarm/nodes/:node_id/restart` | `restart` | restarts this node |
| `PUT /api/v1/swarm/nodes/:node_id/config` | `configure` | writes ONE allowlisted key to this node's `pool.toml` — **does not restart** |

The body is a signed command. The signature is over
`ghost-fleet-v1\n<target_node_id>\n<action>\n<sha256-hex of params JSON>\n<nonce>\n<expires_at>`,
so the target, the action and the parameters cannot be changed after signing.
`expires_at` may be at most 120 s ahead, and each nonce is accepted once.

```json
{
  "target_node_id": "<this node's id>",
  "action": "configure",
  "params": { "key": "network.max_miners", "value": 900 },
  "nonce": "<random hex>",
  "expires_at": 1793000000,
  "signature": "<hex ed25519 signature>"
}
```

`key` and `value` must be inside `params`. Put beside it, outside the signature,
they are refused (`400 unsigned_fields`).

**Settable keys** — nothing else: `alerts.enabled`, every
`alerts.events.<event>` toggle (`low_disk`, `restart_needed`,
`peer_count_drop` (share-chain relay peers dropped, or none), `block_found`,
`reorg_detected`, `behind_tip`, `update_available`, `mempool_congestion`,
`fee_spike`, `failed_login`, `service_restart_loop`), `network.max_miners` (1 to 4294967295)
and `identity.display_name` (1-64 printable characters, no quotes).

Anything else is `403 refused_by_design`, with a `category` saying why:
`credential`, `money_destination`, `mining_mode`, `consensus_geometry`,
`capability_claim` (a capability is earned by passing its verification
challenges, not by setting a flag), `data_redirection`, or `not_on_allowlist`.

A successful change answers `200` with `"applies_at": "next restart"` and
`"restarted": false`. Nothing in `pool.toml` is re-read while the node runs, so
the change rides the next restart — batch it with a binary roll rather than
spending a restart on it. The edit keeps every comment and every other line,
is checked against the node's real config loader before it is written, and
replaces the file atomically with its original owner and mode.

## Security

### Authentication

- **Password-gated** — Set `DASHBOARD_PASSWORD` in the dashboard's systemd
  override (`/etc/systemd/system/ghost-dashboard.service.d/override.conf`,
  root-readable only). Each operator picks their own value.
- **JWT session cookie** — On successful login at `/login`, the dashboard
  issues a signed cookie named `ghost-session`. Middleware
  (`dashboard/src/middleware.ts`) verifies the JWT on every request.
- **No localhost bypass** — there is no origin-based exemption. An earlier
  version of the dashboard skipped authentication for `127.0.0.1` / `::1` /
  `localhost`; that was removed. The middleware deliberately does not consult
  `X-Forwarded-For` or `Host` for any auth decision, because both are
  client-spoofable and the old bypass they powered let a direct connection to a
  mis-bound dashboard skip authentication entirely. Auth is the JWT cookie and
  nothing else, and it fails closed even if the server is mis-bound to
  `0.0.0.0`.
- **Access model: SSH tunnel only** — the dashboard binds to `127.0.0.1:3000`
  and is reached with `ssh -L 3000:localhost:3000 <node>`. The loopback bind and
  the JWT are independent layers; neither is relied upon to cover the other.

### Network Security

- **Localhost binding** — Dashboard listens on `127.0.0.1:3000` only. There
  is no public DNS, no TLS termination, and no nginx reverse proxy in front
  of it by design.
- **No CORS for external** — Cross-origin requests blocked.
- **Audit logging** — Admin actions logged in the dashboard's structured
  log stream.

### Rotate the password

If the dashboard password is compromised:

```bash
# Generate a strong replacement
$ openssl rand -base64 32

# Edit the override file (root only) and replace DASHBOARD_PASSWORD,
# then reload + restart
$ sudo systemctl edit ghost-dashboard
$ sudo systemctl daemon-reload
$ sudo systemctl restart ghost-dashboard
```

Existing `ghost-session` cookies remain valid until they expire — restart
forces a fresh login because the JWT secret is process-scoped.

### Recover a forgotten password

Because the dashboard binds loopback and auth is a single `DASHBOARD_PASSWORD`,
a *forgotten* password would lock the operator out — and there is deliberately
no web-based reset (that would be an authentication bypass). Recovery instead
relies on **node access**, which reaching the dashboard already implies. On the
node, as root, run the bundled helper:

```bash
$ sudo scripts/agathion-reset-password.sh
```

It generates (or accepts, via `--password`) a strong password, writes it to the
`override.conf` drop-in above while preserving other `Environment=` entries,
drops any explicit `DASHBOARD_JWT_SECRET` so old sessions die, runs
`daemon-reload` + `restart`, and prints the new password. The login page's
"Forgot password?" link points operators to this command. See the dashboard
README ("Password recovery") for details.

### Best Practices

1. Use SSH key authentication (no passwords) for the SSH tunnel.
2. Keep your SSH key secure with a passphrase.
3. Use Tailscale for convenient mobile access; the dashboard's
   localhost-binding still applies behind it.
4. Never expose port 3000 or 8080 to the public internet.
5. Rotate `DASHBOARD_PASSWORD` if you suspect compromise.

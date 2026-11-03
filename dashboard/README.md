# Ghost Node

**Ghost Node** — the familiar spirit that watches your Ghost node. A web-based
dashboard for monitoring and managing Ghost Network nodes, bound to serve and
report to its keeper (the node operator). Built with Next.js and React.

> **Infrastructure naming:** the on-disk directory is still `dashboard/` and the
> systemd unit on production nodes is historically named `ghost-dashboard.service`.
> Those names are kept stable so the deployed fleet keeps working; only the
> user-facing product identity is "Ghost Node". A future infra rename can
> happen separately.

> **Releases:** Ghost Node is a **separate download** from the node binaries.
> It ships as a Next.js standalone tarball (`agathion-<version>-node.tar.gz`) cut
> by the `Release Agathion` workflow (tag `agathion-v*`); see the packaged
> `RUN.md` for how to launch it.

## Overview

The dashboard is the operator's view of a node pool node (W2.14). It provides:
- **Overview** - node pool health (service answering, relay peers, settlement, provisional
  blocks, share-chain sync), the Bitcoin node's sync, share-chain tip, fee address, and the
  share chain's start values (genesis anchor, height, tier, table digest)
- **Miners** - connected channels with their slot class, sensing state and firmware warnings;
  per payout address its shares, hashrate, ledger balance, queue position and expected wait,
  linking to a per-address page with workers, payouts and credited shares
- **Pool Blocks** - recent pool blocks, what each paid, the treasury base and change, and
  settlement (matched, provisional, mismatched, undone by a reorg)
- **Share Chain** - tip, sync, relay counters, checkpoints and pruning
- Bitcoin node, privacy, filtering, storage and system pages for the node itself

A value the node does not report is shown as unknown, and a failed call as unavailable; neither
is ever shown as healthy or zero.

## Architecture

```
+------------------+     +------------------+     +------------------+
|    Dashboard     |     |   ghost-node     |     |   ghost-mining     |
|    (Next.js)     | --> |   (Rust API)     | --> |   (Pool DB)      |
|    Port 3000     |     |   Port 8080      |     |   SQLite         |
+------------------+     +------------------+     +------------------+
```

The dashboard queries the node backend's REST API through its own `/api/proxy` route (which
signs requests with `INTERNAL_AUTH_KEY`). The node pool pages read `GET /api/v1/node-pool/status`,
`GET /api/v1/ledger/{address}` and `GET /api/v1/miner/{address}`, which the backend forwards to
pool_sv2's loopback monitoring listener; their JSON is documented in
`bins/pool-sv2/src/lib/node_pool_api.rs` and `node_pool_miner_api.rs`.

## Development

### Prerequisites
- Node.js 18+
- npm or bun

### Setup

```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) to view the dashboard.

### Environment Variables

Create `.env.local` for local development:

```env
# API endpoint (defaults to localhost:8080)
NEXT_PUBLIC_API_URL=http://localhost:8080
```

### Build

```bash
# Production build
npm run build

# Start production server (custom Node server — see below)
npm start
```

## WebSocket authentication (custom server)

Real-time updates use a WebSocket. App-Router route handlers cannot upgrade a
connection, so the dashboard ships a **custom Node server** (`server.js`) that
wraps Next.js and owns the HTTP `upgrade` event:

- The browser connects to the **same-origin** endpoint `wss?://<host>/api/ws`
  (never straight to the backend `:8080`).
- On upgrade, `server.js` validates the `ghost-session` JWT — the *same* cookie
  the middleware and REST proxy enforce. An unauthenticated upgrade is answered
  with `401` and never becomes a socket.
- Only after the token verifies does the server open a socket to the loopback
  backend `/ws` and pipe frames through (the operator's cookie is stripped
  before forwarding).

This closes the previous hole where the browser opened a raw, unauthenticated
socket directly to `ws://<host>:8080/ws`.

### Deployment note (IMPORTANT)

The dashboard entry point is now `server.js`, not `next start`:

- `npm start` runs `NODE_ENV=production node server.js`.
- With `output: 'standalone'`, the Docker image copies `server.js` over the
  generated `.next/standalone/server.js`. **Any systemd unit / process manager
  must launch `node server.js` (from the standalone dir), not `next start`** —
  `next start` does not run the WS relay and is incompatible with standalone.
- `HOSTNAME` defaults to `127.0.0.1` (loopback); access remotely via SSH tunnel
  (`ssh -L 3000:localhost:3000 <node>`).

### Defence-in-depth: backend `:8080`

The node API (`ghost-verification`) listens on `0.0.0.0:8080` because mesh peers
challenge each other over it, and its `/ws` runs unauthenticated
(`WsState::new()` → `require_auth:false`). The `/api/ws` relay is therefore the
**user-auth boundary** for the browser. Operators should still confirm the API
is not needlessly exposed:

```bash
# Expect the node API bound as intended (mesh reachability is by design):
ss -ltnp 'sport = :8080'
```

Locking `:8080` to loopback would break inter-node verification, so it is left
as-is; hardening the backend `/ws` (enabling `require_auth` in prod wiring, or
serving `/ws` on a separate loopback listener) is tracked as a backend follow-up
and is out of scope for this dashboard change.

## Pages

| Route | Description |
|-------|-------------|
| `/` | Node pool health, Bitcoin sync, share-chain tip, settlement, fee address, start values |
| `/miners` | Connected miners: slot class, sensing, firmware warnings, shares, balance, queue, wait |
| `/miners/{address}` | One payout address: workers, ledger, next-block payout by class, payouts, shares |
| `/blocks` | Recent pool blocks, payouts, treasury base and change, settlement |
| `/share-chain` | Tip, sync, relay counters, checkpoints and pruning |
| `/mining` | Stratum endpoints and the username rule |
| `/settings` | Identity, node pool settings (read-only), alerts and node configuration |

## Tests

`npm test` renders the node pool pages from sample JSON shaped as pool_sv2 serves it
(`tests/fixtures/`, checked field by field against the Rust structs) and from a failed API, with
the real components compiled by `tests/helpers/tsx.js`.

## Deployment

### Systemd Service

This is the canonical unit — `/etc/systemd/system/ghost-dashboard.service`,
matching what runs on the fleet:

```ini
[Unit]
Description=Ghost Node Dashboard
After=ghost-node.service
Wants=ghost-node.service

[Service]
Type=simple
User=ghost
Group=ghost
WorkingDirectory=/home/ghost/agathion-node
ExecStart=/usr/bin/node server.js
Environment=NODE_ENV=production
Environment=PORT=3000
Environment=HOSTNAME=127.0.0.1
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Three details are load-bearing, and each has bitten us:

- **`ExecStart=/usr/bin/node server.js`, never `npm start` or `next start`.**
  The standalone build ships a minimal `node_modules` with no `package.json`
  scripts, so `npm start` cannot run there at all, and `next start` does not
  run the WS relay. See the deployment note above.
- **`WorkingDirectory=/home/ghost/agathion-node`.** A stale value here is the
  classic "I deployed but nothing changed" symptom — the unit runs an older
  tree. Always confirm the *effective* value rather than trusting the unit
  file, since drop-ins override it:
  ```bash
  systemctl show -p WorkingDirectory --value ghost-dashboard
  ```
- **`HOSTNAME=127.0.0.1`.** The dashboard must stay loopback-bound; it is
  reached over an SSH tunnel. Auth does not depend on this (the JWT fails
  closed regardless), but binding publicly removes a layer for no benefit.

Secrets do **not** belong in this unit. `DASHBOARD_PASSWORD` lives in
`/etc/ghost/dashboard.env` (root-only, 600), which the unit reads with
`EnvironmentFile=`: systemd shows `Environment=` values to every local user
(`systemctl show`) and never shows a file's contents. `INTERNAL_AUTH_KEY` is in
the `internal-auth.conf` drop-in, which `install-node.sh` keeps equal to
`pool.toml`'s `internal_api_secret`.

### On a node

`install-node.sh` installs the dashboard with the node, from the same signed
release (`bitcoin-ghost-<tag>-dashboard.tar.gz`, packed by
`scripts/package-dashboard.sh`), with Node.js under `/opt/ghost/node`, as
`ghost-dashboard.service` (`scripts/systemd/ghost-dashboard.service`). The
auto-updater moves it with each node pool release. See `RUN.md`.

## Password recovery

Auth is a single `DASHBOARD_PASSWORD`, and the dashboard binds loopback. There
is **no web-based reset**, because a web endpoint that reset the password would
be an authentication bypass (anyone who could reach the login page could take
over the node). The recovery credential is **node access itself**: the
installer generated the password on the node, and reading it needs root there:

```bash
sudo grep DASHBOARD_PASSWORD /etc/ghost/dashboard.env
```

To set a new one, edit that file and `sudo systemctl restart ghost-dashboard`.
With `DASHBOARD_JWT_SECRET` unset (the default), the signing secret derives from
the password, so a new password also ends every existing session. The login
page's "Forgot password?" link says the same.

## Technology Stack

- **Framework**: Next.js 14 (App Router)
- **UI**: Tailwind CSS, custom components
- **State**: React Query (TanStack Query)
- **Charts**: Recharts
- **Build**: Turbopack (dev), Webpack (prod)

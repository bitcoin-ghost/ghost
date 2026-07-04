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

The dashboard provides:
- **Node Status** - Sync height, peer count, uptime, and service health
- **Mining** - Stratum connections, hashrate, shares, blocks found
- **Rewards** - Share breakdown (5-4-3-2-1 model), payout history, earnings projections
- **Ghost Pay (L2)** - Block height, epoch, wraith sessions, settlement status
- **Mesh Network** - Consensus status, peer connections, verification challenges
- **Swarm Management** - Multi-node fleet monitoring and alerts

## Architecture

```
+------------------+     +------------------+     +------------------+
|    Dashboard     |     |   ghost-node     |     |   ghost-pool     |
|    (Next.js)     | --> |   (Rust API)     | --> |   (Pool DB)      |
|    Port 3000     |     |   Port 8080      |     |   SQLite         |
+------------------+     +------------------+     +------------------+
```

The dashboard queries the ghost-node REST API, which in turn:
- Reads node configuration and status directly
- Queries the ghost-pool SQLite database for challenge stats and payouts
- Connects to ghost-pay-node for L2 status
- Aggregates data from configured swarm nodes

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
| `/` | Overview with key metrics |
| `/mining` | Stratum mining status and connected miners |
| `/rewards` | Share breakdown, earnings, payout history |
| `/ghost-pay` | L2 network status, wraith sessions |
| `/operator/mesh` | BFT consensus and verification challenges |
| `/operator/rewards` | Detailed share contributions and network stats |
| `/operator/swarm` | Multi-node fleet management |
| `/network` | Pool-wide statistics and payout transparency |
| `/settings` | Node configuration |

## Share Model (5-4-3-2-1)

Nodes earn shares based on verified capabilities:

| Feature | Shares | Verification |
|---------|--------|--------------|
| Archive Mode | +5 | Random historical block challenges (95% pass rate) |
| Ghost Pay | +4 | L2 block challenges (90% pass rate) |
| Public Mining | +3 | Stratum port accessibility checks (95% pass rate) |
| Bitcoin Pure | +2 | Policy compliance challenges (95% pass rate) |
| Elder Status | +1 | First 101 registered nodes |

**Maximum: 15 shares per node**

## API Integration

The dashboard uses React Query for data fetching with automatic refresh:

```typescript
// Example: Fetch mesh status
const { data, isLoading } = useMeshStatus();
// Refreshes every 30 seconds

// Example: Fetch rewards with custom interval
const { data } = useRewards({ refetchInterval: 60_000 });
```

### Key API Endpoints

- `GET /api/v1/status` - Node status
- `GET /api/v1/mesh/status` - Consensus and challenge stats
- `GET /api/v1/rewards/full` - Complete rewards breakdown
- `GET /api/v1/rewards/node-history` - Payout history for this node
- `GET /api/v1/ghostpay/status` - L2 network status
- `GET /api/v1/swarm` - Fleet node status

## Deployment

### Systemd Service

The dashboard runs as a systemd service on Ghost nodes:

```ini
[Service]
ExecStart=/usr/bin/npm start
WorkingDirectory=/home/ghost/ghost/ghost-node/dashboard
User=ghost
```

### With ghost-node

When deployed alongside ghost-node, the dashboard is accessible at the node's IP on port 3000. Ensure the ghost-node API is running on port 8080.

## Password recovery

Auth is a single `DASHBOARD_PASSWORD`, read from the dashboard's systemd
drop-in (`/etc/systemd/system/ghost-dashboard.service.d/override.conf`), and
the dashboard binds loopback. So a forgotten password can lock the operator
out — there is **no web-based reset**, because a web endpoint that reset the
password would be an authentication bypass (anyone who could reach the login
page could take over the node).

Instead, the recovery credential is **node access itself**: reaching the
dashboard already implies SSH or local access to the node, and only someone
with that access should be able to reset the password. Run this on the node,
as root:

```bash
sudo scripts/agathion-reset-password.sh
```

It:

- Generates a strong password (or accepts one via `--password <value>`).
- Writes it to the systemd drop-in as the `DASHBOARD_PASSWORD=` line,
  **preserving every other `Environment=` entry**, and creates the drop-in if
  it does not exist yet.
- Drops any explicit `DASHBOARD_JWT_SECRET=` so the JWT signing secret
  re-derives from the new password — this plus the restart invalidates all
  existing `ghost-session` cookies (old sessions die).
- Runs `systemctl daemon-reload && systemctl restart ghost-dashboard`.
- Prints the new password.

The script backs up the drop-in before editing it and is idempotent (re-running
just sets a fresh password). Useful flags: `--no-restart` (write only),
`--service <name>` (non-default unit name), `--help`. The login page's "Forgot
password?" link points operators here.

## Technology Stack

- **Framework**: Next.js 14 (App Router)
- **UI**: Tailwind CSS, custom components
- **State**: React Query (TanStack Query)
- **Charts**: Recharts
- **Build**: Turbopack (dev), Webpack (prod)

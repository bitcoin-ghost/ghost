# Node Dashboard

*Monitor your node, track rewards, and manage settings through a web-based dashboard.*

## Overview

Every Ghost node includes a local web dashboard for monitoring and configuration. The dashboard is:

- **Local-only by default** — No public internet exposure
- **Real-time** — Live updates via WebSocket
- **Responsive** — Works on desktop and mobile
- **Secure** — JWT authentication, no external dependencies

- **Status**: ● Online (99.8% uptime)
- **Sync**: 870,234 / 870,234 (100%)
- **Mining**: 1.2 PH/s (12 miners)
- **Shares**: ⭐⭐⭐⭐ (14/15)
- **This Round**: ~0.0234 BTC

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

### Overview Page

- Node status and uptime percentage
- Blockchain sync progress
- Mining hashrate and connected miners
- Current share count (0-15)
- Estimated rewards this round
- Network statistics

### Mining Page

- List of connected miners with hashrate
- Share statistics per worker
- Template profile selector
- Stratum endpoint display
- Historical hashrate graph

### Rewards Page

- Share breakdown (which shares you're earning)
- Payout history with transaction links
- Earnings chart over time
- Payout address configuration

### Network Page

- Pool-wide statistics
- Connected peers list
- Elder registry and your status
- Treasury progress and decay status

### Settings Page

- Ghost Mode toggle
- Archive Mode toggle
- Public Mining toggle
- Mempool and template profiles
- Pruning configuration
- Security settings (rotate `DASHBOARD_PASSWORD` via systemd override)

### Logs Page

- Live log streaming
- Filter by level (info, warn, error)
- Filter by source (core, pool, node)
- Search functionality
- Download logs

## API Access

The dashboard is powered by a REST API that you can also use directly:

Note which service you are talking to. Port `8080` is the **node backend**
(`ghost-verification`), a different process from the dashboard on port `3000`.
The dashboard's authentication does not apply to it, and never did — the
examples below work because these particular backend routes are unauthenticated
in their own right, not because of any localhost exemption.

```bash
# Against the node backend on :8080 (not the dashboard):

# Example: Get node status
$ curl http://localhost:8080/api/v1/node/status

# Example: Get mining stats
$ curl http://localhost:8080/api/v1/mining/status

# Example: Toggle Ghost Mode
$ curl -X PATCH \
     -H "Content-Type: application/json" \
     -d '{"ghost_mode": true}' \
     http://localhost:8080/api/v1/config
```

The dashboard's own API (port `3000`, including the `/api/v1/*` proxy) is a
different matter: it requires a session on **every** request, including from
localhost. Authenticate at `/login` with the configured `DASHBOARD_PASSWORD` to
receive the `ghost-session` JWT cookie; subsequent requests include the cookie
automatically. A request without one is redirected to `/login` (pages) or
answered `401` (API) — there is no local exemption.

Full API documentation: [docs.ghostpool.io/api](https://docs.ghostpool.io/api)

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

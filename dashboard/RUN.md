# Running the node dashboard

The node dashboard is the operator's view of a Ghost node pool node. This is the
**standalone** Next.js build; it needs a **Node.js runtime (>= 22)** (the bundle ships only
the app's minimal `node_modules`, not Node itself).

**On a node set up with `install-node.sh` there is nothing to do here.** The installer
installs this bundle from the same signed release as the node, with its own Node.js runtime
under `/opt/ghost/node`, as `ghost-dashboard.service`, and the auto-updater moves it with
each node pool release. Its password is in `/etc/ghost/dashboard.env` (root-only):

```bash
sudo grep DASHBOARD_PASSWORD /etc/ghost/dashboard.env
```

The rest of this file is for running the bundle by hand.

## Start

```bash
# from inside this directory
DASHBOARD_PASSWORD='choose-a-strong-password' node server.js
```

The launch command is **`node server.js`**, not `next start`. The custom `server.js` is the
auth entrypoint: it wraps Next.js and owns the HTTP `upgrade` event so the real-time `/api/ws`
WebSocket is gated by the same session JWT as the REST API. `next start` does not run that
relay and is incompatible with the standalone output.

## Environment

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `DASHBOARD_PASSWORD` | yes | — | Login password. Also derives the JWT signing secret when `DASHBOARD_JWT_SECRET` is unset. |
| `DASHBOARD_JWT_SECRET` | no | derived from `DASHBOARD_PASSWORD` | Explicit HS256 signing secret (must be >= 32 chars). |
| `INTERNAL_AUTH_KEY` | yes, for node data | — | The node's `internal_api_secret` (`/etc/ghost/pool.toml`). The installer writes it to `/etc/systemd/system/ghost-dashboard.service.d/internal-auth.conf`. |
| `PORT` | no | `3000` | Listen port. |
| `HOSTNAME` | no | `127.0.0.1` | Bind address. Loopback by design; reach it through an SSH tunnel: `ssh -L 3000:127.0.0.1:3000 <you>@<node>`, then open http://localhost:3000. Set `0.0.0.0` only for deliberate LAN exposure (the password is still enforced). |
| `NEXT_PUBLIC_API_URL` | no | `http://127.0.0.1:8080` | The node's ghost-mining REST/WS API. |

## Deploying as a service

The unit the installer writes (`scripts/systemd/ghost-dashboard.service` in the repository),
with this bundle at `/opt/ghost/dashboard` and Node.js at `/opt/ghost/node`. Change
`WorkingDirectory` and the `node` path to wherever you put them:

```ini
[Unit]
Description=Bitcoin Ghost node dashboard
After=network-online.target ghost-mining.service
Wants=network-online.target

[Service]
Type=simple
User=ghost
Group=ghost
WorkingDirectory=/opt/ghost/dashboard
ExecStart=/opt/ghost/node/bin/node server.js
Environment=NODE_ENV=production
Environment=PORT=3000
Environment=HOSTNAME=127.0.0.1
Environment=NEXT_PUBLIC_API_URL=http://127.0.0.1:8080
EnvironmentFile=-/etc/ghost/dashboard.env
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

`ExecStart` must be `node server.js`. Neither `npm start` nor `next start` works here: this is
a standalone build, so its minimal `node_modules` has no `package.json` scripts for `npm start`
to run, and `next start` does not serve the authenticated WS relay.

Keep the password in a root-only file read with `EnvironmentFile=`, not in an `Environment=`
line: systemd shows `Environment=` values to every local user (`systemctl show
ghost-dashboard -p Environment`), and never shows a file's contents.

```bash
sudo install -m 600 /dev/null /etc/ghost/dashboard.env
echo "DASHBOARD_PASSWORD=$(openssl rand -hex 16)" | sudo tee /etc/ghost/dashboard.env >/dev/null
sudo systemctl daemon-reload && sudo systemctl enable --now ghost-dashboard
```

After any redeploy, confirm the unit is running the tree you just installed (a stale
`WorkingDirectory` is the usual cause of "I deployed but nothing changed"):

```bash
systemctl show -p WorkingDirectory --value ghost-dashboard
```

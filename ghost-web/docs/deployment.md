# Deployment

*How to stand up a Ghost node from scratch on Linux. Covers the full stack: ghost-core (the validating node), ghost-pool (the mining-pool daemon), and optionally ghost-pay (the L2 payment network). Targets operators who want their node visibly participating in the mesh, not someone trying out the software in dev mode.*

## What you're deploying

Three binaries that talk to each other:

```
                   ┌─────────────────┐
                   │   ghost-core    │   Bitcoin Core fork
                   │   (port 8332)   │   validates the chain
                   └────────┬────────┘
                            │ RPC + ZMQ
              ┌─────────────┴─────────────┐
              │                           │
   ┌──────────▼──────────┐     ┌─────────▼─────────┐
   │     ghost-pool      │     │     ghost-pay     │
   │  decentralised pool │◄────┤    L2 daemon      │
   │  Stratum + BFT mesh │     │   (optional)      │
   │  (ports 3333/8080…) │     │   (port 8800)     │
   └──────────┬──────────┘     └───────────────────┘
              │ Stratum V1 (port 3333)
              │ Stratum V2 (port 34255)
              ▼
        ┌──────────┐
        │  miners  │
        └──────────┘
```

You always need ghost-core. You almost always want ghost-pool — it's what makes the node a mining-pool participant and earns capability shares. ghost-pay is optional: it adds the L2 payments network and qualifies the node for the +4 GhostPay capability share if you also pass the verification challenges.

## Hardware

| Component | Minimum | Recommended |
|---|---|---|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16+ GB |
| Storage | 500 GB SSD | 1 TB NVMe |
| Network | 100 Mbps symmetric | 1 Gbps |

The disk requirement depends on archive mode. A hazed node sits around 195 GB; a full archive is ~720 GB and growing. Most VPS hosts that advertise 500 GB SSD work for hazed; for full archive plan on 1 TB.

## Software

- **OS:** Ubuntu 22.04 LTS or Debian 12. Other distributions work but aren't tested first.
- **Rust:** 1.75+ (only required if building from source).
- **SQLite 3.35+** — bundled with ghost-pool, no separate install.
- **SQLCipher** — required for ghost-pay if you run it. Available as `libsqlcipher-dev` on Debian-family.

A minimal apt install:

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev libsqlcipher-dev
```

If building from source, also install Rust:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

## Install ghost-core

ghost-core is a fork of Bitcoin Core with the haze, Reaper, and Shroud features added. Build it first so it's ready to validate the chain while you set up ghost-pool.

```bash
git clone https://github.com/bitcoin-ghost/ghost-core.git
cd ghost-core
./autogen.sh
./configure --with-gui=no
make -j$(nproc)
sudo make install
```

Configure it via `/etc/ghost/bitcoin.conf`:

```ini
# Connection
rpcuser=ghostrpc
rpcpassword=CHOOSE_A_LONG_RANDOM_PASSWORD
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcport=8332

# ZMQ — ghost-pool reads new-block notifications via these
zmqpubhashblock=tcp://127.0.0.1:28332
zmqpubhashtx=tcp://127.0.0.1:28333

# Privacy features (defaults; set them explicitly so the choice is in the config)
shroud=1
ghostmode=0
hazemode=Hazed   # or FullArchive if you want to serve raw block data
```

Start it under systemd. A skeleton unit at `/etc/systemd/system/ghost-core.service`:

```ini
[Unit]
Description=Ghost Core (Bitcoin)
After=network.target

[Service]
Type=simple
User=bitcoin
ExecStart=/usr/local/bin/ghostd -conf=/etc/ghost/bitcoin.conf -datadir=/var/lib/bitcoin
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

`sudo systemctl enable --now ghost-core` and let it sync. Initial Block Download takes ~3 minutes via snapshot sync (hazed mode) or several hours from genesis on a slow link.

## Install ghost-pool

Either build from source or download a release.

### Build from source

```bash
git clone https://github.com/bitcoin-ghost/ghost.git
cd ghost
cargo build --release -p ghost-pool --features zk-production
```

The `--features zk-production` flag is **required for mainnet** — it bakes in the requirement that real MPC ceremony parameters be present at runtime. Without it, the binary will refuse to start on mainnet with: `MAINNET SECURITY: ZK consensus on mainnet requires trusted setup parameters`. There are no exceptions to this rule.

Binary lands at `target/release/ghost-pool`. Move it into place:

```bash
sudo mkdir -p /opt/ghost/bin
sudo cp target/release/ghost-pool /opt/ghost/bin/ghost-pool
sudo chown root:root /opt/ghost/bin/ghost-pool
sudo chmod 755 /opt/ghost/bin/ghost-pool
```

### Pre-built binaries

```bash
wget https://github.com/bitcoin-ghost/ghost/releases/latest/download/ghost-pool-linux-amd64.tar.gz
tar -xzf ghost-pool-linux-amd64.tar.gz
sudo cp ghost-pool /opt/ghost/bin/ghost-pool
```

Verify the signature (see [Security](/security.html) for the disclosure flow's GPG fingerprint).

## Configure ghost-pool

The minimum config that runs on mainnet, at `/etc/ghost/pool.toml`:

```toml
[identity]
key_path = "/etc/ghost/node.key"
display_name = "MyGhostNode"

[bitcoin]
network        = "mainnet"
rpc_host       = "127.0.0.1"
rpc_port       = 8332
rpc_user       = "ghostrpc"
rpc_password   = "MUST_MATCH_BITCOIN_CONF"
zmq_hashblock  = "tcp://127.0.0.1:28332"
zmq_hashtx     = "tcp://127.0.0.1:28333"

[network]
public_address    = "pool.example.com"
sv1_port          = 3333
sv2_port          = 34255
http_port         = 8080
public_mining     = true                # qualifies for the +3 PublicMining share
mining_mode       = "PublicPool"        # PublicPool | PrivatePool | PrivateSolo

# REQUIRED on mainnet:
noise_enabled        = true
internal_api_secret  = "$(openssl rand -hex 32)"
seed_nodes           = ["tcp://83.136.251.162:8559", "tcp://85.9.198.212:8559"]
shroud_enabled       = true

[network.p2p]
share_propagation    = 8555
block_announcement   = 8556
consensus_voting     = 8557
health_monitoring    = 8558
discovery            = 8559
elder_management     = 8560
payout_proposal      = 8561
payout_transaction   = 8562

[policy]
profile = "permissive"   # bitcoin_pure | permissive | full_open

[storage]
db_path     = "/var/lib/ghost/data"
wal_mode    = true
haze_mode   = "Standard"

[pool]
treasury_address  = "bc1q..."        # YOUR treasury P2TR address
min_payout_sats   = 10000
```

**Items you must change before the first start:**

- `bitcoin.rpc_password` — match what's in `bitcoin.conf`.
- `network.public_address` — your reachable hostname or IP. Leave blank only if not running public mining.
- `network.internal_api_secret` — generate with `openssl rand -hex 32`. Required on mainnet; ghost-pool refuses to start without it.
- `pool.treasury_address` — a P2TR (`bc1p…`) address you control. The pool fee accumulates here until the treasury threshold is reached.

**Items the deploy fails on if missing:**

The mainnet config validator will reject the start with a specific error if any of these are missing or wrong:

| Missing | Error |
|---|---|
| `noise_enabled = true` | "MAINNET SECURITY: Noise Protocol encryption is REQUIRED for mainnet" |
| `internal_api_secret` | "MAINNET SECURITY: Internal API authentication is REQUIRED for mainnet" |
| `seed_nodes` empty | "MAINNET SECURITY: At least one seed node is REQUIRED for mainnet" |
| `signing_key` missing when `public_mining = true` | "signing_key is REQUIRED when public_mining is enabled" |

These are deliberate hard fails. Don't try to work around them.

## Generate keys

Two keys per node, both managed by `ghost-pool` itself:

```bash
# Ed25519 node identity. Writes to <data_dir>/node.key (default
# ~/.ghost/node.key for the running user). No --output flag — the path
# is derived from --data-dir / config. The PoW step takes a few seconds.
sudo -u ghost /opt/ghost/bin/ghost-pool --generate-identity

# Inspect the generated identity (Node ID, signer type)
sudo -u ghost /opt/ghost/bin/ghost-pool --show-identity

# Tighten permissions on the resulting key file
sudo chmod 600 /home/ghost/.ghost/node.key

# X25519 Noise keypair: auto-generated on first start at
# <data_dir>/noise.key if it doesn't already exist. There is no separate
# subcommand to generate it — just start the service once and the key
# file appears alongside node.key.
```

The node identity is your peer ID forever. Lose it and you lose your peer slot, your verification history, and (if you're an Elder) your Elder position. Back it up.

## Systemd unit for ghost-pool

`/etc/systemd/system/ghost-pool.service`:

```ini
[Unit]
Description=Ghost Pool
After=network.target ghost-core.service
Wants=ghost-core.service

[Service]
Type=simple
User=ghost
Group=ghost
ExecStart=/opt/ghost/bin/ghost-pool --config /etc/ghost/pool.toml
Restart=always
RestartSec=10
LimitNOFILE=65536

# Ensure ZK params are findable
Environment=ZK_PARAMS_PATH=/home/ghost/.ghost/mpc_params
Environment=ZK_PARAMS_HASH=<sha256-of-final-ossified-params>

[Install]
WantedBy=multi-user.target
```

Two environment variables matter on mainnet:

- `ZK_PARAMS_PATH` — directory containing the ossified MPC ceremony params (`note_spend_vk.bin`, `payout_vk.bin`, `unshield_vk.bin`).
- `ZK_PARAMS_HASH` — SHA256 of the params used to verify the binary loaded the right ones. The release notes for each version include the expected hash.

If the params don't match the hash, ghost-pool refuses to start. This protects against a node accidentally running with stale or test params.

## First-time mainnet checklist

Before flipping the service on, walk this checklist. Every item must pass:

**Build:**

- [ ] Binary built with `--features zk-production` (the binary will hard-fail at startup if not).
- [ ] Binary built with `--release` profile.
- [ ] `cargo clippy` clean (project allow rules apply).
- [ ] `cargo audit` clean (no known vulnerabilities).

**Configuration:**

- [ ] `pool.toml: bitcoin.network = "mainnet"`.
- [ ] `pool.toml: bitcoin.rpc_port = 8332`.
- [ ] `pool.toml: noise_enabled = true`.
- [ ] `pool.toml: internal_api_secret` set.
- [ ] `pool.toml: seed_nodes` contains at least one valid peer.
- [ ] `pool.toml: pool.treasury_address` is a P2TR address you control.
- [ ] If running ghost-pay: `GHOST_PAY_API_SECRET` and `GHOST_PAY_PASSWORD` set in the systemd unit, `--network mainnet` flag passed.

**ZK pipeline:**

- [ ] All three VK files present: `note_spend_vk.bin`, `payout_vk.bin`, `unshield_vk.bin`.
- [ ] MPC ceremony has completed for the cluster you're joining (not test params).
- [ ] `ZK_PARAMS_HASH` env matches the published hash for your ghost-pool version.

**Database:**

- [ ] Schema at the version expected by your binary. Migrations run on first start; check the log.
- [ ] If running ghost-pay: SQLCipher encryption enabled on `ghost-pay.db`.
- [ ] Backup scripts installed (recommended: nightly cron of `/var/lib/ghost/data` + `~/.ghost/mpc_params`).

**Operational:**

- [ ] `health-check.sh` (or similar) running every 15 minutes.
- [ ] Alerts wired to Slack / email / PagerDuty.
- [ ] `/metrics` endpoint scraping in your monitoring stack (Prometheus format).

**Network hardening (mainnet defaults):**

- [ ] Address validation rejects non-mainnet addresses.
- [ ] Subsidy mismatch is a hard error.
- [ ] Settlement requires 6 confirmations (not 1).
- [ ] TX-fee sanity limit active (>100 BTC rejected).

These are all on by default in the `--features zk-production` build. The checklist exists because surprise behaviours have caused incidents in the past.

## First start

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ghost-pool
sudo journalctl -u ghost-pool -f
```

What healthy startup logs look like, in order:

```
INFO  Ghost Pool starting...
INFO  Loaded config from /etc/ghost/pool.toml
INFO  Node identity:  <ed25519-public-key>
INFO  Coinbase tag:   - G H O S T - PublicPool
INFO  Loaded ZK params:  note_spend_vk (sha256: …)
INFO  Loaded ZK params:  payout_vk (sha256: …)
INFO  Loaded ZK params:  unshield_vk (sha256: …)
INFO  Connected to ghostd  network=mainnet  block_height=946700
INFO  Mesh listening on tcp://0.0.0.0:8563  (Noise)
INFO  Stratum V1 listening on 0.0.0.0:3333
INFO  Stratum V2 listening on 0.0.0.0:34255
INFO  Verification HTTP API on 0.0.0.0:8080
INFO  Connected to seed peer  83.136.251.162:8559
INFO  Connected to seed peer  85.9.198.212:8559
INFO  Ghost Pool is ready!
```

If you see the "Ghost Pool is ready!" line, the node is up and on the mesh.

If the log stops at `MAINNET SECURITY: …` — fix the mainnet hard-fail and restart.

## Verifying the node is actually participating

Within 1-2 minutes the node should:

1. **Appear in `/api/v1/mesh/status`** on a peer node, with `last_seen` updating every 10 seconds.
2. **Be receiving health pings** — `journalctl -u ghost-pool | grep "Received HealthPing"` should show entries.
3. **Have a registered Elder slot** if it's among the first 101 — visible via `/api/v1/mesh/elders`.

Run `curl -s http://localhost:8080/api/v1/mining/status | jq` to see the local view. Run the same against any peer's public IP to compare.

## Optional: ghost-pay (L2)

If you want the +4 GhostPay capability share, install ghost-pay alongside:

```bash
cargo build --release -p ghost-pay --features mainnet
sudo cp target/release/ghost-pay /opt/ghost/bin/ghost-pay
```

Configure via env vars in the systemd unit:

```ini
Environment=GHOST_PAY_API_SECRET=<openssl rand -hex 32>
Environment=GHOST_PAY_PASSWORD=<another-secret>
ExecStart=/opt/ghost/bin/ghost-pay --network mainnet --port 8800
```

The capability is verified by random L2-block-lookup challenges from peers. Pass rate ≥ 90% over 30 days qualifies the node.

## Where to look when things break

| Symptom | First check |
|---|---|
| ghost-pool exits at startup | `journalctl -u ghost-pool -n 50` — most config errors are explicit |
| Stuck at "Connecting to seed nodes" | Outbound 8559 not allowed by firewall, or seed nodes unreachable |
| Mesh count = 0 | Inbound 8563 (Noise) or 8559 (discovery) blocked, or peer reachability problem |
| Verification challenges all failing | HTTP API not reachable from peers, or `internal_api_secret` mismatch between this node and its peers |
| ZK params hash mismatch | Wrong binary version vs deployed params; rebuild matching the cluster's params |
| `MAINNET SECURITY` errors | A required mainnet field is missing — read the exact error, fix, restart |

The [Recovery runbook](#recovery) covers what to do when a running node breaks (DB corruption, mesh split, payout proposal divergence, etc).

## What this guide isn't

- **It isn't a tuning guide.** Defaults are sane; performance tuning is a separate exercise. Ghost-pool has been running at our reference cluster on 8-core / 16 GB / NVMe for months without configuration past the basics.
- **It isn't multi-node coordination.** A second node uses the same procedure on a different host; they discover each other through the seed-node list. There's no centralised registry or membership flow.
- **It isn't an exhaustive config reference.** Many fields exist that aren't covered here. The internal `DEPLOYMENT_RUNBOOK.md` lists every field; this doc covers the ones an operator must touch.
- **It isn't a security review.** [Security](/security.html) covers the disclosure flow. The deployment doc assumes operators know to keep their RPC credentials out of public repos and their `internal_api_secret` rotated.

## Source

| File | Purpose |
|---|---|
| `bins/ghost-pool/src/main.rs` | Service entry point + config loading + mainnet validation |
| `crates/ghost-common/src/config.rs` | NetworkConfig, P2PPortConfig structures |

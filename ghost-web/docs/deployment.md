# Deployment

*How to stand up a Ghost node on Linux with the one-line installer. Covers what the installer asks for, what it puts where, how the node comes up, and where to look when it doesn't. Targets operators who want their node visibly participating in the mesh, not someone trying out the software in dev mode.*

## What you're deploying

Four services on one machine, all installed by `scripts/install-node.sh`:

```
                   ┌─────────────────┐
                   │     ghostd      │   Bitcoin Core fork
                   │  (P2P 8333,     │   validates the chain
                   │   RPC 8332)     │
                   └────────┬────────┘
                            │ RPC + ZMQ (localhost)
                   ┌────────▼────────┐
                   │  ghost-mining   │   decentralised pool node
                   │  mesh 8555-8563 │   mesh, HTTP API, Template
                   │  HTTP 8080      │   Distribution (TDP)
                   │  TDP 8442       │
                   └────────┬────────┘
                            │ TDP
                   ┌────────▼────────┐
                   │    sri-pool     │   pool_sv2 — Stratum V2, the node
                   │   (SV2 34255,   │   pool's canonical coinbase and
                   │  relay 8566)    │   the share-chain relay
                   └────────┬────────┘
                            │ SV2 (localhost)
                   ┌────────▼────────┐
                   │ sri-translator  │   translator_sv2 — Stratum V1
                   │ (SV1 3333,      │   in front of the SV2 pool
                   │  farm tier 4444)│
                   └────────┬────────┘
                            ▼
                      ┌──────────┐
                      │  miners  │
                      └──────────┘
```

The systemd units are `ghostd`, `ghost-mining`, `sri-pool` and `sri-translator`, plus a fifth, `ghost-mining-gate`, which starts the last three once ghostd has synced (see *The boot gate*, below).

Every binary comes from the signed release tarball. For each release that tarball holds `ghostd`, `ghost-cli` (the ghostd RPC client, like `bitcoin-cli`), `ghost-mining`, `ghost-admin`, `pool_sv2`, `translator_sv2` and `ghost-pool` (a hard link to `ghost-mining`, kept so older installers still find it). The installer installs `ghostd`, `ghost-cli`, `ghost-mining`, `ghost-admin`, `pool_sv2` and `translator_sv2` into `/opt/ghost/bin`; it does not install the `ghost-pool` link.

## Before you start

**Machine.** The installer refuses anything that isn't `x86_64`, and must run as root. It uses `apt-get` and `ufw`, and is written for Ubuntu. Release tarballs also exist for macOS (x86_64 and aarch64), but the installer only uses the Linux one.

| Component | Minimum | Recommended |
|---|---|---|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16+ GB |
| Storage | 500 GB SSD | 1 TB NVMe |
| Network | 100 Mbps symmetric | 1 Gbps |

The installer's preflight (below) checks RAM and free disk against floors lower than this table: on mainnet it fails under 7 GB of RAM and warns under 15 GB, and it fails with less free space on `/var/lib` than 60 GB (`ibd`, which prunes), 250 GB (`haze`, which sits around 195 GB) or 800 GB (`--archive`, ~720 GB and growing). Signet and regtest have smaller floors.

**A fee address** that you control (`--fee-address`). Every transaction fee of a block this node's miners find is paid to it. It must be P2SH, P2WPKH, P2WSH or P2TR, on the network you install (`bc1…`/`3…` on mainnet, `tb1…`/`2…` on signet, `bcrt1…`/`2…` on regtest); P2PKH is refused. The installer verifies the checksum, so a typo is refused rather than paid. Miners are not paid through this address: they are paid from the block subsidy, by the share-chain ledger, at the address they mine with. There is no treasury address to give; the treasury is a protocol constant.

**An alert endpoint** (for example `https://ntfy.sh`). It is optional in the sense that the install completes without it, but then alerts are disabled and every detector — low disk, node offline, behind tip, restart loop — fires into nothing.

**Relay peers**, optionally (`--relay-peer host:port`, repeatable): other node pool nodes for the share-chain relay to dial first. Without any, the node waits for peers to dial it on the relay port (8566).

⚠ **SSH on a non-standard port.** The installer enables `ufw` with `--force` and only allows SSH on `22/tcp`. If your SSH daemon listens anywhere else, add that rule (`sudo ufw allow <port>/tcp`) *before* you run the installer, or you will lock yourself out.

## Install

```bash
curl -sSL https://get.bitcoinghost.org | sudo bash -s -- \
  --fee-address bc1q... \
  --alert-webhook https://ntfy.sh
```

That gives you the defaults: mainnet, full trustless sync with pruning, the node pool (the only mode), the mempool Reaper on, no archive, no Tor, no automatic updates.

**The release must be pinned.** Every release published on GitHub so far is the old network's, which keeps running beside the node pool, so the installer does not track the latest release: it refuses to install without `GHOST_VERSION` naming a node pool release. Set it after `sudo`, so it survives into the root shell:

```bash
curl -sSL https://get.bitcoinghost.org | sudo GHOST_VERSION=<node pool release tag> bash -s -- --fee-address ...
```

**No contact with the old network.** A node pool node writes no mesh seed nodes (`seed_nodes = []` in `pool.toml`) and keeps the old mesh ports (8555–8563) and 8443 closed, so it neither dials nor accepts the old fleet's mesh. Its peers are share-chain relay peers only (`--relay-peer`). Automatic updates are off and `--auto-update` is ignored with a warning: the updater tracks the latest GitHub release, which is the old network's.

**Reading it first.** The installer is one self-contained shell script. To read it before it runs as root, download it and run the file:

```bash
curl -sSLo install-node.sh https://get.bitcoinghost.org
less install-node.sh
sudo bash install-node.sh --fee-address bc1q... --alert-webhook https://ntfy.sh
```

Run from a file like this, with **no** flags at all, on a terminal, the installer starts a guided setup wizard instead. It asks for the network, the fee address (re-asking until it is valid for that network), relay peers, an alert webhook and topic (optional), sync mode, pool name, Reaper, archive, Tor, auto-update, nightly backups and nickname, shows a summary and asks before it changes anything. Piped through `curl`, the wizard never runs; `--non-interactive` also turns it off.

### Preflight

Every install starts with a preflight, before anything on the machine is changed. Each check prints one line, `[PASS]`, `[WARN]` (installs anyway) or `[FAIL]`; any FAIL stops the install with `Nothing has been changed`. `--preflight-only` runs the checks and exits.

| Check | FAIL when | WARN when |
|---|---|---|
| Fee address | not P2SH/P2WPKH/P2WSH/P2TR, wrong network, bad checksum | |
| RAM | below the network's floor (mainnet 7 GB) | below the recommended size (mainnet 15 GB) |
| Disk | free space on `/var/lib` below the floor for the network and sync mode | |
| Ports | ghostd P2P, 8332, 8080, 8442, 3333, 4444, 34255, 9090 or the relay port is held by a process that is not this node's own (a re-run is fine) | |
| Bitcoin node | a node already answering on 127.0.0.1:8332 runs another chain, or the RPC port listens but refuses `bitcoin.conf`'s credentials | |
| Relay | a `--relay-peer` is not `host:port` | no peers given; a peer does not resolve |
| Genesis | `--genesis-anchor` is not 64 hex characters, or all zeros | no share-chain genesis is published for the network (see below) |
| Alert webhook | not an `http(s)://` URL | none given |

On a fresh install there is no Bitcoin node yet; ghostd is installed, and the installer checks again once it runs and prints the result (`[PASS] Bitcoin node answers on 127.0.0.1:8332 (chain main)`) at the end. The relay port is opened on `ufw`; whether it is reachable from outside cannot be tested before anything listens on it, so open it on any firewall in front of the machine yourself.

### Flags

| Flag | Default | What it does |
|---|---|---|
| `--fee-address <address>` | — (required) | Where every transaction fee of a block this node's miners find is paid. `[node_pool] fee_address`. |
| `--network <mainnet\|signet\|regtest>` | `mainnet` | The Bitcoin network, for ghostd, ghost-mining and the node pool. |
| `--relay-port <port>` | `8566` | The share-chain relay port peers dial. Opened on `ufw`. |
| `--relay-peer <host:port>` | none | A relay peer to dial; repeat for more. More are learned from them. |
| `--genesis-anchor <hex>`, `--genesis-height <n>` | the network's | The share chain's genesis anchor and its Bitcoin height. See *Share-chain genesis*, below. |
| `--preflight-only` | | Run the preflight and exit. |
| `--alert-webhook <url>` | none | Push endpoint for node alerts. Without it, `[alerts]` is written with `enabled = false`. |
| `--alert-topic <name>` | `ghost-node` | Push topic. |
| `--nickname <name>` | `ghost-node` | Display name in the mesh. |
| `--pool-name <name>` | `GHOST PublicPool` | Custom coinbase tag, shown on explorers as `- G H O S T - <name>`. Printable ASCII, at most 30 characters. |
| `--sync <ibd\|haze>` | `ibd` | How ghostd stores the chain. See *Sync mode*, below. |
| `--no-reaper` | Reaper on | Don't run the mempool Reaper. |
| `--archive` | off | Full archive node (~720 GB). |
| `--tor` | off | Hybrid Tor: ghostd peers via Tor and publishes an onion, still reachable on clearnet 8333. |
| `--tor-only` | off | ghostd uses Tor only (`onlynet=onion`) and 8333 is closed. Implies `--tor`. |
| `--no-tor` | | Never use Tor (the default). |
| `--auto-update` | off | Ignored on node pool nodes for now, with a warning: the updater tracks the latest GitHub release, which is the old network's. |
| `--no-auto-update` | | Never auto-update (the default). |
| `--backups` | on | Back up the node database every night at 03:00 UTC, kept 7 days. See *Database backups*, below. |
| `--no-backups` | | No nightly backups. The job is still installed; switch it on later with `sudo systemctl enable --now ghost-backup.timer`. |
| `--non-interactive` | | Never start the wizard. |
| `-h`, `--help` | | Print the help. |

Old flags: `--payout-address` is the old name of `--fee-address` and still works. `--node-pool` is accepted and does nothing: the node pool's block reserve (`blockreservedweight=90000`) is always written. `--treasury-address`, `--mining-mode` and `--no-public-mining` are gone; there are no mining modes, treasury prompts or capability flags.

## Choices

### Sync mode

| `--sync` | Writes to `bitcoin.conf` | Meaning |
|---|---|---|
| `ibd` (default) | `prune=550` | Full trustless sync — every block validated — then old block files pruned. Takes hours, up to about a day. |
| `haze` | `hazemode=Hazed` | Strips block data, ~195 GB, faster. **Irreversible**: the node can never serve raw blocks or become an archive node without a full resync. See [Haze](#haze). |

`--archive` overrides both and writes `hazemode=FullArchive` (and `archive_mode = true` in `pool.toml`).

`--sync haze` stops and asks you to type `yes` at the terminal. With `--non-interactive` there is no prompt: passing it is taken as confirmation that you have read the warning above. Without a terminal and without `--non-interactive`, the installer refuses.

### The node pool

Every node is a node pool node; there is no other mode. Miners connect to `stratum+tcp://<your-ip>:3333` (hobby tier), `:4444` (farm tier, ~232,827 starting difficulty) or SV2 on `:34255`, and authorise as `<their payout address>.<worker>`. Their payout address must be P2SH, P2WPKH, P2WSH or P2TR. Each block the pool finds pays miners' ledger balances from the subsidy; this node's fee address takes the block's transaction fees when one of its miners finds it.

The installer writes the node pool into pool_sv2's config, `/etc/ghost/pool-config.toml`. pool_sv2 refuses to start without either section:

```toml
[node_pool]
fee_address = "bc1q..."

[node_pool.relay]
listen = "0.0.0.0:8566"
peers = ["peer.example:8566"]
db_path = "/var/lib/ghost/node-pool.db"
genesis_anchor = "..."
genesis_btc_height = ...
rpc_host = "127.0.0.1"
rpc_port = 8332
rpc_user = "..."
rpc_password = "..."
```

On regtest it also writes `tier_base` (regtest's proof-of-work limit), so CPU-mined shares reach the network tier.

### Share-chain genesis

The relay needs the share chain's genesis: the anchor every node's chain starts from, and its Bitcoin height. Nodes on different geneses never join each other.

| Network | Genesis written |
|---|---|
| mainnet | **`UNSET`** — none is published yet |
| signet | **`UNSET`** — none is published yet |
| regtest | `sha256("GhostNodePool/genesis/regtest")` = `8d8cd561…9c69f1229c`, height 0 |

With `UNSET` the install completes, the preflight warns, the config carries a marked placeholder, and **pool_sv2 refuses to start** with `node_pool.relay.genesis_anchor is UNSET: the share-chain genesis for this network has not been published, and this node will not guess one`. Set `genesis_anchor` and `genesis_btc_height` in `/etc/ghost/pool-config.toml` and restart `sri-pool`, or re-run the installer with `--genesis-anchor` and `--genesis-height`.

### Networks

`--network signet` or `regtest` writes `chain=<network>` and puts every `bitcoin.conf` setting in that chain's section, with the network's own P2P port (38333 or 18444); RPC stays on 8332. `pool.toml` gets `network = "<network>"`, and `assumevalid` is written only on mainnet.

### Tor

`--tor` installs Tor, adds `ControlPort 9051` with cookie authentication to `/etc/tor/torrc`, adds the `ghost` user to `debian-tor`, and gives ghostd `listenonion=1`, `torcontrol=127.0.0.1:9051` and `proxy=127.0.0.1:9050`. `--tor-only` adds `onlynet=onion` and removes the `8333/tcp` firewall rule.

Tor applies to ghostd's Bitcoin P2P only. ghost-mining's mesh, its HTTP API and the Stratum ports stay on clearnet, and `pool.toml` still records the machine's public IP.

## What the installer does

In order:

Before step 1 the preflight runs (see *Preflight*, above); a FAIL stops the install there, before anything is installed.

1. **Packages.** `apt-get install` of the libevent and ZeroMQ runtime libraries, `ufw`, `openssl`, `curl`, `gnupg`, `tar` (and `tor` with `--tor`).
2. **User and directories.** Creates the system user `ghost` with home `/home/ghost`, and `/opt/ghost/bin`, `/etc/ghost`, `/etc/bitcoin`, `/var/lib/bitcoin`, `/var/lib/ghost`, `/home/ghost/.ghost/data`. If you ran it via `sudo`, your own user is added to `systemd-journal` so `journalctl` works without sudo after your next login.
3. **Persistent journal.** Writes `/etc/systemd/journald.conf.d/10-ghost.conf`: `Storage=persistent`, 2 GB cap, 1 GB kept free, two weeks' retention. Without it the journal lives in RAM and a reboot erases the evidence you need.
4. **Download and verify.** Fetches `bitcoin-ghost-<version>-x86_64-unknown-linux-gnu.tar.gz`, `SHA256SUMS.txt` and `SHA256SUMS.txt.asc` from the GitHub release, imports the release key from `https://get.bitcoinghost.org/ghost-release-key.asc`, and requires a valid signature from exactly `777FE81F8CC077FD3D08055E852C2B3190F5B928` before checking the tarball's SHA256. Any failure stops the install before a binary is written.
5. **Secrets.** Generates a fresh RPC password, `internal_api_secret` and `signing_key`, all on this machine. Nothing is shared with any other node.
6. **Configs.** Writes `/etc/bitcoin/bitcoin.conf` and `/etc/ghost/pool.toml` (both `ghost`-owned, mode 600), `/etc/ghost/translator-config.toml` (644) and `/etc/ghost/pool-config.toml` (root-only 600; it holds the SV2 authority secret).
7. **Node identity.** Generates `/home/ghost/.ghost/node.key` with `ghost-mining --generate-identity` — unless one already exists, in which case it is kept.
8. **SV2 keys.** Generates a fresh SV2 pool authority keypair for this node, and derives ghost-mining's template-server key from `node.key` so pool_sv2 can pin it.
9. **Units.** Installs the units below, the firewall, the restart-loop watchdog and the auto-updater.
10. **Start.** Enables and starts `ghostd` and `ghost-mining-gate`. Nothing else.

### Files

| Path | What |
|---|---|
| `/opt/ghost/bin/` | All binaries and helper scripts |
| `/etc/bitcoin/bitcoin.conf` | ghostd config |
| `/var/lib/bitcoin` | ghostd data directory |
| `/etc/ghost/pool.toml` | ghost-mining config |
| `/home/ghost/.ghost/node.key` | Node identity |
| `/home/ghost/.ghost/data` | ghost-mining database |
| `/etc/ghost/pool-config.toml` | pool_sv2 (sri-pool) config, with `[node_pool]` and `[node_pool.relay]` |
| `/var/lib/ghost/node-pool.db` | The share-chain relay's store (anchors, batches, shares, ledger) |
| `/etc/ghost/translator-config.toml` | translator_sv2 (sri-translator) config |
| `/etc/ghost/auto-update.conf` | Auto-update opt-in |
| `/etc/ghost/backup.conf` | Optional off-node backup destination. Not present unless you configure one |
| `/etc/ghost/version` | Installed release version |

### Units

| Unit | Runs as | Enabled at boot | Started by |
|---|---|---|---|
| `ghostd` | `ghost` | yes | systemd |
| `ghost-mining-gate` | root | yes | systemd |
| `ghost-mining` | `ghost` | no | the gate |
| `sri-pool` | root | no | the gate |
| `sri-translator` | `ghost` | no | the gate |
| `ghost-mining-firewall.path` | root | yes | systemd |
| `ghost-restart-watch.timer` | root | yes | systemd |
| `ghost-auto-update.timer` | root | only with `--auto-update` | systemd |
| `ghost-backup.timer` | ghost | unless `--no-backups` | systemd |

### The boot gate

`ghost-mining`, `sri-pool` and `sri-translator` are **disabled at boot on purpose**. `ghost-mining-gate` runs `/opt/ghost/bin/wait-for-ghostd-sync.sh`, which asks ghostd's RPC for `getblockchaininfo` every 30 seconds. Once `initialblockdownload` is `false` it starts `ghost-mining`, then `sri-pool`, then `sri-translator`. On a fresh install that is hours away; on a normal reboot ghostd is already synced and the gate returns almost at once.

The gate is what keeps an unsynced node off the mesh. Don't `systemctl enable` the three gated units yourself.

### Firewall and ports

The installer enables `ufw` and allows:

| Port | Service | Notes |
|---|---|---|
| 22/tcp | SSH | The only SSH rule — see the warning above |
| 8333/tcp | ghostd P2P | 38333 on signet, 18444 on regtest. Removed with `--tor-only` |
| 8566/tcp | Node pool share-chain relay | `--relay-port` |
| 8080/tcp | ghost-mining HTTP API | |
| 8442/tcp | ghost-mining TDP | |

8555–8562 (the old mesh), 8563 (Noise mesh) and 8443 (verification HTTPS) are **not** opened, and a rule an older install left is deleted: ghost-mining still listens on them, but a node pool node has no mesh seeds and must not be reachable by the old network's mesh.

Three more ports are always open: 3333/tcp (SV1), 34255/tcp (SV2) and 4444/tcp (farm tier). `ghost-mining-firewall.path` re-runs `/opt/ghost/bin/reconcile-mining-firewall.sh` whenever `pool.toml` changes, so a rule removed by hand, or closed by an older private or solo install, is put back.

RPC (8332), ZMQ (28332–28334) and pool_sv2's monitoring endpoint (9090) are bound to `127.0.0.1`.

## After the install

The installer ends by printing the Node ID and each service's state:

```
  ✅ Bitcoin Ghost node installed (mainnet).
     Node ID: ...
     [PASS] Bitcoin node answers on 127.0.0.1:8332 (chain main)
     Fee address:     bc1q...
     Relay:           port 8566, peers: none yet
     Genesis:         UNSET — pool_sv2 will refuse to start until it is set in /etc/ghost/pool-config.toml
     Alerts:          https://ntfy.sh
     ghostd:          active
     ghost-mining-gate: active  (waiting for sync, then auto-starts ghost-mining)
     ghost-mining:    inactive  (started by the gate)
     sri-pool:        inactive  ...
     sri-translator:  inactive  ...
```

`inactive` is expected for the last three until ghostd finishes syncing.

Follow the sync, then the gate:

```bash
sudo journalctl -u ghostd -f
sudo journalctl -u ghost-mining-gate -f
```

When the gate logs `ghostd synced — starting ghost-mining`, the node joins the mesh. Then:

```bash
sudo journalctl -u ghost-mining -f
sudo journalctl -u sri-pool -u sri-translator -f
curl -s 'http://127.0.0.1:8080/health?unsigned=true'      # peer_count should be above 0
sudo -u ghost /opt/ghost/bin/ghost-cli -conf=/etc/bitcoin/bitcoin.conf getblockchaininfo
```

`ghost-cli` lives in `/opt/ghost/bin`, not on the default `PATH`, and needs `sudo -u ghost` because `bitcoin.conf` (which holds the RPC password) is readable only by `ghost`.

**Back up `node.key`.** `/home/ghost/.ghost/node.key` is the node's identity. The node ID derives from it, and the node pool's share tags commit to it. Lose it and the node becomes a different node; nothing on the machine backs it up for you. See [Key management](#key-management).

### pool.toml

The installer writes `/etc/ghost/pool.toml` in full. The flags land here:

| Flag | Key |
|---|---|
| `--network` | `[bitcoin] network` |
| `--nickname` | `[identity] display_name` |
| `--pool-name` | `[pool] pool_name` |
| `--archive` | `[storage] archive_mode` |
| `--no-reaper` | `[reaper] enabled` |
| `--alert-webhook`, `--alert-topic` | `[alerts]`, `[alerts.channels.push] webhook_url`, `topic` |

The node pool flags (`--fee-address`, `--relay-port`, `--relay-peer`, `--genesis-anchor`, `--genesis-height`) land in pool_sv2's `/etc/ghost/pool-config.toml`, under `[node_pool]` and `[node_pool.relay]` (see *The node pool*, above).

Older installs may carry keys for removed features (`[network] mining_mode`, `private_mining_password`, `solo_payout_address`, `[pool] treasury_address`, `node_payout_address`, `[coordinator]`, `[ghost_pay]`); they are read and ignored, and the installer no longer writes them.

The installer does not install the node dashboard. It writes `/etc/systemd/system/ghost-dashboard.service.d/internal-auth.conf` so that a dashboard installed later signs its requests with the same `internal_api_secret`. See [Node dashboard](#node-dashboard).

### Re-running the installer

Re-running keeps the things that identify the node: an existing `node.key` is kept, and `internal_api_secret`, `signing_key` and the SV2 authority keypair are read back from the existing `pool.toml` and `pool-config.toml` and reused, so SV2 miners that pinned the authority key keep working. Without the flags, the fee address, relay peers and a set share-chain genesis are also read back from `pool-config.toml`; an install from before the node pool, which has no fee address, uses its old payout address (`coinbase_reward_script`) as the fee address and says so. The relay store `/var/lib/ghost/node-pool.db` is never touched. Everything else is regenerated: `bitcoin.conf`, `pool.toml`, `pool-config.toml` and `translator-config.toml` are rewritten from the flags you pass this time, with a new RPC password. Hand edits to those files do not survive a re-run, and a re-run without the flags you used the first time sets those options back to their defaults.

## Automatic updates

⚠ **Not on node pool nodes yet.** The updater resolves the latest GitHub release, which is the old network's, so the installer leaves it off and ignores `--auto-update`. Do not switch it on from the dashboard either: it would replace the node pool binaries. The rest of this section describes the updater as it works on the old network.

Off by default. A node never upgrades itself unless you opt in, with `--auto-update` at install time or later:

```bash
sudo /opt/ghost/bin/ghost-autoupdate-toggle on     # or off
```

The toggle writes `AUTO_UPDATE=true|false` to `/etc/ghost/auto-update.conf` and enables or disables `ghost-auto-update.timer`. The updater is a no-op unless that file says exactly `AUTO_UPDATE=true`.

When it is on, `ghost-auto-update.timer` runs `/opt/ghost/bin/ghost-auto-update.sh` 15 minutes after boot and then every 6 hours, with up to an hour of random delay. Each run:

1. compares the latest GitHub release with `/etc/ghost/version`, and stops if it is not newer;
2. downloads the tarball, `SHA256SUMS.txt` and `SHA256SUMS.txt.asc`, and verifies the signature against the same pinned key and the tarball's checksum — on any failure no binary is touched;
3. backs up the current binaries next to themselves as `*.bak.<timestamp>`;
4. stops `sri-translator`, `sri-pool`, `ghost-mining` and `ghostd` in that order, swaps in the new `ghostd`, `ghost-mining`, `pool_sv2` and `translator_sv2` (and `ghost-cli` and `ghost-admin` where installed), and starts them again in the opposite order;
5. checks that ghostd's RPC answers, that ghost-mining's `/health` reports more than zero peers, and that the stratum stack is listening on 34255 and 3333, and rolls all of them back to the backups if any check fails.

The SV2 binaries always move with `ghost-mining`: a release that does not carry one your node runs is refused before anything is stopped.

The outcome of the last run is in `/var/lib/ghost/auto-update.status`. `sudo /opt/ghost/bin/ghost-auto-update.sh --dry-run` verifies the latest release and reports what it would swap, without swapping.

## Database backups

`ghost-backup.timer` runs `backup-databases.sh` as `ghost` every night at 03:00 UTC. It takes a `VACUUM INTO` copy of `ghost.db` (and `ghost-pay.db` where present), checks that the copy opens and passes `quick_check`, gzips it into `/var/backups/ghost/db`, and keeps copies that are newer than 7 days or among the newest 7. It refuses to run if free space is below the database size plus 1 GiB. The installer sets it up and enables it unless you pass `--no-backups` (or answer no in the wizard).

Those copies sit on the same disk as the database. They protect you from a bad migration or a corrupted file, but not from losing the disk or the VM.

### Off-node copy (optional)

Off by default, and never required. The network does not provide or pay for the storage. If you want a second copy somewhere you control, set it on the dashboard under **Settings › System › Nightly Database Backups**, or with the helper:

```bash
sudo /opt/ghost/bin/ghost-backup-offsite show
printf 'kind=local\ntarget=/mnt/backup-drive/ghost\nkeep=7\n' | sudo /opt/ghost/bin/ghost-backup-offsite set
printf 'kind=ssh\ntarget=backup@nas.example.org:/srv/ghost\nport=22\nkeep=7\n' | sudo /opt/ghost/bin/ghost-backup-offsite set
sudo /opt/ghost/bin/ghost-backup-offsite test
sudo /opt/ghost/bin/ghost-backup-offsite disable
```

The setting is stored in `/etc/ghost/backup.conf`. If that file doesn't exist, the nightly job does exactly what it did before. There are two kinds of destination:

- **A local directory**, such as a mounted USB drive or an NFS share. It must exist, `ghost` must be able to write to it, and it must be on a different filesystem from both `/var/backups/ghost/db` and the database. A directory on the same disk is refused because it isn't off-disk. This also covers a drive that has come unmounted: its empty mountpoint is on the root filesystem, so nothing is written there.
- **A server over SSH**, given as `user@host:/path` with an optional port. Copies go over SFTP, so a restricted SFTP-only account works. The node generates its own ed25519 key pair in `/var/lib/ghost-backup`, owned by `ghost`. The dashboard and `show` give you the **public** key, which you add to `~/.ssh/authorized_keys` for that account on the server. The private key is never shown. **Test** writes and removes a probe file and pins the server's host key the first time it succeeds. After that, the nightly copy accepts only that host key, and until it has been pinned, the nightly copy refuses to connect.

User names, host names and paths may contain only letters, digits and `. _ - /`. Anything else is rejected, including spaces, `..`, and characters a shell would interpret. IPv6 literals aren't supported; use a host name.

After the local backup succeeds, the nightly job copies that night's files to the destination, then deletes older copies there until only the newest `keep` (default 7) are left. It only ever deletes files whose names the job itself writes (`ghost-YYYYmmddHHMM.db.gz`, `ghost-pay-YYYYmmddHHMM.db.gz`). A local destination also has to have room for the copies plus 256 MiB, or the copy is refused.

**A failed off-node copy never fails or undoes the local backup.** The unit's exit status depends only on the local backup. The off-node outcome is written to `/var/lib/ghost-backup/offsite.status` (`last_offsite_result`, `last_offsite_time`, `last_offsite_error`), and the dashboard shows it. Copies are not encrypted before they leave the node, so store them somewhere only you can read.

## Alerts and the restart watchdog

With `--alert-webhook`, `pool.toml` gets an `[alerts]` block with a push channel. Without it the block is written with `enabled = false` and a comment saying so, and ghost-mining warns at every start. To add one later, set `[alerts] enabled = true` and fill in `[alerts.channels.push]`.

systemd restarts a crashing service for ever and reports it `active` between crashes. `ghost-restart-watch.timer` runs `/opt/ghost/bin/ghost-restart-watch.sh` every 5 minutes against `ghost-mining`, `sri-pool`, `sri-translator` and `ghostd`. It alerts through the node's own `[alerts]` configuration on two conditions: a unit restarting 3 or more times between runs, and a unit that is `active` but not listening on its port (8442, 34255, 3333 and 8332 respectively) for 3 consecutive checks. Optional settings go in `/etc/ghost/restart-watch.conf`.

## Where to look when things break

| Symptom | First check |
|---|---|
| Installer stops with `Release signature verification FAILED` or `Checksum verification FAILED` | The download did not match the signed release. Don't work around it; re-run, and if it persists report it. |
| Installer stops with `could not determine the latest release` | The GitHub API was unreachable. Re-run, or pin `GHOST_VERSION`. |
| Lost SSH after the install | `ufw` only allows 22/tcp. Use the provider's console and `ufw allow <port>/tcp`. |
| ghost-mining, sri-pool, sri-translator all `inactive` | Expected until ghostd is synced. `sudo journalctl -u ghost-mining-gate -f` — it logs `waiting for ghostd to finish initial sync...` until then. |
| ghostd not syncing | `sudo journalctl -u ghostd -n 100`; `sudo -u ghost /opt/ghost/bin/ghost-cli -conf=/etc/bitcoin/bitcoin.conf getblockchaininfo` |
| ghost-mining exits at startup | `sudo journalctl -u ghost-mining -n 100` — most config errors are explicit |
| `peer_count` stays at 0 | Inbound 8555–8563 or 8443 blocked upstream of `ufw` (a provider firewall or security group) |
| Miners can't connect | `sudo journalctl -u sri-pool -u sri-translator -n 100`; `sudo ufw status` should show 3333 (and 34255) for the pool modes. In `solo` mode they are closed on purpose. |
| A service keeps restarting, or is up but serving nothing | `sudo /opt/ghost/bin/ghost-restart-watch.sh --check` |
| An automatic update rolled back | `cat /var/lib/ghost/auto-update.status`; `sudo journalctl -u ghost-auto-update -n 100` |
| The off-node backup copy failed | `sudo /opt/ghost/bin/ghost-backup-offsite show` (see `last_result`); `sudo /opt/ghost/bin/ghost-backup-offsite test`; `sudo journalctl -u ghost-backup -n 100` |

The [Recovery runbook](#recovery) covers what to do when a running node breaks (DB corruption, mesh split, payout proposal divergence, etc).

## What this guide isn't

- **It isn't a tuning guide.** The installer's defaults are what the reference fleet runs.
- **It isn't multi-node coordination.** A second node runs the same installer on a different host; it finds other node pool nodes through the share-chain relay peers it is given (`--relay-peer`) and the peers they pass on. There's no centralised registry or membership flow.
- **It isn't a config reference.** It covers the keys the installer's flags set; other fields keep their defaults.
- **It isn't a security review.** [Security](/security.html) covers the disclosure flow. Keep `pool.toml`, `bitcoin.conf`, `pool-config.toml` and `node.key` off public repos and backups you don't control.

## Source

| File | Purpose |
|---|---|
| `scripts/install-node.sh` | The installer, including the boot gate, firewall reconcile, restart watchdog and auto-updater it lays down |
| `scripts/ghost-auto-update.sh` | Canonical copy of the auto-updater |
| `scripts/backup-databases.sh` | The nightly database backup |
| `scripts/ghost-backup-offsite.sh` | Canonical copy of the optional off-node backup helper |
| `crates/ghost-common/src/constants.rs` | Capability share weights, `MAX_ELDERS` |
| `crates/ghost-common/src/config.rs` | `pool.toml` structures |

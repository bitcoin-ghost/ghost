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
                   │  mesh 8555-8563 │   BFT mesh, payouts, capability
                   │  HTTP 8080      │   challenges, Template
                   │  TDP 8442       │   Distribution (TDP)
                   └────────┬────────┘
                            │ TDP
                   ┌────────▼────────┐
                   │    sri-pool     │   pool_sv2 — Stratum V2
                   │   (SV2 34255)   │
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

Every binary comes from the signed release tarball. For each release that tarball holds `ghostd`, `ghost-cli` (the ghostd RPC client, like `bitcoin-cli`), `ghost-mining`, `ghost-admin`, `pool_sv2`, `translator_sv2`, `jd_client_sv2`, and `ghost-pool` (a hard link to `ghost-mining`, kept so older installers still find it). The installer installs `ghostd`, `ghost-cli`, `ghost-mining`, `ghost-admin`, `pool_sv2` and `translator_sv2` into `/opt/ghost/bin`; it does not install `jd_client_sv2` or the `ghost-pool` link.

## Before you start

**Machine.** The installer refuses anything that isn't `x86_64`, and must run as root. It uses `apt-get` and `ufw`, and is written for Ubuntu. Release tarballs also exist for macOS (x86_64 and aarch64), but the installer only uses the Linux one.

| Component | Minimum | Recommended |
|---|---|---|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16+ GB |
| Storage | 500 GB SSD | 1 TB NVMe |
| Network | 100 Mbps symmetric | 1 Gbps |

The installer does not check any of these — they are guidance, not gates. Disk depends on the sync mode you choose: the default (`ibd`) prunes old blocks, `haze` sits around 195 GB, and a full archive (`--archive`) is ~720 GB and growing.

**Two bech32 mainnet addresses** (`bc1…`) that you control:

- a **payout address**, where this node's reward share is paid; and
- a **treasury address**, where this node's pool fee accumulates. There is deliberately no default — the installer refuses to run without one.

They can be the same address or different ones. A third, a fresh taproot address (`bc1p…`), is needed only if you run a Wraith coordinator (below).

**An alert endpoint** (for example `https://ntfy.sh`). It is optional in the sense that the install completes without it, but then alerts are disabled and every detector — low disk, node offline, behind tip, restart loop — fires into nothing.

⚠ **SSH on a non-standard port.** The installer enables `ufw` with `--force` and only allows SSH on `22/tcp`. If your SSH daemon listens anywhere else, add that rule (`sudo ufw allow <port>/tcp`) *before* you run the installer, or you will lock yourself out.

## Install

```bash
curl -sSL https://get.bitcoinghost.org | sudo bash -s -- \
  --payout-address bc1q... \
  --treasury-address bc1q... \
  --alert-webhook https://ntfy.sh
```

That gives you the defaults: full trustless sync with pruning, Public Pool mining, the mempool Reaper on, no archive, no Wraith coordinator, no Tor, no automatic updates.

The installer always installs the latest published GitHub release. To pin one, set `GHOST_VERSION` — after `sudo`, so it survives into the root shell:

```bash
curl -sSL https://get.bitcoinghost.org | sudo GHOST_VERSION=v1.11.46 bash -s -- --payout-address ...
```

If the GitHub API can't be reached and no version is pinned, the installer stops rather than guessing.

**Reading it first.** The installer is one self-contained shell script. To read it before it runs as root, download it and run the file:

```bash
curl -sSLo install-node.sh https://get.bitcoinghost.org
less install-node.sh
sudo bash install-node.sh --payout-address bc1q... --treasury-address bc1q... --alert-webhook https://ntfy.sh
```

Run from a file like this, with **no** flags at all, on a terminal, the installer starts a guided setup wizard instead. It asks for the same choices as the flags below (payout and treasury addresses, sync mode, mining mode, pool name, Reaper, archive, Wraith, Tor, auto-update, nightly backups, nickname), shows a summary and asks before it changes anything. The wizard does not ask for an alert endpoint, so a wizard install has alerts disabled until you add one. Piped through `curl`, the wizard never runs; `--non-interactive` also turns it off.

### Flags

| Flag | Default | What it does |
|---|---|---|
| `--payout-address <bech32>` | — (required) | Where this node's reward share is paid. |
| `--treasury-address <bech32>` | — (required) | Where this node's pool fee accumulates. |
| `--alert-webhook <url>` | none | Push endpoint for node alerts. Without it, `[alerts]` is written with `enabled = false`. |
| `--alert-topic <name>` | `ghost-node` | Push topic. |
| `--nickname <name>` | `ghost-node` | Display name in the mesh. |
| `--pool-name <name>` | mode default | Custom coinbase tag, shown on explorers as `- G H O S T - <name>`. Printable ASCII, at most 30 characters. |
| `--sync <ibd\|haze>` | `ibd` | How ghostd stores the chain. See *Sync mode*, below. |
| `--mining-mode <public\|pool\|solo>` | `public` | Who can mine on this node. See *Mining mode*, below. |
| `--no-public-mining` | | Older alias for `--mining-mode solo`. If both are given, the last one wins. |
| `--no-reaper` | Reaper on | Don't run the mempool Reaper. |
| `--archive` | off | Full archive node (~720 GB). |
| `--wraith` | off | Run a Wraith mixing coordinator. Requires `--coordinator-fee-address`. |
| `--coordinator-fee-address <bc1p…>` | — | Where the coordinator's per-round fee lands. Must be taproot and must not be the payout address. |
| `--no-wraith` | | Never run a coordinator (the default). |
| `--tor` | off | Hybrid Tor: ghostd peers via Tor and publishes an onion, still reachable on clearnet 8333. |
| `--tor-only` | off | ghostd uses Tor only (`onlynet=onion`) and 8333 is closed. Implies `--tor`. |
| `--no-tor` | | Never use Tor (the default). |
| `--auto-update` | off | Apply newer signed releases automatically. See *Automatic updates*, below. |
| `--no-auto-update` | | Never auto-update (the default). |
| `--backups` | on | Back up the node database every night at 03:00 UTC, kept 7 days. See *Database backups*, below. |
| `--no-backups` | | No nightly backups. The job is still installed; switch it on later with `sudo systemctl enable --now ghost-backup.timer`. |
| `--non-interactive` | | Never start the wizard. |
| `-h`, `--help` | | Print the help. |

## Choices

### Sync mode

| `--sync` | Writes to `bitcoin.conf` | Meaning |
|---|---|---|
| `ibd` (default) | `prune=550` | Full trustless sync — every block validated — then old block files pruned. Takes hours, up to about a day. |
| `haze` | `hazemode=Hazed` | Strips block data, ~195 GB, faster. **Irreversible**: the node can never serve raw blocks or become an archive node without a full resync. See [Haze](#haze). |

`--archive` overrides both and writes `hazemode=FullArchive` (and `archive_mode = true` in `pool.toml`).

`--sync haze` stops and asks you to type `yes` at the terminal. With `--non-interactive` there is no prompt: passing it is taken as confirmation that you have read the warning above. Without a terminal and without `--non-interactive`, the installer refuses.

### Mining mode

| `--mining-mode` | Written as | Who can mine | Rewards | Stratum ports |
|---|---|---|---|---|
| `public` (default) | `public_pool` | Anyone. The node is DNS-registered. | Pool-aggregated (shared). | 3333, 34255 and 4444 open |
| `pool` | `private_pool` | Your miners plus invited external miners, with a password. Not in DNS. | Pool-aggregated (shared). | 3333 and 34255 open |
| `solo` | `private_solo` | Only miners you run locally, with a password. Not in DNS. | 99% of the subsidy plus all fees to your payout address. | all closed |

For the two private modes the installer generates a miner password, writes it to `/etc/ghost/pool.toml` as `[network] private_mining_password`, and prints it at the end of the install. Anyone with it can mine on the node.

Port 4444 is a second SV1 listener (the "farm tier") with a higher starting difficulty, for large and rented miners; 3333 is sized for hobby hardware such as a BitAxe. It exists only in Public Pool mode.

SV1 miners connect to `stratum+tcp://<your-ip>:3333` and may authorise as `<address>.<worker>` to attribute their own shares.

### Capabilities and reward shares

Nodes split the network's node rewards by capability shares, 5-4-3-2-1:

| Shares | Capability | How a node gets there |
|---|---|---|
| +5 | Archive | `--archive`, so the node holds the full chain. |
| +4 | Wraith coordinator | Once activated, earned by running a Wraith coordinator that peers can reach: `--wraith --coordinator-fee-address bc1p…`. See [Wraith](#wraith). |
| +3 | Public Mining | `--mining-mode public` (the default). The private modes do not earn it. |
| +2 | Reaper | On by default; `--no-reaper` gives it up. See [Reaper](#reaper). |
| +1 | Elder | The first 101 nodes. See [Elder system](#elder-system). |

A flag does not award a share. Shares are earned by passing challenges that peers send to the node; a flag only puts the node in a position to pass them. A public-mining node whose Stratum port peers can't reach, or a coordinator whose port 9100 they can't dial, doesn't qualify.

A Wraith coordinator also needs its own fee address. The installer refuses `--wraith` without `--coordinator-fee-address`, refuses one that isn't taproot (`bc1p…`), and refuses the payout address: that address is public, so a round paying it would be identifiable and attributable to this node.

### Tor

`--tor` installs Tor, adds `ControlPort 9051` with cookie authentication to `/etc/tor/torrc`, adds the `ghost` user to `debian-tor`, and gives ghostd `listenonion=1`, `torcontrol=127.0.0.1:9051` and `proxy=127.0.0.1:9050`. `--tor-only` adds `onlynet=onion` and removes the `8333/tcp` firewall rule.

Tor applies to ghostd's Bitcoin P2P only. ghost-mining's mesh, its HTTP API and the Stratum ports stay on clearnet, and `pool.toml` still records the machine's public IP.

## What the installer does

In order:

1. **Packages.** `apt-get install` of the libevent and ZeroMQ runtime libraries, `ufw`, `openssl`, `curl`, `gnupg`, `tar` (and `tor` with `--tor`).
2. **User and directories.** Creates the system user `ghost` with home `/home/ghost`, and `/opt/ghost/bin`, `/etc/ghost`, `/etc/bitcoin`, `/var/lib/bitcoin`, `/var/lib/ghost`, `/home/ghost/.ghost/data`. If you ran it via `sudo`, your own user is added to `systemd-journal` so `journalctl` works without sudo after your next login.
3. **Persistent journal.** Writes `/etc/systemd/journald.conf.d/10-ghost.conf`: `Storage=persistent`, 2 GB cap, 1 GB kept free, two weeks' retention. Without it the journal lives in RAM and a reboot erases the evidence you need.
4. **Download and verify.** Fetches `bitcoin-ghost-<version>-x86_64-unknown-linux-gnu.tar.gz`, `SHA256SUMS.txt` and `SHA256SUMS.txt.asc` from the GitHub release, imports the release key from `https://get.bitcoinghost.org/ghost-release-key.asc`, and requires a valid signature from exactly `777FE81F8CC077FD3D08055E852C2B3190F5B928` before checking the tarball's SHA256. Any failure stops the install before a binary is written.
5. **Secrets.** Generates a fresh RPC password, `internal_api_secret`, `signing_key`, and — for private modes — the miner password, all on this machine. Nothing is shared with any other node.
6. **Configs.** Writes `/etc/bitcoin/bitcoin.conf` and `/etc/ghost/pool.toml` (both `ghost`-owned, mode 600), `/etc/ghost/translator-config.toml` (644) and `/etc/ghost/pool-config.toml` (root-only 600; it holds the SV2 authority secret).
7. **Node identity.** Generates `/home/ghost/.ghost/node.key` with `ghost-mining --generate-identity` — unless one already exists, in which case it is kept.
8. **SV2 keys.** Generates a fresh SV2 pool authority keypair for this node, and derives ghost-mining's template-server key from `node.key` so pool_sv2 can pin it.
9. **Units.** Installs the units below, the firewall, the restart-loop watchdog and the auto-updater.
10. **Start.** Enables and starts `ghostd` and `ghost-mining-gate`. Nothing else.

ghost-mining runs genesis-anchored to the MPC ceremony: the drop-in `/etc/systemd/system/ghost-mining.service.d/genesis-anchor.conf` sets `ZK_GENESIS_PARAMS_HASH`, the immutable hash of the ceremony's genesis parameters, and `ZK_PARAMS_PATH` is `/home/ghost/.ghost/mpc_params`. There is no per-release parameter hash for you to set.

### Files

| Path | What |
|---|---|
| `/opt/ghost/bin/` | All binaries and helper scripts |
| `/etc/bitcoin/bitcoin.conf` | ghostd config |
| `/var/lib/bitcoin` | ghostd data directory |
| `/etc/ghost/pool.toml` | ghost-mining config |
| `/home/ghost/.ghost/node.key` | Node identity |
| `/home/ghost/.ghost/data` | ghost-mining database |
| `/etc/ghost/pool-config.toml` | pool_sv2 (sri-pool) config |
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
| 8333/tcp | ghostd P2P | Removed with `--tor-only` |
| 8080/tcp | ghost-mining HTTP API | |
| 8442/tcp | ghost-mining TDP | |
| 8443/tcp | Verification HTTPS | Peers fetch MPC params and votes |
| 8555–8562/tcp | Mesh consensus | Share propagation, blocks, voting, health, discovery, Elder management, payouts |
| 8563/tcp | Noise mesh | Verifications and MPC exchange |

Four more ports follow `pool.toml`. `ghost-mining-firewall.path` watches the file and re-runs `/opt/ghost/bin/reconcile-mining-firewall.sh` whenever it changes, so changing the mining mode later updates the firewall without a manual `ufw` step:

| Port | Open when |
|---|---|
| 3333/tcp (SV1), 34255/tcp (SV2) | `mining_mode` is `public_pool` or `private_pool` |
| 4444/tcp (farm tier) | `mining_mode` is `public_pool` |
| 9100/tcp (Wraith coordinator) | `[coordinator] coordinator_role_enabled = true` |

RPC (8332), ZMQ (28332–28334) and pool_sv2's monitoring endpoint (9090) are bound to `127.0.0.1`.

## After the install

The installer ends by printing the Node ID and each service's state:

```
  ✅ Bitcoin Ghost node installed.
     ghostd:          active
     ghost-mining-gate: active  (waiting for sync, then auto-starts ghost-mining)
     ghost-mining:    inactive  (started by the gate)
     sri-pool:        inactive  ...
     sri-translator:  inactive  ...
```

`inactive` is expected for the last three until ghostd finishes syncing. For the private modes it also prints the miner password.

Follow the sync, then the gate:

```bash
sudo journalctl -u ghostd -f
sudo journalctl -u ghost-mining-gate -f
```

When the gate logs `ghostd synced — starting ghost-mining`, the node joins the mesh and registers as an Elder if slots remain. Then:

```bash
sudo journalctl -u ghost-mining -f
sudo journalctl -u sri-pool -u sri-translator -f
curl -s 'http://127.0.0.1:8080/health?unsigned=true'      # peer_count should be above 0
sudo -u ghost /opt/ghost/bin/ghost-cli -conf=/etc/bitcoin/bitcoin.conf getblockchaininfo
```

`ghost-cli` lives in `/opt/ghost/bin`, not on the default `PATH`, and needs `sudo -u ghost` because `bitcoin.conf` (which holds the RPC password) is readable only by `ghost`.

**Back up `node.key`.** `/home/ghost/.ghost/node.key` is the node's identity. The node ID derives from it and the Elder slot is bound to it. Lose it and you lose the peer slot, the verification history and any Elder position; nothing on the machine backs it up for you. See [Key management](#key-management).

### pool.toml

The installer writes `/etc/ghost/pool.toml` in full. The flags land here:

| Flag | Key |
|---|---|
| `--payout-address` | `[pool] node_payout_address` (and `[network] solo_payout_address` for `solo`) |
| `--treasury-address` | `[pool] treasury_address` |
| `--nickname` | `[identity] display_name` |
| `--pool-name` | `[pool] pool_name` |
| `--mining-mode` | `[network] mining_mode` |
| `--archive` | `[storage] archive_mode` |
| `--no-reaper` | `[reaper] enabled` |
| `--wraith` | `[coordinator] coordinator_enabled`, `coordinator_role_enabled`, and `[ghost_pay] wraith_enabled` |
| `--coordinator-fee-address` | `[coordinator] coordinator_fee_address` |
| `--alert-webhook`, `--alert-topic` | `[alerts]`, `[alerts.channels.push] webhook_url`, `topic` |

The `[ghost_pay]` section name is historical: Ghost Pay is retired and `enabled` is always `false`; the section survives only because `wraith_enabled` is still read from it. The `[coordinator]` block is written on every node, switched off unless you passed `--wraith`, so the option is visible.

The installer does not install the node dashboard. It writes `/etc/systemd/system/ghost-dashboard.service.d/internal-auth.conf` so that a dashboard installed later signs its requests with the same `internal_api_secret`. See [Node dashboard](#node-dashboard).

### Re-running the installer

Re-running keeps the things that identify the node: an existing `node.key` is kept, and `internal_api_secret`, `signing_key` and the SV2 authority keypair are read back from the existing `pool.toml` and `pool-config.toml` and reused, so SV2 miners that pinned the authority key keep working. Everything else is regenerated: `bitcoin.conf`, `pool.toml`, `pool-config.toml` and `translator-config.toml` are rewritten from the flags you pass this time, with a new RPC password. Hand edits to those files do not survive a re-run, and a re-run without the flags you used the first time sets those options back to their defaults.

## Automatic updates

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
- **It isn't multi-node coordination.** A second node runs the same installer on a different host; it bootstraps from the seed Elders built into the installer and discovers the rest through gossip. There's no centralised registry or membership flow.
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

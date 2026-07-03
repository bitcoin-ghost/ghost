# Wraith Wallet

Desktop wallet for Bitcoin Ghost. Bundles light-wallet, Wraith CoinJoin participation,
Ghost Locks custody, and TAP (L2) payments behind a single GUI / CLI / daemon.

## Workspace layout

| Crate | Role |
|---|---|
| `core/`         | `wraith-wallet-core` — all wallet logic (lib) |
| `ipc/`          | `wraith-wallet-ipc` — JSON-RPC types shared between daemon and clients |
| `daemon/`       | `wraith-wallet-daemon` — `wraithd` binary |
| `cli/`          | `wraith-wallet-cli` — `wraith` binary |
| `gui/src-tauri/`| `wraith-wallet-gui` — `wraith-gui` binary (Tauri 2 desktop shell) |

## Architecture

`wraithd` is the long-running process. It runs all module tasks (light, wraith, tap,
locks, keys, shroud) concurrently as Tokio tasks. The CLI and GUI are thin clients
that round-trip JSON-RPC envelopes over a local Unix socket — there is exactly one
IPC codepath and the GUI never links the core directly.

```
+----------+     +----------+     +-----------+
|  wraith  | --> |          | --> | ghost-pay |
|  (CLI)   |     |          |     +-----------+
+----------+     | wraithd  |
+----------+ --> |          | --> | ghost-gsp |
| wraith-  |     |          |     +-----------+
|  gui     |     +----------+
+----------+        ^
                    |
                    +--- Tor (optional, via embedded SOCKS5 proxy)
```

The wallet only ever talks to `ghost-pay` and `ghost-gsp` — it never reaches past
them to a Bitcoin node directly.

## Quick start

Assuming `cargo` is on your PATH and you've cloned the monorepo:

```sh
# 1. Build everything (first build pulls + compiles a lot of deps).
cargo build -p wraith-wallet-daemon -p wraith-wallet-cli -p wraith-wallet-gui

# 2. Bring up the dev stack (needs a local signet ghostd on :38335).
bash scripts/run-wraith-stack.sh up

# 3. Open the GUI — it kicks off onboarding automatically when there
#    are no wallets. Or use the CLI:
./target/debug/wraith-gui                              # GUI path
./target/debug/wraith wallet create alice              # CLI path
./target/debug/wraith gsp auth                         # → GSP session
./target/debug/wraith light receive --index 0          # show first address
./target/debug/wraith light watch                      # live silent-payment stream
```

Same `wraithd` daemon serves both clients. The GUI window can close
without terminating `wraithd` (system-tray → Quit GUI to do that).

To restore an existing wallet:

```sh
./target/debug/wraith wallet import alice
# (paste 12 or 24 BIP-39 words; choose a fresh passphrase)
```

In the GUI, click `+ restore` next to the wallet picker.

## Build

```sh
cargo build -p wraith-wallet-daemon   # produces `wraithd`
cargo build -p wraith-wallet-cli      # produces `wraith`
cargo build -p wraith-wallet-gui      # produces `wraith-gui`
```

## Local dev stack

`scripts/run-wraith-stack.sh` brings up `ghost-pay`, `ghost-gsp`, and `wraithd` on
loopback for end-to-end testing. Requires a local signet `ghostd` — the Ghost Core
binary, a Bitcoin Core v30 fork (default `http://127.0.0.1:38335`, override with
`GHOSTD_RPC_URL` / `GHOSTD_RPC_USER` / `GHOSTD_RPC_PASSWORD`). `bitcoind` works
interchangeably since the RPC interfaces are identical.

```sh
bash scripts/run-wraith-stack.sh up      # start the stack
bash scripts/run-wraith-stack.sh status  # see what's running
bash scripts/run-wraith-stack.sh down    # tear it down
./target/debug/wraith doctor             # verify the wallet sees both services
```

Logs land in `/tmp/wraith-stack/<service>.log`.

## Shell completions

`wraith` ships generated completions for bash, zsh, fish, elvish, and powershell:

```sh
wraith completions bash > /etc/bash_completion.d/wraith
wraith completions zsh  > ~/.zfunc/_wraith         # ensure ~/.zfunc is in $fpath
wraith completions fish > ~/.config/fish/completions/wraith.fish
```

The script is generated at runtime — re-run after upgrading `wraith` to pick up new
subcommands.

## Daemon environment

`wraithd` is configured by environment variables:

| Var | Purpose | Default |
|---|---|---|
| `WRAITHD_SOCKET`     | IPC socket path                            | `$XDG_RUNTIME_DIR/wraithd-${UID}.sock` |
| `WRAITHD_WALLETS_DIR`| Encrypted keystore directory               | `$HOME/.local/share/wraithd/wallets` |
| `WRAITHD_GHOST_PAY`  | Ghost-pay URL(s), comma-separated          | `http://127.0.0.1:8800` |
| `WRAITHD_GSP`        | GSP WebSocket URL(s), comma-separated      | `ws://127.0.0.1:8900/ws/v1` |
| `WRAITHD_NETWORK`    | `signet` / `mainnet` / `regtest`           | `signet` |
| `WRAITHD_TOR_PROXY`  | SOCKS5(h) URL for Tor                      | (unset = direct) |
| `WRAITHD_IDLE_LOCK_SECS` | Auto-lock wallets after this many seconds of no IPC activity (0 = disabled) | `900` |
| `WRAITHD_SHROUD_MAX_MS` | Shroud relay window: hold each signed payment a uniform random delay in `[0, this]` ms before submitting to ghost-pay (0 = immediate) | `5000` |
| `WRAITHD_UPDATE_MANIFEST_URL` | URL of the release manifest the daemon's `CheckForUpdate` handler fetches by default. Unset = no auto-update channel; per-call URLs still work. | (unset) |

## Release

`scripts/release-wraith.sh` builds release binaries, generates shell completions,
and packs everything into a versioned tarball + machine-readable manifest:

```sh
bash scripts/release-wraith.sh
# produces:
#   dist/wraith-wallet-<version>-<triple>.tar.gz
#   dist/wraith-wallet-<version>-<triple>.tar.gz.sha256
#   dist/wraith-wallet-<version>-<triple>.manifest.json
```

The tarball layout:

```
wraith-wallet-<version>/
  bin/{wraithd, wraith, wraith-gui}
  completions/{wraith.bash, _wraith, wraith.fish}
  README.md
  LICENSE
  BUILDINFO.txt    # version + triple + commit + rustc + build timestamp
```

Manifest schema (consumed by `wraith update check` and downstream
verification tooling):

```json
{
  "version":        "1.8.0",
  "triple":         "x86_64-unknown-linux-gnu",
  "built":          "2026-05-06T17:42:11Z",
  "commit":         "abcd…",
  "rustc":          "rustc 1.93.0 …",
  "tarball":        "wraith-wallet-1.8.0-x86_64-unknown-linux-gnu.tar.gz",
  "tarball_sha256": "…",
  "binaries": {
    "wraithd":    {"sha256": "…", "size": 12345678},
    "wraith":     {"sha256": "…", "size":  4567890},
    "wraith-gui": {"sha256": "…", "size": 23456789}
  }
}
```

### Signing

Set `WRAITH_RELEASE_SIGNING_KEY` to a GPG key id and the script will produce
a detached `manifest.json.asc` next to the manifest:

```sh
WRAITH_RELEASE_SIGNING_KEY=0xDEADBEEF bash scripts/release-wraith.sh
```

When the env var is unset the script still ships an unsigned manifest —
useful for dev / CI dry-runs. **An update client should refuse to act on
an unsigned manifest in production.**

### CI

`.github/workflows/release-wraith.yml` runs on `wraith-v*` tag pushes (or via
`workflow_dispatch`) and produces three installer artifacts, then uploads them
to a draft GitHub release:

| Job | Runner | Output |
|---|---|---|
| `build`     | `ubuntu-latest`  | Linux tarball + GPG-signable manifest (`release-wraith.sh`) |
| `build-msi` | `windows-latest` | Windows `.msi` (Tauri WiX bundler, `wraithd` bundled as sidecar) |
| `build-dmg` | `macos-latest`   | macOS `.dmg`, **Apple Silicon (aarch64) only** for v1, **ad-hoc signed** |

The macOS job targets `aarch64-apple-darwin` only — that is the native target
of the Apple-Silicon `macos-latest` runners, so there is no cross-compile of
the C deps (`aws-lc-sys`, `secp256k1-sys`). A universal binary would double
build time and add cross-compile surface for exactly those deps; revisit if
Intel-Mac demand appears.

The **manifest** and the combined **`SHA256SUMS`** are deliberately NOT
GPG-signed in CI — automated GPG signing would defeat the threat model they
guard against. The expected signing workflow (offline release key) is:

1. Push a `wraith-v…` tag → CI builds all installers and uploads them, the
   per-triple `manifest.json`, and a combined `SHA256SUMS` to a draft release.
2. Pull `manifest.json` + `SHA256SUMS` down to a build host with the offline key.
3. Sign both:
   `gpg --detach-sign --armor --local-user <key> -o manifest.json.asc manifest.json`
   `gpg --detach-sign --armor --local-user <key> -o SHA256SUMS.asc SHA256SUMS`
4. Attach the two `.asc` files to the draft release and publish.

## Installing a release (the free path)

Wraith Wallet ships **free installers with no paid code-signing certificates**
— no Apple Developer Program, no Authenticode CA, no accounts, nothing to sign
up for. The trust anchor is **not** a vendor certificate; it's the **GPG-signed
checksum manifest** you verify yourself before you run anything. Verify first,
then do the one-time OS bypass for your platform.

### 1. Verify first (this is the real trust anchor)

Every release is a GitHub Release carrying, for each platform, the installer
(`.tar.gz` / `.msi` / `.dmg`) plus two verification files:

- **`SHA256SUMS`** — one line per installer asset (`<sha256>  <asset-name>`),
  covering the Linux tarball, the Windows `.msi`, and the macOS `.dmg`.
- **`SHA256SUMS.asc`** — a detached **GPG signature** over `SHA256SUMS`, made
  with the offline release key. (The per-triple `*.manifest.json` +
  `*.manifest.json.asc` are also published — they additionally pin the SHA-256
  of each individual Linux binary inside the tarball.)

```sh
# 1. Import the Ghost release key once (fingerprint is published on
#    bitcoinghost.org and pinned in the repo; confirm it out-of-band).
gpg --recv-keys <RELEASE_KEY_FINGERPRINT>

# 2. Verify the SHA256SUMS signature. This proves the whole checksum list —
#    and therefore every installer hash in it — came from the release key.
gpg --verify SHA256SUMS.asc SHA256SUMS
#   → "Good signature from Bitcoin Ghost Releases <…>"

# 3. Check the file you downloaded against the signed list.
#    Linux/macOS (run in the folder holding SHA256SUMS + your download):
sha256sum -c --ignore-missing SHA256SUMS       # Linux
shasum -a 256 -c --ignore-missing SHA256SUMS   # macOS
#    Windows (PowerShell) — hash the .msi and eyeball it against SHA256SUMS:
CertUtil -hashfile "Wraith.Wallet_<ver>_x64_en-US.msi" SHA256
```

If the GPG signature is **not** "Good", or a hash doesn't match, **stop** — do
not install. A valid signature + matching hash is worth far more than any
"verified publisher" badge a paid cert would buy.

### 2. Install + one-time OS bypass

The installers are unsigned by a commercial CA (on purpose — see below), so each
OS shows a first-run speed-bump. That warning is expected; your real assurance
is the GPG/checksum check you already did.

**Windows (`.msi`)** — double-click the `.msi`. SmartScreen may show
**"Windows protected your PC"** because the publisher is unknown (no paid
Authenticode cert). Click **More info → Run anyway** — once. This is normal for
unsigned software; it does **not** mean the file is tampered with — you already
proved integrity with the checksum/GPG step above.

**macOS (`.dmg`)** — open the `.dmg`, drag **Wraith Wallet** to Applications.
The app is **ad-hoc signed** (so it launches) but **not notarized** (that needs
an Apple account), so first launch is gated by Gatekeeper. Bypass it once:

- **Right-click (or Control-click) the app → Open**, then confirm **Open** in
  the dialog. macOS remembers the choice; normal double-click works afterward.
- Or clear the quarantine flag from a terminal:
  ```sh
  xattr -cr "/Applications/Wraith Wallet.app"
  ```

Ad-hoc signing is what prevents the Apple-Silicon **"app is damaged and can't be
opened"** hard-fail on a fully unsigned bundle — the app carries a valid
(self-issued) signature; it just isn't from a paid Developer ID.

**Linux (`.tar.gz` / AppImage)** — after the GPG + `sha256sum -c` check, unpack
and run:

```sh
tar xzf wraith-wallet-<ver>-x86_64-unknown-linux-gnu.tar.gz
cd wraith-wallet-<ver>
./bin/wraith-gui        # GUI
./bin/wraith --help     # CLI
```

No OS gate on Linux — the checksum/GPG verification is the whole trust story.

### Smoother installs (optional, still no accounts)

The repo ships a self-hosted **Scoop bucket** (Windows) and **Homebrew tap**
(macOS) so you can `scoop install` / `brew install --cask` and get updates.
**Nothing is submitted to any registry** — you opt in by adding the bucket/tap,
which are just files in this repo ([`packaging/scoop/`](packaging/scoop/) and
[`packaging/homebrew/`](packaging/homebrew/)). Both still verify the download's
SHA-256 against the (per-release) hash pinned in the manifest, and both point
at the same GitHub release assets.

**Windows (Scoop):**

```powershell
scoop bucket add ghost https://github.com/bitcoin-ghost/ghost
scoop install wraith-wallet
```

Scoop verifies the manifest's `hash` on download and aborts on any mismatch.
Updates: `scoop update wraith-wallet`.

**macOS (Homebrew):**

```sh
brew tap bitcoin-ghost/ghost https://github.com/bitcoin-ghost/ghost
brew install --cask wraith-wallet
```

The cask strips the download quarantine flag for you, so the ad-hoc-signed app
opens without the manual right-click → Open step. Updates:
`brew upgrade --cask wraith-wallet`.

### Optional: adding real code-signing certificates later

Everything above is the primary, permanent shipping path. **You never have to
buy or apply for anything.** If a maintainer *chooses* to add paid certificates
later, the release workflow already contains a **dormant** signing pipeline that
"just turns on" the moment the matching secrets exist — no workflow edit needed.
Signing only removes the first-run warnings above; it changes nothing about the
GPG-manifest trust model.

The secret names the dormant pipeline looks for (under **Settings → Secrets and
variables → Actions**):

| Platform | GitHub secret(s) | Effect when present |
|---|---|---|
| **Windows** | `WINDOWS_CERTIFICATE` (base64 `.pfx`), `WINDOWS_CERTIFICATE_PASSWORD` | `build-msi` signs `wraithd.exe` + the `.msi` (Authenticode) — no SmartScreen prompt |
| **macOS** | `APPLE_CERTIFICATE`, `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`, `APPLE_PASSWORD`, `APPLE_TEAM_ID` | `build-dmg` swaps ad-hoc signing for a real Developer ID signature **and** notarizes via `notarytool` — no Gatekeeper prompt |

Gating logic (unchanged): Windows signing runs only
`if: env.WINDOWS_CERTIFICATE != ''`; the macOS `HAS_APPLE_SIGNING` flag selects
the real-signed/notarized build when `APPLE_CERTIFICATE` + `APPLE_SIGNING_IDENTITY`
are set, otherwise the **ad-hoc** build (`APPLE_SIGNING_IDENTITY="-"`) runs. The
certless path is the default and is fully supported.

### Update check

`wraith update check [--manifest-url <url>]` fetches the manifest, compares
versions, and reports `up to date` or `update available`. Configure the
default fetch URL with `WRAITHD_UPDATE_MANIFEST_URL`.

## Phase status

| # | Phase | Status |
|---|---|---|
| 0  | Foundation (workspace skeleton)                  | done |
| 1  | Chain client (ghost-pay RPC + GSP WS)            | done |
| 2  | Light wallet                                     | done |
| 3  | CLI maturation (`--json`, doctor, multi-cmd, completions) | done |
| 4  | Multi-wallet (with GUI picker that switches active) | done |
| 5a | Wraith protocol v3 amendment                     | upstream `wraith-protocol/` crate |
| 5b | Wraith wallet module                             | not started |
| 6  | Locks (prepare / confirm / jump)                 | done — CLI + GUI |
| 7  | TAP / L2 payments                                | done — with confirm dialog |
| 8  | Silent payments (BIP-352, candidate-tx push)     | done — with live `wraith light watch` |
| 9  | Shroud relay                                     | done — wallet-side outbound-broadcast delay |
| 10 | Tor transport (SOCKS5 → arti later)              | done (SOCKS5) |
| 11 | Multi-node failover                              | done — comma-separated URLs |
| 12 | Recovery (seed + checkpoint)                     | done — `wallet import` + `wallet restore` |
| 13 | Hardware-wallet trait                            | trait done; vendor backends deferred (drop-in via cargo features when a user asks) |
| 14 | Tauri GUI                                        | done — onboarding, send/recv/locks/identity/settings tabs, system tray, live push toasts |
| 15 | Distribution (signed installers, auto-update)    | done — tarball + manifest + GPG hook + CheckForUpdate IPC + release CI workflow |
| 16 | Hardening (IPC fuzz, external review)            | proptest IPC fuzz + integration tests; external review pending |

Tests as of latest: 64 across the wraith-wallet workspace
(7 IPC + 40 core + 17 daemon), all green. Run them with
`cargo test -p wraith-wallet-{ipc,core,daemon} --tests`.

## Security model

- Encrypted keystore: Argon2id KDF → AES-256-GCM. Per-wallet passphrases.
- IPC socket: bound at owner-only (0600) permissions; channel restricted to
  processes running as the same user as `wraithd`.
- Auto-lock: wallets are dropped from the unlocked set after
  `WRAITHD_IDLE_LOCK_SECS` of no activity (default 15 minutes). Diagnostics
  (Health / Doctor / DaemonEnv) and the WatchPayments stream don't reset
  the timer; everything else does.
- Network boundary: the wallet only ever talks to `ghost-pay` (REST) and
  `ghost-gsp` (REST + WebSocket). It never reaches past them to a Bitcoin
  node directly. Tor routing optional via `WRAITHD_TOR_PROXY`.
- Shroud relay (Phase 9): every signed payment is held for a uniform
  random delay in `[0, WRAITHD_SHROUD_MAX_MS]` (default 5 s) before being
  submitted to ghost-pay. Breaks the timing seam between the wallet's
  HTTP POST and the eventual P2P broadcast that an observer with both
  vantage points could otherwise correlate. Stacks with ghost-core's
  own Shroud and ghost-pool's mesh-forwarding shroud — three independent
  random delays compose. Bypass per-call with `wraith light send …
  --immediate` or override with `--shroud-max-ms <ms>`.
- Mainnet readiness: when `WRAITHD_NETWORK=mainnet`, the daemon refuses
  `WalletImport` with a publicly-known mnemonic (canonical BIP-39 test
  vectors, common docs vectors) — these have been swept thousands of
  times and importing one on mainnet means instant theft. Doctor adds
  three mainnet-only rows: `mainnet/ghost-pay tls`, `mainnet/gsp tls`,
  and `mainnet/tor`. Plaintext non-loopback ghost-pay/GSP URLs fail;
  loopback URLs (127.0.0.1, ::1, localhost) are exempt; missing
  `WRAITHD_TOR_PROXY` is a `skip` (advisory, since Tor is opt-in by
  design). The GUI shows a red `MAINNET` chip in the header so the
  user always knows which network they're on.

## Hard rules

- Wallet talks to ghost-pay/ghost-gsp only. No direct ghost-core or Bitcoin-node
  connection. Every leak of that boundary is a bug.
- All modules run concurrently inside `wraithd`. The UI picks the foreground view,
  never which module is alive.
- The daemon is the unit of life, not the GUI. Closing the window does not kill
  `wraithd`.
- One IPC codepath: GUI and CLI both go through `wraithd`'s JSON-RPC. No direct
  linkage from the GUI into core.

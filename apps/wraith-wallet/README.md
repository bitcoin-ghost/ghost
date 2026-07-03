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
| `build-dmg` | `macos-latest`   | macOS `.dmg`, **Apple Silicon (aarch64) only** for v1 |

The macOS job targets `aarch64-apple-darwin` only — that is the native target
of the Apple-Silicon `macos-latest` runners, so there is no cross-compile of
the C deps (`aws-lc-sys`, `secp256k1-sys`). A universal binary would double
build time and add cross-compile surface for exactly those deps; revisit if
Intel-Mac demand appears.

The **manifest** is still deliberately NOT GPG-signed in CI — automated GPG
signing would defeat the threat model the manifests guard against. The expected
manifest workflow is:

1. Push a `wraith-v…` tag → CI builds + uploads tarball + manifest to a draft.
2. Pull the manifest down to a build host with the offline release key.
3. `gpg --detach-sign --armor --local-user <key> -o manifest.json.asc manifest.json`
4. Attach the `.asc` to the draft release and publish.

### Installer code-signing (Windows Authenticode + macOS Developer ID)

The `.msi` and `.dmg` jobs are wired to code-sign **automatically once the
signing secrets exist**, and to build **unsigned but functional** installers
when they don't. Nothing is hardcoded — signing is gated purely on secret
presence, so today's certless builds keep working and signing "just turns on"
the moment the secrets are added to the repo.

**Until the secrets below are configured, installers are UNSIGNED.** They still
install and run, but users see a warning: Windows SmartScreen ("unknown
publisher") and macOS Gatekeeper ("cannot verify the developer" / needs
right-click → Open). Signing removes those warnings.

What the maintainer must obtain and add as GitHub Actions repo secrets:

| Platform | What you need | Cost | GitHub secret(s) |
|---|---|---|---|
| **Windows** | Authenticode code-signing certificate — an **OV or EV** cert from a CA (DigiCert, Sectigo, SSL.com, …), or **Azure Trusted Signing**. Export the cert + key as a password-protected **PFX**, then base64-encode it (`base64 -w0 cert.pfx`). EV/hardware-token certs earn SmartScreen reputation fastest. | ~$100–400/yr | `WINDOWS_CERTIFICATE` (base64 of the `.pfx`)<br>`WINDOWS_CERTIFICATE_PASSWORD` (PFX password) |
| **macOS** | **Apple Developer Program** membership → a **"Developer ID Application"** certificate. Export it + key as a password-protected `.p12`, base64-encode it. Also create an **app-specific password** for your Apple ID (appleid.apple.com) for notarization, and note your 10-char **Team ID**. | $99/yr | `APPLE_CERTIFICATE` (base64 of the `.p12`)<br>`APPLE_CERTIFICATE_PASSWORD` (p12 password)<br>`APPLE_SIGNING_IDENTITY` (e.g. `Developer ID Application: Your Name (TEAMID)`)<br>`APPLE_ID` (Apple ID email)<br>`APPLE_PASSWORD` (app-specific password)<br>`APPLE_TEAM_ID` (10-char Team ID) |

How the gating works in `release-wraith.yml`:

- **Windows** (`build-msi`): a `Configure Windows code signing` step runs only
  `if: env.WINDOWS_CERTIFICATE != ''`. It decodes the PFX, imports it into the
  runner's certificate store, and patches the thumbprint into
  `tauri.conf.json`'s `bundle.windows`, so the WiX bundler signs both
  `wraithd.exe` and the `.msi`. No secret → step skipped → unsigned `.msi`.
- **macOS** (`build-dmg`): the six `APPLE_*` secrets are passed as env vars on
  the build step. Tauri reads them natively — it signs with the Developer ID
  cert and notarizes via `xcrun notarytool` when they're set, and skips signing
  entirely when they're empty. No secret → unsigned `.dmg`.

Set the secrets under **Settings → Secrets and variables → Actions**. They take
effect on the next `wraith-v*` tag build; no workflow edit is needed.

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

> # ⚠ MAINNET TESTING — NOT READY FOR PUBLIC USE
>
> This software runs on Bitcoin **mainnet** and handles real funds. It is under active
> development and testing. Do not point hashrate, funds, or production infrastructure at it.

# Bitcoin Ghost

[![CI](https://img.shields.io/github/actions/workflow/status/bitcoin-ghost/ghost/ci.yml?label=CI)](https://github.com/bitcoin-ghost/ghost/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/github/v/release/bitcoin-ghost/ghost?label=version)](https://github.com/bitcoin-ghost/ghost/releases/latest)

Bitcoin Ghost is a Bitcoin mainnet project built around a Bitcoin Core fork
(`ghostd`) and a decentralised mining pool (`ghost-pool`). Nodes form a
peer-to-peer mesh, reach BFT consensus on payouts, and are rewarded for the
infrastructure they actually provide — full-node storage, mining, L2 payments,
and mempool filtering — through a verified-capability share system. It also
includes an L2 payments layer (`ghost-pay`) and a CoinJoin privacy protocol
(Wraith). No separate token, no altcoin — it settles in Bitcoin.

- **Website:** <https://bitcoinghost.org>
- **Documentation:** <https://bitcoinghost.org/docs/>
- **Latest release:** <https://github.com/bitcoin-ghost/ghost/releases/latest>

## Components

| Component | Path | Description |
|-----------|------|-------------|
| `ghostd` (Ghost Core) | `ghost-core/` | A fork of Bitcoin Core v30 running on Bitcoin mainnet, with Reaper mempool filtering and Ghost Haze block stripping. Separate C++/CMake build. |
| `ghost-pool` | `bins/ghost-pool/` | Decentralised mining pool node. Runs the P2P consensus mesh, tracks shares, and computes coinbase payouts. |
| `ghost-pay` | `bins/ghost-pay/` | L2 payment service with off-chain transfers proven by zero-knowledge proofs. |
| Wraith | `crates/wraith-protocol/` | Blind-signature CoinJoin mixing at L2 entry. |
| Light wallet | `bins/ghost-cli/`, `crates/ghost-light-wallet/` | CLI/TUI wallet with BIP-352 Silent Payments. |
| SV2 mining apps | `bins/translator-sv2/`, `bins/pool-sv2/` | Stratum V2 translator and pool, amalgamated in-tree. |

The workspace contains over 40 crates and binaries under `crates/` and `bins/`.
See [`docs/protocols/ARCHITECTURE.md`](https://bitcoinghost.org/docs/) on the
website for the full crate map, or browse the source directly.

## Node reward shares (5-4-3-2-1)

Nodes earn shares in the node reward pool by proving — not self-reporting — that
they run real infrastructure. Every capability is verified through
challenge-response probes issued by random peers every five minutes.

| Capability | Shares | Verification |
|------------|:------:|--------------|
| Archive node | +5 | Peers request arbitrary historical blocks. |
| Ghost Pay | +4 | Random L2 state-lookup challenges. |
| Public mining | +3 | Peers probe the Stratum port for accessibility. |
| Reaper | +2 | Mempool policy classification challenges. |
| Elder | +1 | Contributed to the MPC ceremony (first 101 nodes; permanent). |

Maximum 15 shares. Before any shares count, a node must maintain 95% uptime over
a trailing seven-day window. The MPC trusted-setup ceremony admits elders in
order from position 1 up to 101; once the 101st node has contributed, no further
elder positions are created.

## Architecture

```
                       ┌────────────────────────────────┐
                       │       P2P MESH NETWORK          │
                       │  consensus · shares · payouts   │
                       │  blocks · health · discovery    │
                       └────────────────────────────────┘
                        ▲              ▲              ▲
                  ┌─────┴─────┐  ┌─────┴─────┐  ┌─────┴─────┐
                  │  Node A   │  │  Node B   │  │  Node C   │
                  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘
                     ghostd         ghostd         ghostd
                        │              │              │
                   Your miners    Their miners    Light wallets
                  (Stratum V1)   (Stratum V1)    (CLI / TUI)
```

Every node is a peer. Miners connect to whichever node they choose. Nodes reach
consensus through BFT voting on a Noise-encrypted ZeroMQ mesh, and each node
selects its own transactions according to its configured mempool policy.

### Network ports

| Port | Purpose |
|------|---------|
| 3333 | Stratum V1 — hobby tier, ~2,328 starting difficulty |
| 4444 | Stratum V1 — farm/rental tier, ~232,827 starting difficulty (public mining nodes) |
| 34255 | Stratum V2 — via SRI pool |
| 8080 | REST API |
| 8555–8562 | P2P consensus mesh (shares, blocks, voting, health, discovery, elders, payouts) |
| 8800 | Ghost Pay L2 API |
| 8900 | GSP WebSocket (light-wallet backend) |

## Running a node

The install script provisions `ghostd` and `ghost-pool`, writes a config, and
sets up the systemd services. Supply the Bitcoin address your node rewards
should be paid to:

```sh
curl -sSL https://get.bitcoinghost.org | sudo bash -s -- --payout-address bc1q...
```

Run `sudo bash -s -- --help` to see options such as `--archive`, `--ghost-pay`,
`--mining-mode`, and `--sync`. Full setup guidance is at
<https://bitcoinghost.org/docs/>.

Point a miner at your node with `stratum+tcp://<your-ip>:3333` and a worker name
of `<btc_address>.worker1`.

### Verifying releases

Release artifacts ship with a `SHA256SUMS.txt` manifest and a detached PGP
signature `SHA256SUMS.txt.asc`, produced by the maintainer release key:

```sh
gpg --keyserver hkps://keys.openpgp.org --recv-keys 777FE81F8CC077FD3D08055E852C2B3190F5B928
gpg --verify SHA256SUMS.txt.asc SHA256SUMS.txt
sha256sum --check --ignore-missing SHA256SUMS.txt
```

See [`SECURITY.md`](SECURITY.md) for the full verification procedure and for
reporting vulnerabilities.

## Building from source

Requirements:

- Rust 1.85+ (stable toolchain)
- SQLite 3.35+
- A C++ toolchain and CMake (for `ghost-core`)
- Linux or macOS (Windows via WSL2)

```sh
git clone https://github.com/bitcoin-ghost/ghost.git
cd ghost
cargo build --release            # builds the Rust workspace (ghost-pool, ghost-pay, wallets, ...)
```

`ghost-core` has its own build; see [`ghost-core/INSTALL.md`](ghost-core/INSTALL.md).

Common development commands:

```sh
# The Tauri desktop crates need a built JS frontend before `tauri::generate_context!`
# will compile, so the pure-Rust commands exclude them — exactly as CI does.
EXCLUDES="--workspace --exclude wraith-wallet-gui --exclude ghost-tap-desktop"

cargo test $EXCLUDES --lib --bins             # test suite, as CI runs it
cargo test -p ghost-consensus                 # a single crate
cargo clippy $EXCLUDES --all-targets --all-features -- -D warnings
cargo fmt --all                               # format
cargo audit                                   # dependency advisory check
```

`ghost-mpc`'s lifecycle test needs its small-cap harness feature and is run on its own:

```sh
cargo test -p ghost-mpc --test mpc_lifecycle --features mpc-test-cap
```

Before opening a PR, `scripts/record-tests.sh` runs the full gate exactly as CI does
— formatting, clippy with CI's own argument list, docs under `-D warnings`, the fuzz
targets, and the feature-gated suites — and is the quickest way to find out whether
CI will be happy.

## Privacy features

Ghost combines several independent privacy mechanisms; each can be used on its
own:

| Feature | What it does |
|---------|--------------|
| Wraith Protocol | Single-round, coordinator-blinded atomic CoinJoin mixing at L2 entry using blind Schnorr signatures. |
| Ghost Keys (BIP-352) | Silent Payments — a fresh on-chain address per payment from one static identifier. |
| Ghost Pay L2 | Off-chain transfers proven with zero-knowledge proofs. |
| Ghost Mode | Incognito node mode — the node stops accepting and advertising transactions to peers, so its mempool is never exposed to surveillance. Pairs with Tor. |
| Ghost Shroud | Randomised relay delay on transactions to resist timing analysis. |
| Ghost Haze | Strips witness padding, scriptSig stuffing, and OP_RETURN payloads from blocks before they are written to disk, retaining the full economic graph. |

## Documentation

Protocol and operator documentation is published at
<https://bitcoinghost.org/docs/>, covering the consensus protocol, the
node-capability system, economics, Ghost Keys, Ghost Pay, the Wraith Protocol,
Ghost Haze, the Reaper, and deployment.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for development setup, code style, and
the pull-request process.

## Acknowledgments

Ghost builds on the work of several projects:

- [Bitcoin Core](https://github.com/bitcoin/bitcoin) — Ghost Core is a fork of Bitcoin Core v30.
- [Stratum V2 / SRI](https://github.com/stratum-mining/stratum) — the Stratum Reference Implementation Ghost extends.
- BIP authors, including [BIP-352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki) (Silent Payments) and [BIP-340/341](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) (Schnorr/Taproot).
- [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin), [snow](https://github.com/mcginty/snow), Tokio, Axum, ZeroMQ, and SQLite.

## Licence

Released under the [MIT Licence](LICENSE).

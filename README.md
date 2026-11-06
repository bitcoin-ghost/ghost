> # ⚠ MAINNET TESTING — NOT READY FOR PUBLIC USE
>
> This software runs on Bitcoin **mainnet** and handles real funds. It is under active
> development and testing. Do not point hashrate, funds, or production infrastructure at it.

# Bitcoin Ghost

[![CI](https://img.shields.io/github/actions/workflow/status/bitcoin-ghost/ghost/ci.yml?label=CI)](https://github.com/bitcoin-ghost/ghost/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/github/v/release/bitcoin-ghost/ghost?label=version)](https://github.com/bitcoin-ghost/ghost/releases/latest)

Bitcoin Ghost is a Bitcoin mainnet project built around a Bitcoin Core fork
(`ghostd`) and a node pool: a mining pool with no operator. Anyone can run a
node; miners' balances are decided by a light share chain, and every block's
coinbase pays them directly (see [`docs/NODE_POOL_SPEC.md`](docs/NODE_POOL_SPEC.md)).
No separate token, no altcoin — it settles in Bitcoin.

- **Website:** <https://bitcoinghost.org>
- **Documentation:** <https://bitcoinghost.org/docs/>
- **Latest release:** <https://github.com/bitcoin-ghost/ghost/releases/latest>

## Components

| Component | Path | Description |
|-----------|------|-------------|
| `ghostd` (Ghost Core) | `ghost-core/` | A fork of Bitcoin Core v30 running on Bitcoin mainnet, with Reaper mempool filtering and Ghost Haze block stripping. Separate C++/CMake build. |
| `ghost-mining` | `bins/ghost-pool/` | Pool node: block templates for pool_sv2, round statistics and the operator API. |
| SV2 mining apps | `bins/translator-sv2/`, `bins/pool-sv2/` | Stratum V2 translator and pool, amalgamated in-tree. pool_sv2 builds every job's canonical coinbase and runs the node pool share-chain relay. |

The workspace contains over 40 crates and binaries under `crates/` and `bins/`.
See [`docs/protocols/ARCHITECTURE.md`](https://bitcoinghost.org/docs/) on the
website for the full crate map, or browse the source directly.

## Architecture

```
                       ┌────────────────────────────────┐
                       │  NODE POOL SHARE-CHAIN RELAY   │
                       │  shares · anchors · sync (8566)│
                       └────────────────────────────────┘
                        ▲              ▲              ▲
                  ┌─────┴─────┐  ┌─────┴─────┐  ┌─────┴─────┐
                  │  Node A   │  │  Node B   │  │  Node C   │
                  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘
                     ghostd         ghostd         ghostd
                        │              │              │
                   Your miners    Their miners    Their miners
                  (Stratum V1)   (Stratum V1)    (Stratum V1)
```

Every node is a peer. Miners connect to whichever node they choose. Nodes agree
who is owed what through the node pool share chain (most-work fork choice, no
votes), and each node selects its own transactions according to its configured
mempool policy.

### Network ports

| Port | Purpose |
|------|---------|
| 3333 | Stratum V1 — hobby tier, ~2,328 starting difficulty |
| 4444 | Stratum V1 — farm/rental tier, ~232,827 starting difficulty |
| 34255 | Stratum V2 — via SRI pool |
| 8566 | Node pool share-chain relay |
| 8080 | REST API |

## Running a node

The install script provisions `ghostd`, `ghost-mining` and the SV2 stratum stack
as a node pool node, writes the configs, and sets up the systemd services. It
runs a preflight first and changes nothing if a check fails. Supply the address
that takes the transaction fees of blocks your node's miners find (P2SH, P2WPKH,
P2WSH or P2TR):

```sh
curl -sSL https://get.bitcoinghost.org | sudo bash -s -- --fee-address bc1q... --alert-webhook https://ntfy.sh
```

Run `sudo bash -s -- --help` to see options such as `--network`, `--relay-peer`,
`--archive` and `--sync`. Full setup guidance is in
[`ghost-web/docs/deployment.md`](ghost-web/docs/deployment.md).

Point a miner at your node with `stratum+tcp://<your-ip>:3333` and a worker name
of `<your payout address>.worker1`; the address must be P2SH, P2WPKH, P2WSH or P2TR.

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
cargo build --release            # builds the Rust workspace (ghost-mining, pool_sv2, ...)
```

`ghost-core` has its own build; see [`ghost-core/INSTALL.md`](ghost-core/INSTALL.md).

Common development commands:

```sh
EXCLUDES="--workspace"

cargo test $EXCLUDES --lib --bins             # test suite, as CI runs it
cargo test -p ghost-np-relay                  # a single crate
cargo clippy $EXCLUDES --all-targets --all-features -- -D warnings
cargo fmt --all                               # format
cargo audit                                   # dependency advisory check
```

Before opening a PR, `scripts/record-tests.sh` runs the full gate exactly as CI does
— formatting, clippy with CI's own argument list, docs under `-D warnings`, the fuzz
targets — and is the quickest way to find out whether
CI will be happy.

## Privacy features

Ghost combines several independent privacy mechanisms; each can be used on its
own:

| Feature | What it does |
|---------|--------------|
| Ghost Keys (BIP-352) | Silent Payments — a fresh on-chain address per payment from one static identifier. |
| Ghost Mode | Incognito node mode — the node stops accepting and advertising transactions to peers, so its mempool is never exposed to surveillance. Pairs with Tor. |
| Ghost Shroud | Randomised relay delay on transactions to resist timing analysis. |
| Ghost Haze | Strips witness padding, scriptSig stuffing, and OP_RETURN payloads from blocks before they are written to disk, retaining the full economic graph. |

## Documentation

Protocol and operator documentation is published at
<https://bitcoinghost.org/docs/>, covering Ghost Keys, Ghost Haze, the Reaper,
and deployment. The node pool is specified in `docs/NODE_POOL_SPEC.md`.

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

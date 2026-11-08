> # ⚠ MAINNET TESTING — NOT READY FOR PUBLIC USE
>
> This software runs on Bitcoin **mainnet** and handles real funds. It is under active
> development and testing. Do not point hashrate, funds, or production infrastructure at it.

# Ghost Pool

[![CI](https://img.shields.io/github/actions/workflow/status/bitcoin-ghost/ghost/ci.yml?label=CI)](https://github.com/bitcoin-ghost/ghost/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/github/v/release/bitcoin-ghost/ghost?label=version)](https://github.com/bitcoin-ghost/ghost/releases/latest)

Ghost Pool is a solo Bitcoin mining pool. No accounts, no sign-up, no KYC: a miner
connects with its own Bitcoin address as its username, and when it finds a block,
the block pays it directly, in the coinbase. Nobody holds a miner's money; there is
no balance, ledger or payout queue. It runs on Bitcoin mainnet, on a Bitcoin Core
fork (`ghostd`). See [`docs/SOLO.md`](docs/SOLO.md).

- **Website:** <https://bitcoinghost.org>
- **Latest release:** <https://github.com/bitcoin-ghost/ghost/releases>

## The payout rule

Every job a miner is given pays, and nothing else:

1. **The treasury** (`bc1qgxg5ywk835c9fp6arz6d6x50xpk6y0ualt900k`): exactly 0.5% of the
   block subsidy (`subsidy / 200`, rounded down), never any part of the fees.
2. **The miner**, at the address in its username: the subsidy minus that 0.5%, plus
   **every** transaction fee.
3. The witness commitment.

At today's 3.125 BTC subsidy that is 1,562,500 sats to the treasury and 310,937,500
sats plus all fees to the miner. The rule is code in one place
(`ghost_common::solo`), and `ghost-audit check` lets a miner verify that a node's
jobs pay it.

## Components

| Component | Path | Description |
|-----------|------|-------------|
| `ghostd` (Ghost Core) | `ghost-core/` | A fork of Bitcoin Core v30 running on Bitcoin mainnet, with optional Reaper mempool filtering and Ghost Haze block stripping. Separate C++/CMake build. |
| `ghost-mining` | `bins/ghost-pool/` | Block templates for pool_sv2 (the template provider), and the node's public API. |
| SV2 mining apps | `bins/translator-sv2/`, `bins/pool-sv2/` | Stratum V2 translator and pool, amalgamated in-tree. pool_sv2 builds every job's solo coinbase, submits found blocks and serves the miner statistics. |
| `ghost-audit` | `bins/ghost-audit/` | `ghost-audit check`: connects as a miner and checks a node's jobs against the payout rule. |

## Architecture

```
   miners (SV1)            miners (SV1)          miners (SV2)
   :3333 small             :4444 farm tier       :34255
        \                     /                     |
         translator_sv2 ------                      |
                      \                             |
                       pool_sv2 (solo coinbase per channel) ----> other node's ghostd
                          |                                       (found blocks, --peer-node)
                     ghost-mining (template provider)
                          |
                        ghostd  <---- addnode ---->  other node's ghostd
```

Each miner's job pays that miner. A block found is submitted to the node's own
`ghostd` first, then sent to every other node listed in `[solo] submit_rpc`, so it
reaches the network even if one node is slow or down.

### Network ports

| Port | Purpose |
|------|---------|
| 3333 | Stratum V1, small miners (Bitaxe, NerdAxe): the lower starting difficulty |
| 4444 | Stratum V1, the farm tier (S19/S21-class, rented hashrate): the higher starting difficulty |
| 34255 | Stratum V2 (pool_sv2, Noise-authenticated) |
| 8333 | Bitcoin P2P |
| 8080 | REST API |
| 8332 | Bitcoin RPC, opened only to the other node of a pair (`--peer-node`) |

## Running a node

The install script provisions `ghostd`, `ghost-mining` and the SV2 stratum stack,
writes the configs and sets up the systemd services. It runs a preflight first and
changes nothing if a check fails. Nothing is required; with no flags on a terminal it
runs a guided setup:

```sh
curl -sSL https://get.bitcoinghost.org | sudo GHOST_VERSION=np-latest bash -s -- --alert-webhook https://ntfy.sh
```

Run it with `--help` for the options (`--network`, `--peer-node`, `--submit-auth`,
`--reaper`, `--archive`, `--sync`, `--uninstall`, ...). The Reaper (mempool spam filter)
is off by default: blocks built from the standard policy propagate fastest.

Point a miner at your node with `stratum+tcp://<your-ip>:3333` (or `:4444` for the
farm tier) and a username of `<your Bitcoin address>.<worker>`; the address must be
P2SH, P2WPKH, P2WSH or P2TR (P2PKH `1...` addresses are refused). Any password.

### Two nodes

Two nodes back each other up: each sends every block its miners find to the other as
well as to its own `ghostd`, and each keeps a direct Bitcoin connection to the other.
Once both are installed, run on each:

```sh
sudo bash install-node.sh --peer-node <the other node's IP> --submit-auth <its rpcuser:rpcpassword>
```

`--peer-node` adds the other node as a Bitcoin peer (`addnode`), sends found blocks to
its RPC (`http://<ip>:8332`), and lets that one address reach this node's RPC
(`rpcallowip` and a ufw rule for it alone). The other node's credentials are its
`/etc/bitcoin/bitcoin.conf` `rpcuser`/`rpcpassword`, kept root-only in
`/etc/ghost/solo-submit-rpc.auth`. Keep the link between the two private (a VPN or a
private network): the RPC password crosses it.

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
cargo test -p ghost-common                    # a single crate
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
<https://bitcoinghost.org>. Ghost Pool is described in `docs/SOLO.md`; the node pool's
share chain it replaced is archived in `docs/NODE_POOL_SPEC.md`.

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

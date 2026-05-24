# Bitcoin Ghost
<div align="center">

```
 ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓
▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒
▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░
▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░
░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░
░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░
▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░
 ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░
 ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░
      ░              ░
```

<a href="https://git.io/typing-svg">
  <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&size=24&duration=2500&pause=800&color=F7931A&center=true&vCenter=true&width=750&height=90&lines=You+own+your+keys.+You+run+your+node.;Now+own+your+hashrate.;100%25+of+TX+fees+go+to+the+node+operator.;101+Elder+positions.+Then+the+window+closes.;Private+payments.+ZK+proofs.+No+compromises." alt="Typing SVG" />
</a>

<p>
  <img src="https://img.shields.io/badge/Bitcoin-Native-F7931A?style=for-the-badge&logo=bitcoin&logoColor=white" alt="Bitcoin" />
  <img src="https://img.shields.io/badge/Rust-1.75+-000000?style=for-the-badge&logo=rust&logoColor=white" alt="Rust" />
  <a href="https://github.com/bitcoin-ghost/ghost/actions"><img src="https://img.shields.io/github/actions/workflow/status/bitcoin-ghost/ghost/ci.yml?style=for-the-badge&label=CI" alt="CI" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="License" /></a>
  <img src="https://img.shields.io/badge/version-1.8.0-green?style=for-the-badge" alt="Version" />
</p>

<p>
  <a href="https://bitcoinghost.org">
    <img src="https://img.shields.io/badge/Website-bitcoinghost.org-F7931A?style=flat-square&logo=firefox&logoColor=white" alt="Website"/>
  </a>
  <a href="https://bitcoinghost.org/whitepaper">
    <img src="https://img.shields.io/badge/Whitepaper-Read-blue?style=flat-square&logo=gitbook&logoColor=white" alt="Whitepaper"/>
  </a>
  <a href="docs/protocols/GETTING_STARTED.md">
    <img src="https://img.shields.io/badge/Get_Started-Guide-green?style=flat-square&logo=readthedocs&logoColor=white" alt="Getting Started"/>
  </a>
</p>

<sub>
<a href="#the-problem">The Problem</a> · <a href="#complete-your-sovereignty-stack">Sovereignty Stack</a> · <a href="#what-you-can-build">Use Cases</a> · <a href="#the-5-4-3-2-1-share-system">Earn Rewards</a> · <a href="#quick-start">Quick Start</a> · <a href="#deep-dive">Deep Dive</a> · <a href="#acknowledgments">Acknowledgments</a>
</sub>

</div>

<br/>

> *"Three companies control more than half of Bitcoin's hashrate. The base layer of the world's monetary revolution depends on the goodwill of a handful of mining executives. Nobody is getting paid to run the nodes that actually validate every transaction. And every full node operator is unknowingly storing content that could put them in prison. Something is broken."*

---

## The Problem

> [!CAUTION]
> **Bitcoin mining is more centralized than it has ever been.** Three pools — Foundry, AntPool, and ViaBTC — routinely control over 50% of the network's hashrate. When you mine on these pools, someone else selects which transactions enter blocks. Someone else holds your rewards. Someone else can be subpoenaed, pressured, or shut down, and your hashrate vanishes with them. This is not theoretical risk. This is the current state of Bitcoin.

You run a full node. You validate every transaction. You serve blocks to peers. You've been doing this for months, maybe years. **What do you get for it?** Nothing. A higher electricity bill. The infrastructure that Bitcoin depends on — the network of full nodes that enforces consensus rules — runs entirely on unpaid volunteerism. Altruism doesn't scale. When running a node costs money and pays nothing, nodes disappear. When nodes disappear, the network centralizes.

> [!WARNING]
> **There's a problem nobody talks about.** Every Bitcoin full node stores the entire blockchain — including content embedded by malicious third parties via witness data, OP_RETURN, and scriptSig fields. Under strict liability statutes in the US (18 U.S.C. § 2252), UK, and EU, possession of this content is a criminal offense **regardless of intent or knowledge**. Running a full archive node carries legal exposure that most operators don't even know they have.

---

## Complete Your Sovereignty Stack

You've already done the hard parts. Ghost finishes the job.

<table>
<tr>
<td align="center" width="20%">

### ${\color{green}\textbf{&#10003;}}$ Keys

You hold your<br/>own keys

</td>
<td align="center" width="20%">

### ${\color{green}\textbf{&#10003;}}$ Node

You run your<br/>own node

</td>
<td align="center" width="20%">

### ${\color{orange}\textbf{?}}$ Hashrate

Who controls your<br/>mining?

</td>
<td align="center" width="20%">

### ${\color{orange}\textbf{?}}$ Payments

Are your payments<br/>actually private?

</td>
<td align="center" width="20%">

### ${\color{orange}\textbf{?}}$ Protection

Is your node<br/>legally safe?

</td>
</tr>
</table>

**Ghost fills every `?` with a `✓`.** Decentralized mining you control. Private payments with 5 independent privacy layers. Legal protection through structural content removal. One ecosystem. All Bitcoin. No altcoins. No tokens. No trust.

---

## What You Can Build

> [!TIP]
> **Already running `bitcoind`?** Switch to `ghostd` — same Bitcoin Core v30 base, same RPC, same data directory. Enable Archive mode. Start earning from the node reward pool for every block the network finds. You're already donating the storage and bandwidth. Ghost just pays you for it.

<table>
<tr>
<td width="50%" valign="top">

### Start a Pool with Your Friends

You and three friends each have a BitAxe. Instead of pointing them at Foundry, each of you runs a Ghost node. Your miners connect to your own nodes over Stratum V1. The nodes form a P2P mesh, share work, reach BFT consensus on payouts, and submit blocks to Bitcoin. No middleman. No account. No custodian. When you find a block, rewards distribute automatically — every node can verify the math. As more people join, **it becomes more decentralized, not less.**

</td>
<td width="50%" valign="top">

### Earn Bitcoin Running Infrastructure

No mining hardware? Run a Ghost node with Archive mode (${\color{orange}\textbf{+5 shares}}$) and Reaper strict mode (${\color{orange}\textbf{+2 shares}}$). Keep 95% uptime for 7 days, and you're earning a proportional cut of the node reward pool from every block the network finds. Add Ghost Pay (${\color{orange}\textbf{+4}}$) and open your Stratum port (${\color{orange}\textbf{+3}}$) to reach 14 of 15 possible shares. Payouts happen every single block in the coinbase — transparent, verifiable, automatic.

</td>
</tr>
<tr>
<td width="50%" valign="top">

### Send Private Bitcoin Payments

Open your Ghost wallet and send Bitcoin that can't be traced. Wraith Protocol mixes your coins at L2 entry using blind-signature CoinJoin — even the coordinator can't link your input to your output. Ghost Keys (BIP-352) generate a unique on-chain address for every payment from one static identifier. Ghost Pay settles in ~10 seconds with ZK proofs. **No channel management. No liquidity routing. No metadata leakage.**

</td>
<td width="50%" valign="top">

### Protect Your Node from Legal Exposure

Ghost Haze irreversibly strips hazeable fields (witness padding, scriptSig data stuffing, OP_RETURN payloads) from blocks before they touch your disk. Archive size drops from ~718 GB to ~195 GB. What remains is the complete economic graph — every transaction, every UTXO, every balance — with cryptographic proof that stripped content existed, but without the content itself. **For the first time, run a full archival Bitcoin node without storing content you didn't ask for.**

</td>
</tr>
</table>

---

## The 5-4-3-2-1 Share System

Nodes earn shares in the node reward pool by **proving** — not claiming — that they run real infrastructure. Every capability is verified through cryptographic challenges from random peers. No self-reporting. No honor system.

| Capability | Shares | How It's Verified |
|:-----------|:------:|:------------------|
| **Archive Node** | ${\color{orange}\textbf{+5}}$ | Random peers request arbitrary historical blocks. Serve them or fail. |
| **Ghost Pay** | ${\color{orange}\textbf{+4}}$ | Random L2 state lookup challenges. Prove you're processing payments. |
| **Public Mining** | ${\color{orange}\textbf{+3}}$ | Peers probe your Stratum port. Accept real miners or don't claim you do. |
| **Reaper** | ${\color{orange}\textbf{+2}}$ | Policy classification challenges. Prove your mempool rejects dead code. |
| **Elder** | ${\color{orange}\textbf{+1}}$ | Contributed to the MPC ceremony. **First 101 nodes only.** Permanent. |

**Maximum: 15 shares.** A full-capability node earns **15x** what a minimal node earns. Every 5 minutes, 3 random peers challenge you. 10+ challenges at 95% pass rate to qualify. The gatekeeper: **95% uptime over 7 trailing days** before any shares count at all. There are no shortcuts.

> [!IMPORTANT]
> **Where does the money come from?**
>
> | Revenue Source | Who Gets It | Scale |
> |---|---|---|
> | **Transaction fees** | 100% to the node whose template built the winning block | Grows with network activity — unbounded |
> | **Node reward pool** | 0.5–1% of block subsidy, split among top 100 nodes by shares | Currently ~15,625 sats/block at 3.125 BTC subsidy |
> | **Miner pool** | 99% of block subsidy, split among top 200 miners by work | Standard pool payout |
>
> Every payout is on-chain in the coinbase transaction. Transparent. Verifiable by anyone. No invoices. No accounts.

### The Flywheel

Ghost progressively decentralizes over time. The economics **reward early adoption**:

```
More nodes join ──► More blocks through Ghost ──► Treasury hits 21 BTC threshold faster
                                                           │
                                                           ▼
                            ┌─── 5-year decay begins ──────┘
                            │
                            ▼
         Node rewards DOUBLE from 0.5% ──► 1.0% of all block subsidies
                            │
                            ▼
              Better incentives ──► More nodes join ──► Cycle accelerates
```

Year 1: 0.6% nodes / 0.4% treasury. Year 3: 0.8% / 0.2%. **Year 5 onward: 100% of the pool fee goes to node operators. The treasury goes to zero. Permanently.** The faster the network grows, the sooner everyone's rewards double.

> [!CAUTION]
> **101 Elder positions.** The MPC ceremony accepts the first 101 contributing nodes. Elder status grants ${\color{orange}\textbf{+1 share}}$ permanently. Positions are non-transferable — if an elder goes offline, their position is lost forever. Not reassigned. Not recycled. This is a consensus parameter. Once the 101st node contributes, this window closes and never reopens.

---

## Architecture

```
                       ┌──────────────────────────────────┐
                       │       P2P MESH NETWORK            │
                       │                                    │
                       │   consensus · shares · payouts     │
                       │   blocks · health · discovery      │
                       └──────────────────────────────────┘
                        ▲              ▲              ▲
                        │              │              │
                  ┌─────┴─────┐  ┌─────┴─────┐  ┌─────┴─────┐
                  │  Node A   │  │  Node B   │  │  Node C   │
                  │  (you)    │  │ (friend)  │  │ (anyone)  │
                  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘
                        │              │              │
                    ghostd         ghostd         ghostd
                  (Ghost Core)   (Ghost Core)   (Ghost Core)
                        │              │              │
                  ┌─────┴─────┐  ┌─────┴─────┐  ┌─────┴─────┐
                  │  Reaper   │  │  Haze     │  │  Ghost    │
                  │  Filter   │  │  Archive  │  │  Pay L2   │
                  └───────────┘  └───────────┘  └───────────┘
                        ▲              ▲              ▲
                        │              │              │
                   Your miners    Their miners    Light wallets
                   (BitAxe, S19)  (Stratum V1)   (CLI / TUI)
```

Every node is a peer. No node is special. Miners connect to whichever node they choose. Nodes reach consensus through BFT voting on a Noise-encrypted ZeroMQ mesh across 8 dedicated ports. Ghost Core (`ghostd`) is a Bitcoin Core v30 fork with Reaper mempool filtering and Ghost Haze block stripping built in.

<details>
<summary><strong>Network Ports</strong></summary>

| Port | Purpose |
|------|---------|
| 3333 | Stratum V1 — native miner connections |
| 34255 | Stratum V2 — via SRI pool |
| 8080 | REST API |
| 8555–8562 | P2P consensus mesh (shares, blocks, voting, health, discovery, elders, payouts) |
| 8800 | Ghost Pay L2 API |
| 8900 | GSP WebSocket (light wallet backend) |

</details>

---

## Quick Start

```bash
# Clone and build
git clone https://github.com/bitcoin-ghost/ghost.git
cd ghost && git submodule update --init --recursive
cargo build --release

# Start Ghost Core
./ghost-core/bin/ghostd -daemon

# Generate node identity
./target/release/ghost-cli key generate --output ~/.ghost/node.key

# Launch your node — connects to mesh, begins earning
./target/release/ghost-pool --config /etc/ghost/pool.toml
```

**Point a miner at your node:** `stratum+tcp://<your-ip>:3333` — worker name: `<btc_address>.worker1`

<details>
<summary><strong>Prerequisites</strong></summary>

- **Rust** 1.75+ (stable toolchain)
- **Ghost Core** or Bitcoin Core 27.0+
- **SQLite** 3.35+
- **Linux / macOS** (Windows via WSL2)

</details>

<details>
<summary><strong>Docker</strong></summary>

```bash
cd docker && cp .env.example .env    # Edit .env with your config
docker-compose up -d

# With monitoring (Prometheus + Grafana)
docker-compose --profile monitoring up -d
```

</details>

<details>
<summary><strong>Light Wallet</strong></summary>

```bash
./target/release/ghost-light-wallet-cli init
./target/release/ghost-light-wallet-cli receive         # Your Silent Payment address
./target/release/ghost-light-wallet-cli balance --refresh
./target/release/ghost-light-wallet-cli send <address> <amount_sats>
```

</details>

---

## Deep Dive

<details>
<summary><strong>Privacy Stack — Five Independent Layers</strong></summary>

<br/>

Ghost implements defense-in-depth privacy. Each layer operates independently — use any combination. **No other Bitcoin L2 combines all five.**

| Layer | What It Does | What It Defeats |
|-------|-------------|-----------------|
| **Wraith Protocol** | Two-phase CoinJoin mixing at L2 entry with blind Schnorr signatures | Transaction graph analysis |
| **Ghost Keys (BIP-352)** | Silent Payments — unique address per payment from one static ID | Address reuse, sender-recipient linkage |
| **Ghost Pay L2** | ZK-proven off-chain transfers in ~10-second blocks | On-chain surveillance |
| **Ghost Shroud** | Random 0–5s relay delay on all transactions | Network timing analysis |
| **Ghost Haze** | Irreversible witness/scriptSig/OP_RETURN stripping | Archive content forensics |

Lightning has no entry privacy. Liquid is federated. Ark requires trust in service providers. Ghost is the only stack where mixing, stealth addresses, ZK transfers, network obfuscation, and archive stripping all work together.

</details>

<details>
<summary><strong>Ghost Pay — L2 Payments</strong></summary>

<br/>

| | Ghost Pay | Lightning |
|---|---|---|
| **Setup** | Fund one Ghost Lock | Open channels, manage liquidity |
| **Routing** | Direct L2 transfer | Multi-hop path finding |
| **Entry privacy** | Wraith mixing (high) | Channel opens visible on-chain (low) |
| **State model** | ZK-proven (mathematical guarantee) | Channel-based (watch for fraud) |
| **Offline receiving** | Yes (validators store L2 state) | No (must be online) |
| **Self-custody** | Ghost Locks with timelocked recovery | Close channel before counterparty |
| **Maturity** | Active development | Production (5+ years) |

**Retail payments under 100k sats** use optimistic confirmation — merchant sees "Confirmed" immediately if 8 conditions about the sender's lock are met. Full settlement follows on the next virtual block. No protocol fee -- users pay only their share of batch mining costs.

**Self-custody guaranteed.** If the L2 network goes offline permanently, you recover your Bitcoin on L1 after the timelock expires. No federation. No custodian.

</details>

<details>
<summary><strong>Decentralized Mining</strong></summary>

<br/>

**Today:**
```
Miner → Central Pool Server → Operator selects transactions
                             → Operator holds your rewards
                             → Operator can censor, delay, refuse
                             → Operator is a single regulatory target
```

**Ghost:**
```
Miner → Any Ghost Node → P2P mesh (Noise-encrypted ZeroMQ)
                        → BFT consensus on payouts (67% threshold)
                        → Pre-computed payouts (zero block submission delay)
                        → Each node selects its own transactions
```

**Pre-computed payouts** eliminate the block submission delay that costs traditional pools. Ghost maintains continuous rolling consensus on reward distribution. When a winning share arrives, the block is submitted immediately — coinbase outputs already correct.

**Transaction sovereignty.** Each node runs its own mempool policy via BUDS. Nodes running `bitcoin_pure` include only financial transactions. Nodes running `full_open` include everything. The miner chooses which policy to support. No central authority decides what gets mined.

**Censorship resistance.** 67% BFT threshold — 33% of nodes can be malicious or censoring, honest nodes continue. No single entity controls block construction.

</details>

<details>
<summary><strong>Legal Protection — Ghost Haze & Reaper</strong></summary>

<br/>

**Ghost Haze** strips hazeable content from blocks before writing to disk. Content exists only in volatile RAM during validation. Irreversible — SHA-256 is one-way. Complete economic graph preserved.

**Ghost Reaper** detects dead code via 8 algorithmic vectors:
inscription envelopes, drop stuffing, unreachable code, fake pubkeys, oversized OP_RETURN, taproot annex, excess witness data, scriptSig stuffing. **Not a blacklist** — structural analysis that catches unknown patterns automatically.

**Three-layer legal defense:**
1. **Physical impossibility** — content does not exist on disk
2. **No mens rea** — data was opaque bytes in hash functions, never rendered
3. **Analogous precedent** — equivalent to a router forwarding encrypted packets

</details>

---

## The Project

<table>
<tr>
<td width="33%" align="center">

**30+ crates**<br/>
<sub>Modular Rust workspace</sub>

</td>
<td width="33%" align="center">

**14 security audits**<br/>
<sub>Zero critical vulnerabilities</sub>

</td>
<td width="33%" align="center">

**8 protocol specs**<br/>
<sub>Fully documented</sub>

</td>
</tr>
<tr>
<td align="center">

**12 BIPs**<br/>
<sub>Implemented or extended</sub>

</td>
<td align="center">

**Noise + ZK + BFT**<br/>
<sub>Encrypted mesh, proven consensus</sub>

</td>
<td align="center">

**MIT Licensed**<br/>
<sub>Free and open source forever</sub>

</td>
</tr>
</table>

<details>
<summary><strong>Documentation</strong></summary>

| Document | Description |
|----------|-------------|
| **[Getting Started](docs/protocols/GETTING_STARTED.md)** | Step-by-step setup for new operators |
| [Full Specification](docs/SPECIFICATION.md) | Complete protocol specification |
| [Node Capabilities](docs/protocols/NODE_CAPABILITIES.md) | 5-4-3-2-1 verification system |
| [Economics](docs/protocols/ECONOMICS.md) | Reward distribution, treasury decay |
| [Consensus](docs/protocols/CONSENSUS.md) | ZK-BFT consensus protocol |
| [Ghost Keys](docs/protocols/GHOST_KEYS.md) | BIP-352 Silent Payments |
| [Ghost Pay](docs/protocols/GHOST_PAY.md) | L2 payment network |
| [Wraith Protocol](docs/protocols/WRAITH_PROTOCOL.md) | CoinJoin mixing |
| [Ghost Haze](docs/protocols/GHOST_HAZE.md) | Stripped block archival |
| [Ghost Reaper](docs/protocols/GHOST_REAPER.md) | Dead code detection |
| [BUDS Policy](docs/protocols/BUDS_POLICY.md) | Transaction classification |
| [Architecture](docs/protocols/ARCHITECTURE.md) | System architecture and crate map |
| [Deployment](docs/DEPLOYMENT_RUNBOOK.md) | Production deployment guide |
| [API Reference](docs/API_ENDPOINTS.md) | HTTP API documentation |
| [Wallets](docs/wallets/README.md) | Wallet options and setup |

</details>

<details>
<summary><strong>Development</strong></summary>

```bash
cargo build --release                        # Build all binaries
cargo test --workspace                       # Full test suite
cargo test -p ghost-consensus                # Single crate
cargo clippy --workspace -- -D warnings      # Lint (zero warnings)
cargo fmt --all                              # Format
cargo audit                                  # Dependency security audit
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

</details>

<details>
<summary><strong>Security</strong></summary>

14 rounds of comprehensive auditing. Zero critical vulnerabilities in release. Continuous fuzzing via cargo-fuzz. Dependency auditing via cargo-audit in CI.

All P2P communication encrypted via Noise Protocol Framework. Sensitive database fields encrypted at rest. All public APIs rate-limited. Node identity uses Ed25519 with secure key rotation via dual-signature proofs.

Report vulnerabilities to: **security@bitcoinghost.org**

</details>

---

## Acknowledgments

Ghost is built on the work of people and projects we deeply respect:

**[Bitcoin Core](https://github.com/bitcoin/bitcoin)** — Ghost Core is a fork of Bitcoin Core v30. The decades of careful engineering by hundreds of contributors is the foundation everything here is built on.

**[Stratum V2 / SRI](https://github.com/stratum-mining/stratum)** — The Stratum Reference Implementation team built the modern mining protocol Ghost extends. Their mission to decentralize template selection aligns directly with ours.

**BIP Authors** — Ghost implements or extends:
[BIP-352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki) (Silent Payments) by Josie Baker and Ruben Somsen ·
[BIP-340/341](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) (Schnorr/Taproot) by Pieter Wuille, Jonas Nick, Tim Ruffing ·
[BIP-320](https://github.com/bitcoin/bips/blob/master/bip-0320.mediawiki) (Version Rolling) by Timo Hanke ·
BIP-141 (SegWit) · BIP-157/158 (Compact Block Filters) · BIP-32/39/86 (HD Wallets)

**[rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin)** · **[bellperson](https://github.com/filecoin-project/bellperson)** · **[snow](https://github.com/mcginty/snow)** · Tokio · Axum · ZeroMQ · SQLite

<a href="https://github.com/bitcoin-ghost/ghost/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=bitcoin-ghost/ghost" alt="Contributors" />
</a>

---

## License

[MIT](LICENSE)

---

<div align="center">

**Your keys. Your node. Your pool.**

<p>
  <a href="https://bitcoinghost.org">
    <img src="https://img.shields.io/badge/Website-bitcoinghost.org-F7931A?style=for-the-badge&logo=bitcoin&logoColor=white" alt="Website"/>
  </a>
  <a href="https://github.com/bitcoin-ghost">
    <img src="https://img.shields.io/badge/GitHub-bitcoin--ghost-181717?style=for-the-badge&logo=github&logoColor=white" alt="GitHub"/>
  </a>
  <a href="https://bitcoinghost.org/whitepaper">
    <img src="https://img.shields.io/badge/Whitepaper-Read-blue?style=for-the-badge&logo=gitbook&logoColor=white" alt="Whitepaper"/>
  </a>
</p>

<sub>Ghost is free, open-source software under the MIT license. Not financial advice. Not your keys, not your coins. Not your node, not your rules. Not your pool, not your hashrate.<br/>Run your own. Verify everything.</sub>

</div>

<img src="https://capsule-render.vercel.app/api?type=waving&color=F7931A&height=80&section=footer" width="100%" alt=""/>

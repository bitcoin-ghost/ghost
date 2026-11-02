# L2 vs Lightning (and friends)

*A comparison of Ghost Pay against the other Bitcoin scaling layers people actually use today: Lightning, Liquid, Ark, Citrea, RGB, Drivechains. What each one is good at, where each one breaks down, and where Ghost Pay fits in.*

## TL;DR

Different L2s solve different problems. Lightning is great for fast retail payments to people you're routing-friendly with. Liquid is great for federated institutional flow. Ark gives you channel-free UX with periodic on-chain settlement. Citrea is the EVM crowd. RGB is for client-side programmable assets. Drivechains is theoretical until the soft fork lands.

Ghost Pay is positioned as: **private payments that work for everyone, with ZK-proven state validity, no channel management, no federation, no smart contracts**. It's not the right answer if you want EVM. It's not the right answer if you want $5B of institutional volume sitting in one place. It IS the right answer if you want self-custodial private retail payments without the operational burden of Lightning channels.

The rest of this page goes through each alternative honestly. We're not the answer to every question.

## Quick matrix

| Feature | Ghost Pay | Lightning | Citrea | Liquid | Ark | Drivechains | RGB |
|---|---|---|---|---|---|---|---|
| **Type** | L2 + ZK + BFT | Payment channels | ZK rollup | Federated sidechain | VTXO protocol | Miner-validated sidechain | Client-side validation |
| **Settlement** | Instant <$100, ~10 s larger | Instant in-channel | ~12 s blocks | ~2 min finality | Batched rounds | Sidechain blocks | Client-side |
| **Privacy** | High (ZK + Wraith) | Medium | Low (EVM) | Medium (CT) | Medium | Varies | High |
| **Custody** | Non-custodial | Non-custodial | BitVM bridge | Federated (15-of-67) | ASP-coordinated | Miner escrow | Non-custodial |
| **Capacity** | Unlimited | Per-channel | Unlimited | Unlimited | ASP-limited | Unlimited | Unlimited |
| **Smart contracts** | No | HTLCs only | Full EVM | Limited (Elements) | No | Full (sidechain) | Turing-complete |
| **State validity** | ZK-proven | N/A | ZK-proven | Federated | Unilateral exit | Miner-validated | Client-validated |
| **Bitcoin changes** | None | None | None | None | None | Soft fork required | None |
| **Status** | Active | Production | Mainnet (Jan 2026) | Production since 2018 | Beta (2025) | Proposed (not activated) | Mainnet (Nov 2025) |

The rest is detail.

## Lightning Network

The most mature Bitcoin L2. Bidirectional payment channels between participants, with HTLC-routed multi-hop payments.

**Strengths**

- Instant in-channel finality.
- Strong ecosystem — exchanges, wallets, merchants are all wired in.
- 99.7% payment success rate in well-routed deployments.
- Taproot Assets v0.7 enables multi-asset transfers.
- No Bitcoin protocol changes required.

**Weaknesses**

- Channel opening requires an on-chain transaction + capital lockup.
- Inbound liquidity is a persistent UX problem — receiving requires someone to commit funds *toward* you.
- Node count has been declining since the 2022 peak.
- Channel management is the #1 reason new users churn.
- Privacy is limited: routing nodes see the payment hop, the source-routing onion isn't perfect at small networks, and amount correlation is feasible at low traffic.
- Channel jamming and replacement-cycling attacks remain unsolved without protocol changes.

**Vs Ghost Pay**

| Aspect | Ghost Pay | Lightning |
|---|---|---|
| Setup | Fund a Ghost Lock once via Wraith | Open channels, manage liquidity over time |
| Small payments (<$100) | Instant (optimistic) | Instant |
| Large payments | ~10 s virtual block | Instant if there's a route, blocks the channel otherwise |
| Max payment | L2 balance | Channel capacity (typically <0.1 BTC for small users) |
| Privacy | ZK proofs hide amounts; Wraith breaks input-output graph at entry | Routing exposes payment hops |
| Offline receiving | Yes — payment lands on L2 state regardless of recipient liveness | No — recipient must be online to claim |
| Custodial risk | None | None |

**Honest read:** Lightning wins on time-to-instant for already-routed channels and on the depth of its merchant ecosystem. Ghost Pay wins on UX (no channel management), privacy (ZK + Wraith), and offline receive. If you're already running a Lightning node and it works for you, there's no urgent reason to switch. If you've bounced off Lightning's complexity, Ghost Pay is the alternative without that complexity.

## Citrea

Bitcoin's first ZK-rollup. Mainnet launched January 2026.

**Strengths**

- Full EVM compatibility — every Solidity contract Just Works.
- ZK proofs verified on Bitcoin (via BitVM Clementine bridge).
- ctUSD T-bill-backed stablecoin live.
- BTC-backed lending markets, full DeFi stack.
- No Bitcoin soft fork required.

**Weaknesses**

- EVM transactions aren't private. Account balances and contract state are public.
- BitVM bridge introduces complexity and trust assumptions during the optimistic challenge window.
- 12-second block times — fine for DeFi, slow for retail payments.
- Brand new technology; runtime exposure is short.
- Requires trust in the prover infrastructure for liveness (not security).

**Vs Ghost Pay**

These two solve different problems. Citrea is the EVM-on-Bitcoin stack: programmability, lending, stablecoins. Ghost Pay is private payments. The use cases barely overlap.

If you want to deploy a smart contract on Bitcoin, use Citrea. If you want to receive a salary or pay a coffee privately, use Ghost Pay. Both can coexist on the same wallet.

## Liquid Network

Blockstream's federated sidechain. In production since 2018.

**Strengths**

- 5+ years of production track record.
- $5 B+ in TVL.
- Confidential Transactions by default — amounts and asset types are hidden.
- Stablecoin and security-token issuance built in.
- One of the largest blockchain platforms for real-world-asset tokenisation.

**Weaknesses**

- Federated trust model: 15-of-67 multisig of major exchanges and institutions. Not trustless.
- Peg-out requires a federation member.
- 2-minute finality — too slow for retail.
- Limited programmability via Elements script.
- Institutional focus — retail UX is an afterthought.

**Vs Ghost Pay**

| Aspect | Ghost Pay | Liquid |
|---|---|---|
| Trust model | Non-custodial timelocked Ghost Locks | Federated 15-of-67 |
| Finality | ~10 s | ~2 min |
| Privacy | ZK + Wraith | Confidential Transactions |
| Exit to L1 | Self-custody (timelocked recovery script) | Requires federation member to sign |
| Audience | Retail | Institutional, trading desks, asset issuers |

**Honest read:** Liquid is institutional infrastructure with strong privacy (CT). It works at scale because exchanges and OTC desks trust the federation. Ghost Pay declines to require a federation. If "I have to ask someone to peg out" is acceptable for your use case, Liquid is mature and battle-tested. If self-custody is non-negotiable, Ghost Pay is the privacy-first alternative.

## Ark Protocol

Innovative virtual-UTXO-based protocol, Arkade public beta launched 2025.

**Strengths**

- No channel setup. Users have "VTXOs" coordinated by Ark Service Providers (ASPs).
- Atomic swaps between users via shared VTXO state.
- Unilateral on-chain exit if your ASP misbehaves.
- Smaller on-chain footprint than Lightning.
- Works without Bitcoin protocol changes (covenants help, aren't required).

**Weaknesses**

- VTXOs expire — typically 30 days. Long-term hold requires re-roll, which costs.
- Coordinator (ASP) is a centralisation point. Self-custody is preserved via unilateral exit, but operational dependency exists.
- ASP-limited capacity. New ASPs improve this but the model favours one-coordinator-per-pool.
- Newer than Lightning. Production exposure is shallow.

**Vs Ghost Pay**

| Aspect | Ghost Pay | Ark |
|---|---|---|
| Coordination | Mesh of Ghost Pool nodes (BFT consensus) | One ASP per pool |
| Expiry | Permanent until withdrawn | VTXOs expire (typically 30 days) |
| Privacy | ZK proofs hide amounts | Limited — VTXO graph visible to ASP |
| Exit | Reconciliation batches at epoch boundaries | Unilateral on-chain exit |

**Honest read:** Ark and Ghost Pay are both trying to be "channel-free L2 with self-custody". Ark relies on ASP coordination + unilateral-exit fallback. Ghost Pay relies on BFT consensus across a mesh of independent pool nodes. Ark's model is simpler operationally; Ghost Pay's privacy is stronger because amounts and graph are ZK-hidden, not just non-public-by-default.

## Drivechains (BIP-300/301)

Miner-validated sidechain proposal. Not activated.

**Strengths (in theory, if activated)**

- Native programmability — sidechain can be EVM, RGB, anything.
- Miner-secured, no federation.
- Atomic swaps between sidechain assets.

**Weaknesses**

- Requires soft fork. BIP-300/301 has been controversial for years.
- Until activation, this section is hypothetical.
- 6-month withdrawal voting window even if activated.
- Miner escrow concentrates trust in mining pools.

**Vs Ghost Pay**

Ghost Pay deploys today on unmodified Bitcoin. Drivechains needs Bitcoin to soft-fork to deploy at all. As of writing, that hasn't happened. If it ever does, Drivechains becomes a serious comparator. Until then, it's an aspirational design.

## RGB

Client-side validation protocol. Mainnet November 2025.

**Strengths**

- Turing-complete state contracts (RGB-20, RGB-21, smart contracts).
- Truly off-chain — no global state to validate.
- Strong privacy by default (no public state).
- No Bitcoin protocol changes required.

**Weaknesses**

- Atomic swaps between users require interactive sessions.
- Asset transfer requires the recipient to be online (or a relay system).
- Not designed for payments per se — designed for asset transfers.
- Steep learning curve for developers used to public-state systems.

**Vs Ghost Pay**

These don't compete. RGB is for issuing and transferring programmable assets with strong privacy. Ghost Pay is for moving BTC privately. Use them together: an RGB-issued token transferred between users who hold their UTXOs in Ghost Locks gives you both private assets and private movement.

## Where Ghost Pay sits in the picture

Ghost Pay's design choices, summarised:

- **No channels.** A user funds one Ghost Lock via Wraith and never thinks about liquidity again.
- **No federation.** Validity is enforced by ZK proofs verifiable by every node, not by a multisig committee.
- **No smart contracts.** This is a payments layer, not a programmability layer. If you need EVM, use Citrea. If you need state contracts, use RGB.
- **Privacy by default, not opt-in.** Amounts are ZK-proven; entry/exit are mixed via Wraith; addresses are stealth (Silent Payment v2). The default user gets the protection without configuration.
- **BFT-voted state.** A 67% supermajority of pool nodes signs every L2 epoch. No single coordinator can rug.

The trade-offs are real:

- Sub-10-second finality, not microsecond. For a coffee, this is fine. For HFT, this isn't a fit.
- No programmable money. If you want a contract that triggers on a price feed, look elsewhere.
- 6-block confirmation latency on the L1 settlement transaction matters for very large unshields.

## When to use what

| Goal | Use |
|---|---|
| Fast everyday payments to people in your routing graph | Lightning |
| Private retail payments to anyone | **Ghost Pay** |
| EVM smart contracts on Bitcoin | Citrea |
| Institutional confidential transfers | Liquid |
| Channel-free L2 with unilateral exit | Ark |
| Programmable client-side assets | RGB |
| Smart contracts on Bitcoin (someday) | Drivechains, if BIP-300 activates |

Most of these can coexist. A user who runs Lightning for daily commerce, holds long-term cold storage in plain L1, and uses Ghost Pay for privacy-sensitive payments is making perfectly reasonable choices.

## What this comparison isn't

- **Not a feature checklist for picking the "best" L2.** "Best" depends entirely on what you're optimising for. Speed, privacy, programmability, liquidity, institutional acceptability — different L2s sit at different points in that space.
- **Not exhaustive.** There are other Bitcoin L2 attempts (Stacks, Rootstock, Stacks subnets, Lava, Mercurium, etc.) that don't appear here either because they're early-stage or because they target a use case so different that comparison doesn't help. Specific projects you care about can be queried directly.
- **Not a snapshot in time.** L2 ecosystems move fast. Citrea launched mainnet only weeks before this doc was written; RGB launched a couple of months earlier. Numbers in this page (capacities, finality times, TVLs) drift. Treat them as the order-of-magnitude they are, not as today's exact values.
- **Not adversarial.** The other L2s do real work that Ghost Pay isn't trying to do. We're trying to fit a specific niche (private retail payments, no operational burden, no federation), not declare a winner.

## Source

| File | Purpose |
|---|---|
| `bins/ghost-pay/src/` | Ghost Pay L2 implementation |
| `crates/ghost-zkp/src/` | The three ZK circuits — see [ZK proofs](#zk) |
| `crates/ghost-locks/src/` | The on-chain custody primitive — see [Locks](#locks) |
| `crates/ghost-reconciliation/src/` | L2 → L1 settlement — see [Reconciliation](#reconciliation) |

# Ghost Mode

*A node-level switch that stops your node from relaying, announcing, or serving any unconfirmed transaction. To peers, your mempool effectively doesn't exist.*

## The problem

Shroud delays *when* you relay; Ghost Mode decides *whether* you relay at all.

The difference matters because there's a class of attacks Shroud doesn't address. Several services let third parties query "is transaction X in your mempool?" — through `getrawmempool` over RPC, through INV-bait probes, or through getdata requests. If your node answers, an observer learns whether your wallet has authored or seen that transaction. Even with Shroud's relay-timing protection, a queryable mempool leaks plenty.

Bitcoin Core has `-blocksonly`, which is part of the answer but quite blunt — it disables transaction relay for ALL outbound connections and refuses inbound transaction announcements indiscriminately. Ghost Mode is the same idea integrated into ghost-core's runtime config, with a friendly toggle and the rest of the privacy stack designed around it.

## What it does

When `ghost_mode = true`:

1. **`RelayTransaction()` returns early.** Your node never sends transactions to any peer. The Shroud queue is bypassed (there's nothing to delay if you're not relaying).
2. **`getdata` requests for transactions are answered with "not found".** A peer asking "give me transaction X" sees `NOT_FOUND` regardless of whether X is in your mempool. The mempool stops being a public lookup table.
3. **No `INV` announcements for unconfirmed transactions.** Your node doesn't tell peers about new transactions it has seen.
4. **Block relay is unaffected.** You still receive, validate, and forward blocks. The chain still propagates through your node normally.

Net effect: your node validates the chain and serves blocks to peers, but to anyone watching transaction-level traffic, your node looks idle. They can't tell whether you're actively transacting, which transactions you've seen, or even whether you have a wallet.

## A small example

A wallet authoring a payment with Ghost Mode off:

```
Wallet creates tx ──► node accepts to mempool
                  ──► node sends INV to all 8 peers
                  ──► peers GETDATA back, node sends tx
                  ──► tx propagates through network
                  ──► observer running 100 listening nodes records
                      arrival times → triangulates origin → identifies
                      this node as the originator
```

Same wallet with Ghost Mode on:

```
Wallet creates tx ──► node accepts to mempool
                  ──► RelayTransaction() returns early — silently
                  ──► tx never leaves this node
                  ──► observer sees no activity
```

Of course the transaction needs to actually reach a miner, otherwise it never confirms. The wallet is responsible for routing it through some other path: a separate broadcasting node, an out-of-band relay over Tor, a paid broadcast service, or a private connection to a friendly mining pool. Ghost Mode is a *suppression* of the standard relay path, not a replacement transport.

## How it differs from Tor mode

`m_tor_mode` and `m_ghost_mode` are independent atomic flags in `net.cpp`. They solve different problems:

| Mode | What it does | What it doesn't |
|---|---|---|
| **Tor mode** (`m_tor_mode`) | Routes all P2P connections through Tor; suppresses clearnet address gossip | Doesn't change *what* your node says — it relays transactions normally, just over Tor |
| **Ghost mode** (`m_ghost_mode`) | Suppresses outbound transaction relay, INV announcements, and getdata responses | Doesn't change *where* connections go — peers can still be over clearnet |

The two compose. Running both gives you a node that's behind Tor AND silent about transactions — a deeply non-participating presence. Many privacy-focused operators run both.

There's also a small interaction: when Tor mode is on, the maximum Shroud delay is reduced from 5 s to 1 s. The reasoning is that Tor itself adds substantial timing obfuscation already, so the additional Shroud delay is partly redundant. With Ghost Mode on, Shroud doesn't run at all because there's nothing to relay.

## How it differs from `haze::GhostMode` (the storage enum)

The codebase has two unrelated things named "Ghost Mode":

- **`network.ghost_mode: bool`** — this doc. The transaction-relay suppression toggle.
- **`haze::GhostMode { HAZED, FULL_ARCHIVE }`** — an enum in `ghost-core/src/haze/exorcism.h` that selects whether the node strips block data before disk write. See [Exorcism](#exorcism).

The names collided historically. They're separate features with separate flags and don't interact.

## Configuration

Two layers, both off by default.

**ghost-core (transaction-level suppression):**

Set in `ghost.conf` or runtime via the `SetGhostMode()` accessor:

```ini
ghostmode=1
```

Or via the dashboard API:

```
GET  /api/v1/config/ghost_mode      → returns current state
POST /api/v1/config/ghost_mode      → toggle (admin auth required)
```

**ghost-mining (mesh forwarding):**

```toml
[network]
ghost_mode = false   # default
```

Note this is the network config field on the pool side, separate from ghost-core's flag. It's persisted in the node config file and re-applied on restart. The dashboard exposes it as a runtime toggle backed by an authenticated POST handler.

The two layers can be set independently. Most operators who want the privacy posture turn both on; the pool layer's toggle exists because pool-internal mesh forwarding has its own decision logic.

## What Ghost Mode protects against

| Threat | Protection |
|---|---|
| Mempool query services | **Strong.** A node in Ghost Mode answers `NOT_FOUND` to every transaction GETDATA. Querying tools can't tell what's in your mempool. |
| INV-bait probes | **Strong.** No outbound INV announcements means probes that watch for INV responses see nothing. |
| Transaction-origin triangulation | **Strong.** If you don't relay, observers can't time you. (Combine with another broadcast path for actually getting transactions confirmed.) |
| Determining whether you have a wallet | **Strong.** Your node's transaction-level behaviour is indistinguishable from a relay-only / blocks-only setup. |
| Compelled-disclosure / log seizure | **None.** A local mempool still exists in RAM. Anyone with access to the running process can see it. |
| Block-level traffic analysis | **None.** Block relay is unaffected; observers can still tell when you fetch and forward blocks. |

## What Ghost Mode doesn't do

- **It doesn't broadcast for you.** A wallet running on a Ghost Mode node has to find another route to reach miners — out-of-band relay, paid service, a separate broadcasting node. The trade-off is real: privacy in exchange for needing a non-default broadcast path.
- **It doesn't make your node invisible.** Peers can still see that you exist, your IP (unless Tor mode is also on), your block-level activity, and your version string. Ghost Mode is *transaction-level* silence, not full network invisibility.
- **It doesn't help if you operate a public mempool API.** Some node operators expose `getrawmempool` over an authenticated RPC; Ghost Mode doesn't change those endpoints — it only affects P2P-layer behaviour.
- **It doesn't replace Tor.** A Ghost Mode node connected over clearnet still leaks IP addresses to peers. If anonymity at the network layer matters, run Tor mode in addition.
- **It doesn't change consensus.** Validity rules are unchanged; Ghost Mode operates entirely at the gossip layer.

## Where Ghost Mode sits

| Layer | Primitive | What it suppresses / protects |
|---|---|---|
| Network identity | Tor mode | Your IP address from peers |
| **Transaction relay** | **Ghost Mode** | **Whether you relay/announce transactions at all** |
| Relay timing | [Shroud](#shroud) | When you relay (if you do) |
| Address linkability | [Keys](#keys) | Recipient address publication |
| Transaction-graph linkability | [Wraith](#wraith) | Input → output mapping in mixing |

A typical privacy-maximising operator stack:

- Tor mode → IP layer
- Ghost Mode → suppress outbound relay
- Wraith for entry into Ghost Pay
- Ghost Keys for receive-side addresses
- L1 broadcast happens through a separate path (Tor-routed RPC to a remote broadcasting node, or a broadcast service over .onion)

You can mix and match. Most users only need Shroud for the basic timing protection. Ghost Mode is for operators who want zero P2P-layer transaction footprint.

## Source

| File | Purpose |
|---|---|
| `ghost-core/src/net.h` | `GetGhostMode()` / `SetGhostMode()` accessors, `m_ghost_mode` atomic flag |
| `ghost-core/src/net.cpp` | Connection-manager state |
| `ghost-core/src/net_processing.cpp` | Early-return guards in `RelayTransaction()` and `ProcessGetData()` |
| `ghost-core/src/init.cpp` | CLI flag registration |
| `crates/ghost-common/src/config.rs` | `network.ghost_mode` config field |
| `crates/ghost-verification/src/routes.rs` | `/api/v1/config/ghost_mode` GET / POST handlers |

# Shroud

*A 0–5 second random delay added to outbound transaction relay so network observers can't identify a transaction's origin from "first seen" timing.*

## The problem

When a Bitcoin node accepts or creates a new transaction, it normally relays it to every connected peer immediately. A passive observer running monitoring nodes records *when* each transaction first appears at each vantage point. Whichever node relayed first is, with high probability, the origin — or one hop away.

This is how the most successful chain-analysis firms map wallets to network locations. Encrypting the transaction doesn't help: the Bitcoin protocol announces transactions in cleartext over P2P. Routing through Tor helps, but most users don't, and even Tor leaks timing if you're patient.

Shroud breaks the timing correlation directly.

## What it does

Every transaction the node would relay is held in a queue with a random delay between 0 and 5 seconds, then released. From an observer's perspective, your node looks the same as any other node along the propagation path — it relays a few seconds after first seeing the transaction, just like a peer two hops down.

Three things stay unchanged:

- The transaction enters your **local mempool immediately**. Mining is unaffected.
- Block templates include the transaction with zero delay. Your own miners never see stale work.
- Validity, fees, confirmation time — none of it shifts. Shroud is purely a relay-timing layer.

The only thing that changes is when peers find out. And by the time they do, several other nodes have already relayed it too, so the timing signal is gone.

## How it works

```
Without Shroud:
  Node receives tx ──→ Relay to all peers immediately
                        Observer sees: Node A relayed first → Node A is the origin

With Shroud:
  Node receives tx ──→ Add to mempool immediately
                   ──→ Queue relay with random 0–5 s delay
                   ──→ Relay when delay expires
                        Observer sees: many nodes relay near-simultaneously → origin unclear
```

Implementation lives in `ghost-core/src/net_processing.cpp` and is small enough to read in one sitting:

```cpp
struct ShroudEntry {
    Txid  txid;
    Wtxid wtxid;
    std::chrono::microseconds relay_at;   // wall-clock release time
};
std::vector<ShroudEntry> m_shroud_queue;
```

When a transaction would be relayed, `RelayTransaction()` instead computes a per-tx delay and queues it:

```cpp
auto delay = FastRandomContext().randrange<std::chrono::milliseconds>(
    std::chrono::milliseconds{5000});
```

`DrainShroudQueue()` runs every message-processing cycle and releases any entries whose `relay_at` has passed. The 0–5 s window is fixed in code, not configurable — the value was chosen to be longer than typical hop-to-hop propagation (~100 ms) but short enough that confirmation time isn't measurably affected. (Reduced to 1 s when Tor mode is enabled — see Ghost Mode.)

## A concrete observation

Imagine an observer running 50 well-connected listening nodes worldwide. Without Shroud, when you broadcast a transaction, the first ~5 of those nodes record arrival times within ~50 ms of one another, and the closest two hops back to you. Triangulation does the rest.

With Shroud, your transaction sits in your local queue for, say, 3.7 seconds. While it waits, a peer further along the propagation graph happens to broadcast a different transaction; both end up at the observer's nodes within milliseconds of each other. Now ten nodes look like plausible origins, not one. Run that across thousands of transactions and the observer's correlation rate drops from ~80% to under 10%.

The randomness matters: a fixed delay would be defeated by simply subtracting it from observed timestamps. The uniform 0–5 s distribution means each transaction's delay is independent.

## Configuration

Two layers, configured separately.

**ghost-core (transaction relay):**

| Flag | Default | Behaviour |
|---|---|---|
| `-shroud=1` | enabled | Random 0–5 s delay on outbound transaction relay |
| `-shroud=0` | — | Vanilla Bitcoin Core relay (immediate) |

Set in `ghost.conf`:

```ini
# Disable shroud (not recommended)
shroud=0
```

**ghost-mining (P2P mesh forwarding):**

```toml
[network]
shroud_enabled = false   # default — opt-in
```

Independent of the ghost-core flag — the pool's mesh has its own forwarding path, so the toggle exists separately. Most operators leave both on.

:::info Why is it on by default?
The cost of Shroud is at most 5 seconds of additional latency before peers learn about your transaction. The benefit is meaningful protection against the most common form of de-anonymisation. The asymmetry makes the default obvious.
:::

## What Shroud protects against

| Threat | Protection |
|---|---|
| Passive observer with one vantage point | **Strong** — they can no longer tell first-seen ordering apart from propagation-delay ordering |
| Multi-node observer (e.g. 50 listening nodes) | **Moderate** — single transactions are well-protected; aggregate analysis over thousands of transactions still leaks some signal |
| Global observer monitoring every link | **Weak** — but raises the cost of correlation significantly |
| Direct mempool inspection of your node | **None** — transaction is in the local mempool immediately; an observer who can query your mempool sees it before relay |

## What Shroud doesn't do

It's a network-layer privacy primitive, not a transaction-layer one. Specifically:

- **It doesn't hide participation.** Your node relays transactions; an observer can tell you're online and active. Shroud only obscures *which* transactions originated with you.
- **It doesn't encrypt anything.** Transaction contents (amounts, addresses, scripts) are still cleartext on the wire. Use Ghost Keys for address privacy and Wraith for transaction-graph privacy.
- **It doesn't help if your mempool is queryable.** Several services let you query "is transaction X in your mempool?" — Shroud can't help with that. **Ghost Mode** is the answer: it stops the node from accepting or advertising transactions to peers at all. The two are independent toggles and stack cleanly; Shroud handles relay timing, Ghost Mode handles whether the mempool is exposed in the first place.
- **It doesn't change confirmation time.** A 5-second delay before peers see a transaction is well below the time it takes for a miner to actually include it in a block.

## Where it sits

Shroud is one layer in Ghost's defence-in-depth privacy architecture. Each operates independently:

| Layer | Feature | Protects |
|---|---|---|
| Network | **Shroud** | Transaction origin timing |
| Address | Ghost Keys (BIP-352 v2) | Recipient address linkability |
| Transaction | Wraith | Input-output graph linkability |
| Payment | Ghost Pay L2 | On-chain transaction visibility |

You don't have to opt into all four. Enable what's appropriate for your threat model. Shroud is the cheapest of the four — it costs nothing and runs by default.

## Source

| File | Purpose |
|---|---|
| `ghost-core/src/net_processing.cpp` | Shroud queue + `DrainShroudQueue()` |
| `ghost-core/src/net_processing.h` | Option declaration |
| `ghost-core/src/init.cpp` | Argument registration |
| `ghost-core/src/node/peerman_args.cpp` | CLI parsing |

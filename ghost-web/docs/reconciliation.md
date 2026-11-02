# Reconciliation

*The L2's settlement layer. Periodically, accumulated L2 state changes — withdrawals, balance updates, fee allocations — get bundled into a single Bitcoin L1 transaction. Users exiting L2 get their satoshis on chain; users staying get their balances rolled forward into a new state commitment.*

## The problem

Ghost Pay is an L2 — fast, private, off-chain. But the moment users want their BTC on the base layer, they need an actual on-chain transaction. If every withdrawal triggered its own L1 transaction the L2 wouldn't be a meaningful layer at all — it would just be a slow batching wrapper around L1.

Reconciliation solves it the way most L2s do: batch many user actions into one L1 transaction at fixed intervals, amortise the on-chain cost across all participants, and use ZK proofs to keep the off-chain state verifiable from on-chain commitments.

## The epoch cycle

Time on Ghost Pay is divided into **epochs**, each 6 hours long. Within an epoch:

- Users transfer L2 balances freely (instant, off-chain).
- Wraith mixing sessions complete.
- Jump Lock rotations execute.
- Withdrawal requests queue for the next batch.

At the epoch boundary the system fires reconciliation:

```
Epoch N (6 h)        L2 transfers, mixing, withdrawal requests accumulate
       │
       ▼
Epoch N+1 boundary
       │
       │ Calculate net balance changes
       │ Batch withdrawal requests
       │ Build settlement transaction
       │ Sign + broadcast to L1
       ▼
Bitcoin confirmation (1–6 blocks per fee level)
       │
       ▼
Epoch N+1 begins
```

## Settlement classes

Not every withdrawal is urgent. Reconciliation offers three classes that trade speed for cost:

| Class | Batches every | Max wait | Fee multiplier |
|---|---|---|---|
| **Express** | 1 epoch (6 h) | 6 h | 1.5× |
| **Standard** | 4 epochs (24 h) | 24 h | 1.0× |
| **Economy** | 28 epochs (~7 d) | ~7 d | 0.5× |

**Why higher batch counts cost less:** the L1 transaction fee is split across all participants in the batch. An Economy batch — assembled across 28 epochs of accumulated withdrawals — divides the same on-chain cost across many more people than an Express batch fired every epoch.

The user picks the class when they request the withdrawal. Most withdrawals are Standard.

## The settlement transaction

A reconciliation transaction looks like:

```
Settlement TX
├── Inputs:
│   ├── L2 pool UTXO (previous epoch's state-commitment anchor)
│   └── Fee input (from L2 fee pool, covers L1 mining fee)
├── Outputs:
│   ├── Withdrawal #1: 0.50 BTC to Alice's L1 address
│   ├── Withdrawal #2: 0.10 BTC to Bob's L1 address
│   ├── Withdrawal #3: 1.20 BTC to Carol's L1 address
│   ├── ... (one per user exiting L2)
│   ├── Change output: remaining L2 balance — anchors next epoch's state
│   └── OP_RETURN: Merkle root of new L2 state commitment tree
└── Signatures: coordinator + participant threshold
```

Three things to notice:

1. **The new L2 state root is anchored on L1 via OP_RETURN.** That's the cryptographic chain link between L2 epochs. Every node tracking the L2 can re-verify the new state by checking the OP_RETURN against the ZK proofs that produced it.
2. **Withdrawals are individual outputs.** Each exiting user gets one P2WPKH/P2TR output to their L1 address. Standard Bitcoin from there.
3. **The change output continues the L2.** The pool's residual balance stays under L2 custody, ready to back the next epoch's state.

## Withdrawal flow (the user's view)

The standard exit ramp:

1. **User taps "withdraw" in their wallet** (Ghost Tap, Light Wallet CLI, etc.). Specify amount, paste an L1 destination address, choose settlement class.
2. **Wallet generates a `GhostUnshieldCircuit` proof locally** — the ZK circuit for L2-to-L1 exits. See [ZK Proofs](#zk) for the circuit details. The proof commits to: ownership of a specific note, the note's full value as the withdrawal amount, the note's nullifier (preventing double-withdrawal).
3. **Wallet submits the proof to** `POST /api/v1/confidential/unshield`. The request is queued for the next batch of the chosen class.
4. **Batch executes at the epoch boundary.** The user's L1 output is constructed; the proof's nullifier is committed to the new state.
5. **L1 confirmation arrives** within 1–6 blocks depending on fee level. Wallet shows the transaction confirmed.

**Constraints:**

- The unshield circuit only allows full-note withdrawal — no partial unshields. To withdraw 0.3 BTC out of a 1 BTC note, run a note-spend first to produce a 0.3 BTC note, then unshield that.
- Withdrawal must exceed dust threshold (546 sats) and cover the user's share of the L1 mining fee. Recommended minimum: 10 000 sats.
- The L1 destination is committed in the unshield proof's public inputs at submission time — it can't be changed after queueing.

## Roll-forward (the user's view)

If you're not withdrawing, reconciliation is invisible. Your L2 balance updates as you transact during the epoch; at the boundary the new state root is anchored to L1; you keep transacting in the next epoch with no on-chain footprint of your own.

This is most users most of the time. Reconciliation's L1 transaction lists only the people who actually exited; everyone staying in L2 is represented only by their share of the new state-commitment Merkle root.

```
Epoch N state
├── Alice:  1.0 BTC
├── Bob:    0.5 BTC
└── Carol:  0.3 BTC

L2 activity during Epoch N
├── Alice sends 0.2 BTC to Bob
└── Carol receives 0.1 BTC from a mixing session

Epoch N+1 state
├── Alice:  0.8 BTC
├── Bob:    0.7 BTC
└── Carol:  0.4 BTC
```

L1 footprint of this epoch (assuming nobody withdrew): one settlement transaction with one OP_RETURN containing the new state root. No per-user outputs.

## Settlement cadence

The settlement classes are encoded as a single enum in `ghost-common`:

```rust
pub enum SettlementClass {
    Express,    // every  1 epoch  (~6 h)   — 1.5× fee
    Standard,   // every  4 epochs (~24 h)  — 1.0× fee
    Economy,    // every 28 epochs (~7 d)   — 0.5× fee
}
```

A class "is due" at epoch *N* iff `N > 0 && N % epoch_multiplier == 0`. So Express fires every epoch, Standard every fourth, Economy every twenty-eighth — with progressively larger anonymity sets at the cost of longer wait. The user's withdrawal stays queued between fires; their unshield proof has already been verified, just the on-chain settlement waits.

**Idle lock handling** prevents the L2's anonymity set from degrading. If a meaningful share of locks haven't moved within a batch period, the system force-rotates them via Jump Lock rotation. Persistently-idle locks pay a fee penalty that goes into the L2 fee pool.

This sounds aggressive but it has a genuine reason: anonymity for active users depends on inactive users *not* sticking around as identifiable fingerprints. Forcing rotation costs nothing meaningful (Jump rotations are tiny) and keeps the privacy-set quality up.

## Fee distribution

The L2 fee pool collects fees from three sources:

| Source | Per |
|---|---|
| Reconciliation fee share | Each user in a batch |
| Wraith service fee | Each Wraith mixing session |
| L2 transfer fee | 10 sats per L2 transfer |

These accumulate during the epoch. At reconciliation, the pool is distributed:

```
L2 fee income (epoch total)
        │
        ├──► Ghost Pay node reward pool   (paid only to nodes with +4 GhostPay capability)
        │     ratio set by DECAY_SCHEDULE_BPS:
        │       pre-21-BTC threshold:  50% nodes / 50% treasury
        │       post-threshold:        60/40 → 70/30 → 80/20 → 90/10 → 100/0
        │
        └──► Treasury
              inverse of node ratio
```

The treasury threshold is 21 BTC (`TREASURY_THRESHOLD_SATS = 2_100_000_000`). Once the treasury accumulates 21 BTC, the split shifts in favour of nodes, eventually reaching 100% node / 0% treasury after the full decay schedule.

The decay is the same shape as L1 block-subsidy decay, just running on L2 fees rather than mining rewards. Both arrive at the same eventual state: 100% to the operators running the network.

## What reconciliation isn't

- **It isn't an interactive close.** Unlike Lightning channels, you don't need a counterparty to cooperate to exit. Submit your unshield proof; the next batch settles you regardless of what other users do.
- **It isn't a peg-out vote.** No federation, no committee, no signatures from N-of-M trustees. The settlement transaction is constructed from on-chain state + ZK proofs alone. Coordinator + participant signatures sign the L1 tx itself, not the validity of withdrawals.
- **It isn't gas-token-priced.** Fees are paid in BTC from the L2 fee pool. There's no separate fee currency. Users see the share of L1 mining fee they'll contribute before queueing the withdrawal.
- **It doesn't unbreak the chain link if Bitcoin reorgs.** A settlement transaction reorged out of an L1 block requires re-broadcasting; the L2 state for that batch effectively stalls until the L1 settlement re-confirms. In practice 6+ confirmations make this rare.

## What can go wrong

**A queued unshield proof is invalid.** The proof was already verified at submission time — `POST /api/v1/confidential/unshield` rejects bad proofs. By the time a request is in the batch queue, it's known-good. So this case essentially can't happen unless there's a bug in the verifier; one reason verifier code is small and audited heavily.

**Settlement tx fails to broadcast.** Network blip during broadcast — the coordinator retries. The settlement tx is signed and sealed before broadcast attempts; nothing changes about its contents on retry.

**Settlement tx confirms but reorgs out.** Possible if mining is highly contentious and a 1-block confirmation is taken as final. Mitigation: settlement classes default to waiting 6 confirmations before considering the batch finalized.

**A user's wallet goes offline mid-batch.** The user's unshield proof was submitted before the batch executed — they don't need to be online during settlement. They can come back, see the L1 transaction, and confirm receipt.

**The L2 fee pool runs dry.** If accumulated fees can't cover the L1 mining fee, the batch defers. In normal operation this doesn't happen because every L2 transfer pays a small fee that builds the pool. If it does, withdrawals queue until the pool covers the next batch.

## Where reconciliation fits in Ghost Pay

| Layer | What it does | Doc |
|---|---|---|
| L2 state | Off-chain transfers, balances, mixing | [Ghost Pay](#ghost-pay) |
| **Settlement** | **L2 state → L1 transaction at epoch boundary** | **this doc** |
| ZK exit | Unshield proof produces the L1 output | [ZK Proofs](#zk) |
| L1 anchor | OP_RETURN root commits the new L2 state | this doc |

## Source

| File | Purpose |
|---|---|
| `crates/ghost-reconciliation/src/executor.rs` | Epoch scheduler, batch execution |
| `crates/ghost-reconciliation/src/settlement.rs` | Per-class settlement coordination |
| `crates/ghost-reconciliation/src/batch.rs` | Settlement classes, idle-lock rules |
| `crates/ghost-reconciliation/src/commitment.rs` | New L2 state-root commitment |
| `crates/ghost-reconciliation/src/transaction.rs` | OP_RETURN-anchored settlement transaction build |
| `crates/ghost-reconciliation/src/fee_distribution.rs` | L2 fee pool distribution + decay schedule |
| `bins/ghost-pay/src/main.rs` | `POST /api/v1/confidential/unshield` handler + treasury wiring |

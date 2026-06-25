# Wraith

*A single-round, coordinator-blinded CoinJoin. Public Bitcoin UTXOs go in, mixed outputs come out in one atomic transaction, and no one — not even the protocol coordinator — knows which input maps to which output.*

## The problem

If you take a public BTC balance and just move it into Ghost Pay, the chain shows the link: address X spent N satoshis to your deposit UTXO. Anyone watching the chain can correlate. The privacy you get from Ghost Pay's L2 starts the moment you're inside; it doesn't apply to the deposit transaction itself.

CoinJoin is the standard fix — many users sign one transaction with many inputs and many equal-value outputs, breaking the input→output link. The basic weakness is the coordinator: if it can see which output belongs to which participant, it can deanonymise the whole round.

Wraith closes that gap with Schnorr blind signatures, so the coordinator validates that a participant is entitled to an output without ever seeing *which* output. One round is one transaction: N participants in, N equal-denomination outputs out, all in a single atomic broadcast.

## What Wraith does

```
One round = one transaction:

  inputs  (N, one per participant)   →   N × equal-denomination mixed outputs
                                          + per-participant change (where needed)
                                          + 1 service-fee output (Mix rounds only)
                                          + 1 OP_RETURN marker
```

Each participant contributes one input UTXO and receives one mixed output of the tier's fixed denomination. Anything above `denomination + fees` comes straight back as a change output in the same transaction, so a user never has to split a UTXO ahead of time.

The outputs are shuffled with a `ChaCha20` RNG seeded from the session ID plus fresh CSPRNG entropy, so once the transaction is built no one — not even the coordinator — can recover the input→mixed-output mapping from output ordering. The privacy guarantee covers the **mixed** outputs; change outputs go back to an address the participant controls and are linkable to that participant by design.

There is no second phase, no intermediate UTXOs, and no outputs-per-participant fan-out. The mixing happens once, atomically, in the transaction every participant signs.

## Tiers

A tier is a fixed mixed-output denomination. You pick the tier whose denomination you want your post-mix output to be; the rest of your input returns as change in the same transaction.

| Tier id | Denomination | Min participants | Max participants |
|---|---|---|---|
| `100k_sats` | 100 000 sats | 5 | 20 |
| `1m_sats` | 1 000 000 sats | 5 | 30 |
| `10m_sats` | 10 000 000 sats | 5 | 50 |
| `100m_sats` | 100 000 000 sats | 5 | 100 |

Every tier needs **5 participants minimum** before a round can broadcast — the same floor Whirlpool uses, well-tested for fill rate versus anonymity set. The per-tier maximum keeps the on-chain transaction comfortably inside Bitcoin's 100 KB standardness limit (the largest tier at full fill is roughly 14 KB).

Denominations are exact powers of ten, so a remix downgrade (one `1m_sats` output into ten `100k_sats` outputs) divides without remainder.

## Schnorr blind signatures

This is the protocol's core trick. The coordinator issues a one-use signing token to each authorised participant, but the blinding means it never sees the message it signed — and the message is the recipient address.

```
Step 1: Nonce
  Coordinator: k ←$- secp256k1, R = k·G          ← random per participant, bound to ghost_id
  Coordinator → Participant: R

Step 2: Blinding + challenge
  Participant: α, β ←$- secp256k1               ← random blinding factors
               R' = R + α·G + β·X                ← blinded nonce (X = coordinator pubkey)
               c  = H(X ‖ R' ‖ m)                ← BIP-340 challenge over the recipient address m
               c' = c + β                         ← blinded challenge
  Participant → Coordinator: c'

Step 3: Signing
  Coordinator: s = k + c'·x  (mod n)              ← x = coordinator secret
  Coordinator → Participant: s

Step 4: Unblinding
  Participant: s' = s + α
  Final token: (R', s') is a valid Schnorr signature on m
```

What the coordinator sees: a random blinded challenge `c'`. What the coordinator never sees: the message `m` (the recipient address), the blinded nonce `R'`, or the unblinded signature `(R', s')`.

When the participant later presents the mixed-output address with its unblinded token — over a separate, anonymised connection — the coordinator can verify the token is a valid signature from this session (so the address belongs in the round) but cannot tell *which* participant produced it. That is the unlinkability property.

The nonce is bound to the requesting participant's `ghost_id` and is single-use, so one participant cannot hijack another's nonce. Coordinator nonces expire after a configurable window (default one hour) and are rate-limited per participant to prevent memory-exhaustion attacks.

## Session lifecycle

A wallet calls `find_or_create(tier)`: the coordinator either returns an open session at that tier or spins up a new one. The session then walks a fixed state machine:

| State | What happens |
|---|---|
| **Filling** | Open for new participants. Stays open for the fill window (default 5 minutes) after the minimum is reached, up to the tier maximum. |
| **Locked** | The minimum was met and the round is full or the fill window expired. No new participants. The coordinator builds the round transaction. |
| **Signing** | The unsigned transaction is published; participants submit their input witnesses. |
| **Broadcasting** | All witnesses collected; the assembled transaction is broadcast to the network. |
| **Complete** | The transaction is on chain. |
| **Failed** | The round aborted (e.g. fill window expired without quorum, or a round-wide no-sign). |

If a session in Filling never reaches the 5-participant minimum by the time the fill window expires, it transitions to Failed and every escrowed bond is refunded. The coordinator runs as an active node with standby replicas that mirror its session registry via idempotent gossip events, so a coordinator failover doesn't lose in-flight rounds.

## Bonds, dropout, and refunds

Griefing is the failure mode that hurts a single-round CoinJoin: a participant fills a slot, lets the round assemble, then refuses to sign — wasting everyone else's time. Wraith deters this with a small bond rather than re-running the whole round.

At registration each participant escrows `bond_sats` — **0.5 % of the tier denomination** — into Ghost Pay's L2 ledger. The bond is held for the life of the round and resolved when the round closes:

| Outcome | Resolution |
|---|---|
| Round completed (transaction broadcast) | **Refund** — every participant's bond returns in full. |
| Participant withdrew during the open Filling window | **Refund** — changing your mind before commitment isn't griefing. |
| Round voided (≥ 80 % of a Locked round missed Signing) | **Refund** — a wholesale failure isn't any one participant's fault. |
| Coordinator aborted (malformed state, failover loss) | **Refund** — not the participant's fault. |
| Participant joined a Locked round but failed to sign in time | **Slash** — this is the actual griefing case. |

So the only way to lose a bond is to commit to a round (pass Filling) and then disappear during Signing. When that happens to *some* of a round's participants, the no-signers are slashed and the participants who did sign in time are refunded as a voided round; when it happens *wholesale*, everyone is refunded.

The bond lives in the L2 ledger behind a small abstraction, so the protocol crate never depends on Ghost Pay directly and tests can swap in a mock ledger.

## Fees

Two transparent components:

**Service fee** — a fixed 0.5 % of the denomination per participant, aggregated into a single output paid to the coordinator pool's fee address. Charged on Mix rounds only.

| Tier | Denomination | Service fee |
|---|---|---|
| `100k_sats` | 100 000 sats | 500 sats |
| `1m_sats` | 1 000 000 sats | 5 000 sats |
| `10m_sats` | 10 000 000 sats | 50 000 sats |
| `100m_sats` | 100 000 000 sats | 500 000 sats |

**Mining cost** — the Bitcoin transaction fee, split across participants. Each participant pre-pays a share computed against the tier's worst case (smallest round, default 10 sat/vB) so the round always covers its fee even if it broadcasts at the floor; larger rounds slightly overpay, which only makes the transaction more attractive to miners. The full mining surplus is collected directly from participant inputs.

Wallets show the service fee plus projected mining cost before the user commits to joining a round.

**Jump rounds** (`SessionType::Jump`) skip the service-fee output entirely — they pay only the mining cost. A Jump round is used to rotate the keys behind a balance through a CoinJoin without paying the privacy-mix premium.

## What Wraith protects against

| Attacker | Outcome |
|---|---|
| Passive chain observer | **Strong protection.** The mixed outputs are equal-denomination and shuffled; the input→mixed-output mapping isn't recoverable from the transaction. |
| Coordinator-on-the-side | **Strong protection.** Schnorr blind signatures mean the coordinator never sees which output it authorised, and the output shuffle is seeded with entropy it can't predict. |
| Sybil attack on the participant pool | **Moderate protection.** If an attacker controls most of a round's slots, the anonymity set shrinks to the honest minority. The bond requirement raises the cost of filling rounds with sybils, and on mainnet the bond is real L2 money — the dev/regtest auto-escrow mode is explicitly disabled in production. |
| Timing analysis (cross-session) | **Moderate protection.** Mixing immediately after receiving a public payment leaks correlation through timing. Best practice is to wait, vary timing, or chain rounds. |
| Amount correlation across rounds | **Strong protection when denominations match.** Equal-denomination outputs across separate rounds, held for a period longer than typical round times, are unlinkable. |

## What Wraith doesn't do

- **It doesn't hide the existence of mixing.** A transaction with many inputs and many equal-amount outputs is visibly a CoinJoin, and the `OP_RETURN` marker (`WL01` + session ID) tags it as Wraith specifically. Observers know mixing happened — they just can't tell which user mapped to which output.
- **It doesn't help if you spend the output non-privately afterwards.** A mixed output spent immediately to a known address re-correlates. Wraith protects the input→output linkage of one round; downstream privacy is the wallet's responsibility.
- **It doesn't work for arbitrary amounts.** Fixed denominations only — the four powers-of-ten tiers. A balance that doesn't land on a denomination is mixed at the largest tier it affords, with the remainder returned as change; the wallet handles the rest.
- **It isn't instant.** A round waits for at least 5 participants at the same tier and denomination. Common tiers fill fast; rarer high denominations may wait longer for enough peers.
- **It isn't free.** Service fee (Mix rounds) plus a mining-cost share. For the smallest tier the overhead is a fraction of a percent; for the largest it's effectively rounding error.

## Privacy stack context

| Layer | Primitive | What it protects |
|---|---|---|
| Receive | [Ghost Keys](#keys) | Address-to-identity linkability |
| **Mix** | **Wraith** | **Input-to-output graph linkability** |
| Hold | [Locks](#locks) | Custody primitive — recovery without revealing structure |
| Move | Ghost Pay L2 | On-chain transaction visibility |
| Relay | [Shroud](#shroud) | Transaction-origin timing |

Wraith is the layer that breaks the on-chain trail between your public Bitcoin and your Ghost Pay balance. Use it once on entry, once on exit, and your L1 footprint is two confirmed CoinJoin participations rather than a complete spending history.

## Source

| File | Purpose |
|---|---|
| `crates/wraith-protocol/src/single_round.rs` | Single-round transaction builder (`LiteRoundBuilder`) |
| `crates/wraith-protocol/src/lite_session.rs` | Session registry + lifecycle state machine |
| `crates/wraith-protocol/src/blind.rs` | Schnorr blind-signature primitives |
| `crates/wraith-protocol/src/tier.rs` | Tier denominations, participant caps, fee + bond rates |
| `crates/wraith-protocol/src/bond.rs` | Bond types + L2 escrow trait |
| `crates/wraith-protocol/src/coordinator_redundancy.rs` | Active/standby coordinator replication |
| `bins/wraith-coordinator/src/` | Coordinator service: round assembly, witness collection, broadcast |

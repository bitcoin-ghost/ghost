# ZK Proofs

*Three Groth16 zero-knowledge circuits underpin Ghost Pay. They prove that note spends, consolidations, and L2-to-L1 unshields are valid — without revealing amounts, recipients, or the spender's identity. Each proof is 192 bytes, verifies in milliseconds, and is generated locally on the sender's device.*

## What a ZK proof actually is here

A zero-knowledge proof lets you prove a statement is true without revealing anything beyond its truth. In Ghost Pay's specific case, the statements are about money:

- **"I own a note worth at least N satoshis"** — without revealing N, the note's commitment, or your identity.
- **"This batch settlement updates the L2 state correctly"** — without revealing the individual transactions inside.
- **"This withdrawal is authorised by a real note"** — without revealing which note.

The proof is a 192-byte blob. Anyone can verify it in about 5 ms with the public verifying key. The verifier learns *only* that the statement is true — no amounts, no addresses, no link to other transactions.

## The system: Groth16

Ghost Pay uses **Groth16** SNARKs. The properties that make Groth16 the right choice for the L2:

| Property | Value | Why it matters |
|---|---|---|
| Proof size | 192 bytes (constant) | Independent of computation complexity. Settlement batches stay small. |
| Verification | ~5 ms | Validators verify cheaply; a node running on commodity hardware checks thousands per second. |
| Proving | ~170 ms (note-spend) | Sender-side; happens once on the user's device per transaction. |
| Hash function | MiMC (82 rounds) | Constraint-system-friendly; ≥128-bit security. |
| Trusted setup | Rolling MPC, up to 101 contributors | See [MPC Ceremony](#mpc) — 1-of-N honesty assumption. |
| Track record | Used in Zcash, Filecoin, Aleo | Battle-tested in production for years. |

Groth16 has a known cost — the trusted setup. Ghost handles that with its rolling MPC ceremony where 101 participants each contribute fresh randomness; the parameters are sound as long as any one of them honestly destroyed their toxic waste.

## The three circuits

Each circuit proves one specific class of statement. They're independent — separate parameter files, separate proving keys, separate verifying keys.

### 1. GhostNoteSpendCircuit

The most-used circuit. Proves a sender owns a shielded note and is correctly transferring some of its value to a recipient (with the rest going back as change to themselves).

```rust
pub struct GhostNoteSpendCircuit<F: PrimeField> {
    // Private inputs (witness — never revealed)
    pub note_value:           Option<u64>,      // value of note being spent
    pub spending_key:         Option<F>,        // proves ownership
    pub note_blinding:        Option<F>,        // commitment blinding factor
    pub note_index:           Option<u64>,      // position in commitment tree
    pub epoch:                Option<u64>,      // epoch of note creation
    pub amount:               Option<u64>,      // transfer amount
    pub change_blinding:      Option<F>,        // for the change note
    pub recipient_blinding:   Option<F>,        // for the recipient note
    pub merkle_siblings:      Vec<Option<F>>,   // 20 sibling hashes for inclusion
    pub commitment_root:      Option<F>,        // tree root at spend time
}
```

(Recipients are addressed by the [Keys](#keys) layer's ECDH stealth-derivation, not by a pubkey field inside the spend circuit.)

The circuit enforces several thousand constraints (the test suite bounds the count between 5 000 and 20 000 at depth 20) proving:

1. The spent note's commitment is correctly formed (MiMC Pedersen).
2. The note ID incorporates its index, epoch, and commitment.
3. The nullifier is derived from the spending key (proves ownership).
4. The note exists in the commitment tree (Merkle inclusion at depth 20).
5. **Balance conservation:** `change = note_value − amount − fee`, where `fee` is the fixed 10-satoshi L2 transfer fee (`L2_TRANSFER_FEE_SATS`).
6. The change and recipient commitments are correctly formed.
7. **Range proofs:** `amount ∈ [0, 2⁶⁴)` and `change ∈ [0, 2⁶⁴)` (`BALANCE_BITS = 64`; no negative-amount tricks).

**Public inputs (what the verifier sees):**

- `commitment_root` — Merkle root of the L2's commitment tree at the time of spend.
- `nullifier` — derived from the spent note; prevents double-spend, deterministically.
- `change_commitment` — the sender's new note (remaining balance).
- `recipient_commitment` — the recipient's new note (the transferred amount).

The verifier learns *that* a valid spend happened, *that* it preserved balance, and *that* the spent note hasn't been spent before — but learns nothing about the amount, the parties, or which note in the tree was spent.

### 2. NoteConsolidateCircuit

Wallets accumulate small notes over time (especially after Wraith mixing produces fresh-denomination outputs). This circuit merges up to 4 notes into a single note of equal total value, keeping the commitment tree compact and reducing per-spend proving cost.

Same structure as note-spend, but simpler:

```rust
pub struct NoteConsolidateCircuit<F: PrimeField> {
    // Public inputs
    pub commitment_root:  Option<F>,
    pub nullifiers:       Vec<Option<F>>,        // 4 nullifiers (one per input slot)
    pub output_commitment: Option<F>,            // public: the merged output

    // Per-input private data (4-vector; unused slots have is_real=false + zero values)
    pub is_real:          Vec<Option<bool>>,
    pub spending_keys:    Vec<Option<F>>,        // must match across all real inputs
    pub note_values:      Vec<Option<u64>>,
    pub note_blindings:   Vec<Option<F>>,
    pub note_indices:     Vec<Option<u64>>,
    pub epochs:           Vec<Option<u64>>,
    pub merkle_siblings:  Vec<Vec<Option<F>>>,   // one path per input

    // Output private data
    pub output_blinding:  Option<F>,
}
```

Several thousand constraints (the test suite bounds the count between 5 000 and 50 000 for a four-input tree at depth 20), proving:

1. Each input note's commitment is well-formed.
2. Each nullifier matches its spending key (no spending notes you don't own).
3. Each input note exists in the tree (Merkle inclusion).
4. **Sum preservation:** `output_value = Σ input_values`.
5. The output commitment is well-formed.
6. Range proofs on every input/output.

**Public input:** `output_commitment` (alongside the commitment root and four nullifiers exposed via the standard public-input layout).

API: `POST /api/v1/confidential/consolidate`. Required field: `encrypted_output` (encrypted note payload, ≥218 hex chars / 109 bytes).

### 3. GhostUnshieldCircuit

The exit ramp from L2 to L1. Proves ownership of a note and burns its entire value to release the underlying BTC.

Simpler than note-spend — no change, no recipient commitment, the whole note is being consumed:

A few thousand constraints (the test suite bounds the count between 2 000 and 15 000 at depth 20), proving:

1. The note's commitment is well-formed.
2. The nullifier matches the spending key.
3. The note is in the commitment tree (Merkle inclusion).
4. **Full-value withdrawal:** `withdrawal_amount = note_value` (no partial unshields).

**Public inputs:**

- `commitment_root` — tree root.
- `nullifier` — prevents double-withdrawal.
- `withdrawal_amount` — verified inside the circuit to equal the note's value.

API: `POST /api/v1/confidential/unshield`. The amount is public so the L1 settlement transaction can pay out the right number of satoshis to the user's L1 address.

## A worked spend

Alice has a 1 BTC shielded note from a previous Wraith session. She wants to send 0.3 BTC to Bob and keep 0.7 BTC.

**On Alice's device** (Ghost Tap or light wallet):

```
Witness (private):
  note_value           = 100_000_000      sats (1 BTC)
  spending_key         = 0x4f2c…          (Alice's key for this note)
  amount               = 30_000_000       sats (0.3 BTC)
  change_blinding      = 0xb3e7…          (fresh)
  recipient_blinding   = 0x91fd…          (fresh)
  merkle_siblings      = [20 sibling hashes from tree at depth 20]

Public output:
  commitment_root      = 0x2c39…
  nullifier            = sha(spending_key ‖ note_index ‖ epoch)
  change_commitment    = MiMC(70_000_000 ‖ change_blinding)
  recipient_commitment = MiMC(30_000_000 ‖ recipient_blinding)

Proving time: ~170 ms on Alice's phone.
Proof size:   192 bytes.
```

Alice broadcasts `(public inputs, proof)` to a Ghost Pay validator at `POST /api/v1/confidential/transfer`. The validator:

1. Verifies the 192-byte proof against the verifying key — ~5 ms.
2. Checks `commitment_root` matches the current tree state.
3. Records the nullifier in its set (now spent — can never be spent again).
4. Adds the two new commitments (`change_commitment`, `recipient_commitment`) to the tree.

Validator learns: a valid spend happened. Nullifier X is now spent. Two new commitments exist. The balance was preserved. Nothing about Alice, Bob, or the 0.3-vs-0.7 split.

Bob's wallet, scanning the L2: derives an expected commitment using his scan key and the stealth-address hint published alongside the transfer, finds the match, and now knows he received a note worth 0.3 BTC. Only Bob can compute that match.

## Trusted setup

Groth16 requires per-circuit setup. Each Ghost circuit gets its own MPC slot:

| Slot | Circuit | VK file |
|---|---|---|
| 1 | GhostNoteSpendCircuit (depth=20) | `note_spend_vk.bin` |
| 2 | NoteConsolidateCircuit (depth=20) | `payout_vk.bin` |
| 3 | GhostUnshieldCircuit (depth=20) | `unshield_vk.bin` |

The full ceremony details live in [MPC Ceremony](#mpc). Short version: 101 contributors per circuit, each adding fresh randomness on top of the previous parameters; sound as long as any one of them honestly destroyed their toxic waste; ossified after contribution 101 and frozen forever. The verifying keys (`*_vk.bin`) ship in node releases — every node verifies proofs against the same VK.

## What ZK proofs in Ghost Pay don't do

- **Don't hide the existence of a transaction.** A spend produces a public nullifier and two public commitments. Observers see "a transaction happened" and can count L2 throughput; they just can't tell who or how much.
- **Don't replace network privacy.** A user broadcasting many proofs from the same IP is correlatable at the network layer regardless of how strong the cryptography is. Use [Ghost Mode](#ghost-mode), Tor, or both.
- **Don't make timing attacks impossible.** Proving time and validator response latency leak some bits. Real privacy work happens at the protocol design layer, not just in the math.
- **Don't protect the sender's spend key.** The proof is generated using `spending_key`. If the spending key is compromised, all notes derivable from it can be spent by the attacker. ZK adds privacy, not new key custody — that lives in [Locks](#locks).
- **Don't allow partial unshields.** The unshield circuit constrains the withdrawal to the full note value. To unshield 0.5 BTC out of a 1 BTC note, first run a note-spend that produces a 0.5 BTC note, then unshield that. The two-step is intentional: it keeps the unshield circuit small and prevents amount-disclosure attacks during partial exits.
- **Don't perform amount accounting at L1.** L1 sees only the unshield's `withdrawal_amount` public input — not the L2 internal flows. The L2's commitment tree is the source of truth for who holds what; L1 only sees the entry (Wraith mixing into Ghost Locks) and the exit (unshield).

## Where ZK fits in the privacy stack

| Layer | Primitive | Hides |
|---|---|---|
| Network | [Ghost Mode](#ghost-mode), Tor | Origin IP, mempool exposure |
| Relay timing | [Shroud](#shroud) | When you broadcast |
| Address | [Keys](#keys) | Who you're paying / who's paying you |
| Transaction graph | [Wraith](#wraith) | Input → output mapping |
| **Amount + ownership** | **ZK proofs** | **What's being spent, by whom, how much** |
| Custody | [Locks](#locks) | Recovery path on L1 |

ZK is the cryptographic core of Ghost Pay's privacy. Everything else in the stack handles a different leak vector; ZK is what hides the actual money.

## Source

| File | Purpose |
|---|---|
| `crates/ghost-zkp/src/circuit/note_spend.rs` | `GhostNoteSpendCircuit` |
| `crates/ghost-zkp/src/circuit/note_consolidate.rs` | `NoteConsolidateCircuit` |
| `crates/ghost-zkp/src/circuit/unshield.rs` | `GhostUnshieldCircuit` |
| `crates/ghost-zkp/src/prover.rs` | Proof generation (sender-side) |
| `crates/ghost-zkp/src/verifier.rs` | Proof verification (validator-side) |
| `crates/ghost-zkp/src/circuit/mimc.rs` | MiMC hash (constraint-friendly) |
| `crates/ghost-zkp/src/circuit/commitment.rs` | Pedersen commitments |
| `bins/ghost-pay/src/main.rs` | HTTP endpoints (`transfer`, `consolidate`, `unshield`, `shield`) |

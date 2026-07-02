# MPC Ceremony

*Ghost's three Groth16 ZK circuits each need a trusted setup. Rather than running one ceremony at launch with a fixed list of attendees, Ghost runs a rolling MPC where the first 101 nodes to contribute become Elders, and the parameters chain forward through every contribution. Only one honest contributor is needed for the parameters to be sound.*

## The problem

Groth16 — the zero-knowledge proof system Ghost Pay uses for note spending, payout consolidation, and L2 unshielding — is small, fast, and one of the most production-tested SNARK systems. The cost is a *trusted setup*: a one-time procedure that generates the proving and verifying keys, during which secret randomness ("toxic waste") is created and must be destroyed. If the toxic waste leaks, an attacker can mint forged proofs forever.

The traditional fix is a *Powers of Tau ceremony*: a fixed group of well-known parties takes turns contributing randomness, each shredding their toxic waste, and the parameters are sound as long as **at least one** participant was honest. This works, but it's an event — scheduled, finite, dependent on knowing in advance who will participate.

Ghost can't pre-announce a participant list. The network is open; anyone running a node could plausibly be a contributor. The ceremony has to be *rolling* — open to whoever shows up, in the order they show up — while still preserving the 1-of-N honesty assumption.

That's what the Ghost MPC ceremony is.

## How it works

Three independent Groth16 circuits, three independent ceremonies, all running the same protocol:

| Slot | Circuit | What it proves | VK file |
|---|---|---|---|
| 1 | `GhostNoteSpendCircuit` (depth=20) | A shielded note is unspent and the spender is authorised | `note_spend_vk.bin` |
| 2 | `NoteConsolidateCircuit` (depth=20) | N notes can be merged into one without revealing amounts | `payout_vk.bin` |
| 3 | `GhostUnshieldCircuit` (depth=20) | A note is being legitimately exited from L2 to L1 | `unshield_vk.bin` |

Each ceremony admits up to **101 contributions**. After contribution 101, the parameters **ossify** — no more contributions accepted, parameters frozen forever.

```
Genesis (position 1)         auto-approved on the genesis node
Position 2  ── BFT vote ──►  contribution #1's randomness applied to genesis params
Position 3  ── BFT vote ──►  contribution #2's randomness applied to position 2 params
…
Position 101 ── BFT vote ──► final contribution → params OSSIFY permanently
```

Each contribution is a fresh injection of randomness on top of the previous parameters. The chain is hash-linked: a `MpcContributionMessage` includes the previous params hash and the new params hash, so the sequence is verifiable from genesis to ossification.

## Soundness: the 1-of-N argument

Each contributor generates a fresh secret (`tau`, `alpha`, `beta` — the standard Groth16 toxic waste). They transform the existing parameters with their secret, then destroy the secret.

The parameters are sound iff **at least one** contributor's destruction was real. If 100 of 101 contributors retained their toxic waste, the 1 honest contributor's destruction still makes forging proofs impossible.

This is exactly the property a fixed Powers of Tau ceremony delivers, but with rolling open participation. The set of "who would have to collude" includes the genesis-node operator and 100 randomly-arriving Elders. Achieving full collusion would require all 101 to retain their secrets and coordinate.

## Why exactly 101

Two reasons:

1. **It matches the Elder cap.** Ghost's first 101 nodes are the Elders, who hold the +1 elder share in the 5-4-3-2-1 capability stack. The MPC ceremony rides on the same bootstrap event — every Elder is also an MPC contributor, and every MPC contributor (after genesis) became one by being among the first 101 nodes online.
2. **It's a prime number, finite ceremony, big enough anonymity set.** 101 unique participants make the 1-of-N collusion bound very strong. Anything substantially larger (e.g. 1001) starts to make the parameters file enormous and the verification time worse without meaningful security gains.

## Contribution flow

### Position 1: genesis

```
ghost-pool --genesis
```

The genesis node generates fresh trusted-setup parameters from scratch (the so-called "Powers of Tau" prelude) and auto-approves its own contribution locally. There's no BFT vote because there are no other contributors yet.

**Critical operational rule:** exactly ONE node in the network must run with `--genesis`. If multiple nodes do, they each independently generate different genesis parameters, each tries to claim position 1, and the network ends up with `UNIQUE constraint failed: mpc_contributions.position` errors. Recovery requires `DELETE FROM mpc_contributions; rm -rf mpc_params/` on every node and a clean restart from one designated genesis.

### Positions 2–101: BFT-voted

Each subsequent contribution follows this dance:

```
Candidate node:
   1. Wait 15 s after startup; check if ceremony is open + has slots.
   2. Sync existing contributors via /api/v1/mpc/contributors.
   3. Apply fresh randomness to the current parameters → new params.
   4. Generate Schnorr proof-of-knowledge for the (tau, alpha, beta) randomness.
   5. Build MpcContributionMessage including:
        - candidate node_id (Ed25519 pubkey)
        - prev_params_hash (the chain link)
        - new_params_hash (after this contribution)
        - contribution_proof (Schnorr PoK)
        - Ed25519 signature
   6. Broadcast over the Noise-encrypted P2P mesh.

Existing contributors (current Elders), upon receipt:
   1. Verify the candidate's Ed25519 signature.
   2. Verify prev_params_hash matches the current network params.
   3. Verify the Schnorr PoK.
   4. Cast MpcVerificationVote (approve / reject + reason).

When the approval threshold is met:
   - Contribution is applied; the candidate is admitted.
   - New params hash becomes the network's current.
   - Candidate's position is permanent.
```

The approval threshold is a **67 % supermajority of existing contributors**, with a small bootstrap exception: while there are fewer than four contributors (the earliest positions), the threshold floor is one — the genesis node alone can admit the first couple of contributions so the ceremony can get off the ground. From the fourth contributor onward the full `ceil(count × 67 / 100)` supermajority applies.

Only existing MPC contributors can vote on new ones. Non-Elder nodes observe but don't have a vote.

### Joining mid-ceremony (catch-up)

Because the ceremony is rolling, a node can come online at position 30 — or reconnect after days offline — and must trust a chain that was built without it. It does this by **genesis-anchored verification**, not by trusting whoever it synced from:

1. Fetch the full contribution chain and the retained BFT quorum votes from peers (large params transfer in hash-verified chunks).
2. Check the positions are a contiguous `1..=N`.
3. Check position 1's `prev_params_hash` equals the genesis anchor (the genesis params hash, which doubles as the immutable ceremony ID).
4. Check every link: each position's `prev_params_hash` equals the previous position's `new_params_hash`.
5. Check the params on disk hash to the head of the chain.
6. Check each position retained a valid supermajority of signed approval votes.

Catch-up verification runs the same cryptographic checks as live verification but skips the timestamp-freshness window, so a node re-verifying old, already-approved contributions doesn't reject them for being stale. Any mismatch is fail-closed — the node refuses the chain rather than adopt an unverifiable one.

## Toxic waste handling

The defining security claim of MPC is that toxic waste was destroyed. Ghost's contribution code goes to some lengths to make sure a contributor's secrets don't survive their own process:

```rust
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct ToxicWaste {
    tau_bytes:   [u8; 32],
    alpha_bytes: [u8; 32],
    beta_bytes:  [u8; 32],
    // …
}
```

The `ZeroizeOnDrop` derive emits a `Drop` implementation that calls `zeroize()` on every field — volatile writes the compiler cannot elide. No manual `Drop` body and no manual `compiler_fence` are needed; the `zeroize` crate handles the barriers.

In addition:

- Toxic waste is **never written to disk**. It exists only on the stack of the contribution function.
- Each contribution generates **fresh values**. Even on the same node, contributions to slots 1, 2, and 3 use independent secrets.
- Volatile zeroize prevents an aggressive compiler from eliding the wipe as "dead code". The memory barrier prevents reordering that would leave secrets in registers after Drop.

A motivated attacker with kernel access could still potentially extract values from RAM during the few microseconds they exist. Defending against that is outside the protocol's threat model — the assumption is that node operators run trustworthy hardware, and the 1-of-N soundness gives users protection even if some contributors are compromised.

## Parameter files

Each ceremony's contributions chain on disk:

```
~/.ghost/mpc_params/
├── note_spend_params_v0.bin             genesis
├── note_spend_params_v1.bin             after contribution 2
├── …
├── note_spend_params_v100.bin           after contribution 101 (ossified)
├── note_spend_params_current.bin        symlink to latest
├── payout_params_v*.bin                 same shape for slot 2
├── unshield_params_v*.bin               same shape for slot 3
├── note_spend_vk.bin                    final verifying key
├── payout_vk.bin
└── unshield_vk.bin
```

The historical sequence is preserved deliberately: any auditor can re-verify the entire chain from genesis to ossification by replaying contributions and checking each `prev_params_hash → new_params_hash` link.

Verifying keys (`*_vk.bin`) are extracted from the final ossified params and used by every node for proof verification. They're tiny (~kilobytes) and ship in node releases — no need to download the full Powers of Tau-style params unless you're verifying the ceremony itself.

## Ossification

After the 101st contribution to a circuit:

- That circuit's params hash is locked.
- No new contributions accepted on that circuit.
- The verifying key extracted from the final params is what every node uses to validate Ghost Pay shielded transactions forever.
- Elder positions for that ceremony are frozen — no new Elders can join via that circuit.

The three circuits ossify independently. On mainnet the ceremonies are **still rolling** — none of the three circuits has reached position 101 yet. Contributions accrue as new operators onboard, so the ceremonies sit in their early positions and grow toward the cap. Until a circuit ossifies, every node runs against the *current* (latest) params for that circuit (`*_params_current.bin`), and the versioned chain on disk records each position reached so far. The live position is a runtime value — `SELECT contribution_count FROM mpc_ceremony` on any node — not a compiled-in constant.

## What goes wrong if the MPC fails

Two failure modes are worth distinguishing:

1. **Soundness failure (toxic-waste collusion).** All 101 contributors retained their secrets and colluded. With those secrets, an attacker can forge ZK proofs — they could mint shielded notes from nothing, double-spend, or unshield without holding the underlying L2 state. Detection: a successful forged proof produces L2 state inconsistencies that other nodes' Merkle commitments would catch within a settlement batch. Recovery: emergency mainnet halt + ceremony restart with new participants.

2. **Liveness failure (no contributors arrive).** The genesis node generates valid params; nobody else contributes. The chain is sound (the 1-of-N argument trivially holds with only one contributor) but the anonymity set of "who could have created this honest setup" is one. This is a privacy concern, not a soundness concern — and it's mitigated as more contributors join.

In practice, Ghost's mainnet ceremonies are still rolling — they are in their early positions and have not ossified. Each is sound today (the 1-of-N argument holds at every position from genesis onward); the anonymity set of honest contributors simply grows with each new Elder until the chain reaches 101 and freezes.

## Why this matters

The single most common critique of any SNARK-based system is "but the trusted setup". Ghost's rolling MPC turns that critique into a much narrower question: did at least one of the 101 contributors honestly destroy their toxic waste?

The answer is yes if any one of:

- The genesis-node operator is honest, OR
- Any one of the 100 contributing Elders is honest

…destroyed their secrets. The setup is sound by induction over honesty.

That's a substantially weaker trust assumption than "one specific party at one specific moment didn't lie", which is what a single-party trusted setup demands. It's also weaker than the assumption made by most production SNARK systems' setups, which usually have ~10 parties.

## What MPC isn't

- **Not a recurring ritual.** Once 101 contributions are in, the ceremony is over forever. No re-runs, no parameter rotation, no scheduled refresh. The trusted setup is a one-time event whose finality is part of the design.
- **Not an Elder-vote rubber stamp.** Existing Elders' BFT vote on new contributions verifies the cryptography (signatures, PoK, hash chain), not the candidate's identity. The vote is "this contribution is well-formed and chains properly", not "this person is trustworthy".
- **Not the same as the Elder revocation system.** An Elder who goes offline >7 days loses their +1 share, but their *ceremony contribution* stays in the chain — that randomness was already mixed into the params and can't be removed. Loss of Elder status is an economic / reward event, not a cryptographic one.
- **Not Bitcoin consensus-altering.** The ceremony produces parameters used only by Ghost Pay's L2 ZK proofs. L1 Bitcoin validity is unchanged.

## Source

| File | Purpose |
|---|---|
| `crates/ghost-mpc/src/manager.rs` | `CeremonyManager`, contribution flow |
| `crates/ghost-mpc/src/contribution.rs` | `MpcContributionMessage`, Schnorr PoK, `ToxicWaste` (`ZeroizeOnDrop`) |
| `crates/ghost-mpc/src/params.rs` | Param file layout, versioned chain |
| `crates/ghost-consensus/src/mpc_handler.rs` | Mesh broadcast + BFT verification voting |
| `crates/ghost-zkp/src/prover.rs` | Loads ossified params for proof generation |

Related: [Elder system](#elder-system) covers the +1 capability share that MPC contributors earn.

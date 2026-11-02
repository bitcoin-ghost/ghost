# Porting notes: W2.1 pure core and W2.5 relay

Readings chosen where the spec leaves a detail open. Each one follows the Python reference
(`refimpl_v3.py`) for the payout rule, or the simulator in the design folder
(`sims/combined/chain.py`, `sims/anchor-sim/sim_retarget2.py`/`sim_retarget3.py`) for the rest.
Code: `crates/ghost-common/src/{canonical_payout,share_commit,anchor_chain,node_pool_constants,node_pool_u256}.rs`.

## Payout (`canonical_payout.rs`)
- Balances are `i128` face units in memory. They may be negative, as in the reference (a retirement
  computed on another fork's table). `table_root` writes them as 32-byte two's complement, as the
  reference does. Storage format is W2.4's.
- `share_face` carries the product in 256 bits and returns an error, not a wrapped value, where the
  reference would assert. A face above `i128::MAX` is also an error.
- `build_outputs` refuses fewer than 2 slots. The reference never calls it with fewer, and at 1 slot
  its `[:L - 1]` slice would mean "all but the last".
- `cut(H)` returns `None` below height 20 instead of a negative height.
- The treasury script is the reference's placeholder, `TREASURY_SCRIPT_PLACEHOLDER`. It must be
  replaced by the user's address before any network uses it, and the golden vectors regenerated.

## Share tag and checks (`share_commit.rs`)
- Tag field encodings: `node_id` 32 bytes (the existing `NodeId`), `tier` 1 byte, `slot_class` as
  the miner-output count, `u16` little-endian (not a class index, so the provisional class table can
  change without changing what an existing tag means), the rest 32 bytes each. No length prefixes,
  since every field is fixed width.
- The tag goes in the existing `GHNT` 20-byte scriptSig push; `parent_anchor[..16]` goes in the
  `GHPP` 16-byte push. Every share's coinbase is checked for both, since any share can be a block.
- Rule 1 checks the hash against `max(T_net, committed tier)`, the tier the share is credited, so a
  share cannot commit a higher tier than it meets.
- Tier `t` target is `base >> t`, with `base` the difficulty-1 target `0xFFFF * 2^208`. `base` is a
  parameter, not a constant, because regtest cannot mine tier 10 at difficulty 1; see "Open" below.
- Rule 4 compares the whole output list: treasury, canonical miners, an optional finder (present
  only when non-zero, any script), `OP_RETURN "GHNP" || table_root`, and a witness commitment
  (`OP_RETURN aa21a9ed || 32 bytes`, required). The finder script is not class-limited: it retires
  nothing and adds one output.
- Rule 5's era guard reads the including anchor's era from `btc_height + 1`, its job height,
  because `btc_height` is the tip its job saw (simulator convention). Window: `H + 12 >= btc_height`.
- `prev_hash` being a real header, the bits, the median time past and the latest time are
  chain-dependent: the caller resolves them and passes them in.

## Anchor chain (`anchor_chain.rs`)
- Anchor work is `2^(T_net + 8)` for the tier the anchor was required to meet, not the work its
  actual hash shows. Ties go to the numerically lower hash (the hash read as a little-endian number).
- Retarget, from the simulator's final policy (`sim_retarget3.py`): per Bitcoin interval, count the
  anchors stamped with that `btc_height`. A 36-block non-overlapping window moves the tier by 1 when
  it reads more than 0.75 tiers off (the spec gives no band; 0.75 is the simulator's). Every 6
  blocks the fast path reads the last 6 and jumps by the rounded error when more than 3 tiers off
  (the spec says ">= 3"; with integer counts exactly 3 cannot occur, so the two agree). Any change
  clears the window. All of it is exact integer arithmetic; the test pins the simulator's float
  trace on a fixed sequence.
- The fast path runs at absolute Bitcoin heights `= 5 mod 6` (the simulator used its own block
  index). Counts per interval are capped at `2^20`, and `T_net` at 200, to keep the arithmetic
  bounded; neither binds in practice.
- The tier for a job on parent `P` at `btc_height` h is P's state carried through interval h - 1:
  intervals below h are final on P's ancestry because `btc_height` never decreases. Genesis counts
  as one anchor of its own interval.
- `S(H)` is the last anchor on the ancestry with `btc_height < cut(H)`, matching the reference's
  "credits of share height <= cut(H)" with job height `btc_height + 1`. None if there is none (the
  simulator fell back to genesis).
- Rule 6 follows the simulator's `check()`: `S(H)` from the including anchor's ancestry must be an
  ancestor of the share's parent, and the parent's own `S(H)` must be the same anchor. The parent
  may be on a dead fork. A share is a duplicate if it sits in a batch on the including anchor's
  ancestry above the including anchor itself.
- Batches: `attach_batch` refuses a share listed twice or already on the ancestry. Checking each
  share, and that the list matches the committed `batch_root`, belongs to the caller (W2.5).

## Relay (`crates/ghost-np-relay`, W2.5)
Readings chosen where the spec leaves a detail open. Each is a pure function of the including
anchor's ancestry, the share, and the Bitcoin headers, so every viewer reaches the same verdict.

- **`batch_root`** (`share_commit::batch_root`): `sha256("GhostBatch/v1" || n u32 LE || M)`, `M`
  the RFC 6962 merkle tree over the share ids (header hashes, internal byte order) in batch order;
  empty tree is 32 zero bytes. Python vectors in the test. `batch_proof` / `verify_batch_proof` give
  inclusion proofs for `ghost-audit` (W2.9).
- **`T_net` of a share** is the tier its own job required: its `parent_anchor`'s retarget state at
  `max(job btc height, parent btc_height)`. It does not depend on the includer, so a share earns the
  same credit on every fork that can include it. Credit tier is `max(T_net, committed tier)`.
- **An anchor's own share** is checked with the anchor as its includer: it must pay `S(H)` from the
  anchor's own ancestry, and its job height must be `btc_height + 1` (the header's `prev_hash`
  height; the message carries `btc_height` so the header can be placed before the batch arrives). A
  failure makes the anchor invalid. The share is credited only when a later anchor includes it.
- **Header time** has no upper bound for validity (`max_time = u32::MAX`): a bound on a local clock
  would let viewers disagree. Two hours ahead of the local clock is relay policy for loose shares.
- **Duplicates (K).** The duplicate check covers the whole including-anchor ancestry, as
  `AnchorChain` already does. That is the same as stopping at `S(H)`: a carrier at or below `S(H)`
  would have to commit to a share that commits (through its parent anchor) to `S(H)`, which commits
  to the carrier, a hash cycle. So the check is bounded by `S(H)`, about 32 Bitcoin blocks of
  anchors, and pruning below the snapshot cannot change it. `K = 120` is not used as a depth bound:
  a share of job height `H` may sit in a carrier stamped `H - 1` and be re-included by an anchor
  stamped `H + 12`, about 144 anchors later at target spacing, so a 120-anchor lookback would let it
  be credited twice. `REINCLUSION_DEPTH_K` stays defined and unused; the spec's K row should be
  read as "the duplicate check reaches back to `S(H)`".
- **Snapshot table for rule 4**: the genesis table, plus the credits of every batch on `S(H)`'s
  ancestry folded by job height through `table_for` (so job heights above `cut(H)` drop out), minus
  the retirements of blocks below `H` from the `Retirements` hook (W2.7; none until then).
- **Ledger events**: one credit event per `(anchor, job height)`, keyed
  `sha256("GhostNP/credit/v1" || anchor || H u32 LE)`, applied in chain order and job height
  ascending, undone in reverse on a reorg. Block events above them are undone and re-applied after
  the move. The payout table is `np_table_for_block` (a fold of the journals by height), not the
  materialised `np_ledger`, whose `queue_since` follows application order.
- **A share whose job saw an older Bitcoin tip than its parent anchor** is priced at the parent's
  height rather than refused.
- **Waiting is not invalid.** A share whose Bitcoin header or parent anchor this node lacks makes
  its batch wait (and the anchor or header is fetched); it never makes the anchor invalid.
- **Relay policy only, never validity**: anchors more than 6 Bitcoin blocks behind the local tip on
  receipt are kept but not relayed (correction 3); loose shares that fail rule 4, 5 or 6 against
  this node's view are dropped without penalty; a producer batches only shares still includable 2
  blocks ahead, ordered by job height then id (any order is valid: the root commits it).

## Open, not decided here
- **K = 120.** Resolved for the relay above: the duplicate check reaches back to `S(H)`. The spec's
  constants table still lists K; it should be reworded.
- **Regtest tier base.** At difficulty 1, `T_net` floor 10 needs about 2^42 hashes a share, out of
  reach on regtest. The PoW base is a parameter so Phase 3 can choose; `share_face` keeps the
  reference's difficulty-1 constant.
- **Treasury address**, from the user.

# Porting notes: W2.1 pure core

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

## Open, not decided here
- **K = 120.** The spec's constants table lists K, and the simulator's re-inclusion rule measured
  the 12-block window against the first anchor that carried a share, if within K anchors of the
  includer. Rule 5's text measures against the including anchor, and "first carrier on any fork"
  depends on what a node has seen. The code follows rule 5's text; `REINCLUSION_DEPTH_K` is defined
  and unused. Needs a decision before W2.5.
- **Regtest tier base.** At difficulty 1, `T_net` floor 10 needs about 2^42 hashes a share, out of
  reach on regtest. The PoW base is a parameter so Phase 3 can choose; `share_face` keeps the
  reference's difficulty-1 constant.
- **Treasury address**, from the user.

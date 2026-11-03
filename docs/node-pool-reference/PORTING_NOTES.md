# Porting notes: W2.1 pure core, W2.5 relay, W2.9 audit, W2.10 listing, W2.13 sync

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
  the retirements of blocks below `H` from the `Retirements` hook (settlement's `SettledView`).
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

## Coinbase (W2.6, pool_sv2 `node_pool.rs`)
- **The template** (ghost-mining's template provider) carries the whole coinbase value
  (`coinbase_tx_value_remaining` = subsidy + the kept transactions' fees) and the witness
  commitment as its only output. Its scriptSig prefix keeps the `GHPP` slot (zeros) and the plain
  `GHNT` tag, both replaced per job, so the scriptSig length is fixed before any job is built. A
  template of any other shape stops pool_sv2: it cannot carry a canonical coinbase.
- **A job's table** is the relay's for `(parent_anchor of the job's stamp, BIP34 height of the
  template)`, fetched over the relay task's request channel. The request is the new-tip event:
  pool_sv2 sends it the moment a template arrives, and the relay settles the Bitcoin tip (and
  moves its view of the tip) before answering; the relay's 5 s poll is only a backstop. In the
  first 20 blocks after genesis no anchor sits below the cut; the table is then the genesis
  table with settled retirements (`Relay::block_table`).
- **The stamp carries the anchor the table was fetched for** (`NodePool::prepare_job_basis`),
  never one published since. The Phase 3 harness found 3 of 80 blocks paying the whole subsidy
  to the treasury: an anchor published between the fetch and the stamp left the job without its
  table, so it was built on the empty one and every peer refused it.
- **No table within 2 s** (`TABLE_WAIT`, asked every 100 ms): the jobs build on the previous
  job anchor if its table at this height can be had (valid: a share is judged against its own
  parent's table; only its batch is older). Else the template is not served: no job is built from
  an empty or mismatched table, since every peer would refuse its shares and its block's
  retirements while its coinbase paid the subsidy to the treasury. Miners keep their current job;
  a new tip's `SetNewPrevHash` is held (`NODE_POOL_NO_TABLE`) and sent with fresh jobs once the
  table arrives (retried on every anchor publish and every 5 s); a channel opened meanwhile is
  refused with `node-pool-no-snapshot-table`. A sustained hold means the relay or its Bitcoin RPC
  is broken.
- **Work before genesis + 21 is void** (`canonical_payout::first_earning_height`): no anchor
  sits below `cut(H)` for `H <= genesis + 20`, so rule 6 fails every such share. Jobs are still
  served (miners need work, and a block found there is valid and pays the genesis table), and
  pool_sv2 logs `NODE_POOL_VOID_WORK` once per height; the relay neither relays nor anchors a
  local share there (`on_local_share`: "void"), so no node sees an anchor it must refuse. The
  status and miner APIs carry `earning` (`first_earning_height`, `job_height`, `earns`,
  `notice`), shown by the dashboard's health checks and the miner page. Mainnet's genesis anchor
  is set at least 20 blocks before launch (plan, Phase 4) so no live work is void.
- **Outputs**: `coinbase_outputs(H, table, slot_class, fee_script, value - subsidy(H),
  witness)` minus the witness output, which the channel factory appends from the template.
- **The finder** is `[node_pool] fee_address`, required to be one of the four payee classes
  (the spec does not say; share rule 4 accepts any finder script). Chosen so the finder never
  adds sigops or unbounded bytes.
- **Submit check is a post-submit alarm** (user decision, 11-02): a solved block is always sent to
  the template provider at once. Only then is its outputs digest compared with the one its job
  recorded; a mismatch is logged and nothing else. A valid Bitcoin block is worth more than any
  payout mismatch, and settlement on every other node, which retires nothing for a block that does
  not match, is the enforcement.
- **Standard channels and custom work**: standard channels carry the full class. Custom work is
  refused: a SetupConnection asking for work selection gets `unsupported-feature-flags` and
  `SetCustomMiningJob` gets `custom-jobs-not-supported`, so every job pays the canonical outputs.

## Settlement (W2.7, `ghost-np-relay/src/settlement.rs`)
- **Where**: in the relay task, over the relay's store; it is the relay's `Retirements` hook
  (`SettledView`), so every table a share is checked against and every job pays subtracts it.
- **The stored ledger follows the node's Bitcoin best chain**: settlement retires into `np_ledger`
  what pool blocks on this node's best chain paid, judged by the anchors it holds. Since W2.13 no
  table reads it: share checks and jobs use the deterministic rule below.
- **A pool block** has a `GHPP` tag and a `GHNP` second-to-last output. Its anchor is looked up
  by the 16-byte prefix among held anchors with their batch (or genesis). **Match**: the table
  `block_table(anchor, H)` has the root the block commits, and the outputs are canonical for some
  slot class (`share_commit::settle_outputs`; the class is inside the tag's hash, so every class
  is tried, and outputs canonical for any class retire exactly what they paid). **Mismatch**:
  anchor held, no match: nothing retired, though the chain paid it.
- **Provisional**: anchor not held. The miners are the run of outputs after the treasury that
  sums with it to the subsidy (`canonical_payout::provisional_retirements`); each retires its
  value. When the anchor arrives the block is checked: kept on a match (the retirements are
  identical, both are the paid outputs), undone on a mismatch. Undo of a block under later
  events rewinds and re-applies them (`np_undo_block_anywhere`).
- **Reorg**: the last 1,024 best-chain hashes are remembered; a changed hash undoes the settled
  block at that height. On start, every settled block is re-checked against the best chain, and
  one whose anchor is not held goes back to provisional. A sync scans at most 500 blocks.

## Sync, archive and checkpoints (W2.13)
Readings chosen where the spec was silent; written into spec 2.2, "Share-chain sync".

- **Deterministic retirements.** A table for a share of job height `H` on Bitcoin block `P`,
  included by `X`, subtracts the pool blocks on `P`'s ancestry above genesis and below `H` (the
  archive walk, `BtcArchive::pool_blocks_on`). A block retires its paid miner outputs
  (`provisional_retirements`) unless an anchor with its `GHPP` prefix is on `X`'s ancestry and
  none matches it, then nothing. "Held" is replaced by "on the includer's ancestry", which every
  viewer of `X` shares; a job's includer is the next anchor on its parent. A block's own match is
  `block_table_on(A, k, B.prev)`, recursive on lower heights and cached per (block, anchor). The
  tag in the table cache key digests the retirements, not a node view.
- **`block_table(parent, h)`** (pool_sv2's jobs, settlement) uses this node's best-chain block at
  `h - 1` as `prev`: the job's own `prev_hash`. `block_table_on` takes `prev` explicitly.
- **Archive.** Settlement archives every best-chain block it reads (`BlockSource::block`: header,
  height, coinbase without witness, merkle branch from the block's txids), and the 11 headers at
  genesis for median time past. Stale blocks stay. A wanted hash is read back from the local
  Bitcoin node (walking `prev` to an archived block, at most 2,016), then asked of peers. A peer
  block whose parent is missing waits in a pool of 256 while the parent is fetched from the same
  peer. Median time past is computed from the archived times; `next_bits` across a retarget
  boundary only from this node's best-chain child.
- **Headers.** `Headers` replies follow the server's best chain from the first locator hash on
  it. A reply whose first anchor's parent is unknown, or whose anchors do not chain, scores 20. A
  full reply (32) asks again from its last anchor. One header request is outstanding at a time;
  a peer is not re-asked within the request timeout (5 s) unless its last reply was full.
- **Share bodies** are checked against their header before they are kept (`share_integrity`):
  coinbase folds to the merkle root, scriptSig carries the preimage's tag and parent prefix.
  Before W2.13 a substituted body made an honest anchor invalid; now it scores 50 on its sender.
- **Checkpoints.** Fold height `F = btc_height(C) + 1` is the highest at which every includer
  descending from `C` folds the same prefix: no descendant's credit (job height at least
  `btc_height(C) - 12`) has `c + 20 <= F`, and a pool block below `F` was built on an anchor with
  `btc_height < btc_height(C)`, which is on a descendant's ancestry only if it is `C`'s ancestor.
  The fold's Bitcoin ancestry is `C`'s own `prev_hash`. Pool-block checks for heights `F..=F+20`
  are computed before the fold and carried, since their tables reach below `C`; one that arrives
  later counts what it paid. Depth below 40 is raised to 40.
- **Pruning** deletes stored batches below the older kept checkpoint (`np_prune_batches_below`).
  In memory, batches and credits at or below the newest checkpoint are dropped whether or not the
  store prunes; serving reads them back from the store.
- **Migration v64** holds `np_btc_blocks` and `np_checkpoints`; the plan's genesis-table
  import moves to v65.

## Network start (W2.8, pool_sv2 `node_pool_relay.rs`, `ghost_common::node_pool_network`)
- **The network** is `[node_pool.relay] network`; absent means mainnet, the strictest reading, so
  an unlabelled config cannot put a node on a configured genesis.
- **Mainnet** runs only on `MAINNET_START`, compiled in and unset. While unset, the installer's
  `UNSET` is refused by its existing message and a configured genesis by a second one. Once set,
  a configured genesis must equal it, and `tier_base` may not be set.
- **The genesis table digest** is the table's `table_root`, the same digest a block commits. A
  pinned digest is checked against the table the store holds (`np_genesis`, empty until the
  genesis import) before the relay is built on it.
- **Regtest** with `UNSET` uses its default anchor, and then refuses any height but 0.

## Ledger and status API (W2.11, pool_sv2 `node_pool_api.rs`)
- **Served by pool_sv2**, on the monitoring listener: it owns the store (root, 0600) and the live
  relay, settlement and channel state. ghost-mining's public routes forward to it.
- **Queue position** is on the table the next block pays (the relay's `block_table` for the
  current job anchor and the active template's height), ranked by `canonical_payout::
  queue_position`, which shares `select`'s orderings; what each slot class would pay is
  `paid_to`, i.e. `build_outputs`. The balance shown is the materialised ledger (credits to the
  tip), which is ahead of that table by up to 20 blocks of credits.
- **Genesis balances.** `np_ledger` holds only what the share chain changed and starts empty;
  settlement folds it onto the imported genesis table. So every balance the API shows (ledger,
  miner page, wait estimate, balance history) is the payee's `np_genesis` row with its applied
  credits and retirements folded on in applied order by `apply_credits`/`apply_block`
  (`Database::np_payee_balance`); `queue_since` needs that fold, since a carried-over balance
  can cross the floor with a credit the share chain's own row never would. Journalled
  `prior_owed` values get the genesis amount added (owed is additive). The ledger answer carries
  the carried-over row as `genesis`, the history opens with it at the export height
  (`carried_over`, not a credit) when the window reaches back to it, and `ledger_rows` counts
  payees in either table once.
- **Credited shares** are batch memberships whose credit event `(anchor, job height)` is applied,
  so a share in a losing anchor's batch is not listed.
- **Settled or provisional** is settlement's in-memory pending set; a restart re-derives it.

## Miner protection (W2.9, `bins/ghost-audit`, `ghost-np-relay/src/client.rs`)
- **Opening the tag needs the node.** A job's `GHNT` tag hashes `node_id`, tier, slot class, the
  payee, `parent_anchor` and `batch_root`. A miner sees the payee (its own), `parent_anchor[..16]`
  (`GHPP`), and can enumerate tier (256) and class (6), but `node_id` and `batch_root` are known
  only to the node. So pool_sv2's relay answers a new `GetStamps` (type 16) with `Stamps` (17):
  its `node_id` and the last 16 `JobAnchor`s it published, newest first (`NotFound` kind 4 from a
  relay with no pool). Stamps are self-authenticating: one that does not hash to the tag with the
  miner's script proves nothing, so asking the audited node trusts it for nothing. Rate 1/s,
  burst 10. A stamp is node-global (every channel is stamped from the same `AnchorDriver`), so
  disclosing it reveals nothing per miner; `batch_root` becomes public with the anchor anyway.
- **Share-chain data comes from the auditor's own relay node**, run as pool_sv2 runs one minus
  the pool (no listen, no `node_id`), syncing from `--relay-peer`s and settling from the miner's
  Bitcoin node over RPC. The table is `block_table_on(parent, H, prev)` for the job's own
  `prev_hash`: `TableRequest` gained `prev` (pool_sv2 passes `None`, unchanged); with `prev`, the
  answer is `None` unless `prev` is archived at `H - 1`. The audited node is never asked for a
  table. A Bitcoin node is required: a fresh archive has no base without one (see Open).
- **Genesis table**: the auditor's relay starts from the network's, read from the published
  export (`--genesis-export DIR --export-digest HEX`) by `ghost_common::node_pool_genesis_export`,
  the checks pool_sv2's import runs (moved there from pool_sv2 so the two cannot differ), and
  imported into the auditor's store on first use (later runs read the store). Its `table_root`
  must equal `--genesis-table-digest` (or mainnet's compiled pin), or `audit`, `probe` and `list`
  refuse to start; only regtest may run unpinned. A store that already holds another export's
  table, or has run on another table, is refused rather than mixed.
- **Height** is `height(prev_hash) + 1` from the miner's Bitcoin node, and the scriptSig must
  start with its BIP34 push.
- **Tier check**: a committed tier above `floor(log2(difficulty))` (with 1e-9 slack for a float
  printed just under its power of two) fails, except at the floor tier 10, which pool_sv2 commits
  for any difficulty below 1,024 and which `T_net >= 10` makes harmless.
- **Naming a failure** (`check::classify_outputs`), first match wins: no witness or `GHNP`
  commitment (malformed); first output not the treasury script (wrong treasury);
  canonical (pass); canonical for another class (wrong slot class); then, against the canonical
  miners for the committed class, with the last output read as the finder when its script is not
  owed: an unowed script carrying exactly a missing payee's amount (relabelled payee); any other
  unowed script, or an owed one paid more than canonical (inflated balance); treasury plus miners
  below the subsidy (fee skim); a dropped payee, a wrong treasury amount, rule order, a zero-value
  finder (outputs not canonical); everything right but the `GHNP` root (wrong ledger root).
- **Verdicts**: PASS, FAIL, UNCHECKED. UNCHECKED (prev_hash or parent anchor not held yet, or the
  relay port unreachable) is retried for `--wait` seconds and is never a pass. A tag that does
  not open is retried once with fresh stamps (the node may have re-stamped in between).
- **Prober verdict** (`ghost-audit/probe/v2`): `fail` if the relay is on another genesis or
  version, is not a relay, refuses stamps, a stratum port refuses the payee or speaks garbage,
  the SV2 port cannot prove its authority key (`sv2_authority_key`, `sv2_bad_authority_key`), or
  any job on either protocol fails (`job_<reason>`, `sv2_job_<reason>`); else `unmeasured` if
  anything could not be measured (relay or a stratum port unreachable, fewer jobs than asked, a
  job UNCHECKED, no stratum port at all: `no_stratum`); else `pass`. `listable` is
  `verdict == pass`. A failed advert skips the job checks. v2 (from v1): `node.stratum` may be
  null, and `node.sv2`, `node.sv2_authority_key`, `sv2`, `jobs_sv2` and the advert's ports and
  key were added. SV1 and SV2 are probed at once; `--jobs` counts per protocol (on SV2, per
  channel).
- **SV2** (`src/sv2.rs`, `audit_sv2_jobs` in `src/lib.rs`). Noise and framing are
  `stratum-apps`' (`connect_with_noise` with the key, so the responder's certificate must be
  signed by it: `InvalidCertificate` is `Sv2Error::WrongKey`). The key is `--sv2-authority-key`,
  else the relay `Advert`'s. Two connections, each with its own `SetupConnection` (device fields
  from `--sv2-device vendor/hardware/firmware`, since pool_sv2 senses an extended channel's class
  from them): an extended channel first, then a standard channel with `REQUIRES_STANDARD_JOBS`,
  as a header-only miner opens it, so neither connection shows the node it is an auditor
  holding both. Future jobs wait for their `SetNewPrevHash`.
  - **Extended jobs** carry the coinbase (prefix, extranonce, suffix, BIP141-stripped): the
    extranonce is filled with the channel prefix and zeros and the job judged exactly as SV1.
  - **Standard jobs carry only the merkle root**, so their coinbase cannot be read, only
    guessed and checked. pool_sv2 builds every channel's job for a template in one pass with the
    same job factory: the scriptSig is the template prefix, the `/pool//` push, the channel's
    `GHPP` and `GHNT` pushes, then the extranonce (the standard channel's prefix); the outputs
    are the canonical outputs of the channel's class plus the template's witness commitment.
    So from an extended job on the same template the auditor takes version, the rest of the
    scriptSig, sequence, lock time, witness commitment, fees (outputs minus subsidy), the finder's
    script and the merkle path, and for every disclosed stamp whose table it holds, every class
    (500 first) and every tier 10..=63 (the channel target's tier first) builds the canonical
    candidate and folds its txid up the path (`rebuild_standard`). A match is the coinbase the
    miner hashes, judged as any job (so its class and tier are reported). No match against the
    4 newest extended jobs on the job's `prev_hash`, once an extended job has arrived after it
    and 2 s have passed (or `--wait` ran out), is FAIL `standard_job_not_canonical`: which part is
    wrong cannot be told from a hash. No extended job on its `prev_hash`, or no stamped table
    held, until `--wait` is UNCHECKED. Worst case 16 stamps x 6 classes x 54 tiers x 4 jobs
    full-coinbase hashes for a failing job.
  - Not checked on SV2: anything a standard job's merkle root hides beyond "it is or is not a
    canonical coinbase crediting you" (the reason is not named); a node that recognises the
    auditor (by IP, say) can serve it alone honestly, on SV2 as on SV1; group-channel jobs
    (pool_sv2 never sends them); `SetCustomMiningJob` (work selection is refused by pool_sv2).
- **Submits nothing.** Neither client sends `mining.submit` or `SubmitShares*`; the e2e test
  servers (SV1, and SV2 built on the vendored `StandardChannel`/`ExtendedChannel`) panic if one
  does.

## Open listing (W2.10, `bins/ghost-audit/src/{discover,listing,lister}.rs`)
- **The advert** is a relay message, `GetAdvert` (18) / `Advert` (19): SV1 port, SV2 port, SV2
  authority key. Ports only: a host in the advert would let a node point the lister (or miners
  reading the list) at a third party's machine. The `Hello` was left alone, so the handshake and
  its version did not change. pool_sv2 serves `[node_pool.relay] advertise_sv1_port` (the
  translator's port, which pool_sv2 cannot see) and its own SV2 listen port and key.
- **Discovery** is the existing `GetAddr`/`Addr` gossip, crawled by the lister from `--relay-peer`
  and `--seed` relays. Gossip is untrusted: literal IPs only (a host name is never resolved, so
  gossip cannot make the lister query names an attacker picks), publicly routable unless
  `--allow-private` or regtest, at most `--max-candidates` 1,024 and `--max-per-ip` 2, and at
  most `--max-crawl` 256 relays asked a round. On the relay side, `Addr` replies are now a
  random sample (they were always the lowest 64 addresses, so a node above them was never
  gossiped) and one IP may hold at most 4 learned addresses (`MAX_LEARNED_PER_IP`).
- **Probing** reads the advert first: unreachable relay `unmeasured` (`relay_unreachable`); other
  genesis, version or not a relay `fail`; no advert (`advert_none`), no answer
  (`advert_unanswered`) or neither an SV1 nor an SV2 port (`advert_no_stratum`, was
  `advert_no_sv1`) `unmeasured`, so a relay with no pool is a candidate that is never listed.
  Otherwise `probe::probe` on `relay IP:sv1_port` and `relay IP:sv2_port` with the advertised key,
  whichever are advertised; both must pass. An SV2-only node is listable (in `node-list.json`,
  not the DNS fragment, which is SV1 on one port).
- **Policy** (flags, defaults): listed after `list_after` 3 passes in the last `window` 6 probes,
  the latest a pass, no `fail` in the window, and after a delisting only passes since it;
  delisted after `delist_after` 3 non-passes in a row or `delist_after_fail` 1 fails in a row.
  So a node that fails once is off the list at the next write and needs the fail to age out of
  6 probes plus 3 new passes to return. Unlisted candidates unseen by discovery for
  `--forget-after` (7 days) are dropped. History is per relay address, not per `node_id`, which
  is self-declared.
- **Outputs**, written atomically after every round: `node-list.json` (`ghost-audit/node-list/v1`)
  and a zone-file fragment (`<name> <ttl> IN A|AAAA <ip>`), both sorted. The fragment holds only
  listed nodes on `--dns-sv1-port` 3333 (a DNS name carries no port), one record per IP, at most
  `--dns-max` 32 chosen by pass rate, then time listed, then address. `region` is always null.
- **The shim.** "The shim" in the plan is ghost-miner-proxy (#599): a miner-side proxy that
  verified an elder-signed mesh node-list checkpoint against `config/genesis-signers.txt`, the 8
  fleet `node.key`s with 6 required. Both were deleted in wave 3 (`99d27fb88`) with the
  checkpoint's producer. What is left is inert: migration v47's `mesh_node_list_checkpoints`
  table (dropped with the old tables by v65), and `/api/v1/pool/mesh-node-list-checkpoint`,
  which answers 410 Gone. No code on the node pool path checks a signature against a fixed key
  set: the relay accepts any peer on the genesis, the Noise mesh's `trusted_peers` is empty, and
  `fleet_auth` is one operator's key controlling that operator's own node, not listing.

## Genesis import and migration v65 (plan Phase 4)
- **Migration v65** (`crates/ghost-storage/src/migration_v65.rs`) drops the old system's 62
  tables (payout ledger and proposals, settlement, shard, votes, elders, rotation, capabilities
  and challenges, MPC, L2, Wraith, Ghost Pay, locks, glyphs, node-list checkpoints, key-value
  store) and creates `np_genesis` and `np_genesis_meta`. Kept, because code still reads them:
  `miners`, `shares`, `shares_archive` (and the `shares_all` view), `rounds`, `nodes`, `peers`,
  `uptime_samples`, `won_blocks`, and every `np_*` table.
- **It refuses, changing nothing,** on any row in a table that can hold user funds or an unspent
  claim: `withdrawal_requests`, `ghost_locks`, `l2_*`, `wraith_*`, Ghost Pay's
  `confidential_notes`, `nullifiers`, `pending_nullifiers`, `confidential_transfers`,
  `pending_l2_shields`, `accepted_instant_payments` and `instant_payment_reservations`,
  `confirmed_pool_staging` and `reconciliation_entries`, and on a `node_rewards` row whose
  `balance_sats` is not 0 (every health report creates one at 0). The old payout ledger is not
  halted on: the ledger export carries it. It also refuses when a table it drops holds rows but
  no verified copy exists: it takes one
  itself (`<db>.pre-v65`, `VACUUM INTO`, twice the database free required), reuses a verifying
  one, and never overwrites one that does not verify.
- **Refusals come first** (flag-day rehearsal, 2026-11-03): the money, free-space and stale-copy
  refusals run read-only before the first migration of any database below v65. An old fleet
  database is at v62; before this, v63 and v64 committed first, so a refused database was left at
  v64 with no copy taken, under "nothing changed". The copy itself is still taken inside v65, so
  `<db>.pre-v65` is a v64 database (the old release opens it with a "schema is AHEAD" warning).
- **Genesis rows outside the payee classes are refused** (export check 6). The old fleet paid
  P2PKH; the node pool's payee classes (`share_commit::payee_script_class`, spec 2.1) exclude it
  because each P2PKH output costs 4 sigops of the 400 the template leaves the coinbase. The import
  used to carry such rows: in the 2026-11-03 rehearsal (600 P2PKH rows of 3,958, 170 at or above
  the floor) every one was paid in full on signet's near-empty templates, the ledger API refused
  to show them ("cannot be paid by the node pool"), and a 500-output coinbase on a sigop-heavy
  mainnet template could have paid more than 100 of them and been lost. The import and
  `ghost-audit` now refuse such an export, naming the count and the sats; how those balances are
  carried is a cutover decision.
- **Space**: with `auto_vacuum = INCREMENTAL` the free list is drained step by step after the
  commit. At `auto_vacuum = 0` nothing is run; a `VACUUM` needs about twice the database free.
- **Old binaries refuse a v65 database**: the version is stored negated (`-65`), and every
  pre-v65 binary reads `user_version` as `u32` at open and fails. The shell gates decode it.
- **Import**: `pool_sv2 -c CONFIG --np-import-genesis DIR --np-export-digest HEX`, offline, into
  `[node_pool.relay] db_path`, once, before the relay first runs on the store. It checks the
  binary's sha256, the JSON against the binary's genesis rows (rows and totals are the binary's
  tail, so the import reads nothing from the checkpoint fields and does not depend on the export's
  source), the network, and a configured pin. `queue_since` is the export's height for every row at
  or above the 1,000-sat floor, none below. It prints the `table_root` to pin;
  `--np-verify-genesis` recomputes and compares without writing. The relay loads the stored table
  at start and holds it to the pin.

- **K = 120.** Resolved for the relay above: the duplicate check reaches back to `S(H)`. The spec's
  constants table still lists K; it should be reworded.
- **Regtest tier base.** At difficulty 1, `T_net` floor 10 needs about 2^42 hashes a share, out of
  reach on regtest. The PoW base is a parameter so Phase 3 can choose; `share_face` keeps the
  reference's difficulty-1 constant.
- **Treasury address**, from the user.
- **Archive peers.** A fresh node cannot validate batches older than every peer's window. Which
  nodes run with `prune` off (all 8 fleet nodes, at least) is the operators' call.
- **`ghost-audit` without a Bitcoin node.** The auditor's archive needs a trusted base (the
  blocks at genesis) that only a Bitcoin node supplies today. A peer-only bootstrap (walk back
  from the job's `prev_hash` with the archive's peer checks applied top-down) is possible but not
  built.
- **Who runs the lister, and where its outputs are published.** Anyone can run `ghost-audit list`;
  which run feeds `bitcoinghost.org/node-list.json` and the pool DNS name, and how the files get
  there, is the operators' call. A node list from a lister the reader does not run is that
  lister's claim; the probe is reproducible by anyone.
- **The website's `/api/pool/<host>/` proxy.** `miner.js` now asks the hosts in `node-list.json`
  through it (it used to name vm1-vm4 of the old fleet). The proxy lives on the website server,
  outside this repo, and must forward only to hosts listed in the current `node-list.json` (and
  only to the node's public API port), or it is an open proxy. Not built here.
- **Listing over SV2 only.** A node serving only SV2 is never listed, since the probe speaks SV1.
- **`ghost-audit` over SV2.** Only SV1 is audited. pool_sv2 builds one coinbase per extended
  channel either way, but a hostile node could serve SV2 miners differently; an SV2 client (Noise
  handshake, extended channel) is not built.
- **Share inclusion.** The docs page promised a proof that an anchor included the miner's share
  (`share_commit::batch_proof`). The auditor submits nothing, so it has no share to look for; a
  check from the miner's own share log is not built.
- **Deep reorgs.** A share-chain fork from below a node's checkpoint is never followed; that node
  must resync from an archive peer. With the default depth (288 blocks, two days) this needs a
  fork kept private for about two days.

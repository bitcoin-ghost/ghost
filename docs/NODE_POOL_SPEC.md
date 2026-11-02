# Ghost Node Pool: specification

Status: draft 11, 2026-11-02, against `main` at `f1cc40519`. Replaces the #608 path. Nothing here has been built or run on signet or mainnet. Simulation results are in `sims/`; line counts and durations are estimates.

## TLDR

**What it is.** A Bitcoin mining pool with no operator. Anyone can run a node and pick their own transactions, or just point a miner at someone else's node. Everyone is paid directly from the coinbase of the blocks the pool finds, so no one holds miners' money.

**How money moves in a block.**
- 0.5% of the subsidy goes to the treasury.
- The other 99.5% pays miners' ledger balances exactly, up to 500 outputs, minimum 1,000 sats: half to the oldest balances, half to the largest. Nobody is paid more than they are owed; any change goes to the treasury.
- All transaction fees go to the node whose miner found the block.
- Today that is 312,500,000 sats of subsidy: 1,562,500 to the treasury and 310,937,500 to miners. Miners keep about 98.95% of total block value at current fees.

**How the pool agrees who is owed what.** A light share chain. Nodes pass each other the larger shares, and each share proves its own work and its own payee. Roughly every 54 seconds a harder share becomes an anchor that orders the recent ones. The chain with the most work wins. There are no votes, no signatures to trust, no elders and no roster.

**What gets removed.** Node rewards, elders, capabilities, L2, zk, MPC, Wraith and ghostd: about 140,000 lines. About 5,000 are added. 16-22 weeks for one engineer.

**How it gets shipped.** Regtest, then our own signet, then mainnet. Nothing reaches mainnet until every test stage passes.

**The three things you should know.**
1. **Most mining hardware can't carry 500 outputs.** Firmware research (section 2.4) found no common machine that safely takes 16-22 KB. Realistic ceilings are about 20 outputs for a stock S19 (OCEAN's figure, unproven), about 60 for an S21, and about 130-180 for Whatsminer, Avalon, S9/S17 and Bitaxe. So 500 is a cap that most blocks will never reach, and how many miners a block pays depends on who found it. Sending a miner too large a coinbase can corrupt its memory instead of failing cleanly.
2. **Waits are long.** Even if every miner can carry large coinbases, a 100 TH/s miner at 1% of the network waits about 4.5 months for a first payment. On a low-limit mix, about half of small miners were not paid within the simulated 2 years. See section 7.
3. **The pool is about 100,000x short of 1% of the network.** The protocol makes the pool safe. It does not create hashrate.

**Still needed from you.** The treasury address, a Bitaxe run of the sensing loop, the old S19 when you have it, and later a real outside operator.

## How it works, start to finish

1. **Connect.** A miner connects to any listed node, or their own. Its username is its payout address. Only P2SH, P2WPKH, P2WSH and P2TR addresses work.
2. **Get a job.** The node builds a coinbase that everyone can recompute: treasury, then the owed miners in a fixed order, then the finder, then the commitments. The node picks the transactions; it cannot pick the miner payouts. The job carries a tag saying who this share credits and how many outputs the job holds.
3. **Mine.** The miner hashes as it would on any pool. Firmware sees ordinary coinbase bytes.
4. **Share.** A share above the network tier (`T_net`) goes to all nodes. Any node checks it alone: the work, the coinbase, the tag and the payouts. A share with wrong payouts earns nothing, so a block that doesn't pay the ledger earns no credit.
5. **Anchor.** About every 54 s a share 256x harder than `T_net` becomes an anchor and locks in a batch of recent shares. Jobs refresh within about 2 s of each anchor. If two anchors compete, most work wins and the loser's shares are re-included.
6. **Credit.** Each share credits sats at once, worked out from its own difficulty. All nodes reach the same balance because they run the same arithmetic on the same chain.
7. **Block found.** A block's outputs come from the balance table as it stood 20 blocks ago, so a reorg of the share chain can't change what the block should pay.
8. **Settle.** Nodes see the block and retire what it paid. The block itself records which anchor it built on, so a node can check it from Bitcoin plus the share chain. Coinbase rewards spend after 100 confirmations, as usual.
9. **Verify.** `ghost-audit` lets a miner check that their node really credited them. Without it, a miner is trusting that node.

# Spec

## 1. Rules

Anyone can run a node without approval. A miner runs a node and chooses their own template, or points hardware at someone else's node.

| Rule | Value | Status |
|---|---|---|
| Mining modes | Pool only | Decided |
| Miner payment | Coinbase, from subsidy only, via a persistent ledger | Decided |
| Minimum payout | 1,000 sats | Decided; simulation supports it |
| Outputs | Up to 500 miners + treasury + finder, plus witness commitment and one ledger commitment output | Decided as a maximum; must work on every miner, so each job carries what that miner's firmware can hold (W0.2) |
| Treasury | User's fixed address, `S/200` of subsidy plus any change a block can't pay to owed balances | Decided 11-02; address needed as a compiled constant |
| Finder | All tx fees to the node whose miner found the block | Decided |
| Node rewards, elders, capabilities | Removed | Decided |
| Membership | Open: no roster, no approval, no signed-by-8 gate on listing | Decided |
| Ledger agreement | Light share chain, PoW fork choice, no votes | Decided |

## 2. Protocol

### 2.1 Shares
The per-channel `GHNT` tag becomes:
`sha256("GhostShare/v2" || node_id || tier || slot_class || sha256(payee_script) || parent_anchor || batch_root)[..20]`

- `slot_class` commits how many miner outputs this job carries, so hardware with a small coinbase limit gets a shorter deterministic coinbase. It is a parameter of `canonical_outputs`. Provisional classes, sized for all-P2TR outputs so any payee mix fits: 3, 9, 44, 143, 364 and 500 miner outputs, for 500 B, 730 B, 2.25 KB, 6.5 KB, 16 KB and 22 KB coinbases. Every miner must work, so the class is set per connection: a table maps firmware (by user agent) to a known-safe ceiling, and an unknown miner gets the smallest class. A node may step a miner up only while valid shares keep arriving AND never past its model's known-safe ceiling, because oversized coinbases corrupt memory on Bitmain and Avalon firmware rather than being rejected (section 2.4). A valid share proves the firmware built that coinbase; nothing proves what a miner can't carry, so a miner can still under-report. Ceilings start from the research table below and are raised only by tests. Decided 11-02: a disconnect fails a class only while that class is being tested; once a miner has settled, a dropped connection resumes at the settled class. Native SV2 miners are matched on the vendor and firmware fields of SetupConnection. Channels open on `mining.authorize`, since the payee comes from it, and the translator runs with `quantise_to_tiers = true`.
- It uses no extra scriptSig bytes. Firmware sees opaque coinbase bytes.
- SV2 standard channels are allowed and always get the full class; `aggregate_channels = false`.
- Only network shares (NS), those meeting tier `T_net`, travel between nodes. They credit `2^max(T_net, committed_tier)`.
- Payee scripts are limited to P2SH, P2WPKH, P2WSH and P2TR, so size has a known bound and payouts add no sigops. P2PKH is excluded: each output costs 4 sigops, and regtest lost a block at 120 of them on a template of 79,591. Excluding it also removes the need to trim template transactions. The ledger keys on script bytes, not address strings.

A peer checks these as pure functions. Every check runs against the INCLUDING anchor's ancestry, never a node's own best chain, so validity cannot differ between viewers:
1. PoW meets target.
2. Rebuilt coinbase folds to the header merkle root.
3. Tag recomputes from its preimage.
4. Outputs equal `canonical_outputs(S(H), retired, slot_class)` plus finder and commitments. Treasury + miners = subsidy exactly.
5. BIP34 height, bits, time and scriptSig are valid; `prev_hash` is a real Bitcoin header; job height H >= including anchor's `btc_height` - 12, and H is in the same subsidy era as the including anchor. Without the era guard, old-header shares could reprice across a halving at 2x. A bound of 2 is too tight: it voids 48% of a 37.5% side's work in a 60-minute split, against 5.5% at 12.
6. The anchor that defines S(H) is an ancestor of the including anchor; not a duplicate. The share's own `parent_anchor` may sit on a dead fork. Requiring it to be an ancestor of the includer voided 52-80% of the losing side's work in a 10-minute split.

A failed share earns nothing, and an anchor including one is invalid. So a block that doesn't pay the ledger earns no credit.

Coinbase layout, fixed: treasury, canonical miner outputs in rule order, finder, commitment OP_RETURN, witness commitment. A zero-value finder output is omitted. The 21-byte payout-tag slot freed at H carries `parent_anchor[..16]`, so a block's anchor is recoverable from the chain alone. The table root goes in the OP_RETURN.

### 2.2 Anchors
- An anchor is an NS meeting `T_net + 8`. Its job committed `parent_anchor` and `batch_root` before hashing.
- Fork choice: most cumulative anchor work; lower hash breaks ties.
- A losing anchor demotes to a plain NS. Its batch is re-included later.

Constants, changed from the first design by simulation:

| Constant | Value | Why |
|---|---|---|
| Anchor spacing | 54 s | 1.8-4% orphans with pushed jobs; 18-28% on a 30 s timer |
| Job refresh | Push on every anchor within ~2 s; 30 s backstop | As above |
| `T_net` floor | 10 (about 20 TH/s) | Judgement call |
| K | 120, not 10 | K=10 voids 27% of work in a 30-minute 30/70 split; K=120 voids none. Decided 11-02: every window is measured from the INCLUDING anchor (rule 5), never from "the first anchor that carried the share", which depends on what each node has seen and could split nodes. A share stays includable while its job height is within 12 of the including anchor and in the same era; K bounds how far back the duplicate check looks. |
| Snapshot cut | `cut(H) = H-20`, fixed (user decision) | Lag 6-11 let a 30% attacker reorg past the cut on 0.7% of cycles; 0 of 16k at 12-23. Costs about 3.3 h of payout delay. By arithmetic a 120-minute partition (about 12 blocks) rarely reaches a fixed 20-block cut; not simulated at this value |
| Retarget | 36-block non-overlapping window, +/-1 tier, jump if 6 blocks read >=3 tiers off | Overlapping windows reached 31% outside the band |

Mandatory corrections from simulation:
1. **Remove the halt rule.** "Stop issuing jobs when the best anchor is 2 blocks old" permanently stopped the whole pool within about a day at every size. A node stops only when peers show a heavier chain it lacks.
2. **`T_net` must be able to fall on Bitcoin height alone**, or a large hash loss waits 11-16 h for an anchor.
3. **`btc_height` must be non-decreasing, and recent on receipt as relay policy only.** Self-declared height was exploitable: a held anchor stamped below the cut exposed 10/30/45% of blocks at 10/30/45% attacker share. As a hard validity check, recency split honest nodes about 6 times per 30-minute partition.
4. **Compute S from the block's own `parent_anchor` ancestry.** Simulated: one tip and one root after heal in all 600 partitions.
5. **Shares on dead-fork parents stay valid by height.** Simulated in the same runs.
6. **An anchor counts as unseen until its batch is held.** Simulated: honest void 0%, against 1.96-5.8% without it.
7. **Share-chain sync is part of the protocol.** New nodes need headers, batches, retention and pruning rules, and an archive of the stale Bitcoin headers and coinbases that shares refer to, because Bitcoin peers will not serve them.

**Batches and relay (W2.5, `crates/ghost-np-relay`).**
- `batch_root = sha256("GhostBatch/v1" || n as u32 LE || M)`, where `M` is the RFC 6962 merkle tree over the batch's share ids in batch order (`leaf = sha256(0x00 || id)`, `node = sha256(0x01 || left || right)`, split at the largest power of two below `n`, odd nodes carried up, empty tree 32 zero bytes). A share id is its header hash. The count is committed, and the tree gives a miner a log-size proof that an anchor included its share.
- A job's batch is the set of loose network shares its node held when it last re-batched: on every new best anchor, and every 30 s. A share mined since then waits for the next batch.
- Messages, all length-prefixed and capped per type: `Hello` (protocol version, genesis anchor, tip), `Share` (header, coinbase, merkle branch, tag preimage), `Anchor` (`btc_height` and the anchor's own share), `Batch` (anchor and share ids), `GetBatch`, `GetShares`, `Shares`, `GetAnchor`, `NotFound`, `Tip`, `GetAddr`, `Addr`. A node relays an anchor and its batch only after checking them, so it never passes on an anchor it cannot serve.
- An anchor's own share is checked as included by the anchor itself; if it fails, the anchor is invalid. It earns credit only when a later anchor includes it, like any network share.
- Peers are any nodes on the same genesis. Invalid data scores toward a 24-hour ban; late, stale or fork data never does.

Bandwidth estimate at 10 EH/s: about 3.7 KB/s per link, 320 MB/day. An SV1 notify with 500 outputs is about 44 KB, so 1,000 miners on 30 s jobs is about 1.5 MB/s of egress. Anchor pushes raise this; measure it.

### 2.3 Ledger and payout
The normative reference is `docs/node-pool-reference/refimpl_v3.py`; vectors are `docs/node-pool-reference/test_vectors_v3.json` (37 vectors). A Rust port must match it exactly.

Balances are in units of 2^-32 sat, fixed at share time from the share's own header `nBits`, so all nodes agree without a vote.

**Rule (user decision, draft 7): pay ledger balances exactly. Nobody is ever paid more than they are owed; change goes to the treasury.**
```
S=subsidy(H); Rm=S-S/200
face(share)=floor(2^tier * Rm_h * T * 2^32 / (0xFFFF * 2^208))
owed[a]=sum(face)-sum(retired)       table at cut(H)=H-20, retired through tip H-1
eligible = owed >= 1,000 sats
N = miner outputs this job carries (from slot_class); O = ceil(N/2), L = N - O
oldest  = eligible by (queue_since asc, owed desc, script asc), first O
largest = rest of eligible by (owed desc, script asc), first L
top = the single largest eligible balance; it is in the largest list but paid last
pay everyone else in order, oldest first: pay = min(owed, Rm left); stop when Rm left < 1,000 sats
then top: pay = min(owed_top, Rm left), if >= 1,000 sats
retired = pay, exactly
treasury = S/200 + (Rm - sum(pay))
```
- **The top balance absorbs the remainder (user decision, draft 11).** When a block is worth less than its payees are owed, everyone else is paid in full and the largest balance takes the partial payment; the rest of its balance waits for a later block, where it either is top again or ages into the oldest half.
- **Nobody is overpaid, and nobody loses balance.** A balance falls only by the exact amount paid. Not being in a block just means waiting.
- **The ratio, `K_R`, `X` and `x` are gone.** Draft 6 redeemed credit at a floating rate, which overpaid some blocks and underpaid others.
- **Faking a small coinbase should no longer pay.** A faker's block pays at most what the faker is owed, so the gain is being paid sooner, not more. This is reasoning, not yet simulated.
- **The treasury is no longer a fixed 0.5%.** It is 0.5% plus any change: whenever the balances in a block's slots add up to less than `Rm`. That happens when few miners are owed much, as at launch (a block found soon after launch sends most of `Rm` to the treasury), after a lucky run, and on small blocks whose top balances are small. Miners carry the unlucky runs as longer waits, and the treasury keeps the lucky ones. Measured in W1.3 (`sims/combined/results/exact_main.json`, 3 seeds each, 1% and 5% of the network):

| Mix | Change to treasury, whole run | First 50 blocks | Unpaid backlog | Bitaxe / 100 TH/s never paid |
|---|---|---|---|---|
| A: all large coinbases | 1.2-4.7% of Rm | 23-57% | Bounded | 4-20% / 0% |
| B: half the hash at 44 outputs, 30% at 9 | 20-21% | 51-79% | Grows without limit | 69-94% / 52-90% |
| C: 80% of the hash at 9 outputs | 28-33% | 62-86% | Grows without limit | 100% / 100% |

  **This breaks the rule's own promise.** Every sat of change was earned by miners and is still on their balances, but the coin has gone to the treasury, so the total of all balances can never be paid. On a pool with many stock Antminers the treasury would take 20-33% of the miners' reward. Class-faking gain is gone (1.000 against honest, was +34-39%). **Decided 11-02: keep this rule.** Change goes to the treasury. Miners are sensed per connection and paid according to what their firmware can carry; known low-limit SV1 firmware is warned about, not refused.
- `queue_since` is the height the balance crossed 1,000 sats, reset only when it falls below 1,000 sats.
- Balances are stored as blobs, not SQLite i64, which caps at 21.47 BTC in these units.
- `refimpl_v3.py` implements this rule; the older floating-ratio references stay in the design folder only.

Settlement is applied at tip, not at maturity, using Bitcoin ancestry plus the share chain. A block's `parent_anchor[..16]` and table root are on-chain; a node finds the matching anchor, recomputes the canonical outputs and retires only if they match. A block whose anchor a node doesn't have yet, as after a partition, retires provisionally from its coinbase data so its shares are not voided. Anchors with 6-confirmation pool blocks are final. Proposals and signatures go.

Pinned test cases: the 15 in `test_vectors.json`, plus 503/504-output golden vectors, two blocks on one snapshot, reorg restores balances, halving block.

### 2.4 What this does not fix
- **Your own node can harvest you.** A hostile node can put its own payee on jobs before you hash. `ghost-audit` and the proxy check detect it; without them, a miner trusts their node.
- **Block withholding** cannot be prevented, only seen as pool-level luck.
- **A pool-work majority** can censor and rewrite recent anchors. It cannot forge or relabel. A 45% attacker is not contained: 23% per cycle at lag 12-23, 10% at lag 24-47.
- **Small pools have no real security.** One 200 TH/s ASIC is about 65% of today's 110 TH/s. Nothing is worth stealing until blocks are found, but the ledger can be rewritten until hashrate grows.
- **Long partitions** diverge snapshots: 22.5% of 120-minute and 85% of 240-minute partitions, simulated. A 37.5% side loses 2.5% of its work in a 30-minute split, 5.5% in 60 and 21.1% in 120. Provisional retirement should bring these to 0%, 0% and 10.3%; that column is derived, not simulated.
- **Flood griefing is unsolved.** At 500 slots, 2% of pool hash split across addresses took Bitaxe waits from 66 days to 166 at 50,000 addresses, 454 at 200,000 and never at 1M. 2% of a 1% pool equals 178,333 Bitaxes, so a flood looks like real growth. Fees don't help, and floors hurt small miners. A `K_R` cap of 64 cut waits 12-26% under flood; its effect on normal mixes was not measured.
- **Launch goes mostly to the treasury.** With little owed, an early block pays the few balances there are and sends the change to the treasury. Launch hopping no longer gains.
- **Output slots cap small-miner reach.** See section 7.
- **Most hardware can't carry 500 outputs.** Research from published source code, official firmware images and OCEAN's live blocks, 11-02, no hardware. Full notes in `hardware-test/firmware-research/`.

| Hardware | Safe coinbase ceiling | About this many P2TR miner outputs | Evidence |
|---|---|---|---|
| Stock Antminer S19 (Amlogic board, the common one) | about 730 B | 9 | OCEAN's code and talk only; the image is encrypted; no code found that explains it |
| Antminer S19 XP (CVITEK board) | 2,048 B, stack overflow beyond | 40 | Disassembly of Bitmain's official image |
| Antminer S21 | about 2,250 B | 44 | OCEAN's code and talk; production image encrypted |
| Antminer S9, S11, S17, T17, S19 XP Zynq | about 7,650 B, memory overwrite beyond | 170 | Bitmain source: `last_job_buffer[8192]` at `bmminer-mix/driver-btm-c5.c:347`, copied unchecked at `:11115` |
| Avalon (2014-2025, incl. A15, Nano 3s) | 6,144 B | 135 | Canaan source; oversize jobs are silently skipped |
| Whatsminer | about 6,500 B | 143 | OCEAN's code ("tested") |
| Bitaxe ESP-Miner up to v2.15 | large (part 1 at most 1,024 B) | 500 | ESP-Miner source |
| Bitaxe ESP-Miner main, NerdQAxe | about 7,600 B | 170 | Source: 16 KB `mining.notify` line limit |
| ePIC, Braiins OS | 16 KB or more | 364-500 | OCEAN's code; Braiins "not extensively tested" |
| NiceHash | about 500 B | 3 | OCEAN's code |

  - **OCEAN's live blocks:** of the last 200 (967,705-974,204), 85 used OCEAN's Antminer format at 726-757 B with 18-20 outputs, and 115 used other formats at up to 2,307 B and 66 outputs. Roughly 40% of OCEAN's blocks come from miners OCEAN treats as stock Antminers.
  - **Mainnet, all pools:** of 12,000 blocks (962,201-974,200), none had 100 or more payout addresses; the most was 99, from OCEAN. Only OCEAN had 20 or more. In all 1,680 OCEAN blocks since December 2023, none had 100 or more, and before September 2024 none had more than 17. So there is no public evidence that a stock S19 or S21 has ever hashed a 100-output coinbase. Nobody else tries, so this is absence of evidence, not proof of a limit. Data in `hardware-test/firmware-research/`.
  - **S19 XP CVITEK, checked by hand:** the job function reserves a 2,340-byte stack frame and passes `sp+288` as the destination to a helper that tail-calls `memcpy` (PLT slot `0xabc4c`) with no upper bound, so about 2,050 B fit before saved registers are overwritten. That is about 50 P2WPKH outputs. Unless Bitmain checks the length earlier, this board cannot carry 100.
  - **Where 730 B comes from:** OCEAN's first DATUM commit (2024-10-13) and a 2025 talk ("about 700 bytes or so"). Everyone else cites OCEAN. It is the biggest unknown, and it covers the most common machine.
  - **Our path:** 504 outputs (15.8-21.8 KB) passed over SV1 and SV2 on regtest, with no real miner.
  - **Consequence:** a block pays at most as many balances as its finder's firmware allows. Change goes to the treasury.
  - **SV2-native firmware avoids this.** A standard SV2 channel sends the miner only a header, so coinbase size doesn't matter (169-278 B jobs at any size in W0.2). Only SV2 firmware such as Braiins OS can use it; stock Antminers speak SV1 only. This plan currently refuses standard channels; that refusal should be revisited (section 6).
  - Exact payment should remove the gain from faking a small coinbase, which was 34-39% under the draft 6 floating rule. Not yet simulated.
- **A dead pool leaves balances unpaid.** Nobody holds the money, so balances still owed when the pool stops are never paid.

The build plan is in `NODE_POOL_PLAN.md`. Paths starting `sims/` or `hardware-test/` are in the design working folder, not this repo; the normative payout reference and its vectors are in `docs/node-pool-reference/` (`refimpl_v3.py`, `test_vectors_v3.json`; run the script to self-test).

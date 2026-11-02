# Ghost Node Pool: build plan

Companion to `NODE_POOL_SPEC.md`. Simulations, the firmware research and the hardware test kit live outside the repo for now; paths starting `sims/` or `hardware-test/` are relative to that working folder.

## 3. Work plan

Sizes assume one engineer. Workers run in isolated worktrees. Every merge, roll and height is the user's call.

### Phase 0: now, on current code
- **W0.1 First-block fix** (PR #1053 open and parked. It does not go to mainnet alone; it is proved on regtest and signet with the rest of this build). Push the proposal on a win, pull at maturity with a retry list, accept only requested ids from known senders, exempt won proposals from the 24 h prune. Needed because blocks below H settle the old way.
- **W0.2 Large-coinbase spike.** Software half DONE (11-01, branch `spike/large-coinbase` at `2ba4115cb`, unpushed; raw results in `hardware-test/software-results/`). Coinbases of 762 B to 22 KB and 504 outputs passed SV1 and SV2 on regtest, debug builds, 3 blocks per case. The wire held to 65,436 B. At 65,576 B `SubmitSolution` overflows after the share passes, the block is lost and pool_sv2 shuts down, so the protocol ceiling stays at 22 KB. On a saturated template the default 8,000 WU reserve accepted 1.8 KB but lost the block at 2.25 KB; a 90,000 WU reserve carried 22 KB and 504 P2TR. Not covered: SV2 extended firmware, release-build latency, many-miner egress, a 24 h soak and multi-node consensus. No longer a gate: the protocol must work on all miners whatever each limit turns out to be, so Phase 2 does not wait for hardware. `hardware-test/` moves to the Phase 3 signet stage, where it sets the class table.
- **W0.3 974,500 check.** Let the gate fire and check it, since it stays live until H. Do not roll main first. The archive proof on `hazync-proof` is cancelled: archive capability is being removed.
- **W0.4 Archive tag.** Signed `archive/pre-node-pool` tag and git bundle. Copy MPC params and ceremony lineage off-node. Tag the last ghostd commit separately.

### Phase 1: spec freeze (about 1 week)
- **W1.1** Freeze this spec into `docs/NODE_POOL_SPEC.md`. Resolve the open items in section 6.
- **W1.2** DONE, 11-02. One simulator covering corrections 3-6, slot classes, partitions, flood and launch. Results in `sims/combined/`. The `K_R` cap test was stopped unfinished.
- **W1.3** Finish the rule (about 2 days). Rewrite `refimpl_v2.py` to exact payment with change to treasury, measure treasury change, waits and class-faking under it, set 250 + 250, `cut(H) = H-20` and classes 3/9/44/143/364/500 in `refimpl_v2.py`, remove the unused cap modes, regenerate vectors, and rerun partitions at the fixed cut.

### Phase 2: build (6-10 weeks, merges dark behind `u64::MAX`)
Parallel streams, after W2.1 merges:
- **W2.1 Pure core** (about 1,300 lines): `share_commit.rs`, `anchor_chain.rs`, `canonical_payout.rs`, Rust port of the payout rule, vectors. No I/O.
- **W2.2 Limits** (about 200 lines, new constants only; `MAX_MINER_OUTPUTS` feeds live selection at `payout.rs:385` and `:2690`, so it changes only at H): `blockreservedweight=90000` in `bitcoin.conf`, read `target_weight` and the template constraints, script-class limits, and a 22 KB coinbase ceiling.
- **W2.3 SV2 layer** (350): tag stamping, re-stamp on anchor, refuse standard channels.
- **W2.4 Storage** (350): additive tables only, including units in sats.
- **W2.5 Relay** (1,100): NS and anchor messages, tip tracking, batching, job push.
- **W2.6 Coinbase** (300): canonical build, submit-time check, finder output excluded from discharge. Remove the zero-value 31-byte output pool_sv2 adds to each channel's first job (`mining_message_handler.rs:302`, `:678`), which would fail the canonical check. The checkpoint dependency at `main.rs:8740` and the elder proposer at `:10814` stay live below H and only stop being used at H.
- **W2.7 Settlement** (250): ancestry fold at tip.
- **W2.8 Gate** (250): shadow mode, snapshot genesis column, gate logging.
- **W2.9 Miner protection** (200 + tool): proxy tag check, `ghost-audit`, public prober.
- **W2.10 Open listing:** any node with a valid advert that passes an external probe is listed. DNS and `endpoints.html` become generated output. The shim stops trusting the 8 keys.
- **W2.11 Visibility:** `/api/v1/ledger/{address}`, fix legacy routes, rewrite `miner.html`, `ghost-node status`.
- **W2.12 Installer:** remove the treasury prompt and capability flags, add `--fee-address`, preflight, alert webhook prompt.
- **W2.13 Share-chain sync** (not sized yet, expect 800+): initial sync, batch retention and pruning, stale header and coinbase archive, recoverable checkpoint. An outside node cannot reproduce the root without it.

Safe early removal, tested to leave the coinbase byte-identical:
- **R1** `apps/*` and ghost-keys (~53k lines).
- **R2** Solo and private modes, still parsing `mining_mode` (~2k).
- **R3** L2, zk, MPC, glyph (~26k). Keeps `get_mpc_elder_node_ids` until cutover, because elder share still shifts the coinbase. Removes in the same PR: the mainnet zk start gate at `main.rs:5036`, `zk-production` in `release.sh:305` and `release.yml:155`, and the `ghost_pay` config field, or tolerates it, since `NodeConfig` is `deny_unknown_fields` and installed configs carry it. Prove `checkpoint_voter_set.hash` and `ledger_root` unchanged on a canary.
- **R4** Mesh `ShareBatch*` messages only, and dead constants. `ShareBatch` is also the live webhook (`share_webhook.rs:91`, `routes.rs:10355`), which stays.

### Phase 3: prove it (about 4 weeks)
Nothing reaches mainnet until every stage here passes, in this order: regtest, then signet. Positive markers only; a missing reading is UNMEASURED, not a pass.

| Stage | Pass |
|---|---|
| Regtest 8-node e2e, wins at H-1, H, H+1, reorg across H, every slot class | Every node logs settlement for each block; roots equal; exact output sums |
| Hostile build: inflated balance, relabel, wrong treasury, fee skim, withheld shares, old format after H | Each honest node logs a named rejection; no honest node convicted |
| Our own signet, 8+ nodes, real wins on demand, 500 synthetic payees | Wins, reorgs and the cutover all settle on every node; roots equal; 24 h soak; proposals cross a real mesh |
| Signet, Bitaxe sensing run, then the user's S19 | Sensing mode (`hardware-test/coinbase_probe.py --sense`, selftest passes 10 simulated cases) climbs to each miner's highest safe class. |
| Signet, volunteer hardware ladder | A test endpoint serves coinbases from 700 B to 22 KB in both extranonce layouts and checks every share. Owners point each model at it for 15 minutes, stopping below known overflow sizes. The stock S19 (Amlogic) comes first. No miner is taken past its known overflow point |

Mainnet will not produce a win, so win evidence comes only from these. Signet is ours to run: we sign blocks and set difficulty, so a miner of any size can find one. The pool code handles the signet network, but the full stack has not been run on it yet.

### Phase 4: cutover (about 2 weeks, plus ninth node)
- **Release A:** all code, gates at `u64::MAX`. Canaries vm5-8, then vm4-1.
- **Migration:** in-place. Take the genesis table near H-36 from a unanimous finalised checkpoint, using `shard-anchor-rehearsal.sh`. Only ~1.6% of heights qualified when last surveyed, so budget a search. Convert each miner's work to sats at one published rate. Pin the digest in code and publish the table. Waiving balances is out: the website says work "never expires". This table is the ledger's one trusted input: a stranger can verify only the digest.
- **No double credit:** shadow anchors between S and H are dry and never counted, or that week is credited twice. Old-format blocks discharge at tip from their actual outputs, because a block at H-1 would otherwise discharge at H+99 while the new fold is already paying.
- **Release B:** arms S and H = S + 1,008, only at 8/8. S to H-1 pays the old way while nodes emit shadow shares and compare dry coinbases and roots.
- **Soak pass:** dry coinbase and root match 8/8 for all 1,008 blocks, counted positively.
- **At H:** new format only, keyed on job template height. A late node's blocks stay valid but its miners earn nothing.
- **Rollback:** gate to `u64::MAX` any time before H. After H, forward fixes only.
- **Ninth node:** separate person, machine and identity, public docs only, parallel with Release A soak. Must reproduce the root, get its miner credited and have its cheat refused. This also needs a real outside operator as a user dependency.

Order of publication: spec, tag A, snapshot table and notice of H, tag B after 8/8, installer docs at S, payout text at H, retire old docs after H+100.

### Phase 5: after H
- **R5** Remove the qualified set from the mesh checkpoint; then the checkpoint when the shim no longer needs it.
- **R6** `payout_checkpoint.rs`, vote handlers, fee drift (~9k).
- **R7** Challenges, qualification, reverify (~12k). `ghost-verification` keeps API and `fleet_auth`.
- **R8** Wraith, coordinator, ghost-lock, signer (~38k).
- **R9** Migration v64 one release later (v63 is the node pool storage added by W2.4), rehearsed on a DB copy. Halts on non-zero rows in `withdrawal_requests`, `ghost_locks`, `l2_*`, `wraith_*`.
- **R10** ghostd to stock Bitcoin Core over GBT and ZMQ, without sv2-tp, one canary first. Measure `getmempoolfilterstats` first. Haze datadirs need resync; the updater and `release.sh` need changing.
- **R11** Remaining gates and docs.

Do not forget: 26 `deny_unknown_fields` structs versus `[ghost_pay]`, `[coordinator]`, `[reaper]` in installed `pool.toml`; `zk-production` in `release.yml` and `release.sh`; `record-tests.sh`; CI jobs; check scripts; `deploy-node.sh` swaps binaries only, so unit changes must share a restart.

### Phase 6: public launch
Website and docs rewrite, remove the "NOT READY" banner only after Phases 3 and 4 pass. Required wording: no block has ever been found, no payout ever made, your balance may stay unpaid for a long time, an unaudited node can cheat you, use an established pool if you need steady income.

Launch blockers: W2.1-W2.9, W2.11, W2.13, Phases 3 and 4, ninth node.

## 4. Total size
About 5,000 new lines, removals of about 140,000 lines, and 16-22 weeks end to end for one engineer. Soak, signet and hardware are elapsed-time bound whoever does the work.

## 5. User decisions needed
1. Treasury address, compiled in by W1.1. A single key is a single point of loss; a multisig address is possible.
2. Hardware access for the signet stage of Phase 3.
3. A real outside operator for the ninth-node stage.
4. Every merge, roll, and the value of H.

## 6. Open design items for spec freeze
- **SV2 standard channels are allowed (decided 11-02).** An SV2 miner on a standard channel receives only a header, so it always gets the full 500-output class. W2.3 must stamp the per-channel tag in the pool-built coinbase.
- Change goes to the treasury (decided 11-02). Known low-limit SV1 firmware gets a warning at connect and on the miner page, naming the model and the expected cost; it is not refused.
- Sub-NS credit for small miners above about 1 EH/s: at 100 EH/s, 85% of 1.2 TH/s miners earn nothing in a month.
- The table root goes in one OP_RETURN output (`x` no longer exists). ScriptSig is 99/100 full, so the coinbase carries 504 outputs at most.
- ghost-miner-proxy role: optional tool or the default for protected miners.
- Cost of the 90,000 WU reserve: about 20,500 vB of block space, roughly 20,500 sats per full block at 1 sat/vB, or 1.2% of the average fee. Estimate, not measured. It falls on the finder, and every template pays it whatever the slot class.

## 7. The honest reading
Protocol work makes the pool safe. It doesn't create hashrate. Median days to first payment, simulated under the draft 6 floating rule, Bitaxe / 100 TH/s. Exact payment will change these; W1.3 reruns them:

| Pool share of network | Blocks every | Large coinbases, 250 + 250 | Large coinbases, 100 + 400 | Large coinbases, 450 + 50 | Low-limit Mix B, 250 + 250 |
|---|---|---|---|---|---|
| 1% (10.7 EH/s) | 17 hours | 153 / 136 | 470 / 409 | 82 / 66 | About half not paid in 2 years |
| 5% (53 EH/s) | 3.3 hours | 111 / 43 | 141 / 73 | 94 / 26 | 306 / 226 |

"Large coinbases" here means 340 outputs per block, so 170 oldest at 250 + 250; a true 500-output block should do better but was not run. The 250 + 250 and 100 + 400 runs used 2 seeds each and are a quick read. Mix B is 50% of the hash at 40 outputs, 30% at 12 and 20% at 340, using the same rule on every block. With 80% at 12 outputs (Mix C), 73-77% were not paid in 2 years at 1% of the network. 4% of Bitaxes at 1%, and 20% at 5%, were not paid within the run even on large coinbases. The 0.1% case was not rerun; at 450 + 50 it took 1,127 / 1,091 days on large coinbases.

So the first useful audience is node runners and larger miners, and only on firmware with room for large coinbases. Home miners become a real audience only near 1% of the network. Demand testing with real miners remains unfinished and doesn't depend on any of this engineering.

Sources for section 2.4: [DATUM gateway source](https://github.com/OCEAN-xyz/datum_gateway), [mempool.space OCEAN blocks](https://mempool.space/mining/pool/ocean), [Bitcoin Explained on TIDES](https://btctranscripts.com/bitcoin-explained/ocean-tides), [p2poolv2 discussion 668](https://github.com/p2poolv2/p2poolv2/discussions/668).

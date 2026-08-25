# Rolling back `PAYOUT_FROM_SHARD_HEIGHT` (the no-vote payout gate)

**Staged 2026-08-25, before the gate at 964_100 fires.** Branch `ops/payout-gate-rollback`.

This build is identical to the deployed `v1.11.28` except that `PAYOUT_FROM_SHARD_HEIGHT` is
`u64::MAX`, so the gate never fires and every node keeps taking the BFT vote path.

## Why it is staged in advance

⛔ **`GHOST_PAYOUT_FROM_SHARD_HEIGHT` does nothing on this fleet.** `gates::from_env`
(`bins/ghost-pool/src/lib.rs:721`) returns the compiled-in default *before* it reads the
environment when the network is Mainnet, and all eight nodes are `[bitcoin] network = "mainnet"`.
Setting that variable changes nothing and warns about nothing — it looks exactly like a
successful rollback until you check the behaviour.

That short-circuit is correct and must stay: a gate a per-node environment variable can move is a
gate that can differ between nodes, which is the split-brain these heights exist to prevent.

So undoing this gate has always meant *changing the constant and redeploying* — rebuild,
`record-tests.sh`, a 60-minute canary soak, then a production roll one node at a time. **Hours.**
Producing that under incident pressure is what this branch removes.

## What is pre-done, and what is not

| step | state |
|---|---|
| constant disarmed + test flipped to assert it | ✅ `1d2940c85` |
| `scripts/record-tests.sh` — fmt, clippy as CI runs it, docs under `-D warnings`, deploy-gate self-test, SV1 smoke, fuzz build, 718 tests | ✅ passed; `1d2940c85` recorded deployable |
| release binary, `--features zk-production` (required for mainnet) | ✅ built 2026-08-25 |
| canary soak | ❌ **cannot be pre-done** — see below |

**Staged artefact**

```
~/.ghost-deploy/staged/ghost-pool-rollback-1d2940c85
sha256  fa5ac5ab69a2a5d0c5a4579a74e4c59ec27b62145e2a274e65f81257328eb181
```

⚠ Kept outside `target/release/`, which the next `cargo build` of any branch overwrites. If the
copy is gone, rebuild it: `git checkout ops/payout-gate-rollback && cargo build --release -p
ghost-pool --features zk-production` — about 4 minutes with a warm cache. The expensive half is
`record-tests.sh`, and that record is keyed to the SHA and survives.

⚠ `deploy-node.sh` deploys from `target/release/ghost-pool`, so a rollback means checking the
branch out and rebuilding (or copying the staged file into place) — the staged copy is insurance
against a cold cache and a bad moment, not a shortcut around the deploy script.

For reference, what is deployed today (`v1.11.28`, gate ARMED at 964_100):
`sha256 711179a8f721659af972db0c707c3585a700f83385b59dec955f858e9e54110e`

⚠ **The soak cannot be staged.** `deploy-node.sh` records the soak against the binary's hash and
deletes the marker if the node is no longer running what it soaked. Soaking this build on a canary
and then restoring the normal binary invalidates the marker, so it buys nothing. And leaving it on
a canary through the gate would make that node disagree with the rest of the fleet — the exact
failure this gate is careful about.

## Deciding whether to roll back

The gate firing is expected to look like this (`lib.rs:558`):

| signal | before | after |
|---|---|---|
| `Paying from this node's own shard view (no vote` | 0 | ~22/day |
| `Payout consensus approved` | ~22/day | stops |
| `payout ledger checkpoint FINALISED` | continues | **must continue** |

⚠ **If checkpoints stop, this gate is probably NOT the cause** — but the standoff looks identical
to the 18–21 Aug one that paid nobody for three days (that one was #724: v56 disabled the ledger
sweep the checkpoint needed). Check both before concluding — a rollback that "fixes" a standoff it
did not cause leaves the real cause in place.

⚠ Judge by `payout ledger checkpoint FINALISED` — the FULL string. There is also
`mesh node-list checkpoint FINALISED`, so a bare `grep FINALISED` counts the wrong thing, and
`grep finalis` has previously counted the *failure* line.

## Rolling back

⛔ **All-or-nothing.** Every node runs this build or none do. A fleet split across the two
disagrees about how the coinbase is committed, which is worse than either state.

```sh
git checkout ops/payout-gate-rollback
# the deployable record is already present for this SHA; re-run only if the branch moved
scripts/record-tests.sh

scripts/deploy-node.sh ghost-vm5 ghost-pool --canary   # starts the 60-minute soak clock
# ... soak ...
scripts/deploy-node.sh ghost-vm2 ghost-pool            # then vm3, vm4, vm6, vm7, vm8
scripts/deploy-node.sh ghost-vm1 ghost-pool            # vm1 is genesis — last
```

### Verifying it took

⛔ **The node never says which activation heights it is enforcing.** `init_activation_heights`
resolves every gate into a `OnceLock` and logs nothing — there is no `info!` for it anywhere. So
there is NO journal evidence of which gate a running binary carries, and any verification step
built on grepping the log for a height is a check that cannot succeed. (Tracked separately: the
node should report what it enforces at startup.)

Verify by **binary identity** instead, which is exact and immediate:

```sh
sha256sum target/release/ghost-pool                      # the staged rollback build
ssh ghost-vmN "sha256sum /opt/ghost/bin/ghost-pool"      # what the node is running
```

They must match on every node. `deploy-node.sh` already records this hash for its soak check, so
a mismatch also means the soak marker is void.

Then confirm by BEHAVIOUR, over a window rather than a single sample: the
`Paying from this node's own shard view (no vote` line must **stop** appearing, while
`payout ledger checkpoint FINALISED` continues.

⚠ Do not judge any of this from a single sample — [the deploy smoke has passed by reaching
production before](https://github.com/bitcoin-ghost/ghost/issues/759).

## If the gate is fine

Delete the branch. It has no purpose once the fleet is observed paying from the shard, and PR #750
(Stage 6 Release B) deletes the BFT vote path outright — after which this rollback is no longer
possible and no longer needed.

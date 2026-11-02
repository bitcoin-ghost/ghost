# Auditing your node

*`ghost-audit` checks that the node you mine on is honest with you: that every job it sends you pays the canonical coinbase and credits your payout address.*

:::warning Built, not released
`ghost-audit` is built (W2.9 in the build plan) but not in a release yet, and the node pool has not launched. Until you run it against your node, you are trusting that node.
:::

## Why you need it

Any node can check any other node's shares, so a node cannot credit itself work it didn't do, pay the wrong people in a block, or rewrite balances without the rest of the pool refusing it.

What other nodes **cannot** see is the jobs a node hands to *its own* miners before they hash. A hostile node can put its own payee on your jobs. Your hardware would mine for the node, the node would be credited, and you would not. Nothing on the share chain is wrong, so no other node would object.

The only party who can catch that is you, by checking the jobs your node sends you. That is what `ghost-audit` does.

## What it checks

`ghost-audit` connects to your node's stratum port like a miner, over Stratum V1, Stratum V2 or both, logs in with your payout address, and checks each job it is sent:

- **The job credits you.** Every job carries a tag that commits to who its shares credit. `ghost-audit` asks the node's relay port for the job stamps its tags commit to, and checks that the tag opens to *your* payout address. A stamp that does not open the tag proves nothing, so this trusts the node for nothing.
- **The job pays the canonical coinbase.** It recomputes what the coinbase must pay for the job's height, parent anchor and slot class (treasury, the owed miners in the fixed order, the finder, the commitments) and compares it with the job, output by output.
- **Your shares can count.** The difficulty tier the job commits to must be one your shares meet at the difficulty the node set.

It recomputes the coinbase from a share chain it syncs **itself**, from relay peers you name, and settles it from **your own Bitcoin node**, exactly as a node does. It never asks the node you are auditing what the coinbase should be: that is the party being checked.

**It submits nothing.** It never sends a share, so nothing it does is credited to anyone. It only reads jobs.

## Stratum V2

Over Stratum V2, `ghost-audit` first checks it is talking to the node you meant: the node must prove its **authority key** in the encrypted handshake, the key it advertises on its relay port (or the one you pass with `--sv2-authority-key`). A node that cannot is refused before anything else is read.

It then opens two channels, on two connections, as two miners would:

- an **extended channel**, whose jobs carry the coinbase itself. Each is checked exactly like a Stratum V1 job.
- a **standard channel**, the kind header-only SV2 firmware uses. Its jobs carry only the merkle root, a hash of the coinbase, not the coinbase. `ghost-audit` cannot read a hash, so it rebuilds the coinbase the job should have: the node builds every miner's job from the same block template, so the extended job supplies the template's parts, and `ghost-audit` fills in the rest itself, canonically (the outputs your job must pay, a tag crediting you). If that coinbase hashes to the job's merkle root, the job is the canonical one and is checked like any other. If nothing canonical crediting you does, the job fails as **standard job not canonical**: the job pays or credits someone else, but a hash cannot say which part is wrong.

## Results

Each job gets one line:

| Result | Meaning |
|---|---|
| `PASS` | The job pays the canonical coinbase and credits you. |
| `FAIL` | It does not. The reason is named, below. |
| `UNCHECKED` | `ghost-audit` could not judge it yet: its own share chain is still syncing, or your Bitcoin node does not know the job's block. This is not a pass. |

The reasons a job fails:

| Reason | What the node did |
|---|---|
| tag not committing to you | The job's shares credit someone else, or the node will not say what its tags commit to. |
| wrong treasury | The first output does not pay the treasury. |
| skimmed from the outputs | The treasury and miners get less than the block subsidy; the difference goes to the finder or elsewhere. |
| relabelled payee | A miner the ledger owes is replaced by another address carrying its amount. |
| inflated balance | Someone is paid more than the ledger owes them, or paid when it owes them nothing. |
| wrong slot class | The outputs are canonical, but for a different number of miner outputs than the job's tag commits. |
| wrong ledger root | The payouts are right but the job commits a different balance table. |
| tier above your difficulty | The job commits a difficulty tier your shares will not meet, so they would earn nothing. |
| wrong height | The coinbase's block height does not follow the job's previous block. |
| outputs not canonical | Any other difference: wrong order, a dropped payee, the treasury overpaid. |
| standard job not canonical | (SV2 standard channel) No canonical coinbase crediting you hashes to the job's merkle root. |

The exit code is 0 when every job passed, 1 if any failed, 2 if any could not be checked.

## Running it

You need a Bitcoin node with RPC (it can be pruned), and the address of at least one relay peer other than the node you audit.

```
ghost-audit audit \
  --network mainnet \
  --stratum node.example.org:3333 \
  --node-relay node.example.org:8566 \
  --relay-peer other-node.example.org:8566 \
  --address bc1p... \
  --rpc-user you --rpc-password ... \
  --genesis-export ./ledger-export \
  --export-digest <published sha256 of ledger-export.bin> \
  --genesis-table-digest <published table_root> \
  --user-agent "bmminer/2.0.0" \
  --jobs 5
```

For Stratum V2, add or use instead `--sv2 node.example.org:34255`; the authority key is the one the node's relay advertises unless you pass `--sv2-authority-key`. Pass `--sv2-device "vendor/hardware/firmware"` with your miner's SetupConnection fields to audit the jobs your hardware gets. With both `--stratum` and `--sv2`, both are audited at once and `--jobs` counts per protocol (on SV2, per channel). Job ids start `ext-` or `std-` for the SV2 channel they came from.

- `--user-agent`: the node chooses how many outputs your jobs carry from your miner's user agent. Pass the one your hardware sends to audit the jobs your hardware actually gets.
- `--genesis-anchor` and `--genesis-height`: the share chain's start. Regtest has a fixed one; none is published for mainnet or signet yet.
- `--genesis-export` and `--export-digest`: the published ledger export (`ledger-export.bin` and `ledger-export.json`), which holds the balances carried over at the cutover. Every payout table starts from them, so the auditor must start from the same ones the network does. It checks the export exactly as a node's import does and keeps the table in its data directory, so later runs need not pass it again.
- `--genesis-table-digest`: the network's pinned digest of that table (the `table_root` every node pins). `ghost-audit` refuses to audit, probe or list unless its table hashes to it, since a table that is not the network's would make every verdict wrong. Required except on regtest.
- `--json` prints one JSON object per job.

The first run syncs the share chain from your relay peers, which takes a while; jobs are `UNCHECKED` until it has.

## The public prober

`ghost-audit probe` runs the same checks from outside, plus the node's advert (its relay port answers on this share chain and discloses its job stamps), and prints a JSON verdict: `pass`, `fail` or `unmeasured`, with reason codes. It probes every protocol the node advertises (SV1, SV2 or both), and each must pass, so a node that serves SV2 miners worse than SV1 miners fails. Open listing uses it to decide whether a node is listed: only `pass` is listed. A node that serves only SV2 can be listed; it appears in the node list but not the DNS name, which carries the SV1 port. Being listed means a node passed this probe when it ran; it does not mean the node is honest with every miner, which is why you audit your own.

## What it does not check

- **Whether your shares were included.** Each anchor commits to its batch of shares in a merkle tree, so a miner can get a short proof that an anchor included a share. `ghost-audit` submits no shares, so it has none to look for.
- **Which part of a bad standard job is wrong.** A standard-channel job is only a hash, so a failing one is reported as not canonical, not as, say, a relabelled payee.
- **A node that recognises the auditor.** A node that can tell `ghost-audit`'s connection from your miner's (by IP address, for instance) could serve it alone honestly. Running it from your miner's own network and with your miner's user agent or device fields narrows that.
- **Withheld blocks.** A node can hide a block your miner found. That shows only as bad luck over time.

## Until you run it

- **Run your own node** if you can. A miner on its own node has nothing to audit.
- If you mine on someone else's node without auditing it, you are trusting its operator. An unaudited node can cheat you.
- Watch your balance on the [miner page](/miner.html). A balance that does not grow while your miner reports accepted shares is a warning sign, though not proof.

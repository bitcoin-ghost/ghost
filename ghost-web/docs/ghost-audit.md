# Auditing your node

*`ghost-audit` is the tool a miner will use to check that the node it mines on is honest. It is not built yet. Until it is, a miner is trusting the node it mines on.*

:::warning Coming, not built
`ghost-audit` is planned work (W2.9 in the build plan). Nothing on this page exists yet. It is a launch blocker: the node pool does not open to the public without it.
:::

## Why you need it

Any node can check any other node's shares, so a node cannot credit itself work it didn't do, pay the wrong people in a block, or rewrite balances without the rest of the pool refusing it.

What other nodes **cannot** see is the jobs a node hands to *its own* miners before they hash. A hostile node can put its own payee on your jobs. Your hardware would mine for the node, the node would be credited, and you would not. Nothing on the share chain is wrong, so no other node would object.

The only party who can catch that is you, by checking the jobs your node sends you. That is what `ghost-audit` is for.

## What it will check

- **The jobs pay the canonical coinbase.** Every node can compute what a job's coinbase must pay for its slot class: treasury, the owed miners in the fixed order, the finder, the commitments. `ghost-audit` recomputes it and compares it with the jobs your node actually sends.
- **The jobs credit you.** Every job carries a tag that commits to who the share credits. `ghost-audit` checks that the tag names your payout address.
- **Your shares were included.** Each anchor commits to its batch of shares in a merkle tree, so a miner can get a short proof that a given anchor included its share.

It will be paired with a **public prober**: an outside check that a listed node serves honest jobs.

## Until then

- **Run your own node** if you can. A miner on its own node has nothing to audit.
- If you mine on someone else's node, you are trusting its operator. An unaudited node can cheat you.
- Watch your balance on the [miner page](/miner.html). A balance that does not grow while your miner reports accepted shares is a warning sign, though not proof.

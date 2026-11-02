# Before you mine

*What the node pool has and hasn't done, how long you may wait to be paid, and when you should mine somewhere else.*

## The plain facts

- **No block has ever been found** by the node pool.
- **No payout has ever been made.**
- **Your balance may stay unpaid for a long time.** Even if every miner could carry large coinbases, a 100 TH/s miner on a pool at 1% of the network would wait about 4.5 months for a first payment. On hardware with low coinbase limits, about half of small miners were not paid within 2 simulated years.
- **An unaudited node can cheat you.** The node you mine on builds your jobs. Until `ghost-audit` exists, you are trusting it. See [Auditing your node](#ghost-audit).
- **If you need steady income, use an established pool.**

## What has been tested

Nothing has run on signet or mainnet yet. Before anything reaches mainnet it must pass, in order: multi-node tests on regtest, a hostile-node test build, several nodes on our own signet with real block wins, and real hardware on signet. Until those pass, this site carries a NOT READY banner.

## How long you may wait

The protocol makes the pool safe. It doesn't create hashrate, and the pool is about 100,000 times short of 1% of the Bitcoin network.

Median days to a first payment, simulated, for a Bitaxe / a 100 TH/s miner:

| Pool share of network | A block every | Large coinbases, 250 oldest + 250 largest | Low-limit hardware mix |
|---|---|---|---|
| 1% (10.7 EH/s) | 17 hours | 153 / 136 days | About half not paid in 2 years |
| 5% (53 EH/s) | 3.3 hours | 111 / 43 days | 306 / 226 days |

Read these with care:

- They were simulated under an **earlier** version of the payout rule. The exact-payment rule now in force will change them; they are being rerun.
- "Large coinbases" means every miner's firmware carries 340 outputs. Most hardware carries far fewer (see [firmware compatibility](#mining)). The low-limit mix is 50% of the hash at 40 outputs, 30% at 12 and 20% at 340.
- With 80% of the hash at 12 outputs, 73-77% of small miners were not paid in 2 years, at 1% of the network.
- Even on large coinbases, 4% of Bitaxes at 1% of the network, and 20% at 5%, were not paid within the simulated run.
- At 0.1% of the network, the one case rerun (450 oldest + 50 largest, large coinbases) took 1,127 / 1,091 days.
- The pool today is nowhere near 1%.

So the first useful audience is node runners and larger miners on firmware with room for large coinbases. Home miners become a real audience only if the pool nears 1% of the network.

## What the protocol does not protect against

- **Your own node can harvest you.** See above.
- **Block withholding** can't be prevented, only seen as bad luck at pool level.
- **A majority of the pool's work** can censor and rewrite recent anchors. It cannot forge shares or relabel them to itself.
- **Small pools have no real security.** One 200 TH/s machine would be about 65% of a pool the size of today's (about 110 TH/s). Nothing is worth stealing until blocks are found, but until the hashrate grows the ledger can be rewritten.
- **Long network partitions** can make nodes disagree about balances for a while, and a side cut off for long enough loses some of its work.
- **Flooding with many addresses** can push small miners' waits out much further. This is unsolved.
- **Launch goes mostly to the treasury.** With little owed, an early block pays the few balances there are and sends the change to the treasury. See [The payout rule](#payouts).
- **A dead pool leaves balances unpaid.** Nobody holds the money, so balances still owed when the pool stops are never paid.

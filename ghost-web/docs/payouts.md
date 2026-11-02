# The payout rule

*How the node pool decides who a block pays and how much. Every node runs the same arithmetic on the same share chain, so every node reaches the same answer without a vote.*

:::warning Not ready
No block has ever been found by the node pool and no payout has ever been made. This page describes the rule as specified; it has not run on signet or mainnet. The normative version is `docs/node-pool-reference/refimpl_v3.py` in the repository, with its test vectors.
:::

## The short version

- You are credited as you mine. Each share adds sats to your balance straight away.
- When the pool finds a block, the block pays balances **exactly**. Nobody is ever paid more than they are owed, and a balance only goes down by what was actually paid.
- A block has a limited number of payout slots. Half go to the balances that have waited longest, half to the largest balances.
- The minimum payout is **1,000 sats**. Balances below that wait.
- The treasury gets 0.5% of the subsidy, plus anything a block could not pay out.
- The node whose miner found the block gets all of its transaction fees.

## 1. Credit at share time

Your balance grows the moment a share is accepted into the share chain. The amount comes from the share itself: its difficulty compared with the Bitcoin block difficulty in its own header, times the miners' part of the subsidy. A share with a millionth of the work of a block is credited a millionth of that amount. All nodes agree because the number comes from the share's own header, not from any node's clock or opinion.

Only network shares, those above the pool's network tier, travel between nodes and earn credit. The network tier moves with the pool's hashrate (it is retargeted every 36 Bitcoin blocks). A small miner finds network shares less often, so its credit arrives in lumps.

Balances are kept in units of 2^-32 sat, so rounding never moves money between miners.

## 2. The snapshot: `cut(H) = H - 20`

A block at Bitcoin height H pays from the balance table **as it stood at height H - 20**, less everything already paid by blocks up to H - 1. The 20-block lag means a reorg of the share chain cannot change what a block should pay. It costs about 3.3 hours of payout delay.

## 3. Who is eligible

A balance is eligible once it is at least **1,000 sats**. Its place in the "oldest" queue is the height at which it first crossed 1,000 sats. That place is only lost if the balance falls back below 1,000 sats.

## 4. How many slots: the slot class

Each job carries a fixed number of miner payout slots, set by the **slot class** of the miner hashing it. A block found on that job pays at most that many balances.

| Slot class (miner outputs) | Coinbase size, all P2TR payees |
|---|---|
| 3 | 500 B |
| 9 | 730 B |
| 44 | 2.25 KB |
| 143 | 6.5 KB |
| 364 | 16 KB |
| 500 | 22 KB |

The class depends on what the finder's firmware can safely carry, not on how much you are owed. See [Mining on the node pool](#mining) for how a node picks it.

## 5. Who gets the slots

With N slots:

1. **Half the slots (rounded up) go to the oldest balances**: the eligible balances that crossed 1,000 sats earliest. Ties go to the larger balance, then by payout script.
2. **The other half go to the largest balances** among the rest. Ties go by payout script.
3. **The single largest eligible balance is paid last.** It sits in the "largest" half, but it is paid after everyone else.

## 6. How much each gets

The miners' part of the subsidy is `Rm = S - S/200`, where S is the block subsidy.

1. Going through the slots, oldest first, each balance is paid in full, or whatever of `Rm` is left if that is less.
2. Payment stops when less than 1,000 sats of `Rm` is left.
3. Then the largest balance is paid whatever of `Rm` remains, up to what it is owed, as long as that is at least 1,000 sats.

So when a block is worth less than its payees are owed, everyone else is paid in full and **the largest balance takes the partial payment**. The rest of its balance waits for a later block, where it is either the largest again or has aged into the oldest half.

Each payee's balance goes down by exactly what it was paid.

## 7. The treasury and the finder

- **Treasury** = `S/200` (0.5% of the subsidy) **plus any change**: whatever part of `Rm` the slots did not use. The treasury address is a fixed protocol constant; it has not been published yet.
- **Finder**: all transaction fees go to the fee address of the node whose miner found the block. Fees are not part of the ledger. If they are zero, the finder output is left out.

At today's subsidy of 312,500,000 sats: 1,562,500 to the treasury and 310,937,500 for miners.

## Change goes to the treasury, and it can be a lot

The treasury takes change whenever the balances in a block's slots add up to less than `Rm`. That happens when few miners are owed much, as at launch, after a lucky run, and on blocks found by miners whose firmware only carries a few slots. The sats that went to the treasury were earned by miners and stay on their balances, but the coin has gone, so the total of all balances can never be fully paid.

Simulated (3 seeds each, pool at 1% and 5% of the network):

| Hardware mix | Change to treasury, whole run | First 50 blocks | Unpaid backlog |
|---|---|---|---|
| A: every miner carries large coinbases | 1.2-4.7% of `Rm` | 23-57% | Bounded |
| B: half the hash at 44 outputs, 30% at 9 | 20-21% | 51-79% | Grows without limit |
| C: 80% of the hash at 9 outputs | 28-33% | 62-86% | Grows without limit |

On a pool with many stock Antminers the treasury would take 20-33% of the miners' reward. This was decided knowingly: change goes to the treasury, and miners are paid according to what their firmware can carry.

A block found soon after launch, when little is owed, sends most of `Rm` to the treasury.

## What this rule does and doesn't promise

- **Nobody is overpaid and nobody loses balance.** Not being in a block just means waiting.
- **Faking a small coinbase should not pay.** A block pays at most what each payee is owed, so a miner who makes its blocks carry fewer slots is at most paid sooner, not more. In simulation of this rule the gain from faking was gone (under the older floating rule it was 34-39%).
- **Work never expires**, but a balance is only worth something if the pool keeps finding blocks. If the pool stops, balances still owed are never paid: nobody holds the money.
- **Waits can be very long.** See [Before you mine](#honest-reading).

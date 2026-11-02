# Mining on the node pool

*How to point a miner at a node pool node, what your payout address must be, and why the node may give your hardware a small coinbase.*

:::warning Not ready
The node pool has never found a block and has never made a payout. It has not run on signet or mainnet. Read [Before you mine](#honest-reading) first. If you need steady income, use an established pool.
:::

## Connect

Pick a node from [the node list](/endpoints.html), or run your own (see [Deployment](#deployment)). Then set your miner to:

| Protocol | URL | Notes |
|---|---|---|
| Stratum V1 | `stratum+tcp://<node>:3333` | Hobby tier. Through the node's SV1 translator. |
| Stratum V1 | `stratum+tcp://<node>:4444` | Farm tier, higher starting difficulty (about 232,827). |
| Stratum V2 | `<node>:34255` | Standard channels always get the full 500-slot class. |

- **Username:** `<your payout address>.<worker name>`. The address is where you are paid. The worker name is yours to choose.
- **Payout address type:** P2SH (`3…`), P2WPKH or P2WSH (`bc1q…`) or P2TR (`bc1p…`). **P2PKH (`1…`) is refused**: each such output costs 4 sigops and they could cost the pool a block.

You are credited at the payout address, on every node, whichever node you mine on. Check your balance on the [miner page](/miner.html).

Which node you use matters in two ways:

- **That node builds your jobs.** A dishonest node can put its own payee on your jobs. `ghost-audit` detects this ([Auditing your node](#ghost-audit)); it is built but not released yet. Until you run it, you are trusting the node you mine on. Running your own node removes that trust.
- **That node gets the transaction fees** of any block you find. If you run your own node, that is you.

## Why your coinbase may be small

Every block the pool finds pays up to 500 miners straight from its coinbase. A 500-output coinbase is about 22 KB. **Most mining firmware cannot safely take that.** Worse, sending some firmware too large a coinbase does not fail cleanly: on Bitmain and Avalon firmware it can corrupt the miner's memory or make it silently skip the job.

So each job carries a **slot class**: how many miner payouts its coinbase holds. The classes are 3, 9, 44, 143, 364 and 500 outputs (500 B, 730 B, 2.25 KB, 6.5 KB, 16 KB and 22 KB coinbases). A block your miner finds pays at most as many balances as your class allows. Your **credit** does not depend on your class: every share is credited the same way. What the class changes is how many owed balances a block you find can pay, and so how much of that block's reward goes to the treasury as change (see [The payout rule](#payouts)).

## Firmware compatibility

These are the known-safe ceilings the node uses. They come from published source code, official firmware images and OCEAN's public blocks. **None of them was measured on our own hardware.** Ceilings are raised only by tests.

| Hardware | Safe coinbase ceiling | About this many miner outputs | Evidence |
|---|---|---|---|
| Stock Antminer S19 (Amlogic board, the common one) | about 730 B | 9 | OCEAN's code and talk only; image encrypted |
| Antminer S19 XP (CVITEK board) | 2,048 B | 40 | Disassembly of Bitmain's official image; stack overflow beyond |
| Antminer S21 | about 2,250 B | 44 | OCEAN's code and talk; image encrypted |
| Antminer S9, S11, S17, T17, S19 XP Zynq | about 7,650 B | 170 | Bitmain source; memory overwrite beyond |
| Avalon (2014-2025, incl. A15, Nano 3s) | 6,144 B | 135 | Canaan source; oversize jobs silently skipped |
| Whatsminer | about 6,500 B | 143 | OCEAN's code ("tested") |
| Bitaxe ESP-Miner up to v2.15 | large (first part at most 1,024 B) | 500 | ESP-Miner source |
| Bitaxe ESP-Miner main, NerdQAxe | about 7,600 B | 170 | Source: 16 KB `mining.notify` line limit |
| ePIC, Braiins OS | 16 KB or more | 364-500 | OCEAN's code; Braiins "not extensively tested" |
| NiceHash | about 500 B | 3 | OCEAN's code |

"About this many outputs" assumes P2TR payees. A miner can only be given a class whose whole coinbase fits under its ceiling, so the class it ends up on can be lower than this column (an S21 at about 2,250 B fits the 44 class; an S19 at about 730 B fits the 9 class).

Some context from mainnet: of 12,000 recent blocks from all pools, none had 100 or more payout addresses. There is no public evidence that a stock S19 or S21 has ever hashed a 100-output coinbase. That is absence of evidence, not proof of a limit, but it is why the ceilings start low.

### Stratum V2 avoids the limit

On a **standard SV2 channel** the miner receives only a block header; the node builds the coinbase. Coinbase size never reaches the firmware, so a standard channel always gets the full 500-slot class. Only SV2 firmware such as Braiins OS can use this. Stock Antminers speak SV1 only.

### Known low-limit firmware is warned, not refused

If your SV1 firmware is on the list above with a ceiling below the full class, the node accepts it and warns you: at connect, in the node's monitoring, and on the miner page, naming the model and what the limit is expected to cost. Blocks it finds will pay fewer balances and send more to the treasury. You are not refused.

## The sensing loop

A node cannot know for certain what your firmware can carry. A valid share proves the firmware built that coinbase; nothing proves what it can't. So the node feels its way up, per connection:

1. **Identify.** The node looks your miner up by its user agent (for SV1, sent by the translator; for native SV2, the vendor and firmware fields of the connection setup). An unknown miner gets the smallest class only.
2. **Start small.** Every miner starts at the smallest class, 3 outputs.
3. **Step up.** After **20 valid shares** at a class, the node tries the next class up.
4. **Never past the ceiling.** It never tries a class larger than your model's known-safe ceiling from the table, however well the miner is doing.
5. **Drop back on failure.** If the miner shows a sign of failure while a larger class is being tried, such as disconnecting or no longer returning valid shares on the new work, the node drops back to the last class that worked and stays there.
6. **Settled is settled.** A disconnect counts as a failure only while a class is being tried. Once a miner has settled, a dropped connection resumes at the settled class.

A miner can under-report what it can carry; nothing in the protocol prevents that, but under the exact-payment rule it should gain nothing by it. A miner can't make the node exceed its model's ceiling.

## What you can check today

- Your balance: the [miner page](/miner.html).
- Whether your node pays you honestly: [`ghost-audit`](#ghost-audit), built but not released yet.

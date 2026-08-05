# Hazync sync

*Reaching the chain tip from a zero-knowledge proof that the chain was valid, instead of validating every block yourself. The node loads a UTXO set it never built, on the authority of a proof, and validates normally from there onward.*

## The problem

A new Bitcoin node validates roughly a billion transactions to learn a single fact: which coins exist. Days of CPU, hundreds of gigabytes of download, to arrive at a few gigabytes of answer. Every node repeats the same work, and the work grows every year.

Bitcoin Core already offers a shortcut, `assumeutxo`: load a UTXO snapshot and start from there. But it is checked against a hash the Core developers computed and compiled into the binary. That is a reasonable engineering compromise and an honest one — Core documents it clearly — but it is a trust assumption. You are believing a number chosen by people, not a fact about the chain.

Hazync replaces the number with a proof.

## What replaces what

| | Core `assumeutxo` | Hazync sync |
|---|---|---|
| Which heights are allowed | Those compiled into the binary | Any height a proof covers |
| What the set is checked against | `hash_serialized`, chosen by developers | Utreexo accumulator roots a zk proof commits to |
| What you are trusting | That the developers picked the right hash | That the guest program is the consensus rules, and that the proof verifies |
| Background validation | Re-validates 1..N to confirm | None — that is the work being replaced |

The trust does not vanish; it moves. You stop trusting a chosen constant and start trusting that a published program implements Bitcoin's rules and that a proof of its execution verifies. That program is public, reproducible, and pinned by an image id the node checks before it will look at a proof at all.

## The three things that must be true

Adoption is deliberately built as three separate checks, because each can fail independently and each has its own failure message.

### 1. The proof verifies, and is anchored at genesis

`-hazyncproof=<file>` verifies a range proof and reports the state it commits to. Verification is delegated to the Rust implementation the Hazync project's CI exercises on every push, over a C ABI — not reimplemented in C++, which would be a large body of consensus-critical code drifting from the one that is actually tested.

There is deliberately **no "verified but not anchored" success case**. A proof of some arbitrary mid-chain range proves nothing about *this* chain, so anchoring is folded into the return code rather than offered as a separate flag a caller could forget to check.

The guest image id is **pinned** in the binary and compared before the proof file is even read. A verifier built against a superseded guest is a build error, not a confusing proof rejection.

### 2. The UTXO set is the one the proof commits to

`-hazyncutxo=<dump>` checks a set of coins against the accumulator roots the proof attests to.

This is the step that makes the snapshot *proven* rather than trusted. It cannot be done with a Core-format snapshot alone: the accumulator deletes by swap-and-shrink, so a leaf's position depends on the entire history that produced the set, and Core's snapshot carries coins without positions. The dump is therefore an intermediate that carries them.

The check runs on the consuming side, never in whatever produced the dump. A producer that verifies its own output moves the trust to the producer, which is the arrangement being replaced.

### 3. The operator asked for it, twice

Adoption is off unless the node was started with `-hazyncadopt` **and** the `hazyncadoptsnapshot` RPC is called. Neither alone adopts anything.

It cannot be a startup action: the base block must already be in the node's headers chain, and a node that has just started has only genesis. Call it once headers have synced.

## Using it

```sh
ghostd -hazyncproof=/path/proof.snark \
       -hazyncutxo=/path/dump.bin \
       -hazyncadopt
```

Then, once headers have synced past the proven height:

```sh
ghost-cli -rpcclienttimeout=0 hazyncadoptsnapshot
```

A node will tell you what it is standing on:

```json
"hazync": {
  "provenheight": 220000,
  "proventip": "0000000000000...",
  "guestid": "4722cec826239c1b...",
  "utxoleaves": 3567901,
  "utxodumpmatched": true,
  "adoptionarmed": true,
  "actedon": true
}
```

`adoptionarmed` and `actedon` are separate on purpose. Armed is not adopted — a node merely *permitted* to adopt must not read as though a proof is holding it up. The whole object is absent when no proof was accepted.

## What a proof-adopted node does not do

**It does not run background validation.** Core keeps a second chainstate that re-validates 1..N to confirm its trusted snapshot. Here that chain has already been validated, under real consensus, by the guest the proof was verified against. Re-downloading it is precisely the work the proof exists to replace, so it is not merely skipped — it is refused.

Consequently the node stays snapshot-based permanently, and the empty background chainstate directory stays on disk, disabled. That is an honest record that the chain below the base was never validated here, not an oversight.

**It does not keep the exemption across a restart.** The authority is re-derived from the proof on every start. A node restarted without its proof stops and says so, naming the flags it was adopted under. The exemption is a claim that must still hold, not a property the chainstate acquired once.

**It cannot serve historical blocks** below the adopted height, and stops advertising that it can.

## Trust model

What you are relying on, stated plainly:

- **The guest program is Bitcoin's consensus rules.** It compiles Core's real script verification, sighash and libsecp256k1. It is public and reproducible; the id in your binary either matches the published one or the build fails.
- **The proof verifies and is anchored at genesis.** Not "some range was proved" — the range starts at block 1 from an empty UTXO set.
- **The set you load is the set the proof commits to.** Established by rebuilding the accumulator, not by comparing against a chosen hash.

What you are *not* relying on: any value chosen by the developers of this software, any peer's honesty, or any snapshot provider.

## Limitations

- **The journal commits no transaction count.** An adopting node therefore has no attested figure for the cumulative transaction count at the adopted height, and substitutes a proven lower bound. It is not consensus-relevant, but it feeds progress estimation, so such a node **under-reports `verificationprogress`** until the chain catches up.
- **A proof cannot be checked against an arbitrary third-party snapshot** — only against one accompanied by accumulator positions from a source tracking the same accumulator. An order-independent digest committed beside the roots would remove that restriction.
- **Mainnet only.** The guest compiles mainnet chain parameters; another network needs a different guest and therefore a different image id.
- **Byte-identical acceptance is not yet demonstrated at scale.** That an adopted chainstate matches one built by validating every block has been shown at a low height, not at a height with real transaction volume. That is a question of proving time, not of code.

## Source

- Node side: `src/haze/hazync_proof.{h,cpp}`, `src/validation.cpp`
- Verifier and set-binding: the Hazync project's `verifier-ffi`
- Related: [Haze](#haze) — the storage mode whose *validity* gap a proof closes

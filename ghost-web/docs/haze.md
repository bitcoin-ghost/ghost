# Haze

*The state of a Ghost node whose historical archive has been irreversibly stripped of arbitrary embedded content. Witness blobs, OP_RETURN payloads, scriptSig data, and coinbase messages are not on disk and cannot be reconstructed locally. The structural economic graph — who paid whom, how much, when — is fully preserved.*

## The problem

The Bitcoin blockchain accepts arbitrary data through several vectors: OP_RETURN outputs, witness fields (Ordinals inscriptions live here), bare-multisig scriptSig stuffing, coinbase scriptSig, even crafted address encodings. Over the years, those vectors have been used for everything from harmless metadata to material that's flatly illegal in most jurisdictions, including CSAM.

Every full archive node operator stores all of it on disk in plaintext. They didn't put it there; they didn't want it there; they have no realistic way to know it's there in any specific block. Strict-liability statutes in most jurisdictions don't care:

- US: 18 U.S.C. § 2252
- UK: Protection of Children Act 1978
- EU: Directive 2011/93/EU

Possession is the offence. Intent and knowledge don't enter the picture. A single high-profile prosecution targeting a node operator could trigger mass node shutdowns and damage Bitcoin's decentralisation badly.

Ghost Haze removes the data from disk. Not encrypts it. Removes it. Bitcoin's existing cryptographic commitments — txids, witness commitments, merkle roots — already prove that the destroyed content existed and was validated. Nothing about the chain breaks; the chain's structure is exactly preserved. What's gone is the *contents* of fields that don't influence ownership.

## The three pieces

Three distinct things, often confused:

| Name | What it is | When it runs |
|---|---|---|
| **Haze** | The *state* of a node whose archive has been stripped — the result, not a process. | Always (as long as the node is in `Hazed` mode). |
| **Exorcism** | The *runtime process* that strips block data before writing to disk. Validates in RAM, persists only structural data. | Every block, in real time, during the validation pipeline. See [Exorcism](#exorcism). |
| **Exorcist** | The *one-shot conversion tool* that takes an existing full archive and turns it into a hazed archive. | Once, when an operator wants to migrate. See [Exorcism — The Exorcist section](#exorcism). |

This doc covers Haze: the steady-state condition of the node and what its archive looks like. Exorcism explains the runtime mechanics. The Exorcist tool is documented in the Exorcism page since it's a one-time operation.

## What stays, what goes

When a block is hazed (either at runtime via Exorcism or one-shot via the Exorcist), four categories of data are stripped:

| Stripped | Why it was there | Why it can go |
|---|---|---|
| **Witness data (~200 GB across the chain)** | Schnorr/ECDSA signatures, Tapscript, inscription payloads | Signatures already verified at block acceptance; their work is done. Inscription content has zero relevance to ownership. |
| **scriptSig data (~75 GB)** | Legacy (pre-SegWit) input signatures | Same — already verified, no longer load-bearing. |
| **OP_RETURN payloads (~3 GB)** | Application-layer data: Runes, Omni, OpenTimestamps | Every protocol that uses OP_RETURN runs its own indexing infrastructure. Bitcoin nodes are not the canonical archive for application data. |
| **Coinbase arbitrary data (~0.06 GB)** | Pool tags, miner messages | Zero operational value. The coinbase tag was already broadcast across the network when the block was mined; it doesn't need to live on every node forever. |

Total stripped: roughly **278 GB** of the ~720 GB chain at the time of writing. Everything else stays:

- Block headers, prev-hash links, version, timestamp, nonce, merkle root.
- Every transaction's structural skeleton: version, locktime, input count, output count.
- Every output's amount and `scriptPubKey` (the locking script — the address).
- Every input's outpoint reference (which UTXO is being spent) and sequence number.
- Coinbase amount and outputs (the "who got paid" half), just not the scriptSig blob.

Net result: a hazed archive is roughly **195 GB compressed**, vs ~718 GB for a full archive. You can still answer "is address X owed Y satoshis at height H" from a hazed archive. You cannot reconstruct an inscription image out of one.

## The three modes

Configured in `pool.toml`:

```toml
[storage]
haze_mode = "Standard"   # Standard | Hazed | FullArchive
```

| Mode | Behaviour |
|---|---|
| `Standard` | Default Bitcoin Core behaviour with Ghost pool integration. No stripping. (Same disk footprint as plain Bitcoin Core, but with Ghost's pool-mining stack on top.) |
| `Hazed` | Ghost Haze + Exorcism active. Hazeable content stripped at runtime; existing archive can be converted via the Exorcist tool. |
| `FullArchive` | Full archive retained, plus the daily-checkpoint infrastructure for faster IBD. For operators who accept the legal risk in exchange for serving raw data to peers. |

The mode is sticky — a hazed node writes `gsb*.dat` files (Ghost Stripped Block format) instead of `blk*.dat`. Once a node is hazed, the unstripped originals were never on disk; reverting requires resync from a full-archive peer.

## Side-by-side

| Attribute | Hazed | Full Archive |
|---|---|---|
| Storage | ~195 GB (compressed) | ~718 GB |
| IBD via snapshot sync | ~3 min to usable | ~15 min to usable |
| IBD from genesis | ~35 min | ~3.5 h |
| Monthly growth | ~2 GB | ~6.5 GB |
| Legal liability for embedded content | None — content physically absent | Full — present in plaintext |
| Transaction graph | Complete | Complete |
| UTXO set | Complete | Complete |
| Historical signatures | Absent (committed by txid/wtxid) | Present |
| Historical OP_RETURN data | Absent (committed by txid) | Present |
| Serves hazed peers | Yes | Yes |
| Serves Bitcoin Core peers | Structural only; redirects raw requests | Yes (full blocks) |

## Why this works without consensus changes

Three properties make Haze safe inside Bitcoin's existing rules:

1. **Bitcoin's cryptographic commitments are stronger than anything we'd add.** Every transaction's `txid` already commits to its scriptSig. Every block's witness commitment commits to all witness data. The merkle root commits to every transaction. Stripping the data after validation doesn't break any commitment — the data is "remembered" by the txid that exists, just not by raw bytes anyone can read.
2. **Validation always uses the full block.** Stripping happens *after* the block has passed every consensus check. The chain remains consensus-valid. The disk just doesn't keep some of the bytes.
3. **No custom records added.** A hazed node doesn't add per-field haze hashes or per-block "what we stripped" metadata. There's nothing to forge or canonicalise. The proof that stripped content existed is the unchanged Bitcoin commitment that already existed.

The diff between Hazed and full-archive Bitcoin Core is a small change in the block-write path, no consensus rules touched. From the network's perspective, hazed nodes are normal full nodes that happen to serve a stripped form on request.

## Operational lifecycle

A hazed node's life looks like this:

```
1. Operator picks haze_mode = "Hazed" in pool.toml at first launch.
2. Node syncs from peers — could be hazed peers (fast, structural-only)
   or full peers (still works; received blocks pass through Exorcism
   on this side and only the stripped form lands on disk).
3. From the very first block written, only structural data is on disk.
4. Routine operation: blocks arrive, validate in RAM, write structural,
   zero RAM. Exorcism is invisible from the outside.
5. If the operator wants to share the archive (e.g. seed a new peer),
   they ship gsb*.dat files. Recipients in Hazed mode load them directly.
```

If the operator started in full-archive mode and now wants to convert: run the Exorcist tool. It walks the existing `blk*.dat` files, strips each block, writes the structural archive, generates a Legal Compliance Packet documenting what was stripped and when, and deletes the originals. The conversion is **not reversible without resync** — the unstripped originals are gone after the Exorcist completes its verify-then-delete pass.

## What hazed nodes can and can't serve

When a peer asks a hazed node for a block, the node returns the stripped structural form. For most peers — wallets verifying receipt, other hazed nodes, light clients — this is exactly what they need. The transaction graph, the amounts, the addresses, the merkle proof of inclusion — all preserved.

When a peer asks specifically for a transaction's witness data (e.g. for inscription rendering or signature replay), a hazed node has nothing to send. Two options the network has:

1. **Redirect to a full-archive peer.** Hazed nodes know which of their peers are full-archive and can refer the requester. The requester gets the data; the hazed node didn't store it.
2. **Refuse.** Some nodes operate in environments where redirecting is itself a liability concern. Refusal is consistent with Bitcoin's protocol-level "this peer doesn't have what you want" semantics.

For a node validating the chain, neither matters: validation only needs the full witness during block acceptance, and it has it then (the block arrives over the wire fully formed). Witness data only becomes "missing" *after* validation, when it's been stripped from disk.

## Reorgs, restarts, and the limits of stripped storage

Stripped storage is enough to *undo* a block and not enough to *apply* one, and almost everything about how a hazed node behaves at the edges follows from that asymmetry.

**Undoing needs nothing haze removes.** The disconnect path reads no scriptSig and no witness — it walks outputs and prevouts, both preserved, and the undo data it works from is written whether or not the block was stripped. So a hazed node reorgs off its own history normally, and its reorg depth is bounded by how long undo files are kept, exactly as on a pruned node.

**Applying a block needs five things stripping destroys:** script verification, the BIP34 coinbase height, the BIP141 witness commitment, the block weight, and the sigop cost. No amount of care recovers them locally. A block rebuilt from stripped storage is therefore allowed to be disconnected and refused outright if anything tries to connect it.

That produces three behaviours worth knowing about:

- **Transactions from a disconnected stripped block do not return to the mempool.** They have no signatures, so they are no longer signable or relayable transactions by anyone — re-adding them would queue objects certain to be rejected. Anything still wanted must be re-broadcast by its owner. The node logs this each time rather than leaving it to be discovered.
- **Wallets are still told correctly.** A rebuilt block cannot compute its own transaction ids — for anything that had a scriptSig, the computed id belongs to a different transaction — so the real ids are carried alongside it and wallets mark their own transactions unconfirmed by those. A wallet on a hazed node does not silently keep showing a reorged-away transaction as confirmed.
- **Reorging back onto an abandoned branch re-downloads it.** The node cannot apply blocks it only holds in stripped form, so it asks peers for them again. The re-fetched block passes back through Exorcism and is stripped again before anything is written, so nothing hazeable is retained — the same posture as validating it the first time.

**After an unclean shutdown, some blocks are downloaded again.** A block's stripped form is written before it is connected. If the node stops in between, what survives is a block it cannot apply, so it forgets it and fetches it again. Typically a handful of blocks, and no full block is ever kept on disk to avoid it — which would defeat the entire point.

> **One surprising consequence:** because the node genuinely deletes block data in that case, it records that fact the same way a pruning node does, and `getblockchaininfo` will report `pruned: true`. It has not started pruning in the ordinary sense and has not deleted any block *file*; the flag records that some block data it once held is gone. See below.

## What Haze isn't

- **It isn't pruning.** Pruned nodes delete entire old block files; they can't serve any block to anyone. Hazed nodes keep every block file on disk and can still serve them — just in stripped form. A hazed node is a full participant in the network; a pruned node is a leaf. (A hazed node may still report `pruned: true` after discarding a block it could not apply — see the section above. That flag is about data having been deleted, not about running in pruned mode.)
- **It isn't encryption.** The hazeable content is removed, not protected by a key. There's no "decrypt with password" path. The data is gone.
- **It isn't selective.** A hazed node doesn't pick and choose which content to strip — every hazeable field is stripped from every block. Selectivity would create the illusion of control over content classification, which is exactly the legal risk the design wants to eliminate.
- **It isn't a wallet feature.** Wallets don't care whether the underlying node is hazed. UTXOs, balances, addresses, history — all available either way. Haze is purely about disk-side data.
- **It isn't censorship.** The block was already mined and broadcast; the data was already on the network at some point. Hazed nodes don't refuse to validate, mine, or relay anything. They just don't keep the application-data bytes after the chain has moved on.
- **It isn't a way to "delete bad stuff" from the chain.** The block headers, txids, and witness commitments still exist. What's gone is one node's *local copy* of the underlying bytes. Other full-archive nodes may still have them.

## What it doesn't protect against

- **Compelled disclosure of running memory.** Hazeable content exists in RAM during validation. A live process dump could capture it. The mitigation is to keep the validation window short and to zero RAM after writing, both of which Exorcism does — but a memory-acquisition warrant on a running node is outside the threat model.
- **Operator running unverified code.** A modified ghost-core build could secretly write hazeable content elsewhere before the SecureZero pass. Operators are responsible for verifying their binaries against the open source.
- **Network-layer surveillance.** When a block arrives over the P2P wire, the full block traverses the operator's network interface. ISPs and middleboxes could capture in transit. Mitigation: peer over Tor (`-tor=1`) or i2p; block-level encryption between nodes; Bitcoin Core's V2 transport.
- **Future jurisdictional changes.** A jurisdiction could pass a statute making *the act of stripping* a regulated activity. Operators in that jurisdiction would have to choose between full-archive (with the existing strict-liability problem) and stopping running a node altogether. There's no legal answer that's robust against arbitrary future law.

## Source

| File | Purpose |
|---|---|
| `ghost-core/src/haze/exorcism.{h,cpp}` | Runtime stripping (see [Exorcism](#exorcism)) |
| `ghost-core/src/haze/block_stripper.h` | Per-field stripping logic |
| `ghost-core/src/haze/stripped_block.h` | GSB on-disk format |
| `ghost-core/src/haze/legal_packet.h` | Legal Compliance Packet generator |
| `ghost-core/src/node/blockstorage.cpp` | `gsb*.dat` FlatFileSeq integration |
| `crates/ghost-common/src/config.rs` | `storage.haze_mode` config field |

Companion docs: [Exorcism](#exorcism) for the runtime process, [Pruning](#pruning) for related disk-management concepts.

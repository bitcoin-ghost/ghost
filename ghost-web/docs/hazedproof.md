# HazedProof & the Proof-Backed Wallet

*How a hazed node — which has thrown away witnesses and scriptSigs — stays fully wallet-capable for every coin type, by spending from a proven UTXO set instead of from transaction history.*

## What HazedProof is

Haze (see [Exorcism](exorcism.md) / [Haze](haze.md)) validates every block in full, then permanently strips the non-consensus, potentially-hazardous data — witnesses, scriptSigs, OP_RETURN payloads, coinbase scriptSig — writing a stripped block (`.gsb`) to disk. The node keeps the **economic graph** (who paid whom, how much, to which script) and the **live UTXO set**, but not the raw spending data.

**HazedProof** is the endgame: a recursive **validity proof** that attests the retained state (the UTXO set / its commitment) is the correct result of applying every valid block from genesis. It lets a node be trusted — and bootstrap fast ("zero-sync") — without re-downloading or re-validating history. The witness was scaffolding on a deadline: kept only long enough to be proven, then discarded.

This document specs the **wallet-facing payoff** of that design: the *proof-backed UTXO wallet path*, which closes the one real gap hazed nodes otherwise have.

## The problem it solves

A stripped transaction can only have its **txid** recomputed when its scriptSig was empty — i.e. **native SegWit**. For **legacy** spends and the **coinbase**, the scriptSig is part of the txid preimage and is gone, so the txid is *stored* but the reconstructed transaction object no longer hashes to it.

Bitcoin Core's wallet is **transaction-centric**: `mapWallet` is keyed on `tx.GetHash()`, and spend-tracking, conflict detection and on-disk serialization all re-derive that key from the transaction itself. So the wallet can only hold receives whose transaction it can faithfully reconstruct — **SegWit only**. A legacy or coinbase receive can be *reported* by the address index but cannot be held as a spendable wallet entry, because there is no transaction object that both carries the coin and hashes to the real txid (forging one is a SHA256d preimage — infeasible).

:::warning This is a data limitation, not a bug
The block-reconstruction rescan shipped in v1.10.23 is **complete for SegWit** and honestly skips + counts the rest (`unreconstructed_hazed_txs`). No amount of implementation makes a legacy transaction re-hash from stripped data — the bytes are gone by design.
:::

## Key insight: you spend outputs, not transactions

To **spend** a coin you never need the transaction that created it. You need exactly four things:

1. the **outpoint** `(txid, vout)`,
2. the **scriptPubKey** being spent,
3. the **amount**, and
4. your **key**.

Both sighash flavours (legacy and SegWit) are satisfied by the scriptPubKey (+ amount) of the *output being spent* — never the originating transaction's scriptSig/witness. Core drags the whole transaction around only because of its tx-centric bookkeeping; it is a *software* constraint, not a cryptographic one.

**A hazed node already holds all four for every coin**: the UTXO set is retained, and the address index exposes `(authoritative txid, vout, height, value, scriptPubKey)` — with the txid taken from the **UTXO set**, not from a reconstructed transaction. So the fix is not to un-strip data or store more in the block. The things we "include" are the ones we already keep (the UTXO set) and generate (the proof); the change is teaching the **wallet** to hold **proof-backed UTXOs** instead of transactions.

## Design: the proof-backed UTXO wallet path

### 1. Enumeration
For each watched scriptPubKey, enumerate unspent outputs from the address index (`getaddressutxos` / `scanaddressindex`): `{txid, vout, height, value, scriptPubKey}`. The txid is authoritative (UTXO-set-derived), independent of transaction reconstruction, so it is correct for **legacy, coinbase and SegWit alike**.

### 2. Proof binding (what makes trusting the coin sound)
Each UTXO carries a **proof handle**:
- **Self-validated hazed node** — the node validated every block before stripping; the coin's presence in its live `CCoinsView` *is* the attestation.
- **Zero-sync / fast-bootstrapped node** — the coin is accompanied by an **inclusion proof** against the UTXO-set commitment that the HazedProof validity proof binds (a Utreexo-style accumulator root, or the UTXO-set Merkle root the proof commits to). The wallet accepts the coin **iff** the inclusion proof verifies against that committed root.

This is the hinge: the proof elevates the coin from "trust this node's index" to "trust the validity proof" — required for light/zero-sync clients that never validated history themselves.

### 3. Storage — a coin record, not a tx record
Introduce a **UTXO-centric wallet record** keyed on the **outpoint**: `{value, scriptPubKey, height, proof_handle, is_mine/watch}`. It lives *alongside* `CWalletTx`, never replacing it:
- On a **full** node the wallet keeps using `CWalletTx` unchanged.
- On a **hazed** node the wallet populates coins from the index. SegWit coins may *additionally* get a reconstructed `CWalletTx` (for full history display); legacy/coinbase coins live **only** as coin records.

Crucially, this path **never constructs a transaction that lies about its hash** — it sidesteps transaction identity entirely, so no consensus-code contamination and no reload/serialization hazard.

### 4. Spending
Build the input from the outpoint; sign using the stored `scriptPubKey` + `amount` (PSBT-style, exactly what hardware wallets already do without a prevtx for SegWit; the scriptPubKey alone suffices for the legacy sighash). No originating transaction is fetched. Broadcast through the node.

### 5. Balance & history
- **Balance** = sum of unspent proof-backed coins — **complete and correct for all coin types**.
- **History** is best-effort for *display*: SegWit receives render in full (reconstructed); legacy/coinbase render honestly as "received `value` at height `H` (`txid…`)" from the index, without full provenance. Funds are complete; provenance display is partial — and clearly labelled as such.

### 6. Reorgs & consistency
The address index (and thus the coin set) tracks the active chain; on reorg the index updates and the wallet re-enumerates. A coin drops the moment the index marks its outpoint spent.

## Trust model summary

| Node type | Coin trust source | Legacy/coinbase spendable? |
|---|---|---|
| Full archive | own validation, full tx history | yes (classic path) |
| Hazed, self-validated | own validation + live UTXO set | **yes** (coin records) |
| Zero-sync / light | HazedProof validity proof + UTXO-set inclusion proof | **yes** (proof-verified coin records) |

## Where this sits in the roadmap

- The **serving layer** (address index) provides *enumeration*; **HazedProof** provides *trust*; this path provides *spendability*. Together they make a hazed node **fully wallet-capable for every coin type** — the differentiator that turns "cautious storage mode" into "no-compromise node."
- **Interim, pre-proof:** on a self-validated hazed node the coin set is already trustworthy from the node's own validation, so the coin-record path can ship ahead of the proof for self-hosted wallets; the proof is required only to extend it to fast-synced / light clients.
- **Interim fallback if this path is deferred:** the SegWit-complete block-rescan (shipped v1.10.23) + the address index for report-only legacy balances; optionally a stripping-policy tweak that retains standard P2PKH scriptSigs so ordinary legacy txids reconstruct (partial — P2SH/bare scripts can still carry data, so not a general answer).

:::info The clean resolution
The legacy/coinbase "gap" is not a half-built feature — it is the point at which a transaction-centric wallet meets a witness-free node. Moving the wallet to a **UTXO-centric, proof-backed** model resolves it by construction, and does so using exactly the artefacts HazedProof already produces.
:::

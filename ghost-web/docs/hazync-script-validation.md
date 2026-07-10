# Hazync Phase 3 — script validation scope

*The last big consensus rule Hazync does not yet enforce in-circuit. Today a spent
coin's `scriptPubKey` is **committed** (as a hash inside the coin leaf) but never
**executed** — the fold proves PoW, chain linkage, UTXO add/spend, and value
conservation, but not that the spender was actually authorised to spend. This is
the multi-month body of work.*

## Where it plugs in

Each spent input in `coin_tx*` currently proves the coin's leaf opens under the
accumulator root. Script validation adds one obligation per spent input:

> the spending input's witness/scriptSig **satisfies** the script whose hash is
> committed in the spent coin's leaf (`spk_hash`), evaluated against the sighash
> of this transaction.

So the coin commitment already binds the script; validation proves the unlock.

## The cost centre: signature verification over secp256k1

The dominant expense is **ECDSA / Schnorr verification in-circuit**. Bitcoin signs
over **secp256k1**, whose base field is *not* the Pallas/Vesta scalar field the
circuit arithmetises over. So every EC operation is **non-native (foreign-field)
arithmetic** — emulated secp256k1 field math over the native field — which is
where the millions of constraints go. This single primitive is why Phase 3 is
multi-month, not multi-week. Folding helps: one signature per fold step amortises
it, but per-step prover cost is high.

## Strategy: standard-template circuits first, general interpreter later

Bitcoin script is a ~100-opcode stack machine, but **>99% of real outputs are a
handful of standard templates**. Do not build a general interpreter first. Build
dedicated circuits per script type, ordered by value coverage:

| Priority | Type | What it needs in-circuit |
|---|---|---|
| 1 | **P2WPKH** | `HASH160(pubkey) == committed hash` + **ECDSA verify** over BIP143 sighash |
| 2 | **P2TR key-path** | **Schnorr verify** over BIP341 sighash (no hash-lock; simplest sig path) |
| 3 | **P2WSH** / **P2SH** | reveal + hash-match the witness/redeem script, then satisfy it |
| 4 | **P2PKH** (legacy) | as P2WPKH with the legacy (pre-segwit) sighash |
| 5 | bare multisig, `OP_RETURN` (unspendable), timelocks | small opcode set |
| 6 | **bounded general interpreter** | arbitrary scripts, opcode-by-opcode, capped step count |

P2WPKH + P2TR key-path alone cover the large majority of spends by count and value.

## Milestones (each is a self-contained, testable increment)

- **M1 — sighash gadget.** Compute the BIP143 (segwit) sighash in-circuit from the
  tx fields. Reuses the existing `sha256d` gadget; no new crypto. Foundational —
  every signature check consumes it. *(Smallest; do first.)*
- **M2 — secp256k1 non-native field.** Emulate secp256k1 base-field add/mul/inv
  over the native field, then point add/double/scalar-mul. **The big rock.** Everything
  cryptographic depends on it; budget the most time here and verify against a native
  oracle exhaustively before building on it.
- **M3 — ECDSA verify gadget.** M1 + M2 + `HASH160` → verify a signature for the
  P2WPKH path.
- **M4 — P2WPKH spend circuit, integrated into the tx fold.** Extend `CoinTxStep` /
  `CoinTxFanoutStep` so a spent input additionally proves script satisfaction. First
  end-to-end "authorised spend" milestone.
- **M5 — Schnorr verify + P2TR key-path.** Second signature scheme; unlocks taproot.
- **M6 — P2WSH/P2SH wrappers + bounded interpreter** for the residual non-standard
  scripts. Largest remaining piece; needed for full consensus coverage.

## A pragmatic middle ground worth a decision up front

Bitcoin Core itself ships **`assumevalid`**: it skips script/signature checks below
a trusted checkpoint height and only fully validates above it. Hazync can mirror
this: prove **structure + PoW + UTXO + value conservation** over all history, but
treat **scripts as assumed-valid below a height** and validate signatures only for
recent blocks. This slashes the proving burden by orders of magnitude while keeping
almost all of the trust-minimisation benefit (the expensive part — historical
signature re-verification — is exactly what `assumevalid` already skips network-wide).

**Recommendation:** land **M1 + M2** (the reusable foundations), then **M3 + M4**
for P2WPKH (highest-value coverage), and decide the `assumevalid` boundary before
committing to M5/M6. Full historical script validation for every input back to
genesis is the maximalist end state; `assumevalid`-style scoping is the practical
path to a shippable proof.

## Explicitly out of scope for the spike (tracked elsewhere)

- Variable-length tx serialisation / real witness parsing (currently fixed-shape).
- Non-`assumevalid` full opcode coverage (M6).
- The post-quantum backend swap (separate track — see `project_hazedproof` memory).

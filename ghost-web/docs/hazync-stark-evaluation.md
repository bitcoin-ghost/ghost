# Hazync: STARK evaluation (Raito / Cairo + stwo)

Measured 2026-07-12. This records why the in-circuit ECDSA line of work
(`ghost-hazync`, Nova/R1CS) is superseded by a Cairo + stwo STARK stack, and what
the real costs look like on both sides.

## The comparison that settles it

Verifying one ECDSA signature over secp256k1:

| Stack | Cost of one signature |
|---|---|
| Nova / R1CS (`ghost-hazync`, hand-built) | **10.11M constraints** |
| Cairo + stwo (Raito) | **2 `Secp256k1Mul` syscalls** |

The Nova figure is the *optimised* one. Baseline was 37.72M constraints; pinning the
modulus as a circuit constant, 4-bit fixed-window scalar multiplication, and GLV
endomorphism decomposition together bought 3.73x — and still landed at 10.11M per
signature. At that size a single signature needs a 2^24 commitment key, which is why
prover runs OOM-killed an 11 GiB box.

Cairo exposes secp256k1 as a **native builtin**, so the prover handles the curve
arithmetic directly. We were hand-building in-circuit exactly what this stack provides
for free. That is the whole argument for the pivot, and it is now measured rather than
assumed.

## Measured: real block validation (Raito client, `--features shinigami`)

Block 170 (`full_169.json`) — coinbase plus the Satoshi→Hal P2PK spend, the first real
transaction spend in Bitcoin's history:

```
OK   steps: 140,627   memory holes: 12,132
builtins: range_check 19,951, bitwise 72, poseidon 28
syscalls: Sha256ProcessBlock 22, Secp256k1Mul 2, Secp256k1New 1,
          Secp256k1Add 1, Secp256k1GetXy 1, Secp256k1GetPointFromX 1
```

`Secp256k1Mul: 2` is exactly the two scalar multiplications an ECDSA verify requires —
this is real signature verification executing, not a stub.

Header-only (`light_*`) fixtures, for reference: **4,929–8,137 steps** (21/21 pass). So
one real P2PK signature is roughly the difference between ~5k and ~140k steps.

## Cost scales with signatures, and that is the ceiling

Execution cost tracks signature count, so a modern block with a few thousand
transactions means thousands of `Secp256k1Mul` syscalls and a proportionally enormous
trace. Observed while climbing toward full blocks: a 48 MB trace with an 81 MB memory
dump, then an OOM kill on an 11 GiB box. Nothing is broken — the machine is simply too
small to execute a full modern block in one shot.

The consequence: **block-level execution must be sharded.** Script validation is
independently checkable per input, because each input carries its own
`previous_output.data`. The smallest *sound* unit is `(whole tx, one input index)` — not
a lone input — because the sighash for any input commits to the entire transaction.

## Trap: script validation is off by default

`packages/consensus/src/lib.cairo` gates the `script` module behind the `shinigami`
feature. With the feature **off**, it substitutes a stub:

```cairo
#[cfg(not(feature: "shinigami"))]
pub mod script {
    pub fn validate_scripts(header: @Header, txs: Span<Transaction>) -> Result<(), ByteArray> {
        Result::Ok(())
    }
}
```

A default `scarb test` or a default-built client therefore **never validates scripts** and
never compiles the script code at all. Consensus suite: 103 tests default, 105 with
`--features shinigami`. Any Raito benchmark or test result that does not name the feature
should be assumed not to have run the script engine.

## Upstream bug found and fixed

`validate_script` broke out of its per-input loop on the *first* input whose script
executed successfully, so inputs after index 0 were never checked — a transaction with a
valid input 0 and a forged script on any later input passed validation. It was flagged
in-code with a `// TODO: verify this is correct`.

Fixed: continue the loop on success, stop only on first failure; also propagate
`EngineImpl::new` errors instead of `.unwrap()`-panicking. Two regression tests added
using pure arithmetic scripts (no signatures needed). Branch
`fix/validate-all-tx-inputs`, commit `f32bb5b`, pushed to `defenwycke/raito`; candidate
for upstream PR to `starkware-bitcoin/raito`.

The feature gate is very likely why this survived: their own fixtures don't run the
script engine unless you opt in.

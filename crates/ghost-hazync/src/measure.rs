//! Constraint-count measurement harness (test-only).
//!
//! Prints the REAL R1CS constraint (and witness-variable) count of each gadget
//! on the in-memory `TestConstraintSystem` — small instances only, so it runs on
//! a memory-constrained box without ever building the full prover-scale circuit.
//! The full 256-bit `scalar_mul` and full ECDSA verify are *computed* from a
//! linear fit over small `scalar_mul` widths + measured component costs, never
//! synthesised at full size (that's what OOMs).
//!
//! Run:  cargo test -p ghost-hazync -- --ignored --nocapture measure_counts

#![cfg(test)]

use crate::ecdsa::{derive_u1_u2, enforce_rx_equals_r};
use crate::secp256k1_ec::{complete_add, point_add, scalar_mul, to_proj, Point};
use crate::secp256k1_field::{add_mod, alloc_fp, div_mod, inverse, mul_mod, sub_mod, to_bits_le};
use crate::secp256k1_scalar as scalarn;
use crate::test_cs::TestConstraintSystem;
use nova_snark::frontend::{AllocatedBit, Boolean, ConstraintSystem};
use nova_snark::provider::PallasEngine;
use nova_snark::traits::Engine;
use num_bigint::BigInt;

type Scalar = <PallasEngine as Engine>::Scalar;

fn bn(h: &str) -> BigInt {
    BigInt::parse_bytes(h.as_bytes(), 16).unwrap()
}
fn gx() -> BigInt {
    bn("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
}
fn gy() -> BigInt {
    bn("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
}
fn n() -> BigInt {
    scalarn::secp256k1_n()
}

/// Build `G` and `2G` (real on-curve points, so values stay well-formed).
fn g(cs: &mut TestConstraintSystem<Scalar>, tag: &str) -> Point<Scalar> {
    Point {
        x: alloc_fp(cs.namespace(|| format!("{tag}.x")), gx()).unwrap(),
        y: alloc_fp(cs.namespace(|| format!("{tag}.y")), gy()).unwrap(),
    }
}
fn two_g(cs: &mut TestConstraintSystem<Scalar>, tag: &str) -> Point<Scalar> {
    Point {
        x: alloc_fp(
            cs.namespace(|| format!("{tag}.x")),
            bn("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
        )
        .unwrap(),
        y: alloc_fp(
            cs.namespace(|| format!("{tag}.y")),
            bn("1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"),
        )
        .unwrap(),
    }
}

/// Run one gadget-builder against a fresh CS; return (constraints, witness vars).
fn count(f: impl FnOnce(&mut TestConstraintSystem<Scalar>)) -> (usize, usize) {
    let mut cs = TestConstraintSystem::<Scalar>::new();
    f(&mut cs);
    (cs.num_constraints(), cs.num_aux())
}

fn scalar_mul_width(w: usize) -> (usize, usize) {
    count(|cs| {
        let p = g(cs, "P");
        let bits: Vec<Boolean> = (0..w)
            .map(|i| {
                Boolean::from(
                    AllocatedBit::alloc(cs.namespace(|| format!("b{i}")), Some(i % 2 == 0)).unwrap(),
                )
            })
            .collect();
        let _ = scalar_mul(cs.namespace(|| "kP"), &bits, &p).unwrap();
    })
}

#[test]
#[ignore = "measurement harness — run explicitly with --ignored --nocapture"]
fn measure_counts() {
    // ---- primitive field ops (mod p) ----
    let f_mul = count(|cs| {
        let x = alloc_fp(cs.namespace(|| "x"), gx()).unwrap();
        let y = alloc_fp(cs.namespace(|| "y"), gy()).unwrap();
        let _ = mul_mod(cs.namespace(|| "m"), &x, &y).unwrap();
    });
    let f_add = count(|cs| {
        let x = alloc_fp(cs.namespace(|| "x"), gx()).unwrap();
        let y = alloc_fp(cs.namespace(|| "y"), gy()).unwrap();
        let _ = add_mod(cs.namespace(|| "a"), &x, &y).unwrap();
    });
    let f_sub = count(|cs| {
        let x = alloc_fp(cs.namespace(|| "x"), gx()).unwrap();
        let y = alloc_fp(cs.namespace(|| "y"), gy()).unwrap();
        let _ = sub_mod(cs.namespace(|| "s"), &x, &y).unwrap();
    });
    let f_inv = count(|cs| {
        let x = alloc_fp(cs.namespace(|| "x"), gx()).unwrap();
        let _ = inverse(cs.namespace(|| "i"), &x).unwrap();
    });
    let f_div = count(|cs| {
        let x = alloc_fp(cs.namespace(|| "x"), gx()).unwrap();
        let y = alloc_fp(cs.namespace(|| "y"), gy()).unwrap();
        let _ = div_mod(cs.namespace(|| "d"), &x, &y).unwrap();
    });
    let f_alloc = count(|cs| {
        let _ = alloc_fp(cs.namespace(|| "x"), gx()).unwrap();
    });
    let f_bits = count(|cs| {
        let x = alloc_fp(cs.namespace(|| "x"), gx()).unwrap();
        let _ = to_bits_le(cs.namespace(|| "b"), &x).unwrap();
    });

    // ---- scalar-field ops (mod n) ----
    let n_mul = count(|cs| {
        let x = alloc_fp(cs.namespace(|| "x"), gx() % n()).unwrap();
        let y = alloc_fp(cs.namespace(|| "y"), gy() % n()).unwrap();
        let _ = scalarn::mul_mod(cs.namespace(|| "m"), &x, &y).unwrap();
    });
    let n_inv = count(|cs| {
        let x = alloc_fp(cs.namespace(|| "x"), gx() % n()).unwrap();
        let _ = scalarn::inverse(cs.namespace(|| "i"), &x).unwrap();
    });

    // ---- EC ops ----
    let ec_add = count(|cs| {
        let p = g(cs, "P");
        let q = two_g(cs, "Q");
        let pp = to_proj(cs.namespace(|| "pp"), &p).unwrap();
        let qq = to_proj(cs.namespace(|| "qq"), &q).unwrap();
        let _ = complete_add(cs.namespace(|| "add"), &pp, &qq).unwrap();
    });
    let ec_padd = count(|cs| {
        let p = g(cs, "P");
        let q = two_g(cs, "Q");
        let _ = point_add(cs.namespace(|| "padd"), &p, &q).unwrap();
    });

    // ---- scalar_mul: linear fit over small widths ----
    let widths = [2usize, 4, 8, 16];
    let sm: Vec<(usize, usize)> = widths.iter().map(|&w| scalar_mul_width(w)).collect();
    // slope (constraints per scalar bit) from the two extreme measured widths.
    let (c_lo, w_lo) = (sm[0].0 as f64, widths[0] as f64);
    let (c_hi, w_hi) = (sm[3].0 as f64, widths[3] as f64);
    let per_bit = (c_hi - c_lo) / (w_hi - w_lo);
    let intercept = c_lo - per_bit * w_lo;
    let sm256 = (intercept + per_bit * 256.0).round() as i64;

    // ---- ECDSA assembly components ----
    let ec_derive = count(|cs| {
        let z = alloc_fp(cs.namespace(|| "z"), gx() % n()).unwrap();
        let r = alloc_fp(cs.namespace(|| "r"), gy() % n()).unwrap();
        let s = alloc_fp(cs.namespace(|| "s"), (gx() + BigInt::from(7)) % n()).unwrap();
        let _ = derive_u1_u2(cs.namespace(|| "u"), &z, &r, &s).unwrap();
    });
    let ec_rxchk = count(|cs| {
        let rx = alloc_fp(cs.namespace(|| "rx"), gx()).unwrap();
        let r = alloc_fp(cs.namespace(|| "r"), gx() % n()).unwrap();
        let _ = enforce_rx_equals_r(cs.namespace(|| "chk"), &rx, &r);
    });

    // verify_full = derive_u1_u2 + 2·to_bits_le + 2·scalar_mul(256) + point_add + rx-check
    let sig256: i64 =
        ec_derive.0 as i64 + 2 * f_bits.0 as i64 + 2 * sm256 + ec_padd.0 as i64 + ec_rxchk.0 as i64;

    let row = |name: &str, c: usize, a: usize| {
        println!("  {name:<34} {c:>12} {a:>12}");
    };
    println!("\n================= HAZYNC CONSTRAINT COUNTS (measured) =================");
    println!("  {:<34} {:>12} {:>12}", "gadget", "constraints", "witness");
    println!("  {:-<34} {:-<12} {:-<12}", "", "", "");
    row("alloc_fp (well-formed 256-bit)", f_alloc.0, f_alloc.1);
    row("mul_mod (mod p)", f_mul.0, f_mul.1);
    row("add_mod (mod p)", f_add.0, f_add.1);
    row("sub_mod (mod p)", f_sub.0, f_sub.1);
    row("inverse (mod p)", f_inv.0, f_inv.1);
    row("div_mod (mod p)", f_div.0, f_div.1);
    row("to_bits_le (256)", f_bits.0, f_bits.1);
    row("mul_mod (mod n)", n_mul.0, n_mul.1);
    row("inverse (mod n)", n_inv.0, n_inv.1);
    row("complete_add (projective)", ec_add.0, ec_add.1);
    row("point_add (affine)", ec_padd.0, ec_padd.1);
    for (i, &w) in widths.iter().enumerate() {
        row(&format!("scalar_mul({w} bits)"), sm[i].0, sm[i].1);
    }
    row("derive_u1_u2", ec_derive.0, ec_derive.1);
    row("enforce_rx_equals_r", ec_rxchk.0, ec_rxchk.1);
    println!("  {:-<34} {:-<12} {:-<12}", "", "", "");
    println!("  scalar_mul per-bit cost   : {:>12.0} constraints/bit", per_bit);
    println!("  scalar_mul(256) [computed]: {sm256:>12}");
    println!("  ---------------------------------------------------------------------");
    println!("  ONE ECDSA SIG (verify_full, computed): {sig256:>12} constraints");
    println!("  = derive_u1_u2 + 2·to_bits_le + 2·scalar_mul(256) + point_add + rx-check");
    println!("======================================================================");
    // Rough working-set guides (measured constraint count × observed ~1-1.5 GB/M).
    let gb_lo = sig256 as f64 * 1.0 / 1_000_000.0;
    let gb_hi = sig256 as f64 * 1.5 / 1_000_000.0;
    println!(
        "  Implied single-sig prover RAM (rough): ~{gb_lo:.0}-{gb_hi:.0} GB   (WSL2 ceiling ~5M constraints)"
    );
    println!("  Full block ~5,000 sigs: ~{} constraints\n", 5000i64 * sig256);
}

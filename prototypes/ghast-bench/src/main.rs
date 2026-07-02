//! GHAST Block Download — benchmark prototype.
//!
//! Tests the core speed hypothesis of the GHAST (Ghost + fast) block-download
//! design (see `docs/DESIGN_progressive_hazed_sync.md`): is columnar /
//! multi-pass block validation — specifically a single batched, parallel
//! signature pass over the whole chain segment — faster than traditional
//! row-wise, per-block validation?
//!
//! It also quantifies the two GHAST wins that do NOT depend on the batching
//! question:
//!   1. hazed bandwidth ratio (full blocks vs economic-graph-only bytes), and
//!   2. "time to usable" (Phantom / L1) from deferring the signature pass.
//!
//! All signatures are REAL secp256k1 ECDSA / Schnorr signatures over real
//! message digests that actually verify. Nothing about the crypto is mocked.
//!
//! Three strategies are timed over the IDENTICAL synthesized workload:
//!   A) row-wise, single-threaded   (naive baseline)
//!   B) row-wise, parallel per block (the STRONG baseline — what Bitcoin Core does)
//!   C) GHAST columnar: pass1 headers, pass2 UTXO (serial), pass3 ALL sigs
//!      collected up front and verified as one batched + parallel pass.

use rand::{rngs::StdRng, Rng, SeedableRng};
use rayon::prelude::*;
use secp256k1::{
    ecdsa::Signature as EcdsaSig, schnorr::Signature as SchnorrSig, Keypair, Message, PublicKey,
    Secp256k1, SecretKey, XOnlyPublicKey,
};
use std::collections::HashMap;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Data model — a synthetic chain segment held in memory.
// ---------------------------------------------------------------------------

/// A UTXO identifier. 36 bytes on the wire (32 txid + 4 vout), like Bitcoin.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct OutPoint {
    txid: [u8; 32],
    vout: u32,
}

/// One transaction input. Carries a REAL signature over `msg` that verifies
/// against `pubkey`. `schnorr_*` mirror the same authorisation with a Schnorr
/// signature so we can time ECDSA-parallel vs Schnorr separately.
struct Input {
    prevout: OutPoint,
    msg: [u8; 32],
    ecdsa_sig: EcdsaSig,
    pubkey: PublicKey,
    schnorr_sig: SchnorrSig,
    xonly: XOnlyPublicKey,
}

struct Output {
    outpoint: OutPoint,
    value: u64,
    // `script` stands in for the locking script / economic payload. Kept in the
    // economic graph (NOT stripped by Haze).
    script_len: usize,
}

struct Tx {
    inputs: Vec<Input>,
    outputs: Vec<Output>,
}

struct Block {
    header: [u8; 80], // real Bitcoin header size
    txs: Vec<Tx>,
}

// ---------------------------------------------------------------------------
// Wire-size accounting (for the hazed bandwidth ratio). These are the same
// component sizes Bitcoin uses, so the ratio is representative of the real
// witness-vs-economic split for this workload shape.
// ---------------------------------------------------------------------------

const HEADER_BYTES: usize = 80;
const OUTPOINT_BYTES: usize = 36; // 32 txid + 4 vout
const AMOUNT_BYTES: usize = 8;
const SEQUENCE_BYTES: usize = 4;
const ECDSA_SIG_BYTES: usize = 72; // DER sig, typical
const PUBKEY_BYTES: usize = 33; // compressed

/// Bytes of a FULL block: economic graph + the witness/signature column.
/// Economic part = header + per-input (outpoint+sequence) + per-output
/// (amount+script). Witness part = per-input (ecdsa sig + pubkey), i.e. the
/// authorisation data Haze can strip / defer.
fn block_sizes(block: &Block) -> (usize, usize) {
    let mut economic = HEADER_BYTES;
    let mut witness = 0usize;
    for tx in &block.txs {
        for _inp in &tx.inputs {
            economic += OUTPOINT_BYTES + SEQUENCE_BYTES;
            witness += ECDSA_SIG_BYTES + PUBKEY_BYTES;
        }
        for out in &tx.outputs {
            economic += AMOUNT_BYTES + out.script_len;
        }
    }
    (economic, witness)
}

// ---------------------------------------------------------------------------
// Workload generation. Every input gets a real key, a real digest, and a real
// ECDSA + Schnorr signature. Prevouts are pre-seeded into the initial UTXO map
// so the UTXO pass does genuine genesis->tip set churn (remove spent, insert
// created), exactly like connect-block.
// ---------------------------------------------------------------------------

struct Workload {
    blocks: Vec<Block>,
    initial_utxos: HashMap<OutPoint, u64>,
    total_sigs: usize,
}

fn generate(cfg: &Config, secp: &Secp256k1<secp256k1::All>) -> Workload {
    let mut rng = StdRng::seed_from_u64(0x6057u64.wrapping_add(cfg.seed));
    let mut blocks = Vec::with_capacity(cfg.blocks);
    let mut initial_utxos: HashMap<OutPoint, u64> = HashMap::new();
    let mut total_sigs = 0usize;
    let mut txid_ctr: u64 = 1;

    for _b in 0..cfg.blocks {
        let mut txs = Vec::with_capacity(cfg.txs_per_block);
        for _t in 0..cfg.txs_per_block {
            let mut inputs = Vec::with_capacity(cfg.inputs_per_tx);
            for _i in 0..cfg.inputs_per_tx {
                // A fresh prevout that "already exists" in the coin set.
                let mut txid = [0u8; 32];
                rng.fill(&mut txid);
                let prevout = OutPoint {
                    txid,
                    vout: rng.gen_range(0..4),
                };
                initial_utxos.insert(prevout, rng.gen_range(1..100_000_000u64));

                // Real key + digest + signatures.
                let mut sk_bytes = [0u8; 32];
                rng.fill(&mut sk_bytes);
                let sk = SecretKey::from_slice(&sk_bytes)
                    .unwrap_or_else(|_| SecretKey::from_slice(&[1u8; 32]).unwrap());
                let pubkey = PublicKey::from_secret_key(secp, &sk);
                let keypair = Keypair::from_secret_key(secp, &sk);
                let (xonly, _parity) = keypair.x_only_public_key();

                let mut digest = [0u8; 32];
                rng.fill(&mut digest);
                let msg = Message::from_digest(digest);

                let ecdsa_sig = secp.sign_ecdsa(&msg, &sk);
                let schnorr_sig = secp.sign_schnorr_no_aux_rand(&digest, &keypair);

                inputs.push(Input {
                    prevout,
                    msg: digest,
                    ecdsa_sig,
                    pubkey,
                    schnorr_sig,
                    xonly,
                });
                total_sigs += 1;
            }

            // A couple of created outputs per tx (new coins).
            let mut new_txid = [0u8; 32];
            new_txid[..8].copy_from_slice(&txid_ctr.to_le_bytes());
            txid_ctr += 1;
            let mut outputs = Vec::with_capacity(cfg.outputs_per_tx);
            for v in 0..cfg.outputs_per_tx {
                outputs.push(Output {
                    outpoint: OutPoint {
                        txid: new_txid,
                        vout: v as u32,
                    },
                    value: rng.gen_range(1..100_000_000u64),
                    script_len: 34, // ~P2WPKH/P2TR scriptPubKey size
                });
            }
            txs.push(Tx { inputs, outputs });
        }
        let mut header = [0u8; 80];
        rng.fill(&mut header[..]);
        blocks.push(Block { header, txs });
    }

    Workload {
        blocks,
        initial_utxos,
        total_sigs,
    }
}

// ---------------------------------------------------------------------------
// The UTXO transition (economic) pass — inherently serial, genesis->tip.
// Applies each block's spends/creates against a live coin set. Shared by all
// strategies so the economic work is identical everywhere.
// ---------------------------------------------------------------------------

#[inline]
fn apply_utxo(blocks: &[Block], base: &HashMap<OutPoint, u64>) -> u64 {
    let mut utxos = base.clone();
    let mut acc = 0u64; // consume the values so the work isn't optimised away
    for block in blocks {
        for tx in &block.txs {
            for inp in &tx.inputs {
                if let Some(v) = utxos.remove(&inp.prevout) {
                    acc = acc.wrapping_add(v);
                }
            }
            for out in &tx.outputs {
                utxos.insert(out.outpoint, out.value);
            }
        }
    }
    acc
}

/// Cheap header/PoW-shape pass (pass 1). Just touches every header serially.
#[inline]
fn header_pass(blocks: &[Block]) -> u64 {
    let mut acc = 0u64;
    for b in blocks {
        acc = acc.wrapping_add(b.header.iter().map(|&x| x as u64).sum::<u64>());
    }
    acc
}

// ---------------------------------------------------------------------------
// Strategies.
// ---------------------------------------------------------------------------

/// A) Row-wise, single-threaded: per block apply UTXO then verify each input's
/// signature inline, one core.
fn strat_a_rowwise_single(
    wl: &Workload,
    secp: &Secp256k1<secp256k1::All>,
) -> (u64, usize) {
    let _ = header_pass(&wl.blocks);
    let mut utxos = wl.initial_utxos.clone();
    let mut acc = 0u64;
    let mut verified = 0usize;
    for block in &wl.blocks {
        for tx in &block.txs {
            for inp in &tx.inputs {
                if let Some(v) = utxos.remove(&inp.prevout) {
                    acc = acc.wrapping_add(v);
                }
                let msg = Message::from_digest(inp.msg);
                if secp.verify_ecdsa(&msg, &inp.ecdsa_sig, &inp.pubkey).is_ok() {
                    verified += 1;
                }
            }
            for out in &tx.outputs {
                utxos.insert(out.outpoint, out.value);
            }
        }
    }
    (acc, verified)
}

/// B) Row-wise, parallel per block: identical block loop, but each block's
/// signatures are verified across the rayon pool. UTXO stays serial (as it must)
/// and blocks stay serial. This is what Bitcoin Core does — the strong baseline.
fn strat_b_rowwise_parallel(
    wl: &Workload,
    secp: &Secp256k1<secp256k1::All>,
) -> (u64, usize) {
    let _ = header_pass(&wl.blocks);
    let mut utxos = wl.initial_utxos.clone();
    let mut acc = 0u64;
    let mut verified = 0usize;
    for block in &wl.blocks {
        // UTXO transitions for this block: serial.
        for tx in &block.txs {
            for inp in &tx.inputs {
                if let Some(v) = utxos.remove(&inp.prevout) {
                    acc = acc.wrapping_add(v);
                }
            }
            for out in &tx.outputs {
                utxos.insert(out.outpoint, out.value);
            }
        }
        // This block's script checks: parallel (one join barrier per block).
        // Collect this block's inputs into a flat slice first, so the ONLY
        // difference from strategy C is the batch granularity (per-block here
        // vs whole-chain in C), not the collection strategy. Fair to B.
        let block_inputs: Vec<&Input> =
            block.txs.iter().flat_map(|tx| tx.inputs.iter()).collect();
        verified += block_inputs
            .par_iter()
            .filter(|inp| {
                let msg = Message::from_digest(inp.msg);
                secp.verify_ecdsa(&msg, &inp.ecdsa_sig, &inp.pubkey).is_ok()
            })
            .count();
    }
    (acc, verified)
}

/// C) GHAST columnar: pass1 headers, pass2 UTXO (serial genesis->tip), pass3
/// gather ALL signatures across the whole segment and verify them in ONE
/// batched + parallel sweep (a single rayon work-stealing pool over the entire
/// set, no per-block barriers).
fn strat_c_columnar(
    wl: &Workload,
    secp: &Secp256k1<secp256k1::All>,
) -> (u64, usize) {
    // Pass 1: headers.
    let _ = header_pass(&wl.blocks);
    // Pass 2: UTXO transitions, serial.
    let acc = apply_utxo(&wl.blocks, &wl.initial_utxos);
    // Pass 3: collect every input, verify as one homogeneous parallel sweep.
    let all_inputs: Vec<&Input> = wl
        .blocks
        .iter()
        .flat_map(|b| b.txs.iter())
        .flat_map(|tx| tx.inputs.iter())
        .collect();
    let verified = all_inputs
        .par_iter()
        .filter(|inp| {
            let msg = Message::from_digest(inp.msg);
            secp.verify_ecdsa(&msg, &inp.ecdsa_sig, &inp.pubkey).is_ok()
        })
        .count();
    (acc, verified)
}

/// C', Schnorr variant of pass 3: one parallel sweep of Schnorr verifications.
/// (rust-secp256k1 0.30 does not expose libsecp256k1's experimental
/// `schnorrsig_verify_batch`, so this is per-signature Schnorr verify spread
/// across the pool, not a single aggregate batch check. Reported separately and
/// honestly labelled.)
fn strat_c_schnorr(wl: &Workload, secp: &Secp256k1<secp256k1::All>) -> usize {
    let _ = header_pass(&wl.blocks);
    let _ = apply_utxo(&wl.blocks, &wl.initial_utxos);
    let all_inputs: Vec<&Input> = wl
        .blocks
        .iter()
        .flat_map(|b| b.txs.iter())
        .flat_map(|tx| tx.inputs.iter())
        .collect();
    all_inputs
        .par_iter()
        .filter(|inp| {
            secp.verify_schnorr(&inp.schnorr_sig, &inp.msg, &inp.xonly)
                .is_ok()
        })
        .count()
}

/// The "time to usable" (Phantom / L1) path: passes 1 + 2 only. UTXO set built,
/// signatures deferred. No verification.
fn time_to_usable(wl: &Workload) -> u64 {
    let _ = header_pass(&wl.blocks);
    apply_utxo(&wl.blocks, &wl.initial_utxos)
}

// ---------------------------------------------------------------------------
// Timing harness: warm up once, then median of N runs.
// ---------------------------------------------------------------------------

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

fn bench<F: FnMut() -> u64>(runs: usize, mut f: F) -> Duration {
    let _ = f(); // warm-up
    let mut times = Vec::with_capacity(runs);
    for _ in 0..runs {
        let start = Instant::now();
        let r = f();
        let e = start.elapsed();
        std::hint::black_box(r);
        times.push(e);
    }
    median(times)
}

// ---------------------------------------------------------------------------
// Config + CLI.
// ---------------------------------------------------------------------------

struct Config {
    // CPU benchmark (measured) workload.
    blocks: usize,
    txs_per_block: usize,
    inputs_per_tx: usize,
    outputs_per_tx: usize,
    runs: usize,
    seed: u64,
    // Multi-peer parallel-fetch model (analytical bandwidth math + measured CPU).
    chain_gb: f64,            // total full-block data of a realistic chain (decimal GB)
    economic_ratio: f64,      // economic-only fraction of full blocks (hazed strip)
    peer_mbps: f64,           // per-peer serve bandwidth (MB/s)
    downlinks_mbps: Vec<f64>, // downlink tiers to model (MB/s)
    peers_sweep: Vec<usize>,  // peer counts to sweep
}

impl Default for Config {
    fn default() -> Self {
        // Defaults ~= 360k signatures: finishes in a few minutes total.
        Config {
            blocks: 300,
            txs_per_block: 30,
            inputs_per_tx: 40,
            outputs_per_tx: 2,
            runs: 3,
            seed: 1,
            // ASSUMPTIONS (all CLI-overridable, all echoed in the output):
            //  - ~600 GB of Bitcoin full-block data today.
            //  - economic-only ratio ~0.29 (from the §9 hazed measurement:
            //    the witness/sig column is ~71% of block bytes).
            //  - 3 MB/s (= 24 Mbit/s) per peer connection.
            //  - two downlink tiers: 100 Mbit (~12.5 MB/s), 1 Gbit (~125 MB/s).
            chain_gb: 600.0,
            economic_ratio: 0.29,
            peer_mbps: 3.0,
            downlinks_mbps: vec![12.5, 125.0],
            peers_sweep: vec![1, 10, 20, 30, 40],
        }
    }
}

fn parse_f64_list(s: &str) -> Vec<f64> {
    s.split(',').filter_map(|x| x.trim().parse::<f64>().ok()).collect()
}
fn parse_usize_list(s: &str) -> Vec<usize> {
    s.split(',').filter_map(|x| x.trim().parse::<usize>().ok()).collect()
}

fn parse_args() -> Config {
    let mut cfg = Config::default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let key = args[i].trim_start_matches("--");
        let raw = args.get(i + 1);
        let val = raw.and_then(|s| s.parse::<usize>().ok());
        let fval = raw.and_then(|s| s.parse::<f64>().ok());
        match key {
            "blocks" => cfg.blocks = val.unwrap_or(cfg.blocks),
            "txs" | "txs-per-block" => cfg.txs_per_block = val.unwrap_or(cfg.txs_per_block),
            "inputs" | "inputs-per-tx" => cfg.inputs_per_tx = val.unwrap_or(cfg.inputs_per_tx),
            "outputs" | "outputs-per-tx" => cfg.outputs_per_tx = val.unwrap_or(cfg.outputs_per_tx),
            "runs" => cfg.runs = val.unwrap_or(cfg.runs),
            "seed" => cfg.seed = val.map(|v| v as u64).unwrap_or(cfg.seed),
            "chain-gb" => cfg.chain_gb = fval.unwrap_or(cfg.chain_gb),
            "economic-ratio" => cfg.economic_ratio = fval.unwrap_or(cfg.economic_ratio),
            "peer-mbps" => cfg.peer_mbps = fval.unwrap_or(cfg.peer_mbps),
            "downlinks-mbps" => {
                if let Some(s) = raw {
                    let l = parse_f64_list(s);
                    if !l.is_empty() {
                        cfg.downlinks_mbps = l;
                    }
                }
            }
            "peers" => {
                if let Some(s) = raw {
                    let l = parse_usize_list(s);
                    if !l.is_empty() {
                        cfg.peers_sweep = l;
                    }
                }
            }
            _ => {}
        }
        i += 2;
    }
    cfg
}

// ---------------------------------------------------------------------------
// Multi-peer parallel-fetch model (design §10).
//
// MEASURED: the CPU throughput of the header+UTXO passes (MB of economic graph
// verified per second), taken from the real time-to-usable run on the synthetic
// segment.
// MODELLED (analytical, NOT a real network): downloading the hazed economic
// graph from N peers, each serving `peer_mbps`, bounded by the local downlink.
//
// Integrity of each fetched height-range is checked CRYPTOGRAPHICALLY against
// its own header-PoW-committed merkle root — NOT by peer agreement — so a lying
// peer's range simply fails its merkle check and is re-requested elsewhere. Peer
// count buys SPEED + RESILIENCE, never trust.
// ---------------------------------------------------------------------------

fn run_bandwidth_model(cfg: &Config, cpu_mbps_measured: f64) {
    let economic_bytes = cfg.chain_gb * 1e9 * cfg.economic_ratio; // decimal GB
    let economic_mb = economic_bytes / 1e6;
    let full_mb = cfg.chain_gb * 1e9 / 1e6;
    // CPU (measured throughput) applied to the modelled real economic size.
    let cpu_time_s = economic_mb / cpu_mbps_measured;

    println!();
    println!("============== MULTI-PEER PARALLEL FETCH (design §10 model) ==============");
    println!("ASSUMED rates (all --overridable):");
    println!(
        "  chain full-block data    = {:.0} GB  (economic ratio {:.2} -> {:.0} GB hazed graph)",
        cfg.chain_gb,
        cfg.economic_ratio,
        economic_mb / 1000.0
    );
    println!(
        "  per-peer serve bandwidth = {:.1} MB/s ({:.0} Mbit/s) per connection",
        cfg.peer_mbps,
        cfg.peer_mbps * 8.0
    );
    println!(
        "  bytes to move: full IBD  = {:.0} GB   vs hazed {:.0} GB ({:.0}% less to download)",
        full_mb / 1000.0,
        economic_mb / 1000.0,
        (1.0 - cfg.economic_ratio) * 100.0
    );
    println!(
        "MEASURED CPU: header+UTXO passes verify {:.0} MB/s of economic graph (from §9 run)",
        cpu_mbps_measured
    );
    println!(
        "  -> modelled CPU time to build UTXO for the {:.0} GB hazed graph = {:.0} s ({:.2} h)",
        economic_mb / 1000.0,
        cpu_time_s,
        cpu_time_s / 3600.0
    );
    println!("  [network transfer = MODELLED bandwidth math; CPU rate = MEASURED]");

    for &downlink in &cfg.downlinks_mbps {
        println!();
        println!(
            "--- downlink tier: {:.1} MB/s ({:.0} Mbit/s) ---",
            downlink,
            downlink * 8.0
        );
        println!(
            "{:>6} {:>13} {:>13} {:>11} {:>10} {:>19}",
            "peers", "eff BW MB/s", "download", "dl speedup", "saturated", "total to-usable"
        );
        println!("{}", "-".repeat(76));
        let base_eff = cfg.peer_mbps.min(downlink); // N=1 baseline
        let base_dl = economic_mb / base_eff;
        for &n in &cfg.peers_sweep {
            let offered = n as f64 * cfg.peer_mbps;
            let eff = offered.min(downlink);
            let dl_time = economic_mb / eff;
            let saturated = offered >= downlink;
            let speedup = base_dl / dl_time;
            // Serial upper bound: download then verify (conservative; pipelined
            // they overlap toward max(dl, cpu) — noted in the doc).
            let total = dl_time + cpu_time_s;
            println!(
                "{:>6} {:>13.1} {:>11.0}s {:>10.2}x {:>10} {:>12.0}s ({:.2} h)",
                n,
                eff,
                dl_time,
                speedup,
                if saturated { "yes" } else { "no" },
                total,
                total / 3600.0
            );
        }
        let sat_peers = (downlink / cfg.peer_mbps).ceil() as usize;
        println!("{}", "-".repeat(76));
        println!(
            "  downlink saturates at ceil({:.1}/{:.1}) = {} peers; beyond that, added peers buy 0 speed (only resilience).",
            downlink, cfg.peer_mbps, sat_peers
        );
    }
    println!();
    println!("VERDICT (multi-peer): parallelism is linear ONLY until the downlink saturates.");
    println!("'How fast can we get' is bounded by YOUR pipe, not peer count. Extra peers past");
    println!("saturation give resilience (drop a slow/lying peer, re-request its range), not speed.");
}

fn throughput(sigs: usize, d: Duration) -> f64 {
    sigs as f64 / d.as_secs_f64()
}

fn main() {
    let cfg = parse_args();
    let secp = Secp256k1::new();
    let threads = rayon::current_num_threads();

    println!("=== GHAST Block Download — validation benchmark ===");
    println!(
        "config: blocks={} txs/block={} inputs/tx={} outputs/tx={} runs={} rayon_threads={}",
        cfg.blocks, cfg.txs_per_block, cfg.inputs_per_tx, cfg.outputs_per_tx, cfg.runs, threads
    );

    print!("generating workload (real keys + ECDSA + Schnorr sigs)... ");
    use std::io::Write;
    std::io::stdout().flush().ok();
    let gen_start = Instant::now();
    let wl = generate(&cfg, &secp);
    println!("done in {:.1}s", gen_start.elapsed().as_secs_f64());
    println!(
        "total inputs (signatures) = {} ({:.0}k)",
        wl.total_sigs,
        wl.total_sigs as f64 / 1000.0
    );
    println!();

    // --- Bandwidth accounting (hazed ratio) ---------------------------------
    let (mut economic_total, mut witness_total) = (0usize, 0usize);
    for b in &wl.blocks {
        let (e, w) = block_sizes(b);
        economic_total += e;
        witness_total += w;
    }
    let full_total = economic_total + witness_total;
    let hazed_ratio = full_total as f64 / economic_total as f64;
    let witness_frac = witness_total as f64 / full_total as f64 * 100.0;

    // --- Strategy timings ---------------------------------------------------
    println!("timing strategies (median of {} runs, after warm-up)...", cfg.runs);

    let sigs = wl.total_sigs;

    let t_a = bench(cfg.runs, || {
        let (acc, v) = strat_a_rowwise_single(&wl, &secp);
        assert_eq!(v, sigs, "strategy A must verify every sig");
        acc
    });
    println!("  [A] row-wise single-threaded : {:>8.3}s", t_a.as_secs_f64());

    let t_b = bench(cfg.runs, || {
        let (acc, v) = strat_b_rowwise_parallel(&wl, &secp);
        assert_eq!(v, sigs, "strategy B must verify every sig");
        acc
    });
    println!("  [B] row-wise parallel/block  : {:>8.3}s", t_b.as_secs_f64());

    let t_c = bench(cfg.runs, || {
        let (acc, v) = strat_c_columnar(&wl, &secp);
        assert_eq!(v, sigs, "strategy C must verify every sig");
        acc
    });
    println!("  [C] GHAST columnar batch     : {:>8.3}s", t_c.as_secs_f64());

    let t_cs = bench(cfg.runs, || {
        let v = strat_c_schnorr(&wl, &secp);
        assert_eq!(v, sigs, "Schnorr pass must verify every sig");
        v as u64
    });
    println!("  [C-schnorr] columnar Schnorr : {:>8.3}s", t_cs.as_secs_f64());

    let t_usable = bench(cfg.runs, || time_to_usable(&wl));
    println!(
        "  [Phantom/L1] passes 1+2 only : {:>8.3}s  (UTXO built, sigs deferred)",
        t_usable.as_secs_f64()
    );

    // --- Results table ------------------------------------------------------
    let base = t_b.as_secs_f64(); // speedups are vs the STRONG baseline B
    println!();
    println!("================================ RESULTS ================================");
    println!(
        "{:<30} {:>10} {:>14} {:>14}",
        "strategy", "median", "sigs/s", "speedup vs B"
    );
    println!("{}", "-".repeat(72));
    let row = |name: &str, d: Duration| {
        println!(
            "{:<30} {:>9.3}s {:>14.0} {:>13.2}x",
            name,
            d.as_secs_f64(),
            throughput(sigs, d),
            base / d.as_secs_f64()
        );
    };
    row("A row-wise single-threaded", t_a);
    row("B row-wise parallel (baseline)", t_b);
    row("C GHAST columnar batch (ECDSA)", t_c);
    row("C-schnorr columnar (Schnorr)", t_cs);
    println!("{}", "-".repeat(72));

    println!();
    println!("Hazed bandwidth:");
    println!(
        "  full block bytes     = {:>12} ({:.1} MB)",
        full_total,
        full_total as f64 / 1e6
    );
    println!(
        "  economic-graph bytes = {:>12} ({:.1} MB)",
        economic_total,
        economic_total as f64 / 1e6
    );
    println!(
        "  witness/sig column   = {:>12} ({:.1} MB, {:.1}% of full)",
        witness_total,
        witness_total as f64 / 1e6,
        witness_frac
    );
    println!(
        "  hazed ratio (full/economic) = {:.2}x  -> economic-only sync moves {:.0}% of the bytes",
        hazed_ratio,
        economic_total as f64 / full_total as f64 * 100.0
    );

    println!();
    println!("Time-to-usable (Phantom / L1):");
    println!(
        "  passes 1+2 (usable)      = {:>7.3}s",
        t_usable.as_secs_f64()
    );
    println!(
        "  full validation (B)      = {:>7.3}s",
        t_b.as_secs_f64()
    );
    println!(
        "  deferral speedup to usable = {:.1}x faster to a double-spend-safe UTXO set",
        t_b.as_secs_f64() / t_usable.as_secs_f64().max(1e-9)
    );

    println!();
    println!("Interpretation:");
    let c_vs_b = base / t_c.as_secs_f64();
    if c_vs_b >= 1.10 {
        println!(
            "  * Columnar batching (C) beats parallel-row-wise (B) by {:.2}x on this workload:",
            c_vs_b
        );
        println!("    one big work-stealing sweep amortises per-block join barriers.");
    } else if c_vs_b >= 0.95 {
        println!(
            "  * Columnar batching (C) is ~parity with parallel-row-wise (B) ({:.2}x).",
            c_vs_b
        );
        println!("    The batching itself is NOT the win — B already saturates the cores.");
        println!("    The real GHAST wins are DEFERRAL (time-to-usable) and BANDWIDTH (hazed).");
    } else {
        println!(
            "  * Columnar batching (C) is SLOWER than B ({:.2}x) — collection overhead.",
            c_vs_b
        );
        println!("    The GHAST wins are DEFERRAL and BANDWIDTH, not the batching.");
    }

    // --- Multi-peer parallel-fetch model (design §10) -----------------------
    // Measured CPU throughput of the header+UTXO passes on the synthetic
    // segment: economic MB processed per second. Fed into the analytical
    // download model to give total time-to-usable(N).
    let cpu_mbps_measured = (economic_total as f64 / 1e6) / t_usable.as_secs_f64().max(1e-9);
    run_bandwidth_model(&cfg, cpu_mbps_measured);
}

//! Backtest with ONLY computational validity checks — all pattern filters disabled.
//! Shows what the computational engine catches independently.
//!
//! Run: cargo test -p ghost-reaper --test backtest_computational_only -- --ignored --nocapture

use bitcoin::consensus::deserialize;
use bitcoin::Block;
use ghost_reaper::{analyze, ReaperConfig, Verdict};
use std::process::Command;

fn fetch_block_hash(height: u64) -> Option<String> {
    let output = Command::new("curl")
        .args([
            "-sf",
            &format!("https://mempool.space/api/block-height/{}", height),
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn fetch_raw_block(hash: &str) -> Option<Vec<u8>> {
    let output = Command::new("curl")
        .args([
            "-sf",
            &format!("https://mempool.space/api/block/{}/raw", hash),
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(output.stdout)
}

#[test]
#[ignore]
fn backtest_computational_only() {
    // Disable ALL pattern filters — only computational checks active
    let config = ReaperConfig {
        reject_inscription_envelope: false,
        reject_drop_stuffing: false,
        reject_unreachable_code: false,
        reject_fake_pubkeys: false,
        reject_annex: false,
        max_op_return_bytes: usize::MAX, // effectively disable OP_RETURN check
        reject_legacy_data_stuffing: false,
        // Keep computational checks ON
        reject_excess_witness: true,
        min_excess_witness_bytes: 500,
        // Keep EC validation ON (it's output-level, independent of witness patterns)
        validate_pubkey_curve_point: true,
        ..Default::default()
    };

    let tip_output = Command::new("curl")
        .args(["-sf", "https://mempool.space/api/blocks/tip/height"])
        .output()
        .expect("curl failed");
    let tip_height: u64 = String::from_utf8_lossy(&tip_output.stdout)
        .trim()
        .parse()
        .expect("bad tip height");

    let start_height = tip_height - 9;

    println!("\n============================================================");
    println!("Ghost Reaper — COMPUTATIONAL-ONLY Backtest");
    println!("All pattern filters DISABLED. Only computational checks active.");
    println!("Blocks {} to {}", start_height, tip_height);
    println!("============================================================\n");

    let mut total_txs: usize = 0;
    let mut corpse = 0;
    let mut by_type: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut examples: Vec<String> = Vec::new();

    for height in start_height..=tip_height {
        print!("Block {}... ", height);

        let hash = match fetch_block_hash(height) {
            Some(h) => h,
            None => {
                println!("SKIP");
                continue;
            }
        };
        let raw = match fetch_raw_block(&hash) {
            Some(r) => r,
            None => {
                println!("SKIP");
                continue;
            }
        };
        let block: Block = match deserialize(&raw) {
            Ok(b) => b,
            Err(e) => {
                println!("SKIP ({})", e);
                continue;
            }
        };

        let mut block_corpse = 0;
        for tx in &block.txdata {
            if tx.is_coinbase() {
                continue;
            }
            total_txs += 1;

            let verdict = analyze(tx, &config);
            if verdict.verdict == Verdict::Corpse {
                corpse += 1;
                block_corpse += 1;

                for region in &verdict.dead_regions {
                    let type_name = format!("{:?}", region.dead_code_type);
                    *by_type.entry(type_name).or_insert(0) += 1;
                }

                // Collect first 20 examples with details
                if examples.len() < 20 {
                    let txid = tx.compute_txid();
                    let types: Vec<_> = verdict
                        .dead_regions
                        .iter()
                        .map(|r| format!("{:?}", r.dead_code_type))
                        .collect();
                    let breakdown_info = verdict
                        .input_analyses
                        .iter()
                        .filter_map(|a| a.witness_breakdown.as_ref())
                        .map(|bd| {
                            format!(
                                "essential={}B dead={}B stack={}/{} excess_stack={}",
                                bd.essential_bytes,
                                bd.dead_bytes,
                                bd.essential_stack_items,
                                bd.actual_stack_items,
                                bd.excess_stack_items
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("; ");
                    examples.push(format!(
                        "  {} dead={}B types={:?} [{}]",
                        txid, verdict.total_dead_bytes, types, breakdown_info
                    ));
                }
            }
        }

        println!("{} txs, {} corpse", block.txdata.len(), block_corpse);
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    println!("\n============================================================");
    println!("RESULTS — Computational Only (no pattern filters)");
    println!("============================================================");
    println!("Total transactions: {}", total_txs);
    println!("Corpse (computational only): {}", corpse);
    println!(
        "Corpse rate: {:.4}%",
        corpse as f64 / total_txs.max(1) as f64 * 100.0
    );

    if !by_type.is_empty() {
        println!("\nDetection type breakdown:");
        let mut types: Vec<_> = by_type.iter().collect();
        types.sort_by(|a, b| b.1.cmp(a.1));
        for (type_name, count) in types {
            println!("  {:30} {}", type_name, count);
        }
    }

    if !examples.is_empty() {
        println!("\nExample corpse transactions:");
        for ex in &examples {
            println!("{}", ex);
        }
    }

    // Now run WITH all filters to compare
    println!("\n--- Comparison: full filters ---");
    let full_config = ReaperConfig::default();
    let mut full_corpse = 0;
    // Re-check just 1 block for comparison
    let hash = fetch_block_hash(tip_height).unwrap();
    let raw = fetch_raw_block(&hash).unwrap();
    let block: Block = deserialize(&raw).unwrap();
    let block_txs = block.txdata.len() - 1; // minus coinbase
    for tx in &block.txdata {
        if tx.is_coinbase() {
            continue;
        }
        let v = analyze(tx, &full_config);
        if v.verdict == Verdict::Corpse {
            full_corpse += 1;
        }
    }
    println!(
        "Block {} with FULL filters: {}/{} corpse",
        tip_height, full_corpse, block_txs
    );
    println!("Block {} with COMPUTATIONAL ONLY: see above", tip_height);
}

//! Compare: filters-only vs filters+computational (simulator-enhanced).
//! Runs 100 blocks. For every corpse, audits whether it could be a legitimate
//! monetary transaction. Shows exactly which txs the computational engine
//! catches that patterns miss.
//!
//! Run: cargo test -p ghost-reaper --test backtest_simulator_delta -- --ignored --nocapture

use bitcoin::consensus::deserialize;
use bitcoin::Block;
use ghost_reaper::{analyze, DeadCodeType, ReaperConfig, Verdict};
use std::collections::HashMap;
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

/// Classify a corpse tx: is it flagged by known spam patterns, or ONLY by
/// computational / EC checks? The latter is the danger zone for false positives.
fn classify_corpse(regions: &[ghost_reaper::DeadCodeRegion]) -> CorpseClass {
    let has_pattern = regions.iter().any(|r| {
        matches!(
            r.dead_code_type,
            DeadCodeType::InscriptionEnvelope
                | DeadCodeType::DropStuffing
                | DeadCodeType::UnreachableCode
                | DeadCodeType::FakePubkey
                | DeadCodeType::AnnexPresent
                | DeadCodeType::OversizedOpReturn
                | DeadCodeType::LegacyScriptSigData
        )
    });
    let has_computational = regions.iter().any(|r| {
        matches!(
            r.dead_code_type,
            DeadCodeType::ExcessWitnessData
                | DeadCodeType::ExcessStackItems
                | DeadCodeType::FakePubkeyCurvePoint
        )
    });

    match (has_pattern, has_computational) {
        (true, _) => CorpseClass::PatternCaught,
        (false, true) => CorpseClass::ComputationalOnly,
        (false, false) => CorpseClass::Unknown,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CorpseClass {
    PatternCaught,     // Known spam pattern detected
    ComputationalOnly, // ONLY computational/EC — potential false positive zone
    Unknown,           // Neither? (shouldn't happen)
}

#[test]
#[ignore]
fn backtest_simulator_delta() {
    // Config A: patterns only (no computational checks, no EC)
    let patterns_only = ReaperConfig {
        reject_excess_witness: false,
        validate_pubkey_curve_point: false,
        ..Default::default()
    };

    // Config B: full (patterns + computational + EC validation)
    let full = ReaperConfig::default();

    let tip_output = Command::new("curl")
        .args(["-sf", "https://mempool.space/api/blocks/tip/height"])
        .output()
        .expect("curl failed");
    let tip_height: u64 = String::from_utf8_lossy(&tip_output.stdout)
        .trim()
        .parse()
        .expect("bad tip height");

    let num_blocks: u64 = 100;
    let start_height = tip_height - (num_blocks - 1);

    println!("\n============================================================");
    println!("Ghost Reaper — 100-Block Delta: Patterns vs Full");
    println!(
        "Blocks {} to {} ({} blocks)",
        start_height, tip_height, num_blocks
    );
    println!("============================================================\n");

    let mut total_txs: usize = 0;
    let mut total_blocks: usize = 0;
    let mut patterns_corpse: usize = 0;
    let mut full_corpse: usize = 0;

    // Delta tracking: txs caught by full but NOT patterns
    let mut delta_catches: Vec<String> = Vec::new();
    let mut delta_by_type: HashMap<String, usize> = HashMap::new();
    let mut delta_count: usize = 0;
    let mut delta_dead_bytes: usize = 0;

    // False positive audit: every corpse gets classified
    let mut corpse_pattern_caught: usize = 0;
    let mut corpse_computational_only: usize = 0;
    let mut computational_only_details: Vec<String> = Vec::new();

    // Spend type breakdown for all corpse txs
    let mut corpse_spend_types: HashMap<String, usize> = HashMap::new();

    for height in start_height..=tip_height {
        let block_num = height - start_height + 1;
        if block_num % 10 == 1 || block_num == num_blocks {
            print!("[{}/{}] Block {}... ", block_num, num_blocks, height);
        }

        let hash = match fetch_block_hash(height) {
            Some(h) => h,
            None => {
                if block_num % 10 == 1 {
                    println!("SKIP");
                }
                continue;
            }
        };
        let raw = match fetch_raw_block(&hash) {
            Some(r) => r,
            None => {
                if block_num % 10 == 1 {
                    println!("SKIP");
                }
                continue;
            }
        };
        let block: Block = match deserialize(&raw) {
            Ok(b) => b,
            Err(e) => {
                if block_num % 10 == 1 {
                    println!("SKIP ({})", e);
                }
                continue;
            }
        };

        total_blocks += 1;
        let mut block_delta = 0;

        for tx in &block.txdata {
            if tx.is_coinbase() {
                continue;
            }
            total_txs += 1;

            let v_patterns = analyze(tx, &patterns_only);
            let v_full = analyze(tx, &full);

            let is_corpse_patterns = v_patterns.verdict == Verdict::Corpse;
            let is_corpse_full = v_full.verdict == Verdict::Corpse;

            if is_corpse_patterns {
                patterns_corpse += 1;
            }
            if is_corpse_full {
                full_corpse += 1;

                // Classify every corpse for false positive audit
                let class = classify_corpse(&v_full.dead_regions);
                match class {
                    CorpseClass::PatternCaught => corpse_pattern_caught += 1,
                    CorpseClass::ComputationalOnly => {
                        corpse_computational_only += 1;

                        // These are the danger zone — log ALL of them
                        if computational_only_details.len() < 50 {
                            let txid = tx.compute_txid();
                            let types: Vec<_> = v_full
                                .dead_regions
                                .iter()
                                .map(|r| format!("{:?}", r.dead_code_type))
                                .collect();
                            let spend_types: Vec<_> = v_full
                                .input_analyses
                                .iter()
                                .map(|a| a.spend_type.clone())
                                .collect();
                            let breakdown = v_full.input_analyses.iter()
                                .filter_map(|a| a.witness_breakdown.as_ref())
                                .map(|bd| format!(
                                    "essential={}B dead={}B script={}/{}B stack={}/{} excess={}({}B)",
                                    bd.essential_bytes, bd.dead_bytes,
                                    bd.essential_script_bytes, bd.original_script_bytes,
                                    bd.essential_stack_items, bd.actual_stack_items,
                                    bd.excess_stack_items, bd.excess_stack_bytes
                                ))
                                .collect::<Vec<_>>()
                                .join("; ");
                            computational_only_details.push(format!(
                                "  {} block={} dead={}B\n    types={:?} spends={:?}\n    [{}]",
                                txid,
                                height,
                                v_full.total_dead_bytes,
                                types,
                                spend_types,
                                breakdown
                            ));
                        }
                    }
                    CorpseClass::Unknown => {}
                }

                // Spend type breakdown
                for analysis in &v_full.input_analyses {
                    if analysis.dead_bytes > 0 {
                        *corpse_spend_types
                            .entry(analysis.spend_type.clone())
                            .or_insert(0) += 1;
                    }
                }
            }

            // Delta: caught by full but NOT by patterns
            if is_corpse_full && !is_corpse_patterns {
                delta_count += 1;
                block_delta += 1;
                delta_dead_bytes += v_full.total_dead_bytes;

                for region in &v_full.dead_regions {
                    let type_name = format!("{:?}", region.dead_code_type);
                    *delta_by_type.entry(type_name).or_insert(0) += 1;
                }

                if delta_catches.len() < 50 {
                    let txid = tx.compute_txid();
                    let types: Vec<_> = v_full
                        .dead_regions
                        .iter()
                        .map(|r| format!("{:?}", r.dead_code_type))
                        .collect();
                    let breakdown = v_full
                        .input_analyses
                        .iter()
                        .filter_map(|a| a.witness_breakdown.as_ref())
                        .map(|bd| {
                            format!(
                                "essential={}B dead={}B stack={}/{} excess={}({}B)",
                                bd.essential_bytes,
                                bd.dead_bytes,
                                bd.essential_stack_items,
                                bd.actual_stack_items,
                                bd.excess_stack_items,
                                bd.excess_stack_bytes
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("; ");
                    delta_catches.push(format!(
                        "  {} dead={}B types={:?}\n    [{}]",
                        txid, v_full.total_dead_bytes, types, breakdown
                    ));
                }
            }
        }

        if block_num % 10 == 1 || block_num == num_blocks {
            println!("{} txs | delta=+{}", block.txdata.len(), block_delta);
        }
        // 250ms to stay under mempool.space rate limit (100 blocks ~= 25s)
        std::thread::sleep(std::time::Duration::from_millis(250));
    }

    // ── Results ──────────────────────────────────────────────────────────
    println!("\n============================================================");
    println!("RESULTS — 100-Block Backtest");
    println!("============================================================");
    println!("Blocks analyzed:            {}", total_blocks);
    println!("Total transactions:         {}", total_txs);
    println!();
    println!("Corpse (patterns only):     {}", patterns_corpse);
    println!("Corpse (full):              {}", full_corpse);
    println!("DELTA (additional catches):  +{}", delta_count);
    println!("Delta dead bytes:           {} bytes", delta_dead_bytes);
    println!(
        "Patterns corpse rate:       {:.4}%",
        patterns_corpse as f64 / total_txs.max(1) as f64 * 100.0
    );
    println!(
        "Full corpse rate:           {:.4}%",
        full_corpse as f64 / total_txs.max(1) as f64 * 100.0
    );

    // ── False Positive Audit ─────────────────────────────────────────────
    println!("\n============================================================");
    println!("FALSE POSITIVE AUDIT — Every corpse classified");
    println!("============================================================");
    println!("Total corpse txs:           {}", full_corpse);
    println!(
        "  Pattern-caught:           {} (known spam — safe)",
        corpse_pattern_caught
    );
    println!(
        "  Computational-only:       {} (REVIEW THESE)",
        corpse_computational_only
    );

    if corpse_computational_only > 0 {
        println!("\n*** COMPUTATIONAL-ONLY CORPSE DETAILS ***");
        println!("These txs were flagged WITHOUT any known spam pattern.");
        println!("If any are legitimate monetary txs, we have a false positive.\n");
        for detail in &computational_only_details {
            println!("{}", detail);
        }
    } else {
        println!("\nAll corpse txs were caught by known spam patterns.");
        println!("Computational checks did not independently flag any tx.");
    }

    // ── Spend Type Breakdown ─────────────────────────────────────────────
    if !corpse_spend_types.is_empty() {
        println!("\nCorpse spend type breakdown:");
        let mut types: Vec<_> = corpse_spend_types.iter().collect();
        types.sort_by(|a, b| b.1.cmp(a.1));
        for (type_name, count) in types {
            println!("  {:30} {}", type_name, count);
        }
    }

    // ── Delta Details ────────────────────────────────────────────────────
    if !delta_by_type.is_empty() {
        println!("\nDelta detection types (computational catches that patterns missed):");
        let mut types: Vec<_> = delta_by_type.iter().collect();
        types.sort_by(|a, b| b.1.cmp(a.1));
        for (type_name, count) in types {
            println!("  {:30} {}", type_name, count);
        }
    }

    if !delta_catches.is_empty() {
        println!("\nDelta transactions (caught ONLY by full, not patterns):");
        for ex in &delta_catches {
            println!("{}", ex);
        }
    } else {
        println!("\nNo delta catches — patterns caught everything.");
    }

    println!();
}

//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: analyzer.rs                                                                                                    |
//|======================================================================================================================|

use bitcoin::Transaction;
use tracing::debug;

use crate::config::ReaperConfig;
use crate::dead_code::detect_dead_code;
use crate::essential::compute_witness_breakdown;
use crate::flow::analyze_script_flow;
use crate::legacy::analyze_legacy_scriptsig;
use crate::output::analyze_outputs;
use crate::verdict::{
    AnalysisLocation, DeadCodeRegion, DeadCodeType, InputAnalysis, ReaperVerdict, Verdict,
};
use crate::witness::{has_annex, identify_spend, SpendType};

/// Analyze a transaction for dead code in witness scripts and outputs.
///
/// Returns a `ReaperVerdict` with detailed region-level findings and
/// a final `Verdict` (Accept or Corpse) based on dead code presence.
pub fn analyze(tx: &Transaction, config: &ReaperConfig) -> ReaperVerdict {
    // Disabled → accept everything
    if !config.enabled {
        return ReaperVerdict::accept();
    }

    // Coinbase transactions contain legitimate miner data
    if tx.is_coinbase() {
        return ReaperVerdict::accept();
    }

    let mut all_regions: Vec<DeadCodeRegion> = Vec::new();
    let mut input_analyses: Vec<InputAnalysis> = Vec::new();
    let mut total_witness_bytes: usize = 0;
    let mut total_essential_bytes: usize = 0;
    let mut total_excess_bytes: usize = 0;

    // Analyze each input's witness
    for (idx, input) in tx.input.iter().enumerate() {
        let spend_type = identify_spend(input);
        let mut input_dead_bytes: usize = 0;
        let mut input_regions: Vec<DeadCodeRegion> = Vec::new();
        let mut flow_regions: Vec<DeadCodeRegion> = Vec::new();

        // Calculate witness size for this input
        let witness_size: usize = input.witness.iter().map(|item| item.len()).sum();
        total_witness_bytes += witness_size;

        // Detect dead code in the relevant script
        match &spend_type {
            SpendType::P2trScriptPath { tapscript, .. } => {
                // Pattern detection (controlled by per-toggle config)
                let pattern_regions = detect_dead_code(tapscript, idx, config);
                input_regions.extend(pattern_regions);

                // Flow analysis (always runs) — principled dead code detection
                flow_regions = analyze_script_flow(tapscript, idx);
                input_regions.extend(flow_regions.clone());

                // Dedup overlapping regions (pattern + flow often find the same dead code)
                input_dead_bytes = dedup_dead_bytes(&input_regions);
            }
            SpendType::P2wsh { witness_script } => {
                let pattern_regions = detect_dead_code(witness_script, idx, config);
                input_regions.extend(pattern_regions);

                flow_regions = analyze_script_flow(witness_script, idx);
                input_regions.extend(flow_regions.clone());

                input_dead_bytes = dedup_dead_bytes(&input_regions);
            }
            SpendType::Legacy
                // Legacy scriptSig data stuffing analysis
                if config.reject_legacy_data_stuffing => {
                    let legacy_regions =
                        analyze_legacy_scriptsig(input.script_sig.as_bytes(), idx, config);
                    for region in &legacy_regions {
                        input_dead_bytes += region.size;
                    }
                    input_regions.extend(legacy_regions);
                }
            _ => {
                // P2TR key path, P2WPKH, Empty — no script to analyze
            }
        }

        // Check for annex presence
        if config.reject_annex && has_annex(input) {
            let annex_size = input.witness.iter().last().map_or(0, |a| a.len());
            let region = DeadCodeRegion {
                location: AnalysisLocation::Input(idx),
                dead_code_type: DeadCodeType::AnnexPresent,
                offset: 0,
                size: annex_size,
                description: format!("Witness annex present: {} bytes", annex_size),
            };
            input_dead_bytes += annex_size;
            input_regions.push(region);
        }

        // Compute witness breakdown using flow regions (independent of pattern toggles)
        let breakdown = compute_witness_breakdown(input, &spend_type, &flow_regions, idx);

        // Flag excess witness data and excess stack items
        if let Some(ref bd) = breakdown {
            total_essential_bytes += bd.essential_bytes;
            total_excess_bytes += bd.dead_bytes;

            if config.reject_excess_witness && bd.dead_bytes > config.min_excess_witness_bytes {
                let region = DeadCodeRegion {
                    location: AnalysisLocation::Input(idx),
                    dead_code_type: DeadCodeType::ExcessWitnessData,
                    offset: 0,
                    size: bd.dead_bytes,
                    description: format!(
                        "Excess witness data: {} bytes beyond {} essential bytes",
                        bd.dead_bytes, bd.essential_bytes
                    ),
                };
                input_dead_bytes += bd.dead_bytes;
                input_regions.push(region);
            }

            if bd.excess_stack_items > 0 && bd.excess_stack_bytes > config.min_excess_witness_bytes
            {
                let region = DeadCodeRegion {
                    location: AnalysisLocation::Input(idx),
                    dead_code_type: DeadCodeType::ExcessStackItems,
                    offset: 0,
                    size: bd.excess_stack_bytes,
                    description: format!(
                        "Excess stack items: {} items ({} bytes) beyond {} essential",
                        bd.excess_stack_items, bd.excess_stack_bytes, bd.essential_stack_items
                    ),
                };
                // Don't double-count: ExcessStackItems is a subset of ExcessWitnessData
                // Only add if ExcessWitnessData wasn't already added
                if !(config.reject_excess_witness
                    && bd.dead_bytes > config.min_excess_witness_bytes)
                {
                    input_dead_bytes += bd.excess_stack_bytes;
                }
                input_regions.push(region);
            }
        }

        // Get script size for reporting
        let script_size = match &spend_type {
            SpendType::P2trScriptPath { tapscript, .. } => tapscript.len(),
            SpendType::P2wsh { witness_script } => witness_script.len(),
            _ => 0,
        };

        all_regions.extend(input_regions.clone());
        input_analyses.push(InputAnalysis {
            input_index: idx,
            spend_type: spend_type.to_string(),
            script_size,
            dead_bytes: input_dead_bytes,
            regions: input_regions,
            witness_breakdown: breakdown,
        });
    }

    // Analyze outputs
    let output_regions = analyze_outputs(tx, config);
    let output_dead_bytes: usize = output_regions.iter().map(|r| r.size).sum();
    all_regions.extend(output_regions);

    // Calculate totals (dedup overlapping pattern + flow regions)
    let total_dead_bytes = dedup_dead_bytes(&all_regions);
    let dead_code_ratio = if total_witness_bytes > 0 {
        total_dead_bytes as f64 / total_witness_bytes as f64
    } else if output_dead_bytes > 0 {
        // Only output-level dead code, no witness to ratio against
        1.0
    } else {
        0.0
    };

    // Determine verdict based on mode
    let verdict = determine_verdict(total_dead_bytes, dead_code_ratio, &all_regions, config);

    if verdict == Verdict::Corpse {
        debug!(
            dead_bytes = total_dead_bytes,
            ratio = format!("{:.2}%", dead_code_ratio * 100.0),
            regions = all_regions.len(),
            "Transaction classified as Corpse"
        );
    }

    ReaperVerdict {
        verdict,
        dead_regions: all_regions,
        input_analyses,
        total_dead_bytes,
        total_witness_bytes,
        dead_code_ratio,
        total_essential_bytes,
        total_excess_bytes,
    }
}

/// Calculate total dead bytes from potentially overlapping regions.
/// Merges overlapping intervals to avoid double-counting when pattern
/// detection and flow analysis flag the same bytes.
fn dedup_dead_bytes(regions: &[DeadCodeRegion]) -> usize {
    if regions.is_empty() {
        return 0;
    }

    let mut intervals: Vec<(usize, usize)> = regions
        .iter()
        .map(|r| (r.offset, r.offset + r.size))
        .collect();
    intervals.sort_by_key(|&(start, _)| start);

    let mut total = 0;
    let (mut cur_start, mut cur_end) = intervals[0];

    for &(start, end) in &intervals[1..] {
        if start <= cur_end {
            cur_end = cur_end.max(end);
        } else {
            total += cur_end - cur_start;
            cur_start = start;
            cur_end = end;
        }
    }
    total += cur_end - cur_start;

    total
}

/// Determine verdict: any dead bytes → Corpse, otherwise Accept.
fn determine_verdict(
    total_dead_bytes: usize,
    _dead_code_ratio: f64,
    regions: &[DeadCodeRegion],
    _config: &ReaperConfig,
) -> Verdict {
    if regions.is_empty() || total_dead_bytes == 0 {
        Verdict::Accept
    } else {
        Verdict::Corpse
    }
}

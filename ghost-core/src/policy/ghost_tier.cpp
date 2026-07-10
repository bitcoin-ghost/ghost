// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/ghost_tier.h>

#include <consensus/validation.h>
#include <logging.h>
#include <policy/policy.h>
#include <script/script.h>
#include <tinyformat.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <vector>

// ---------------------------------------------------------------------------
// Detectors — byte-exact ports of `crates/ghost-buds/src/detector.rs`.
// ---------------------------------------------------------------------------

namespace {

//! Inscription envelope magic: OP_FALSE OP_IF OP_PUSHBYTES_3.
constexpr unsigned char INSCRIPTION_ENVELOPE_START[3] = {0x00, 0x63, 0x03};
//! Inscription content-type marker "ord".
constexpr unsigned char INSCRIPTION_CONTENT_TYPE[3] = {'o', 'r', 'd'};
//! Runes protocol magic: OP_RETURN OP_13.
constexpr unsigned char RUNES_MAGIC[2] = {0x6a, 0x5d};
//! BRC-20 JSON pattern.
constexpr char BRC20_PATTERN[] = {'"', 'p', '"', ':', '"', 'b', 'r', 'c', '-', '2', '0', '"'};
constexpr size_t BRC20_PATTERN_LEN = sizeof(BRC20_PATTERN);

//! Port of `detector::is_runes_script`: raw output script starts with 0x6a 0x5d.
bool IsRunesScript(const CScript& script)
{
    return script.size() >= 2 && script[0] == RUNES_MAGIC[0] && script[1] == RUNES_MAGIC[1];
}

//! Port of `detector::detect_multisig` (bare multisig only). Inspects the raw
//! output-script bytes: last byte OP_CHECKMULTISIG, first byte OP_1..OP_16 = m,
//! second-to-last byte OP_1..OP_16 = n, with m <= n <= 16.
bool DetectBareMultisig(const CScript& script)
{
    const size_t len = script.size();
    if (len < 3) return false;

    if (script[len - 1] != OP_CHECKMULTISIG) return false;

    const unsigned char first_byte = script[0];
    if (first_byte < OP_1 || first_byte > OP_16) return false;
    const unsigned int m = static_cast<unsigned int>(first_byte) - OP_1 + 1;

    const unsigned char n_byte = script[len - 2];
    if (n_byte < OP_1 || n_byte > OP_16) return false;
    const unsigned int n = static_cast<unsigned int>(n_byte) - OP_1 + 1;

    return m <= n && n <= 16;
}

//! Port of `detector::contains_cltv`/`contains_csv`/`is_htlc_pattern`: a single
//! pass over the script's opcodes recording the hash/timelock/conditional
//! primitives. Mirrors rust-bitcoin's `Script::instructions()`, which stops at
//! the first parse error — `GetOp` returning false terminates the walk the same
//! way, and data inside pushes is never mistaken for an opcode.
void ScanScriptOps(const CScript& script, bool& has_hash, bool& has_timelock, bool& has_if)
{
    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    std::vector<unsigned char> data;
    while (pc < script.end()) {
        if (!script.GetOp(pc, opcode, data)) break;
        switch (opcode) {
        case OP_HASH160:
        case OP_SHA256:
        case OP_HASH256:
            has_hash = true;
            break;
        case OP_CHECKLOCKTIMEVERIFY:  // OP_NOP2
        case OP_CHECKSEQUENCEVERIFY:  // OP_NOP3
            has_timelock = true;
            break;
        case OP_IF:
        case OP_NOTIF:
            has_if = true;
            break;
        default:
            break;
        }
    }
}

//! Search for a 3-byte "ord" window; returns its first index if present.
bool FindOrdWindow(const std::vector<unsigned char>& data, size_t& pos_out)
{
    if (data.size() < 3) return false;
    for (size_t i = 0; i + 3 <= data.size(); ++i) {
        if (data[i] == INSCRIPTION_CONTENT_TYPE[0] &&
            data[i + 1] == INSCRIPTION_CONTENT_TYPE[1] &&
            data[i + 2] == INSCRIPTION_CONTENT_TYPE[2]) {
            pos_out = i;
            return true;
        }
    }
    return false;
}

//! Port of `detector::is_inscription_envelope`. Reproduces the exact control
//! flow: when a witness item both starts with the envelope magic AND contains
//! "ord", the result is `pos < 20` (which can be false for a late "ord" without
//! falling through to the loose scan — a deliberate quirk of the original).
bool IsInscriptionEnvelope(const std::vector<unsigned char>& data)
{
    if (data.size() < 10) return false;

    if (data[0] == INSCRIPTION_ENVELOPE_START[0] &&
        data[1] == INSCRIPTION_ENVELOPE_START[1] &&
        data[2] == INSCRIPTION_ENVELOPE_START[2]) {
        size_t pos = 0;
        if (FindOrdWindow(data, pos)) {
            return pos < 20;
        }
    }

    // Loose fallback: any "ord" 3-byte window anywhere in the item.
    for (size_t i = 0; i + 3 <= data.size(); ++i) {
        if (data[i] == INSCRIPTION_CONTENT_TYPE[0] &&
            data[i + 1] == INSCRIPTION_CONTENT_TYPE[1] &&
            data[i + 2] == INSCRIPTION_CONTENT_TYPE[2]) {
            return true;
        }
    }
    return false;
}

//! Port of `detector::contains_brc20_pattern`: literal `"p":"brc-20"` anywhere.
bool ContainsBrc20Pattern(const std::vector<unsigned char>& data)
{
    if (data.size() < BRC20_PATTERN_LEN) return false;
    for (size_t i = 0; i + BRC20_PATTERN_LEN <= data.size(); ++i) {
        if (std::memcmp(data.data() + i, BRC20_PATTERN, BRC20_PATTERN_LEN) == 0) {
            return true;
        }
    }
    return false;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Classifier — byte-exact port of `crates/ghost-buds/src/classifier.rs`.
// ---------------------------------------------------------------------------

GhostTierAnalysis AnalyzeTransactionTier(const CTransaction& tx)
{
    GhostTierAnalysis a;

    // Coinbase transactions are always T0.
    if (tx.IsCoinBase()) {
        a.tier = GhostTier::T0;
        a.reason = "coinbase";
        a.output_count = tx.vout.size();
        a.tx_weight = GetTransactionWeight(tx);
        return a;
    }

    // Analyze outputs.
    for (const CTxOut& txout : tx.vout) {
        const CScript& spk = txout.scriptPubKey;

        // OP_RETURN detection matches rust-bitcoin `Script::is_op_return()`
        // (first byte == OP_RETURN); size quirk = script.len().saturating_sub(2).
        if (spk.size() >= 1 && spk[0] == OP_RETURN) {
            a.has_op_return = true;
            const size_t size = spk.size() >= 2 ? spk.size() - 2 : 0;
            a.max_op_return_size = std::max(a.max_op_return_size, size);
        }

        if (IsRunesScript(spk)) {
            a.has_runes = true;
        }

        if (DetectBareMultisig(spk)) {
            a.has_multisig = true;
        }

        bool has_hash = false, has_timelock = false, has_if = false;
        ScanScriptOps(spk, has_hash, has_timelock, has_if);
        if (has_timelock) {
            a.has_timelock = true;
        }
        if (has_hash && has_timelock && has_if) {
            a.has_htlc = true;
        }
    }

    // Analyze inputs (witnesses).
    for (const CTxIn& txin : tx.vin) {
        size_t input_witness_size = 0;
        for (const auto& item : txin.scriptWitness.stack) {
            input_witness_size += item.size();
        }
        a.max_witness_size = std::max(a.max_witness_size, input_witness_size);
        a.total_witness_size += input_witness_size;

        for (const auto& item : txin.scriptWitness.stack) {
            if (IsInscriptionEnvelope(item)) {
                a.has_inscription = true;
            }
            if (ContainsBrc20Pattern(item)) {
                a.has_brc20 = true;
            }
        }
    }

    a.output_count = tx.vout.size();
    a.tx_weight = GetTransactionWeight(tx);

    // ---- determine_tier: ordered first-match cascade ----

    // T3: inscriptions, BRC-20, runes.
    if (a.has_inscription) {
        a.tier = GhostTier::T3;
        a.reason = "inscription";
        return a;
    }
    if (a.has_brc20) {
        a.tier = GhostTier::T3;
        a.reason = "brc20";
        return a;
    }
    if (a.has_runes) {
        a.tier = GhostTier::T3;
        a.reason = "runes";
        return a;
    }

    // T3: large OP_RETURN (> 80 bytes).
    if (a.has_op_return && a.max_op_return_size > GHOST_TIER_SMALL_OP_RETURN_THRESHOLD) {
        a.tier = GhostTier::T3;
        a.reason = strprintf("large-op-return(%u)", a.max_op_return_size);
        return a;
    }

    // T3: very large witness.
    if (a.max_witness_size > GHOST_TIER_VERY_LARGE_WITNESS_PER_INPUT ||
        a.total_witness_size > GHOST_TIER_VERY_LARGE_WITNESS_TOTAL) {
        a.tier = GhostTier::T3;
        a.reason = strprintf("large-witness(%u)", a.total_witness_size);
        return a;
    }

    // T3: extremely large transaction (weight > 400_000 WU).
    if (a.tx_weight > GHOST_TIER_MAX_TX_WEIGHT) {
        a.tier = GhostTier::T3;
        a.reason = strprintf("large-tx-weight(%d)", a.tx_weight);
        return a;
    }

    // T2: small OP_RETURN (<= 80 bytes).
    if (a.has_op_return) {
        a.tier = GhostTier::T2;
        a.reason = strprintf("small-op-return(%u)", a.max_op_return_size);
        return a;
    }

    // T1: extended witness (> 108 but <= 400 bytes per input).
    if (a.max_witness_size > GHOST_TIER_STANDARD_WITNESS_THRESHOLD &&
        a.max_witness_size <= GHOST_TIER_EXTENDED_WITNESS_THRESHOLD) {
        if (a.has_htlc) {
            a.tier = GhostTier::T1;
            a.reason = "htlc";
        } else if (a.has_timelock) {
            a.tier = GhostTier::T1;
            a.reason = "timelock";
        } else if (a.has_multisig) {
            a.tier = GhostTier::T1;
            a.reason = "multisig";
        } else {
            a.tier = GhostTier::T1;
            a.reason = "complex-script";
        }
        return a;
    }

    // T1: bare multisig (even with a small witness).
    if (a.has_multisig) {
        a.tier = GhostTier::T1;
        a.reason = "multisig";
        return a;
    }

    // T1: timelocks.
    if (a.has_timelock) {
        a.tier = GhostTier::T1;
        a.reason = "timelock";
        return a;
    }

    // T1: HTLC.
    if (a.has_htlc) {
        a.tier = GhostTier::T1;
        a.reason = "htlc";
        return a;
    }

    // T0: standard payment.
    a.tier = GhostTier::T0;
    a.reason = "standard-payment";
    return a;
}

GhostTier ClassifyTransactionTier(const CTransaction& tx)
{
    return AnalyzeTransactionTier(tx).tier;
}

// ---------------------------------------------------------------------------
// Mempool-acceptance gate.
// ---------------------------------------------------------------------------

namespace {
//! Cumulative-since-start rejection counters for the tier/policy gate. Stats
//! only, so relaxed ordering suffices (no cross-thread invariant rides on them).
std::atomic<uint64_t> g_tier_rejected_txs{0};
std::atomic<uint64_t> g_tier_rejected_vbytes{0};

//! Core tier/policy predicate. Returns true if admissible, false (with `reason`
//! filled) on the single reject decision. Kept side-effect-free so the public
//! wrapper can bump the observability counters exactly once per rejected tx.
bool TierPolicyCheck(const CTransaction& tx, const GhostTierPolicyConfig& config, CAmount base_fees, std::string& reason)
{
    const GhostTierAnalysis a = AnalyzeTransactionTier(tx);

    // (1) Tier gate — the whole story for the {T0,T1} / {T0,T1,T2} / all presets.
    if (!config.TierAllowed(a.tier)) {
        reason = "tier-policy";
        LogPrintLevel(BCLog::MEMPOOLREJ, BCLog::Level::Debug,
                      "Tier policy: rejected tx %s — tier T%d not allowed (%s)\n",
                      tx.GetHash().ToString(), static_cast<int>(a.tier), a.reason);
        return false;
    }

    // (2) Tier-independent content rejects. These bite even when the content's
    // tier is allowed, mirroring ghost-pool's allow_inscriptions/runes/brc20.
    // The detections are reused from the classifier pass above (no re-scan).
    if (!config.allow_inscriptions && a.has_inscription) {
        reason = "tier-policy-inscription";
        LogPrintLevel(BCLog::MEMPOOLREJ, BCLog::Level::Debug,
                      "Tier policy: rejected tx %s — inscriptions not allowed\n", tx.GetHash().ToString());
        return false;
    }
    if (!config.allow_runes && a.has_runes) {
        reason = "tier-policy-runes";
        LogPrintLevel(BCLog::MEMPOOLREJ, BCLog::Level::Debug,
                      "Tier policy: rejected tx %s — runes not allowed\n", tx.GetHash().ToString());
        return false;
    }
    if (!config.allow_brc20 && a.has_brc20) {
        reason = "tier-policy-brc20";
        LogPrintLevel(BCLog::MEMPOOLREJ, BCLog::Level::Debug,
                      "Tier policy: rejected tx %s — brc20 not allowed\n", tx.GetHash().ToString());
        return false;
    }

    // (3) Custom per-field limits, accounting byte-exact with ghost-pool's
    // `policy_field_violation`. Each is skipped when unset (std::nullopt).

    // Transaction size: vbytes = weight / 4.
    const int64_t vbytes = a.tx_weight / 4;
    if (config.max_tx_size && vbytes > static_cast<int64_t>(*config.max_tx_size)) {
        reason = "tier-policy-txsize";
        LogPrintLevel(BCLog::MEMPOOLREJ, BCLog::Level::Debug,
                      "Tier policy: rejected tx %s — size %d > %u vB\n",
                      tx.GetHash().ToString(), vbytes, *config.max_tx_size);
        return false;
    }

    // Output count.
    if (config.max_tx_outputs && a.output_count > *config.max_tx_outputs) {
        reason = "tier-policy-outputs";
        LogPrintLevel(BCLog::MEMPOOLREJ, BCLog::Level::Debug,
                      "Tier policy: rejected tx %s — %u outputs > %u\n",
                      tx.GetHash().ToString(), a.output_count, *config.max_tx_outputs);
        return false;
    }

    // OP_RETURN payload size (script.len() - 2 accounting).
    if (config.max_op_return_size && a.has_op_return &&
        a.max_op_return_size > *config.max_op_return_size) {
        reason = "tier-policy-opreturn";
        LogPrintLevel(BCLog::MEMPOOLREJ, BCLog::Level::Debug,
                      "Tier policy: rejected tx %s — OP_RETURN %u > %u bytes\n",
                      tx.GetHash().ToString(), a.max_op_return_size, *config.max_op_return_size);
        return false;
    }

    // Per-input witness size (largest input).
    if (config.max_witness_per_input && a.max_witness_size > *config.max_witness_per_input) {
        reason = "tier-policy-witness";
        LogPrintLevel(BCLog::MEMPOOLREJ, BCLog::Level::Debug,
                      "Tier policy: rejected tx %s — witness %u > %u bytes\n",
                      tx.GetHash().ToString(), a.max_witness_size, *config.max_witness_per_input);
        return false;
    }

    // Fee-rate floor (sat/vB). Mirrors ghost-pool: keep iff fee_rate >= min.
    if (config.min_fee_rate && vbytes > 0) {
        const double fee_rate = static_cast<double>(base_fees) / (static_cast<double>(a.tx_weight) / 4.0);
        if (fee_rate < *config.min_fee_rate) {
            reason = "tier-policy-minfeerate";
            LogPrintLevel(BCLog::MEMPOOLREJ, BCLog::Level::Debug,
                          "Tier policy: rejected tx %s — fee-rate %.4f < %.4f sat/vB\n",
                          tx.GetHash().ToString(), fee_rate, *config.min_fee_rate);
            return false;
        }
    }

    return true;
}
} // anonymous namespace

bool IsGhostTierPolicyClean(const CTransaction& tx, const GhostTierPolicyConfig& config, CAmount base_fees, std::string& reason)
{
    if (TierPolicyCheck(tx, config, base_fees, reason)) {
        return true;
    }
    // Rejected: count exactly once. TierPolicyCheck returns from a single reject
    // site per call, so a tx is tallied once regardless of which rule bit it.
    const uint64_t rejected = g_tier_rejected_txs.fetch_add(1, std::memory_order_relaxed) + 1;
    g_tier_rejected_vbytes.fetch_add(static_cast<uint64_t>(GetVirtualTransactionSize(tx)),
                                     std::memory_order_relaxed);
    // Per-tx detail stays at Debug (BCLog::MEMPOOLREJ) to avoid spam. Emit a
    // periodic aggregate at the default log level so an operator sees that tier
    // filtering is active in debug.log without enabling a debug category — the
    // exact counts remain available via getmempoolfilterstats.
    if (rejected == 1 || rejected % 1000 == 0) {
        LogInfo("Tier policy: %d transactions rejected cumulatively (%d vbytes)",
                rejected, g_tier_rejected_vbytes.load(std::memory_order_relaxed));
    }
    return false;
}

uint64_t GhostTierRejectedTxs()
{
    return g_tier_rejected_txs.load(std::memory_order_relaxed);
}

uint64_t GhostTierRejectedVbytes()
{
    return g_tier_rejected_vbytes.load(std::memory_order_relaxed);
}

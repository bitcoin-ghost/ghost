// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_GHOST_TIER_H
#define BITCOIN_POLICY_GHOST_TIER_H

#include <consensus/amount.h>
#include <primitives/transaction.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

//! BUDS tier classifier, ported byte-exact from `crates/ghost-buds`
//! (`classifier.rs::determine_tier` + the detectors in `detector.rs`).
//!
//! ghostd's mempool-acceptance tier gate MUST classify every transaction into
//! the SAME tier that ghost-pool assigns, so a reject here matches ghost-pool's
//! block-template classification exactly. Any change to this file must be
//! mirrored in the Rust classifier (and both locked by the shared golden
//! test-vector corpus) or parity drifts.

//! Standard witness size threshold (T0 upper bound). Matches the Rust
//! classifier's hard-coded `standard_witness_threshold` (72-byte sig + 33-byte
//! pubkey + overhead).
static constexpr size_t GHOST_TIER_STANDARD_WITNESS_THRESHOLD{108};
//! Extended witness size threshold (T1 upper bound). Matches
//! `MAX_WITNESS_BYTES_PER_INPUT` in ghost-common.
static constexpr size_t GHOST_TIER_EXTENDED_WITNESS_THRESHOLD{400};
//! Small OP_RETURN payload threshold (T2 upper bound). Matches
//! `MAX_OP_RETURN_SMALL_BYTES` in ghost-common.
static constexpr size_t GHOST_TIER_SMALL_OP_RETURN_THRESHOLD{80};
//! Per-input witness byte bound above which a tx is T3. Hard-coded in the Rust
//! classifier (`max_witness_size > 1000`).
static constexpr size_t GHOST_TIER_VERY_LARGE_WITNESS_PER_INPUT{1000};
//! Total witness byte bound above which a tx is T3. Hard-coded in the Rust
//! classifier (`total_witness_size > 4000`).
static constexpr size_t GHOST_TIER_VERY_LARGE_WITNESS_TOTAL{4000};
//! Transaction weight (WU) above which a tx is T3. Matches
//! `MAX_TX_SIZE_BITCOIN_PURE * 4` (100_000 * 4).
static constexpr int64_t GHOST_TIER_MAX_TX_WEIGHT{400000};

/** BUDS transaction tier. Lower tiers are "purer" financial transactions. */
enum class GhostTier : uint8_t {
    T0 = 0,  //!< Standard payments
    T1 = 1,  //!< Complex-but-financial (multisig, timelocks, HTLC, extended witness)
    T2 = 2,  //!< Small OP_RETURN data anchoring (Lightning, timestamps)
    T3 = 3,  //!< Heavy data (inscriptions, BRC-20, runes, large OP_RETURN/witness)
};

/**
 * Full structural analysis of a transaction. Carries both the assigned tier and
 * the intermediate detections, so the mempool gate can reuse them for the
 * tier-independent content toggles and the custom per-field limits without a
 * second pass over the transaction.
 */
struct GhostTierAnalysis {
    GhostTier tier{GhostTier::T0};
    //! Human-readable classification reason (for logging only; not the reject reason).
    std::string reason;

    bool has_inscription{false};
    bool has_brc20{false};
    bool has_runes{false};
    bool has_op_return{false};
    bool has_multisig{false};
    bool has_timelock{false};
    bool has_htlc{false};

    size_t max_op_return_size{0};   //!< Largest OP_RETURN payload (script.size() - 2, quirk-exact).
    size_t max_witness_size{0};     //!< Largest per-input witness byte size.
    size_t total_witness_size{0};   //!< Summed witness byte size over all inputs.
    size_t output_count{0};
    int64_t tx_weight{0};           //!< Transaction weight in WU.
};

/**
 * Analyze a transaction and assign its BUDS tier plus all intermediate
 * detections. Byte-exact port of `BudsClassifier::classify`.
 */
GhostTierAnalysis AnalyzeTransactionTier(const CTransaction& tx);

/** Convenience wrapper returning only the tier. */
GhostTier ClassifyTransactionTier(const CTransaction& tx);

/**
 * Node-local tier/policy configuration for mempool acceptance.
 *
 * DEFAULT = fully permissive ("full_open"): all four tiers allowed, all content
 * types allowed, no custom per-field limits. In this state IsInert() is true and
 * the gate is a no-op, so a node with no `-ghostpolicy-*` flags behaves exactly
 * as it did before this feature existed.
 */
struct GhostTierPolicyConfig {
    bool allow_t0{true};
    bool allow_t1{true};
    bool allow_t2{true};
    bool allow_t3{true};

    //! Tier-independent content rejects (bite even when the content's tier is allowed).
    bool allow_inscriptions{true};
    bool allow_runes{true};
    bool allow_brc20{true};

    //! Custom per-field limits. std::nullopt = no limit (default). Each mirrors
    //! ghost-pool's `policy_field_violation` accounting exactly.
    std::optional<unsigned int> max_op_return_size;    //!< Bytes; reject OP_RETURN payload > this.
    std::optional<unsigned int> max_witness_per_input; //!< Bytes; reject any per-input witness > this.
    std::optional<unsigned int> max_tx_outputs;        //!< Reject output count > this.
    std::optional<unsigned int> max_tx_size;           //!< vBytes (weight/4); reject > this.
    std::optional<double> min_fee_rate;                //!< sat/vB; reject fee-rate < this.

    //! True when the config imposes no restriction whatsoever (fast-path no-op).
    bool IsInert() const
    {
        return allow_t0 && allow_t1 && allow_t2 && allow_t3 &&
               allow_inscriptions && allow_runes && allow_brc20 &&
               !max_op_return_size && !max_witness_per_input &&
               !max_tx_outputs && !max_tx_size && !min_fee_rate;
    }

    //! Whether a given tier is in the allowed set.
    bool TierAllowed(GhostTier tier) const
    {
        switch (tier) {
        case GhostTier::T0: return allow_t0;
        case GhostTier::T1: return allow_t1;
        case GhostTier::T2: return allow_t2;
        case GhostTier::T3: return allow_t3;
        }
        return true;
    }
};

/**
 * Check whether a transaction passes the configured tier/policy gate.
 *
 * Applies, in order: the tier gate, the tier-independent content toggles, and
 * the custom per-field limits (including the fee-rate floor, which needs the
 * transaction's fee). Returns true if the transaction is admissible; on
 * rejection returns false and fills `reason` with a single clear reject reason
 * (always prefixed "tier-policy").
 *
 * @param[in]  tx        The transaction to check.
 * @param[in]  config    The tier/policy configuration.
 * @param[in]  base_fees The transaction's fee in satoshis (for min_fee_rate).
 * @param[out] reason    Reject reason if the check fails.
 * @return true if admissible, false if the transaction must be rejected.
 */
bool IsGhostTierPolicyClean(const CTransaction& tx, const GhostTierPolicyConfig& config, CAmount base_fees, std::string& reason);

#endif // BITCOIN_POLICY_GHOST_TIER_H

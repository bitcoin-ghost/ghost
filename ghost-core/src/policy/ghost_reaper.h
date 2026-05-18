// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_GHOST_REAPER_H
#define BITCOIN_POLICY_GHOST_REAPER_H

#include <primitives/transaction.h>

#include <string>

/** Configuration for Ghost Reaper mempool filter.
 *
 * Each detector is independently toggleable. The master CLI flag
 * `-ghostreaper=enabled|disabled` sets the default value for every per-vector
 * toggle at startup, but individual `-ghostreaper-reject*` flags override
 * per-detector when explicitly set. A detector runs iff its `reject_*` flag
 * is true. */
struct GhostReaperConfig {
    /** Reject inputs containing OP_FALSE OP_IF ... OP_ENDIF inscription envelopes */
    bool reject_inscription{true};
    /** Reject inputs with large push followed by OP_DROP/OP_2DROP */
    bool reject_dropstuffing{true};
    /** Reject bare multisig outputs whose pubkey pushes have invalid prefixes */
    bool reject_fakepubkey{true};
    /** Reject P2TR inputs carrying a witness annex */
    bool reject_annex{true};
    /** Reject outputs with OP_RETURN payloads exceeding max_op_return_bytes */
    bool reject_opreturn{true};
    /** Reject outputs encoding a Runestone (OP_RETURN OP_13 ...) */
    bool reject_runestone{true};
    /** Maximum OP_RETURN data payload in bytes (default 83, matching Bitcoin Core relay default) */
    unsigned int max_op_return_bytes{83};
    /** Minimum push size to trigger drop stuffing detection (default 76) */
    unsigned int min_drop_size{76};
};

/**
 * Check whether a transaction passes Ghost Reaper dead-code filtering.
 *
 * Layer 1 defense: fast pattern matching at mempool acceptance.
 * Detects inscription envelopes, drop stuffing, fake multisig pubkeys,
 * P2TR annex abuse, and oversized OP_RETURN outputs.
 *
 * @param[in]  tx       The transaction to check
 * @param[in]  config   Reaper configuration (mode, thresholds)
 * @param[out] reason   Rejection reason string if the check fails
 * @return true if the transaction is clean, false if rejected
 */
bool IsGhostReaperClean(const CTransaction& tx, const GhostReaperConfig& config, std::string& reason);

/** Individual detector functions (exposed for testing) */

/**
 * Check witness scripts for OP_FALSE OP_IF ... OP_ENDIF inscription envelopes.
 */
bool CheckInscriptionEnvelope(const CTransaction& tx, std::string& reason);

/**
 * Check witness scripts for large push followed by OP_DROP/OP_2DROP.
 * @param[in] min_drop_size  Minimum push size to consider as drop stuffing
 */
bool CheckDropStuffing(const CTransaction& tx, unsigned int min_drop_size, std::string& reason);

/**
 * Check bare multisig outputs for pubkey pushes with invalid prefixes.
 * Valid compressed pubkeys start with 0x02 or 0x03.
 */
bool CheckFakeMultisigPubkeys(const CTransaction& tx, std::string& reason);

/**
 * Check P2TR witness stacks for annex presence (last element starts with 0x50).
 */
bool CheckAnnexPresence(const CTransaction& tx, std::string& reason);

/**
 * Check outputs for OP_RETURN with data payload exceeding the configured limit.
 * @param[in] max_bytes  Maximum allowed OP_RETURN data bytes
 */
bool CheckOversizedOpReturn(const CTransaction& tx, unsigned int max_bytes, std::string& reason);

/**
 * Check outputs for Runestone protocol markers.
 * A Runestone is identified by an output whose scriptPubKey starts with
 * OP_RETURN followed by OP_PUSHNUM_13 (opcodes 0x6a 0x5d). The OP_13 must
 * be a standalone opcode — data pushes whose first byte happens to be
 * 0x5d are NOT Runestones.
 */
bool CheckRunestone(const CTransaction& tx, std::string& reason);

#endif // BITCOIN_POLICY_GHOST_REAPER_H

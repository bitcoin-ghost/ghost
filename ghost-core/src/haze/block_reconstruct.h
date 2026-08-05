// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_HAZE_BLOCK_RECONSTRUCT_H
#define BITCOIN_HAZE_BLOCK_RECONSTRUCT_H

#include <haze/stripped_block.h>
#include <primitives/block.h>

namespace haze {

/**
 * Reconstruct a partial CBlock from a CStrippedBlock.
 *
 * The returned block has:
 * - Correct block header (unchanged)
 * - Transactions with empty scriptSig and empty witness
 * - Outputs with preserved values and scriptPubKeys
 * - Stripped OP_RETURN outputs preserved as OP_RETURN + 0x00
 *
 * ⚠ THE RETURNED BLOCK'S TXIDS ARE NOT THE REAL ONES, and cannot be made so. Each transaction
 * computes its txid from its own contents, and those contents are missing the scriptSigs — so for
 * every transaction that had one (every coinbase, every legacy and P2SH-wrapped spend) the value
 * `GetHash()` returns is the hash of a different transaction. `CTransaction` has nowhere to put an
 * authoritative txid, so this is a property of the type rather than something this function could
 * be taught to fix.
 *
 * An earlier version of this comment claimed the stored txid was preserved here. It never was —
 * nothing in this file reads `m_has_stored_txid` — and believing it leads somewhere expensive:
 * anything keying a UTXO lookup on one of these txids, as `DisconnectBlock` does for every output
 * of every transaction, addresses outpoints that do not exist and leaves the real coins in place.
 *
 * **The authoritative source is `CStrippedBlock::GetTxid(i)`.** Use it, and pass the txids alongside
 * the block rather than expecting the block to know them. See `haze_tests.cpp`,
 * `reconstructed_block_cannot_carry_txids`.
 *
 * The block is suitable for RPC JSON serialization with haze indicators,
 * but NOT for full validation (signatures are missing).
 *
 * @param[in] stripped  The stripped block to reconstruct from.
 * @return A partial CBlock with stripped fields empty/zeroed.
 */
CBlock ReconstructPartialBlock(const CStrippedBlock& stripped);

/**
 * Metadata about a reconstructed block.
 *
 * Returned alongside the block to indicate which fields were stripped,
 * for RPC output enrichment.
 */
struct ReconstructionMeta {
    bool is_reconstructed{false};
    bool witness_stripped{true};
    bool scriptsig_stripped{true};
    bool opreturn_stripped{true};
    bool coinbase_stripped{true};
};

/**
 * Reconstruct a partial CBlock with metadata about stripped fields.
 *
 * @param[in]  stripped  The stripped block to reconstruct from.
 * @param[out] meta      Metadata about what was stripped.
 * @return A partial CBlock.
 */
CBlock ReconstructPartialBlockWithMeta(const CStrippedBlock& stripped, ReconstructionMeta& meta);

} // namespace haze

#endif // BITCOIN_HAZE_BLOCK_RECONSTRUCT_H

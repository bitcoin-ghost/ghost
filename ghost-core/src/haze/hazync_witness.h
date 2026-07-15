// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_HAZE_HAZYNC_WITNESS_H
#define BITCOIN_HAZE_HAZYNC_WITNESS_H

#include <consensus/amount.h>
#include <script/script.h>
#include <util/fs.h>

#include <cstdint>
#include <memory>
#include <vector>

class ArgsManager;
class CBlock;
class CBlockIndex;

namespace haze {

/**
 * Hazync witness emitter (the "archive-node bridge").
 *
 * When enabled via -hazyncwitness=<dir>, ghostd writes one JSON witness file per connected block
 * (block_<height>.json) as blocks are validated during IBD. Each file carries exactly what the
 * external Hazync zkVM prover needs to prove the block under real consensus: the header fields, the
 * coinbase, every transaction's raw bytes, and — for every spent input — the spent coin's value,
 * scriptPubKey, creation height, coinbase flag, and creation median-time-past (MTP).
 *
 * This is purely observational: it only READS the coin view (before UpdateCoins spends the coin) and
 * writes files. It changes no consensus state and returns nothing to validation. The JSON shape is
 * byte-for-byte what prover/fetch_block.py produces, so the prover's build_full consumes it unchanged
 * — the emitter simply replaces the explorer fetcher with the node's own, always-correct coin data.
 *
 * Requires full validation (SwiftSync OFF): during SwiftSync-accelerated IBD the ephemeral coin cache
 * is not in the view, so spent-coin metadata is unavailable. Producing proofs wants full validation
 * anyway. If -hazyncwitness is set while SwiftSync would activate, the node refuses to start.
 */
class HazyncWitnessEmitter
{
public:
    /** Per-input spent-coin metadata gathered in ConnectBlock before the coin is spent. */
    struct InputMeta {
        CAmount value;
        CScript scriptPubKey;
        int32_t coin_height;
        bool coin_is_coinbase;
        uint32_t coin_mtp; //!< nTime of the block that created the coin (the accumulator leaf's time
                           //!< reference; also used for BIP68 time-based locks).
    };

    /** Construct from -hazyncwitness=<dir>; returns nullptr if the option is unset. Creates <dir>. */
    static std::unique_ptr<HazyncWitnessEmitter> MaybeCreate(const ArgsManager& args);

    explicit HazyncWitnessEmitter(fs::path out_dir) : m_out_dir(std::move(out_dir)) {}

    /**
     * Write the witness file for one connected block.
     * @param block   the block (header + all transactions)
     * @param pindex  its block index (for height)
     * @param spent   spent[i] = metadata for block.vtx[i]'s inputs, in input order; spent[0] (the
     *                coinbase) is empty. Sized block.vtx.size().
     */
    void WriteBlock(const CBlock& block, const CBlockIndex& pindex,
                    const std::vector<std::vector<InputMeta>>& spent) const;

private:
    const fs::path m_out_dir;
};

} // namespace haze

#endif // BITCOIN_HAZE_HAZYNC_WITNESS_H

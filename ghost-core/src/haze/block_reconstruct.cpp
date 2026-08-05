// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <haze/block_reconstruct.h>

#include <primitives/transaction.h>
#include <script/script.h>

namespace haze {

static CMutableTransaction ReconstructTransaction(const CStrippedTransaction& stripped_tx)
{
    CMutableTransaction mtx;
    mtx.version = stripped_tx.m_version;
    mtx.nLockTime = stripped_tx.m_locktime;

    // Reconstruct inputs: prevout + sequence, empty scriptSig and witness
    mtx.vin.reserve(stripped_tx.m_inputs.size());
    for (const auto& sin : stripped_tx.m_inputs) {
        CTxIn txin;
        txin.prevout = sin.prevout;
        txin.nSequence = sin.n_sequence;
        // scriptSig left empty (default constructed)
        // scriptWitness left empty (default constructed)
        mtx.vin.push_back(std::move(txin));
    }

    // Reconstruct outputs: value + scriptPubKey preserved
    mtx.vout.reserve(stripped_tx.m_outputs.size());
    for (const auto& sout : stripped_tx.m_outputs) {
        CTxOut txout;
        txout.nValue = sout.n_value;
        txout.scriptPubKey = sout.script_pub_key;
        mtx.vout.push_back(std::move(txout));
    }

    return mtx;
}

CBlock ReconstructPartialBlock(const CStrippedBlock& stripped)
{
    CBlock block;
    block.nVersion = stripped.m_header.nVersion;
    block.hashPrevBlock = stripped.m_header.hashPrevBlock;
    block.hashMerkleRoot = stripped.m_header.hashMerkleRoot;
    block.nTime = stripped.m_header.nTime;
    block.nBits = stripped.m_header.nBits;
    block.nNonce = stripped.m_header.nNonce;

    block.vtx.reserve(stripped.m_transactions.size());
    for (const auto& stripped_tx : stripped.m_transactions) {
        block.vtx.push_back(MakeTransactionRef(ReconstructTransaction(stripped_tx)));
    }

    // Mark it for what it is, and carry the real txids with it. ConnectBlock refuses a block
    // carrying the marker, and every consumer that matches transactions by id finds the correct ids
    // already attached — neither depends on a caller remembering where the block came from.
    block.m_haze_reconstructed = true;
    block.m_haze_authoritative_txids.reserve(stripped.GetTxCount());
    for (size_t i = 0; i < stripped.GetTxCount(); ++i) {
        block.m_haze_authoritative_txids.push_back(Txid::FromUint256(stripped.GetTxid(i)));
    }

    return block;
}

CBlock ReconstructPartialBlockWithMeta(const CStrippedBlock& stripped, ReconstructionMeta& meta)
{
    meta.is_reconstructed = true;
    meta.witness_stripped = true;
    meta.scriptsig_stripped = true;
    meta.opreturn_stripped = true;
    meta.coinbase_stripped = true;

    return ReconstructPartialBlock(stripped);
}

} // namespace haze

// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INDEX_ADDRESSINDEX_H
#define BITCOIN_INDEX_ADDRESSINDEX_H

#include <index/base.h>
#include <script/script.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <memory>
#include <vector>

static constexpr bool DEFAULT_ADDRESSINDEX{false};

/**
 * One unit of address activity: an output paying a scriptPubKey, and — if it
 * has since been spent — where it was spent. Built entirely from the structural
 * data every block (full or stripped/hazed) retains: output value + script,
 * input outpoints, and txids. No witness/signature data is required.
 */
struct AddressIndexEntry {
    uint256 txid;               //!< tx that created the output
    uint32_t index{0};          //!< output index (vout)
    int32_t height{0};          //!< block height of the output
    int64_t value{0};           //!< output value in satoshis
    bool spent{false};          //!< true if the output has been spent
    uint256 spending_txid;      //!< tx that spent it (valid iff spent)
    int32_t spending_height{0}; //!< height of the spend (valid iff spent)
};

/**
 * AddressIndex maps every scriptPubKey to the outputs that pay it and records
 * which outpoints have been spent, so a node can answer address balance,
 * history and UTXO queries — the trusted-mode serving layer for wallets and
 * explorers. Self-contained (never reads block files after indexing), so it is
 * compatible with pruning, including pruned-hazed nodes.
 */
class AddressIndex final : public BaseIndex
{
protected:
    class DB;

private:
    const std::unique_ptr<DB> m_db;

    // The index keeps its own database, so it does not need the block files
    // retained — it works fine on a pruned (and pruned-hazed) node.
    bool AllowPrune() const override { return true; }

protected:
    bool CustomAppend(const interfaces::BlockInfo& block) override;
    bool CustomRemove(const interfaces::BlockInfo& block) override;

    BaseIndex::DB& GetDB() const override;

public:
    explicit AddressIndex(std::unique_ptr<interfaces::Chain> chain, size_t n_cache_size, bool f_memory = false, bool f_wipe = false);

    virtual ~AddressIndex() override;

    //! Return every output paying `script`, each annotated with spent status.
    //! Entries are returned unsorted; callers sort as needed.
    bool FindActivity(const CScript& script, std::vector<AddressIndexEntry>& entries) const;
};

/// The global address index. May be null.
extern std::unique_ptr<AddressIndex> g_addressindex;

#endif // BITCOIN_INDEX_ADDRESSINDEX_H

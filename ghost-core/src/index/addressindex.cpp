// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <index/addressindex.h>

#include <common/args.h>
#include <dbwrapper.h>
#include <hash.h>
#include <interfaces/chain.h>
#include <logging.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>

#include <memory>
#include <utility>

// DB key prefixes.
constexpr uint8_t DB_ADDRESS_OUTPUT{'a'}; //!< outputs paying a script
constexpr uint8_t DB_ADDRESS_SPENT{'b'};  //!< spent outpoints

std::unique_ptr<AddressIndex> g_addressindex;

namespace {
//! Fixed-size, prefix-scannable key for an output paying `script_hash`.
struct OutputKey {
    uint256 script_hash;
    uint32_t height{0};
    uint256 txid;
    uint32_t index{0};

    SERIALIZE_METHODS(OutputKey, obj)
    {
        READWRITE(obj.script_hash, obj.height, obj.txid, obj.index);
    }
};

//! Key marking an outpoint (txid:index) as spent.
struct SpentKey {
    uint256 txid;
    uint32_t index{0};

    SERIALIZE_METHODS(SpentKey, obj) { READWRITE(obj.txid, obj.index); }
};

//! Where an outpoint was spent.
struct SpentValue {
    uint32_t height{0};
    uint256 spending_txid;

    SERIALIZE_METHODS(SpentValue, obj) { READWRITE(obj.height, obj.spending_txid); }
};

//! Double-SHA256 of a scriptPubKey — a uniform-length index key.
uint256 ScriptHash(const CScript& script)
{
    return (HashWriter{} << script).GetHash();
}
} // namespace

/** Access to the address index database (indexes/addressindex/) */
class AddressIndex::DB : public BaseIndex::DB
{
public:
    explicit DB(size_t n_cache_size, bool f_memory = false, bool f_wipe = false);
};

AddressIndex::DB::DB(size_t n_cache_size, bool f_memory, bool f_wipe) :
    BaseIndex::DB(gArgs.GetDataDirNet() / "indexes" / "addressindex", n_cache_size, f_memory, f_wipe)
{}

AddressIndex::AddressIndex(std::unique_ptr<interfaces::Chain> chain, size_t n_cache_size, bool f_memory, bool f_wipe)
    : BaseIndex(std::move(chain), "addressindex"),
      m_db(std::make_unique<AddressIndex::DB>(n_cache_size, f_memory, f_wipe))
{}

AddressIndex::~AddressIndex() = default;

BaseIndex::DB& AddressIndex::GetDB() const { return *m_db; }

bool AddressIndex::CustomAppend(const interfaces::BlockInfo& block)
{
    // Genesis outputs are unspendable and never referenced.
    if (block.height == 0) return true;
    assert(block.data);

    CDBBatch batch(*m_db);
    for (const auto& txref : block.data->vtx) {
        const CTransaction& tx = *txref;
        const uint256 txid = tx.GetHash().ToUint256();

        // Record every output against the script it pays.
        for (uint32_t n = 0; n < tx.vout.size(); ++n) {
            const CTxOut& out = tx.vout[n];
            if (out.scriptPubKey.empty()) continue;
            batch.Write(std::make_pair(DB_ADDRESS_OUTPUT,
                                       OutputKey{ScriptHash(out.scriptPubKey),
                                                 static_cast<uint32_t>(block.height), txid, n}),
                        static_cast<int64_t>(out.nValue));
        }

        // Mark each spent outpoint (coinbase has none).
        if (!tx.IsCoinBase()) {
            for (const auto& in : tx.vin) {
                batch.Write(std::make_pair(DB_ADDRESS_SPENT,
                                           SpentKey{in.prevout.hash.ToUint256(), in.prevout.n}),
                            SpentValue{static_cast<uint32_t>(block.height), txid});
            }
        }
    }
    return m_db->WriteBatch(batch);
}

bool AddressIndex::CustomRemove(const interfaces::BlockInfo& block)
{
    if (block.height == 0) return true;
    assert(block.data);

    CDBBatch batch(*m_db);
    for (const auto& txref : block.data->vtx) {
        const CTransaction& tx = *txref;
        const uint256 txid = tx.GetHash().ToUint256();
        for (uint32_t n = 0; n < tx.vout.size(); ++n) {
            const CTxOut& out = tx.vout[n];
            if (out.scriptPubKey.empty()) continue;
            batch.Erase(std::make_pair(DB_ADDRESS_OUTPUT,
                                       OutputKey{ScriptHash(out.scriptPubKey),
                                                 static_cast<uint32_t>(block.height), txid, n}));
        }
        if (!tx.IsCoinBase()) {
            for (const auto& in : tx.vin) {
                batch.Erase(std::make_pair(DB_ADDRESS_SPENT,
                                           SpentKey{in.prevout.hash.ToUint256(), in.prevout.n}));
            }
        }
    }
    return m_db->WriteBatch(batch);
}

bool AddressIndex::FindActivity(const CScript& script, std::vector<AddressIndexEntry>& entries) const
{
    const uint256 script_hash = ScriptHash(script);

    std::unique_ptr<CDBIterator> it(m_db->NewIterator());
    it->Seek(std::make_pair(DB_ADDRESS_OUTPUT, OutputKey{script_hash, 0, uint256{}, 0}));
    for (; it->Valid(); it->Next()) {
        std::pair<uint8_t, OutputKey> key;
        if (!it->GetKey(key)) break;
        if (key.first != DB_ADDRESS_OUTPUT || key.second.script_hash != script_hash) break;

        int64_t value{0};
        if (!it->GetValue(value)) continue;

        AddressIndexEntry entry;
        entry.txid = key.second.txid;
        entry.index = key.second.index;
        entry.height = static_cast<int32_t>(key.second.height);
        entry.value = value;

        SpentValue sv;
        if (m_db->Read(std::make_pair(DB_ADDRESS_SPENT, SpentKey{entry.txid, entry.index}), sv)) {
            entry.spent = true;
            entry.spending_txid = sv.spending_txid;
            entry.spending_height = static_cast<int32_t>(sv.height);
        }
        entries.push_back(std::move(entry));
    }
    return true;
}

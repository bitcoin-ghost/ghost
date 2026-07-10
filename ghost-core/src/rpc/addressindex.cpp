// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <index/addressindex.h>
#include <key_io.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/signingprovider.h>
#include <univalue.h>

#include <algorithm>
#include <set>
#include <vector>

namespace {

//! Resolve an address string to the scriptPubKey it locks, or throw.
CScript ScriptForAddress(const std::string& address)
{
    const CTxDestination dest = DecodeDestination(address);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid address: ") + address);
    }
    return GetScriptForDestination(dest);
}

//! Fetch address activity from the index, or throw if the index is unavailable.
std::vector<AddressIndexEntry> QueryAddress(const std::string& address)
{
    if (!g_addressindex) {
        throw JSONRPCError(RPC_MISC_ERROR, "Address index is not enabled. Restart with -addressindex.");
    }
    if (!g_addressindex->BlockUntilSyncedToCurrentChain()) {
        throw JSONRPCError(RPC_MISC_ERROR, "Address index is still syncing. Try again shortly.");
    }
    std::vector<AddressIndexEntry> entries;
    g_addressindex->FindActivity(ScriptForAddress(address), entries);
    return entries;
}

RPCHelpMan getaddressbalance()
{
    return RPCHelpMan{
        "getaddressbalance",
        "Return the confirmed balance and total received for an address, from the address index.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The address to query"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "balance", "Current spendable balance in satoshis"},
                {RPCResult::Type::NUM, "received", "Total ever received in satoshis"},
            }},
        RPCExamples{HelpExampleCli("getaddressbalance", "\"bcrt1q...\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            const auto entries = QueryAddress(request.params[0].get_str());
            int64_t balance{0}, received{0};
            for (const auto& e : entries) {
                received += e.value;
                if (!e.spent) balance += e.value;
            }
            UniValue result(UniValue::VOBJ);
            result.pushKV("balance", balance);
            result.pushKV("received", received);
            return result;
        },
    };
}

RPCHelpMan getaddressutxos()
{
    return RPCHelpMan{
        "getaddressutxos",
        "Return the unspent outputs (UTXOs) paying an address, from the address index.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The address to query"},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                 {
                     {RPCResult::Type::STR_HEX, "txid", "The output's transaction id"},
                     {RPCResult::Type::NUM, "outputIndex", "The output index (vout)"},
                     {RPCResult::Type::NUM, "height", "The block height of the output"},
                     {RPCResult::Type::NUM, "satoshis", "The output value in satoshis"},
                 }},
            }},
        RPCExamples{HelpExampleCli("getaddressutxos", "\"bcrt1q...\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto entries = QueryAddress(request.params[0].get_str());
            std::sort(entries.begin(), entries.end(), [](const AddressIndexEntry& a, const AddressIndexEntry& b) {
                return a.height < b.height;
            });
            UniValue result(UniValue::VARR);
            for (const auto& e : entries) {
                if (e.spent) continue;
                UniValue u(UniValue::VOBJ);
                u.pushKV("txid", e.txid.GetHex());
                u.pushKV("outputIndex", static_cast<uint64_t>(e.index));
                u.pushKV("height", e.height);
                u.pushKV("satoshis", e.value);
                result.push_back(std::move(u));
            }
            return result;
        },
    };
}

RPCHelpMan getaddresstxids()
{
    return RPCHelpMan{
        "getaddresstxids",
        "Return every transaction id that funded or spent an address, from the address index.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The address to query"},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "A transaction id touching the address"},
            }},
        RPCExamples{HelpExampleCli("getaddresstxids", "\"bcrt1q...\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            const auto entries = QueryAddress(request.params[0].get_str());
            // Preserve first-seen order by height while de-duplicating.
            std::vector<std::pair<int32_t, uint256>> ordered;
            std::set<uint256> seen;
            for (const auto& e : entries) {
                if (seen.insert(e.txid).second) ordered.emplace_back(e.height, e.txid);
                if (e.spent && seen.insert(e.spending_txid).second) {
                    ordered.emplace_back(e.spending_height, e.spending_txid);
                }
            }
            std::stable_sort(ordered.begin(), ordered.end(),
                             [](const auto& a, const auto& b) { return a.first < b.first; });
            UniValue result(UniValue::VARR);
            for (const auto& [height, txid] : ordered) result.push_back(txid.GetHex());
            return result;
        },
    };
}

RPCHelpMan scanaddressindex()
{
    return RPCHelpMan{
        "scanaddressindex",
        "Scan a descriptor (or xpub) against the address index and aggregate balance, UTXOs and history\n"
        "across every derived address. The trusted-mode equivalent of an xpub rescan — it works on pruned\n"
        "and hazed nodes because the address index never reads block files, only structural data.\n",
        {
            {"descriptor", RPCArg::Type::STR, RPCArg::Optional::NO,
             "An output descriptor to scan, ranged for an xpub sweep, e.g. \"wpkh(xpub6C.../0/*)\""},
            {"range", RPCArg::Type::RANGE, RPCArg::Optional::OMITTED,
             "The child-index range to derive: a single number (0..N) or a [begin,end] array. Default 0..1000."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "scanned", "Number of scripts derived from the descriptor"},
                {RPCResult::Type::NUM, "used", "How many derived addresses had any activity"},
                {RPCResult::Type::NUM, "balance", "Combined spendable balance in satoshis"},
                {RPCResult::Type::NUM, "received", "Combined total ever received in satoshis"},
                {RPCResult::Type::ARR, "utxos", "Combined unspent outputs, oldest first",
                 {
                     {RPCResult::Type::OBJ, "", "",
                      {
                          {RPCResult::Type::STR_HEX, "txid", "The output's transaction id"},
                          {RPCResult::Type::NUM, "outputIndex", "The output index (vout)"},
                          {RPCResult::Type::NUM, "height", "The block height of the output"},
                          {RPCResult::Type::NUM, "satoshis", "The output value in satoshis"},
                          {RPCResult::Type::STR, "address", /*optional=*/true, "The address that owns the output, if decodable"},
                      }},
                 }},
                {RPCResult::Type::ARR, "txids", "Every txid touching any derived address, oldest first",
                 {
                     {RPCResult::Type::STR_HEX, "txid", "A transaction id touching the descriptor"},
                 }},
            }},
        RPCExamples{
            HelpExampleCli("scanaddressindex", "\"wpkh(xpub6C.../0/*)\"") +
            HelpExampleCli("scanaddressindex", "\"wpkh(xpub6C.../0/*)\" 499")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            if (!g_addressindex) {
                throw JSONRPCError(RPC_MISC_ERROR, "Address index is not enabled. Restart with -addressindex.");
            }
            if (!g_addressindex->BlockUntilSyncedToCurrentChain()) {
                throw JSONRPCError(RPC_MISC_ERROR, "Address index is still syncing. Try again shortly.");
            }

            // Fold the (descriptor, range) params back into a scanobject so the
            // shared descriptor evaluator handles parsing and range expansion.
            UniValue scanobject(UniValue::VOBJ);
            scanobject.pushKV("desc", request.params[0].get_str());
            if (!request.params[1].isNull()) scanobject.pushKV("range", request.params[1]);
            FlatSigningProvider provider;
            const std::vector<CScript> scripts = EvalDescriptorStringOrObject(scanobject, provider);

            struct UtxoRow { AddressIndexEntry entry; std::string address; };
            int64_t balance{0}, received{0};
            int used{0};
            std::vector<UtxoRow> utxos;
            std::vector<std::pair<int32_t, uint256>> ordered_txids;
            std::set<uint256> seen;

            for (const CScript& script : scripts) {
                std::string address;
                CTxDestination dest;
                if (ExtractDestination(script, dest)) address = EncodeDestination(dest);

                std::vector<AddressIndexEntry> entries;
                g_addressindex->FindActivity(script, entries);
                if (!entries.empty()) ++used;
                for (const auto& e : entries) {
                    received += e.value;
                    if (!e.spent) {
                        balance += e.value;
                        utxos.push_back({e, address});
                    }
                    if (seen.insert(e.txid).second) ordered_txids.emplace_back(e.height, e.txid);
                    if (e.spent && seen.insert(e.spending_txid).second) {
                        ordered_txids.emplace_back(e.spending_height, e.spending_txid);
                    }
                }
            }

            std::sort(utxos.begin(), utxos.end(), [](const UtxoRow& a, const UtxoRow& b) {
                return a.entry.height < b.entry.height;
            });
            std::stable_sort(ordered_txids.begin(), ordered_txids.end(),
                             [](const auto& a, const auto& b) { return a.first < b.first; });

            UniValue utxo_arr(UniValue::VARR);
            for (const auto& row : utxos) {
                UniValue u(UniValue::VOBJ);
                u.pushKV("txid", row.entry.txid.GetHex());
                u.pushKV("outputIndex", static_cast<uint64_t>(row.entry.index));
                u.pushKV("height", row.entry.height);
                u.pushKV("satoshis", row.entry.value);
                if (!row.address.empty()) u.pushKV("address", row.address);
                utxo_arr.push_back(std::move(u));
            }
            UniValue txid_arr(UniValue::VARR);
            for (const auto& [height, txid] : ordered_txids) txid_arr.push_back(txid.GetHex());

            UniValue result(UniValue::VOBJ);
            result.pushKV("scanned", static_cast<uint64_t>(scripts.size()));
            result.pushKV("used", used);
            result.pushKV("balance", balance);
            result.pushKV("received", received);
            result.pushKV("utxos", std::move(utxo_arr));
            result.pushKV("txids", std::move(txid_arr));
            return result;
        },
    };
}

} // namespace

void RegisterAddressindexRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"addressindex", &getaddressbalance},
        {"addressindex", &getaddressutxos},
        {"addressindex", &getaddresstxids},
        {"addressindex", &scanaddressindex},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}

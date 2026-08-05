// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/blockchain.h>

#include <blockfilter.h>
#include <chain.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <coins.h>
#include <common/args.h>
#include <consensus/amount.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <deploymentinfo.h>
#include <deploymentstatus.h>
#include <flatfile.h>
#include <hash.h>
#include <haze/block_reconstruct.h>
#include <haze/checkpoint.h>
#include <haze/checkpoint_signing.h>
#include <haze/hazync_proof.h>
#include <haze/stripped_block.h>
#include <index/blockfilterindex.h>
#include <index/coinstatsindex.h>
#include <interfaces/mining.h>
#include <kernel/coinstats.h>
#include <logging/timer.h>
#include <net.h>
#include <net_processing.h>
#include <netmessagemaker.h>
#include <node/blockstorage.h>
#include <node/context.h>
#include <node/transaction.h>
#include <node/utxo_snapshot.h>
#include <node/warnings.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <serialize.h>
#include <streams.h>
#include <sync.h>
#include <txdb.h>
#include <txmempool.h>
#include <undo.h>
#include <univalue.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <util/syserror.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>
#include <versionbits.h>

#include <cstdint>
#include <fstream>

#include <condition_variable>
#include <iterator>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

using kernel::CCoinsStats;
using kernel::CoinStatsHashType;

using interfaces::BlockRef;
using interfaces::Mining;
using node::BlockManager;
using node::NodeContext;
using node::SnapshotMetadata;
using util::MakeUnorderedList;

std::tuple<std::unique_ptr<CCoinsViewCursor>, CCoinsStats, const CBlockIndex*>
PrepareUTXOSnapshot(
    Chainstate& chainstate,
    const std::function<void()>& interruption_point = {})
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

UniValue WriteUTXOSnapshot(
    Chainstate& chainstate,
    CCoinsViewCursor* pcursor,
    CCoinsStats* maybe_stats,
    const CBlockIndex* tip,
    AutoFile&& afile,
    const fs::path& path,
    const fs::path& temppath,
    const std::function<void()>& interruption_point = {});

/* Calculate the difficulty for a given block index.
 */
double GetDifficulty(const CBlockIndex& blockindex)
{
    int nShift = (blockindex.nBits >> 24) & 0xff;
    double dDiff =
        (double)0x0000ffff / (double)(blockindex.nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

static int ComputeNextBlockAndDepth(const CBlockIndex& tip, const CBlockIndex& blockindex, const CBlockIndex*& next)
{
    next = tip.GetAncestor(blockindex.nHeight + 1);
    if (next && next->pprev == &blockindex) {
        return tip.nHeight - blockindex.nHeight + 1;
    }
    next = nullptr;
    return &blockindex == &tip ? 1 : -1;
}

static const CBlockIndex* ParseHashOrHeight(const UniValue& param, ChainstateManager& chainman)
{
    LOCK(::cs_main);
    CChain& active_chain = chainman.ActiveChain();

    if (param.isNum()) {
        const int height{param.getInt<int>()};
        if (height < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Target block height %d is negative", height));
        }
        const int current_tip{active_chain.Height()};
        if (height > current_tip) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Target block height %d after current tip %d", height, current_tip));
        }

        return active_chain[height];
    } else {
        const uint256 hash{ParseHashV(param, "hash_or_height")};
        const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hash);

        if (!pindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }

        return pindex;
    }
}

UniValue blockheaderToJSON(const CBlockIndex& tip, const CBlockIndex& blockindex, const uint256 pow_limit)
{
    // Serialize passed information without accessing chain state of the active chain!
    AssertLockNotHeld(cs_main); // For performance reasons

    UniValue result(UniValue::VOBJ);
    result.pushKV("hash", blockindex.GetBlockHash().GetHex());
    const CBlockIndex* pnext;
    int confirmations = ComputeNextBlockAndDepth(tip, blockindex, pnext);
    result.pushKV("confirmations", confirmations);
    result.pushKV("height", blockindex.nHeight);
    result.pushKV("version", blockindex.nVersion);
    result.pushKV("versionHex", strprintf("%08x", blockindex.nVersion));
    result.pushKV("merkleroot", blockindex.hashMerkleRoot.GetHex());
    result.pushKV("time", blockindex.nTime);
    result.pushKV("mediantime", blockindex.GetMedianTimePast());
    result.pushKV("nonce", blockindex.nNonce);
    result.pushKV("bits", strprintf("%08x", blockindex.nBits));
    result.pushKV("target", GetTarget(blockindex, pow_limit).GetHex());
    result.pushKV("difficulty", GetDifficulty(blockindex));
    result.pushKV("chainwork", blockindex.nChainWork.GetHex());
    result.pushKV("nTx", blockindex.nTx);

    if (blockindex.pprev)
        result.pushKV("previousblockhash", blockindex.pprev->GetBlockHash().GetHex());
    if (pnext)
        result.pushKV("nextblockhash", pnext->GetBlockHash().GetHex());
    return result;
}

UniValue blockToJSON(BlockManager& blockman, const CBlock& block, const CBlockIndex& tip, const CBlockIndex& blockindex, TxVerbosity verbosity, const uint256 pow_limit, bool is_hazed, const std::vector<uint256>* original_txids)
{
    UniValue result = blockheaderToJSON(tip, blockindex, pow_limit);

    result.pushKV("strippedsize", (int)::GetSerializeSize(TX_NO_WITNESS(block)));
    result.pushKV("size", (int)::GetSerializeSize(TX_WITH_WITNESS(block)));
    result.pushKV("weight", (int)::GetBlockWeight(block));
    UniValue txs(UniValue::VARR);
    txs.reserve(block.vtx.size());

    switch (verbosity) {
        case TxVerbosity::SHOW_TXID:
            for (size_t i = 0; i < block.vtx.size(); ++i) {
                if (original_txids && i < original_txids->size()) {
                    txs.push_back((*original_txids)[i].GetHex());
                } else {
                    txs.push_back(block.vtx[i]->GetHash().GetHex());
                }
            }
            break;

        case TxVerbosity::SHOW_DETAILS:
        case TxVerbosity::SHOW_DETAILS_AND_PREVOUT:
            CBlockUndo blockUndo;
            const bool is_not_pruned{WITH_LOCK(::cs_main, return !blockman.IsBlockPruned(blockindex))};
            // Hazed nodes don't have undo data
            bool have_undo{!is_hazed && is_not_pruned && WITH_LOCK(::cs_main, return blockindex.nStatus & BLOCK_HAVE_UNDO)};
            if (have_undo && !blockman.ReadBlockUndo(blockUndo, blockindex)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Undo data expected but can't be read. This could be due to disk corruption or a conflict with a pruning event.");
            }
            for (size_t i = 0; i < block.vtx.size(); ++i) {
                const CTransactionRef& tx = block.vtx.at(i);
                // coinbase transaction (i.e. i == 0) doesn't have undo data
                const CTxUndo* txundo = (have_undo && i > 0) ? &blockUndo.vtxundo.at(i - 1) : nullptr;
                const uint256* override_txid = (original_txids && i < original_txids->size())
                    ? &(*original_txids)[i] : nullptr;
                UniValue objTx(UniValue::VOBJ);
                TxToUniv(*tx, /*block_hash=*/uint256(), /*entry=*/objTx, /*include_hex=*/true, txundo, verbosity, is_hazed, override_txid);
                txs.push_back(std::move(objTx));
            }
            break;
    }

    result.pushKV("tx", std::move(txs));

    if (is_hazed) {
        UniValue haze_status(UniValue::VOBJ);
        haze_status.pushKV("mode", "hazed");
        UniValue fields(UniValue::VARR);
        fields.push_back("witness");
        fields.push_back("scriptsig");
        fields.push_back("op_return_data");
        fields.push_back("coinbase");
        haze_status.pushKV("fields_stripped", std::move(fields));
        result.pushKV("haze_status", std::move(haze_status));
    }

    return result;
}

static RPCHelpMan getblockcount()
{
    return RPCHelpMan{
        "getblockcount",
        "Returns the height of the most-work fully-validated chain.\n"
                "The genesis block has height 0.\n",
                {},
                RPCResult{
                    RPCResult::Type::NUM, "", "The current block count"},
                RPCExamples{
                    HelpExampleCli("getblockcount", "")
            + HelpExampleRpc("getblockcount", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    return chainman.ActiveChain().Height();
},
    };
}

static RPCHelpMan getbestblockhash()
{
    return RPCHelpMan{
        "getbestblockhash",
        "Returns the hash of the best (tip) block in the most-work fully-validated chain.\n",
                {},
                RPCResult{
                    RPCResult::Type::STR_HEX, "", "the block hash, hex-encoded"},
                RPCExamples{
                    HelpExampleCli("getbestblockhash", "")
            + HelpExampleRpc("getbestblockhash", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    return chainman.ActiveChain().Tip()->GetBlockHash().GetHex();
},
    };
}

static RPCHelpMan waitfornewblock()
{
    return RPCHelpMan{
        "waitfornewblock",
        "Waits for any new block and returns useful info about it.\n"
                "\nReturns the current block on timeout or exit.\n"
                "\nMake sure to use no RPC timeout (bitcoin-cli -rpcclienttimeout=0)",
                {
                    {"timeout", RPCArg::Type::NUM, RPCArg::Default{0}, "Time in milliseconds to wait for a response. 0 indicates no timeout."},
                    {"current_tip", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Method waits for the chain tip to differ from this."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hash", "The blockhash"},
                        {RPCResult::Type::NUM, "height", "Block height"},
                    }},
                RPCExamples{
                    HelpExampleCli("waitfornewblock", "1000")
            + HelpExampleRpc("waitfornewblock", "1000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    int timeout = 0;
    if (!request.params[0].isNull())
        timeout = request.params[0].getInt<int>();
    if (timeout < 0) throw JSONRPCError(RPC_MISC_ERROR, "Negative timeout");

    NodeContext& node = EnsureAnyNodeContext(request.context);
    Mining& miner = EnsureMining(node);

    // If the caller provided a current_tip value, pass it to waitTipChanged().
    //
    // If the caller did not provide a current tip hash, call getTip() to get
    // one and wait for the tip to be different from this value. This mode is
    // less reliable because if the tip changed between waitfornewblock calls,
    // it will need to change a second time before this call returns.
    BlockRef current_block{CHECK_NONFATAL(miner.getTip()).value()};

    uint256 tip_hash{request.params[1].isNull()
        ? current_block.hash
        : ParseHashV(request.params[1], "current_tip")};

    // If the user provided an invalid current_tip then this call immediately
    // returns the current tip.
    std::optional<BlockRef> block = timeout ? miner.waitTipChanged(tip_hash, std::chrono::milliseconds(timeout)) :
                                              miner.waitTipChanged(tip_hash);

    // Return current block upon shutdown
    if (block) current_block = *block;

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("hash", current_block.hash.GetHex());
    ret.pushKV("height", current_block.height);
    return ret;
},
    };
}

static RPCHelpMan waitforblock()
{
    return RPCHelpMan{
        "waitforblock",
        "Waits for a specific new block and returns useful info about it.\n"
                "\nReturns the current block on timeout or exit.\n"
                "\nMake sure to use no RPC timeout (bitcoin-cli -rpcclienttimeout=0)",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Block hash to wait for."},
                    {"timeout", RPCArg::Type::NUM, RPCArg::Default{0}, "Time in milliseconds to wait for a response. 0 indicates no timeout."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hash", "The blockhash"},
                        {RPCResult::Type::NUM, "height", "Block height"},
                    }},
                RPCExamples{
                    HelpExampleCli("waitforblock", "\"0000000000079f8ef3d2c688c244eb7a4570b24c9ed7b4a8c619eb02596f8862\" 1000")
            + HelpExampleRpc("waitforblock", "\"0000000000079f8ef3d2c688c244eb7a4570b24c9ed7b4a8c619eb02596f8862\", 1000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    int timeout = 0;

    uint256 hash(ParseHashV(request.params[0], "blockhash"));

    if (!request.params[1].isNull())
        timeout = request.params[1].getInt<int>();
    if (timeout < 0) throw JSONRPCError(RPC_MISC_ERROR, "Negative timeout");

    NodeContext& node = EnsureAnyNodeContext(request.context);
    Mining& miner = EnsureMining(node);

    // Abort if RPC came out of warmup too early
    BlockRef current_block{CHECK_NONFATAL(miner.getTip()).value()};

    const auto deadline{std::chrono::steady_clock::now() + 1ms * timeout};
    while (current_block.hash != hash) {
        std::optional<BlockRef> block;
        if (timeout) {
            auto now{std::chrono::steady_clock::now()};
            if (now >= deadline) break;
            const MillisecondsDouble remaining{deadline - now};
            block = miner.waitTipChanged(current_block.hash, remaining);
        } else {
            block = miner.waitTipChanged(current_block.hash);
        }
        // Return current block upon shutdown
        if (!block) break;
        current_block = *block;
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("hash", current_block.hash.GetHex());
    ret.pushKV("height", current_block.height);
    return ret;
},
    };
}

static RPCHelpMan waitforblockheight()
{
    return RPCHelpMan{
        "waitforblockheight",
        "Waits for (at least) block height and returns the height and hash\n"
                "of the current tip.\n"
                "\nReturns the current block on timeout or exit.\n"
                "\nMake sure to use no RPC timeout (bitcoin-cli -rpcclienttimeout=0)",
                {
                    {"height", RPCArg::Type::NUM, RPCArg::Optional::NO, "Block height to wait for."},
                    {"timeout", RPCArg::Type::NUM, RPCArg::Default{0}, "Time in milliseconds to wait for a response. 0 indicates no timeout."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hash", "The blockhash"},
                        {RPCResult::Type::NUM, "height", "Block height"},
                    }},
                RPCExamples{
                    HelpExampleCli("waitforblockheight", "100 1000")
            + HelpExampleRpc("waitforblockheight", "100, 1000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    int timeout = 0;

    int height = request.params[0].getInt<int>();

    if (!request.params[1].isNull())
        timeout = request.params[1].getInt<int>();
    if (timeout < 0) throw JSONRPCError(RPC_MISC_ERROR, "Negative timeout");

    NodeContext& node = EnsureAnyNodeContext(request.context);
    Mining& miner = EnsureMining(node);

    // Abort if RPC came out of warmup too early
    BlockRef current_block{CHECK_NONFATAL(miner.getTip()).value()};

    const auto deadline{std::chrono::steady_clock::now() + 1ms * timeout};

    while (current_block.height < height) {
        std::optional<BlockRef> block;
        if (timeout) {
            auto now{std::chrono::steady_clock::now()};
            if (now >= deadline) break;
            const MillisecondsDouble remaining{deadline - now};
            block = miner.waitTipChanged(current_block.hash, remaining);
        } else {
            block = miner.waitTipChanged(current_block.hash);
        }
        // Return current block on shutdown
        if (!block) break;
        current_block = *block;
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("hash", current_block.hash.GetHex());
    ret.pushKV("height", current_block.height);
    return ret;
},
    };
}

static RPCHelpMan syncwithvalidationinterfacequeue()
{
    return RPCHelpMan{
        "syncwithvalidationinterfacequeue",
        "Waits for the validation interface queue to catch up on everything that was there when we entered this function.\n",
                {},
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("syncwithvalidationinterfacequeue","")
            + HelpExampleRpc("syncwithvalidationinterfacequeue","")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    CHECK_NONFATAL(node.validation_signals)->SyncWithValidationInterfaceQueue();
    return UniValue::VNULL;
},
    };
}

static RPCHelpMan getdifficulty()
{
    return RPCHelpMan{
        "getdifficulty",
        "Returns the proof-of-work difficulty as a multiple of the minimum difficulty.\n",
                {},
                RPCResult{
                    RPCResult::Type::NUM, "", "the proof-of-work difficulty as a multiple of the minimum difficulty."},
                RPCExamples{
                    HelpExampleCli("getdifficulty", "")
            + HelpExampleRpc("getdifficulty", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    return GetDifficulty(*CHECK_NONFATAL(chainman.ActiveChain().Tip()));
},
    };
}

static RPCHelpMan getblockfrompeer()
{
    return RPCHelpMan{
        "getblockfrompeer",
        "Attempt to fetch block from a given peer.\n\n"
        "We must have the header for this block, e.g. using submitheader.\n"
        "The block will not have any undo data which can limit the usage of the block data in a context where the undo data is needed.\n"
        "Subsequent calls for the same block may cause the response from the previous peer to be ignored.\n"
        "Peers generally ignore requests for a stale block that they never fully verified, or one that is more than a month old.\n"
        "When a peer does not respond with a block, we will disconnect.\n"
        "Note: The block could be re-pruned as soon as it is received.\n\n"
        "Returns an empty JSON object if the request was successfully scheduled.",
        {
            {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash to try to fetch"},
            {"peer_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "The peer to fetch it from (see getpeerinfo for peer IDs)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", /*optional=*/false, "", {}},
        RPCExamples{
            HelpExampleCli("getblockfrompeer", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\" 0")
            + HelpExampleRpc("getblockfrompeer", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\" 0")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    PeerManager& peerman = EnsurePeerman(node);

    const uint256& block_hash{ParseHashV(request.params[0], "blockhash")};
    const NodeId peer_id{request.params[1].getInt<int64_t>()};

    const CBlockIndex* const index = WITH_LOCK(cs_main, return chainman.m_blockman.LookupBlockIndex(block_hash););

    if (!index) {
        throw JSONRPCError(RPC_MISC_ERROR, "Block header missing");
    }

    // Fetching blocks before the node has syncing past their height can prevent block files from
    // being pruned, so we avoid it if the node is in prune mode.
    if (chainman.m_blockman.IsPruneMode() && index->nHeight > WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip()->nHeight)) {
        throw JSONRPCError(RPC_MISC_ERROR, "In prune mode, only blocks that the node has already synced previously can be fetched from a peer");
    }

    const bool block_has_data = WITH_LOCK(::cs_main, return index->nStatus & BLOCK_HAVE_DATA);
    if (block_has_data) {
        throw JSONRPCError(RPC_MISC_ERROR, "Block already downloaded");
    }

    if (const auto err{peerman.FetchBlock(peer_id, *index)}) {
        throw JSONRPCError(RPC_MISC_ERROR, err.value());
    }
    return UniValue::VOBJ;
},
    };
}

static RPCHelpMan getblockhash()
{
    return RPCHelpMan{
        "getblockhash",
        "Returns hash of block in best-block-chain at height provided.\n",
                {
                    {"height", RPCArg::Type::NUM, RPCArg::Optional::NO, "The height index"},
                },
                RPCResult{
                    RPCResult::Type::STR_HEX, "", "The block hash"},
                RPCExamples{
                    HelpExampleCli("getblockhash", "1000")
            + HelpExampleRpc("getblockhash", "1000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    const CChain& active_chain = chainman.ActiveChain();

    int nHeight = request.params[0].getInt<int>();
    if (nHeight < 0 || nHeight > active_chain.Height())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");

    const CBlockIndex* pblockindex = active_chain[nHeight];
    return pblockindex->GetBlockHash().GetHex();
},
    };
}

static RPCHelpMan getblockheader()
{
    return RPCHelpMan{
        "getblockheader",
        "If verbose is false, returns a string that is serialized, hex-encoded data for blockheader 'hash'.\n"
                "If verbose is true, returns an Object with information about blockheader <hash>.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash"},
                    {"verbose", RPCArg::Type::BOOL, RPCArg::Default{true}, "true for a json object, false for the hex-encoded data"},
                },
                {
                    RPCResult{"for verbose = true",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "hash", "the block hash (same as provided)"},
                            {RPCResult::Type::NUM, "confirmations", "The number of confirmations, or -1 if the block is not on the main chain"},
                            {RPCResult::Type::NUM, "height", "The block height or index"},
                            {RPCResult::Type::NUM, "version", "The block version"},
                            {RPCResult::Type::STR_HEX, "versionHex", "The block version formatted in hexadecimal"},
                            {RPCResult::Type::STR_HEX, "merkleroot", "The merkle root"},
                            {RPCResult::Type::NUM_TIME, "time", "The block time expressed in " + UNIX_EPOCH_TIME},
                            {RPCResult::Type::NUM_TIME, "mediantime", "The median block time expressed in " + UNIX_EPOCH_TIME},
                            {RPCResult::Type::NUM, "nonce", "The nonce"},
                            {RPCResult::Type::STR_HEX, "bits", "nBits: compact representation of the block difficulty target"},
                            {RPCResult::Type::STR_HEX, "target", "The difficulty target"},
                            {RPCResult::Type::NUM, "difficulty", "The difficulty"},
                            {RPCResult::Type::STR_HEX, "chainwork", "Expected number of hashes required to produce the current chain"},
                            {RPCResult::Type::NUM, "nTx", "The number of transactions in the block"},
                            {RPCResult::Type::STR_HEX, "previousblockhash", /*optional=*/true, "The hash of the previous block (if available)"},
                            {RPCResult::Type::STR_HEX, "nextblockhash", /*optional=*/true, "The hash of the next block (if available)"},
                        }},
                    RPCResult{"for verbose=false",
                        RPCResult::Type::STR_HEX, "", "A string that is serialized, hex-encoded data for block 'hash'"},
                },
                RPCExamples{
                    HelpExampleCli("getblockheader", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
            + HelpExampleRpc("getblockheader", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    uint256 hash(ParseHashV(request.params[0], "hash"));

    bool fVerbose = true;
    if (!request.params[1].isNull())
        fVerbose = request.params[1].get_bool();

    const CBlockIndex* pblockindex;
    const CBlockIndex* tip;
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    {
        LOCK(cs_main);
        pblockindex = chainman.m_blockman.LookupBlockIndex(hash);
        tip = chainman.ActiveChain().Tip();
    }

    if (!pblockindex) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
    }

    if (!fVerbose)
    {
        DataStream ssBlock{};
        ssBlock << pblockindex->GetBlockHeader();
        std::string strHex = HexStr(ssBlock);
        return strHex;
    }

    return blockheaderToJSON(*tip, *pblockindex, chainman.GetConsensus().powLimit);
},
    };
}

void CheckBlockDataAvailability(BlockManager& blockman, const CBlockIndex& blockindex, bool check_for_undo)
{
    AssertLockHeld(cs_main);
    uint32_t flag = check_for_undo ? BLOCK_HAVE_UNDO : BLOCK_HAVE_DATA;
    if (!(blockindex.nStatus & flag)) {
        if (blockman.IsBlockPruned(blockindex)) {
            throw JSONRPCError(RPC_MISC_ERROR, strprintf("%s not available (pruned data)", check_for_undo ? "Undo data" : "Block"));
        }
        if (check_for_undo) {
            throw JSONRPCError(RPC_MISC_ERROR, "Undo data not available");
        }
        throw JSONRPCError(RPC_MISC_ERROR, "Block not available (not fully downloaded)");
    }
}

static CBlock GetBlockChecked(BlockManager& blockman, const CBlockIndex& blockindex)
{
    CBlock block;
    {
        LOCK(cs_main);
        CheckBlockDataAvailability(blockman, blockindex, /*check_for_undo=*/false);
    }

    if (!blockman.ReadBlock(block, blockindex)) {
        // Block not found on disk. This shouldn't normally happen unless the block was
        // pruned right after we released the lock above.
        throw JSONRPCError(RPC_MISC_ERROR, "Block not found on disk");
    }

    return block;
}

static std::vector<std::byte> GetRawBlockChecked(BlockManager& blockman, const CBlockIndex& blockindex)
{
    std::vector<std::byte> data{};
    FlatFilePos pos{};
    {
        LOCK(cs_main);
        CheckBlockDataAvailability(blockman, blockindex, /*check_for_undo=*/false);
        pos = blockindex.GetBlockPos();
    }

    if (!blockman.ReadRawBlock(data, pos)) {
        // Block not found on disk. This shouldn't normally happen unless the block was
        // pruned right after we released the lock above.
        throw JSONRPCError(RPC_MISC_ERROR, "Block not found on disk");
    }

    return data;
}

static CBlockUndo GetUndoChecked(BlockManager& blockman, const CBlockIndex& blockindex)
{
    CBlockUndo blockUndo;

    // The Genesis block does not have undo data
    if (blockindex.nHeight == 0) return blockUndo;

    {
        LOCK(cs_main);
        CheckBlockDataAvailability(blockman, blockindex, /*check_for_undo=*/true);
    }

    if (!blockman.ReadBlockUndo(blockUndo, blockindex)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Can't read undo data from disk");
    }

    return blockUndo;
}

const RPCResult getblock_vin{
    RPCResult::Type::ARR, "vin", "",
    {
        {RPCResult::Type::OBJ, "", "",
        {
            {RPCResult::Type::ELISION, "", "The same output as verbosity = 2"},
            {RPCResult::Type::OBJ, "prevout", "(Only if undo information is available)",
            {
                {RPCResult::Type::BOOL, "generated", "Coinbase or not"},
                {RPCResult::Type::NUM, "height", "The height of the prevout"},
                {RPCResult::Type::STR_AMOUNT, "value", "The value in " + CURRENCY_UNIT},
                {RPCResult::Type::OBJ, "scriptPubKey", "",
                {
                    {RPCResult::Type::STR, "asm", "Disassembly of the output script"},
                    {RPCResult::Type::STR, "desc", "Inferred descriptor for the output"},
                    {RPCResult::Type::STR_HEX, "hex", "The raw output script bytes, hex-encoded"},
                    {RPCResult::Type::STR, "address", /*optional=*/true, "The Bitcoin address (only if a well-defined address exists)"},
                    {RPCResult::Type::STR, "type", "The type (one of: " + GetAllOutputTypes() + ")"},
                }},
            }},
        }},
    }
};

static RPCHelpMan getblock()
{
    return RPCHelpMan{
        "getblock",
        "If verbosity is 0, returns a string that is serialized, hex-encoded data for block 'hash'.\n"
                "If verbosity is 1, returns an Object with information about block <hash>.\n"
                "If verbosity is 2, returns an Object with information about block <hash> and information about each transaction.\n"
                "If verbosity is 3, returns an Object with information about block <hash> and information about each transaction, including prevout information for inputs (only for unpruned blocks in the current best chain).\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The block hash"},
                    {"verbosity|verbose", RPCArg::Type::NUM, RPCArg::Default{1}, "0 for hex-encoded data, 1 for a JSON object, 2 for JSON object with transaction data, and 3 for JSON object with transaction data including prevout information for inputs",
                     RPCArgOptions{.skip_type_check = true}},
                },
                {
                    RPCResult{"for verbosity = 0",
                RPCResult::Type::STR_HEX, "", "A string that is serialized, hex-encoded data for block 'hash'"},
                    RPCResult{"for verbosity = 1",
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "hash", "the block hash (same as provided)"},
                    {RPCResult::Type::NUM, "confirmations", "The number of confirmations, or -1 if the block is not on the main chain"},
                    {RPCResult::Type::NUM, "size", "The block size"},
                    {RPCResult::Type::NUM, "strippedsize", "The block size excluding witness data"},
                    {RPCResult::Type::NUM, "weight", "The block weight as defined in BIP 141"},
                    {RPCResult::Type::NUM, "height", "The block height or index"},
                    {RPCResult::Type::NUM, "version", "The block version"},
                    {RPCResult::Type::STR_HEX, "versionHex", "The block version formatted in hexadecimal"},
                    {RPCResult::Type::STR_HEX, "merkleroot", "The merkle root"},
                    {RPCResult::Type::ARR, "tx", "The transaction ids",
                        {{RPCResult::Type::STR_HEX, "", "The transaction id"}}},
                    {RPCResult::Type::NUM_TIME, "time",       "The block time expressed in " + UNIX_EPOCH_TIME},
                    {RPCResult::Type::NUM_TIME, "mediantime", "The median block time expressed in " + UNIX_EPOCH_TIME},
                    {RPCResult::Type::NUM, "nonce", "The nonce"},
                    {RPCResult::Type::STR_HEX, "bits", "nBits: compact representation of the block difficulty target"},
                    {RPCResult::Type::STR_HEX, "target", "The difficulty target"},
                    {RPCResult::Type::NUM, "difficulty", "The difficulty"},
                    {RPCResult::Type::STR_HEX, "chainwork", "Expected number of hashes required to produce the chain up to this block (in hex)"},
                    {RPCResult::Type::NUM, "nTx", "The number of transactions in the block"},
                    {RPCResult::Type::STR_HEX, "previousblockhash", /*optional=*/true, "The hash of the previous block (if available)"},
                    {RPCResult::Type::STR_HEX, "nextblockhash", /*optional=*/true, "The hash of the next block (if available)"},
                }},
                    RPCResult{"for verbosity = 2",
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::ELISION, "", "Same output as verbosity = 1"},
                    {RPCResult::Type::ARR, "tx", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::ELISION, "", "The transactions in the format of the getrawtransaction RPC. Different from verbosity = 1 \"tx\" result"},
                            {RPCResult::Type::NUM, "fee", "The transaction fee in " + CURRENCY_UNIT + ", omitted if block undo data is not available"},
                        }},
                    }},
                }},
                    RPCResult{"for verbosity = 3",
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::ELISION, "", "Same output as verbosity = 2"},
                    {RPCResult::Type::ARR, "tx", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            getblock_vin,
                        }},
                    }},
                }},
        },
                RPCExamples{
                    HelpExampleCli("getblock", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
            + HelpExampleRpc("getblock", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    uint256 hash(ParseHashV(request.params[0], "blockhash"));

    int verbosity{ParseVerbosity(request.params[1], /*default_verbosity=*/1, /*allow_bool=*/true)};

    const CBlockIndex* pblockindex;
    const CBlockIndex* tip;
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    {
        LOCK(cs_main);
        pblockindex = chainman.m_blockman.LookupBlockIndex(hash);
        tip = chainman.ActiveChain().Tip();

        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
    }

    // Whether THIS block is stripped, not whether the node is hazed. A hazed node still holds some
    // blocks whole — genesis is written by WriteBlock even in hazed mode — and routing those through
    // the stripped reader looks for their payload in the gsb sequence while it sits in blk, so
    // `getblock` on genesis failed with "Stripped block not found on disk".
    const bool is_hazed = WITH_LOCK(::cs_main, return pblockindex->nStatus & BLOCK_HAZED_STRIPPED);

    if (is_hazed) {
        // Hazed mode: read stripped block from GSB files, reconstruct partial block
        haze::CStrippedBlock stripped;
        FlatFilePos pos;
        {
            LOCK(cs_main);
            CheckBlockDataAvailability(chainman.m_blockman, *pblockindex, /*check_for_undo=*/false);
            pos = pblockindex->GetBlockPos();
        }
        if (!chainman.m_blockman.ReadStrippedBlock(stripped, pos)) {
            throw JSONRPCError(RPC_MISC_ERROR, "Stripped block not found on disk");
        }

        if (verbosity <= 0) {
            // Return raw hex of the stripped block data (GSB format)
            std::vector<std::byte> gsb_data;
            haze::SerializeGSB(stripped, gsb_data);
            return HexStr(gsb_data);
        }

        // Extract original txids before reconstruction (stripped data preserves them)
        std::vector<uint256> original_txids;
        original_txids.reserve(stripped.GetTxCount());
        for (size_t i = 0; i < stripped.GetTxCount(); ++i) {
            original_txids.push_back(stripped.GetTxid(i));
        }

        CBlock block = haze::ReconstructPartialBlock(stripped);

        TxVerbosity tx_verbosity;
        if (verbosity == 1) {
            tx_verbosity = TxVerbosity::SHOW_TXID;
        } else if (verbosity == 2) {
            tx_verbosity = TxVerbosity::SHOW_DETAILS;
        } else {
            tx_verbosity = TxVerbosity::SHOW_DETAILS_AND_PREVOUT;
        }

        return blockToJSON(chainman.m_blockman, block, *tip, *pblockindex, tx_verbosity, chainman.GetConsensus().powLimit, /*is_hazed=*/true, &original_txids);
    }

    // Full archive mode: standard path
    const std::vector<std::byte> block_data{GetRawBlockChecked(chainman.m_blockman, *pblockindex)};

    if (verbosity <= 0) {
        return HexStr(block_data);
    }

    DataStream block_stream{block_data};
    CBlock block{};
    block_stream >> TX_WITH_WITNESS(block);

    TxVerbosity tx_verbosity;
    if (verbosity == 1) {
        tx_verbosity = TxVerbosity::SHOW_TXID;
    } else if (verbosity == 2) {
        tx_verbosity = TxVerbosity::SHOW_DETAILS;
    } else {
        tx_verbosity = TxVerbosity::SHOW_DETAILS_AND_PREVOUT;
    }

    return blockToJSON(chainman.m_blockman, block, *tip, *pblockindex, tx_verbosity, chainman.GetConsensus().powLimit);
},
    };
}

//! Return height of highest block that has been pruned, or std::nullopt if no blocks have been pruned
std::optional<int> GetPruneHeight(const BlockManager& blockman, const CChain& chain) {
    AssertLockHeld(::cs_main);

    // Search for the last block missing block data or undo data. Don't let the
    // search consider the genesis block, because the genesis block does not
    // have undo data, but should not be considered pruned.
    const CBlockIndex* first_block{chain[1]};
    const CBlockIndex* chain_tip{chain.Tip()};

    // If there are no blocks after the genesis block, or no blocks at all, nothing is pruned.
    if (!first_block || !chain_tip) return std::nullopt;

    // If the chain tip is pruned, everything is pruned.
    if (!((chain_tip->nStatus & BLOCK_HAVE_MASK) == BLOCK_HAVE_MASK)) return chain_tip->nHeight;

    const auto& first_unpruned{*CHECK_NONFATAL(blockman.GetFirstBlock(*chain_tip, /*status_mask=*/BLOCK_HAVE_MASK, first_block))};
    if (&first_unpruned == first_block) {
        // All blocks between first_block and chain_tip have data, so nothing is pruned.
        return std::nullopt;
    }

    // Block before the first unpruned block is the last pruned block.
    return CHECK_NONFATAL(first_unpruned.pprev)->nHeight;
}

static RPCHelpMan pruneblockchain()
{
    return RPCHelpMan{"pruneblockchain",
                "Attempts to delete block and undo data up to a specified height or timestamp, if eligible for pruning.\n"
                "Requires `-prune` to be enabled at startup. While pruned data may be re-fetched in some cases (e.g., via `getblockfrompeer`), local deletion is irreversible.\n",
                {
                    {"height", RPCArg::Type::NUM, RPCArg::Optional::NO, "The block height to prune up to. May be set to a discrete height, or to a " + UNIX_EPOCH_TIME + "\n"
            "                  to prune blocks whose block time is at least 2 hours older than the provided timestamp."},
                },
                RPCResult{
                    RPCResult::Type::NUM, "", "Height of the last block pruned"},
                RPCExamples{
                    HelpExampleCli("pruneblockchain", "1000")
            + HelpExampleRpc("pruneblockchain", "1000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    if (!chainman.m_blockman.IsPruneMode()) {
        throw JSONRPCError(RPC_MISC_ERROR, "Cannot prune blocks because node is not in prune mode.");
    }

    LOCK(cs_main);
    Chainstate& active_chainstate = chainman.ActiveChainstate();
    CChain& active_chain = active_chainstate.m_chain;

    int heightParam = request.params[0].getInt<int>();
    if (heightParam < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative block height.");
    }

    // Height value more than a billion is too high to be a block height, and
    // too low to be a block time (corresponds to timestamp from Sep 2001).
    if (heightParam > 1000000000) {
        // Add a 2 hour buffer to include blocks which might have had old timestamps
        const CBlockIndex* pindex = active_chain.FindEarliestAtLeast(heightParam - TIMESTAMP_WINDOW, 0);
        if (!pindex) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Could not find block with at least the specified timestamp.");
        }
        heightParam = pindex->nHeight;
    }

    unsigned int height = (unsigned int) heightParam;
    unsigned int chainHeight = (unsigned int) active_chain.Height();
    if (chainHeight < chainman.GetParams().PruneAfterHeight()) {
        throw JSONRPCError(RPC_MISC_ERROR, "Blockchain is too short for pruning.");
    } else if (height > chainHeight) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Blockchain is shorter than the attempted prune height.");
    } else if (height > chainHeight - MIN_BLOCKS_TO_KEEP) {
        LogDebug(BCLog::RPC, "Attempt to prune blocks close to the tip.  Retaining the minimum number of blocks.\n");
        height = chainHeight - MIN_BLOCKS_TO_KEEP;
    }

    PruneBlockFilesManual(active_chainstate, height);
    return GetPruneHeight(chainman.m_blockman, active_chain).value_or(-1);
},
    };
}

CoinStatsHashType ParseHashType(const std::string& hash_type_input)
{
    if (hash_type_input == "hash_serialized_3") {
        return CoinStatsHashType::HASH_SERIALIZED;
    } else if (hash_type_input == "muhash") {
        return CoinStatsHashType::MUHASH;
    } else if (hash_type_input == "none") {
        return CoinStatsHashType::NONE;
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("'%s' is not a valid hash_type", hash_type_input));
    }
}

/**
 * Calculate statistics about the unspent transaction output set
 *
 * @param[in] index_requested Signals if the coinstatsindex should be used (when available).
 */
static std::optional<kernel::CCoinsStats> GetUTXOStats(CCoinsView* view, node::BlockManager& blockman,
                                                       kernel::CoinStatsHashType hash_type,
                                                       const std::function<void()>& interruption_point = {},
                                                       const CBlockIndex* pindex = nullptr,
                                                       bool index_requested = true)
{
    // Use CoinStatsIndex if it is requested and available and a hash_type of Muhash or None was requested
    if ((hash_type == kernel::CoinStatsHashType::MUHASH || hash_type == kernel::CoinStatsHashType::NONE) && g_coin_stats_index && index_requested) {
        if (pindex) {
            return g_coin_stats_index->LookUpStats(*pindex);
        } else {
            CBlockIndex& block_index = *CHECK_NONFATAL(WITH_LOCK(::cs_main, return blockman.LookupBlockIndex(view->GetBestBlock())));
            return g_coin_stats_index->LookUpStats(block_index);
        }
    }

    // If the coinstats index isn't requested or is otherwise not usable, the
    // pindex should either be null or equal to the view's best block. This is
    // because without the coinstats index we can only get coinstats about the
    // best block.
    CHECK_NONFATAL(!pindex || pindex->GetBlockHash() == view->GetBestBlock());

    return kernel::ComputeUTXOStats(hash_type, view, blockman, interruption_point);
}

static RPCHelpMan gettxoutsetinfo()
{
    return RPCHelpMan{
        "gettxoutsetinfo",
        "Returns statistics about the unspent transaction output set.\n"
                "Note this call may take some time if you are not using coinstatsindex.\n",
                {
                    {"hash_type", RPCArg::Type::STR, RPCArg::Default{"hash_serialized_3"}, "Which UTXO set hash should be calculated. Options: 'hash_serialized_3' (the legacy algorithm), 'muhash', 'none'."},
                    {"hash_or_height", RPCArg::Type::NUM, RPCArg::DefaultHint{"the current best block"}, "The block hash or height of the target height (only available with coinstatsindex).",
                     RPCArgOptions{
                         .skip_type_check = true,
                         .type_str = {"", "string or numeric"},
                     }},
                    {"use_index", RPCArg::Type::BOOL, RPCArg::Default{true}, "Use coinstatsindex, if available."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "height", "The block height (index) of the returned statistics"},
                        {RPCResult::Type::STR_HEX, "bestblock", "The hash of the block at which these statistics are calculated"},
                        {RPCResult::Type::NUM, "txouts", "The number of unspent transaction outputs"},
                        {RPCResult::Type::NUM, "bogosize", "Database-independent, meaningless metric indicating the UTXO set size"},
                        {RPCResult::Type::STR_HEX, "hash_serialized_3", /*optional=*/true, "The serialized hash (only present if 'hash_serialized_3' hash_type is chosen)"},
                        {RPCResult::Type::STR_HEX, "muhash", /*optional=*/true, "The serialized hash (only present if 'muhash' hash_type is chosen)"},
                        {RPCResult::Type::NUM, "transactions", /*optional=*/true, "The number of transactions with unspent outputs (not available when coinstatsindex is used)"},
                        {RPCResult::Type::NUM, "disk_size", /*optional=*/true, "The estimated size of the chainstate on disk (not available when coinstatsindex is used)"},
                        {RPCResult::Type::STR_AMOUNT, "total_amount", "The total amount of coins in the UTXO set"},
                        {RPCResult::Type::STR_AMOUNT, "total_unspendable_amount", /*optional=*/true, "The total amount of coins permanently excluded from the UTXO set (only available if coinstatsindex is used)"},
                        {RPCResult::Type::OBJ, "block_info", /*optional=*/true, "Info on amounts in the block at this block height (only available if coinstatsindex is used)",
                        {
                            {RPCResult::Type::STR_AMOUNT, "prevout_spent", "Total amount of all prevouts spent in this block"},
                            {RPCResult::Type::STR_AMOUNT, "coinbase", "Coinbase subsidy amount of this block"},
                            {RPCResult::Type::STR_AMOUNT, "new_outputs_ex_coinbase", "Total amount of new outputs created by this block"},
                            {RPCResult::Type::STR_AMOUNT, "unspendable", "Total amount of unspendable outputs created in this block"},
                            {RPCResult::Type::OBJ, "unspendables", "Detailed view of the unspendable categories",
                            {
                                {RPCResult::Type::STR_AMOUNT, "genesis_block", "The unspendable amount of the Genesis block subsidy"},
                                {RPCResult::Type::STR_AMOUNT, "bip30", "Transactions overridden by duplicates (no longer possible with BIP30)"},
                                {RPCResult::Type::STR_AMOUNT, "scripts", "Amounts sent to scripts that are unspendable (for example OP_RETURN outputs)"},
                                {RPCResult::Type::STR_AMOUNT, "unclaimed_rewards", "Fee rewards that miners did not claim in their coinbase transaction"},
                            }}
                        }},
                    }},
                RPCExamples{
                    HelpExampleCli("gettxoutsetinfo", "") +
                    HelpExampleCli("gettxoutsetinfo", R"("none")") +
                    HelpExampleCli("gettxoutsetinfo", R"("none" 1000)") +
                    HelpExampleCli("gettxoutsetinfo", R"("none" '"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09"')") +
                    HelpExampleCli("-named gettxoutsetinfo", R"(hash_type='muhash' use_index='false')") +
                    HelpExampleRpc("gettxoutsetinfo", "") +
                    HelpExampleRpc("gettxoutsetinfo", R"("none")") +
                    HelpExampleRpc("gettxoutsetinfo", R"("none", 1000)") +
                    HelpExampleRpc("gettxoutsetinfo", R"("none", "00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09")")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue ret(UniValue::VOBJ);

    const CBlockIndex* pindex{nullptr};
    const CoinStatsHashType hash_type{request.params[0].isNull() ? CoinStatsHashType::HASH_SERIALIZED : ParseHashType(request.params[0].get_str())};
    bool index_requested = request.params[2].isNull() || request.params[2].get_bool();

    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    Chainstate& active_chainstate = chainman.ActiveChainstate();
    active_chainstate.ForceFlushStateToDisk();

    CCoinsView* coins_view;
    BlockManager* blockman;
    {
        LOCK(::cs_main);
        coins_view = &active_chainstate.CoinsDB();
        blockman = &active_chainstate.m_blockman;
        pindex = blockman->LookupBlockIndex(coins_view->GetBestBlock());
    }

    if (!request.params[1].isNull()) {
        if (!g_coin_stats_index) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Querying specific block heights requires coinstatsindex");
        }

        if (hash_type == CoinStatsHashType::HASH_SERIALIZED) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "hash_serialized_3 hash type cannot be queried for a specific block");
        }

        if (!index_requested) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot set use_index to false when querying for a specific block");
        }
        pindex = ParseHashOrHeight(request.params[1], chainman);
    }

    if (index_requested && g_coin_stats_index) {
        if (!g_coin_stats_index->BlockUntilSyncedToCurrentChain()) {
            const IndexSummary summary{g_coin_stats_index->GetSummary()};

            // If a specific block was requested and the index has already synced past that height, we can return the
            // data already even though the index is not fully synced yet.
            if (pindex->nHeight > summary.best_block_height) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Unable to get data because coinstatsindex is still syncing. Current height: %d", summary.best_block_height));
            }
        }
    }

    const std::optional<CCoinsStats> maybe_stats = GetUTXOStats(coins_view, *blockman, hash_type, node.rpc_interruption_point, pindex, index_requested);
    if (maybe_stats.has_value()) {
        const CCoinsStats& stats = maybe_stats.value();
        ret.pushKV("height", (int64_t)stats.nHeight);
        ret.pushKV("bestblock", stats.hashBlock.GetHex());
        ret.pushKV("txouts", (int64_t)stats.nTransactionOutputs);
        ret.pushKV("bogosize", (int64_t)stats.nBogoSize);
        if (hash_type == CoinStatsHashType::HASH_SERIALIZED) {
            ret.pushKV("hash_serialized_3", stats.hashSerialized.GetHex());
        }
        if (hash_type == CoinStatsHashType::MUHASH) {
            ret.pushKV("muhash", stats.hashSerialized.GetHex());
        }
        CHECK_NONFATAL(stats.total_amount.has_value());
        ret.pushKV("total_amount", ValueFromAmount(stats.total_amount.value()));
        if (!stats.index_used) {
            ret.pushKV("transactions", static_cast<int64_t>(stats.nTransactions));
            ret.pushKV("disk_size", stats.nDiskSize);
        } else {
            CCoinsStats prev_stats{};
            if (pindex->nHeight > 0) {
                const std::optional<CCoinsStats> maybe_prev_stats = GetUTXOStats(coins_view, *blockman, hash_type, node.rpc_interruption_point, pindex->pprev, index_requested);
                if (!maybe_prev_stats) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read UTXO set");
                }
                prev_stats = maybe_prev_stats.value();
            }

            CAmount block_total_unspendable_amount = stats.total_unspendables_genesis_block +
                                                     stats.total_unspendables_bip30 +
                                                     stats.total_unspendables_scripts +
                                                     stats.total_unspendables_unclaimed_rewards;
            CAmount prev_block_total_unspendable_amount = prev_stats.total_unspendables_genesis_block +
                                                          prev_stats.total_unspendables_bip30 +
                                                          prev_stats.total_unspendables_scripts +
                                                          prev_stats.total_unspendables_unclaimed_rewards;

            ret.pushKV("total_unspendable_amount", ValueFromAmount(block_total_unspendable_amount));

            UniValue block_info(UniValue::VOBJ);
            // These per-block values should fit uint64 under normal circumstances
            arith_uint256 diff_prevout = stats.total_prevout_spent_amount - prev_stats.total_prevout_spent_amount;
            arith_uint256 diff_coinbase = stats.total_coinbase_amount - prev_stats.total_coinbase_amount;
            arith_uint256 diff_outputs = stats.total_new_outputs_ex_coinbase_amount - prev_stats.total_new_outputs_ex_coinbase_amount;
            CAmount prevout_amount = static_cast<CAmount>(diff_prevout.GetLow64());
            CAmount coinbase_amount = static_cast<CAmount>(diff_coinbase.GetLow64());
            CAmount outputs_amount = static_cast<CAmount>(diff_outputs.GetLow64());
            block_info.pushKV("prevout_spent", ValueFromAmount(prevout_amount));
            block_info.pushKV("coinbase", ValueFromAmount(coinbase_amount));
            block_info.pushKV("new_outputs_ex_coinbase", ValueFromAmount(outputs_amount));
            block_info.pushKV("unspendable", ValueFromAmount(block_total_unspendable_amount - prev_block_total_unspendable_amount));

            UniValue unspendables(UniValue::VOBJ);
            unspendables.pushKV("genesis_block", ValueFromAmount(stats.total_unspendables_genesis_block - prev_stats.total_unspendables_genesis_block));
            unspendables.pushKV("bip30", ValueFromAmount(stats.total_unspendables_bip30 - prev_stats.total_unspendables_bip30));
            unspendables.pushKV("scripts", ValueFromAmount(stats.total_unspendables_scripts - prev_stats.total_unspendables_scripts));
            unspendables.pushKV("unclaimed_rewards", ValueFromAmount(stats.total_unspendables_unclaimed_rewards - prev_stats.total_unspendables_unclaimed_rewards));
            block_info.pushKV("unspendables", std::move(unspendables));

            ret.pushKV("block_info", std::move(block_info));
        }
    } else {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read UTXO set");
    }
    return ret;
},
    };
}

static RPCHelpMan gettxout()
{
    return RPCHelpMan{
        "gettxout",
        "Returns details about an unspent transaction output.\n",
        {
            {"txid", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction id"},
            {"n", RPCArg::Type::NUM, RPCArg::Optional::NO, "vout number"},
            {"include_mempool", RPCArg::Type::BOOL, RPCArg::Default{true}, "Whether to include the mempool. Note that an unspent output that is spent in the mempool won't appear."},
        },
        {
            RPCResult{"If the UTXO was not found", RPCResult::Type::NONE, "", ""},
            RPCResult{"Otherwise", RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR_HEX, "bestblock", "The hash of the block at the tip of the chain"},
                {RPCResult::Type::NUM, "confirmations", "The number of confirmations"},
                {RPCResult::Type::STR_AMOUNT, "value", "The transaction value in " + CURRENCY_UNIT},
                {RPCResult::Type::OBJ, "scriptPubKey", "", {
                    {RPCResult::Type::STR, "asm", "Disassembly of the output script"},
                    {RPCResult::Type::STR, "desc", "Inferred descriptor for the output"},
                    {RPCResult::Type::STR_HEX, "hex", "The raw output script bytes, hex-encoded"},
                    {RPCResult::Type::STR, "type", "The type, eg pubkeyhash"},
                    {RPCResult::Type::STR, "address", /*optional=*/true, "The Bitcoin address (only if a well-defined address exists)"},
                }},
                {RPCResult::Type::BOOL, "coinbase", "Coinbase or not"},
            }},
        },
        RPCExamples{
            "\nGet unspent transactions\n"
            + HelpExampleCli("listunspent", "") +
            "\nView the details\n"
            + HelpExampleCli("gettxout", "\"txid\" 1") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("gettxout", "\"txid\", 1")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    LOCK(cs_main);

    UniValue ret(UniValue::VOBJ);

    auto hash{Txid::FromUint256(ParseHashV(request.params[0], "txid"))};
    COutPoint out{hash, request.params[1].getInt<uint32_t>()};
    bool fMempool = true;
    if (!request.params[2].isNull())
        fMempool = request.params[2].get_bool();

    Chainstate& active_chainstate = chainman.ActiveChainstate();
    CCoinsViewCache* coins_view = &active_chainstate.CoinsTip();

    std::optional<Coin> coin;
    if (fMempool) {
        const CTxMemPool& mempool = EnsureMemPool(node);
        LOCK(mempool.cs);
        CCoinsViewMemPool view(coins_view, mempool);
        if (!mempool.isSpent(out)) coin = view.GetCoin(out);
    } else {
        coin = coins_view->GetCoin(out);
    }
    if (!coin) return UniValue::VNULL;

    const CBlockIndex* pindex = active_chainstate.m_blockman.LookupBlockIndex(coins_view->GetBestBlock());
    ret.pushKV("bestblock", pindex->GetBlockHash().GetHex());
    if (coin->nHeight == MEMPOOL_HEIGHT) {
        ret.pushKV("confirmations", 0);
    } else {
        ret.pushKV("confirmations", (int64_t)(pindex->nHeight - coin->nHeight + 1));
    }
    ret.pushKV("value", ValueFromAmount(coin->out.nValue));
    UniValue o(UniValue::VOBJ);
    ScriptToUniv(coin->out.scriptPubKey, /*out=*/o, /*include_hex=*/true, /*include_address=*/true);
    ret.pushKV("scriptPubKey", std::move(o));
    ret.pushKV("coinbase", (bool)coin->fCoinBase);

    return ret;
},
    };
}

static RPCHelpMan verifychain()
{
    return RPCHelpMan{
        "verifychain",
        "Verifies blockchain database.\n",
                {
                    {"checklevel", RPCArg::Type::NUM, RPCArg::DefaultHint{strprintf("%d, range=0-4", DEFAULT_CHECKLEVEL)},
                        strprintf("How thorough the block verification is:\n%s", MakeUnorderedList(CHECKLEVEL_DOC))},
                    {"nblocks", RPCArg::Type::NUM, RPCArg::DefaultHint{strprintf("%d, 0=all", DEFAULT_CHECKBLOCKS)}, "The number of blocks to check."},
                },
                RPCResult{
                    RPCResult::Type::BOOL, "", "Verification finished successfully. If false, check debug.log for reason."},
                RPCExamples{
                    HelpExampleCli("verifychain", "")
            + HelpExampleRpc("verifychain", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const int check_level{request.params[0].isNull() ? DEFAULT_CHECKLEVEL : request.params[0].getInt<int>()};
    const int check_depth{request.params[1].isNull() ? DEFAULT_CHECKBLOCKS : request.params[1].getInt<int>()};

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);

    Chainstate& active_chainstate = chainman.ActiveChainstate();
    return CVerifyDB(chainman.GetNotifications()).VerifyDB(
               active_chainstate, chainman.GetParams().GetConsensus(), active_chainstate.CoinsTip(), check_level, check_depth) == VerifyDBResult::SUCCESS;
},
    };
}

static void SoftForkDescPushBack(const CBlockIndex* blockindex, UniValue& softforks, const ChainstateManager& chainman, Consensus::BuriedDeployment dep)
{
    // For buried deployments.

    if (!DeploymentEnabled(chainman, dep)) return;

    UniValue rv(UniValue::VOBJ);
    rv.pushKV("type", "buried");
    // getdeploymentinfo reports the softfork as active from when the chain height is
    // one below the activation height
    rv.pushKV("active", DeploymentActiveAfter(blockindex, chainman, dep));
    rv.pushKV("height", chainman.GetConsensus().DeploymentHeight(dep));
    softforks.pushKV(DeploymentName(dep), std::move(rv));
}

static void SoftForkDescPushBack(const CBlockIndex* blockindex, UniValue& softforks, const ChainstateManager& chainman, Consensus::DeploymentPos id)
{
    // For BIP9 deployments.
    if (!DeploymentEnabled(chainman, id)) return;
    if (blockindex == nullptr) return;

    UniValue bip9(UniValue::VOBJ);
    BIP9Info info{chainman.m_versionbitscache.Info(*blockindex, chainman.GetConsensus(), id)};
    const auto& depparams{chainman.GetConsensus().vDeployments[id]};

    // BIP9 parameters
    if (info.stats.has_value()) {
        bip9.pushKV("bit", depparams.bit);
    }
    bip9.pushKV("start_time", depparams.nStartTime);
    bip9.pushKV("timeout", depparams.nTimeout);
    bip9.pushKV("min_activation_height", depparams.min_activation_height);

    // BIP9 status
    bip9.pushKV("status", info.current_state);
    bip9.pushKV("since", info.since);
    bip9.pushKV("status_next", info.next_state);

    // BIP9 signalling status, if applicable
    if (info.stats.has_value()) {
        UniValue statsUV(UniValue::VOBJ);
        statsUV.pushKV("period", info.stats->period);
        statsUV.pushKV("elapsed", info.stats->elapsed);
        statsUV.pushKV("count", info.stats->count);
        if (info.stats->threshold > 0 || info.stats->possible) {
            statsUV.pushKV("threshold", info.stats->threshold);
            statsUV.pushKV("possible", info.stats->possible);
        }
        bip9.pushKV("statistics", std::move(statsUV));

        std::string sig;
        sig.reserve(info.signalling_blocks.size());
        for (const bool s : info.signalling_blocks) {
            sig.push_back(s ? '#' : '-');
        }
        bip9.pushKV("signalling", sig);
    }

    UniValue rv(UniValue::VOBJ);
    rv.pushKV("type", "bip9");
    bool is_active = false;
    if (info.active_since.has_value()) {
        rv.pushKV("height", *info.active_since);
        is_active = (*info.active_since <= blockindex->nHeight + 1);
    }
    rv.pushKV("active", is_active);
    rv.pushKV("bip9", bip9);
    softforks.pushKV(DeploymentName(id), std::move(rv));
}

// used by rest.cpp:rest_chaininfo, so cannot be static
RPCHelpMan getblockchaininfo()
{
    return RPCHelpMan{"getblockchaininfo",
        "Returns an object containing various state info regarding blockchain processing.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "chain", "current network name (" LIST_CHAIN_NAMES ")"},
                {RPCResult::Type::NUM, "blocks", "the height of the most-work fully-validated chain. The genesis block has height 0"},
                {RPCResult::Type::NUM, "headers", "the current number of headers we have validated"},
                {RPCResult::Type::STR, "bestblockhash", "the hash of the currently best block"},
                {RPCResult::Type::STR_HEX, "bits", "nBits: compact representation of the block difficulty target"},
                {RPCResult::Type::STR_HEX, "target", "The difficulty target"},
                {RPCResult::Type::NUM, "difficulty", "the current difficulty"},
                {RPCResult::Type::NUM_TIME, "time", "The block time expressed in " + UNIX_EPOCH_TIME},
                {RPCResult::Type::NUM_TIME, "mediantime", "The median block time expressed in " + UNIX_EPOCH_TIME},
                {RPCResult::Type::NUM, "verificationprogress", "estimate of verification progress [0..1]"},
                {RPCResult::Type::BOOL, "initialblockdownload", "(debug information) estimate of whether this node is in Initial Block Download mode"},
                {RPCResult::Type::STR_HEX, "chainwork", "total amount of work in active chain, in hexadecimal"},
                {RPCResult::Type::NUM, "size_on_disk", "the estimated size of the block and undo files on disk"},
                {RPCResult::Type::BOOL, "pruned", "if the blocks are subject to pruning"},
                {RPCResult::Type::BOOL, "hazed", "true if this node is running in Ghost Haze mode (stripped blocks)"},
                {RPCResult::Type::NUM, "pruneheight", /*optional=*/true, "height of the last block pruned, plus one (only present if pruning is enabled)"},
                {RPCResult::Type::BOOL, "automatic_pruning", /*optional=*/true, "whether automatic pruning is enabled (only present if pruning is enabled)"},
                {RPCResult::Type::NUM, "prune_target_size", /*optional=*/true, "the target size used by pruning (only present if automatic pruning is enabled)"},
                {RPCResult::Type::STR_HEX, "signet_challenge", /*optional=*/true, "the block challenge (aka. block script), in hexadecimal (only present if the current network is a signet)"},
                {RPCResult::Type::OBJ, "hazync", /*optional=*/true, "Hazync proof this node verified at startup (only present if -hazyncproof was accepted)",
                {
                    {RPCResult::Type::NUM, "provenheight", "height through which the proof attests validity, anchored at genesis"},
                    {RPCResult::Type::STR_HEX, "proventip", "block hash the proof commits to at that height"},
                    {RPCResult::Type::STR_HEX, "guestid", "Hazync guest image id the proof was verified against"},
                    {RPCResult::Type::NUM, "utxoleaves", "number of leaves in the UTXO accumulator the proof commits to"},
                    {RPCResult::Type::BOOL, "utxodumpmatched", "whether a -hazyncutxo dump was supplied and matched the proven accumulator roots"},
                    {RPCResult::Type::BOOL, "adoptionarmed", "whether -hazyncadopt authorised adoption. Armed is not adopted: see actedon"},
                    {RPCResult::Type::BOOL, "actedon", "whether this node's active chainstate stands on the proof, i.e. the proven UTXO set was adopted and blocks below it were never validated here"},
                }},
                (IsDeprecatedRPCEnabled("warnings") ?
                    RPCResult{RPCResult::Type::STR, "warnings", "any network and blockchain warnings (DEPRECATED)"} :
                    RPCResult{RPCResult::Type::ARR, "warnings", "any network and blockchain warnings (run with `-deprecatedrpc=warnings` to return the latest warning as a single string)",
                    {
                        {RPCResult::Type::STR, "", "warning"},
                    }
                    }
                ),
            }},
        RPCExamples{
            HelpExampleCli("getblockchaininfo", "")
            + HelpExampleRpc("getblockchaininfo", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    Chainstate& active_chainstate = chainman.ActiveChainstate();

    const CBlockIndex& tip{*CHECK_NONFATAL(active_chainstate.m_chain.Tip())};
    const int height{tip.nHeight};
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("chain", chainman.GetParams().GetChainTypeString());
    obj.pushKV("blocks", height);
    obj.pushKV("headers", chainman.m_best_header ? chainman.m_best_header->nHeight : -1);
    obj.pushKV("bestblockhash", tip.GetBlockHash().GetHex());
    obj.pushKV("bits", strprintf("%08x", tip.nBits));
    obj.pushKV("target", GetTarget(tip, chainman.GetConsensus().powLimit).GetHex());
    obj.pushKV("difficulty", GetDifficulty(tip));
    obj.pushKV("time", tip.GetBlockTime());
    obj.pushKV("mediantime", tip.GetMedianTimePast());
    obj.pushKV("verificationprogress", chainman.GuessVerificationProgress(&tip));
    obj.pushKV("initialblockdownload", chainman.IsInitialBlockDownload());
    obj.pushKV("chainwork", tip.nChainWork.GetHex());
    obj.pushKV("size_on_disk", chainman.m_blockman.CalculateCurrentUsage());
    obj.pushKV("pruned", chainman.m_blockman.IsPruneMode());
    // An operator must be able to ask a RUNNING node whether it is relying on a proof. A startup log
    // line is not an answer once it has scrolled away. `actedon` is reported explicitly rather than
    // implied, so the field does not silently change meaning when adoption lands.
    if (const auto& hazync_proof{haze::HazyncVerifiedProof()}) {
        UniValue hz(UniValue::VOBJ);
        hz.pushKV("provenheight", (uint64_t)hazync_proof->height);
        hz.pushKV("proventip", hazync_proof->tip_hash.GetHex());
        hz.pushKV("guestid", haze::HazyncMethodId());
        hz.pushKV("utxoleaves", hazync_proof->utxo_leaves);
        hz.pushKV("utxodumpmatched", haze::HazyncUtxoDumpMatched());
        hz.pushKV("adoptionarmed", haze::HazyncAdoptedSnapshot().has_value());
        // `actedon` is the question that matters: is this node's chainstate standing on the proof?
        // True only when a snapshot is active AND it is the one this proof authorises — an armed
        // node that has not yet adopted, or one whose active snapshot came from somewhere else,
        // must not read as though the proof is holding anything up.
        const auto& adoption{haze::HazyncAdoptedSnapshot()};
        const auto snapshot_base{chainman.SnapshotBlockhash()};
        hz.pushKV("actedon", adoption && snapshot_base && adoption->base_blockhash == *snapshot_base);
        obj.pushKV("hazync", std::move(hz));
    }
    if (chainman.m_blockman.IsPruneMode()) {
        const auto prune_height{GetPruneHeight(chainman.m_blockman, active_chainstate.m_chain)};
        obj.pushKV("pruneheight", prune_height ? prune_height.value() + 1 : 0);

        const bool automatic_pruning{chainman.m_blockman.GetPruneTarget() != BlockManager::PRUNE_TARGET_MANUAL};
        obj.pushKV("automatic_pruning",  automatic_pruning);
        if (automatic_pruning) {
            obj.pushKV("prune_target_size", chainman.m_blockman.GetPruneTarget());
        }
    }
    obj.pushKV("hazed", chainman.m_blockman.IsHazeMode());
    if (chainman.GetParams().GetChainType() == ChainType::SIGNET) {
        const std::vector<uint8_t>& signet_challenge =
            chainman.GetParams().GetConsensus().signet_challenge;
        obj.pushKV("signet_challenge", HexStr(signet_challenge));
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    obj.pushKV("warnings", node::GetWarningsForRpc(*CHECK_NONFATAL(node.warnings), IsDeprecatedRPCEnabled("warnings")));
    return obj;
},
    };
}

namespace {
const std::vector<RPCResult> RPCHelpForDeployment{
    {RPCResult::Type::STR, "type", "one of \"buried\", \"bip9\""},
    {RPCResult::Type::NUM, "height", /*optional=*/true, "height of the first block which the rules are or will be enforced (only for \"buried\" type, or \"bip9\" type with \"active\" status)"},
    {RPCResult::Type::BOOL, "active", "true if the rules are enforced for the mempool and the next block"},
    {RPCResult::Type::OBJ, "bip9", /*optional=*/true, "status of bip9 softforks (only for \"bip9\" type)",
    {
        {RPCResult::Type::NUM, "bit", /*optional=*/true, "the bit (0-28) in the block version field used to signal this softfork (only for \"started\" and \"locked_in\" status)"},
        {RPCResult::Type::NUM_TIME, "start_time", "the minimum median time past of a block at which the bit gains its meaning"},
        {RPCResult::Type::NUM_TIME, "timeout", "the median time past of a block at which the deployment is considered failed if not yet locked in"},
        {RPCResult::Type::NUM, "min_activation_height", "minimum height of blocks for which the rules may be enforced"},
        {RPCResult::Type::STR, "status", "status of deployment at specified block (one of \"defined\", \"started\", \"locked_in\", \"active\", \"failed\")"},
        {RPCResult::Type::NUM, "since", "height of the first block to which the status applies"},
        {RPCResult::Type::STR, "status_next", "status of deployment at the next block"},
        {RPCResult::Type::OBJ, "statistics", /*optional=*/true, "numeric statistics about signalling for a softfork (only for \"started\" and \"locked_in\" status)",
        {
            {RPCResult::Type::NUM, "period", "the length in blocks of the signalling period"},
            {RPCResult::Type::NUM, "threshold", /*optional=*/true, "the number of blocks with the version bit set required to activate the feature (only for \"started\" status)"},
            {RPCResult::Type::NUM, "elapsed", "the number of blocks elapsed since the beginning of the current period"},
            {RPCResult::Type::NUM, "count", "the number of blocks with the version bit set in the current period"},
            {RPCResult::Type::BOOL, "possible", /*optional=*/true, "returns false if there are not enough blocks left in this period to pass activation threshold (only for \"started\" status)"},
        }},
        {RPCResult::Type::STR, "signalling", /*optional=*/true, "indicates blocks that signalled with a # and blocks that did not with a -"},
    }},
};

UniValue DeploymentInfo(const CBlockIndex* blockindex, const ChainstateManager& chainman)
{
    UniValue softforks(UniValue::VOBJ);
    SoftForkDescPushBack(blockindex, softforks, chainman, Consensus::DEPLOYMENT_HEIGHTINCB);
    SoftForkDescPushBack(blockindex, softforks, chainman, Consensus::DEPLOYMENT_DERSIG);
    SoftForkDescPushBack(blockindex, softforks, chainman, Consensus::DEPLOYMENT_CLTV);
    SoftForkDescPushBack(blockindex, softforks, chainman, Consensus::DEPLOYMENT_CSV);
    SoftForkDescPushBack(blockindex, softforks, chainman, Consensus::DEPLOYMENT_SEGWIT);
    SoftForkDescPushBack(blockindex, softforks, chainman, Consensus::DEPLOYMENT_TESTDUMMY);
    SoftForkDescPushBack(blockindex, softforks, chainman, Consensus::DEPLOYMENT_TAPROOT);
    return softforks;
}
} // anon namespace

RPCHelpMan getdeploymentinfo()
{
    return RPCHelpMan{"getdeploymentinfo",
        "Returns an object containing various state info regarding deployments of consensus changes.",
        {
            {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Default{"hash of current chain tip"}, "The block hash at which to query deployment state"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR, "hash", "requested block hash (or tip)"},
                {RPCResult::Type::NUM, "height", "requested block height (or tip)"},
                {RPCResult::Type::OBJ_DYN, "deployments", "", {
                    {RPCResult::Type::OBJ, "xxxx", "name of the deployment", RPCHelpForDeployment}
                }},
            }
        },
        RPCExamples{ HelpExampleCli("getdeploymentinfo", "") + HelpExampleRpc("getdeploymentinfo", "") },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const ChainstateManager& chainman = EnsureAnyChainman(request.context);
            LOCK(cs_main);
            const Chainstate& active_chainstate = chainman.ActiveChainstate();

            const CBlockIndex* blockindex;
            if (request.params[0].isNull()) {
                blockindex = CHECK_NONFATAL(active_chainstate.m_chain.Tip());
            } else {
                const uint256 hash(ParseHashV(request.params[0], "blockhash"));
                blockindex = chainman.m_blockman.LookupBlockIndex(hash);
                if (!blockindex) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
                }
            }

            UniValue deploymentinfo(UniValue::VOBJ);
            deploymentinfo.pushKV("hash", blockindex->GetBlockHash().ToString());
            deploymentinfo.pushKV("height", blockindex->nHeight);
            deploymentinfo.pushKV("deployments", DeploymentInfo(blockindex, chainman));
            return deploymentinfo;
        },
    };
}

/** Comparison function for sorting the getchaintips heads.  */
struct CompareBlocksByHeight
{
    bool operator()(const CBlockIndex* a, const CBlockIndex* b) const
    {
        /* Make sure that unequal blocks with the same height do not compare
           equal. Use the pointers themselves to make a distinction. */

        if (a->nHeight != b->nHeight)
          return (a->nHeight > b->nHeight);

        return a < b;
    }
};

static RPCHelpMan getchaintips()
{
    return RPCHelpMan{"getchaintips",
                "Return information about all known tips in the block tree,"
                " including the main chain as well as orphaned branches.\n",
                {},
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {{RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::NUM, "height", "height of the chain tip"},
                            {RPCResult::Type::STR_HEX, "hash", "block hash of the tip"},
                            {RPCResult::Type::NUM, "branchlen", "zero for main chain, otherwise length of branch connecting the tip to the main chain"},
                            {RPCResult::Type::STR, "status", "status of the chain, \"active\" for the main chain\n"
            "Possible values for status:\n"
            "1.  \"invalid\"               This branch contains at least one invalid block\n"
            "2.  \"headers-only\"          Not all blocks for this branch are available, but the headers are valid\n"
            "3.  \"valid-headers\"         All blocks are available for this branch, but they were never fully validated\n"
            "4.  \"valid-fork\"            This branch is not part of the active chain, but is fully validated\n"
            "5.  \"active\"                This is the tip of the active main chain, which is certainly valid"},
                        }}}},
                RPCExamples{
                    HelpExampleCli("getchaintips", "")
            + HelpExampleRpc("getchaintips", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    CChain& active_chain = chainman.ActiveChain();

    /*
     * Idea: The set of chain tips is the active chain tip, plus orphan blocks which do not have another orphan building off of them.
     * Algorithm:
     *  - Make one pass through BlockIndex(), picking out the orphan blocks, and also storing a set of the orphan block's pprev pointers.
     *  - Iterate through the orphan blocks. If the block isn't pointed to by another orphan, it is a chain tip.
     *  - Add the active chain tip
     */
    std::set<const CBlockIndex*, CompareBlocksByHeight> setTips;
    std::set<const CBlockIndex*> setOrphans;
    std::set<const CBlockIndex*> setPrevs;

    for (const auto& [_, block_index] : chainman.BlockIndex()) {
        if (!active_chain.Contains(&block_index)) {
            setOrphans.insert(&block_index);
            setPrevs.insert(block_index.pprev);
        }
    }

    for (std::set<const CBlockIndex*>::iterator it = setOrphans.begin(); it != setOrphans.end(); ++it) {
        if (setPrevs.erase(*it) == 0) {
            setTips.insert(*it);
        }
    }

    // Always report the currently active tip.
    setTips.insert(active_chain.Tip());

    /* Construct the output array.  */
    UniValue res(UniValue::VARR);
    for (const CBlockIndex* block : setTips) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("height", block->nHeight);
        obj.pushKV("hash", block->phashBlock->GetHex());

        const int branchLen = block->nHeight - active_chain.FindFork(block)->nHeight;
        obj.pushKV("branchlen", branchLen);

        std::string status;
        if (active_chain.Contains(block)) {
            // This block is part of the currently active chain.
            status = "active";
        } else if (block->nStatus & BLOCK_FAILED_MASK) {
            // This block or one of its ancestors is invalid.
            status = "invalid";
        } else if (!block->HaveNumChainTxs()) {
            // This block cannot be connected because full block data for it or one of its parents is missing.
            status = "headers-only";
        } else if (block->IsValid(BLOCK_VALID_SCRIPTS)) {
            // This block is fully validated, but no longer part of the active chain. It was probably the active block once, but was reorganized.
            status = "valid-fork";
        } else if (block->IsValid(BLOCK_VALID_TREE)) {
            // The headers for this block are valid, but it has not been validated. It was probably never part of the most-work chain.
            status = "valid-headers";
        } else {
            // No clue.
            status = "unknown";
        }
        obj.pushKV("status", status);

        res.push_back(std::move(obj));
    }

    return res;
},
    };
}

static RPCHelpMan preciousblock()
{
    return RPCHelpMan{
        "preciousblock",
        "Treats a block as if it were received before others with the same work.\n"
                "\nA later preciousblock call can override the effect of an earlier one.\n"
                "\nThe effects of preciousblock are not retained across restarts.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hash of the block to mark as precious"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("preciousblock", "\"blockhash\"")
            + HelpExampleRpc("preciousblock", "\"blockhash\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    uint256 hash(ParseHashV(request.params[0], "blockhash"));
    CBlockIndex* pblockindex;

    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    {
        LOCK(cs_main);
        pblockindex = chainman.m_blockman.LookupBlockIndex(hash);
        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
    }

    BlockValidationState state;
    chainman.ActiveChainstate().PreciousBlock(state, pblockindex);

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.ToString());
    }

    return UniValue::VNULL;
},
    };
}

void InvalidateBlock(ChainstateManager& chainman, const uint256 block_hash) {
    BlockValidationState state;
    CBlockIndex* pblockindex;
    {
        LOCK(chainman.GetMutex());
        pblockindex = chainman.m_blockman.LookupBlockIndex(block_hash);
        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
    }
    chainman.ActiveChainstate().InvalidateBlock(state, pblockindex);

    if (state.IsValid()) {
        chainman.ActiveChainstate().ActivateBestChain(state);
    }

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.ToString());
    }
}

static RPCHelpMan invalidateblock()
{
    return RPCHelpMan{
        "invalidateblock",
        "Permanently marks a block as invalid, as if it violated a consensus rule.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hash of the block to mark as invalid"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("invalidateblock", "\"blockhash\"")
            + HelpExampleRpc("invalidateblock", "\"blockhash\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    uint256 hash(ParseHashV(request.params[0], "blockhash"));

    InvalidateBlock(chainman, hash);

    return UniValue::VNULL;
},
    };
}

void ReconsiderBlock(ChainstateManager& chainman, uint256 block_hash) {
    {
        LOCK(chainman.GetMutex());
        CBlockIndex* pblockindex = chainman.m_blockman.LookupBlockIndex(block_hash);
        if (!pblockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }

        chainman.ActiveChainstate().ResetBlockFailureFlags(pblockindex);
        chainman.RecalculateBestHeader();
    }

    BlockValidationState state;
    chainman.ActiveChainstate().ActivateBestChain(state);

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.ToString());
    }
}

static RPCHelpMan reconsiderblock()
{
    return RPCHelpMan{
        "reconsiderblock",
        "Removes invalidity status of a block, its ancestors and its descendants, reconsider them for activation.\n"
                "This can be used to undo the effects of invalidateblock.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hash of the block to reconsider"},
                },
                RPCResult{RPCResult::Type::NONE, "", ""},
                RPCExamples{
                    HelpExampleCli("reconsiderblock", "\"blockhash\"")
            + HelpExampleRpc("reconsiderblock", "\"blockhash\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    uint256 hash(ParseHashV(request.params[0], "blockhash"));

    ReconsiderBlock(chainman, hash);

    return UniValue::VNULL;
},
    };
}

static RPCHelpMan getchaintxstats()
{
    return RPCHelpMan{
        "getchaintxstats",
        "Compute statistics about the total number and rate of transactions in the chain.\n",
                {
                    {"nblocks", RPCArg::Type::NUM, RPCArg::DefaultHint{"one month"}, "Size of the window in number of blocks"},
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::DefaultHint{"chain tip"}, "The hash of the block that ends the window."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM_TIME, "time", "The timestamp for the final block in the window, expressed in " + UNIX_EPOCH_TIME},
                        {RPCResult::Type::NUM, "txcount", /*optional=*/true,
                         "The total number of transactions in the chain up to that point, if known. "
                         "It may be unknown when using assumeutxo."},
                        {RPCResult::Type::STR_HEX, "window_final_block_hash", "The hash of the final block in the window"},
                        {RPCResult::Type::NUM, "window_final_block_height", "The height of the final block in the window."},
                        {RPCResult::Type::NUM, "window_block_count", "Size of the window in number of blocks"},
                        {RPCResult::Type::NUM, "window_interval", /*optional=*/true, "The elapsed time in the window in seconds. Only returned if \"window_block_count\" is > 0"},
                        {RPCResult::Type::NUM, "window_tx_count", /*optional=*/true,
                         "The number of transactions in the window. "
                         "Only returned if \"window_block_count\" is > 0 and if txcount exists for the start and end of the window."},
                        {RPCResult::Type::NUM, "txrate", /*optional=*/true,
                         "The average rate of transactions per second in the window. "
                         "Only returned if \"window_interval\" is > 0 and if window_tx_count exists."},
                    }},
                RPCExamples{
                    HelpExampleCli("getchaintxstats", "")
            + HelpExampleRpc("getchaintxstats", "2016")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    const CBlockIndex* pindex;
    int blockcount = 30 * 24 * 60 * 60 / chainman.GetParams().GetConsensus().nPowTargetSpacing; // By default: 1 month

    if (request.params[1].isNull()) {
        LOCK(cs_main);
        pindex = chainman.ActiveChain().Tip();
    } else {
        uint256 hash(ParseHashV(request.params[1], "blockhash"));
        LOCK(cs_main);
        pindex = chainman.m_blockman.LookupBlockIndex(hash);
        if (!pindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
        if (!chainman.ActiveChain().Contains(pindex)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Block is not in main chain");
        }
    }

    CHECK_NONFATAL(pindex != nullptr);

    if (request.params[0].isNull()) {
        blockcount = std::max(0, std::min(blockcount, pindex->nHeight - 1));
    } else {
        blockcount = request.params[0].getInt<int>();

        if (blockcount < 0 || (blockcount > 0 && blockcount >= pindex->nHeight)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block count: should be between 0 and the block's height - 1");
        }
    }

    const CBlockIndex& past_block{*CHECK_NONFATAL(pindex->GetAncestor(pindex->nHeight - blockcount))};
    const int64_t nTimeDiff{pindex->GetMedianTimePast() - past_block.GetMedianTimePast()};

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("time", (int64_t)pindex->nTime);
    if (pindex->m_chain_tx_count) {
        ret.pushKV("txcount", pindex->m_chain_tx_count);
    }
    ret.pushKV("window_final_block_hash", pindex->GetBlockHash().GetHex());
    ret.pushKV("window_final_block_height", pindex->nHeight);
    ret.pushKV("window_block_count", blockcount);
    if (blockcount > 0) {
        ret.pushKV("window_interval", nTimeDiff);
        if (pindex->m_chain_tx_count != 0 && past_block.m_chain_tx_count != 0) {
            const auto window_tx_count = pindex->m_chain_tx_count - past_block.m_chain_tx_count;
            ret.pushKV("window_tx_count", window_tx_count);
            if (nTimeDiff > 0) {
                ret.pushKV("txrate", double(window_tx_count) / nTimeDiff);
            }
        }
    }

    return ret;
},
    };
}

template<typename T>
static T CalculateTruncatedMedian(std::vector<T>& scores)
{
    size_t size = scores.size();
    if (size == 0) {
        return 0;
    }

    std::sort(scores.begin(), scores.end());
    if (size % 2 == 0) {
        return (scores[size / 2 - 1] + scores[size / 2]) / 2;
    } else {
        return scores[size / 2];
    }
}

void CalculatePercentilesByWeight(CAmount result[NUM_GETBLOCKSTATS_PERCENTILES], std::vector<std::pair<CAmount, int64_t>>& scores, int64_t total_weight)
{
    if (scores.empty()) {
        return;
    }

    std::sort(scores.begin(), scores.end());

    // 10th, 25th, 50th, 75th, and 90th percentile weight units.
    const double weights[NUM_GETBLOCKSTATS_PERCENTILES] = {
        total_weight / 10.0, total_weight / 4.0, total_weight / 2.0, (total_weight * 3.0) / 4.0, (total_weight * 9.0) / 10.0
    };

    int64_t next_percentile_index = 0;
    int64_t cumulative_weight = 0;
    for (const auto& element : scores) {
        cumulative_weight += element.second;
        while (next_percentile_index < NUM_GETBLOCKSTATS_PERCENTILES && cumulative_weight >= weights[next_percentile_index]) {
            result[next_percentile_index] = element.first;
            ++next_percentile_index;
        }
    }

    // Fill any remaining percentiles with the last value.
    for (int64_t i = next_percentile_index; i < NUM_GETBLOCKSTATS_PERCENTILES; i++) {
        result[i] = scores.back().first;
    }
}

template<typename T>
static inline bool SetHasKeys(const std::set<T>& set) {return false;}
template<typename T, typename Tk, typename... Args>
static inline bool SetHasKeys(const std::set<T>& set, const Tk& key, const Args&... args)
{
    return (set.count(key) != 0) || SetHasKeys(set, args...);
}

// outpoint (needed for the utxo index) + nHeight + fCoinBase
static constexpr size_t PER_UTXO_OVERHEAD = sizeof(COutPoint) + sizeof(uint32_t) + sizeof(bool);

static RPCHelpMan getblockstats()
{
    return RPCHelpMan{
        "getblockstats",
        "Compute per block statistics for a given window. All amounts are in satoshis.\n"
                "It won't work for some heights with pruning.\n",
                {
                    {"hash_or_height", RPCArg::Type::NUM, RPCArg::Optional::NO, "The block hash or height of the target block",
                     RPCArgOptions{
                         .skip_type_check = true,
                         .type_str = {"", "string or numeric"},
                     }},
                    {"stats", RPCArg::Type::ARR, RPCArg::DefaultHint{"all values"}, "Values to plot (see result below)",
                        {
                            {"height", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Selected statistic"},
                            {"time", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Selected statistic"},
                        },
                        RPCArgOptions{.oneline_description="stats"}},
                },
                RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "avgfee", /*optional=*/true, "Average fee in the block"},
                {RPCResult::Type::NUM, "avgfeerate", /*optional=*/true, "Average feerate (in satoshis per virtual byte)"},
                {RPCResult::Type::NUM, "avgtxsize", /*optional=*/true, "Average transaction size"},
                {RPCResult::Type::STR_HEX, "blockhash", /*optional=*/true, "The block hash (to check for potential reorgs)"},
                {RPCResult::Type::ARR_FIXED, "feerate_percentiles", /*optional=*/true, "Feerates at the 10th, 25th, 50th, 75th, and 90th percentile weight unit (in satoshis per virtual byte)",
                {
                    {RPCResult::Type::NUM, "10th_percentile_feerate", "The 10th percentile feerate"},
                    {RPCResult::Type::NUM, "25th_percentile_feerate", "The 25th percentile feerate"},
                    {RPCResult::Type::NUM, "50th_percentile_feerate", "The 50th percentile feerate"},
                    {RPCResult::Type::NUM, "75th_percentile_feerate", "The 75th percentile feerate"},
                    {RPCResult::Type::NUM, "90th_percentile_feerate", "The 90th percentile feerate"},
                }},
                {RPCResult::Type::NUM, "height", /*optional=*/true, "The height of the block"},
                {RPCResult::Type::NUM, "ins", /*optional=*/true, "The number of inputs (excluding coinbase)"},
                {RPCResult::Type::NUM, "maxfee", /*optional=*/true, "Maximum fee in the block"},
                {RPCResult::Type::NUM, "maxfeerate", /*optional=*/true, "Maximum feerate (in satoshis per virtual byte)"},
                {RPCResult::Type::NUM, "maxtxsize", /*optional=*/true, "Maximum transaction size"},
                {RPCResult::Type::NUM, "medianfee", /*optional=*/true, "Truncated median fee in the block"},
                {RPCResult::Type::NUM, "mediantime", /*optional=*/true, "The block median time past"},
                {RPCResult::Type::NUM, "mediantxsize", /*optional=*/true, "Truncated median transaction size"},
                {RPCResult::Type::NUM, "minfee", /*optional=*/true, "Minimum fee in the block"},
                {RPCResult::Type::NUM, "minfeerate", /*optional=*/true, "Minimum feerate (in satoshis per virtual byte)"},
                {RPCResult::Type::NUM, "mintxsize", /*optional=*/true, "Minimum transaction size"},
                {RPCResult::Type::NUM, "outs", /*optional=*/true, "The number of outputs"},
                {RPCResult::Type::NUM, "subsidy", /*optional=*/true, "The block subsidy"},
                {RPCResult::Type::NUM, "swtotal_size", /*optional=*/true, "Total size of all segwit transactions"},
                {RPCResult::Type::NUM, "swtotal_weight", /*optional=*/true, "Total weight of all segwit transactions"},
                {RPCResult::Type::NUM, "swtxs", /*optional=*/true, "The number of segwit transactions"},
                {RPCResult::Type::NUM, "time", /*optional=*/true, "The block time"},
                {RPCResult::Type::NUM, "total_out", /*optional=*/true, "Total amount in all outputs (excluding coinbase and thus reward [ie subsidy + totalfee])"},
                {RPCResult::Type::NUM, "total_size", /*optional=*/true, "Total size of all non-coinbase transactions"},
                {RPCResult::Type::NUM, "total_weight", /*optional=*/true, "Total weight of all non-coinbase transactions"},
                {RPCResult::Type::NUM, "totalfee", /*optional=*/true, "The fee total"},
                {RPCResult::Type::NUM, "txs", /*optional=*/true, "The number of transactions (including coinbase)"},
                {RPCResult::Type::NUM, "utxo_increase", /*optional=*/true, "The increase/decrease in the number of unspent outputs (not discounting op_return and similar)"},
                {RPCResult::Type::NUM, "utxo_size_inc", /*optional=*/true, "The increase/decrease in size for the utxo index (not discounting op_return and similar)"},
                {RPCResult::Type::NUM, "utxo_increase_actual", /*optional=*/true, "The increase/decrease in the number of unspent outputs, not counting unspendables"},
                {RPCResult::Type::NUM, "utxo_size_inc_actual", /*optional=*/true, "The increase/decrease in size for the utxo index, not counting unspendables"},
            }},
                RPCExamples{
                    HelpExampleCli("getblockstats", R"('"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09"' '["minfeerate","avgfeerate"]')") +
                    HelpExampleCli("getblockstats", R"(1000 '["minfeerate","avgfeerate"]')") +
                    HelpExampleRpc("getblockstats", R"("00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09", ["minfeerate","avgfeerate"])") +
                    HelpExampleRpc("getblockstats", R"(1000, ["minfeerate","avgfeerate"])")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    const CBlockIndex& pindex{*CHECK_NONFATAL(ParseHashOrHeight(request.params[0], chainman))};

    std::set<std::string> stats;
    if (!request.params[1].isNull()) {
        const UniValue stats_univalue = request.params[1].get_array();
        for (unsigned int i = 0; i < stats_univalue.size(); i++) {
            const std::string stat = stats_univalue[i].get_str();
            stats.insert(stat);
        }
    }

    const CBlock& block = GetBlockChecked(chainman.m_blockman, pindex);
    const CBlockUndo& blockUndo = GetUndoChecked(chainman.m_blockman, pindex);

    const bool do_all = stats.size() == 0; // Calculate everything if nothing selected (default)
    const bool do_mediantxsize = do_all || stats.count("mediantxsize") != 0;
    const bool do_medianfee = do_all || stats.count("medianfee") != 0;
    const bool do_feerate_percentiles = do_all || stats.count("feerate_percentiles") != 0;
    const bool loop_inputs = do_all || do_medianfee || do_feerate_percentiles ||
        SetHasKeys(stats, "utxo_increase", "utxo_increase_actual", "utxo_size_inc", "utxo_size_inc_actual", "totalfee", "avgfee", "avgfeerate", "minfee", "maxfee", "minfeerate", "maxfeerate");
    const bool loop_outputs = do_all || loop_inputs || stats.count("total_out");
    const bool do_calculate_size = do_mediantxsize ||
        SetHasKeys(stats, "total_size", "avgtxsize", "mintxsize", "maxtxsize", "swtotal_size");
    const bool do_calculate_weight = do_all || SetHasKeys(stats, "total_weight", "avgfeerate", "swtotal_weight", "avgfeerate", "feerate_percentiles", "minfeerate", "maxfeerate");
    const bool do_calculate_sw = do_all || SetHasKeys(stats, "swtxs", "swtotal_size", "swtotal_weight");

    CAmount maxfee = 0;
    CAmount maxfeerate = 0;
    CAmount minfee = MAX_MONEY;
    CAmount minfeerate = MAX_MONEY;
    CAmount total_out = 0;
    CAmount totalfee = 0;
    int64_t inputs = 0;
    int64_t maxtxsize = 0;
    int64_t mintxsize = MAX_BLOCK_SERIALIZED_SIZE;
    int64_t outputs = 0;
    int64_t swtotal_size = 0;
    int64_t swtotal_weight = 0;
    int64_t swtxs = 0;
    int64_t total_size = 0;
    int64_t total_weight = 0;
    int64_t utxos = 0;
    int64_t utxo_size_inc = 0;
    int64_t utxo_size_inc_actual = 0;
    std::vector<CAmount> fee_array;
    std::vector<std::pair<CAmount, int64_t>> feerate_array;
    std::vector<int64_t> txsize_array;

    for (size_t i = 0; i < block.vtx.size(); ++i) {
        const auto& tx = block.vtx.at(i);
        outputs += tx->vout.size();

        CAmount tx_total_out = 0;
        if (loop_outputs) {
            for (const CTxOut& out : tx->vout) {
                tx_total_out += out.nValue;

                size_t out_size = GetSerializeSize(out) + PER_UTXO_OVERHEAD;
                utxo_size_inc += out_size;

                // The Genesis block and the repeated BIP30 block coinbases don't change the UTXO
                // set counts, so they have to be excluded from the statistics
                if (pindex.nHeight == 0 || (IsBIP30Repeat(pindex) && tx->IsCoinBase())) continue;
                // Skip unspendable outputs since they are not included in the UTXO set
                if (out.scriptPubKey.IsUnspendable()) continue;

                ++utxos;
                utxo_size_inc_actual += out_size;
            }
        }

        if (tx->IsCoinBase()) {
            continue;
        }

        inputs += tx->vin.size(); // Don't count coinbase's fake input
        total_out += tx_total_out; // Don't count coinbase reward

        int64_t tx_size = 0;
        if (do_calculate_size) {

            tx_size = tx->GetTotalSize();
            if (do_mediantxsize) {
                txsize_array.push_back(tx_size);
            }
            maxtxsize = std::max(maxtxsize, tx_size);
            mintxsize = std::min(mintxsize, tx_size);
            total_size += tx_size;
        }

        int64_t weight = 0;
        if (do_calculate_weight) {
            weight = GetTransactionWeight(*tx);
            total_weight += weight;
        }

        if (do_calculate_sw && tx->HasWitness()) {
            ++swtxs;
            swtotal_size += tx_size;
            swtotal_weight += weight;
        }

        if (loop_inputs) {
            CAmount tx_total_in = 0;
            const auto& txundo = blockUndo.vtxundo.at(i - 1);
            for (const Coin& coin: txundo.vprevout) {
                const CTxOut& prevoutput = coin.out;

                tx_total_in += prevoutput.nValue;
                size_t prevout_size = GetSerializeSize(prevoutput) + PER_UTXO_OVERHEAD;
                utxo_size_inc -= prevout_size;
                utxo_size_inc_actual -= prevout_size;
            }

            CAmount txfee = tx_total_in - tx_total_out;
            CHECK_NONFATAL(MoneyRange(txfee));
            if (do_medianfee) {
                fee_array.push_back(txfee);
            }
            maxfee = std::max(maxfee, txfee);
            minfee = std::min(minfee, txfee);
            totalfee += txfee;

            // New feerate uses satoshis per virtual byte instead of per serialized byte
            CAmount feerate = weight ? (txfee * WITNESS_SCALE_FACTOR) / weight : 0;
            if (do_feerate_percentiles) {
                feerate_array.emplace_back(feerate, weight);
            }
            maxfeerate = std::max(maxfeerate, feerate);
            minfeerate = std::min(minfeerate, feerate);
        }
    }

    CAmount feerate_percentiles[NUM_GETBLOCKSTATS_PERCENTILES] = { 0 };
    CalculatePercentilesByWeight(feerate_percentiles, feerate_array, total_weight);

    UniValue feerates_res(UniValue::VARR);
    for (int64_t i = 0; i < NUM_GETBLOCKSTATS_PERCENTILES; i++) {
        feerates_res.push_back(feerate_percentiles[i]);
    }

    UniValue ret_all(UniValue::VOBJ);
    ret_all.pushKV("avgfee", (block.vtx.size() > 1) ? totalfee / (block.vtx.size() - 1) : 0);
    ret_all.pushKV("avgfeerate", total_weight ? (totalfee * WITNESS_SCALE_FACTOR) / total_weight : 0); // Unit: sat/vbyte
    ret_all.pushKV("avgtxsize", (block.vtx.size() > 1) ? total_size / (block.vtx.size() - 1) : 0);
    ret_all.pushKV("blockhash", pindex.GetBlockHash().GetHex());
    ret_all.pushKV("feerate_percentiles", std::move(feerates_res));
    ret_all.pushKV("height", (int64_t)pindex.nHeight);
    ret_all.pushKV("ins", inputs);
    ret_all.pushKV("maxfee", maxfee);
    ret_all.pushKV("maxfeerate", maxfeerate);
    ret_all.pushKV("maxtxsize", maxtxsize);
    ret_all.pushKV("medianfee", CalculateTruncatedMedian(fee_array));
    ret_all.pushKV("mediantime", pindex.GetMedianTimePast());
    ret_all.pushKV("mediantxsize", CalculateTruncatedMedian(txsize_array));
    ret_all.pushKV("minfee", (minfee == MAX_MONEY) ? 0 : minfee);
    ret_all.pushKV("minfeerate", (minfeerate == MAX_MONEY) ? 0 : minfeerate);
    ret_all.pushKV("mintxsize", mintxsize == MAX_BLOCK_SERIALIZED_SIZE ? 0 : mintxsize);
    ret_all.pushKV("outs", outputs);
    ret_all.pushKV("subsidy", GetBlockSubsidy(pindex.nHeight, chainman.GetParams().GetConsensus()));
    ret_all.pushKV("swtotal_size", swtotal_size);
    ret_all.pushKV("swtotal_weight", swtotal_weight);
    ret_all.pushKV("swtxs", swtxs);
    ret_all.pushKV("time", pindex.GetBlockTime());
    ret_all.pushKV("total_out", total_out);
    ret_all.pushKV("total_size", total_size);
    ret_all.pushKV("total_weight", total_weight);
    ret_all.pushKV("totalfee", totalfee);
    ret_all.pushKV("txs", (int64_t)block.vtx.size());
    ret_all.pushKV("utxo_increase", outputs - inputs);
    ret_all.pushKV("utxo_size_inc", utxo_size_inc);
    ret_all.pushKV("utxo_increase_actual", utxos - inputs);
    ret_all.pushKV("utxo_size_inc_actual", utxo_size_inc_actual);

    if (do_all) {
        return ret_all;
    }

    UniValue ret(UniValue::VOBJ);
    for (const std::string& stat : stats) {
        const UniValue& value = ret_all[stat];
        if (value.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid selected statistic '%s'", stat));
        }
        ret.pushKV(stat, value);
    }
    return ret;
},
    };
}

namespace {
//! Search for a given set of pubkey scripts
bool FindScriptPubKey(std::atomic<int>& scan_progress, const std::atomic<bool>& should_abort, int64_t& count, CCoinsViewCursor* cursor, const std::set<CScript>& needles, std::map<COutPoint, Coin>& out_results, std::function<void()>& interruption_point)
{
    scan_progress = 0;
    count = 0;
    while (cursor->Valid()) {
        COutPoint key;
        Coin coin;
        if (!cursor->GetKey(key) || !cursor->GetValue(coin)) return false;
        if (++count % 8192 == 0) {
            interruption_point();
            if (should_abort) {
                // allow to abort the scan via the abort reference
                return false;
            }
        }
        if (count % 256 == 0) {
            // update progress reference every 256 item
            uint32_t high = 0x100 * *UCharCast(key.hash.begin()) + *(UCharCast(key.hash.begin()) + 1);
            scan_progress = (int)(high * 100.0 / 65536.0 + 0.5);
        }
        if (needles.count(coin.out.scriptPubKey)) {
            out_results.emplace(key, coin);
        }
        cursor->Next();
    }
    scan_progress = 100;
    return true;
}
} // namespace

/** RAII object to prevent concurrency issue when scanning the txout set */
static std::atomic<int> g_scan_progress;
static std::atomic<bool> g_scan_in_progress;
static std::atomic<bool> g_should_abort_scan;
class CoinsViewScanReserver
{
private:
    bool m_could_reserve{false};
public:
    explicit CoinsViewScanReserver() = default;

    bool reserve() {
        CHECK_NONFATAL(!m_could_reserve);
        if (g_scan_in_progress.exchange(true)) {
            return false;
        }
        CHECK_NONFATAL(g_scan_progress == 0);
        m_could_reserve = true;
        return true;
    }

    ~CoinsViewScanReserver() {
        if (m_could_reserve) {
            g_scan_in_progress = false;
            g_scan_progress = 0;
        }
    }
};

static const auto scan_action_arg_desc = RPCArg{
    "action", RPCArg::Type::STR, RPCArg::Optional::NO, "The action to execute\n"
        "\"start\" for starting a scan\n"
        "\"abort\" for aborting the current scan (returns true when abort was successful)\n"
        "\"status\" for progress report (in %) of the current scan"
};

static const auto output_descriptor_obj = RPCArg{
    "", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "An object with output descriptor and metadata",
    {
        {"desc", RPCArg::Type::STR, RPCArg::Optional::NO, "An output descriptor"},
        {"range", RPCArg::Type::RANGE, RPCArg::Default{1000}, "The range of HD chain indexes to explore (either end or [begin,end])"},
    }
};

static const auto scan_objects_arg_desc = RPCArg{
    "scanobjects", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Array of scan objects. Required for \"start\" action\n"
        "Every scan object is either a string descriptor or an object:",
    {
        {"descriptor", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "An output descriptor"},
        output_descriptor_obj,
    },
    RPCArgOptions{.oneline_description="[scanobjects,...]"},
};

static const auto scan_result_abort = RPCResult{
    "when action=='abort'", RPCResult::Type::BOOL, "success",
    "True if scan will be aborted (not necessarily before this RPC returns), or false if there is no scan to abort"
};
static const auto scan_result_status_none = RPCResult{
    "when action=='status' and no scan is in progress - possibly already completed", RPCResult::Type::NONE, "", ""
};
static const auto scan_result_status_some = RPCResult{
    "when action=='status' and a scan is currently in progress", RPCResult::Type::OBJ, "", "",
    {{RPCResult::Type::NUM, "progress", "Approximate percent complete"},}
};


static RPCHelpMan scantxoutset()
{
    // raw() descriptor corresponding to mainnet address 12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S
    const std::string EXAMPLE_DESCRIPTOR_RAW = "raw(76a91411b366edfc0a8b66feebae5c2e25a7b6a5d1cf3188ac)#fm24fxxy";

    return RPCHelpMan{
        "scantxoutset",
        "Scans the unspent transaction output set for entries that match certain output descriptors.\n"
        "Examples of output descriptors are:\n"
        "    addr(<address>)                      Outputs whose output script corresponds to the specified address (does not include P2PK)\n"
        "    raw(<hex script>)                    Outputs whose output script equals the specified hex-encoded bytes\n"
        "    combo(<pubkey>)                      P2PK, P2PKH, P2WPKH, and P2SH-P2WPKH outputs for the given pubkey\n"
        "    pkh(<pubkey>)                        P2PKH outputs for the given pubkey\n"
        "    sh(multi(<n>,<pubkey>,<pubkey>,...)) P2SH-multisig outputs for the given threshold and pubkeys\n"
        "    tr(<pubkey>)                         P2TR\n"
        "    tr(<pubkey>,{pk(<pubkey>)})          P2TR with single fallback pubkey in tapscript\n"
        "    rawtr(<pubkey>)                      P2TR with the specified key as output key rather than inner\n"
        "    wsh(and_v(v:pk(<pubkey>),after(2)))  P2WSH miniscript with mandatory pubkey and a timelock\n"
        "\nIn the above, <pubkey> either refers to a fixed public key in hexadecimal notation, or to an xpub/xprv optionally followed by one\n"
        "or more path elements separated by \"/\", and optionally ending in \"/*\" (unhardened), or \"/*'\" or \"/*h\" (hardened) to specify all\n"
        "unhardened or hardened child keys.\n"
        "In the latter case, a range needs to be specified by below if different from 1000.\n"
        "For more information on output descriptors, see the documentation in the doc/descriptors.md file.\n",
        {
            scan_action_arg_desc,
            scan_objects_arg_desc,
        },
        {
            RPCResult{"when action=='start'; only returns after scan completes", RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::BOOL, "success", "Whether the scan was completed"},
                {RPCResult::Type::NUM, "txouts", "The number of unspent transaction outputs scanned"},
                {RPCResult::Type::NUM, "height", "The block height at which the scan was done"},
                {RPCResult::Type::STR_HEX, "bestblock", "The hash of the block at the tip of the chain"},
                {RPCResult::Type::ARR, "unspents", "",
                {
                    {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
                        {RPCResult::Type::NUM, "vout", "The vout value"},
                        {RPCResult::Type::STR_HEX, "scriptPubKey", "The output script"},
                        {RPCResult::Type::STR, "desc", "A specialized descriptor for the matched output script"},
                        {RPCResult::Type::STR_AMOUNT, "amount", "The total amount in " + CURRENCY_UNIT + " of the unspent output"},
                        {RPCResult::Type::BOOL, "coinbase", "Whether this is a coinbase output"},
                        {RPCResult::Type::NUM, "height", "Height of the unspent transaction output"},
                        {RPCResult::Type::STR_HEX, "blockhash", "Blockhash of the unspent transaction output"},
                        {RPCResult::Type::NUM, "confirmations", "Number of confirmations of the unspent transaction output when the scan was done"},
                    }},
                }},
                {RPCResult::Type::STR_AMOUNT, "total_amount", "The total amount of all found unspent outputs in " + CURRENCY_UNIT},
            }},
            scan_result_abort,
            scan_result_status_some,
            scan_result_status_none,
        },
        RPCExamples{
            HelpExampleCli("scantxoutset", "start \'[\"" + EXAMPLE_DESCRIPTOR_RAW + "\"]\'") +
            HelpExampleCli("scantxoutset", "status") +
            HelpExampleCli("scantxoutset", "abort") +
            HelpExampleRpc("scantxoutset", "\"start\", [\"" + EXAMPLE_DESCRIPTOR_RAW + "\"]") +
            HelpExampleRpc("scantxoutset", "\"status\"") +
            HelpExampleRpc("scantxoutset", "\"abort\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue result(UniValue::VOBJ);
    const auto action{self.Arg<std::string>("action")};
    if (action == "status") {
        CoinsViewScanReserver reserver;
        if (reserver.reserve()) {
            // no scan in progress
            return UniValue::VNULL;
        }
        result.pushKV("progress", g_scan_progress.load());
        return result;
    } else if (action == "abort") {
        CoinsViewScanReserver reserver;
        if (reserver.reserve()) {
            // reserve was possible which means no scan was running
            return false;
        }
        // set the abort flag
        g_should_abort_scan = true;
        return true;
    } else if (action == "start") {
        CoinsViewScanReserver reserver;
        if (!reserver.reserve()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Scan already in progress, use action \"abort\" or \"status\"");
        }

        if (request.params.size() < 2) {
            throw JSONRPCError(RPC_MISC_ERROR, "scanobjects argument is required for the start action");
        }

        std::set<CScript> needles;
        std::map<CScript, std::string> descriptors;
        CAmount total_in = 0;

        // loop through the scan objects
        for (const UniValue& scanobject : request.params[1].get_array().getValues()) {
            FlatSigningProvider provider;
            auto scripts = EvalDescriptorStringOrObject(scanobject, provider);
            for (CScript& script : scripts) {
                std::string inferred = InferDescriptor(script, provider)->ToString();
                needles.emplace(script);
                descriptors.emplace(std::move(script), std::move(inferred));
            }
        }

        // Scan the unspent transaction output set for inputs
        UniValue unspents(UniValue::VARR);
        std::vector<CTxOut> input_txos;
        std::map<COutPoint, Coin> coins;
        g_should_abort_scan = false;
        int64_t count = 0;
        std::unique_ptr<CCoinsViewCursor> pcursor;
        const CBlockIndex* tip;
        NodeContext& node = EnsureAnyNodeContext(request.context);
        {
            ChainstateManager& chainman = EnsureChainman(node);
            LOCK(cs_main);
            Chainstate& active_chainstate = chainman.ActiveChainstate();
            active_chainstate.ForceFlushStateToDisk();
            pcursor = CHECK_NONFATAL(active_chainstate.CoinsDB().Cursor());
            tip = CHECK_NONFATAL(active_chainstate.m_chain.Tip());
        }
        bool res = FindScriptPubKey(g_scan_progress, g_should_abort_scan, count, pcursor.get(), needles, coins, node.rpc_interruption_point);
        result.pushKV("success", res);
        result.pushKV("txouts", count);
        result.pushKV("height", tip->nHeight);
        result.pushKV("bestblock", tip->GetBlockHash().GetHex());

        for (const auto& it : coins) {
            const COutPoint& outpoint = it.first;
            const Coin& coin = it.second;
            const CTxOut& txo = coin.out;
            const CBlockIndex& coinb_block{*CHECK_NONFATAL(tip->GetAncestor(coin.nHeight))};
            input_txos.push_back(txo);
            total_in += txo.nValue;

            UniValue unspent(UniValue::VOBJ);
            unspent.pushKV("txid", outpoint.hash.GetHex());
            unspent.pushKV("vout", outpoint.n);
            unspent.pushKV("scriptPubKey", HexStr(txo.scriptPubKey));
            unspent.pushKV("desc", descriptors[txo.scriptPubKey]);
            unspent.pushKV("amount", ValueFromAmount(txo.nValue));
            unspent.pushKV("coinbase", coin.IsCoinBase());
            unspent.pushKV("height", coin.nHeight);
            unspent.pushKV("blockhash", coinb_block.GetBlockHash().GetHex());
            unspent.pushKV("confirmations", tip->nHeight - coin.nHeight + 1);

            unspents.push_back(std::move(unspent));
        }
        result.pushKV("unspents", std::move(unspents));
        result.pushKV("total_amount", ValueFromAmount(total_in));
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid action '%s'", action));
    }
    return result;
},
    };
}

/** RAII object to prevent concurrency issue when scanning blockfilters */
static std::atomic<int> g_scanfilter_progress;
static std::atomic<int> g_scanfilter_progress_height;
static std::atomic<bool> g_scanfilter_in_progress;
static std::atomic<bool> g_scanfilter_should_abort_scan;
class BlockFiltersScanReserver
{
private:
    bool m_could_reserve{false};
public:
    explicit BlockFiltersScanReserver() = default;

    bool reserve() {
        CHECK_NONFATAL(!m_could_reserve);
        if (g_scanfilter_in_progress.exchange(true)) {
            return false;
        }
        m_could_reserve = true;
        return true;
    }

    ~BlockFiltersScanReserver() {
        if (m_could_reserve) {
            g_scanfilter_in_progress = false;
        }
    }
};

static bool CheckBlockFilterMatches(BlockManager& blockman, const CBlockIndex& blockindex, const GCSFilter::ElementSet& needles)
{
    const CBlock block{GetBlockChecked(blockman, blockindex)};
    const CBlockUndo block_undo{GetUndoChecked(blockman, blockindex)};

    // Check if any of the outputs match the scriptPubKey
    for (const auto& tx : block.vtx) {
        if (std::any_of(tx->vout.cbegin(), tx->vout.cend(), [&](const auto& txout) {
                return needles.count(std::vector<unsigned char>(txout.scriptPubKey.begin(), txout.scriptPubKey.end())) != 0;
            })) {
            return true;
        }
    }
    // Check if any of the inputs match the scriptPubKey
    for (const auto& txundo : block_undo.vtxundo) {
        if (std::any_of(txundo.vprevout.cbegin(), txundo.vprevout.cend(), [&](const auto& coin) {
                return needles.count(std::vector<unsigned char>(coin.out.scriptPubKey.begin(), coin.out.scriptPubKey.end())) != 0;
            })) {
            return true;
        }
    }

    return false;
}

static RPCHelpMan scanblocks()
{
    return RPCHelpMan{
        "scanblocks",
        "Return relevant blockhashes for given descriptors (requires blockfilterindex).\n"
        "This call may take several minutes. Make sure to use no RPC timeout (bitcoin-cli -rpcclienttimeout=0)",
        {
            scan_action_arg_desc,
            scan_objects_arg_desc,
            RPCArg{"start_height", RPCArg::Type::NUM, RPCArg::Default{0}, "Height to start to scan from"},
            RPCArg{"stop_height", RPCArg::Type::NUM, RPCArg::DefaultHint{"chain tip"}, "Height to stop to scan"},
            RPCArg{"filtertype", RPCArg::Type::STR, RPCArg::Default{BlockFilterTypeName(BlockFilterType::BASIC)}, "The type name of the filter"},
            RPCArg{"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "",
                {
                    {"filter_false_positives", RPCArg::Type::BOOL, RPCArg::Default{false}, "Filter false positives (slower and may fail on pruned nodes). Otherwise they may occur at a rate of 1/M"},
                },
                RPCArgOptions{.oneline_description="options"}},
        },
        {
            scan_result_status_none,
            RPCResult{"When action=='start'; only returns after scan completes", RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::NUM, "from_height", "The height we started the scan from"},
                {RPCResult::Type::NUM, "to_height", "The height we ended the scan at"},
                {RPCResult::Type::ARR, "relevant_blocks", "Blocks that may have matched a scanobject.", {
                    {RPCResult::Type::STR_HEX, "blockhash", "A relevant blockhash"},
                }},
                {RPCResult::Type::BOOL, "completed", "true if the scan process was not aborted"}
            }},
            RPCResult{"when action=='status' and a scan is currently in progress", RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::NUM, "progress", "Approximate percent complete"},
                    {RPCResult::Type::NUM, "current_height", "Height of the block currently being scanned"},
                },
            },
            scan_result_abort,
        },
        RPCExamples{
            HelpExampleCli("scanblocks", "start '[\"addr(bcrt1q4u4nsgk6ug0sqz7r3rj9tykjxrsl0yy4d0wwte)\"]' 300000") +
            HelpExampleCli("scanblocks", "start '[\"addr(bcrt1q4u4nsgk6ug0sqz7r3rj9tykjxrsl0yy4d0wwte)\"]' 100 150 basic") +
            HelpExampleCli("scanblocks", "status") +
            HelpExampleRpc("scanblocks", "\"start\", [\"addr(bcrt1q4u4nsgk6ug0sqz7r3rj9tykjxrsl0yy4d0wwte)\"], 300000") +
            HelpExampleRpc("scanblocks", "\"start\", [\"addr(bcrt1q4u4nsgk6ug0sqz7r3rj9tykjxrsl0yy4d0wwte)\"], 100, 150, \"basic\"") +
            HelpExampleRpc("scanblocks", "\"status\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue ret(UniValue::VOBJ);
    if (request.params[0].get_str() == "status") {
        BlockFiltersScanReserver reserver;
        if (reserver.reserve()) {
            // no scan in progress
            return NullUniValue;
        }
        ret.pushKV("progress", g_scanfilter_progress.load());
        ret.pushKV("current_height", g_scanfilter_progress_height.load());
        return ret;
    } else if (request.params[0].get_str() == "abort") {
        BlockFiltersScanReserver reserver;
        if (reserver.reserve()) {
            // reserve was possible which means no scan was running
            return false;
        }
        // set the abort flag
        g_scanfilter_should_abort_scan = true;
        return true;
    } else if (request.params[0].get_str() == "start") {
        BlockFiltersScanReserver reserver;
        if (!reserver.reserve()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Scan already in progress, use action \"abort\" or \"status\"");
        }
        const std::string filtertype_name{request.params[4].isNull() ? "basic" : request.params[4].get_str()};

        BlockFilterType filtertype;
        if (!BlockFilterTypeByName(filtertype_name, filtertype)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown filtertype");
        }

        UniValue options{request.params[5].isNull() ? UniValue::VOBJ : request.params[5]};
        bool filter_false_positives{options.exists("filter_false_positives") ? options["filter_false_positives"].get_bool() : false};

        BlockFilterIndex* index = GetBlockFilterIndex(filtertype);
        if (!index) {
            throw JSONRPCError(RPC_MISC_ERROR, "Index is not enabled for filtertype " + filtertype_name);
        }

        NodeContext& node = EnsureAnyNodeContext(request.context);
        ChainstateManager& chainman = EnsureChainman(node);

        // set the start-height
        const CBlockIndex* start_index = nullptr;
        const CBlockIndex* stop_block = nullptr;
        {
            LOCK(cs_main);
            CChain& active_chain = chainman.ActiveChain();
            start_index = active_chain.Genesis();
            stop_block = active_chain.Tip(); // If no stop block is provided, stop at the chain tip.
            if (!request.params[2].isNull()) {
                start_index = active_chain[request.params[2].getInt<int>()];
                if (!start_index) {
                    throw JSONRPCError(RPC_MISC_ERROR, "Invalid start_height");
                }
            }
            if (!request.params[3].isNull()) {
                stop_block = active_chain[request.params[3].getInt<int>()];
                if (!stop_block || stop_block->nHeight < start_index->nHeight) {
                    throw JSONRPCError(RPC_MISC_ERROR, "Invalid stop_height");
                }
            }
        }
        CHECK_NONFATAL(start_index);
        CHECK_NONFATAL(stop_block);

        // loop through the scan objects, add scripts to the needle_set
        GCSFilter::ElementSet needle_set;
        for (const UniValue& scanobject : request.params[1].get_array().getValues()) {
            FlatSigningProvider provider;
            std::vector<CScript> scripts = EvalDescriptorStringOrObject(scanobject, provider);
            for (const CScript& script : scripts) {
                needle_set.emplace(script.begin(), script.end());
            }
        }
        UniValue blocks(UniValue::VARR);
        const int amount_per_chunk = 10000;
        std::vector<BlockFilter> filters;
        int start_block_height = start_index->nHeight; // for progress reporting
        const int total_blocks_to_process = stop_block->nHeight - start_block_height;

        g_scanfilter_should_abort_scan = false;
        g_scanfilter_progress = 0;
        g_scanfilter_progress_height = start_block_height;
        bool completed = true;

        const CBlockIndex* end_range = nullptr;
        do {
            node.rpc_interruption_point(); // allow a clean shutdown
            if (g_scanfilter_should_abort_scan) {
                completed = false;
                break;
            }

            // split the lookup range in chunks if we are deeper than 'amount_per_chunk' blocks from the stopping block
            int start_block = !end_range ? start_index->nHeight : start_index->nHeight + 1; // to not include the previous round 'end_range' block
            end_range = (start_block + amount_per_chunk < stop_block->nHeight) ?
                    WITH_LOCK(::cs_main, return chainman.ActiveChain()[start_block + amount_per_chunk]) :
                    stop_block;

            if (index->LookupFilterRange(start_block, end_range, filters)) {
                for (const BlockFilter& filter : filters) {
                    // compare the elements-set with each filter
                    if (filter.GetFilter().MatchAny(needle_set)) {
                        if (filter_false_positives) {
                            // Double check the filter matches by scanning the block
                            const CBlockIndex& blockindex = *CHECK_NONFATAL(WITH_LOCK(cs_main, return chainman.m_blockman.LookupBlockIndex(filter.GetBlockHash())));

                            if (!CheckBlockFilterMatches(chainman.m_blockman, blockindex, needle_set)) {
                                continue;
                            }
                        }

                        blocks.push_back(filter.GetBlockHash().GetHex());
                    }
                }
            }
            start_index = end_range;

            // update progress
            int blocks_processed = end_range->nHeight - start_block_height;
            if (total_blocks_to_process > 0) { // avoid division by zero
                g_scanfilter_progress = (int)(100.0 / total_blocks_to_process * blocks_processed);
            } else {
                g_scanfilter_progress = 100;
            }
            g_scanfilter_progress_height = end_range->nHeight;

        // Finish if we reached the stop block
        } while (start_index != stop_block);

        ret.pushKV("from_height", start_block_height);
        ret.pushKV("to_height", start_index->nHeight); // start_index is always the last scanned block here
        ret.pushKV("relevant_blocks", std::move(blocks));
        ret.pushKV("completed", completed);
    }
    else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid action '%s'", request.params[0].get_str()));
    }
    return ret;
},
    };
}

static RPCHelpMan getdescriptoractivity()
{
    return RPCHelpMan{
        "getdescriptoractivity",
        "Get spend and receive activity associated with a set of descriptors for a set of blocks. "
        "This command pairs well with the `relevant_blocks` output of `scanblocks()`.\n"
        "This call may take several minutes. If you encounter timeouts, try specifying no RPC timeout (bitcoin-cli -rpcclienttimeout=0)",
        {
            RPCArg{"blockhashes", RPCArg::Type::ARR, RPCArg::Optional::NO, "The list of blockhashes to examine for activity. Order doesn't matter. Must be along main chain or an error is thrown.\n", {
                {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A valid blockhash"},
            }},
            RPCArg{"scanobjects", RPCArg::Type::ARR, RPCArg::Optional::NO, "The list of descriptors (scan objects) to examine for activity. Every scan object is either a string descriptor or an object:",
                {
                    {"descriptor", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "An output descriptor"},
                    output_descriptor_obj,
                },
                RPCArgOptions{.oneline_description="[scanobjects,...]"},
            },
            {"include_mempool", RPCArg::Type::BOOL, RPCArg::Default{true}, "Whether to include unconfirmed activity"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::ARR, "activity", "events", {
                    {RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR, "type", "always 'spend'"},
                        {RPCResult::Type::STR_AMOUNT, "amount", "The total amount in " + CURRENCY_UNIT + " of the spent output"},
                        {RPCResult::Type::STR_HEX, "blockhash", /*optional=*/true, "The blockhash this spend appears in (omitted if unconfirmed)"},
                        {RPCResult::Type::NUM, "height", /*optional=*/true, "Height of the spend (omitted if unconfirmed)"},
                        {RPCResult::Type::STR_HEX, "spend_txid", "The txid of the spending transaction"},
                        {RPCResult::Type::NUM, "spend_vin", "The input index of the spend"},
                        {RPCResult::Type::STR_HEX, "prevout_txid", "The txid of the prevout"},
                        {RPCResult::Type::NUM, "prevout_vout", "The vout of the prevout"},
                        {RPCResult::Type::OBJ, "prevout_spk", "", ScriptPubKeyDoc()},
                    }},
                    {RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR, "type", "always 'receive'"},
                        {RPCResult::Type::STR_AMOUNT, "amount", "The total amount in " + CURRENCY_UNIT + " of the new output"},
                        {RPCResult::Type::STR_HEX, "blockhash", /*optional=*/true, "The block that this receive is in (omitted if unconfirmed)"},
                        {RPCResult::Type::NUM, "height", /*optional=*/true, "The height of the receive (omitted if unconfirmed)"},
                        {RPCResult::Type::STR_HEX, "txid", "The txid of the receiving transaction"},
                        {RPCResult::Type::NUM, "vout", "The vout of the receiving output"},
                        {RPCResult::Type::OBJ, "output_spk", "", ScriptPubKeyDoc()},
                    }},
                    // TODO is the skip_type_check avoidable with a heterogeneous ARR?
                }, /*skip_type_check=*/true},
            },
        },
        RPCExamples{
            HelpExampleCli("getdescriptoractivity", "'[\"000000000000000000001347062c12fded7c528943c8ce133987e2e2f5a840ee\"]' '[\"addr(bc1qzl6nsgqzu89a66l50cvwapnkw5shh23zarqkw9)\"]'")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue ret(UniValue::VOBJ);
    UniValue activity(UniValue::VARR);
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);

    struct CompareByHeightAscending {
        bool operator()(const CBlockIndex* a, const CBlockIndex* b) const {
            return a->nHeight < b->nHeight;
        }
    };

    std::set<const CBlockIndex*, CompareByHeightAscending> blockindexes_sorted;

    {
        // Validate all given blockhashes, and ensure blocks are along a single chain.
        LOCK(::cs_main);
        for (const UniValue& blockhash : request.params[0].get_array().getValues()) {
            uint256 bhash = ParseHashV(blockhash, "blockhash");
            CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(bhash);
            if (!pindex) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
            }
            if (!chainman.ActiveChain().Contains(pindex)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Block is not in main chain");
            }
            blockindexes_sorted.insert(pindex);
        }
    }

    std::set<CScript> scripts_to_watch;

    // Determine scripts to watch.
    for (const UniValue& scanobject : request.params[1].get_array().getValues()) {
        FlatSigningProvider provider;
        std::vector<CScript> scripts = EvalDescriptorStringOrObject(scanobject, provider);

        for (const CScript& script : scripts) {
            scripts_to_watch.insert(script);
        }
    }

    const auto AddSpend = [&](
            const CScript& spk,
            const CAmount val,
            const CTransactionRef& tx,
            int vin,
            const CTxIn& txin,
            const CBlockIndex* index
            ) {
        UniValue event(UniValue::VOBJ);
        UniValue spkUv(UniValue::VOBJ);
        ScriptToUniv(spk, /*out=*/spkUv, /*include_hex=*/true, /*include_address=*/true);

        event.pushKV("type", "spend");
        event.pushKV("amount", ValueFromAmount(val));
        if (index) {
            event.pushKV("blockhash", index->GetBlockHash().ToString());
            event.pushKV("height", index->nHeight);
        }
        event.pushKV("spend_txid", tx->GetHash().ToString());
        event.pushKV("spend_vin", vin);
        event.pushKV("prevout_txid", txin.prevout.hash.ToString());
        event.pushKV("prevout_vout", txin.prevout.n);
        event.pushKV("prevout_spk", spkUv);

        return event;
    };

    const auto AddReceive = [&](const CTxOut& txout, const CBlockIndex* index, int vout, const CTransactionRef& tx) {
        UniValue event(UniValue::VOBJ);
        UniValue spkUv(UniValue::VOBJ);
        ScriptToUniv(txout.scriptPubKey, /*out=*/spkUv, /*include_hex=*/true, /*include_address=*/true);

        event.pushKV("type", "receive");
        event.pushKV("amount", ValueFromAmount(txout.nValue));
        if (index) {
            event.pushKV("blockhash", index->GetBlockHash().ToString());
            event.pushKV("height", index->nHeight);
        }
        event.pushKV("txid", tx->GetHash().ToString());
        event.pushKV("vout", vout);
        event.pushKV("output_spk", spkUv);

        return event;
    };

    BlockManager* blockman;
    Chainstate& active_chainstate = chainman.ActiveChainstate();
    {
        LOCK(::cs_main);
        blockman = CHECK_NONFATAL(&active_chainstate.m_blockman);
    }

    for (const CBlockIndex* blockindex : blockindexes_sorted) {
        const CBlock block{GetBlockChecked(chainman.m_blockman, *blockindex)};
        const CBlockUndo block_undo{GetUndoChecked(*blockman, *blockindex)};

        for (size_t i = 0; i < block.vtx.size(); ++i) {
            const auto& tx = block.vtx.at(i);

            if (!tx->IsCoinBase()) {
                // skip coinbase; spends can't happen there.
                const auto& txundo = block_undo.vtxundo.at(i - 1);

                for (size_t vin_idx = 0; vin_idx < tx->vin.size(); ++vin_idx) {
                    const auto& coin = txundo.vprevout.at(vin_idx);
                    const auto& txin = tx->vin.at(vin_idx);
                    if (scripts_to_watch.contains(coin.out.scriptPubKey)) {
                        activity.push_back(AddSpend(
                                    coin.out.scriptPubKey, coin.out.nValue, tx, vin_idx, txin, blockindex));
                    }
                }
            }

            for (size_t vout_idx = 0; vout_idx < tx->vout.size(); ++vout_idx) {
                const auto& vout = tx->vout.at(vout_idx);
                if (scripts_to_watch.contains(vout.scriptPubKey)) {
                    activity.push_back(AddReceive(vout, blockindex, vout_idx, tx));
                }
            }
        }
    }

    bool search_mempool = true;
    if (!request.params[2].isNull()) {
        search_mempool = request.params[2].get_bool();
    }

    if (search_mempool) {
        const CTxMemPool& mempool = EnsureMemPool(node);
        LOCK(::cs_main);
        LOCK(mempool.cs);
        const CCoinsViewCache& coins_view = &active_chainstate.CoinsTip();

        for (const CTxMemPoolEntry& e : mempool.entryAll()) {
            const auto& tx = e.GetSharedTx();

            for (size_t vin_idx = 0; vin_idx < tx->vin.size(); ++vin_idx) {
                CScript scriptPubKey;
                CAmount value;
                const auto& txin = tx->vin.at(vin_idx);
                std::optional<Coin> coin = coins_view.GetCoin(txin.prevout);

                // Check if the previous output is in the chain
                if (!coin) {
                    // If not found in the chain, check the mempool. Likely, this is a
                    // child transaction of another transaction in the mempool.
                    CTransactionRef prev_tx = CHECK_NONFATAL(mempool.get(txin.prevout.hash));

                    if (txin.prevout.n >= prev_tx->vout.size()) {
                        throw std::runtime_error("Invalid output index");
                    }
                    const CTxOut& out = prev_tx->vout[txin.prevout.n];
                    scriptPubKey = out.scriptPubKey;
                    value = out.nValue;
                } else {
                    // Coin found in the chain
                    const CTxOut& out = coin->out;
                    scriptPubKey = out.scriptPubKey;
                    value = out.nValue;
                }

                if (scripts_to_watch.contains(scriptPubKey)) {
                    UniValue event(UniValue::VOBJ);
                    activity.push_back(AddSpend(
                                scriptPubKey, value, tx, vin_idx, txin, nullptr));
                }
            }

            for (size_t vout_idx = 0; vout_idx < tx->vout.size(); ++vout_idx) {
                const auto& vout = tx->vout.at(vout_idx);
                if (scripts_to_watch.contains(vout.scriptPubKey)) {
                    activity.push_back(AddReceive(vout, nullptr, vout_idx, tx));
                }
            }
        }
    }

    ret.pushKV("activity", activity);
    return ret;
},
    };
}

static RPCHelpMan getblockfilter()
{
    return RPCHelpMan{
        "getblockfilter",
        "Retrieve a BIP 157 content filter for a particular block.\n",
                {
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hash of the block"},
                    {"filtertype", RPCArg::Type::STR, RPCArg::Default{BlockFilterTypeName(BlockFilterType::BASIC)}, "The type name of the filter"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "filter", "the hex-encoded filter data"},
                        {RPCResult::Type::STR_HEX, "header", "the hex-encoded filter header"},
                    }},
                RPCExamples{
                    HelpExampleCli("getblockfilter", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\" \"basic\"") +
                    HelpExampleRpc("getblockfilter", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\", \"basic\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    uint256 block_hash = ParseHashV(request.params[0], "blockhash");
    std::string filtertype_name = BlockFilterTypeName(BlockFilterType::BASIC);
    if (!request.params[1].isNull()) {
        filtertype_name = request.params[1].get_str();
    }

    BlockFilterType filtertype;
    if (!BlockFilterTypeByName(filtertype_name, filtertype)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown filtertype");
    }

    BlockFilterIndex* index = GetBlockFilterIndex(filtertype);
    if (!index) {
        throw JSONRPCError(RPC_MISC_ERROR, "Index is not enabled for filtertype " + filtertype_name);
    }

    const CBlockIndex* block_index;
    bool block_was_connected;
    {
        ChainstateManager& chainman = EnsureAnyChainman(request.context);
        LOCK(cs_main);
        block_index = chainman.m_blockman.LookupBlockIndex(block_hash);
        if (!block_index) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
        block_was_connected = block_index->IsValid(BLOCK_VALID_SCRIPTS);
    }

    bool index_ready = index->BlockUntilSyncedToCurrentChain();

    BlockFilter filter;
    uint256 filter_header;
    if (!index->LookupFilter(block_index, filter) ||
        !index->LookupFilterHeader(block_index, filter_header)) {
        int err_code;
        std::string errmsg = "Filter not found.";

        if (!block_was_connected) {
            err_code = RPC_INVALID_ADDRESS_OR_KEY;
            errmsg += " Block was not connected to active chain.";
        } else if (!index_ready) {
            err_code = RPC_MISC_ERROR;
            errmsg += " Block filters are still in the process of being indexed.";
        } else {
            err_code = RPC_INTERNAL_ERROR;
            errmsg += " This error is unexpected and indicates index corruption.";
        }

        throw JSONRPCError(err_code, errmsg);
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("filter", HexStr(filter.GetEncodedFilter()));
    ret.pushKV("header", filter_header.GetHex());
    return ret;
},
    };
}

/**
 * RAII class that disables the network in its constructor and enables it in its
 * destructor.
 */
class NetworkDisable
{
    CConnman& m_connman;
public:
    NetworkDisable(CConnman& connman) : m_connman(connman) {
        m_connman.SetNetworkActive(false);
        if (m_connman.GetNetworkActive()) {
            throw JSONRPCError(RPC_MISC_ERROR, "Network activity could not be suspended.");
        }
    };
    ~NetworkDisable() {
        m_connman.SetNetworkActive(true);
    };
};

/**
 * RAII class that temporarily rolls back the local chain in it's constructor
 * and rolls it forward again in it's destructor.
 */
class TemporaryRollback
{
    ChainstateManager& m_chainman;
    const CBlockIndex& m_invalidate_index;
public:
    TemporaryRollback(ChainstateManager& chainman, const CBlockIndex& index) : m_chainman(chainman), m_invalidate_index(index) {
        InvalidateBlock(m_chainman, m_invalidate_index.GetBlockHash());
    };
    ~TemporaryRollback() {
        ReconsiderBlock(m_chainman, m_invalidate_index.GetBlockHash());
    };
};

/**
 * Serialize the UTXO set to a file for loading elsewhere.
 *
 * @see SnapshotMetadata
 */
static RPCHelpMan dumptxoutset()
{
    return RPCHelpMan{
        "dumptxoutset",
        "Write the serialized UTXO set to a file. This can be used in loadtxoutset afterwards if this snapshot height is supported in the chainparams as well.\n\n"
        "Unless the \"latest\" type is requested, the node will roll back to the requested height and network activity will be suspended during this process. "
        "Because of this it is discouraged to interact with the node in any other way during the execution of this call to avoid inconsistent results and race conditions, particularly RPCs that interact with blockstorage.\n\n"
        "This call may take several minutes. Make sure to use no RPC timeout (bitcoin-cli -rpcclienttimeout=0)",
        {
            {"path", RPCArg::Type::STR, RPCArg::Optional::NO, "Path to the output file. If relative, will be prefixed by datadir."},
            {"type", RPCArg::Type::STR, RPCArg::Default(""), "The type of snapshot to create. Can be \"latest\" to create a snapshot of the current UTXO set or \"rollback\" to temporarily roll back the state of the node to a historical block before creating the snapshot of a historical UTXO set. This parameter can be omitted if a separate \"rollback\" named parameter is specified indicating the height or hash of a specific historical block. If \"rollback\" is specified and separate \"rollback\" named parameter is not specified, this will roll back to the latest valid snapshot block that can currently be loaded with loadtxoutset."},
            {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "",
                {
                    {"rollback", RPCArg::Type::NUM, RPCArg::Optional::OMITTED,
                        "Height or hash of the block to roll back to before creating the snapshot. Note: The further this number is from the tip, the longer this process will take. Consider setting a higher -rpcclienttimeout value in this case.",
                    RPCArgOptions{.skip_type_check = true, .type_str = {"", "string or numeric"}}},
                },
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::NUM, "coins_written", "the number of coins written in the snapshot"},
                    {RPCResult::Type::STR_HEX, "base_hash", "the hash of the base of the snapshot"},
                    {RPCResult::Type::NUM, "base_height", "the height of the base of the snapshot"},
                    {RPCResult::Type::STR, "path", "the absolute path that the snapshot was written to"},
                    {RPCResult::Type::STR_HEX, "txoutset_hash", "the hash of the UTXO set contents"},
                    {RPCResult::Type::NUM, "nchaintx", "the number of transactions in the chain up to and including the base block"},
                }
        },
        RPCExamples{
            HelpExampleCli("-rpcclienttimeout=0 dumptxoutset", "utxo.dat latest") +
            HelpExampleCli("-rpcclienttimeout=0 dumptxoutset", "utxo.dat rollback") +
            HelpExampleCli("-rpcclienttimeout=0 -named dumptxoutset", R"(utxo.dat rollback=853456)")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    const CBlockIndex* tip{WITH_LOCK(::cs_main, return node.chainman->ActiveChain().Tip())};
    const CBlockIndex* target_index{nullptr};
    const std::string snapshot_type{self.Arg<std::string>("type")};
    const UniValue options{request.params[2].isNull() ? UniValue::VOBJ : request.params[2]};
    if (options.exists("rollback")) {
        if (!snapshot_type.empty() && snapshot_type != "rollback") {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid snapshot type \"%s\" specified with rollback option", snapshot_type));
        }
        target_index = ParseHashOrHeight(options["rollback"], *node.chainman);
    } else if (snapshot_type == "rollback") {
        auto snapshot_heights = node.chainman->GetParams().GetAvailableSnapshotHeights();
        CHECK_NONFATAL(snapshot_heights.size() > 0);
        auto max_height = std::max_element(snapshot_heights.begin(), snapshot_heights.end());
        target_index = ParseHashOrHeight(*max_height, *node.chainman);
    } else if (snapshot_type == "latest") {
        target_index = tip;
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid snapshot type \"%s\" specified. Please specify \"rollback\" or \"latest\"", snapshot_type));
    }

    const ArgsManager& args{EnsureAnyArgsman(request.context)};
    const fs::path path = fsbridge::AbsPathJoin(args.GetDataDirNet(), fs::u8path(request.params[0].get_str()));
    // Write to a temporary path and then move into `path` on completion
    // to avoid confusion due to an interruption.
    const fs::path temppath = fsbridge::AbsPathJoin(args.GetDataDirNet(), fs::u8path(request.params[0].get_str() + ".incomplete"));

    if (fs::exists(path)) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            path.utf8string() + " already exists. If you are sure this is what you want, "
            "move it out of the way first");
    }

    FILE* file{fsbridge::fopen(temppath, "wb")};
    AutoFile afile{file};
    if (afile.IsNull()) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "Couldn't open file " + temppath.utf8string() + " for writing.");
    }

    CConnman& connman = EnsureConnman(node);
    const CBlockIndex* invalidate_index{nullptr};
    std::optional<NetworkDisable> disable_network;
    std::optional<TemporaryRollback> temporary_rollback;

    // If the user wants to dump the txoutset of the current tip, we don't have
    // to roll back at all
    if (target_index != tip) {
        // If the node is running in pruned mode we ensure all necessary block
        // data is available before starting to roll back.
        if (node.chainman->m_blockman.IsPruneMode()) {
            LOCK(node.chainman->GetMutex());
            const CBlockIndex* current_tip{node.chainman->ActiveChain().Tip()};
            const CBlockIndex* first_block{node.chainman->m_blockman.GetFirstBlock(*current_tip, /*status_mask=*/BLOCK_HAVE_MASK)};
            if (first_block->nHeight > target_index->nHeight) {
                throw JSONRPCError(RPC_MISC_ERROR, "Could not roll back to requested height since necessary block data is already pruned.");
            }
        }

        // Suspend network activity for the duration of the process when we are
        // rolling back the chain to get a utxo set from a past height. We do
        // this so we don't punish peers that send us that send us data that
        // seems wrong in this temporary state. For example a normal new block
        // would be classified as a block connecting an invalid block.
        // Skip if the network is already disabled because this
        // automatically re-enables the network activity at the end of the
        // process which may not be what the user wants.
        if (connman.GetNetworkActive()) {
            disable_network.emplace(connman);
        }

        invalidate_index = WITH_LOCK(::cs_main, return node.chainman->ActiveChain().Next(target_index));
        temporary_rollback.emplace(*node.chainman, *invalidate_index);
    }

    Chainstate* chainstate;
    std::unique_ptr<CCoinsViewCursor> cursor;
    CCoinsStats stats;
    {
        // Lock the chainstate before calling PrepareUtxoSnapshot, to be able
        // to get a UTXO database cursor while the chain is pointing at the
        // target block. After that, release the lock while calling
        // WriteUTXOSnapshot. The cursor will remain valid and be used by
        // WriteUTXOSnapshot to write a consistent snapshot even if the
        // chainstate changes.
        LOCK(node.chainman->GetMutex());
        chainstate = &node.chainman->ActiveChainstate();
        // In case there is any issue with a block being read from disk we need
        // to stop here, otherwise the dump could still be created for the wrong
        // height.
        // The new tip could also not be the target block if we have a stale
        // sister block of invalidate_index. This block (or a descendant) would
        // be activated as the new tip and we would not get to new_tip_index.
        if (target_index != chainstate->m_chain.Tip()) {
            LogWarning("dumptxoutset failed to roll back to requested height, reverting to tip.\n");
            throw JSONRPCError(RPC_MISC_ERROR, "Could not roll back to requested height.");
        } else {
            std::tie(cursor, stats, tip) = PrepareUTXOSnapshot(*chainstate, node.rpc_interruption_point);
        }
    }

    UniValue result = WriteUTXOSnapshot(*chainstate,
                                        cursor.get(),
                                        &stats,
                                        tip,
                                        std::move(afile),
                                        path,
                                        temppath,
                                        node.rpc_interruption_point);
    fs::rename(temppath, path);

    result.pushKV("path", path.utf8string());
    return result;
},
    };
}

std::tuple<std::unique_ptr<CCoinsViewCursor>, CCoinsStats, const CBlockIndex*>
PrepareUTXOSnapshot(
    Chainstate& chainstate,
    const std::function<void()>& interruption_point)
{
    std::unique_ptr<CCoinsViewCursor> pcursor;
    std::optional<CCoinsStats> maybe_stats;
    const CBlockIndex* tip;

    {
        // We need to lock cs_main to ensure that the coinsdb isn't written to
        // between (i) flushing coins cache to disk (coinsdb), (ii) getting stats
        // based upon the coinsdb, and (iii) constructing a cursor to the
        // coinsdb for use in WriteUTXOSnapshot.
        //
        // Cursors returned by leveldb iterate over snapshots, so the contents
        // of the pcursor will not be affected by simultaneous writes during
        // use below this block.
        //
        // See discussion here:
        //   https://github.com/bitcoin/bitcoin/pull/15606#discussion_r274479369
        //
        AssertLockHeld(::cs_main);

        chainstate.ForceFlushStateToDisk();

        maybe_stats = GetUTXOStats(&chainstate.CoinsDB(), chainstate.m_blockman, CoinStatsHashType::HASH_SERIALIZED, interruption_point);
        if (!maybe_stats) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read UTXO set");
        }

        pcursor = chainstate.CoinsDB().Cursor();
        tip = CHECK_NONFATAL(chainstate.m_blockman.LookupBlockIndex(maybe_stats->hashBlock));
    }

    return {std::move(pcursor), *CHECK_NONFATAL(maybe_stats), tip};
}

UniValue WriteUTXOSnapshot(
    Chainstate& chainstate,
    CCoinsViewCursor* pcursor,
    CCoinsStats* maybe_stats,
    const CBlockIndex* tip,
    AutoFile&& afile,
    const fs::path& path,
    const fs::path& temppath,
    const std::function<void()>& interruption_point)
{
    LOG_TIME_SECONDS(strprintf("writing UTXO snapshot at height %s (%s) to file %s (via %s)",
        tip->nHeight, tip->GetBlockHash().ToString(),
        fs::PathToString(path), fs::PathToString(temppath)));

    SnapshotMetadata metadata{chainstate.m_chainman.GetParams().MessageStart(), tip->GetBlockHash(), maybe_stats->coins_count};

    afile << metadata;

    COutPoint key;
    Txid last_hash;
    Coin coin;
    unsigned int iter{0};
    size_t written_coins_count{0};
    std::vector<std::pair<uint32_t, Coin>> coins;

    // To reduce space the serialization format of the snapshot avoids
    // duplication of tx hashes. The code takes advantage of the guarantee by
    // leveldb that keys are lexicographically sorted.
    // In the coins vector we collect all coins that belong to a certain tx hash
    // (key.hash) and when we have them all (key.hash != last_hash) we write
    // them to file using the below lambda function.
    // See also https://github.com/bitcoin/bitcoin/issues/25675
    auto write_coins_to_file = [&](AutoFile& afile, const Txid& last_hash, const std::vector<std::pair<uint32_t, Coin>>& coins, size_t& written_coins_count) {
        afile << last_hash;
        WriteCompactSize(afile, coins.size());
        for (const auto& [n, coin] : coins) {
            WriteCompactSize(afile, n);
            afile << coin;
            ++written_coins_count;
        }
    };

    pcursor->GetKey(key);
    last_hash = key.hash;
    while (pcursor->Valid()) {
        if (iter % 5000 == 0) interruption_point();
        ++iter;
        if (pcursor->GetKey(key) && pcursor->GetValue(coin)) {
            if (key.hash != last_hash) {
                write_coins_to_file(afile, last_hash, coins, written_coins_count);
                last_hash = key.hash;
                coins.clear();
            }
            coins.emplace_back(key.n, coin);
        }
        pcursor->Next();
    }

    if (!coins.empty()) {
        write_coins_to_file(afile, last_hash, coins, written_coins_count);
    }

    CHECK_NONFATAL(written_coins_count == maybe_stats->coins_count);

    if (afile.fclose() != 0) {
        throw std::ios_base::failure(
            strprintf("Error closing %s: %s", fs::PathToString(temppath), SysErrorString(errno)));
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("coins_written", written_coins_count);
    result.pushKV("base_hash", tip->GetBlockHash().ToString());
    result.pushKV("base_height", tip->nHeight);
    result.pushKV("path", path.utf8string());
    result.pushKV("txoutset_hash", maybe_stats->hashSerialized.ToString());
    result.pushKV("nchaintx", tip->m_chain_tx_count);
    return result;
}

UniValue CreateUTXOSnapshot(
    node::NodeContext& node,
    Chainstate& chainstate,
    AutoFile&& afile,
    const fs::path& path,
    const fs::path& tmppath)
{
    auto [cursor, stats, tip]{WITH_LOCK(::cs_main, return PrepareUTXOSnapshot(chainstate, node.rpc_interruption_point))};
    return WriteUTXOSnapshot(chainstate,
                             cursor.get(),
                             &stats,
                             tip,
                             std::move(afile),
                             path,
                             tmppath,
                             node.rpc_interruption_point);
}

static RPCHelpMan loadtxoutset()
{
    return RPCHelpMan{
        "loadtxoutset",
        "Load the serialized UTXO set from a file.\n"
        "Once this snapshot is loaded, its contents will be "
        "deserialized into a second chainstate data structure, which is then used to sync to "
        "the network's tip. "
        "Meanwhile, the original chainstate will complete the initial block download process in "
        "the background, eventually validating up to the block that the snapshot is based upon.\n\n"

        "The result is a usable bitcoind instance that is current with the network tip in a "
        "matter of minutes rather than hours. UTXO snapshot are typically obtained from "
        "third-party sources (HTTP, torrent, etc.) which is reasonable since their "
        "contents are always checked by hash.\n\n"

        "You can find more information on this process in the `assumeutxo` design "
        "document (<https://github.com/bitcoin/bitcoin/blob/master/doc/design/assumeutxo.md>).",
        {
            {"path",
                RPCArg::Type::STR,
                RPCArg::Optional::NO,
                "path to the snapshot file. If relative, will be prefixed by datadir."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::NUM, "coins_loaded", "the number of coins loaded from the snapshot"},
                    {RPCResult::Type::STR_HEX, "tip_hash", "the hash of the base of the snapshot"},
                    {RPCResult::Type::NUM, "base_height", "the height of the base of the snapshot"},
                    {RPCResult::Type::STR, "path", "the absolute path that the snapshot was loaded from"},
                }
        },
        RPCExamples{
            HelpExampleCli("-rpcclienttimeout=0 loadtxoutset", "utxo.dat")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    const fs::path path{AbsPathForConfigVal(EnsureArgsman(node), fs::u8path(self.Arg<std::string>("path")))};

    FILE* file{fsbridge::fopen(path, "rb")};
    AutoFile afile{file};
    if (afile.IsNull()) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "Couldn't open file " + path.utf8string() + " for reading.");
    }

    SnapshotMetadata metadata{chainman.GetParams().MessageStart()};
    try {
        afile >> metadata;
    } catch (const std::ios_base::failure& e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("Unable to parse metadata: %s", e.what()));
    }

    auto activation_result{chainman.ActivateSnapshot(afile, metadata, false)};
    if (!activation_result) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Unable to load UTXO snapshot: %s. (%s)", util::ErrorString(activation_result).original, path.utf8string()));
    }

    // Because we can't provide historical blocks during tip or background sync.
    // Update local services to reflect we are a limited peer until we are fully sync.
    node.connman->RemoveLocalServices(NODE_NETWORK);
    // Setting the limited state is usually redundant because the node can always
    // provide the last 288 blocks, but it doesn't hurt to set it.
    node.connman->AddLocalServices(NODE_NETWORK_LIMITED);

    if (chainman.m_blockman.m_ghost_exorcism.IsActive()) {
        LogInfo("[snapshot] Hazed mode: background IBD disabled, snapshot is sole chainstate");
    }

    CBlockIndex& snapshot_index{*CHECK_NONFATAL(*activation_result)};

    UniValue result(UniValue::VOBJ);
    result.pushKV("coins_loaded", metadata.m_coins_count);
    result.pushKV("tip_hash", snapshot_index.GetBlockHash().ToString());
    result.pushKV("base_height", snapshot_index.nHeight);
    result.pushKV("path", fs::PathToString(path));
    return result;
},
    };
}

static RPCHelpMan hazyncadoptsnapshot()
{
    return RPCHelpMan{
        "hazyncadoptsnapshot",
        "Adopt the UTXO set a verified Hazync proof commits to, and validate onward from there.\n\n"

        "This is `loadtxoutset` with the trust removed. Core's assumeutxo loads a snapshot at a "
        "height its developers compiled in, checked against a hash they chose; this loads one at the "
        "height a zk proof attests the chain was valid through, checked against the accumulator "
        "roots that proof commits to. No developer-chosen value takes part.\n\n"

        "Requires the node to have been started with -hazyncadopt, -hazyncproof and -hazyncutxo, and "
        "re-runs both checks now rather than relying on the startup verdict. The base block must "
        "already be in this node's headers chain, so call this once headers have synced past the "
        "proven height.\n\n"

        "Background validation is disabled on success: re-downloading and re-validating the chain "
        "below the proven height is precisely the work the proof replaces.",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::NUM, "coins_loaded", "the number of coins loaded from the proven set"},
                    {RPCResult::Type::STR_HEX, "tip_hash", "the base block of the adopted set"},
                    {RPCResult::Type::NUM, "base_height", "the height of that base block"},
                    {RPCResult::Type::STR_HEX, "guestid", "Hazync guest image id the proof was verified against"},
                }
        },
        RPCExamples{
            HelpExampleCli("-rpcclienttimeout=0 hazyncadoptsnapshot", "")
            + HelpExampleRpc("hazyncadoptsnapshot", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    const ArgsManager& args{EnsureArgsman(node)};

    // Re-derive the authority now. The startup verdict is a statement about files as they were at
    // startup; adoption is irreversible, so it is made on a fresh reading of them.
    std::string err;
    const auto authority{haze::HazyncAdoption::Authorise(args, err)};
    if (!authority) {
        throw JSONRPCError(RPC_MISC_ERROR, strprintf("Hazync adoption is not authorised: %s", err));
    }

    // Materialise the proven set in Core's own snapshot format. WriteCoreSnapshotFromDump is
    // reachable only for a dump that passed the roots check, which Authorise just re-ran.
    const fs::path snapshot_path{args.GetDataDirNet() / "hazync_snapshot.tmp"};
    if (!haze::WriteCoreSnapshotFromDump(fs::PathFromString(args.GetArg("-hazyncutxo", "")),
                                         snapshot_path, authority->base_blockhash, err)) {
        fs::remove(snapshot_path);
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Could not write the proven set as a snapshot: %s", err));
    }

    FILE* file{fsbridge::fopen(snapshot_path, "rb")};
    AutoFile afile{file};
    // Unlink immediately, keeping only the open descriptor. This closes the window between writing
    // the file and reading it in which something else could have put a different set at that path —
    // the coins loaded below are then, unavoidably, the ones just checked against the proof. It also
    // means the temporary cannot be left behind by an error return.
    fs::remove(snapshot_path);
    if (afile.IsNull()) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Could not reopen the snapshot that was just written.");
    }

    SnapshotMetadata metadata{chainman.GetParams().MessageStart()};
    try {
        afile >> metadata;
    } catch (const std::ios_base::failure& e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("Unable to parse metadata: %s", e.what()));
    }

    auto activation_result{chainman.ActivateSnapshot(afile, metadata, /*in_memory=*/false, &*authority)};
    if (!activation_result) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Unable to adopt the proven UTXO set: %s",
            util::ErrorString(activation_result).original));
    }

    // As for loadtxoutset: historical blocks below the base were never downloaded, so this node
    // cannot serve them and must stop advertising that it can.
    node.connman->RemoveLocalServices(NODE_NETWORK);
    node.connman->AddLocalServices(NODE_NETWORK_LIMITED);

    CBlockIndex& snapshot_index{*CHECK_NONFATAL(*activation_result)};

    LogInfo("[hazync] ADOPTED the proven UTXO set at height %d (%llu coins). Validation continues "
            "from height %d. Blocks below it were never downloaded and are not held by this node.\n",
            snapshot_index.nHeight, (unsigned long long)metadata.m_coins_count, snapshot_index.nHeight + 1);

    UniValue result(UniValue::VOBJ);
    result.pushKV("coins_loaded", metadata.m_coins_count);
    result.pushKV("tip_hash", snapshot_index.GetBlockHash().ToString());
    result.pushKV("base_height", snapshot_index.nHeight);
    result.pushKV("guestid", haze::HazyncMethodId());
    return result;
},
    };
}

static RPCHelpMan hazyncverifychain()
{
    return RPCHelpMan{
        "hazyncverifychain",
        "Establish, from this node's own stripped archive, that the chain it holds is the real chain "
        "and ends where its Hazync proof says it does.\n\n"

        "This is the half a proof cannot supply. A proof attests that the transactions in a range were "
        "VALID; it says nothing about whether this node holds that range. A hazed archive answers that "
        "and only that — stripping destroys witnesses and scriptSigs but keeps the txids, and a txid "
        "that had to be stored verbatim is not taken on trust, because the merkle root is recomputed "
        "from whatever txids the block yields and must match its header.\n\n"

        "Identity from the archive, validity from the proof. This is the join.\n\n"

        "REFUSES when the proof does not commit to the tip this node holds — a proof about some other "
        "chain must not be reported as evidence about this one.\n\n"

        "Requires -hazyncproof. Reads every block in the range from disk, so it is slow over a long "
        "one; use -rpcclienttimeout=0.",
        {
            {"from_height", RPCArg::Type::NUM, RPCArg::Default{1},
             "First height to check. 1 establishes the whole chain. A higher value checks only a "
             "suffix, which is cheaper and proves correspondingly less."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::BOOL, "bound", "whether the archive is bound to the proof"},
                    {RPCResult::Type::NUM, "from_height", "first height checked"},
                    {RPCResult::Type::NUM, "through_height", "last height checked, always the proven height"},
                    {RPCResult::Type::NUM, "blocks_checked", "how many blocks were read and recomputed"},
                    {RPCResult::Type::BOOL, "complete", "true only if checked from height 1, i.e. the whole chain rather than a suffix"},
                    {RPCResult::Type::STR_HEX, "archive_tip", "tip the archive itself yields at the proven height"},
                    {RPCResult::Type::STR_HEX, "proven_tip", "tip the proof commits to"},
                    {RPCResult::Type::STR, "failure", /*optional=*/true, "why the binding does not hold, if it does not"},
                }
        },
        RPCExamples{
            HelpExampleCli("-rpcclienttimeout=0 hazyncverifychain", "")
            + HelpExampleRpc("hazyncverifychain", "1")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);

    const auto& proven{haze::HazyncVerifiedProof()};
    if (!proven) {
        throw JSONRPCError(RPC_MISC_ERROR,
            "no verified Hazync proof — start with -hazyncproof=<file>. Without one there is nothing "
            "to bind the archive to.");
    }

    const int from_height{self.Arg<int>("from_height")};

    haze::HazedChainBinding result;
    const bool bound{haze::VerifyHazedChainBinding(chainman, *proven, from_height, result)};

    if (bound) {
        LogInfo("[hazync] archive BOUND to proof: %d blocks checked through height %d%s\n",
                result.blocks_checked, result.through_height,
                result.complete ? ", from genesis" : " (suffix only)");
    } else {
        LogWarning("[hazync] archive NOT bound to proof: %s\n", result.failure);
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("bound", bound);
    obj.pushKV("from_height", result.from_height);
    obj.pushKV("through_height", result.through_height);
    obj.pushKV("blocks_checked", result.blocks_checked);
    obj.pushKV("complete", result.complete);
    obj.pushKV("archive_tip", result.archive_tip.GetHex());
    obj.pushKV("proven_tip", proven->tip_hash.GetHex());
    if (!bound) obj.pushKV("failure", result.failure);
    return obj;
},
    };
}

const std::vector<RPCResult> RPCHelpForChainstate{
    {RPCResult::Type::NUM, "blocks", "number of blocks in this chainstate"},
    {RPCResult::Type::STR_HEX, "bestblockhash", "blockhash of the tip"},
    {RPCResult::Type::STR_HEX, "bits", "nBits: compact representation of the block difficulty target"},
    {RPCResult::Type::STR_HEX, "target", "The difficulty target"},
    {RPCResult::Type::NUM, "difficulty", "difficulty of the tip"},
    {RPCResult::Type::NUM, "verificationprogress", "progress towards the network tip"},
    {RPCResult::Type::STR_HEX, "snapshot_blockhash", /*optional=*/true, "the base block of the snapshot this chainstate is based on, if any"},
    {RPCResult::Type::NUM, "coins_db_cache_bytes", "size of the coinsdb cache"},
    {RPCResult::Type::NUM, "coins_tip_cache_bytes", "size of the coinstip cache"},
    {RPCResult::Type::BOOL, "validated", "whether the chainstate is fully validated. True if all blocks in the chainstate were validated, false if the chain is based on a snapshot and the snapshot has not yet been validated."},
};

static RPCHelpMan getchainstates()
{
return RPCHelpMan{
        "getchainstates",
        "Return information about chainstates.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::NUM, "headers", "the number of headers seen so far"},
                {RPCResult::Type::ARR, "chainstates", "list of the chainstates ordered by work, with the most-work (active) chainstate last", {{RPCResult::Type::OBJ, "", "", RPCHelpForChainstate},}},
            }
        },
        RPCExamples{
            HelpExampleCli("getchainstates", "")
    + HelpExampleRpc("getchainstates", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    LOCK(cs_main);
    UniValue obj(UniValue::VOBJ);

    ChainstateManager& chainman = EnsureAnyChainman(request.context);

    auto make_chain_data = [&](const Chainstate& cs, bool validated) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        AssertLockHeld(::cs_main);
        UniValue data(UniValue::VOBJ);
        if (!cs.m_chain.Tip()) {
            return data;
        }
        const CChain& chain = cs.m_chain;
        const CBlockIndex* tip = chain.Tip();

        data.pushKV("blocks",                (int)chain.Height());
        data.pushKV("bestblockhash",         tip->GetBlockHash().GetHex());
        data.pushKV("bits", strprintf("%08x", tip->nBits));
        data.pushKV("target", GetTarget(*tip, chainman.GetConsensus().powLimit).GetHex());
        data.pushKV("difficulty", GetDifficulty(*tip));
        data.pushKV("verificationprogress", chainman.GuessVerificationProgress(tip));
        data.pushKV("coins_db_cache_bytes",  cs.m_coinsdb_cache_size_bytes);
        data.pushKV("coins_tip_cache_bytes", cs.m_coinstip_cache_size_bytes);
        if (cs.m_from_snapshot_blockhash) {
            data.pushKV("snapshot_blockhash", cs.m_from_snapshot_blockhash->ToString());
        }
        data.pushKV("validated", validated);
        return data;
    };

    obj.pushKV("headers", chainman.m_best_header ? chainman.m_best_header->nHeight : -1);

    const auto& chainstates = chainman.GetAll();
    UniValue obj_chainstates{UniValue::VARR};
    for (Chainstate* cs : chainstates) {
      obj_chainstates.push_back(make_chain_data(*cs, !cs->m_from_snapshot_blockhash || chainstates.size() == 1));
    }
    obj.pushKV("chainstates", std::move(obj_chainstates));
    return obj;
}
    };
}


static RPCHelpMan generatecheckpoint()
{
    return RPCHelpMan{
        "generatecheckpoint",
        "Generate a full checkpoint at the specified height.\n"
        "Creates headers.bin, UTXO chunk files, bloom.bin, and manifest.bin in the output directory.\n"
        "If a secret key is provided, the manifest is signed before writing.\n"
        "This is a long-running operation that locks the UTXO set.\n",
        {
            {"height", RPCArg::Type::NUM, RPCArg::Optional::NO, "The block height to checkpoint at."},
            {"output_dir", RPCArg::Type::STR, RPCArg::Optional::NO, "Directory to write checkpoint files."},
            {"secret_key", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Ed25519 secret key (hex) to sign the manifest."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "height", "checkpoint height"},
                {RPCResult::Type::STR_HEX, "block_hash", "block hash at checkpoint height"},
                {RPCResult::Type::NUM, "utxo_count", "number of UTXOs in the set"},
                {RPCResult::Type::STR_HEX, "utxo_hash", "hash of the UTXO set"},
                {RPCResult::Type::NUM, "total_chunks", "number of UTXO chunk files"},
                {RPCResult::Type::STR_HEX, "bloom_hash", "SHA-256 of bloom.bin"},
                {RPCResult::Type::STR_HEX, "headers_hash", "SHA-256 of headers.bin"},
                {RPCResult::Type::BOOL, "signed", "whether the manifest was signed"},
                {RPCResult::Type::OBJ, "manifest", "full manifest details",
                    {
                        {RPCResult::Type::ELISION, "", ""},
                    }
                },
            }
        },
        RPCExamples{
            HelpExampleCli("generatecheckpoint", "160 /tmp/checkpoint")
            + HelpExampleCli("generatecheckpoint", "160 /tmp/checkpoint abc123...")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);

    const int height = self.Arg<int>("height");
    const std::string output_dir = self.Arg<std::string>("output_dir");

    if (height < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Height must be non-negative");
    }

    haze::CheckpointManifest manifest;
    std::unique_ptr<CCoinsViewCursor> chunk_cursor;
    std::unique_ptr<CCoinsViewCursor> bloom_cursor;

    {
        // Hold cs_main briefly to validate chain, generate headers, flush
        // coins to disk, compute UTXO stats, and create leveldb cursors.
        // Cursors are snapshot-based and remain valid after lock release.
        LOCK(cs_main);

        Chainstate& chainstate = chainman.ActiveChainstate();
        const CChain& chain = chainstate.m_chain;

        if (chain.Height() < height) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("Chain height %d < requested checkpoint height %d", chain.Height(), height));
        }

        // Step 1: Generate headers.bin + manifest skeleton
        if (!haze::GenerateCheckpoint(chain, chainman.m_blockman, height, output_dir, manifest)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to generate checkpoint headers");
        }

        // Step 2: Flush coins and prepare cursors (must be done under cs_main)
        chainstate.ForceFlushStateToDisk();

        auto maybe_stats = GetUTXOStats(&chainstate.CoinsDB(), chainstate.m_blockman,
                                         CoinStatsHashType::HASH_SERIALIZED,
                                         node.rpc_interruption_point);
        if (!maybe_stats) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read UTXO set");
        }

        manifest.utxo_count = maybe_stats->coins_count;
        manifest.utxo_hash = maybe_stats->hashSerialized;

        chunk_cursor = chainstate.CoinsDB().Cursor();
        bloom_cursor = chainstate.CoinsDB().Cursor();
    }
    // cs_main released — slow I/O happens without holding the lock.

    // Step 3: Generate UTXO chunks (no lock needed — cursor is a leveldb snapshot)
    if (!haze::GenerateUTXOChunks(*chunk_cursor, manifest.utxo_count, manifest.utxo_hash,
                                   output_dir, haze::DEFAULT_CHUNK_SIZE, manifest,
                                   node.rpc_interruption_point)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to generate UTXO chunks");
    }

    // Step 4: Generate bloom filter (no lock needed)
    if (!haze::GenerateBloomFilter(*bloom_cursor, output_dir, manifest,
                                    node.rpc_interruption_point)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to generate bloom filter");
    }

    // Step 5: Optionally sign the manifest
    bool was_signed = false;
    if (!request.params[2].isNull()) {
        const std::string secret_key_hex = request.params[2].get_str();
        auto parsed = TryParseHex<uint8_t>(secret_key_hex);
        if (!parsed || parsed->size() != 32) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Secret key must be exactly 32 bytes (64 hex characters)");
        }
        haze::Ed25519SecKey secret_key;
        std::copy(parsed->begin(), parsed->end(), secret_key.begin());
        if (!haze::SignCheckpoint(manifest, secret_key)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to sign checkpoint manifest");
        }
        was_signed = true;
    }

    // Step 6: Re-serialize manifest with all hashes populated
    const std::string manifest_path = output_dir + "/manifest.bin";
    DataStream ss;
    ss << manifest;

    std::ofstream manifest_file(manifest_path, std::ios::binary | std::ios::trunc);
    if (!manifest_file.is_open()) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Cannot write final manifest.bin");
    }
    manifest_file.write(reinterpret_cast<const char*>(ss.data()), ss.size());
    manifest_file.flush();
    manifest_file.close();

    // Return summary + full manifest JSON
    UniValue result(UniValue::VOBJ);
    result.pushKV("height", manifest.height);
    result.pushKV("block_hash", manifest.block_hash.GetHex());
    result.pushKV("utxo_count", static_cast<int64_t>(manifest.utxo_count));
    result.pushKV("utxo_hash", manifest.utxo_hash.GetHex());
    result.pushKV("total_chunks", static_cast<int>(manifest.chunk_manifest.total_chunks));
    result.pushKV("bloom_hash", manifest.bloom_hash.GetHex());
    result.pushKV("headers_hash", manifest.headers_hash.GetHex());
    result.pushKV("signed", was_signed);
    result.pushKV("manifest", manifest.ToJSON());
    return result;
},
    };
}

static RPCHelpMan downloadcheckpoint()
{
    return RPCHelpMan{
        "downloadcheckpoint",
        "Initiate checkpoint download from a specific peer.\n"
        "Sends a getchkpt message to the peer, which will respond with a checkpoint manifest.\n"
        "Download progress is visible in debug.log.\n",
        {
            {"peer_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "The peer ID to request the checkpoint from."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "requested", "whether the request was sent successfully"},
                {RPCResult::Type::NUM, "peer_id", "the peer ID the request was sent to"},
            }
        },
        RPCExamples{
            HelpExampleCli("downloadcheckpoint", "0")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    CConnman& connman = EnsureConnman(node);

    const NodeId peer_id = self.Arg<int>("peer_id");

    bool sent = connman.ForNode(peer_id, [&](CNode* pnode) {
        connman.PushMessage(pnode, NetMsg::Make(NetMsgType::GETCHECKPOINT, static_cast<int32_t>(-1)));
        return true;
    });

    UniValue result(UniValue::VOBJ);
    result.pushKV("requested", sent);
    result.pushKV("peer_id", peer_id);
    return result;
},
    };
}

void RegisterBlockchainRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"blockchain", &getblockchaininfo},
        {"blockchain", &getchaintxstats},
        {"blockchain", &getblockstats},
        {"blockchain", &getbestblockhash},
        {"blockchain", &getblockcount},
        {"blockchain", &getblock},
        {"blockchain", &getblockfrompeer},
        {"blockchain", &getblockhash},
        {"blockchain", &getblockheader},
        {"blockchain", &getchaintips},
        {"blockchain", &getdifficulty},
        {"blockchain", &getdeploymentinfo},
        {"blockchain", &gettxout},
        {"blockchain", &gettxoutsetinfo},
        {"blockchain", &pruneblockchain},
        {"blockchain", &verifychain},
        {"blockchain", &preciousblock},
        {"blockchain", &scantxoutset},
        {"blockchain", &scanblocks},
        {"blockchain", &getdescriptoractivity},
        {"blockchain", &getblockfilter},
        {"blockchain", &dumptxoutset},
        {"blockchain", &loadtxoutset},
        {"blockchain", &hazyncadoptsnapshot},
        {"blockchain", &hazyncverifychain},
        {"blockchain", &getchainstates},
        {"blockchain", &generatecheckpoint},
        {"blockchain", &downloadcheckpoint},
        {"hidden", &invalidateblock},
        {"hidden", &reconsiderblock},
        {"blockchain", &waitfornewblock},
        {"blockchain", &waitforblock},
        {"blockchain", &waitforblockheight},
        {"hidden", &syncwithvalidationinterfacequeue},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}

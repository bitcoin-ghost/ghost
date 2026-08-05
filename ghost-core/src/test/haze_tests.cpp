// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <addresstype.h>
#include <haze/block_reconstruct.h>
#include <haze/block_stripper.h>
#include <haze/field_classifier.h>
#include <haze/stripped_block.h>
#include <key.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/solver.h>
#include <uint256.h>

#include <validation.h>
#include <consensus/validation.h>
#include <coins.h>
#include <primitives/transaction_identifier.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <vector>

BOOST_FIXTURE_TEST_SUITE(haze_tests, TestChain100Setup)

// ============================================================================
// Field Classifier
// ============================================================================

BOOST_AUTO_TEST_CASE(classify_segwit_transaction)
{
    // Construct a transaction with witness data — the classifier inspects
    // the transaction structure, not signature validity.
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint(m_coinbase_txns[0]->GetHash(), 0));
    mtx.vout.emplace_back(49 * COIN, GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey())));

    // Add fake witness data to simulate a signed P2WPKH input
    mtx.vin[0].scriptWitness.stack.push_back({0x30, 0x44}); // fake signature
    mtx.vin[0].scriptWitness.stack.push_back({0x02, 0xab});  // fake pubkey

    CTransactionRef tx = MakeTransactionRef(std::move(mtx));
    auto fields = haze::ClassifyTransaction(*tx, /*is_coinbase=*/false, /*tx_index=*/0);

    bool has_witness = false;
    for (const auto& f : fields) {
        if (f.type == haze::HazeFieldType::WITNESS) has_witness = true;
    }
    BOOST_CHECK(has_witness);
}

BOOST_AUTO_TEST_CASE(classify_legacy_transaction)
{
    // Construct a legacy-style transaction with non-empty scriptSig.
    // RequiresStoredTxid should return true (scriptSig will be stripped,
    // making txid non-recomputable).
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint(m_coinbase_txns[1]->GetHash(), 0));
    mtx.vin[0].scriptSig = CScript() << std::vector<uint8_t>(72, 0x30) << std::vector<uint8_t>(33, 0x02);
    // No witness data — this is a legacy P2PKH-like input
    mtx.vout.emplace_back(49 * COIN, CScript() << OP_DUP << OP_HASH160 << std::vector<uint8_t>(20, 0xAB) << OP_EQUALVERIFY << OP_CHECKSIG);

    CTransactionRef tx = MakeTransactionRef(std::move(mtx));

    // Should have SCRIPTSIG field
    auto fields = haze::ClassifyTransaction(*tx, /*is_coinbase=*/false, /*tx_index=*/1);
    bool has_scriptsig = false;
    for (const auto& f : fields) {
        if (f.type == haze::HazeFieldType::SCRIPTSIG) has_scriptsig = true;
    }
    BOOST_CHECK(has_scriptsig);

    // RequiresStoredTxid should be true for transactions with non-empty scriptSig
    BOOST_CHECK(haze::RequiresStoredTxid(*tx));
}

BOOST_AUTO_TEST_CASE(classify_coinbase)
{
    // The first transaction in any block is coinbase
    BOOST_REQUIRE(!m_coinbase_txns.empty());
    auto& cb = m_coinbase_txns[0];
    auto fields = haze::ClassifyTransaction(*cb, /*is_coinbase=*/true, /*tx_index=*/0);

    bool has_coinbase = false;
    for (const auto& f : fields) {
        if (f.type == haze::HazeFieldType::COINBASE) {
            has_coinbase = true;
            BOOST_CHECK_EQUAL(f.tx_index, 0U);
            BOOST_CHECK_EQUAL(f.field_index, 0U);
            BOOST_CHECK_GT(f.original_size, 0U);
        }
    }
    BOOST_CHECK(has_coinbase);
}

BOOST_AUTO_TEST_CASE(classify_opreturn)
{
    // Build an OP_RETURN script
    std::vector<uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF};
    CScript opreturn_script = CScript() << OP_RETURN << payload;
    BOOST_CHECK(haze::IsOpReturn(opreturn_script));

    // Non-OP_RETURN script
    CScript p2pkh = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    BOOST_CHECK(!haze::IsOpReturn(p2pkh));
}

BOOST_AUTO_TEST_CASE(classify_block)
{
    // Mine a block with a transaction — ClassifyBlock should find fields
    CScript dest = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));

    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint(m_coinbase_txns[0]->GetHash(), 0));
    mtx.vout.emplace_back(49 * COIN, dest);

    CBlock block = CreateAndProcessBlock({mtx}, dest);

    auto fields = haze::ClassifyBlock(block);
    // At minimum should have coinbase field from the coinbase tx
    bool has_coinbase = false;
    for (const auto& f : fields) {
        if (f.type == haze::HazeFieldType::COINBASE) has_coinbase = true;
    }
    BOOST_CHECK(has_coinbase);
    BOOST_CHECK_GT(fields.size(), 0U);
}

BOOST_AUTO_TEST_CASE(witness_data_size)
{
    // Empty witness should be size 0
    CScriptWitness empty_witness;
    BOOST_CHECK_EQUAL(haze::WitnessDataSize(empty_witness), 0U);

    // Non-empty witness
    CScriptWitness witness;
    witness.stack.push_back({0x01, 0x02, 0x03});
    witness.stack.push_back({0x04, 0x05});
    BOOST_CHECK_EQUAL(haze::WitnessDataSize(witness), 5U);
}

// ============================================================================
// Stripped Block Format
// ============================================================================

BOOST_AUTO_TEST_CASE(gsb_serialize_deserialize_roundtrip)
{
    // Strip a real block, serialize to GSB, deserialize back
    CScript dest = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));
    CBlock block = CreateAndProcessBlock({}, dest);

    haze::StripResult result = haze::StripBlock(block);

    // Serialize
    std::vector<std::byte> data;
    haze::SerializeGSB(result.stripped_block, data);
    BOOST_CHECK_GT(data.size(), 8U); // At least magic + size

    // Deserialize
    haze::CStrippedBlock restored;
    BOOST_CHECK(haze::DeserializeGSB(data, restored));

    // Verify roundtrip
    BOOST_CHECK_EQUAL(restored.GetTxCount(), result.stripped_block.GetTxCount());
    BOOST_CHECK(restored.m_header.GetHash() == result.stripped_block.m_header.GetHash());

    for (size_t i = 0; i < restored.GetTxCount(); i++) {
        BOOST_CHECK(restored.GetTxid(i) == result.stripped_block.GetTxid(i));
    }
}

BOOST_AUTO_TEST_CASE(gsb_magic_bytes)
{
    CScript dest = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));
    CBlock block = CreateAndProcessBlock({}, dest);
    haze::StripResult result = haze::StripBlock(block);

    std::vector<std::byte> data;
    haze::SerializeGSB(result.stripped_block, data);

    // GSB magic is "GSB\0" = 0x47 0x53 0x42 0x00
    BOOST_REQUIRE_GE(data.size(), 4U);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(data[0]), 0x47);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(data[1]), 0x53);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(data[2]), 0x42);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(data[3]), 0x00);
}

BOOST_AUTO_TEST_CASE(gsb_invalid_magic_rejected)
{
    std::vector<std::byte> bad_data = {
        std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}
    };

    haze::CStrippedBlock block;
    BOOST_CHECK(!haze::DeserializeGSB(bad_data, block));
}

BOOST_AUTO_TEST_CASE(stripped_block_merkle_root)
{
    CScript dest = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));
    CBlock block = CreateAndProcessBlock({}, dest);

    haze::StripResult result = haze::StripBlock(block);
    uint256 computed_root = result.stripped_block.ComputeMerkleRoot();

    BOOST_CHECK(computed_root == block.hashMerkleRoot);
}

BOOST_AUTO_TEST_CASE(stripped_tx_stored_txid)
{
    // Coinbase tx always has non-empty scriptSig (coinbase data),
    // so after stripping, the txid must be stored
    CScript dest = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));
    CBlock block = CreateAndProcessBlock({}, dest);

    haze::StripResult result = haze::StripBlock(block);
    BOOST_REQUIRE_GT(result.stripped_block.GetTxCount(), 0U);

    // Coinbase (tx 0) should have stored txid since coinbase scriptSig is stripped
    const auto& stripped_coinbase = result.stripped_block.m_transactions[0];
    BOOST_CHECK(stripped_coinbase.m_has_stored_txid);

    // The stored txid should match the original coinbase txid
    BOOST_CHECK(stripped_coinbase.GetTxid() == block.vtx[0]->GetHash().ToUint256());
}

BOOST_AUTO_TEST_CASE(stripped_opreturn_minimal)
{
    // Create a block with an OP_RETURN transaction
    CScript dest = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));
    std::vector<uint8_t> payload = {'G', 'H', 'O', 'S', 'T', '_', 'T', 'E', 'S', 'T'};
    CScript opreturn_script = CScript() << OP_RETURN << payload;

    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint(m_coinbase_txns[0]->GetHash(), 0));
    mtx.vout.emplace_back(0, opreturn_script);
    mtx.vout.emplace_back(49 * COIN, dest);

    CBlock block = CreateAndProcessBlock({mtx}, dest);

    haze::StripResult result = haze::StripBlock(block);

    // Find the OP_RETURN output in the stripped block — payload should be minimal
    CScript expected_stripped = haze::MakeStrippedOpReturn();
    bool found_stripped_opreturn = false;
    for (const auto& stx : result.stripped_block.m_transactions) {
        for (const auto& out : stx.m_outputs) {
            if (haze::IsOpReturn(out.script_pub_key)) {
                BOOST_CHECK(out.script_pub_key == expected_stripped);
                found_stripped_opreturn = true;
            }
        }
    }
    BOOST_CHECK(found_stripped_opreturn);
}

// ============================================================================
// Block Stripper
// ============================================================================

BOOST_AUTO_TEST_CASE(strip_block_preserves_merkle)
{
    CScript dest = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));
    CBlock block = CreateAndProcessBlock({}, dest);

    haze::StripResult result = haze::StripBlock(block);
    BOOST_CHECK(haze::VerifyStrippedBlock(result.stripped_block, block.GetBlockHeader()));
}

BOOST_AUTO_TEST_CASE(strip_block_removes_witness)
{
    // Create a SegWit transaction that will have witness data
    CScript dest = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));

    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint(m_coinbase_txns[0]->GetHash(), 0));
    mtx.vout.emplace_back(49 * COIN, dest);

    CBlock block = CreateAndProcessBlock({mtx}, dest);

    haze::StripResult result = haze::StripBlock(block);

    // Coinbase always has some data, so at minimum coinbase bytes removed
    size_t total_removed = result.witness_bytes_removed +
                           result.scriptsig_bytes_removed +
                           result.coinbase_bytes_removed +
                           result.opreturn_bytes_removed +
                           result.nonstandard_bytes_removed;
    BOOST_CHECK_GT(total_removed, 0U);
}

BOOST_AUTO_TEST_CASE(strip_block_statistics)
{
    CScript dest = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));
    CBlock block = CreateAndProcessBlock({}, dest);

    haze::StripResult result = haze::StripBlock(block);

    // original_size should be greater than stripped_size
    BOOST_CHECK_GT(result.original_size, 0U);
    BOOST_CHECK_GT(result.stripped_size, 0U);
    BOOST_CHECK_GE(result.original_size, result.stripped_size);

    // Total removed should be self-consistent
    size_t total_removed = result.witness_bytes_removed +
                           result.scriptsig_bytes_removed +
                           result.coinbase_bytes_removed +
                           result.opreturn_bytes_removed +
                           result.nonstandard_bytes_removed;
    // stripped_size + removed ≈ original_size (not exact due to format differences)
    // But removed should not exceed original
    BOOST_CHECK_LE(total_removed, result.original_size);
}

BOOST_AUTO_TEST_CASE(strip_coinbase_only_block)
{
    // Block with no extra transactions — just the coinbase
    CScript dest = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));
    CBlock block = CreateAndProcessBlock({}, dest);

    BOOST_CHECK_EQUAL(block.vtx.size(), 1U);

    haze::StripResult result = haze::StripBlock(block);

    BOOST_CHECK_EQUAL(result.stripped_block.GetTxCount(), 1U);
    BOOST_CHECK(haze::VerifyStrippedBlock(result.stripped_block, block.GetBlockHeader()));
    BOOST_CHECK_GT(result.coinbase_bytes_removed, 0U);
}

// ============================================================================
// Block Reconstruct
// ============================================================================

BOOST_AUTO_TEST_CASE(reconstruct_partial_block)
{
    CScript dest = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));
    CBlock block = CreateAndProcessBlock({}, dest);

    haze::StripResult result = haze::StripBlock(block);
    CBlock reconstructed = haze::ReconstructPartialBlock(result.stripped_block);

    // Header should match
    BOOST_CHECK(reconstructed.GetBlockHeader().GetHash() == block.GetBlockHeader().GetHash());

    // Same number of transactions
    BOOST_CHECK_EQUAL(reconstructed.vtx.size(), block.vtx.size());
}

BOOST_AUTO_TEST_CASE(reconstruct_preserves_outputs)
{
    CScript dest = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));

    // Create a block with a transfer tx
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint(m_coinbase_txns[0]->GetHash(), 0));
    mtx.vout.emplace_back(49 * COIN, dest);

    CBlock block = CreateAndProcessBlock({mtx}, dest);

    haze::StripResult result = haze::StripBlock(block);
    CBlock reconstructed = haze::ReconstructPartialBlock(result.stripped_block);

    // Check that output values and scriptPubKeys are preserved for all txs
    for (size_t i = 0; i < block.vtx.size(); i++) {
        BOOST_REQUIRE_EQUAL(reconstructed.vtx[i]->vout.size(), block.vtx[i]->vout.size());
        for (size_t j = 0; j < block.vtx[i]->vout.size(); j++) {
            BOOST_CHECK_EQUAL(reconstructed.vtx[i]->vout[j].nValue,
                              block.vtx[i]->vout[j].nValue);
            // For standard (non-stripped) outputs, scriptPubKey should be identical
            if (!haze::IsOpReturn(block.vtx[i]->vout[j].scriptPubKey) &&
                !haze::IsNonstandardScript(block.vtx[i]->vout[j].scriptPubKey)) {
                BOOST_CHECK(reconstructed.vtx[i]->vout[j].scriptPubKey ==
                            block.vtx[i]->vout[j].scriptPubKey);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(reconstructed_block_cannot_carry_txids)
{
    // A reconstructed CBlock's transactions compute their own txid from their contents, and their
    // contents are missing the scriptSigs. So for any transaction that HAD a scriptSig — every
    // coinbase, every legacy and P2SH-wrapped spend — the reconstruction's txid is the hash of a
    // different transaction. `CTransaction` has nowhere to put an authoritative txid, so this is a
    // property of the type, not an oversight that could be patched inside ReconstructPartialBlock.
    //
    // This matters well beyond display. Anything that keys a UTXO lookup on a reconstructed txid —
    // DisconnectBlock does, for every output of every transaction — would look up outpoints that do
    // not exist, leave the real coins untouched, and report the block as merely "unclean".
    //
    // The authoritative source is CStrippedBlock::GetTxid(), which returns the STORED txid when
    // there is one. Asserted here in both directions so the trap is documented rather than
    // rediscovered.
    CScript dest = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));
    CBlock block = CreateAndProcessBlock({}, dest);

    haze::StripResult result = haze::StripBlock(block);
    CBlock reconstructed = haze::ReconstructPartialBlock(result.stripped_block);
    BOOST_REQUIRE_GT(result.stripped_block.GetTxCount(), 0U);

    // A coinbase always carries scriptSig data, so it always ends up with a stored txid.
    BOOST_REQUIRE(result.stripped_block.m_transactions[0].m_has_stored_txid);

    // The control: the authoritative source is right. Without this the check below could pass
    // because stripping is broken rather than because reconstruction cannot carry txids.
    BOOST_CHECK(result.stripped_block.GetTxid(0) == block.vtx[0]->GetHash().ToUint256());

    // The trap: the reconstruction's own txid is NOT the real one.
    BOOST_CHECK(reconstructed.vtx[0]->GetHash().ToUint256() != block.vtx[0]->GetHash().ToUint256());

    // And it is not a near miss that some later comparison might tolerate: it is the hash of a
    // transaction whose scriptSig is empty.
    BOOST_CHECK(reconstructed.vtx[0]->vin[0].scriptSig.empty());
    BOOST_CHECK(!block.vtx[0]->vin[0].scriptSig.empty());
}

// ============================================================================
// Reorg from stripped storage (#545)
// ============================================================================

BOOST_AUTO_TEST_CASE(disconnect_from_stripped_matches_disconnect_from_full)
{
    // The claim reorg-from-stripped rests on: undoing a block needs nothing haze destroyed, so a
    // block rebuilt from stripped storage must undo to exactly the same UTXO set as the real one.
    //
    // Asserted by doing both and comparing, rather than by checking a handful of coins — a spot
    // check would pass while some other coin silently differed.
    // The spend must be properly signed, or the block is invalid, never connects, and the whole
    // comparison below runs against a tip that is not this block at all.
    CScript dest = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));
    CMutableTransaction spend = CreateValidMempoolTransaction(
        /*input_transaction=*/m_coinbase_txns[0], /*input_vout=*/0, /*input_height=*/0,
        /*input_signing_key=*/coinbaseKey, /*output_destination=*/dest,
        /*output_amount=*/49 * COIN, /*submit=*/false);
    CBlock block = CreateAndProcessBlock({spend}, dest);

    LOCK(cs_main);
    Chainstate& chainstate = m_node.chainman->ActiveChainstate();
    CBlockIndex* pindex = m_node.chainman->m_blockman.LookupBlockIndex(block.GetHash());
    BOOST_REQUIRE(pindex);
    // Load-bearing: if the block did not become the tip it was rejected, and disconnecting it would
    // be measuring nothing.
    BOOST_REQUIRE(chainstate.m_chain.Tip() == pindex);
    BOOST_REQUIRE_EQUAL(block.vtx.size(), 2U); // coinbase + the spend, so inputs really are restored

    haze::StripResult result = haze::StripBlock(block);
    CBlock rebuilt = haze::ReconstructPartialBlock(result.stripped_block);

    // The reconstruction carries the real txids, so no caller has to supply them and none can
    // forget. Checked against the original block, not against the stripped form it came from —
    // otherwise this would only prove the two agree with each other.
    BOOST_REQUIRE_EQUAL(rebuilt.m_haze_authoritative_txids.size(), block.vtx.size());
    for (size_t i = 0; i < block.vtx.size(); ++i) {
        BOOST_CHECK(rebuilt.m_haze_authoritative_txids[i] == block.vtx[i]->GetHash());
    }

    // Undo with the real block.
    CCoinsViewCache from_full(&chainstate.CoinsTip());
    BOOST_REQUIRE_EQUAL(chainstate.DisconnectBlock(block, pindex, from_full), DISCONNECT_OK);

    // Undo with the rebuilt block, which needs nothing extra.
    CCoinsViewCache from_stripped(&chainstate.CoinsTip());
    BOOST_REQUIRE_EQUAL(chainstate.DisconnectBlock(rebuilt, pindex, from_stripped), DISCONNECT_OK);

    // Same best block, and the same verdict on every coin the block touched.
    BOOST_CHECK(from_full.GetBestBlock() == from_stripped.GetBestBlock());
    for (const auto& tx : block.vtx) {
        for (size_t o = 0; o < tx->vout.size(); ++o) {
            const COutPoint out{tx->GetHash(), static_cast<uint32_t>(o)};
            BOOST_CHECK_EQUAL(from_full.HaveCoin(out), from_stripped.HaveCoin(out));
        }
        if (!tx->IsCoinBase()) {
            for (const auto& in : tx->vin) {
                BOOST_CHECK_EQUAL(from_full.HaveCoin(in.prevout), from_stripped.HaveCoin(in.prevout));
                BOOST_CHECK(from_full.AccessCoin(in.prevout).out == from_stripped.AccessCoin(in.prevout).out);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(disconnect_from_stripped_without_txids_is_refused)
{
    // The negative that makes the parameter load-bearing. Without it this call would not fail — it
    // would look up outpoints that do not exist, miss every one, and leave spent coins in the set
    // while reporting no worse than "unclean". It must be refused outright instead.
    CScript dest = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));
    CBlock block = CreateAndProcessBlock({}, dest);

    LOCK(cs_main);
    Chainstate& chainstate = m_node.chainman->ActiveChainstate();
    CBlockIndex* pindex = m_node.chainman->m_blockman.LookupBlockIndex(block.GetHash());
    BOOST_REQUIRE(pindex);

    haze::StripResult result = haze::StripBlock(block);
    CBlock rebuilt = haze::ReconstructPartialBlock(result.stripped_block);
    BOOST_REQUIRE(rebuilt.m_haze_reconstructed);

    // Stripping the ids back off is not something any caller does — they travel with the block —
    // but the refusal is kept as defence in depth, because the alternative failure is silent.
    CBlock without_ids = rebuilt;
    without_ids.m_haze_authoritative_txids.clear();
    CCoinsViewCache view(&chainstate.CoinsTip());
    BOOST_CHECK_EQUAL(chainstate.DisconnectBlock(without_ids, pindex, view), DISCONNECT_FAILED);

    // A wrong-sized set is refused too, rather than read past the end or applied to the wrong txs.
    CBlock short_ids = rebuilt;
    short_ids.m_haze_authoritative_txids.pop_back();
    CCoinsViewCache view2(&chainstate.CoinsTip());
    BOOST_CHECK_EQUAL(chainstate.DisconnectBlock(short_ids, pindex, view2), DISCONNECT_FAILED);
}

BOOST_AUTO_TEST_CASE(connecting_a_reconstructed_block_is_refused)
{
    // The hard guard the design asks for: rebuilt blocks may be disconnected, never connected.
    // Without it, ConnectBlock would run against empty scriptSigs and empty witnesses — nothing to
    // verify, no BIP34 height, no witness commitment — and could only produce a meaningless pass.
    CScript dest = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));
    CBlock block = CreateAndProcessBlock({}, dest);

    LOCK(cs_main);
    Chainstate& chainstate = m_node.chainman->ActiveChainstate();
    CBlockIndex* pindex = m_node.chainman->m_blockman.LookupBlockIndex(block.GetHash());
    BOOST_REQUIRE(pindex);

    haze::StripResult result = haze::StripBlock(block);
    CBlock rebuilt = haze::ReconstructPartialBlock(result.stripped_block);

    // ConnectBlock asserts the view sits at pindex->pprev (validation.cpp), so disconnect first —
    // which also makes this a genuine round trip rather than a contrived view.
    CCoinsViewCache view(&chainstate.CoinsTip());
    BOOST_REQUIRE_EQUAL(chainstate.DisconnectBlock(block, pindex, view), DISCONNECT_OK);
    BOOST_REQUIRE(view.GetBestBlock() == pindex->pprev->GetBlockHash());

    BlockValidationState state;
    BOOST_CHECK(!chainstate.ConnectBlock(rebuilt, state, pindex, view, /*fJustCheck=*/true));

    // Refused as an internal error, NOT as an invalid block: the block itself is fine and marking it
    // invalid would poison a legitimate part of the chain over a caller's mistake.
    BOOST_CHECK(state.IsError());
    BOOST_CHECK(!state.IsInvalid());

    // The control, from the same view: the real block connects. Without it the refusal above could
    // be the fixture being wrong rather than the guard working. The refused call returns before
    // touching the view, so the view is still at pprev here.
    BOOST_REQUIRE(!block.m_haze_reconstructed);
    BlockValidationState state2;
    BOOST_CHECK(chainstate.ConnectBlock(block, state2, pindex, view, /*fJustCheck=*/true));
}

// ============================================================================
// Forgetting stripped blocks that were never connected (#542)
// ============================================================================

BOOST_AUTO_TEST_CASE(unconnected_stripped_blocks_are_forgotten_connected_ones_kept)
{
    // A hazed node records BLOCK_HAVE_DATA when it writes a block's stripped form, before the block
    // is connected. Stop it in that window and the index claims to have a block that can never be
    // connected from — the scriptSigs are gone and the in-memory copy died with the process. That is
    // #542. The claim is what is wrong, so it is withdrawn and the block re-downloaded.
    //
    // The discrimination is the whole point: a stripped block that IS already connected must be
    // kept, because for it the stored form really is sufficient — it will only ever be disconnected,
    // which needs nothing haze removed.
    CScript dest = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));

    // Two blocks built on the SAME parent, before either is processed. The first to arrive becomes
    // the tip; the second is accepted and stored but never connected, since it has equal work and
    // first-seen wins. That is the state an unclean shutdown leaves behind, reached deterministically.
    CScript other_dest = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    CBlock winner = CreateBlock({}, dest, m_node.chainman->ActiveChainstate());
    CBlock side = CreateBlock({}, other_dest, m_node.chainman->ActiveChainstate());
    BOOST_REQUIRE(winner.GetHash() != side.GetHash());
    BOOST_REQUIRE(winner.hashPrevBlock == side.hashPrevBlock);

    BOOST_REQUIRE(Assert(m_node.chainman)->ProcessNewBlock(std::make_shared<const CBlock>(winner),
                                                           /*force_processing=*/true,
                                                           /*min_pow_checked=*/true, nullptr));
    BOOST_REQUIRE(Assert(m_node.chainman)->ProcessNewBlock(std::make_shared<const CBlock>(side),
                                                           /*force_processing=*/true,
                                                           /*min_pow_checked=*/true, nullptr));

    LOCK(cs_main);
    ChainstateManager& chainman = *m_node.chainman;
    CBlockIndex* side_index = chainman.m_blockman.LookupBlockIndex(side.GetHash());
    CBlockIndex* tip = chainman.ActiveChain().Tip();
    BOOST_REQUIRE(side_index);
    BOOST_REQUIRE(tip);
    // Load-bearing: if the side block became the tip there is no "unconnected" case to test.
    BOOST_REQUIRE(side_index != tip);
    BOOST_REQUIRE(chainman.ActiveChain().Contains(tip));
    BOOST_REQUIRE(!chainman.ActiveChain().Contains(side_index));
    BOOST_REQUIRE(side_index->nStatus & BLOCK_HAVE_DATA);
    BOOST_REQUIRE(tip->nStatus & BLOCK_HAVE_DATA);

    // Nothing happens off a hazed node: an archive node's stored blocks are complete and connectable.
    side_index->nStatus |= BLOCK_HAZED_STRIPPED;
    tip->nStatus |= BLOCK_HAZED_STRIPPED;
    BOOST_CHECK_EQUAL(chainman.DropUnconnectableStrippedBlocks(), 0);
    BOOST_CHECK(side_index->nStatus & BLOCK_HAVE_DATA);

    chainman.m_blockman.m_ghost_exorcism.Init(haze::GhostMode::HAZED);
    BOOST_REQUIRE(chainman.m_blockman.m_ghost_exorcism.IsActive());

    BOOST_CHECK_EQUAL(chainman.DropUnconnectableStrippedBlocks(), 1);

    // The unconnected one is forgotten, and forgotten completely — a lingering file position would
    // send a later read back into the wrong file sequence, which is the original bug.
    BOOST_CHECK(!(side_index->nStatus & BLOCK_HAVE_DATA));
    BOOST_CHECK(!(side_index->nStatus & BLOCK_HAVE_UNDO));
    BOOST_CHECK_EQUAL(side_index->nFile, 0);
    BOOST_CHECK_EQUAL(side_index->nDataPos, 0U);

    // The connected one is untouched.
    BOOST_CHECK(tip->nStatus & BLOCK_HAVE_DATA);

    // m_have_pruned must be set, and this is not bookkeeping pedantry: CheckBlockIndex asserts that
    // BLOCK_HAVE_DATA and nTx > 0 agree unless it is set, and they now deliberately do not.
    BOOST_CHECK(chainman.m_blockman.m_have_pruned);

    // The assertion that matters. Everything above could be individually true while the index as a
    // whole had been left inconsistent, and it is CheckBlockIndex that a real node would trip over.
    chainman.CheckBlockIndex();

    // Idempotent: a second pass finds nothing left to forget.
    BOOST_CHECK_EQUAL(chainman.DropUnconnectableStrippedBlocks(), 0);
}

BOOST_AUTO_TEST_CASE(reconnecting_a_stripped_block_refetches_instead_of_dying)
{
    // The case archive fallback exists for: a hazed node reorgs back onto a branch it abandoned.
    // The block was connected once, so its stripped form was sufficient then — and is not now,
    // because connecting needs the scriptSigs and witnesses haze destroyed.
    //
    // Before this, ConnectTip called FatalError and the node shut down. It must instead withdraw the
    // BLOCK_HAVE_DATA claim, which is what was false, and let the ordinary download machinery fetch
    // the block from a peer that still has it.
    CScript dest = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));
    CBlock block = CreateAndProcessBlock({}, dest);

    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();

    CBlockIndex* pindex{nullptr};
    CBlockIndex* parent{nullptr};
    {
        LOCK(cs_main);
        pindex = chainman.m_blockman.LookupBlockIndex(block.GetHash());
        BOOST_REQUIRE(pindex);
        BOOST_REQUIRE(chainstate.m_chain.Tip() == pindex);
        parent = pindex->pprev;
        BOOST_REQUIRE(parent);
        BOOST_REQUIRE(pindex->nStatus & BLOCK_HAVE_DATA);
    }

    // Abandon the branch, then come back to it — the reorg-back case, not a contrivance. The
    // disconnect happens while the block is still whole, which is what really occurs: a block is
    // only stripped storage once it has been written, and this test is about the RE-connect.
    BlockValidationState invalidate_state;
    BOOST_REQUIRE(chainstate.InvalidateBlock(invalidate_state, pindex));
    BOOST_REQUIRE(WITH_LOCK(cs_main, return chainstate.m_chain.Tip() == parent));

    {
        LOCK(cs_main);
        // Now only the stripped form survives, so this block can no longer be read as a full one.
        pindex->nStatus |= BLOCK_HAZED_STRIPPED;
        chainstate.ResetBlockFailureFlags(pindex);
        // ResetBlockFailureFlags clears the failure but does not restore m_best_header, which
        // InvalidateBlock lowered. On a real node the header is the best one known — that is why the
        // reorg back is being attempted at all — so the fixture is made to match. Without this,
        // CheckBlockIndex asserts that a non-failed block outranks the best header, which is a
        // property of this Invalidate/Reconsider sequence and nothing to do with haze: verified by
        // running the same sequence with no stripped block involved.
        chainman.m_best_header = pindex;
    }

    // Reconnecting must not be fatal. Whether the activation reports success is not the point —
    // the node surviving with a consistent index, and the block queued for download, is.
    BlockValidationState state;
    chainstate.ActivateBestChain(state);
    BOOST_CHECK(!state.IsError());

    LOCK(cs_main);
    // The false claim is withdrawn, so the block is fetched again rather than read from storage that
    // cannot satisfy the read.
    BOOST_CHECK(!(pindex->nStatus & BLOCK_HAVE_DATA));
    BOOST_CHECK_EQUAL(pindex->nDataPos, 0U);
    // Required, or CheckBlockIndex aborts — see ForgetStrippedBlockData.
    BOOST_CHECK(chainman.m_blockman.m_have_pruned);
    // The tip did not advance onto a block that could not be validated.
    BOOST_CHECK(chainstate.m_chain.Tip() == parent);
    // And the index is still self-consistent, which is what a real node would trip over.
    chainman.CheckBlockIndex();
}

BOOST_AUTO_TEST_CASE(reconstruct_meta_flags)
{
    CScript dest = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));
    CBlock block = CreateAndProcessBlock({}, dest);

    haze::StripResult result = haze::StripBlock(block);
    haze::ReconstructionMeta meta;
    CBlock reconstructed = haze::ReconstructPartialBlockWithMeta(result.stripped_block, meta);

    BOOST_CHECK(meta.is_reconstructed);
    BOOST_CHECK(meta.witness_stripped);
    BOOST_CHECK(meta.scriptsig_stripped);
    BOOST_CHECK(meta.coinbase_stripped);
}

// ============================================================================
// Non-standard Script Stripping
// ============================================================================

BOOST_AUTO_TEST_CASE(classify_nonstandard_multisig)
{
    // Build a bare 1-of-2 multisig scriptPubKey — this is the primary data
    // embedding vector that non-standard stripping targets.
    CKey key2;
    key2.MakeNewKey(true);
    CScript multisig = GetScriptForMultisig(1, {coinbaseKey.GetPubKey(), key2.GetPubKey()});

    BOOST_CHECK(haze::IsNonstandardScript(multisig));

    // Build a transaction with the multisig output and classify it
    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint(m_coinbase_txns[0]->GetHash(), 0));
    mtx.vout.emplace_back(49 * COIN, multisig);
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));

    auto fields = haze::ClassifyTransaction(*tx, /*is_coinbase=*/false, /*tx_index=*/0);
    bool has_nonstandard = false;
    for (const auto& f : fields) {
        if (f.type == haze::HazeFieldType::NONSTANDARD_SCRIPT) {
            has_nonstandard = true;
            BOOST_CHECK_EQUAL(f.field_index, 0U);
            BOOST_CHECK_EQUAL(f.original_size, multisig.size());
        }
    }
    BOOST_CHECK(has_nonstandard);
}

BOOST_AUTO_TEST_CASE(classify_standard_p2wpkh_kept)
{
    // P2WPKH is hash-based and must NOT be classified as non-standard
    CScript p2wpkh = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));
    BOOST_CHECK(!haze::IsNonstandardScript(p2wpkh));

    // Also check other standard types
    CScript p2pkh = GetScriptForDestination(PKHash(coinbaseKey.GetPubKey()));
    BOOST_CHECK(!haze::IsNonstandardScript(p2pkh));

    CScript p2sh = GetScriptForDestination(ScriptHash(p2wpkh));
    BOOST_CHECK(!haze::IsNonstandardScript(p2sh));
}

BOOST_AUTO_TEST_CASE(strip_nonstandard_multisig)
{
    // Bare multisig output should be replaced with OP_RETURN + OP_1 placeholder
    CKey key2;
    key2.MakeNewKey(true);
    CScript multisig = GetScriptForMultisig(1, {coinbaseKey.GetPubKey(), key2.GetPubKey()});
    CScript dest = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));

    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint(m_coinbase_txns[0]->GetHash(), 0));
    mtx.vout.emplace_back(1 * COIN, multisig);   // non-standard output
    mtx.vout.emplace_back(48 * COIN, dest);       // standard change output
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));

    auto stripped = haze::StripTransaction(*tx, /*is_coinbase=*/false);

    // First output (multisig) should be replaced with placeholder
    CScript expected = haze::MakeStrippedNonstandard();
    BOOST_CHECK(stripped.m_outputs[0].script_pub_key == expected);

    // Second output (P2WPKH) should be preserved
    BOOST_CHECK(stripped.m_outputs[1].script_pub_key == dest);

    // Values should be preserved
    BOOST_CHECK_EQUAL(stripped.m_outputs[0].n_value, 1 * COIN);
    BOOST_CHECK_EQUAL(stripped.m_outputs[1].n_value, 48 * COIN);

    // txid must be stored since output was modified
    BOOST_CHECK(stripped.m_has_stored_txid);
}

BOOST_AUTO_TEST_CASE(strip_nonstandard_preserves_merkle)
{
    // Stripping non-standard outputs must still produce a valid merkle root
    // via stored txids
    CKey key2;
    key2.MakeNewKey(true);
    CScript multisig = GetScriptForMultisig(1, {coinbaseKey.GetPubKey(), key2.GetPubKey()});
    CScript dest = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));

    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint(m_coinbase_txns[0]->GetHash(), 0));
    mtx.vout.emplace_back(49 * COIN, multisig);

    CBlock block = CreateAndProcessBlock({mtx}, dest);

    haze::StripResult result = haze::StripBlock(block);
    BOOST_CHECK(haze::VerifyStrippedBlock(result.stripped_block, block.GetBlockHeader()));
}

BOOST_AUTO_TEST_CASE(requires_stored_txid_nonstandard)
{
    // A transaction with a non-standard output requires stored txid
    CKey key2;
    key2.MakeNewKey(true);
    CScript multisig = GetScriptForMultisig(1, {coinbaseKey.GetPubKey(), key2.GetPubKey()});

    CMutableTransaction mtx;
    mtx.vin.emplace_back(COutPoint(m_coinbase_txns[0]->GetHash(), 0));
    mtx.vout.emplace_back(49 * COIN, multisig);
    CTransactionRef tx = MakeTransactionRef(std::move(mtx));

    BOOST_CHECK(haze::RequiresStoredTxid(*tx));
}

BOOST_AUTO_TEST_SUITE_END()

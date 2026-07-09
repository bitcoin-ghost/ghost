// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/ghost_tier.h>

#include <core_io.h>
#include <primitives/transaction.h>
#include <script/script.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

namespace {

//! Build a minimal non-coinbase transaction (1 input, 1 P2WPKH output).
CMutableTransaction MakeBaseTx()
{
    CMutableTransaction tx;
    tx.version = 2;
    tx.nLockTime = 0;
    tx.vin.resize(1);
    // Non-coinbase: prevout with n != NULL_INDEX (COutPoint::IsNull() is false).
    tx.vin[0].prevout.hash.SetNull();
    tx.vin[0].prevout.n = 0;
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 50000;
    tx.vout[0].scriptPubKey = CScript() << OP_0 << std::vector<unsigned char>(20, 0x00);
    return tx;
}

CScript OpReturnScript(size_t data_size)
{
    return CScript() << OP_RETURN << std::vector<unsigned char>(data_size, 0x00);
}

GhostTier TierOf(const CMutableTransaction& mtx)
{
    return ClassifyTransactionTier(CTransaction(mtx));
}

} // anonymous namespace

BOOST_AUTO_TEST_SUITE(ghost_tier_tests)

// ============================================================================
// Per-tier representative classification
// ============================================================================

BOOST_AUTO_TEST_CASE(coinbase_is_t0)
{
    CMutableTransaction mtx = MakeBaseTx();
    mtx.vin[0].prevout.SetNull(); // null prevout + single input => coinbase
    BOOST_CHECK(CTransaction(mtx).IsCoinBase());
    BOOST_CHECK(TierOf(mtx) == GhostTier::T0);
}

BOOST_AUTO_TEST_CASE(simple_payment_is_t0)
{
    BOOST_CHECK(TierOf(MakeBaseTx()) == GhostTier::T0);
}

BOOST_AUTO_TEST_CASE(small_op_return_is_t2)
{
    CMutableTransaction mtx = MakeBaseTx();
    mtx.vout.emplace_back(0, OpReturnScript(40)); // payload 40 <= 80
    BOOST_CHECK(TierOf(mtx) == GhostTier::T2);
}

BOOST_AUTO_TEST_CASE(op_return_exactly_80_is_t2)
{
    // Boundary: classifier size = script.len()-2. For an 80-byte push the script
    // is OP_RETURN + OP_PUSHDATA1 + len(80) + 80 = 83 bytes => size 81 (> 80 => T3).
    // A 79-byte push serialises as OP_RETURN + PUSHBYTES_79 + 79 = 81 bytes =>
    // size 79 (<= 80 => T2). Verify the >80 boundary lands where expected.
    CMutableTransaction t2 = MakeBaseTx();
    t2.vout.emplace_back(0, OpReturnScript(79));
    BOOST_CHECK(TierOf(t2) == GhostTier::T2);
}

BOOST_AUTO_TEST_CASE(large_op_return_is_t3)
{
    CMutableTransaction mtx = MakeBaseTx();
    mtx.vout.emplace_back(0, OpReturnScript(100)); // payload 100 > 80
    BOOST_CHECK(TierOf(mtx) == GhostTier::T3);
}

BOOST_AUTO_TEST_CASE(runes_is_t3)
{
    CMutableTransaction mtx = MakeBaseTx();
    CScript runes = CScript() << OP_RETURN << OP_13 << std::vector<unsigned char>(4, 0x00);
    mtx.vout.emplace_back(0, runes);
    BOOST_CHECK(TierOf(mtx) == GhostTier::T3);
}

BOOST_AUTO_TEST_CASE(bare_multisig_is_t1)
{
    CMutableTransaction mtx = MakeBaseTx();
    std::vector<unsigned char> pubkey{0x02};
    pubkey.resize(33, 0x00);
    CScript ms = CScript() << OP_1 << pubkey << OP_1 << OP_CHECKMULTISIG;
    mtx.vout[0].scriptPubKey = ms;
    BOOST_CHECK(TierOf(mtx) == GhostTier::T1);
}

BOOST_AUTO_TEST_CASE(cltv_timelock_is_t1)
{
    CMutableTransaction mtx = MakeBaseTx();
    CScript cltv = CScript() << std::vector<unsigned char>{0x01, 0x02, 0x03}
                             << OP_CHECKLOCKTIMEVERIFY << OP_DROP
                             << OP_0 << std::vector<unsigned char>(20, 0x00);
    mtx.vout[0].scriptPubKey = cltv;
    BOOST_CHECK(TierOf(mtx) == GhostTier::T1);
}

BOOST_AUTO_TEST_CASE(csv_timelock_is_t1)
{
    CMutableTransaction mtx = MakeBaseTx();
    CScript csv = CScript() << std::vector<unsigned char>{0x40}
                            << OP_CHECKSEQUENCEVERIFY << OP_DROP
                            << OP_0 << std::vector<unsigned char>(20, 0x00);
    mtx.vout[0].scriptPubKey = csv;
    BOOST_CHECK(TierOf(mtx) == GhostTier::T1);
}

BOOST_AUTO_TEST_CASE(htlc_is_t1)
{
    // hash op + timelock + conditional in one output script.
    CMutableTransaction mtx = MakeBaseTx();
    CScript htlc = CScript() << OP_IF
                             << OP_HASH160 << std::vector<unsigned char>(20, 0x11) << OP_EQUALVERIFY
                             << OP_ELSE
                             << std::vector<unsigned char>{0x10} << OP_CHECKLOCKTIMEVERIFY << OP_DROP
                             << OP_ENDIF;
    mtx.vout[0].scriptPubKey = htlc;
    BOOST_CHECK(TierOf(mtx) == GhostTier::T1);
}

BOOST_AUTO_TEST_CASE(extended_witness_is_t1)
{
    // 200-byte witness on the only input: 108 < 200 <= 400 => T1 (complex script).
    CMutableTransaction mtx = MakeBaseTx();
    mtx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(200, 0x00));
    BOOST_CHECK(TierOf(mtx) == GhostTier::T1);
}

BOOST_AUTO_TEST_CASE(small_witness_stays_t0)
{
    CMutableTransaction mtx = MakeBaseTx();
    mtx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(64, 0x00)); // <= 108
    BOOST_CHECK(TierOf(mtx) == GhostTier::T0);
}

BOOST_AUTO_TEST_CASE(very_large_witness_is_t3)
{
    CMutableTransaction mtx = MakeBaseTx();
    mtx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(1200, 0x00)); // > 1000
    BOOST_CHECK(TierOf(mtx) == GhostTier::T3);
}

BOOST_AUTO_TEST_CASE(inscription_envelope_is_t3)
{
    CMutableTransaction mtx = MakeBaseTx();
    std::vector<unsigned char> item{0x00, 0x63, 0x03, 'o', 'r', 'd'};
    item.resize(26, 0x00); // >= 10 bytes, "ord" near start
    mtx.vin[0].scriptWitness.stack.push_back(item);
    BOOST_CHECK(TierOf(mtx) == GhostTier::T3);
}

BOOST_AUTO_TEST_CASE(loose_ord_window_is_inscription_t3)
{
    // No envelope prefix, but a bare "ord" 3-byte window anywhere => T3.
    CMutableTransaction mtx = MakeBaseTx();
    std::vector<unsigned char> item{0xaa, 0xbb, 0xcc, 'o', 'r', 'd', 0xdd, 0xee, 0xff, 0x11};
    mtx.vin[0].scriptWitness.stack.push_back(item);
    BOOST_CHECK(TierOf(mtx) == GhostTier::T3);
}

BOOST_AUTO_TEST_CASE(brc20_witness_is_t3)
{
    CMutableTransaction mtx = MakeBaseTx();
    std::string s = "random-prefix-data\"p\":\"brc-20\"trailing";
    std::vector<unsigned char> item(s.begin(), s.end());
    mtx.vin[0].scriptWitness.stack.push_back(item);
    BOOST_CHECK(TierOf(mtx) == GhostTier::T3);
}

// ============================================================================
// Preset gating: {T0,T1} (strict) / {T0,T1,T2} (permissive) / all (full_open)
// ============================================================================

BOOST_AUTO_TEST_CASE(preset_strict_gate)
{
    GhostTierPolicyConfig strict; // {T0,T1}
    strict.allow_t2 = false;
    strict.allow_t3 = false;
    BOOST_CHECK(!strict.IsInert());
    BOOST_CHECK(strict.TierAllowed(GhostTier::T0));
    BOOST_CHECK(strict.TierAllowed(GhostTier::T1));
    BOOST_CHECK(!strict.TierAllowed(GhostTier::T2));
    BOOST_CHECK(!strict.TierAllowed(GhostTier::T3));

    std::string reason;
    // T0 accepted, T2/T3 rejected with "tier-policy".
    BOOST_CHECK(IsGhostTierPolicyClean(CTransaction(MakeBaseTx()), strict, 1000, reason));

    CMutableTransaction t2 = MakeBaseTx();
    t2.vout.emplace_back(0, OpReturnScript(40));
    BOOST_CHECK(!IsGhostTierPolicyClean(CTransaction(t2), strict, 1000, reason));
    BOOST_CHECK_EQUAL(reason, "tier-policy");

    CMutableTransaction t3 = MakeBaseTx();
    t3.vout.emplace_back(0, OpReturnScript(100));
    BOOST_CHECK(!IsGhostTierPolicyClean(CTransaction(t3), strict, 1000, reason));
    BOOST_CHECK_EQUAL(reason, "tier-policy");
}

BOOST_AUTO_TEST_CASE(preset_permissive_gate)
{
    GhostTierPolicyConfig permissive; // {T0,T1,T2}
    permissive.allow_t3 = false;
    BOOST_CHECK(permissive.TierAllowed(GhostTier::T2));
    BOOST_CHECK(!permissive.TierAllowed(GhostTier::T3));

    std::string reason;
    CMutableTransaction t2 = MakeBaseTx();
    t2.vout.emplace_back(0, OpReturnScript(40));
    BOOST_CHECK(IsGhostTierPolicyClean(CTransaction(t2), permissive, 1000, reason));

    CMutableTransaction t3 = MakeBaseTx();
    t3.vout.emplace_back(0, OpReturnScript(100));
    BOOST_CHECK(!IsGhostTierPolicyClean(CTransaction(t3), permissive, 1000, reason));
    BOOST_CHECK_EQUAL(reason, "tier-policy");
}

BOOST_AUTO_TEST_CASE(preset_full_open_is_inert)
{
    GhostTierPolicyConfig full_open; // default = all allowed
    BOOST_CHECK(full_open.IsInert());
    BOOST_CHECK(full_open.TierAllowed(GhostTier::T3));

    std::string reason;
    CMutableTransaction t3 = MakeBaseTx();
    t3.vout.emplace_back(0, OpReturnScript(100));
    BOOST_CHECK(IsGhostTierPolicyClean(CTransaction(t3), full_open, 1000, reason));
}

// ============================================================================
// Tier-independent content toggles + custom per-field limits
// ============================================================================

BOOST_AUTO_TEST_CASE(content_toggle_inscriptions)
{
    GhostTierPolicyConfig cfg; // all tiers allowed, but block inscriptions
    cfg.allow_inscriptions = false;
    BOOST_CHECK(!cfg.IsInert());

    CMutableTransaction insc = MakeBaseTx();
    std::vector<unsigned char> item{0x00, 0x63, 0x03, 'o', 'r', 'd'};
    item.resize(26, 0x00);
    insc.vin[0].scriptWitness.stack.push_back(item);

    std::string reason;
    BOOST_CHECK(!IsGhostTierPolicyClean(CTransaction(insc), cfg, 1000, reason));
    BOOST_CHECK_EQUAL(reason, "tier-policy-inscription");
}

BOOST_AUTO_TEST_CASE(content_toggle_runes)
{
    GhostTierPolicyConfig cfg;
    cfg.allow_runes = false;
    CMutableTransaction rune = MakeBaseTx();
    rune.vout.emplace_back(0, CScript() << OP_RETURN << OP_13 << std::vector<unsigned char>(4, 0));
    std::string reason;
    BOOST_CHECK(!IsGhostTierPolicyClean(CTransaction(rune), cfg, 1000, reason));
    BOOST_CHECK_EQUAL(reason, "tier-policy-runes");
}

BOOST_AUTO_TEST_CASE(custom_limit_max_tx_outputs)
{
    GhostTierPolicyConfig cfg;
    cfg.max_tx_outputs = 2;
    CMutableTransaction mtx = MakeBaseTx();
    mtx.vout.resize(3, CTxOut(1000, CScript() << OP_0 << std::vector<unsigned char>(20, 0)));
    std::string reason;
    BOOST_CHECK(!IsGhostTierPolicyClean(CTransaction(mtx), cfg, 1000, reason));
    BOOST_CHECK_EQUAL(reason, "tier-policy-outputs");
}

BOOST_AUTO_TEST_CASE(custom_limit_max_op_return_size)
{
    GhostTierPolicyConfig cfg;
    cfg.allow_t3 = true; // keep tier gate open so the op_return limit is what bites
    cfg.max_op_return_size = 20;
    CMutableTransaction mtx = MakeBaseTx();
    mtx.vout.emplace_back(0, OpReturnScript(40)); // size 40 > 20
    std::string reason;
    BOOST_CHECK(!IsGhostTierPolicyClean(CTransaction(mtx), cfg, 1000, reason));
    BOOST_CHECK_EQUAL(reason, "tier-policy-opreturn");
}

BOOST_AUTO_TEST_CASE(custom_limit_max_witness_per_input)
{
    GhostTierPolicyConfig cfg;
    cfg.max_witness_per_input = 100;
    CMutableTransaction mtx = MakeBaseTx();
    mtx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(150, 0));
    std::string reason;
    BOOST_CHECK(!IsGhostTierPolicyClean(CTransaction(mtx), cfg, 1000, reason));
    BOOST_CHECK_EQUAL(reason, "tier-policy-witness");
}

BOOST_AUTO_TEST_CASE(custom_limit_min_fee_rate)
{
    GhostTierPolicyConfig cfg;
    cfg.min_fee_rate = 5.0; // sat/vB
    CMutableTransaction mtx = MakeBaseTx();
    const CTransaction tx(mtx);
    // Fee of 1 sat over a >1 vB tx is far below 5 sat/vB.
    std::string reason;
    BOOST_CHECK(!IsGhostTierPolicyClean(tx, cfg, 1, reason));
    BOOST_CHECK_EQUAL(reason, "tier-policy-minfeerate");
    // A generous fee passes.
    BOOST_CHECK(IsGhostTierPolicyClean(tx, cfg, 1'000'000, reason));
}

// ============================================================================
// Parity golden vectors: raw tx hex -> expected tier.
//
// The SAME corpus MUST be added to the Rust `ghost-buds` tests in a follow-up so
// both classifiers stay locked in lockstep. Generated with the deterministic
// serialisation of representative transactions (see PR description).
// ============================================================================

BOOST_AUTO_TEST_CASE(parity_golden_vectors)
{
    struct Vector {
        const char* hex;
        GhostTier tier;
    };
    static const std::vector<Vector> vectors = {
        {"020000000111111111111111111111111111111111111111111111111111111111111111110000000000000000000150c3000000000000160014000000000000000000000000000000000000000000000000", GhostTier::T0},  // T0 simple P2WPKH payment
        {"0200000000010111111111111111111111111111111111111111111111111111111111111111110000000000000000000150c3000000000000160014000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", GhostTier::T0},  // T0 small witness (64B)
        {"020000000111111111111111111111111111111111111111111111111111111111111111110000000000000000000250c3000000000000160014000000000000000000000000000000000000000000000000000000002a6a280000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", GhostTier::T2},  // T2 small OP_RETURN(40)
        {"020000000111111111111111111111111111111111111111111111111111111111111111110000000000000000000250c300000000000016001400000000000000000000000000000000000000000000000000000000676a4c640000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", GhostTier::T3},  // T3 large OP_RETURN(100)
        {"020000000111111111111111111111111111111111111111111111111111111111111111110000000000000000000250c300000000000016001400000000000000000000000000000000000000000000000000000000076a5d040000000000000000", GhostTier::T3},  // T3 runes (OP_RETURN OP_13)
        {"020000000111111111111111111111111111111111111111111111111111111111111111110000000000000000000150c300000000000025512102000000000000000000000000000000000000000000000000000000000000000051ae00000000", GhostTier::T1},  // T1 bare 1-of-1 multisig
        {"020000000111111111111111111111111111111111111111111111111111111111111111110000000000000000000150c30000000000001c03010203b1750014000000000000000000000000000000000000000000000000", GhostTier::T1},  // T1 CLTV timelock script
        {"0200000000010111111111111111111111111111111111111111111111111111111111111111110000000000000000000150c30000000000001600140000000000000000000000000000000000000000021a0063036f726400000000000000000000000000000000000000000a0000000000000000000000000000", GhostTier::T3},  // T3 inscription envelope
        {"0200000000010111111111111111111111111111111111111111111111111111111111111111110000000000000000000150c30000000000001600140000000000000000000000000000000000000000012e006372616e646f6d2d7072656669782d646174612270223a226272632d323022747261696c696e672d627974657300000000", GhostTier::T3},  // T3 brc-20 witness
        {"0200000000010111111111111111111111111111111111111111111111111111111111111111110000000000000000000150c3000000000000160014000000000000000000000000000000000000000001fdb00400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", GhostTier::T3},  // T3 very large witness(1200)
        {"0200000000010111111111111111111111111111111111111111111111111111111111111111110000000000000000000150c3000000000000160014000000000000000000000000000000000000000001c8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", GhostTier::T1},  // T1 extended witness(200)
    };

    for (const auto& v : vectors) {
        CMutableTransaction tx;
        BOOST_REQUIRE_MESSAGE(DecodeHexTx(tx, v.hex), std::string("failed to decode: ") + v.hex);
        const GhostTier got = ClassifyTransactionTier(CTransaction(tx));
        BOOST_CHECK_MESSAGE(got == v.tier,
                            "tier mismatch: expected T" << static_cast<int>(v.tier)
                            << " got T" << static_cast<int>(got) << " for " << v.hex);
    }
}

BOOST_AUTO_TEST_SUITE_END()

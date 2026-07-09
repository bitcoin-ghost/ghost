// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/ghost_reaper.h>
#include <policy/ghost_tier.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/script.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
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
    tx.vin[0].prevout.hash.SetNull();
    tx.vin[0].prevout.n = 0; // non-null prevout index => not a coinbase
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 50000;
    tx.vout[0].scriptPubKey = CScript() << OP_0 << std::vector<unsigned char>(20, 0x00);
    return tx;
}

} // anonymous namespace

BOOST_AUTO_TEST_SUITE(ghost_filter_counters_tests)

// The counters are process-global and cumulative since start, so this shared
// test binary cannot assert they equal zero here (other suites exercise the
// gates first). Instead we assert exact deltas: a clean tx must not move them,
// and a rejected tx must add exactly 1 to the tx counter and its virtual size
// to the vbyte counter.

BOOST_AUTO_TEST_CASE(accessors_are_readable)
{
    // Accessors must be callable and return a concrete value (0 at process
    // start; possibly non-zero once other suites have run).
    (void)GhostTierRejectedTxs();
    (void)GhostTierRejectedVbytes();
    (void)GhostReaperRejectedTxs();
    (void)GhostReaperRejectedVbytes();
    BOOST_CHECK(true);
}

BOOST_AUTO_TEST_CASE(tier_counter_increments_on_reject)
{
    GhostTierPolicyConfig strict; // {T0,T1}: reject T2/T3
    strict.allow_t2 = false;
    strict.allow_t3 = false;
    BOOST_CHECK(!strict.IsInert());

    std::string reason;

    // A clean T0 payment must NOT move the counters.
    const uint64_t txs_before_clean = GhostTierRejectedTxs();
    const uint64_t vbytes_before_clean = GhostTierRejectedVbytes();
    BOOST_CHECK(IsGhostTierPolicyClean(CTransaction(MakeBaseTx()), strict, 1000, reason));
    BOOST_CHECK_EQUAL(GhostTierRejectedTxs(), txs_before_clean);
    BOOST_CHECK_EQUAL(GhostTierRejectedVbytes(), vbytes_before_clean);

    // A small OP_RETURN is T2, which `strict` rejects.
    CMutableTransaction t2 = MakeBaseTx();
    t2.vout.emplace_back(0, CScript() << OP_RETURN << std::vector<unsigned char>(40, 0x00));
    const CTransaction rejected_tx(t2);
    const int64_t vsize = GetVirtualTransactionSize(rejected_tx);
    BOOST_CHECK(vsize > 0);

    const uint64_t txs_before = GhostTierRejectedTxs();
    const uint64_t vbytes_before = GhostTierRejectedVbytes();
    BOOST_CHECK(!IsGhostTierPolicyClean(rejected_tx, strict, 1000, reason));
    BOOST_CHECK_EQUAL(reason, "tier-policy");

    // Exactly one tx and its vsize were added.
    BOOST_CHECK_EQUAL(GhostTierRejectedTxs(), txs_before + 1);
    BOOST_CHECK_EQUAL(GhostTierRejectedVbytes(), vbytes_before + static_cast<uint64_t>(vsize));
}

BOOST_AUTO_TEST_CASE(reaper_counter_increments_once_on_reject)
{
    GhostReaperConfig config; // all detectors enabled by default
    std::string reason;

    // A clean payment must NOT move the counters.
    const uint64_t txs_before_clean = GhostReaperRejectedTxs();
    const uint64_t vbytes_before_clean = GhostReaperRejectedVbytes();
    BOOST_CHECK(IsGhostReaperClean(CTransaction(MakeBaseTx()), config, reason));
    BOOST_CHECK_EQUAL(GhostReaperRejectedTxs(), txs_before_clean);
    BOOST_CHECK_EQUAL(GhostReaperRejectedVbytes(), vbytes_before_clean);

    // A Runestone output (OP_RETURN OP_13) trips the Reaper.
    CMutableTransaction rune = MakeBaseTx();
    rune.vout.emplace_back(0, CScript() << OP_RETURN << OP_13);
    const CTransaction rejected_tx(rune);
    const int64_t vsize = GetVirtualTransactionSize(rejected_tx);
    BOOST_CHECK(vsize > 0);

    const uint64_t txs_before = GhostReaperRejectedTxs();
    const uint64_t vbytes_before = GhostReaperRejectedVbytes();
    BOOST_CHECK(!IsGhostReaperClean(rejected_tx, config, reason));
    BOOST_CHECK_EQUAL(reason, "ghost-reaper-runestone");

    // Exactly one tx and its vsize were added.
    BOOST_CHECK_EQUAL(GhostReaperRejectedTxs(), txs_before + 1);
    BOOST_CHECK_EQUAL(GhostReaperRejectedVbytes(), vbytes_before + static_cast<uint64_t>(vsize));
}

BOOST_AUTO_TEST_CASE(reaper_counts_once_when_multiple_detectors_would_fire)
{
    GhostReaperConfig config;
    std::string reason;

    // Construct a 1-in/1-out tx whose sole output is BOTH a Runestone and an
    // oversized OP_RETURN — it would trip multiple detectors, but the wrapper
    // must count it exactly once.
    CMutableTransaction mtx = MakeBaseTx();
    mtx.vout.clear();
    mtx.vout.emplace_back(0, CScript() << OP_RETURN << OP_13
                                       << std::vector<unsigned char>(120, 0xab));
    const CTransaction rejected_tx(mtx);

    const uint64_t txs_before = GhostReaperRejectedTxs();
    BOOST_CHECK(!IsGhostReaperClean(rejected_tx, config, reason));
    BOOST_CHECK_EQUAL(GhostReaperRejectedTxs(), txs_before + 1);
}

BOOST_AUTO_TEST_SUITE_END()

// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/mempool_args.h>

#include <kernel/mempool_limits.h>
#include <kernel/mempool_options.h>

#include <common/args.h>
#include <common/messages.h>
#include <consensus/amount.h>
#include <kernel/chainparams.h>
#include <logging.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <tinyformat.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/translation.h>

#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <memory>
#include <string>

using common::AmountErrMsg;
using kernel::MemPoolLimits;
using kernel::MemPoolOptions;

//! Maximum mempool size on 32-bit systems.
static constexpr int MAX_32BIT_MEMPOOL_MB{500};

namespace {
void ApplyArgsManOptions(const ArgsManager& argsman, MemPoolLimits& mempool_limits)
{
    mempool_limits.ancestor_count = argsman.GetIntArg("-limitancestorcount", mempool_limits.ancestor_count);

    if (auto vkb = argsman.GetIntArg("-limitancestorsize")) mempool_limits.ancestor_size_vbytes = *vkb * 1'000;

    mempool_limits.descendant_count = argsman.GetIntArg("-limitdescendantcount", mempool_limits.descendant_count);

    if (auto vkb = argsman.GetIntArg("-limitdescendantsize")) mempool_limits.descendant_size_vbytes = *vkb * 1'000;
}
}

util::Result<void> ApplyArgsManOptions(const ArgsManager& argsman, const CChainParams& chainparams, MemPoolOptions& mempool_opts)
{
    mempool_opts.check_ratio = argsman.GetIntArg("-checkmempool", mempool_opts.check_ratio);

    if (auto mb = argsman.GetIntArg("-maxmempool")) {
        constexpr bool is_32bit{sizeof(void*) == 4};
        if (is_32bit && *mb > MAX_32BIT_MEMPOOL_MB) {
            return util::Error{Untranslated(strprintf("-maxmempool is set to %i but can't be over %i MB on 32-bit systems", *mb, MAX_32BIT_MEMPOOL_MB))};
        }
        mempool_opts.max_size_bytes = *mb * 1'000'000;
    }

    if (auto hours = argsman.GetIntArg("-mempoolexpiry")) mempool_opts.expiry = std::chrono::hours{*hours};

    // incremental relay fee sets the minimum feerate increase necessary for replacement in the mempool
    // and the amount the mempool min fee increases above the feerate of txs evicted due to mempool limiting.
    if (const auto arg{argsman.GetArg("-incrementalrelayfee")}) {
        if (std::optional<CAmount> inc_relay_fee = ParseMoney(*arg)) {
            mempool_opts.incremental_relay_feerate = CFeeRate{inc_relay_fee.value()};
        } else {
            return util::Error{AmountErrMsg("incrementalrelayfee", *arg)};
        }
    }

    static_assert(DEFAULT_MIN_RELAY_TX_FEE == DEFAULT_INCREMENTAL_RELAY_FEE);
    if (const auto arg{argsman.GetArg("-minrelaytxfee")}) {
        if (std::optional<CAmount> min_relay_feerate = ParseMoney(*arg)) {
            // High fee check is done afterward in CWallet::Create()
            mempool_opts.min_relay_feerate = CFeeRate{min_relay_feerate.value()};
        } else {
            return util::Error{AmountErrMsg("minrelaytxfee", *arg)};
        }
    } else if (mempool_opts.incremental_relay_feerate > mempool_opts.min_relay_feerate) {
        // Allow only setting incremental fee to control both
        mempool_opts.min_relay_feerate = mempool_opts.incremental_relay_feerate;
        LogInfo("Increasing minrelaytxfee to %s to match incrementalrelayfee", mempool_opts.min_relay_feerate.ToString());
    }

    // Feerate used to define dust.  Shouldn't be changed lightly as old
    // implementations may inadvertently create non-standard transactions
    if (const auto arg{argsman.GetArg("-dustrelayfee")}) {
        if (std::optional<CAmount> parsed = ParseMoney(*arg)) {
            mempool_opts.dust_relay_feerate = CFeeRate{parsed.value()};
        } else {
            return util::Error{AmountErrMsg("dustrelayfee", *arg)};
        }
    }

    mempool_opts.permit_bare_multisig = argsman.GetBoolArg("-permitbaremultisig", DEFAULT_PERMIT_BAREMULTISIG);

    if (argsman.GetBoolArg("-datacarrier", DEFAULT_ACCEPT_DATACARRIER)) {
        mempool_opts.max_datacarrier_bytes = argsman.GetIntArg("-datacarriersize", MAX_OP_RETURN_RELAY);
    } else {
        mempool_opts.max_datacarrier_bytes = std::nullopt;
    }

    mempool_opts.require_standard = !argsman.GetBoolArg("-acceptnonstdtxn", DEFAULT_ACCEPT_NON_STD_TXN);
    if (!chainparams.IsTestChain() && !mempool_opts.require_standard) {
        return util::Error{Untranslated(strprintf("acceptnonstdtxn is not currently supported for %s chain", chainparams.GetChainTypeString()))};
    }

    mempool_opts.persist_v1_dat = argsman.GetBoolArg("-persistmempoolv1", mempool_opts.persist_v1_dat);

    // Full RBF is on by default; -mempoolfullrbf=0 lets an operator opt out and
    // fall back to BIP125 opt-in replacement (see ReplacementChecks/PreChecks).
    mempool_opts.full_rbf = argsman.GetBoolArg("-mempoolfullrbf", DEFAULT_MEMPOOL_FULL_RBF);

    // Ghost Reaper configuration.
    //
    // The master `-ghostreaper` flag sets the default value for every per-vector
    // toggle. Each `-ghostreaper-reject*` flag overrides its detector independently:
    // a detector runs iff its per-vector flag is true (after defaulting from
    // the master). This lets operators run any subset of detectors, e.g.
    // `-ghostreaper=disabled -ghostreaper-rejectannex=1` enables only the
    // annex check.
    {
        const std::string reaper_mode = argsman.GetArg("-ghostreaper", "enabled");
        const bool master_default = (reaper_mode != "disabled");

        auto& reaper = mempool_opts.ghost_reaper;
        reaper.reject_inscription  = argsman.GetBoolArg("-ghostreaper-rejectinscription",  master_default);
        reaper.reject_dropstuffing = argsman.GetBoolArg("-ghostreaper-rejectdropstuffing", master_default);
        reaper.reject_fakepubkey   = argsman.GetBoolArg("-ghostreaper-rejectfakepubkey",   master_default);
        reaper.reject_annex        = argsman.GetBoolArg("-ghostreaper-rejectannex",        master_default);
        reaper.reject_opreturn     = argsman.GetBoolArg("-ghostreaper-rejectopreturn",     master_default);
        reaper.reject_runestone    = argsman.GetBoolArg("-ghostreaper-rejectrunestone",    master_default);
        reaper.reject_dustflood    = argsman.GetBoolArg("-ghostreaper-rejectdustflood",    master_default);

        if (argsman.IsArgSet("-ghostreaper-maxopreturn")) {
            reaper.max_op_return_bytes = argsman.GetIntArg("-ghostreaper-maxopreturn", 83);
        }
        if (argsman.IsArgSet("-ghostreaper-mindropsize")) {
            reaper.min_drop_size = argsman.GetIntArg("-ghostreaper-mindropsize", 76);
        }
        if (argsman.IsArgSet("-ghostreaper-dustfloodthreshold")) {
            reaper.dust_flood_threshold = argsman.GetIntArg("-ghostreaper-dustfloodthreshold", 330);
        }
    }

    // Ghost BUDS tier/policy configuration.
    //
    // Every flag defaults to the fully permissive "full_open" profile: all four
    // tiers allowed, every content type allowed, and no custom per-field limits.
    // In that state GhostTierPolicyConfig::IsInert() is true and the mempool
    // gate is a no-op, so a node with no -ghostpolicy-* flags behaves exactly as
    // it did before this feature existed. ghost-setup wires these flags through
    // the managed systemd drop-in (see MANAGED_GHOSTD_FLAG_PREFIXES).
    {
        auto& tier = mempool_opts.ghost_tier_policy;

        if (argsman.IsArgSet("-ghostpolicy-allowtiers")) {
            // CSV of tier numbers, e.g. "0,1,2,3". Listed tiers are allowed;
            // any tier not listed is rejected at mempool acceptance.
            tier.allow_t0 = false;
            tier.allow_t1 = false;
            tier.allow_t2 = false;
            tier.allow_t3 = false;
            const std::string csv = argsman.GetArg("-ghostpolicy-allowtiers", "");
            for (const auto& part : util::SplitString(csv, ',')) {
                const std::string trimmed = util::TrimString(part);
                if (trimmed.empty()) continue;
                const auto n = ToIntegral<int>(trimmed);
                if (!n || *n < 0 || *n > 3) {
                    return util::Error{Untranslated(strprintf("Invalid tier '%s' in -ghostpolicy-allowtiers (expected values 0-3)", trimmed))};
                }
                switch (*n) {
                case 0: tier.allow_t0 = true; break;
                case 1: tier.allow_t1 = true; break;
                case 2: tier.allow_t2 = true; break;
                case 3: tier.allow_t3 = true; break;
                }
            }
        }

        tier.allow_inscriptions = argsman.GetBoolArg("-ghostpolicy-allowinscriptions", true);
        tier.allow_runes        = argsman.GetBoolArg("-ghostpolicy-allowrunes", true);
        tier.allow_brc20        = argsman.GetBoolArg("-ghostpolicy-allowbrc20", true);

        if (argsman.IsArgSet("-ghostpolicy-maxopreturn")) {
            tier.max_op_return_size = static_cast<unsigned int>(argsman.GetIntArg("-ghostpolicy-maxopreturn", 0));
        }
        if (argsman.IsArgSet("-ghostpolicy-maxwitness")) {
            tier.max_witness_per_input = static_cast<unsigned int>(argsman.GetIntArg("-ghostpolicy-maxwitness", 0));
        }
        if (argsman.IsArgSet("-ghostpolicy-maxtxoutputs")) {
            tier.max_tx_outputs = static_cast<unsigned int>(argsman.GetIntArg("-ghostpolicy-maxtxoutputs", 0));
        }
        if (argsman.IsArgSet("-ghostpolicy-maxtxsize")) {
            tier.max_tx_size = static_cast<unsigned int>(argsman.GetIntArg("-ghostpolicy-maxtxsize", 0));
        }
        if (argsman.IsArgSet("-ghostpolicy-minfeerate")) {
            const std::string raw = argsman.GetArg("-ghostpolicy-minfeerate", "");
            errno = 0;
            char* end = nullptr;
            const double val = std::strtod(raw.c_str(), &end);
            if (raw.empty() || end != raw.c_str() + raw.size() || errno != 0 || val < 0) {
                return util::Error{Untranslated(strprintf("Invalid -ghostpolicy-minfeerate '%s' (expected a non-negative sat/vB value)", raw))};
            }
            tier.min_fee_rate = val;
        }
    }

    ApplyArgsManOptions(argsman, mempool_opts.limits);

    return {};
}

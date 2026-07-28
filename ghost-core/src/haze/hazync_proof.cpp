// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <haze/hazync_proof.h>

#include <common/args.h>
#include <logging.h>
#include <streams.h>
#include <tinyformat.h>
#include <util/strencodings.h>

#include <algorithm>
#include <fstream>
#include <span>

#ifdef WITH_HAZYNC_VERIFY
#include <hazync_verify.h>
#endif

namespace haze {

bool HazyncVerifyAvailable()
{
#ifdef WITH_HAZYNC_VERIFY
    return true;
#else
    return false;
#endif
}

std::string HazyncMethodId()
{
#ifdef WITH_HAZYNC_VERIFY
    const char* id = hazync_method_id();
    return id ? std::string{id} : std::string{};
#else
    return {};
#endif
}

std::string HazyncErrorString(int rc)
{
#ifdef WITH_HAZYNC_VERIFY
    switch (rc) {
    case HAZYNC_OK:                  return "ok";
    case HAZYNC_ERR_NULL:            return "empty or unreadable proof";
    case HAZYNC_ERR_PARSE:           return "not a Hazync receipt";
    case HAZYNC_ERR_PROOF:           return "PROOF INVALID for this guest — forged, tampered, corrupt, or built against a different guest";
    case HAZYNC_ERR_JOURNAL:         return "journal is not a RangeState";
    case HAZYNC_ERR_NOT_ANCHORED:    return "proof is valid but NOT genesis-anchored — it proves some arbitrary range, not the chain from genesis";
    case HAZYNC_ERR_SELF_ID:         return "journal self_id does not match the guest image id";
    case HAZYNC_ERR_KIND:            return "wrong domain tag — not a range proof";
    case HAZYNC_ERR_TOO_MANY_ROOTS:  return "more accumulator roots than the interface can carry";
    default:                         return strprintf("unknown verifier error %d", rc);
    }
#else
    return strprintf("built without Hazync proof support (rc %d)", rc);
#endif
}

std::optional<HazyncProofState> VerifyHazyncProof(const fs::path& proof_file, std::string& error_out)
{
#ifndef WITH_HAZYNC_VERIFY
    error_out = "this ghostd was built without Hazync proof support (-DWITH_HAZYNC_VERIFY=ON)";
    return std::nullopt;
#else
    std::ifstream f{proof_file, std::ios::binary};
    if (!f.good()) {
        error_out = strprintf("cannot read proof file %s", fs::PathToString(proof_file));
        return std::nullopt;
    }
    std::vector<uint8_t> buf{std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
    if (buf.empty()) {
        error_out = strprintf("proof file %s is empty", fs::PathToString(proof_file));
        return std::nullopt;
    }

    HazyncState st{};
    const int rc = hazync_verify_proof(buf.data(), buf.size(), &st);
    if (rc != HAZYNC_OK) {
        // On any non-zero return the FFI guarantees `st` was NOT written; do not read it.
        error_out = HazyncErrorString(rc);
        return std::nullopt;
    }

    HazyncProofState out;
    out.height = st.height;
    // The FFI hands back tip_hash in DISPLAY order (what getblockhash prints). uint256 stores
    // INTERNAL order and reverses again in GetHex(), so it must be reversed on the way in — otherwise
    // GetHex() prints the hash backwards and it silently fails to compare against a CBlockIndex hash.
    {
        std::array<unsigned char, 32> internal_order{};
        std::reverse_copy(std::begin(st.tip_hash), std::end(st.tip_hash), internal_order.begin());
        out.tip_hash = uint256{std::span<const unsigned char>{internal_order}};
    }
    out.cumulative_work_lo = st.cumulative_work_lo;
    out.cumulative_work_hi = st.cumulative_work_hi;
    out.utxo_leaves = st.utxo_leaves;
    out.next_bits = st.next_bits;
    out.epoch_start_time = st.epoch_start_time;
    out.prev_time = st.prev_time;
    for (uint32_t i = 0; i < st.root_count; ++i) {
        // Accumulator roots are already internal-order hashes; no reversal.
        out.utxo_roots.emplace_back(std::span<const unsigned char>{st.utxo_roots[i], 32});
    }
    return out;
#endif
}

void HazyncProofStartupCheck(const ArgsManager& args)
{
    const auto arg = args.GetArg("-hazyncproof", "");
    if (arg.empty()) return;

    if (!HazyncVerifyAvailable()) {
        LogWarning("-hazyncproof was given but this ghostd was built without Hazync proof support; "
                   "rebuild with -DWITH_HAZYNC_VERIFY=ON. Ignoring.\n");
        return;
    }

    const fs::path p{fs::PathFromString(arg)};
    std::string err;
    const auto st = VerifyHazyncProof(p, err);
    if (!st) {
        // Deliberately not fatal: this increment only REPORTS. A bad proof must be impossible to
        // miss in the log, but it cannot yet affect how this node validates anything.
        LogWarning("[hazync] proof %s REJECTED: %s\n", fs::PathToString(p), err);
        return;
    }

    LogInfo("[hazync] proof VERIFIED against guest %s\n", HazyncMethodId());
    LogInfo("[hazync]   genesis-anchored through height %u\n", st->height);
    LogInfo("[hazync]   tip            %s\n", st->tip_hash.GetHex());
    LogInfo("[hazync]   cumulative work %llu\n", (unsigned long long)st->cumulative_work_lo);
    LogInfo("[hazync]   UTXO set       %llu leaves, %u accumulator roots\n",
            (unsigned long long)st->utxo_leaves, (unsigned)st->utxo_roots.size());
    LogInfo("[hazync]   next-block target 0x%08x\n", st->next_bits);
    LogInfo("[hazync] NOT YET ACTED ON: this build verifies and reports only. Nothing is skipped and "
            "no chainstate is adopted — every block is still validated in full.\n");
}

} // namespace haze

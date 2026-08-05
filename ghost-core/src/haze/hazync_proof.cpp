// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <haze/hazync_proof.h>

#include <chainparams.h>
#include <coins.h>
#include <common/args.h>
#include <logging.h>
#include <node/utxo_snapshot.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <tinyformat.h>
#include <util/fs_helpers.h>
#include <util/strencodings.h>

#include <algorithm>
#include <array>
#include <cstring>
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
    case HAZYNC_ERR_DUMP_MAGIC:      return "not a Hazync UTXO dump (bad magic)";
    case HAZYNC_ERR_DUMP_VERSION:    return "unsupported UTXO dump version — regenerate it with a matching host";
    case HAZYNC_ERR_DUMP_HEIGHT:     return "UTXO dump is for a different height than the proof";
    case HAZYNC_ERR_DUMP_COUNT:      return "UTXO dump holds a different number of coins than the proof commits to";
    case HAZYNC_ERR_DUMP_TRUNC:      return "UTXO dump is truncated or has trailing bytes";
    case HAZYNC_ERR_DUMP_POS:        return "UTXO dump positions are not a permutation of 0..n-1 — it does not describe one accumulator";
    case HAZYNC_ERR_DUMP_ROOTS:      return "UTXO SET DOES NOT MATCH THE PROOF — rebuilt accumulator roots differ from the proven ones";
    default:                         return strprintf("unknown verifier error %d", rc);
    }
#else
    return strprintf("built without Hazync proof support (rc %d)", rc);
#endif
}

namespace {
//! Set once in HazyncProofStartupCheck during init, before the RPC server starts. See header.
std::optional<HazyncProofState> g_verified_proof;
//! Whether a -hazyncutxo dump was supplied AND matched the proof. Same single-write discipline.
bool g_utxo_dump_ok{false};
} // namespace

bool HazyncUtxoDumpMatched() { return g_utxo_dump_ok; }

const std::optional<HazyncProofState>& HazyncVerifiedProof() { return g_verified_proof; }

std::optional<HazyncProofState> VerifyHazyncProof(const fs::path& proof_file, std::string& error_out)
{
#ifndef WITH_HAZYNC_VERIFY
    error_out = "this ghostd was built without Hazync proof support (-DWITH_HAZYNC_VERIFY=ON)";
    return std::nullopt;
#else
    // Check the linked verifier's guest id BEFORE reading anything. A proof is only meaningful
    // relative to the guest that produced it, so a verifier built against a different guest cannot
    // answer the question being asked — regardless of what the proof file contains. Refusing here
    // rather than after verification keeps the failure unambiguous: it is the BUILD that is wrong.
    const std::string linked_id{HazyncMethodId()};
    if (linked_id != HAZYNC_EXPECTED_METHOD_ID) {
        error_out = strprintf(
            "linked Hazync verifier is for guest %s but this ghostd trusts %s — refusing to verify. "
            "The verifier and ghostd must be rebuilt together after a Hazync re-baseline.",
            linked_id.empty() ? "(none reported)" : linked_id,
            std::string{HAZYNC_EXPECTED_METHOD_ID});
        return std::nullopt;
    }

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

bool CheckHazyncUtxoDump(const fs::path& dump_file, const fs::path& proof_file, std::string& error_out)
{
#ifndef WITH_HAZYNC_VERIFY
    error_out = "this ghostd was built without Hazync proof support (-DWITH_HAZYNC_VERIFY=ON)";
    return false;
#else
    // Re-verify rather than trust a state handed in. See the header: the API deliberately offers no
    // way to check a dump against an unverified proof.
    std::ifstream pf{proof_file, std::ios::binary};
    if (!pf.good()) {
        error_out = strprintf("cannot read proof file %s", fs::PathToString(proof_file));
        return false;
    }
    std::vector<uint8_t> pbuf{std::istreambuf_iterator<char>(pf), std::istreambuf_iterator<char>()};

    HazyncState proven{};
    const int prc = hazync_verify_proof(pbuf.data(), pbuf.size(), &proven);
    if (prc != HAZYNC_OK) {
        error_out = strprintf("proof did not verify: %s", HazyncErrorString(prc));
        return false;
    }

    std::ifstream df{dump_file, std::ios::binary};
    if (!df.good()) {
        error_out = strprintf("cannot read UTXO dump %s", fs::PathToString(dump_file));
        return false;
    }
    std::vector<uint8_t> dbuf{std::istreambuf_iterator<char>(df), std::istreambuf_iterator<char>()};
    if (dbuf.empty()) {
        error_out = strprintf("UTXO dump %s is empty", fs::PathToString(dump_file));
        return false;
    }

    const int rc = hazync_check_utxo_dump(dbuf.data(), dbuf.size(), &proven);
    if (rc != HAZYNC_OK) {
        error_out = HazyncErrorString(rc);
        return false;
    }
    return true;
#endif
}

bool WriteCoreSnapshotFromDump(const fs::path& dump_file, const fs::path& out_file,
                               const uint256& base_blockhash, std::string& error_out)
{
    std::ifstream df{dump_file, std::ios::binary};
    if (!df.good()) {
        error_out = strprintf("cannot read UTXO dump %s", fs::PathToString(dump_file));
        return false;
    }
    const std::vector<uint8_t> b{std::istreambuf_iterator<char>(df), std::istreambuf_iterator<char>()};

    // Header: "HZUTXO\0\0" ‖ version ‖ height ‖ count. Mirrors `host dump-snapshot`.
    constexpr size_t HDR = 8 + 4 + 4 + 8;
    static const std::array<uint8_t, 8> kMagic{'H', 'Z', 'U', 'T', 'X', 'O', 0, 0};
    if (b.size() < HDR || !std::equal(kMagic.begin(), kMagic.end(), b.begin())) {
        error_out = "not a Hazync UTXO dump (bad magic)";
        return false;
    }
    auto rd32 = [&b](size_t o) { return uint32_t(b[o]) | uint32_t(b[o + 1]) << 8 | uint32_t(b[o + 2]) << 16 | uint32_t(b[o + 3]) << 24; };
    auto rd64 = [&rd32](size_t o) { return uint64_t(rd32(o)) | uint64_t(rd32(o + 4)) << 32; };
    if (rd32(8) != 1) { error_out = "unsupported UTXO dump version"; return false; }
    const uint64_t count = rd64(16);

    // The dump is sorted by (txid, vout), so Core's txid-grouped layout falls out of one sequential
    // pass — no buffering of the whole set, which matters at ~180M coins.
    AutoFile afile{fsbridge::fopen(out_file, "wb")};
    if (afile.IsNull()) {
        error_out = strprintf("cannot open %s for writing", fs::PathToString(out_file));
        return false;
    }
    node::SnapshotMetadata metadata{Params().MessageStart(), base_blockhash, count};
    afile << metadata;

    size_t o = HDR;
    uint64_t written = 0;
    std::vector<std::pair<uint32_t, Coin>> group;
    Txid group_txid;
    auto flush_group = [&]() {
        if (group.empty()) return;
        afile << group_txid;
        WriteCompactSize(afile, group.size());
        for (const auto& [n, coin] : group) {
            WriteCompactSize(afile, n);
            afile << coin;      // Core's own Coin serialiser — compression is never reimplemented here
            ++written;
        }
        group.clear();
    };

    for (uint64_t i = 0; i < count; ++i) {
        if (o + 61 > b.size()) { error_out = "UTXO dump is truncated"; return false; }
        uint256 txid_raw;
        std::memcpy(txid_raw.begin(), b.data() + o, 32);
        const Txid txid{Txid::FromUint256(txid_raw)};
        const uint32_t vout = rd32(o + 32);
        const uint64_t value = rd64(o + 36);
        const uint32_t height = rd32(o + 44);
        const bool is_cb = b[o + 48] != 0;
        // o+49 coin_mtp and o+53 position are accumulator inputs; Core's snapshot carries neither.
        const uint32_t spk_len = rd32(o + 57);
        o += 61;
        if (o + spk_len > b.size()) { error_out = "UTXO dump is truncated"; return false; }
        CScript spk{b.data() + o, b.data() + o + spk_len};
        o += spk_len;

        if (!group.empty() && txid != group_txid) flush_group();
        group_txid = txid;
        group.emplace_back(vout, Coin{CTxOut{CAmount(value), std::move(spk)}, int(height), is_cb});
    }
    flush_group();

    if (o != b.size()) { error_out = "UTXO dump has trailing bytes"; return false; }
    if (written != count) {
        error_out = strprintf("wrote %llu coins but the dump declared %llu",
                              (unsigned long long)written, (unsigned long long)count);
        return false;
    }
    if (afile.fclose() != 0) {
        error_out = strprintf("failed to close %s", fs::PathToString(out_file));
        return false;
    }
    return true;
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

    g_verified_proof = st;

    LogInfo("[hazync] proof VERIFIED against guest %s\n", HazyncMethodId());
    LogInfo("[hazync]   genesis-anchored through height %u\n", st->height);
    LogInfo("[hazync]   tip            %s\n", st->tip_hash.GetHex());
    LogInfo("[hazync]   cumulative work %llu\n", (unsigned long long)st->cumulative_work_lo);
    LogInfo("[hazync]   UTXO set       %llu leaves, %u accumulator roots\n",
            (unsigned long long)st->utxo_leaves, (unsigned)st->utxo_roots.size());
    LogInfo("[hazync]   next-block target 0x%08x\n", st->next_bits);
    // -hazyncutxo is optional and only meaningful alongside a proof: a UTXO dump on its own has
    // nothing to be checked against, which is precisely the trusted-snapshot situation this avoids.
    const auto utxo_arg = args.GetArg("-hazyncutxo", "");
    if (!utxo_arg.empty()) {
        const fs::path up{fs::PathFromString(utxo_arg)};
        std::string uerr;
        if (CheckHazyncUtxoDump(up, p, uerr)) {
            g_utxo_dump_ok = true;
            LogInfo("[hazync]   UTXO dump %s MATCHES the proven set (%llu coins)\n",
                    fs::PathToString(up), (unsigned long long)st->utxo_leaves);

            // Only reachable once the dump has been checked against the proof. Converting an
            // unchecked dump would emit a well-formed snapshot of an unproven UTXO set — exactly
            // what trusted assumeutxo already does, and what this exists to replace.
            const auto snap_arg = args.GetArg("-hazyncsnapshotout", "");
            if (!snap_arg.empty()) {
                const fs::path sp{fs::PathFromString(snap_arg)};
                std::string serr;
                if (WriteCoreSnapshotFromDump(up, sp, st->tip_hash, serr)) {
                    LogInfo("[hazync]   wrote a loadtxoutset snapshot of the PROVEN set to %s\n",
                            fs::PathToString(sp));
                } else {
                    LogWarning("[hazync] could not write snapshot %s: %s\n", fs::PathToString(sp), serr);
                }
            }
        } else {
            // Not fatal in a report-only build, but it must be impossible to miss: this is the
            // check that would otherwise let an unproven UTXO set in.
            LogWarning("[hazync] UTXO dump %s REJECTED: %s\n", fs::PathToString(up), uerr);
        }
    }

    LogInfo("[hazync] NOT YET ACTED ON: this build verifies and reports only. Nothing is skipped and "
            "no chainstate is adopted — every block is still validated in full.\n");
}

} // namespace haze

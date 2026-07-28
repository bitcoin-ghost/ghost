// Copyright (c) 2026 The Bitcoin Ghost developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_HAZE_HAZYNC_PROOF_H
#define BITCOIN_HAZE_HAZYNC_PROOF_H

#include <uint256.h>
#include <util/fs.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

class ArgsManager;

namespace haze {

/**
 * Hazync proof adoption — the INBOUND direction.
 *
 * hazync_witness.{h,cpp} is the outbound half: ghostd emits per-block witnesses so the external
 * Hazync zkVM prover can prove blocks under real consensus. This is the return path — ghostd
 * *consuming* a proof that those blocks were valid.
 *
 * Why that matters for a hazed node: haze permanently destroys witnesses and scriptSigs, so a hazed
 * archive can establish what its transactions WERE (merkle root over retained txids, checked against
 * the header) but never that they were VALID. A Hazync proof supplies exactly the missing half —
 * identity from the chain, validity from the proof.
 *
 * ── SCOPE OF THIS INCREMENT ────────────────────────────────────────────────────────────────────
 * Verify and REPORT. Nothing here changes consensus behaviour, skips validation, or alters the
 * chainstate. It exists so the verification path can be exercised, reviewed and trusted before
 * anything is allowed to act on its result. Adopting proven state during IBD is a separate change.
 *
 * Verification is delegated to the Rust implementation in the hazync repo via a C ABI
 * (hazync-verify-ffi). It is NOT reimplemented here: verifying a risc0 receipt means Groth16 over
 * BN254 plus risc0's receipt and claim format, and a second implementation in C++ would be a large
 * body of consensus-critical code that would inevitably drift from the one CI exercises.
 */
struct HazyncProofState {
    uint32_t height{0};
    uint256 tip_hash;                    //!< display order, comparable with CBlockIndex::GetBlockHash()
    uint64_t cumulative_work_lo{0};
    uint64_t cumulative_work_hi{0};
    uint64_t utxo_leaves{0};
    uint32_t next_bits{0};
    uint32_t epoch_start_time{0};
    uint32_t prev_time{0};
    std::vector<uint256> utxo_roots;
};

/** Human-readable reason a proof was rejected, for logging. Never empty on failure. */
std::string HazyncErrorString(int rc);

/**
 * Verify a genesis-anchored Hazync proof from disk.
 *
 * @return the committed state on success; std::nullopt on ANY failure — including a valid proof that
 *         is not genesis-anchored. There is deliberately no "verified but unanchored" success case:
 *         a caller that forgot to check a separate flag would adopt a fabricated anchor.
 */
std::optional<HazyncProofState> VerifyHazyncProof(const fs::path& proof_file, std::string& error_out);

/** Guest image id this build trusts, or empty if the verifier is not compiled in. */
std::string HazyncMethodId();

/** Is proof support compiled in? False when built without -DWITH_HAZYNC_VERIFY. */
bool HazyncVerifyAvailable();

/** Handle -hazyncproof=<file> at startup: verify, log the adopted state, and report. */
void HazyncProofStartupCheck(const ArgsManager& args);

} // namespace haze

#endif // BITCOIN_HAZE_HAZYNC_PROOF_H

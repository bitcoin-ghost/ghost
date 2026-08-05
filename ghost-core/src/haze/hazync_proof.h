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
/**
 * The guest image id this ghostd is willing to trust.
 *
 * A Hazync proof is only meaningful relative to the guest that produced it: a different guest is a
 * different consensus program, and a proof under a superseded id proves nothing about this chain.
 * The linked verifier reports the id it was BUILT with, so without pinning, linking an older
 * libhazync_verify.a would make ghostd silently honour proofs under a retired guest — and say
 * "VERIFIED" while doing it.
 *
 * ⚠ This must be updated in lockstep with a Hazync re-baseline, together with hazync's
 * reproduce/METHOD_ID. scripts/check-hazync-guest-id.sh fails the build when the two disagree.
 */
inline constexpr std::string_view HAZYNC_EXPECTED_METHOD_ID{
    "4722cec826239c1b3a3598bbac284376cc7b920c9bcd9863fa34f40c9ea7bbae"};

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

/**
 * Check that a bridge UTXO dump is exactly the set `proven` commits to.
 *
 * This is the step that makes assumeutxo PROVEN rather than trusted. Core's `loadtxoutset` checks a
 * snapshot against a hash compiled into the binary by its developers; this checks one against the
 * accumulator roots a zk proof attests to, so the trust rests on "these blocks were valid under real
 * consensus" instead of "someone we trust picked this hash".
 *
 * Takes the PROOF FILE rather than an already-parsed state, deliberately: a caller cannot then check
 * a dump against a state that was never verified, because the API gives them no way to supply one.
 * Re-verifying costs about a second at startup, which is nothing against the cost of that mistake.
 *
 * SCOPE: reports only. Nothing is loaded into a chainstate — that is a separate change and must not
 * land before this path has been reviewed and exercised.
 */
bool CheckHazyncUtxoDump(const fs::path& dump_file, const fs::path& proof_file,
                         std::string& error_out);

/** Guest image id this build trusts, or empty if the verifier is not compiled in. */
std::string HazyncMethodId();

/** Is proof support compiled in? False when built without -DWITH_HAZYNC_VERIFY. */
bool HazyncVerifyAvailable();

/** Handle -hazyncproof=<file> at startup: verify, log the adopted state, and report. */
void HazyncProofStartupCheck(const ArgsManager& args);

/**
 * The proof this node verified at startup, or nullopt if none was given or it was refused.
 *
 * Set once during init, before the RPC server accepts connections, and never mutated afterwards —
 * so readers need no lock. An operator must be able to ask a RUNNING node whether it is relying on
 * a proof; a line in a startup log that has since scrolled away is not an answer.
 */
const std::optional<HazyncProofState>& HazyncVerifiedProof();

/** True only if a -hazyncutxo dump was supplied AND matched the proven accumulator roots. */
bool HazyncUtxoDumpMatched();

} // namespace haze

#endif // BITCOIN_HAZE_HAZYNC_PROOF_H

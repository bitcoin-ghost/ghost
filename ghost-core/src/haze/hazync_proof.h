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
class ChainstateManager;

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
 * ── SCOPE ──────────────────────────────────────────────────────────────────────────────────────
 * Verifying and reporting is unconditional and changes nothing. ADOPTION — loading the proven UTXO
 * set as a chainstate and validating onward from there — is off unless the operator arms it with
 * -hazyncadopt and then asks for it explicitly over RPC, and is unreachable unless the proof
 * verified and the dump matched. See HazyncAdoption below for how that is enforced rather than
 * merely intended.
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

/**
 * Convert a Hazync bridge UTXO dump into a snapshot in Core's own `loadtxoutset` format.
 *
 * The dump is deliberately uncompressed and Core-format-agnostic, so that the emitter (Rust, in the
 * hazync repo) never has to reproduce `CTxOutCompressor` byte-for-byte. The conversion happens here
 * instead, using Core's own serialisers — one implementation of that format, in the project that
 * owns it.
 *
 * Call this only for a dump that has already passed CheckHazyncUtxoDump. Converting an unchecked
 * dump produces a well-formed snapshot of an unproven UTXO set, which is precisely the thing
 * `assumeutxo` already does and this exists to replace.
 *
 * `base_blockhash` must be the block hash at the dump's height — take it from the proof.
 */
bool WriteCoreSnapshotFromDump(const fs::path& dump_file, const fs::path& out_file,
                               const uint256& base_blockhash, std::string& error_out);

/**
 * Authority to load a UTXO set at a height chainparams knows nothing about.
 *
 * Core's `assumeutxo` will only load a snapshot whose height its developers compiled into the
 * binary, and it checks the coins against a hash they chose. This type replaces both halves of that
 * arrangement: a set is admitted because a zk proof attests the chain to that height was valid under
 * real consensus, and because that same set was shown to be exactly the one the proof commits to.
 *
 * The constructor is private, so the only way to obtain one is Authorise(), which returns nullopt
 * unless adoption was explicitly armed, the proof verified AND the dump matched. Holding one is
 * therefore evidence those checks ran. This is the point of the type: the checks cannot be skipped
 * by a caller who simply forgot them, because there is no other way to name the thing they gate.
 */
class HazyncAdoption
{
public:
    /**
     * Re-derive the authority from the configured proof and dump.
     *
     * Deliberately re-runs verification rather than caching a verdict: an authority is only ever a
     * statement about files as they are NOW, and re-reading them costs about a second.
     *
     * @return nullopt with `error_out` set whenever adoption is not authorised — including the
     *         ordinary case of it simply not being armed, which is not an error condition.
     */
    static std::optional<HazyncAdoption> Authorise(const ArgsManager& args, std::string& error_out);

    uint256 base_blockhash;  //!< internal order, so it compares with CBlockIndex::GetBlockHash()
    int height{0};
    uint64_t coins_count{0}; //!< leaves in the proven accumulator; the snapshot must hold exactly this many

    /**
     * Bootstrap value for CBlockIndex::m_chain_tx_count at the base block.
     *
     * ⚠ This is NOT a proven transaction count — the guest's RangeState commits no such figure, so
     * there is none to adopt. It is `height + 1`, a genuine LOWER BOUND (every block carries at
     * least a coinbase), chosen over a plausible-looking guess because a fabricated number here
     * would be indistinguishable from a proven one.
     *
     * Only its NON-ZERO-ness is load-bearing: CBlockIndex::HaveNumChainTxs() gates entry to
     * setBlockIndexCandidates, and CheckBlockIndex asserts the snapshot base has it set. The
     * magnitude feeds GuessVerificationProgress alone, which is reporting only — so a node that
     * adopts a proof UNDER-REPORTS `verificationprogress` until the background chain catches up.
     * The fix is a transaction count in the guest journal, which costs a METHOD_ID re-baseline and
     * should ride along with the next one rather than force its own.
     */
    uint64_t chain_tx_count_bootstrap{0};

private:
    HazyncAdoption() = default;
};

/**
 * The adoption authority this node was started with, or nullopt if adoption was not armed or its
 * preconditions did not hold.
 *
 * Set once during init before the chainstate is loaded, and never mutated — same discipline as
 * HazyncVerifiedProof(), and for the same reason: readers need no lock.
 *
 * ⚠ This is the AMBIENT authority, used where a call chain cannot carry one: bootstrapping snapshot
 * metadata on restart, and deciding there is no background validation left to complete. It is
 * deliberately NOT what admits coins — ActivateSnapshot takes an explicit HazyncAdoption pointer, so
 * `loadtxoutset` cannot pick this up by accident and load an arbitrary file on a proof's authority.
 */
const std::optional<HazyncAdoption>& HazyncAdoptedSnapshot();

/** Outcome of binding a hazed archive to a proof. See VerifyHazedChainBinding. */
struct HazedChainBinding {
    int from_height{0};        //!< first height checked
    int through_height{0};     //!< last height checked, always the proven height
    int blocks_checked{0};
    bool complete{false};      //!< true only when every block from 1 was checked
    uint256 archive_tip;       //!< tip the archive itself yields at through_height
    std::string failure;       //!< empty on success; never empty on failure
};

/**
 * Establish, from a hazed archive alone, that the chain it holds is the real chain — and that it ends
 * where a verified proof says it does.
 *
 * This is the half a proof cannot supply. A proof attests that the transactions in a range were
 * VALID; it says nothing about whether this node is holding that range. A hazed archive can answer
 * that and only that: stripping destroys witnesses and scriptSigs but keeps the txids, and a txid
 * that had to be stored verbatim is not taken on trust, because the merkle root is recomputed from
 * whatever txids the block yields and must match the header. A forged stored txid fails there.
 *
 * So: identity from the archive, validity from the proof, and this function is the join. It
 * recomputes every merkle root from the archive's own retained txids, checks each header links to its
 * parent and meets its stated target, and finally requires that the tip the archive yields at the
 * proven height equals the tip the proof commits to.
 *
 * **It refuses when the proof does not commit to the tip held.** That is the point of the check, not
 * an error path: a proof about some other chain must not be reported as evidence about this one.
 *
 * @param from_height  1 to establish the whole chain. A higher value checks only a suffix, which is
 *                     cheaper and proves correspondingly less — `complete` records which was done.
 * @return true if the binding holds. On false, `out.failure` says which block failed and how.
 */
bool VerifyHazedChainBinding(ChainstateManager& chainman, const HazyncProofState& proven,
                             int from_height, HazedChainBinding& out);

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

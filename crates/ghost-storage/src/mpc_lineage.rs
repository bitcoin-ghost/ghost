//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| FILE: mpc_lineage.rs                                                                                                |
//|======================================================================================================================|

//! Genesis-anchored MPC lineage verification (Stage C).
//!
//! This is the replacement for the static *current-params* file-hash pin during
//! the rolling ceremony. Instead of trusting a single pinned SHA-256 of the
//! current params (which changes every contribution and so cannot be pinned
//! while rolling), a node validates the EVOLVING setup from an IMMUTABLE trust
//! root — the genesis lineage anchor — plus the recorded lineage chain and a
//! retained BFT quorum per position. The retained quorum is what lets a node
//! trust positions it did not personally witness WITHOUT keeping every
//! historical multi-hundred-megabyte parameter blob: it keeps only the head
//! params on disk, plus the cheap contribution rows + vote signatures.
//!
//! # The check (fail-closed)
//!
//! Given the immutable `genesis_anchor` (a LINEAGE hash = `hash_parameters` of
//! the genesis params = `mpc_contributions[1].prev_params_hash`) and the
//! `head_lineage` (= `hash_parameters` of the on-disk current params):
//!
//! 1. The chain rows are exactly positions `1..=N`, contiguous.
//! 2. `contributions[1].prev == genesis_anchor`            (anchor to the root).
//! 3. `contributions[i].prev == contributions[i-1].new`    (lineage intact).
//! 4. `contributions[N].new == head_lineage`               (on-disk head matches).
//! 5. For each position `i >= 2`, a stored BFT quorum of VALID approve-vote
//!    signatures from the then-eligible elder set (contributors at positions
//!    `< i`) exists — `>= mpc_bft_threshold(i-1)` distinct valid voters.
//!    Position 1 (genesis) has no electorate and is trusted solely via the
//!    immutable anchor (step 2).
//!
//! Accept only if ALL hold; otherwise FAIL-CLOSED.
//!
//! # No forge window
//!
//! To make a node accept forged params as its head, an attacker must defeat ALL
//! of the above. Swapping the on-disk head changes `head_lineage` (step 4), so
//! they must also rewrite `contributions[N].new`, which breaks the chain link
//! (step 3) unless they rewrite the whole chain back to `contributions[1].prev`
//! — which is pinned to the immutable anchor (step 2). A full alternate chain
//! additionally needs, at every position, `>= 67%` (steady state) genuine elder
//! signatures over `contribution_hash(contributor, position, new_params_hash)`
//! (step 5). Each such signature was only ever produced by an elder that itself
//! ran `verify_contribution` (Schnorr + h/l pairing) before approving. So the
//! attacker's only options are: (a) produce params that pass
//! `verify_contribution` — a GENUINE valid transform, which preserves 1-of-N and
//! is harmless; (b) forge `>=` quorum elder signatures — needs `> quorum` key
//! compromise; or (c) break SHA-256 / the anchor. There is no fourth path.

use crate::queries::MpcVerificationVote;
use ghost_common::error::{GhostError, GhostResult};
use ghost_common::identity::verify_signature;
use ghost_common::mpc::{contribution_hash, mpc_bft_threshold, vote_signing_message};
use ghost_common::types::NodeId;
use std::collections::HashSet;

/// One contribution row reduced to the fields the lineage check needs.
#[derive(Debug, Clone)]
pub struct ContribLineageRow {
    pub position: u32,
    /// Contributor (candidate) public key / node id, decoded to bytes.
    pub contributor: NodeId,
    pub prev_params_hash: [u8; 32],
    pub new_params_hash: [u8; 32],
}

/// One retained vote reduced to what the quorum check needs.
#[derive(Debug, Clone)]
pub struct VoteLineageRow {
    pub voter: NodeId,
    pub approve: bool,
    pub signature: [u8; 64],
}

/// Why a genesis-anchored lineage verification failed. Every variant is a hard,
/// fail-closed rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineageError {
    /// Contributions exist but no head params were loaded to cross-check.
    MissingHead,
    /// The chain rows are not the contiguous set `1..=N` (gap/duplicate).
    NonContiguousChain { expected: u32, found: u32 },
    /// `contributions[1].prev != genesis_anchor` — not rooted at the trust anchor.
    AnchorMismatch,
    /// `contributions[i].prev != contributions[i-1].new` — lineage broken.
    ChainBreak { position: u32 },
    /// `contributions[N].new != head_lineage` — on-disk head out of step.
    HeadMismatch,
    /// Position `i` lacks a retained BFT quorum of valid approve signatures.
    QuorumNotMet {
        position: u32,
        valid: u32,
        required: u32,
    },
}

impl std::fmt::Display for LineageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LineageError::MissingHead => write!(
                f,
                "on-disk head params are not loaded but the chain has contributions"
            ),
            LineageError::NonContiguousChain { expected, found } => write!(
                f,
                "contribution chain is not contiguous: expected position {expected}, found {found}"
            ),
            LineageError::AnchorMismatch => {
                write!(f, "contributions[1].prev does not equal the genesis anchor")
            }
            LineageError::ChainBreak { position } => {
                write!(
                    f,
                    "lineage break at position {position} (prev != previous.new)"
                )
            }
            LineageError::HeadMismatch => {
                write!(
                    f,
                    "on-disk head lineage hash does not match contributions[N].new"
                )
            }
            LineageError::QuorumNotMet {
                position,
                valid,
                required,
            } => write!(
                f,
                "position {position} has only {valid} valid approve signatures, needs {required}"
            ),
        }
    }
}

/// PURE genesis-anchored lineage verification.
///
/// `contributions` must be ALL recorded contributions (any order). `votes_for`
/// returns the retained votes for a given position. `head_lineage` is the
/// `hash_parameters` of the on-disk current params (`None` if not loaded).
///
/// Returns `Ok(n)` where `n` is the verified chain length, or `Err(LineageError)`
/// (fail-closed). With `n == 0` (no contributions) the chain is trivially valid
/// only when there is no head, or the head equals the genesis anchor (a
/// genesis-forming / pre-rolling node holding only the genesis params).
pub fn verify_genesis_anchored_chain<'a>(
    genesis_anchor: &[u8; 32],
    head_lineage: Option<&[u8; 32]>,
    contributions: &'a [ContribLineageRow],
    mut votes_for: impl FnMut(u32) -> &'a [VoteLineageRow],
) -> Result<u32, LineageError> {
    let n = contributions.len() as u32;

    if n == 0 {
        // Pre-genesis / genesis-forming. Nothing applied to cross-check.
        return match head_lineage {
            None => Ok(0),
            Some(h) if h == genesis_anchor => Ok(0),
            Some(_) => Err(LineageError::AnchorMismatch),
        };
    }

    // Index by position and require the contiguous set 1..=N.
    let mut by_pos: Vec<Option<&ContribLineageRow>> = vec![None; (n + 1) as usize];
    for c in contributions {
        if c.position == 0 || c.position > n {
            return Err(LineageError::NonContiguousChain {
                expected: n,
                found: c.position,
            });
        }
        let slot = &mut by_pos[c.position as usize];
        if slot.is_some() {
            // Duplicate position.
            return Err(LineageError::NonContiguousChain {
                expected: c.position,
                found: c.position,
            });
        }
        *slot = Some(c);
    }
    for pos in 1..=n {
        if by_pos[pos as usize].is_none() {
            return Err(LineageError::NonContiguousChain {
                expected: pos,
                found: 0,
            });
        }
    }

    // Step 2: anchor.
    let first = by_pos[1].unwrap();
    if &first.prev_params_hash != genesis_anchor {
        return Err(LineageError::AnchorMismatch);
    }

    // Step 3: lineage links.
    for pos in 2..=n {
        let cur = by_pos[pos as usize].unwrap();
        let prev = by_pos[(pos - 1) as usize].unwrap();
        if cur.prev_params_hash != prev.new_params_hash {
            return Err(LineageError::ChainBreak { position: pos });
        }
    }

    // Step 4: head match.
    let head = head_lineage.ok_or(LineageError::MissingHead)?;
    let last = by_pos[n as usize].unwrap();
    if &last.new_params_hash != head {
        return Err(LineageError::HeadMismatch);
    }

    // Step 5: retained BFT quorum per position (i >= 2). Eligible voters for
    // position i are the contributors at positions 1..i-1 (the elder set that
    // existed when i was voted on). Position 1 (genesis) has no electorate and is
    // trusted via the anchor alone.
    let mut eligible: HashSet<NodeId> = HashSet::new();
    eligible.insert(first.contributor); // contributor #1 becomes eligible for #2+
    for pos in 2..=n {
        let cur = by_pos[pos as usize].unwrap();
        let eligible_count = pos - 1; // contributors 1..=pos-1
        let required = mpc_bft_threshold(eligible_count);

        // The message every honest elder signed to approve THIS contribution.
        let ch = contribution_hash(&cur.contributor, pos, &cur.new_params_hash);
        let approve_msg = vote_signing_message(&ch, true);

        let mut counted: HashSet<NodeId> = HashSet::new();
        for v in votes_for(pos) {
            if !v.approve {
                continue;
            }
            if !eligible.contains(&v.voter) {
                continue; // vote from a non-elder (or future elder) does not count
            }
            if counted.contains(&v.voter) {
                continue; // one vote per voter
            }
            match verify_signature(&v.voter, &approve_msg, &v.signature) {
                Ok(true) => {
                    counted.insert(v.voter);
                }
                _ => continue, // invalid signature does not count
            }
        }

        let valid = counted.len() as u32;
        if valid < required {
            return Err(LineageError::QuorumNotMet {
                position: pos,
                valid,
                required,
            });
        }

        // This contributor joins the eligible set for later positions.
        eligible.insert(cur.contributor);
    }

    Ok(n)
}

/// Map a DB vote row into the lineage-check shape, dropping malformed signatures.
fn vote_row(v: &MpcVerificationVote) -> Option<VoteLineageRow> {
    let voter = hex::decode(&v.voter_node_id)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())?;
    let signature = <[u8; 64]>::try_from(v.signature.as_slice()).ok()?;
    Some(VoteLineageRow {
        voter,
        approve: v.approve,
        signature,
    })
}

impl crate::Database {
    /// Genesis-anchored startup verification (Stage C task 2), DB-driven.
    ///
    /// Loads the ordered contribution chain + retained votes from the database
    /// and runs [`verify_genesis_anchored_chain`] against the immutable
    /// `genesis_anchor` and the supplied `head_lineage` (the `hash_parameters`
    /// of the on-disk current params, or `None` if not loaded). Returns the
    /// verified chain length on success; fail-closed `Err` otherwise.
    pub fn verify_mpc_genesis_anchored_lineage(
        &self,
        genesis_anchor: &[u8; 32],
        head_lineage: Option<&[u8; 32]>,
    ) -> GhostResult<u32> {
        // Load the chain.
        let max = self.get_mpc_max_contribution_position()?.unwrap_or(0);
        let mut rows: Vec<ContribLineageRow> = Vec::with_capacity(max as usize);
        for pos in 1..=max {
            let rec = self.get_mpc_contribution(pos)?.ok_or_else(|| {
                GhostError::Database(format!(
                    "MPC lineage: contribution row {pos} missing (chain gap)"
                ))
            })?;
            let contributor = hex::decode(&rec.contributor_node_id)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                .ok_or_else(|| {
                    GhostError::Database(format!(
                        "MPC lineage: contributor_node_id at position {pos} is not a 32-byte hex node id"
                    ))
                })?;
            rows.push(ContribLineageRow {
                position: pos,
                contributor,
                prev_params_hash: rec.prev_params_hash,
                new_params_hash: rec.new_params_hash,
            });
        }

        // Pre-load votes per position (decoded), so the closure is allocation-free.
        let mut votes_by_pos: Vec<Vec<VoteLineageRow>> = vec![Vec::new(); (max + 1) as usize];
        for pos in 1..=max {
            let raw = self.get_mpc_votes(pos)?;
            votes_by_pos[pos as usize] = raw.iter().filter_map(vote_row).collect();
        }
        let empty: Vec<VoteLineageRow> = Vec::new();

        verify_genesis_anchored_chain(genesis_anchor, head_lineage, &rows, |pos| {
            votes_by_pos
                .get(pos as usize)
                .map(|v| v.as_slice())
                .unwrap_or(empty.as_slice())
        })
        .map_err(|e| GhostError::Database(format!("MPC genesis-anchored lineage FAILED: {e}")))
    }

    /// Stage C task 5: true-up the `mpc_ceremony` singleton to the verified head.
    ///
    /// A node that abstained on some position (could not fetch it then) may carry
    /// a lagged singleton. After the lineage+quorum verification succeeds, this
    /// reconciles `contribution_count` / `current_params_hash` to match the
    /// verified on-disk head + chain length. Other singleton fields (ceremony_id,
    /// ossified, vk hashes) are PRESERVED. No-op when already in step; creates the
    /// singleton if absent (using the genesis anchor as `ceremony_id`).
    pub fn reconcile_mpc_singleton_to_head(
        &self,
        verified_count: u32,
        verified_head: &[u8; 32],
        genesis_anchor: &[u8; 32],
        updated_at: u64,
    ) -> GhostResult<bool> {
        let existing = self.get_mpc_ceremony_state()?;
        match existing {
            Some(state) => {
                if state.contribution_count == verified_count
                    && &state.current_params_hash == verified_head
                {
                    return Ok(false); // already in step
                }
                let mut new_state = state.clone();
                new_state.contribution_count = verified_count;
                new_state.current_params_hash = *verified_head;
                if new_state.updated_at < updated_at {
                    new_state.updated_at = updated_at;
                }
                // Preserve a valid ceremony_id; backfill from the anchor if missing.
                if new_state.ceremony_id == [0u8; 32] {
                    new_state.ceremony_id = *genesis_anchor;
                }
                self.save_mpc_ceremony_state(&new_state)?;
                Ok(true)
            }
            None => {
                let new_state = crate::queries::MpcCeremonyState {
                    contribution_count: verified_count,
                    current_params_hash: *verified_head,
                    is_ossified: verified_count >= 101,
                    ossified_at: None,
                    block_vk_hash: None,
                    payout_vk_hash: None,
                    updated_at,
                    ceremony_id: *genesis_anchor,
                    // The file-hash pin is latched separately by the startup path
                    // (which has the on-disk params to hash); reconcile only
                    // records the verified lineage head + length here.
                    ossified_file_hash: None,
                };
                self.save_mpc_ceremony_state(&new_state)?;
                Ok(true)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::identity::NodeIdentity;

    const ANCHOR: [u8; 32] = [0xC9; 32];

    /// A fully-built, internally-consistent chain of `n` contributions with the
    /// retained approve votes for every position `>= 2` from ALL then-eligible
    /// elders. This is the genesis-anchored happy path.
    struct Chain {
        contribs: Vec<ContribLineageRow>, // positions 1..=n (index 0 = pos1)
        votes: Vec<Vec<VoteLineageRow>>,  // indexed by position; [0] unused
        head: [u8; 32],
    }

    impl Chain {
        fn votes_for(&self, pos: u32) -> &[VoteLineageRow] {
            self.votes
                .get(pos as usize)
                .map(|v| v.as_slice())
                .unwrap_or(&[])
        }
    }

    fn tag(pos: u32) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = pos as u8;
        a[1] = 0xAB;
        a[2] = (pos >> 8) as u8;
        a
    }

    fn build_valid_chain(n: u32) -> Chain {
        let mut identities: Vec<NodeIdentity> = Vec::new();
        let mut contribs: Vec<ContribLineageRow> = Vec::new();
        let mut votes: Vec<Vec<VoteLineageRow>> = vec![Vec::new(); (n + 1) as usize];

        let mut prev = ANCHOR;
        for pos in 1..=n {
            let id = NodeIdentity::generate();
            let new = tag(pos);
            contribs.push(ContribLineageRow {
                position: pos,
                contributor: id.node_id(),
                prev_params_hash: prev,
                new_params_hash: new,
            });
            identities.push(id);
            prev = new;
        }

        // Build approve votes for positions 2..=n from all eligible elders
        // (contributors at positions 1..pos-1).
        for pos in 2..=n {
            let c = &contribs[(pos - 1) as usize];
            let ch = contribution_hash(&c.contributor, pos, &c.new_params_hash);
            let msg = vote_signing_message(&ch, true);
            let mut row = Vec::new();
            for elder in identities.iter().take((pos - 1) as usize) {
                row.push(VoteLineageRow {
                    voter: elder.node_id(),
                    approve: true,
                    signature: elder.sign(&msg),
                });
            }
            votes[pos as usize] = row;
        }

        let head = contribs[(n - 1) as usize].new_params_hash;
        let _ = &identities; // identities are only needed to produce the signatures above
        Chain {
            contribs,
            votes,
            head,
        }
    }

    fn run(chain: &Chain) -> Result<u32, LineageError> {
        verify_genesis_anchored_chain(&ANCHOR, Some(&chain.head), &chain.contribs, |p| {
            chain.votes_for(p)
        })
    }

    #[test]
    fn test_happy_path_passes() {
        // 6 positions (mirrors the live 6-node mesh) — spans bootstrap (2..4)
        // and supermajority (5,6).
        let chain = build_valid_chain(6);
        assert_eq!(run(&chain).unwrap(), 6);
    }

    #[test]
    fn test_empty_chain_with_no_head_ok() {
        let empty: Vec<ContribLineageRow> = Vec::new();
        assert_eq!(
            verify_genesis_anchored_chain(&ANCHOR, None, &empty, |_| &[]).unwrap(),
            0
        );
    }

    #[test]
    fn test_empty_chain_head_must_equal_anchor() {
        let empty: Vec<ContribLineageRow> = Vec::new();
        // Head == anchor (genesis params on disk) → ok.
        assert_eq!(
            verify_genesis_anchored_chain(&ANCHOR, Some(&ANCHOR), &empty, |_| &[]).unwrap(),
            0
        );
        // Head != anchor with no contributions → reject.
        let other = [0x77; 32];
        assert_eq!(
            verify_genesis_anchored_chain(&ANCHOR, Some(&other), &empty, |_| &[]),
            Err(LineageError::AnchorMismatch)
        );
    }

    #[test]
    fn test_anchor_mismatch_fails_closed() {
        let mut chain = build_valid_chain(5);
        chain.contribs[0].prev_params_hash = [0xEE; 32]; // not the anchor
        assert_eq!(run(&chain), Err(LineageError::AnchorMismatch));
    }

    #[test]
    fn test_broken_lineage_link_fails_closed() {
        let mut chain = build_valid_chain(5);
        // Break the link into position 4.
        chain.contribs[3].prev_params_hash = [0x12; 32];
        assert_eq!(run(&chain), Err(LineageError::ChainBreak { position: 4 }));
    }

    #[test]
    fn test_head_mismatch_fails_closed() {
        let chain = build_valid_chain(5);
        let forged_head = [0x99; 32];
        let res =
            verify_genesis_anchored_chain(&ANCHOR, Some(&forged_head), &chain.contribs, |p| {
                chain.votes_for(p)
            });
        assert_eq!(res, Err(LineageError::HeadMismatch));
    }

    #[test]
    fn test_missing_head_when_contributions_exist_fails_closed() {
        let chain = build_valid_chain(3);
        let res =
            verify_genesis_anchored_chain(&ANCHOR, None, &chain.contribs, |p| chain.votes_for(p));
        assert_eq!(res, Err(LineageError::MissingHead));
    }

    #[test]
    fn test_missing_quorum_position_fails_closed() {
        let mut chain = build_valid_chain(6);
        // Remove ALL retained votes for position 5 (a supermajority position).
        chain.votes[5].clear();
        match run(&chain) {
            Err(LineageError::QuorumNotMet {
                position,
                valid,
                required,
            }) => {
                assert_eq!(position, 5);
                assert_eq!(valid, 0);
                assert_eq!(required, mpc_bft_threshold(4)); // = 3
            }
            other => panic!("expected QuorumNotMet at 5, got {other:?}"),
        }
    }

    #[test]
    fn test_non_contiguous_chain_fails_closed() {
        let mut chain = build_valid_chain(4);
        // Drop position 3 — leaves a gap (positions 1,2,4 → length 3 but pos 4 > n).
        chain.contribs.remove(2);
        let res = verify_genesis_anchored_chain(&ANCHOR, Some(&chain.head), &chain.contribs, |p| {
            chain.votes_for(p)
        });
        assert!(matches!(res, Err(LineageError::NonContiguousChain { .. })));
    }

    // ---- NO-FORGE proofs ----

    /// Forging the head's `new_params_hash` (and pointing `head_lineage` at it)
    /// passes the head-match and chain-link checks for the LAST position only if
    /// the attacker rewrites `contributions[N].new`. But the retained approve
    /// signatures for position N were signed over the ORIGINAL new hash, so the
    /// quorum recomputed over the forged hash no longer verifies → rejected.
    /// This proves a head swap cannot be laundered through the lineage.
    #[test]
    fn test_no_forge_faked_head_lineage_breaks_quorum() {
        let mut chain = build_valid_chain(6);
        let forged = [0x5A; 32];
        // Rewrite the recorded head row to the forged value AND point head at it,
        // so the anchor, all links, and the head-match all still hold.
        let last = chain.contribs.len() - 1;
        chain.contribs[last].new_params_hash = forged;
        chain.head = forged;
        // The links are intact (we only changed the terminal .new, which nothing
        // chains from), and head==contribs[N].new, so steps 2-4 pass …
        match run(&chain) {
            // … but the position-6 approve signatures were over the real hash, so
            // the quorum over the forged hash collapses to zero valid votes.
            Err(LineageError::QuorumNotMet {
                position, valid, ..
            }) => {
                assert_eq!(position, 6);
                assert_eq!(valid, 0, "forged head invalidates every retained signature");
            }
            other => panic!("expected QuorumNotMet at 6 for forged head, got {other:?}"),
        }
    }

    /// A head that is a structurally-fine new position (valid chain link) but
    /// carries NO quorum signatures is rejected — hash/lineage continuity is
    /// never sufficient on its own.
    #[test]
    fn test_no_forge_valid_link_without_quorum_rejected() {
        let mut chain = build_valid_chain(5);
        // Append a 6th position that chains correctly but has zero votes.
        let attacker = NodeIdentity::generate();
        let new6 = tag(6);
        chain.contribs.push(ContribLineageRow {
            position: 6,
            contributor: attacker.node_id(),
            prev_params_hash: chain.contribs[4].new_params_hash, // valid link
            new_params_hash: new6,
        });
        chain.votes.push(Vec::new()); // no votes for position 6
        chain.head = new6;
        match run(&chain) {
            Err(LineageError::QuorumNotMet { position, .. }) => assert_eq!(position, 6),
            other => panic!("expected QuorumNotMet at 6, got {other:?}"),
        }
    }

    /// An approve vote from an INELIGIBLE node (not yet an elder at that position)
    /// does not count toward quorum.
    #[test]
    fn test_ineligible_voter_does_not_count() {
        let mut chain = build_valid_chain(6);
        // Replace position 5's real elder votes with a single vote from a brand
        // new (non-elder) identity that correctly signs the approve message.
        let c5 = &chain.contribs[4];
        let ch = contribution_hash(&c5.contributor, 5, &c5.new_params_hash);
        let msg = vote_signing_message(&ch, true);
        let outsider = NodeIdentity::generate();
        chain.votes[5] = vec![VoteLineageRow {
            voter: outsider.node_id(),
            approve: true,
            signature: outsider.sign(&msg),
        }];
        match run(&chain) {
            Err(LineageError::QuorumNotMet {
                position, valid, ..
            }) => {
                assert_eq!(position, 5);
                assert_eq!(
                    valid, 0,
                    "an outsider's signature must not count toward quorum"
                );
            }
            other => panic!("expected QuorumNotMet at 5, got {other:?}"),
        }
    }

    /// A tampered (invalid) signature from an eligible elder does not count.
    #[test]
    fn test_tampered_signature_does_not_count() {
        let mut chain = build_valid_chain(6);
        for v in chain.votes[5].iter_mut() {
            v.signature[0] ^= 0x01; // corrupt every signature at position 5
        }
        match run(&chain) {
            Err(LineageError::QuorumNotMet {
                position, valid, ..
            }) => {
                assert_eq!(position, 5);
                assert_eq!(valid, 0);
            }
            other => panic!("expected QuorumNotMet at 5, got {other:?}"),
        }
    }

    // ---- DB round-trip + singleton true-up ----

    #[test]
    fn test_db_roundtrip_and_singleton_trueup() {
        use crate::queries::{MpcContributionRecord, MpcVerificationVote};
        let db = crate::Database::in_memory().unwrap();
        let chain = build_valid_chain(4);

        // Persist contributions + votes exactly as the live/sync path would.
        for c in &chain.contribs {
            db.save_mpc_contribution(&MpcContributionRecord {
                elder_position: c.position,
                contributor_node_id: hex::encode(c.contributor),
                prev_params_hash: c.prev_params_hash,
                new_params_hash: c.new_params_hash,
                contribution_proof: vec![1, 2, 3], // non-empty (proof retained)
                epoch: 0,
                created_at: 1000,
            })
            .unwrap();
        }
        for pos in 2..=4u32 {
            for v in chain.votes_for(pos) {
                db.save_mpc_vote(&MpcVerificationVote {
                    contribution_position: pos,
                    voter_node_id: hex::encode(v.voter),
                    approve: v.approve,
                    signature: v.signature.to_vec(),
                    voted_at: 1000,
                })
                .unwrap();
            }
        }

        // DB-driven verification passes against the head.
        let n = db
            .verify_mpc_genesis_anchored_lineage(&ANCHOR, Some(&chain.head))
            .unwrap();
        assert_eq!(n, 4);

        // No singleton yet → true-up creates it at the verified head.
        let changed = db
            .reconcile_mpc_singleton_to_head(n, &chain.head, &ANCHOR, 2000)
            .unwrap();
        assert!(changed);
        let s = db.get_mpc_ceremony_state().unwrap().unwrap();
        assert_eq!(s.contribution_count, 4);
        assert_eq!(s.current_params_hash, chain.head);
        assert_eq!(s.ceremony_id, ANCHOR);

        // Idempotent second true-up.
        let changed2 = db
            .reconcile_mpc_singleton_to_head(n, &chain.head, &ANCHOR, 2000)
            .unwrap();
        assert!(!changed2);
    }

    #[test]
    fn test_db_trueup_advances_lagged_singleton() {
        use crate::queries::{MpcCeremonyState, MpcContributionRecord, MpcVerificationVote};
        let db = crate::Database::in_memory().unwrap();
        let chain = build_valid_chain(5);
        for c in &chain.contribs {
            db.save_mpc_contribution(&MpcContributionRecord {
                elder_position: c.position,
                contributor_node_id: hex::encode(c.contributor),
                prev_params_hash: c.prev_params_hash,
                new_params_hash: c.new_params_hash,
                contribution_proof: vec![9],
                epoch: 0,
                created_at: 1,
            })
            .unwrap();
        }
        for pos in 2..=5u32 {
            for v in chain.votes_for(pos) {
                db.save_mpc_vote(&MpcVerificationVote {
                    contribution_position: pos,
                    voter_node_id: hex::encode(v.voter),
                    approve: v.approve,
                    signature: v.signature.to_vec(),
                    voted_at: 1,
                })
                .unwrap();
            }
        }
        // Plant a LAGGED singleton (count 3, stale hash) as if the node abstained.
        db.save_mpc_ceremony_state(&MpcCeremonyState {
            contribution_count: 3,
            current_params_hash: chain.contribs[2].new_params_hash,
            is_ossified: false,
            ossified_at: None,
            block_vk_hash: None,
            payout_vk_hash: None,
            updated_at: 1,
            ceremony_id: ANCHOR,
            ossified_file_hash: None,
        })
        .unwrap();

        let n = db
            .verify_mpc_genesis_anchored_lineage(&ANCHOR, Some(&chain.head))
            .unwrap();
        assert_eq!(n, 5);
        let changed = db
            .reconcile_mpc_singleton_to_head(n, &chain.head, &ANCHOR, 9)
            .unwrap();
        assert!(changed, "lagged singleton must be advanced");
        let s = db.get_mpc_ceremony_state().unwrap().unwrap();
        assert_eq!(s.contribution_count, 5);
        assert_eq!(s.current_params_hash, chain.head);
        assert_eq!(s.ceremony_id, ANCHOR, "ceremony_id preserved");
    }
}

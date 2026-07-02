//|======================================================================================================================|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| FILE: mpc_lifecycle.rs                                                                                               |
//|======================================================================================================================|

//! Stage D — regtest MPC rolling-ceremony lifecycle harness.
//!
//! This is the MANDATORY GATE before the mainnet un-pin of the resumed MPC
//! rolling ceremony (`tasks/plan_mpc_rolling_resume.md`, Stage 5). It walks the
//! full ceremony lifecycle against the SAME machinery the mainnet binary runs:
//!
//!   * real `ghost_mpc::CeremonyManager` with real Groth16 parameters (genesis +
//!     each contribution is a genuine phase-2 transform),
//!   * the real Schnorr + h/l pairing `verify_contribution` gate,
//!   * the real `apply_contribution_multi` (disk write + symlink + hot-swap +
//!     ossify) param swap,
//!   * the real genesis-anchored lineage + retained-BFT-quorum startup verifier
//!     (`Database::verify_mpc_genesis_anchored_lineage`, Stage C),
//!   * real `ghost_common::identity` elder signatures over the real
//!     `ghost_common::mpc::contribution_hash` / `vote_signing_message`,
//!   * the real `ghost_zkp::select_startup_mode` un-pin selection.
//!
//! # Where this lives, and why (cap injection)
//!
//! The harness is a `ghost-mpc` integration test rather than a member of the
//! live cluster-chaos suite (`tests/cluster_chaos_mod/`, which drives the real
//! 4-node signet VMs over SSH/HTTP and cannot run here) precisely so the small
//! ceremony cap can be injected with ZERO mainnet-reachability risk. The cap is
//! the compile-time `mpc-test-cap` cargo feature on `ghost-mpc`
//! (`MAX_CEREMONY_CONTRIBUTORS` = 4 instead of 101). Because the feature is not
//! a default feature and is enabled ONLY by an explicit
//! `--features mpc-test-cap` on a targeted `-p ghost-mpc` test run, it can never
//! be unified into the production `ghost-pool` build, and there is no env var or
//! runtime knob (a consensus constant must not be runtime-tunable). See
//! `MAX_CEREMONY_CONTRIBUTORS` in `crates/ghost-mpc/src/lib.rs`.
//!
//! # How to run
//!
//! ```text
//! # The full harness (real-crypto path included) — release for speed:
//! cargo test -p ghost-mpc --release --features mpc-test-cap --test mpc_lifecycle -- --nocapture
//!
//! # The cheap pure-function / DB assertions alone (debug is fine):
//! cargo test -p ghost-mpc --features mpc-test-cap --test mpc_lifecycle \
//!     supermajority unpin catchup forged_old_structural -- --nocapture
//! ```
//!
//! # Coverage map (each is a Stage-5 gate)
//!
//! | # | Assertion                                   | Level proven here                          |
//! |---|---------------------------------------------|--------------------------------------------|
//! | 1 | Genesis init, stable identical ceremony_id  | node-level (real managers) + DB            |
//! | 2 | BFT-approved contributions converge + quorum| node-level convergence + DB retained quorum|
//! | 3 | Hash evolves; restart re-validates, rejoins | node-level (real reload from disk)         |
//! | 4 | Forged contribution REJECTED (hole closed)  | node-level real verify + pure no-forge     |
//! | 5 | Ossify at cap; further contribution refused | node-level (real ossify)                   |
//! | 6 | Post-ossification fresh node verify + can't | node-level (real reload) + DB lineage      |
//! | 7 | Un-pin / catch-up rehearsal                  | env mode-flip + DB catch-up via vote shape |
//!
//! The ≥67% SUPERMAJORITY retained-quorum geometry is exercised at the
//! pure-function / DB level (`supermajority_retained_quorum_db`) with a 6-position
//! chain and real elder signatures: with the real-crypto cap of 4 every position
//! sits in the BFT *bootstrap* regime (threshold = 1), so the supermajority math
//! (`ceil(count * 67 / 100)`) is only reachable with ≥4 eligible voters, i.e.
//! position ≥5. This split is the harness's deliberate, documented choice (the
//! Stage-5 fallback): the node-level flow runs at whatever cap is feasible for
//! real Groth16, and the supermajority assertion is proven on the pure verifier.

use ghost_common::identity::NodeIdentity;
use ghost_common::mpc::{contribution_hash, mpc_bft_threshold, vote_signing_message};
use ghost_mpc::contribution::hash_parameters;
use ghost_mpc::{CeremonyManager, Groth16Params, MpcError, MAX_CEREMONY_CONTRIBUTORS};
use ghost_storage::queries::{MpcCeremonyState, MpcContributionRecord, MpcVerificationVote};
use ghost_storage::Database;
use tempfile::TempDir;

// ============================================================================
// Shared helpers
// ============================================================================

/// Generate one fresh set of genesis Groth16 parameters (the three ceremony
/// circuits), mirroring `CeremonyManager::ensure_genesis_initialized`. Generated
/// ONCE per harness run and cloned into every simulated node so they all share
/// an identical genesis (as a real fleet does: node 1 generates, the rest fetch).
fn generate_genesis_params() -> (Groth16Params, Groth16Params, Groth16Params) {
    use bellperson::groth16::generate_random_parameters;
    use blstrs::{Bls12, Scalar as Fr};
    use ghost_zkp::circuit::{GhostNoteSpendCircuit, GhostUnshieldCircuit, NoteConsolidateCircuit};
    use rand::rngs::OsRng;

    let note = generate_random_parameters::<Bls12, _, _>(
        GhostNoteSpendCircuit::<Fr>::dummy(20),
        &mut OsRng,
    )
    .expect("genesis note-spend params");
    let consolidate = generate_random_parameters::<Bls12, _, _>(
        NoteConsolidateCircuit::<Fr>::dummy(20),
        &mut OsRng,
    )
    .expect("genesis consolidation params");
    let unshield = generate_random_parameters::<Bls12, _, _>(
        GhostUnshieldCircuit::<Fr>::dummy(20),
        &mut OsRng,
    )
    .expect("genesis unshield params");
    (note, consolidate, unshield)
}

/// A simulated node: a real ceremony manager over its own params dir, plus its
/// own database (the lightweight contribution-row + vote ledger it retains).
struct Node {
    manager: CeremonyManager,
    db: Database,
    _dir: TempDir,
}

impl Node {
    /// Stand up a node sharing the supplied genesis params, persist the genesis
    /// singleton, and return it ready at contribution_count 0.
    fn genesis(
        note: &Groth16Params,
        consolidate: &Groth16Params,
        unshield: &Groth16Params,
    ) -> Self {
        let dir = TempDir::new().unwrap();
        let manager = CeremonyManager::new(dir.path().to_path_buf());
        manager
            .initialize_genesis_multi(note.clone(), consolidate.clone(), unshield.clone())
            .expect("genesis init");
        let db = Database::in_memory().unwrap();
        // Persist the genesis singleton (contribution_count 0, head = anchor).
        let st = manager.state();
        db.save_mpc_ceremony_state(&MpcCeremonyState {
            contribution_count: 0,
            current_params_hash: st.current_params_hash,
            is_ossified: false,
            ossified_at: None,
            block_vk_hash: None,
            payout_vk_hash: None,
            updated_at: st.updated_at,
            ceremony_id: st.ceremony_id,
            ossified_file_hash: None,
        })
        .unwrap();
        Self {
            manager,
            db,
            _dir: dir,
        }
    }
}

/// Persist the `mpc_ceremony` singleton from a manager's authoritative state —
/// exactly what the production `persist_singleton` does after an apply.
fn persist_singleton_from_manager(db: &Database, manager: &CeremonyManager) {
    let st = manager.state();
    db.save_mpc_ceremony_state(&MpcCeremonyState {
        contribution_count: st.contribution_count,
        current_params_hash: st.current_params_hash,
        is_ossified: st.is_ossified,
        ossified_at: st.ossified_at,
        block_vk_hash: st.note_spend_vk_hash,
        payout_vk_hash: st.payout_vk_hash,
        updated_at: st.updated_at,
        ceremony_id: st.ceremony_id,
        ossified_file_hash: st.ossified_file_hash,
    })
    .unwrap();
}

/// Persist a contribution row + the retained approve votes for `position` from
/// the then-eligible elder set (contributors at positions `1..position`). Mirrors
/// what a node records after BFT approval, and is exactly the data the
/// genesis-anchored startup verifier re-checks.
#[allow(clippy::too_many_arguments)]
fn record_contribution_and_votes(
    db: &Database,
    position: u32,
    contributor: &NodeIdentity,
    electorate: &[&NodeIdentity],
    prev_hash: [u8; 32],
    new_hash: [u8; 32],
    proof: Vec<u8>,
    now: u64,
) {
    db.save_mpc_contribution(&MpcContributionRecord {
        elder_position: position,
        contributor_node_id: hex::encode(contributor.node_id()),
        prev_params_hash: prev_hash,
        new_params_hash: new_hash,
        contribution_proof: proof,
        epoch: 0,
        created_at: now,
    })
    .unwrap();

    // Every then-eligible elder approves (full participation). The signed bytes
    // are byte-identical to what the live voter signs and what the startup
    // verifier re-derives.
    let ch = contribution_hash(&contributor.node_id(), position, &new_hash);
    let approve_msg = vote_signing_message(&ch, true);
    for elder in electorate {
        db.save_mpc_vote(&MpcVerificationVote {
            contribution_position: position,
            voter_node_id: hex::encode(elder.node_id()),
            approve: true,
            signature: elder.sign(&approve_msg).to_vec(),
            voted_at: now,
        })
        .unwrap();
    }
}

/// The OLD structural-only pre-check (`mpc_handler::structural_precheck`), which
/// Stage 1a proved insufficient. Replicated here (for position-1 / no-predecessor
/// inputs) so assertion 4 can demonstrate that a forged contribution which the
/// real cryptographic gate REJECTS would have sailed through the old gate. The
/// chain-link branch is omitted because the forged input under test is position 1
/// (genesis has no predecessor), exactly where the old check returned `true`.
fn old_structural_precheck_genesis(
    proof: &[u8],
    prev_params_hash: &[u8; 32],
    new_params_hash: &[u8; 32],
) -> bool {
    !proof.is_empty()
        && *prev_params_hash != [0u8; 32]
        && *new_params_hash != [0u8; 32]
        && prev_params_hash != new_params_hash
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ============================================================================
// (A) NODE-LEVEL REAL-CRYPTO LIFECYCLE — assertions 1,2,3,4,5,6
// ============================================================================

/// Drives the real ceremony end to end on TWO simulated nodes that share one
/// genesis: forged-rejection probe → genesis → BFT-approved contributions (with
/// per-node convergence + lineage + strictly-evolving hashes + retained quorum)
/// → mid-ceremony restart/revalidate → ossify at the cap → post-ossification
/// fresh node. One genesis is generated and reused so the whole real-crypto path
/// stays within a couple of minutes in release.
#[test]
fn realcrypto_lifecycle() {
    let cap = MAX_CEREMONY_CONTRIBUTORS;
    assert!(
        cap <= 8,
        "this harness must run under --features mpc-test-cap (small cap); got {cap}"
    );

    let (g_note, g_consolidate, g_unshield) = generate_genesis_params();

    // Two nodes from one genesis (a real fleet: node 1 generates, peers fetch).
    let node_a = Node::genesis(&g_note, &g_consolidate, &g_unshield);
    let mut node_b = Node::genesis(&g_note, &g_consolidate, &g_unshield);

    // ---- Assertion 1: genesis init; stable, fleet-identical ceremony_id -------
    let anchor = node_a.manager.current_params_hash();
    assert_ne!(anchor, [0u8; 32], "genesis params hash must be non-zero");
    assert_eq!(
        node_a.manager.contribution_count(),
        0,
        "genesis node starts at contribution_count 0"
    );
    assert_eq!(
        node_a.manager.state().ceremony_id,
        anchor,
        "ceremony_id must equal the genesis lineage hash (= position-1 prev)"
    );
    assert_eq!(
        node_b.manager.current_params_hash(),
        anchor,
        "both nodes share an identical genesis head"
    );
    assert_eq!(
        node_a.manager.state().ceremony_id,
        node_b.manager.state().ceremony_id,
        "ceremony_id is identical across nodes"
    );
    // Genesis singleton row exists on both, identical ceremony_id.
    let sa = node_a.db.get_mpc_ceremony_state().unwrap().unwrap();
    let sb = node_b.db.get_mpc_ceremony_state().unwrap().unwrap();
    assert_eq!(sa.contribution_count, 0);
    assert_eq!(sa.ceremony_id, sb.ceremony_id);
    assert_eq!(sa.ceremony_id, anchor);
    // Genesis-anchored verify of a fresh node holding only genesis params: the
    // empty chain with head == anchor is trivially valid.
    assert_eq!(
        node_a
            .db
            .verify_mpc_genesis_anchored_lineage(&anchor, Some(&anchor))
            .unwrap(),
        0,
        "a genesis-only node verifies against the anchor with an empty chain"
    );

    // ---- Assertion 4 (node level): forged contribution REJECTED ---------------
    // A position-1 candidate with a TAMPERED Schnorr proof. Parameters + all
    // hashes are untouched, so it is structurally perfect — only the real
    // cryptographic gate can catch it. This is a read-only probe; the managers
    // remain at count 0 for the real run below.
    {
        let candidate = NodeIdentity::generate();
        let (forged_params, mut forged) = node_a
            .manager
            .generate_contribution(&hex::encode(candidate.node_id()))
            .unwrap();
        assert_eq!(forged.position, 1);
        // Tamper only the low byte of the tau Schnorr response (stays a valid scalar).
        forged.proof.tau_pok.response[0] ^= 0x01;

        // PROOF the hole is closed: the OLD structural-only check would have
        // approved this forged contribution.
        assert!(
            old_structural_precheck_genesis(
                &serde_json::to_vec(&forged.proof).unwrap(),
                &forged.prev_params_hash,
                &forged.new_params_hash,
            ),
            "old structural-only pre-check WOULD have passed the forged contribution"
        );

        // The real gate REJECTS on BOTH nodes (Schnorr verification fails).
        assert!(
            node_a
                .manager
                .verify_contribution(&forged_params, &forged)
                .is_err(),
            "node A's real verify must reject the tampered proof"
        );
        assert!(
            node_b
                .manager
                .verify_contribution(&forged_params, &forged)
                .is_err(),
            "node B's real verify must reject the tampered proof"
        );

        // Never applied: both nodes still at the genesis head, count 0.
        assert_eq!(node_a.manager.contribution_count(), 0);
        assert_eq!(node_b.manager.contribution_count(), 0);
        assert_eq!(node_a.manager.current_params_hash(), anchor);
        assert_eq!(node_b.manager.current_params_hash(), anchor);
    }

    // ---- Assertions 2 + 3: BFT-approved contributions, convergence, restart ---
    // A distinct elder identity per position (index 1..=cap); index 0 unused.
    let mut elders: Vec<NodeIdentity> = Vec::with_capacity(cap as usize + 1);
    elders.push(NodeIdentity::generate()); // slot 0, unused
    for _ in 1..=cap {
        elders.push(NodeIdentity::generate());
    }

    let mut prev_head = anchor;
    let mut hashes_seen = std::collections::HashSet::new();
    hashes_seen.insert(anchor);

    for p in 1..=cap {
        let contributor = &elders[p as usize];
        let (new_params, contribution) = node_a
            .manager
            .generate_contribution(&hex::encode(contributor.node_id()))
            .unwrap();

        assert_eq!(contribution.position, p, "positions are sequential");
        assert_eq!(
            contribution.prev_params_hash, prev_head,
            "prev_params_hash chains from the previous head (lineage)"
        );
        // Hash strictly evolves and is never repeated.
        assert_ne!(
            contribution.new_params_hash, prev_head,
            "each contribution must change the params hash"
        );
        assert!(
            hashes_seen.insert(contribution.new_params_hash),
            "every position's new hash is strictly new"
        );

        // BOTH nodes cryptographically verify (Schnorr + h/l pairing) BEFORE applying.
        assert!(
            node_a
                .manager
                .verify_contribution(&new_params, &contribution)
                .unwrap(),
            "node A verifies the contribution"
        );
        assert!(
            node_b
                .manager
                .verify_contribution(&new_params, &contribution)
                .unwrap(),
            "node B verifies the contribution"
        );

        // Apply on both nodes (disk write + symlink + hot-swap + ossify check).
        node_a
            .manager
            .apply_contribution(new_params.clone(), &contribution)
            .unwrap();
        node_b
            .manager
            .apply_contribution(new_params, &contribution)
            .unwrap();

        // Convergence: the new current_params_hash == new_params_hash on EVERY node.
        assert_eq!(
            node_a.manager.current_params_hash(),
            contribution.new_params_hash,
            "node A head == new_params_hash"
        );
        assert_eq!(
            node_b.manager.current_params_hash(),
            contribution.new_params_hash,
            "node B head == new_params_hash"
        );
        assert_eq!(node_a.manager.contribution_count(), p);
        assert_eq!(node_b.manager.contribution_count(), p);

        // On-disk head really equals the recorded lineage head on every node.
        assert_eq!(
            hash_parameters(&node_a.manager.note_spend_params().unwrap()).unwrap(),
            contribution.new_params_hash,
            "node A on-disk params hash == singleton head"
        );

        // Record the row + retained approve votes (electorate = positions 1..p-1).
        let electorate: Vec<&NodeIdentity> = (1..p).map(|i| &elders[i as usize]).collect();
        let proof = serde_json::to_vec(&contribution.proof).unwrap();
        assert!(!proof.is_empty(), "the contribution proof is retained");
        for db in [&node_a.db, &node_b.db] {
            record_contribution_and_votes(
                db,
                p,
                contributor,
                &electorate,
                contribution.prev_params_hash,
                contribution.new_params_hash,
                proof.clone(),
                now_secs(),
            );
        }
        // Persist the singleton from the manager's authoritative state on both.
        persist_singleton_from_manager(&node_a.db, &node_a.manager);
        persist_singleton_from_manager(&node_b.db, &node_b.manager);

        // A ≥ threshold quorum of approve votes is recorded for this position.
        // Position 1 (the genesis contribution) has NO electorate — it is trusted
        // solely via the immutable genesis anchor (exactly as the genesis-anchored
        // verifier treats it: the quorum check runs only for positions >= 2). Every
        // later position must carry a >= threshold(electorate) approve quorum.
        let (approvals, rejections) = node_a.db.count_mpc_approvals(p).unwrap();
        assert_eq!(rejections, 0, "no reject votes for an honest contribution");
        if p == 1 {
            assert_eq!(
                approvals, 0,
                "the genesis contribution has no electorate (anchor-trusted)"
            );
        } else {
            let required = mpc_bft_threshold(p - 1);
            assert!(
                approvals >= required,
                "position {p}: {approvals} approvals must meet the threshold {required}"
            );
        }

        prev_head = contribution.new_params_hash;

        // ---- Assertion 3: restart node B mid-ceremony, re-validate, rejoin ----
        if p == cap / 2 && cap >= 2 {
            let dir = node_b._dir.path().to_path_buf();
            let head_at_restart = node_b.manager.current_params_hash();
            // Reconstruct the state the node would load from its DB singleton.
            let restored_state = ghost_mpc::CeremonyState {
                contribution_count: p,
                current_params_hash: head_at_restart,
                ceremony_id: anchor,
                ..Default::default()
            };
            let reloaded =
                CeremonyManager::load_or_init(dir, Some(restored_state)).expect("node B restart");
            // It reloaded the real params from disk and they match the head.
            assert!(reloaded.has_current_params(), "restart reloads params");
            assert_eq!(reloaded.current_params_hash(), head_at_restart);
            assert_eq!(
                hash_parameters(&reloaded.note_spend_params().unwrap()).unwrap(),
                head_at_restart,
                "on-disk params survive a restart and match the head"
            );
            // It re-validates via the genesis-anchored startup path.
            assert_eq!(
                node_b
                    .db
                    .verify_mpc_genesis_anchored_lineage(&anchor, Some(&head_at_restart))
                    .unwrap(),
                p,
                "restarted node B re-validates the chain via the genesis anchor"
            );
            // Swap the reloaded manager in so it rejoins and keeps contributing.
            node_b.manager = reloaded;
        }
    }

    let final_head = prev_head;

    // ---- Assertion 5: ossification at the cap -------------------------------
    assert!(
        node_a.manager.is_ossified(),
        "node A ossifies at the cap ({cap})"
    );
    assert!(
        node_b.manager.is_ossified(),
        "node B ossifies at the cap ({cap})"
    );
    assert!(
        node_a
            .db
            .get_mpc_ceremony_state()
            .unwrap()
            .unwrap()
            .is_ossified,
        "node A singleton persists is_ossified=1"
    );
    assert!(
        node_b
            .db
            .get_mpc_ceremony_state()
            .unwrap()
            .unwrap()
            .is_ossified,
        "node B singleton persists is_ossified=1"
    );
    // A further contribution attempt is refused with CeremonyOssified.
    let late = node_a.manager.generate_contribution("late-comer");
    assert!(
        matches!(late.as_ref().err(), Some(MpcError::CeremonyOssified(_))),
        "a post-cap contribution must be rejected with CeremonyOssified, got is_err={}",
        late.is_err()
    );

    // Full chain (with retained quorum at every position) verifies on both nodes.
    assert_eq!(
        node_a
            .db
            .verify_mpc_genesis_anchored_lineage(&anchor, Some(&final_head))
            .unwrap(),
        cap
    );
    assert_eq!(
        node_b
            .db
            .verify_mpc_genesis_anchored_lineage(&anchor, Some(&final_head))
            .unwrap(),
        cap,
        "node B (which restarted mid-ceremony) verifies the FULL ossified chain"
    );

    // ---- Assertion 6: post-ossification fresh node --------------------------
    // A brand-new node fetches the final params (it loads them from disk here,
    // standing in for the network fetch) + the lightweight chain rows, verifies
    // via the lineage path, reports ossified, can serve, and CANNOT contribute.
    {
        let fresh_state = ghost_mpc::CeremonyState {
            contribution_count: cap,
            current_params_hash: final_head,
            is_ossified: true,
            ceremony_id: anchor,
            ..Default::default()
        };
        // Reuse node A's on-disk params dir as the "fetched" final params.
        let fresh =
            CeremonyManager::load_or_init(node_a.manager.params_dir().clone(), Some(fresh_state))
                .expect("fresh node load");
        assert!(fresh.is_ossified(), "fresh node reports ossified");
        assert!(fresh.has_current_params(), "fresh node can serve params");
        let fetched_head = hash_parameters(&fresh.note_spend_params().unwrap()).unwrap();
        assert_eq!(
            fetched_head, final_head,
            "fresh node really holds the final ossified params"
        );
        // It verifies the fetched params against the recorded lineage (node A's DB
        // = the ledger it synced).
        assert_eq!(
            node_a
                .db
                .verify_mpc_genesis_anchored_lineage(&anchor, Some(&fetched_head))
                .unwrap(),
            cap,
            "fresh node verifies the final params via the genesis-anchored lineage"
        );
        // It CANNOT contribute.
        let attempt = fresh.generate_contribution("johnny-come-lately");
        assert!(
            matches!(attempt.as_ref().err(), Some(MpcError::CeremonyOssified(_))),
            "fresh post-ossification node must not be able to contribute, got is_err={}",
            attempt.is_err()
        );
    }
}

// ============================================================================
// (A2) BUG-1 INVARIANT — candidate generation must not move current.bin
// ============================================================================

/// Bug-1 regression (the node5 crash-loop): GENERATING a contribution must NOT
/// advance the node's active params. Only `apply_contribution_multi` (after BFT
/// approval) may move `current.bin` / `current_params_hash`.
///
/// Walks the real machinery the mainnet binary uses:
///   1. genesis → active head = anchor (on disk AND in the manager).
///   2. `generate_contribution_at_position` → candidate params + contribution;
///      the manager's `current_params_hash` is UNCHANGED (anchor) and the
///      on-disk `note_spend_params_current.bin` STILL hashes to anchor.
///   3. the candidate is written to its SEPARATE serving file (the exact
///      `ghost_common::mpc::candidate_note_spend_filename` the contributor uses)
///      and is retrievable + hashes to the contribution's `new_params_hash` —
///      WITHOUT having disturbed current.bin.
///   4. only after `apply_contribution_multi` do the manager head AND the
///      on-disk current.bin become the candidate (`new_params_hash`).
#[test]
fn generate_does_not_advance_current_only_apply_does() {
    use ghost_mpc::params::load_parameters;

    let (note, consolidate, unshield) = generate_genesis_params();
    let node = Node::genesis(&note, &consolidate, &unshield);

    let params_dir = node.manager.params_dir().clone();
    let current_bin = params_dir.join("note_spend_params_current.bin");
    assert!(current_bin.exists(), "genesis must install current.bin");

    // The applied head before any contribution.
    let anchor = node.manager.current_params_hash();
    let ondisk_anchor =
        hash_parameters(&load_parameters(&current_bin).expect("load genesis current")).unwrap();
    assert_eq!(
        ondisk_anchor, anchor,
        "on-disk current.bin must hash to the manager's head at genesis"
    );

    // (2) Generate position-1 candidate. This must NOT touch active state.
    let contributor = NodeIdentity::generate();
    let (new_params, contribution) = node
        .manager
        .generate_contribution_at_position(&hex::encode(contributor.node_id()), 1)
        .expect("generate candidate");
    assert_ne!(
        contribution.new_params_hash, anchor,
        "a real phase-2 transform must change the lineage hash"
    );
    assert_eq!(
        node.manager.current_params_hash(),
        anchor,
        "GENERATION must not advance the manager head"
    );
    assert_eq!(
        hash_parameters(&load_parameters(&current_bin).expect("reload current")).unwrap(),
        anchor,
        "GENERATION must not rewrite the on-disk current.bin"
    );

    // (3) Write the candidate to its hash-keyed serving file (what the
    // contributor does) and confirm it is retrievable + correct, and STILL has
    // not disturbed current.bin.
    let mut buf = Vec::new();
    new_params.write(&mut buf).expect("serialize candidate");
    let candidate_path = params_dir.join(ghost_common::mpc::candidate_note_spend_filename(
        &contribution.new_params_hash,
    ));
    std::fs::write(&candidate_path, &buf).expect("write candidate");
    assert_ne!(
        candidate_path, current_bin,
        "candidate file must be separate"
    );

    let served = load_parameters(&candidate_path).expect("load served candidate");
    assert_eq!(
        hash_parameters(&served).unwrap(),
        contribution.new_params_hash,
        "candidate served by hash must be the un-applied params the voter verifies"
    );
    assert_eq!(
        node.manager.current_params_hash(),
        anchor,
        "writing the candidate serving file must not move the manager head"
    );
    assert_eq!(
        hash_parameters(&load_parameters(&current_bin).unwrap()).unwrap(),
        anchor,
        "writing the candidate serving file must not rewrite current.bin"
    );

    // (4) Apply through the manager (the ONLY legitimate writer of current.bin).
    node.manager
        .apply_contribution_multi(new_params, None, None, &contribution)
        .expect("apply contribution");
    assert_eq!(
        node.manager.current_params_hash(),
        contribution.new_params_hash,
        "apply must advance the manager head to the candidate"
    );
    assert_eq!(
        hash_parameters(&load_parameters(&current_bin).expect("reload current after apply"))
            .unwrap(),
        contribution.new_params_hash,
        "apply must repoint on-disk current.bin to the candidate"
    );
}

// ============================================================================
// (B) ≥67% SUPERMAJORITY retained quorum — pure verifier + DB
// ============================================================================

/// Builds a 6-position chain (synthetic lineage hashes, but REAL elder
/// signatures) and drives it through `Database::verify_mpc_genesis_anchored_
/// lineage` so the genuine ≥67% supermajority threshold is exercised — at
/// position 6 the electorate is the 5 prior elders and the threshold is
/// `ceil(5 * 67 / 100) = 4`. (Under the real-crypto cap of 4 every position is in
/// the bootstrap regime, so this is where the supermajority math is proven.)
#[test]
fn supermajority_retained_quorum_db() {
    let anchor = [0xC9u8; 32];
    let n: u32 = 6;

    // Sanity: position 6 must actually be in the supermajority regime.
    assert_eq!(mpc_bft_threshold(5), 4, "position 6 needs a 4-of-5 quorum");

    let db = Database::in_memory().unwrap();
    let elders: Vec<NodeIdentity> = (0..=n).map(|_| NodeIdentity::generate()).collect();

    let tag = |p: u32| -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = p as u8;
        a[1] = 0xAB;
        a
    };

    let mut prev = anchor;
    for p in 1..=n {
        let new = tag(p);
        let electorate: Vec<&NodeIdentity> = (1..p).map(|i| &elders[i as usize]).collect();
        record_contribution_and_votes(
            &db,
            p,
            &elders[p as usize],
            &electorate,
            prev,
            new,
            vec![1, 2, 3],
            1_000,
        );
        prev = new;
    }
    let head = tag(n);

    // Full 4-of-5 (and below) quorum at every position → verifies.
    assert_eq!(
        db.verify_mpc_genesis_anchored_lineage(&anchor, Some(&head))
            .unwrap(),
        n,
        "a fully-signed supermajority chain verifies"
    );

    // Boundary: dropping ONE of position 6's five signers leaves exactly 4 == the
    // threshold → still verifies.
    {
        let db4 = Database::in_memory().unwrap();
        let mut prev = anchor;
        for p in 1..=n {
            let new = tag(p);
            // At position 6 drop one elder (elders[1]); elsewhere full participation.
            let electorate: Vec<&NodeIdentity> = (1..p)
                .filter(|&i| !(p == n && i == 1))
                .map(|i| &elders[i as usize])
                .collect();
            record_contribution_and_votes(
                &db4,
                p,
                &elders[p as usize],
                &electorate,
                prev,
                new,
                vec![9],
                1_000,
            );
            prev = new;
        }
        assert_eq!(
            db4.verify_mpc_genesis_anchored_lineage(&anchor, Some(&head))
                .unwrap(),
            n,
            "exactly meeting the 4-of-5 threshold still verifies"
        );
    }

    // Below threshold: dropping TWO of position 6's signers leaves 3 < 4 → reject.
    {
        let db3 = Database::in_memory().unwrap();
        let mut prev = anchor;
        for p in 1..=n {
            let new = tag(p);
            let electorate: Vec<&NodeIdentity> = (1..p)
                .filter(|&i| !(p == n && (i == 1 || i == 2)))
                .map(|i| &elders[i as usize])
                .collect();
            record_contribution_and_votes(
                &db3,
                p,
                &elders[p as usize],
                &electorate,
                prev,
                new,
                vec![9],
                1_000,
            );
            prev = new;
        }
        let res = db3.verify_mpc_genesis_anchored_lineage(&anchor, Some(&head));
        assert!(
            res.is_err(),
            "3-of-5 (below the 4 supermajority) must fail closed, got {res:?}"
        );
    }
}

// ============================================================================
// (C) Forged head cannot be laundered through the lineage (no-forge, DB level)
// ============================================================================

/// A forged head that chains structurally (valid prev link) but lacks a quorum
/// of valid signatures is rejected by the genesis-anchored verifier — proving
/// that hash/lineage continuity is never sufficient on its own at the DB layer.
#[test]
fn forged_head_without_quorum_rejected_db() {
    let anchor = [0xC9u8; 32];
    let db = Database::in_memory().unwrap();
    let elders: Vec<NodeIdentity> = (0..=5).map(|_| NodeIdentity::generate()).collect();
    let tag = |p: u32| {
        let mut a = [0u8; 32];
        a[0] = p as u8;
        a[1] = 0xCD;
        a
    };

    // Positions 1..4 fully signed.
    let mut prev = anchor;
    for p in 1..=4u32 {
        let new = tag(p);
        let electorate: Vec<&NodeIdentity> = (1..p).map(|i| &elders[i as usize]).collect();
        record_contribution_and_votes(
            &db,
            p,
            &elders[p as usize],
            &electorate,
            prev,
            new,
            vec![7],
            1,
        );
        prev = new;
    }
    // Position 5: a structurally-valid link (prev == position-4 head) but NO votes.
    let forged_new = tag(5);
    let attacker = NodeIdentity::generate();
    db.save_mpc_contribution(&MpcContributionRecord {
        elder_position: 5,
        contributor_node_id: hex::encode(attacker.node_id()),
        prev_params_hash: prev,
        new_params_hash: forged_new,
        contribution_proof: vec![1, 2, 3],
        epoch: 0,
        created_at: 1,
    })
    .unwrap();

    let res = db.verify_mpc_genesis_anchored_lineage(&anchor, Some(&forged_new));
    assert!(
        res.is_err(),
        "a quorum-less but structurally-valid head must be rejected, got {res:?}"
    );
}

// ============================================================================
// (D) Un-pin / catch-up rehearsal — assertion 7
// ============================================================================

use std::sync::Mutex;
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// The Stage-4 dry run: startup-mode selection flips StaticPin ⇄
/// GenesisAnchoredRolling as the operator removes / restores the static current
/// pin, and the node enters rolling WITHOUT crashing (the genesis-anchored
/// verify succeeds in rolling mode).
#[test]
fn unpin_rollback_env_mode_flip() {
    use ghost_zkp::{
        select_startup_mode, ZkStartupMode, ZK_GENESIS_PARAMS_HASH_ENV, ZK_PARAMS_HASH_ENV,
    };

    let _guard = ENV_LOCK.lock().unwrap();
    // Clean slate.
    std::env::remove_var(ZK_PARAMS_HASH_ENV);
    std::env::remove_var(ZK_GENESIS_PARAMS_HASH_ENV);

    // Build a small fully-signed chain + anchor we can verify in rolling mode.
    let anchor = [0xA7u8; 32];
    let anchor_hex = hex::encode(anchor);
    let db = Database::in_memory().unwrap();
    let elders: Vec<NodeIdentity> = (0..=3).map(|_| NodeIdentity::generate()).collect();
    let tag = |p: u32| {
        let mut a = [0u8; 32];
        a[0] = p as u8;
        a[1] = 0xEE;
        a
    };
    let mut prev = anchor;
    for p in 1..=3u32 {
        let new = tag(p);
        let electorate: Vec<&NodeIdentity> = (1..p).map(|i| &elders[i as usize]).collect();
        record_contribution_and_votes(
            &db,
            p,
            &elders[p as usize],
            &electorate,
            prev,
            new,
            vec![5],
            1,
        );
        prev = new;
    }
    let head = tag(3);

    // 1. Pinned (frozen): ZK_PARAMS_HASH set → StaticPin.
    std::env::set_var(ZK_PARAMS_HASH_ENV, "BLOCK:00");
    std::env::set_var(ZK_GENESIS_PARAMS_HASH_ENV, &anchor_hex);
    assert_eq!(
        select_startup_mode().unwrap(),
        ZkStartupMode::StaticPin,
        "with the static pin present the node stays frozen"
    );

    // 2. Un-pin: drop ZK_PARAMS_HASH, keep the genesis anchor → rolling.
    std::env::remove_var(ZK_PARAMS_HASH_ENV);
    match select_startup_mode().unwrap() {
        ZkStartupMode::GenesisAnchoredRolling { genesis_anchor } => {
            assert_eq!(genesis_anchor, anchor, "rolling carries the genesis anchor");
        }
        other => panic!("expected rolling after un-pin, got {other:?}"),
    }
    // Enters rolling WITHOUT crash: the genesis-anchored verify succeeds.
    assert_eq!(
        db.verify_mpc_genesis_anchored_lineage(&anchor, Some(&head))
            .unwrap(),
        3,
        "rolling node validates its chain via the genesis anchor (no crash)"
    );

    // 3. Rollback: re-add the static pin → back to frozen.
    std::env::set_var(ZK_PARAMS_HASH_ENV, "BLOCK:00");
    assert_eq!(
        select_startup_mode().unwrap(),
        ZkStartupMode::StaticPin,
        "re-adding the pin rolls back to frozen"
    );

    std::env::remove_var(ZK_PARAMS_HASH_ENV);
    std::env::remove_var(ZK_GENESIS_PARAMS_HASH_ENV);
}

/// A FRESH node catches up purely via the `GET /api/v1/mpc/votes/{position}`
/// data path: it fetches each position's contribution PROOF + retained votes,
/// persists them into an empty DB, and its genesis-anchored startup quorum check
/// then passes — proving the autonomous catch-up the mainnet un-pin depends on.
///
/// This drives the SAME JSON shape the live endpoint serves
/// (`api_mpc_votes_handler`) and the SAME field extraction the live sync uses
/// (`sync_mpc_proof_and_votes`), at the function level. The cross-process HTTP
/// hop itself is covered by `ghost-verification`'s `test_mpc_votes_endpoint_
/// roundtrip` and, end to end, by the docker regtest cluster (see module docs).
#[test]
fn catchup_via_votes_endpoint_shape() {
    let anchor = [0x5Au8; 32];

    // ---- "Server" node: a fully populated ledger. ----
    let server = Database::in_memory().unwrap();
    let elders: Vec<NodeIdentity> = (0..=5).map(|_| NodeIdentity::generate()).collect();
    let tag = |p: u32| {
        let mut a = [0u8; 32];
        a[0] = p as u8;
        a[1] = 0xF0;
        a
    };
    let n = 5u32;
    let mut prev = anchor;
    for p in 1..=n {
        let new = tag(p);
        let electorate: Vec<&NodeIdentity> = (1..p).map(|i| &elders[i as usize]).collect();
        record_contribution_and_votes(
            &server,
            p,
            &elders[p as usize],
            &electorate,
            prev,
            new,
            vec![0xDE, 0xAD, 0xBE, 0xEF], // non-empty retained proof
            1_000,
        );
        prev = new;
    }
    let head = tag(n);

    // ---- Fresh node: empty DB, catches up position by position over the wire. ----
    let fresh = Database::in_memory().unwrap();
    for p in 1..=n {
        let json = server_votes_json(&server, p);
        // The endpoint carries the real proof (the field the /contributors
        // endpoint drops) — assert it is non-empty as the fresh node sees it.
        let proof_hex = json["contribution"]["contribution_proof"].as_str().unwrap();
        assert!(
            !proof_hex.is_empty(),
            "votes endpoint serves the retained proof"
        );
        let persisted = apply_votes_json(&fresh, p, &json);
        assert!(
            persisted,
            "fresh node persisted position {p} from the endpoint"
        );
    }

    // The fresh node's genesis-anchored startup quorum check passes on the
    // catch-up-only data — no historical param blobs needed.
    assert_eq!(
        fresh
            .verify_mpc_genesis_anchored_lineage(&anchor, Some(&head))
            .unwrap(),
        n,
        "fresh node verifies the synced chain via genesis-anchored quorum"
    );

    // And the retained proof bytes really landed in the fresh DB.
    let row = fresh.get_mpc_contribution(n).unwrap().unwrap();
    assert!(
        !row.contribution_proof.is_empty(),
        "the fresh node retained the non-empty proof"
    );
}

/// Build the JSON the live `GET /api/v1/mpc/votes/{position}` endpoint serves
/// (mirrors `api_mpc_votes_handler` in `ghost-verification`).
fn server_votes_json(db: &Database, position: u32) -> serde_json::Value {
    let rec = db.get_mpc_contribution(position).unwrap().unwrap();
    let votes: Vec<serde_json::Value> = db
        .get_mpc_votes(position)
        .unwrap()
        .into_iter()
        .map(|v| {
            serde_json::json!({
                "voter_node_id": v.voter_node_id,
                "approve": v.approve,
                "signature": hex::encode(v.signature),
                "voted_at": v.voted_at,
            })
        })
        .collect();
    serde_json::json!({
        "contribution": {
            "position": rec.elder_position,
            "node_id": rec.contributor_node_id,
            "prev_params_hash": hex::encode(rec.prev_params_hash),
            "new_params_hash": hex::encode(rec.new_params_hash),
            "contribution_proof": hex::encode(&rec.contribution_proof),
            "epoch": rec.epoch,
            "created_at": rec.created_at,
        },
        "votes": votes,
        "vote_count": votes.len(),
    })
}

/// Persist a fetched votes-endpoint response into a fresh DB (mirrors the field
/// extraction in `sync_mpc_proof_and_votes` in `bins/ghost-pool/src/main.rs`).
fn apply_votes_json(db: &Database, position: u32, data: &serde_json::Value) -> bool {
    let mut persisted = false;

    if let Some(c) = data.get("contribution") {
        let proof_hex = c
            .get("contribution_proof")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let node_id = c.get("node_id").and_then(|v| v.as_str()).unwrap_or("");
        let prev = c
            .get("prev_params_hash")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
        let new = c
            .get("new_params_hash")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
        let created_at = c.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0);
        let epoch = c.get("epoch").and_then(|v| v.as_u64()).unwrap_or(0);

        if let (false, Ok(proof_bytes), Some(prev), Some(new)) = (
            proof_hex.is_empty() || node_id.is_empty(),
            hex::decode(proof_hex),
            prev,
            new,
        ) {
            db.save_mpc_contribution(&MpcContributionRecord {
                elder_position: position,
                contributor_node_id: node_id.to_string(),
                prev_params_hash: prev,
                new_params_hash: new,
                contribution_proof: proof_bytes,
                epoch,
                created_at,
            })
            .unwrap();
            persisted = true;
        }
    }

    if let Some(votes) = data.get("votes").and_then(|v| v.as_array()) {
        for v in votes {
            let voter = v.get("voter_node_id").and_then(|x| x.as_str());
            let approve = v.get("approve").and_then(|x| x.as_bool());
            let sig = v
                .get("signature")
                .and_then(|x| x.as_str())
                .and_then(|h| hex::decode(h).ok());
            let voted_at = v.get("voted_at").and_then(|x| x.as_u64()).unwrap_or(0);
            if let (Some(voter), Some(approve), Some(sig)) = (voter, approve, sig) {
                db.save_mpc_vote(&MpcVerificationVote {
                    contribution_position: position,
                    voter_node_id: voter.to_string(),
                    approve,
                    signature: sig,
                    voted_at,
                })
                .unwrap();
                persisted = true;
            }
        }
    }

    persisted
}

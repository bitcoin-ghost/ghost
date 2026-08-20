//! Verify a signed Ghost node-list checkpoint against a trusted signer set, and advance the
//! trusted set along the signed forward chain.
//!
//! This is the security core of the shim. It performs the SAME checks a pool node's
//! `apply_synced_checkpoint` does, but rooted in the shim's OWN trusted signer set — the
//! baked-in genesis MPC elders, advanced by verified deltas — rather than a node's live voter
//! set. So a miner discovers pool nodes without trusting DNS, the website, or the serving node:
//! only a ≥67% supermajority of the already-trusted signers can move the set forward or attest
//! a node list.

use std::collections::HashSet;

use anyhow::{bail, Context, Result};

use ghost_common::identity::verify_signature;
use ghost_common::types::NodeId;
use ghost_consensus::{
    mesh_advert_set_root, mesh_node_list_root, mesh_signer_set_root, MeshEndpointAdvert,
    MeshNodeEntry, MeshNodeListCheckpointMessage, MeshNodeListCheckpointVoteMessage,
    SignerSetDelta,
};

const BFT_THRESHOLD_PERCENT: u64 = 67;

/// Approvals required: ceil of 67% of `n` trusted signers.
fn quorum_for(n: usize) -> usize {
    (n as u64 * BFT_THRESHOLD_PERCENT).div_ceil(100) as usize
}

/// The signed checkpoint blob as served by `GET /api/v1/pool/mesh-node-list-checkpoint`.
#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct CheckpointBlob {
    pub height: u64,
    pub cutoff_ts: i64,
    pub nodes: Vec<BlobNode>,
    /// One self-signed advert per node in the qualified set at `cutoff_ts`.
    #[serde(default)]
    pub adverts: Vec<BlobAdvert>,
    /// `mesh_advert_set_root(adverts)`. Inside `checkpoint_hash`, so the hash — and therefore
    /// every signature over it — cannot be reconstructed without it.
    #[serde(default)]
    pub advert_root: String,
    pub list_root: String,
    pub signer_set_root: String,
    #[serde(default)]
    pub signer_set_delta: BlobDelta,
    pub active_node_count: u32,
    pub proposer: String,
    pub proposer_signature: String,
    #[serde(default)]
    pub approvals: Vec<BlobApproval>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct BlobAdvert {
    pub node_id: String,
    pub host: String,
    pub sv1_port: u16,
    pub sv2_port: u16,
    pub public_mining: bool,
    pub seq: u64,
    pub signature: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct BlobNode {
    pub node_id: String,
    pub host: String,
    pub sv1_port: u16,
    pub sv2_port: u16,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub(crate) struct BlobDelta {
    #[serde(default)]
    pub added: Vec<String>,
    #[serde(default)]
    pub removed: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct BlobApproval {
    pub voter: String,
    pub signature: String,
}

/// A verified pool node a miner can be routed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedNode {
    pub host: String,
    pub sv1_port: u16,
    pub sv2_port: u16,
}

fn hex32(s: &str) -> Result<[u8; 32]> {
    let b = hex::decode(s).context("invalid hex")?;
    if b.len() != 32 {
        bail!("expected 32 bytes, got {}", b.len());
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    Ok(a)
}

fn hex64(s: &str) -> Result<[u8; 64]> {
    let b = hex::decode(s).context("invalid hex")?;
    if b.len() != 64 {
        bail!("expected 64 bytes, got {}", b.len());
    }
    let mut a = [0u8; 64];
    a.copy_from_slice(&b);
    Ok(a)
}

/// Verify `blob` against `trusted` (the shim's current trusted signer set) and, on success,
/// ADVANCE `trusted` to the checkpoint's signer set and return the verified node list.
///
/// All of these must hold:
/// 1. `list_root == mesh_node_list_root(nodes)` — the node list matches its declared root.
/// 2. The proposer is a member of the trusted set and its signature over the checkpoint hash
///    verifies.
/// 3. At least 67% of the TRUSTED (prior) set signed an approve-vote over the checkpoint hash
///    (decision C: a delta/list is attested by a supermajority of the already-trusted signers,
///    so an attacker cannot inject signers and self-certify).
/// 4. Applying the signed delta to the trusted set yields a set whose root equals the signed
///    `signer_set_root`.
///
/// On success `trusted` becomes that new set. On any failure `trusted` is left unchanged.
pub(crate) fn verify_and_advance(
    blob: &CheckpointBlob,
    trusted: &mut Vec<NodeId>,
) -> Result<Vec<VerifiedNode>> {
    let trusted_set: HashSet<NodeId> = trusted.iter().copied().collect();
    if trusted_set.is_empty() {
        bail!("empty trusted signer set (need a genesis anchor)");
    }

    // (1) Node list ↔ list_root.
    let entries: Vec<MeshNodeEntry> = blob
        .nodes
        .iter()
        .map(|n| {
            Ok(MeshNodeEntry {
                node_id: hex32(&n.node_id)?,
                host: n.host.clone(),
                sv1_port: n.sv1_port,
                sv2_port: n.sv2_port,
            })
        })
        .collect::<Result<_>>()?;
    let list_root = hex32(&blob.list_root)?;
    if mesh_node_list_root(&entries) != list_root {
        bail!("list_root does not match the node list");
    }

    // Parse the remaining signed fields and reconstruct the checkpoint hash (timestamp is not
    // part of it, so 0 is fine).
    let signer_set_root = hex32(&blob.signer_set_root)?;
    let added: Vec<NodeId> = blob
        .signer_set_delta
        .added
        .iter()
        .map(|s| hex32(s))
        .collect::<Result<_>>()?;
    let removed: Vec<NodeId> = blob
        .signer_set_delta
        .removed
        .iter()
        .map(|s| hex32(s))
        .collect::<Result<_>>()?;
    let proposer = hex32(&blob.proposer)?;
    let proposer_signature = hex64(&blob.proposer_signature)?;

    // (1b) Every endpoint must be signed BY THE NODE IT POINTS AT.
    //
    // This is what a quorum signature alone does not give you. Without it the checkpoint says
    // "67% of the trusted set agreed on this list" — but not that any listed node ever claimed
    // that address, so a proposer able to reach quorum could point miners anywhere. With it,
    // redirecting a node's traffic requires that node's own key.
    let adverts: Vec<MeshEndpointAdvert> = blob
        .adverts
        .iter()
        .map(|a| {
            Ok(MeshEndpointAdvert {
                node_id: hex32(&a.node_id)?,
                host: a.host.clone(),
                sv1_port: a.sv1_port,
                sv2_port: a.sv2_port,
                public_mining: a.public_mining,
                seq: a.seq,
                signature: hex64(&a.signature)?,
            })
        })
        .collect::<Result<_>>()?;
    for (a, raw) in adverts.iter().zip(blob.adverts.iter()) {
        if !a.is_self_signed() {
            bail!("advert for {} is not signed by that node", raw.node_id);
        }
    }
    let advert_root = hex32(&blob.advert_root)?;
    if mesh_advert_set_root(&adverts) != advert_root {
        bail!("advert_root does not match the adverts");
    }

    // (1c) The rendered list must be exactly what those adverts produce. A served blob that
    // carries valid adverts AND a different `nodes` array beside them is the obvious way to
    // slip an unattested host past a signature check that only covers the roots.
    let rendered: Vec<MeshNodeEntry> = {
        let mut v: Vec<MeshNodeEntry> = adverts
            .iter()
            .filter(|a| a.public_mining)
            .map(|a| a.to_entry())
            .collect();
        v.sort_by_key(|n| n.node_id);
        v
    };
    if mesh_node_list_root(&rendered) != list_root {
        bail!("the node list is not what its adverts derive to");
    }

    let msg = MeshNodeListCheckpointMessage {
        height: blob.height,
        cutoff_ts: blob.cutoff_ts,
        nodes: entries.clone(),
        adverts: adverts.clone(),
        advert_root,
        list_root,
        signer_set_delta: SignerSetDelta {
            added: added.clone(),
            removed: removed.clone(),
        },
        signer_set_root,
        active_node_count: blob.active_node_count,
        proposer,
        proposer_signature,
        timestamp: 0,
    };
    let hash = msg.checkpoint_hash();

    // (2) Proposer must be trusted and its signature valid.
    if !trusted_set.contains(&proposer) {
        bail!("proposer is not in the trusted signer set");
    }
    if !verify_signature(&proposer, &hash, &proposer_signature).unwrap_or(false) {
        bail!("proposer signature invalid");
    }

    // (3) ≥67% of the trusted (prior) set signed a valid approve-vote over the hash.
    let needed = quorum_for(trusted.len());
    let mut seen = HashSet::new();
    let mut valid = 0usize;
    for ap in &blob.approvals {
        let Ok(voter) = hex32(&ap.voter) else {
            continue;
        };
        if !trusted_set.contains(&voter) || !seen.insert(voter) {
            continue;
        }
        let Ok(sig) = hex64(&ap.signature) else {
            continue;
        };
        let vote = MeshNodeListCheckpointVoteMessage {
            height: blob.height,
            checkpoint_hash: hash,
            voter,
            approve: true,
            signature: sig,
            timestamp: 0,
        };
        if verify_signature(&voter, &vote.signing_message(), &sig).unwrap_or(false) {
            valid += 1;
        }
    }
    if valid < needed {
        bail!("insufficient quorum: {valid}/{needed} of the trusted signer set approved");
    }

    // (4) Applying the delta must yield the signed signer-set root.
    let mut new_set = trusted_set.clone();
    for r in &removed {
        new_set.remove(r);
    }
    for a in &added {
        new_set.insert(*a);
    }
    let mut new_vec: Vec<NodeId> = new_set.into_iter().collect();
    new_vec.sort_unstable();
    if mesh_signer_set_root(&new_vec) != signer_set_root {
        bail!("signer_set_root does not match the applied delta");
    }

    // Adopt.
    *trusted = new_vec;
    Ok(entries
        .into_iter()
        .map(|e| VerifiedNode {
            host: e.host,
            sv1_port: e.sv1_port,
            sv2_port: e.sv2_port,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::identity::NodeIdentity;

    /// A node's own signed advert, as production builds it.
    ///
    /// Fixtures must sign with the SUBJECT's key now: a checkpoint whose hosts nobody attested
    /// is exactly what `verify_and_advance` refuses, so a fixture that fabricated `node_id`
    /// bytes would be testing a shape the shim no longer accepts.
    fn advert(id: &NodeIdentity, host: &str, public_mining: bool) -> MeshEndpointAdvert {
        let mut a = MeshEndpointAdvert {
            node_id: id.node_id(),
            host: host.into(),
            sv1_port: 3333,
            sv2_port: 34255,
            public_mining,
            seq: 1,
            signature: [0u8; 64],
        };
        a.signature = id.sign(&a.signing_bytes());
        a
    }

    fn blob_advert(a: &MeshEndpointAdvert) -> BlobAdvert {
        BlobAdvert {
            node_id: hex::encode(a.node_id),
            host: a.host.clone(),
            sv1_port: a.sv1_port,
            sv2_port: a.sv2_port,
            public_mining: a.public_mining,
            seq: a.seq,
            signature: hex::encode(a.signature),
        }
    }

    /// The rendered list, derived the one way production derives it.
    fn entries_from(adverts: &[MeshEndpointAdvert]) -> Vec<MeshNodeEntry> {
        let mut v: Vec<MeshNodeEntry> = adverts
            .iter()
            .filter(|a| a.public_mining)
            .map(|a| a.to_entry())
            .collect();
        v.sort_by_key(|n| n.node_id);
        v
    }

    /// Build a valid signed blob. `signers` = identities of the PRIOR trusted set (the voters);
    /// `new_signer_set` = the resulting signer set (delta computed prior→new). Proposer =
    /// `prior[height % n]`; every signer casts an approve vote.
    fn build_blob(
        signers: &[NodeIdentity],
        adverts: &[MeshEndpointAdvert],
        new_signer_set: &[NodeId],
        height: u64,
    ) -> CheckpointBlob {
        let nodes = &entries_from(adverts);
        let advert_root = mesh_advert_set_root(adverts);
        let mut prior: Vec<NodeId> = signers.iter().map(|i| i.node_id()).collect();
        prior.sort_unstable();
        let prior_set: HashSet<NodeId> = prior.iter().copied().collect();
        let new_set: HashSet<NodeId> = new_signer_set.iter().copied().collect();
        let mut added: Vec<NodeId> = new_set.difference(&prior_set).copied().collect();
        let mut removed: Vec<NodeId> = prior_set.difference(&new_set).copied().collect();
        added.sort_unstable();
        removed.sort_unstable();

        let list_root = mesh_node_list_root(nodes);
        let signer_set_root = mesh_signer_set_root(new_signer_set);
        let proposer_id = prior[(height as usize) % prior.len()];
        let msg = MeshNodeListCheckpointMessage {
            height,
            cutoff_ts: 1_784_000_000,
            nodes: nodes.to_vec(),
            adverts: adverts.to_vec(),
            advert_root,
            list_root,
            signer_set_delta: SignerSetDelta {
                added: added.clone(),
                removed: removed.clone(),
            },
            signer_set_root,
            active_node_count: prior.len() as u32,
            proposer: proposer_id,
            proposer_signature: [0u8; 64],
            timestamp: 0,
        };
        let hash = msg.checkpoint_hash();
        let proposer_ident = signers.iter().find(|i| i.node_id() == proposer_id).unwrap();
        let proposer_sig = proposer_ident.sign(&hash);
        let approvals: Vec<BlobApproval> = signers
            .iter()
            .map(|i| {
                let vote = MeshNodeListCheckpointVoteMessage {
                    height,
                    checkpoint_hash: hash,
                    voter: i.node_id(),
                    approve: true,
                    signature: [0u8; 64],
                    timestamp: 0,
                };
                BlobApproval {
                    voter: hex::encode(i.node_id()),
                    signature: hex::encode(i.sign(&vote.signing_message())),
                }
            })
            .collect();
        CheckpointBlob {
            height,
            cutoff_ts: 1_784_000_000,
            nodes: nodes
                .iter()
                .map(|e| BlobNode {
                    node_id: hex::encode(e.node_id),
                    host: e.host.clone(),
                    sv1_port: e.sv1_port,
                    sv2_port: e.sv2_port,
                })
                .collect(),
            adverts: adverts.iter().map(blob_advert).collect(),
            advert_root: hex::encode(advert_root),
            list_root: hex::encode(list_root),
            signer_set_root: hex::encode(signer_set_root),
            signer_set_delta: BlobDelta {
                added: added.iter().map(hex::encode).collect(),
                removed: removed.iter().map(hex::encode).collect(),
            },
            active_node_count: prior.len() as u32,
            proposer: hex::encode(proposer_id),
            proposer_signature: hex::encode(proposer_sig),
            approvals,
        }
    }

    /// Two advertising nodes, each signing its own endpoint. Returned sorted by node_id so a
    /// test can index into the derived list deterministically.
    fn two_mining_nodes() -> (Vec<NodeIdentity>, Vec<MeshEndpointAdvert>) {
        let mut ids: Vec<NodeIdentity> = (0..2).map(|_| NodeIdentity::generate()).collect();
        ids.sort_by_key(|i| i.node_id());
        let adverts = vec![
            advert(&ids[0], "203.0.113.1", true),
            advert(&ids[1], "203.0.113.2", true),
        ];
        (ids, adverts)
    }

    /// Assert the checkpoint is refused FOR THE STATED REASON.
    ///
    /// A bare `is_err()` is nearly worthless on this function: it has nine distinct refusal
    /// paths, and a fixture that trips an earlier one passes a test named after a later one
    /// while proving nothing about it. That is how a suite stays green through a regression in
    /// exactly the check it claims to cover.
    fn refused_because(blob: &CheckpointBlob, trusted: &[NodeId], expected: &str) {
        let mut t = trusted.to_vec();
        let err = verify_and_advance(blob, &mut t)
            .expect_err("expected refusal, got acceptance")
            .to_string();
        assert!(
            err.contains(expected),
            "refused for the wrong reason:\n  expected to contain: {expected}\n  actual: {err}"
        );
        assert_eq!(
            t, trusted,
            "a refused checkpoint must not advance the trusted set"
        );
    }

    fn signer_ids(signers: &[NodeIdentity]) -> Vec<NodeId> {
        let mut v: Vec<NodeId> = signers.iter().map(|i| i.node_id()).collect();
        v.sort_unstable();
        v
    }

    #[test]
    fn valid_checkpoint_verifies_and_returns_nodes() {
        let (node_ids, adverts) = two_mining_nodes();
        // The advertising nodes are also the signers: an advert only reaches a checkpoint if
        // its subject is in the qualified set, which is the property that stops an outsider
        // inserting itself into the directory.
        let signers = node_ids;
        let trusted = signer_ids(&signers);
        let blob = build_blob(&signers, &adverts, &trusted, 100);
        let mut t = trusted.clone();
        let out = verify_and_advance(&blob, &mut t).expect("valid");
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].host, "203.0.113.1");
        assert_eq!(out[0].sv1_port, 3333);
        assert_eq!(t, trusted, "stable signer set unchanged");
    }

    #[test]
    fn membership_change_advances_trusted_set() {
        let signers: Vec<NodeIdentity> = (0..4).map(|_| NodeIdentity::generate()).collect();
        let prior = signer_ids(&signers);
        let newcomer = [42u8; 32];
        let mut new_set = prior.clone();
        new_set.push(newcomer);
        new_set.sort_unstable();
        let node = NodeIdentity::generate();
        let adverts = vec![advert(&node, "h", true)];
        let blob = build_blob(&signers, &adverts, &new_set, 100);
        let mut trusted = prior.clone();
        verify_and_advance(&blob, &mut trusted).expect("valid membership change");
        assert!(
            trusted.contains(&newcomer),
            "trusted advanced to include newcomer"
        );
        assert_eq!(trusted.len(), 5);
    }

    #[test]
    fn tampered_proposer_signature_rejected() {
        let signers: Vec<NodeIdentity> = (0..4).map(|_| NodeIdentity::generate()).collect();
        let trusted = signer_ids(&signers);
        let node = NodeIdentity::generate();
        let adverts = vec![advert(&node, "h", true)];
        let mut blob = build_blob(&signers, &adverts, &trusted, 100);
        let mut sig = hex::decode(&blob.proposer_signature).unwrap();
        sig[0] ^= 0xff;
        blob.proposer_signature = hex::encode(sig);
        // `refused_because` also asserts the trusted set is untouched.
        refused_because(&blob, &trusted, "proposer signature invalid");
    }

    #[test]
    fn sub_quorum_rejected() {
        let signers: Vec<NodeIdentity> = (0..4).map(|_| NodeIdentity::generate()).collect();
        let trusted = signer_ids(&signers);
        let node = NodeIdentity::generate();
        let adverts = vec![advert(&node, "h", true)];
        let mut blob = build_blob(&signers, &adverts, &trusted, 100);
        blob.approvals.truncate(2); // 2 < quorum(4) = 3
        refused_because(&blob, &trusted, "insufficient quorum");
    }

    #[test]
    fn wrong_list_root_rejected() {
        let signers: Vec<NodeIdentity> = (0..4).map(|_| NodeIdentity::generate()).collect();
        let trusted = signer_ids(&signers);
        let node = NodeIdentity::generate();
        let adverts = vec![advert(&node, "h", true)];
        let mut blob = build_blob(&signers, &adverts, &trusted, 100);
        blob.list_root = hex::encode([9u8; 32]);
        refused_because(&blob, &trusted, "list_root does not match the node list");
    }

    #[test]
    fn outsider_signed_checkpoint_rejected() {
        // A checkpoint signed entirely by NON-trusted keys must be rejected: the proposer isn't
        // trusted and none of the approvals count, so an attacker can't self-certify a node list.
        let real: Vec<NodeIdentity> = (0..4).map(|_| NodeIdentity::generate()).collect();
        let trusted = signer_ids(&real);
        let attackers: Vec<NodeIdentity> = (0..4).map(|_| NodeIdentity::generate()).collect();
        let atk_set = signer_ids(&attackers);
        let node = NodeIdentity::generate();
        let adverts = vec![advert(&node, "evil.example", true)];
        let blob = build_blob(&attackers, &adverts, &atk_set, 100);
        refused_because(&blob, &trusted, "proposer is not in the trusted signer set");
    }
    /// The refusal that did not exist before: a quorum-signed checkpoint whose hosts nobody
    /// attested. Previously the shim verified only that ≥67% signed A list — never that any
    /// listed node had claimed that address — so a proposer able to reach quorum could point
    /// miners anywhere. Here the adverts are valid but `nodes` says something else.
    #[test]
    fn a_host_the_node_never_attested_is_rejected() {
        let (node_ids, adverts) = two_mining_nodes();
        let signers = node_ids;
        let trusted = signer_ids(&signers);
        let mut blob = build_blob(&signers, &adverts, &trusted, 100);
        // Swap one rendered host for somewhere its node never signed for, and re-root so the
        // list_root check passes — the derivation check is the one that must catch this.
        blob.nodes[0].host = "attacker.example".into();
        let tampered: Vec<MeshNodeEntry> = blob
            .nodes
            .iter()
            .map(|n| MeshNodeEntry {
                node_id: hex32(&n.node_id).unwrap(),
                host: n.host.clone(),
                sv1_port: n.sv1_port,
                sv2_port: n.sv2_port,
            })
            .collect();
        blob.list_root = hex::encode(mesh_node_list_root(&tampered));
        refused_because(&blob, &trusted, "not what its adverts derive to");
    }

    /// An advert signed by anyone other than its subject must not be usable, or the endpoint
    /// attestation is decorative.
    #[test]
    fn an_advert_signed_by_an_impostor_is_rejected() {
        let (node_ids, mut adverts) = two_mining_nodes();
        let signers = node_ids;
        let trusted = signer_ids(&signers);
        let impostor = NodeIdentity::generate();
        adverts[0].host = "attacker.example".into();
        adverts[0].signature = impostor.sign(&adverts[0].signing_bytes());
        let blob = build_blob(&signers, &adverts, &trusted, 100);
        refused_because(&blob, &trusted, "is not signed by that node");
    }
}

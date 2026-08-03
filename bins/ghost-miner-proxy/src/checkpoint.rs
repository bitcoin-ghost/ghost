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
    mesh_node_list_root, mesh_signer_set_root, MeshNodeEntry, MeshNodeListCheckpointMessage,
    MeshNodeListCheckpointVoteMessage, SignerSetDelta,
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
    let msg = MeshNodeListCheckpointMessage {
        height: blob.height,
        cutoff_ts: blob.cutoff_ts,
        nodes: entries.clone(),
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

    fn entry(id: u8, host: &str) -> MeshNodeEntry {
        MeshNodeEntry {
            node_id: [id; 32],
            host: host.into(),
            sv1_port: 3333,
            sv2_port: 34255,
        }
    }

    /// Build a valid signed blob. `signers` = identities of the PRIOR trusted set (the voters);
    /// `new_signer_set` = the resulting signer set (delta computed prior→new). Proposer =
    /// `prior[height % n]`; every signer casts an approve vote.
    fn build_blob(
        signers: &[NodeIdentity],
        nodes: &[MeshNodeEntry],
        new_signer_set: &[NodeId],
        height: u64,
    ) -> CheckpointBlob {
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

    fn signer_ids(signers: &[NodeIdentity]) -> Vec<NodeId> {
        let mut v: Vec<NodeId> = signers.iter().map(|i| i.node_id()).collect();
        v.sort_unstable();
        v
    }

    #[test]
    fn valid_checkpoint_verifies_and_returns_nodes() {
        let signers: Vec<NodeIdentity> = (0..4).map(|_| NodeIdentity::generate()).collect();
        let trusted = signer_ids(&signers);
        let nodes = vec![entry(200, "203.0.113.1"), entry(201, "203.0.113.2")];
        let blob = build_blob(&signers, &nodes, &trusted, 100);
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
        let nodes = vec![entry(200, "h")];
        let blob = build_blob(&signers, &nodes, &new_set, 100);
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
        let nodes = vec![entry(200, "h")];
        let mut blob = build_blob(&signers, &nodes, &trusted, 100);
        let mut sig = hex::decode(&blob.proposer_signature).unwrap();
        sig[0] ^= 0xff;
        blob.proposer_signature = hex::encode(sig);
        let mut t = trusted.clone();
        assert!(verify_and_advance(&blob, &mut t).is_err());
        assert_eq!(t, trusted, "trusted untouched on failure");
    }

    #[test]
    fn sub_quorum_rejected() {
        let signers: Vec<NodeIdentity> = (0..4).map(|_| NodeIdentity::generate()).collect();
        let trusted = signer_ids(&signers);
        let nodes = vec![entry(200, "h")];
        let mut blob = build_blob(&signers, &nodes, &trusted, 100);
        blob.approvals.truncate(2); // 2 < quorum(4) = 3
        assert!(verify_and_advance(&blob, &mut trusted.clone()).is_err());
    }

    #[test]
    fn wrong_list_root_rejected() {
        let signers: Vec<NodeIdentity> = (0..4).map(|_| NodeIdentity::generate()).collect();
        let trusted = signer_ids(&signers);
        let nodes = vec![entry(200, "h")];
        let mut blob = build_blob(&signers, &nodes, &trusted, 100);
        blob.list_root = hex::encode([9u8; 32]);
        assert!(verify_and_advance(&blob, &mut trusted.clone()).is_err());
    }

    #[test]
    fn outsider_signed_checkpoint_rejected() {
        // A checkpoint signed entirely by NON-trusted keys must be rejected: the proposer isn't
        // trusted and none of the approvals count, so an attacker can't self-certify a node list.
        let real: Vec<NodeIdentity> = (0..4).map(|_| NodeIdentity::generate()).collect();
        let trusted = signer_ids(&real);
        let attackers: Vec<NodeIdentity> = (0..4).map(|_| NodeIdentity::generate()).collect();
        let atk_set = signer_ids(&attackers);
        let nodes = vec![entry(200, "evil.example")];
        let blob = build_blob(&attackers, &nodes, &atk_set, 100);
        assert!(verify_and_advance(&blob, &mut trusted.clone()).is_err());
    }
}

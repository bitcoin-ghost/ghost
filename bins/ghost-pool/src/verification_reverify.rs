//! CONSENSUS SECURITY: recipient-side re-derivation of peer-broadcast
//! capability verdicts (Increment 1: Archive).
//!
//! Node-reward 5-4-3-2-1 shares are paid on peer-VERIFIED capabilities. The
//! consensus handler (`ghost_consensus::verification_handler`) used to store the
//! challenger's `passed` flag verbatim. A >5% colluding minority could therefore
//! sign `passed=false` against an honest node, drag it under the 95% gate, and
//! steal its reward share.
//!
//! `ChainReVerifier` closes this by RE-DERIVING the Archive verdict from:
//!   1. the TARGET's own signed `ArchiveResponse` (the only trustworthy input —
//!      `challenge_data`/`response_data` are authored by the adversarial
//!      challenger and are NOT in the signed tuple), and
//!   2. THIS node's own Bitcoin Core (ground truth),
//! using the SAME comparator the challenger runs
//! ([`ghost_verification::challenge::validate_archive_response`]) so there is
//! zero logic divergence.
//!
//! Verdict semantics (see `ReVerdict`):
//!   - `Pass`         — target's signed block data matches our chain.
//!   - `Fail`         — target's signed block data contradicts our chain.
//!   - `Unverifiable` — we cannot judge (no/invalid target signature,
//!     unparseable response, RPC error, or our node lacks the block). NEVER a
//!     false `Fail`: an unverifiable result must not be usable to grief.

use std::sync::Arc;

use async_trait::async_trait;

use ghost_common::identity::verify_signature;
use ghost_common::rpc::BitcoinRpc;
use ghost_common::types::NodeId;
use ghost_consensus::verification_handler::{ReVerdict, ResultReVerifier};
use ghost_policy::{PolicyEngine, PolicyProfile};
use ghost_verification::challenge::{
    validate_archive_response, validate_policy_response, ArchiveResponse, GhostPayResponse,
    PolicyResponse, SignedResponse,
};

/// Read-only view of the recipient's own chain. Abstracted behind a trait so the
/// re-derivation logic can be unit-tested with a stub instead of a live node.
#[async_trait]
trait ChainOracle: Send + Sync {
    /// Current validated chain tip height (`None` on RPC error).
    async fn block_count(&self) -> Option<u64>;
    /// Block hash at `height` (`None` if missing / RPC error).
    async fn block_hash(&self, height: u64) -> Option<String>;
    /// Merkle root of the block identified by `hash` (`None` on error).
    async fn merkle_root(&self, hash: &str) -> Option<String>;
}

/// [`ChainOracle`] backed by the node's real Bitcoin Core RPC.
struct RpcOracle(Arc<BitcoinRpc>);

#[async_trait]
impl ChainOracle for RpcOracle {
    async fn block_count(&self) -> Option<u64> {
        self.0.get_block_count().await.ok()
    }

    async fn block_hash(&self, height: u64) -> Option<String> {
        self.0.get_block_hash(height).await.ok()
    }

    async fn merkle_root(&self, hash: &str) -> Option<String> {
        self.0
            .get_block_header(hash)
            .await
            .ok()
            .map(|h| h.merkleroot)
    }
}

/// Re-derives Archive verdicts against the node's own Bitcoin Core, and Policy
/// verdicts against the node's own [`PolicyEngine`].
pub struct ChainReVerifier {
    rpc: Arc<BitcoinRpc>,
    /// The node's configured policy profile — the recipient's ground truth for
    /// re-classifying a policy-challenge tx. A fresh [`PolicyEngine`] is built per
    /// call (`evaluate` takes `&mut self`).
    policy: PolicyProfile,
}

impl ChainReVerifier {
    /// Create a re-verifier bound to the node's Bitcoin Core RPC client and its
    /// configured policy profile.
    pub fn new(rpc: Arc<BitcoinRpc>, policy: PolicyProfile) -> Self {
        Self { rpc, policy }
    }
}

#[async_trait]
impl ResultReVerifier for ChainReVerifier {
    async fn reverify_archive(
        &self,
        target_node_id: &NodeId,
        challenge_data: &str,
        target_signed_response: Option<&str>,
    ) -> ReVerdict {
        let oracle = RpcOracle(Arc::clone(&self.rpc));
        reverify_archive_impl(
            &oracle,
            target_node_id,
            challenge_data,
            target_signed_response,
        )
        .await
    }

    async fn reverify_policy(
        &self,
        target_node_id: &NodeId,
        challenge_data: &str,
        target_signed_response: Option<&str>,
    ) -> ReVerdict {
        reverify_policy_impl(
            &self.policy,
            target_node_id,
            challenge_data,
            target_signed_response,
        )
    }

    async fn reverify_ghostpay(
        &self,
        target_node_id: &NodeId,
        challenge_data: &str,
        target_signed_response: Option<&str>,
    ) -> ReVerdict {
        reverify_ghostpay_impl(target_node_id, challenge_data, target_signed_response)
    }
}

/// Core Archive re-derivation, generic over the chain source for testability.
///
/// SECURITY: every value the verdict turns on comes from a trustworthy source —
/// `height`/`hash`/`merkle_root` from inside the TARGET-signed payload, and the
/// ground-truth hash/merkle from the recipient's OWN node. Nothing from the
/// challenger is consulted.
async fn reverify_archive_impl<O: ChainOracle + ?Sized>(
    oracle: &O,
    target_node_id: &NodeId,
    challenge_data: &str,
    target_signed_response: Option<&str>,
) -> ReVerdict {
    // 1. No signed response at all — we cannot judge.
    let raw = match target_signed_response {
        Some(s) if !s.trim().is_empty() => s,
        _ => return ReVerdict::Unverifiable,
    };

    // 2. Parse the TARGET's signed response. A malformed blob is not a FAIL.
    let signed: SignedResponse<ArchiveResponse> = match serde_json::from_str(raw) {
        Ok(s) => s,
        Err(_) => return ReVerdict::Unverifiable,
    };

    // 3a. The signer MUST be the target. A response signed by anyone else (or a
    //     proxied response) tells us nothing about the target.
    let target_hex = hex::encode(target_node_id);
    if !signed.signer.eq_ignore_ascii_case(&target_hex) {
        return ReVerdict::Unverifiable;
    }

    // 3b. Verify the target's Ed25519 signature + freshness (timestamp bounds are
    //     enforced inside `SignedResponse::verify`). A bad/absent signature is
    //     Unverifiable, NOT Fail — a forged or stale signature must not let a
    //     challenger grief the target.
    let verify_result = signed.verify(|signer_hex, message_hash, signature_bytes| {
        let pk_bytes = match hex::decode(signer_hex) {
            Ok(b) if b.len() == 32 => b,
            _ => return false,
        };
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&pk_bytes);
        let sig: [u8; 64] = match signature_bytes.try_into() {
            Ok(s) => s,
            Err(_) => return false,
        };
        verify_signature(&pk, message_hash, &sig).unwrap_or(false)
    });
    if verify_result.is_err() {
        return ReVerdict::Unverifiable;
    }

    // 3c. Bind the response to THIS challenge.
    //
    //     `SignedResponse::verify` above only bounds freshness — `MAX_RESPONSE_AGE_SECS`
    //     is 300s — so a correct, correctly-signed response captured from an earlier
    //     challenge can be replayed inside that window to keep a node earning the
    //     capability after it has stopped serving it. The nonce the challenge chose is
    //     what ties the signature to this request.
    //
    //     `challenge_data` is authored by the (adversarial) challenger, exactly like the
    //     height in step 4, so a mismatch is UNVERIFIABLE and never Fail. Otherwise
    //     naming a wrong nonce would be a free way to drag an honest node under its
    //     pass-rate gate — the griefing vector this whole function exists to close.
    //
    //     A challenge_data carrying no nonce is not enforced, so challengers that
    //     predate this still get their results judged rather than silently dropped.
    //     That also means omitting the nonce bypasses the binding, which is why making
    //     it mandatory needs a height gate once the fleet is known to send one.
    if let Some(expected) = serde_json::from_str::<serde_json::Value>(challenge_data)
        .ok()
        .as_ref()
        .and_then(|v| v.get("nonce"))
        .and_then(|n| n.as_str())
        .map(str::to_owned)
    {
        match signed.challenge_nonce.as_deref() {
            Some(got) if got == expected => {}
            _ => return ReVerdict::Unverifiable,
        }
    }

    // 4. Take the height from inside the TARGET-signed payload — NEVER from the
    //    challenger's challenge_data. (Taking height from challenge_data would let
    //    a colluder pair a valid signed response with a mismatched height to force
    //    a false FAIL.)
    let block_data = match signed.payload.block_data.as_ref() {
        Some(bd) => bd,
        None => return ReVerdict::Unverifiable,
    };
    let height = block_data.height;

    // 5. Ground truth from the recipient's OWN node. If we are behind / lack the
    //    block / hit an RPC error, we cannot judge — do not grief a lagging node.
    let tip = match oracle.block_count().await {
        Some(h) => h,
        None => return ReVerdict::Unverifiable,
    };
    if height > tip {
        return ReVerdict::Unverifiable;
    }
    let real_hash = match oracle.block_hash(height).await {
        Some(h) => h,
        None => return ReVerdict::Unverifiable,
    };
    let real_merkle = match oracle.merkle_root(&real_hash).await {
        Some(m) => m,
        None => return ReVerdict::Unverifiable,
    };

    // 6. Same comparator the challenger uses — zero divergence. The target's
    //    claimed hash/merkle are checked against OUR hash/merkle for OUR height.
    let (passed, _detail) =
        validate_archive_response(&signed.payload, &real_hash, height, Some(&real_merkle));
    if passed {
        ReVerdict::Pass
    } else {
        ReVerdict::Fail
    }
}

/// Core Policy re-derivation. Pure (no RPC) so it can be unit-tested with a real
/// [`PolicyProfile`] + real transactions.
///
/// SECURITY: every value the verdict turns on comes from a trustworthy source —
/// the classification from inside the TARGET-signed payload, and the ground-truth
/// `(tier, accepted)` from the recipient's OWN policy engine over the SAME tx. The
/// only thing read from the (adversarial) challenger is the `tx_hex`, and it is
/// BOUND to the signature: the recompiled txid must equal the signed `tx_txid`,
/// so a colluder cannot pair a valid signed classification with a different tx to
/// force a mismatch and grief the target.
fn reverify_policy_impl(
    policy: &PolicyProfile,
    target_node_id: &NodeId,
    challenge_data: &str,
    target_signed_response: Option<&str>,
) -> ReVerdict {
    // 1. No signed response at all — we cannot judge.
    let raw = match target_signed_response {
        Some(s) if !s.trim().is_empty() => s,
        _ => return ReVerdict::Unverifiable,
    };

    // 2. Parse the TARGET's signed response. A malformed blob is not a FAIL.
    let signed: SignedResponse<PolicyResponse> = match serde_json::from_str(raw) {
        Ok(s) => s,
        Err(_) => return ReVerdict::Unverifiable,
    };

    // 3a. The signer MUST be the target. A response signed by anyone else tells us
    //     nothing about the target.
    let target_hex = hex::encode(target_node_id);
    if !signed.signer.eq_ignore_ascii_case(&target_hex) {
        return ReVerdict::Unverifiable;
    }

    // 3b. Verify the target's Ed25519 signature + freshness. A bad/absent/stale
    //     signature is Unverifiable, NOT Fail.
    let verify_result = signed.verify(|signer_hex, message_hash, signature_bytes| {
        let pk_bytes = match hex::decode(signer_hex) {
            Ok(b) if b.len() == 32 => b,
            _ => return false,
        };
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&pk_bytes);
        let sig: [u8; 64] = match signature_bytes.try_into() {
            Ok(s) => s,
            Err(_) => return false,
        };
        verify_signature(&pk, message_hash, &sig).unwrap_or(false)
    });
    if verify_result.is_err() {
        return ReVerdict::Unverifiable;
    }

    // 4. Extract the tx_hex the challenger broadcast and reconstruct the tx. A
    //    missing / undecodable / undeserializable tx_hex is Unverifiable.
    let tx_hex = match serde_json::from_str::<serde_json::Value>(challenge_data)
        .ok()
        .and_then(|v| v.get("tx_hex").and_then(|t| t.as_str()).map(String::from))
    {
        Some(h) => h,
        None => return ReVerdict::Unverifiable,
    };
    let tx_bytes = match hex::decode(&tx_hex) {
        Ok(b) => b,
        Err(_) => return ReVerdict::Unverifiable,
    };
    let tx: bitcoin::Transaction = match bitcoin::consensus::deserialize(&tx_bytes) {
        Ok(t) => t,
        Err(_) => return ReVerdict::Unverifiable,
    };

    // 5. BINDING: the tx the challenger gave us MUST be the tx the target signed.
    //    If the signed payload has no txid, or it doesn't match, the challenger
    //    swapped the tx — we cannot judge, so we must NOT grief the target.
    match signed.payload.tx_txid.as_deref() {
        Some(signed_txid) if signed_txid == tx.compute_txid().to_string() => {}
        _ => return ReVerdict::Unverifiable,
    }

    // 6. Re-classify with the recipient's OWN engine — ground truth. `evaluate`
    //    needs `&mut self`, so build a fresh engine per call.
    let decision = PolicyEngine::new(policy.clone()).evaluate(&tx);
    let our_tier = decision.tier().to_string();
    let our_accepted = decision.is_accepted();

    // 7. Same comparator the challenger uses — zero divergence. The target's
    //    signed classification is checked against OUR engine's classification of
    //    the SAME tx.
    let (passed, _detail) = validate_policy_response(&signed.payload, &our_tier, our_accepted);
    if passed {
        ReVerdict::Pass
    } else {
        ReVerdict::Fail
    }
}

/// Core GhostPay re-derivation. Pure (no RPC) so it can be unit-tested directly.
///
/// GhostPay reachability of an L2 endpoint cannot be reproduced from a transcript
/// by a node that does not itself run that L2 — but the TARGET can PROVE fresh
/// possession of L2 state cryptographically: for a challenger-chosen random epoch
/// it returns `epoch_state_hash` and a nonce-bound proof
/// `SHA256(epoch_state_hash || challenge_nonce)`, all inside a response SIGNED by
/// its node identity (which also binds the `challenge_nonce`). A colluding
/// challenger therefore cannot fabricate a PASS for a target that never answered:
/// it can forge neither the signature nor a nonce-bound proof over a random epoch.
///
/// SECURITY: this verdict is PASS-or-`Unverifiable` — it NEVER returns `Fail`.
/// Every negative (no/invalid/stale signature, missing epoch proof, nonce
/// mismatch) could equally be an honest target that a colluding challenger denied
/// a fair challenge (omitted the epoch, swapped the nonce), so recording a FAIL
/// would let a colluder grief. A node that cannot positively prove GhostPay simply
/// accrues no PASS rows and never reaches the qualification floor — which is the
/// correct outcome without any grief surface. (The residual "an operator runs its
/// OWN signing target" self-attestation is a Sybil-cost problem addressed by
/// Surface A-2/A-5, not by re-derivation.)
fn reverify_ghostpay_impl(
    target_node_id: &NodeId,
    challenge_data: &str,
    target_signed_response: Option<&str>,
) -> ReVerdict {
    // 1. No signed response at all — we cannot judge.
    let raw = match target_signed_response {
        Some(s) if !s.trim().is_empty() => s,
        _ => return ReVerdict::Unverifiable,
    };

    // 2. Parse the TARGET's signed response. A malformed blob is not a FAIL.
    let signed: SignedResponse<GhostPayResponse> = match serde_json::from_str(raw) {
        Ok(s) => s,
        Err(_) => return ReVerdict::Unverifiable,
    };

    // 3a. The signer MUST be the target.
    let target_hex = hex::encode(target_node_id);
    if !signed.signer.eq_ignore_ascii_case(&target_hex) {
        return ReVerdict::Unverifiable;
    }

    // 3b. Verify the target's Ed25519 signature + freshness. This authenticates the
    //     payload AND the `challenge_nonce` the target signed over. A
    //     bad/absent/stale signature is Unverifiable, NOT Fail.
    let verify_result = signed.verify(|signer_hex, message_hash, signature_bytes| {
        let pk_bytes = match hex::decode(signer_hex) {
            Ok(b) if b.len() == 32 => b,
            _ => return false,
        };
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&pk_bytes);
        let sig: [u8; 64] = match signature_bytes.try_into() {
            Ok(s) => s,
            Err(_) => return false,
        };
        verify_signature(&pk, message_hash, &sig).unwrap_or(false)
    });
    if verify_result.is_err() {
        return ReVerdict::Unverifiable;
    }

    // 4. Extract the nonce the challenger says it issued (challenger-authored, but
    //    bound to the broadcast by the M-6 challenge_data_hash signature).
    let challenge_nonce = match serde_json::from_str::<serde_json::Value>(challenge_data)
        .ok()
        .and_then(|v| {
            v.get("challenge_nonce")
                .and_then(|n| n.as_str())
                .map(String::from)
        }) {
        Some(n) if !n.is_empty() => n,
        _ => return ReVerdict::Unverifiable,
    };

    // 5. BINDING: the nonce the TARGET signed over must be the nonce the challenger
    //    issued. A mismatch means the challenger paired this challenge with an
    //    unrelated signed response — we cannot judge, so we must not grief.
    match signed.challenge_nonce.as_deref() {
        Some(cn) if cn == challenge_nonce => {}
        _ => return ReVerdict::Unverifiable,
    }

    // 6. The signed payload must positively PROVE fresh L2 state: success, an
    //    epoch state hash, and a nonce-bound proof. Anything short of that is
    //    Unverifiable (never a griefing FAIL).
    let payload = &signed.payload;
    let (state_hash, nonce_bound_proof) = match (
        payload.success,
        payload.epoch_state_hash.as_deref(),
        payload.nonce_bound_proof.as_deref(),
    ) {
        (true, Some(h), Some(p)) if !h.is_empty() && !p.is_empty() => (h, p),
        _ => return ReVerdict::Unverifiable,
    };

    // 7. Recompute the nonce-bound proof from the TARGET-signed epoch_state_hash and
    //    the issued nonce, exactly as the server does
    //    (SHA256(epoch_state_hash || challenge_nonce)), and require an exact match.
    //    This proves the target incorporated THIS challenge's nonce into a proof
    //    over its OWN epoch state — defeating precompute and replay.
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(state_hash.as_bytes());
    hasher.update(challenge_nonce.as_bytes());
    let expected = hex::encode(hasher.finalize());

    if expected.eq_ignore_ascii_case(nonce_bound_proof) {
        ReVerdict::Pass
    } else {
        ReVerdict::Unverifiable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::identity::NodeIdentity;
    use ghost_verification::challenge::BlockData;

    /// Stub chain that returns a fixed `(hash, merkle)` for a single height.
    struct StubOracle {
        tip: u64,
        height: u64,
        hash: String,
        merkle: String,
        /// When true, all lookups fail (simulates RPC error / IBD).
        broken: bool,
    }

    #[async_trait]
    impl ChainOracle for StubOracle {
        async fn block_count(&self) -> Option<u64> {
            if self.broken {
                None
            } else {
                Some(self.tip)
            }
        }
        async fn block_hash(&self, height: u64) -> Option<String> {
            if self.broken || height != self.height {
                None
            } else {
                Some(self.hash.clone())
            }
        }
        async fn merkle_root(&self, hash: &str) -> Option<String> {
            if self.broken || hash != self.hash {
                None
            } else {
                Some(self.merkle.clone())
            }
        }
    }

    const REAL_HASH: &str = "00000000000000000001a2b3c4d5e6f70809102030405060708090a0b0c0d0e0";
    const REAL_MERKLE: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn good_oracle() -> StubOracle {
        StubOracle {
            tip: 1_000,
            height: 500,
            hash: REAL_HASH.to_string(),
            merkle: REAL_MERKLE.to_string(),
            broken: false,
        }
    }

    /// Build a `SignedResponse<ArchiveResponse>` JSON signed by `identity` for the
    /// given block fields.
    fn make_signed_response(
        identity: &NodeIdentity,
        height: u64,
        hash: &str,
        merkle: &str,
        success: bool,
    ) -> String {
        let resp = ArchiveResponse {
            success,
            block_data: Some(BlockData {
                hash: hash.to_string(),
                height,
                timestamp: 1_600_000_000, // safely in the past
                tx_count: 2,
                merkle_root: merkle.to_string(),
            }),
            tx_data: None,
            error: None,
        };
        let signer_hex = identity.node_id_hex();
        let signed = SignedResponse::new(resp, signer_hex, |msg| identity.sign(msg), None);
        serde_json::to_string(&signed).expect("serialize signed response")
    }

    fn make_signed_response_bound(
        identity: &NodeIdentity,
        height: u64,
        hash: &str,
        merkle: &str,
        challenge_nonce: Option<String>,
    ) -> String {
        let resp = ArchiveResponse {
            success: true,
            block_data: Some(BlockData {
                hash: hash.to_string(),
                height,
                timestamp: 1_600_000_000,
                tx_count: 2,
                merkle_root: merkle.to_string(),
            }),
            tx_data: None,
            error: None,
        };
        let signer_hex = identity.node_id_hex();
        let signed =
            SignedResponse::new(resp, signer_hex, |msg| identity.sign(msg), challenge_nonce);
        serde_json::to_string(&signed).expect("serialize signed response")
    }

    /// REPLAY: a correct, correctly-signed response that was bound to a DIFFERENT
    /// challenge must not count for this one.
    ///
    /// `SignedResponse::verify` only bounds freshness to `MAX_RESPONSE_AGE_SECS`
    /// (300s), so without binding the reply to the nonce this challenge chose, a
    /// captured response can be replayed inside that window to keep a node earning
    /// the capability after it has stopped serving it.
    #[tokio::test]
    async fn a_response_bound_to_another_nonce_is_unverifiable_not_pass() {
        let target = NodeIdentity::generate();
        let raw = make_signed_response_bound(
            &target,
            500,
            REAL_HASH,
            REAL_MERKLE,
            Some("aaaaaaaaaaaaaaaa".to_string()),
        );
        let challenge_data = r#"{"nonce":"bbbbbbbbbbbbbbbb"}"#;

        let verdict = reverify_archive_impl(
            &good_oracle(),
            &target.node_id(),
            challenge_data,
            Some(&raw),
        )
        .await;

        assert_eq!(
            verdict,
            ReVerdict::Unverifiable,
            "a response bound to another nonce must not be accepted"
        );
    }

    /// ANTI-GRIEF: the nonce comparison uses challenger-authored `challenge_data`,
    /// so a malicious challenger can put any nonce there. A mismatch must therefore
    /// be Unverifiable and NEVER Fail — otherwise naming a wrong nonce becomes a
    /// free way to drag an honest node below its pass-rate gate.
    #[tokio::test]
    async fn a_nonce_mismatch_is_never_a_fail() {
        let target = NodeIdentity::generate();
        let raw = make_signed_response_bound(
            &target,
            500,
            REAL_HASH,
            REAL_MERKLE,
            Some("honest-nonce".to_string()),
        );
        let lying_challenge_data = r#"{"nonce":"attacker-chosen"}"#;

        let verdict = reverify_archive_impl(
            &good_oracle(),
            &target.node_id(),
            lying_challenge_data,
            Some(&raw),
        )
        .await;

        assert_ne!(
            verdict,
            ReVerdict::Fail,
            "a nonce mismatch must never grief the target"
        );
    }

    /// The bound case still passes: nonce echoed, signature good, chain agrees.
    #[tokio::test]
    async fn a_response_bound_to_this_nonce_passes() {
        let target = NodeIdentity::generate();
        let raw = make_signed_response_bound(
            &target,
            500,
            REAL_HASH,
            REAL_MERKLE,
            Some("cafebabecafebabe".to_string()),
        );
        let challenge_data = r#"{"nonce":"cafebabecafebabe"}"#;

        let verdict = reverify_archive_impl(
            &good_oracle(),
            &target.node_id(),
            challenge_data,
            Some(&raw),
        )
        .await;

        assert_eq!(verdict, ReVerdict::Pass);
    }

    /// FRAUD: target signs a wrong hash for the height; our RPC disagrees => Fail,
    /// regardless of what the challenger claimed.
    #[tokio::test]
    async fn fraud_wrong_hash_is_fail() {
        let target = NodeIdentity::generate();
        let bogus_hash = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef0";
        let raw = make_signed_response(&target, 500, bogus_hash, REAL_MERKLE, true);

        let verdict =
            reverify_archive_impl(&good_oracle(), &target.node_id(), "{}", Some(&raw)).await;
        assert_eq!(verdict, ReVerdict::Fail);
    }

    /// FRAUD: target signs a wrong merkle root => Fail.
    #[tokio::test]
    async fn fraud_wrong_merkle_is_fail() {
        let target = NodeIdentity::generate();
        let bogus_merkle = "2222222222222222222222222222222222222222222222222222222222222222";
        let raw = make_signed_response(&target, 500, REAL_HASH, bogus_merkle, true);

        let verdict =
            reverify_archive_impl(&good_oracle(), &target.node_id(), "{}", Some(&raw)).await;
        assert_eq!(verdict, ReVerdict::Fail);
    }

    /// GRIEFING (priority): challenger claimed `passed=false`, but the target's
    /// signed response matches our ground truth => Pass (override to true). The
    /// challenger's claim never reaches this function — the verdict is derived
    /// purely from the signature + our chain.
    #[tokio::test]
    async fn honest_response_overrides_grief_to_pass() {
        let target = NodeIdentity::generate();
        let raw = make_signed_response(&target, 500, REAL_HASH, REAL_MERKLE, true);

        let verdict =
            reverify_archive_impl(&good_oracle(), &target.node_id(), "{}", Some(&raw)).await;
        assert_eq!(verdict, ReVerdict::Pass);
    }

    /// Verdict equals what the shared comparator returns: a response with
    /// `success=false` (genuinely wrong) is a Fail even with the right hash.
    #[tokio::test]
    async fn unsuccessful_response_is_fail() {
        let target = NodeIdentity::generate();
        let raw = make_signed_response(&target, 500, REAL_HASH, REAL_MERKLE, false);

        let verdict =
            reverify_archive_impl(&good_oracle(), &target.node_id(), "{}", Some(&raw)).await;
        assert_eq!(verdict, ReVerdict::Fail);

        // Cross-check: the free comparator agrees on the same payload.
        let signed: SignedResponse<ArchiveResponse> = serde_json::from_str(&raw).unwrap();
        let (passed, _) =
            validate_archive_response(&signed.payload, REAL_HASH, 500, Some(REAL_MERKLE));
        assert!(!passed);
    }

    /// No signed response => Unverifiable (and the handler stores nothing).
    #[tokio::test]
    async fn missing_response_is_unverifiable() {
        let target = NodeIdentity::generate();
        assert_eq!(
            reverify_archive_impl(&good_oracle(), &target.node_id(), "{}", None).await,
            ReVerdict::Unverifiable
        );
        assert_eq!(
            reverify_archive_impl(&good_oracle(), &target.node_id(), "{}", Some("   ")).await,
            ReVerdict::Unverifiable
        );
    }

    /// Unparseable signed response => Unverifiable.
    #[tokio::test]
    async fn unparseable_response_is_unverifiable() {
        let target = NodeIdentity::generate();
        assert_eq!(
            reverify_archive_impl(&good_oracle(), &target.node_id(), "{}", Some("{not json")).await,
            ReVerdict::Unverifiable
        );
    }

    /// Signed by the WRONG key (not the target) => Unverifiable, NOT Fail.
    #[tokio::test]
    async fn wrong_signer_is_unverifiable() {
        let target = NodeIdentity::generate();
        let imposter = NodeIdentity::generate();
        // Imposter signs (signer field = imposter), but we judge it as `target`.
        let raw = make_signed_response(&imposter, 500, REAL_HASH, REAL_MERKLE, true);

        let verdict =
            reverify_archive_impl(&good_oracle(), &target.node_id(), "{}", Some(&raw)).await;
        assert_eq!(verdict, ReVerdict::Unverifiable);
    }

    /// Tampered signature (signer claims target, but bytes don't verify) =>
    /// Unverifiable.
    #[tokio::test]
    async fn invalid_signature_is_unverifiable() {
        let target = NodeIdentity::generate();
        let mut raw = make_signed_response(&target, 500, REAL_HASH, REAL_MERKLE, true);
        // Corrupt the signature hex in-place (flip a nibble) while keeping length.
        let mut value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let sig = value["signature"].as_str().unwrap().to_string();
        let mut chars: Vec<char> = sig.chars().collect();
        chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
        value["signature"] = serde_json::Value::String(chars.into_iter().collect());
        raw = serde_json::to_string(&value).unwrap();

        let verdict =
            reverify_archive_impl(&good_oracle(), &target.node_id(), "{}", Some(&raw)).await;
        assert_eq!(verdict, ReVerdict::Unverifiable);
    }

    /// RPC error (node behind / IBD) => Unverifiable, never a grief-FAIL.
    #[tokio::test]
    async fn rpc_error_is_unverifiable() {
        let target = NodeIdentity::generate();
        let raw = make_signed_response(&target, 500, REAL_HASH, REAL_MERKLE, true);
        let mut oracle = good_oracle();
        oracle.broken = true;

        let verdict = reverify_archive_impl(&oracle, &target.node_id(), "{}", Some(&raw)).await;
        assert_eq!(verdict, ReVerdict::Unverifiable);
    }

    /// Height beyond our tip (we lack the block) => Unverifiable.
    #[tokio::test]
    async fn height_above_tip_is_unverifiable() {
        let target = NodeIdentity::generate();
        // Sign a response for height 5000 while our tip is only 1000.
        let raw = make_signed_response(&target, 5_000, REAL_HASH, REAL_MERKLE, true);

        let verdict =
            reverify_archive_impl(&good_oracle(), &target.node_id(), "{}", Some(&raw)).await;
        assert_eq!(verdict, ReVerdict::Unverifiable);
    }

    // =================================================================
    // Policy (Bitcoin Pure) re-derivation tests. Real txs + a real
    // bitcoin_pure PolicyProfile so classification is genuine, not faked.
    // =================================================================

    use ghost_verification::challenge::PolicyClassification;

    /// A clean single-output P2WPKH payment — `bitcoin_pure` classifies it T0 and
    /// accepts it.
    fn clean_tx() -> bitcoin::Transaction {
        use bitcoin::hashes::Hash;
        use bitcoin::locktime::absolute::LockTime;
        use bitcoin::script::{Builder, ScriptBuf};
        use bitcoin::transaction::{Transaction, Version};
        use bitcoin::{Amount, OutPoint, Sequence, TxIn, TxOut, Txid, Witness};

        let p2wpkh = Builder::new()
            .push_int(0)
            .push_slice([7u8; 20])
            .into_script();
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::all_zeros(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: p2wpkh,
            }],
        }
    }

    /// A data-carrier tx with a 100-byte OP_RETURN — `bitcoin_pure`
    /// (`max_op_return_size = 0`) classifies it non-T0 and refuses it.
    fn dirty_tx() -> bitcoin::Transaction {
        use bitcoin::hashes::Hash;
        use bitcoin::locktime::absolute::LockTime;
        use bitcoin::script::{Builder, PushBytesBuf, ScriptBuf};
        use bitcoin::transaction::{Transaction, Version};
        use bitcoin::{Amount, OutPoint, Sequence, TxIn, TxOut, Txid, Witness};

        let p2wpkh = Builder::new()
            .push_int(0)
            .push_slice([9u8; 20])
            .into_script();
        let payload = PushBytesBuf::try_from(vec![0x42u8; 100]).unwrap();
        let op_return = Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_RETURN)
            .push_slice(&payload)
            .into_script();
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::all_zeros(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey: p2wpkh,
                },
                TxOut {
                    value: Amount::from_sat(0),
                    script_pubkey: op_return,
                },
            ],
        }
    }

    fn pure() -> PolicyProfile {
        PolicyProfile::bitcoin_pure()
    }

    /// `{"tx_hex": "<consensus hex of tx>"}` — exactly what the challenger broadcasts.
    fn challenge_data_for(tx: &bitcoin::Transaction) -> String {
        let hex = bitcoin::consensus::encode::serialize_hex(tx);
        serde_json::json!({ "tx_hex": hex }).to_string()
    }

    /// Classify `tx` with the recipient's own bitcoin_pure engine -> `(tier, accepted)`.
    fn classify(tx: &bitcoin::Transaction) -> (String, bool) {
        let decision = PolicyEngine::new(pure()).evaluate(tx);
        (decision.tier().to_string(), decision.is_accepted())
    }

    /// Build a `SignedResponse<PolicyResponse>` JSON signed by `identity`.
    fn make_signed_policy_response(
        identity: &NodeIdentity,
        tier: &str,
        accepted: bool,
        tx_txid: Option<String>,
        success: bool,
    ) -> String {
        let resp = PolicyResponse {
            success,
            profile: "bitcoin_pure".to_string(),
            classification: Some(PolicyClassification {
                tier: tier.to_string(),
                reason: "test".to_string(),
                features: vec![],
            }),
            accepted,
            rejection_reason: None,
            tx_txid,
            error: None,
        };
        let signer_hex = identity.node_id_hex();
        let signed = SignedResponse::new(resp, signer_hex, |msg| identity.sign(msg), None);
        serde_json::to_string(&signed).expect("serialize signed policy response")
    }

    /// FRAUD: target signs tier="T0"/accepted=true bound to a DIRTY data-carrier
    /// tx; our engine classifies it non-T0/reject => Fail.
    #[test]
    fn fraud_dirty_tx_claimed_t0_is_fail() {
        let target = NodeIdentity::generate();
        let tx = dirty_tx();
        let signed = make_signed_policy_response(
            &target,
            "T0",
            true,
            Some(tx.compute_txid().to_string()),
            true,
        );
        let verdict = reverify_policy_impl(
            &pure(),
            &target.node_id(),
            &challenge_data_for(&tx),
            Some(&signed),
        );
        assert_eq!(verdict, ReVerdict::Fail);
    }

    /// GRIEFING (priority): the target's signed classification MATCHES our own
    /// classification of the bound tx => Pass (overrides any challenger
    /// `passed=false`). The challenger's claim never reaches this function.
    #[test]
    fn honest_classification_overrides_grief_to_pass() {
        let target = NodeIdentity::generate();
        let tx = clean_tx();
        let (tier, accepted) = classify(&tx);
        let signed = make_signed_policy_response(
            &target,
            &tier,
            accepted,
            Some(tx.compute_txid().to_string()),
            true,
        );
        let verdict = reverify_policy_impl(
            &pure(),
            &target.node_id(),
            &challenge_data_for(&tx),
            Some(&signed),
        );
        assert_eq!(verdict, ReVerdict::Pass);
    }

    /// No-regression: honest correct classification => Pass, and the verdict
    /// equals what the shared comparator returns on the same inputs.
    #[test]
    fn honest_matches_shared_comparator() {
        let target = NodeIdentity::generate();
        let tx = clean_tx();
        let (tier, accepted) = classify(&tx);
        let signed_raw = make_signed_policy_response(
            &target,
            &tier,
            accepted,
            Some(tx.compute_txid().to_string()),
            true,
        );
        let verdict = reverify_policy_impl(
            &pure(),
            &target.node_id(),
            &challenge_data_for(&tx),
            Some(&signed_raw),
        );
        assert_eq!(verdict, ReVerdict::Pass);

        // Cross-check: the free comparator agrees on the same payload.
        let signed: SignedResponse<PolicyResponse> = serde_json::from_str(&signed_raw).unwrap();
        let (passed, _) = validate_policy_response(&signed.payload, &tier, accepted);
        assert!(passed);
    }

    /// TX-SWAP: the signed response is valid (signed for the CLEAN tx), but the
    /// challenger pairs it with a DIFFERENT tx_hex (the dirty tx) => the recomputed
    /// txid won't match the signed `tx_txid` => Unverifiable (no grief).
    #[test]
    fn tx_swap_is_unverifiable() {
        let target = NodeIdentity::generate();
        let clean = clean_tx();
        let dirty = dirty_tx();
        let (tier, accepted) = classify(&clean);
        // Signature commits to the CLEAN tx's txid.
        let signed = make_signed_policy_response(
            &target,
            &tier,
            accepted,
            Some(clean.compute_txid().to_string()),
            true,
        );
        // But the challenge_data carries the DIRTY tx.
        let verdict = reverify_policy_impl(
            &pure(),
            &target.node_id(),
            &challenge_data_for(&dirty),
            Some(&signed),
        );
        assert_eq!(verdict, ReVerdict::Unverifiable);
    }

    /// Payload with no `tx_txid` (nothing to bind to) => Unverifiable.
    #[test]
    fn missing_tx_txid_is_unverifiable() {
        let target = NodeIdentity::generate();
        let tx = clean_tx();
        let (tier, accepted) = classify(&tx);
        let signed = make_signed_policy_response(&target, &tier, accepted, None, true);
        let verdict = reverify_policy_impl(
            &pure(),
            &target.node_id(),
            &challenge_data_for(&tx),
            Some(&signed),
        );
        assert_eq!(verdict, ReVerdict::Unverifiable);
    }

    /// No signed response / blank => Unverifiable.
    #[test]
    fn policy_missing_response_is_unverifiable() {
        let target = NodeIdentity::generate();
        let tx = clean_tx();
        let cd = challenge_data_for(&tx);
        assert_eq!(
            reverify_policy_impl(&pure(), &target.node_id(), &cd, None),
            ReVerdict::Unverifiable
        );
        assert_eq!(
            reverify_policy_impl(&pure(), &target.node_id(), &cd, Some("   ")),
            ReVerdict::Unverifiable
        );
    }

    /// Unparseable signed response => Unverifiable.
    #[test]
    fn policy_unparseable_response_is_unverifiable() {
        let target = NodeIdentity::generate();
        let cd = challenge_data_for(&clean_tx());
        assert_eq!(
            reverify_policy_impl(&pure(), &target.node_id(), &cd, Some("{not json")),
            ReVerdict::Unverifiable
        );
    }

    /// Signed by the WRONG key (not the target) => Unverifiable, NOT Fail.
    #[test]
    fn policy_wrong_signer_is_unverifiable() {
        let target = NodeIdentity::generate();
        let imposter = NodeIdentity::generate();
        let tx = clean_tx();
        let (tier, accepted) = classify(&tx);
        let signed = make_signed_policy_response(
            &imposter,
            &tier,
            accepted,
            Some(tx.compute_txid().to_string()),
            true,
        );
        let verdict = reverify_policy_impl(
            &pure(),
            &target.node_id(),
            &challenge_data_for(&tx),
            Some(&signed),
        );
        assert_eq!(verdict, ReVerdict::Unverifiable);
    }

    /// Tampered signature => Unverifiable.
    #[test]
    fn policy_invalid_signature_is_unverifiable() {
        let target = NodeIdentity::generate();
        let tx = clean_tx();
        let (tier, accepted) = classify(&tx);
        let raw = make_signed_policy_response(
            &target,
            &tier,
            accepted,
            Some(tx.compute_txid().to_string()),
            true,
        );
        // Flip a nibble of the signature hex in-place.
        let mut value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let sig = value["signature"].as_str().unwrap().to_string();
        let mut chars: Vec<char> = sig.chars().collect();
        chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
        value["signature"] = serde_json::Value::String(chars.into_iter().collect());
        let tampered = serde_json::to_string(&value).unwrap();

        let verdict = reverify_policy_impl(
            &pure(),
            &target.node_id(),
            &challenge_data_for(&tx),
            Some(&tampered),
        );
        assert_eq!(verdict, ReVerdict::Unverifiable);
    }

    /// Missing `tx_hex` in challenge_data => Unverifiable.
    #[test]
    fn policy_missing_tx_hex_is_unverifiable() {
        let target = NodeIdentity::generate();
        let tx = clean_tx();
        let (tier, accepted) = classify(&tx);
        let signed = make_signed_policy_response(
            &target,
            &tier,
            accepted,
            Some(tx.compute_txid().to_string()),
            true,
        );
        let verdict = reverify_policy_impl(&pure(), &target.node_id(), "{}", Some(&signed));
        assert_eq!(verdict, ReVerdict::Unverifiable);
    }

    /// Undeserializable `tx_hex` (valid hex, not a tx) => Unverifiable.
    #[test]
    fn policy_undeserializable_tx_hex_is_unverifiable() {
        let target = NodeIdentity::generate();
        let tx = clean_tx();
        let (tier, accepted) = classify(&tx);
        let signed = make_signed_policy_response(
            &target,
            &tier,
            accepted,
            Some(tx.compute_txid().to_string()),
            true,
        );
        let cd = serde_json::json!({ "tx_hex": "00" }).to_string();
        let verdict = reverify_policy_impl(&pure(), &target.node_id(), &cd, Some(&signed));
        assert_eq!(verdict, ReVerdict::Unverifiable);

        // Non-hex tx_hex also => Unverifiable.
        let cd2 = serde_json::json!({ "tx_hex": "zzzz" }).to_string();
        let verdict2 = reverify_policy_impl(&pure(), &target.node_id(), &cd2, Some(&signed));
        assert_eq!(verdict2, ReVerdict::Unverifiable);
    }

    // =================================================================
    // GhostPay re-derivation (nonce-bound epoch proof)
    // =================================================================

    use ghost_verification::challenge::GhostPayResponse;

    const GP_STATE_HASH: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    fn nonce_bound(state_hash: &str, nonce: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(state_hash.as_bytes());
        h.update(nonce.as_bytes());
        hex::encode(h.finalize())
    }

    /// Build a `SignedResponse<GhostPayResponse>` JSON. When `good_proof` the
    /// `nonce_bound_proof` is the correct `SHA256(state_hash || nonce)`; otherwise
    /// it is a deliberately wrong value.
    fn make_signed_ghostpay(
        identity: &NodeIdentity,
        challenge_nonce: &str,
        state_hash: Option<&str>,
        success: bool,
        good_proof: bool,
    ) -> String {
        let nonce_bound_proof = state_hash.map(|sh| {
            if good_proof {
                nonce_bound(sh, challenge_nonce)
            } else {
                "00".repeat(32)
            }
        });
        let resp = GhostPayResponse {
            success,
            l2_enabled: true,
            virtual_block: Some(42),
            epoch: Some(7),
            balance_sats: None,
            wraith_enabled: false,
            epoch_state_hash: state_hash.map(String::from),
            epoch_tx_count: Some(3),
            nonce_bound_proof,
            epoch_proof: None,
            error: None,
        };
        let signer_hex = identity.node_id_hex();
        let signed = SignedResponse::new(
            resp,
            signer_hex,
            |msg| identity.sign(msg),
            Some(challenge_nonce.to_string()),
        );
        serde_json::to_string(&signed).expect("serialize signed ghostpay response")
    }

    fn gp_challenge_data(nonce: &str) -> String {
        serde_json::json!({
            "endpoint": "ghostpay",
            "challenge_epoch": 7,
            "challenge_nonce": nonce,
        })
        .to_string()
    }

    /// Happy path: signed, fresh, correct nonce-bound epoch proof => Pass.
    #[test]
    fn ghostpay_valid_nonce_bound_proof_is_pass() {
        let target = NodeIdentity::generate();
        let nonce = "a1b2c3d4e5f60718";
        let signed = make_signed_ghostpay(&target, nonce, Some(GP_STATE_HASH), true, true);
        let verdict =
            reverify_ghostpay_impl(&target.node_id(), &gp_challenge_data(nonce), Some(&signed));
        assert_eq!(verdict, ReVerdict::Pass);
    }

    /// No signed response at all => Unverifiable (never fabricate a PASS).
    #[test]
    fn ghostpay_missing_signed_response_is_unverifiable() {
        let target = NodeIdentity::generate();
        assert_eq!(
            reverify_ghostpay_impl(&target.node_id(), &gp_challenge_data("deadbeef"), None),
            ReVerdict::Unverifiable
        );
        assert_eq!(
            reverify_ghostpay_impl(
                &target.node_id(),
                &gp_challenge_data("deadbeef"),
                Some("   ")
            ),
            ReVerdict::Unverifiable
        );
    }

    /// Signed by someone OTHER than the target => Unverifiable (anti-proxy).
    #[test]
    fn ghostpay_wrong_signer_is_unverifiable() {
        let target = NodeIdentity::generate();
        let impostor = NodeIdentity::generate();
        let nonce = "a1b2c3d4e5f60718";
        let signed = make_signed_ghostpay(&impostor, nonce, Some(GP_STATE_HASH), true, true);
        let verdict =
            reverify_ghostpay_impl(&target.node_id(), &gp_challenge_data(nonce), Some(&signed));
        assert_eq!(verdict, ReVerdict::Unverifiable);
    }

    /// The nonce the target signed differs from the one the challenger issued =>
    /// Unverifiable (a colluder cannot bolt a valid proof onto a foreign challenge).
    #[test]
    fn ghostpay_nonce_mismatch_is_unverifiable() {
        let target = NodeIdentity::generate();
        let signed_nonce = "1111111111111111";
        let signed = make_signed_ghostpay(&target, signed_nonce, Some(GP_STATE_HASH), true, true);
        // challenger claims a DIFFERENT nonce
        let verdict = reverify_ghostpay_impl(
            &target.node_id(),
            &gp_challenge_data("2222222222222222"),
            Some(&signed),
        );
        assert_eq!(verdict, ReVerdict::Unverifiable);
    }

    /// A wrong `nonce_bound_proof` (precompute/replay attempt) => Unverifiable,
    /// NEVER Fail (a FAIL would be a grief surface).
    #[test]
    fn ghostpay_bad_nonce_bound_proof_is_unverifiable() {
        let target = NodeIdentity::generate();
        let nonce = "a1b2c3d4e5f60718";
        let signed = make_signed_ghostpay(&target, nonce, Some(GP_STATE_HASH), true, false);
        let verdict =
            reverify_ghostpay_impl(&target.node_id(), &gp_challenge_data(nonce), Some(&signed));
        assert_eq!(verdict, ReVerdict::Unverifiable);
    }

    /// A signed response that fails to prove epoch state (no epoch_state_hash, or
    /// success=false) => Unverifiable, never Fail.
    #[test]
    fn ghostpay_missing_epoch_proof_is_unverifiable() {
        let target = NodeIdentity::generate();
        let nonce = "a1b2c3d4e5f60718";

        // No epoch_state_hash / nonce_bound_proof.
        let no_state = make_signed_ghostpay(&target, nonce, None, true, true);
        assert_eq!(
            reverify_ghostpay_impl(
                &target.node_id(),
                &gp_challenge_data(nonce),
                Some(&no_state)
            ),
            ReVerdict::Unverifiable
        );

        // success=false even with a well-formed proof.
        let not_success = make_signed_ghostpay(&target, nonce, Some(GP_STATE_HASH), false, true);
        assert_eq!(
            reverify_ghostpay_impl(
                &target.node_id(),
                &gp_challenge_data(nonce),
                Some(&not_success)
            ),
            ReVerdict::Unverifiable
        );
    }
}

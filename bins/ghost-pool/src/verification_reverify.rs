//! CONSENSUS SECURITY: recipient-side re-derivation of peer-broadcast
//! capability verdicts (Increment 1: Archive).
//!
//! Node-reward 5-4-3-2-1 shares are paid on peer-VERIFIED capabilities. The
//! consensus handler (`ghost_consensus::verification_handler`) used to store the
//! challenger's `passed` flag verbatim. A >5% colluding minority could therefore
//! sign `passed=false` against an honest node, drag it under the 95% gate, and
//! steal its reward share.
//!
//! [`ChainReVerifier`] closes this by RE-DERIVING the Archive verdict from:
//!   1. the TARGET's own signed `ArchiveResponse` (the only trustworthy input —
//!      `challenge_data`/`response_data` are authored by the adversarial
//!      challenger and are NOT in the signed tuple), and
//!   2. THIS node's own Bitcoin Core (ground truth),
//! using the SAME comparator the challenger runs
//! ([`ghost_verification::challenge::validate_archive_response`]) so there is
//! zero logic divergence.
//!
//! Verdict semantics (see [`ReVerdict`]):
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
use ghost_verification::challenge::{validate_archive_response, ArchiveResponse, SignedResponse};

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

/// Re-derives Archive verdicts against the node's own Bitcoin Core.
pub struct ChainReVerifier {
    rpc: Arc<BitcoinRpc>,
}

impl ChainReVerifier {
    /// Create a re-verifier bound to the node's Bitcoin Core RPC client.
    pub fn new(rpc: Arc<BitcoinRpc>) -> Self {
        Self { rpc }
    }
}

#[async_trait]
impl ResultReVerifier for ChainReVerifier {
    async fn reverify_archive(
        &self,
        target_node_id: &NodeId,
        target_signed_response: Option<&str>,
    ) -> ReVerdict {
        let oracle = RpcOracle(Arc::clone(&self.rpc));
        reverify_archive_impl(&oracle, target_node_id, target_signed_response).await
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

    /// FRAUD: target signs a wrong hash for the height; our RPC disagrees => Fail,
    /// regardless of what the challenger claimed.
    #[tokio::test]
    async fn fraud_wrong_hash_is_fail() {
        let target = NodeIdentity::generate();
        let bogus_hash = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef0";
        let raw = make_signed_response(&target, 500, bogus_hash, REAL_MERKLE, true);

        let verdict = reverify_archive_impl(&good_oracle(), &target.node_id(), Some(&raw)).await;
        assert_eq!(verdict, ReVerdict::Fail);
    }

    /// FRAUD: target signs a wrong merkle root => Fail.
    #[tokio::test]
    async fn fraud_wrong_merkle_is_fail() {
        let target = NodeIdentity::generate();
        let bogus_merkle = "2222222222222222222222222222222222222222222222222222222222222222";
        let raw = make_signed_response(&target, 500, REAL_HASH, bogus_merkle, true);

        let verdict = reverify_archive_impl(&good_oracle(), &target.node_id(), Some(&raw)).await;
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

        let verdict = reverify_archive_impl(&good_oracle(), &target.node_id(), Some(&raw)).await;
        assert_eq!(verdict, ReVerdict::Pass);
    }

    /// Verdict equals what the shared comparator returns: a response with
    /// `success=false` (genuinely wrong) is a Fail even with the right hash.
    #[tokio::test]
    async fn unsuccessful_response_is_fail() {
        let target = NodeIdentity::generate();
        let raw = make_signed_response(&target, 500, REAL_HASH, REAL_MERKLE, false);

        let verdict = reverify_archive_impl(&good_oracle(), &target.node_id(), Some(&raw)).await;
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
            reverify_archive_impl(&good_oracle(), &target.node_id(), None).await,
            ReVerdict::Unverifiable
        );
        assert_eq!(
            reverify_archive_impl(&good_oracle(), &target.node_id(), Some("   ")).await,
            ReVerdict::Unverifiable
        );
    }

    /// Unparseable signed response => Unverifiable.
    #[tokio::test]
    async fn unparseable_response_is_unverifiable() {
        let target = NodeIdentity::generate();
        assert_eq!(
            reverify_archive_impl(&good_oracle(), &target.node_id(), Some("{not json")).await,
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

        let verdict = reverify_archive_impl(&good_oracle(), &target.node_id(), Some(&raw)).await;
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

        let verdict = reverify_archive_impl(&good_oracle(), &target.node_id(), Some(&raw)).await;
        assert_eq!(verdict, ReVerdict::Unverifiable);
    }

    /// RPC error (node behind / IBD) => Unverifiable, never a grief-FAIL.
    #[tokio::test]
    async fn rpc_error_is_unverifiable() {
        let target = NodeIdentity::generate();
        let raw = make_signed_response(&target, 500, REAL_HASH, REAL_MERKLE, true);
        let mut oracle = good_oracle();
        oracle.broken = true;

        let verdict = reverify_archive_impl(&oracle, &target.node_id(), Some(&raw)).await;
        assert_eq!(verdict, ReVerdict::Unverifiable);
    }

    /// Height beyond our tip (we lack the block) => Unverifiable.
    #[tokio::test]
    async fn height_above_tip_is_unverifiable() {
        let target = NodeIdentity::generate();
        // Sign a response for height 5000 while our tip is only 1000.
        let raw = make_signed_response(&target, 5_000, REAL_HASH, REAL_MERKLE, true);

        let verdict = reverify_archive_impl(&good_oracle(), &target.node_id(), Some(&raw)).await;
        assert_eq!(verdict, ReVerdict::Unverifiable);
    }
}

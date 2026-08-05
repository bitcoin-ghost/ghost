//! H-7: prove a node controls the address it CLAIMS.
//!
//! Challenger diversity is deduplicated per `/24` subnet, and that subnet is derived
//! from `nodes.public_address` — which arrives in the node's own health ping and is
//! stored after a single `!is_empty()` check. Nothing probes it. So a node advertising
//! an address in a `/24` it does not occupy is counted as a distinct challenger, at no
//! cost, and the griefing resistance that rests on distinct-subnet majorities is
//! fabricable.
//!
//! A plain reachability probe does not close it: connecting to a claimed address proves
//! only that *something* answers there, and a node can advertise any reachable
//! third-party address. What closes it is requiring the thing that answers to prove it
//! holds the node's identity key, over a nonce the prober chose:
//!
//!   1. prober picks a fresh random nonce
//!   2. prober dials the CLAIMED address: `GET /health?nonce=<nonce>`
//!   3. the reply must be a `SignedResponse` whose `signer` is the claimed node id,
//!      whose `challenge_nonce` is the nonce from step 1, and whose signature verifies
//!
//! Only then may that address's `/24` count toward diversity.
//!
//! The verification is a pure function of the response body so it can be tested without a
//! network. The transport that performs step 2 is deliberately NOT here yet: probing is
//! blocked on `nodes.public_address` being populated at all — it currently holds one row in
//! eight on every production node, so there is nothing to probe. See #629.

use ghost_common::identity::verify_signature;

use crate::challenge::{HealthResponse, SignedResponse};

/// Why an address proof was rejected. Distinguished so a caller can tell "this node is
/// lying about where it lives" from "this node is currently down", which are very
/// different facts about a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressProofFailure {
    /// The reply was not a signed response at all (`signed: false`, or unparseable).
    NotSigned,
    /// Signed, but by a different node than the one claiming this address. This is the
    /// interesting case: something answers there, and it is not who claimed it.
    WrongSigner,
    /// Signed by the right node, but not bound to the nonce we chose — so it could be a
    /// replay of an earlier exchange rather than a live answer.
    NonceMismatch,
    /// Signature did not verify, or the response failed its freshness bounds.
    BadSignature,
}

/// Verify a `/health?nonce=…` reply proves `expected_node_id` is reachable at the
/// address it was fetched from.
///
/// `body` is the raw JSON: `{"signed": bool, "response": …}`.
///
/// Returns `Ok(())` only when the response is signed by exactly `expected_node_id` and
/// bound to `expected_nonce`. Every other outcome names why.
pub fn verify_address_proof(
    body: &str,
    expected_node_id: &str,
    expected_nonce: &str,
) -> Result<(), AddressProofFailure> {
    let wrapper: serde_json::Value =
        serde_json::from_str(body).map_err(|_| AddressProofFailure::NotSigned)?;

    // An unsigned reply proves nothing about who is answering. Note a node running a
    // build with no signing identity answers `signed: false` for every request, so this
    // is also what "peer predates address proofs" looks like — the caller decides
    // whether that is tolerable, this function only reports it.
    if wrapper.get("signed").and_then(|s| s.as_bool()) != Some(true) {
        return Err(AddressProofFailure::NotSigned);
    }

    let inner = wrapper
        .get("response")
        .ok_or(AddressProofFailure::NotSigned)?;
    // Deserialise the payload as the CONCRETE type the responder signed, not a generic
    // `Value`. `SignedResponse::verify` recomputes the hash over `serde_json::to_vec(payload)`,
    // so the payload must re-serialise to the same bytes the signer produced — which only
    // holds if both sides use the same type and the same serde configuration. Verifying via
    // `serde_json::Value` reproduces the shape but not necessarily the bytes, and fails with
    // `BadSignature` against a genuinely valid proof. Found by testing against a real reply
    // from vm5; every hand-built fixture passed.
    let signed: SignedResponse<HealthResponse> =
        serde_json::from_value(inner.clone()).map_err(|_| AddressProofFailure::NotSigned)?;

    // The signer must be the node that CLAIMED this address. Anything else means
    // something answers there, but not the claimant — which is exactly the case a bare
    // TCP probe cannot distinguish and this check exists for.
    if !signed.signer.eq_ignore_ascii_case(expected_node_id) {
        return Err(AddressProofFailure::WrongSigner);
    }

    // Bound to OUR nonce, or it may be a replay of an earlier exchange.
    if signed.challenge_nonce.as_deref() != Some(expected_nonce) {
        return Err(AddressProofFailure::NonceMismatch);
    }

    signed
        .verify(|signer_hex, message_hash, signature_bytes| {
            let Ok(pk_bytes) = hex::decode(signer_hex) else {
                return false;
            };
            if pk_bytes.len() != 32 {
                return false;
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&pk_bytes);
            let Ok(sig) = <[u8; 64]>::try_from(signature_bytes) else {
                return false;
            };
            verify_signature(&pk, message_hash, &sig).unwrap_or(false)
        })
        .map_err(|_| AddressProofFailure::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::identity::NodeIdentity;

    /// Build the exact wire shape `/health?nonce=…` returns.
    fn health_body(identity: &NodeIdentity, nonce: Option<&str>, signed_flag: bool) -> String {
        let payload = HealthResponse {
            mesh_validation: None,
            healthy: true,
            core_reachable: Some(true),
            core_last_ok_secs: Some(0),
            node_id: identity.node_id_hex(),
            version: "test".to_string(),
            block_height: 961_180,
            round_id: 1,
            miner_count: 0,
            peer_count: 7,
            capabilities: crate::challenge::CapabilityStatus::default(),
            uptime_secs: 1,
        };
        let signed = SignedResponse::new(
            payload,
            identity.node_id_hex(),
            |msg| identity.sign(msg),
            nonce.map(str::to_owned),
        );
        serde_json::json!({"signed": signed_flag, "response": signed}).to_string()
    }

    #[test]
    fn a_reply_signed_by_the_claimant_over_our_nonce_proves_the_address() {
        let node = NodeIdentity::generate();
        let body = health_body(&node, Some("nonce-we-chose"), true);
        assert_eq!(
            verify_address_proof(&body, &node.node_id_hex(), "nonce-we-chose"),
            Ok(())
        );
    }

    /// The case a bare TCP probe cannot see: something answers at the claimed address,
    /// but it is not the node that claimed it. This is the whole point of H-7 — a node
    /// may advertise any reachable third-party address.
    #[test]
    fn a_reply_signed_by_someone_else_is_wrong_signer() {
        let claimant = NodeIdentity::generate();
        let whoever_actually_answers = NodeIdentity::generate();
        let body = health_body(&whoever_actually_answers, Some("n"), true);
        assert_eq!(
            verify_address_proof(&body, &claimant.node_id_hex(), "n"),
            Err(AddressProofFailure::WrongSigner)
        );
    }

    #[test]
    fn a_reply_bound_to_a_different_nonce_is_a_mismatch() {
        let node = NodeIdentity::generate();
        let body = health_body(&node, Some("some-old-nonce"), true);
        assert_eq!(
            verify_address_proof(&body, &node.node_id_hex(), "the-nonce-we-chose"),
            Err(AddressProofFailure::NonceMismatch)
        );
    }

    #[test]
    fn a_reply_with_no_nonce_at_all_is_a_mismatch() {
        let node = NodeIdentity::generate();
        let body = health_body(&node, None, true);
        assert_eq!(
            verify_address_proof(&body, &node.node_id_hex(), "n"),
            Err(AddressProofFailure::NonceMismatch)
        );
    }

    /// What every node answered before the signing identity was wired: `signed: false`.
    #[test]
    fn an_unsigned_reply_proves_nothing() {
        let node = NodeIdentity::generate();
        let body = health_body(&node, Some("n"), false);
        assert_eq!(
            verify_address_proof(&body, &node.node_id_hex(), "n"),
            Err(AddressProofFailure::NotSigned)
        );
    }

    #[test]
    fn a_tampered_signature_does_not_verify() {
        let node = NodeIdentity::generate();
        let body = health_body(&node, Some("n"), true);
        let mut v: serde_json::Value = serde_json::from_str(&body).unwrap();
        // Flip the signature to something structurally valid but wrong.
        v["response"]["signature"] = serde_json::json!("00".repeat(64));
        assert_eq!(
            verify_address_proof(&v.to_string(), &node.node_id_hex(), "n"),
            Err(AddressProofFailure::BadSignature)
        );
    }

    #[test]
    fn garbage_is_not_a_proof() {
        let node = NodeIdentity::generate();
        assert_eq!(
            verify_address_proof("not json", &node.node_id_hex(), "n"),
            Err(AddressProofFailure::NotSigned)
        );
    }
}

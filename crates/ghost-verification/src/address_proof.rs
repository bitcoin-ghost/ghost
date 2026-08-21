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
    /// Nothing could be reached at the claimed address, or the request was refused
    /// before it was made (SSRF guard, unresolvable host, timeout).
    ///
    /// Deliberately distinct from every other variant: "I could not reach it" is not
    /// evidence that the claimant lied, and must not be treated as such. A node that is
    /// merely down would otherwise lose its subnet on the strength of a transient.
    Unreachable,
}

/// What a probe outcome is allowed to ASSERT to the rest of the fleet.
///
/// `Some(true)` = broadcast a PASS, `Some(false)` = broadcast a FAIL, `None` = say nothing.
///
/// Only a cryptographic failure is evidence that the claimant lied about where it lives.
/// Everything else is a fact about the network or about the peer's build, and a verdict that
/// confused the two would cost honest nodes their subnet:
///
/// - [`AddressProofFailure::Unreachable`] is overwhelmingly transient. Measured across all
///   eight production nodes over 24h on 2026-08-21: **181 of 181 probe failures** were
///   `Unreachable`, spread over seven distinct peers with none above ~8% of its own probes,
///   against 9,681 passes. Not one `WrongSigner`, `NonceMismatch`, or `BadSignature` occurred.
/// - [`AddressProofFailure::NotSigned`] is ambiguous by construction: a peer running a build
///   with no signing identity answers `signed: false` to every request, so this is also
///   precisely what "peer predates address proofs" looks like.
///
/// Staying silent on both is the same PASS-or-Unverifiable rule the other capabilities apply
/// to challenger-authored data — never a false FAIL, never an unverified PASS.
pub fn address_verdict(outcome: Result<(), AddressProofFailure>) -> Option<bool> {
    match outcome {
        Ok(()) => Some(true),
        Err(AddressProofFailure::Unreachable | AddressProofFailure::NotSigned) => None,
        Err(
            AddressProofFailure::WrongSigner
            | AddressProofFailure::NonceMismatch
            | AddressProofFailure::BadSignature,
        ) => Some(false),
    }
}

/// The `/health` endpoint to probe for an address a node advertises.
///
/// A node's stored `public_address` carries whichever port it advertised — on this fleet
/// that is the **mesh** port (`:8559`), and some rows carry no port at all. `/health` is on
/// [`api_port`]. Probing the stored value verbatim therefore fails for every peer:
/// measured against a live node, `83.136.251.162:8559` gave `Unreachable` while
/// `83.136.251.162:8080` verified.
///
/// That failure mode is worse than the bug this whole feature exists to fix — gating on a
/// probe that can never succeed would exclude every subnet and collapse the challenger pool
/// to zero, where today it is at least populated.
///
/// So the host is taken and the caller's API port applied. The port is a PARAMETER rather
/// than a constant because it depends on the scheme the client is configured for:
/// `HTTP_API_PORT` (8080) serves plaintext, `VERIFICATION_HTTPS_PORT` (8443) serves TLS.
/// Hardcoding 8080 while the production client runs with `use_https: true` builds
/// `https://host:8080` — TLS against the plaintext port — which fails for every peer.
/// Measured on the fleet:
///
/// ```text
/// http://host:8080/health   -> 200
/// https://host:8080/health  -> 000   (what the hardcoded version built)
/// https://host:8443/health  -> signed response
/// ```
///
/// IPv6 literals keep their brackets; a bare unbracketed IPv6 address is ambiguous (its
/// colons are not a port separator) and is returned unchanged rather than silently
/// truncated to nothing.
pub(crate) fn health_endpoint_for(claimed_address: &str, api_port: u16) -> String {
    let trimmed = claimed_address.trim();

    if let Some(rest) = trimmed.strip_prefix('[') {
        // Bracketed IPv6, with or without a port: [::1] / [::1]:8559
        if let Some((host, _)) = rest.split_once(']') {
            return format!("[{}]:{}", host, api_port);
        }
        return trimmed.to_string();
    }

    // More than one colon and no brackets: a bare IPv6 literal. Splitting would destroy it.
    if trimmed.matches(':').count() > 1 {
        return trimmed.to_string();
    }

    let host = trimmed.split(':').next().unwrap_or(trimmed);
    format!("{}:{}", host, api_port)
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
mod verdict_tests {
    use super::{address_verdict, AddressProofFailure};

    /// The whole point of H-7: something answered at the claimed address and it was NOT the
    /// claimant. This is the only class a bare TCP probe cannot distinguish, and it must vote.
    #[test]
    fn a_cryptographic_failure_votes_fail() {
        for failure in [
            AddressProofFailure::WrongSigner,
            AddressProofFailure::NonceMismatch,
            AddressProofFailure::BadSignature,
        ] {
            assert_eq!(
                address_verdict(Err(failure)),
                Some(false),
                "{failure:?} is evidence the claimant lied and must be broadcast as a FAIL"
            );
        }
    }

    /// Guards the property the live measurement bought: 181 of 181 observed failures were
    /// `Unreachable`. Were this to return `Some(false)`, every honest node would lose its
    /// subnet on a transient, and the diversity floor it feeds would collapse toward the
    /// single-subnet state #629 fixed.
    #[test]
    fn an_unreachable_peer_says_nothing() {
        assert_eq!(address_verdict(Err(AddressProofFailure::Unreachable)), None);
    }

    /// A peer on a build with no signing identity answers `signed: false` to everything, so
    /// `NotSigned` cannot distinguish a liar from an old binary. During any rollout that is
    /// most of the fleet.
    #[test]
    fn an_unsigned_reply_says_nothing() {
        assert_eq!(address_verdict(Err(AddressProofFailure::NotSigned)), None);
    }

    #[test]
    fn a_proved_address_votes_pass() {
        assert_eq!(address_verdict(Ok(())), Some(true));
    }
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

    /// The stored address carries the MESH port; `/health` is on the API port. Probing the
    /// stored value verbatim fails for every peer — measured live: `:8559` was Unreachable,
    /// `:8080` verified. Gating on that would exclude every subnet.
    #[test]
    fn the_probe_endpoint_uses_the_api_port_not_the_advertised_one() {
        assert_eq!(
            health_endpoint_for("83.136.251.162:8559", 8080),
            "83.136.251.162:8080"
        );
        // Some rows carry no port at all (a node's own row is stored that way).
        assert_eq!(
            health_endpoint_for("94.237.102.192", 8080),
            "94.237.102.192:8080"
        );
        // Whitespace must not defeat it.
        assert_eq!(health_endpoint_for("  1.2.3.4:9999 ", 8080), "1.2.3.4:8080");
        // And an HTTPS client must get the TLS port. Hardcoding 8080 while the client
        // speaks https built `https://host:8080` and made every probe Unreachable.
        assert_eq!(
            health_endpoint_for("83.136.251.162:8559", 8443),
            "83.136.251.162:8443"
        );
    }

    /// IPv6 must not be silently truncated: splitting on the first colon would turn
    /// `[::1]:8559` into an empty host and probe nothing.
    #[test]
    fn ipv6_survives_endpoint_normalisation() {
        assert_eq!(
            health_endpoint_for("[2001:db8::1]:8559", 8080),
            "[2001:db8::1]:8080"
        );
        assert_eq!(health_endpoint_for("[::1]", 8080), "[::1]:8080");
        // Bare unbracketed IPv6 is ambiguous — returned unchanged, never truncated.
        assert_eq!(health_endpoint_for("2001:db8::1", 8080), "2001:db8::1");
    }
}

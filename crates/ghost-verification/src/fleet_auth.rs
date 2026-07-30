//! Operator-signed fleet control (#403).
//!
//! # Why not the existing internal HMAC
//!
//! `auth.rs` protects internal endpoints with an HMAC-SHA256 shared secret. That is the right
//! tool for one service talking to another on the same box, and the wrong one for fleet
//! control, for three reasons:
//!
//! 1. **A shared secret is symmetric.** Every node holding it can mint a valid command for
//!    every other node. Compromise one node and you own the fleet.
//! 2. **It authenticates the caller as "something that knows the secret"**, not as the
//!    operator. It cannot distinguish the owner from a peer.
//! 3. **It cannot cross an operator boundary.** In a multi-operator pool you cannot hand your
//!    secret to a peer, so the model has nowhere to go.
//!
//! # The model
//!
//! Control is **operator to node**, never node to node.
//!
//! Each node is configured with the operator's **public** key. The operator signs a command
//! with the matching private key, which never leaves their machine. A node verifies the
//! signature and executes only if the command names *itself*.
//!
//! Consequences that matter:
//!
//! - A node holds no secret capable of producing a command, so compromising it grants no
//!   authority over any other node — including its own siblings.
//! - A node can safely **relay** a command it cannot forge or alter.
//! - Peers in the mesh have no control authority at all. Nothing here consults the elder set,
//!   the voter set, or any quorum: fleet control is ownership, not consensus, and conflating
//!   the two would let a Sybil majority (#570) reboot other people's hardware.
//!
//! # What is signed
//!
//! The signing payload binds every field that could otherwise be swapped:
//!
//! ```text
//! ghost-fleet-v1\n<target_node_id>\n<action>\n<params_hash>\n<nonce>\n<expires_at>
//! ```
//!
//! - `target_node_id` — a command for node A is invalid at node B, so a relay cannot redirect
//!   it and a captured command cannot be replayed elsewhere.
//! - `action` and `params_hash` — "restart" cannot be edited into "update version", and the
//!   body cannot be altered while keeping the signature.
//! - `nonce` + `expires_at` — bounded replay window, and within it each nonce is single-use.
//!
//! The domain prefix stops a signature produced for some other Ghost purpose being replayed
//! here as a control command.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain separator. Any change to the signing payload's meaning must change this string.
const DOMAIN: &str = "ghost-fleet-v1";

/// How far ahead of now an `expires_at` may sit.
///
/// Bounds how long a captured command stays useful. Generous enough for clock skew between an
/// operator's laptop and a node, short enough that a command scraped from a log is stale.
pub const MAX_TTL_SECS: u64 = 120;

/// Nonces retained for replay rejection. Any nonce older than `MAX_TTL_SECS` is already
/// rejected by expiry, so the store only has to cover that window.
const NONCE_CAPACITY: usize = 4096;

/// A control command, as sent over the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCommand {
    /// Node this command is for. Hex node id.
    pub target_node_id: String,
    /// What to do — `restart`, `update-version`, `config`, …
    pub action: String,
    /// Action parameters. Hashed into the signature, so it cannot be altered in flight.
    #[serde(default)]
    pub params: serde_json::Value,
    /// Single-use value, unique within the TTL window.
    pub nonce: String,
    /// Unix seconds after which this command is refused.
    pub expires_at: u64,
    /// Operator signature over [`SignedCommand::signing_payload`], hex-encoded.
    pub signature: String,
}

/// Why a command was refused. Distinct variants so the node can log the real reason —
/// "unauthorised" alone would leave an operator guessing whether the key, the clock or the
/// target was wrong.
#[derive(Debug, PartialEq, Eq)]
pub enum FleetAuthError {
    /// No operator key configured — the node cannot be controlled remotely at all.
    NoOperatorKey,
    /// Command is for a different node.
    WrongTarget { expected: String, got: String },
    /// `expires_at` has passed.
    Expired { expires_at: u64, now: u64 },
    /// `expires_at` is further ahead than [`MAX_TTL_SECS`] allows.
    TtlTooLong { expires_at: u64, now: u64 },
    /// This nonce has already been used within the window.
    ReplayedNonce,
    /// Signature is not valid for the configured operator key.
    BadSignature,
    /// Signature field is not valid hex, or not 64 bytes.
    MalformedSignature,
}

impl std::fmt::Display for FleetAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoOperatorKey => write!(
                f,
                "no operator public key is configured; remote control is disabled on this node"
            ),
            Self::WrongTarget { expected, got } => write!(
                f,
                "command targets {got} but this node is {expected} — send it to that node directly"
            ),
            Self::Expired { expires_at, now } => {
                write!(f, "command expired at {expires_at}, now {now}")
            }
            Self::TtlTooLong { expires_at, now } => write!(
                f,
                "command expires at {expires_at}, more than {MAX_TTL_SECS}s ahead of {now}"
            ),
            Self::ReplayedNonce => write!(f, "nonce already used"),
            Self::BadSignature => write!(f, "signature does not verify against the operator key"),
            Self::MalformedSignature => write!(f, "signature is not 64 bytes of hex"),
        }
    }
}

impl SignedCommand {
    /// Exact bytes the operator signs.
    ///
    /// Newline-separated with a domain prefix. Fields cannot contain a newline in practice
    /// (node ids are hex, actions are a fixed vocabulary, nonce is hex, numbers are numbers),
    /// and `params` is folded in as a hash rather than inline so its own formatting cannot
    /// shift field boundaries.
    pub fn signing_payload(&self) -> Vec<u8> {
        let params_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&self.params).unwrap_or_default(),
        ));
        format!(
            "{DOMAIN}\n{}\n{}\n{}\n{}\n{}",
            self.target_node_id, self.action, params_hash, self.nonce, self.expires_at
        )
        .into_bytes()
    }
}

/// Verifies operator-signed commands for one node.
pub struct FleetAuth {
    /// This node's id, hex. A command naming anything else is refused.
    node_id: String,
    /// The operator's public key. `None` disables remote control entirely — which is the
    /// correct default: a node nobody configured for control must not be controllable.
    operator_pubkey: Option<[u8; 32]>,
    /// Nonces seen within the TTL window, with the expiry that retired them.
    seen: Mutex<HashMap<String, u64>>,
}

impl FleetAuth {
    pub fn new(node_id: String, operator_pubkey: Option<[u8; 32]>) -> Self {
        Self {
            node_id,
            operator_pubkey,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// True when this node will accept control commands at all.
    pub fn is_enabled(&self) -> bool {
        self.operator_pubkey.is_some()
    }

    /// Verify a command, consuming its nonce on success.
    ///
    /// Checks run cheapest-first, and the nonce is only consumed once everything else passes —
    /// otherwise an attacker could burn an operator's nonces with unsigned garbage.
    pub fn verify(&self, cmd: &SignedCommand, now: u64) -> Result<(), FleetAuthError> {
        let Some(pubkey) = self.operator_pubkey else {
            return Err(FleetAuthError::NoOperatorKey);
        };

        if cmd.target_node_id != self.node_id {
            return Err(FleetAuthError::WrongTarget {
                expected: self.node_id.clone(),
                got: cmd.target_node_id.clone(),
            });
        }
        if cmd.expires_at <= now {
            return Err(FleetAuthError::Expired {
                expires_at: cmd.expires_at,
                now,
            });
        }
        if cmd.expires_at > now + MAX_TTL_SECS {
            return Err(FleetAuthError::TtlTooLong {
                expires_at: cmd.expires_at,
                now,
            });
        }

        let sig_bytes = hex::decode(&cmd.signature)
            .ok()
            .filter(|b| b.len() == 64)
            .ok_or(FleetAuthError::MalformedSignature)?;
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_bytes);

        if !verify_ed25519(&pubkey, &cmd.signing_payload(), &sig) {
            return Err(FleetAuthError::BadSignature);
        }

        // Signature is good — now claim the nonce. Done last so a forged command cannot
        // consume a nonce the operator intended to use.
        let mut seen = self.seen.lock();
        seen.retain(|_, exp| *exp > now);
        if seen.len() >= NONCE_CAPACITY {
            // Full of live nonces. Refusing is the safe direction: accepting without recording
            // would silently disable replay protection under load.
            return Err(FleetAuthError::ReplayedNonce);
        }
        if seen.insert(cmd.nonce.clone(), cmd.expires_at).is_some() {
            return Err(FleetAuthError::ReplayedNonce);
        }
        Ok(())
    }
}

/// Ed25519 verification, reusing the node-identity primitive rather than a second
/// implementation — node ids and operator keys are both Ed25519 public keys, and having one
/// verification path means one place to get it right.
fn verify_ed25519(pubkey: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    ghost_common::identity::verify_signature(pubkey, message, signature).unwrap_or(false)
}

/// Current unix seconds.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn operator() -> (SigningKey, [u8; 32]) {
        // Fixed seed: these tests must not depend on randomness.
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn signed(
        sk: &SigningKey,
        target: &str,
        action: &str,
        nonce: &str,
        expires: u64,
    ) -> SignedCommand {
        let mut cmd = SignedCommand {
            target_node_id: target.to_string(),
            action: action.to_string(),
            params: serde_json::json!({"service": "ghost-pool"}),
            nonce: nonce.to_string(),
            expires_at: expires,
            signature: String::new(),
        };
        cmd.signature = hex::encode(sk.sign(&cmd.signing_payload()).to_bytes());
        cmd
    }

    #[test]
    fn a_correctly_signed_command_is_accepted_once() {
        let (sk, pk) = operator();
        let auth = FleetAuth::new("node-a".into(), Some(pk));
        let cmd = signed(&sk, "node-a", "restart", "n1", 1_000_060);

        assert_eq!(auth.verify(&cmd, 1_000_000), Ok(()));
        // Replay of the identical command must fail.
        assert_eq!(
            auth.verify(&cmd, 1_000_001),
            Err(FleetAuthError::ReplayedNonce)
        );
    }

    /// The property that makes relaying safe: a command for one node is worthless at another.
    /// Without this, a node asked to forward a restart could redirect it at a sibling.
    #[test]
    fn a_command_for_another_node_is_refused() {
        let (sk, pk) = operator();
        let auth = FleetAuth::new("node-b".into(), Some(pk));
        let cmd = signed(&sk, "node-a", "restart", "n1", 1_000_060);

        assert!(matches!(
            auth.verify(&cmd, 1_000_000),
            Err(FleetAuthError::WrongTarget { .. })
        ));
    }

    /// Every signed field must be bound. Editing any of them invalidates the signature rather
    /// than producing a different valid command.
    #[test]
    fn tampering_with_any_signed_field_breaks_the_signature() {
        let (sk, pk) = operator();
        let auth = FleetAuth::new("node-a".into(), Some(pk));
        let base = signed(&sk, "node-a", "restart", "n1", 1_000_060);

        let mut action = base.clone();
        action.action = "update-version".into();
        assert_eq!(
            auth.verify(&action, 1_000_000),
            Err(FleetAuthError::BadSignature),
            "action must be bound"
        );

        let mut params = base.clone();
        params.params = serde_json::json!({"service": "ghostd"});
        assert_eq!(
            auth.verify(&params, 1_000_000),
            Err(FleetAuthError::BadSignature),
            "params must be bound"
        );

        let mut nonce = base.clone();
        nonce.nonce = "n2".into();
        assert_eq!(
            auth.verify(&nonce, 1_000_000),
            Err(FleetAuthError::BadSignature),
            "nonce must be bound"
        );

        let mut expiry = base;
        expiry.expires_at = 1_000_090;
        assert_eq!(
            auth.verify(&expiry, 1_000_000),
            Err(FleetAuthError::BadSignature),
            "expiry must be bound, or a captured command could be extended"
        );
    }

    #[test]
    fn expiry_is_enforced_in_both_directions() {
        let (sk, pk) = operator();
        let auth = FleetAuth::new("node-a".into(), Some(pk));

        let stale = signed(&sk, "node-a", "restart", "n1", 999_999);
        assert!(matches!(
            auth.verify(&stale, 1_000_000),
            Err(FleetAuthError::Expired { .. })
        ));

        // An unbounded TTL would make a captured command useful forever.
        let far = signed(&sk, "node-a", "restart", "n2", 1_000_000 + MAX_TTL_SECS + 1);
        assert!(matches!(
            auth.verify(&far, 1_000_000),
            Err(FleetAuthError::TtlTooLong { .. })
        ));
    }

    /// A different key must not work — this is the whole point of asymmetric control. A node
    /// holds only a public key, so compromising it yields nothing that can sign.
    #[test]
    fn a_different_operator_key_is_refused() {
        let (_sk, pk) = operator();
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let auth = FleetAuth::new("node-a".into(), Some(pk));
        let cmd = signed(&attacker, "node-a", "restart", "n1", 1_000_060);

        assert_eq!(
            auth.verify(&cmd, 1_000_000),
            Err(FleetAuthError::BadSignature)
        );
    }

    /// Unconfigured means uncontrollable. A node that nobody set up for remote control must
    /// not be remotely controllable by anyone.
    #[test]
    fn without_an_operator_key_nothing_is_accepted() {
        let (sk, _pk) = operator();
        let auth = FleetAuth::new("node-a".into(), None);
        let cmd = signed(&sk, "node-a", "restart", "n1", 1_000_060);

        assert!(!auth.is_enabled());
        assert_eq!(
            auth.verify(&cmd, 1_000_000),
            Err(FleetAuthError::NoOperatorKey)
        );
    }

    /// A forged command must not consume a nonce the operator still intends to use.
    #[test]
    fn a_rejected_command_does_not_burn_its_nonce() {
        let (sk, pk) = operator();
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let auth = FleetAuth::new("node-a".into(), Some(pk));

        let forged = signed(&attacker, "node-a", "restart", "shared-nonce", 1_000_060);
        assert_eq!(
            auth.verify(&forged, 1_000_000),
            Err(FleetAuthError::BadSignature)
        );

        // The operator's genuine command with that nonce must still work.
        let real = signed(&sk, "node-a", "restart", "shared-nonce", 1_000_060);
        assert_eq!(auth.verify(&real, 1_000_000), Ok(()));
    }

    /// Expired nonces must be evicted, or the store fills and starts refusing valid commands.
    #[test]
    fn nonces_are_evicted_once_they_expire() {
        let (sk, pk) = operator();
        let auth = FleetAuth::new("node-a".into(), Some(pk));

        let first = signed(&sk, "node-a", "restart", "n1", 1_000_060);
        assert_eq!(auth.verify(&first, 1_000_000), Ok(()));
        assert_eq!(auth.seen.lock().len(), 1);

        // Well past the first command's expiry: the retain() sweep should drop it.
        let later = signed(&sk, "node-a", "restart", "n2", 1_000_200);
        assert_eq!(auth.verify(&later, 1_000_150), Ok(()));
        assert_eq!(
            auth.seen.lock().len(),
            1,
            "the expired nonce should have been evicted, not accumulated"
        );
    }
}

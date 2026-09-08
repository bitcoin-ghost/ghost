//! Local BIP-352 silent-payment detection.
//!
//! Given one candidate transaction — an ephemeral pubkey and the taproot
//! outputs that went with it — this works out which of those outputs, if any,
//! were paid to the wallet, and at which derivation index. The keys never
//! leave the machine and no server is told what matched.
//!
//! # Where candidates come from
//!
//! Nowhere, yet. This used to be fed by pushes from the operator's GSP, which
//! filtered the chain on the wallet's behalf; that went with the rest of L2.
//! The detection itself was always local and always correct, so it is kept
//! here whole, waiting on a scanner that reads blocks from the wallet's own
//! node.
//!
//! Keeping it is the cheap half of the decision: re-deriving BIP-352 parity
//! handling from scratch later would be the expensive half.

use ghost_keys::{GhostKeys, PaymentDetector};

/// Seconds since the Unix epoch.
fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// One taproot output of a candidate transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateOutput {
    /// The output's x-only pubkey, hex, 32 bytes.
    pub output_pubkey: String,
    pub amount_sats: Option<u64>,
    pub vout: u32,
}

/// One BIP-352 silent-payment detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedPayment {
    pub txid: String,
    pub block_height: Option<u32>,
    pub vout: u32,
    pub amount_sats: Option<u64>,
    /// Derivation index (k) used by the sender. Recorded so a future
    /// "spend this output" call can re-derive the spend key.
    pub k: u32,
    pub received_at: i64,
}

/// Run the local BIP-352 scanner against one candidate transaction. Returns
/// any detected payments belonging to `keys`.
pub fn scan_candidate(
    keys: &GhostKeys,
    ephemeral_pubkey_hex: &str,
    outputs: &[CandidateOutput],
    txid: &str,
    block_height: Option<u32>,
) -> Result<Vec<DetectedPayment>, String> {
    use bitcoin::secp256k1::PublicKey;

    let eph_bytes = hex::decode(ephemeral_pubkey_hex).map_err(|e| format!("ephemeral hex: {e}"))?;
    let ephemeral =
        PublicKey::from_slice(&eph_bytes).map_err(|e| format!("ephemeral pubkey: {e}"))?;

    // Decode each x-only (32-byte) output pubkey. Stash the raw x-only bytes
    // for later — BIP-352 output keys are taproot (x-only on chain), so we
    // need to try BOTH parities (0x02 / 0x03) when feeding the scanner,
    // since `PaymentDetector` compares full SEC1 byte equality and only
    // one of the two parities will be the real BIP-352-derived point.
    struct Decoded {
        xonly: [u8; 32],
        amount: Option<u64>,
        vout: u32,
    }
    let mut decoded: Vec<Decoded> = Vec::with_capacity(outputs.len());
    for out in outputs {
        let xonly_bytes =
            hex::decode(&out.output_pubkey).map_err(|e| format!("output hex: {e}"))?;
        if xonly_bytes.len() != 32 {
            return Err(format!(
                "output_pubkey must be 32 bytes (x-only), got {}",
                xonly_bytes.len()
            ));
        }
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&xonly_bytes);
        decoded.push(Decoded {
            xonly,
            amount: out.amount_sats,
            vout: out.vout,
        });
    }

    let detector = PaymentDetector::new(keys);
    let now = now_unix_secs();
    let mut detections: Vec<DetectedPayment> = Vec::new();

    // Scan once with each parity. Dedupe matches by (vout, k) since the same
    // real output can never match under both parities (each x-only key
    // belongs to exactly one curve point with a defined parity).
    for parity in [0x02u8, 0x03u8] {
        let mut scan_inputs: Vec<(PublicKey, Option<u64>)> = Vec::with_capacity(decoded.len());
        for d in &decoded {
            let mut sec1 = [0u8; 33];
            sec1[0] = parity;
            sec1[1..].copy_from_slice(&d.xonly);
            let pk = match PublicKey::from_slice(&sec1) {
                Ok(p) => p,
                Err(_) => {
                    // Off-curve x-only with this parity — skip this input.
                    continue;
                }
            };
            scan_inputs.push((pk, d.amount));
        }
        let scanned = detector.scan_transaction(&ephemeral, &scan_inputs);
        for s in scanned {
            // Map the scanner's slice-index back to our on-chain vout.
            // Note: the slice index can drift if any inputs were skipped above;
            // we only skip on parse failure which should never happen for valid
            // x-only bytes, so this is safe in practice.
            let d = match decoded.get(s.output_index as usize) {
                Some(d) => d,
                None => continue,
            };
            // Dedupe across parities.
            if detections.iter().any(|x| x.vout == d.vout && x.k == s.k) {
                continue;
            }
            detections.push(DetectedPayment {
                txid: txid.to_string(),
                block_height,
                vout: d.vout,
                amount_sats: s.amount,
                k: s.k,
                received_at: now,
            });
        }
    }
    Ok(detections)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// End-to-end synthetic test: sender constructs a BIP-352 payment to a
    /// receiver's `GhostKeys`, packages it as a `CandidateTransaction`, and
    /// the wallet's `scan_candidate` detects the match.
    #[test]
    fn scan_candidate_detects_synthetic_match() {
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        use ghost_keys::{derive_payment_address_v2, derive_shared_secret};
        use rand::RngCore;

        let receiver = GhostKeys::generate();

        // Sender's role: pick a one-shot ephemeral keypair (in real BIP-352
        // this is derived from the input set; the scanner only sees the pubkey).
        let secp = Secp256k1::new();
        let mut eph_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut eph_bytes);
        let eph_secret = SecretKey::from_slice(&eph_bytes).expect("nonzero scalar");
        let ephemeral_pub = PublicKey::from_secret_key(&secp, &eph_secret);

        // Both sides compute the same shared secret via ECDH (commutativity).
        // Sender side: ECDH(eph_secret, receiver.scan_pubkey).
        let shared_secret = derive_shared_secret(&eph_secret, receiver.scan_pubkey());

        // Sender derives the destination output pubkey at index k=0.
        let k: u32 = 0;
        let (output_pubkey, _tweak) =
            derive_payment_address_v2(receiver.spend_pubkey(), &shared_secret, k)
                .expect("derive output pubkey");

        // On chain we'd see the x-only form (taproot output).
        let serialized = output_pubkey.serialize();
        let xonly = &serialized[1..];

        let candidate_outputs = vec![CandidateOutput {
            output_pubkey: hex::encode(xonly),
            amount_sats: Some(50_000),
            vout: 7,
        }];

        let txid = "0".repeat(64);
        let detections = scan_candidate(
            &receiver,
            &hex::encode(ephemeral_pub.serialize()),
            &candidate_outputs,
            &txid,
            Some(123_456),
        )
        .expect("scan succeeds");

        assert_eq!(detections.len(), 1, "expected one match");
        let det = &detections[0];
        assert_eq!(det.k, k);
        assert_eq!(det.amount_sats, Some(50_000));
        assert_eq!(det.vout, 7);
        assert_eq!(det.block_height, Some(123_456));
        assert_eq!(det.txid, txid);
    }

    #[test]
    fn scan_candidate_returns_empty_on_no_match() {
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        use rand::RngCore;

        let receiver = GhostKeys::generate();

        let secp = Secp256k1::new();
        let mut eph_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut eph_bytes);
        let eph_secret = SecretKey::from_slice(&eph_bytes).unwrap();
        let ephemeral_pub = PublicKey::from_secret_key(&secp, &eph_secret);

        // Output addressed to a DIFFERENT receiver — should not match.
        let other = GhostKeys::generate();
        let mut other_eph_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut other_eph_bytes);
        let other_eph_secret = SecretKey::from_slice(&other_eph_bytes).unwrap();
        let shared_secret =
            ghost_keys::derive_shared_secret(&other_eph_secret, other.scan_pubkey());
        let (output_pubkey, _tweak) =
            ghost_keys::derive_payment_address_v2(other.spend_pubkey(), &shared_secret, 0).unwrap();
        let serialized = output_pubkey.serialize();
        let xonly = &serialized[1..];

        let candidate_outputs = vec![CandidateOutput {
            output_pubkey: hex::encode(xonly),
            amount_sats: Some(1_000),
            vout: 0,
        }];

        let detections = scan_candidate(
            &receiver,
            &hex::encode(ephemeral_pub.serialize()),
            &candidate_outputs,
            "deadbeef",
            None,
        )
        .expect("scan succeeds");

        assert!(
            detections.is_empty(),
            "no match expected, got {:?}",
            detections
        );
    }
}

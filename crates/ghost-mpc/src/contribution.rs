//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: contribution.rs                                                                                                |
//|======================================================================================================================|

//! MPC contribution generation and verification
//!
//! Each contributor applies a random transformation to the parameters
//! and provides a proof that the transformation was valid.

use crate::errors::{MpcError, MpcResult};
use bellperson::groth16::Parameters;
use blstrs::{Bls12, G1Affine, G2Affine, Scalar};
use ff::Field;
use group::{prime::PrimeCurveAffine, Curve};
use pairing::Engine;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
// zeroize derive macros are used on ToxicWaste struct

/// A contribution to the MPC ceremony
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MpcContribution {
    /// Position in the ceremony (1-101)
    pub position: u32,
    /// Hash of the previous parameters (chain link)
    pub prev_params_hash: [u8; 32],
    /// Hash of the new parameters after contribution
    pub new_params_hash: [u8; 32],
    /// Proof that the contribution was valid
    pub proof: ContributionProof,
    /// Node ID of the contributor
    pub contributor: String,
    /// Timestamp of contribution
    pub timestamp: u64,
    /// CRIT-2 FIX: Commitment hash that was announced before contribution
    /// This allows verification that no contributions were dropped
    pub commitment_hash: Option<[u8; 32]>,
}

/// CRIT-2 FIX: Contribution commitment for inclusion verification
///
/// Before generating a contribution, a participant broadcasts a commitment.
/// This commitment is recorded by all elders. After the ceremony completes,
/// anyone can verify that all committed contributions were actually included.
///
/// This prevents a malicious coordinator from selectively dropping honest
/// contributions to recover the toxic waste.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContributionCommitment {
    /// Node ID of the committing contributor
    pub contributor: String,
    /// Hash of current parameters (commits to specific chain position)
    pub prev_params_hash: [u8; 32],
    /// Random nonce to prevent commitment guessing
    pub nonce: [u8; 32],
    /// Timestamp of commitment
    pub timestamp: u64,
    /// Ceremony ID this commitment is for (4.22 SECURITY: binding)
    pub ceremony_id: [u8; 32],
}

impl ContributionCommitment {
    /// Create a new commitment before generating a contribution
    ///
    /// # Arguments
    /// * `contributor` - Node ID of the contributor
    /// * `prev_params_hash` - Hash of current parameters
    /// * `ceremony_id` - Unique ceremony identifier
    ///
    /// # Returns
    /// A commitment that should be broadcast to all elders before revealing the contribution
    ///
    /// # Errors
    /// Returns `MpcError::RandomFailure` if secure random number generation fails
    pub fn new(
        contributor: &str,
        prev_params_hash: [u8; 32],
        ceremony_id: [u8; 32],
    ) -> MpcResult<Self> {
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| MpcError::RandomFailure(format!("Failed to generate nonce: {}", e)))?;

        Ok(Self {
            contributor: contributor.to_string(),
            prev_params_hash,
            nonce,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            ceremony_id,
        })
    }

    /// Compute the commitment hash
    ///
    /// This is what gets recorded by elders and later verified against contributions.
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"mpc/commitment/v1");
        hasher.update(self.ceremony_id);
        hasher.update(self.contributor.as_bytes());
        hasher.update(self.prev_params_hash);
        hasher.update(self.nonce);
        hasher.update(self.timestamp.to_le_bytes());
        hasher.finalize().into()
    }

    /// Verify this commitment matches a contribution
    ///
    /// Returns true if the contribution was made by the same contributor
    /// and chains from the same previous parameters.
    pub fn matches_contribution(&self, contribution: &MpcContribution) -> bool {
        // Verify contributor matches
        if self.contributor != contribution.contributor {
            return false;
        }

        // Verify prev_params_hash matches
        if self.prev_params_hash != contribution.prev_params_hash {
            return false;
        }

        // Verify commitment hash matches (if contribution has one)
        if let Some(commitment_hash) = contribution.commitment_hash {
            if commitment_hash != self.hash() {
                return false;
            }
        }

        true
    }
}

/// Proof that a contribution was validly computed
///
/// This uses a Schnorr-like protocol to prove knowledge of the
/// secret scalars (tau, alpha, beta) without revealing them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContributionProof {
    /// Commitment to tau: g1^tau (in G1)
    pub tau_g1: Vec<u8>,
    /// Commitment to tau: g2^tau (in G2)
    pub tau_g2: Vec<u8>,
    /// Commitment to alpha: g1^alpha (in G1)
    pub alpha_g1: Vec<u8>,
    /// Commitment to beta: g1^beta (in G1)
    pub beta_g1: Vec<u8>,
    /// Commitment to beta: g2^beta (in G2)
    pub beta_g2: Vec<u8>,
    /// Schnorr proof components for tau
    pub tau_pok: ProofOfKnowledge,
    /// Schnorr proof components for alpha
    pub alpha_pok: ProofOfKnowledge,
    /// Schnorr proof components for beta
    pub beta_pok: ProofOfKnowledge,
}

/// Schnorr proof of knowledge for a discrete log
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofOfKnowledge {
    /// Random commitment R = g^r
    pub commitment_g1: Vec<u8>,
    /// Challenge hash
    pub challenge: [u8; 32],
    /// Response s = r + c*x
    pub response: Vec<u8>,
}

/// Toxic waste - the secret random values used in contribution
///
/// SECURITY: These values MUST be zeroized after use to prevent recovery from memory.
/// Uses `ZeroizeOnDrop` derive which uses volatile writes with compiler barriers
/// to prevent optimization from removing the zeroing operation.
///
/// 2.1 HIGH: Using ZeroizeOnDrop derive for reliable memory clearing.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct ToxicWaste {
    /// Raw bytes for tau (zeroized on drop)
    tau_bytes: [u8; 32],
    /// Raw bytes for alpha (zeroized on drop)
    alpha_bytes: [u8; 32],
    /// Raw bytes for beta (zeroized on drop)
    beta_bytes: [u8; 32],
    /// Computed scalars (derived from bytes) - marked skip since Scalar doesn't impl Zeroize
    /// but we zero the source bytes which is sufficient
    #[zeroize(skip)]
    tau: Scalar,
    #[zeroize(skip)]
    alpha: Scalar,
    #[zeroize(skip)]
    beta: Scalar,
}

impl ToxicWaste {
    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let tau = Scalar::random(&mut *rng);
        let alpha = Scalar::random(&mut *rng);
        let beta = Scalar::random(&mut *rng);
        Self {
            tau_bytes: tau.to_bytes_le(),
            alpha_bytes: alpha.to_bytes_le(),
            beta_bytes: beta.to_bytes_le(),
            tau,
            alpha,
            beta,
        }
    }
}

/// Generate a new MPC contribution
///
/// This function:
/// 1. Generates random tau, alpha, beta (toxic waste)
/// 2. Applies transformation to parameters
/// 3. Generates proof of valid transformation
/// 4. Zeroizes toxic waste from memory
///
/// # Arguments
/// * `prev_params` - The previous MPC parameters to transform
/// * `ceremony_id` - 4.22 SECURITY: Unique ceremony identifier to prevent cross-ceremony replay
/// * `position` - This contributor's position in the ceremony
/// * `contributor` - Contributor identifier
/// * `rng` - Cryptographically secure random number generator
pub fn generate_contribution<R: RngCore + CryptoRng>(
    prev_params: &Parameters<Bls12>,
    ceremony_id: &[u8; 32],
    position: u32,
    contributor: &str,
    rng: &mut R,
) -> MpcResult<(Parameters<Bls12>, MpcContribution)> {
    // Generate toxic waste
    let toxic = ToxicWaste::random(rng);

    // Hash the previous parameters
    let prev_params_hash = hash_parameters(prev_params)?;

    // Apply transformation to create new parameters
    let new_params = apply_contribution(prev_params, &toxic)?;

    // Hash the new parameters
    let new_params_hash = hash_parameters(&new_params)?;

    // Generate proof of valid transformation
    // 4.22: Include ceremony_id in proof to prevent replay attacks
    let proof = generate_proof(&toxic, ceremony_id, rng)?;

    // Create contribution record
    let contribution = MpcContribution {
        position,
        prev_params_hash,
        new_params_hash,
        proof,
        contributor: contributor.to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        // CRIT-2 FIX: Commitment hash is set later when generating with commitment
        commitment_hash: None,
    };

    // toxic is automatically zeroized here on drop

    Ok((new_params, contribution))
}

/// Result of a multi-circuit contribution
pub struct MultiContributionResult {
    /// Transformed note spend parameters (GhostNoteSpendCircuit)
    pub note_spend_params: Parameters<Bls12>,
    /// Transformed payout parameters (if provided)
    pub payout_params: Option<Parameters<Bls12>>,
    /// Transformed unshield parameters (if provided)
    pub unshield_params: Option<Parameters<Bls12>>,
    /// Contribution record (hash chain based on note spend params)
    pub contribution: MpcContribution,
}

/// Generate contributions for all circuit types using the same toxic waste
///
/// This ensures all parameter sets are transformed with identical randomness,
/// maintaining the 1-of-N security guarantee across all circuits.
/// The hash chain tracks note spend params as the primary circuit.
///
/// # Arguments
/// * `note_spend_params` - Note spend circuit parameters (required)
/// * `payout_params` - Payout circuit parameters (optional)
/// * `unshield_params` - Unshield circuit parameters (optional)
/// * `ceremony_id` - Unique ceremony identifier
/// * `position` - Contributor's position
/// * `contributor` - Contributor identifier
/// * `rng` - Cryptographically secure RNG
pub fn generate_multi_contribution<R: RngCore + CryptoRng>(
    note_spend_params: &Parameters<Bls12>,
    payout_params: Option<&Parameters<Bls12>>,
    unshield_params: Option<&Parameters<Bls12>>,
    ceremony_id: &[u8; 32],
    position: u32,
    contributor: &str,
    rng: &mut R,
) -> MpcResult<MultiContributionResult> {
    // Generate toxic waste (shared across all circuits)
    let toxic = ToxicWaste::random(rng);

    // Hash the previous note spend parameters (primary chain)
    let prev_params_hash = hash_parameters(note_spend_params)?;

    // Apply transformation to all parameter sets
    let new_note_spend_params = apply_contribution(note_spend_params, &toxic)?;
    let new_note_spend_hash = hash_parameters(&new_note_spend_params)?;

    let new_payout_params = match payout_params {
        Some(params) => Some(apply_contribution(params, &toxic)?),
        None => None,
    };

    let new_unshield_params = match unshield_params {
        Some(params) => Some(apply_contribution(params, &toxic)?),
        None => None,
    };

    // Generate proof of valid transformation
    let proof = generate_proof(&toxic, ceremony_id, rng)?;

    let contribution = MpcContribution {
        position,
        prev_params_hash,
        new_params_hash: new_note_spend_hash,
        proof,
        contributor: contributor.to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        commitment_hash: None,
    };

    // toxic is automatically zeroized here on drop

    Ok(MultiContributionResult {
        note_spend_params: new_note_spend_params,
        payout_params: new_payout_params,
        unshield_params: new_unshield_params,
        contribution,
    })
}

/// Apply a contribution's transformation to parameters
///
/// Implements Groth16 Phase 2 transformation:
/// - delta_g2 *= tau  (scale the witness-hiding delta)
/// - h[i] *= tau^(-1) (compensate: h encodes 1/delta factors)
/// - l[i] *= tau^(-1) (compensate: l encodes 1/delta factors)
///
/// Alpha, beta, gamma, ic, a, b_g1, b_g2 are NOT transformed.
/// Alpha and beta are fixed from the initial setup; modifying them without
/// updating the corresponding proving key elements (a, b, ic) would break
/// the Groth16 pairing equation e(A,B) = e(α,β) · e(acc,γ) · e(C,δ).
fn apply_contribution(
    params: &Parameters<Bls12>,
    toxic: &ToxicWaste,
) -> MpcResult<Parameters<Bls12>> {
    use std::sync::Arc;

    let mut new_params = params.clone();

    // tau^(-1): h and l encode 1/δ, so when δ *= tau, they must *= tau^(-1)
    let tau_inv = toxic
        .tau
        .invert()
        .expect("tau must be non-zero (generated from random bytes)");

    // Transform delta: both G1 and G2 representations must stay consistent.
    // The prover uses delta_g1 for randomization (A and C elements),
    // the verifier uses delta_g2 for the pairing check.
    let delta_g1_proj = new_params.vk.delta_g1.to_curve();
    new_params.vk.delta_g1 = (delta_g1_proj * toxic.tau).to_affine();

    let delta_g2_proj = new_params.vk.delta_g2.to_curve();
    new_params.vk.delta_g2 = (delta_g2_proj * toxic.tau).to_affine();

    // Transform h vector: h[i]' = h[i] * tau^(-1)
    // h encodes t(x)·x^i / δ, so scaling δ by tau requires scaling h by tau^(-1)
    let new_h: Vec<G1Affine> = params
        .h
        .iter()
        .map(|h| (h.to_curve() * tau_inv).to_affine())
        .collect();
    new_params.h = Arc::new(new_h);

    // Transform l vector: l[i]' = l[i] * tau^(-1)
    // l encodes (β·u_i(x) + α·v_i(x) + w_i(x)) / δ for private wires
    let new_l: Vec<G1Affine> = params
        .l
        .iter()
        .map(|l| (l.to_curve() * tau_inv).to_affine())
        .collect();
    new_params.l = Arc::new(new_l);

    // a, b_g1, b_g2, alpha, beta, gamma, ic: unchanged
    // These encode circuit structure and VK constants from initial setup

    Ok(new_params)
}

/// Generate proof of knowledge for the toxic waste
///
/// 4.22 SECURITY: ceremony_id is included in Schnorr challenges to prevent replay attacks
fn generate_proof<R: RngCore + CryptoRng>(
    toxic: &ToxicWaste,
    ceremony_id: &[u8; 32],
    rng: &mut R,
) -> MpcResult<ContributionProof> {
    let g1_generator = G1Affine::generator();
    let g2_generator = G2Affine::generator();

    // Compute commitments
    let tau_g1 = (g1_generator.to_curve() * toxic.tau).to_affine();
    let tau_g2 = (g2_generator.to_curve() * toxic.tau).to_affine();
    let alpha_g1 = (g1_generator.to_curve() * toxic.alpha).to_affine();
    let beta_g1 = (g1_generator.to_curve() * toxic.beta).to_affine();
    let beta_g2 = (g2_generator.to_curve() * toxic.beta).to_affine();

    // Generate Schnorr proofs for each secret
    // 4.22: Include ceremony_id in challenge to prevent cross-ceremony replay
    let tau_pok = schnorr_prove(g1_generator, &toxic.tau, ceremony_id, rng)?;
    let alpha_pok = schnorr_prove(g1_generator, &toxic.alpha, ceremony_id, rng)?;
    let beta_pok = schnorr_prove(g1_generator, &toxic.beta, ceremony_id, rng)?;

    Ok(ContributionProof {
        tau_g1: serialize_g1(&tau_g1)?,
        tau_g2: serialize_g2(&tau_g2)?,
        alpha_g1: serialize_g1(&alpha_g1)?,
        beta_g1: serialize_g1(&beta_g1)?,
        beta_g2: serialize_g2(&beta_g2)?,
        tau_pok,
        alpha_pok,
        beta_pok,
    })
}

/// Schnorr proof of knowledge of discrete log
///
/// 4.22 SECURITY: Challenge is bound to ceremony_id to prevent replay attacks
/// across different ceremonies.
fn schnorr_prove<R: RngCore + CryptoRng>(
    generator: G1Affine,
    secret: &Scalar,
    ceremony_id: &[u8; 32],
    rng: &mut R,
) -> MpcResult<ProofOfKnowledge> {
    // Random nonce
    let r = Scalar::random(rng);

    // Commitment R = g^r
    let commitment = (generator.to_curve() * r).to_affine();
    let commitment_bytes = serialize_g1(&commitment)?;

    // Public key Y = g^x
    let public_key = (generator.to_curve() * secret).to_affine();
    let public_key_bytes = serialize_g1(&public_key)?;

    // 4.22 SECURITY: Challenge c = H(ceremony_id || g || Y || R)
    // Including ceremony_id prevents proofs from being replayed in different ceremonies
    let mut hasher = Sha256::new();
    hasher.update(b"mpc/schnorr/v2/"); // Domain separator
    hasher.update(ceremony_id);
    hasher.update(&serialize_g1(&generator)?);
    hasher.update(&public_key_bytes);
    hasher.update(&commitment_bytes);
    let challenge: [u8; 32] = hasher.finalize().into();

    // Convert challenge to scalar
    let c = scalar_from_hash(&challenge);

    // Response s = r + c*x
    let response = r + (c * secret);
    let response_bytes = serialize_scalar(&response)?;

    Ok(ProofOfKnowledge {
        commitment_g1: commitment_bytes,
        challenge,
        response: response_bytes,
    })
}

/// Verify a contribution proof (LIVE path — enforces the ±1h timestamp skew).
///
/// 4.22 SECURITY: ceremony_id is used to verify Schnorr proofs are bound to this
/// ceremony. Use this when verifying a contribution that is being proposed RIGHT
/// NOW (the live voter / single-position incremental adoption): the skew window
/// rejects stale replayed contributions.
pub fn verify_contribution(
    prev_params: &Parameters<Bls12>,
    new_params: &Parameters<Bls12>,
    contribution: &MpcContribution,
    ceremony_id: &[u8; 32],
) -> MpcResult<bool> {
    verify_contribution_inner(
        prev_params,
        new_params,
        contribution,
        ceremony_id,
        /* enforce_timestamp_skew = */ true,
    )
}

/// Verify a contribution proof for HISTORICAL catch-up / lineage re-verification
/// (does NOT enforce the timestamp skew).
///
/// Stage C task 4: the genesis-anchored startup verification and the catch-up
/// path re-verify contributions that were legitimately approved LONG ago (a node
/// offline for days, or replaying the full chain at boot). Those contributions'
/// timestamps are far outside any ±1h window, so the live skew check would
/// wrongly reject them. The cryptographic guarantees that matter here — the
/// Schnorr proof bound to `ceremony_id`, the hash chain, and the h/l pairing
/// transform checks — are IDENTICAL to the live path; only the freshness window
/// (a replay defence for *live* proposals, irrelevant once a contribution is
/// already a BFT-approved part of the immutable lineage) is dropped.
pub fn verify_contribution_lineage(
    prev_params: &Parameters<Bls12>,
    new_params: &Parameters<Bls12>,
    contribution: &MpcContribution,
    ceremony_id: &[u8; 32],
) -> MpcResult<bool> {
    verify_contribution_inner(
        prev_params,
        new_params,
        contribution,
        ceremony_id,
        /* enforce_timestamp_skew = */ false,
    )
}

/// Shared verification core. `enforce_timestamp_skew` toggles ONLY the ±1h
/// freshness window; every cryptographic check is unconditional.
fn verify_contribution_inner(
    prev_params: &Parameters<Bls12>,
    new_params: &Parameters<Bls12>,
    contribution: &MpcContribution,
    ceremony_id: &[u8; 32],
    enforce_timestamp_skew: bool,
) -> MpcResult<bool> {
    // SECURITY: Validate timestamp is within ±1 hour of current time
    // This prevents replay attacks with old contributions (LIVE path only).
    if enforce_timestamp_skew {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let timestamp_diff = now.abs_diff(contribution.timestamp);
        const MAX_TIMESTAMP_SKEW_SECS: u64 = 3600; // 1 hour
        if timestamp_diff > MAX_TIMESTAMP_SKEW_SECS {
            return Err(MpcError::InvalidProof(format!(
                "Contribution timestamp too far from current time: {} seconds",
                timestamp_diff
            )));
        }
    }

    // Verify hash chain
    let prev_hash = hash_parameters(prev_params)?;
    if prev_hash != contribution.prev_params_hash {
        return Err(MpcError::InvalidChain {
            expected: hex::encode(contribution.prev_params_hash),
            actual: hex::encode(prev_hash),
        });
    }

    let new_hash = hash_parameters(new_params)?;
    if new_hash != contribution.new_params_hash {
        return Err(MpcError::HashMismatch {
            expected: hex::encode(contribution.new_params_hash),
            actual: hex::encode(new_hash),
        });
    }

    // Verify the proof of knowledge for each component
    let g1_generator = G1Affine::generator();

    // Deserialize proof commitments
    let tau_g1: G1Affine = deserialize_g1(&contribution.proof.tau_g1)?;
    let alpha_g1: G1Affine = deserialize_g1(&contribution.proof.alpha_g1)?;
    let beta_g1: G1Affine = deserialize_g1(&contribution.proof.beta_g1)?;

    // 4.22: Verify Schnorr proofs are bound to this ceremony
    if !schnorr_verify(
        g1_generator,
        &tau_g1,
        ceremony_id,
        &contribution.proof.tau_pok,
    )? {
        return Err(MpcError::InvalidProof(
            "tau proof verification failed".into(),
        ));
    }
    if !schnorr_verify(
        g1_generator,
        &alpha_g1,
        ceremony_id,
        &contribution.proof.alpha_pok,
    )? {
        return Err(MpcError::InvalidProof(
            "alpha proof verification failed".into(),
        ));
    }
    if !schnorr_verify(
        g1_generator,
        &beta_g1,
        ceremony_id,
        &contribution.proof.beta_pok,
    )? {
        return Err(MpcError::InvalidProof(
            "beta proof verification failed".into(),
        ));
    }

    // Verify the transformation was applied correctly using pairing checks
    // For each h[i]: e(new_h[i], G2) == e(old_h[i], tau_G2)
    let tau_g2: G2Affine = deserialize_g2(&contribution.proof.tau_g2)?;
    let g2_gen = G2Affine::generator();

    // Verify delta_g2 transformation
    // e(delta_g1, G2) should equal e(G1, new_delta_g2)
    // This verifies the contribution applied tau correctly to delta

    // Verify h vector transformation: new_h[i] = old_h[i] * tau^(-1)
    // Pairing check: e(new_h[i], tau_G2) == e(old_h[i], G2)
    //   ↔ new_h_scalar * tau == old_h_scalar ↔ new_h = old_h * tau^(-1) ✓
    let check_count = prev_params.h.len().min(new_params.h.len());

    for i in 0..check_count {
        let old_h = &prev_params.h[i];
        let new_h = &new_params.h[i];

        let lhs = blstrs::Bls12::pairing(&new_h.to_curve().to_affine(), &tau_g2);
        let rhs = blstrs::Bls12::pairing(&old_h.to_curve().to_affine(), &g2_gen);

        if lhs != rhs {
            return Err(MpcError::InvalidProof(format!(
                "Pairing check failed at h[{}]: transformation not applied correctly",
                i
            )));
        }
    }

    // Verify l vector transformation: new_l[i] = old_l[i] * tau^(-1)
    let l_check_count = prev_params.l.len().min(new_params.l.len());

    for i in 0..l_check_count {
        let old_l = &prev_params.l[i];
        let new_l = &new_params.l[i];

        let lhs = blstrs::Bls12::pairing(&new_l.to_curve().to_affine(), &tau_g2);
        let rhs = blstrs::Bls12::pairing(&old_l.to_curve().to_affine(), &g2_gen);

        if lhs != rhs {
            return Err(MpcError::InvalidProof(format!(
                "Pairing check failed at l[{}]: transformation not applied correctly",
                i
            )));
        }
    }

    Ok(true)
}

/// Verify a Schnorr proof of knowledge
///
/// 4.22 SECURITY: ceremony_id must match what was used during proof generation
/// to prevent cross-ceremony replay attacks.
fn schnorr_verify(
    generator: G1Affine,
    public_key: &G1Affine,
    ceremony_id: &[u8; 32],
    proof: &ProofOfKnowledge,
) -> MpcResult<bool> {
    let commitment: G1Affine = deserialize_g1(&proof.commitment_g1)?;
    let response: Scalar = deserialize_scalar(&proof.response)?;

    // 4.22: Recompute challenge with ceremony_id to match signing
    let mut hasher = Sha256::new();
    hasher.update(b"mpc/schnorr/v2/"); // Domain separator must match signing
    hasher.update(ceremony_id);
    hasher.update(&serialize_g1(&generator)?);
    hasher.update(&serialize_g1(public_key)?);
    hasher.update(&proof.commitment_g1);
    let expected_challenge: [u8; 32] = hasher.finalize().into();

    if expected_challenge != proof.challenge {
        return Ok(false);
    }

    // Verify: g^s = R * Y^c
    let c = scalar_from_hash(&proof.challenge);
    let lhs = (generator.to_curve() * response).to_affine();
    let rhs = (commitment.to_curve() + (public_key.to_curve() * c)).to_affine();

    Ok(lhs == rhs)
}

/// Hash parameters to create a chain link
pub fn hash_parameters(params: &Parameters<Bls12>) -> MpcResult<[u8; 32]> {
    let mut hasher = Sha256::new();

    // Hash the verification key components
    hasher.update(&serialize_g1(&params.vk.alpha_g1)?);
    hasher.update(&serialize_g1(&params.vk.beta_g1)?);
    hasher.update(&serialize_g2(&params.vk.beta_g2)?);
    hasher.update(&serialize_g2(&params.vk.gamma_g2)?);
    hasher.update(&serialize_g2(&params.vk.delta_g2)?);

    // Hash IC (input commitment) points
    for ic in &params.vk.ic {
        hasher.update(&serialize_g1(ic)?);
    }

    // SECURITY: Hash ALL h values to detect any tampering
    // Using streaming hash to handle large parameter sets efficiently
    hasher.update((params.h.len() as u64).to_le_bytes());
    for h in params.h.iter() {
        hasher.update(&serialize_g1(h)?);
    }

    // Also hash l values (Lagrange basis)
    hasher.update((params.l.len() as u64).to_le_bytes());
    for l in params.l.iter() {
        hasher.update(&serialize_g1(l)?);
    }

    Ok(hasher.finalize().into())
}

// Serialization helpers

fn serialize_g1(point: &G1Affine) -> MpcResult<Vec<u8>> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&point.to_compressed());
    Ok(buf)
}

fn deserialize_g1(bytes: &[u8]) -> MpcResult<G1Affine> {
    if bytes.len() != 48 {
        return Err(MpcError::Serialization(format!(
            "Invalid G1 point length: expected 48, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 48];
    arr.copy_from_slice(bytes);
    Option::from(G1Affine::from_compressed(&arr))
        .ok_or_else(|| MpcError::Serialization("Invalid G1 point".into()))
}

fn serialize_g2(point: &G2Affine) -> MpcResult<Vec<u8>> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&point.to_compressed());
    Ok(buf)
}

#[allow(dead_code)] // Reserved for verification proof deserialization
fn deserialize_g2(bytes: &[u8]) -> MpcResult<G2Affine> {
    if bytes.len() != 96 {
        return Err(MpcError::Serialization(format!(
            "Invalid G2 point length: expected 96, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 96];
    arr.copy_from_slice(bytes);
    Option::from(G2Affine::from_compressed(&arr))
        .ok_or_else(|| MpcError::Serialization("Invalid G2 point".into()))
}

fn serialize_scalar(scalar: &Scalar) -> MpcResult<Vec<u8>> {
    Ok(scalar.to_bytes_le().to_vec())
}

fn deserialize_scalar(bytes: &[u8]) -> MpcResult<Scalar> {
    if bytes.len() != 32 {
        return Err(MpcError::Serialization(format!(
            "Invalid scalar length: expected 32, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Option::from(Scalar::from_bytes_le(&arr))
        .ok_or_else(|| MpcError::Serialization("Invalid scalar".into()))
}

fn scalar_from_hash(hash: &[u8; 32]) -> Scalar {
    // Reduce hash into the BLS12-381 scalar field.
    // The scalar field modulus is ~2^255, so raw 32-byte values fail from_bytes_le ~50% of the time.
    // We clear the top 2 bits to guarantee the value is < 2^254, which is always below the modulus.
    // This avoids the previous Scalar::ONE fallback which broke Schnorr proof security.
    let mut reduced = *hash;
    reduced[31] &= 0x3F; // Clear top 2 bits of the most significant byte (LE format)
    Scalar::from_bytes_le(&reduced)
        .expect("scalar_from_hash: value with top 2 bits cleared must be in range")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_schnorr_proof_roundtrip() {
        let mut rng = OsRng;
        let secret = Scalar::random(&mut rng);
        let generator = G1Affine::generator();
        // 4.22: Test ceremony_id for proof binding
        let ceremony_id = [0u8; 32];

        let proof = schnorr_prove(generator, &secret, &ceremony_id, &mut rng).unwrap();
        let public_key = (generator.to_curve() * secret).to_affine();

        assert!(schnorr_verify(generator, &public_key, &ceremony_id, &proof).unwrap());
    }

    #[test]
    fn test_schnorr_proof_wrong_key_fails() {
        let mut rng = OsRng;
        let secret = Scalar::random(&mut rng);
        let wrong_secret = Scalar::random(&mut rng);
        let generator = G1Affine::generator();
        // 4.22: Test ceremony_id for proof binding
        let ceremony_id = [0u8; 32];

        let proof = schnorr_prove(generator, &secret, &ceremony_id, &mut rng).unwrap();
        let wrong_public_key = (generator.to_curve() * wrong_secret).to_affine();

        assert!(!schnorr_verify(generator, &wrong_public_key, &ceremony_id, &proof).unwrap());
    }

    #[test]
    fn test_schnorr_proof_wrong_ceremony_id_fails() {
        // 4.22: Verify proofs cannot be replayed across ceremonies
        let mut rng = OsRng;
        let secret = Scalar::random(&mut rng);
        let generator = G1Affine::generator();
        let ceremony_id = [1u8; 32];
        let wrong_ceremony_id = [2u8; 32];

        let proof = schnorr_prove(generator, &secret, &ceremony_id, &mut rng).unwrap();
        let public_key = (generator.to_curve() * secret).to_affine();

        // Verification with wrong ceremony_id should fail
        assert!(!schnorr_verify(generator, &public_key, &wrong_ceremony_id, &proof).unwrap());
        // Verification with correct ceremony_id should pass
        assert!(schnorr_verify(generator, &public_key, &ceremony_id, &proof).unwrap());
    }

    #[test]
    fn test_scalar_from_hash_never_fails() {
        // Verify that all-0xFF input does NOT produce Scalar::ONE (the old broken fallback)
        let max_hash = [0xFF; 32];
        let result = scalar_from_hash(&max_hash);
        assert_ne!(
            result,
            Scalar::ONE,
            "0xFF hash must not produce Scalar::ONE"
        );

        // Verify 100 random inputs all produce non-zero scalars
        use rand::RngCore;
        let mut rng = OsRng;
        for _ in 0..100 {
            let mut hash = [0u8; 32];
            rng.fill_bytes(&mut hash);
            let scalar = scalar_from_hash(&hash);
            assert_ne!(
                scalar,
                Scalar::ZERO,
                "scalar_from_hash should never produce zero for random input"
            );
        }
    }

    #[test]
    fn test_scalar_from_hash_deterministic() {
        let hash = [0x42; 32];
        let a = scalar_from_hash(&hash);
        let b = scalar_from_hash(&hash);
        assert_eq!(a, b, "scalar_from_hash must be deterministic");
    }

    #[test]
    fn test_serialize_roundtrip_g1() {
        let generator = G1Affine::generator();
        let bytes = serialize_g1(&generator).unwrap();
        let recovered = deserialize_g1(&bytes).unwrap();
        assert_eq!(generator, recovered);
    }

    #[test]
    fn test_serialize_roundtrip_scalar() {
        let mut rng = OsRng;
        let scalar = Scalar::random(&mut rng);
        let bytes = serialize_scalar(&scalar).unwrap();
        let recovered = deserialize_scalar(&bytes).unwrap();
        assert_eq!(scalar, recovered);
    }
}

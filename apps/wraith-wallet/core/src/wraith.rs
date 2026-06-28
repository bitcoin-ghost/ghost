//! Wraith Lite v1 — participant client.
//!
//! Drives the wallet's side of the protocol against a `wraith-coordinator`
//! HTTP endpoint:
//!
//! ```text
//! /find_or_create   → enrol in a session (placeholder bond_id)
//! (wallet escrows)  → bond is escrowed against (ghost_id, session_id)
//! /inputs           → commit UTXO + change addr; coordinator verifies bond
//! /nonce            → fetch coordinator pubkey + a fresh signing nonce
//! /blind-sign       → coordinator blind-signs the wallet's mix-output addr
//! /outputs          → wallet anonymously submits unblinded address + sig
//! /round-tx         → fetch the assembled unsigned bitcoin transaction
//! /witness          → submit signed witness for own input;
//!                     final submission triggers merge + broadcast
//! ```
//!
//! Phase 5b status — this is the entry point. The minimum viable
//! shape:
//!   - `WraithSessionClient` holds the base URL + an HTTP client.
//!   - `execute_mix` runs the whole pipeline once, end-to-end, and
//!     returns the broadcast txid.
//!   - The bond escrow step is the caller's responsibility (a real
//!     wallet calls ghost-pay; the integration test swaps in a
//!     direct `MockBondLedger.escrow` call). Future iterations will
//!     wire a `BondLedgerClient` trait so the wallet's bond
//!     dependency is pluggable like the coordinator's `BondLedger`.
//!   - Witness signing is supplied by the caller via a closure. The
//!     wallet's keystore + signer modules will plug in here later;
//!     for now any FnMut(&Transaction, usize) -> Witness works,
//!     including the placeholder-bytes function the coordinator's
//!     test suite uses.
//!
//! ## What's NOT in this commit
//!
//! - **Anonymous output submission.** The /outputs call uses the
//!   same HTTP client as /inputs, so the coordinator can correlate
//!   the wallet's IP across both. Real privacy requires a separate
//!   transport (Tor circuit / VPN / new TCP connection) for /outputs.
//!   The struct exposes `outputs_http` as a separate field so the
//!   future Tor wiring can swap it without touching this code.
//!
//! - **Coordinator pool / failover.** The client takes a single
//!   `base_url`. Multi-coordinator failover is B/6 territory.
//!
//! - **No-sign deadline awareness.** The client doesn't currently
//!   surface deadline hints to the caller; it just hits /witness
//!   and surfaces 410 Gone if the round expired underneath.
//!
//! - **Retries / idempotency.** Every call is one-shot. Production
//!   hardening adds bounded retry on transient HTTP errors.

use std::time::Duration;

use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::{Network, Transaction, Txid, Witness};
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use tracing::debug;

use wraith_protocol::{BlindSignatureResponse, BlindingContext, PublicNonce, UnblindedToken};

#[derive(Debug, thiserror::Error)]
pub enum WraithClientError {
    #[error("HTTP transport: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("coordinator returned {status}: {detail}")]
    Coordinator { status: u16, detail: String },
    #[error("response body did not match expected shape: {0}")]
    Shape(String),
    #[error("hex decode: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("bitcoin consensus encode: {0}")]
    Consensus(String),
    #[error("crypto: {0}")]
    Crypto(#[from] wraith_protocol::WraithError),
    #[error("signer rejected input {input_index}: {detail}")]
    Signer { input_index: usize, detail: String },
    #[error("bond escrow: {0}")]
    Bond(String),
}

/// Caller-supplied input commitment. The wallet picks the UTXO it
/// wants mixed; the client just shuttles the values to the
/// coordinator.
#[derive(Debug, Clone)]
pub struct ParticipantUtxo {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    /// Hex-encoded scriptPubKey of the spending output. Coordinator
    /// trusts the wallet here; bitcoind/mempool acceptance enforces
    /// correctness at broadcast time.
    pub scriptpubkey_hex: String,
}

/// One full mix request. Caller pre-chooses every value; the client
/// drives the protocol with no further input until `WitnessSigner`
/// gets called back.
#[derive(Debug, Clone)]
pub struct MixRequest {
    pub tier_id: String,
    pub ghost_id: String,
    /// Bond id placeholder echoed at /find_or_create time. The
    /// coordinator verifies the actual bond against the
    /// (ghost_id, session_id) tuple at /inputs time, so this is
    /// purely cosmetic here.
    pub bond_id_placeholder: String,
    pub utxo: ParticipantUtxo,
    /// Optional change address. Required when input.value_sats
    /// exceeds (denom + per-participant fee shares) by ≥ dust.
    pub change_address: Option<String>,
    /// Wallet's destination address for its mixed (denom-sized)
    /// output. Must NOT be linkable to the wallet's input UTXO —
    /// fresh address recommended.
    pub mix_output_address: String,
}

/// The result of a successful mix.
#[derive(Debug, Clone)]
pub struct MixOutcome {
    pub session_id: String,
    pub broadcast_txid: Txid,
    /// Index in the assembled tx's `output` vec where the wallet's
    /// mixed output landed. Useful for the wallet to register the
    /// new UTXO without scanning the chain.
    pub mixed_output_tx_index: usize,
}

/// One tier in `/api/v1/pool/discover`. Mirrors the coordinator's
/// `TierDescriptor` shape.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DiscoverTier {
    pub id: String,
    pub denomination_sats: u64,
    pub min_participants: u32,
    pub max_participants: u32,
    pub bond_sats: u64,
    pub service_fee_sats: u64,
}

/// The full `/api/v1/pool/discover` payload. Returned by
/// [`WraithSessionClient::discover`] alongside the URL that
/// actually answered.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DiscoverPayload {
    pub network: String,
    pub pool_id: String,
    pub service_fee_bps: u32,
    pub bond_bps: u32,
    pub fill_window_secs: u64,
    pub tiers: Vec<DiscoverTier>,
}

/// The intermediate result of `prepare_mix`. Carries the assembled
/// (unsigned) tx and all the metadata the caller needs to produce a
/// `bitcoin::Witness` for its own input. Pass this to
/// `submit_witness` once the witness is computed.
///
/// Holding a `PreparedMix` does NOT keep the round alive on the
/// coordinator side — the Signing-state no-sign deadline is ticking.
/// Sign and submit promptly.
#[derive(Debug, Clone)]
pub struct PreparedMix {
    pub session_id: String,
    /// The full unsigned round transaction — already mixed with
    /// other participants' inputs and outputs, just missing
    /// witnesses.
    pub unsigned_tx: Transaction,
    /// Index into `unsigned_tx.input` of THIS wallet's UTXO. The
    /// caller's signer needs this to compute the right sighash.
    pub input_index: usize,
    /// Value of the wallet's input UTXO. Required for BIP-143 /
    /// BIP-341 sighash computation; not derivable from the unsigned
    /// tx (it's the prev-out amount, not a tx-internal value).
    pub prev_amount_sats: u64,
    /// Per-input prevouts (script_pubkey + amount) in
    /// `unsigned_tx.input` order. Required for BIP-341 (Taproot)
    /// SIGHASH_DEFAULT, which commits to the prevouts of every
    /// input — not just the one this wallet is signing. P2WPKH
    /// signers can still get away with just `prev_amount_sats` /
    /// the wallet's own scriptPubKey, but exposing the full slice
    /// keeps the API uniform.
    pub prevouts: Vec<PreparedPrevOut>,
    /// Index in `unsigned_tx.output` where the wallet's mixed output
    /// landed. Carry-through to `MixOutcome.mixed_output_tx_index`.
    pub mixed_output_tx_index: usize,
    /// Wallet identity — kept for the /witness POST; not used by
    /// the caller.
    pub ghost_id: String,
}

/// One input prevout reference. Mirrors the coordinator's wire-format
/// type but lives on the wallet side so the wallet client doesn't
/// expose serde DTOs in its public API.
#[derive(Debug, Clone)]
pub struct PreparedPrevOut {
    /// Hex-encoded scriptPubKey of the spending output.
    pub scriptpubkey_hex: String,
    pub value_sats: u64,
}

/// The wallet's signing callback. Given the unsigned tx + the index
/// of this wallet's input, return a `Witness` that satisfies the
/// input's `script_pubkey`. Real wallets compute the proper sighash
/// (BIP-143/BIP-341 depending on the script type) and sign with the
/// keystore-managed key. Tests can return placeholder bytes when the
/// downstream broadcaster doesn't actually validate.
pub trait WitnessSigner {
    fn sign(
        &mut self,
        tx: &Transaction,
        input_index: usize,
        prev_amount_sats: u64,
    ) -> Result<Witness, WraithClientError>;
}

impl<F> WitnessSigner for F
where
    F: FnMut(&Transaction, usize, u64) -> Result<Witness, WraithClientError>,
{
    fn sign(
        &mut self,
        tx: &Transaction,
        input_index: usize,
        prev_amount_sats: u64,
    ) -> Result<Witness, WraithClientError> {
        (self)(tx, input_index, prev_amount_sats)
    }
}

/// Wallet-side participant client. Constructed once per coordinator,
/// re-used across rounds.
pub struct WraithSessionClient {
    base_url: String,
    /// Optional fallback coordinator URLs. When the primary
    /// `base_url` returns a connection error (refused, timed out,
    /// DNS-unresolvable), each peer URL is tried in order before the
    /// request fails. Mid-flight rounds where the wallet has only
    /// committed identity (Filling / Locked phases) survive an
    /// Active dying — the next request lands on a Standby that's
    /// been mirroring state via gossip. The Signing window still
    /// requires the v2 re-blind handover (DESIGN_LITE §7) because
    /// blinded signatures are bound to the original Active's
    /// signing key.
    peers: Vec<String>,
    network: Network,
    /// HTTP client used for everything that's NOT /outputs. The
    /// coordinator already knows the participant's identity at these
    /// endpoints (ghost_id is in the body), so anonymising them
    /// adds latency without privacy benefit.
    http: reqwest::Client,
    /// HTTP client used for /outputs only — the one anonymous
    /// submission. Defaults to a clone of `http`; when a SOCKS5
    /// proxy is configured (Tor in production), routes through it
    /// so the coordinator can't correlate input UTXOs with
    /// mix-output addresses by source IP.
    outputs_http: reqwest::Client,
}

impl WraithSessionClient {
    /// Construct without anonymising /outputs. Both HTTP clients use
    /// the same direct-connect transport. Suitable for test setups
    /// where the coordinator is on localhost; NOT suitable for
    /// production runs against a real coordinator.
    pub fn new(base_url: impl Into<String>, network: Network) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("reqwest build");
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            peers: Vec::new(),
            network,
            outputs_http: http.clone(),
            http,
        }
    }

    /// Construct with explicit fallback peer URLs. Coordinator pool
    /// failover for the connection-refused / timeout case: when the
    /// primary `base_url` is unreachable, requests rotate through
    /// `peers` (in order) before failing.
    ///
    /// Use for any non-test setup against a real coordinator pool.
    /// Pass `peers` as the `--peers` list configured on the
    /// coordinator binary so wallet and operator agree on the
    /// pool's address set.
    pub fn with_peers(base_url: impl Into<String>, peers: Vec<String>, network: Network) -> Self {
        let mut client = Self::new(base_url, network);
        client.peers = peers
            .into_iter()
            .map(|u| u.trim_end_matches('/').to_string())
            .collect();
        client
    }

    /// Construct with /outputs routed through `socks5_proxy_url`
    /// (e.g. `socks5h://127.0.0.1:9050` for system Tor). The /inputs
    /// /nonce /blind-sign /round-tx /witness paths still go direct;
    /// only /outputs uses the proxy, because /outputs is the one
    /// step where the coordinator must NOT learn the participant's
    /// IP (which would correlate them with their /inputs UTXO).
    ///
    /// Returns an error if the proxy URL is malformed.
    pub fn with_outputs_proxy(
        base_url: impl Into<String>,
        network: Network,
        socks5_proxy_url: &str,
    ) -> Result<Self, WraithClientError> {
        let direct = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;
        let proxy = reqwest::Proxy::all(socks5_proxy_url)
            .map_err(|e| WraithClientError::Shape(format!("invalid SOCKS5 proxy URL: {e}")))?;
        let outputs_http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .proxy(proxy)
            .build()?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            peers: Vec::new(),
            network,
            http: direct,
            outputs_http,
        })
    }

    /// Drive a single Wraith Lite round end-to-end with a synchronous
    /// signer callback. Convenience wrapper over `prepare_mix` +
    /// `submit_witness`; equivalent to:
    ///
    /// ```ignore
    /// let prepared = client.prepare_mix(req, bond_setup).await?;
    /// let witness = signer.sign(&prepared.unsigned_tx,
    ///                            prepared.input_index,
    ///                            prepared.prev_amount_sats)?;
    /// let outcome = client.submit_witness(&prepared, witness).await?;
    /// ```
    ///
    /// Use the split form when the signer is async (hardware wallet,
    /// remote signer service) or when the caller wants to inspect
    /// `prepared.unsigned_tx` before signing — e.g. the
    /// daemon-integrated CLI.
    pub async fn execute_mix<S, B, BFut>(
        &self,
        request: MixRequest,
        mut signer: S,
        bond_setup: B,
    ) -> Result<MixOutcome, WraithClientError>
    where
        S: WitnessSigner,
        B: FnMut(&str, u64) -> BFut,
        BFut: std::future::Future<Output = Result<(), WraithClientError>>,
    {
        let prepared = self.prepare_mix(request, bond_setup).await?;
        let witness = signer
            .sign(
                &prepared.unsigned_tx,
                prepared.input_index,
                prepared.prev_amount_sats,
            )
            .map_err(|e| match e {
                WraithClientError::Signer { .. } => e,
                other => WraithClientError::Signer {
                    input_index: prepared.input_index,
                    detail: other.to_string(),
                },
            })?;
        self.submit_witness(&prepared, witness).await
    }

    /// Drive the protocol from /find_or_create through /round-tx.
    /// Returns a `PreparedMix` with the assembled unsigned transaction
    /// and the metadata the caller needs to produce its own input
    /// witness. The caller signs asynchronously (hardware wallet,
    /// remote signer, etc.) and then calls `submit_witness`.
    ///
    /// `bond_setup` runs after /find_or_create returns the session_id
    /// — the wallet's bond ledger client (or test-time MockBondLedger
    /// escrow) plugs in here.
    pub async fn prepare_mix<B, BFut>(
        &self,
        request: MixRequest,
        mut bond_setup: B,
    ) -> Result<PreparedMix, WraithClientError>
    where
        B: FnMut(&str, u64) -> BFut,
        BFut: std::future::Future<Output = Result<(), WraithClientError>>,
    {
        // 1. Enrol.
        let foc: FindOrCreateResponse = self
            .post_json(
                "/api/v1/session/find_or_create",
                &serde_json::json!({
                    "tier_id": request.tier_id,
                    "ghost_id": request.ghost_id,
                    "bond_id": request.bond_id_placeholder,
                }),
            )
            .await?;
        let session_id = foc.session.session_id.clone();
        debug!(%session_id, "enrolled in session");

        // 2. Caller-driven bond escrow against the now-known session.
        bond_setup(&session_id, foc.session.bond_amount_sats).await?;

        // 2b. Wait for the coordinator to flip Filling → Locked. /inputs
        //     refuses Filling-state submissions, so we have to block
        //     until quorum forms (or the fill window expires). Bounded
        //     poll loop with backoff; gives up after the round's fill
        //     window plus a safety margin.
        self.wait_for_locked(&session_id).await?;

        // 3. Commit UTXO. The 5th /inputs auto-advances the round to
        //    Signing on the coordinator side. Earlier submitters
        //    leave the session in Locked until the 5th lands.
        let _inputs: serde_json::Value = self
            .post_json(
                &format!("/api/v1/session/{session_id}/inputs"),
                &serde_json::json!({
                    "ghost_id": request.ghost_id,
                    "input": {
                        "txid": request.utxo.txid,
                        "vout": request.utxo.vout,
                        "value_sats": request.utxo.value_sats,
                        "scriptpubkey_hex": request.utxo.scriptpubkey_hex,
                    },
                    "change_address": request.change_address,
                }),
            )
            .await?;

        // 3b. Wait for Locked → Signing. /nonce 409s in Locked state;
        //     only the 5th /inputs flips us to Signing, so the first
        //     four submitters need to wait for the last one to land
        //     before continuing.
        self.wait_for_signing(&session_id).await?;

        // 4. /nonce — get the coordinator's per-round signing pubkey
        //    + a fresh blind-sig nonce.
        let nonce: NonceResponse = self
            .post_json(
                &format!("/api/v1/session/{session_id}/nonce"),
                &serde_json::json!({ "ghost_id": request.ghost_id }),
            )
            .await?;
        let pubkey_bytes = hex::decode(&nonce.signing_pubkey)?;
        let signer_pubkey = PublicKey::from_slice(&pubkey_bytes)
            .map_err(|e| WraithClientError::Shape(format!("signing_pubkey: {e}")))?;
        let nonce_point = decode_33(&nonce.nonce_point)?;
        let blind_session_id = decode_32(&nonce.blind_session_id)?;
        let signing_key_id = decode_32(&nonce.signing_key_id)?;
        let public_nonce = PublicNonce {
            nonce_point,
            session_id: blind_session_id,
        };

        // 5. Blind the mix-output address locally.
        let blinding = BlindingContext::new(
            request.mix_output_address.as_bytes().to_vec(),
            &signer_pubkey,
            &public_nonce,
        )?;
        let blinded_challenge = blinding.create_blinded_challenge()?;
        let blinded_nonce_point = blinding.blinded_nonce().serialize();

        // 6. /blind-sign.
        let bs: BlindSignResponse = self
            .post_json(
                &format!("/api/v1/session/{session_id}/blind-sign"),
                &serde_json::json!({
                    "ghost_id": request.ghost_id,
                    "blinded_challenge": hex::encode(blinded_challenge.challenge),
                    "blind_session_id": hex::encode(blinded_challenge.session_id),
                }),
            )
            .await?;
        let s_bytes = decode_32(&bs.signature_scalar)?;
        let response = BlindSignatureResponse {
            signature_scalar: s_bytes,
            session_id: blind_session_id,
        };
        let token: UnblindedToken = blinding.unblind(&response, signing_key_id)?;

        // 7. /outputs — anonymous submission of the unblinded address +
        //    sig. NOTE v1: same HTTP client; production swaps in Tor.
        let _: serde_json::Value = self
            .post_json_via(
                &self.outputs_http,
                &format!("/api/v1/session/{session_id}/outputs"),
                &serde_json::json!({
                    "address": request.mix_output_address,
                    "blinded_nonce_point": hex::encode(blinded_nonce_point),
                    "unblinded_signature_scalar": hex::encode(token.signature_scalar),
                }),
            )
            .await?;

        // 8. Fetch the assembled tx. /round-tx returns 404 until ALL
        //    participants have posted /outputs — only the last
        //    submitter triggers assembly. Earlier submitters arrive
        //    here while the coordinator still has incomplete output
        //    data, so poll with backoff. Bounded so a stuck round
        //    doesn't hang the caller forever.
        let rt: RoundTxResponse = self.wait_for_round_tx(session_id.as_str()).await?;
        let tx: Transaction = deserialize_hex(&rt.unsigned_tx_hex)
            .map_err(|e| WraithClientError::Consensus(e.to_string()))?;

        // Find this wallet's input index.
        let target_txid = bitcoin::Txid::from_str_hex(&request.utxo.txid)?;
        let input_index = tx
            .input
            .iter()
            .position(|t| {
                t.previous_output.txid == target_txid && t.previous_output.vout == request.utxo.vout
            })
            .ok_or_else(|| {
                WraithClientError::Shape("our input is not in the assembled tx".into())
            })?;

        // 9. Locate the mixed output tx index by scriptPubKey match.
        //    The wallet's mix_output_address is unique within the
        //    round (coordinator rejects duplicates), so the address
        //    parses to a single scriptPubKey we can find in tx.output.
        let mixed_output_tx_index =
            locate_mix_output_index(&tx, &request.mix_output_address, self.network)?;

        let prevouts = rt
            .prevouts
            .iter()
            .map(|p| PreparedPrevOut {
                scriptpubkey_hex: p.scriptpubkey_hex.clone(),
                value_sats: p.value_sats,
            })
            .collect();

        Ok(PreparedMix {
            session_id,
            unsigned_tx: tx,
            input_index,
            prev_amount_sats: request.utxo.value_sats,
            prevouts,
            mixed_output_tx_index,
            ghost_id: request.ghost_id,
        })
    }

    /// Submit the signed witness for a prepared mix. Drives /witness
    /// and (for non-final submitters) waits for the round to reach
    /// Complete before returning. Returns the broadcast txid.
    pub async fn submit_witness(
        &self,
        prepared: &PreparedMix,
        witness: Witness,
    ) -> Result<MixOutcome, WraithClientError> {
        let witness_hex = bitcoin::consensus::encode::serialize_hex(&witness);
        let session_id = &prepared.session_id;

        let wresp: WitnessResponse = self
            .post_json(
                &format!("/api/v1/session/{session_id}/witness"),
                &serde_json::json!({
                    "ghost_id": prepared.ghost_id,
                    "input_index": prepared.input_index,
                    "witness_hex": witness_hex,
                }),
            )
            .await?;

        // Only the Nth (last) submitter gets `broadcast_txid` directly
        // in the /witness response — the other N-1 wallets see a
        // non-terminal acknowledgement and have to wait for the
        // session to flip to Complete.
        let broadcast_txid = match wresp.broadcast_txid {
            Some(txid_hex) => Txid::from_str_hex(&txid_hex)?,
            None => {
                self.wait_for_complete(session_id).await?;
                Txid::from_str_hex(&prepared.unsigned_tx.compute_txid().to_string())?
            }
        };

        Ok(MixOutcome {
            session_id: session_id.clone(),
            broadcast_txid,
            mixed_output_tx_index: prepared.mixed_output_tx_index,
        })
    }

    /// Poll `GET /:id` until the session reaches Complete. Used by
    /// non-final witness submitters to know when broadcast happened
    /// (the Nth submitter triggers it, learns directly; everyone else
    /// finds out via /status).
    async fn wait_for_complete(&self, session_id: &str) -> Result<(), WraithClientError> {
        let deadline = std::time::Instant::now() + Duration::from_secs(120);
        loop {
            let status: SessionStatusResponse = self
                .get_json(&format!("/api/v1/session/{session_id}"))
                .await?;
            match status.session.state.as_str() {
                "complete" => return Ok(()),
                "failed" => {
                    return Err(WraithClientError::Coordinator {
                        status: 410,
                        detail: "session failed before reaching Complete".into(),
                    });
                }
                _ => {}
            }
            if std::time::Instant::now() >= deadline {
                return Err(WraithClientError::Shape(
                    "timed out waiting for session to reach Complete".into(),
                ));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Poll `GET /:id` until the session is in Signing. Used
    /// between /inputs and /nonce: the 5th /inputs auto-advances
    /// Locked → Signing on the coordinator, so the first four
    /// submitters must wait for the last one to land before
    /// /nonce will accept their request.
    async fn wait_for_signing(&self, session_id: &str) -> Result<(), WraithClientError> {
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            let status: SessionStatusResponse = self
                .get_json(&format!("/api/v1/session/{session_id}"))
                .await?;
            match status.session.state.as_str() {
                "signing" => return Ok(()),
                "failed" => {
                    return Err(WraithClientError::Coordinator {
                        status: 410,
                        detail: "session failed before reaching Signing".into(),
                    });
                }
                _ => {}
            }
            if std::time::Instant::now() >= deadline {
                return Err(WraithClientError::Shape(
                    "timed out waiting for session to reach Signing".into(),
                ));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Poll `GET /:id/round-tx` until it returns 200 (round
    /// assembled) or 410 (session failed). Anything else times
    /// out. Used by `prepare_mix` after /outputs because /round-tx
    /// returns 404 `round_not_assembled` for every submitter
    /// except the very last one — assembly only fires when the
    /// final /outputs lands. We can't predict ordering, so every
    /// submitter polls.
    ///
    /// 60s timeout: generous enough to absorb the slowest peer's
    /// /outputs round-trip, tight enough that a genuinely stuck
    /// round surfaces as an error instead of hanging the caller.
    async fn wait_for_round_tx(
        &self,
        session_id: &str,
    ) -> Result<RoundTxResponse, WraithClientError> {
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            match self
                .get_json::<RoundTxResponse>(&format!("/api/v1/session/{session_id}/round-tx"))
                .await
            {
                Ok(rt) => return Ok(rt),
                // 404 with `round_not_assembled` body is the
                // expected "not yet" — keep polling. Other 4xx /
                // 5xx errors are real failures we surface
                // immediately. The body text check is best-effort:
                // current coordinator emits the literal token, but
                // future versions may not — fall through to retry
                // on any 404.
                Err(WraithClientError::Coordinator { status: 404, .. }) => {}
                Err(WraithClientError::Coordinator {
                    status: 410,
                    detail,
                }) => {
                    return Err(WraithClientError::Coordinator {
                        status: 410,
                        detail,
                    });
                }
                Err(e) => return Err(e),
            }
            if std::time::Instant::now() >= deadline {
                return Err(WraithClientError::Shape(
                    "timed out waiting for /round-tx (round never assembled)".into(),
                ));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Poll `GET /:id` until the session is in Locked or Signing.
    /// Bounded by a generous timeout so a misconfigured coordinator
    /// (or a round that legitimately times out) doesn't hang the
    /// caller forever. Polls every 250ms — frequent enough to ride
    /// the manual state-flip in tests, sparse enough to avoid
    /// hammering a real coordinator.
    async fn wait_for_locked(&self, session_id: &str) -> Result<(), WraithClientError> {
        let deadline = std::time::Instant::now() + Duration::from_secs(360);
        loop {
            let status: SessionStatusResponse = self
                .get_json(&format!("/api/v1/session/{session_id}"))
                .await?;
            match status.session.state.as_str() {
                "locked" | "signing" => return Ok(()),
                "failed" => {
                    return Err(WraithClientError::Coordinator {
                        status: 410,
                        detail: "session failed before reaching Locked".into(),
                    });
                }
                _ => {} // filling, complete, broadcasting — keep waiting
            }
            if std::time::Instant::now() >= deadline {
                return Err(WraithClientError::Shape(
                    "timed out waiting for session to reach Locked".into(),
                ));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Fetch the coordinator's `/api/v1/pool/discover` payload —
    /// network, supported tiers, fee + bond rates. Same connect-error
    /// rotation as the mix calls: HTTP errors propagate unchanged
    /// (a coordinator answered, even if it errored), only
    /// connection-level failures rotate to the next peer.
    ///
    /// Returns the URL that actually answered alongside the parsed
    /// payload, so the caller can show users which active served the
    /// response after a failover.
    pub async fn discover(&self) -> Result<(String, DiscoverPayload), WraithClientError> {
        let mut last_err: Option<reqwest::Error> = None;
        for url in self.urls_in_order() {
            let endpoint = format!("{url}/api/v1/pool/discover");
            match self.http.get(&endpoint).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if !status.is_success() {
                        let detail = resp.text().await.unwrap_or_default();
                        return Err(WraithClientError::Coordinator {
                            status: status.as_u16(),
                            detail,
                        });
                    }
                    let parsed = resp
                        .json::<DiscoverPayload>()
                        .await
                        .map_err(|e| WraithClientError::Shape(e.to_string()))?;
                    return Ok((url.to_string(), parsed));
                }
                Err(e) if is_connectivity_error(&e) => {
                    tracing::warn!(
                        url = %url,
                        error = %e,
                        "wraith-coordinator discover unreachable, rotating to next peer"
                    );
                    last_err = Some(e);
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
        Err(last_err
            .map(WraithClientError::from)
            .unwrap_or_else(|| WraithClientError::Shape("no coordinator URLs configured".into())))
    }

    async fn post_json<R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<R, WraithClientError> {
        self.post_json_via(&self.http, path, body).await
    }

    async fn post_json_via<R: serde::de::DeserializeOwned>(
        &self,
        http: &reqwest::Client,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<R, WraithClientError> {
        let mut last_err: Option<reqwest::Error> = None;
        for url in self.urls_in_order() {
            match http.post(format!("{url}{path}")).json(body).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if !status.is_success() {
                        // Real HTTP error from a reachable coordinator
                        // — surface as-is, not a connectivity failure.
                        let detail = resp.text().await.unwrap_or_default();
                        return Err(WraithClientError::Coordinator {
                            status: status.as_u16(),
                            detail,
                        });
                    }
                    return resp
                        .json::<R>()
                        .await
                        .map_err(|e| WraithClientError::Shape(e.to_string()));
                }
                Err(e) if is_connectivity_error(&e) => {
                    tracing::warn!(
                        url = %url,
                        path = %path,
                        error = %e,
                        "wraith-coordinator unreachable, rotating to next peer"
                    );
                    last_err = Some(e);
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
        Err(last_err
            .map(WraithClientError::from)
            .unwrap_or_else(|| WraithClientError::Shape("no coordinator URLs configured".into())))
    }

    async fn get_json<R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<R, WraithClientError> {
        let mut last_err: Option<reqwest::Error> = None;
        for url in self.urls_in_order() {
            match self.http.get(format!("{url}{path}")).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if !status.is_success() {
                        let detail = resp.text().await.unwrap_or_default();
                        return Err(WraithClientError::Coordinator {
                            status: status.as_u16(),
                            detail,
                        });
                    }
                    return resp
                        .json::<R>()
                        .await
                        .map_err(|e| WraithClientError::Shape(e.to_string()));
                }
                Err(e) if is_connectivity_error(&e) => {
                    tracing::warn!(
                        url = %url,
                        path = %path,
                        error = %e,
                        "wraith-coordinator unreachable, rotating to next peer"
                    );
                    last_err = Some(e);
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
        Err(last_err
            .map(WraithClientError::from)
            .unwrap_or_else(|| WraithClientError::Shape("no coordinator URLs configured".into())))
    }

    /// `base_url` first, then each peer in configured order. Rotated
    /// per-request so a single transient connect failure doesn't
    /// permanently route around the primary.
    fn urls_in_order(&self) -> Vec<&str> {
        let mut out = Vec::with_capacity(1 + self.peers.len());
        out.push(self.base_url.as_str());
        for p in &self.peers {
            out.push(p.as_str());
        }
        out
    }
}

/// Treat connection-level reqwest errors as failover triggers.
/// 4xx/5xx HTTP responses come back as `Ok(resp)` and are NOT
/// failover triggers — they mean a coordinator answered, even if it
/// rejected the request.
fn is_connectivity_error(e: &reqwest::Error) -> bool {
    e.is_connect() || e.is_timeout() || e.is_request()
}

fn locate_mix_output_index(
    tx: &Transaction,
    address: &str,
    network: Network,
) -> Result<usize, WraithClientError> {
    use std::str::FromStr;
    let parsed = bitcoin::Address::from_str(address)
        .map_err(|e| WraithClientError::Shape(format!("can't parse mix address: {e}")))?
        .require_network(network)
        .map_err(|e| WraithClientError::Shape(format!("address wrong network: {e}")))?;
    let target_spk = parsed.script_pubkey();
    tx.output
        .iter()
        .position(|o| o.script_pubkey == target_spk)
        .ok_or_else(|| WraithClientError::Shape("mix output not in assembled tx".into()))
}

fn decode_32(s: &str) -> Result<[u8; 32], WraithClientError> {
    let raw = hex::decode(s)?;
    if raw.len() != 32 {
        return Err(WraithClientError::Shape(format!(
            "expected 32 bytes, got {}",
            raw.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn decode_33(s: &str) -> Result<[u8; 33], WraithClientError> {
    let raw = hex::decode(s)?;
    if raw.len() != 33 {
        return Err(WraithClientError::Shape(format!(
            "expected 33 bytes, got {}",
            raw.len()
        )));
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(&raw);
    Ok(out)
}

trait FromHex: Sized {
    fn from_str_hex(s: &str) -> Result<Self, WraithClientError>;
}

impl FromHex for Txid {
    fn from_str_hex(s: &str) -> Result<Self, WraithClientError> {
        use std::str::FromStr;
        Txid::from_str(s).map_err(|e| WraithClientError::Shape(format!("bad txid hex: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Wire-format DTOs (intentional duplicates of the coordinator's response
// types — coordinator is a binary, not a published crate, so we don't
// share Rust types across the wire).
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Serialize)]
struct FindOrCreateResponse {
    session: SessionDescriptor,
    joined: bool,
    bond_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct SessionDescriptor {
    session_id: String,
    tier_id: String,
    state: String,
    slots_filled: u32,
    slots_total: u32,
    bond_amount_sats: u64,
    fill_window_expires_at: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct NonceResponse {
    signing_pubkey: String,
    signer_session_id: String,
    signing_key_id: String,
    nonce_point: String,
    blind_session_id: String,
}

#[derive(Debug, Deserialize)]
struct BlindSignResponse {
    signature_scalar: String,
    blind_session_id: String,
}

#[derive(Debug, Deserialize)]
struct RoundTxResponse {
    unsigned_tx_hex: String,
    txid: String,
    mining_fee_sats: u64,
    #[serde(default)]
    prevouts: Vec<PrevOutDto>,
    assembled_at: u64,
}

#[derive(Debug, Deserialize)]
struct PrevOutDto {
    scriptpubkey_hex: String,
    value_sats: u64,
}

#[derive(Debug, Deserialize)]
struct WitnessResponse {
    state: String,
    witnesses_collected: u32,
    enrolled_count: u32,
    broadcast_txid: Option<String>,
    bonds_resolved: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct SessionStatusResponse {
    session: SessionDescriptor,
}

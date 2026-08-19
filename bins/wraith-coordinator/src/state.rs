//! Shared coordinator state. Held in an `Arc<CoordinatorState>` and
//! threaded into every endpoint handler via Axum's `State` extractor.
//!
//! All mutable state lives behind sync primitives (`Mutex`, `RwLock` from
//! the protocol crate's pieces). Axum handlers are async; the inner
//! locks are short-lived so we don't need async mutexes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use bitcoin::Network;

use wraith_protocol::{
    BondLedger, Clock, CoordinatorSigner, LiteSessionRegistry, LiteTier, RandomSessionIdGenerator,
    RemixQueue, SessionIdGenerator, SystemClock,
};

use crate::assembly::AssembledRound;
use crate::broadcaster::Broadcaster;
use crate::inputs::AcceptedInputs;
use crate::outputs::AcceptedOutput;
use crate::utxo_source::UtxoSource;
use crate::witnesses::AcceptedWitness;

/// One Schnorr blind-signature signer per active round, lazily created
/// the first time a participant hits `/nonce`. Kept inside an
/// `Arc<Mutex<…>>` so handlers can lock briefly during crypto operations
/// without holding the outer registry mutex.
pub type SharedSigner = Arc<Mutex<CoordinatorSigner>>;

/// Process-global state shared across HTTP handlers.
pub struct CoordinatorState {
    /// Bitcoin network this coordinator serves.
    pub network: Network,
    /// In-flight session registry. Active coordinators populate it via
    /// `find_or_create` + lifecycle transitions; standbys mirror it via
    /// gossip events.
    pub sessions: LiteSessionRegistry,
    /// Remix queue per tier. Wallets enrol after a successful round to
    /// auto-rotate into the next session.
    pub remix: RemixQueue,
    /// Source of "now". `SystemClock` in production; tests inject
    /// `MockClock` so fill-window expiry can be exercised deterministically.
    pub clock: Arc<dyn Clock>,
    /// Source of fresh session IDs. `RandomSessionIdGenerator` in
    /// production; tests inject `DeterministicSessionIdGenerator` so they
    /// can pin exact session_id strings.
    pub id_gen: Arc<dyn SessionIdGenerator>,
    /// L2 escrow ledger. `None` until phase C wires the real ghost-pay
    /// client; tests inject `MockBondLedger`. `/inputs` returns
    /// `503 ledger_not_configured` while this is None — the binary boots
    /// fine without it but won't accept commit-phase submissions.
    pub bond_ledger: Option<Arc<dyn BondLedger>>,
    /// UTXO-set lookup. `None` until an operator configures a node
    /// connection; `/inputs` returns `503 utxo_source_not_configured`
    /// while it is, because registration must never fall back to
    /// trusting the wallet's own account of its input (#699).
    pub utxo_source: Option<Arc<dyn UtxoSource>>,
    /// Coordinator's fee-collection address. Used as the destination for
    /// the per-Mix-round service-fee output. `None` until the operator
    /// supplies one (CLI flag / config). `/inputs` returns
    /// `503 fee_address_not_configured` for Mix rounds while this is None;
    /// Jump rounds don't need it.
    pub coordinator_fee_address: Option<String>,
    /// Per-session validated participant inputs, accumulated as
    /// participants hit `/inputs`. Once every enrolled participant has
    /// submitted, the session transitions Locked → Signing.
    pub inputs_store: Mutex<HashMap<String, Vec<AcceptedInputs>>>,
    /// Per-session unblinded mix-output addresses, accumulated as
    /// wallets hit `/outputs` over anonymous connections. NO ghost_id
    /// is recorded — that's the unlinkability invariant. Once
    /// `outputs.len() == enrolled_count`, B/5b's tx-assembly path
    /// kicks in.
    pub outputs_store: Mutex<HashMap<String, Vec<AcceptedOutput>>>,
    /// Per-session assembled round transactions, populated by B/5b
    /// the first time `/outputs` lands the Nth submission. Wallets
    /// fetch the unsigned transaction hex from `GET /:id/round-tx`
    /// and produce per-input witnesses for B/5c.
    pub assembled_rounds: Mutex<HashMap<String, AssembledRound>>,
    /// Per-session witness submissions accumulated as wallets hit
    /// `/witness`. Once `witnesses.len() == enrolled_count`, the
    /// coordinator merges them into the assembled tx and calls
    /// `broadcaster.broadcast(&tx)`.
    pub witnesses_store: Mutex<HashMap<String, Vec<AcceptedWitness>>>,
    /// Per-session no-sign deadline (unix seconds). Recorded by /inputs
    /// when it advances Locked → Signing. /witness checks it at the
    /// top: if `now >= deadline` and the round hasn't completed, the
    /// round fails, non-signers' bonds get slashed, signers' bonds
    /// get refunded as RoundVoided.
    pub signing_deadlines: Mutex<HashMap<String, u64>>,
    /// Network broadcast backend. `None` until phase D wires the
    /// real bitcoind RPC client; tests inject `StubBroadcaster`. The
    /// witness handler returns 503 `broadcaster_not_configured` while
    /// this is None on the round-completing submission.
    pub broadcaster: Option<Arc<dyn Broadcaster>>,
    /// Per-round Schnorr blind-signature signer. Lazily created on the
    /// first `/nonce` call for a session; reused for every subsequent
    /// `/nonce` and `/blind-sign` on the same session. Each signer
    /// holds its own ephemeral signing keypair so the coordinator
    /// can't link blinded requests to unblinded outputs.
    ///
    /// Failover note: signers are in-memory only — a coordinator
    /// restart drops them, and B/6 (Active/Standby gossip) will need
    /// the re-blinding-on-failover path described in DESIGN_LITE §7
    /// before standbys can serve a round started by a now-dead Active.
    pub signers: Mutex<HashMap<String, SharedSigner>>,
    /// Shared HMAC key for the inter-coordinator gossip route. When
    /// `Some`, the receive handler verifies `X-Ghost-Signature` +
    /// `X-Ghost-Timestamp` against this key (see `gossip_auth.rs`).
    /// When `None`, the route accepts unsigned requests — operators
    /// must firewall the `/api/v1/internal/` prefix.
    pub gossip_peer_secret: Option<String>,
    /// Unix-seconds the binary started. `/health` reports uptime.
    pub started_at: u64,
    /// Override for the per-session fill window in seconds. Defaults
    /// to `LITE_FILL_WINDOW_SECS` (300s) — the production-tuned value
    /// from DESIGN_LITE §11. Operators may shorten this (e.g.
    /// regtest demos use `2s`) to skip the wait between
    /// `min_participants` and `max_participants`. Refused on mainnet
    /// without operator consent — see the binary's CLI gate.
    pub fill_window_secs: u64,
}

impl CoordinatorState {
    /// Production constructor — system clock, CSPRNG-based session ids,
    /// no bond ledger (phase C wires it), no fee address (operator
    /// configures it), no broadcaster (phase D wires it).
    pub fn new(network: Network) -> Self {
        Self::with_components(
            network,
            Arc::new(SystemClock),
            Arc::new(RandomSessionIdGenerator),
            None,
            None,
            None,
        )
    }

    /// Test / advanced-config constructor — caller supplies clock, id
    /// generator, bond ledger, fee address, and broadcaster. Used by
    /// integration tests under `tests/` to pin deterministic session
    /// IDs and inject `MockBondLedger` + `StubBroadcaster`.
    pub fn with_components(
        network: Network,
        clock: Arc<dyn Clock>,
        id_gen: Arc<dyn SessionIdGenerator>,
        bond_ledger: Option<Arc<dyn BondLedger>>,
        coordinator_fee_address: Option<String>,
        broadcaster: Option<Arc<dyn Broadcaster>>,
    ) -> Self {
        let started_at = clock.unix_secs();
        Self {
            network,
            sessions: LiteSessionRegistry::new(),
            remix: RemixQueue::new(),
            clock,
            id_gen,
            bond_ledger,
            utxo_source: None,
            coordinator_fee_address,
            inputs_store: Mutex::new(HashMap::new()),
            outputs_store: Mutex::new(HashMap::new()),
            assembled_rounds: Mutex::new(HashMap::new()),
            witnesses_store: Mutex::new(HashMap::new()),
            broadcaster,
            signing_deadlines: Mutex::new(HashMap::new()),
            signers: Mutex::new(HashMap::new()),
            gossip_peer_secret: None,
            started_at,
            fill_window_secs: wraith_protocol::LITE_FILL_WINDOW_SECS,
        }
    }

    /// Attach a UTXO source. Separate from `with_components` because it
    /// is the seventh knob and the positional list is already long —
    /// callers chain it: `with_components(..).with_utxo_source(src)`.
    pub fn with_utxo_source(mut self, source: Arc<dyn UtxoSource>) -> Self {
        self.utxo_source = Some(source);
        self
    }

    /// Get-or-create the per-round signer. Idempotent under concurrent
    /// access — only one signer is ever created per session_id, even
    /// if multiple `/nonce` requests race.
    pub fn signer_for(
        &self,
        session_id: &str,
    ) -> Result<SharedSigner, wraith_protocol::WraithError> {
        let mut signers = self.signers.lock().expect("signers poisoned");
        if let Some(existing) = signers.get(session_id) {
            return Ok(existing.clone());
        }
        // Derive a 32-byte signer-internal session id from the textual
        // round id. The signer's `session_id` is opaque internally — it
        // just needs to be a stable per-round value.
        let mut digest = [0u8; 32];
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"wraith-coordinator/signer-session-id/v1");
        h.update(session_id.as_bytes());
        digest.copy_from_slice(&h.finalize());
        let signer = CoordinatorSigner::new(&digest)?;
        let arc = Arc::new(Mutex::new(signer));
        signers.insert(session_id.to_string(), arc.clone());
        Ok(arc)
    }

    /// Stable lowercase name of the network — matches the wallet's
    /// `wraith env` output and the protocol crate's `as_str()` helpers.
    pub fn network_name(&self) -> &'static str {
        match self.network {
            Network::Bitcoin => "mainnet",
            Network::Testnet => "testnet",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
            _ => "unknown",
        }
    }

    /// All tiers this coordinator advertises support for. v1 supports
    /// every tier in the protocol; future iterations may filter (e.g.
    /// "this coordinator pool only handles ≥1m_sats").
    pub fn supported_tiers(&self) -> Vec<LiteTier> {
        LiteTier::all().to_vec()
    }

    /// Convenience — `now` from the configured clock.
    pub fn now(&self) -> u64 {
        self.clock.unix_secs()
    }

    /// Convenience — `now` minus `started_at`, saturating at 0. Used by
    /// `/health`. Started_at is captured against the same clock, so this
    /// is correct under MockClock too.
    pub fn uptime_secs(&self) -> u64 {
        self.now().saturating_sub(self.started_at)
    }
}

/// Stable wall-clock at module load — kept around for the rare case where
/// a test wants the real wall-clock baseline. Production code uses the
/// per-state `started_at` field instead.
pub fn process_start_unix() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

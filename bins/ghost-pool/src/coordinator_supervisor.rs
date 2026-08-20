//! In-process Wraith coordinator activation — Inc 4 of
//! `tasks/plan_coordinator_activation.md`.
//!
//! When this node is elected a coordinator seat (per the deterministic
//! [`crate::coordinator_election`] view), it must actually RUN the coordinator
//! so wallets can mix with it. The `wraith-coordinator` crate is a library
//! (`build_router` + `CoordinatorState`), so we run it in-process on a spawned
//! axum task rather than managing a subprocess.
//!
//! Lifecycle is reconciled against the election each epoch flip:
//! - elected & not running → build state (ghostd broadcaster + UTXO source)
//!   and serve on the coordinator port;
//! - not elected & running → graceful shutdown (a lost seat next epoch).
//!
//! ## Gating + secure-by-default
//! Activation is OFF unless `coordinator_role_enabled`. Anti-DoS no longer
//! needs a configured backend: registration proves control of the input UTXO
//! and a coin that kills a round goes into cooldown (#699). What it does need
//! is a UTXO source, and that comes from the same ghostd RPC the broadcaster
//! uses — so a coordinator that can broadcast can always verify inputs too.

use std::net::SocketAddr;
use std::sync::Arc;

use bitcoin::Network;
use parking_lot::Mutex;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use ghost_consensus::mesh::MeshNetwork;
use wraith_coordinator::broadcaster::{Broadcaster, GhostdBroadcaster};
use wraith_coordinator::rpc::RpcClient;
use wraith_coordinator::utxo_source::{GhostdUtxoSource, UtxoSource};
use wraith_coordinator::{build_router, CoordinatorState};
use wraith_protocol::{RandomSessionIdGenerator, SystemClock};

/// Everything the supervisor needs to construct + run a coordinator. Built from
/// `[coordinator]` + `[bitcoin]` config.
pub struct CoordinatorRoleConfig {
    /// Run the coordinator when elected (`coordinator_role_enabled`).
    pub enabled: bool,
    pub network: Network,
    /// Address the embedded coordinator binds (`0.0.0.0:coordinator_port`).
    pub listen: SocketAddr,
    pub fee_address: Option<String>,
    /// ghostd RPC the broadcaster pushes merged round txs to (reused from
    /// `[bitcoin]`).
    pub ghostd_rpc_url: String,
    pub ghostd_rpc_user: String,
    pub ghostd_rpc_password: String,
}

/// The secure-by-default refusal reason for activating a coordinator, if any.
/// Pure so it is unit-testable without a live mesh.
///
/// A mainnet coordinator must be able to check an input against the chain —
/// without that, registration takes the participant's word for what its own
/// input is, and the ownership proof underneath means nothing (#699). The
/// check is the ghostd RPC the broadcaster already needs, so the refusal is
/// about that being configured at all.
fn mainnet_activation_refusal(cfg: &CoordinatorRoleConfig) -> Option<String> {
    if cfg.enabled && cfg.network == Network::Bitcoin && cfg.ghostd_rpc_url.trim().is_empty() {
        return Some(
            "MAINNET REFUSAL: [coordinator] coordinator_role_enabled requires a ghostd RPC URL \
             so the coordinator can verify participant inputs against the chain; without one \
             every registration is taken on trust"
                .to_string(),
        );
    }
    None
}

/// A live coordinator instance: the serving task + its graceful-shutdown signal
/// + the shared state we read the session count from.
struct Running {
    shutdown: Arc<Notify>,
    handle: JoinHandle<()>,
    state: Arc<CoordinatorState>,
}

/// Starts/stops the in-process coordinator to track the election.
pub struct CoordinatorSupervisor {
    cfg: CoordinatorRoleConfig,
    mesh: Arc<MeshNetwork>,
    running: Mutex<Option<Running>>,
}

impl CoordinatorSupervisor {
    /// Construct the supervisor, or `None` when role activation is disabled.
    /// Returns `Err` if activation is requested on mainnet without a real bond
    /// ledger (secure-by-default refusal).
    pub fn maybe_new(
        cfg: CoordinatorRoleConfig,
        mesh: Arc<MeshNetwork>,
    ) -> Result<Option<Arc<Self>>, String> {
        if !cfg.enabled {
            return Ok(None);
        }
        if let Some(reason) = mainnet_activation_refusal(&cfg) {
            return Err(reason);
        }
        Ok(Some(Arc::new(Self {
            cfg,
            mesh,
            running: Mutex::new(None),
        })))
    }

    /// Reconcile the running coordinator against the election: start when newly
    /// elected, stop when the seat is lost, and refresh the advertised session
    /// count while running. No-op when role activation is disabled.
    pub async fn reconcile(&self, am_i_coordinator: bool) {
        if !self.cfg.enabled {
            return;
        }
        let is_running = self.running.lock().is_some();
        match (am_i_coordinator, is_running) {
            (true, false) => self.start().await,
            (false, true) => self.stop(),
            _ => {}
        }
        // While serving, publish the live session count so the mesh can size
        // seats by demand (the source for `seats_for_demand`).
        if let Some(r) = self.running.lock().as_ref() {
            self.mesh
                .set_coordinator_sessions(r.state.sessions.len() as u32);
        }
    }

    async fn start(&self) {
        // One RPC client, two jobs: broadcasting merged rounds and reading
        // the UTXO set so registration can verify an input rather than
        // believe it (#699).
        let rpc = RpcClient::new(
            self.cfg.ghostd_rpc_url.clone(),
            &self.cfg.ghostd_rpc_user,
            &self.cfg.ghostd_rpc_password,
        );
        let utxo_source: Arc<dyn UtxoSource> = Arc::new(GhostdUtxoSource::new(rpc.clone()));

        let broadcaster: Option<Arc<dyn Broadcaster>> =
            Some(Arc::new(GhostdBroadcaster::from_rpc(rpc)));

        let state = Arc::new(
            CoordinatorState::with_components(
                self.cfg.network,
                Arc::new(SystemClock),
                Arc::new(RandomSessionIdGenerator),
                self.cfg.fee_address.clone(),
                broadcaster,
            )
            .with_utxo_source(utxo_source),
        );

        let listener = match tokio::net::TcpListener::bind(self.cfg.listen).await {
            Ok(l) => l,
            Err(e) => {
                error!(addr = %self.cfg.listen, error = %e, "coordinator: bind failed; not activating");
                return;
            }
        };

        let app = build_router(Arc::clone(&state));
        let shutdown = Arc::new(Notify::new());
        let shutdown_for_task = Arc::clone(&shutdown);
        let handle = tokio::spawn(async move {
            let served = axum::serve(listener, app)
                .with_graceful_shutdown(async move { shutdown_for_task.notified().await })
                .await;
            if let Err(e) = served {
                warn!(error = %e, "coordinator: server exited with error");
            }
        });

        info!(addr = %self.cfg.listen, "coordinator: ELECTED — activated in-process");
        *self.running.lock() = Some(Running {
            shutdown,
            handle,
            state,
        });
    }

    fn stop(&self) {
        if let Some(r) = self.running.lock().take() {
            // Signal graceful shutdown; abort as a backstop so a stuck server
            // can't keep the seat's port held into the next epoch.
            r.shutdown.notify_waiters();
            r.handle.abort();
            info!("coordinator: seat lost — stopped");
        }
        // No longer coordinating → stop contributing to mesh demand.
        self.mesh.set_coordinator_sessions(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(enabled: bool, network: Network, ghostd_rpc_url: &str) -> CoordinatorRoleConfig {
        CoordinatorRoleConfig {
            enabled,
            network,
            listen: "0.0.0.0:9100".parse().unwrap(),
            fee_address: None,
            ghostd_rpc_url: ghostd_rpc_url.to_string(),
            ghostd_rpc_user: "u".to_string(),
            ghostd_rpc_password: "p".to_string(),
        }
    }

    /// The mainnet gate moved with the bonds (#699). It used to demand a
    /// ghost-pay bond ledger; a coordinator's non-optional dependency is now
    /// a node it can check participants' inputs against, because without one
    /// registration would take every input on trust.
    #[test]
    fn mainnet_without_a_node_is_refused_only_when_activating() {
        // Refused: activating on mainnet with no ghostd RPC.
        assert!(mainnet_activation_refusal(&cfg(true, Network::Bitcoin, "")).is_some());
        // Allowed: mainnet WITH one.
        assert!(
            mainnet_activation_refusal(&cfg(true, Network::Bitcoin, "http://127.0.0.1:8332"))
                .is_none()
        );
        // Allowed: not activating (disabled) — the gate doesn't apply.
        assert!(mainnet_activation_refusal(&cfg(false, Network::Bitcoin, "")).is_none());
        // Allowed: test nets may run without one.
        assert!(mainnet_activation_refusal(&cfg(true, Network::Signet, "")).is_none());
        assert!(mainnet_activation_refusal(&cfg(true, Network::Regtest, "")).is_none());
    }
}

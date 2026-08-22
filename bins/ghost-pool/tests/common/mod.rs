//! Shared regtest wiring for the integration tests.
//!
//! ## Why this exists
//!
//! Five test files each hardcoded their own RPC credentials — three used `ghosttest:ghosttest`
//! and two used `rt:rt` — and **neither pair matches the shipped `docker/docker-compose.yml`**,
//! which takes `BITCOIN_RPC_USER` / `BITCOIN_RPC_PASSWORD` from the environment.
//!
//! The consequence was not a loud failure. Every one of those tests opens with
//!
//! ```ignore
//! let Some(rpc) = regtest_rpc() else { eprintln!("SKIP: no regtest ghostd"); return; };
//! ```
//!
//! so a credential mismatch is indistinguishable from an absent node, and the test **passes by
//! not running**. Measured 2026-08-22: a healthy regtest node was up at 484 blocks and
//! `payout_ledger_e2e` — 928 lines, four tests, including the only end-to-end proof that a mined
//! block pays the miners it should — still skipped, because it was asking for a user that does
//! not exist anywhere in the repo.
//!
//! CI runs these targets (`cargo test --tests`, ci.yml) but has no regtest node, so they skip
//! there too. The coverage existed as code and never as coverage.
//!
//! ## The contract
//!
//! Credentials come from the environment with the compose defaults, so the tests work against the
//! standard `docker-compose.yml` with no arguments.
//!
//! ⛔ **Set `GHOST_REGTEST_REQUIRED=1` to make a missing node a FAILURE rather than a skip.** CI
//! and any run that intends to exercise these paths should set it. Without it a silent skip is
//! back, and this whole class of bug returns.

#![allow(dead_code)]

use std::sync::Arc;

use ghost_common::rpc::BitcoinRpc;

/// Host, port, user and password for the regtest node, from the environment.
///
/// Defaults match `docker/docker-compose.yml`, so the shipped cluster needs no configuration.
fn regtest_params() -> (String, u16, String, String) {
    let host = std::env::var("GHOST_REGTEST_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = std::env::var("GHOST_REGTEST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(18443u16);
    let user = std::env::var("BITCOIN_RPC_USER")
        .or_else(|_| std::env::var("GHOST_REGTEST_RPC_USER"))
        .unwrap_or_else(|_| "ghost".to_string());
    let pass = std::env::var("BITCOIN_RPC_PASSWORD")
        .or_else(|_| std::env::var("GHOST_REGTEST_RPC_PASSWORD"))
        .unwrap_or_else(|_| "ghostpass".to_string());
    (host, port, user, pass)
}

/// An RPC client for the regtest node, or `None` if it is not reachable.
///
/// ⚠ Prefer [`require_regtest`] in any test that is supposed to prove something. This returns
/// `None` for BOTH "no node" and "wrong credentials", which is exactly the ambiguity that let
/// five test files rot.
pub fn regtest_rpc() -> Option<Arc<BitcoinRpc>> {
    let (host, port, user, pass) = regtest_params();
    BitcoinRpc::new(&host, port, &user, &pass)
        .ok()
        .map(Arc::new)
}

/// The same client, un-wrapped, for callers that must configure it before use.
///
/// `empty_template_e2e` needs `set_network(Regtest)` — the checked `get_block_template`
/// validates the target against the client's network, and regtest's trivial target reads as
/// "too easy" under the mainnet limit.
pub fn regtest_rpc_raw() -> Option<BitcoinRpc> {
    let (host, port, user, pass) = regtest_params();
    BitcoinRpc::new(&host, port, &user, &pass).ok()
}

/// For tests that require an EXPLICIT `GHOST_REGTEST_RPC=host:port` opt-in.
///
/// `regtest_settlement_rehearsal` and `regtest_shard_settlement` are driven against a chain the
/// caller has prepared (they also need `GHOST_REGTEST_TAGGED_HEIGHT`), so they should not pick up
/// an incidental node from the defaults. The opt-in is kept; only the credentials are shared.
pub fn regtest_rpc_explicit() -> Option<Arc<BitcoinRpc>> {
    let hostport = std::env::var("GHOST_REGTEST_RPC").ok()?;
    let (host, port) = hostport.split_once(':')?;
    let (_, _, user, pass) = regtest_params();
    Some(Arc::new(
        BitcoinRpc::new(host, port.parse().ok()?, &user, &pass).expect("rpc"),
    ))
}

/// An RPC client, or a decision about what a missing node means.
///
/// Returns `None` only when regtest is genuinely absent AND `GHOST_REGTEST_REQUIRED` is unset.
/// When it is set, an unreachable node **panics** with what was tried — so a run that intended to
/// exercise these paths cannot report success without having done so.
///
/// The panic names the host, port and user deliberately: the failure this replaces was a
/// credential mismatch that read as an absent node for months.
pub async fn require_regtest() -> Option<Arc<BitcoinRpc>> {
    let (host, port, user, _) = regtest_params();
    let required = std::env::var("GHOST_REGTEST_REQUIRED").is_ok();

    let rpc = regtest_rpc();
    let reachable = match &rpc {
        Some(r) => r.get_block_count().await.is_ok(),
        None => false,
    };

    if reachable {
        return rpc;
    }
    assert!(
        !required,
        "GHOST_REGTEST_REQUIRED is set but regtest is not reachable at {user}@{host}:{port} — \
         start it (docker start rc-bitcoind) or unset the variable. This is a FAILURE rather \
         than a skip on purpose: a silent skip is why these tests went unrun."
    );
    eprintln!(
        "SKIP: regtest not reachable at {user}@{host}:{port} \
         (set GHOST_REGTEST_REQUIRED=1 to make this a failure)"
    );
    None
}

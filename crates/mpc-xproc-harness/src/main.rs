//! `mpc-xnode` — one real MPC ceremony node, driven as a separate OS process.
//!
//! The cross-process Stage-D harness (`tests/xproc.rs`) spawns several of these
//! and wires them together over real HTTP + a stdin/stdout JSON control channel
//! to prove the resumed rolling-ceremony CONTRIBUTION flow works across genuine
//! process boundaries — the gate before the mainnet un-pin
//! (`tasks/plan_mpc_rolling_resume.md`).
//!
//! Each node holds a real long-lived [`ghost_mpc::CeremonyManager`] over its own
//! params dir (exactly like the mainnet `ghost-pool` process), and:
//!   * (contributor) generates a real phase-2 candidate, writes it to the
//!     SEPARATE serving file `note_spend_params_candidate_<hash>.bin` (NEVER the
//!     active `note_spend_params_current.bin`), and serves it via the EXACT
//!     production handler `ghost_verification::api_mpc_params_handler` at
//!     `GET /api/v1/mpc/params?new_hash=<hex>`;
//!   * (voter) FETCHES a peer's candidate by hash over real HTTP, parses it with
//!     the same `ghost_mpc::params::read_parameters_from_bytes` the mainnet fetch
//!     uses, and runs the real `verify_contribution` (Schnorr + h/l pairing);
//!   * (all) applies an approved contribution through the sole legitimate writer
//!     of `current.bin`, `apply_contribution_multi`.
//!
//! STARTUP GENESIS-ANCHORED GUARD (the node5 crash-loop reproduction): when
//! `--expected-head` is supplied, the node hashes its on-disk
//! `note_spend_params_current.bin` and, if it does not equal the expected BFT
//! chain head, prints `FATAL ...` and exits non-zero — the exact fail-closed
//! behaviour that crash-looped node5 when an un-applied candidate had been
//! written over current.bin. With the fix, a contributor that has only GENERATED
//! (not applied) leaves current.bin at the head, so this guard passes.
//!
//! Control protocol: one JSON object per stdin line -> one JSON object per stdout
//! line (prefixed `RESP `). Human/diagnostic lines are prefixed `EVENT `.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ghost_mpc::contribution::hash_parameters;
use ghost_mpc::params::{load_parameters, read_parameters_from_bytes};
use ghost_mpc::{CeremonyManager, CeremonyState, Groth16Params, MpcError};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, BufReader};

/// Parse `--flag value` pairs and bare `--flag` switches from argv.
struct Args {
    map: HashMap<String, String>,
    switches: Vec<String>,
}
impl Args {
    fn parse(argv: &[String]) -> Self {
        let mut map = HashMap::new();
        let mut switches = Vec::new();
        let mut i = 0;
        while i < argv.len() {
            let a = &argv[i];
            if let Some(key) = a.strip_prefix("--") {
                if i + 1 < argv.len() && !argv[i + 1].starts_with("--") {
                    map.insert(key.to_string(), argv[i + 1].clone());
                    i += 2;
                } else {
                    switches.push(key.to_string());
                    i += 1;
                }
            } else {
                i += 1;
            }
        }
        Self { map, switches }
    }
    fn get(&self, k: &str) -> Option<&str> {
        self.map.get(k).map(|s| s.as_str())
    }
    fn has(&self, k: &str) -> bool {
        self.switches.iter().any(|s| s == k)
    }
}

fn hex32(s: &str) -> [u8; 32] {
    let b = hex::decode(s).expect("hex");
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    a
}

/// Lineage hash of the on-disk active head (`note_spend_params_current.bin`).
fn current_bin_lineage_hash(params_dir: &Path) -> Option<String> {
    let p = params_dir.join("note_spend_params_current.bin");
    let params = load_parameters(&p).ok()?;
    Some(hex::encode(hash_parameters(&params).ok()?))
}

fn emit_event(msg: &str) {
    println!("EVENT {msg}");
    let _ = std::io::stdout().flush();
}
fn emit_resp(v: &Value) {
    println!("RESP {v}");
    let _ = std::io::stdout().flush();
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mode = argv.first().cloned().unwrap_or_default();
    match mode.as_str() {
        "node" => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(run_node(&argv[1..]));
        }
        other => {
            eprintln!("unknown mode: {other:?}; expected `node`");
            std::process::exit(64);
        }
    }
}

async fn run_node(argv: &[String]) {
    let args = Args::parse(argv);
    let home = PathBuf::from(args.get("home").expect("--home"));
    let params_dir = home.join(".ghost/mpc_params");
    let head = hex32(args.get("head").expect("--head"));
    let ceremony_id = hex32(args.get("ceremony-id").expect("--ceremony-id"));
    let count: u32 = args.get("count").unwrap_or("0").parse().unwrap();
    let ossified = args.has("ossified");
    let node_id = args.get("node-id").unwrap_or("xnode").to_string();

    // Rebuild the manager exactly as ghost-pool does at startup: state from the
    // (simulated) DB singleton, params loaded from disk.
    let state = CeremonyState {
        contribution_count: count,
        current_params_hash: head,
        is_ossified: ossified,
        ceremony_id,
        ..Default::default()
    };
    let manager =
        CeremonyManager::load_or_init(params_dir.clone(), Some(state)).expect("load_or_init");
    // Force the on-disk current params into memory even at count 0 (a genesis
    // holder must be able to generate/verify against them).
    manager.load_current_params().expect("load_current_params");

    // ---- STARTUP GENESIS-ANCHORED CROSS-CHECK (node5 crash-loop guard) -------
    if let Some(expected) = args.get("expected-head") {
        if expected != "none" {
            match current_bin_lineage_hash(&params_dir) {
                Some(got) if got == expected => {
                    emit_event(&format!(
                        "startup-guard OK current.bin={}… == chain-head",
                        &got[..16]
                    ));
                }
                got => {
                    // EXACTLY the node5 failure: on-disk head != BFT chain head.
                    eprintln!(
                        "FATAL genesis-anchored cross-check: current.bin={:?} != expected head {}…",
                        got.as_deref().map(|g| &g[..g.len().min(16)]),
                        &expected[..16]
                    );
                    std::process::exit(2);
                }
            }
        }
    }

    let manager = Arc::new(manager);

    // ---- Optional REAL params-serving HTTP endpoint --------------------------
    if let Some(port) = args.get("http-port") {
        let port: u16 = port.parse().unwrap();
        // The production handler reads $HOME/.ghost/mpc_params; the parent spawns
        // us with HOME=<home> so it serves THIS node's params dir.
        std::env::set_var("HOME", &home);
        spawn_params_server(port, node_id.clone()).await;
        emit_event(&format!("serving :{port} /api/v1/mpc/params"));
    }

    // Announce readiness AFTER the guard + server bind so the parent can rely on
    // it as a synchronisation point.
    emit_resp(&json!({
        "ready": true,
        "node_id": node_id,
        "count": manager.contribution_count(),
        "head": hex::encode(manager.current_params_hash()),
        "current_bin_hash": current_bin_lineage_hash(&params_dir),
        "ossified": manager.is_ossified(),
    }));

    // In-memory cache of candidate params this node holds (generated OR fetched),
    // keyed by lineage hash — the params it will apply on BFT approval.
    let mut params_cache: HashMap<String, Groth16Params> = HashMap::new();

    let stdin = tokio::io::stdin();
    let mut lines = BufReader::new(stdin).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let cmd: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                emit_resp(&json!({"error": format!("bad json: {e}")}));
                continue;
            }
        };
        let c = cmd.get("cmd").and_then(|v| v.as_str()).unwrap_or("");
        match c {
            "inspect" => {
                emit_resp(&json!({
                    "count": manager.contribution_count(),
                    "mgr_head": hex::encode(manager.current_params_hash()),
                    "current_bin_hash": current_bin_lineage_hash(&params_dir),
                    "ossified": manager.is_ossified(),
                }));
            }
            "gen_candidate" => {
                let contributor = cmd
                    .get("contributor_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&node_id)
                    .to_string();
                match manager.generate_contribution(&contributor) {
                    Ok((params, contrib)) => {
                        let new_hash = hex::encode(contrib.new_params_hash);
                        // Serialize + write to the SEPARATE candidate serving file
                        // (mirrors ghost-pool::write_candidate_note_spend_params;
                        // NEVER touches current.bin).
                        let mut buf = Vec::new();
                        params.write(&mut buf).expect("serialize candidate");
                        write_candidate(&params_dir, &contrib.new_params_hash, &buf);
                        params_cache.insert(new_hash.clone(), params);
                        emit_resp(&json!({
                            "ok": true,
                            "position": contrib.position,
                            "prev_hash": hex::encode(contrib.prev_params_hash),
                            "new_hash": new_hash,
                            // current.bin MUST be unchanged by generation.
                            "current_bin_hash": current_bin_lineage_hash(&params_dir),
                            "mgr_head": hex::encode(manager.current_params_hash()),
                            "contribution": serde_json::to_string(&contrib).unwrap(),
                        }));
                    }
                    Err(e) => emit_resp(&json!({"ok": false, "err": err_kind(&e)})),
                }
            }
            "fetch_verify" => {
                let url = cmd.get("url").and_then(|v| v.as_str()).unwrap().to_string();
                let new_hash = cmd
                    .get("new_hash")
                    .and_then(|v| v.as_str())
                    .unwrap()
                    .to_string();
                let contribution_json = cmd
                    .get("contribution")
                    .and_then(|v| v.as_str())
                    .unwrap()
                    .to_string();
                let resp = do_fetch_verify(&manager, &url, &new_hash, &contribution_json).await;
                if let Some(p) = resp.1 {
                    params_cache.insert(new_hash.clone(), p);
                }
                emit_resp(&resp.0);
            }
            "apply" => {
                let new_hash = cmd
                    .get("new_hash")
                    .and_then(|v| v.as_str())
                    .unwrap()
                    .to_string();
                let contribution_json = cmd
                    .get("contribution")
                    .and_then(|v| v.as_str())
                    .unwrap()
                    .to_string();
                let contrib: ghost_mpc::contribution::MpcContribution =
                    serde_json::from_str(&contribution_json).unwrap();
                match params_cache.remove(&new_hash) {
                    Some(params) => {
                        match manager.apply_contribution_multi(params, None, None, &contrib) {
                            Ok(()) => emit_resp(&json!({
                                "ok": true,
                                "count": manager.contribution_count(),
                                "mgr_head": hex::encode(manager.current_params_hash()),
                                "current_bin_hash": current_bin_lineage_hash(&params_dir),
                                "ossified": manager.is_ossified(),
                            })),
                            Err(e) => emit_resp(&json!({"ok": false, "err": err_kind(&e)})),
                        }
                    }
                    None => emit_resp(&json!({
                        "ok": false,
                        "err": "no cached params for new_hash (node never fetched/generated it)"
                    })),
                }
            }
            // Bare fetch (optionally by hash) with NO verify — used by a fresh
            // post-ossification node to fetch the final params and confirm their
            // lineage hash, since `verify_contribution` refuses once ossified.
            "fetch_head" => {
                let url = cmd.get("url").and_then(|v| v.as_str()).unwrap().to_string();
                let new_hash = cmd
                    .get("new_hash")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let full = match &new_hash {
                    Some(h) => format!("{url}?new_hash={h}"),
                    None => url,
                };
                match reqwest::Client::new()
                    .get(&full)
                    .timeout(std::time::Duration::from_secs(60))
                    .send()
                    .await
                {
                    Ok(r) if r.status().is_success() => {
                        let data = r.bytes().await.unwrap_or_default();
                        match read_parameters_from_bytes(&data) {
                            Ok(p) => emit_resp(&json!({
                                "ok": true,
                                "fetched_hash": hex::encode(hash_parameters(&p).unwrap()),
                                "size": data.len(),
                            })),
                            Err(e) => {
                                emit_resp(&json!({"ok": false, "err": format!("parse: {e}")}))
                            }
                        }
                    }
                    Ok(r) => {
                        emit_resp(&json!({"ok": false, "err": format!("status {}", r.status())}))
                    }
                    Err(e) => emit_resp(&json!({"ok": false, "err": format!("http: {e}")})),
                }
            }
            "try_generate" => {
                let contributor = cmd
                    .get("contributor_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("late-comer");
                match manager.generate_contribution(contributor) {
                    Ok((_p, cnt)) => emit_resp(&json!({"ok": true, "position": cnt.position})),
                    Err(e) => emit_resp(&json!({"ok": false, "err": err_kind(&e)})),
                }
            }
            // NEGATIVE CONTROL: reproduce the OLD Bug-1 behaviour — write the
            // un-applied candidate OVER the active current.bin. A subsequent
            // restart must then crash-loop (startup guard fails), proving the
            // guard has teeth and that the fixed path (separate file) avoids it.
            "simulate_old_bug_overwrite_current" => {
                let new_hash = cmd
                    .get("new_hash")
                    .and_then(|v| v.as_str())
                    .unwrap()
                    .to_string();
                match params_cache.get(&new_hash) {
                    Some(params) => {
                        let mut buf = Vec::new();
                        params.write(&mut buf).unwrap();
                        let current = params_dir.join("note_spend_params_current.bin");
                        std::fs::write(&current, &buf).unwrap();
                        emit_resp(&json!({
                            "ok": true,
                            "current_bin_hash": current_bin_lineage_hash(&params_dir),
                        }));
                    }
                    None => emit_resp(&json!({"ok": false, "err": "no cached params"})),
                }
            }
            "shutdown" => {
                emit_resp(&json!({"ok": true, "bye": true}));
                std::process::exit(0);
            }
            other => emit_resp(&json!({"error": format!("unknown cmd {other:?}")})),
        }
    }
}

/// Mirror of `ghost-pool::write_candidate_note_spend_params`: write the candidate
/// to its own hash-keyed serving file and purge superseded ones. NEVER current.bin.
fn write_candidate(params_dir: &Path, new_params_hash: &[u8; 32], serialized: &[u8]) {
    std::fs::create_dir_all(params_dir).unwrap();
    let keep = ghost_common::mpc::candidate_note_spend_filename(new_params_hash);
    if let Ok(entries) = std::fs::read_dir(params_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(ghost_common::mpc::CANDIDATE_NOTE_SPEND_PREFIX)
                && name.ends_with(".bin")
                && name != keep
            {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    std::fs::write(params_dir.join(&keep), serialized).unwrap();
}

/// Fetch a candidate by hash over real HTTP and run the real cryptographic
/// verify. Mirrors `ghost-pool::fetch_and_parse_params` (the `?new_hash=` URL
/// shape + `read_parameters_from_bytes` + hash check) then `verify_contribution`.
async fn do_fetch_verify(
    manager: &CeremonyManager,
    base_url: &str,
    new_hash: &str,
    contribution_json: &str,
) -> (Value, Option<Groth16Params>) {
    let url = format!("{base_url}?new_hash={new_hash}");
    let resp = match reqwest::Client::new()
        .get(&url)
        .timeout(std::time::Duration::from_secs(60))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return (
                json!({"verify_ok": false, "err": format!("http: {e}")}),
                None,
            )
        }
    };
    if !resp.status().is_success() {
        return (
            json!({"verify_ok": false, "err": format!("status {}", resp.status())}),
            None,
        );
    }
    let data = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            return (
                json!({"verify_ok": false, "err": format!("body: {e}")}),
                None,
            )
        }
    };
    if data.len() <= 1000 {
        return (json!({"verify_ok": false, "err": "params too small"}), None);
    }
    let params = match read_parameters_from_bytes(&data) {
        Ok(p) => p,
        Err(e) => {
            return (
                json!({"verify_ok": false, "err": format!("parse: {e}")}),
                None,
            )
        }
    };
    let fetched_hash = match hash_parameters(&params) {
        Ok(h) => hex::encode(h),
        Err(e) => {
            return (
                json!({"verify_ok": false, "err": format!("hash: {e}")}),
                None,
            )
        }
    };
    let contrib: ghost_mpc::contribution::MpcContribution =
        match serde_json::from_str(contribution_json) {
            Ok(c) => c,
            Err(e) => {
                return (
                    json!({"verify_ok": false, "err": format!("contrib json: {e}")}),
                    None,
                )
            }
        };
    let verify_ok = matches!(manager.verify_contribution(&params, &contrib), Ok(true));
    (
        json!({
            "verify_ok": verify_ok,
            "fetched_hash": fetched_hash,
            "size": data.len(),
            "served_by_hash": fetched_hash == new_hash,
        }),
        Some(params),
    )
}

/// Stand up the REAL production params-serving handler on `127.0.0.1:port`.
async fn spawn_params_server(port: u16, node_id: String) {
    use ghost_common::types::NodeCapabilities;
    use ghost_policy::PolicyProfile;
    use ghost_verification::{api_mpc_params_handler, VerificationState};

    let state = Arc::new(VerificationState::new(
        node_id,
        "xproc".to_string(),
        PolicyProfile::default(),
        NodeCapabilities::default(),
    ));
    // Mount ONLY the real params handler — same code path the mainnet node
    // serves `/api/v1/mpc/params?new_hash=` through, minus unrelated middleware.
    let app = axum::Router::new()
        .route(
            "/api/v1/mpc/params",
            axum::routing::get(api_mpc_params_handler),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("bind params server");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
}

fn err_kind(e: &MpcError) -> String {
    match e {
        MpcError::CeremonyOssified(_) => "CeremonyOssified".to_string(),
        MpcError::InvalidPosition(a, b) => format!("InvalidPosition({a},{b})"),
        MpcError::InvalidProof(_) => "InvalidProof".to_string(),
        other => format!("{other:?}"),
    }
}

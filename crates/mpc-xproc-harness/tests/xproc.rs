//! Cross-PROCESS MPC rolling-ceremony contribution harness (Stage D / Stage 5).
//!
//! This is the GATE before the mainnet un-pin (`tasks/plan_mpc_rolling_resume.md`).
//! It proves the resumed CONTRIBUTION flow works across genuine, separate OS
//! processes with real mesh-style HTTP fetching — the exact path the node5
//! mainnet attempt broke on. The in-process `ghost-mpc` harness
//! (`tests/mpc_lifecycle.rs`) already proves the crypto + DB lineage at node
//! level; THIS harness adds the real process boundary the fix is about.
//!
//! Topology: one shared genesis (generated once, like fleet node 1) distributed
//! to a fixed committee of `COMMITTEE` real `mpc-xnode` processes on localhost.
//! Node C is the contributor + params HTTP server; V1..V3 are voters that FETCH
//! C's candidate by hash over real HTTP and verify it with real crypto.
//!
//! # Run
//! ```text
//! cargo test -p mpc-xproc-harness --release --features mpc-test-cap \
//!     --test xproc -- --nocapture --test-threads=1
//! ```
//! (`--release` because it drives real Groth16 phase-2 transforms to the cap;
//!  `mpc-test-cap` shrinks the cap 101 -> 4 so it finishes in a few minutes.)
//!
//! # The five gates (each a mainnet-canary precondition)
//! 1. genesis inits (count 0); a SEPARATE process generates a candidate and
//!    SERVES it at `?new_hash=<hash>` while its OWN current.bin is UNCHANGED.
//! 2. a voter PROCESS fetches the candidate by hash, runs real
//!    `verify_contribution`, and approves; a >= threshold quorum forms.
//! 3. on threshold the contribution APPLIES; every node's current.bin converges
//!    to the candidate — and NOT before apply.
//! 4. Bug-1 cross-process: the contributor's current.bin never equals the
//!    un-applied candidate, and a mid-ceremony RESTART does not crash-loop
//!    (plus a negative control: the OLD overwrite-current behaviour DOES).
//! 5. drive to the cap -> ossify; a fresh node fetches+confirms the final params
//!    and CANNOT contribute.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};

use ghost_mpc::{CeremonyManager, Groth16Params, MAX_CEREMONY_CONTRIBUTORS};
use serde_json::{json, Value};

const COMMITTEE: usize = 4; // C + V1 + V2 + V3 -> BFT threshold ceil(4*0.67)=3
const BASE_PORT: u16 = 8563; // Noise-mesh-adjacent; the fix opened 8563/8443.

// ---------------------------------------------------------------------------
// Genesis (one shared set, like fleet node 1 generating and peers fetching).
// ---------------------------------------------------------------------------
fn generate_genesis_params() -> (Groth16Params, Groth16Params, Groth16Params) {
    use bellperson::groth16::generate_random_parameters;
    use blstrs::{Bls12, Scalar as Fr};
    use ghost_zkp::circuit::{GhostNoteSpendCircuit, GhostUnshieldCircuit, NoteConsolidateCircuit};
    use rand::rngs::OsRng;

    let note = generate_random_parameters::<Bls12, _, _>(
        GhostNoteSpendCircuit::<Fr>::dummy(20),
        &mut OsRng,
    )
    .expect("genesis note-spend");
    let consolidate = generate_random_parameters::<Bls12, _, _>(
        NoteConsolidateCircuit::<Fr>::dummy(20),
        &mut OsRng,
    )
    .expect("genesis consolidate");
    let unshield = generate_random_parameters::<Bls12, _, _>(
        GhostUnshieldCircuit::<Fr>::dummy(20),
        &mut OsRng,
    )
    .expect("genesis unshield");
    (note, consolidate, unshield)
}

fn copy_dir_files(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap().flatten() {
        let p = entry.path();
        if p.is_file() {
            std::fs::copy(&p, dst.join(entry.file_name())).unwrap();
        }
    }
}

// ---------------------------------------------------------------------------
// One spawned node process, driven over its stdin/stdout JSON control channel.
// ---------------------------------------------------------------------------
struct Node {
    name: String,
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
    port: Option<u16>,
}

impl Node {
    /// Read stdout until the next `RESP <json>` line, echoing `EVENT` lines.
    /// Returns `None` if the process closed stdout (e.g. exited) first.
    fn read_resp(&mut self) -> Option<Value> {
        loop {
            let mut line = String::new();
            match self.stdout.read_line(&mut line) {
                Ok(0) => return None, // EOF: process exited
                Ok(_) => {}
                Err(_) => return None,
            }
            let line = line.trim_end();
            if let Some(rest) = line.strip_prefix("RESP ") {
                return Some(serde_json::from_str(rest).expect("resp json"));
            } else if let Some(rest) = line.strip_prefix("EVENT ") {
                println!("[{}] {}", self.name, rest);
            } else if !line.is_empty() {
                println!("[{}] (raw) {}", self.name, line);
            }
        }
    }

    fn send(&mut self, v: Value) -> Value {
        writeln!(self.stdin, "{v}").unwrap();
        self.stdin.flush().unwrap();
        self.read_resp()
            .unwrap_or_else(|| panic!("[{}] process died awaiting response to {v}", self.name))
    }

    fn url(&self) -> String {
        format!(
            "http://127.0.0.1:{}/api/v1/mpc/params",
            self.port.expect("node has no http port")
        )
    }

    fn shutdown(&mut self) {
        let _ = writeln!(self.stdin, "{}", json!({"cmd": "shutdown"}));
        let _ = self.stdin.flush();
        let _ = self.child.wait();
    }
}

/// Spawn a node process and wait for the startup `RESP {ready:true}` handshake;
/// returns a fully-owned `Node`, or `None` if the process exited before
/// readiness (a fail-closed startup guard firing — the node5 crash-loop).
#[allow(clippy::too_many_arguments)]
fn start_node(
    name: &str,
    home: &Path,
    head_hex: &str,
    ceremony_id_hex: &str,
    count: u32,
    ossified: bool,
    http_port: Option<u16>,
    expected_head: Option<&str>,
) -> Option<Node> {
    let bin = env!("CARGO_BIN_EXE_mpc-xnode");
    let mut cmd = Command::new(bin);
    cmd.arg("node")
        .arg("--home")
        .arg(home)
        .arg("--head")
        .arg(head_hex)
        .arg("--ceremony-id")
        .arg(ceremony_id_hex)
        .arg("--count")
        .arg(count.to_string())
        .arg("--node-id")
        .arg(name)
        .env("HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if ossified {
        cmd.arg("--ossified");
    }
    if let Some(p) = http_port {
        cmd.arg("--http-port").arg(p.to_string());
    }
    if let Some(e) = expected_head {
        cmd.arg("--expected-head").arg(e);
    }
    let mut child = cmd.spawn().expect("spawn mpc-xnode");
    let stdin = child.stdin.take().unwrap();
    let stdout = BufReader::new(child.stdout.take().unwrap());
    let mut node = Node {
        name: name.to_string(),
        child,
        stdin,
        stdout,
        port: http_port,
    };
    match node.read_resp() {
        Some(ready) => {
            assert_eq!(
                ready["ready"],
                json!(true),
                "[{name}] first RESP must be ready"
            );
            Some(node)
        }
        None => {
            let _ = node.child.wait();
            None
        }
    }
}

#[test]
fn cross_process_contribution_flow() {
    let cap = MAX_CEREMONY_CONTRIBUTORS;
    assert!(
        cap <= 8,
        "run under --features mpc-test-cap (small cap); got {cap}. \
         Without it this would need 101 real phase-2 transforms."
    );
    let threshold = ghost_mpc::mpc_bft_threshold(COMMITTEE as u32);
    println!("== cross-process MPC ceremony: cap={cap}, committee={COMMITTEE}, BFT threshold={threshold} ==");

    // ---- Shared genesis (fleet node 1 generates; peers fetch the files) ------
    let seed_root = tempfile::tempdir().unwrap();
    let seed_params = seed_root.path().join(".ghost/mpc_params");
    let seed_mgr = CeremonyManager::new(seed_params.clone());
    let (g_note, g_consolidate, g_unshield) = generate_genesis_params();
    seed_mgr
        .initialize_genesis_multi(g_note, g_consolidate, g_unshield)
        .expect("genesis init");
    let anchor_bytes = seed_mgr.current_params_hash();
    let anchor = hex::encode(anchor_bytes);
    println!("genesis anchor (ceremony_id) = {}…", &anchor[..16]);
    assert_ne!(anchor_bytes, [0u8; 32]);

    // Distribute identical genesis to every committee node's params dir.
    let node_roots: Vec<tempfile::TempDir> = (0..COMMITTEE)
        .map(|_| tempfile::tempdir().unwrap())
        .collect();
    let homes: Vec<PathBuf> = node_roots.iter().map(|d| d.path().to_path_buf()).collect();
    for home in &homes {
        copy_dir_files(&seed_params, &home.join(".ghost/mpc_params"));
    }

    // ---- Spawn the committee: node 0 = contributor+server; 1..=voters --------
    // Every node starts pinned to the genesis anchor (expected-head = anchor).
    let names: Vec<String> = (0..COMMITTEE)
        .map(|i| {
            if i == 0 {
                "C".to_string()
            } else {
                format!("V{i}")
            }
        })
        .collect();
    let mut nodes: Vec<Node> = Vec::new();
    for i in 0..COMMITTEE {
        let port = if i == 0 { Some(BASE_PORT) } else { None };
        let n = start_node(
            &names[i],
            &homes[i],
            &anchor,
            &anchor,
            0,
            false,
            port,
            Some(&anchor),
        )
        .expect("committee node must start clean at genesis");
        nodes.push(n);
    }
    // GATE 1a: genesis initialised, count 0 on every node, current.bin == anchor.
    for n in nodes.iter_mut() {
        let s = n.send(json!({"cmd": "inspect"}));
        assert_eq!(s["count"], json!(0), "genesis count 0");
        assert_eq!(
            s["current_bin_hash"],
            json!(anchor),
            "on-disk head == anchor"
        );
        assert_eq!(s["ossified"], json!(false));
    }
    println!("GATE 1a PASS: {COMMITTEE} separate processes share genesis; count 0; current.bin == anchor");

    let contributor_url = nodes[0].url();
    let mut current_head = anchor.clone();
    let restart_at: u32 = 2.min(cap.max(1));

    for p in 1..=cap {
        println!("\n---- position {p} ----");

        // ---- (1) CONTRIBUTOR (separate process) generates + serves candidate --
        let mut gen =
            nodes[0].send(json!({"cmd": "gen_candidate", "contributor_id": format!("elder-{p}")}));
        assert_eq!(gen["ok"], json!(true), "gen_candidate ok");
        assert_eq!(gen["position"], json!(p), "sequential position");
        assert_eq!(
            gen["prev_hash"],
            json!(current_head),
            "prev chains from head"
        );
        let mut new_hash = gen["new_hash"].as_str().unwrap().to_string();
        let mut contribution = gen["contribution"].as_str().unwrap().to_string();
        assert_ne!(new_hash, current_head, "candidate hash strictly evolves");
        // GATE 1b: contributor's OWN current.bin is UNCHANGED by generation.
        assert_eq!(
            gen["current_bin_hash"],
            json!(current_head),
            "GATE 1: generating a candidate MUST NOT move the contributor's current.bin"
        );
        println!(
            "GATE 1 PASS: C generated pos {p} candidate {}… ; C.current.bin still {}… (un-applied)",
            &new_hash[..16],
            &current_head[..16]
        );

        // ---- (4) Bug-1 cross-process RESTART mid-ceremony (fixed path) --------
        if p == restart_at {
            println!("-- Bug-1: restarting contributor C mid-position (candidate generated, not applied) --");
            // Kill C hard (it has an un-applied candidate on disk).
            let _ = nodes[0].child.kill();
            let _ = nodes[0].child.wait();
            std::thread::sleep(std::time::Duration::from_millis(500));
            // Respawn pinned to the APPLIED head (current_head). With the fix,
            // current.bin is still the applied head, so the guard passes.
            let restarted = start_node(
                "C",
                &homes[0],
                &current_head,
                &anchor,
                p - 1,
                false,
                Some(BASE_PORT),
                Some(&current_head),
            )
            .expect(
                "GATE 4: contributor must NOT crash-loop on restart (current.bin == chain head)",
            );
            nodes[0] = restarted;
            let s = nodes[0].send(json!({"cmd": "inspect"}));
            assert_eq!(
                s["current_bin_hash"],
                json!(current_head),
                "GATE 4: after restart current.bin == applied chain head (never the candidate)"
            );
            println!(
                "GATE 4 PASS: C restarted cleanly; current.bin == chain head {}… (no crash-loop)",
                &current_head[..16]
            );
            // Regenerate the candidate on the fresh process (cache was lost).
            gen = nodes[0]
                .send(json!({"cmd": "gen_candidate", "contributor_id": format!("elder-{p}")}));
            assert_eq!(gen["ok"], json!(true));
            new_hash = gen["new_hash"].as_str().unwrap().to_string();
            contribution = gen["contribution"].as_str().unwrap().to_string();
            assert_eq!(
                gen["current_bin_hash"],
                json!(current_head),
                "still un-applied after regen"
            );
        }

        // ---- (2) VOTERS (separate processes) FETCH by hash + real verify ------
        let mut approvals = 0u32;
        for v in 1..COMMITTEE {
            let r = nodes[v].send(json!({
                "cmd": "fetch_verify",
                "url": contributor_url,
                "new_hash": new_hash,
                "contribution": contribution,
            }));
            assert_eq!(
                r["served_by_hash"],
                json!(true),
                "voter must receive the candidate served via ?new_hash= (hash matches)"
            );
            assert_eq!(
                r["fetched_hash"],
                json!(new_hash),
                "fetched params hash == candidate"
            );
            assert_eq!(
                r["verify_ok"],
                json!(true),
                "real verify_contribution (Schnorr+pairing) approves"
            );
            approvals += 1;
            println!(
                "  [{}] fetched {} bytes via ?new_hash=, verify_ok=true",
                nodes[v].name, r["size"]
            );
        }
        // The contributor holds valid params it generated -> counts as an approval.
        approvals += 1;
        assert!(
            approvals >= threshold,
            "GATE 2: {approvals} approvals must meet BFT threshold {threshold}"
        );
        println!("GATE 2 PASS: {approvals}/{COMMITTEE} approvals >= threshold {threshold} (voters fetched+verified cross-process)");

        // ---- (3 + 4) NOT before threshold: current.bin still un-applied -------
        let pre = nodes[0].send(json!({"cmd": "inspect"}));
        assert_eq!(
            pre["current_bin_hash"], json!(current_head),
            "GATE 3/4: before apply the contributor's current.bin is STILL the old head (candidate not adopted)"
        );

        // ---- (3) APPLY on every node -> convergence ---------------------------
        for n in nodes.iter_mut() {
            // Voters already fetched+cached; the contributor holds its generated
            // params. Contributor also needs the params cached — it does (gen).
            let a =
                n.send(json!({"cmd": "apply", "new_hash": new_hash, "contribution": contribution}));
            assert_eq!(a["ok"], json!(true), "[{}] apply ok", n.name);
            assert_eq!(a["count"], json!(p), "[{}] count advanced to {p}", n.name);
            assert_eq!(
                a["current_bin_hash"],
                json!(new_hash),
                "GATE 3: [{}] current.bin converged to the candidate after apply",
                n.name
            );
        }
        println!(
            "GATE 3 PASS: all {COMMITTEE} nodes' current.bin converged to {}… (count {p})",
            &new_hash[..16]
        );

        current_head = new_hash;
    }

    // ---- (5) Ossification at the cap -----------------------------------------
    println!("\n---- ossification ----");
    for n in nodes.iter_mut() {
        let s = n.send(json!({"cmd": "inspect"}));
        assert_eq!(s["ossified"], json!(true), "[{}] ossified at cap", n.name);
        let t = n.send(json!({"cmd": "try_generate", "contributor_id": "late"}));
        assert_eq!(t["ok"], json!(false));
        assert_eq!(
            t["err"],
            json!("CeremonyOssified"),
            "[{}] post-cap contribute refused",
            n.name
        );
    }
    println!("GATE 5a PASS: every node ossified at cap {cap}; further contribution refused (CeremonyOssified)");

    // ---- (5) Fresh node fetches final params + cannot contribute -------------
    let fresh_root = tempfile::tempdir().unwrap();
    let fresh_home = fresh_root.path().to_path_buf();
    // A fresh node "fetches" genesis+the chain to disk (we copy the contributor's
    // final params dir, standing in for the network sync), then boots ossified.
    copy_dir_files(
        &homes[0].join(".ghost/mpc_params"),
        &fresh_home.join(".ghost/mpc_params"),
    );
    let mut fresh = start_node(
        "F",
        &fresh_home,
        &current_head,
        &anchor,
        cap,
        true,
        None,
        Some(&current_head),
    )
    .expect("fresh post-ossification node must boot clean");
    // It fetches the final params from the still-serving contributor and confirms
    // the lineage hash equals the ossified head.
    let f =
        fresh.send(json!({"cmd": "fetch_head", "url": contributor_url, "new_hash": current_head}));
    assert_eq!(
        f["ok"],
        json!(true),
        "fresh node fetched final params over HTTP"
    );
    assert_eq!(
        f["fetched_hash"],
        json!(current_head),
        "GATE 5: fresh node's fetched final params hash == ossified head"
    );
    // And it CANNOT contribute.
    let t = fresh.send(json!({"cmd": "try_generate", "contributor_id": "johnny-come-lately"}));
    assert_eq!(t["ok"], json!(false));
    assert_eq!(
        t["err"],
        json!("CeremonyOssified"),
        "fresh node cannot contribute post-ossification"
    );
    println!(
        "GATE 5b PASS: fresh node fetched final params ({}…) + cannot contribute",
        &current_head[..16]
    );

    // ---- (4) NEGATIVE CONTROL: the OLD overwrite-current behaviour crashes ----
    // Prove the startup guard actually detects the node5 condition, and that the
    // fixed contributor path (separate candidate file) is what avoids it.
    println!("\n---- Bug-1 negative control (old behaviour must crash-loop) ----");
    let d_root = tempfile::tempdir().unwrap();
    let d_home = d_root.path().to_path_buf();
    copy_dir_files(&seed_params, &d_home.join(".ghost/mpc_params"));
    let mut d = start_node(
        "D",
        &d_home,
        &anchor,
        &anchor,
        0,
        false,
        None,
        Some(&anchor),
    )
    .expect("D starts clean at genesis");
    let dg = d.send(json!({"cmd": "gen_candidate", "contributor_id": "d-elder"}));
    let d_new_hash = dg["new_hash"].as_str().unwrap().to_string();
    assert_eq!(
        dg["current_bin_hash"],
        json!(anchor),
        "D fixed path: current.bin still anchor"
    );
    // Simulate the OLD bug: write the un-applied candidate OVER current.bin.
    let ob = d.send(json!({"cmd": "simulate_old_bug_overwrite_current", "new_hash": d_new_hash}));
    assert_eq!(ob["ok"], json!(true));
    assert_eq!(
        ob["current_bin_hash"],
        json!(d_new_hash),
        "D now has candidate as current.bin (the bug)"
    );
    d.shutdown();
    std::thread::sleep(std::time::Duration::from_millis(300));
    // Restart D pinned to the real chain head (anchor). current.bin != anchor now,
    // so the genesis-anchored guard MUST fail-closed (exit non-zero, no ready).
    let crashed = start_node(
        "D",
        &d_home,
        &anchor,
        &anchor,
        0,
        false,
        None,
        Some(&anchor),
    );
    assert!(
        crashed.is_none(),
        "GATE 4 negative control: overwriting current.bin with the candidate MUST crash-loop on restart"
    );
    println!("GATE 4 negative control PASS: old overwrite-current behaviour fails the startup guard (crash-loop reproduced)");

    // ---- Teardown ------------------------------------------------------------
    for n in nodes.iter_mut() {
        n.shutdown();
    }
    fresh.shutdown();
    // keep tempdirs alive until here
    drop(node_roots);
    drop(seed_root);
    println!("\n== ALL GATES PASS (cross-process) ==");
}

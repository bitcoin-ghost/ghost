//! `ghost-audit merge` end to end, as the binary: lists written by the lister's own renderer, one
//! read from a file, one served over HTTP, one lister that cannot be reached; the merged
//! `node-list.json` and DNS fragment; and the DNS hook, run only when the records change.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Command;

use ghost_audit::lister::now_secs;
use ghost_audit::listing::{
    render_node_list, AdvertInfo, ListMeta, ListState, Outcome, Policy, ProbeRecord,
};

const G: &str = "8d8cd561340ff83e99410e115619d64ad94516264d3e5cd6a991109c69f1229c";

fn list(relays: &[&str]) -> String {
    let p = Policy::default();
    let mut s = ListState::default();
    for r in relays {
        let a: SocketAddr = r.parse().unwrap();
        s.observe(a, 100, 1024);
        for t in 0..3u64 {
            s.record(
                a,
                Some(AdvertInfo {
                    sv1_port: 3333,
                    ..AdvertInfo::default()
                }),
                ProbeRecord {
                    at: 1_000 + t,
                    outcome: Outcome::Pass,
                    reasons: vec![],
                },
                &p,
            );
        }
    }
    render_node_list(
        &s,
        &ListMeta {
            generated_at: now_secs(),
            network: "regtest".into(),
            genesis_anchor: G.into(),
            policy: p,
        },
    )
}

/// Serve `body` as JSON to every request on a loopback port the OS picks.
fn serve(body: String) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let _ = c.read(&mut buf);
            let _ = write!(
                c,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    format!("http://{addr}/api/v1/node-pool/node-list")
}

/// A loopback port nothing listens on.
fn closed_port() -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    format!("http://{a}/api/v1/node-pool/node-list")
}

fn merge(dir: &Path, listers: &[&str], hook: &Path) -> (i32, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_ghost-audit"));
    c.arg("merge").args(["--network", "regtest"]);
    for l in listers {
        c.args(["--lister", l]);
    }
    c.arg("--out-json")
        .arg(dir.join("node-list.json"))
        .arg("--out-dns")
        .arg(dir.join("pool.zone"))
        .arg("--dns-hook")
        .arg(hook)
        .args(["--dns-hook-arg", "--dry-run", "--timeout", "5"]);
    let o = c.output().unwrap();
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

fn hook_calls(log: &Path) -> Vec<String> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

#[cfg(unix)]
#[test]
fn merge_lists_the_majority_and_pushes_dns_only_on_change() {
    use std::os::unix::fs::PermissionsExt;
    let dir: PathBuf =
        std::env::temp_dir().join(format!("ghost-audit-merge-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("hook.log");
    let hook = dir.join("hook.sh");
    std::fs::write(
        &hook,
        format!(
            "#!/bin/sh\necho \"$1 $2 first=$GHOST_DNS_FIRST_PUSH new=$(echo \"$GHOST_DNS_NEW_RECORDS\" \
             | tr '\\n' ',')\" >> {}\n",
            log.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();

    let a = dir.join("a.json");
    std::fs::write(&a, list(&["1.1.1.1:8566", "2.2.2.2:8566"])).unwrap();
    let b = serve(list(&["1.1.1.1:8566"]));
    let c = closed_port();
    let listers = [a.to_str().unwrap(), b.as_str(), c.as_str()];

    // Three configured, one unreachable: 1.1.1.1 has two votes of three, 2.2.2.2 one.
    let (code, err) = merge(&dir, &listers, &hook);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("SKIPPED, unreachable"), "{err}");
    assert!(
        err.contains("2 of 3 listers voted, a node needs 2; 1 listed of 2 candidates"),
        "{err}"
    );
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("node-list.json")).unwrap())
            .unwrap();
    assert_eq!(v["schema"], "ghost-audit/node-list/v1");
    assert_eq!(v["listed"], 1);
    assert_eq!(v["nodes"][0]["relay"], "1.1.1.1:8566");
    assert_eq!(v["nodes"][0]["votes"], 2);
    assert_eq!(v["merge"]["configured"], 3);
    let zone = std::fs::read_to_string(dir.join("pool.zone")).unwrap();
    assert!(zone.contains("pool 300 IN A 1.1.1.1\n"), "{zone}");
    assert!(!zone.contains("2.2.2.2"), "{zone}");
    let calls = hook_calls(&log);
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert_eq!(
        calls[0],
        format!(
            "--dry-run {} first=1 new=pool 300 IN A 1.1.1.1,",
            dir.join("pool.zone").display()
        )
    );

    // The same records again: the hook is not run.
    let (code, err) = merge(&dir, &listers, &hook);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("records unchanged"), "{err}");
    assert_eq!(hook_calls(&log).len(), 1);

    // 2.2.2.2 now listed by the HTTP lister too: changed, pushed.
    let b2 = serve(list(&["1.1.1.1:8566", "2.2.2.2:8566"]));
    let (code, err) = merge(&dir, &[listers[0], &b2, &c], &hook);
    assert_eq!(code, 0, "{err}");
    let calls = hook_calls(&log);
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert!(calls[1].ends_with("first=0 new=pool 300 IN A 1.1.1.1,pool 300 IN A 2.2.2.2,"));

    // Two of three unreachable: no quorum. Exit 2, and the published files are left as they are.
    let before_json = std::fs::read_to_string(dir.join("node-list.json")).unwrap();
    let before_zone = std::fs::read_to_string(dir.join("pool.zone")).unwrap();
    let (code, err) = merge(&dir, &[listers[0], &closed_port(), &c], &hook);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("no quorum"), "{err}");
    assert_eq!(
        std::fs::read_to_string(dir.join("node-list.json")).unwrap(),
        before_json
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("pool.zone")).unwrap(),
        before_zone
    );
    assert_eq!(hook_calls(&log).len(), 2);

    // A wrong-schema list is skipped by name and votes for nothing.
    let bad = dir.join("bad.json");
    std::fs::write(&bad, r#"{"schema":"ghost-audit/node-list/v0","nodes":[]}"#).unwrap();
    let (code, err) = merge(&dir, &[listers[0], &b2, bad.to_str().unwrap()], &hook);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("SKIPPED, wrong schema"), "{err}");

    // A failing hook: written, exit 4, and retried on the next run.
    let failing = dir.join("fail.sh");
    std::fs::write(&failing, "#!/bin/sh\nexit 1\n").unwrap();
    std::fs::set_permissions(&failing, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (code, err) = merge(&dir, &[listers[0], &b, &c], &failing);
    assert_eq!(code, 4, "{err}");
    assert!(err.contains("push FAILED"), "{err}");
    let (code, _) = merge(&dir, &[listers[0], &b, &c], &hook);
    assert_eq!(code, 0);
    assert_eq!(hook_calls(&log).len(), 3);

    // The same lister twice is refused: each lister votes once.
    let (code, err) = merge(&dir, &[listers[0], listers[0], &b], &hook);
    assert_eq!(code, 3, "{err}");
    assert!(err.contains("given twice"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

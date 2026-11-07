//! The solo pool's public API routes, and the routes of removed features.
//!
//! - `GET /api/v1/miner/{address}`, `GET /api/v1/miner/{address}/history?window=24h|7d|30d` and
//!   `GET /api/v1/pool/status` are forwarded to the same paths on pool_sv2's API
//!   ([`crate::server::VerificationState::node_pool_api`], its loopback monitoring listener),
//!   which owns the miners' statistics, the found blocks and the live channels. ghost-mining
//!   holds none of that state, so it forwards rather than re-deriving: the answer, its status
//!   code and its body pass through unchanged. pool_sv2 not answering is a 503 that says so. The
//!   JSON is documented in pool_sv2's `solo_api.rs`. `GET /api/v1/node-pool/status` is kept as
//!   an alias of `/api/v1/pool/status` until every caller has moved.
//! - `GET /api/v1/pool/miners` (operator only) is forwarded the same way, but it names every
//!   connected miner's payout address, so it is not on the public tier: `operator_router` is
//!   merged into the HMAC-authenticated internal router (the dashboard's proxy signs its GETs),
//!   and the website proxy never forwards it.
//! - `GET /api/v1/node-pool/node-list` (dormant: the open-listing lister is gone) serves this node's open-listing lister's `node-list.json`
//!   (`ghost-audit list`, enabled with `install-node.sh --lister`) read-only, so `ghost-audit
//!   merge` can collect each lister's list over the API port every node already exposes, with no
//!   new port or process. It reads one fixed file
//!   ([`crate::server::VerificationState::node_list_path`]), takes no input, and serves it only
//!   if it parses as a `ghost-audit/node-list/v1` list: a node with no lister answers 404, an
//!   unreadable or half-written file 503.
//! - Routes of features the node pool removed (the old payout ledger, node rewards, elders and
//!   capabilities, checkpoints, solo and private modes, Ghost Pay, Wraith, L2, zk and MPC) answer
//!   `410 Gone` with the feature's name and where its replacement is, rather than a bare 404, so
//!   an old dashboard, website page or script says what happened.

use std::{sync::Arc, time::Duration};

use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{any, get},
    Json, Router,
};

use crate::server::VerificationState;

/// Longest a forwarded request may take.
const FORWARD_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest forwarded body.
const FORWARD_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Longest address accepted for forwarding (a P2TR bech32m address is 62 characters).
const MAX_ADDRESS_LEN: usize = 100;

fn client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(FORWARD_TIMEOUT)
            .build()
            .unwrap_or_default()
    })
}

fn json_error(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

/// Forward `GET {node_pool_api}{path}` and pass its status and JSON body through.
async fn forward(state: &VerificationState, path: &str) -> Response {
    let url = format!("{}{path}", state.node_pool_api.trim_end_matches('/'));
    let unavailable = |why: String| {
        json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("the node pool service (pool_sv2) did not answer: {why}"),
        )
    };
    let resp = match client().get(&url).send().await {
        Ok(r) => r,
        Err(e) => return unavailable(e.without_url().to_string()),
    };
    let code = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    if resp
        .content_length()
        .is_some_and(|n| n > FORWARD_MAX_BYTES as u64)
    {
        return unavailable("its answer is too large".to_string());
    }
    match resp.bytes().await {
        Ok(b) if b.len() <= FORWARD_MAX_BYTES => {
            (code, [(header::CONTENT_TYPE, "application/json")], b).into_response()
        }
        Ok(_) => unavailable("its answer is too large".to_string()),
        Err(e) => unavailable(e.without_url().to_string()),
    }
}

/// The address, if it has only the characters of a Bitcoin address and a sane length; else the
/// 400 that says so. pool_sv2 checks the rest (checksum, network, payee class) and names what is
/// wrong.
fn checked_address(address: &str) -> Result<&str, Box<Response>> {
    let a = address.trim();
    if a.is_empty() || a.len() > MAX_ADDRESS_LEN || !a.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(Box::new(json_error(
            StatusCode::BAD_REQUEST,
            format!("{a:?} is not a Bitcoin address"),
        )));
    }
    Ok(a)
}

/// `GET /api/v1/miner/{address}`: one miner's workers, best shares, blocks found and expected
/// time to a block.
async fn miner_handler(
    State(state): State<Arc<VerificationState>>,
    Path(address): Path<String>,
) -> Response {
    match checked_address(&address) {
        Ok(a) => forward(&state, &format!("/api/v1/miner/{a}")).await,
        Err(r) => *r,
    }
}

/// History windows pool_sv2 serves.
const HISTORY_WINDOWS: [&str; 3] = ["24h", "7d", "30d"];

/// `GET /api/v1/miner/{address}/history?window=24h|7d|30d`: hashrate, shares and best share over
/// time. The window defaults to `24h`; any other value than the three is refused here.
async fn miner_history_handler(
    State(state): State<Arc<VerificationState>>,
    Path(address): Path<String>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let a = match checked_address(&address) {
        Ok(a) => a,
        Err(r) => return *r,
    };
    let w = q.get("window").map_or("24h", |w| w.trim());
    if !HISTORY_WINDOWS.contains(&w) {
        return json_error(
            StatusCode::BAD_REQUEST,
            format!("window {w:?} is not one of 24h, 7d or 30d"),
        );
    }
    forward(&state, &format!("/api/v1/miner/{a}/history?window={w}")).await
}

/// `GET /api/v1/pool/status` (and its old name `/api/v1/node-pool/status`): the pool-wide view.
async fn status_handler(State(state): State<Arc<VerificationState>>) -> Response {
    forward(&state, "/api/v1/pool/status").await
}

/// `GET /api/v1/pool/miners`: every active payout address with its workers and hashrate. On
/// the authenticated tier only (see [`operator_router`]).
async fn miners_handler(State(state): State<Arc<VerificationState>>) -> Response {
    forward(&state, "/api/v1/pool/miners").await
}

/// Schema of a lister's `node-list.json`.
const NODE_LIST_SCHEMA: &str = "ghost-audit/node-list/v1";
/// Largest node list served (the merge reads at most this much from one lister).
const NODE_LIST_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// `GET /api/v1/node-pool/node-list`: this node's lister's `node-list.json`, as written.
async fn node_list_handler(State(state): State<Arc<VerificationState>>) -> Response {
    let path = &state.node_list_path;
    let unreadable = || {
        json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "this node's lister has not written a readable node list",
        )
    };
    match tokio::fs::metadata(path).await {
        Ok(m) if m.is_file() && m.len() <= NODE_LIST_MAX_BYTES => {}
        Ok(_) => return unreadable(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return json_error(
                StatusCode::NOT_FOUND,
                "this node runs no lister (install-node.sh --lister), so it has no node list",
            )
        }
        Err(_) => return unreadable(),
    }
    let Ok(body) = tokio::fs::read(path).await else {
        return unreadable();
    };
    let schema_ok = body.len() as u64 <= NODE_LIST_MAX_BYTES
        && serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .is_some_and(|v| v.get("schema").and_then(|s| s.as_str()) == Some(NODE_LIST_SCHEMA));
    if !schema_ok {
        return unreadable();
    }
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}

/// The public pool routes.
pub(crate) fn node_pool_router() -> Router<Arc<VerificationState>> {
    Router::new()
        .route("/api/v1/node-pool/node-list", get(node_list_handler))
        .route("/api/v1/miner/:address", get(miner_handler))
        .route("/api/v1/miner/:address/history", get(miner_history_handler))
        .route("/api/v1/pool/status", get(status_handler))
        .route("/api/v1/node-pool/status", get(status_handler))
}

/// The operator's pool routes. Merged into the internal router, behind its HMAC check: never on
/// the public tier.
pub(crate) fn operator_router() -> Router<Arc<VerificationState>> {
    Router::new().route("/api/v1/pool/miners", get(miners_handler))
}

/// A removed feature: what it was, and where its replacement is.
struct Removed {
    feature: &'static str,
    replacement: &'static str,
    paths: &'static [&'static str],
}

const LEDGER: &str = "/api/v1/miner/{address} and /api/v1/pool/status";

/// Every route of a removed feature that a client may still call. Paths are taken from the route
/// tables of the releases that served them (`main` at `f1cc40519`) and from the old dashboard
/// and test callers; a trailing `*rest` covers a whole removed family.
const REMOVED: &[Removed] = &[
    Removed {
        feature: "the node pool's share-chain ledger",
        replacement: LEDGER,
        paths: &["/api/v1/ledger/*rest"],
    },
    Removed {
        feature: "the old payout ledger, payout checkpoints and node rewards",
        replacement: LEDGER,
        paths: &[
            "/payouts",
            "/api/v1/payments",
            "/api/v1/network/payout-history",
            "/api/v1/payout/checkpoint",
            "/api/v1/pool/next_payout",
            "/api/v1/pool/treasury_state",
            "/api/v1/network/treasury",
            "/api/v1/settlement/status",
            "/api/v1/rewards/*rest",
        ],
    },
    Removed {
        feature: "elders, capabilities and the node-list checkpoint",
        replacement: "/api/v1/pool/status",
        paths: &[
            "/api/v1/network/elder",
            "/api/v1/config/elder",
            "/api/v1/pool/coordinator",
            "/api/v1/pool/mesh-node-list-checkpoint",
            "/api/v1/qualification/scoped-set",
            "/verify/archive",
            "/verify/coordinator",
            "/verify/policy",
            "/verify/stratum",
        ],
    },
    Removed {
        feature: "solo, private and public mining modes and the per-node payout address",
        replacement: "every miner mines solo to its own address; see /api/v1/pool/status",
        paths: &[
            "/api/v1/mining/payout_address",
            "/api/v1/mining/private",
            "/api/v1/mining/public",
            "/api/v1/config/public_mining",
        ],
    },
    Removed {
        feature: "Ghost Pay",
        replacement: "none: Ghost Pay is not part of the pool",
        paths: &[
            "/api/v1/ghostpay/*rest",
            "/api/v1/ghost-pay/*rest",
            "/api/v1/config/ghost_pay",
            "/api/v1/settings/ghostpay_payout_address",
            "/verify/ghostpay",
        ],
    },
    Removed {
        feature: "Wraith and ghost-lock",
        replacement: "none: Wraith is not part of the pool",
        paths: &[
            "/api/v1/wraith/*rest",
            "/api/v1/config/wraith",
            "/api/v1/locks",
        ],
    },
    Removed {
        feature: "L2, zk, MPC and glyph",
        replacement: "none: they are not part of the pool",
        paths: &[
            "/api/v1/l2/*rest",
            "/api/internal/l2/*rest",
            "/api/v1/mpc/*rest",
            "/api/v1/glyph/*rest",
        ],
    },
];

/// Routes of removed features, each answering `410 Gone` to every method.
pub(crate) fn removed_router() -> Router<Arc<VerificationState>> {
    let mut r = Router::new();
    for f in REMOVED {
        let (feature, replacement) = (f.feature, f.replacement);
        for path in f.paths {
            r = r.route(
                path,
                any(move || async move {
                    (
                        StatusCode::GONE,
                        Json(serde_json::json!({
                            "error": "gone",
                            "feature": feature,
                            "detail": format!(
                                "{feature} was removed"
                            ),
                            "replacement": replacement,
                        })),
                    )
                }),
            );
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn state(api: &str) -> Arc<VerificationState> {
        Arc::new(VerificationState::new("test_node".into(), "1.0.0".into()).with_node_pool_api(api))
    }

    async fn call(app: Router, method: &str, uri: &str) -> (StatusCode, serde_json::Value) {
        let r = app
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let code = r.status();
        let body = r.into_body().collect().await.unwrap().to_bytes();
        (
            code,
            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
        )
    }

    /// A stand-in pool_sv2 node pool API that answers every path with `(code, body)` and
    /// records the paths it was asked for.
    async fn upstream(
        code: u16,
        body: &'static str,
    ) -> (String, Arc<parking_lot::Mutex<Vec<String>>>) {
        let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let s = seen.clone();
        let app = Router::new().fallback(move |uri: axum::http::Uri| {
            let s = s.clone();
            async move {
                s.lock().push(uri.path().to_string());
                (
                    StatusCode::from_u16(code).unwrap(),
                    [(header::CONTENT_TYPE, "application/json")],
                    body,
                )
            }
        });
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (base, seen)
    }

    #[tokio::test]
    async fn the_status_is_forwarded_with_its_status_code() {
        let (base, seen) = upstream(200, r#"{"network":"regtest"}"#).await;
        let app = crate::routes::create_router(state(&base));
        let (code, v) = call(app.clone(), "GET", "/api/v1/pool/status").await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(v["network"], "regtest");
        let (code, _) = call(app, "GET", "/api/v1/node-pool/status").await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(
            *seen.lock(),
            vec![
                "/api/v1/pool/status".to_string(),
                "/api/v1/pool/status".to_string()
            ]
        );

        let (base, _) = upstream(400, r#"{"error":"not a regtest address"}"#).await;
        let app = crate::routes::create_router(state(&base));
        let (code, v) = call(app, "GET", "/api/v1/miner/bc1qxyz").await;
        assert_eq!(
            code,
            StatusCode::BAD_REQUEST,
            "pool_sv2's 400 passes through"
        );
        assert_eq!(v["error"], "not a regtest address");
    }

    #[tokio::test]
    async fn a_malformed_address_is_refused_before_forwarding() {
        let (base, seen) = upstream(200, "{}").await;
        let app = crate::routes::create_router(state(&base));
        for bad in ["a%2Fb", "abc%3Fx%3D1", &"q".repeat(101)] {
            let (code, v) = call(app.clone(), "GET", &format!("/api/v1/miner/{bad}")).await;
            assert_eq!(code, StatusCode::BAD_REQUEST, "{bad}");
            assert!(v["error"]
                .as_str()
                .unwrap()
                .contains("not a Bitcoin address"));
        }
        assert!(seen.lock().is_empty(), "nothing malformed reaches pool_sv2");
    }

    /// A stand-in that records the full request URI (path and query).
    async fn upstream_uri(body: &'static str) -> (String, Arc<parking_lot::Mutex<Vec<String>>>) {
        let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let s = seen.clone();
        let app = Router::new().fallback(move |uri: axum::http::Uri| {
            let s = s.clone();
            async move {
                s.lock().push(uri.to_string());
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/json")],
                    body,
                )
            }
        });
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (base, seen)
    }

    #[tokio::test]
    async fn the_miner_routes_are_forwarded_with_their_window() {
        let (base, seen) = upstream_uri(r#"{"workers":[]}"#).await;
        let app = crate::routes::create_router(state(&base));
        let addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
        let (code, v) = call(app.clone(), "GET", &format!("/api/v1/miner/{addr}")).await;
        assert_eq!(code, StatusCode::OK);
        assert!(v["workers"].is_array());
        for (q, want) in [("", "24h"), ("?window=7d", "7d"), ("?window=30d", "30d")] {
            let (code, _) = call(
                app.clone(),
                "GET",
                &format!("/api/v1/miner/{addr}/history{q}"),
            )
            .await;
            assert_eq!(code, StatusCode::OK, "{q}");
            assert_eq!(
                seen.lock().last().unwrap(),
                &format!("/api/v1/miner/{addr}/history?window={want}")
            );
        }
        assert_eq!(seen.lock()[0], format!("/api/v1/miner/{addr}"));
        let n = seen.lock().len();

        // Bad windows and addresses never reach pool_sv2.
        for uri in [
            format!("/api/v1/miner/{addr}/history?window=1y"),
            format!("/api/v1/miner/{addr}/history?window=24h%26x%3D1"),
            "/api/v1/miner/a%2Fb".to_string(),
            "/api/v1/miner/a%2Fb/history".to_string(),
            format!("/api/v1/miner/{}", "q".repeat(101)),
        ] {
            let (code, v) = call(app.clone(), "GET", &uri).await;
            assert_eq!(code, StatusCode::BAD_REQUEST, "{uri}");
            assert!(v["error"].is_string(), "{uri}");
        }
        assert_eq!(seen.lock().len(), n, "nothing malformed reaches pool_sv2");
    }

    #[tokio::test]
    async fn the_listers_node_list_is_served_read_only_and_only_when_valid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node-list.json");
        let app = || {
            crate::routes::create_router(Arc::new(
                VerificationState::new("test_node".into(), "1.0.0".into())
                    .with_node_list_path(&path),
            ))
        };
        // No lister: 404, saying so.
        let (code, v) = call(app(), "GET", "/api/v1/node-pool/node-list").await;
        assert_eq!(code, StatusCode::NOT_FOUND);
        assert!(
            v["error"].as_str().unwrap().contains("runs no lister"),
            "{v}"
        );
        // A valid list: served as written.
        let list = r#"{"schema":"ghost-audit/node-list/v1","listed":0,"nodes":[]}"#;
        std::fs::write(&path, list).unwrap();
        let r = app()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/node-pool/node-list")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(r.headers()[header::CONTENT_TYPE], "application/json");
        let body = r.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], list.as_bytes());
        // Half a file, another schema, or too large: 503, and nothing of it served.
        for bad in [
            &br#"{"schema":"ghost-audit/node-list/v1","nod"#[..],
            &br#"{"schema":"something/else","nodes":[]}"#[..],
        ] {
            std::fs::write(&path, bad).unwrap();
            let (code, v) = call(app(), "GET", "/api/v1/node-pool/node-list").await;
            assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
            assert!(v["error"]
                .as_str()
                .unwrap()
                .contains("not written a readable"));
        }
        std::fs::write(&path, vec![b' '; NODE_LIST_MAX_BYTES as usize + 1]).unwrap();
        let (code, _) = call(app(), "GET", "/api/v1/node-pool/node-list").await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        // Read-only: nothing but GET.
        std::fs::write(&path, list).unwrap();
        let (code, _) = call(app(), "POST", "/api/v1/node-pool/node-list").await;
        assert_eq!(code, StatusCode::METHOD_NOT_ALLOWED);
    }

    fn secret(seed: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(seed);
        }
        s
    }

    #[tokio::test]
    async fn the_miner_list_is_forwarded_only_to_signed_requests() {
        let (base, seen) = upstream(200, r#"{"miners":[{"address":"bcrt1qx"}]}"#).await;
        let auth = crate::auth::InternalAuth::new(&secret(0x42)).unwrap();
        let st = Arc::new(
            VerificationState::new("test_node".into(), "1.0.0".into())
                .with_node_pool_api(&base)
                .with_internal_auth(auth.clone()),
        );
        let app = crate::routes::create_router(st);
        // Unsigned (the public, a website proxy): refused, and pool_sv2 is never asked.
        let (code, _) = call(app.clone(), "GET", "/api/v1/pool/miners").await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
        // A wrong signature: refused too.
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let bad = crate::auth::InternalAuth::new(&secret(0x17)).unwrap();
        for (key, want) in [(&bad, StatusCode::UNAUTHORIZED), (&auth, StatusCode::OK)] {
            let r = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/pool/miners")
                        .header("X-Ghost-Signature", key.sign(ts, b""))
                        .header("X-Ghost-Timestamp", ts.to_string())
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(r.status(), want);
            if want == StatusCode::OK {
                let body = r.into_body().collect().await.unwrap().to_bytes();
                let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(v["miners"][0]["address"], "bcrt1qx");
            }
        }
        assert_eq!(*seen.lock(), vec!["/api/v1/pool/miners".to_string()]);

        // With no internal auth configured at all, the route refuses everything.
        let (base, seen) = upstream(200, "{}").await;
        let app = crate::routes::create_router(state(&base));
        let (code, _) = call(app, "GET", "/api/v1/pool/miners").await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
        assert!(seen.lock().is_empty());
    }

    #[tokio::test]
    async fn pool_sv2_not_answering_is_a_503_that_says_so() {
        // A port nothing listens on.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        drop(l);
        let app = crate::routes::create_router(state(&base));
        for uri in [
            "/api/v1/pool/status",
            "/api/v1/node-pool/status",
            "/api/v1/miner/bcrt1qabc",
            "/api/v1/miner/bcrt1qabc/history?window=7d",
        ] {
            let (code, v) = call(app.clone(), "GET", uri).await;
            assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE, "{uri}");
            assert!(v["error"]
                .as_str()
                .unwrap()
                .contains("pool_sv2) did not answer"));
        }
    }

    #[tokio::test]
    async fn removed_features_answer_410_gone() {
        let app = crate::routes::create_router(state("http://127.0.0.1:1"));
        for f in REMOVED {
            for path in f.paths {
                let uri = path.replace("*rest", "status/x");
                for method in ["GET", "POST"] {
                    let (code, v) = call(app.clone(), method, &uri).await;
                    assert_eq!(code, StatusCode::GONE, "{method} {uri}");
                    assert_eq!(v["error"], "gone");
                    assert_eq!(v["feature"], f.feature);
                    assert_eq!(v["replacement"], f.replacement);
                }
            }
        }
    }

    /// No removed path shadows a route that is still served.
    #[test]
    fn removed_paths_are_not_served_routes() {
        let src = include_str!("routes.rs");
        for f in REMOVED {
            for path in f.paths {
                if path.contains('*') {
                    continue;
                }
                assert!(
                    !src.contains(&format!("\"{path}\"")),
                    "{path} is still routed in routes.rs"
                );
            }
        }
    }
}

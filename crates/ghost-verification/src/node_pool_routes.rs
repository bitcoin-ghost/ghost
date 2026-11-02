//! The node pool's public API routes (W2.11), and the routes of removed features.
//!
//! - `GET /api/v1/ledger/{address}`, `GET /api/v1/node-pool/status`, and the miner pages'
//!   `GET /api/v1/miner/{address}` and `GET /api/v1/miner/{address}/history?window=24h|7d|30d`
//!   (W2.17) are forwarded to
//!   pool_sv2's node pool API ([`crate::server::VerificationState::node_pool_api`]), which owns
//!   the share-chain ledger, its store and the live relay state. ghost-mining cannot read that
//!   store (pool_sv2 runs as root and writes it 0600) and holds none of the live state, so it
//!   forwards rather than re-deriving: the answer, its status code and its body pass through
//!   unchanged. pool_sv2 not answering is a 503 that says so.
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

/// Longest a forwarded request may take: the ledger may wait on the relay for its next table.
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

/// `GET /api/v1/ledger/{address}`: one miner's balance, queue position, shares and payouts.
async fn ledger_handler(
    State(state): State<Arc<VerificationState>>,
    Path(address): Path<String>,
) -> Response {
    match checked_address(&address) {
        Ok(a) => forward(&state, &format!("/api/v1/node-pool/ledger/{a}")).await,
        Err(r) => *r,
    }
}

/// `GET /api/v1/miner/{address}`: one miner's workers on this node and its expected wait.
async fn miner_handler(
    State(state): State<Arc<VerificationState>>,
    Path(address): Path<String>,
) -> Response {
    match checked_address(&address) {
        Ok(a) => forward(&state, &format!("/api/v1/node-pool/miner/{a}")).await,
        Err(r) => *r,
    }
}

/// History windows pool_sv2 serves.
const HISTORY_WINDOWS: [&str; 3] = ["24h", "7d", "30d"];

/// `GET /api/v1/miner/{address}/history?window=24h|7d|30d`: hashrate, shares and balance over
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
    forward(
        &state,
        &format!("/api/v1/node-pool/miner/{a}/history?window={w}"),
    )
    .await
}

/// `GET /api/v1/node-pool/status`: the pool-wide view.
async fn status_handler(State(state): State<Arc<VerificationState>>) -> Response {
    forward(&state, "/api/v1/node-pool/status").await
}

/// The public node pool routes.
pub(crate) fn node_pool_router() -> Router<Arc<VerificationState>> {
    Router::new()
        .route("/api/v1/ledger/:address", get(ledger_handler))
        .route("/api/v1/miner/:address", get(miner_handler))
        .route("/api/v1/miner/:address/history", get(miner_history_handler))
        .route("/api/v1/node-pool/status", get(status_handler))
}

/// A removed feature: what it was, and where its replacement is.
struct Removed {
    feature: &'static str,
    replacement: &'static str,
    paths: &'static [&'static str],
}

const LEDGER: &str = "/api/v1/ledger/{address} and /api/v1/node-pool/status";

/// Every route of a removed feature that a client may still call. Paths are taken from the route
/// tables of the releases that served them (`main` at `f1cc40519`) and from the old dashboard
/// and test callers; a trailing `*rest` covers a whole removed family.
const REMOVED: &[Removed] = &[
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
        replacement: "/api/v1/node-pool/status",
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
        replacement: "the node pool is the only mode; see /api/v1/node-pool/status",
        paths: &[
            "/api/v1/mining/payout_address",
            "/api/v1/mining/private",
            "/api/v1/mining/public",
            "/api/v1/config/public_mining",
        ],
    },
    Removed {
        feature: "Ghost Pay",
        replacement: "none: Ghost Pay is not part of the node pool",
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
        replacement: "none: Wraith is not part of the node pool",
        paths: &[
            "/api/v1/wraith/*rest",
            "/api/v1/config/wraith",
            "/api/v1/locks",
        ],
    },
    Removed {
        feature: "L2, zk, MPC and glyph",
        replacement: "none: they are not part of the node pool",
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
                                "{feature} was removed with the move to the node pool"
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
    async fn the_ledger_and_status_are_forwarded_with_their_status_codes() {
        let (base, seen) = upstream(200, r#"{"known":true,"balance":{"sats":5}}"#).await;
        let app = crate::routes::create_router(state(&base));
        let addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
        let (code, v) = call(app.clone(), "GET", &format!("/api/v1/ledger/{addr}")).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(v["balance"]["sats"], 5);
        let (code, _) = call(app, "GET", "/api/v1/node-pool/status").await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(
            *seen.lock(),
            vec![
                format!("/api/v1/node-pool/ledger/{addr}"),
                "/api/v1/node-pool/status".to_string()
            ]
        );

        let (base, _) = upstream(400, r#"{"error":"not a regtest address"}"#).await;
        let app = crate::routes::create_router(state(&base));
        let (code, v) = call(app, "GET", "/api/v1/ledger/bc1qxyz").await;
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
            let (code, v) = call(app.clone(), "GET", &format!("/api/v1/ledger/{bad}")).await;
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
                &format!("/api/v1/node-pool/miner/{addr}/history?window={want}")
            );
        }
        assert_eq!(seen.lock()[0], format!("/api/v1/node-pool/miner/{addr}"));
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
    async fn pool_sv2_not_answering_is_a_503_that_says_so() {
        // A port nothing listens on.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        drop(l);
        let app = crate::routes::create_router(state(&base));
        for uri in [
            "/api/v1/node-pool/status",
            "/api/v1/ledger/bcrt1qabc",
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

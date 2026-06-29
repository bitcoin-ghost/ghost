//! Production `BondLedger` impl backed by a remote ghost-pay HTTP
//! endpoint.
//!
//! This is the client side of phase C. The matching server-side
//! endpoints live in `bins/ghost-pay/` and are added as a follow-on;
//! this module defines the wire contract so both sides can be
//! written and tested in parallel.
//!
//! ## Wire contract
//!
//! All endpoints sit under `<base_url>/api/v1/wraith/bond/`. JSON in,
//! JSON out. Authentication is HTTP Bearer (rotating token issued
//! by the coordinator's operator and stored in ghost-pay's auth
//! table). 4xx maps onto specific `BondError` variants; 5xx /
//! transport failures map onto `BondError::LedgerUnreachable`.
//!
//! ### POST /api/v1/wraith/bond/verify
//! ```text
//! request:  { ghost_id, session_id, expected_sats }
//! reply:    { bond_id }
//! errors:   404 "not_bonded"     → BondError::NotBonded
//!           409 "amount_mismatch" with { actual_sats } in detail
//!                                 → BondError::AmountMismatch
//!           503 "ledger_unreachable" → BondError::LedgerUnreachable
//! ```
//!
//! ### POST /api/v1/wraith/bond/resolve
//! ```text
//! request:  { bond_id, resolution }   // see BondResolution serde shape
//! reply:    { bond_id, ghost_id, session_id, amount_sats, status }
//!                                     // BondRecord serde shape
//! errors:   409 "already_resolved"    → BondError::AlreadyResolved
//!           404 "not_found"           → BondError::Other("...")
//! ```
//!
//! ### GET /api/v1/wraith/bond/{bond_id}
//! ```text
//! reply:    BondRecord JSON
//! errors:   404 "not_found"           → BondError::Other("...")
//! ```
//!
//! ## What this module is NOT
//!
//! - It is NOT a wraith-protocol-level concern. The protocol crate
//!   defines the `BondLedger` trait abstractly; this is one impl.
//!   Tests use `MockBondLedger`; production wires this; future
//!   variants (eg. threshold-signed bond proofs) drop in by
//!   implementing the same trait.
//!
//! - It does NOT itself talk to bitcoind. ghost-pay handles all the
//!   on-chain / L2 escrow accounting; this client just observes
//!   the result.

use std::sync::Arc;
use std::time::Duration;

use ghost_common::tls::{IdentityPinningVerifier, PubkeyAllowList};
use serde::{Deserialize, Serialize};
use tracing::debug;

use wraith_protocol::{BondError, BondId, BondLedger, BondRecord, BondResolution};

/// Ghost-pay HTTP-backed BondLedger.
///
/// Transport is HTTPS over `ureq` — pure-sync with no internal tokio
/// runtime. `reqwest::blocking` would panic on Drop inside the
/// surrounding axum/tokio runtime.
///
/// ## Identity-pinned TLS
///
/// ghost-pay serves its bond endpoints with a self-signed,
/// **identity-derived** certificate whose Ed25519 public key IS the node's
/// `node_id` (see `ghost_common::tls::build_server_config_with_identity`).
/// There is no CA and no DNS name to validate against. So this client pins:
/// the TLS server certificate is accepted iff its Ed25519 pubkey equals the
/// one `node_id` the coordinator was told to expect (the co-located
/// ghost-pay derives its cert from the SAME `node.key`, so cert pubkey ==
/// node_id). Any other certificate — a MITM, a different node, a CA-issued
/// cert — is rejected at the handshake. `base_url` MUST be `https://`.
pub struct GhostPayBondLedger {
    base_url: String,
    /// Bearer auth token; sent as `Authorization: Bearer <token>` on
    /// every call. Rotating these is the operator's job (config
    /// reload + restart).
    auth_header: String,
    agent: ureq::Agent,
}

impl GhostPayBondLedger {
    /// Construct from a base URL + bearer token, pinning the TLS server
    /// certificate to `expected_node_id`.
    ///
    /// `base_url` is normalised to lose any trailing slash so subsequent path
    /// concatenation is unambiguous, and MUST use the `https://` scheme — the
    /// bond seam carries fund-bearing escrow state and is never spoken in the
    /// clear. The `ureq` agent is configured with a rustls `ClientConfig`
    /// whose certificate verifier ([`IdentityPinningVerifier`]) accepts ONLY a
    /// server cert whose Ed25519 public key equals `expected_node_id`.
    ///
    /// # Errors
    ///
    /// Returns [`BondError::Other`] if `base_url` is not `https://`.
    pub fn new(
        base_url: impl Into<String>,
        bearer_token: &str,
        expected_node_id: [u8; 32],
    ) -> Result<Self, BondError> {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        if !base_url.starts_with("https://") {
            return Err(BondError::Other(format!(
                "bond ledger base_url must use https:// (identity-pinned TLS); got `{base_url}`"
            )));
        }

        // Install the process-wide rustls crypto provider on first use so the
        // constructor is self-sufficient (idempotent: a second install returns
        // Err which we deliberately ignore).
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // Pin to EXACTLY the co-located ghost-pay's node_id. ghost-pay derives
        // its identity cert from the same `node.key`, so the presented cert's
        // Ed25519 pubkey must equal `expected_node_id`; anything else (MITM,
        // wrong node, CA cert) fails the handshake.
        let allow: PubkeyAllowList = Arc::new(move |k: &[u8; 32]| *k == expected_node_id);
        let verifier = Arc::new(IdentityPinningVerifier::new(allow));
        let tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(15))
            .tls_config(Arc::new(tls_config))
            .build();
        Ok(Self {
            base_url,
            auth_header: format!("Bearer {bearer_token}"),
            agent,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

#[derive(Debug, Serialize)]
struct VerifyRequest<'a> {
    ghost_id: &'a str,
    session_id: &'a str,
    expected_sats: u64,
}

#[derive(Debug, Deserialize)]
struct VerifyResponse {
    bond_id: String,
}

#[derive(Debug, Serialize)]
struct ResolveRequest<'a> {
    bond_id: &'a str,
    resolution: &'a BondResolution,
}

/// Server-side error envelope. Matches the shape every other
/// endpoint in this codebase uses (`{ error, detail }`); ghost-pay
/// returns this on any non-2xx.
#[derive(Debug, Deserialize)]
struct ErrorEnvelope {
    error: String,
    #[serde(default)]
    detail: String,
}

impl BondLedger for GhostPayBondLedger {
    fn verify_bond(
        &self,
        ghost_id: &str,
        session_id: &str,
        expected_sats: u64,
    ) -> Result<BondId, BondError> {
        let req = VerifyRequest {
            ghost_id,
            session_id,
            expected_sats,
        };
        debug!(
            ghost_id,
            session_id, expected_sats, "ghost-pay /verify_bond"
        );
        let body = serde_json::to_value(&req)
            .map_err(|e| BondError::Other(format!("verify: encode {e}")))?;
        let resp = self
            .agent
            .post(&self.url("/api/v1/wraith/bond/verify"))
            .set("Authorization", &self.auth_header)
            .send_json(body);
        match resp {
            Ok(r) => {
                let parsed: VerifyResponse = r
                    .into_json()
                    .map_err(|e| BondError::Other(format!("verify: parse {e}")))?;
                Ok(BondId::new(parsed.bond_id))
            }
            Err(ureq::Error::Status(_, response)) => {
                Err(decode_error_body(response, |env| {
                    match env.error.as_str() {
                        "not_bonded" => BondError::NotBonded {
                            ghost_id: ghost_id.into(),
                            session_id: session_id.into(),
                        },
                        "amount_mismatch" => BondError::AmountMismatch {
                            bond_id: BondId::new("unknown"),
                            expected_sats,
                            actual_sats: 0,
                        },
                        "ledger_unreachable" => BondError::LedgerUnreachable(env.detail),
                        other => BondError::Other(format!("{other}: {}", env.detail)),
                    }
                }))
            }
            Err(ureq::Error::Transport(t)) => {
                Err(BondError::LedgerUnreachable(format!("{:?}: {t}", t.kind())))
            }
        }
    }

    fn resolve_bond(
        &self,
        bond_id: &BondId,
        resolution: BondResolution,
    ) -> Result<BondRecord, BondError> {
        let req = ResolveRequest {
            bond_id: bond_id.as_str(),
            resolution: &resolution,
        };
        debug!(%bond_id, ?resolution, "ghost-pay /resolve_bond");
        let body = serde_json::to_value(&req)
            .map_err(|e| BondError::Other(format!("resolve: encode {e}")))?;
        let resp = self
            .agent
            .post(&self.url("/api/v1/wraith/bond/resolve"))
            .set("Authorization", &self.auth_header)
            .send_json(body);
        match resp {
            Ok(r) => r
                .into_json::<BondRecord>()
                .map_err(|e| BondError::Other(format!("resolve: parse {e}"))),
            Err(ureq::Error::Status(_, response)) => {
                Err(decode_error_body(response, |env| {
                    match env.error.as_str() {
                        "already_resolved" => BondError::AlreadyResolved {
                            bond_id: bond_id.clone(),
                        },
                        "not_found" => BondError::Other(format!("bond {bond_id} not found")),
                        "ledger_unreachable" => BondError::LedgerUnreachable(env.detail),
                        other => BondError::Other(format!("{other}: {}", env.detail)),
                    }
                }))
            }
            Err(ureq::Error::Transport(t)) => {
                Err(BondError::LedgerUnreachable(format!("{:?}: {t}", t.kind())))
            }
        }
    }

    fn snapshot_bond(&self, bond_id: &BondId) -> Result<BondRecord, BondError> {
        debug!(%bond_id, "ghost-pay /snapshot_bond");
        let resp = self
            .agent
            .get(&self.url(&format!("/api/v1/wraith/bond/{bond_id}")))
            .set("Authorization", &self.auth_header)
            .call();
        match resp {
            Ok(r) => r
                .into_json::<BondRecord>()
                .map_err(|e| BondError::Other(format!("snapshot: parse {e}"))),
            Err(ureq::Error::Status(_, response)) => {
                Err(decode_error_body(response, |env| {
                    match env.error.as_str() {
                        "not_found" => BondError::Other(format!("bond {bond_id} not found")),
                        "ledger_unreachable" => BondError::LedgerUnreachable(env.detail),
                        other => BondError::Other(format!("{other}: {}", env.detail)),
                    }
                }))
            }
            Err(ureq::Error::Transport(t)) => {
                Err(BondError::LedgerUnreachable(format!("{:?}: {t}", t.kind())))
            }
        }
    }
}

fn decode_error_body<F>(response: ureq::Response, f: F) -> BondError
where
    F: FnOnce(ErrorEnvelope) -> BondError,
{
    let status = response.status();
    match response.into_json::<ErrorEnvelope>() {
        Ok(env) => f(env),
        Err(e) => BondError::Other(format!(
            "{status}: response body did not match {{error,detail}}: {e}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::thread::JoinHandle;

    use ghost_common::config::TlsConfig;
    use ghost_common::signer::{LocalSigner, Signer};
    use ghost_common::tls::build_server_config_with_identity;

    /// The `node_id` (Ed25519 pubkey) ghost-pay advertises for a given 32-byte
    /// identity seed — the value an honest client must pin against.
    fn node_id_for(secret: &[u8; 32]) -> [u8; 32] {
        LocalSigner::from_bytes(secret).public_key()
    }

    /// One-shot HTTPS/1.1 server serving an **identity-derived** TLS cert
    /// (cert pubkey == node_id from `secret`) that answers exactly one request
    /// with `(reply_status, reply_body)`. Returns the `https://` base URL, the
    /// served node_id, and a join handle yielding the request line + body the
    /// client sent. The client below completes a real rustls handshake and
    /// pins on the cert pubkey — this is the production trust path, not a mock.
    ///
    /// All socket IO is failure-tolerant so the negative pinning test (where
    /// the client aborts the handshake) never panics the server thread.
    fn one_shot_tls(
        secret: [u8; 32],
        reply_status: u16,
        reply_body: serde_json::Value,
    ) -> (String, [u8; 32], JoinHandle<String>) {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let server_config = build_server_config_with_identity(&TlsConfig::default(), &secret, None)
            .expect("server identity TLS config");
        let node_id = node_id_for(&secret);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = format!("https://127.0.0.1:{port}");

        let handle = std::thread::spawn(move || {
            let (mut tcp, _) = listener.accept().unwrap();
            let mut conn = rustls::ServerConnection::new(server_config).unwrap();
            let body_str = reply_body.to_string();
            let request = {
                let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
                let request = read_request(&mut tls);
                let resp = format!(
                    "HTTP/1.1 {} OK\r\n\
                     Content-Type: application/json\r\n\
                     Connection: close\r\n\
                     Content-Length: {}\r\n\
                     \r\n\
                     {}",
                    reply_status,
                    body_str.len(),
                    body_str
                );
                let _ = tls.write_all(resp.as_bytes());
                let _ = tls.flush();
                request
            };
            // Cleanly close the TLS session so the client reads to EOF.
            conn.send_close_notify();
            let _ = conn.complete_io(&mut tcp);
            request
        });
        (url, node_id, handle)
    }

    /// Read one HTTP/1.1 request (request line, then a Content-Length body)
    /// from any `Read`, returning `"<METHOD PATH> <body>"`. Tolerant of IO
    /// errors (a rejected handshake just yields what was read so far).
    fn read_request<R: Read>(stream: R) -> String {
        let mut reader = BufReader::new(stream);
        let mut content_length: usize = 0;
        let mut method_path = String::new();
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            if line == "\r\n" {
                break;
            }
            if method_path.is_empty() {
                method_path = line.trim().to_string();
            }
            let lower = line.to_ascii_lowercase();
            if let Some(rest) = lower.strip_prefix("content-length:") {
                content_length = rest.trim().parse().unwrap_or(0);
            }
        }
        if content_length == 0 {
            return method_path;
        }
        let mut body = vec![0u8; content_length];
        if reader.read_exact(&mut body).is_err() {
            return method_path;
        }
        format!("{method_path} {}", String::from_utf8_lossy(&body))
    }

    #[test]
    fn new_rejects_non_https_base_url() {
        // `GhostPayBondLedger` isn't `Debug`, so match rather than `unwrap_err`.
        match GhostPayBondLedger::new("http://127.0.0.1:8800", "tok", [0u8; 32]) {
            Ok(_) => panic!("http:// base_url must be rejected"),
            Err(BondError::Other(m)) => assert!(m.contains("https"), "msg: {m}"),
            Err(other) => panic!("expected Other(https...); got {other:?}"),
        }
    }

    #[test]
    fn verify_bond_returns_bond_id_on_success() {
        let (url, node_id, server) = one_shot_tls(
            [1u8; 32],
            200,
            serde_json::json!({ "bond_id": "ghost-pay-bond-abc" }),
        );
        let ledger = GhostPayBondLedger::new(url, "tok", node_id).unwrap();
        let id = ledger
            .verify_bond("wallet-x", "session-y", 500)
            .expect("verify ok");
        assert_eq!(id.as_str(), "ghost-pay-bond-abc");
        let req = server.join().unwrap();
        assert!(req.contains("/api/v1/wraith/bond/verify"));
        assert!(req.contains("wallet-x"));
        assert!(req.contains("session-y"));
        assert!(req.contains("500"));
    }

    #[test]
    fn verify_bond_maps_404_to_not_bonded() {
        let (url, node_id, server) = one_shot_tls(
            [2u8; 32],
            404,
            serde_json::json!({ "error": "not_bonded", "detail": "" }),
        );
        let ledger = GhostPayBondLedger::new(url, "tok", node_id).unwrap();
        let err = ledger.verify_bond("wx", "sy", 500).unwrap_err();
        match err {
            BondError::NotBonded {
                ghost_id,
                session_id,
            } => {
                assert_eq!(ghost_id, "wx");
                assert_eq!(session_id, "sy");
            }
            other => panic!("expected NotBonded; got {other:?}"),
        }
        server.join().unwrap();
    }

    #[test]
    fn verify_bond_maps_409_amount_mismatch() {
        let (url, node_id, server) = one_shot_tls(
            [3u8; 32],
            409,
            serde_json::json!({ "error": "amount_mismatch", "detail": "actual=499" }),
        );
        let ledger = GhostPayBondLedger::new(url, "tok", node_id).unwrap();
        let err = ledger.verify_bond("wx", "sy", 500).unwrap_err();
        match err {
            BondError::AmountMismatch { expected_sats, .. } => {
                assert_eq!(expected_sats, 500);
            }
            other => panic!("expected AmountMismatch; got {other:?}"),
        }
        server.join().unwrap();
    }

    #[test]
    fn verify_bond_maps_transport_error_to_unreachable() {
        // 127.0.0.1:1 — reserved-low, refuses immediately. The `https` scheme
        // satisfies the constructor; the connection itself fails at transport.
        let ledger = GhostPayBondLedger::new("https://127.0.0.1:1", "tok", [0u8; 32]).unwrap();
        let err = ledger.verify_bond("a", "b", 1).unwrap_err();
        match err {
            BondError::LedgerUnreachable(_) => {}
            other => panic!("expected LedgerUnreachable; got {other:?}"),
        }
    }

    /// NEGATIVE pinning test — the whole point of the fix. The server presents
    /// an identity cert for node_id A, but the client pins node_id B. The
    /// rustls handshake MUST reject the cert, so the call fails at transport
    /// and never reads the (would-be successful) 200 body. A pinning impl that
    /// accepted any cert would turn this into an `Ok` and fail the test.
    #[test]
    fn verify_bond_rejects_wrong_pinned_node_id() {
        let (url, served_node_id, server) = one_shot_tls(
            [4u8; 32],
            200,
            serde_json::json!({ "bond_id": "must-never-be-read" }),
        );
        // Client pins a DIFFERENT node_id (seed [5u8; 32]) than the server serves.
        let wrong_node_id = node_id_for(&[5u8; 32]);
        assert_ne!(served_node_id, wrong_node_id, "test setup: ids must differ");

        let ledger = GhostPayBondLedger::new(url, "tok", wrong_node_id).unwrap();
        let err = ledger
            .verify_bond("wallet-x", "session-y", 500)
            .expect_err("pinning a wrong node_id must NOT succeed");
        match err {
            BondError::LedgerUnreachable(_) => {}
            other => panic!(
                "wrong pinned node_id MUST fail the TLS handshake \
                 (LedgerUnreachable); got {other:?}"
            ),
        }
        let _ = server.join();
    }
}

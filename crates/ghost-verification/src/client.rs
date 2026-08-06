//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: client.rs                                                                                                      |
//|======================================================================================================================|

//! Verification client for challenging other nodes

use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

use ghost_common::constants::VERIFICATION_TIMEOUT_SECS;
use ghost_common::error::{GhostError, GhostResult};
use ghost_common::tls::{IdentityPinningVerifier, PubkeyAllowList};

use crate::challenge::*;

/// Configuration for the verification client
///
/// AUTH4-2: Configurable HTTPS support to prevent MITM attacks on verification requests.
#[derive(Debug, Clone)]
pub struct VerificationClientConfig {
    /// Use HTTPS for verification requests (default: true)
    ///
    /// SECURITY: Should always be true in production. Set to false only for
    /// local testing where TLS certificates are not available.
    pub use_https: bool,
    /// Request timeout
    pub timeout: Duration,
    /// Accept invalid TLS certificates (DANGEROUS - testing only)
    pub danger_accept_invalid_certs: bool,
    /// L-29 FIX: Whether running on mainnet (blocks insecure TLS bypass)
    /// When true, GHOST_ALLOW_INSECURE_TLS is completely ignored
    pub is_mainnet: bool,
}

impl Default for VerificationClientConfig {
    fn default() -> Self {
        Self {
            use_https: true,
            timeout: Duration::from_secs(VERIFICATION_TIMEOUT_SECS),
            danger_accept_invalid_certs: false,
            is_mainnet: false, // Default to non-mainnet for safety in testing
        }
    }
}

impl VerificationClientConfig {
    /// Create a config for production (HTTPS required)
    pub fn production() -> Self {
        Self::default()
    }

    /// L-29 FIX: Create a config for mainnet (HTTPS required, insecure bypass blocked)
    pub fn mainnet() -> Self {
        Self {
            use_https: true,
            timeout: Duration::from_secs(VERIFICATION_TIMEOUT_SECS),
            danger_accept_invalid_certs: false,
            is_mainnet: true, // Blocks all insecure TLS bypass attempts
        }
    }

    /// Create a config for testing (HTTP allowed)
    ///
    /// WARNING: Do not use in production - allows MITM attacks.
    ///
    /// L-29: This method is only available when the `allow-insecure` feature is enabled.
    /// In release builds without this feature, this method does not exist, making it
    /// impossible to accidentally create an insecure configuration.
    #[cfg(feature = "allow-insecure")]
    pub fn insecure_for_testing() -> Self {
        Self {
            use_https: false,
            timeout: Duration::from_secs(VERIFICATION_TIMEOUT_SECS),
            danger_accept_invalid_certs: false,
            is_mainnet: false,
        }
    }
}

/// Verification client
#[derive(Debug, Clone)]
pub struct VerificationClient {
    /// HTTP client
    client: reqwest::Client,
    /// Configuration
    config: VerificationClientConfig,
}

impl VerificationClient {
    /// Create a new verification client with default configuration (HTTPS required)
    ///
    /// AUTH4-2: Uses HTTPS by default to prevent MITM attacks.
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be created
    pub fn new() -> GhostResult<Self> {
        Self::with_config(VerificationClientConfig::default())
    }

    /// Create with custom configuration
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be created
    ///
    /// L-29 FIX: On mainnet, insecure TLS bypass is completely blocked.
    /// When compiled without `allow-insecure` feature, danger_accept_invalid_certs is ignored.
    pub fn with_config(config: VerificationClientConfig) -> GhostResult<Self> {
        // L-29: `mut` only needed when `allow-insecure` feature is enabled
        #[allow(unused_mut)]
        let mut builder = reqwest::Client::builder().timeout(config.timeout);

        // L-29: Insecure TLS options only available with `allow-insecure` feature
        #[cfg(feature = "allow-insecure")]
        if config.danger_accept_invalid_certs {
            // L-29 FIX: On mainnet, COMPLETELY block insecure TLS - no env var override
            if config.is_mainnet {
                return Err(GhostError::Config(
                    "L-29 SECURITY: Insecure TLS is NEVER allowed on mainnet. \
                     GHOST_ALLOW_INSECURE_TLS has no effect on mainnet."
                        .into(),
                ));
            }

            // For non-mainnet: Require explicit environment variable to allow insecure TLS
            // This prevents accidental MITM vulnerability from misconfiguration
            if std::env::var("GHOST_ALLOW_INSECURE_TLS").is_err() {
                return Err(GhostError::Config(
                    "danger_accept_invalid_certs requires GHOST_ALLOW_INSECURE_TLS=1 environment variable (non-mainnet only)".into()
                ));
            }
            warn!("DANGER: Verification client accepting invalid TLS certificates - GHOST_ALLOW_INSECURE_TLS is set (non-mainnet)");
            builder = builder.danger_accept_invalid_certs(true);
        }

        // L-29: When compiled without `allow-insecure`, silently ignore danger_accept_invalid_certs
        #[cfg(not(feature = "allow-insecure"))]
        if config.danger_accept_invalid_certs {
            warn!("L-29: danger_accept_invalid_certs ignored - compile with 'allow-insecure' feature to enable (testing only)");
        }

        let client = builder.build().map_err(|e| {
            debug!("HTTP client creation error: {}", e);
            GhostError::Internal("Failed to create HTTP client".to_string())
        })?;

        Ok(Self { client, config })
    }

    /// Create with custom timeout (uses HTTPS)
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be created
    pub fn with_timeout(timeout: Duration) -> GhostResult<Self> {
        Self::with_config(VerificationClientConfig {
            timeout,
            ..Default::default()
        })
    }

    /// Create a verification client that pins TLS server certs against the
    /// given Ed25519 public-key allow list (typically a closure that consults
    /// the live peer registry). This is the mainnet-correct path: certs are
    /// trusted iff their pubkey matches a registered peer's `node_id`, with
    /// no CA chain or hostname validation.
    ///
    /// `config` controls timeout and HTTPS scheme; `is_mainnet` should match
    /// the bitcoin network. The allow list itself is stable across calls (it
    /// reads live state internally), so a single client can challenge any
    /// peer that joins or leaves over time.
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be built.
    pub fn with_pinning(
        config: VerificationClientConfig,
        allow: PubkeyAllowList,
    ) -> GhostResult<Self> {
        // Install the rustls process-level crypto provider on first use so
        // the constructor is self-sufficient (idempotent: a second install
        // returns Err which we deliberately ignore).
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let verifier = Arc::new(IdentityPinningVerifier::new(allow));
        let rustls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

        let builder = reqwest::Client::builder()
            .timeout(config.timeout)
            .use_preconfigured_tls(rustls_config);

        let client = builder.build().map_err(|e| {
            debug!("HTTP client (pinned) creation error: {}", e);
            GhostError::Internal("Failed to create pinned HTTP client".to_string())
        })?;

        info!("Verification client built with identity-pinned TLS (cert pubkey == node_id)");
        Ok(Self { client, config })
    }

    /// Get the URL scheme based on configuration
    fn scheme(&self) -> &'static str {
        if self.config.use_https {
            "https"
        } else {
            "http"
        }
    }

    /// M-11 FIX: Validate that an IP address is not a private/internal address
    ///
    /// Rejects:
    /// - Private ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
    /// - Link-local: 169.254.x.x
    /// - Localhost: 127.x.x.x
    /// - Cloud metadata: 169.254.169.254
    /// - IPv6 equivalents
    fn is_internal_address(host: &str) -> bool {
        // Extract the host part (handle IPv6 with brackets and port)
        // IPv6 with port: [::1]:8080 -> ::1
        // IPv6 without port: ::1 -> ::1
        // IPv4 with port: 127.0.0.1:8080 -> 127.0.0.1
        let host_part = if host.starts_with('[') {
            // IPv6 address with brackets, possibly with port
            host.trim_start_matches('[')
                .split(']')
                .next()
                .unwrap_or(host)
        } else if host.contains("::") {
            // IPv6 address without brackets (like ::1)
            // IPv6 addresses have multiple colons, so we can't just split on ':'
            host
        } else {
            // IPv4 or hostname, split on ':' to remove port
            host.split(':').next().unwrap_or(host)
        };

        // Check for IPv4 addresses
        if let Ok(ip) = host_part.parse::<std::net::Ipv4Addr>() {
            // Localhost: 127.0.0.0/8
            if ip.octets()[0] == 127 {
                return true;
            }
            // Private: 10.0.0.0/8
            if ip.octets()[0] == 10 {
                return true;
            }
            // Private: 172.16.0.0/12
            if ip.octets()[0] == 172 && ip.octets()[1] >= 16 && ip.octets()[1] <= 31 {
                return true;
            }
            // Private: 192.168.0.0/16
            if ip.octets()[0] == 192 && ip.octets()[1] == 168 {
                return true;
            }
            // Link-local: 169.254.0.0/16
            if ip.octets()[0] == 169 && ip.octets()[1] == 254 {
                return true;
            }
            // Broadcast: 255.255.255.255
            if ip.octets() == [255, 255, 255, 255] {
                return true;
            }
            // Current network: 0.0.0.0/8
            if ip.octets()[0] == 0 {
                return true;
            }
            return false;
        }

        // Check for IPv6 addresses
        if let Ok(ip) = host_part.parse::<std::net::Ipv6Addr>() {
            // Loopback: ::1
            if ip.is_loopback() {
                return true;
            }
            // Unspecified: ::
            if ip.is_unspecified() {
                return true;
            }
            // IPv4-mapped IPv6 addresses - check the embedded IPv4
            if let Some(ipv4) = ip.to_ipv4_mapped() {
                // Localhost
                if ipv4.octets()[0] == 127 {
                    return true;
                }
                // Private ranges
                if ipv4.octets()[0] == 10 {
                    return true;
                }
                if ipv4.octets()[0] == 172 && ipv4.octets()[1] >= 16 && ipv4.octets()[1] <= 31 {
                    return true;
                }
                if ipv4.octets()[0] == 192 && ipv4.octets()[1] == 168 {
                    return true;
                }
                if ipv4.octets()[0] == 169 && ipv4.octets()[1] == 254 {
                    return true;
                }
            }
            // Unique local addresses: fc00::/7
            let segments = ip.segments();
            if (segments[0] >> 9) == 0b1111110 {
                return true;
            }
            // Link-local: fe80::/10
            if (segments[0] >> 6) == 0b1111111010 {
                return true;
            }
            return false;
        }

        // Check for hostname-based bypasses
        let host_lower = host_part.to_lowercase();

        // Localhost variants
        if host_lower == "localhost"
            || host_lower == "localhost.localdomain"
            || host_lower.ends_with(".localhost")
        {
            return true;
        }

        // Cloud metadata service endpoints
        // AWS/GCP/Azure all use 169.254.169.254
        // Some also respond to hostnames
        if host_lower == "metadata.google.internal"
            || host_lower == "metadata"
            || host_lower.contains("169.254.169.254")
        {
            return true;
        }

        false
    }

    /// M-19 FIX: Check if an IP address is internal/private
    ///
    /// Separated from hostname checking for use with resolved IPs.
    fn is_internal_ip(ip: std::net::IpAddr) -> bool {
        match ip {
            std::net::IpAddr::V4(ipv4) => {
                // Localhost: 127.0.0.0/8
                if ipv4.octets()[0] == 127 {
                    return true;
                }
                // Private: 10.0.0.0/8
                if ipv4.octets()[0] == 10 {
                    return true;
                }
                // Private: 172.16.0.0/12
                if ipv4.octets()[0] == 172 && ipv4.octets()[1] >= 16 && ipv4.octets()[1] <= 31 {
                    return true;
                }
                // Private: 192.168.0.0/16
                if ipv4.octets()[0] == 192 && ipv4.octets()[1] == 168 {
                    return true;
                }
                // Link-local: 169.254.0.0/16
                if ipv4.octets()[0] == 169 && ipv4.octets()[1] == 254 {
                    return true;
                }
                // Broadcast: 255.255.255.255
                if ipv4.octets() == [255, 255, 255, 255] {
                    return true;
                }
                // Current network: 0.0.0.0/8
                if ipv4.octets()[0] == 0 {
                    return true;
                }
                false
            }
            std::net::IpAddr::V6(ipv6) => {
                // Loopback: ::1
                if ipv6.is_loopback() {
                    return true;
                }
                // Unspecified: ::
                if ipv6.is_unspecified() {
                    return true;
                }
                // IPv4-mapped IPv6 addresses - check the embedded IPv4
                if let Some(ipv4) = ipv6.to_ipv4_mapped() {
                    if ipv4.octets()[0] == 127
                        || ipv4.octets()[0] == 10
                        || (ipv4.octets()[0] == 172
                            && ipv4.octets()[1] >= 16
                            && ipv4.octets()[1] <= 31)
                        || (ipv4.octets()[0] == 192 && ipv4.octets()[1] == 168)
                        || (ipv4.octets()[0] == 169 && ipv4.octets()[1] == 254)
                    {
                        return true;
                    }
                }
                // Unique local addresses: fc00::/7
                let segments = ipv6.segments();
                if (segments[0] >> 9) == 0b1111110 {
                    return true;
                }
                // Link-local: fe80::/10
                if (segments[0] >> 6) == 0b1111111010 {
                    return true;
                }
                false
            }
        }
    }

    /// M-19 FIX: Resolve hostname and check if it resolves to internal addresses
    ///
    /// This prevents DNS rebinding attacks where an attacker's DNS server
    /// returns internal IP addresses for their malicious hostname.
    fn resolve_and_check_host(host: &str) -> GhostResult<()> {
        use std::net::ToSocketAddrs;

        // Extract host part without port for resolution
        let host_part = if host.starts_with('[') {
            // IPv6 with brackets
            host.trim_start_matches('[')
                .split(']')
                .next()
                .unwrap_or(host)
        } else if host.contains("::") {
            // IPv6 without brackets
            host
        } else {
            // IPv4 or hostname
            host.split(':').next().unwrap_or(host)
        };

        // Add a default port for DNS resolution (won't affect actual connection)
        let addr_with_port = format!("{}:443", host_part);

        // Resolve the hostname to IP addresses
        match addr_with_port.to_socket_addrs() {
            Ok(addrs) => {
                for addr in addrs {
                    if Self::is_internal_ip(addr.ip()) {
                        return Err(GhostError::Config(format!(
                            "M-19 SSRF Protection: Host '{}' resolves to internal address: {}",
                            host,
                            addr.ip()
                        )));
                    }
                }
                Ok(())
            }
            Err(e) => {
                // H-09: DNS resolution failure must block the request to prevent SSRF.
                // If we can't resolve the host, we can't verify it doesn't point to
                // an internal address. Allowing the request would bypass SSRF protection.
                Err(GhostError::Config(format!(
                    "H-09: DNS resolution failed for {}: {} — blocking request to prevent SSRF",
                    host, e
                )))
            }
        }
    }

    /// M-11/M-19 FIX: Build a URL with comprehensive SSRF protection
    ///
    /// Returns an error if:
    /// - The host is a known internal hostname (localhost, metadata, etc.)
    /// - The host resolves (via DNS) to an internal/private IP address
    fn build_url(&self, host: &str, path: &str) -> GhostResult<String> {
        // M-11 FIX: First validate the host string isn't a known internal address
        if Self::is_internal_address(host) {
            return Err(GhostError::Config(format!(
                "M-11 SSRF Protection: Refusing to connect to internal address: {}",
                host
            )));
        }

        // M-19 FIX: Resolve hostname and check if it resolves to internal addresses
        // This prevents DNS rebinding attacks
        Self::resolve_and_check_host(host)?;

        Ok(format!("{}://{}{}", self.scheme(), host, path))
    }

    /// Extract the bare host (no port) from a `host:port` style address.
    ///
    /// Handles IPv4 (`1.2.3.4:8080` -> `1.2.3.4`), bracketed IPv6
    /// (`[2001:db8::1]:8080` -> `2001:db8::1`), bare IPv6 (`2001:db8::1` kept
    /// whole), and bare hostnames. Returns `None` when no host can be
    /// determined (empty input).
    fn extract_host_part(address: &str) -> Option<&str> {
        let addr = address.trim();
        if addr.is_empty() {
            return None;
        }
        let host = if addr.starts_with('[') {
            // Bracketed IPv6, possibly with a trailing :port
            addr.trim_start_matches('[')
                .split(']')
                .next()
                .unwrap_or(addr)
        } else if addr.contains("::") || addr.matches(':').count() > 1 {
            // Bare IPv6 (multiple colons) — there is no host:port split here,
            // the whole thing is the host.
            addr
        } else {
            // IPv4 or hostname, optionally with :port
            addr.split(':').next().unwrap_or(addr)
        };
        let host = host.trim();
        if host.is_empty() {
            None
        } else {
            Some(host)
        }
    }

    /// CONSENSUS SECURITY: Independent stratum-port reachability probe.
    ///
    /// This replaces the old self-attestation path, where the challenger asked
    /// the target's `/verify/stratum` HTTP endpoint and the TARGET scanned its
    /// OWN `/proc/net/tcp` for a LISTEN socket — a lying target could simply
    /// self-report "up". Here the CHALLENGER itself opens a TCP connection to
    /// the target's public stratum port and directly observes reachability, so
    /// the verdict reflects the truth the challenger sees, not a relayed claim.
    ///
    /// `node_address` is the peer's mesh/HTTP address (`host:port` form); only
    /// the host is used, combined with the supplied public stratum `port`
    /// (Stratum V1 `3333`). The probe uses the client's configured timeout.
    ///
    /// Returns:
    /// - `Some(true)`  — TCP connect succeeded ⇒ reachable ⇒ pass.
    /// - `Some(false)` — connection refused or timed out ⇒ unreachable ⇒ fail
    ///   (a genuinely-down node must fail).
    /// - `None`        — INCONCLUSIVE: the target host could not be determined
    ///   or resolved (challenger-side / unknown address). The caller MUST NOT
    ///   record a verdict in this case — it mirrors the RPC-unavailable archive
    ///   path which skips rather than recording a false fail.
    pub async fn probe_stratum_port(&self, node_address: &str, port: u16) -> Option<bool> {
        use tokio::net::TcpStream;

        // Determine the target host. An undeterminable host is inconclusive.
        let host = match Self::extract_host_part(node_address) {
            Some(h) => h,
            None => {
                debug!(
                    address = %node_address,
                    "Stratum probe: could not determine target host (inconclusive, skipping)"
                );
                return None;
            }
        };

        // Resolve host:port to concrete socket addresses. A resolution failure
        // is a challenger-side / unknown-address condition: inconclusive, never
        // a false fail.
        let target = format!("{host}:{port}");
        let addrs = match tokio::net::lookup_host(&target).await {
            Ok(iter) => iter.collect::<Vec<_>>(),
            Err(e) => {
                debug!(
                    target = %target,
                    error = %e,
                    "Stratum probe: host resolution failed (inconclusive, skipping)"
                );
                return None;
            }
        };
        let addr = match addrs.into_iter().next() {
            Some(a) => a,
            None => {
                debug!(
                    target = %target,
                    "Stratum probe: host resolved to no addresses (inconclusive, skipping)"
                );
                return None;
            }
        };

        // Open a real TCP connection. Success ⇒ reachable; a definitive connect
        // failure (refused) or a timeout ⇒ unreachable ⇒ fail.
        match tokio::time::timeout(self.config.timeout, TcpStream::connect(addr)).await {
            Ok(Ok(_stream)) => {
                debug!(target = %target, "Stratum probe: reachable (TCP connect succeeded)");
                Some(true)
            }
            Ok(Err(e)) => {
                debug!(target = %target, error = %e, "Stratum probe: unreachable (connect failed)");
                Some(false)
            }
            Err(_elapsed) => {
                debug!(target = %target, "Stratum probe: unreachable (connect timed out)");
                Some(false)
            }
        }
    }

    /// Prove Public Mining by completing a handshake, rather than by asking the target (#605).
    ///
    /// The live Public Mining check (`verify_stratum`) is an HTTP GET to the target that trusts
    /// `resp.success && resp.connected` — **both self-reported by the node being challenged**. The
    /// challenger never touches the target's stratum port, so a node with no stratum port at all
    /// passes by answering its own HTTP endpoint truthfully-shaped but falsely. That is 3 of the 15
    /// node-reward shares earned on an assertion.
    ///
    /// `probe_stratum_port` was no better and, despite being what #605 blames, is not even in the
    /// live path — its only callers are its own tests. A bare TCP connect is passed by `nc -l 3333`.
    ///
    /// This connects and speaks the protocol: `StratumVerifier::verify_sv1` sends a real
    /// `mining.subscribe` and requires a well-formed reply. Something listening but not speaking
    /// stratum now FAILS, which is the whole point.
    ///
    /// Returns, deliberately three-valued:
    ///
    /// - `Some(true)` — connected AND a valid `mining.subscribe` reply. Proven.
    /// - `Some(false)` — reachable but did not speak stratum, or refused. A genuine failure.
    /// - `None` — INCONCLUSIVE: the target host could not even be determined, which is a
    ///   challenger-side condition. Never recorded as a failure, because punishing an honest node
    ///   for the challenger's own DNS problem is worse than missing a dishonest one.
    ///
    /// A timeout after a successful connect is `Some(false)`, not `None`: something accepted the
    /// connection and then failed to speak, which is exactly the `nc -l` case.
    pub async fn probe_stratum_handshake(&self, node_address: &str, port: u16) -> Option<bool> {
        let host = match Self::extract_host_part(node_address) {
            Some(h) => h,
            None => {
                debug!(
                    address = %node_address,
                    "Stratum handshake: cannot determine target host (inconclusive, not a failure)"
                );
                return None;
            }
        };

        let verifier = crate::handlers::StratumVerifier::new().with_timeout(self.config.timeout);
        match verifier.verify_sv1(host, port).await {
            Ok(r) => {
                let proven = r.connected && r.valid_protocol;
                debug!(
                    host = %host, port,
                    connected = r.connected,
                    valid_protocol = r.valid_protocol,
                    "Stratum handshake result"
                );
                Some(proven)
            }
            // Connect refused, write/read failure, closed connection, or a timeout after
            // connecting. All of these mean the node is not serving miners at that port.
            Err(e) => {
                debug!(host = %host, port, error = %e, "Stratum handshake FAILED");
                Some(false)
            }
        }
    }

    /// Get health status of a node
    pub async fn health(&self, node_address: &str) -> GhostResult<HealthResponse> {
        let url = self.build_url(node_address, "/health?unsigned=true")?;
        debug!(url = %url, "Checking node health");

        let response = self.client.get(&url).send().await.map_err(|e| {
            debug!("Health check request failed: {}", e);
            GhostError::VerificationTimeout("Health check request failed".to_string())
        })?;

        // Health endpoint returns {"signed": bool, "response": HealthResponse}
        // We request unsigned=true for simplicity, but still need to unwrap
        let wrapper: serde_json::Value = response.json().await.map_err(|e| {
            debug!("Health check response parse error: {}", e);
            GhostError::InvalidVerificationResponse("Invalid health response format".to_string())
        })?;

        // Extract the inner response object
        let inner = wrapper.get("response").ok_or_else(|| {
            GhostError::InvalidVerificationResponse("Missing 'response' field".to_string())
        })?;

        let health: HealthResponse = serde_json::from_value(inner.clone()).map_err(|e| {
            debug!("Health response deserialization error: {}", e);
            GhostError::InvalidVerificationResponse("Invalid health response data".to_string())
        })?;

        Ok(health)
    }

    /// Verify archive capability.
    ///
    /// Returns the parsed [`ArchiveResponse`] together with the RAW
    /// `SignedResponse<ArchiveResponse>` JSON when the target returned a signed
    /// response (`Some`), or `None` when it returned an unsigned one.
    ///
    /// SECURITY: unlike the other capability probes, the archive path requests
    /// the SIGNED response (it does NOT pass `unsigned=true`). The raw signed
    /// JSON is threaded into the broadcast so that every recipient can RE-DERIVE
    /// the verdict from the target's own signature instead of trusting the
    /// challenger's `passed` flag (see `ghost-pool` `ChainReVerifier`).
    pub async fn verify_archive(
        &self,
        node_address: &str,
        block_hash: Option<&str>,
        txid: Option<&str>,
        challenge_nonce: Option<&str>,
    ) -> GhostResult<(ArchiveResponse, Option<String>)> {
        let mut params: Vec<String> = Vec::new();
        if let Some(hash) = block_hash {
            params.push(format!("block={}", hash));
        }
        if let Some(tx) = txid {
            params.push(format!("tx={}", tx));
        }
        // Bind the target's signature to THIS challenge. Without it `SignedResponse`
        // is bounded only by `MAX_RESPONSE_AGE_SECS` (300s), so a captured response
        // can be replayed inside that window to keep a node earning +5 after it has
        // stopped serving. The recipient re-derivation compares this against the
        // nonce recorded in `challenge_data`.
        if let Some(nonce) = challenge_nonce {
            params.push(format!("nonce={}", nonce));
        }

        let path = if params.is_empty() {
            "/verify/archive".to_string()
        } else {
            format!("/verify/archive?{}", params.join("&"))
        };
        let url = self.build_url(node_address, &path)?;

        debug!(url = %url, "Verifying archive capability");

        let response = self.client.get(&url).send().await.map_err(|e| {
            debug!("Archive verification request failed: {}", e);
            GhostError::VerificationTimeout("Archive verification request failed".to_string())
        })?;

        // Archive endpoint returns {"signed": bool, "response": <T>} where T is a
        // `SignedResponse<ArchiveResponse>` when signed==true, else a bare
        // `ArchiveResponse`.
        let wrapper: serde_json::Value = response.json().await.map_err(|e| {
            debug!("Archive verification response parse error: {}", e);
            GhostError::InvalidVerificationResponse("Invalid archive response format".to_string())
        })?;

        let signed_flag = wrapper
            .get("signed")
            .and_then(|s| s.as_bool())
            .unwrap_or(false);

        let inner = wrapper.get("response").ok_or_else(|| {
            GhostError::InvalidVerificationResponse("Missing 'response' field".to_string())
        })?;

        if signed_flag {
            // `inner` is a SignedResponse<ArchiveResponse>; the ArchiveResponse is
            // its `payload`. Capture the raw signed JSON verbatim so the target's
            // signature stays verifiable end-to-end by recipients.
            let raw_signed = serde_json::to_string(inner).map_err(|e| {
                debug!("Archive signed response re-serialization error: {}", e);
                GhostError::InvalidVerificationResponse(
                    "Invalid signed archive response".to_string(),
                )
            })?;

            let payload = inner.get("payload").ok_or_else(|| {
                GhostError::InvalidVerificationResponse(
                    "Signed archive response missing 'payload'".to_string(),
                )
            })?;

            let result: ArchiveResponse = serde_json::from_value(payload.clone()).map_err(|e| {
                debug!("Archive payload deserialization error: {}", e);
                GhostError::InvalidVerificationResponse("Invalid archive response data".to_string())
            })?;

            Ok((result, Some(raw_signed)))
        } else {
            let result: ArchiveResponse = serde_json::from_value(inner.clone()).map_err(|e| {
                debug!("Archive response deserialization error: {}", e);
                GhostError::InvalidVerificationResponse("Invalid archive response data".to_string())
            })?;

            Ok((result, None))
        }
    }

    /// Verify policy capability.
    ///
    /// Returns `(PolicyResponse, Option<raw_signed_json>)`. We request a SIGNED
    /// response (no `unsigned=true`) so recipients of the broadcast can RE-DERIVE
    /// the verdict against their own policy engine + the target's signature
    /// instead of trusting the challenger's `passed`. The second element is the
    /// raw `SignedResponse<PolicyResponse>` JSON verbatim (when the target signed),
    /// so the target's signature stays verifiable end-to-end.
    pub async fn verify_policy(
        &self,
        node_address: &str,
        tx_hex: &str,
    ) -> GhostResult<(PolicyResponse, Option<String>)> {
        let url = self.build_url(
            node_address,
            &format!("/verify/policy?tx={}", urlencoding::encode(tx_hex)),
        )?;

        debug!(url = %url, "Verifying policy capability");

        let response = self.client.get(&url).send().await.map_err(|e| {
            debug!("Policy verification request failed: {}", e);
            GhostError::VerificationTimeout("Policy verification request failed".to_string())
        })?;

        // Policy endpoint returns {"signed": bool, "response": <T>} where T is a
        // `SignedResponse<PolicyResponse>` when signed==true, else a bare
        // `PolicyResponse`.
        let wrapper: serde_json::Value = response.json().await.map_err(|e| {
            debug!("Policy verification response parse error: {}", e);
            GhostError::InvalidVerificationResponse("Invalid policy response format".to_string())
        })?;

        let signed_flag = wrapper
            .get("signed")
            .and_then(|s| s.as_bool())
            .unwrap_or(false);

        let inner = wrapper.get("response").ok_or_else(|| {
            GhostError::InvalidVerificationResponse("Missing 'response' field".to_string())
        })?;

        if signed_flag {
            // `inner` is a SignedResponse<PolicyResponse>; the PolicyResponse is
            // its `payload`. Capture the raw signed JSON verbatim so the target's
            // signature stays verifiable end-to-end by recipients.
            let raw_signed = serde_json::to_string(inner).map_err(|e| {
                debug!("Policy signed response re-serialization error: {}", e);
                GhostError::InvalidVerificationResponse(
                    "Invalid signed policy response".to_string(),
                )
            })?;

            let payload = inner.get("payload").ok_or_else(|| {
                GhostError::InvalidVerificationResponse(
                    "Signed policy response missing 'payload'".to_string(),
                )
            })?;

            let result: PolicyResponse = serde_json::from_value(payload.clone()).map_err(|e| {
                debug!("Policy payload deserialization error: {}", e);
                GhostError::InvalidVerificationResponse("Invalid policy response data".to_string())
            })?;

            Ok((result, Some(raw_signed)))
        } else {
            let result: PolicyResponse = serde_json::from_value(inner.clone()).map_err(|e| {
                debug!("Policy response deserialization error: {}", e);
                GhostError::InvalidVerificationResponse("Invalid policy response data".to_string())
            })?;

            Ok((result, None))
        }
    }

    /// Verify stratum capability
    pub async fn verify_stratum(
        &self,
        node_address: &str,
        protocol: StratumProtocol,
    ) -> GhostResult<StratumResponse> {
        let protocol_str = match protocol {
            StratumProtocol::Sv1 => "sv1",
            StratumProtocol::Sv2 => "sv2",
        };

        let url = self.build_url(
            node_address,
            &format!("/verify/stratum?protocol={}&unsigned=true", protocol_str),
        )?;

        debug!(url = %url, "Verifying stratum capability");

        let response = self.client.get(&url).send().await.map_err(|e| {
            debug!("Stratum verification request failed: {}", e);
            GhostError::VerificationTimeout("Stratum verification request failed".to_string())
        })?;

        // Stratum endpoint returns {"signed": bool, "response": StratumResponse}
        let wrapper: serde_json::Value = response.json().await.map_err(|e| {
            debug!("Stratum verification response parse error: {}", e);
            GhostError::InvalidVerificationResponse("Invalid stratum response format".to_string())
        })?;

        let inner = wrapper.get("response").ok_or_else(|| {
            GhostError::InvalidVerificationResponse("Missing 'response' field".to_string())
        })?;

        let result: StratumResponse = serde_json::from_value(inner.clone()).map_err(|e| {
            debug!("Stratum response deserialization error: {}", e);
            GhostError::InvalidVerificationResponse("Invalid stratum response data".to_string())
        })?;

        Ok(result)
    }

    /// Verify GhostPay capability
    ///
    /// H-1 FIX: Now accepts challenge_epoch parameter to require epoch state proof.
    /// When challenge_epoch is provided, the response must include epoch_state_hash
    /// to prove the node actually has L2 state data.
    ///
    /// VER-2 FIX: Now accepts challenge_nonce parameter to prevent precomputation attacks.
    /// When challenge_nonce is provided, the response must include nonce_bound_proof
    /// which is SHA256(epoch_state_hash || challenge_nonce).
    pub async fn verify_ghostpay(
        &self,
        node_address: &str,
        challenge_epoch: Option<u64>,
    ) -> GhostResult<GhostPayResponse> {
        self.verify_ghostpay_with_nonce(node_address, challenge_epoch, None)
            .await
            .map(|(resp, _signed)| resp)
    }

    /// VER-2 FIX: Verify GhostPay capability with challenge nonce
    ///
    /// The challenge_nonce is a random 32-byte hex string that must be incorporated
    /// into the response's nonce_bound_proof field as SHA256(epoch_state_hash || nonce).
    /// This prevents attackers from precomputing a lookup table of epoch_state_hash values.
    ///
    /// Returns `(GhostPayResponse, Option<raw_signed_json>)`. We request a SIGNED
    /// response (no `unsigned=true`) so recipients of the broadcast can RE-DERIVE
    /// the verdict against the target's own signature + nonce-bound epoch proof
    /// (GHOST-01). The second element is the raw `SignedResponse<GhostPayResponse>`
    /// JSON verbatim (when the target signed), so the signature stays verifiable
    /// end-to-end.
    pub async fn verify_ghostpay_with_nonce(
        &self,
        node_address: &str,
        challenge_epoch: Option<u64>,
        challenge_nonce: Option<&str>,
    ) -> GhostResult<(GhostPayResponse, Option<String>)> {
        // H-1/VER-2 FIX: Include both challenge_epoch and challenge_nonce in the request
        let mut params: Vec<String> = Vec::new();
        if let Some(epoch) = challenge_epoch {
            params.push(format!("challenge_epoch={}", epoch));
        }
        if let Some(nonce) = challenge_nonce {
            params.push(format!("challenge_nonce={}", nonce));
        }
        let path = if params.is_empty() {
            "/verify/ghostpay".to_string()
        } else {
            format!("/verify/ghostpay?{}", params.join("&"))
        };
        let url = self.build_url(node_address, &path)?;

        debug!(url = %url, challenge_epoch = ?challenge_epoch, challenge_nonce = ?challenge_nonce, "Verifying GhostPay capability");

        let response = self.client.get(&url).send().await.map_err(|e| {
            debug!("GhostPay verification request failed: {}", e);
            GhostError::VerificationTimeout("GhostPay verification request failed".to_string())
        })?;

        // GhostPay endpoint returns {"signed": bool, "response": <T>} where T is a
        // `SignedResponse<GhostPayResponse>` when signed==true, else a bare
        // `GhostPayResponse`.
        let wrapper: serde_json::Value = response.json().await.map_err(|e| {
            debug!("GhostPay verification response parse error: {}", e);
            GhostError::InvalidVerificationResponse("Invalid GhostPay response format".to_string())
        })?;

        let signed_flag = wrapper
            .get("signed")
            .and_then(|s| s.as_bool())
            .unwrap_or(false);

        let inner = wrapper.get("response").ok_or_else(|| {
            GhostError::InvalidVerificationResponse("Missing 'response' field".to_string())
        })?;

        if signed_flag {
            // `inner` is a SignedResponse<GhostPayResponse>; the GhostPayResponse is
            // its `payload`. Capture the raw signed JSON verbatim so the target's
            // signature stays verifiable end-to-end by recipients.
            let raw_signed = serde_json::to_string(inner).map_err(|e| {
                debug!("GhostPay signed response re-serialization error: {}", e);
                GhostError::InvalidVerificationResponse(
                    "Invalid signed GhostPay response".to_string(),
                )
            })?;

            let payload = inner.get("payload").ok_or_else(|| {
                GhostError::InvalidVerificationResponse(
                    "Signed GhostPay response missing 'payload'".to_string(),
                )
            })?;

            let result: GhostPayResponse =
                serde_json::from_value(payload.clone()).map_err(|e| {
                    debug!("GhostPay payload deserialization error: {}", e);
                    GhostError::InvalidVerificationResponse(
                        "Invalid GhostPay response data".to_string(),
                    )
                })?;

            Ok((result, Some(raw_signed)))
        } else {
            let result: GhostPayResponse = serde_json::from_value(inner.clone()).map_err(|e| {
                debug!("GhostPay response deserialization error: {}", e);
                GhostError::InvalidVerificationResponse(
                    "Invalid GhostPay response data".to_string(),
                )
            })?;

            Ok((result, None))
        }
    }

    /// Probe a peer's current GhostPay epoch without issuing a challenge.
    ///
    /// Calls the GhostPay verification endpoint with `unsigned=true` and no challenge
    /// parameters. The response's `epoch` field indicates the peer's current epoch,
    /// which is then used to select a random challenge epoch in range [0, peer_epoch].
    pub async fn probe_ghostpay_epoch(&self, node_address: &str) -> GhostResult<u64> {
        let path = "/verify/ghostpay?unsigned=true";
        let url = self.build_url(node_address, path)?;

        debug!(url = %url, "Probing GhostPay current epoch");

        let response = self.client.get(&url).send().await.map_err(|e| {
            debug!("GhostPay epoch probe failed: {}", e);
            GhostError::VerificationTimeout("GhostPay epoch probe failed".to_string())
        })?;

        let wrapper: serde_json::Value = response.json().await.map_err(|e| {
            debug!("GhostPay epoch probe parse error: {}", e);
            GhostError::InvalidVerificationResponse("Invalid GhostPay probe response".to_string())
        })?;

        // Extract epoch from the response (nested under "response")
        let epoch = wrapper
            .get("response")
            .and_then(|r| r.get("epoch"))
            .and_then(|e| e.as_u64())
            .unwrap_or(0);

        debug!(epoch = epoch, "GhostPay epoch probe result");
        Ok(epoch)
    }

    /// Run full verification suite
    pub async fn verify_all_capabilities(
        &self,
        node_address: &str,
        test_block_hash: Option<&str>,
        test_tx_hex: Option<&str>,
    ) -> VerificationSuiteResult {
        let mut result = VerificationSuiteResult::default();

        // Health check
        match self.health(node_address).await {
            Ok(health) => {
                result.health = Some(health.clone());
                result.claimed_capabilities = health.capabilities;
            }
            Err(e) => {
                warn!(error = %e, "Health check failed");
                result.errors.push(format!("Health: {}", e));
                return result;
            }
        }

        // Archive verification
        if result.claimed_capabilities.archive_mode {
            if let Some(hash) = test_block_hash {
                // No challenge nonce: this path discards the signed response and
                // feeds no consensus verdict, so there is nothing to bind a replay to.
                match self
                    .verify_archive(node_address, Some(hash), None, None)
                    .await
                {
                    Ok((resp, _signed)) => result.archive_verified = resp.success,
                    Err(e) => result.errors.push(format!("Archive: {}", e)),
                }
            }
        }

        // Policy verification
        if result.claimed_capabilities.reaper {
            if let Some(tx) = test_tx_hex {
                match self.verify_policy(node_address, tx).await {
                    Ok((resp, _signed)) => result.policy_verified = resp.success,
                    Err(e) => result.errors.push(format!("Policy: {}", e)),
                }
            }
        }

        // Stratum verification
        if result.claimed_capabilities.public_mining {
            match self
                .verify_stratum(node_address, StratumProtocol::Sv2)
                .await
            {
                Ok(resp) => result.stratum_verified = resp.success && resp.connected,
                Err(e) => result.errors.push(format!("Stratum: {}", e)),
            }
        }

        // GhostPay verification
        if result.claimed_capabilities.ghost_pay {
            // M-10: Generate random nonce to prevent precomputed responses
            let ghostpay_nonce = {
                let mut nonce = [0u8; 32];
                getrandom::getrandom(&mut nonce).ok();
                Some(hex::encode(nonce))
            };
            match self
                .verify_ghostpay_with_nonce(node_address, None, ghostpay_nonce.as_deref())
                .await
            {
                Ok((resp, _signed)) => result.ghostpay_verified = resp.success && resp.l2_enabled,
                Err(e) => result.errors.push(format!("GhostPay: {}", e)),
            }
        }

        result
    }

    /// H-7: prove a node holds its identity key at the address it CLAIMS.
    ///
    /// The `/24` used for challenger diversity is derived from `nodes.public_address`,
    /// which a node advertises about itself. A bare reachability probe cannot close that:
    /// connecting proves only that *something* answers there, and a node may advertise any
    /// reachable third-party address. So this dials the claimed address and requires the
    /// answer to be signed under `expected_node_id` over a nonce chosen here.
    ///
    /// The nonce is fresh per call, so a reply captured from an earlier probe cannot be
    /// replayed — `SignedResponse` bounds freshness only to `MAX_RESPONSE_AGE_SECS`.
    ///
    /// `build_url` applies the SSRF guard (M-11) and the DNS-rebinding re-check (M-19),
    /// which matter more here than anywhere else in this client: the host being dialled is
    /// attacker-supplied by construction — it is precisely the value this function exists
    /// to distrust.
    ///
    /// A failure to reach the address returns
    /// [`crate::address_proof::AddressProofFailure::Unreachable`], which callers MUST NOT
    /// treat as evidence of a lie. Down is not dishonest.
    pub async fn probe_claimed_address(
        &self,
        claimed_address: &str,
        expected_node_id: &str,
    ) -> Result<(), crate::address_proof::AddressProofFailure> {
        use crate::address_proof::{verify_address_proof, AddressProofFailure};

        let mut nonce_bytes = [0u8; 16];
        if getrandom::getrandom(&mut nonce_bytes).is_err() {
            // No randomness means no binding, and an unbound probe is worse than none —
            // it would accept a replay. Report unreachable rather than issue it.
            warn!("H-7: no randomness for an address-proof nonce - skipping probe");
            return Err(AddressProofFailure::Unreachable);
        }
        let nonce = hex::encode(nonce_bytes);

        let url = self
            .build_url(
                &crate::address_proof::health_endpoint_for(claimed_address),
                &format!("/health?nonce={}", nonce),
            )
            .map_err(|e| {
                debug!(address = %claimed_address, error = %e, "H-7: refusing to probe address");
                AddressProofFailure::Unreachable
            })?;

        let response = self.client.get(&url).send().await.map_err(|e| {
            debug!(address = %claimed_address, error = %e, "H-7: address probe did not connect");
            AddressProofFailure::Unreachable
        })?;

        let body = response.text().await.map_err(|e| {
            debug!(address = %claimed_address, error = %e, "H-7: address probe body unreadable");
            AddressProofFailure::Unreachable
        })?;

        verify_address_proof(&body, expected_node_id, &nonce)
    }
}

/// Result of full verification suite
#[derive(Debug, Clone, Default)]
pub struct VerificationSuiteResult {
    /// Health response
    pub health: Option<HealthResponse>,
    /// Claimed capabilities
    pub claimed_capabilities: CapabilityStatus,
    /// Archive verified
    pub archive_verified: bool,
    /// Policy verified
    pub policy_verified: bool,
    /// Stratum verified
    pub stratum_verified: bool,
    /// GhostPay verified
    pub ghostpay_verified: bool,
    /// Errors encountered
    pub errors: Vec<String>,
}

impl VerificationSuiteResult {
    /// Calculate pass rate
    pub fn pass_rate(&self) -> f64 {
        let mut checks = 0;
        let mut passes = 0;

        if self.claimed_capabilities.archive_mode {
            checks += 1;
            if self.archive_verified {
                passes += 1;
            }
        }

        if self.claimed_capabilities.reaper {
            checks += 1;
            if self.policy_verified {
                passes += 1;
            }
        }

        if self.claimed_capabilities.public_mining {
            checks += 1;
            if self.stratum_verified {
                passes += 1;
            }
        }

        if self.claimed_capabilities.ghost_pay {
            checks += 1;
            if self.ghostpay_verified {
                passes += 1;
            }
        }

        if checks == 0 {
            return 1.0;
        }

        passes as f64 / checks as f64
    }
}

// URL encoding helper
mod urlencoding {
    pub(super) fn encode(s: &str) -> String {
        let mut result = String::new();
        for c in s.chars() {
            match c {
                'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => result.push(c),
                _ => {
                    for byte in c.to_string().as_bytes() {
                        result.push_str(&format!("%{:02X}", byte));
                    }
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn test_url_encoding() {
        assert_eq!(urlencoding::encode("hello world"), "hello%20world");
        assert_eq!(urlencoding::encode("test=value"), "test%3Dvalue");
    }

    #[test]
    fn test_pass_rate() {
        let mut result = VerificationSuiteResult::default();
        result.claimed_capabilities.archive_mode = true;
        result.claimed_capabilities.public_mining = true;
        result.archive_verified = true;
        result.stratum_verified = false;

        assert_eq!(result.pass_rate(), 0.5);
    }

    #[test]
    #[serial]
    #[cfg(feature = "allow-insecure")]
    fn test_insecure_tls_requires_env_var() {
        // M-7: Ensure insecure TLS is rejected without env var
        // First, ensure the env var is NOT set
        std::env::remove_var("GHOST_ALLOW_INSECURE_TLS");

        let config = VerificationClientConfig {
            use_https: true,
            timeout: std::time::Duration::from_secs(10),
            danger_accept_invalid_certs: true,
            is_mainnet: false, // Test non-mainnet behavior
        };

        let result = VerificationClient::with_config(config);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("GHOST_ALLOW_INSECURE_TLS"),
            "Error should mention required env var: {}",
            err
        );
    }

    #[test]
    #[serial]
    #[cfg(not(feature = "allow-insecure"))]
    fn test_insecure_tls_ignored_without_feature() {
        // L-29: Without allow-insecure feature, danger_accept_invalid_certs is ignored
        std::env::remove_var("GHOST_ALLOW_INSECURE_TLS");

        let config = VerificationClientConfig {
            use_https: true,
            timeout: std::time::Duration::from_secs(10),
            danger_accept_invalid_certs: true, // This is ignored without feature
            is_mainnet: false,
        };

        // Should succeed because danger_accept_invalid_certs is ignored
        let result = VerificationClient::with_config(config);
        assert!(
            result.is_ok(),
            "L-29: Without allow-insecure feature, client creation should succeed"
        );
    }

    #[test]
    #[serial]
    #[cfg(feature = "allow-insecure")]
    fn test_insecure_tls_allowed_with_env_var() {
        // M-7: Ensure insecure TLS works when env var is set
        std::env::set_var("GHOST_ALLOW_INSECURE_TLS", "1");

        let config = VerificationClientConfig {
            use_https: true,
            timeout: std::time::Duration::from_secs(10),
            danger_accept_invalid_certs: true,
            is_mainnet: false, // Test non-mainnet behavior
        };

        let result = VerificationClient::with_config(config);
        assert!(result.is_ok(), "Should succeed with env var set");

        // Clean up
        std::env::remove_var("GHOST_ALLOW_INSECURE_TLS");
    }

    #[test]
    #[serial]
    fn test_secure_tls_does_not_require_env_var() {
        // M-7: Normal secure TLS should work without env var
        std::env::remove_var("GHOST_ALLOW_INSECURE_TLS");

        let config = VerificationClientConfig::default();
        assert!(!config.danger_accept_invalid_certs);

        let result = VerificationClient::with_config(config);
        assert!(result.is_ok(), "Secure TLS should work without env var");
    }

    #[test]
    #[serial]
    #[cfg(feature = "allow-insecure")]
    fn test_l29_insecure_tls_blocked_on_mainnet() {
        // L-29 FIX: Insecure TLS must be COMPLETELY blocked on mainnet
        // Even with GHOST_ALLOW_INSECURE_TLS set, mainnet should reject
        std::env::set_var("GHOST_ALLOW_INSECURE_TLS", "1");

        let config = VerificationClientConfig {
            use_https: true,
            timeout: std::time::Duration::from_secs(10),
            danger_accept_invalid_certs: true,
            is_mainnet: true, // MAINNET
        };

        let result = VerificationClient::with_config(config);
        assert!(result.is_err(), "Insecure TLS must be rejected on mainnet");

        let err = result.unwrap_err();
        let err_str = err.to_string();
        assert!(
            err_str.contains("L-29") || err_str.contains("mainnet"),
            "Error should mention L-29 or mainnet: {}",
            err_str
        );

        // Clean up
        std::env::remove_var("GHOST_ALLOW_INSECURE_TLS");
    }

    #[test]
    #[serial]
    #[cfg(not(feature = "allow-insecure"))]
    fn test_l29_mainnet_insecure_ignored_without_feature() {
        // L-29: Without allow-insecure feature, danger_accept_invalid_certs is ignored
        // even on mainnet
        let config = VerificationClientConfig {
            use_https: true,
            timeout: std::time::Duration::from_secs(10),
            danger_accept_invalid_certs: true, // Ignored without feature
            is_mainnet: true,
        };

        // Should succeed because the dangerous option is ignored
        let result = VerificationClient::with_config(config);
        assert!(
            result.is_ok(),
            "L-29: Without allow-insecure feature, client creation should succeed"
        );
    }

    #[test]
    fn test_l29_mainnet_config_rejects_insecure() {
        // L-29 FIX: The mainnet() constructor should have is_mainnet=true
        let config = VerificationClientConfig::mainnet();
        assert!(
            config.is_mainnet,
            "mainnet() config should have is_mainnet=true"
        );
        assert!(config.use_https, "mainnet() config should require HTTPS");
        assert!(
            !config.danger_accept_invalid_certs,
            "mainnet() config should not accept invalid certs"
        );
    }

    #[test]
    fn test_m11_ssrf_protection_private_ipv4() {
        // M-11: Test SSRF protection rejects private IPv4 ranges
        // Private: 10.0.0.0/8
        assert!(VerificationClient::is_internal_address("10.0.0.1"));
        assert!(VerificationClient::is_internal_address("10.255.255.255"));
        assert!(VerificationClient::is_internal_address("10.0.0.1:8080"));

        // Private: 172.16.0.0/12
        assert!(VerificationClient::is_internal_address("172.16.0.1"));
        assert!(VerificationClient::is_internal_address("172.31.255.255"));
        assert!(!VerificationClient::is_internal_address("172.15.0.1")); // Not private
        assert!(!VerificationClient::is_internal_address("172.32.0.1")); // Not private

        // Private: 192.168.0.0/16
        assert!(VerificationClient::is_internal_address("192.168.0.1"));
        assert!(VerificationClient::is_internal_address("192.168.255.255"));
    }

    #[test]
    fn test_m11_ssrf_protection_localhost() {
        // M-11: Test SSRF protection rejects localhost
        assert!(VerificationClient::is_internal_address("127.0.0.1"));
        assert!(VerificationClient::is_internal_address("127.255.255.255"));
        assert!(VerificationClient::is_internal_address("localhost"));
        assert!(VerificationClient::is_internal_address("localhost:8080"));
        assert!(VerificationClient::is_internal_address(
            "localhost.localdomain"
        ));
    }

    #[test]
    fn test_m11_ssrf_protection_link_local() {
        // M-11: Test SSRF protection rejects link-local
        assert!(VerificationClient::is_internal_address("169.254.0.1"));
        assert!(VerificationClient::is_internal_address("169.254.169.254")); // AWS metadata
    }

    #[test]
    fn test_m11_ssrf_protection_cloud_metadata() {
        // M-11: Test SSRF protection rejects cloud metadata endpoints
        assert!(VerificationClient::is_internal_address("169.254.169.254"));
        assert!(VerificationClient::is_internal_address(
            "metadata.google.internal"
        ));
        assert!(VerificationClient::is_internal_address("metadata"));
    }

    #[test]
    fn test_m11_ssrf_protection_public_ip_allowed() {
        // M-11: Test SSRF protection allows legitimate public IPs
        assert!(!VerificationClient::is_internal_address("8.8.8.8"));
        assert!(!VerificationClient::is_internal_address("1.1.1.1"));
        assert!(!VerificationClient::is_internal_address("203.0.113.1")); // TEST-NET-3
        assert!(!VerificationClient::is_internal_address("93.184.216.34")); // example.com
    }

    #[test]
    fn test_m11_ssrf_protection_ipv6() {
        // M-11: Test SSRF protection rejects internal IPv6 addresses
        assert!(VerificationClient::is_internal_address("::1")); // Loopback
        assert!(VerificationClient::is_internal_address("::")); // Unspecified

        // Allow legitimate public IPv6
        assert!(!VerificationClient::is_internal_address(
            "2001:4860:4860::8888"
        )); // Google DNS
    }

    #[test]
    fn test_extract_host_part() {
        // IPv4 with and without port
        assert_eq!(
            VerificationClient::extract_host_part("1.2.3.4:8080"),
            Some("1.2.3.4")
        );
        assert_eq!(
            VerificationClient::extract_host_part("1.2.3.4"),
            Some("1.2.3.4")
        );
        // Bracketed IPv6 with port
        assert_eq!(
            VerificationClient::extract_host_part("[2001:db8::1]:8080"),
            Some("2001:db8::1")
        );
        // Bare IPv6 (no port) kept whole
        assert_eq!(
            VerificationClient::extract_host_part("2001:db8::1"),
            Some("2001:db8::1")
        );
        // Hostname with port
        assert_eq!(
            VerificationClient::extract_host_part("node.example.org:8080"),
            Some("node.example.org")
        );
        // Empty -> None (inconclusive)
        assert_eq!(VerificationClient::extract_host_part(""), None);
        assert_eq!(VerificationClient::extract_host_part("   "), None);
    }

    /// THE #605 CASE: a socket that accepts and says nothing must FAIL.
    ///
    /// `nc -l 3333` passes both the bare TCP connect and — because the live check just asks the
    /// target — the current Public Mining challenge. Completing a real `mining.subscribe` is what
    /// separates "a port is open" from "a miner can actually mine here".
    #[tokio::test]
    async fn stratum_handshake_fails_a_socket_that_accepts_and_stays_silent() {
        use tokio::net::TcpListener;

        let client = VerificationClient::new().unwrap();

        // A listener that accepts and never speaks — the `nc -l` impostor.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            // Accept and hold, replying with nothing at all.
            if let Ok((stream, _)) = listener.accept().await {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                drop(stream);
            }
        });

        assert_eq!(
            client.probe_stratum_handshake("127.0.0.1", port).await,
            Some(false),
            "#605: a socket that accepts but never speaks stratum must FAIL, not pass"
        );
    }

    /// THE test that exercises the PROTOCOL requirement — a socket that replies with rubbish.
    ///
    /// Added because the silent-socket test above does NOT cover this: a silent peer makes
    /// `verify_sv1` return `Err` (read timeout), so the error branch decides and
    /// `valid_protocol` is never consulted. Removing `&& r.valid_protocol` left that test passing —
    /// caught by mutation check, and the same shape as the H-13 tests that passed while production
    /// rejected every share.
    ///
    /// A peer that ANSWERS gives `Ok(connected: true, valid_protocol: false)` for anything that is
    /// not a well-formed `mining.subscribe` reply, which is the only path through the boolean.
    #[tokio::test]
    async fn stratum_handshake_fails_a_socket_that_replies_with_rubbish() {
        use tokio::io::AsyncWriteExt as _;
        use tokio::net::TcpListener;

        let client = VerificationClient::new().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                // Answers promptly, but it is not stratum. An HTTP server, a debug echo, anything.
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\n\r\nnot stratum\n")
                    .await;
                let _ = stream.flush().await;
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        });

        assert_eq!(
            client.probe_stratum_handshake("127.0.0.1", port).await,
            Some(false),
            "#605: connecting is not proof — the reply must be a valid mining.subscribe response"
        );
    }

    /// A closed port is a definite failure, not inconclusive.
    #[tokio::test]
    async fn stratum_handshake_fails_a_refused_port() {
        use tokio::net::TcpListener;
        let client = VerificationClient::new().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener); // now refused

        assert_eq!(
            client.probe_stratum_handshake("127.0.0.1", port).await,
            Some(false),
            "a refused port means no miner can connect — a real failure"
        );
    }

    /// An undeterminable host is the CHALLENGER's problem and must never be recorded as the
    /// target's failure. Punishing an honest node for our own resolution failure is worse than
    /// missing a dishonest one.
    #[tokio::test]
    async fn stratum_handshake_is_inconclusive_when_the_host_is_unknown() {
        let client = VerificationClient::new().unwrap();
        assert_eq!(
            client.probe_stratum_handshake("", 3333).await,
            None,
            "an empty address is inconclusive, never a failure"
        );
    }

    #[tokio::test]
    async fn test_probe_stratum_port_reachable_and_refused() {
        use tokio::net::TcpListener;

        // CONSENSUS SECURITY: the independent probe must return TRUE for a
        // listening socket (reachable) and FALSE for a closed port (refused).
        let client = VerificationClient::new().unwrap();

        // Bind a throwaway listener on an ephemeral loopback port.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_port = listener.local_addr().unwrap().port();

        // Positive: a real LISTEN socket is observed as reachable.
        let reachable = client.probe_stratum_port("127.0.0.1", listen_port).await;
        assert_eq!(
            reachable,
            Some(true),
            "a listening socket must probe as reachable (pass)"
        );

        // Negative: drop the listener so the port is closed, then probe it.
        // connect() to a closed loopback port is refused immediately -> false.
        drop(listener);
        let refused = client.probe_stratum_port("127.0.0.1", listen_port).await;
        assert_eq!(
            refused,
            Some(false),
            "a closed port must probe as unreachable (fail)"
        );
    }

    #[tokio::test]
    async fn test_probe_stratum_port_inconclusive_on_empty_host() {
        // An undeterminable target host is INCONCLUSIVE -> None, never a false
        // fail (the caller must skip rather than record passed=false).
        let client = VerificationClient::new().unwrap();
        let inconclusive = client.probe_stratum_port("", 3333).await;
        assert_eq!(
            inconclusive, None,
            "empty address -> inconclusive (None), not a false fail"
        );
    }

    #[test]
    fn test_m11_build_url_rejects_internal() {
        // M-11: Test that build_url rejects internal addresses
        let client = VerificationClient::new().unwrap();

        // Should reject localhost
        let result = client.build_url("127.0.0.1:8080", "/health");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("M-11"));

        // Should reject private IPs
        let result = client.build_url("192.168.1.1:8080", "/health");
        assert!(result.is_err());

        // Should allow public IPs
        let result = client.build_url("93.184.216.34:8080", "/health");
        assert!(result.is_ok());
    }

    /// H-7: the address being probed is attacker-supplied by construction — it is the
    /// value the probe exists to distrust. So the SSRF guard must apply to it, and a
    /// refusal must surface as `Unreachable` rather than as evidence the node lied.
    ///
    /// Uses an internal address, which `build_url` refuses (M-11), so no request is made.
    #[tokio::test]
    async fn probing_an_internal_address_is_refused_as_unreachable() {
        use crate::address_proof::AddressProofFailure;

        let client = VerificationClient::with_config(VerificationClientConfig {
            use_https: false,
            timeout: std::time::Duration::from_millis(200),
            danger_accept_invalid_certs: false,
            is_mainnet: false,
        })
        .expect("client");

        for addr in ["127.0.0.1:8080", "10.0.0.1:8080", "192.168.1.1:8080"] {
            let got = client.probe_claimed_address(addr, &"ab".repeat(32)).await;
            assert_eq!(
                got,
                Err(AddressProofFailure::Unreachable),
                "{addr} must be refused as Unreachable, not treated as a failed proof"
            );
        }
    }
}

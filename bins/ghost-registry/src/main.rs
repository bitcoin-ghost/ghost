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
//| FILE: main.rs                                                                                                        |
//|======================================================================================================================|

//! Ghost Registry - Pool Node Registry and DNS Load Balancer
//!
//! This service receives registrations from ghost-pool nodes and manages
//! Cloudflare DNS records for geographic load balancing.
//!
//! Run with: ghost-registry --config registry.toml

#![deny(unreachable_pub)]

mod api;
mod auth;
mod cloudflare;
mod config;
mod db;
mod health_checker;

use anyhow::Result;
use axum::extract::DefaultBodyLimit;
use axum::middleware::Next;
use axum::response::Response;
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::broadcast;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

/// LOW-API-1: Security headers middleware for all HTTP responses
async fn security_headers_middleware(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();

    use axum::http::HeaderValue;

    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "x-xss-protection",
        HeaderValue::from_static("1; mode=block"),
    );
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));

    response
}

use api::{build_router, AppState};
use auth::{InternalAuth, RateLimiter};
use cloudflare::CloudflareClient;
use config::RegistryServiceConfig;
use db::RegistryDb;
use health_checker::HealthChecker;
use std::time::Duration;

/// Ghost Registry - Pool Node Registry and DNS Load Balancer
#[derive(Parser, Debug)]
#[command(name = "ghost-registry")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "/etc/ghost/registry.toml")]
    config: PathBuf,

    /// Log level
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Override listen address
    #[arg(long)]
    listen: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Setup logging
    let level = match args.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set tracing subscriber");

    info!("╔══════════════════════════════════════════════════════════════╗");
    info!(
        "║              Ghost Registry v{}                         ║",
        env!("CARGO_PKG_VERSION")
    );
    info!("║         Pool Node Registry & DNS Load Balancer               ║");
    info!("╚══════════════════════════════════════════════════════════════╝");

    // Load configuration
    let mut config = load_config(&args.config)?;

    // Resolve environment variables in Cloudflare config
    config.cloudflare.resolve_env();

    // API-2: Resolve environment variables in server config (for API_SECRET)
    config.server.resolve_env();

    // API-2 CRITICAL: Require API_SECRET at startup - fail if missing
    let api_secret = config.server.api_secret.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "API-2 SECURITY: API_SECRET environment variable is required. \
             Set API_SECRET to a 64-character hex string (32 bytes). \
             Generate with: openssl rand -hex 32"
        )
    })?;

    // Create InternalAuth from the secret
    let internal_auth = Arc::new(InternalAuth::from_hex(api_secret).map_err(|e| {
        anyhow::anyhow!(
            "API-2 SECURITY: Invalid API_SECRET: {}. \
             Must be a 64-character hex string (32 bytes). \
             Generate with: openssl rand -hex 32",
            e
        )
    })?);
    info!("API-2: HMAC authentication configured for state-modifying endpoints");

    // API-3: Create rate limiter for status endpoint
    let rate_limiter = Arc::new(RateLimiter::new(
        config.server.status_rate_limit_per_min,
        Duration::from_secs(60),
    ));
    info!(
        "API-3: Rate limiter configured ({} req/min per IP)",
        config.server.status_rate_limit_per_min
    );

    // Override listen address if specified
    if let Some(listen) = args.listen {
        config.server.listen = listen;
    }

    // Ensure database directory exists
    if let Some(parent) = config.database.path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Initialize database
    let db = Arc::new(RegistryDb::open(&config.database.path)?);
    info!("Database opened: {}", config.database.path.display());

    // Initialize Cloudflare client
    let cloudflare = Arc::new(CloudflareClient::new(
        config.cloudflare.clone(),
        config.dns.clone(),
    )?);

    if config.cloudflare.enabled {
        info!(
            "Cloudflare DNS integration enabled for {}",
            config.cloudflare.base_domain
        );
    } else {
        info!("Cloudflare DNS integration disabled");
    }

    // Create shutdown channel
    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    // Initialize health checker
    let health_checker = Arc::new(HealthChecker::new(
        Arc::clone(&db),
        Arc::clone(&cloudflare),
        config.health.clone(),
        config.dns.max_nodes_per_region,
    ));

    // Start health checker background task
    let health_checker_task = Arc::clone(&health_checker);
    let health_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        health_checker_task.start(health_shutdown).await;
    });

    // Create app state
    let app_state = Arc::new(AppState {
        db,
        health_checker,
        health_config: config.health.clone(),
        internal_auth,
        rate_limiter,
    });

    // CRIT-API-2: Build CORS layer with explicit allowed origins (no Any)
    let cors = if let Some(ref origins_str) = config.server.cors_allowed_origins {
        // Parse and validate allowed origins
        let origins: Vec<_> = origins_str
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .filter_map(|origin| {
                // CRIT-API-2 + MED-API-1: Require https:// for all origins
                if !origin.starts_with("https://") {
                    warn!(
                        origin = %origin,
                        "CRIT-API-2: Rejecting CORS origin without https:// scheme"
                    );
                    return None;
                }
                // Parse as HeaderValue
                origin.parse::<axum::http::HeaderValue>().ok()
            })
            .collect();

        if origins.is_empty() {
            warn!("CRIT-API-2: No valid CORS origins configured, using secure defaults");
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(["https://bitcoinghost.org"
                    .parse()
                    .unwrap()]))
                .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
                .allow_headers([axum::http::header::CONTENT_TYPE])
        } else {
            info!(
                "CRIT-API-2: CORS configured with {} validated https:// origins",
                origins.len()
            );
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(origins))
                .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
                .allow_headers([axum::http::header::CONTENT_TYPE])
        }
    } else {
        warn!("CRIT-API-2: No CORS origins configured, using secure defaults");
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(["https://bitcoinghost.org"
                .parse()
                .unwrap()]))
            .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
            .allow_headers([axum::http::header::CONTENT_TYPE])
    };

    // Build router with middleware
    // H-9: Apply body size limit from config (prevents memory exhaustion)
    // LOW-API-1: Add security headers to all responses
    let app = build_router(app_state)
        .layer(axum::middleware::from_fn(security_headers_middleware))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .layer(DefaultBodyLimit::max(config.server.max_body_size));

    info!(
        "H-9: Request body limit set to {} bytes",
        config.server.max_body_size
    );

    // Parse listen address
    let addr: SocketAddr = config.server.listen.parse()?;

    // CRIT-API-1: Check TLS configuration and warn if not using reverse proxy
    if config.server.tls_cert_path.is_none() && config.server.tls_key_path.is_none() {
        error!(
            "CRIT-API-1: TLS not configured! Server will use unencrypted HTTP. \
             For production, use a reverse proxy (nginx/Cloudflare) for TLS termination."
        );
    }

    info!("════════════════════════════════════════════════════════════════");
    info!("Ghost Registry is ready!");
    info!("  HTTP API:     {}", addr);
    info!("  TLS:          Use reverse proxy (nginx/Cloudflare recommended)");
    info!("  Health check: {}/health", addr);
    info!(
        "  Cloudflare:   {}",
        if config.cloudflare.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    info!("════════════════════════════════════════════════════════════════");

    // Start server
    // CRIT-API-1 NOTE: TLS configuration fields added to config but not yet implemented.
    // For production, use a reverse proxy (nginx/Cloudflare) to terminate TLS.
    // This is the recommended approach for operational simplicity.
    if config.server.tls_cert_path.is_some() || config.server.tls_key_path.is_some() {
        warn!(
            "CRIT-API-1: TLS configuration detected but native TLS not yet implemented. \
             Use a reverse proxy (nginx/Cloudflare) for TLS termination in production."
        );
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;

    // API-3: Use into_make_service_with_connect_info to enable IP-based rate limiting
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C handler");
        info!("Shutdown signal received");
        let _ = shutdown_tx.send(());
    })
    .await?;

    info!("Ghost Registry shutdown complete");
    Ok(())
}

/// Load configuration from file
fn load_config(path: &PathBuf) -> Result<RegistryServiceConfig> {
    if path.exists() {
        let content = std::fs::read_to_string(path)?;
        let config: RegistryServiceConfig = toml::from_str(&content)?;
        info!("Configuration loaded from: {}", path.display());
        Ok(config)
    } else {
        info!("No config file found at {}, using defaults", path.display());
        Ok(RegistryServiceConfig::default())
    }
}

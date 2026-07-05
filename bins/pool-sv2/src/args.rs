//! CLI argument parsing for the Pool binary.
//!
//! Defines the `Args` struct and a function to process CLI arguments into a PoolConfig.

use clap::Parser;
use ext_config::{Config, File, FileFormat};
use pool_sv2::config::PoolConfig;
use std::path::PathBuf;
use stratum_apps::key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};

/// Holds the parsed CLI arguments for the Pool binary.
#[derive(Parser, Debug)]
#[command(author, version, about = "Pool CLI", long_about = None)]
pub struct Args {
    #[arg(
        short = 'c',
        long = "config",
        help = "Path to the TOML configuration file",
        default_value = "pool-config.toml"
    )]
    pub config_path: PathBuf,
    #[arg(
        short = 'f',
        long = "log-file",
        help = "Path to the log file. If not set, logs will only be written to stdout."
    )]
    pub log_file: Option<PathBuf>,
    /// Mint a fresh SV2 authority keypair and print it as two ready-to-paste
    /// `pool-config.toml` lines (`authority_public_key`/`authority_secret_key`),
    /// then exit. Used by the node installer to give every node its own static
    /// Noise identity instead of a shared, baked-in one.
    #[arg(
        long = "generate-key",
        help = "Generate a fresh SV2 authority keypair (prints TOML lines) and exit",
        conflicts_with = "tdp_pubkey_from_keyfile"
    )]
    pub generate_key: bool,
    /// Derive the base58 authority public key for the node identity key stored at
    /// PATH (the first 32 bytes are used as the secp256k1 secret, matching how
    /// ghost-pool derives its TDP authority key) and print it, then exit. Used by
    /// the installer to fill `[template_provider_type.Sv2Tp] public_key` so the
    /// pool trusts this node's own ghost-pool TDP server.
    #[arg(
        long = "tdp-pubkey-from-keyfile",
        value_name = "PATH",
        help = "Print the base58 authority public key derived from a node key file and exit"
    )]
    pub tdp_pubkey_from_keyfile: Option<PathBuf>,
}

/// Read the first 32 bytes of a node identity key file and return them as a
/// secp256k1 secret key. Mirrors ghost-pool's TDP key loading (the file holds a
/// 32-byte secret optionally followed by a PoW proof), so the derived public key
/// is byte-identical to the one ghost-pool advertises for its TDP server.
fn secret_from_keyfile(path: &std::path::Path) -> Result<Secp256k1SecretKey, String> {
    let bytes = std::fs::read(path)
        .map_err(|e| format!("failed to read key file {}: {e}", path.display()))?;
    if bytes.len() < 32 {
        return Err(format!(
            "key file {} is too short: expected at least 32 bytes, got {}",
            path.display(),
            bytes.len()
        ));
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&bytes[..32]);
    Secp256k1SecretKey::from_bytes(&secret).map_err(|e| {
        format!(
            "key file {} does not hold a valid secp256k1 secret: {e}",
            path.display()
        )
    })
}

#[cfg_attr(not(test), hotpath::measure)]
/// Parses CLI arguments and loads the PoolConfig from the specified file.
///
/// The key-tooling flags (`--generate-key`, `--tdp-pubkey-from-keyfile`) short
/// circuit here: they print their result and exit the process without loading a
/// config, so they can be run before any config exists.
pub fn process_cli_args() -> PoolConfig {
    let args = Args::parse();

    if args.generate_key {
        let secret = Secp256k1SecretKey::generate();
        let public = Secp256k1PublicKey::from(secret);
        println!("authority_public_key = \"{public}\"");
        println!("authority_secret_key = \"{secret}\"");
        std::process::exit(0);
    }

    if let Some(ref path) = args.tdp_pubkey_from_keyfile {
        match secret_from_keyfile(path) {
            Ok(secret) => {
                println!("{}", Secp256k1PublicKey::from(secret));
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(2);
            }
        }
    }

    let config_path = args.config_path.to_str().expect("Invalid config path");
    let mut config: PoolConfig = Config::builder()
        .add_source(File::new(config_path, FileFormat::Toml))
        .build()
        .and_then(|settings| settings.try_deserialize::<PoolConfig>())
        .expect("Failed to load or deserialize config");

    config.set_log_dir(args.log_file);

    config
}

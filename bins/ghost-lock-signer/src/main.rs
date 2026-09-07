//! Offline co-signer for a Ghost Lock's key path.
//!
//! Runs on the machine holding the backup key — ideally one with no network
//! interface. It reads a signing request as JSON, shows what the spend does,
//! and produces this device's half of a MuSig2 signature.
//!
//! # It verifies. It is never told.
//!
//! The request carries the whole transaction, not a hash. This device derives
//! the sighash itself and displays the amounts it derived them from, so what
//! you are shown and what gets signed come from one source. A device handed a
//! bare 32-byte message could not tell a legitimate spend from an attacker's:
//! it would display "sign this?" either way, and the air gap would have
//! protected the key while the coins left.
//!
//! # Why one process, and not two commands
//!
//! MuSig2 needs two rounds, and between them this device holds a **secret
//! nonce**. Using that nonce for two signatures publishes the key, so it must
//! not be casually persisted — a copy on disk is a copy that can be restored
//! from a backup and used again.
//!
//! So a signing session is one interactive run: round 1, you carry the nonce
//! out and the aggregate back, round 2, done. The secret nonce lives in memory
//! and dies with the process. If you close it early, nothing is lost that
//! matters — start again, and the ledger will not object, because a fresh
//! nonce was never used.
//!
//! The ledger is still required, for the case memory cannot cover: a signature
//! that was produced, and a process that came back afterwards.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use ghost_lock::airgap::{NonceReply, PartialReply, PartialRequest, SigningRequest, SpendSummary};
use ghost_lock::nonce_ledger_file::FileNonceLedger;
use ghost_lock::signing::SigningSession;

#[derive(Parser)]
#[command(version, about = "Offline co-signer for a Ghost Lock", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show what a signing request would do, and stop. Signs nothing.
    ///
    /// Useful for checking a request on a machine that does not hold the key.
    Review {
        /// Signing request JSON. `-` reads stdin.
        #[arg(long)]
        request: String,
        /// Network the addresses belong to.
        #[arg(long, default_value = "bitcoin")]
        network: String,
    },
    /// Print the public key this device signs with.
    ///
    /// This is what gets registered as the Lock's `backup_pubkey`. Derived
    /// from the phrase rather than typed, so the key in the Lock is provably
    /// the key this device will sign with.
    Pubkey {
        /// File holding this device's BIP39 seed phrase.
        #[arg(long)]
        seed: PathBuf,
        /// File holding the BIP39 passphrase, if any.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        /// Derivation index.
        #[arg(long, default_value_t = 0)]
        index: u32,
    },
    /// Co-sign a spend. Two rounds, one interactive session.
    Sign {
        /// Signing request JSON, as a file path.
        ///
        /// A path rather than stdin, because stdin is needed for round 2.
        #[arg(long)]
        request: PathBuf,
        /// File holding this device's BIP39 seed phrase, and nothing else.
        ///
        /// A file rather than an argument: a phrase on the command line ends
        /// up in shell history and in the process list, where anything on the
        /// machine can read it.
        #[arg(long)]
        seed: PathBuf,
        /// File holding the BIP39 passphrase, if this device uses one.
        ///
        /// Optional, and empty by default. A passphrase produces a completely
        /// different key, so a device configured with one must keep it —
        /// losing it loses the funds exactly as losing the phrase would.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        /// Derivation index. Must match the key registered in the Lock.
        #[arg(long, default_value_t = 0)]
        index: u32,
        /// Where to record spent nonces. Must be durable storage.
        #[arg(long)]
        ledger: PathBuf,
        /// Network the addresses belong to.
        #[arg(long, default_value = "bitcoin")]
        network: String,
        /// Skip the typed confirmation.
        ///
        /// For scripted testing. On a device holding a key, the confirmation is
        /// the only moment a human compares the screen to what they intended.
        #[arg(long)]
        no_confirm: bool,
    },
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ghost-lock-signer: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    match Cli::parse().command {
        Command::Review { request, network } => {
            let network = parse_network(&network)?;
            let req = read_request(&request)?;
            let (summary, message) = ghost_lock::airgap::review(&req, network)
                .map_err(|e| format!("this request cannot be signed: {e}"))?;
            print_summary(&summary);
            println!("\nsighash: {}", hex::encode(message));
            println!("(reviewed only — nothing was signed)");
            Ok(())
        }
        Command::Pubkey {
            seed,
            passphrase_file,
            index,
        } => {
            let phrase = read_secret_file(&seed, "seed phrase")?;
            let pass = match &passphrase_file {
                Some(p) => read_secret_file(p, "passphrase")?,
                None => String::new(),
            };
            let pk = ghost_lock::backup_key::public_key(&phrase, &pass, index)
                .map_err(|e| e.to_string())?;
            println!("{}", hex::encode(pk.serialize()));
            eprintln!(
                "derived at {} — register this as the Lock's backup_pubkey",
                ghost_lock::backup_key::derivation_path(index)
            );
            Ok(())
        }
        Command::Sign {
            request,
            seed,
            passphrase_file,
            index,
            ledger,
            network,
            no_confirm,
        } => sign(
            request,
            seed,
            passphrase_file,
            index,
            ledger,
            &network,
            no_confirm,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn sign(
    request_path: PathBuf,
    seed_path: PathBuf,
    passphrase_path: Option<PathBuf>,
    index: u32,
    ledger_path: PathBuf,
    network: &str,
    no_confirm: bool,
) -> Result<(), String> {
    let network = parse_network(network)?;
    let raw = std::fs::read_to_string(&request_path)
        .map_err(|e| format!("cannot read {}: {e}", request_path.display()))?;
    let req: SigningRequest =
        serde_json::from_str(&raw).map_err(|e| format!("request is not valid JSON: {e}"))?;

    // Derived here, from the transaction. Never taken from the request.
    let (summary, message) = ghost_lock::airgap::review(&req, network)
        .map_err(|e| format!("this request cannot be signed: {e}"))?;
    let keys = ghost_lock::airgap::keys(&req).map_err(|e| e.to_string())?;
    let root = ghost_lock::airgap::merkle_root(&req).map_err(|e| e.to_string())?;

    print_summary(&summary);

    if !no_confirm {
        confirm()?;
    }

    let phrase = read_secret_file(&seed_path, "seed phrase")?;
    let pass = match &passphrase_path {
        Some(p) => read_secret_file(p, "passphrase")?,
        None => String::new(),
    };
    let seckey =
        ghost_lock::backup_key::secret_key(&phrase, &pass, index).map_err(|e| e.to_string())?;

    // The key this device holds must be one of the co-signers named in the
    // request. If it is not, the request is for a Lock this device is not part
    // of — signing would burn a nonce and produce a share nobody can use.
    let ours = seckey
        .x_only_public_key(&bitcoin::secp256k1::Secp256k1::new())
        .0;
    if !keys.contains(&ours) {
        return Err(format!(
            "this device's key is not one of the co-signers in this request.\n               this device (index {index}): {}\n               the request names:          {}\n             Either the index is wrong, or this request belongs to a different Lock.",
            hex::encode(ours.serialize()),
            keys.iter()
                .map(|k| hex::encode(k.serialize()))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let mut ledger =
        FileNonceLedger::open(&ledger_path).map_err(|e| format!("nonce ledger: {e}"))?;

    // Round 1.
    let (session, commitment) = SigningSession::begin(&keys, &seckey, root, &message)
        .map_err(|e| format!("round 1: {e}"))?;
    let session_hex = hex::encode(commitment.session.as_bytes());
    let our_nonce = commitment.public_nonce;

    let reply = NonceReply {
        session: session_hex.clone(),
        public_nonce: hex::encode(our_nonce),
    };
    println!("\n--- round 1: carry this back ---");
    println!(
        "{}",
        serde_json::to_string_pretty(&reply).map_err(|e| e.to_string())?
    );
    println!("--- end ---");
    println!("\nNow paste the round 2 request and press enter.");
    println!("Nothing is signed until you do, and closing this window costs nothing.");

    let partial_req: PartialRequest = read_json_from_stdin()?;

    // The second payload must belong to the spend that was displayed. Without
    // this check a host could show one transaction in round 1 and complete a
    // different one in round 2, and the screen would have been meaningless.
    if partial_req.session != session_hex {
        return Err(format!(
            "this round 2 request is for a different spend.\n  \
             shown:    {session_hex}\n  \
             received: {}\n\
             Nothing has been signed. Start again rather than trusting this.",
            partial_req.session
        ));
    }

    let mut nonces = Vec::with_capacity(partial_req.public_nonces.len());
    for (i, n) in partial_req.public_nonces.iter().enumerate() {
        let bytes =
            hex::decode(n.trim()).map_err(|e| format!("public_nonces[{i}] is not hex: {e}"))?;
        let arr: [u8; 66] = bytes
            .try_into()
            .map_err(|_| format!("public_nonces[{i}] must be 66 bytes"))?;
        nonces.push(arr);
    }

    // Our own nonce must be in the set being aggregated. If it is not, the host
    // is building a signature this device is not part of, and signing into it
    // would burn a nonce for nothing.
    if !nonces.contains(&our_nonce) {
        return Err(
            "this device's nonce is not in the round 2 request, so the signature being \
             built is not one this device is part of. Nothing has been signed."
                .into(),
        );
    }

    // Round 2. Burns the nonce durably before producing anything.
    let partial = session
        .sign(&mut ledger, &nonces)
        .map_err(|e| format!("round 2: {e}"))?;

    let out = PartialReply {
        session: session_hex,
        partial: hex::encode(partial),
    };
    println!("\n--- round 2: carry this back ---");
    println!(
        "{}",
        serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?
    );
    println!("--- end ---");
    Ok(())
}

fn print_summary(s: &SpendSummary) {
    println!("This spend:");
    println!(
        "  from   {} ({} sats)",
        s.input_address
            .as_deref()
            .unwrap_or("(unrenderable script)"),
        s.input_sats
    );
    for o in &s.outputs {
        println!(
            "  pays   {} sats to {}",
            o.sats,
            o.address.as_deref().unwrap_or("(unrenderable script)")
        );
    }
    println!("  fee    {} sats", s.fee_sats);
    if s.input_count > 1 {
        println!(
            "\n  ! this transaction spends {} inputs. You are signing input {}.",
            s.input_count, s.input_index
        );
        println!("    The other inputs are signed by whoever owns them.");
    }
}

/// Require the word, not a keystroke.
///
/// A y/n prompt is answered by reflex. Typing `sign` is a decision, and it is
/// the only point at which a person compares this screen against what they
/// meant to do.
fn confirm() -> Result<(), String> {
    print!("\nType `sign` to co-sign this, or anything else to stop: ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("could not read confirmation: {e}"))?;
    if line.trim() != "sign" {
        return Err("stopped. Nothing was signed.".into());
    }
    Ok(())
}

/// Read JSON from stdin, finishing as soon as it parses.
///
/// Accumulates lines rather than waiting for EOF, so a pasted payload completes
/// on its own and the operator does not have to know to press Ctrl-D.
fn read_json_from_stdin<T: serde::de::DeserializeOwned>() -> Result<T, String> {
    let stdin = std::io::stdin();
    let mut buf = String::new();
    for line in stdin.lock().lines() {
        let line = line.map_err(|e| format!("stdin: {e}"))?;
        buf.push_str(&line);
        buf.push('\n');
        if let Ok(v) = serde_json::from_str::<T>(&buf) {
            return Ok(v);
        }
    }
    serde_json::from_str::<T>(&buf).map_err(|e| format!("input is not valid JSON: {e}"))
}

fn read_request(source: &str) -> Result<SigningRequest, String> {
    let raw = if source == "-" {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)
            .map_err(|e| format!("stdin: {e}"))?;
        s
    } else {
        std::fs::read_to_string(source).map_err(|e| format!("cannot read {source}: {e}"))?
    };
    serde_json::from_str(&raw).map_err(|e| format!("request is not valid JSON: {e}"))
}

/// Read a secret from a file, refusing one others can read.
///
/// Mode is checked before the contents are touched. A seed phrase readable by
/// another account on the machine is already disclosed, and continuing would
/// put a signature behind a key somebody else can derive.
fn read_secret_file(path: &PathBuf, what: &str) -> Result<String, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).map_err(|e| format!("cannot stat {what}: {e}"))?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "{} is readable by others (mode {:o}); run `chmod 600` on it. \
                 A {what} another account can read is one you no longer control.",
                path.display(),
                meta.permissions().mode() & 0o777
            ));
        }
    }
    let raw = std::fs::read_to_string(path).map_err(|e| format!("cannot read {what}: {e}"))?;
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        return Err(format!("{} is empty", path.display()));
    }
    Ok(trimmed)
}

fn parse_network(s: &str) -> Result<bitcoin::Network, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "bitcoin" | "mainnet" => Ok(bitcoin::Network::Bitcoin),
        "testnet" => Ok(bitcoin::Network::Testnet),
        "signet" => Ok(bitcoin::Network::Signet),
        "regtest" => Ok(bitcoin::Network::Regtest),
        other => Err(format!(
            "unknown network '{other}' (bitcoin, testnet, signet, regtest)"
        )),
    }
}

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
    /// Print the quorum's public key for one Lock.
    ///
    /// A quorum derives a different key per Lock, from the Lock's own id, so
    /// there is no list to keep. This is what an operator puts in a Lock's
    /// `quorum_pubkey` when building it — derived from the seed rather than
    /// typed, so the key in the Lock is provably the one the coordinator will
    /// sign with.
    QuorumPubkey {
        /// File holding the coordinator's BIP39 quorum seed.
        #[arg(long)]
        seed: PathBuf,
        /// File holding the BIP39 passphrase, if any.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        /// The Lock this key is for.
        #[arg(long)]
        lock_id: String,
    },
    /// Claim a Savings lane by a leaf that is yours — heir or backup device.
    ///
    /// One signature, no ceremony, no counterparty: the leaf is a plain
    /// timelock over your key. What it needs is the delay to have passed, and
    /// the transaction to say so correctly.
    ///
    /// You need the Lock's descriptor — four public keys and two heights —
    /// and your own seed. Nothing secret from the owner.
    Claim {
        /// Claim JSON: the Lock descriptor plus the spend. `-` reads stdin.
        #[arg(long)]
        request: String,
        /// File holding your BIP39 seed phrase.
        #[arg(long)]
        seed: PathBuf,
        /// File holding the BIP39 passphrase, if any.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        /// Derivation index your key sits at.
        #[arg(long, default_value_t = 0)]
        index: u32,
        /// Network the addresses belong to.
        #[arg(long, default_value = "bitcoin")]
        network: String,
        /// Skip the typed confirmation. For scripted testing.
        #[arg(long)]
        no_confirm: bool,
    },
    /// Create this device's seed phrase.
    ///
    /// Entropy comes from the OS CSPRNG. Dice or coin flips, if you supply
    /// them, are **mixed in and never substituted**, so they can only ever make
    /// the result stronger — supplying none, or supplying predictable rolls,
    /// leaves the seed exactly as strong as the OS bytes alone.
    ///
    /// The reason to bother: with one source, nothing can notice it silently
    /// degrading. Coldcard firmware once generated seeds through a PRNG rather
    /// than its hardware TRNG, dropping to about 40 bits with a normal-looking
    /// output distribution, and roughly 1,816 BTC was swept years later. Dice
    /// give a floor that does not depend on any implementation being right.
    Generate {
        /// File of die rolls: digits 1-6, whitespace ignored.
        #[arg(long)]
        dice_file: Option<PathBuf>,
        /// File of coin flips: H/T or 1/0, whitespace ignored.
        #[arg(long)]
        coins_file: Option<PathBuf>,
        /// Also write the phrase here, mode 0600.
        ///
        /// Optional. Writing a seed to disk is itself a risk; the phrase is
        /// printed either way so it can be written down.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Derivation index to report the public key for.
        #[arg(long, default_value_t = 0)]
        index: u32,
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
        Command::QuorumPubkey {
            seed,
            passphrase_file,
            lock_id,
        } => {
            let phrase = read_secret_file(&seed, "seed phrase")?;
            let pass = match &passphrase_file {
                Some(p) => read_secret_file(p, "passphrase")?,
                None => String::new(),
            };
            let pk = ghost_lock::backup_key::quorum_public_key(&phrase, &pass, &lock_id)
                .map_err(|e| e.to_string())?;
            println!("{}", hex::encode(pk.serialize()));
            eprintln!(
                "derived at {} — put this in the Lock's quorum_pubkey",
                ghost_lock::backup_key::quorum_derivation_path(&lock_id)
            );
            Ok(())
        }
        Command::Claim {
            request,
            seed,
            passphrase_file,
            index,
            network,
            no_confirm,
        } => claim(request, seed, passphrase_file, index, &network, no_confirm),
        Command::Generate {
            dice_file,
            coins_file,
            out,
            index,
        } => generate(dice_file, coins_file, out, index),
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

/// What a claimant is handed: the Lock in public terms, plus the spend.
#[derive(serde::Serialize, serde::Deserialize)]
struct ClaimRequest {
    /// The Lock, as four public keys and two heights.
    descriptor: ghost_lock::descriptor::LockDescriptor,
    /// The unsigned spend, base64 PSBT.
    psbt: String,
    /// Which input is the Savings lane.
    input_index: u32,
    /// `backup-recovery` or `inheritance`.
    claim: String,
}

/// Sign a Savings leaf that belongs to the claimant.
#[allow(clippy::too_many_arguments)]
fn claim(
    request: String,
    seed_path: PathBuf,
    passphrase_path: Option<PathBuf>,
    index: u32,
    network: &str,
    no_confirm: bool,
) -> Result<(), String> {
    use ghost_lock::escape::OtherClaim;

    let network = parse_network(network)?;
    let raw = if request == "-" {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)
            .map_err(|e| format!("stdin: {e}"))?;
        s
    } else {
        std::fs::read_to_string(&request).map_err(|e| format!("cannot read {request}: {e}"))?
    };
    let req: ClaimRequest =
        serde_json::from_str(&raw).map_err(|e| format!("claim request is not valid JSON: {e}"))?;

    let kind = match req.claim.trim().to_ascii_lowercase().as_str() {
        "backup-recovery" | "backup" => OtherClaim::BackupRecovery,
        "inheritance" | "heir" => OtherClaim::Inheritance {
            height: req.descriptor.inherit_height,
        },
        other => {
            return Err(format!(
                "unknown claim '{other}' (try backup-recovery or inheritance)"
            ))
        }
    };

    // Rebuild the lane from the descriptor. Derived, not accepted: an address
    // handed over could be anyone's.
    let lane = req
        .descriptor
        .savings_lane(network)
        .map_err(|e| format!("this descriptor does not build a lane: {e}"))?;

    let (summary, psbt, prevouts) =
        ghost_lock::airgap::summarise(&req.psbt, req.input_index, network)
            .map_err(|e| format!("this spend cannot be read: {e}"))?;

    // The input must be the lane the descriptor describes.
    let idx = req.input_index as usize;
    let prev = prevouts
        .get(idx)
        .ok_or_else(|| format!("input {idx} does not exist"))?;
    if prev.script_pubkey != lane.address.script_pubkey() {
        return Err(format!(
            "input {idx} is not this Lock's Savings lane.\n               the lane is: {}\n               the input pays: {}",
            lane.address,
            summary
                .input_address
                .as_deref()
                .unwrap_or("an unrenderable script")
        ));
    }

    println!("{} — {}", kind.label(), lane.address);
    print_summary(&summary);
    match kind {
        OtherClaim::BackupRecovery => println!(
            "\nThis leaf opens {} blocks after the coin was confirmed.",
            ghost_lock::constants::BACKUP_RECOVERY_BLOCKS
        ),
        OtherClaim::Inheritance { height } => {
            println!("\nThis leaf opens at block height {height}.")
        }
    }

    if !no_confirm {
        confirm()?;
    }

    let phrase = read_secret_file(&seed_path, "seed phrase")?;
    let pass = match &passphrase_path {
        Some(p) => read_secret_file(p, "passphrase")?,
        None => String::new(),
    };
    let key =
        ghost_lock::backup_key::secret_key(&phrase, &pass, index).map_err(|e| e.to_string())?;
    let ours = key
        .x_only_public_key(&bitcoin::secp256k1::Secp256k1::new())
        .0;

    // The key must be the one this claim belongs to. Otherwise the leaf is
    // built around somebody else's key and has no control block, which reads
    // as a confusing tree error rather than "wrong index".
    let expected = match kind {
        OtherClaim::BackupRecovery => req.descriptor.backup(),
        OtherClaim::Inheritance { .. } => req.descriptor.heir(),
    }
    .map_err(|e| e.to_string())?;
    if ours != expected {
        return Err(format!(
            "the key at index {index} is not the one this claim is for.\n               yours:    {}\n               expected: {}\n             Either the index is wrong, or this descriptor is for a different person.",
            hex::encode(ours.serialize()),
            hex::encode(expected.serialize())
        ));
    }

    let leaf = kind.leaf(&ours).map_err(|e| e.to_string())?;
    let witness = match kind {
        OtherClaim::BackupRecovery => ghost_lock::escape::sign_escape(
            &lane,
            &leaf,
            ghost_lock::constants::BACKUP_RECOVERY_BLOCKS,
            &key,
            &psbt.unsigned_tx,
            idx,
            &prevouts,
        ),
        OtherClaim::Inheritance { height } => ghost_lock::escape::sign_inheritance(
            &lane,
            &leaf,
            height,
            &key,
            &psbt.unsigned_tx,
            idx,
            &prevouts,
        ),
    }
    .map_err(|e| e.to_string())?;

    let mut signed = psbt;
    signed.inputs[idx].final_script_witness = Some(witness);
    let tx = signed
        .extract_tx()
        .map_err(|e| format!("the claim is signed but the transaction is not complete ({e})"))?;

    println!("\n--- broadcast this ---");
    println!("{}", bitcoin::consensus::encode::serialize_hex(&tx));
    println!("--- end ---");
    Ok(())
}

/// Create a seed phrase, optionally mixing in rolls the operator produced.
fn generate(
    dice_file: Option<PathBuf>,
    coins_file: Option<PathBuf>,
    out: Option<PathBuf>,
    index: u32,
) -> Result<(), String> {
    let mut user = ghost_entropy::UserEntropy::new();

    if let Some(path) = &dice_file {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        for (i, c) in raw.chars().filter(|c| !c.is_whitespace()).enumerate() {
            let face = c
                .to_digit(10)
                .ok_or_else(|| format!("die roll {} is '{c}', not a digit", i + 1))?;
            user.push_die(face as u8)
                .map_err(|e| format!("die roll {}: {e}", i + 1))?;
        }
    }
    if let Some(path) = &coins_file {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        for (i, c) in raw.chars().filter(|c| !c.is_whitespace()).enumerate() {
            match c {
                'h' | 'H' | '1' => user.push_coin(true),
                't' | 'T' | '0' => user.push_coin(false),
                other => return Err(format!("coin flip {} is '{other}'; use H/T or 1/0", i + 1)),
            }
        }
    }

    // `digest` enforces the minimum contribution. That floor is not about
    // safety — mixing means any amount is safe — it is about not letting
    // somebody believe six rolls bought them something.
    let user_digest = if user.is_empty() {
        println!("Entropy: OS CSPRNG only.");
        println!(
            "  You can mix in dice or coin flips with --dice-file / --coins-file.\n  \
             They can only make the seed stronger, never weaker."
        );
        None
    } else {
        let d = user.digest().map_err(|e| e.to_string())?;
        println!(
            "Entropy: OS CSPRNG mixed with {} die rolls and {} coin flips ({:.0} bits of yours).",
            user.die_rolls(),
            user.coin_flips(),
            user.bits()
        );
        println!("  Mixed, never substituted — the OS bytes are still there in full.");
        Some(d)
    };

    let phrase =
        ghost_lock::backup_key::new_phrase(user_digest.as_ref()).map_err(|e| e.to_string())?;
    let pk = ghost_lock::backup_key::public_key(&phrase, "", index).map_err(|e| e.to_string())?;

    println!("\n--- write these words down. They are the only way back. ---");
    for (i, word) in phrase.split_whitespace().enumerate() {
        println!("{:>3}. {word}", i + 1);
    }
    println!("--- end ---");

    println!(
        "\npublic key at {}:",
        ghost_lock::backup_key::derivation_path(index)
    );
    println!("{}", hex::encode(pk.serialize()));
    println!("Register that as the Lock's backup_pubkey.");

    if let Some(path) = &out {
        write_secret_file(path, &phrase)?;
        println!("\nAlso written to {} (mode 0600).", path.display());
        println!("A seed on disk is a seed a backup can copy. The words above are the record.");
    }
    Ok(())
}

/// Write a secret to a new file, owner-readable only.
fn write_secret_file(path: &PathBuf, body: &str) -> Result<(), String> {
    use std::io::Write as _;
    let mut f = std::fs::File::create(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Before the contents, so the window where it is world-readable does
        // not contain a seed.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("cannot secure {}: {e}", path.display()))?;
    }
    f.write_all(body.as_bytes())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    f.write_all(b"\n").ok();
    f.sync_all().ok();
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

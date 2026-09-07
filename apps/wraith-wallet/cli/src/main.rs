//! `wraith` — Wraith Wallet CLI.
//!
//! Thin client that speaks JSON-RPC to a running `wraithd` over a local Unix socket.

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

#[derive(Parser)]
#[command(version, about = "Ghost Wallet CLI", long_about = None)]
struct Cli {
    /// Print the response as JSON instead of human-readable output.
    /// Errors are printed as JSON too (`{"error": {"message": "..."}}`).
    #[arg(long, global = true)]
    json: bool,

    /// Don't auto-spawn `wraithd` if it isn't running. Fail with a
    /// "daemon not running" error instead.
    #[arg(long, global = true)]
    no_spawn: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Round-trip a health request to wraithd.
    Health,
    /// One-shot summary of daemon + ghost-pay + ghost-gsp + active wallet + session.
    Doctor,
    /// Print the daemon's configured environment (URLs, network, paths).
    Env,
    /// One-line-each summary: daemon, doctor pass-rate, active wallet,
    /// balance, lock count, GSP session. Aggregates several IPC calls
    /// into one terminal-friendly view; useful as a `watch` target.
    Status,
    /// Chain backend (ghost-pay) commands.
    Chain {
        #[command(subcommand)]
        sub: ChainCommand,
    },
    /// GSP WebSocket commands.
    Gsp {
        #[command(subcommand)]
        sub: GspCommand,
    },
    /// Wallet (keystore) commands.
    Wallet {
        #[command(subcommand)]
        sub: WalletCommand,
    },
    /// Light wallet commands (on-chain address derivation, balance, send/receive).
    Light {
        #[command(subcommand)]
        sub: LightCommand,
    },
    /// Release / update commands.
    Update {
        #[command(subcommand)]
        sub: UpdateCommand,
    },
    /// Wraith Lite v1 mix subcommands. Two-step flow: `prepare`
    /// drives the protocol up to the `/round-tx` fetch and prints
    /// the unsigned transaction; the user signs out-of-band and
    /// invokes `submit` with the witness hex.
    ///
    Mix {
        #[command(subcommand)]
        sub: MixCommand,
    },
    /// Ghost Lock: one account, four compartments.
    ///
    /// Savings needs your backup device; Spending co-signs with the Wraith
    /// quorum; Cash is yours alone and deliberately not private; Investments
    /// is the one lane the quorum can move without you.
    Lock {
        #[command(subcommand)]
        sub: LockCommand,
    },
    /// Print a shell-completion script to stdout. Pipe into your shell's
    /// completion location, e.g.:
    ///   wraith completions bash > /etc/bash_completion.d/wraith
    ///   wraith completions zsh  > ~/.zfunc/_wraith    # add ~/.zfunc to fpath
    ///   wraith completions fish > ~/.config/fish/completions/wraith.fish
    Completions {
        /// Target shell.
        shell: Shell,
    },
}

#[derive(Subcommand)]
enum MixCommand {
    /// Turn an ordinary coin into exactly one round seat.
    ///
    /// A round has no change output, because a change output would identify
    /// you inside it — so your input has to be worth precisely what a seat
    /// costs. This asks the coordinator that price, picks a fresh address for
    /// the seat coin, and builds the split.
    ///
    /// It stops at an unsigned PSBT. Sign it with `wraith psbt sign` and send
    /// it with `wraith psbt broadcast`, then mix using the resulting output
    /// once it has confirmed.
    ///
    /// Note the split transaction is visible on-chain and marks you as
    /// preparing to mix. That is the cost of not carrying the link into the
    /// round itself, where it would reveal which output was yours.
    PrepareCoin {
        /// HTTP URL of the wraith-coordinator endpoint.
        #[arg(long)]
        coordinator: String,
        /// Fallback coordinator URLs, repeatable.
        #[arg(long = "peer")]
        peers: Vec<String>,
        /// Tier to buy a seat in, e.g. `100k_sats`.
        #[arg(long)]
        tier: String,
        /// BIP86 index for the address that receives the seat.
        #[arg(long)]
        index: Option<u32>,
        /// Mining fee rate for the split, sats/vB.
        #[arg(long, default_value_t = 5)]
        fee_rate: u64,
        /// Highest BIP86 index to scan for spendable UTXOs.
        #[arg(long, default_value_t = 32)]
        scan_max: u32,
    },
    /// Step 1: enrol in a Wraith Lite mix session against
    /// `coordinator_url`, commit the supplied UTXO, run the blind-
    /// sig protocol over `mix_output_address`, and fetch the
    /// assembled unsigned tx. Prints { session_id, unsigned_tx_hex,
    /// input_index, prev_amount_sats } on success.
    Prepare {
        /// HTTP URL of the wraith-coordinator endpoint.
        #[arg(long)]
        coordinator: String,
        /// Optional fallback coordinator URLs. Repeatable. Used in
        /// order if `--coordinator` is unreachable (connection
        /// refused, timeout, DNS-unresolvable). HTTP error responses
        /// from `--coordinator` do NOT trigger failover. See
        /// DESIGN_LITE §7.
        #[arg(long = "coordinator-peer")]
        coordinator_peers: Vec<String>,
        /// Optional SOCKS5 proxy for the /outputs anonymous step
        /// (e.g. `socks5h://127.0.0.1:9050` for Tor).
        #[arg(long)]
        socks5_proxy: Option<String>,
        /// Tier id from /api/v1/pool/discover (e.g. `100k_sats`).
        #[arg(long)]
        tier: String,
        /// Wallet's per-round identity. Free-form; the coordinator
        /// only uses it to dedupe against double-enrolment.
        #[arg(long)]
        ghost_id: String,
        /// UTXO outpoint as `txid:vout`.
        #[arg(long)]
        utxo: String,
        /// UTXO value in satoshis.
        #[arg(long)]
        utxo_value: u64,
        /// UTXO scriptPubKey, hex-encoded.
        #[arg(long)]
        utxo_scriptpubkey: String,
        /// Anonymous destination for the wallet's denom-sized
        /// mixed output. Should NOT be linkable to the input.
        #[arg(long)]
        mix_output_address: String,
    },
    /// Fetch the coordinator's `/api/v1/pool/discover` payload —
    /// network, supported tiers, fee rates. Useful for
    /// debugging "is this coordinator alive and serving the tiers
    /// I expect" before running a real mix.
    Discover {
        /// HTTP URL of the wraith-coordinator endpoint.
        #[arg(long)]
        coordinator: String,
        /// Optional fallback coordinator URLs. Repeatable. Same
        /// connect-error rotation as `mix prepare --coordinator-peer`.
        #[arg(long = "coordinator-peer")]
        coordinator_peers: Vec<String>,
    },
    /// Step 2: submit the signed witness for a previously-prepared
    /// mix session and drive the round to broadcast. Prints
    /// { broadcast_txid, mixed_output_tx_index } on success.
    Submit {
        /// session_id returned by `mix prepare`.
        #[arg(long)]
        session_id: String,
        /// Hex-encoded `bitcoin::Witness` (consensus-encoded
        /// length-prefixed witness stack).
        #[arg(long)]
        witness_hex: String,
    },
    /// One-shot mix: daemon does prepare + sign (using the active
    /// wallet's BIP86 keystore) + submit, all in a single IPC call.
    /// Use when the input UTXO is owned by the active wallet at a
    /// BIP86 derivation index ≤ `--bip86-scan-max`.
    Run {
        #[arg(long)]
        coordinator: String,
        /// Optional fallback coordinator URLs. Repeatable. Same
        /// semantics as `mix prepare --coordinator-peer`.
        #[arg(long = "coordinator-peer")]
        coordinator_peers: Vec<String>,
        #[arg(long)]
        socks5_proxy: Option<String>,
        #[arg(long)]
        tier: String,
        #[arg(long)]
        ghost_id: String,
        #[arg(long)]
        utxo: String,
        #[arg(long)]
        utxo_value: u64,
        #[arg(long)]
        utxo_scriptpubkey: String,
        #[arg(long)]
        mix_output_address: String,
        /// BIP86 derivation index of the wallet key that owns the
        /// input UTXO. Skipped scan when supplied.
        #[arg(long)]
        bip86_index: Option<u32>,
        /// Maximum BIP86 index to scan for a key matching the input
        /// scriptPubKey. Default 1024 (daemon-side).
        #[arg(long)]
        bip86_scan_max: Option<u32>,
    },
}

#[derive(Subcommand)]
enum LockCommand {
    /// Every Lock this wallet remembers.
    List,
    /// Remember a Lock's definition.
    ///
    /// Stores the keys it is built from, not the coins. The lanes are derived
    /// from these every time, so forgetting a Lock never moves money.
    Save {
        /// Optional name, so a list of ids is a list of things.
        #[arg(long)]
        label: Option<String>,
        /// Backup device's x-only key, hex.
        #[arg(long)]
        backup_pubkey: String,
        /// Heir's x-only key, hex.
        #[arg(long)]
        heir_pubkey: String,
        /// Wraith quorum's x-only key, hex.
        #[arg(long)]
        quorum_pubkey: String,
        /// Height the Lock is anchored at — normally the current tip.
        #[arg(long)]
        anchor_height: u32,
        /// Absolute height the inheritance leaf matures at.
        #[arg(long)]
        inherit_height: u32,
        /// BIP86 index for the owner key. Defaults to 0.
        #[arg(long)]
        bip86_index: Option<u32>,
    },
    /// Forget a Lock's definition. The funds stay exactly where they are.
    Forget {
        #[arg(long)]
        lock_id: String,
    },
    /// Show a Lock's four lanes, their addresses and balances.
    Lanes {
        #[arg(long)]
        backup_pubkey: String,
        #[arg(long)]
        heir_pubkey: String,
        #[arg(long)]
        quorum_pubkey: String,
        #[arg(long)]
        anchor_height: u32,
        #[arg(long)]
        inherit_height: u32,
        #[arg(long)]
        bip86_index: Option<u32>,
    },
    /// Where a round should pay to fund one lane privately.
    ///
    /// Prints the address without running anything, for when you want to
    /// drive the round yourself. `lock fund` does both in one step.
    Destination {
        #[arg(long)]
        lock_id: String,
        /// savings, spending or investments. Cash is refused.
        #[arg(long)]
        lane: String,
    },
    /// What leaving alone needs, and whether the coins are old enough.
    ///
    /// Ask before building the transaction: the input's `nSequence` is fixed by
    /// the leaf's delay, and a wrong one is rejected as non-final.
    EscapePlan {
        #[arg(long)]
        lock_id: String,
        /// savings, spending or investments.
        #[arg(long)]
        lane: String,
    },
    /// Sign a lane's escape leaf — leaving alone, after the delay.
    ///
    /// No quorum, no backup device, no ceremony. This is the path that stops a
    /// silent quorum from being the end of the money.
    Escape {
        #[arg(long)]
        lock_id: String,
        #[arg(long)]
        lane: String,
        /// The spend, base64 PSBT, with the nSequence `escape-plan` reported.
        #[arg(long)]
        psbt: String,
        #[arg(long)]
        input_index: u32,
    },
    /// Air-gapped key-path signing, in three steps.
    ///
    /// MuSig2 needs two rounds, so a spend is: begin (carry a request to the
    /// device), nonce (carry the device's reply back, then a second request
    /// out), complete (carry the device's signature back). The device never
    /// receives a bare hash — it gets the whole transaction and derives the
    /// hash itself, so what it shows you and what it signs cannot differ.
    Sign {
        #[command(subcommand)]
        sub: LockSignCommand,
    },
    /// Fund one lane through a round — private entry.
    ///
    /// The round's output IS the lane, so on-chain the deposit looks like any
    /// other round output rather than a transfer from a wallet you are known
    /// to control. Funding a lane directly works too; it just publishes the
    /// link between those coins and the Lock.
    ///
    /// You name the lane, never an address: the daemon derives it from the
    /// remembered Lock, so a typo cannot send a round's proceeds to a
    /// stranger. Cash is refused — it is public by design, so a round would
    /// buy unlinkability the lane discards on arrival.
    Fund {
        /// `lock_id` from `wraith lock list`.
        #[arg(long)]
        lock_id: String,
        /// Lane to fund: savings, spending or investments.
        #[arg(long)]
        lane: String,
        #[arg(long)]
        coordinator: String,
        /// Optional fallback coordinator URLs. Repeatable.
        #[arg(long = "coordinator-peer")]
        coordinator_peers: Vec<String>,
        #[arg(long)]
        socks5_proxy: Option<String>,
        #[arg(long)]
        tier: String,
        #[arg(long)]
        ghost_id: String,
        #[arg(long)]
        utxo: String,
        #[arg(long)]
        utxo_value: u64,
        #[arg(long)]
        utxo_scriptpubkey: String,
        #[arg(long)]
        bip86_index: Option<u32>,
        #[arg(long)]
        bip86_scan_max: Option<u32>,
        /// Smallest anonymity set, in distinct entities, worth signing into.
        /// Stating a floor is a decision; dismissing a dialog is a reflex.
        #[arg(long)]
        min_entities: Option<usize>,
    },
}

#[derive(Subcommand)]
enum LockSignCommand {
    /// Round 1. Review the spend and commit this wallet's nonce.
    ///
    /// Prints what the spend does — check it — and the JSON to carry to the
    /// backup device.
    Begin {
        #[arg(long)]
        lock_id: String,
        /// savings or spending. Cash signs as ordinary single-sig;
        /// Investments has no owner key path.
        #[arg(long)]
        lane: String,
        /// The unsigned spend, base64 PSBT.
        #[arg(long)]
        psbt: String,
        /// Which input belongs to the lane.
        #[arg(long)]
        input_index: u32,
    },
    /// Round 1 reply. Hand back the device's public nonce.
    ///
    /// This wallet signs its own share here, so its nonce is burned durably
    /// before the second payload goes out — no secret nonce is held while you
    /// walk to the device again.
    Nonce {
        #[arg(long)]
        session: String,
        /// The device's public nonce, hex.
        #[arg(long)]
        device_nonce: String,
    },
    /// Round 2 reply. Hand back the device's partial signature.
    Complete {
        #[arg(long)]
        session: String,
        /// The device's partial signature, hex.
        #[arg(long)]
        device_partial: String,
    },
}

#[derive(Subcommand)]
enum ChainCommand {
    /// Query ghost-pay's `/api/v1/status` via wraithd.
    Status,
}

#[derive(Subcommand)]
enum GspCommand {
    /// Open a WebSocket to GSP, send Ping, wait for Pong.
    Ping,
    /// Register the active wallet with GSP (idempotent) and create a session.
    Auth,
    /// Show the daemon's stored GSP session token.
    SessionStatus,
    /// Register the active wallet's BIP-352 scan public key with the GSP so the
    /// server can detect incoming silent payments on its behalf.
    RegisterScanKey,
}

#[derive(Subcommand)]
enum LightCommand {
    /// Derive a fresh BIP86 taproot receive address from the active wallet.
    Receive {
        #[arg(short, long, default_value_t = 0)]
        index: u32,
    },
    /// Show the active wallet's last-known on-chain balance.
    Balance,
    /// List the active wallet's UTXOs.
    Utxos {
        /// Minimum number of confirmations. Default 1.
        #[arg(short = 'c', long, default_value_t = 1)]
        min_confirmations: u32,
    },
    /// Scan ghost-pay's bitcoind for unspent L1 outputs at the
    /// active wallet's BIP86 receive addresses 0..`scan_max_index`.
    /// Each row comes back tagged with the BIP86 derivation index
    /// that produced its address — drop straight into a Wraith mix
    /// request to skip the daemon-side address scan.
    L1Utxos {
        /// Highest BIP86 index to derive. Daemon scans 0..this.
        /// Capped at 1024.
        #[arg(long, default_value_t = 32)]
        scan_max_index: u32,
        /// Minimum number of confirmations. 0 includes mempool.
        #[arg(short = 'c', long, default_value_t = 0)]
        min_confirmations: u32,
    },
    /// Show BIP-352 silent-payment matches detected by the persistent
    /// session's local scanner since `wraith gsp auth` ran.
    Detected,
    /// Stream BIP-352 detections live as they arrive. Holds the connection
    /// open and prints each detection on a new line. Ctrl-C to exit.
    Watch,
    /// Show the active wallet's transaction history.
    History {
        /// Maximum number of transactions to return.
        #[arg(short, long, default_value_t = 50)]
        limit: u32,
        /// Pagination offset.
        #[arg(short, long, default_value_t = 0)]
        offset: u32,
    },
    /// Send an instant L2 payment. Mode is `ghostpay` (the only accepted
    /// value; default). For unlinkable L1 spends use the Mix flow instead.
    Send {
        /// Recipient: a Bitcoin address or a Ghost ID.
        recipient: String,
        /// Amount in satoshis.
        amount_sats: u64,
        /// Payment mode. Only `ghostpay` (instant L2) is supported.
        #[arg(long, default_value = "ghostpay")]
        mode: String,
        /// Optional memo, included with the payment metadata.
        #[arg(long)]
        memo: Option<String>,
        /// Skip the wallet's outbound-broadcast shroud delay for this send.
        /// Equivalent to --shroud-max-ms=0. Use only when latency matters
        /// more than origin-timing privacy.
        #[arg(long, conflicts_with = "shroud_max_ms")]
        immediate: bool,
        /// Override the daemon's default shroud window (ms) for this send.
        /// `0` disables; `n` picks a uniform random delay in `[0, n]`.
        #[arg(long, value_name = "MS")]
        shroud_max_ms: Option<u64>,
    },
}

#[derive(Subcommand)]
enum UpdateCommand {
    /// Fetch the configured release manifest, compare against the running
    /// daemon's version, and report whether an upgrade is available.
    Check {
        /// Override the daemon's configured manifest URL for this call.
        #[arg(long, value_name = "URL")]
        manifest_url: Option<String>,
    },
}

#[derive(Subcommand)]
enum WalletCommand {
    /// Create a fresh wallet under the given name (generates a new BIP39 mnemonic).
    Create {
        name: String,
        /// Roll your own dice (or flip coins) and mix them into the seed.
        ///
        /// Your rolls are combined with this computer's randomness, never
        /// used instead of it, so they can only help: if the operating
        /// system's random source were ever weak, your rolls still stand
        /// between an attacker and your coins. 99 die rolls or 256 coin
        /// flips is a full-strength contribution; 50 rolls / 128 flips is
        /// the minimum accepted.
        #[arg(long)]
        dice: bool,
    },
    /// Import a wallet from an existing BIP-39 mnemonic. Prompts for the words
    /// and a new passphrase. Refuses to overwrite an existing wallet of the
    /// same name.
    Import { name: String },
    /// Unlock the named wallet (becomes active).
    Unlock { name: String },
    /// Lock a wallet by name, or the active one if no name is given.
    Lock { name: Option<String> },
    /// List all on-disk wallets with unlocked / active status.
    List,
    /// Set the active wallet (must already be unlocked).
    Select { name: String },
    /// Show the active wallet's path and unlocked state.
    Status,
    /// Derive a public key at a BIP32 path from the active wallet.
    Derive { path: String },
    /// Show the GSP authentication identity (wallet_id + auth pubkey) of the active wallet.
    AuthInfo,
    /// Show the active wallet's BIP-352 Ghost ID (silent payment receive identity).
    GhostId,
    /// Re-display the BIP39 mnemonic for a named wallet.
    ShowMnemonic { name: String },
    /// Copy the encrypted keystore for `name` to a backup file.
    Export {
        name: String,
        /// Destination path for the backup. Refuses to overwrite existing files.
        to: String,
    },
    /// Install an encrypted keystore from a backup file as wallet `name`.
    Restore {
        name: String,
        /// Source path of the backup file.
        from: String,
    },
}

fn main() -> std::process::ExitCode {
    // Restore default SIGPIPE so `wraith ... | head -1` exits cleanly instead of
    // panicking when the consumer closes the pipe early.
    // Safety: setting SIG_DFL is always sound; we do it before spawning threads.
    // No-op on Windows, which has no SIGPIPE.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL)
    };

    let cli = Cli::parse();

    // Short-circuit shell completions: don't spin up the runtime, don't try
    // to spawn or talk to wraithd. Just emit the script and exit.
    if let Command::Completions { shell } = cli.command {
        let mut cmd = Cli::command();
        // Hardcode "wraith" (the binary name we ship); clap defaults to the
        // package name (wraith-wallet-cli) which would generate completions
        // bound to the wrong word.
        clap_complete::generate(shell, &mut cmd, "wraith", &mut std::io::stdout());
        return std::process::ExitCode::SUCCESS;
    }

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("wraith: failed to start runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    runtime.block_on(client::run(cli.command, cli.json, cli.no_spawn))
}

/// Client side of the wraithd IPC. Talks to the daemon over a
/// cross-platform local socket (Unix-domain socket on unix, named pipe
/// on Windows) via the `interprocess` crate.
mod client {
    use interprocess::local_socket::traits::tokio::Stream as _;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use wraith_wallet_ipc::{Envelope, Request, Response};

    /// Full-duplex IPC stream to the daemon.
    type IpcStream = interprocess::local_socket::tokio::Stream;

    /// Connect to the running `wraithd` over its local IPC endpoint.
    async fn connect_daemon() -> std::io::Result<IpcStream> {
        let name = wraith_wallet_ipc::endpoint_name()?;
        IpcStream::connect(name).await
    }

    use crate::{
        ChainCommand, Command, GspCommand, LightCommand, LockCommand, LockSignCommand, MixCommand,
        UpdateCommand, WalletCommand,
    };

    pub async fn run(command: Command, json: bool, no_spawn: bool) -> std::process::ExitCode {
        // Make sure wraithd is up before constructing the request — the request
        // build for some subcommands (eg. wallet create) prompts for a passphrase,
        // and we want to fail fast on "no daemon" instead of after the user types it.
        if !no_spawn {
            if let Err(e) = ensure_daemon().await {
                if json {
                    let body = serde_json::json!({
                        "error": { "message": format!("auto-spawn: {e}") }
                    });
                    println!("{body}");
                } else {
                    eprintln!("wraith: auto-spawn failed: {e}");
                }
                return std::process::ExitCode::FAILURE;
            }
        }

        // Streaming subcommand: handed off to its own code path so we don't
        // try to render it as a single Response.
        if let Command::Light {
            sub: LightCommand::Watch,
        } = &command
        {
            return run_watch(json).await;
        }

        // Multi-call: private entry chains the lane lookup and the round so
        // the user issues one command. The lookup must come first — the round
        // needs the lane's address as its output, and the daemon refuses a
        // lane a round must not pay into before any coin is committed.
        if let Command::Lock {
            sub: LockCommand::Fund { .. },
        } = &command
        {
            if let Command::Lock {
                sub:
                    LockCommand::Fund {
                        lock_id,
                        lane,
                        coordinator,
                        coordinator_peers,
                        socks5_proxy,
                        tier,
                        ghost_id,
                        utxo,
                        utxo_value,
                        utxo_scriptpubkey,
                        bip86_index,
                        bip86_scan_max,
                        min_entities,
                    },
            } = command
            {
                return run_fund_lock(
                    json,
                    lock_id,
                    lane,
                    coordinator,
                    coordinator_peers,
                    socks5_proxy,
                    tier,
                    ghost_id,
                    utxo,
                    utxo_value,
                    utxo_scriptpubkey,
                    bip86_index,
                    bip86_scan_max,
                    min_entities,
                )
                .await;
            }
        }

        // Multi-call summary: aggregate several IPC round-trips into one
        // terminal-friendly view.
        if matches!(&command, Command::Status) {
            return run_status(json).await;
        }

        let request = match command {
            Command::Health => Request::Health,
            Command::Doctor => Request::Doctor,
            Command::Env => Request::DaemonEnv,
            Command::Chain { sub } => match sub {
                ChainCommand::Status => Request::ChainStatus,
            },
            Command::Gsp { sub } => match sub {
                GspCommand::Ping => Request::GspPing,
                GspCommand::Auth => Request::GspAuth,
                GspCommand::SessionStatus => Request::GspSessionStatus,
                GspCommand::RegisterScanKey => Request::GspRegisterScanKey,
            },
            Command::Light { sub } => match sub {
                LightCommand::Receive { index } => Request::LightReceive { index },
                LightCommand::Balance => Request::LightBalance,
                LightCommand::Utxos { min_confirmations } => {
                    Request::LightUtxos { min_confirmations }
                }
                LightCommand::L1Utxos {
                    scan_max_index,
                    min_confirmations,
                } => Request::LightL1Utxos {
                    scan_max_index,
                    min_confirmations,
                },
                LightCommand::History { limit, offset } => Request::LightHistory { limit, offset },
                LightCommand::Detected => Request::LightDetected,
                LightCommand::Watch => unreachable!("Watch handled above"),
                LightCommand::Send {
                    recipient,
                    amount_sats,
                    mode,
                    memo,
                    immediate,
                    shroud_max_ms,
                } => Request::LightSend {
                    recipient,
                    amount_sats,
                    mode,
                    memo,
                    shroud_max_ms: if immediate { Some(0) } else { shroud_max_ms },
                },
            },
            Command::Update { sub } => match sub {
                UpdateCommand::Check { manifest_url } => Request::CheckForUpdate { manifest_url },
            },
            Command::Wallet { sub } => match sub {
                WalletCommand::Create { name, dice } => {
                    let user_entropy_digest = if dice {
                        match collect_user_entropy() {
                            Ok(d) => Some(d),
                            Err(e) => return io_err(e),
                        }
                    } else {
                        None
                    };
                    match prompt_new_passphrase() {
                        Ok(pass) => Request::WalletCreate {
                            name,
                            passphrase: pass,
                            user_entropy_digest,
                        },
                        Err(e) => return io_err(e),
                    }
                }
                WalletCommand::Import { name } => {
                    let mnemonic = match prompt_mnemonic() {
                        Ok(m) => m,
                        Err(e) => return io_err(e),
                    };
                    let pass = match prompt_new_passphrase() {
                        Ok(p) => p,
                        Err(e) => return io_err(e),
                    };
                    Request::WalletImport {
                        name,
                        mnemonic,
                        passphrase: pass,
                    }
                }
                WalletCommand::Unlock { name } => match prompt_passphrase("passphrase: ") {
                    Ok(pass) => Request::WalletUnlock {
                        name,
                        passphrase: pass,
                    },
                    Err(e) => return io_err(e),
                },
                WalletCommand::Lock { name } => Request::WalletLock { name },
                WalletCommand::List => Request::WalletList,
                WalletCommand::Select { name } => Request::WalletSelect { name },
                WalletCommand::Status => Request::WalletStatus,
                WalletCommand::Derive { path } => Request::WalletDerive { path },
                WalletCommand::AuthInfo => Request::WalletAuthInfo,
                WalletCommand::GhostId => Request::WalletGhostId,
                WalletCommand::ShowMnemonic { name } => match prompt_passphrase("passphrase: ") {
                    Ok(pass) => Request::WalletShowMnemonic {
                        name,
                        passphrase: pass,
                    },
                    Err(e) => return io_err(e),
                },
                WalletCommand::Export { name, to } => Request::WalletExport { name, to_path: to },
                WalletCommand::Restore { name, from } => Request::WalletRestore {
                    name,
                    from_path: from,
                },
            },
            Command::Lock { sub } => match sub {
                LockCommand::List => Request::GhostLockList,
                LockCommand::Save {
                    label,
                    backup_pubkey,
                    heir_pubkey,
                    quorum_pubkey,
                    anchor_height,
                    inherit_height,
                    bip86_index,
                } => Request::GhostLockSave {
                    label,
                    backup_pubkey,
                    heir_pubkey,
                    quorum_pubkey,
                    anchor_height,
                    inherit_height,
                    bip86_index,
                },
                LockCommand::Forget { lock_id } => Request::GhostLockForget { lock_id },
                LockCommand::Lanes {
                    backup_pubkey,
                    heir_pubkey,
                    quorum_pubkey,
                    anchor_height,
                    inherit_height,
                    bip86_index,
                } => Request::GhostLockLanes {
                    backup_pubkey,
                    heir_pubkey,
                    quorum_pubkey,
                    anchor_height,
                    inherit_height,
                    bip86_index,
                },
                LockCommand::Destination { lock_id, lane } => {
                    Request::GhostLockRoundDestination { lock_id, lane }
                }
                LockCommand::EscapePlan { lock_id, lane } => {
                    Request::GhostLockEscapePlan { lock_id, lane }
                }
                LockCommand::Escape {
                    lock_id,
                    lane,
                    psbt,
                    input_index,
                } => Request::GhostLockEscapeSign {
                    lock_id,
                    lane,
                    psbt,
                    input_index,
                },
                LockCommand::Sign { sub } => match sub {
                    LockSignCommand::Begin {
                        lock_id,
                        lane,
                        psbt,
                        input_index,
                    } => Request::GhostLockSignBegin {
                        lock_id,
                        lane,
                        psbt,
                        input_index,
                    },
                    LockSignCommand::Nonce {
                        session,
                        device_nonce,
                    } => Request::GhostLockSignNonce {
                        session,
                        device_nonce,
                    },
                    LockSignCommand::Complete {
                        session,
                        device_partial,
                    } => Request::GhostLockSignComplete {
                        session,
                        device_partial,
                    },
                },
                // Intercepted above: private entry is two calls, not one.
                LockCommand::Fund { .. } => unreachable!("lock fund handled above"),
            },
            Command::Mix { sub } => match sub {
                MixCommand::PrepareCoin {
                    coordinator,
                    peers,
                    tier,
                    index,
                    fee_rate,
                    scan_max,
                } => Request::WraithPrepareCoin {
                    tier_id: tier,
                    coordinator_url: coordinator,
                    coordinator_peers: peers,
                    receive_index: index,
                    fee_rate_sats_per_vb: fee_rate,
                    bip86_scan_max: scan_max,
                },
                MixCommand::Prepare {
                    coordinator,
                    coordinator_peers,
                    socks5_proxy,
                    tier,
                    ghost_id,
                    utxo,
                    utxo_value,
                    utxo_scriptpubkey,
                    mix_output_address,
                } => {
                    let (txid, vout) = match parse_outpoint(&utxo) {
                        Ok(v) => v,
                        Err(e) => {
                            return io_err(std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                e,
                            ));
                        }
                    };
                    Request::WraithMixPrepare {
                        min_entities: None,
                        coordinator_url: coordinator,
                        coordinator_peers,
                        socks5_proxy,
                        tier_id: tier,
                        ghost_id,
                        utxo_txid: txid,
                        utxo_vout: vout,
                        utxo_value_sats: utxo_value,
                        utxo_scriptpubkey_hex: utxo_scriptpubkey,
                        mix_output_address,
                    }
                }
                MixCommand::Discover {
                    coordinator,
                    coordinator_peers,
                } => Request::WraithCoordinatorDiscover {
                    coordinator_url: coordinator,
                    coordinator_peers,
                },
                MixCommand::Submit {
                    session_id,
                    witness_hex,
                } => Request::WraithMixSubmit {
                    session_id,
                    witness_hex,
                },
                MixCommand::Run {
                    coordinator,
                    coordinator_peers,
                    socks5_proxy,
                    tier,
                    ghost_id,
                    utxo,
                    utxo_value,
                    utxo_scriptpubkey,
                    mix_output_address,
                    bip86_index,
                    bip86_scan_max,
                } => {
                    let (txid, vout) = match parse_outpoint(&utxo) {
                        Ok(v) => v,
                        Err(e) => {
                            return io_err(std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                e,
                            ));
                        }
                    };
                    Request::WraithMixOneShot {
                        min_entities: None,
                        coordinator_url: coordinator,
                        coordinator_peers,
                        socks5_proxy,
                        tier_id: tier,
                        ghost_id,
                        utxo_txid: txid,
                        utxo_vout: vout,
                        utxo_value_sats: utxo_value,
                        utxo_scriptpubkey_hex: utxo_scriptpubkey,
                        mix_output_address,
                        bip86_index,
                        bip86_scan_max,
                    }
                }
            },
            // Handled in main() before we reach the runtime; the arm exists
            // here only so the match is exhaustive.
            Command::Completions { .. } => unreachable!("Completions handled in main"),
            Command::Status => unreachable!("Status handled above"),
        };

        let result = call(request).await;

        // --json: emit the full Response (or a synthesized {"error": {...}} on
        // transport failure) and exit. SUCCESS for any non-Error variant,
        // FAILURE for Error / transport problems.
        if json {
            return print_json(&result);
        }

        match result {
            Ok(Response::WraithCoinPrepared(p)) => {
                println!(
                    "seat price:   {} sats — exact, a round has no change output",
                    p.seat_price_sats
                );
                println!(
                    "destination:  {} (index {})",
                    p.destination_address, p.destination_index
                );
                println!(
                    "inputs:       {} totalling {} sats",
                    p.input_count, p.total_input_sats
                );
                println!("change back:  {} sats", p.change_sats);
                println!("mining fee:   {} sats", p.fee_sats);
                println!();
                println!("psbt:");
                println!("{}", p.psbt);
                println!();
                println!("Next: `wraith psbt sign` then `wraith psbt broadcast`.");
                println!(
                    "Once it confirms, mix using the output at {} — that coin is exactly one seat.",
                    p.destination_address
                );
                println!();
                println!(
                    "This split is visible on-chain and marks you as preparing to mix. It does\n\
                     not reveal which output of the round is yours, which carrying the change\n\
                     into the round would."
                );
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::Doctor(d)) => {
                for c in &d.checks {
                    let mark = match c.status.as_str() {
                        "pass" => "  ok ",
                        "fail" => "FAIL ",
                        "skip" => "skip ",
                        _ => "  ?  ",
                    };
                    println!("{mark} {:<14}  {}", c.name, c.detail);
                }
                println!();
                println!(
                    "{}",
                    if d.all_pass {
                        "all checks passed"
                    } else {
                        "one or more checks failed"
                    }
                );
                if d.all_pass {
                    std::process::ExitCode::SUCCESS
                } else {
                    std::process::ExitCode::FAILURE
                }
            }
            Ok(Response::Health(h)) => {
                println!(
                    "wraithd ok — version {} — uptime {}s",
                    h.daemon_version, h.uptime_secs
                );
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::ChainStatus(s)) => {
                println!("ghost-pay {} ({})", s.backend_version, s.network);
                println!(
                    "  keys: {}   locks: {}   active sessions: {}",
                    if s.has_keys { "yes" } else { "no" },
                    s.lock_count,
                    s.active_sessions,
                );
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::GspPing(p)) => {
                match p.round_trip_ms {
                    Some(rtt) => println!(
                        "gsp ok — server_time {} — round-trip {}ms",
                        p.server_time, rtt
                    ),
                    None => println!("gsp ok — server_time {}", p.server_time),
                }
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::GspAuth(a)) => {
                if a.already_registered {
                    println!("(already registered) — session created");
                } else {
                    println!("registered + session created");
                }
                println!("  wallet_id:    {}", a.wallet_id);
                println!("  token (prefix): {}...", a.token_prefix);
                println!("  expires_at:   {}", a.expires_at);
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::GspScanKeyRegistered {
                wallet_id,
                scan_pubkey_hex,
            }) => {
                println!("scan key registered with GSP");
                println!("  wallet_id:   {wallet_id}");
                println!("  scan_pubkey: {scan_pubkey_hex}");
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::GspSessionStatus(s)) => {
                if !s.have_token {
                    println!("(no session — run `wraith gsp auth`)");
                } else {
                    println!("session active");
                    if let Some(n) = s.wallet_name {
                        println!("  wallet:        {n}");
                    }
                    if let Some(id) = s.wallet_id {
                        println!("  wallet_id:     {id}");
                    }
                    if let Some(p) = s.phase {
                        let cnt = s.connect_count.unwrap_or(0);
                        println!("  ws phase:      {p} (connects: {cnt})");
                    }
                    if let Some(err) = s.last_error {
                        println!("  last error:    {err}");
                    }
                    if let Some(rem) = s.remaining_secs {
                        let hours = rem / 3600;
                        let mins = (rem % 3600) / 60;
                        println!("  expires in:    {hours}h {mins}m ({rem}s)");
                    }
                }
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::LightUtxos(u)) => {
                if u.utxos.is_empty() {
                    println!("(no utxos)");
                } else {
                    for x in &u.utxos {
                        let spendable = if x.spendable { " " } else { " *" };
                        println!(
                            "{}:{}  {} sats  ({} confs, {}){}",
                            x.txid,
                            x.vout,
                            x.amount_sats,
                            x.confirmations,
                            x.script_type,
                            spendable
                        );
                    }
                    println!("\ntotal: {} sats ({} utxos)", u.total_sats, u.utxos.len());
                    if u.utxos.iter().any(|x| !x.spendable) {
                        println!("  * = not currently spendable");
                    }
                }
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::LightL1Utxos(u)) => {
                if u.utxos.is_empty() {
                    println!(
                        "(no L1 UTXOs at indices 0..{} — chain height {})",
                        u.scanned_max_index, u.chain_height
                    );
                } else {
                    println!(
                        "L1 UTXOs at indices 0..{} (chain height {})",
                        u.scanned_max_index, u.chain_height
                    );
                    for x in &u.utxos {
                        println!(
                            "  [bip86 {:>3}] {}:{}  {:>15} sats  {} confs  {}",
                            x.bip86_index,
                            x.txid,
                            x.vout,
                            x.amount_sats,
                            x.confirmations,
                            x.address,
                        );
                        println!("              spk={}", x.scriptpubkey_hex);
                    }
                    println!("\ntotal: {} sats ({} utxos)", u.total_sats, u.utxos.len());
                }
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::GhostLockEscapePlan(r)) => {
                println!("{} — {} lane of {}", r.escape, r.lane, r.lock_id);
                println!("  wait:     {} blocks", r.delay_blocks);
                println!(
                    "  nSequence every input must carry: {}",
                    r.required_sequence
                );
                println!("  lane:     {}", r.lane_address);
                if r.coins.is_empty() {
                    println!("\n(no coins in this lane)");
                } else {
                    println!("\ncoins:");
                    for c in &r.coins {
                        if c.blocks_remaining == 0 {
                            println!(
                                "  {}:{}  {} sats  ready now ({} confirmations)",
                                c.txid, c.vout, c.sats, c.confirmations
                            );
                        } else {
                            println!(
                                "  {}:{}  {} sats  {} more blocks (~{:.1} days)",
                                c.txid,
                                c.vout,
                                c.sats,
                                c.blocks_remaining,
                                f64::from(c.blocks_remaining) / 144.0
                            );
                        }
                    }
                }
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::GhostLockEscapeSigned(r)) => {
                println!(
                    "{} signed for the {} lane of {}",
                    r.escape, r.lane, r.lock_id
                );
                println!("\ntransaction (hex) — broadcast this:");
                println!("{}", r.tx_hex);
                println!("\npsbt:");
                println!("{}", r.psbt);
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::GhostLockSignBegun(r)) => {
                let s = &r.summary;
                println!("CHECK THIS BEFORE YOU CARRY ANYTHING ANYWHERE");
                println!(
                    "  spending  {} sats from {}",
                    s.input_sats,
                    s.input_address
                        .as_deref()
                        .unwrap_or("(unrenderable script)")
                );
                if s.input_count > 1 {
                    println!(
                        "  ⚠ this transaction has {} inputs; you are signing input {}",
                        s.input_count, s.input_index
                    );
                }
                for o in &s.outputs {
                    println!(
                        "  paying    {} sats to {}",
                        o.sats,
                        o.address.as_deref().unwrap_or("(unrenderable script)")
                    );
                }
                println!("  fee       {} sats", s.fee_sats);
                println!("\nsession: {}", r.session);
                println!("our nonce: {}", r.our_nonce);
                println!("\n--- carry this to the backup device ---");
                println!("{}", r.device_request);
                println!(
                    "--- then: wraith lock sign nonce --session {} --device-nonce <hex>",
                    r.session
                );
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::GhostLockSignNonced(r)) => {
                println!("this wallet has signed its share; its nonce is burned.");
                println!("\n--- carry this to the backup device ---");
                println!("{}", r.device_request);
                println!(
                    "--- then: wraith lock sign complete --session {} --device-partial <hex>",
                    r.session
                );
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::GhostLockSigned(r)) => {
                println!("signed. the signature verifies against the lane's output key.");
                println!("signature: {}", r.signature);
                println!("\nsigned psbt:");
                println!("{}", r.psbt);
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::GhostLockRoundDestination(d)) => {
                println!("lock:    {}", d.lock_id);
                println!("lane:    {} ({})", d.label, d.lane);
                println!("address: {}", d.address);
                println!("\nfund it with `wraith lock fund`, which runs a round whose");
                println!("output is this address. Paying it directly also works, and");
                println!("publishes the link between those coins and the Lock.");
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::LightDetected(d)) => {
                if d.detections.is_empty() {
                    println!("(no detections — server scanner may not be wired yet,");
                    println!(" or no incoming silent payments since auth)");
                } else {
                    for det in &d.detections {
                        let amt = det
                            .amount_sats
                            .map(|a| format!("{a} sats"))
                            .unwrap_or_else(|| "?".into());
                        let height = det
                            .block_height
                            .map(|h| h.to_string())
                            .unwrap_or_else(|| "(mempool)".into());
                        println!(
                            "{}:{}  {amt}  k={}  height {height}",
                            det.txid, det.vout, det.k
                        );
                    }
                    println!("\n{} detection(s)", d.detections.len());
                }
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::LightHistory(h)) => {
                if h.transactions.is_empty() {
                    println!("(no transactions)");
                } else {
                    for t in &h.transactions {
                        let dir = if t.amount_sats >= 0 { "+" } else { "" };
                        let height = t
                            .block_height
                            .map(|h| h.to_string())
                            .unwrap_or_else(|| "(mempool)".into());
                        let memo = t.memo.as_deref().unwrap_or("");
                        println!(
                            "{}  {dir}{}  {}  height {}  ({} confs){}",
                            t.txid,
                            t.amount_sats,
                            t.tx_type,
                            height,
                            t.confirmations,
                            if memo.is_empty() {
                                String::new()
                            } else {
                                format!("  — {memo}")
                            }
                        );
                    }
                    println!(
                        "\n{} of {} transactions",
                        h.transactions.len(),
                        h.total_count
                    );
                }
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::LightSent(s)) => {
                println!("payment submitted");
                println!("  payment_id: {}", s.payment_id);
                if let Some(tx) = &s.txid {
                    println!("  txid:       {tx}");
                } else {
                    println!("  txid:       (L2 — no on-chain txid)");
                }
                println!("  recipient:  {}", s.recipient);
                println!("  amount:     {} sats", s.amount_sats);
                println!("  fee:        {} sats", s.fee_sats);
                println!("  mode:       {}", s.mode);
                match s.shroud_delay_ms {
                    Some(ms) => println!("  shroud:     held {ms} ms before broadcast"),
                    None => println!("  shroud:     disabled (immediate)"),
                }
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::LightBalance(b)) => {
                match b.confirmed_sats {
                    None => println!("(balance not yet known — session still authenticating?)"),
                    Some(c) => {
                        println!("confirmed:   {c} sats");
                        if let Some(u) = b.unconfirmed_sats {
                            println!("unconfirmed: {u} sats");
                        }
                        if let Some(l) = b.locked_sats {
                            println!("locked:      {l} sats");
                        }
                        if let Some(t) = b.received_at {
                            println!("as of:       unix {t}");
                        }
                    }
                }
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::GhostLockLanes(r)) => {
                println!(
                    "ghost lock: {} sats settled, {} pending (block {})",
                    r.total_sats, r.total_pending_sats, r.chain_height
                );
                if r.custodial_sats > 0 {
                    println!(
                        "  {} sats in Investments — the quorum can move these without you",
                        r.custodial_sats
                    );
                }
                for l in &r.lanes {
                    let mut flags = String::new();
                    if l.quorum_can_spend_alone {
                        flags.push_str("  [custodial]");
                    }
                    if !l.round_eligible {
                        flags.push_str("  [not private]");
                    }
                    println!("  {:<12} {} sats{}", l.label, l.balance_sats, flags);
                    if l.pending_sats > 0 {
                        println!("               +{} pending", l.pending_sats);
                    }
                    println!("               {}", l.address);
                }
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::GhostLockSaved(r)) => {
                println!(
                    "{} {}",
                    if r.created { "saved" } else { "updated" },
                    r.lock.label.as_deref().unwrap_or(&r.lock.lock_id)
                );
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::GhostLockList(r)) => {
                if r.locks.is_empty() {
                    println!("(no Ghost Locks)");
                }
                for l in &r.locks {
                    println!(
                        "{}  {}",
                        l.lock_id,
                        l.label.as_deref().unwrap_or("(unnamed)")
                    );
                }
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::GhostLockForgotten(r)) => {
                // Says what it did NOT do: forgetting a definition leaves the
                // funds exactly where they were.
                if r.existed {
                    println!("forgot {} — funds untouched", r.lock_id);
                } else {
                    println!("no such lock: {}", r.lock_id);
                }
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WraithMixRefused(r)) => {
                println!(
                    "refused: {} distinct entities across {} seats (floor {})",
                    r.report.entities, r.report.seats, r.min_entities
                );
                for reason in &r.reasons {
                    println!("  {reason}");
                }
                if !r.lowering_the_floor_would_help {
                    println!("  the coordinator claimed more than its coins support");
                }
                std::process::ExitCode::FAILURE
            }
            Ok(Response::NodeEndpointsSet(r)) => {
                println!("node endpoints updated (preset: {})", r.preset);
                if !r.ghost_pay_urls.is_empty() {
                    println!("  ghost-pay: {}", r.ghost_pay_urls.join(", "));
                }
                if !r.gsp_urls.is_empty() {
                    println!("  gsp:       {}", r.gsp_urls.join(", "));
                }
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletCreate(c)) => {
                println!("wallet '{}' created at {}", c.name, c.path);
                println!("\nWrite these 24 words down somewhere safe.");
                println!("They are the ONLY way to recover this wallet if the file is lost.\n");
                println!("{}\n", c.mnemonic);
                println!("Wallet '{}' is unlocked and active.", c.name);
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::CheckForUpdate(c)) => {
                if c.up_to_date {
                    println!("up to date — running v{}", c.current_version);
                    println!("  source: {}", c.manifest_url);
                } else if let Some(latest) = &c.latest_version {
                    println!("update available: v{} → v{}", c.current_version, latest);
                    println!("  source: {}", c.manifest_url);
                    if let (Some(t), Some(h)) = (&c.tarball, &c.tarball_sha256) {
                        println!("  tarball: {t}");
                        println!("  sha256:  {h}");
                    }
                } else {
                    // The daemon would have returned Response::Error here, but
                    // be defensive in case the manifest schema ever drifts.
                    println!(
                        "could not determine latest version (running v{})",
                        c.current_version
                    );
                }
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletImported { name, path }) => {
                println!("wallet '{name}' imported at {path}");
                println!("Wallet '{name}' is unlocked and active.");
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletUnlocked) => {
                println!("wallet unlocked and selected as active");
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletLocked { name }) => {
                println!("wallet '{name}' locked");
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletDeleted { name }) => {
                println!("wallet '{name}' deleted");
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletList(l)) => {
                if l.wallets.is_empty() {
                    println!("(no wallets)");
                } else {
                    for w in l.wallets {
                        let mark = if w.active {
                            "*"
                        } else if w.unlocked {
                            "+"
                        } else {
                            " "
                        };
                        println!("{mark} {} ({})", w.name, w.path);
                    }
                    println!("\n  * = active   + = unlocked");
                }
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletSelected { name }) => {
                println!("active wallet is now '{name}'");
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletStatus(s)) => {
                match s.active {
                    Some(n) => {
                        println!("active: {n}");
                        if let Some(p) = s.path {
                            println!("  path:     {p}");
                        }
                        println!("  unlocked: {}", if s.unlocked { "yes" } else { "no" });
                    }
                    None => println!("(no active wallet)"),
                }
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletDerive(d)) => {
                println!("path:       {}", d.path);
                println!("public_key: {}", d.public_key_hex);
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletAuthInfo(a)) => {
                println!("wallet_id:      {}", a.wallet_id);
                println!("auth_public_key: {}", a.auth_public_key_hex);
                println!("derivation:      {}", a.derivation_path);
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletGhostId(g)) => {
                println!("{}", g.ghost_id);
                println!("  network: {}", g.network);
                println!("  scan_pubkey:  {}", g.scan_public_key_hex);
                println!("  spend_pubkey: {}", g.spend_public_key_hex);
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletGlyph(g)) => {
                println!("ghost_id:     {}", g.ghost_id);
                println!("status:       {}", g.status);
                println!("bitmap_hash:  {}", g.bitmap_hash);
                println!("commitment:   {}", g.commitment);
                if let Some(txid) = &g.funding_txid {
                    println!("funding_txid: {txid}");
                }
                if let Some(at) = g.registered_at {
                    println!("registered_at:{at}");
                }
                println!("pixels:       {} bytes", g.pixels.len());
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletGlyphClaimed(r)) => {
                println!("status:       {}", r.status);
                println!("bitmap_hash:  {}", r.bitmap_hash);
                println!("commitment:   {}", r.commitment);
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletGlyphChecked { available }) => {
                println!("available: {available}");
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletShowMnemonic(m)) => {
                println!("WARNING: anyone with these 24 words owns the wallet.\n");
                println!("{}\n", m.mnemonic);
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletExported { name, path, bytes }) => {
                println!("exported wallet '{name}' → {path} ({bytes} bytes)");
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WalletRestored { name, path, bytes }) => {
                println!("restored wallet '{name}' from backup → {path} ({bytes} bytes)");
                println!("run `wraith wallet unlock {name}` to use it");
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::LightReceive(r)) => {
                println!("{}", r.address);
                println!("  index:   {}", r.index);
                println!("  network: {}", r.network);
                println!("  path:    {}", r.derivation_path);
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WraithMixPrepared(p)) => {
                println!("session_id:            {}", p.session_id);
                println!("input_index:           {}", p.input_index);
                println!("prev_amount_sats:      {}", p.prev_amount_sats);
                println!("mixed_output_tx_index: {}", p.mixed_output_tx_index);
                println!("unsigned_tx_hex:");
                println!("  {}", p.unsigned_tx_hex);
                println!();
                println!(
                    "next: sign input {} (amount {}) externally and run:",
                    p.input_index, p.prev_amount_sats
                );
                println!(
                    "  wraith mix submit --session-id {} --witness-hex <HEX>",
                    p.session_id
                );
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WraithMixCompleted(c)) => {
                println!("broadcast_txid:        {}", c.broadcast_txid);
                println!("session_id:            {}", c.session_id);
                println!("mixed_output_tx_index: {}", c.mixed_output_tx_index);
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WraithCoordinatorDiscover(d)) => {
                println!("answered_by:      {}", d.answered_by);
                println!("network:          {}", d.network);
                println!("pool_id:          {}", d.pool_id);
                println!("service_fee_bps:  {}", d.service_fee_bps);
                println!("fill_window_secs: {}", d.fill_window_secs);
                if d.tiers.is_empty() {
                    println!("tiers:            (none)");
                } else {
                    println!("tiers:");
                    for t in &d.tiers {
                        println!(
                            "  {:>10}  denom={:>12} sats  min={}  max={}",
                            t.id, t.denomination_sats, t.min_participants, t.max_participants,
                        );
                    }
                }
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::WraithCoordinatorResolved { endpoint, epoch }) => {
                match endpoint {
                    Some(ep) => println!("endpoint: {ep}"),
                    None => {
                        println!("endpoint: (none — election off/pending; use a manual URL)")
                    }
                }
                if let Some(e) = epoch {
                    println!("epoch:    {e}");
                }
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::Error(e)) => {
                eprintln!("wraithd error: {}", e.message);
                std::process::ExitCode::FAILURE
            }
            Ok(Response::DaemonEnv(e)) => {
                println!("network:      {}", e.network);
                println!("socket:       {}", e.socket_path);
                println!("wallets dir:  {}", e.wallets_dir);
                println!("ghost-pay:    {}", e.ghost_pay_urls.join(", "));
                println!("gsp:          {}", e.gsp_urls.join(", "));
                if let Some(p) = &e.tor_proxy {
                    println!("tor proxy:    {p}");
                } else {
                    println!("tor proxy:    (direct)");
                }
                if e.idle_lock_secs == 0 {
                    println!("idle lock:    disabled");
                } else {
                    println!("idle lock:    {}s", e.idle_lock_secs);
                }
                if e.shroud_max_ms == 0 {
                    println!("shroud:       disabled (immediate broadcast)");
                } else {
                    println!("shroud:       0–{} ms random delay", e.shroud_max_ms);
                }
                match &e.update_manifest_url {
                    Some(u) => println!("update url:   {u}"),
                    None => println!(
                        "update url:   (unset — pass --manifest-url to `wraith update check`)"
                    ),
                }
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::ConnectionStatus(s)) => {
                println!("network:    {}", s.network);
                println!(
                    "ghost-pay:  {}{}",
                    if s.ghost_pay_reachable {
                        "reachable"
                    } else {
                        "unreachable"
                    },
                    s.ghost_pay_version
                        .as_deref()
                        .map(|v| format!(" (v{v})"))
                        .or_else(|| s.ghost_pay_error.as_deref().map(|e| format!(" — {e}")))
                        .unwrap_or_default()
                );
                println!(
                    "gsp:        {}",
                    if s.gsp_connected {
                        "connected"
                    } else {
                        s.gsp_phase.as_deref().unwrap_or("disconnected")
                    }
                );
                match s.chain_height {
                    Some(h) if s.chain_synced => println!("chain:      synced · #{h}"),
                    Some(h) => println!("chain:      syncing · #{h}"),
                    None => println!("chain:      unknown"),
                }
                std::process::ExitCode::SUCCESS
            }
            // Streaming variants are handled in run_watch() and never reach here.
            Ok(Response::Watching) | Ok(Response::PaymentDetected(_)) => {
                eprintln!("wraith: unexpected streaming variant on a one-shot request");
                std::process::ExitCode::FAILURE
            }
            // PSBT and multisig-descriptor commands (WIP): bespoke human-readable
            // output is not wired up yet, so emit the structured response as JSON —
            // the data is fully usable (`--json` produces the same). Replace with
            // per-command formatting when the PSBT/multisig CLI UX is finalised.
            Ok(
                resp @ (Response::WalletXpub(_)
                | Response::MultisigDescriptorInspected(_)
                | Response::MultisigDescriptorSaved(_)
                | Response::MultisigDescriptorList(_)
                | Response::MultisigDescriptorAddresses(_)
                | Response::MultisigDescriptorDeleted { .. }
                | Response::PsbtCreated(_)
                | Response::PsbtSigned(_)
                | Response::PsbtBroadcast(_)
                | Response::PsbtBumped(_)
                | Response::PsbtInspected(_)),
            ) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&resp).unwrap_or_else(|_| format!("{resp:?}"))
                );
                std::process::ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("wraith: {e}");
                std::process::ExitCode::FAILURE
            }
        }
    }

    /// Connect to the wraithd endpoint; if absent, find `wraithd` next to ourselves
    /// and spawn it detached. Polls the endpoint up to ~3 s.
    async fn ensure_daemon() -> Result<(), String> {
        // Fast path: already up.
        if connect_daemon().await.is_ok() {
            return Ok(());
        }

        // Find `wraithd` next to ourselves (`wraithd.exe` on Windows).
        let me = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
        let dir = me
            .parent()
            .ok_or_else(|| "current_exe has no parent dir".to_string())?;
        #[cfg(windows)]
        let daemon_bin = dir.join("wraithd.exe");
        #[cfg(not(windows))]
        let daemon_bin = dir.join("wraithd");
        if !daemon_bin.is_file() {
            return Err(format!(
                "wraithd binary not found at {} (is it built?)",
                daemon_bin.display()
            ));
        }

        // Spawn detached. Stdin/out/err → null so the daemon doesn't keep our
        // terminal alive; environment is inherited so WRAITHD_* vars work.
        let mut cmd = std::process::Command::new(&daemon_bin);
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());

        // Detach from the controlling terminal / console so the daemon
        // outlives the shell that launched it. Unix: start a new session
        // (setsid) so a terminal SIGHUP doesn't kill it. Windows: the
        // DETACHED_PROCESS flag (0x0000_0008) drops the inherited console.
        #[cfg(unix)]
        unsafe {
            use std::os::unix::process::CommandExt;
            cmd.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const DETACHED_PROCESS: u32 = 0x0000_0008;
            cmd.creation_flags(DETACHED_PROCESS);
        }

        cmd.spawn().map_err(|e| format!("spawn wraithd: {e}"))?;

        // Poll for the endpoint. ~3s budget at 60ms each.
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(60)).await;
            if connect_daemon().await.is_ok() {
                return Ok(());
            }
        }
        Err(format!(
            "wraithd did not bind {} within 3s",
            wraith_wallet_ipc::endpoint_display()
        ))
    }

    fn io_err(e: std::io::Error) -> std::process::ExitCode {
        eprintln!("wraith: {e}");
        std::process::ExitCode::FAILURE
    }

    /// Parse a `txid:vout` outpoint string. Used by the `mix prepare`
    /// CLI to take a single `--utxo` arg instead of separate
    /// `--utxo-txid` + `--utxo-vout` args.
    fn parse_outpoint(s: &str) -> Result<(String, u32), String> {
        let (txid, vout) = s
            .rsplit_once(':')
            .ok_or_else(|| format!("expected txid:vout, got '{s}'"))?;
        if txid.len() != 64 {
            return Err(format!(
                "txid must be 64 hex chars; '{txid}' is {}",
                txid.len()
            ));
        }
        let vout: u32 = vout
            .parse()
            .map_err(|e| format!("vout '{vout}' is not a u32: {e}"))?;
        Ok((txid.to_string(), vout))
    }

    fn print_json(result: &Result<Response, String>) -> std::process::ExitCode {
        match result {
            Ok(resp) => {
                let s = serde_json::to_string(resp).unwrap_or_else(|e| {
                    format!("{{\"error\":{{\"message\":\"serialise: {e}\"}}}}")
                });
                println!("{s}");
                if matches!(resp, Response::Error(_)) {
                    std::process::ExitCode::FAILURE
                } else {
                    std::process::ExitCode::SUCCESS
                }
            }
            Err(e) => {
                let body = serde_json::json!({ "error": { "message": e } });
                println!("{body}");
                std::process::ExitCode::FAILURE
            }
        }
    }

    fn prompt_passphrase(prompt: &str) -> std::io::Result<String> {
        use std::io::{BufRead, IsTerminal};
        if std::io::stdin().is_terminal() {
            rpassword::prompt_password(prompt)
        } else {
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line)?;
            Ok(line
                .trim_end_matches('\n')
                .trim_end_matches('\r')
                .to_string())
        }
    }

    /// Collect dice rolls / coin flips and reduce them to a digest.
    ///
    /// The raw sequence never leaves this process: only the digest is sent
    /// to the daemon. The minimum-contribution floor is enforced here, where
    /// the rolls are, which is safe because mixing is one-directional — a
    /// small contribution cannot weaken the seed, it just cannot honestly be
    /// called protection.
    fn collect_user_entropy() -> std::io::Result<String> {
        use std::io::{BufRead, Write};
        use wraith_wallet_core::user_entropy::{UserEntropy, MIN_USER_BITS, RECOMMENDED_USER_BITS};

        println!("{}", wraith_wallet_core::user_entropy::guidance());
        println!();
        println!(
            "Enter die rolls as digits 1-6, or coin flips as h/t. Spaces are fine, and you can\n\
             paste a whole line at once. Type `done` when you have enough, or `cancel` to stop.\n"
        );

        let mut entropy = UserEntropy::new();
        let stdin = std::io::stdin();
        let mut lines = stdin.lock().lines();
        loop {
            print!(
                "  {:.0}/{:.0} bits ({} rolls, {} flips) > ",
                entropy.bits(),
                RECOMMENDED_USER_BITS,
                entropy.die_rolls(),
                entropy.coin_flips()
            );
            std::io::stdout().flush()?;

            let line = match lines.next() {
                Some(l) => l?,
                None => break,
            };
            let trimmed = line.trim().to_ascii_lowercase();
            if trimmed == "cancel" {
                return Err(std::io::Error::other("cancelled"));
            }
            if trimmed == "done" {
                break;
            }

            for ch in trimmed.chars().filter(|c| !c.is_whitespace()) {
                match ch {
                    '1'..='6' => {
                        entropy
                            .push_die(ch as u8 - b'0')
                            .map_err(std::io::Error::other)?;
                    }
                    'h' => entropy.push_coin(true),
                    't' => entropy.push_coin(false),
                    other => {
                        println!("  ignoring '{other}' — expected 1-6, h or t");
                    }
                }
            }
        }

        // Report before refusing, so a user who stopped early can see how
        // close they were rather than just being told no.
        if entropy.bits() < MIN_USER_BITS {
            let (rolls, flips) = entropy.remaining_for(MIN_USER_BITS);
            return Err(std::io::Error::other(format!(
                "only {:.0} bits supplied; {:.0} is the minimum ({rolls} more rolls or \
                 {flips} more flips). Re-run without --dice to create the wallet from the \
                 operating system's randomness alone, which is what happens by default.",
                entropy.bits(),
                MIN_USER_BITS
            )));
        }
        if entropy.bits() < RECOMMENDED_USER_BITS {
            println!(
                "  note: {:.0} bits is accepted, but {:.0} matches the strength of the seed \
                 it mixes into.",
                entropy.bits(),
                RECOMMENDED_USER_BITS
            );
        }

        let digest = entropy.digest().map_err(std::io::Error::other)?;
        println!(
            "  mixing {:.0} bits of your own entropy into the seed.\n",
            entropy.bits()
        );
        Ok(hex::encode(digest))
    }

    fn prompt_new_passphrase() -> std::io::Result<String> {
        let pass = prompt_passphrase("new passphrase: ")?;
        if pass.is_empty() {
            return Err(std::io::Error::other("passphrase must not be empty"));
        }
        if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            let again = prompt_passphrase("repeat passphrase: ")?;
            if pass != again {
                return Err(std::io::Error::other("passphrases do not match"));
            }
        }
        Ok(pass)
    }

    /// Reads a BIP-39 mnemonic from stdin. We don't echo it (treat as secret),
    /// so it goes through rpassword on a TTY; on a pipe we just read a line.
    /// Whitespace is normalised to a single space so users can paste from any
    /// line wrapping.
    fn prompt_mnemonic() -> std::io::Result<String> {
        let raw = prompt_passphrase("mnemonic (12 or 24 words): ")?;
        let words: Vec<&str> = raw.split_whitespace().collect();
        if words.len() != 12 && words.len() != 24 {
            return Err(std::io::Error::other(format!(
                "expected 12 or 24 words, got {}",
                words.len()
            )));
        }
        Ok(words.join(" "))
    }

    async fn call(request: Request) -> Result<Response, String> {
        let stream = connect_daemon().await.map_err(|e| {
            format!(
                "could not connect to wraithd at {}: {e} \
                 (is the daemon running?)",
                wraith_wallet_ipc::endpoint_display()
            )
        })?;
        let (reader, mut writer) = stream.split();
        let mut line = serde_json::to_string(&Envelope::new(1, request))
            .map_err(|e| format!("failed to serialise request: {e}"))?;
        line.push('\n');
        writer
            .write_all(line.as_bytes())
            .await
            .map_err(|e| format!("write failed: {e}"))?;
        writer
            .shutdown()
            .await
            .map_err(|e| format!("shutdown failed: {e}"))?;
        let mut response_line = String::new();
        BufReader::new(reader)
            .read_line(&mut response_line)
            .await
            .map_err(|e| format!("read failed: {e}"))?;
        let envelope: Envelope<Response> =
            serde_json::from_str(&response_line).map_err(|e| format!("malformed response: {e}"))?;
        Ok(envelope.payload)
    }

    /// Private entry: fund one lane of a remembered Lock through a round.
    ///
    /// Two calls, in this order for a reason. `GhostLockRoundDestination`
    /// resolves the lane to an address AND applies the compartment rule, so a
    /// lane a round must not pay into is refused before a coin is registered
    /// anywhere. Only then is the round run, with that address as its output.
    ///
    /// The address is never taken from the user. The whole property being
    /// bought here is that the round's output belongs to the Lock; letting a
    /// caller supply the destination would make "fund my Savings privately"
    /// and "send my coins to this address" the same command.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn run_fund_lock(
        json: bool,
        lock_id: String,
        lane: String,
        coordinator: String,
        coordinator_peers: Vec<String>,
        socks5_proxy: Option<String>,
        tier: String,
        ghost_id: String,
        utxo: String,
        utxo_value: u64,
        utxo_scriptpubkey: String,
        bip86_index: Option<u32>,
        bip86_scan_max: Option<u32>,
        min_entities: Option<usize>,
    ) -> std::process::ExitCode {
        let (txid, vout) = match parse_outpoint(&utxo) {
            Ok(v) => v,
            Err(e) => return io_err(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)),
        };

        if !json {
            println!("[1/2] resolving {lane} lane of {lock_id}");
        }
        let dest = match call(Request::GhostLockRoundDestination {
            lock_id: lock_id.clone(),
            lane: lane.clone(),
        })
        .await
        {
            Ok(Response::GhostLockRoundDestination(d)) => d,
            Ok(Response::Error(e)) => return fund_lock_err(json, e.message),
            Ok(other) => return fund_lock_err(json, format!("unexpected response {other:?}")),
            Err(e) => return fund_lock_err(json, e),
        };
        if !json {
            println!("      {} → {}", dest.label, dest.address);
        }

        if !json {
            println!("[2/2] running round; its output funds the lane");
        }
        let mixed = match call(Request::WraithMixOneShot {
            coordinator_url: coordinator,
            coordinator_peers,
            socks5_proxy,
            tier_id: tier,
            ghost_id,
            utxo_txid: txid,
            utxo_vout: vout,
            utxo_value_sats: utxo_value,
            utxo_scriptpubkey_hex: utxo_scriptpubkey,
            mix_output_address: dest.address.clone(),
            bip86_index,
            bip86_scan_max,
            min_entities,
        })
        .await
        {
            Ok(Response::WraithMixCompleted(m)) => m,
            Ok(Response::Error(e)) => return fund_lock_err(json, e.message),
            Ok(other) => return fund_lock_err(json, format!("unexpected response {other:?}")),
            Err(e) => return fund_lock_err(json, e),
        };

        if json {
            let body = serde_json::json!({
                "lock_id": dest.lock_id,
                "lane": dest.lane,
                "address": dest.address,
                "session_id": mixed.session_id,
                "broadcast_txid": mixed.broadcast_txid,
                "mixed_output_tx_index": mixed.mixed_output_tx_index,
            });
            println!("{body}");
        } else {
            println!("      txid:   {}", mixed.broadcast_txid);
            println!("      vout:   {}", mixed.mixed_output_tx_index);
            println!(
                "done. {} of {} is funded; the deposit is a round output, not a transfer.",
                dest.label, dest.lock_id
            );
            println!("      it will show as pending until the round transaction confirms.");
        }
        std::process::ExitCode::SUCCESS
    }

    /// Failure path for `run_fund_lock`, matching the CLI's `--json` contract.
    fn fund_lock_err(json: bool, msg: String) -> std::process::ExitCode {
        if json {
            let body = serde_json::json!({ "error": { "message": msg } });
            println!("{body}");
        } else {
            eprintln!("wraith: {msg}");
        }
        std::process::ExitCode::FAILURE
    }

    /// Multi-call status summary. Issues a few cheap requests in sequence and
    /// renders one line per facet. With --json, dumps the consolidated map
    /// instead so it's machine-readable.
    pub(crate) async fn run_status(json: bool) -> std::process::ExitCode {
        let health = call(Request::Health).await;
        let env_resp = call(Request::DaemonEnv).await;
        let wallets = call(Request::WalletList).await;
        let session = call(Request::GspSessionStatus).await;
        let balance = call(Request::LightBalance).await;

        if json {
            let body = serde_json::json!({
                "health":  result_value(&health),
                "env":     result_value(&env_resp),
                "wallets": result_value(&wallets),
                "session": result_value(&session),
                "balance": result_value(&balance),
            });
            println!("{body}");
            return std::process::ExitCode::SUCCESS;
        }

        // daemon row
        match &health {
            Ok(Response::Health(h)) => {
                let secs = h.uptime_secs;
                let pretty = if secs < 60 {
                    format!("{secs}s")
                } else if secs < 3600 {
                    format!("{}m {}s", secs / 60, secs % 60)
                } else {
                    format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
                };
                println!("daemon:   v{} — uptime {pretty}", h.daemon_version);
            }
            _ => println!("daemon:   unreachable"),
        }
        // env: just show the network so a user can spot \"oh I'm on signet\"
        if let Ok(Response::DaemonEnv(e)) = &env_resp {
            println!("network:  {}", e.network);
        }
        // wallet row — picks out the active one
        match &wallets {
            Ok(Response::WalletList(l)) => {
                if let Some(active) = l.wallets.iter().find(|w| w.active) {
                    println!("wallet:   {} (unlocked, active)", active.name);
                } else if let Some(any) = l.wallets.first() {
                    println!(
                        "wallet:   {} (locked) — {} total",
                        any.name,
                        l.wallets.len()
                    );
                } else {
                    println!("wallet:   (none — `wraith wallet create <name>`)");
                }
            }
            _ => println!("wallet:   error"),
        }
        // balance row — only meaningful if we have a session
        match &balance {
            Ok(Response::LightBalance(b)) => {
                let confirmed = b.confirmed_sats.unwrap_or(0);
                let unconfirmed = b.unconfirmed_sats.unwrap_or(0);
                if unconfirmed > 0 {
                    println!("balance:  {confirmed} sat ({unconfirmed} unconfirmed)");
                } else {
                    println!("balance:  {confirmed} sat");
                }
            }
            Ok(Response::Error(_)) | Err(_) => {
                println!("balance:  (no session — `wraith gsp auth`)");
            }
            _ => {}
        }
        // session row
        match &session {
            Ok(Response::GspSessionStatus(s)) if s.have_token => {
                let remaining = s.remaining_secs.unwrap_or(0).max(0);
                let pretty = if remaining < 60 {
                    format!("{remaining}s")
                } else if remaining < 3600 {
                    format!("{}m {}s", remaining / 60, remaining % 60)
                } else {
                    format!("{}h {}m", remaining / 3600, (remaining % 3600) / 60)
                };
                let wallet = s.wallet_name.as_deref().unwrap_or("(unknown)");
                let phase = s.phase.as_deref().unwrap_or("?");
                println!("session:  {wallet} — {phase} — expires in {pretty}");
            }
            Ok(Response::GspSessionStatus(_)) => println!("session:  (none)"),
            _ => println!("session:  (none)"),
        }
        std::process::ExitCode::SUCCESS
    }

    fn result_value(r: &Result<Response, String>) -> serde_json::Value {
        match r {
            Ok(resp) => serde_json::to_value(resp).unwrap_or(serde_json::Value::Null),
            Err(e) => serde_json::json!({"error": e}),
        }
    }

    /// Streaming subscriber for `Request::WatchPayments`. Connects, sends the
    /// request, expects a `Response::Watching` ack, then prints each
    /// `Response::PaymentDetected` line until the daemon closes the stream
    /// (or the user hits Ctrl-C). With `--json`, every line is the raw
    /// envelope JSON exactly as the daemon emits it.
    pub(crate) async fn run_watch(json: bool) -> std::process::ExitCode {
        let stream = match connect_daemon().await {
            Ok(s) => s,
            Err(e) => {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"error": {"message": format!("connect: {e}")}})
                    );
                } else {
                    eprintln!(
                        "wraith: could not connect to wraithd at {}: {e}",
                        wraith_wallet_ipc::endpoint_display()
                    );
                }
                return std::process::ExitCode::FAILURE;
            }
        };
        let (reader, mut writer) = stream.split();
        let req = Envelope::new(1, Request::WatchPayments);
        let mut line = match serde_json::to_string(&req) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("wraith: serialise: {e}");
                return std::process::ExitCode::FAILURE;
            }
        };
        line.push('\n');
        if let Err(e) = writer.write_all(line.as_bytes()).await {
            eprintln!("wraith: write: {e}");
            return std::process::ExitCode::FAILURE;
        }
        let mut reader = BufReader::new(reader);
        if !json {
            eprintln!("wraith: watching for silent-payment detections (Ctrl-C to stop)");
        }
        loop {
            let mut buf = String::new();
            match reader.read_line(&mut buf).await {
                Ok(0) => return std::process::ExitCode::SUCCESS,
                Ok(_) => {
                    if json {
                        print!("{buf}");
                        continue;
                    }
                    let env: Envelope<Response> = match serde_json::from_str(&buf) {
                        Ok(e) => e,
                        Err(e) => {
                            eprintln!("wraith: malformed push: {e}; raw={buf}");
                            continue;
                        }
                    };
                    match env.payload {
                        Response::Watching => {} // ack — keep waiting
                        Response::PaymentDetected(d) => {
                            let height = d
                                .block_height
                                .map(|h| h.to_string())
                                .unwrap_or_else(|| "—".to_string());
                            let amt = d
                                .amount_sats
                                .map(|a| a.to_string())
                                .unwrap_or_else(|| "?".to_string());
                            println!(
                                "{} sat  height={}  vout={}  k={}  txid={}",
                                amt, height, d.vout, d.k, d.txid
                            );
                        }
                        Response::Error(e) => {
                            eprintln!("wraith: daemon error: {}", e.message);
                            return std::process::ExitCode::FAILURE;
                        }
                        other => {
                            eprintln!("wraith: unexpected push variant: {other:?}");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("wraith: read: {e}");
                    return std::process::ExitCode::FAILURE;
                }
            }
        }
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    /// clap's own validity check: duplicate flags, bad names, conflicting
    /// shorts. Cheap, and it fails at test time rather than on first run.
    #[test]
    fn the_command_tree_is_well_formed() {
        Cli::command().debug_assert();
    }

    /// Every Lock subcommand parses.
    ///
    /// This exists because the CLI shipped with four `GhostLock*` response
    /// renderers and no commands that could produce them — the wallet could
    /// format a lock list it had no way to ask for, and a help string pointed
    /// at a `lock-list` command that did not exist. Nothing caught it because
    /// nothing parsed the tree. This does.
    #[test]
    fn every_lock_subcommand_parses() {
        let cases: Vec<Vec<&str>> = vec![
            vec!["wraith", "lock", "list"],
            vec!["wraith", "lock", "forget", "--lock-id", "abc"],
            vec![
                "wraith",
                "lock",
                "destination",
                "--lock-id",
                "abc",
                "--lane",
                "savings",
            ],
            vec![
                "wraith",
                "lock",
                "save",
                "--backup-pubkey",
                "aa",
                "--heir-pubkey",
                "bb",
                "--quorum-pubkey",
                "cc",
                "--anchor-height",
                "1",
                "--inherit-height",
                "2",
            ],
            vec![
                "wraith",
                "lock",
                "lanes",
                "--backup-pubkey",
                "aa",
                "--heir-pubkey",
                "bb",
                "--quorum-pubkey",
                "cc",
                "--anchor-height",
                "1",
                "--inherit-height",
                "2",
            ],
            vec![
                "wraith",
                "lock",
                "fund",
                "--lock-id",
                "abc",
                "--lane",
                "savings",
                "--coordinator",
                "http://127.0.0.1:9100",
                "--tier",
                "1m_sats",
                "--ghost-id",
                "g",
                "--utxo",
                "aa:0",
                "--utxo-value",
                "1000000",
                "--utxo-scriptpubkey",
                "5120aa",
            ],
        ];
        for argv in cases {
            let joined = argv.join(" ");
            Cli::try_parse_from(&argv).unwrap_or_else(|e| panic!("`{joined}` must parse: {e}"));
        }
    }

    /// The escape subcommands parse.
    #[test]
    fn the_escape_commands_parse() {
        let cases: Vec<Vec<&str>> = vec![
            vec![
                "wraith",
                "lock",
                "escape-plan",
                "--lock-id",
                "a",
                "--lane",
                "spending",
            ],
            vec![
                "wraith",
                "lock",
                "escape",
                "--lock-id",
                "a",
                "--lane",
                "investments",
                "--psbt",
                "cHNidP8=",
                "--input-index",
                "0",
            ],
        ];
        for argv in cases {
            let joined = argv.join(" ");
            Cli::try_parse_from(&argv).unwrap_or_else(|e| panic!("`{joined}` must parse: {e}"));
        }
    }

    /// The three signing steps parse, so the flow cannot ship half-wired.
    #[test]
    fn every_sign_step_parses() {
        let cases: Vec<Vec<&str>> = vec![
            vec![
                "wraith",
                "lock",
                "sign",
                "begin",
                "--lock-id",
                "a",
                "--lane",
                "savings",
                "--psbt",
                "cHNidP8=",
                "--input-index",
                "0",
            ],
            vec![
                "wraith",
                "lock",
                "sign",
                "nonce",
                "--session",
                "aa",
                "--device-nonce",
                "bb",
            ],
            vec![
                "wraith",
                "lock",
                "sign",
                "complete",
                "--session",
                "aa",
                "--device-partial",
                "bb",
            ],
        ];
        for argv in cases {
            let joined = argv.join(" ");
            Cli::try_parse_from(&argv).unwrap_or_else(|e| panic!("`{joined}` must parse: {e}"));
        }
    }

    /// The lane names the CLI documents are the ones the daemon accepts.
    ///
    /// Kept as a literal list rather than derived, because the daemon parses
    /// these from a string: if someone renames a lane on one side only, this
    /// is the thing that notices.
    #[test]
    fn the_documented_lanes_are_the_daemon_s_lanes() {
        for lane in ["savings", "spending", "investments", "cash"] {
            let argv = vec![
                "wraith",
                "lock",
                "destination",
                "--lock-id",
                "a",
                "--lane",
                lane,
            ];
            Cli::try_parse_from(&argv).unwrap_or_else(|e| panic!("lane `{lane}`: {e}"));
        }
    }
}

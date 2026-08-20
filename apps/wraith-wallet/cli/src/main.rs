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
    /// Ghost Locks (custody primitive) commands.
    Locks {
        #[command(subcommand)]
        sub: LocksCommand,
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
enum LocksCommand {
    /// List all Ghost Locks for the active wallet.
    List,
    /// Ask GSP to prepare a new ghost lock — returns a funding address.
    Prepare {
        /// Capacity of the lock in satoshis.
        capacity_sats: u64,
    },
    /// Confirm that a prepared lock has been funded on-chain.
    Confirm {
        lock_id: String,
        funding_txid: String,
    },
    /// Initiate a jump (key rotation) for an existing lock.
    Jump {
        lock_id: String,
        /// Target address for the new lock.
        target_address: String,
        /// Priority: normal (default), high, or urgent.
        #[arg(long, default_value = "normal")]
        priority: String,
    },
    /// Prepare a lock AND fund it through a Wraith CoinJoin in one
    /// shot. The mix's denom output is the lock's funding output, so
    /// chain analysts see a CoinJoin — they cannot tell which output
    /// became which user's L2 entry. This is the private-entry path
    /// that distinguishes Ghost Locks from typical L2 funding (where
    /// the channel-open tx is a chain-analysis goldmine).
    ///
    /// CLI chains three IPC calls under the hood:
    ///   1. LocksPrepare(capacity_sats)               → funding_address
    ///   2. WraithMixOneShot(mix_output=funding_addr) → broadcast_txid
    ///   3. LocksConfirm(lock_id, broadcast_txid)     → block_height
    ///
    PrepareViaWraith {
        /// Lock capacity in satoshis. Must match a Wraith Lite tier
        /// denomination (100k_sats / 1m_sats / 10m_sats / 100m_sats).
        #[arg(long)]
        capacity_sats: u64,
        /// HTTP URL of the wraith-coordinator endpoint.
        #[arg(long)]
        coordinator: String,
        /// Wraith Lite tier id matching `capacity_sats`.
        #[arg(long)]
        tier: String,
        /// Wallet's per-round identity for the wraith coordinator.
        #[arg(long)]
        ghost_id: String,
        /// Optional SOCKS5 proxy for the /outputs anonymous step
        /// (e.g. `socks5h://127.0.0.1:9050` for Tor).
        #[arg(long)]
        socks5_proxy: Option<String>,
        /// UTXO outpoint feeding the mix as `txid:vout`.
        #[arg(long)]
        utxo: String,
        /// UTXO value in satoshis.
        #[arg(long)]
        utxo_value: u64,
        /// UTXO scriptPubKey, hex.
        #[arg(long)]
        utxo_scriptpubkey: String,
        /// Optional BIP86 derivation index of the wallet key that
        /// owns the input UTXO. None → daemon scans 0..1024.
        #[arg(long)]
        bip86_index: Option<u32>,
    },
    /// Unilateral exit — spend a Ghost Lock via the timelock recovery
    /// branch to a wallet-controlled L1 destination, without any
    /// operator cooperation. Daemon talks straight to bitcoind. Only
    /// works once the lock's CSV timelock has matured (current height
    /// >= creation_height + recovery_blocks).
    Recover {
        /// Lock to recover.
        #[arg(long)]
        lock_id: String,
        /// L1 destination address for the recovered funds.
        #[arg(long, value_name = "ADDR")]
        to: String,
        /// Mining fee in sats. Subtracted from the lock value.
        #[arg(long, default_value_t = 1000)]
        fee_sats: u64,
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
        ChainCommand, Command, GspCommand, LightCommand, LocksCommand, MixCommand, UpdateCommand,
        WalletCommand,
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

        // Multi-call summary: aggregate several IPC round-trips into one
        // terminal-friendly view.
        if matches!(&command, Command::Status) {
            return run_status(json).await;
        }

        // Multi-call entry-via-wraith flow: chains LocksPrepare →
        // WraithMixOneShot → LocksConfirm under the hood, so the
        // user sees one command.
        if let Command::Locks {
            sub: LocksCommand::PrepareViaWraith { .. },
        } = &command
        {
            if let Command::Locks {
                sub:
                    LocksCommand::PrepareViaWraith {
                        capacity_sats,
                        coordinator,
                        tier,
                        ghost_id,
                        socks5_proxy,
                        utxo,
                        utxo_value,
                        utxo_scriptpubkey,
                        bip86_index,
                    },
            } = command
            {
                return run_prepare_via_wraith(
                    json,
                    capacity_sats,
                    coordinator,
                    tier,
                    ghost_id,
                    socks5_proxy,
                    utxo,
                    utxo_value,
                    utxo_scriptpubkey,
                    bip86_index,
                )
                .await;
            }
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
            Command::Locks { sub } => match sub {
                LocksCommand::List => Request::LocksList,
                LocksCommand::Prepare { capacity_sats } => Request::LocksPrepare { capacity_sats },
                LocksCommand::Confirm {
                    lock_id,
                    funding_txid,
                } => Request::LocksConfirm {
                    lock_id,
                    funding_txid,
                },
                LocksCommand::Jump {
                    lock_id,
                    target_address,
                    priority,
                } => Request::LocksJump {
                    lock_id,
                    target_address,
                    priority,
                },
                LocksCommand::Recover {
                    lock_id,
                    to,
                    fee_sats,
                } => Request::LocksRecover {
                    lock_id,
                    destination_address: to,
                    fee_sats,
                },
                // Multi-call flow — handled before this match in
                // run() proper. The arm exists only so the match
                // is exhaustive.
                LocksCommand::PrepareViaWraith { .. } => {
                    unreachable!("PrepareViaWraith handled by run_prepare_via_wraith")
                }
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
            Ok(Response::LocksPrepared(r)) => {
                println!("lock prepared");
                println!("  lock_id:         {}", r.lock_id);
                println!("  funding address: {}", r.funding_address);
                println!("  required:        {} sats", r.required_sats);
                println!();
                println!(
                    "Send {} sats to the address above, then run:",
                    r.required_sats
                );
                println!("  wraith locks confirm {} <funding_txid>", r.lock_id);
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::LocksConfirmed(r)) => {
                println!("lock confirmed");
                println!("  lock_id:      {}", r.lock_id);
                println!("  funding txid: {}", r.txid);
                println!("  block height: {}", r.block_height);
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::LocksJumped(r)) => {
                println!("jump initiated");
                println!("  lock_id:   {}", r.lock_id);
                match r.jump_txid {
                    Some(tx) => println!("  jump txid: {tx}"),
                    None => println!("  jump txid: (queued — not yet broadcast)"),
                }
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::LocksRecovered(r)) => {
                println!("✓ unilateral exit broadcast — funds back on L1");
                println!("  lock_id:        {}", r.lock_id);
                println!("  broadcast_txid: {}", r.broadcast_txid);
                println!("  destination:    {}", r.destination_address);
                println!("  recovered_sats: {}", r.recovered_sats);
                println!("  fee_sats:       {}", r.fee_sats);
                std::process::ExitCode::SUCCESS
            }
            Ok(Response::LocksList(r)) => {
                if r.locks.is_empty() {
                    println!("(no locks)");
                } else {
                    for l in &r.locks {
                        println!(
                            "{}  {}  {} / {} sats  ({})",
                            &l.lock_id[..16.min(l.lock_id.len())],
                            l.status,
                            l.balance_sats,
                            l.capacity_sats,
                            l.denomination,
                        );
                        println!("  funding: {}", l.funding_address);
                        if let (Some(txid), Some(vout)) = (&l.funding_txid, l.funding_vout) {
                            println!("  outpoint: {txid}:{vout}");
                        }
                    }
                    println!(
                        "\n{} locks  total: {} sats",
                        r.locks.len(),
                        r.total_locked_sats
                    );
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

    /// `wraith locks prepare-via-wraith` flow. Three IPC calls under
    /// the hood:
    ///   1. LocksPrepare(capacity_sats)               → funding_address + lock_id
    ///   2. WraithMixOneShot(mix_output=funding_addr) → broadcast_txid
    ///   3. LocksConfirm(lock_id, broadcast_txid)     → block_height
    ///
    /// Stops at the first error and surfaces it to the user. The
    /// printed step-by-step trail makes it obvious which phase
    /// broke if the operator/coordinator misbehaves mid-flight.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn run_prepare_via_wraith(
        json: bool,
        capacity_sats: u64,
        coordinator: String,
        tier: String,
        ghost_id: String,
        socks5_proxy: Option<String>,
        utxo: String,
        utxo_value: u64,
        utxo_scriptpubkey: String,
        bip86_index: Option<u32>,
    ) -> std::process::ExitCode {
        let (txid, vout) = match parse_outpoint(&utxo) {
            Ok(v) => v,
            Err(e) => {
                return io_err(std::io::Error::new(std::io::ErrorKind::InvalidInput, e));
            }
        };

        // Phase 1: prepare the lock.
        if !json {
            println!("[1/3] preparing lock ({capacity_sats} sats)");
        }
        let prep = match call(Request::LocksPrepare { capacity_sats }).await {
            Ok(Response::LocksPrepared(p)) => p,
            Ok(Response::Error(e)) => {
                return error_out(json, format!("LocksPrepare: {}", e.message))
            }
            Ok(other) => {
                return error_out(json, format!("LocksPrepare: unexpected response {other:?}"))
            }
            Err(e) => return error_out(json, format!("LocksPrepare: {e}")),
        };
        if !json {
            println!("      lock_id:         {}", prep.lock_id);
            println!("      funding_address: {}", prep.funding_address);
        }

        // Phase 2: run the wraith mix with the lock's funding address
        // as the mix output. The CoinJoin's denom output IS the
        // lock's funding output — the on-chain footprint is
        // indistinguishable from any other Wraith mix.
        if !json {
            println!("[2/3] running wraith mix → {}", prep.funding_address);
        }
        let mix = match call(Request::WraithMixOneShot {
            coordinator_url: coordinator,
            coordinator_peers: Vec::new(),
            socks5_proxy,
            tier_id: tier,
            ghost_id,
            utxo_txid: txid,
            utxo_vout: vout,
            utxo_value_sats: utxo_value,
            utxo_scriptpubkey_hex: utxo_scriptpubkey,
            mix_output_address: prep.funding_address.clone(),
            bip86_index,
            bip86_scan_max: None,
        })
        .await
        {
            Ok(Response::WraithMixCompleted(m)) => m,
            Ok(Response::Error(e)) => {
                return error_out(json, format!("WraithMixOneShot: {}", e.message))
            }
            Ok(other) => {
                return error_out(
                    json,
                    format!("WraithMixOneShot: unexpected response {other:?}"),
                )
            }
            Err(e) => return error_out(json, format!("WraithMixOneShot: {e}")),
        };
        if !json {
            println!("      session_id:     {}", mix.session_id);
            println!("      broadcast_txid: {}", mix.broadcast_txid);
        }

        // Phase 3: confirm the lock against the broadcast txid.
        if !json {
            println!("[3/3] confirming lock funding");
        }
        let conf = match call(Request::LocksConfirm {
            lock_id: prep.lock_id.clone(),
            funding_txid: mix.broadcast_txid.clone(),
        })
        .await
        {
            Ok(Response::LocksConfirmed(c)) => c,
            Ok(Response::Error(e)) => {
                return error_out(json, format!("LocksConfirm: {}", e.message))
            }
            Ok(other) => {
                return error_out(json, format!("LocksConfirm: unexpected response {other:?}"))
            }
            Err(e) => return error_out(json, format!("LocksConfirm: {e}")),
        };

        if json {
            let body = serde_json::json!({
                "lock_id": prep.lock_id,
                "funding_address": prep.funding_address,
                "broadcast_txid": mix.broadcast_txid,
                "block_height": conf.block_height,
                "session_id": mix.session_id,
            });
            println!("{body}");
        } else {
            println!();
            println!("✓ lock funded via Wraith CoinJoin");
            println!("  lock_id:        {}", prep.lock_id);
            println!("  broadcast_txid: {}", mix.broadcast_txid);
            println!("  block_height:   {}", conf.block_height);
            println!();
            println!("the chain shows a CoinJoin tx — chain analysts cannot tell");
            println!("which output became this lock. that's the privacy property.");
        }
        std::process::ExitCode::SUCCESS
    }

    fn error_out(json: bool, msg: String) -> std::process::ExitCode {
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
        let locks = call(Request::LocksList).await;

        if json {
            let body = serde_json::json!({
                "health":  result_value(&health),
                "env":     result_value(&env_resp),
                "wallets": result_value(&wallets),
                "session": result_value(&session),
                "balance": result_value(&balance),
                "locks":   result_value(&locks),
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
        // locks row
        match &locks {
            Ok(Response::LocksList(l)) => {
                println!(
                    "locks:    {} ({} sat capacity)",
                    l.locks.len(),
                    l.total_locked_sats
                );
            }
            Ok(Response::Error(_)) | Err(_) => println!("locks:    (no session)"),
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

use clap::{Parser, Subcommand};
use ghost_common::config::NodeConfig;
use ghost_common::setup::{self, FieldValue};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command as ProcCommand;

const DROPIN_DIR: &str = "/etc/systemd/system/ghostd.service.d";
const DROPIN_PATH: &str = "/etc/systemd/system/ghostd.service.d/reaper.conf";

#[derive(Subcommand)]
enum Command {
    /// Apply the `[reaper]` per-vector settings from pool.toml to the ghostd
    /// mempool reaper: writes a systemd drop-in and restarts ghostd. Needs root
    /// (run with sudo, or it shells out to sudo for the privileged steps).
    ApplyReaper {
        /// Config directory holding pool.toml.
        #[arg(long, default_value = "/etc/ghost")]
        config_dir: PathBuf,
        /// Print the flags + drop-in without writing or restarting.
        #[arg(long)]
        dry_run: bool,
        /// Write the drop-in but do not restart ghostd.
        #[arg(long)]
        no_restart: bool,
    },
}

#[derive(Parser)]
#[command(name = "ghost-setup", about = "Ghost Pool node setup (headless)")]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
    /// Node nickname
    #[arg(long)]
    nickname: Option<String>,
    /// Enable public mining
    #[arg(long)]
    public_mining: bool,
    /// Payout address (bech32)
    #[arg(long)]
    payout_address: Option<String>,
    /// Enable archive mode
    #[arg(long, default_value = "true")]
    archive: bool,
    /// Enable Ghost Pay
    #[arg(long, default_value = "true")]
    ghost_pay: bool,
    /// Enable Reaper
    #[arg(long, default_value = "true")]
    reaper: bool,
    /// Mempool profile: permissive (0), bitcoin_pure (1), full_open (2)
    #[arg(long, default_value = "permissive")]
    mempool_profile: String,
    /// Config directory
    #[arg(long, default_value = "/etc/ghost")]
    config_dir: PathBuf,
    /// Data directory
    #[arg(long, default_value = "~/.ghost/data")]
    data_dir: PathBuf,
}

fn main() {
    let args = Args::parse();

    if let Some(Command::ApplyReaper {
        config_dir,
        dry_run,
        no_restart,
    }) = &args.command
    {
        if let Err(e) = apply_reaper_to_ghostd(config_dir, *dry_run, *no_restart) {
            eprintln!("apply-reaper failed: {e}");
            std::process::exit(1);
        }
        return;
    }

    // Expand ~ in data_dir
    let data_dir = if args.data_dir.starts_with("~") {
        if let Some(home) = dirs::home_dir() {
            home.join(args.data_dir.strip_prefix("~").unwrap_or(&args.data_dir))
        } else {
            args.data_dir.clone()
        }
    } else {
        args.data_dir.clone()
    };

    let mut fields = HashMap::new();
    if let Some(ref name) = args.nickname {
        fields.insert("nickname".to_string(), FieldValue::Text(name.clone()));
    }
    fields.insert(
        "public_mining".to_string(),
        FieldValue::Bool(args.public_mining),
    );
    if let Some(ref addr) = args.payout_address {
        fields.insert("payout_address".to_string(), FieldValue::Text(addr.clone()));
    }
    fields.insert("archive_mode".to_string(), FieldValue::Bool(args.archive));
    fields.insert("ghost_pay".to_string(), FieldValue::Bool(args.ghost_pay));
    fields.insert("reaper".to_string(), FieldValue::Bool(args.reaper));

    let profile_idx = match args.mempool_profile.as_str() {
        "bitcoin_pure" => 1,
        "full_open" => 2,
        _ => 0, // permissive
    };
    fields.insert(
        "mempool_profile".to_string(),
        FieldValue::Selected(profile_idx),
    );

    match setup::apply_initial_setup(&fields, &args.config_dir, &data_dir) {
        Ok(result) => {
            println!("Setup complete!");
            println!("  Node ID: {}", result.node_id_hex);
            println!("  Config:  {}", result.config_path.display());
        }
        Err(e) => {
            eprintln!("Setup failed: {e}");
            std::process::exit(1);
        }
    }
}

/// Translate pool.toml's `[reaper]` per-vector settings into ghostd's mempool
/// reaper flags and apply them via a systemd drop-in.
fn apply_reaper_to_ghostd(
    config_dir: &Path,
    dry_run: bool,
    no_restart: bool,
) -> Result<(), String> {
    let pool_toml = config_dir.join("pool.toml");
    let config = NodeConfig::load(&pool_toml)?;
    let settings = &config.reaper;
    let launch = &config.node_launch;
    let storage = &config.storage;
    let policy = &config.policy;

    println!("Ghost-managed ghostd flags (from {}):", pool_toml.display());
    for f in settings
        .ghostd_flags()
        .iter()
        .chain(launch.ghostd_flags().iter())
        .chain(storage.ghostd_flags().iter())
        .chain(policy.ghostd_flags().iter())
    {
        println!("  {f}");
    }

    let exec_argv = read_ghostd_exec_argv()?;
    let dropin = setup::ghostd_managed_dropin(&exec_argv, settings, launch, storage, policy);

    if dry_run {
        println!("\n--- drop-in {DROPIN_PATH} (dry-run, not written) ---\n{dropin}");
        return Ok(());
    }

    write_dropin(&dropin)?;
    run_root(&["systemctl", "daemon-reload"])?;
    println!("Wrote {DROPIN_PATH} and reloaded systemd.");
    if no_restart {
        println!(
            "ghostd NOT restarted (--no-restart). Run `sudo systemctl restart ghostd` to apply."
        );
    } else {
        run_root(&["systemctl", "restart", "ghostd"])?;
        println!("Restarted ghostd; per-vector reaper flags are now live.");
    }
    Ok(())
}

/// Read ghostd's resolved command line from systemd (`argv[]` of ExecStart).
fn read_ghostd_exec_argv() -> Result<String, String> {
    let out = ProcCommand::new("systemctl")
        .args(["show", "ghostd", "-p", "ExecStart", "--value"])
        .output()
        .map_err(|e| format!("systemctl show ghostd: {e}"))?;
    let s = String::from_utf8_lossy(&out.stdout);
    let start = s
        .find("argv[]=")
        .ok_or("could not find argv[] in ghostd ExecStart (is ghostd installed?)")?;
    let rest = &s[start + "argv[]=".len()..];
    let end = rest.find(" ;").unwrap_or(rest.len());
    let argv = rest[..end].trim();
    if argv.is_empty() {
        return Err("ghostd ExecStart argv[] was empty".into());
    }
    Ok(argv.to_string())
}

/// Run a privileged command via sudo (works whether or not we are already root).
fn run_root(argv: &[&str]) -> Result<(), String> {
    let status = ProcCommand::new("sudo")
        .args(argv)
        .status()
        .map_err(|e| format!("run `sudo {}`: {e}", argv.join(" ")))?;
    if !status.success() {
        return Err(format!("`sudo {}` failed ({status})", argv.join(" ")));
    }
    Ok(())
}

/// Write the drop-in to its system path via `sudo tee`, backing up any existing one.
fn write_dropin(dropin: &str) -> Result<(), String> {
    use std::io::Write;
    run_root(&["mkdir", "-p", DROPIN_DIR])?;
    let _ = run_root(&[
        "sh",
        "-c",
        &format!("[ -f {DROPIN_PATH} ] && cp {DROPIN_PATH} {DROPIN_PATH}.bak.$(date +%s) || true"),
    ]);
    let mut child = ProcCommand::new("sudo")
        .args(["tee", DROPIN_PATH])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn `sudo tee`: {e}"))?;
    child
        .stdin
        .as_mut()
        .ok_or("no stdin for tee")?
        .write_all(dropin.as_bytes())
        .map_err(|e| format!("write drop-in: {e}"))?;
    let status = child.wait().map_err(|e| format!("wait tee: {e}"))?;
    if !status.success() {
        return Err(format!("`sudo tee {DROPIN_PATH}` failed ({status})"));
    }
    Ok(())
}

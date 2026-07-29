//! Hardware-derived miner capacity.
//!
//! The load balancer routes new miners to the under-utilised peer; the
//! advertised capacity is what's used for that decision. Letting operators
//! pick an arbitrary number invites gaming (declare 10^9, attract everything),
//! so capacity is calculated from real hardware:
//!
//! ```text
//!   ram_max  = total_ram_mb / MEM_MB_PER_MINER     // ~3 MB per miner
//!   cpu_max  = logical_cores * MINERS_PER_CORE     // ~500 per core
//!   fd_max   = ulimit_fd     / FD_BUDGET_DIVISOR   // 25% of FD budget
//!   calculated = min(ram_max, cpu_max, fd_max)
//! ```
//!
//! The operator's `network.max_miners` becomes a *ceiling* — they can throttle
//! their own node DOWN below the calculated cap (e.g. they're co-locating
//! ghost-pay on the same box and need headroom) but they can't exceed it.
//! The advertised capacity is `min(calculated, operator_declared)`.

use serde::Serialize;
use tracing::info;

/// Estimated RAM cost per active miner connection: TCP buffers, SV2 channel
/// state, vardiff history, share queue. 3 MB is conservative against the
/// observed ~1.8 MB/miner under steady-state load on the production VMs.
const MEM_MB_PER_MINER: u64 = 3;

/// Logical-core throughput budget. One core can validate ~5000 shares/sec
/// (MiMC + secp checks). At a 10s share interval per miner that supports
/// ~50000 miners/core in theory; we cap at 500 to leave headroom for spikes,
/// BUDS classification, signature verification on bursts, etc.
const MINERS_PER_CORE: u32 = 500;

/// Reserve only a quarter of the file-descriptor limit for miner sockets.
/// The other 75% goes to ZMQ mesh, internal HTTP clients, RPC pools, DB
/// connections, log files, and so on.
const FD_BUDGET_DIVISOR: u64 = 4;

/// Fallback RAM if `/proc/meminfo` can't be read (containers, exotic libcs):
/// assume 2 GB so we don't accidentally compute 0 capacity.
const FALLBACK_RAM_MB: u64 = 2048;

/// Fallback FD limit if `getrlimit(RLIMIT_NOFILE)` fails. Linux default is
/// 1024 — pessimistic but safe.
const FALLBACK_FD_LIMIT: u64 = 1024;

#[derive(Debug, Clone, Copy, Serialize)]
pub struct CapacityBreakdown {
    /// Logical CPU cores (`std::thread::available_parallelism`).
    pub cpu_cores: u32,
    /// Total physical RAM in MB.
    pub ram_mb: u64,
    /// Soft limit on open file descriptors (`getrlimit(RLIMIT_NOFILE)`).
    pub fd_limit: u64,
    /// Miners the RAM budget can support.
    pub ram_max: u32,
    /// Miners the CPU budget can support.
    pub cpu_max: u32,
    /// Miners the FD budget can support.
    pub fd_max: u32,
    /// `min(ram_max, cpu_max, fd_max)` — what the hardware actually allows.
    pub calculated_max: u32,
    /// Operator's `network.max_miners` (None = no override).
    pub operator_max: Option<u32>,
    /// `min(calculated_max, operator_max)` — what the network sees.
    pub effective_max: u32,
    /// Which constraint binds: `"ram"`, `"cpu"`, `"fd"`, or `"operator"`.
    pub bound_by: &'static str,
}

impl CapacityBreakdown {
    /// One-line summary suitable for the startup banner.
    pub fn summary(&self) -> String {
        format!(
            "cores={} ram={}MB fd={} | ram_max={} cpu_max={} fd_max={} → calculated={} operator={} → effective={} ({}-bound)",
            self.cpu_cores,
            self.ram_mb,
            self.fd_limit,
            self.ram_max,
            self.cpu_max,
            self.fd_max,
            self.calculated_max,
            self.operator_max
                .map(|n| n.to_string())
                .unwrap_or_else(|| "—".into()),
            self.effective_max,
            self.bound_by,
        )
    }
}

/// Measure the host and compute the effective capacity, applying the operator
/// override as a ceiling. Logs the breakdown at INFO so operators can see the
/// math.
pub fn measure(operator_declared: Option<u32>) -> CapacityBreakdown {
    let cpu_cores = detect_cpu_cores();
    let ram_mb = detect_ram_mb();
    let fd_limit = detect_fd_limit();

    let ram_max = (ram_mb / MEM_MB_PER_MINER).min(u32::MAX as u64) as u32;
    let cpu_max = cpu_cores.saturating_mul(MINERS_PER_CORE);
    let fd_max = (fd_limit / FD_BUDGET_DIVISOR).min(u32::MAX as u64) as u32;

    let (calculated_max, hw_bound) = pick_min(ram_max, cpu_max, fd_max);

    let (effective_max, bound_by) = match operator_declared {
        Some(decl) if decl < calculated_max => (decl, "operator"),
        _ => (calculated_max, hw_bound),
    };

    let breakdown = CapacityBreakdown {
        cpu_cores,
        ram_mb,
        fd_limit,
        ram_max,
        cpu_max,
        fd_max,
        calculated_max,
        operator_max: operator_declared,
        effective_max,
        bound_by,
    };

    info!("Capacity: {}", breakdown.summary());
    breakdown
}

fn pick_min(ram: u32, cpu: u32, fd: u32) -> (u32, &'static str) {
    if ram <= cpu && ram <= fd {
        (ram, "ram")
    } else if cpu <= fd {
        (cpu, "cpu")
    } else {
        (fd, "fd")
    }
}

fn detect_cpu_cores() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
}

#[cfg(target_os = "linux")]
fn detect_ram_mb() -> u64 {
    // Read MemTotal from /proc/meminfo (KB → MB).
    match std::fs::read_to_string("/proc/meminfo") {
        Ok(contents) => {
            for line in contents.lines() {
                if let Some(rest) = line.strip_prefix("MemTotal:") {
                    let kb: u64 = rest
                        .split_whitespace()
                        .next()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                    if kb > 0 {
                        return kb / 1024;
                    }
                }
            }
            FALLBACK_RAM_MB
        }
        Err(_) => FALLBACK_RAM_MB,
    }
}

#[cfg(not(target_os = "linux"))]
fn detect_ram_mb() -> u64 {
    FALLBACK_RAM_MB
}

#[cfg(unix)]
fn detect_fd_limit() -> u64 {
    let mut rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) };
    if rc == 0 && rlim.rlim_cur > 0 {
        rlim.rlim_cur
    } else {
        FALLBACK_FD_LIMIT
    }
}

#[cfg(not(unix))]
fn detect_fd_limit() -> u64 {
    FALLBACK_FD_LIMIT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measure_returns_positive_capacity_on_host() {
        let b = measure(None);
        assert!(b.cpu_cores > 0, "cpu detection should succeed");
        assert!(b.ram_mb > 0, "ram detection should succeed");
        assert!(b.fd_limit > 0, "fd limit detection should succeed");
        assert!(b.calculated_max > 0, "calculated capacity should be > 0");
        assert!(
            b.effective_max > 0 && b.effective_max <= b.calculated_max,
            "effective must be > 0 and ≤ calculated when no operator override"
        );
    }

    #[test]
    fn operator_below_calculated_throttles_down() {
        let b = measure(Some(50));
        assert!(b.calculated_max > 50, "test host should calc > 50");
        assert_eq!(b.effective_max, 50);
        assert_eq!(b.operator_max, Some(50));
        assert_eq!(b.bound_by, "operator");
    }

    #[test]
    fn operator_above_calculated_is_ignored() {
        let b = measure(Some(u32::MAX));
        assert_eq!(b.effective_max, b.calculated_max);
        assert_ne!(b.bound_by, "operator");
    }

    #[test]
    fn pick_min_picks_smallest_with_ram_first_on_ties() {
        assert_eq!(pick_min(100, 200, 300), (100, "ram"));
        assert_eq!(pick_min(300, 100, 200), (100, "cpu"));
        assert_eq!(pick_min(300, 200, 100), (100, "fd"));
        // Ties go to ram first — that's the most concrete/predictable.
        assert_eq!(pick_min(100, 100, 100), (100, "ram"));
    }

    #[test]
    fn summary_contains_key_fields() {
        let b = measure(Some(123));
        let s = b.summary();
        assert!(s.contains("cores="));
        assert!(s.contains("ram="));
        assert!(s.contains("calculated="));
        assert!(s.contains("effective=123"));
    }
}

//! Bounds on concurrent downstream connections to the world-open SV2 port (#994).
//!
//! ## Why the accounting is RAII and not a decrement
//!
//! ⛔⛔ This is the same shape of code as the TDP client slot counter, which leaked a slot on **six
//! early-return paths**. At ten leaked slots that node refused *every* `pool_sv2` connection for
//! ever and needed `systemctl restart ghost-pool` to clear — so a leak does not weaken the defence,
//! it becomes the outage the defence was added to prevent.
//!
//! The per-connection task in `channel_manager` has **four** early `return`s (handshake timeout,
//! handshake error, shutdown during handshake, bootstrap failure) plus the normal end after
//! `downstream.start(...).await`. A [`ConnectionSlot`] releases itself in `Drop`, which covers all
//! five without any path having to remember, and makes a new early return added tomorrow safe by
//! construction rather than by review.
//!
//! ## Two details that are load-bearing
//!
//! **The slot is acquired in the accept loop, before the task is spawned.** Acquiring it inside the
//! task means the task, its socket and its descriptor already exist, which is most of what the cap
//! is for.
//!
//! **The per-IP map drops entries at zero.** Otherwise an attacker cycling source addresses grows
//! the map without bound and the limiter becomes the memory-exhaustion vector it was added to
//! prevent. `active_addresses()` exists so a test can assert that, rather than it being a comment.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
};

use tracing::warn;

/// Concurrent downstream connections allowed in total, when the operator sets no value.
///
/// `pool_sv2` normally holds ONE upstream connection from the co-located translator plus any direct
/// SV2 miners; the node advertises capacity for ~1,000 miners (MEASURED: `cpu_max=1000` on the
/// 2-core VMs) and nearly all of them arrive through the translator's single connection. 512 is
/// therefore far above any legitimate shape while still bounding a flood.
pub const DEFAULT_MAX_DOWNSTREAM_CONNECTIONS: u32 = 512;

/// Concurrent connections allowed from one address, when the operator sets no value.
///
/// A farm behind one NAT address can legitimately open several. 64 is generous for that and still
/// means one source cannot occupy the whole table.
pub const DEFAULT_MAX_CONNECTIONS_PER_IP: u32 = 64;

/// Why a connection was refused. Returned rather than logged here so the caller can log it with the
/// peer address it already has, and so a test can assert which bound was hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusedBecause {
    /// The total cap is full.
    TotalFull { limit: u32 },
    /// This address already holds its share.
    PerIpFull { limit: u32, ip_active: u32 },
}

/// Tracks how many downstream connections are live, in total and per address.
#[derive(Debug)]
pub struct ConnectionLimiter {
    max_total: u32,
    max_per_ip: u32,
    state: Mutex<LimiterState>,
}

#[derive(Debug, Default)]
struct LimiterState {
    total: u32,
    per_ip: HashMap<IpAddr, u32>,
}

impl ConnectionLimiter {
    /// `None` for either bound takes the default; both are clamped to at least 1, because a limiter
    /// configured to zero would refuse the co-located translator and the node would mine nothing
    /// while reporting healthy.
    pub fn new(max_total: Option<u32>, max_per_ip: Option<u32>) -> Self {
        Self {
            max_total: max_total
                .unwrap_or(DEFAULT_MAX_DOWNSTREAM_CONNECTIONS)
                .max(1),
            max_per_ip: max_per_ip.unwrap_or(DEFAULT_MAX_CONNECTIONS_PER_IP).max(1),
            state: Mutex::new(LimiterState::default()),
        }
    }

    pub fn max_total(&self) -> u32 {
        self.max_total
    }

    pub fn max_per_ip(&self) -> u32 {
        self.max_per_ip
    }

    /// Take a slot for `ip`, or say why not.
    ///
    /// The returned [`ConnectionSlot`] must be held for the life of the connection; dropping it
    /// releases the slot. ⛔ Do not call this inside the spawned task — see the module docs.
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Result<ConnectionSlot, RefusedBecause> {
        // `unwrap_or_else` on the poison rather than `super_safe_lock`: a poisoned limiter must not
        // take the pool down, and the count it holds is a bound, not money. Recovering the guard
        // keeps the cap enforced on a best-effort basis instead of panicking the accept loop.
        let mut st = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if st.total >= self.max_total {
            return Err(RefusedBecause::TotalFull {
                limit: self.max_total,
            });
        }
        let ip_active = st.per_ip.get(&ip).copied().unwrap_or(0);
        if ip_active >= self.max_per_ip {
            return Err(RefusedBecause::PerIpFull {
                limit: self.max_per_ip,
                ip_active,
            });
        }

        st.total += 1;
        *st.per_ip.entry(ip).or_insert(0) += 1;
        drop(st);

        Ok(ConnectionSlot {
            limiter: Arc::clone(self),
            ip,
        })
    }

    /// Live connections in total.
    pub fn active_total(&self) -> u32 {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).total
    }

    /// Addresses currently holding at least one connection.
    ///
    /// Exists so a test can assert the map SHRINKS. Without that, "entries are removed at zero" is
    /// a comment, and an unbounded map keyed by attacker-chosen addresses is exactly the failure a
    /// connection limiter is supposed to remove.
    pub fn active_addresses(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .per_ip
            .len()
    }

    fn release(&self, ip: IpAddr) {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        st.total = st.total.saturating_sub(1);
        match st.per_ip.get_mut(&ip) {
            Some(n) => {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    // At zero the KEY goes too, or the map grows for ever across distinct sources.
                    st.per_ip.remove(&ip);
                }
            }
            None => {
                // Cannot happen while slots are only created by `try_acquire`, which is why it is
                // worth saying out loud if it does: a release without an acquire means the
                // accounting is wrong in a direction that eventually refuses everything.
                warn!(%ip, "connection slot released for an address with no record — slot accounting is inconsistent");
            }
        }
    }
}

/// A held connection slot. Releases itself on drop.
///
/// ⛔ Deliberately has no `release()` method. An explicit release is a thing a code path can forget,
/// and the TDP slot leak was six paths that did.
#[derive(Debug)]
pub struct ConnectionSlot {
    limiter: Arc<ConnectionLimiter>,
    ip: IpAddr,
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.limiter.release(self.ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    #[test]
    fn a_slot_is_released_on_drop_and_the_address_is_forgotten() {
        let lim = Arc::new(ConnectionLimiter::new(Some(4), Some(2)));
        {
            let _a = lim.try_acquire(ip(1)).expect("first");
            assert_eq!(lim.active_total(), 1);
            assert_eq!(lim.active_addresses(), 1);
        }
        assert_eq!(lim.active_total(), 0, "drop must release the total");
        assert_eq!(
            lim.active_addresses(),
            0,
            "the per-IP entry must be REMOVED at zero, not left at 0 — otherwise an attacker \
             cycling addresses grows this map without bound"
        );
    }

    #[test]
    fn the_total_cap_refuses_the_next_connection() {
        let lim = Arc::new(ConnectionLimiter::new(Some(2), Some(99)));
        let _a = lim.try_acquire(ip(1)).expect("1st");
        let _b = lim.try_acquire(ip(2)).expect("2nd");
        // `unwrap_err` rather than comparing the whole Result: deriving `PartialEq` on
        // `ConnectionSlot` to make that compile would put an equality on a `Drop` type whose
        // identity is the slot it holds, which is a worse thing to own than this line.
        assert_eq!(
            lim.try_acquire(ip(3)).unwrap_err(),
            RefusedBecause::TotalFull { limit: 2 },
            "a third connection must be refused on the total cap"
        );
    }

    #[test]
    fn the_per_ip_cap_refuses_one_source_while_admitting_another() {
        let lim = Arc::new(ConnectionLimiter::new(Some(99), Some(2)));
        let _a = lim.try_acquire(ip(1)).expect("1st from .1");
        let _b = lim.try_acquire(ip(1)).expect("2nd from .1");
        assert_eq!(
            lim.try_acquire(ip(1)).unwrap_err(),
            RefusedBecause::PerIpFull {
                limit: 2,
                ip_active: 2
            },
            "a third from the SAME address must be refused"
        );
        // The point of a per-IP cap: one noisy source must not shut everyone else out.
        assert!(
            lim.try_acquire(ip(2)).is_ok(),
            "a DIFFERENT address must still be admitted while one source is at its cap"
        );
    }

    /// ⛔⛔ The anti-leak property the TDP slot counter did not have.
    ///
    /// That counter leaked on six early-return paths and at ten leaked slots refused every
    /// connection for ever. Here every exit path drops the slot, so the cap must be reusable
    /// indefinitely. Churned well past the cap: a leak of even one per cycle shows up as a refusal.
    #[test]
    fn slots_are_reusable_indefinitely_so_the_cap_cannot_silently_wedge() {
        let lim = Arc::new(ConnectionLimiter::new(Some(3), Some(3)));
        for round in 0..200 {
            let a = lim.try_acquire(ip(1)).unwrap_or_else(|e| {
                panic!("round {round}: refused {e:?} — a slot leaked on an earlier round")
            });
            let b = lim.try_acquire(ip(1)).expect("second in round");
            let c = lim.try_acquire(ip(1)).expect("third in round");
            assert_eq!(lim.active_total(), 3, "round {round}");
            drop((a, b, c));
            assert_eq!(
                lim.active_total(),
                0,
                "round {round} must release everything"
            );
        }
        assert_eq!(lim.active_addresses(), 0);
    }

    /// Many short-lived sources must not grow the map — the limiter must not become the
    /// memory-exhaustion vector it exists to remove.
    #[test]
    fn churning_distinct_addresses_does_not_grow_the_map() {
        let lim = Arc::new(ConnectionLimiter::new(Some(10), Some(10)));
        for i in 0..=255u8 {
            let _s = lim.try_acquire(ip(i)).expect("one at a time always fits");
            assert_eq!(
                lim.active_addresses(),
                1,
                "only the live address is tracked"
            );
        }
        assert_eq!(
            lim.active_addresses(),
            0,
            "256 distinct addresses came and went; the map must be empty"
        );
    }

    /// A zero limit would refuse the co-located translator, so the node would mine nothing while
    /// every service reported healthy. Clamped rather than honoured.
    #[test]
    fn a_zero_limit_is_clamped_so_a_node_cannot_be_configured_to_mine_nothing() {
        let lim = Arc::new(ConnectionLimiter::new(Some(0), Some(0)));
        assert_eq!(lim.max_total(), 1);
        assert_eq!(lim.max_per_ip(), 1);
        assert!(
            lim.try_acquire(ip(1)).is_ok(),
            "the translator's one connection must still be admitted"
        );
    }

    #[test]
    fn absent_config_takes_the_documented_defaults() {
        let lim = Arc::new(ConnectionLimiter::new(None, None));
        assert_eq!(lim.max_total(), DEFAULT_MAX_DOWNSTREAM_CONNECTIONS);
        assert_eq!(lim.max_per_ip(), DEFAULT_MAX_CONNECTIONS_PER_IP);
    }
}

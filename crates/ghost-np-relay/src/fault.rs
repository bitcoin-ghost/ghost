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
//| FILE: fault.rs                                                                                                       |
//|======================================================================================================================|

//! Test-only lies a relay tells the peers it serves, for the harness's lying sync peer
//! (`scripts/regtest-node-pool`, plan Phase 3 "lying sync peer"). Compiled only with the
//! `fault-injection` feature, which pool_sv2's `np-fault-injection` turns on and no release build
//! enables; without it this module does not exist.
//!
//! `GHOST_NP_SYNC_FAULT` picks the lie, read once. Only messages sent to one peer are changed
//! (replies to sync requests, stamps, tips), never broadcasts:
//! - `balances`: served share bodies credit someone else. Every other share in a `Shares` reply
//!   has its tag's payee replaced by a thief's script; the rest have their first coinbase output
//!   raised by 1,000 sats.
//! - `stamps`: anchors in `Headers` and `Anchor` replies claim a `btc_height` one above the true
//!   one, and `Stamps` replies carry job stamps with a flipped batch root.
//! - `truncate`: `Headers` replies stop after their first two anchors while `Tip` and `Hello` still
//!   advertise the whole chain, and `Batch` replies drop their last share id.
//!
//! Every lie also answers `GetAddr` with no addresses, so a node that knows only the liar stays
//! alone with it.
//!
//! Anything else, or unset, changes nothing.
//!
//! A test build also dials its peers from its relay's listen address ([`connect_from`]), so that
//! on a one-host test network a liar on its own loopback address is told apart by IP.

use std::sync::OnceLock;

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::{Amount, Transaction};
use tracing::warn;

use crate::wire::Message;

/// A sync lie.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncFault {
    /// Tell the truth.
    None,
    /// Altered credits in served share bodies.
    Balances,
    /// Altered anchor heights and job stamps.
    Stamps,
    /// Truncated headers and batches.
    Truncate,
}

/// The configured lie, from `GHOST_NP_SYNC_FAULT`.
pub fn sync_fault() -> SyncFault {
    static FAULT: OnceLock<SyncFault> = OnceLock::new();
    *FAULT.get_or_init(|| {
        let f = parse(std::env::var("GHOST_NP_SYNC_FAULT").ok().as_deref());
        if f != SyncFault::None {
            warn!(fault = ?f, "NODE_POOL_FAULT: this relay serves TAMPERED sync data (test build)");
        }
        f
    })
}

fn parse(v: Option<&str>) -> SyncFault {
    match v {
        Some("balances") => SyncFault::Balances,
        Some("stamps") => SyncFault::Stamps,
        Some("truncate") => SyncFault::Truncate,
        _ => SyncFault::None,
    }
}

/// Dial `to`, from `from` when given (a test build's lying relay dials from its own listen
/// address, so peers on one host can tell it apart by IP).
pub async fn connect_from(
    from: Option<std::net::IpAddr>,
    to: std::net::SocketAddr,
) -> std::io::Result<tokio::net::TcpStream> {
    let Some(ip) = from.filter(|ip| ip.is_ipv4() == to.is_ipv4()) else {
        return tokio::net::TcpStream::connect(to).await;
    };
    let sock = if to.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    sock.bind(std::net::SocketAddr::new(ip, 0))?;
    sock.connect(to).await
}

/// The script a `balances` liar credits instead of the share's payee.
pub fn thief_script() -> Vec<u8> {
    let mut s = vec![0x51, 0x20];
    s.extend_from_slice(&[0x77; 32]);
    s
}

/// The message as the configured lie would send it.
pub fn tamper(m: Message) -> Message {
    tamper_with(sync_fault(), m)
}

fn tamper_with(f: SyncFault, m: Message) -> Message {
    match (f, m) {
        (SyncFault::Balances, Message::Shares(mut v)) => {
            for (k, s) in v.iter_mut().enumerate() {
                if k % 2 == 0 {
                    s.tag.payee_script = thief_script();
                } else if let Ok(mut tx) = deserialize::<Transaction>(&s.coinbase) {
                    if let Some(o) = tx.output.first_mut() {
                        o.value += Amount::from_sat(1_000);
                        s.coinbase = serialize(&tx);
                    }
                }
            }
            Message::Shares(v)
        }
        (SyncFault::Stamps, Message::Headers(mut v)) => {
            for a in &mut v {
                a.btc_height += 1;
            }
            Message::Headers(v)
        }
        (SyncFault::Stamps, Message::Anchor(mut a)) => {
            a.btc_height += 1;
            Message::Anchor(a)
        }
        (SyncFault::Stamps, Message::Stamps(mut st)) => {
            for j in &mut st.recent {
                j.batch_root[0] ^= 1;
            }
            Message::Stamps(st)
        }
        (SyncFault::Truncate, Message::Headers(mut v)) => {
            v.truncate(2);
            Message::Headers(v)
        }
        (SyncFault::Truncate, Message::Batch { anchor, mut ids }) => {
            ids.pop();
            Message::Batch { anchor, ids }
        }
        // Every liar also hides its other peers, so a node that knows only the liar stays alone
        // with it (an eclipse) instead of learning honest peers from it.
        (SyncFault::Balances | SyncFault::Stamps | SyncFault::Truncate, Message::Addr(_)) => {
            Message::Addr(vec![])
        }
        (_, m) => m,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::JobAnchor;
    use crate::wire::JobStamps;

    #[test]
    fn faults_parse_and_the_truth_is_untouched() {
        assert_eq!(parse(Some("balances")), SyncFault::Balances);
        assert_eq!(parse(Some("stamps")), SyncFault::Stamps);
        assert_eq!(parse(Some("truncate")), SyncFault::Truncate);
        assert_eq!(parse(Some("other")), SyncFault::None);
        assert_eq!(parse(None), SyncFault::None);
        let b = Message::Batch {
            anchor: [1; 32],
            ids: vec![[2; 32], [3; 32]],
        };
        assert_eq!(tamper_with(SyncFault::None, b.clone()), b);
        assert_eq!(tamper_with(SyncFault::Balances, b.clone()), b);
    }

    #[test]
    fn each_lie_changes_what_it_names() {
        let b = Message::Batch {
            anchor: [1; 32],
            ids: vec![[2; 32], [3; 32]],
        };
        assert_eq!(
            tamper_with(SyncFault::Truncate, b),
            Message::Batch {
                anchor: [1; 32],
                ids: vec![[2; 32]]
            }
        );
        let st = Message::Stamps(JobStamps {
            node_id: [9; 32],
            recent: vec![JobAnchor {
                parent_anchor: [4; 32],
                batch_root: [5; 32],
            }],
        });
        let Message::Stamps(t) = tamper_with(SyncFault::Stamps, st) else {
            panic!("stamps")
        };
        assert_eq!(t.recent[0].parent_anchor, [4; 32]);
        assert_eq!(t.recent[0].batch_root[0], 5 ^ 1);
        assert_eq!(t.recent[0].batch_root[1..], [5; 31]);
        let addr = Message::Addr(vec!["127.0.0.1:1".into()]);
        assert_eq!(
            tamper_with(SyncFault::Truncate, addr.clone()),
            Message::Addr(vec![])
        );
        assert_eq!(tamper_with(SyncFault::None, addr.clone()), addr);
    }
}

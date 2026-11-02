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
//| FILE: sv1.rs                                                                                                         |
//|======================================================================================================================|

//! A Stratum V1 client that connects like a miner and only ever listens.
//!
//! It subscribes, authorizes with the miner's payout address as its username, and reads
//! `mining.set_difficulty`, `mining.set_extranonce` and `mining.notify`. It never sends
//! `mining.submit`: no share it could find would be credited to anyone, the miner included, and
//! nothing it does costs the node more than one idle miner.

use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

use crate::job::Job;

/// Longest line accepted from the node: a 500-output notify is about 44 KB.
const MAX_LINE: usize = 1 << 20;

/// Why the stratum session failed.
#[derive(Debug, thiserror::Error)]
pub enum Sv1Error {
    /// Could not connect, or the connection broke.
    #[error("connection: {0}")]
    Io(String),
    /// No answer in time.
    #[error("timed out waiting for {0}")]
    Timeout(&'static str),
    /// The node closed the connection.
    #[error("the node closed the connection")]
    Closed,
    /// The node sent something that is not Stratum V1.
    #[error("protocol: {0}")]
    Protocol(String),
    /// The node refused the subscription or the payout address.
    #[error("refused: {0}")]
    Refused(String),
}

/// How to connect.
#[derive(Debug, Clone)]
pub struct Sv1Config {
    /// `host:port` of the node's SV1 port.
    pub addr: String,
    /// The username: the payout address (optionally `address.worker`).
    pub username: String,
    /// The password; nodes ignore it.
    pub password: String,
    /// The user agent sent in `mining.subscribe`. The node picks the slot class from it, so
    /// passing the miner's own firmware agent audits the class that miner is served.
    pub user_agent: String,
    /// Deadline for the handshake.
    pub timeout: Duration,
}

/// A subscribed, authorized session.
pub struct Sv1Session {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    extranonce1: Vec<u8>,
    extranonce2_size: usize,
    difficulty: Option<f64>,
    next_id: u64,
    pending: Vec<Job>,
}

impl Sv1Session {
    /// Connect, subscribe and authorize.
    pub async fn connect(cfg: &Sv1Config) -> Result<Sv1Session, Sv1Error> {
        let stream = tokio::time::timeout(cfg.timeout, TcpStream::connect(&cfg.addr))
            .await
            .map_err(|_| Sv1Error::Timeout("the connection"))?
            .map_err(|e| Sv1Error::Io(e.to_string()))?;
        let _ = stream.set_nodelay(true);
        let (r, w) = stream.into_split();
        let mut s = Sv1Session {
            reader: BufReader::new(r),
            writer: w,
            extranonce1: Vec::new(),
            extranonce2_size: 0,
            difficulty: None,
            next_id: 1,
            pending: Vec::new(),
        };
        let sub = s
            .call("mining.subscribe", json!([cfg.user_agent]), cfg.timeout)
            .await?;
        let arr = sub
            .as_array()
            .ok_or_else(|| Sv1Error::Protocol("subscribe result is not an array".into()))?;
        s.extranonce1 = arr
            .get(1)
            .and_then(Value::as_str)
            .and_then(|h| hex::decode(h).ok())
            .ok_or_else(|| Sv1Error::Protocol("subscribe result has no extranonce1".into()))?;
        s.extranonce2_size =
            arr.get(2).and_then(Value::as_u64).ok_or_else(|| {
                Sv1Error::Protocol("subscribe result has no extranonce2 size".into())
            })? as usize;
        let auth = s
            .call(
                "mining.authorize",
                json!([cfg.username, cfg.password]),
                cfg.timeout,
            )
            .await?;
        if auth != Value::Bool(true) {
            return Err(Sv1Error::Refused(format!(
                "mining.authorize for {} answered {auth}",
                cfg.username
            )));
        }
        Ok(s)
    }

    /// The difficulty the node set last.
    pub fn difficulty(&self) -> Option<f64> {
        self.difficulty
    }

    async fn send(&mut self, v: &Value) -> Result<(), Sv1Error> {
        let mut line = serde_json::to_vec(v).map_err(|e| Sv1Error::Protocol(e.to_string()))?;
        line.push(b'\n');
        self.writer
            .write_all(&line)
            .await
            .map_err(|e| Sv1Error::Io(e.to_string()))
    }

    async fn read_message(&mut self) -> Result<Value, Sv1Error> {
        let mut line = String::new();
        loop {
            line.clear();
            let n = (&mut self.reader)
                .take(MAX_LINE as u64)
                .read_line(&mut line)
                .await
                .map_err(|e| Sv1Error::Io(e.to_string()))?;
            if n == 0 {
                return Err(Sv1Error::Closed);
            }
            if !line.ends_with('\n') && n >= MAX_LINE {
                return Err(Sv1Error::Protocol("a line over 1 MB".into()));
            }
            if line.trim().is_empty() {
                continue;
            }
            return serde_json::from_str(line.trim())
                .map_err(|e| Sv1Error::Protocol(format!("not JSON: {e}")));
        }
    }

    /// Apply a notification; a `mining.notify` becomes a pending job.
    fn on_notification(&mut self, method: &str, params: &[Value]) -> Result<(), Sv1Error> {
        match method {
            "mining.set_difficulty" => {
                self.difficulty = params.first().and_then(Value::as_f64);
            }
            "mining.set_extranonce" => {
                if let Some(e) = params
                    .first()
                    .and_then(Value::as_str)
                    .and_then(|h| hex::decode(h).ok())
                {
                    self.extranonce1 = e;
                }
                if let Some(n) = params.get(1).and_then(Value::as_u64) {
                    self.extranonce2_size = n as usize;
                }
            }
            "mining.notify" => {
                let job = Job::from_sv1_notify(
                    params,
                    &self.extranonce1,
                    self.extranonce2_size,
                    self.difficulty,
                )
                .map_err(Sv1Error::Protocol)?;
                self.pending.push(job);
            }
            _ => {}
        }
        Ok(())
    }

    async fn call(
        &mut self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, Sv1Error> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"id": id, "method": method, "params": params}))
            .await?;
        let wait = async {
            loop {
                let m = self.read_message().await?;
                if let Some(meth) = m.get("method").and_then(Value::as_str) {
                    let params = m
                        .get("params")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    self.on_notification(meth, &params)?;
                    continue;
                }
                if m.get("id").and_then(Value::as_u64) == Some(id) {
                    if let Some(e) = m.get("error").filter(|e| !e.is_null()) {
                        return Err(Sv1Error::Refused(format!("{method}: {e}")));
                    }
                    return Ok(m.get("result").cloned().unwrap_or(Value::Null));
                }
            }
        };
        tokio::time::timeout(timeout, wait)
            .await
            .map_err(|_| Sv1Error::Timeout("an answer"))?
    }

    /// The next job, in the order the node sent them.
    pub async fn next_job(&mut self, timeout: Duration) -> Result<Job, Sv1Error> {
        if !self.pending.is_empty() {
            return Ok(self.pending.remove(0));
        }
        let wait = async {
            loop {
                let m = self.read_message().await?;
                if let Some(meth) = m.get("method").and_then(Value::as_str) {
                    let params = m
                        .get("params")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    self.on_notification(meth, &params)?;
                    if !self.pending.is_empty() {
                        return Ok(self.pending.remove(0));
                    }
                }
            }
        };
        tokio::time::timeout(timeout, wait)
            .await
            .map_err(|_| Sv1Error::Timeout("a job"))?
    }
}

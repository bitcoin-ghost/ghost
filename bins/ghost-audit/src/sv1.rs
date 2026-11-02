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
        // Subscribe and authorize back to back, as most miners do. A client that waits for the
        // subscribe answer first is a "serialising" miner to the translator: it is answered with
        // a placeholder extranonce (corrected only by mining.set_extranonce, which it sends only
        // to clients that asked for it), so every coinbase built from it failed to parse, or,
        // with open_channel_on_subscribe, its channel opened under a provisional identity that
        // the node pool refuses.
        let mut answers = s
            .calls(
                &[
                    ("mining.subscribe", json!([cfg.user_agent])),
                    ("mining.authorize", json!([cfg.username, cfg.password])),
                ],
                cfg.timeout,
            )
            .await?;
        let auth = answers.pop().unwrap_or(Value::Null);
        let sub = answers.pop().unwrap_or(Value::Null);
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

    /// Send every request at once, then wait for every answer, in whatever order they come.
    async fn calls(
        &mut self,
        reqs: &[(&str, Value)],
        timeout: Duration,
    ) -> Result<Vec<Value>, Sv1Error> {
        let first = self.next_id;
        for (method, params) in reqs {
            let id = self.next_id;
            self.next_id += 1;
            self.send(&json!({"id": id, "method": method, "params": params}))
                .await?;
        }
        let mut answers: Vec<Option<Value>> = vec![None; reqs.len()];
        let wait = async {
            while answers.iter().any(Option::is_none) {
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
                let Some(k) = m
                    .get("id")
                    .and_then(Value::as_u64)
                    .and_then(|id| id.checked_sub(first))
                    .map(|k| k as usize)
                    .filter(|k| *k < reqs.len())
                else {
                    continue;
                };
                if let Some(e) = m.get("error").filter(|e| !e.is_null()) {
                    return Err(Sv1Error::Refused(format!("{}: {e}", reqs[k].0)));
                }
                answers[k] = Some(m.get("result").cloned().unwrap_or(Value::Null));
            }
            Ok(())
        };
        tokio::time::timeout(timeout, wait)
            .await
            .map_err(|_| Sv1Error::Timeout("an answer"))??;
        Ok(answers
            .into_iter()
            .map(|a| a.unwrap_or(Value::Null))
            .collect())
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// The translator answers a subscribe only once the channel is open, and opens it on
    /// authorize: a client that waits for the subscribe answer before authorizing gets a
    /// placeholder extranonce. The handshake sends both at once and takes the answers in any
    /// order. This server answers nothing until both arrived, authorize first.
    #[tokio::test]
    async fn subscribe_and_authorize_go_out_together() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (r, mut w) = sock.into_split();
            let mut lines = BufReader::new(r).lines();
            let a: Value =
                serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
            let b: Value =
                serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
            assert_eq!(a["method"], "mining.subscribe");
            assert_eq!(b["method"], "mining.authorize");
            for m in [
                json!({"id": b["id"], "result": true, "error": null}),
                json!({"id": a["id"], "result": [[], "0a0b0c0d", 8], "error": null}),
            ] {
                w.write_all(format!("{m}\n").as_bytes()).await.unwrap();
            }
            w
        });
        let s = Sv1Session::connect(&Sv1Config {
            addr: addr.to_string(),
            username: "bcrt1q.w".into(),
            password: "x".into(),
            user_agent: "test/1".into(),
            timeout: Duration::from_secs(5),
        })
        .await
        .expect("handshake");
        assert_eq!(s.extranonce1, vec![0x0a, 0x0b, 0x0c, 0x0d]);
        assert_eq!(s.extranonce2_size, 8);
        drop(server.await.unwrap());
    }
}

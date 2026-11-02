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
//| FILE: slot_class_sensing.rs                                                                                          |
//|======================================================================================================================|

//! Slot-class sensing (spec 2.1 and 2.4): how many miner outputs a job may carry for one miner.
//!
//! Most mining firmware cannot carry a 500-output coinbase, and some (Bitmain, Avalon) corrupt
//! memory or silently skip the job rather than refusing it. So every miner is sensed per
//! connection: it starts at the smallest class, steps up one class after `min_shares` valid
//! shares, never past the known-safe ceiling of its model, and drops back for good on the first
//! sign of failure. A valid share proves the firmware hashed that coinbase; nothing proves what a
//! miner cannot carry, so the ceilings come from published research and are raised only by
//! hardware tests.
//!
//! This is a port of the prototype's sense mode (`hardware-test/coinbase_probe.py --sense` in the
//! design folder): the same ceiling table with its evidence notes, the same stepping rules and
//! failure signals. The prototype's regular expressions are hand-ported to plain string matching
//! so this crate takes no new dependency; the tests pin each row.
//!
//! Pure: no I/O and no clock. Times are milliseconds on any monotonic clock the caller chooses.
//! Nothing here persists; [`SensingStore`] is the interface storage (W2.4) will implement.

use std::collections::VecDeque;
use std::fmt;

use crate::node_pool_constants::SLOT_CLASSES;

/// Coinbase bytes each slot class is sized for, all-P2TR payees, parallel to [`SLOT_CLASSES`]
/// (spec 2.1). A miner may be stepped to a class only if this size is at or below its ceiling.
pub const SLOT_CLASS_COINBASE_BYTES: [u32; 6] = [500, 730, 2_250, 6_500, 16_000, 22_000];

/// Index of the full class (500 miner outputs). SV2 standard channels always get it: the miner
/// receives only a header, so the coinbase size never reaches the firmware.
pub const FULL_CLASS_INDEX: usize = SLOT_CLASSES.len() - 1;

/// SV2 extension type of the Ghost user-agent TLV. The translator attaches the SV1 miner's
/// `mining.subscribe` agent to `OpenExtendedMiningChannel` under it, so the pool, which builds
/// the coinbase, can look the model up. Private to Ghost; negotiated like any SV2 extension.
pub const AGENT_TLV_EXTENSION_TYPE: u16 = 0x4748;

/// Field type of the user agent inside [`AGENT_TLV_EXTENSION_TYPE`].
pub const AGENT_TLV_FIELD_TYPE: u8 = 0x01;

/// Longest user agent kept, in bytes. Longer agents are cut at a character boundary.
pub const MAX_AGENT_LEN: usize = 255;

/// Cut an agent to [`MAX_AGENT_LEN`] bytes at a character boundary.
pub fn clamp_agent(agent: &str) -> &str {
    if agent.len() <= MAX_AGENT_LEN {
        return agent;
    }
    let mut end = MAX_AGENT_LEN;
    while !agent.is_char_boundary(end) {
        end -= 1;
    }
    &agent[..end]
}

/// One row of the firmware ceiling table.
#[derive(Debug)]
pub struct CeilingRule {
    /// Model name, used in logs and the low-limit warning.
    pub label: &'static str,
    /// Matches the lower-cased SV1 user agent.
    matches: fn(&str) -> bool,
    /// Matches a native SV2 miner's lower-cased `SetupConnection` fields, used when there is no
    /// SV1 agent.
    matches_sv2: fn(&Sv2Device) -> bool,
    /// The row applies only to agents whose first dotted version is at or below this.
    pub max_version: Option<(u32, u32)>,
    /// Known-safe coinbase ceiling in bytes: the most the loop may try. NOT a measurement unless
    /// the evidence says so.
    pub ceiling_bytes: u32,
    /// Coinbase bytes proven on real hardware of this model. When set, sensing starts at the
    /// largest class within it instead of the smallest. None of the rows has one yet.
    pub proven_bytes: Option<u32>,
    /// Where the ceiling comes from.
    pub evidence: &'static str,
}

impl CeilingRule {
    /// Whether this row matches `agent` (any case), given its parsed version.
    fn applies(&self, lower: &str, version: Option<(u32, u32)>) -> bool {
        (self.matches)(lower) && self.version_ok(version)
    }

    /// Whether this row matches a native SV2 miner, given its firmware's parsed version.
    fn applies_sv2(&self, device: &Sv2Device, version: Option<(u32, u32)>) -> bool {
        (self.matches_sv2)(device) && self.version_ok(version)
    }

    fn version_ok(&self, version: Option<(u32, u32)>) -> bool {
        match self.max_version {
            None => true,
            Some(max) => version.is_some_and(|v| v <= max),
        }
    }
}

fn word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// `needle` occurs with a word boundary after it, and before it too when `left` is set: the
/// regular-expression `\b` the prototype used.
fn has_word(hay: &str, needle: &str, left: bool) -> bool {
    let h = hay.as_bytes();
    hay.match_indices(needle).any(|(i, _)| {
        let end = i + needle.len();
        let right_ok = end == h.len() || !word_byte(h[end]);
        let left_ok = !left || i == 0 || !word_byte(h[i - 1]);
        right_ok && left_ok
    })
}

fn any_of(hay: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| hay.contains(n))
}

fn m_nicehash(a: &str) -> bool {
    a.contains("nicehash")
}
fn m_nerdqaxe(a: &str) -> bool {
    any_of(a, &["nerdaxe", "nerdqaxe", "nerdoctaxe"])
}
fn m_esp_miner(a: &str) -> bool {
    any_of(a, &["bitaxe", "esp-miner", "espminer", "axeos"])
}
fn m_s21(a: &str) -> bool {
    a.starts_with("antminer s21/")
}
fn m_s19xp(a: &str) -> bool {
    any_of(a, &["antminer s19xp", "antminer s19 xp"])
}
fn m_s9_family(a: &str) -> bool {
    [
        "antminer s9",
        "antminer s11",
        "antminer s17",
        "antminer t17",
    ]
    .iter()
    .any(|n| has_word(a, n, false))
}
fn m_antminer(a: &str) -> bool {
    any_of(a, &["antminer", "bmminer", "bitmain"])
}
fn m_avalon(a: &str) -> bool {
    any_of(a, &["avalon", "canaan"])
}
fn m_whatsminer(a: &str) -> bool {
    any_of(a, &["whatsminer", "microbt", "btminer"])
}
fn m_epic(a: &str) -> bool {
    a.contains("powerplay") || has_word(a, "epic", true)
}
fn m_braiins(a: &str) -> bool {
    any_of(a, &["bosminer", "braiins"])
}
fn m_never(_: &str) -> bool {
    false
}

/// A native SV2 miner's identity, from its `SetupConnection`: `vendor`, `hardware_version` and
/// `firmware`. Stored lower-cased and cut to [`MAX_AGENT_LEN`] each; `display` keeps the case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sv2Device {
    vendor: String,
    hardware: String,
    firmware: String,
    firmware_raw: String,
    display: String,
}

impl Sv2Device {
    /// From the three `SetupConnection` fields. `None` when all three are empty.
    pub fn new(vendor: &str, hardware_version: &str, firmware: &str) -> Option<Self> {
        let (v, h, f) = (
            clamp_agent(vendor.trim()),
            clamp_agent(hardware_version.trim()),
            clamp_agent(firmware.trim()),
        );
        if v.is_empty() && h.is_empty() && f.is_empty() {
            return None;
        }
        Some(Self {
            vendor: v.to_ascii_lowercase(),
            hardware: h.to_ascii_lowercase(),
            firmware: f.to_ascii_lowercase(),
            firmware_raw: f.to_string(),
            display: format!("{v}/{h}/{f}"),
        })
    }

    /// `vendor/hardware_version/firmware`, as received.
    pub fn display(&self) -> &str {
        &self.display
    }

    /// The firmware field, as received.
    fn firmware_raw(&self) -> &str {
        &self.firmware_raw
    }

    /// Vendor and firmware, the fields that name the firmware rather than the machine.
    fn software(&self) -> String {
        format!("{}/{}", self.vendor, self.firmware)
    }

    fn all(&self) -> String {
        format!("{}/{}/{}", self.vendor, self.hardware, self.firmware)
    }
}

/// Firmware that replaces the maker's: its own row decides, not the machine it runs on.
fn third_party_firmware(d: &Sv2Device) -> bool {
    let s = d.software();
    m_nicehash(&s) || m_nerdqaxe(&s) || m_esp_miner(&s) || m_epic(&s) || m_braiins(&s)
}

/// Stock firmware on a machine named by `hardware_version`, from a maker named anywhere.
fn stock(d: &Sv2Device, maker: fn(&str) -> bool) -> bool {
    !third_party_firmware(d) && maker(&d.all())
}

fn s_nicehash(d: &Sv2Device) -> bool {
    m_nicehash(&d.software())
}
fn s_nerdqaxe(d: &Sv2Device) -> bool {
    m_nerdqaxe(&d.all())
}
fn s_esp_miner(d: &Sv2Device) -> bool {
    m_esp_miner(&d.all())
}
fn s_s21(d: &Sv2Device) -> bool {
    stock(d, m_antminer) && matches!(d.hardware.as_str(), "s21" | "antminer s21")
}
fn s_s19xp(d: &Sv2Device) -> bool {
    stock(d, m_antminer) && any_of(&d.hardware, &["s19xp", "s19 xp"])
}
fn s_s9_family(d: &Sv2Device) -> bool {
    stock(d, m_antminer)
        && ["s9", "s11", "s17", "t17"]
            .iter()
            .any(|n| has_word(&d.hardware, n, true))
}
fn s_antminer(d: &Sv2Device) -> bool {
    stock(d, m_antminer)
}
fn s_avalon(d: &Sv2Device) -> bool {
    stock(d, m_avalon)
}
fn s_whatsminer(d: &Sv2Device) -> bool {
    stock(d, m_whatsminer)
}
fn s_epic(d: &Sv2Device) -> bool {
    m_epic(&d.software())
}
fn s_braiins(d: &Sv2Device) -> bool {
    m_braiins(&d.software())
}
fn s_never(_: &Sv2Device) -> bool {
    false
}

/// Known-safe coinbase ceilings by user agent (the first parameter of `mining.subscribe`). First
/// matching row wins, so specific rows sit above generic ones. Ported row for row, evidence
/// included, from the prototype's `CEILINGS`. The agent patterns are partly guesses: only the
/// Bitaxe/ESP-Miner format (`bitaxe/<asic>/<version>`) is known from source.
pub static CEILINGS: [CeilingRule; 12] = [
    CeilingRule {
        label: "NiceHash",
        matches: m_nicehash,
        matches_sv2: s_nicehash,
        max_version: None,
        ceiling_bytes: 500,
        proven_bytes: None,
        evidence: "OCEAN DATUM source comment (500 B). Not measured.",
    },
    CeilingRule {
        label: "NerdQAxe",
        matches: m_nerdqaxe,
        matches_sv2: s_nerdqaxe,
        max_version: None,
        ceiling_bytes: 7_600,
        proven_bytes: None,
        evidence: "ESP-Miner-derived; 16 KB mining.notify line limit => about 7.6 KB coinbase. \
                   Source reading.",
    },
    CeilingRule {
        label: "Bitaxe ESP-Miner <= v2.15",
        matches: m_esp_miner,
        matches_sv2: s_esp_miner,
        max_version: Some((2, 15)),
        ceiling_bytes: 22_000,
        proven_bytes: None,
        evidence: "ESP-Miner source up to v2.15: no line limit found, coinb1 at most 1,024 B. \
                   Source reading.",
    },
    CeilingRule {
        label: "Bitaxe ESP-Miner main / newer / no version",
        matches: m_esp_miner,
        matches_sv2: s_esp_miner,
        max_version: None,
        ceiling_bytes: 7_600,
        proven_bytes: None,
        evidence: "ESP-Miner main drops notify lines over 16,384 chars => about 7.6 KB coinbase. \
                   Source reading.",
    },
    CeilingRule {
        label: "Antminer S21",
        matches: m_s21,
        matches_sv2: s_s21,
        max_version: None,
        ceiling_bytes: 2_250,
        proven_bytes: None,
        evidence: "OCEAN DATUM code and talk; production image encrypted. Not measured.",
    },
    CeilingRule {
        label: "Antminer S19 XP",
        matches: m_s19xp,
        matches_sv2: s_s19xp,
        max_version: None,
        ceiling_bytes: 2_048,
        proven_bytes: None,
        evidence: "Disassembly of Bitmain's CVITEK image: stack overflow past 2,048 B. The Zynq \
                   variant (7,650 B) cannot be told apart by agent, so the lower ceiling applies.",
    },
    CeilingRule {
        label: "Antminer S9/S11/S17/T17",
        matches: m_s9_family,
        matches_sv2: s_s9_family,
        max_version: None,
        ceiling_bytes: 7_650,
        proven_bytes: None,
        evidence: "Bitmain source: last_job_buffer[8192] at bmminer-mix/driver-btm-c5.c:347, \
                   copied unchecked at :11115 => memory overwrite past about 7.65 KB.",
    },
    CeilingRule {
        label: "Stock Antminer (default)",
        matches: m_antminer,
        matches_sv2: s_antminer,
        max_version: None,
        ceiling_bytes: 730,
        proven_bytes: None,
        evidence: "OCEAN DATUM default for stock Antminer. Image encrypted; no code found that \
                   explains it.",
    },
    CeilingRule {
        label: "Avalon",
        matches: m_avalon,
        matches_sv2: s_avalon,
        max_version: None,
        ceiling_bytes: 6_144,
        proven_bytes: None,
        evidence: "Canaan source: oversize jobs silently skipped, miner keeps hashing stale work.",
    },
    CeilingRule {
        label: "Whatsminer",
        matches: m_whatsminer,
        matches_sv2: s_whatsminer,
        max_version: None,
        ceiling_bytes: 6_500,
        proven_bytes: None,
        evidence: "OCEAN DATUM code ('tested'). Not measured by us.",
    },
    CeilingRule {
        label: "ePIC PowerPlay-BM",
        matches: m_epic,
        matches_sv2: s_epic,
        max_version: None,
        ceiling_bytes: 16_000,
        proven_bytes: None,
        evidence: "OCEAN DATUM code (16 KB). Not measured.",
    },
    CeilingRule {
        label: "Braiins bosminer",
        matches: m_braiins,
        matches_sv2: s_braiins,
        max_version: None,
        ceiling_bytes: 16_000,
        proven_bytes: None,
        evidence: "OCEAN DATUM code; Braiins 'not extensively tested'.",
    },
];

/// The row an agent gets when no row matches, or when there is no agent at all.
pub static UNKNOWN_AGENT: CeilingRule = CeilingRule {
    label: "unknown agent",
    matches: m_never,
    matches_sv2: s_never,
    max_version: None,
    ceiling_bytes: SLOT_CLASS_COINBASE_BYTES[0],
    proven_bytes: None,
    evidence: "No row matched: smallest class only (spec 2.1).",
};

/// Read `digits '.' digits ('.' digits)* ([-+] [\w.-]*)?` at `i`; returns the end and
/// `(major, minor)`. Numbers too large for `u32` saturate.
fn scan_version(b: &[u8], i: usize) -> Option<(usize, (u32, u32))> {
    fn digits(b: &[u8], mut i: usize) -> Option<(usize, u32)> {
        let start = i;
        let mut n: u32 = 0;
        while i < b.len() && b[i].is_ascii_digit() {
            n = n.saturating_mul(10).saturating_add((b[i] - b'0') as u32);
            i += 1;
        }
        (i > start).then_some((i, n))
    }
    let (i, major) = digits(b, i)?;
    if b.get(i) != Some(&b'.') {
        return None;
    }
    let (mut i, minor) = digits(b, i + 1)?;
    while b.get(i) == Some(&b'.') && b.get(i + 1).is_some_and(|c| c.is_ascii_digit()) {
        i = digits(b, i + 1)?.0;
    }
    if matches!(b.get(i), Some(b'-' | b'+')) {
        i += 1;
        while b
            .get(i)
            .is_some_and(|&c| word_byte(c) || c == b'.' || c == b'-')
        {
            i += 1;
        }
    }
    Some((i, (major, minor)))
}

/// The version token in an agent and its `(major, minor)`, as the prototype's
/// `parse_firmware`: first a `v1.2...` token at a word start, else a bare `1.2...` not preceded
/// by a word character or a dot.
pub fn parse_firmware(agent: &str) -> (Option<String>, Option<(u32, u32)>) {
    let b = agent.as_bytes();
    for (i, &c) in b.iter().enumerate() {
        if (c == b'v' || c == b'V') && (i == 0 || !word_byte(b[i - 1])) {
            if let Some((end, v)) = scan_version(b, i + 1) {
                return (Some(agent[i..end].to_string()), Some(v));
            }
        }
    }
    for (i, &c) in b.iter().enumerate() {
        let free = i == 0 || !(word_byte(b[i - 1]) || b[i - 1] == b'.');
        if c.is_ascii_digit() && free {
            if let Some((end, v)) = scan_version(b, i) {
                return (Some(agent[i..end].to_string()), Some(v));
            }
        }
    }
    (None, None)
}

/// The ceiling row for an agent and the firmware token parsed from it.
pub fn lookup_ceiling(agent: Option<&str>) -> (&'static CeilingRule, Option<String>) {
    let Some(agent) = agent else {
        return (&UNKNOWN_AGENT, None);
    };
    let (firmware, version) = parse_firmware(agent);
    let lower = agent.to_ascii_lowercase();
    let rule = CEILINGS
        .iter()
        .find(|r| r.applies(&lower, version))
        .unwrap_or(&UNKNOWN_AGENT);
    (rule, firmware)
}

/// The ceiling row for a native SV2 miner, matched on its `SetupConnection` fields, and the
/// firmware token parsed from its firmware field.
pub fn lookup_ceiling_sv2(device: &Sv2Device) -> (&'static CeilingRule, Option<String>) {
    let (firmware, version) = parse_firmware(device.firmware_raw());
    let rule = CEILINGS
        .iter()
        .find(|r| r.applies_sv2(device, version))
        .unwrap_or(&UNKNOWN_AGENT);
    (rule, firmware)
}

/// Who a miner says it is: an SV1 `mining.subscribe` agent, or a native SV2 miner's
/// `SetupConnection` fields. The agent wins when both exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MinerIdentity {
    /// The SV1 agent, forwarded by the translator.
    Agent(String),
    /// A native SV2 miner's `SetupConnection`.
    Sv2(Sv2Device),
}

impl MinerIdentity {
    /// The ceiling row and parsed firmware token for this identity.
    pub fn lookup(&self) -> (&'static CeilingRule, Option<String>) {
        match self {
            MinerIdentity::Agent(a) => lookup_ceiling(Some(a)),
            MinerIdentity::Sv2(d) => lookup_ceiling_sv2(d),
        }
    }

    /// The identity as shown in logs and status.
    pub fn display(&self) -> &str {
        match self {
            MinerIdentity::Agent(a) => a,
            MinerIdentity::Sv2(d) => d.display(),
        }
    }
}

/// Index of the largest class whose coinbase fits `bytes`. The smallest class is always served,
/// even below its size: every miner must work.
pub fn class_index_within(bytes: u32) -> usize {
    SLOT_CLASS_COINBASE_BYTES
        .iter()
        .rposition(|&b| b <= bytes)
        .unwrap_or(0)
}

/// Warning for known low-limit firmware (plan section 6): the model and the class it is limited
/// to. Shown at connect and on the miner's status; the miner is not refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareWarning {
    /// Model, from the ceiling table.
    pub model: &'static str,
    /// The largest class this firmware may be stepped to, in miner outputs.
    pub limited_to_class: u16,
    /// The model's known-safe coinbase ceiling, in bytes.
    pub ceiling_bytes: u32,
}

impl fmt::Display for FirmwareWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} firmware is limited to slot class {} ({} B coinbase ceiling): a block it finds \
             pays at most {} owed balances, and what it cannot pay goes to the treasury",
            self.model, self.limited_to_class, self.ceiling_bytes, self.limited_to_class
        )
    }
}

/// The warning for an agent, if it is known low-limit firmware: a table row (not the unknown
/// fallback) whose ceiling keeps it below the full class.
pub fn firmware_warning(agent: Option<&str>) -> Option<FirmwareWarning> {
    let (rule, _) = lookup_ceiling(agent);
    warning_for(rule)
}

fn warning_for(rule: &'static CeilingRule) -> Option<FirmwareWarning> {
    let top = class_index_within(rule.ceiling_bytes);
    if std::ptr::eq(rule, &UNKNOWN_AGENT) || top == FULL_CLASS_INDEX {
        return None;
    }
    Some(FirmwareWarning {
        model: rule.label,
        limited_to_class: SLOT_CLASSES[top],
        ceiling_bytes: rule.ceiling_bytes,
    })
}

/// Loop settings. Defaults follow the prototype's `--sense` defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SensingParams {
    /// Valid shares needed at a class before stepping up (M in the spec).
    pub min_shares: u32,
    /// Most time a trial class gets to reach `min_shares`.
    pub dwell_ms: u64,
    /// No valid share for this many share intervals is a failure.
    pub timeout_factor: u32,
    /// Floor on that timeout.
    pub min_timeout_ms: u64,
    /// Shares on older, smaller work with none on the current job that count as a silent skip.
    pub stale_limit: u32,
    /// How long after a class change shares on the previous class are tolerated.
    pub grace_ms: u64,
    /// The share interval the channel's difficulty aims at.
    pub expected_share_interval_ms: u64,
}

impl Default for SensingParams {
    fn default() -> Self {
        Self {
            min_shares: 20,
            dwell_ms: 300_000,
            timeout_factor: 20,
            min_timeout_ms: 30_000,
            stale_limit: 3,
            grace_ms: 20_000,
            expected_share_interval_ms: 3_000,
        }
    }
}

impl SensingParams {
    /// Defaults for a channel aiming at `shares_per_minute`. The dwell is stretched to twice the
    /// expected time to `min_shares`, so a slow share rate does not read as low yield.
    pub fn for_shares_per_minute(shares_per_minute: f32, min_shares: u32) -> Self {
        let d = Self::default();
        let interval = if shares_per_minute.is_finite() && shares_per_minute > 0.0 {
            (60_000.0 / shares_per_minute as f64).round() as u64
        } else {
            d.expected_share_interval_ms
        };
        let min_shares = min_shares.max(1);
        Self {
            min_shares,
            dwell_ms: d.dwell_ms.max(2 * min_shares as u64 * interval.max(1)),
            expected_share_interval_ms: interval.max(1),
            ..d
        }
    }
}

/// Why a class was given up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// No valid share within the timeout.
    NoShares,
    /// A trial class did not reach `min_shares` within its dwell.
    LowYield,
    /// A share did not recompute against the job sent: the firmware hashed other bytes.
    Corrupt,
    /// The miner kept hashing older, smaller work: the job was silently skipped.
    StaleWork,
    /// The connection dropped while the class was served.
    Disconnect,
}

impl FailureKind {
    /// Short name for logs and status.
    pub fn as_str(self) -> &'static str {
        match self {
            FailureKind::NoShares => "no-shares",
            FailureKind::LowYield => "low-yield",
            FailureKind::Corrupt => "corrupt",
            FailureKind::StaleWork => "stale-work",
            FailureKind::Disconnect => "disconnect",
        }
    }
}

/// What the pool made of a share, as far as sensing cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareVerdict {
    /// The share recomputed against its job and met the target.
    Valid,
    /// The share did not recompute against its job (wrong header or under target).
    Corrupt,
    /// Refused for another reason (stale, duplicate); counts only as evidence of which job the
    /// miner is hashing.
    Other,
}

/// Why the served class changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeCause {
    /// The class passed; trying the next one.
    Passed,
    /// The class failed; back to the highest passed class, or the floor.
    Failed(FailureKind),
}

/// A change in the class served to one miner. The caller rebuilds the miner's job when
/// `from != to`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassChange {
    /// Miner outputs before.
    pub from: u16,
    /// Miner outputs now.
    pub to: u16,
    /// Why.
    pub cause: ChangeCause,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// Counting valid shares toward a step up.
    Trial,
    /// Settled: no further step this session.
    Hold,
}

#[derive(Debug, Clone, Copy)]
struct Attempt {
    started_ms: u64,
    last_progress_ms: u64,
    valid: u32,
    stale: u32,
}

const CLASS_COUNT: usize = SLOT_CLASSES.len();

/// What a miner's sensing has established, for storage (W2.4) and status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensingRecord {
    /// The agent the miner reported, if any.
    pub agent: Option<String>,
    /// The largest class that passed this session, in miner outputs.
    pub highest_passed: Option<u16>,
    /// Classes that failed this session and why, in miner outputs.
    pub failed: Vec<(u16, FailureKind)>,
}

/// Storage for sensing results, keyed by miner (payout script plus worker, or whatever key the
/// caller sensed under). Implemented by W2.4; nothing persists until then. How a stored record
/// seeds a new session is W2.4's decision: the spec bounds retries only within a session.
pub trait SensingStore {
    /// The stored record for `miner`, if any.
    fn load(&self, miner: &str) -> Option<SensingRecord>;
    /// Store `record` for `miner`.
    fn save(&self, miner: &str, record: &SensingRecord);
}

/// Status of one miner's sensing, for logs and the status API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensingStatus {
    /// The agent the miner reported, if any.
    pub agent: Option<String>,
    /// Firmware version token parsed from the agent.
    pub firmware: Option<String>,
    /// The ceiling row that applied.
    pub model: &'static str,
    /// That row's ceiling, in coinbase bytes.
    pub ceiling_bytes: u32,
    /// The largest class the loop may try, in miner outputs.
    pub ceiling_class: u16,
    /// The class being served now.
    pub serving_class: u16,
    /// Whether the loop has settled.
    pub settled: bool,
    /// The largest class that passed.
    pub highest_passed: Option<u16>,
    /// Classes that failed and why.
    pub failed: Vec<(u16, FailureKind)>,
    /// Valid shares counted this session.
    pub valid_shares: u64,
    /// The low-limit firmware warning, if this model is one.
    pub warning: Option<FirmwareWarning>,
}

/// The sensing loop for one miner, for one session.
#[derive(Debug, Clone)]
pub struct ClassSensor {
    params: SensingParams,
    rule: &'static CeilingRule,
    agent: Option<String>,
    firmware: Option<String>,
    top: usize,
    idx: usize,
    role: Role,
    passed: [bool; CLASS_COUNT],
    failed: [Option<FailureKind>; CLASS_COUNT],
    att: Attempt,
    valid_times: VecDeque<u64>,
    connected: bool,
    valid_total: u64,
}

/// How many recent valid-share times feed the measured share interval.
const VALID_TIMES_KEPT: usize = 50;

impl ClassSensor {
    /// Start sensing a miner that connected at `now_ms` with `agent`.
    pub fn new(agent: Option<&str>, params: SensingParams, now_ms: u64) -> Self {
        let agent = agent.map(clamp_agent);
        let (rule, firmware) = lookup_ceiling(agent);
        Self::with_rule(rule, agent.map(str::to_string), firmware, params, now_ms)
    }

    /// Start sensing a miner known by an SV1 agent or its SV2 `SetupConnection`, or by nothing.
    pub fn for_identity(
        identity: Option<&MinerIdentity>,
        params: SensingParams,
        now_ms: u64,
    ) -> Self {
        match identity {
            Some(MinerIdentity::Agent(a)) => Self::new(Some(a), params, now_ms),
            Some(id @ MinerIdentity::Sv2(d)) => {
                let (rule, firmware) = id.lookup();
                Self::with_rule(
                    rule,
                    Some(d.display().to_string()),
                    firmware,
                    params,
                    now_ms,
                )
            }
            None => Self::new(None, params, now_ms),
        }
    }

    fn with_rule(
        rule: &'static CeilingRule,
        agent: Option<String>,
        firmware: Option<String>,
        params: SensingParams,
        now_ms: u64,
    ) -> Self {
        let top = class_index_within(rule.ceiling_bytes);
        // A class proven on this model's hardware counts as passed: start there, still climbing.
        let start = rule
            .proven_bytes
            .map_or(0, |p| class_index_within(p).min(top));
        let mut passed = [false; CLASS_COUNT];
        passed[..start].iter_mut().for_each(|p| *p = true);
        Self {
            params,
            rule,
            agent,
            firmware,
            top,
            idx: start,
            role: Role::Trial,
            passed,
            failed: [None; CLASS_COUNT],
            att: Attempt {
                started_ms: now_ms,
                last_progress_ms: now_ms,
                valid: 0,
                stale: 0,
            },
            valid_times: VecDeque::new(),
            connected: true,
            valid_total: 0,
        }
    }

    /// The class to build this miner's jobs at, in miner outputs.
    pub fn serving_class(&self) -> u16 {
        SLOT_CLASSES[self.idx]
    }

    /// The ceiling row that applies.
    pub fn rule(&self) -> &'static CeilingRule {
        self.rule
    }

    /// Whether the miner is connected, as far as this sensor was told.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    fn begin(&mut self, idx: usize, role: Role, now_ms: u64) {
        self.idx = idx;
        self.role = role;
        self.att = Attempt {
            started_ms: now_ms,
            last_progress_ms: now_ms,
            valid: 0,
            stale: 0,
        };
    }

    fn highest_passed_index(&self) -> Option<usize> {
        self.passed.iter().rposition(|&p| p)
    }

    /// Give up the current class: never retried this session. Back to the highest passed class
    /// and hold there; if nothing has passed, the smallest class stays in service as the floor.
    fn fail(&mut self, kind: FailureKind, now_ms: u64) -> ClassChange {
        let from = self.idx;
        self.failed[from].get_or_insert(kind);
        self.passed[from] = false;
        match self.highest_passed_index() {
            Some(back) => self.begin(back, Role::Hold, now_ms),
            None => self.begin(0, Role::Trial, now_ms),
        }
        ClassChange {
            from: SLOT_CLASSES[from],
            to: SLOT_CLASSES[self.idx],
            cause: ChangeCause::Failed(kind),
        }
    }

    fn on_valid(&mut self, now_ms: u64) -> Option<ClassChange> {
        self.att.valid += 1;
        self.att.last_progress_ms = now_ms;
        self.valid_total += 1;
        self.valid_times.push_back(now_ms);
        while self.valid_times.len() > VALID_TIMES_KEPT {
            self.valid_times.pop_front();
        }
        if self.role != Role::Trial || self.att.valid < self.params.min_shares {
            return None;
        }
        self.passed[self.idx] = true;
        let from = self.idx;
        let next = from + 1;
        if next < CLASS_COUNT && next <= self.top && self.failed[next].is_none() {
            self.begin(next, Role::Trial, now_ms);
            Some(ClassChange {
                from: SLOT_CLASSES[from],
                to: SLOT_CLASSES[next],
                cause: ChangeCause::Passed,
            })
        } else {
            self.begin(from, Role::Hold, now_ms);
            None
        }
    }

    /// A share arrived for a job built at `job_class` miner outputs.
    ///
    /// A share for another class than the one served is in-flight work from a class just left
    /// (ignored), or, past the grace period and on a smaller class, a sign the miner never took
    /// the new job: `stale_limit` of those with no valid share on the new job fail the class.
    pub fn on_share(
        &mut self,
        job_class: u16,
        verdict: ShareVerdict,
        now_ms: u64,
    ) -> Option<ClassChange> {
        let serving = self.serving_class();
        if job_class != serving {
            let late = now_ms.saturating_sub(self.att.started_ms) > self.params.grace_ms;
            if late && job_class < serving {
                self.att.stale += 1;
                if self.att.stale >= self.params.stale_limit && self.att.valid == 0 {
                    return Some(self.fail(FailureKind::StaleWork, now_ms));
                }
            }
            return None;
        }
        match verdict {
            ShareVerdict::Valid => self.on_valid(now_ms),
            ShareVerdict::Corrupt => Some(self.fail(FailureKind::Corrupt, now_ms)),
            ShareVerdict::Other => None,
        }
    }

    /// The miner's connection dropped. A class still being tested (its step-up dwell) fails:
    /// the drop may be the firmware choking on it. A settled miner keeps its class and resumes
    /// there on reconnect; classes that failed earlier stay failed.
    pub fn on_disconnect(&mut self, now_ms: u64) -> Option<ClassChange> {
        self.connected = false;
        (self.role == Role::Trial).then(|| self.fail(FailureKind::Disconnect, now_ms))
    }

    /// The miner came back. The no-share clock does not run while it was away, and a settled
    /// class resumes where it was.
    pub fn on_reconnect(&mut self, now_ms: u64) {
        self.connected = true;
        self.att.last_progress_ms = now_ms;
    }

    /// The no-share timeout: `timeout_factor` share intervals, measured once there are enough
    /// valid shares, never below `min_timeout_ms`.
    pub fn timeout_ms(&self) -> u64 {
        let t = &self.valid_times;
        let measured = match (t.front(), t.back()) {
            (Some(first), Some(last)) if t.len() >= 5 => (last - first) / (t.len() as u64 - 1),
            _ => 0,
        };
        let interval = self.params.expected_share_interval_ms.max(measured);
        self.params
            .min_timeout_ms
            .max(interval.saturating_mul(self.params.timeout_factor as u64))
    }

    /// Check the clocks: no valid share within the timeout, or a trial past its dwell.
    pub fn tick(&mut self, now_ms: u64) -> Option<ClassChange> {
        if !self.connected {
            return None;
        }
        let idle = now_ms.saturating_sub(self.att.last_progress_ms);
        if idle > self.timeout_ms() {
            let kind = if self.att.stale > 0 && self.att.valid == 0 {
                FailureKind::StaleWork
            } else {
                FailureKind::NoShares
            };
            return Some(self.fail(kind, now_ms));
        }
        if self.role == Role::Trial
            && now_ms.saturating_sub(self.att.started_ms) > self.params.dwell_ms
        {
            return Some(self.fail(FailureKind::LowYield, now_ms));
        }
        None
    }

    fn failed_list(&self) -> Vec<(u16, FailureKind)> {
        self.failed
            .iter()
            .enumerate()
            .filter_map(|(i, f)| f.map(|k| (SLOT_CLASSES[i], k)))
            .collect()
    }

    /// What this session has established, for storage.
    pub fn record(&self) -> SensingRecord {
        SensingRecord {
            agent: self.agent.clone(),
            highest_passed: self.highest_passed_index().map(|i| SLOT_CLASSES[i]),
            failed: self.failed_list(),
        }
    }

    /// Status for logs and the status API.
    pub fn status(&self) -> SensingStatus {
        SensingStatus {
            agent: self.agent.clone(),
            firmware: self.firmware.clone(),
            model: self.rule.label,
            ceiling_bytes: self.rule.ceiling_bytes,
            ceiling_class: SLOT_CLASSES[self.top],
            serving_class: self.serving_class(),
            settled: self.role == Role::Hold,
            highest_passed: self.highest_passed_index().map(|i| SLOT_CLASSES[i]),
            failed: self.failed_list(),
            valid_shares: self.valid_total,
            warning: warning_for(self.rule),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn label(agent: &str) -> &'static str {
        lookup_ceiling(Some(agent)).0.label
    }

    fn params() -> SensingParams {
        SensingParams {
            min_shares: 3,
            dwell_ms: 60_000,
            timeout_factor: 10,
            min_timeout_ms: 5_000,
            stale_limit: 3,
            grace_ms: 2_000,
            expected_share_interval_ms: 1_000,
        }
    }

    /// Feed `n` valid shares one second apart at the class being served.
    fn feed(s: &mut ClassSensor, n: u32, now: &mut u64) -> Vec<ClassChange> {
        let mut out = vec![];
        for _ in 0..n {
            *now += 1_000;
            out.extend(s.on_share(s.serving_class(), ShareVerdict::Valid, *now));
        }
        out
    }

    #[test]
    fn class_sizes_match_the_classes() {
        assert_eq!(SLOT_CLASS_COINBASE_BYTES.len(), SLOT_CLASSES.len());
        assert!(SLOT_CLASS_COINBASE_BYTES.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(class_index_within(0), 0, "the floor is always served");
        assert_eq!(class_index_within(730), 1);
        assert_eq!(class_index_within(2_249), 1);
        assert_eq!(class_index_within(7_650), 3);
        assert_eq!(class_index_within(22_000), FULL_CLASS_INDEX);
    }

    #[test]
    fn each_ceiling_row_matches_its_agents() {
        let cases = [
            ("NiceHash/1.0.0", "NiceHash"),
            ("NerdQAxe++/BM1370/v1.0.30", "NerdQAxe"),
            ("nerdoctaxe/2.0", "NerdQAxe"),
            ("bitaxe/BM1366/v2.4.0", "Bitaxe ESP-Miner <= v2.15"),
            ("bitaxe/BM1370/v2.15.3", "Bitaxe ESP-Miner <= v2.15"),
            (
                "bitaxe/BM1370/v2.16.0",
                "Bitaxe ESP-Miner main / newer / no version",
            ),
            (
                "bitaxe/BM1370",
                "Bitaxe ESP-Miner main / newer / no version",
            ),
            ("AxeOS 3.1", "Bitaxe ESP-Miner main / newer / no version"),
            ("Antminer S21/Fri Feb 2 2024", "Antminer S21"),
            ("Antminer S21 Pro", "Stock Antminer (default)"),
            ("Antminer S19XP/x", "Antminer S19 XP"),
            ("antminer s19 xp hyd", "Antminer S19 XP"),
            ("Antminer S9/1.0", "Antminer S9/S11/S17/T17"),
            ("antminer t17+", "Antminer S9/S11/S17/T17"),
            ("Antminer S19j Pro", "Stock Antminer (default)"),
            ("Antminer S95", "Stock Antminer (default)"),
            ("bmminer/2.0.0", "Stock Antminer (default)"),
            ("cgminer/4.11.1 Avalon", "Avalon"),
            ("whatsminer/v1.0", "Whatsminer"),
            ("BTMiner 3.1", "Whatsminer"),
            ("PowerPlay-BM/1.0", "ePIC PowerPlay-BM"),
            ("epic/2.0", "ePIC PowerPlay-BM"),
            ("bosminer-plus/1.0", "Braiins bosminer"),
            ("cgminer/4.10", "unknown agent"),
            ("epicminer", "unknown agent"),
            ("", "unknown agent"),
        ];
        for (agent, want) in cases {
            assert_eq!(label(agent), want, "agent {agent:?}");
        }
        assert_eq!(lookup_ceiling(None).0.label, "unknown agent");
    }

    #[test]
    fn firmware_versions_parse_like_the_prototype() {
        assert_eq!(
            parse_firmware("bitaxe/BM1366/v2.4.0"),
            (Some("v2.4.0".into()), Some((2, 4)))
        );
        assert_eq!(
            parse_firmware("bosminer/22.08.1-plus"),
            (Some("22.08.1-plus".into()), Some((22, 8)))
        );
        assert_eq!(
            parse_firmware("x V3.10"),
            (Some("V3.10".into()), Some((3, 10)))
        );
        // A version glued to a word is not a version token.
        assert_eq!(parse_firmware("abc1.2"), (None, None));
        assert_eq!(parse_firmware("no version"), (None, None));
        assert_eq!(parse_firmware("v.1"), (None, None));
        // A `v` token wins over an earlier bare number.
        assert_eq!(parse_firmware("1.0 v2.3").1, Some((2, 3)));
    }

    #[test]
    fn agents_are_clamped() {
        let long = "é".repeat(200);
        let c = clamp_agent(&long);
        assert!(c.len() <= MAX_AGENT_LEN && c.is_char_boundary(c.len()));
        assert_eq!(clamp_agent("short"), "short");
    }

    #[test]
    fn known_low_limit_firmware_is_warned_about() {
        let w = firmware_warning(Some("Antminer S19j Pro")).unwrap();
        assert_eq!(w.model, "Stock Antminer (default)");
        assert_eq!(w.limited_to_class, 9);
        assert!(w.to_string().contains("limited to slot class 9"));
        // The S21's 2,250 B ceiling is exactly the 44 class's size: it fits.
        assert_eq!(
            firmware_warning(Some("Antminer S21/x"))
                .unwrap()
                .limited_to_class,
            44
        );
    }

    #[test]
    fn full_class_firmware_and_unknown_agents_get_no_warning() {
        assert_eq!(firmware_warning(Some("bitaxe/BM1366/v2.4.0")), None);
        assert_eq!(firmware_warning(Some("mystery miner")), None);
        assert_eq!(firmware_warning(None), None);
        assert_eq!(
            firmware_warning(Some("bosminer/1.0"))
                .unwrap()
                .limited_to_class,
            364
        );
    }

    #[test]
    fn climbs_one_class_at_a_time_to_the_ceiling_and_settles() {
        let mut now = 0;
        // Avalon: 6,144 B ceiling, so classes 3, 9 and 44 only.
        let mut s = ClassSensor::new(Some("Avalon Nano 3s"), params(), now);
        assert_eq!(s.serving_class(), 3, "always starts at the smallest class");
        let mut ups = vec![];
        for _ in 0..10 {
            ups.extend(feed(&mut s, 3, &mut now));
        }
        let path: Vec<_> = ups.iter().map(|c| (c.from, c.to)).collect();
        assert_eq!(path, [(3, 9), (9, 44)]);
        assert!(ups.iter().all(|c| c.cause == ChangeCause::Passed));
        let st = s.status();
        assert_eq!((st.serving_class, st.ceiling_class), (44, 44));
        assert!(st.settled);
        assert_eq!(st.highest_passed, Some(44));
        assert_eq!(st.warning.unwrap().limited_to_class, 44);
    }

    #[test]
    fn an_unknown_agent_stays_at_the_smallest_class() {
        let mut now = 0;
        let mut s = ClassSensor::new(None, params(), now);
        assert!(feed(&mut s, 30, &mut now).is_empty());
        assert_eq!(s.serving_class(), 3);
        assert!(s.status().settled);
    }

    #[test]
    fn a_corrupt_share_drops_back_and_the_class_is_never_retried() {
        let mut now = 0;
        let mut s = ClassSensor::new(Some("bitaxe/BM1366/v2.4.0"), params(), now);
        feed(&mut s, 6, &mut now); // passes 3 and 9, now trying 44
        assert_eq!(s.serving_class(), 44);
        now += 1_000;
        let c = s.on_share(44, ShareVerdict::Corrupt, now).unwrap();
        assert_eq!(
            c,
            ClassChange {
                from: 44,
                to: 9,
                cause: ChangeCause::Failed(FailureKind::Corrupt)
            }
        );
        // Held at 9 for good: more valid shares never step back up to 44.
        assert!(feed(&mut s, 50, &mut now).is_empty());
        assert_eq!(s.serving_class(), 9);
        assert_eq!(s.record().failed, vec![(44, FailureKind::Corrupt)]);
        assert_eq!(s.record().highest_passed, Some(9));
    }

    #[test]
    fn a_disconnect_mid_probe_fails_that_probe() {
        let mut now = 0;
        let mut s = ClassSensor::new(Some("Avalon"), params(), now);
        feed(&mut s, 3, &mut now);
        assert_eq!(s.serving_class(), 9, "probing 9");
        let c = s.on_disconnect(now).unwrap();
        assert_eq!((c.from, c.to), (9, 3));
        assert_eq!(c.cause, ChangeCause::Failed(FailureKind::Disconnect));
        assert_eq!(s.tick(now + 1_000_000), None, "no clock while away");
        s.on_reconnect(now + 1_000_000);
        now += 1_000_000;
        assert!(s.tick(now + 1_000).is_none());
        assert_eq!(s.serving_class(), 3);
        assert!(feed(&mut s, 10, &mut now).is_empty(), "9 is not retried");
    }

    #[test]
    fn a_flapping_settled_bitaxe_keeps_its_class() {
        let mut now = 0;
        let mut s = ClassSensor::new(Some("bitaxe/BM1366/v2.4.0"), params(), now);
        // Passes 3, 9, 44 and 143, fails 364 on a corrupt share, settles back at 143.
        feed(&mut s, 12, &mut now);
        assert_eq!(s.serving_class(), 364);
        now += 1_000;
        s.on_share(364, ShareVerdict::Corrupt, now).unwrap();
        assert_eq!(s.serving_class(), 143);
        assert!(s.status().settled);
        for _ in 0..5 {
            now += 1_000;
            assert_eq!(
                s.on_disconnect(now),
                None,
                "a settled class survives a drop"
            );
            assert!(!s.is_connected());
            now += 60_000;
            s.on_reconnect(now);
            assert_eq!(s.serving_class(), 143);
            assert!(s.tick(now + 1_000).is_none());
            feed(&mut s, 2, &mut now);
        }
        let st = s.status();
        assert!(st.settled);
        assert_eq!(st.highest_passed, Some(143));
        assert_eq!(
            st.failed,
            vec![(364, FailureKind::Corrupt)],
            "364 stays failed"
        );
        assert!(
            feed(&mut s, 20, &mut now).is_empty(),
            "and is never retried"
        );
    }

    #[test]
    fn silence_fails_the_class_after_the_timeout() {
        let mut now = 0;
        let mut s = ClassSensor::new(Some("Avalon"), params(), now);
        feed(&mut s, 3, &mut now); // trying 9
        assert_eq!(s.tick(now + 9_000), None, "timeout is 10 s at 1 s shares");
        let c = s.tick(now + 10_001).unwrap();
        assert_eq!(c.cause, ChangeCause::Failed(FailureKind::NoShares));
        assert_eq!((c.from, c.to), (9, 3));
    }

    #[test]
    fn the_timeout_follows_the_measured_share_rate() {
        let mut now = 0;
        let mut s = ClassSensor::new(None, params(), now);
        for _ in 0..6 {
            now += 4_000;
            s.on_share(3, ShareVerdict::Valid, now);
        }
        assert_eq!(s.timeout_ms(), 40_000);
    }

    #[test]
    fn a_silently_skipped_job_reads_as_stale_work() {
        let mut now = 0;
        let mut s = ClassSensor::new(Some("Avalon"), params(), now);
        feed(&mut s, 3, &mut now); // serving 9 from `now`
                                   // In-flight class-3 shares inside the grace period are ignored.
        assert_eq!(s.on_share(3, ShareVerdict::Valid, now + 1_000), None);
        // After it, the miner is still on class-3 work: three of those fail 9.
        assert_eq!(s.on_share(3, ShareVerdict::Valid, now + 3_000), None);
        assert_eq!(s.on_share(3, ShareVerdict::Other, now + 3_500), None);
        let c = s.on_share(3, ShareVerdict::Valid, now + 4_000).unwrap();
        assert_eq!(c.cause, ChangeCause::Failed(FailureKind::StaleWork));
        assert_eq!(c.to, 3);
    }

    #[test]
    fn work_from_a_larger_class_just_left_is_ignored() {
        let mut now = 0;
        let mut s = ClassSensor::new(Some("Avalon"), params(), now);
        feed(&mut s, 3, &mut now);
        s.on_share(9, ShareVerdict::Corrupt, now + 100);
        assert_eq!(s.serving_class(), 3);
        for t in 1..10 {
            assert_eq!(s.on_share(9, ShareVerdict::Valid, now + t * 5_000), None);
        }
    }

    #[test]
    fn a_failure_at_the_floor_keeps_the_floor_in_service() {
        let mut now = 0;
        let mut s = ClassSensor::new(Some("Avalon"), params(), now);
        let c = s.on_share(3, ShareVerdict::Corrupt, 1).unwrap();
        assert_eq!((c.from, c.to), (3, 3));
        // The floor is not a retry: it can still pass, but 9 is then the next step.
        feed(&mut s, 3, &mut now);
        assert_eq!(s.serving_class(), 9);
        assert_eq!(s.record().failed, vec![(3, FailureKind::Corrupt)]);
    }

    #[test]
    fn a_trial_past_its_dwell_is_low_yield() {
        let p = SensingParams {
            min_shares: 10,
            dwell_ms: 20_000,
            ..params()
        };
        let mut s = ClassSensor::new(Some("Avalon"), p, 0);
        // A valid share every 5 s keeps the no-share timeout (10 s) away, but four shares in a
        // 20 s dwell never reach ten.
        let mut got = None;
        for t in (5_000..=25_000).step_by(5_000) {
            assert_eq!(s.on_share(3, ShareVerdict::Valid, t), None);
            got = got.or(s.tick(t + 1_000));
        }
        let c = got.unwrap();
        assert_eq!(c.cause, ChangeCause::Failed(FailureKind::LowYield));
        assert_eq!((c.from, c.to), (3, 3));
    }

    #[test]
    fn a_proven_class_starts_the_climb_there() {
        static PROVEN: CeilingRule = CeilingRule {
            label: "test",
            matches: m_never,
            matches_sv2: s_never,
            max_version: None,
            ceiling_bytes: 16_000,
            proven_bytes: Some(2_250),
            evidence: "test",
        };
        let mut now = 0;
        let mut s = ClassSensor::with_rule(&PROVEN, None, None, params(), now);
        assert_eq!(s.serving_class(), 44);
        assert_eq!(s.record().highest_passed, Some(9));
        let c = feed(&mut s, 3, &mut now);
        assert_eq!((c[0].from, c[0].to), (44, 143));
    }

    #[test]
    fn params_scale_with_the_share_rate() {
        let p = SensingParams::for_shares_per_minute(6.0, 20);
        assert_eq!(p.expected_share_interval_ms, 10_000);
        assert_eq!(p.dwell_ms, 400_000);
        let p = SensingParams::for_shares_per_minute(f32::NAN, 0);
        assert_eq!(p.min_shares, 1);
        assert_eq!(p.expected_share_interval_ms, 3_000);
    }

    fn sv2(vendor: &str, hw: &str, fw: &str) -> &'static str {
        lookup_ceiling_sv2(&Sv2Device::new(vendor, hw, fw).unwrap())
            .0
            .label
    }

    #[test]
    fn native_sv2_miners_match_on_their_setup_connection() {
        let cases = [
            (
                "Braiins",
                "Antminer S19j Pro",
                "bosminer-plus 23.03",
                "Braiins bosminer",
            ),
            (
                "Braiins",
                "Antminer S21",
                "Braiins OS 24.02",
                "Braiins bosminer",
            ),
            ("Bitmain", "S21", "1.0", "Antminer S21"),
            (
                "Bitmain",
                "Antminer S21 Pro",
                "1.0",
                "Stock Antminer (default)",
            ),
            ("Bitmain", "S19 XP", "", "Antminer S19 XP"),
            ("Bitmain", "Antminer S9", "", "Antminer S9/S11/S17/T17"),
            ("Bitmain", "S95", "", "Stock Antminer (default)"),
            ("ePIC", "S19j Pro", "PowerPlay-BM 1.2", "ePIC PowerPlay-BM"),
            ("Canaan", "A1566", "", "Avalon"),
            ("MicroBT", "M50S", "", "Whatsminer"),
            ("bitaxe", "BM1366", "v2.4.0", "Bitaxe ESP-Miner <= v2.15"),
            (
                "bitaxe",
                "BM1370",
                "v2.16.1",
                "Bitaxe ESP-Miner main / newer / no version",
            ),
            ("NiceHash", "", "", "NiceHash"),
            ("SRI", "", "", "unknown agent"),
            ("", "", "proxy 1.0", "unknown agent"),
        ];
        for (v, h, f, want) in cases {
            assert_eq!(sv2(v, h, f), want, "{v}/{h}/{f}");
        }
        assert_eq!(Sv2Device::new("", " ", ""), None);
    }

    #[test]
    fn an_sv2_identity_seeds_the_sensor_and_its_warning() {
        let id = MinerIdentity::Sv2(Sv2Device::new("Bitmain", "S21", "x").unwrap());
        let s = ClassSensor::for_identity(Some(&id), params(), 0);
        let st = s.status();
        assert_eq!(st.model, "Antminer S21");
        assert_eq!(st.agent.as_deref(), Some("Bitmain/S21/x"));
        assert_eq!(st.warning.unwrap().limited_to_class, 44);
        let agent = MinerIdentity::Agent("Avalon Nano 3s".into());
        assert_eq!(agent.lookup().0.label, "Avalon");
        assert_eq!(agent.display(), "Avalon Nano 3s");
        let none = ClassSensor::for_identity(None, params(), 0);
        assert_eq!(none.rule().label, "unknown agent");
    }
}

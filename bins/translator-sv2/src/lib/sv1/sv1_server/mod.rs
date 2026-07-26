use stratum_apps::stratum_core::sv1_api::{json_rpc, Message};

pub(super) mod channel;
mod difficulty_manager;
pub mod downstream_message_handler;
pub mod sv1_server;

use tracing::warn;

/// Delimiter used to separate original job ID from keepalive mutation counter.
/// Format: `{original_job_id}#{counter}`
const KEEPALIVE_JOB_ID_DELIMITER: char = '#';

/// Check if Sv1 message is mining.authorize
pub(super) fn is_mining_authorize(msg: &Message) -> bool {
    if let json_rpc::Message::StandardRequest(r) = &msg {
        r.method == "mining.authorize"
    } else {
        false
    }
}

/// Check if Sv1 message is mining.configure (BIP310 version-rolling negotiation).
/// Stateless handshake message that needs an immediate response — must NOT be
/// queued behind channel-open or the miner deadlocks waiting for the configure
/// reply before sending subscribe/authorize.
pub(super) fn is_mining_configure(msg: &Message) -> bool {
    if let json_rpc::Message::StandardRequest(r) = &msg {
        r.method == "mining.configure"
    } else {
        false
    }
}

/// Check if Sv1 message is mining.subscribe.
pub(super) fn is_mining_subscribe(msg: &Message) -> bool {
    if let json_rpc::Message::StandardRequest(r) = &msg {
        r.method == "mining.subscribe"
    } else {
        false
    }
}

/// Check if Sv1 message is mining.suggest_difficulty.
///
/// Like `mining.configure`, this must be processed IMMEDIATELY rather than queued behind
/// channel-open: the whole point of the suggestion is to size the channel's initial target,
/// and the channel opens on `mining.authorize`. A queued suggestion would be drained only
/// after the open and would arrive too late to prevent the ramp it exists to avoid.
pub(super) fn is_mining_suggest_difficulty(msg: &Message) -> bool {
    if let json_rpc::Message::StandardRequest(r) = &msg {
        r.method == "mining.suggest_difficulty"
    } else {
        false
    }
}

/// Upper sanity bound on a client-declared hashrate (1 ZH/s — comfortably above the whole
/// Bitcoin network). Guards against a nonsense or hostile suggestion overflowing the
/// hashrate→target conversion. The dangerous direction is a suggestion that is too LOW
/// (a share flood); that is bounded separately by clamping up to the configured
/// `min_individual_miner_hashrate`.
pub(super) const MAX_SUGGESTED_HASHRATE: f64 = 1e21;

/// Hashes per unit of difficulty: `2^48 / 0xFFFF` ≈ 4.295e9.
///
/// This is the exact inverse of the `hash_rate_to_target` maths in `channels_sv2`, which sets
/// `target = (2^256 - h·s) / (h·s + 1)`. Substituting the difficulty-1 target `0xFFFF · 2^208`
/// into `difficulty = target_1 / target` gives `difficulty = h · s · 0xFFFF / 2^48`. It is
/// deliberately NOT the more familiar `2^32` approximation — that is 0.0015% off, which would
/// hand a miner a slightly different difficulty from the one it asked for.
const HASHES_PER_DIFFICULTY: f64 = (1u64 << 48) as f64 / 0xFFFF as f64;

/// Convert an SV1 share difficulty into the equivalent nominal hashrate at a given share
/// cadence.
///
/// A miner producing `shares_per_minute` shares at difficulty `d` is hashing at
/// `d * HASHES_PER_DIFFICULTY * shares_per_minute / 60` H/s. Expressing the suggestion as a
/// hashrate (rather than plumbing a second difficulty unit through the stack) means it flows
/// into the existing `hash_rate_to_target` / vardiff machinery unchanged, and the target the
/// pool derives comes back out as exactly the difficulty the miner asked for.
pub(super) fn difficulty_to_hashrate(difficulty: f64, shares_per_minute: f64) -> f64 {
    difficulty * HASHES_PER_DIFFICULTY * shares_per_minute / 60.0
}

/// Parse a difficulty request out of an SV1 `mining.authorize` password field.
///
/// There is no standard here, only a widely-copied convention: rented-hashrate marketplaces
/// and most large pools accept the difficulty in the password as `d=<number>`, optionally
/// alongside other directives and commonly with a placeholder password in front —
/// `x`, `d=1000000`, `x;d=1000000`, `m=solo,d=65536`. We accept `d=` and `diff=`,
/// case-insensitively, separated by `,`, `;` or whitespace.
///
/// Returns `None` for an absent, malformed, non-finite or non-positive value, in which case
/// the caller keeps the configured default — a miner that fat-fingers its password gets the
/// old behaviour rather than a broken channel.
pub(super) fn parse_password_difficulty(password: &str) -> Option<f64> {
    password
        .split([',', ';', ' ', '\t'])
        .filter_map(|field| {
            let (key, value) = field.split_once('=')?;
            let key = key.trim().to_ascii_lowercase();
            if key != "d" && key != "diff" {
                return None;
            }
            value.trim().parse::<f64>().ok()
        })
        .find(|d| d.is_finite() && *d > 0.0)
}

/// Split a trailing difficulty directive off an SV1 username.
///
/// Returns `(username_without_directive, difficulty)`.
///
/// Needed because some order forms expose only a username field — Braiins' hashrate
/// marketplace has Pool URL and Pool Username and nothing else, so there is no password to put
/// `d=` in, and no way to declare the size of the order being pointed at us. Accepting the same
/// directive as a trailing dot-segment (`<address>.<worker>.d=9300000`) gives those clients a
/// route. Several pools accept this form for the same reason.
///
/// The directive is stripped before the username is used for anything else, so payout-address
/// and worker attribution are unaffected — the pool still sees `<address>.<worker>`.
pub(super) fn split_username_difficulty(name: &str) -> (&str, Option<f64>) {
    let Some((head, last)) = name.rsplit_once('.') else {
        return (name, None);
    };
    match parse_password_difficulty(last) {
        // Only strip when the final segment is *nothing but* the directive; a worker legitimately
        // named e.g. `d=rig` parses to None and is left alone.
        Some(difficulty) => (head, Some(difficulty)),
        None => (name, None),
    }
}

/// Extract the difficulty from a `mining.suggest_difficulty` request.
///
/// The method takes a single numeric parameter. Accepts a JSON number or a numeric string,
/// since miners in the wild send both.
pub(super) fn parse_suggest_difficulty(msg: &Message) -> Option<f64> {
    let json_rpc::Message::StandardRequest(r) = msg else {
        return None;
    };
    let first = r.params.as_array()?.first()?;
    let difficulty = match first {
        serde_json::Value::Number(n) => n.as_f64()?,
        serde_json::Value::String(s) => s.trim().parse::<f64>().ok()?,
        _ => return None,
    };
    (difficulty.is_finite() && difficulty > 0.0).then_some(difficulty)
}

/// Truncates a string to [`MAX_USER_IDENTITY_BYTES`], respecting UTF-8 character boundaries.
///
/// If the input string exceeds the limit, it is truncated at the last valid UTF-8 character
/// boundary before or at [`MAX_USER_IDENTITY_BYTES`] and a warning is logged.
fn tlv_compatible_username(s: &str) -> &str {
    // The SV2 wire type is `Str0255`, so 255 bytes are permitted; this cap is ours. It was 32,
    // which fits a worker name but truncates a full `<address>.<worker>` — a bech32 address is
    // 42 bytes on its own. The TLV now carries the full identity for miners whose channel was
    // opened before `mining.authorize` arrived, so it must fit one.
    const MAX_USER_IDENTITY_BYTES: usize = 255;
    let len = s.len();

    if len <= MAX_USER_IDENTITY_BYTES {
        return s;
    }
    // Find the last valid UTF-8 char boundary at or before MAX_USER_IDENTITY_BYTES
    let mut end = MAX_USER_IDENTITY_BYTES;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let truncated = &s[..end];
    warn!(
        "Username '{}' exceeds {} bytes ({} bytes), truncating to '{}'. \
         Consider using a shorter username for full visibility on the pool dashboard.",
        s, MAX_USER_IDENTITY_BYTES, len, truncated
    );
    truncated
}

#[cfg(test)]
mod difficulty_suggestion_tests {
    use super::*;

    fn suggest(params: serde_json::Value) -> Message {
        json_rpc::Message::StandardRequest(json_rpc::StandardRequest {
            id: 1,
            method: "mining.suggest_difficulty".to_string(),
            params,
        })
    }

    #[test]
    fn password_difficulty_accepts_the_conventional_forms() {
        // Bare directive, and the common "placeholder password then directive" shapes.
        assert_eq!(parse_password_difficulty("d=1000000"), Some(1_000_000.0));
        assert_eq!(parse_password_difficulty("x;d=1000000"), Some(1_000_000.0));
        assert_eq!(parse_password_difficulty("m=solo,d=65536"), Some(65536.0));
        assert_eq!(parse_password_difficulty("x d=512"), Some(512.0));
        // Case-insensitive key, and the `diff=` spelling.
        assert_eq!(parse_password_difficulty("D=42"), Some(42.0));
        assert_eq!(parse_password_difficulty("diff=8.5"), Some(8.5));
    }

    #[test]
    fn password_difficulty_rejects_junk_so_the_default_stands() {
        // A miner that fat-fingers its password must get the configured default, not a
        // broken channel.
        for password in [
            "", "x", "d=", "d=abc", "d=-5", "d=0", "d=NaN", "dd=100", "password",
        ] {
            assert_eq!(
                parse_password_difficulty(password),
                None,
                "expected {password:?} to yield no difficulty"
            );
        }
    }

    #[test]
    fn suggest_difficulty_accepts_numbers_and_numeric_strings() {
        // Miners in the wild send both.
        assert_eq!(
            parse_suggest_difficulty(&suggest(serde_json::json!([1_000_000]))),
            Some(1_000_000.0)
        );
        assert_eq!(
            parse_suggest_difficulty(&suggest(serde_json::json!(["65536"]))),
            Some(65536.0)
        );
        assert_eq!(
            parse_suggest_difficulty(&suggest(serde_json::json!([8.25]))),
            Some(8.25)
        );
    }

    #[test]
    fn suggest_difficulty_rejects_malformed_requests() {
        for params in [
            serde_json::json!([]),
            serde_json::json!([0]),
            serde_json::json!([-1]),
            serde_json::json!(["abc"]),
            serde_json::json!([null]),
            serde_json::json!({"d": 1}),
        ] {
            assert_eq!(
                parse_suggest_difficulty(&suggest(params.clone())),
                None,
                "expected {params:?} to yield no difficulty"
            );
        }
    }

    #[test]
    fn difficulty_and_hashrate_round_trip() {
        // The floor this pool ships (500 GH/s at 6 shares/min) is what produced the
        // difficulty 1164 that rented-hashrate orders trip over; the conversion must
        // reproduce it, so a miner asking for difficulty D is targeted at exactly D.
        // Tolerance is relative and tight enough to fail against the common `2^32`
        // approximation (which is 1.5e-5 out); the residual here is ~4e-9, from the
        // truncated decimal in the difficulty literal rather than the conversion.
        let hashrate = difficulty_to_hashrate(1164.1354499328882, 6.0);
        let relative_error = (hashrate - 500_000_000_000.0).abs() / 500_000_000_000.0;
        assert!(
            relative_error < 1e-6,
            "expected 500 GH/s, got {hashrate} (relative error {relative_error:e})"
        );
        // And a 4 PH/s rental should ask for a difficulty in the millions, not the thousands —
        // ~8000x the floor, which is why vardiff's capped ramp cannot get there quickly.
        let four_ph = difficulty_to_hashrate(9_313_082.0, 6.0);
        assert!(
            (3.9e15..4.1e15).contains(&four_ph),
            "expected ~4 PH/s, got {four_ph}"
        );
    }
}

#[cfg(test)]
mod username_difficulty_tests {
    use super::*;

    const ADDR: &str = "bc1q7zvdh3uza6u52uemd3c60g0h0eu9g9yvm2y492";

    #[test]
    fn strips_a_trailing_difficulty_directive() {
        let username = format!("{ADDR}.braiins.d=9300000");
        let (name, difficulty) = split_username_difficulty(&username);
        assert_eq!(name, format!("{ADDR}.braiins"));
        assert_eq!(difficulty, Some(9_300_000.0));
    }

    #[test]
    fn leaves_ordinary_usernames_untouched() {
        // Attribution must survive: the pool derives payout address and worker from this.
        for username in [
            format!("{ADDR}.braiins"),
            format!("{ADDR}.bitaxe1"),
            ADDR.to_string(),
            // A worker legitimately containing an `=` but not a difficulty directive.
            format!("{ADDR}.d=rig"),
            format!("{ADDR}.diff=abc"),
        ] {
            let (name, difficulty) = split_username_difficulty(&username);
            assert_eq!(
                name, username,
                "username {username:?} must not be rewritten"
            );
            assert_eq!(
                difficulty, None,
                "username {username:?} must not yield a difficulty"
            );
        }
    }

    #[test]
    fn a_stripped_username_still_has_its_worker_separator() {
        // The bare-worker rejection runs on the stripped name, so stripping must not turn a
        // valid `<address>.<worker>` into a bare address and get the miner rejected.
        let username = format!("{ADDR}.braiins.d=9300000");
        let (name, _) = split_username_difficulty(&username);
        assert!(name.contains('.'));
        // The full `<address>.<worker>` must survive intact — it is now what the TLV
        // carries, so losing either half misattributes the share.
        assert_eq!(name, format!("{ADDR}.braiins"));
    }
}

#[cfg(test)]
mod worker_tlv_length_tests {
    use stratum_apps::stratum_core::{extensions_sv2::UserIdentity, parsers_sv2::TlvField};

    /// A full `<address>.<worker>` must survive TLV encode AND decode.
    ///
    /// Lives here rather than in `parsers-sv2` because that crate is not a workspace member,
    /// so tests written there never run.
    ///
    /// Regression guard for a two-layer bug: `MAX_USER_IDENTITY_LENGTH` was declared
    /// independently in BOTH `extensions_sv2` (gating `UserIdentity::new`) and
    /// `parsers_sv2::tlv_extensions` (gating `to_tlv`/`from_tlv`). Raising only the first left
    /// encoding still rejecting at 32 bytes; the caller discarded that error with `.ok()`, so
    /// the share went upstream with NO identity TLV and the pool credited it to the channel's
    /// provisional identity — i.e. the operator's address instead of the miner's. Verified
    /// end-to-end on an isolated node: before, a share from `<addr>.attrtest` landed on
    /// `<config-addr>.miner2`; after, it lands on `<addr>.attrtest`.
    #[test]
    fn full_address_and_worker_round_trips_through_tlv() {
        for identity in [
            "bc1q7zvdh3uza6u52uemd3c60g0h0eu9g9yvm2y492.attrtest",
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr.worker1",
        ] {
            assert!(identity.len() > 32, "must exceed the old 32-byte cap");
            let ui = UserIdentity::new(identity).expect("construct");
            let tlv = ui
                .to_tlv()
                .unwrap_or_else(|e| panic!("encode rejected {identity:?}: {e:?}"));
            let decoded = UserIdentity::from_tlv(&tlv).expect("decode");
            assert_eq!(decoded.as_str().unwrap(), identity);
        }
    }
}

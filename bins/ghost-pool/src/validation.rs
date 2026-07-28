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
//| FILE: validation.rs                                                                                                  |
//|======================================================================================================================|

//! Input validation layer for Stratum server
//!
//! All external input MUST pass through this module before processing.
//! This provides defense-in-depth against injection attacks, buffer overflows,
//! and malformed data from untrusted miners.

use std::ops::RangeInclusive;
use thiserror::Error;

/// Maximum lengths for all string inputs
pub const MAX_USERNAME_LEN: usize = 128;
pub const MAX_WORKER_NAME_LEN: usize = 32;
pub const MAX_PASSWORD_LEN: usize = 128;
pub const MAX_METHOD_LEN: usize = 32;
pub const MAX_JOB_ID_LEN: usize = 32;
pub const MAX_EXTRANONCE2_LEN: usize = 32; // 16 bytes hex max
pub const MAX_NTIME_LEN: usize = 8; // 4 bytes hex
pub const MAX_NONCE_LEN: usize = 8; // 4 bytes hex
pub const MAX_USER_AGENT_LEN: usize = 256;

/// Validation errors
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Field '{0}' exceeds maximum length of {1} characters")]
    TooLong(&'static str, usize),

    #[error("Field '{0}' is below minimum length of {1} characters")]
    TooShort(&'static str, usize),

    #[error("Field '{0}' must be between {1} and {2} characters")]
    InvalidLength(&'static str, usize, usize),

    #[error("Field '{0}' contains non-ASCII characters")]
    NonAscii(&'static str),

    #[error("Field '{0}' contains control characters")]
    ControlChars(&'static str),

    #[error("Field '{0}' contains invalid characters")]
    InvalidChars(&'static str),

    #[error("Field '{0}' must be valid hexadecimal")]
    InvalidHex(&'static str),

    #[error("Field '{0}' is empty")]
    Empty(&'static str),

    #[error("Field '{0}' contains path traversal characters")]
    PathTraversal(&'static str),

    #[error("Field '{0}' contains null bytes")]
    NullByte(&'static str),
}

/// Validate a string is ASCII-only with no control characters
fn validate_ascii_printable(s: &str, field: &'static str) -> Result<(), ValidationError> {
    // Check for null bytes (could truncate strings in C code)
    if s.contains('\0') {
        return Err(ValidationError::NullByte(field));
    }

    // Must be ASCII
    if !s.is_ascii() {
        return Err(ValidationError::NonAscii(field));
    }

    // No control characters except possibly tab/newline in some contexts
    if s.chars().any(|c| c.is_ascii_control()) {
        return Err(ValidationError::ControlChars(field));
    }

    Ok(())
}

/// Validate a hex string
fn validate_hex(
    s: &str,
    field: &'static str,
    len_range: RangeInclusive<usize>,
) -> Result<(), ValidationError> {
    if s.is_empty() {
        return Err(ValidationError::Empty(field));
    }

    if s.len() < *len_range.start() {
        return Err(ValidationError::TooShort(field, *len_range.start()));
    }

    if s.len() > *len_range.end() {
        return Err(ValidationError::TooLong(field, *len_range.end()));
    }

    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ValidationError::InvalidHex(field));
    }

    Ok(())
}

/// Validate and sanitize miner username before any processing
///
/// Usernames are in the format `address.worker` or just `address`.
/// This validates the raw string before parsing.
pub fn validate_username(username: &str) -> Result<&str, ValidationError> {
    // Empty check
    if username.is_empty() {
        return Err(ValidationError::Empty("username"));
    }

    // Length check
    if username.len() > MAX_USERNAME_LEN {
        return Err(ValidationError::TooLong("username", MAX_USERNAME_LEN));
    }

    // ASCII printable only
    validate_ascii_printable(username, "username")?;

    // No path traversal attempts (security)
    if username.contains("..") || username.contains('/') || username.contains('\\') {
        return Err(ValidationError::PathTraversal("username"));
    }

    // No shell metacharacters
    const SHELL_CHARS: &[char] = &[
        '`', '$', '|', ';', '&', '>', '<', '!', '{', '}', '[', ']', '(', ')',
    ];
    if username.chars().any(|c| SHELL_CHARS.contains(&c)) {
        return Err(ValidationError::InvalidChars("username"));
    }

    Ok(username)
}

/// Validate password (minimal validation - passwords can be complex)
pub fn validate_password(password: &str) -> Result<&str, ValidationError> {
    if password.len() > MAX_PASSWORD_LEN {
        return Err(ValidationError::TooLong("password", MAX_PASSWORD_LEN));
    }

    // No null bytes
    if password.contains('\0') {
        return Err(ValidationError::NullByte("password"));
    }

    // Must be valid UTF-8 (already guaranteed by &str) but check ASCII for safety
    if !password.is_ascii() {
        return Err(ValidationError::NonAscii("password"));
    }

    Ok(password)
}

/// Validate worker name (extracted from username)
pub fn validate_worker_name(worker: &str) -> Result<&str, ValidationError> {
    if worker.is_empty() {
        // Empty is OK - will default to "default"
        return Ok(worker);
    }

    if worker.len() > MAX_WORKER_NAME_LEN {
        return Err(ValidationError::TooLong("worker_name", MAX_WORKER_NAME_LEN));
    }

    validate_ascii_printable(worker, "worker_name")?;

    // Worker names should be alphanumeric with limited punctuation
    if !worker
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(ValidationError::InvalidChars("worker_name"));
    }

    Ok(worker)
}

/// Validate user agent string
pub fn validate_user_agent(agent: &str) -> Result<&str, ValidationError> {
    if agent.len() > MAX_USER_AGENT_LEN {
        return Err(ValidationError::TooLong("user_agent", MAX_USER_AGENT_LEN));
    }

    // Allow empty user agent
    if agent.is_empty() {
        return Ok(agent);
    }

    validate_ascii_printable(agent, "user_agent")?;

    Ok(agent)
}

/// Validate share submission parameters
pub fn validate_share_params(
    job_id: &str,
    extranonce2: &str,
    ntime: &str,
    nonce: &str,
) -> Result<(), ValidationError> {
    // Job ID: variable length hex
    validate_hex(job_id, "job_id", 1..=MAX_JOB_ID_LEN)?;

    // Extranonce2: variable length hex (depends on extranonce2_size from subscribe)
    validate_hex(extranonce2, "extranonce2", 1..=MAX_EXTRANONCE2_LEN)?;

    // ntime: exactly 8 hex chars (4 bytes)
    validate_hex(ntime, "ntime", 8..=8)?;

    // nonce: exactly 8 hex chars (4 bytes)
    validate_hex(nonce, "nonce", 8..=8)?;

    Ok(())
}

/// Validate job ID
pub fn validate_job_id(job_id: &str) -> Result<&str, ValidationError> {
    validate_hex(job_id, "job_id", 1..=MAX_JOB_ID_LEN)?;
    Ok(job_id)
}

/// Validated share parameters (zero-copy where possible)
#[derive(Debug)]
pub struct ValidatedShareParams<'a> {
    pub job_id: &'a str,
    pub extranonce2: &'a str,
    pub ntime: u32,
    pub nonce: u32,
}

impl<'a> ValidatedShareParams<'a> {
    /// Parse and validate share parameters
    pub fn parse(
        job_id: &'a str,
        extranonce2: &'a str,
        ntime_hex: &str,
        nonce_hex: &str,
    ) -> Result<Self, ValidationError> {
        // Validate all fields first
        validate_share_params(job_id, extranonce2, ntime_hex, nonce_hex)?;

        // Parse ntime (already validated as 8 hex chars)
        let ntime =
            u32::from_str_radix(ntime_hex, 16).map_err(|_| ValidationError::InvalidHex("ntime"))?;

        // Parse nonce (already validated as 8 hex chars)
        let nonce =
            u32::from_str_radix(nonce_hex, 16).map_err(|_| ValidationError::InvalidHex("nonce"))?;

        Ok(Self {
            job_id,
            extranonce2,
            ntime,
            nonce,
        })
    }
}

/// Validated miner credentials
#[derive(Debug)]
pub struct ValidatedCredentials {
    pub address: String,
    pub worker_name: String,
}

impl ValidatedCredentials {
    /// Parse and validate miner username into address and worker
    pub fn parse(username: &str, password: &str) -> Result<Self, ValidationError> {
        // Validate raw inputs
        let username = validate_username(username)?;
        let _password = validate_password(password)?;

        // Parse username into address.worker
        // FIRST dot, matching parse_user_identity and pool_sv2's PayoutMode (#481).
        let (address, worker) = if let Some(dot_pos) = username.find('.') {
            let addr = &username[..dot_pos];
            let worker = &username[dot_pos + 1..];
            (addr, worker)
        } else {
            (username, "")
        };

        // Validate worker name
        validate_worker_name(worker)?;

        // Worker defaults to "default" if empty
        let worker_name = if worker.is_empty() {
            "default".to_string()
        } else {
            worker.to_string()
        };

        Ok(Self {
            address: address.to_string(),
            worker_name,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_username_valid() {
        assert!(validate_username("bc1qxyz123.rig1").is_ok());
        assert!(validate_username("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2").is_ok());
        assert!(validate_username("address.worker_name-1").is_ok());
    }

    #[test]
    fn test_validate_username_invalid() {
        // Too long
        let long = "a".repeat(MAX_USERNAME_LEN + 1);
        assert!(matches!(
            validate_username(&long),
            Err(ValidationError::TooLong(..))
        ));

        // Path traversal
        assert!(matches!(
            validate_username("../etc/passwd"),
            Err(ValidationError::PathTraversal(..))
        ));
        assert!(matches!(
            validate_username("foo/bar"),
            Err(ValidationError::PathTraversal(..))
        ));

        // Shell metacharacters
        assert!(matches!(
            validate_username("foo`whoami`"),
            Err(ValidationError::InvalidChars(..))
        ));
        assert!(matches!(
            validate_username("foo;rm -rf"),
            Err(ValidationError::InvalidChars(..))
        ));
        // Note: $(cat /etc/passwd) contains '/' which triggers PathTraversal first
        assert!(matches!(
            validate_username("$(cat /etc/passwd)"),
            Err(ValidationError::PathTraversal(..))
        ));
        // Test shell chars without path chars
        assert!(matches!(
            validate_username("$HOME"),
            Err(ValidationError::InvalidChars(..))
        ));
        assert!(matches!(
            validate_username("foo|bar"),
            Err(ValidationError::InvalidChars(..))
        ));

        // Empty
        assert!(matches!(
            validate_username(""),
            Err(ValidationError::Empty(..))
        ));

        // Control characters
        assert!(matches!(
            validate_username("foo\x00bar"),
            Err(ValidationError::NullByte(..))
        ));
        assert!(matches!(
            validate_username("foo\nbar"),
            Err(ValidationError::ControlChars(..))
        ));
    }

    #[test]
    fn test_validate_share_params_valid() {
        assert!(validate_share_params("1a2b3c", "00000000", "12345678", "abcdef00").is_ok());
    }

    #[test]
    fn test_validate_share_params_invalid() {
        // Invalid ntime (wrong length)
        assert!(validate_share_params("1a", "00", "1234567", "abcdef00").is_err());

        // Invalid nonce (not hex)
        assert!(validate_share_params("1a", "00", "12345678", "ghijklmn").is_err());
    }

    #[test]
    fn test_validated_credentials() {
        let creds = ValidatedCredentials::parse("bc1qxyz.rig1", "x").unwrap();
        assert_eq!(creds.address, "bc1qxyz");
        assert_eq!(creds.worker_name, "rig1");

        let creds = ValidatedCredentials::parse("bc1qxyz", "x").unwrap();
        assert_eq!(creds.address, "bc1qxyz");
        assert_eq!(creds.worker_name, "default");
    }

    #[test]
    fn test_validated_share_params() {
        let params =
            ValidatedShareParams::parse("abc123", "00000001", "65432100", "deadbeef").unwrap();
        assert_eq!(params.job_id, "abc123");
        assert_eq!(params.ntime, 0x65432100);
        assert_eq!(params.nonce, 0xdeadbeef);
    }
}

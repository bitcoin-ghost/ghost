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
//| FILE: rpc.rs                                                                                                         |
//|======================================================================================================================|

//! Safe JSON-RPC parsing for Stratum protocol
//!
//! Provides hardened JSON-RPC parsing with:
//! - Size limits to prevent DoS
//! - Depth limits to prevent stack overflow
//! - Method whitelisting to reduce attack surface
//! - Strict parameter validation

use serde_json::Value;
use thiserror::Error;
use tracing::warn;

/// Maximum size of a JSON-RPC message
pub const MAX_MESSAGE_SIZE: usize = 4096;

/// Maximum nesting depth in JSON
pub const MAX_JSON_DEPTH: usize = 4;

/// Maximum number of parameters in a method call
pub const MAX_PARAMS: usize = 10;

/// Maximum string length in parameters
pub const MAX_PARAM_STRING_LEN: usize = 256;

/// JSON-RPC parsing errors
#[derive(Debug, Error)]
pub enum RpcError {
    #[error("Message too large: {0} bytes (max {MAX_MESSAGE_SIZE})")]
    MessageTooLarge(usize),

    #[error("Invalid JSON: {0}")]
    InvalidJson(String),

    #[error("JSON nesting too deep (max {MAX_JSON_DEPTH} levels)")]
    TooDeep,

    #[error("Missing required field: {0}")]
    MissingField(&'static str),

    #[error("Unknown method: {0}")]
    UnknownMethod(String),

    #[error("Invalid parameter type for {0}: expected {1}")]
    InvalidParamType(&'static str, &'static str),

    #[error("Too many parameters: {0} (max {MAX_PARAMS})")]
    TooManyParams(usize),

    #[error("Parameter string too long: {0}")]
    ParamTooLong(&'static str),

    #[error("Invalid parameter value: {0}")]
    InvalidParamValue(String),
}

/// Allowed Stratum methods (whitelist)
pub const ALLOWED_METHODS: &[&str] = &[
    "mining.subscribe",
    "mining.authorize",
    "mining.submit",
    "mining.extranonce.subscribe",
    "mining.get_transactions", // Optional
    "mining.configure",        // Stratum V2 extension
];

/// Parsed JSON-RPC request
#[derive(Debug, Clone)]
pub struct RpcRequest {
    /// Request ID (can be any JSON value)
    pub id: Option<Value>,
    /// Method name (validated against whitelist)
    pub method: String,
    /// Parameters (validated)
    pub params: Vec<Value>,
}

impl RpcRequest {
    /// Create a JSON-RPC response
    pub fn response(&self, result: Value) -> String {
        let id = self.id.clone().unwrap_or(Value::Null);
        serde_json::json!({
            "id": id,
            "result": result,
            "error": null
        })
        .to_string()
    }

    /// Create a JSON-RPC error response
    pub fn error_response(&self, code: i32, message: &str) -> String {
        let id = self.id.clone().unwrap_or(Value::Null);
        serde_json::json!({
            "id": id,
            "result": null,
            "error": [code, message, null]
        })
        .to_string()
    }
}

/// Calculate the depth of a JSON value
fn json_depth(value: &Value) -> usize {
    match value {
        Value::Array(arr) => 1 + arr.iter().map(json_depth).max().unwrap_or(0),
        Value::Object(obj) => 1 + obj.values().map(json_depth).max().unwrap_or(0),
        _ => 0,
    }
}

/// Validate a JSON value doesn't contain excessively long strings
/// M-16: Uses InvalidParamValue with owned String instead of Box::leak to prevent memory leaks
fn validate_string_lengths(value: &Value, path: &str) -> Result<(), RpcError> {
    match value {
        Value::String(s) if s.len() > MAX_PARAM_STRING_LEN => {
            // M-16: Return InvalidParamValue with an owned String instead of leaking memory
            Err(RpcError::InvalidParamValue(format!(
                "M-16: parameter at '{}' exceeds maximum string length ({})",
                path, MAX_PARAM_STRING_LEN
            )))
        }
        Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                validate_string_lengths(v, &format!("{}[{}]", path, i))?;
            }
            Ok(())
        }
        Value::Object(obj) => {
            for (k, v) in obj.iter() {
                validate_string_lengths(v, &format!("{}.{}", path, k))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Parse a JSON-RPC request with security hardening
pub fn parse_request(line: &str) -> Result<RpcRequest, RpcError> {
    // 1. Size limit BEFORE parsing
    if line.len() > MAX_MESSAGE_SIZE {
        warn!(size = line.len(), "Rejected oversized JSON-RPC message");
        return Err(RpcError::MessageTooLarge(line.len()));
    }

    // 2. Parse JSON
    let value: Value =
        serde_json::from_str(line).map_err(|e| RpcError::InvalidJson(e.to_string()))?;

    // 3. Depth check
    let depth = json_depth(&value);
    if depth > MAX_JSON_DEPTH {
        warn!(depth = depth, "Rejected deeply nested JSON-RPC message");
        return Err(RpcError::TooDeep);
    }

    // 4. Extract ID (optional, can be any type)
    let id = value.get("id").cloned();

    // 5. Extract and validate method
    let method = value
        .get("method")
        .and_then(|m| m.as_str())
        .ok_or(RpcError::MissingField("method"))?;

    // 6. Whitelist check
    if !ALLOWED_METHODS.contains(&method) {
        warn!(method = method, "Rejected unknown JSON-RPC method");
        return Err(RpcError::UnknownMethod(method.to_string()));
    }

    // 7. Extract and validate params
    let params = match value.get("params") {
        Some(Value::Array(arr)) => {
            if arr.len() > MAX_PARAMS {
                return Err(RpcError::TooManyParams(arr.len()));
            }
            arr.clone()
        }
        Some(Value::Null) | None => Vec::new(),
        Some(_) => return Err(RpcError::InvalidParamType("params", "array")),
    };

    // 8. Validate string lengths in params
    for (i, param) in params.iter().enumerate() {
        validate_string_lengths(param, &format!("params[{}]", i))?;
    }

    Ok(RpcRequest {
        id,
        method: method.to_string(),
        params,
    })
}

/// Stratum error codes
pub mod error_codes {
    /// Unknown error
    pub const UNKNOWN: i32 = 20;
    /// Job not found (stale)
    pub const JOB_NOT_FOUND: i32 = 21;
    /// Duplicate share
    pub const DUPLICATE_SHARE: i32 = 22;
    /// Low difficulty share
    pub const LOW_DIFFICULTY: i32 = 23;
    /// Unauthorized worker
    pub const UNAUTHORIZED: i32 = 24;
    /// Not subscribed
    pub const NOT_SUBSCRIBED: i32 = 25;
    /// Invalid parameters
    pub const INVALID_PARAMS: i32 = 26;
    /// Rate limited
    pub const RATE_LIMITED: i32 = 27;
}

/// Create a standard Stratum notification (no id)
pub fn notification(method: &str, params: Value) -> String {
    serde_json::json!({
        "id": null,
        "method": method,
        "params": params
    })
    .to_string()
}

/// Create mining.set_difficulty notification
pub fn set_difficulty(difficulty: f64) -> String {
    notification("mining.set_difficulty", serde_json::json!([difficulty]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_request() {
        let json = r#"{"id": 1, "method": "mining.subscribe", "params": []}"#;
        let req = parse_request(json).unwrap();
        assert_eq!(req.method, "mining.subscribe");
        assert!(req.params.is_empty());
    }

    #[test]
    fn test_parse_with_params() {
        let json = r#"{"id": 2, "method": "mining.authorize", "params": ["user.worker", "pass"]}"#;
        let req = parse_request(json).unwrap();
        assert_eq!(req.method, "mining.authorize");
        assert_eq!(req.params.len(), 2);
    }

    #[test]
    fn test_reject_oversized() {
        let json = format!(
            r#"{{"id": 1, "method": "mining.subscribe", "params": ["{}"]}}"#,
            "x".repeat(5000)
        );
        let result = parse_request(&json);
        assert!(matches!(result, Err(RpcError::MessageTooLarge(_))));
    }

    #[test]
    fn test_reject_unknown_method() {
        let json = r#"{"id": 1, "method": "evil.method", "params": []}"#;
        let result = parse_request(json);
        assert!(matches!(result, Err(RpcError::UnknownMethod(_))));
    }

    #[test]
    fn test_reject_deep_nesting() {
        // Create deeply nested JSON
        let json = r#"{"id": 1, "method": "mining.subscribe", "params": [[[[[[]]]]]]}"#;
        let result = parse_request(json);
        assert!(matches!(result, Err(RpcError::TooDeep)));
    }

    #[test]
    fn test_reject_too_many_params() {
        let params: Vec<i32> = (0..20).collect();
        let json = format!(
            r#"{{"id": 1, "method": "mining.subscribe", "params": {:?}}}"#,
            params
        );
        let result = parse_request(&json);
        assert!(matches!(result, Err(RpcError::TooManyParams(_))));
    }

    #[test]
    fn test_json_depth() {
        assert_eq!(json_depth(&serde_json::json!(1)), 0);
        assert_eq!(json_depth(&serde_json::json!([1])), 1);
        assert_eq!(json_depth(&serde_json::json!([[1]])), 2);
        assert_eq!(json_depth(&serde_json::json!({"a": {"b": 1}})), 2);
    }

    #[test]
    fn test_response_creation() {
        let req = RpcRequest {
            id: Some(Value::from(1)),
            method: "mining.subscribe".to_string(),
            params: vec![],
        };

        let resp = req.response(Value::Bool(true));
        assert!(resp.contains("\"result\":true"));
        assert!(resp.contains("\"error\":null"));
    }

    #[test]
    fn test_error_response() {
        let req = RpcRequest {
            id: Some(Value::from(1)),
            method: "mining.submit".to_string(),
            params: vec![],
        };

        let resp = req.error_response(error_codes::DUPLICATE_SHARE, "Duplicate share");
        assert!(resp.contains("\"error\""));
        assert!(resp.contains("Duplicate share"));
    }
}

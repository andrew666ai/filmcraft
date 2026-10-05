//! Loopback control authentication and transport budgets.
//!
//! Personal/local use: a 256-bit bearer token gates TCP method dispatch. There is no
//! capability model and no audit log. Stdio MCP does not use this token.

use std::fs::OpenOptions;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};

use crate::AutomationError;

/// The first request on every TCP connection must use this method.
pub const AUTH_METHOD: &str = "auth";
/// Maximum encoded JSON request line, including its newline.
pub const MAX_REQUEST_BYTES: usize = 1 << 20;
/// Maximum encoded JSON reply, including its newline.
pub const MAX_RESPONSE_BYTES: usize = 8 << 20;
/// Maximum simultaneously serviced TCP connections per listener.
pub const MAX_CONNECTIONS: usize = 16;
/// Idle/read and write timeout for loopback TCP connections.
pub const IO_TIMEOUT: Duration = Duration::from_secs(30);

const TOKEN_BYTES: usize = 32;
const TOKEN_HEX_LEN: usize = TOKEN_BYTES * 2;

/// Result of reading one bounded JSON-lines frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineRead {
    Eof,
    Line,
    TooLong,
}

/// Read one line without buffering more than [`MAX_REQUEST_BYTES`] plus one byte.
pub fn read_bounded_line(reader: &mut impl BufRead, line: &mut String) -> std::io::Result<LineRead> {
    line.clear();
    let mut limited = std::io::Read::take(reader, (MAX_REQUEST_BYTES + 1) as u64);
    let n = limited.read_line(line)?;
    if n == 0 {
        Ok(LineRead::Eof)
    } else if n > MAX_REQUEST_BYTES {
        Ok(LineRead::TooLong)
    } else {
        Ok(LineRead::Line)
    }
}

/// Generate a 256-bit bearer token with the operating system CSPRNG.
pub fn generate_token() -> Result<String, AutomationError> {
    let mut bytes = [0u8; TOKEN_BYTES];
    getrandom::fill(&mut bytes).map_err(|e| AutomationError::Other(format!("cannot generate control token: {e}")))?;
    let mut token = String::with_capacity(TOKEN_HEX_LEN);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        let hi = usize::from(byte >> 4);
        let lo = usize::from(byte & 0x0f);
        let Some(hi) = HEX.get(hi).copied() else {
            return Err(AutomationError::Other("cannot encode control token".into()));
        };
        let Some(lo) = HEX.get(lo).copied() else {
            return Err(AutomationError::Other("cannot encode control token".into()));
        };
        token.push(hi as char);
        token.push(lo as char);
    }
    Ok(token)
}

/// Accept only the fixed-width hexadecimal representation emitted by [`generate_token`].
pub fn validate_token(token: &str) -> Result<(), AutomationError> {
    if token.len() != TOKEN_HEX_LEN || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AutomationError::BadRequest("control token must contain exactly 64 hexadecimal characters".into()));
    }
    Ok(())
}

/// Compare fixed-width tokens without leaving early on a mismatching byte.
pub fn token_matches(expected: &str, supplied: &str) -> bool {
    if expected.len() != TOKEN_HEX_LEN || supplied.len() != TOKEN_HEX_LEN {
        return false;
    }
    let mut different = 0u8;
    for (a, b) in expected.bytes().zip(supplied.bytes()) {
        different |= a.to_ascii_lowercase() ^ b.to_ascii_lowercase();
    }
    different == 0
}

/// Validate the first TCP frame. No control method is represented in the reply.
pub fn authentication_reply(line: &str, expected_token: &str) -> (Value, bool) {
    let req: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return (json!({"id": null, "ok": false, "error": "authentication required"}), false),
    };
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let supplied = req.get("params").and_then(|p| p.get("token")).and_then(Value::as_str).unwrap_or("");
    let ok = req.get("method").and_then(Value::as_str) == Some(AUTH_METHOD) && token_matches(expected_token, supplied);
    if ok {
        (json!({"id": id, "ok": true, "result": {"authenticated": true}}), true)
    } else {
        (json!({"id": id, "ok": false, "error": "authentication required"}), false)
    }
}

fn read_token_file(path: &Path) -> Result<String, AutomationError> {
    let file = std::fs::File::open(path).map_err(|e| AutomationError::Other(format!("{}: {e}", path.display())))?;
    // 64 hex digits plus a trailing CRLF. Anything longer cannot be a valid token file.
    let mut limited = Read::take(file, (TOKEN_HEX_LEN + 2) as u64);
    let mut token = String::new();
    limited.read_to_string(&mut token).map_err(|e| AutomationError::Other(format!("{}: {e}", path.display())))?;
    let token = token.trim().to_owned();
    validate_token(&token)?;
    Ok(token)
}

fn create_token_file(path: &Path, token: &str) -> Result<(), AutomationError> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| AutomationError::Other(format!("{}: {e}", parent.display())))?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| AutomationError::Other(format!("{}: {e}", path.display())))?;
    writeln!(file, "{token}").map_err(|e| AutomationError::Other(format!("{}: {e}", path.display())))
}

/// Resolve a server token. With no supplied token or file, a fresh token is returned.
/// A missing token file is created; an existing one is read and validated.
pub fn server_token(supplied: Option<&str>, token_file: Option<&Path>) -> Result<String, AutomationError> {
    if supplied.is_some() && token_file.is_some() {
        return Err(AutomationError::BadRequest("use either a control token or a control token file, not both".into()));
    }
    if let Some(token) = supplied {
        validate_token(token)?;
        return Ok(token.to_ascii_lowercase());
    }
    let token = generate_token()?;
    let Some(path) = token_file else {
        return Ok(token);
    };
    match read_token_file(path) {
        Ok(existing) => Ok(existing.to_ascii_lowercase()),
        Err(AutomationError::Other(_)) if !path.exists() => match create_token_file(path, &token) {
            Ok(()) => Ok(token),
            Err(AutomationError::Other(_)) if path.exists() => read_token_file(path).map(|v| v.to_ascii_lowercase()),
            Err(e) => Err(e),
        },
        Err(e) => Err(e),
    }
}

/// Resolve the token used by a client. Clients never silently generate credentials.
pub fn client_token(supplied: Option<&str>, token_file: Option<&Path>) -> Result<String, AutomationError> {
    if supplied.is_some() && token_file.is_some() {
        return Err(AutomationError::BadRequest("use either a control token or a control token file, not both".into()));
    }
    if let Some(token) = supplied {
        validate_token(token)?;
        return Ok(token.to_ascii_lowercase());
    }
    token_file.map_or_else(
        || {
            Err(AutomationError::BadRequest(
                "bridge mode needs --control-token, --control-token-file, FILMCRAFT_CONTROL_TOKEN, or FILMCRAFT_CONTROL_TOKEN_FILE".into(),
            ))
        },
        |path| read_token_file(path).map(|v| v.to_ascii_lowercase()),
    )
}

/// Counts active connections and returns a permit only while below the configured maximum.
pub struct ConnectionLimiter {
    active: AtomicUsize,
    max: usize,
}

impl ConnectionLimiter {
    pub fn new(max: usize) -> Arc<Self> {
        Arc::new(Self { active: AtomicUsize::new(0), max })
    }

    pub fn try_acquire(self: &Arc<Self>) -> Option<ConnectionPermit> {
        let mut current = self.active.load(Ordering::Acquire);
        loop {
            if current >= self.max {
                return None;
            }
            let next = current.checked_add(1)?;
            match self.active.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Some(ConnectionPermit { limiter: Arc::clone(self) }),
                Err(actual) => current = actual,
            }
        }
    }
}

pub struct ConnectionPermit {
    limiter: Arc<ConnectionLimiter>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.limiter.active.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Apply idle and write timeouts before handing a socket to a connection worker.
pub fn configure_stream(stream: &std::net::TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))
}

/// CLI flags, filled in from the environment when a flag was not passed.
pub fn token_inputs(supplied: Option<String>, token_file: Option<PathBuf>) -> (Option<String>, Option<PathBuf>) {
    let supplied = supplied.or_else(|| std::env::var("FILMCRAFT_CONTROL_TOKEN").ok());
    let token_file = token_file.or_else(|| std::env::var_os("FILMCRAFT_CONTROL_TOKEN_FILE").map(PathBuf::from));
    (supplied, token_file)
}

struct LimitedWriter {
    bytes: Vec<u8>,
    maximum: usize,
}

impl Write for LimitedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let room = self.maximum.saturating_sub(self.bytes.len());
        if buf.len() > room {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("response exceeds {} bytes", self.maximum)));
        }
        self.bytes.try_reserve(buf.len()).map_err(|error| std::io::Error::other(format!("response allocation failed: {error}")))?;
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn encode_with_limit(value: &impl Serialize, maximum: usize) -> Result<Vec<u8>, ()> {
    let mut writer = LimitedWriter { bytes: Vec::new(), maximum };
    serde_json::to_writer(&mut writer, value).map_err(|_| ())?;
    Ok(writer.bytes)
}

/// Encode one JSON-lines reply. An oversized payload becomes a short error that keeps `id`.
/// The operation may already have completed.
pub fn write_reply(out: &mut impl Write, reply: &Value) -> std::io::Result<()> {
    let encoded = match encode_with_limit(reply, MAX_RESPONSE_BYTES.saturating_sub(1)) {
        Ok(bytes) => bytes,
        Err(()) => {
            let error = json!({
                "id": reply.get("id").cloned().unwrap_or(Value::Null),
                "ok": false,
                "error": format!("response exceeds {MAX_RESPONSE_BYTES} bytes; operation may have completed"),
            });
            match encode_with_limit(&error, MAX_RESPONSE_BYTES.saturating_sub(1)) {
                Ok(bytes) => bytes,
                Err(()) => b"{\"id\":null,\"ok\":false,\"error\":\"response budget exceeded\"}".to_vec(),
            }
        }
    };
    out.write_all(&encoded)?;
    out.write_all(b"\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_tokens_are_valid_and_distinct() {
        let a = generate_token().unwrap();
        let b = generate_token().unwrap();
        validate_token(&a).unwrap();
        assert_ne!(a, b);
        assert!(token_matches(&a, &a));
        assert!(token_matches(&a, &a.to_ascii_uppercase()));
        assert!(!token_matches(&a, &b));
        assert!(!token_matches(&a, "short"));
    }

    #[test]
    fn bounded_reader_rejects_an_oversized_line() {
        let input = format!("{}\n", "x".repeat(MAX_REQUEST_BYTES + 1));
        let mut reader = std::io::Cursor::new(input);
        let mut line = String::new();
        assert_eq!(read_bounded_line(&mut reader, &mut line).unwrap(), LineRead::TooLong);
        assert_eq!(line.len(), MAX_REQUEST_BYTES + 1);
    }

    #[test]
    fn authentication_rejects_missing_and_wrong_tokens_without_a_result() {
        let token = generate_token().unwrap();
        let (reply, authenticated) = authentication_reply(r#"{"id":1,"method":"engine.commands","params":{}}"#, &token);
        assert!(!authenticated);
        assert_eq!(reply["id"], 1);
        assert_eq!(reply["error"], "authentication required");
        assert!(reply.get("result").is_none());

        let wrong = "f".repeat(TOKEN_HEX_LEN);
        let line = json!({"id": 2, "method": AUTH_METHOD, "params": {"token": wrong}}).to_string();
        let (reply, authenticated) = authentication_reply(&line, &token);
        assert!(!authenticated);
        assert_eq!(reply["error"], "authentication required");
        let text = reply.to_string();
        assert!(!text.contains(&token));
        assert!(!text.contains(&wrong));

        let smuggled = json!({"id": 3, "method": "app.quit", "params": {"token": token}}).to_string();
        let (reply, authenticated) = authentication_reply(&smuggled, &token);
        assert!(!authenticated);
        assert_eq!(reply["error"], "authentication required");

        let line = json!({"id": 4, "method": AUTH_METHOD, "params": {"token": token}}).to_string();
        let (reply, authenticated) = authentication_reply(&line, &token);
        assert!(authenticated);
        assert_eq!(reply["result"]["authenticated"], true);
    }

    #[test]
    fn token_file_round_trips_between_server_and_client() {
        let path = std::env::temp_dir().join(format!("filmcraft-control-token-{}-{}.txt", std::process::id(), generate_token().unwrap()));
        let server = server_token(None, Some(&path)).unwrap();
        let client = client_token(None, Some(&path)).unwrap();
        assert_eq!(server, client);
        assert!(token_matches(&server, &client));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0);
        }
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn token_and_file_together_are_rejected() {
        let err = server_token(Some("ab".repeat(32).as_str()), Some(Path::new("token.txt"))).unwrap_err();
        assert!(err.to_string().contains("not both"));
        let err = client_token(None, None).unwrap_err();
        assert!(err.to_string().contains("FILMCRAFT_CONTROL_TOKEN"));
    }

    #[test]
    fn connection_limiter_releases_capacity() {
        let limiter = ConnectionLimiter::new(1);
        let permit = limiter.try_acquire().unwrap();
        assert!(limiter.try_acquire().is_none());
        drop(permit);
        assert!(limiter.try_acquire().is_some());
    }

    #[test]
    fn oversized_reply_is_one_complete_error_with_matching_id() {
        let reply = json!({"id": 7, "ok": true, "result": "x".repeat(MAX_RESPONSE_BYTES)});
        let mut out = Vec::new();
        write_reply(&mut out, &reply).unwrap();
        assert!(out.len() < 1024);
        assert_eq!(out.iter().filter(|&&byte| byte == b'\n').count(), 1);
        let error: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(error["id"], 7);
        assert_eq!(error["ok"], false);
        assert!(error["error"].as_str().unwrap().contains("operation may have completed"));
        assert!(!error["error"].as_str().unwrap().contains("xxxx"));
    }
}

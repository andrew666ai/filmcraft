//! Client for the desktop app's JSON-lines control protocol. One connection, reconnect on failure.
//! The first frame on every connection is `auth`; methods are sent only after it succeeds.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::AutomationError;
use crate::security::{AUTH_METHOD, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, validate_token};

type Conn = (BufReader<tokio::net::tcp::OwnedReadHalf>, tokio::net::tcp::OwnedWriteHalf);

pub struct BridgeClient {
    addr: String,
    token: String,
    conn: Mutex<Option<Conn>>,
    next_id: AtomicU64,
    timeout: Duration,
}

impl BridgeClient {
    /// `addr` such as `127.0.0.1:9876` (loopback only). `token` is 64 hexadecimal characters.
    pub fn new(addr: impl Into<String>, token: impl Into<String>) -> Result<Self, AutomationError> {
        let addr = addr.into();
        let token = token.into();
        let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(&addr);
        if !matches!(host, "127.0.0.1" | "localhost" | "[::1]" | "::1") {
            return Err(AutomationError::BadRequest(format!("bridge address must be loopback, got `{addr}`")));
        }
        validate_token(&token)?;
        Ok(Self { addr, token: token.to_ascii_lowercase(), conn: Mutex::new(None), next_id: AtomicU64::new(1), timeout: Duration::from_secs(90) })
    }

    /// Call a control method; returns `result` or the app's error.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, AutomationError> {
        let mut guard = self.conn.lock().await;
        for attempt in 0..2 {
            if guard.is_none() {
                match self.connect_authed().await {
                    Ok(conn) => *guard = Some(conn),
                    Err(e @ AutomationError::App(_)) | Err(e @ AutomationError::BadRequest(_)) => return Err(e),
                    Err(_) if attempt == 0 => continue,
                    Err(e) => return Err(e),
                }
            }
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let Some(conn) = guard.as_mut() else {
                return Err(AutomationError::Bridge(format!("not connected to {}", self.addr)));
            };
            match tokio::time::timeout(self.timeout, exchange(conn, id, method, &params)).await {
                Ok(Ok(Err(error @ AutomationError::BadRequest(_)))) => {
                    *guard = None;
                    return Err(error);
                }
                Ok(Ok(v)) => return v,
                Ok(Err(e)) if attempt == 0 => {
                    *guard = None;
                    let _ = e;
                }
                Ok(Err(e)) => {
                    *guard = None;
                    return Err(e);
                }
                Err(_) => {
                    *guard = None;
                    return Err(AutomationError::Bridge(format!("`{method}` timed out after {:?}", self.timeout)));
                }
            }
        }
        Err(AutomationError::Bridge("unreachable".into()))
    }

    async fn connect_authed(&self) -> Result<Conn, AutomationError> {
        let s = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&self.addr))
            .await
            .map_err(|_| AutomationError::Bridge(format!("timed out connecting to {}", self.addr)))?
            .map_err(|e| {
                AutomationError::Bridge(format!(
                    "cannot connect to {} ({e}); start the app with `filmcraft --control <port>` and the same control token",
                    self.addr
                ))
            })?;
        let (r, w) = s.into_split();
        let mut conn = (BufReader::new(r), w);
        let auth_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let auth = tokio::time::timeout(Duration::from_secs(5), exchange(&mut conn, auth_id, AUTH_METHOD, &json!({"token": self.token})))
            .await
            .map_err(|_| AutomationError::Bridge("control authentication timed out".into()))??;
        auth?;
        Ok(conn)
    }
}

/// Outer `Err` is a transport failure (the caller may reconnect). Inner `Err` is the app's result.
async fn exchange(conn: &mut Conn, id: u64, method: &str, params: &Value) -> Result<Result<Value, AutomationError>, AutomationError> {
    let mut line = serde_json::to_string(&json!({"id": id, "method": method, "params": params})).map_err(|e| AutomationError::Other(e.to_string()))?;
    line.push('\n');
    if line.len() > MAX_REQUEST_BYTES {
        return Ok(Err(AutomationError::BadRequest(format!("request is {} bytes; maximum is {MAX_REQUEST_BYTES}", line.len()))));
    }
    let io = |e: std::io::Error| AutomationError::Bridge(e.to_string());
    conn.1.write_all(line.as_bytes()).await.map_err(io)?;
    conn.1.flush().await.map_err(io)?;
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let n = (&mut conn.0).take((MAX_RESPONSE_BYTES + 1) as u64).read_until(b'\n', &mut buf).await.map_err(io)?;
        if n > MAX_RESPONSE_BYTES {
            return Ok(Err(AutomationError::BadRequest(format!("bridge response exceeds {MAX_RESPONSE_BYTES} bytes; operation may have completed"))));
        }
        if n == 0 {
            return Err(AutomationError::Bridge("connection closed by the app".into()));
        }
        let Ok(v) = serde_json::from_slice::<Value>(&buf) else {
            continue;
        };
        if v.get("id").and_then(Value::as_u64) != Some(id) {
            continue;
        }
        return Ok(if v.get("ok").and_then(Value::as_bool) == Some(true) {
            Ok(v.get("result").cloned().unwrap_or(Value::Null))
        } else {
            Err(AutomationError::App(v.get("error").and_then(Value::as_str).unwrap_or("unknown error").to_owned()))
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn bridge_rejects_non_loopback_and_bad_tokens() {
        assert!(BridgeClient::new("192.0.2.1:9", TOKEN).is_err());
        assert!(BridgeClient::new("127.0.0.1:9", "short").is_err());
        assert!(BridgeClient::new("localhost:9", TOKEN).is_ok());
    }

    #[tokio::test]
    async fn bridge_authenticates_before_the_method() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (r, mut w) = sock.into_split();
            let mut reader = BufReader::new(r);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let v: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(v["method"], "auth");
            assert_eq!(v["params"]["token"], TOKEN);
            let reply = json!({"id": v["id"].clone(), "ok": true, "result": {"authenticated": true}});
            w.write_all(format!("{reply}\n").as_bytes()).await.unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            let v: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(v["method"], "ui.inspect");
            assert!(v["params"].get("token").is_none());
            let reply = json!({"id": v["id"].clone(), "ok": true, "result": {"tool": "selection"}});
            w.write_all(format!("{reply}\n").as_bytes()).await.unwrap();
        });
        let client = BridgeClient::new(addr, TOKEN).unwrap();
        let v = client.call("ui.inspect", json!({})).await.unwrap();
        assert_eq!(v["tool"], "selection");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn failed_authentication_does_not_send_a_method() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (r, mut w) = sock.into_split();
            let mut reader = BufReader::new(r);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let v: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(v["method"], "auth");
            let reply = json!({"id": v["id"].clone(), "ok": false, "error": "authentication required"});
            w.write_all(format!("{reply}\n").as_bytes()).await.unwrap();
            w.flush().await.unwrap();
            line.clear();
            match tokio::time::timeout(Duration::from_millis(300), reader.read_line(&mut line)).await {
                Ok(Ok(0)) => {}
                Ok(Ok(_)) => panic!("method dispatched before authentication: {line}"),
                Ok(Err(e)) => panic!("{e}"),
                Err(_) => {}
            }
        });
        let client = BridgeClient::new(addr, TOKEN).unwrap();
        let err = client.call("app.quit", json!({})).await.unwrap_err();
        assert!(err.to_string().contains("authentication required"), "{err}");
        server.await.unwrap();
    }
}

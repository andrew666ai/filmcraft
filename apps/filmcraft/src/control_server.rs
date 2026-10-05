//! Localhost JSON-lines control server (one request per line, one reply per line). Loopback only.
//! The first line on a connection must be `auth`. Later lines are dispatched to the UI thread.

use std::io::{BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Duration;

use filmcraft_automation::security::{
    ConnectionLimiter, LineRead, MAX_CONNECTIONS, MAX_REQUEST_BYTES, authentication_reply, configure_stream, read_bounded_line, write_reply,
};
use filmcraft_ui_egui::ControlRequest;
use serde_json::{Value, json};

pub fn start(port: u16, token: String, ctx: egui::Context) -> Receiver<ControlRequest> {
    let (tx, rx) = channel::<ControlRequest>();
    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("filmcraft: control server failed to bind 127.0.0.1:{port}: {e}");
            return rx;
        }
    };
    match listener.local_addr() {
        Ok(addr) if addr.ip().is_loopback() => {}
        _ => {
            eprintln!("filmcraft: control server refused a non-loopback address");
            return rx;
        }
    }
    eprintln!("filmcraft: control server listening on 127.0.0.1:{port}");
    std::thread::spawn(move || accept_loop(listener, token, tx, ctx));
    rx
}

fn accept_loop(listener: TcpListener, token: String, tx: Sender<ControlRequest>, ctx: egui::Context) {
    let limiter = ConnectionLimiter::new(MAX_CONNECTIONS);
    let token = Arc::<str>::from(token);
    for mut stream in listener.incoming().flatten() {
        let Some(permit) = limiter.try_acquire() else {
            let _ = configure_stream(&stream);
            let _ = writeln!(stream, "{}", json!({"id": null, "ok": false, "error": "connection limit reached"}));
            continue;
        };
        let tx = tx.clone();
        let ctx = ctx.clone();
        let token = Arc::clone(&token);
        std::thread::spawn(move || {
            let _permit = permit;
            serve(stream, &token, tx, ctx);
        });
    }
}

fn serve(stream: TcpStream, token: &str, tx: Sender<ControlRequest>, ctx: egui::Context) {
    if configure_stream(&stream).is_err() {
        return;
    }
    let Ok(read) = stream.try_clone() else { return };
    let mut reader = BufReader::new(read);
    let mut out = stream;
    let mut line = String::new();
    let mut authenticated = false;
    loop {
        match read_bounded_line(&mut reader, &mut line) {
            Ok(LineRead::Eof) | Err(_) => break,
            Ok(LineRead::TooLong) => {
                let reply = json!({
                    "id": null,
                    "ok": false,
                    "error": format!("request exceeds {MAX_REQUEST_BYTES} bytes"),
                });
                let _ = write_reply(&mut out, &reply);
                let _ = out.flush();
                break;
            }
            Ok(LineRead::Line) if line.trim().is_empty() => continue,
            Ok(LineRead::Line) => {}
        }
        if !authenticated {
            let (reply, ok) = authentication_reply(&line, token);
            authenticated = ok;
            if write_reply(&mut out, &reply).is_err() || out.flush().is_err() || !authenticated {
                break;
            }
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(msg) => {
                let id = msg.get("id").cloned().unwrap_or(Value::Null);
                let method = msg.get("method").and_then(Value::as_str).unwrap_or("").to_string();
                let params = msg.get("params").cloned().unwrap_or(json!({}));
                let (req, rrx) = ControlRequest::new(method, params);
                if tx.send(req).is_err() {
                    break;
                }
                ctx.request_repaint();
                let mut r = rrx.recv_timeout(Duration::from_secs(60)).unwrap_or_else(|_| json!({"ok": false, "error": "timeout"}));
                if let Some(o) = r.as_object_mut() {
                    o.insert("id".into(), id);
                }
                r
            }
            Err(e) => json!({"ok": false, "error": format!("bad JSON: {e}")}),
        };
        if write_reply(&mut out, &reply).is_err() || out.flush().is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::serve;
    use std::io::{BufRead, BufReader, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc::channel;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use filmcraft_automation::security::MAX_REQUEST_BYTES;
    use filmcraft_ui_egui::ControlRequest;
    use serde_json::{Value, json};

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn roundtrip(addr: std::net::SocketAddr, payloads: &[String]) -> Vec<Value> {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut replies = Vec::new();
        for payload in payloads {
            writeln!(stream, "{payload}").unwrap();
            stream.flush().unwrap();
            let mut line = String::new();
            let n = reader.read_line(&mut line).unwrap();
            assert!(n > 0, "connection closed before a reply");
            replies.push(serde_json::from_str(&line).unwrap());
        }
        replies
    }

    #[test]
    fn unauthenticated_and_wrong_token_never_dispatch() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = channel::<ControlRequest>();
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let seen_handler = Arc::clone(&seen);
        let handler = std::thread::spawn(move || {
            while let Ok(req) = rx.recv() {
                seen_handler.lock().unwrap().push(req.method);
                let _ = req.reply.send(json!({"ok": true, "result": "dispatched"}));
            }
        });
        let server = std::thread::spawn(move || {
            for _ in 0..3 {
                let (stream, _) = listener.accept().unwrap();
                serve(stream, TOKEN, tx.clone(), egui::Context::default());
            }
        });

        let unauth = roundtrip(addr, &[json!({"id": 1, "method": "app.quit"}).to_string()]);
        assert_eq!(unauth[0]["id"], 1);
        assert_eq!(unauth[0]["ok"], false);
        assert_eq!(unauth[0]["error"], "authentication required");
        assert!(unauth[0].get("result").is_none());
        assert!(seen.lock().unwrap().is_empty());

        let wrong = "ab".repeat(32);
        let bad = roundtrip(addr, &[json!({"id": 2, "method": "auth", "params": {"token": wrong}}).to_string()]);
        assert_eq!(bad[0]["error"], "authentication required");
        assert!(!bad[0].to_string().contains(&wrong));
        assert!(seen.lock().unwrap().is_empty());

        let ok = roundtrip(
            addr,
            &[
                json!({"id": 3, "method": "auth", "params": {"token": TOKEN}}).to_string(),
                json!({"id": 4, "method": "ui.inspect"}).to_string(),
                "not-json".to_string(),
            ],
        );
        assert_eq!(ok[0]["result"]["authenticated"], true);
        assert_eq!(ok[1]["id"], 4);
        assert_eq!(ok[1]["result"], "dispatched");
        assert!(ok[2]["error"].as_str().unwrap().contains("bad JSON"));
        assert_eq!(seen.lock().unwrap().as_slice(), ["ui.inspect".to_string()]);

        server.join().unwrap();
        handler.join().unwrap();
    }

    #[test]
    fn oversized_request_is_rejected_without_dispatch() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = channel::<ControlRequest>();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            serve(stream, TOKEN, tx, egui::Context::default());
        });
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut body = vec![b'A'; MAX_REQUEST_BYTES + 1];
        body.push(b'\n');
        stream.write_all(&body).unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let reply: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(reply["ok"], false);
        assert!(reply["error"].as_str().unwrap().contains("exceeds"));
        assert!(rx.try_recv().is_err());
        server.join().unwrap();
    }
}

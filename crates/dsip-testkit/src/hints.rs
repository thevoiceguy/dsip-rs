//! A hints node's HTTP API in the test process (DHT Hints Profile §10), reduced to what tests need: it keeps the latest
//! frame posted for each subject and returns it. A real node verifies what it stores; here every reader verifies
//! (§8.3), which is what the tests are about.
//!
//! Spec: none (infrastructure).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A hints node on 127.0.0.1 (plain `http`): `GET /dsip/v1/hints/{did}` and `POST /dsip/v1/hints`. Returns its URL.
pub async fn hints_node() -> String {
    let held: Arc<Mutex<HashMap<String, String>>> = Arc::default();
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let url = format!("http://{}", tcp.local_addr().expect("bound"));
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = tcp.accept().await else { return };
            let held = held.clone();
            tokio::spawn(async move {
                let mut buf = vec![];
                let mut chunk = [0u8; 8192];
                // one request: the headers, then a body of content-length bytes
                let (head, body) = loop {
                    let n = s.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf).to_string();
                    if let Some(i) = text.find("\r\n\r\n") {
                        let len = text[..i]
                            .lines()
                            .find_map(|l| l.to_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0)))
                            .unwrap_or(0);
                        if buf.len() >= i + 4 + len {
                            break (text[..i].to_string(), String::from_utf8_lossy(&buf[i + 4..i + 4 + len]).to_string());
                        }
                    }
                };
                let line = head.lines().next().unwrap_or("").to_string();
                let (status, reply) = if let Some(did) = line.strip_prefix("GET /dsip/v1/hints/").and_then(|r| r.split(' ').next()) {
                    match held.lock().map(|h| h.get(did).cloned()).ok().flatten() {
                        Some(f) => ("200 OK", json!({"hints": [f]}).to_string()),
                        None => ("404 Not Found", "{}".to_string()),
                    }
                } else if line.starts_with("POST /dsip/v1/hints ") {
                    let subject = dsip_core::envelope::Envelope::from_frame(&body)
                        .ok()
                        .and_then(|e| dsip_core::b64::decode(&e.payload))
                        .and_then(|p| serde_json::from_slice::<Value>(&p).ok())
                        .and_then(|p| p["subject"].as_str().map(String::from));
                    match subject {
                        Some(sub) => {
                            if let Ok(mut h) = held.lock() {
                                h.insert(sub, body);
                            }
                            ("202 Accepted", json!({"acknowledged": 0}).to_string())
                        }
                        None => ("400 Bad Request", "{}".to_string()),
                    }
                } else {
                    ("404 Not Found", "{}".to_string())
                };
                let resp = format!("HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}", reply.len());
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    url
}

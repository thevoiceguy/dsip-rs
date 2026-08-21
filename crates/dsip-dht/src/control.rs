//! JSON-lines control port for a node (used by the Python testnet harness and the CLI).
//!
//! Spec: none (infrastructure). One request object per line, one reply per line:
//! `{"op":"publish","frame":…}`, `{"op":"get","did":…}`, `{"op":"addrs"}`,
//! `{"op":"stats"}`, `{"op":"shutdown"}`, and the test-only `{"op":"put_raw","did":…,"frame":…}`.

use anyhow::Result;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use crate::node::Handle;

/// Serve the control protocol on `listener` until the node stops.
pub async fn serve(listener: TcpListener, handle: Handle) -> Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let h = handle.clone();
        tokio::spawn(async move {
            let _ = connection(stream, h).await;
        });
    }
}

async fn connection(stream: TcpStream, handle: Handle) -> Result<()> {
    let (r, mut w) = stream.into_split();
    let mut lines = BufReader::new(r).lines();
    while let Some(line) = lines.next_line().await? {
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                w.write_all(format!("{}\n", json!({"ok": false, "error": e.to_string()})).as_bytes()).await?;
                continue;
            }
        };
        let reply = dispatch(&req, &handle).await;
        w.write_all(format!("{reply}\n").as_bytes()).await?;
        if req["op"] == "shutdown" {
            break;
        }
    }
    Ok(())
}

/// Dispatch one control request.
pub async fn dispatch(req: &Value, handle: &Handle) -> Value {
    let r = match req["op"].as_str().unwrap_or("") {
        "publish" => handle
            .publish(req["frame"].as_str().unwrap_or("").to_string())
            .await
            .map(|o| json!({"ok": true, "key": o.key, "acknowledged": o.acknowledged, "verdict": o.verdict})),
        "put_raw" => handle
            .put_raw(req["did"].as_str().unwrap_or("").to_string(), req["frame"].as_str().unwrap_or("").to_string())
            .await
            .map(|o| json!({"ok": true, "key": o.key, "acknowledged": o.acknowledged, "verdict": o.verdict})),
        "get" => handle.get(req["did"].as_str().unwrap_or("").to_string()).await.map(|o| {
            json!({"ok": true, "did": o.did, "returned": o.returned, "winner": o.winner,
                   "candidates": o.candidates.iter().map(|(f, v)| json!({"frame": f, "verdict": v})).collect::<Vec<_>>()})
        }),
        "addrs" => handle.addrs().await.map(|a| json!({"ok": true, "addrs": a.iter().map(ToString::to_string).collect::<Vec<_>>()})),
        "stats" => handle.stats().await.map(|s| json!({"ok": true, "stats": s})),
        "shutdown" => {
            handle.shutdown().await;
            Ok(json!({"ok": true}))
        }
        other => Err(anyhow::anyhow!("unknown op {other}")),
    };
    r.unwrap_or_else(|e| json!({"ok": false, "error": e.to_string()}))
}

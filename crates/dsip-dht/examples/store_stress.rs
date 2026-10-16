//! How a hints node's record store holds up at scale: fills a [`DiskStore`] with N real, signed `did:key` hints and
//! measures what an operator needs to size a node — put rate, bytes on disk per record, lookup latency (with the
//! verification every returned record gets), a full paced pass over the store, reopening it, and resident memory.
//!
//! Spec: none (infrastructure).
//!
//! `cargo run --release -p dsip-dht --example store_stress -- --records 1000000 --dir /tmp/stress`
//! Prints one JSON object (the report) on the last line.

use std::time::Instant;

use dsip_core::did::StaticResolver;
use dsip_core::keys::KeyPair;
use dsip_dht::record::{hint_payload, key_for, sign_hint, Endpoint};
use dsip_dht::store::DiskStore;
use libp2p::kad::store::RecordStore;
use libp2p::kad::{Record, RecordKey};
use libp2p::PeerId;

fn rss_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| l.split_whitespace().nth(1)?.parse().ok()))
        .unwrap_or(0)
}

fn arg(name: &str, default: &str) -> String {
    let args: Vec<String> = std::env::args().collect();
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned()).unwrap_or_else(|| default.into())
}

fn main() -> anyhow::Result<()> {
    let n: usize = arg("--records", "100000").parse()?;
    let dir = std::path::PathBuf::from(arg("--dir", "/tmp/dsip-store-stress"));
    let cache: usize = arg("--cache-mb", "256").parse::<usize>()? << 20;
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("overlay-records.redb");
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() as i64;
    let rss_start = rss_kb();

    // 1. N signed hints as a browser publishes them: a did:key identity's device signs, presenting its delegation
    //    inline; a relay and a mailbox endpoint
    let t = Instant::now();
    let mut mailbox = Endpoint::signaling("wss://mailbox.example:9443/dsip");
    mailbox.extra.insert("service".into(), "DSIPMailbox".into());
    mailbox.extra.insert("mailbox".into(), "did:key:z6MkmDofjNWY2jwMsssxw3pkEUgHQqEQEX3ZPAm3eM7ghLKk".into());
    let endpoints = [Endpoint::signaling("wss://relay.example:8443/dsip"), mailbox];
    let mut sample_keys = vec![];
    let mut store = DiskStore::open(Some(&path), PeerId::random(), StaticResolver::default(), n + 1, cache)?;
    let mut value_bytes = 0usize;
    let mut put_secs = 0f64;
    for i in 0..n {
        let (identity, device) = (KeyPair::generate(), KeyPair::generate());
        let caps = ["dsip.signaling", "dsip.media.interactive", "dsip.messaging"];
        let deleg = dsip_core::envelope::sign(
            &dsip_core::delegation::delegation_payload(&identity.did(), &device.did(), now - 60, now + 7 * 86_400, &caps),
            &identity,
            &identity.kid(),
        );
        let at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() as i64;
        let p = hint_payload(&identity.did(), &identity.did(), &endpoints, at, at, 3600);
        let frame = sign_hint(&p, &device, vec![deleg]).frame();
        let key = key_for(&identity.did());
        value_bytes += frame.len();
        if i % (n / 1000).max(1) == 0 {
            sample_keys.push(key.clone());
        }
        let tp = Instant::now();
        store.put(Record { key: RecordKey::new(&key), value: frame.into_bytes(), publisher: None, expires: None })
            .map_err(|e| anyhow::anyhow!("put {i}: {e:?}"))?;
        put_secs += tp.elapsed().as_secs_f64();
        if (i + 1) % 1000 == 0 {
            store.flush(); // the node flushes once a maintenance tick; this is more often than that
        }
        if (i + 1) % 100_000 == 0 {
            eprintln!("  {} records, {:.0} s, rss {} MB", i + 1, t.elapsed().as_secs_f64(), rss_kb() / 1024);
        }
    }
    let fill_secs = t.elapsed().as_secs_f64();
    let rss_filled = rss_kb();
    store.flush();
    drop(store);
    let file_bytes = DiskStore::file_bytes(&path);

    // 2. reopen: what a restart costs before the node serves
    let t = Instant::now();
    let store = DiskStore::open(Some(&path), PeerId::random(), StaticResolver::default(), n + 1, cache)?;
    let reopen_ms = t.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(store.len(), n);

    // 3. lookups: read and verify (what serving a GET costs)
    let t = Instant::now();
    let mut served = 0;
    for k in &sample_keys {
        served += usize::from(store.get(&RecordKey::new(k)).is_some());
    }
    let get_us = t.elapsed().as_secs_f64() * 1e6 / sample_keys.len() as f64;
    assert_eq!(served, sample_keys.len(), "every sampled hint verifies");

    // 4. a full paced pass, as the node walks it: one second's share at a time over a 1,200 s republish
    let t = Instant::now();
    let share = n.div_ceil(1200);
    let (mut cursor, mut walked, mut peak_share) = (None::<Vec<u8>>, 0usize, 0u64);
    loop {
        let batch = store.batch_after(cursor.as_deref(), share);
        walked += batch.len();
        peak_share = peak_share.max(rss_kb());
        if batch.len() < share {
            break;
        }
        cursor = batch.last().map(|(k, _)| k.clone());
    }
    let pass_secs = t.elapsed().as_secs_f64();
    assert_eq!(walked, n);

    let report = serde_json::json!({
        "records": n,
        "mean_value_bytes": value_bytes / n.max(1),
        "file_bytes": file_bytes,
        "file_bytes_per_record": file_bytes / n.max(1) as u64,
        "cache_mb": cache >> 20,
        "fill_secs": (fill_secs * 10.0).round() / 10.0,
        "puts_per_sec": (n as f64 / put_secs.max(1e-9)).round(),
        "reopen_ms": (reopen_ms * 10.0).round() / 10.0,
        "get_verified_us": get_us.round(),
        "full_pass_secs": (pass_secs * 10.0).round() / 10.0,
        "rss_mb": {"start": rss_start / 1024, "filled": rss_filled / 1024, "peak_during_pass": peak_share / 1024},
    });
    println!("{report}");
    Ok(())
}

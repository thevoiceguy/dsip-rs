//! HTTP limits and metrics: the per-IP token bucket answers 429 (profile §10), `/metrics` is never limited and counts it.

use std::net::SocketAddr;
use std::sync::Arc;

async fn serve(node: dsip_node::Node) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    let app = dsip_node::router(Arc::new(node)).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(l, app).await });
    base
}

fn limited(per_min: u32, trust: bool) -> dsip_node::Node {
    let mut n = dsip_node::Node::new(None, None, "-".into(), None);
    n.limits = dsip_node::Limits { http_per_ip_per_min: per_min, trust_forwarded_for: trust };
    n
}

#[tokio::test]
async fn the_sixth_request_in_a_minute_is_429_and_metrics_count_it() {
    let base = serve(limited(5, false)).await;
    let http = reqwest::Client::new();
    let z = "y".repeat(52);
    for i in 0..5 {
        assert_eq!(http.get(format!("{base}/{z}")).send().await.unwrap().status(), 404, "request {i} is admitted");
    }
    let r = http.get(format!("{base}/{z}")).send().await.unwrap();
    assert_eq!(r.status(), 429);
    assert_eq!(r.headers()["retry-after"], "60");
    // metrics are never limited, and count both outcomes
    let m = http.get(format!("{base}/metrics")).send().await.unwrap();
    assert_eq!(m.status(), 200);
    let text = m.text().await.unwrap();
    assert!(text.contains("dsip_node_http_requests_total{route=\"/{z32}\",status=\"404\"} 5"), "{text}");
    assert!(text.contains("dsip_node_http_requests_total{route=\"/{z32}\",status=\"429\"} 1"), "{text}");
    assert!(text.contains("# TYPE dsip_node_pkarr_held gauge"), "{text}");
}

#[tokio::test]
async fn forwarded_clients_get_their_own_buckets_only_when_trusted() {
    let http = reqwest::Client::new();
    let z = "y".repeat(52);
    for (trust, second) in [(true, 404), (false, 429)] {
        let base = serve(limited(1, trust)).await;
        let get = |ip: &'static str| http.get(format!("{base}/{z}")).header("x-forwarded-for", ip).send();
        assert_eq!(get("192.0.2.1").await.unwrap().status(), 404);
        assert_eq!(get("192.0.2.2").await.unwrap().status().as_u16(), second,
                   "trusted: another client; untrusted: the same socket address, already spent");
    }
}

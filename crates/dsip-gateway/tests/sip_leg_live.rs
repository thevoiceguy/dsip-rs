//! G1 verification: the SIP leg is real on the wire — it answers OPTIONS, sends 100 Trying to an
//! INVITE, surfaces it as a `SipEvent::Invite` with the caller number, and its controller-driven
//! reject reaches the caller with the mapped status. No DSIP or media leg needed.
#![cfg(feature = "host")]

use std::time::Duration;

use dsip_gateway::controller::GatewayCall;
use dsip_gateway::host::sip_leg::{SipEvent, SipLeg};
use dsip_gateway::map_outbound;
use tokio::net::UdpSocket;

async fn recv(sock: &UdpSocket) -> String {
    let mut buf = vec![0u8; 65535];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf)).await.expect("timed out").unwrap();
    String::from_utf8_lossy(&buf[..n]).to_string()
}

#[tokio::test]
async fn invite_is_answered_and_surfaced() {
    // A caller socket.
    let caller = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let caller_addr = caller.local_addr().unwrap();

    // The gateway SIP leg on a fixed loopback port.
    let listen = "127.0.0.1:45061".parse().unwrap();
    let (leg, mut rx) = SipLeg::new(listen, "127.0.0.1", "gateway").await.unwrap();

    let invite = format!(
        "INVITE sip:+15551234567@127.0.0.1 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:{cp};branch=z9hG4bK-test1\r\n\
         From: <sip:+15559998888@127.0.0.1>;tag=caller\r\n\
         To: <sip:+15551234567@127.0.0.1>\r\n\
         Call-ID: g1-test-call\r\n\
         CSeq: 1 INVITE\r\n\
         Contact: <sip:+15559998888@127.0.0.1:{cp}>\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: 0\r\n\r\n",
        cp = caller_addr.port()
    );
    caller.send_to(invite.as_bytes(), listen).await.unwrap();

    // 100 Trying comes back to the caller.
    let trying = recv(&caller).await;
    assert!(trying.starts_with("SIP/2.0 100"), "expected 100 Trying, got: {trying}");

    // The leg surfaces the INVITE with the caller number parsed from From.
    let ev = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await.expect("no event").unwrap();
    let (call_id, from_tn) = match ev {
        SipEvent::Invite { call_id, from_tn, .. } => (call_id, from_tn),
        other => panic!("expected Invite, got {other:?}"),
    };
    assert_eq!(call_id, "g1-test-call");
    assert_eq!(from_tn, "+15559998888");

    // The controller maps a DSIP reject to a SIP status; the leg sends it and the caller sees it.
    let mut ctrl = GatewayCall::new(&serde_json::json!({"direction": "inbound"}));
    // Feed the same INVITE event to the controller and take its 100 (already sent) — then reject.
    let _ = ctrl.step(&serde_json::json!({"sip": {"request": "INVITE", "from_tn": from_tn}}));
    let mapped = map_outbound("policy.first-contact-required", "pre-answer");
    let status = mapped["status"].as_u64().unwrap() as u16;
    leg.reject(&call_id, status, mapped["q850"].as_u64().map(|c| c as u32), "policy.first-contact-required").await.unwrap();
    let refusal = recv(&caller).await;
    assert!(refusal.starts_with(&format!("SIP/2.0 {status}")), "expected {status}, got: {refusal}");
    assert!(refusal.contains("Reason: "), "the refusal carries the DSIP reason: {refusal}");
    assert!(refusal.contains("DSIP") && refusal.contains("policy.first-contact-required"), "reason names the DSIP token: {refusal}");
}

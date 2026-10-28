//! A softphone in about twenty lines: call a DID, or answer whoever calls, sending a 440 Hz tone.
//!
//! ```sh
//! cargo run -p dsip-cli -- identity init --dir /tmp/alice --name Alice     # an identity directory
//! cargo run -p dsip-phone --example softphone -- /tmp/alice wss://127.0.0.1:8443/dsip relay/cert.pem [did:key:…]
//! ```

use dsip_phone::{AnswerPolicy, Identity, Media, Outcome, Phone};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let (dir, relay, ca) = (&args[1], &args[2], &args[3]);
    let media = dsip_media::MediaConfig { source: dsip_media::Source::Tone { hz: 440.0 }, ..Default::default() };
    let mut phone = Phone::builder().identity(Identity::load(dir.as_ref())?).relay(relay).media(Media::Native(media));
    if let Some(tls) = dsip_transport::tls::client_config(Some(ca.as_ref()))? {
        phone = phone.tls(tls);
    }
    let phone = phone.answer(AnswerPolicy::Accept).build().await?;
    println!("{} on {relay}", phone.identity());

    let mut call = match args.get(4) {
        Some(to) => phone.call(to).await?,
        None => phone.incoming().await.ok_or("closed")?.call, // answered by policy
    };
    match call.outcome().await {
        Outcome::Answered { answered_by } => println!("answered ({answered_by}); ended: {}", call.ended().await),
        Outcome::Ended { reason } => println!("not answered: {reason}"),
    }
    Ok(())
}

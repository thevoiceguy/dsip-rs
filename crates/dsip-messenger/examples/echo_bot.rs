//! A chat bot: it answers every text message with the same text, in the conversation it came from. Its state lives in
//! memory, so it starts over each run (a real bot uses a persistent `Store`, as dsip-msg does with SQLite).
//!
//! ```sh
//! cargo run -p dsip-cli -- identity init --dir /tmp/bot --name Bot
//! cargo run -p dsip-messenger --example echo_bot -- /tmp/bot <mailbox DID> wss://127.0.0.1:9443/dsip mailbox/cert.pem
//! ```
//!
//! Anyone with a grant from the bot (M§14) can then create a conversation with it and write.

use std::collections::VecDeque;

use serde_json::{json, Value};

use dsip_messaging_device::{Event, MemoryStore, Ui};
use dsip_messenger::{Config, Engine, Host, Messenger, Output};

/// Prints what happens and remembers the texts to answer.
#[derive(Default)]
struct Bot {
    identity: String,
    to_answer: VecDeque<(String, Value)>,
}

impl Host<MemoryStore> for Bot {
    async fn output(&mut self, _engine: &Engine<MemoryStore>, out: Output) {
        match out {
            Output::Event(Event::Ui(Ui::Message { group, from, object, .. })) if from != self.identity && object["kind"] == "text" => {
                println!("{from}: {}", object["text"]);
                self.to_answer.push_back((group, object["text"].clone()));
            }
            Output::Connected { mailbox, .. } => println!("connected to {mailbox}"),
            other => println!("{other:?}"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let id = dsip_transport::identity::Identity::load(args[1].as_ref())?;
    let (mailbox, uri) = (args[2].clone(), args[3].clone());
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let identity_json = json!({"identity": id.meta.identity, "device_seed_hex": hex(&id.device.seed()), "delegation": id.delegation.frame(),
                               "controller_seed_hex": hex(&id.controller.seed()), "display_name": id.meta.display_name}).to_string();
    let now = dsip_transport::now_s() as f64;
    let engine = Engine::open(&identity_json, &mailbox, &uri, MemoryStore::default(), &Value::Null, now)?;
    let cfg = Config { identity: id.meta.identity.clone(), device: id.device.clone(), delegation: id.delegation.clone(),
                       mailbox: (mailbox, uri), resolver_files: vec![], ca: args.get(4).map(Into::into),
                       media_dir: std::env::temp_dir().join("echo-bot"), host_key: "echo-bot".into() };
    let mut mx = Messenger::new(engine, cfg, vec![])?;
    let mut bot = Bot { identity: id.meta.identity.clone(), ..Bot::default() };
    mx.connect(&mut bot).await?;
    let frame = mx.engine_mut().key_packages_frame(4, now)?; // so that others can add this device (M§5.5)
    mx.send_frame(&mut bot, &frame).await?;
    mx.sync(&mut bot, true).await?;

    let mut clock = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        tokio::select! {
            Some(frame) = mx.recv() => mx.received(&mut bot, frame).await,
            _ = clock.tick() => {
                mx.tick(&mut bot).await;
                mx.check_reconnect(&mut bot).await?;
            }
        }
        while let Some((group, text)) = bot.to_answer.pop_front() {
            let now = dsip_transport::now_s();
            let conversation = mx.engine().conversations(now as f64).into_iter().find(|c| c.group == group).map(|c| c.conversation);
            let reply = json!({"object": "content", "id": mx.engine_mut().new_id(now as f64), "conversation": conversation,
                               "sender": bot.identity, "sent_at": now, "purpose": "message",
                               "kind": "text", "content_type": "text/plain", "text": text});
            let sent = mx.engine_mut().send(&group, &reply, now as f64)?;
            if !sent.send.is_empty() {
                mx.send_frame(&mut bot, &sent.send).await?;
            }
        }
        mx.settle(&mut bot).await;
    }
}

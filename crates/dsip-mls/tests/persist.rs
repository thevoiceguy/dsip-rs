//! A device's MLS state across restarts, on the `sqlite` provider: KeyPackage secrets and group state
//! survive the process, and a rolled-back transaction restores a message secret that processing had
//! consumed — which is why a device commits delivery state with MLS state (M§5.4, spec-gap 44).
//!
//! Spec: M§5.4, M§5.5, M§6.6, M§8.5.

use std::path::Path;

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use serde_json::json;

use dsip_core::delegation::delegation_payload;
use dsip_core::envelope::sign;
use dsip_core::keys::KeyPair;
use dsip_mls::sqlite::SqliteProvider;
use dsip_mls::{Device, MlsError};

const NOW: i64 = 1_790_000_000;

fn delegation(identity: &KeyPair, device: &KeyPair) -> String {
    let p = delegation_payload(&identity.did(), &device.did(), NOW - 3600, NOW + 7 * 86400, &["dsip.messaging"]);
    let e = sign(&p, identity, &identity.kid());
    format!("{}.{}.{}", e.protected, e.payload, e.signature)
}

/// Bob's device, opened afresh from its database: what a restarted process would have.
fn bob(db: &Path) -> Device<SqliteProvider> {
    let (i, d) = (KeyPair::from_fixture_name("bob"), KeyPair::from_fixture_name("bob-phone"));
    let deleg = delegation(&i, &d);
    Device::with_provider(d, deleg, SqliteProvider::open(db).expect("open"))
}

fn protocol(bytes: &[u8]) -> ProtocolMessage {
    MlsMessageIn::tls_deserialize_exact(bytes).unwrap().try_into_protocol_message().unwrap()
}

fn decrypt(dev: &Device<SqliteProvider>, group: &mut MlsGroup, bytes: &[u8]) -> Result<Vec<u8>, String> {
    let processed = group.process_message(dev.provider(), protocol(bytes)).map_err(|e| format!("{e:?}"))?;
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app) => Ok(app.into_bytes()),
        _ => Err("not application".into()),
    }
}

#[test]
fn device_state_survives_restart_and_rolls_back_atomically() {
    let dir = std::env::temp_dir().join(format!("dsip-mls-persist-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("device.sqlite");

    let (ai, ad) = (KeyPair::from_fixture_name("alice"), KeyPair::from_fixture_name("alice-phone"));
    let alice = Device::new(KeyPair::from_seed(ad.seed()), delegation(&ai, &ad));
    let gid = b"01M2PERSISTGROUP000000000".to_vec();
    let conv = serde_json::to_vec(&json!({"conversation": "c", "kind": "direct", "hub": {"did": "h", "uri": "u"}, "successor_of": null})).unwrap();

    // M§5.5: Bob uploads a KeyPackage, then his process ends before any welcome arrives.
    let kp_bytes = bob(&db).key_package().unwrap();

    // Alice adds Bob from that KeyPackage.
    let mut ag = alice.create_group(&gid, &conv).unwrap();
    let kp = KeyPackageIn::tls_deserialize_exact(&kp_bytes).unwrap().validate(alice.provider().crypto(), ProtocolVersion::Mls10).unwrap();
    let (_, welcome, _) = ag.add_members(alice.provider(), &alice.signer(), &[kp]).unwrap();
    ag.merge_pending_commit(alice.provider()).unwrap();
    let send = |ag: &mut MlsGroup, text: &str| ag.create_message(alice.provider(), &alice.signer(), text.as_bytes()).unwrap().tls_serialize_detached().unwrap();

    // M§6.6: a restarted Bob still holds the KeyPackage's private keys, so the welcome joins.
    {
        let dev = bob(&db);
        let group = dev.join(&welcome.tls_serialize_detached().unwrap()).expect("join after restart");
        assert_eq!(group.epoch().as_u64(), 1);
        dev.provider().put_state("group", &json!(String::from_utf8(gid.clone()).unwrap())).unwrap();
    }

    // Group state survives: a restarted Bob loads the group and decrypts.
    let m1 = send(&mut ag, "one");
    {
        let dev = bob(&db);
        assert_eq!(dev.provider().get_state("group").unwrap(), Some(json!(String::from_utf8(gid.clone()).unwrap())));
        let mut group = dev.load_group(&gid).unwrap().expect("group persisted");
        let pt = dev.provider().atomically(|| {
            let pt = decrypt(&dev, &mut group, &m1).map_err(MlsError)?;
            dev.provider().put_state("cursor", &json!("c:1"))?;
            Ok(pt)
        });
        assert_eq!(pt.unwrap(), b"one");
    }

    // A crash after processing but before commit: the transaction rolls back, and the secret with it.
    let m2 = send(&mut ag, "two");
    {
        let dev = bob(&db);
        let mut group = dev.load_group(&gid).unwrap().unwrap();
        let crashed: Result<(), MlsError> = dev.provider().atomically(|| {
            assert_eq!(decrypt(&dev, &mut group, &m2).unwrap(), b"two");
            dev.provider().put_state("cursor", &json!("c:2"))?;
            Err(MlsError("crash before commit".into()))
        });
        assert!(crashed.is_err());
    }
    {
        let dev = bob(&db);
        assert_eq!(dev.provider().get_state("cursor").unwrap(), Some(json!("c:1")), "the ack cursor rolled back too");
        let mut group = dev.load_group(&gid).unwrap().unwrap();
        // Redelivered after the rollback, the item decrypts: nothing was lost.
        let pt = dev.provider().atomically(|| {
            let pt = decrypt(&dev, &mut group, &m2).map_err(MlsError)?;
            dev.provider().put_state("cursor", &json!("c:2"))?;
            Ok(pt)
        });
        assert_eq!(pt.unwrap(), b"two");
    }

    // Once committed, the same bytes can never be decrypted again: a redelivered item has to be
    // recognised by its seq, not by its content id (M§8.5, spec-gap 44).
    {
        let dev = bob(&db);
        let mut group = dev.load_group(&gid).unwrap().unwrap();
        let again = decrypt(&dev, &mut group, &m2);
        assert!(again.is_err(), "a consumed secret must not decrypt twice: {again:?}");
        assert_eq!(decrypt(&dev, &mut group, &send(&mut ag, "three")).unwrap(), b"three", "later messages still decrypt");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

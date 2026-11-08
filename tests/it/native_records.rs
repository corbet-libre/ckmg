//! Actual native core consumes only record-purpose initializers made inside Keys.
//! Existing Authority fixture is not claimed as real server G3 or remote restore.
#![cfg(all(feature = "native-records", not(target_arch = "wasm32")))]
use crate::support::*;
use ckmg::*;
use cvln::{Limits, Node, Publication, core::VeilidConfig};
use std::{num::NonZeroUsize, time::Duration};

#[tokio::test]
async fn passkey_record_reopens_with_exact_read_custody_and_separates_scopes() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = VeilidConfig::new(
        "custody_test",
        "records",
        "org",
        Some(directory.path().to_str().unwrap()),
        None,
    );
    config.protected_store.always_use_insecure_storage = true;
    config.network.routing_table.bootstrap.clear();
    config.network.routing_table.bootstrap_keys.clear();
    let node = Node::start(
        config,
        Limits {
            queued_messages: NonZeroUsize::new(8).unwrap(),
            listeners: NonZeroUsize::new(2).unwrap(),
            deadline: Duration::from_millis(100),
        },
    )
    .await
    .unwrap();
    let records = node.record_backend(NonZeroUsize::new(3).unwrap()).unwrap();
    assert!(passkey::native_passkey_record(&prf(1), "").is_err());
    let record = records
        .initialize(passkey::native_passkey_record(&prf(1), "garden").unwrap())
        .await
        .unwrap();
    let key = record.key();
    let owner = record.owner();
    assert!(matches!(
        record
            .republish(0, 7, b"opaque wrapped root fixture")
            .await
            .unwrap(),
        Publication::Queued
    ));
    record.close().await.unwrap();
    let reopened = records
        .initialize(passkey::native_passkey_record(&prf(1), "garden").unwrap())
        .await
        .unwrap();
    assert_eq!(reopened.key(), key);
    assert_eq!(reopened.owner(), owner);
    let value = reopened.get(0, false).await.unwrap().unwrap();
    assert_eq!(value.data(), b"opaque wrapped root fixture");
    assert_eq!(u32::from(value.seq()), 7);
    let other = records
        .initialize(passkey::native_passkey_record(&prf(1), "other").unwrap())
        .await
        .unwrap();
    let second = records
        .initialize(passkey::native_passkey_record(&prf(2), "garden").unwrap())
        .await
        .unwrap();
    assert_ne!(other.key(), key);
    assert_ne!(other.owner(), owner);
    assert_ne!(second.key(), key);
    assert_ne!(second.owner(), owner);
    other.close().await.unwrap();
    second.close().await.unwrap();
    reopened.close().await.unwrap();

    let store = Memory::default();
    let time = Time::default();
    let guard = Guard::default();
    let mut keys = machine(&store, &time, &guard, 73);
    create(&mut keys, &guard, &prf(1), &binding("garden")).await;
    let handle = keys.key(purpose(Scope::Member, "history")).await.unwrap();
    let expected_owner = *handle.certificate().key.value();
    let initializer = keys
        .native_record_initializer(&handle, NativeRecordSchema::dflt(1).unwrap())
        .await
        .unwrap();
    let record = records.initialize(initializer).await.unwrap();
    assert_eq!(
        record.owner().ref_value().bytes().as_ref(),
        expected_owner.as_slice()
    );
    record.close().await.unwrap();
    keys.lock();
    assert!(
        keys.native_record_initializer(&handle, NativeRecordSchema::dflt(1).unwrap())
            .await
            .is_err()
    );
    node.shutdown().await;
}

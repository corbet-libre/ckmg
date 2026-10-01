//! The same real state-machine and crypto cases execute natively and in Chrome Wasm.
mod support;
use ckmg::*;
use futures::executor::block_on;
use support::*;

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn restore_is_identity_preserving_and_never_implicitly_creates() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 1);
        assert_eq!(a.unlock(&prf(1), "a").await, Err(Error::MissingCheckpoint));
        assert_eq!(a.state(), State::MissingCheckpoint);
        assert_eq!(store.0.borrow().writes, 0);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        let before = a.lineage().await.unwrap();
        let key = a.key(purpose(Scope::Device, "profile")).await.unwrap();
        let public = key.certificate().key;
        a.lock();
        assert_eq!(a.sign(&key, b"hello").await, Err(Error::Locked));
        a.unlock(&prf(1), "a").await.unwrap();
        assert_eq!(a.lineage().await.unwrap(), before);
        assert_eq!(a.sign(&key, b"hello").await, Err(Error::Unauthorized));
        let restored = a.key(purpose(Scope::Device, "profile")).await.unwrap();
        assert_eq!(restored.certificate().key, public);
        let sig = a.sign(&restored, b"hello").await.unwrap();
        verify(&public, b"hello", &sig).unwrap();
        assert!(verify(&public, b"changed", &sig).is_err());
        a.lock();
        assert_eq!(
            a.create_scope(&prf(1), binding("a"), info(), &[])
                .await
                .unwrap_err(),
            Error::RootExists
        );
        assert_eq!(a.unlock(&prf(2), "a").await, Err(Error::MissingCheckpoint));
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn signatures_and_encryption_bind_community_purpose_device_and_epoch() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 2);
        let mut b = machine(&store, &time, &guard, 3);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        create(&mut b, &guard, &prf(1), &binding("b")).await;
        let lineage = a.lineage().await.unwrap();
        let p = purpose(Scope::Member, "profile");
        let ka = a.key(p.clone()).await.unwrap();
        let kb = b.key(p.clone()).await.unwrap();
        let wrong = a.key(purpose(Scope::Member, "other")).await.unwrap();
        assert_ne!(ka.certificate().key, kb.certificate().key);
        assert_ne!(lineage.root, b.lineage().await.unwrap().root);
        ka.certificate().verify(&lineage, &p).unwrap();
        assert!(
            ka.certificate()
                .verify(&b.lineage().await.unwrap(), &p)
                .is_err()
        );
        assert!(
            ka.certificate()
                .verify(&lineage, &purpose(Scope::Member, "other"))
                .is_err()
        );
        let plain = a.sign_ed25519(&ka, b"owner-transcript").await.unwrap();
        verify_ed25519(ka.certificate().key.value(), b"owner-transcript", &plain).unwrap();
        assert!(
            verify(
                &ka.certificate().key,
                b"owner-transcript",
                &Signature::new(VLD0, plain)
            )
            .is_err()
        );
        let sealed = a
            .seal(&ka, b"revision=1", b"private-profile")
            .await
            .unwrap();
        assert_eq!(
            &*a.open(&ka, b"revision=1", &sealed).await.unwrap(),
            b"private-profile"
        );
        assert!(a.open(&ka, b"revision=2", &sealed).await.is_err());
        assert!(a.open(&wrong, b"revision=1", &sealed).await.is_err());
        assert!(b.open(&kb, b"revision=1", &sealed).await.is_err());
        let mut altered = sealed.clone();
        *altered.last_mut().unwrap() ^= 1;
        assert!(a.open(&ka, b"revision=1", &altered).await.is_err());
        assert_ne!(
            sealed,
            a.seal(&ka, b"revision=1", b"private-profile")
                .await
                .unwrap()
        );
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn pairing_requires_possession_approval_exact_root_and_single_use() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 4);
        let mut b = machine(&store, &time, &guard, 5);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        let anchor = a.lineage().await.unwrap();
        let request = request(&mut b, &prf(2), &anchor).await;
        assert_eq!(b.state(), State::PendingDevice);
        assert!(b.key(purpose(Scope::Device, "profile")).await.is_err());
        let mut tampered = request.clone();
        tampered.nonce[0] ^= 1;
        assert!(a.authorize_device(&tampered, &[]).await.is_err());
        assert!(a.authorize_device(&request, &[]).await.is_err());
        assert_eq!(a.state(), State::Locked);
        a.unlock(&prf(1), "a").await.unwrap();
        let grant = grant(&mut a, &guard, &request).await;
        let mut tampered = grant.clone();
        tampered.sealed_root[8] ^= 1;
        assert!(b.accept_pairing(&tampered, &[]).await.is_err());
        let mut swapped = grant.clone();
        swapped.request.nonce[0] ^= 1;
        assert!(b.accept_pairing(&swapped, &[]).await.is_err());
        accept(&mut b, &grant).await;
        assert_eq!(b.state(), State::Authorized);
        assert_eq!(a.lineage().await.unwrap(), b.lineage().await.unwrap());
        assert!(b.accept_pairing(&grant, &[]).await.is_err());
        assert!(a.authorize_device(&request, &[]).await.is_err());
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn paired_devices_share_only_member_purposes_and_restore_the_same_logical_device() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 6);
        let mut b = machine(&store, &time, &guard, 7);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        pair(&mut a, &mut b, &guard, &prf(2)).await;
        let ma = a.key(purpose(Scope::Member, "records")).await.unwrap();
        let mb = b.key(purpose(Scope::Member, "records")).await.unwrap();
        let da = a.key(purpose(Scope::Device, "mls")).await.unwrap();
        let db = b.key(purpose(Scope::Device, "mls")).await.unwrap();
        assert_eq!(ma.certificate().key, mb.certificate().key);
        assert_ne!(da.certificate().key, db.certificate().key);
        let sealed = a.seal(&ma, b"record", b"stored-value").await.unwrap();
        assert_eq!(
            &*b.open(&mb, b"record", &sealed).await.unwrap(),
            b"stored-value"
        );
        let before = b.lineage().await.unwrap();
        let cert = db.certificate().clone();
        let mut restored = machine(&store, &time, &guard, 8);
        restored.unlock(&prf(2), "a").await.unwrap();
        assert_eq!(restored.lineage().await.unwrap(), before);
        assert_eq!(
            restored
                .key(purpose(Scope::Device, "mls"))
                .await
                .unwrap()
                .certificate(),
            &cert
        );
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rotation_is_atomic_preserves_pseudonym_and_denies_revoked_and_stale_keys() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 9);
        let mut b = machine(&store, &time, &guard, 10);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        let grant = pair(&mut a, &mut b, &guard, &prf(2)).await;
        let previous = a.lineage().await.unwrap();
        let old = a.key(purpose(Scope::Device, "profile")).await.unwrap();
        let removed = b.key(purpose(Scope::Member, "records")).await.unwrap();
        prepare(&mut a, grant.request.device).await;
        assert_eq!(a.state(), State::Prepared);
        assert_eq!(a.sign(&old, b"blocked").await, Err(Error::Pending));
        let receipt = a.commit().await.unwrap().unwrap();
        rotation(&receipt).verify(&previous).unwrap();
        assert_eq!(rotation(&receipt).lineage.binding, previous.binding);
        assert_eq!(rotation(&receipt).lineage.epoch, previous.epoch + 1);
        guard.publish(&receipt);
        a.acknowledge(receipt.operation).await.unwrap();
        assert!(a.sign(&old, b"stale").await.is_err());
        let new = a.key(purpose(Scope::Device, "profile")).await.unwrap();
        assert_ne!(new.certificate().key, old.certificate().key);
        assert!(b.sign(&removed, b"revoked").await.is_err());
        b.unlock(&prf(2), "a").await.unwrap();
        let r = b
            .apply_rotation(rotation(&receipt), &adoption(rotation(&receipt)))
            .await
            .unwrap();
        b.acknowledge(r.operation).await.unwrap();
        assert_eq!(b.state(), State::Revoked);
        assert_eq!(
            b.key(purpose(Scope::Device, "anything")).await.unwrap_err(),
            Error::Revoked
        );
        b.lock();
        b.unlock(&prf(2), "a").await.unwrap();
        assert_eq!(b.state(), State::Revoked);
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn remaining_device_adopts_exact_successor_and_rejects_tampering() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 11);
        let mut b = machine(&store, &time, &guard, 12);
        let mut c = machine(&store, &time, &guard, 13);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        pair(&mut a, &mut b, &guard, &prf(2)).await;
        let grant = pair(&mut a, &mut c, &guard, &prf(3)).await;
        let old = b.lineage().await.unwrap();
        let next = a.lineage().await.unwrap();
        let r = b
            .adopt_lineage(
                &next,
                &consent(
                    Action::Adopt,
                    &old.binding,
                    Some(old.root),
                    old.epoch,
                    None,
                    Some(next.digest().unwrap()),
                ),
            )
            .await
            .unwrap();
        b.acknowledge(r.operation).await.unwrap();
        prepare(&mut a, grant.request.device).await;
        let receipt = a.commit().await.unwrap().unwrap();
        guard.publish(&receipt);
        a.acknowledge(receipt.operation).await.unwrap();
        let mut bad = rotation(&receipt).clone();
        bad.envelopes[0].sealed_root[10] ^= 1;
        assert!(b.apply_rotation(&bad, &adoption(&bad)).await.is_err());
        let r = b
            .apply_rotation(rotation(&receipt), &adoption(rotation(&receipt)))
            .await
            .unwrap();
        b.acknowledge(r.operation).await.unwrap();
        assert_eq!(a.lineage().await.unwrap(), b.lineage().await.unwrap());
        let ka = a.key(purpose(Scope::Member, "records")).await.unwrap();
        let kb = b.key(purpose(Scope::Member, "records")).await.unwrap();
        assert_eq!(ka.certificate().key, kb.certificate().key);
        assert!(
            b.apply_rotation(rotation(&receipt), &adoption(rotation(&receipt)))
                .await
                .is_err()
        );
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn expiry_and_clock_regression_fail_without_publishing() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 14);
        let mut b = machine(&store, &time, &guard, 15);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        let anchor = a.lineage().await.unwrap();
        let request = request(&mut b, &prf(2), &anchor).await;
        time.0.set(request.expires_at);
        let writes = store.0.borrow().writes;
        assert_eq!(
            a.authorize_device(&request, &[]).await.unwrap_err(),
            Error::Expired
        );
        assert_eq!(store.0.borrow().writes, writes);
        time.0.set(1);
        assert_eq!(
            a.key(purpose(Scope::Device, "x")).await.unwrap_err(),
            Error::Clock
        );
        assert_eq!(a.state(), State::Locked);
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn unknown_outcomes_reconcile_without_regenerating_identity_or_outputs() {
    block_on(async {
        for fault in [Fault::Before, Fault::After, Fault::Conflict] {
            let store = Memory::default();
            let time = Time::default();
            let guard = Guard::default();
            let mut a = machine(&store, &time, &guard, 16);
            let mut b = machine(&store, &time, &guard, 17);
            create(&mut a, &guard, &prf(1), &binding("a")).await;
            let grant = pair(&mut a, &mut b, &guard, &prf(2)).await;
            let previous = a.lineage().await.unwrap();
            prepare(&mut a, grant.request.device).await;
            store.0.borrow_mut().fault = fault;
            assert_eq!(a.commit().await.unwrap_err(), Error::Reconcile);
            assert_eq!(a.state(), State::Reconcile);
            assert_eq!(a.commit().await.unwrap_err(), Error::Pending);
            store.0.borrow_mut().fault = Fault::None;
            a.unlock(&prf(1), "a").await.unwrap();
            if matches!(fault, Fault::After) {
                let receipt = a.pending_output().await.unwrap().unwrap();
                guard.publish(&receipt);
                assert_ne!(rotation(&receipt).lineage.root, previous.root);
                assert_eq!(a.pending_output().await.unwrap(), Some(receipt.clone()));
                a.lock();
                a.unlock(&prf(1), "a").await.unwrap();
                assert_eq!(a.pending_output().await.unwrap(), Some(receipt.clone()));
                a.acknowledge(receipt.operation).await.unwrap();
                a.acknowledge(receipt.operation).await.unwrap();
            } else {
                assert_eq!(a.lineage().await.unwrap(), previous);
                assert!(a.pending_output().await.unwrap().is_none());
            }
        }
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn cancelled_write_before_or_after_commit_can_only_reconcile() {
    block_on(async {
        use std::future::Future;
        use std::task::{Context, Poll};
        for fault in [Fault::CancelBefore, Fault::CancelAfter] {
            let store = Memory::default();
            let time = Time::default();
            let guard = Guard::default();
            let mut a = machine(&store, &time, &guard, 18);
            let mut b = machine(&store, &time, &guard, 19);
            create(&mut a, &guard, &prf(1), &binding("a")).await;
            let grant = pair(&mut a, &mut b, &guard, &prf(2)).await;
            let previous = a.lineage().await.unwrap();
            prepare(&mut a, grant.request.device).await;
            store.0.borrow_mut().fault = fault;
            {
                let mut pending = Box::pin(a.commit());
                assert!(matches!(
                    pending
                        .as_mut()
                        .poll(&mut Context::from_waker(futures::task::noop_waker_ref())),
                    Poll::Pending
                ));
            }
            assert_eq!(a.state(), State::Reconcile);
            store.0.borrow_mut().fault = Fault::None;
            a.unlock(&prf(1), "a").await.unwrap();
            if matches!(fault, Fault::CancelAfter) {
                let output = a.pending_output().await.unwrap().unwrap();
                rotation(&output).verify(&previous).unwrap();
                guard.publish(&output);
                a.acknowledge(output.operation).await.unwrap();
            } else {
                assert_eq!(a.lineage().await.unwrap(), previous);
            }
        }
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn corrupted_swapped_or_unavailable_storage_never_unlocks_or_signs() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 20);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        let location = passkey::vault_location(&prf(1), "a").unwrap();
        let good = store.0.borrow().records[&location].clone();
        let key = a.key(purpose(Scope::Device, "x")).await.unwrap();
        store.0.borrow_mut().read_failure = true;
        assert_eq!(a.sign(&key, b"x").await, Err(Error::Unavailable));
        assert_eq!(a.state(), State::Locked);
        store.0.borrow_mut().read_failure = false;
        let wrong_location = passkey::vault_location(&prf(2), "a").unwrap();
        store
            .0
            .borrow_mut()
            .records
            .insert(wrong_location, good.clone());
        assert!(a.unlock(&prf(2), "a").await.is_err());
        let mut bad = good.clone();
        *bad.last_mut().unwrap() ^= 1;
        store.0.borrow_mut().records.insert(location, bad);
        assert!(a.unlock(&prf(1), "a").await.is_err());
        assert_eq!(a.state(), State::Locked);
        for size in [0, 1, 20, good.len() - 1] {
            store
                .0
                .borrow_mut()
                .records
                .insert(location, good[..size].into());
            assert!(a.unlock(&prf(1), "a").await.is_err());
        }
        store
            .0
            .borrow_mut()
            .records
            .insert(location, vec![0; MAX_CHECKPOINT_BYTES + 1]);
        assert_eq!(a.unlock(&prf(1), "a").await, Err(Error::Limit));
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn stale_writer_and_rollback_are_refused() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 21);
        let mut b = machine(&store, &time, &guard, 22);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        let grant = pair(&mut a, &mut b, &guard, &prf(2)).await;
        let location = passkey::vault_location(&prf(1), "a").unwrap();
        let old_blob = store.0.borrow().records[&location].clone();
        let mut stale = machine(&store, &time, &guard, 23);
        stale.unlock(&prf(1), "a").await.unwrap();
        let key = stale.key(purpose(Scope::Device, "x")).await.unwrap();
        prepare(&mut a, grant.request.device).await;
        let receipt = a.commit().await.unwrap().unwrap();
        guard.publish(&receipt);
        a.acknowledge(receipt.operation).await.unwrap();
        assert_eq!(stale.sign(&key, b"stale").await, Err(Error::Reconcile));
        // Even if a broken store rolls the ciphertext back, current external authority
        // refuses the old root epoch; no fresh purpose handle can be minted.
        store.0.borrow_mut().records.insert(location, old_blob);
        stale.unlock(&prf(1), "a").await.unwrap();
        assert!(stale.key(purpose(Scope::Device, "x")).await.is_err());
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn entropy_failure_and_cancelled_preparation_preserve_stored_keys() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let random = Random::new(24);
        let fail = random.fail.clone();
        let mut a = Keys::new(store.clone(), time.clone(), random, guard.clone());
        fail.set(true);
        assert_eq!(
            a.create_scope(
                &prf(1),
                binding("a"),
                info(),
                &consent(Action::Create, &binding("a"), None, 0, None, None),
            )
            .await
            .unwrap_err(),
            Error::Randomness
        );
        assert_eq!(store.0.borrow().writes, 0);
        fail.set(false);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        let mut b = machine(&store, &time, &guard, 25);
        let grant = pair(&mut a, &mut b, &guard, &prf(2)).await;
        let previous = a.lineage().await.unwrap();
        prepare(&mut a, grant.request.device).await;
        a.cancel_prepared().unwrap();
        assert_eq!(a.lineage().await.unwrap(), previous);
        assert!(a.pending_output().await.unwrap().is_none());
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn diagnostics_and_ciphertexts_omit_private_metadata() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 26);
        let receipt = create(&mut a, &guard, &prf(1), &binding("a")).await;
        let lineage = a.lineage().await.unwrap();
        let key = a.key(purpose(Scope::Device, "x")).await.unwrap();
        let debug = format!("{a:?} {receipt:?} {lineage:?} {key:?} {:?}", info());
        for marker in [
            "pseudonym-a",
            "private-device-name",
            "private-authority-reference",
            &lineage.root.to_string(),
        ] {
            assert!(!debug.contains(marker));
            for value in store.0.borrow().records.values() {
                assert!(!String::from_utf8_lossy(value).contains(marker));
            }
        }
        let public = serde_json::to_string(&receipt).unwrap();
        assert!(!public.contains("private-device-name"));
        assert!(!public.contains("private-authority-reference"));
        assert_eq!(a.device_info().await.unwrap(), info());
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn parsers_are_bounded_and_validate_deserialized_purposes() {
    for label in ["", "slash/label", "space here", "ümlaut", &"x".repeat(65)] {
        assert!(Purpose::new(Scope::Device, label, 0).is_err());
        let json = serde_json::json!({"scope":"device", "label":label, "version":0});
        assert!(serde_json::from_value::<Purpose>(json).is_err());
    }
    assert!(
        Purpose::new(Scope::Device, "x", u32::MAX)
            .unwrap()
            .next_version()
            .is_err()
    );
    assert!(serde_json::from_str::<Binding>(r#"{"community":"","member":"x"}"#).is_err());
    assert!(DeviceInfo::new("", &[]).is_err());
    assert!(passkey::PrfOutput::from_bytes(&[0; 31]).is_err());
    for text in [
        "VLD0".to_string(),
        "VLD0:AAAA".into(),
        format!("VLD0:{}", "A".repeat(1_000_000)),
    ] {
        assert!(text.parse::<PublicKey>().is_err());
    }
    let weak = PublicKey::new(VLD0, [0; 32]);
    assert!(validate_public_key(&weak).is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn prf_derivation_separates_store_wrap_location_and_communities() {
    let p = prf(27);
    let a = passkey::vault_location(&p, "a").unwrap();
    assert_eq!(a, passkey::vault_location(&p, "a").unwrap());
    assert_ne!(a, passkey::vault_location(&p, "b").unwrap());
    assert_ne!(a, passkey::vault_location(&prf(28), "a").unwrap());
    let wrap = passkey::store_cipher(&p, "a").unwrap();
    let sealed = wrap
        .seal(
            &mut Random::new(27),
            b"cwst-device-key",
            b"synthetic-storage-secret",
        )
        .unwrap();
    assert_eq!(
        &*wrap.open(b"cwst-device-key", &sealed).unwrap(),
        b"synthetic-storage-secret"
    );
    assert!(wrap.open(b"wrong-context", &sealed).is_err());
    assert!(
        passkey::store_cipher(&p, "b")
            .unwrap()
            .open(b"cwst-device-key", &sealed)
            .is_err()
    );
    assert!(passkey::vault_location(&p, "").is_err());
}

fn restore_consent(anchor: &Lineage) -> Vec<u8> {
    consent(
        Action::Restore,
        &anchor.binding,
        Some(anchor.root),
        anchor.epoch,
        None,
        Some(anchor.digest().unwrap()),
    )
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn lost_vault_rederives_the_exact_identity_device_and_member_keys() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut old = machine(&store, &time, &guard, 30);
        create(&mut old, &guard, &prf(1), &binding("a")).await;
        let lineage = old.lineage().await.unwrap();
        let member = old.key(purpose(Scope::Member, "records")).await.unwrap();
        let device = old.key(purpose(Scope::Device, "mls")).await.unwrap();
        let old_ciphertext = old
            .seal(&member, b"record", b"existing-data")
            .await
            .unwrap();
        // No ciphertext checkpoint, no device metadata, a different entropy source.
        let empty = Memory::default();
        let mut phone = machine(&empty, &time, &guard, 31);
        assert_eq!(
            phone.unlock(&prf(1), "a").await,
            Err(Error::MissingCheckpoint)
        );
        // Registering an existing member is forbidden even though storage is empty.
        assert_eq!(
            phone
                .create_scope(
                    &prf(1),
                    binding("a"),
                    info(),
                    &consent(Action::Create, &binding("a"), None, 0, None, None)
                )
                .await
                .unwrap_err(),
            Error::Unauthorized
        );
        let receipt = phone
            .restore_scope(
                &prf(1),
                &lineage,
                RestoreRoot::Derived,
                info(),
                &restore_consent(&lineage),
            )
            .await
            .unwrap();
        assert!(matches!(receipt.change, Change::Restored(_)));
        phone.acknowledge(receipt.operation).await.unwrap();
        assert_eq!(phone.lineage().await.unwrap(), lineage);
        let restored_member = phone.key(purpose(Scope::Member, "records")).await.unwrap();
        let restored_device = phone.key(purpose(Scope::Device, "mls")).await.unwrap();
        assert_eq!(member.certificate(), restored_member.certificate());
        assert_eq!(device.certificate(), restored_device.certificate());
        assert_eq!(
            &*phone
                .open(&restored_member, b"record", &old_ciphertext)
                .await
                .unwrap(),
            b"existing-data"
        );
        let sig = phone
            .sign(&restored_member, b"same-membership")
            .await
            .unwrap();
        verify(&member.certificate().key, b"same-membership", &sig).unwrap();
        phone.lock();
        assert_eq!(
            phone
                .restore_scope(
                    &prf(1),
                    &lineage,
                    RestoreRoot::Derived,
                    info(),
                    &restore_consent(&lineage)
                )
                .await
                .unwrap_err(),
            Error::RootExists
        );
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn restore_refuses_unavailable_wrong_prf_forged_authority_and_stale_revision() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 32);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        let old = a.lineage().await.unwrap();
        let empty = Memory::default();
        let mut phone = machine(&empty, &time, &guard, 33);
        empty.0.borrow_mut().read_failure = true;
        assert_eq!(phone.unlock(&prf(1), "a").await, Err(Error::Unavailable));
        assert_eq!(phone.state(), State::Locked);
        assert_eq!(
            phone
                .restore_scope(
                    &prf(1),
                    &old,
                    RestoreRoot::Derived,
                    info(),
                    &restore_consent(&old)
                )
                .await
                .unwrap_err(),
            Error::Unavailable
        );
        assert_eq!(
            phone
                .create_scope(&prf(1), binding("a"), info(), &[])
                .await
                .unwrap_err(),
            Error::Unavailable
        );
        empty.0.borrow_mut().read_failure = false;
        assert_eq!(
            phone
                .restore_scope(
                    &prf(2),
                    &old,
                    RestoreRoot::Derived,
                    info(),
                    &restore_consent(&old)
                )
                .await
                .unwrap_err(),
            Error::Unauthorized
        );
        assert_eq!(
            phone
                .restore_scope(&prf(1), &old, RestoreRoot::Derived, info(), &[])
                .await
                .unwrap_err(),
            Error::Unauthorized
        );
        let mut b = machine(&store, &time, &guard, 34);
        pair(&mut a, &mut b, &guard, &prf(2)).await;
        // Same root and epoch, but an older device set cannot be restored.
        assert_eq!(
            phone
                .restore_scope(
                    &prf(1),
                    &old,
                    RestoreRoot::Derived,
                    info(),
                    &restore_consent(&old)
                )
                .await
                .unwrap_err(),
            Error::Unauthorized
        );
        assert_eq!(empty.0.borrow().writes, 0);
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn paired_and_rotated_custody_restore_from_prf_and_authenticated_transfers() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 35);
        let mut b = machine(&store, &time, &guard, 36);
        let mut c = machine(&store, &time, &guard, 37);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        let grant = pair(&mut a, &mut b, &guard, &prf(2)).await;
        let anchor = a.lineage().await.unwrap();
        time.0.set(1400); // The original pairing challenge has expired.
        let empty = Memory::default();
        let mut phone = machine(&empty, &time, &guard, 38);
        assert_eq!(
            phone
                .restore_scope(
                    &prf(2),
                    &anchor,
                    RestoreRoot::Derived,
                    info(),
                    &restore_consent(&anchor)
                )
                .await
                .unwrap_err(),
            Error::Unauthorized
        );
        let mut damaged = grant.clone();
        damaged.sealed_root[40] ^= 1;
        assert!(
            phone
                .restore_scope(
                    &prf(2),
                    &anchor,
                    RestoreRoot::Paired(&damaged),
                    info(),
                    &restore_consent(&anchor)
                )
                .await
                .is_err()
        );
        let receipt = phone
            .restore_scope(
                &prf(2),
                &anchor,
                RestoreRoot::Paired(&grant),
                info(),
                &restore_consent(&anchor),
            )
            .await
            .unwrap();
        phone.acknowledge(receipt.operation).await.unwrap();
        assert_eq!(phone.lineage().await.unwrap(), anchor);
        let third = pair(&mut a, &mut c, &guard, &prf(3)).await;
        prepare(&mut a, third.request.device).await;
        let receipt = a.commit().await.unwrap().unwrap();
        guard.publish(&receipt);
        a.acknowledge(receipt.operation).await.unwrap();
        let rotation = rotation(&receipt);
        let anchor = &rotation.lineage;
        // The rotating credential regenerates the current root without a transfer.
        let mut owner = machine(&Memory::default(), &time, &guard, 39);
        let restored = owner
            .restore_scope(
                &prf(1),
                anchor,
                RestoreRoot::Derived,
                info(),
                &restore_consent(anchor),
            )
            .await
            .unwrap();
        owner.acknowledge(restored.operation).await.unwrap();
        assert_eq!(owner.lineage().await.unwrap(), *anchor);
        // Another surviving credential uses its retained epoch envelope.
        let empty = Memory::default();
        let mut survivor = machine(&empty, &time, &guard, 40);
        let restored = survivor
            .restore_scope(
                &prf(2),
                anchor,
                RestoreRoot::Rotated(rotation),
                info(),
                &restore_consent(anchor),
            )
            .await
            .unwrap();
        survivor.acknowledge(restored.operation).await.unwrap();
        assert_eq!(survivor.lineage().await.unwrap(), *anchor);
        let mut removed = machine(&Memory::default(), &time, &guard, 41);
        assert_eq!(
            removed
                .restore_scope(
                    &prf(3),
                    anchor,
                    RestoreRoot::Rotated(rotation),
                    info(),
                    &restore_consent(anchor)
                )
                .await
                .unwrap_err(),
            Error::Unauthorized
        );
        assert_eq!(
            removed
                .restore_scope(
                    &prf(3),
                    &third.lineage,
                    RestoreRoot::Paired(&third),
                    info(),
                    &restore_consent(&third.lineage)
                )
                .await
                .unwrap_err(),
            Error::Unauthorized
        );
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn lost_restore_reply_replays_the_same_committed_receipt() {
    block_on(async {
        let time = Time::default();
        let guard = Guard::default();
        let mut old = machine(&Memory::default(), &time, &guard, 42);
        create(&mut old, &guard, &prf(1), &binding("a")).await;
        let anchor = old.lineage().await.unwrap();
        let store = Memory::default();
        store.0.borrow_mut().fault = Fault::After;
        let mut phone = machine(&store, &time, &guard, 43);
        assert_eq!(
            phone
                .restore_scope(
                    &prf(1),
                    &anchor,
                    RestoreRoot::Derived,
                    info(),
                    &restore_consent(&anchor)
                )
                .await
                .unwrap_err(),
            Error::Reconcile
        );
        store.0.borrow_mut().fault = Fault::None;
        phone.unlock(&prf(1), "a").await.unwrap();
        let receipt = phone.pending_output().await.unwrap().unwrap();
        assert_eq!(receipt.change, Change::Restored(anchor));
        phone.lock();
        phone.unlock(&prf(1), "a").await.unwrap();
        assert_eq!(phone.pending_output().await.unwrap(), Some(receipt));
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn renew_pairing_and_private_rename_keep_device_identity() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 44);
        let mut b = machine(&store, &time, &guard, 45);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        let anchor = a.lineage().await.unwrap();
        let first = request(&mut b, &prf(2), &anchor).await;
        let approval = consent(
            Action::RequestPairing,
            &anchor.binding,
            Some(anchor.root),
            anchor.epoch,
            None,
            Some(anchor.digest().unwrap()),
        );
        assert_eq!(
            b.renew_pairing(&anchor, &approval).await.unwrap_err(),
            Error::Unauthorized
        );
        time.0.set(first.expires_at);
        let renewed = b.renew_pairing(&anchor, &approval).await.unwrap();
        b.acknowledge(renewed.operation).await.unwrap();
        let Change::PairingRequested(second) = renewed.change else {
            panic!()
        };
        assert_eq!(first.device, second.device);
        assert_ne!(first.nonce, second.nonce);
        let grant = grant(&mut a, &guard, &second).await;
        accept(&mut b, &grant).await;
        let before = b.lineage().await.unwrap();
        b.rename_device("new-private-name").await.unwrap();
        assert_eq!(b.lineage().await.unwrap(), before);
        assert_eq!(b.device_info().await.unwrap().name(), "new-private-name");
        assert_eq!(
            b.device_info().await.unwrap().authority_reference(),
            info().authority_reference()
        );
        assert!(b.rename_device("").await.is_err());
        b.lock();
        b.unlock(&prf(2), "a").await.unwrap();
        assert_eq!(b.device_info().await.unwrap().name(), "new-private-name");
    });
}

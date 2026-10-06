//! Original Keys/Envelope crypto and durable checkpoints, with test-only lineage
//! fixtures. These vectors do not claim production active-passkey G3.
#![cfg(feature = "profile-envelope")]
mod support;
use ckmg::{envelope as cnvl, *};
use futures::executor::block_on;
use support::*;
#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);
fn context() -> cnvl::Context {
    cnvl::Context {
        community: "a".into(),
        owner: "pseudonym-a".into(),
        profile_revision: 1,
        schema_revision: 1,
        key_generation: 1,
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn common_root_profile_custody_restores_under_an_equal_paired_passkey() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 91);
        let mut b = machine(&store, &time, &guard, 92);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        let (envelope, wrapped) = a
            .with_profile_custody(|signer, custody| {
                assert_eq!(signer.hpke_public_key().unwrap(), custody.public_key());
                let (envelope, key) = custody.seal(context(), b"original packed profile").unwrap();
                (envelope, key.wrap().unwrap())
            })
            .await
            .unwrap();
        pair(&mut a, &mut b, &guard, &prf(2)).await;
        for keys in [&mut a, &mut b] {
            keys.with_profile_custody(|_, custody| {
                let key = custody.restore(context(), &wrapped).unwrap();
                assert_eq!(
                    cnvl::open(&envelope, &key, &context()).unwrap().as_slice(),
                    b"original packed profile"
                );
            })
            .await
            .unwrap();
        }
        b.lock();
        assert!(b.with_profile_custody(|_, _| ()).await.is_err());
        b.unlock(&prf(2), "a").await.unwrap();
        b.with_profile_custody(|_, custody| {
            custody.restore(context(), &wrapped).unwrap();
        })
        .await
        .unwrap();
        let unrelated_store = Memory::default();
        let unrelated_guard = Guard::default();
        let mut unrelated = machine(&unrelated_store, &time, &unrelated_guard, 93);
        create(&mut unrelated, &unrelated_guard, &prf(3), &binding("a")).await;
        unrelated
            .with_profile_custody(|_, custody| {
                assert!(custody.restore(context(), &wrapped).is_err());
            })
            .await
            .unwrap();
        let mut damaged = wrapped.as_bytes().to_vec();
        damaged[25] ^= 1;
        let damaged = cnvl::WrappedReadKey::from_bytes(&damaged).unwrap();
        b.with_profile_custody(|_, custody| {
            assert!(custody.restore(context(), &damaged).is_err());
            let mut changed = context();
            changed.profile_revision += 1;
            assert!(custody.restore(changed, &wrapped).is_err());
        })
        .await
        .unwrap();
        guard.0.borrow_mut().get_mut("a").unwrap().devices.clear();
        assert!(b.with_profile_custody(|_, _| ()).await.is_err());
    });
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn original_store_cipher_wrapping_migrates_without_a_plaintext_api() {
    use chacha20poly1305::{
        XChaCha20Poly1305, XNonce,
        aead::{Aead, KeyInit, Payload},
    };
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut keys = machine(&store, &time, &guard, 94);
        create(&mut keys, &guard, &prf(1), &binding("a")).await;
        let legacy = passkey::store_cipher(&prf(1), "a").unwrap();
        // Exact pre-migration public wire, generated only with test-owned material.
        let aad = serde_json::to_vec(&("cnvl.profile.v1", "VLD0", context())).unwrap();
        let original_profile_key = [55; 32];
        let wrapped = legacy
            .seal(&mut SystemEntropy, &aad, &original_profile_key)
            .unwrap();
        let nonce = [9; 24];
        let ciphertext = XChaCha20Poly1305::new(&original_profile_key.into())
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: b"retained legacy content",
                    aad: &aad,
                },
            )
            .unwrap();
        let wire = serde_json::to_vec(&serde_json::json!({"version":1,"context":context(),"nonce":nonce,"ciphertext":ciphertext})).unwrap();
        let envelope = cnvl::Envelope::from_bytes(&wire).unwrap();
        let migrated = keys
            .migrate_profile_key(&legacy, context(), &wrapped)
            .await
            .unwrap();
        keys.with_profile_custody(|_, custody| {
            let reader = custody.restore(context(), &migrated).unwrap();
            assert_eq!(
                cnvl::open(&envelope, &reader, &context())
                    .unwrap()
                    .as_slice(),
                b"retained legacy content"
            );
        })
        .await
        .unwrap();
        let wrong = passkey::store_cipher(&prf(2), "a").unwrap();
        assert!(
            keys.migrate_profile_key(&wrong, context(), &wrapped)
                .await
                .is_err()
        );
        assert!(
            keys.migrate_profile_key(&legacy, context(), b"truncated")
                .await
                .is_err()
        );
    });
}

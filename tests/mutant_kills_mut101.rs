//! Boundary and state-machine pins for `ckmg/src/keys.rs` (lane mut101).
//! Each test fails under the corresponding cargo-mutants mutant while
//! passing on the real code. Product code is untouched.
mod support;
use ckmg::*;
use futures::executor::block_on;
use support::*;

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

fn restore_consent_for(anchor: &Lineage) -> Vec<u8> {
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
fn operation_id_as_bytes_matches_committed_bytes() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 101);
        let receipt = create(&mut a, &guard, &prf(1), &binding("a")).await;
        let value = serde_json::to_value(&receipt.operation).unwrap();
        let expected: Vec<u8> = value
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect();
        assert_eq!(&receipt.operation.as_bytes()[..], &expected[..]);
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn ed25519_signer_accepts_exact_max_transcript() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 102);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        let handle = a.key(purpose(Scope::Device, "mls")).await.unwrap();
        let public = *handle.certificate().key.value();
        let message = vec![0u8; MAX_MESSAGE_BYTES];
        let signature = a
            .with_ed25519_signer(&handle, |signer| {
                assert_eq!(signer.public_key(), &public);
                signer.sign(&message).unwrap()
            })
            .await
            .unwrap();
        verify_ed25519(&public, &message, &signature).unwrap();
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn vld0_signer_accepts_exact_max_message() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 103);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        let handle = a.key(purpose(Scope::Device, "mls")).await.unwrap();
        let public = *handle.certificate().key.value();
        let message = vec![0u8; MAX_MESSAGE_BYTES];
        let signature = a
            .with_vld0_signer(&handle, |signer| {
                assert_eq!(signer.public_key(), &public);
                signer.sign(&message).unwrap()
            })
            .await
            .unwrap();
        verify(
            &PublicKey::new(VLD0, public),
            &message,
            &Signature::new(VLD0, signature),
        )
        .unwrap();
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn debug_format_names_state() {
    let store = Memory::default();
    let time = Time::default();
    let guard = Guard::default();
    let a = machine(&store, &time, &guard, 104);
    let debug = format!("{a:?}");
    assert!(debug.contains("Keys"), "{debug}");
    assert!(debug.contains("Locked"), "{debug}");
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn authorize_device_evidence_is_bounded_above() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 105);
        let mut b = machine(&store, &time, &guard, 106);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        let anchor = a.lineage().await.unwrap();
        let request = request(&mut b, &prf(2), &anchor).await;
        assert_eq!(
            a.authorize_device(&request, &vec![0; 4097])
                .await
                .unwrap_err(),
            Error::Limit
        );
        assert_eq!(
            a.authorize_device(&request, &vec![0; 4096])
                .await
                .unwrap_err(),
            Error::Unauthorized
        );
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn create_scope_evidence_is_bounded_above() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut keys = machine(&store, &time, &guard, 107);
        assert_eq!(
            keys.create_scope(&prf(1), binding("zz"), info(), &vec![0; 4097])
                .await
                .unwrap_err(),
            Error::Limit
        );
        assert_eq!(
            keys.create_scope(&prf(1), binding("zz"), info(), &vec![0; 4096])
                .await
                .unwrap_err(),
            Error::Unauthorized
        );
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn unlock_checkpoint_bytes_are_bounded_above() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut keys = machine(&store, &time, &guard, 108);
        let location = passkey::vault_location(&prf(1), "a").unwrap();
        store
            .0
            .borrow_mut()
            .records
            .insert(location, vec![0; MAX_CHECKPOINT_BYTES]);
        assert_eq!(
            keys.unlock(&prf(1), "a").await.unwrap_err(),
            Error::Encoding
        );
        store
            .0
            .borrow_mut()
            .records
            .insert(location, vec![0; MAX_CHECKPOINT_BYTES + 1]);
        assert_eq!(keys.unlock(&prf(1), "a").await.unwrap_err(), Error::Limit);
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn restore_checkpoint_bytes_are_bounded_above() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 109);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        let anchor = a.lineage().await.unwrap();
        let empty = Memory::default();
        let mut phone = machine(&empty, &time, &guard, 110);
        let exact = vec![0u8; MAX_CHECKPOINT_BYTES];
        assert_eq!(
            phone
                .restore_scope(
                    &prf(1),
                    &anchor,
                    RestoreRoot::Checkpoint(&exact),
                    info(),
                    &restore_consent_for(&anchor),
                )
                .await
                .unwrap_err(),
            Error::Encoding
        );
        let over = vec![0u8; MAX_CHECKPOINT_BYTES + 1];
        assert_eq!(
            phone
                .restore_scope(
                    &prf(1),
                    &anchor,
                    RestoreRoot::Checkpoint(&over),
                    info(),
                    &restore_consent_for(&anchor),
                )
                .await
                .unwrap_err(),
            Error::Limit
        );
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn restore_with_older_checkpoint_and_advanced_clock_succeeds() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 111);
        let mut b = machine(&store, &time, &guard, 112);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        let retained = a.retained_checkpoint().await.unwrap();
        pair(&mut a, &mut b, &guard, &prf(2)).await;
        let anchor = a.lineage().await.unwrap();
        time.0.set(1500);
        let empty = Memory::default();
        let mut phone = machine(&empty, &time, &guard, 113);
        let receipt = phone
            .restore_scope(
                &prf(1),
                &anchor,
                RestoreRoot::Checkpoint(&retained),
                info(),
                &restore_consent_for(&anchor),
            )
            .await
            .unwrap();
        phone.acknowledge(receipt.operation).await.unwrap();
        assert_eq!(phone.lineage().await.unwrap(), anchor);
    });
}

struct AllowAll;
impl Authority for AllowAll {
    async fn check(&mut self, _request: Authorization<'_>) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn restore_with_newer_checkpoint_than_anchor_is_refused() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 114);
        let mut b = machine(&store, &time, &guard, 115);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        let stale = a.lineage().await.unwrap();
        pair(&mut a, &mut b, &guard, &prf(2)).await;
        let retained = a.retained_checkpoint().await.unwrap();
        let empty = Memory::default();
        let mut phone = Keys::new(empty, time.clone(), Random::new(116), AllowAll);
        assert_eq!(
            phone
                .restore_scope(
                    &prf(1),
                    &stale,
                    RestoreRoot::Checkpoint(&retained),
                    info(),
                    &[],
                )
                .await
                .unwrap_err(),
            Error::Unauthorized
        );
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn restore_paired_device_against_newer_anchor_succeeds() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 120);
        let mut b = machine(&store, &time, &guard, 121);
        let mut c = machine(&store, &time, &guard, 122);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        let grant = pair(&mut a, &mut b, &guard, &prf(2)).await;
        pair(&mut a, &mut c, &guard, &prf(3)).await;
        let anchor = a.lineage().await.unwrap();
        let empty = Memory::default();
        let mut phone = machine(&empty, &time, &guard, 123);
        let receipt = phone
            .restore_scope(
                &prf(2),
                &anchor,
                RestoreRoot::Paired(&grant),
                info(),
                &restore_consent_for(&anchor),
            )
            .await
            .unwrap();
        phone.acknowledge(receipt.operation).await.unwrap();
        assert_eq!(phone.lineage().await.unwrap(), anchor);
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn restore_paired_with_foreign_grant_is_refused() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 124);
        let mut b = machine(&store, &time, &guard, 125);
        let mut c = machine(&store, &time, &guard, 126);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        pair(&mut a, &mut b, &guard, &prf(2)).await;
        let foreign = pair(&mut a, &mut c, &guard, &prf(3)).await;
        let anchor = a.lineage().await.unwrap();
        let empty = Memory::default();
        let mut phone = machine(&empty, &time, &guard, 127);
        assert_eq!(
            phone
                .restore_scope(
                    &prf(2),
                    &anchor,
                    RestoreRoot::Paired(&foreign),
                    info(),
                    &restore_consent_for(&anchor),
                )
                .await
                .unwrap_err(),
            Error::Unauthorized
        );
    });
}
// Profile signer pins for `ckmg/src/keys.rs` (lane mut101). Each test
// fails under the corresponding cargo-mutants mutant while passing on the
// real code. Product code is untouched.
#[cfg(feature = "profile-envelope")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn profile_signer_reports_certified_device_key() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 131);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        let lineage = a.lineage().await.unwrap();
        let expected = lineage.devices[0];
        a.with_profile_custody(|signer, _| {
            assert_eq!(signer.public_key(), expected.value());
        })
        .await
        .unwrap();
    });
}

#[cfg(feature = "profile-envelope")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn profile_hpke_key_matches_custody() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 132);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        a.with_profile_custody(|signer, custody| {
            assert_eq!(signer.hpke_public_key(), custody.public_key());
        })
        .await
        .unwrap();
    });
}

#[cfg(feature = "profile-envelope")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn profile_certificate_verifies_against_lineage() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 133);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        let lineage = a.lineage().await.unwrap();
        a.with_profile_custody(|signer, _| {
            let certificate = signer.hpke_certificate();
            certificate.verify(&lineage, &certificate.purpose).unwrap();
        })
        .await
        .unwrap();
    });
}

#[cfg(feature = "profile-envelope")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn profile_sign_verifies_with_device_key() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 134);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        a.with_profile_custody(|signer, _| {
            let transcript = [b"cpfl:publication:v1\0".as_slice(), b"mut101".as_slice()].concat();
            let signature = signer.sign(&transcript).unwrap();
            assert_ne!(signature, [0; 64]);
            assert_ne!(signature, [1; 64]);
            verify_ed25519(signer.public_key(), &transcript, &signature).unwrap();
            assert_eq!(signer.sign(b"wrong-tag").unwrap_err(), Error::Unauthorized);
        })
        .await
        .unwrap();
    });
}

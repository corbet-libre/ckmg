//! Original Keys-produced signatures only; no peer authority or freshness claim.
mod support;
use ckmg::*;
use futures::executor::block_on;
use support::*;

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn original_device_certificate_requires_all_independent_expectations_and_signed_fields() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 31);
        let mut b = machine(&store, &time, &guard, 32);
        let expected_binding = binding("a");
        let expected_purpose = purpose(Scope::Device, "profile");
        create(&mut a, &guard, &prf(1), &expected_binding).await;
        let paired = pair(&mut a, &mut b, &guard, &prf(2)).await;
        let expected_device = a.device_public_key().await.unwrap();
        let certificate = a
            .key(expected_purpose.clone())
            .await
            .unwrap()
            .certificate()
            .clone();
        assert_eq!(certificate.device, expected_device);
        certificate
            .verify_device_certificate(&expected_binding, &expected_purpose, &expected_device)
            .unwrap();
        certificate
            .verify(&a.lineage().await.unwrap(), &expected_purpose)
            .unwrap();
        // Expected values are fixed from the real setup/approved pairing, not
        // copied from a hostile certificate while executing verification.
        for wrong in [
            Binding::new("another", expected_binding.member()).unwrap(),
            Binding::new("a", "another-pseudonym").unwrap(),
        ] {
            assert_eq!(
                certificate.verify_device_certificate(&wrong, &expected_purpose, &expected_device),
                Err(Error::Unauthorized)
            );
        }
        for wrong in [
            purpose(Scope::Member, "profile"),
            purpose(Scope::Device, "other"),
            expected_purpose.next_version().unwrap(),
        ] {
            assert_eq!(
                certificate.verify_device_certificate(&expected_binding, &wrong, &expected_device),
                Err(Error::Unauthorized)
            );
        }
        assert_eq!(
            certificate.verify_device_certificate(
                &expected_binding,
                &expected_purpose,
                &paired.request.device
            ),
            Err(Error::Unauthorized)
        );
        let mut zero = certificate.clone();
        zero.epoch = 0;
        assert_eq!(
            zero.verify_device_certificate(&expected_binding, &expected_purpose, &expected_device),
            Err(Error::Unauthorized)
        );
        let mut changed_epoch = certificate.clone();
        changed_epoch.epoch += 1;
        assert!(
            changed_epoch
                .verify_device_certificate(&expected_binding, &expected_purpose, &expected_device)
                .is_err()
        );
        let mut changed_key = certificate.clone();
        changed_key.key = a
            .key(purpose(Scope::Device, "other"))
            .await
            .unwrap()
            .certificate()
            .key;
        assert!(
            changed_key
                .verify_device_certificate(&expected_binding, &expected_purpose, &expected_device)
                .is_err()
        );
        let mut changed_signature = certificate.clone();
        let mut signature = *changed_signature.signature.value();
        signature[0] ^= 1;
        changed_signature.signature = Signature::new(VLD0, signature);
        assert!(
            changed_signature
                .verify_device_certificate(&expected_binding, &expected_purpose, &expected_device)
                .is_err()
        );
        let mut wrong_kind = certificate;
        wrong_kind.signature = Signature::new(CryptoKind(*b"BAD!"), *wrong_kind.signature.value());
        assert!(
            wrong_kind
                .verify_device_certificate(&expected_binding, &expected_purpose, &expected_device)
                .is_err()
        );
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn certificate_signature_alone_never_replaces_current_full_lineage_after_real_rotation() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 41);
        let mut b = machine(&store, &time, &guard, 42);
        let expected_binding = binding("a");
        let expected_purpose = purpose(Scope::Device, "profile");
        create(&mut a, &guard, &prf(1), &expected_binding).await;
        let paired = pair(&mut a, &mut b, &guard, &prf(2)).await;
        let expected_device = a.device_public_key().await.unwrap();
        let previous = a.lineage().await.unwrap();
        let old = a
            .key(expected_purpose.clone())
            .await
            .unwrap()
            .certificate()
            .clone();
        old.verify(&previous, &expected_purpose).unwrap();
        prepare(&mut a, paired.request.device).await;
        let receipt = a.commit().await.unwrap().unwrap();
        rotation(&receipt).verify(&previous).unwrap();
        guard.publish(&receipt);
        a.acknowledge(receipt.operation).await.unwrap();
        let current = a.lineage().await.unwrap();
        current.verify().unwrap();
        assert_eq!(current.epoch, previous.epoch + 1);
        assert_eq!(
            old.verify(&current, &expected_purpose),
            Err(Error::Unauthorized)
        );
        // The historical signature is still authentic. This separate data
        // check cannot confer currentness or invalidate the full-lineage fence.
        old.verify_device_certificate(&expected_binding, &expected_purpose, &expected_device)
            .unwrap();
        let fresh = a
            .key(expected_purpose.clone())
            .await
            .unwrap()
            .certificate()
            .clone();
        fresh.verify(&current, &expected_purpose).unwrap();
        fresh
            .verify_device_certificate(&expected_binding, &expected_purpose, &expected_device)
            .unwrap();
    });
}

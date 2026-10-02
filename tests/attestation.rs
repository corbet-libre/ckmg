//! Actual device/root signatures; current passkey/revocation policy stays external.
mod support;
use ckmg::*;
use futures::executor::block_on;
use support::*;
#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn durable_receipt_binds_original_change_and_active_device_claim() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut keys = machine(&store, &time, &guard, 83);
        let receipt = create(&mut keys, &guard, &prf(1), &binding("garden")).await;
        let (lineage, author) = receipt.attested_lineage().unwrap();
        assert!(lineage.devices.contains(&author));
        let challenge = receipt.passkey_challenge().unwrap();
        let serialized = serde_json::to_vec(&receipt).unwrap();
        let restored: Receipt = serde_json::from_slice(&serialized).unwrap();
        assert_eq!(restored.attested_lineage().unwrap().1, author);
        assert_eq!(restored.passkey_challenge().unwrap(), challenge);
        let mut legacy = receipt.clone();
        legacy.attestation = None;
        // Device-possession evidence is independent of the authenticator challenge.
        assert_eq!(legacy.passkey_challenge().unwrap(), challenge);
        assert!(matches!(
            legacy.attested_lineage(),
            Err(Error::Unauthorized)
        ));
        let mut wire = serde_json::to_value(&legacy).unwrap();
        wire.as_object_mut().unwrap().remove("attestation");
        let legacy: Receipt = serde_json::from_value(wire).unwrap();
        assert!(legacy.attested_lineage().is_err());
        for field in ["revision", "epoch"] {
            let mut changed = receipt.clone();
            let Change::Created(lineage) = &mut changed.change else {
                panic!("creation")
            };
            if field == "epoch" {
                lineage.epoch += 1;
            } else {
                lineage.revision += 1;
            }
            assert!(changed.attested_lineage().is_err());
            assert_ne!(changed.passkey_challenge().unwrap(), challenge);
        }
        let mut changed = receipt.clone();
        changed.attestation.as_mut().unwrap().device = PublicKey::new(VLD0, [9; 32]);
        assert!(changed.attested_lineage().is_err());
        let mut changed = receipt.clone();
        changed.attestation.as_mut().unwrap().signature = Signature::new(VLD0, [0; 64]);
        assert!(changed.attested_lineage().is_err());
        let other_store = Memory::default();
        let other_guard = Guard::default();
        let mut other = machine(&other_store, &time, &other_guard, 84);
        let other = create(&mut other, &other_guard, &prf(2), &binding("garden")).await;
        let mut changed = receipt.clone();
        changed.operation = other.operation;
        assert!(changed.attested_lineage().is_err());
        assert_ne!(changed.passkey_challenge().unwrap(), challenge);
        let mut changed = receipt.clone();
        changed.change = other.change;
        assert!(changed.attested_lineage().is_err());
        assert_ne!(changed.passkey_challenge().unwrap(), challenge);
        // An unchanged valid signature remains evidence only; this test never
        // asserts that a server considers the passkey active or lineage latest.
        assert_eq!(receipt.attested_lineage().unwrap().1, author);
    });
}

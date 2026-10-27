//! Original accepted checkpoint bootstrap and real VLD0 record crypto.
//! The parent's strict local Use observation does not establish HTTPS/G3.
use super::*;

struct Verify;
impl cdht::Verifier for Verify {
    fn verify(&self, key: &[u8; 32], data: &[u8], signature: &[u8; 64]) -> bool {
        vld0::verify(
            &PublicKey::new(VLD0, *key),
            data,
            &Signature::new(VLD0, *signature),
        )
        .is_ok()
    }
}

fn validate(descriptor: &cdht::Descriptor, value: &cdht::SignedValue, subkey: u32) {
    let schema = descriptor.validate(&Verify).unwrap();
    value
        .validate(
            &descriptor.key(),
            &descriptor.owner,
            &schema,
            subkey,
            &Verify,
        )
        .unwrap();
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn passkey_publication_matches_original_reader_and_preserves_exact_retry() {
    let (prf, metadata, material) = fixture();
    let custody = bootstrap(&prf, &metadata, &material);
    let nonce = [17; 24];
    let packed = b"original packed recovery";
    let (descriptor, value) = custody.passkey_publication(&prf, 7, packed, nonce).unwrap();
    validate(&descriptor, &value, 0);
    assert_eq!(descriptor.schema, cdht::Schema::dflt(1).unwrap().compile());
    let reader = custody.passkey_reader(&prf).unwrap();
    assert_eq!(descriptor.owner, *reader.owner().value());
    assert_ne!(descriptor.owner, *metadata.lineage.root.value());
    assert_eq!(value.seq, 7);
    assert_eq!(value.nonce, Some(nonce));
    assert_eq!(value.writer, descriptor.owner);
    assert_ne!(value.data, packed);
    assert_eq!(
        reader
            .with_cipher(|cipher| cipher.crypt(&nonce, &value.data).unwrap())
            .as_slice(),
        packed
    );
    let (retry_descriptor, retry) = custody.passkey_publication(&prf, 7, packed, nonce).unwrap();
    assert_eq!(retry_descriptor.key(), descriptor.key());
    assert_eq!(retry_descriptor.signature, descriptor.signature);
    assert_eq!(retry.raw_blob().unwrap(), value.raw_blob().unwrap());
    assert_eq!(retry.signature, value.signature);

    let schema = descriptor.validate(&Verify).unwrap();
    let mut altered = value.clone();
    altered.nonce = Some([18; 24]);
    assert!(
        altered
            .validate(&descriptor.key(), &descriptor.owner, &schema, 0, &Verify)
            .is_err()
    );
    altered = value.clone();
    altered.data[0] ^= 1;
    assert!(
        altered
            .validate(&descriptor.key(), &descriptor.owner, &schema, 0, &Verify)
            .is_err()
    );
    assert!(
        value
            .validate(&descriptor.key(), &descriptor.owner, &schema, 1, &Verify)
            .is_err()
    );

    let other_prf = PrfOutput::from_bytes(&[42; 32]).unwrap();
    assert!(matches!(
        custody.passkey_publication(&other_prf, 7, packed, [19; 24]),
        Err(Error::Unauthorized)
    ));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn compound_publication_uses_original_scoped_owner_cipher_and_subkey_signatures() {
    let (prf, metadata, material) = fixture();
    let custody = bootstrap(&prf, &metadata, &material);
    let record = custody.record(None).unwrap();
    for (subkey, nonce, packed) in [
        (0, [21; 24], b"part zero".as_slice()),
        (31, [22; 24], b"part last".as_slice()),
    ] {
        let (descriptor, value) = record.publication(subkey, 9, packed, nonce).unwrap();
        validate(&descriptor, &value, subkey);
        assert_eq!(descriptor.schema, cdht::Schema::dflt(32).unwrap().compile());
        assert_eq!(
            descriptor.owner,
            *original_owner(&prf, &metadata, &material, "vault.checkpoint").value()
        );
        assert_eq!(descriptor.owner, *record.public_key().value());
        assert_eq!(
            record
                .with_record(|_, cipher| cipher.crypt(&nonce, &value.data))
                .unwrap()
                .as_slice(),
            packed
        );
        let schema = descriptor.validate(&Verify).unwrap();
        assert!(
            value
                .validate(
                    &descriptor.key(),
                    &descriptor.owner,
                    &schema,
                    subkey ^ 1,
                    &Verify
                )
                .is_err()
        );
        let child = custody.record(Some(0)).unwrap();
        assert_ne!(child.public_key(), record.public_key());
        assert_ne!(
            child
                .with_record(|_, cipher| cipher.crypt(&nonce, &value.data))
                .unwrap()
                .as_slice(),
            packed
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn fixed_publication_refuses_original_schema_sequence_and_payload_limits() {
    let (prf, metadata, material) = fixture();
    let custody = bootstrap(&prf, &metadata, &material);
    let record = custody.record(None).unwrap();
    assert!(matches!(
        record.publication(32, 0, b"bounded", [30; 24]),
        Err(Error::Limit)
    ));
    assert!(matches!(
        record.publication(0, cdht::MAX_SEQ + 1, b"bounded", [31; 24]),
        Err(Error::Limit)
    ));
    assert!(matches!(
        custody.passkey_publication(&prf, cdht::MAX_SEQ + 1, b"bounded", [32; 24]),
        Err(Error::Limit)
    ));
    for packed in [Vec::new(), vec![0; cdht::MAX_SUBKEY_SIZE + 1]] {
        assert!(matches!(
            record.publication(0, 0, &packed, [33; 24]),
            Err(Error::Limit)
        ));
        assert!(matches!(
            custody.passkey_publication(&prf, 0, &packed, [34; 24]),
            Err(Error::Limit)
        ));
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn fixed_accepts_exact_schema_sequence_and_payload_bounds() {
    let (prf, metadata, material) = fixture();
    let custody = bootstrap(&prf, &metadata, &material);
    let record = custody.record(None).unwrap();
    let (descriptor, value) = record
        .publication(0, cdht::MAX_SEQ, b"exact bounds", [40; 24])
        .unwrap();
    assert_eq!(value.seq, cdht::MAX_SEQ);
    validate(&descriptor, &value, 0);
    let exact = vec![0xab; cdht::MAX_SUBKEY_SIZE];
    let (descriptor, value) = record.publication(31, 9, &exact, [41; 24]).unwrap();
    validate(&descriptor, &value, 31);
    assert_eq!(
        record
            .with_record(|_, cipher| cipher.crypt(&[41; 24], &value.data))
            .unwrap()
            .as_slice(),
        exact.as_slice()
    );
}

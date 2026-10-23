use super::*;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn historical_lineage_keeps_its_original_domain_and_serialized_fields() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/lineage-v1.json")).unwrap();
    let secret = crate::keyring::secret(&[7; 32]).unwrap();
    let root = fixture["root"].as_str().unwrap().parse().unwrap();
    let device = fixture["device"].as_str().unwrap().parse().unwrap();
    assert_eq!(root, vld0::public_key(&secret));
    let mut lineage = Lineage {
        version: 1,
        binding: Binding::new("historical-community", "historical-pseudonym").unwrap(),
        epoch: 1,
        revision: 1,
        root,
        identity: None,
        devices: vec![device],
        delegates: Vec::new(),
        signature: Signature::new(crate::VLD0, [0; 64]),
    };
    let expected = data_encoding::HEXLOWER
        .decode(
            fixture["signed_transcript_hex"]
                .as_str()
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
    assert_eq!(lineage.signed_bytes().unwrap(), expected);
    lineage.signature = vld0::sign(&secret, &expected).unwrap();
    lineage.verify().unwrap();
    let encoded = serde_json::to_value(&lineage).unwrap();
    assert!(encoded.get("identity").is_none());
    let decoded: Lineage = serde_json::from_value(encoded).unwrap();
    assert_eq!(decoded, lineage);
    assert_eq!(decoded.signed_bytes().unwrap(), expected);

    // A retained common root uses an explicit new version and authenticated field.
    lineage.version = 2;
    lineage.identity = Some(root);
    let current = lineage.signed_bytes().unwrap();
    assert!(current.starts_with(b"ckmg.lineage.v2\0"));
    assert_ne!(current, expected);
    assert!(lineage.verify().is_err());
    lineage.signature = vld0::sign(&secret, &current).unwrap();
    lineage.verify().unwrap();
    lineage.identity = Some(device);
    assert!(lineage.verify().is_err());
    lineage.version = 1;
    assert!(lineage.signed_bytes().is_err());
    lineage.version = 2;
    lineage.identity = None;
    assert!(lineage.signed_bytes().is_err());
}

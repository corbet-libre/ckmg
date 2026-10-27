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

// ---- focused shape/transcript tests: each surviving mutant in src/lineage.rs
// must make at least one of these fail. Key seeds use distinct high bits in
// byte 0 because ed25519 clamping clears the low three bits, so tags must
// differ above bit 2 to stay distinct keys.

fn seed_key(first: u8, second: u8) -> PublicKey {
    let mut bytes = [0u8; 32];
    bytes[0] = first;
    bytes[1] = second;
    bytes[2] = 0x5A;
    let secret = crate::keyring::secret(&bytes).unwrap();
    vld0::public_key(&secret)
}

fn sign_as(first: u8, second: u8, data: &[u8]) -> Signature {
    let mut bytes = [0u8; 32];
    bytes[0] = first;
    bytes[1] = second;
    bytes[2] = 0x5A;
    let secret = crate::keyring::secret(&bytes).unwrap();
    vld0::sign(&secret, data).unwrap()
}

fn sorted_keys(tag: u8, count: usize) -> Vec<PublicKey> {
    let mut keys: Vec<PublicKey> = (0..count).map(|i| seed_key(tag, i as u8)).collect();
    keys.sort();
    keys.dedup();
    assert_eq!(keys.len(), count);
    assert!(keys.windows(2).all(|v| v[0] < v[1]));
    keys
}

fn base_lineage() -> Lineage {
    Lineage {
        version: 1,
        binding: Binding::new("mut-community", "mut-member").unwrap(),
        epoch: 1,
        revision: 1,
        root: seed_key(0x30, 7),
        identity: None,
        devices: vec![seed_key(0x40, 3)],
        delegates: Vec::new(),
        signature: Signature::new(crate::VLD0, [0; 64]),
    }
}

fn signed_lineage(
    version: u8,
    root: (u8, u8),
    devices: Vec<PublicKey>,
    delegates: Vec<PublicKey>,
) -> Lineage {
    let root_key = seed_key(root.0, root.1);
    let mut lineage = Lineage {
        version,
        binding: Binding::new("mut-community", "mut-member").unwrap(),
        epoch: 1,
        revision: 1,
        root: root_key,
        identity: (version == 2).then_some(root_key),
        devices,
        delegates,
        signature: Signature::new(crate::VLD0, [0; 64]),
    };
    let bytes = lineage.signed_bytes().unwrap();
    lineage.signature = sign_as(root.0, root.1, &bytes);
    lineage.verify().unwrap();
    lineage
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn shape_rejects_zero_epoch_and_revision() {
    let mut lineage = base_lineage();
    lineage.epoch = 0;
    assert!(lineage.signed_bytes().is_err());
    lineage.epoch = 1;
    lineage.revision = 0;
    assert!(lineage.signed_bytes().is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn shape_rejects_empty_devices() {
    let mut lineage = base_lineage();
    lineage.devices.clear();
    assert!(lineage.signed_bytes().is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn shape_rejects_too_many_devices() {
    let mut lineage = base_lineage();
    lineage.devices = sorted_keys(0x10, MAX_DEVICES + 1);
    assert!(lineage.signed_bytes().is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn shape_rejects_unsorted_or_duplicate_devices() {
    let mut pair = vec![seed_key(0x40, 3), seed_key(0x40, 9)];
    pair.sort();
    pair.reverse();
    assert!(pair[0] > pair[1]);
    let mut lineage = base_lineage();
    lineage.devices = pair;
    assert!(lineage.signed_bytes().is_err());
    let key = seed_key(0x40, 3);
    lineage.devices = vec![key, key];
    assert!(lineage.signed_bytes().is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn shape_rejects_version_1_delegates() {
    let mut lineage = base_lineage();
    lineage.delegates = vec![seed_key(0x20, 3)];
    assert!(lineage.signed_bytes().is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn shape_rejects_too_many_delegates() {
    let mut lineage = base_lineage();
    lineage.version = 2;
    lineage.identity = Some(lineage.root);
    lineage.delegates = sorted_keys(0x20, MAX_DEVICES + 1);
    assert!(lineage.signed_bytes().is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn shape_rejects_unsorted_delegates() {
    let mut pair = vec![seed_key(0x20, 3), seed_key(0x20, 9)];
    pair.sort();
    pair.reverse();
    assert!(pair[0] > pair[1]);
    let mut lineage = base_lineage();
    lineage.version = 2;
    lineage.identity = Some(lineage.root);
    lineage.delegates = pair;
    assert!(lineage.signed_bytes().is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn shape_rejects_delegate_overlapping_devices() {
    let mut lineage = base_lineage();
    lineage.version = 2;
    lineage.identity = Some(lineage.root);
    lineage.delegates = lineage.devices.clone();
    assert!(lineage.signed_bytes().is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn shape_accepts_exactly_max_devices() {
    let lineage = signed_lineage(1, (0x30, 7), sorted_keys(0x10, MAX_DEVICES), Vec::new());
    assert_eq!(lineage.devices.len(), MAX_DEVICES);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn shape_accepts_exactly_max_delegates() {
    let lineage = signed_lineage(
        2,
        (0x30, 7),
        vec![seed_key(0x40, 3)],
        sorted_keys(0x20, MAX_DEVICES),
    );
    assert_eq!(lineage.delegates.len(), MAX_DEVICES);
}

fn valid_request() -> PairingRequest {
    PairingRequest {
        version: 1,
        binding: Binding::new("mut-community", "mut-member").unwrap(),
        root: seed_key(0x30, 7),
        epoch: 1,
        device: seed_key(0x40, 3),
        nonce: [9; 32],
        issued_at: 1_000,
        expires_at: 1_200,
        proof: Signature::new(crate::VLD0, [0; 64]),
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn request_signed_bytes_pins_domain() {
    let bytes = valid_request().signed_bytes().unwrap();
    assert!(!bytes.is_empty());
    assert!(bytes.starts_with(b"ckmg.pairing.request.v1\0"));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn request_rejects_bad_version() {
    let mut request = valid_request();
    request.version = 2;
    assert!(request.signed_bytes().is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn request_rejects_empty_or_inverted_window() {
    let mut request = valid_request();
    request.expires_at = request.issued_at;
    assert!(request.signed_bytes().is_err());
    request.expires_at = request.issued_at - 1;
    assert!(request.signed_bytes().is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn request_rejects_window_over_five_minutes() {
    let mut request = valid_request();
    request.issued_at = 0;
    request.expires_at = 301;
    assert!(request.signed_bytes().is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn request_rejects_same_root_and_device() {
    let mut request = valid_request();
    request.device = request.root;
    assert!(request.signed_bytes().is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn request_accepts_issuance_at_zero() {
    let mut request = valid_request();
    request.issued_at = 0;
    request.expires_at = 100;
    let bytes = request.signed_bytes().unwrap();
    assert!(bytes.starts_with(b"ckmg.pairing.request.v1\0"));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn request_verify_enforces_window_edges() {
    let mut request = valid_request();
    let bytes = request.signed_bytes().unwrap();
    request.proof = sign_as(0x40, 3, &bytes);
    request.verify(request.issued_at).unwrap();
    assert_eq!(
        request.verify(request.issued_at - 1).unwrap_err(),
        Error::Expired
    );
    assert_eq!(
        request.verify(request.expires_at).unwrap_err(),
        Error::Expired
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn request_digest_binds_the_proof() {
    let request = valid_request();
    let digest = request.digest().unwrap();
    assert_ne!(digest, [0; 32]);
    assert_ne!(digest, [1; 32]);
    let mut other = request.clone();
    let bytes = other.signed_bytes().unwrap();
    other.proof = sign_as(0x40, 3, &bytes);
    assert_ne!(request.digest().unwrap(), other.digest().unwrap());
}

fn valid_grant(version: u8) -> PairingGrant {
    let request = valid_request();
    let lineage = signed_lineage(1, (0x30, 7), vec![seed_key(0x40, 3)], Vec::new());
    let sealed_len = match version {
        2 => 5 + 32 + 64 + 16,
        _ => 5 + 32 + 32 + 16,
    };
    PairingGrant {
        version,
        request,
        lineage,
        sealed_root: vec![0u8; sealed_len],
        signature: Signature::new(crate::VLD0, [0; 64]),
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn grant_version_defaults_to_legacy_transfer() {
    let grant = valid_grant(1);
    let request = serde_json::to_value(&grant.request).unwrap();
    let lineage = serde_json::to_value(&grant.lineage).unwrap();
    let signature = serde_json::to_value(grant.signature).unwrap();
    let sealed_root = serde_json::to_value(&grant.sealed_root).unwrap();
    let json = serde_json::json!({
        "request": request,
        "lineage": lineage,
        "sealed_root": sealed_root,
        "signature": signature,
    });
    assert!(json.get("version").is_none());
    let decoded: PairingGrant = serde_json::from_value(json).unwrap();
    assert_eq!(decoded.version, 1);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn grant_version_omitted_only_for_legacy_transfer() {
    let encoded = serde_json::to_value(valid_grant(1)).unwrap();
    assert!(encoded.get("version").is_none());
    let encoded = serde_json::to_value(valid_grant(2)).unwrap();
    assert_eq!(encoded.get("version").and_then(|v| v.as_u64()), Some(2));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn grant_aad_pins_version_domains() {
    let aad = valid_grant(1).aad().unwrap();
    assert!(aad.starts_with(b"ckmg.pairing.root.v2\0"));
    let aad = valid_grant(2).aad().unwrap();
    assert!(aad.starts_with(b"ckmg.pairing.root.v3\0"));
    let aad = valid_grant(3).aad().unwrap();
    assert!(aad.starts_with(b"ckmg.pairing.root.v4\0"));
    assert!(valid_grant(9).aad().is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn grant_signed_bytes_pins_version_domain() {
    let bytes = valid_grant(1).signed_bytes().unwrap();
    assert!(bytes.starts_with(b"ckmg.pairing.grant.v1\0"));
    let bytes = valid_grant(2).signed_bytes().unwrap();
    assert!(bytes.starts_with(b"ckmg.pairing.grant.v2\0"));
}

fn valid_rotation(version: u8) -> Rotation {
    let mut devices = vec![seed_key(0x40, 3), seed_key(0x40, 9)];
    devices.sort();
    let lineage = signed_lineage(1, (0x30, 7), devices.clone(), Vec::new());
    let sealed_len = if version == 2 {
        5 + 32 + 64 + 16
    } else {
        5 + 32 + 32 + 16
    };
    let envelopes = devices
        .iter()
        .map(|device| RootEnvelope {
            device: *device,
            sealed_root: vec![0u8; sealed_len],
        })
        .collect();
    Rotation {
        version,
        predecessor: [5; 32],
        previous_root: seed_key(0x30, 8),
        revoked: seed_key(0x40, 11),
        lineage,
        envelopes,
        signature: Signature::new(crate::VLD0, [0; 64]),
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rotation_aad_pins_version_domains() {
    let aad = valid_rotation(1).aad(seed_key(0x40, 3)).unwrap();
    assert!(aad.starts_with(b"ckmg.rotation.root.v1\0"));
    let aad = valid_rotation(2).aad(seed_key(0x40, 3)).unwrap();
    assert!(aad.starts_with(b"ckmg.rotation.root.v2\0"));
    let aad = valid_rotation(3).aad(seed_key(0x40, 3)).unwrap();
    assert!(aad.starts_with(b"ckmg.rotation.root.v3\0"));
    assert!(valid_rotation(9).aad(seed_key(0x40, 3)).is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rotation_signed_bytes_pins_domain() {
    let bytes = valid_rotation(1).signed_bytes().unwrap();
    assert!(!bytes.is_empty());
    assert!(bytes.starts_with(b"ckmg.rotation.v1\0"));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rotation_rejects_envelope_count_mismatch() {
    let mut rotation = valid_rotation(1);
    rotation.envelopes.pop();
    assert!(rotation.signed_bytes().is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rotation_rejects_misdirected_envelope() {
    let mut rotation = valid_rotation(1);
    rotation.envelopes[1].device = seed_key(0x40, 11);
    assert!(rotation.signed_bytes().is_err());
}

fn valid_rotation_many(version: u8, count: usize) -> Rotation {
    let devices = sorted_keys(0x10, count);
    let lineage = signed_lineage(1, (0x30, 7), devices.clone(), Vec::new());
    let sealed_len = if version == 2 {
        5 + 32 + 64 + 16
    } else {
        5 + 32 + 32 + 16
    };
    let envelopes = devices
        .iter()
        .map(|device| RootEnvelope {
            device: *device,
            sealed_root: vec![0u8; sealed_len],
        })
        .collect();
    Rotation {
        version,
        predecessor: [5; 32],
        previous_root: seed_key(0x30, 8),
        revoked: seed_key(0x40, 11),
        lineage,
        envelopes,
        signature: Signature::new(crate::VLD0, [0; 64]),
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rotation_rejects_too_many_envelopes() {
    // Rotation::signed_bytes does not check the lineage shape, so the envelope
    // bound is reachable with an over-long lineage built directly (a
    // shape-valid lineage can never have more devices than MAX_DEVICES).
    let devices = sorted_keys(0x10, MAX_DEVICES + 1);
    let lineage = Lineage {
        version: 1,
        binding: Binding::new("mut-community", "mut-member").unwrap(),
        epoch: 1,
        revision: 1,
        root: seed_key(0x30, 7),
        identity: None,
        devices: devices.clone(),
        delegates: Vec::new(),
        signature: Signature::new(crate::VLD0, [0; 64]),
    };
    let envelopes = devices
        .iter()
        .map(|device| RootEnvelope {
            device: *device,
            sealed_root: vec![0u8; 5 + 32 + 32 + 16],
        })
        .collect();
    let rotation = Rotation {
        version: 1,
        predecessor: [5; 32],
        previous_root: seed_key(0x30, 8),
        revoked: seed_key(0x40, 11),
        lineage,
        envelopes,
        signature: Signature::new(crate::VLD0, [0; 64]),
    };
    assert_eq!(rotation.envelopes.len(), rotation.lineage.devices.len());
    assert!(rotation.signed_bytes().is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rotation_accepts_max_envelopes() {
    let rotation = valid_rotation_many(1, MAX_DEVICES);
    let bytes = rotation.signed_bytes().unwrap();
    assert!(bytes.starts_with(b"ckmg.rotation.v1\0"));
}

// ---- Rotation::verify succession tests: each surviving mutant in verify
// must make at least one of these fail. The fixtures below build an exact
// succession (previous epoch 1/revision 1/root Rp/devices [A, B], next
// epoch 2/revision 2/root Rn/devices [A], revoked B) with both lineages
// signed and the rotation authorized by the previous root.

fn resign_lineage(lineage: &mut Lineage, first: u8, second: u8) {
    let bytes = lineage.signed_bytes().unwrap();
    lineage.signature = sign_as(first, second, &bytes);
}

fn resign_rotation(rotation: &mut Rotation, first: u8, second: u8) {
    let bytes = rotation.signed_bytes().unwrap();
    rotation.signature = sign_as(first, second, &bytes);
}

fn verify_pair_v1() -> (Lineage, Rotation) {
    let mut devices = vec![seed_key(0x40, 3), seed_key(0x40, 9)];
    devices.sort();
    let mut previous = Lineage {
        version: 1,
        binding: Binding::new("mut-community", "mut-member").unwrap(),
        epoch: 1,
        revision: 1,
        root: seed_key(0x30, 7),
        identity: None,
        devices: devices.clone(),
        delegates: Vec::new(),
        signature: Signature::new(crate::VLD0, [0; 64]),
    };
    resign_lineage(&mut previous, 0x30, 7);
    previous.verify().unwrap();
    let mut next = Lineage {
        version: 1,
        binding: Binding::new("mut-community", "mut-member").unwrap(),
        epoch: 2,
        revision: 2,
        root: seed_key(0x30, 8),
        identity: None,
        devices: vec![devices[0]],
        delegates: Vec::new(),
        signature: Signature::new(crate::VLD0, [0; 64]),
    };
    resign_lineage(&mut next, 0x30, 8);
    next.verify().unwrap();
    let mut rotation = Rotation {
        version: 1,
        predecessor: previous.digest().unwrap(),
        previous_root: seed_key(0x30, 7),
        revoked: devices[1],
        lineage: next,
        envelopes: vec![RootEnvelope {
            device: devices[0],
            sealed_root: vec![0u8; 5 + 32 + 32 + 16],
        }],
        signature: Signature::new(crate::VLD0, [0; 64]),
    };
    resign_rotation(&mut rotation, 0x30, 7);
    rotation.verify(&previous).unwrap();
    (previous, rotation)
}

fn verify_pair_v2_delegate_revoked() -> (Lineage, Rotation) {
    let device = seed_key(0x40, 3);
    let delegate = seed_key(0x20, 5);
    let mut previous = Lineage {
        version: 2,
        binding: Binding::new("mut-community", "mut-member").unwrap(),
        epoch: 1,
        revision: 1,
        root: seed_key(0x30, 7),
        identity: Some(seed_key(0x30, 7)),
        devices: vec![device],
        delegates: vec![delegate],
        signature: Signature::new(crate::VLD0, [0; 64]),
    };
    resign_lineage(&mut previous, 0x30, 7);
    previous.verify().unwrap();
    let mut next = Lineage {
        version: 2,
        binding: Binding::new("mut-community", "mut-member").unwrap(),
        epoch: 2,
        revision: 2,
        root: seed_key(0x30, 8),
        identity: Some(seed_key(0x30, 7)),
        devices: vec![device],
        delegates: Vec::new(),
        signature: Signature::new(crate::VLD0, [0; 64]),
    };
    resign_lineage(&mut next, 0x30, 8);
    next.verify().unwrap();
    let mut rotation = Rotation {
        version: 2,
        predecessor: previous.digest().unwrap(),
        previous_root: seed_key(0x30, 7),
        revoked: delegate,
        lineage: next,
        envelopes: vec![RootEnvelope {
            device,
            sealed_root: vec![0u8; 5 + 32 + 64 + 16],
        }],
        signature: Signature::new(crate::VLD0, [0; 64]),
    };
    resign_rotation(&mut rotation, 0x30, 7);
    rotation.verify(&previous).unwrap();
    (previous, rotation)
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rotation_verify_accepts_exact_succession() {
    let (previous, rotation) = verify_pair_v1();
    assert_eq!(rotation.verify(&previous), Ok(()));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rotation_verify_accepts_delegate_revocation() {
    let (previous, rotation) = verify_pair_v2_delegate_revoked();
    assert_eq!(rotation.verify(&previous), Ok(()));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rotation_verify_rejects_identity_change_alone() {
    let (previous, mut rotation) = verify_pair_v2_delegate_revoked();
    rotation.lineage.identity = Some(seed_key(0x50, 1));
    resign_lineage(&mut rotation.lineage, 0x30, 8);
    resign_rotation(&mut rotation, 0x30, 7);
    assert_eq!(rotation.verify(&previous), Err(Error::Unauthorized));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rotation_verify_rejects_wrong_predecessor() {
    let (previous, mut rotation) = verify_pair_v1();
    rotation.predecessor = [9; 32];
    resign_rotation(&mut rotation, 0x30, 7);
    assert_eq!(rotation.verify(&previous), Err(Error::Unauthorized));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rotation_verify_rejects_wrong_previous_root() {
    let (previous, mut rotation) = verify_pair_v1();
    rotation.previous_root = seed_key(0x50, 1);
    resign_rotation(&mut rotation, 0x50, 1);
    assert_eq!(rotation.verify(&previous), Err(Error::Unauthorized));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rotation_verify_rejects_binding_change() {
    let (previous, mut rotation) = verify_pair_v1();
    rotation.lineage.binding = Binding::new("other-community", "mut-member").unwrap();
    resign_lineage(&mut rotation.lineage, 0x30, 8);
    resign_rotation(&mut rotation, 0x30, 7);
    assert_eq!(rotation.verify(&previous), Err(Error::Unauthorized));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rotation_verify_rejects_same_root() {
    let (previous, mut rotation) = verify_pair_v1();
    rotation.lineage.root = seed_key(0x30, 7);
    resign_lineage(&mut rotation.lineage, 0x30, 7);
    resign_rotation(&mut rotation, 0x30, 7);
    assert_eq!(rotation.verify(&previous), Err(Error::Unauthorized));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rotation_verify_rejects_stale_epoch() {
    let (previous, mut rotation) = verify_pair_v1();
    rotation.lineage.epoch = 1;
    resign_lineage(&mut rotation.lineage, 0x30, 8);
    resign_rotation(&mut rotation, 0x30, 7);
    assert_eq!(rotation.verify(&previous), Err(Error::Unauthorized));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rotation_verify_rejects_stale_revision() {
    let (previous, mut rotation) = verify_pair_v1();
    rotation.lineage.revision = 1;
    resign_lineage(&mut rotation.lineage, 0x30, 8);
    resign_rotation(&mut rotation, 0x30, 7);
    assert_eq!(rotation.verify(&previous), Err(Error::Unauthorized));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rotation_verify_rejects_foreign_revoked() {
    let (previous, mut rotation) = verify_pair_v1();
    rotation.revoked = seed_key(0x50, 2);
    // Keep the full previous device set (with matching envelopes) so that the
    // revoked-membership clause alone fires: the devices clause sees
    // lineage.devices == remaining because the foreign key removed nothing.
    let mut devices = rotation.lineage.devices.clone();
    devices.push(previous.devices[1]);
    devices.sort();
    rotation.envelopes.push(RootEnvelope {
        device: previous.devices[1],
        sealed_root: vec![0u8; 5 + 32 + 32 + 16],
    });
    rotation.envelopes.sort_by(|a, b| a.device.cmp(&b.device));
    rotation.lineage.devices = devices;
    resign_lineage(&mut rotation.lineage, 0x30, 8);
    resign_rotation(&mut rotation, 0x30, 7);
    assert_eq!(rotation.verify(&previous), Err(Error::Unauthorized));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rotation_verify_rejects_device_set_mismatch() {
    let (previous, mut rotation) = verify_pair_v1();
    let mut devices = rotation.lineage.devices.clone();
    devices.push(rotation.revoked);
    devices.sort();
    rotation.envelopes.push(RootEnvelope {
        device: rotation.revoked,
        sealed_root: vec![0u8; 5 + 32 + 32 + 16],
    });
    rotation.envelopes.sort_by(|a, b| a.device.cmp(&b.device));
    rotation.lineage.devices = devices;
    resign_lineage(&mut rotation.lineage, 0x30, 8);
    resign_rotation(&mut rotation, 0x30, 7);
    assert_eq!(rotation.verify(&previous), Err(Error::Unauthorized));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rotation_verify_rejects_delegate_set_mismatch() {
    let (previous, mut rotation) = verify_pair_v2_delegate_revoked();
    rotation.lineage.delegates = vec![rotation.revoked];
    resign_lineage(&mut rotation.lineage, 0x30, 8);
    resign_rotation(&mut rotation, 0x30, 7);
    assert_eq!(rotation.verify(&previous), Err(Error::Unauthorized));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rotation_signed_bytes_v2_pins_domain() {
    let bytes = valid_rotation(2).signed_bytes().unwrap();
    assert!(bytes.starts_with(b"ckmg.rotation.v2\0"));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rotation_rejects_bad_sealed_root_length() {
    let mut rotation = valid_rotation(1);
    rotation.envelopes[0].sealed_root = vec![0u8; 10];
    assert!(rotation.signed_bytes().is_err());
}

// ---- encode bound tests: the MAX_MESSAGE_BYTES limit must accept exactly
// MAX_MESSAGE_BYTES and refuse anything longer.

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn encode_accepts_exactly_max_message_bytes() {
    let domain = b"ckmg.test.exact.v1\0";
    let pad = MAX_MESSAGE_BYTES - domain.len() - 2;
    let bytes = encode(domain, &"a".repeat(pad)).unwrap();
    assert_eq!(bytes.len(), MAX_MESSAGE_BYTES);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn encode_rejects_over_max_message_bytes() {
    let domain = b"ckmg.test.exact.v1\0";
    let pad = MAX_MESSAGE_BYTES - domain.len() - 2 + 1;
    assert_eq!(encode(domain, &"a".repeat(pad)).unwrap_err(), Error::Limit);
}

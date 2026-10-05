//! Real original checkpoint encryption and lineage signatures; no Authority fixture.
use super::*;

const COMMUNITY: &str = "inspection-community";

fn fixture() -> (PrfOutput, Metadata, Material) {
    let prf = PrfOutput::from_bytes(&[41; 32]).unwrap();
    let material = Material::derive(&prf, COMMUNITY, true, &mut crate::SystemEntropy).unwrap();
    let root = vld0::public_key(material.root().unwrap());
    let mut lineage = Lineage {
        version: 2,
        binding: Binding::new(COMMUNITY, "original-pseudonym").unwrap(),
        epoch: 3,
        revision: 7,
        root,
        identity: Some(root),
        devices: vec![vld0::public_key(&material.device)],
        signature: empty_signature(),
    };
    lineage.signature =
        vld0::sign(material.root().unwrap(), &lineage.signed_bytes().unwrap()).unwrap();
    let metadata = Metadata {
        version: 1,
        revision: 11,
        last_time: 1100,
        info: DeviceInfo::new("private-device-label", b"private-passkey-reference").unwrap(),
        lineage,
        pairing: None,
        revoked: false,
        output: None,
    };
    (prf, metadata, material)
}

fn seal_raw(prf: &PrfOutput, plaintext: &[u8]) -> Vec<u8> {
    let location = passkey::vault_location(prf, COMMUNITY).unwrap();
    let key = passkey::ring_key(prf, COMMUNITY).unwrap();
    let mut sealed = CHECKPOINT_HEADER.to_vec();
    sealed.extend(
        keyring::seal(
            &mut crate::SystemEntropy,
            &key,
            &checkpoint_aad(location),
            plaintext,
        )
        .unwrap(),
    );
    sealed
}
fn seal(prf: &PrfOutput, metadata: &Metadata, material: &Material) -> Vec<u8> {
    seal_raw(prf, &encode_checkpoint(metadata, material).unwrap())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn authentic_checkpoint_exposes_only_original_public_claims_and_exact_provenance() {
    let (prf, metadata, material) = fixture();
    let sealed = seal(&prf, &metadata, &material);
    let inspection = inspect_checkpoint(&prf, COMMUNITY, &sealed).unwrap();
    assert_eq!(inspection.lineage(), &metadata.lineage);
    assert_eq!(inspection.device(), vld0::public_key(&material.device));
    assert_eq!(inspection.revision(), 11);
    assert_eq!(inspection.last_time(), 1100);
    assert_eq!(inspection.sealed_digest(), blake3::hash(&sealed).as_bytes());
    assert_eq!(
        format!("{inspection:?}"),
        "CheckpointInspection([redacted])"
    );
    let resealed = seal(&prf, &metadata, &material);
    let again = inspect_checkpoint(&prf, COMMUNITY, &resealed).unwrap();
    assert_eq!(inspection.lineage(), again.lineage());
    assert_ne!(inspection.sealed_digest(), again.sealed_digest());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn wrong_prf_scope_tampering_and_bounded_encoding_refuse() {
    let (prf, metadata, material) = fixture();
    let mut sealed = seal(&prf, &metadata, &material);
    let other = PrfOutput::from_bytes(&[42; 32]).unwrap();
    assert_eq!(
        inspect_checkpoint(&other, COMMUNITY, &sealed).unwrap_err(),
        Error::Open
    );
    assert_eq!(
        inspect_checkpoint(&prf, "another-community", &sealed).unwrap_err(),
        Error::Open
    );
    assert!(inspect_checkpoint(&prf, "", &sealed).is_err());
    *sealed.last_mut().unwrap() ^= 1;
    assert_eq!(
        inspect_checkpoint(&prf, COMMUNITY, &sealed).unwrap_err(),
        Error::Open
    );
    assert_eq!(
        inspect_checkpoint(&prf, COMMUNITY, b"not-a-checkpoint").unwrap_err(),
        Error::Encoding
    );
    assert_eq!(
        inspect_checkpoint(&prf, COMMUNITY, &vec![0; MAX_CHECKPOINT_BYTES + 1]).unwrap_err(),
        Error::Limit
    );
    assert_eq!(
        inspect_checkpoint(&prf, COMMUNITY, &seal_raw(&prf, &[1, 2, 3])).unwrap_err(),
        Error::Encoding
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn aead_is_not_a_substitute_for_original_scope_lineage_and_material_checks() {
    let (prf, metadata, material) = fixture();
    let mut wrong = metadata.clone();
    wrong.lineage.binding = Binding::new("another-community", "original-pseudonym").unwrap();
    assert_eq!(
        inspect_checkpoint(&prf, COMMUNITY, &seal(&prf, &wrong, &material)).unwrap_err(),
        Error::Unauthorized
    );
    wrong = metadata.clone();
    wrong.version = 2;
    assert_eq!(
        inspect_checkpoint(&prf, COMMUNITY, &seal(&prf, &wrong, &material)).unwrap_err(),
        Error::Encoding
    );
    wrong = metadata.clone();
    wrong.revision = 0;
    assert_eq!(
        inspect_checkpoint(&prf, COMMUNITY, &seal(&prf, &wrong, &material)).unwrap_err(),
        Error::Encoding
    );
    wrong = metadata.clone();
    wrong.lineage.revision += 1;
    assert_eq!(
        inspect_checkpoint(&prf, COMMUNITY, &seal(&prf, &wrong, &material)).unwrap_err(),
        Error::BadSignature
    );
    let mut wrong_material = material.clone();
    wrong_material.device = crate::keyring::secret(&[73; 32]).unwrap();
    assert_eq!(
        inspect_checkpoint(&prf, COMMUNITY, &seal(&prf, &metadata, &wrong_material)).unwrap_err(),
        Error::Encoding
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn pending_and_valid_pairing_or_revoked_checkpoints_grant_no_inspection() {
    let (prf, mut metadata, mut material) = fixture();
    metadata.output = Some(Receipt {
        operation: OperationId([9; 32]),
        change: Change::Created(metadata.lineage.clone()),
        attestation: None,
    });
    assert_eq!(
        inspect_checkpoint(&prf, COMMUNITY, &seal(&prf, &metadata, &material)).unwrap_err(),
        Error::Pending
    );
    metadata.output = None;
    let other_device = vld0::public_key(&crate::keyring::secret(&[73; 32]).unwrap());
    metadata.lineage.devices = vec![other_device];
    metadata.lineage.signature = vld0::sign(
        material.root().unwrap(),
        &metadata.lineage.signed_bytes().unwrap(),
    )
    .unwrap();
    let mut request = PairingRequest {
        version: 1,
        binding: metadata.lineage.binding.clone(),
        root: metadata.lineage.root,
        epoch: metadata.lineage.epoch,
        device: vld0::public_key(&material.device),
        nonce: [5; 32],
        issued_at: 1100,
        expires_at: 1200,
        proof: empty_signature(),
    };
    request.proof = vld0::sign(&material.device, &request.signed_bytes().unwrap()).unwrap();
    request.verify(1100).unwrap();
    metadata.pairing = Some(request);
    material.root = None;
    material.identity = None;
    validate_checkpoint(&metadata, &material).unwrap();
    assert_eq!(
        inspect_checkpoint(&prf, COMMUNITY, &seal(&prf, &metadata, &material)).unwrap_err(),
        Error::NoRoot
    );
    metadata.pairing = None;
    metadata.revoked = true;
    validate_checkpoint(&metadata, &material).unwrap();
    assert_eq!(
        inspect_checkpoint(&prf, COMMUNITY, &seal(&prf, &metadata, &material)).unwrap_err(),
        Error::Revoked
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn valid_old_checkpoints_remain_inspectable_without_claiming_freshness() {
    let (prf, mut metadata, material) = fixture();
    let old = seal(&prf, &metadata, &material);
    metadata.revision += 1;
    metadata.last_time += 1;
    metadata.lineage.revision += 1;
    metadata.lineage.signature = vld0::sign(
        material.root().unwrap(),
        &metadata.lineage.signed_bytes().unwrap(),
    )
    .unwrap();
    let current = seal(&prf, &metadata, &material);
    let old_claims = inspect_checkpoint(&prf, COMMUNITY, &old).unwrap();
    let current_claims = inspect_checkpoint(&prf, COMMUNITY, &current).unwrap();
    assert!(old_claims.revision() < current_claims.revision());
    assert!(old_claims.lineage().revision < current_claims.lineage().revision);
    assert!(old_claims.last_time() < current_claims.last_time());
    // No Authority was supplied or invoked: only the real current record and
    // live credential composition can decide which observation is acceptable.
    assert_ne!(old_claims.sealed_digest(), current_claims.sealed_digest());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn narrow_inspector_survives_consumed_prf_without_retaining_unlocked_material() {
    let (prf, metadata, material) = fixture();
    let sealed = seal(&prf, &metadata, &material);
    let inspector = CheckpointInspector::new(&prf, COMMUNITY).unwrap();
    let wrong_scope = CheckpointInspector::new(&prf, "another-community").unwrap();
    assert!(CheckpointInspector::new(&prf, "").is_err());
    drop(prf);
    drop(material);
    let first = inspector.inspect(&sealed).unwrap();
    let second = inspector.inspect(&sealed).unwrap();
    assert_eq!(first.lineage(), &metadata.lineage);
    assert_eq!(first.sealed_digest(), second.sealed_digest());
    assert_eq!(wrong_scope.inspect(&sealed).unwrap_err(), Error::Open);
    drop(inspector);
}

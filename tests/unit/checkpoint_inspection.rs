//! Real original checkpoint encryption and lineage signatures; no Authority fixture.
use super::*;

#[path = "checkpoint_publication.rs"]
mod publication_tests;

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
        initial: None,
        ledger: Default::default(),
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

// Test-only authority observations; no HTTPS or DHT authority is established.
struct BootstrapClock(u64, u64);
impl Clock for BootstrapClock {
    fn now(&mut self) -> Result<u64, Error> {
        let now = self.0;
        self.0 = self.1;
        Ok(now)
    }
}
struct BootstrapAuthority<'a> {
    metadata: &'a Metadata,
    device: PublicKey,
    calls: usize,
    refuse: bool,
}
impl Authority for BootstrapAuthority<'_> {
    async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        self.calls += 1;
        assert_eq!(request.action, Action::Use);
        assert_eq!(request.binding, &self.metadata.lineage.binding);
        assert_eq!(request.root, Some(self.metadata.lineage.root));
        assert_eq!(request.device, self.device);
        assert_eq!(request.epoch, self.metadata.lineage.epoch);
        assert_eq!(
            request.statement,
            Some(self.metadata.lineage.digest().unwrap())
        );
        assert!(request.target.is_none() && request.signing.is_none());
        assert_eq!(request.evidence, b"component-evidence");
        if self.refuse {
            Err(Error::Unauthorized)
        } else {
            Ok(())
        }
    }
}
fn bootstrap(prf: &PrfOutput, metadata: &Metadata, material: &Material) -> CheckpointBootstrap {
    let mut authority = BootstrapAuthority {
        metadata,
        device: vld0::public_key(&material.device),
        calls: 0,
        refuse: false,
    };
    let result =
        futures::executor::block_on(CheckpointInspector::new(prf, COMMUNITY).unwrap().bootstrap(
            &seal(prf, metadata, material),
            b"component-evidence",
            &mut BootstrapClock(1100, 1100),
            &mut authority,
        ))
        .unwrap();
    assert_eq!(authority.calls, 1);
    result
}
fn original_owner(
    prf: &PrfOutput,
    metadata: &Metadata,
    material: &Material,
    label: &str,
) -> PublicKey {
    let original = Open {
        location: passkey::vault_location(prf, COMMUNITY).unwrap(),
        key: passkey::ring_key(prf, COMMUNITY).unwrap(),
        session: [0; 32],
        stamp: [0; 32],
        metadata: metadata.clone(),
        material: material.clone(),
    };
    // The record purposes are reserved: callers cannot name them (X3 M2).
    assert_eq!(
        Purpose::new(Scope::Member, label, 0).unwrap_err(),
        Error::InvalidPurpose
    );
    let purpose = Purpose::reserved(Scope::Member, label, 0).unwrap();
    vld0::public_key(&purpose_secret(&original, &purpose, false).unwrap())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn bootstrap_refuses_evidence_authority_clock_and_sealed_state_before_lending() {
    let (prf, metadata, material) = fixture();
    let sealed = seal(&prf, &metadata, &material);
    let inspector = CheckpointInspector::new(&prf, COMMUNITY).unwrap();
    for (first, second, refuse, expected, calls) in [
        (1100, 1100, true, Error::Unauthorized, 1),
        (1099, 1100, false, Error::Clock, 0),
        (1100, 1099, false, Error::Clock, 1),
    ] {
        let mut authority = BootstrapAuthority {
            metadata: &metadata,
            device: vld0::public_key(&material.device),
            calls: 0,
            refuse,
        };
        assert_eq!(
            futures::executor::block_on(inspector.bootstrap(
                &sealed,
                b"component-evidence",
                &mut BootstrapClock(first, second),
                &mut authority
            ))
            .unwrap_err(),
            expected
        );
        assert_eq!(authority.calls, calls);
    }
    let mut authority = BootstrapAuthority {
        metadata: &metadata,
        device: vld0::public_key(&material.device),
        calls: 0,
        refuse: false,
    };
    for evidence in [vec![], vec![0; MAX_MESSAGE_BYTES + 1]] {
        assert_eq!(
            futures::executor::block_on(inspector.bootstrap(
                &sealed,
                &evidence,
                &mut BootstrapClock(1100, 1100),
                &mut authority
            ))
            .unwrap_err(),
            Error::Limit
        );
    }
    let mut tampered = sealed;
    *tampered.last_mut().unwrap() ^= 1;
    let mut pending = metadata.clone();
    pending.output = Some(Receipt {
        operation: OperationId([9; 32]),
        change: Change::Created(pending.lineage.clone()),
        attestation: None,
    });
    for (wire, expected) in [
        (tampered, Error::Open),
        (seal(&prf, &pending, &material), Error::Pending),
    ] {
        assert_eq!(
            futures::executor::block_on(inspector.bootstrap(
                &wire,
                b"component-evidence",
                &mut BootstrapClock(1100, 1100),
                &mut authority
            ))
            .unwrap_err(),
            expected
        );
    }
    assert_eq!(authority.calls, 0);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn two_passkeys_share_only_the_same_common_root_compound_capabilities() {
    let (prf, mut metadata, material) = fixture();
    let other_prf = PrfOutput::from_bytes(&[43; 32]).unwrap();
    let mut other =
        Material::derive(&other_prf, COMMUNITY, true, &mut crate::SystemEntropy).unwrap();
    other.root = material.root.clone();
    other.identity = material.identity.clone();
    assert_ne!(
        vld0::public_key(&other.device),
        vld0::public_key(&material.device)
    );
    metadata
        .lineage
        .devices
        .push(vld0::public_key(&other.device));
    metadata.lineage.devices.sort();
    metadata.lineage.signature = vld0::sign(
        material.root().unwrap(),
        &metadata.lineage.signed_bytes().unwrap(),
    )
    .unwrap();
    let first = bootstrap(&prf, &metadata, &material);
    let second = bootstrap(&other_prf, &metadata, &other);
    let wrapped = first
        .store_cipher()
        .unwrap()
        .seal(&mut crate::SystemEntropy, b"compound", b"data key")
        .unwrap();
    assert_eq!(
        second
            .store_cipher()
            .unwrap()
            .open(b"compound", &wrapped)
            .unwrap()
            .as_slice(),
        b"data key"
    );
    for child in [None, Some(0), Some(9)] {
        assert_eq!(
            first.record(child).unwrap().public_key(),
            second.record(child).unwrap().public_key()
        );
    }
    let (foreign_prf, foreign_metadata, foreign_material) = fixture();
    let foreign = bootstrap(&foreign_prf, &foreign_metadata, &foreign_material);
    assert_eq!(
        foreign
            .store_cipher()
            .unwrap()
            .open(b"compound", &wrapped)
            .unwrap_err(),
        Error::Open
    );
    assert_eq!(
        second
            .store_cipher()
            .unwrap()
            .open(b"foreign scope", &wrapped)
            .unwrap_err(),
        Error::Open
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn bootstrap_matches_original_record_derivation_and_bounded_purposes() {
    let (prf, metadata, material) = fixture();
    let custody = bootstrap(&prf, &metadata, &material);
    assert_eq!(custody.checked_at(), 1100);
    assert_eq!(custody.inspection().lineage(), &metadata.lineage);
    for (child, label) in [
        (None, "vault.checkpoint"),
        (Some(0), "vault.checkpoint.chunk.0"),
        (Some(9), "vault.checkpoint.chunk.9"),
    ] {
        let record = custody.record(child).unwrap();
        assert_eq!(
            record.public_key(),
            original_owner(&prf, &metadata, &material, label)
        );
        let signature = record
            .with_record(|signer, _| signer.sign(b"record"))
            .unwrap();
        vld0::verify(
            &record.public_key(),
            b"record",
            &Signature::new(VLD0, signature),
        )
        .unwrap();
    }
    assert_eq!(custody.record(Some(10)).unwrap_err(), Error::Limit);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn compound_wrapping_rotates_while_wallet_identity_stays_stable() {
    let (prf, mut metadata, mut material) = fixture();
    let before = bootstrap(&prf, &metadata, &material);
    let identity = material.identity.clone();
    material.root = Some(vld0::random_secret(&mut crate::SystemEntropy).unwrap());
    metadata.lineage.root = vld0::public_key(material.root().unwrap());
    metadata.lineage.epoch += 1;
    metadata.lineage.revision += 1;
    metadata.revision += 1;
    metadata.lineage.signature = vld0::sign(
        material.root().unwrap(),
        &metadata.lineage.signed_bytes().unwrap(),
    )
    .unwrap();
    let after = bootstrap(&prf, &metadata, &material);
    assert!(material.identity == identity);
    assert_eq!(
        before.inspection().lineage().identity,
        after.inspection().lineage().identity
    );
    let sealed = before
        .store_cipher()
        .unwrap()
        .seal(&mut crate::SystemEntropy, b"compound", b"data key")
        .unwrap();
    assert_eq!(
        after
            .store_cipher()
            .unwrap()
            .open(b"compound", &sealed)
            .unwrap_err(),
        Error::Open
    );
    assert_ne!(
        before.record(None).unwrap().public_key(),
        after.record(None).unwrap().public_key()
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn lineage_read_capability_reads_only_the_one_record_for_the_exact_binding() {
    let (_, metadata, material) = fixture();
    let lineage = &metadata.lineage;
    let capability = lineage_read_capability(material.root().unwrap(), lineage).unwrap();
    assert_eq!(
        format!("{capability:?}"),
        "LineageReadCapability([redacted])"
    );
    let reader =
        LineageReadCustody::from_capability(capability.as_bytes(), &lineage.binding).unwrap();
    assert_eq!(reader.owner(), lineage.root);
    // The peer's custody decrypts exactly what the owner's lineage cipher encrypted.
    let secret = lineage_secret(material.root().unwrap(), lineage).unwrap();
    let nonce = [7u8; 24];
    let sealed = crate::Vld0RecordCipher { secret: &secret }
        .crypt(&nonce, b"lineage evidence")
        .unwrap();
    assert_eq!(
        &**reader.open(&nonce, &sealed).unwrap(),
        b"lineage evidence"
    );
    // Another binding, truncation, trailing bytes and a foreign domain refuse.
    let other = Binding::new(lineage.binding.community(), "someone-else").unwrap();
    assert_eq!(
        LineageReadCustody::from_capability(capability.as_bytes(), &other).err(),
        Some(Error::Unauthorized)
    );
    let bytes = capability.as_bytes();
    assert!(
        LineageReadCustody::from_capability(&bytes[..bytes.len() - 1], &lineage.binding).is_err()
    );
    let mut longer = bytes.to_vec();
    longer.push(0);
    assert!(LineageReadCustody::from_capability(&longer, &lineage.binding).is_err());
    let mut foreign = bytes.to_vec();
    foreign[0] ^= 1;
    assert!(LineageReadCustody::from_capability(&foreign, &lineage.binding).is_err());
    // A different root (another record) yields a different read key.
    let mut changed = bytes.to_vec();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    let wrong = LineageReadCustody::from_capability(&changed, &lineage.binding).unwrap();
    assert_ne!(&**wrong.open(&nonce, &sealed).unwrap(), b"lineage evidence");
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn the_signing_ledger_section_round_trips_and_is_absent_when_empty() {
    use crate::SigningPhase;
    let (_, mut metadata, material) = fixture();
    let before = encode_checkpoint(&metadata, &material).unwrap();
    // No section when empty: the pre-ledger bytes decode unchanged.
    let (decoded, _) = decode_checkpoint(&before).unwrap();
    assert!(decoded.ledger == crate::signing_ledger::AccountLedger::default());
    metadata
        .ledger
        .insert([1; 32], SigningPhase::Contact, [2; 32])
        .unwrap();
    let after = encode_checkpoint(&metadata, &material).unwrap();
    assert_eq!(after.len(), before.len() + 3 + 65);
    let (decoded, reparsed) = decode_checkpoint(&after).unwrap();
    assert!(decoded.ledger == metadata.ledger);
    assert!(reparsed.device == material.device);
    assert_eq!(
        decoded
            .ledger
            .admits(&[1; 32], SigningPhase::Contact, &[3; 32]),
        Err(Error::Unauthorized)
    );
}

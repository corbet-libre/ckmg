//! Original Keys checkpoint/CDHT owners and exact synthetic completion inputs.
//! This strict fixture is not production certificate, HTTPS or G3 authority.
use super::*;
use futures::{FutureExt, executor::block_on};
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    rc::Rc,
};

const COMMUNITY: &str = "pending-completion";
const PAYLOAD: &[u8] = b"exact packed certified completion fixture";

#[derive(Clone, Default)]
struct Memory(Rc<RefCell<HashMap<Locator, Vec<u8>>>>);
impl SecureStore for Memory {
    async fn load(&mut self, location: &Locator) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.0.borrow().get(location).cloned())
    }
    async fn compare_exchange(
        &mut self,
        location: &Locator,
        expected: Option<[u8; 32]>,
        next: &[u8],
    ) -> Result<Commit, Error> {
        let mut stored = self.0.borrow_mut();
        if stored
            .get(location)
            .map(|bytes| *blake3::hash(bytes).as_bytes())
            != expected
        {
            return Ok(Commit::Conflict);
        }
        stored.insert(*location, next.to_vec());
        Ok(Commit::Committed)
    }
}
#[derive(Clone)]
struct Time(Rc<Cell<u64>>);
impl Clock for Time {
    fn now(&mut self) -> Result<u64, Error> {
        Ok(self.0.get())
    }
}
struct FinishingTime {
    samples: [u64; 3],
    next: usize,
}
impl Clock for FinishingTime {
    fn now(&mut self) -> Result<u64, Error> {
        let now = self.samples[self.next.min(self.samples.len() - 1)];
        self.next += 1;
        Ok(now)
    }
}
struct CreateOnly {
    binding: Binding,
    device: PublicKey,
    used: bool,
    calls: Rc<Cell<usize>>,
}
impl Authority for CreateOnly {
    async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        self.calls.set(self.calls.get() + 1);
        if self.used
            || request.binding != &self.binding
            || request.device != self.device
            || request.action != Action::Create
            || request.root.is_some()
            || request.epoch != 0
            || request.target.is_some()
            || request.statement.is_some()
            || request.signing.is_some()
            || request.now != 1000
            || request.evidence != b"registration"
        {
            return Err(Error::Unauthorized);
        }
        self.used = true;
        Ok(())
    }
}
type Machine = Keys<Memory, Time, crate::SystemEntropy, CreateOnly>;
async fn fixture() -> (Machine, PrfOutput, Vec<u8>, Time) {
    let prf = PrfOutput::from_bytes(&[61; 32]).unwrap();
    let binding = Binding::new(COMMUNITY, "original-member").unwrap();
    let store = Memory::default();
    let time = Time(Rc::new(Cell::new(1000)));
    let mut keys = Keys::new(
        store.clone(),
        time.clone(),
        crate::SystemEntropy,
        CreateOnly {
            binding: binding.clone(),
            device: passkey::device_public_key(&prf, COMMUNITY).unwrap(),
            used: false,
            calls: Rc::new(Cell::new(0)),
        },
    );
    keys.create_scope(
        &prf,
        binding,
        DeviceInfo::new("fixture", b"credential").unwrap(),
        b"registration",
    )
    .await
    .unwrap();
    let sealed = store
        .0
        .borrow()
        .get(&passkey::vault_location(&prf, COMMUNITY).unwrap())
        .cloned()
        .unwrap();
    (keys, prf, sealed, time)
}
fn intent() -> CompletionIntent {
    CompletionIntent {
        outer_generation: 2,
        outer_digest: [31; 32],
        inner_version: 1,
        inner_operation: [32; 32],
        inner_digest: [33; 32],
        nonce: [34; 24],
        packed_evidence: PAYLOAD.to_vec(),
        prepared_at: 1000,
        expires: 1060,
    }
}
struct CompletionOwner {
    receipt: Receipt,
    location: Locator,
    sealed_digest: [u8; 32],
    expected: CompletionIntent,
    time: Time,
    observed: Time,
    mode: Rc<Cell<u8>>,
    final_checks: usize,
    credential: Vec<u8>,
}
impl CompletionOwner {
    fn new(pending: &PendingCreation, time: Time) -> Self {
        Self {
            receipt: pending.receipt().clone(),
            location: *pending.location(),
            sealed_digest: *pending.sealed_digest(),
            expected: intent(),
            time,
            observed: Time(Rc::new(Cell::new(1000))),
            mode: Rc::new(Cell::new(0)),
            final_checks: 0,
            credential: b"credential".to_vec(),
        }
    }
    fn exact(&self, request: &crate::CompletionAuthorization<'_>) -> Result<(), Error> {
        let actual = request.intent;
        let expected = &self.expected;
        if request.receipt != &self.receipt
            || request.authority_reference != self.credential.as_slice()
            || request.location != &self.location
            || request.sealed_digest != &self.sealed_digest
            || actual.outer_generation != expected.outer_generation
            || actual.outer_digest != expected.outer_digest
            || actual.inner_version != expected.inner_version
            || actual.inner_operation != expected.inner_operation
            || actual.inner_digest != expected.inner_digest
            || actual.nonce != expected.nonce
            || actual.packed_evidence != expected.packed_evidence
            || actual.prepared_at != expected.prepared_at
            || actual.expires != expected.expires
            || request.now != self.time.0.get()
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}
impl Authority for CompletionOwner {
    async fn check(&mut self, _: Authorization<'_>) -> Result<(), Error> {
        Err(Error::Unauthorized)
    }
    async fn check_completion(
        &mut self,
        request: crate::CompletionAuthorization<'_>,
    ) -> Result<u64, Error> {
        self.exact(&request)?;
        match self.mode.get() {
            1 => futures::future::pending::<()>().await,
            2 => self.time.0.set(1060),
            3 => self.time.0.set(999),
            5 => return Err(Error::Unavailable),
            _ => (),
        }
        Ok(self.observed.0.get())
    }
    fn check_completion_current(
        &mut self,
        request: crate::CompletionAuthorization<'_>,
    ) -> Result<u64, Error> {
        self.final_checks += 1;
        self.exact(&request)?;
        if self.mode.get() == 4 {
            return Err(Error::Unauthorized);
        }
        Ok(self.observed.0.get())
    }
}
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
macro_rules! shared {
    ($name:ident,$body:block) => {
        #[cfg_attr(target_arch="wasm32", wasm_bindgen_test::wasm_bindgen_test)]
        #[cfg_attr(not(target_arch="wasm32"), test)]
        fn $name() { block_on(async $body); }
    };
}

shared!(
    pending_owner_authenticates_original_create_but_normal_inspection_stays_pending,
    {
        let (mut keys, prf, sealed, mut time) = fixture().await;
        let inspector = CheckpointInspector::new(&prf, COMMUNITY).unwrap();
        let pending = inspector.pending_creation(&sealed).unwrap();
        assert_eq!(
            pending.receipt(),
            &keys.pending_output().await.unwrap().unwrap()
        );
        assert_eq!(pending.sealed_digest(), blake3::hash(&sealed).as_bytes());
        assert_eq!(pending.last_time(), 1000);
        assert_eq!(
            pending.location(),
            &passkey::vault_location(&prf, COMMUNITY).unwrap()
        );
        assert_eq!(inspector.inspect(&sealed).unwrap_err(), Error::Pending);
        assert_eq!(
            inspector
                .bootstrap(&sealed, PAYLOAD, &mut time, &mut keys.authority)
                .await
                .unwrap_err(),
            Error::Pending
        );
        assert_eq!(keys.authority.calls.get(), 1);
        let mut owner = CompletionOwner::new(&pending, time.clone());
        keys.lock();
        let admitted = pending
            .authorize_completion(intent(), &mut time, &mut owner)
            .await
            .unwrap();
        assert_eq!(admitted.receipt(), &owner.receipt);
        assert_eq!(admitted.location(), &owner.location);
        assert_eq!(admitted.sealed_digest(), &owner.sealed_digest);
        assert_eq!(format!("{admitted:?}"), "PendingCompletion([redacted])");
        // A fresh inspector authenticates the durable pending owner after process
        // state was discarded; it never invokes original Keys Use or recreates a marker.
        assert!(
            CheckpointInspector::new(&prf, COMMUNITY)
                .unwrap()
                .pending_creation(&sealed)
                .is_ok()
        );
    }
);

shared!(
    same_authenticated_prepared_intent_replays_exact_original_cdht_bytes,
    {
        let (keys, prf, sealed, mut time) = fixture().await;
        let inspector = CheckpointInspector::new(&prf, COMMUNITY).unwrap();
        let read = super::super::lineage_secret(
            keys.loaded().unwrap().material.root().unwrap(),
            &keys.loaded().unwrap().metadata.lineage,
        )
        .unwrap();
        let expected_cipher = passkey::common_store_cipher(
            keys.loaded().unwrap().material.root().unwrap(),
            COMMUNITY,
        )
        .unwrap();
        let mut exact = None;
        for _ in 0..2 {
            let pending = inspector.pending_creation(&sealed).unwrap();
            let mut owner = CompletionOwner::new(&pending, time.clone());
            let admitted = pending
                .authorize_completion(intent(), &mut time, &mut owner)
                .await
                .unwrap();
            let wire = expected_cipher
                .seal(
                    &mut crate::SystemEntropy,
                    COMMUNITY.as_bytes(),
                    b"opaque wrapping fixture",
                )
                .unwrap();
            assert_eq!(
                &*admitted
                    .store_cipher()
                    .open(COMMUNITY.as_bytes(), &wire)
                    .unwrap(),
                b"opaque wrapping fixture"
            );
            assert!(
                passkey::store_cipher(&prf, COMMUNITY)
                    .unwrap()
                    .open(COMMUNITY.as_bytes(), &wire)
                    .is_err()
            );
            let (descriptor, value) = admitted.complete_genesis(&mut time, &mut owner).unwrap();
            assert_eq!(owner.final_checks, 1);
            let schema = descriptor.validate(&Verify).unwrap();
            assert_eq!(schema, cdht::Schema::dflt(1).unwrap());
            assert_eq!(
                descriptor.owner,
                *keys.loaded().unwrap().metadata.lineage.root.value()
            );
            assert_eq!(value.writer, descriptor.owner);
            assert_eq!(value.seq, 0);
            assert_eq!(value.nonce, Some(intent().nonce));
            value
                .validate(&descriptor.key(), &descriptor.owner, &schema, 0, &Verify)
                .unwrap();
            assert!(
                value
                    .validate(&descriptor.key(), &descriptor.owner, &schema, 1, &Verify)
                    .is_err()
            );
            assert_eq!(
                &*crate::Vld0RecordCipher { secret: &read }
                    .crypt(&value.nonce.unwrap(), &value.data)
                    .unwrap(),
                PAYLOAD
            );
            let bytes = (
                serde_json::to_vec(&descriptor).unwrap(),
                serde_json::to_vec(&value).unwrap(),
            );
            if let Some(previous) = exact.as_ref() {
                assert_eq!(&bytes, previous);
            }
            exact = Some(bytes);
        }
        assert_eq!(keys.authority.calls.get(), 1);
    }
);

fn reseal(prf: &PrfOutput, metadata: &Metadata, material: &Material) -> Vec<u8> {
    let location = passkey::vault_location(prf, COMMUNITY).unwrap();
    let key = passkey::ring_key(prf, COMMUNITY).unwrap();
    let mut sealed = CHECKPOINT_HEADER.to_vec();
    sealed.extend(
        keyring::seal(
            &mut crate::SystemEntropy,
            &key,
            &checkpoint_aad(location),
            &encode_checkpoint(metadata, material).unwrap(),
        )
        .unwrap(),
    );
    sealed
}
shared!(
    noninitial_absent_restored_or_wrongly_attested_pending_sources_refuse,
    {
        let (keys, prf, sealed, _) = fixture().await;
        let inspector = CheckpointInspector::new(&prf, COMMUNITY).unwrap();
        let original = keys.loaded().unwrap();
        for failure in 0..6 {
            let mut metadata = original.metadata.clone();
            match failure {
                0 => metadata.revision = 2,
                1 => metadata.output = None,
                2 => metadata.output.as_mut().unwrap().attestation = None,
                3 => metadata.output.as_mut().unwrap().operation = OperationId([91; 32]),
                4 => {
                    let receipt = metadata.output.as_mut().unwrap();
                    receipt.change = Change::Restored(metadata.lineage.clone());
                    let device = vld0::public_key(&original.material.device);
                    receipt.attestation = Some(DeviceAttestation {
                        device,
                        signature: vld0::sign(
                            &original.material.device,
                            &receipt.attestation_bytes(device).unwrap(),
                        )
                        .unwrap(),
                    });
                }
                5 => {
                    metadata.lineage.epoch = 2;
                    metadata.lineage.signature = vld0::sign(
                        original.material.root().unwrap(),
                        &metadata.lineage.signed_bytes().unwrap(),
                    )
                    .unwrap();
                    let receipt = metadata.output.as_mut().unwrap();
                    receipt.change = Change::Created(metadata.lineage.clone());
                    let device = vld0::public_key(&original.material.device);
                    receipt.attestation = Some(DeviceAttestation {
                        device,
                        signature: vld0::sign(
                            &original.material.device,
                            &receipt.attestation_bytes(device).unwrap(),
                        )
                        .unwrap(),
                    });
                }
                _ => unreachable!(),
            }
            assert!(
                inspector
                    .pending_creation(&reseal(&prf, &metadata, &original.material))
                    .is_err()
            );
        }
        let other = PrfOutput::from_bytes(&[62; 32]).unwrap();
        assert!(
            CheckpointInspector::new(&other, COMMUNITY)
                .unwrap()
                .pending_creation(&sealed)
                .is_err()
        );
        assert!(
            CheckpointInspector::new(&prf, "wrong-community")
                .unwrap()
                .pending_creation(&sealed)
                .is_err()
        );
        let mut corrupted = sealed;
        *corrupted.last_mut().unwrap() ^= 1;
        assert!(inspector.pending_creation(&corrupted).is_err());
    }
);

shared!(
    dedicated_owner_compares_every_frozen_store_and_intent_field,
    {
        let (_, prf, sealed, mut time) = fixture().await;
        let inspector = CheckpointInspector::new(&prf, COMMUNITY).unwrap();
        for failure in 0..11 {
            let pending = inspector.pending_creation(&sealed).unwrap();
            let mut owner = CompletionOwner::new(&pending, time.clone());
            let mut submitted = intent();
            match failure {
                0 => submitted.outer_generation += 1,
                1 => submitted.outer_digest[0] ^= 1,
                2 => submitted.inner_version += 1,
                3 => submitted.inner_operation[0] ^= 1,
                4 => submitted.inner_digest[0] ^= 1,
                5 => submitted.nonce[0] ^= 1,
                6 => submitted.packed_evidence.push(1),
                7 => submitted.prepared_at -= 1,
                8 => submitted.expires += 1,
                9 => submitted.packed_evidence.clear(),
                10 => submitted.packed_evidence = vec![0; cdht::MAX_SUBKEY_SIZE + 1],
                _ => unreachable!(),
            }
            assert!(
                pending
                    .authorize_completion(submitted, &mut time, &mut owner)
                    .await
                    .is_err()
            );
            assert_eq!(owner.final_checks, 0);
        }
    }
);

shared!(
    completion_wait_cancellation_expiry_and_rollback_release_only_the_pending_owner,
    {
        let (keys, prf, sealed, mut time) = fixture().await;
        let inspector = CheckpointInspector::new(&prf, COMMUNITY).unwrap();
        for failure in 1..=5 {
            if failure == 4 {
                continue;
            }
            time.0.set(1000);
            let pending = inspector.pending_creation(&sealed).unwrap();
            let mut owner = CompletionOwner::new(&pending, time.clone());
            owner.mode.set(failure);
            let attempt = pending.authorize_completion(intent(), &mut time, &mut owner);
            if failure == 1 {
                assert!(attempt.now_or_never().is_none());
            } else {
                assert!(attempt.await.is_err());
            }
            assert_eq!(owner.final_checks, 0);
        }
        time.0.set(1000);
        let pending = inspector.pending_creation(&sealed).unwrap();
        let mut owner = CompletionOwner::new(&pending, time.clone());
        let admitted = pending
            .authorize_completion(intent(), &mut time, &mut owner)
            .await
            .unwrap();
        drop(admitted);
        assert_eq!(keys.authority.calls.get(), 1);
        assert_eq!(
            keys.store
                .0
                .borrow()
                .get(&passkey::vault_location(&prf, COMMUNITY).unwrap())
                .unwrap(),
            &sealed
        );
    }
);

shared!(
    poststore_current_refusal_and_original_clock_boundaries_withhold_outputs,
    {
        let (_, prf, sealed, mut time) = fixture().await;
        let inspector = CheckpointInspector::new(&prf, COMMUNITY).unwrap();
        for failure in 0..4 {
            time.0.set(1000);
            let pending = inspector.pending_creation(&sealed).unwrap();
            let mut owner = CompletionOwner::new(&pending, time.clone());
            let admitted = pending
                .authorize_completion(intent(), &mut time, &mut owner)
                .await
                .unwrap();
            // CVLT owns the final original Store wait. This lower-owner test changes
            // the exact current inputs before the synchronous completion boundary.
            match failure {
                0 => owner.mode.set(4),
                1 => time.0.set(1060),
                2 => time.0.set(999),
                3 => owner.expected.inner_digest[0] ^= 1,
                _ => unreachable!(),
            }
            assert!(admitted.complete_genesis(&mut time, &mut owner).is_err());
        }
        for time_before in [999, 1060] {
            time.0.set(time_before);
            let pending = inspector.pending_creation(&sealed).unwrap();
            let mut owner = CompletionOwner::new(&pending, time.clone());
            assert!(
                pending
                    .authorize_completion(intent(), &mut time, &mut owner)
                    .await
                    .is_err()
            );
        }
    }
);

shared!(
    ordinary_authorities_refuse_both_completion_boundaries_by_default,
    {
        let (mut keys, prf, sealed, mut time) = fixture().await;
        let pending = CheckpointInspector::new(&prf, COMMUNITY)
            .unwrap()
            .pending_creation(&sealed)
            .unwrap();
        let frozen = intent();
        assert_eq!(
            keys.authority
                .check_completion_current(crate::CompletionAuthorization {
                    receipt: pending.receipt(),
                    authority_reference: b"credential",
                    location: pending.location(),
                    sealed_digest: pending.sealed_digest(),
                    intent: &frozen,
                    now: 1000,
                }),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            pending
                .authorize_completion(frozen, &mut time, &mut keys.authority)
                .await
                .unwrap_err(),
            Error::Unauthorized
        );
        assert_eq!(keys.authority.calls.get(), 1);
    }
);

shared!(
    persisted_preparing_floor_deadline_and_postcrypto_time_never_renew,
    {
        let (_, prf, sealed, mut time) = fixture().await;
        let inspector = CheckpointInspector::new(&prf, COMMUNITY).unwrap();
        let pending = inspector.pending_creation(&sealed).unwrap();
        let mut owner = CompletionOwner::new(&pending, time.clone());
        let mut prepared = intent();
        prepared.prepared_at = 1005;
        owner.expected.prepared_at = 1005;
        time.0.set(1004);
        assert_eq!(
            pending
                .authorize_completion(prepared, &mut time, &mut owner)
                .await
                .unwrap_err(),
            Error::Clock
        );

        // The retained exact intent has expired. Offering a new deadline cannot
        // pass this independently held exact completion owner.
        time.0.set(1060);
        let pending = inspector.pending_creation(&sealed).unwrap();
        let mut owner = CompletionOwner::new(&pending, time.clone());
        let mut renewed = intent();
        renewed.expires = 1061;
        assert_eq!(
            pending
                .authorize_completion(renewed, &mut time, &mut owner)
                .await
                .unwrap_err(),
            Error::Unauthorized
        );

        for final_time in [999, 1060] {
            time.0.set(1000);
            let pending = inspector.pending_creation(&sealed).unwrap();
            let mut owner = CompletionOwner::new(&pending, time.clone());
            let admitted = pending
                .authorize_completion(intent(), &mut time, &mut owner)
                .await
                .unwrap();
            let mut ending = FinishingTime {
                samples: [1000, 1000, final_time],
                next: 0,
            };
            let error = admitted
                .complete_genesis(&mut ending, &mut owner)
                .unwrap_err();
            assert_eq!(
                error,
                if final_time == 999 {
                    Error::Clock
                } else {
                    Error::Expired
                }
            );
            assert_eq!(owner.final_checks, 1);
        }
    }
);

shared!(
    fresh_owner_floor_ahead_of_local_clock_refuses_admission_and_outputs,
    {
        let (_, prf, sealed, mut time) = fixture().await;
        let inspector = CheckpointInspector::new(&prf, COMMUNITY).unwrap();
        let pending = inspector.pending_creation(&sealed).unwrap();
        let mut owner = CompletionOwner::new(&pending, time.clone());
        owner.observed.0.set(1001);
        assert_eq!(
            pending
                .authorize_completion(intent(), &mut time, &mut owner)
                .await
                .unwrap_err(),
            Error::Clock
        );
        assert_eq!(owner.final_checks, 0);

        let pending = inspector.pending_creation(&sealed).unwrap();
        let mut owner = CompletionOwner::new(&pending, time.clone());
        let admitted = pending
            .authorize_completion(intent(), &mut time, &mut owner)
            .await
            .unwrap();
        owner.observed.0.set(1001);
        assert_eq!(
            admitted
                .complete_genesis(&mut time, &mut owner)
                .unwrap_err(),
            Error::Clock
        );
        assert_eq!(owner.final_checks, 1);

        // A reopened exact intent still needs a new independent owner observation;
        // the old successful admission cannot stand in for its newer floor.
        let pending = CheckpointInspector::new(&prf, COMMUNITY)
            .unwrap()
            .pending_creation(&sealed)
            .unwrap();
        let mut owner = CompletionOwner::new(&pending, time.clone());
        owner.observed.0.set(1002);
        assert_eq!(
            pending
                .authorize_completion(intent(), &mut time, &mut owner)
                .await
                .unwrap_err(),
            Error::Clock
        );
    }
);

shared!(
    pending_completion_keeps_the_original_authenticated_passkey_reference,
    {
        let (keys, prf, _, mut time) = fixture().await;
        let original = keys.loaded().unwrap();
        let mut metadata = original.metadata.clone();
        // Authenticate another original DeviceInfo reference with the real owner
        // format. Same member/root/device/receipt alone cannot admit key substitution.
        metadata.info = DeviceInfo::new("fixture", b"other credential").unwrap();
        let sealed = reseal(&prf, &metadata, &original.material);
        let pending = CheckpointInspector::new(&prf, COMMUNITY)
            .unwrap()
            .pending_creation(&sealed)
            .unwrap();
        let mut owner = CompletionOwner::new(&pending, time.clone());
        assert_eq!(
            pending
                .authorize_completion(intent(), &mut time, &mut owner)
                .await
                .unwrap_err(),
            Error::Unauthorized
        );
        assert_eq!(owner.final_checks, 0);
    }
);

shared!(
    initial_reader_opens_only_the_original_signed_record_without_borrowing_completion,
    {
        let (mut keys, prf, sealed, mut time) = fixture().await;
        let pending = CheckpointInspector::new(&prf, COMMUNITY)
            .unwrap()
            .pending_creation(&sealed)
            .unwrap();
        let mut owner = CompletionOwner::new(&pending, time.clone());
        let completion = pending
            .authorize_completion(intent(), &mut time, &mut owner)
            .await
            .unwrap();
        let reader = completion.lineage_reader().unwrap();
        assert_eq!(format!("{reader:?}"), "InitialLineageReader([redacted])");
        let (descriptor, value) = completion.complete_genesis(&mut time, &mut owner).unwrap();
        assert_eq!(reader.owner().value(), &descriptor.owner);
        let schema = descriptor.validate(&Verify).unwrap();
        assert_eq!(schema, cdht::Schema::dflt(1).unwrap());
        value
            .validate(&descriptor.key(), &descriptor.owner, &schema, 0, &Verify)
            .unwrap();
        assert_eq!(
            &*reader.open(&value.nonce.unwrap(), &value.data).unwrap(),
            PAYLOAD
        );
        // This reader is not a current writer or member grant. The original
        // Keys owner still has its unchanged pending output and denies Use.
        let original_receipt = keys.pending_output().await.unwrap().unwrap();
        assert_eq!(original_receipt, owner.receipt);
        drop(reader);
        assert_eq!(
            keys.pending_output().await.unwrap().unwrap(),
            original_receipt
        );
        assert_eq!(keys.store.0.borrow().get(&owner.location).unwrap(), &sealed);
        assert_eq!(keys.lineage().await.unwrap_err(), Error::Unauthorized);
        assert_eq!(keys.authority.calls.get(), 2);
    }
);

shared!(
    current_completion_check_keeps_latest_floor_and_refusal_is_terminal,
    {
        let (_, prf, sealed, mut time) = fixture().await;
        for failure in 0..5 {
            time.0.set(1000);
            let pending = CheckpointInspector::new(&prf, COMMUNITY)
                .unwrap()
                .pending_creation(&sealed)
                .unwrap();
            let mut owner = CompletionOwner::new(&pending, time.clone());
            let mut completion = pending
                .authorize_completion(intent(), &mut time, &mut owner)
                .await
                .unwrap();
            time.0.set(1020);
            assert_eq!(
                completion.check_current(&mut time, &mut owner).unwrap(),
                1020
            );
            assert_eq!(owner.final_checks, 1);
            let expected = match failure {
                0 => {
                    time.0.set(1010);
                    Error::Clock
                }
                1 => {
                    time.0.set(1060);
                    Error::Expired
                }
                2 => {
                    owner.observed.0.set(1021);
                    Error::Clock
                }
                3 => {
                    owner.mode.set(4);
                    Error::Unauthorized
                }
                4 => {
                    owner.credential = b"other credential".to_vec();
                    Error::Unauthorized
                }
                _ => unreachable!(),
            };
            assert_eq!(
                completion.check_current(&mut time, &mut owner).unwrap_err(),
                expected
            );
            assert_eq!(
                completion.lineage_reader().unwrap_err(),
                Error::Unauthorized
            );
            let checks = owner.final_checks;
            time.0.set(1030);
            owner.mode.set(0);
            owner.observed.0.set(1000);
            owner.credential = b"credential".to_vec();
            assert_eq!(
                completion.check_current(&mut time, &mut owner),
                Err(Error::Unauthorized)
            );
            assert_eq!(owner.final_checks, checks);
            assert_eq!(
                completion
                    .complete_genesis(&mut time, &mut owner)
                    .unwrap_err(),
                Error::Unauthorized
            );
        }
    }
);

shared!(
    current_check_samples_after_owner_and_genesis_samples_after_crypto,
    {
        let (_, prf, sealed, mut time) = fixture().await;
        for completed in [999, 1060] {
            time.0.set(1000);
            let pending = CheckpointInspector::new(&prf, COMMUNITY)
                .unwrap()
                .pending_creation(&sealed)
                .unwrap();
            let mut owner = CompletionOwner::new(&pending, time.clone());
            let mut completion = pending
                .authorize_completion(intent(), &mut time, &mut owner)
                .await
                .unwrap();
            let mut ending = FinishingTime {
                samples: [1000, completed, completed],
                next: 0,
            };
            assert_eq!(
                completion
                    .check_current(&mut ending, &mut owner)
                    .unwrap_err(),
                if completed == 999 {
                    Error::Clock
                } else {
                    Error::Expired
                }
            );
            assert_eq!(
                completion.check_current(&mut time, &mut owner),
                Err(Error::Unauthorized)
            );
            assert_eq!(owner.final_checks, 1);
        }
        let pending = CheckpointInspector::new(&prf, COMMUNITY)
            .unwrap()
            .pending_creation(&sealed)
            .unwrap();
        let mut owner = CompletionOwner::new(&pending, time.clone());
        let completion = pending
            .authorize_completion(intent(), &mut time, &mut owner)
            .await
            .unwrap();
        // Signing starts after a successful completion observation at 1020;
        // rolling back to 1010 still after original 1000 must not release bytes.
        let mut ending = FinishingTime {
            samples: [1000, 1020, 1010],
            next: 0,
        };
        assert_eq!(
            completion
                .complete_genesis(&mut ending, &mut owner)
                .unwrap_err(),
            Error::Clock
        );
        assert_eq!(owner.final_checks, 1);
    }
);

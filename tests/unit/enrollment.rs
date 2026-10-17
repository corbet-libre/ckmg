//! Original codec, private random candidate and atomic standalone checkpoint.
//! Strict synthetic activation inputs prove no HTTPS, compound CWST or G3 grant.
use super::*;
use futures::{FutureExt, executor::block_on};
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    rc::Rc,
};

const COMMUNITY: &str = "initial-enrollment";
const REFERENCE: &[u8] = b"original credential";

#[derive(Clone)]
struct Time {
    now: Rc<Cell<u64>>,
    fail: Rc<Cell<bool>>,
}
impl Default for Time {
    fn default() -> Self {
        Self {
            now: Rc::new(Cell::new(1000)),
            fail: Rc::new(Cell::new(false)),
        }
    }
}
impl Clock for Time {
    fn now(&mut self) -> Result<u64, Error> {
        if self.fail.get() {
            Err(Error::Unavailable)
        } else {
            Ok(self.now.get())
        }
    }
}
#[derive(Clone, Default)]
struct Memory {
    rows: Rc<RefCell<HashMap<Locator, Vec<u8>>>>,
    mode: Rc<Cell<u8>>,
    clock_failure: Rc<Cell<bool>>,
    writes: Rc<Cell<usize>>,
}
impl SecureStore for Memory {
    async fn load(&mut self, location: &Locator) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.rows.borrow().get(location).cloned())
    }
    async fn compare_exchange(
        &mut self,
        location: &Locator,
        expected: Option<[u8; 32]>,
        next: &[u8],
    ) -> Result<Commit, Error> {
        if self
            .rows
            .borrow()
            .get(location)
            .map(|bytes| *blake3::hash(bytes).as_bytes())
            != expected
        {
            return Ok(Commit::Conflict);
        }
        if self.mode.get() == 1 {
            return Ok(Commit::Conflict);
        }
        if self.mode.get() == 4 {
            futures::future::pending::<()>().await;
        }
        self.rows.borrow_mut().insert(*location, next.to_vec());
        self.writes.set(self.writes.get() + 1);
        match self.mode.get() {
            2 => Ok(Commit::Unknown),
            3 => {
                futures::future::pending::<()>().await;
                unreachable!()
            }
            5 => {
                self.clock_failure.set(true);
                Ok(Commit::Committed)
            }
            _ => Ok(Commit::Committed),
        }
    }
}
struct Deny;
impl Authority for Deny {
    async fn check(&mut self, _: Authorization<'_>) -> Result<(), Error> {
        Err(Error::Unauthorized)
    }
}
struct Owner {
    binding: Binding,
    device: PublicKey,
    reference: Vec<u8>,
    seed: [u8; 32],
    operation: OperationId,
    location: Locator,
    sealed_digest: [u8; 32],
    durable: crate::InitialActivationIntent,
    mode: Rc<Cell<u8>>,
    checks: usize,
    final_checks: usize,
}
impl Owner {
    fn new(candidate: &UnenrolledCreation) -> Self {
        Self {
            binding: candidate.metadata.lineage.binding.clone(),
            device: vld0::public_key(&candidate.material.device),
            reference: candidate.metadata.info.authority_reference().to_vec(),
            seed: candidate.commitment().unwrap(),
            operation: candidate.metadata.output.as_ref().unwrap().operation,
            location: candidate.location,
            sealed_digest: *blake3::hash(candidate.as_bytes()).as_bytes(),
            // This strict fixture's retained generation/digest is not a real
            // compound outer Store; that composition belongs to CVLT tests.
            durable: crate::InitialActivationIntent {
                generation: 1,
                digest: [87; 32],
            },
            mode: Rc::new(Cell::new(0)),
            checks: 0,
            final_checks: 0,
        }
    }
    fn exact(&self, r: &crate::InitialActivationAuthorization<'_>) -> Result<(), Error> {
        if r.binding != &self.binding
            || r.device != self.device
            || r.authority_reference != self.reference.as_slice()
            || r.seed != &self.seed
            || r.operation != self.operation
            || r.location != &self.location
            || r.sealed_digest != &self.sealed_digest
            || r.durable.generation != self.durable.generation
            || r.durable.digest != self.durable.digest
            || r.now != 1000
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}
impl Authority for Owner {
    async fn check(&mut self, _: Authorization<'_>) -> Result<(), Error> {
        Err(Error::Unauthorized)
    }
    async fn check_initial_activation(
        &mut self,
        request: crate::InitialActivationAuthorization<'_>,
    ) -> Result<u64, Error> {
        self.checks += 1;
        self.exact(&request)?;
        if self.mode.get() == 1 {
            futures::future::pending::<()>().await;
        }
        Ok(1000)
    }
    fn check_initial_activation_current(
        &mut self,
        request: crate::InitialActivationAuthorization<'_>,
    ) -> Result<u64, Error> {
        self.final_checks += 1;
        self.exact(&request)?;
        if self.final_checks == 2 {
            if self.mode.get() == 2 {
                return Err(Error::Revoked);
            }
            if self.mode.get() == 3 {
                return Ok(1001);
            }
        }
        Ok(1000)
    }
}
fn candidate(time: &mut Time) -> (PrfOutput, UnenrolledCreation) {
    let prf = PrfOutput::from_bytes(&[66; 32]).unwrap();
    let seed = EnrollmentSeed::new(
        Binding::new(COMMUNITY, "original member").unwrap(),
        &mut crate::SystemEntropy,
    )
    .unwrap();
    let commitment = seed.commitment().unwrap();
    let candidate = seed
        .seal(
            &prf,
            DeviceInfo::new("fixture", REFERENCE).unwrap(),
            time,
            &mut crate::SystemEntropy,
        )
        .unwrap();
    assert_eq!(candidate.commitment().unwrap(), commitment);
    (prf, candidate)
}
fn durable() -> crate::InitialActivationIntent {
    crate::InitialActivationIntent {
        generation: 1,
        digest: [87; 32],
    }
}
macro_rules! shared {
    ($name:ident,$body:block) => {
        #[cfg_attr(target_arch="wasm32", wasm_bindgen_test::wasm_bindgen_test)]
        #[cfg_attr(not(target_arch="wasm32"), test)]
        fn $name() { block_on(async $body); }
    };
}

shared!(revision_zero_never_opens_ordinary_or_provisional_custody, {
    let mut time = Time::default();
    let (prf, candidate) = candidate(&mut time);
    let inspector = CheckpointInspector::new(&prf, COMMUNITY).unwrap();
    assert!(inspector.inspect(candidate.as_bytes()).is_err());
    assert!(inspector.pending_creation(candidate.as_bytes()).is_err());
    assert!(
        inspector
            .read_lineage(candidate.as_bytes(), b"evidence", &mut time, &mut Deny)
            .await
            .is_err()
    );
    assert!(
        inspector
            .bootstrap(candidate.as_bytes(), b"evidence", &mut time, &mut Deny)
            .await
            .is_err()
    );
    let store = Memory::default();
    store
        .rows
        .borrow_mut()
        .insert(candidate.location, candidate.as_bytes().to_vec());
    let mut keys = Keys::new(store.clone(), time, crate::SystemEntropy, Deny);
    assert_eq!(keys.unlock(&prf, COMMUNITY).await, Err(Error::Encoding));
    assert_eq!(keys.state(), State::Locked);
    assert_eq!(store.writes.get(), 0);
});

shared!(
    reopening_keeps_frozen_root_operation_and_rejects_key_scope_or_accepted_state,
    {
        let mut time = Time::default();
        let (prf, candidate) = candidate(&mut time);
        let source = candidate.as_bytes().to_vec();
        let seed = candidate.commitment().unwrap();
        let expected = candidate.metadata.output.as_ref().unwrap().clone();
        for _ in 0..2 {
            let reopened = UnenrolledCreation::reopen(&prf, COMMUNITY, &source).unwrap();
            assert_eq!(reopened.as_bytes(), source);
            assert_eq!(reopened.commitment().unwrap(), seed);
            assert_eq!(reopened.metadata.output.as_ref().unwrap(), &expected);
        }
        assert!(
            UnenrolledCreation::reopen(
                &PrfOutput::from_bytes(&[67; 32]).unwrap(),
                COMMUNITY,
                &source
            )
            .is_err()
        );
        assert!(UnenrolledCreation::reopen(&prf, "other scope", &source).is_err());
        let mut damaged = source.clone();
        *damaged.last_mut().unwrap() ^= 1;
        assert!(UnenrolledCreation::reopen(&prf, COMMUNITY, &damaged).is_err());
        let owner = Owner::new(&candidate);
        let store = Memory::default();
        let challenge = candidate.passkey_challenge().unwrap();
        let mut keys = Keys::new(store.clone(), time, crate::SystemEntropy, owner);
        let activated = keys.activate_initial(candidate, durable()).await.unwrap();
        assert_eq!(activated, expected);
        // The pre-activation challenge is exactly the activated receipt's challenge.
        assert_eq!(activated.passkey_challenge().unwrap(), challenge);
        assert_eq!(keys.authority.checks, 1);
        assert_eq!(keys.authority.final_checks, 2);
        let accepted = store
            .rows
            .borrow()
            .get(&keys.loaded().unwrap().location)
            .unwrap()
            .clone();
        let nonce = CHECKPOINT_HEADER.len();
        assert_ne!(&source[nonce..nonce + 24], &accepted[nonce..nonce + 24]);
        assert!(UnenrolledCreation::reopen(&prf, COMMUNITY, &accepted).is_err());
        let original_candidate = UnenrolledCreation::reopen(&prf, COMMUNITY, &source).unwrap();
        let inspector = CheckpointInspector::new(&prf, COMMUNITY).unwrap();
        assert!(
            original_candidate.matches_pending(&inspector.pending_creation(&accepted).unwrap())
        );
        // DeviceInfo is authenticated by the checkpoint but is not included in
        // the public receipt. Preserve every real signature and original root,
        // operation and locator while changing only the retained raw key ID.
        let open = keys.loaded().unwrap();
        let mut metadata = open.metadata.clone();
        metadata.info = DeviceInfo::new("fixture", b"other credential").unwrap();
        let mut substituted = CHECKPOINT_HEADER.to_vec();
        substituted.extend(
            keyring::seal(
                &mut crate::SystemEntropy,
                &open.key,
                &checkpoint_aad(open.location),
                &encode_checkpoint(&metadata, &open.material).unwrap(),
            )
            .unwrap(),
        );
        let other = inspector.pending_creation(&substituted).unwrap();
        assert_eq!(other.receipt(), &expected);
        assert_eq!(other.location(), &original_candidate.location);
        assert!(!original_candidate.matches_pending(&other));
        assert_eq!(keys.pending_output().await.unwrap().unwrap(), expected);
        assert_eq!(keys.lineage().await.unwrap_err(), Error::Unauthorized);
    }
);

shared!(
    activation_defaults_and_wrong_original_fields_refuse_before_persistence,
    {
        let mut time = Time::default();
        let (_, unaccepted) = candidate(&mut time);
        let store = Memory::default();
        let mut keys = Keys::new(store.clone(), time.clone(), crate::SystemEntropy, Deny);
        assert_eq!(
            keys.activate_initial(unaccepted, durable()).await,
            Err(Error::Unauthorized)
        );
        assert_eq!(store.writes.get(), 0);
        for mismatch in 0..9 {
            let (_, unaccepted) = candidate(&mut time);
            let mut owner = Owner::new(&unaccepted);
            match mismatch {
                0 => owner.reference = b"equal-standing different key".to_vec(),
                1 => owner.seed[0] ^= 1,
                2 => owner.binding = Binding::new("other scope", "original member").unwrap(),
                3 => owner.operation = OperationId([99; 32]),
                4 => owner.device = vld0::public_key(&Zeroizing::new([98; 32])),
                5 => owner.location = Locator([97; 32]),
                6 => owner.sealed_digest[0] ^= 1,
                7 => owner.durable.generation += 1,
                8 => owner.durable.digest[0] ^= 1,
                _ => unreachable!(),
            }
            let store = Memory::default();
            let mut keys = Keys::new(store.clone(), time.clone(), crate::SystemEntropy, owner);
            assert_eq!(
                keys.activate_initial(unaccepted, durable()).await,
                Err(Error::Unauthorized)
            );
            assert_eq!(store.writes.get(), 0);
            assert!(store.rows.borrow().is_empty());
        }
    }
);

shared!(
    lost_activation_reply_cannot_reactivate_or_recreate_a_root,
    {
        for mode in [2, 3] {
            let mut time = Time::default();
            let (prf, unaccepted) = candidate(&mut time);
            let original = unaccepted.as_bytes().to_vec();
            let expected = unaccepted.metadata.output.as_ref().unwrap().clone();
            let location = unaccepted.location;
            let owner = Owner::new(&unaccepted);
            let store = Memory::default();
            store.mode.set(mode);
            let mut keys = Keys::new(store.clone(), time.clone(), crate::SystemEntropy, owner);
            let attempt = keys.activate_initial(unaccepted, durable());
            if mode == 3 {
                assert!(attempt.now_or_never().is_none());
            } else {
                assert_eq!(attempt.await, Err(Error::Reconcile));
            }
            assert_eq!(keys.state(), State::Reconcile);
            assert!(keys.pending_output().await.is_err());
            assert_eq!(store.writes.get(), 1);
            let reopened = UnenrolledCreation::reopen(&prf, COMMUNITY, &original).unwrap();
            let owner = Owner::new(&reopened);
            let mut retry = Keys::new(store.clone(), time.clone(), crate::SystemEntropy, owner);
            assert_eq!(
                retry.activate_initial(reopened, durable()).await,
                Err(Error::RootExists)
            );
            assert_eq!(store.writes.get(), 1);
            // Explicit ordinary checkpoint reopen recovers the original committed
            // receipt; it never recreates the consumed initial genesis marker.
            let mut recovered = Keys::new(store.clone(), time, crate::SystemEntropy, Deny);
            recovered.unlock(&prf, COMMUNITY).await.unwrap();
            assert_eq!(recovered.pending_output().await.unwrap().unwrap(), expected);
            assert!(recovered.genesis.is_none());
            assert!(
                UnenrolledCreation::reopen(
                    &prf,
                    COMMUNITY,
                    store.rows.borrow().get(&location).unwrap()
                )
                .is_err()
            );
        }
    }
);

shared!(
    cancelled_uncommitted_activation_reopens_only_the_same_candidate,
    {
        for waiting_on_owner in [true, false] {
            let mut time = Time::default();
            let (prf, unaccepted) = candidate(&mut time);
            let original = unaccepted.as_bytes().to_vec();
            let expected = unaccepted.metadata.output.as_ref().unwrap().clone();
            let owner = Owner::new(&unaccepted);
            let store = Memory::default();
            if waiting_on_owner {
                owner.mode.set(1);
            } else {
                store.mode.set(4);
            }
            let mut keys = Keys::new(store.clone(), time.clone(), crate::SystemEntropy, owner);
            assert!(
                keys.activate_initial(unaccepted, durable())
                    .now_or_never()
                    .is_none()
            );
            assert_eq!(store.writes.get(), 0);
            assert!(store.rows.borrow().is_empty());
            let reopened = UnenrolledCreation::reopen(&prf, COMMUNITY, &original).unwrap();
            let owner = Owner::new(&reopened);
            store.mode.set(0);
            let mut retry = Keys::new(store.clone(), time, crate::SystemEntropy, owner);
            assert_eq!(
                retry.activate_initial(reopened, durable()).await.unwrap(),
                expected
            );
            assert_eq!(store.writes.get(), 1);
        }
    }
);

shared!(
    postcas_clock_authority_and_owner_floor_failures_lock_the_original_keys,
    {
        for failure in 0..3 {
            let mut time = Time::default();
            let (_, unaccepted) = candidate(&mut time);
            let owner = Owner::new(&unaccepted);
            let mut store = Memory::default();
            if failure == 0 {
                store.mode.set(5);
                store.clock_failure = time.fail.clone();
            } else {
                owner.mode.set(if failure == 1 { 2 } else { 3 });
            }
            let mut keys = Keys::new(store.clone(), time, crate::SystemEntropy, owner);
            assert_eq!(
                keys.activate_initial(unaccepted, durable()).await,
                Err(match failure {
                    0 => Error::Unavailable,
                    1 => Error::Revoked,
                    _ => Error::Clock,
                })
            );
            assert_eq!(keys.state(), State::Locked);
            assert_eq!(store.writes.get(), 1);
            assert!(keys.genesis.is_none());
            assert!(keys.pending_output().await.is_err());
            assert!(keys.open.is_none());
        }
    }
);

shared!(
    authenticated_nonoriginal_revision_zero_material_refuses_reopen,
    {
        let mut time = Time::default();
        let (prf, original) = candidate(&mut time);
        for malformed in 0..4 {
            let mut metadata = original.metadata.clone();
            let mut material = original.material.clone();
            match malformed {
                0 => metadata.output.as_mut().unwrap().operation = OperationId([0; 32]),
                1 => {
                    material.root = Some(Zeroizing::new([0; 32]));
                    material.identity = material.root.clone();
                }
                2 => material.identity = Some(Zeroizing::new([77; 32])),
                3 => material.history.push((1, Zeroizing::new([78; 32]))),
                _ => unreachable!(),
            }
            // Keep both actual upstream signatures valid for the modified private
            // material. Refusal must target the original creation invariants, not
            // merely a stale signature left behind by a metadata mutation.
            metadata.lineage.root = vld0::public_key(material.root().unwrap());
            metadata.lineage.identity = material.identity.as_ref().map(vld0::public_key);
            metadata.lineage.signature = vld0::sign(
                material.root().unwrap(),
                &metadata.lineage.signed_bytes().unwrap(),
            )
            .unwrap();
            let receipt = metadata.output.as_mut().unwrap();
            receipt.change = Change::Created(metadata.lineage.clone());
            let device = vld0::public_key(&material.device);
            receipt.attestation = Some(DeviceAttestation {
                device,
                signature: vld0::sign(
                    &material.device,
                    &receipt.attestation_bytes(device).unwrap(),
                )
                .unwrap(),
            });
            let mut sealed = CHECKPOINT_HEADER.to_vec();
            sealed.extend(
                keyring::seal(
                    &mut crate::SystemEntropy,
                    &original.key,
                    &checkpoint_aad(original.location),
                    &encode_checkpoint(&metadata, &material).unwrap(),
                )
                .unwrap(),
            );
            assert_eq!(
                UnenrolledCreation::reopen(&prf, COMMUNITY, &sealed).unwrap_err(),
                Error::Unauthorized
            );
        }
    }
);

shared!(pre_activation_device_signatures_bind_exactly_one_purpose, {
    let mut time = Time::default();
    let (prf, candidate) = candidate(&mut time);
    let device = *passkey::device_public_key(&prf, COMMUNITY).unwrap().value();
    let payload = b"community, challenge and key";
    let purposes = [
        DevicePurpose::DeviceJoin,
        DevicePurpose::DeviceSession,
        DevicePurpose::SaltDerivation,
    ];
    let tags: Vec<&[u8]> = purposes.iter().map(|purpose| purpose.tag()).collect();
    assert_eq!(
        tags,
        [
            &b"cvld.device-join.v1\0"[..],
            b"cvld.device-session.v1\0",
            b"cmsg.device-join.salt.v1\0"
        ]
    );
    for purpose in purposes {
        let signature = candidate.sign_device(purpose, payload).unwrap();
        // Valid under its own tag only: never over the bare payload ...
        let signed = [purpose.tag(), &payload[..]].concat();
        vld0::verify_ed25519(&device, &signed, &signature).unwrap();
        assert!(vld0::verify_ed25519(&device, payload, &signature).is_err());
        // ... and never as another purpose.
        for other in purposes.into_iter().filter(|other| *other != purpose) {
            let as_other = [other.tag(), &payload[..]].concat();
            assert!(vld0::verify_ed25519(&device, &as_other, &signature).is_err());
        }
    }
    // After activation the unlocked passkey session signs the session message with the same
    // key and tag (a restarted device-key member), and only that purpose.
    assert_eq!(
        passkey::sign_device_session(&prf, COMMUNITY, payload).unwrap(),
        candidate
            .sign_device(DevicePurpose::DeviceSession, payload)
            .unwrap()
    );
    assert!(
        passkey::sign_device_session(&prf, "another-community", payload).unwrap()
            != candidate
                .sign_device(DevicePurpose::DeviceSession, payload)
                .unwrap()
    );
    // The opening signer also rebuilds the salt signature (same bytes as before activation)
    // and never signs the join.
    assert_eq!(
        passkey::sign_device_opened(&prf, COMMUNITY, DevicePurpose::SaltDerivation, payload)
            .unwrap(),
        candidate
            .sign_device(DevicePurpose::SaltDerivation, payload)
            .unwrap()
    );
    assert_eq!(
        passkey::sign_device_opened(&prf, COMMUNITY, DevicePurpose::DeviceJoin, payload),
        Err(Error::Unauthorized)
    );
    let session_limit = MAX_MESSAGE_BYTES - DevicePurpose::DeviceSession.tag().len();
    assert_eq!(
        passkey::sign_device_session(&prf, COMMUNITY, &vec![0; session_limit + 1]),
        Err(Error::Limit)
    );
    // The same device key that activation keeps (the lineage's only device).
    let lineage = &candidate.metadata.lineage;
    assert_eq!(
        lineage.devices,
        [passkey::device_public_key(&prf, COMMUNITY).unwrap()]
    );
    let limit = MAX_MESSAGE_BYTES - DevicePurpose::SaltDerivation.tag().len();
    assert!(
        candidate
            .sign_device(DevicePurpose::SaltDerivation, &vec![0; limit])
            .is_ok()
    );
    assert_eq!(
        candidate.sign_device(DevicePurpose::SaltDerivation, &vec![0; limit + 1]),
        Err(Error::Limit)
    );
});

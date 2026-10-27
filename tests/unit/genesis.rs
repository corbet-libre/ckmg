//! Real Keys and original CDHT crypto, with exact synthetic registration and
//! genesis admission inputs. This is not production certificate/HTTPS evidence.
use super::*;
use futures::{FutureExt, executor::block_on};
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    rc::Rc,
};

#[derive(Clone, Default)]
struct Memory {
    data: Rc<RefCell<HashMap<Locator, Vec<u8>>>>,
    pause_reads: Rc<Cell<bool>>,
    reads: Rc<futures::lock::Mutex<()>>,
}
impl SecureStore for Memory {
    async fn load(&mut self, location: &Locator) -> Result<Option<Vec<u8>>, Error> {
        if self.pause_reads.get() {
            let _held = self.reads.lock().await;
        }
        Ok(self.data.borrow().get(location).cloned())
    }
    async fn compare_exchange(
        &mut self,
        location: &Locator,
        expected: Option<[u8; 32]>,
        next: &[u8],
    ) -> Result<Commit, Error> {
        let mut data = self.data.borrow_mut();
        if data
            .get(location)
            .map(|value| *blake3::hash(value).as_bytes())
            != expected
        {
            return Ok(Commit::Conflict);
        }
        data.insert(*location, next.to_vec());
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

const PAYLOAD: &[u8] = b"exact packed certified genesis fixture";
struct Owner {
    binding: Binding,
    device: PublicKey,
    created: bool,
    receipt: Rc<RefCell<Option<Receipt>>>,
    mode: Rc<Cell<u8>>,
    time: Time,
    store: Memory,
    location: Locator,
    final_checks: Rc<Cell<usize>>,
}
impl Authority for Owner {
    async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        if request.binding != &self.binding
            || request.device != self.device
            || request.target.is_some()
            || request.statement.is_some()
            || request.signing.is_some()
        {
            return Err(Error::Unauthorized);
        }
        if !self.created
            && request.action == Action::Create
            && request.root.is_none()
            && request.epoch == 0
            && request.now == 1000
            && request.evidence == b"registration"
        {
            self.created = true;
            return Ok(());
        }
        // One exact current-Use fixture only, to exercise marker destruction.
        let receipt = self.receipt.borrow();
        if request.action == Action::Use
            && request.evidence.is_empty()
            && receipt
                .as_ref()
                .is_some_and(|receipt| match &receipt.change {
                    Change::Created(lineage) => {
                        request.root == Some(lineage.root) && request.epoch == lineage.epoch
                    }
                    _ => false,
                })
        {
            return Ok(());
        }
        Err(Error::Unauthorized)
    }
    async fn check_genesis(
        &mut self,
        request: crate::GenesisAuthorization<'_>,
    ) -> Result<(), Error> {
        if self.receipt.borrow().as_ref() != Some(request.receipt)
            || request.authority_reference != b"credential"
            || request.evidence != PAYLOAD
            || request.now != 1000
            || request.expires != 1060
        {
            return Err(Error::Unauthorized);
        }
        match self.mode.get() {
            1 => futures::future::pending::<()>().await,
            2 => self.time.0.set(1060),
            3 => self.time.0.set(999),
            4 => {
                *self
                    .store
                    .data
                    .borrow_mut()
                    .get_mut(&self.location)
                    .unwrap()
                    .last_mut()
                    .unwrap() ^= 1;
            }
            5 => return Err(Error::Unavailable),
            7 => self.store.pause_reads.set(true),
            10 => return Err(Error::Revoked),
            _ => (),
        }
        Ok(())
    }
    fn check_genesis_current(
        &mut self,
        request: crate::GenesisAuthorization<'_>,
    ) -> Result<(), Error> {
        self.final_checks.set(self.final_checks.get() + 1);
        match self.mode.get() {
            8 => return Err(Error::Revoked),
            9 => return Err(Error::Unavailable),
            _ => (),
        }
        if self.receipt.borrow().as_ref() != Some(request.receipt)
            || request.authority_reference != b"credential"
            || request.evidence != PAYLOAD
            || request.now != 1000
            || request.expires != 1060
            || self.mode.get() == 6
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}
type Machine = Keys<Memory, Time, crate::SystemEntropy, Owner>;
async fn fixture() -> (Machine, PrfOutput, Receipt, Rc<Cell<u8>>) {
    fixture_with_reference(b"credential").await
}
async fn fixture_with_reference(reference: &[u8]) -> (Machine, PrfOutput, Receipt, Rc<Cell<u8>>) {
    let prf = PrfOutput::from_bytes(&[29; 32]).unwrap();
    let binding = Binding::new("genesis", "fixture").unwrap();
    let store = Memory::default();
    let time = Time(Rc::new(Cell::new(1000)));
    let receipt = Rc::new(RefCell::new(None));
    let mode = Rc::new(Cell::new(0));
    let mut keys = Keys::new(
        store.clone(),
        time.clone(),
        crate::SystemEntropy,
        Owner {
            binding: binding.clone(),
            device: passkey::device_public_key(&prf, "genesis").unwrap(),
            created: false,
            receipt: receipt.clone(),
            mode: mode.clone(),
            time,
            store,
            location: passkey::vault_location(&prf, "genesis").unwrap(),
            final_checks: Rc::new(Cell::new(0)),
        },
    );
    let original = keys
        .create_scope(
            &prf,
            binding,
            DeviceInfo::new("fixture", reference).unwrap(),
            b"registration",
        )
        .await
        .unwrap();
    *receipt.borrow_mut() = Some(original.clone());
    (keys, prf, original, mode)
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
    immutable_publication_commitment_binds_original_exact_intent,
    {
        let (keys, _, receipt, _) = fixture().await;
        let nonce = [61; 24];
        let commitment = receipt
            .initial_publication_commitment(&nonce, PAYLOAD, 1000, 1060)
            .unwrap();
        let restored: Receipt =
            serde_json::from_slice(&serde_json::to_vec(&receipt).unwrap()).unwrap();
        assert_eq!(
            restored
                .initial_publication_commitment(&nonce, PAYLOAD, 1000, 1060)
                .unwrap(),
            commitment
        );
        for (other_nonce, evidence, start, end) in [
            ([62; 24], PAYLOAD, 1000, 1060),
            (nonce, b"different packed evidence".as_slice(), 1000, 1060),
            (nonce, PAYLOAD, 1001, 1060),
            (nonce, PAYLOAD, 1000, 1061),
        ] {
            assert_ne!(
                receipt
                    .initial_publication_commitment(&other_nonce, evidence, start, end)
                    .unwrap(),
                commitment
            );
        }
        for binding in [false, true] {
            let mut changed = receipt.clone();
            if binding {
                let Change::Created(lineage) = &mut changed.change else {
                    unreachable!()
                };
                lineage.binding = Binding::new("other-community", "fixture").unwrap();
                lineage.signature = vld0::sign(
                    keys.loaded().unwrap().material.root().unwrap(),
                    &lineage.signed_bytes().unwrap(),
                )
                .unwrap();
            } else {
                changed.operation = OperationId([63; 32]);
            }
            let device = changed.attestation.as_ref().unwrap().device;
            changed.attestation.as_mut().unwrap().signature = vld0::sign(
                &keys.loaded().unwrap().material.device,
                &changed.attestation_bytes(device).unwrap(),
            )
            .unwrap();
            assert_ne!(
                changed
                    .initial_publication_commitment(&nonce, PAYLOAD, 1000, 1060)
                    .unwrap(),
                commitment
            );
        }
        assert!(
            receipt
                .initial_publication_commitment(&nonce, &[], 1000, 1060)
                .is_err()
        );
        assert!(
            receipt
                .initial_publication_commitment(&nonce, PAYLOAD, 1060, 1060)
                .is_err()
        );
        assert!(
            receipt
                .initial_publication_commitment(
                    &nonce,
                    &vec![1; cdht::MAX_SUBKEY_SIZE + 1],
                    1000,
                    1060
                )
                .is_err()
        );
    }
);

shared!(
    only_original_fixed_genesis_descriptor_and_encrypted_value_escape,
    {
        let (mut keys, _, receipt, _) = fixture().await;
        assert_eq!(keys.pending_output().await.unwrap(), Some(receipt.clone()));
        let read = inspection::lineage_secret(
            keys.loaded().unwrap().material.root().unwrap(),
            &keys.loaded().unwrap().metadata.lineage,
        )
        .unwrap();
        let (descriptor, value) = keys
            .prepare_genesis_record(&receipt, PAYLOAD, 1060)
            .await
            .unwrap();
        let schema = descriptor.validate(&Verify).unwrap();
        assert_eq!(schema, cdht::Schema::dflt(1).unwrap());
        assert_eq!(
            descriptor.owner,
            *keys.loaded().unwrap().metadata.lineage.root.value()
        );
        assert_eq!(value.seq, 0);
        assert_eq!(value.writer, descriptor.owner);
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
        assert_ne!(value.data.as_slice(), PAYLOAD);
        let mut corrupted = value.clone();
        corrupted.data[0] ^= 1;
        assert!(
            corrupted
                .validate(&descriptor.key(), &descriptor.owner, &schema, 0, &Verify)
                .is_err()
        );
        assert_eq!(
            keys.prepare_genesis_record(&receipt, PAYLOAD, 1060)
                .await
                .err(),
            Some(Error::Unauthorized)
        );
        assert_eq!(keys.pending_output().await.unwrap(), Some(receipt));
    }
);

shared!(
    tampering_and_invalid_bounds_consume_the_only_genesis_attempt,
    {
        for case in 0..4 {
            let (mut keys, _, receipt, _) = fixture().await;
            let mut submitted = receipt.clone();
            match case {
                0 => submitted.operation = OperationId([77; 32]),
                1 => submitted.attestation = None,
                _ => (),
            }
            let evidence = if case == 2 {
                b"different bytes".as_slice()
            } else if case == 3 {
                b"".as_slice()
            } else {
                PAYLOAD
            };
            assert!(
                keys.prepare_genesis_record(&submitted, evidence, 1060)
                    .await
                    .is_err()
            );
            assert!(keys.genesis.is_none());
            assert_eq!(
                keys.prepare_genesis_record(&receipt, PAYLOAD, 1060)
                    .await
                    .err(),
                Some(Error::Unauthorized)
            );
        }
    }
);

shared!(
    authority_wait_cancellation_expiry_clock_and_changed_checkpoint_withhold_outputs,
    {
        for case in 1..=5 {
            let (mut keys, _, receipt, mode) = fixture().await;
            mode.set(case);
            let mut attempt = Box::pin(keys.prepare_genesis_record(&receipt, PAYLOAD, 1060));
            if case == 1 {
                assert!(attempt.as_mut().now_or_never().is_none());
                drop(attempt);
            } else {
                let expected = [
                    Error::Expired,
                    Error::Clock,
                    Error::Reconcile,
                    Error::Unavailable,
                ][usize::from(case - 2)];
                assert_eq!(attempt.await.err(), Some(expected));
            }
            assert!(keys.genesis.is_none());
            assert_eq!(
                keys.prepare_genesis_record(&receipt, PAYLOAD, 1060)
                    .await
                    .err(),
                Some(Error::Unauthorized)
            );
        }
    }
);

shared!(
    unlock_and_normal_member_use_never_recreate_genesis_admission,
    {
        for reopen in [false, true] {
            let (mut keys, prf, receipt, _) = fixture().await;
            if reopen {
                keys.lock();
                keys.unlock(&prf, "genesis").await.unwrap();
            } else {
                keys.lineage().await.unwrap();
            }
            assert!(keys.genesis.is_none());
            assert_eq!(
                keys.prepare_genesis_record(&receipt, PAYLOAD, 1060)
                    .await
                    .err(),
                Some(Error::Unauthorized)
            );
        }
    }
);

shared!(
    final_current_owner_refusal_after_store_wait_consumes_the_attempt_without_outputs,
    {
        for change_clock in [false, true] {
            let (mut keys, _, receipt, mode) = fixture().await;
            let reads = keys.store.reads.clone();
            let final_checks = keys.authority.final_checks.clone();
            let clock = keys.clock.clone();
            let held = reads.lock().await;
            mode.set(7);
            let mut attempt = Box::pin(keys.prepare_genesis_record(&receipt, PAYLOAD, 1060));
            assert!(attempt.as_mut().now_or_never().is_none());
            assert_eq!(final_checks.get(), 0);
            if change_clock {
                clock.0.set(1001);
            } else {
                mode.set(6);
            }
            drop(held);
            assert_eq!(attempt.await.err(), Some(Error::Unauthorized));
            assert_eq!(final_checks.get(), 1);
            assert!(keys.genesis.is_none());
            assert_eq!(
                keys.prepare_genesis_record(&receipt, PAYLOAD, 1060)
                    .await
                    .err(),
                Some(Error::Unauthorized)
            );
        }
    }
);

struct DefaultRefusal;
impl Authority for DefaultRefusal {
    async fn check(&mut self, _: Authorization<'_>) -> Result<(), Error> {
        Err(Error::Unauthorized)
    }
}
shared!(existing_authorities_refuse_both_genesis_ports_by_default, {
    let (_, _, receipt, _) = fixture().await;
    let mut owner = DefaultRefusal;
    assert_eq!(
        owner
            .check_genesis(crate::GenesisAuthorization {
                receipt: &receipt,
                authority_reference: b"credential",
                evidence: PAYLOAD,
                now: 1000,
                expires: 1060
            })
            .await,
        Err(Error::Unauthorized)
    );
    assert_eq!(
        owner.check_genesis_current(crate::GenesisAuthorization {
            receipt: &receipt,
            authority_reference: b"credential",
            evidence: PAYLOAD,
            now: 1000,
            expires: 1060
        }),
        Err(Error::Unauthorized)
    );
});

shared!(
    original_genesis_reference_cannot_be_replaced_by_another_current_passkey,
    {
        let (mut keys, _, receipt, _) = fixture_with_reference(b"other credential").await;
        assert_eq!(
            keys.prepare_genesis_record(&receipt, PAYLOAD, 1060)
                .await
                .err(),
            Some(Error::Unauthorized)
        );
        assert_eq!(keys.authority.final_checks.get(), 0);
    }
);

/// Install the caller-mutated `lineage` (re-signed with `root`) into `receipt`
/// and re-sign the attestation over the updated bytes, so the receipt verifies
/// as a whole and reaches the shape check under test.
fn resign_created(keys: &Machine, receipt: &mut Receipt, lineage: &mut Lineage, root: &Secret) {
    lineage.signature = vld0::sign(root, &lineage.signed_bytes().unwrap()).unwrap();
    let Change::Created(into) = &mut receipt.change else {
        unreachable!()
    };
    *into = lineage.clone();
    let device = keys.loaded().unwrap().material.device.clone();
    let author = receipt.attestation.as_ref().unwrap().device;
    receipt.attestation.as_mut().unwrap().signature =
        vld0::sign(&device, &receipt.attestation_bytes(author).unwrap()).unwrap();
}

shared!(
    exact_max_evidence_is_accepted_while_empty_and_oversize_are_limited,
    {
        let (_, _, receipt, _) = fixture().await;
        let nonce = [61; 24];
        // Exactly MAX_SUBKEY_SIZE bytes are accepted, not limited.
        receipt
            .initial_publication_commitment(&nonce, &vec![7; cdht::MAX_SUBKEY_SIZE], 1000, 1060)
            .unwrap();
        // Empty and oversize evidence are both Error::Limit, never silent acceptance
        // or a later authority refusal.
        for evidence in [Vec::new(), vec![7; cdht::MAX_SUBKEY_SIZE + 1]] {
            let (mut keys, _, receipt, _) = fixture().await;
            assert_eq!(
                keys.prepare_genesis_record(&receipt, &evidence, 1060)
                    .await
                    .err(),
                Some(Error::Limit)
            );
        }
        // Exactly MAX_SUBKEY_SIZE bytes pass the bound; the fixture authority still
        // refuses the unknown evidence, proving the bound itself did not fire.
        let (mut keys, _, receipt, _) = fixture().await;
        assert_eq!(
            keys.prepare_genesis_record(&receipt, &vec![7; cdht::MAX_SUBKEY_SIZE], 1060)
                .await
                .err(),
            Some(Error::Unauthorized)
        );
    }
);

shared!(commitment_rejects_any_single_attested_field_mismatch, {
    // Epoch-only mismatch.
    let (keys, _, receipt, _) = fixture().await;
    let root = keys.loaded().unwrap().material.root().unwrap().clone();
    let mut changed = receipt.clone();
    let Change::Created(lineage) = changed.change.clone() else {
        unreachable!()
    };
    let mut epoch = lineage.clone();
    epoch.epoch = 2;
    resign_created(&keys, &mut changed, &mut epoch, &root);
    assert!(
        changed
            .initial_publication_commitment(&[61; 24], PAYLOAD, 1000, 1060)
            .is_err()
    );
    // Revision-only mismatch.
    let mut revision = lineage.clone();
    revision.revision = 2;
    resign_created(&keys, &mut changed, &mut revision, &root);
    assert!(
        changed
            .initial_publication_commitment(&[61; 24], PAYLOAD, 1000, 1060)
            .is_err()
    );
    // Devices-only mismatch: the author plus one fresh key.
    let fresh = vld0::public_key(&vld0::random_secret(&mut crate::SystemEntropy).unwrap());
    let mut devices = lineage.clone();
    devices.devices.push(fresh);
    devices.devices.sort();
    resign_created(&keys, &mut changed, &mut devices, &root);
    assert!(
        changed
            .initial_publication_commitment(&[61; 24], PAYLOAD, 1000, 1060)
            .is_err()
    );
});

shared!(
    initial_check_binds_operation_and_stamp_before_created_shape,
    {
        let (keys, _, receipt, _) = fixture().await;
        let open = keys.loaded().unwrap();
        let initial = InitialPublication::new(receipt.operation, open.stamp);
        assert!(initial.check(open, &receipt).is_ok());
        // Operation mismatch alone refuses, even with a matching stamp.
        let mut bad_op = receipt.clone();
        bad_op.operation = OperationId([63; 32]);
        assert_eq!(
            initial.check(open, &bad_op).err(),
            Some(Error::Unauthorized)
        );
        // Stamp mismatch alone refuses, even with a matching operation.
        let mut bad_open = open.clone();
        bad_open.stamp = [64; 32];
        assert_eq!(
            initial.check(&bad_open, &receipt).err(),
            Some(Error::Unauthorized)
        );
        // A matching operation and stamp still refuse a non-Created receipt.
        let mut bad_change = receipt.clone();
        let Change::Created(lineage) = bad_change.change.clone() else {
            unreachable!()
        };
        bad_change.change = Change::Restored(lineage);
        assert_eq!(
            initial.check(open, &bad_change).err(),
            Some(Error::Unauthorized)
        );
    }
);

shared!(created_shape_refuses_each_condition_alone, {
    let (keys, _, receipt, _) = fixture().await;
    let open = keys.loaded().unwrap();
    let (metadata, material) = (open.metadata.clone(), open.material.clone());
    assert!(check_created(&metadata, &material, &receipt).is_ok());
    // Revoked alone refuses, with correct output and no pairing.
    let mut revoked = metadata.clone();
    revoked.revoked = true;
    assert_eq!(
        check_created(&revoked, &material, &receipt).err(),
        Some(Error::Unauthorized)
    );
    // Pairing alone refuses, with correct output and no revocation.
    let mut pairing = metadata.clone();
    pairing.pairing = Some(PairingRequest {
        version: 1,
        binding: metadata.lineage.binding.clone(),
        root: metadata.lineage.root,
        epoch: 1,
        device: receipt.attestation.as_ref().unwrap().device,
        nonce: [0; 32],
        issued_at: 1000,
        expires_at: 1300,
        proof: receipt.attestation.as_ref().unwrap().signature.clone(),
    });
    assert_eq!(
        check_created(&pairing, &material, &receipt).err(),
        Some(Error::Unauthorized)
    );
    let root = keys.loaded().unwrap().material.root().unwrap().clone();
    // Receipt lineage differing from the checkpoint lineage refuses, even though
    // the attestation matches the receipt.
    let mut changed = receipt.clone();
    let Change::Created(lineage) = changed.change.clone() else {
        unreachable!()
    };
    let mut other = lineage.clone();
    other.binding = Binding::new("other", "fixture").unwrap();
    resign_created(&keys, &mut changed, &mut other, &root);
    // The pending output is the mutated receipt itself, so the check reaches the
    // lineage comparison instead of refusing on output identity.
    let mut output = metadata.clone();
    output.output = Some(changed.clone());
    assert_eq!(
        check_created(&output, &material, &changed).err(),
        Some(Error::Unauthorized)
    );
    // Devices differing from exactly the attested author refuse. The checkpoint
    // carries the same device list, isolating the devices comparison.
    let fresh = vld0::public_key(&vld0::random_secret(&mut crate::SystemEntropy).unwrap());
    let mut changed = receipt.clone();
    let mut extra = lineage.clone();
    extra.devices.push(fresh);
    extra.devices.sort();
    resign_created(&keys, &mut changed, &mut extra, &root);
    let mut devices = metadata.clone();
    devices.lineage = extra.clone();
    devices.output = Some(changed.clone());
    assert_eq!(
        check_created(&devices, &material, &changed).err(),
        Some(Error::Unauthorized)
    );
    // A device key that is not the attested author's refuses.
    let mut other_device = material.clone();
    other_device.device = vld0::random_secret(&mut crate::SystemEntropy).unwrap();
    assert_eq!(
        check_created(&metadata, &other_device, &receipt).err(),
        Some(Error::Unauthorized)
    );
    // A root key that did not sign the lineage refuses.
    let mut other_root = material.clone();
    other_root.root = Some(vld0::random_secret(&mut crate::SystemEntropy).unwrap());
    assert_eq!(
        check_created(&metadata, &other_root, &receipt).err(),
        Some(Error::Unauthorized)
    );
});

shared!(
    genesis_authority_outcome_is_preserved_with_exact_custody_state,
    {
        // A first-check Revoked is preserved and revokes custody.
        let (mut keys, _, receipt, mode) = fixture().await;
        mode.set(10);
        assert_eq!(
            keys.prepare_genesis_record(&receipt, PAYLOAD, 1060)
                .await
                .err(),
            Some(Error::Revoked)
        );
        assert_eq!(keys.state(), State::Revoked);
        // A first-check Unavailable locks custody without revoking it.
        let (mut keys, _, receipt, mode) = fixture().await;
        mode.set(5);
        assert_eq!(
            keys.prepare_genesis_record(&receipt, PAYLOAD, 1060)
                .await
                .err(),
            Some(Error::Unavailable)
        );
        assert_eq!(keys.state(), State::Locked);
        // A final-check Revoked is preserved and revokes custody.
        let (mut keys, _, receipt, mode) = fixture().await;
        mode.set(8);
        assert_eq!(
            keys.prepare_genesis_record(&receipt, PAYLOAD, 1060)
                .await
                .err(),
            Some(Error::Revoked)
        );
        assert_eq!(keys.state(), State::Revoked);
        // A final-check Unavailable is preserved and locks custody.
        let (mut keys, _, receipt, mode) = fixture().await;
        mode.set(9);
        assert_eq!(
            keys.prepare_genesis_record(&receipt, PAYLOAD, 1060)
                .await
                .err(),
            Some(Error::Unavailable)
        );
        assert_eq!(keys.state(), State::Locked);
    }
);

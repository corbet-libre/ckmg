//! Original ACK encryption/CAS and immutable completion binding. This uses the
//! strict completion fixture; it is not current HTTPS or Charter qualification.
use super::*;

struct InterruptedStore {
    memory: Memory,
    cut: u8,
}

struct SampledClock {
    samples: std::collections::VecDeque<u64>,
    time: Time,
}
impl Clock for SampledClock {
    fn now(&mut self) -> Result<u64, Error> {
        let now = self.samples.pop_front().unwrap_or(self.time.0.get());
        self.time.0.set(now);
        Ok(now)
    }
}

shared!(
    higher_keys_sample_fences_completion_and_post_cas_rollback_is_terminal,
    {
        let (old, prf, sealed, mut time) = fixture().await;
        let memory = old.store.clone();
        let pending = CheckpointInspector::new(&prf, COMMUNITY)
            .unwrap()
            .pending_creation(&sealed)
            .unwrap();
        let mut owner = CompletionOwner::new(&pending, time.clone());
        let mut completion = pending
            .authorize_completion(intent(), &mut time, &mut owner)
            .await
            .unwrap();
        drop(old);
        let clock = SampledClock {
            // Unlock; completion start/end; newer Keys sample; rolled-back CAS completion.
            samples: [1000, 1000, 1000, 1020, 1010].into(),
            time: time.clone(),
        };
        let mut keys = Keys::new(memory, clock, crate::SystemEntropy, owner);
        keys.unlock(&prf, COMMUNITY).await.unwrap();
        assert_eq!(
            keys.acknowledge_initial(&mut completion).await,
            Err(Error::Reconcile)
        );
        assert_eq!(keys.state(), State::Reconcile);
        assert!(completion.initial_acknowledgment().is_err());
        assert!(completion.lineage_reader().is_err());
        time.0.set(1030);
        assert_eq!(
            completion.check_current(&mut time, &mut keys.authority),
            Err(Error::Unauthorized)
        );
    }
);

struct DelayedStore {
    memory: Memory,
    time: Time,
    mode: Rc<Cell<u8>>,
    revoke: bool,
}
impl SecureStore for DelayedStore {
    async fn load(&mut self, location: &Locator) -> Result<Option<Vec<u8>>, Error> {
        self.memory.load(location).await
    }
    async fn compare_exchange(
        &mut self,
        location: &Locator,
        expected: Option<[u8; 32]>,
        next: &[u8],
    ) -> Result<Commit, Error> {
        let outcome = self
            .memory
            .compare_exchange(location, expected, next)
            .await?;
        if self.revoke {
            self.mode.set(4);
        } else {
            self.time.0.set(1060);
        }
        Ok(outcome)
    }
}

shared!(
    successful_cas_crossing_expiry_or_current_key_refusal_releases_no_live_keys,
    {
        for revoke in [false, true] {
            let (old, prf, sealed, mut time) = fixture().await;
            let memory = old.store.clone();
            let inspector = CheckpointInspector::new(&prf, COMMUNITY).unwrap();
            let pending = inspector.pending_creation(&sealed).unwrap();
            let mut owner = CompletionOwner::new(&pending, time.clone());
            let mut completion = pending
                .authorize_completion(intent(), &mut time, &mut owner)
                .await
                .unwrap();
            let receipt = completion.receipt().clone();
            let mode = owner.mode.clone();
            drop(old);
            let mut keys = Keys::new(
                DelayedStore {
                    memory: memory.clone(),
                    time: time.clone(),
                    mode,
                    revoke,
                },
                time.clone(),
                crate::SystemEntropy,
                owner,
            );
            keys.unlock(&prf, COMMUNITY).await.unwrap();
            assert_eq!(
                keys.acknowledge_initial(&mut completion).await,
                Err(Error::Reconcile)
            );
            assert_eq!(keys.state(), State::Reconcile);
            assert!(keys.pending_output().await.is_err());
            assert!(completion.initial_acknowledgment().is_err());
            // The actually committed historical bytes remain, but their public
            // inspection grants no current Use or permission to bypass revoked keys.
            let winner = memory
                .0
                .borrow()
                .get(&passkey::vault_location(&prf, COMMUNITY).unwrap())
                .unwrap()
                .clone();
            assert!(
                inspector
                    .initial_acknowledgment(&winner, &receipt, PAYLOAD)
                    .is_ok()
            );
        }
    }
);
impl SecureStore for InterruptedStore {
    async fn load(&mut self, location: &Locator) -> Result<Option<Vec<u8>>, Error> {
        self.memory.load(location).await
    }
    async fn compare_exchange(
        &mut self,
        location: &Locator,
        expected: Option<[u8; 32]>,
        next: &[u8],
    ) -> Result<Commit, Error> {
        if self.cut == 0 {
            futures::future::pending::<()>().await;
        }
        let result = self
            .memory
            .compare_exchange(location, expected, next)
            .await?;
        if self.cut == 1 {
            futures::future::pending::<()>().await;
        }
        if self.cut == 2 {
            return Err(Error::Unavailable);
        }
        Ok(result)
    }
}

shared!(
    initial_ack_cancellation_and_lost_reply_reopen_only_the_actual_cas_winner,
    {
        for cut in 0..3 {
            let (old, prf, sealed, mut time) = fixture().await;
            let memory = old.store.clone();
            let inspector = CheckpointInspector::new(&prf, COMMUNITY).unwrap();
            let pending = inspector.pending_creation(&sealed).unwrap();
            let mut owner = CompletionOwner::new(&pending, time.clone());
            let mut completion = pending
                .authorize_completion(intent(), &mut time, &mut owner)
                .await
                .unwrap();
            let receipt = completion.receipt().clone();
            drop(old);
            let mut keys = Keys::new(
                InterruptedStore {
                    memory: memory.clone(),
                    cut,
                },
                time.clone(),
                crate::SystemEntropy,
                owner,
            );
            keys.unlock(&prf, COMMUNITY).await.unwrap();
            if cut < 2 {
                assert!(
                    keys.acknowledge_initial(&mut completion)
                        .now_or_never()
                        .is_none()
                );
            } else {
                assert_eq!(
                    keys.acknowledge_initial(&mut completion).await,
                    Err(Error::Reconcile)
                );
            }
            assert_eq!(keys.state(), State::Reconcile);
            assert!(completion.initial_acknowledgment().is_err());
            assert!(completion.lineage_reader().is_err());
            drop(keys);
            drop(completion);
            let winner = memory
                .0
                .borrow()
                .get(&passkey::vault_location(&prf, COMMUNITY).unwrap())
                .unwrap()
                .clone();
            if cut == 0 {
                assert_eq!(winner, sealed);
                assert_eq!(
                    inspector
                        .initial_acknowledgment(&winner, &receipt, PAYLOAD)
                        .unwrap_err(),
                    Error::Pending
                );
            } else {
                assert_ne!(winner, sealed);
                assert_eq!(
                    inspector
                        .initial_acknowledgment(&winner, &receipt, PAYLOAD)
                        .unwrap()
                        .operation(),
                    receipt.operation
                );
                assert_eq!(inspector.inspect(&winner).unwrap().revision(), 2);
            }
        }
    }
);

shared!(
    initial_ack_survives_restart_without_renewing_the_completion,
    {
        let (keys, prf, sealed, mut time) = fixture().await;
        let store = keys.store.clone();
        let inspector = CheckpointInspector::new(&prf, COMMUNITY).unwrap();
        let pending = inspector.pending_creation(&sealed).unwrap();
        let mut owner = CompletionOwner::new(&pending, time.clone());
        let mut completion = pending
            .authorize_completion(intent(), &mut time, &mut owner)
            .await
            .unwrap();
        let expected = completion.initial_acknowledgment().unwrap();
        let receipt = completion.receipt().clone();
        assert_eq!(
            inspector
                .initial_acknowledgment(&sealed, &receipt, PAYLOAD)
                .unwrap_err(),
            Error::Pending
        );
        drop(keys);
        let mut keys = Keys::new(store.clone(), time.clone(), crate::SystemEntropy, owner);
        keys.unlock(&prf, COMMUNITY).await.unwrap();
        keys.acknowledge_initial(&mut completion).await.unwrap();
        assert!(keys.pending_output().await.unwrap().is_none());
        let acknowledged = store
            .0
            .borrow()
            .get(&passkey::vault_location(&prf, COMMUNITY).unwrap())
            .unwrap()
            .clone();
        drop(keys);
        drop(completion);
        time.0.set(2000);
        let reopened = CheckpointInspector::new(&prf, COMMUNITY).unwrap();
        let actual = reopened
            .initial_acknowledgment(&acknowledged, &receipt, PAYLOAD)
            .unwrap();
        assert_eq!(actual.to_bytes().unwrap(), expected.to_bytes().unwrap());
        assert_eq!(actual.operation(), receipt.operation);
        // The authenticated ACK is the restored device's only route to a join signature: the
        // device key's DeviceJoin signature (the opening signs only the session).
        let device = passkey::device_public_key(&prf, COMMUNITY).unwrap();
        let signature = actual
            .sign_device_join_restored(&prf, COMMUNITY, PAYLOAD)
            .unwrap();
        let tagged = [crate::DeviceFormat::DeviceJoin.tag(), PAYLOAD].concat();
        vld0::verify_ed25519(device.value(), &tagged, &signature).unwrap();
        // X3 M4: the provenance binds its own location and device. A scope-A provenance
        // never signs a join for another community or another PRF, and the creation-time
        // provenance (no acknowledged checkpoint yet) signs nothing.
        assert!(
            actual
                .sign_device_join_restored(&prf, "another-community", PAYLOAD)
                .is_err()
        );
        let other = passkey::PrfOutput::from_bytes(&[0x5a; 32]).unwrap();
        assert!(
            actual
                .sign_device_join_restored(&other, COMMUNITY, PAYLOAD)
                .is_err()
        );
        assert!(
            expected
                .sign_device_join_restored(&prf, COMMUNITY, PAYLOAD)
                .is_err()
        );
        assert_eq!(reopened.inspect(&acknowledged).unwrap().revision(), 2);
        assert_eq!(
            reopened
                .initial_acknowledgment(&acknowledged, &receipt, b"changed evidence")
                .unwrap_err(),
            Error::Unauthorized
        );
        let mut wrong = receipt.clone();
        wrong.operation = OperationId([77; 32]);
        assert!(
            reopened
                .initial_acknowledgment(&acknowledged, &wrong, PAYLOAD)
                .is_err()
        );
        assert_eq!(
            format!("{actual:?}"),
            "InitialCheckpointProvenance([redacted])"
        );
    }
);

shared!(
    initial_ack_refuses_expired_or_substituted_completion_without_mutation,
    {
        for changed in [false, true] {
            let (keys, prf, sealed, mut time) = fixture().await;
            let store = keys.store.clone();
            let pending = CheckpointInspector::new(&prf, COMMUNITY)
                .unwrap()
                .pending_creation(&sealed)
                .unwrap();
            let mut owner = CompletionOwner::new(&pending, time.clone());
            let mut completion = pending
                .authorize_completion(intent(), &mut time, &mut owner)
                .await
                .unwrap();
            drop(keys);
            let mut keys = Keys::new(store.clone(), time.clone(), crate::SystemEntropy, owner);
            keys.unlock(&prf, COMMUNITY).await.unwrap();
            if changed {
                keys.authority.credential = b"other key".to_vec();
            } else {
                time.0.set(1060);
            }
            assert!(keys.acknowledge_initial(&mut completion).await.is_err());
            assert_eq!(
                store
                    .0
                    .borrow()
                    .get(&passkey::vault_location(&prf, COMMUNITY).unwrap())
                    .unwrap(),
                &sealed
            );
            assert!(completion.initial_acknowledgment().is_err());
        }
    }
);

shared!(
    legacy_ack_and_later_mutation_cannot_retain_initial_approval,
    {
        let (mut legacy, prf, sealed, mut time) = fixture().await;
        let inspector = CheckpointInspector::new(&prf, COMMUNITY).unwrap();
        let receipt = legacy.pending_output().await.unwrap().unwrap();
        legacy.acknowledge(receipt.operation).await.unwrap();
        let old = legacy
            .store
            .0
            .borrow()
            .get(&passkey::vault_location(&prf, COMMUNITY).unwrap())
            .unwrap()
            .clone();
        assert_eq!(
            inspector
                .initial_acknowledgment(&old, &receipt, PAYLOAD)
                .unwrap_err(),
            Error::Unauthorized
        );
        // Restore the original pending source in an independent actual store, then
        // exercise the same owner preparation path used by subsequent mutations.
        let store = Memory::default();
        store.0.borrow_mut().insert(
            passkey::vault_location(&prf, COMMUNITY).unwrap(),
            sealed.clone(),
        );
        let pending = inspector.pending_creation(&sealed).unwrap();
        let mut owner = CompletionOwner::new(&pending, time.clone());
        let mut completion = pending
            .authorize_completion(intent(), &mut time, &mut owner)
            .await
            .unwrap();
        let mut keys = Keys::new(store, time.clone(), crate::SystemEntropy, owner);
        keys.unlock(&prf, COMMUNITY).await.unwrap();
        keys.acknowledge_initial(&mut completion).await.unwrap();
        let original = keys.loaded().unwrap().clone();
        assert!(original.metadata.initial.is_some());
        keys.prepare(original.clone(), Some(original.stamp), None)
            .unwrap();
        keys.commit().await.unwrap();
        let later = keys
            .store
            .0
            .borrow()
            .get(&original.location)
            .unwrap()
            .clone();
        assert_eq!(inspector.inspect(&later).unwrap().revision(), 3);
        assert_eq!(
            inspector
                .initial_acknowledgment(&later, &receipt, PAYLOAD)
                .unwrap_err(),
            Error::Unauthorized
        );
        assert_eq!(keys.loaded().unwrap().metadata.version, 1);
    }
);

shared!(provenance_binds_exact_seed_publication_and_bytes, {
    let (_, prf, sealed, mut time) = fixture().await;
    let pending = CheckpointInspector::new(&prf, COMMUNITY)
        .unwrap()
        .pending_creation(&sealed)
        .unwrap();
    let mut owner = CompletionOwner::new(&pending, time.clone());
    let completion = pending
        .authorize_completion(intent(), &mut time, &mut owner)
        .await
        .unwrap();
    let provenance = completion.initial_acknowledgment().unwrap();
    let receipt = completion.receipt().clone();
    // The seed is the exact enrollment commitment, never a constant.
    let (lineage, _) = receipt.attested_lineage().unwrap();
    let expected_seed = crate::keys::enrollment::commitment(
        &lineage.binding,
        &completion.source.root,
        receipt.operation,
    )
    .unwrap();
    assert_eq!(provenance.seed(), expected_seed);
    assert_ne!(provenance.seed(), [0; 32]);
    assert_ne!(provenance.seed(), [1; 32]);
    // The publication is the exact initial-publication commitment, never a constant.
    let intent = intent();
    let expected_publication = receipt
        .initial_publication_commitment(
            &intent.nonce,
            &intent.packed_evidence,
            intent.prepared_at,
            intent.expires,
        )
        .unwrap();
    assert_eq!(provenance.publication(), expected_publication);
    assert_ne!(provenance.publication(), [0; 32]);
    assert_ne!(provenance.publication(), [1; 32]);
    // The canonical bytes are nonempty real facts, never a constant.
    let bytes = provenance.to_bytes().unwrap();
    assert!(bytes.len() > 1);
    assert_ne!(bytes, vec![0u8]);
    assert_ne!(bytes, vec![1u8]);
});

shared!(
    stored_initial_validate_refuses_a_single_metadata_version_mismatch,
    {
        let (keys, prf, sealed, mut time) = fixture().await;
        let store = keys.store.clone();
        let pending = CheckpointInspector::new(&prf, COMMUNITY)
            .unwrap()
            .pending_creation(&sealed)
            .unwrap();
        let mut owner = CompletionOwner::new(&pending, time.clone());
        let mut completion = pending
            .authorize_completion(intent(), &mut time, &mut owner)
            .await
            .unwrap();
        drop(keys);
        let mut keys = Keys::new(store.clone(), time.clone(), crate::SystemEntropy, owner);
        keys.unlock(&prf, COMMUNITY).await.unwrap();
        keys.acknowledge_initial(&mut completion).await.unwrap();
        let open = keys.loaded().unwrap().clone();
        let stored = open.metadata.initial.clone().unwrap();
        // Only the metadata version differs; every other validated fact is exact.
        let mut bad = open.metadata.clone();
        bad.version = 1;
        assert_eq!(
            stored.validate(&bad, &open.material),
            Err(Error::Unauthorized)
        );
        // Sanity: the exact acknowledged metadata validates.
        assert!(stored.validate(&open.metadata, &open.material).is_ok());
    }
);

shared!(
    initial_acknowledgment_refuses_a_resigned_lineage_with_an_added_delegate,
    {
        let (keys, prf, sealed, mut time) = fixture().await;
        let store = keys.store.clone();
        let inspector = CheckpointInspector::new(&prf, COMMUNITY).unwrap();
        let pending = inspector.pending_creation(&sealed).unwrap();
        let mut owner = CompletionOwner::new(&pending, time.clone());
        let mut completion = pending
            .authorize_completion(intent(), &mut time, &mut owner)
            .await
            .unwrap();
        let receipt = completion.receipt().clone();
        drop(keys);
        let mut keys = Keys::new(store.clone(), time.clone(), crate::SystemEntropy, owner);
        keys.unlock(&prf, COMMUNITY).await.unwrap();
        keys.acknowledge_initial(&mut completion).await.unwrap();
        let open = keys.loaded().unwrap().clone();
        // Re-sign the acknowledged lineage with one added delegate: receipt,
        // author, digest and publication still match, but the lineage does not.
        let delegate =
            passkey::device_public_key(&PrfOutput::from_bytes(&[9; 32]).unwrap(), COMMUNITY)
                .unwrap();
        let mut bad = open.metadata.clone();
        bad.lineage.delegates.push(delegate);
        bad.lineage.signature = vld0::sign(
            open.material.root().unwrap(),
            &bad.lineage.signed_bytes().unwrap(),
        )
        .unwrap();
        let resealed = reseal(&prf, &bad, &open.material);
        assert_eq!(
            inspector
                .initial_acknowledgment(&resealed, &receipt, PAYLOAD)
                .unwrap_err(),
            Error::Unauthorized
        );
    }
);

shared!(bind_acknowledgment_enforces_the_exact_clock_floor, {
    for (now, succeeds) in [(1000u64, true), (999u64, false)] {
        let (keys, prf, sealed, mut time) = fixture().await;
        let pending = CheckpointInspector::new(&prf, COMMUNITY)
            .unwrap()
            .pending_creation(&sealed)
            .unwrap();
        let mut owner = CompletionOwner::new(&pending, time.clone());
        let mut completion = pending
            .authorize_completion(intent(), &mut time, &mut owner)
            .await
            .unwrap();
        let current = keys.loaded().unwrap().clone();
        // Only the clock differs: 999 precedes the checked completion floor.
        if succeeds {
            assert!(completion.bind_acknowledgment(&current, now).is_ok());
        } else {
            assert!(matches!(
                completion.bind_acknowledgment(&current, now),
                Err(Error::Unauthorized)
            ));
        }
    }
});

shared!(
    acknowledgment_guard_finish_refuses_a_completion_before_its_floor,
    {
        let (_, prf, sealed, mut time) = fixture().await;
        let pending = CheckpointInspector::new(&prf, COMMUNITY)
            .unwrap()
            .pending_creation(&sealed)
            .unwrap();
        let mut owner = CompletionOwner::new(&pending, time.clone());
        let mut completion = pending
            .authorize_completion(intent(), &mut time, &mut owner)
            .await
            .unwrap();
        let guard = completion.acknowledgment_guard();
        assert_eq!(
            guard.finish(&mut time, &mut owner, 1001).unwrap_err(),
            Error::Clock
        );
    }
);

shared!(
    acknowledgment_guard_finish_accepts_a_completion_at_or_after_its_floor,
    {
        let (_, prf, sealed, mut time) = fixture().await;
        let pending = CheckpointInspector::new(&prf, COMMUNITY)
            .unwrap()
            .pending_creation(&sealed)
            .unwrap();
        let mut owner = CompletionOwner::new(&pending, time.clone());
        let mut completion = pending
            .authorize_completion(intent(), &mut time, &mut owner)
            .await
            .unwrap();
        let guard = completion.acknowledgment_guard();
        assert_eq!(guard.finish(&mut time, &mut owner, 999).unwrap(), 1000);
    }
);

shared!(
    initial_acknowledgment_enforces_packed_evidence_bounds_before_receipt_checks,
    {
        let (keys, prf, sealed, mut time) = fixture().await;
        let store = keys.store.clone();
        let inspector = CheckpointInspector::new(&prf, COMMUNITY).unwrap();
        let pending = inspector.pending_creation(&sealed).unwrap();
        let mut owner = CompletionOwner::new(&pending, time.clone());
        let mut completion = pending
            .authorize_completion(intent(), &mut time, &mut owner)
            .await
            .unwrap();
        let receipt = completion.receipt().clone();
        drop(keys);
        let mut keys = Keys::new(store.clone(), time.clone(), crate::SystemEntropy, owner);
        keys.unlock(&prf, COMMUNITY).await.unwrap();
        keys.acknowledge_initial(&mut completion).await.unwrap();
        let acknowledged = store
            .0
            .borrow()
            .get(&passkey::vault_location(&prf, COMMUNITY).unwrap())
            .unwrap()
            .clone();
        // Empty evidence is refused as Limit, not as a receipt mismatch.
        assert_eq!(
            inspector
                .initial_acknowledgment(&acknowledged, &receipt, &[])
                .unwrap_err(),
            Error::Limit
        );
        // Oversized evidence is refused as Limit.
        let oversized = vec![0u8; cdht::MAX_SUBKEY_SIZE + 1];
        assert_eq!(
            inspector
                .initial_acknowledgment(&acknowledged, &receipt, &oversized)
                .unwrap_err(),
            Error::Limit
        );
        // Boundary-size evidence passes the length gate and fails on the digest.
        let boundary = vec![0u8; cdht::MAX_SUBKEY_SIZE];
        assert_eq!(
            inspector
                .initial_acknowledgment(&acknowledged, &receipt, &boundary)
                .unwrap_err(),
            Error::Unauthorized
        );
    }
);

shared!(stored_initial_validate_refuses_a_single_output_mismatch, {
    let (keys, prf, sealed, mut time) = fixture().await;
    let store = keys.store.clone();
    let pending = CheckpointInspector::new(&prf, COMMUNITY)
        .unwrap()
        .pending_creation(&sealed)
        .unwrap();
    let mut owner = CompletionOwner::new(&pending, time.clone());
    let mut completion = pending
        .authorize_completion(intent(), &mut time, &mut owner)
        .await
        .unwrap();
    let receipt = completion.receipt().clone();
    drop(keys);
    let mut keys = Keys::new(store.clone(), time.clone(), crate::SystemEntropy, owner);
    keys.unlock(&prf, COMMUNITY).await.unwrap();
    keys.acknowledge_initial(&mut completion).await.unwrap();
    let open = keys.loaded().unwrap().clone();
    let stored = open.metadata.initial.clone().unwrap();
    // Only the output differs; every other validated fact is exact.
    let mut bad = open.metadata.clone();
    bad.output = Some(receipt);
    assert_eq!(
        stored.validate(&bad, &open.material),
        Err(Error::Unauthorized)
    );
});

shared!(stored_initial_validate_refuses_a_revoked_checkpoint, {
    let (keys, prf, sealed, mut time) = fixture().await;
    let store = keys.store.clone();
    let pending = CheckpointInspector::new(&prf, COMMUNITY)
        .unwrap()
        .pending_creation(&sealed)
        .unwrap();
    let mut owner = CompletionOwner::new(&pending, time.clone());
    let mut completion = pending
        .authorize_completion(intent(), &mut time, &mut owner)
        .await
        .unwrap();
    drop(keys);
    let mut keys = Keys::new(store.clone(), time.clone(), crate::SystemEntropy, owner);
    keys.unlock(&prf, COMMUNITY).await.unwrap();
    keys.acknowledge_initial(&mut completion).await.unwrap();
    let open = keys.loaded().unwrap().clone();
    let stored = open.metadata.initial.clone().unwrap();
    // Only the revocation flag differs; every other validated fact is exact.
    let mut bad = open.metadata.clone();
    bad.revoked = true;
    assert_eq!(
        stored.validate(&bad, &open.material),
        Err(Error::Unauthorized)
    );
});

shared!(
    stored_initial_validate_refuses_a_single_lineage_revision_mismatch,
    {
        let (keys, prf, sealed, mut time) = fixture().await;
        let store = keys.store.clone();
        let pending = CheckpointInspector::new(&prf, COMMUNITY)
            .unwrap()
            .pending_creation(&sealed)
            .unwrap();
        let mut owner = CompletionOwner::new(&pending, time.clone());
        let mut completion = pending
            .authorize_completion(intent(), &mut time, &mut owner)
            .await
            .unwrap();
        drop(keys);
        let mut keys = Keys::new(store.clone(), time.clone(), crate::SystemEntropy, owner);
        keys.unlock(&prf, COMMUNITY).await.unwrap();
        keys.acknowledge_initial(&mut completion).await.unwrap();
        let open = keys.loaded().unwrap().clone();
        let stored = open.metadata.initial.clone().unwrap();
        // Only the lineage revision differs; every other validated fact is exact.
        let mut bad = open.metadata.clone();
        bad.lineage.revision = 2;
        assert_eq!(
            stored.validate(&bad, &open.material),
            Err(Error::Unauthorized)
        );
    }
);

shared!(
    stored_initial_validate_refuses_a_nonempty_material_history,
    {
        let (keys, prf, sealed, mut time) = fixture().await;
        let store = keys.store.clone();
        let pending = CheckpointInspector::new(&prf, COMMUNITY)
            .unwrap()
            .pending_creation(&sealed)
            .unwrap();
        let mut owner = CompletionOwner::new(&pending, time.clone());
        let mut completion = pending
            .authorize_completion(intent(), &mut time, &mut owner)
            .await
            .unwrap();
        drop(keys);
        let mut keys = Keys::new(store.clone(), time.clone(), crate::SystemEntropy, owner);
        keys.unlock(&prf, COMMUNITY).await.unwrap();
        keys.acknowledge_initial(&mut completion).await.unwrap();
        let open = keys.loaded().unwrap().clone();
        let stored = open.metadata.initial.clone().unwrap();
        // Only the material history differs; every other validated fact is exact.
        let mut material = open.material.clone();
        material
            .history
            .push((2, vld0::random_secret(&mut crate::SystemEntropy).unwrap()));
        assert_eq!(
            stored.validate(&open.metadata, &material),
            Err(Error::Unauthorized)
        );
    }
);

shared!(stored_initial_validate_refuses_a_stale_last_time, {
    let (keys, prf, sealed, mut time) = fixture().await;
    let store = keys.store.clone();
    let pending = CheckpointInspector::new(&prf, COMMUNITY)
        .unwrap()
        .pending_creation(&sealed)
        .unwrap();
    let mut owner = CompletionOwner::new(&pending, time.clone());
    let mut completion = pending
        .authorize_completion(intent(), &mut time, &mut owner)
        .await
        .unwrap();
    drop(keys);
    let mut keys = Keys::new(store.clone(), time.clone(), crate::SystemEntropy, owner);
    keys.unlock(&prf, COMMUNITY).await.unwrap();
    keys.acknowledge_initial(&mut completion).await.unwrap();
    let open = keys.loaded().unwrap().clone();
    let stored = open.metadata.initial.clone().unwrap();
    // Only the clock floor differs; every other validated fact is exact.
    let mut bad = open.metadata.clone();
    bad.last_time = 999;
    assert_eq!(
        stored.validate(&bad, &open.material),
        Err(Error::Unauthorized)
    );
});

shared!(stored_initial_validate_refuses_a_foreign_lineage_binding, {
    let (keys, prf, sealed, mut time) = fixture().await;
    let store = keys.store.clone();
    let pending = CheckpointInspector::new(&prf, COMMUNITY)
        .unwrap()
        .pending_creation(&sealed)
        .unwrap();
    let mut owner = CompletionOwner::new(&pending, time.clone());
    let mut completion = pending
        .authorize_completion(intent(), &mut time, &mut owner)
        .await
        .unwrap();
    drop(keys);
    let mut keys = Keys::new(store.clone(), time.clone(), crate::SystemEntropy, owner);
    keys.unlock(&prf, COMMUNITY).await.unwrap();
    keys.acknowledge_initial(&mut completion).await.unwrap();
    let open = keys.loaded().unwrap().clone();
    let stored = open.metadata.initial.clone().unwrap();
    // Only the lineage binding differs, so only the seed check fails.
    let mut bad = open.metadata.clone();
    bad.lineage.binding = Binding::new(COMMUNITY, "other-member").unwrap();
    assert_eq!(
        stored.validate(&bad, &open.material),
        Err(Error::Unauthorized)
    );
});

shared!(bind_acknowledgment_refuses_a_relocated_checkpoint, {
    let (keys, prf, sealed, mut time) = fixture().await;
    let pending = CheckpointInspector::new(&prf, COMMUNITY)
        .unwrap()
        .pending_creation(&sealed)
        .unwrap();
    let mut owner = CompletionOwner::new(&pending, time.clone());
    let mut completion = pending
        .authorize_completion(intent(), &mut time, &mut owner)
        .await
        .unwrap();
    let mut current = keys.loaded().unwrap().clone();
    // Only the store location differs; clock, stamp and custody are exact.
    current.location =
        passkey::vault_location(&PrfOutput::from_bytes(&[9; 32]).unwrap(), COMMUNITY).unwrap();
    assert!(matches!(
        completion.bind_acknowledgment(&current, 1000),
        Err(Error::Unauthorized)
    ));
});

shared!(
    bind_acknowledgment_refuses_a_substituted_authority_reference,
    {
        let (keys, prf, sealed, mut time) = fixture().await;
        let pending = CheckpointInspector::new(&prf, COMMUNITY)
            .unwrap()
            .pending_creation(&sealed)
            .unwrap();
        let mut owner = CompletionOwner::new(&pending, time.clone());
        let mut completion = pending
            .authorize_completion(intent(), &mut time, &mut owner)
            .await
            .unwrap();
        let mut current = keys.loaded().unwrap().clone();
        // Only the authority reference differs; clock, stamp and store are exact.
        current.metadata.info = DeviceInfo::new("fixture", b"other credential").unwrap();
        assert!(matches!(
            completion.bind_acknowledgment(&current, 1000),
            Err(Error::Unauthorized)
        ));
    }
);

shared!(bind_acknowledgment_refuses_a_nonpending_revision, {
    let (keys, prf, sealed, mut time) = fixture().await;
    let pending = CheckpointInspector::new(&prf, COMMUNITY)
        .unwrap()
        .pending_creation(&sealed)
        .unwrap();
    let mut owner = CompletionOwner::new(&pending, time.clone());
    let mut completion = pending
        .authorize_completion(intent(), &mut time, &mut owner)
        .await
        .unwrap();
    let mut current = keys.loaded().unwrap().clone();
    // Only the revision differs; clock, stamp and custody are exact.
    current.metadata.revision = 2;
    assert!(matches!(
        completion.bind_acknowledgment(&current, 1000),
        Err(Error::Unauthorized)
    ));
});

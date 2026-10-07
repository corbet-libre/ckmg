//! Crate-internal scenarios for the custody state machine. They forge checkpoints,
//! grants and lineages with the deterministic test secrets, so they can reach the
//! refusals that follow an approved authority check. Every case asserts the exact
//! refusal and that storage and local state are unchanged.
use super::*;
use crate::tests::fixture::support::{Memory, Random, Time, binding, info, prf, purpose};
use crate::tests::fixture::{
    Gated, approve, ask, device_key, enroll, founder, gated, other_member, resigned, root_secret,
    scene, take, with_devices,
};
use futures::executor::block_on;

fn snapshot(machine: &Gated) -> (Metadata, Material) {
    let open = machine.open.as_ref().unwrap();
    (open.metadata.clone(), open.material.clone())
}

fn refused(metadata: &Metadata, material: &Material) -> Error {
    validate_checkpoint(metadata, material).unwrap_err()
}

fn plant(store: &Memory, n: u8, community: &str, plaintext: &[u8]) {
    let secret = prf(n);
    let location = passkey::vault_location(&secret, community).unwrap();
    let key = passkey::ring_key(&secret, community).unwrap();
    let mut sealed = CHECKPOINT_HEADER.to_vec();
    sealed.extend_from_slice(
        &keyring::seal(
            &mut Random::new(77),
            &key,
            &checkpoint_aad(location),
            plaintext,
        )
        .unwrap(),
    );
    store.0.borrow_mut().records.insert(location, sealed);
}

fn request_from(n: u8, pseudonym: crate::Binding, root: PublicKey, epoch: u64) -> PairingRequest {
    let material = Material::derive(&prf(n), "a", false).unwrap();
    let mut request = PairingRequest {
        version: 1,
        binding: pseudonym,
        root,
        epoch,
        device: vld0::public_key(&material.device),
        nonce: [5; 32],
        issued_at: 1000,
        expires_at: 1300,
        proof: Signature::new(VLD0, [0; 64]),
    };
    request.proof = vld0::sign(&material.device, &request.signed_bytes().unwrap()).unwrap();
    request
}

fn edited(lineage: &Lineage, secret: &Secret, edit: impl FnOnce(&mut Lineage)) -> Lineage {
    let mut copy = lineage.clone();
    edit(&mut copy);
    resigned(copy, secret)
}

#[test]
fn checkpoint_validation_refuses_every_inconsistent_combination() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let mut live = gated(&store, &time, 1);
        founder(&mut live).await;
        let (metadata, material) = snapshot(&live);
        validate_checkpoint(&metadata, &material).unwrap();
        let root = root_secret(1, "a", 1);
        let stranger = device_key(9, "a");

        let mut bad = metadata.clone();
        bad.version = 2;
        assert_eq!(refused(&bad, &material), Error::Encoding);
        let mut bad = metadata.clone();
        bad.revision = 0;
        assert_eq!(refused(&bad, &material), Error::Encoding);
        let mut bad = metadata.clone();
        bad.lineage.signature = Signature::new(VLD0, [0; 64]);
        assert_eq!(refused(&bad, &material), Error::BadSignature);

        // A root that is not the lineage root, and a device missing from the lineage.
        let mut wrong_root = material.clone();
        wrong_root.root = Some(Zeroizing::new([9u8; 32]));
        assert_eq!(refused(&metadata, &wrong_root), Error::Encoding);
        let mut bad = metadata.clone();
        bad.lineage = with_devices(metadata.lineage.clone(), &[stranger], &root);
        assert_eq!(refused(&bad, &material), Error::Encoding);

        // A pending device must match its persisted request in every field.
        let mut pending = gated(&store, &time, 2);
        ask(&mut pending, 2, &metadata.lineage).await;
        let (waiting, bare) = snapshot(&pending);
        validate_checkpoint(&waiting, &bare).unwrap();
        let own = vld0::public_key(&bare.device);
        let creator = vld0::public_key(&material.device);
        let mut bad = waiting.clone();
        bad.pairing.as_mut().unwrap().device = stranger;
        assert_eq!(refused(&bad, &bare), Error::Encoding);
        let mut bad = waiting.clone();
        bad.pairing.as_mut().unwrap().binding = other_member();
        assert_eq!(refused(&bad, &bare), Error::Encoding);
        let mut bad = waiting.clone();
        bad.pairing.as_mut().unwrap().root = stranger;
        assert_eq!(refused(&bad, &bare), Error::Encoding);
        let mut bad = waiting.clone();
        bad.pairing.as_mut().unwrap().epoch += 1;
        assert_eq!(refused(&bad, &bare), Error::Encoding);
        let mut bad = waiting.clone();
        bad.lineage = with_devices(waiting.lineage.clone(), &[creator, own], &root);
        assert_eq!(refused(&bad, &bare), Error::Encoding);
        let mut bad = waiting.clone();
        bad.pairing.as_mut().unwrap().proof = Signature::new(VLD0, [0; 64]);
        assert_eq!(refused(&bad, &bare), Error::BadSignature);
        let mut holds_root = bare.clone();
        holds_root.root = Some(Zeroizing::new([9u8; 32]));
        assert_eq!(refused(&waiting, &holds_root), Error::Encoding);

        // A revoked device keeps no root and is no longer listed.
        let mut revoked = waiting.clone();
        revoked.pairing = None;
        revoked.revoked = true;
        validate_checkpoint(&revoked, &bare).unwrap();
        let mut still_listed = revoked.clone();
        still_listed.lineage = with_devices(waiting.lineage.clone(), &[creator, own], &root);
        assert_eq!(refused(&still_listed, &bare), Error::Encoding);
        let mut idle = waiting.clone();
        idle.pairing = None;
        assert_eq!(refused(&idle, &bare), Error::Encoding);
    });
}

#[test]
fn forged_checkpoints_never_unlock() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let mut live = gated(&store, &time, 1);
        founder(&mut live).await;
        let (metadata, material) = snapshot(&live);
        let good = encode_checkpoint(&metadata, &material).unwrap();
        let fresh = Memory::default();
        let mut victim = gated(&fresh, &time, 4);

        // A checkpoint of another community, sealed under this community's key.
        plant(&fresh, 1, "b", &good);
        assert_eq!(victim.unlock(&prf(1), "b").await, Err(Error::Unauthorized));
        assert_eq!(victim.state(), State::Locked);

        let mut beyond = u32::MAX.to_le_bytes().to_vec();
        beyond.extend_from_slice(b"{}");
        let mut junk = 3u32.to_le_bytes().to_vec();
        junk.extend_from_slice(b"{ }");
        let mut short_material = good.to_vec();
        short_material.truncate(good.len() - 5);
        let mut inconsistent = metadata.clone();
        inconsistent.version = 2;
        let inconsistent = encode_checkpoint(&inconsistent, &material).unwrap();
        let plaintexts = [
            Vec::new(),
            vec![1u8, 2],
            beyond,
            junk,
            short_material,
            inconsistent.to_vec(),
        ];
        for (index, plaintext) in plaintexts.iter().enumerate() {
            plant(&fresh, 1, "a", plaintext);
            assert_eq!(
                victim.unlock(&prf(1), "a").await,
                Err(Error::Encoding),
                "case {index}"
            );
            assert_eq!(victim.state(), State::Locked);
        }
        assert_eq!(fresh.0.borrow().writes, 0);

        // The genuine record still opens afterwards.
        plant(&fresh, 1, "a", &good);
        victim.unlock(&prf(1), "a").await.unwrap();
        assert_eq!(victim.state(), State::Authorized);
    });
}

#[test]
fn restore_from_a_paired_grant_refuses_each_mismatch() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let mut a = gated(&store, &time, 1);
        let mut b = gated(&store, &time, 2);
        founder(&mut a).await;
        let grant = enroll(&mut a, &mut b, 2).await;
        let anchor = a.lineage().await.unwrap();
        assert_eq!(grant.lineage, anchor);
        let first = root_secret(1, "a", 1);
        let creator = device_key(1, "a");
        let stranger = device_key(9, "a");
        let outsider = Zeroizing::new([9u8; 32]);

        let mut variants: Vec<(PairingGrant, Error)> = Vec::new();
        let mut g = grant.clone();
        g.request.device = creator;
        variants.push((g, Error::Unauthorized));
        let mut g = grant.clone();
        g.request.binding = other_member();
        variants.push((g, Error::Unauthorized));
        let mut g = grant.clone();
        g.request.root = stranger;
        variants.push((g, Error::Unauthorized));
        let mut g = grant.clone();
        g.request.epoch = 9;
        variants.push((g, Error::Unauthorized));
        let mut g = grant.clone();
        g.lineage = edited(&grant.lineage, &first, |l| l.binding = other_member());
        variants.push((g, Error::Unauthorized));
        let mut g = grant.clone();
        g.lineage = edited(&grant.lineage, &outsider, |l| {
            l.root = vld0::public_key(&outsider)
        });
        variants.push((g, Error::Unauthorized));
        let mut g = grant.clone();
        g.lineage = edited(&grant.lineage, &first, |l| l.epoch = 2);
        variants.push((g, Error::Unauthorized));
        let mut g = grant.clone();
        g.lineage = edited(&grant.lineage, &first, |l| l.revision += 1);
        variants.push((g, Error::Unauthorized));
        let mut g = grant.clone();
        g.lineage = with_devices(grant.lineage.clone(), &[creator], &first);
        variants.push((g, Error::Unauthorized));
        let mut g = grant.clone();
        g.request.proof = Signature::new(VLD0, [0; 64]);
        variants.push((g, Error::BadSignature));
        let mut g = grant.clone();
        g.sealed_root[40] ^= 1;
        g.signature = vld0::sign(&first, &g.signed_bytes().unwrap()).unwrap();
        variants.push((g, Error::Open));

        for (index, (forged, expected)) in variants.iter().enumerate() {
            let empty = Memory::default();
            let mut phone = gated(&empty, &time, 5);
            let result = phone
                .restore_scope(&prf(2), &anchor, RestoreRoot::Paired(forged), info(), &[])
                .await;
            assert_eq!(result.unwrap_err(), *expected, "case {index}");
            assert_eq!(phone.state(), State::Locked);
            assert!(empty.0.borrow().records.is_empty());
            assert_eq!(empty.0.borrow().writes, 0);
        }

        let empty = Memory::default();
        let mut phone = gated(&empty, &time, 6);
        let receipt = phone
            .restore_scope(&prf(2), &anchor, RestoreRoot::Paired(&grant), info(), &[])
            .await
            .unwrap();
        phone.acknowledge(receipt.operation).await.unwrap();
        assert_eq!(phone.lineage().await.unwrap(), anchor);
    });
}

#[test]
fn restore_from_a_rotation_refuses_each_mismatch() {
    block_on(async {
        let scene = scene().await;
        let anchor = scene.rotation.lineage.clone();
        let first = root_secret(1, "a", 1);
        let second = root_secret(1, "a", 2);
        let device = device_key(2, "a");
        let outsider = Zeroizing::new([9u8; 32]);

        let mut variants: Vec<(Rotation, Error)> = Vec::new();
        let mut r = scene.rotation.clone();
        r.lineage = edited(&anchor, &second, |l| l.binding = other_member());
        variants.push((r, Error::Unauthorized));
        let mut r = scene.rotation.clone();
        r.lineage = edited(&anchor, &outsider, |l| l.root = vld0::public_key(&outsider));
        variants.push((r, Error::Unauthorized));
        let mut r = scene.rotation.clone();
        r.lineage = edited(&anchor, &second, |l| l.epoch = 7);
        variants.push((r, Error::Unauthorized));
        let mut r = scene.rotation.clone();
        r.lineage = edited(&anchor, &second, |l| l.revision += 1);
        variants.push((r, Error::Unauthorized));
        let mut r = scene.rotation.clone();
        r.revoked = device;
        variants.push((r, Error::Unauthorized));
        let mut r = scene.rotation.clone();
        r.signature = Signature::new(VLD0, [0; 64]);
        variants.push((r, Error::BadSignature));
        let mut r = scene.rotation.clone();
        let index = r.envelopes.iter().position(|e| e.device == device).unwrap();
        r.envelopes[index].sealed_root[40] ^= 1;
        r.signature = vld0::sign(&first, &r.signed_bytes().unwrap()).unwrap();
        variants.push((r, Error::Open));

        for (index, (forged, expected)) in variants.iter().enumerate() {
            let empty = Memory::default();
            let mut phone = gated(&empty, &scene.time, 5);
            let result = phone
                .restore_scope(&prf(2), &anchor, RestoreRoot::Rotated(forged), info(), &[])
                .await;
            assert_eq!(result.unwrap_err(), *expected, "case {index}");
            assert_eq!(phone.state(), State::Locked);
            assert!(empty.0.borrow().records.is_empty());
            assert_eq!(empty.0.borrow().writes, 0);
        }

        let empty = Memory::default();
        let mut phone = gated(&empty, &scene.time, 6);
        let receipt = phone
            .restore_scope(
                &prf(2),
                &anchor,
                RestoreRoot::Rotated(&scene.rotation),
                info(),
                &[],
            )
            .await
            .unwrap();
        phone.acknowledge(receipt.operation).await.unwrap();
        assert_eq!(phone.lineage().await.unwrap(), anchor);
    });
}

#[test]
fn applying_a_rotation_refuses_a_forged_envelope_without_losing_the_root() {
    block_on(async {
        let mut scene = scene().await;
        let first = root_secret(1, "a", 1);
        let device = device_key(2, "a");
        let before = scene.b.lineage().await.unwrap();
        assert_eq!(before, scene.previous);

        let mut damaged = scene.rotation.clone();
        let index = damaged
            .envelopes
            .iter()
            .position(|e| e.device == device)
            .unwrap();
        damaged.envelopes[index].sealed_root[40] ^= 1;
        damaged.signature = vld0::sign(&first, &damaged.signed_bytes().unwrap()).unwrap();
        assert_eq!(
            scene.b.apply_rotation(&damaged, &[]).await.unwrap_err(),
            Error::Open
        );

        let mut wrong_root = scene.rotation.clone();
        wrong_root.envelopes[index].sealed_root = vld0::seal_to(
            &mut Random::new(3),
            &device,
            &wrong_root.aad(device).unwrap(),
            &[7u8; 32],
        )
        .unwrap();
        wrong_root.signature = vld0::sign(&first, &wrong_root.signed_bytes().unwrap()).unwrap();
        assert_eq!(
            scene.b.apply_rotation(&wrong_root, &[]).await.unwrap_err(),
            Error::InvalidKey
        );

        // Refusals changed nothing: the genuine rotation still applies.
        assert_eq!(scene.b.state(), State::Authorized);
        assert_eq!(scene.b.lineage().await.unwrap(), before);
        let receipt = scene.b.apply_rotation(&scene.rotation, &[]).await.unwrap();
        scene.b.acknowledge(receipt.operation).await.unwrap();
        assert_eq!(scene.b.lineage().await.unwrap(), scene.rotation.lineage);
    });
}

#[test]
fn accepting_a_forged_grant_is_refused_and_the_pending_device_survives() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let mut a = gated(&store, &time, 1);
        let mut b = gated(&store, &time, 2);
        let anchor = founder(&mut a).await;
        let request = ask(&mut b, 2, &anchor).await;
        let grant = approve(&mut a, &request).await;
        let first = root_secret(1, "a", 1);
        let creator = device_key(1, "a");
        let device = device_key(2, "a");
        let outsider = Zeroizing::new([9u8; 32]);

        let mut variants: Vec<(PairingGrant, Error)> = Vec::new();
        let mut g = grant.clone();
        g.lineage = edited(&grant.lineage, &first, |l| l.binding = other_member());
        variants.push((g, Error::Unauthorized));
        let mut g = grant.clone();
        g.lineage = edited(&grant.lineage, &outsider, |l| {
            l.root = vld0::public_key(&outsider)
        });
        variants.push((g, Error::Unauthorized));
        let mut g = grant.clone();
        g.lineage = edited(&grant.lineage, &first, |l| l.epoch = 2);
        variants.push((g, Error::Unauthorized));
        let mut g = grant.clone();
        g.lineage = edited(&grant.lineage, &first, |l| l.revision = 1);
        variants.push((g, Error::Unauthorized));
        let mut g = grant.clone();
        g.lineage = with_devices(grant.lineage.clone(), &[creator], &first);
        variants.push((g, Error::Unauthorized));
        let mut g = grant.clone();
        g.lineage = with_devices(grant.lineage.clone(), &[device], &first);
        variants.push((g, Error::Unauthorized));
        let mut g = grant.clone();
        g.sealed_root[40] ^= 1;
        g.signature = vld0::sign(&first, &g.signed_bytes().unwrap()).unwrap();
        variants.push((g, Error::Open));
        let mut g = grant.clone();
        g.sealed_root =
            vld0::seal_to(&mut Random::new(3), &device, &g.aad().unwrap(), &[7u8; 32]).unwrap();
        g.signature = vld0::sign(&first, &g.signed_bytes().unwrap()).unwrap();
        variants.push((g, Error::InvalidKey));

        let writes = store.0.borrow().writes;
        for (index, (forged, expected)) in variants.iter().enumerate() {
            assert_eq!(
                b.accept_pairing(forged, &[]).await.unwrap_err(),
                *expected,
                "case {index}"
            );
            assert_eq!(b.state(), State::PendingDevice);
            assert_eq!(store.0.borrow().writes, writes);
        }
        take(&mut b, &grant).await;
        assert_eq!(b.state(), State::Authorized);
    });
}

#[test]
fn adopting_a_lineage_refuses_each_inconsistent_successor() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let mut a = gated(&store, &time, 1);
        let mut b = gated(&store, &time, 2);
        founder(&mut a).await;
        enroll(&mut a, &mut b, 2).await;
        let current = b.lineage().await.unwrap();
        let first = root_secret(1, "a", 1);
        let outsider = Zeroizing::new([9u8; 32]);
        let own = device_key(2, "a");

        let next = |lineage: &Lineage| {
            let mut copy = lineage.clone();
            copy.revision += 1;
            copy
        };
        let candidates = [
            edited(&next(&current), &first, |l| l.binding = other_member()),
            edited(&next(&current), &outsider, |l| {
                l.root = vld0::public_key(&outsider)
            }),
            edited(&next(&current), &first, |l| l.epoch = 2),
            current.clone(),
            with_devices(next(&current), &[own], &first),
        ];
        let writes = store.0.borrow().writes;
        for (index, candidate) in candidates.iter().enumerate() {
            assert_eq!(
                b.adopt_lineage(candidate, &[]).await.unwrap_err(),
                Error::Unauthorized,
                "case {index}"
            );
            assert!(b.pending_output().await.unwrap().is_none());
            assert_eq!(store.0.borrow().writes, writes);
        }
        assert_eq!(b.lineage().await.unwrap(), current);
    });
}

#[test]
fn authorizing_a_device_refuses_mismatched_requests_and_exhausted_counters() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let mut a = gated(&store, &time, 1);
        let anchor = founder(&mut a).await;
        let first = root_secret(1, "a", 1);
        let member = binding("a");
        let writes = store.0.borrow().writes;

        let mismatched = [
            request_from(2, other_member(), anchor.root, 1),
            request_from(2, member.clone(), device_key(9, "a"), 1),
            request_from(2, member.clone(), anchor.root, 2),
            // The creating device is already part of the lineage.
            request_from(1, member.clone(), anchor.root, 1),
        ];
        for (index, request) in mismatched.iter().enumerate() {
            assert_eq!(
                a.authorize_device(request, &[]).await.unwrap_err(),
                Error::Unauthorized,
                "case {index}"
            );
            assert!(a.pending_output().await.unwrap().is_none());
        }

        let fresh = request_from(2, member, anchor.root, 1);
        let mut crowd: Vec<PublicKey> = (1..=127u8)
            .map(|i| vld0::public_key(&Zeroizing::new([i; 32])))
            .collect();
        crowd.push(device_key(1, "a"));
        let full = with_devices(anchor.clone(), &crowd, &first);
        assert_eq!(full.devices.len(), crate::MAX_DEVICES);
        a.open.as_mut().unwrap().metadata.lineage = full;
        assert_eq!(
            a.authorize_device(&fresh, &[]).await.unwrap_err(),
            Error::Limit
        );

        a.open.as_mut().unwrap().metadata.lineage =
            edited(&anchor, &first, |l| l.revision = u64::MAX);
        assert_eq!(
            a.authorize_device(&fresh, &[]).await.unwrap_err(),
            Error::Limit
        );
        assert_eq!(store.0.borrow().writes, writes);
    });
}

#[test]
fn preparing_a_rotation_refuses_exhausted_epoch_and_revision_counters() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let mut a = gated(&store, &time, 1);
        let mut b = gated(&store, &time, 2);
        founder(&mut a).await;
        enroll(&mut a, &mut b, 2).await;
        let current = a.lineage().await.unwrap();
        let first = root_secret(1, "a", 1);
        let removed = device_key(2, "a");
        let writes = store.0.borrow().writes;

        a.open.as_mut().unwrap().metadata.lineage =
            edited(&current, &first, |l| l.epoch = u64::MAX);
        assert_eq!(
            a.prepare_rotation(removed, &[]).await.unwrap_err(),
            Error::Limit
        );
        a.open.as_mut().unwrap().metadata.lineage =
            edited(&current, &first, |l| l.revision = u64::MAX);
        assert_eq!(
            a.prepare_rotation(removed, &[]).await.unwrap_err(),
            Error::Limit
        );
        assert_eq!(a.state(), State::Authorized);
        assert!(a.prepared.is_none());
        assert_eq!(store.0.borrow().writes, writes);
    });
}

#[test]
fn a_prepared_rotation_that_lost_its_output_or_session_cannot_commit() {
    block_on(async {
        for case in 0..3 {
            let store = Memory::default();
            let time = Time::default();
            let mut a = gated(&store, &time, 1);
            let mut b = gated(&store, &time, 2);
            founder(&mut a).await;
            let grant = enroll(&mut a, &mut b, 2).await;
            let lineage = a.lineage().await.unwrap();
            a.prepare_rotation(grant.request.device, &[]).await.unwrap();
            let writes = store.0.borrow().writes;
            let expected = match case {
                0 => {
                    a.prepared.as_mut().unwrap().candidate.metadata.output = None;
                    Error::Encoding
                }
                1 => {
                    a.prepared.as_mut().unwrap().candidate.metadata.output = Some(Receipt {
                        operation: OperationId([1; 32]),
                        change: Change::Created(lineage),
                    });
                    Error::Encoding
                }
                _ => {
                    a.open = None;
                    Error::Unauthorized
                }
            };
            assert_eq!(a.commit().await.unwrap_err(), expected, "case {case}");
            assert_eq!(a.state(), State::Reconcile);
            assert_eq!(store.0.borrow().writes, writes);
        }
    });
}

#[test]
fn a_full_or_exhausted_checkpoint_is_refused_before_it_is_written() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let mut a = gated(&store, &time, 1);
        founder(&mut a).await;
        a.open.as_mut().unwrap().metadata.revision = u64::MAX;
        let writes = store.0.borrow().writes;
        assert_eq!(a.rename_device("renamed").await.unwrap_err(), Error::Limit);
        assert_eq!(a.state(), State::Authorized);
        assert_eq!(store.0.borrow().writes, writes);

        let mut b = gated(&store, &time, 2);
        let receipt = b
            .create_scope(&prf(2), binding("c"), info(), &[])
            .await
            .unwrap();
        b.open.as_mut().unwrap().metadata.info = DeviceInfo {
            name: "n".repeat(300_000),
            authority_reference: Vec::new(),
        };
        let writes = store.0.borrow().writes;
        assert_eq!(
            b.acknowledge(receipt.operation).await.unwrap_err(),
            Error::Limit
        );
        assert_eq!(store.0.borrow().writes, writes);
        assert_eq!(b.pending_output().await.unwrap(), Some(receipt));
    });
}

#[test]
fn a_pending_device_may_only_use_authority_for_pairing_actions() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let mut a = gated(&store, &time, 1);
        let mut b = gated(&store, &time, 2);
        let anchor = founder(&mut a).await;
        ask(&mut b, 2, &anchor).await;
        b.authorize(Action::RequestPairing, None, None, &[])
            .await
            .unwrap();
        assert_eq!(
            b.authorize(Action::Use, None, None, &[]).await,
            Err(Error::Unauthorized)
        );
        assert_eq!(b.state(), State::PendingDevice);
    });
}

#[test]
fn a_certificate_of_another_device_is_not_a_usable_handle() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let mut a = gated(&store, &time, 1);
        let mut b = gated(&store, &time, 2);
        founder(&mut a).await;
        enroll(&mut a, &mut b, 2).await;
        let theirs = b.key(purpose(Scope::Device, "x")).await.unwrap();
        let session = a.open.as_ref().unwrap().session;
        let forged = KeyHandle {
            session,
            certificate: theirs.certificate().clone(),
        };
        assert_eq!(a.sign(&forged, b"x").await, Err(Error::Unauthorized));
        assert_eq!(
            a.sign_ed25519(&forged, b"x").await,
            Err(Error::Unauthorized)
        );
        assert_eq!(
            a.seal(&forged, b"context", b"secret").await,
            Err(Error::Unauthorized)
        );
        assert_eq!(a.state(), State::Authorized);
    });
}

macro_rules! at_every_draw {
    ($allowed:ident, $attempt:block) => {{
        let mut finished = false;
        for count in 0..40usize {
            let $allowed = count;
            let succeeded: bool = $attempt;
            if succeeded {
                finished = true;
                break;
            }
        }
        assert!(finished, "the operation never succeeded");
    }};
}

#[test]
fn creation_and_renaming_survive_randomness_failing_at_every_draw() {
    block_on(async {
        at_every_draw!(allowed, {
            let store = Memory::default();
            let time = Time::default();
            let mut a = gated(&store, &time, 1);
            a.entropy.budget.set(allowed);
            match a.create_scope(&prf(1), binding("a"), info(), &[]).await {
                Ok(_) => true,
                Err(error) => {
                    assert_eq!(error, Error::Randomness);
                    assert!(store.0.borrow().records.is_empty());
                    assert_eq!(a.state(), State::Locked);
                    false
                }
            }
        });
        at_every_draw!(allowed, {
            let store = Memory::default();
            let time = Time::default();
            let mut a = gated(&store, &time, 1);
            founder(&mut a).await;
            a.entropy.budget.set(allowed);
            let writes = store.0.borrow().writes;
            match a.rename_device("renamed").await {
                Ok(()) => true,
                Err(error) => {
                    assert_eq!(error, Error::Randomness);
                    assert_eq!(store.0.borrow().writes, writes);
                    assert_eq!(a.device_info().await.unwrap(), info());
                    false
                }
            }
        });
    });
}

#[test]
fn pairing_survives_randomness_failing_at_every_draw() {
    block_on(async {
        at_every_draw!(allowed, {
            let store = Memory::default();
            let time = Time::default();
            let mut a = gated(&store, &time, 1);
            let mut b = gated(&store, &time, 2);
            let anchor = founder(&mut a).await;
            let request = ask(&mut b, 2, &anchor).await;
            a.entropy.budget.set(allowed);
            let writes = store.0.borrow().writes;
            match a.authorize_device(&request, &[]).await {
                Ok(_) => true,
                Err(error) => {
                    assert_eq!(error, Error::Randomness);
                    assert_eq!(store.0.borrow().writes, writes);
                    assert!(a.pending_output().await.unwrap().is_none());
                    false
                }
            }
        });
        at_every_draw!(allowed, {
            let store = Memory::default();
            let time = Time::default();
            let mut a = gated(&store, &time, 1);
            let mut b = gated(&store, &time, 2);
            let anchor = founder(&mut a).await;
            let request = ask(&mut b, 2, &anchor).await;
            let grant = approve(&mut a, &request).await;
            b.entropy.budget.set(allowed);
            let writes = store.0.borrow().writes;
            match b.accept_pairing(&grant, &[]).await {
                Ok(_) => true,
                Err(error) => {
                    assert_eq!(error, Error::Randomness);
                    assert_eq!(store.0.borrow().writes, writes);
                    assert_eq!(b.state(), State::PendingDevice);
                    false
                }
            }
        });
        at_every_draw!(allowed, {
            let store = Memory::default();
            let time = Time::default();
            let mut a = gated(&store, &time, 1);
            let mut b = gated(&store, &time, 2);
            let anchor = founder(&mut a).await;
            let first = ask(&mut b, 2, &anchor).await;
            time.0.set(first.expires_at);
            b.entropy.budget.set(allowed);
            let writes = store.0.borrow().writes;
            match b.renew_pairing(&anchor, &[]).await {
                Ok(_) => true,
                Err(error) => {
                    assert_eq!(error, Error::Randomness);
                    assert_eq!(store.0.borrow().writes, writes);
                    assert_eq!(b.state(), State::PendingDevice);
                    false
                }
            }
        });
    });
}

#[test]
fn lineage_changes_survive_randomness_failing_at_every_draw() {
    block_on(async {
        at_every_draw!(allowed, {
            let store = Memory::default();
            let time = Time::default();
            let mut a = gated(&store, &time, 1);
            let mut b = gated(&store, &time, 2);
            let mut c = gated(&store, &time, 3);
            founder(&mut a).await;
            enroll(&mut a, &mut b, 2).await;
            enroll(&mut a, &mut c, 3).await;
            let next = a.lineage().await.unwrap();
            b.entropy.budget.set(allowed);
            let writes = store.0.borrow().writes;
            match b.adopt_lineage(&next, &[]).await {
                Ok(_) => true,
                Err(error) => {
                    assert_eq!(error, Error::Randomness);
                    assert_eq!(store.0.borrow().writes, writes);
                    false
                }
            }
        });
        at_every_draw!(allowed, {
            let store = Memory::default();
            let time = Time::default();
            let mut a = gated(&store, &time, 1);
            let mut b = gated(&store, &time, 2);
            founder(&mut a).await;
            let grant = enroll(&mut a, &mut b, 2).await;
            a.entropy.budget.set(allowed);
            let writes = store.0.borrow().writes;
            match a.prepare_rotation(grant.request.device, &[]).await {
                Ok(()) => true,
                Err(error) => {
                    assert_eq!(error, Error::Randomness);
                    assert_eq!(a.state(), State::Authorized);
                    assert!(a.prepared.is_none());
                    assert_eq!(store.0.borrow().writes, writes);
                    false
                }
            }
        });
    });
}

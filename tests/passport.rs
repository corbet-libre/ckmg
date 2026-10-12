//! Fresh-authorized opaque initialization of the real holder engine; Wallet owns its lifetime.
#![cfg(feature = "passport")]
mod support;

use ckmg::*;
use cpsd::rand::{SeedableRng, rngs::StdRng};
use futures::executor::block_on;
use support::*;

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn holder_rederives_identity_and_requires_exact_current_wallet_custody() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut keys = machine(&store, &time, &guard, 73);
        create(&mut keys, &guard, &prf(1), &binding("wallet")).await;
        let holder = keys
            .with_holder_seed(|seed| seed.into_passport_holder())
            .await
            .unwrap()
            .unwrap();
        let community = cpsd::CommunityId::new(b"community-a").unwrap();
        let (nym, tag) = {
            assert!(holder.attributes().is_none());
            (holder.pseudonym(&community), holder.issuer_tag())
        };
        drop(holder);
        keys.lock();
        keys.unlock(&prf(1), "wallet").await.unwrap();
        let mut holder = keys
            .with_holder_seed(|seed| seed.into_passport_holder())
            .await
            .unwrap()
            .unwrap();
        let same = (holder.pseudonym(&community), holder.issuer_tag());
        assert_eq!(same, (nym, tag));

        let mut rng = StdRng::seed_from_u64(92);
        let gate = cpsd::GateId::new("phone").unwrap();
        let issuer = cpsd::IssuerKey::generate(
            &mut rng,
            cpsd::KeyId::new("issuer").unwrap(),
            vec![gate.clone()],
        )
        .unwrap();
        let challenge = cpsd::IssuanceChallenge::generate(&mut rng);
        let attrs = cpsd::PassportAttributes::new(2000, 7).with_gate(gate.clone(), 1500);
        let request =
            cpsd::PresentationRequest::new(&mut rng, community.clone(), 7, [gate], 1000).unwrap();
        let mut signer = csgn::Signer::new(
            "cmty:test",
            csgn::SecretKey::from_seed(&mut [4; 32]),
            0,
            cpsd::TIME_LIMIT,
        )
        .unwrap();
        let signed = signer
            .sign(csgn::Kind::Credential, &request.to_bytes(), 0, 1001)
            .unwrap();
        let expected = cpsd::AuthenticatedCommunity::from_authenticated_origin(
            community,
            signer.key_ring().clone(),
        );
        assert!(matches!(
            holder.present(&mut rng, &expected, &signed, 1000),
            Err(cpsd::Error::PassportUnavailable)
        ));
        let issuance = holder
            .begin_issuance(&mut rng, issuer.public_key(), &challenge)
            .unwrap();
        let blind = issuer
            .issue_blind(&mut rng, &issuance, &challenge, &attrs)
            .unwrap();
        let pending = holder.seal(&mut rng).unwrap();
        drop(holder);
        keys.lock();
        keys.unlock(&prf(1), "wallet").await.unwrap();
        let mut holder = keys
            .with_holder_seed(|seed| seed.open_passport_holder(&pending))
            .await
            .unwrap()
            .unwrap();
        let mut damaged = pending.as_bytes().to_vec();
        *damaged.last_mut().unwrap() ^= 1;
        let damaged = cpsd::SealedHolder::from_bytes(&damaged).unwrap();
        assert!(
            keys.with_holder_seed(|seed| seed.open_passport_holder(&damaged))
                .await
                .unwrap()
                .is_err()
        );
        holder.finish_issuance(&blind).unwrap();
        assert_eq!(holder.attributes(), Some(&attrs));
        let proof = holder.present(&mut rng, &expected, &signed, 1000).unwrap();
        assert_eq!(
            cpsd::verify(&mut rng, &[issuer.public_key().clone()], &request, &proof).unwrap(),
            nym
        );
        let sealed = holder.seal(&mut rng).unwrap();
        let peer_store = Memory::default();
        let mut peer = machine(&peer_store, &time, &guard, 74);
        pair(&mut keys, &mut peer, &guard, &prf(2)).await;
        let peer_holder = peer
            .with_holder_seed(|seed| seed.open_passport_holder(&sealed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(peer_holder.attributes(), Some(&attrs));
        let proof = peer_holder
            .present(&mut rng, &expected, &signed, 1000)
            .unwrap();
        assert_eq!(
            cpsd::verify(&mut rng, &[issuer.public_key().clone()], &request, &proof).unwrap(),
            nym
        );
        drop(peer_holder);
        let unrelated_store = Memory::default();
        let unrelated_guard = Guard::default();
        let mut unrelated = machine(&unrelated_store, &time, &unrelated_guard, 75);
        create(
            &mut unrelated,
            &unrelated_guard,
            &prf(3),
            &binding("wallet"),
        )
        .await;
        assert!(
            unrelated
                .with_holder_seed(|seed| seed.open_passport_holder(&sealed))
                .await
                .unwrap()
                .is_err()
        );
        holder.cancel_issuance();
        drop(holder); // The composing Wallet owns wiping its engine on lock.
        keys.lock();
        let called = std::cell::Cell::new(false);
        assert!(keys.with_holder_seed(|_| called.set(true)).await.is_err());
        assert!(!called.get());
        keys.unlock(&prf(1), "wallet").await.unwrap();
        keys.with_holder_seed(|_| called.set(true)).await.unwrap();
        assert!(called.get());
        called.set(false);
        guard
            .0
            .borrow_mut()
            .get_mut("wallet")
            .unwrap()
            .devices
            .clear();
        assert!(keys.with_holder_seed(|_| called.set(true)).await.is_err());
        assert!(!called.get());
        assert_eq!(keys.state(), State::Revoked);
    });
}

// Link the maintained profiler only into instrumented test binaries.
#[cfg(all(target_arch = "wasm32", owned_browser_coverage))]
#[wasm_bindgen_test::wasm_bindgen_test]
fn profiling_runtime_is_linked() {
    let _ = browser_coverage_runtime::__owned_test_module_signature();
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn the_pending_creation_holder_seed_serves_only_the_exact_pending_created_receipt() {
    block_on(async {
        let (store, time, guard) = (Memory::default(), Time::default(), Guard::default());
        let mut keys = machine(&store, &time, &guard, 1);
        let b = binding("wallet");
        let receipt = keys
            .create_scope(
                &prf(1),
                b.clone(),
                info(),
                &consent(Action::Create, &b, None, 0, None, None),
            )
            .await
            .unwrap();
        guard.publish(&receipt);
        assert!(matches!(
            keys.with_holder_seed(|seed| seed.into_passport_holder())
                .await,
            Err(Error::Pending)
        ));
        let other = Memory::default();
        let mut foreign_keys = machine(&other, &time, &guard, 2);
        let fb = binding("wallet");
        let foreign = foreign_keys
            .create_scope(
                &prf(2),
                fb.clone(),
                info(),
                &consent(Action::Create, &fb, None, 0, None, None),
            )
            .await
            .unwrap();
        assert!(matches!(
            keys.with_holder_seed_for_pending_creation(&foreign, |seed| seed
                .into_passport_holder())
                .await,
            Err(Error::Unauthorized)
        ));
        keys.with_holder_seed_for_pending_creation(&receipt, |seed| seed.into_passport_holder())
            .await
            .unwrap()
            .unwrap();
        keys.acknowledge(receipt.operation).await.unwrap();
        assert!(matches!(
            keys.with_holder_seed_for_pending_creation(&receipt, |seed| seed
                .into_passport_holder())
                .await,
            Err(Error::Unauthorized)
        ));
    });
}

//! Real opaque holder operations behind freshly checked wallet custody.
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
        keys.install_wallet_roots().await.unwrap();
        assert!(keys.install_wallet_roots().await.is_err());
        let community = cpsd::CommunityId::new(b"community-a").unwrap();
        let (nym, tag) = keys.with_passport_holder( |holder| {
            assert!(holder.attributes().is_none());
            (holder.pseudonym(&community), holder.issuer_tag())
        }).await.unwrap();
        keys.lock();
        keys.unlock(&prf(1), "wallet").await.unwrap();
        keys.install_wallet_roots().await.unwrap();
        let same = keys.with_passport_holder( |holder| {
            (holder.pseudonym(&community), holder.issuer_tag())
        }).await.unwrap();
        assert_eq!(same, (nym, tag));

        let mut rng = StdRng::seed_from_u64(92);
        let gate = cpsd::GateId::new("phone").unwrap();
        let issuer = cpsd::IssuerKey::generate(&mut rng, cpsd::KeyId::new("issuer").unwrap(), vec![gate.clone()]).unwrap();
        let challenge = cpsd::IssuanceChallenge::generate(&mut rng);
        let attrs = cpsd::PassportAttributes::new(2000, 7).with_gate(gate.clone(), 1500);
        let request = cpsd::PresentationRequest::new(&mut rng, community.clone(), 7, [gate], 1000).unwrap();
        let mut signer = csgn::Signer::new("cmty:test", csgn::SecretKey::from_seed(&mut [4; 32]), 0, cpsd::TIME_LIMIT).unwrap();
        let signed = signer.sign(csgn::Kind::Credential, &request.to_bytes(), 0, 1001).unwrap();
        let expected = cpsd::AuthenticatedCommunity::from_authenticated_origin(community, signer.key_ring().clone());
        let issuance = keys.with_passport_holder( |mut holder| {
            assert!(matches!(holder.present(&mut rng, &expected, &signed, 1000), Err(cpsd::Error::PassportUnavailable)));
            holder.begin_issuance(&mut rng, issuer.public_key(), &challenge)
        }).await.unwrap().unwrap();
        let blind = issuer.issue_blind(&mut rng, &issuance, &challenge, &attrs).unwrap();
        keys.with_passport_holder( |mut holder| holder.finish_issuance(&blind)).await.unwrap().unwrap();
        let proof = keys.with_passport_holder( |holder| {
            assert_eq!(holder.attributes(), Some(&attrs));
            holder.present(&mut rng, &expected, &signed, 1000)
        }).await.unwrap().unwrap();
        assert_eq!(cpsd::verify(&mut rng, &[issuer.public_key().clone()], &request, &proof).unwrap(), nym);
        keys.with_passport_holder( |mut holder| holder.cancel_issuance()).await.unwrap();
        keys.lock();
        let called = std::cell::Cell::new(false);
        assert!(keys.with_passport_holder( |_| called.set(true)).await.is_err());
        assert!(!called.get());
        keys.unlock(&prf(1), "wallet").await.unwrap();
        assert!(keys.with_passport_holder(|_| called.set(true)).await.is_err());
        assert!(!called.get());
        keys.install_wallet_roots().await.unwrap();
        guard.0.borrow_mut().get_mut("wallet").unwrap().devices.clear();
        assert!(keys.with_passport_holder( |_| called.set(true)).await.is_err());
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

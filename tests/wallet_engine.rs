//! Original uninitialized engine custody only. No accepted balance, proof or
//! Wave release is manufactured by the test-only lineage authority fixture.
#![cfg(feature = "wallet-engine")]
mod support;
use ckmg::*;
use futures::executor::block_on;
use support::*;

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn original_engine_sealing_restores_only_the_same_retained_common_identity() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut first = machine(&store, &time, &guard, 111);
        let mut peer = machine(&store, &time, &guard, 112);
        create(&mut first, &guard, &prf(1), &binding("wallet")).await;
        let engine: wallet_engine::Engine = first.wallet_engine().await.unwrap();
        let sealed: wallet_engine::Sealed = engine.seal().unwrap();
        drop(engine);
        first.lock();
        assert!(matches!(
            first.restore_wallet_engine(&sealed).await,
            Err(Error::Locked)
        ));
        first.unlock(&prf(1), "wallet").await.unwrap();
        let restored = first.restore_wallet_engine(&sealed).await.unwrap();
        let resealed = restored.seal().unwrap();
        assert_ne!(sealed.as_bytes(), resealed.as_bytes());
        pair(&mut first, &mut peer, &guard, &prf(2)).await;
        let peer_engine = peer.restore_wallet_engine(&resealed).await.unwrap();
        let peer_sealed = peer_engine.seal().unwrap();
        first.restore_wallet_engine(&peer_sealed).await.unwrap();
        let mut damaged = peer_sealed.as_bytes().to_vec();
        *damaged.last_mut().unwrap() ^= 1;
        let damaged = wallet_engine::Sealed::from_bytes(&damaged).unwrap();
        assert!(matches!(
            first.restore_wallet_engine(&damaged).await,
            Err(Error::Open)
        ));

        let unrelated_store = Memory::default();
        let unrelated_guard = Guard::default();
        let mut unrelated = machine(&unrelated_store, &time, &unrelated_guard, 113);
        create(
            &mut unrelated,
            &unrelated_guard,
            &prf(1),
            &binding("wallet"),
        )
        .await;
        assert!(matches!(
            unrelated.restore_wallet_engine(&sealed).await,
            Err(Error::Open)
        ));
        let mut other_scope = machine(&store, &time, &guard, 114);
        create(&mut other_scope, &guard, &prf(1), &binding("other")).await;
        assert!(matches!(
            other_scope.restore_wallet_engine(&sealed).await,
            Err(Error::Open)
        ));
        guard
            .0
            .borrow_mut()
            .get_mut("wallet")
            .unwrap()
            .devices
            .clear();
        assert!(matches!(
            first.restore_wallet_engine(&sealed).await,
            Err(Error::Revoked)
        ));
        assert_eq!(first.state(), State::Revoked);
    });
}

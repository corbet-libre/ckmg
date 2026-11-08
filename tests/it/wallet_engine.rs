//! Original uninitialized engine custody only. No accepted balance, proof or
//! Wave release is manufactured by the test-only lineage authority fixture.
#![cfg(feature = "wallet-engine")]
use crate::support::*;
use ckmg::*;
use futures::executor::block_on;

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

async fn pending_creation(
    store: &Memory,
    time: &Time,
    guard: &Guard,
    seed: u8,
    community: &str,
) -> (Machine, Receipt) {
    let mut keys = machine(store, time, guard, seed);
    let b = binding(community);
    let receipt = keys
        .create_scope(
            &prf(seed),
            b.clone(),
            info(),
            &consent(Action::Create, &b, None, 0, None, None),
        )
        .await
        .unwrap();
    guard.publish(&receipt);
    (keys, receipt)
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn the_pending_creation_path_serves_only_the_exact_pending_created_receipt() {
    block_on(async {
        let (store, time, guard) = (Memory::default(), Time::default(), Guard::default());
        let (mut keys, receipt) = pending_creation(&store, &time, &guard, 1, "wallet").await;
        // The ordinary path is closed while the output is pending; the dedicated one opens.
        assert!(matches!(keys.wallet_engine().await, Err(Error::Pending)));
        keys.wallet_engine_for_pending_creation(&receipt)
            .await
            .unwrap();

        // A receipt of another scope, or one with a different operation, is refused.
        let other = Memory::default();
        let (_, foreign) = pending_creation(&other, &time, &guard, 2, "foreign").await;
        assert!(matches!(
            keys.wallet_engine_for_pending_creation(&foreign).await,
            Err(Error::Unauthorized)
        ));
        // Nothing was opened by the refusal.
        assert!(matches!(keys.wallet_engine().await, Err(Error::Pending)));

        // After the acknowledgment there is no pending output: the path is closed.
        keys.acknowledge(receipt.operation).await.unwrap();
        assert!(matches!(
            keys.wallet_engine_for_pending_creation(&receipt).await,
            Err(Error::Unauthorized)
        ));
        keys.wallet_engine().await.unwrap();
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn the_pending_creation_path_refuses_a_pending_output_that_is_not_a_creation() {
    block_on(async {
        let (store, time, guard) = (Memory::default(), Time::default(), Guard::default());
        let mut first = machine(&store, &time, &guard, 111);
        create(&mut first, &guard, &prf(1), &binding("wallet")).await;
        let anchor = first.lineage().await.unwrap();
        let mut new = machine(&Memory::default(), &time, &guard, 113);
        let pending = new
            .request_pairing(
                &prf(2),
                &anchor,
                info(),
                &consent(
                    Action::RequestPairing,
                    &anchor.binding,
                    Some(anchor.root),
                    anchor.epoch,
                    None,
                    Some(anchor.digest().unwrap()),
                ),
            )
            .await
            .unwrap();
        assert!(!matches!(pending.change, Change::Created(_)));
        assert!(
            new.wallet_engine_for_pending_creation(&pending)
                .await
                .is_err()
        );
        assert!(new.wallet_engine().await.is_err());
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn the_pending_creation_path_still_needs_fresh_use_authority() {
    block_on(async {
        let (store, time, guard) = (Memory::default(), Time::default(), Guard::default());
        let mut keys = machine(&store, &time, &guard, 1);
        let b = binding("wallet");
        // The lineage is deliberately NOT published to the authority fixture.
        let receipt = keys
            .create_scope(
                &prf(1),
                b.clone(),
                info(),
                &consent(Action::Create, &b, None, 0, None, None),
            )
            .await
            .unwrap();
        assert!(
            keys.wallet_engine_for_pending_creation(&receipt)
                .await
                .is_err()
        );
    });
}

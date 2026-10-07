//! Refusal scenarios for the custody state machine, driven through the public API with
//! the shared fixtures. Each case asserts the exact refusal and that storage and local
//! state did not change; none of them may reveal or alter secret material.
mod support;
use ckmg::*;
use futures::executor::block_on;
use std::{cell::RefCell, rc::Rc};
use support::*;

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

/// Authority that refuses with the scripted error, or approves when none is set.
#[derive(Clone, Default)]
struct Scripted(Rc<RefCell<Option<Error>>>);
impl Authority for Scripted {
    async fn check(&mut self, _request: Authorization<'_>) -> Result<(), Error> {
        match *self.0.borrow() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn an_unacknowledged_output_blocks_every_mutation_and_foreign_acknowledgement() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 1);
        let mut other = machine(&store, &time, &guard, 2);
        let foreign = create(&mut other, &guard, &prf(2), &binding("b")).await;
        let receipt = a
            .create_scope(
                &prf(1),
                binding("a"),
                info(),
                &consent(Action::Create, &binding("a"), None, 0, None, None),
            )
            .await
            .unwrap();
        guard.publish(&receipt);
        assert_eq!(receipt.operation.as_bytes().len(), 32);
        assert_ne!(receipt.operation, foreign.operation);
        let lineage = match &receipt.change {
            Change::Created(lineage) => lineage.clone(),
            _ => panic!("expected a created lineage"),
        };
        let writes = store.0.borrow().writes;

        assert_eq!(a.rename_device("renamed").await, Err(Error::Pending));
        assert_eq!(
            a.key(purpose(Scope::Device, "x")).await.unwrap_err(),
            Error::Pending
        );
        assert_eq!(
            a.adopt_lineage(&lineage, &[]).await.unwrap_err(),
            Error::Pending
        );
        assert_eq!(
            a.prepare_rotation(lineage.devices[0], &[]).await,
            Err(Error::Pending)
        );
        assert_eq!(
            a.renew_pairing(&lineage, &[]).await.unwrap_err(),
            Error::Pending
        );
        // An unlocked machine neither creates, restores nor requests pairing again.
        assert_eq!(
            a.create_scope(&prf(1), binding("a"), info(), &[])
                .await
                .unwrap_err(),
            Error::Pending
        );
        assert_eq!(
            a.restore_scope(&prf(1), &lineage, RestoreRoot::Derived, info(), &[])
                .await
                .unwrap_err(),
            Error::Pending
        );
        assert_eq!(
            a.request_pairing(&prf(1), &lineage, info(), &[])
                .await
                .unwrap_err(),
            Error::Pending
        );
        // Another operation's identifier never clears this output.
        assert_eq!(
            a.acknowledge(foreign.operation).await,
            Err(Error::Unauthorized)
        );
        assert_eq!(a.pending_output().await.unwrap(), Some(receipt.clone()));
        assert_eq!(a.cancel_prepared(), Err(Error::Pending));
        assert_eq!(store.0.borrow().writes, writes);
        a.acknowledge(receipt.operation).await.unwrap();
        assert!(a.pending_output().await.unwrap().is_none());
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn the_reconcile_state_refuses_everything_until_the_next_unlock() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 3);
        let mut b = machine(&store, &time, &guard, 4);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        let grant = pair(&mut a, &mut b, &guard, &prf(2)).await;
        let before = a.lineage().await.unwrap();
        prepare(&mut a, grant.request.device).await;
        store.0.borrow_mut().fault = Fault::Conflict;
        assert_eq!(a.commit().await.unwrap_err(), Error::Reconcile);
        assert_eq!(a.state(), State::Reconcile);
        assert_eq!(a.pending_output().await, Err(Error::Reconcile));
        assert_eq!(a.lineage().await.unwrap_err(), Error::Reconcile);
        assert_eq!(a.device_info().await.unwrap_err(), Error::Reconcile);
        assert_eq!(a.rename_device("renamed").await, Err(Error::Reconcile));
        store.0.borrow_mut().fault = Fault::None;
        a.unlock(&prf(1), "a").await.unwrap();
        assert_eq!(a.state(), State::Authorized);
        assert_eq!(a.lineage().await.unwrap(), before);
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn oversized_inputs_are_refused_before_any_further_work() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 5);
        assert_eq!(
            a.create_scope(&prf(1), binding("a"), info(), &[0u8; 4097])
                .await
                .unwrap_err(),
            Error::Limit
        );
        assert_eq!(a.state(), State::Locked);
        assert_eq!(store.0.borrow().writes, 0);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        let lineage = a.lineage().await.unwrap();
        assert_eq!(
            a.adopt_lineage(&lineage, &[0u8; 4097]).await.unwrap_err(),
            Error::Limit
        );
        let key = a.key(purpose(Scope::Member, "p")).await.unwrap();
        let big = vec![0u8; MAX_MESSAGE_BYTES + 1];
        assert_eq!(a.sign(&key, &big).await, Err(Error::Limit));
        assert_eq!(a.sign_ed25519(&key, &big).await, Err(Error::Limit));
        assert_eq!(a.seal(&key, &[0u8; 4097], b"x").await, Err(Error::Limit));
        assert_eq!(a.seal(&key, b"ctx", &big).await, Err(Error::Limit));
        assert_eq!(
            a.open(&key, &[0u8; 4097], b"x").await.unwrap_err(),
            Error::Limit
        );
        let sealed_big = vec![0u8; MAX_MESSAGE_BYTES + 64];
        assert_eq!(
            a.open(&key, b"ctx", &sealed_big).await.unwrap_err(),
            Error::Limit
        );
        // Nothing above reached the authority or changed custody.
        assert_eq!(a.state(), State::Authorized);
        let sealed = a.seal(&key, b"ctx", b"ok").await.unwrap();
        assert_eq!(&*a.open(&key, b"ctx", &sealed).await.unwrap(), b"ok");
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn authority_unavailability_and_revocation_keep_their_own_errors() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let gate = Scripted::default();
        let mut keys = Keys::new(store.clone(), time.clone(), Random::new(6), gate.clone());
        *gate.0.borrow_mut() = Some(Error::Unavailable);
        assert_eq!(
            keys.create_scope(&prf(1), binding("a"), info(), &[])
                .await
                .unwrap_err(),
            Error::Unavailable
        );
        assert_eq!(keys.state(), State::Locked);
        *gate.0.borrow_mut() = Some(Error::Randomness);
        assert_eq!(
            keys.create_scope(&prf(1), binding("a"), info(), &[])
                .await
                .unwrap_err(),
            Error::Unauthorized
        );
        *gate.0.borrow_mut() = Some(Error::Revoked);
        assert_eq!(
            keys.create_scope(&prf(1), binding("a"), info(), &[])
                .await
                .unwrap_err(),
            Error::Revoked
        );
        assert_eq!(keys.state(), State::Revoked);
        assert_eq!(store.0.borrow().writes, 0);
        assert!(store.0.borrow().records.is_empty());

        // A revoked machine must be locked again before it can create anything.
        *gate.0.borrow_mut() = None;
        assert_eq!(
            keys.create_scope(&prf(1), binding("a"), info(), &[])
                .await
                .unwrap_err(),
            Error::Pending
        );
        keys.lock();
        let receipt = keys
            .create_scope(&prf(1), binding("a"), info(), &[])
            .await
            .unwrap();
        keys.acknowledge(receipt.operation).await.unwrap();
        *gate.0.borrow_mut() = Some(Error::Unavailable);
        assert_eq!(keys.lineage().await.unwrap_err(), Error::Unavailable);
        assert_eq!(keys.state(), State::Locked);
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rotation_commit_rechecks_authority_and_clock_without_writing() {
    block_on(async {
        for regress in [false, true] {
            let store = Memory::default();
            let time = Time::default();
            let guard = Guard::default();
            let mut a = machine(&store, &time, &guard, 7);
            let mut b = machine(&store, &time, &guard, 8);
            create(&mut a, &guard, &prf(1), &binding("a")).await;
            let grant = pair(&mut a, &mut b, &guard, &prf(2)).await;
            prepare(&mut a, grant.request.device).await;
            let writes = store.0.borrow().writes;
            if regress {
                time.0.set(1);
            } else {
                guard.0.borrow_mut().clear();
            }
            let expected = if regress {
                Error::Clock
            } else {
                Error::Unauthorized
            };
            assert_eq!(a.commit().await.unwrap_err(), expected);
            assert_eq!(store.0.borrow().writes, writes);
            assert_eq!(a.state(), State::Locked);
        }
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn renewing_a_pairing_challenge_is_refused_for_the_wrong_state_or_anchor() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 9);
        let mut b = machine(&store, &time, &guard, 10);
        let mut other = machine(&store, &time, &guard, 11);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        create(&mut other, &guard, &prf(3), &binding("c")).await;
        let anchor = a.lineage().await.unwrap();
        let foreign = other.lineage().await.unwrap();
        // A live device has no challenge to renew.
        assert_eq!(
            a.renew_pairing(&anchor, &[]).await.unwrap_err(),
            Error::Unauthorized
        );
        let request = request(&mut b, &prf(2), &anchor).await;
        let grant = grant(&mut a, &guard, &request).await;
        time.0.set(request.expires_at);
        let writes = store.0.borrow().writes;
        // An anchor of another community, and one that already lists the device.
        assert_eq!(
            b.renew_pairing(&foreign, &[]).await.unwrap_err(),
            Error::Unauthorized
        );
        assert_eq!(
            b.renew_pairing(&grant.lineage, &[]).await.unwrap_err(),
            Error::Unauthorized
        );
        assert_eq!(b.state(), State::PendingDevice);
        assert_eq!(store.0.borrow().writes, writes);
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rotation_refuses_self_removal_strangers_and_missing_consent() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 12);
        let mut b = machine(&store, &time, &guard, 13);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        let grant = pair(&mut a, &mut b, &guard, &prf(2)).await;
        let own = a
            .key(purpose(Scope::Device, "x"))
            .await
            .unwrap()
            .certificate()
            .device;
        let stranger = a
            .key(purpose(Scope::Member, "y"))
            .await
            .unwrap()
            .certificate()
            .key;
        let anchor = a.lineage().await.unwrap();
        let approval = |target: PublicKey| {
            consent(
                Action::Rotate,
                &anchor.binding,
                Some(anchor.root),
                anchor.epoch,
                Some(target),
                Some(anchor.digest().unwrap()),
            )
        };
        let writes = store.0.borrow().writes;
        assert_eq!(
            a.prepare_rotation(own, &approval(own)).await,
            Err(Error::Unauthorized)
        );
        assert_eq!(
            a.prepare_rotation(stranger, &approval(stranger)).await,
            Err(Error::Unauthorized)
        );
        assert_eq!(a.state(), State::Authorized);
        // Without the user's approval the authority refuses and the device locks.
        assert_eq!(
            a.prepare_rotation(grant.request.device, &[]).await,
            Err(Error::Unauthorized)
        );
        assert_eq!(a.state(), State::Locked);
        assert_eq!(store.0.borrow().writes, writes);
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn an_oversized_replacement_record_forces_reconciliation() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 14);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        let location = passkey::vault_location(&prf(1), "a").unwrap();
        store
            .0
            .borrow_mut()
            .records
            .insert(location, vec![0u8; MAX_CHECKPOINT_BYTES + 1]);
        assert_eq!(a.lineage().await.unwrap_err(), Error::Reconcile);
        assert_eq!(a.state(), State::Reconcile);
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn device_metadata_is_bounded() {
    assert!(DeviceInfo::new(&"n".repeat(128), &[0u8; 1024]).is_ok());
    assert_eq!(
        DeviceInfo::new(&"n".repeat(129), &[]).unwrap_err(),
        Error::Encoding
    );
    assert_eq!(
        DeviceInfo::new("bad\nname", &[]).unwrap_err(),
        Error::Encoding
    );
    assert_eq!(
        DeviceInfo::new("name", &[0u8; 1025]).unwrap_err(),
        Error::Encoding
    );
    let json = r#"{"name":"","authority_reference":[]}"#;
    assert!(serde_json::from_str::<DeviceInfo>(json).is_err());
}

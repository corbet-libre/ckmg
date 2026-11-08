//! Original Keys/crypto with explicit test-only authority routing observations.
//! No HTTPS, DHT currentness, Tor runtime or complete restore is qualified here.
use crate::support::*;
use ckmg::*;
use futures::{FutureExt, executor::block_on};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[derive(Clone, Copy, Default)]
enum AfterCheck {
    #[default]
    None,
    LoseStore,
    RegressClock,
}

#[derive(Clone)]
struct ObservedAuthority {
    guard: Guard,
    live: Rc<RefCell<Option<(Binding, PublicKey)>>>,
    member: Rc<Cell<bool>>,
    refusal: Rc<Cell<Option<Error>>>,
    calls: Rc<RefCell<Vec<Action>>>,
    after: Rc<Cell<AfterCheck>>,
    store: Memory,
    time: Time,
}
impl Authority for ObservedAuthority {
    async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        self.calls.borrow_mut().push(request.action);
        if let Action::UseTransport(_) = request.action {
            // Only the test's explicit live binding/device is sufficient here.
            // Deliberately do not consult Guard's member-lineage fixture.
            if !self
                .live
                .borrow()
                .as_ref()
                .is_some_and(|(binding, device)| {
                    binding == request.binding && *device == request.device
                })
            {
                return Err(Error::Revoked);
            }
            if request.target.is_some()
                || request.statement.is_some()
                || request.signing.is_some()
                || !request.evidence.is_empty()
            {
                return Err(Error::Unauthorized);
            }
            if let Some(error) = self.refusal.get() {
                return Err(error);
            }
            match self.after.replace(AfterCheck::None) {
                AfterCheck::None => {}
                AfterCheck::LoseStore => self.store.0.borrow_mut().records.clear(),
                AfterCheck::RegressClock => self.time.0.set(999),
            }
            return Ok(());
        }
        if !self.member.get() {
            return Err(Error::Unavailable);
        }
        self.guard.check(request).await
    }
}

struct Fixture {
    keys: Keys<Memory, Time, Random, ObservedAuthority>,
    authority: ObservedAuthority,
    store: Memory,
    receipt: Receipt,
}
async fn fixture(pending: bool) -> Fixture {
    let store = Memory::default();
    let time = Time::default();
    let authority = ObservedAuthority {
        guard: Guard::default(),
        live: Rc::new(RefCell::new(None)),
        member: Rc::new(Cell::new(true)),
        refusal: Rc::new(Cell::new(None)),
        calls: Rc::new(RefCell::new(Vec::new())),
        after: Rc::new(Cell::new(AfterCheck::None)),
        store: store.clone(),
        time: time.clone(),
    };
    let mut keys = Keys::new(store.clone(), time, Random::new(171), authority.clone());
    let binding = binding("transport-test");
    let receipt = keys
        .create_scope(
            &prf(1),
            binding.clone(),
            info(),
            &consent(Action::Create, &binding, None, 0, None, None),
        )
        .await
        .unwrap();
    let (_, device) = receipt.attested_lineage().unwrap();
    *authority.live.borrow_mut() = Some((binding, device));
    authority.guard.publish(&receipt);
    if !pending {
        keys.acknowledge(receipt.operation).await.unwrap();
    }
    authority.member.set(false);
    authority.calls.borrow_mut().clear();
    Fixture {
        keys,
        authority,
        store,
        receipt,
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn fixed_node_purposes_request_fresh_transport_admission_without_member_lineage() {
    block_on(async {
        for (node, label) in [
            (NodePurpose::Vld0, "tor.node"),
            (NodePurpose::TorOnion, "tor.onion"),
        ] {
            let mut f = fixture(false).await;
            f.authority.guard.0.borrow_mut().clear();
            for generation in [0, 7] {
                let purpose = node.purpose(generation).unwrap();
                assert_eq!(purpose.scope(), Scope::Device);
                assert_eq!(purpose.label(), label);
                assert_eq!(purpose.version(), generation);
                let handle = f.keys.key(purpose).await.unwrap();
                assert_eq!(
                    *f.authority.calls.borrow(),
                    vec![Action::UseTransport(node)]
                );
                f.authority.calls.borrow_mut().clear();
                if node == NodePurpose::Vld0 {
                    for _ in 0..2 {
                        let signature = f
                            .keys
                            .with_vld0_node(&handle, |signer, cipher| {
                                assert_eq!(signer.public_key(), cipher.public_key());
                                signer.sign(b"node envelope").unwrap()
                            })
                            .await
                            .unwrap();
                        verify(
                            &handle.certificate().key,
                            b"node envelope",
                            &Signature::new(VLD0, signature),
                        )
                        .unwrap();
                    }
                    assert_eq!(
                        *f.authority.calls.borrow(),
                        vec![Action::UseTransport(node); 2]
                    );
                    f.authority.calls.borrow_mut().clear();
                }
                #[cfg(all(feature = "native-tor", not(target_arch = "wasm32")))]
                if node == NodePurpose::TorOnion {
                    let initializer = f
                        .keys
                        .native_tor_initializer(&handle, ctrn::Scope([23; 32]))
                        .await
                        .unwrap();
                    drop(initializer);
                    assert_eq!(
                        *f.authority.calls.borrow(),
                        vec![Action::UseTransport(node)]
                    );
                    f.authority.calls.borrow_mut().clear();
                }
                #[cfg(all(feature = "browser-tor", target_arch = "wasm32"))]
                if node == NodePurpose::TorOnion {
                    let initializer = f
                        .keys
                        .browser_tor_initializer(&handle, ctrn::Scope([23; 32]))
                        .await
                        .unwrap();
                    drop(initializer);
                    assert_eq!(
                        *f.authority.calls.borrow(),
                        vec![Action::UseTransport(node)]
                    );
                    f.authority.calls.borrow_mut().clear();
                }
            }
        }
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn adjacent_labels_and_member_scope_cannot_obtain_transport_admission() {
    block_on(async {
        for (scope, label) in [
            (Scope::Member, "tor.node"),
            (Scope::Member, "tor.onion"),
            (Scope::Device, "tor.node.extra"),
            (Scope::Device, "tor.onion.extra"),
            (Scope::Device, "profile"),
        ] {
            let mut f = fixture(false).await;
            if label.starts_with("tor.") {
                // Reserved labels outside the two node purposes never reach any authority.
                assert_eq!(
                    f.keys.key(wire_purpose(scope, label)).await.unwrap_err(),
                    Error::InvalidPurpose
                );
                assert!(f.authority.calls.borrow().is_empty());
                assert_eq!(f.keys.state(), State::Authorized);
                continue;
            }
            // An ordinary label goes to the member authority, never to transport admission.
            // Its transient outage refuses this call only: the keys stay usable.
            assert_eq!(
                f.keys.key(purpose(scope, label)).await.unwrap_err(),
                Error::Unavailable
            );
            assert_eq!(*f.authority.calls.borrow(), vec![Action::Use]);
            assert_eq!(f.keys.state(), State::Authorized);
            f.authority.member.set(true);
            assert!(f.keys.key(purpose(scope, label)).await.is_ok());
            assert_eq!(*f.authority.calls.borrow(), vec![Action::Use, Action::Use]);
            assert_eq!(f.keys.state(), State::Authorized);
        }
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn node_borrow_refuses_wrong_purpose_before_authority_or_callback() {
    block_on(async {
        for (scope, label) in [
            (Scope::Member, "tor.node"),
            (Scope::Device, "tor.onion"),
            (Scope::Device, "tor.node.extra"),
            (Scope::Device, "profile"),
        ] {
            let mut f = fixture(false).await;
            f.authority.member.set(true);
            let wire = wire_purpose(scope, label);
            if wire.is_reserved() && NodePurpose::TorOnion.purpose(0).unwrap() != wire {
                // A reserved non-node purpose yields no handle at all.
                assert_eq!(f.keys.key(wire).await.unwrap_err(), Error::InvalidPurpose);
                continue;
            }
            let handle = f.keys.key(wire).await.unwrap();
            f.authority.member.set(false);
            f.authority.calls.borrow_mut().clear();
            let called = Cell::new(false);
            assert_eq!(
                f.keys
                    .with_vld0_node(&handle, |_, _| called.set(true))
                    .await,
                Err(Error::Unauthorized)
            );
            assert!(!called.get());
            assert!(f.authority.calls.borrow().is_empty());
            assert_eq!(f.keys.state(), State::Authorized);
        }
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn transport_handles_never_admit_member_operations() {
    block_on(async {
        for operation in 0..5 {
            let mut f = fixture(false).await;
            let handle = f
                .keys
                .key(NodePurpose::Vld0.purpose(0).unwrap())
                .await
                .unwrap();
            f.authority.calls.borrow_mut().clear();
            let mut outcomes = Vec::new();
            // First with the member authority transiently unavailable, then available again.
            for available in [false, true] {
                f.authority.member.set(available);
                let called = Cell::new(false);
                let result = match operation {
                    0 => f.keys.sign(&handle, b"member statement").await.map(|_| ()),
                    1 => {
                        f.keys
                            .with_vld0_record(&handle, |_, _| called.set(true))
                            .await
                    }
                    2 => f.keys.lineage().await.map(|_| ()),
                    3 => f
                        .keys
                        .key(purpose(Scope::Member, "records"))
                        .await
                        .map(|_| ()),
                    _ => f.keys.with_identity(|_| called.set(true)).await,
                };
                outcomes.push((result, called.get()));
            }
            if operation < 2 {
                // A node handle is reserved: generic purpose APIs refuse it before any
                // authority (X3 M2), whether or not the authority is available.
                for (result, called) in outcomes {
                    assert_eq!(result, Err(Error::InvalidPurpose));
                    assert!(!called);
                }
                assert!(f.authority.calls.borrow().is_empty());
                assert_eq!(f.keys.state(), State::Authorized);
                continue;
            }
            // Member operations ask the member authority (Use), never transport admission. A
            // transient outage refuses that call only; the next call with the authority back
            // succeeds, so the keys were never locked.
            assert_eq!(outcomes[0], (Err(Error::Unavailable), false));
            assert_eq!(outcomes[1].0, Ok(()));
            assert_eq!(outcomes[1].1, operation == 4);
            assert_eq!(*f.authority.calls.borrow(), vec![Action::Use, Action::Use]);
            assert_eq!(f.keys.state(), State::Authorized);
        }
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn transport_refusal_or_live_device_removal_fences_before_callback() {
    block_on(async {
        for refusal in [None, Some(Error::Unavailable), Some(Error::Unauthorized)] {
            let mut f = fixture(false).await;
            let handle = f
                .keys
                .key(NodePurpose::Vld0.purpose(0).unwrap())
                .await
                .unwrap();
            f.authority.calls.borrow_mut().clear();
            f.authority.refusal.set(refusal);
            if refusal.is_none() {
                *f.authority.live.borrow_mut() = None;
            }
            let expected = refusal.unwrap_or(Error::Revoked);
            let called = Cell::new(false);
            assert_eq!(
                f.keys
                    .with_vld0_node(&handle, |_, _| called.set(true))
                    .await,
                Err(expected)
            );
            assert!(!called.get());
            assert_eq!(
                *f.authority.calls.borrow(),
                vec![Action::UseTransport(NodePurpose::Vld0)]
            );
            if expected == Error::Unavailable {
                // A transient refusal refuses this call only: the keys stay usable and the
                // next admission, with the authority back, reaches the callback.
                assert_eq!(f.keys.state(), State::Authorized);
                f.authority.refusal.set(None);
                assert_eq!(
                    f.keys
                        .with_vld0_node(&handle, |_, _| called.set(true))
                        .await,
                    Ok(())
                );
                assert!(called.get());
                assert_eq!(f.authority.calls.borrow().len(), 2);
                continue;
            }
            // A genuine denial or a live device removal locks (or revokes) and stays so: the
            // next call is refused without asking any authority.
            assert_eq!(
                f.keys.state(),
                if expected == Error::Revoked {
                    State::Revoked
                } else {
                    State::Locked
                }
            );
            assert!(
                f.keys
                    .with_vld0_node(&handle, |_, _| called.set(true))
                    .await
                    .is_err()
            );
            assert!(!called.get());
            assert_eq!(f.authority.calls.borrow().len(), 1);
        }
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn transport_rechecks_storage_and_clock_after_authority_before_lending_or_issuing() {
    block_on(async {
        for issue in [false, true] {
            for (change, error, state) in [
                (AfterCheck::LoseStore, Error::Reconcile, State::Reconcile),
                (AfterCheck::RegressClock, Error::Clock, State::Locked),
            ] {
                let mut f = fixture(false).await;
                let handle = f
                    .keys
                    .key(NodePurpose::Vld0.purpose(0).unwrap())
                    .await
                    .unwrap();
                f.authority.calls.borrow_mut().clear();
                f.authority.after.set(change);
                let called = Cell::new(false);
                let result = if issue {
                    f.keys
                        .key(NodePurpose::Vld0.purpose(0).unwrap())
                        .await
                        .map(|_| ())
                } else {
                    f.keys
                        .with_vld0_node(&handle, |_, _| called.set(true))
                        .await
                };
                assert_eq!(result, Err(error));
                assert!(!called.get());
                assert_eq!(f.keys.state(), state);
                assert_eq!(
                    *f.authority.calls.borrow(),
                    vec![Action::UseTransport(NodePurpose::Vld0)]
                );
            }
        }
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn durable_pending_receipt_allows_transport_but_not_member_use_or_uncertain_state() {
    block_on(async {
        let mut f = fixture(true).await;
        let writes = f.store.0.borrow().writes;
        let original = f.store.0.borrow().records.clone();
        let handle = f
            .keys
            .key(NodePurpose::Vld0.purpose(0).unwrap())
            .await
            .unwrap();
        let bytes = serde_json::to_vec(&f.receipt).unwrap();
        let signature = f
            .keys
            .with_vld0_node(&handle, |signer, _| signer.sign(&bytes).unwrap())
            .await
            .unwrap();
        verify(
            &handle.certificate().key,
            &bytes,
            &Signature::new(VLD0, signature),
        )
        .unwrap();
        assert_eq!(
            f.keys.pending_output().await.unwrap(),
            Some(f.receipt.clone())
        );
        assert_eq!(
            f.keys.sign(&handle, b"member statement").await,
            Err(Error::InvalidPurpose)
        );
        assert_eq!(
            f.keys
                .key(purpose(Scope::Member, "records"))
                .await
                .unwrap_err(),
            Error::Pending
        );
        assert_eq!(f.store.0.borrow().writes, writes);
        assert!(f.store.0.borrow().records == original);
        assert_eq!(
            *f.authority.calls.borrow(),
            vec![Action::UseTransport(NodePurpose::Vld0); 2]
        );

        // A cancelled persistence operation is not a durable pending output.
        f.store.0.borrow_mut().fault = Fault::CancelBefore;
        let mut writing = Box::pin(f.keys.acknowledge(f.receipt.operation));
        assert!(writing.as_mut().now_or_never().is_none());
        drop(writing);
        assert_eq!(f.keys.state(), State::Reconcile);
        assert_eq!(
            f.keys
                .key(NodePurpose::Vld0.purpose(0).unwrap())
                .await
                .unwrap_err(),
            Error::Reconcile
        );
        assert_eq!(f.store.0.borrow().writes, writes);
        assert!(f.store.0.borrow().records == original);
        assert_eq!(f.authority.calls.borrow().len(), 2);
    });
}

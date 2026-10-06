//! Independent [`TransportSession`] custody: fixed UseTransport(Vld0) shape,
//! fresh authority per use, fail-closed wipe, and stable node keys.
mod support;
use ckmg::*;
use futures::{FutureExt, executor::block_on};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};
use support::*;

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

/// Exact fixture authority is explicitly test-only, not product.
#[derive(Clone, Default)]
struct TestAuthority {
    calls: Rc<RefCell<Vec<Record>>>,
    refusal: Rc<Cell<Option<Error>>>,
    pend: Rc<Cell<bool>>,
}

#[derive(Clone, PartialEq, Eq)]
struct Record {
    binding: Binding,
    root: Option<PublicKey>,
    device: PublicKey,
    epoch: u64,
    action: Action,
    target: bool,
    statement: bool,
    signing: bool,
    evidence: usize,
}

impl Authority for TestAuthority {
    async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        self.calls.borrow_mut().push(Record {
            binding: request.binding.clone(),
            root: request.root,
            device: request.device,
            epoch: request.epoch,
            action: request.action,
            target: request.target.is_some(),
            statement: request.statement.is_some(),
            signing: request.signing.is_some(),
            evidence: request.evidence.len(),
        });
        if self.pend.get() {
            std::future::pending::<()>().await;
            unreachable!();
        }
        if let Some(error) = self.refusal.get() {
            return Err(error);
        }
        Ok(())
    }
}

#[derive(Clone)]
struct TestClock(Rc<Cell<u64>>);
impl Clock for TestClock {
    fn now(&mut self) -> Result<u64, Error> {
        Ok(self.0.get())
    }
}

#[derive(Clone)]
struct ScriptClock {
    calls: Rc<Cell<u32>>,
    first: u64,
    rest: u64,
}
impl Clock for ScriptClock {
    fn now(&mut self) -> Result<u64, Error> {
        let n = self.calls.get();
        self.calls.set(n + 1);
        Ok(if n == 0 { self.first } else { self.rest })
    }
}

fn fixture(
    prf_byte: u8,
    community: &str,
) -> (
    TransportSession<TestClock, TestAuthority>,
    TestClock,
    TestAuthority,
    Binding,
) {
    let binding = binding(community);
    let clock = TestClock(Rc::new(Cell::new(1000)));
    let authority = TestAuthority::default();
    let session = TransportSession::new(
        &prf(prf_byte),
        binding.clone(),
        clock.clone(),
        authority.clone(),
    )
    .unwrap();
    (session, clock, authority, binding)
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn fixed_shape_and_fresh_check_per_use() {
    block_on(async {
        let (mut session, _, authority, binding) = fixture(1, "transport-session");
        // Constructor grants no authority.
        assert!(authority.calls.borrow().is_empty());
        let node = session.public_key().unwrap();
        let signature = session
            .with_node(|signer, cipher| {
                assert_eq!(signer.public_key(), cipher.public_key());
                assert_eq!(cipher.public_key(), node.value());
                let signature = signer.sign(b"node envelope").unwrap();
                let sealed = cipher.crypt(node.value(), &[7; 24], b"hello").unwrap();
                let open = cipher.crypt(node.value(), &[7; 24], &sealed).unwrap();
                assert_eq!(&open[..], b"hello");
                signature
            })
            .await
            .unwrap();
        // Original signatures/verifier show the callback succeeds.
        verify(&node, b"node envelope", &Signature::new(VLD0, signature)).unwrap();
        assert_eq!(authority.calls.borrow().len(), 1);
        let first = authority.calls.borrow()[0].clone();
        assert_eq!(first.binding, binding);
        assert_eq!(
            first.device,
            passkey::device_public_key(&prf(1), binding.community()).unwrap()
        );
        assert_eq!(first.root, None);
        assert_eq!(first.epoch, 0);
        assert_eq!(first.action, Action::UseTransport(NodePurpose::Vld0));
        assert!(!first.target && !first.statement && !first.signing);
        assert_eq!(first.evidence, 0);
        // Every with_node requires a fresh call; only UseTransport is ever sent.
        session.with_node(|_, _| ()).await.unwrap();
        let calls = authority.calls.borrow();
        assert_eq!(calls.len(), 2);
        assert!(
            calls
                .iter()
                .all(|r| r.action == Action::UseTransport(NodePurpose::Vld0))
        );
        assert_eq!(calls[1].device, first.device);
        assert_eq!(calls[1].binding, binding);
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn refusal_wipes_session_and_skips_callback() {
    block_on(async {
        for refusal in [Error::Unauthorized, Error::Unavailable] {
            let (mut session, _, authority, _) = fixture(1, "transport-session");
            session.with_node(|_, _| ()).await.unwrap();
            authority.refusal.set(Some(refusal));
            let called = Cell::new(false);
            assert_eq!(
                session
                    .with_node(|_, _| called.set(true))
                    .await
                    .unwrap_err(),
                refusal
            );
            assert!(!called.get());
            assert_eq!(session.public_key().unwrap_err(), Error::Locked);
            let len = authority.calls.borrow().len();
            assert_eq!(len, 2);
            let called = Cell::new(false);
            assert_eq!(
                session
                    .with_node(|_, _| called.set(true))
                    .await
                    .unwrap_err(),
                Error::Locked
            );
            assert!(!called.get());
            assert_eq!(authority.calls.borrow().len(), len);
        }
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn cancelled_pending_check_wipes_session() {
    block_on(async {
        let binding = binding("transport-session");
        let clock = TestClock(Rc::new(Cell::new(1000)));
        let authority = TestAuthority {
            pend: Rc::new(Cell::new(true)),
            ..TestAuthority::default()
        };
        let mut session =
            TransportSession::new(&prf(1), binding, clock, authority.clone()).unwrap();
        let called = Cell::new(false);
        let mut pending = Box::pin(session.with_node(|_, _| {
            called.set(true);
        }));
        // Poll once with no sleeps; the pending authority call never resolves.
        assert!(pending.as_mut().now_or_never().is_none());
        drop(pending);
        assert!(!called.get());
        assert_eq!(authority.calls.borrow().len(), 1);
        assert_eq!(session.public_key().unwrap_err(), Error::Locked);
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn clock_rollback_before_and_after_check_locks() {
    block_on(async {
        // Rollback before the check: last_time already advanced past now.
        let (mut session, clock, authority, _) = fixture(1, "transport-session");
        session.with_node(|_, _| ()).await.unwrap();
        clock.0.set(999);
        let called = Cell::new(false);
        assert_eq!(
            session
                .with_node(|_, _| called.set(true))
                .await
                .unwrap_err(),
            Error::Clock
        );
        assert!(!called.get());
        assert_eq!(session.public_key().unwrap_err(), Error::Locked);
        assert_eq!(authority.calls.borrow().len(), 1);

        // Rollback after the check: second clock read regresses within one check.
        let binding = binding("transport-session");
        let clock = ScriptClock {
            calls: Rc::new(Cell::new(0)),
            first: 1000,
            rest: 999,
        };
        let authority = TestAuthority::default();
        let mut session =
            TransportSession::new(&prf(1), binding, clock, authority.clone()).unwrap();
        let called = Cell::new(false);
        assert_eq!(
            session
                .with_node(|_, _| called.set(true))
                .await
                .unwrap_err(),
            Error::Clock
        );
        assert!(!called.get());
        assert_eq!(session.public_key().unwrap_err(), Error::Locked);
        assert_eq!(authority.calls.borrow().len(), 1);
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn stable_node_key_per_prf_and_binding() {
    let key = |prf_byte: u8, binding: Binding| {
        TransportSession::new(
            &prf(prf_byte),
            binding,
            TestClock(Rc::new(Cell::new(1000))),
            TestAuthority::default(),
        )
        .unwrap()
        .public_key()
        .unwrap()
    };
    let base = key(1, binding("stable"));
    // Identical PRF+Binding gives a stable node key across new sessions.
    assert_eq!(key(1, binding("stable")), base);
    assert_ne!(key(2, binding("stable")), base);
    assert_ne!(key(1, binding("other-community")), base);
    assert_ne!(
        key(1, Binding::new("stable", "other-member").unwrap()),
        base
    );
}

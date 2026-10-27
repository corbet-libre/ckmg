#![cfg(not(target_arch = "wasm32"))]
//! Decided 2026-10-27 (custody review): a transient authority outcome ("could not
//! check": `Unavailable`) refuses that one call but never locks the keys; only a
//! genuine denial locks, and that lock stays.
mod support;
use ckmg::*;
use futures::executor::block_on;
use std::{cell::Cell, rc::Rc};
use support::*;

/// The shared test authority, except that it answers its next check with `next`.
#[derive(Clone)]
struct Scripted {
    inner: Guard,
    next: Rc<Cell<Option<Error>>>,
}
impl Authority for Scripted {
    async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        if let Some(error) = self.next.take() {
            return Err(error);
        }
        self.inner.check(request).await
    }
}

async fn unlocked(
    seed: u8,
) -> (
    Keys<Memory, Time, Random, Scripted>,
    KeyHandle,
    Rc<Cell<Option<Error>>>,
) {
    let store = Memory::default();
    let time = Time::default();
    let guard = Guard::default();
    let next = Rc::new(Cell::new(None));
    let mut keys = Keys::new(
        store,
        time,
        Random::new(seed),
        Scripted {
            inner: guard.clone(),
            next: next.clone(),
        },
    );
    let b = binding("a");
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
    keys.acknowledge(receipt.operation).await.unwrap();
    let key = keys.key(purpose(Scope::Device, "x")).await.unwrap();
    keys.sign(&key, b"x").await.unwrap();
    (keys, key, next)
}

#[test]
fn a_transient_authority_outcome_refuses_the_call_but_never_locks_the_keys() {
    block_on(async {
        let (mut keys, key, next) = unlocked(201).await;
        let before = keys.state();
        next.set(Some(Error::Unavailable));
        assert_eq!(keys.sign(&key, b"x").await, Err(Error::Unavailable));
        assert_eq!(keys.state(), before);
        // A later call checks again and succeeds.
        keys.sign(&key, b"x").await.unwrap();
    });
}

#[test]
fn a_genuine_denial_still_locks_and_stays_locked() {
    block_on(async {
        let (mut keys, key, next) = unlocked(202).await;
        next.set(Some(Error::Unauthorized));
        assert_eq!(keys.sign(&key, b"x").await, Err(Error::Unauthorized));
        assert_eq!(keys.state(), State::Locked);
        // The authority would admit again; the lock holds anyway.
        assert!(keys.sign(&key, b"x").await.is_err());
        assert_eq!(keys.state(), State::Locked);
    });
}

//! Original Keys/pairing/rotation with scoped test-only current owner checks.
//! This does not qualify production HTTPS admission or initialized account proof.
#![cfg(feature = "wallet-engine")]
mod support;
use ckmg::*;
use futures::{FutureExt, executor::block_on};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    task::{Poll, Waker},
};
use support::*;

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[derive(Clone)]
struct Current {
    guard: Guard,
    owner_clock: Time,
    checked: Rc<RefCell<Option<(Binding, PublicKey, PublicKey, u64)>>>,
}
impl Authority for Current {
    async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        let exact = (
            request.binding.clone(),
            request.root.ok_or(Error::Unauthorized)?,
            request.device,
            request.epoch,
        );
        self.guard.check(request).await?;
        *self.checked.borrow_mut() = Some(exact);
        Ok(())
    }
    fn check_record_recipient_current(&mut self, request: Authorization<'_>) -> Result<u64, Error> {
        if request.action != Action::Use
            || request.target.is_some()
            || request.statement.is_some()
            || request.signing.is_some()
            || !request.evidence.is_empty()
            || self.checked.borrow().as_ref()
                != Some(&(
                    request.binding.clone(),
                    request.root.ok_or(Error::Unauthorized)?,
                    request.device,
                    request.epoch,
                ))
        {
            return Err(Error::Unauthorized);
        }
        let anchors = self.guard.0.borrow();
        let current = anchors
            .get(request.binding.community())
            .ok_or(Error::Unavailable)?;
        current.verify()?;
        if !current.devices.contains(&request.device) {
            return Err(Error::Revoked);
        }
        if current.binding != *request.binding
            || Some(current.root) != request.root
            || current.epoch != request.epoch
        {
            return Err(Error::Unauthorized);
        }
        let observed = self.owner_clock.0.get();
        if observed < request.now {
            return Err(Error::Clock);
        }
        Ok(observed)
    }
}

#[derive(Clone, Default)]
struct Gate {
    armed: Rc<Cell<bool>>,
    reads: Rc<Cell<usize>>,
    reached: Rc<Cell<bool>>,
    released: Rc<Cell<bool>>,
    waker: Rc<RefCell<Option<Waker>>>,
}
impl Gate {
    fn arm(&self) {
        self.armed.set(true);
        self.reads.set(0);
    }
    fn release(&self) {
        self.released.set(true);
        if let Some(waker) = self.waker.borrow_mut().take() {
            waker.wake();
        }
    }
}
#[derive(Clone)]
struct Gated {
    memory: Memory,
    gate: Gate,
}
impl SecureStore for Gated {
    async fn load(&mut self, location: &Locator) -> Result<Option<Vec<u8>>, Error> {
        let bytes = self.memory.load(location).await?;
        if self.gate.armed.get() {
            self.gate.reads.set(self.gate.reads.get() + 1);
            if self.gate.reads.get() == 2 {
                self.gate.reached.set(true);
                std::future::poll_fn(|context| {
                    if self.gate.released.get() {
                        Poll::Ready(())
                    } else {
                        *self.gate.waker.borrow_mut() = Some(context.waker().clone());
                        Poll::Pending
                    }
                })
                .await;
            }
        }
        Ok(bytes)
    }
    async fn compare_exchange(
        &mut self,
        location: &Locator,
        expected: Option<[u8; 32]>,
        replacement: &[u8],
    ) -> Result<Commit, Error> {
        self.memory
            .compare_exchange(location, expected, replacement)
            .await
    }
}

fn authority(guard: &Guard, time: &Time) -> Current {
    Current {
        guard: guard.clone(),
        owner_clock: time.clone(),
        checked: Rc::default(),
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn equal_passkeys_keep_one_recipient_and_default_current_port_refuses() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut first = machine(&store, &time, &guard, 131);
        let mut peer = machine(&store, &time, &guard, 132);
        create(&mut first, &guard, &prf(1), &binding("community")).await;
        pair(&mut first, &mut peer, &guard, &prf(2)).await;
        assert_eq!(
            first.with_record_recipient(|r| r.public_key()).await,
            Err(Error::Unauthorized)
        );
        assert_eq!(first.state(), State::Locked);
        let mut first = Keys::new(
            store.clone(),
            time.clone(),
            Random::new(133),
            authority(&guard, &time),
        );
        first.unlock(&prf(1), "community").await.unwrap();
        let coordinate = first
            .with_record_recipient(|r| r.public_key())
            .await
            .unwrap();
        let mut peer = Keys::new(
            store.clone(),
            time.clone(),
            Random::new(134),
            authority(&guard, &time),
        );
        peer.unlock(&prf(2), "community").await.unwrap();
        assert_eq!(
            coordinate,
            peer.with_record_recipient(|r| r.public_key())
                .await
                .unwrap()
        );
        first.lock();
        assert_eq!(
            first.with_record_recipient(|r| r.public_key()).await,
            Err(Error::Locked)
        );
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn final_store_wait_cannot_hide_real_original_rotation_revocation() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut first = machine(&store, &time, &guard, 135);
        let mut peer = machine(&store, &time, &guard, 136);
        let created = create(&mut first, &guard, &prf(1), &binding("community")).await;
        let (_, device) = created.attested_lineage().unwrap();
        pair(&mut first, &mut peer, &guard, &prf(2)).await;
        let gate = Gate::default();
        let mut first = Keys::new(
            Gated {
                memory: store,
                gate: gate.clone(),
            },
            time.clone(),
            Random::new(137),
            authority(&guard, &time),
        );
        first.unlock(&prf(1), "community").await.unwrap();
        gate.arm();
        let called = Cell::new(false);
        let mut future = Box::pin(first.with_record_recipient(|_| called.set(true)));
        assert!(future.as_mut().now_or_never().is_none());
        assert!(gate.reached.get());
        prepare(&mut peer, device).await;
        let rotation = peer.commit().await.unwrap().unwrap();
        guard.publish(&rotation);
        peer.acknowledge(rotation.operation).await.unwrap();
        gate.release();
        assert_eq!(future.await, Err(Error::Revoked));
        assert!(!called.get());
        assert_eq!(first.state(), State::Revoked);
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn final_wait_rollback_or_newer_genuine_owner_floor_refuses_before_callback() {
    block_on(async {
        for rollback in [true, false] {
            let store = Memory::default();
            let time = Time::default();
            let owner_time = Time::default();
            let guard = Guard::default();
            let mut setup = machine(&store, &time, &guard, 138);
            create(&mut setup, &guard, &prf(1), &binding("community")).await;
            let gate = Gate::default();
            let mut keys = Keys::new(
                Gated {
                    memory: store,
                    gate: gate.clone(),
                },
                time.clone(),
                Random::new(139),
                authority(&guard, &owner_time),
            );
            keys.unlock(&prf(1), "community").await.unwrap();
            gate.arm();
            let called = Cell::new(false);
            let mut future = Box::pin(keys.with_record_recipient(|_| called.set(true)));
            assert!(future.as_mut().now_or_never().is_none());
            assert!(gate.reached.get());
            if rollback {
                time.0.set(999);
            } else {
                owner_time.0.set(1001);
            }
            gate.release();
            assert_eq!(future.await, Err(Error::Clock));
            assert!(!called.get());
            assert_eq!(keys.state(), State::Locked);
        }
    });
}

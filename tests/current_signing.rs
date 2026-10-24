//! Original Keys/intent/store adversaries; the owner is a strict test fixture,
//! not production HTTPS or Charter qualification.
mod support;
use ckmg::*;
use futures::{
    FutureExt,
    executor::block_on,
    lock::{Mutex, OwnedMutexGuard},
};
use std::{cell::Cell, rc::Rc, sync::Arc};
use support::*;

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);
const ORIGIN: &str = "https://garden.example.com";
const BYTES: &[u8] = b"cfrm.account.request.v1\0exact original owner delegation";
const FORMAT: DeviceFormat = DeviceFormat::AccountRequest;

struct Held {
    current: Guard,
    intent: IntentVerifier,
    time: Time,
    mode: Rc<Cell<u8>>,
    armed: Rc<Cell<bool>>,
    accepted: Option<(Vec<u8>, u64)>,
    owner: Arc<Mutex<()>>,
    lease: Option<OwnedMutexGuard<()>>,
}
impl Authority for Held {
    async fn check_device_signing(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        self.lease = Some(self.owner.clone().lock_owned().await);
        self.check(request).await
    }
    fn discard_current_attempt(&mut self) {
        self.lease = None;
        self.accepted = None;
    }
    async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        self.current
            .check(Authorization {
                binding: request.binding,
                root: request.root,
                device: request.device,
                epoch: request.epoch,
                action: request.action,
                target: request.target,
                statement: request.statement,
                signing: request.signing,
                now: request.now,
                evidence: request.evidence,
            })
            .await?;
        if request.action == Action::SignDeviceEd25519 {
            self.intent.consume(&request, ORIGIN)?;
            let signing = request.signing.ok_or(Error::Unauthorized)?;
            self.accepted = Some((signing.transcript.to_vec(), signing.expires));
            self.armed.set(true);
            if self.mode.get() == 8 {
                std::future::pending::<()>().await;
            }
        }
        Ok(())
    }
    fn check_device_signing_current(&mut self, request: Authorization<'_>) -> Result<u64, Error> {
        if self.mode.get() == 5 {
            return self.current.check_device_signing_current(request);
        }
        let signing = request.signing.ok_or(Error::Unauthorized)?;
        if self.accepted.take() != Some((signing.transcript.to_vec(), signing.expires))
            || request.action != Action::SignDeviceEd25519
            || request.target.is_some()
            || request.statement.is_some()
            || !request.evidence.is_empty()
        {
            return Err(Error::Unauthorized);
        }
        let anchors = self.current.0.borrow();
        let lineage = anchors
            .get(request.binding.community())
            .ok_or(Error::Unauthorized)?;
        if lineage.binding != *request.binding
            || Some(lineage.root) != request.root
            || lineage.epoch != request.epoch
            || !lineage.devices.contains(&request.device)
        {
            return Err(Error::Revoked);
        }
        if signing.expires > 1200 || request.now >= signing.expires {
            return Err(Error::Expired);
        }
        match self.mode.get() {
            6 => Ok(1101),
            7 => {
                self.time.0.set(1200);
                Ok(request.now)
            }
            _ => Ok(self.time.0.get()),
        }
    }
}
#[derive(Clone)]
struct Store {
    inner: Memory,
    current: Guard,
    time: Time,
    mode: Rc<Cell<u8>>,
    armed: Rc<Cell<bool>>,
}
impl SecureStore for Store {
    async fn load(&mut self, location: &Locator) -> Result<Option<Vec<u8>>, Error> {
        if self.armed.replace(false) {
            match self.mode.get() {
                1 => self
                    .current
                    .0
                    .borrow_mut()
                    .get_mut("a")
                    .unwrap()
                    .devices
                    .clear(),
                2 => self.current.0.borrow_mut().get_mut("a").unwrap().epoch += 1,
                3 => self.time.0.set(1200),
                4 => self.time.0.set(999),
                9 => std::future::pending::<()>().await,
                10 => self.inner.0.borrow_mut().records.clear(),
                11 => return Err(Error::Unavailable),
                _ => {}
            }
        }
        self.inner.load(location).await
    }
    async fn compare_exchange(
        &mut self,
        location: &Locator,
        expected: Option<[u8; 32]>,
        replacement: &[u8],
    ) -> Result<Commit, Error> {
        self.inner
            .compare_exchange(location, expected, replacement)
            .await
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn current_signing_checks_the_actual_owner_after_storage_and_consumes_intent() {
    block_on(async {
        for mode in 0..15 {
            let memory = Memory::default();
            let time = Time::default();
            let current = Guard::default();
            let mut original = machine(&memory, &time, &current, 103);
            create(&mut original, &current, &prf(1), &binding("a")).await;
            let lineage = original.lineage().await.unwrap();
            let device = original.device_public_key().await.unwrap();
            drop(original);
            let (mut admission, intent) = intent_channel();
            let selected = Rc::new(Cell::new(mode));
            let armed = Rc::new(Cell::new(false));
            let owner = Arc::new(Mutex::new(()));
            let mut keys = Keys::new(
                Store {
                    inner: memory.clone(),
                    current: current.clone(),
                    time: time.clone(),
                    mode: selected.clone(),
                    armed: armed.clone(),
                },
                time.clone(),
                Random::new(104),
                Held {
                    current: current.clone(),
                    intent,
                    time: time.clone(),
                    mode: selected.clone(),
                    armed,
                    accepted: None,
                    owner: owner.clone(),
                    lease: None,
                },
            );
            keys.unlock(&prf(1), "a").await.unwrap();
            let admitted = admission
                .admit(
                    AdmittedCommand {
                        binding: lineage.binding,
                        origin: ORIGIN.into(),
                        action: if mode == 14 {
                            Action::AuthorizeAccountDevice
                        } else {
                            Action::SignDeviceEd25519
                        },
                        device,
                        root: Some(lineage.root),
                        epoch: lineage.epoch,
                        target: None,
                        statement: None,
                        transcript: Some(BYTES.to_vec()),
                        format: (mode != 14).then_some(FORMAT),
                        expires: 1200,
                    },
                    1000,
                )
                .unwrap();
            if mode == 8 || mode == 9 {
                assert!(
                    keys.sign_device_ed25519_current(FORMAT, BYTES, 1200)
                        .now_or_never()
                        .is_none()
                );
            } else {
                let result = keys
                    .sign_device_ed25519_current(
                        FORMAT,
                        if mode == 12 {
                            b"cfrm.account.request.v1\0changed transcript"
                        } else {
                            BYTES
                        },
                        if mode == 13 { 1199 } else { 1200 },
                    )
                    .await;
                if mode == 0 {
                    let signature = result.unwrap();
                    verify_ed25519(device.value(), BYTES, &signature).unwrap();
                    assert!(
                        verify_ed25519(
                            device.value(),
                            b"cfrm.account.request.v1\0changed transcript",
                            &signature
                        )
                        .is_err()
                    );
                } else {
                    assert!(
                        result.is_err(),
                        "case {mode} signed without current authority"
                    );
                }
            }
            selected.set(0);
            assert!(
                owner.try_lock().is_some(),
                "case {mode} retained its scoped guard"
            );
            if mode != 0 {
                assert_eq!(keys.state(), State::Locked);
            }
            assert!(
                keys.sign_device_ed25519_current(FORMAT, BYTES, 1200)
                    .await
                    .is_err()
            );
            assert_eq!(keys.state(), State::Locked);
            drop(admitted);
        }
    });
}

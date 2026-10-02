//! Exact intent is tested with original Keys crypto/storage and a test-only
//! lineage fixture. This fixture does not establish production passkey G3.
mod support;
use ckmg::*;
use futures::{FutureExt, executor::block_on};
use std::{cell::Cell, rc::Rc};
use support::*;

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

struct SigningAuthority {
    current: Guard,
    intent: IntentVerifier,
    store: Memory,
    time: Time,
    after: Rc<Cell<u8>>,
}
impl Authority for SigningAuthority {
    async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        if request.action == Action::LendDeviceSigner {
            return Err(Error::Unauthorized);
        }
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
            self.intent
                .consume(&request, "https://garden.example.com")?;
            match self.after.get() {
                1 => self.time.0.set(1200),
                2 => self.store.0.borrow_mut().records.clear(),
                3 => self.time.0.set(999),
                4 => self.store.0.borrow_mut().read_failure = true,
                5 => std::future::pending::<()>().await,
                _ => {}
            }
        }
        Ok(())
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn exact_signing_rechecks_after_await_and_never_reuses_consumed_intent() {
    block_on(async {
        for case in 0..8 {
            let store = Memory::default();
            let time = Time::default();
            let current = Guard::default();
            let mut initial = machine(&store, &time, &current, 98);
            create(&mut initial, &current, &prf(1), &binding("a")).await;
            let lineage = initial.lineage().await.unwrap();
            let device = initial.device_public_key().await.unwrap();
            drop(initial);
            let (mut admission, intent) = intent_channel();
            let after = Rc::new(Cell::new(if case >= 3 { case - 2 } else { 0 }));
            let mut keys = Keys::new(
                store.clone(),
                time.clone(),
                Random::new(99),
                SigningAuthority {
                    current,
                    intent,
                    store: store.clone(),
                    time: time.clone(),
                    after: after.clone(),
                },
            );
            keys.unlock(&prf(1), "a").await.unwrap();
            let transcript = b"original prepared owner bytes";
            let guard = admission
                .admit(
                    AdmittedCommand {
                        binding: lineage.binding,
                        origin: "https://garden.example.com".into(),
                        action: Action::SignDeviceEd25519,
                        device,
                        root: Some(lineage.root),
                        epoch: lineage.epoch,
                        target: None,
                        statement: None,
                        transcript: Some(transcript.to_vec()),
                        expires: 1200,
                    },
                    1000,
                )
                .unwrap();
            // Public metadata cannot consume the admitted signing attempt.
            assert_eq!(keys.device_public_key().await.unwrap(), device);
            if case == 7 {
                // Drop a suspended authorization after it consumed exact intent.
                assert!(
                    keys.sign_device_ed25519(transcript, 1200)
                        .now_or_never()
                        .is_none()
                );
                after.set(0);
                assert_eq!(
                    keys.sign_device_ed25519(transcript, 1200).await,
                    Err(Error::Unauthorized)
                );
            } else {
                let result = keys
                    .sign_device_ed25519(
                        if case == 1 {
                            b"different owner bytes"
                        } else {
                            transcript
                        },
                        if case == 2 { 1199 } else { 1200 },
                    )
                    .await;
                match case {
                    0 => {
                        let signature = result.unwrap();
                        verify_ed25519(device.value(), transcript, &signature).unwrap();
                        assert!(verify_ed25519(device.value(), b"different", &signature).is_err());
                        assert_eq!(
                            keys.sign_device_ed25519(transcript, 1200).await,
                            Err(Error::Unauthorized)
                        );
                    }
                    1 | 2 => assert_eq!(result, Err(Error::Unauthorized)),
                    3 => assert_eq!(result, Err(Error::Expired)),
                    4 => assert_eq!(result, Err(Error::Reconcile)),
                    5 => assert_eq!(result, Err(Error::Clock)),
                    _ => assert_eq!(result, Err(Error::Unavailable)),
                }
            }
            drop(guard);
        }
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn metadata_authority_does_not_lend_a_generic_device_signer() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let current = Guard::default();
        let mut initial = machine(&store, &time, &current, 100);
        create(&mut initial, &current, &prf(1), &binding("a")).await;
        drop(initial);
        let (_, intent) = intent_channel();
        let mut keys = Keys::new(
            store.clone(),
            time.clone(),
            Random::new(101),
            SigningAuthority {
                current,
                intent,
                store,
                time,
                after: Rc::new(Cell::new(0)),
            },
        );
        keys.unlock(&prf(1), "a").await.unwrap();
        keys.device_public_key().await.unwrap();
        let called = Cell::new(false);
        assert_eq!(
            keys.with_device_ed25519_signer(|_| called.set(true)).await,
            Err(Error::Unauthorized)
        );
        assert!(!called.get());
    });
}

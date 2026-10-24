//! Real Keys/root signatures and one-use intent under a strict test-only owner.
//! This file does not qualify the HTTPS/Charter or account issuer composition.
mod support;
use ckmg::*;
use data_encoding::BASE64URL_NOPAD as B64;
use futures::{FutureExt, executor::block_on};
use std::{cell::Cell, rc::Rc};
use support::*;

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

const ORIGIN: &str = "https://garden.example.com";
fn community() -> Binding {
    Binding::new("garden", &"12".repeat(48)).unwrap()
}

struct HeldOwner {
    current: Guard,
    intent: IntentVerifier,
    time: Time,
    store: Memory,
    mode: Rc<Cell<u8>>,
    transcript: Option<Vec<u8>>,
}
impl HeldOwner {
    fn current(&self, request: &Authorization<'_>) -> Result<(), Error> {
        let anchors = self.current.0.borrow();
        let lineage = anchors
            .get(request.binding.community())
            .ok_or(Error::Unauthorized)?;
        if lineage.binding != *request.binding
            || Some(lineage.root) != request.root
            || lineage.epoch != request.epoch
            || !lineage.devices.contains(&request.device)
            || request.action != Action::AuthorizeAccountDevice
            || request.target.is_some()
            || request.statement.is_some()
            || !request.evidence.is_empty()
        {
            return Err(Error::Unauthorized);
        }
        let signing = request.signing.ok_or(Error::Unauthorized)?;
        if signing.expires > 1100 || request.now >= signing.expires {
            return Err(Error::Expired);
        }
        Ok(())
    }
}
impl Authority for HeldOwner {
    async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        if request.action == Action::Use {
            return self.current.check(request).await;
        }
        self.current(&request)?;
        self.intent.consume(&request, ORIGIN)?;
        self.transcript = Some(request.signing.unwrap().transcript.to_vec());
        match self.mode.get() {
            1 => self.time.0.set(1100),
            2 => self.time.0.set(999),
            3 => self.store.0.borrow_mut().records.clear(),
            4 => std::future::pending::<()>().await,
            5 => self.store.0.borrow_mut().read_failure = true,
            9 => self.mode.set(13),
            10 => self
                .current
                .0
                .borrow_mut()
                .get_mut("garden")
                .unwrap()
                .devices
                .clear(),
            11 => self.current.0.borrow_mut().get_mut("garden").unwrap().epoch += 1,
            _ => {}
        }
        Ok(())
    }
    fn check_account_device_current(&mut self, request: Authorization<'_>) -> Result<u64, Error> {
        self.current(&request)?;
        if self.transcript.as_deref() != Some(request.signing.unwrap().transcript) {
            return Err(Error::Unauthorized);
        }
        match self.mode.get() {
            6 => Err(Error::Revoked),
            12 => self.current.check_account_device_current(request),
            7 => Ok(1101),
            8 => {
                self.time.0.set(1100);
                Ok(request.now)
            }
            _ => Ok(self.time.0.get()),
        }
    }
}
#[derive(Clone)]
struct DelayedStore {
    inner: Memory,
    mode: Rc<Cell<u8>>,
}
impl SecureStore for DelayedStore {
    async fn load(&mut self, location: &Locator) -> Result<Option<Vec<u8>>, Error> {
        if self.mode.get() == 13 {
            std::future::pending::<()>().await;
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
type AccountKeys = Keys<DelayedStore, Time, Random, HeldOwner>;
async fn fixture() -> (
    AccountKeys,
    IntentAdmission,
    Memory,
    Time,
    Guard,
    Rc<Cell<u8>>,
) {
    let store = Memory::default();
    let time = Time::default();
    let current = Guard::default();
    let mut original = machine(&store, &time, &current, 41);
    create(&mut original, &current, &prf(9), &community()).await;
    drop(original);
    let (admission, intent) = intent_channel();
    let mode = Rc::new(Cell::new(0));
    let mut keys = Keys::new(
        DelayedStore {
            inner: store.clone(),
            mode: mode.clone(),
        },
        time.clone(),
        Random::new(42),
        HeldOwner {
            current: current.clone(),
            intent,
            time: time.clone(),
            store: store.clone(),
            mode: mode.clone(),
            transcript: None,
        },
    );
    keys.unlock(&prf(9), "garden").await.unwrap();
    (keys, admission, store, time, current, mode)
}
fn admit(
    admission: &mut IntentAdmission,
    plan: &AccountDevicePlan,
    action: Action,
    now: u64,
) -> Option<IntentGuard> {
    admission
        .admit(
            AdmittedCommand {
                binding: plan.binding().clone(),
                origin: ORIGIN.into(),
                action,
                device: plan.device(),
                root: Some(plan.root()),
                epoch: plan.epoch(),
                target: None,
                statement: None,
                transcript: Some(plan.signing_bytes().to_vec()),
                format: None,
                expires: plan.expires_at(),
            },
            now,
        )
        // Device signing is typed, so the account-device bytes are never admitted for it.
        .inspect_err(|_| assert_eq!(action, Action::SignDeviceEd25519))
        .ok()
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn fixed_current_root_signs_original_account_device_bytes_only_after_exact_intent() {
    block_on(async {
        let (mut keys, mut admission, _, _, _, _) = fixture().await;
        let plan = keys.prepare_account_device(1100).await.unwrap();
        let bytes = plan.signing_bytes().to_vec();
        let root = plan.root();
        let device = plan.device();
        let _guard = admit(&mut admission, &plan, Action::AuthorizeAccountDevice, 1000);
        let output = keys.authorize_account_device(plan).await.unwrap();
        assert_eq!(output.signing_bytes().unwrap(), bytes);
        let wire: serde_json::Value = serde_json::from_slice(&output.to_bytes().unwrap()).unwrap();
        assert_eq!(wire["version"], 1);
        assert_eq!(wire["communityId"], "garden");
        use sha2::{Digest, Sha256};
        assert_eq!(wire["memberId"], B64.encode(&Sha256::digest([0x12; 48])));
        assert_eq!(wire["rootPublicKey"], B64.encode(root.value()));
        assert_eq!(wire["devicePublicKey"], B64.encode(device.value()));
        assert_eq!(wire["issuedAt"], 1000);
        assert_eq!(wire["expiresAt"], 1100);
        let signature: [u8; 64] = B64
            .decode(wire["signature"].as_str().unwrap().as_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        verify_ed25519(root.value(), &bytes, &signature).unwrap();
        assert!(verify_ed25519(device.value(), &bytes, &signature).is_err());
        let mut changed = bytes.clone();
        changed.push(0);
        assert!(verify_ed25519(root.value(), &changed, &signature).is_err());
        let second = keys.prepare_account_device(1100).await.unwrap();
        assert!(keys.authorize_account_device(second).await.is_err());
        assert_eq!(keys.state(), State::Locked);
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn cancellation_store_change_clock_expiry_and_final_owner_refusal_release_no_signature() {
    block_on(async {
        for failure in 1..=12 {
            let (mut keys, mut admission, _, _, _, mode) = fixture().await;
            let plan = keys.prepare_account_device(1100).await.unwrap();
            let _guard = admit(&mut admission, &plan, Action::AuthorizeAccountDevice, 1000);
            mode.set(failure);
            if matches!(failure, 4 | 9) {
                assert!(keys.authorize_account_device(plan).now_or_never().is_none());
            } else {
                assert!(keys.authorize_account_device(plan).await.is_err());
            }
            assert_eq!(keys.state(), State::Locked);
        }
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn distinct_intent_owner_deadline_and_reopened_session_are_mandatory() {
    block_on(async {
        for failure in 0..4 {
            let (mut keys, mut admission, _, _, _, _) = fixture().await;
            let plan = keys
                .prepare_account_device(if failure == 1 { 1101 } else { 1100 })
                .await
                .unwrap();
            let guard = admit(
                &mut admission,
                &plan,
                if failure == 0 {
                    Action::SignDeviceEd25519
                } else {
                    Action::AuthorizeAccountDevice
                },
                1000,
            );
            if failure == 2 {
                keys.unlock(&prf(9), "garden").await.unwrap();
            }
            if failure == 3 {
                admission.cancel();
            }
            assert!(keys.authorize_account_device(plan).await.is_err());
            assert_eq!(keys.state(), State::Locked);
            drop(guard);
        }
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn wallet_uuid_and_noncanonical_community_members_cannot_prepare_account_root_authority() {
    block_on(async {
        for binding in [
            Binding::new("wallet", "00000000-0000-4000-8000-000000000001").unwrap(),
            Binding::new("wallet", &"12".repeat(48)).unwrap(),
            Binding::new("garden", &"AB".repeat(48)).unwrap(),
            Binding::new("garden", "caller-account-id").unwrap(),
        ] {
            let store = Memory::default();
            let time = Time::default();
            let current = Guard::default();
            let mut keys = machine(&store, &time, &current, 53);
            create(&mut keys, &current, &prf(8), &binding).await;
            assert!(keys.prepare_account_device(1100).await.is_err());
        }
    });
}

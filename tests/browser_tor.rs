//! Real Keys state/crypto and the original Node over a controlled private engine
//! seam. The signed fixture Authority is not production G3, Tor or Snowflake.
#![cfg(all(feature = "browser-tor", target_arch = "wasm32"))]

mod support;
use ckmg::*;
use ed25519_dalek::SigningKey;
use js_sys::{Function, Uint8Array};
use std::sync::Arc;
use support::*;
use wasm_bindgen::{JsCast, prelude::*};
use wasm_bindgen_test::wasm_bindgen_test;
use zeroize::Zeroizing;

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen(module = "/tests/browser-tor-support.js")]
extern "C" {
    fn fixture() -> JsValue;
    fn factory(fixture: &JsValue, verify: &Function) -> Function;
    fn count(fixture: &JsValue, name: &str) -> u32;
    fn flag(fixture: &JsValue, name: &str) -> bool;
    fn scope(fixture: &JsValue) -> Uint8Array;
    fn aborted(fixture: &JsValue) -> bool;
    fn hold(fixture: &JsValue);
    fn release(fixture: &JsValue);
    fn matches(fixture: &JsValue, supplied: &Uint8Array, verify: &Function) -> bool;
    fn refuses(fixture: &JsValue, supplied: &Uint8Array) -> bool;
    #[wasm_bindgen(js_name = afterTurn)]
    fn after_turn(callback: &Function);
}

const NAMESPACE: [u8; 32] = [17; 32];
type SeedVerifier = Closure<dyn Fn(Uint8Array) -> bool>;

// Compare only the public key. The transferred seed and Rust copy are transient
// and wiped; the SigningKey uses the existing enabled zeroize-on-drop feature.
fn verifier(expected: PublicKey) -> SeedVerifier {
    SeedVerifier::new(move |supplied: Uint8Array| {
        if supplied.length() != 32 {
            supplied.fill(0, 0, supplied.length());
            return false;
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        supplied.copy_to(&mut bytes[..]);
        supplied.fill(0, 0, supplied.length());
        expected.kind() == VLD0
            && SigningKey::from_bytes(&bytes).verifying_key().to_bytes() == *expected.value()
    })
}

struct TransportClock;
impl ctrn::Clock for TransportClock {
    fn now(&self) -> u64 {
        0
    }
    fn sleep_until(&self, _: u64) -> ctrn::BoxFuture<'_, ()> {
        Box::pin(futures::future::pending())
    }
}

fn initialize(
    initializer: BrowserTorInitializer,
    fixture: &JsValue,
    verify: &SeedVerifier,
) -> Result<Arc<ctrn::Node>, ctrn::Error> {
    initializer.initialize(
        factory(fixture, verify.as_ref().unchecked_ref()),
        Arc::new(TransportClock),
        ctrn::Limits {
            streams: 8,
            bootstrap_ms: 1000,
            operation_ms: 1000,
        },
    )
}

async fn setup(seed: u8) -> (Memory, Time, Guard, Machine) {
    let store = Memory::default();
    let time = Time::default();
    let guard = Guard::default();
    let mut keys = machine(&store, &time, &guard, seed);
    create(&mut keys, &guard, &prf(1), &binding("garden")).await;
    (store, time, guard, keys)
}

async fn settle() {
    let (send, receive) = futures::channel::oneshot::channel();
    let callback = Closure::once(move || {
        let _ = send.send(());
    });
    after_turn(callback.as_ref().unchecked_ref());
    receive.await.unwrap();
}

#[wasm_bindgen_test]
async fn exact_device_purpose_and_namespace_bind_the_original_ed25519_key() {
    let (_, _, _, mut keys) = setup(81).await;
    let fixture = fixture();
    for invalid in [
        purpose(Scope::Member, "tor.onion"),
        purpose(Scope::Device, "profile"),
    ] {
        let handle = keys.key(invalid).await.unwrap();
        assert!(matches!(
            keys.browser_tor_initializer(&handle, ctrn::Scope(NAMESPACE))
                .await,
            Err(Error::InvalidPurpose)
        ));
    }
    assert_eq!(count(&fixture, "calls"), 0);
    let handle = keys.key(purpose(Scope::Device, "tor.onion")).await.unwrap();
    let verify = verifier(handle.certificate().key);
    let initializer = keys
        .browser_tor_initializer(&handle, ctrn::Scope(NAMESPACE))
        .await
        .unwrap();
    assert_eq!(initializer.community(), "garden");
    let node = initialize(initializer, &fixture, &verify).unwrap();
    assert_eq!(node.health(), ctrn::State::Stopped);
    assert_eq!(count(&fixture, "calls"), 0);
    node.start().await.unwrap();
    assert_eq!(node.health(), ctrn::State::Ready);
    assert_eq!(count(&fixture, "calls"), 1);
    assert!(flag(&fixture, "matched"));
    assert!(flag(&fixture, "wiped"));
    assert!(flag(&fixture, "snowflake")); // Option forwarding only, not connectivity.
    assert_eq!(scope(&fixture).to_vec(), NAMESPACE);
    for wrong in [vec![17; 31], vec![17; 33], vec![18; 32]] {
        assert!(refuses(&fixture, &Uint8Array::from(wrong.as_slice())));
    }
    assert!(matches(
        &fixture,
        &Uint8Array::from(NAMESPACE.as_slice()),
        verify.as_ref().unchecked_ref()
    ));
    node.stop();
    drop(node);
    assert_eq!(count(&fixture, "stops"), 1);
    assert!(refuses(&fixture, &Uint8Array::from(NAMESPACE.as_slice())));
}

#[wasm_bindgen_test]
async fn lock_drop_and_observed_authority_loss_stop_bound_nodes_and_callbacks() {
    for case in 0..5 {
        let (store, time, guard, keys) = setup(82 + case).await;
        let mut keys = Some(keys);
        let handle = keys
            .as_mut()
            .unwrap()
            .key(purpose(Scope::Device, "tor.onion"))
            .await
            .unwrap();
        let verify = verifier(handle.certificate().key);
        let fixture = fixture();
        let initializer = keys
            .as_mut()
            .unwrap()
            .browser_tor_initializer(&handle, ctrn::Scope(NAMESPACE))
            .await
            .unwrap();
        let node = initialize(initializer, &fixture, &verify).unwrap();
        node.start().await.unwrap();
        assert!(flag(&fixture, "matched"));
        match case {
            0 => keys.as_mut().unwrap().lock(),
            1 => drop(keys.take()),
            _ => {
                match case {
                    2 => guard
                        .0
                        .borrow_mut()
                        .get_mut("garden")
                        .unwrap()
                        .devices
                        .clear(),
                    3 => store.0.borrow_mut().records.clear(),
                    _ => time.0.set(999),
                }
                // Remote loss is observed through the real Keys check. A
                // running transport never stands in for that fresh authority.
                assert!(
                    keys.as_mut()
                        .unwrap()
                        .browser_tor_initializer(&handle, ctrn::Scope(NAMESPACE))
                        .await
                        .is_err()
                );
            }
        }
        assert_eq!(node.health(), ctrn::State::Stopped);
        assert_eq!(count(&fixture, "stops"), 1);
        assert!(refuses(&fixture, &Uint8Array::from(NAMESPACE.as_slice())));
        assert!(node.start().await.is_err());
        node.stop();
        drop(node);
        assert_eq!(count(&fixture, "stops"), 1);
    }
}

#[wasm_bindgen_test]
async fn closed_unused_initializer_cannot_bind_or_call_the_factory() {
    for drop_keys in [false, true] {
        let (_, _, _, mut keys) = setup(88).await;
        let handle = keys.key(purpose(Scope::Device, "tor.onion")).await.unwrap();
        let verify = verifier(handle.certificate().key);
        let fixture = fixture();
        let initializer = keys
            .browser_tor_initializer(&handle, ctrn::Scope(NAMESPACE))
            .await
            .unwrap();
        if drop_keys {
            drop(keys);
        } else {
            keys.lock();
        }
        assert!(matches!(
            initialize(initializer, &fixture, &verify),
            Err(error) if error.kind() == ctrn::ErrorKind::Closed
        ));
        assert_eq!(count(&fixture, "calls"), 0);
        assert_eq!(count(&fixture, "stops"), 0);
    }
}

#[wasm_bindgen_test]
async fn eight_custodies_are_bounded_and_initializer_or_node_drop_frees_capacity() {
    let (_, _, _, mut keys) = setup(89).await;
    let handle = keys.key(purpose(Scope::Device, "tor.onion")).await.unwrap();
    let mut held = Vec::new();
    for _ in 0..8 {
        held.push(
            keys.browser_tor_initializer(&handle, ctrn::Scope(NAMESPACE))
                .await
                .unwrap(),
        );
    }
    assert!(matches!(
        keys.browser_tor_initializer(&handle, ctrn::Scope(NAMESPACE))
            .await,
        Err(Error::Limit)
    ));
    drop(held.pop().unwrap());
    held.push(
        keys.browser_tor_initializer(&handle, ctrn::Scope(NAMESPACE))
            .await
            .unwrap(),
    );
    let verify = verifier(handle.certificate().key);
    let fixture = fixture();
    let node = initialize(held.pop().unwrap(), &fixture, &verify).unwrap();
    node.start().await.unwrap();
    assert!(matches!(
        keys.browser_tor_initializer(&handle, ctrn::Scope(NAMESPACE))
            .await,
        Err(Error::Limit)
    ));
    drop(node);
    assert_eq!(count(&fixture, "stops"), 1);
    assert!(refuses(&fixture, &Uint8Array::from(NAMESPACE.as_slice())));
    held.push(
        keys.browser_tor_initializer(&handle, ctrn::Scope(NAMESPACE))
            .await
            .unwrap(),
    );
    assert_eq!(held.len(), 8);
}

#[wasm_bindgen_test]
async fn lock_during_start_refuses_retained_identity_and_disposes_late_backend_once() {
    let (_, _, _, mut keys) = setup(90).await;
    let handle = keys.key(purpose(Scope::Device, "tor.onion")).await.unwrap();
    let verify = verifier(handle.certificate().key);
    let fixture = fixture();
    hold(&fixture);
    let initializer = keys
        .browser_tor_initializer(&handle, ctrn::Scope(NAMESPACE))
        .await
        .unwrap();
    let node = initialize(initializer, &fixture, &verify).unwrap();
    let mut pending = Box::pin(node.start());
    assert!(futures::poll!(&mut pending).is_pending());
    settle().await;
    assert_eq!(count(&fixture, "calls"), 1);
    assert!(flag(&fixture, "matched"));
    assert!(flag(&fixture, "wiped"));
    assert!(!aborted(&fixture));
    keys.lock();
    assert!(aborted(&fixture));
    assert_eq!(count(&fixture, "aborts"), 1);
    assert_eq!(node.health(), ctrn::State::Stopped);
    assert!(refuses(&fixture, &Uint8Array::from(NAMESPACE.as_slice())));
    drop(pending);
    release(&fixture);
    settle().await;
    assert_eq!(count(&fixture, "stops"), 1);
    node.stop();
    drop(node);
    assert_eq!(count(&fixture, "stops"), 1);
}

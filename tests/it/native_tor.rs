//! Original Keys and actual stopped Arti construction. The signed fixture
//! Authority below is test-only; this does not claim server G3 or live Tor.
#![cfg(all(feature = "native-tor", not(target_arch = "wasm32")))]
use crate::support::*;
use ckmg::*;
use std::{cell::Cell, path::Path, rc::Rc, sync::Arc};

fn initialize(
    initializer: NativeTorInitializer,
    directory: &Path,
) -> Result<Arc<ctrn::Node>, ctrn::Error> {
    initializer.initialize(
        tor_rtcompat::tokio::TokioRustlsRuntime::current().unwrap(),
        Default::default(),
        ctrn::arti::Directories {
            state: directory.join("state"),
            cache: directory.join("cache"),
        },
        Arc::new(ctrn::arti::TokioClock::default()),
        ctrn::Limits {
            streams: 8,
            bootstrap_ms: 1000,
            operation_ms: 1000,
        },
    )
}

#[tokio::test]
async fn only_the_fresh_device_onion_purpose_can_construct_the_actual_engine() {
    let store = Memory::default();
    let time = Time::default();
    let guard = Guard::default();
    let mut keys = machine(&store, &time, &guard, 73);
    create(&mut keys, &guard, &prf(1), &binding("garden")).await;
    // A member `tor.onion` lies in the reserved `tor.` namespace (ckmg S1): no handle exists for it.
    assert!(matches!(
        keys.key(wire_purpose(Scope::Member, "tor.onion")).await,
        Err(Error::InvalidPurpose)
    ));
    // An ordinary device purpose gets a handle, but never the engine.
    let handle = keys.key(purpose(Scope::Device, "profile")).await.unwrap();
    assert!(matches!(
        keys.native_tor_initializer(&handle, ctrn::Scope([4; 32]))
            .await,
        Err(Error::InvalidPurpose)
    ));
    let handle = keys
        .key(wire_purpose(Scope::Device, "tor.onion"))
        .await
        .unwrap();
    let initializer = keys
        .native_tor_initializer(&handle, ctrn::Scope([4; 32]))
        .await
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    assert_eq!(initializer.community(), "garden");
    let node = initialize(initializer, directory.path()).unwrap();
    assert_eq!(node.health(), ctrn::State::Stopped);
    // Construction does not bootstrap or publish; release remains explicit.
    node.stop();
    drop(node);
    keys.lock();
    assert!(
        keys.native_tor_initializer(&handle, ctrn::Scope([4; 32]))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn locked_or_dropped_keys_invalidate_an_initializer_already_transferred() {
    for drop_keys in [false, true] {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut keys = machine(&store, &time, &guard, 74);
        create(&mut keys, &guard, &prf(1), &binding("garden")).await;
        let handle = keys
            .key(wire_purpose(Scope::Device, "tor.onion"))
            .await
            .unwrap();
        let initializer = keys
            .native_tor_initializer(&handle, ctrn::Scope([4; 32]))
            .await
            .unwrap();
        if drop_keys {
            drop(keys);
        } else {
            keys.lock();
        }
        let directory = tempfile::tempdir().unwrap();
        assert!(matches!(
            initialize(initializer, directory.path()),
            Err(error) if error.kind() == ctrn::ErrorKind::Closed
        ));
    }
}

#[tokio::test]
async fn replaced_checkpoint_revoked_device_and_regressed_clock_refuse_custody() {
    for case in 0..3 {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut keys = machine(&store, &time, &guard, 75);
        create(&mut keys, &guard, &prf(1), &binding("garden")).await;
        let handle = keys
            .key(wire_purpose(Scope::Device, "tor.onion"))
            .await
            .unwrap();
        match case {
            0 => store.0.borrow_mut().records.clear(),
            1 => guard
                .0
                .borrow_mut()
                .get_mut("garden")
                .unwrap()
                .devices
                .clear(),
            _ => time.0.set(999),
        }
        assert!(
            keys.native_tor_initializer(&handle, ctrn::Scope([4; 32]))
                .await
                .is_err()
        );
    }
}

struct AfterCheck {
    guard: Guard,
    store: Memory,
    time: Time,
    effect: Rc<Cell<u8>>,
}
impl Authority for AfterCheck {
    async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        self.guard.check(request).await?;
        match self.effect.get() {
            1 => self.store.0.borrow_mut().records.clear(),
            2 => self.time.0.set(999),
            3 => self.store.0.borrow_mut().read_failure = true,
            _ => {}
        }
        Ok(())
    }
}

#[tokio::test]
async fn the_original_checkpoint_and_clock_are_rechecked_after_authority_returns() {
    for case in 1..=3 {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut initial = machine(&store, &time, &guard, 76);
        create(&mut initial, &guard, &prf(1), &binding("garden")).await;
        drop(initial);
        let effect = Rc::new(Cell::new(0));
        let mut keys = Keys::new(
            store.clone(),
            time.clone(),
            Random::new(77),
            AfterCheck {
                guard,
                store,
                time,
                effect: effect.clone(),
            },
        );
        keys.unlock(&prf(1), "garden").await.unwrap();
        let handle = keys
            .key(wire_purpose(Scope::Device, "tor.onion"))
            .await
            .unwrap();
        let pending = keys
            .native_tor_initializer(&handle, ctrn::Scope([4; 32]))
            .await
            .unwrap();
        effect.set(case);
        assert!(
            keys.native_tor_initializer(&handle, ctrn::Scope([4; 32]))
                .await
                .is_err()
        );
        // The failure also invalidates already-transferred, unused custody.
        let directory = tempfile::tempdir().unwrap();
        assert!(initialize(pending, directory.path()).is_err());
    }
}

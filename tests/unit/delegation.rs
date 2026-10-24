//! Device delegation with real Keys, real crypto and synthetic test authority.
//! The authority below is a test adapter only; it is not production membership.
use super::*;
use futures::executor::block_on;
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    rc::Rc,
};

const COMMUNITY: &str = "delegation";
const CEREMONY: &[u8] = b"test ceremony";

#[derive(Clone, Default)]
struct Memory(Rc<RefCell<HashMap<Locator, Vec<u8>>>>);
impl SecureStore for Memory {
    async fn load(&mut self, location: &Locator) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.0.borrow().get(location).cloned())
    }
    async fn compare_exchange(
        &mut self,
        location: &Locator,
        expected: Option<[u8; 32]>,
        next: &[u8],
    ) -> Result<Commit, Error> {
        let mut data = self.0.borrow_mut();
        if data
            .get(location)
            .map(|value| *blake3::hash(value).as_bytes())
            != expected
        {
            return Ok(Commit::Conflict);
        }
        data.insert(*location, next.to_vec());
        Ok(Commit::Committed)
    }
}

#[derive(Clone)]
struct Time(Rc<Cell<u64>>);
impl Clock for Time {
    fn now(&mut self) -> Result<u64, Error> {
        Ok(self.0.get())
    }
}

/// Published current lineage, as the server would hold it.
#[derive(Clone, Default)]
struct Current(Rc<RefCell<Option<Lineage>>>);
impl Current {
    fn publish(&self, receipt: &Receipt) {
        let lineage = match &receipt.change {
            Change::Created(lineage) | Change::DeviceDelegated(lineage) => lineage.clone(),
            Change::Rotated(rotation) => rotation.lineage.clone(),
            _ => return,
        };
        lineage.verify().unwrap();
        *self.0.borrow_mut() = Some(lineage);
    }
}

/// Current-lineage authority: the device must be listed in the current epoch;
/// lineage-changing actions also need the ceremony evidence.
struct Allow(Current);
impl Authority for Allow {
    async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        let current = self.0.0.borrow();
        let Some(lineage) = current.as_ref() else {
            return if request.action == Action::Create {
                Ok(())
            } else {
                Err(Error::Unauthorized)
            };
        };
        if request.binding != &lineage.binding
            || request.root != Some(lineage.root)
            || request.epoch != lineage.epoch
        {
            return Err(Error::Unauthorized);
        }
        if request.action == Action::RequestPairing {
            return Ok(());
        }
        // A delegate is current for Use only; every lineage action needs a device.
        let delegate = request.action == Action::Use && lineage.delegates.contains(&request.device);
        if !lineage.devices.contains(&request.device) && !delegate {
            return Err(Error::Revoked);
        }
        match request.action {
            Action::DelegateDevice => {
                if request.evidence != CEREMONY
                    || request.target.is_none()
                    || request.statement.is_none()
                {
                    return Err(Error::Unauthorized);
                }
            }
            Action::Rotate | Action::Pair if request.evidence != CEREMONY => {
                return Err(Error::Unauthorized);
            }
            _ => {}
        }
        Ok(())
    }
}

type Machine = Keys<Memory, Time, crate::SystemEntropy, Allow>;

struct Fixture {
    keys: Machine,
    store: Memory,
    time: Time,
    current: Current,
    prf: PrfOutput,
}

impl Fixture {
    async fn new() -> Self {
        let prf = PrfOutput::from_bytes(&[41; 32]).unwrap();
        let store = Memory::default();
        let time = Time(Rc::new(Cell::new(1000)));
        let current = Current::default();
        let mut keys = Keys::new(
            store.clone(),
            time.clone(),
            crate::SystemEntropy,
            Allow(current.clone()),
        );
        let receipt = keys
            .create_scope(
                &prf,
                Binding::new(COMMUNITY, "member").unwrap(),
                DeviceInfo::new("fixture", b"credential").unwrap(),
                b"registration",
            )
            .await
            .unwrap();
        current.publish(&receipt);
        keys.acknowledge(receipt.operation).await.unwrap();
        Self {
            keys,
            store,
            time,
            current,
            prf,
        }
    }

    fn machine(&self) -> Machine {
        Keys::new(
            self.store.clone(),
            self.time.clone(),
            crate::SystemEntropy,
            Allow(self.current.clone()),
        )
    }

    async fn delegate(&mut self, purposes: &[Purpose]) -> (Receipt, DeviceDelegation) {
        let (receipt, delegation) = self.keys.delegate_device(purposes, CEREMONY).await.unwrap();
        self.current.publish(&receipt);
        self.keys.acknowledge(receipt.operation).await.unwrap();
        (receipt, delegation)
    }

    async fn rotate_out(&mut self, revoked: PublicKey) {
        self.keys.prepare_rotation(revoked, CEREMONY).await.unwrap();
        let receipt = self.keys.commit().await.unwrap().unwrap();
        self.current.publish(&receipt);
        self.keys.acknowledge(receipt.operation).await.unwrap();
    }

    async fn delegated(&self, delegation: &DeviceDelegation) -> Machine {
        let mut keys = self.machine();
        keys.unlock_delegated(delegation).unwrap();
        assert_eq!(keys.state(), State::Delegated);
        keys
    }
}

fn member(label: &str) -> Purpose {
    Purpose::new(Scope::Member, label, 1).unwrap()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

macro_rules! shared {
    ($name:ident, $body:block) => {
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
        #[cfg_attr(not(target_arch = "wasm32"), test)]
        fn $name() {
            block_on(async $body);
        }
    };
}

shared!(
    delegation_bytes_hold_no_root_identity_history_ring_or_prf_material,
    {
        let mut f = Fixture::new().await;
        let (_, first) = f.delegate(&[member("board"), member("chat")]).await;
        f.rotate_out(first.device_public_key()).await;
        let (_, second) = f.delegate(&[member("board"), member("chat")]).await;
        let material = f.keys.open.as_ref().unwrap().material.clone();
        let mut forbidden: Vec<(&str, Vec<u8>)> = vec![
            ("prf", [41u8; 32].to_vec()),
            (
                "ring key",
                passkey::ring_key(&f.prf, COMMUNITY).unwrap().to_vec(),
            ),
            (
                "vault location",
                passkey::vault_location(&f.prf, COMMUNITY)
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            ),
            (
                "prf device seed",
                passkey::device_seed(&f.prf, COMMUNITY).unwrap().to_vec(),
            ),
            (
                "prf store cipher",
                passkey::store_cipher(&f.prf, COMMUNITY)
                    .unwrap()
                    .secret()
                    .to_vec(),
            ),
            ("root", material.root.as_ref().unwrap().to_vec()),
            ("identity", material.identity.as_ref().unwrap().to_vec()),
            ("device", material.device.to_vec()),
        ];
        let (record_owner, record_read) = passkey::record_material(&f.prf, COMMUNITY).unwrap();
        forbidden.push(("record owner", record_owner.to_vec()));
        forbidden.push(("record read", record_read.to_vec()));
        assert!(!material.history.is_empty());
        for (epoch, root) in &material.history {
            forbidden.push(("history root", root.to_vec()));
            assert_eq!(*epoch, 1);
        }
        #[cfg(feature = "profile-envelope")]
        forbidden.push((
            "profile storage",
            passkey::profile_storage_key(material.identity.as_ref().unwrap(), COMMUNITY)
                .unwrap()
                .to_vec(),
        ));
        for delegation in [&first, &second] {
            let bytes = delegation.to_sealed_bytes().unwrap();
            for (name, value) in &forbidden {
                assert_eq!(value.len(), 32, "{name}");
                assert!(
                    !contains(&bytes, value),
                    "{name} leaked into the delegation"
                );
            }
            // Positive control: the delegation key itself is in the bytes.
            assert!(contains(&bytes, delegation.device.as_slice()));
        }
    }
);

shared!(
    delegation_key_is_fresh_and_enrolled_by_a_root_signed_revision,
    {
        let mut f = Fixture::new().await;
        let before = f.keys.lineage().await.unwrap();
        let (receipt, first) = f.delegate(&[member("board")]).await;
        let (_, second) = f.delegate(&[member("board")]).await;
        let prf_device = passkey::device_public_key(&f.prf, COMMUNITY).unwrap();
        assert_ne!(first.device_public_key(), second.device_public_key());
        assert_ne!(first.device_public_key(), prf_device);
        assert_ne!(second.device_public_key(), prf_device);
        let lineage = first.lineage();
        lineage.verify().unwrap();
        assert_eq!(lineage.revision, before.revision + 1);
        assert_eq!(lineage.root, before.root);
        assert_eq!(lineage.epoch, before.epoch);
        assert!(lineage.delegates == vec![first.device_public_key()]);
        assert!(lineage.devices == before.devices);
        assert!(lineage.devices.contains(&prf_device));
        assert_eq!(receipt.change, Change::DeviceDelegated(lineage.clone()));
        let (attested, author) = receipt.attested_lineage().unwrap();
        assert!(attested == lineage && author == prf_device);
        let now = f.keys.lineage().await.unwrap();
        assert!(now.delegates.contains(&first.device_public_key()));
        assert!(now.delegates.contains(&second.device_public_key()));
        assert!(now.devices == before.devices);
        assert_eq!(now.revision, before.revision + 2);
        // Session signatures by the delegation key use the existing DeviceSession tag.
        let signature = first.sign_device_session(b"session").unwrap();
        let mut message = DevicePurpose::DeviceSession.tag().to_vec();
        message.extend_from_slice(b"session");
        vld0::verify_ed25519(first.device_public_key().value(), &message, &signature).unwrap();
    }
);

shared!(
    delegate_device_refuses_a_bad_purpose_list_without_changing_lineage,
    {
        let mut f = Fixture::new().await;
        let before = f.keys.lineage().await.unwrap();
        let device = Purpose::new(Scope::Device, "board", 1).unwrap();
        let too_many: Vec<Purpose> = (0..=MAX_DELEGATED_PURPOSES)
            .map(|n| member(&format!("p{n}")))
            .collect();
        for (purposes, error) in [
            (vec![device], Error::InvalidPurpose),
            (
                vec![Purpose::new(Scope::Member, "vault.checkpoint", 0).unwrap()],
                Error::InvalidPurpose,
            ),
            (vec![member("tor.anything")], Error::InvalidPurpose),
            (
                vec![member("board"), member("board")],
                Error::InvalidPurpose,
            ),
            (too_many, Error::Limit),
        ] {
            assert_eq!(
                f.keys.delegate_device(&purposes, CEREMONY).await.err(),
                Some(error)
            );
        }
        assert_eq!(
            f.keys
                .delegate_device(&[member("board")], b"no ceremony")
                .await
                .err(),
            Some(Error::Unauthorized)
        );
        f.keys.unlock(&f.prf, COMMUNITY).await.unwrap();
        assert!(f.keys.lineage().await.unwrap() == before);
        assert!(f.current.0.borrow().as_ref() == Some(&before));
    }
);

shared!(delegated_purposes_match_authorized_custody, {
    let mut f = Fixture::new().await;
    let board = member("board");
    let (_, delegation) = f.delegate(std::slice::from_ref(&board)).await;
    let mut delegated = f.delegated(&delegation).await;
    let full = f.keys.key(board.clone()).await.unwrap();
    let handle = delegated.key(board.clone()).await.unwrap();
    assert_eq!(handle.certificate().key, full.certificate().key);
    assert_eq!(handle.certificate().device, delegation.device_public_key());
    let sealed = f
        .keys
        .seal(&full, b"ctx", b"from the passkey")
        .await
        .unwrap();
    assert_eq!(
        &*delegated.open(&handle, b"ctx", &sealed).await.unwrap(),
        b"from the passkey"
    );
    let sealed = delegated
        .seal(&handle, b"ctx", b"from the delegation")
        .await
        .unwrap();
    assert_eq!(
        &*f.keys.open(&full, b"ctx", &sealed).await.unwrap(),
        b"from the delegation"
    );
    let signature = delegated.sign(&handle, b"owner bytes").await.unwrap();
    vld0::verify(&handle.certificate().key, b"owner bytes", &signature).unwrap();
    // Device purposes derive from the delegation key, never the passkey device.
    let local = Purpose::new(Scope::Device, "drafts", 1).unwrap();
    let mine = delegated.key(local.clone()).await.unwrap();
    assert_ne!(
        mine.certificate().key,
        f.keys.key(local).await.unwrap().certificate().key
    );
    // Raw purpose signers never sign with the delegation key itself (H2): its only
    // plain-Ed25519 use is the typed DeviceSession signature.
    assert_ne!(mine.certificate().key, delegation.device_public_key());
    assert_ne!(handle.certificate().key, delegation.device_public_key());
    assert_eq!(delegated.lineage().await.unwrap(), *delegation.lineage());
    assert_eq!(
        delegated.device_public_key().await.unwrap(),
        delegation.device_public_key()
    );
    // Peers' certificate check accepts lineage devices only, never a delegate.
    assert_eq!(
        handle
            .certificate()
            .verify(delegation.lineage(), &board)
            .err(),
        Some(Error::Unauthorized)
    );
    // A handle from the full custody is not accepted by the delegated one.
    assert_eq!(
        delegated.sign(&full, b"owner bytes").await.err(),
        Some(Error::Unauthorized)
    );
});

shared!(delegated_custody_refuses_every_root_operation, {
    let mut f = Fixture::new().await;
    let board = member("board");
    let (receipt, delegation) = f.delegate(std::slice::from_ref(&board)).await;
    let lineage = delegation.lineage().clone();
    let full = f.keys.key(board.clone()).await.unwrap();
    let sealed = f.keys.seal(&full, b"ctx", b"x").await.unwrap();
    let mut guest = f.machine();
    let request = match guest
        .request_pairing(
            &PrfOutput::from_bytes(&[42; 32]).unwrap(),
            &lineage,
            DeviceInfo::new("guest", b"other").unwrap(),
            CEREMONY,
        )
        .await
        .unwrap()
        .change
    {
        Change::PairingRequested(request) => *request,
        _ => panic!(),
    };
    let snapshot = f.store.0.borrow().clone();
    let mut keys = f.delegated(&delegation).await;
    let handle = keys.key(board.clone()).await.unwrap();
    let no_root = Some(Error::NoRoot);
    // Purposes outside the delegation and transport purposes.
    assert_eq!(keys.key(member("wallet")).await.err(), no_root);
    for reserved in [
        Purpose::new(Scope::Device, "tor.node", 1).unwrap(),
        Purpose::new(Scope::Device, "tor.onion", 1).unwrap(),
        Purpose::new(Scope::Member, "vault.checkpoint", 0).unwrap(),
        Purpose::new(Scope::Device, "vault.local", 1).unwrap(),
    ] {
        assert_eq!(keys.key(reserved).await.err(), Some(Error::Unauthorized));
    }
    // Lineage changes, rotation and pairing.
    assert_eq!(
        keys.delegate_device(std::slice::from_ref(&board), CEREMONY)
            .await
            .err(),
        no_root
    );
    assert_eq!(
        keys.prepare_rotation(delegation.device_public_key(), CEREMONY)
            .await
            .err(),
        no_root
    );
    assert_eq!(
        keys.authorize_device(&request, CEREMONY).await.err(),
        no_root
    );
    assert_eq!(keys.adopt_lineage(&lineage, CEREMONY).await.err(), no_root);
    assert_eq!(keys.rename_device("x").await.err(), no_root);
    assert_eq!(keys.migrate_compound_wrapping().await.err(), no_root);
    assert_eq!(keys.acknowledge(receipt.operation).await.err(), no_root);
    assert_eq!(keys.pending_output().await.err(), no_root);
    // Identity proofs and device-key lending.
    assert_eq!(keys.with_identity(|_| ()).await.err(), no_root);
    assert_eq!(keys.with_device_ed25519_signer(|_| ()).await.err(), no_root);
    assert_eq!(keys.sign_device_ed25519(b"x", 2000).await.err(), no_root);
    #[cfg(feature = "profile-envelope")]
    assert_eq!(keys.with_profile_custody(|_, _| ()).await.err(), no_root);
    #[cfg(feature = "wallet-engine")]
    {
        assert_eq!(keys.with_record_recipient(|_| ()).await.err(), no_root);
        assert!(matches!(keys.wallet_engine().await, Err(Error::NoRoot)));
    }
    #[cfg(feature = "passport")]
    assert_eq!(keys.with_holder_seed(|_| ()).await.err(), no_root);
    // Record reads and writes, retained custody and history.
    assert_eq!(keys.retained_checkpoint().await.err(), no_root);
    assert!(matches!(
        keys.export_lineage_read_capability().await,
        Err(Error::NoRoot)
    ));
    assert!(matches!(
        keys.prepare_lineage_revision_record(&receipt, &lineage, b"evidence", CEREMONY)
            .await,
        Err(Error::NoRoot)
    ));
    assert_eq!(
        keys.open_historical(&handle, 1, b"ctx", &sealed)
            .await
            .err(),
        no_root
    );
    assert!(matches!(
        keys.with_historical_vld0_reader(&handle, 1, |_| ()).await,
        Err(Error::NoRoot)
    ));
    // Creating or restoring needs the passkey, after an explicit lock.
    let prf = PrfOutput::from_bytes(&[41; 32]).unwrap();
    assert_eq!(
        keys.create_scope(
            &prf,
            Binding::new("other", "member").unwrap(),
            DeviceInfo::new("x", b"y").unwrap(),
            CEREMONY,
        )
        .await
        .err(),
        Some(Error::Unauthorized)
    );
    assert_eq!(
        keys.request_pairing(
            &prf,
            &lineage,
            DeviceInfo::new("x", b"y").unwrap(),
            CEREMONY
        )
        .await
        .err(),
        Some(Error::Unauthorized)
    );
    // Still delegated, still usable, and nothing was written.
    assert_eq!(keys.state(), State::Delegated);
    assert_eq!(&*keys.open(&handle, b"ctx", &sealed).await.unwrap(), b"x");
    assert!(*f.store.0.borrow() == snapshot);
});

shared!(rotation_shuts_out_an_old_delegation, {
    let mut f = Fixture::new().await;
    let board = member("board");
    let (_, old) = f.delegate(std::slice::from_ref(&board)).await;
    f.rotate_out(old.device_public_key()).await;
    let (_, new) = f.delegate(std::slice::from_ref(&board)).await;
    assert_eq!(old.lineage().epoch, 1);
    assert_eq!(new.lineage().epoch, 2);
    assert!(!new.lineage().devices.contains(&old.device_public_key()));
    // Only new-epoch secrets: every secret differs and the Store cipher rotated.
    assert!(old.store.secret() != new.store.secret());
    assert!(old.purposes[0].signing != new.purposes[0].signing);
    assert!(old.purposes[0].encryption != new.purposes[0].encryption);
    let full = f.keys.key(board.clone()).await.unwrap();
    let mut current = f.delegated(&new).await;
    assert_eq!(
        current.key(board.clone()).await.unwrap().certificate().key,
        full.certificate().key
    );
    // The old delegation is refused by current authority and wiped.
    let mut stale = f.delegated(&old).await;
    assert_eq!(
        stale.key(board.clone()).await.err(),
        Some(Error::Unauthorized)
    );
    assert_eq!(stale.state(), State::Locked);
    assert!(stale.delegated.is_none());
    // Its retained epoch-1 key opens nothing sealed in epoch 2.
    let sealed = f.keys.seal(&full, b"ctx", b"epoch two").await.unwrap();
    let aad = purpose_aad(f.keys.loaded().unwrap(), &board, b"ctx").unwrap();
    let body = sealed.strip_prefix(PURPOSE_HEADER).unwrap();
    assert!(keyring::open(&old.purposes[0].encryption, &aad, body).is_err());
    assert!(keyring::open(&new.purposes[0].encryption, &aad, body).is_ok());
});

shared!(sealed_bytes_round_trip_and_refuse_tampering, {
    let mut f = Fixture::new().await;
    let (_, delegation) = f.delegate(&[member("board"), member("chat")]).await;
    let bytes = delegation.to_sealed_bytes().unwrap();
    let back = DeviceDelegation::from_sealed_bytes(&bytes).unwrap();
    assert_eq!(back.device_public_key(), delegation.device_public_key());
    assert_eq!(back.lineage(), delegation.lineage());
    assert_eq!(*back.to_sealed_bytes().unwrap(), *bytes);
    let mut keys = f.delegated(&back).await;
    keys.key(member("chat")).await.unwrap();
    for length in 0..bytes.len() {
        assert!(DeviceDelegation::from_sealed_bytes(&bytes[..length]).is_err());
    }
    let mut longer = bytes.to_vec();
    longer.push(0);
    assert!(DeviceDelegation::from_sealed_bytes(&longer).is_err());
    let header = DELEGATION_HEADER.len();
    for index in [0, header, header + 31] {
        let mut changed = bytes.to_vec();
        changed[index] ^= 1;
        assert!(
            DeviceDelegation::from_sealed_bytes(&changed).is_err(),
            "{index}"
        );
    }
});

shared!(rotation_seals_nothing_to_a_delegate, {
    let mut f = Fixture::new().await;
    let board = member("board");
    let (_, kept) = f.delegate(std::slice::from_ref(&board)).await;
    let (_, removed) = f.delegate(std::slice::from_ref(&board)).await;
    f.keys
        .prepare_rotation(removed.device_public_key(), CEREMONY)
        .await
        .unwrap();
    let receipt = f.keys.commit().await.unwrap().unwrap();
    let Change::Rotated(rotation) = &receipt.change else {
        panic!()
    };
    // The kept delegate stays listed; neither delegate gets an envelope.
    assert!(rotation.lineage.delegates == vec![kept.device_public_key()]);
    assert!(rotation.lineage.devices == kept.lineage().devices);
    for delegation in [&kept, &removed] {
        let key = delegation.device_public_key();
        assert!(rotation.envelopes.iter().all(|e| e.device != key));
        for envelope in &rotation.envelopes {
            assert!(
                vld0::open(
                    &delegation.device,
                    &rotation.aad(envelope.device).unwrap(),
                    &envelope.sealed_root
                )
                .is_err()
            );
        }
    }
    f.current.publish(&receipt);
    f.keys.acknowledge(receipt.operation).await.unwrap();
    // Neither delegate obtains a new-epoch secret: both hold epoch 1 only, and the
    // current authority refuses their stale epoch.
    let full = f.keys.key(board.clone()).await.unwrap();
    for delegation in [&kept, &removed] {
        assert_eq!(delegation.lineage().epoch, 1);
        let mut keys = f.delegated(delegation).await;
        assert_eq!(
            keys.key(board.clone()).await.err(),
            Some(Error::Unauthorized)
        );
        assert!(delegation.purposes[0].signing != delegated_secret_for(&f, &board));
    }
    assert_eq!(f.keys.lineage().await.unwrap().epoch, 2);
    let _ = full;
    // Removing the last delegate is the same ordinary rotation.
    f.rotate_out(kept.device_public_key()).await;
    assert!(f.keys.lineage().await.unwrap().delegates.is_empty());
});

fn delegated_secret_for(f: &Fixture, purpose: &Purpose) -> Secret {
    purpose_secret(f.keys.loaded().unwrap(), purpose, false).unwrap()
}

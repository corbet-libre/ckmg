//! Shared in-crate fixtures: a permissive test authority, enrolment helpers and forging
//! helpers that re-sign lineages with the deterministic test secrets.
#![allow(dead_code)]

#[path = "../../tests/support/mod.rs"]
pub(crate) mod support;

use crate::{
    Authority, Authorization, Change, Error, Keys, Lineage, PairingGrant, PairingRequest,
    PublicKey, Rotation, passkey, vld0,
};
use support::{Memory, Random, Time, binding, info, prf};

/// Test-only authority that approves every request. It lets scenarios reach the checks
/// that run after authorization; it is never part of the shipped library.
#[derive(Clone, Copy, Default)]
pub(crate) struct Allow;

impl Authority for Allow {
    async fn check(&mut self, _request: Authorization<'_>) -> Result<(), Error> {
        Ok(())
    }
}

pub(crate) type Gated = Keys<Memory, Time, Random, Allow>;

pub(crate) fn gated(store: &Memory, time: &Time, seed: u8) -> Gated {
    Keys::new(store.clone(), time.clone(), Random::new(seed), Allow)
}

/// Root secret of passkey `n` in `community` at `epoch`.
pub(crate) fn root_secret(n: u8, community: &str, epoch: u64) -> crate::Secret {
    passkey::lineage_root(&passkey::lineage_seed(&prf(n), community).unwrap(), epoch).unwrap()
}

/// Public device key of passkey `n` in `community`.
pub(crate) fn device_key(n: u8, community: &str) -> PublicKey {
    vld0::public_key(&passkey::device_seed(&prf(n), community).unwrap())
}

/// Replace the signature of a modified lineage with one by `secret`.
pub(crate) fn resigned(mut lineage: Lineage, secret: &crate::Secret) -> Lineage {
    lineage.signature = vld0::sign(secret, &lineage.signed_bytes().unwrap()).unwrap();
    lineage
}

/// Replace the device set (kept sorted and unique), then re-sign.
pub(crate) fn with_devices(
    mut lineage: Lineage,
    devices: &[PublicKey],
    secret: &crate::Secret,
) -> Lineage {
    lineage.devices = devices.to_vec();
    lineage.devices.sort();
    lineage.devices.dedup();
    resigned(lineage, secret)
}

/// A different, valid pseudonym in the same community.
pub(crate) fn other_member() -> crate::Binding {
    crate::Binding::new("a", "other-pseudonym").unwrap()
}

/// Create community `a` for passkey 1 and clear the output.
pub(crate) async fn founder(machine: &mut Gated) -> Lineage {
    let receipt = machine
        .create_scope(&prf(1), binding("a"), info(), &[])
        .await
        .unwrap();
    machine.acknowledge(receipt.operation).await.unwrap();
    machine.lineage().await.unwrap()
}

/// The new device persists a pending request and clears the output.
pub(crate) async fn ask(new: &mut Gated, n: u8, anchor: &Lineage) -> PairingRequest {
    let receipt = new
        .request_pairing(&prf(n), anchor, info(), &[])
        .await
        .unwrap();
    new.acknowledge(receipt.operation).await.unwrap();
    match receipt.change {
        Change::PairingRequested(request) => *request,
        _ => panic!("expected a pairing request"),
    }
}

/// The live device authorizes `request` and clears the output.
pub(crate) async fn approve(live: &mut Gated, request: &PairingRequest) -> PairingGrant {
    let receipt = live.authorize_device(request, &[]).await.unwrap();
    live.acknowledge(receipt.operation).await.unwrap();
    match receipt.change {
        Change::DeviceAuthorized(grant) => *grant,
        _ => panic!("expected a pairing grant"),
    }
}

/// The new device accepts `grant` and clears the output.
pub(crate) async fn take(new: &mut Gated, grant: &PairingGrant) {
    let receipt = new.accept_pairing(grant, &[]).await.unwrap();
    new.acknowledge(receipt.operation).await.unwrap();
}

/// Full enrolment of passkey `n` as a new device of `live`.
pub(crate) async fn enroll(live: &mut Gated, new: &mut Gated, n: u8) -> PairingGrant {
    let anchor = live.lineage().await.unwrap();
    let request = ask(new, n, &anchor).await;
    let grant = approve(live, &request).await;
    take(new, &grant).await;
    grant
}

/// Three enrolled devices, then the first removes the third by rotating the root.
pub(crate) struct Scene {
    pub store: Memory,
    pub time: Time,
    pub a: Gated,
    pub b: Gated,
    /// Lineage with all three devices, before the rotation.
    pub previous: Lineage,
    pub rotation: Rotation,
    /// Public key of the removed device.
    pub removed: PublicKey,
}

pub(crate) async fn scene() -> Scene {
    let store = Memory::default();
    let time = Time::default();
    let mut a = gated(&store, &time, 1);
    let mut b = gated(&store, &time, 2);
    let mut c = gated(&store, &time, 3);
    founder(&mut a).await;
    enroll(&mut a, &mut b, 2).await;
    let third = enroll(&mut a, &mut c, 3).await;
    let previous = a.lineage().await.unwrap();
    let receipt = b.adopt_lineage(&previous, &[]).await.unwrap();
    b.acknowledge(receipt.operation).await.unwrap();
    a.prepare_rotation(third.request.device, &[]).await.unwrap();
    let receipt = a.commit().await.unwrap().unwrap();
    a.acknowledge(receipt.operation).await.unwrap();
    let rotation = match receipt.change {
        Change::Rotated(rotation) => *rotation,
        _ => panic!("expected a rotation"),
    };
    Scene {
        store,
        time,
        a,
        b,
        previous,
        rotation,
        removed: third.request.device,
    }
}

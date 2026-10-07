//! Succession checks that need lineages re-signed with the deterministic test secrets.
use super::fixture::{resigned, root_secret, scene, with_devices};
use crate::{Error, Rotation};
use futures::executor::block_on;

fn pointed_at(mut rotation: Rotation, previous: &crate::Lineage) -> Rotation {
    rotation.predecessor = previous.digest().unwrap();
    rotation.previous_root = previous.root;
    rotation
}

#[test]
fn succession_refuses_each_mismatched_predecessor_field() {
    block_on(async {
        let scene = scene().await;
        let first_root = root_secret(1, "a", 1);
        scene.rotation.verify(&scene.previous).unwrap();

        // A predecessor in another pseudonym of the same community.
        let mut other = scene.previous.clone();
        other.binding = super::fixture::other_member();
        let other = resigned(other, &first_root);
        let rotation = pointed_at(scene.rotation.clone(), &other);
        assert_eq!(rotation.verify(&other), Err(Error::Unauthorized));

        // The replacement lineage cannot be its own predecessor.
        let own = scene.rotation.lineage.clone();
        let rotation = pointed_at(scene.rotation.clone(), &own);
        assert_eq!(rotation.verify(&own), Err(Error::Unauthorized));

        // A predecessor whose epoch is not exactly one behind.
        let mut skipped = scene.previous.clone();
        skipped.epoch = 5;
        let skipped = resigned(skipped, &first_root);
        let rotation = pointed_at(scene.rotation.clone(), &skipped);
        assert_eq!(rotation.verify(&skipped), Err(Error::Unauthorized));

        // A predecessor whose revision is not exactly one behind.
        let mut ahead = scene.previous.clone();
        ahead.revision = 10;
        let ahead = resigned(ahead, &first_root);
        let rotation = pointed_at(scene.rotation.clone(), &ahead);
        assert_eq!(rotation.verify(&ahead), Err(Error::Unauthorized));

        // Counters that cannot be incremented are a bound, not a wrap-around.
        let mut last_epoch = scene.previous.clone();
        last_epoch.epoch = u64::MAX;
        let last_epoch = resigned(last_epoch, &first_root);
        let rotation = pointed_at(scene.rotation.clone(), &last_epoch);
        assert_eq!(rotation.verify(&last_epoch), Err(Error::Limit));
        let mut last_revision = scene.previous.clone();
        last_revision.revision = u64::MAX;
        let last_revision = resigned(last_revision, &first_root);
        let rotation = pointed_at(scene.rotation.clone(), &last_revision);
        assert_eq!(rotation.verify(&last_revision), Err(Error::Limit));

        // Removing a device other than the announced one, and a stranger.
        let mut wrong = scene.rotation.clone();
        wrong.revoked = scene
            .previous
            .devices
            .iter()
            .copied()
            .find(|device| *device != scene.removed)
            .unwrap();
        assert_eq!(wrong.verify(&scene.previous), Err(Error::Unauthorized));
        let smaller = with_devices(
            scene.previous.clone(),
            &scene.previous.devices[1..],
            &first_root,
        );
        assert_eq!(
            scene.rotation.verify(&smaller),
            Err(Error::Unauthorized),
            "a different predecessor digest is never accepted"
        );
    });
}

#[test]
fn canonical_encoding_is_bounded() {
    let big = vec![0u8; 600_000];
    assert_eq!(
        crate::lineage::encode(b"ckmg.test.v1\0", &big),
        Err(Error::Limit)
    );
    assert_eq!(
        crate::lineage::digest(b"ckmg.test.v1\0", &big),
        Err(Error::Limit)
    );
    assert!(crate::lineage::encode(b"ckmg.test.v1\0", &[0u8; 8]).is_ok());
}

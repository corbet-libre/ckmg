//! The device key that appears in MLS leaf credentials is scope-bound: the same
//! passkey in two communities never yields the same public key.
mod support;
use ckmg::*;
use support::*;

#[test]
fn device_public_key_differs_per_community_and_is_stable_within_one() {
    let p = prf(7);
    let a1 = passkey::device_public_key(&p, "community-a").unwrap();
    let a2 = passkey::device_public_key(&p, "community-a").unwrap();
    let b = passkey::device_public_key(&p, "community-b").unwrap();
    assert_eq!(a1, a2);
    assert_ne!(a1, b);
    assert_ne!(
        passkey::device_public_key(&prf(8), "community-a").unwrap(),
        a1
    );
}

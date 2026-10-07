//! Boundary refusals of the private primitives: sealing, key parsing and HPKE opening.
use super::fixture::support::Random;
use crate::keyring::{self, Material};
use crate::{CryptoKind, Error, PublicKey, Signature, VLD0, passkey, vld0};
use zeroize::Zeroizing;

fn weak_key() -> PublicKey {
    let mut bytes = [0u8; 32];
    bytes[0] = 1;
    PublicKey::new(VLD0, bytes)
}

#[test]
fn material_parsing_accepts_only_the_two_exact_layouts() {
    assert_eq!(Material::parse(&[]).err(), Some(Error::Encoding));
    assert_eq!(Material::parse(&[2u8; 33]).err(), Some(Error::Encoding));
    assert_eq!(Material::parse(&[0u8; 32]).err(), Some(Error::Encoding));
    assert_eq!(Material::parse(&[1u8; 33]).err(), Some(Error::Encoding));
    assert_eq!(Material::parse(&[1u8; 66]).err(), Some(Error::Encoding));
    let device_only = Material::parse(&[0u8; 33]).unwrap();
    assert_eq!(device_only.root().err(), Some(Error::NoRoot));
    let with_root = Material::parse(&[1u8; 65]).unwrap();
    assert!(with_root.root().is_ok());
    let mut out = Zeroizing::new(Vec::new());
    with_root.append(&mut out);
    assert_eq!(out.len(), 65);
    assert_eq!(keyring::secret(&[0u8; 31]).err(), Some(Error::Encoding));
    assert_eq!(keyring::secret(&[0u8; 33]).err(), Some(Error::Encoding));
}

#[test]
fn sealed_checkpoints_refuse_short_forged_and_unseedable_input() {
    let key = Zeroizing::new([7u8; 32]);
    let other = Zeroizing::new([8u8; 32]);
    let sealed = keyring::seal(&mut Random::new(1), &key, b"aad", b"plain").unwrap();
    assert_eq!(&*keyring::open(&key, b"aad", &sealed).unwrap(), b"plain");
    assert_eq!(
        keyring::open(&key, b"aad", &sealed[..39]).err(),
        Some(Error::Open)
    );
    assert_eq!(
        keyring::open(&other, b"aad", &sealed).err(),
        Some(Error::Open)
    );
    assert_eq!(
        keyring::open(&key, b"other", &sealed).err(),
        Some(Error::Open)
    );
    let mut failing = Random::new(1);
    failing.fail.set(true);
    assert_eq!(
        keyring::seal(&mut failing, &key, b"aad", b"plain").err(),
        Some(Error::Randomness)
    );
}

#[test]
fn hpke_opening_and_sealing_refuse_malformed_inputs() {
    let secret = Zeroizing::new([9u8; 32]);
    let public = vld0::public_key(&secret);
    assert_eq!(
        vld0::open(&secret, b"aad", &[0u8; 36]).err(),
        Some(Error::Encoding)
    );
    let mut wrong_header = [0u8; 80];
    wrong_header[0] = 2;
    assert_eq!(
        vld0::open(&secret, b"aad", &wrong_header).err(),
        Some(Error::UnsupportedKind)
    );
    let mut garbage = [3u8; 85];
    garbage[..5].copy_from_slice(b"\x01VLD0");
    assert_eq!(
        vld0::open(&secret, b"aad", &garbage).err(),
        Some(Error::Open)
    );
    let mut rng = Random::new(2);
    let sealed = vld0::seal_to(&mut rng, &public, b"aad", b"hello").unwrap();
    assert_eq!(&*vld0::open(&secret, b"aad", &sealed).unwrap(), b"hello");
    assert_eq!(
        vld0::open(&secret, b"other", &sealed).err(),
        Some(Error::Open)
    );
    assert_eq!(
        vld0::seal_to(&mut rng, &weak_key(), b"aad", b"hello").err(),
        Some(Error::InvalidKey)
    );
    let foreign = PublicKey::new(CryptoKind(*b"XXXX"), *public.value());
    assert_eq!(
        vld0::seal_to(&mut rng, &foreign, b"aad", b"hello").err(),
        Some(Error::UnsupportedKind)
    );
    rng.fail.set(true);
    assert_eq!(
        vld0::seal_to(&mut rng, &public, b"aad", b"hello").err(),
        Some(Error::Randomness)
    );
    assert_eq!(vld0::random_secret(&mut rng).err(), Some(Error::Randomness));
}

#[test]
fn signature_checks_refuse_foreign_kinds_and_weak_keys() {
    let secret = Zeroizing::new([5u8; 32]);
    let public = vld0::public_key(&secret);
    let signature = vld0::sign(&secret, b"data").unwrap();
    vld0::verify(&public, b"data", &signature).unwrap();
    let foreign_key = PublicKey::new(CryptoKind(*b"XXXX"), *public.value());
    assert_eq!(
        vld0::verify(&foreign_key, b"data", &signature),
        Err(Error::UnsupportedKind)
    );
    let foreign_signature = Signature::new(CryptoKind(*b"XXXX"), *signature.value());
    assert_eq!(
        vld0::verify(&public, b"data", &foreign_signature),
        Err(Error::UnsupportedKind)
    );
    assert_eq!(
        vld0::verify(&weak_key(), b"data", &signature),
        Err(Error::InvalidKey)
    );
    assert_eq!(
        vld0::verify_ed25519(weak_key().value(), b"data", signature.value()),
        Err(Error::InvalidKey)
    );
    assert_eq!(
        vld0::verify_ed25519(&[0u8; 32], b"data", signature.value()),
        Err(Error::InvalidKey)
    );
    assert_eq!(
        vld0::verify_ed25519(public.value(), b"changed", signature.value()),
        Err(Error::BadSignature)
    );
}

#[test]
fn lineage_roots_need_a_positive_epoch() {
    let seed = Zeroizing::new([3u8; 32]);
    assert_eq!(passkey::lineage_root(&seed, 0).err(), Some(Error::Encoding));
    assert!(passkey::lineage_root(&seed, 1).is_ok());
    assert_ne!(
        *passkey::lineage_root(&seed, 1).unwrap(),
        *passkey::lineage_root(&seed, u64::MAX).unwrap()
    );
}

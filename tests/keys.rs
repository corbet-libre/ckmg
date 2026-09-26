//! Key hierarchy, signing, sealing, delegation, pairing and persistence.

use ckmg::{
    Error, KeyRef, KeyRing, PublicKey, Purpose, Scope, Signature, VLD0, passkey, seal_to, verify,
};
use ed25519_dalek::{Digest, Sha512, Signer, SigningKey};

fn member_ring() -> KeyRing {
    let mut ring = KeyRing::generate().unwrap();
    ring.create_root().unwrap();
    ring
}

fn purpose(scope: Scope, label: &str) -> Purpose {
    Purpose::new(scope, label, 0).unwrap()
}

#[test]
fn typed_keys_use_veilid_text_and_binary_forms() {
    let ring = KeyRing::generate().unwrap();
    let key = ring.device_public();
    let text = key.to_string();
    assert!(text.starts_with("VLD0:"));
    assert_eq!(text.len(), 5 + 43);
    assert_eq!(text.parse::<PublicKey>().unwrap(), key);
    assert_eq!(
        PublicKey::from_typed_bytes(&key.to_typed_bytes()).unwrap(),
        key
    );
    let json = serde_json::to_string(&key).unwrap();
    assert_eq!(json, format!("\"{text}\""));
    assert_eq!(serde_json::from_str::<PublicKey>(&json).unwrap(), key);
    assert_eq!("VLD0".parse::<PublicKey>().unwrap_err(), Error::Encoding);
    assert_eq!(
        "VLD0:AAAA".parse::<PublicKey>().unwrap_err(),
        Error::Encoding
    );
}

#[test]
fn sign_and_verify_with_every_level() {
    let ring = member_ring();
    let mls = purpose(Scope::Device, "mls.signature");
    for key in [KeyRef::Root, KeyRef::Device, KeyRef::Purpose(&mls)] {
        let public = ring.public_key(key).unwrap();
        let signature = ring.sign(key, b"statement").unwrap();
        assert_eq!(signature.kind(), VLD0);
        verify(&public, b"statement", &signature).unwrap();
        assert_eq!(
            verify(&public, b"other statement", &signature).unwrap_err(),
            Error::BadSignature
        );
    }
    let device = ring.device_public();
    let root = ring.root_public().unwrap();
    let root_signature = ring.sign(KeyRef::Root, b"statement").unwrap();
    assert_ne!(device, root);
    assert_eq!(
        verify(&device, b"statement", &root_signature).unwrap_err(),
        Error::BadSignature
    );
}

#[test]
fn signatures_are_veilid_vld0_ed25519ph() {
    let ring = member_ring();
    let delegated = ring
        .delegate(&purpose(Scope::Member, "cdht.writer"))
        .unwrap();
    // Sign independently with the upstream crate exactly as Veilid's VLD0 does.
    let signing = SigningKey::from_bytes(&delegated.secret);
    let mut prehash = Sha512::new();
    prehash.update(b"record bytes");
    let upstream = signing
        .sign_prehashed(prehash, Some(&b"VLD0_SIGN"[..]))
        .unwrap();
    verify(
        &delegated.public_key,
        b"record bytes",
        &Signature::new(VLD0, upstream.to_bytes()),
    )
    .unwrap();
    // A plain (non-prehashed) Ed25519 signature is not a VLD0 signature.
    let plain = signing.sign(b"record bytes");
    assert!(
        verify(
            &delegated.public_key,
            b"record bytes",
            &Signature::new(VLD0, plain.to_bytes())
        )
        .is_err()
    );
    ckmg::verify_ed25519(
        &delegated.public_key.value().clone(),
        b"record bytes",
        &plain.to_bytes(),
    )
    .unwrap();
}

#[test]
fn purpose_keys_are_deterministic_scoped_and_rotatable() {
    let ring = member_ring();
    let a = purpose(Scope::Device, "tor.onion");
    let key = ring.public_key(KeyRef::Purpose(&a)).unwrap();
    assert_eq!(ring.public_key(KeyRef::Purpose(&a)).unwrap(), key);
    assert_eq!(ring.delegate(&a).unwrap().public_key, key);
    let rotated = a.next_version().unwrap();
    assert_eq!(rotated.version(), 1);
    assert_ne!(ring.public_key(KeyRef::Purpose(&rotated)).unwrap(), key);
    let other_label = purpose(Scope::Device, "tor.onion2");
    assert_ne!(ring.public_key(KeyRef::Purpose(&other_label)).unwrap(), key);
    // Delegated keys are never the parents.
    assert_ne!(key, ring.device_public());
    assert_ne!(
        ring.delegate(&purpose(Scope::Member, "x"))
            .unwrap()
            .public_key,
        ring.root_public().unwrap()
    );
    // Symmetric secrets differ from signing seeds for the same purpose.
    assert_ne!(
        *ring.delegate_secret(&a).unwrap().secret,
        *ring.delegate(&a).unwrap().secret
    );
}

#[test]
fn member_scope_needs_the_root() {
    let ring = KeyRing::generate().unwrap();
    assert!(!ring.has_root());
    assert_eq!(
        ring.delegate(&purpose(Scope::Member, "state")).unwrap_err(),
        Error::NoRoot
    );
    assert_eq!(ring.sign(KeyRef::Root, b"x").unwrap_err(), Error::NoRoot);
    ring.delegate(&purpose(Scope::Device, "state")).unwrap();
}

#[test]
fn invalid_purposes() {
    for label in ["", "slash/label", "space here", "ümlaut", &"x".repeat(65)] {
        assert_eq!(
            Purpose::new(Scope::Device, label, 0).unwrap_err(),
            Error::InvalidPurpose
        );
    }
    assert!(Purpose::new(Scope::Device, "cdht.writer:VLD0-abc_1", 7).is_ok());
    assert_eq!(
        Purpose::new(Scope::Device, "x", u32::MAX)
            .unwrap()
            .next_version()
            .unwrap_err(),
        Error::InvalidPurpose
    );
}

#[test]
fn delegation_certificates() {
    let ring = member_ring();
    let p = purpose(Scope::Device, "mls.signature");
    let delegation = ring.certify(&p, 100, 200).unwrap();
    assert_eq!(delegation.parent, ring.device_public());
    assert_eq!(delegation.public_key, ring.delegate(&p).unwrap().public_key);
    delegation.verify(150).unwrap();
    assert_eq!(delegation.verify(99).unwrap_err(), Error::Expired);
    assert_eq!(delegation.verify(200).unwrap_err(), Error::Expired);
    let mut tampered = delegation.clone();
    tampered.expires_at = 300;
    assert_eq!(tampered.verify(150).unwrap_err(), Error::BadSignature);

    let member = ring
        .certify(&purpose(Scope::Member, "profile"), 1, 2)
        .unwrap();
    assert_eq!(member.parent, ring.root_public().unwrap());
    let json = serde_json::to_string(&member).unwrap();
    assert_eq!(
        serde_json::from_str::<ckmg::Delegation>(&json).unwrap(),
        member
    );
}

#[test]
fn seal_to_device_and_open() {
    let alice = member_ring();
    let bob = KeyRing::generate().unwrap();
    let sealed = seal_to(&bob.device_public(), b"context", b"secret message").unwrap();
    assert_eq!(&sealed[..4], b"VLD0");
    assert_eq!(
        bob.open(KeyRef::Device, b"context", &sealed)
            .unwrap()
            .as_slice(),
        b"secret message"
    );
    assert_eq!(
        bob.open(KeyRef::Device, b"other context", &sealed)
            .unwrap_err(),
        Error::Open
    );
    assert_eq!(
        alice.open(KeyRef::Device, b"context", &sealed).unwrap_err(),
        Error::Open
    );
}

#[test]
fn pairing_hands_the_root_to_one_device_only() {
    let live = member_ring();
    let mut new_device = KeyRing::generate().unwrap();
    let mut stranger = KeyRing::generate().unwrap();
    let root = live.root_public().unwrap();
    let context = b"pairing session 42";

    let sealed = live
        .seal_root_for_device(&new_device.device_public(), context)
        .unwrap();
    assert_eq!(
        stranger.import_root(&sealed, context, &root).unwrap_err(),
        Error::Open
    );
    assert_eq!(
        new_device
            .import_root(&sealed, b"other session", &root)
            .unwrap_err(),
        Error::Open
    );
    let wrong_root = KeyRing::generate().unwrap().device_public();
    assert_eq!(
        new_device
            .import_root(&sealed, context, &wrong_root)
            .unwrap_err(),
        Error::InvalidKey
    );
    new_device.import_root(&sealed, context, &root).unwrap();
    assert_eq!(new_device.root_public(), Some(root));

    // Member-scope purpose keys agree across the member's devices; device-scope do not.
    let shared = purpose(Scope::Member, "state");
    let local = purpose(Scope::Device, "state");
    assert_eq!(
        live.public_key(KeyRef::Purpose(&shared)).unwrap(),
        new_device.public_key(KeyRef::Purpose(&shared)).unwrap()
    );
    assert_ne!(
        live.public_key(KeyRef::Purpose(&local)).unwrap(),
        new_device.public_key(KeyRef::Purpose(&local)).unwrap()
    );

    // No sealing to oneself, and a device without root has nothing to hand over.
    assert_eq!(
        live.seal_root_for_device(&live.device_public(), context)
            .unwrap_err(),
        Error::InvalidKey
    );
    assert_eq!(
        stranger
            .seal_root_for_device(&live.device_public(), context)
            .unwrap_err(),
        Error::NoRoot
    );
}

#[test]
fn root_rotation_is_signed_by_the_old_root() {
    let mut ring = member_ring();
    let old = ring.root_public().unwrap();
    let mut statement = Vec::new();
    let (new, signature) = ring
        .rotate_root(|new| {
            statement = format!("succession {old} -> {new}").into_bytes();
            statement.clone()
        })
        .unwrap();
    assert_ne!(new, old);
    assert_eq!(ring.root_public(), Some(new));
    verify(&old, &statement, &signature).unwrap();
}

#[test]
fn migration_hook_accepts_only_the_current_kind() {
    let mut ring = KeyRing::generate().unwrap();
    ring.migrate(VLD0).unwrap();
    assert_eq!(
        ring.migrate(ckmg::CryptoKind(*b"VLD1")).unwrap_err(),
        Error::UnsupportedKind
    );
}

#[test]
fn ring_is_sealed_at_rest_under_the_passkey_prf() {
    let prf = passkey::PrfOutput::from_bytes(&[3u8; 32]).unwrap();
    let key = passkey::ring_key(&prf, "community-a").unwrap();
    let ring = member_ring();
    let sealed = ring.seal_at_rest(&key).unwrap();
    assert_ne!(ring.seal_at_rest(&key).unwrap(), sealed);

    let loaded = KeyRing::open_at_rest(&sealed, &key).unwrap();
    assert_eq!(loaded.device_public(), ring.device_public());
    assert_eq!(loaded.root_public(), ring.root_public());
    let p = purpose(Scope::Member, "state");
    assert_eq!(
        loaded.public_key(KeyRef::Purpose(&p)).unwrap(),
        ring.public_key(KeyRef::Purpose(&p)).unwrap()
    );

    let rootless = KeyRing::generate().unwrap();
    let loaded = KeyRing::open_at_rest(&rootless.seal_at_rest(&key).unwrap(), &key).unwrap();
    assert!(!loaded.has_root());
    assert_eq!(loaded.device_public(), rootless.device_public());

    // Another store name or another passkey cannot open it; neither can a modified blob.
    let other_store = passkey::ring_key(&prf, "community-b").unwrap();
    assert_eq!(
        KeyRing::open_at_rest(&sealed, &other_store).unwrap_err(),
        Error::Open
    );
    let other_prf = passkey::PrfOutput::from_bytes(&[4u8; 32]).unwrap();
    let other_key = passkey::ring_key(&other_prf, "community-a").unwrap();
    assert_eq!(
        KeyRing::open_at_rest(&sealed, &other_key).unwrap_err(),
        Error::Open
    );
    let mut modified = sealed.clone();
    let last = modified.len() - 1;
    modified[last] ^= 1;
    assert_eq!(
        KeyRing::open_at_rest(&modified, &key).unwrap_err(),
        Error::Open
    );
    assert_eq!(
        KeyRing::open_at_rest(b"garbage", &key).unwrap_err(),
        Error::Encoding
    );
}

#[test]
fn passkey_prf_becomes_a_store_password() {
    let prf = passkey::PrfOutput::from_bytes(&[7u8; 32]).unwrap();
    let other = passkey::PrfOutput::from_bytes(&[8u8; 32]).unwrap();
    let a = passkey::store_password(&prf, "community-a").unwrap();
    assert_eq!(*a, *passkey::store_password(&prf, "community-a").unwrap());
    assert_ne!(*a, *passkey::store_password(&prf, "community-b").unwrap());
    assert_ne!(*a, *passkey::store_password(&other, "community-a").unwrap());
    assert_eq!(
        passkey::store_password(&prf, "").unwrap_err(),
        Error::Encoding
    );
    assert!(passkey::PrfOutput::from_bytes(&[0u8; 31]).is_err());
    assert_eq!(passkey::unlock_prf_input(), passkey::unlock_prf_input());
}

#[test]
fn passkey_requests_are_validated() {
    let login = passkey::LoginRequest {
        rp_id: "example.org".into(),
        challenge: vec![1; 32],
        allow_credentials: vec![],
        timeout_ms: 60_000,
    };
    login.validate().unwrap();
    let short = passkey::LoginRequest {
        challenge: vec![1; 8],
        ..login
    };
    assert_eq!(short.validate().unwrap_err(), Error::Encoding);
}

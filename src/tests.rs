//! In-crate tests for redaction, formatting and boundary validation.
use crate::*;
use std::collections::HashSet;

pub(crate) mod fixture;
mod lineage_internal;
mod primitives;

#[test]
fn every_error_variant_has_a_distinct_message() {
    let all = [
        Error::Locked,
        Error::Pending,
        Error::Reconcile,
        Error::MissingCheckpoint,
        Error::Unauthorized,
        Error::Revoked,
        Error::Unavailable,
        Error::Limit,
        Error::Clock,
        Error::Encoding,
        Error::UnsupportedKind,
        Error::InvalidKey,
        Error::BadSignature,
        Error::Open,
        Error::Expired,
        Error::InvalidPurpose,
        Error::NoRoot,
        Error::RootExists,
        Error::Randomness,
        Error::Crypto,
    ];
    let messages: HashSet<String> = all.iter().map(|error| error.to_string()).collect();
    assert_eq!(messages.len(), all.len());
}

#[test]
fn redact_discards_the_backend_detail_and_keeps_the_selected_error() {
    let mapped: Result<(), Error> =
        Err("backend detail").map_err(crate::error::redact(Error::Crypto));
    assert_eq!(mapped, Err(Error::Crypto));
}

#[test]
fn secret_bearing_values_debug_as_redacted() {
    assert_eq!(format!("{:?}", Locator([7; 32])), "Locator([redacted])");
    assert_eq!(format!("{:?}", VLD0), "CryptoKind(VLD0)");
    assert_eq!(VLD0.bytes(), b"VLD0");
    assert_eq!(
        format!("{:?}", PublicKey::new(VLD0, [1; 32])),
        "PublicKey([redacted])"
    );
    assert_eq!(
        format!("{:?}", Signature::new(VLD0, [1; 64])),
        "Signature([redacted])"
    );
    assert_eq!(
        format!("{:?}", HashDigest::new(VLD0, [1; 32])),
        "HashDigest([redacted])"
    );
    let binding = Binding::new("community", "member").unwrap();
    assert_eq!(format!("{binding:?}"), "Binding([redacted])");
    let purpose = Purpose::new(Scope::Member, "label", 1).unwrap();
    assert_eq!(format!("{purpose:?}"), "Purpose([redacted])");
}

#[test]
fn typed_values_refuse_malformed_text_and_bytes() {
    let key = PublicKey::new(VLD0, [9; 32]);
    assert_eq!(key.to_string().parse::<PublicKey>(), Ok(key));
    assert_eq!(PublicKey::from_typed_bytes(&[0; 3]), Err(Error::Encoding));
    let text = key.to_string();
    assert_eq!("".parse::<PublicKey>(), Err(Error::Encoding));
    // Right length, no separator.
    assert_eq!(
        text.replace(':', "x").parse::<PublicKey>(),
        Err(Error::Encoding)
    );
    // Right length, kind of the wrong width.
    let short_kind = format!("VLD:{}", &text[4..]);
    assert_eq!(short_kind.len(), text.len());
    assert_eq!(short_kind.parse::<PublicKey>(), Err(Error::Encoding));
    // Right length, not base64url.
    let bad_value = format!("VLD0:{}", "!".repeat(text.len() - 5));
    assert_eq!(bad_value.parse::<PublicKey>(), Err(Error::Encoding));
}

#[test]
fn purposes_validate_labels_and_versions() {
    let purpose = Purpose::new(Scope::Device, "a.b-c_d:e", 4).unwrap();
    assert_eq!(purpose.scope(), Scope::Device);
    assert_eq!(purpose.label(), "a.b-c_d:e");
    assert_eq!(purpose.version(), 4);
    assert_eq!(purpose.next_version().unwrap().version(), 5);
    let last = Purpose::new(Scope::Device, "x", u32::MAX).unwrap();
    assert_eq!(last.next_version().err(), Some(Error::Limit));
    assert_eq!(
        Purpose::new(Scope::Member, "", 1).err(),
        Some(Error::InvalidPurpose)
    );
    assert_eq!(
        Purpose::new(Scope::Member, &"x".repeat(MAX_LABEL_BYTES + 1), 1).err(),
        Some(Error::InvalidPurpose)
    );
    assert_eq!(
        Purpose::new(Scope::Member, "bad label", 1).err(),
        Some(Error::InvalidPurpose)
    );
}

#[test]
fn system_entropy_fills_the_buffer() {
    let mut buffer = [0u8; 64];
    SystemEntropy.fill(&mut buffer).unwrap();
    assert_ne!(buffer, [0u8; 64]);
}

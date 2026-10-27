//! Boundary pins for `src/error.rs`, `src/intent.rs`, `src/purpose.rs`, `src/typed.rs`
//! (lane mut115). Each test fails under the corresponding cargo-mutants mutant
//! while passing on the real code. Product code is untouched.
use ckmg::*;

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

fn valid_command() -> AdmittedCommand {
    AdmittedCommand {
        binding: Binding::new("garden", "member").unwrap(),
        origin: "https://garden.example.com".into(),
        action: Action::Pair,
        device: PublicKey::new(VLD0, [1; 32]),
        root: Some(PublicKey::new(VLD0, [2; 32])),
        epoch: 3,
        target: Some(PublicKey::new(VLD0, [3; 32])),
        statement: Some([4; 32]),
        transcript: None,
        format: None,
        expires: 1200,
    }
}

fn request_for(binding: &Binding) -> Authorization<'_> {
    Authorization {
        binding,
        root: Some(PublicKey::new(VLD0, [2; 32])),
        device: PublicKey::new(VLD0, [1; 32]),
        epoch: 3,
        action: Action::Pair,
        target: Some(PublicKey::new(VLD0, [3; 32])),
        statement: Some([4; 32]),
        signing: None,
        now: 1100,
        evidence: &[],
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn origin_of_exactly_2048_bytes_is_admitted() {
    let (mut admission, mut verifier) = intent_channel();
    let origin = "x".repeat(2048);
    let mut command = valid_command();
    command.origin = origin.clone();
    let guard = admission.admit(command, 1000).unwrap();
    let binding = Binding::new("garden", "member").unwrap();
    verifier.consume(&request_for(&binding), &origin).unwrap();
    drop(guard);
}

fn device_session_command(transcript_len: usize) -> AdmittedCommand {
    let mut transcript = DeviceFormat::DeviceSession.tag().to_vec();
    transcript.resize(transcript_len, b'x');
    AdmittedCommand {
        binding: Binding::new("garden", "member").unwrap(),
        origin: "https://garden.example.com".into(),
        action: Action::SignDeviceEd25519,
        device: PublicKey::new(VLD0, [1; 32]),
        root: Some(PublicKey::new(VLD0, [2; 32])),
        epoch: 3,
        target: None,
        statement: None,
        transcript: Some(transcript),
        format: Some(DeviceFormat::DeviceSession),
        expires: 1200,
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn device_session_transcript_of_exactly_max_message_bytes_is_admitted() {
    let (mut admission, _) = intent_channel();
    admission
        .admit(device_session_command(MAX_MESSAGE_BYTES), 1000)
        .unwrap();
    assert!(matches!(
        admission.admit(device_session_command(MAX_MESSAGE_BYTES + 1), 1000),
        Err(Error::Encoding)
    ));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn crypto_kind_bytes_return_the_four_code_bytes() {
    assert_eq!(VLD0.bytes(), b"VLD0");
    assert_eq!(CryptoKind(*b"BAD!").bytes(), b"BAD!");
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn crypto_kind_debug_names_the_kind() {
    assert_eq!(format!("{:?}", VLD0), "CryptoKind(VLD0)");
    assert_eq!(format!("{:?}", CryptoKind(*b"BAD!")), "CryptoKind(BAD!)");
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn error_display_spells_every_variant() {
    let cases = [
        (Error::Locked, "keys are locked"),
        (Error::Pending, "pending transition or output"),
        (Error::Reconcile, "reload current state"),
        (Error::MissingCheckpoint, "encrypted checkpoint absent"),
        (Error::Unauthorized, "authority refused"),
        (Error::Revoked, "device revoked"),
        (Error::Unavailable, "port unavailable"),
        (Error::Limit, "limit exceeded"),
        (Error::Clock, "clock regressed"),
        (Error::Encoding, "malformed input"),
        (Error::UnsupportedKind, "unsupported cryptosystem"),
        (Error::InvalidKey, "invalid key"),
        (Error::BadSignature, "signature did not verify"),
        (Error::Open, "sealed data did not open"),
        (Error::Expired, "outside validity window"),
        (Error::InvalidPurpose, "invalid purpose"),
        (Error::NoRoot, "no member root on this device"),
        (Error::RootExists, "member root already present"),
        (Error::Randomness, "randomness unavailable"),
        (Error::Crypto, "cryptographic failure"),
    ];
    for (error, text) in cases {
        assert_eq!(format!("{error}"), text);
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn purpose_shape_accepts_exactly_max_label_bytes() {
    let label = "a".repeat(MAX_LABEL_BYTES);
    assert_eq!(
        Purpose::new(Scope::Device, &label, 0).unwrap().label(),
        label
    );
    assert_eq!(
        Purpose::new(Scope::Member, &label, 0).unwrap().label(),
        label
    );
    let wire: Purpose = serde_json::from_value(serde_json::json!({
        "scope": "device",
        "label": label,
        "version": 0,
    }))
    .unwrap();
    assert_eq!(wire.label(), label);
}

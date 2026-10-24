//! Local admission is intentionally distinct from real G3 authority.
use ckmg::*;
#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);
fn command() -> AdmittedCommand {
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
fn request(binding: &Binding) -> Authorization<'_> {
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
fn exact_single_consumption_reservation_and_channel_isolation() {
    let (mut admission, mut verifier) = intent_channel();
    let binding = Binding::new("garden", "member").unwrap();
    let request = request(&binding);
    assert!(
        verifier
            .consume(&request, "https://garden.example.com")
            .is_err()
    );
    let guard = admission.admit(command(), 1000).unwrap();
    let (_, mut unrelated) = intent_channel();
    assert!(
        unrelated
            .consume(&request, "https://garden.example.com")
            .is_err()
    );
    assert!(matches!(
        admission.admit(command(), 1000),
        Err(Error::Pending)
    ));
    verifier
        .consume(&request, "https://garden.example.com")
        .unwrap();
    assert!(
        verifier
            .consume(&request, "https://garden.example.com")
            .is_err()
    );
    assert!(matches!(
        admission.admit(command(), 1100),
        Err(Error::Pending)
    ));
    drop(guard);
    let guard = admission.admit(command(), 1100).unwrap();
    drop(guard);
    assert!(
        verifier
            .consume(&request, "https://garden.example.com")
            .is_err()
    );
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn every_scope_field_and_exclusive_deadline_are_bound() {
    for case in 0..11 {
        let (mut admission, mut verifier) = intent_channel();
        let _guard = admission.admit(command(), 1000).unwrap();
        let binding = Binding::new("garden", if case == 0 { "other" } else { "member" }).unwrap();
        let foreign_binding = Binding::new("other", "member").unwrap();
        let mut request = request(&binding);
        let mut origin = "https://garden.example.com";
        match case {
            0 => {}
            1 => origin = "https://foreign.example.com",
            2 => request.action = Action::Rotate,
            3 => request.device = PublicKey::new(VLD0, [5; 32]),
            4 => request.root = None,
            5 => request.epoch = 4,
            6 => request.target = None,
            7 => request.statement = Some([5; 32]),
            8 => request.now = 1200,
            9 => request.now = 999,
            _ => request.binding = &foreign_binding,
        }
        assert!(verifier.consume(&request, origin).is_err());
        let binding = Binding::new("garden", "member").unwrap();
        assert!(
            verifier
                .consume(&self::request(&binding), "https://garden.example.com")
                .is_err()
        );
    }
    let (mut admission, mut verifier) = intent_channel();
    let _guard = admission.admit(command(), 1000).unwrap();
    let binding = Binding::new("garden", "member").unwrap();
    let mut request = request(&binding);
    request.now = 1199;
    verifier
        .consume(&request, "https://garden.example.com")
        .unwrap();
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn stale_guard_cannot_cancel_later_admission_and_invalid_input_cannot_reserve() {
    let (mut admission, mut verifier) = intent_channel();
    for origin in [
        String::new(),
        "x".repeat(2049),
        "https://example.com\n".into(),
    ] {
        let mut input = command();
        input.origin = origin;
        assert!(matches!(admission.admit(input, 1000), Err(Error::Encoding)));
    }
    assert!(matches!(
        admission.admit(command(), 1200),
        Err(Error::Expired)
    ));
    let old = admission.admit(command(), 1000).unwrap();
    admission.cancel();
    let current = admission.admit(command(), 1001).unwrap();
    drop(old);
    let binding = Binding::new("garden", "member").unwrap();
    verifier
        .consume(&request(&binding), "https://garden.example.com")
        .unwrap();
    drop(current);
    admission.cancel();
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn signing_binds_original_bytes_and_deadline_without_authorizing_a_signer_lender() {
    for case in 0..7 {
        let (mut admission, mut verifier) = intent_channel();
        let mut command = command();
        command.action = Action::SignDeviceEd25519;
        command.target = None;
        command.statement = None;
        command.transcript = Some(b"cvld.device-session.v1\0original owner transcript".to_vec());
        command.format = Some(DeviceFormat::DeviceSession);
        let _guard = admission.admit(command, 1000).unwrap();
        let binding = Binding::new("garden", "member").unwrap();
        let mut request = request(&binding);
        request.action = Action::SignDeviceEd25519;
        request.target = None;
        request.statement = None;
        request.signing = Some(DeviceSigning {
            transcript: b"cvld.device-session.v1\0original owner transcript",
            format: Some(DeviceFormat::DeviceSession),
            expires: 1200,
        });
        match case {
            0 => {}
            1 => request.signing.as_mut().unwrap().transcript = b"different transcript",
            2 => request.signing.as_mut().unwrap().expires = 1201,
            3 => request.signing = None,
            4 => request.action = Action::LendDeviceSigner,
            5 => request.signing.as_mut().unwrap().format = Some(DeviceFormat::DeviceJoin),
            _ => request.action = Action::Use,
        }
        assert_eq!(
            verifier
                .consume(&request, "https://garden.example.com")
                .is_ok(),
            case == 0
        );
        request.action = Action::SignDeviceEd25519;
        request.signing = Some(DeviceSigning {
            transcript: b"cvld.device-session.v1\0original owner transcript",
            format: Some(DeviceFormat::DeviceSession),
            expires: 1200,
        });
        assert!(
            verifier
                .consume(&request, "https://garden.example.com")
                .is_err()
        );
    }
    let (mut admission, _) = intent_channel();
    for case in 0..8 {
        let mut command = command();
        command.action = Action::SignDeviceEd25519;
        command.target = None;
        command.statement = None;
        command.transcript = Some(b"cvld.device-session.v1\0original owner transcript".to_vec());
        command.format = Some(DeviceFormat::DeviceSession);
        match case {
            0 => command.transcript = None,
            1 => command.action = Action::Use,
            2 => command.target = Some(PublicKey::new(VLD0, [3; 32])),
            3 => command.statement = Some([1; 32]),
            // Device signing is typed: a format is required, must lead the transcript and
            // must be one exact admission may sign.
            4 => command.format = None,
            5 => command.format = Some(DeviceFormat::AccountRequest),
            6 => command.format = Some(DeviceFormat::DeviceJoin),
            _ => command.transcript = Some(vec![0; MAX_MESSAGE_BYTES + 1]),
        }
        assert!(matches!(
            admission.admit(command, 1000),
            Err(Error::Encoding)
        ));
    }
}

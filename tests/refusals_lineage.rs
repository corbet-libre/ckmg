//! Refusals of the public transcripts: lineages, pairing requests and grants, rotations,
//! certificates, passkey derivations and signature checks. All inputs are mutated copies
//! of genuine values produced by the shared fixtures.
mod support;
use ckmg::*;
use futures::executor::block_on;
use support::*;

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

/// The identity point: a valid encoding of a small-order, therefore weak, key.
fn weak() -> PublicKey {
    let mut bytes = [0u8; 32];
    bytes[0] = 1;
    PublicKey::new(VLD0, bytes)
}

fn foreign_kind() -> CryptoKind {
    CryptoKind(*b"XXXX")
}

fn amended_lineage(value: &Lineage, edit: impl FnOnce(&mut Lineage)) -> Lineage {
    let mut copy = value.clone();
    edit(&mut copy);
    copy
}

fn amended_request(
    value: &PairingRequest,
    edit: impl FnOnce(&mut PairingRequest),
) -> PairingRequest {
    let mut copy = value.clone();
    edit(&mut copy);
    copy
}

fn amended_rotation(value: &Rotation, edit: impl FnOnce(&mut Rotation)) -> Rotation {
    let mut copy = value.clone();
    edit(&mut copy);
    copy
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn a_lineage_with_an_invalid_shape_has_no_transcript_signature_or_digest() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 1);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        let lineage = a.lineage().await.unwrap();
        lineage.verify().unwrap();
        assert_eq!(lineage.binding.community(), "a");
        assert_eq!(lineage.binding.member(), "pseudonym-a");

        let cases = [
            (
                "version",
                amended_lineage(&lineage, |l| l.version = 2),
                Error::Encoding,
            ),
            (
                "epoch",
                amended_lineage(&lineage, |l| l.epoch = 0),
                Error::Encoding,
            ),
            (
                "revision",
                amended_lineage(&lineage, |l| l.revision = 0),
                Error::Encoding,
            ),
            (
                "no devices",
                amended_lineage(&lineage, |l| l.devices.clear()),
                Error::Encoding,
            ),
            (
                "too many devices",
                amended_lineage(&lineage, |l| {
                    l.devices = vec![l.devices[0]; MAX_DEVICES + 1]
                }),
                Error::Encoding,
            ),
            (
                "unsorted devices",
                amended_lineage(&lineage, |l| l.devices = vec![l.devices[0], l.devices[0]]),
                Error::Encoding,
            ),
            (
                "weak root",
                amended_lineage(&lineage, |l| l.root = weak()),
                Error::InvalidKey,
            ),
            (
                "foreign root",
                amended_lineage(&lineage, |l| {
                    l.root = PublicKey::new(foreign_kind(), *l.root.value())
                }),
                Error::UnsupportedKind,
            ),
            (
                "weak device",
                amended_lineage(&lineage, |l| l.devices = vec![weak()]),
                Error::InvalidKey,
            ),
            (
                "root listed as a device",
                amended_lineage(&lineage, |l| l.devices = vec![l.root]),
                Error::InvalidKey,
            ),
        ];
        for (name, bad, expected) in cases {
            assert_eq!(bad.signed_bytes().unwrap_err(), expected, "{name}");
            assert_eq!(bad.verify().unwrap_err(), expected, "{name}");
            assert_eq!(bad.digest().unwrap_err(), expected, "{name}");
        }
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn a_malformed_or_expired_pairing_request_is_refused_everywhere() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 2);
        let mut b = machine(&store, &time, &guard, 3);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        let anchor = a.lineage().await.unwrap();
        let request = request(&mut b, &prf(2), &anchor).await;
        request.verify(request.issued_at).unwrap();
        request.signed_bytes().unwrap();
        request.digest().unwrap();

        let cases = [
            (
                "version",
                amended_request(&request, |r| r.version = 2),
                Error::Encoding,
            ),
            (
                "epoch",
                amended_request(&request, |r| r.epoch = 0),
                Error::Encoding,
            ),
            (
                "empty window",
                amended_request(&request, |r| r.issued_at = r.expires_at),
                Error::Encoding,
            ),
            (
                "window above five minutes",
                amended_request(&request, |r| r.expires_at = r.issued_at + 301),
                Error::Encoding,
            ),
            (
                "root equals device",
                amended_request(&request, |r| r.root = r.device),
                Error::Encoding,
            ),
            (
                "weak root",
                amended_request(&request, |r| r.root = weak()),
                Error::InvalidKey,
            ),
            (
                "weak device",
                amended_request(&request, |r| r.device = weak()),
                Error::InvalidKey,
            ),
        ];
        for (name, bad, expected) in cases {
            assert_eq!(bad.signed_bytes().unwrap_err(), expected, "{name}");
            assert_eq!(bad.digest().unwrap_err(), expected, "{name}");
            assert_eq!(
                bad.verify(request.issued_at).unwrap_err(),
                expected,
                "{name}"
            );
        }
        assert_eq!(
            request.verify(request.issued_at - 1).unwrap_err(),
            Error::Expired
        );
        assert_eq!(
            request.verify(request.expires_at).unwrap_err(),
            Error::Expired
        );
        let forged = amended_request(&request, |r| r.proof = Signature::new(VLD0, [0; 64]));
        assert_eq!(
            forged.verify(request.issued_at).unwrap_err(),
            Error::BadSignature
        );
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn a_grant_with_a_truncated_root_envelope_is_refused_and_the_request_stays_pending() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 4);
        let mut b = machine(&store, &time, &guard, 5);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        let anchor = a.lineage().await.unwrap();
        let request = request(&mut b, &prf(2), &anchor).await;
        let grant = grant(&mut a, &guard, &request).await;
        let mut bad = grant.clone();
        bad.sealed_root.truncate(10);
        let approval = consent(
            Action::Adopt,
            &request.binding,
            Some(request.root),
            request.epoch,
            Some(request.device),
            Some(request.digest().unwrap()),
        );
        let writes = store.0.borrow().writes;
        assert_eq!(
            b.accept_pairing(&bad, &approval).await.unwrap_err(),
            Error::Encoding
        );
        assert_eq!(b.state(), State::PendingDevice);
        assert_eq!(store.0.borrow().writes, writes);
        accept(&mut b, &grant).await;
        assert_eq!(b.state(), State::Authorized);
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn a_rotation_refuses_every_malformed_envelope_set_and_mismatched_predecessor() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 6);
        let mut b = machine(&store, &time, &guard, 7);
        let mut c = machine(&store, &time, &guard, 8);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        pair(&mut a, &mut b, &guard, &prf(2)).await;
        let third = pair(&mut a, &mut c, &guard, &prf(3)).await;
        let previous = a.lineage().await.unwrap();
        prepare(&mut a, third.request.device).await;
        let receipt = a.commit().await.unwrap().unwrap();
        let genuine = rotation(&receipt).clone();
        genuine.verify(&previous).unwrap();
        genuine.signed_bytes().unwrap();
        let stays = previous
            .devices
            .iter()
            .copied()
            .find(|d| *d != third.request.device)
            .unwrap();

        let malformed = [
            (
                "missing envelope",
                amended_rotation(&genuine, |r| {
                    r.envelopes.pop();
                }),
            ),
            (
                "swapped envelopes",
                amended_rotation(&genuine, |r| r.envelopes.swap(0, 1)),
            ),
            (
                "short ciphertext",
                amended_rotation(&genuine, |r| {
                    r.envelopes[0].sealed_root.pop();
                }),
            ),
            (
                "too many devices",
                amended_rotation(&genuine, |r| {
                    r.envelopes = vec![r.envelopes[0].clone(); MAX_DEVICES + 1];
                    r.lineage.devices = vec![r.lineage.devices[0]; MAX_DEVICES + 1];
                }),
            ),
        ];
        for (name, bad) in malformed {
            assert_eq!(bad.signed_bytes().unwrap_err(), Error::Encoding, "{name}");
            assert_eq!(
                bad.verify(&previous).unwrap_err(),
                Error::Encoding,
                "{name}"
            );
        }

        let mismatched = [
            (
                "predecessor",
                amended_rotation(&genuine, |r| r.predecessor[0] ^= 1),
                Error::Unauthorized,
            ),
            (
                "previous root",
                amended_rotation(&genuine, |r| r.previous_root = r.lineage.root),
                Error::Unauthorized,
            ),
            (
                "removed stranger",
                amended_rotation(&genuine, |r| r.revoked = r.lineage.root),
                Error::Unauthorized,
            ),
            (
                "removed another device",
                amended_rotation(&genuine, |r| r.revoked = stays),
                Error::Unauthorized,
            ),
            (
                "signature",
                amended_rotation(&genuine, |r| r.signature = Signature::new(VLD0, [0; 64])),
                Error::BadSignature,
            ),
        ];
        for (name, bad, expected) in mismatched {
            assert_eq!(bad.verify(&previous).unwrap_err(), expected, "{name}");
        }
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn a_key_certificate_only_verifies_against_its_own_lineage_epoch_purpose_and_device() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut a = machine(&store, &time, &guard, 9);
        let mut b = machine(&store, &time, &guard, 10);
        let mut other = machine(&store, &time, &guard, 11);
        create(&mut a, &guard, &prf(1), &binding("a")).await;
        create(&mut other, &guard, &prf(3), &binding("c")).await;
        let before = a.lineage().await.unwrap();
        let grant = pair(&mut a, &mut b, &guard, &prf(2)).await;
        let current = a.lineage().await.unwrap();
        let foreign = other.lineage().await.unwrap();
        let member = purpose(Scope::Member, "p");
        let device = purpose(Scope::Device, "d");
        let mine = a.key(member.clone()).await.unwrap();
        let theirs = b.key(device.clone()).await.unwrap();
        mine.certificate().verify(&current, &member).unwrap();
        theirs.certificate().verify(&current, &device).unwrap();

        assert_eq!(
            mine.certificate().verify(&foreign, &member).unwrap_err(),
            Error::Unauthorized
        );
        // The device was not yet listed in the lineage before it was paired.
        assert_eq!(
            theirs.certificate().verify(&before, &device).unwrap_err(),
            Error::Unauthorized
        );
        // A newer epoch of the same pseudonym does not vouch for an older certificate.
        prepare(&mut a, grant.request.device).await;
        let receipt = a.commit().await.unwrap().unwrap();
        let next = rotation(&receipt).lineage.clone();
        assert_eq!(
            mine.certificate().verify(&next, &member).unwrap_err(),
            Error::Unauthorized
        );
        let mut weak_key = mine.certificate().clone();
        weak_key.key = weak();
        assert_eq!(
            weak_key.verify(&current, &member).unwrap_err(),
            Error::InvalidKey
        );
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn passkey_derivations_and_wrapping_refuse_bad_domains_and_oversized_input() {
    let p = prf(1);
    let roots = passkey::identity_roots(&p, "wallet").unwrap();
    roots.proof_transcript(&[0u8; 4096]).unwrap();
    assert_eq!(
        roots.proof_transcript(&[0u8; 4097]).unwrap_err(),
        Error::Limit
    );
    assert_eq!(
        roots.prove_possession(&[0u8; 4097]).unwrap_err(),
        Error::Limit
    );

    let cipher = passkey::store_cipher(&p, "a").unwrap();
    let mut rng = Random::new(1);
    let big = vec![0u8; MAX_MESSAGE_BYTES + 1];
    assert_eq!(
        cipher.seal(&mut rng, &[0u8; 4097], b"x").unwrap_err(),
        Error::Limit
    );
    assert_eq!(
        cipher.seal(&mut rng, b"ctx", &big).unwrap_err(),
        Error::Limit
    );
    assert_eq!(cipher.open(&[0u8; 4097], b"x").unwrap_err(), Error::Limit);
    let sealed_big = vec![0u8; MAX_MESSAGE_BYTES + 41];
    assert_eq!(cipher.open(b"ctx", &sealed_big).unwrap_err(), Error::Limit);

    let long = "a".repeat(257);
    for bad in ["", "bad\0domain", "bad\u{7}domain", long.as_str()] {
        assert_eq!(
            passkey::vault_location(&p, bad).unwrap_err(),
            Error::Encoding
        );
        assert_eq!(passkey::store_cipher(&p, bad).err(), Some(Error::Encoding));
        assert_eq!(
            passkey::identity_roots(&p, bad).err(),
            Some(Error::Encoding)
        );
    }
    for length in [0usize, 31, 33] {
        assert_eq!(
            passkey::PrfOutput::from_bytes(&vec![1u8; length]).err(),
            Some(Error::Encoding)
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn signature_and_key_checks_refuse_weak_and_foreign_inputs() {
    assert_eq!(validate_public_key(&weak()), Err(Error::InvalidKey));
    assert_eq!(
        validate_public_key(&PublicKey::new(foreign_kind(), [7; 32])),
        Err(Error::UnsupportedKind)
    );
    let foreign = Signature::new(foreign_kind(), [0; 64]);
    assert_eq!(verify(&weak(), b"x", &foreign), Err(Error::UnsupportedKind));
    assert_eq!(
        verify(
            &PublicKey::new(foreign_kind(), [7; 32]),
            b"x",
            &Signature::new(VLD0, [0; 64])
        ),
        Err(Error::UnsupportedKind)
    );
    assert_eq!(
        verify(&weak(), b"x", &Signature::new(VLD0, [0; 64])),
        Err(Error::InvalidKey)
    );
    assert_eq!(
        verify_ed25519(weak().value(), b"x", &[0u8; 64]),
        Err(Error::InvalidKey)
    );
    assert_eq!(
        verify_ed25519(&[0u8; 32], b"x", &[0u8; 64]),
        Err(Error::InvalidKey)
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn authorization_debug_names_the_action_only() {
    let pseudonym = binding("a");
    let request = Authorization {
        binding: &pseudonym,
        root: None,
        device: PublicKey::new(VLD0, [1; 32]),
        epoch: 0,
        action: Action::Create,
        target: None,
        statement: None,
        now: 0,
        evidence: b"private-evidence",
    };
    let shown = format!("{request:?}");
    assert!(shown.contains("Create"));
    for marker in ["pseudonym-a", "VLD0", "private-evidence"] {
        assert!(!shown.contains(marker), "{marker}");
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn binding_identifiers_are_validated() {
    assert!(Binding::new(&"c".repeat(256), &"m".repeat(256)).is_ok());
    let long = "x".repeat(257);
    let cases = [
        ("", "m"),
        ("c", ""),
        (long.as_str(), "m"),
        ("c", long.as_str()),
        ("bad\nc", "m"),
        ("c", "bad\tm"),
    ];
    for (community, member) in cases {
        assert_eq!(
            Binding::new(community, member).unwrap_err(),
            Error::Encoding
        );
    }
}

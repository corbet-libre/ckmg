//! X3 H2, M2 and M3: every device-key signature is typed. A signer signs a message only if
//! it is led by one `DeviceFormat` tag that the signer's class allows; reserved purposes
//! stay internal; Profile custody never receives the device scalar.
mod support;
use ckmg::*;
use futures::executor::block_on;
use support::*;

/// The stamp-salt tag (crate-private in ckmg): no signer may accept it.
const SALT_TAG: &[u8] = b"cmsg.device-join.salt.v1\0";
const PAYLOAD: &[u8] = b"attacker-chosen payload";
/// `SHA-256(Ed25519(device(prf(1), "a"), SALT_TAG || u16(1) || "a" || device))`, recorded
/// from cmsg `derived_salt` over the former raw `SaltDerivation` signer (ckmg d1b9016).
const SALT_VECTOR: &str = "32ca4334474fafa03510cd8fc27cdb6bd8020a94bd74d3f84f7a5a431dfff15b";

struct Permit {
    guard: Guard,
    time: Time,
}
impl Authority for Permit {
    async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        // Test-only: Profile custody is lent without the fixture's approval evidence.
        if request.action == Action::LendProfileCustody {
            return Ok(());
        }
        self.guard.check(request).await
    }
    fn check_device_signing_current(&mut self, _request: Authorization<'_>) -> Result<u64, Error> {
        Ok(self.time.0.get())
    }
}

/// Every reserved tag a former raw signer could reach: all formats and the salt.
fn tags() -> Vec<&'static [u8]> {
    let mut tags: Vec<&[u8]> = DeviceFormat::ALL
        .iter()
        .map(|format| format.tag())
        .collect();
    tags.push(SALT_TAG);
    tags
}

/// A tag and what a signer answered for `tag || PAYLOAD`.
type Attempt = (&'static [u8], Result<[u8; 64], Error>);

fn tagged(tag: &[u8]) -> Vec<u8> {
    [tag, PAYLOAD].concat()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn tags_are_prefix_free_and_well_shaped() {
    let tags = tags();
    for tag in &tags {
        let terminator = tag[tag.len() - 1];
        let name = match tag[0] {
            // `["name",`
            b'[' => tag
                .strip_prefix(b"[\"")
                .and_then(|rest| rest.strip_suffix(b"\","))
                .unwrap(),
            // `n name\0`, a postcard string: one length byte below `[` and the letters.
            n if n < b'[' => {
                assert_eq!(usize::from(n), tag.len() - 1, "{tag:?}");
                assert_eq!(terminator, 0, "{tag:?}");
                &tag[1..tag.len() - 1]
            }
            // `name\0` or `name\n`
            _ => {
                assert!(terminator == 0 || terminator == b'\n', "{tag:?}");
                &tag[..tag.len() - 1]
            }
        };
        assert!(name.first().is_some_and(u8::is_ascii_lowercase), "{tag:?}");
        assert!(
            name.iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._:-".contains(b)),
            "{tag:?}"
        );
    }
    for (i, a) in tags.iter().enumerate() {
        for (j, b) in tags.iter().enumerate() {
            if i != j {
                assert!(!b.starts_with(a), "{a:?} prefixes {b:?}");
            }
        }
    }
    for format in DeviceFormat::ALL {
        assert_eq!(DeviceFormat::of(&tagged(format.tag())), Some(format));
    }
    assert_eq!(DeviceFormat::of(&tagged(SALT_TAG)), None);
    assert_eq!(DeviceFormat::of(PAYLOAD), None);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn exact_admission_signs_only_admitted_formats_led_by_their_tag() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut created = machine(&store, &time, &guard, 31);
        create(&mut created, &guard, &prf(1), &binding("a")).await;
        let device = created.device_public_key().await.unwrap();
        drop(created);
        let mut keys = Keys::new(
            store.clone(),
            time.clone(),
            Random::new(32),
            Permit {
                guard: guard.clone(),
                time: time.clone(),
            },
        );
        keys.unlock(&prf(1), "a").await.unwrap();
        for format in DeviceFormat::ALL {
            for tag in tags() {
                let message = tagged(tag);
                let result = keys
                    .sign_device_ed25519_current(format, &message, 1200)
                    .await;
                if tag == format.tag() && format.allowed(SigningClass::Admitted) {
                    let signature = result.unwrap();
                    verify_ed25519(device.value(), &message, &signature).unwrap();
                } else {
                    assert_eq!(
                        result,
                        Err(Error::Unauthorized),
                        "{format:?} signed {tag:?}"
                    );
                }
            }
            // A bare payload (no tag) is never signed.
            assert!(
                keys.sign_device_ed25519_current(format, PAYLOAD, 1200)
                    .await
                    .is_err()
            );
        }
        // The typed formats are never exact-admitted: join, pairing possession.
        assert!(!DeviceFormat::DeviceJoin.allowed(SigningClass::Admitted));
        assert!(!DeviceFormat::PairingPossession.allowed(SigningClass::Admitted));
        assert!(!DeviceFormat::WalletBirthDevice.allowed(SigningClass::Admitted));
        assert!(!DeviceFormat::WalletBirthPassport.allowed(SigningClass::Admitted));
        assert_eq!(keys.state(), State::Authorized);
    });
}

/// The owner status request is signed only through exact admission.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn account_status_is_allowed_in_the_admitted_class_only() {
    let tag = DeviceFormat::AccountStatus.tag();
    assert_eq!(tag, b"cfrm.account.status.v1\0");
    assert_eq!(
        DeviceFormat::of(&tagged(tag)),
        Some(DeviceFormat::AccountStatus)
    );
    assert!(DeviceFormat::AccountStatus.allowed(SigningClass::Admitted));
    for class in [
        SigningClass::Enrollment,
        SigningClass::Opening,
        SigningClass::Provenance,
        SigningClass::Profile,
        SigningClass::Delegate,
    ] {
        assert!(!DeviceFormat::AccountStatus.allowed(class), "{class:?}");
    }
}

#[cfg(feature = "profile-envelope")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn profile_signer_signs_only_profile_formats_and_holds_no_device_scalar() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut created = machine(&store, &time, &guard, 33);
        create(&mut created, &guard, &prf(1), &binding("a")).await;
        drop(created);
        let mut keys = Keys::new(
            store.clone(),
            time.clone(),
            Random::new(36),
            Permit {
                guard: guard.clone(),
                time: time.clone(),
            },
        );
        keys.unlock(&prf(1), "a").await.unwrap();
        let lineage = keys.lineage().await.unwrap();
        let (device, hpke, certificate, results) = keys
            .with_profile_custody(|signer, custody| {
                assert_eq!(signer.hpke_public_key(), custody.public_key());
                let results: Vec<Attempt> = tags()
                    .into_iter()
                    .map(|tag| (tag, signer.sign(&tagged(tag))))
                    .collect();
                assert!(signer.sign(PAYLOAD).is_err());
                (
                    *signer.public_key(),
                    signer.hpke_public_key(),
                    signer.hpke_certificate().clone(),
                    results,
                )
            })
            .await
            .unwrap();
        for (tag, result) in results {
            match DeviceFormat::of(&tagged(tag)) {
                Some(format) if format.allowed(SigningClass::Profile) => {
                    verify_ed25519(&device, &tagged(tag), &result.unwrap()).unwrap();
                }
                _ => assert_eq!(result, Err(Error::Unauthorized), "profile signed {tag:?}"),
            }
        }
        // M3: the Profile HPKE key is a certified Device-scope purpose key, not the device's
        // X25519 form (which opens its root envelopes).
        let device_x25519 = ed25519_dalek::VerifyingKey::from_bytes(&device)
            .unwrap()
            .to_montgomery()
            .to_bytes();
        assert_ne!(hpke, device_x25519);
        assert_eq!(certificate.device, PublicKey::new(VLD0, device));
        assert_eq!(certificate.purpose.scope(), Scope::Device);
        assert!(certificate.purpose.is_reserved());
        assert_eq!(
            ed25519_dalek::VerifyingKey::from_bytes(certificate.key.value())
                .unwrap()
                .to_montgomery()
                .to_bytes(),
            hpke
        );
        certificate.verify(&lineage, &certificate.purpose).unwrap();
        // Generic derivation never reaches the Profile purpose.
        assert_eq!(
            keys.key(certificate.purpose.clone()).await.unwrap_err(),
            Error::InvalidPurpose
        );
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn opening_signs_only_the_session_and_the_salt_equals_cmsg() {
    block_on(async {
        let device = passkey::device_public_key(&prf(1), "a").unwrap();
        let mut salted = 1u16.to_be_bytes().to_vec();
        salted.extend_from_slice(b"a");
        salted.extend_from_slice(device.value());
        let salt = passkey::device_salt(&prf(1), "a", &salted).unwrap();
        assert_eq!(hex(&salt), SALT_VECTOR);
        // Keys derives the same salt from the same device key.
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut keys = machine(&store, &time, &guard, 35);
        create(&mut keys, &guard, &prf(1), &binding("a")).await;
        assert_eq!(keys.device_public_key().await.unwrap(), device);
        assert_eq!(keys.device_salt(&salted).await.unwrap(), salt);
        // The opening's only signature is the session; it is led by the session tag.
        let session = passkey::sign_device_session(&prf(1), "a", PAYLOAD).unwrap();
        verify_ed25519(
            device.value(),
            &tagged(DeviceFormat::DeviceSession.tag()),
            &session,
        )
        .unwrap();
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn reserved_purposes_stay_internal() {
    block_on(async {
        let store = Memory::default();
        let time = Time::default();
        let guard = Guard::default();
        let mut keys = machine(&store, &time, &guard, 34);
        create(&mut keys, &guard, &prf(1), &binding("a")).await;
        for label in [
            "vault.checkpoint",
            "vault.checkpoint.chunk.0",
            "ckmg.anything",
        ] {
            assert!(
                Purpose::new(Scope::Member, label, 0).is_err(),
                "Purpose::new accepted {label}"
            );
            let smuggled = wire_purpose(Scope::Member, label);
            assert!(smuggled.is_reserved());
            assert_eq!(
                keys.key(smuggled).await.unwrap_err(),
                Error::InvalidPurpose,
                "key() derived reserved {label}"
            );
        }
        assert!(Purpose::new(Scope::Device, "tor.onion", 0).is_err());
        let onion = keys
            .key(NodePurpose::TorOnion.purpose(0).unwrap())
            .await
            .unwrap();
        assert!(onion.certificate().purpose.is_reserved());
        assert_eq!(
            keys.sign_ed25519(&onion, b"application bytes").await,
            Err(Error::InvalidPurpose),
            "the onion seed signed application bytes"
        );
        assert!(!purpose(Scope::Member, "profile").is_reserved());
    });
}

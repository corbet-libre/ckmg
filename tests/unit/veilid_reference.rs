// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Test-only reference composition adapted from Veilid, revision
// dd8e2cdd72b5bf817172ac31c20872b168c5c8fc:
// veilid-core-optimized/src/{sign,seal}.rs and
// veilid-core/src/crypto/crypto_system/hpke.rs.
// https://gitlab.com/veilid/veilid
// Kept in its own MPL-2.0 file; never included in the production library.

use crate::{Entropy, Error, PublicKey, Signature, VLD0, keyring, vld0};
use ed25519_dalek::{Digest, Sha512, SigningKey};
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};
use rand_core::SeedableRng;
use zeroize::Zeroizing;

type Kem = hpke::kem::X25519HkdfSha256;
type Kdf = hpke::kdf::HkdfSha256;
type Aead = hpke::aead::ChaCha20Poly1305;

struct Fixed;
impl Entropy for Fixed {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
        output.fill(19);
        Ok(())
    }
}

fn decode(value: &str) -> Vec<u8> {
    data_encoding::HEXLOWER.decode(value.as_bytes()).unwrap()
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn veilid_sign_hash_key_and_typed_format_conformance() {
    // RFC 8032 seed/public pair; the signature uses Veilid's distinct ph context.
    let seed = keyring::secret(&decode(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    ))
    .unwrap();
    let public = vld0::public_key(&seed);
    assert_eq!(
        public.value().as_slice(),
        decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    );
    for message in [
        &b""[..],
        &b"Veilid VLD0 conformance"[..],
        &[0x5a; 32768][..],
    ] {
        // Veilid's signing_key validates the full keypair before signing.
        let mut keypair = Zeroizing::new([0; 64]);
        keypair[..32].copy_from_slice(seed.as_slice());
        keypair[32..].copy_from_slice(public.value());
        let signer = SigningKey::from_keypair_bytes(&keypair).unwrap();
        let mut prehash = Sha512::default();
        prehash.update(message);
        let reference = signer.sign_prehashed(prehash, Some(b"VLD0_SIGN")).unwrap();
        let actual = vld0::sign(&seed, message).unwrap();
        assert_eq!(actual.value(), &reference.to_bytes());
        vld0::verify(
            &public,
            message,
            &Signature::new(VLD0, reference.to_bytes()),
        )
        .unwrap();
        assert_eq!(
            vld0::hash(message).value(),
            blake3::hash(message).as_bytes()
        );
        let mut wrong_context = Sha512::default();
        wrong_context.update(message);
        let signature = signer
            .sign_prehashed(wrong_context, Some(b"other"))
            .unwrap();
        assert!(
            vld0::verify(
                &public,
                message,
                &Signature::new(VLD0, signature.to_bytes())
            )
            .is_err()
        );
    }
    let text = format!(
        "VLD0:{}",
        data_encoding::BASE64URL_NOPAD.encode(public.value())
    );
    assert_eq!(text.parse::<PublicKey>().unwrap(), public);
    assert_eq!(public.to_string(), text);
    assert_eq!(
        PublicKey::from_typed_bytes(&public.to_typed_bytes()).unwrap(),
        public
    );
    assert!(format!("{text}=").parse::<PublicKey>().is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn veilid_hpke_header_conversion_info_and_cross_open_conformance() {
    let seed = Zeroizing::new([23; 32]);
    let public = vld0::public_key(&seed);
    let reference_public = ed25519_dalek::VerifyingKey::from_bytes(public.value())
        .unwrap()
        .to_montgomery()
        .to_bytes();
    let expanded = Zeroizing::new(<[u8; 64]>::from(
        Sha512::default().chain_update(seed.as_slice()).finalize(),
    ));
    let reference_private = <Kem as hpke::Kem>::PrivateKey::from_bytes(&expanded[..32]).unwrap();
    let recipient = <Kem as hpke::Kem>::PublicKey::from_bytes(&reference_public).unwrap();
    let info = b"veilid-hpke/1VLD0";
    let (enc, ciphertext) = hpke::single_shot_seal_with_rng::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &recipient,
        info,
        b"root-transport-fixture",
        b"context",
        &mut rand_chacha::ChaCha20Rng::from_seed([19; 32]),
    )
    .unwrap();
    let mut reference = vec![1];
    reference.extend_from_slice(b"VLD0");
    reference.extend_from_slice(enc.to_bytes().as_slice());
    reference.extend_from_slice(&ciphertext);
    let actual = vld0::seal_to(&mut Fixed, &public, b"context", b"root-transport-fixture").unwrap();
    assert_eq!(actual, reference);
    assert_eq!(
        &*vld0::open(&seed, b"context", &reference).unwrap(),
        b"root-transport-fixture"
    );
    assert_eq!(
        hpke::single_shot_open::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &reference_private,
            &enc,
            info,
            &actual[37..],
            b"context",
        )
        .unwrap(),
        b"root-transport-fixture"
    );
    for index in [0, 1, 5, actual.len() - 1] {
        let mut changed = actual.clone();
        changed[index] ^= 1;
        assert!(vld0::open(&seed, b"context", &changed).is_err());
    }
    assert!(vld0::open(&seed, b"other", &actual).is_err());
    assert!(vld0::open(&Zeroizing::new([24; 32]), b"context", &actual).is_err());
    for length in 0..actual.len() {
        assert!(vld0::open(&seed, b"context", &actual[..length]).is_err());
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn veilid_rfc9180_a2_fixture_uses_the_selected_upstream_suite() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/rfc9180_a2_base.json")).unwrap();
    let field = |name: &str| decode(fixture[name].as_str().unwrap());
    let (private, public) = Kem::derive_keypair(&field("ikmR"));
    assert_eq!(private.to_bytes().as_slice(), field("skRm"));
    assert_eq!(public.to_bytes().as_slice(), field("pkRm"));
    let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&field("enc")).unwrap();
    let encryption = &fixture["encryption"];
    let ciphertext = decode(encryption["ct"].as_str().unwrap());
    let aad = decode(encryption["aad"].as_str().unwrap());
    let opened = hpke::single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &private,
        &enc,
        &field("info"),
        &ciphertext,
        &aad,
    )
    .unwrap();
    assert_eq!(opened, decode(encryption["pt"].as_str().unwrap()));
}

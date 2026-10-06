// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Test-only reference composition adapted from Veilid, revision
// dd8e2cdd72b5bf817172ac31c20872b168c5c8fc:
// veilid-core/src/crypto/crypto_system/vld0/mod.rs (compute_dh, crypt_no_auth),
// veilid-core-optimized/src/sign.rs (Ed25519-to-X25519 conversion),
// veilid-core-optimized/src/dh.rs and cipher.rs.
// https://gitlab.com/veilid/veilid
// Kept in its own MPL-2.0 file; never included in the production library.

use super::*;
use chacha20::{
    XChaCha20,
    cipher::{KeyIvInit, StreamCipher},
};
use ed25519_dalek::{Digest, Sha512, SigningKey, VerifyingKey};

fn reference_public(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

// Deliberately does not use ckmg's conversion or compute_dh helpers. The raw
// first half of SHA-512 is essential: a reduced Ed25519 scalar is not equivalent.
fn reference_raw_dh(seed: &[u8; 32], peer: &[u8; 32]) -> [u8; 32] {
    let expanded: [u8; 64] = Sha512::default().chain_update(seed).finalize().into();
    let private = x25519_dalek::StaticSecret::from(<[u8; 32]>::try_from(&expanded[..32]).unwrap());
    let public = x25519_dalek::PublicKey::from(
        VerifyingKey::from_bytes(peer)
            .unwrap()
            .to_montgomery()
            .to_bytes(),
    );
    let shared = private.diffie_hellman(&public);
    assert!(shared.was_contributory());
    shared.to_bytes()
}

fn reference_secret(seed: &[u8; 32], peer: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"VLD0_CRYPT");
    hasher.update(&reference_raw_dh(seed, peer));
    *hasher.finalize().as_bytes()
}

fn reference_crypt(secret: &[u8; 32], nonce: &[u8; 24], input: &[u8]) -> Vec<u8> {
    let mut output = vec![0; input.len()];
    XChaCha20::new(secret.into(), nonce.into()).apply_keystream_b2b(input, &mut output);
    output
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn original_veilid_node_dh_and_xchacha_cross_open_in_both_directions() {
    // The first pair is RFC 8032's seed/public fixture, also used in the existing
    // VLD0 signature conformance tests. Other seeds exercise different scalars.
    let rfc_seed: [u8; 32] = data_encoding::HEXLOWER
        .decode(b"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        reference_public(&rfc_seed).as_slice(),
        data_encoding::HEXLOWER
            .decode(b"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
            .unwrap()
    );
    for (left_seed, right_seed) in [(rfc_seed, [24; 32]), ([23; 32], [197; 32])] {
        let left_secret = Zeroizing::new(left_seed);
        let right_secret = Zeroizing::new(right_seed);
        let left = Vld0NodeCipher {
            secret: &left_secret,
            public_key: reference_public(&left_seed),
        };
        let right = Vld0NodeCipher {
            secret: &right_secret,
            public_key: reference_public(&right_seed),
        };
        let expected = reference_secret(&left_seed, right.public_key());
        assert_eq!(expected, reference_secret(&right_seed, left.public_key()));
        assert_eq!(
            *vld0::compute_dh(&left_secret, &PublicKey::new(VLD0, *right.public_key())).unwrap(),
            expected
        );
        let nonce = [37; 24];
        for plaintext in [
            &b""[..],
            &b"original ENV0 encrypted operation"[..],
            &[0x5a; 1024][..],
        ] {
            let reference = reference_crypt(&expected, &nonce, plaintext);
            let encrypted = left.crypt(right.public_key(), &nonce, plaintext).unwrap();
            assert_eq!(*encrypted, reference);
            assert_eq!(
                &*right.crypt(left.public_key(), &nonce, &reference).unwrap(),
                plaintext
            );
            assert_eq!(reference_crypt(&expected, &nonce, &encrypted), plaintext);
            let reverse = right.crypt(left.public_key(), &nonce, plaintext).unwrap();
            assert_eq!(
                &*left.crypt(right.public_key(), &nonce, &reverse).unwrap(),
                plaintext
            );
        }
        let plaintext = b"domain and nonce separation";
        let ciphertext = left.crypt(right.public_key(), &nonce, plaintext).unwrap();
        let raw = reference_raw_dh(&left_seed, right.public_key());
        assert_ne!(reference_crypt(&raw, &nonce, plaintext), *ciphertext);
        assert_ne!(
            reference_crypt(blake3::hash(&raw).as_bytes(), &nonce, plaintext),
            *ciphertext
        );
        let mut wrong_domain = blake3::Hasher::new();
        wrong_domain.update(b"VLD0_SIGN");
        wrong_domain.update(&raw);
        assert_ne!(
            reference_crypt(wrong_domain.finalize().as_bytes(), &nonce, plaintext),
            *ciphertext
        );
        assert_ne!(
            *left
                .crypt(right.public_key(), &[38; 24], plaintext)
                .unwrap(),
            *ciphertext
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn node_cipher_rejects_malformed_and_weak_peers_and_bounds_original_packets() {
    let secret = Zeroizing::new([47; 32]);
    let cipher = Vld0NodeCipher {
        secret: &secret,
        public_key: reference_public(&secret),
    };
    let nonce = [48; 24];
    let peer = reference_public(&[49; 32]);
    let largest = vec![0x39; 65_507];
    let ciphertext = cipher.crypt(&peer, &nonce, &largest).unwrap();
    assert_eq!(ciphertext.len(), largest.len());
    assert_eq!(
        reference_crypt(&reference_secret(&secret, &peer), &nonce, &ciphertext),
        largest
    );
    assert_eq!(
        cipher.crypt(&peer, &nonce, &vec![0; 65_508]),
        Err(Error::Limit)
    );
    let mut identity = [0; 32];
    identity[0] = 1;
    for weak in [[0; 32], identity] {
        assert!(VerifyingKey::from_bytes(&weak).unwrap().is_weak());
        assert_eq!(
            cipher.crypt(&weak, &nonce, b"packet"),
            Err(Error::InvalidKey)
        );
        assert_eq!(cipher.crypt(&weak, &nonce, &[]), Err(Error::InvalidKey));
    }
    // Select an actual rejected compressed point using the maintained parser;
    // do not assume every noncanonical-looking encoding is off the curve.
    let malformed = (0..=u8::MAX)
        .map(|byte| [byte; 32])
        .find(|point| VerifyingKey::from_bytes(point).is_err())
        .expect("the bounded fixture set includes an invalid curve point");
    assert_eq!(
        cipher.crypt(&malformed, &nonce, b"packet"),
        Err(Error::InvalidKey)
    );
    assert_eq!(
        cipher.crypt(&malformed, &nonce, &vec![0; 65_508]),
        Err(Error::Limit)
    );
}

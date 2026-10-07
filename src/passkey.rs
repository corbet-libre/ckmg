//! Deterministic custody from an opaque, high-entropy PRF secret.
//!
//! Device-side cpky Passkeys acquires the secret; server-side ckyh Keyhole verifies
//! authentication. This module has no WebAuthn adapter, options, credential IDs or
//! PRF-input salt. Keys cannot tell which authenticator produced the input.
//! Every derivation is specified in docs/CONSTRUCTIONS.md.

use crate::{Error, Locator, Secret};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

const HKDF_SALT: &[u8] = b"ckmg.passkey-prf.v1";
const STORE_PASSWORD_INFO: &[u8] = b"ckmg.cwst-password.v1\0";
const RING_KEY_INFO: &[u8] = b"ckmg.keyring-key.v1\0";
const LOCATION_INFO: &[u8] = b"ckmg.vault-location.v1\0";
const IDENTITY_INFO: &[u8] = b"ckmg.identity-root.v1\0";
const HOLDER_INFO: &[u8] = b"ckmg.passport-holder-seed.v1\0";
const DEVICE_INFO: &[u8] = b"ckmg.device-lineage-seed.v1\0";
const LINEAGE_INFO: &[u8] = b"ckmg.member-lineage-seed.v1\0";

/// Opaque 32-byte input from device-side Passkeys. Wiped on drop; no Debug,
/// serialization, cloning or byte getter. This is not evidence of authentication.
///
/// ```compile_fail
/// let input = ckmg::passkey::PrfOutput::from_bytes(&[1; 32]).unwrap();
/// println!("{input:?}");
/// ```
pub struct PrfOutput(Zeroizing<[u8; 32]>);

impl PrfOutput {
    /// Wrap the 32-byte `results.first` value of the PRF extension.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(crate::keyring::secret(bytes)?))
    }
}

/// Stable identity custody for a separately selected wallet domain. Never send this
/// capability or its public identity key to community services as a member ID.
/// The holder seed stays private pending an upstream passport-engine integration;
/// deriving it is not passport issuance or proof of membership.
pub struct IdentityRoots {
    domain: String,
    identity: Secret,
    // Reserved for the upstream holder engine, never exposed as bytes or an RNG.
    passport_holder_seed: Secret,
}

impl IdentityRoots {
    /// Public identity verification key; independent of device/lineage rotations.
    pub fn public_key(&self) -> crate::PublicKey {
        crate::vld0::public_key(&self.identity)
    }

    /// Sign a bounded identity-possession challenge with a dedicated domain.
    /// This does not authorize a community action or manufacture a passport.
    pub fn prove_possession(&self, challenge: &[u8]) -> Result<crate::Signature, Error> {
        crate::vld0::sign(&self.identity, &self.proof_transcript(challenge)?)
    }

    /// Canonical identity-possession transcript for independent verification.
    pub fn proof_transcript(&self, challenge: &[u8]) -> Result<Vec<u8>, Error> {
        if challenge.len() > 4096 {
            return Err(Error::Limit);
        }
        crate::lineage::encode(b"ckmg.identity.proof.v1\0", &(&self.domain, challenge))
    }
}

impl Drop for IdentityRoots {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.identity.zeroize();
        self.passport_holder_seed.zeroize();
    }
}
crate::lineage::redacted!(IdentityRoots);

/// Reconstruct identity root and passport holder secret seed without storage or
/// randomness. The wallet domain must be stable and isolated from community custody.
/// Passport credentials themselves still need issuer renewal if their data is lost.
pub fn identity_roots(prf: &PrfOutput, wallet_domain: &str) -> Result<IdentityRoots, Error> {
    let identity = expand(prf, IDENTITY_INFO, wallet_domain)?;
    let passport_holder_seed = expand(prf, HOLDER_INFO, wallet_domain)?;
    Ok(IdentityRoots {
        domain: wallet_domain.into(),
        identity,
        passport_holder_seed,
    })
}

pub(crate) fn device_seed(prf: &PrfOutput, community: &str) -> Result<Secret, Error> {
    expand(prf, DEVICE_INFO, community)
}

pub(crate) fn lineage_seed(prf: &PrfOutput, community: &str) -> Result<Secret, Error> {
    expand(prf, LINEAGE_INFO, community)
}

pub(crate) fn lineage_root(seed: &Secret, epoch: u64) -> Result<Secret, Error> {
    if epoch == 0 {
        return Err(Error::Encoding);
    }
    let mut root = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(b"ckmg.lineage-root.v1"), seed.as_slice())
        .expand(&epoch.to_be_bytes(), root.as_mut())
        .map_err(crate::error::redact(Error::Crypto))?;
    Ok(root)
}

/// Opaque wrapping capability for storage adapters. Uses an independent HKDF label
/// from key-ring encryption, so it cannot decrypt ckmg's custody checkpoints.
pub struct StoreCipher(Secret);

impl StoreCipher {
    /// Wrap a bounded storage secret or record with authenticated owner context.
    pub fn seal(
        &self,
        rng: &mut impl crate::Entropy,
        context: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if context.len() > 4096 || plaintext.len() > crate::MAX_MESSAGE_BYTES {
            return Err(Error::Limit);
        }
        crate::keyring::seal(rng, &self.0, &store_context(context), plaintext)
    }
    /// Open data from this storage capability; no raw wrapping key is exposed.
    pub fn open(&self, context: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        if context.len() > 4096 || sealed.len() > crate::MAX_MESSAGE_BYTES + 40 {
            return Err(Error::Limit);
        }
        crate::keyring::open(&self.0, &store_context(context), sealed)
    }
}
crate::lineage::redacted!(StoreCipher);

fn store_context(context: &[u8]) -> Vec<u8> {
    let mut aad = b"ckmg.storage.wrap.v1\0".to_vec();
    aad.extend_from_slice(context);
    aad
}

/// Derive an opaque storage-wrapping capability, separate from the vault locator and
/// custody key. The adapter may wrap its own data key without obtaining our key.
pub fn store_cipher(prf: &PrfOutput, community: &str) -> Result<StoreCipher, Error> {
    Ok(StoreCipher(expand(prf, STORE_PASSWORD_INFO, community)?))
}

/// Derive the key that seals the private key material at rest. Independent of the
/// storage capability (different HKDF info), so the ring stays sealed even to code that can
/// read the store.
pub(crate) fn ring_key(prf: &PrfOutput, store: &str) -> Result<Secret, Error> {
    expand(prf, RING_KEY_INFO, store)
}

/// Derive the stable community-local vault locator from the authenticator PRF.
/// The same synced credential locates the same logical device. This is not a
/// membership identity, and does not guarantee that a network retains its record.
pub fn vault_location(prf: &PrfOutput, community: &str) -> Result<Locator, Error> {
    Ok(Locator(*expand(prf, LOCATION_INFO, community)?))
}

fn expand(prf: &PrfOutput, label: &[u8], store: &str) -> Result<Zeroizing<[u8; 32]>, Error> {
    if store.is_empty() || store.len() > 256 || store.chars().any(char::is_control) {
        return Err(Error::Encoding);
    }
    let mut info = Vec::with_capacity(label.len() + store.len());
    info.extend_from_slice(label);
    info.extend_from_slice(store.as_bytes());
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(HKDF_SALT), prf.0.as_slice())
        .expand(&info, out.as_mut())
        .map_err(crate::error::redact(Error::Crypto))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn hkdf_derivation_matches_independent_hmac_vectors() {
        // Independently evaluated from RFC 5869 Extract + one Expand block (L=32).
        let prf = PrfOutput::from_bytes(&[27; 32]).unwrap();
        let hex = |bytes: &[u8]| data_encoding::HEXLOWER.encode(bytes);
        assert_eq!(
            hex(vault_location(&prf, "a").unwrap().as_bytes()),
            "c5086bf525ec6e443a5a0592e044e1d0fdfcde4b7d8d0c6195b3565fcc02690a"
        );
        assert_eq!(
            hex(ring_key(&prf, "a").unwrap().as_slice()),
            "1f267040dddfa9cbf9d26075ae78d90ff69a5a1fc98d7242a30ae770b0db6b64"
        );
        assert_eq!(
            hex(store_cipher(&prf, "a").unwrap().0.as_slice()),
            "767cc54cee7a526522277a226fa0aeb6671f2040a9fc768743f1820b9a88ab4b"
        );
        let roots = identity_roots(&prf, "a").unwrap();
        assert_eq!(
            hex(roots.identity.as_slice()),
            "305fd593f6b34de15c321bd2daddf61034fd5185347d68d2d4bfcae20dc2e740"
        );
        assert_eq!(
            hex(roots.passport_holder_seed.as_slice()),
            "fb89d2196c2d2f07a23f69c7b3f6d919a10f71e8609bc211eaf0000f0050c68f"
        );
        assert_eq!(
            hex(device_seed(&prf, "a").unwrap().as_slice()),
            "cda24928113648d6cd3dc9f1d83e96cae9cb91d29491e4a75d7c9b61dfefba0f"
        );
        let seed = lineage_seed(&prf, "a").unwrap();
        assert_eq!(
            hex(seed.as_slice()),
            "7c7b50366ada27df5c5bbf1519e0523fa92dfd7b2197abe488918e3ee4b1cd44"
        );
        assert_eq!(
            hex(lineage_root(&seed, 1).unwrap().as_slice()),
            "ab89538e361da6c46348c22a983be09ba3f078f7e4152c797d6857c89ecc3d0f"
        );
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn all_roots_restore_without_storage_and_separate_domains() {
        let prf = PrfOutput::from_bytes(&[27; 32]).unwrap();
        let other = PrfOutput::from_bytes(&[28; 32]).unwrap();
        let a = identity_roots(&prf, "a").unwrap();
        let restored = identity_roots(&prf, "a").unwrap();
        assert_eq!(a.identity, restored.identity);
        assert_eq!(a.passport_holder_seed, restored.passport_holder_seed);
        for different in [
            identity_roots(&prf, "b").unwrap(),
            identity_roots(&other, "a").unwrap(),
        ] {
            assert_ne!(a.identity, different.identity);
            assert_ne!(a.passport_holder_seed, different.passport_holder_seed);
        }
        let seed = lineage_seed(&prf, "a").unwrap();
        let branches = [
            a.identity.clone(),
            a.passport_holder_seed.clone(),
            device_seed(&prf, "a").unwrap(),
            seed.clone(),
            lineage_root(&seed, 1).unwrap(),
            lineage_root(&seed, 2).unwrap(),
            ring_key(&prf, "a").unwrap(),
            store_cipher(&prf, "a").unwrap().0,
        ];
        for (i, value) in branches.iter().enumerate() {
            for other in &branches[i + 1..] {
                assert_ne!(value, other);
            }
        }
        let signature = a.prove_possession(b"challenge").unwrap();
        crate::verify(
            &restored.public_key(),
            &restored.proof_transcript(b"challenge").unwrap(),
            &signature,
        )
        .unwrap();
        assert!(
            crate::verify(
                &restored.public_key(),
                &restored.proof_transcript(b"other").unwrap(),
                &signature
            )
            .is_err()
        );
        assert!(lineage_root(&seed, 0).is_err());
        for domain in ["", "bad\0domain", &"a".repeat(257)] {
            assert!(identity_roots(&prf, domain).is_err());
            assert!(vault_location(&prf, domain).is_err());
        }
    }
}

//! VLD0 operations on raw secrets. Crate-private: secrets never cross the public API.
//!
//! The semantics follow Veilid's VLD0 cryptosystem so that keys and signatures made here
//! are valid in Veilid: Ed25519ph with the context string `VLD0_SIGN` for signatures,
//! the Ed25519 → X25519 conversion for key agreement, HPKE (RFC 9180, DHKEM(X25519,
//! HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305) for sealing to a public key, BLAKE3 for
//! hashing. The implementation composes the upstream crates; no primitive is ours.

use crate::typed::{HashDigest, PublicKey, Signature, VLD0};
use crate::{Entropy, Error, Secret};
use ed25519_dalek::{Digest, Sha512, SigningKey, VerifyingKey};
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use rand_core::SeedableRng;
use zeroize::{Zeroize, Zeroizing};

const VLD0_DOMAIN_SIGN: &[u8] = b"VLD0_SIGN";
const HPKE_INFO: &[u8] = b"veilid-hpke/1VLD0";
const HPKE_HEADER: &[u8] = b"\x01VLD0";
pub(crate) fn sealed_root_bytes(version: u8) -> Result<usize, Error> {
    match version {
        1 => Ok(5 + 32 + 32 + 16),
        2 => Ok(5 + 32 + 64 + 16),
        _ => Err(Error::Encoding),
    }
}
pub(crate) fn validate_sealed_root(version: u8, length: usize) -> Result<(), Error> {
    if version == 3 {
        let plain = length.checked_sub(5 + 32 + 16).ok_or(Error::Encoding)?;
        if plain <= crate::MAX_CHECKPOINT_BYTES
            && ((plain >= 73 && (plain - 33) % 40 == 0) || (plain >= 105 && (plain - 65) % 40 == 0))
        {
            return Ok(());
        }
    } else if sealed_root_bytes(version)? == length {
        return Ok(());
    }
    Err(Error::Encoding)
}
const HPKE_ENC_LENGTH: usize = 32;

type Kem = hpke::kem::X25519HkdfSha256;
type Kdf = hpke::kdf::HkdfSha256;
type Aead = hpke::aead::ChaCha20Poly1305;

pub(crate) fn random_secret(rng: &mut impl Entropy) -> Result<Secret, Error> {
    let mut out = Zeroizing::new([0u8; 32]);
    rng.fill(out.as_mut())?;
    Ok(out)
}

/// The public key of an Ed25519 secret seed.
pub(crate) fn public_key(secret: &Secret) -> PublicKey {
    PublicKey::new(
        VLD0,
        SigningKey::from_bytes(secret).verifying_key().to_bytes(),
    )
}

fn prehash(data: &[u8]) -> Sha512 {
    let mut digest = Sha512::new();
    digest.update(data);
    digest
}

/// VLD0 `sign`: Ed25519ph over `data` with context `VLD0_SIGN`.
pub(crate) fn sign(secret: &Secret, data: &[u8]) -> Result<Signature, Error> {
    let signature = SigningKey::from_bytes(secret)
        .sign_prehashed(prehash(data), Some(VLD0_DOMAIN_SIGN))
        .map_err(|__cause| {
            crate::cause::emit(file!(), line!(), "Error::Crypto", Error::Crypto, &__cause)
        })?;
    Ok(Signature::new(VLD0, signature.to_bytes()))
}

fn verifying_key(key: &PublicKey) -> Result<VerifyingKey, Error> {
    if key.kind() != VLD0 {
        return Err(Error::UnsupportedKind);
    }
    let verifying = VerifyingKey::from_bytes(key.value()).map_err(|__cause| {
        crate::cause::emit(
            file!(),
            line!(),
            "Error::InvalidKey",
            Error::InvalidKey,
            &__cause,
        )
    })?;
    if verifying.is_weak() {
        return Err(Error::InvalidKey);
    }
    Ok(verifying)
}

/// VLD0 `verify` (strict): `Ok(())` only for a valid signature by `key` over `data`.
pub fn verify(key: &PublicKey, data: &[u8], signature: &Signature) -> Result<(), Error> {
    if signature.kind() != VLD0 {
        return Err(Error::UnsupportedKind);
    }
    let signature = ed25519_dalek::Signature::from_bytes(signature.value());
    verifying_key(key)?
        .verify_prehashed_strict(prehash(data), Some(VLD0_DOMAIN_SIGN), &signature)
        .map_err(|__cause| {
            crate::cause::emit(
                file!(),
                line!(),
                "Error::BadSignature",
                Error::BadSignature,
                &__cause,
            )
        })
}

/// Check that `key` is a usable VLD0 public key (on the curve, not weak).
pub fn validate_public_key(key: &PublicKey) -> Result<(), Error> {
    verifying_key(key).map(|_| ())
}

/// Plain Ed25519 strict verification, for signatures that other parties make without
/// the VLD0 context (for example `cvld` admission grants).
pub fn verify_ed25519(
    public_key: &[u8; 32],
    data: &[u8],
    signature: &[u8; 64],
) -> Result<(), Error> {
    let verifying = VerifyingKey::from_bytes(public_key).map_err(|__cause| {
        crate::cause::emit(
            file!(),
            line!(),
            "Error::InvalidKey",
            Error::InvalidKey,
            &__cause,
        )
    })?;
    if verifying.is_weak() {
        return Err(Error::InvalidKey);
    }
    verifying
        .verify_strict(data, &ed25519_dalek::Signature::from_bytes(signature))
        .map_err(|__cause| {
            crate::cause::emit(
                file!(),
                line!(),
                "Error::BadSignature",
                Error::BadSignature,
                &__cause,
            )
        })
}

/// VLD0 `generate_hash`: BLAKE3.
pub fn hash(data: &[u8]) -> HashDigest {
    HashDigest::new(VLD0, *blake3::hash(data).as_bytes())
}

pub(crate) fn x25519_public(key: &PublicKey) -> Result<[u8; 32], Error> {
    Ok(verifying_key(key)?.to_montgomery().to_bytes())
}

/// The X25519 secret an Ed25519 seed expands to: the raw first half of SHA-512(seed),
/// clamped by X25519 itself (as in Veilid; not the reduced scalar).
pub(crate) fn x25519_secret(secret: &Secret) -> Zeroizing<[u8; 32]> {
    let mut expanded: [u8; 64] = Sha512::new()
        .chain_update(secret.as_slice())
        .finalize()
        .into();
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&expanded[..32]);
    expanded.zeroize();
    out
}

/// Original VLD0 node DH: Ed25519 conversion, contributory X25519, then
/// BLAKE3("VLD0_CRYPT" || shared). Matches Veilid dd8e2cd's compute_dh.
/// Both the raw agreement and its hash stay inside custody and wipe on drop.
pub(crate) fn compute_dh(secret: &Secret, peer: &PublicKey) -> Result<Secret, Error> {
    let public = x25519_dalek::PublicKey::from(x25519_public(peer)?);
    let private = x25519_dalek::StaticSecret::from(*x25519_secret(secret));
    let shared = private.diffie_hellman(&public);
    if !shared.was_contributory() {
        return Err(Error::InvalidKey);
    }
    let mut hasher = Zeroizing::new(blake3::Hasher::new());
    hasher.update(b"VLD0_CRYPT");
    hasher.update(shared.as_bytes());
    let digest = Zeroizing::new(hasher.finalize());
    Ok(Zeroizing::new(*digest.as_bytes()))
}

/// Seal `plaintext` to the holder of `recipient` (HPKE base mode).
/// Veilid HPKE v1 output: `1 ‖ VLD0 ‖ enc ‖ ciphertext`.
pub(crate) fn seal_to(
    rng: &mut impl Entropy,
    recipient: &PublicKey,
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let recipient = <Kem as hpke::Kem>::PublicKey::from_bytes(&x25519_public(recipient)?).map_err(
        |__cause| {
            crate::cause::emit(
                file!(),
                line!(),
                "Error::InvalidKey",
                Error::InvalidKey,
                &__cause,
            )
        },
    )?;
    let (enc, ciphertext) = hpke::single_shot_seal_with_rng::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &recipient,
        HPKE_INFO,
        plaintext,
        associated_data,
        &mut rand_chacha::ChaCha20Rng::from_seed(*random_secret(rng)?),
    )
    .map_err(|__cause| {
        crate::cause::emit(file!(), line!(), "Error::Crypto", Error::Crypto, &__cause)
    })?;
    let enc = enc.to_bytes();
    let mut out = Vec::with_capacity(5 + HPKE_ENC_LENGTH + ciphertext.len());
    out.extend_from_slice(HPKE_HEADER);
    out.extend_from_slice(enc.as_slice());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a [`seal_to`] blob with the recipient's Ed25519 seed.
pub(crate) fn open(
    secret: &Secret,
    associated_data: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if sealed.len() < 5 + HPKE_ENC_LENGTH {
        return Err(Error::Encoding);
    }
    if &sealed[..5] != HPKE_HEADER {
        return Err(Error::UnsupportedKind);
    }
    let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&sealed[5..5 + HPKE_ENC_LENGTH])
        .map_err(|__cause| {
            crate::cause::emit(file!(), line!(), "Error::Open", Error::Open, &__cause)
        })?;
    let private = <Kem as hpke::Kem>::PrivateKey::from_bytes(x25519_secret(secret).as_slice())
        .map_err(|__cause| {
            crate::cause::emit(file!(), line!(), "Error::Crypto", Error::Crypto, &__cause)
        })?;
    hpke::single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &private,
        &enc,
        HPKE_INFO,
        &sealed[5 + HPKE_ENC_LENGTH..],
        associated_data,
    )
    .map(Zeroizing::new)
    .map_err(|__cause| crate::cause::emit(file!(), line!(), "Error::Open", Error::Open, &__cause))
}

/// Plain Ed25519 for owner formats (COSE/OpenMLS/cgrd) that do not use Ed25519ph.
pub(crate) fn sign_ed25519(secret: &Secret, data: &[u8]) -> [u8; 64] {
    use ed25519_dalek::Signer;
    SigningKey::from_bytes(secret).sign(data).to_bytes()
}

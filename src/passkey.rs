//! PRF-based wrapping/device derivation and private retained-root purpose derivation.
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
const HOLDER_SEAL_INFO: &[u8] = b"ckmg.wallet-holder-seal.v1\0";
const BALANCE_SEED_INFO: &[u8] = b"ckmg.wallet-balance-seed.v1\0";
const BALANCE_SEAL_INFO: &[u8] = b"ckmg.wallet-balance-seal.v1\0";
const DEVICE_INFO: &[u8] = b"ckmg.device-lineage-seed.v1\0";

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
/// The holder seed stays private. Wallet consumes a separately borrowed seed
/// capability; Keys owns no Wallet engine, session, or installed passport.
pub struct IdentityRoots {
    domain: String,
    identity: Secret,
    // Reserved for the upstream holder engine, never exposed as bytes or an RNG.
    passport_holder_seed: Secret,
    holder_sealing_key: Secret,
    balance_seed: Secret,
    balance_sealing_key: Secret,
}

impl IdentityRoots {
    pub(crate) fn retained(
        domain: &str,
        device: crate::PublicKey,
        common: &Secret,
    ) -> Result<Self, Error> {
        let _ = device;
        identity_roots(&PrfOutput(common.clone()), domain)
    }

    #[cfg(feature = "passport")]
    pub(crate) fn holder_seed(&self) -> HolderSeed<'_> {
        HolderSeed {
            seed: &self.passport_holder_seed,
            sealing_key: &self.holder_sealing_key,
            wallet_context: self.domain.as_bytes(),
        }
    }

    #[cfg(feature = "wallet-engine")]
    pub(crate) fn wallet_engine(&self) -> Result<cwlt_engine::Engine, Error> {
        let mut seed = Zeroizing::new(*self.balance_seed);
        let mut key = Zeroizing::new(*self.balance_sealing_key);
        cwlt_engine::Engine::from_seed_and_sealing_key(&mut seed, &mut key, self.domain.as_bytes())
            .map_err(|_| Error::Encoding)
    }

    /// Mint the one-shot account-key signer for exactly `digest`. Crate-private: only
    /// `Keys::sign_account_digest` calls it, after its ledger, admission and final
    /// recheck; the raw balance seed and sealing key never leave this type.
    #[cfg(feature = "wallet-engine")]
    pub(crate) fn account_signing(
        &self,
        digest: [u8; 32],
    ) -> Result<cwlt_engine::account_key::AccountSigning, Error> {
        let mut seed = Zeroizing::new(*self.balance_seed);
        let mut key = Zeroizing::new(*self.balance_sealing_key);
        cwlt_engine::account_key::AccountSigning::mint(
            &mut seed,
            &mut key,
            self.domain.as_bytes(),
            digest,
        )
        .map_err(|_| Error::Encoding)
    }

    /// Public identity verification key derived from the retained common random root.
    /// Independent of the passkey wrapping it and of device/lineage rotations.
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
        self.holder_sealing_key.zeroize();
        self.balance_seed.zeroize();
        self.balance_sealing_key.zeroize();
    }
}
crate::lineage::redacted!(IdentityRoots);

// Kept private for legacy vector compatibility. New identities always supply the
// retained random common root here, never an authenticator PRF. Existing labels
// stay byte-identical; the versioned custody envelope identifies the source.
fn identity_roots(prf: &PrfOutput, wallet_domain: &str) -> Result<IdentityRoots, Error> {
    let identity = expand(prf, IDENTITY_INFO, wallet_domain)?;
    let passport_holder_seed = expand(prf, HOLDER_INFO, wallet_domain)?;
    let holder_sealing_key = expand(prf, HOLDER_SEAL_INFO, wallet_domain)?;
    let balance_seed = expand(prf, BALANCE_SEED_INFO, wallet_domain)?;
    let balance_sealing_key = expand(prf, BALANCE_SEAL_INFO, wallet_domain)?;
    Ok(IdentityRoots {
        domain: wallet_domain.into(),
        identity,
        passport_holder_seed,
        holder_sealing_key,
        balance_seed,
        balance_sealing_key,
    })
}

pub(crate) fn device_seed(prf: &PrfOutput, community: &str) -> Result<Secret, Error> {
    expand(prf, DEVICE_INFO, community)
}

/// Original device public key for binding this unlocked passkey session to a
/// live server observation. This does not grant authority or expose custody.
pub fn device_public_key(prf: &PrfOutput, community: &str) -> Result<crate::PublicKey, Error> {
    Ok(crate::vld0::public_key(&device_seed(prf, community)?))
}

/// The device key's session signature (`DeviceFormat::DeviceSession`, its fixed tag
/// prepended) straight from the unlocked passkey session. A device-key member restarted after
/// activation opens its community sessions with it BEFORE its Keys are live: the lease that
/// opens them needs a session. Same key and tag rule as `UnenrolledCreation::sign_device`;
/// only this one purpose, and the device seed never leaves.
pub fn sign_device_session(
    prf: &PrfOutput,
    community: &str,
    payload: &[u8],
) -> Result<[u8; 64], Error> {
    crate::format::sign_payload(
        &device_seed(prf, community)?,
        crate::DeviceFormat::DeviceSession,
        crate::SigningClass::Opening,
        Some(community),
        payload,
    )
}

/// The wallet device key's birth signature (`DeviceFormat::WalletBirthDevice` or
/// `WalletBirthPassport`, the tag prepended) from the unlocked wallet opening: a registration
/// restarted after activation binds its wallet device from the unlocked session. Opening class,
/// and ckmg refuses any scope but the wallet's; every other format is refused here.
pub fn sign_device_birth(
    prf: &PrfOutput,
    community: &str,
    format: crate::DeviceFormat,
    payload: &[u8],
) -> Result<[u8; 64], Error> {
    if !matches!(
        format,
        crate::DeviceFormat::WalletBirthDevice | crate::DeviceFormat::WalletBirthPassport
    ) {
        return Err(Error::Unauthorized);
    }
    crate::format::sign_payload(
        &device_seed(prf, community)?,
        format,
        crate::SigningClass::Opening,
        Some(community),
        payload,
    )
}

/// The opening's stamp salt for a device-key member restarted during its first publication:
/// it rebuilds its genesis stamp salt bit-exact (`SHA-256(Ed25519(device, salt tag ||
/// payload))`, deterministic). The signature never leaves ckmg; no signer accepts the tag.
pub fn device_salt(prf: &PrfOutput, community: &str, payload: &[u8]) -> Result<[u8; 32], Error> {
    crate::format::device_salt(&device_seed(prf, community)?, payload)
}

/// The device key's join signature (`DeviceFormat::DeviceJoin`) from the opening, ONLY for a
/// device restoring a member whose join the community already applied. Crate-private: the
/// only way in is `InitialCheckpointProvenance::sign_device_join_restored`, whose receiver
/// (minted only by ckmg from the PRF-authenticated original initial ACK) is the capability.
/// The community answers such a stamp-less join only as the re-confirmation of that applied
/// join (same key, same seed); any new join still needs a fresh wallet stamp.
pub(crate) fn sign_device_join_restored(
    prf: &PrfOutput,
    community: &str,
    payload: &[u8],
) -> Result<[u8; 64], Error> {
    crate::format::sign_payload(
        &device_seed(prf, community)?,
        crate::DeviceFormat::DeviceJoin,
        crate::SigningClass::Provenance,
        Some(community),
        payload,
    )
}

#[cfg(feature = "profile-envelope")]
pub(crate) fn profile_storage_key(common: &Secret, community: &str) -> Result<Secret, Error> {
    expand(
        &PrfOutput(common.clone()),
        b"ckmg.profile-envelope-storage.v2\0",
        community,
    )
}

/// Dedicated immutable common-root recipient; never reuse balance or device keys.
#[cfg(feature = "wallet-engine")]
pub(crate) fn with_record_recipient<T>(
    common: &Secret,
    community: &str,
    checked_at: u64,
    consume: impl for<'key> FnOnce(cwlt_engine::RecordRecipient<'key>) -> T,
) -> Result<T, Error> {
    use sha2::Digest;
    let mut seed = expand(
        &PrfOutput(common.clone()),
        b"ckmg.record-witness-recipient.v1\0",
        community,
    )?;
    // Original AccountLedger uses SHA-256 of its authenticated community ID.
    let coordinate = Sha256::digest(community.as_bytes()).into();
    let recipient = cwlt_engine::RecordRecipient::from_seed(&mut seed, coordinate, checked_at)
        .map_err(|_| Error::Encoding)?;
    Ok(consume(recipient))
}

/// One-use holder-seed capability borrowed from freshly authorized Keys.
/// No byte/RNG getter, callback, Clone, Debug or serialization is implemented.
/// Wallet consumes it to initialize the maintained Pseudonyms engine; the engine
/// and every subsequent holder operation belong to Wallet, never Keys.
#[cfg(feature = "passport")]
pub struct HolderSeed<'key> {
    seed: &'key Secret,
    sealing_key: &'key Secret,
    wallet_context: &'key [u8],
}

#[cfg(feature = "passport")]
impl HolderSeed<'_> {
    /// Initialize the existing opaque holder, consuming the capability without
    /// exposing the seed. This produces no credential or membership authority.
    /// Wallet must load its authenticated checkpoint and retain lifecycle custody.
    pub fn into_passport_holder(self) -> Result<cpsd::OpaqueHolder, Error> {
        let mut seed = Zeroizing::new(**self.seed);
        let mut key = Zeroizing::new(**self.sealing_key);
        cpsd::OpaqueHolder::from_seed_and_sealing_key(&mut seed, &mut key, self.wallet_context)
            .map_err(|_| Error::Encoding)
    }

    /// Open the original CPSD sealed holder under freshly authorized wallet custody.
    /// The immutable sealing key is selected only here; neither it nor a plaintext
    /// codec escapes. Wallet must still reconcile its actual compound checkpoint.
    pub fn open_passport_holder(
        self,
        sealed: &cpsd::SealedHolder,
    ) -> Result<cpsd::OpaqueHolder, Error> {
        self.into_passport_holder()?
            .restored(sealed)
            .map_err(|_| Error::Open)
    }
}

/// Opaque wrapping capability for storage adapters. Uses an independent HKDF label
/// from key-ring encryption, so it cannot decrypt ckmg's custody checkpoints.
pub struct StoreCipher(Secret);

impl StoreCipher {
    /// Only Keys custody and its delegation construct a common-root cipher.
    pub(crate) fn from_secret(secret: Secret) -> Self {
        Self(secret)
    }
    /// The wrapping key for the delegation's own sealed form; never public.
    pub(crate) fn secret(&self) -> &Secret {
        &self.0
    }
    #[cfg(feature = "profile-envelope")]
    pub(crate) fn envelope_legacy_key(&self) -> &[u8; 32] {
        &self.0
    }
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

/// Compound wrapping follows the current random root, never the stable identity
/// seed or an individual authenticator. Only the Keys custody owner calls this.
pub(crate) fn common_store_cipher(root: &Secret, community: &str) -> Result<StoreCipher, Error> {
    Ok(StoreCipher(expand(
        &PrfOutput(root.clone()),
        b"ckmg.compound-store-root.v1\0",
        community,
    )?))
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

/// Read-only custody for this passkey's original DFLT(1) root record. The
/// derivations are identical to `native_passkey_record`, on native and Wasm.
/// This lends no writer, root, member-purpose key or current authority.
/// The reader cannot outlive the consumed passkey unlock retained by Vault.
///
/// ```compile_fail
/// let prf = ckmg::passkey::PrfOutput::from_bytes(&[7; 32]).unwrap();
/// let reader = ckmg::passkey::passkey_record_reader(&prf, "garden").unwrap();
/// drop(prf);
/// let _ = reader.owner();
/// ```
pub struct PasskeyRecordReader<'prf> {
    owner: crate::PublicKey,
    read: Secret,
    _unlock: std::marker::PhantomData<&'prf PrfOutput>,
}
impl PasskeyRecordReader<'_> {
    pub(crate) fn into_session(self) -> PasskeyRecordReader<'static> {
        PasskeyRecordReader {
            owner: self.owner,
            read: self.read,
            _unlock: std::marker::PhantomData,
        }
    }

    /// Public owner used with the fixed original DFLT(1) schema.
    pub fn owner(&self) -> crate::PublicKey {
        self.owner
    }

    /// Lend only the original read cipher, synchronously. The adapter must check
    /// the original descriptor and value signatures before calling this method.
    pub fn with_cipher<T>(
        &self,
        read: impl for<'key> FnOnce(crate::Vld0RecordCipher<'key>) -> T,
    ) -> T {
        read(crate::Vld0RecordCipher { secret: &self.read })
    }
}
impl std::fmt::Debug for PasskeyRecordReader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasskeyRecordReader([redacted])")
    }
}

/// Derive only the existing passkey-root record read capability. There is no
/// arbitrary purpose selector and no authority inference from record absence.
pub fn passkey_record_reader<'prf>(
    prf: &'prf PrfOutput,
    community: &str,
) -> Result<PasskeyRecordReader<'prf>, Error> {
    let (owner, read) = record_material(prf, community)?;
    Ok(PasskeyRecordReader {
        owner: crate::vld0::public_key(&owner),
        read,
        _unlock: std::marker::PhantomData,
    })
}

/// Write custody for one passkey-scoped DFLT(1) record (the wallet membership index): the
/// record owner's signer and read cipher, derived exactly like [`passkey_record_reader`].
/// Lent only synchronously; it exposes no secret and grants no membership or G3 authority.
pub struct PasskeyRecordWriter {
    owner: Secret,
    read: Secret,
}
impl PasskeyRecordWriter {
    /// Public owner used with the fixed original DFLT(1) schema.
    pub fn owner(&self) -> crate::PublicKey {
        crate::vld0::public_key(&self.owner)
    }
    /// Lend the record's signer and cipher synchronously; owned signed/encrypted bytes may
    /// leave the callback, never custody.
    pub fn with_record<T>(
        &self,
        use_record: impl for<'key> FnOnce(crate::Vld0Signer<'key>, crate::Vld0RecordCipher<'key>) -> T,
    ) -> T {
        use_record(
            crate::keys::vld0_signer(&self.owner),
            crate::Vld0RecordCipher { secret: &self.read },
        )
    }
}
impl std::fmt::Debug for PasskeyRecordWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasskeyRecordWriter([redacted])")
    }
}

/// Derive write custody for the passkey-scoped record named `scope`. Same derivations as
/// [`passkey_record_reader`] and `native_passkey_record`; absence never creates identity.
pub fn passkey_record_writer(prf: &PrfOutput, scope: &str) -> Result<PasskeyRecordWriter, Error> {
    let (owner, read) = record_material(prf, scope)?;
    Ok(PasskeyRecordWriter { owner, read })
}

pub(crate) fn record_material(prf: &PrfOutput, community: &str) -> Result<(Secret, Secret), Error> {
    Ok((
        expand(prf, b"passkey-record-owner-v1\0", community)?,
        expand(prf, b"passkey-record-read-v1\0", community)?,
    ))
}

/// Derive one passkey's private root-record initializer before unlocking custody.
/// Core derives its canonical DFLT(1) key; the local checkpoint locator is unrelated.
/// This grants no membership or G3 authority, and absence never creates an identity.
#[cfg(all(feature = "native-records", not(target_arch = "wasm32")))]
pub fn native_passkey_record(
    prf: &PrfOutput,
    community: &str,
) -> Result<crate::NativeRecordInitializer, Error> {
    let (owner, read) = record_material(prf, community)?;
    let schema = crate::NativeRecordSchema::dflt(1).map_err(|_| Error::Encoding)?;
    Ok(crate::native_record::owner(schema, &owner, &read))
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
        .map_err(|_| Error::Crypto)?;
    Ok(out)
}

#[cfg(test)]
#[path = "../tests/unit/passkey.rs"]
mod tests;

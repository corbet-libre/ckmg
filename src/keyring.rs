//! The key ring: member root → device → purpose keys.
//!
//! - The **device key** is generated on the device and never leaves it.
//! - The **member root** is created on the member's first device and reaches another
//!   device only through pairing: sealed to that device's public key (HPKE), from a live
//!   device. There is no password- or file-based export and no recovery path.
//! - **Purpose keys** derive one-way from the root (member scope) or the device key
//!   (device scope) and are the only secrets that may be handed out.
//!
//! At rest the ring is sealed under a [`RingKey`] that only the passkey PRF yields
//! ([`crate::passkey::ring_key`]); the caller (`cvlt`) stores the sealed blob in its
//! encrypted `cwst` drawer. `ckmg` does no I/O and holds no policy.

use crate::purpose::{DelegatedKey, DelegatedSecret, Delegation, Purpose, Scope};
use crate::typed::{BEST_KIND, CryptoKind, PublicKey, Signature, VLD0};
use crate::{Error, Secret, vld0};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::Zeroizing;

const STORED_HEADER: &[u8] = b"ckmg.keyring.v1\0";
const SEALED_HEADER: &[u8] = b"ckmg.keyring.sealed.v1\0";
const NONCE_LENGTH: usize = 24;
const PAIRING_AAD: &[u8] = b"ckmg.pairing.root.v1\0";

/// Which key an operation uses.
#[derive(Clone, Copy, Debug)]
pub enum KeyRef<'a> {
    /// The member root.
    Root,
    /// This device's key.
    Device,
    /// A purpose key derived from the root or the device key.
    Purpose(&'a Purpose),
}

/// The device's keys. Secrets never leave this value except as purpose keys
/// ([`KeyRing::delegate`]) or as a root sealed to another device
/// ([`KeyRing::seal_root_for_device`]).
pub struct KeyRing {
    kind: CryptoKind,
    device: Secret,
    root: Option<Secret>,
}

impl std::fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRing")
            .field("kind", &self.kind)
            .field("device", &self.device_public())
            .field("root", &self.root_public())
            .finish()
    }
}

impl KeyRing {
    /// A new ring with a fresh device key and no root (a device before it is paired, or
    /// before it creates a new member).
    pub fn generate() -> Result<Self, Error> {
        Ok(Self {
            kind: BEST_KIND,
            device: vld0::random_secret()?,
            root: None,
        })
    }

    /// The cryptosystem of the ring's keys.
    pub fn kind(&self) -> CryptoKind {
        self.kind
    }

    /// This device's public key.
    pub fn device_public(&self) -> PublicKey {
        vld0::public_key(&self.device)
    }

    /// Whether this device holds the member root.
    pub fn has_root(&self) -> bool {
        self.root.is_some()
    }

    /// The member root's public key, if this device holds the root.
    pub fn root_public(&self) -> Option<PublicKey> {
        self.root.as_ref().map(vld0::public_key)
    }

    /// Create the member root on a member's first device.
    pub fn create_root(&mut self) -> Result<PublicKey, Error> {
        if self.root.is_some() {
            return Err(Error::RootExists);
        }
        let root = vld0::random_secret()?;
        let public = vld0::public_key(&root);
        self.root = Some(root);
        Ok(public)
    }

    fn root_secret(&self) -> Result<&Secret, Error> {
        self.root.as_ref().ok_or(Error::NoRoot)
    }

    fn purpose_parent(&self, purpose: &Purpose) -> Result<&Secret, Error> {
        match purpose.scope() {
            Scope::Member => self.root_secret(),
            Scope::Device => Ok(&self.device),
        }
    }

    fn purpose_signing_secret(&self, purpose: &Purpose) -> Result<Secret, Error> {
        Ok(vld0::derive_child(
            purpose.signing_context(),
            self.purpose_parent(purpose)?,
            purpose.label(),
            purpose.version(),
        ))
    }

    fn secret(&self, key: KeyRef<'_>) -> Result<Zeroizing<[u8; 32]>, Error> {
        match key {
            KeyRef::Root => Ok(self.root_secret()?.clone()),
            KeyRef::Device => Ok(self.device.clone()),
            KeyRef::Purpose(purpose) => self.purpose_signing_secret(purpose),
        }
    }

    /// The public key of `key`.
    pub fn public_key(&self, key: KeyRef<'_>) -> Result<PublicKey, Error> {
        Ok(vld0::public_key(&self.secret(key)?))
    }

    /// Sign `data` with `key` (VLD0). Callers put their own domain label into `data`.
    pub fn sign(&self, key: KeyRef<'_>, data: &[u8]) -> Result<Signature, Error> {
        vld0::sign(&self.secret(key)?, data)
    }

    /// Open a blob sealed with [`crate::seal_to`] to `key`'s public key.
    pub fn open(
        &self,
        key: KeyRef<'_>,
        associated_data: &[u8],
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        vld0::open(&self.secret(key)?, associated_data, sealed)
    }

    /// Hand a purpose signing key to the engine that needs it. Only purpose keys can be
    /// delegated; root and device secrets have no export.
    pub fn delegate(&self, purpose: &Purpose) -> Result<DelegatedKey, Error> {
        let secret = self.purpose_signing_secret(purpose)?;
        Ok(DelegatedKey {
            purpose: purpose.clone(),
            public_key: vld0::public_key(&secret),
            secret,
        })
    }

    /// Hand a symmetric purpose secret (for example a record encryption key) to the
    /// engine that needs it.
    pub fn delegate_secret(&self, purpose: &Purpose) -> Result<DelegatedSecret, Error> {
        Ok(DelegatedSecret {
            purpose: purpose.clone(),
            secret: vld0::derive_child(
                purpose.secret_context(),
                self.purpose_parent(purpose)?,
                purpose.label(),
                purpose.version(),
            ),
        })
    }

    /// Certify a purpose key: its parent (root or device key) signs that the key serves
    /// the purpose between `issued_at` and `expires_at` (Unix seconds).
    pub fn certify(
        &self,
        purpose: &Purpose,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Delegation, Error> {
        if issued_at >= expires_at {
            return Err(Error::Expired);
        }
        let parent_secret = self.purpose_parent(purpose)?;
        let parent = vld0::public_key(parent_secret);
        let public_key = vld0::public_key(&self.purpose_signing_secret(purpose)?);
        let bytes = Delegation::signed_bytes(purpose, &public_key, &parent, issued_at, expires_at);
        Ok(Delegation {
            purpose: purpose.clone(),
            public_key,
            parent,
            issued_at,
            expires_at,
            signature: vld0::sign(parent_secret, &bytes)?,
        })
    }

    /// Pairing: seal the member root to a new device's public key. `context` binds the
    /// blob to one pairing session; the receiving device must pass the same context.
    ///
    /// This is not a backup: the result opens only with that device's key, which never
    /// leaves that device. `cvlt` calls this only from a live device, after the member
    /// confirmed the pairing.
    pub fn seal_root_for_device(
        &self,
        recipient_device: &PublicKey,
        context: &[u8],
    ) -> Result<Vec<u8>, Error> {
        vld0::validate_public_key(recipient_device)?;
        if *recipient_device == self.device_public() {
            return Err(Error::InvalidKey);
        }
        let root = self.root_secret()?;
        vld0::seal_to(recipient_device, &pairing_aad(context), root.as_slice())
    }

    /// Pairing, receiving side: accept a root sealed to this device. `expected_root` is
    /// the root public key the member confirmed; any other root is rejected. Replaces a
    /// root this device already holds (after a rotation, see [`KeyRing::rotate_root`]).
    pub fn import_root(
        &mut self,
        sealed: &[u8],
        context: &[u8],
        expected_root: &PublicKey,
    ) -> Result<(), Error> {
        let plaintext = vld0::open(&self.device, &pairing_aad(context), sealed)?;
        let bytes: [u8; 32] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| Error::Encoding)?;
        let root = Zeroizing::new(bytes);
        if vld0::public_key(&root) != *expected_root {
            return Err(Error::InvalidKey);
        }
        self.root = Some(root);
        Ok(())
    }

    /// Replace the member root (after a device removal). `succession` builds the
    /// statement announcing the new root; the **old** root signs it, then the new root
    /// takes its place. Returns the new root's public key and the old root's signature.
    /// Save the ring and seal the new root to every remaining device afterwards.
    pub fn rotate_root(
        &mut self,
        succession: impl FnOnce(&PublicKey) -> Vec<u8>,
    ) -> Result<(PublicKey, Signature), Error> {
        let old = self.root_secret()?;
        let new = vld0::random_secret()?;
        let new_public = vld0::public_key(&new);
        let signature = vld0::sign(old, &succession(&new_public))?;
        self.root = Some(new);
        Ok((new_public, signature))
    }

    /// Migration hook: move the ring to another cryptosystem. Only VLD0 exists today, so
    /// this succeeds only as a no-op. A future kind (for example Veilid's VLD1) is added
    /// here: the device key is regenerated, purpose keys re-derive on first use, and
    /// `cvlt` re-certifies the device in the member's lineage.
    pub fn migrate(&mut self, target: CryptoKind) -> Result<(), Error> {
        if target == self.kind {
            return Ok(());
        }
        Err(Error::UnsupportedKind)
    }

    /// Serialize the ring (secrets included) for the vault's own encrypted storage.
    fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(STORED_HEADER.len() + 4 + 1 + 64));
        out.extend_from_slice(STORED_HEADER);
        out.extend_from_slice(self.kind.bytes());
        match &self.root {
            Some(root) => {
                out.push(1);
                out.extend_from_slice(self.device.as_slice());
                out.extend_from_slice(root.as_slice());
            }
            None => {
                out.push(0);
                out.extend_from_slice(self.device.as_slice());
            }
        }
        out
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let rest = bytes.strip_prefix(STORED_HEADER).ok_or(Error::Encoding)?;
        if rest.len() < 5 {
            return Err(Error::Encoding);
        }
        let kind = CryptoKind(rest[..4].try_into().map_err(|_| Error::Encoding)?);
        if kind != VLD0 {
            return Err(Error::UnsupportedKind);
        }
        let secret = |slice: &[u8]| -> Result<Secret, Error> {
            let array: [u8; 32] = slice.try_into().map_err(|_| Error::Encoding)?;
            Ok(Zeroizing::new(array))
        };
        let body = &rest[5..];
        let (device, root) = match (rest[4], body.len()) {
            (0, 32) => (secret(body)?, None),
            (1, 64) => (secret(&body[..32])?, Some(secret(&body[32..])?)),
            _ => return Err(Error::Encoding),
        };
        Ok(Self { kind, device, root })
    }

    /// Seal the ring for storage at rest (XChaCha20-Poly1305 under `key`).
    pub fn seal_at_rest(&self, key: &RingKey) -> Result<Vec<u8>, Error> {
        let mut nonce = [0u8; NONCE_LENGTH];
        getrandom::fill(&mut nonce).map_err(|_| Error::Randomness)?;
        let plaintext = self.to_bytes();
        let ciphertext = XChaCha20Poly1305::new_from_slice(key.0.as_slice())
            .map_err(|_| Error::Crypto)?
            .encrypt(
                &XNonce::try_from(&nonce[..]).map_err(|_| Error::Crypto)?,
                Payload {
                    msg: &plaintext,
                    aad: SEALED_HEADER,
                },
            )
            .map_err(|_| Error::Crypto)?;
        let mut out = Vec::with_capacity(SEALED_HEADER.len() + NONCE_LENGTH + ciphertext.len());
        out.extend_from_slice(SEALED_HEADER);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Open a ring sealed with [`KeyRing::seal_at_rest`].
    pub fn open_at_rest(sealed: &[u8], key: &RingKey) -> Result<Self, Error> {
        let rest = sealed.strip_prefix(SEALED_HEADER).ok_or(Error::Encoding)?;
        if rest.len() < NONCE_LENGTH {
            return Err(Error::Encoding);
        }
        let (nonce, ciphertext) = rest.split_at(NONCE_LENGTH);
        let plaintext = Zeroizing::new(
            XChaCha20Poly1305::new_from_slice(key.0.as_slice())
                .map_err(|_| Error::Crypto)?
                .decrypt(
                    &XNonce::try_from(nonce).map_err(|_| Error::Encoding)?,
                    Payload {
                        msg: ciphertext,
                        aad: SEALED_HEADER,
                    },
                )
                .map_err(|_| Error::Open)?,
        );
        Self::from_bytes(&plaintext)
    }
}

/// The key that seals a [`KeyRing`] at rest. Obtained only from the passkey PRF
/// ([`crate::passkey::ring_key`]); wiped on drop.
pub struct RingKey(pub(crate) Secret);

impl std::fmt::Debug for RingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RingKey([redacted])")
    }
}

fn pairing_aad(context: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PAIRING_AAD.len() + context.len());
    out.extend_from_slice(PAIRING_AAD);
    out.extend_from_slice(context);
    out
}

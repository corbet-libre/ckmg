//! Purpose keys: narrowly scoped keys that may leave the vault.
//!
//! A purpose key serves exactly one purpose (one DHT record writer, one conversation, one
//! onion address). It is derived one-way from the member root or the device key, so
//! handing it to an engine (Veilid, OpenMLS, Arti) never exposes its parent, and
//! compromising it affects only that purpose. Rotating it means bumping its version.

use crate::typed::{PublicKey, Signature};
use crate::{Error, vld0};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Maximum length of a purpose label.
pub const MAX_LABEL_BYTES: usize = 64;

/// Which parent a purpose key derives from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Scope {
    /// Derived from the member root: identical on every device of the member (for
    /// example the key that encrypts the member's own records).
    Member,
    /// Derived from this device's key: exists on this device only (for example this
    /// device's MLS signature key or onion service key).
    Device,
}

impl Scope {
    fn code(self) -> &'static str {
        match self {
            Scope::Member => "member",
            Scope::Device => "device",
        }
    }
}

/// A purpose: scope, label and version. The label is ASCII letters, digits, `.`, `-`,
/// `_` and `:` (so a base64url record key fits), for example `mls.signature` or
/// `cdht.writer:<record>`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Purpose {
    scope: Scope,
    label: String,
    version: u32,
}

impl Purpose {
    /// A validated purpose.
    pub fn new(scope: Scope, label: &str, version: u32) -> Result<Self, Error> {
        if label.is_empty()
            || label.len() > MAX_LABEL_BYTES
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-:".contains(&b))
        {
            return Err(Error::InvalidPurpose);
        }
        Ok(Self {
            scope,
            label: label.to_owned(),
            version,
        })
    }

    /// The same purpose with the next version (rotation).
    pub fn next_version(&self) -> Result<Self, Error> {
        Ok(Self {
            scope: self.scope,
            label: self.label.clone(),
            version: self.version.checked_add(1).ok_or(Error::InvalidPurpose)?,
        })
    }

    /// Scope.
    pub fn scope(&self) -> Scope {
        self.scope
    }
    /// Label.
    pub fn label(&self) -> &str {
        &self.label
    }
    /// Version.
    pub fn version(&self) -> u32 {
        self.version
    }

    pub(crate) fn signing_context(&self) -> &'static str {
        match self.scope {
            Scope::Member => "ckmg 2026-09 member purpose signing key v1",
            Scope::Device => "ckmg 2026-09 device purpose signing key v1",
        }
    }

    pub(crate) fn secret_context(&self) -> &'static str {
        match self.scope {
            Scope::Member => "ckmg 2026-09 member purpose secret v1",
            Scope::Device => "ckmg 2026-09 device purpose secret v1",
        }
    }
}

/// A purpose signing key handed out of the vault. The seed is wiped on drop.
pub struct DelegatedKey {
    /// What the key is for.
    pub purpose: Purpose,
    /// Its public key.
    pub public_key: PublicKey,
    /// The Ed25519 seed (VLD0 secret key) for the engine that needs it.
    pub secret: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for DelegatedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DelegatedKey")
            .field("purpose", &self.purpose)
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

/// A symmetric purpose secret handed out of the vault (for example a record encryption
/// key). Wiped on drop.
pub struct DelegatedSecret {
    /// What the secret is for.
    pub purpose: Purpose,
    /// 32 secret bytes.
    pub secret: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for DelegatedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DelegatedSecret")
            .field("purpose", &self.purpose)
            .finish_non_exhaustive()
    }
}

/// A signed statement by the parent key (root for member scope, device key for device
/// scope) that `public_key` serves `purpose` until `expires_at`. Lets others check that
/// a delegated key belongs to its parent without ever seeing the parent's secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Delegation {
    /// What the key is for.
    pub purpose: Purpose,
    /// The delegated public key.
    pub public_key: PublicKey,
    /// The parent public key that signed.
    pub parent: PublicKey,
    /// Unix seconds from which the delegation is valid.
    pub issued_at: u64,
    /// Unix seconds at which the delegation expires.
    pub expires_at: u64,
    /// Parent's signature over [`Delegation::signed_bytes`].
    pub signature: Signature,
}

impl Delegation {
    /// The exact bytes the parent signs.
    pub fn signed_bytes(
        purpose: &Purpose,
        public_key: &PublicKey,
        parent: &PublicKey,
        issued_at: u64,
        expires_at: u64,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(128 + purpose.label.len());
        out.extend_from_slice(b"ckmg.delegation.v1\0");
        out.extend_from_slice(purpose.scope.code().as_bytes());
        out.push(0);
        out.extend_from_slice(&(purpose.label.len() as u32).to_le_bytes());
        out.extend_from_slice(purpose.label.as_bytes());
        out.extend_from_slice(&purpose.version.to_le_bytes());
        out.extend_from_slice(&public_key.to_typed_bytes());
        out.extend_from_slice(&parent.to_typed_bytes());
        out.extend_from_slice(&issued_at.to_le_bytes());
        out.extend_from_slice(&expires_at.to_le_bytes());
        out
    }

    /// Verify the parent's signature and the validity window at `now` (Unix seconds).
    /// The caller decides whether `parent` is a key it trusts.
    pub fn verify(&self, now: u64) -> Result<(), Error> {
        if self.issued_at >= self.expires_at || now < self.issued_at || now >= self.expires_at {
            return Err(Error::Expired);
        }
        vld0::verify(
            &self.parent,
            &Self::signed_bytes(
                &self.purpose,
                &self.public_key,
                &self.parent,
                self.issued_at,
                self.expires_at,
            ),
            &self.signature,
        )
    }
}

//! Passkeys: the top unlock factor of the vault and the member's login signature.
//!
//! - **Unlock:** the WebAuthn PRF extension returns a secret that only the authenticator
//!   can produce for this credential. [`store_password`] turns it (HKDF-SHA256) into the
//!   password that protects the `cwst` device encryption key.
//! - **Login:** the authenticator signs a login challenge from `cvld` (a WebAuthn
//!   assertion). The vault only produces the [`Assertion`]; the facade sends it and `cpky`
//!   verifies it on the server.
//! - **Registration:** on a member's first device and during pairing (rules in `cvlt`).
//!
//! WebAuthn works only in window contexts, never in workers; the browser half
//! ([`browser`]) therefore runs in the vault's own cross-origin iframe. Everything in
//! this module outside [`browser`] is plain data and pure functions, usable and tested
//! on every target.

use crate::{Error, RingKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub mod browser;

/// COSE algorithm identifiers offered at registration, in order of preference:
/// EdDSA, ES256, RS256.
pub const COSE_ALGORITHMS: [i32; 3] = [-8, -7, -257];

const HKDF_SALT: &[u8] = b"ckmg.passkey-prf.v1";
const STORE_PASSWORD_INFO: &[u8] = b"ckmg.cwst-password.v1\0";
const RING_KEY_INFO: &[u8] = b"ckmg.keyring-key.v1\0";

/// The PRF input ("salt") the vault evaluates for store unlock. Fixed, so every login on
/// every authenticator holding the credential yields the same secret.
pub fn unlock_prf_input() -> [u8; 32] {
    blake3::derive_key(
        "ckmg 2026-09 passkey PRF input for vault store unlock v1",
        b"",
    )
}

/// A PRF result from the authenticator. Wiped on drop.
pub struct PrfOutput(Zeroizing<[u8; 32]>);

impl PrfOutput {
    /// Wrap the 32-byte `results.first` value of the PRF extension.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let array: [u8; 32] = bytes.try_into().map_err(|_| Error::Encoding)?;
        Ok(Self(Zeroizing::new(array)))
    }
}

impl std::fmt::Debug for PrfOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrfOutput([redacted])")
    }
}

/// Derive the `cwst` store password from the PRF output. `store` names the store (one
/// per community vault), so one passkey can unlock several stores without sharing a
/// password between them.
pub fn store_password(prf: &PrfOutput, store: &str) -> Result<Zeroizing<[u8; 32]>, Error> {
    expand(prf, STORE_PASSWORD_INFO, store)
}

/// Derive the key that seals the [`KeyRing`](crate::KeyRing) at rest. Independent of the
/// store password (different HKDF info), so the ring stays sealed even to code that can
/// read the store.
pub fn ring_key(prf: &PrfOutput, store: &str) -> Result<RingKey, Error> {
    Ok(RingKey(expand(prf, RING_KEY_INFO, store)?))
}

fn expand(prf: &PrfOutput, label: &[u8], store: &str) -> Result<Zeroizing<[u8; 32]>, Error> {
    if store.is_empty() || store.len() > 256 {
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

/// Relying party (the community's base domain).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RelyingParty {
    /// RP ID, for example `example.org`; the vault iframe on `vault.example.org` may use it.
    pub id: String,
    /// Human-readable name.
    pub name: String,
}

/// Registration request: create a discoverable, user-verified passkey with PRF.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRequest {
    /// Relying party.
    pub rp: RelyingParty,
    /// Opaque user handle (random, never the member id in clear).
    pub user_id: Vec<u8>,
    /// Account name shown by the authenticator.
    pub user_name: String,
    /// Display name shown by the authenticator.
    pub user_display_name: String,
    /// Server challenge (from `cvld`/`cpky`).
    pub challenge: Vec<u8>,
    /// Credentials the authenticator must not already hold.
    pub exclude_credentials: Vec<Vec<u8>>,
    /// Timeout in milliseconds.
    pub timeout_ms: u32,
}

/// Login request: sign `challenge` with one of `allow_credentials` (empty: any
/// discoverable credential for the RP) and evaluate the unlock PRF.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LoginRequest {
    /// RP ID.
    pub rp_id: String,
    /// Server challenge (from `cvld`/`cpky`).
    pub challenge: Vec<u8>,
    /// Acceptable credential ids.
    pub allow_credentials: Vec<Vec<u8>>,
    /// Timeout in milliseconds.
    pub timeout_ms: u32,
}

/// A new credential, for `cpky` to verify and store on the server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Registration {
    /// Credential id (`rawId`).
    pub credential_id: Vec<u8>,
    /// `response.clientDataJSON`.
    pub client_data_json: Vec<u8>,
    /// `response.attestationObject`.
    pub attestation_object: Vec<u8>,
    /// Whether the authenticator reported PRF support.
    pub prf_enabled: bool,
}

/// A login signature (WebAuthn assertion), for `cpky` to verify.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Assertion {
    /// Credential id (`rawId`).
    pub credential_id: Vec<u8>,
    /// `response.clientDataJSON`.
    pub client_data_json: Vec<u8>,
    /// `response.authenticatorData`.
    pub authenticator_data: Vec<u8>,
    /// `response.signature`.
    pub signature: Vec<u8>,
    /// `response.userHandle`, when the authenticator returned one.
    pub user_handle: Option<Vec<u8>>,
}

impl RegistrationRequest {
    /// Basic shape checks before calling the authenticator.
    pub fn validate(&self) -> Result<(), Error> {
        if self.rp.id.is_empty()
            || self.user_id.is_empty()
            || self.user_id.len() > 64
            || self.challenge.len() < 16
            || self.user_name.is_empty()
        {
            return Err(Error::Encoding);
        }
        Ok(())
    }
}

impl LoginRequest {
    /// Basic shape checks before calling the authenticator.
    pub fn validate(&self) -> Result<(), Error> {
        if self.rp_id.is_empty() || self.challenge.len() < 16 {
            return Err(Error::Encoding);
        }
        Ok(())
    }
}

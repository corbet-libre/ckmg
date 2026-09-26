//! `ckmg`: key management for the member vault.
//!
//! - **Hierarchy:** member root → device key → purpose keys ([`KeyRing`]). Root and
//!   device secrets never leave the ring; purpose keys ([`Purpose`]) derive one-way and
//!   are the only secrets that may be delegated to engines (Veilid, OpenMLS, Arti).
//! - **Format:** Veilid's VLD0 cryptosystem and typed keys (`VLD0:<base64url>`), built
//!   from the crates Veilid uses (ed25519-dalek, x25519-dalek, hpke with
//!   chacha20poly1305, blake3). Keys and signatures made here are valid Veilid keys and
//!   signatures, so purpose keys can own and write Veilid DHT records directly.
//! - **Operations:** sign, verify, seal to a device, open, certify a purpose key
//!   ([`Delegation`]), pairing (seal the root to a new device) and root rotation.
//! - **Passkeys** ([`passkey`]): WebAuthn registration and login signing, and the PRF
//!   secret that becomes the `cwst` store password.
//!
//! `ckmg` holds no policy: `cvlt` decides who may request which operation, when pairing
//! is allowed, and when the root rotates. There is no export, backup or recovery path.

mod error;
mod keyring;
pub mod passkey;
mod purpose;
mod typed;
mod vld0;

pub use error::Error;
pub use keyring::{KeyRef, KeyRing, RingKey};
pub use purpose::{DelegatedKey, DelegatedSecret, Delegation, MAX_LABEL_BYTES, Purpose, Scope};
pub use typed::{BEST_KIND, CryptoKind, HashDigest, PublicKey, Signature, VLD0};
pub use vld0::{hash, seal_to, validate_public_key, verify, verify_ed25519};

/// A 32-byte secret that is wiped on drop.
pub(crate) type Secret = zeroize::Zeroizing<[u8; 32]>;

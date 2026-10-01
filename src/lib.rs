//! Community-local key custody for the member vault.
//!
//! [`Keys`] owns a root, independent device key, purpose capabilities, signed lineage,
//! pairing, atomic rotation and passkey-PRF restoration. [`SecureStore`], [`Clock`],
//! [`Entropy`] and [`Authority`] are injected. No networking or filesystem adapter is
//! built in. Root and device secrets have no public getter or plaintext serialization.
//!
//! Owner transcripts retain their exact bytes: [`Keys::sign`] is Veilid VLD0
//! Ed25519ph with context `VLD0_SIGN`; [`Keys::sign_ed25519`] serves plain-Ed25519
//! formats. A [`KeyCertificate`] binds the purpose key to community, pseudonym, device
//! and epoch. Consumers must verify it against authenticated current [`Lineage`].
//!
//! See `docs/CONTRACT.md`, `docs/CONSTRUCTIONS.md` and `docs/SECURITY-REVIEW.md`.
//! Cryptographic custody is not proof of community membership or current eligibility.

mod error;
mod keyring;
mod keys;
mod lineage;
pub mod passkey;
mod ports;
mod purpose;
mod typed;
mod vld0;

pub use error::Error;
pub use keys::{Change, DeviceInfo, KeyHandle, Keys, OperationId, Receipt, RestoreRoot, State};
pub use lineage::{
    Binding, KeyCertificate, Lineage, PairingGrant, PairingRequest, RootEnvelope, Rotation,
};
pub use ports::{
    Action, Authority, Authorization, Clock, Commit, Entropy, Locator, MAX_CHECKPOINT_BYTES,
    MAX_DEVICES, MAX_MESSAGE_BYTES, SecureStore, SystemEntropy,
};
pub use purpose::{MAX_LABEL_BYTES, Purpose, Scope};
pub use typed::{BEST_KIND, CryptoKind, HashDigest, PublicKey, Signature, VLD0};
pub use vld0::{hash, validate_public_key, verify, verify_ed25519};

/// Secret material is wiped on drop; never serialized outside encrypted checkpoints.
pub(crate) type Secret = zeroize::Zeroizing<[u8; 32]>;

#[cfg(target_arch = "wasm32")]
#[cfg(test)]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[cfg(test)]
mod veilid_reference_tests;

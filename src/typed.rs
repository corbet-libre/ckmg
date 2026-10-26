//! Veilid's typed-key format: a four-character cryptosystem code plus the raw bytes.
//!
//! Text form `VLD0:<base64url, no padding>`, binary form `VLD0 ‖ bytes`. The kind makes
//! every key and signature self-describing, which is what allows migrating to another
//! cryptosystem later without ambiguity.

use crate::Error;
use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

/// A cryptosystem identifier (Veilid `CryptoKind`, a FourCC).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CryptoKind(pub [u8; 4]);

/// Veilid's VLD0 cryptosystem: Ed25519 (Ed25519ph with context `VLD0_SIGN`), X25519,
/// XChaCha20-Poly1305, BLAKE3, Argon2id. The only kind supported today.
pub const VLD0: CryptoKind = CryptoKind(*b"VLD0");

/// The cryptosystem new keys are created with.
pub const BEST_KIND: CryptoKind = VLD0;

impl CryptoKind {
    /// The four bytes of the code.
    pub fn bytes(&self) -> &[u8; 4] {
        &self.0
    }
}

impl fmt::Display for CryptoKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.0))
    }
}

impl fmt::Debug for CryptoKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CryptoKind({self})")
    }
}

macro_rules! typed_bytes {
    ($(#[$doc:meta])* $name:ident, $len:expr) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name {
            kind: CryptoKind,
            value: [u8; $len],
        }

        impl $name {
            /// Length of the raw value in bytes.
            pub const LENGTH: usize = $len;

            /// A typed value from its kind and raw bytes.
            pub fn new(kind: CryptoKind, value: [u8; $len]) -> Self {
                Self { kind, value }
            }

            /// The cryptosystem.
            pub fn kind(&self) -> CryptoKind {
                self.kind
            }

            /// The raw bytes without the kind.
            pub fn value(&self) -> &[u8; $len] {
                &self.value
            }

            /// Binary form: kind followed by the raw bytes.
            pub fn to_typed_bytes(&self) -> Vec<u8> {
                let mut out = Vec::with_capacity(4 + $len);
                out.extend_from_slice(&self.kind.0);
                out.extend_from_slice(&self.value);
                out
            }

            /// Parse the binary form.
            pub fn from_typed_bytes(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() != 4 + $len {
                    return Err(Error::Encoding);
                }
                let mut kind = [0u8; 4];
                kind.copy_from_slice(&bytes[..4]);
                let mut value = [0u8; $len];
                value.copy_from_slice(&bytes[4..]);
                Ok(Self { kind: CryptoKind(kind), value })
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}:{}", self.kind, BASE64URL_NOPAD.encode(&self.value))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }

        impl FromStr for $name {
            type Err = Error;
            fn from_str(s: &str) -> Result<Self, Error> {
                if s.len() != 5 + (($len as usize) * 8).div_ceil(6) { return Err(Error::Encoding); }
                let (kind, value) = s.split_once(':').ok_or(Error::Encoding)?;
                let kind: [u8; 4] = kind.as_bytes().try_into().map_err(|__cause| crate::cause::emit(file!(), line!(), "Error::Encoding", Error::Encoding, &__cause))?;
                let bytes = BASE64URL_NOPAD
                    .decode(value.as_bytes())
                    .map_err(|__cause| crate::cause::emit(file!(), line!(), "Error::Encoding", Error::Encoding, &__cause))?;
                let value: [u8; $len] = bytes.try_into().map_err(|__cause| crate::cause::emit(file!(), line!(), "Error::Encoding", Error::Encoding, &__cause))?;
                Ok(Self { kind: CryptoKind(kind), value })
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl schemars::JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                stringify!($name).into()
            }
            fn schema_id() -> std::borrow::Cow<'static, str> {
                concat!(module_path!(), "::", stringify!($name)).into()
            }
            fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
                // Serde emits the typed base64url string, never the internal array.
                <String as schemars::JsonSchema>::json_schema(generator)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                text.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

typed_bytes!(
    /// A typed public signing key (VLD0: Ed25519).
    PublicKey,
    32
);
typed_bytes!(
    /// A typed signature (VLD0: Ed25519ph with context `VLD0_SIGN`).
    Signature,
    64
);
typed_bytes!(
    /// A typed 32-byte hash (VLD0: BLAKE3).
    HashDigest,
    32
);

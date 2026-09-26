use std::fmt;

/// Key management errors. Coarse on purpose: never carry keys or plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Malformed input or stored data.
    Encoding,
    /// A cryptosystem other than VLD0.
    UnsupportedKind,
    /// An unusable public key (not on the curve, weak, or not allowed here).
    InvalidKey,
    /// A signature did not verify.
    BadSignature,
    /// A sealed blob did not open (wrong recipient, wrong context, or modified).
    Open,
    /// A statement is outside its validity window.
    Expired,
    /// Invalid purpose label or version.
    InvalidPurpose,
    /// This device holds no member root.
    NoRoot,
    /// This device already holds a member root.
    RootExists,
    /// The platform random number generator failed.
    Randomness,
    /// A cryptographic operation failed unexpectedly.
    Crypto,
    /// WebAuthn needs a window context (not a worker).
    NoWindow,
    /// A browser API call failed.
    Browser,
    /// The member cancelled, or the authenticator refused.
    Cancelled,
    /// The authenticator does not support the PRF extension.
    PrfUnsupported,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Encoding => f.write_str("malformed input"),
            Error::UnsupportedKind => f.write_str("unsupported cryptosystem"),
            Error::InvalidKey => f.write_str("invalid key"),
            Error::BadSignature => f.write_str("signature did not verify"),
            Error::Open => f.write_str("sealed data did not open"),
            Error::Expired => f.write_str("outside validity window"),
            Error::InvalidPurpose => f.write_str("invalid purpose"),
            Error::NoRoot => f.write_str("no member root on this device"),
            Error::RootExists => f.write_str("member root already present"),
            Error::Randomness => f.write_str("randomness unavailable"),
            Error::Crypto => f.write_str("cryptographic failure"),
            Error::NoWindow => f.write_str("WebAuthn needs a window context"),
            Error::Browser => f.write_str("browser API failure"),
            Error::Cancelled => f.write_str("cancelled"),
            Error::PrfUnsupported => f.write_str("authenticator lacks the PRF extension"),
        }
    }
}

impl std::error::Error for Error {}

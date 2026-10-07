use std::fmt;

/// Key management errors. Coarse on purpose: never carry keys or plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Operation requires a currently unlocked, authorized device.
    Locked,
    /// A mutation is prepared or an output awaits durable acknowledgement.
    Pending,
    /// Current state must be reloaded after a conflicting or uncertain write.
    Reconcile,
    /// No surviving encrypted checkpoint exists at the passkey-derived location.
    MissingCheckpoint,
    /// Current authority or an exact request binding was refused.
    Unauthorized,
    /// Current device is revoked.
    Revoked,
    /// A store or authority port is unavailable.
    Unavailable,
    /// Resource or counter bound exceeded.
    Limit,
    /// Injected time regressed.
    Clock,
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
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Locked => f.write_str("keys are locked"),
            Error::Pending => f.write_str("pending transition or output"),
            Error::Reconcile => f.write_str("reload current state"),
            Error::MissingCheckpoint => f.write_str("encrypted checkpoint absent"),
            Error::Unauthorized => f.write_str("authority refused"),
            Error::Revoked => f.write_str("device revoked"),
            Error::Unavailable => f.write_str("port unavailable"),
            Error::Limit => f.write_str("limit exceeded"),
            Error::Clock => f.write_str("clock regressed"),
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
        }
    }
}

impl std::error::Error for Error {}

/// Discard backend details while preserving the boundary's selected error.
pub(crate) fn redact<E>(error: Error) -> impl FnOnce(E) -> Error {
    move |_| error
}

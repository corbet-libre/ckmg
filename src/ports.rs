//! Trusted runtime ports. There are no default storage or authority implementations.

use crate::{Binding, Error, PublicKey, Purpose, Scope};
use serde::{Deserialize, Serialize};
use std::future::Future;

/// Maximum encoded encrypted checkpoint size. Adapters must bound reads before allocation.
pub const MAX_CHECKPOINT_BYTES: usize = 262_144;
/// Maximum devices in a lineage, including the current device.
pub const MAX_DEVICES: usize = 128;
/// Maximum plaintext or owner signing transcript size.
pub const MAX_MESSAGE_BYTES: usize = 1_048_576;

/// A community-local, PRF-derived opaque lookup key. Never log or publicly index it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Locator(pub(crate) [u8; 32]);

impl Locator {
    /// Opaque bytes for a storage or record adapter, not a public member identifier.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for Locator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Locator([redacted])")
    }
}

/// Outcome of an atomic, durable compare/exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Commit {
    /// The exact replacement is durably installed.
    Committed,
    /// Nothing was written because the expected ciphertext digest did not match.
    Conflict,
    /// It may have committed. Reopen the current record; never regenerate a candidate.
    Unknown,
}

/// Injected protected storage. This adapter receives ciphertext only.
///
/// `expected` is BLAKE3 of the previously loaded ciphertext, or `None` for absence.
/// Compare and replacement must be one atomic durable operation, with no ABA or
/// rollback. A returned error from a write is treated as an unknown outcome. Reads
/// must be authoritative (not a stale replica) and bounded by [`MAX_CHECKPOINT_BYTES`].
/// A cwst adapter must include the owner's output in its composite transaction.
/// These futures intentionally impose no `Send` requirement on browser adapters.
pub trait SecureStore {
    /// Load the current sealed checkpoint; absence is distinct from unavailability.
    fn load(&mut self, location: &Locator) -> impl Future<Output = Result<Option<Vec<u8>>, Error>>;

    /// Atomically compare and durably replace the checkpoint.
    fn compare_exchange(
        &mut self,
        location: &Locator,
        expected: Option<[u8; 32]>,
        replacement: &[u8],
    ) -> impl Future<Output = Result<Commit, Error>>;

    /// Commit a root transition and its compound Store wrapper atomically.
    /// The cipher belongs to the exact prepared replacement root. A compound
    /// adapter MUST rewrap its existing random data key in the same transaction
    /// as replacement and companion owners/outputs. It must never split writes.
    /// The default is only for standalone sealed-checkpoint stores, which have
    /// no outer compound wrapper; their existing atomic persistence is sufficient.
    fn compare_exchange_wrapped(
        &mut self,
        location: &Locator,
        expected: Option<[u8; 32]>,
        replacement: &[u8],
        _cipher: &crate::passkey::StoreCipher,
    ) -> impl Future<Output = Result<Commit, Error>> {
        self.compare_exchange(location, expected, replacement)
    }
}

/// An injected trusted clock, in Unix seconds. Regressions fail closed.
pub trait Clock {
    /// Read current time without a hidden wall-clock dependency in the key machine.
    fn now(&mut self) -> Result<u64, Error>;
}

/// An injected cryptographically secure random source. Deterministic sources belong
/// only in test adapters; production callers must supply independent secure entropy.
pub trait Entropy {
    /// Fill the entire output, or fail without publishing any candidate.
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error>;
}

/// System CSPRNG adapter; uses Web Crypto on wasm32.
#[derive(Debug, Default)]
pub struct SystemEntropy;

impl Entropy for SystemEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(output).map_err(|_| Error::Randomness)
    }
}

/// The only device purposes admitted without a member-lineage read.
/// This discriminant cannot name an arbitrary purpose or a member key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodePurpose {
    /// The device's onion-service identity, never an application signing key.
    TorOnion,
    /// Original VLD0 node signing/DH for Tor Records envelopes.
    Vld0,
}
impl NodePurpose {
    /// Construct the exact device purpose with its owner-selected generation.
    pub fn purpose(self, generation: u32) -> Result<Purpose, Error> {
        Purpose::new(Scope::Device, self.label(), generation)
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::TorOnion => "tor.onion",
            Self::Vld0 => "tor.node",
        }
    }

    pub(crate) fn of(purpose: &Purpose) -> Option<Self> {
        if purpose.scope() != Scope::Device {
            return None;
        }
        match purpose.label() {
            "tor.onion" => Some(Self::TorOnion),
            "tor.node" => Some(Self::Vld0),
            _ => None,
        }
    }
}

/// The operation whose authorization the enclosing vault must verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Explicit first registration; never inferred from a missing restore record.
    Create,
    /// Reconstitute an absent checkpoint for this exact current, unrevoked lineage.
    /// Must not authorize a new member or accept a stale self-signed anchor.
    Restore,
    /// Generate a pending device after confirming the root out of band.
    RequestPairing,
    /// Use current device authority for signing, encryption or key handles.
    Use,
    /// Use only the named device node purpose while custody is unlocked in this
    /// session and its device remains in the live HTTPS membership set. This
    /// check must not read lineage through that same transport. It grants no
    /// member-purpose, statement, pairing, rotation or application authority.
    UseTransport(NodePurpose),
    /// Read only the root-owned lineage record during this restore attempt.
    /// Requires the original checkpoint, current certificate/assertion and fresh
    /// HTTPS device membership. Grants no Store cipher, writer or member use.
    ReadLineage,
    /// Sign only the exact original bytes and deadline in `Authorization::signing`.
    SignDeviceEd25519,
    /// Lend the broad synchronous Profile signer; requires separate explicit admission.
    /// Metadata reads and exact Board signing must never authorize this capability.
    LendDeviceSigner,
    /// Lend Profile signing and immutable Envelope custody together. This needs
    /// original Profile/Exchange admission, never a metadata or Board-sign intent.
    LendProfileCustody,
    /// Approve a pending device after authenticated, user-confirmed pairing.
    Pair,
    /// Remove a device and replace the root, without resetting the member pseudonym.
    Rotate,
    /// Adopt an authenticated lineage or root update.
    Adopt,
}

/// Original owner signing bytes and exclusive deadline. Input, not authority.
/// The trusted adapter must verify that this deadline is within its current G3
/// authority and local grant, then consume the exact admitted command once.
#[derive(Clone, Copy)]
pub struct DeviceSigning<'a> {
    /// Exact bounded owner transcript; no digest or alternative framing.
    pub transcript: &'a [u8],
    /// Exclusive Unix-second deadline from the trusted local admission.
    pub expires: u64,
}

/// Authorization input, not a verified capability. Debug omits all identifiers.
///
/// `evidence` is passed through from the caller to the authority adapter. Its meaning
/// and verification belong to cvlt/Foyer (for example the live passkey session).
pub struct Authorization<'a> {
    /// Community and externally verified cpsd pseudonym.
    pub binding: &'a Binding,
    /// Current or proposed root. Absent only during first creation.
    pub root: Option<PublicKey>,
    /// Local device key.
    pub device: PublicKey,
    /// Authority epoch (zero for first creation).
    pub epoch: u64,
    /// Exact requested operation.
    pub action: Action,
    /// Added or removed device, when applicable.
    pub target: Option<PublicKey>,
    /// Digest of the exact pairing request or transition, where applicable.
    pub statement: Option<[u8; 32]>,
    /// Present only for `SignDeviceEd25519`; bytes are borrowed through authorization.
    pub signing: Option<DeviceSigning<'a>>,
    /// Current injected time.
    pub now: u64,
    /// Opaque, bounded authority evidence; never persisted or logged by ckmg.
    pub evidence: &'a [u8],
}

/// Exact first-lineage payload, not current member authority. The enclosing
/// owner must decode its canonical packed evidence and verify this original
/// receipt's certificate/assertion against current policy and fresh HTTPS device
/// membership after its waits. A login assertion cannot replace the receipt's
/// dedicated passkey challenge. No generic root signing is authorized.
pub struct GenesisAuthorization<'a> {
    /// Exact original durable Created receipt, including its device attestation.
    pub receipt: &'a crate::Receipt,
    /// Exact authority reference authenticated in the original Created Keys
    /// checkpoint. The creation composer must have bound it to the original
    /// CPky credential ID; require that same ID in the verified certificate.
    pub authority_reference: &'a [u8],
    /// Exact packed plaintext that the fixed CDHT lineage value will encrypt.
    pub evidence: &'a [u8],
    /// Current injected Unix-second observation.
    pub now: u64,
    /// Exclusive trusted request deadline; the owner must also bound it by its
    /// actual session, certificate, assertion and current policy lifetimes.
    pub expires: u64,
}

impl std::fmt::Debug for GenesisAuthorization<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GenesisAuthorization([redacted])")
    }
}

/// Exact original pending Created receipt and authenticated durable completion
/// intent. The enclosing owner verifies original certificate/assertion proof
/// for this receipt's dedicated challenge, current signed Policy and original
/// live membership, plus every Store generation/digest and immutable intent
/// field against its actual authenticated outer/inner owner state. Caller
/// numbers, login assertions and cached accepting results are insufficient.
pub struct CompletionAuthorization<'a> {
    /// Exact pending Created receipt authenticated by the original Keys decoder.
    pub receipt: &'a crate::Receipt,
    /// Original sealed DeviceInfo reference, never a caller-selected current
    /// passkey. The verified certificate must name this exact original ID.
    pub authority_reference: &'a [u8],
    /// Original fixed PRF-derived local Keys slot.
    pub location: &'a Locator,
    /// Digest of the exact original pending encrypted Keys entry.
    pub sealed_digest: &'a [u8; 32],
    /// All immutable inputs loaded from the actual durable Prepared intent.
    pub intent: &'a crate::CompletionIntent,
    /// Current Unix-second observation, checked around awaits and signing.
    pub now: u64,
}
impl std::fmt::Debug for CompletionAuthorization<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CompletionAuthorization([redacted])")
    }
}

impl std::fmt::Debug for Authorization<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authorization")
            .field("action", &self.action)
            .finish_non_exhaustive()
    }
}

/// Trusted authorization/freshness adapter implemented by the enclosing vault.
///
/// Check origin, pseudonym, exact device revocation and live passkey authority.
/// UseTransport admits only its fixed device purpose using unlocked session
/// custody and a fresh live server device-set observation, without a lineage read.
/// Member operations additionally require the highest-epoch certified lineage
/// observed by a forced DHT read under its read agreement (ties: smaller hash),
/// containing this device. This does not claim a globally latest lineage.
/// Neither path may reuse an accepting result, lease or grace period. A detected
/// server/lineage removal must invalidate custody at the next check.
/// Pair/Rotate must verify the bound user approval; possession of
/// a public key or a pairing proof alone is insufficient. SignDeviceEd25519 requires
/// exact one-use transcript/deadline admission; LendDeviceSigner requires its own
/// explicit owner operation and must never follow from Use or signing admission.
/// Recheck authority deadlines after waits. Refuse if current authority
/// cannot be established. No permissive implementation ships with this library.
pub trait Authority {
    /// Authorize this exact request or refuse with a coarse error.
    fn check(&mut self, request: Authorization<'_>) -> impl Future<Output = Result<(), Error>>;

    /// Dedicated, one-attempt certified genesis admission. Existing authorities
    /// refuse by default; Create, transport use or normal Use cannot substitute.
    fn check_genesis(
        &mut self,
        _request: GenesisAuthorization<'_>,
    ) -> impl Future<Output = Result<(), Error>> {
        async { Err(Error::Unauthorized) }
    }

    /// Reborrow original current policy and check the retained owner membership
    /// observation at the point of use, after Keys' final Store wait. Verify the
    /// same exact request, live session/device generation, nonregressing clock
    /// and exclusive deadlines. No cached boolean or synthetic lease suffices.
    /// This callback performs no I/O and must not retain borrowed request bytes.
    fn check_genesis_current(&mut self, _request: GenesisAuthorization<'_>) -> Result<(), Error> {
        Err(Error::Unauthorized)
    }

    /// Dedicated authenticated pending-creation completion only. Existing
    /// authorities refuse; ordinary Create/Use/genesis ports never substitute.
    /// Every reopen requires a new actual original Foyer/Keyhole owner check and
    /// its checked time floor. Caller timestamps, cached policy or a verdict
    /// remembered before restart cannot supply this observation.
    fn check_completion(
        &mut self,
        _request: CompletionAuthorization<'_>,
    ) -> impl Future<Output = Result<u64, Error>> {
        async { Err(Error::Unauthorized) }
    }

    /// After the final Store await, synchronously compare the same original
    /// authenticated Store/Prepared intent and reborrow current signed Policy
    /// and actual original membership/session lease. No I/O, copied verdict,
    /// fabricated observation or borrowed request retention is permitted.
    /// Return the actual original Foyer/Keyhole owner's checked time floor,
    /// including its retained monotonic observations. A caller timestamp or
    /// cached policy verdict cannot supply this floor, including after reopen.
    fn check_completion_current(
        &mut self,
        _request: CompletionAuthorization<'_>,
    ) -> Result<u64, Error> {
        Err(Error::Unauthorized)
    }
}

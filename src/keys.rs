//! The custody state machine: prepare, validate, commit, then expose outputs.

use crate::keyring::{self, Material};
use crate::lineage::{digest, encode, redacted};
use crate::passkey::{self, PrfOutput};
use crate::{
    Action, Authority, Authorization, Binding, Clock, Commit, Entropy, Error, KeyCertificate,
    Lineage, Locator, MAX_CHECKPOINT_BYTES, MAX_DEVICES, MAX_MESSAGE_BYTES, NodePurpose,
    PairingGrant, PairingRequest, PublicKey, Purpose, RootEnvelope, Rotation, Scope, Secret,
    SecureStore, Signature, VLD0, vld0,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

mod account_device;
mod current_signing;
mod enrollment;
mod genesis;
mod inspection;
mod transport;

enum CurrentCheck<'a> {
    Ordinary(Option<crate::DeviceSigning<'a>>),
    #[cfg(feature = "wallet-engine")]
    RecordRecipient,
    DeviceSigning(crate::DeviceSigning<'a>),
}
pub use account_device::{AccountDeviceAuthorization, AccountDevicePlan};
pub use enrollment::{EnrollmentSeed, UnenrolledCreation};
pub use inspection::{
    CheckpointBootstrap, CheckpointInspection, CheckpointInspector, CheckpointRecordCustody,
    CompletionIntent, InitialCheckpointProvenance, InitialLineageReader, LineageReadCapability,
    LineageReadCustody, PendingCompletion, PendingCreation, ProvisionalLineage, inspect_checkpoint,
};
pub use transport::TransportSession;

const CHECKPOINT_HEADER: &[u8] = b"ckmg.checkpoint.v1\0";
const PURPOSE_HEADER: &[u8] = b"ckmg.purpose.sealed.v1\0";

/// Local custody state; Authorized still requires a fresh authority check per operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum State {
    /// No decrypted material held.
    Locked,
    /// Device persisted, awaiting an exact root transfer.
    PendingDevice,
    /// Root and authorized device material loaded.
    Authorized,
    /// Replacement exists only in memory; secret operations are suspended.
    Prepared,
    /// Commit may have happened, or another writer changed storage. Unlock to reconcile.
    Reconcile,
    /// No checkpoint exists. Authorized restoration still needs a retained encrypted copy.
    MissingCheckpoint,
    /// This logical device has been removed; no root is retained.
    Revoked,
}

/// Private local device metadata. Serialized only inside the encrypted checkpoint.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(try_from = "DeviceInfoWire", into = "DeviceInfoWire")]
pub struct DeviceInfo {
    name: String,
    authority_reference: Vec<u8>,
}

#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct DeviceInfoWire {
    name: String,
    authority_reference: Vec<u8>,
}
impl TryFrom<DeviceInfoWire> for DeviceInfo {
    type Error = Error;
    fn try_from(value: DeviceInfoWire) -> Result<Self, Error> {
        Self::new(&value.name, &value.authority_reference)
    }
}
impl From<DeviceInfo> for DeviceInfoWire {
    fn from(value: DeviceInfo) -> Self {
        Self {
            name: value.name,
            authority_reference: value.authority_reference,
        }
    }
}
impl DeviceInfo {
    /// Device name and opaque passkey/authority reference; neither enters lineage traffic.
    pub fn new(name: &str, authority_reference: &[u8]) -> Result<Self, Error> {
        if name.is_empty()
            || name.len() > 128
            || name.chars().any(char::is_control)
            || authority_reference.len() > 1024
        {
            return Err(Error::Encoding);
        }
        Ok(Self {
            name: name.into(),
            authority_reference: authority_reference.into(),
        })
    }
    /// Local display name.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Local authority reference for the vault adapter.
    pub fn authority_reference(&self) -> &[u8] {
        &self.authority_reference
    }
}

/// Idempotency identity for one committed output; contains no secret.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationId([u8; 32]);
impl OperationId {
    /// Opaque identifier for durable publication deduplication.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Committed output. Publish idempotently, then acknowledge its operation ID.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    /// Stable across a lost response, restart and retry of publication.
    pub operation: OperationId,
    /// Exact output committed with the replacement checkpoint.
    pub change: Change,
    /// Device signature over this exact operation and change. Historical outputs
    /// may lack it and must not authorize a current lineage publication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<DeviceAttestation>,
}

/// Untrusted public device-possession evidence. This signature is not a passkey
/// assertion and never authorizes current lineage. G3 additionally requires the
/// original passkey assertion and authenticated offline credential/revocation feed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceAttestation {
    /// Device key certified by the original community credential.
    pub device: PublicKey,
    /// VLD0 signature over the exact receipt operation and complete change.
    pub signature: Signature,
}
impl Receipt {
    /// Exact public challenge for the original Keyhole passkey assertion verifier.
    /// Binds the complete change and durable operation under a separate purpose;
    /// obtaining this digest proves neither credential activity nor authorization.
    /// The caller must retain the original public assertion and Policy-authenticated
    /// credential descriptor, and check current offline revocations before adoption.
    pub fn passkey_challenge(&self) -> Result<[u8; 32], Error> {
        digest(b"ckmg.passkey-change.v1\0", &(self.operation, &self.change))
    }
    fn attestation_bytes(&self, device: PublicKey) -> Result<Vec<u8>, Error> {
        encode(
            b"ckmg.device-change.v1\0",
            &(self.operation, &self.change, device),
        )
    }
    /// Verify original device signature and self-signed lineage, returning its
    /// claimed device author. This proves possession only, never active passkey
    /// status or global currentness. A delegated device key cannot substitute for
    /// the original passkey assertion required to authorize a lineage change.
    pub fn attested_lineage(&self) -> Result<(&Lineage, PublicKey), Error> {
        let attestation = self.attestation.as_ref().ok_or(Error::Unauthorized)?;
        vld0::verify(
            &attestation.device,
            &self.attestation_bytes(attestation.device)?,
            &attestation.signature,
        )?;
        let lineage = match &self.change {
            Change::Created(lineage)
            | Change::Restored(lineage)
            | Change::Paired(lineage)
            | Change::Adopted(lineage) => lineage,
            Change::DeviceAuthorized(grant) => &grant.lineage,
            Change::Rotated(rotation) => &rotation.lineage,
            Change::PairingRequested(_) | Change::Revoked(_) => return Err(Error::Unauthorized),
        };
        lineage.verify()?;
        if !lineage.devices.contains(&attestation.device) {
            return Err(Error::Unauthorized);
        }
        Ok((lineage, attestation.device))
    }
}

/// Public/ciphertext changes stored atomically with custody; never raw root/device keys.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Change {
    /// Explicit new community identity custody.
    Created(Lineage),
    /// Existing identity restored after authoritative checkpoint absence.
    Restored(Lineage),
    /// Pending recipient proof, persisted before it is sent.
    PairingRequested(Box<PairingRequest>),
    /// Live device authorized a recipient and sealed the root to it.
    DeviceAuthorized(Box<PairingGrant>),
    /// Receiving device durably accepted its root.
    Paired(Lineage),
    /// Root replacement and remaining-device envelopes.
    Rotated(Box<Rotation>),
    /// Adopted a newer authenticated lineage or root.
    Adopted(Lineage),
    /// Current device removed and local root erased.
    Revoked(Lineage),
}

/// Source of the current shared root when reconstituting an absent checkpoint.
/// All cases also require independently authenticated current lineage/authority.
pub enum RestoreRoot<'a> {
    /// Historical API spelling retained only to refuse recordless restoration.
    /// Every passkey needs a retained encrypted copy; this always returns MissingCheckpoint.
    Derived,
    /// Exact retained PRF-encrypted Keys checkpoint, including its independently
    /// wrapped random root. Never a plaintext root or another domain's checkpoint.
    Checkpoint(&'a [u8]),
    /// A retained root transfer for a different credential enrolled by pairing.
    Paired(&'a PairingGrant),
    /// A retained current-epoch envelope when another credential rotated the root.
    Rotated(&'a Rotation),
}

/// Opaque session-bound purpose capability. No raw key getter or serialization.
///
/// ```compile_fail
/// # fn probe(handle: ckmg::KeyHandle) {
/// let secret = handle.secret;
/// # }
/// ```
pub struct KeyHandle {
    session: [u8; 32],
    certificate: KeyCertificate,
}
impl KeyHandle {
    /// Public key and its scope/device/epoch certificate.
    pub fn certificate(&self) -> &KeyCertificate {
        &self.certificate
    }
}

/// Synchronous signing access for an upstream engine inside one authorized call.
/// No secret getter, owned copy or serialization is available. The capability
/// cannot outlive [`Keys::with_ed25519_signer`]'s callback.
pub struct Ed25519Signer<'key> {
    secret: &'key Secret,
    public_key: [u8; 32],
}

impl Ed25519Signer<'_> {
    /// The public key for the already authorized purpose.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Sign an exact bounded owner transcript using upstream plain Ed25519.
    pub fn sign(&self, transcript: &[u8]) -> Result<[u8; 64], Error> {
        if transcript.len() > MAX_MESSAGE_BYTES {
            return Err(Error::Limit);
        }
        Ok(vld0::sign_ed25519(self.secret, transcript))
    }
}

/// The freshly authorized lineage device, distinct from a derived purpose signer.
/// Only `Keys::with_device_ed25519_signer` can lend this capability. It cannot
/// escape that call or be constructed from an unsigned public key.
pub struct DeviceEd25519Signer<'key>(Ed25519Signer<'key>);

impl DeviceEd25519Signer<'_> {
    /// Exact public key of this authorized lineage device.
    pub fn public_key(&self) -> &[u8; 32] {
        self.0.public_key()
    }

    /// X25519 public key of this same authorized device, using the maintained
    /// VLD0 conversion already used by pairing. Profile signs it explicitly;
    /// peers must verify that signed field through Guard before HPKE release.
    pub fn hpke_public_key(&self) -> Result<[u8; 32], Error> {
        vld0::x25519_public(&PublicKey::new(VLD0, *self.public_key()))
    }

    /// Sign a bounded owner transcript with the actual device key.
    pub fn sign(&self, transcript: &[u8]) -> Result<[u8; 64], Error> {
        self.0.sign(transcript)
    }
}

/// Scoped synchronous Veilid VLD0 signer, distinct from plain Ed25519.
/// It borrows purpose custody only for one fresh-authorized callback.
pub struct Vld0Signer<'key>(Ed25519Signer<'key>);

impl Vld0Signer<'_> {
    /// The public key for the already authorized purpose.
    pub fn public_key(&self) -> &[u8; 32] {
        self.0.public_key()
    }

    /// Sign exact owner bytes using upstream Ed25519ph and `VLD0_SIGN`.
    pub fn sign(&self, data: &[u8]) -> Result<[u8; 64], Error> {
        if data.len() > MAX_MESSAGE_BYTES {
            return Err(Error::Limit);
        }
        Ok(*vld0::sign(self.0.secret, data)?.value())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    version: u8,
    revision: u64,
    last_time: u64,
    info: DeviceInfo,
    lineage: Lineage,
    pairing: Option<PairingRequest>,
    revoked: bool,
    output: Option<Receipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    initial: Option<inspection::StoredInitial>,
}

#[derive(Clone)]
struct Open {
    location: Locator,
    key: Secret,
    session: [u8; 32],
    stamp: [u8; 32],
    metadata: Metadata,
    material: Material,
}

struct Prepared {
    candidate: Open,
    expected: Option<[u8; 32]>,
    sealed: Vec<u8>,
    rotation_approval: Option<Zeroizing<Vec<u8>>>,
    rewrap: bool,
}

/// One logical device in one community. Ports are supplied by the enclosing vault.
///
/// It owns no network, files, membership policy, or Wallet engine. A missing
/// checkpoint never implicitly creates an identity. Every secret operation
/// rechecks storage generation, clock and the injected current authority.
pub struct Keys<S, C, R, A> {
    store: S,
    clock: C,
    entropy: R,
    authority: A,
    state: State,
    open: Option<Open>,
    prepared: Option<Prepared>,
    last_time: u64,
    genesis: Option<genesis::InitialPublication>,
    #[cfg(all(feature = "native-tor", not(target_arch = "wasm32")))]
    tor_custody: crate::native_tor::Custody,
    #[cfg(all(feature = "browser-tor", target_arch = "wasm32"))]
    browser_tor_custody: crate::browser_tor::Custody,
}

impl<S, C, R, A> std::fmt::Debug for Keys<S, C, R, A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keys")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}
redacted!(DeviceInfo, OperationId, Receipt, Change, KeyHandle);

impl<S: SecureStore, C: Clock, R: Entropy, A: Authority> Keys<S, C, R, A> {
    /// Construct a locked machine from trusted adapters.
    pub fn new(store: S, clock: C, entropy: R, authority: A) -> Self {
        Self {
            store,
            clock,
            entropy,
            authority,
            state: State::Locked,
            open: None,
            prepared: None,
            last_time: 0,
            genesis: None,
            #[cfg(all(feature = "native-tor", not(target_arch = "wasm32")))]
            tor_custody: crate::native_tor::Custody::default(),
            #[cfg(all(feature = "browser-tor", target_arch = "wasm32"))]
            browser_tor_custody: crate::browser_tor::Custody::default(),
        }
    }

    /// Current local custody state, without identifiers or keys.
    pub fn state(&self) -> State {
        self.state
    }

    /// Wipe decrypted material and uncommitted candidates. A committed pending output
    /// remains in storage for reconciliation. All existing handles become unusable.
    pub fn lock(&mut self) {
        #[cfg(all(feature = "native-tor", not(target_arch = "wasm32")))]
        self.tor_custody.close();
        #[cfg(all(feature = "browser-tor", target_arch = "wasm32"))]
        self.browser_tor_custody.close();
        self.open = None;
        self.prepared = None;
        self.genesis = None;
        self.state = State::Locked;
    }

    fn fail_closed(&mut self, state: State) {
        self.lock();
        self.state = state;
    }

    fn now(&mut self) -> Result<u64, Error> {
        let now = self.clock.now()?;
        if now < self.last_time {
            self.fail_closed(State::Locked);
            return Err(Error::Clock);
        }
        self.last_time = now;
        Ok(now)
    }

    fn loaded(&self) -> Result<&Open, Error> {
        match self.state {
            State::Prepared => Err(Error::Pending),
            State::Reconcile => Err(Error::Reconcile),
            State::Locked | State::MissingCheckpoint => Err(Error::Locked),
            _ => self.open.as_ref().ok_or(Error::Locked),
        }
    }

    fn writable(&self) -> Result<(), Error> {
        if self.loaded()?.metadata.output.is_some() {
            return Err(Error::Pending);
        }
        Ok(())
    }

    async fn refresh(&mut self) -> Result<(), Error> {
        let current = self.loaded()?;
        let location = current.location;
        let stamp = current.stamp;
        match self.store.load(&location).await {
            Ok(Some(bytes))
                if bytes.len() <= MAX_CHECKPOINT_BYTES
                    && *blake3::hash(&bytes).as_bytes() == stamp =>
            {
                Ok(())
            }
            Ok(_) => {
                self.fail_closed(State::Reconcile);
                Err(Error::Reconcile)
            }
            Err(_) => {
                self.fail_closed(State::Locked);
                Err(Error::Unavailable)
            }
        }
    }

    async fn authorize(
        &mut self,
        action: Action,
        target: Option<PublicKey>,
        statement: Option<[u8; 32]>,
        evidence: &[u8],
    ) -> Result<(), Error> {
        self.authorize_with_signing(action, target, statement, evidence, None)
            .await
    }

    async fn authorize_with_signing(
        &mut self,
        action: Action,
        target: Option<PublicKey>,
        statement: Option<[u8; 32]>,
        evidence: &[u8],
        signing: Option<crate::DeviceSigning<'_>>,
    ) -> Result<(), Error> {
        self.authorize_with_check(
            action,
            target,
            statement,
            evidence,
            CurrentCheck::Ordinary(signing),
        )
        .await
    }

    async fn authorize_with_check(
        &mut self,
        action: Action,
        target: Option<PublicKey>,
        statement: Option<[u8; 32]>,
        evidence: &[u8],
        route: CurrentCheck<'_>,
    ) -> Result<(), Error> {
        if evidence.len() > 4096 {
            return Err(Error::Limit);
        }
        self.refresh().await?;
        let now = self.now()?;
        let current = self.loaded()?;
        if current.metadata.revoked {
            return Err(Error::Revoked);
        }
        if action != Action::Adopt
            && action != Action::RequestPairing
            && current.metadata.pairing.is_some()
        {
            return Err(Error::Unauthorized);
        }
        let binding = current.metadata.lineage.binding.clone();
        let root = current.metadata.lineage.root;
        let epoch = current.metadata.lineage.epoch;
        let device = vld0::public_key(&current.material.device);
        let signing = match &route {
            CurrentCheck::Ordinary(signing) => *signing,
            #[cfg(feature = "wallet-engine")]
            CurrentCheck::RecordRecipient => None,
            CurrentCheck::DeviceSigning(signing) => Some(*signing),
        };
        self.check_authority_with(
            Authorization {
                binding: &binding,
                root: Some(root),
                device,
                epoch,
                action,
                target,
                statement,
                signing,
                now,
                evidence,
            },
            route,
        )
        .await?;
        if action == Action::Use {
            self.genesis = None;
        }
        Ok(())
    }

    async fn check_authority(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        self.check_authority_with(request, CurrentCheck::Ordinary(None))
            .await
    }

    async fn check_authority_with(
        &mut self,
        request: Authorization<'_>,
        route: CurrentCheck<'_>,
    ) -> Result<(), Error> {
        if request.evidence.len() > 4096 {
            return Err(Error::Limit);
        }
        let result = match route {
            CurrentCheck::Ordinary(_) => self.authority.check(request).await,
            #[cfg(feature = "wallet-engine")]
            CurrentCheck::RecordRecipient => self.authority.check_record_recipient(request).await,
            CurrentCheck::DeviceSigning(_) => self.authority.check_device_signing(request).await,
        };
        if let Err(error) = result {
            self.fail_closed(if error == Error::Revoked {
                State::Revoked
            } else {
                State::Locked
            });
            return Err(match error {
                Error::Unavailable => Error::Unavailable,
                Error::Revoked => Error::Revoked,
                _ => Error::Unauthorized,
            });
        }
        Ok(())
    }

    /// Restore exactly the stored logical device using the same PRF and community.
    /// This only unlocks custody; every later key operation still checks authority.
    /// Missing/corrupt records never create a replacement identity.
    pub async fn unlock(&mut self, prf: &PrfOutput, community: &str) -> Result<(), Error> {
        self.lock();
        let location = passkey::vault_location(prf, community)?;
        let key = passkey::ring_key(prf, community)?;
        let Some(sealed) = self
            .store
            .load(&location)
            .await
            .map_err(|_| Error::Unavailable)?
        else {
            self.state = State::MissingCheckpoint;
            return Err(Error::MissingCheckpoint);
        };
        if sealed.len() > MAX_CHECKPOINT_BYTES {
            return Err(Error::Limit);
        }
        let aad = checkpoint_aad(location);
        let bytes = sealed
            .strip_prefix(CHECKPOINT_HEADER)
            .ok_or(Error::Encoding)?;
        let plaintext = keyring::open(&key, &aad, bytes)?;
        let (metadata, material) = decode_checkpoint(&plaintext)?;
        if metadata.lineage.binding.community() != community {
            return Err(Error::Unauthorized);
        }
        validate_checkpoint(&metadata, &material)?;
        self.last_time = self.last_time.max(metadata.last_time);
        self.now()?;
        let session = *vld0::random_secret(&mut self.entropy)?;
        let open = Open {
            location,
            key,
            session,
            stamp: *blake3::hash(&sealed).as_bytes(),
            metadata,
            material,
        };
        self.state = open.state();
        self.open = Some(open);
        Ok(())
    }

    /// Explicitly create a random common root and a PRF-wrapped device, after the authority adapter
    /// verifies the new-member binding. Existing storage is never overwritten.
    pub async fn create_scope(
        &mut self,
        prf: &PrfOutput,
        binding: Binding,
        info: DeviceInfo,
        evidence: &[u8],
    ) -> Result<Receipt, Error> {
        self.require_locked()?;
        let location = passkey::vault_location(prf, binding.community())?;
        self.require_absent(location).await?;
        let now = self.now()?;
        let material = Material::derive(prf, binding.community(), true, &mut self.entropy)?;
        let device = vld0::public_key(&material.device);
        self.check_authority(Authorization {
            binding: &binding,
            root: None,
            device,
            epoch: 0,
            action: Action::Create,
            target: None,
            statement: None,
            signing: None,
            now,
            evidence,
        })
        .await?;
        let mut lineage = Lineage {
            version: 2,
            binding,
            epoch: 1,
            revision: 1,
            root: vld0::public_key(material.root()?),
            identity: material.identity.as_ref().map(vld0::public_key),
            devices: vec![device],
            signature: empty_signature(),
        };
        lineage.signature = vld0::sign(material.root()?, &lineage.signed_bytes()?)?;
        let change = Change::Created(lineage.clone());
        let candidate = self.initial(prf, location, material, info, lineage, None)?;
        self.prepare(candidate, None, Some(change))?;
        let receipt = self.commit().await?.ok_or(Error::Crypto)?;
        self.genesis = Some(genesis::InitialPublication::new(
            receipt.operation,
            self.loaded()?.stamp,
        ));
        Ok(receipt)
    }

    /// Reconstitute an absent checkpoint for an existing member. The same PRF derives
    /// the same logical device; current authority must authenticate the exact anchor
    /// and reject removed devices. Unreachable/corrupt/existing records never reach
    /// this path. A retained authenticated transfer is required: the PRF alone
    /// cannot recreate the common random root. Binding, epoch and lineage stay unchanged.
    pub async fn restore_scope(
        &mut self,
        prf: &PrfOutput,
        anchor: &Lineage,
        source: RestoreRoot<'_>,
        info: DeviceInfo,
        evidence: &[u8],
    ) -> Result<Receipt, Error> {
        self.require_locked()?;
        anchor.verify()?;
        let location = passkey::vault_location(prf, anchor.binding.community())?;
        self.require_absent(location).await?;
        let mut material =
            Material::derive(prf, anchor.binding.community(), false, &mut self.entropy)?;
        let device = vld0::public_key(&material.device);
        if !anchor.devices.contains(&device) {
            return Err(Error::Unauthorized);
        }
        let now = self.now()?;
        self.check_authority(Authorization {
            binding: &anchor.binding,
            root: Some(anchor.root),
            device,
            epoch: anchor.epoch,
            action: Action::Restore,
            target: None,
            statement: Some(anchor.digest()?),
            signing: None,
            now,
            evidence,
        })
        .await?;
        match source {
            RestoreRoot::Derived => return Err(Error::MissingCheckpoint),
            RestoreRoot::Checkpoint(sealed) => {
                if sealed.len() > MAX_CHECKPOINT_BYTES {
                    return Err(Error::Limit);
                }
                let key = passkey::ring_key(prf, anchor.binding.community())?;
                let bytes = sealed
                    .strip_prefix(CHECKPOINT_HEADER)
                    .ok_or(Error::Encoding)?;
                let plaintext = keyring::open(&key, &checkpoint_aad(location), bytes)?;
                let (metadata, retained) = decode_checkpoint(&plaintext)?;
                validate_checkpoint(&metadata, &retained)?;
                if vld0::public_key(&retained.device) != device
                    || metadata.revoked
                    || metadata.pairing.is_some()
                    || metadata.lineage.binding != anchor.binding
                    || metadata.lineage.root != anchor.root
                    || metadata.lineage.epoch != anchor.epoch
                    || metadata.lineage.identity != anchor.identity
                    || metadata.lineage.revision > anchor.revision
                {
                    return Err(Error::Unauthorized);
                }
                if metadata.last_time > now {
                    return Err(Error::Clock);
                }
                material = retained;
            }
            RestoreRoot::Paired(grant) => {
                grant.lineage.verify()?;
                if grant.lineage.version != anchor.version
                    || grant.lineage.identity != anchor.identity
                    || grant.request.device != device
                    || grant.request.binding != anchor.binding
                    || grant.request.root != anchor.root
                    || grant.request.epoch != anchor.epoch
                    || grant.lineage.binding != anchor.binding
                    || grant.lineage.root != anchor.root
                    || grant.lineage.epoch != anchor.epoch
                    || grant.lineage.revision > anchor.revision
                    || !grant.lineage.devices.contains(&device)
                {
                    return Err(Error::Unauthorized);
                }
                // Restore is not fresh enrollment: the original challenge may have
                // expired. Current authority above confirms the retained device.
                vld0::verify(
                    &device,
                    &grant.request.signed_bytes()?,
                    &grant.request.proof,
                )?;
                vld0::verify(&anchor.root, &grant.signed_bytes()?, &grant.signature)?;
                let plaintext = vld0::open(&material.device, &grant.aad()?, &grant.sealed_root)?;
                material.receive(grant.version, &plaintext)?;
            }
            RestoreRoot::Rotated(rotation) => {
                rotation.lineage.verify()?;
                if rotation.lineage.version != anchor.version
                    || rotation.lineage.identity != anchor.identity
                    || rotation.lineage.binding != anchor.binding
                    || rotation.lineage.root != anchor.root
                    || rotation.lineage.epoch != anchor.epoch
                    || rotation.lineage.revision > anchor.revision
                    || rotation.revoked == device
                {
                    return Err(Error::Unauthorized);
                }
                // The current independently authenticated anchor is the trust root;
                // no missing historical checkpoint is treated as proof of freshness.
                vld0::verify(
                    &rotation.previous_root,
                    &rotation.signed_bytes()?,
                    &rotation.signature,
                )?;
                let envelope = rotation
                    .envelopes
                    .iter()
                    .find(|e| e.device == device)
                    .ok_or(Error::Unauthorized)?;
                let plaintext = vld0::open(
                    &material.device,
                    &rotation.aad(device)?,
                    &envelope.sealed_root,
                )?;
                material.receive(rotation.version, &plaintext)?;
            }
        }
        if vld0::public_key(material.root()?) != anchor.root {
            return Err(Error::Unauthorized);
        }
        let candidate = self.initial(prf, location, material, info, anchor.clone(), None)?;
        self.prepare(candidate, None, Some(Change::Restored(anchor.clone())))?;
        self.commit().await?.ok_or(Error::Crypto)
    }

    /// Retain the exact already-durable PRF-wrapped checkpoint in owner Records.
    /// No new encryption format or plaintext root is exposed. The current root,
    /// device authority and storage generation are checked before returning bytes.
    pub async fn retained_checkpoint(&mut self) -> Result<Vec<u8>, Error> {
        self.writable()?;
        self.authorize(Action::Use, None, None, &[]).await?;
        let current = self.loaded()?;
        let location = current.location;
        let stamp = current.stamp;
        match self.store.load(&location).await {
            Ok(Some(bytes))
                if bytes.len() <= MAX_CHECKPOINT_BYTES
                    && *blake3::hash(&bytes).as_bytes() == stamp =>
            {
                Ok(bytes)
            }
            Ok(_) => {
                self.fail_closed(State::Reconcile);
                Err(Error::Reconcile)
            }
            Err(_) => {
                self.fail_closed(State::Locked);
                Err(Error::Unavailable)
            }
        }
    }

    /// Persist a deterministically derived device and a short-lived proof, after the authority
    /// confirms this exact root/binding. The passkey ecosystem is the logical device.
    pub async fn request_pairing(
        &mut self,
        prf: &PrfOutput,
        anchor: &Lineage,
        info: DeviceInfo,
        evidence: &[u8],
    ) -> Result<Receipt, Error> {
        self.require_locked()?;
        anchor.verify()?;
        let location = passkey::vault_location(prf, anchor.binding.community())?;
        self.require_absent(location).await?;
        let now = self.now()?;
        let material = Material::derive(prf, anchor.binding.community(), false, &mut self.entropy)?;
        let device = vld0::public_key(&material.device);
        self.check_authority(Authorization {
            binding: &anchor.binding,
            root: Some(anchor.root),
            device,
            epoch: anchor.epoch,
            action: Action::RequestPairing,
            target: None,
            statement: Some(anchor.digest()?),
            signing: None,
            now,
            evidence,
        })
        .await?;
        let mut request = PairingRequest {
            version: 1,
            binding: anchor.binding.clone(),
            root: anchor.root,
            epoch: anchor.epoch,
            device,
            nonce: *vld0::random_secret(&mut self.entropy)?,
            issued_at: now,
            expires_at: now.checked_add(300).ok_or(Error::Limit)?,
            proof: empty_signature(),
        };
        request.proof = vld0::sign(&material.device, &request.signed_bytes()?)?;
        let change = Change::PairingRequested(Box::new(request.clone()));
        let candidate =
            self.initial(prf, location, material, info, anchor.clone(), Some(request))?;
        self.prepare(candidate, None, Some(change))?;
        self.commit().await?.ok_or(Error::Crypto)
    }

    /// Replace an expired pending challenge after confirming fresh root authority.
    /// Reuses the persisted device key; it never creates another identity on timeout.
    pub async fn renew_pairing(
        &mut self,
        anchor: &Lineage,
        evidence: &[u8],
    ) -> Result<Receipt, Error> {
        self.writable()?;
        self.refresh().await?;
        anchor.verify()?;
        let now = self.now()?;
        let mut candidate = self.loaded()?.clone();
        let pending = candidate
            .metadata
            .pairing
            .as_ref()
            .ok_or(Error::Unauthorized)?;
        if candidate.metadata.lineage.binding != anchor.binding || now < pending.expires_at {
            return Err(Error::Unauthorized);
        }
        let device = vld0::public_key(&candidate.material.device);
        if anchor.devices.contains(&device) {
            return Err(Error::Unauthorized);
        }
        self.check_authority(Authorization {
            binding: &anchor.binding,
            root: Some(anchor.root),
            device,
            epoch: anchor.epoch,
            action: Action::RequestPairing,
            target: None,
            statement: Some(anchor.digest()?),
            signing: None,
            now,
            evidence,
        })
        .await?;
        let now = self.now()?;
        let mut request = PairingRequest {
            version: 1,
            binding: anchor.binding.clone(),
            root: anchor.root,
            epoch: anchor.epoch,
            device,
            nonce: *vld0::random_secret(&mut self.entropy)?,
            issued_at: now,
            expires_at: now.checked_add(300).ok_or(Error::Limit)?,
            proof: empty_signature(),
        };
        request.proof = vld0::sign(&candidate.material.device, &request.signed_bytes()?)?;
        candidate.metadata.pairing = Some(request.clone());
        candidate.metadata.lineage = anchor.clone();
        let expected = candidate.stamp;
        self.prepare(
            candidate,
            Some(expected),
            Some(Change::PairingRequested(Box::new(request))),
        )?;
        self.commit().await?.ok_or(Error::Crypto)
    }

    fn require_locked(&self) -> Result<(), Error> {
        if !matches!(self.state, State::Locked | State::MissingCheckpoint) {
            return Err(Error::Pending);
        }
        Ok(())
    }
    async fn require_absent(&mut self, location: Locator) -> Result<(), Error> {
        if self
            .store
            .load(&location)
            .await
            .map_err(|_| Error::Unavailable)?
            .is_some()
        {
            return Err(Error::RootExists);
        }
        Ok(())
    }
    fn initial(
        &mut self,
        prf: &PrfOutput,
        location: Locator,
        material: Material,
        info: DeviceInfo,
        lineage: Lineage,
        pairing: Option<PairingRequest>,
    ) -> Result<Open, Error> {
        Ok(Open {
            location,
            key: passkey::ring_key(prf, lineage.binding.community())?,
            session: *vld0::random_secret(&mut self.entropy)?,
            stamp: [0; 32],
            material,
            metadata: Metadata {
                version: 1,
                revision: 0,
                last_time: self.last_time,
                info,
                lineage,
                pairing,
                revoked: false,
                output: None,
                initial: None,
            },
        })
    }

    fn prepare(
        &mut self,
        mut candidate: Open,
        expected: Option<[u8; 32]>,
        change: Option<Change>,
    ) -> Result<(), Error> {
        // Initial provenance authenticates only the exact original ACK. Later
        // mutations cannot carry it as approval for a new lineage or operation.
        if candidate.metadata.revision >= 2 || change.is_some() {
            candidate.metadata.initial = None;
            candidate.metadata.version = 1;
        }
        candidate.metadata.revision = candidate
            .metadata
            .revision
            .checked_add(1)
            .ok_or(Error::Limit)?;
        candidate.metadata.last_time = self.last_time;
        candidate.metadata.output = match change {
            Some(change) => {
                let mut receipt = Receipt {
                    operation: OperationId(*vld0::random_secret(&mut self.entropy)?),
                    change,
                    attestation: None,
                };
                let device = vld0::public_key(&candidate.material.device);
                let signature = vld0::sign(
                    &candidate.material.device,
                    &receipt.attestation_bytes(device)?,
                )?;
                receipt.attestation = Some(DeviceAttestation { device, signature });
                Some(receipt)
            }
            None => None,
        };
        self.prepare_checkpoint(candidate, expected)
    }

    fn prepare_checkpoint(
        &mut self,
        mut candidate: Open,
        expected: Option<[u8; 32]>,
    ) -> Result<(), Error> {
        validate_checkpoint(&candidate.metadata, &candidate.material)?;
        let plaintext = encode_checkpoint(&candidate.metadata, &candidate.material)?;
        let mut sealed = CHECKPOINT_HEADER.to_vec();
        sealed.extend_from_slice(&keyring::seal(
            &mut self.entropy,
            &candidate.key,
            &checkpoint_aad(candidate.location),
            &plaintext,
        )?);
        if sealed.len() > MAX_CHECKPOINT_BYTES {
            return Err(Error::Limit);
        }
        candidate.stamp = *blake3::hash(&sealed).as_bytes();
        self.prepared = Some(Prepared {
            candidate,
            expected,
            sealed,
            rotation_approval: None,
            rewrap: false,
        });
        self.state = State::Prepared;
        Ok(())
    }

    /// Durably commit a prepared rotation. Cancellation, conflict or unknown outcome
    /// leaves Reconcile with no decrypted state. Unlock reads the actual stored winner.
    /// The returned output is also stored, so a lost response never loses key material.
    pub async fn commit(&mut self) -> Result<Option<Receipt>, Error> {
        let prepared = self.prepared.take().ok_or(Error::Pending)?;
        let previous = self.open.as_ref().map(|open| open.metadata.lineage.clone());
        let root_changed = self.open.as_ref().and_then(|open| {
            open.material
                .root
                .as_ref()
                .map(|_| open.metadata.lineage.root)
        }) != prepared
            .candidate
            .material
            .root
            .as_ref()
            .map(|_| prepared.candidate.metadata.lineage.root);
        self.fail_closed(State::Reconcile);
        if let Some(evidence) = &prepared.rotation_approval {
            let previous = previous.ok_or(Error::Unauthorized)?;
            let output = prepared
                .candidate
                .metadata
                .output
                .as_ref()
                .ok_or(Error::Encoding)?;
            let Change::Rotated(rotation) = &output.change else {
                return Err(Error::Encoding);
            };
            let now = self.now()?;
            self.check_authority(Authorization {
                binding: &previous.binding,
                root: Some(previous.root),
                device: vld0::public_key(&prepared.candidate.material.device),
                epoch: previous.epoch,
                action: Action::Rotate,
                target: Some(rotation.revoked),
                statement: Some(previous.digest()?),
                signing: None,
                now,
                evidence,
            })
            .await?;
        }
        let cipher = if root_changed || prepared.rewrap {
            prepared
                .candidate
                .material
                .root
                .as_ref()
                .map(|root| {
                    passkey::common_store_cipher(
                        root,
                        prepared.candidate.metadata.lineage.binding.community(),
                    )
                })
                .transpose()?
        } else {
            None
        };
        let outcome = match cipher {
            Some(cipher) => {
                self.store
                    .compare_exchange_wrapped(
                        &prepared.candidate.location,
                        prepared.expected,
                        &prepared.sealed,
                        &cipher,
                    )
                    .await
            }
            None => {
                self.store
                    .compare_exchange(
                        &prepared.candidate.location,
                        prepared.expected,
                        &prepared.sealed,
                    )
                    .await
            }
        };
        match outcome {
            Ok(Commit::Committed) => {
                let output = prepared.candidate.metadata.output.clone();
                self.state = prepared.candidate.state();
                self.open = Some(prepared.candidate);
                Ok(output)
            }
            _ => Err(Error::Reconcile),
        }
    }

    /// Discard an uncommitted prepared rotation, preserving the original stored state.
    pub fn cancel_prepared(&mut self) -> Result<(), Error> {
        if self.state != State::Prepared {
            return Err(Error::Pending);
        }
        self.prepared = None;
        self.state = self.open.as_ref().map_or(State::Locked, Open::state);
        Ok(())
    }

    /// Retrieve the exact committed output after a lost reply or restart. No secret
    /// operation is performed; the passkey-authenticated checkpoint protects the bytes.
    pub async fn pending_output(&mut self) -> Result<Option<Receipt>, Error> {
        self.refresh().await?;
        Ok(self.loaded()?.metadata.output.clone())
    }

    /// Clear a durably published output by exact ID. Repeating acknowledgement after
    /// it was cleared succeeds; a different still-pending output can never be cleared.
    pub async fn acknowledge(&mut self, operation: OperationId) -> Result<(), Error> {
        self.refresh().await?;
        self.now()?;
        let mut candidate = self.loaded()?.clone();
        match &candidate.metadata.output {
            None => return Ok(()),
            Some(output) if output.operation == operation => {}
            _ => return Err(Error::Unauthorized),
        }
        candidate.metadata.output = None;
        let expected = candidate.stamp;
        self.prepare(candidate, Some(expected), None)?;
        self.commit().await?;
        Ok(())
    }

    /// Acknowledge only the exact original pending Created operation admitted
    /// by its sealed completion owner. Public intent arguments cannot substitute.
    /// The original SecureStore CAS commits provenance and cleared output together.
    pub async fn acknowledge_initial(
        &mut self,
        completion: &mut PendingCompletion,
    ) -> Result<(), Error> {
        self.refresh().await?;
        completion.check_current(&mut self.clock, &mut self.authority)?;
        let now = self.now()?;
        let mut candidate = self.loaded()?.clone();
        let initial = completion.bind_acknowledgment(&candidate, now)?;
        let completion = completion.acknowledgment_guard();
        candidate.metadata.initial = Some(initial);
        candidate.metadata.version = 2;
        candidate.metadata.output = None;
        let expected = candidate.stamp;
        self.prepare(candidate, Some(expected), None)?;
        self.commit().await?;
        // A successful backend CAS may have crossed the original deadline or
        // lost the live key lease. Keep the durable winner, but no live owner
        // survives an uncertain post-write authority outcome.
        match completion.finish(&mut self.clock, &mut self.authority, self.last_time) {
            Ok(completed) => self.last_time = completed,
            _ => {
                self.fail_closed(State::Reconcile);
                return Err(Error::Reconcile);
            }
        }
        Ok(())
    }

    /// Return current public lineage after checking local freshness and live authority.
    pub async fn lineage(&mut self) -> Result<Lineage, Error> {
        self.authorize(Action::Use, None, None, &[]).await?;
        Ok(self.loaded()?.metadata.lineage.clone())
    }

    /// Read only the current lineage device key under fresh authority. This does
    /// not lend a signer or consume a signing intent.
    pub async fn device_public_key(&mut self) -> Result<PublicKey, Error> {
        self.authorize(Action::Use, None, None, &[]).await?;
        self.refresh().await?;
        self.now()?;
        Ok(vld0::public_key(&self.loaded()?.material.device))
    }

    /// Sign exactly the borrowed original owner transcript after distinct,
    /// one-use intent and current G3 authorization. No generic signer escapes.
    /// The trusted composer supplies the original exclusive grant deadline and
    /// retains its IntentGuard through the downstream operation, including waits.
    pub async fn sign_device_ed25519(
        &mut self,
        transcript: &[u8],
        expires: u64,
    ) -> Result<[u8; 64], Error> {
        self.writable()?;
        self.authorize_with_signing(
            Action::SignDeviceEd25519,
            None,
            None,
            &[],
            Some(crate::DeviceSigning {
                transcript,
                expires,
            }),
        )
        .await?;
        // Authorization can suspend; refuse a replaced/locked checkpoint and
        // expired or regressed clock before touching the device signer. Exact
        // local intent has already been consumed even when these checks refuse.
        self.refresh().await?;
        if self.now()? >= expires {
            self.fail_closed(State::Locked);
            return Err(Error::Expired);
        }
        let secret = &self.loaded()?.material.device;
        Ed25519Signer {
            secret,
            public_key: *vld0::public_key(secret).value(),
        }
        .sign(transcript)
    }

    /// Authorized local access to private device metadata; never included in network outputs.
    pub async fn device_info(&mut self) -> Result<DeviceInfo, Error> {
        self.authorize(Action::Use, None, None, &[]).await?;
        Ok(self.loaded()?.metadata.info.clone())
    }

    /// Rename this device in its encrypted checkpoint without changing public lineage
    /// or its immutable authority reference. The name never becomes a network output.
    pub async fn rename_device(&mut self, name: &str) -> Result<(), Error> {
        self.writable()?;
        self.authorize(Action::Use, None, None, &[]).await?;
        let mut candidate = self.loaded()?.clone();
        candidate.metadata.info =
            DeviceInfo::new(name, candidate.metadata.info.authority_reference())?;
        let expected = candidate.stamp;
        self.prepare(candidate, Some(expected), None)?;
        self.commit().await?;
        Ok(())
    }

    /// Verify a pending device's proof and the injected pairing approval, then atomically
    /// add it and seal the root. No transfer leaves before the write commits.
    pub async fn authorize_device(
        &mut self,
        request: &PairingRequest,
        evidence: &[u8],
    ) -> Result<Receipt, Error> {
        self.writable()?;
        request.verify(self.now()?)?;
        self.authorize(
            Action::Pair,
            Some(request.device),
            Some(request.digest()?),
            evidence,
        )
        .await?;
        // Authority adapters can await external work; recheck time before sealing.
        request.verify(self.now()?)?;
        let mut candidate = self.loaded()?.clone();
        let previous = &candidate.metadata.lineage;
        if request.binding != previous.binding
            || request.root != previous.root
            || request.epoch != previous.epoch
            || previous.devices.contains(&request.device)
        {
            return Err(Error::Unauthorized);
        }
        if previous.devices.len() >= MAX_DEVICES {
            return Err(Error::Limit);
        }
        let lineage = &mut candidate.metadata.lineage;
        lineage.revision = lineage.revision.checked_add(1).ok_or(Error::Limit)?;
        lineage.devices.push(request.device);
        lineage.devices.sort();
        lineage.signature = vld0::sign(candidate.material.root()?, &lineage.signed_bytes()?)?;
        let mut grant = PairingGrant {
            version: candidate.material.transfer_version(),
            request: request.clone(),
            lineage: lineage.clone(),
            sealed_root: Vec::new(),
            signature: empty_signature(),
        };
        grant.sealed_root = vld0::seal_to(
            &mut self.entropy,
            &request.device,
            &grant.aad()?,
            &candidate.material.transfer()?,
        )?;
        grant.signature = vld0::sign(candidate.material.root()?, &grant.signed_bytes()?)?;
        let expected = candidate.stamp;
        self.prepare(
            candidate,
            Some(expected),
            Some(Change::DeviceAuthorized(Box::new(grant))),
        )?;
        self.commit().await?.ok_or(Error::Crypto)
    }

    /// Accept only the exact pending challenge and confirmed root. A paired device
    /// cannot import arbitrary roots or replay a prior grant.
    pub async fn accept_pairing(
        &mut self,
        grant: &PairingGrant,
        evidence: &[u8],
    ) -> Result<Receipt, Error> {
        self.writable()?;
        grant.request.verify(self.now()?)?;
        self.refresh().await?;
        let mut candidate = self.loaded()?.clone();
        if candidate.metadata.pairing.as_ref() != Some(&grant.request) {
            return Err(Error::Unauthorized);
        }
        let previous = &candidate.metadata.lineage;
        grant.lineage.verify()?;
        if grant.lineage.version != previous.version
            || grant.lineage.identity != previous.identity
            || grant.lineage.binding != previous.binding
            || grant.lineage.root != previous.root
            || grant.lineage.epoch != previous.epoch
            || grant.lineage.revision <= previous.revision
            || !grant.lineage.devices.contains(&grant.request.device)
            || !previous
                .devices
                .iter()
                .all(|d| grant.lineage.devices.contains(d))
        {
            return Err(Error::Unauthorized);
        }
        vld0::verify(&previous.root, &grant.signed_bytes()?, &grant.signature)?;
        self.authorize(
            Action::Adopt,
            Some(grant.request.device),
            Some(grant.request.digest()?),
            evidence,
        )
        .await?;
        grant.request.verify(self.now()?)?;
        let plaintext = vld0::open(
            &candidate.material.device,
            &grant.aad()?,
            &grant.sealed_root,
        )?;
        candidate.material.receive(grant.version, &plaintext)?;
        if vld0::public_key(candidate.material.root()?) != previous.root {
            return Err(Error::InvalidKey);
        }
        candidate.metadata.pairing = None;
        candidate.metadata.lineage = grant.lineage.clone();
        let expected = candidate.stamp;
        self.prepare(
            candidate,
            Some(expected),
            Some(Change::Paired(grant.lineage.clone())),
        )?;
        self.commit().await?.ok_or(Error::Crypto)
    }

    /// Adopt additions made by another authorized device in the same root epoch.
    /// Removal, rollback and same-revision equivocation are refused here.
    pub async fn adopt_lineage(
        &mut self,
        next: &Lineage,
        evidence: &[u8],
    ) -> Result<Receipt, Error> {
        self.writable()?;
        next.verify()?;
        self.authorize(Action::Adopt, None, Some(next.digest()?), evidence)
            .await?;
        let mut candidate = self.loaded()?.clone();
        let previous = &candidate.metadata.lineage;
        if next.version != previous.version
            || next.identity != previous.identity
            || next.binding != previous.binding
            || next.root != previous.root
            || next.epoch != previous.epoch
            || next.revision <= previous.revision
            || !previous.devices.iter().all(|d| next.devices.contains(d))
        {
            return Err(Error::Unauthorized);
        }
        candidate.metadata.lineage = next.clone();
        let expected = candidate.stamp;
        self.prepare(
            candidate,
            Some(expected),
            Some(Change::Adopted(next.clone())),
        )?;
        self.commit().await?.ok_or(Error::Crypto)
    }

    /// Prepare a root replacement that removes one other device. No output or new key
    /// is usable until commit. The pseudonym and all non-key domain state are unchanged.
    pub async fn prepare_rotation(
        &mut self,
        revoked: PublicKey,
        evidence: &[u8],
    ) -> Result<(), Error> {
        self.writable()?;
        let previous = self.loaded()?.metadata.lineage.clone();
        if revoked == vld0::public_key(&self.loaded()?.material.device)
            || !previous.devices.contains(&revoked)
        {
            return Err(Error::Unauthorized);
        }
        self.authorize(
            Action::Rotate,
            Some(revoked),
            Some(previous.digest()?),
            evidence,
        )
        .await?;
        let mut candidate = self.loaded()?.clone();
        let mut next = previous.clone();
        next.epoch = next.epoch.checked_add(1).ok_or(Error::Limit)?;
        let root = vld0::random_secret(&mut self.entropy)?;
        next.root = vld0::public_key(&root);
        next.revision = next.revision.checked_add(1).ok_or(Error::Limit)?;
        next.devices.retain(|d| *d != revoked);
        next.signature = vld0::sign(&root, &next.signed_bytes()?)?;
        let mut replacement = candidate.material.clone();
        replacement
            .history
            .push((previous.epoch, candidate.material.root()?.clone()));
        replacement.root = Some(root.clone());
        let mut rotation = Rotation {
            version: replacement.transfer_version(),
            predecessor: previous.digest()?,
            previous_root: previous.root,
            revoked,
            lineage: next.clone(),
            envelopes: Vec::new(),
            signature: empty_signature(),
        };
        let transfer = replacement.transfer()?;
        for device in &next.devices {
            let sealed_root = vld0::seal_to(
                &mut self.entropy,
                device,
                &rotation.aad(*device)?,
                &transfer,
            )?;
            rotation.envelopes.push(RootEnvelope {
                device: *device,
                sealed_root,
            });
        }
        rotation.signature = vld0::sign(candidate.material.root()?, &rotation.signed_bytes()?)?;
        rotation.verify(&previous)?;
        candidate.material = replacement;
        candidate.metadata.lineage = next;
        let expected = candidate.stamp;
        self.prepare(
            candidate,
            Some(expected),
            Some(Change::Rotated(Box::new(rotation))),
        )?;
        self.prepared
            .as_mut()
            .ok_or(Error::Pending)?
            .rotation_approval = Some(Zeroizing::new(evidence.to_vec()));
        Ok(())
    }

    /// Apply an exact authenticated succession. Removed devices erase their root;
    /// surviving devices open only their own envelope. A stale predecessor fails.
    pub async fn apply_rotation(
        &mut self,
        rotation: &Rotation,
        evidence: &[u8],
    ) -> Result<Receipt, Error> {
        self.writable()?;
        self.refresh().await?;
        let mut candidate = self.loaded()?.clone();
        rotation.verify(&candidate.metadata.lineage)?;
        let now = self.now()?;
        let device = vld0::public_key(&candidate.material.device);
        // Adoption asks about the new epoch, so a current authority adapter need not
        // temporarily reauthorize a removed old device to let it erase its root.
        self.check_authority(Authorization {
            binding: &rotation.lineage.binding,
            root: Some(rotation.lineage.root),
            device,
            epoch: rotation.lineage.epoch,
            action: Action::Adopt,
            target: Some(rotation.revoked),
            statement: Some(digest(b"ckmg.rotation.digest.v1\0", rotation)?),
            signing: None,
            now,
            evidence,
        })
        .await?;
        let change = if device == rotation.revoked {
            candidate.material.root = None;
            candidate.material.identity = None;
            candidate.material.history.clear();
            candidate.metadata.revoked = true;
            Change::Revoked(rotation.lineage.clone())
        } else {
            let envelope = rotation
                .envelopes
                .iter()
                .find(|e| e.device == device)
                .ok_or(Error::Unauthorized)?;
            let plaintext = vld0::open(
                &candidate.material.device,
                &rotation.aad(device)?,
                &envelope.sealed_root,
            )?;
            let mut expected_history = candidate.material.history.clone();
            expected_history.push((
                candidate.metadata.lineage.epoch,
                candidate.material.root()?.clone(),
            ));
            candidate.material.receive(rotation.version, &plaintext)?;
            if rotation.version < 3 {
                // Old signed rotations have no history transfer; preserve the
                // exact locally authenticated predecessor without rewriting bytes.
                candidate.material.history = expected_history;
            } else if candidate.material.history != expected_history {
                return Err(Error::InvalidKey);
            }
            if vld0::public_key(candidate.material.root()?) != rotation.lineage.root {
                return Err(Error::InvalidKey);
            }
            Change::Adopted(rotation.lineage.clone())
        };
        candidate.metadata.lineage = rotation.lineage.clone();
        let expected = candidate.stamp;
        self.prepare(candidate, Some(expected), Some(change))?;
        self.commit().await?.ok_or(Error::Crypto)
    }

    /// Obtain a purpose capability and device-signed public certificate. The handle
    /// is invalid after lock, restore, root rotation, or current-device revocation.
    pub async fn key(&mut self, purpose: Purpose) -> Result<KeyHandle, Error> {
        purpose.validate()?;
        if let Some(node) = NodePurpose::of(&purpose) {
            // A durable pending receipt must be publishable before member
            // authority exists. This does not permit a prepared/uncertain write.
            self.authorize(Action::UseTransport(node), None, None, &[])
                .await?;
            self.refresh().await?;
            self.now()?;
        } else {
            self.writable()?;
            self.authorize(Action::Use, None, None, &[]).await?;
        }
        let current = self.loaded()?;
        let secret = purpose_secret(current, &purpose, false)?;
        let mut certificate = KeyCertificate {
            binding: current.metadata.lineage.binding.clone(),
            epoch: current.metadata.lineage.epoch,
            device: vld0::public_key(&current.material.device),
            purpose,
            key: vld0::public_key(&secret),
            signature: empty_signature(),
        };
        certificate.signature = vld0::sign(&current.material.device, &certificate.signed_bytes()?)?;
        Ok(KeyHandle {
            session: current.session,
            certificate,
        })
    }

    /// Explicitly migrate a legacy compound wrapper through the original atomic
    /// SecureStore port. No cipher escapes Keys. The enclosing Vault must stage
    /// its version/operation fence first; cancellation requires reconciliation.
    pub async fn migrate_compound_wrapping(&mut self) -> Result<(), Error> {
        self.writable()?;
        self.authorize(Action::Use, None, None, &[]).await?;
        self.refresh().await?;
        self.now()?;
        let candidate = self.loaded()?.clone();
        candidate.material.root()?;
        let expected = candidate.stamp;
        self.prepare(candidate, Some(expected), None)?;
        self.prepared.as_mut().ok_or(Error::Pending)?.rewrap = true;
        self.commit().await?;
        self.authorize(Action::Use, None, None, &[]).await?;
        self.refresh().await?;
        self.now()?;
        Ok(())
    }

    async fn check_handle(&mut self, handle: &KeyHandle) -> Result<(), Error> {
        self.writable()?;
        self.authorize(Action::Use, None, None, &[]).await?;
        self.validate_handle(handle)
    }

    async fn check_transport_handle(
        &mut self,
        handle: &KeyHandle,
        purpose: NodePurpose,
    ) -> Result<(), Error> {
        if NodePurpose::of(&handle.certificate.purpose) != Some(purpose) {
            return Err(Error::Unauthorized);
        }
        if self.loaded()?.metadata.revoked {
            return Err(Error::Revoked);
        }
        self.validate_handle(handle)?;
        self.authorize(Action::UseTransport(purpose), None, None, &[])
            .await?;
        self.refresh().await?;
        self.now()?;
        self.validate_handle(handle)
    }

    fn validate_handle(&self, handle: &KeyHandle) -> Result<(), Error> {
        let current = self.loaded()?;
        if handle.session != current.session {
            return Err(Error::Unauthorized);
        }
        handle
            .certificate
            .verify(&current.metadata.lineage, &handle.certificate.purpose)?;
        if handle.certificate.device != vld0::public_key(&current.material.device) {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    /// VLD0-sign exact owner bytes. Verify the handle's certificate against current
    /// lineage and expected purpose before accepting the signature. This retains
    /// Veilid DHT wire compatibility without adding a second owner transcript.
    pub async fn sign(
        &mut self,
        handle: &KeyHandle,
        transcript: &[u8],
    ) -> Result<Signature, Error> {
        if transcript.len() > MAX_MESSAGE_BYTES {
            return Err(Error::Limit);
        }
        self.check_handle(handle).await?;
        vld0::sign(
            &purpose_secret(self.loaded()?, &handle.certificate.purpose, false)?,
            transcript,
        )
    }

    /// Plain Ed25519 for upstream formats such as OpenMLS and cgrd. The returned bytes
    /// are deliberately not labeled a VLD0 signature. Same authority/certificate checks.
    pub async fn sign_ed25519(
        &mut self,
        handle: &KeyHandle,
        transcript: &[u8],
    ) -> Result<[u8; 64], Error> {
        if transcript.len() > MAX_MESSAGE_BYTES {
            return Err(Error::Limit);
        }
        self.check_handle(handle).await?;
        Ok(vld0::sign_ed25519(
            &purpose_secret(self.loaded()?, &handle.certificate.purpose, false)?,
            transcript,
        ))
    }

    /// Check current authority asynchronously, then lend a synchronous purpose
    /// signer to an engine such as OpenMLS. The callback cannot retain the signer
    /// or borrow its secret beyond this call. The derived seed is wiped on return
    /// or unwinding. Fresh authority is checked again on every invocation.
    ///
    /// ```compile_fail
    /// # use ckmg::*;
    /// # async fn escape<S: SecureStore, C: Clock, R: Entropy, A: Authority>(
    /// #     keys: &mut Keys<S, C, R, A>, handle: &KeyHandle) {
    /// let retained = keys.with_ed25519_signer(handle, |signer| signer).await;
    /// # }
    /// ```
    pub async fn with_ed25519_signer<T>(
        &mut self,
        handle: &KeyHandle,
        use_signer: impl for<'key> FnOnce(Ed25519Signer<'key>) -> T,
    ) -> Result<T, Error> {
        self.check_handle(handle).await?;
        let secret = purpose_secret(self.loaded()?, &handle.certificate.purpose, false)?;
        Ok(use_signer(Ed25519Signer {
            secret: &secret,
            public_key: *handle.certificate.key.value(),
        }))
    }

    /// Lend a synchronous VLD0 purpose signer for original descriptor/value bytes.
    /// Authorization, lifetime and zeroization match `with_ed25519_signer`.
    ///
    /// ```compile_fail
    /// # use ckmg::*;
    /// # async fn escape<S: SecureStore, C: Clock, R: Entropy, A: Authority>(
    /// #     keys: &mut Keys<S, C, R, A>, handle: &KeyHandle) {
    /// let retained = keys.with_vld0_signer(handle, |signer| signer).await;
    /// # }
    /// ```
    pub async fn with_vld0_signer<T>(
        &mut self,
        handle: &KeyHandle,
        use_signer: impl for<'key> FnOnce(Vld0Signer<'key>) -> T,
    ) -> Result<T, Error> {
        self.with_ed25519_signer(handle, |signer| use_signer(Vld0Signer(signer)))
            .await
    }

    /// Lend the same device-purpose signer and node DH cipher to an original
    /// VLD0 envelope owner. Each call checks the exact `tor.node` device purpose,
    /// unlocked session and fresh transport authority. Local certificate binding
    /// is checked without requiring a remote member-lineage read through this node.
    /// Only owned signed/encrypted output can cross the following network await.
    ///
    /// ```compile_fail
    /// # use ckmg::*;
    /// # async fn escape<S: SecureStore, C: Clock, R: Entropy, A: Authority>(
    /// #     keys: &mut Keys<S, C, R, A>, handle: &KeyHandle) {
    /// let retained = keys.with_vld0_node(handle, |_, cipher| cipher).await;
    /// # }
    /// ```
    pub async fn with_vld0_node<T>(
        &mut self,
        handle: &KeyHandle,
        use_node: impl for<'key> FnOnce(Vld0Signer<'key>, crate::Vld0NodeCipher<'key>) -> T,
    ) -> Result<T, Error> {
        self.check_transport_handle(handle, NodePurpose::Vld0)
            .await?;
        let secret = purpose_secret(self.loaded()?, &handle.certificate.purpose, false)?;
        let public_key = *handle.certificate.key.value();
        Ok(use_node(
            Vld0Signer(Ed25519Signer {
                secret: &secret,
                public_key,
            }),
            crate::Vld0NodeCipher {
                secret: &secret,
                public_key,
            },
        ))
    }

    /// Lend the original Veilid record cipher without exporting its read secret.
    /// A separate derivation context prevents sharing a key with purpose AEAD.
    /// The record adapter owns nonce freshness and verification of the signed
    /// value before decryption. Current authority is checked for every call.
    ///
    /// ```compile_fail
    /// # use ckmg::*;
    /// # async fn escape<S: SecureStore, C: Clock, R: Entropy, A: Authority>(
    /// #     keys: &mut Keys<S, C, R, A>, handle: &KeyHandle) {
    /// let retained = keys.with_vld0_record_cipher(handle, |cipher| cipher).await;
    /// # }
    /// ```
    pub async fn with_vld0_record_cipher<T>(
        &mut self,
        handle: &KeyHandle,
        use_cipher: impl for<'key> FnOnce(crate::Vld0RecordCipher<'key>) -> T,
    ) -> Result<T, Error> {
        self.check_handle(handle).await?;
        let purpose = purpose_secret(self.loaded()?, &handle.certificate.purpose, true)?;
        let secret = Zeroizing::new(blake3::derive_key(
            "ckmg 2026-10 VLD0 record encryption v1",
            &*purpose,
        ));
        Ok(use_cipher(crate::Vld0RecordCipher { secret: &secret }))
    }

    /// Lend the original record signer and read cipher together for synchronous
    /// signed queue preparation. This uses the same separate derivation contexts
    /// as the individual capabilities and checks current authority once for the
    /// entire borrow. Persist the prepared output before network publication.
    ///
    /// ```compile_fail
    /// # use ckmg::*;
    /// # async fn escape<S: SecureStore, C: Clock, R: Entropy, A: Authority>(
    /// #     keys: &mut Keys<S, C, R, A>, handle: &KeyHandle) {
    /// let retained = keys.with_vld0_record(handle, |signer, _| signer).await;
    /// # }
    /// ```
    pub async fn with_vld0_record<T>(
        &mut self,
        handle: &KeyHandle,
        use_record: impl for<'key> FnOnce(Vld0Signer<'key>, crate::Vld0RecordCipher<'key>) -> T,
    ) -> Result<T, Error> {
        self.check_handle(handle).await?;
        let current = self.loaded()?;
        let signer = purpose_secret(current, &handle.certificate.purpose, false)?;
        let purpose = purpose_secret(current, &handle.certificate.purpose, true)?;
        let cipher = Zeroizing::new(blake3::derive_key(
            "ckmg 2026-10 VLD0 record encryption v1",
            &*purpose,
        ));
        Ok(use_record(
            Vld0Signer(Ed25519Signer {
                secret: &signer,
                public_key: *handle.certificate.key.value(),
            }),
            crate::Vld0RecordCipher { secret: &cipher },
        ))
    }

    /// Lend the actual lineage device signer for upstream plain-Ed25519 formats
    /// such as profile publication. Its public key is a member of `Lineage.devices`,
    /// unlike a purpose key. Current server/device authority is checked first.
    /// This requests LendDeviceSigner, never metadata Use or exact transcript
    /// admission. The authority must explicitly allow this broader owner operation.
    /// This capability is never a replacement for the server's G3 authorization.
    ///
    /// ```compile_fail
    /// # use ckmg::*;
    /// # async fn escape<S: SecureStore, C: Clock, R: Entropy, A: Authority>(
    /// #     keys: &mut Keys<S, C, R, A>) {
    /// let retained = keys.with_device_ed25519_signer(|signer| signer).await;
    /// # }
    /// ```
    pub async fn with_device_ed25519_signer<T>(
        &mut self,
        use_signer: impl for<'key> FnOnce(DeviceEd25519Signer<'key>) -> T,
    ) -> Result<T, Error> {
        self.writable()?;
        self.authorize(Action::LendDeviceSigner, None, None, &[])
            .await?;
        let secret = &self.loaded()?.material.device;
        Ok(use_signer(DeviceEd25519Signer(Ed25519Signer {
            secret,
            public_key: *vld0::public_key(secret).value(),
        })))
    }

    /// Export this member's OWN lineage-record read capability so a peer can read
    /// it (the Veilid record-key model). Requires fresh live-device `Use`
    /// authorization with the current lineage. It covers only this scope's own
    /// lineage record and never carries a writer, root, device or Store secret.
    /// The caller may place the bytes only inside its own signed message.
    pub async fn export_lineage_read_capability(&mut self) -> Result<LineageReadCapability, Error> {
        self.writable()?;
        self.authorize(Action::Use, None, None, &[]).await?;
        let current = self.loaded()?;
        crate::keys::inspection::lineage_read_capability(
            current.material.root()?,
            &current.metadata.lineage,
        )
    }

    /// Lend the originating scope identity after fresh live-device authorization.
    /// Pairing and retained checkpoints preserve this identity across distinct PRFs.
    /// The borrowed capability and secret material cannot escape the callback.
    pub async fn with_identity<T>(
        &mut self,
        use_identity: impl for<'call> FnOnce(&'call passkey::IdentityRoots) -> T,
    ) -> Result<T, Error> {
        self.writable()?;
        self.authorize(Action::Use, None, None, &[]).await?;
        let current = self.loaded()?;
        let seeds = current
            .material
            .identity
            .as_ref()
            .ok_or(Error::MissingCheckpoint)?;
        let roots = passkey::IdentityRoots::retained(
            current.metadata.lineage.binding.community(),
            vld0::public_key(&current.material.device),
            seeds,
        )?;
        Ok(use_identity(&roots))
    }

    /// Lend original Profile signing and Envelope custody after distinct current
    /// authority and post-await checkpoint/clock checks. Private buffers are
    /// zeroized when this synchronous callback ends; ReadKey cannot escape it.
    ///
    /// ```compile_fail
    /// # use ckmg::*;
    /// # async fn escape<S: SecureStore, C: Clock, R: Entropy, A: Authority>(
    /// # keys: &mut Keys<S,C,R,A>) {
    /// let retained = keys.with_profile_custody(|_, custody| custody).await;
    /// # }
    /// ```
    #[cfg(feature = "profile-envelope")]
    pub async fn with_profile_custody<T>(
        &mut self,
        consume: impl for<'key> FnOnce(DeviceEd25519Signer<'key>, cnvl::Custodian<'key>) -> T,
    ) -> Result<T, Error> {
        self.writable()?;
        self.authorize(Action::LendProfileCustody, None, None, &[])
            .await?;
        self.refresh().await?;
        self.now()?;
        let current = self.loaded()?;
        let binding = &current.metadata.lineage.binding;
        let common = current
            .material
            .identity
            .as_ref()
            .ok_or(Error::MissingCheckpoint)?;
        let wrapping = passkey::profile_storage_key(common, binding.community())?;
        let hpke = vld0::x25519_secret(&current.material.device);
        let public = *vld0::public_key(&current.material.device).value();
        let custody = cnvl::Custodian::from_keys(
            &hpke,
            &wrapping,
            binding.community(),
            binding.member(),
            public,
        )
        .map_err(|_| Error::Crypto)?;
        let signer = DeviceEd25519Signer(Ed25519Signer {
            secret: &current.material.device,
            public_key: public,
        });
        Ok(consume(signer, custody))
    }

    /// Migrate only an original encrypted v1 Profile key to Envelope's immutable
    /// common-root storage purpose. No raw profile/wrapping key crosses this API.
    /// Profile must atomically persist the returned encrypted bytes before use.
    #[cfg(feature = "profile-envelope")]
    pub async fn migrate_profile_key(
        &mut self,
        legacy: &passkey::StoreCipher,
        context: cnvl::Context,
        wrapped: &[u8],
    ) -> Result<cnvl::WrappedReadKey, Error> {
        self.with_profile_custody(|_, custody| {
            custody
                .restore_legacy_store(context, wrapped, legacy.envelope_legacy_key())
                .and_then(|key| key.wrap())
                .map_err(|_| Error::Crypto)
        })
        .await?
    }

    /// Lend one opaque holder initializer after fresh current device authority.
    /// Wallet consumes it; Keys never retains a Wallet engine or returns seed bytes.
    /// The borrowed capability cannot escape this call.
    ///
    /// ```compile_fail
    /// # use ckmg::*;
    /// # async fn escape<S: SecureStore, C: Clock, R: Entropy, A: Authority>(
    /// #     keys: &mut Keys<S, C, R, A>) {
    /// let retained = keys.with_holder_seed(|seed| seed).await;
    /// # }
    /// ```
    #[cfg(feature = "passport")]
    pub async fn with_holder_seed<T>(
        &mut self,
        consume: impl for<'key> FnOnce(passkey::HolderSeed<'key>) -> T,
    ) -> Result<T, Error> {
        self.with_identity(|identity| consume(identity.holder_seed()))
            .await
    }

    /// Initialize the original pure Wallet engine under fresh current custody.
    /// It retains an immutable purpose key; no root/seed/RNG callback or rekey
    /// operation is exposed. Initialization grants no accepted balance or Wave.
    /// Upper Wallet consumes the exact types reexported in `wallet_engine`.
    #[cfg(feature = "wallet-engine")]
    pub async fn wallet_engine(&mut self) -> Result<crate::wallet_engine::Engine, Error> {
        self.with_identity(|identity| identity.wallet_engine())
            .await?
    }

    /// The same engine for the one moment the ordinary path is closed: the exact
    /// original `Created` output is still pending and its acknowledgment is the
    /// transaction that initializes the Wallet records. The caller names the
    /// receipt; it must equal the durable pending output, which must be a
    /// `Created` change, both before and after fresh current Use authority.
    /// Any other pending output, or none, is refused; no other write is enabled.
    #[cfg(feature = "wallet-engine")]
    pub async fn wallet_engine_for_pending_creation(
        &mut self,
        receipt: &Receipt,
    ) -> Result<crate::wallet_engine::Engine, Error> {
        self.refresh().await?;
        self.check_pending_creation(receipt)?;
        self.authorize(Action::Use, None, None, &[]).await?;
        self.check_pending_creation(receipt)?;
        let current = self.loaded()?;
        let seeds = current
            .material
            .identity
            .as_ref()
            .ok_or(Error::MissingCheckpoint)?;
        let roots = passkey::IdentityRoots::retained(
            current.metadata.lineage.binding.community(),
            vld0::public_key(&current.material.device),
            seeds,
        )?;
        roots.wallet_engine()
    }

    #[cfg(feature = "wallet-engine")]
    fn check_pending_creation(&self, receipt: &Receipt) -> Result<(), Error> {
        let pending = self.loaded()?.metadata.output.as_ref();
        if !matches!(receipt.change, Change::Created(_)) || pending != Some(receipt) {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    /// Lend the dedicated common-root record recipient after fresh normal Use.
    /// Scope comes from this loaded original Binding, never a caller domain.
    /// Fetch the whole bounded object first, then freshly authenticate its Epoch
    /// and invoke this synchronous callback. Transport opening is not account
    /// initialization or proof authority; no recipient can survive an await.
    ///
    /// ```compile_fail
    /// # use ckmg::*;
    /// # async fn escape<S: SecureStore, C: Clock, R: Entropy, A: Authority>(
    /// #     keys: &mut Keys<S, C, R, A>) {
    /// let retained = keys.with_record_recipient(|recipient| recipient).await;
    /// # }
    /// ```
    #[cfg(feature = "wallet-engine")]
    pub async fn with_record_recipient<T>(
        &mut self,
        consume: impl for<'key> FnOnce(crate::wallet_engine::RecordRecipient<'key>) -> T,
    ) -> Result<T, Error> {
        self.writable()?;
        let mut attempt = current_signing::Attempt {
            keys: self,
            accepted: false,
        };
        attempt
            .keys
            .authorize_with_check(Action::Use, None, None, &[], CurrentCheck::RecordRecipient)
            .await?;
        attempt.keys.refresh().await?;
        let now = attempt.keys.now()?;
        let current = attempt.keys.loaded()?;
        let binding = current.metadata.lineage.binding.clone();
        let root = current.metadata.lineage.root;
        let epoch = current.metadata.lineage.epoch;
        let device = vld0::public_key(&current.material.device);
        let floor = match attempt
            .keys
            .authority
            .check_record_recipient_current(Authorization {
                binding: &binding,
                root: Some(root),
                device,
                epoch,
                action: Action::Use,
                target: None,
                statement: None,
                signing: None,
                now,
                evidence: &[],
            }) {
            Ok(floor) => floor,
            Err(error) => {
                attempt.keys.fail_closed(if error == Error::Revoked {
                    State::Revoked
                } else {
                    State::Locked
                });
                return Err(error);
            }
        };
        let completed = attempt.keys.now()?;
        if completed < floor {
            attempt.keys.fail_closed(State::Locked);
            return Err(Error::Clock);
        }
        let current = attempt.keys.loaded()?;
        let common = current
            .material
            .identity
            .as_ref()
            .ok_or(Error::MissingCheckpoint)?;
        let output = passkey::with_record_recipient(
            common,
            current.metadata.lineage.binding.community(),
            completed,
            consume,
        )?;
        attempt.accepted = true;
        Ok(output)
    }

    /// Restore only the engine's authenticated original ciphertext inside fresh
    /// Keys custody. Wallet must still reconcile its original Store and accepted
    /// state; successful sealing/opening alone grants no release authority.
    #[cfg(feature = "wallet-engine")]
    pub async fn restore_wallet_engine(
        &mut self,
        sealed: &crate::wallet_engine::Sealed,
    ) -> Result<crate::wallet_engine::Engine, Error> {
        self.wallet_engine()
            .await?
            .restored(sealed)
            .map_err(|_| Error::Open)
    }

    /// Encrypt bounded data with current device, epoch, purpose and caller context.
    /// Member-scope ciphertext opens on paired devices.
    pub async fn seal(
        &mut self,
        handle: &KeyHandle,
        context: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if context.len() > 4096 || plaintext.len() > MAX_MESSAGE_BYTES {
            return Err(Error::Limit);
        }
        self.check_handle(handle).await?;
        let current = self.loaded()?;
        let aad = purpose_aad(current, &handle.certificate.purpose, context)?;
        let key = purpose_secret(current, &handle.certificate.purpose, true)?;
        let mut sealed = PURPOSE_HEADER.to_vec();
        sealed.extend_from_slice(&keyring::seal(&mut self.entropy, &key, &aad, plaintext)?);
        Ok(sealed)
    }

    /// Authenticated purpose decryption; failed opens return no plaintext.
    pub async fn open(
        &mut self,
        handle: &KeyHandle,
        context: &[u8],
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        if context.len() > 4096 || sealed.len() > MAX_MESSAGE_BYTES + PURPOSE_HEADER.len() + 40 {
            return Err(Error::Limit);
        }
        self.check_handle(handle).await?;
        let current = self.loaded()?;
        let aad = purpose_aad(current, &handle.certificate.purpose, context)?;
        let key = purpose_secret(current, &handle.certificate.purpose, true)?;
        keyring::open(
            &key,
            &aad,
            sealed.strip_prefix(PURPOSE_HEADER).ok_or(Error::Open)?,
        )
    }

    /// Open retained purpose ciphertext from an earlier epoch under fresh current
    /// device authority. A current handle is mandatory; stale handles remain refused.
    /// Historical roots cannot sign, issue certificates, or encrypt new records.
    pub async fn open_historical(
        &mut self,
        handle: &KeyHandle,
        epoch: u64,
        context: &[u8],
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        if context.len() > 4096 || sealed.len() > MAX_MESSAGE_BYTES + PURPOSE_HEADER.len() + 40 {
            return Err(Error::Limit);
        }
        self.check_handle(handle).await?;
        let current = self.loaded()?;
        let root = historical_root(current, epoch)?;
        let aad = purpose_aad_at(current, &handle.certificate.purpose, epoch, context)?;
        let key = purpose_secret_at(current, &handle.certificate.purpose, true, epoch, root)?;
        keyring::open(
            &key,
            &aad,
            sealed.strip_prefix(PURPOSE_HEADER).ok_or(Error::Open)?,
        )
    }

    /// Borrow only historical VLD0 opening custody after fresh current authorization.
    /// Records must first verify the original signed value and its nonce. This does
    /// not restore, copy or resume an MLS ratchet; Threads owns that continuation.
    pub async fn with_historical_vld0_reader<T>(
        &mut self,
        handle: &KeyHandle,
        epoch: u64,
        read: impl for<'key> FnOnce(crate::Vld0RecordReader<'key>) -> T,
    ) -> Result<T, Error> {
        self.check_handle(handle).await?;
        let current = self.loaded()?;
        let root = historical_root(current, epoch)?;
        let purpose = purpose_secret_at(current, &handle.certificate.purpose, true, epoch, root)?;
        let secret = Zeroizing::new(blake3::derive_key(
            "ckmg 2026-10 VLD0 record encryption v1",
            &*purpose,
        ));
        Ok(read(crate::Vld0RecordReader {
            cipher: crate::Vld0RecordCipher { secret: &secret },
        }))
    }

    /// Transfer only this freshly authorized purpose's signing/read custody into
    /// the maintained native record engine. The opaque initializer has no key
    /// getter, Clone, Debug or serialization. Mesh consumes it in its sole core.
    /// Lock/revocation requires the composer to close any previously opened record.
    #[cfg(all(feature = "native-records", not(target_arch = "wasm32")))]
    pub async fn native_record_initializer(
        &mut self,
        handle: &KeyHandle,
        schema: crate::NativeRecordSchema,
    ) -> Result<crate::NativeRecordInitializer, Error> {
        self.check_handle(handle).await?;
        let current = self.loaded()?;
        let owner = purpose_secret(current, &handle.certificate.purpose, false)?;
        let cipher = purpose_secret(current, &handle.certificate.purpose, true)?;
        let read = Zeroizing::new(blake3::derive_key(
            "ckmg 2026-10 VLD0 record encryption v1",
            &*cipher,
        ));
        Ok(crate::native_record::owner(schema, &owner, &read))
    }

    /// Transfer only the authorized device onion purpose into the maintained
    /// native Tor engine. No root, device seed or general-purpose key getter is
    /// exposed. The scope is selected by the trusted Vault composer, never JSON.
    ///
    /// The handle must have device scope and the exact `tor.onion` purpose.
    /// Generation is the owner's explicit purpose version. Like native record
    /// initialization, this transfers narrow custody. Keys invalidation/drop
    /// clears unused capabilities and stops their Nodes. The composer must also
    /// stop/drop its Mesh and engine on shutdown and any remote authority loss;
    /// an active Tor transport never substitutes for a new live G3 check.
    #[cfg(all(feature = "native-tor", not(target_arch = "wasm32")))]
    pub async fn native_tor_initializer(
        &mut self,
        handle: &KeyHandle,
        scope: ctrn::Scope,
    ) -> Result<crate::NativeTorInitializer, Error> {
        let purpose = &handle.certificate.purpose;
        if purpose.scope() != crate::Scope::Device || purpose.label() != "tor.onion" {
            return Err(Error::InvalidPurpose);
        }
        self.check_transport_handle(handle, NodePurpose::TorOnion)
            .await?;
        let current = self.loaded()?;
        let secret = purpose_secret(current, purpose, false)?;
        let community = current.metadata.lineage.binding.community().to_owned();
        self.tor_custody.initializer(scope, secret, community)
    }

    /// Consume-only browser onion custody for the exact device `tor.onion`
    /// purpose. The trusted Vault composer supplies the opaque storage scope;
    /// no key or initializer is exported through generated product actions.
    /// Lock, detected authority loss and Keys drop revoke pending custody and
    /// stop bound Nodes. The composer must still enforce fresh remote authority.
    #[cfg(all(feature = "browser-tor", target_arch = "wasm32"))]
    pub async fn browser_tor_initializer(
        &mut self,
        handle: &KeyHandle,
        scope: ctrn::Scope,
    ) -> Result<crate::BrowserTorInitializer, Error> {
        let purpose = &handle.certificate.purpose;
        if purpose.scope() != crate::Scope::Device || purpose.label() != "tor.onion" {
            return Err(Error::InvalidPurpose);
        }
        self.check_transport_handle(handle, NodePurpose::TorOnion)
            .await?;
        let current = self.loaded()?;
        let secret = purpose_secret(current, purpose, false)?;
        let community = current.metadata.lineage.binding.community().to_owned();
        self.browser_tor_custody
            .initializer(scope, secret, community)
    }
}

impl Open {
    fn state(&self) -> State {
        if self.metadata.revoked {
            State::Revoked
        } else if self.metadata.pairing.is_some() {
            State::PendingDevice
        } else {
            State::Authorized
        }
    }
}

fn empty_signature() -> Signature {
    Signature::new(VLD0, [0; 64])
}

fn checkpoint_aad(location: Locator) -> Vec<u8> {
    let mut aad = CHECKPOINT_HEADER.to_vec();
    aad.extend_from_slice(location.as_bytes());
    aad
}

fn encode_checkpoint(
    metadata: &Metadata,
    material: &Material,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let metadata = Zeroizing::new(serde_json::to_vec(metadata).map_err(|_| Error::Encoding)?);
    if metadata.len() + 101 > MAX_CHECKPOINT_BYTES - 64 {
        return Err(Error::Limit);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(4 + metadata.len() + 97));
    bytes.extend_from_slice(&(metadata.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&metadata);
    material.append(&mut bytes);
    Ok(bytes)
}

fn decode_checkpoint(bytes: &[u8]) -> Result<(Metadata, Material), Error> {
    let length = bytes.get(..4).ok_or(Error::Encoding)?;
    let length = u32::from_le_bytes(length.try_into().map_err(|_| Error::Encoding)?) as usize;
    let end = 4usize.checked_add(length).ok_or(Error::Encoding)?;
    let metadata = serde_json::from_slice(bytes.get(4..end).ok_or(Error::Encoding)?)
        .map_err(|_| Error::Encoding)?;
    let material = Material::parse(bytes.get(end..).ok_or(Error::Encoding)?)?;
    Ok((metadata, material))
}

fn validate_checkpoint(metadata: &Metadata, material: &Material) -> Result<(), Error> {
    if metadata.revision == 0 || metadata.version != if metadata.initial.is_some() { 2 } else { 1 }
    {
        return Err(Error::Encoding);
    }
    metadata.lineage.verify()?;
    if let Some(initial) = &metadata.initial {
        initial.validate(metadata, material)?;
    }
    if material
        .history
        .iter()
        .any(|(epoch, _)| *epoch >= metadata.lineage.epoch)
        || (material.root.is_none() && !material.history.is_empty())
    {
        return Err(Error::Encoding);
    }
    if let Some(seeds) = &material.identity {
        if metadata.lineage.identity != Some(vld0::public_key(seeds)) {
            return Err(Error::Encoding);
        }
    } else if metadata.lineage.identity.is_some() && material.root.is_some() {
        return Err(Error::Encoding);
    }
    let device = vld0::public_key(&material.device);
    match (&material.root, &metadata.pairing, metadata.revoked) {
        (Some(root), None, false)
            if vld0::public_key(root) == metadata.lineage.root
                && metadata.lineage.devices.contains(&device) => {}
        (None, Some(request), false)
            if request.device == device
                && request.binding == metadata.lineage.binding
                && request.root == metadata.lineage.root
                && request.epoch == metadata.lineage.epoch
                && !metadata.lineage.devices.contains(&device) =>
        {
            vld0::verify(&device, &request.signed_bytes()?, &request.proof)?;
        }
        (None, None, true) if !metadata.lineage.devices.contains(&device) => {}
        _ => return Err(Error::Encoding),
    }
    Ok(())
}

fn purpose_aad(current: &Open, purpose: &Purpose, context: &[u8]) -> Result<Vec<u8>, Error> {
    purpose_aad_at(current, purpose, current.metadata.lineage.epoch, context)
}

fn purpose_aad_at(
    current: &Open,
    purpose: &Purpose,
    epoch: u64,
    context: &[u8],
) -> Result<Vec<u8>, Error> {
    let device = match purpose.scope() {
        Scope::Device => Some(vld0::public_key(&current.material.device)),
        Scope::Member => None,
    };
    encode(
        b"ckmg.purpose.context.v1\0",
        &(
            &current.metadata.lineage.binding,
            epoch,
            device,
            purpose,
            context,
        ),
    )
}

fn purpose_secret(current: &Open, purpose: &Purpose, symmetric: bool) -> Result<Secret, Error> {
    purpose_secret_at(
        current,
        purpose,
        symmetric,
        current.metadata.lineage.epoch,
        current.material.root()?,
    )
}

fn historical_root(current: &Open, epoch: u64) -> Result<&Secret, Error> {
    if epoch == current.metadata.lineage.epoch {
        return current.material.root();
    }
    current
        .material
        .history
        .iter()
        .find(|(candidate, _)| *candidate == epoch)
        .map(|(_, root)| root)
        .ok_or(Error::MissingCheckpoint)
}

fn purpose_secret_at(
    current: &Open,
    purpose: &Purpose,
    symmetric: bool,
    epoch: u64,
    root: &Secret,
) -> Result<Secret, Error> {
    purpose.validate()?;
    let parent = match purpose.scope() {
        Scope::Member => root,
        Scope::Device => &current.material.device,
    };
    let context = purpose_aad_at(current, purpose, epoch, &[])?;
    Ok(derive_purpose_secret(parent, &context, symmetric))
}

fn derive_purpose_secret(parent: &Secret, context: &[u8], symmetric: bool) -> Secret {
    let mut material = Zeroizing::new(Vec::with_capacity(32 + context.len()));
    material.extend_from_slice(parent.as_slice());
    material.extend_from_slice(context);
    let domain = if symmetric {
        "ckmg 2026-10 purpose encryption v1"
    } else {
        "ckmg 2026-10 purpose signing v1"
    };
    Zeroizing::new(blake3::derive_key(domain, &material))
}

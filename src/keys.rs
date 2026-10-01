//! The custody state machine: prepare, validate, commit, then expose outputs.

use crate::keyring::{self, Material};
use crate::lineage::{digest, encode, redacted};
use crate::passkey::{self, PrfOutput};
use crate::{
    Action, Authority, Authorization, Binding, Clock, Commit, Entropy, Error, KeyCertificate,
    Lineage, Locator, MAX_CHECKPOINT_BYTES, MAX_DEVICES, MAX_MESSAGE_BYTES, PairingGrant,
    PairingRequest, PublicKey, Purpose, RootEnvelope, Rotation, Scope, Secret, SecureStore,
    Signature, VLD0, vld0,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const CHECKPOINT_HEADER: &[u8] = b"ckmg.checkpoint.v1\0";
const PURPOSE_HEADER: &[u8] = b"ckmg.purpose.sealed.v1\0";

/// Local custody state; Authorized still requires a fresh authority check per operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    /// No checkpoint exists. Explicit authorized restoration can rederive custody.
    MissingCheckpoint,
    /// This logical device has been removed; no root is retained.
    Revoked,
}

/// Private local device metadata. Serialized only inside the encrypted checkpoint.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "DeviceInfoWire", into = "DeviceInfoWire")]
pub struct DeviceInfo {
    name: String,
    authority_reference: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
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
    /// Derive this credential's root at the authenticated current epoch.
    Derived,
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
}

#[derive(Clone)]
struct Open {
    location: Locator,
    key: Secret,
    lineage_seed: Secret,
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
}

/// One logical device in one community. Ports are supplied by the enclosing vault.
///
/// It owns no network, files, membership policy or global-holder material. A missing
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
        }
    }

    /// Current local custody state, without identifiers or keys.
    pub fn state(&self) -> State {
        self.state
    }

    /// Wipe decrypted material and uncommitted candidates. A committed pending output
    /// remains in storage for reconciliation. All existing handles become unusable.
    pub fn lock(&mut self) {
        self.open = None;
        self.prepared = None;
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
        self.check_authority(Authorization {
            binding: &binding,
            root: Some(root),
            device,
            epoch,
            action,
            target,
            statement,
            now,
            evidence,
        })
        .await
    }

    async fn check_authority(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        if request.evidence.len() > 4096 {
            return Err(Error::Limit);
        }
        if let Err(error) = self.authority.check(request).await {
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
            lineage_seed: passkey::lineage_seed(prf, community)?,
            session,
            stamp: *blake3::hash(&sealed).as_bytes(),
            metadata,
            material,
        };
        self.state = open.state();
        self.open = Some(open);
        Ok(())
    }

    /// Explicitly create the first community root/device, after the authority adapter
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
        let material = Material::derive(prf, binding.community(), true)?;
        let device = vld0::public_key(&material.device);
        self.check_authority(Authorization {
            binding: &binding,
            root: None,
            device,
            epoch: 0,
            action: Action::Create,
            target: None,
            statement: None,
            now,
            evidence,
        })
        .await?;
        let mut lineage = Lineage {
            version: 1,
            binding,
            epoch: 1,
            revision: 1,
            root: vld0::public_key(material.root()?),
            devices: vec![device],
            signature: empty_signature(),
        };
        lineage.signature = vld0::sign(material.root()?, &lineage.signed_bytes()?)?;
        let change = Change::Created(lineage.clone());
        let candidate = self.initial(prf, location, material, info, lineage, None)?;
        self.prepare(candidate, None, Some(change))?;
        self.commit().await?.ok_or(Error::Crypto)
    }

    /// Reconstitute an absent checkpoint for an existing member. The same PRF derives
    /// the same logical device; current authority must authenticate the exact anchor
    /// and reject removed devices. Unreachable/corrupt/existing records never reach
    /// this path. Only data is recreated; binding, epoch and lineage stay unchanged.
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
        let mut material = Material::derive(prf, anchor.binding.community(), false)?;
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
            now,
            evidence,
        })
        .await?;
        material.root = Some(match source {
            RestoreRoot::Derived => passkey::lineage_root(
                &passkey::lineage_seed(prf, anchor.binding.community())?,
                anchor.epoch,
            )?,
            RestoreRoot::Paired(grant) => {
                grant.lineage.verify()?;
                if grant.request.device != device
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
                keyring::secret(&vld0::open(
                    &material.device,
                    &grant.aad()?,
                    &grant.sealed_root,
                )?)?
            }
            RestoreRoot::Rotated(rotation) => {
                rotation.lineage.verify()?;
                if rotation.lineage.binding != anchor.binding
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
                keyring::secret(&vld0::open(
                    &material.device,
                    &rotation.aad(device)?,
                    &envelope.sealed_root,
                )?)?
            }
        });
        if vld0::public_key(material.root()?) != anchor.root {
            return Err(Error::Unauthorized);
        }
        let candidate = self.initial(prf, location, material, info, anchor.clone(), None)?;
        self.prepare(candidate, None, Some(Change::Restored(anchor.clone())))?;
        self.commit().await?.ok_or(Error::Crypto)
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
        let material = Material::derive(prf, anchor.binding.community(), false)?;
        let device = vld0::public_key(&material.device);
        self.check_authority(Authorization {
            binding: &anchor.binding,
            root: Some(anchor.root),
            device,
            epoch: anchor.epoch,
            action: Action::RequestPairing,
            target: None,
            statement: Some(anchor.digest()?),
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
            lineage_seed: passkey::lineage_seed(prf, lineage.binding.community())?,
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
            },
        })
    }

    fn prepare(
        &mut self,
        mut candidate: Open,
        expected: Option<[u8; 32]>,
        change: Option<Change>,
    ) -> Result<(), Error> {
        candidate.metadata.revision = candidate
            .metadata
            .revision
            .checked_add(1)
            .ok_or(Error::Limit)?;
        candidate.metadata.last_time = self.last_time;
        candidate.metadata.output = match change {
            Some(change) => Some(Receipt {
                operation: OperationId(*vld0::random_secret(&mut self.entropy)?),
                change,
            }),
            None => None,
        };
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
                now,
                evidence,
            })
            .await?;
        }
        let outcome = self
            .store
            .compare_exchange(
                &prepared.candidate.location,
                prepared.expected,
                &prepared.sealed,
            )
            .await;
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

    /// Return current public lineage after checking local freshness and live authority.
    pub async fn lineage(&mut self) -> Result<Lineage, Error> {
        self.authorize(Action::Use, None, None, &[]).await?;
        Ok(self.loaded()?.metadata.lineage.clone())
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
            request: request.clone(),
            lineage: lineage.clone(),
            sealed_root: Vec::new(),
            signature: empty_signature(),
        };
        grant.sealed_root = vld0::seal_to(
            &mut self.entropy,
            &request.device,
            &grant.aad()?,
            candidate.material.root()?.as_slice(),
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
        if grant.lineage.binding != previous.binding
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
        let root = keyring::secret(&plaintext)?;
        if vld0::public_key(&root) != previous.root {
            return Err(Error::InvalidKey);
        }
        candidate.material.root = Some(root);
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
        if next.binding != previous.binding
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
        let root = passkey::lineage_root(&candidate.lineage_seed, next.epoch)?;
        next.root = vld0::public_key(&root);
        next.revision = next.revision.checked_add(1).ok_or(Error::Limit)?;
        next.devices.retain(|d| *d != revoked);
        next.signature = vld0::sign(&root, &next.signed_bytes()?)?;
        let mut rotation = Rotation {
            predecessor: previous.digest()?,
            previous_root: previous.root,
            revoked,
            lineage: next.clone(),
            envelopes: Vec::new(),
            signature: empty_signature(),
        };
        for device in &next.devices {
            let sealed_root = vld0::seal_to(
                &mut self.entropy,
                device,
                &rotation.aad(*device)?,
                root.as_slice(),
            )?;
            rotation.envelopes.push(RootEnvelope {
                device: *device,
                sealed_root,
            });
        }
        rotation.signature = vld0::sign(candidate.material.root()?, &rotation.signed_bytes()?)?;
        rotation.verify(&previous)?;
        candidate.material.root = Some(root);
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
            now,
            evidence,
        })
        .await?;
        let change = if device == rotation.revoked {
            candidate.material.root = None;
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
            let root = keyring::secret(&plaintext)?;
            if vld0::public_key(&root) != rotation.lineage.root {
                return Err(Error::InvalidKey);
            }
            candidate.material.root = Some(root);
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
        self.writable()?;
        purpose.validate()?;
        self.authorize(Action::Use, None, None, &[]).await?;
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

    async fn check_handle(&mut self, handle: &KeyHandle) -> Result<(), Error> {
        self.writable()?;
        self.authorize(Action::Use, None, None, &[]).await?;
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

    /// Encrypt with a separate symmetric purpose key, authenticating scope, epoch,
    /// purpose, and caller context. Member-scope ciphertext opens on paired devices.
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
    if metadata.len() + 69 > MAX_CHECKPOINT_BYTES - 64 {
        return Err(Error::Limit);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(4 + metadata.len() + 65));
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
    if metadata.version != 1 || metadata.revision == 0 {
        return Err(Error::Encoding);
    }
    metadata.lineage.verify()?;
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
    let device = match purpose.scope() {
        Scope::Device => Some(vld0::public_key(&current.material.device)),
        Scope::Member => None,
    };
    encode(
        b"ckmg.purpose.context.v1\0",
        &(
            &current.metadata.lineage.binding,
            current.metadata.lineage.epoch,
            device,
            purpose,
            context,
        ),
    )
}

fn purpose_secret(current: &Open, purpose: &Purpose, symmetric: bool) -> Result<Secret, Error> {
    purpose.validate()?;
    let parent = match purpose.scope() {
        Scope::Member => current.material.root()?,
        Scope::Device => &current.material.device,
    };
    let context = purpose_aad(current, purpose, &[])?;
    let mut material = Zeroizing::new(Vec::with_capacity(32 + context.len()));
    material.extend_from_slice(parent.as_slice());
    material.extend_from_slice(&context);
    let domain = if symmetric {
        "ckmg 2026-10 purpose encryption v1"
    } else {
        "ckmg 2026-10 purpose signing v1"
    };
    Ok(Zeroizing::new(blake3::derive_key(domain, &material)))
}

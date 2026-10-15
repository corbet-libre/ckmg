//! Original random creation material retained before registration acceptance.
use super::*;

#[cfg(test)]
#[path = "../../tests/unit/enrollment.rs"]
mod tests;

/// Private original root and operation prepared before the server challenge.
/// Only original public binding and an opaque commitment escape; there is no
/// Receipt, Keys or root getter.
pub struct EnrollmentSeed {
    binding: Binding,
    root: Secret,
    operation: OperationId,
}
redacted!(EnrollmentSeed);

impl EnrollmentSeed {
    /// Original caller-supplied scope and member, unchanged by preparation.
    /// This is public composition data, never an accepted enrollment or authority.
    pub fn binding(&self) -> &Binding {
        &self.binding
    }

    /// Generate the original nonzero random root and operation exactly once.
    /// The trusted composer supplies the original Passport-derived binding.
    pub fn new(binding: Binding, entropy: &mut impl Entropy) -> Result<Self, Error> {
        Ok(Self {
            binding,
            root: vld0::random_secret(entropy)?,
            operation: OperationId(*vld0::random_secret(entropy)?),
        })
    }

    /// Bind the original registration pending challenge without root coordinates.
    pub fn commitment(&self) -> Result<[u8; 32], Error> {
        commitment(&self.binding, &self.root, self.operation)
    }

    /// Seal this unaccepted candidate only after the original CPky ceremony
    /// supplied its PRF and credential ID. The original checkpoint codec uses
    /// revision zero, which every ordinary Keys/inspection path rejects.
    /// The composer must durably retain these exact bytes before register_finish.
    pub fn seal(
        self,
        prf: &PrfOutput,
        info: DeviceInfo,
        clock: &mut impl Clock,
        entropy: &mut impl Entropy,
    ) -> Result<UnenrolledCreation, Error> {
        if info.authority_reference().is_empty() {
            return Err(Error::Unauthorized);
        }
        let location = passkey::vault_location(prf, self.binding.community())?;
        let key = passkey::ring_key(prf, self.binding.community())?;
        let material = Material {
            device: passkey::device_seed(prf, self.binding.community())?,
            identity: Some(self.root.clone()),
            root: Some(self.root),
            history: vec![],
        };
        let device = vld0::public_key(&material.device);
        let mut lineage = Lineage {
            version: 2,
            binding: self.binding,
            epoch: 1,
            revision: 1,
            root: vld0::public_key(material.root()?),
            identity: material.identity.as_ref().map(vld0::public_key),
            devices: vec![device],
            signature: empty_signature(),
        };
        lineage.signature = vld0::sign(material.root()?, &lineage.signed_bytes()?)?;
        let mut receipt = Receipt {
            operation: self.operation,
            change: Change::Created(lineage.clone()),
            attestation: None,
        };
        receipt.attestation = Some(DeviceAttestation {
            device,
            signature: vld0::sign(&material.device, &receipt.attestation_bytes(device)?)?,
        });
        let metadata = Metadata {
            version: 1,
            revision: 0,
            last_time: clock.now()?,
            info,
            lineage,
            pairing: None,
            revoked: false,
            output: Some(receipt),
            initial: None,
        };
        validate_unenrolled(&metadata, &material)?;
        let plaintext = encode_checkpoint(&metadata, &material)?;
        let mut sealed = CHECKPOINT_HEADER.to_vec();
        sealed.extend_from_slice(&keyring::seal(
            entropy,
            &key,
            &checkpoint_aad(location),
            &plaintext,
        )?);
        if sealed.len() > MAX_CHECKPOINT_BYTES {
            return Err(Error::Limit);
        }
        Ok(UnenrolledCreation {
            metadata,
            material,
            location,
            key,
            sealed,
        })
    }
}

/// The closed set of things a device key may sign before activation, each under its own
/// fixed domain tag that ckmg prepends (`UnenrolledCreation::sign_device`).
///
/// ```compile_fail
/// // No raw transcript and no caller-chosen tag: a purpose is required.
/// fn raw(candidate: &ckmg::UnenrolledCreation) {
///     let _ = candidate.sign_device(b"cvld.device-join.v1\0");
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DevicePurpose {
    /// The community's device-join message (`cvld.device-join.v1`).
    DeviceJoin,
    /// The community's device-session message (`cvld.device-session.v1`).
    DeviceSession,
    /// A stamp salt derivation; the signature is only ever hashed, never published.
    SaltDerivation,
}

impl DevicePurpose {
    /// The fixed domain tag prepended to every payload of this purpose.
    pub const fn tag(self) -> &'static [u8] {
        match self {
            Self::DeviceJoin => b"cvld.device-join.v1\0",
            Self::DeviceSession => b"cvld.device-session.v1\0",
            Self::SaltDerivation => b"cmsg.device-join.salt.v1\0",
        }
    }
}

/// Authenticated original revision-zero material, never accepted custody.
/// Loading it cannot synthesize registration provenance or a public receipt.
pub struct UnenrolledCreation {
    metadata: Metadata,
    material: Material,
    location: Locator,
    key: Secret,
    sealed: Vec<u8>,
}
redacted!(UnenrolledCreation);
impl UnenrolledCreation {
    /// Original passkey-wrapped ciphertext for the durable encrypted owner Store.
    pub fn as_bytes(&self) -> &[u8] {
        &self.sealed
    }

    /// Recomputed from the original private material, not a caller assertion.
    pub fn commitment(&self) -> Result<[u8; 32], Error> {
        commitment(
            &self.metadata.lineage.binding,
            self.material.root()?,
            self.metadata
                .output
                .as_ref()
                .ok_or(Error::Encoding)?
                .operation,
        )
    }

    /// The lineage challenge digest (`Receipt::passkey_challenge`) of the creation receipt
    /// that activation outputs, so a device can have the genesis stamp cover it before
    /// activation. A public digest only: no receipt, key or secret, and no authority.
    pub fn passkey_challenge(&self) -> Result<[u8; 32], Error> {
        self.metadata
            .output
            .as_ref()
            .ok_or(Error::Encoding)?
            .passkey_challenge()
    }

    /// Sign `payload` with this candidate's device key under the fixed domain tag of
    /// `purpose` (plain Ed25519 over `purpose.tag() || payload`). The only device signer
    /// before activation: a device-key member must join and open its session before it can
    /// activate. The caller chooses neither the tag nor a raw transcript, so the signature
    /// is valid for exactly that purpose; after activation `Keys` signs.
    pub fn sign_device(&self, purpose: DevicePurpose, payload: &[u8]) -> Result<[u8; 64], Error> {
        let tag = purpose.tag();
        if payload.len() > MAX_MESSAGE_BYTES - tag.len() {
            return Err(Error::Limit);
        }
        let mut message = Vec::with_capacity(tag.len() + payload.len());
        message.extend_from_slice(tag);
        message.extend_from_slice(payload);
        Ok(vld0::sign_ed25519(&self.material.device, &message))
    }

    /// Compare only against an authenticated original pending checkpoint. This
    /// reveals no pre-enrollment receipt and grants no completion authority.
    pub fn matches_pending(&self, pending: &PendingCreation) -> bool {
        self.metadata.output.as_ref() == Some(pending.receipt())
            && self.location == *pending.location()
            && self.metadata.info.authority_reference() == pending.original_reference()
    }

    /// Reopen only the exact retained unaccepted format with this original PRF.
    /// Wrong key/scope, ordinary accepted checkpoints and malformed input refuse.
    pub fn reopen(prf: &PrfOutput, community: &str, sealed: &[u8]) -> Result<Self, Error> {
        if sealed.len() > MAX_CHECKPOINT_BYTES {
            return Err(Error::Limit);
        }
        let location = passkey::vault_location(prf, community)?;
        let key = passkey::ring_key(prf, community)?;
        let encrypted = sealed
            .strip_prefix(CHECKPOINT_HEADER)
            .ok_or(Error::Encoding)?;
        let plaintext = keyring::open(&key, &checkpoint_aad(location), encrypted)?;
        let (metadata, material) = decode_checkpoint(&plaintext)?;
        if metadata.lineage.binding.community() != community {
            return Err(Error::Unauthorized);
        }
        validate_unenrolled(&metadata, &material)?;
        Ok(Self {
            metadata,
            material,
            location,
            key,
            sealed: sealed.to_vec(),
        })
    }
}

pub(super) fn commitment(
    binding: &Binding,
    root: &Secret,
    operation: OperationId,
) -> Result<[u8; 32], Error> {
    // Reuse maintained BLAKE3 and the original canonical public encoding. The
    // private root is fed directly, avoiding an unzeroized serialized key copy.
    let public = encode(b"ckmg.initial-enrollment.v1\0", &(binding, operation))?;
    let mut hash = blake3::Hasher::new();
    hash.update(&public);
    hash.update(root.as_slice());
    Ok(*hash.finalize().as_bytes())
}

fn validate_unenrolled(metadata: &Metadata, material: &Material) -> Result<(), Error> {
    if metadata.revision != 0 || metadata.info.authority_reference().is_empty() {
        return Err(Error::Unauthorized);
    }
    let receipt = metadata.output.as_ref().ok_or(Error::Unauthorized)?;
    if receipt.operation.0 == [0; 32]
        || material.root()?.as_slice() == [0; 32]
        || material.identity.as_ref().map(|key| key.as_slice()) != Some(material.root()?.as_slice())
        || !material.history.is_empty()
    {
        return Err(Error::Unauthorized);
    }
    genesis::check_created(metadata, material, receipt)?;
    let mut accepted_shape = metadata.clone();
    accepted_shape.revision = 1;
    validate_checkpoint(&accepted_shape, material)
}

struct Checked {
    binding: Binding,
    device: PublicKey,
    reference: Vec<u8>,
    seed: [u8; 32],
    operation: OperationId,
    location: Locator,
    sealed_digest: [u8; 32],
    durable: crate::InitialActivationIntent,
}
impl Checked {
    fn request(&self, now: u64) -> crate::InitialActivationAuthorization<'_> {
        crate::InitialActivationAuthorization {
            binding: &self.binding,
            device: self.device,
            authority_reference: &self.reference,
            seed: &self.seed,
            operation: self.operation,
            location: &self.location,
            sealed_digest: &self.sealed_digest,
            durable: &self.durable,
            now,
        }
    }
}

impl<S: SecureStore, C: Clock, E: Entropy, A: Authority> Keys<S, C, E, A> {
    /// Activate only this original retained candidate after actual same-key
    /// enrollment authorization. No replacement root or operation is generated.
    /// The private adapter must commit the candidate and complete compound Store
    /// atomically. Only its actual Committed result can release the receipt.
    pub async fn activate_initial(
        &mut self,
        candidate: UnenrolledCreation,
        durable: crate::InitialActivationIntent,
    ) -> Result<Receipt, Error> {
        self.require_locked()?;
        validate_unenrolled(&candidate.metadata, &candidate.material)?;
        if durable.generation == 0 {
            return Err(Error::Unauthorized);
        }
        self.require_absent(candidate.location).await?;
        let checked = Checked {
            binding: candidate.metadata.lineage.binding.clone(),
            device: vld0::public_key(&candidate.material.device),
            reference: candidate.metadata.info.authority_reference().to_vec(),
            seed: candidate.commitment()?,
            operation: candidate
                .metadata
                .output
                .as_ref()
                .ok_or(Error::Unauthorized)?
                .operation,
            location: candidate.location,
            sealed_digest: *blake3::hash(&candidate.sealed).as_bytes(),
            durable,
        };
        let now = self.now()?;
        if now < candidate.metadata.last_time {
            return Err(Error::Clock);
        }
        let owner_floor = self
            .authority
            .check_initial_activation(checked.request(now))
            .await?;
        if self.now()? < owner_floor {
            return Err(Error::Clock);
        }
        self.require_absent(candidate.location).await?;
        let now = self.now()?;
        let owner_floor = self
            .authority
            .check_initial_activation_current(checked.request(now))?;
        if self.now()? < owner_floor {
            return Err(Error::Clock);
        }
        let mut metadata = candidate.metadata;
        metadata.revision = 1;
        metadata.last_time = self.last_time;
        let open = Open {
            location: candidate.location,
            key: candidate.key,
            session: *vld0::random_secret(&mut self.entropy)?,
            stamp: [0; 32],
            metadata,
            material: candidate.material,
        };
        // A new nonce seals accepted metadata. The revision-zero nonce is never
        // reused for different plaintext; original root/receipt stay unchanged.
        self.prepare_checkpoint(open, None)?;
        let receipt = self.commit().await?.ok_or(Error::Crypto)?;
        let result = self.now().and_then(|now| {
            self.authority
                .check_initial_activation_current(checked.request(now))
        });
        let result = result.and_then(|floor| {
            if self.now()? < floor {
                Err(Error::Clock)
            } else {
                Ok(())
            }
        });
        if let Err(error) = result {
            self.lock();
            return Err(error);
        }
        self.genesis = Some(genesis::InitialPublication::new(
            receipt.operation,
            self.loaded()?.stamp,
        ));
        Ok(receipt)
    }
}

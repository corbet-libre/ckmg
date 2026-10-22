//! Authenticated original initial ACK facts; no live authority or Store custody.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::keys) struct StoredInitial {
    version: u8,
    operation: OperationId,
    seed: [u8; 32],
    publication: [u8; 32],
    nonce: [u8; 24],
    evidence_digest: [u8; 32],
    prepared_at: u64,
    expires: u64,
}

/// Public original creation facts authenticated by the normal PRF checkpoint.
/// This is not current authority. Only the original same-key owner, actual
/// selected lineage and later exact inner Store join may authorize recovery.
pub struct InitialCheckpointProvenance(StoredInitial);
impl InitialCheckpointProvenance {
    /// The restored device's `DeviceJoin` signature for the stamp-less re-confirmation of the
    /// join the community already applied (key from `prf` and `community`, enrollment tag).
    /// This authenticated original ACK is the capability; no other public route signs a join
    /// outside the enrollment (`passkey::sign_device_opened` refuses it).
    pub fn sign_device_join_restored(
        &self,
        prf: &crate::passkey::PrfOutput,
        community: &str,
        payload: &[u8],
    ) -> Result<[u8; 64], Error> {
        crate::passkey::sign_device_join_restored(prf, community, payload)
    }
    /// Original enrollment commitment, recomputed from retained private root.
    pub fn seed(&self) -> [u8; 32] {
        self.0.seed
    }
    /// Original immutable publication commitment; its deadline is not renewed.
    pub fn publication(&self) -> [u8; 32] {
        self.0.publication
    }
    /// Original exact Created operation.
    pub fn operation(&self) -> OperationId {
        self.0.operation
    }
    /// Canonical public facts for the same original Store acknowledgment batch.
    /// These bytes alone are never an authenticated checkpoint or a capability.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        encode(b"ckmg.initial-acknowledgment.v1\0", &self.0)
    }
}
redacted!(InitialCheckpointProvenance);

impl StoredInitial {
    pub(in crate::keys) fn validate(
        &self,
        metadata: &Metadata,
        material: &Material,
    ) -> Result<(), Error> {
        let device = vld0::public_key(&material.device);
        if self.version != 1
            || metadata.version != 2
            || metadata.revision != 2
            || metadata.output.is_some()
            || metadata.pairing.is_some()
            || metadata.revoked
            || metadata.lineage.epoch != 1
            || metadata.lineage.revision != 1
            || metadata.lineage.devices != [device]
            || !material.history.is_empty()
            || self.prepared_at >= self.expires
            || metadata.last_time < self.prepared_at
            || self.operation.0 == [0; 32]
            || self.seed
                != super::super::enrollment::commitment(
                    &metadata.lineage.binding,
                    material.root()?,
                    self.operation,
                )?
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
    fn verify_receipt(
        &self,
        metadata: &Metadata,
        material: &Material,
        receipt: &Receipt,
        packed: &[u8],
    ) -> Result<(), Error> {
        self.validate(metadata, material)?;
        let Change::Created(lineage) = &receipt.change else {
            return Err(Error::Unauthorized);
        };
        let (_, author) = receipt.attested_lineage()?;
        if receipt.operation != self.operation
            || lineage != &metadata.lineage
            || author != vld0::public_key(&material.device)
            || blake3::hash(packed).as_bytes() != &self.evidence_digest
            || receipt.initial_publication_commitment(
                &self.nonce,
                packed,
                self.prepared_at,
                self.expires,
            )? != self.publication
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}

impl PendingCompletion {
    /// Prepare public original facts for the ACK batch. This is only data until
    /// the normal checkpoint and exact original Store CAS have committed it.
    pub fn initial_acknowledgment(&self) -> Result<InitialCheckpointProvenance, Error> {
        self.checked_at.ok_or(Error::Unauthorized)?;
        let (lineage, _) = self.source.receipt.attested_lineage()?;
        Ok(InitialCheckpointProvenance(StoredInitial {
            version: 1,
            operation: self.source.receipt.operation,
            seed: super::super::enrollment::commitment(
                &lineage.binding,
                &self.source.root,
                self.source.receipt.operation,
            )?,
            publication: self.source.receipt.initial_publication_commitment(
                &self.intent.nonce,
                &self.intent.packed_evidence,
                self.intent.prepared_at,
                self.intent.expires,
            )?,
            nonce: self.intent.nonce,
            evidence_digest: *blake3::hash(&self.intent.packed_evidence).as_bytes(),
            prepared_at: self.intent.prepared_at,
            expires: self.intent.expires,
        }))
    }

    pub(in crate::keys) fn bind_acknowledgment(
        &mut self,
        current: &Open,
        now: u64,
    ) -> Result<StoredInitial, Error> {
        let floor = self.checked_at.take().ok_or(Error::Unauthorized)?;
        if now < floor
            || now >= self.intent.expires
            || current.location != self.source.location
            || current.stamp != self.source.sealed_digest
            || current.metadata.info.authority_reference() != self.source.authority_reference
            || current.metadata.output.as_ref() != Some(&self.source.receipt)
            || current.metadata.revision != 1
            || current.metadata.initial.is_some()
        {
            return Err(Error::Unauthorized);
        }
        super::super::genesis::check_created(
            &current.metadata,
            &current.material,
            &self.source.receipt,
        )?;
        if current.material.root()?.as_slice() != self.source.root.as_slice() {
            return Err(Error::Unauthorized);
        }
        self.checked_at = Some(now);
        Ok(self.initial_acknowledgment()?.0)
    }

    pub(in crate::keys) fn acknowledgment_guard(&mut self) -> AcknowledgmentGuard<'_> {
        AcknowledgmentGuard {
            completion: self,
            accepted: false,
        }
    }
}

pub(in crate::keys) struct AcknowledgmentGuard<'a> {
    completion: &'a mut PendingCompletion,
    accepted: bool,
}
impl AcknowledgmentGuard<'_> {
    pub(in crate::keys) fn finish(
        mut self,
        clock: &mut impl Clock,
        authority: &mut impl Authority,
        floor: u64,
    ) -> Result<u64, Error> {
        let completed = self.completion.check_current(clock, authority)?;
        if completed < floor {
            return Err(Error::Clock);
        }
        self.accepted = true;
        Ok(completed)
    }
}
impl Drop for AcknowledgmentGuard<'_> {
    fn drop(&mut self) {
        if !self.accepted {
            self.completion.checked_at = None;
        }
    }
}

impl CheckpointInspector {
    /// Inspect only an original normal initial ACK, binding its exact immutable
    /// receipt and packed evidence. Legacy, pending, rotated, paired or revoked
    /// checkpoints cannot acquire this route through a fresh certificate.
    pub fn initial_acknowledgment(
        &self,
        sealed: &[u8],
        receipt: &Receipt,
        packed_evidence: &[u8],
    ) -> Result<InitialCheckpointProvenance, Error> {
        if packed_evidence.is_empty() || packed_evidence.len() > cdht::MAX_SUBKEY_SIZE {
            return Err(Error::Limit);
        }
        let (metadata, material) = self.decode(sealed)?;
        let initial = metadata.initial.as_ref().ok_or(Error::Unauthorized)?;
        initial.verify_receipt(&metadata, &material, receipt, packed_evidence)?;
        Ok(InitialCheckpointProvenance(initial.clone()))
    }
}

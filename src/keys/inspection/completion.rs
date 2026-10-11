//! Completion of one authenticated initial checkpoint, never member custody.
use super::*;

/// Immutable inputs loaded by CVLT from its authenticated durable Prepared
/// intent. These public inputs are not authority: the dedicated owner must
/// compare every field to its actual original Store and registration evidence.
/// Once admitted, callers cannot replace the nonce, evidence or deadline.
pub struct CompletionIntent {
    /// Actual original outer Store version containing the Prepared intent.
    pub outer_generation: u64,
    /// Digest of that exact authenticated outer encrypted checkpoint.
    pub outer_digest: [u8; 32],
    /// Initial common-root inner Store version, necessarily one.
    pub inner_version: u64,
    /// Exact original inner Store operation, distinct from the Keys receipt ID.
    pub inner_operation: [u8; 32],
    /// Digest of the exact common-root inner encrypted checkpoint.
    pub inner_digest: [u8; 32],
    /// Nonce generated once and durably retained before signing/publication.
    pub nonce: [u8; 24],
    /// Exact final packed canonical evidence encrypted in the fixed CDHT value.
    pub packed_evidence: Vec<u8>,
    /// Original persisted preparing clock floor; reopening cannot reset it.
    pub prepared_at: u64,
    /// Original exclusive deadline; reopening cannot renew it.
    pub expires: u64,
}
redacted!(CompletionIntent);

/// Original authenticated pending Created checkpoint. There is no ordinary
/// Keys owner, operation, signer, cipher accessor, cloning or serialization.
/// Only dedicated current completion authorization can expose bounded custody.
pub struct PendingCreation {
    root: Secret,
    receipt: Receipt,
    authority_reference: Vec<u8>,
    location: Locator,
    sealed_digest: [u8; 32],
    last_time: u64,
}
redacted!(PendingCreation);

impl CheckpointInspector {
    /// Authenticate exactly an initial pending Created checkpoint through the
    /// original decoder and PRF/locator binding. Normal inspect/bootstrap still
    /// reject Pending. This owner is not a restored genesis marker or Keys Use.
    pub fn pending_creation(&self, sealed: &[u8]) -> Result<PendingCreation, Error> {
        let (metadata, mut material) = self.decode_retained(sealed)?;
        if metadata.revision != 1 {
            return Err(Error::Unauthorized);
        }
        let receipt = metadata.output.as_ref().ok_or(Error::Unauthorized)?;
        super::super::genesis::check_created(&metadata, &material, receipt)?;
        Ok(PendingCreation {
            root: material.root.take().ok_or(Error::NoRoot)?,
            receipt: receipt.clone(),
            authority_reference: metadata.info.authority_reference().to_vec(),
            location: self.location,
            sealed_digest: *blake3::hash(sealed).as_bytes(),
            last_time: metadata.last_time,
        })
    }
}

impl PendingCreation {
    /// Exact original pending receipt; no certificate or currentness inferred.
    pub fn receipt(&self) -> &Receipt {
        &self.receipt
    }
    /// Digest of the exact authenticated original sealed Keys entry.
    pub fn sealed_digest(&self) -> &[u8; 32] {
        &self.sealed_digest
    }
    /// Original PRF-derived local Keys locator, never a caller-selected slot.
    pub fn location(&self) -> &Locator {
        &self.location
    }

    /// Persisted clock floor authenticated by this exact original checkpoint.
    /// It is a public claim, not a live clock or current authority observation.
    pub fn last_time(&self) -> u64 {
        self.last_time
    }

    /// Consume this owner before the dedicated async check. Cancellation or
    /// refusal drops the root; reopening may only retry the same authenticated
    /// immutable Prepared intent under its unchanged deadline. No Create, Use,
    /// unlock or generic genesis authorization substitutes for this port.
    pub async fn authorize_completion(
        self,
        intent: CompletionIntent,
        clock: &mut impl Clock,
        authority: &mut impl Authority,
    ) -> Result<PendingCompletion, Error> {
        if intent.packed_evidence.is_empty() || intent.packed_evidence.len() > cdht::MAX_SUBKEY_SIZE
        {
            return Err(Error::Limit);
        }
        if intent.outer_generation == 0 || intent.inner_version != 1 {
            return Err(Error::Unauthorized);
        }
        let now = clock.now()?;
        let floor = self.last_time.max(intent.prepared_at);
        check_time(now, floor, intent.expires)?;
        let owner_floor = authority
            .check_completion(crate::CompletionAuthorization {
                receipt: &self.receipt,
                authority_reference: &self.authority_reference,
                location: &self.location,
                sealed_digest: &self.sealed_digest,
                intent: &intent,
                now,
            })
            .await
            .map_err(authority_error)?;
        let checked_at = clock.now()?;
        check_time(checked_at, now.max(owner_floor), intent.expires)?;
        let (lineage, _) = self.receipt.attested_lineage()?;
        let cipher = passkey::common_store_cipher(&self.root, lineage.binding.community())?;
        Ok(PendingCompletion {
            source: self,
            intent,
            cipher,
            checked_at: Some(checked_at),
        })
    }
}

/// Authorized temporary initial Store custody and one fixed genesis transcript.
/// The enclosing owner checks the exact inner version/operation/Keys bytes
/// while retaining its actual Store lock before consuming the signing boundary.
/// No general Keys/Wallet owner or arbitrary root signer escapes.
pub struct PendingCompletion {
    source: PendingCreation,
    intent: CompletionIntent,
    cipher: passkey::StoreCipher,
    checked_at: Option<u64>,
}
redacted!(PendingCompletion);

impl PendingCompletion {
    /// Exact original pending receipt for the authenticated inner Store check.
    pub fn receipt(&self) -> &Receipt {
        self.source.receipt()
    }
    /// Exact sealed Keys digest for the authenticated inner Store check.
    pub fn sealed_digest(&self) -> &[u8; 32] {
        self.source.sealed_digest()
    }
    /// Fixed local Keys slot for the authenticated inner Store check.
    pub fn location(&self) -> &Locator {
        self.source.location()
    }
    /// Borrow only the original scoped common-root Store wrapping capability.
    /// The borrow cannot survive disposal/cancellation of this completion owner.
    pub fn store_cipher(&self) -> &passkey::StoreCipher {
        &self.cipher
    }

    /// Retain only the original initial lineage read key after the dedicated
    /// completion admission. The owned reader does not borrow this root owner.
    /// The enclosing attempt must own and drop it on refusal or disposal; it
    /// grants no ordinary Keys Use or publication acknowledgement.
    pub fn lineage_reader(&self) -> Result<InitialLineageReader, Error> {
        self.checked_at.ok_or(Error::Unauthorized)?;
        let (lineage, _) = self.source.receipt.attested_lineage()?;
        super::lineage::initial_reader(&self.source.root, lineage)
    }

    /// Recheck only this exact dedicated completion after an enclosing await.
    /// Refusal consumes the monotonic check state; no later call can revive it.
    /// This does not authorize ordinary Keys Use or acknowledge publication.
    pub fn check_current(
        &mut self,
        clock: &mut impl Clock,
        authority: &mut impl Authority,
    ) -> Result<u64, Error> {
        let floor = self.checked_at.take().ok_or(Error::Unauthorized)?;
        let now = clock.now()?;
        check_time(now, floor, self.intent.expires)?;
        let owner_floor = authority
            .check_completion_current(crate::CompletionAuthorization {
                receipt: &self.source.receipt,
                authority_reference: &self.source.authority_reference,
                location: &self.source.location,
                sealed_digest: &self.source.sealed_digest,
                intent: &self.intent,
                now,
            })
            .map_err(authority_error)?;
        let completed = clock.now()?;
        check_time(completed, now.max(owner_floor), self.intent.expires)?;
        self.checked_at = Some(completed);
        Ok(completed)
    }

    /// Consume this owner after the final authenticated Store await. No new
    /// evidence, nonce or deadline can be supplied here. The dedicated sync
    /// authority must reborrow original current policy, validate its actual
    /// retained membership/session lease and compare the same durable intent.
    /// Signed outputs must be durably recorded before any transport exposure.
    pub fn complete_genesis(
        mut self,
        clock: &mut impl Clock,
        authority: &mut impl Authority,
    ) -> Result<(cdht::Descriptor, cdht::SignedValue), Error> {
        let checked_at = self.check_current(clock, authority)?;
        let (lineage, _) = self.source.receipt.attested_lineage()?;
        let outputs = super::super::genesis::fixed_record(
            &self.source.root,
            lineage,
            &self.intent.packed_evidence,
            self.intent.nonce,
        )?;
        check_time(clock.now()?, checked_at, self.intent.expires)?;
        Ok(outputs)
    }
}

fn check_time(now: u64, floor: u64, expires: u64) -> Result<(), Error> {
    if now < floor {
        return Err(Error::Clock);
    }
    if now >= expires {
        return Err(Error::Expired);
    }
    Ok(())
}

fn authority_error(error: Error) -> Error {
    match error {
        Error::Unavailable | Error::Revoked => error,
        _ => Error::Unauthorized,
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/completion.rs"]
mod tests;

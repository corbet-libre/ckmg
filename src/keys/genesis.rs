//! Fixed original CDHT genesis outputs, never a lent root signer or cipher.
use super::*;

impl Receipt {
    /// Original immutable first-publication identity for the enrollment owner's
    /// opaque compare-and-set. This authorizes nothing and signs no output.
    /// Mutable Store progress is excluded; the exact receipt, output nonce,
    /// packed evidence and unchanged intent lifetime are all bound canonically.
    pub fn initial_publication_commitment(
        &self,
        nonce: &[u8; 24],
        packed_evidence: &[u8],
        prepared_at: u64,
        expires: u64,
    ) -> Result<[u8; 32], Error> {
        if packed_evidence.is_empty() || packed_evidence.len() > cdht::MAX_SUBKEY_SIZE {
            return Err(Error::Limit);
        }
        if prepared_at >= expires || self.operation.as_bytes() == &[0; 32] {
            return Err(Error::Unauthorized);
        }
        let Change::Created(_) = self.change else {
            return Err(Error::Unauthorized);
        };
        let (lineage, author) = self.attested_lineage()?;
        if lineage.epoch != 1 || lineage.revision != 1 || lineage.devices.as_slice() != [author] {
            return Err(Error::Unauthorized);
        }
        digest(
            b"ckmg.initial-publication.v1\0",
            &(self, nonce, packed_evidence, prepared_at, expires),
        )
    }
}

pub(super) struct InitialPublication {
    operation: OperationId,
    stamp: [u8; 32],
}
impl InitialPublication {
    pub(super) fn new(operation: OperationId, stamp: [u8; 32]) -> Self {
        Self { operation, stamp }
    }

    fn check(&self, open: &Open, receipt: &Receipt) -> Result<(), Error> {
        if self.operation != receipt.operation || self.stamp != open.stamp {
            return Err(Error::Unauthorized);
        }
        check_created(&open.metadata, &open.material, receipt)
    }
}

pub(in crate::keys) fn check_created(
    metadata: &Metadata,
    material: &Material,
    receipt: &Receipt,
) -> Result<(), Error> {
    if metadata.output.as_ref() != Some(receipt) || metadata.revoked || metadata.pairing.is_some() {
        return Err(Error::Unauthorized);
    }
    let Change::Created(lineage) = &receipt.change else {
        return Err(Error::Unauthorized);
    };
    let (attested, device) = receipt.attested_lineage()?;
    if lineage != &metadata.lineage
        || attested != lineage
        || lineage.epoch != 1
        || lineage.revision != 1
        || lineage.devices.as_slice() != [device]
        || device != vld0::public_key(&material.device)
        || lineage.root != vld0::public_key(material.root()?)
    {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

// Only this module can construct the root adapter. No caller callback receives
// it; the two original CDHT constructors below choose every signed transcript.
struct RootSigner<'a>(&'a Secret);
impl cdht::Signer for RootSigner<'_> {
    fn public_key(&self) -> [u8; 32] {
        *vld0::public_key(self.0).value()
    }
    fn sign(&self, data: &[u8]) -> Result<[u8; 64], cdht::Error> {
        vld0::sign(self.0, data)
            .map(|signature| *signature.value())
            .map_err(|_| cdht::Error::BadSignature)
    }
}

pub(in crate::keys) fn fixed_record(
    root: &Secret,
    lineage: &Lineage,
    evidence: &[u8],
    nonce: [u8; 24],
) -> Result<(cdht::Descriptor, cdht::SignedValue), Error> {
    let read = inspection::lineage_secret(root, lineage)?;
    let ciphertext = crate::Vld0RecordCipher { secret: &read }.crypt(&nonce, evidence)?;
    let signer = RootSigner(root);
    let schema = cdht::Schema::dflt(1).map_err(|_| Error::Encoding)?;
    let descriptor = cdht::Descriptor::create(&schema, &signer).map_err(|_| Error::Crypto)?;
    let value = cdht::SignedValue::sign_with_nonce(
        &descriptor.owner,
        0,
        0,
        ciphertext.to_vec(),
        Some(nonce),
        &signer,
    )
    .map_err(|_| Error::Crypto)?;
    Ok((descriptor, value))
}

impl<S: SecureStore, C: Clock, R: Entropy, A: Authority> Keys<S, C, R, A> {
    /// Prepare only the certified first lineage record: original DFLT(1),
    /// root-owned subkey zero, sequence zero and a fresh encrypted value.
    /// `canonical_evidence` is the exact final packed plaintext admitted by the
    /// dedicated owner. CVLT owns packing and certificate/assertion verification.
    ///
    /// Only successful original Create can arm this attempt. The marker is
    /// consumed before any await, including refusal/cancellation. Reopening,
    /// restore, pending-output inspection or a generic signing intent cannot
    /// create another attempt. Persist the exact signed outputs before network
    /// publication; this method grants no normal Use or recovery checkpoint.
    pub async fn prepare_genesis_record(
        &mut self,
        receipt: &Receipt,
        canonical_evidence: &[u8],
        expires: u64,
    ) -> Result<(cdht::Descriptor, cdht::SignedValue), Error> {
        let initial = self.genesis.take().ok_or(Error::Unauthorized)?;
        if canonical_evidence.is_empty() || canonical_evidence.len() > cdht::MAX_SUBKEY_SIZE {
            return Err(Error::Limit);
        }
        self.refresh().await?;
        initial.check(self.loaded()?, receipt)?;
        let authority_reference = self.loaded()?.metadata.info.authority_reference().to_vec();
        let now = self.now()?;
        if now >= expires {
            return Err(Error::Expired);
        }
        if let Err(error) = self
            .authority
            .check_genesis(crate::GenesisAuthorization {
                receipt,
                authority_reference: &authority_reference,
                evidence: canonical_evidence,
                now,
                expires,
            })
            .await
        {
            self.fail_closed(if error == Error::Revoked {
                State::Revoked
            } else {
                State::Locked
            });
            return Err(match error {
                Error::Unavailable | Error::Revoked => error,
                _ => Error::Unauthorized,
            });
        }
        // The authority may await current policy/HTTPS. Verify the same original
        // durable Keys generation again; no prior local check authorizes output.
        self.refresh().await?;
        let completed = self.now()?;
        if completed >= expires {
            return Err(Error::Expired);
        }
        initial.check(self.loaded()?, receipt)?;
        // The asynchronous admission precedes the final Store wait. The owner
        // must reborrow its actual current policy/session observation now.
        if let Err(error) = self
            .authority
            .check_genesis_current(crate::GenesisAuthorization {
                receipt,
                authority_reference: &authority_reference,
                evidence: canonical_evidence,
                now: completed,
                expires,
            })
        {
            self.fail_closed(if error == Error::Revoked {
                State::Revoked
            } else {
                State::Locked
            });
            return Err(match error {
                Error::Unavailable | Error::Revoked => error,
                _ => Error::Unauthorized,
            });
        }
        let mut nonce = [0; 24];
        self.entropy.fill(&mut nonce)?;
        let open = self.loaded()?;
        let output = fixed_record(
            open.material.root()?,
            &open.metadata.lineage,
            canonical_evidence,
            nonce,
        )?;
        if self.now()? >= expires {
            return Err(Error::Expired);
        }
        Ok(output)
    }
}

#[cfg(test)]
#[path = "../../tests/unit/genesis.rs"]
mod tests;

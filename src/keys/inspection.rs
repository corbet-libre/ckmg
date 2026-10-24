//! Original sealed checkpoint metadata, without granting authority or custody.
use super::*;

mod completion;
mod initial_ack;
pub use initial_ack::InitialCheckpointProvenance;
pub(in crate::keys) use initial_ack::StoredInitial;
mod lineage;
mod publication;
pub use completion::{CompletionIntent, PendingCompletion, PendingCreation};
pub use lineage::{
    InitialLineageReader, LineageReadCapability, LineageReadCustody, ProvisionalLineage,
};
pub(in crate::keys) use lineage::{lineage_read_capability, lineage_secret};

#[cfg(test)]
#[path = "../../tests/unit/checkpoint_inspection.rs"]
mod tests;

/// Public claims authenticated by the original PRF-wrapped checkpoint format.
/// This is not current authority: the composer must independently bind these
/// bytes to a forced authenticated Records read and current live device rights.
/// No secret, device name, passkey reference or signing capability is retained.
pub struct CheckpointInspection {
    lineage: Lineage,
    device: PublicKey,
    revision: u64,
    last_time: u64,
    digest: [u8; 32],
}

impl CheckpointInspection {
    /// Original verified public lineage, not proof that it is the latest one.
    pub fn lineage(&self) -> &Lineage {
        &self.lineage
    }
    /// Device public key derived from the actual sealed device material.
    pub fn device(&self) -> PublicKey {
        self.device
    }
    /// Original local checkpoint revision, distinct from the Records sequence.
    pub fn revision(&self) -> u64 {
        self.revision
    }
    /// Persisted clock floor; the live composer clock must not precede it.
    pub fn last_time(&self) -> u64 {
        self.last_time
    }
    /// Digest of the exact original encrypted checkpoint, never plaintext keys.
    pub fn sealed_digest(&self) -> &[u8; 32] {
        &self.digest
    }
}
redacted!(CheckpointInspection);

/// Authenticate and inspect an original retained Keys checkpoint with its PRF.
/// Uses exactly the owner's wrapping key, local locator AAD, decoder and lineage
/// validation. All decrypted material is dropped before returning public claims.
///
/// This cannot unlock Keys, create a root, prove currentness, approve an intent or
/// substitute for live Authority. A stale correctly sealed checkpoint may pass
/// inspection; only the original Records/current-authority composition can reject
/// staleness. Pending, revoked and pairing-only checkpoints refuse this path.
pub fn inspect_checkpoint(
    prf: &PrfOutput,
    community: &str,
    sealed: &[u8],
) -> Result<CheckpointInspection, Error> {
    CheckpointInspector::new(prf, community)?.inspect(sealed)
}

/// Narrow original checkpoint-decryption capability for a trusted Authority.
/// Retains only the original zeroizing wrapping key, local locator and scope;
/// never the PRF, root/device material, a signer or current-authority state.
///
/// The owning composer must drop this capability with custody on lock, expiry,
/// revocation or cancellation. Locking a separate Keys instance cannot revoke an
/// independently held inspector. There is no clone, serialization or key getter.
pub struct CheckpointInspector {
    key: Secret,
    location: Locator,
    community: String,
}

impl CheckpointInspector {
    /// Derive only the existing checkpoint wrapping capability in its original scope.
    pub fn new(prf: &PrfOutput, community: &str) -> Result<Self, Error> {
        Ok(Self {
            location: passkey::vault_location(prf, community)?,
            key: passkey::ring_key(prf, community)?,
            community: community.into(),
        })
    }

    /// Authenticate original checkpoint metadata without granting custody or
    /// freshness. The original decoder, lineage and state checks remain decisive.
    pub fn inspect(&self, sealed: &[u8]) -> Result<CheckpointInspection, Error> {
        let (metadata, material) = self.decode(sealed)?;
        Ok(inspection(metadata, &material, sealed))
    }

    /// Recover only compound checkpoint custody, after the injected current
    /// authority has checked this exact lineage and original recovery evidence.
    /// No general Keys owner, device signer or Wallet capability is constructed.
    /// The enclosing Vault must drop this owner on lock/cancellation/revocation.
    pub async fn bootstrap(
        &self,
        sealed: &[u8],
        evidence: &[u8],
        clock: &mut impl Clock,
        authority: &mut impl Authority,
    ) -> Result<CheckpointBootstrap, Error> {
        if evidence.is_empty() || evidence.len() > MAX_MESSAGE_BYTES {
            return Err(Error::Limit);
        }
        let (metadata, mut material) = self.decode(sealed)?;
        let now = clock.now()?;
        if now < metadata.last_time {
            return Err(Error::Clock);
        }
        authority
            .check(Authorization {
                binding: &metadata.lineage.binding,
                root: Some(metadata.lineage.root),
                device: vld0::public_key(&material.device),
                epoch: metadata.lineage.epoch,
                action: Action::Use,
                target: None,
                statement: Some(metadata.lineage.digest()?),
                signing: None,
                now,
                evidence,
            })
            .await?;
        let checked_at = clock.now()?;
        if checked_at < now {
            return Err(Error::Clock);
        }
        let root = material.root.take().ok_or(Error::NoRoot)?;
        let cipher = passkey::common_store_cipher(&root, metadata.lineage.binding.community())?;
        Ok(CheckpointBootstrap {
            location: self.location,
            root,
            cipher,
            checked_at,
            inspection: inspection(metadata, &material, sealed),
        })
    }

    fn decode_retained(&self, sealed: &[u8]) -> Result<(Metadata, Material), Error> {
        if sealed.len() > MAX_CHECKPOINT_BYTES {
            return Err(Error::Limit);
        }
        let bytes = sealed
            .strip_prefix(CHECKPOINT_HEADER)
            .ok_or(Error::Encoding)?;
        let plaintext = keyring::open(&self.key, &checkpoint_aad(self.location), bytes)?;
        let (metadata, material) = decode_checkpoint(&plaintext)?;
        if metadata.lineage.binding.community() != self.community {
            return Err(Error::Unauthorized);
        }
        validate_checkpoint(&metadata, &material)?;
        if metadata.revoked {
            return Err(Error::Revoked);
        }
        if metadata.pairing.is_some() || material.root.is_none() {
            return Err(Error::NoRoot);
        }
        Ok((metadata, material))
    }

    fn decode(&self, sealed: &[u8]) -> Result<(Metadata, Material), Error> {
        let (metadata, material) = self.decode_retained(sealed)?;
        if metadata.output.is_some() {
            return Err(Error::Pending);
        }
        Ok((metadata, material))
    }
}

fn inspection(metadata: Metadata, material: &Material, sealed: &[u8]) -> CheckpointInspection {
    CheckpointInspection {
        device: vld0::public_key(&material.device),
        lineage: metadata.lineage,
        revision: metadata.revision,
        last_time: metadata.last_time,
        digest: *blake3::hash(sealed).as_bytes(),
    }
}

/// Temporary root custody restricted to the approved compound checkpoint.
/// No root/device getter, cloning, signing, serialization or general purpose
/// selector exists. It grants no member authority and cannot initialize Wallet.
pub struct CheckpointBootstrap {
    location: Locator,
    root: Secret,
    cipher: passkey::StoreCipher,
    checked_at: u64,
    inspection: CheckpointInspection,
}
impl CheckpointBootstrap {
    /// Monotonic observation floor only; this is never an accepting lease.
    pub fn checked_at(&self) -> u64 {
        self.checked_at
    }
    /// Exact authenticated source claims, for matching the restored Keys entry.
    pub fn inspection(&self) -> &CheckpointInspection {
        &self.inspection
    }

    /// Retain only this exact passkey record's read custody in the recovered
    /// member owner. Available after full bootstrap Use, never from provisional
    /// lineage admission. No PRF, writer or authority verdict is retained.
    /// Drop it with that member owner on lock or revocation; reads cannot reopen
    /// Keys or bypass any subsequent member check.
    pub fn passkey_reader(
        &self,
        prf: &passkey::PrfOutput,
    ) -> Result<passkey::PasskeyRecordReader<'static>, Error> {
        let community = self.inspection.lineage.binding.community();
        if passkey::vault_location(prf, community)? != self.location {
            return Err(Error::Unauthorized);
        }
        Ok(passkey::passkey_record_reader(prf, community)?.into_session())
    }

    /// Derive only the current common-root Store wrapping domain.
    /// The borrow cannot outlive this bootstrap owner, including across Store I/O.
    ///
    /// ```compile_fail
    /// fn escape(bootstrap: ckmg::CheckpointBootstrap) {
    ///     let cipher = bootstrap.store_cipher().unwrap();
    ///     drop(bootstrap);
    ///     let _ = cipher.open(b"scope", b"sealed");
    /// }
    /// ```
    pub fn store_cipher(&self) -> Result<&passkey::StoreCipher, Error> {
        Ok(&self.cipher)
    }

    /// Initialize only the fixed compound manifest or one of its bounded chunks.
    /// This preserves the original member-purpose derivation and epoch address.
    ///
    /// ```compile_fail
    /// fn escape(bootstrap: ckmg::CheckpointBootstrap) {
    ///     let record = bootstrap.record(None).unwrap();
    ///     drop(bootstrap);
    ///     let _ = record.with_record(|signer, _| signer.sign(b"record"));
    /// }
    /// ```
    pub fn record(&self, child: Option<u8>) -> Result<CheckpointRecordCustody<'_>, Error> {
        let purpose = super::checkpoint_record_purpose(child.map(usize::from))?;
        let lineage = &self.inspection.lineage;
        let context = encode(
            b"ckmg.purpose.context.v1\0",
            &(
                &lineage.binding,
                lineage.epoch,
                Option::<PublicKey>::None,
                &purpose,
                &[] as &[u8],
            ),
        )?;
        let owner = derive_purpose_secret(&self.root, &context, false);
        let cipher = derive_purpose_secret(&self.root, &context, true);
        let read = Zeroizing::new(blake3::derive_key(
            "ckmg 2026-10 VLD0 record encryption v1",
            &*cipher,
        ));
        Ok(CheckpointRecordCustody {
            owner,
            read,
            _bootstrap: std::marker::PhantomData,
        })
    }
}
redacted!(CheckpointBootstrap);

/// An opaque initializer for the fixed DFLT(32) compound record. Carries only
/// this record's derived owner/read keys, never a common root or device seed.
pub struct CheckpointRecordCustody<'bootstrap> {
    owner: Secret,
    read: Secret,
    _bootstrap: std::marker::PhantomData<&'bootstrap CheckpointBootstrap>,
}
impl CheckpointRecordCustody<'_> {
    /// Canonical public owner; Records derives its locator from this and DFLT(32).
    pub fn public_key(&self) -> PublicKey {
        vld0::public_key(&self.owner)
    }

    /// Lend only this record's original signer and read cipher synchronously.
    /// The callback may return owned signed/encrypted bytes, never secret custody.
    pub fn with_record<T>(
        &self,
        use_record: impl for<'key> FnOnce(Vld0Signer<'key>, crate::Vld0RecordCipher<'key>) -> T,
    ) -> T {
        use_record(
            Vld0Signer(Ed25519Signer {
                secret: &self.owner,
                public_key: *self.public_key().value(),
            }),
            crate::Vld0RecordCipher { secret: &self.read },
        )
    }
}
impl std::fmt::Debug for CheckpointRecordCustody<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CheckpointRecordCustody([redacted])")
    }
}

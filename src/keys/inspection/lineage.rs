//! Fixed root-owned lineage decryption; never a member authorization result.
use super::*;

/// Read-only custody retained by the authorized member owner. The root is only
/// its public record owner; only the purpose-separated read key is retained.
/// No writer, arbitrary purpose, key export, clone or serializer exists.
pub struct LineageReadCustody {
    owner: PublicKey,
    read: Secret,
}
impl LineageReadCustody {
    /// Original root public key, used with the fixed DFLT(1) lineage schema.
    pub fn owner(&self) -> PublicKey {
        self.owner
    }

    /// Open only original ciphertext after the adapter verifies its signed
    /// descriptor/value and forced read agreement. This conveys no authority.
    pub fn open(&self, nonce: &[u8; 24], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        crate::Vld0RecordReader {
            cipher: crate::Vld0RecordCipher { secret: &self.read },
        }
        .open(nonce, ciphertext)
    }
}
redacted!(LineageReadCustody);

/// Provisional reader borrowing the exact retained checkpoint for one restore
/// attempt. It cannot open the Store, sign, publish or become member custody.
/// Drop it before completing restore; never retain it as member authority.
///
/// ```compile_fail
/// fn escape(reader: ckmg::ProvisionalLineage<'_>) -> ckmg::LineageReadCustody {
///     reader.custody
/// }
/// ```
pub struct ProvisionalLineage<'attempt> {
    custody: LineageReadCustody,
    _attempt: std::marker::PhantomData<&'attempt [u8]>,
}
impl ProvisionalLineage<'_> {
    pub fn owner(&self) -> PublicKey {
        self.custody.owner()
    }
    pub fn open(&self, nonce: &[u8; 24], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.custody.open(nonce, ciphertext)
    }
}
redacted!(ProvisionalLineage<'_>);

impl CheckpointInspector {
    /// Decrypt the original checkpoint and ask only for the decided provisional
    /// read admission. Authority verifies certificate/assertion against current
    /// policy after fresh HTTPS, binding every original checkpoint claim.
    pub async fn read_lineage<'attempt>(
        &self,
        sealed: &'attempt [u8],
        evidence: &[u8],
        clock: &mut impl Clock,
        authority: &mut impl Authority,
    ) -> Result<ProvisionalLineage<'attempt>, Error> {
        if evidence.is_empty() || evidence.len() > MAX_MESSAGE_BYTES {
            return Err(Error::Limit);
        }
        let (metadata, material) = self.decode(sealed)?;
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
                action: Action::ReadLineage,
                target: None,
                statement: Some(metadata.lineage.digest()?),
                signing: None,
                now,
                evidence,
            })
            .await?;
        if clock.now()? < now {
            return Err(Error::Clock);
        }
        Ok(ProvisionalLineage {
            custody: lineage_reader(material.root()?, &metadata.lineage)?,
            _attempt: std::marker::PhantomData,
        })
    }
}

impl CheckpointBootstrap {
    /// Create the member owner's independent read custody only after normal
    /// member authorization has succeeded. The provisional reader is not reused.
    /// The enclosing member owner must drop this with its session on lock.
    pub fn lineage_reader(&self) -> Result<LineageReadCustody, Error> {
        lineage_reader(&self.root, &self.inspection.lineage)
    }
}

fn lineage_reader(root: &Secret, lineage: &Lineage) -> Result<LineageReadCustody, Error> {
    let purpose = Purpose::new(Scope::Member, "vault.lineage", 0)?;
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
    let cipher = derive_purpose_secret(root, &context, true);
    Ok(LineageReadCustody {
        owner: lineage.root,
        read: Zeroizing::new(blake3::derive_key(
            "ckmg 2026-10 VLD0 record encryption v1",
            &*cipher,
        )),
    })
}

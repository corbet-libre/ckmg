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

const CAPABILITY_DOMAIN: &[u8] = b"ckmg.lineage-read.v1\0";

/// Peer-shareable READ capability of this member's OWN lineage record for one
/// community scope: the record owner's public key plus the purpose-separated
/// read key (the full record key of the Veilid model). It carries no writer,
/// root, device or Store secret and exists only for that one record. It is
/// produced solely by [`crate::Keys::export_lineage_read_capability`] under
/// current member authority, and its bytes travel only inside signed messages.
pub struct LineageReadCapability(Zeroizing<Vec<u8>>);
impl LineageReadCapability {
    /// The opaque handle bytes to place in a signed wave request or announcement.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
redacted!(LineageReadCapability);

pub(in crate::keys) fn lineage_read_capability(
    root: &Secret,
    lineage: &Lineage,
) -> Result<LineageReadCapability, Error> {
    let read = lineage_secret(root, lineage)?;
    let mut out = Zeroizing::new(CAPABILITY_DOMAIN.to_vec());
    for part in [
        lineage.binding.community().as_bytes(),
        lineage.binding.member().as_bytes(),
    ] {
        out.extend_from_slice(
            &u16::try_from(part.len())
                .map_err(|_| Error::Limit)?
                .to_be_bytes(),
        );
        out.extend_from_slice(part);
    }
    out.extend_from_slice(lineage.root.value());
    out.extend_from_slice(&*read);
    Ok(LineageReadCapability(out))
}

impl LineageReadCustody {
    /// Rebuild read-only custody of ONE peer's lineage record from a handle that
    /// the peer signed and handed over. The embedded binding must equal the
    /// expected peer binding. The handle only lets the holder decrypt; the
    /// adapter still verifies the record owner's signatures and the lineage
    /// evidence against the current Charter.
    pub fn from_capability(bytes: &[u8], expected: &Binding) -> Result<Self, Error> {
        let mut rest = bytes
            .strip_prefix(CAPABILITY_DOMAIN)
            .ok_or(Error::Encoding)?;
        fn take<'a>(rest: &mut &'a [u8], count: usize) -> Result<&'a [u8], Error> {
            if rest.len() < count {
                return Err(Error::Encoding);
            }
            let (head, tail) = rest.split_at(count);
            *rest = tail;
            Ok(head)
        }
        let mut parts = Vec::new();
        for _ in 0..2 {
            let length = u16::from_be_bytes(
                take(&mut rest, 2)?
                    .try_into()
                    .map_err(|_| Error::Encoding)?,
            );
            parts.push(take(&mut rest, usize::from(length))?.to_vec());
        }
        let owner: [u8; 32] = take(&mut rest, 32)?
            .try_into()
            .map_err(|_| Error::Encoding)?;
        let read: [u8; 32] = take(&mut rest, 32)?
            .try_into()
            .map_err(|_| Error::Encoding)?;
        if !rest.is_empty() {
            return Err(Error::Encoding);
        }
        if parts[0] != expected.community().as_bytes() || parts[1] != expected.member().as_bytes() {
            return Err(Error::Unauthorized);
        }
        let owner = PublicKey::new(VLD0, owner);
        vld0::validate_public_key(&owner)?;
        Ok(Self {
            owner,
            read: Zeroizing::new(read),
        })
    }
}

/// Fixed initial lineage read custody for one enclosing completion attempt.
/// Only the original purpose-separated read key is retained. This grants no
/// writer, root, Store access, ordinary Keys Use or acknowledgement. The
/// enclosing attempt must own and drop this capability on refusal or disposal;
/// dropping a separate completion owner does not revoke an independent reader.
pub struct InitialLineageReader {
    custody: LineageReadCustody,
}
impl InitialLineageReader {
    /// Exact original initial root public key for its fixed DFLT(1) record.
    pub fn owner(&self) -> PublicKey {
        self.custody.owner()
    }
    /// Open only after the adapter verifies the original signed descriptor,
    /// nonce and value under this fixed owner and fresh forced read agreement.
    /// This decryption is not an authentication or current-authority verdict.
    pub fn open(&self, nonce: &[u8; 24], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.custody.open(nonce, ciphertext)
    }
}
redacted!(InitialLineageReader);

pub(super) fn initial_reader(
    root: &Secret,
    lineage: &Lineage,
) -> Result<InitialLineageReader, Error> {
    Ok(InitialLineageReader {
        custody: lineage_reader(root, lineage)?,
    })
}

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
    /// Public owner of the fixed original lineage record; no member authority.
    pub fn owner(&self) -> PublicKey {
        self.custody.owner()
    }
    /// Decrypt only that original lineage record under this borrowed attempt.
    /// The cipher, root, Store custody and all publication keys remain private.
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
    Ok(LineageReadCustody {
        owner: lineage.root,
        read: lineage_secret(root, lineage)?,
    })
}

pub(in crate::keys) fn lineage_secret(root: &Secret, lineage: &Lineage) -> Result<Secret, Error> {
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
    Ok(Zeroizing::new(blake3::derive_key(
        "ckmg 2026-10 VLD0 record encryption v1",
        &*cipher,
    )))
}

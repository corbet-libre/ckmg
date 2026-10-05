//! Original sealed checkpoint metadata, without granting authority or custody.
use super::*;

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
        if metadata.output.is_some() {
            return Err(Error::Pending);
        }
        Ok(CheckpointInspection {
            device: vld0::public_key(&material.device),
            lineage: metadata.lineage,
            revision: metadata.revision,
            last_time: metadata.last_time,
            digest: *blake3::hash(sealed).as_bytes(),
        })
    }
}

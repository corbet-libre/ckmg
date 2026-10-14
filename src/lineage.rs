//! Bounded, versioned custody transcripts. These are not membership credentials.

use crate::{Error, MAX_DEVICES, MAX_MESSAGE_BYTES, PublicKey, Purpose, Signature, vld0};
use serde::{Deserialize, Serialize};

#[cfg(test)]
#[path = "../tests/unit/lineage.rs"]
mod tests;

/// Community identifier and the externally verified cpsd pseudonym. Never root-derived.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(try_from = "BindingWire", into = "BindingWire")]
pub struct Binding {
    community: String,
    member: String,
}

#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct BindingWire {
    community: String,
    member: String,
}

impl TryFrom<BindingWire> for Binding {
    type Error = Error;
    fn try_from(value: BindingWire) -> Result<Self, Error> {
        Self::new(&value.community, &value.member)
    }
}

impl From<Binding> for BindingWire {
    fn from(value: Binding) -> Self {
        Self {
            community: value.community,
            member: value.member,
        }
    }
}

impl Binding {
    /// Validate identifiers, without claiming to verify membership. The injected
    /// authority must authenticate this binding before creating or using any keys.
    pub fn new(community: &str, member: &str) -> Result<Self, Error> {
        for value in [community, member] {
            if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
                return Err(Error::Encoding);
            }
        }
        Ok(Self {
            community: community.into(),
            member: member.into(),
        })
    }

    /// Community identifier, for authorized local use.
    pub fn community(&self) -> &str {
        &self.community
    }
    /// Pseudonym, unchanged by device or root rotation.
    pub fn member(&self) -> &str {
        &self.member
    }
}

/// Root-signed current device set. The root is community-local and is never a member ID.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Lineage {
    /// Format version; 2 binds a retained common identity, 1 is historical.
    pub version: u8,
    /// Scope of every key in this lineage.
    pub binding: Binding,
    /// Increases on every root rotation; starts at 1.
    pub epoch: u64,
    /// Strictly increasing lineage revision, including pairing additions.
    pub revision: u64,
    /// Current root public key.
    pub root: PublicKey,
    /// Original scope-local identity; version 2 preserves it across epoch rotations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<PublicKey>,
    /// Unique authorized device keys, sorted by typed bytes.
    pub devices: Vec<PublicKey>,
    /// Root signature over [`Self::signed_bytes`].
    pub signature: Signature,
}

impl Lineage {
    /// Canonical transcript, independent of a transport's JSON formatting.
    pub fn signed_bytes(&self) -> Result<Vec<u8>, Error> {
        self.shape()?;
        if self.version == 2 {
            return encode(
                b"ckmg.lineage.v2\0",
                &(
                    self.version,
                    &self.binding,
                    self.epoch,
                    self.revision,
                    self.root,
                    &self.devices,
                    self.identity,
                ),
            );
        }
        encode(
            b"ckmg.lineage.v1\0",
            &(
                self.version,
                &self.binding,
                self.epoch,
                self.revision,
                self.root,
                &self.devices,
            ),
        )
    }

    fn shape(&self) -> Result<(), Error> {
        if !matches!((self.version, self.identity), (1, None) | (2, Some(_)))
            || self.epoch == 0
            || self.revision == 0
            || self.devices.is_empty()
            || self.devices.len() > MAX_DEVICES
            || self.devices.windows(2).any(|v| v[0] >= v[1])
        {
            return Err(Error::Encoding);
        }
        vld0::validate_public_key(&self.root)?;
        if let Some(identity) = self.identity {
            vld0::validate_public_key(&identity)?;
        }
        for device in &self.devices {
            vld0::validate_public_key(device)?;
            if *device == self.root {
                return Err(Error::InvalidKey);
            }
        }
        Ok(())
    }

    /// Check the self-signature. This does not establish trusted origin or freshness;
    /// callers must compare with authenticated current authority from their own port.
    pub fn verify(&self) -> Result<(), Error> {
        vld0::verify(&self.root, &self.signed_bytes()?, &self.signature)
    }

    /// Canonical digest used to bind an exact predecessor.
    pub fn digest(&self) -> Result<[u8; 32], Error> {
        self.verify()?;
        digest(b"ckmg.lineage.digest.v1\0", self)
    }
}

/// Hard upper bound of a pairing request's lifetime; the composer chooses the actual
/// lifetime from the community rulebook and may never exceed this.
pub const MAX_PAIRING_SECONDS: u64 = 900;

/// Default pairing request lifetime when the caller names none.
pub const DEFAULT_PAIRING_SECONDS: u64 = 300;

/// Proof of possession by a pending device, bound to a confirmed community root.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingRequest {
    /// Format version, currently 1.
    pub version: u8,
    /// Intended community and pseudonym.
    pub binding: Binding,
    /// Root confirmed through the authenticated pairing channel.
    pub root: PublicKey,
    /// Expected current authority epoch.
    pub epoch: u64,
    /// Independent recipient device key.
    pub device: PublicKey,
    /// Single-use random challenge, persisted before publication.
    pub nonce: [u8; 32],
    /// Inclusive start of the validity window.
    pub issued_at: u64,
    /// Exclusive deadline, at most five minutes after issuance.
    pub expires_at: u64,
    /// Recipient device proof over [`Self::signed_bytes`].
    pub proof: Signature,
}

impl PairingRequest {
    /// Canonical transcript for the device proof and authority adapter.
    pub fn signed_bytes(&self) -> Result<Vec<u8>, Error> {
        if self.version != 1
            || self.epoch == 0
            || self.issued_at >= self.expires_at
            || self.expires_at - self.issued_at > MAX_PAIRING_SECONDS
            || self.root == self.device
        {
            return Err(Error::Encoding);
        }
        vld0::validate_public_key(&self.root)?;
        vld0::validate_public_key(&self.device)?;
        encode(
            b"ckmg.pairing.request.v1\0",
            &(
                self.version,
                &self.binding,
                self.root,
                self.epoch,
                self.device,
                self.nonce,
                self.issued_at,
                self.expires_at,
            ),
        )
    }

    /// Check possession and time. User approval is separately required by Authority.
    pub fn verify(&self, now: u64) -> Result<(), Error> {
        let bytes = self.signed_bytes()?;
        if now < self.issued_at || now >= self.expires_at {
            return Err(Error::Expired);
        }
        vld0::verify(&self.device, &bytes, &self.proof)
    }

    /// Stable digest for approval binding; includes the proof.
    pub fn digest(&self) -> Result<[u8; 32], Error> {
        self.signed_bytes()?;
        digest(b"ckmg.pairing.digest.v1\0", self)
    }
}

fn legacy_transfer() -> u8 {
    1
}
fn is_legacy_transfer(version: &u8) -> bool {
    *version == 1
}

/// Root transfer to exactly one proven device. Contains no clear secret.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingGrant {
    /// Transfer format: 1 epoch root; 2 adds identity; 3 adds historical opening roots.
    #[serde(
        default = "legacy_transfer",
        skip_serializing_if = "is_legacy_transfer"
    )]
    pub version: u8,
    /// Exact request approved by the live device.
    pub request: PairingRequest,
    /// Updated root-signed device set.
    pub lineage: Lineage,
    /// HPKE ciphertext containing epoch root and, in version 2, the common random identity root.
    pub sealed_root: Vec<u8>,
    /// Root signature authenticating the entire grant including ciphertext.
    pub signature: Signature,
}

impl PairingGrant {
    pub(crate) fn aad(&self) -> Result<Vec<u8>, Error> {
        encode(
            match self.version {
                1 => b"ckmg.pairing.root.v2\0".as_slice(),
                2 => b"ckmg.pairing.root.v3\0".as_slice(),
                3 => b"ckmg.pairing.root.v4\0".as_slice(),
                _ => return Err(Error::Encoding),
            },
            &(self.request.digest()?, self.lineage.digest()?),
        )
    }
    pub(crate) fn signed_bytes(&self) -> Result<Vec<u8>, Error> {
        crate::vld0::validate_sealed_root(self.version, self.sealed_root.len())?;
        encode(
            match self.version {
                1 => b"ckmg.pairing.grant.v1\0",
                2 => b"ckmg.pairing.grant.v2\0",
                3 => b"ckmg.pairing.grant.v3\0",
                _ => return Err(Error::Encoding),
            },
            &(&self.request, &self.lineage, &self.sealed_root),
        )
    }
}

/// Root ciphertext for a remaining device during rotation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootEnvelope {
    /// Only this device can open the ciphertext.
    pub device: PublicKey,
    /// HPKE ciphertext; never a raw key.
    pub sealed_root: Vec<u8>,
}

/// Old-root-authorized transition to the next root and epoch.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rotation {
    /// Transfer format: 1 epoch root; 2 adds identity; 3 adds historical opening roots.
    #[serde(
        default = "legacy_transfer",
        skip_serializing_if = "is_legacy_transfer"
    )]
    pub version: u8,
    /// Digest of the exact previous lineage.
    pub predecessor: [u8; 32],
    /// Previous root, whose signature authorizes succession.
    pub previous_root: PublicKey,
    /// Revoked device; it never receives the replacement root.
    pub revoked: PublicKey,
    /// Replacement root and device set, signed by that root.
    pub lineage: Lineage,
    /// One root envelope per surviving device, including the initiator.
    pub envelopes: Vec<RootEnvelope>,
    /// Old root's signature over all fields except this one.
    pub signature: Signature,
}

impl Rotation {
    pub(crate) fn aad(&self, device: PublicKey) -> Result<Vec<u8>, Error> {
        encode(
            match self.version {
                1 => b"ckmg.rotation.root.v1\0".as_slice(),
                2 => b"ckmg.rotation.root.v2\0".as_slice(),
                3 => b"ckmg.rotation.root.v3\0".as_slice(),
                _ => return Err(Error::Encoding),
            },
            &(
                self.predecessor,
                self.previous_root,
                self.revoked,
                self.lineage.digest()?,
                device,
            ),
        )
    }

    /// Exact succession transcript, including every ciphertext.
    pub fn signed_bytes(&self) -> Result<Vec<u8>, Error> {
        if self.envelopes.len() != self.lineage.devices.len()
            || self.envelopes.len() > MAX_DEVICES
            || self
                .envelopes
                .iter()
                .zip(&self.lineage.devices)
                .any(|(e, d)| {
                    e.device != *d
                        || crate::vld0::validate_sealed_root(self.version, e.sealed_root.len())
                            .is_err()
                })
        {
            return Err(Error::Encoding);
        }
        encode(
            match self.version {
                1 => b"ckmg.rotation.v1\0",
                2 => b"ckmg.rotation.v2\0",
                3 => b"ckmg.rotation.v3\0",
                _ => return Err(Error::Encoding),
            },
            &(
                self.predecessor,
                self.previous_root,
                self.revoked,
                &self.lineage,
                &self.envelopes,
            ),
        )
    }

    /// Verify exact predecessor, one removed device, next epoch/revision, new-root
    /// possession and old-root authorization. Freshness remains the authority's job.
    pub fn verify(&self, previous: &Lineage) -> Result<(), Error> {
        previous.verify()?;
        self.lineage.verify()?;
        if self.lineage.version != previous.version || self.lineage.identity != previous.identity {
            return Err(Error::Unauthorized);
        }
        let remaining: Vec<_> = previous
            .devices
            .iter()
            .copied()
            .filter(|d| *d != self.revoked)
            .collect();
        if self.predecessor != previous.digest()?
            || self.previous_root != previous.root
            || self.lineage.binding != previous.binding
            || self.lineage.root == previous.root
            || self.lineage.epoch != previous.epoch.checked_add(1).ok_or(Error::Limit)?
            || self.lineage.revision != previous.revision.checked_add(1).ok_or(Error::Limit)?
            || !previous.devices.contains(&self.revoked)
            || self.lineage.devices != remaining
        {
            return Err(Error::Unauthorized);
        }
        vld0::verify(&self.previous_root, &self.signed_bytes()?, &self.signature)
    }
}

/// Device-certified purpose key. All authority context is in this signed transcript;
/// owner payloads can consequently retain their exact upstream bytes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyCertificate {
    /// Community and pseudonym.
    pub binding: Binding,
    /// Current authority epoch.
    pub epoch: u64,
    /// Authorizing device.
    pub device: PublicKey,
    /// Narrow key purpose, scope and generation.
    pub purpose: Purpose,
    /// Purpose public key, never the device or root secret.
    pub key: PublicKey,
    /// Device's signature over all preceding fields.
    pub signature: Signature,
}

impl KeyCertificate {
    pub(crate) fn signed_bytes(&self) -> Result<Vec<u8>, Error> {
        self.purpose.validate()?;
        vld0::validate_public_key(&self.key)?;
        encode(
            b"ckmg.purpose.certificate.v1\0",
            &(
                &self.binding,
                self.epoch,
                self.device,
                &self.purpose,
                self.key,
            ),
        )
    }

    /// Verify against authenticated current lineage and the expected purpose.
    pub fn verify(&self, current: &Lineage, expected: &Purpose) -> Result<(), Error> {
        current.verify()?;
        if self.binding != current.binding
            || self.epoch != current.epoch
            || self.purpose != *expected
            || !current.devices.contains(&self.device)
        {
            return Err(Error::Unauthorized);
        }
        vld0::verify(&self.device, &self.signed_bytes()?, &self.signature)
    }

    /// Verify only the original device-certified data against independently
    /// authenticated peer binding, purpose and device expectations.
    ///
    /// This establishes neither current lineage nor epoch freshness, enrollment,
    /// membership or revocation status. Those remain the authenticated peer
    /// owner's responsibility; no custody or authorization capability is returned.
    pub fn verify_device_certificate(
        &self,
        expected_binding: &Binding,
        expected_purpose: &Purpose,
        expected_device: &PublicKey,
    ) -> Result<(), Error> {
        if self.binding != *expected_binding
            || self.purpose != *expected_purpose
            || self.device != *expected_device
            || self.epoch == 0
        {
            return Err(Error::Unauthorized);
        }
        vld0::verify(expected_device, &self.signed_bytes()?, &self.signature)
    }
}

pub(crate) fn encode<T: Serialize>(domain: &[u8], value: &T) -> Result<Vec<u8>, Error> {
    let mut bytes = domain.to_vec();
    serde_json::to_writer(&mut bytes, value).map_err(|_| Error::Encoding)?;
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(Error::Limit);
    }
    Ok(bytes)
}

pub(crate) fn digest<T: Serialize>(domain: &[u8], value: &T) -> Result<[u8; 32], Error> {
    Ok(*blake3::hash(&encode(domain, value)?).as_bytes())
}

macro_rules! redacted {
    ($($ty:ty),+ $(,)?) => { $(
        impl std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($ty), "([redacted])"))
            }
        }
    )+ };
}
pub(crate) use redacted;
redacted!(
    Binding,
    Lineage,
    PairingRequest,
    PairingGrant,
    RootEnvelope,
    Rotation,
    KeyCertificate
);

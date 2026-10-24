//! Typed pairing messages. A pairing signature is never over caller-chosen bytes: the
//! guest's possession proof and the host's revision approval are built here and led by their
//! `DeviceFormat` tag, so the signature is valid for no other format.
use crate::{DeviceFormat, Error};

/// Which of the two pairing steps a [`PairingPossession`] answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingStep {
    /// `device_add`: register the key PENDING.
    Add,
    /// `device_activate`: make the pending key ACTIVE.
    Activate,
}

impl PairingStep {
    const fn code(self) -> u8 {
        match self {
            Self::Add => 1,
            Self::Activate => 2,
        }
    }
}

fn check_name(value: &str) -> Result<(), Error> {
    if value.is_empty() || value.len() > usize::from(u16::MAX) {
        return Err(Error::Encoding);
    }
    Ok(())
}

/// The only message a pairing guest's device key signs before it is a member of anything:
/// the community, the step, the community's one-use challenge of that step and the guest's
/// own public key. A typed input, never raw bytes; signed under its own format tag
/// ([`DeviceFormat::PairingPossession`]) so the signature is valid for no other format, and
/// it names the step, so an add signature is not an activate signature. It grants nothing
/// alone: the community accepts it only with the approved PENDING record of exactly this key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairingPossession<'a> {
    community: &'a str,
    step: PairingStep,
    challenge: &'a str,
    device: [u8; 32],
}

impl<'a> PairingPossession<'a> {
    /// The possession message of `step` for `device` over the community's `challenge`.
    /// Community and challenge are non-empty and at most 65535 bytes (two-byte lengths).
    pub fn new(
        community: &'a str,
        step: PairingStep,
        challenge: &'a str,
        device: &[u8; 32],
    ) -> Result<Self, Error> {
        check_name(community)?;
        check_name(challenge)?;
        Ok(Self {
            community,
            step,
            challenge,
            device: *device,
        })
    }

    /// The community this possession is for.
    pub fn community(&self) -> &str {
        self.community
    }

    /// The pairing step this possession answers.
    pub fn step(&self) -> PairingStep {
        self.step
    }

    /// The public device key this possession is for.
    pub fn device(&self) -> &[u8; 32] {
        &self.device
    }

    /// The payload under the format tag: step, community, challenge, device key.
    pub fn payload(&self) -> Vec<u8> {
        let mut payload = vec![self.step.code()];
        payload.extend_from_slice(&(self.community.len() as u16).to_be_bytes());
        payload.extend_from_slice(self.community.as_bytes());
        payload.extend_from_slice(&(self.challenge.len() as u16).to_be_bytes());
        payload.extend_from_slice(self.challenge.as_bytes());
        payload.extend_from_slice(&self.device);
        payload
    }

    /// The exact signed bytes (format tag then payload), checked with the device key.
    pub fn message(&self) -> Vec<u8> {
        [DeviceFormat::PairingPossession.tag(), &self.payload()[..]].concat()
    }
}

/// The approving (host) device's evidence over one pairing revision: its own device key
/// signs the pairing digest of a community (`cvld.device-pair.v1`, the digest the stamp
/// covers) under [`DeviceFormat::PairingApproval`], through
/// `Keys::sign_device_ed25519_current` (exact one-use admission, class `Admitted`). With the
/// stamp it is the evidence of a lineage revision above 1; the verifier requires the signer
/// in the CURRENT lineage's device set. It grants nothing alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairingApproval<'a> {
    community: &'a str,
    digest: [u8; 32],
}

impl<'a> PairingApproval<'a> {
    /// The approval of `digest` in `community` (non-empty, at most 65535 bytes).
    pub fn new(community: &'a str, digest: &[u8; 32]) -> Result<Self, Error> {
        check_name(community)?;
        Ok(Self {
            community,
            digest: *digest,
        })
    }

    /// The community this approval is for.
    pub fn community(&self) -> &str {
        self.community
    }

    /// The pairing digest it covers.
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Payload: u16 big-endian community length, the community, the 32-byte digest.
    pub fn payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(2 + self.community.len() + 32);
        payload.extend_from_slice(&(self.community.len() as u16).to_be_bytes());
        payload.extend_from_slice(self.community.as_bytes());
        payload.extend_from_slice(&self.digest);
        payload
    }

    /// The exact signed bytes (format tag then payload), verified with the host's device key.
    pub fn message(&self) -> Vec<u8> {
        [DeviceFormat::PairingApproval.tag(), &self.payload()[..]].concat()
    }
}

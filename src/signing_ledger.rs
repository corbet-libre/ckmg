//! One account-key signature per wave slot and phase, never two digests.
//!
//! The account key signs three kinds of digest in a wave: the contact consent, the
//! Resolution receipt and the Acknowledgment. Signing two different digests for the same
//! slot and phase would let a device equivocate, so the owner keeps this ledger: the
//! first digest of a (slot, phase) is recorded with its signature, the same digest later
//! returns that signature, and a different digest is refused. The owner persists the
//! ledger before the signature is sent anywhere.
use crate::{Action, Error};
use serde::{Deserialize, Serialize};

/// The three account-key signatures of one wave.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningPhase {
    /// Consent to one introduction (the `cblc.contact.v1` digest).
    Contact,
    /// The responder's receipt of an Answer or Close.
    Resolution,
    /// The sender's acknowledgment of an Answer.
    Acknowledgment,
}

impl SigningPhase {
    /// The Keys admission that signs this phase.
    pub fn action(self) -> Action {
        match self {
            Self::Contact => Action::SignContact,
            Self::Resolution => Action::SignResolution,
            Self::Acknowledgment => Action::SignAcknowledgment,
        }
    }
}

/// A signature the ledger already holds for the exact digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredSignature(pub [u8; 64]);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    slot: [u8; 32],
    phase: SigningPhase,
    digest: [u8; 32],
    signature: Vec<u8>,
}

/// Bounded record of every account-key signature this device made.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningLedger {
    entries: Vec<Entry>,
}

impl SigningLedger {
    /// Most entries held at once; finished waves are pruned with [`Self::forget`].
    pub const MAX_ENTRIES: usize = 1024;

    /// An empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// The stored signature for this exact digest, `None` if the slot and phase are
    /// unused, and `Unauthorized` if they hold a DIFFERENT digest.
    pub fn lookup(
        &self,
        slot: &[u8; 32],
        phase: SigningPhase,
        digest: &[u8; 32],
    ) -> Result<Option<StoredSignature>, Error> {
        let Some(entry) = self
            .entries
            .iter()
            .find(|e| &e.slot == slot && e.phase == phase)
        else {
            return Ok(None);
        };
        if &entry.digest != digest {
            return Err(Error::Unauthorized);
        }
        let signature: [u8; 64] = entry
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| Error::Encoding)?;
        Ok(Some(StoredSignature(signature)))
    }

    /// Record the first signature of a slot and phase. Recording the same digest again is
    /// a no-op; a different digest is refused.
    pub(crate) fn record(
        &mut self,
        slot: [u8; 32],
        phase: SigningPhase,
        digest: [u8; 32],
        signature: [u8; 64],
    ) -> Result<(), Error> {
        if self.lookup(&slot, phase, &digest)?.is_some() {
            return Ok(());
        }
        if self.entries.len() >= Self::MAX_ENTRIES {
            return Err(Error::Limit);
        }
        self.entries.push(Entry {
            slot,
            phase,
            digest,
            signature: signature.to_vec(),
        });
        Ok(())
    }

    /// Drop every entry of a finished wave.
    pub fn forget(&mut self, slot: &[u8; 32]) {
        self.entries.retain(|e| &e.slot != slot);
    }

    /// Number of entries held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the ledger is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Canonical bytes for the owner's durable record.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(self).map_err(|_| Error::Encoding)
    }

    /// Strict decoding of [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let ledger: Self = serde_json::from_slice(bytes).map_err(|_| Error::Encoding)?;
        if ledger.entries.len() > Self::MAX_ENTRIES
            || ledger.entries.iter().any(|e| e.signature.len() != 64)
        {
            return Err(Error::Encoding);
        }
        Ok(ledger)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_digest_per_slot_and_phase() {
        let mut ledger = SigningLedger::new();
        let (slot, a, b) = ([1; 32], [2; 32], [3; 32]);
        assert_eq!(ledger.lookup(&slot, SigningPhase::Contact, &a), Ok(None));
        ledger
            .record(slot, SigningPhase::Contact, a, [7; 64])
            .unwrap();
        assert_eq!(
            ledger.lookup(&slot, SigningPhase::Contact, &a),
            Ok(Some(StoredSignature([7; 64])))
        );
        // A second, different digest is refused; the same digest changes nothing.
        assert_eq!(
            ledger.lookup(&slot, SigningPhase::Contact, &b),
            Err(Error::Unauthorized)
        );
        assert!(
            ledger
                .record(slot, SigningPhase::Contact, b, [8; 64])
                .is_err()
        );
        ledger
            .record(slot, SigningPhase::Contact, a, [9; 64])
            .unwrap();
        assert_eq!(
            ledger.lookup(&slot, SigningPhase::Contact, &a),
            Ok(Some(StoredSignature([7; 64])))
        );
        // Another phase and another slot are independent.
        assert_eq!(ledger.lookup(&slot, SigningPhase::Resolution, &b), Ok(None));
        assert_eq!(ledger.lookup(&[9; 32], SigningPhase::Contact, &b), Ok(None));
        ledger.forget(&slot);
        assert!(ledger.is_empty());
    }

    #[test]
    fn the_wire_form_round_trips_and_is_bounded() {
        let mut ledger = SigningLedger::new();
        ledger
            .record([1; 32], SigningPhase::Acknowledgment, [2; 32], [3; 64])
            .unwrap();
        let bytes = ledger.to_bytes().unwrap();
        assert_eq!(SigningLedger::from_bytes(&bytes).unwrap(), ledger);
        assert!(SigningLedger::from_bytes(b"{\"entries\":[],\"x\":1}").is_err());
        for n in 0..SigningLedger::MAX_ENTRIES {
            let mut slot = [0u8; 32];
            slot[..8].copy_from_slice(&(n as u64).to_be_bytes());
            let _ = ledger.record(slot, SigningPhase::Contact, [4; 32], [5; 64]);
        }
        assert_eq!(ledger.len(), SigningLedger::MAX_ENTRIES);
        assert!(
            ledger
                .record([0xff; 32], SigningPhase::Contact, [4; 32], [5; 64])
                .is_err()
        );
    }
}

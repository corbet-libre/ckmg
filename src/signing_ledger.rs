//! One account-key signature per wave slot and phase, never two digests.
//!
//! The account key signs three kinds of digest in a wave: the contact consent, the
//! Resolution receipt and the Acknowledgment. Signing two different digests for the same
//! slot and phase would let a device equivocate, so Keys keeps this ledger inside its own
//! encrypted checkpoint ([`AccountLedger`]): the first digest of a (slot, phase) is
//! committed in the same compare-exchange that releases its signature, the same digest
//! later is signed again (RFC 6979 and low-S make the bytes identical), and a different
//! digest is refused. No caller holds, supplies or edits it; entries leave only through
//! `Keys::forget_wave`, under its own admitted action.
//!
//! [`SigningLedger`] is only the former caller-held wire form, kept so that
//! `Keys::import_signing_ledger` can migrate it once. It signs and records nothing.
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

    fn code(self) -> u8 {
        match self {
            Self::Contact => 1,
            Self::Resolution => 2,
            Self::Acknowledgment => 3,
        }
    }

    fn from_code(code: u8) -> Result<Self, Error> {
        match code {
            1 => Ok(Self::Contact),
            2 => Ok(Self::Resolution),
            3 => Ok(Self::Acknowledgment),
            _ => Err(Error::Encoding),
        }
    }
}

/// The statement `Keys::forget_wave` admits: the wave slot and its final receipt
/// digest, domain-separated, so an admission for one wave never forgets another.
pub fn forget_wave_statement(slot: &[u8; 32], receipt: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("ckmg 2026-10 forget wave v1");
    hasher.update(slot);
    hasher.update(receipt);
    *hasher.finalize().as_bytes()
}

/// A signature the former caller-held ledger holds for the exact digest.
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

/// The former caller-held ledger, decoded only to migrate it into Keys.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningLedger {
    entries: Vec<Entry>,
}

impl SigningLedger {
    /// Most entries the former wire form held.
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

    /// Number of entries held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the ledger is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Canonical bytes of the former wire form.
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

/// Leading byte of the checkpoint's ledger section. Material starts with a flag of
/// 0 to 3, so a checkpoint without a section decodes exactly as before.
const SECTION: u8 = b'L';
/// slot (32) | phase (1) | digest (32). No signature is stored: it is recomputed.
const ENTRY_BYTES: usize = 65;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Held {
    slot: [u8; 32],
    phase: SigningPhase,
    digest: [u8; 32],
}

/// The ledger inside the Keys checkpoint. Crate-private: only Keys reads or changes
/// it, and only in a prepared checkpoint that it then compare-exchanges.
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct AccountLedger(Vec<Held>);

impl AccountLedger {
    /// Most entries held; at the cap a new slot and phase is refused, never evicted.
    pub(crate) const MAX_ENTRIES: usize = 1024;

    /// `Ok(true)` if this exact digest already holds the slot and phase, `Ok(false)` if
    /// they are free and there is room, `Unauthorized` if a different digest holds
    /// them, `Limit` if they are free but the ledger is full.
    pub(crate) fn admits(
        &self,
        slot: &[u8; 32],
        phase: SigningPhase,
        digest: &[u8; 32],
    ) -> Result<bool, Error> {
        match self.0.iter().find(|e| &e.slot == slot && e.phase == phase) {
            Some(held) if &held.digest == digest => Ok(true),
            Some(_) => Err(Error::Unauthorized),
            None if self.0.len() >= Self::MAX_ENTRIES => Err(Error::Limit),
            None => Ok(false),
        }
    }

    /// Hold the first digest of a slot and phase; the same digest again changes nothing.
    pub(crate) fn insert(
        &mut self,
        slot: [u8; 32],
        phase: SigningPhase,
        digest: [u8; 32],
    ) -> Result<(), Error> {
        if !self.admits(&slot, phase, &digest)? {
            self.0.push(Held {
                slot,
                phase,
                digest,
            });
        }
        Ok(())
    }

    /// Drop every entry of one finished wave. Whether anything was dropped.
    pub(crate) fn forget(&mut self, slot: &[u8; 32]) -> bool {
        let before = self.0.len();
        self.0.retain(|e| &e.slot != slot);
        self.0.len() != before
    }

    /// Add the former caller-held ledger. Add-only: a slot and phase already held keeps
    /// its digest (the import can only refuse more), and the whole import is refused if
    /// it would pass the cap. Whether anything was added.
    pub(crate) fn import(&mut self, legacy: &SigningLedger) -> Result<bool, Error> {
        let mut merged = self.clone();
        for entry in &legacy.entries {
            match merged.admits(&entry.slot, entry.phase, &entry.digest) {
                Ok(true) | Err(Error::Unauthorized) => {}
                Ok(false) => merged.0.push(Held {
                    slot: entry.slot,
                    phase: entry.phase,
                    digest: entry.digest,
                }),
                Err(error) => return Err(error),
            }
        }
        let added = merged.0.len() != self.0.len();
        *self = merged;
        Ok(added)
    }

    /// Bytes the section adds to a checkpoint.
    pub(crate) fn encoded_len(&self) -> usize {
        if self.0.is_empty() {
            0
        } else {
            3 + self.0.len() * ENTRY_BYTES
        }
    }

    /// Append the section: nothing when empty, else `L`, a u16 LE count and the entries
    /// in the order they were first held.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        if self.0.is_empty() {
            return;
        }
        out.push(SECTION);
        out.extend_from_slice(&(self.0.len() as u16).to_le_bytes());
        for held in &self.0 {
            out.extend_from_slice(&held.slot);
            out.push(held.phase.code());
            out.extend_from_slice(&held.digest);
        }
    }

    /// Strictly decode an optional leading section; returns it and the rest.
    pub(crate) fn decode(bytes: &[u8]) -> Result<(Self, &[u8]), Error> {
        let Some(rest) = bytes.strip_prefix(&[SECTION]) else {
            return Ok((Self::default(), bytes));
        };
        let count = rest.get(..2).ok_or(Error::Encoding)?;
        let count = usize::from(u16::from_le_bytes([count[0], count[1]]));
        if count == 0 || count > Self::MAX_ENTRIES {
            return Err(Error::Encoding);
        }
        let end = 2 + count * ENTRY_BYTES;
        let body = rest.get(2..end).ok_or(Error::Encoding)?;
        let mut ledger = Self(Vec::with_capacity(count));
        for chunk in body.as_chunks::<ENTRY_BYTES>().0 {
            let slot: [u8; 32] = chunk[..32].try_into().map_err(|_| Error::Encoding)?;
            let phase = SigningPhase::from_code(chunk[32])?;
            let digest: [u8; 32] = chunk[33..].try_into().map_err(|_| Error::Encoding)?;
            if ledger.0.iter().any(|e| e.slot == slot && e.phase == phase) {
                return Err(Error::Encoding);
            }
            ledger.0.push(Held {
                slot,
                phase,
                digest,
            });
        }
        Ok((ledger, &rest[end..]))
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.0.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(n: usize) -> [u8; 32] {
        let mut slot = [0u8; 32];
        slot[..8].copy_from_slice(&(n as u64).to_be_bytes());
        slot
    }

    #[test]
    fn one_digest_per_slot_and_phase() {
        let mut ledger = AccountLedger::default();
        let (s, a, b) = ([1; 32], [2; 32], [3; 32]);
        assert_eq!(ledger.admits(&s, SigningPhase::Contact, &a), Ok(false));
        ledger.insert(s, SigningPhase::Contact, a).unwrap();
        assert_eq!(ledger.admits(&s, SigningPhase::Contact, &a), Ok(true));
        assert_eq!(
            ledger.admits(&s, SigningPhase::Contact, &b),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            ledger.insert(s, SigningPhase::Contact, b),
            Err(Error::Unauthorized)
        );
        ledger.insert(s, SigningPhase::Contact, a).unwrap();
        assert_eq!(ledger.len(), 1);
        // Another phase and another slot are independent.
        assert_eq!(ledger.admits(&s, SigningPhase::Resolution, &b), Ok(false));
        assert_eq!(
            ledger.admits(&[9; 32], SigningPhase::Contact, &b),
            Ok(false)
        );
        assert!(ledger.forget(&s));
        assert!(!ledger.forget(&s));
        assert_eq!(ledger.len(), 0);
    }

    #[test]
    fn the_section_round_trips_strictly_and_is_absent_when_empty() {
        let empty = AccountLedger::default();
        let mut out = Vec::new();
        empty.encode(&mut out);
        assert!(out.is_empty());
        assert_eq!(empty.encoded_len(), 0);
        // A checkpoint without a section decodes to the material unchanged.
        let (decoded, rest) = AccountLedger::decode(&[2, 9, 9]).unwrap();
        assert!(decoded == empty && rest == [2, 9, 9]);

        let mut ledger = AccountLedger::default();
        ledger
            .insert([1; 32], SigningPhase::Contact, [2; 32])
            .unwrap();
        ledger
            .insert([1; 32], SigningPhase::Acknowledgment, [3; 32])
            .unwrap();
        let mut out = Vec::new();
        ledger.encode(&mut out);
        assert_eq!(out.len(), ledger.encoded_len());
        assert_eq!(out.len(), 3 + 2 * 65);
        out.extend_from_slice(&[0, 7]);
        let (decoded, rest) = AccountLedger::decode(&out).unwrap();
        assert!(decoded == ledger && rest == [0, 7]);

        // A zero count, an unknown phase, a duplicate slot and phase, and a short body
        // are refused.
        assert!(AccountLedger::decode(&[b'L', 0, 0]).is_err());
        let mut bad = out.clone();
        bad[3 + 32] = 4;
        assert!(AccountLedger::decode(&bad).is_err());
        let mut duplicate = out.clone();
        duplicate[3 + 65 + 32] = 1;
        duplicate[3 + 65 + 33..3 + 130].copy_from_slice(&[2; 32]);
        assert!(AccountLedger::decode(&duplicate).is_err());
        assert!(AccountLedger::decode(&out[..out.len() - 3]).is_err());
    }

    #[test]
    fn the_cap_refuses_and_never_evicts() {
        let mut ledger = AccountLedger::default();
        for n in 0..AccountLedger::MAX_ENTRIES {
            ledger
                .insert(slot(n), SigningPhase::Contact, [4; 32])
                .unwrap();
        }
        assert_eq!(
            ledger.insert([0xff; 32], SigningPhase::Contact, [4; 32]),
            Err(Error::Limit)
        );
        // Held digests still re-sign at the cap; the first entry was not evicted.
        assert_eq!(
            ledger.admits(&slot(0), SigningPhase::Contact, &[4; 32]),
            Ok(true)
        );
        let mut out = Vec::new();
        ledger.encode(&mut out);
        assert_eq!(out.len(), 3 + 1024 * 65);
        assert!(AccountLedger::decode(&out).unwrap().0 == ledger);
    }

    #[test]
    fn the_import_is_add_only() {
        let legacy: SigningLedger = serde_json::from_value(serde_json::json!({
            "entries": [
                {"slot": vec![1u8; 32], "phase": "contact", "digest": vec![2u8; 32], "signature": vec![0u8; 64]},
                {"slot": vec![5u8; 32], "phase": "resolution", "digest": vec![6u8; 32], "signature": vec![0u8; 64]},
            ]
        }))
        .unwrap();
        let mut ledger = AccountLedger::default();
        ledger
            .insert([1; 32], SigningPhase::Contact, [9; 32])
            .unwrap();
        assert_eq!(ledger.import(&legacy), Ok(true));
        // The held digest stays; the conflicting import entry enables nothing.
        assert_eq!(
            ledger.admits(&[1; 32], SigningPhase::Contact, &[9; 32]),
            Ok(true)
        );
        assert_eq!(
            ledger.admits(&[1; 32], SigningPhase::Contact, &[2; 32]),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            ledger.admits(&[5; 32], SigningPhase::Resolution, &[6; 32]),
            Ok(true)
        );
        assert_eq!(ledger.import(&legacy), Ok(false));
        assert_eq!(ledger.len(), 2);
    }

    #[test]
    fn the_former_wire_form_still_decodes_strictly() {
        let legacy = SigningLedger::new();
        let bytes = legacy.to_bytes().unwrap();
        assert_eq!(SigningLedger::from_bytes(&bytes).unwrap(), legacy);
        assert!(SigningLedger::from_bytes(b"{\"entries\":[],\"x\":1}").is_err());
    }

    #[test]
    fn the_forget_statement_binds_slot_and_receipt() {
        let a = forget_wave_statement(&[1; 32], &[2; 32]);
        assert_ne!(a, forget_wave_statement(&[2; 32], &[1; 32]));
        assert_ne!(a, forget_wave_statement(&[1; 32], &[3; 32]));
        assert_eq!(a, forget_wave_statement(&[1; 32], &[2; 32]));
    }
}

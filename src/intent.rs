//! Local command admission, independent of membership, lineage or device authority.
use crate::{Action, Authorization, Binding, Error, PublicKey};
use std::{cell::RefCell, rc::Rc};

/// Exact owner-derived scope of one admitted local command. This is input, not
/// evidence of user identity or permission. Only the trusted Door owns admission.
pub struct AdmittedCommand {
    /// Authenticated community and member binding.
    pub binding: Binding,
    /// Exact origin admitted by the trusted Door; never copied from the request body.
    pub origin: String,
    /// One exact action; approval never implies another action.
    pub action: Action,
    /// Current logical device.
    pub device: PublicKey,
    /// Current/proposed root, or None for explicit creation.
    pub root: Option<PublicKey>,
    /// Exact owner-derived epoch.
    pub epoch: u64,
    /// Exact added/removed device where applicable.
    pub target: Option<PublicKey>,
    /// Original owner pairing/transition digest where applicable.
    pub statement: Option<[u8; 32]>,
    /// Exact original owner bytes, only for SignDeviceEd25519. Never a request-body transcript.
    pub transcript: Option<Vec<u8>>,
    /// Exclusive trusted Unix-second deadline.
    pub expires: u64,
}
struct Pending {
    generation: u64,
    admitted_at: u64,
    command: Option<AdmittedCommand>,
}
#[derive(Default)]
struct Slot {
    generation: u64,
    pending: Option<Pending>,
}
/// Door-only half of one thread-confined intent channel. No Clone/Debug/serde.
pub struct IntentAdmission(Rc<RefCell<Slot>>);
/// Authority-composer half. Successful consumption proves local intent only;
/// actual Foyer session and verified current Records lineage are still mandatory.
pub struct IntentVerifier(Rc<RefCell<Slot>>);
/// Hold across child awaits and HTTP cancellation. Dropping cancels unused intent;
/// no new command is admitted while this generation remains reserved.
pub struct IntentGuard {
    slot: Rc<RefCell<Slot>>,
    generation: u64,
}
/// Construct inside the trusted runtime. Retain admission in the Door and move the
/// verifier into the real authority composer. Never expose either through an API.
/// This creates no member/device/root authority and uses no bearer token format.
pub fn intent_channel() -> (IntentAdmission, IntentVerifier) {
    let slot = Rc::new(RefCell::new(Slot::default()));
    (IntentAdmission(slot.clone()), IntentVerifier(slot))
}
impl IntentAdmission {
    /// Reserve the exact already-admitted local command. The caller must obtain
    /// its scope from actual owners after origin/action/body/capability validation.
    pub fn admit(&mut self, command: AdmittedCommand, now: u64) -> Result<IntentGuard, Error> {
        let mut slot = self.0.borrow_mut();
        if slot.pending.is_some() {
            return Err(Error::Pending);
        }
        if command.origin.is_empty()
            || command.origin.len() > 2048
            || command.origin.chars().any(char::is_control)
        {
            return Err(Error::Encoding);
        }
        if (command.action == Action::SignDeviceEd25519) != command.transcript.is_some()
            || command.transcript.as_ref().is_some_and(|bytes| {
                bytes.len() > crate::MAX_MESSAGE_BYTES
                    || command.target.is_some()
                    || command.statement.is_some()
            })
        {
            return Err(Error::Encoding);
        }
        if command.expires <= now {
            return Err(Error::Expired);
        }
        let generation = slot.generation.checked_add(1).ok_or(Error::Limit)?;
        slot.generation = generation;
        slot.pending = Some(Pending {
            generation,
            admitted_at: now,
            command: Some(command),
        });
        Ok(IntentGuard {
            slot: self.0.clone(),
            generation,
        })
    }
    /// Cancel an admitted operation on explicit runtime cancellation/shutdown.
    /// An older guard cannot later cancel a subsequently admitted command.
    pub fn cancel(&mut self) {
        self.0.borrow_mut().pending = None;
    }
}
impl IntentVerifier {
    /// Consume one attempt after actual live session/current lineage checks and
    /// their post-await deadline rechecks. Refusal also consumes this attempt;
    /// a failed or ambiguous operation never implicitly receives another approval.
    pub fn consume(&mut self, request: &Authorization<'_>, origin: &str) -> Result<(), Error> {
        let mut slot = self.0.borrow_mut();
        let pending = slot.pending.as_mut().ok_or(Error::Unauthorized)?;
        let command = pending.command.take().ok_or(Error::Unauthorized)?;
        if request.now < pending.admitted_at {
            return Err(Error::Clock);
        }
        if request.now >= command.expires {
            return Err(Error::Expired);
        }
        if origin != command.origin
            || request.binding != &command.binding
            || request.action != command.action
            || request.device != command.device
            || request.root != command.root
            || request.epoch != command.epoch
            || request.target != command.target
            || request.statement != command.statement
            || match (request.signing, command.transcript.as_deref()) {
                (None, None) => false,
                (Some(signing), Some(bytes)) => {
                    signing.transcript != bytes || signing.expires != command.expires
                }
                _ => true,
            }
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}
impl Drop for IntentGuard {
    fn drop(&mut self) {
        let mut slot = self.slot.borrow_mut();
        if slot
            .pending
            .as_ref()
            .is_some_and(|pending| pending.generation == self.generation)
        {
            slot.pending = None;
        }
    }
}

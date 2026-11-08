//! Account-key signatures behind exact-digest Keys admissions, with the ledger inside
//! the Keys checkpoint. The owner is a strict test fixture, not the production HTTPS
//! or Charter qualification.
#![cfg(feature = "wallet-engine")]
use crate::support::*;
use ckmg::wallet_engine::{account::verify_prehash, account_key::SealedAccountKey};
use ckmg::*;
use futures::executor::block_on;

const ORIGIN: &str = "https://garden.example.com";
const SLOT: [u8; 32] = [5; 32];

struct Owner {
    guard: Guard,
    intent: IntentVerifier,
    time: Time,
    accepted: Option<(Action, [u8; 32])>,
}
impl Authority for Owner {
    async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        {
            let anchors = self.guard.0.borrow();
            let anchor = anchors
                .get(request.binding.community())
                .ok_or(Error::Unauthorized)?;
            if anchor.binding != *request.binding
                || Some(anchor.root) != request.root
                || anchor.epoch != request.epoch
                || !anchor.devices.contains(&request.device)
            {
                return Err(Error::Unauthorized);
            }
        }
        match request.action {
            Action::SignContact | Action::SignResolution | Action::SignAcknowledgment => {
                self.intent.consume(&request, ORIGIN)?;
                self.accepted = Some((
                    request.action,
                    request.statement.ok_or(Error::Unauthorized)?,
                ));
                Ok(())
            }
            Action::ForgetWave => self.intent.consume(&request, ORIGIN),
            Action::Use => Ok(()),
            _ => Err(Error::Unauthorized),
        }
    }
    fn check_account_signing_current(&mut self, request: Authorization<'_>) -> Result<u64, Error> {
        if self.accepted.take() != request.statement.map(|d| (request.action, d)) {
            return Err(Error::Unauthorized);
        }
        Ok(self.time.0.get())
    }
}
/// The same owner without the final hook: ckmg's default must refuse.
struct NoFinalHook(Owner);
impl Authority for NoFinalHook {
    async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        self.0.check(request).await
    }
}

struct World<A: Authority> {
    memory: Memory,
    time: Time,
    guard: Guard,
    keys: Keys<Memory, Time, Random, A>,
    admission: IntentAdmission,
    lineage: Lineage,
    device: PublicKey,
    public: [u8; 64],
    sealed: SealedAccountKey,
}

fn fresh<A: Authority>(
    memory: &Memory,
    time: &Time,
    guard: &Guard,
    wrap: impl FnOnce(Owner) -> A,
) -> (Keys<Memory, Time, Random, A>, IntentAdmission) {
    let (admission, intent) = intent_channel();
    let keys = Keys::new(
        memory.clone(),
        time.clone(),
        Random::new(104),
        wrap(Owner {
            guard: guard.clone(),
            intent,
            time: time.clone(),
            accepted: None,
        }),
    );
    (keys, admission)
}

async fn world<A: Authority>(wrap: impl FnOnce(Owner) -> A) -> World<A> {
    let memory = Memory::default();
    let time = Time::default();
    let guard = Guard::default();
    let mut original = machine(&memory, &time, &guard, 103);
    create(&mut original, &guard, &prf(1), &binding("wallet")).await;
    let lineage = original.lineage().await.unwrap();
    let device = original.device_public_key().await.unwrap();
    // Ordinary Use still restores the key for its projection; it cannot sign.
    let engine = original.wallet_engine().await.unwrap();
    drop(original);
    let key = engine.prepare_account_key("wallet", [1; 32]).unwrap();
    let public = key.projection(&engine).unwrap().public_key;
    let sealed = key.seal().unwrap();
    let (mut keys, admission) = fresh(&memory, &time, &guard, wrap);
    keys.unlock(&prf(1), "wallet").await.unwrap();
    World {
        memory,
        time,
        guard,
        keys,
        admission,
        lineage,
        device,
        public,
        sealed,
    }
}

impl<A: Authority> World<A> {
    fn admit(&mut self, action: Action, statement: [u8; 32]) -> IntentGuard {
        admit(
            &mut self.admission,
            &self.lineage,
            self.device,
            action,
            statement,
        )
    }
    async fn sign(&mut self, phase: SigningPhase, digest: [u8; 32]) -> Result<[u8; 64], Error> {
        self.keys
            .sign_account_digest(phase, SLOT, digest, &self.sealed, 1200)
            .await
    }
    /// Admit and sign one digest.
    async fn admitted(&mut self, phase: SigningPhase, digest: [u8; 32]) -> Result<[u8; 64], Error> {
        let _guard = self.admit(phase.action(), digest);
        self.sign(phase, digest).await
    }
    async fn relock(&mut self) {
        self.keys.lock();
        self.keys.unlock(&prf(1), "wallet").await.unwrap();
    }
}

fn admit(
    admission: &mut IntentAdmission,
    lineage: &Lineage,
    device: PublicKey,
    action: Action,
    statement: [u8; 32],
) -> IntentGuard {
    admission
        .admit(
            AdmittedCommand {
                binding: lineage.binding.clone(),
                origin: ORIGIN.into(),
                action,
                device,
                root: Some(lineage.root),
                epoch: lineage.epoch,
                target: None,
                statement: Some(statement),
                transcript: None,
                format: None,
                expires: 1200,
            },
            1000,
        )
        .unwrap()
}

#[test]
fn a_signature_needs_its_exact_admission_and_the_ledger_allows_one_digest() {
    block_on(async {
        let mut w = world(|owner| owner).await;
        let digest = [7; 32];
        let signature = w.admitted(SigningPhase::Contact, digest).await.unwrap();
        verify_prehash(&w.public, &digest, &signature).unwrap();
        // The same digest needs a fresh admission and re-signs to identical bytes.
        assert!(w.sign(SigningPhase::Contact, digest).await.is_err());
        w.relock().await;
        assert_eq!(
            w.admitted(SigningPhase::Contact, digest).await,
            Ok(signature)
        );
        // A different digest for the same slot and phase is refused before any
        // admission is consumed, and custody stays open.
        let guard = w.admit(Action::SignContact, [8; 32]);
        assert_eq!(
            w.sign(SigningPhase::Contact, [8; 32]).await,
            Err(Error::Unauthorized)
        );
        assert_eq!(w.keys.state(), State::Authorized);
        drop(guard);
        // Another phase of the same slot is independent.
        assert!(w.admitted(SigningPhase::Resolution, [8; 32]).await.is_ok());
    });
}

#[test]
fn no_admission_a_wrong_phase_or_a_wrong_digest_never_signs() {
    block_on(async {
        // No admitted command.
        let mut w = world(|owner| owner).await;
        assert!(w.sign(SigningPhase::Contact, [7; 32]).await.is_err());
        // A contact admission does not sign a resolution.
        let mut w = world(|owner| owner).await;
        let guard = w.admit(Action::SignContact, [7; 32]);
        assert!(w.sign(SigningPhase::Resolution, [7; 32]).await.is_err());
        drop(guard);
        // An admission for one digest does not sign another.
        let mut w = world(|owner| owner).await;
        let guard = w.admit(Action::SignAcknowledgment, [7; 32]);
        assert!(w.sign(SigningPhase::Acknowledgment, [9; 32]).await.is_err());
        drop(guard);
        // None of the refusals held the slot: the right digest signs after unlock.
        w.relock().await;
        assert!(
            w.admitted(SigningPhase::Acknowledgment, [9; 32])
                .await
                .is_ok()
        );
    });
}

#[test]
fn an_owner_without_the_final_current_check_cannot_sign() {
    block_on(async {
        let mut w = world(NoFinalHook).await;
        let _guard = w.admit(Action::SignContact, [7; 32]);
        assert!(w.sign(SigningPhase::Contact, [7; 32]).await.is_err());
    });
}

#[test]
fn a_foreign_capsule_never_signs_and_holds_nothing() {
    block_on(async {
        let mut w = world(|owner| owner).await;
        let other = ckmg::wallet_engine::Engine::from_seed_and_sealing_key(
            &mut [1; 32],
            &mut [2; 32],
            b"wallet",
        )
        .unwrap()
        .prepare_account_key("wallet", [1; 32])
        .unwrap()
        .seal()
        .unwrap();
        let _guard = w.admit(Action::SignContact, [7; 32]);
        assert_eq!(
            w.keys
                .sign_account_digest(SigningPhase::Contact, SLOT, [7; 32], &other, 1200)
                .await,
            Err(Error::Crypto)
        );
        drop(_guard);
        w.relock().await;
        assert!(w.admitted(SigningPhase::Contact, [8; 32]).await.is_ok());
    });
}

// X3 H1 attacks (K1 S2): each held before the fix.

#[test]
fn two_fresh_callers_never_sign_two_digests_for_one_slot_and_phase() {
    block_on(async {
        let mut w = world(|owner| owner).await;
        w.admitted(SigningPhase::Contact, [7; 32]).await.unwrap();
        // A second, freshly constructed caller over the same store.
        let (mut keys, mut admission) = fresh(&w.memory, &w.time, &w.guard, |owner| owner);
        keys.unlock(&prf(1), "wallet").await.unwrap();
        let _guard = admit(
            &mut admission,
            &w.lineage,
            w.device,
            Action::SignContact,
            [8; 32],
        );
        assert_eq!(
            keys.sign_account_digest(SigningPhase::Contact, SLOT, [8; 32], &w.sealed, 1200)
                .await,
            Err(Error::Unauthorized)
        );
    });
}

#[test]
fn the_ledger_survives_lock_and_unlock() {
    block_on(async {
        let mut w = world(|owner| owner).await;
        w.admitted(SigningPhase::Resolution, [7; 32]).await.unwrap();
        w.relock().await;
        let _guard = w.admit(Action::SignResolution, [8; 32]);
        assert_eq!(
            w.sign(SigningPhase::Resolution, [8; 32]).await,
            Err(Error::Unauthorized)
        );
    });
}

#[test]
fn a_lost_ledger_cas_releases_no_signature() {
    block_on(async {
        let mut w = world(|owner| owner).await;
        let writes = w.memory.0.borrow().writes;
        w.memory.0.borrow_mut().fault = Fault::Conflict;
        assert_eq!(
            w.admitted(SigningPhase::Acknowledgment, [7; 32]).await,
            Err(Error::Reconcile)
        );
        assert_eq!(w.keys.state(), State::Reconcile);
        assert_eq!(w.memory.0.borrow().writes, writes);
        // Nothing was held: after unlock the ledger is re-read and the slot is free.
        w.memory.0.borrow_mut().fault = Fault::None;
        w.relock().await;
        let signature = w
            .admitted(SigningPhase::Acknowledgment, [8; 32])
            .await
            .unwrap();
        verify_prehash(&w.public, &[8; 32], &signature).unwrap();
    });
}

#[test]
fn an_uncertain_commit_releases_nothing_but_the_written_entry_binds() {
    block_on(async {
        let mut w = world(|owner| owner).await;
        w.memory.0.borrow_mut().fault = Fault::After;
        assert_eq!(
            w.admitted(SigningPhase::Contact, [7; 32]).await,
            Err(Error::Reconcile)
        );
        w.memory.0.borrow_mut().fault = Fault::None;
        w.relock().await;
        let _guard = w.admit(Action::SignContact, [8; 32]);
        assert_eq!(
            w.sign(SigningPhase::Contact, [8; 32]).await,
            Err(Error::Unauthorized)
        );
        drop(_guard);
        assert!(w.admitted(SigningPhase::Contact, [7; 32]).await.is_ok());
    });
}

#[test]
fn the_desk_ledger_import_is_add_only_and_durable() {
    block_on(async {
        let mut w = world(|owner| owner).await;
        w.admitted(SigningPhase::Contact, [7; 32]).await.unwrap();
        let legacy = SigningLedger::from_bytes(
            &serde_json::to_vec(&serde_json::json!({
                "entries": [
                    {"slot": SLOT, "phase": "contact", "digest": vec![9u8; 32], "signature": vec![0u8; 64]},
                    {"slot": SLOT, "phase": "resolution", "digest": vec![6u8; 32], "signature": vec![0u8; 64]},
                ]
            }))
            .unwrap(),
        )
        .unwrap();
        w.keys
            .import_signing_ledger(&legacy.to_bytes().unwrap())
            .await
            .unwrap();
        w.relock().await;
        // The held contact digest stays; the import's conflicting one enables nothing.
        assert!(w.admitted(SigningPhase::Contact, [7; 32]).await.is_ok());
        let guard = w.admit(Action::SignContact, [9; 32]);
        assert_eq!(
            w.sign(SigningPhase::Contact, [9; 32]).await,
            Err(Error::Unauthorized)
        );
        drop(guard);
        // The imported resolution entry now refuses every other digest.
        let _guard = w.admit(Action::SignResolution, [5; 32]);
        assert_eq!(
            w.sign(SigningPhase::Resolution, [5; 32]).await,
            Err(Error::Unauthorized)
        );
        assert!(
            w.keys
                .import_signing_ledger(b"{\"entries\":[],\"x\":1}")
                .await
                .is_err()
        );
    });
}

#[test]
fn forgetting_a_wave_needs_its_own_admission_with_the_final_receipt() {
    block_on(async {
        let mut w = world(|owner| owner).await;
        w.admitted(SigningPhase::Contact, [7; 32]).await.unwrap();
        let receipt = [3; 32];
        // No admission, or an admission for another wave's statement, forgets nothing.
        assert!(w.keys.forget_wave(SLOT, receipt).await.is_err());
        w.relock().await;
        let guard = w.admit(
            Action::ForgetWave,
            forget_wave_statement(&[6; 32], &receipt),
        );
        assert!(w.keys.forget_wave(SLOT, receipt).await.is_err());
        drop(guard);
        w.relock().await;
        let guard = w.admit(Action::SignContact, [8; 32]);
        assert_eq!(
            w.sign(SigningPhase::Contact, [8; 32]).await,
            Err(Error::Unauthorized)
        );
        drop(guard);
        let guard = w.admit(Action::ForgetWave, forget_wave_statement(&SLOT, &receipt));
        w.keys.forget_wave(SLOT, receipt).await.unwrap();
        drop(guard);
        w.relock().await;
        assert!(w.admitted(SigningPhase::Contact, [8; 32]).await.is_ok());
    });
}

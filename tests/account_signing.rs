//! Account-key signatures behind exact-digest Keys admissions. The owner is a strict
//! test fixture, not the production HTTPS or Charter qualification.
#![cfg(feature = "wallet-engine")]
mod support;
use ckmg::wallet_engine::{self, account::verify_prehash};
use ckmg::*;
use futures::executor::block_on;
use support::*;

const ORIGIN: &str = "https://garden.example.com";

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
        if matches!(
            request.action,
            Action::SignContact | Action::SignResolution | Action::SignAcknowledgment
        ) {
            self.intent.consume(&request, ORIGIN)?;
            self.accepted = Some((
                request.action,
                request.statement.ok_or(Error::Unauthorized)?,
            ));
            Ok(())
        } else {
            Err(Error::Unauthorized)
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
    keys: Keys<Memory, Time, Random, A>,
    admission: IntentAdmission,
    lineage: Lineage,
    device: PublicKey,
    engine: wallet_engine::Engine,
    key: wallet_engine::account_key::AccountKey,
}

async fn world<A: Authority>(wrap: impl FnOnce(Owner) -> A) -> World<A> {
    let memory = Memory::default();
    let time = Time::default();
    let guard = Guard::default();
    let mut original = machine(&memory, &time, &guard, 103);
    create(&mut original, &guard, &prf(1), &binding("wallet")).await;
    let lineage = original.lineage().await.unwrap();
    let device = original.device_public_key().await.unwrap();
    let engine = original.wallet_engine().await.unwrap();
    drop(original);
    let (admission, intent) = intent_channel();
    let mut keys = Keys::new(
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
    keys.unlock(&prf(1), "wallet").await.unwrap();
    let key = engine.prepare_account_key("wallet", [1; 32]).unwrap();
    World {
        memory,
        keys,
        admission,
        lineage,
        device,
        engine,
        key,
    }
}

impl<A: Authority> World<A> {
    fn admit(&mut self, action: Action, digest: [u8; 32]) -> IntentGuard {
        self.admission
            .admit(
                AdmittedCommand {
                    binding: self.lineage.binding.clone(),
                    origin: ORIGIN.into(),
                    action,
                    device: self.device,
                    root: Some(self.lineage.root),
                    epoch: self.lineage.epoch,
                    target: None,
                    statement: Some(digest),
                    transcript: None,
                    expires: 1200,
                },
                1000,
            )
            .unwrap()
    }
    async fn sign(
        &mut self,
        ledger: &mut SigningLedger,
        phase: SigningPhase,
        digest: [u8; 32],
    ) -> Result<[u8; 64], Error> {
        self.keys
            .sign_account_digest(
                ledger,
                phase,
                [5; 32],
                digest,
                &self.key,
                &self.engine,
                1200,
            )
            .await
    }
}

#[test]
fn a_signature_needs_its_exact_admission_and_the_ledger_allows_one_digest() {
    block_on(async {
        let mut w = world(|owner| owner).await;
        let public = w.key.projection(&w.engine).unwrap().public_key;
        let mut ledger = SigningLedger::new();
        let digest = [7; 32];
        let _guard = w.admit(Action::SignContact, digest);
        let signature = w
            .sign(&mut ledger, SigningPhase::Contact, digest)
            .await
            .unwrap();
        verify_prehash(&public, &digest, &signature).unwrap();
        assert_eq!(ledger.len(), 1);
        // The same digest returns the stored signature with no new admission.
        assert_eq!(
            w.sign(&mut ledger, SigningPhase::Contact, digest).await,
            Ok(signature)
        );
        // A different digest for the same slot and phase is refused.
        assert!(
            w.sign(&mut ledger, SigningPhase::Contact, [8; 32])
                .await
                .is_err()
        );
        assert_eq!(ledger.len(), 1);
    });
}

#[test]
fn no_admission_a_wrong_phase_or_a_wrong_digest_never_signs() {
    block_on(async {
        // No admitted command.
        let mut w = world(|owner| owner).await;
        let mut ledger = SigningLedger::new();
        assert!(
            w.sign(&mut ledger, SigningPhase::Contact, [7; 32])
                .await
                .is_err()
        );
        assert!(ledger.is_empty());
        // A contact admission does not sign a resolution.
        let mut w = world(|owner| owner).await;
        let _guard = w.admit(Action::SignContact, [7; 32]);
        assert!(
            w.sign(&mut ledger, SigningPhase::Resolution, [7; 32])
                .await
                .is_err()
        );
        assert!(ledger.is_empty());
        // An admission for one digest does not sign another.
        let mut w = world(|owner| owner).await;
        let _guard = w.admit(Action::SignAcknowledgment, [7; 32]);
        assert!(
            w.sign(&mut ledger, SigningPhase::Acknowledgment, [9; 32])
                .await
                .is_err()
        );
        assert!(ledger.is_empty());
    });
}

#[test]
fn an_owner_without_the_final_current_check_cannot_sign() {
    block_on(async {
        let mut w = world(NoFinalHook).await;
        let mut ledger = SigningLedger::new();
        let _guard = w.admit(Action::SignContact, [7; 32]);
        assert!(
            w.sign(&mut ledger, SigningPhase::Contact, [7; 32])
                .await
                .is_err()
        );
        assert!(ledger.is_empty());
    });
}

// X3 H1 attacks (K1 S2): each held before the fix.

#[test]
fn two_fresh_caller_ledgers_never_sign_two_digests_for_one_slot_and_phase() {
    block_on(async {
        let mut w = world(|owner| owner).await;
        let guard = w.admit(Action::SignContact, [7; 32]);
        w.sign(&mut SigningLedger::new(), SigningPhase::Contact, [7; 32])
            .await
            .unwrap();
        drop(guard);
        let _guard = w.admit(Action::SignContact, [8; 32]);
        assert_eq!(
            w.sign(&mut SigningLedger::new(), SigningPhase::Contact, [8; 32])
                .await,
            Err(Error::Unauthorized)
        );
    });
}

#[test]
fn the_ledger_survives_lock_and_unlock() {
    block_on(async {
        let mut w = world(|owner| owner).await;
        let guard = w.admit(Action::SignResolution, [7; 32]);
        w.sign(&mut SigningLedger::new(), SigningPhase::Resolution, [7; 32])
            .await
            .unwrap();
        drop(guard);
        w.keys.lock();
        w.keys.unlock(&prf(1), "wallet").await.unwrap();
        let _guard = w.admit(Action::SignResolution, [8; 32]);
        assert_eq!(
            w.sign(&mut SigningLedger::new(), SigningPhase::Resolution, [8; 32])
                .await,
            Err(Error::Unauthorized)
        );
    });
}

#[test]
fn a_lost_ledger_cas_releases_no_signature() {
    block_on(async {
        let mut w = world(|owner| owner).await;
        let _guard = w.admit(Action::SignAcknowledgment, [7; 32]);
        w.memory.0.borrow_mut().fault = Fault::Conflict;
        let writes = w.memory.0.borrow().writes;
        assert!(
            w.sign(&mut SigningLedger::new(), SigningPhase::Acknowledgment, [7; 32])
                .await
                .is_err()
        );
        assert_eq!(w.memory.0.borrow().writes, writes);
    });
}

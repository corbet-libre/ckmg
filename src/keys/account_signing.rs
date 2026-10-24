//! Account-key signatures behind narrow, exact-digest Keys admissions, with the
//! one-digest-per-slot-and-phase ledger inside the Keys checkpoint.
use super::*;
use crate::{SigningLedger, SigningPhase};
#[cfg(feature = "wallet-engine")]
use crate::wallet_engine::account_key::SealedAccountKey;

impl<S: SecureStore, C: Clock, E: Entropy, A: Authority> Keys<S, C, E, A> {
    /// Sign `digest` with the account key sealed in `sealed`, for one wave `slot` and
    /// `phase`. No key, engine or ledger is an argument, and none leaves.
    ///
    /// In one attempt: the checkpoint ledger refuses a different digest for this slot
    /// and phase (and a new slot and phase at the cap); fresh authority for exactly this
    /// phase's action and digest (single-use admitted command, asynchronous check, final
    /// synchronous recheck after the last Store await); then a one-shot
    /// [`AccountSigning`](crate::wallet_engine::account_key::AccountSigning) is minted
    /// from the identity roots for this digest only, restores the key and signs; a new
    /// entry is committed in the same checkpoint compare-exchange. The signature is
    /// returned only after `Committed`: a lost or uncertain commit releases nothing and
    /// leaves Reconcile, after which unlocking re-reads the durable ledger. The same
    /// digest signs again to identical bytes (RFC 6979, low-S), so a retry needs no
    /// stored signature.
    ///
    /// Ordinary `Use` lends no account-key signer: the Wallet engine restores the
    /// key, but cannot sign with it (X3 H1).
    ///
    /// ```no_run
    /// # use ckmg::*;
    /// # async fn restore<S: SecureStore, C: Clock, R: Entropy, A: Authority>(
    /// #     keys: &mut Keys<S, C, R, A>, sealed: &wallet_engine::account_key::SealedAccountKey) {
    /// let engine = keys.wallet_engine().await.unwrap();
    /// let key = engine.restore_account_key(sealed, "wallet").unwrap();
    /// # let _ = key;
    /// # }
    /// ```
    /// ```compile_fail
    /// # use ckmg::*;
    /// # async fn escape<S: SecureStore, C: Clock, R: Entropy, A: Authority>(
    /// #     keys: &mut Keys<S, C, R, A>, sealed: &wallet_engine::account_key::SealedAccountKey) {
    /// let engine = keys.wallet_engine().await.unwrap();
    /// let key = engine.restore_account_key(sealed, "wallet").unwrap();
    /// let _ = key.sign_prehash(&engine, &[0; 32]);
    /// # }
    /// ```
    #[cfg(feature = "wallet-engine")]
    pub async fn sign_account_digest(
        &mut self,
        phase: SigningPhase,
        slot: [u8; 32],
        digest: [u8; 32],
        sealed: &SealedAccountKey,
        expires: u64,
    ) -> Result<[u8; 64], Error> {
        self.writable()?;
        // A refusal by the ledger consumes no admission and keeps custody open.
        self.loaded()?
            .metadata
            .ledger
            .admits(&slot, phase, &digest)?;
        let action = phase.action();
        let mut attempt = current_signing::Attempt {
            keys: self,
            accepted: false,
        };
        attempt
            .keys
            .authorize_with_check(
                action,
                None,
                Some(digest),
                &[],
                CurrentCheck::AccountSigning,
            )
            .await?;
        attempt.keys.refresh().await?;
        let now = attempt.keys.now()?;
        if now >= expires {
            return Err(Error::Expired);
        }
        let current = attempt.keys.loaded()?;
        // The ledger of the checkpoint `refresh` just proved durable decides.
        let held = current.metadata.ledger.admits(&slot, phase, &digest)?;
        let lineage = current.metadata.lineage.clone();
        let device = vld0::public_key(&current.material.device);
        let floor = attempt
            .keys
            .authority
            .check_account_signing_current(Authorization {
                binding: &lineage.binding,
                root: Some(lineage.root),
                device,
                epoch: lineage.epoch,
                action,
                target: None,
                statement: Some(digest),
                signing: None,
                now,
                evidence: &[],
            })?;
        let completed = attempt.keys.now()?;
        if completed < now.max(floor) {
            return Err(Error::Clock);
        }
        if completed >= expires {
            return Err(Error::Expired);
        }
        let current = attempt.keys.loaded()?;
        let community = current.metadata.lineage.binding.community();
        let signing = passkey::IdentityRoots::retained(
            community,
            device,
            current
                .material
                .identity
                .as_ref()
                .ok_or(Error::MissingCheckpoint)?,
        )?
        .account_signing(digest)?;
        let signature = signing.sign(sealed, community).map_err(|_| Error::Crypto)?;
        if held {
            // Already committed: `refresh` proved this checkpoint is the durable one.
            attempt.accepted = true;
            return Ok(signature);
        }
        let mut candidate = current.clone();
        candidate.metadata.ledger.insert(slot, phase, digest)?;
        let expected = candidate.stamp;
        attempt.keys.prepare(candidate, Some(expected), None)?;
        // The commit owns the outcome from here: it fails closed to Reconcile itself
        // (also when cancelled), and only `Committed` returns the signature.
        attempt.accepted = true;
        attempt.keys.commit().await?;
        Ok(signature)
    }

    /// Drop the ledger entries of one finished wave `slot`, so the ledger stays under its
    /// cap. Needs its own single-use admitted [`Action::ForgetWave`] whose statement is
    /// [`forget_wave_statement`](crate::forget_wave_statement)`(slot, receipt)`, with
    /// `receipt` the digest of the wave's final receipt; the entries go in one checkpoint
    /// compare-exchange. Nothing held for the slot is a no-op after the admission.
    pub async fn forget_wave(&mut self, slot: [u8; 32], receipt: [u8; 32]) -> Result<(), Error> {
        self.writable()?;
        let statement = crate::forget_wave_statement(&slot, &receipt);
        self.authorize(Action::ForgetWave, None, Some(statement), &[])
            .await?;
        self.refresh().await?;
        self.now()?;
        let mut candidate = self.loaded()?.clone();
        if !candidate.metadata.ledger.forget(&slot) {
            return Ok(());
        }
        let expected = candidate.stamp;
        self.prepare(candidate, Some(expected), None)?;
        self.commit().await?;
        Ok(())
    }

    /// Migrate the former caller-held ledger ([`SigningLedger::to_bytes`]) into the
    /// checkpoint once, under fresh `Use`. Add-only: a slot and phase already held keeps
    /// its digest, so an import can only refuse more and never enables a second digest;
    /// one that would pass the cap is refused whole. Repeating it changes nothing.
    pub async fn import_signing_ledger(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let legacy = SigningLedger::from_bytes(bytes)?;
        self.writable()?;
        self.authorize(Action::Use, None, None, &[]).await?;
        self.refresh().await?;
        self.now()?;
        let mut candidate = self.loaded()?.clone();
        if !candidate.metadata.ledger.import(&legacy)? {
            return Ok(());
        }
        let expected = candidate.stamp;
        self.prepare(candidate, Some(expected), None)?;
        self.commit().await?;
        Ok(())
    }
}

//! Account-key signatures behind narrow, exact-digest Keys admissions.
use super::*;
use crate::wallet_engine::{Engine, account_key::AccountKey};
use crate::{SigningLedger, SigningPhase};

impl<S: SecureStore, C: Clock, E: Entropy, A: Authority> Keys<S, C, E, A> {
    /// Sign `digest` with the account `key` for one wave `slot` and `phase`.
    ///
    /// The ledger decides first: the same digest returns the stored signature without
    /// touching custody, a different digest is refused. Otherwise this needs fresh
    /// authority for exactly this phase's action and digest (single-use admitted command,
    /// asynchronous check, final synchronous recheck after the last Store await), signs,
    /// records the signature in `ledger` and returns it. The caller persists `ledger`
    /// BEFORE sending the signature anywhere, and resends it unchanged.
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
    #[allow(clippy::too_many_arguments)]
    pub async fn sign_account_digest(
        &mut self,
        ledger: &mut SigningLedger,
        phase: SigningPhase,
        slot: [u8; 32],
        digest: [u8; 32],
        key: &AccountKey,
        engine: &Engine,
        expires: u64,
    ) -> Result<[u8; 64], Error> {
        if let Some(stored) = ledger.lookup(&slot, phase, &digest)? {
            return Ok(stored.0);
        }
        self.writable()?;
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
        let signature = key
            .sign_prehash(engine, &digest)
            .map_err(|_| Error::Crypto)?;
        ledger.record(slot, phase, digest, signature)?;
        attempt.accepted = true;
        Ok(signature)
    }
}

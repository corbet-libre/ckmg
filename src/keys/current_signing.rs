//! Exact original device signing with a retained-owner check after storage.
use super::*;

pub(super) struct Attempt<'a, S: SecureStore, C: Clock, E: Entropy, A: Authority> {
    pub(super) keys: &'a mut Keys<S, C, E, A>,
    pub(super) accepted: bool,
}
impl<S: SecureStore, C: Clock, E: Entropy, A: Authority> Drop for Attempt<'_, S, C, E, A> {
    fn drop(&mut self) {
        self.keys.authority.discard_current_attempt();
        if !self.accepted && self.keys.state != State::Revoked {
            self.keys.fail_closed(State::Locked);
        }
    }
}

impl<S: SecureStore, C: Clock, E: Entropy, A: Authority> Keys<S, C, E, A> {
    /// Sign the original borrowed transcript in one admitted device format only after
    /// exact one-use intent (for these bytes, this format and this deadline), asynchronous G3
    /// and a final synchronous retained-owner recheck after the last checkpoint await. The
    /// transcript must be led by `format`'s tag and `format` must allow exact admission
    /// (`SigningClass::Admitted`); every other message is refused before authorization. No
    /// signer or key escapes. Failure or cancellation wipes this live attempt, including
    /// cancellation during a Store read. This is the only Keys path that signs with the
    /// device key; no raw device signer exists.
    ///
    /// ```compile_fail
    /// # use ckmg::*;
    /// # async fn raw<S: SecureStore, C: Clock, R: Entropy, A: Authority>(keys: &mut Keys<S, C, R, A>) {
    /// let _ = keys.sign_device_ed25519(b"cvld.device-join.v1\0payload", 1).await;
    /// # }
    /// ```
    ///
    /// ```compile_fail
    /// # use ckmg::*;
    /// # async fn lent<S: SecureStore, C: Clock, R: Entropy, A: Authority>(keys: &mut Keys<S, C, R, A>) {
    /// let _ = keys.with_device_ed25519_signer(|signer| signer.sign(b"any")).await;
    /// # }
    /// ```
    pub async fn sign_device_ed25519_current(
        &mut self,
        format: crate::DeviceFormat,
        transcript: &[u8],
        expires: u64,
    ) -> Result<[u8; 64], Error> {
        format
            .admit(crate::SigningClass::Admitted, None, transcript)
            .inspect_err(|__e| crate::cause::print(file!(), line!(), "sign_device_current", __e))?;
        self.writable()
            .inspect_err(|__e| crate::cause::print(file!(), line!(), "sign_device_current", __e))?;
        let mut attempt = Attempt {
            keys: self,
            accepted: false,
        };
        let signing = crate::DeviceSigning {
            transcript,
            format: Some(format),
            expires,
        };
        attempt
            .keys
            .authorize_with_check(
                Action::SignDeviceEd25519,
                None,
                None,
                &[],
                CurrentCheck::DeviceSigning(signing),
            )
            .await?;
        attempt.keys.refresh().await?;
        let now = attempt
            .keys
            .now()
            .inspect_err(|__e| crate::cause::print(file!(), line!(), "sign_device_current", __e))?;
        if now >= expires {
            crate::cause::print(
                file!(),
                line!(),
                "sign_device_current refusal",
                &Error::Expired,
            );
            return Err(Error::Expired);
        }
        let current = attempt
            .keys
            .loaded()
            .inspect_err(|__e| crate::cause::print(file!(), line!(), "sign_device_current", __e))?;
        let lineage = current.metadata.lineage.clone();
        let device = vld0::public_key(&current.material.device);
        let floor = attempt
            .keys
            .authority
            .check_device_signing_current(Authorization {
                binding: &lineage.binding,
                root: Some(lineage.root),
                device,
                epoch: lineage.epoch,
                action: Action::SignDeviceEd25519,
                target: None,
                statement: None,
                signing: Some(signing),
                now,
                evidence: &[],
            })
            .inspect_err(|__e| crate::cause::print(file!(), line!(), "sign_device_current", __e))?;
        let completed = attempt
            .keys
            .now()
            .inspect_err(|__e| crate::cause::print(file!(), line!(), "sign_device_current", __e))?;
        if completed < now.max(floor) {
            crate::cause::print(
                file!(),
                line!(),
                "sign_device_current refusal",
                &Error::Clock,
            );
            return Err(Error::Clock);
        }
        if completed >= expires {
            crate::cause::print(
                file!(),
                line!(),
                "sign_device_current refusal",
                &Error::Expired,
            );
            return Err(Error::Expired);
        }
        let secret = &attempt
            .keys
            .loaded()
            .inspect_err(|__e| crate::cause::print(file!(), line!(), "sign_device_current", __e))?
            .material
            .device;
        let signature = crate::format::sign(
            secret,
            format,
            crate::SigningClass::Admitted,
            None,
            transcript,
        )
        .inspect_err(|__e| crate::cause::print(file!(), line!(), "sign_device_current", __e))?;
        attempt.accepted = true;
        Ok(signature)
    }
}

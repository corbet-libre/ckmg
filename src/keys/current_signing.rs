//! Exact original device signing with a retained-owner check after storage.
use super::*;

struct Attempt<'a, S: SecureStore, C: Clock, E: Entropy, A: Authority> {
    keys: &'a mut Keys<S, C, E, A>,
    accepted: bool,
}
impl<S: SecureStore, C: Clock, E: Entropy, A: Authority> Drop for Attempt<'_, S, C, E, A> {
    fn drop(&mut self) {
        if !self.accepted {
            self.keys.fail_closed(State::Locked);
        }
    }
}

impl<S: SecureStore, C: Clock, E: Entropy, A: Authority> Keys<S, C, E, A> {
    /// Sign the original borrowed transcript only after exact one-use intent,
    /// asynchronous G3 and a final synchronous retained-owner recheck after the
    /// last checkpoint await. No signer or key escapes. Failure or cancellation
    /// wipes this live attempt, including cancellation during a Store read.
    pub async fn sign_device_ed25519_current(
        &mut self,
        transcript: &[u8],
        expires: u64,
    ) -> Result<[u8; 64], Error> {
        self.writable()?;
        let mut attempt = Attempt {
            keys: self,
            accepted: false,
        };
        let signing = crate::DeviceSigning {
            transcript,
            expires,
        };
        attempt
            .keys
            .authorize_with_signing(Action::SignDeviceEd25519, None, None, &[], Some(signing))
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
            })?;
        let completed = attempt.keys.now()?;
        if completed < now.max(floor) {
            return Err(Error::Clock);
        }
        if completed >= expires {
            return Err(Error::Expired);
        }
        let secret = &attempt.keys.loaded()?.material.device;
        let signature = Ed25519Signer {
            secret,
            public_key: *device.value(),
        }
        .sign(transcript)?;
        attempt.accepted = true;
        Ok(signature)
    }
}

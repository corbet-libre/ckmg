//! The original fixed device-authorization transcript, never a root signer loan.
use super::*;
use data_encoding::{BASE64URL_NOPAD as B64, HEXLOWER};
use sha2::{Digest, Sha256};

const MAX_TIME: u64 = 9_007_199_254_740_991;

/// Original public account-device authorization. Its root signature grants no
/// account admission, enrollment, current membership or accepted balance alone.
/// There is no caller constructor or private key field.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountDeviceAuthorization {
    version: u32,
    community_id: String,
    member_id: String,
    root_public_key: String,
    device_public_key: String,
    issued_at: u64,
    expires_at: u64,
    signature: String,
}
impl AccountDeviceAuthorization {
    /// Exact original `cmsg.device.v1` bytes, without a new signature framing.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(&serde_json::json!([
            "cmsg.device.v1",
            self.community_id,
            self.member_id,
            self.root_public_key,
            self.device_public_key,
            self.issued_at,
            self.expires_at
        ]))
        .map_err(|_| Error::Encoding)
    }
    /// Original public wire bytes for the upper account owner's strict decoder.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(self).map_err(|_| Error::Encoding)
    }
}

/// One unsigned, fixed public plan from an already unlocked original Keys owner.
/// It is not authority. Door must admit its exact transcript separately; only the
/// same live Keys session and unchanged checkpoint can consume it once.
pub struct AccountDevicePlan {
    authorization: AccountDeviceAuthorization,
    transcript: Vec<u8>,
    binding: Binding,
    root: PublicKey,
    device: PublicKey,
    epoch: u64,
    session: [u8; 32],
    stamp: [u8; 32],
}
impl AccountDevicePlan {
    /// Exact owner-derived bytes for the separate trusted Door intent.
    pub fn signing_bytes(&self) -> &[u8] {
        &self.transcript
    }
    /// Original community/pseudonym binding; never a caller-selected account ID.
    pub fn binding(&self) -> &Binding {
        &self.binding
    }
    /// Current root public key selected by the actual loaded lineage.
    pub fn root(&self) -> PublicKey {
        self.root
    }
    /// Only the loaded logical device can receive this authorization.
    pub fn device(&self) -> PublicKey {
        self.device
    }
    /// Exact current lineage epoch for local intent matching.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    /// Original exclusive requested deadline; the genuine owner must also cap it.
    pub fn expires_at(&self) -> u64 {
        self.authorization.expires_at
    }

    fn check(&self, current: &Open) -> Result<(), Error> {
        if current.session != self.session
            || current.stamp != self.stamp
            || current.metadata.lineage.binding != self.binding
            || current.metadata.lineage.root != self.root
            || current.metadata.lineage.epoch != self.epoch
            || vld0::public_key(&current.material.device) != self.device
            || current.metadata.output.is_some()
            || current.metadata.pairing.is_some()
            || current.metadata.revoked
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}

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
    /// Prepare only the original fixed public statement for this community's
    /// current logical device. This releases no root signature or signer. Global
    /// Wallet UUIDs cannot enter the community pseudonym/account relation.
    pub async fn prepare_account_device(
        &mut self,
        expires: u64,
    ) -> Result<AccountDevicePlan, Error> {
        self.writable()?;
        self.authorize(Action::Use, None, None, &[]).await?;
        self.refresh().await?;
        let now = self.now()?;
        if now == 0 || now >= expires || expires > MAX_TIME {
            return Err(Error::Expired);
        }
        let current = self.loaded()?;
        let lineage = &current.metadata.lineage;
        if lineage.binding.community() == "wallet" {
            return Err(Error::Unauthorized);
        }
        let pseudonym = HEXLOWER
            .decode(lineage.binding.member().as_bytes())
            .map_err(|_| Error::Unauthorized)?;
        if pseudonym.len() != 48 || HEXLOWER.encode(&pseudonym) != lineage.binding.member() {
            return Err(Error::Unauthorized);
        }
        let device = vld0::public_key(&current.material.device);
        let authorization = AccountDeviceAuthorization {
            version: 1,
            community_id: lineage.binding.community().into(),
            member_id: B64.encode(&Sha256::digest(&pseudonym)),
            root_public_key: B64.encode(lineage.root.value()),
            device_public_key: B64.encode(device.value()),
            issued_at: now,
            expires_at: expires,
            signature: String::new(),
        };
        let transcript = authorization.signing_bytes()?;
        Ok(AccountDevicePlan {
            authorization,
            transcript,
            binding: lineage.binding.clone(),
            root: lineage.root,
            device,
            epoch: lineage.epoch,
            session: current.session,
            stamp: current.stamp,
        })
    }

    /// Consume this owner's exact plan after independent one-use Door intent,
    /// current G3 and a fresh retained-owner check after the last Store await.
    /// Any failure or cancellation wipes this live Keys attempt. A new login and
    /// a new explicit local intent are required; no cached approval is replayed.
    pub async fn authorize_account_device(
        &mut self,
        mut plan: AccountDevicePlan,
    ) -> Result<AccountDeviceAuthorization, Error> {
        self.writable()?;
        let mut attempt = Attempt {
            keys: self,
            accepted: false,
        };
        plan.check(attempt.keys.loaded()?)?;
        let expires = plan.expires_at();
        if attempt.keys.now()? >= expires {
            return Err(Error::Expired);
        }
        attempt
            .keys
            .authorize_with_signing(
                Action::AuthorizeAccountDevice,
                None,
                None,
                &[],
                Some(crate::DeviceSigning {
                    transcript: &plan.transcript,
                    format: None,
                    expires,
                }),
            )
            .await?;
        attempt.keys.refresh().await?;
        plan.check(attempt.keys.loaded()?)?;
        let now = attempt.keys.now()?;
        if now >= expires {
            return Err(Error::Expired);
        }
        let floor = attempt
            .keys
            .authority
            .check_account_device_current(Authorization {
                binding: &plan.binding,
                root: Some(plan.root),
                device: plan.device,
                epoch: plan.epoch,
                action: Action::AuthorizeAccountDevice,
                target: None,
                statement: None,
                signing: Some(crate::DeviceSigning {
                    transcript: &plan.transcript,
                    format: None,
                    expires,
                }),
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
        plan.check(attempt.keys.loaded()?)?;
        plan.authorization.signature = B64.encode(&vld0::sign_ed25519(
            attempt.keys.loaded()?.material.root()?,
            &plan.transcript,
        ));
        attempt.accepted = true;
        Ok(plan.authorization)
    }
}

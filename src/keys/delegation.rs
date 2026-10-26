//! Device delegation: a fresh device key enrolled in the lineage plus only the
//! current epoch's purpose custody, so a device can resume without its passkey.
//!
//! A delegation never holds the root, the common identity, historical roots, the
//! checkpoint (ring) key, the PRF or anything derived from it. Opening Keys from it
//! yields [`State::Delegated`], where every operation that needs any of those refuses
//! (`loaded()` returns `NoRoot`); only the explicit delegated branches below work.

use super::*;

const DELEGATION_HEADER: &[u8] = b"ckmg.delegation.v1\0";
const STATEMENT_DOMAIN: &[u8] = b"ckmg.device-delegation.v1\0";

/// Upper bound of member purposes one delegation may carry.
pub const MAX_DELEGATED_PURPOSES: usize = 32;

#[derive(Clone)]
pub(super) struct DelegatedPurpose {
    purpose: Purpose,
    signing: Secret,
    encryption: Secret,
}

/// What Keys holds in [`State::Delegated`]: public lineage, the delegation key and
/// the delegated member-purpose secrets. Nothing else.
pub(super) struct Delegated {
    lineage: Lineage,
    device: Secret,
    purposes: Vec<DelegatedPurpose>,
    session: [u8; 32],
}

/// Resume custody for one community on one device.
///
/// It holds a delegation key generated from this device's entropy (never derived from
/// a PRF) whose public key the root signed into `lineage.delegates` (never
/// `lineage.devices`, so no rotation ever seals a root to it), the common Store
/// cipher of the epoch it was granted in, and the member-purpose secrets of that epoch
/// for a closed list of purposes. It holds no root, identity, history, checkpoint key,
/// PRF or passkey record custody, and no ckmg API leads from it to any of them.
///
/// No `Clone`, `Debug` or serde; secrets are wiped on drop.
///
/// ```compile_fail
/// fn clone<T: Clone>() {}
/// clone::<ckmg::DeviceDelegation>();
/// ```
///
/// ```compile_fail
/// fn debug<T: std::fmt::Debug>() {}
/// debug::<ckmg::DeviceDelegation>();
/// ```
///
/// ```compile_fail
/// fn escape(delegation: ckmg::DeviceDelegation) {
///     let _ = delegation.device;
/// }
/// ```
///
/// A delegation is not a passkey PRF and cannot unlock passkey custody:
///
/// ```compile_fail
/// # use ckmg::*;
/// # async fn escape<S: SecureStore, C: Clock, R: Entropy, A: Authority>(
/// #     keys: &mut Keys<S, C, R, A>, delegation: &DeviceDelegation) {
/// let _ = keys.unlock(delegation, "community").await;
/// # }
/// ```
///
/// ```compile_fail
/// fn escape(delegation: &ckmg::DeviceDelegation) -> ckmg::passkey::PrfOutput {
///     delegation.into()
/// }
/// ```
///
/// The borrowed Store cipher cannot outlive the delegation:
///
/// ```compile_fail
/// fn escape(delegation: ckmg::DeviceDelegation) {
///     let cipher = delegation.store_cipher();
///     drop(delegation);
///     let _ = cipher.open(b"scope", b"sealed");
/// }
/// ```
pub struct DeviceDelegation {
    lineage: Lineage,
    device: Secret,
    store: passkey::StoreCipher,
    purposes: Vec<DelegatedPurpose>,
}

impl DeviceDelegation {
    /// The root-signed lineage this delegation was granted in; lists the delegation key.
    pub fn lineage(&self) -> &Lineage {
        &self.lineage
    }

    /// Community of this delegation.
    pub fn community(&self) -> &str {
        self.lineage.binding.community()
    }

    /// Public delegation key, as enrolled in [`Self::lineage`].
    pub fn device_public_key(&self) -> PublicKey {
        vld0::public_key(&self.device)
    }

    /// Delegated member purposes, in grant order.
    pub fn purposes(&self) -> impl Iterator<Item = &Purpose> {
        self.purposes.iter().map(|entry| &entry.purpose)
    }

    /// The common Store cipher of the granted epoch, to open this community's local Store.
    pub fn store_cipher(&self) -> &passkey::StoreCipher {
        &self.store
    }

    /// The delegation key's community session signature (`DeviceFormat::DeviceSession`,
    /// same tag as the passkey device key, class `Delegate`). No other device purpose is signed here.
    pub fn sign_device_session(&self, payload: &[u8]) -> Result<[u8; 64], Error> {
        crate::format::sign_payload(
            &self.device,
            crate::DeviceFormat::DeviceSession,
            crate::SigningClass::Delegate,
            None,
            payload,
        )
    }

    /// Plaintext form for the caller's sealed resume store only; seal it before it
    /// leaves memory. Versioned and length-checked.
    pub fn to_sealed_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let lineage = serde_json::to_vec(&self.lineage).map_err(|__cause| {
            crate::cause::emit(
                file!(),
                line!(),
                "Error::Encoding",
                Error::Encoding,
                &__cause,
            )
        })?;
        let mut out = Zeroizing::new(Vec::with_capacity(
            DELEGATION_HEADER.len() + 70 + lineage.len() + self.purposes.len() * 160,
        ));
        out.extend_from_slice(DELEGATION_HEADER);
        out.extend_from_slice(self.device.as_slice());
        out.extend_from_slice(self.store.secret().as_slice());
        out.extend_from_slice(
            &u32::try_from(lineage.len())
                .map_err(|__cause| {
                    crate::cause::emit(file!(), line!(), "Error::Limit", Error::Limit, &__cause)
                })?
                .to_le_bytes(),
        );
        out.extend_from_slice(&lineage);
        out.extend_from_slice(
            &u16::try_from(self.purposes.len())
                .map_err(|__cause| {
                    crate::cause::emit(file!(), line!(), "Error::Limit", Error::Limit, &__cause)
                })?
                .to_le_bytes(),
        );
        for entry in &self.purposes {
            let purpose = serde_json::to_vec(&entry.purpose).map_err(|__cause| {
                crate::cause::emit(
                    file!(),
                    line!(),
                    "Error::Encoding",
                    Error::Encoding,
                    &__cause,
                )
            })?;
            out.extend_from_slice(
                &u16::try_from(purpose.len())
                    .map_err(|__cause| {
                        crate::cause::emit(file!(), line!(), "Error::Limit", Error::Limit, &__cause)
                    })?
                    .to_le_bytes(),
            );
            out.extend_from_slice(&purpose);
            out.extend_from_slice(entry.signing.as_slice());
            out.extend_from_slice(entry.encryption.as_slice());
        }
        if out.len() > MAX_CHECKPOINT_BYTES {
            return Err(Error::Limit);
        }
        Ok(out)
    }

    /// Parse [`Self::to_sealed_bytes`] output. Refuses a wrong version, truncation,
    /// trailing bytes, an unverifiable lineage, a key the lineage does not list, and
    /// any purpose list that `delegate_device` would refuse.
    pub fn from_sealed_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(Error::Limit);
        }
        let mut input = Reader(
            bytes
                .strip_prefix(DELEGATION_HEADER)
                .ok_or(Error::Encoding)?,
        );
        let device = keyring::secret(input.take(32)?)?;
        let store = passkey::StoreCipher::from_secret(keyring::secret(input.take(32)?)?);
        let length = u32::from_le_bytes(input.array()?) as usize;
        let lineage: Lineage = serde_json::from_slice(input.take(length)?).map_err(|__cause| {
            crate::cause::emit(
                file!(),
                line!(),
                "Error::Encoding",
                Error::Encoding,
                &__cause,
            )
        })?;
        let count = usize::from(u16::from_le_bytes(input.array()?));
        if count > MAX_DELEGATED_PURPOSES {
            return Err(Error::Encoding);
        }
        let mut purposes = Vec::with_capacity(count);
        for _ in 0..count {
            let length = usize::from(u16::from_le_bytes(input.array()?));
            let purpose: Purpose =
                serde_json::from_slice(input.take(length)?).map_err(|__cause| {
                    crate::cause::emit(
                        file!(),
                        line!(),
                        "Error::Encoding",
                        Error::Encoding,
                        &__cause,
                    )
                })?;
            purposes.push(DelegatedPurpose {
                purpose,
                signing: keyring::secret(input.take(32)?)?,
                encryption: keyring::secret(input.take(32)?)?,
            });
        }
        if !input.0.is_empty() {
            return Err(Error::Encoding);
        }
        let listed: Vec<Purpose> = purposes.iter().map(|entry| entry.purpose.clone()).collect();
        if checked_purposes(&listed).is_err() {
            return Err(Error::Encoding);
        }
        let delegation = Self {
            lineage,
            device,
            store,
            purposes,
        };
        delegation.validate().map_err(|__cause| {
            crate::cause::emit(
                file!(),
                line!(),
                "Error::Encoding",
                Error::Encoding,
                &__cause,
            )
        })?;
        Ok(delegation)
    }

    fn validate(&self) -> Result<(), Error> {
        self.lineage.verify()?;
        if !self.lineage.delegates.contains(&self.device_public_key()) {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < length {
            return Err(Error::Encoding);
        }
        let (head, tail) = self.0.split_at(length);
        self.0 = tail;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|__cause| {
            crate::cause::emit(
                file!(),
                line!(),
                "Error::Encoding",
                Error::Encoding,
                &__cause,
            )
        })
    }
}

/// Internal namespaces (compound recovery records, transport identities) are never
/// delegated or derived in Delegated custody, whatever their scope.
fn reserved(purpose: &Purpose) -> bool {
    purpose.is_reserved() || NodePurpose::of(purpose).is_some()
}

/// The closed purpose list: bounded, valid, member scope, no reserved purpose, no
/// duplicate. Device-scope purposes are never delegated; they derive from the
/// delegation key itself.
fn checked_purposes(purposes: &[Purpose]) -> Result<Vec<Purpose>, Error> {
    if purposes.len() > MAX_DELEGATED_PURPOSES {
        return Err(Error::Limit);
    }
    for (index, purpose) in purposes.iter().enumerate() {
        purpose.validate()?;
        if purpose.scope() != Scope::Member
            || reserved(purpose)
            || purposes[..index].contains(purpose)
        {
            return Err(Error::InvalidPurpose);
        }
    }
    Ok(purposes.to_vec())
}

fn delegated_secret(
    current: &Delegated,
    purpose: &Purpose,
    symmetric: bool,
) -> Result<Secret, Error> {
    purpose.validate()?;
    match purpose.scope() {
        Scope::Member => current
            .purposes
            .iter()
            .find(|entry| entry.purpose == *purpose)
            .map(|entry| {
                if symmetric {
                    entry.encryption.clone()
                } else {
                    entry.signing.clone()
                }
            })
            .ok_or(Error::NoRoot),
        Scope::Device => {
            let context = purpose_context(
                &current.lineage,
                &current.device,
                purpose,
                current.lineage.epoch,
                &[],
            )?;
            Ok(derive_purpose_secret(&current.device, &context, symmetric))
        }
    }
}

impl<S: SecureStore, C: Clock, R: Entropy, A: Authority> Keys<S, C, R, A> {
    /// Enrol a fresh delegation key for this device and return its delegation.
    ///
    /// Requires PRF-unlocked Authorized custody with no pending output and fresh
    /// `Action::DelegateDevice` authority (the evidence is the ceremony this enrolment
    /// rides on). The key comes from this device's entropy. The lineage gains it in a
    /// root-signed revision + 1; no root is sealed. The delegation is returned only
    /// after the change commits; publish and acknowledge the receipt as usual.
    /// `purposes` is the closed member-purpose list the delegation may use.
    pub async fn delegate_device(
        &mut self,
        purposes: &[Purpose],
        evidence: &[u8],
    ) -> Result<(Receipt, DeviceDelegation), Error> {
        self.writable()?;
        let purposes = checked_purposes(purposes)?;
        self.loaded()?.material.root()?;
        let device = vld0::random_secret(&mut self.entropy)?;
        let public = vld0::public_key(&device);
        let statement = digest(STATEMENT_DOMAIN, &(public, &purposes))?;
        self.authorize(
            Action::DelegateDevice,
            Some(public),
            Some(statement),
            evidence,
        )
        .await?;
        self.writable()?;
        let mut candidate = self.loaded()?.clone();
        let previous = &candidate.metadata.lineage;
        if previous.version != 2
            || previous.devices.contains(&public)
            || previous.delegates.contains(&public)
        {
            return Err(Error::Unauthorized);
        }
        if previous.delegates.len() >= MAX_DEVICES {
            return Err(Error::Limit);
        }
        let lineage = &mut candidate.metadata.lineage;
        lineage.revision = lineage.revision.checked_add(1).ok_or(Error::Limit)?;
        // A delegate, never a device: rotation seals root and identity to `devices` only.
        lineage.delegates.push(public);
        lineage.delegates.sort();
        lineage.signature = vld0::sign(candidate.material.root()?, &lineage.signed_bytes()?)?;
        let lineage = candidate.metadata.lineage.clone();
        let store =
            passkey::common_store_cipher(candidate.material.root()?, lineage.binding.community())?;
        let secrets = purposes
            .iter()
            .map(|purpose| {
                Ok(DelegatedPurpose {
                    purpose: purpose.clone(),
                    signing: purpose_secret(&candidate, purpose, false)?,
                    encryption: purpose_secret(&candidate, purpose, true)?,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let expected = candidate.stamp;
        self.prepare(
            candidate,
            Some(expected),
            Some(Change::DeviceDelegated(lineage.clone())),
        )?;
        let receipt = self.commit().await?.ok_or(Error::Crypto)?;
        Ok((
            receipt,
            DeviceDelegation {
                lineage,
                device,
                store,
                purposes: secrets,
            },
        ))
    }

    /// Open read-only delegated custody ([`State::Delegated`]). It permits only the
    /// delegated member purposes and the delegation key's own device purposes (`key`,
    /// `sign`, `sign_ed25519`, `with_ed25519_signer`, `with_vld0_signer`,
    /// `with_vld0_record_cipher`, `with_vld0_record`, `seal`, `open`) plus `lineage` and
    /// `device_public_key`, each under fresh current authority for the delegation key.
    /// Everything that needs the root, identity, history, checkpoint or passkey refuses.
    pub fn unlock_delegated(&mut self, delegation: &DeviceDelegation) -> Result<(), Error> {
        self.lock();
        delegation.validate()?;
        self.now()?;
        let session = *vld0::random_secret(&mut self.entropy)?;
        self.delegated = Some(Delegated {
            lineage: delegation.lineage.clone(),
            device: delegation.device.clone(),
            purposes: delegation.purposes.clone(),
            session,
        });
        self.state = State::Delegated;
        Ok(())
    }

    fn delegated_custody(&self) -> Result<&Delegated, Error> {
        match self.state {
            State::Delegated => self.delegated.as_ref().ok_or(Error::Locked),
            _ => Err(Error::Locked),
        }
    }

    async fn authorize_delegated(&mut self) -> Result<(), Error> {
        let now = self.now()?;
        let current = self.delegated_custody()?;
        let binding = current.lineage.binding.clone();
        let root = current.lineage.root;
        let epoch = current.lineage.epoch;
        let device = vld0::public_key(&current.device);
        self.check_authority(Authorization {
            binding: &binding,
            root: Some(root),
            device,
            epoch,
            action: Action::Use,
            target: None,
            statement: None,
            signing: None,
            now,
            evidence: &[],
        })
        .await
    }

    pub(super) async fn delegated_lineage(&mut self) -> Result<Lineage, Error> {
        self.authorize_delegated().await?;
        Ok(self.delegated_custody()?.lineage.clone())
    }

    pub(super) async fn delegated_lineage_device(&mut self) -> Result<PublicKey, Error> {
        self.authorize_delegated().await?;
        Ok(vld0::public_key(&self.delegated_custody()?.device))
    }

    pub(super) async fn delegated_key(&mut self, purpose: Purpose) -> Result<KeyHandle, Error> {
        if reserved(&purpose) {
            return Err(Error::Unauthorized);
        }
        self.authorize_delegated().await?;
        let current = self.delegated_custody()?;
        let secret = delegated_secret(current, &purpose, false)?;
        let mut certificate = KeyCertificate {
            binding: current.lineage.binding.clone(),
            epoch: current.lineage.epoch,
            device: vld0::public_key(&current.device),
            purpose,
            key: vld0::public_key(&secret),
            signature: empty_signature(),
        };
        certificate.signature = vld0::sign(&current.device, &certificate.signed_bytes()?)?;
        Ok(KeyHandle {
            session: current.session,
            certificate,
        })
    }

    pub(super) async fn check_delegated_handle(&mut self, handle: &KeyHandle) -> Result<(), Error> {
        self.authorize_delegated().await?;
        let current = self.delegated_custody()?;
        if handle.session != current.session {
            return Err(Error::Unauthorized);
        }
        // Local check only: `KeyCertificate::verify` accepts lineage devices, never
        // delegates, so peers do not accept a delegate's purpose certificate.
        let device = vld0::public_key(&current.device);
        if handle.certificate.epoch != current.lineage.epoch
            || !current.lineage.delegates.contains(&device)
        {
            return Err(Error::Unauthorized);
        }
        handle.certificate.verify_device_certificate(
            &current.lineage.binding,
            &handle.certificate.purpose,
            &device,
        )
    }

    /// The purpose secret behind an already checked handle, in either custody.
    pub(super) fn handle_secret(
        &self,
        handle: &KeyHandle,
        symmetric: bool,
    ) -> Result<Secret, Error> {
        let purpose = &handle.certificate.purpose;
        match self.state {
            State::Delegated => delegated_secret(self.delegated_custody()?, purpose, symmetric),
            _ => purpose_secret(self.loaded()?, purpose, symmetric),
        }
    }

    /// Purpose AEAD context and key behind an already checked handle.
    pub(super) fn handle_aead(
        &self,
        handle: &KeyHandle,
        context: &[u8],
    ) -> Result<(Vec<u8>, Secret), Error> {
        let purpose = &handle.certificate.purpose;
        match self.state {
            State::Delegated => {
                let current = self.delegated_custody()?;
                let aad = purpose_context(
                    &current.lineage,
                    &current.device,
                    purpose,
                    current.lineage.epoch,
                    context,
                )?;
                Ok((aad, delegated_secret(current, purpose, true)?))
            }
            _ => {
                let current = self.loaded()?;
                Ok((
                    purpose_aad(current, purpose, context)?,
                    purpose_secret(current, purpose, true)?,
                ))
            }
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/delegation.rs"]
mod tests;

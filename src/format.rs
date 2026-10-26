//! The closed registry of everything a device key signs with plain Ed25519.
//!
//! Every device-key signature (the PRF device seed or a delegated device key) goes over a
//! message that starts with exactly one [`DeviceFormat::tag`], and only through a signer whose
//! [`SigningClass`] allows that format. The tags are the leading bytes the verifiers already
//! rebuild, so the wire is unchanged.
//!
//! Prefix-freeness: every tag has one of three shapes: `name T` with `T` one of `\0` or
//! `\n`; `["name",` (a JSON array's first element); or `n name \0`, a postcard string whose
//! one length byte `n` (below `0x5b`) counts `name \0`. A name starts with a lowercase letter
//! and uses only `[a-z0-9._:-]`, so it contains no NUL, newline or `"`. The shapes differ in
//! their first byte (a letter, `[`, or a length below `[` and the letters), and within a shape
//! the terminator first occurs at the tag's end (or the length byte fixes the tag's length),
//! so no tag is a prefix of another. If a signature over `m` were accepted for two formats F and G, ckmg
//! signed `m` under F (tag(F) prefixes m) and G's verifier rebuilds `m` led by tag(G), so one
//! tag prefixes the other and F = G. The stamp-salt tag has the first shape too and is no
//! format: no signer accepts it (see `device_salt`).
use crate::Error;

/// The domain tag of the stamp-salt derivation. Never a [`DeviceFormat`]: the derived
/// signature is hashed inside ckmg and never leaves it.
pub(crate) const SALT_TAG: &[u8] = b"cmsg.device-join.salt.v1\0";

/// One device-key message format, named by its verifier's fixed leading bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DeviceFormat {
    /// The community's device-join message (cvld).
    DeviceJoin,
    /// The community's device-session message (cvld).
    DeviceSession,
    /// The garden device-session message (cvld).
    GardenSession,
    /// The pairing possession proof (cvld); reserved for the step-bound pairing signer.
    PairingPossession,
    /// The host device's approval of a pairing revision (cvld/cchr), exact-admitted.
    PairingApproval,
    /// The account request (cblc `cfrm.account.request.v1`).
    AccountRequest,
    /// The account status request (cblc `cfrm.account.status.v1`, signed for the owner status check).
    AccountStatus,
    /// The record-witness recipient request (cblc).
    RecordRecipient,
    /// The accounting delegation (cblc).
    AccountingDelegation,
    /// The forum session challenge (cswb).
    ForumChallenge,
    /// The forum signed request (cswb; board posts through clnk).
    ForumRequest,
    /// The group consent statement (cgrp).
    GroupConsent,
    /// The vouching endorsement (cvch).
    Endorsement,
    /// The thread invitation statement (cthr, postcard).
    ThreadInvitation,
    /// The Profile publication transcript (cpfl).
    ProfilePublication,
    /// The Guard profile bundle binding (cgrd).
    ProfileBundle,
    /// The wallet device key's birth binding (cvld/cgbl), wallet scope only.
    WalletBirthDevice,
    /// The wallet device key's signature over a birth passport request (cgbl), wallet scope only.
    WalletBirthPassport,
    /// The admin decision approval (cvld governance): the device key signs
    /// `tag || proposal_digest`. Exact-admitted, Admitted class only.
    AdminApproval,
}

/// The capability through which a device key signs. Each allows a fixed set of formats.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SigningClass {
    /// The unenrolled candidate before activation (`UnenrolledCreation::sign_device`).
    Enrollment,
    /// The unlocked passkey opening before Keys is live (`passkey::sign_device_session`).
    Opening,
    /// The authenticated original initial ACK of a restored device.
    Provenance,
    /// Exact one-use admitted transcripts (`Keys::sign_device_ed25519_current`).
    Admitted,
    /// The signer lent with Profile custody (`Keys::with_profile_custody`).
    Profile,
    /// A delegated device key; it signs community sessions only.
    Delegate,
}

impl DeviceFormat {
    /// Every format, for exhaustive checks.
    pub const ALL: [DeviceFormat; 19] = [
        Self::DeviceJoin,
        Self::DeviceSession,
        Self::GardenSession,
        Self::PairingPossession,
        Self::PairingApproval,
        Self::AccountRequest,
        Self::AccountStatus,
        Self::RecordRecipient,
        Self::AccountingDelegation,
        Self::ForumChallenge,
        Self::ForumRequest,
        Self::GroupConsent,
        Self::Endorsement,
        Self::ThreadInvitation,
        Self::ProfilePublication,
        Self::ProfileBundle,
        Self::WalletBirthDevice,
        Self::WalletBirthPassport,
        Self::AdminApproval,
    ];

    /// The exact leading bytes of every message of this format.
    pub const fn tag(self) -> &'static [u8] {
        match self {
            Self::DeviceJoin => b"cvld.device-join.v1\0",
            Self::DeviceSession => b"cvld.device-session.v1\0",
            Self::GardenSession => b"cvld.garden-session.v1\0",
            Self::PairingPossession => b"cvld.device-pairing-possession.v1\0",
            Self::PairingApproval => b"cvld.device-pairing-approval.v1\0",
            Self::AccountRequest => b"cfrm.account.request.v1\0",
            Self::AccountStatus => b"cfrm.account.status.v1\0",
            Self::RecordRecipient => b"[\"cblc.record-recipient.v2\",",
            Self::AccountingDelegation => b"[\"cmsg.accounting-delegation.v1\",",
            Self::ForumChallenge => b"[\"cswb.challenge.v1\",",
            Self::ForumRequest => b"[\"cswb.request.v1\",",
            Self::GroupConsent => b"[\"cgrp.consent.v4\",",
            Self::Endorsement => b"cvch.endorsement.v3\n",
            Self::ThreadInvitation => b"\x13cthr.invitation.v1\0",
            Self::ProfilePublication => b"cpfl:publication:v1\0",
            Self::ProfileBundle => b"cgrd:bundle:v1\0",
            Self::WalletBirthDevice => b"cvld.wallet-birth-device.v1\0",
            Self::WalletBirthPassport => b"cvld.wallet-birth-passport.v1\0",
            Self::AdminApproval => b"cvld.admin-approval.v1\0",
        }
    }

    /// Whether `class` may sign this format.
    pub const fn allowed(self, class: SigningClass) -> bool {
        use SigningClass::*;
        match self {
            Self::DeviceJoin => matches!(class, Enrollment | Provenance),
            Self::DeviceSession => matches!(class, Enrollment | Opening | Admitted | Delegate),
            // Signed only by `passkey::sign_pairing_possession`, from the unlocked opening and
            // a typed `PairingPossession`; no raw-payload opening signer takes this format.
            Self::PairingPossession => matches!(class, Opening),
            Self::GardenSession
            | Self::PairingApproval
            | Self::AccountRequest
            | Self::AccountStatus
            | Self::RecordRecipient
            | Self::AccountingDelegation
            | Self::ForumChallenge
            | Self::ForumRequest
            | Self::GroupConsent
            | Self::Endorsement
            | Self::ThreadInvitation
            | Self::AdminApproval => matches!(class, Admitted),
            Self::ProfilePublication | Self::ProfileBundle => matches!(class, Profile),
            // The classes whose real paths sign them: the wallet candidate before activation
            // (`UnenrolledCreation::sign_device`) and the unlocked wallet opening
            // (`passkey::sign_device_birth`).
            Self::WalletBirthDevice | Self::WalletBirthPassport => {
                matches!(class, Enrollment | Opening)
            }
        }
    }

    /// Whether a device key of `scope` (the lineage community, `None` when unknown) may sign
    /// this format. The birth formats name the wallet device key `K`: wallet scope only.
    pub(crate) fn allowed_in(self, scope: Option<&str>) -> bool {
        match self {
            Self::WalletBirthDevice | Self::WalletBirthPassport => {
                scope == Some(crate::keys::WALLET_COMMUNITY)
            }
            _ => true,
        }
    }

    /// The one format whose tag leads `message`, if any (unique by prefix-freeness).
    pub fn of(message: &[u8]) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|format| message.starts_with(format.tag()))
    }

    /// Refuse unless `message` is led by this format's tag and `class` allows it.
    pub(crate) fn admit(
        self,
        class: SigningClass,
        scope: Option<&str>,
        message: &[u8],
    ) -> Result<(), Error> {
        if message.len() > crate::MAX_MESSAGE_BYTES {
            return Err(Error::Limit);
        }
        if !self.allowed(class) || !self.allowed_in(scope) || !message.starts_with(self.tag()) {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    /// `tag() || payload`, refused unless `class` allows this format.
    pub(crate) fn message(
        self,
        class: SigningClass,
        scope: Option<&str>,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let tag = self.tag();
        if payload.len() > crate::MAX_MESSAGE_BYTES - tag.len() {
            return Err(Error::Limit);
        }
        let message = [tag, payload].concat();
        self.admit(class, scope, &message)?;
        Ok(message)
    }
}

/// Plain Ed25519 with a device key over a message `format` and `class` admit.
pub(crate) fn sign(
    device: &crate::Secret,
    format: DeviceFormat,
    class: SigningClass,
    scope: Option<&str>,
    message: &[u8],
) -> Result<[u8; 64], Error> {
    format.admit(class, scope, message)?;
    Ok(crate::vld0::sign_ed25519(device, message))
}

/// `format.tag() || payload` signed with a device key, refused unless `class` allows it.
pub(crate) fn sign_payload(
    device: &crate::Secret,
    format: DeviceFormat,
    class: SigningClass,
    scope: Option<&str>,
    payload: &[u8],
) -> Result<[u8; 64], Error> {
    let message = format.message(class, scope, payload)?;
    Ok(crate::vld0::sign_ed25519(device, &message))
}

/// The stamp salt `SHA-256(Ed25519(device, SALT_TAG || payload))`. The signature never
/// leaves this function; no signer accepts `SALT_TAG`.
pub(crate) fn device_salt(device: &crate::Secret, payload: &[u8]) -> Result<[u8; 32], Error> {
    use sha2::Digest as _;
    if payload.len() > crate::MAX_MESSAGE_BYTES - SALT_TAG.len() {
        return Err(Error::Limit);
    }
    let message = zeroize::Zeroizing::new([SALT_TAG, payload].concat());
    let signature = zeroize::Zeroizing::new(crate::vld0::sign_ed25519(device, &message));
    Ok(sha2::Sha256::digest(signature.as_slice()).into())
}

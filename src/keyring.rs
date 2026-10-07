//! Private secret material and encrypted checkpoints. No serialization of raw keys
//! crosses the crate boundary; see docs/CONSTRUCTIONS.md for every construction.

use crate::{Entropy, Error, Secret, passkey};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::Zeroizing;

#[derive(Clone)]
pub(crate) struct Material {
    pub(crate) device: Secret,
    pub(crate) root: Option<Secret>,
}

impl Material {
    pub(crate) fn derive(
        prf: &passkey::PrfOutput,
        community: &str,
        root: bool,
    ) -> Result<Self, Error> {
        Ok(Self {
            device: passkey::device_seed(prf, community)?,
            root: if root {
                Some(passkey::lineage_root(
                    &passkey::lineage_seed(prf, community)?,
                    1,
                )?)
            } else {
                None
            },
        })
    }

    pub(crate) fn root(&self) -> Result<&Secret, Error> {
        self.root.as_ref().ok_or(Error::NoRoot)
    }

    pub(crate) fn append(&self, out: &mut Zeroizing<Vec<u8>>) {
        out.push(u8::from(self.root.is_some()));
        out.extend_from_slice(self.device.as_slice());
        if let Some(root) = &self.root {
            out.extend_from_slice(root.as_slice());
        }
    }

    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let (flag, bytes) = bytes.split_first().ok_or(Error::Encoding)?;
        let root = match (*flag, bytes.len()) {
            (0, 32) => None,
            (1, 64) => Some(secret(&bytes[32..])?),
            _ => return Err(Error::Encoding),
        };
        Ok(Self {
            device: secret(&bytes[..32])?,
            root,
        })
    }
}

pub(crate) fn secret(bytes: &[u8]) -> Result<Secret, Error> {
    if bytes.len() != 32 {
        return Err(Error::Encoding);
    }
    let mut value = Zeroizing::new([0; 32]);
    value.copy_from_slice(bytes);
    Ok(value)
}

pub(crate) fn seal(
    rng: &mut impl Entropy,
    key: &Secret,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut nonce = [0; 24];
    rng.fill(&mut nonce)?;
    let ciphertext = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(crate::error::redact(Error::Crypto))?
        .encrypt(
            &XNonce::try_from(nonce.as_slice()).map_err(crate::error::redact(Error::Crypto))?,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(crate::error::redact(Error::Crypto))?;
    let mut result = Vec::with_capacity(24 + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

pub(crate) fn open(key: &Secret, aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if sealed.len() < 40 {
        return Err(Error::Open);
    }
    let (nonce, ciphertext) = sealed.split_at(24);
    XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(crate::error::redact(Error::Crypto))?
        .decrypt(
            &XNonce::try_from(nonce).map_err(crate::error::redact(Error::Open))?,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(crate::error::redact(Error::Open))
}

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
    pub(crate) identity: Option<Secret>,
    // Opening-only history. Never used to issue a certificate or sign new data.
    pub(crate) history: Vec<(u64, Secret)>,
}

impl Material {
    pub(crate) fn derive(
        prf: &passkey::PrfOutput,
        community: &str,
        root: bool,
        rng: &mut impl Entropy,
    ) -> Result<Self, Error> {
        let common = if root {
            Some(crate::vld0::random_secret(rng)?)
        } else {
            None
        };
        Ok(Self {
            device: passkey::device_seed(prf, community)?,
            identity: common.clone(),
            root: common,
            history: Vec::new(),
        })
    }

    pub(crate) fn root(&self) -> Result<&Secret, Error> {
        self.root.as_ref().ok_or(Error::NoRoot)
    }

    pub(crate) fn transfer_version(&self) -> u8 {
        if !self.history.is_empty() {
            3
        } else if self.identity.is_some() {
            2
        } else {
            1
        }
    }

    pub(crate) fn transfer(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        if self.history.len() > (crate::MAX_CHECKPOINT_BYTES - 65) / 40 {
            return Err(Error::Limit);
        }
        let mut bytes = Zeroizing::new(self.root()?.to_vec());
        if !self.history.is_empty() {
            bytes.push(u8::from(self.identity.is_some()));
        }
        if let Some(identity) = &self.identity {
            bytes.extend_from_slice(identity.as_slice());
        }
        for (epoch, root) in &self.history {
            bytes.extend_from_slice(&epoch.to_le_bytes());
            bytes.extend_from_slice(root.as_slice());
        }
        Ok(bytes)
    }

    pub(crate) fn receive(&mut self, version: u8, bytes: &[u8]) -> Result<(), Error> {
        let (identity, history) = match (version, bytes.len()) {
            (1, 32) => (None, Vec::new()),
            (2, 64) => (Some(secret(&bytes[32..])?), Vec::new()),
            (3, length) if (73..=crate::MAX_CHECKPOINT_BYTES).contains(&length) => {
                let (identity, start) = match bytes[32] {
                    0 => (None, 33),
                    1 => (Some(secret(&bytes[33..65])?), 65),
                    _ => return Err(Error::Encoding),
                };
                let tail = &bytes[start..];
                if tail.is_empty() || !tail.len().is_multiple_of(40) {
                    return Err(Error::Encoding);
                }
                let mut history = Vec::with_capacity(tail.len() / 40);
                let mut previous = 0;
                for entry in tail.as_chunks::<40>().0 {
                    let epoch = u64::from_le_bytes(entry[..8].try_into().map_err(|__cause| {
                        crate::cause::emit(
                            file!(),
                            line!(),
                            "Error::Encoding",
                            Error::Encoding,
                            &__cause,
                        )
                    })?);
                    if epoch <= previous {
                        return Err(Error::Encoding);
                    }
                    history.push((epoch, secret(&entry[8..])?));
                    previous = epoch;
                }
                (identity, history)
            }
            _ => return Err(Error::Encoding),
        };
        self.root = Some(secret(&bytes[..32])?);
        self.identity = identity;
        self.history = history;
        Ok(())
    }

    pub(crate) fn append(&self, out: &mut Zeroizing<Vec<u8>>) {
        let flag = if self.root.is_some() {
            self.transfer_version()
        } else {
            0
        };
        out.push(flag);
        out.extend_from_slice(self.device.as_slice());
        if let Some(root) = &self.root {
            if flag == 3 {
                out.extend_from_slice(root.as_slice());
                out.push(u8::from(self.identity.is_some()));
                if let Some(identity) = &self.identity {
                    out.extend_from_slice(identity.as_slice());
                }
                for (epoch, root) in &self.history {
                    out.extend_from_slice(&epoch.to_le_bytes());
                    out.extend_from_slice(root.as_slice());
                }
            } else {
                out.extend_from_slice(root.as_slice());
                if let Some(identity) = &self.identity {
                    out.extend_from_slice(identity.as_slice());
                }
            }
        }
    }

    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let (flag, bytes) = bytes.split_first().ok_or(Error::Encoding)?;
        if !matches!((*flag, bytes.len()), (0, 32) | (1, 64) | (2, 96))
            && !(*flag == 3 && (105..=crate::MAX_CHECKPOINT_BYTES).contains(&bytes.len()))
        {
            return Err(Error::Encoding);
        }
        let mut material = Self {
            device: secret(&bytes[..32])?,
            root: None,
            identity: None,
            history: Vec::new(),
        };
        if *flag != 0 {
            material.receive(*flag, &bytes[32..])?;
        }
        Ok(material)
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
        .map_err(|__cause| {
            crate::cause::emit(file!(), line!(), "Error::Crypto", Error::Crypto, &__cause)
        })?
        .encrypt(
            &XNonce::try_from(nonce.as_slice()).map_err(|__cause| {
                crate::cause::emit(file!(), line!(), "Error::Crypto", Error::Crypto, &__cause)
            })?,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|__cause| {
            crate::cause::emit(file!(), line!(), "Error::Crypto", Error::Crypto, &__cause)
        })?;
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
        .map_err(|__cause| {
            crate::cause::emit(file!(), line!(), "Error::Crypto", Error::Crypto, &__cause)
        })?
        .decrypt(
            &XNonce::try_from(nonce).map_err(|__cause| {
                crate::cause::emit(file!(), line!(), "Error::Open", Error::Open, &__cause)
            })?,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|__cause| {
            crate::cause::emit(file!(), line!(), "Error::Open", Error::Open, &__cause)
        })
}

#[cfg(test)]
#[path = "../tests/unit/keyring.rs"]
mod tests;

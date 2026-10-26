//! Borrowed upstream XChaCha20 for Veilid's signed record format.
use crate::{Error, MAX_MESSAGE_BYTES, Secret};
use chacha20::{
    XChaCha20,
    cipher::{KeyIvInit, StreamCipher},
};
use zeroize::Zeroizing;

/// One current-authorized record cipher call. No key export or serialization.
/// This is Veilid's unauthenticated stream cipher: the record owner must verify
/// the original VLD0 signed value and nonce before opening, and supply a fresh
/// unpredictable nonce for every encryption. Never use this as a generic AEAD.
pub struct Vld0RecordCipher<'key> {
    pub(crate) secret: &'key Secret,
}

/// Historical opening capability. No signing or current-record writer is lent.
pub struct Vld0RecordReader<'key> {
    pub(crate) cipher: Vld0RecordCipher<'key>,
}
impl Vld0RecordReader<'_> {
    /// Open an original signed-and-verified retained record with its original nonce.
    pub fn open(&self, nonce: &[u8; 24], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.cipher.crypt(nonce, ciphertext)
    }
}

impl Vld0RecordCipher<'_> {
    /// Apply the upstream record cipher to bounded original bytes.
    /// The zeroizing output may be ciphertext or plaintext; it is not a key.
    pub fn crypt(&self, nonce: &[u8; 24], input: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        if input.len() > MAX_MESSAGE_BYTES {
            return Err(Error::Limit);
        }
        let mut output = Zeroizing::new(input.to_vec());
        XChaCha20::new((&**self.secret).into(), nonce.into())
            .try_apply_keystream(&mut output)
            .map_err(|__cause| {
                crate::cause::emit(file!(), line!(), "Error::Crypto", Error::Crypto, &__cause)
            })?;
        Ok(output)
    }
}

#[cfg(test)]
#[path = "../tests/unit/record_cipher.rs"]
mod tests;

//! Borrowed original VLD0 node DH and ENV0 stream encryption.
use crate::{Error, PublicKey, Secret, VLD0, Vld0RecordCipher, vld0};
use zeroize::Zeroizing;

/// One freshly authorized node-purpose cipher. No private key or DH secret
/// export is available, and the capability cannot escape its owner callback.
///
/// The envelope owner must authenticate the original ENV0 signature, recipient,
/// timestamp and inner operation before accepting decrypted data, and generate
/// a fresh unpredictable nonce when sealing. This is unauthenticated XChaCha20
/// for the original signed envelope format, not a standalone AEAD.
pub struct Vld0NodeCipher<'key> {
    pub(crate) secret: &'key Secret,
    pub(crate) public_key: [u8; 32],
}

impl Vld0NodeCipher<'_> {
    /// Public coordinate of the same node purpose as the accompanying signer.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Original VLD0 compute_dh(peer, node) followed by crypt_no_auth.
    /// Refuses weak or invalid peers and bounds input before deriving any key.
    pub fn crypt(
        &self,
        peer: &[u8; 32],
        nonce: &[u8; 24],
        input: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        // ENV0's complete packet limit, before the owner subtracts overhead.
        if input.len() > 65_507 {
            return Err(Error::Limit);
        }
        let secret = vld0::compute_dh(self.secret, &PublicKey::new(VLD0, *peer))?;
        Vld0RecordCipher { secret: &secret }.crypt(nonce, input)
    }
}

#[cfg(test)]
#[path = "../tests/unit/node_cipher.rs"]
mod tests;

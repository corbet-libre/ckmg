//! Fixed original Records output from normal member bootstrap custody.
use super::*;

impl CheckpointBootstrap {
    /// Prepare this exact passkey's original DFLT(1), subkey-zero record using
    /// its original PRF derivation. No arbitrary signer or cipher escapes.
    /// The composer must retain exact output durably before any transport call,
    /// and recheck current member authority around its own asynchronous work.
    /// Supply a fresh unpredictable nonce for every distinct plaintext under
    /// this read key. Retry by retaining the exact immutable signed ciphertext;
    /// never reuse its nonce to encrypt different bytes.
    pub fn passkey_publication(
        &self,
        prf: &passkey::PrfOutput,
        sequence: u32,
        packed: &[u8],
        nonce: [u8; 24],
    ) -> Result<(cdht::Descriptor, cdht::SignedValue), Error> {
        let scope = self.inspection.lineage.binding.community();
        if passkey::vault_location(prf, scope)? != self.location {
            return Err(Error::Unauthorized);
        }
        let (owner, read) = passkey::record_material(prf, scope)?;
        fixed(&owner, &read, 1, 0, sequence, packed, nonce)
    }
}

impl CheckpointRecordCustody<'_> {
    /// Prepare one bounded subkey of this original DFLT(32) compound record.
    /// This is original owner packing/cipher/signature preparation, not durable
    /// queueing, delivery, current authority or an acknowledgment.
    /// Supply a fresh unpredictable nonce for every distinct plaintext under
    /// this read key, including writes to different subkeys. Retry the exact
    /// retained signed ciphertext rather than reusing its nonce for new bytes.
    pub fn publication(
        &self,
        subkey: u32,
        sequence: u32,
        packed: &[u8],
        nonce: [u8; 24],
    ) -> Result<(cdht::Descriptor, cdht::SignedValue), Error> {
        fixed(&self.owner, &self.read, 32, subkey, sequence, packed, nonce)
    }
}

struct Signer<'a>(&'a Secret);
impl cdht::Signer for Signer<'_> {
    fn public_key(&self) -> [u8; 32] {
        *vld0::public_key(self.0).value()
    }
    fn sign(&self, data: &[u8]) -> Result<[u8; 64], cdht::Error> {
        vld0::sign(self.0, data)
            .map(|signature| *signature.value())
            .map_err(|__cause| {
                crate::cause::emit(
                    file!(),
                    line!(),
                    "cdht::Error::BadSignature",
                    cdht::Error::BadSignature,
                    &__cause,
                )
            })
    }
}
fn fixed(
    owner: &Secret,
    read: &Secret,
    subkeys: u16,
    subkey: u32,
    sequence: u32,
    packed: &[u8],
    nonce: [u8; 24],
) -> Result<(cdht::Descriptor, cdht::SignedValue), Error> {
    if packed.is_empty()
        || packed.len() > cdht::MAX_SUBKEY_SIZE
        || sequence > cdht::MAX_SEQ
        || subkey >= u32::from(subkeys)
    {
        return Err(Error::Limit);
    }
    let schema = cdht::Schema::dflt(subkeys).map_err(|__cause| {
        crate::cause::emit(
            file!(),
            line!(),
            "Error::Encoding",
            Error::Encoding,
            &__cause,
        )
    })?;
    let signer = Signer(owner);
    let descriptor = cdht::Descriptor::create(&schema, &signer).map_err(|__cause| {
        crate::cause::emit(file!(), line!(), "Error::Crypto", Error::Crypto, &__cause)
    })?;
    let ciphertext = crate::Vld0RecordCipher { secret: read }.crypt(&nonce, packed)?;
    let value = cdht::SignedValue::sign_with_nonce(
        &descriptor.owner,
        subkey,
        sequence,
        ciphertext.to_vec(),
        Some(nonce),
        &signer,
    )
    .map_err(|__cause| {
        crate::cause::emit(file!(), line!(), "Error::Crypto", Error::Crypto, &__cause)
    })?;
    Ok((descriptor, value))
}

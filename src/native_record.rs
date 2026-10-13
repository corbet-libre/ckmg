//! Native engine initialization inside Keys; no network I/O or key getter.
use crate::{NativeRecordInitializer, NativeRecordSchema, Secret, vld0};
use cvln::core::{
    BarePublicKey, BareSecretKey, BareSharedSecret, CRYPTO_KIND_VLD0, KeyPair, PublicKey,
    SharedSecret,
};

pub(crate) fn owner(
    schema: NativeRecordSchema,
    owner: &Secret,
    read: &Secret,
) -> NativeRecordInitializer {
    let public = vld0::public_key(owner);
    let key = PublicKey::new(
        CRYPTO_KIND_VLD0,
        BarePublicKey::from(public.value().as_slice()),
    );
    let pair = KeyPair::new_from_parts(key, BareSecretKey::from(owner.as_slice()));
    let read = SharedSecret::new(CRYPTO_KIND_VLD0, BareSharedSecret::from(read.as_slice()));
    NativeRecordInitializer::owner(schema, pair, read)
}

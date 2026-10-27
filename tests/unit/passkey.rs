use super::*;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn record_recipient_label_has_an_independent_standard_hkdf_vector() {
    let hex = |bytes: &[u8]| data_encoding::HEXLOWER.encode(bytes);
    let common = PrfOutput::from_bytes(&[27; 32]).unwrap();
    let recipient = expand(&common, b"ckmg.record-witness-recipient.v1\0", "a").unwrap();
    // Independently evaluated by Node's OpenSSL-backed crypto.hkdfSync.
    assert_eq!(
        hex(recipient.as_slice()),
        "29207e2943ad50807f652582fa72529d910ffc82a6db9b7d6bb5cd08c290f198"
    );
    let roots = identity_roots(&common, "a").unwrap();
    assert_ne!(recipient, roots.balance_seed);
    assert_ne!(recipient, roots.balance_sealing_key);
    assert_ne!(recipient, device_seed(&common, "a").unwrap());
    assert_ne!(
        recipient,
        expand(&common, b"ckmg.record-witness-recipient.v1\0", "b").unwrap()
    );
}

const LINEAGE_INFO: &[u8] = b"ckmg.member-lineage-seed.v1\0";

fn lineage_seed(prf: &PrfOutput, community: &str) -> Result<Secret, Error> {
    expand(prf, LINEAGE_INFO, community)
}

fn lineage_root(seed: &Secret, epoch: u64) -> Result<Secret, Error> {
    if epoch == 0 {
        return Err(Error::Encoding);
    }
    let mut root = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(b"ckmg.lineage-root.v1"), seed.as_slice())
        .expand(&epoch.to_be_bytes(), root.as_mut())
        .map_err(|_| Error::Crypto)?;
    Ok(root)
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn hkdf_derivation_matches_independent_hmac_vectors() {
    // Independently evaluated from RFC 5869 Extract + one Expand block (L=32).
    let prf = PrfOutput::from_bytes(&[27; 32]).unwrap();
    let hex = |bytes: &[u8]| data_encoding::HEXLOWER.encode(bytes);
    assert_eq!(
        hex(vault_location(&prf, "a").unwrap().as_bytes()),
        "c5086bf525ec6e443a5a0592e044e1d0fdfcde4b7d8d0c6195b3565fcc02690a"
    );
    assert_eq!(
        hex(ring_key(&prf, "a").unwrap().as_slice()),
        "1f267040dddfa9cbf9d26075ae78d90ff69a5a1fc98d7242a30ae770b0db6b64"
    );
    assert_eq!(
        hex(store_cipher(&prf, "a").unwrap().0.as_slice()),
        "767cc54cee7a526522277a226fa0aeb6671f2040a9fc768743f1820b9a88ab4b"
    );
    let roots = identity_roots(&prf, "a").unwrap();
    assert_eq!(
        hex(roots.identity.as_slice()),
        "305fd593f6b34de15c321bd2daddf61034fd5185347d68d2d4bfcae20dc2e740"
    );
    assert_eq!(
        hex(roots.passport_holder_seed.as_slice()),
        "fb89d2196c2d2f07a23f69c7b3f6d919a10f71e8609bc211eaf0000f0050c68f"
    );
    assert_eq!(
        hex(device_seed(&prf, "a").unwrap().as_slice()),
        "cda24928113648d6cd3dc9f1d83e96cae9cb91d29491e4a75d7c9b61dfefba0f"
    );
    assert_eq!(
        hex(roots.holder_sealing_key.as_slice()),
        "ceb5a2ef739dcbe1c3bdb9d8ef7543ebf8f2af6d77e6d9b0a736e290bb9559e2"
    );
    assert_eq!(
        hex(roots.balance_seed.as_slice()),
        "2589cab8f9b8522a5cbed74f38dcad0775f0fe41f8cb9dbde59042a0c1d48042"
    );
    assert_eq!(
        hex(roots.balance_sealing_key.as_slice()),
        "fe524fdaab3dec920c9515b489860744aa14c0f5c57bf90a8736d1858813a901"
    );
    let seed = lineage_seed(&prf, "a").unwrap();
    assert_eq!(
        hex(seed.as_slice()),
        "7c7b50366ada27df5c5bbf1519e0523fa92dfd7b2197abe488918e3ee4b1cd44"
    );
    assert_eq!(
        hex(lineage_root(&seed, 1).unwrap().as_slice()),
        "ab89538e361da6c46348c22a983be09ba3f078f7e4152c797d6857c89ecc3d0f"
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn legacy_purpose_vectors_remain_stable_and_separate_domains() {
    let prf = PrfOutput::from_bytes(&[27; 32]).unwrap();
    let other = PrfOutput::from_bytes(&[28; 32]).unwrap();
    let a = identity_roots(&prf, "a").unwrap();
    let restored = identity_roots(&prf, "a").unwrap();
    assert_eq!(a.identity, restored.identity);
    assert_eq!(a.passport_holder_seed, restored.passport_holder_seed);
    assert_eq!(a.holder_sealing_key, restored.holder_sealing_key);
    assert_eq!(a.balance_sealing_key, restored.balance_sealing_key);
    assert_eq!(a.balance_seed, restored.balance_seed);
    for different in [
        identity_roots(&prf, "b").unwrap(),
        identity_roots(&other, "a").unwrap(),
    ] {
        assert_ne!(a.identity, different.identity);
        assert_ne!(a.passport_holder_seed, different.passport_holder_seed);
        assert_ne!(a.holder_sealing_key, different.holder_sealing_key);
        assert_ne!(a.balance_sealing_key, different.balance_sealing_key);
        assert_ne!(a.balance_seed, different.balance_seed);
    }
    let seed = lineage_seed(&prf, "a").unwrap();
    let branches = [
        a.identity.clone(),
        a.passport_holder_seed.clone(),
        a.holder_sealing_key.clone(),
        a.balance_sealing_key.clone(),
        a.balance_seed.clone(),
        device_seed(&prf, "a").unwrap(),
        seed.clone(),
        lineage_root(&seed, 1).unwrap(),
        lineage_root(&seed, 2).unwrap(),
        ring_key(&prf, "a").unwrap(),
        store_cipher(&prf, "a").unwrap().0,
    ];
    for (i, value) in branches.iter().enumerate() {
        for other in &branches[i + 1..] {
            assert_ne!(value, other);
        }
    }
    let signature = a.prove_possession(b"challenge").unwrap();
    crate::verify(
        &restored.public_key(),
        &restored.proof_transcript(b"challenge").unwrap(),
        &signature,
    )
    .unwrap();
    assert!(
        crate::verify(
            &restored.public_key(),
            &restored.proof_transcript(b"other").unwrap(),
            &signature
        )
        .is_err()
    );
    assert!(lineage_root(&seed, 0).is_err());
    for domain in ["", "bad\0domain", &"a".repeat(257)] {
        assert!(identity_roots(&prf, domain).is_err());
        assert!(vault_location(&prf, domain).is_err());
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn proof_transcript_enforces_the_4096_byte_bound() {
    let prf = PrfOutput::from_bytes(&[27; 32]).unwrap();
    let roots = identity_roots(&prf, "a").unwrap();
    let max = vec![0u8; 4096];
    let transcript = roots.proof_transcript(&max).unwrap();
    let signature = roots.prove_possession(&max).unwrap();
    crate::verify(&roots.public_key(), &transcript, &signature).unwrap();
    assert!(matches!(
        roots.proof_transcript(&vec![0u8; 4097]),
        Err(Error::Limit)
    ));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn store_cipher_seal_enforces_both_bounds_at_exact_limits() {
    let prf = PrfOutput::from_bytes(&[27; 32]).unwrap();
    let cipher = store_cipher(&prf, "a").unwrap();
    assert!(matches!(
        cipher.seal(&mut crate::SystemEntropy, &vec![0u8; 4097], b"x"),
        Err(Error::Limit)
    ));
    assert!(matches!(
        cipher.seal(
            &mut crate::SystemEntropy,
            b"context",
            &vec![0u8; crate::MAX_MESSAGE_BYTES + 1]
        ),
        Err(Error::Limit)
    ));
    let context = vec![9u8; 4096];
    let sealed = cipher
        .seal(&mut crate::SystemEntropy, &context, b"exact")
        .unwrap();
    assert_eq!(
        cipher.open(&context, &sealed).unwrap().as_slice(),
        b"exact".as_slice()
    );
    let plaintext = vec![7u8; crate::MAX_MESSAGE_BYTES];
    let big = cipher
        .seal(&mut crate::SystemEntropy, b"c", &plaintext)
        .unwrap();
    assert_eq!(
        cipher.open(b"c", &big).unwrap().as_slice(),
        plaintext.as_slice()
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn store_cipher_open_enforces_both_bounds_at_exact_limits() {
    let prf = PrfOutput::from_bytes(&[27; 32]).unwrap();
    let cipher = store_cipher(&prf, "a").unwrap();
    assert!(matches!(
        cipher.open(&vec![0u8; 4097], &vec![0u8; 50]),
        Err(Error::Limit)
    ));
    assert!(matches!(
        cipher.open(b"context", &vec![0u8; crate::MAX_MESSAGE_BYTES + 41]),
        Err(Error::Limit)
    ));
    assert!(matches!(
        cipher.open(b"context", &vec![0u8; crate::MAX_MESSAGE_BYTES + 40]),
        Err(Error::Open)
    ));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn record_custody_debug_stays_redacted() {
    let prf = PrfOutput::from_bytes(&[27; 32]).unwrap();
    assert_eq!(
        format!("{:?}", passkey_record_reader(&prf, "a").unwrap()),
        "PasskeyRecordReader([redacted])"
    );
    assert_eq!(
        format!("{:?}", passkey_record_writer(&prf, "a").unwrap()),
        "PasskeyRecordWriter([redacted])"
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn record_material_matches_reader_writer_and_separates_communities() {
    let prf = PrfOutput::from_bytes(&[27; 32]).unwrap();
    let (owner, read) = record_material(&prf, "a").unwrap();
    assert_eq!(
        owner,
        expand(&prf, b"passkey-record-owner-v1\0", "a").unwrap()
    );
    assert_eq!(
        read,
        expand(&prf, b"passkey-record-read-v1\0", "a").unwrap()
    );
    assert_ne!(owner, read);
    assert_ne!(*owner, [0; 32]);
    assert_ne!(*read, [0; 32]);
    let reader = passkey_record_reader(&prf, "a").unwrap();
    assert_eq!(reader.owner(), crate::vld0::public_key(&owner));
    assert_eq!(
        passkey_record_writer(&prf, "a").unwrap().owner(),
        reader.owner()
    );
    assert_ne!(record_material(&prf, "b").unwrap().0, owner);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn vault_location_enforces_the_256_byte_community_bound() {
    let prf = PrfOutput::from_bytes(&[27; 32]).unwrap();
    assert!(vault_location(&prf, &"a".repeat(256)).is_ok());
    assert!(vault_location(&prf, &"a".repeat(257)).is_err());
}

#[cfg(feature = "profile-envelope")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn profile_storage_key_is_label_bound_and_separates_communities() {
    let common: Secret = Zeroizing::new([27u8; 32]);
    let key = profile_storage_key(&common, "a").unwrap();
    assert_eq!(
        key,
        expand(
            &PrfOutput(common.clone()),
            b"ckmg.profile-envelope-storage.v2\0",
            "a"
        )
        .unwrap()
    );
    assert_ne!(*key, [0; 32]);
    assert_ne!(profile_storage_key(&common, "b").unwrap(), key);
    assert!(profile_storage_key(&common, "").is_err());
}

#[cfg(feature = "profile-envelope")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn envelope_legacy_key_is_the_live_cipher_secret() {
    let prf = PrfOutput::from_bytes(&[27; 32]).unwrap();
    let cipher = store_cipher(&prf, "a").unwrap();
    let live: [u8; 32] = **cipher.secret();
    assert_eq!(*cipher.envelope_legacy_key(), live);
    assert_ne!(*cipher.envelope_legacy_key(), [0; 32]);
    assert_ne!(*cipher.envelope_legacy_key(), [1; 32]);
    assert_ne!(
        store_cipher(&prf, "b").unwrap().envelope_legacy_key(),
        cipher.envelope_legacy_key()
    );
}

#[cfg(feature = "wallet-engine")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn record_recipient_is_deterministic_and_separates_communities() {
    let common: Secret = Zeroizing::new([27u8; 32]);
    let first =
        with_record_recipient(&common, "a", 1000, |recipient| recipient.public_key()).unwrap();
    let second =
        with_record_recipient(&common, "a", 1000, |recipient| recipient.public_key()).unwrap();
    assert_eq!(first, second);
    assert_ne!(first, [0; 32]);
    let other =
        with_record_recipient(&common, "b", 1000, |recipient| recipient.public_key()).unwrap();
    assert_ne!(first, other);
}

#[cfg(feature = "wallet-engine")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn wallet_engine_restores_only_under_its_own_domain() {
    let prf = PrfOutput::from_bytes(&[27; 32]).unwrap();
    let engine = identity_roots(&prf, "a").unwrap().wallet_engine().unwrap();
    let sealed = engine.seal().unwrap();
    assert!(engine.restored(&sealed).is_ok());
    let foreign = identity_roots(&prf, "b").unwrap().wallet_engine().unwrap();
    assert!(foreign.restored(&sealed).is_err());
}

#[cfg(feature = "wallet-engine")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn account_signing_binds_exact_digest_and_scope() {
    let prf = PrfOutput::from_bytes(&[27; 32]).unwrap();
    let roots = identity_roots(&prf, "a").unwrap();
    let engine = roots.wallet_engine().unwrap();
    let sealed = engine
        .prepare_account_key("a", [5; 32])
        .unwrap()
        .seal()
        .unwrap();
    let digest = [9; 32];
    let first = roots
        .account_signing(digest)
        .unwrap()
        .sign(&sealed, "a")
        .unwrap();
    let second = roots
        .account_signing(digest)
        .unwrap()
        .sign(&sealed, "a")
        .unwrap();
    assert_eq!(first, second);
    let other = roots
        .account_signing([10; 32])
        .unwrap()
        .sign(&sealed, "a")
        .unwrap();
    assert_ne!(first, other);
    assert!(
        roots
            .account_signing(digest)
            .unwrap()
            .sign(&sealed, "b")
            .is_err()
    );
}

#[cfg(feature = "passport")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn holder_seed_rebuilds_the_same_holder_per_domain() {
    use cpsd::rand::{SeedableRng, rngs::StdRng};
    let prf = PrfOutput::from_bytes(&[27; 32]).unwrap();
    let community = cpsd::CommunityId::new(b"community-a").unwrap();
    let holder = identity_roots(&prf, "a")
        .unwrap()
        .holder_seed()
        .into_passport_holder()
        .unwrap();
    let expected = holder.pseudonym(&community);
    let rebuilt = identity_roots(&prf, "a")
        .unwrap()
        .holder_seed()
        .into_passport_holder()
        .unwrap();
    assert_eq!(rebuilt.pseudonym(&community), expected);
    let foreign = identity_roots(&prf, "b")
        .unwrap()
        .holder_seed()
        .into_passport_holder()
        .unwrap();
    assert_ne!(foreign.pseudonym(&community), expected);
    let mut rng = StdRng::seed_from_u64(1);
    let sealed = holder.seal(&mut rng).unwrap();
    let opened = identity_roots(&prf, "a")
        .unwrap()
        .holder_seed()
        .open_passport_holder(&sealed)
        .unwrap();
    assert_eq!(opened.pseudonym(&community), expected);
    assert!(
        identity_roots(&prf, "b")
            .unwrap()
            .holder_seed()
            .open_passport_holder(&sealed)
            .is_err()
    );
}

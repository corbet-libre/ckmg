use super::*;

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
    for different in [
        identity_roots(&prf, "b").unwrap(),
        identity_roots(&other, "a").unwrap(),
    ] {
        assert_ne!(a.identity, different.identity);
        assert_ne!(a.passport_holder_seed, different.passport_holder_seed);
    }
    let seed = lineage_seed(&prf, "a").unwrap();
    let branches = [
        a.identity.clone(),
        a.passport_holder_seed.clone(),
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

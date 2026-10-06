use super::*;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn material_versions_preserve_legacy_bytes_and_require_the_whole_common_root() {
    for flag in 0..=2 {
        let mut historical = Zeroizing::new(vec![flag]);
        historical.extend_from_slice(&[1; 32]);
        if flag != 0 {
            historical.extend_from_slice(&[2; 32]);
        }
        if flag == 2 {
            historical.extend_from_slice(&[3; 32]);
        }
        let material = Material::parse(&historical).unwrap();
        let mut encoded = Zeroizing::new(Vec::new());
        material.append(&mut encoded);
        assert_eq!(*encoded, *historical);
        assert_eq!(material.identity.is_some(), flag == 2);
        if flag == 0 {
            assert!(matches!(material.transfer(), Err(Error::NoRoot)));
        } else {
            let transfer = material.transfer().unwrap();
            assert!(Material::parse(&historical[..33]).is_err());
            let mut pending = Material {
                device: secret(&[4; 32]).unwrap(),
                root: None,
                identity: None,
                history: Vec::new(),
            };
            pending.receive(flag, &transfer).unwrap();
            assert_eq!(pending.root, material.root);
            assert_eq!(pending.identity, material.identity);
            let incompatible_length = if flag == 1 { 64 } else { 32 };
            assert_eq!(
                pending.receive(flag, &vec![0; incompatible_length]),
                Err(Error::Encoding)
            );
            assert_eq!(pending.receive(3, &transfer), Err(Error::Encoding));
            for length in [0, 31, 33, 63, 65] {
                assert_eq!(
                    pending.receive(flag, &vec![0; length]),
                    Err(Error::Encoding)
                );
                assert_eq!(pending.root, material.root);
                assert_eq!(pending.identity, material.identity);
            }
        }
    }
    for bytes in [vec![], vec![3; 97], vec![0; 32], vec![1; 33], vec![2; 65]] {
        assert!(matches!(Material::parse(&bytes), Err(Error::Encoding)));
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn history_transfer_is_bounded_ordered_and_all_or_nothing() {
    for identity in [None, Some(secret(&[9; 32]).unwrap())] {
        let material = Material {
            device: secret(&[4; 32]).unwrap(),
            root: Some(secret(&[5; 32]).unwrap()),
            identity,
            history: vec![
                (1, secret(&[6; 32]).unwrap()),
                (2, secret(&[7; 32]).unwrap()),
            ],
        };
        assert_eq!(material.transfer_version(), 3);
        let transfer = material.transfer().unwrap();
        let mut checkpoint = Zeroizing::new(Vec::new());
        material.append(&mut checkpoint);
        let parsed = Material::parse(&checkpoint).unwrap();
        assert_eq!(parsed.history, material.history);
        assert_eq!(parsed.identity, material.identity);
        let mut target = Material {
            device: secret(&[4; 32]).unwrap(),
            root: None,
            identity: None,
            history: Vec::new(),
        };
        target.receive(3, &transfer).unwrap();
        assert_eq!(target.history, material.history);
        let start = if material.identity.is_some() { 65 } else { 33 };
        for epoch in [0u64, 1] {
            let mut invalid = transfer.clone();
            invalid[start + 40..start + 48].copy_from_slice(&epoch.to_le_bytes());
            assert_eq!(target.receive(3, &invalid), Err(Error::Encoding));
            assert_eq!(target.history, material.history);
        }
        assert_eq!(
            target.receive(3, &transfer[..transfer.len() - 1]),
            Err(Error::Encoding)
        );
        assert_eq!(
            target.receive(3, &vec![0; crate::MAX_CHECKPOINT_BYTES + 1]),
            Err(Error::Encoding)
        );
    }
}

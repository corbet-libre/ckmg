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
            let mut pending = Material { device: secret(&[4; 32]).unwrap(), root: None, identity: None };
            pending.receive(flag, &transfer).unwrap();
            assert_eq!(pending.root, material.root);
            assert_eq!(pending.identity, material.identity);
            let incompatible_length = if flag == 1 { 64 } else { 32 };
            assert_eq!(pending.receive(flag, &vec![0; incompatible_length]), Err(Error::Encoding));
            assert_eq!(pending.receive(3, &transfer), Err(Error::Encoding));
            for length in [0, 31, 33, 63, 65] {
                assert_eq!(pending.receive(flag, &vec![0; length]), Err(Error::Encoding));
                assert_eq!(pending.root, material.root);
                assert_eq!(pending.identity, material.identity);
            }
        }
    }
    for bytes in [vec![], vec![3; 97], vec![0; 32], vec![1; 33], vec![2; 65]] {
        assert!(matches!(Material::parse(&bytes), Err(Error::Encoding)));
    }
}

use super::*;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn matches_independent_libsodium_xchacha20_vector() {
    // crypto_stream_xchacha20_xor, libsodium.so.26; synthetic key/nonce.
    let secret = Zeroizing::new([7; 32]);
    let cipher = Vld0RecordCipher { secret: &secret };
    let expected = [
        167, 156, 114, 88, 37, 147, 113, 164, 172, 90, 120, 252, 228, 191, 23, 21, 65, 65, 7, 16,
        152, 147, 114, 11, 33, 19, 86, 8,
    ];
    assert_eq!(
        &*cipher
            .crypt(&[21; 24], b"original Veilid record bytes")
            .unwrap(),
        &expected
    );
    assert_eq!(
        &*cipher.crypt(&[21; 24], &expected).unwrap(),
        b"original Veilid record bytes"
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn exact_max_message_crypts_and_round_trips() {
    let secret = Zeroizing::new([7; 32]);
    let cipher = Vld0RecordCipher { secret: &secret };
    let plaintext = vec![0x5a; MAX_MESSAGE_BYTES];
    let ciphertext = cipher.crypt(&[21; 24], &plaintext).unwrap();
    assert_eq!(ciphertext.len(), MAX_MESSAGE_BYTES);
    assert_eq!(&*cipher.crypt(&[21; 24], &ciphertext).unwrap(), &plaintext);
    assert_eq!(
        cipher
            .crypt(&[21; 24], &vec![0; MAX_MESSAGE_BYTES + 1])
            .unwrap_err(),
        Error::Limit
    );
}

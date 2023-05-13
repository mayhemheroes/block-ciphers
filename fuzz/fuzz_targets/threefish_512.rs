#![no_main]
use libfuzzer_sys::fuzz_target;

use threefish::Threefish512;
use threefish::cipher::{
    BlockEncrypt, BlockDecrypt,
    generic_array::GenericArray, generic_array::typenum::U64
};

fuzz_target!(|value: (&[u8], &[u8], &[u8])| {
    let (key_bytes, tweak_bytes, to_encode) = value;
    if key_bytes.len() < 64 {
        return
    }
    if tweak_bytes.len() < 16 {
        return
    }
    if to_encode.len() < 64 {
        return
    }

    let mut checked_key = [0; 64];
    checked_key.clone_from_slice(&key_bytes[0..64]);

    let mut checked_tweak = [0; 16];
    checked_tweak.clone_from_slice(&tweak_bytes[0..16]);

    let cipher = Threefish512::new_with_tweak(&checked_key, &checked_tweak);

    let mut to_encrypt: GenericArray<u8, U64> = GenericArray::clone_from_slice(&to_encode[0..64]);
    let mut temp_block = GenericArray::from([0u8; 64]);

    let to_encrypt_copy = to_encrypt.clone();
    cipher.encrypt_block(&mut to_encrypt);

    cipher.decrypt_block_b2b(&to_encrypt, &mut temp_block);
    cipher.decrypt_block(&mut to_encrypt);

    assert_eq!(to_encrypt, to_encrypt_copy);
    assert_eq!(temp_block, to_encrypt_copy);
});
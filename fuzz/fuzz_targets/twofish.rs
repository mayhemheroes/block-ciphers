#![no_main]
use aes::cipher::KeyInit;
use libfuzzer_sys::fuzz_target;

use twofish::Twofish;
use twofish::cipher::{
    BlockEncrypt, BlockDecrypt,
    generic_array::GenericArray, generic_array::typenum::U16
};

fuzz_target!(|value: (&[u8], &[u8])| {
    let (key_bytes, to_encode) = value;
    if key_bytes.len() < 16 {
        return
    }
    if to_encode.len() < 32 {
        return
    }

    let mut checked_key = [0; 16];
    checked_key.clone_from_slice(&key_bytes[0..16]);

    let cipher = Twofish::new_from_slice(&checked_key).unwrap();

    let mut to_encrypt: GenericArray<u8, U16> = GenericArray::clone_from_slice(&to_encode[0..16]);
    let mut temp_block = GenericArray::from([0u8; 16]);

    let to_encrypt_copy = to_encrypt.clone();
    cipher.encrypt_block(&mut to_encrypt);

    cipher.decrypt_block_b2b(&to_encrypt, &mut temp_block);
    cipher.decrypt_block(&mut to_encrypt);

    assert_eq!(to_encrypt, to_encrypt_copy);
    assert_eq!(temp_block, to_encrypt_copy);
});
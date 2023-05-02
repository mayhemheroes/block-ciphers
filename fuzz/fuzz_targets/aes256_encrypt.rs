#![no_main]
use libfuzzer_sys::fuzz_target;

use aes::Aes256;
use aes::cipher::{
    BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
    generic_array::typenum::U16
};

fuzz_target!(|value: (&[u8], &[u8])| {
    let (encrypt_bytes, key_bytes) = value;
    if encrypt_bytes.len() < 16 {
        return
    }
    if key_bytes.len() < 16 {
        return
    }
    
    let key = GenericArray::clone_from_slice(&key_bytes[0..16]);
    let mut to_encrypt: GenericArray<u8, U16> = GenericArray::clone_from_slice(&encrypt_bytes[0..16]);

    let mut temp_block = GenericArray::from([0u8; 16]);

    let cipher = Aes256::new(&key);
    let to_encrypt_copy = to_encrypt.clone();
    cipher.encrypt_block(&mut to_encrypt);

    cipher.decrypt_block_b2b(&to_encrypt, &mut temp_block);
    cipher.decrypt_block(&mut to_encrypt);


    assert_eq!(to_encrypt, to_encrypt_copy);
    assert_eq!(temp_block, to_encrypt_copy);
});

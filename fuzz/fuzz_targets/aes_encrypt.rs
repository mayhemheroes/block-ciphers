#![no_main]
use libfuzzer_sys::fuzz_target;

use aes::Aes128;
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
    generic_array::typenum::U16
};

fuzz_target!(|value: &[u8]| {
    if value.len() < 16 {
        return
    }
    let key = GenericArray::from([0u8; 16]);
    let mut block: GenericArray<u8, U16> = GenericArray::clone_from_slice(&value[0..16]);

    let mut temp_block = GenericArray::from([0u8; 16]);

    let cipher = Aes128::new(&key);
    let block_copy = block.clone();
    cipher.encrypt_block(&mut block);
    cipher.decrypt_block(&mut block);

    cipher.decrypt_block_b2b(&block, &mut temp_block);
    assert_eq!(block, block_copy);
});
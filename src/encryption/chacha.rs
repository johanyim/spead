use rand_core::RngCore;
use std::io::Read;

use chacha20::{
    cipher::{generic_array::sequence::GenericSequence, KeyIvInit, StreamCipher},
    ChaCha20, Nonce,
};

use super::KEY_LEN;

pub fn encrypt(plaintext: Vec<u8>, password: [u8; KEY_LEN]) -> Vec<u8> {
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);

    //let nonce = Nonce::default();
    let mut stream = ChaCha20::new_from_slices(&password, &nonce).unwrap();

    let mut buffer = plaintext;
    stream.apply_keystream(&mut buffer);
    //println!("Plaintext = {:?}", buffer);
    //stream
    //    .xor_read(&mut buffer[..])
    //    .expect("hit end of stream far too soon");
    buffer.to_vec()
}

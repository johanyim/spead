use aes_gcm_siv::{
    aead::{Aead, OsRng},
    AeadCore, Aes256GcmSiv, KeyInit, Nonce,
};

pub fn encrypt(plaintext: Vec<u8>) -> Vec<u8> {
    let key = "aslkfjsadf".as_bytes().into();

    let cipher = Aes256GcmSiv::new(key);

    let nonce = Aes256GcmSiv::generate_nonce(&mut OsRng);
    //let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
    let ciphertext = cipher.encrypt(&nonce, &*plaintext).unwrap();

    ciphertext

    //println!("{:?}", String::from_utf8_lossy(&ciphertext));

    //let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
    //
    //println!("{:?}", String::from_utf8_lossy(&plaintext));
}

use cloudproof_fpe::core::Alphabet;
use rand::Rng;

pub fn encrypt_integral(secret_key: &[u8], nonce: &[u8], s: &str) -> String {
    let alphabet = Alphabet::numeric();

    let mut rng = rand::rng();

    let padded = format!("{:0>12}{s:0>12}", rng.random_range(1..1_000_000_000_000u64)); // 12 digit padding
    let encrypted = alphabet.encrypt(&secret_key, nonce, &padded).unwrap();

    // add extra bit from 1-9 to ensure number doesn't begin with '0'
    format!("{}{encrypted}", rand::random_range(1..=9u8))
}

pub fn decrypt_integral(secret_key: &[u8], nonce: &[u8], s: &str) -> String {
    let alphabet = Alphabet::numeric();

    // remove first digit
    let unpadded = &s[1..];

    let decrypted = alphabet.decrypt(&secret_key, nonce, &unpadded).unwrap();
    let unpadded2 = &decrypted[12..]; // remove 12 digit padding

    let trimmed = unpadded2.trim_start_matches('0');
    // special case for decrypting '0'
    match trimmed.is_empty() {
        true => "0",
        false => trimmed,
    }
    .to_string()
}

pub fn encrypt_fractional(secret_key: &[u8], nonce: &[u8], s: &str) -> String {
    let alphabet = Alphabet::numeric();

    let mut rng = rand::rng();

    let right_padded = format!("{s:0<12}{:0<12}", rng.random_range(1..1_000_000_000_000u64));
    let encrypted = alphabet.encrypt(&secret_key, nonce, &right_padded).unwrap();

    // add extra bit from 1-9 to ensure number doesn't end in '0'
    format!("{encrypted}{}", rand::random_range(1..=9u8))
}

pub fn decrypt_fractional(secret_key: &[u8], nonce: &[u8], s: &str) -> String {
    let alphabet = Alphabet::numeric();

    // remove last digit
    let unpadded = &s[0..s.len() - 1];

    let decrypted = alphabet.decrypt(&secret_key, nonce, &unpadded).unwrap();
    let unpadded2 = &decrypted[0..s.len() - 12]; // remove 12 digit padding

    let trimmed = unpadded2.trim_end_matches('0');

    match trimmed.is_empty() {
        true => "0",
        false => trimmed,
    }
    .to_string()
}

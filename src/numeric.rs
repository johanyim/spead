use cloudproof_fpe::core::Alphabet;
use rand::Rng;

const WIDTH: usize = 8;
const WIDTH_U32: u32 = 8;

pub fn encrypt_integral(secret_key: &[u8], nonce: &[u8], mut s: &str) -> String {
    let negative = if s.starts_with('-') {
        s = &s[1..];
        true
    } else {
        false
    };

    let alphabet = Alphabet::numeric();

    let mut rng = rand::rng();

    let rand = rng.random_range(1..10u64.pow(WIDTH_U32));

    // if rand is even, flip the sign
    let new_sign = if negative ^ (rand % 2 == 0) { "-" } else { "" };

    //println!("new_sign = '{rand}'")

    let padded = format!("{:0>WIDTH$}{s:0>WIDTH$}", rand); // <WIDTH> padding
    let encrypted = alphabet.encrypt(&secret_key, nonce, &padded).unwrap();

    // add extra bit from 1-9 to ensure number doesn't begin with '0'
    format!("{new_sign}{}{encrypted}", rand::random_range(1..=9u8))
}

pub fn decrypt_integral(secret_key: &[u8], nonce: &[u8], mut s: &str) -> String {
    let negative = if s.starts_with('-') {
        s = &s[1..];
        true
    } else {
        false
    };

    let alphabet = Alphabet::numeric();

    // remove first digit
    let unpadded = &s[1..];

    let decrypted = alphabet.decrypt(&secret_key, nonce, &unpadded).unwrap();

    let rand = decrypted.chars().nth(WIDTH - 1).unwrap();

    //eprintln!("[dec]: rand = {rand}");

    let new_sign = if negative ^ (rand.to_digit(10).unwrap() % 2 == 0) {
        "-"
    } else {
        ""
    };

    let unpadded2 = &decrypted[WIDTH..]; // remove <WIDTH> digit padding

    let trimmed = unpadded2.trim_start_matches('0');
    // special case for decrypting '0'
    format!(
        "{new_sign}{}",
        match trimmed.is_empty() {
            true => "0",
            false => trimmed,
        }
    )
}

pub fn encrypt_fractional(secret_key: &[u8], nonce: &[u8], s: &str) -> String {
    let alphabet = Alphabet::numeric();

    let mut rng = rand::rng();

    let right_padded = format!(
        "{s:0<WIDTH$}{:0<WIDTH$}",
        rng.random_range(1..10u64.pow(WIDTH_U32))
    );
    let encrypted = alphabet.encrypt(&secret_key, nonce, &right_padded).unwrap();

    // add extra bit from 1-9 to ensure number doesn't end in '0'
    format!("{encrypted}{}", rand::random_range(1..=9u8))
}

pub fn decrypt_fractional(secret_key: &[u8], nonce: &[u8], s: &str) -> String {
    let alphabet = Alphabet::numeric();

    // remove last digit
    let unpadded = &s[0..s.len() - 1];

    let decrypted = alphabet.decrypt(&secret_key, nonce, &unpadded).unwrap();
    let unpadded2 = &decrypted[0..s.len() - 1 - WIDTH]; // remove <WIDTH> digit padding

    let trimmed = unpadded2.trim_end_matches('0');

    match trimmed.is_empty() {
        true => "0",
        false => trimmed,
    }
    .to_string()
}

use cloudproof_fpe::core::Alphabet;
use rand::Rng;

const WIDTH: usize = 8;
const WIDTH_U32: u32 = 8;

pub fn encrypt_integral(secret_key: &[u8], nonce: &[u8], mut s: &str) -> String {
    assert!(!s.trim_start_matches('-').starts_with("0"));

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

    let padded = format!("{:0>WIDTH$}{s:0>WIDTH$}", rand); // <WIDTH> padding
    let encrypted = alphabet
        .encrypt(&secret_key, nonce, &padded)
        .expect("Should properly encrypt");

    // add extra bit from 1-9 to ensure number doesn't begin with '0'
    let res = format!("{new_sign}{}{encrypted}", rand::random_range(1..=9u8));

    assert!(!res.trim_start_matches('-').starts_with('0'));

    res
}

pub fn decrypt_integral(secret_key: &[u8], nonce: &[u8], mut s: &str) -> String {
    assert!(!s.trim_start_matches('-').starts_with('0'));

    let negative = if s.starts_with('-') {
        s = &s[1..];
        true
    } else {
        false
    };

    let alphabet = Alphabet::numeric();

    // remove first digit
    let unpadded = &s[1..];

    let decrypted = alphabet
        .decrypt(&secret_key, nonce, &unpadded)
        .expect("Should properly decrypt");

    let rand = decrypted
        .chars()
        .nth(WIDTH - 1)
        .expect("Number post-decryption should be at least more than WIDTH characters");

    //eprintln!("[dec]: rand = {rand}");

    let new_sign = if negative ^ (rand.to_digit(10).unwrap() % 2 == 0) {
        "-"
    } else {
        ""
    };

    let unpadded2 = &decrypted[WIDTH..]; // remove <WIDTH> digit padding

    let trimmed = unpadded2.trim_start_matches('0');
    // special case for decrypting '0'
    let res = format!(
        "{new_sign}{}",
        match trimmed.is_empty() {
            true => "0",
            false => trimmed,
        }
    );

    assert!(!s.trim_start_matches('-').starts_with('0'));

    res
}

pub fn encrypt_fractional(secret_key: &[u8], nonce: &[u8], s: &str) -> String {
    assert!(!s.ends_with('0'));

    let alphabet = Alphabet::numeric();

    let mut rng = rand::rng();

    let right_padded = format!(
        "{s:0<WIDTH$}{:0<WIDTH$}",
        rng.random_range(1..10u64.pow(WIDTH_U32))
    );
    let encrypted = alphabet
        .encrypt(&secret_key, nonce, &right_padded)
        .expect("Should properly encrypt");

    // add extra bit from 1-9 to ensure number doesn't end in '0'
    let res = format!("{encrypted}{}", rand::random_range(1..=9u8));

    assert!(!res.ends_with('0'));

    res
}

pub fn decrypt_fractional(secret_key: &[u8], nonce: &[u8], s: &str) -> String {
    assert!(!s.ends_with('0'));
    let alphabet = Alphabet::numeric();

    // remove last digit
    let unpadded = &s[0..s.len() - 1];

    let decrypted = alphabet
        .decrypt(&secret_key, nonce, &unpadded)
        .expect("Should properly decrypt");
    let unpadded2 = &decrypted[0..s.len() - 1 - WIDTH]; // remove <WIDTH> digit padding

    let trimmed = unpadded2.trim_end_matches('0');

    let res = match trimmed.is_empty() {
        true => "0",
        false => trimmed,
    }
    .to_string();

    assert!(!res.ends_with('0'));

    res
}

#[cfg(test)]
mod tests {
    use rand::TryRngCore;
    use rand_core::OsRng;

    use crate::utils::KEY_LEN;
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn integer_encrypt_then_decrypt() {
        for _ in 0..1000 {
            let mut key = [0; KEY_LEN];
            let mut nonce = [0; KEY_LEN];
            OsRng.try_fill_bytes(&mut key).unwrap();
            OsRng.try_fill_bytes(&mut nonce).unwrap();

            let int: u64 = rand::random();
            let original = int.to_string();

            let encrypted = encrypt_integral(&key, &nonce, &original);

            assert_ne!(original, encrypted);

            let decrypted = decrypt_integral(&key, &nonce, &encrypted);

            assert_eq!(original, decrypted);
        }
    }

    #[test]
    fn fractional_encrypt_then_decrypt() {
        for _ in 0..1000 {
            let mut key = [0; KEY_LEN];
            let mut nonce = [0; KEY_LEN];
            OsRng.try_fill_bytes(&mut key).unwrap();
            OsRng.try_fill_bytes(&mut nonce).unwrap();

            let int: f64 = rand::random();
            let original = int.to_string().split_once(".").unwrap().1.to_string();

            let encrypted = encrypt_fractional(&key, &nonce, &original);

            assert_ne!(original, encrypted);

            let decrypted = decrypt_fractional(&key, &nonce, &encrypted);

            assert_eq!(original, decrypted);
        }
    }
}

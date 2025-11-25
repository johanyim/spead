pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

use argon2::Argon2;

/// key derivation function
pub fn kdf(password: &str) -> argon2::Result<[u8; KEY_LEN]> {
    let password = password.as_bytes();

    // no salt
    let salt = [0u8; SALT_LEN];

    let mut output_key_material = [0u8; KEY_LEN]; // Can be any desired size
    Argon2::default().hash_password_into(password, &salt, &mut output_key_material)?;
    Ok(output_key_material)
}

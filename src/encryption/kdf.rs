use argon2::Argon2;

use super::{KEY_LEN, SALT_LEN};

pub fn generate(password: String) -> argon2::Result<[u8; KEY_LEN]> {
    let password = password.as_bytes();

    // no salt
    let salt = [0u8; SALT_LEN];

    let mut output_key_material = [0u8; KEY_LEN]; // Can be any desired size
    Argon2::default().hash_password_into(&password, &salt, &mut output_key_material)?;
    Ok(output_key_material)
}

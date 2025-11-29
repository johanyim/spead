mod error;
mod numeric;
pub mod prelude;
pub mod utils;
use std::str::FromStr;

use cloudproof_fpe::core::Alphabet;
use serde_json::Number;

use crate::utils::KEY_LEN;
#[derive(Debug, Default)]
pub enum Method {
    #[default]
    Encrypt,
    Decrypt,
}

#[derive(Debug, Default)]
pub enum FileFormat {
    #[default]
    Json,
}

#[derive(Debug, Default)]
pub struct Spead {
    //val: serde_json::Value,
    pub(crate) key: [u8; KEY_LEN],
    //method: Method,
    //_format: FileFormat,
    pub(crate) include_keys: bool,
    pub(crate) max_depth: u32,
}

#[allow(non_snake_case)]
impl Spead {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn secret_key(mut self, secret_key: [u8; KEY_LEN]) -> Self {
        self.key = secret_key;
        self
    }

    pub fn password(mut self, password: &str) -> Self {
        self.key = utils::kdf(password).expect("Should derive key from password");
        self
    }

    pub fn include_keys(mut self, include_keys: bool) -> Self {
        self.include_keys = include_keys;
        self
    }

    pub fn max_depth(mut self, max_depth: u32) -> Self {
        self.max_depth = max_depth;
        self
    }

    pub fn encrypt(self, value: &mut serde_json::Value) {
        self.traverse(value, b"#", 1, &Method::Encrypt);
    }

    pub fn decrypt(self, value: &mut serde_json::Value) {
        self.traverse(value, b"#", 1, &Method::Decrypt);
    }

    fn traverse(
        &self,
        node: &mut serde_json::Value,
        current_pointer: &[u8],
        depth: u32,
        method: &Method,
    ) {
        match node {
            serde_json::Value::Number(num) => {
                let s = num.as_str();

                // NOTE: first number is random, rest is deterministic
                let enc = match s.split_once('.') {
                    None => match method {
                        Method::Encrypt => {
                            numeric::encrypt_integral(&self.key, current_pointer, &s)
                        }
                        Method::Decrypt => {
                            numeric::decrypt_integral(&self.key, current_pointer, &s)
                        }
                    },

                    Some((left, right)) => {
                        let left_enc = match method {
                            Method::Encrypt => numeric::encrypt_integral(
                                &self.key,
                                &[current_pointer, &[0]].concat(),
                                &left,
                            ),
                            Method::Decrypt => numeric::decrypt_integral(
                                &self.key,
                                &[current_pointer, &[0]].concat(),
                                &left,
                            ),
                        };

                        let right_enc = match method {
                            Method::Encrypt => numeric::encrypt_fractional(
                                &self.key,
                                &[current_pointer, &[1]].concat(),
                                &right,
                            ),
                            Method::Decrypt => numeric::decrypt_fractional(
                                &self.key,
                                &[current_pointer, &[1]].concat(),
                                &right,
                            ),
                        };

                        left_enc + "." + &right_enc
                    }
                };

                *node = serde_json::Value::Number(Number::from_str(&enc).unwrap())
            }
            serde_json::Value::String(s) => {
                let alphabet = Alphabet::utf();
                match method {
                    Method::Encrypt => {
                        let encrypted = alphabet.encrypt(&self.key, current_pointer, &s).unwrap();
                        *node = serde_json::Value::String(encrypted);
                    }
                    Method::Decrypt => {
                        let decrypted = alphabet.decrypt(&self.key, current_pointer, &s).unwrap();
                        if decrypted.starts_with("json") {
                            match serde_json::from_str(&decrypted[4..]) {
                                Ok(obj) => {
                                    *node = serde_json::Value::Object(obj);
                                    return;
                                }
                                Err(_) => {}
                            }
                        }
                        *node = serde_json::Value::String(decrypted)
                    }
                };
            }
            serde_json::Value::Array(values) => {
                for (val, i) in values.iter_mut().zip(0u8..) {
                    self.traverse(val, &[current_pointer, &[i]].concat(), depth, method);
                }
            }

            serde_json::Value::Object(map) => {
                // TODO: decrypt finite depth encrypted file
                if self.max_depth < depth && self.max_depth > 0 {
                    let alphabet = Alphabet::utf();
                    let s = String::from("json") + &serde_json::to_string(map).unwrap();
                    *node = serde_json::Value::String(
                        alphabet.encrypt(&self.key, current_pointer, &s).unwrap(),
                    );
                } else {
                    for (k, v) in map {
                        self.traverse(
                            v,
                            &[current_pointer, k.as_bytes()].concat(),
                            depth + 1,
                            method,
                        )
                    }
                }
            }
            _ => {}
        }
    }
}

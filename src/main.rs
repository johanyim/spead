mod error;
mod numeric;
mod prelude;
mod utils;

use std::{
    io::{stdin, Read, Write},
    str::FromStr,
};

use camino::Utf8PathBuf;
use clap::{arg, error::ErrorKind, CommandFactory, Parser};
use cloudproof_fpe::core::Alphabet;
use prelude::*;
use serde::Serialize;
use serde_json::Number;
use utils::KEY_LEN;

#[derive(Parser, Debug)]
#[command(version, long_about)]
struct Cli {
    #[arg(value_name = "file")]
    input: Option<Utf8PathBuf>,

    /// Encryption/Decryption key as a path to a file
    #[arg(short = 'k', long, value_name = "file")]
    password_file: Option<Utf8PathBuf>,

    /// Encryption/Decryption key as an argument
    #[arg(short, long, value_name = "password")]
    password: Option<String>,

    /// Decrypt rather than encrypting
    #[arg(short, long, default_value_t = false)]
    decrypt: bool,

    // TODO:
    /// Encrypt/Decrypt keys as well as values
    #[arg(short = 'K', long, default_value_t = false)]
    include_keys: bool,

    ///// Modify the file in-place, rather than printing to stdout
    //#[arg(short, long)]
    //in_place: bool,
    /// Modify the file in-place, rather than printing to stdout
    #[arg(short, long)]
    in_place: bool,

    /// Maximum recursion depth to encrypt while preserving encryption, rather than encrypting the
    /// whole value (0 = no depth limit)
    #[arg(short = 'L', long, default_value_t = 0)]
    max_depth: u32,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // 1.: determine the source of the input
    let mut val: serde_json::Value = match cli.input {
        Some(ref file) if file.exists() => {
            // open file and read to value
            let f = std::fs::File::open(file).unwrap();
            let mut reader = std::io::BufReader::new(f);

            // TODO: determine the type of file

            // json
            serde_json::from_reader(&mut reader).unwrap()
        }
        Some(file) => {
            let mut cmd = Cli::command();
            cmd.error(
                ErrorKind::ValueValidation,
                format!("file not found: {}", file),
            )
            .exit()
        }
        None => {
            // TODO: determine the type of file

            if atty::is(atty::Stream::Stdin) {
                // Stdin is from a terminal → not piped
                let mut cmd = Cli::command();
                cmd.error(
                    ErrorKind::ValueValidation,
                    "no input provided (expected file or piped stdin)",
                )
                .exit();
            }

            serde_json::from_reader(stdin().lock()).unwrap()
        }
    };

    // 2.: Password
    let password = match (cli.password.as_ref(), cli.password_file.as_ref()) {
        (Some(_), Some(_)) => {
            let mut cmd = Cli::command();
            cmd.error(
                ErrorKind::ArgumentConflict,
                format!("unsure whether to use raw key or key from file"),
            )
            .exit();
        }
        (Some(p), None) => p.to_string(),
        (None, Some(f)) => std::fs::read_to_string(f).expect("Failed to read file"),
        (None, None) => {
            write!(std::io::stderr(), "Password: ").unwrap();
            std::io::stderr().flush().unwrap();
            let password = rpassword::read_password().unwrap();

            write!(std::io::stderr(), "Re-type: ").unwrap();
            std::io::stderr().flush().unwrap();

            let retype = rpassword::read_password().unwrap();
            if password != retype {
                eprintln!("\nPasswords did not match.");
                std::process::exit(1);
            }

            password.to_string()
        }
    };

    // 3.: key derivation
    let secret_key = utils::kdf(password.to_string())?;

    let method = match cli.decrypt {
        true => Spead::JsonDecrypt,
        false => Spead::JsonEncrypt,
    };

    // 4.: encryption
    method.traverse(&cli, &mut val, b"#", secret_key, 1);

    let output = serde_json::to_string(&val).unwrap();

    std::io::stdout().write_all(output.as_bytes()).unwrap();

    Ok(())
}

pub enum Spead {
    JsonEncrypt,
    JsonDecrypt,
}

impl Spead {
    // NOTE: using JSON RFC6901 to create unique nonces on a per-struct basis
    fn traverse(
        &self,
        cli: &Cli,
        node: &mut serde_json::Value,
        current_pointer: &[u8],
        secret_key: [u8; KEY_LEN],
        depth: u32,
    ) {
        //println!("{current_pointer}");
        match node {
            serde_json::Value::Number(num) => {
                //println!("{}", current_pointer);
                let s = num.as_str();

                // NOTE: first number is random, rest is deterministic
                let enc = match s.split_once('.') {
                    None => match self {
                        Spead::JsonEncrypt => {
                            numeric::encrypt_integral(&secret_key, current_pointer, &s)
                        }
                        Spead::JsonDecrypt => {
                            numeric::decrypt_integral(&secret_key, current_pointer, &s)
                        }
                    },

                    Some((left, right)) => {
                        let left_enc = match self {
                            Spead::JsonEncrypt => numeric::encrypt_integral(
                                &secret_key,
                                &[current_pointer, &[0]].concat(),
                                &left,
                            ),
                            Spead::JsonDecrypt => numeric::decrypt_integral(
                                &secret_key,
                                &[current_pointer, &[0]].concat(),
                                &left,
                            ),
                        };

                        let right_enc = match self {
                            Spead::JsonEncrypt => numeric::encrypt_fractional(
                                &secret_key,
                                &[current_pointer, &[1]].concat(),
                                &right,
                            ),
                            Spead::JsonDecrypt => numeric::decrypt_fractional(
                                &secret_key,
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
                match self {
                    Spead::JsonEncrypt => {
                        let encrypted = alphabet.encrypt(&secret_key, current_pointer, &s).unwrap();
                        *node = serde_json::Value::String(encrypted);
                    }
                    Spead::JsonDecrypt => {
                        let decrypted = alphabet.decrypt(&secret_key, current_pointer, &s).unwrap();
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
                    self.traverse(
                        cli,
                        val,
                        &[current_pointer, &[i]].concat(),
                        secret_key,
                        depth,
                    );
                }
            }

            serde_json::Value::Object(map) => {
                // TODO: decrypt finite depth encrypted file
                if cli.max_depth < depth && cli.max_depth > 0 {
                    let alphabet = Alphabet::utf();
                    let s = String::from("json") + &serde_json::to_string(map).unwrap();
                    *node = serde_json::Value::String(
                        alphabet.encrypt(&secret_key, current_pointer, &s).unwrap(),
                    );
                } else {
                    for (k, v) in map {
                        self.traverse(
                            cli,
                            v,
                            &[current_pointer, k.as_bytes()].concat(),
                            secret_key,
                            depth + 1,
                        )
                    }
                }
            }
            _ => {}
        }
    }
}

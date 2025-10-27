mod encryption;
mod error;
mod prelude;

use std::{io::Write, str::FromStr};

use camino::Utf8PathBuf;
use clap::{arg, error::ErrorKind, CommandFactory, Parser};
use cloudproof_fpe::core::Alphabet;
use encryption::{kdf, KEY_LEN};
use prelude::*;
use serde::Serialize;
use serde_json::Number;

#[derive(clap::ValueEnum, Clone, Default, Debug, Serialize)]
enum EncryptionMethod {
    #[default]
    AES,
    Chacha20,
    XOR,
}

///
#[derive(Parser, Debug)]
#[command(version, long_about)]
struct Cli {
    #[arg(required = true, value_name = "file")]
    input: Option<Utf8PathBuf>,

    /// Which encryption method to use
    #[arg(short, long, value_enum, default_value_t)]
    method: EncryptionMethod,

    /// Encryption/Decryption key as a path to a file
    #[arg(short, long, value_name = "path")]
    key: Option<Utf8PathBuf>,

    /// Encryption/Decryption key as an argument
    #[arg(short, long, value_name = "key")]
    raw_key: Option<String>,

    /// Modify the file in-place, rather than printing to stdout
    #[arg(short, long)]
    in_place: bool,

    /// Decrypt rather than encrypting
    #[arg(short, long, default_value_t = false)]
    decrypt: bool,

    /// Repeat n times
    #[arg(short = 'n', long, default_value_t = 1, value_name = "n")]
    repeat: u16,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // check the input exists
    if let Some(ref input) = cli.input
        && !input.exists()
    {
        let mut cmd = Cli::command();
        cmd.error(
            ErrorKind::ValueValidation,
            format!("file not found: {}", input),
        )
        .exit();
    }

    if cli.key.is_some() && cli.raw_key.is_some() {}

    let password = match (cli.raw_key, cli.key) {
        (Some(_), Some(_)) => {
            let mut cmd = Cli::command();
            cmd.error(
                ErrorKind::ArgumentConflict,
                format!("unsure whether to use raw key or key from file"),
            )
            .exit();
        }
        (Some(p), None) => p,
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

            password
        }
    };

    // open file and read to value
    let file = std::fs::File::open(cli.input.unwrap()).unwrap();
    let mut reader = std::io::BufReader::new(file);

    // TODO: determine the type of file

    // json
    let mut val: serde_json::Value = serde_json::from_reader(&mut reader).unwrap();

    // key derivation
    let secret_key = encryption::kdf::generate(password)?;

    //println!("{val:#?}");

    let method = match cli.decrypt {
        true => Spead::JsonDecrypt,
        false => Spead::JsonEncrypt,
    };

    method.traverse(&mut val, String::from("#"), secret_key);

    let output = serde_json::to_string_pretty(&val).unwrap();

    std::io::stdout()
        .write_all(format!("{output}").as_bytes())
        .unwrap();

    //do the encryption!
    Ok(())
}

pub enum Spead {
    JsonEncrypt,
    JsonDecrypt,
}

impl Spead {
    // NOTE: using RFC6901 to create unique nonces on a per-struct basis
    fn traverse(
        &self,
        node: &mut serde_json::Value,
        current_pointer: String,
        secret_key: [u8; KEY_LEN],
    ) {
        match node {
            serde_json::Value::Number(num) => {
                //println!("{}", current_pointer);
                let mut s = num.as_str();

                // TODO: encrypt sign
                let sign = if s.starts_with('-') {
                    s = &s[1..];
                    "-"
                } else {
                    ""
                }
                .to_string();

                let alphabet = Alphabet::numeric();
                //let alphabet = Alphabet::try_from("10").unwrap();
                //let x = sign
                //    + &alphabet
                //        .decrypt(&secret_key, b"abc", &s)
                //        .unwrap()
                //        .trim_start_matches('0');
                // IDEA: split by first, rest?
                // NOTE: may be all zeros (10^-16)
                let enc = match s.split_once('.') {
                    None => {
                        match self {
                            Spead::JsonEncrypt => {
                                let padded = format!("{s:0>12}");
                                let encrypted = alphabet
                                    .encrypt(&secret_key, current_pointer.as_bytes(), &padded)
                                    .unwrap();
                                format!("1{encrypted}")
                            }
                            Spead::JsonDecrypt => {
                                //let padded = format!("{s:0>30}");
                                let unpadded = &s[1..];
                                let decrypted = alphabet
                                    .decrypt(&secret_key, current_pointer.as_bytes(), &unpadded)
                                    .unwrap();

                                decrypted.trim_start_matches('0').to_string()
                                //format!()

                                //format!("1{encrypted}");
                            }
                        }

                        //encrypted.trim_start_matches('0').to_string()
                    }
                    Some((left, right)) => {
                        //let left_padded = format!("{left:0>12}"); // appending
                        let right_padded = format!("{right:0<12}");

                        // json pointer
                        let left_pointer = format!("{current_pointer}/left");
                        let right_pointer = format!("{current_pointer}/right");

                        let left_enc = match self {
                            Spead::JsonEncrypt => {
                                let left_padded = format!("{left:0>12}");
                                let encrypted = alphabet
                                    .encrypt(&secret_key, left_pointer.as_bytes(), &left_padded)
                                    .unwrap();
                                format!("1{encrypted}")
                            }
                            Spead::JsonDecrypt => {
                                //let padded = format!("{s:0>30}");
                                let unpadded = &left[1..];
                                let decrypted = alphabet
                                    .decrypt(&secret_key, left_pointer.as_bytes(), &unpadded)
                                    .unwrap();

                                decrypted.trim_start_matches('0').to_string()
                                //format!()

                                //format!("1{encrypted}");
                            }
                        };

                        // TODO:
                        let right_enc = match self {
                            Spead::JsonEncrypt => alphabet
                                // TODO: differentiate right and right since they use the same nonce
                                .encrypt(&secret_key, right_pointer.as_bytes(), &right_padded)
                                .unwrap(),
                            Spead::JsonDecrypt => alphabet
                                // TODO: differentiate right and right since they use the same nonce
                                .decrypt(&secret_key, right_pointer.as_bytes(), &right_padded)
                                .unwrap(),
                        };

                        format!("{}.{}", left_enc, right_enc.trim_end_matches('0'))
                    }
                };

                //let Some((left, right)) = s.split_once(".").unwrap();
                //let left = &format!("{s:0>16}");

                //println!("{x}");
                let result = sign + &enc;
                //println!("{result}");

                *node = serde_json::Value::Number(Number::from_str(&result).unwrap())
            }
            serde_json::Value::String(s) => {
                //println!("{}", current_pointer);
                let alphabet = Alphabet::utf();
                let x = match self {
                    Spead::JsonEncrypt => alphabet
                        .encrypt(&secret_key, current_pointer.as_bytes(), &s)
                        .unwrap(),
                    Spead::JsonDecrypt => alphabet
                        .decrypt(&secret_key, current_pointer.as_bytes(), &s)
                        .unwrap(),
                };
                *node = serde_json::Value::String(x);
            }
            serde_json::Value::Array(values) => {
                for (i, val) in values.iter_mut().enumerate() {
                    self.traverse(val, format!("{current_pointer}/{i}"), secret_key);
                }
            }
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    //println!("{k}");
                    self.traverse(v, format!("{current_pointer}/{k}"), secret_key)
                }
            }
            _ => {}
        }
    }
}

#[test]
fn enc_dec_number() {
    for i in 0..100 {
        let password = i.to_string();
        let key = kdf::generate(password).unwrap();

        let plaintext: serde_json::Value =
            serde_json::from_str(include_str!("../file.json")).unwrap();
        let mut encrypted = plaintext.clone();

        Spead::JsonEncrypt.traverse(&mut encrypted, String::from("#"), key);

        Spead::JsonDecrypt.traverse(&mut encrypted, String::from("#"), key);

        assert_eq!(encrypted, plaintext);
    }
}

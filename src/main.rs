mod encryption;
mod error;
mod prelude;

use std::str::FromStr;

use camino::Utf8PathBuf;
use clap::{arg, error::ErrorKind, CommandFactory, Parser};
use prelude::*;
use scanpw::scanpw;
use serde::Serialize;

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
    println!("{cli:#?}");

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
        (None, Some(f)) => std::fs::read_to_string(f).unwrap(),
        (None, None) => {
            let password = scanpw!("Password: ");
            if password != scanpw!("\nRe-type : ") {
                println!("\nPasswords did not match.");
                std::process::exit(1);
            }

            password
        }
    };

    let file = std::fs::File::open(cli.input.unwrap()).unwrap();

    let reader = std::io::BufReader::new(file);
    let s = std::io::read_to_string(reader).unwrap();

    // determine the type of the file

    // TODO: consider from_reader
    let mut val: serde_json::Value = serde_json::from_str(&s).unwrap();

    // key derivation
    let secret_key = encryption::kdf::generate(password)?;

    for (_k, v) in val.as_object_mut().unwrap() {
        let mut bytes: Vec<u8> = Vec::new();
        serde_json::to_writer(&mut bytes, &v).unwrap();

        let new_bytes = encryption::chacha::encrypt(bytes, secret_key);
        *v = new_bytes.into()
    }

    let output = serde_json::to_string(&val).unwrap();

    println!("{output}");
    //do the encryption!
    Ok(())
}

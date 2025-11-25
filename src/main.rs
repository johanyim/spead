use std::io::{stdin, Write};

use camino::Utf8PathBuf;
use clap::{arg, error::ErrorKind, CommandFactory, Parser};
use spead::prelude::*;
use spead::{utils, Spead};

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

    /// Maximum recursion depth to encrypt while preserving encryption, rather than encrypting the
    /// whole value (0 = no depth limit)
    #[arg(short = 'L', long, default_value_t = 0)]
    max_depth: u32,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // TODO: determine file format
    let _format = spead::FileFormat::Json;

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
    let secret_key = utils::kdf(&password)?;

    // 4.: creating the encryption/decryption struct
    let spead = Spead::new()
        .secret_key(secret_key)
        .max_depth(cli.max_depth)
        .include_keys(cli.include_keys);

    match cli.decrypt {
        true => spead.decrypt(&mut val),
        false => spead.encrypt(&mut val),
    }

    // 5.: output to stdout
    let output = serde_json::to_string(&val).unwrap();
    std::io::stdout().write_all(output.as_bytes()).unwrap();

    Ok(())
}

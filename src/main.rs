use camino::Utf8PathBuf;
use clap::{arg, error::ErrorKind, CommandFactory, Parser};
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

fn main() {
    let cli = Cli::parse();
    println!("{cli:#?}");

    // check the input exists
    if let Some(input) = cli.input
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
}

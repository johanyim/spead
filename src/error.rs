use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Argon2(String),
    //#[error("Password unable to hash")]
    //Stdio(#[from] std::io::Error),
}

impl From<argon2::Error> for Error {
    fn from(value: argon2::Error) -> Self {
        match value {
            _ => Error::Argon2("Could not hash password".to_string()),
        }
    }
}

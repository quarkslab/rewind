
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GenericError {
    FileError(#[from]std::io::Error),
    SerdeError(#[from]serde_json::Error),
    Generic(String),

}

impl std::fmt::Display for GenericError {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "error: {:?}", self)
    }

}

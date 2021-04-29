
//! Error handling

use thiserror::Error;

/// Error
#[derive(Debug, Error)]
pub enum GenericError {
    /// File error
    FileError(#[from]std::io::Error),
    /// Serde error
    SerdeError(#[from]serde_json::Error),
    /// Yaml error
    YamlError(#[from]serde_yaml::Error),
    /// Unspecified error
    Generic(String),

}

impl std::fmt::Display for GenericError {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "error: {:?}", self)
    }

}

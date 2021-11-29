
//! Error handling

use thiserror::Error;

/// Error
#[derive(Debug, Error)]
pub enum GenericError {
    /// File error
    #[error(transparent)]
    FileError(#[from] std::io::Error),
    /// Serde error
    #[error(transparent)]
    SerdeError(#[from]serde_json::Error),
    /// Yaml error
    #[error(transparent)]
    YamlError(#[from]serde_yaml::Error),
    /// Unspecified error
    #[error("error: {}", .0)]
    Generic(String),

}

// impl std::fmt::Display for GenericError {

//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         write!(f, "GenericError({:?})", self)
//     }

// }

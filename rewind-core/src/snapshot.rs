
//! Snapshot

use thiserror::Error;

/// Snapshot error
#[derive(Debug, Error)]
pub enum SnapshotError {
    /// Unspecified error
    #[error("generic error {}", .0)]
    GenericError(String),

    /// Missing page in snapshot
    #[error("missing page {:x}", .0)]
    MissingPage(u64),

    /// IO error
    #[error("File error: {:?}", .0)]
    FileError(#[from]std::io::Error)

}

/// Snapshot interface
pub trait Snapshot {

    /// Read physical address from snapshot
    fn read_gpa(&self, gpa: u64, buffer: &mut [u8]) -> Result<(), SnapshotError>;

    /// Get cr3
    fn get_cr3(&self) -> u64;

    /// Get module list address
    fn get_module_list(&self) -> u64;
}


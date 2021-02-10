
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("generic error {}", .0)]
    GenericError(String),

    #[error("missing page {:x}", .0)]
    MissingPage(u64),

    #[error(transparent)]
    FileError(#[from]std::io::Error)

}


pub trait Snapshot {

    fn read_gpa(&self, gpa: u64, buffer: &mut [u8]) -> Result<(), SnapshotError>;

}


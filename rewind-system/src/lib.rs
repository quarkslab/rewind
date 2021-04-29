
#![warn(missing_docs)]

//! System support.
//!
//! Mainly used to load binaries and PE to resolve symbols

pub use pdbstore::{PdbStore, StoreError};
pub use system::{System, SystemError};

mod pdbstore;
mod pe;
mod system;
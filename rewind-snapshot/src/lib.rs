
#![warn(missing_docs)]

//! Snapshot support.
//!
//! Support full kernel dump and bitmap kernel dump


use dump::ParserError;
use rewind_core::snapshot::{Snapshot, SnapshotError};
use rewind_core::mem::{self, X64VirtualAddressSpace, VirtMemError};

mod dump;

/// Dump-based snapshot
pub struct DumpSnapshot <'a> {
    dump: dump::RawDmp<'a>,
}

impl <'a> DumpSnapshot <'a> {

    /// Constructor
    pub fn new(buffer: &'a [u8]) -> Result<Self, SnapshotError> {
        let dump = dump::RawDmp::parse(buffer)?;

        let snapshot = DumpSnapshot {
            dump,
        };

        Ok(snapshot)

    }

    /// Get cr3
    pub fn get_cr3(&self) -> u64 {
        self.dump.cr3()
    }

    /// Get module list address
    pub fn get_module_list(&self) -> u64 {
        self.dump.header.ps_loaded_module_list
    }

}

impl <'a> Snapshot for DumpSnapshot <'a> {

    fn read_gpa(&self, gpa: u64, buffer: &mut [u8]) -> Result<(), SnapshotError> {
        let base = gpa & !0xfff;
        let offset = (gpa & 0xfff) as usize;

        let available = 0x1000 - offset;
        let size = std::cmp::min(available, buffer.len());

        match self.dump.physmem.get(&base) {
            Some(b) => buffer[..size].clone_from_slice(&b[offset..offset+size]),
            None => {
                return Err(SnapshotError::MissingPage(base))
            }
        }
        Ok(())
    }

}

impl <'a> X64VirtualAddressSpace for DumpSnapshot <'a> {

    fn read_gpa(&self, gpa: mem::Gpa, buf: &mut [u8]) -> Result<(), VirtMemError> {
        Snapshot::read_gpa(self, gpa, buf)
            .map_err(|e| VirtMemError::GenericError(e.to_string()))
    }

    fn write_gpa(&mut self, _gpa: mem::Gpa, _data: &[u8]) -> Result<(), VirtMemError> {
        Err(VirtMemError::GenericError("Read-only snapshot".to_string()))
    }

}

impl From<ParserError> for SnapshotError {

    fn from(e: ParserError) -> Self {
        SnapshotError::GenericError(e.to_string())
    }
}

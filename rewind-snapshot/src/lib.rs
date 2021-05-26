
#![warn(missing_docs)]

//! Snapshot support.
//!
//! Support full kernel dump and bitmap kernel dump


use std::{cell::RefCell, io::{Read, Write, BufWriter}};

use serde::{Serialize, Deserialize};

use dump::ParserError;

use rewind_core::{error::GenericError, snapshot::{Snapshot, SnapshotError}};
use rewind_core::mem::{self, X64VirtualAddressSpace, VirtMemError};

mod dump;

/// Dump-based snapshot
pub struct DumpSnapshot <'a> {
    dump: dump::RawDmp<'a>,
    pages: std::cell::RefCell<Vec<u64>>,
}

impl <'a> DumpSnapshot <'a> {

    /// Constructor
    pub fn new(buffer: &'a [u8]) -> Result<Self, SnapshotError> {
        let dump = dump::RawDmp::parse(buffer)?;

        let snapshot = DumpSnapshot {
            dump,
            pages: std::cell::RefCell::new(Vec::new()),
        };

        Ok(snapshot)

    }

    /// Save loaded physical pages to disk
    // FIXME: interior mutability for now, don't want to change prototypes, will need to be changed someday
    pub fn save<P>(&self, path: P) -> Result<(), SnapshotError>
    where P: AsRef<std::path::Path> {
        let path = path.as_ref().to_path_buf();
        let context = SnapshotContext {
            cr3: self.get_cr3(),
            ps_loaded_module_list: self.get_module_list(),
        };
        context.save(path.join("snapshot.json")).map_err(|e| { 
            SnapshotError::GenericError(e.to_string())
        })?;

        let snapshot = FileSnapshot::new(path)?;
        let pages: Vec<u64> = self.pages.borrow().iter().cloned().collect();
        for page in pages.iter() {
            let mut data = vec![0u8; 0x1000];
            Snapshot::read_gpa(self, *page, &mut data)?;
            snapshot.write_gpa(*page, &data)?;
        }
        Ok(())
    }


}

impl <'a> Snapshot for DumpSnapshot <'a> {

    fn read_gpa(&self, gpa: u64, buffer: &mut [u8]) -> Result<(), SnapshotError> {
        let base = gpa & !0xfff;
        let offset = (gpa & 0xfff) as usize;

        let available = 0x1000 - offset;
        let size = std::cmp::min(available, buffer.len());

        match self.dump.physmem.get(&base) {
            Some(b) => {
                buffer[..size].clone_from_slice(&b[offset..offset+size]);
                self.pages.borrow_mut().push(base);
            }
            None => {
                return Err(SnapshotError::MissingPage(base))
            }
        }
        Ok(())
    }

    fn get_cr3(&self) -> u64 {
        self.dump.cr3()
    }

    fn get_module_list(&self) -> u64 {
        self.dump.header.ps_loaded_module_list
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
/// User-controlled input
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct SnapshotContext {
    /// cr3
    pub cr3: u64,
    /// Head of modules
    pub ps_loaded_module_list: u64,
}

impl SnapshotContext {

    /// Serialize to json and save to disk
    pub fn save<P>(&self, path: P) -> Result<(), GenericError>
    where P: AsRef<std::path::Path>
    {
        let mut fp = BufWriter::new(std::fs::File::create(&path)?);
        let data = serde_json::to_vec_pretty(&self)?;
        fp.write_all(&data)?;
        Ok(())
    }

    /// Read from disk and deserialize
    pub fn load<P>(path: P) -> Result<Self, GenericError>
    where P: AsRef<std::path::Path>
    {
        let input_str = std::fs::read_to_string(&path)?;
        let input = serde_json::from_str(&input_str)?;
        Ok(input)
    }

}


/// File-based snapshot
#[derive(Default)]
pub struct FileSnapshot {
    path: std::path::PathBuf,
    context: SnapshotContext,
    cache: RefCell<mem::GpaManager>,
}

impl FileSnapshot {

    /// Constructor
    pub fn new<P>(path: P) -> Result<Self, SnapshotError>
    where P: Into<std::path::PathBuf>
    {
        let path = path.into();
        if !path.exists() {
            std::fs::create_dir(&path)?;
            std::fs::create_dir(path.join("mem"))?;
        }

        let context = SnapshotContext::load(path.join("snapshot.json"))
            .map_err(|e| { SnapshotError::GenericError(e.to_string()) })?;

        let cache = RefCell::new(mem::GpaManager::new());
        let file_snapshot = Self { path, context, cache };
        Ok(file_snapshot)
    }

    fn write_gpa(&self, gpa: u64, buffer: &[u8]) -> Result<(), SnapshotError> {
        let base = gpa & !0xfff;

        let filename = format!("{:016x}.bin", base);
        let path = self.path.join("mem").join(filename);
        let mut fp = std::fs::File::create(path)?;
        fp.write_all(buffer)?;
        Ok(())
    }

}

impl Snapshot for FileSnapshot {

    fn read_gpa(&self, gpa: u64, buffer: &mut [u8]) -> Result<(), SnapshotError> {
        let base = gpa & !0xfff;
        let offset = (gpa & 0xfff) as usize;

        let mut data = [0u8; 0x1000];
        let page_in_cache = self.cache.borrow().is_gpa_present(base);
        if page_in_cache {
            self.cache.borrow().read_gpa(base, &mut data)
                .map_err(|e| SnapshotError::GenericError(e.to_string()))?;
            buffer.copy_from_slice(&data[offset..offset+buffer.len()]);
            return Ok(())
        }

        let filename = format!("{:016x}.bin", base);
        let path = self.path.join("mem").join(filename);
        let mut fp = std::fs::File::open(path)?;
        fp.read_exact(&mut data)?;
        buffer.copy_from_slice(&data[offset..offset+buffer.len()]);
        self.cache.borrow_mut().add_page(base, data);

        Ok(())
    }

    fn get_cr3(&self) -> u64 {
        self.context.cr3
    }

    fn get_module_list(&self) -> u64 {
        self.context.ps_loaded_module_list
    }
}

/// Available snapshots
pub enum SnapshotKind <'a> {
    /// Kernel dump snapshots
    DumpSnapshot(DumpSnapshot<'a>),

    /// File-based snapshots
    FileSnapshot(FileSnapshot)
}

impl <'a> SnapshotKind <'a> {
    /// Save to disk memory pages read from snapshot
    pub fn save<P>(&self, path: P) -> Result<(), SnapshotError>
    where P: AsRef<std::path::Path> {
        match self {
            Self::DumpSnapshot(snapshot) => {
                snapshot.save(path)
            }
            _ => {
                Ok(())
            }
        }

    }
}

impl <'a> Snapshot for SnapshotKind<'a> {

    fn read_gpa(&self, gpa: u64, buffer: &mut [u8]) -> Result<(), SnapshotError> {
        match self {
            Self::DumpSnapshot(snapshot) => Snapshot::read_gpa(snapshot, gpa, buffer),
            Self::FileSnapshot(snapshot) => snapshot.read_gpa(gpa, buffer),
        }
    }

    fn get_cr3(&self) -> u64 {
        match self {
            Self::DumpSnapshot(snapshot) => snapshot.get_cr3(),
            Self::FileSnapshot(snapshot) => snapshot.get_cr3(),
        }
    }

    fn get_module_list(&self) -> u64 {
        match self {
            Self::DumpSnapshot(snapshot) => snapshot.get_module_list(),
            Self::FileSnapshot(snapshot) => snapshot.get_module_list(),
        }
    }
}

impl <'a> X64VirtualAddressSpace for SnapshotKind<'a> {

    fn read_gpa(&self, gpa: u64, buffer: &mut [u8]) -> Result<(), VirtMemError> {
        match self {
            Self::DumpSnapshot(snapshot) => Snapshot::read_gpa(snapshot, gpa, buffer).map_err(|e| VirtMemError::GenericError(e.to_string())),
            Self::FileSnapshot(snapshot) => Snapshot::read_gpa(snapshot, gpa, buffer).map_err(|e| VirtMemError::GenericError(e.to_string())),
        }
    }

    fn write_gpa(&mut self, _gpa: u64, _data: &[u8]) -> Result<(), VirtMemError> {
        Err(VirtMemError::GenericError("read-only snapshot".to_string()))
    }
}


impl From<ParserError> for SnapshotError {

    fn from(e: ParserError) -> Self {
        SnapshotError::GenericError(e.to_string())
    }
}

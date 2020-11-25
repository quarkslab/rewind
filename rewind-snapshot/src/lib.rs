
use anyhow::Result;
use memmap::{MmapOptions, Mmap};

use dmp;

use rewind_core::snapshot::Snapshot;
use rewind_core::mem::{self, X64VirtualAddressSpace};

#[macro_use]
extern crate log;

#[macro_use]
extern crate anyhow;


pub struct DumpSnapshot <'a> {

    pub dump: dmp::Dmp<'a>

}

impl <'a> DumpSnapshot <'a> {

    pub fn new(path: &std::path::PathBuf) -> Result<Self> {
        info!("parsing dump file");
        let fp = std::fs::File::open(path)?;
        let buffer = unsafe { MmapOptions::new().map(&fp)? };

        let static_ref: &'static Mmap = Box::leak(Box::new(buffer));
        let dump = dmp::Dmp::parse(&static_ref)?;
        // dump.dump();

        let snapshot = DumpSnapshot {
            dump: dump
        };
        Ok(snapshot)

    }

    pub fn get_cr3(&self) -> u64 {
        let header = &self.dump.raw_dmp.dmp_header;
        let cr3 = header.directory_table_base;
        cr3
    }

    pub fn get_module_list(&self) -> u64 {
        let header = &self.dump.raw_dmp.dmp_header;
        let module_list = header.ps_loaded_module_list;
        module_list
    }


}

impl <'a> Snapshot for DumpSnapshot <'a> {

    fn read_gpa(&self, gpa: u64, buffer: &mut [u8]) -> Result<()> {
        let base = gpa & !0xfff;
        let offset = (gpa & 0xfff) as usize;

        let available = 0x1000 - offset;
        let size = std::cmp::min(available, buffer.len());

        match self.dump.physmem.get(&base) {
            Some(b) => buffer[..size].clone_from_slice(&b[offset..offset+size]),
            None => {
                warn!("can't find page in dump");
                return Err(anyhow!("can't find page in dump"));
            }
        }
        Ok(())
    }

}

impl <'a> X64VirtualAddressSpace for DumpSnapshot <'a> {

    fn read_gpa(&self, gpa: mem::Gpa, buf: &mut [u8]) -> anyhow::Result<()> {
        Snapshot::read_gpa(self, gpa, buf)
    }

    fn write_gpa(&mut self, _gpa: mem::Gpa, _data: &[u8]) -> anyhow::Result<()> {
        warn!("read-only snapshot");
        Ok(())
    }

}


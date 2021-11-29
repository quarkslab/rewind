use std::io::Read;

use rewind_core::{mem::{self, X64VirtualAddressSpace}, snapshot::Snapshot, trace};

#[derive(Default)]
pub struct TestHook {

}

impl trace::Hook for TestHook {
    fn setup<T: trace::Tracer>(&mut self, _tracer: &mut T) {

    }

    fn handle_breakpoint<T: trace::Tracer>(&mut self, _tracer: &mut T) -> Result<bool, trace::TracerError> {
        todo!()
    }

    fn handle_trace(&self, _trace: &mut trace::Trace) -> Result<bool, trace::TracerError> {
        Ok(true)
    }

    fn patch_page(&self, _: u64) -> bool {
        todo!()
    }
}

#[derive(Default)]
pub struct TestSnapshot {

}

impl Snapshot for TestSnapshot {

    fn read_gpa(&self, gpa: u64, buffer: &mut [u8]) -> Result<(), rewind_core::snapshot::SnapshotError> {
        let base = gpa & !0xfff;
        let offset = (gpa & 0xfff) as usize;

        let mut data = vec![0u8; 0x1000];
        let path = std::path::PathBuf::from(format!("../tests/fixtures/sdb/mem/{:016x}.bin", base));
        let mut fp = std::fs::File::open(path).unwrap();
        fp.read_exact(&mut data).unwrap();
        buffer.copy_from_slice(&data[offset..offset+buffer.len()]);
        Ok(())
    }

    fn get_cr3(&self) -> u64 {
        todo!()
    }

    fn get_module_list(&self) -> u64 {
        todo!()
    }
}

impl X64VirtualAddressSpace for TestSnapshot {

    fn read_gpa(&self, gpa: mem::Gpa, buf: &mut [u8]) -> Result<(), mem::VirtMemError> {
        Snapshot::read_gpa(self, gpa, buf).map_err(|_e| mem::VirtMemError::MissingPage(gpa))
    }

    fn write_gpa(&mut self, _gpa: mem::Gpa, _data: &[u8]) -> Result<(), mem::VirtMemError> {
        Ok(())
    }
}

use anyhow::Result;

pub trait Snapshot {

    fn read_gpa(&self, gpa: u64, buffer: &mut [u8]) -> Result<()>;

}


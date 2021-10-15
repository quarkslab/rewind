
use std::io::Write;

use clap::Clap;

use color_eyre::{Report, eyre::WrapErr};
use memmap::MmapOptions;
use rewind_core::trace::ProcessorState;
use rewind_snapshot::{DumpSnapshot, FileSnapshot, SnapshotKind};

use crate::helpers::{self, parse_hex};

/// Manage snapshots.
#[derive(Clap, Debug)]
pub(crate) struct Snapshot {
    #[clap(subcommand)]
    subcmd: SnapshotSubCommand
}

impl Snapshot {

    pub(crate) fn run(&self) -> Result<(), Report> {
        match &self.subcmd {
            SnapshotSubCommand::Extract(t) => t.run(),
            SnapshotSubCommand::Convert(t) => t.run(),
        }
    }
}

#[derive(Clap, Debug)]
enum SnapshotSubCommand {
    Extract(SnapshotExtract),
    Convert(SnapshotConvert),
}

/// Extract physical pages from snapshot
#[derive(Clap, Debug)]
struct SnapshotExtract {
    /// Snapshot path
    #[clap(parse(from_os_str))]
    pub snapshot: std::path::PathBuf,

    /// Output directory
    #[clap(parse(from_os_str))]
    pub path: std::path::PathBuf,

    /// Physical pages to extract (in hexadecimal)
    #[clap(multiple_values(true), number_of_values(1), parse(try_from_str=parse_hex))]
    pub addresses: Vec<usize>,

}

impl SnapshotExtract {
    /// Implementation of `rewind snapshot extract`
    fn run(&self) -> Result<(), Report> {
        let progress = helpers::start();
        let progress = progress.enter("Extracting pages from snapshot");

        let snapshot_path = &self.snapshot;

        progress.single("Loading snapshot");
        let buffer;

        let snapshot = if snapshot_path.join("mem.dmp").exists() {
            let dump_path = snapshot_path.join("mem.dmp");

            let fp = std::fs::File::open(&dump_path).wrap_err(format!("Can't load snapshot {}", dump_path.display()))?;
            buffer = unsafe { MmapOptions::new().map(&fp)? };

            let snapshot = DumpSnapshot::new(&buffer)?;
            SnapshotKind::DumpSnapshot(snapshot)
        } else {
            let snapshot = FileSnapshot::new(&snapshot_path)?;
            SnapshotKind::FileSnapshot(snapshot)
        };

        progress.single("Extracting pages");
        for address in &self.addresses {
            let gpa = *address as u64;
            let base = gpa & !0xfff;
            let filename = format!("{:016x}.bin", base);
            let path = &self.path.join(filename);

            println!("Copying {:x} to {}", address, path.display());
            let mut data = vec![0u8; 0x1000];
            rewind_core::snapshot::Snapshot::read_gpa(&snapshot, gpa, &mut data)?;

            let mut fp = std::fs::File::create(path)?;
            fp.write_all(&data)?;
        }

        Ok(())
    }


}
/// Convert from bdump snapshots
#[derive(Clap, Debug)]
struct SnapshotConvert {
    /// Snapshot path
    #[clap(parse(from_os_str))]
    pub snapshot: std::path::PathBuf,

}

impl SnapshotConvert {

    fn run(&self) -> Result<(), Report> {
        let progress = helpers::start();
        let progress = progress.enter("Converting snapshot");

        let path = self.snapshot.join("regs.json");

        progress.single("Loading bdump processor state");
        let bd_processor_state = rewind_core::trace::BdProcessorState::load(&path)?;

        let processor_state: ProcessorState = bd_processor_state.into();

        progress.single("Saving processor state");
        let path = self.snapshot.join("context.json");
        processor_state.save(&path)?;

        let path = self.snapshot.join("params.json");
        let params = rewind_core::trace::Params::default();
        params.save(&path)?;
        
        Ok(())
    }

}
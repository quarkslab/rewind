
use std::io::Write;

use clap::Clap;

use color_eyre::{Report, eyre::WrapErr};
use memmap::MmapOptions;
use rewind_core::{mem::X64VirtualAddressSpace, trace::ProcessorState};
use rewind_snapshot::{DumpSnapshot, FileSnapshot, SnapshotKind};
use rewind_system::{PdbStore, System};

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

    /// Symbol store path
    #[clap(parse(from_os_str))]
    pub store: std::path::PathBuf,

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

        let snapshot_path = &self.snapshot;

        progress.single("Loading snapshot");
        let buffer;

        let snapshot = {
            let dump_path = snapshot_path.join("mem.dmp");

            let fp = std::fs::File::open(&dump_path).wrap_err(format!("Can't load snapshot {}", dump_path.display()))?;
            buffer = unsafe { MmapOptions::new().map(&fp)? };

            let snapshot = DumpSnapshot::new(&buffer)?;
            SnapshotKind::DumpSnapshot(snapshot)
        };

        let path = &self.store;
        if !path.exists() {
            progress.warn("Symbol store doesn't exist");
            progress.single("Creating symbol store directories");
            std::fs::create_dir(&path)?;
            std::fs::create_dir(path.join("binaries"))?;
            std::fs::create_dir(path.join("symbols"))?;
        }

        let mut system = System::new(&snapshot)?;

        system.load_modules()?;

        let mut store = PdbStore::new(path)?;

        let progress = progress.enter("Fetching kernel info");
        let module = system.get_module_by_name("ntoskrnl.exe").expect("can't find ntoskrnl");
        if let Ok(info) = system.get_file_information(module) {
            progress.single("Downloading ntoskrnl.exe");
            if let Err(e) = store.download_pe(&module.name, &info) {
                progress.warn(format!("Error during download: {}", e));
            } else {
                progress.single("Downloaded ntoskrnl.exe");
            }
        }

        if let Ok(info) = system.get_debug_information(module) {
            let (name, guid) = info.into();
            progress.single(format!("Downloading {}", name));
            if let Err(e) = store.download_pdb(&name, &guid) {
                progress.warn(format!("Error during download: {}", e));
            } else if let Err(e) = store.load_pdb(module.base, &name, &guid) {
                progress.warn(format!("Can't load pdb: {}", e));
            } else {
                progress.single(format!("Downloaded and loaded {}", name));
            }
        }

        let mut params = rewind_core::trace::Params::default();

        for name in ["KeBugCheck2", "KeBugCheckEx"] {
            let address = store.resolve_name(name).unwrap_or_else(|| panic!("can't find {}", name));
            params.excluded_addresses.insert(name.into(), address);
        }

        params.return_address = snapshot.read_gva_u64(processor_state.cr3, processor_state.rsp)?;

        let progress = progress.leave();

        progress.single("Saving parameters");
        let path = self.snapshot.join("params.json");
        params.save(&path)?;
 
        Ok(())
    }

}
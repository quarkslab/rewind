
//! Rewind CLI.

use color_eyre::Report;

use clap::Clap;

use rewind_core::{mutation, snapshot, trace::{self, Tracer, TracerError}};
use rewind_core::mem::{X64VirtualAddressSpace, VirtMemError};
use rewind_core::fuzz;

use crate::commands::{FuzzCmd, MutationCmd, SnapshotCmd, TraceCmd};

/// Backend
#[allow(clippy::large_enum_variant)]
pub enum Backend<'a, S>
where S: snapshot::Snapshot {
    /// Hyper-V backend 
    #[cfg(windows)]
    Whvp(rewind_whvp::WhvpTracer<'a, S>),

    /// Bochs backend
    Bochs(rewind_bochs::BochsTracer<'a, S>),

    /// Kvm backend
    #[cfg(unix)]
    Kvm(rewind_kvm::KvmTracer)

}

impl<'a, S> trace::Tracer for Backend<'a, S>
where S: snapshot::Snapshot + X64VirtualAddressSpace {

    fn get_state(&mut self) -> Result<trace::ProcessorState, TracerError> {
        match self {
            #[cfg(windows)]
            Self::Whvp(tracer) => tracer.get_state(),
            Self::Bochs(tracer) => tracer.get_state(),
            #[cfg(unix)]
            Self::Kvm(tracer) => tracer.get_state(),
        }
    }

    fn set_state(&mut self, state: &trace::ProcessorState) -> Result<(), TracerError> {
        match self {
            #[cfg(windows)]
            Self::Whvp(tracer) => tracer.set_state(state),
            Self::Bochs(tracer) => tracer.set_state(state),
            #[cfg(unix)]
            Self::Kvm(tracer) => tracer.set_state(state),
        }
    }

    fn run<H: trace::Hook>(&mut self, params: &trace::Params, hook: &mut H) -> Result<trace::Trace, TracerError> {
        match self {
            #[cfg(windows)]
            Self::Whvp(tracer) => tracer.run(params, hook),
            Self::Bochs(tracer) => tracer.run(params, hook),
            #[cfg(unix)]
            Self::Kvm(tracer) => tracer.run(params, hook),
        }
    }

    fn run_with_trace<H: trace::Hook>(&mut self, params: &trace::Params, hook: &mut H, trace: &mut trace::Trace) -> Result<(), TracerError> {
        match self {
            #[cfg(windows)]
            Self::Whvp(tracer) => tracer.run_with_trace(params, hook, trace),
            Self::Bochs(tracer) => tracer.run_with_trace(params, hook, trace),
            #[cfg(unix)]
            Self::Kvm(tracer) => tracer.run_with_trace(params, hook, trace),
        }
    }

    fn restore_snapshot(&mut self) -> Result<usize, TracerError> {
        match self {
            #[cfg(windows)]
            Self::Whvp(tracer) => tracer.restore_snapshot(),
            Self::Bochs(tracer) => tracer.restore_snapshot(),
            #[cfg(unix)]
            Self::Kvm(tracer) => tracer.restore_snapshot(),
        }
    }

    fn read_gva(&mut self, cr3: u64, vaddr: u64, data: &mut [u8]) -> Result<(), TracerError> {
        match self {
            #[cfg(windows)]
            Self::Whvp(tracer) => Tracer::read_gva(tracer, cr3, vaddr, data),
            Self::Bochs(tracer) => Tracer::read_gva(tracer, cr3, vaddr, data),
            #[cfg(unix)]
            Self::Kvm(tracer) => tracer.read_gva(cr3, vaddr, data),
        }
    }

    fn write_gva(&mut self, cr3: u64, vaddr: u64, data: &[u8]) -> Result<(), TracerError> {
        match self {
            #[cfg(windows)]
            Self::Whvp(tracer) => Tracer::write_gva(tracer, cr3, vaddr, data),
            Self::Bochs(tracer) => Tracer::write_gva(tracer, cr3, vaddr, data),
            #[cfg(unix)]
            Self::Kvm(tracer) => Tracer::write_gva(tracer, cr3, vaddr, data),
        }
    }

    fn cr3(&mut self) -> Result<u64, TracerError> {
        match self {
            #[cfg(windows)]
            Self::Whvp(tracer) => tracer.cr3(),
            Self::Bochs(tracer) => tracer.cr3(),
            #[cfg(unix)]
            Self::Kvm(tracer) => tracer.cr3(),
        }
    }

    fn singlestep<H: trace::Hook>(&mut self, params: &trace::Params, hook: &mut H) -> Result<trace::Trace, TracerError> {
        match self {
            #[cfg(windows)]
            Self::Whvp(tracer) => tracer.singlestep(params, hook),
            Self::Bochs(tracer) => tracer.singlestep(params, hook),
            #[cfg(unix)]
            Self::Kvm(tracer) => tracer.singlestep(params, hook),
        }
    }

    fn add_breakpoint(&mut self, address: u64) {
        match self {
            #[cfg(windows)]
            Self::Whvp(tracer) => tracer.add_breakpoint(address),
            Self::Bochs(tracer) => tracer.add_breakpoint(address),
            #[cfg(unix)]
            Self::Kvm(tracer) => tracer.add_breakpoint(address),
        }

    }

    fn get_mapped_pages(&self) -> Result<usize, TracerError> {
        match self {
            #[cfg(windows)]
            Self::Whvp(tracer) => tracer.get_mapped_pages(),
            Self::Bochs(tracer) => tracer.get_mapped_pages(),
            #[cfg(unix)]
            Self::Kvm(tracer) => tracer.get_mapped_pages(),
        }
    }
}



impl<'a, S> X64VirtualAddressSpace for Backend<'a, S>
where S: snapshot::Snapshot + X64VirtualAddressSpace {

    fn read_gpa(&self, gpa: u64, buf: &mut [u8]) -> Result<(), VirtMemError> {
        match self {
            #[cfg(windows)]
            Self::Whvp(tracer) => tracer.read_gpa(gpa, buf),
            Self::Bochs(tracer) => tracer.read_gpa(gpa, buf),
            #[cfg(unix)]
            Self::Kvm(tracer) => tracer.read_gpa(gpa, buf)
        }
    }

    fn write_gpa(&mut self, gpa: u64, data: &[u8]) -> Result<(), VirtMemError> {
        match self {
            #[cfg(windows)]
            Self::Whvp(tracer) => tracer.write_gpa(gpa, data),
            Self::Bochs(tracer) => tracer.write_gpa(gpa, data),
            #[cfg(unix)]
            Self::Kvm(tracer) => tracer.write_gpa(gpa, data)
        }
    }
}

// fn load_snapshot<'a>(path: &Path) -> Result<Snapshot<'a>> {
//     if path.join("mem.dmp").exists() {
//         let dump_path = path.join("mem.dmp");

//         let fp = std::fs::File::open(&dump_path).wrap_err(format!("Can't load snapshot {}", dump_path.display()))?;
//         let buffer = unsafe { MmapOptions::new().map(&fp)? };

//         let snapshot = DumpSnapshot::new(&buffer)?;
//         Ok(Snapshot::DumpSnapshot(snapshot))
//     } else {
//         let snapshot = FileSnapshot::new(path)?;
//         Ok(Snapshot::FileSnapshot(snapshot))
//     }
// }

/// Allow to customize CLI
pub trait Rewind {

    /// Hook used during trace
    type TraceHook: trace::Hook;

    /// Hook used during fuzzing
    type FuzzerHook: trace::Hook;

    /// Fuzzing strategy
    type FuzzingStrategy: fuzz::Strategy;

    /// Tracer hook constructor
    fn create_tracer_hook(&self) -> Self::TraceHook;

    /// Fuzzer hook constructor
    fn create_fuzzer_hook(&self) -> Self::FuzzerHook;

    /// Fuzzing strategy constructor
    fn create_fuzzing_strategy(&self, params: &fuzz::Params, mutator: mutation::Mutator) -> Self::FuzzingStrategy;
    
}


/// PoC for a snapshot-based coverage-guided fuzzer targeting Windows kernel components.
#[derive(Clap, Debug)]
#[clap(
    name="rewind",
    bin_name="rewind",
    version="0.1.0",
    author="Damien Aumaitre <daumaitre@quarkslab.com>",
    setting = clap::AppSettings::DisableHelpSubcommand,
    setting = clap::AppSettings::DeriveDisplayOrder,
    setting = clap::AppSettings::InferSubcommands,
    setting = clap::AppSettings::GlobalVersion,
    setting = clap::AppSettings::HelpRequired,
)]

// FIXME: will need to revisit when https://github.com/clap-rs/clap/issues/1431 is done
struct RewindArgs {
    #[clap(subcommand)]
    subcmd: SubCommand,

}

impl RewindArgs {

}

#[derive(Clap, Debug)]
enum SubCommand {
    Snapshot(SnapshotCmd),
    Trace(TraceCmd),
    Fuzz(FuzzCmd),
    Mutate(MutationCmd)
}

/// CLI
#[derive(Default)]
pub struct Cli {
}

impl Cli {
    /// Constructor
    pub fn new() -> Self {
        Self {
        }
    }

    /// Command dispatcher
    pub fn run(&self) -> Result<(), Report> {
        let args = RewindArgs::parse();
        // FIXME: use args.run
        match &args.subcmd {
            SubCommand::Snapshot(t) => t.run(),      
            SubCommand::Trace(t) => t.run(self),
            SubCommand::Fuzz(t) => t.run(self),
            SubCommand::Mutate(t) => t.run(),
        }
    }
}

impl Rewind for Cli {
    type TraceHook = trace::NoHook;
    type FuzzerHook = trace::NoHook;
    type FuzzingStrategy = mutation::BasicStrategy;

    fn create_fuzzer_hook(&self) -> Self::FuzzerHook {
        trace::NoHook::default()
    }

    fn create_tracer_hook(&self) -> Self::TraceHook {
        trace::NoHook::default()
    }

    fn create_fuzzing_strategy(&self, _params: &fuzz::Params, mutator: mutation::Mutator) -> Self::FuzzingStrategy {
        mutation::BasicStrategy::new(mutator)
    }
}
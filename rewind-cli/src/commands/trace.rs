
use std::{collections::{HashMap, HashSet}, io::{BufWriter, Read, Write}, path::PathBuf, str::FromStr, time::Instant};
use std::fmt::Write as FmtWrite;

use clap::Clap;
use color_eyre::{Report, eyre::Context};
use memmap::MmapOptions;
use rewind_core::{mem::X64VirtualAddressSpace, trace::{self, CoverageMode, Hook, Tracer}};
use rewind_snapshot::{DumpSnapshot, FileSnapshot, SnapshotKind};
use rewind_system::{PdbStore, System};
use rewind_tui::{Collection, parse_trace};
use crate::{Rewind, cli::Backend, helpers::{self, decode_instruction, format_instruction}};


/// Do stuff with traces.
#[derive(Clap, Debug)]
pub(crate) struct TraceCmd {
    #[clap(subcommand)]
    subcmd: TraceSubCommand
}

impl TraceCmd {

    pub(crate) fn run<C: Rewind>(&self, cli: &C) -> Result<(), Report> {
        match &self.subcmd {
            TraceSubCommand::Run(t) => t.run(cli),
            TraceSubCommand::Inspect(t) => t.run(),
            TraceSubCommand::Convert(t) => t.run(),
        }
    }
}

#[derive(Clap, Debug)]
enum TraceSubCommand {
    Run(TracerRun),
    Inspect(TracerInspect),
    Convert(TracerConvert),
}



/// Run tracer
#[derive(Clap, Debug)]
pub struct TracerRun {
    /// Set the level of verbosity
    #[clap(long, short, parse(from_occurrences))]
    pub verbose: usize,
 
    /// Snapshot path
    #[clap(parse(from_os_str))]
    pub snapshot: PathBuf,

    /// Execution limit
    #[clap(long="limit", default_value="0")]
    pub limit: u64,

    /// Save context
    #[clap(long="save-context")]
    pub save_context: bool,

    /// Max tracing time (in seconds)
    #[clap(long="max-time", default_value="0")]
    pub max_time: u64,

    /// Save trace to file
    #[clap(long="save-trace", parse(from_os_str))]
    pub trace: Option<PathBuf>,

    /// Tracing backend
    #[clap(long="backend", possible_values(&["whvp", "bochs", "kvm"]), default_value="bochs")]
    pub backend: crate::BackendType,

    /// Tracing coverage
    #[clap(long="coverage", possible_values(&["no", "instrs", "hit"]), default_value="no")]
    pub coverage: CoverageMode,

    /// Input description
    #[clap(long="input", parse(from_os_str))]
    pub input: Option<PathBuf>,

    /// Input data
    #[clap(long="data", parse(from_os_str))]
    pub data: Option<PathBuf>,

    /// Save input to file
    #[clap(long="save-input", parse(from_os_str))]
    pub save_input: Option<PathBuf>,

    /// Save physical pages fetched from snapshot (debug)
    #[clap(long="save-mem", parse(from_os_str))]
    pub save_mem: Option<PathBuf>,


}

impl TracerRun {

    /// Implementation of `rewind trace run`
    fn run<C: Rewind>(&self, cli: &C) -> Result<(), Report> {
        let progress = helpers::start();
        let progress = progress.enter("Running tracer");

        progress.single("loading snapshot");

        // FIXME: finish load_snapshot
        // let snapshot = load_snapshot(&args.snapshot)?;
        let buffer;

        let snapshot = if self.snapshot.join("mem.dmp").exists() {
            let dump_path = self.snapshot.join("mem.dmp");

            let fp = std::fs::File::open(&dump_path).wrap_err(format!("Can't load snapshot {}", dump_path.display()))?;
            buffer = unsafe { MmapOptions::new().map(&fp)? };

            // FIXME: ugly
            let static_buffer: &'static [u8] = Box::leak(Box::new(buffer));
            let snapshot = DumpSnapshot::new(static_buffer)?;
            SnapshotKind::DumpSnapshot(snapshot)
        } else {
            let snapshot = FileSnapshot::new(&self.snapshot)?;
            SnapshotKind::FileSnapshot(snapshot)
        };

        let context_path = self.snapshot.join("context.json");
        let context = trace::ProcessorState::load(&context_path)?;

        let params_path = self.snapshot.join("params.json");
        let mut params = trace::Params::load(&params_path)?;

        params.limit = self.limit;
        params.save_context = self.save_context;
        params.max_duration = std::time::Duration::from_secs(self.max_time);
        params.coverage_mode = self.coverage.clone();

        progress.single(format!("will use {} backend", self.backend));
        let mut tracer = match self.backend {
            crate::BackendType::Bochs => {
                Backend::Bochs(rewind_bochs::BochsTracer::new(&snapshot))
            },
            #[cfg(windows)]
            crate::BackendType::Whvp => {
                Backend::Whvp(rewind_whvp::WhvpTracer::new(&snapshot)?)
            },
            #[cfg(unix)]
            crate::BackendType::Kvm => {
                Backend::Kvm(rewind_kvm::KvmTracer::new(snapshot)?)
            }
        };

        progress.single(format!("setting tracer initial state\n{}", &context));
        tracer.set_state(&context)?;

        match (&self.input, &self.data) {
            (Some(desc), Some(filename)) => {
                let input_desc = rewind_core::mutation::InputDesc::load(desc)
                    .wrap_err(format!("Can't load input description {}", desc.display()))?;

                progress.single(format!("replaying input {:?}", filename));

                let cr3 = context.cr3;

                let mut file = std::fs::File::open(filename)?;
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer)?;

                for item in input_desc.items { 
                    // FIXME: wrong
                    let slice = &buffer[item.offset..item.offset+item.size];
                    progress.single(format!("writing input ({:x} bytes) to {:x} (cr3 {:x})", slice.len(), item.address, cr3));
                    Tracer::write_gva(&mut tracer, cr3, item.address, slice).wrap_err("can't write fuzzer input")?;
                }
            }
            (Some(desc), None) => {
                let input_desc = rewind_core::mutation::InputDesc::load(desc)
                    .wrap_err(format!("Can't load input description {}", desc.display()))?;

                // FIXME: compute needed size
                let mut buffer = vec![0u8; 0x1000];

                let cr3 = context.cr3;
                for item in input_desc.items { 
                    progress.single(format!("reading input from {:x}", item.address));
                    Tracer::read_gva(&mut tracer, cr3, item.address, &mut buffer[item.offset..item.offset+item.size]).wrap_err("can't read fuzzer input")?;
                }

                if let Some(path) = &self.save_input {
                    progress.single(format!("saving input to {:?} ({:x})", path, buffer.len()));
                    let mut file = std::fs::File::create(path)?;
                    file.write_all(&buffer)?;
                }

            }
            _ => {
                // progress.warn("--input or --data parameters incorrectly used, ignoring");
            }
        }

        progress.single("running tracer");
        let mut trace = trace::Trace::new();

        let start = Instant::now();

        let mut hook = cli.create_tracer_hook();

        hook.setup(&mut tracer);

        // FIXME: should be in tracer.run
        // singlestep doesn't need hook and params
        loop {

            let mut bp_trace = tracer.run(&params, &mut hook)?;
            trace.seen.append(&mut bp_trace.seen);
            trace.coverage.append(&mut bp_trace.coverage);
            trace.mem_accesses.append(&mut bp_trace.mem_accesses);
            trace.status = bp_trace.status;
            match trace.status {
                trace::EmulationStatus::Breakpoint => {
                    if hook.handle_breakpoint(&mut tracer)? {
                        tracer.singlestep(&params, &mut hook)?;
                    }
                },
                trace::EmulationStatus::SingleStep => {
                    // rearm bps ?

                }
                _ => {
                    break
                }
            }
        }

        let end = Instant::now();

        trace.start = Some(start);
        trace.end = Some(end);

        hook.handle_trace(&mut trace)?;

        let t = end - start;

        let pages = tracer.get_mapped_pages()?;
        let mem = rewind_core::helpers::convert((pages * 0x1000) as f64);
        progress.single(format!("executed {} instruction(s) in {:?} ({:?})", trace.coverage.len(), t, trace.status));
        progress.single(format!("seen {} unique address(es)", trace.seen.len()));
        progress.single(format!("mapped {} page(s) ({})", pages, mem));

        let pages = tracer.restore_snapshot();
        progress.single(format!("{:?} page(s) were modified", pages.unwrap()));

        if let Some(path) = &self.trace {
            progress.single(format!("saving trace to {}", path.display()));
            trace.save(&path)?;
        }

        if let Some(path) = &self.save_mem {
            progress.single(format!("saving fetched physical pages to {}", path.display()));
            // snapshot.save(&path)?;
        }

        Ok(())
    }
}

/// Inspect trace
#[derive(Clap, Debug)]
pub struct TracerInspect {
    /// Snapshot path
    #[clap(parse(from_os_str))]
    pub snapshot: PathBuf,

    /// Trace to load
    #[clap(parse(from_os_str))]
    pub trace: PathBuf,

    /// Symbol store
    #[clap(long="store", parse(from_os_str))]
    pub store: PathBuf,

    /// Set the level of verbosity
    #[clap(long, short, parse(from_occurrences))]
    pub verbose: usize,

    /// Show coverage after execution
    #[clap(long="show-coverage")]
    pub show_coverage: bool,

    /// Show executed instructions after execution
    #[clap(long="show-instructions")]
    pub show_instructions: bool,

    /// Number of instructions to display
    #[clap(long="count")]
    pub instructions_count: Option<usize>,

    /// Number of instructions to skip
    #[clap(long="skip")]
    pub skip_instructions: Option<usize>,

    /// Show last executed instructions
    #[clap(long="last")]
    pub last: bool,

    /// Show only instructions matching pattern
    #[clap(long="filter")]
    pub filter: Option<String>,

    /// Save formatted trace to file
    #[clap(long="symbolize")]
    pub symbolize: Option<PathBuf>,

    /// Apply dummy sanitizer (experimental)
    #[clap(long="sanitize")]
    pub sanitize: bool,

    /// Save physical pages fetched from snapshot (debug)
    #[clap(long="save-mem", parse(from_os_str))]
    pub save_mem: Option<PathBuf>,

}

impl TracerInspect {

    pub(crate) fn run(&self) -> Result<(), Report> {
        let progress = helpers::start();
        let progress = progress.enter("Inspecting trace");

        progress.single("loading snapshot");
        let buffer;

        let snapshot = if self.snapshot.join("mem.dmp").exists() {
            let dump_path = self.snapshot.join("mem.dmp");

            let fp = std::fs::File::open(&dump_path).wrap_err(format!("Can't load snapshot {}", dump_path.display()))?;
            buffer = unsafe { MmapOptions::new().map(&fp)? };

            let snapshot = DumpSnapshot::new(&buffer)?;
            SnapshotKind::DumpSnapshot(snapshot)
        } else {
            let snapshot = FileSnapshot::new(&self.snapshot)?;
            SnapshotKind::FileSnapshot(snapshot)
        };

        let context_path = self.snapshot.join("context.json");
        let context = trace::ProcessorState::load(&context_path)?;
 
        progress.single("loading trace");
        let mut trace = trace::Trace::load(&self.trace)?;

        // FIXME: check if context is present
        progress.single(format!("trace contains {} instructions ({} unique(s))", trace.coverage.len(), trace.seen.len()));

        let path = &self.store;
        if !path.exists() {
            progress.warn("symbol store doesn't exist");

            progress.single("creating symbol store directories");
            std::fs::create_dir(&path)?;
            std::fs::create_dir(path.join("binaries"))?;
            std::fs::create_dir(path.join("symbols"))?;
        }

        let mut system = System::new(&snapshot)?;

        let progress = progress.leave();
        let progress = progress.enter("Analysing trace");

        progress.single("loading modules");
        system.load_modules()?;

        let mut store = PdbStore::new(path)?;
        // FIXME: rename collection and move definition
        let mut collection = Collection::new();

        progress.single("parsing trace");
        parse_trace(&mut collection, &mut trace, &system, &mut store)?;

        progress.single(format!("trace has {} modules(s) and {} function(s)", collection.modules.len(), collection.functions.len()));

        let mut out_writer = match &self.symbolize {
            Some(x) => {
                Box::new(BufWriter::new(std::fs::File::create(x)?)) as Box<dyn Write>
            }
            None => Box::new(std::io::stdout()) as Box<dyn Write>,
        };

        if self.show_coverage {
            progress.single("displaying coverage");

            let mut functions: Vec<_> = collection.functions.iter().collect();
            functions.sort();

            for (name, instructions) in functions.iter() {
                // FIXME: compute percentage
                writeln!(out_writer, "{}: {} instructions", &name, instructions.coverage)?;

            }
        }

        if self.show_instructions {
            let skip = self.skip_instructions.unwrap_or(0);

            progress.single("displaying instructions");
            let instructions = trace.coverage.iter()
                // .map(|(addr, _context)| {
                    // addr
                // })
                .enumerate();

            let instructions: Box<dyn Iterator<Item = (usize, _)>> = if self.last {
                if let Some(count) = self.instructions_count {
                    Box::new(instructions.rev().skip(skip).take(count).rev())
                } else {
                    Box::new(instructions.rev().skip(skip).rev())
                }
            } else if let Some(count) = self.instructions_count {
                Box::new(instructions.skip(skip).take(count))
            } else {
                Box::new(instructions.skip(skip))
            };

            for (index, (addr, maybe_context)) in instructions {
                let mut bytes = vec![0u8; 16];
                system.snapshot.read_gva(context.cr3, *addr, &mut bytes)?;
                let instruction = decode_instruction(&bytes)?;
                let n = instruction.length as usize;
                let formatted_instruction = format_instruction(*addr, instruction)?;

                let mut formatted_bytes = String::with_capacity(2 * n);
                for byte in &bytes[..n] {
                    write!(formatted_bytes, "{:02x}", byte)?;
                }
                
                let formatted_context = match maybe_context {
                    Some(c) => format!("{}\n", c),
                    None => format!("")
                };

                let text = match store.resolve_address(*addr) {
                    Some(symbol) => {
                        format!("instruction #{}:\n{}{}\n{:016x} {:<32}{:<20}\n", index, formatted_context, symbol, *addr, formatted_bytes, formatted_instruction)
                    }
                    None => {
                        format!("instruction #{}:\n{}{:016x} {:<32}{:<20}\n", index, formatted_context, *addr, formatted_bytes, formatted_instruction)
                    }
                };

                if let Some(filter) = &self.filter {
                    let pattern = filter.to_lowercase();
                    if text.to_lowercase().matches(&pattern).count() > 0 {
                        writeln!(out_writer, "{}", text)?;
                    }
                } else {
                    writeln!(out_writer, "{}", text)?;
                }

            }
        }

        if self.sanitize {
            println!("DO NOT USE: half baked attempt, doesn't work");
            // FIXME: can't work for now
            // need to find a way to have return address for ExAllocatePool to be able to have buffer address
            // mem accesses don't record read or written values
            let allocate = store.resolve_name("ExAllocatePoolWithTag").unwrap();
            println!("allocate @ {:x}", allocate);
            let free = store.resolve_name("ExFreePoolWithTag").unwrap();
            println!("free @ {:x}", free);

            let instructions = trace.coverage.iter()
                .enumerate();

            let mut values = vec![];
            for (index, (addr, maybe_context)) in instructions {
                if *addr == allocate {
                    
                    println!("allocate called ({}, {:x})", index, addr);
                    if let Some(context) = maybe_context {
                        println!("rcx: {:x}", context.rcx);
                        println!("rdx: {:x}", context.rdx);
                        println!("rsp: {:x}", context.rsp);
                        for access in trace.mem_accesses.iter() {
                            if access.vaddr == context.rsp && access.size == 8 && access.access_type == trace::MemAccessType::Write {
                                println!("found rsp, rip {:x}", access.rip);
                                values.push(access.rip);
                            } 
                        }

                    } else {
                        println!("error: need a trace with context");
                        break
                    }
                }
                if *addr == free {
                    println!("free called ({}, {:x})", index, addr);
                    if let Some(context) = maybe_context {
                        println!("rcx: {:x}", context.rcx);
                    } else {
                        println!("error: need a trace with context");
                        break
                    }
                }

                if values.contains(addr) {
                    println!("values match");
                    if let Some(context) = maybe_context {
                        println!("rax: {:x}", context.rax);
                    } else {
                        println!("error: need a trace with context");
                        break
                    }
                }
            }
        }

        if let Some(path) = &self.save_mem {
            progress.single(format!("saving fetched physical pages to {}", path.display()));
            snapshot.save(&path)?;
        }

        Ok(())
    }

}

/// Trace formats
#[derive(Debug)]
pub enum TraceFormat {
    /// Text
    Text,
    /// Tenet
    Tenet,
}

impl FromStr for TraceFormat {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "txt" => Ok(Self::Text),
            "tenet" => Ok(Self::Tenet),
            _ => Err("no match"),
        }
    }
}

impl std::fmt::Display for TraceFormat {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        match self {
            Self::Text => {
                f.write_str("txt")
            },
            Self::Tenet => {
                f.write_str("tenet")
            }
        }
    }
}


/// Convert trace
#[derive(Clap, Debug)]
pub struct TracerConvert {
    /// Snapshot path
    #[clap(parse(from_os_str))]
    pub snapshot: PathBuf,

    /// Trace to load
    #[clap(parse(from_os_str))]
    pub trace: PathBuf,

    /// Symbol store
    #[clap(long="store", parse(from_os_str))]
    pub store: PathBuf,

    /// Set the level of verbosity
    #[clap(long, short, parse(from_occurrences))]
    pub verbose: usize,

    /// Save formatted trace to file
    #[clap(long)]
    pub output: Option<PathBuf>,

    /// Output format
    #[clap(long, possible_values(&["txt", "tenet"]), default_value="txt")]
    pub format: TraceFormat,
}

impl TracerConvert {

    pub(crate) fn run(&self) -> Result<(), Report> {
        let progress = helpers::start();
        let progress = progress.enter("Converting trace");

        progress.single("loading snapshot");
        let buffer;

        let snapshot = if self.snapshot.join("mem.dmp").exists() {
            let dump_path = self.snapshot.join("mem.dmp");

            let fp = std::fs::File::open(&dump_path).wrap_err(format!("Can't load snapshot {}", dump_path.display()))?;
            buffer = unsafe { MmapOptions::new().map(&fp)? };

            let snapshot = DumpSnapshot::new(&buffer)?;
            SnapshotKind::DumpSnapshot(snapshot)
        } else {
            let snapshot = FileSnapshot::new(&self.snapshot)?;
            SnapshotKind::FileSnapshot(snapshot)
        };

        let context_path = self.snapshot.join("context.json");
        let context = trace::ProcessorState::load(&context_path)?;
 
        progress.single("loading trace");
        let mut trace = trace::Trace::load(&self.trace)?;

        // FIXME: check if context is present
        progress.single(format!("trace contains {} instructions ({} unique(s))", trace.coverage.len(), trace.seen.len()));

        let path = &self.store;
        if !path.exists() {
            progress.warn("symbol store doesn't exist");

            progress.single("creating symbol store directories");
            std::fs::create_dir(&path)?;
            std::fs::create_dir(path.join("binaries"))?;
            std::fs::create_dir(path.join("symbols"))?;
        }

        let mut system = System::new(&snapshot)?;

        let progress = progress.leave();
        let progress = progress.enter("Analysing trace");

        progress.single("loading modules");
        system.load_modules()?;

        let mut store = PdbStore::new(path)?;
        let mut collection = Collection::new();

        progress.single("parsing trace");
        parse_trace(&mut collection, &mut trace, &system, &mut store)?;

        progress.single(format!("trace has {} modules(s) and {} function(s)", collection.modules.len(), collection.functions.len()));

        let mut out_writer = match &self.output {
            Some(x) => {
                Box::new(BufWriter::new(std::fs::File::create(x)?)) as Box<dyn Write>
            }
            None => Box::new(std::io::stdout()) as Box<dyn Write>,
        };


        match self.format {
            TraceFormat::Text => {
                let instructions = trace.coverage.iter()
                .enumerate();

                for (index, (addr, maybe_context)) in instructions {
                    let mut bytes = vec![0u8; 16];
                    system.snapshot.read_gva(context.cr3, *addr, &mut bytes)?;
                    let instruction = decode_instruction(&bytes)?;
                    let n = instruction.length as usize;
                    let formatted_instruction = format_instruction(*addr, instruction)?;

                    let mut formatted_bytes = String::with_capacity(2 * n);
                    for byte in &bytes[..n] {
                        write!(formatted_bytes, "{:02x}", byte)?;
                    }
                    
                    let formatted_context = match maybe_context {
                        Some(c) => format!("{}\n", c),
                        None => format!("")
                    };

                    let text = match store.resolve_address(*addr) {
                        Some(symbol) => {
                            format!("instruction #{}:\n{}{}\n{:016x} {:<32}{:<20}\n", index, formatted_context, symbol, *addr, formatted_bytes, formatted_instruction)
                        }
                        None => {
                            format!("instruction #{}:\n{}{:016x} {:<32}{:<20}\n", index, formatted_context, *addr, formatted_bytes, formatted_instruction)
                        }
                    };

                    writeln!(out_writer, "{}", text)?;
                }
            }
            TraceFormat::Tenet => {
                let mut modules = HashSet::new();
                let mut previous_context: Option<&trace::Context> = None;

                let mut accesses = HashMap::new();
                for access in trace.mem_accesses.iter() {
                    accesses.insert(access.rip, access);
                }

                for (address, maybe_context) in trace.coverage.iter() {
                    let context = maybe_context.as_ref().unwrap();
                    if let Some(module) = system.get_module_by_address(*address) {
                        if modules.insert(module) {
                            // let text = format!("Loaded image: 0x{:x}:0x{:x} -> {}", module.base, module.base + module.size, module.name);
                            // writeln!(out_writer, "{}", text)?;
                        }
                    }
                    if let Some(previous_context) = previous_context {
                        macro_rules! reg {
                            ($($reg_name:ident),*) => {
                                $(
                                if previous_context.$reg_name != context.$reg_name {
                                    let text = format!(concat!(stringify!($reg_name), "=0x{:x},"), context.$reg_name);
                                    write!(out_writer, "{}", text)?;
                                }
                                )*
                            }
                        }
                        reg!(rax,rbx,rcx,rdx,rsi,rdi,rsp,rbp);
                        reg!(r8,r9,r10,r11,r12,r13,r14,r15);
                    } else {
                        macro_rules! reg {
                            ($($reg_name:ident),*) => {
                                $(
                                let text = format!(concat!(stringify!($reg_name), "=0x{:x},"), context.$reg_name);
                                write!(out_writer, "{}", text)?;
                                )*
                            }
                        }
                        reg!(rax,rbx,rcx,rdx,rsi,rdi,rsp,rbp);
                        reg!(r8,r9,r10,r11,r12,r13,r14,r15);
                    }

                    let text = format!("rip=0x{:x}", context.rip);
                    write!(out_writer, "{}", text)?;

                    if let Some(&access) = accesses.get(address) {
                        match access.access_type {
                            trace::MemAccessType::Read => {
                                let text = format!(",mr=0x{:x}:", access.vaddr);
                                write!(out_writer, "{}", text)?;
                            },
                            trace::MemAccessType::Write => {
                                let text = format!(",mr=0x{:x}:", access.vaddr);
                                write!(out_writer, "{}", text)?;
                            },
                            trace::MemAccessType::Execute => {
                                let text = format!(",mr=0x{:x}:", access.vaddr);
                                write!(out_writer, "{}", text)?;
                            },
                            trace::MemAccessType::RW => {
                                let text = format!(",mrw=0x{:x}:", access.vaddr);
                                write!(out_writer, "{}", text)?;
                            },
                        }
                        for byte in access.data.iter() {
                            write!(out_writer, "{:02x}", byte)?;
                        }
                    }

                    writeln!(out_writer)?;

                    previous_context = Some(context);
                }
            }
        }

        Ok(())
    }

}


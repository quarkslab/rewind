
use std::fmt::Write as FmtWrite;
use std::io::{Read, Write};
use std::time::Instant;

use color_eyre::{Report, eyre::{bail, Result, WrapErr}};

use clap::{Clap, crate_version};

use memmap::MmapOptions;

use rewind_core::{fuzz, corpus, mem::{X64VirtualAddressSpace, VirtMemError}, snapshot, mutation, trace::{self, Tracer, TracerError, NoHook, Hook}};

use rewind_snapshot::DumpSnapshot;

use rewind_system::{system, pdbstore};

use rewind_tui::ui;


use crate::helpers;
#[allow(clippy::large_enum_variant)]
pub enum Backend<'a, S>
where S: snapshot::Snapshot {

    #[cfg(windows)]
    Whvp(rewind_whvp::WhvpTracer<'a, S>),
    Bochs(rewind_bochs::BochsTracer<'a, S>)
}

impl<'a, S> trace::Tracer for Backend<'a, S>
where S: snapshot::Snapshot + X64VirtualAddressSpace {

    fn get_state(&mut self) -> Result<trace::ProcessorState, TracerError> {
        match self {
            #[cfg(windows)]
            Self::Whvp(tracer) => tracer.get_state(),
            Self::Bochs(tracer) => tracer.get_state()
        }
    }

    fn set_state(&mut self, state: &trace::ProcessorState) -> Result<(), TracerError> {
        match self {
            #[cfg(windows)]
            Self::Whvp(tracer) => tracer.set_state(state),
            Self::Bochs(tracer) => tracer.set_state(state)
        }
    }

    fn run<H: trace::Hook>(&mut self, params: &trace::Params, hook: &mut H) -> Result<trace::Trace, TracerError> {
        match self {
            #[cfg(windows)]
            Self::Whvp(tracer) => tracer.run(params, hook),
            Self::Bochs(tracer) => tracer.run(params, hook)
        }
    }

    fn restore_snapshot(&mut self) -> Result<usize, TracerError> {
        match self {
            #[cfg(windows)]
            Self::Whvp(tracer) => tracer.restore_snapshot(),
            Self::Bochs(tracer) => tracer.restore_snapshot()
        }
    }

    fn read_gva(&mut self, cr3: u64, vaddr: u64, data: &mut [u8]) -> Result<(), TracerError> {
        match self {
            #[cfg(windows)]
            Self::Whvp(tracer) => tracer.read_gva(cr3, vaddr, data),
            Self::Bochs(tracer) => tracer.read_gva(cr3, vaddr, data)
        }
    }

    fn write_gva(&mut self, cr3: u64, vaddr: u64, data: &[u8]) -> Result<(), TracerError> {
        match self {
            #[cfg(windows)]
            Self::Whvp(tracer) => Tracer::write_gva(tracer, cr3, vaddr, data),
            Self::Bochs(tracer) => Tracer::write_gva(tracer, cr3, vaddr, data)
        }
    }

    fn cr3(&mut self) -> Result<u64, TracerError> {
        match self {
            #[cfg(windows)]
            Self::Whvp(tracer) => tracer.cr3(),
            Self::Bochs(tracer) => tracer.cr3()
        }
    }

    fn singlestep<H: trace::Hook>(&mut self, params: &trace::Params, hook: &mut H) -> Result<trace::Trace, TracerError> {
        match self {
            #[cfg(windows)]
            Self::Whvp(tracer) => tracer.singlestep(params, hook),
            Self::Bochs(tracer) => tracer.singlestep(params, hook)
        }
    }

    fn add_breakpoint(&mut self, address: u64) {
        match self {
            #[cfg(windows)]
            Self::Whvp(tracer) => tracer.add_breakpoint(address),
            Self::Bochs(tracer) => tracer.add_breakpoint(address)
        }

    }

    fn get_mapped_pages(&self) -> Result<usize, TracerError> {
        match self {
            #[cfg(windows)]
            Self::Whvp(tracer) => tracer.get_mapped_pages(),
            Self::Bochs(tracer) => tracer.get_mapped_pages()
        }
    }
}

impl<'a, S> X64VirtualAddressSpace for Backend<'a, S>
where S: snapshot::Snapshot + X64VirtualAddressSpace {

    fn read_gpa(&self, gpa: u64, buf: &mut [u8]) -> Result<(), VirtMemError> {
        match self {
            #[cfg(windows)]
            Self::Whvp(tracer) => tracer.read_gpa(gpa, buf),
            Self::Bochs(tracer) => tracer.read_gpa(gpa, buf)
        }
    }

    fn write_gpa(&mut self, gpa: u64, data: &[u8]) -> Result<(), VirtMemError> {
        match self {
            #[cfg(windows)]
            Self::Whvp(tracer) => tracer.write_gpa(gpa, data),
            Self::Bochs(tracer) => tracer.write_gpa(gpa, data)
        }
    }
}

pub struct Rewind {
}

impl Rewind
{
    pub fn new() -> Self {
        Self {
        }
    }

}

impl Default for Rewind {

    fn default() -> Self {
        Self::new()
    }
}

pub trait CliExt {

    type TraceHook: trace::Hook + Default;
    type FuzzerHook: trace::Hook + Default;

    fn create_tracer_hook(&self) -> Self::TraceHook;

    fn create_fuzzer_hook(&self) -> Self::FuzzerHook;

    fn handle_trace_run(&self, args: &TracerRun) -> Result<()>
    {
        let progress = helpers::start();
        let progress = progress.enter("Running tracer");

        progress.single("loading snapshot");
        let dump_path = args.snapshot.join("mem.dmp");

        let fp = std::fs::File::open(&dump_path)?;
        let buffer = unsafe { MmapOptions::new().map(&fp)? };

        let snapshot = DumpSnapshot::new(&buffer)?;

        let context_path = args.snapshot.join("context.json");
        let context = trace::ProcessorState::load(&context_path)?;

        let params_path = args.snapshot.join("params.json");
        let mut params = trace::Params::load(&params_path)?;

        params.limit = args.limit;
        params.save_context = args.save_context;
        params.max_duration = std::time::Duration::from_secs(args.max_time);
        params.coverage_mode = args.coverage.clone();

        progress.single(format!("will use {} backend", args.backend));
        let mut tracer = match args.backend {
            crate::BackendType::Bochs => {
                Backend::Bochs(rewind_bochs::BochsTracer::new(&snapshot))

            },
            #[cfg(windows)]
            crate::BackendType::Whvp => {
                Backend::Whvp(rewind_whvp::WhvpTracer::new(&snapshot)?)
            }
        };

        progress.single(format!("setting tracer initial state\n{}", &context));
        tracer.set_state(&context)?;

        match (&args.input, &args.data) {
            (Some(input_path), Some(filename)) => {

                progress.single(format!("replaying input {:?}", filename));
                let input = trace::Input::load(&input_path)?;

                let cr3 = context.cr3;

                let mut file = std::fs::File::open(filename)?;
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer)?;

                let address = input.address;
                let size: u64 = input.size;

                progress.single(format!("writing input to {:x} ({:x})", address, size));
                Tracer::write_gva(&mut tracer, cr3, address, &buffer[..0x1000]).wrap_err("can't write fuzzer input")?;
            }
            (Some(input_path), None) => {
                let input = trace::Input::load(&input_path)?;
                
                let size: u64 = input.size;
                let mut data = vec![0u8; size as usize];

                let cr3 = context.cr3;
                tracer.read_gva(cr3, input.address, &mut data)?;

                if let Some(path) = &args.save_input {
                    progress.single(format!("saving input to {:?} ({:x})", path, size));
                    let mut file = std::fs::File::create(path)?;
                    file.write_all(&data)?;
                }

            }
            _ => ()
        }

        progress.single("running tracer");
        let mut trace = trace::Trace::new();

        let start = Instant::now();

        let mut hook = self.create_tracer_hook();

        hook.setup(&mut tracer);

        // FIXME: should be in tracer.run
        // singlestep doesn't need hook and params
        loop {

            let mut bp_trace = tracer.run(&params, &mut hook)?;
            trace.seen.append(&mut bp_trace.seen);
            trace.coverage.append(&mut bp_trace.coverage);
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

        if let Some(path) = &args.trace {
            trace.save(&path)?;
        }

        if args.show_coverage {
            if let Some(path) = &args.store {
                if !path.exists() {
                    progress.warn("symbol store doesn't exist");

                    progress.single("creating symbol store directories");
                    std::fs::create_dir(&path)?;
                    std::fs::create_dir(path.join("binaries"))?;
                    std::fs::create_dir(path.join("symbols"))?;
                }

                // FIXME: need to resolve lifetime issues in bochs
                // let snapshot = DumpSnapshot::new(static_ref)?;
                let mut system = system::System::new(&snapshot)?;

                let progress = progress.leave();
                let progress = progress.enter("Analysing trace");

                progress.single("loading modules");
                system.load_modules()?;

                let mut store = pdbstore::PdbStore::new(path)?;
                // FIXME: rename collection and move definition
                let mut collection = ui::Collection::new();

                progress.single("parsing trace");
                ui::parse_trace(&mut collection, &mut trace, &system, &mut store)?;

                progress.single("displaying coverage");

                let mut functions: Vec<_> = collection.functions.iter().collect();
                functions.sort();

                for (name, instructions) in functions.iter() {
                    // FIXME: compute percentage
                    println!("{}: {} instructions", &name, instructions.coverage);

                }

                if args.show_instructions {
                    let skip = args.skip_instructions.unwrap_or(0);

                    progress.single("displaying instructions");
                    let instructions = trace.coverage.iter()
                        .map(|(addr, _context)| {
                        addr
                    }).enumerate();

                    let instructions: Box<dyn Iterator<Item = (usize, &u64)>> = if args.last {
                        if let Some(count) = args.instructions_count {
                            Box::new(instructions.rev().skip(skip).take(count).rev())
                        } else {
                            Box::new(instructions.rev().skip(skip).rev())
                        }
                    } else if let Some(count) = args.instructions_count {
                        Box::new(instructions.skip(skip).take(count))
                    } else {
                        Box::new(instructions.skip(skip))
                    };

                    for (index, addr) in instructions {
                        let mut bytes = vec![0u8; 16];
                        system.snapshot.read_gva(context.cr3, *addr, &mut bytes)?;
                        let instruction = decode_instruction(&bytes)?;
                        let n = instruction.length as usize;
                        let formatted_instruction = format_instruction(*addr, instruction)?;

                        let mut formatted_bytes = String::with_capacity(2 * n);
                        for byte in &bytes[..n] {
                            write!(formatted_bytes, "{:02x}", byte)?;
                        }
                        
                        let text = match store.resolve_address(*addr) {
                            Some(symbol) => {
                                format!("instruction #{}\n{}\n{:016x} {:<32}{:<20}", index, symbol, *addr, formatted_bytes, formatted_instruction)
                            }
                            None => {
                                format!("instruction #{}\n{:016x} {:<32}{:<20}", index, *addr, formatted_bytes, formatted_instruction)
                            }
                        };

                        if let Some(filter) = &args.filter {
                            let pattern = filter.to_lowercase();
                            if text.to_lowercase().matches(&pattern).count() > 0 {
                                println!("{}", text);
                            }
                        } else {
                            println!("{}", text);
                        }

                    }

                }

            } else {
                progress.warn("need a symbol store to show coverage (--store is missing)")
            }

        }

        Ok(())
    }

    fn handle_fuzzer_init(&self, args: &FuzzerInit) -> Result<()> {

        let progress = helpers::start();
        let progress = progress.enter("Init fuzzer");

        progress.single("checking parameters");

        let path = &args.workdir;
        if path.exists() {
            bail!("can't init fuzzer, working directory exists");
        }

        let mut fuzz_params = fuzz::Params::default();

        let mut input = trace::Input::default();

        let input_address = u64::from_str_radix(&args.input_address.trim_start_matches("0x"), 16)
            .wrap_err_with(|| "can't parse input address")?;

        input.address = input_address;
        fuzz_params.input = input_address;

        let input_size = u64::from_str_radix(&args.input_size.trim_start_matches("0x"), 16)
            .wrap_err_with(|| "can't parse input size")?;

        input.size = input_size;
        fuzz_params.input_size = input_size;

        let snapshot_path = &args.snapshot;

        progress.single("checking snapshot");
        let dump_path = snapshot_path.join("mem.dmp");

        let fp = std::fs::File::open(&dump_path).wrap_err_with(|| "can't open snapshot")?;
        let buffer = unsafe { MmapOptions::new().map(&fp)? };

        let _snapshot = DumpSnapshot::new(&buffer)?;

        let context_path = snapshot_path.join("context.json");
        let _context = trace::ProcessorState::load(&context_path)?;

        let params_path = snapshot_path.join("params.json");
        let _params = trace::Params::load(&params_path)?;

        std::fs::create_dir(&path)?;
        std::fs::create_dir(path.join("corpus"))?;
        std::fs::create_dir(path.join("crashes"))?;
        std::fs::create_dir(path.join("traces"))?;
        std::fs::create_dir(path.join("instances"))?;

        progress.single("writing params");
        fuzz_params.snapshot_path =  std::fs::canonicalize(snapshot_path)?;
        fuzz_params.save(path.join("params.json"))?;
        input.save(path.join("input.json"))?;

        Ok(())
    }

    fn handle_fuzzer_run(&self, args: &FuzzerRun) -> Result<()> {

        let progress = helpers::start();
        let progress = progress.enter("Launching fuzzer");

        progress.single("Loading parameters");
        let input_path = args.workdir.join("params.json");
        let mut fuzz_params = fuzz::Params::load(&input_path)?;
 
        progress.single("Using random strategy");
        // FIXME: strategy should be check from param
        // FIXME: strategy params should be in args too
        // FIXME: input mutation should be in mutation hints
        let mut strategy = mutation::BasicStrategy::new(fuzz_params.input_size as usize);

        // FIXME: input_size used twice ...
        if let Some(range) = args.range.as_ref() {
            progress.single(format!("Will fuzz {} range", range));
            strategy.range(range.clone());
        } else {
            let range = mutation::Range::new()
                .low(0)
                .high(fuzz_params.input_size as usize);
            strategy.range(range);
        }

        fuzz_params.max_duration = std::time::Duration::from_secs(args.max_time);
        fuzz_params.max_iterations = args.max_iterations;
        fuzz_params.stop_on_crash = args.stop_on_crash;

        let snapshot_path = &fuzz_params.snapshot_path;

        progress.single("Loading snapshot");
        let dump_path = snapshot_path.join("mem.dmp");

        let fp = std::fs::File::open(&dump_path)?;
        let buffer = unsafe { MmapOptions::new().map(&fp)? };

        let snapshot = DumpSnapshot::new(&buffer)?;

        let context_path = snapshot_path.join("context.json");
        let context = trace::ProcessorState::load(&context_path)?;

        let params_path = snapshot_path.join("params.json");
        let mut trace_params = trace::Params::load(&params_path)?;

        trace_params.coverage_mode = args.coverage.clone();
        trace_params.max_duration = std::time::Duration::from_secs(args.max_time);

        let mut fuzzer = fuzz::Fuzzer::new(&args.workdir)?;

        progress.single(format!("Fuzzing function {:x} with input {:x} ({:x})", context.rip, fuzz_params.input, fuzz_params.input_size));

        let mut tracer = match args.backend {
            crate::BackendType::Bochs => {
                Backend::Bochs(rewind_bochs::BochsTracer::new(&snapshot))

            },
            #[cfg(windows)]
            crate::BackendType::Whvp => {
                Backend::Whvp(rewind_whvp::WhvpTracer::new(&snapshot)?)
            }
        };
        
        let mut corpus = corpus::Corpus::new(&args.workdir);

        let mut hook = self.create_fuzzer_hook();

        // FIXME: handle properly ctrlc

        if args.verbose > 0 {
            let progress_bar = indicatif::ProgressBar::new_spinner();
            progress_bar.enable_steady_tick(250);
            progress_bar.set_style(indicatif::ProgressStyle::default_spinner().template("{spinner} {elapsed} {msg}"));

            let mut last_updated = std::time::Instant::now();

            fuzzer.callback( move |stats| {
                if last_updated.elapsed() > std::time::Duration::from_millis(1000) {
                    let elapsed = chrono::Utc::now() - stats.start;
                    let num_seconds = std::cmp::max(1, elapsed.num_seconds());
    
                    let message = format!("{} iterations, {} exec/s, coverage {}, mapped pages {} ({}), corpus {}, crashes {}",
                        stats.iterations,
                        stats.iterations / num_seconds as u64,
                        stats.coverage,
                        stats.mapped_pages,
                        indicatif::HumanBytes((stats.mapped_pages * 0x1000) as u64),
                        stats.corpus_size,
                        stats.crashes);

                    progress_bar.set_message(&message);
                    last_updated = std::time::Instant::now();
                }
                if stats.done {
                    progress_bar.finish_and_clear();
                }
            });
        }

        let stats = fuzzer.run(&mut corpus, &mut strategy, &fuzz_params, &mut tracer, &context, &trace_params, &mut hook)?;

        progress.single(format!("Session ended after {:?} and {} iteration(s), got {} crash(es)",
            stats.elapsed(), stats.iterations, stats.crashes));

        Ok(())
    }

    fn handle_fuzzer_monitor(&self, args: &FuzzerMonitor) -> Result<()> {
        // monitor hook
        ui::display_tui::<<Self as CliExt>::TraceHook>(args.workdir.clone(), args.store.clone())?;

        Ok(())
    }

    fn run(&self) -> Result<()>
    {
        let args = RewindArgs::parse();
        match &args.subcmd {
            SubCommand::Trace(t) => {
                match &t.subcmd {
                    TraceSubCommand::Run(t) => self.handle_trace_run(t)
                }
            }
            SubCommand::Fuzz(t) => {
                match &t.subcmd {
                    FuzzerSubCommand::Init(t) => self.handle_fuzzer_init(t),
                    FuzzerSubCommand::Run(t) => self.handle_fuzzer_run(t),
                    FuzzerSubCommand::Monitor(t) => self.handle_fuzzer_monitor(t)
                }
            }
        }
    }
}

impl CliExt for Rewind
{
    type TraceHook = NoHook;
    type FuzzerHook = NoHook;

    fn create_fuzzer_hook(&self) -> Self::FuzzerHook {
        NoHook::default()
    }

    fn create_tracer_hook(&self) -> Self::TraceHook {
        NoHook::default()
    }
}

#[derive(Clap, Debug)]
#[clap(name="rewind", version=crate_version!(), author="Damien Aumaitre")]
struct RewindArgs {
    #[clap(subcommand)]
    pub subcmd: SubCommand,

}

#[derive(Clap, Debug)]
pub enum SubCommand {
    Trace(Trace),
    Fuzz(Fuzz)
}

#[derive(Clap, Debug)]
pub struct Trace {
    #[clap(subcommand)]
    pub subcmd: TraceSubCommand
}


#[derive(Clap, Debug)]
pub enum TraceSubCommand {
    Run(TracerRun)
}

#[derive(Clap, Debug)]
pub struct Fuzz {
    #[clap(subcommand)]
    pub subcmd: FuzzerSubCommand
}


#[derive(Clap, Debug)]
pub enum FuzzerSubCommand {
    Init(FuzzerInit),
    Run(FuzzerRun),
    Monitor(FuzzerMonitor),

}

#[derive(Clap, Debug)]
#[clap(author="Damien Aumaitre")]
pub struct TracerRun {
    /// Set the level of verbosity
    #[clap(long, short, parse(from_occurrences))]
    pub verbose: usize,
 
    /// Snapshot path
    #[clap(long, parse(from_os_str))]
    pub snapshot: std::path::PathBuf,

    #[clap(long="limit", default_value="0")]
    pub limit: u64,

    #[clap(long="save-context")]
    pub save_context: bool,

    #[clap(long="max-time", default_value="0")]
    pub max_time: u64,

    /// Save trace to file
    #[clap(long="save-trace", parse(from_os_str))]
    pub trace: Option<std::path::PathBuf>,

    #[clap(long="backend", possible_values(&["whvp", "bochs"]), default_value="bochs")]
    pub backend: crate::BackendType,

    #[clap(long="coverage", possible_values(&["no", "instrs", "hit"]), default_value="no")]
    pub coverage: rewind_core::trace::CoverageMode,

    /// JSON file describing input
    #[clap(long="input", parse(from_os_str))]
    pub input: Option<std::path::PathBuf>,

    /// Input data
    #[clap(long="data", parse(from_os_str))]
    pub data: Option<std::path::PathBuf>,

    /// Save input to file
    #[clap(long="save-input", parse(from_os_str))]
    pub save_input: Option<std::path::PathBuf>,

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

    /// Symbol store
    #[clap(long="store", parse(from_os_str))]
    pub store: Option<std::path::PathBuf>,

}

#[derive(Clap, Debug)]
pub struct FuzzerInit {
    /// Path to snapshot
    #[clap(long="snapshot", parse(from_os_str))]
    pub snapshot: std::path::PathBuf,

    /// Fuzzer work directory
    #[clap(parse(from_os_str))]
    pub workdir: std::path::PathBuf,

    /// Input address
    #[clap(long="input-address")]
    pub input_address: String,

    /// Input size
    #[clap(long="input-size")]
    pub input_size: String,

}

#[derive(Clap, Debug)]
#[clap(author="Damien Aumaitre")]
pub struct FuzzerRun {
    /// Set the level of verbosity
    #[clap(long, short, parse(from_occurrences))]
    pub verbose: usize,
 
    #[clap(long="max-iterations", default_value="0")]
    pub max_iterations: u64,

    #[clap(long="stop-on-crash")]
    pub stop_on_crash: bool,

    #[clap(long="max-time", default_value="0")]
    pub max_time: u64,

    #[clap(long="backend", possible_values(&["whvp", "bochs"]), default_value="bochs")]
    pub backend: crate::BackendType,

    #[clap(long="coverage", possible_values(&["no", "instrs", "hit"]), default_value="hit")]
    pub coverage: rewind_core::trace::CoverageMode,

    #[clap(long="range")]
    pub range: Option<rewind_core::mutation::Range>,

    #[clap(parse(from_os_str))]
    pub workdir: std::path::PathBuf,

}

#[derive(Clap, Debug)]
#[clap(author="Damien Aumaitre")]
pub struct FuzzerMonitor {
    /// Set the level of verbosity
    #[clap(long, short, parse(from_occurrences))]
    pub verbose: usize,

    #[clap(parse(from_os_str))]
    pub workdir: std::path::PathBuf,

    #[clap(parse(from_os_str))]
    pub store: std::path::PathBuf,

}



fn decode_instruction(buffer: &[u8]) -> Result<zydis::DecodedInstruction> {
    let decoder = zydis::Decoder::new(zydis::MachineMode::LONG_64, zydis::AddressWidth::_64)?;
    let result = decoder.decode(&buffer)?;
    if let Some(instruction) = result {
        Ok(instruction)
    } else {
        Err(Report::msg("can't decode instruction".to_string()))
    }
}

fn format_instruction(rip: u64, instruction: zydis::DecodedInstruction) -> Result<String> {
    let mut formatter = zydis::Formatter::new(zydis::FormatterStyle::INTEL)?;
    formatter.set_property(zydis::FormatterProperty::HexUppercase(false))?;
    let mut buffer = [0u8; 200];
    let mut buffer = zydis::OutputBuffer::new(&mut buffer[..]);
    formatter.format_instruction(&instruction, &mut buffer, Some(rip as u64), None)?;
    let output = format!("{}", buffer);
    Ok(output)
}


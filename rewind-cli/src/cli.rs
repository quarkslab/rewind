
use std::{collections::{BTreeSet, HashMap}, fmt::Write as FmtWrite};
use std::io::{Read, Write};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use color_eyre::{Report, eyre::{bail, Result, WrapErr}};

use clap::{Clap, crate_version};

use memmap::MmapOptions;

use rewind_core::{fuzz, mem::{X64VirtualAddressSpace, VirtMemError}, snapshot, mutation, trace::{self, Tracer, TracerError}};

use rewind_snapshot::DumpSnapshot;

use rewind_system::{system, pdbstore};

use rewind_tui::ui;
use trace::ProcessorState;


use crate::helpers;
#[allow(clippy::large_enum_variant)]
pub enum Backend<'a, S>
where S: snapshot::Snapshot {

    Whvp(rewind_whvp::WhvpTracer<'a, S>),
    Bochs(rewind_bochs::BochsTracer<'a, S>)
}

impl<'a, S> trace::Tracer for Backend<'a, S>
where S: snapshot::Snapshot + X64VirtualAddressSpace {

    fn get_state(&mut self) -> Result<trace::ProcessorState, TracerError> {
        match self {
            Self::Whvp(tracer) => tracer.get_state(),
            Self::Bochs(tracer) => tracer.get_state()
        }
    }

    fn set_state(&mut self, state: &trace::ProcessorState) -> Result<(), TracerError> {
        match self {
            Self::Whvp(tracer) => tracer.set_state(state),
            Self::Bochs(tracer) => tracer.set_state(state)
        }
    }

    fn run<H: trace::Hook>(&mut self, params: &trace::Params, hook: &mut H) -> Result<trace::Trace, TracerError> {
        match self {
            Self::Whvp(tracer) => tracer.run(params, hook),
            Self::Bochs(tracer) => tracer.run(params, hook)
        }
    }

    fn restore_snapshot(&mut self) -> Result<usize, TracerError> {
        match self {
            Self::Whvp(tracer) => tracer.restore_snapshot(),
            Self::Bochs(tracer) => tracer.restore_snapshot()
        }
    }

    fn read_gva(&mut self, cr3: u64, vaddr: u64, data: &mut [u8]) -> Result<(), TracerError> {
        match self {
            Self::Whvp(tracer) => tracer.read_gva(cr3, vaddr, data),
            Self::Bochs(tracer) => tracer.read_gva(cr3, vaddr, data)
        }
    }

    fn write_gva(&mut self, cr3: u64, vaddr: u64, data: &[u8]) -> Result<(), TracerError> {
        match self {
            Self::Whvp(tracer) => Tracer::write_gva(tracer, cr3, vaddr, data),
            Self::Bochs(tracer) => Tracer::write_gva(tracer, cr3, vaddr, data)
        }
    }

    fn cr3(&mut self) -> Result<u64, TracerError> {
        match self {
            Self::Whvp(tracer) => tracer.cr3(),
            Self::Bochs(tracer) => tracer.cr3()
        }
    }

    fn singlestep<H: trace::Hook>(&mut self, params: &trace::Params, hook: &mut H) -> Result<trace::Trace, TracerError> {
        match self {
            Self::Whvp(tracer) => tracer.singlestep(params, hook),
            Self::Bochs(tracer) => tracer.singlestep(params, hook)
        }
    }

    fn add_breakpoint(&mut self, address: u64) {
        match self {
            Self::Whvp(tracer) => tracer.add_breakpoint(address),
            Self::Bochs(tracer) => tracer.add_breakpoint(address)
        }

    }

    fn get_mapped_pages(&self) -> Result<usize, TracerError> {
        match self {
            Self::Whvp(tracer) => tracer.get_mapped_pages(),
            Self::Bochs(tracer) => tracer.get_mapped_pages()
        }
    }
}

impl<'a, S> X64VirtualAddressSpace for Backend<'a, S>
where S: snapshot::Snapshot + X64VirtualAddressSpace {

    fn read_gpa(&self, gpa: u64, buf: &mut [u8]) -> Result<(), VirtMemError> {
        match self {
            Self::Whvp(tracer) => tracer.read_gpa(gpa, buf),
            Self::Bochs(tracer) => tracer.read_gpa(gpa, buf)
        }
    }

    fn write_gpa(&mut self, gpa: u64, data: &[u8]) -> Result<(), VirtMemError> {
        match self {
            Self::Whvp(tracer) => tracer.write_gpa(gpa, data),
            Self::Bochs(tracer) => tracer.write_gpa(gpa, data)
        }
    }
}

pub struct Rewind<H> {
    args: RewindArgs,
    progress: helpers::Progress,
    _marker: std::marker::PhantomData<H>

}

impl <H> Rewind <H>
where H: trace::Hook + Default
{
    pub fn parse_args() -> Self {
        let args = RewindArgs::parse();

        let progress = helpers::start();

        Self {
            args,
            progress,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn handle_trace_run(&self, args: &TracerRun) -> Result<()>
    {
        let progress = self.progress.enter("Running tracer");

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

        let mut hook = H::default();

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
                parse_trace(&mut collection, &mut trace, &system, &mut store)?;

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

    pub fn handle_fuzzer_init(&self, args: &FuzzerInit) -> Result<()> {
        let progress = self.progress.enter("Init fuzzer");

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

        let snapshot_path = &fuzz_params.snapshot_path;

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
        fuzz_params.save(path.join("params.json"))?;
        input.save(path.join("input.json"))?;

        Ok(())
    }

    pub fn handle_fuzzer_run(&self, args: &FuzzerRun) -> Result<()> {
        let progress = self.progress.enter("Launching fuzzer");

        progress.single("Loading parameters");
        let input_path = args.workdir.join("params.json");
        let mut fuzz_params = fuzz::Params::load(&input_path)?;
 
        progress.single("Using random strategy");
        // FIXME: strategy should be check from param
        // FIXME: strategy params should be in args too
        // FIXME: input mutation should be in mutation hints
        let mut strategy = mutation::BasicStrategy::new();

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
            crate::BackendType::Whvp => {
                Backend::Whvp(rewind_whvp::WhvpTracer::new(&snapshot)?)
            }
        };
        
        let mut corpus = fuzz::Corpus::new(&args.workdir);

        let mut hook = H::default();

        if args.verbose > 0 {
            let progress_bar = indicatif::ProgressBar::new_spinner();
            progress_bar.enable_steady_tick(250);
            progress_bar.set_style(indicatif::ProgressStyle::default_spinner().template("{spinner} {elapsed} {msg}"));

            let mut last_updated = std::time::Instant::now();

            fuzzer.callback( move |stats| {
                if last_updated.elapsed() > std::time::Duration::from_millis(1000) {
                    let elapsed = chrono::Utc::now() - stats.start;
                    let num_seconds = std::cmp::max(1, elapsed.num_seconds());
    
                    let message = format!("{} executions, {} exec/s, coverage {}, mapped pages {} ({}), corpus {}, crashes {}",
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

    pub fn handle_fuzzer_monitor(&self, args: &FuzzerMonitor) -> Result<()> {
        let (tx, rx) = flume::unbounded();
        let (control_instance_tx, control_instance_rx) = flume::unbounded();
        let (control_coverage_tx, control_coverage_rx) = flume::unbounded();

        start_coverage_collector_thread::<H>(control_coverage_rx, tx.clone());
        start_instances_collector_thread(control_instance_rx, tx);

        control_coverage_tx.send(Control::Start((args.workdir.clone(), args.store.clone())))?;
        control_instance_tx.send(Control::Start((args.workdir.clone(), args.store.clone())))?;

        if args.ui {
            display_tui(rx)?;
        }

        Ok(())
    }

    // FIXME: insert sanitizer, configure timeout for trace, remove useless corpus entries

    pub fn run(&self) -> Result<()>
    {
        match &self.args.subcmd {
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
                    // FIXME: monitor
                }
            }
        }
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

    // #[clap(long="display-delay", default_value="1")]
    // pub display_delay: u64,

    #[clap(long="max-time", default_value="0")]
    pub max_time: u64,

    #[clap(long="backend", possible_values(&["whvp", "bochs"]), default_value="bochs")]
    pub backend: crate::BackendType,

    #[clap(long="coverage", possible_values(&["no", "instrs", "hit"]), default_value="hit")]
    pub coverage: rewind_core::trace::CoverageMode,

    #[clap(parse(from_os_str))]
    pub workdir: std::path::PathBuf,

}

#[derive(Clap, Debug)]
#[clap(author="Damien Aumaitre")]
pub struct FuzzerMonitor {
    /// Set the level of verbosity
    #[clap(long, short, parse(from_occurrences))]
    pub verbose: usize,

    #[clap(long="max-time", default_value="0")]
    pub max_time: u64,

    #[clap(parse(from_os_str))]
    pub workdir: std::path::PathBuf,

    #[clap(parse(from_os_str))]
    pub store: std::path::PathBuf,

    #[clap(long="ui")]
    pub ui: bool,

}

fn parse_trace(collection: &mut ui::Collection, trace: &mut trace::Trace, system: &system::System, store: &mut pdbstore::PdbStore) -> Result<()> {

    for &address in trace.seen.difference(&collection.coverage) {
        if let Some(module) = system.get_module_by_address(address) {
            *collection.modules.entry(module.name.clone()).or_insert_with(|| {

                // FIXME: need a fn in system.rs
                if let Ok(info) = system.get_file_information(module) {
                    if store.download_pe(&module.name, &info).is_ok() {

                    }
                }

                if let Ok(info) = system.get_debug_information(module) {
                    let (name, guid) = info.into();
                    if store.download_pdb(&name, &guid).is_ok() && store.load_pdb(module.base, &name, &guid).is_ok() {

                    }
                }

                0
            }) += 1;

            if let Some(symbol) = store.resolve_address(address) {
                // FIXME: get size of symbol and size of func
                let name = format!("{}!{}", symbol.module, symbol.name);
                collection.functions.entry(name)
                    .and_modify(|f| f.coverage += 1)
                    .or_insert_with(|| {
                        ui::Function::new(symbol.module, symbol.name, 1)
                    });
            }
        }
    }

    collection.coverage.append(&mut trace.seen);

    Ok(())
}

fn replay_file<H: trace::Hook>(_tx: &flume::Sender<Message>,
        path: &std::path::Path,
        tracer: &mut rewind_bochs::BochsTracer<DumpSnapshot>,
        context: &ProcessorState,
        trace_params: &trace::Params,
        fuzz_params: &fuzz::Params) -> Result<trace::Trace> {

    // tx.send(Message::Log(format!("replaying {}", path.display())))?;

    let mut file = std::fs::File::open(&path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    let cr3 = context.cr3;

    match Tracer::write_gva(tracer, cr3, fuzz_params.input, &data) {
        Ok(()) => {}
        Err(e) => {
            return Err(Report::msg(format!("can't write input {}", e)));
        }
    }

    tracer.set_state(&context)?;

    let mut hook = H::default();
    hook.setup(tracer);

    let mut trace = tracer.run(&trace_params, &mut hook)?;

    hook.handle_trace(&mut trace)?;
    tracer.restore_snapshot()?;

    Ok(trace)

}

fn collect_coverage_thread<H: trace::Hook>(control_rx: flume::Receiver<Control>, tx: flume::Sender<Message>) -> Result<()> {
    loop {

        let control = control_rx.recv()?;

        match control {
            Control::Start((workdir, store)) => {
                let input_path = workdir.join("params.json");
                let fuzz_params = fuzz::Params::load(&input_path)?;

                let snapshot_path = &fuzz_params.snapshot_path;

                let dump_path = snapshot_path.join("mem.dmp");

                let fp = std::fs::File::open(&dump_path)?;
                let buffer = unsafe { MmapOptions::new().map(&fp)? };

                let snapshot = DumpSnapshot::new(&buffer)?;

                let context_path = snapshot_path.join("context.json");
                let context = trace::ProcessorState::load(&context_path)?;

                let params_path = snapshot_path.join("params.json");
                let trace_params = trace::Params::load(&params_path)?;

                // trace_params.max_duration = std::time::Duration::from_secs(args.max_time);

                let mut tracer = rewind_bochs::BochsTracer::new(&snapshot);

                let mut system = system::System::new(&snapshot)?;
                system.load_modules()?;

                let path = &store;
                if !path.exists() {
                    std::fs::create_dir(&path)?;
                    std::fs::create_dir(path.join("binaries"))?;
                    std::fs::create_dir(path.join("symbols"))?;
                }

                let mut store = pdbstore::PdbStore::new(path)?;

                let mut hints = mutation::MutationHint::new();

                let mut known_files: BTreeSet<String> = std::collections::BTreeSet::new();
                    
                let mut collection = ui::Collection::new();

                let mut need_update = false;

                loop {
                    let path = workdir.join("corpus");
                    let mut entries = std::fs::read_dir(&path)?
                        .map(|res| res.map(|e| e.path()))
                        .collect::<Result<Vec<_>, std::io::Error>>()?;

                    let path = workdir.join("crashes");
                    let crash_entries = std::fs::read_dir(&path)?
                        .map(|res| res.map(|e| e.path()))
                        .collect::<Result<Vec<_>, std::io::Error>>()?;

                    entries.extend(crash_entries);
                    entries.sort();

                    for path in entries {
                        let filename = path.file_name().unwrap().to_str().unwrap().to_string();
                        if known_files.get(&filename).is_some() {
                            continue
                        }

                        if path.extension() == Some(std::ffi::OsStr::new("bin")) {
                            need_update = true;
                            let mut trace = replay_file::<H>(&tx, &path, &mut tracer, &context, &trace_params, &fuzz_params)?;

                            let corpus_path = path.to_path_buf();

                            let mut corpus_file = ui::CorpusFile::new(corpus_path.file_name().unwrap());
                            corpus_file.seen = trace.seen.len() as u64;
                            corpus_file.count = trace.coverage.len() as u64;

                            match trace.status {
                                trace::EmulationStatus::Success => {
                                    tx.send(Message::Corpus(corpus_file))?;
                                },
                                _ => {
                                    tx.send(Message::Crash(corpus_file))?;
                                }
                            }

                            known_files.insert(filename);

                            let functions = collection.functions.clone();
                            tx.send(Message::Coverage(functions))?;

                            hints.immediates.append(&mut trace.immediates);
                            let address = fuzz_params.input;
                            let size = fuzz_params.input_size;
                            let filtered = trace.mem_access.iter()
                                .filter(|a| {
                                    a.1 >= address && a.1 < address + size
                                })
                                .map(|a| {
                                    a.1 - address
                                });

                            hints.offsets.extend(filtered);

                            if trace.seen.is_subset(&collection.coverage) {
                                std::fs::remove_file(&path)?;
                            } else {
                                parse_trace(&mut collection, &mut trace, &system, &mut store)?;
                                trace.save(workdir.join("traces").join(format!("{}.json", path.file_name().unwrap().to_str().unwrap())))?;
                            }
                        }
                    }

                    if need_update {
                        tx.send(Message::Log(format!("immediates {}, offsets {}", hints.immediates.len(), hints.offsets.len())))?;
                        tx.send(Message::Log(format!("unique addresses {}, {} modules, {} functions", collection.coverage.len(), collection.modules.len(), collection.functions.len())))?;
                        let path = workdir.join("hints.json");
                        hints.save(&path)?;
                        need_update = false;
                        
                    }

                    // if !control_rx.is_empty() {
                    //     tx.send(Message::Log("someone talked to me".to_string()))?;
                    //     break
                    // }

                    std::thread::sleep(std::time::Duration::from_secs(2));
                }
            },
            _ => {
                tx.send(Message::Log("stopping coverage thread".to_string()))?;
                return Ok(())
            }
        }

    }

}

#[derive(Debug)]
enum Control {
    Start((std::path::PathBuf, std::path::PathBuf)),
    Stop,
}

#[derive(Debug)]
enum Message {
    Instances(HashMap<std::path::PathBuf, fuzz::Stats>),
    Log(String),
    Coverage(HashMap<String, ui::Function>),
    Corpus(ui::CorpusFile),
    Crash(ui::CorpusFile),
}

fn start_coverage_collector_thread<H: trace::Hook>(control_rx: flume::Receiver<Control>, tx: flume::Sender<Message>) {
    thread::spawn( move || {
        let result = collect_coverage_thread::<H>(control_rx, tx);
        println!("thread returned {:?}", result);
    });
}

fn start_instances_collector_thread(control_rx: flume::Receiver<Control>, tx: flume::Sender<Message>) {
    thread::spawn( move || {
        let result = collect_instances_thread(control_rx, tx);
        println!("thread returned {:?}", result);
    });
 
}

fn collect_instances_thread(control_rx: flume::Receiver<Control>, tx: flume::Sender<Message>) -> Result<()> {
    loop {
        let control = control_rx.recv()?;
        match control {
            Control::Start((workdir, _store)) => {
                loop {
                    let path = workdir.join("instances");
                    let mut entries = std::fs::read_dir(&path)?
                        .map(|res| res.map(|e| e.path()))
                        .collect::<Result<Vec<_>, std::io::Error>>()?;

                    entries.sort();

                    let mut instances = HashMap::new();
                    for path in entries {
                        if path.extension() == Some(std::ffi::OsStr::new("json")) {
                            let stats = fuzz::Stats::load(&path)?;

                            let filename = path.to_path_buf();
                            instances.insert(filename, stats);
                        }
                    }
                        
                    tx.send(Message::Instances(instances))?;

                    if !control_rx.is_empty() {
                        break
                    }

                    std::thread::sleep(std::time::Duration::from_secs(2));
                }

            },
            _ => {
                tx.send(Message::Log("stopping thread".to_string()))?;
                return Ok(())
            }
        }
 
    }
}



fn display_tui(data_rx: flume::Receiver<Message>) -> Result<()> {
    let stdout_val = ui::setup_terminal()?;

    let backend = ui::CrosstermBackend::new(stdout_val);

    let mut terminal = ui::Terminal::new(backend)?;

    // Setup input handling
    let (tx, rx) = mpsc::channel();
    let collector_tx = tx.clone();

    let tick_rate = Duration::from_millis(250);
    // polling thread
    thread::spawn(move || {
        let mut last_tick = Instant::now();
        loop {
            // poll for tick rate duration, if no events, sent tick event.
            let timeout = tick_rate
                .checked_sub(last_tick.elapsed())
                .unwrap_or_else(|| Duration::from_secs(0));

            if ui::event::poll(timeout).unwrap() {
                if let ui::Event::Key(key) = ui::event::read().unwrap() {
                    tx.send(ui::TuiEvent::Input(key)).unwrap();
                }
            }
            if last_tick.elapsed() >= tick_rate {
                tx.send(ui::TuiEvent::Tick).unwrap();
                last_tick = Instant::now();
            }
        }
    });

    // collector thread
    thread::spawn(move || {
        while let Ok(message) = data_rx.recv() {
            match message {
                Message::Log(m) => {
                    let now: chrono::DateTime<chrono::Utc> = chrono::Utc::now();
                    let m = format!("{} {}", now.to_rfc2822(), m);
                    collector_tx.send(ui::TuiEvent::Log(m)).unwrap()
                },
                Message::Instances(i) => {
                    collector_tx.send(ui::TuiEvent::Instances(i)).unwrap()
                },
                Message::Coverage(c) => {
                    collector_tx.send(ui::TuiEvent::Coverage(c)).unwrap();
                },
                Message::Corpus(i) => {
                    collector_tx.send(ui::TuiEvent::Corpus(i)).unwrap();
                }
                Message::Crash(i) => {
                    collector_tx.send(ui::TuiEvent::Crash(i)).unwrap();
                }
            }
        }
    });

    let mut app = ui::App::new();

    terminal.clear()?;
    terminal.hide_cursor()?;

     loop {
        terminal.draw(|f| ui::draw(f, &mut app))?;
        match rx.recv()? {
            ui::TuiEvent::Input(event) => match event.code {
                ui::KeyCode::Char('q') => {
                    ui::cleanup_terminal(&mut terminal)?;
                    break;
                }
                ui::KeyCode::Char(c) => app.on_key(c),
                ui::KeyCode::Left => app.on_left(),
                ui::KeyCode::Right => app.on_right(),
                ui::KeyCode::Tab => app.on_tab(),
                ui::KeyCode::Up => app.on_up(),
                ui::KeyCode::Down => app.on_down(),
                ui::KeyCode::PageUp => app.on_page_up(),
                ui::KeyCode::PageDown => app.on_page_down(),
                _ => {}
            },
            ui::TuiEvent::Tick => {
                app.on_tick();
            },
            ui::TuiEvent::Coverage(c) => {
                app.on_collect(c);
            },
            ui::TuiEvent::Log(l) => {
                app.on_log(l)
            },
            ui::TuiEvent::Instances(i) => {
                app.on_instance(i)
            },
            ui::TuiEvent::Corpus(i) => {
                app.on_corpus(i)
            },
            ui::TuiEvent::Crash(i) => {
                app.on_crash(i)
            }
        }

    }

    Ok(())
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


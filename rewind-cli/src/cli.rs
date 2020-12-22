
use std::str::FromStr;
use std::io::{Read, Write, stdout};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use clap::{Clap, crate_version};

use rewind_core::{fuzz,
                  mutation,
                  trace::{self, Tracer}};

use rewind_snapshot::DumpSnapshot;

use rewind_system::{system, pdbstore};

use rewind_tui::ui;


use crate::helpers;

pub enum Backend<S>
where S: rewind_core::snapshot::Snapshot + 'static {

    Whvp(rewind_whvp::WhvpTracer<S>),
    Bochs(rewind_bochs::BochsTracer<S>)
}

impl<S> trace::Tracer for Backend<S>
where S: rewind_core::snapshot::Snapshot + rewind_core::mem::X64VirtualAddressSpace + 'static {

    fn get_state(&mut self) -> anyhow::Result<trace::ProcessorState> {
        match self {
            Self::Whvp(tracer) => tracer.get_state(),
            Self::Bochs(tracer) => tracer.get_state()
        }
    }

    fn set_state(&mut self, state: &trace::ProcessorState) -> anyhow::Result<()> {
        match self {
            Self::Whvp(tracer) => tracer.set_state(state),
            Self::Bochs(tracer) => tracer.set_state(state)
        }
    }

    fn run<H: trace::Hook>(&mut self, params: &trace::Params, hook: &mut H) -> anyhow::Result<trace::Trace> {
        match self {
            Self::Whvp(tracer) => tracer.run(params, hook),
            Self::Bochs(tracer) => tracer.run(params, hook)
        }
    }

    fn restore_snapshot(&mut self) -> anyhow::Result<usize> {
        match self {
            Self::Whvp(tracer) => tracer.restore_snapshot(),
            Self::Bochs(tracer) => tracer.restore_snapshot()
        }
    }

    fn read_gva(&mut self, cr3: u64, vaddr: u64, data: &mut [u8]) -> anyhow::Result<()> {
        match self {
            Self::Whvp(tracer) => tracer.read_gva(cr3, vaddr, data),
            Self::Bochs(tracer) => tracer.read_gva(cr3, vaddr, data)
        }
    }

    fn write_gva(&mut self, cr3: u64, vaddr: u64, data: &[u8]) -> anyhow::Result<()> {
        match self {
            Self::Whvp(tracer) => tracer.write_gva(cr3, vaddr, data),
            Self::Bochs(tracer) => tracer.write_gva(cr3, vaddr, data)
        }
    }

    fn cr3(&mut self) -> anyhow::Result<u64> {
        match self {
            Self::Whvp(tracer) => tracer.cr3(),
            Self::Bochs(tracer) => tracer.cr3()
        }
    }

    fn singlestep<H: trace::Hook>(&mut self, params: &trace::Params, hook: &mut H) -> anyhow::Result<trace::Trace> {
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

}

pub struct Rewind<H> {
    args: RewindArgs,
    progress: helpers::Progress,
    _phantom: std::marker::PhantomData<H>

}

impl <HH: trace::Hook> Rewind <HH> {
    pub fn parse_args() -> Self {
        let args = RewindArgs::parse();

        let progress = helpers::start();

        Self {
            args,
            progress,
            _phantom: std::marker::PhantomData
        }
    }

    pub fn handle_trace_run<H: trace::Hook>(&self, args: &TracerRun, hook: &mut H) -> anyhow::Result<()>
    {
        let progress = self.progress.enter("Running tracer");

        progress.single("loading snapshot");
        let dump_path = args.snapshot.join("mem.dmp");
        let snapshot = DumpSnapshot::new(&dump_path)?;

        let context_path = args.snapshot.join("context.json");
        let context = trace::ProcessorState::load(&context_path)?;

        let params_path = args.snapshot.join("params.json");
        let mut params = trace::Params::load(&params_path)?;

        params.limit = args.limit;
        params.save_context = args.save_context;
        params.max_duration = std::time::Duration::from_secs(args.max_time);
        params.coverage_mode = args.coverage.clone();

        let mut tracer = match args.backend {
            crate::BackendType::Bochs => {
                Backend::Bochs(rewind_bochs::BochsTracer::new(snapshot)?)

            },
            crate::BackendType::Whvp => {
                Backend::Whvp(rewind_whvp::WhvpTracer::new(snapshot)?)
            }
        };

        tracer.set_state(&context)?;

        match (&args.input, &args.data) {
            (Some(input_path), Some(filename)) => {

                progress.single(format!("replaying input {:?}", filename));
                let input = trace::Input::load(&input_path)?;

                let cr3 = context.cr3;

                let mut file = std::fs::File::open(filename)?;
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer)?;

                let address = input.address.into();
                let size: u64 = input.size.into();

                progress.single(format!("writing input to {:x} ({:x})", address, size));
                match tracer.write_gva(cr3, address, &buffer) {
                    Ok(()) => {}
                    Err(e) => {
                        return Err(anyhow!("can't write fuzzer input {}", e));
                    }
                }
            }
            (Some(input_path), None) => {
                let input = trace::Input::load(&input_path)?;
                
                let size: u64 = input.size.into();
                let mut data = vec![0u8; size as usize];

                let cr3 = context.cr3;
                tracer.read_gva(cr3, input.address.into(), &mut data)?;

                let hash = fuzz::calculate_hash(&data);
                let path = std::path::PathBuf::from(format!("{:x}.bin", hash));

                progress.single(format!("saving input to {:?} ({:x})", path, size));
                let mut file = std::fs::File::create(path)?;
                file.write_all(&data)?;

            }
            _ => ()
        }

        progress.single("running tracer");
        let mut trace = trace::Trace::new();

        let start = Instant::now();

        hook.setup(&mut tracer);

        loop {

            let mut bp_trace = tracer.run(&params, hook)?;
            trace.seen.append(&mut bp_trace.seen);
            trace.coverage.append(&mut bp_trace.coverage);
            trace.status = bp_trace.status;
            match trace.status {
                trace::EmulationStatus::Breakpoint => {
                    if hook.handle_breakpoint(&mut tracer)? {
                        tracer.singlestep(&params, hook)?;
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

        // FIXME: what to do if trace is incomplete
        // FIXME: will be false if bp are used
        let t = end - start;

        // FIXME: don't store that in trace, use tracer instead
        let pages = trace.code + trace.data;
        let mem = rewind_core::helpers::convert((pages * 0x1000) as f64);
        progress.single(format!("executed {} instructions in {:?} ({:?})", trace.coverage.len(), t, trace.status));
        progress.single(format!("seen {} unique addresses", trace.seen.len()));
        progress.single(format!("mapped {} pages ({})", pages, mem));

        let pages = tracer.restore_snapshot();
        progress.single(format!("{:?} page(s) were modified", pages.unwrap()));

        match &args.trace {
            Some(path) => {
                trace.save(&path)?;
            }
            None => {}
        }

        Ok(())
    }

    pub fn handle_fuzzer_init(&self, args: &FuzzerInit) -> anyhow::Result<()> {
        let progress = self.progress.enter("Init fuzzer");

        let path = &args.workdir;
        if path.exists() {
            return Err(anyhow!("fuzzer working directory already exists"))
        }

        let mut fuzz_params = fuzz::Params::default();

        fuzz_params.snapshot_path = std::fs::canonicalize(&args.snapshot)?;

        let input_str = std::fs::read_to_string(&args.input)?;
        let input = trace::Input::from_str(&input_str)?;

        fuzz_params.input = input.address.into();
        fuzz_params.input_size = input.size.into();

        let snapshot_path = &fuzz_params.snapshot_path;

        progress.single("checking snapshot");
        let dump_path = snapshot_path.join("mem.dmp");
        let _snapshot = DumpSnapshot::new(&dump_path)?;

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
        Ok(())
    }

    pub fn handle_fuzzer_run<H: trace::Hook>(&self, args: &FuzzerRun, _hook: &mut H) -> anyhow::Result<()> {
        let progress = self.progress.enter("Running fuzzer");

        progress.single("loading fuzzer parameters");
        let input_path = args.workdir.join("params.json");
        let mut fuzz_params = fuzz::Params::load(&input_path)?;
 
        progress.single("will use random strategy");
        // FIXME: strategy should be check from param
        let mut strategy = mutation::BasicStrategy::new(fuzz_params.input_size as usize);

        // fuzz_params.display_delay = std::time::Duration::from_secs(args.display_delay);
        fuzz_params.max_duration = std::time::Duration::from_secs(args.max_time);
        fuzz_params.max_iterations = args.max_iterations;

        let snapshot_path = &fuzz_params.snapshot_path;

        progress.single("loading snapshot");
        let dump_path = snapshot_path.join("mem.dmp");
        let snapshot = DumpSnapshot::new(&dump_path)?;

        let context_path = snapshot_path.join("context.json");
        let context = trace::ProcessorState::load(&context_path)?;

        let params_path = snapshot_path.join("params.json");
        let mut trace_params = trace::Params::load(&params_path)?;

        // params.limit = args.limit;
        trace_params.coverage_mode = args.coverage.clone();
        trace_params.max_duration = std::time::Duration::from_secs(args.max_time);

        let mut fuzzer = fuzz::Fuzzer::new(&args.workdir)?;

        eprintln!("Will fuzz function {:x}, input {:x} ({:x})", context.rip, fuzz_params.input, fuzz_params.input_size);

        let mut tracer = match args.backend {
            crate::BackendType::Bochs => {
                Backend::Bochs(rewind_bochs::BochsTracer::new(snapshot)?)

            },
            crate::BackendType::Whvp => {
                Backend::Whvp(rewind_whvp::WhvpTracer::new(snapshot)?)
            }
        };
            
        // FIXME: need to send hook
        let _hook = HH::default();
        let stats = fuzzer.run(&mut strategy, &fuzz_params, &mut tracer, &context, &trace_params)?;

        eprintln!("fuzzing session ended after {:?} and {} iteration(s)", stats.elapsed(), stats.iterations);

        Ok(())
    }

    pub fn handle_fuzzer_monitor<H: trace::Hook>(&self, args: &FuzzerMonitor, _hook: &mut H) -> anyhow::Result<()> {
        let progress = self.progress.enter("Running monitor");

        progress.single("loading fuzzer parameters");
        // start_collector_thread
        let (tx, rx) = flume::unbounded();

        start_collector_thread(args, tx)?;

        if args.ui {
            display_tui(rx)?;
        }
        else {
            // FIXME: collect event from rx
            loop {
                let collection = rx.recv()?;
                println!("{:?}", collection.coverage.len());
            }
        }

        Ok(())
    }

    // FIXME: insert sanitizer, configure timeout for trace, remove useless corpus entries

    pub fn run<H: trace::Hook>(&self, hook: &mut H) -> anyhow::Result<()>
    {
        match &self.args.subcmd {
            SubCommand::Trace(t) => {
                match &t.subcmd {
                    TraceSubCommand::Run(t) => self.handle_trace_run(t, hook)
                }
            }
            SubCommand::Fuzz(t) => {
                match &t.subcmd {
                    FuzzerSubCommand::Init(t) => self.handle_fuzzer_init(t),
                    FuzzerSubCommand::Run(t) => self.handle_fuzzer_run(t, hook),
                    FuzzerSubCommand::Monitor(t) => self.handle_fuzzer_monitor(t, hook)
                    // FIXME: monitor
                }
            }
        }
    }

}

#[derive(Clap, Debug)]
#[clap(version=crate_version!(), author="Damien Aumaitre")]
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
 
    #[clap(long, parse(from_os_str))]
    pub snapshot: std::path::PathBuf,

    #[clap(long="limit", default_value="0")]
    pub limit: u64,

    #[clap(long="save-context")]
    pub save_context: bool,

    #[clap(long="max-time", default_value="0")]
    pub max_time: u64,

    #[clap(long="save-trace", parse(from_os_str))]
    pub trace: Option<std::path::PathBuf>,

    #[clap(long="backend", possible_values(&["whvp", "bochs"]), default_value="bochs")]
    pub backend: crate::BackendType,

    #[clap(long="coverage", possible_values(&["no", "instrs", "hit"]), default_value="no")]
    pub coverage: rewind_core::trace::CoverageMode,

    #[clap(long="input", parse(from_os_str))]
    pub input: Option<std::path::PathBuf>,

    #[clap(long="data", parse(from_os_str))]
    pub data: Option<std::path::PathBuf>,

}

#[derive(Clap, Debug)]
pub struct FuzzerInit {
    #[clap(long="snapshot", parse(from_os_str))]
    pub snapshot: std::path::PathBuf,

    #[clap(parse(from_os_str))]
    pub workdir: std::path::PathBuf,

    #[clap(long="input", parse(from_os_str))]
    pub input: std::path::PathBuf,
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

fn parse_trace(collection: &mut ui::Collection, trace: &mut trace::Trace, system: &system::System, store: &mut pdbstore::PdbStore) -> anyhow::Result<()> {

    for &address in trace.seen.difference(&mut collection.coverage) {
        // if !coverage.insert(address) {
            // continue
        // }
        match system.get_module_by_address(address) {
            Some(module) => {
                *collection.modules.entry(module.name.clone()).or_insert_with(|| {

                    // FIXME: need a fn in system.rs
                    match system.get_file_information(module) {
                        Ok(info) => {
                            match store.download_pe(&module.name, &info) {
                                Ok(_) => { }
                                Err(_error) => {
                                    // println!("{:?}", error);
                                }
                            }
                        }
                        Err(_) => { }
                    }

                    match system.get_debug_information(module) {
                        Ok(info) => {
                            let (name, guid) = info.into();
                            match store.download_pdb(&name, &guid) {
                                Ok(_) => {
                                    match store.load_pdb(module.base, &name, &guid) {
                                        Ok(_) => (),
                                        Err(_error) => {
                                            // println!("{:?}", error);
                                        }
                                    }
                                }
                                Err(_error) => {
                                    // println!("{:?}", error);
                                }
                            }
                        }
                        Err(_) => { }

                    }
                        
                    0
                }) += 1;

                match store.resolve_address(address) {
                    Some(symbol) => {
                        // FIXME: get size of symbol and size of func
                        let name = format!("{}!{}", symbol.module, symbol.name);
                        collection.functions.entry(name)
                            .and_modify(|f| f.coverage += 1)
                            .or_insert_with(|| {
                                let func = ui::Function::new(symbol.module, symbol.name, 1);
                                func
                            });
                    }
                    None => {
                        // FIXME: need to send event
                        // println!("can't resolve symbol for {:x}", address);
                    }
                }
    
            }
            None => ()
        }
    }

    collection.coverage.append(&mut trace.seen);

    Ok(())
}

// fn display_coverage(modules: &mut HashMap<String, usize>, functions: &mut HashMap<String, usize>) {
//     let mut modules: Vec<_> = modules.iter().collect();
//     modules.sort();

//     for (name, instructions) in &modules {
//         // FIXME: compute percentage
//         println!("{}: {} instructions", &name, instructions);
//     }

//     let mut functions: Vec<_> = functions.iter().collect();
//     functions.sort();

//     for (name, instructions) in &functions {
//         // FIXME: compute percentage
//         println!("{}: {} instructions", &name, instructions);

//     }

// }

fn collector_thread(control_rx: flume::Receiver<Control>, tx: flume::Sender<ui::Collection>) -> anyhow::Result<()> {
    let control = control_rx.recv()?;

    match control {
        Control::Args((workdir, store)) => {
            let input_path = workdir.join("params.json");
            let fuzz_params = fuzz::Params::load(&input_path)?;

            let snapshot_path = &fuzz_params.snapshot_path;

            let dump_path = snapshot_path.join("mem.dmp");
            let snapshot = DumpSnapshot::new(&dump_path)?;

            let context_path = snapshot_path.join("context.json");
            let context = trace::ProcessorState::load(&context_path)?;

            let params_path = snapshot_path.join("params.json");
            let trace_params = trace::Params::load(&params_path)?;

            // trace_params.max_duration = std::time::Duration::from_secs(args.max_time);

            let mut tracer = rewind_bochs::BochsTracer::new(snapshot)?;

            let mut system = system::System::new(&tracer.snapshot)?;
            system.load_modules()?;

            let path = &store;
            if !path.exists() {
                std::fs::create_dir(&path)?;
                std::fs::create_dir(path.join("binaries"))?;
                std::fs::create_dir(path.join("symbols"))?;
            }

            let mut store = pdbstore::PdbStore::new(path)?;

            let mut hints = fuzz::MutationHint::new();


            // FIXME: need to share it
            let mut hook = fuzz::Hook {};

            // let mut known_files: BTreeSet<std::path::PathBuf> = BTreeSet::new();

            loop {
                // FIXME: listen to events ?
                let mut collection = ui::Collection::new();

                let path = workdir.join("instances");
                let mut entries = std::fs::read_dir(&path)?
                    .map(|res| res.map(|e| e.path()))
                    .collect::<Result<Vec<_>, std::io::Error>>()?;

                entries.sort();

                for path in entries {
                    if path.extension() == Some(std::ffi::OsStr::new("json")) {
                        let stats = fuzz::Stats::load(&path)?;

                        let filename = path.to_path_buf();
                        collection.instances.insert(filename, stats);
                    }
                }
 
                let path = workdir.join("corpus");
                let mut entries = std::fs::read_dir(&path)?
                    .map(|res| res.map(|e| e.path()))
                    .collect::<Result<Vec<_>, std::io::Error>>()?;

                entries.sort();

                for path in entries {
                    // if known_files.contains(&path) {
                        // continue
                    // }
                    if path.extension() == Some(std::ffi::OsStr::new("bin")) {
                        let mut file = std::fs::File::open(&path)?;
                        let mut data = Vec::new();
                        file.read_to_end(&mut data)?;

                        let cr3 = context.cr3;

                        match tracer.write_gva(cr3, fuzz_params.input, &data) {
                            Ok(()) => {}
                            Err(e) => {
                                return Err(anyhow!("can't write input {}", e));
                            }
                        }

                        tracer.set_state(&context)?;

                        let mut trace = tracer.run(&trace_params, &mut hook)?;
                        tracer.restore_snapshot()?;

                        let corpus_path = path.to_path_buf();
                        let mut corpus_file = ui::CorpusFile::new(corpus_path);
                        corpus_file.seen = trace.seen.len() as u64;
                        corpus_file.count = trace.coverage.len() as u64;
                        collection.corpus.insert(corpus_file.path.clone(), corpus_file);

                        hints.immediates.append(&mut trace.immediates);
                        // let address = fuzz_params.input;
                        // let size = fuzz_params.input_size;
                        // let filtered = trace.mem_access.iter().filter(|a| {
                        //     a.1 >= address && a.1 < address + size
                        // }).map(|a| {
                        //     a.1 - address
                        // });

                        // FIXME: need to send this with parameters
                        let offsets = (8..0x58).chain(0x100..0x108)
                                                            .chain(0x200..0x208)
                                                            .chain(0x300..0x308)
                                                            .chain(0x400..0x408);
                    
                        hints.offsets.extend(offsets);

                        // let count = trace.seen.difference(&coverage).count();
                        if trace.seen.is_subset(&collection.coverage) {
                            // println!("no new coverage for {:?}, deleting file", path);
                            std::fs::remove_file(&path)?;
                        } else {
                            parse_trace(&mut collection, &mut trace, &system, &mut store)?;
                            trace.save(workdir.join("traces").join(format!("{}.json", path.file_name().unwrap().to_str().unwrap())))?;
                        }

                        // known_files.insert(path.to_path_buf());

                        // FIXME: save trace to traces directory

                    }
                }
                // println!("immediates {}, offsets {}", hints.immediates.len(), hints.offsets.len());
                // println!("unique addresses {}, {} modules, {} functions", coverage.len(), modules.len(), functions.len());
                // display_coverage(&mut modules, &mut functions);

                // FIXME: replay and triage crashes

                let path = workdir.join("hints.json");
                hints.save(&path)?;

                tx.send(collection)?;

                // FIXME: args
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
        }
    }


}

enum Control {
    Args((std::path::PathBuf, std::path::PathBuf))
}

fn start_collector_thread(args: &FuzzerMonitor, tx: flume::Sender<ui::Collection>) -> anyhow::Result<()> {
    let (control_tx, control_rx) = flume::unbounded();
    thread::spawn(move || {
        let result = collector_thread(control_rx, tx);
        println!("thread returned {:?}", result);
    });
    control_tx.send(Control::Args((args.workdir.clone(), args.store.clone())))?;
    Ok(())
}

fn display_tui(data_rx: flume::Receiver<ui::Collection>) -> anyhow::Result<()> {
    // let is_debug = false;

    // FIXME: use a func similar to cleanup_terminal => setup_terminal ?
    let mut stdout_val = stdout();
    ui::execute!(stdout_val, ui::EnterAlternateScreen, ui::EnableMouseCapture)?;
    ui::enable_raw_mode()?;

    let backend = ui::CrosstermBackend::new(stdout_val);

    let mut terminal = ui::Terminal::new(backend)?;

    // Setup input handling
    let (tx, rx) = mpsc::channel();

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

    let mut app = ui::App::new("Rewind monitor");

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
                // KeyCode::Left => app.on_left(),
                // KeyCode::Right => app.on_right(),
                ui::KeyCode::Tab => app.on_tab(),
                ui::KeyCode::Up => app.on_up(),
                ui::KeyCode::Down => app.on_down(),
                _ => {}
            },
            ui::TuiEvent::Tick => {
                app.on_tick();
            }
        }

        // FIXME: move this in thread and with proper event
        match data_rx.recv_timeout(Duration::from_millis(10)) {
            Ok(collection) => {
                app.on_collect(collection);
            }
            Err(_) => {

            }
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}

use std::convert::TryInto;

use clap::Clap;
use color_eyre::{Report, eyre::{WrapErr, bail}};
use memmap::MmapOptions;
use rewind_core::{corpus, fuzz, mutation, trace};
use rewind_snapshot::{DumpSnapshot, FileSnapshot, SnapshotKind};
use rewind_tui::display_tui;

use crate::{Rewind, cli::Backend, helpers};

/// Fuzz all the things
#[derive(Clap, Debug)]
pub(crate) struct Fuzz {
    #[clap(subcommand)]
    subcmd: FuzzerSubCommand
}

impl Fuzz {

    pub(crate) fn run<C: Rewind>(&self, cli: &C) -> Result<(), Report> {
        match &self.subcmd {
            FuzzerSubCommand::Init(t) => t.run(),
            FuzzerSubCommand::Run(t) => t.run(cli),
            FuzzerSubCommand::Monitor(t) => t.run(cli),
        }
    }

}

#[derive(Clap, Debug)]
enum FuzzerSubCommand {
    Init(FuzzerInit),
    Run(FuzzerRun),
    Monitor(FuzzerMonitor),

}

/// Initialize fuzzer
#[derive(Clap, Debug)]
pub struct FuzzerInit {
    /// Fuzzer work directory
    #[clap(parse(from_os_str))]
    pub workdir: std::path::PathBuf,

    /// Path to snapshot
    #[clap(parse(from_os_str))]
    pub snapshot: std::path::PathBuf,

    /// Input address
    #[clap(long="input-address")]
    pub input_address: String,

    /// Input size
    #[clap(long="input-size")]
    pub input_size: String,

}

impl FuzzerInit {

    fn run(&self) -> Result<(), Report> {
        let progress = helpers::start();
        let progress = progress.enter("Init fuzzer");

        progress.single("checking parameters");

        let path = &self.workdir;
        if path.exists() {
            bail!("can't init fuzzer, working directory exists");
        }

        let mut fuzz_params = fuzz::Params::default();

        let mut input = trace::Input::default();

        let input_address = u64::from_str_radix(self.input_address.trim_start_matches("0x"), 16)
            .wrap_err_with(|| "can't parse input address")?;

        input.address = input_address;
        fuzz_params.input = input_address;

        let input_size = u64::from_str_radix(self.input_size.trim_start_matches("0x"), 16)
            .wrap_err_with(|| "can't parse input size")?;

        input.size = input_size;
        fuzz_params.input_size = input_size;

        let snapshot_path = &self.snapshot;

        progress.single("checking snapshot");
        let buffer;

        let _snapshot = if snapshot_path.join("mem.dmp").exists() {
            let dump_path = snapshot_path.join("mem.dmp");

            let fp = std::fs::File::open(&dump_path).wrap_err(format!("Can't load snapshot {}", dump_path.display()))?;
            buffer = unsafe { MmapOptions::new().map(&fp)? };

            let snapshot = DumpSnapshot::new(&buffer)?;
            SnapshotKind::DumpSnapshot(snapshot)
        } else {
            let snapshot = FileSnapshot::new(&self.snapshot)?;
            SnapshotKind::FileSnapshot(snapshot)
        };

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

}

/// Run a fuzzer instance
#[derive(Clap, Debug)]
pub struct FuzzerRun {
    /// Set the level of verbosity
    #[clap(long, short, parse(from_occurrences))]
    pub verbose: usize,
 
    /// Maximum number of iterations
    #[clap(long="max-iterations", default_value="0")]
    pub max_iterations: u64,

    /// Stop fuzzing upon crash
    #[clap(long="stop-on-crash")]
    pub stop_on_crash: bool,

    /// Maximum fuzzing time
    #[clap(long="max-time", default_value="0")]
    pub max_time: u64,

    /// Tracer backend
    #[clap(long="backend", possible_values(&["whvp", "bochs", "kvm"]), default_value="bochs")]
    pub backend: crate::BackendType,

    /// Coverage mode
    #[clap(long="coverage", possible_values(&["no", "instrs", "hit"]), default_value="hit")]
    pub coverage: rewind_core::trace::CoverageMode,

    /// Fuzzer workdir
    #[clap(parse(from_os_str))]
    pub workdir: std::path::PathBuf,

    /// Mutations to apply
    #[clap(long="mutation", parse(from_os_str))]
    pub mutation: std::path::PathBuf,

}

impl FuzzerRun {

    fn run<C: Rewind>(&self, cli: &C) -> Result<(), Report> {
        let progress = helpers::start();
        let progress = progress.enter("Launching fuzzer");

        progress.single("Loading parameters");
        let input_path = self.workdir.join("params.json");

        progress.single("Loading fuzzing parameters");
        let mut fuzz_params = fuzz::Params::load(&input_path)?;
 
        fuzz_params.max_duration = std::time::Duration::from_secs(self.max_time);
        fuzz_params.max_iterations = self.max_iterations;
        fuzz_params.stop_on_crash = self.stop_on_crash;

        let desc = mutation::StructDesc::load(&self.mutation)?;

        let mutator: mutation::Mutator = desc.try_into()?;
        // FIXME: strategy should be check from param
        // FIXME: strategy params should be in args too
        // FIXME: input mutation should be in mutation hints

        let mut strategy = cli.create_fuzzing_strategy(&fuzz_params, mutator);

        let snapshot_path = &fuzz_params.snapshot_path;

        progress.single("Loading snapshot");
        let buffer;

        let snapshot = if snapshot_path.join("mem.dmp").exists() {
            let dump_path = snapshot_path.join("mem.dmp");

            let fp = std::fs::File::open(&dump_path).wrap_err(format!("Can't load snapshot {}", dump_path.display()))?;
            buffer = unsafe { MmapOptions::new().map(&fp)? };

            // FIXME: ugly
            let static_buffer: &'static [u8] = Box::leak(Box::new(buffer));
            let snapshot = DumpSnapshot::new(static_buffer)?;
            SnapshotKind::DumpSnapshot(snapshot)
        } else {
            let snapshot = FileSnapshot::new(&snapshot_path)?;
            SnapshotKind::FileSnapshot(snapshot)
        };

        let context_path = snapshot_path.join("context.json");
        let context = trace::ProcessorState::load(&context_path)?;

        let params_path = snapshot_path.join("params.json");
        let mut trace_params = trace::Params::load(&params_path)?;

        trace_params.coverage_mode = self.coverage.clone();
        trace_params.max_duration = std::time::Duration::from_secs(self.max_time);

        let mut fuzzer = fuzz::Fuzzer::new(&self.workdir)?;

        progress.single(format!("Fuzzing function {:x} with input {:x} ({:x})", context.rip, fuzz_params.input, fuzz_params.input_size));

        let mut tracer = match self.backend {
            crate::BackendType::Bochs => {
                Backend::Bochs(rewind_bochs::BochsTracer::new(&snapshot))
            },
            #[cfg(windows)]
            crate::BackendType::Whvp => {
                Backend::Whvp(rewind_whvp::WhvpTracer::new(&snapshot)?)
            }
            #[cfg(unix)]
            crate::BackendType::Kvm => {
                Backend::Kvm(rewind_kvm::KvmTracer::new(snapshot)?)
            }
        };
        
        let mut corpus = corpus::Corpus::new(&self.workdir);

        let mut hook = cli.create_fuzzer_hook();

        // FIXME: handle properly ctrlc

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

        let stats = fuzzer.run(&mut corpus, &mut strategy, &fuzz_params, &mut tracer, &context, &trace_params, &mut hook)?;

        progress.single(format!("Session ended after {:?} and {} iteration(s), got {} crash(es)",
            stats.elapsed(), stats.iterations, stats.crashes));

        Ok(())
    }

}


/// Launch monitor TUI
#[derive(Clap, Debug)]
pub struct FuzzerMonitor {
    /// Set the level of verbosity
    #[clap(long, short, parse(from_occurrences))]
    pub verbose: usize,

    /// Fuzzer workdir
    #[clap(parse(from_os_str))]
    pub workdir: std::path::PathBuf,

    /// Store path
    #[clap(parse(from_os_str))]
    pub store: std::path::PathBuf,

}

impl FuzzerMonitor {

    fn run<C: Rewind>(&self, _cli: &C) -> Result<(), Report> {
        // monitor hook
        display_tui::<<C>::TraceHook>(self.workdir.clone(), self.store.clone())?;
        Ok(())
    }
}


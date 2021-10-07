
//! Rewind CLI.

use std::{convert::TryInto, fmt::Write as FmtWrite, num::ParseIntError, path::PathBuf};
use std::io::{BufWriter, Read, Write};
use std::time::Instant;

use color_eyre::{Report, eyre::{bail, Result, WrapErr}};

use clap::Clap;

use memmap::MmapOptions;

use rewind_core::{corpus, fuzz, mem::{X64VirtualAddressSpace, VirtMemError}, mutation, snapshot, trace::{self, Tracer, TracerError, Hook}};

use rewind_snapshot::{SnapshotKind, DumpSnapshot, FileSnapshot};

use rewind_system::{System, PdbStore};

use rewind_tui::{Collection, parse_trace, display_tui};

use crate::helpers;

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
            Self::Whvp(tracer) => tracer.read_gva(cr3, vaddr, data),
            Self::Bochs(tracer) => tracer.read_gva(cr3, vaddr, data),
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

    /// Implementation of `rewind trace run`
    fn handle_trace_run(&self, args: &TracerRun) -> Result<()>
    {
        let progress = helpers::start();
        let progress = progress.enter("Running tracer");

        progress.single("loading snapshot");

        // FIXME: finish load_snapshot
        // let snapshot = load_snapshot(&args.snapshot)?;
        let buffer;

        let snapshot = if args.snapshot.join("mem.dmp").exists() {
            let dump_path = args.snapshot.join("mem.dmp");

            let fp = std::fs::File::open(&dump_path).wrap_err(format!("Can't load snapshot {}", dump_path.display()))?;
            buffer = unsafe { MmapOptions::new().map(&fp)? };

            // FIXME: ugly
            let static_buffer: &'static [u8] = Box::leak(Box::new(buffer));
            let snapshot = DumpSnapshot::new(static_buffer)?;
            SnapshotKind::DumpSnapshot(snapshot)
        } else {
            let snapshot = FileSnapshot::new(&args.snapshot)?;
            SnapshotKind::FileSnapshot(snapshot)
        };

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
            },
            #[cfg(unix)]
            crate::BackendType::Kvm => {
                Backend::Kvm(rewind_kvm::KvmTracer::new(snapshot)?)
            }
        };

        progress.single(format!("setting tracer initial state\n{}", &context));
        tracer.set_state(&context)?;

        match (&args.input_address, &args.input_data) {
            (Some(address), Some(filename)) => {
                progress.single(format!("replaying input {:?}", filename));

                let cr3 = context.cr3;

                let mut file = std::fs::File::open(filename)?;
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer)?;

                progress.single(format!("writing input to {:x}", address));
                Tracer::write_gva(&mut tracer, cr3, *address as u64, &buffer[..0x1000]).wrap_err("can't write fuzzer input")?;
            }
            (Some(address), None) => {
                // FIXME: hardcoding first page for now
                let size: u64 = 0x1000;
                let mut data = vec![0u8; size as usize];

                let cr3 = context.cr3;
                Tracer::read_gva(&mut tracer, cr3, *address as u64, &mut data)?;

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
            progress.single(format!("saving trace to {}", path.display()));
            trace.save(&path)?;
        }

        if let Some(path) = &args.save_mem {
            progress.single(format!("saving fetched physical pages to {}", path.display()));
            // snapshot.save(&path)?;
        }

        Ok(())
    }

    /// Implementation of `rewind trace inspect`
    fn handle_trace_inspect(&self, args: &TracerInspect) -> Result<()> {
        let progress = helpers::start();
        let progress = progress.enter("Inspecting trace");

        progress.single("loading snapshot");
        let buffer;

        let snapshot = if args.snapshot.join("mem.dmp").exists() {
            let dump_path = args.snapshot.join("mem.dmp");

            let fp = std::fs::File::open(&dump_path).wrap_err(format!("Can't load snapshot {}", dump_path.display()))?;
            buffer = unsafe { MmapOptions::new().map(&fp)? };

            let snapshot = DumpSnapshot::new(&buffer)?;
            SnapshotKind::DumpSnapshot(snapshot)
        } else {
            let snapshot = FileSnapshot::new(&args.snapshot)?;
            SnapshotKind::FileSnapshot(snapshot)
        };

        let context_path = args.snapshot.join("context.json");
        let context = trace::ProcessorState::load(&context_path)?;
 
        progress.single("loading trace");
        let mut trace = trace::Trace::load(&args.trace)?;

        // FIXME: check if context is present
        progress.single(format!("trace contains {} instructions ({} unique(s))", trace.coverage.len(), trace.seen.len()));

        let path = &args.store;
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

        let mut out_writer = match &args.symbolize {
            Some(x) => {
                Box::new(BufWriter::new(std::fs::File::create(x)?)) as Box<dyn Write>
            }
            None => Box::new(std::io::stdout()) as Box<dyn Write>,
        };

        if args.show_coverage {
            progress.single("displaying coverage");

            let mut functions: Vec<_> = collection.functions.iter().collect();
            functions.sort();

            for (name, instructions) in functions.iter() {
                // FIXME: compute percentage
                writeln!(out_writer, "{}: {} instructions", &name, instructions.coverage)?;

            }
        }

        if args.show_instructions {
            let skip = args.skip_instructions.unwrap_or(0);

            progress.single("displaying instructions");
            let instructions = trace.coverage.iter()
                // .map(|(addr, _context)| {
                    // addr
                // })
                .enumerate();

            let instructions: Box<dyn Iterator<Item = (usize, _)>> = if args.last {
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

                if let Some(filter) = &args.filter {
                    let pattern = filter.to_lowercase();
                    if text.to_lowercase().matches(&pattern).count() > 0 {
                        writeln!(out_writer, "{}", text)?;
                    }
                } else {
                    writeln!(out_writer, "{}", text)?;
                }

            }
        }

        if args.sanitize {
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

        if let Some(path) = &args.save_mem {
            progress.single(format!("saving fetched physical pages to {}", path.display()));
            snapshot.save(&path)?;
        }

        Ok(())
    }

    /// Implementation of `rewind trace info`
    fn handle_trace_info(&self, args: &TracerInfo) -> Result<()> {
        let progress = helpers::start();
        let progress = progress.enter("Inspecting trace");

        progress.single("loading trace");
        let trace = trace::Trace::load(&args.trace)?;

        progress.single(format!("trace has {} instructions", trace.coverage.len()));

        Ok(())
    }

    /// Implementation of `rewind fuzz init`
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

        let input_address = u64::from_str_radix(args.input_address.trim_start_matches("0x"), 16)
            .wrap_err_with(|| "can't parse input address")?;

        input.address = input_address;
        fuzz_params.input = input_address;

        let input_size = u64::from_str_radix(args.input_size.trim_start_matches("0x"), 16)
            .wrap_err_with(|| "can't parse input size")?;

        input.size = input_size;
        fuzz_params.input_size = input_size;

        let snapshot_path = &args.snapshot;

        progress.single("checking snapshot");
        let buffer;

        let _snapshot = if snapshot_path.join("mem.dmp").exists() {
            let dump_path = snapshot_path.join("mem.dmp");

            let fp = std::fs::File::open(&dump_path).wrap_err(format!("Can't load snapshot {}", dump_path.display()))?;
            buffer = unsafe { MmapOptions::new().map(&fp)? };

            let snapshot = DumpSnapshot::new(&buffer)?;
            SnapshotKind::DumpSnapshot(snapshot)
        } else {
            let snapshot = FileSnapshot::new(&args.snapshot)?;
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

    /// Implementation of `rewind fuzz run`
    fn handle_fuzzer_run(&self, args: &FuzzerRun) -> Result<()> {

        let progress = helpers::start();
        let progress = progress.enter("Launching fuzzer");

        progress.single("Loading parameters");
        let input_path = args.workdir.join("params.json");

        progress.single("Loading fuzzing parameters");
        let mut fuzz_params = fuzz::Params::load(&input_path)?;
 
        fuzz_params.max_duration = std::time::Duration::from_secs(args.max_time);
        fuzz_params.max_iterations = args.max_iterations;
        fuzz_params.stop_on_crash = args.stop_on_crash;

        let desc = mutation::StructDesc::load(&args.mutation)?;

        let mutator: mutation::Mutator = desc.try_into()?;
        // FIXME: strategy should be check from param
        // FIXME: strategy params should be in args too
        // FIXME: input mutation should be in mutation hints

        let mut strategy = self.create_fuzzing_strategy(&fuzz_params, mutator);

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
            #[cfg(unix)]
            crate::BackendType::Kvm => {
                Backend::Kvm(rewind_kvm::KvmTracer::new(snapshot)?)
            }
        };
        
        let mut corpus = corpus::Corpus::new(&args.workdir);

        let mut hook = self.create_fuzzer_hook();

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

    /// Implementation of `rewind fuzz monitor`
    fn handle_fuzzer_monitor(&self, args: &FuzzerMonitor) -> Result<()> {
        // monitor hook
        display_tui::<<Self as Rewind>::TraceHook>(args.workdir.clone(), args.store.clone())?;

        Ok(())
    }

    /// Implementation of `rewind snapshot extract`
    fn handle_snapshot_extract(&self, args: &SnapshotExtract) -> Result<()> {
        let progress = helpers::start();
        let progress = progress.enter("Extracting pages from snapshot");

        let snapshot_path = &args.snapshot;

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
        for address in &args.addresses {
            let gpa = *address as u64;
            let base = gpa & !0xfff;
            let filename = format!("{:016x}.bin", base);
            let path = &args.path.join(filename);

            println!("Copying {:x} to {}", address, path.display());
            let mut data = vec![0u8; 0x1000];
            rewind_core::snapshot::Snapshot::read_gpa(&snapshot, gpa, &mut data)?;

            let mut fp = std::fs::File::create(path)?;
            fp.write_all(&data)?;
        }

        Ok(())
    }

    /// Command dispatcher
    fn run(&self) -> Result<()>
    {
        let args = RewindArgs::parse();
        match &args.subcmd {
            SubCommand::Snapshot(t) => {
                match &t.subcmd {
                    SnapshotSubCommand::Extract(t) => self.handle_snapshot_extract(t),
                }
            }
            SubCommand::Trace(t) => {
                match &t.subcmd {
                    TraceSubCommand::Run(t) => self.handle_trace_run(t),
                    TraceSubCommand::Inspect(t) => self.handle_trace_inspect(t),
                    TraceSubCommand::Info(t) => self.handle_trace_info(t)
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


/// Rewind
///
/// PoC for a snapshot-based coverage-guided fuzzer targeting Windows kernel components.
#[derive(Clap, Debug)]
struct RewindArgs {
    #[clap(subcommand)]
    subcmd: SubCommand,

}

#[derive(Clap, Debug)]
enum SubCommand {
    Snapshot(Snapshot),
    Trace(Trace),
    Fuzz(Fuzz)
}

#[derive(Clap, Debug)]
/// Manage snapshots.
struct Snapshot {
    #[clap(subcommand)]
    subcmd: SnapshotSubCommand
}

#[derive(Clap, Debug)]
enum SnapshotSubCommand {
    Extract(SnapshotExtract),
}

/// Extract physical pages from snapshot
#[derive(Clap, Debug)]
pub struct SnapshotExtract {
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

#[derive(Clap, Debug)]
/// Do stuff with traces.
struct Trace {
    #[clap(subcommand)]
    subcmd: TraceSubCommand
}


#[derive(Clap, Debug)]
enum TraceSubCommand {
    Run(TracerRun),
    Inspect(TracerInspect),
    Info(TracerInfo),
}

fn parse_hex(input: &str) -> Result<usize, ParseIntError> {
    usize::from_str_radix(input, 16)
}

/// Run tracer
#[derive(Clap, Debug)]
pub struct TracerRun {
    /// Set the level of verbosity
    #[clap(long, short, parse(from_occurrences))]
    pub verbose: usize,
 
    /// Snapshot path
    #[clap(parse(from_os_str))]
    pub snapshot: std::path::PathBuf,

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
    pub trace: Option<std::path::PathBuf>,

    /// Tracing backend
    #[clap(long="backend", possible_values(&["whvp", "bochs", "kvm"]), default_value="bochs")]
    pub backend: crate::BackendType,

    /// Tracing coverage
    #[clap(long="coverage", possible_values(&["no", "instrs", "hit"]), default_value="no")]
    pub coverage: rewind_core::trace::CoverageMode,

    /// Input address in hexadecimal
    #[clap(long="input-address", parse(try_from_str = parse_hex))]
    pub input_address: Option<usize>,

    /// Input size in hexadecimal
    #[clap(long="input-size", parse(try_from_str = parse_hex))]
    pub input_size: Option<usize>,

    /// Input data
    #[clap(long="input-data", parse(from_os_str))]
    pub input_data: Option<std::path::PathBuf>,

    /// Save input to file
    #[clap(long="save-input", parse(from_os_str))]
    pub save_input: Option<std::path::PathBuf>,

    /// Save physical pages fetched from snapshot (debug)
    #[clap(long="save-mem", parse(from_os_str))]
    pub save_mem: Option<std::path::PathBuf>,


}

/// Inspect trace
#[derive(Clap, Debug)]
pub struct TracerInspect {
    /// Snapshot path
    #[clap(long, parse(from_os_str))]
    pub snapshot: std::path::PathBuf,

    /// Trace to load
    #[clap(long, parse(from_os_str))]
    pub trace: std::path::PathBuf,

    /// Symbol store
    #[clap(long="store", parse(from_os_str))]
    pub store: std::path::PathBuf,

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
    pub save_mem: Option<std::path::PathBuf>,

}

/// Get basic info on a trace
#[derive(Clap, Debug)]
pub struct TracerInfo {
    /// Snapshot path
    #[clap(long, parse(from_os_str))]
    pub snapshot: std::path::PathBuf,

    /// Trace to load
    #[clap(long, parse(from_os_str))]
    pub trace: std::path::PathBuf,

    /// Set the level of verbosity
    #[clap(long, short, parse(from_occurrences))]
    pub verbose: usize,
}
 
/// Fuzz all the things
#[derive(Clap, Debug)]
struct Fuzz {
    #[clap(subcommand)]
    subcmd: FuzzerSubCommand
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


fn decode_instruction(buffer: &[u8]) -> Result<zydis::DecodedInstruction> {
    let decoder = zydis::Decoder::new(zydis::MachineMode::LONG_64, zydis::AddressWidth::_64)?;
    let result = decoder.decode(buffer)?;
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



use std::str::FromStr;
use std::collections::BTreeSet;
use std::io::Write;

use simple_logger;

use clap::Clap;

use rewind_core::fuzz::{self, Strategy, Corpus, Params};
use rewind_core::trace::{self, Tracer};
use rewind_cli::helpers;

use rewind_snapshot as snapshot;

use basic_mutator;

#[macro_use]
extern crate anyhow;

use anyhow::Result;

pub mod cli;

use rewind_cli::Backend;

fn main() -> Result<()> {

    let args = cli::Cli::parse();

    let level = match args.verbose {
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };

    if args.verbose > 0 {
        simple_logger::SimpleLogger::new()
            .with_level(level)
            .with_module_level("bochscpu", log::LevelFilter::Off)
        .init()?;
    }

    let p = helpers::start();
    
    let p = p.enter("Fuzzer setup");

    let mut fuzz_params = fuzz::Params::default();

    let path = args.workdir;
    if !path.exists() {
        match args.snapshot {
            Some(path) => {
                fuzz_params.snapshot_path = std::fs::canonicalize(path)?;
            },
            None => {
                p.error(format!("{}", "--snapshot is needed"));
                return Err(anyhow!("missing snapshot"));
            }
        }

        p.single("Reading input");
        match args.input {
            Some(input_path) => {
                let input_str = std::fs::read_to_string(&input_path)?;
                let input = trace::Input::from_str(&input_str)?;

                fuzz_params.input = input.address.into();
                fuzz_params.input_size = input.size.into();

            },
            None => {
                p.error(format!("{}", "--input is needed"));
                return Err(anyhow!("missing input"));
            }
        }

        p.single("Creating fuzzer directories");
        std::fs::create_dir(&path)?;
        std::fs::create_dir(path.join("corpus"))?;
        std::fs::create_dir(path.join("crashes"))?;


    } else {
        p.single("Loading fuzzer parameters");
        let input_path = path.join("params.json");
        let input_str = std::fs::read_to_string(&input_path)?;
        fuzz_params = fuzz::Params::from_str(&input_str)?;
        // read parameters from workdir
        // set input param and size from state
    }

    p.single("Selecting random strategy");
    let mut strategy = BasicStrategy::new(fuzz_params.input_size as usize);

    // let mut strategy = fuzz::RandomStrategy::new();
 
    fuzz_params.display_delay = std::time::Duration::from_secs(args.display_delay);
    fuzz_params.max_duration = std::time::Duration::from_secs(args.max_time);

    if args.input_size != 0 {
        fuzz_params.input_size = args.input_size;
    }

    fuzz_params.save(path.join("params.json"))?;

    let p = p.leave();

    let p = p.enter("Tracer setup");

    let snapshot_path = &fuzz_params.snapshot_path;

    p.single("Loading snapshot");
    let dump_path = snapshot_path.join("mem.dmp");
    let snapshot = snapshot::DumpSnapshot::new(&dump_path)?;

    p.single("Loading context");
    let context_path = snapshot_path.join("context.json");
    let context_str = std::fs::read_to_string(&context_path)?;
    let context = trace::ProcessorState::from_str(&context_str)?;

    p.single("Loading parameters");
    let params_path = snapshot_path.join("params.json");
    let params_str = std::fs::read_to_string(&params_path)?;
    let mut params = trace::parse_params(&params_str)?;

    params.limit = args.limit;
    params.save_context = args.save_context;
    params.coverage_mode = args.coverage;

    p.single("Loading tracer");

    // FIXME: need a better name
    let mut backend = Backend::new(snapshot, args.backend)?;

    let p = p.leave();

    let p = p.enter("Running fuzzer");

    let mut fuzzer = fuzz::Fuzzer::new(&path)?;

    // FIXME: need to periodically write fuzzer stats

    eprintln!("Will fuzz function {:x}, input {:x} ({:x})", context.rip, fuzz_params.input, fuzz_params.input_size);

    let callback = |fuzzer: &mut fuzz::Fuzzer, stats: &mut fuzz::Stats| -> Result<()> {
        match stats.update_display() {
            Some(msg) => {
                eprintln!("{}", msg);
            }
            None => ()
        }
        Ok(())
    };

    // FIXME: method on emulator ? calling this Fuzzer ?
    let stats = backend.fuzz(&mut fuzzer, &mut strategy, &fuzz_params, &context, &params, callback)?;

    eprintln!("fuzzing session ended after {:?} and {} iteration(s)", stats.total_start.elapsed(), stats.total_iterations);
    p.single("All done");

    Ok(())
}

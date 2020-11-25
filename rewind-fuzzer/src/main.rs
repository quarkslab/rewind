
use std::str::FromStr;
use anyhow::{Result, Context};
use simple_logger;

use clap::Clap;

use rewind_core::fuzz;
use rewind_core::trace::{self, Tracer};
use rewind_cli::helpers;

use rewind_snapshot as snapshot;

#[macro_use]
extern crate anyhow;

pub mod cli;

#[cfg(feature = "whvp")]
use rewind_whvp::WhvpTracer;

#[cfg(feature = "bochs")]
use rewind_bochs::BochsTracer;

enum Emulator<S>
where S: rewind_core::snapshot::Snapshot + 'static {
    #[cfg(feature = "whvp")]
    Whvp(WhvpTracer<S>),
    #[cfg(feature = "bochs")]
    Bochs(BochsTracer<S>),
    None
}


fn get_emulator<S>(snapshot: S, emulator_type: rewind_cli::EmulatorType) -> Result<Emulator<S>>
where S: rewind_core::snapshot::Snapshot + rewind_core::mem::X64VirtualAddressSpace {
    match emulator_type {
        #[cfg(feature = "whvp")]
        rewind_cli::EmulatorType::Whvp => {
            let tracer = WhvpTracer::new(snapshot)?;
            return Ok(Emulator::Whvp(tracer))
        },
        #[cfg(feature = "bochs")]
        rewind_cli::EmulatorType::Bochs => {
            let tracer = BochsTracer::new(snapshot)?;
            return Ok(Emulator::Bochs(tracer))
        },
        _ => {
            return Err(anyhow!("missing feature"))

        }
    }

}

fn fuzzer_callback(fuzzer: &mut fuzz::Fuzzer, stats: &mut fuzz::Stats) -> Result<()> {
   match stats.update_display() {
       Some(msg) => eprintln!("{}", msg),
       None => ()
   }
   Ok(()) 
}

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
        .init().context("can't setup logger")?;
    }

    let p = helpers::start();
    
    let p = p.enter("Fuzzer setup");

    let mut fuzz_params = fuzz::Params::default();

    let path = args.workdir;
    if !path.exists() {
        p.warn("Fuzzer workdir doesn't exist");

        p.single("Creating fuzzer directories");
        std::fs::create_dir(&path)?;
        std::fs::create_dir(path.join("corpus"))?;
        std::fs::create_dir(path.join("crashes"))?;

        match args.snapshot {
            Some(path) => {
                fuzz_params.snapshot_path = std::fs::canonicalize(path)?;
            },
            None => {
                p.error(format!("{}", "--snapshot is needed"));
            }
        }

        p.single("Reading input");
        match args.input {
            Some(input_path) => {
                let input_str = std::fs::read_to_string(&input_path).context("can't read input")?;
                let input = fuzz::Input::from_str(&input_str).context("can't parse input")?;

                fuzz_params.input = input.address.into();
                fuzz_params.input_size = input.size.into();

            },
            None => {
                p.error(format!("{}", "--input is needed"));
            }
        }

    } else {
        p.single("Loading fuzzer parameters");
        let input_path = path.join("params.json");
        let input_str = std::fs::read_to_string(&input_path).context("can't read input")?;
        fuzz_params = fuzz::Params::from_str(&input_str).context("can't parse input")?;
        // read parameters from workdir
        // set input param and size from state
    }

    p.single("Will use random strategy");
    let mut strategy = fuzz::RandomStrategy::new();
 
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
    let context_str = std::fs::read_to_string(&context_path).context("can't read context")?;
    let context = trace::ProcessorState::from_str(&context_str).context("can't parse context")?;

    p.single("Loading parameters");
    let params_path = snapshot_path.join("params.json");
    let params_str = std::fs::read_to_string(&params_path).context("can't read params")?;
    let mut params = trace::parse_params(&params_str).context("can't parse params")?;

    params.limit = args.limit;
    params.save_context = args.save_context;
    params.coverage_mode = args.coverage;

    p.single("Loading tracer");

    // FIXME: need a better name
    // replace emulator with backend or tracer
    let mut tracer = get_emulator(snapshot, args.emulator)?;

    let p = p.leave();

    let p = p.enter("Running fuzzer");

   let mut fuzzer = fuzz::Fuzzer::new(&path)?;

    // FIXME: need to periodically write fuzzer stats

    eprintln!("Will fuzz function {:x}, input {:x} ({:x})", context.rip, fuzz_params.input, fuzz_params.input_size);

    let callback = |fuzzer: &mut fuzz::Fuzzer, stats: &mut fuzz::Stats| -> Result<()> {
        match stats.update_display() {
            Some(msg) => eprintln!("{}", msg),
            None => ()
        }
        Ok(())
    };

    // FIXME: method on emulator ? calling this Fuzzer ?
    let stats = match tracer {
        #[cfg(feature = "whvp")]
        Emulator::Whvp(mut tracer) => {
            let stats = fuzzer.run(&mut strategy, &fuzz_params, &mut tracer, &context, &params, callback)?;
            stats
        }
        #[cfg(feature = "bochs")]
        Emulator::Bochs(mut tracer) => {
            let stats = fuzzer.run(&mut strategy, &fuzz_params, &mut tracer, &context, &params, callback)?;
            stats
        }
        _ => {
            unreachable!();

        }
    };

    eprintln!("fuzzing session ended after {:?} and {} iteration(s)", stats.total_start.elapsed(), stats.total_iterations);
    p.single("All done");

    Ok(())
}

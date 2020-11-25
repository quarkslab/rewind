
use std::io::prelude::*;
use std::str::FromStr;
use anyhow::{Result, Context};
use simple_logger;

use clap::Clap;

use rewind_core::trace::{self, Tracer};
use rewind_cli::helpers;

use rewind_snapshot as snapshot;

#[macro_use]
extern crate anyhow;

pub mod cli;

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
    
    let p = p.enter("Parsing snapshot");

    p.single("Loading dump file");
    let dump_path = args.snapshot.join("mem.dmp");
    let snapshot = snapshot::DumpSnapshot::new(&dump_path)?;

    p.single("Reading context");
    let context_path = args.snapshot.join("context.json");
    let context_str = std::fs::read_to_string(&context_path).context("can't read context")?;
    let context = trace::ProcessorState::from_str(&context_str).context("can't parse context")?;

    p.single("Reading parameters");
    let params_path = args.snapshot.join("params.json");
    let params_str = std::fs::read_to_string(&params_path).context("can't read params")?;
    let mut params = trace::parse_params(&params_str).context("can't parse params")?;

    let p = p.leave();

    let p = p.enter("Running tracer");

    let mut tracer: Box<dyn Tracer> = match args.emulator {
        rewind_cli::EmulatorType::Whvp => {
            #[cfg(feature = "whvp")] {
                use rewind_whvp::WhvpTracer;
                let tracer = WhvpTracer::new(snapshot)?;
                Box::new(tracer)
            } 
            #[cfg(not(feature = "whvp"))] {
                p.error("can't use whvp tracer, feature is missing");
                return Err(anyhow!("missing feature"))
            }
        },
        rewind_cli::EmulatorType::Bochs => {
            #[cfg(feature = "bochs")] {
                use rewind_bochs::BochsTracer;
                let tracer = BochsTracer::new(snapshot)?;
                Box::new(tracer)
            }
            #[cfg(not(feature = "bochs"))] {
                p.error("can't use bochs tracer, feature is missing");
                return Err(anyhow!("missing feature"))
            }
        },
    };

    tracer.set_initial_context(&context)?;

    params.limit = args.limit;
    params.save_context = args.save_context;
    params.coverage_mode = args.coverage;
    let mut trace = tracer.run(&params)?;

    // FIXME: what to do if trace is incomplete
    let t = trace.end.unwrap() - trace.start.unwrap();

    let pages = trace.code + trace.data;
    let mem = rewind_core::helpers::convert((pages * 0x1000) as f64);
    p.single(format!("executed {} instructions in {:?} ({:?})", trace.coverage.len(), t, trace.status));
    p.single(format!("seen {} unique addresses", trace.seen.len()));
    p.single(format!("mapped {} pages ({})", pages, mem));

    let pages = tracer.restore_snapshot();
    p.single(format!("{:?} page(s) were modified", pages.unwrap()));

    let p = p.leave();

    match (args.input, args.data) {
        (Some(input_path), Some(filename)) => {
            let p = p.enter("Replaying input");
            p.single("Reading input");
            let input_str = std::fs::read_to_string(&input_path).context("can't read input")?;
            let input = trace::Input::from_str(&input_str).context("can't parse input")?;
            tracer.set_initial_context(&context)?;

            let cr3 = context.cr3;

            let mut file = std::fs::File::open(filename)?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;

            match tracer.write_gva(cr3, input.address.into(), &buffer) {
                Ok(()) => {}
                Err(e) => {
                    return Err(anyhow!("can't write fuzzer input"));
                }
            }

            tracer.set_initial_context(&context)?;

            trace = tracer.run(&params)?;

            let t = trace.end.unwrap() - trace.start.unwrap();

            let pages = trace.code + trace.data;
            let mem = rewind_core::helpers::convert((pages * 0x1000) as f64);
            p.single(format!("executed {} instructions in {:?} ({:?})", trace.coverage.len(), t, trace.status));
            p.single(format!("seen {} unique addresses", trace.seen.len()));
            p.single(format!("mapped {} pages ({})", pages, mem));

            let pages = tracer.restore_snapshot();
            p.single(format!("{:?} page(s) were modified", pages.unwrap()));

        },
        (Some(input_path), None) => {
            let input_str = std::fs::read_to_string(&input_path).context("can't read input")?;
            let input = trace::Input::from_str(&input_str).context("can't parse input")?;
            
            let size: u64 = input.size.into();
            let mut data = vec![0u8; size as usize];

            let cr3 = tracer.cr3()?;
            tracer.read_gva(cr3, input.address.into(), &mut data)?;

            let hash = rewind_core::fuzz::calculate_hash(&data);
            let path = std::path::PathBuf::from(format!("{:x}.bin", hash));
            let mut file = std::fs::File::create(path)?;
            file.write_all(&data)?;


        }
        _ => ()
    }
 
    match args.trace {
        Some(path) => {
            let p = p.enter(format!("Saving trace to {:?}", path));
            trace.save(path.to_str().unwrap())?;
            p.leave();
        }
        None => {}
    }

    p.single("All done");

    Ok(())
}

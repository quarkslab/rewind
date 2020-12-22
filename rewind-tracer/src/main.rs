
use std::io::prelude::*;
use std::str::FromStr;
use std::collections::BTreeSet;

use anyhow::{Result, Context};
use simple_logger;

use clap::Clap;

use rewind_core::trace::{self, Tracer};
use rewind_core::mem::X64VirtualAddressSpace;

use rewind_cli::{Backend, helpers};

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
    let mut params = trace::Params::from_str(&params_str).context("can't parse params")?;

    let p = p.leave();

    let p = p.enter("Running tracer");

    // let mut backend = Backend::new(snapshot, args.backend)?;

    let mut tracer = rewind_cli::BochsTracer::new(snapshot)?;

    // let backend: Backend<snapshot::DumpSnapshot> = tracer.into();
    // let tracer = backend.get_tracer();

    tracer.set_state(&context)?;

    params.limit = args.limit;
    params.save_context = args.save_context;
    params.max_duration = std::time::Duration::from_secs(args.max_time);
    params.coverage_mode = args.coverage;

    let trace = tracer.run(&params)?;

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
            let input_str = std::fs::read_to_string(&input_path).context("can't read input")?;
            let input = trace::Input::from_str(&input_str).context("can't parse input")?;

            let cr3 = context.cr3;

            let mut file = std::fs::File::open(filename)?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;

            let address = input.address.into();
            let size: u64 = input.size.into();

            p.single(format!("Writing input {:x} ({:x})", address, size));

            match Tracer::write_gva(&mut tracer, cr3, address, &buffer) {
                Ok(()) => {}
                Err(e) => {
                    return Err(anyhow!("can't write fuzzer input {}", e));
                }
            }

            // params.excluded_addresses.insert("nt!HalRequestSoftwareInterrupt".to_string(), 0xfffff8048061a030);

            tracer.set_state(&context)?;

            let cng_save_root_address: u64 = 0xfffff8048308fe2f;
            let ex_allocate_pool_address: u64 = 0xfffff80480db1030;

            let hal_request: u64 = 0xfffff8048061a030;

            tracer.add_breakpoint(ex_allocate_pool_address);
            tracer.add_breakpoint(cng_save_root_address);
            tracer.add_breakpoint(hal_request);


            let mut count = 0;
            let mut allocs: Vec<(u64, u64)> = Vec::new();
            let mut size = 0;
            loop {
                let trace = tracer.run(&params)?;
                // break;
                for access in trace.mem_access.iter() {
                    for alloc in allocs.iter() {
                        if access.1 >= alloc.0 && access.1 < alloc.0 + alloc.1 {
                            // println!("{:x?} {:x?}", access, alloc);
                            if access.1 + access.3 as u64 > alloc.0 + alloc.1 {
                                println!("access outside known alloc");
                            }
                        }
                        if access.1 == alloc.0 + alloc.1 {
                            println!("{:x?} {:x?}", access, alloc);
                            println!("access outside known alloc");

                        }

                    }
                }

                if trace.status != rewind_core::trace::EmulationStatus::Breakpoint {
                    println!("{} allocations", count);

                    let pages = tracer.restore_snapshot()?;

                    let t = trace.end.unwrap() - trace.start.unwrap();

                    let total = trace.code + trace.data;
                    let mem = rewind_core::helpers::convert((total * 0x1000) as f64);
                    p.single(format!("executed {} instructions in {:?} ({:?})", trace.coverage.len(), t, trace.status));
                    p.single(format!("seen {} unique addresses", trace.seen.len()));
                    p.single(format!("mapped {} pages ({})", total, mem));

                    p.single(format!("{:?} page(s) were modified", pages));
                    println!("{:x?}", allocs);
                   break
                }

                let mut state = tracer.get_state()?;
                match state.rip {
                    _ if state.rip == ex_allocate_pool_address => {
                        let return_address = tracer.read_gva_u64(state.cr3, state.rsp)?;
                        // println!("return address is {:x}", return_address);
                        tracer.add_breakpoint(return_address);
                        count += 1;
                        size = state.rdx;
                        // println!("allocate {:x} {:x} {:x}", rcx, rdx, r8);
                        tracer.singlestep(&params)?;
                    },
                    _ if state.rip == cng_save_root_address => {
                        println!("in save root");
                        state.rax = 0;
                        state.rip = state.rip + 5;
                        tracer.set_state(&state);
                    },
                    _ if state.rip == hal_request => {
                        println!("request_software");
                        println!("{:x?}", state.rcx);
                        tracer.singlestep(&params)?;
                    }
                    _ => {
                        allocs.push((state.rax, size));
                        // println!("rax {:x}", state.rax);
                        tracer.singlestep(&params)?;

                    }
                }


                // break

            }

            

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
            p.single(format!("writing input to {:?}", &path));
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

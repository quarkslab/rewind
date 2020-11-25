use std::str::FromStr;
use std::collections::HashMap;

use anyhow::{Result, Context};
use simple_logger;

use rewind_core::trace;
use rewind_cli::helpers;

use rewind_snapshot as snapshot;

#[macro_use]
extern crate anyhow;

use custom_debug::Debug;

use clap::{Clap, crate_version};

#[derive(Clap, Debug)]
#[clap(version=crate_version!(), author="Damien Aumaitre")]
pub struct Cli {
    /// Set the level of verbosity
    #[clap(long, short, parse(from_occurrences))]
    pub verbose: usize,
 
    #[clap(long="snapshot", parse(from_os_str))]
    pub snapshot: std::path::PathBuf,

    #[clap(long="trace", parse(from_os_str))]
    pub trace: std::path::PathBuf,

    #[clap(long="store", parse(from_os_str))]
    pub store: std::path::PathBuf,


}

mod system;
mod pe;
mod pdbstore;

fn main() -> Result<()> {
    let args = Cli::parse();

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
    
    let p = p.enter("Loading snapshot");

    let dump_path = args.snapshot.join("mem.dmp");
    let snapshot = snapshot::DumpSnapshot::new(&dump_path)?;

    p.single("loading modules");
    let mut system = system::System::new(snapshot)?;

    system.load_modules()?;

    p.single(format!("loaded {} modules", system.modules.len()));

    let p = p.leave();

    let p = p.enter("Loading trace");

    let trace_str = std::fs::read_to_string(&args.trace).context("can't read trace")?;
    let trace = trace::Trace::from_str(&trace_str).context("can't parse trace")?;

    let instructions = trace.coverage.len();
    let unique = trace.seen.len();

    p.single(format!("trace has {} instructions and {} are unique", instructions, unique));

    let path = args.store;
    if !path.exists() {
        p.warn("store doesn't exist");

        p.single("Creating directories");
        std::fs::create_dir(&path)?;
        std::fs::create_dir(path.join("binaries"))?;
        std::fs::create_dir(path.join("symbols"))?;
    }

    let mut store = pdbstore::PdbStore::new(path)?;

    let mut modules = HashMap::new();
    let mut functions = HashMap::new();

    for &address in trace.seen.iter() {
        match system.get_module_by_address(address) {
            Some(module) => {
                *modules.entry(&module.name).or_insert_with(|| {

                    match system.get_file_information(module) {
                        Ok(info) => {
                            match store.download_pe(&module.name, &info) {
                                Ok(_) => { }
                                Err(error) => {
                                    p.error(format!("{:?}", error));
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
                                        Err(error) => {
                                            p.error(format!("{:?}", error));
                                        }
                                    }
                                }
                                Err(error) => {
                                    p.error(format!("{:?}", error));
                                }
                            }
                        }
                        Err(_) => { }

                    }
                        
                    0
                }) += 1;

                match store.resolve_address(address) {
                    Some(symbol) => {
                        let name = format!("{}!{}", symbol.module, symbol.name);
                        *functions.entry(name).or_insert(0) += 1;
                    }
                    None => {
                        p.error(format!("can't resolve symbol for {:x}", address));
                    }
                }
    
            }
            None => ()
        }
    }


    let p = p.leave();

    let p = p.enter("Modules");

    let mut modules: Vec<_> = modules.iter().collect();
    modules.sort();

    println!("{} modules", modules.len());

    for (name, instructions) in &modules {
        // FIXME: compute percentage
        p.single(format!("module {}: {} instructions", &name, instructions));

    }

    let p = p.leave();

    let p = p.enter("Functions");

    let mut functions: Vec<_> = functions.iter().collect();
    functions.sort();

    println!("{} functions", functions.len());
    for (name, instructions) in &functions {
        // FIXME: compute percentage
        p.single(format!("function {}: {} instructions", &name, instructions));

    }


    // let path = std::path::PathBuf::from("C:\\ProgramData\\Dbg\\sym");
    // ntkrnlmp.pdb\B16053724B46515388FDEA9D0470D02E1\ntkrnlmp.pdb

    // store.load_pdb("ntkrnlmp.pdb", "B16053724B46515388FDEA9D0470D02E1")?;

    // let address = store.resolve_name("ExAllocatePoolWithTag");
    // println!("{:x?}", address);

    // let address = store.resolve_name("ConfigIoHandler_Safeguarded");
    // println!("{:x?}", address);
 
    // let name = "CfgAdtpFormatPropertyBlock";
    // let address = 0xfffff8007489245c;

    // let resolved_name = store.resolve_address(address);
    // println!("{:?}", resolved_name);

    // let resolved_name = store.resolve_address(address+1);
    // println!("{:?}", resolved_name);

    // let address = 0xfffff8007485c883;
    // let resolved_name = store.resolve_address(address);
    // println!("{:?}", resolved_name);

    // let a = store.resolve_proc(name);
    // println!("{:?}", a);



    // let iterations = iter.map(|(a, _b)| a).dedup().inspect(|a| {
        // println!("{:016x}", a);
    // })
    // .take(9000)
    // .take_while(|(_, (a, b))| {
        // a == b
    // })
    // .count();

    Ok(())


}


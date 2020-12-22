
use std::str::FromStr;
use std::collections::{HashMap, BTreeSet};
use std::io::Read;

use anyhow::{Result, Context};
use simple_logger;

use clap::Clap;

use rewind_core::fuzz;
use rewind_core::trace::{self, Tracer};
use rewind_cli::helpers;
use rewind_bochs::BochsTracer;
use rewind_system::system;
use rewind_system::pdbstore;
use rewind_snapshot as snapshot;

#[macro_use]
extern crate anyhow;

#[derive(Clap, Debug)]
#[clap(author="Damien Aumaitre")]
pub struct Cli {
    /// Set the level of verbosity
    #[clap(long, short, parse(from_occurrences))]
    pub verbose: usize,

    /// Specify fuzzer workdir
    #[clap(long="workdir", parse(from_os_str))]
    pub workdir: std::path::PathBuf,

    /// Specify symbol directory
    #[clap(long="store", parse(from_os_str))]
    pub store: std::path::PathBuf,

}

fn parse_trace(coverage: &mut BTreeSet<u64>, trace: &trace::Trace, system: &system::System, store: &mut pdbstore::PdbStore, modules: &mut HashMap<String, usize>, functions: &mut HashMap<String, usize>) -> Result<()> {
    for &address in trace.seen.difference(coverage) {
        // if !coverage.insert(address) {
            // continue
        // }
        match system.get_module_by_address(address) {
            Some(module) => {
                *modules.entry(module.name.clone()).or_insert_with(|| {

                    // FIXME: need a fn in system.rs
                    match system.get_file_information(module) {
                        Ok(info) => {
                            match store.download_pe(&module.name, &info) {
                                Ok(_) => { }
                                Err(error) => {
                                    println!("{:?}", error);
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
                                            println!("{:?}", error);
                                        }
                                    }
                                }
                                Err(error) => {
                                    println!("{:?}", error);
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
                        println!("can't resolve symbol for {:x}", address);
                    }
                }
    
            }
            None => ()
        }
    }


    Ok(())
}

fn display_coverage(modules: &mut HashMap<String, usize>, functions: &mut HashMap<String, usize>) {
    let mut modules: Vec<_> = modules.iter().collect();
    modules.sort();

    for (name, instructions) in &modules {
        // FIXME: compute percentage
        println!("{}: {} instructions", &name, instructions);
    }

    let mut functions: Vec<_> = functions.iter().collect();
    functions.sort();

    for (name, instructions) in &functions {
        // FIXME: compute percentage
        println!("{}: {} instructions", &name, instructions);

    }

}

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
    
    let p = p.enter("Fuzzer setup");

    let path = &args.workdir;
    if !path.exists() {
        return Err(anyhow!("workdir doesn't"));
    }

    p.single("Loading fuzzer parameters");
    let input_path = path.join("params.json");
    let input_str = std::fs::read_to_string(&input_path).context("can't read input")?;
    let fuzz_params = fuzz::Params::from_str(&input_str).context("can't parse input")?;

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

    params.save_context = true;

    p.single("Running tracer");

    let mut tracer = BochsTracer::new(snapshot)?;
    // tracer.set_state(&context)?;

    // let mut trace = tracer.run(&params)?;

    // let _pages = tracer.restore_snapshot();
    // p.single(format!("{:?} page(s) were modified", pages.unwrap()));

    let mut system = system::System::new(&tracer.snapshot)?;
    system.load_modules()?;

    p.single(format!("Loaded {} modules", system.modules.len()));

    let path = &args.store;
    if !path.exists() {
        p.single("Creating store directories");
        std::fs::create_dir(&path)?;
        std::fs::create_dir(path.join("binaries"))?;
        std::fs::create_dir(path.join("symbols"))?;
    }

    let mut store = pdbstore::PdbStore::new(path)?;

    let mut rules = fuzz::MutationRules::new();

    loop {
        let path = std::path::Path::new(&args.workdir).join("corpus");
        let mut entries = std::fs::read_dir(path)?
            .map(|res| res.map(|e| e.path()))
            .collect::<Result<Vec<_>, std::io::Error>>()?;

        entries.sort();

        let mut coverage = BTreeSet::new();
        let mut modules = HashMap::new();
        let mut functions = HashMap::new();

        p.single(format!("Replaying corpus, {} files", entries.len()));
        for path in entries {
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

                let mut trace = tracer.run(&params)?;
                tracer.restore_snapshot()?;

                rules.immediates.append(&mut trace.immediates);
                let address = fuzz_params.input;
                let size = fuzz_params.input_size;
                let filtered = trace.mem_access.iter().filter(|a| {
                    a.1 >= address && a.1 < address + size
                }).map(|a| {
                    a.1 - address
                });
            
                rules.offsets.extend(filtered);

                // let count = trace.seen.difference(&coverage).count();
                if trace.seen.is_subset(&coverage) {
                    println!("no new coverage for {:?}, deleting file", path);
                    std::fs::remove_file(&path)?;
                } else {
                    parse_trace(&mut coverage, &trace, &system, &mut store, &mut modules, &mut functions)?;
                    coverage.append(&mut trace.seen);
                }
            }
        }
        println!("immediates {}, offsets {}", rules.immediates.len(), rules.offsets.len());
        println!("unique addresses {}, {} modules, {} functions", coverage.len(), modules.len(), functions.len());
        display_coverage(&mut modules, &mut functions);

        let path = std::path::Path::new(&args.workdir).join("rules.json");
        rules.save(&path)?;

        p.single("Waiting 5 secs");
        std::thread::sleep(std::time::Duration::from_secs(5));
    }

    // FIXME: insert sanitizer, configure timeout for trace, remove useless corpus entries

    p.single("All done");

    Ok(())
}

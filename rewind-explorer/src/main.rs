use std::str::FromStr;
use std::collections::HashMap;
use std::fmt::Write;
use std::io::Write as IoWrite;

#[macro_use]
extern crate anyhow;

use anyhow::{Result, Context};
use simple_logger;

use rewind_core::trace;
use rewind_core::mem::X64VirtualAddressSpace;

use rewind_cli::helpers;

use rewind_system::system;
use rewind_system::pdbstore;

use rewind_snapshot as snapshot;

use custom_debug::Debug;

use clap::{Clap, crate_version};

use zydis;

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

    #[clap(short='l', long="limit")]
    pub limit: Option<usize>,

    #[clap(short='s', long="skip")]
    pub skip: Option<usize>,

    #[clap(long="exclude")]
    pub exclude: Option<Vec<String>>,

    #[clap(long="include")]
    pub include: Option<Vec<String>>,

    #[clap(short='o', long="output", parse(from_os_str))]
    pub output: Option<std::path::PathBuf>,

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
    
    let p = p.enter("Loading snapshot");

    let dump_path = args.snapshot.join("mem.dmp");
    let snapshot = snapshot::DumpSnapshot::new(&dump_path)?;

    let cr3 = snapshot.get_cr3();

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

    let path = &args.store;

    if !path.exists() {
        p.warn("store doesn't exist");

        p.single("Creating directories");
        std::fs::create_dir(&path)?;
        std::fs::create_dir(path.join("binaries"))?;
        std::fs::create_dir(path.join("symbols"))?;
    }

    let mut store = pdbstore::PdbStore::new(path)?;

    p.single("loading modules belonging to trace");

    let mut modules = HashMap::new();

    for &address in trace.seen.iter() {
        match system.get_module_by_address(address) {
            Some(module) => {
                *modules.entry(&module.name).or_insert_with(|| {

                    // FIXME: need a fn in system.rs
                    match system.get_file_information(module) {
                        Ok(info) => {
                            match store.download_pe(&module.name, &info) {
                                Ok(_) => {
                                    eprintln!("downloaded {}", &module.name);
                                 }
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
                                    eprintln!("downloaded {}", &name);
                                    match store.load_pdb(module.base, &name, &guid) {
                                        Ok(_) => {
                                            eprintln!("loaded pdb {} {}", &name, &guid);
                                        },
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
            }
            None => ()
        }
    }

    let p = p.leave();
    let p = p.enter("Parsing trace");

    let iter = trace.coverage.iter().map(|(address, _context)| -> Result<String>{
        let name = match store.resolve_address(*address) {
            Some(symbol) => {

                let name = match symbol.offset {
                    0 => {
                        format!("{}!{}", symbol.module, symbol.name)
                    },
                    _ => {
                        format!("{}!{}+{:x}", symbol.module, symbol.name, symbol.offset)
                    }
                };

                Some(name)

            }
            None => {
                match system.get_module_by_address(*address) {
                    Some(module) => {
                        let name = format!("{}+{:x}", module.name, *address - module.base);
                        Some(name)
                    }
                    None => {
                        None
                    }
                }
            }
        };

        let mut bytes = vec![0u8; 16];
        system.snapshot.read_gva(cr3, *address, &mut bytes)?;
        let instruction = decode_instruction(&bytes)?;
        let n = instruction.length as usize;
        let formatted_instruction = format_instruction(*address, instruction)?;

        let mut formatted_bytes = String::with_capacity(2 * n);
        for byte in &bytes[..n] {
            write!(formatted_bytes, "{:02x}", byte)?;
        }
        
        let result = match name {
            Some(name) => {
                format!("{}\n{:016x} {:<32}{:<20}", name, *address, formatted_bytes, formatted_instruction)
            }
            None => {
                format!("{:016x} {:<32}{:<20}", *address, formatted_bytes, formatted_instruction)
            }
        };

        Ok(result)

    })
    .enumerate()
    .filter(|(_, line)| {
        match line {
            Ok(line) => {
                match &args.exclude {
                    Some(patterns) => {
                        !patterns.iter().any(|pattern| {
                            let p = pattern.to_lowercase();
                            line.to_lowercase().matches(&p).count() > 0
                        })
                    }
                    None => {
                        true
                    }
                }
            }
            Err(_) => {
                true
            }
        }
    })
    .filter(|(_, line)| {
        match line {
            Ok(line) => {
                match &args.include {
                    Some(patterns) => {
                        patterns.iter().any(|pattern| {
                            let p = pattern.to_lowercase();
                            line.to_lowercase().matches(&p).count() > 0
                        })
                    }
                    None => {
                        true
                    }
                }
            }
            Err(_) => {
                true
            }
        }
    })
    .enumerate()
    .skip_while(|(i, (_, _))| {
        match args.skip {
            Some(skip) => {
                *i < skip
            }
            _ => {
                false
            }
        }
    })
    .take_while(|(i, (_, _))| {
        match args.limit {
            Some(limit) => {
                *i < limit
            }
            _ => {
                true
            }
        }
    });

    match &args.output {
        Some(path) => {
            let mut file = std::fs::File::create(path)?;
            p.single("writing result to file");
            for (i, (index, line)) in iter {
                match line {
                    Ok(line) => {
                        writeln!(&mut file, "=> instruction #{} (#{})", i, index)?;
                        writeln!(&mut file, "{}\n", line)?;
                    }
                    Err(_) => ()
                }
            }
        }
        None => {
            for (i, (index, line)) in iter {
                match line {
                    Ok(line) => {
                        println!("=> instruction #{} (#{})", i, index);
                        println!("{}\n", line);
                    }
                    Err(_) => ()
                }
            }
        }
    }

    let p = p.leave();
    p.enter("All done");

    Ok(())

}

fn decode_instruction(buffer: &[u8]) -> Result<zydis::DecodedInstruction> {
    let decoder = zydis::Decoder::new(zydis::MachineMode::LONG_64, zydis::AddressWidth::_64)?;
    let result = decoder.decode(&buffer)?;
    if let Some(instruction) = result {
        Ok(instruction)
    } else {
        Err(anyhow!("can't decode instruction"))
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


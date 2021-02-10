
use std::collections::{HashMap, BTreeMap};
use std::fs::File;
use std::io;
// use std::io::Read;
use std::path::PathBuf;

use thiserror::Error;

use pdb::{FallibleIterator, Rva, SymbolData,PDB};

use crate::pe;

const SYMBOL_SERVER: &str = "http://msdl.microsoft.com/download/symbols";

type Symbols = HashMap<String, u64>;

#[derive(Debug)]
pub struct Procedure {
    size: usize,
    offset: u64
}

type Procedures = HashMap<String, Procedure>;

#[derive(Debug)]
pub struct Symbol {
    pub module: String,
    pub name: String,
    pub address: u64,
    pub offset: usize
}

impl std::fmt::Display for Symbol {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.offset == 0 {
            write!(f, "{}!{}", self.module, self.name)
        } else {
            write!(f, "{}!{}+0x{:x}", self.module, self.name, self.offset)
        }
    }
}

pub struct LoadedPdb {
    pub name: String,
    pub symbols: Symbols,
    pub procedures: Procedures,
    pub index: BTreeMap<u64, String>,
    // pub structs: StructStore,
}

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("error happened during server download: {0}")]
    DownloadError(String),

    #[error("unknown store error")]
    Unknown,

    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("pdb error: {0}")]
    PdbError(#[from] pdb::Error),

    #[error("network error: {0}")]
    NetworkError(#[from] reqwest::Error),
}


pub struct PdbStore {
    path: PathBuf,
    pdbs: HashMap<u64, LoadedPdb>,
}

impl PdbStore {

    pub fn new<P>(path: P) -> Result<Self, StoreError>
    where P: Into<PathBuf> 
    {
        let store = Self {
            path: path.into(),
            pdbs: HashMap::new()
        };
        Ok(store)

    }

    pub fn load_pdb(&mut self, base: u64, pdbname: &str, guid: &str) -> Result<(), StoreError> {
        let pdb_path = self.path.join("symbols").join(pdbname).join(guid).join(pdbname);

        // println!("path is {:?}", pdb_path);
        let f = File::open(pdb_path)?;
        let mut pdb = PDB::open(f)?;

        let _info = pdb.pdb_information()?;
        let _dbi = pdb.debug_information()?;
        // println!("PDB for {}, guid: {}, age: {}\n", dbi.machine_type().unwrap(), info.guid, dbi.age().unwrap_or(0));

        let type_information = pdb.type_information()?;
        let mut type_finder = type_information.finder();
        let mut iter = type_information.iter();
        while let Some(_typ) = iter.next().unwrap() {
            type_finder.update(&iter);
        }

        let mut symbols: Symbols = HashMap::new();
        let mut procedures: Procedures = HashMap::new();

        let mut index: BTreeMap<u64, String> = BTreeMap::new();

        let addr_map = pdb.address_map()?;
        let global_symbols = pdb.global_symbols()?;
        let mut iter = global_symbols.iter();
        while let Some(symbol) = iter.next()? {
            match symbol.parse()? {
                SymbolData::Public(data) => {
                    let Rva(rva) = data.offset.to_rva(&addr_map).unwrap_or_default();
                    let name = data.name.to_string().to_string();
                    symbols.insert(name.clone(), rva as u64);
                    index.insert(rva.into(), name);

                }
                SymbolData::Procedure(data) => {
                    println!("procedure {:?}", data);
                }
                _ => {}
            }
        }

        let debug_info = pdb.debug_information()?;
        let mut modules = debug_info.modules()?;
        while let Some(module) = modules.next()? {
            let module_info = pdb.module_info(&module)?;
            if module_info.is_none() {
                // println!("Could not get module info for debug module: {:?}", module);
                continue;
            }

            // println!("grabbing symbols for module: {}", module.module_name());
            let module_info = module_info.unwrap();
            let mut symbol_iter = module_info.symbols()?;
            while let Some(symbol) = symbol_iter.next()? {
                match symbol.parse() {
                    Ok(data) => {
                        match data {
                            SymbolData::Public(data) => {
                                let Rva(rva) = data.offset.to_rva(&addr_map).unwrap_or_default();
                                let name = data.name.to_string().to_string();
                                symbols.insert(name.clone(), rva as u64);
                            }
                            SymbolData::Procedure(data) => {
                                let Rva(offset) = data.offset.to_rva(&addr_map).unwrap_or_default();
                                
                                let name = data.name.to_string().to_string();
                                let procedure = Procedure {
                                    size: data.len as usize,
                                    offset: offset as u64
                                };

                                procedures.insert(name, procedure);
                            }
                            _ => {}
                        }
                    },
                    Err(_e) => {
                        // println!("could not parse {:?}", e);
                    }
                }
            }
        }

        // println!("loaded {} symbols", symbols.len());
        // println!("loaded {} functions", procedures.len());

        let pdb = LoadedPdb {
            name: pdbname.to_string(),
            symbols,
            procedures,
            index,
        };

        self.pdbs.insert(base, pdb);

        Ok(())
    }

    pub fn resolve_name(&mut self, name: &str) -> Option<u64> {
        for (base, pdb) in self.pdbs.iter() {
            let symbol = pdb.symbols.iter().find(|symbol| {
                symbol.0 == name
            });
            
            if let Some((_name, address)) = symbol {
                return Some(base + *address)
            }
        }

        None
    }

    pub fn resolve_proc(&mut self, procname: &str) -> Option<&Procedure> {
        for (_base, pdb) in self.pdbs.iter() {
            let procedure = pdb.procedures.iter().find(|(name, _procedure)| {
                *name == procname
            });
            
            if let Some((_name, procedure)) = procedure {
                return Some(procedure)
            }
        }

        None
    }

    pub fn resolve_address(&mut self, address: u64) -> Option<Symbol> {
        for (base, pdb) in self.pdbs.iter() {
            if address < *base {
                continue
            }

            let mut iter = pdb.index.iter().peekable();
            while let Some((&rva, name)) = iter.next() {
                // println!("comparing {:x} vs {:x}", base + rva, address);
                if address >= base + rva {
                    if let Some((&next_rva, _next_name)) = iter.peek() {
                        if address < base + next_rva {
                            let offset = address - base - rva;
                            let pdbname = pdb.name.replace(".pdb", "");
                            let symbol = Symbol {
                                module: pdbname,
                                name: name.to_string(),
                                address: base + rva,
                                offset: offset as usize
                            };
                            
                            return Some(symbol)
                        }
                    }
                }
            }

            // let symbol = pdb.symbols.iter().find(|symbol| {
            //     *symbol.1 == address - base
            // });
            
            // match symbol {
            //     Some((name, _address)) => return Some(name.to_string()),
            //     None => ()
            // }

            // let procedure = pdb.procedures.iter().find(|(name, procedure)| {
            //     address >= base + procedure.offset && address < base + procedure.offset + procedure.size as u64
            // });

            // match procedure {
            //     Some((name, procedure)) => return Some(format!("{}+{:x}", name, address - base - procedure.offset)),
            //     None => ()
            // }
        }

        None
    }

    pub fn download_pe(&self, name: &str, info: &pe::FileInformation) -> Result<(), StoreError> {
        // should return an enum with download, or already present
        // FIXME: symbol server should not be hardcoded
        let hash = format!("{:08X}{:X}", info.timestamp, info.size);
        let directory = self.path.join("binaries").join(name).join(&hash);
        let outfile = directory.join(name);
        
        if outfile.exists() {
            return Ok(())
        }

        let url = format!("{}/{}/{}/{}", SYMBOL_SERVER, name, &hash, name);

        let mut resp = reqwest::blocking::get(&url)?;

        let status = resp.status();
        if !status.is_success() {
            let msg = format!("{} for {}", status, url);
            return Err(StoreError::DownloadError(msg));
        }

        std::fs::create_dir_all(&directory)?;
        let mut out = File::create(outfile)?;
        io::copy(&mut resp, &mut out)?;
        Ok(())
    }

    pub fn download_pdb(&self, name: &str, guid: &str) -> Result<(), StoreError> {
        // should return an enum with download, or already present
        let directory = self.path.join("symbols").join(name).join(guid);
        let outfile = directory.join(name);
        
        if outfile.exists() {
            return Ok(())
        }

        let url = format!("{}/{}/{}/{}", SYMBOL_SERVER, name, guid, name);

        let mut resp = reqwest::blocking::get(&url)?;

        let status = resp.status();
        if !status.is_success() {
            let msg = format!("{} for {}", status, url);
            return Err(StoreError::DownloadError(msg));
        }

        std::fs::create_dir_all(&directory)?;
        let mut out = File::create(outfile)?;
        io::copy(&mut resp, &mut out)?;
        Ok(())
    }


}

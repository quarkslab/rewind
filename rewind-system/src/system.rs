

use std::char::DecodeUtf16Error;
use zerocopy::{LayoutVerified, FromBytes};

use thiserror::Error;

use rewind_core::{mem::X64VirtualAddressSpace, snapshot::Snapshot};

use crate::pe;

/// System error
#[derive(Debug, Error)]
pub enum SystemError {
    /// Can't parse PE
    #[error("parse error: {}", .0)]
    ParseError(String),

    /// Can't read debug info from virtual memory
    #[error("mem error: {0}")]
    MemError(#[from] rewind_core::mem::VirtMemError),

    /// Can't decode UTF-16 string
    #[error("decode error: {0}")]
    DecodeError(#[from] DecodeUtf16Error),

}

/// Operating system
pub struct System <'a, S> {

    /// Snapshot
    pub snapshot: &'a S,

    /// Loaded modules
    pub modules: Vec<LoadedModule>,

}

impl <'a, S> System <'a, S>
where S: Snapshot + X64VirtualAddressSpace
{
    /// Constructor
    pub fn new(snapshot: &'a S) -> Result<Self, SystemError> {
        let system = Self {
            snapshot,
            modules: Vec::new(),

        };
        Ok(system)
    }

    /// Get loaded modules
    pub fn get_loaded_modules(&self) -> Vec<LoadedModule> {
        let cr3 = self.snapshot.get_cr3();
        println!("cr3 is {:x}", cr3);
        todo!()
    } 

    /// Parse snapshot and load modules
    pub fn load_modules(&mut self) -> Result<(), SystemError> {
        let cr3 = self.snapshot.get_cr3();
        // println!("cr3 is {:x}", cr3);

        let module_list = self.snapshot.get_module_list();
        // println!("module list head: {:x}", module_list);

        let size = std::mem::size_of::<LdrDataTableEntry>();

        let mut address = self.snapshot.read_gva_u64(cr3, module_list)?;
        // println!("module is {:x}", address);

        let mut data = vec![0u8; size];

        while address != module_list {
            self.snapshot.read_gva(cr3, address, &mut data)?;
            let (entry, _) = LayoutVerified::<_, LdrDataTableEntry>::new_from_prefix(&data[..])
                .ok_or_else(|| SystemError::ParseError("can't read ldr data".into()))?;

            address = entry.InLoadOrderLinks.Flink;

            let dllname = entry.BaseDllName.Buffer;
            let length = entry.BaseDllName.Length as usize;

            let mut name = vec![0u8; length];
            self.snapshot.read_gva(cr3, dllname, &mut name)?;

            let iter = (0..length / 2).map(|i| u16::from_le_bytes([name[2*i], name[2*i+1]]));
            let name = std::char::decode_utf16(iter).collect::<Result<String, _>>()?;

            let base = entry.DllBase;
            let image_size = entry.SizeOfImage;
            // println!("{} is loaded @ {:x} ({:x})", name, base, image_size);

            let module = LoadedModule::new(name, base, image_size.into())?;
            self.modules.push(module);

        }

        Ok(())
    }

    /// Get module by address
    pub fn get_module_by_address(&self, address: u64) -> Option<&LoadedModule> {
        self.modules.iter().find(|&module| {
            module.base <= address && address < module.base + module.size 
        })
    }

    /// Get module by name
    pub fn get_module_by_name(&self, name: &str) -> Option<&LoadedModule> {
        self.modules.iter().find(|&module| {
            module.name == name 
        })
    }

    /// Get PE FileInfo
    pub fn get_file_information(&self, module: &LoadedModule) -> Result<pe::FileInformation, SystemError> {
        let cr3 = self.snapshot.get_cr3();

        let addr = module.base;

        let mut buf = vec![0u8; 0x1000];
        self.snapshot.read_gva(cr3, addr, &mut buf)?;

        let (header, _) = LayoutVerified::<_, pe::ImageDosHeader>::new_from_prefix(&buf[..])
            .ok_or_else(|| SystemError::ParseError("can't read dos header".into()))?;

        let offset = header.e_lfanew as usize;

        let (header, _) = LayoutVerified::<_, pe::ImageNtHeaders64>::new_from_prefix(&buf[offset..])
            .ok_or_else(|| SystemError::ParseError("can't read nt header".into()))?;

        let info: pe::FileInformation = header.into_ref().into();
        Ok(info)

    }

    /// Get PE DebugInfo
    pub fn get_debug_information(&self, module: &LoadedModule) -> Result<pe::DebugInformation, SystemError> {
        let cr3 = self.snapshot.get_cr3();

        let addr = module.base;

        let mut buf = vec![0u8; 0x1000];
        self.snapshot.read_gva(cr3, addr, &mut buf)?;

        let (header, _) = LayoutVerified::<_, pe::ImageDosHeader>::new_from_prefix(&buf[..])
            .ok_or_else(|| SystemError::ParseError("can't read dos header".into()))?;

        let offset = header.e_lfanew as usize;

        let (header, _) = LayoutVerified::<_, pe::ImageNtHeaders64>::new_from_prefix(&buf[offset..])
            .ok_or_else(|| SystemError::ParseError("can't read nt header".into()))?;

        let debug_directory = &header.optional_header.data_directories[6];
        let address = module.base + debug_directory.virtual_address as u64;
        let size = debug_directory.size as usize;

        self.snapshot.read_gva(cr3, address, &mut buf[..size])?;

        let (directory, _) = LayoutVerified::<_, pe::ImageDebugDirectory>::new_from_prefix(&buf[..])
            .ok_or_else(|| SystemError::ParseError("can't debug directory".into()))?;

        if directory.debug_type != 2 {
            return Err(SystemError::ParseError(format!("debug type {:x} is not handled (yet)", directory.debug_type)));
        }

        let address = module.base + directory.address_of_rawdata as u64;

        let size = directory.size_of_data as usize;
        self.snapshot.read_gva(cr3, address, &mut buf[..size])?;

        let (debug, _) = LayoutVerified::<_, pe::CodeView>::new_from_prefix(&buf[..])
            .ok_or_else(|| SystemError::ParseError("can't read codeview structure".into()))?;

        if debug.signature != 0x53445352 {
            return Err(SystemError::ParseError(format!("invalid codeview signature {:x}", debug.signature)));
        }

        let name = String::from_utf8_lossy(&buf[0x18..size-1]);
        let info = pe::DebugInformation {
            name: name.to_string(),
            guid: debug.guid.clone(),
            age: debug.age,
        };
        Ok(info)

    }
}

#[derive(FromBytes, Debug)]
#[allow(non_snake_case)]
#[repr(C)]
struct ListEntry {
    Flink: u64,
    Blink: u64
}

#[derive(FromBytes, Debug)]
#[allow(non_snake_case)]
#[repr(C)]
struct UnicodeString {
    Length: u16,
    MaximumLength: u16,
    Padding: u32,
    Buffer: u64
}

#[derive(FromBytes, Debug)]
#[allow(non_snake_case)]
#[repr(C)]
struct LdrDataTableEntry {
    InLoadOrderLinks: ListEntry,
    InMemoryOrderLinks: ListEntry,
    InInitializationOrderLinks: ListEntry,
    DllBase: u64,
    EntryPoint: u64,
    SizeOfImage: u32,
    Padding: u32,
    FullDllName: UnicodeString,
    BaseDllName: UnicodeString
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct LoadedModule {
    pub name: String,
    pub base: u64,
    pub size: u64

}

impl LoadedModule {

    pub fn new(name: String, base: u64, size: u64) -> Result<Self, SystemError> {

        let module = Self {
            name,
            base,
            size
        };

        Ok(module)
    }


}


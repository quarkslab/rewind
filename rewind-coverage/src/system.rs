
// let mut tracer = bochs::BochsTracer::new(snapshot)?;

        // tracer.set_initial_context(&context)?;
        // let header = &snapshot.dump.raw_dmp.dmp_header;
        // let major_version = header.major_version;
        // let minor_version = header.minor_version;

        // println!("system is {} {}", major_version, minor_version);


        // let cr3 = header.directory_table_base;
        // let kernel_base = 0;
        // let module_list = header.ps_loaded_module_list;

// pub fn get_modules(snapshot, )
//         let size = std::mem::size_of::<LdrDataTableEntry>();

//         let mut address = snapshot.read_gva_u64(cr3, module_list)?;
//         println!("module is {:x}", address);

//         let mut data = vec![0u8; size];

//         loop {
//             snapshot.read_gva(cr3, address, &mut data);
//             let entry = LdrDataTableEntry::view(&data)?;
//             address = entry.InLoadOrderLinks.Flink.to_int();

//             let buf = entry.BaseDllName.Buffer.to_int();
//             let size = entry.BaseDllName.Length.to_int() as usize;

//             let mut name = vec![0u8; size];
//             snapshot.read_gva(cr3, buf, &mut name)?;

//             let iter = (0..size / 2).map(|i| u16::from_le_bytes([name[2*i], name[2*i+1]]));

//             let name = std::char::decode_utf16(iter).collect::<Result<String, _>>()?;
//             let addr = entry.DllBase.to_int();
//             let size = entry.SizeOfImage.to_int() as usize;
//             println!("{} is loaded @ {:x} ({:x})", name, addr, size);


//             if name == "ntoskrnl.exe" {
//                 let mut buf = vec![0u8; 0x1000];
//                 snapshot.read_gva(cr3, addr, &mut buf)?;
//                 info!("reading PE");
//                 let header = goblin::pe::header::Header::parse(&buf)?;
//                 println!("{:#x?}", header);
//                 let offset = &mut (header.dos_header.pe_pointer as usize
//                     + goblin::pe::header::SIZEOF_PE_MAGIC
//                     + goblin::pe::header::SIZEOF_COFF_HEADER
//                     + header.coff_header.size_of_optional_header as usize);
//                 let sections = header.coff_header.sections(&buf, offset)?;
//                 println!("{:#x?}", sections);
//                 if let Some(optional_header) = header.optional_header {
//                     let file_alignment = optional_header.windows_fields.file_alignment;
//                     if let Some(debug_table) = *optional_header.data_directories.get_debug_table() {
//                         println!("{:#x?}", debug_table);
//                         let rva = addr + (debug_table.virtual_address as u64);
//                         println!("rva {:x}", rva);
//                         let mut debug_data = vec![0u8; debug_table.size as usize];
//                         snapshot.read_gva(cr3, rva, &mut debug_data)?;
//                         println!("{:#x?}", debug_data.hex_dump());
//                         use scroll::Pread;
//                         let dd: goblin::pe::debug::ImageDebugDirectory = (&debug_data).pread_with(0, scroll::LE)?;
//                         println!("{:#x?}", dd);
//                         let cda = addr + (dd.address_of_raw_data as u64);
//                         let cds = dd.size_of_data as usize;
//                         let mut cdd = vec![0u8; cds];
//                         snapshot.read_gva(cr3, cda, &mut cdd);
//                         println!("{:#x?}", cdd.hex_dump());
//                         let mut offset = 0;
//                         let bytes = &cdd;
//                         let codeview_signature: u32 = bytes.gread_with(&mut offset, scroll::LE)?;

//                         let mut signature: [u8; 16] = [0; 16];
//                         signature.copy_from_slice(bytes.gread_with(&mut offset, 16)?);
//                         let age: u32 = bytes.gread_with(&mut offset, scroll::LE)?;
//                         let filename = String::from_utf8_lossy(&bytes[offset..]);

//                         println!("{} {:x?} {}", filename, signature, age);
//                         // let debug_data = Some(goblin::pe::debug::DebugData::parse(
//                             // &buf,
//                             // debug_table,
//                             // &sections,
//                             // file_alignment,
//                         // )?);
//                     }
//                 }
//             }
//             if address == module_list {
//                 break;
//             }

//         }

use anyhow::{Result, Context};
use simple_logger;

use deku::prelude::*;

use rewind_core::mem::{self, X64VirtualAddressSpace};

use crate::pe;


pub struct System <'a> {

    snapshot: rewind_snapshot::DumpSnapshot<'a>,

    pub modules: Vec<LoadedModule>,

}

impl <'a> System <'a>
{

    pub fn new(snapshot: rewind_snapshot::DumpSnapshot<'a>) -> Result<Self>
    {
        let system = Self {
            snapshot,
            modules: Vec::new(),

        };
        Ok(system)
    }

    pub fn get_loaded_modules(&self) -> Vec<LoadedModule> {
        let cr3 = self.snapshot.get_cr3();
        println!("cr3 is {:x}", cr3);
        vec![]
    } 

    pub fn load_modules(&mut self) -> Result<()> {
        let cr3 = self.snapshot.get_cr3();
        // println!("cr3 is {:x}", cr3);

        let module_list = self.snapshot.get_module_list();
        // println!("module list is {:x}", module_list);

        let size = std::mem::size_of::<LdrDataTableEntry>();

        let mut address = self.snapshot.read_gva_u64(cr3, module_list)?;
        // println!("module is {:x}", address);

        let mut data = vec![0u8; size];

        while address != module_list {
            self.snapshot.read_gva(cr3, address, &mut data);
            let (_, entry) = LdrDataTableEntry::from_bytes((&data, 0))?;

            address = entry.InLoadOrderLinks.Flink;

            let dllname = entry.BaseDllName.Buffer;
            let length = entry.BaseDllName.Length as usize;

            let mut name = vec![0u8; length.into()];
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

    pub fn get_module_by_address(&self, address: u64) -> Option<&LoadedModule> {
        self.modules.iter().find(|&module| {
            module.base <= address && address < module.base + module.size 
        })
    }

    pub fn get_module_by_name(&self, name: &str) -> Option<&LoadedModule> {
        self.modules.iter().find(|&module| {
            module.name == name 
        })
    }

    pub fn get_file_information(&self, module: &LoadedModule) -> Result<pe::FileInformation> {
        let cr3 = self.snapshot.get_cr3();

        let addr = module.base;

        let mut buf = vec![0u8; 0x1000];
        self.snapshot.read_gva(cr3, addr, &mut buf)?;
        let (_, header) = pe::ImageDosHeader::from_bytes((&buf, 0))?;

        let offset = header.e_lfanew as usize;

        let (_, header) = pe::ImageNtHeaders64::from_bytes((&buf[offset..], 0))?;

        let info: pe::FileInformation = header.into();
        Ok(info)

    }
    pub fn get_debug_information(&self, module: &LoadedModule) -> Result<pe::DebugInformation> {
        let cr3 = self.snapshot.get_cr3();

        let addr = module.base;

        let mut buf = vec![0u8; 0x1000];
        self.snapshot.read_gva(cr3, addr, &mut buf)?;

        let (_, header) = pe::ImageDosHeader::from_bytes((&buf, 0))?;

        let offset = header.e_lfanew as usize;

        let (_, header) = pe::ImageNtHeaders64::from_bytes((&buf[offset..], 0))?;

        let debug_directory = &header.optional_header.data_directories[6];
        let address = module.base + debug_directory.virtual_address as u64;
        let size = debug_directory.size as usize;

        self.snapshot.read_gva(cr3, address, &mut buf[..size])?;

        let (_, directory) = pe::ImageDebugDirectory::from_bytes((&buf, 0))?;

        if directory.debug_type != 2 {
            return Err(anyhow!("debug type {:x} is not handled (yet)", directory.debug_type));
        }

        let address = module.base + directory.address_of_rawdata as u64;

        let size = directory.size_of_data as usize;
        self.snapshot.read_gva(cr3, address, &mut buf[..size])?;

        let (_, debug) = pe::CodeView::from_bytes((&buf, 0))?;

        if debug.signature != 0x53445352 {
            return Err(anyhow!("invalid codeview signature {:x}", debug.signature));
        }

        let name = String::from_utf8_lossy(&buf[0x18..size-1]);
        let mut info = pe::DebugInformation::default();
        info.name = name.to_string();
        info.guid = debug.guid;
        info.age = debug.age;
        Ok(info)

    }
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[allow(non_snake_case)]
struct ListEntry {
    Flink: u64,
    Blink: u64
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[allow(non_snake_case)]
struct UnicodeString {
    Length: u16,
    MaximumLength: u16,
    Padding: u32,
    Buffer: u64
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[allow(non_snake_case)]
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

    pub fn new(name: String, base: u64, size: u64) -> Result<Self> {

        let module = Self {
            name,
            base,
            size
        };

        Ok(module)
    }


}


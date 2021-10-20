
use zerocopy::FromBytes;

/// DOS header present in all PE binaries
#[derive(FromBytes, Debug, Default)]
#[repr(C)]
pub struct ImageDosHeader {
    /// Magic number: 5a4d
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    /// Pointer to PE header, always at offset 0x3c
    pub e_lfanew: u32,
}

// pub const DOS_MAGIC: u16 = 0x5a4d;

/// COFF Header
#[derive(FromBytes, Debug, Default)]
#[repr(C)]
pub struct ImageFileHeader {
    /// The machine type
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

// pub const PE_MAGIC: u32 = 0x0000_4550;

#[derive(FromBytes, Debug, Default)]
#[repr(C)]
pub struct ImageNtHeaders64 {
    pub signature: u32,
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader64
}

#[derive(FromBytes, Debug, Default)]
#[repr(C)]
pub struct ImageOptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directories: [ImageDataDirectory; 16]
}

#[derive(FromBytes, Debug, Default)]
#[repr(C)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32
}

#[derive(Debug, Default)]
#[repr(C)]
pub struct FileInformation {
    pub timestamp: u32,
    pub size: u32
}

impl From<&ImageNtHeaders64> for FileInformation {

    fn from(header: &ImageNtHeaders64) -> Self {
        Self {
            timestamp: header.file_header.time_date_stamp,
            size: header.optional_header.size_of_image,

        }
    }
}

#[derive(Debug, Default)]
pub struct DebugInformation {
    pub name: String,
    pub guid: Guid,
    pub age: u32
}

impl From<DebugInformation> for (String, String) {

    fn from(info: DebugInformation) -> Self {
        let hash = format!("{:08x}{:04x}{:04x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:x}",
            info.guid.data1,
            info.guid.data2,
            info.guid.data3,
            info.guid.data4[0],
            info.guid.data4[1],
            info.guid.data4[2],
            info.guid.data4[3],
            info.guid.data4[4],
            info.guid.data4[5],
            info.guid.data4[6],
            info.guid.data4[7],
            info.age,
        );
        (info.name, hash)

    }
}

#[derive(FromBytes, Debug, Default)]
#[repr(C)]
pub struct ImageDebugDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub debug_type: u32,
    pub size_of_data: u32,
    pub address_of_rawdata: u32,
    pub pointer_to_rawdata: u32
}

#[derive(FromBytes, Debug, Default, Clone)]
#[repr(C)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8]
}

#[derive(FromBytes, Debug, Default)]
#[repr(C)]
pub struct CodeView {
    pub signature: u32,
    pub guid: Guid,
    pub age: u32,
}
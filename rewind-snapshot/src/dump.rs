use std::collections::BTreeMap;

use zerocopy::{FromBytes, LayoutVerified};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParserError {
    #[error("parse error: {}", .0)]
    ParseError(String),

}

#[derive(Debug)]
pub struct RawDmp <'a>{
    pub header: LayoutVerified<&'a [u8], DmpHeader64>,
    pub context: LayoutVerified<&'a [u8], Context>,
    pub header_ext: LayoutVerified<&'a [u8], DmpHeader64Ext>,
    pub physmem: BTreeMap<u64, &'a [u8]>,
}

impl <'a> RawDmp <'a> {

    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParserError> {
        let (header, run_base) = LayoutVerified::<_, DmpHeader64>::new_from_prefix(bytes).ok_or_else(|| ParserError::ParseError("can't read header".into()))?;
        if header.signature != 0x4547_4150 {
            return Err(ParserError::ParseError(format!("invalid signature, got {:x} instead of {:x}", header.signature, 0x4547_4150)))
        }

        if header.valid_dump != 0x3436_5544 {
            return Err(ParserError::ParseError(format!("invalid signature, got {:x} instead of {:x}", header.valid_dump, 0x3436_5544)))
        }
 
        let buffer = &bytes[0x348..];

        let (context, _bytes) = LayoutVerified::<_, Context>::new_from_prefix(buffer).ok_or_else(|| ParserError::ParseError("can't read context".into()))?;

        let buffer = &bytes[0xf00..];

        let (header_ext, _bytes) = LayoutVerified::<_, DmpHeader64Ext>::new_from_prefix(buffer).ok_or_else(|| ParserError::ParseError("can't read header".into()))?;

        let mut physmem = BTreeMap::new();
        if header_ext.dump_type == 1 {
            // full dump
            let buffer = run_base;
            let (physical_memory_block_buffer, _bytes) = LayoutVerified::<_, PhysicalMemoryBlockBuffer>::new_from_prefix(buffer).ok_or_else(|| ParserError::ParseError("can't read physical memory block buffer".into()))?;

            let mut base = 0x2000;
            let mut physpage: usize = 0;
            let runs = physical_memory_block_buffer.number_of_pages as usize;
            for i in 0..runs {
                let offset = 0x10usize * i;
                let buffer = &run_base[0x10 + offset..];
                let (run, _bytes) = LayoutVerified::<_, PhysicalMemoryRun>::new_from_prefix(buffer).ok_or_else(|| ParserError::ParseError("can't read physical memory block buffer".into()))?;
                for page_index in 0..run.page_count {
                    let pa = (run.base_page + page_index) * 0x1000;
                    let page_base = base + page_index * 0x1000;
                    let offset = page_base as usize;
                    physmem.insert(pa, &bytes[offset..offset+0x1000]);
                    physpage += 1;
                }

                base += run.page_count * 0x1000;
            }

            if physical_memory_block_buffer.number_of_runs as usize != physpage {
                return Err(ParserError::ParseError("invalid number of physical pages".into()))
            }
 
        } else if header_ext.dump_type == 5 {
            // bitmap dump

            let buffer = &bytes[0x2000..];
            let (bitmap, _bytes) = LayoutVerified::<_, DmpBitmap64>::new_from_prefix(buffer).ok_or_else(|| ParserError::ParseError("can't read bitmap".into()))?;

            if bitmap.signature != 0x504d_4453{
                return Err(ParserError::ParseError(format!("invalid signature, got {:x} instead of {:x}", bitmap.signature, 0x504d_4453)))
            }

            if bitmap.valid_dump != 0x504d_5544 {
                return Err(ParserError::ParseError(format!("invalid signature, got {:x} instead of {:x}", bitmap.valid_dump, 0x504d_5544)))
            }
    
            let mut physpage: usize = 0;
            let mut addr: u64 = 0;

            let bitmap_len: usize = ((bitmap.pages as usize - 1) / 64 + 1) * 8; 

            let start_offset: usize = 0x2038;
            let end_offset: usize = start_offset + bitmap_len;

            if end_offset != bitmap.first_page as usize {
                return Err(ParserError::ParseError("invalid bitmap".into()))
            }

            for b in &bytes[start_offset..end_offset] {
                for ii in 0..8 {
                    let bit = 1 << ii;
                    if bit & b == bit {
                        let offset = bitmap.first_page as usize + physpage * 0x1000;
                        physmem.insert(addr, &bytes[offset..offset+0x1000]);
                        physpage += 1;
                    }
                    addr += 0x1000;
                }
            }

            if bitmap.total_present_pages as usize != physmem.len() {
                return Err(ParserError::ParseError("invalid bitmap".into()))
            }
        }
        else {
            return Err(ParserError::ParseError(format!("invalid dump type, got {:x}", header_ext.dump_type)))
        }

        Ok(Self {
             header,
             context,
             header_ext,
             physmem,
         })
    }

    pub fn cr3(&self) -> u64 {
        self.header.directory_table_base
    }

}

#[derive(FromBytes, Debug)]
pub struct PhysicalMemoryRun {
    base_page: u64,
    page_count: u64,
}

#[derive(FromBytes, Debug)]
pub struct PhysicalMemoryBlockBuffer {
    pub number_of_runs: u32,
    pub _u: u32,
    pub number_of_pages: u64,
}

#[derive(FromBytes, Debug)]
#[repr(C)]
pub struct DmpHeader64 {
    pub signature: u32,
    pub valid_dump: u32,
    pub major_version: u32,
    pub minor_version: u32,
    pub directory_table_base: u64,
    pub pfn_data_base: u64,
    pub ps_loaded_module_list: u64,
    pub ps_active_process_head: u64,
    pub machine_image_type: u32,
    pub number_processors: u32,
    pub bug_check_code: u32,
    _u1: u32,

    pub bug_check_code_parameter: [u64; 4],

    _u2: [u8; 0x20],

    pub kd_debugger_data_block: u64,
}

#[derive(Debug, FromBytes)]
#[repr(C)]
pub struct DmpHeader64Ext {
    pub exception: ExceptionRecord64,
    pub dump_type: u32,
    _u1: u32,
    pub required_dump_space: u64,
    pub system_time: u64,
    pub comment: [u8; 128],
    pub system_up_time: u64,
    pub mini_dump_fields: u32,
    pub secondary_data_state: u32,
    pub product_type: u32,
    pub suite_mask: u32,
    pub writer_status: u32,
    _u2: u8,
    pub kd_secondary_version: u8,
}

#[derive(Debug, FromBytes)]
#[repr(C)]
pub struct Context {
    _u1: [u8; 0x30],
    flags: u32,
    mxcsr: u32,
    cs: u16,
    ds: u16,
    es: u16,
    fs: u16,
    gs: u16,
    ss: u16,
    rflags: u32,
    _u2: [u8; 0x30],
    rax: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    rsp: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    // fpcw: u16,
    // _u3: [u8; 0x80],
    // _u4: [u8; 0x28],
    // xmm0: u128,
    // xmm1: u128,
    // xmm2: u128,
    // xmm3: u128,
    // xmm4: u128,
    // xmm5: u128,
    // xmm6: u128,
    // xmm7: u128,
    // xmm8: u128,
    // xmm9: u128,
    // xmm10: u128,
    // xmm11: u128,
    // xmm12: u128,
    // xmm13: u128,
    // xmm14: u128,
    // xmm15: u128,
}

#[derive(Debug, FromBytes)]
#[repr(C)]
pub struct ExceptionRecord64 {
    exception_code: i32,
    exception_flags: u32,
    exception_record: u64,
    exception_address: u64,
    number_parameters: u32,
    _u1: u32,
    exception_information: [u64; 15],
}

#[derive(Debug, FromBytes)]
#[repr(C)]
pub struct DmpBitmap64 {
    pub signature: u32,
    pub valid_dump: u32,
    _u1: [u8; 24],
    pub first_page: u64,
    pub total_present_pages: u64,
    pub pages: u64,
}


#[cfg(test)]
mod tests {

    use super::*;
    use memmap::*;

    #[test]
    fn test_bitmap_dmp() {
        let path = "../tests/ConfigIoHandler_Safeguarded/mem.dmp";
        let fp = std::fs::File::open(path).unwrap();
    
        let bytes = unsafe { MmapOptions::new().map(&fp).unwrap() };
        let dump = RawDmp::parse(&bytes).unwrap();

        assert_eq!(dump.context.rip, 0xfffff8024b436c3c);
        assert_eq!(dump.context.rflags, 0x00040246);

        assert_eq!(dump.cr3(), 0xb43c7002);

        assert_eq!(dump.physmem.len(), 849814);

        let paddr = 0x4336000;
        let page = *dump.physmem.get(&paddr).unwrap();

        assert_eq!(page[0xc3c], 0x4c);
        assert_eq!(page[0xc3d], 0x8b);
        assert_eq!(page[0xc3e], 0xdc);
        assert_eq!(page[0xc3f], 0x49);

    }

    #[test]
    fn test_full_dmp() {
        let path = "../tests/_ConfigurationFunctionIoHandler/mem.dmp";
        let fp = std::fs::File::open(path).unwrap();
    
        let bytes = unsafe { MmapOptions::new().map(&fp).unwrap() };
        let dump = RawDmp::parse(&bytes).unwrap();

        assert_eq!(dump.context.rip, 0xfffff80719037f54);
        assert_eq!(dump.context.rflags, 0x00040246);

        assert_eq!(dump.cr3(), 0xa5a72002);

        assert_eq!(dump.physmem.len(), 0xffc94);

        let paddr = 0x4336000;
        let page = *dump.physmem.get(&paddr).unwrap();

        assert_eq!(page[0xc3c], 0x4c);
        assert_eq!(page[0xc3d], 0x8b);
        assert_eq!(page[0xc3e], 0xdc);
        assert_eq!(page[0xc3f], 0x49);

    }


}
use std::{
    io::{BufWriter, Write},
    path::PathBuf, fmt::Display, collections::HashMap,
};

use argh::FromArgs;
use bit_field::BitField;
use serde::{Deserialize, Serialize};
use windows::{
    core::{Error, IUnknown, Interface, HRESULT},
    Win32::{
        Foundation::PSTR,
        System::Diagnostics::Debug::{
            IDebugControl, IDebugDataSpaces4, IDebugRegisters, DEBUG_EXECUTE_DEFAULT,
            DEBUG_OUTCTL_ALL_CLIENTS, DEBUG_OUTPUT_ERROR, DEBUG_OUTPUT_NORMAL, IDebugSymbols,
        },
    },
};

const S_OK: HRESULT = HRESULT(0);

#[no_mangle]
pub extern "C" fn DebugExtensionInitialize(_version: *mut u32, _flags: *mut u32) -> HRESULT {
    S_OK
}

#[no_mangle]
pub extern "C" fn DebugExtensionCanUnload() -> HRESULT {
    S_OK
}

#[no_mangle]
pub extern "C" fn DebugExtensionUnInitialize() {}

#[no_mangle]
pub extern "C" fn DebugExtensionUnload() {}

#[no_mangle]
pub extern "C" fn snapshot(client: IUnknown, args: PSTR) -> HRESULT {
    let client = ClientWrapper::new(client);
    let mut end = args.0;

    unsafe {
        while *end != 0 {
            end = end.add(1);
        }
    }
    let result = unsafe {
        String::from_utf8_lossy(std::slice::from_raw_parts(
            args.0,
            end.offset_from(args.0) as _,
        ))
        .to_string()
    };

    let args = shlex::split(&result).unwrap_or_default();
    let args: Vec<&str> = args.iter().map(|l| l.as_str()).collect();
    match Args::from_args(&["!snapshot"], &args[..]) {
        Ok(args) => {
            if let Err(e) = create_snapshot(&client, args) {
                let msg = format!("can't create snapshot: {:?}\n", e);
                client.warn(&msg).unwrap_or_default();
            }
        }
        Err(e) => {
            client.log(&e.output).unwrap_or_default();
        }
    }

    S_OK
}

/// Create snapshots.
#[derive(argh::FromArgs)]
struct Args {
    /// take a complete memory dump instead of active memory dump (https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/active-memory-dump)
    #[argh(switch)]
    full: bool,

    /// overwrite snapshot if existing
    #[argh(switch)]
    overwrite: bool,

    /// path
    #[argh(positional)]
    path: PathBuf,
}

#[allow(clippy::field_reassign_with_default)]
fn create_snapshot(client: &ClientWrapper, args: Args) -> Result<(), Error> {
    let rip = client.get_reg_64("rip")?;
    let name = client.get_name(rip)?;
    if name.displacement != 0 {
        client
            .warn("aborting, not on a function boundary\n")
            .unwrap_or_default();
        return Ok(());
    }

    let build_address = client.get_symbol_address("nt!NtBuildLabEx")?;
    let build_number = client.read_cstring(build_address)?;

    let path = args.path.join(build_number).join(name.name);

    if path.exists() && !args.overwrite {
        client
            .warn(&format!("aborting, {} exists, use --overwrite if it's what you want\n", path.display()))
            .unwrap_or_default();
        return Ok(());
    }

    if let Err(e) = std::fs::create_dir_all(&path) {
        client
            .warn(&format!("can't create snapshot directory: {}\n", e))
            .unwrap_or_default();
        return Ok(());
    }

    let mut processor_state = ProcessorState::default();

    processor_state.gdtr = client.get_reg_64("gdtr")?;
    processor_state.gdtl = client.get_reg_16("gdtl")?;
    processor_state.idtr = client.get_reg_64("idtr")?;
    processor_state.idtl = client.get_reg_16("idtl")?;
    processor_state.cr0 = client.get_reg_64("cr0")?;
    processor_state.cr3 = client.get_reg_64("cr3")?;
    processor_state.cr4 = client.get_reg_64("cr4")?;
    processor_state.cr8 = client.get_reg_64("cr8")?;
    processor_state.efer = client.read_msr(ProcessorState::IA32_EFER)?;
    processor_state.fs_base = client.read_msr(ProcessorState::FS_BASE)?;
    processor_state.gs_base = client.read_msr(ProcessorState::GS_BASE)?;
    processor_state.kernel_gs_base = client.read_msr(ProcessorState::KERNEL_GS_BASE)?;
    processor_state.sysenter_cs = client.read_msr(ProcessorState::IA32_SYSENTER_CS)?;
    processor_state.sysenter_esp = client.read_msr(ProcessorState::IA32_SYSENTER_ESP)?;
    processor_state.sysenter_eip = client.read_msr(ProcessorState::IA32_SYSENTER_EIP)?;
    processor_state.star = client.read_msr(ProcessorState::STAR)?;
    processor_state.lstar = client.read_msr(ProcessorState::LSTAR)?;
    processor_state.cstar = client.read_msr(ProcessorState::CSTAR)?;
    processor_state.apic_base = client.read_msr(ProcessorState::APIC_BASE)?;
    processor_state.rax = client.get_reg_64("rax")?;
    processor_state.rbx = client.get_reg_64("rbx")?;
    processor_state.rcx = client.get_reg_64("rcx")?;
    processor_state.rdx = client.get_reg_64("rdx")?;
    processor_state.rsi = client.get_reg_64("rsi")?;
    processor_state.rdi = client.get_reg_64("rdi")?;
    processor_state.r8 = client.get_reg_64("r8")?;
    processor_state.r9 = client.get_reg_64("r9")?;
    processor_state.r10 = client.get_reg_64("r10")?;
    processor_state.r11 = client.get_reg_64("r11")?;
    processor_state.r12 = client.get_reg_64("r12")?;
    processor_state.r13 = client.get_reg_64("r13")?;
    processor_state.r14 = client.get_reg_64("r14")?;
    processor_state.r15 = client.get_reg_64("r15")?;
    processor_state.rbp = client.get_reg_64("rbp")?;
    processor_state.rsp = client.get_reg_64("rsp")?;
    processor_state.rip = client.get_reg_64("rip")?;
    processor_state.rflags = client.get_reg_64("efl")?;

    let selector = client.get_reg_16("cs")?;
    let offset = ((selector >> 2) << 2) as u64;
    let address = processor_state.gdtr + offset;
    let entry = client.read_virtual_memory_u64(address)?;
    let entry = GdtEntry(entry);

    processor_state.cs.selector = selector;
    processor_state.cs.base = entry.base();
    processor_state.cs.limit = entry.limit();
    processor_state.cs.flags = entry.flags();

    let selector = client.get_reg_16("ds")?;
    let offset = ((selector >> 2) << 2) as u64;
    let address = processor_state.gdtr + offset;
    let entry = client.read_virtual_memory_u64(address)?;
    let entry = GdtEntry(entry);

    processor_state.ds.selector = selector;
    processor_state.ds.base = entry.base();
    processor_state.ds.limit = entry.limit();
    processor_state.ds.flags = entry.flags();

    let selector = client.get_reg_16("es")?;
    let offset = ((selector >> 2) << 2) as u64;
    let address = processor_state.gdtr + offset;
    let entry = client.read_virtual_memory_u64(address)?;
    let entry = GdtEntry(entry);

    processor_state.es.selector = selector;
    processor_state.es.base = entry.base();
    processor_state.es.limit = entry.limit();
    processor_state.es.flags = entry.flags();

    let selector = client.get_reg_16("fs")?;
    let offset = ((selector >> 2) << 2) as u64;
    let address = processor_state.gdtr + offset;
    let entry = client.read_virtual_memory_u64(address)?;
    let entry = GdtEntry(entry);

    processor_state.fs.selector = selector;
    processor_state.fs.base = entry.base();
    processor_state.fs.limit = entry.limit();
    processor_state.fs.flags = entry.flags();

    let selector = client.get_reg_16("gs")?;
    let offset = ((selector >> 2) << 2) as u64;
    let address = processor_state.gdtr + offset;
    let entry = client.read_virtual_memory_u64(address)?;
    let entry = GdtEntry(entry);

    processor_state.gs.selector = selector;
    processor_state.gs.base = entry.base();
    processor_state.gs.limit = entry.limit();
    processor_state.gs.flags = entry.flags();

    let selector = client.get_reg_16("ss")?;
    let offset = ((selector >> 2) << 2) as u64;
    let address = processor_state.gdtr + offset;
    let entry = client.read_virtual_memory_u64(address)?;
    let entry = GdtEntry(entry);

    processor_state.ss.selector = selector;
    processor_state.ss.base = entry.base();
    processor_state.ss.limit = entry.limit();
    processor_state.ss.flags = entry.flags();

    let processor_state_path = path.join("context.json");

    client.log(&format!("Writing processor state to {}\n", processor_state_path.display())).unwrap_or_default();

    if let Err(_e) = processor_state.save(&processor_state_path) {
        client.warn(&format!("error: can't save processor state, {}", _e)).unwrap_or_default();
        return Ok(())
    }

    let mut excluded_addresses = HashMap::new();
    for name in ["nt!KeBugCheck", "nt!KeBugCheck2", "nt!KeBugCheckEx"] {
        excluded_addresses.insert(name.into(), client.get_symbol_address(name)?);
    }

    let params = Params {
        return_address: client.read_virtual_memory_u64(processor_state.rsp)?,
        excluded_addresses,
    };

    let params_path = path.join("params.json");

    client.log(&format!("Writing parameters to {}\n", params_path.display())).unwrap_or_default();

    if let Err(_e) = params.save(&params_path) {
        client.warn(&format!("error: can't save parameters, {}", _e)).unwrap_or_default();
        return Ok(())
    }

    let dump_path = path.join("mem.dmp");

    client.log(&format!("Writing snapshot to {}\n", dump_path.display())).unwrap_or_default();

    let cmd = if args.full {
        format!(".dump /f /o {}", dump_path.display())
    } else {
        format!(".dump /ka /o {}", dump_path.display())
    };

    client.exec(&cmd).unwrap_or_default();

    Ok(())
}

/// Processor segment
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Segment {
    /// Selector
    pub selector: u16,
    /// Base
    pub base: u64,
    /// Limit
    pub limit: u32,
    /// Flags
    pub flags: u16,
}

/// Processor state
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ProcessorState {
    /// rax
    pub rax: u64,
    /// rbx
    pub rbx: u64,
    /// rcx
    pub rcx: u64,
    /// rdx
    pub rdx: u64,
    /// rsi
    pub rsi: u64,
    /// rdi
    pub rdi: u64,
    /// rsp
    pub rsp: u64,
    /// rbp
    pub rbp: u64,
    /// r8
    pub r8: u64,
    /// r9
    pub r9: u64,
    /// r10
    pub r10: u64,
    /// r11
    pub r11: u64,
    /// r12
    pub r12: u64,
    /// r13
    pub r13: u64,
    /// r14
    pub r14: u64,
    /// r15
    pub r15: u64,
    /// rflags
    pub rflags: u64,
    /// rip
    pub rip: u64,
    /// cr0
    pub cr0: u64,
    /// cr3
    pub cr3: u64,
    /// cr4
    pub cr4: u64,
    /// cr8
    pub cr8: u64,
    /// EFER MSR
    pub efer: u64,
    /// gdtr
    pub gdtr: u64,
    /// gdtl
    pub gdtl: u16,
    /// idtr
    pub idtr: u64,
    /// idtl
    pub idtl: u16,
    /// cs
    pub cs: Segment,
    /// ss
    pub ss: Segment,
    /// ds
    pub ds: Segment,
    /// es
    pub es: Segment,
    /// fs
    pub fs: Segment,
    /// gs
    pub gs: Segment,
    /// FS_BASE MSR
    pub fs_base: u64,
    /// GS_BASE MSR
    pub gs_base: u64,
    /// KERNEL_GS_BASE MSR
    pub kernel_gs_base: u64,
    /// SYSENTER_CS MSR
    pub sysenter_cs: u64,
    /// SYSENTER_ESP MSR
    pub sysenter_esp: u64,
    /// SYSENTER_EIP MSR
    pub sysenter_eip: u64,
    /// STAR MSR
    pub star: u64,
    /// LSTAR MSR
    pub lstar: u64,
    /// CSTAR MSR
    pub cstar: u64,
    /// APIC_BASE MSR
    pub apic_base: u64,
}

impl ProcessorState {
    // const TSC: u32 = 0x10;
    const APIC_BASE: u32 = 0x1b;
    const IA32_SYSENTER_CS: u32 = 0x174;
    const IA32_SYSENTER_ESP: u32 = 0x175;
    const IA32_SYSENTER_EIP: u32 = 0x176;
    // const PAT: u32 = 0x277;
    const IA32_EFER: u32 = 0xC0000080;
    const STAR: u32 = 0xC0000081;
    const LSTAR: u32 = 0xC0000082;
    const CSTAR: u32 = 0xC0000083;
    // const SFMASK: u32 = 0xC0000084;
    const FS_BASE: u32 = 0xC0000100;
    const GS_BASE: u32 = 0xC0000101;
    const KERNEL_GS_BASE: u32 = 0xC0000102;
    // const TSC_AUX: u32 = 0xC0000103;

    /// Serialize to json and save to disk
    fn save<P>(&self, path: P) -> Result<(), Box<dyn std::error::Error>>
    where
        P: AsRef<std::path::Path>,
    {
        let mut fp = BufWriter::new(std::fs::File::create(&path)?);
        let data = serde_json::to_vec_pretty(&self)?;
        fp.write_all(&data)?;
        Ok(())
    }

    /// Read from disk and deserialize
    fn _load<P>(path: P) -> Result<Self, Box<dyn std::error::Error>>
    where
        P: AsRef<std::path::Path>,
    {
        let input_str = std::fs::read_to_string(&path)?;
        let input = serde_json::from_str(&input_str)?;
        Ok(input)
    }
}

/// Tracing parameters
#[derive(Default, Serialize, Deserialize, Debug)]
struct Params {
    /// Expected return address (used to stop tracing)
    return_address: u64,
    /// Excluded addresses (used to stop tracing)
    excluded_addresses: HashMap<String, u64>,
}

impl Params {
    /// Serialize to json and save to disk
    fn save<P>(&self, path: P) -> Result<(), Box<dyn std::error::Error>>
    where P: AsRef<std::path::Path>
    {
        let mut fp = BufWriter::new(std::fs::File::create(&path)?);
        let data = serde_json::to_vec_pretty(&self)?;
        fp.write_all(&data)?;
        Ok(())
    }

    /// Read from disk and deserialize
    fn _load<P>(path: P) -> Result<Self, Box<dyn std::error::Error>>
    where P: AsRef<std::path::Path>
    {
        let input_str = std::fs::read_to_string(&path)?;
        let input = serde_json::from_str(&input_str)?;
        Ok(input)
    }

}

struct ClientWrapper {
    client: IUnknown,
}

impl ClientWrapper {
    fn new(client: IUnknown) -> Self {
        Self { client }
    }

    fn log(&self, msg: &str) -> Result<(), Error> {
        unsafe {
            let control = self.client.cast::<IDebugControl>()?;
            control.ControlledOutput(DEBUG_OUTCTL_ALL_CLIENTS, DEBUG_OUTPUT_NORMAL, msg)?;
        }
        Ok(())
    }

    fn warn(&self, msg: &str) -> Result<(), Error> {
        unsafe {
            let control = self.client.cast::<IDebugControl>()?;
            control.ControlledOutput(DEBUG_OUTCTL_ALL_CLIENTS, DEBUG_OUTPUT_ERROR, msg)?;
        }
        Ok(())
    }

    fn exec(&self, cmd: &str) -> Result<(), Error> {
        unsafe {
            let control = self.client.cast::<IDebugControl>()?;
            control.Execute(DEBUG_OUTCTL_ALL_CLIENTS, cmd, DEBUG_EXECUTE_DEFAULT)?;
        }
        Ok(())
    }

    fn get_reg_64(&self, regname: &str) -> Result<u64, Error> {
        unsafe {
            let regs = self.client.cast::<IDebugRegisters>()?;
            let register = regs.GetIndexByName(regname)?;
            let value = regs.GetValue(register)?.Anonymous.Anonymous.I64;
            Ok(value)
        }
    }

    fn get_reg_16(&self, regname: &str) -> Result<u16, Error> {
        unsafe {
            let regs = self.client.cast::<IDebugRegisters>()?;
            let register = regs.GetIndexByName(regname)?;
            let value = regs.GetValue(register)?.Anonymous.I16;
            Ok(value)
        }
    }

    fn read_msr(&self, msr: u32) -> Result<u64, Error> {
        unsafe {
            let iface = self.client.cast::<IDebugDataSpaces4>()?;
            let value = iface.ReadMsr(msr)?;
            Ok(value)
        }
    }

    fn get_symbol_address(&self, name: &str) -> Result<u64, Error> {
        unsafe {
            let symbols = self.client.cast::<IDebugSymbols>()?;
            symbols.GetOffsetByName(name)
        }
    }

    fn get_name(&self, address: u64) -> Result<Symbol, Error> {
        unsafe {
            let symbols = self.client.cast::<IDebugSymbols>()?;
            let mut data = vec![0u8; 0x100];
            let name = PSTR(data.as_mut_ptr());
            let mut size = 0u32;
            let mut displacement = 0u64;
            symbols.GetNameByOffset(address, name, data.len() as u32, &mut size as *mut u32, &mut displacement as *mut u64)?;
            data.resize((size - 1) as usize, 0);
            let name = String::from_utf8(data).unwrap_or_default();
            Ok(Symbol {
                name,
                address,
                displacement,
            })
        }
    }

    fn read_virtual_memory(&self, address: u64, data: &mut [u8]) -> Result<(), Error> {
        unsafe {
            let iface = self.client.cast::<IDebugDataSpaces4>()?;
            let mut bytesread = 0u32;
            iface.ReadVirtual(address, data.as_mut_ptr() as *mut _, data.len() as u32, &mut bytesread as *mut u32)
        }
    }

    fn read_virtual_memory_u64(&self, address: u64) -> Result<u64, Error> {
        let mut buffer = [0u8; 8];
        self.read_virtual_memory(address, &mut buffer)?;
        Ok(u64::from_le_bytes(buffer))
    }

    fn read_cstring(&self, address: u64) -> Result<String, Error> {
        unsafe {
            let iface = self.client.cast::<IDebugDataSpaces4>()?;
            let mut data = vec![0u8; 0x100];
            let mut bytesread = 0u32;
            let cstring = PSTR(data.as_mut_ptr());
            iface.ReadMultiByteStringVirtual(address, data.len() as u32, cstring, data.len() as u32, &mut bytesread as *mut _)?;
            data.resize((bytesread - 1) as usize, 0);
            let cstring = String::from_utf8(data).unwrap_or_default();
            Ok(cstring)
        }
    }
}

#[derive(Debug)]
struct Symbol {
    name: String,
    address: u64,
    displacement: u64,
}

struct GdtEntry(u64);

impl GdtEntry {

    fn base(&self) -> u64 {
        (self.0.get_bits(16..=31) | self.0.get_bits(32..=39) << 16) | self.0.get_bits(56..=63) << 24
    }

    fn limit(&self) -> u32 {
        (self.0.get_bits(0..=15) | self.0.get_bits(48..=51) << 16) as u32
    }

    fn flags(&self) -> u16 {
        (self.0.get_bits(40..=47) | self.0.get_bits(52..=55) << 12) as u16
    }

    fn long(&self) -> u8 {
        self.0.get_bit(53) as u8
    }

    // fn size(&self) -> u8 {
    //     self.0.get_bit(54) as u8
    // }

    // fn granularity(&self) -> u8 {
    //     self.0.get_bit(55) as u8
    // }

    fn present(&self) -> bool {
        self.0.get_bit(47)
    }

    fn privilege_level(&self) -> u16 {
        self.0.get_bits(45..=46) as u16
    }

    // fn type_(&self) -> u8 {
    //     self.0.get_bit(44) as u8
    // }

    // fn executable(&self) -> u8 {
    //     self.0.get_bit(43) as u8
    // }

    // fn dc(&self) -> u8 {
    //     self.0.get_bit(42) as u8
    // }

    // fn rw(&self) -> u8 {
    //     self.0.get_bit(41) as u8
    // }
}

impl Display for GdtEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{:x}: base {:x} limit {:x} flags {:x}
long {} present {} level {}",
        self.0, self.base(), self.limit(), self.flags(),
        self.long(), self.present(), self.privilege_level())
    }
}


#[test]
fn test_segment() {

    let segment = GdtEntry(0x00209b0000000000);
    println!("{}", segment);
    assert_eq!(segment.base(), 0);
    assert_eq!(segment.limit(), 0);
    assert_eq!(segment.flags(), 0x209b);
    assert!(segment.present());
    assert_eq!(segment.privilege_level(), 0);

    let segment = GdtEntry(0x00cff3000000ffff);
    println!("{}", segment);
    assert_eq!(segment.base(), 0);
    assert_eq!(segment.limit(), 0xfffff);
    assert_eq!(segment.flags(), 0xc0f3);
    assert!(segment.present());
    assert_eq!(segment.privilege_level(), 3);

    let segment = GdtEntry(0x0040f30000003c00);
    println!("{}", segment);
    assert_eq!(segment.base(), 0);
    assert_eq!(segment.limit(), 0x3c00);
    assert_eq!(segment.flags(), 0x40f3);
    assert!(segment.present());
    assert_eq!(segment.privilege_level(), 3);

}







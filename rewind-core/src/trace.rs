
use std::str::FromStr;
use std::collections::BTreeSet;
use std::collections::HashMap;

use std::io::{BufWriter, Write};

use std::time::{Instant, Duration};

use thiserror::Error;

use serde::{Serialize, Deserialize};

use crate::{error, mem};

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Segment {
    pub selector: u16,
    pub base: u64,
    pub limit: u32,
    pub flags: u16
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ProcessorState {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rflags: u64,
    pub rip: u64,
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub gdtr: u64,
    pub gdtl: u16,
    pub idtr: u64,
    pub idtl: u16,
    pub cs: Segment,
    pub ss: Segment,
    pub ds: Segment,
    pub es: Segment,
    pub fs: Segment,
    pub gs: Segment,
    pub fs_base: u64,
    pub gs_base: u64,
    pub kernel_gs_base: u64,
    pub sysenter_cs: u64,
    pub sysenter_esp: u64,
    pub sysenter_eip: u64,
    pub star: u64,
    pub lstar: u64,
    pub cstar: u64,
    pub apic_base: u64
}

impl ProcessorState {

    pub fn save<P>(&self, path: P) -> Result<(), error::GenericError>
    where P: AsRef<std::path::Path>
    {
        let mut fp = BufWriter::new(std::fs::File::create(&path)?);
        let data = serde_json::to_vec_pretty(&self)?;
        fp.write_all(&data)?;
        Ok(())
    }

    pub fn load<P>(path: P) -> Result<Self, error::GenericError>
    where P: AsRef<std::path::Path>
    {
        let input_str = std::fs::read_to_string(&path)?;
        let input = serde_json::from_str(&input_str)?;
        Ok(input)
    }

}

impl FromStr for ProcessorState {
    type Err = error::GenericError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let context = serde_json::from_str(s)?;
        Ok(context)
    }
}

impl std::fmt::Display for ProcessorState {

    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "rax={:016x} rbx={:016x} rcx={:016x}
rdx={:016x} rsi={:016x} rdi={:016x}
rip={:016x} rsp={:016x} rbp={:016x}
 r8={:016x}  r9={:016x} r10={:016x}
r11={:016x} r12={:016x} r13={:016x}
r14={:016x} r15={:016x}
cs={:04x}  ss={:04x}  ds={:04x}  es={:04x}  fs={:04x}  gs={:04x}  rflags={:04x}",
        self.rax, self.rbx, self.rcx,
        self.rdx, self.rsi, self.rdi,
        self.rip, self.rsp, self.rbp,
        self.r8, self.r9, self.r10,
        self.r11, self.r12, self.r13,
        self.r14, self.r15,
        self.cs.selector, self.ss.selector, self.ds.selector,
        self.es.selector, self.fs.selector, self.gs.selector,
        self.rflags)
    }
}

#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub enum CoverageMode {
    None,
    Instrs,
    Hit,
}

impl Default for CoverageMode {
    fn default() -> Self {
        CoverageMode::None
    }
}

impl FromStr for CoverageMode {
    type Err = error::GenericError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let coverage_mode = match s {
            "no" => CoverageMode::None,
            "instrs" => CoverageMode::Instrs,
            "hit" => CoverageMode::Hit,
            _ => {
                return Err(error::GenericError::Generic("invalid coverage mode".to_string()))
            }
        };
        Ok(coverage_mode)
    }
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Params {
    #[serde(skip)]
    pub limit: u64,
    #[serde(skip)]
    pub max_duration: Duration,
    pub return_address: u64,
    pub excluded_addresses: HashMap<String, u64>,
    #[serde(skip)]
    pub save_context: bool,
    #[serde(skip)]
    pub coverage_mode: CoverageMode,
    #[serde(skip)]
    pub save_instructions: bool,
}

impl Params {
    pub fn save<P>(&self, path: P) -> Result<(), error::GenericError>
    where P: AsRef<std::path::Path>
    {
        let mut fp = BufWriter::new(std::fs::File::create(&path)?);
        let data = serde_json::to_vec_pretty(&self)?;
        fp.write_all(&data)?;
        Ok(())
    }

    pub fn load<P>(path: P) -> Result<Self, error::GenericError>
    where P: AsRef<std::path::Path>
    {
        let input_str = std::fs::read_to_string(&path)?;
        let input = serde_json::from_str(&input_str)?;
        Ok(input)
    }

}

impl FromStr for Params {
    type Err = error::GenericError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let params = serde_json::from_str(s)?;
        Ok(params)
    }
}

#[derive(Debug, PartialEq, PartialOrd, Serialize, Deserialize, Clone)]
pub enum EmulationStatus {
    Success,
    Error(String),
    ForbiddenAddress(String),
    Timeout,
    LimitExceeded,
    UnHandledException,
    Breakpoint,
    SingleStep,
}

impl std::fmt::Display for EmulationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            EmulationStatus::Success => write!(f, "Success"),
            EmulationStatus::Error(e) => write!(f, "Error: {}", e),
            EmulationStatus::ForbiddenAddress(e) => write!(f, "ForbiddenAddress: {}", e),
            EmulationStatus::Timeout => write!(f, "Timeout"),
            EmulationStatus::LimitExceeded => write!(f, "LimitExceeded"),
            EmulationStatus::UnHandledException => write!(f, "UnhandledException"),
            EmulationStatus::Breakpoint => write!(f, "Breakpoint"),
            EmulationStatus::SingleStep => write!(f, "SingleStep"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct Context {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rflags: u64,
    pub rip: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Trace {
    #[serde(skip)]
    pub start: Option<Instant>,
    #[serde(skip)]
    pub end: Option<Instant>,
    pub coverage: Vec<(u64, Option<Context>)>,
    pub immediates: BTreeSet<u64>,
    pub status: EmulationStatus,
    pub seen: BTreeSet<u64>,
    pub mem_access: Vec<(u64, u64, u64, usize, String)>,
    pub code: usize,
    pub data: usize,
}

impl Trace {

    pub fn new() -> Self {
        Trace {
            start: None,
            end: None,
            coverage: Vec::new(),
            immediates: BTreeSet::new(),
            seen: BTreeSet::new(),
            status: EmulationStatus::Success,
            mem_access: Vec::new(),
            code: 0,
            data: 0,
        }
    }

    pub fn save<P>(&self, path: P) -> Result<(), error::GenericError>
    where P: AsRef<std::path::Path>
    {
        let mut fp = BufWriter::new(std::fs::File::create(&path)?);
        let data = serde_json::to_vec_pretty(&self)?;
        fp.write_all(&data)?;
        Ok(())
    }

    pub fn load<P>(path: P) -> Result<Self, error::GenericError>
    where P: AsRef<std::path::Path>
    {
        let input_str = std::fs::read_to_string(&path)?;
        let input = serde_json::from_str(&input_str)?;
        Ok(input)
    }

}

impl Default for Trace {

    fn default() -> Self {
        Self::new()
    }
}

impl FromStr for Trace {
    type Err = error::GenericError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let result = serde_json::from_str(s)?;
        Ok(result)
    }
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Input {
    pub address: u64,
    pub size: u64,
}

impl Input {

    pub fn save<P>(&self, path: P) -> Result<(), error::GenericError>
    where P: AsRef<std::path::Path>
    {
        let mut fp = BufWriter::new(std::fs::File::create(&path)?);
        let data = serde_json::to_vec_pretty(&self)?;
        fp.write_all(&data)?;
        Ok(())
    }

    pub fn load<P>(path: P) -> Result<Self, error::GenericError>
    where P: AsRef<std::path::Path>
    {
        let input_str = std::fs::read_to_string(&path)?;
        let input = serde_json::from_str(&input_str)?;
        Ok(input)
    }

}

impl FromStr for Input {
    type Err = error::GenericError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let input = serde_json::from_str(s)?;
        Ok(input)
    }
}

#[derive(Debug, Error)]
pub enum TracerError {
    #[error(transparent)]
    FileError(#[from]std::io::Error),

    #[error(transparent)]
    SerdeError(#[from]serde_json::Error),

    #[error(transparent)]
    GenericError(#[from]error::GenericError),

    #[error(transparent)]
    VirtMemError(#[from]crate::mem::VirtMemError),

    #[error("unknown error: {}", .0)]
    UnknownError(String),

    #[error("first exec failed: {}", .0)]
    FirstExecFailed(String),

    #[error("bad input size: {}", .0)]
    BadInputSize(usize),

}

// FIXME: no need to have read_gva and write_gva in tracer
pub trait Tracer {

    fn get_state(&mut self) -> Result<ProcessorState, TracerError>;

    fn set_state(&mut self, state: &ProcessorState) -> Result<(), TracerError>;

    fn run<'a, H: Hook>(&'a mut self, params: &'a Params, hook: &'a mut H) -> Result<Trace, TracerError>;

    fn restore_snapshot(&mut self) -> Result<usize, TracerError>;

    fn read_gva(&mut self, cr3: u64, vaddr: u64, data: &mut [u8]) -> Result<(), TracerError>;

    fn write_gva(&mut self, cr3: u64, vaddr: u64, data: &[u8]) -> Result<(), TracerError>;

    fn cr3(&mut self) -> Result<u64, TracerError>;

    fn singlestep<H: Hook>(&mut self, params: &Params, hook: &mut H) -> Result<Trace, TracerError>;

    fn add_breakpoint(&mut self, address: u64);

    fn get_mapped_pages(&self) -> Result<usize, TracerError>;

}


pub trait Hook: Default {
    fn setup<T: Tracer + mem::X64VirtualAddressSpace>(&mut self, tracer: &mut T);

    fn handle_breakpoint<T: Tracer + mem::X64VirtualAddressSpace>(&mut self, tracer: &mut T) -> Result<bool, TracerError>;

    fn handle_trace(&self, trace: &mut Trace) -> Result<bool, TracerError>;

    fn patch_page(&self, gva: u64) -> bool;
}

#[derive(Default)]
pub struct NoHook {

}

impl Hook for NoHook {
    fn setup<T: Tracer + mem::X64VirtualAddressSpace>(&mut self, _tracer: &mut T) {
        
    }

    fn handle_breakpoint<T: Tracer + mem::X64VirtualAddressSpace>(&mut self, _tracer: &mut T) -> Result<bool, TracerError> {
        Ok(true)
    }

    fn handle_trace(&self, _trace: &mut Trace) -> Result<bool, TracerError> {
        Ok(true)
    }

    fn patch_page(&self, _gva: u64) -> bool {
        true
    }
}

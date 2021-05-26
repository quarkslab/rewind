
//! Tracing

use std::str::FromStr;
use std::collections::BTreeSet;
use std::collections::HashMap;

use std::io::{BufWriter, Write};

use std::time::{Instant, Duration};

use thiserror::Error;

use serde::{Serialize, Deserialize};

use crate::{error, mem};

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
    pub flags: u16
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
    pub apic_base: u64
}

impl ProcessorState {

    /// Serialize to json and save to disk
    pub fn save<P>(&self, path: P) -> Result<(), error::GenericError>
    where P: AsRef<std::path::Path>
    {
        let mut fp = BufWriter::new(std::fs::File::create(&path)?);
        let data = serde_json::to_vec_pretty(&self)?;
        fp.write_all(&data)?;
        Ok(())
    }

    /// Read from disk and deserialize
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

/// Coverage mode
#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub enum CoverageMode {
    /// No coverage
    None,
    /// Coverage on every instructions executed
    Instrs,
    /// Coverage on newly discovered instructions
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

/// Tracing parameters
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Params {
    /// VM-Exits limit
    #[serde(skip)]
    pub limit: u64,
    /// Duration limit
    #[serde(skip)]
    pub max_duration: Duration,
    /// Expected return address (used to stop tracing)
    pub return_address: u64,
    /// Excluded addresses (used to stop tracing)
    pub excluded_addresses: HashMap<String, u64>,
    /// If true, save context
    #[serde(skip)]
    pub save_context: bool,
    /// Coverage mode
    #[serde(skip)]
    pub coverage_mode: CoverageMode,
    // #[serde(skip)]
    // pub save_instructions: bool,
}

impl Params {
    /// Serialize to json and save to disk
    pub fn save<P>(&self, path: P) -> Result<(), error::GenericError>
    where P: AsRef<std::path::Path>
    {
        let mut fp = BufWriter::new(std::fs::File::create(&path)?);
        let data = serde_json::to_vec_pretty(&self)?;
        fp.write_all(&data)?;
        Ok(())
    }

    /// Read from disk and deserialize
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

/// Tracing result
#[derive(Debug, PartialEq, PartialOrd, Serialize, Deserialize, Clone)]
pub enum EmulationStatus {
    /// Expected return address was executed
    Success,
    /// Unexpected error during tracing
    Error(String),
    /// Excluded address was executed
    ForbiddenAddress(String),
    /// Max execution time exceeded
    Timeout,
    /// Max VM-Exits exceeded
    LimitExceeded,
    /// Unhandled exception
    UnHandledException,
    /// Breakpoint
    Breakpoint,
    /// Singlestep
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

/// Basic processor context
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct Context {
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
}

impl std::fmt::Display for Context {

    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "rax={:016x} rbx={:016x} rcx={:016x}
rdx={:016x} rsi={:016x} rdi={:016x}
rip={:016x} rsp={:016x} rbp={:016x}
 r8={:016x}  r9={:016x} r10={:016x}
r11={:016x} r12={:016x} r13={:016x}
r14={:016x} r15={:016x}
rflags={:04x}",
        self.rax, self.rbx, self.rcx,
        self.rdx, self.rsi, self.rdi,
        self.rip, self.rsp, self.rbp,
        self.r8, self.r9, self.r10,
        self.r11, self.r12, self.r13,
        self.r14, self.r15,
        self.rflags)
    }
}

/// Trace obtained after executing target function
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Trace {
    /// Beginning of trace
    #[serde(skip)]
    pub start: Option<Instant>,
    /// End of trace
    #[serde(skip)]
    pub end: Option<Instant>,
    /// Addresses discovered
    pub coverage: Vec<(u64, Option<Context>)>,
    /// Immediates discovered
    pub immediates: BTreeSet<u64>,
    /// Result of emulation
    pub status: EmulationStatus,
    /// Unique addresses discovered
    pub seen: BTreeSet<u64>,
    /// Memory accesses
    pub mem_accesses: Vec<MemAccess>,
}

impl Trace {

    /// Constructor
    pub fn new() -> Self {
        Trace {
            start: None,
            end: None,
            coverage: Vec::new(),
            immediates: BTreeSet::new(),
            seen: BTreeSet::new(),
            status: EmulationStatus::Success,
            mem_accesses: Vec::new(),
        }
    }

    /// Serialize to json and save to disk
    pub fn save<P>(&self, path: P) -> Result<(), error::GenericError>
    where P: AsRef<std::path::Path>
    {
        let mut fp = BufWriter::new(std::fs::File::create(&path)?);
        let data = serde_json::to_vec_pretty(&self)?;
        fp.write_all(&data)?;
        Ok(())
    }

    /// Read from disk and deserialize
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

/// User-controlled input
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Input {
    /// Address
    pub address: u64,
    /// Size
    pub size: u64,
}

impl Input {

    /// Serialize to json and save to disk
    pub fn save<P>(&self, path: P) -> Result<(), error::GenericError>
    where P: AsRef<std::path::Path>
    {
        let mut fp = BufWriter::new(std::fs::File::create(&path)?);
        let data = serde_json::to_vec_pretty(&self)?;
        fp.write_all(&data)?;
        Ok(())
    }

    /// Read from disk and deserialize
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

/// Tracing error
#[derive(Debug, Error)]
pub enum TracerError {
    /// IO error
    #[error(transparent)]
    FileError(#[from]std::io::Error),

    /// Serde error
    #[error(transparent)]
    SerdeError(#[from]serde_json::Error),

    /// Unspecified error
    #[error(transparent)]
    GenericError(#[from]error::GenericError),

    /// Memory error
    #[error(transparent)]
    VirtMemError(#[from]crate::mem::VirtMemError),

    /// Unknown error
    #[error("unknown error: {}", .0)]
    UnknownError(String),

    /// Dry-run failed
    #[error("first exec failed: {}", .0)]
    FirstExecFailed(String),

    /// Bad input size
    #[error("bad input size: {}", .0)]
    BadInputSize(usize),

}

/// Tracer interface
// FIXME: no need to have read_gva and write_gva in tracer
pub trait Tracer {

    /// Get processor state
    fn get_state(&mut self) -> Result<ProcessorState, TracerError>;

    /// Set processor state
    fn set_state(&mut self, state: &ProcessorState) -> Result<(), TracerError>;

    /// Run tracer
    fn run<'a, H: Hook>(&'a mut self, params: &'a Params, hook: &'a mut H) -> Result<Trace, TracerError>;

    /// Restore modified pages
    fn restore_snapshot(&mut self) -> Result<usize, TracerError>;

    /// Read gva
    fn read_gva(&mut self, cr3: u64, vaddr: u64, data: &mut [u8]) -> Result<(), TracerError>;

    /// Write gva
    fn write_gva(&mut self, cr3: u64, vaddr: u64, data: &[u8]) -> Result<(), TracerError>;

    /// Get cr3
    fn cr3(&mut self) -> Result<u64, TracerError>;

    /// Execute next instruction
    fn singlestep<H: Hook>(&mut self, params: &Params, hook: &mut H) -> Result<Trace, TracerError>;

    /// Add a breakpoint
    fn add_breakpoint(&mut self, address: u64);

    /// Get mapped pages
    fn get_mapped_pages(&self) -> Result<usize, TracerError>;

}

/// Hook tracer
pub trait Hook: Default {
    /// Initialize hook
    fn setup<T: Tracer + mem::X64VirtualAddressSpace>(&mut self, tracer: &mut T);

    /// Called on breakpoint
    fn handle_breakpoint<T: Tracer + mem::X64VirtualAddressSpace>(&mut self, tracer: &mut T) -> Result<bool, TracerError>;

    /// Called after execution
    fn handle_trace(&self, trace: &mut Trace) -> Result<bool, TracerError>;

    /// Called before mapping a page from snapshot (only used for WHVP when pages are filled with 0xcc)
    fn patch_page(&self, gva: u64) -> bool;
}

/// No-op hook
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


/// Memory access
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MemAccess {
    /// rip
    pub rip: u64,
    /// vaddr
    pub vaddr: u64,
    /// size
    pub size: usize,
    /// access_type
    pub access_type: MemAccessType,
}

/// Type of memory access
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum MemAccessType {
    /// Read
    Read,
    /// Write
    Write,
    /// Execute
    Execute,
    /// RW
    RW
}
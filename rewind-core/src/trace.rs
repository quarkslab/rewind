
use std::str::FromStr;
use std::collections::BTreeSet;
use std::collections::HashMap;

use std::io::{BufWriter, Write};

use std::time::{Instant, Duration};

use anyhow::Result;

use serde::{Serialize, Deserialize, Deserializer, de::Error};


#[derive(Serialize, Deserialize, CustomDebug, Default)]
pub struct Segment {
    pub selector: u16,
    pub base: u64,
    pub limit: u32,
    pub flags: u16
}

#[derive(Serialize, Deserialize, CustomDebug, Default)]
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

    pub fn save<P>(&self, path: P) -> Result<()>
    where P: AsRef<std::path::Path>
    {
        let mut fp = BufWriter::new(std::fs::File::create(&path)?);
        let data = serde_json::to_vec_pretty(&self)?;
        fp.write_all(&data)?;
        Ok(())
    }

    pub fn load<P>(path: P) -> Result<Self>
    where P: AsRef<std::path::Path>
    {
        let input_str = std::fs::read_to_string(&path)?;
        let input = serde_json::from_str(&input_str)?;
        Ok(input)
    }

}

impl FromStr for ProcessorState {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<ProcessorState> {
        let context = serde_json::from_str(s)?;
        Ok(context)
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
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<CoverageMode> {
        let coverage_mode = match s {
            "no" => CoverageMode::None,
            "instrs" => CoverageMode::Instrs,
            "hit" => CoverageMode::Hit,
            _ => {
                return Err(anyhow!(
                    "invalid coverage mode",
                ))
            }
        };
        Ok(coverage_mode)
    }
}


#[derive(Default, Serialize, Deserialize, CustomDebug)]
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
    pub fn save<P>(&self, path: P) -> Result<()>
    where P: AsRef<std::path::Path>
    {
        let mut fp = BufWriter::new(std::fs::File::create(&path)?);
        let data = serde_json::to_vec_pretty(&self)?;
        fp.write_all(&data)?;
        Ok(())
    }

    pub fn load<P>(path: P) -> Result<Self>
    where P: AsRef<std::path::Path>
    {
        let input_str = std::fs::read_to_string(&path)?;
        let input = serde_json::from_str(&input_str)?;
        Ok(input)
    }

}

impl FromStr for Params {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let params = serde_json::from_str(s)?;
        Ok(params)
    }
}

#[derive(Debug, PartialEq, PartialOrd, Serialize, Deserialize)]
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

#[derive(CustomDebug, Serialize, Deserialize)]
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

#[derive(CustomDebug, Serialize, Deserialize)]
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

    pub fn save<P>(&self, path: P) -> Result<()>
    where P: AsRef<std::path::Path>
    {
        let mut fp = BufWriter::new(std::fs::File::create(&path)?);
        let data = serde_json::to_vec_pretty(&self)?;
        fp.write_all(&data)?;
        Ok(())
    }

    pub fn load<P>(path: P) -> Result<Self>
    where P: AsRef<std::path::Path>
    {
        let input_str = std::fs::read_to_string(&path)?;
        let input = serde_json::from_str(&input_str)?;
        Ok(input)
    }

}

impl FromStr for Trace {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Trace> {
        let result = serde_json::from_str(s)?;
        Ok(result)
    }
}

#[derive(Debug, Serialize, PartialEq, Default)]
pub struct HexNumber(u64);

impl<'de> Deserialize<'de> for HexNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: &str = Deserialize::deserialize(deserializer)?;
        // do better hex decoding than this
        u64::from_str_radix(&s[2..], 16)
            .map(HexNumber)
            .map_err(D::Error::custom)
    }
}

impl From<u64> for HexNumber {

    fn from(n: u64) -> Self {
        Self(n)
    }
}

impl From<HexNumber> for u64 {

    fn from(n: HexNumber) -> Self {
        n.0
    }
}


#[derive(Default, Serialize, Deserialize, CustomDebug)]
pub struct Input {
    pub address: HexNumber,
    pub size: HexNumber,
}

impl Input {

    pub fn save<P>(&self, path: P) -> Result<()>
    where P: AsRef<std::path::Path>
    {
        let mut fp = BufWriter::new(std::fs::File::create(&path)?);
        let data = serde_json::to_vec_pretty(&self)?;
        fp.write_all(&data)?;
        Ok(())
    }

    pub fn load<P>(path: P) -> Result<Self>
    where P: AsRef<std::path::Path>
    {
        let input_str = std::fs::read_to_string(&path)?;
        let input = serde_json::from_str(&input_str)?;
        Ok(input)
    }

}

impl FromStr for Input {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Input> {
        let input = serde_json::from_str(s)?;
        Ok(input)
    }
}

pub trait Tracer {

    fn get_state(&mut self) -> Result<ProcessorState>;

    fn set_state(&mut self, state: &ProcessorState) -> Result<()>;

    fn run<H: Hook>(&mut self, params: &Params, hook: &mut H) -> Result<Trace>;

    fn restore_snapshot(&mut self) -> Result<usize>;

    fn read_gva(&mut self, cr3: u64, vaddr: u64, data: &mut [u8]) -> Result<()>;

    fn write_gva(&mut self, cr3: u64, vaddr: u64, data: &[u8]) -> Result<()>;

    fn cr3(&mut self) -> Result<u64>;

    fn singlestep<H: Hook>(&mut self, params: &Params, hook: &mut H) -> Result<Trace>;

    fn add_breakpoint(&mut self, address: u64);

}

// impl Tracer for Box<dyn Tracer> {

//     fn get_state(&mut self) -> Result<ProcessorState> {
//         self.as_mut().get_state()
//     }

//     fn set_state(&mut self, state: &ProcessorState) -> Result<()> {
//         self.as_mut().set_state(state)
//     }

//     fn run(&mut self, params: &Params, hook: &mut Hook) -> Result<Trace> {
//         self.as_mut().run(params, hook)
//     }

//     fn restore_snapshot(&mut self) -> Result<usize> {
//         self.as_mut().restore_snapshot()
//     }

//     fn read_gva(&mut self, cr3: u64, vaddr: u64, data: &mut [u8]) -> Result<()> {
//         self.as_mut().read_gva(cr3, vaddr, data)
//     }

//     fn write_gva(&mut self, cr3: u64, vaddr: u64, data: &[u8]) -> Result<()> {
//         self.as_mut().write_gva(cr3, vaddr, data)
//     }

//     fn cr3(&mut self) -> Result<u64> {
//         self.as_mut().cr3()
//     }

//     fn singlestep(&mut self, params: &Params) -> Result<Trace> {
//         self.as_mut().singlestep(params)
//     }

// }

pub trait Hook: Default {
    fn setup<T: Tracer>(&self, tracer: &mut T);

    fn handle_breakpoint<T: Tracer>(&mut self, tracer: &mut T) -> Result<bool>;

    fn handle_trace(&self, trace: &mut Trace) -> Result<bool>;

}



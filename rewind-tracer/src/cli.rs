
use custom_debug::Debug;

use clap::{Clap, crate_version};

#[derive(Clap, Debug)]
#[clap(version=crate_version!(), author="Damien Aumaitre")]
pub struct Cli {
    /// Set the level of verbosity
    #[clap(long, short, parse(from_occurrences))]
    pub verbose: usize,
 
    #[clap(long="snapshot", parse(from_os_str))]
    pub snapshot: std::path::PathBuf,

    #[clap(long="limit", default_value="0")]
    pub limit: u64,

    #[clap(long="save-context")]
    pub save_context: bool,

    #[clap(long="save-instructions")]
    pub save_instructions: bool,

    #[clap(long="max-time", default_value="0")]
    pub max_time: u64,

    #[clap(long="save-trace", parse(from_os_str))]
    pub trace: Option<std::path::PathBuf>,

    #[clap(long="emulator", possible_values(&["whvp", "bochs"]), default_value="bochs")]
    pub emulator: rewind_cli::EmulatorType,

    #[clap(long="coverage", possible_values(&["no", "instrs", "hit"]), default_value="no")]
    pub coverage: rewind_core::trace::CoverageMode,

    #[clap(long="input", parse(from_os_str))]
    pub input: Option<std::path::PathBuf>,

    #[clap(long="data", parse(from_os_str))]
    pub data: Option<std::path::PathBuf>,


}


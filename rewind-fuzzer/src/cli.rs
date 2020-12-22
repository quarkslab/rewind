
use custom_debug::Debug;

use clap::Clap;

#[derive(Clap, Debug)]
#[clap(author="Damien Aumaitre")]
pub struct Cli {
    /// Set the level of verbosity
    #[clap(long, short, parse(from_occurrences))]
    pub verbose: usize,
 
    #[clap(long="snapshot", parse(from_os_str))]
    pub snapshot: Option<std::path::PathBuf>,

    #[clap(long="max-iterations", default_value="0")]
    pub limit: u64,

    #[clap(long="save-context")]
    pub save_context: bool,

    #[clap(long="save-instructions")]
    pub save_instructions: bool,

    #[clap(long="stop-on-crash")]
    pub save_on_crash: bool,

    #[clap(long="display-delay", default_value="1")]
    pub display_delay: u64,

    #[clap(long="strategy", possible_values(&["random"]), default_value="random")]
    pub strategy: String,

    #[clap(long="max-time", default_value="0")]
    pub max_time: u64,

    #[clap(long="save-trace", parse(from_os_str))]
    pub trace: Option<std::path::PathBuf>,

    #[clap(long="backend", possible_values(&["whvp", "bochs"]), default_value="bochs")]
    pub backend: rewind_cli::BackendType,

    #[clap(long="coverage", possible_values(&["no", "instrs", "hit"]), default_value="no")]
    pub coverage: rewind_core::trace::CoverageMode,

    #[clap(long="workdir", parse(from_os_str))]
    pub workdir: std::path::PathBuf,

    #[clap(long="input", parse(from_os_str))]
    pub input: Option<std::path::PathBuf>,

    #[clap(long="input-address", default_value="0")]
    pub input_address: u64,

    #[clap(long="input-size", default_value="0")]
    pub input_size: u64,

}


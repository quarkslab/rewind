
use color_eyre::eyre::Result;

use rewind_core::{fuzz, mutation, trace::NoHook};

use rewind_cli::Rewind;

#[derive(Default)]
struct Cli {
}

impl Cli
{
    fn new() -> Self {
        Self {
        }
    }
}

impl Rewind for Cli {
    type TraceHook = NoHook;
    type FuzzerHook = NoHook;
    type FuzzingStrategy = mutation::BasicStrategy;

    fn create_fuzzer_hook(&self) -> Self::FuzzerHook {
        NoHook::default()
    }

    fn create_tracer_hook(&self) -> Self::TraceHook {
        NoHook::default()
    }

    fn create_fuzzing_strategy(&self, _params: &fuzz::Params, mutator: mutation::Mutator) -> Self::FuzzingStrategy {
        mutation::BasicStrategy::new(mutator)
    }
}

fn main() -> Result<()> {
    color_eyre::install()?;

    let cli = Cli::new();
    cli.run()?;

    Ok(())

}

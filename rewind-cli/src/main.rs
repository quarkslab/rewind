
use color_eyre::eyre::Result;

use rewind_cli::{Rewind, cli::CliExt};

fn main() -> Result<()> {
    color_eyre::install()?;

    let cli = Rewind::new();
    cli.run()?;

    Ok(())

}

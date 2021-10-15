
use color_eyre::Report;

use rewind_cli::cli::Cli;


fn main() -> Result<(), Report> {
    color_eyre::install()?;

    let cli = Cli::new();
    cli.run()?;

    Ok(())

}

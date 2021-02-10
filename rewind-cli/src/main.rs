
use color_eyre::eyre::Result;

use rewind_cli::Rewind;
use rewind_core::trace::NoHook;

fn main() -> Result<()> {

    color_eyre::install()?;
    Rewind::<NoHook>::parse_args()
            .run()?;

    Ok(())

}

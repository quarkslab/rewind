
use crate::Rewind;

fn main() -> Result<(), Box<dyn Error>> {

    Rewind::parse_args()
            .run()?;

    Ok(())

}

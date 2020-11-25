
use std::str::FromStr;

pub mod helpers;

#[derive(Debug)]
pub enum EmulatorType {
    Whvp,
    Bochs
}

impl FromStr for EmulatorType {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "bochs" => Ok(EmulatorType::Bochs),
            "whvp" => Ok(EmulatorType::Whvp),
            _ => Err("no match"),
        }
    }
}


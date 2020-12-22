
use std::str::FromStr;

#[macro_use]
extern crate anyhow;

use anyhow::Result;

pub use rewind_core::{fuzz, mem, mutation, trace, trace::Tracer};
pub use rewind_whvp::WhvpTracer;
pub use rewind_bochs::BochsTracer;

pub mod helpers;
pub mod cli;

pub use crate::cli::Rewind;

#[derive(Debug)]
pub enum BackendType {
    Whvp,
    Bochs
}

impl FromStr for BackendType {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "bochs" => Ok(Self::Bochs),
            "whvp" => Ok(Self::Whvp),
            _ => Err("no match"),
        }
    }
}


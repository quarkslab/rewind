
#![warn(missing_docs)]

//! Core of Rewind framework.
//!
//! Provides several traits to implement tracers and fuzzers

#[macro_use]
extern crate log;

pub mod mem;
pub mod watch;
pub mod fuzz;
pub mod trace;
pub mod snapshot;
pub mod helpers;
pub mod mutation;
pub mod corpus;
pub mod error;
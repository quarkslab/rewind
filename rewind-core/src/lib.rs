
#![warn(missing_docs)]

//! Core of Rewind framework.
//!
//! Provides several traits for developing various tracers and fuzzers

#[macro_use]
extern crate log;

#[doc(hidden)]
pub mod mem;

#[doc(hidden)]
pub mod watch;

#[doc(hidden)]
pub mod fuzz;

#[doc(hidden)]
pub mod trace;

#[doc(hidden)]
pub mod snapshot;

#[doc(hidden)]
pub mod helpers;

#[doc(hidden)]
pub mod mutation;

#[doc(hidden)]
pub mod corpus;

#[doc(hidden)]
pub mod error;
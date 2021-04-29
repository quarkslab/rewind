#![warn(missing_docs)]

//! Bochs based backend
//!
//! Implementation of Rewind `rewind_core::trace::Tracer` for bochs

#[macro_use]
extern crate log;

mod bochs;

pub use crate::bochs::BochsTracer;

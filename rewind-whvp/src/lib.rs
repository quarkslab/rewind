
#[cfg(windows)]
#[macro_use]
extern crate bitflags;

#[cfg(windows)]
#[macro_use]
extern crate log;

#[allow(non_upper_case_globals)]
#[cfg(windows)]
pub mod whvp;

#[cfg(windows)]
mod trace;

#[cfg(windows)]
pub use trace::WhvpTracer;



#![warn(missing_docs)]

//! TUI for monitoring fuzzing sessions
//!
//! Based on [tui-rs](https://github.com/fdehau/tui-rs)


pub use ui::{Collection, parse_trace, display_tui};

mod ui;
mod widget;
mod app;
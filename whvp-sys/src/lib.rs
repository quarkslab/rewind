
//! Bindings for [WHVP](https://docs.microsoft.com/en-us/virtualization/api/hypervisor-platform/hypervisor-platform) API
//!
//! The Windows Hypervisor Platform adds an extended user-mode API for third-party virtualization
//! stacks and applications to create and manage partitions at the hypervisor level, configure memory
//! mappings for the partition, and create and control execution of virtual processors.
//!
//! Generated with [bindgen](https://github.com/rust-lang/rust-bindgen)

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]
#![allow(clippy::all)] 
#![allow(deref_nullptr)]
include!(concat!(env!("OUT_DIR"), "/whvp_bindings.rs"));

extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("wrapper.h")
        .rustfmt_bindings(true)
        .allowlist_function("WHvGetCapability")
        .allowlist_function("WHvCreatePartition")
        .allowlist_function("WHvDeletePartition")
        .allowlist_function("WHvSetPartitionProperty")
        .allowlist_function("WHvSetupPartition")
        .allowlist_function("WHvCreateVirtualProcessor")
        .allowlist_function("WHvDeleteVirtualProcessor")
        .allowlist_function("WHvMapGpaRange")
        .allowlist_function("WHvUnmapGpaRange")
        .allowlist_function("WHvQueryGpaRangeDirtyBitmap")
        .allowlist_function("WHvTranslateGva")
        .allowlist_function("WHvGetVirtualProcessorRegisters")
        .allowlist_function("WHvSetVirtualProcessorRegisters")
        .allowlist_function("WHvCancelRunVirtualProcessor")
        .allowlist_function("WHvRunVirtualProcessor")
        .allowlist_type("WHV_CAPABILITY")
        .allowlist_type("WHV_EXTENDED_VM_EXITS")
        .allowlist_type("WHV_REGISTER_NAME")
        .allowlist_type("WHV_REGISTER_VALUE")
        .allowlist_type("WHV_RUN_VP_EXIT_CONTEXT")
        .allowlist_type("WHV_TRANSLATE_GVA_RESULT")
        .allowlist_type("WHV_EXCEPTION_TYPE")
        .allowlist_type("WHV_MEMORY_ACCESS_TYPE")
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("whvp_bindings.rs"))
        .expect("Couldn't write bindings!");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-link-lib=WinHvPlatform");
    println!("cargo:rustc-link-lib=WinHvEmulation");
}

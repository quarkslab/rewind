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
        .whitelist_function("WHvGetCapability")
        .whitelist_function("WHvCreatePartition")
        .whitelist_function("WHvDeletePartition")
        .whitelist_function("WHvSetPartitionProperty")
        .whitelist_function("WHvSetupPartition")
        .whitelist_function("WHvCreateVirtualProcessor")
        .whitelist_function("WHvDeleteVirtualProcessor")
        .whitelist_function("WHvMapGpaRange")
        .whitelist_function("WHvUnmapGpaRange")
        .whitelist_function("WHvQueryGpaRangeDirtyBitmap")
        .whitelist_function("WHvTranslateGva")
        .whitelist_function("WHvGetVirtualProcessorRegisters")
        .whitelist_function("WHvSetVirtualProcessorRegisters")
        .whitelist_function("WHvCancelRunVirtualProcessor")
        .whitelist_function("WHvRunVirtualProcessor")
        .whitelist_type("WHV_CAPABILITY")
        .whitelist_type("WHV_EXTENDED_VM_EXITS")
        .whitelist_type("WHV_REGISTER_NAME")
        .whitelist_type("WHV_REGISTER_VALUE")
        .whitelist_type("WHV_RUN_VP_EXIT_CONTEXT")
        .whitelist_type("WHV_TRANSLATE_GVA_RESULT")
        .whitelist_type("WHV_EXCEPTION_TYPE")
        .whitelist_type("WHV_MEMORY_ACCESS_TYPE")
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

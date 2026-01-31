use std::env;
use std::path::PathBuf;

// Look for valgrind library
fn is_valgrind_installed() -> bool {
    pkg_config::Config::new()
        // Don't link (we only need header macros)
        .cargo_metadata(false)
        .probe("valgrind")
        .is_ok()
}

fn main() {
    if !is_valgrind_installed() {
        // Only build if valgrind is installed
        return;
    }

    // Set has_valgrind flag
    println!("cargo:rustc-cfg=has_valgrind");

    // Invalidate the built crate whenever the wrapper and the build script changes.
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=wrapper.c");
    println!("cargo:rerun-if-changed=build.rs");

    let mut build = cc::Build::new();
    build.flag_if_supported("-fstack-protector-strong");
    build.flag_if_supported("-Werror=incompatible-pointer-types");
    build.define("_FORTIFY_SOURCE", Some("2"));
    build
        .files(["wrapper.c"].iter())
        .compile("valgrind-wrapper");

    let binding_builder = bindgen::Builder::default()
        .header("wrapper.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_function("valgrind_.*")
        .use_core();

    // Finish the builder and generate the bindings.
    let bindings = binding_builder
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs");
    bindings
        .write_to_file(out_path)
        .expect("Couldn't write bindings!");
}

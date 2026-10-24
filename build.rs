// SPDX-License-Identifier: MIT
#[path = "build/vole_tables/mod.rs"]
mod vole_tables;
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build/vole_tables");
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(out.join("vole_tables.rs"), vole_tables::generate_all())
        .expect("write generated VOLE tables");
}

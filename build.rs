//! Build script: one link flag, for Windows only.
//!
//! # The defect this closes (campaign 10, round 2)
//!
//! `q21.exe` imports `bcrypt.dll` statically (`src/rng.rs`), and that library
//! is not among those Windows protects: the loader looks for it in the
//! program's own folder first. A `bcrypt.dll` left in the folder the archive
//! is extracted into, a downloads folder, ran as the user at every launch,
//! before `main` and before any seed was drawn. The flag below tells the
//! loader to resolve the program's static imports from `System32` only
//! (`LOAD_LIBRARY_SEARCH_SYSTEM32`, honored since Windows 10, version 1607).
//! Every library the programs import statically lives there.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if os == "windows" && env == "msvc" {
        println!("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
    }
}

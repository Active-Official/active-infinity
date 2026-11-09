//! Build script for the Active Infinity FFI crate (INF-POLY-05).
//!
//! On Windows MSVC fuzz builds, cargo-fuzz links every crate with
//! `/include:main`, and a cdylib has no `main`, so the FFI DLL link fails
//! with LNK2001. The fallback is declared here (see `src/lib.rs`,
//! `active_infinity_ffi_main_shim`): `/alternatename:main=<shim>` tells
//! the linker to use the shim only if `main` is otherwise undefined, so
//! a real `main` (libFuzzer's, in the fuzz binaries) always wins and the
//! shim can never hijack an entry point. The directive is inert on every
//! other build: it is only consulted when `main` is undefined, and `main`
//! is only forced-undefined by cargo-fuzz's `/include:main`.
//! (MSVC-only flag, so it is emitted only for windows-msvc targets; the
//! shim itself only exists in fuzz builds, so the directive is emitted
//! only when the fuzz cfg is visible here.)

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os != "windows" || target_env != "msvc" {
        return;
    }
    // `cfg(fuzzing)` is set by cargo-fuzz via RUSTFLAGS (`--cfg fuzzing`).
    // Build scripts see it as CARGO_CFG_FUZZING; RUSTFLAGS is also visible
    // here, so check all three spellings — whichever survives.
    let fuzzing = std::env::var_os("CARGO_CFG_FUZZING").is_some()
        || std::env::var("RUSTFLAGS")
            .map(|v| v.contains("fuzzing"))
            .unwrap_or(false)
        || std::env::var("CARGO_ENCODED_RUSTFLAGS")
            .map(|v| v.contains("fuzzing"))
            .unwrap_or(false);
    if fuzzing {
        println!("cargo:rustc-link-arg=/alternatename:main=active_infinity_ffi_main_shim");
    }
}

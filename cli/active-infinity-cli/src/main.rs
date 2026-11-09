//! Production CLI for Active Infinity (binary entry point).
//!
//! The argument parser and every command live in the library so the
//! parser can be fuzzed in-process (`fuzz/fuzz_targets/fuzz_cli_args.rs`,
//! INF-POLY-05); this binary only maps the result to an exit code.

use std::process::ExitCode;

fn main() -> ExitCode {
    match active_infinity_cli::run(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(if error.starts_with("usage:") { 2 } else { 1 })
        }
    }
}

//! Collection of repo-specific CI checks.

use std::{path::PathBuf, process::Command, str::FromStr};

use clap::Parser;

mod lints_enabled;

/// Run CI checks on all crates.
#[derive(clap::Parser)]
pub struct Args {
    /// Set the directory to treat as the repo root.
    ///
    /// If omitted, shells out to `git rev-parse --show-toplevel` from the cwd.
    #[clap(long, short)]
    root: Option<PathBuf>,
}

/// Alias for a check function, which performs some check on the repo and may return an
/// error.
pub type CheckFn = fn(&Args) -> BoxResult<()>;

/// The set of check fns to run.
pub const CHECK_FNS: &[(&str, CheckFn)] = &[("lints_enabled", lints_enabled::run)];

/// Convenience alias for `Result` with a boxed `std::error::Error`.
pub type BoxResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Return the path to the root of the repo by shelling out to `git rev-parse`.
pub fn repo_root() -> BoxResult<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()?;

    let s = core::str::from_utf8(&output.stdout)?.trim();
    let path = PathBuf::from_str(s)?;

    Ok(path)
}

fn main() {
    let args = Args::parse();

    let root = args
        .root
        .clone()
        .ok_or("no root")
        .or_else(|_| repo_root())
        .unwrap();

    std::env::set_current_dir(&root).unwrap();

    let mut failed = false;

    for (name, f) in CHECK_FNS {
        if let Err(e) = f(&args) {
            failed = true;
            eprintln!("check {name}: {e}");
        }
    }

    if failed {
        std::process::exit(1);
    }
}

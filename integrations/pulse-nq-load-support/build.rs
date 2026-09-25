//! Record the source commit release automation names at compile time.

use std::env;
use std::fs;
use std::path::PathBuf;

#[path = "src/source_commit.rs"]
mod source_commit;

use source_commit::{SOURCE_COMMIT_VARIABLE, parse_source_commit};

fn main() {
    println!("cargo:rerun-if-env-changed={SOURCE_COMMIT_VARIABLE}");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/source_commit.rs");
    let value = env::var_os(SOURCE_COMMIT_VARIABLE);
    let value = match value.as_deref().map(std::ffi::OsStr::to_str) {
        Some(None) => {
            eprintln!("pulse-nq-load-support: {SOURCE_COMMIT_VARIABLE} is not valid UTF-8");
            std::process::exit(1);
        }
        Some(Some(value)) => Some(value),
        None => None,
    };
    let commit = match parse_source_commit(value) {
        Ok(commit) => commit,
        Err(diagnostic) => {
            eprintln!("pulse-nq-load-support: {diagnostic}");
            std::process::exit(1);
        }
    };
    let version = env::var("CARGO_PKG_VERSION").expect("cargo provides CARGO_PKG_VERSION");
    let (source_commit, version_string) = match commit {
        Some(commit) => (format!("Some({commit:?})"), format!("{version} ({commit})")),
        None => ("None".to_owned(), version),
    };
    let generated = format!(
        "/// Source commit recorded through `{SOURCE_COMMIT_VARIABLE}` at compile time.\n\
         pub const SOURCE_COMMIT: Option<&str> = {source_commit};\n\
         /// `--version` text: the workspace version, followed by the recorded\n\
         /// source commit in parentheses when one was recorded.\n\
         pub const VERSION_STRING: &str = {version_string:?};\n"
    );
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("cargo provides OUT_DIR"));
    fs::write(out_dir.join("source_commit_generated.rs"), generated)
        .expect("write generated source commit constants");
}

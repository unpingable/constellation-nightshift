//! Machine-readable build identity emitted before any argument parsing,
//! store access, or input read.

use std::ffi::OsStr;
use std::io::{self, Write};

use serde::Serialize;

mod source_commit;

pub use source_commit::{parse_source_commit, SOURCE_COMMIT_VARIABLE};

include!(concat!(env!("OUT_DIR"), "/source_commit_generated.rs"));

/// Schema identifier of the `--build-info` document.
pub const BUILD_INFO_SCHEMA: &str = "nightshift.build_info.v1";

/// Workspace version compiled into every Nightshift executable.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Exact identity of one shipped executable.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BuildInfo<'a> {
    pub schema: &'static str,
    pub component: &'a str,
    pub version: &'static str,
    pub debug_assertions: bool,
    /// Full git commit id recorded through `NIGHTSHIFT_SOURCE_COMMIT`;
    /// `null` for ordinary development builds.
    pub source_commit: Option<&'static str>,
}

impl<'a> BuildInfo<'a> {
    #[must_use]
    pub const fn current(component: &'a str) -> Self {
        Self {
            schema: BUILD_INFO_SCHEMA,
            component,
            version: VERSION,
            debug_assertions: cfg!(debug_assertions),
            source_commit: SOURCE_COMMIT,
        }
    }
}

/// Write one compact JSON build-information document and return `true` when
/// `--build-info` is the process's only argument; otherwise return `false`.
pub fn write_if_requested(component: &str) -> io::Result<bool> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    if arguments.next().as_deref() != Some(OsStr::new("--build-info")) || arguments.next().is_some()
    {
        return Ok(false);
    }
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, &BuildInfo::current(component)).map_err(io::Error::other)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_information_is_closed_and_machine_readable() {
        let bytes = serde_json::to_vec(&BuildInfo::current("fixture")).unwrap();
        let decoded: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded["schema"], BUILD_INFO_SCHEMA);
        assert_eq!(decoded["component"], "fixture");
        assert_eq!(decoded["version"], VERSION);
        assert_eq!(decoded["debug_assertions"], cfg!(debug_assertions));
        assert_eq!(decoded["source_commit"].as_str(), SOURCE_COMMIT);
        assert_eq!(decoded.as_object().map(serde_json::Map::len), Some(5));
    }

    #[test]
    fn version_string_carries_the_recorded_commit() {
        match SOURCE_COMMIT {
            Some(commit) => assert_eq!(VERSION_STRING, format!("{VERSION} ({commit})")),
            None => assert_eq!(VERSION_STRING, VERSION),
        }
    }

    #[test]
    fn source_commit_accepts_only_a_full_lowercase_commit_id() {
        let commit = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(parse_source_commit(None), Ok(None));
        assert_eq!(parse_source_commit(Some("")), Ok(None));
        assert_eq!(parse_source_commit(Some(commit)), Ok(Some(commit)));
        for rejected in [
            "0123456789abcdef0123456789abcdef0123456",
            "0123456789abcdef0123456789abcdef012345678",
            "0123456789ABCDEF0123456789abcdef01234567",
            "0123456789abcdef0123456789abcdef0123456g",
            " 0123456789abcdef0123456789abcdef01234567",
            "HEAD",
        ] {
            let error = parse_source_commit(Some(rejected)).expect_err(rejected);
            assert!(error.contains(SOURCE_COMMIT_VARIABLE), "{error}");
        }
    }
}

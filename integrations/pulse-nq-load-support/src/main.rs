#![forbid(unsafe_code)]

use std::env;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use pulse_nq_load_support::{
    LoadSupportConfigV1, PresentEvidenceQueryV1, ingest, produce, resolve,
};

#[cfg(test)]
mod source_commit;

include!(concat!(env!("OUT_DIR"), "/source_commit_generated.rs"));

const COMPONENT: &str = "pulse-nq-load-support";
const BUILD_INFO_SCHEMA: &str = "pulse_nq_load_support.build_info.v1";

/// Answer `--version` or `--build-info` when it is the only argument, for
/// every executable role, before any configuration or input is read.
fn identity_request() -> Option<String> {
    let mut arguments = env::args_os().skip(1);
    let first = arguments.next()?;
    if arguments.next().is_some() {
        return None;
    }
    match first.to_str()? {
        "--version" => Some(format!("{COMPONENT} {VERSION_STRING}")),
        "--build-info" => Some(
            serde_json::json!({
                "schema": BUILD_INFO_SCHEMA,
                "component": COMPONENT,
                "version": env!("CARGO_PKG_VERSION"),
                "debug_assertions": cfg!(debug_assertions),
                "source_commit": SOURCE_COMMIT,
            })
            .to_string(),
        ),
        _ => None,
    }
}

fn main() {
    if let Some(identity) = identity_request() {
        println!("{identity}");
        return;
    }
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let executable = env::args_os()
        .next()
        .and_then(|value| PathBuf::from(value).file_name().map(|name| name.to_owned()))
        .and_then(|value| value.to_str().map(str::to_owned))
        .ok_or_else(|| "cannot determine executable basename".to_owned())?;
    let args: Vec<String> = env::args().skip(1).collect();
    match executable.as_str() {
        "pulse-load-pressure-producer" => role_command("produce", &args),
        "pulse-load-pressure-receiver" => role_command("ingest", &args),
        "pulse-support-resolver" => resolver_command(&args),
        "pulse-nq-load-support" => {
            let (role, rest) = args
                .split_first()
                .ok_or_else(|| "usage: pulse-nq-load-support produce|ingest ...".to_owned())?;
            role_command(role, rest)
        }
        _ => Err("unsupported executable role".into()),
    }
}

fn role_command(role: &str, args: &[String]) -> Result<(), String> {
    if args.len() != 4 || args[0] != "--config" || args[2] != "--acquisition-id" {
        return Err(format!(
            "usage: {role} --config ABSOLUTE_PATH --acquisition-id TOKEN"
        ));
    }
    let config_path = Path::new(&args[1]);
    if !config_path.is_absolute() {
        return Err("configuration path must be absolute".into());
    }
    let config = LoadSupportConfigV1::from_path(config_path)?;
    let identity = match role {
        "produce" => produce(&config, &args[3])?,
        "ingest" => ingest(&config, &args[3])?,
        _ => return Err("only the closed produce and ingest roles exist".into()),
    };
    println!("{identity}");
    Ok(())
}

fn resolver_command(args: &[String]) -> Result<(), String> {
    if !args.is_empty() {
        return Err("pulse-support-resolver accepts no arguments".into());
    }
    let config_path = env::var_os("PULSE_LOAD_SUPPORT_CONFIG")
        .ok_or_else(|| "PULSE_LOAD_SUPPORT_CONFIG is required".to_owned())?;
    let config_path = PathBuf::from(config_path);
    if !config_path.is_absolute() {
        return Err("PULSE_LOAD_SUPPORT_CONFIG must be absolute".into());
    }
    let config = match env::var("PULSE_LOAD_SUPPORT_CONFIG_SHA256") {
        Ok(expected_sha256) => {
            LoadSupportConfigV1::from_sealed_descriptor_path(&config_path, &expected_sha256)?
        }
        Err(env::VarError::NotPresent) => LoadSupportConfigV1::from_path(&config_path)?,
        Err(env::VarError::NotUnicode(_)) => {
            return Err("PULSE_LOAD_SUPPORT_CONFIG_SHA256 must be UTF-8".into());
        }
    };
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(64 * 1_024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > 64 * 1_024 {
        return Err("Nightshift support query exceeds the byte bound".into());
    }
    let query: PresentEvidenceQueryV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    let support = resolve(&config, &query)?;
    let output = serde_jcs::to_vec(&support).map_err(|error| error.to_string())?;
    std::io::stdout()
        .write_all(&output)
        .map_err(|error| error.to_string())?;
    Ok(())
}

#[cfg(test)]
mod identity_tests {
    use super::source_commit::{SOURCE_COMMIT_VARIABLE, parse_source_commit};
    use super::{SOURCE_COMMIT, VERSION_STRING};

    #[test]
    fn version_string_carries_the_recorded_commit() {
        match SOURCE_COMMIT {
            Some(commit) => assert_eq!(
                VERSION_STRING,
                format!("{} ({commit})", env!("CARGO_PKG_VERSION"))
            ),
            None => assert_eq!(VERSION_STRING, env!("CARGO_PKG_VERSION")),
        }
    }

    #[test]
    fn source_commit_accepts_only_a_full_lowercase_commit_id() {
        let commit = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(parse_source_commit(None), Ok(None));
        assert_eq!(parse_source_commit(Some("")), Ok(None));
        assert_eq!(parse_source_commit(Some(commit)), Ok(Some(commit)));
        for rejected in ["0123456789ABCDEF0123456789abcdef01234567", "abc", "HEAD"] {
            let error = parse_source_commit(Some(rejected)).expect_err(rejected);
            assert!(error.contains(SOURCE_COMMIT_VARIABLE), "{error}");
        }
    }
}

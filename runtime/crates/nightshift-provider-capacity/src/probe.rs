use crate::model::{
    CapacityObservationV1, CapacityWindow, Confidence, ObservationDisposition, ObservationEvidence,
    SourceClass, WindowType, CAPACITY_OBSERVATION_SCHEMA_V1,
};
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::fs::{self, File};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration as StdDuration;

const RAW_DOMAIN: &[u8] = b"nightshift.provider-capacity.raw-source/v1\0";
const READ_BUFFER_BYTES: usize = 4096;

#[derive(Clone, Debug)]
pub struct CodexProbeOptions {
    pub codex_executable: PathBuf,
    pub expected_executable_digest: String,
    pub expected_protocol_version: String,
    pub account_profile_locator: String,
    pub observed_at: DateTime<Utc>,
    pub expires_after: Duration,
    pub timeout: StdDuration,
    pub maximum_response_bytes: usize,
}

#[derive(Clone, Debug)]
struct ProbeIdentity {
    executable_path: String,
    executable_digest: String,
    protocol_version: Option<String>,
}

struct PreparedExecutable {
    file: File,
    path: PathBuf,
    digest: String,
}

/// Runs only the supported Codex App Server read method over a fresh bounded
/// stdio connection. The native executable is opened and digest-verified before
/// it is invoked through its pinned descriptor. The initialize response must
/// independently confirm the expected protocol version before quota testimony
/// can become usable.
pub fn probe_codex_app_server(options: &CodexProbeOptions) -> CapacityObservationV1 {
    let prepared = match prepare_executable(options) {
        Ok(prepared) => prepared,
        Err(reason) => return unknown_observation_with_identity(&[], options, reason, None),
    };
    let executable_identity = ProbeIdentity {
        executable_path: prepared.path.display().to_string(),
        executable_digest: prepared.digest.clone(),
        protocol_version: None,
    };
    match collect_codex_response(options, &prepared) {
        Ok(raw) => {
            let mut verified_identity = executable_identity;
            verified_identity.protocol_version =
                Some(format!("codex-cli-{}", options.expected_protocol_version));
            normalize_codex_response_with_identity(&raw, options, Some(&verified_identity))
        }
        Err(reason) => {
            unknown_observation_with_identity(&[], options, reason, Some(&executable_identity))
        }
    }
}

fn prepare_executable(options: &CodexProbeOptions) -> Result<PreparedExecutable, String> {
    if !options.codex_executable.is_absolute() {
        return Err("EXECUTABLE_PATH_NOT_ABSOLUTE".to_string());
    }
    if options.expected_protocol_version.trim().is_empty()
        || options
            .expected_protocol_version
            .chars()
            .any(char::is_whitespace)
    {
        return Err("PROTOCOL_VERSION_INVALID".to_string());
    }
    if !is_sha256_digest(&options.expected_executable_digest) {
        return Err("EXECUTABLE_DIGEST_INVALID".to_string());
    }
    let canonical = fs::canonicalize(&options.codex_executable)
        .map_err(|_| "EXECUTABLE_UNAVAILABLE".to_string())?;
    if canonical != options.codex_executable {
        return Err("EXECUTABLE_PATH_NOT_CANONICAL".to_string());
    }
    let mut file = File::open(&canonical).map_err(|_| "EXECUTABLE_UNAVAILABLE".to_string())?;
    let metadata = file
        .metadata()
        .map_err(|_| "EXECUTABLE_METADATA_UNAVAILABLE".to_string())?;
    if !metadata.is_file() {
        return Err("EXECUTABLE_NOT_REGULAR_FILE".to_string());
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err("EXECUTABLE_PERMISSION_REFUSED".to_string());
    }

    let mut magic = [0_u8; 4];
    file.read_exact(&mut magic)
        .map_err(|_| "EXECUTABLE_READ_FAILED".to_string())?;
    if magic != *b"\x7fELF" {
        return Err("EXECUTABLE_NOT_NATIVE".to_string());
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| "EXECUTABLE_READ_FAILED".to_string())?;
    let digest = executable_digest(&mut file)?;
    if digest != options.expected_executable_digest {
        return Err("EXECUTABLE_DIGEST_MISMATCH".to_string());
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| "EXECUTABLE_READ_FAILED".to_string())?;
    Ok(PreparedExecutable {
        file,
        path: canonical,
        digest,
    })
}

fn executable_digest(file: &mut File) -> Result<String, String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| "EXECUTABLE_READ_FAILED".to_string())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

#[cfg(target_os = "linux")]
fn collect_codex_response(
    options: &CodexProbeOptions,
    prepared: &PreparedExecutable,
) -> Result<Vec<u8>, String> {
    let descriptor_path = format!("/proc/self/fd/{}", prepared.file.as_raw_fd());
    let mut child = Command::new(descriptor_path)
        .args(["app-server", "--listen", "stdio://"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "PROBE_PROCESS_UNAVAILABLE".to_string())?;

    let input = child.stdin.take();
    let output = child.stdout.take();
    let error = child.stderr.take();
    let (Some(mut input), Some(output), Some(error)) = (input, output, error) else {
        let _ = child.kill();
        let _ = child.wait();
        return Err("PROBE_STDIO_UNAVAILABLE".to_string());
    };
    let error_drain = thread::spawn(move || {
        let _ = std::io::copy(&mut BufReader::new(error), &mut std::io::sink());
    });
    let requests = [
        serde_json::json!({"method":"initialize","id":1,"params":{"clientInfo":{
            "name":"nightshift_provider_capacity",
            "title":"Nightshift Provider Capacity Probe",
            "version":env!("CARGO_PKG_VERSION")
        },"capabilities":{"optOutNotificationMethods":["account/rateLimits/updated"]}}}),
        serde_json::json!({"method":"initialized","params":{}}),
        serde_json::json!({"method":"account/rateLimits/read","id":2}),
    ];
    let write_result = requests.iter().try_for_each(|request| {
        serde_json::to_writer(&mut input, request).map_err(|_| "PROBE_REQUEST_ENCODE_FAILED")?;
        input
            .write_all(b"\n")
            .map_err(|_| "PROBE_REQUEST_WRITE_FAILED")
    });
    let write_result =
        write_result.and_then(|()| input.flush().map_err(|_| "PROBE_REQUEST_WRITE_FAILED"));
    let (sender, receiver) = mpsc::channel();
    let maximum = options.maximum_response_bytes;
    let expected_version = options.expected_protocol_version.clone();
    let reader = thread::spawn(move || {
        let result = read_bounded_response(output, maximum, &expected_version);
        let _ = sender.send(result);
    });
    let mut result = match write_result {
        Ok(()) => receiver
            .recv_timeout(options.timeout)
            .unwrap_or_else(|_| Err("PROBE_TIMEOUT".to_string())),
        Err(reason) => Err(reason.to_string()),
    };

    drop(input);
    let _ = child.kill();
    if child.wait().is_err() && result.is_ok() {
        result = Err("PROBE_PROCESS_TEARDOWN_FAILED".to_string());
    }
    if reader.join().is_err() && result.is_ok() {
        result = Err("PROBE_READER_JOIN_FAILED".to_string());
    }
    if error_drain.join().is_err() && result.is_ok() {
        result = Err("PROBE_STDERR_JOIN_FAILED".to_string());
    }
    result
}

#[cfg(not(target_os = "linux"))]
fn collect_codex_response(
    _options: &CodexProbeOptions,
    _prepared: &PreparedExecutable,
) -> Result<Vec<u8>, String> {
    Err("PINNED_EXECUTION_UNAVAILABLE".to_string())
}

fn read_bounded_response<R: Read>(
    mut output: R,
    maximum: usize,
    expected_version: &str,
) -> Result<Vec<u8>, String> {
    let mut buffer = [0_u8; READ_BUFFER_BYTES];
    let mut line = Vec::new();
    let mut total = 0_usize;
    let mut version_verified = false;
    loop {
        let read = output
            .read(&mut buffer)
            .map_err(|_| "PROBE_OUTPUT_READ_FAILED".to_string())?;
        if read == 0 {
            if !line.is_empty() {
                if let Some(response) =
                    inspect_line(&line, expected_version, &mut version_verified)?
                {
                    return Ok(response);
                }
            }
            return Err(if total == 0 {
                "PROBE_NO_OUTPUT"
            } else {
                "PROBE_TARGET_RESPONSE_ABSENT"
            }
            .to_string());
        }
        if read > maximum.saturating_sub(total) {
            return Err("PROBE_RESPONSE_OVERSIZED".to_string());
        }
        total += read;

        let mut start = 0;
        for (index, byte) in buffer[..read].iter().enumerate() {
            if *byte == b'\n' {
                line.extend_from_slice(&buffer[start..=index]);
                if let Some(response) =
                    inspect_line(&line, expected_version, &mut version_verified)?
                {
                    return Ok(response);
                }
                line.clear();
                start = index + 1;
            }
        }
        line.extend_from_slice(&buffer[start..read]);
    }
}

fn inspect_line(
    line: &[u8],
    expected_version: &str,
    version_verified: &mut bool,
) -> Result<Option<Vec<u8>>, String> {
    let Ok(value) = serde_json::from_slice::<Value>(line) else {
        return Ok(None);
    };
    match value.get("id").and_then(Value::as_i64) {
        Some(1) => {
            if value.get("error").is_some() {
                return Err("PROBE_INITIALIZE_REFUSED".to_string());
            }
            let user_agent = value
                .pointer("/result/userAgent")
                .and_then(Value::as_str)
                .ok_or_else(|| "PROTOCOL_VERSION_UNAVAILABLE".to_string())?;
            let expected_agent = format!("codex_cli_rs/{expected_version}");
            if user_agent.split_whitespace().next() != Some(expected_agent.as_str()) {
                return Err("PROTOCOL_VERSION_MISMATCH".to_string());
            }
            *version_verified = true;
            Ok(None)
        }
        Some(2) if !*version_verified => Err("PROTOCOL_VERSION_UNVERIFIED".to_string()),
        Some(2) => Ok(Some(line.to_vec())),
        _ => Ok(None),
    }
}

/// Deterministic parser entry for exact fixture responses. The supplied
/// executable identity must already have been verified by the fixture owner;
/// the live entrypoint performs that verification itself.
pub fn normalize_codex_response(
    raw_response: &[u8],
    options: &CodexProbeOptions,
) -> CapacityObservationV1 {
    let identity = ProbeIdentity {
        executable_path: options.codex_executable.display().to_string(),
        executable_digest: options.expected_executable_digest.clone(),
        protocol_version: Some(format!("codex-cli-{}", options.expected_protocol_version)),
    };
    normalize_codex_response_with_identity(raw_response, options, Some(&identity))
}

fn normalize_codex_response_with_identity(
    raw_response: &[u8],
    options: &CodexProbeOptions,
    identity: Option<&ProbeIdentity>,
) -> CapacityObservationV1 {
    let parsed: Value = match serde_json::from_slice(raw_response) {
        Ok(value) => value,
        Err(_) => {
            return unknown_observation_with_identity(
                raw_response,
                options,
                "MALFORMED_RESPONSE",
                identity,
            );
        }
    };
    if parsed.get("id").and_then(Value::as_i64) != Some(2) {
        return unknown_observation_with_identity(
            raw_response,
            options,
            "RESPONSE_ID_MISMATCH",
            identity,
        );
    }
    if parsed.get("error").is_some() {
        return unknown_observation_with_identity(
            raw_response,
            options,
            "PROVIDER_READ_REFUSED",
            identity,
        );
    }
    let Some(snapshot) = parsed.pointer("/result/rateLimits") else {
        return unknown_observation_with_identity(
            raw_response,
            options,
            "LAYOUT_UNRECOGNIZED",
            identity,
        );
    };

    let mut windows = Vec::new();
    for (name, pointer) in [("primary", "/primary"), ("secondary", "/secondary")] {
        let Some(window) = snapshot.pointer(pointer) else {
            continue;
        };
        if window.is_null() {
            continue;
        }
        let Some(used) = window.get("usedPercent").and_then(Value::as_f64) else {
            return unknown_observation_with_identity(
                raw_response,
                options,
                "LAYOUT_UNRECOGNIZED",
                identity,
            );
        };
        if !used.is_finite() || !(0.0..=100.0).contains(&used) {
            return unknown_observation_with_identity(
                raw_response,
                options,
                "IMPOSSIBLE_PERCENTAGE",
                identity,
            );
        }
        let duration = match window.get("windowDurationMins") {
            Some(Value::Number(number)) => match number.as_u64() {
                Some(value) if value > 0 => Some(value),
                _ => {
                    return unknown_observation_with_identity(
                        raw_response,
                        options,
                        "IMPOSSIBLE_WINDOW",
                        identity,
                    );
                }
            },
            Some(Value::Null) | None => None,
            _ => {
                return unknown_observation_with_identity(
                    raw_response,
                    options,
                    "LAYOUT_UNRECOGNIZED",
                    identity,
                );
            }
        };
        let resets_at = match window.get("resetsAt") {
            Some(Value::Number(number)) => {
                match number
                    .as_i64()
                    .and_then(|value| DateTime::from_timestamp(value, 0))
                {
                    Some(value) => Some(value),
                    None => {
                        return unknown_observation_with_identity(
                            raw_response,
                            options,
                            "IMPOSSIBLE_RESET",
                            identity,
                        );
                    }
                }
            }
            Some(Value::Null) | None => None,
            _ => {
                return unknown_observation_with_identity(
                    raw_response,
                    options,
                    "LAYOUT_UNRECOGNIZED",
                    identity,
                );
            }
        };
        let window_type = match duration {
            Some(300) => WindowType::FiveHour,
            Some(10_080) => WindowType::Weekly,
            _ => WindowType::ProviderDefined,
        };
        windows.push(CapacityWindow {
            window_id: name.to_string(),
            window_type,
            remaining_fraction: Some((100.0 - used) / 100.0),
            remaining_units: None,
            resets_at,
        });
    }
    if windows.is_empty() {
        return unknown_observation_with_identity(
            raw_response,
            options,
            "NO_CAPACITY_WINDOWS",
            identity,
        );
    }
    if windows.len() == 2
        && windows[0].window_type == windows[1].window_type
        && windows[0].resets_at == windows[1].resets_at
        && windows[0].remaining_fraction != windows[1].remaining_fraction
    {
        return unknown_observation_with_identity(
            raw_response,
            options,
            "CONTRADICTORY_WINDOWS",
            identity,
        );
    }
    make_observation(
        raw_response,
        options,
        Confidence::High,
        ObservationDisposition::Usable,
        Vec::new(),
        windows,
        identity,
    )
}

pub fn unknown_observation(
    raw_response: &[u8],
    options: &CodexProbeOptions,
    reason: impl Into<String>,
) -> CapacityObservationV1 {
    unknown_observation_with_identity(raw_response, options, reason, None)
}

fn unknown_observation_with_identity(
    raw_response: &[u8],
    options: &CodexProbeOptions,
    reason: impl Into<String>,
    identity: Option<&ProbeIdentity>,
) -> CapacityObservationV1 {
    make_observation(
        raw_response,
        options,
        Confidence::Unknown,
        ObservationDisposition::Unknown,
        vec![reason.into()],
        Vec::new(),
        identity,
    )
}

fn make_observation(
    raw: &[u8],
    options: &CodexProbeOptions,
    confidence: Confidence,
    disposition: ObservationDisposition,
    unknown_reasons: Vec<String>,
    windows: Vec<CapacityWindow>,
    identity: Option<&ProbeIdentity>,
) -> CapacityObservationV1 {
    let usable = disposition == ObservationDisposition::Usable;
    let mut value = CapacityObservationV1 {
        schema: CAPACITY_OBSERVATION_SCHEMA_V1.to_string(),
        provider_id: "openai-codex".to_string(),
        account_profile_locator: options.account_profile_locator.clone(),
        model_family: None,
        observed_at: options.observed_at,
        expires_at: options.observed_at + options.expires_after,
        source_class: if usable {
            SourceClass::Observed
        } else {
            SourceClass::Unknown
        },
        confidence,
        disposition,
        unknown_reasons,
        windows,
        evidence: ObservationEvidence {
            probe_id: "codex-app-server-rate-limits-read-v1".to_string(),
            protocol_method: "account/rateLimits/read".to_string(),
            protocol_version: identity.and_then(|value| value.protocol_version.clone()),
            executable_path: identity.map(|value| value.executable_path.clone()),
            executable_digest: identity.map(|value| value.executable_digest.clone()),
            raw_source_digest: raw_digest(raw),
        },
        observation_digest: String::new(),
    };
    value.observation_digest = value.compute_digest().expect("observation serializes");
    value
}

fn raw_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(RAW_DOMAIN);
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod collector_tests {
    use super::*;
    use std::io::{Cursor, Read};
    #[cfg(unix)]
    use std::os::unix::fs::{symlink, PermissionsExt};

    struct DelayedEof(StdDuration);

    impl Read for DelayedEof {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            thread::sleep(self.0);
            Ok(0)
        }
    }

    fn initialize() -> Vec<u8> {
        br#"{"id":1,"result":{"userAgent":"codex_cli_rs/0.147.0 (fixture)"}}
"#
        .to_vec()
    }

    fn target() -> Vec<u8> {
        br#"{"id":2,"result":{"rateLimits":{}}}
"#
        .to_vec()
    }

    #[cfg(unix)]
    fn executable_options(path: PathBuf, digest: String) -> CodexProbeOptions {
        CodexProbeOptions {
            codex_executable: path,
            expected_executable_digest: digest,
            expected_protocol_version: "0.147.0".to_string(),
            account_profile_locator: "fixture-profile".to_string(),
            observed_at: DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
            expires_after: Duration::minutes(15),
            timeout: StdDuration::from_millis(20),
            maximum_response_bytes: 4096,
        }
    }

    #[test]
    fn incremental_collector_accepts_only_version_bound_target() {
        let mut input = initialize();
        input.extend_from_slice(&target());
        assert_eq!(
            read_bounded_response(Cursor::new(input), 4096, "0.147.0").unwrap(),
            target()
        );
    }

    #[test]
    fn incremental_collector_refuses_oversize_before_growing_line() {
        let result = read_bounded_response(Cursor::new(vec![b'x'; 65]), 64, "0.147.0");
        assert_eq!(result.unwrap_err(), "PROBE_RESPONSE_OVERSIZED");
    }

    #[test]
    fn collector_no_output_and_version_substitution_are_distinct() {
        assert_eq!(
            read_bounded_response(Cursor::new(Vec::<u8>::new()), 64, "0.147.0").unwrap_err(),
            "PROBE_NO_OUTPUT"
        );
        let wrong = br#"{"id":1,"result":{"userAgent":"codex_cli_rs/9.9.9"}}
"#;
        assert_eq!(
            read_bounded_response(Cursor::new(wrong), 4096, "0.147.0").unwrap_err(),
            "PROTOCOL_VERSION_MISMATCH"
        );
    }

    #[test]
    fn collector_timeout_is_exercised_on_the_reader_path() {
        let (sender, receiver) = mpsc::channel();
        let reader = thread::spawn(move || {
            let result =
                read_bounded_response(DelayedEof(StdDuration::from_millis(25)), 64, "0.147.0");
            let _ = sender.send(result);
        });
        assert!(receiver.recv_timeout(StdDuration::from_millis(1)).is_err());
        reader.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn executable_digest_and_native_format_are_verified_before_spawn() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"\x7fELFfixture-native-bytes").unwrap();
        fs::set_permissions(file.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let canonical = fs::canonicalize(file.path()).unwrap();

        let mismatch = executable_options(canonical.clone(), format!("sha256:{}", "0".repeat(64)));
        assert_eq!(
            prepare_executable(&mismatch).err().unwrap(),
            "EXECUTABLE_DIGEST_MISMATCH"
        );

        let mut wrapper = tempfile::NamedTempFile::new().unwrap();
        wrapper.write_all(b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(wrapper.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let wrapper_options = executable_options(
            fs::canonicalize(wrapper.path()).unwrap(),
            format!("sha256:{}", "0".repeat(64)),
        );
        assert_eq!(
            prepare_executable(&wrapper_options).err().unwrap(),
            "EXECUTABLE_NOT_NATIVE"
        );
    }

    #[cfg(unix)]
    #[test]
    fn executable_symlink_path_is_refused_before_spawn() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"\x7fELFfixture-native-bytes").unwrap();
        fs::set_permissions(file.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let link = directory.path().join("codex-link");
        symlink(file.path(), &link).unwrap();
        let options = executable_options(link, format!("sha256:{}", "0".repeat(64)));
        assert_eq!(
            prepare_executable(&options).err().unwrap(),
            "EXECUTABLE_PATH_NOT_CANONICAL"
        );
    }
}

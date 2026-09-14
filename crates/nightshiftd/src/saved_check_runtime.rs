//! Durable owner for one scheduled saved-check evaluation.
//!
//! This module invokes only the enrolled Monitor and NQ roles. It does not
//! schedule a daemon, grant authority, or retry a source read after an
//! indeterminate subprocess transition.

#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::fd::AsRawFd as _;
#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension as _, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

use crate::saved_check_recurrence::{SavedCheckDueRequestV1, SavedCheckScheduleV1};

pub const CONFIG_SCHEMA: &str = "nightshift.saved-check-runtime-config/v1";
pub const RECORD_SCHEMA: &str = "nightshift.saved-check-evaluation/v1";
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_RESULT_BYTES: u64 = 1024 * 1024;
const MAX_PROGRAM_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SavedCheckRuntimeConfigV1 {
    pub schema: String,
    pub monitor_program: PathBuf,
    pub monitor_program_sha256: String,
    pub monitor_project: PathBuf,
    pub monitor_trusted_root: PathBuf,
    pub expected_project: String,
    pub expected_producer: String,
    pub expected_manifest_digest: String,
    pub concern_id: String,
    pub nq_program: PathBuf,
    pub nq_program_sha256: String,
    pub nq_config: PathBuf,
    pub nq_config_sha256: String,
    pub saved_check_target: PathBuf,
    pub definition_reference: String,
    pub definition_digest: String,
    pub source_identity: String,
    pub definition_currentness_seconds: u64,
    pub condition_component: String,
    pub condition_kind: String,
    pub condition_subject: String,
    pub command_timeout_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SavedCheckEvaluationV1 {
    pub schema: String,
    pub evaluation_id: String,
    pub policy_digest: String,
    pub slot_id: String,
    pub config_digest: String,
    pub state: String,
    pub projection_at: Option<String>,
    pub due_request: SavedCheckDueRequestV1,
    pub monitor_inventory: Option<Value>,
    pub monitor_inventory_bytes_hex: Option<String>,
    pub monitor_inventory_sha256: Option<String>,
    pub acquisition_acquired_at_unix_ms: Option<u64>,
    pub source_observed_at: Option<String>,
    pub nq_request_binding: Option<Value>,
    pub nq_result: Option<Value>,
    pub nq_result_bytes_hex: Option<String>,
    pub nq_result_sha256: Option<String>,
    pub condition: Option<Value>,
    pub condition_bytes_hex: Option<String>,
    pub condition_sha256: Option<String>,
    pub assumption: String,
    pub authority: String,
}

impl SavedCheckRuntimeConfigV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != CONFIG_SCHEMA {
            return Err("unsupported saved-check runtime config schema".into());
        }
        for path in [
            &self.monitor_program,
            &self.monitor_project,
            &self.monitor_trusted_root,
            &self.nq_program,
            &self.nq_config,
            &self.saved_check_target,
        ] {
            if !path.is_absolute() {
                return Err("saved-check runtime paths must be absolute".into());
            }
        }
        for value in [
            &self.expected_project,
            &self.expected_producer,
            &self.concern_id,
            &self.definition_reference,
            &self.source_identity,
            &self.condition_component,
            &self.condition_kind,
            &self.condition_subject,
        ] {
            if value.is_empty() || value.len() > 256 || !value.bytes().all(|b| b.is_ascii_graphic())
            {
                return Err("saved-check runtime tokens must be 1..256 visible ASCII bytes".into());
            }
        }
        for digest in [
            &self.monitor_program_sha256,
            &self.expected_manifest_digest,
            &self.nq_program_sha256,
            &self.nq_config_sha256,
            &self.definition_digest,
        ] {
            require_digest(digest)?;
        }
        if !(1..=300).contains(&self.command_timeout_seconds) {
            return Err("command_timeout_seconds must be in 1..=300".into());
        }
        if self.definition_currentness_seconds == 0 {
            return Err("definition_currentness_seconds must be nonzero".into());
        }
        Ok(())
    }
}

pub fn read_config(path: &Path) -> Result<(SavedCheckRuntimeConfigV1, String), String> {
    let bytes = bounded_read(path, MAX_CONFIG_BYTES)?;
    let config: SavedCheckRuntimeConfigV1 = strict_json(&bytes)?;
    let canonical = serde_jcs::to_vec(&config).map_err(|e| e.to_string())?;
    if canonical != bytes {
        return Err("saved-check runtime config must be exact JCS JSON".into());
    }
    config.validate()?;
    Ok((config, sha256(&bytes)))
}

pub struct SavedCheckRuntimeV1 {
    connection: Connection,
}

impl SavedCheckRuntimeV1 {
    pub fn open(path: &Path) -> Result<Self, String> {
        let connection = Connection::open(path).map_err(|e| e.to_string())?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|e| e.to_string())?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS saved_check_evaluations (
               evaluation_id TEXT PRIMARY KEY,
               policy_digest TEXT NOT NULL,
               slot_id TEXT NOT NULL,
               config_digest TEXT NOT NULL,
               state TEXT NOT NULL,
               record_json BLOB NOT NULL,
               CHECK(length(record_json) <= 1048576)
             ) STRICT;",
            )
            .map_err(|e| e.to_string())?;
        Ok(Self { connection })
    }

    pub fn open_read_only(path: &Path) -> Result<Self, String> {
        let connection =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(|e| e.to_string())?;
        let columns: Vec<String> = connection
            .prepare("SELECT name FROM pragma_table_info('saved_check_evaluations') ORDER BY cid")
            .map_err(|e| e.to_string())?
            .query_map([], |row| row.get(0))
            .map_err(|e| e.to_string())?
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())?;
        if columns
            != [
                "evaluation_id",
                "policy_digest",
                "slot_id",
                "config_digest",
                "state",
                "record_json",
            ]
        {
            return Err(
                "saved-check evaluation table is absent or has an unsupported schema".into(),
            );
        }
        Ok(Self { connection })
    }

    pub fn inspect(&self, evaluation_id: &str) -> Result<Option<SavedCheckEvaluationV1>, String> {
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT record_json FROM saved_check_evaluations WHERE evaluation_id=?1",
                [evaluation_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        bytes
            .map(|b| {
                let record: SavedCheckEvaluationV1 = strict_json(&b)?;
                validate_record(&record)?;
                Ok(record)
            })
            .transpose()
    }

    fn open_evaluation(&mut self, record: &SavedCheckEvaluationV1) -> Result<bool, String> {
        let bytes = serde_jcs::to_vec(record).map_err(|e| e.to_string())?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        let existing: Option<Vec<u8>> = tx
            .query_row(
                "SELECT record_json FROM saved_check_evaluations WHERE evaluation_id=?1",
                [&record.evaluation_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if let Some(existing) = existing {
            let prior: SavedCheckEvaluationV1 = strict_json(&existing)?;
            if prior.policy_digest != record.policy_digest
                || prior.slot_id != record.slot_id
                || prior.config_digest != record.config_digest
                || prior.due_request.evaluation_id != record.due_request.evaluation_id
            {
                return Err(
                    "evaluation identity conflicts with retained saved-check material".into(),
                );
            }
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO saved_check_evaluations VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                record.evaluation_id,
                record.policy_digest,
                record.slot_id,
                record.config_digest,
                record.state,
                bytes
            ],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        Ok(true)
    }

    fn transition(&mut self, prior: &str, next: &SavedCheckEvaluationV1) -> Result<bool, String> {
        let bytes = serde_jcs::to_vec(next).map_err(|e| e.to_string())?;
        let changed = self.connection.execute(
            "UPDATE saved_check_evaluations SET state=?1,record_json=?2 WHERE evaluation_id=?3 AND state=?4",
            params![next.state, bytes, next.evaluation_id, prior],
        ).map_err(|e| e.to_string())?;
        Ok(changed == 1)
    }

    pub fn run(
        &mut self,
        config: &SavedCheckRuntimeConfigV1,
        config_digest: &str,
        policy: &SavedCheckScheduleV1,
        scheduler_clock_id: &str,
        at: DateTime<Utc>,
    ) -> Result<SavedCheckEvaluationV1, String> {
        config.validate()?;
        if policy.definition_reference != config.definition_reference
            || policy.definition_digest != config.definition_digest
            || policy.source_identity != config.source_identity
        {
            return Err("schedule policy does not match enrolled saved-check definition".into());
        }
        let selection = policy.select(scheduler_clock_id, at)?;
        let request = selection.request.ok_or("saved-check slot is not due")?;
        let mut record = SavedCheckEvaluationV1 {
            schema: RECORD_SCHEMA.into(), evaluation_id: request.evaluation_id.clone(),
            policy_digest: request.policy_digest.clone(), slot_id: request.slot.slot_id.clone(),
            config_digest: config_digest.into(), state: "selected".into(), projection_at: None, due_request: request,
            monitor_inventory: None, monitor_inventory_bytes_hex: None, monitor_inventory_sha256: None,
            acquisition_acquired_at_unix_ms: None, source_observed_at: None,
            nq_request_binding: None, nq_result: None, nq_result_bytes_hex: None, nq_result_sha256: None,
            condition: None, condition_bytes_hex: None, condition_sha256: None,
            assumption: "operator_enrolled_monitor_observation_and_saved_check_target_refer_to_the_intended_local_source;not_an_atomic_snapshot_proof".into(),
            authority: "none".into(),
        };
        if let Some(existing) = self.inspect(&record.evaluation_id)? {
            // Reuse the same conflict checks as the transactional open before
            // returning a terminal without reopening deployment files.
            if existing.policy_digest != record.policy_digest
                || existing.slot_id != record.slot_id
                || existing.config_digest != record.config_digest
            {
                return Err(
                    "evaluation identity conflicts with retained saved-check material".into(),
                );
            }
            record = existing;
            if record.state == "terminal" {
                return Ok(record);
            }
            return self.resume(config, record);
        }
        verify_definition(config)?;
        if !self.open_evaluation(&record)? {
            record = self
                .inspect(&record.evaluation_id)?
                .ok_or("retained evaluation disappeared")?;
            if record.state == "terminal" {
                return Ok(record);
            }
            return self.resume(config, record);
        }
        record.state = "acquisition_started".into();
        if !self.transition("selected", &record)? {
            return Err("saved-check acquisition launch lost its CAS".into());
        }
        let monitor = run_bounded(
            &config.monitor_program,
            &config.monitor_program_sha256,
            None,
            &[
                "collect".into(),
                config.monitor_project.as_os_str().into(),
                "--trusted-root".into(),
                config.monitor_trusted_root.as_os_str().into(),
                "--allow-exec".into(),
                "--json".into(),
            ],
            config.command_timeout_seconds,
        )?;
        if !monitor.success {
            return Ok(record);
        }
        let inventory: Value = strict_json(&monitor.stdout)?;
        let (acquired, observed) = verify_inventory(config, &inventory)?;
        record.monitor_inventory_sha256 = Some(sha256(&monitor.stdout));
        record.monitor_inventory_bytes_hex = Some(hex(&monitor.stdout));
        record.monitor_inventory = Some(inventory);
        record.acquisition_acquired_at_unix_ms = Some(acquired);
        record.source_observed_at = Some(observed.clone());
        record.nq_request_binding = Some(json!({
            "definition_digest":config.definition_digest,"target_reference":config.saved_check_target,
            "source_identity":config.source_identity,"currentness_seconds":config.definition_currentness_seconds,
            "source_observed_at_assertion":observed
        }));
        record.state = "nq_bound".into();
        if !self.transition("acquisition_started", &record)? {
            return Err("saved-check acquisition retention lost its CAS".into());
        }
        self.resume(config, record)
    }

    fn resume(
        &mut self,
        config: &SavedCheckRuntimeConfigV1,
        mut record: SavedCheckEvaluationV1,
    ) -> Result<SavedCheckEvaluationV1, String> {
        if record.state == "terminal" {
            return Ok(record);
        }
        if record.state == "acquisition_started" {
            return Ok(record);
        }
        if record.state == "result_retained" {
            let bytes = unhex(
                record
                    .nq_result_bytes_hex
                    .as_deref()
                    .ok_or("retained NQ result bytes absent")?,
            )?;
            let value = strict_json(&bytes)?;
            return self.finish(config, record, JsonOutput { value, bytes });
        }
        if record.state == "selected" {
            return Err("selected evaluation has no durable launch disposition".into());
        }
        verify_definition(config)?;
        let result_output = nq_json(
            config,
            &[
                "saved-check",
                "result",
                "--evaluation-id",
                &record.evaluation_id,
            ],
        )?;
        let result = &result_output.value;
        let outcome = result
            .get("outcome")
            .and_then(Value::as_str)
            .ok_or("NQ result lacks outcome")?;
        if outcome == "claimed" {
            require_claimed_indeterminate(result)?;
            return self.retain_claimed(record, result_output);
        }
        if outcome == "missing" {
            if *result
                != json!({"evaluation_id":record.evaluation_id.clone(),"indeterminate":true,"outcome":"missing"})
            {
                return Err("NQ missing result is not the exact supported response".into());
            }
            if record.state == "nq_started" {
                return Ok(record);
            }
            record.state = "nq_started".into();
            if !self.transition("nq_bound", &record)? {
                return Ok(self
                    .inspect(&record.evaluation_id)?
                    .ok_or("evaluation disappeared")?);
            }
            let evaluated = nq_json(
                config,
                &[
                    "saved-check",
                    "evaluate",
                    &config.definition_reference,
                    "--evaluation-id",
                    &record.evaluation_id,
                    "--target",
                    config
                        .saved_check_target
                        .to_str()
                        .ok_or("saved-check target is not UTF-8")?,
                    "--source-observed-at",
                    record
                        .source_observed_at
                        .as_deref()
                        .ok_or("source observation absent")?,
                ],
            );
            if evaluated.is_err() {
                return Ok(record);
            }
            let evaluated = evaluated?;
            if evaluated.value.get("outcome").and_then(Value::as_str) == Some("claimed") {
                return self.retain_claimed(record, evaluated);
            }
            return self.finish(config, record, evaluated);
        }
        self.finish(config, record, result_output)
    }

    fn finish(
        &mut self,
        config: &SavedCheckRuntimeConfigV1,
        mut record: SavedCheckEvaluationV1,
        result: JsonOutput,
    ) -> Result<SavedCheckEvaluationV1, String> {
        verify_nq_result(&record, &result.value)?;
        if record.state != "result_retained" {
            record.nq_result_sha256 = Some(sha256(&result.bytes));
            record.nq_result_bytes_hex = Some(hex(&result.bytes));
            record.nq_result = Some(result.value.clone());
            record.projection_at = Some(Utc::now().to_rfc3339());
            let prior = record.state.clone();
            record.state = "result_retained".into();
            if !self.transition(&prior, &record)? {
                let retained = self
                    .inspect(&record.evaluation_id)?
                    .ok_or("result custody disappeared")?;
                if retained.state == "terminal" {
                    return Ok(retained);
                }
                let bytes = unhex(
                    retained
                        .nq_result_bytes_hex
                        .as_deref()
                        .ok_or("retained result bytes absent")?,
                )?;
                return self.finish(
                    config,
                    retained,
                    JsonOutput {
                        value: strict_json(&bytes)?,
                        bytes,
                    },
                );
            }
        }
        let at_text = record
            .projection_at
            .clone()
            .ok_or("result projection time absent")?;
        let condition = nq_json(
            config,
            &[
                "saved-check",
                "condition",
                "--evaluation-id",
                &record.evaluation_id,
                "--component",
                &config.condition_component,
                "--kind",
                &config.condition_kind,
                "--subject",
                &config.condition_subject,
                "--at",
                &at_text,
            ],
        )?;
        if condition.value.get("schema").and_then(Value::as_str)
            != Some("nq.saved-check-condition/v1")
            || condition.value.get("evaluation_id").and_then(Value::as_str)
                != Some(&record.evaluation_id)
        {
            return Err("NQ condition projection does not bind the evaluation".into());
        }
        let binding = record
            .nq_request_binding
            .as_ref()
            .ok_or("retained NQ request binding absent")?;
        let expected_mapping = json!({
            "component":config.condition_component,"kind":config.condition_kind,
            "subject":config.condition_subject,"at":at_text,"mapping_owner":"caller"
        });
        if condition.value.pointer("/original_result/outcome") != result.value.get("outcome")
            || condition.value.pointer("/original_result/detail") != result.value.get("detail")
            || condition.value.get("caller_mapping") != Some(&expected_mapping)
            || condition.value.pointer("/source_assertion/identity")
                != binding.get("source_identity")
            || condition.value.pointer("/source_assertion/observed_at")
                != binding.get("source_observed_at_assertion")
            || condition
                .value
                .pointer("/source_assertion/currentness_seconds")
                != binding.get("currentness_seconds")
        {
            return Err("NQ condition projection differs from retained result or mapping".into());
        }
        record.condition_sha256 = Some(sha256(&condition.bytes));
        record.condition_bytes_hex = Some(hex(&condition.bytes));
        record.condition = Some(condition.value);
        record.state = "terminal".into();
        if !self.transition("result_retained", &record)? {
            return Ok(self
                .inspect(&record.evaluation_id)?
                .ok_or("terminal evaluation disappeared")?);
        }
        Ok(record)
    }

    fn retain_claimed(
        &mut self,
        mut record: SavedCheckEvaluationV1,
        result: JsonOutput,
    ) -> Result<SavedCheckEvaluationV1, String> {
        require_claimed_indeterminate(&result.value)?;
        verify_nq_result(&record, &result.value)?;
        record.nq_result_sha256 = Some(sha256(&result.bytes));
        record.nq_result_bytes_hex = Some(hex(&result.bytes));
        record.nq_result = Some(result.value);
        let prior = record.state.clone();
        record.state = "nq_started".into();
        if prior == "nq_started" {
            if !self.transition("nq_started", &record)? {
                return self
                    .inspect(&record.evaluation_id)?
                    .ok_or("claimed evaluation disappeared");
            }
        } else if !self.transition(&prior, &record)? {
            return self
                .inspect(&record.evaluation_id)?
                .ok_or("claimed evaluation disappeared");
        }
        Ok(record)
    }
}

struct Output {
    success: bool,
    stdout: Vec<u8>,
}

fn run_bounded(
    program: &Path,
    program_digest: &str,
    config: Option<(&Path, &str)>,
    args: &[std::ffi::OsString],
    seconds: u64,
) -> Result<Output, String> {
    let executable = capture_sealed(program, program_digest, MAX_PROGRAM_BYTES, true)?;
    let config_capture = config
        .map(|(path, digest)| capture_sealed(path, digest, MAX_CONFIG_BYTES, false))
        .transpose()?;
    let executable_path = format!("/proc/self/fd/{}", executable.as_raw_fd());
    let config_path = config_capture
        .as_ref()
        .map(|file| std::ffi::OsString::from(format!("/proc/self/fd/{}", file.as_raw_fd())));
    let args: Vec<_> = args
        .iter()
        .map(|arg| {
            if config.is_some_and(|(path, _)| arg == path.as_os_str()) {
                config_path.clone().expect("captured config path")
            } else {
                arg.clone()
            }
        })
        .collect();
    let stdout = tempfile::tempfile().map_err(|e| e.to_string())?;
    let stderr = tempfile::tempfile().map_err(|e| e.to_string())?;
    let mut child = Command::new(executable_path)
        .args(args)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout.try_clone().map_err(|e| e.to_string())?))
        .stderr(Stdio::from(stderr.try_clone().map_err(|e| e.to_string())?))
        .spawn()
        .map_err(|e| format!("cannot start saved-check role: {e}"))?;
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        if stdout.metadata().map_err(|e| e.to_string())?.len() > MAX_RESULT_BYTES
            || stderr.metadata().map_err(|e| e.to_string())?.len() > MAX_RESULT_BYTES
        {
            kill_process_group(child.id());
            let _ = child.wait();
            return Err("saved-check role exceeded its output bound".into());
        }
        if Instant::now() >= deadline {
            kill_process_group(child.id());
            let _ = child.wait();
            return Err("saved-check role exceeded its bounded runtime".into());
        }
        thread::sleep(Duration::from_millis(10));
    };
    kill_process_group(child.id());
    // Enforce the same limit after the final write/exit transition.
    let _ = read_file(stderr, MAX_RESULT_BYTES)?;
    Ok(Output {
        success: status.success(),
        stdout: read_file(stdout, MAX_RESULT_BYTES)?,
    })
}

struct JsonOutput {
    value: Value,
    bytes: Vec<u8>,
}

fn nq_json(config: &SavedCheckRuntimeConfigV1, tail: &[&str]) -> Result<JsonOutput, String> {
    let mut args = vec![
        "--config".into(),
        config.nq_config.as_os_str().into(),
        "--json".into(),
    ];
    args.extend(
        tail.iter()
            .map(|argument| std::ffi::OsString::from(*argument)),
    );
    let output = run_bounded(
        &config.nq_program,
        &config.nq_program_sha256,
        Some((&config.nq_config, &config.nq_config_sha256)),
        &args,
        config.command_timeout_seconds,
    )?;
    if !output.success {
        return Err("configured NQ command refused".into());
    }
    Ok(JsonOutput {
        value: strict_json(&output.stdout)?,
        bytes: output.stdout,
    })
}

fn verify_definition(config: &SavedCheckRuntimeConfigV1) -> Result<(), String> {
    let value = nq_json(
        config,
        &["saved-check", "inspect", &config.definition_reference],
    )?;
    if value.value.get("reference").and_then(Value::as_str) != Some(&config.definition_reference)
        || value.value.get("definition_digest").and_then(Value::as_str)
            != Some(&config.definition_digest)
        || value
            .value
            .pointer("/definition/source_identity")
            .and_then(Value::as_str)
            != Some(&config.source_identity)
        || value
            .value
            .pointer("/definition/currentness_seconds")
            .and_then(Value::as_u64)
            != Some(config.definition_currentness_seconds)
    {
        return Err("installed NQ definition does not match runtime enrollment".into());
    }
    Ok(())
}

fn verify_nq_result(record: &SavedCheckEvaluationV1, result: &Value) -> Result<(), String> {
    if result.get("evaluation_id").and_then(Value::as_str) != Some(&record.evaluation_id) {
        return Err("NQ result evaluation identity mismatch".into());
    }
    let outcome = result
        .get("outcome")
        .and_then(Value::as_str)
        .ok_or("NQ result outcome absent")?;
    if !matches!(outcome, "passed" | "failed" | "refused" | "claimed") {
        return Err("unsupported NQ saved-check outcome".into());
    }
    let binding = result
        .pointer("/detail/binding")
        .ok_or("NQ result binding absent")?;
    if Some(binding) != record.nq_request_binding.as_ref() {
        return Err("NQ result binding differs from retained request".into());
    }
    Ok(())
}

fn require_claimed_indeterminate(result: &Value) -> Result<(), String> {
    if result.get("outcome").and_then(Value::as_str) != Some("claimed")
        || result.get("indeterminate").and_then(Value::as_bool) != Some(true)
    {
        return Err("claimed NQ result must be explicitly indeterminate".into());
    }
    Ok(())
}

fn validate_record(record: &SavedCheckEvaluationV1) -> Result<(), String> {
    if record.schema != RECORD_SCHEMA
        || record.evaluation_id != record.due_request.evaluation_id
        || record.policy_digest != record.due_request.policy_digest
        || record.slot_id != record.due_request.slot.slot_id
        || record.authority != "none"
        || !matches!(
            record.state.as_str(),
            "selected"
                | "acquisition_started"
                | "nq_bound"
                | "nq_started"
                | "result_retained"
                | "terminal"
        )
    {
        return Err("retained saved-check evaluation violates its identity law".into());
    }
    require_digest(&record.config_digest)?;
    if record.state == "nq_bound" || record.state == "nq_started" || record.state == "terminal" {
        if record.monitor_inventory.is_none()
            || record.monitor_inventory_bytes_hex.is_none()
            || record.monitor_inventory_sha256.is_none()
            || record.source_observed_at.is_none()
            || record.nq_request_binding.is_none()
        {
            return Err("retained saved-check evaluation omits acquired material".into());
        }
        let inventory_bytes = unhex(record.monitor_inventory_bytes_hex.as_deref().unwrap())?;
        if sha256(&inventory_bytes) != *record.monitor_inventory_sha256.as_ref().unwrap()
            || strict_json::<Value>(&inventory_bytes)?
                != *record.monitor_inventory.as_ref().unwrap()
        {
            return Err("retained Monitor inventory bytes do not reproduce".into());
        }
    }
    if record.state == "terminal"
        && (record.nq_result.is_none()
            || record.nq_result_bytes_hex.is_none()
            || record.nq_result_sha256.is_none()
            || record.condition.is_none()
            || record.condition_bytes_hex.is_none()
            || record.condition_sha256.is_none())
    {
        return Err("retained terminal saved-check evaluation is incomplete".into());
    }
    if matches!(record.state.as_str(), "result_retained" | "terminal")
        && record.projection_at.is_none()
    {
        return Err("retained saved-check result omits its projection coordinate".into());
    }
    if record.state == "terminal" {
        let result_bytes = unhex(record.nq_result_bytes_hex.as_deref().unwrap())?;
        if sha256(&result_bytes) != *record.nq_result_sha256.as_ref().unwrap()
            || strict_json::<Value>(&result_bytes)? != *record.nq_result.as_ref().unwrap()
        {
            return Err("retained NQ result bytes do not reproduce".into());
        }
        let condition_bytes = unhex(record.condition_bytes_hex.as_deref().unwrap())?;
        if sha256(&condition_bytes) != *record.condition_sha256.as_ref().unwrap()
            || strict_json::<Value>(&condition_bytes)? != *record.condition.as_ref().unwrap()
        {
            return Err("retained NQ condition bytes do not reproduce".into());
        }
    }
    Ok(())
}

fn verify_inventory(
    config: &SavedCheckRuntimeConfigV1,
    value: &Value,
) -> Result<(u64, String), String> {
    if value.get("schema").and_then(Value::as_str)
        != Some("monitor.project-observation.inventory/v1")
        || value.get("project").and_then(Value::as_str) != Some(&config.expected_project)
        || value
            .pointer("/acquisition/disposition")
            .and_then(Value::as_str)
            != Some("ACQUIRED_AND_VALIDATED")
        || value
            .pointer("/acquisition/producer")
            .and_then(Value::as_str)
            != Some(&config.expected_producer)
        || value
            .pointer("/acquisition/manifest_digest")
            .and_then(Value::as_str)
            != Some(&config.expected_manifest_digest)
    {
        return Err("Monitor inventory does not match saved-check enrollment".into());
    }
    let acquired = value
        .pointer("/acquisition/acquired_at_unix_ms")
        .and_then(Value::as_u64)
        .ok_or("Monitor acquisition time absent")?;
    let concerns = value
        .get("concerns")
        .and_then(Value::as_array)
        .ok_or("Monitor concerns absent")?;
    let concern = concerns
        .iter()
        .find(|v| v.pointer("/declaration/id").and_then(Value::as_str) == Some(&config.concern_id))
        .ok_or("enrolled Monitor concern absent")?;
    if concern.get("monitor_state").and_then(Value::as_str) != Some("OBSERVED")
        || concern
            .pointer("/observation/observation_present")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err("enrolled Monitor concern is not observed".into());
    }
    let observed = concern
        .pointer("/observation/observed_at")
        .and_then(Value::as_str)
        .ok_or("Monitor observation timestamp absent")?;
    DateTime::parse_from_rfc3339(observed)
        .map_err(|_| "Monitor observation timestamp is invalid")?;
    Ok((acquired, observed.into()))
}

fn strict_json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let value = T::deserialize(&mut de).map_err(|e| e.to_string())?;
    de.end().map_err(|e| e.to_string())?;
    Ok(value)
}
fn bounded_read(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    let file = open_bounded_descriptor(path, max, false)?;
    read_file(file, max)
}
fn read_file(mut file: File, max: u64) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    let mut out = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut out)
        .map_err(|e| e.to_string())?;
    if out.len() as u64 > max {
        return Err("saved-check input exceeds byte bound".into());
    }
    Ok(out)
}
#[cfg(target_os = "linux")]
fn capture_sealed(path: &Path, expected: &str, max: u64, executable: bool) -> Result<File, String> {
    let mut source = open_bounded_descriptor(path, max, executable)?;
    let name = CString::new("nightshift-saved-check").map_err(|e| e.to_string())?;
    // SAFETY: `name` is a live NUL-terminated string; the returned descriptor
    // is checked before it is uniquely adopted by `File`.
    let descriptor = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_ALLOW_SEALING) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: ownership of the successful fresh descriptor transfers exactly
    // once to this File.
    let mut captured = unsafe { File::from_raw_fd(descriptor) };
    let mut hasher = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = source.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        copied = copied
            .checked_add(u64::try_from(count).map_err(|e| e.to_string())?)
            .ok_or("deployment input length overflow")?;
        if copied > max {
            return Err("saved-check deployment input exceeds its bound".into());
        }
        hasher.update(&buffer[..count]);
        captured
            .write_all(&buffer[..count])
            .map_err(|e| e.to_string())?;
    }
    let actual = format!("sha256:{:x}", hasher.finalize());
    if actual != expected {
        return Err("saved-check runtime deployment digest mismatch".into());
    }
    captured.flush().map_err(|e| e.to_string())?;
    if executable {
        // SAFETY: fchmod operates on the owned live descriptor.
        if unsafe { libc::fchmod(captured.as_raw_fd(), 0o500) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL;
    // SAFETY: fcntl operates on the owned live memfd and uses the documented
    // F_ADD_SEALS integer argument.
    if unsafe { libc::fcntl(captured.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    captured
        .seek(SeekFrom::Start(0))
        .map_err(|e| e.to_string())?;
    Ok(captured)
}

#[cfg(not(target_os = "linux"))]
fn capture_sealed(
    _path: &Path,
    _expected: &str,
    _max: u64,
    _executable: bool,
) -> Result<File, String> {
    Err("saved-check sealed runtime is supported only on Linux".into())
}

fn open_bounded_descriptor(path: &Path, max: u64, executable: bool) -> Result<File, String> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.file_type().is_file() || metadata.len() > max {
        return Err("saved-check deployment input must be a bounded regular file".into());
    }
    if executable && metadata.permissions().mode() & 0o111 == 0 {
        return Err("saved-check enrolled program is not executable".into());
    }
    Ok(file)
}

fn kill_process_group(pid: u32) {
    if let Ok(pid) = i32::try_from(pid) {
        // SAFETY: a negative pid addresses only the child-created process
        // group; SIGKILL requires no borrowed memory or callback.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
}
fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn unhex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 || value.len() > 2_097_152 {
        return Err("retained hexadecimal bytes violate their bound".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).map_err(|e| e.to_string()))
        .collect()
}
fn require_digest(value: &str) -> Result<(), String> {
    let h = value.strip_prefix("sha256:").unwrap_or("");
    if h.len() != 64
        || !h
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("expected lowercase SHA-256 digest".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_store::{RecurrenceSlotV1, RecurrenceTriggerV1};
    use crate::saved_check_recurrence::{POLICY_SCHEMA, REQUEST_SCHEMA};
    use tempfile::TempDir;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }
    fn config(root: &Path) -> SavedCheckRuntimeConfigV1 {
        SavedCheckRuntimeConfigV1 {
            schema: CONFIG_SCHEMA.into(),
            monitor_program: root.join("monitor"),
            monitor_program_sha256: digest('a'),
            monitor_project: root.join("project"),
            monitor_trusted_root: root.into(),
            expected_project: "project-a".into(),
            expected_producer: "project-a.status".into(),
            expected_manifest_digest: digest('b'),
            concern_id: "queue.depth".into(),
            nq_program: root.join("nq"),
            nq_program_sha256: digest('c'),
            nq_config: root.join("nq.json"),
            nq_config_sha256: digest('d'),
            saved_check_target: root.join("source.sqlite"),
            definition_reference: "capacity".into(),
            definition_digest: digest('e'),
            source_identity: "project-a.sqlite".into(),
            definition_currentness_seconds: 300,
            condition_component: "queue".into(),
            condition_kind: "backlog".into(),
            condition_subject: "local".into(),
            command_timeout_seconds: 2,
        }
    }

    fn request() -> SavedCheckDueRequestV1 {
        let due = DateTime::parse_from_rfc3339("2026-09-14T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let slot = RecurrenceSlotV1::new(
            "p".into(),
            digest('1'),
            "s".into(),
            "scope".into(),
            "clock".into(),
            due,
            due + chrono::Duration::seconds(5),
            0,
            RecurrenceTriggerV1::Scheduled,
            None,
        )
        .unwrap();
        SavedCheckDueRequestV1 {
            schema: REQUEST_SCHEMA.into(),
            policy_digest: digest('1'),
            evaluation_id: digest('2'),
            slot,
            definition_reference: "capacity".into(),
            definition_digest: digest('e'),
            source_identity: "project-a.sqlite".into(),
        }
    }

    fn record() -> SavedCheckEvaluationV1 {
        let request = request();
        SavedCheckEvaluationV1 {
            schema: RECORD_SCHEMA.into(),
            evaluation_id: request.evaluation_id.clone(),
            policy_digest: request.policy_digest.clone(),
            slot_id: request.slot.slot_id.clone(),
            config_digest: digest('3'),
            state: "selected".into(),
            projection_at: Some("2026-09-14T00:00:02Z".into()),
            due_request: request,
            monitor_inventory: None,
            monitor_inventory_bytes_hex: None,
            monitor_inventory_sha256: None,
            acquisition_acquired_at_unix_ms: None,
            source_observed_at: None,
            nq_request_binding: None,
            nq_result: None,
            nq_result_bytes_hex: None,
            nq_result_sha256: None,
            condition: None,
            condition_bytes_hex: None,
            condition_sha256: None,
            assumption: "fixture assumption".into(),
            authority: "none".into(),
        }
    }

    #[test]
    fn exact_evaluation_open_is_idempotent_and_conflict_refuses() {
        let root = TempDir::new().unwrap();
        let mut store = SavedCheckRuntimeV1::open(&root.path().join("nightshift.sqlite")).unwrap();
        let record = record();
        assert!(store.open_evaluation(&record).unwrap());
        assert!(!store.open_evaluation(&record).unwrap());
        let mut changed = record;
        changed.config_digest = digest('4');
        assert!(store.open_evaluation(&changed).is_err());
    }

    #[test]
    fn read_only_inspection_does_not_create_an_absent_store() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("absent.sqlite");
        assert!(SavedCheckRuntimeV1::open_read_only(&path).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn monitor_observation_time_is_selected_not_acquisition_time() {
        let root = TempDir::new().unwrap();
        let config = config(root.path());
        let inventory = json!({"schema":"monitor.project-observation.inventory/v1","project":"project-a","acquisition":{"disposition":"ACQUIRED_AND_VALIDATED","acquired_at_unix_ms":9000,"producer":"project-a.status","manifest_digest":digest('b')},"concerns":[{"declaration":{"id":"queue.depth"},"monitor_state":"OBSERVED","observation":{"observation_present":true,"observed_at":"2026-09-14T00:00:01Z"}}]});
        let (acquired, observed) = verify_inventory(&config, &inventory).unwrap();
        assert_eq!(acquired, 9000);
        assert_eq!(observed, "2026-09-14T00:00:01Z");
        let mut wrong = inventory;
        wrong["concerns"][0]["monitor_state"] = json!("MISSING");
        assert!(verify_inventory(&config, &wrong).is_err());
    }

    #[test]
    fn result_must_reproduce_retained_nq_binding() {
        let mut record = record();
        record.nq_request_binding = Some(
            json!({"definition_digest":digest('e'),"target_reference":"/source.sqlite","source_identity":"project-a.sqlite","currentness_seconds":300,"source_observed_at_assertion":"2026-09-14T00:00:01Z"}),
        );
        let result = json!({"evaluation_id":record.evaluation_id.clone(),"outcome":"passed","detail":{"binding":record.nq_request_binding.clone()}});
        assert!(verify_nq_result(&record, &result).is_ok());
        let mut wrong = result;
        wrong["detail"]["binding"]["source_identity"] = json!("other");
        assert!(verify_nq_result(&record, &wrong).is_err());
        assert!(
            require_claimed_indeterminate(&json!({"outcome":"claimed","indeterminate":true}))
                .is_ok()
        );
        assert!(
            require_claimed_indeterminate(&json!({"outcome":"claimed","indeterminate":false}))
                .is_err()
        );
    }

    #[test]
    fn policy_definition_identity_is_part_of_selection() {
        let policy = SavedCheckScheduleV1 {
            schema: POLICY_SCHEMA.into(),
            policy_id: "p".into(),
            configuration_version: "1".into(),
            definition_reference: "capacity".into(),
            definition_digest: digest('e'),
            source_identity: "project-a.sqlite".into(),
            subject_id: "s".into(),
            scope_id: "scope".into(),
            scheduler_clock_id: "clock".into(),
            epoch: DateTime::parse_from_rfc3339("2026-09-14T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            interval_seconds: 60,
            admissible_delay_seconds: 5,
        };
        assert_eq!(
            policy
                .select("clock", policy.epoch)
                .unwrap()
                .request
                .unwrap()
                .definition_digest,
            digest('e')
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_role_timeout_does_not_wait_for_pipe_closure() {
        let root = TempDir::new().unwrap();
        let program = root.path().join("nonterminating-role");
        fs::write(&program, b"#!/bin/sh\nwhile :; do :; done\n").unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
        let started = Instant::now();
        let expected = sha256(&fs::read(&program).unwrap());
        assert!(run_bounded(&program, &expected, None, &[], 1).is_err());
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sealed_capture_is_unchanged_by_pathname_content_mutation() {
        let root = TempDir::new().unwrap();
        let program = root.path().join("role");
        let original = b"#!/bin/sh\nprintf original\n";
        fs::write(&program, original).unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
        let captured = capture_sealed(&program, &sha256(original), 4096, true).unwrap();
        fs::write(&program, b"#!/bin/sh\nprintf changed\n").unwrap();
        let output = Command::new(format!("/proc/self/fd/{}", captured.as_raw_fd()))
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"original");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn launched_role_reads_captured_config_not_replaced_pathname() {
        let root = TempDir::new().unwrap();
        let program = root.path().join("role");
        let config = root.path().join("config");
        fs::write(&program, b"#!/bin/sh\ncat \"$1\"\n").unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&config, b"original").unwrap();
        let captured = capture_sealed(&config, &sha256(b"original"), 4096, false).unwrap();
        fs::write(&config, b"replacement").unwrap();
        let output = Command::new(&program)
            .arg(format!("/proc/self/fd/{}", captured.as_raw_fd()))
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"original");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn completed_role_cleans_descendants_in_its_process_group() {
        let root = TempDir::new().unwrap();
        let marker = root.path().join("descendant-ran");
        let program = root.path().join("role");
        fs::write(
            &program,
            format!(
                "#!/bin/sh\n(sleep 1; touch {}) &\nexit 0\n",
                marker.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
        let expected = sha256(&fs::read(&program).unwrap());
        assert!(
            run_bounded(&program, &expected, None, &[], 2)
                .unwrap()
                .success
        );
        thread::sleep(Duration::from_millis(1200));
        assert!(!marker.exists());
    }
}

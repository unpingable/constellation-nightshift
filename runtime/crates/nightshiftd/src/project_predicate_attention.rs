//! Generic, operator-governed attention over verified Pulse project-predicate receipts.
//!
//! This module does not evaluate project predicates, support independence, or
//! primary/support freshness. Pulse owns those decisions. Nightshift verifies
//! the exact Pulse receipt by replay and applies one closed recurrence policy
//! to a durable history of distinct upstream evidence occurrences.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rusqlite::{params, Connection, OptionalExtension as _, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const POLICY_SCHEMA_V1: &str = "nightshift.project-predicate-attention-policy/v1";
pub const EVENT_SCHEMA_V1: &str = "nightshift.project-predicate-attention-event/v1";
pub const RECEIPT_SCHEMA_V1: &str = "nightshift.project-predicate-attention/v1";
pub const BUNDLE_SCHEMA_V1: &str = "nightshift.project-predicate-attention-replay-bundle/v1";
pub const REPLAY_SCHEMA_V1: &str = "nightshift.project-predicate-attention-replay/v1";
pub const INGEST_SCHEMA_V1: &str = "nightshift.project-predicate-attention-ingest/v1";
pub const PULSE_RECEIPT_SCHEMA_V1: &str = "pulse.project-predicate-qualified-support/v1";
pub const PULSE_REPLAY_SCHEMA_V1: &str = "pulse.project-predicate-support-replay/v1";

const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EXECUTABLE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_VERIFIER_OUTPUT_BYTES: u64 = 256 * 1024;
const VERIFIER_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionPolicyV1 {
    pub schema: String,
    pub policy_id: String,
    pub policy_digest: String,
    pub target: AttentionTargetV1,
    pub pulse_verifier_executable_digest: String,
    pub trigger: AttentionTriggerV1,
    pub recurrence: RecurrencePolicyV1,
    pub reset: ResetPolicyV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionTargetV1 {
    pub project: String,
    pub concern: String,
    pub question: String,
    pub declaration_profile: String,
    pub predicate_profile: String,
    pub nq_catalog_digest: String,
    pub nq_profile_digest: String,
    pub nq_input_schema_digest: String,
    pub pulse_support_policy_id: String,
    pub pulse_support_policy_digest: String,
    pub subject_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum AttentionTriggerV1 {
    /// The operator explicitly declares that a current, independently
    /// supported positive proposition is attention-worthy.
    PropositionAttention,
    /// The operator explicitly selects Pulse failure dispositions whose
    /// recurrence constitutes loss-of-assurance attention.
    AssuranceAttention {
        dispositions: Vec<PulseDispositionV1>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecurrencePolicyV1 {
    pub required_distinct_occurrences: u32,
    pub within_seconds: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResetPolicyV1 {
    HorizonExpiry,
    SupportedCurrent,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PulseDispositionV1 {
    SupportedCurrent,
    NqReceiptInvalid,
    MissingSupport,
    SupportProducerFailed,
    SupportEvidenceInvalid,
    IdentityMismatch,
    IndependenceNotQualified,
    PrimaryStale,
    SupportStale,
    SkewExceeded,
    Contradictory,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PulseQualifiedSupportReceiptV1 {
    pub schema: String,
    pub receipt_digest: String,
    pub policy_id: String,
    pub policy_digest: String,
    pub project: String,
    pub concern: String,
    pub question: String,
    pub declaration_profile: String,
    pub predicate_profile: String,
    pub nq_catalog_digest: String,
    pub nq_profile_digest: String,
    pub nq_input_schema_digest: String,
    pub nq_receipt_digest: String,
    pub nq_verifier_executable_digest: String,
    pub primary_observed_at: Option<String>,
    pub support_evidence_id: Option<String>,
    pub support_evidence_digest: Option<String>,
    pub support_observed_at: Option<String>,
    pub support_producer_id: Option<String>,
    pub support_source_id: Option<String>,
    pub support_vantage_id: Option<String>,
    pub subject_id: String,
    pub qualification_at: String,
    pub current_until_unix_ms: Option<i64>,
    pub primary_support_skew_ms: Option<u64>,
    pub independence_basis: String,
    pub disposition: PulseDispositionV1,
    pub detail: String,
    pub validated: Vec<String>,
    pub not_validated: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PulseReplayResultV1 {
    pub schema: String,
    pub matches: bool,
    pub expected_receipt_digest: String,
    pub recomputed_receipt_digest: String,
}

#[derive(Clone, Debug)]
pub struct PulseReplayInputsV1 {
    pub pulse_executable: PathBuf,
    pub pulse_policy: PathBuf,
    pub nq_executable: PathBuf,
    pub nq_receipt: PathBuf,
    pub inventory: PathBuf,
    pub catalog: PathBuf,
    pub support_evidence: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionEventV1 {
    pub schema: String,
    pub event_id: String,
    pub policy_digest: String,
    pub recurrence_id: String,
    pub occurrence_at: String,
    pub pulse_receipt: PulseQualifiedSupportReceiptV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IngestDispositionV1 {
    Accepted,
    DuplicateEvidenceOccurrence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IngestResultV1 {
    pub schema: String,
    pub disposition: IngestDispositionV1,
    pub policy_digest: String,
    pub event_id: String,
    pub recurrence_id: String,
    pub pulse_receipt_digest: String,
    pub history_event_count: u64,
    pub history_head_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttentionDispositionV1 {
    NoAttention,
    WaitingForRecurrence,
    AttentionRequired,
    InputNotCurrent,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttentionReasonClassV1 {
    None,
    PropositionAttention,
    AssuranceAttention,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionReceiptV1 {
    pub schema: String,
    pub receipt_digest: String,
    pub policy_id: String,
    pub policy_digest: String,
    pub project: String,
    pub concern: String,
    pub question: String,
    pub declaration_profile: String,
    pub predicate_profile: String,
    pub nq_catalog_digest: String,
    pub nq_profile_digest: String,
    pub nq_input_schema_digest: String,
    pub pulse_support_policy_id: String,
    pub pulse_support_policy_digest: String,
    pub subject_id: String,
    pub evaluated_at: String,
    pub window_start_inclusive: String,
    pub window_end_inclusive: String,
    pub required_distinct_occurrences: u32,
    pub qualifying_distinct_occurrences: u32,
    pub qualifying_event_ids: Vec<String>,
    pub qualifying_recurrence_ids: Vec<String>,
    pub pulse_receipt_digests: Vec<String>,
    pub upstream_dispositions: Vec<PulseDispositionV1>,
    pub history_digest: String,
    pub attention_reason_class: AttentionReasonClassV1,
    pub disposition: AttentionDispositionV1,
    pub detail: String,
    pub recurrence_basis: String,
    pub currentness_basis: String,
    pub reset_basis: String,
    pub validated: Vec<String>,
    pub not_validated: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionReplayBundleV1 {
    pub schema: String,
    pub policy: AttentionPolicyV1,
    pub history: Vec<AttentionEventV1>,
    pub receipt: AttentionReceiptV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionReplayResultV1 {
    pub schema: String,
    pub matches: bool,
    pub expected_receipt_digest: String,
    pub recomputed_receipt_digest: String,
}

impl AttentionPolicyV1 {
    pub fn seal(&mut self) -> Result<(), String> {
        self.policy_digest = digest_without_field(self, "policy_digest")?;
        self.validate()
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != POLICY_SCHEMA_V1 {
            return Err(format!(
                "unsupported attention policy schema {}",
                self.schema
            ));
        }
        for (name, value) in [
            ("policy_id", self.policy_id.as_str()),
            ("project", self.target.project.as_str()),
            ("concern", self.target.concern.as_str()),
            ("question", self.target.question.as_str()),
            (
                "declaration_profile",
                self.target.declaration_profile.as_str(),
            ),
            ("predicate_profile", self.target.predicate_profile.as_str()),
            (
                "pulse_support_policy_id",
                self.target.pulse_support_policy_id.as_str(),
            ),
            ("subject_id", self.target.subject_id.as_str()),
        ] {
            require_token(name, value)?;
        }
        for (name, value) in [
            ("policy_digest", self.policy_digest.as_str()),
            ("nq_catalog_digest", self.target.nq_catalog_digest.as_str()),
            ("nq_profile_digest", self.target.nq_profile_digest.as_str()),
            (
                "nq_input_schema_digest",
                self.target.nq_input_schema_digest.as_str(),
            ),
            (
                "pulse_support_policy_digest",
                self.target.pulse_support_policy_digest.as_str(),
            ),
            (
                "pulse_verifier_executable_digest",
                self.pulse_verifier_executable_digest.as_str(),
            ),
        ] {
            require_digest(name, value)?;
        }
        if self.recurrence.required_distinct_occurrences == 0 || self.recurrence.within_seconds == 0
        {
            return Err("recurrence count and horizon must be nonzero".into());
        }
        match &self.trigger {
            AttentionTriggerV1::PropositionAttention => {
                if self.reset != ResetPolicyV1::HorizonExpiry {
                    return Err("proposition attention v1 resets only by governed horizon/currentness expiry".into());
                }
            }
            AttentionTriggerV1::AssuranceAttention { dispositions } => {
                if dispositions.is_empty() {
                    return Err(
                        "assurance attention requires at least one selected Pulse disposition"
                            .into(),
                    );
                }
                let mut ordered = dispositions.clone();
                ordered.sort();
                ordered.dedup();
                if &ordered != dispositions {
                    return Err("assurance dispositions must be strictly ordered and unique".into());
                }
                if dispositions.contains(&PulseDispositionV1::SupportedCurrent) {
                    return Err("SUPPORTED_CURRENT is not an assurance-failure disposition".into());
                }
            }
        }
        if self.policy_digest != digest_without_field(self, "policy_digest")? {
            return Err("attention policy digest does not bind its exact content".into());
        }
        Ok(())
    }
}

impl PulseQualifiedSupportReceiptV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != PULSE_RECEIPT_SCHEMA_V1 {
            return Err(format!("unsupported Pulse receipt schema {}", self.schema));
        }
        for (name, value) in [
            ("receipt_digest", self.receipt_digest.as_str()),
            ("policy_digest", self.policy_digest.as_str()),
            ("nq_catalog_digest", self.nq_catalog_digest.as_str()),
            ("nq_profile_digest", self.nq_profile_digest.as_str()),
            (
                "nq_input_schema_digest",
                self.nq_input_schema_digest.as_str(),
            ),
            ("nq_receipt_digest", self.nq_receipt_digest.as_str()),
            (
                "nq_verifier_executable_digest",
                self.nq_verifier_executable_digest.as_str(),
            ),
        ] {
            require_digest(name, value)?;
        }
        for (name, value) in [
            ("policy_id", self.policy_id.as_str()),
            ("project", self.project.as_str()),
            ("concern", self.concern.as_str()),
            ("question", self.question.as_str()),
            ("declaration_profile", self.declaration_profile.as_str()),
            ("predicate_profile", self.predicate_profile.as_str()),
            ("subject_id", self.subject_id.as_str()),
            ("qualification_at", self.qualification_at.as_str()),
            ("independence_basis", self.independence_basis.as_str()),
        ] {
            require_token(name, value)?;
        }
        parse_time(&self.qualification_at)?;
        for value in [&self.primary_observed_at, &self.support_observed_at]
            .into_iter()
            .flatten()
        {
            parse_time(value)?;
        }
        for value in [&self.support_evidence_id, &self.support_evidence_digest]
            .into_iter()
            .flatten()
        {
            require_digest("support evidence digest", value)?;
        }
        if self.disposition == PulseDispositionV1::SupportedCurrent {
            let deadline = self.current_until_unix_ms.ok_or_else(|| {
                "SUPPORTED_CURRENT Pulse receipt lacks its exclusive currentness bound".to_string()
            })?;
            if self.primary_observed_at.is_none()
                || self.support_observed_at.is_none()
                || self.support_evidence_id.is_none()
                || self.support_evidence_digest.is_none()
            {
                return Err(
                    "SUPPORTED_CURRENT Pulse receipt lacks exact evidence occurrences".into(),
                );
            }
            let qualified_at = unix_ms(parse_time(&self.qualification_at)?)?;
            if deadline <= qualified_at {
                return Err("SUPPORTED_CURRENT Pulse deadline is not after qualification".into());
            }
        }
        if self.receipt_digest != digest_without_field(self, "receipt_digest")? {
            return Err("Pulse receipt digest does not bind its exact content".into());
        }
        Ok(())
    }

    pub fn validate_for(&self, policy: &AttentionPolicyV1) -> Result<(), String> {
        self.validate()?;
        let target = &policy.target;
        if self.project != target.project
            || self.concern != target.concern
            || self.question != target.question
            || self.declaration_profile != target.declaration_profile
            || self.predicate_profile != target.predicate_profile
            || self.nq_catalog_digest != target.nq_catalog_digest
            || self.nq_profile_digest != target.nq_profile_digest
            || self.nq_input_schema_digest != target.nq_input_schema_digest
            || self.policy_id != target.pulse_support_policy_id
            || self.policy_digest != target.pulse_support_policy_digest
            || self.subject_id != target.subject_id
        {
            return Err("Pulse receipt does not exactly bind the attention policy target".into());
        }
        Ok(())
    }
}

impl AttentionEventV1 {
    pub fn from_verified(
        policy: &AttentionPolicyV1,
        pulse_receipt: PulseQualifiedSupportReceiptV1,
    ) -> Result<Self, String> {
        policy.validate()?;
        pulse_receipt.validate_for(policy)?;
        let occurrence_at = pulse_receipt
            .support_observed_at
            .clone()
            .unwrap_or_else(|| pulse_receipt.qualification_at.clone());
        let recurrence_id = recurrence_id(&pulse_receipt)?;
        let mut event = Self {
            schema: EVENT_SCHEMA_V1.into(),
            event_id: String::new(),
            policy_digest: policy.policy_digest.clone(),
            recurrence_id,
            occurrence_at,
            pulse_receipt,
        };
        event.event_id = digest_without_field(&event, "event_id")?;
        event.validate(policy)?;
        Ok(event)
    }

    pub fn validate(&self, policy: &AttentionPolicyV1) -> Result<(), String> {
        if self.schema != EVENT_SCHEMA_V1 || self.policy_digest != policy.policy_digest {
            return Err("attention event schema or policy lineage mismatch".into());
        }
        self.pulse_receipt.validate_for(policy)?;
        if self.recurrence_id != recurrence_id(&self.pulse_receipt)? {
            return Err("attention event recurrence identity is invalid".into());
        }
        let expected_occurrence = self
            .pulse_receipt
            .support_observed_at
            .as_ref()
            .unwrap_or(&self.pulse_receipt.qualification_at);
        if &self.occurrence_at != expected_occurrence {
            return Err(
                "attention event occurrence does not match governed Pulse occurrence".into(),
            );
        }
        parse_time(&self.occurrence_at)?;
        if self.event_id != digest_without_field(self, "event_id")? {
            return Err("attention event digest is invalid".into());
        }
        Ok(())
    }
}

pub fn verify_pulse_receipt(
    policy: &AttentionPolicyV1,
    pulse_receipt_path: &Path,
    inputs: &PulseReplayInputsV1,
) -> Result<PulseQualifiedSupportReceiptV1, String> {
    policy.validate()?;
    let pulse_receipt: PulseQualifiedSupportReceiptV1 = read_json(pulse_receipt_path)?;
    pulse_receipt.validate_for(policy)?;
    let executable_digest = file_digest(&inputs.pulse_executable, MAX_EXECUTABLE_BYTES)?;
    if executable_digest != policy.pulse_verifier_executable_digest {
        return Err("Pulse verifier executable digest does not match attention policy".into());
    }
    if inputs
        .pulse_executable
        .file_name()
        .and_then(|value| value.to_str())
        != Some("pulse-project-predicate-support")
    {
        return Err("Pulse verifier must use the pulse-project-predicate-support basename".into());
    }
    let output = tempfile::NamedTempFile::new().map_err(|error| error.to_string())?;
    let mut command = Command::new(&inputs.pulse_executable);
    command
        .args(["replay", "--policy"])
        .arg(&inputs.pulse_policy)
        .arg("--nq-executable")
        .arg(&inputs.nq_executable)
        .arg("--nq-receipt")
        .arg(&inputs.nq_receipt)
        .arg("--inventory")
        .arg(&inputs.inventory)
        .arg("--catalog")
        .arg(&inputs.catalog)
        .arg("--receipt")
        .arg(pulse_receipt_path)
        .arg("--output")
        .arg(output.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(evidence) = &inputs.support_evidence {
        command.arg("--support-evidence").arg(evidence);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("starting Pulse verifier: {error}"))?;
    let started = Instant::now();
    loop {
        if child
            .try_wait()
            .map_err(|error| error.to_string())?
            .is_some()
        {
            break;
        }
        if started.elapsed() >= VERIFIER_TIMEOUT {
            child.kill().map_err(|error| error.to_string())?;
            let _ = child.wait();
            return Err("Pulse verifier exceeded its bounded runtime".into());
        }
        thread::sleep(Duration::from_millis(5));
    }
    let result = child
        .wait_with_output()
        .map_err(|error| format!("waiting for Pulse verifier: {error}"))?;
    if result.stderr.len() as u64 > MAX_VERIFIER_OUTPUT_BYTES {
        return Err("Pulse verifier stderr exceeded its byte bound".into());
    }
    if !result.status.success() {
        return Err(format!(
            "Pulse replay refused: {}",
            String::from_utf8_lossy(&result.stderr).trim()
        ));
    }
    let replay: PulseReplayResultV1 = read_json(output.path())?;
    if replay.schema != PULSE_REPLAY_SCHEMA_V1
        || !replay.matches
        || replay.expected_receipt_digest != pulse_receipt.receipt_digest
        || replay.recomputed_receipt_digest != pulse_receipt.receipt_digest
    {
        return Err("Pulse replay did not reproduce the exact qualified-support receipt".into());
    }
    Ok(pulse_receipt)
}

pub struct AttentionStoreV1 {
    connection: Connection,
}

impl AttentionStoreV1 {
    pub fn open(path: &Path) -> Result<Self, String> {
        let connection = Connection::open(path).map_err(|error| error.to_string())?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE IF NOT EXISTS project_predicate_attention_lineages (
                   policy_digest TEXT PRIMARY KEY,
                   policy_id TEXT NOT NULL,
                   event_count INTEGER NOT NULL,
                   head_digest TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS project_predicate_attention_events (
                   policy_digest TEXT NOT NULL,
                   sequence INTEGER NOT NULL,
                   event_id TEXT NOT NULL,
                   predecessor_digest TEXT NOT NULL,
                   recurrence_id TEXT NOT NULL,
                   event_json TEXT NOT NULL,
                   PRIMARY KEY (policy_digest, sequence),
                   UNIQUE (policy_digest, recurrence_id),
                   FOREIGN KEY (policy_digest) REFERENCES project_predicate_attention_lineages(policy_digest)
                 );",
            )
            .map_err(|error| error.to_string())?;
        Ok(Self { connection })
    }

    pub fn ingest_verified(
        &mut self,
        policy: &AttentionPolicyV1,
        pulse_receipt: PulseQualifiedSupportReceiptV1,
    ) -> Result<IngestResultV1, String> {
        let event = AttentionEventV1::from_verified(policy, pulse_receipt)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| error.to_string())?;
        let existing: Option<String> = transaction
            .query_row(
                "SELECT event_id FROM project_predicate_attention_events
                 WHERE policy_digest = ?1 AND recurrence_id = ?2",
                params![policy.policy_digest, event.recurrence_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        if let Some(existing_event_id) = existing {
            let (count, head): (u64, String) = transaction
                .query_row(
                    "SELECT event_count, head_digest FROM project_predicate_attention_lineages
                     WHERE policy_digest = ?1",
                    params![policy.policy_digest],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|error| error.to_string())?;
            transaction.commit().map_err(|error| error.to_string())?;
            return Ok(IngestResultV1 {
                schema: INGEST_SCHEMA_V1.into(),
                disposition: IngestDispositionV1::DuplicateEvidenceOccurrence,
                policy_digest: policy.policy_digest.clone(),
                event_id: existing_event_id,
                recurrence_id: event.recurrence_id,
                pulse_receipt_digest: event.pulse_receipt.receipt_digest,
                history_event_count: count,
                history_head_digest: head,
            });
        }
        let lineage: Option<(u64, String, String)> = transaction
            .query_row(
                "SELECT event_count, head_digest, policy_id
                 FROM project_predicate_attention_lineages WHERE policy_digest = ?1",
                params![policy.policy_digest],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let (sequence, predecessor) = match lineage {
            Some((count, head, policy_id)) => {
                if policy_id != policy.policy_id {
                    return Err("attention lineage policy identity mismatch".into());
                }
                (count + 1, head)
            }
            None => {
                transaction
                    .execute(
                        "INSERT INTO project_predicate_attention_lineages
                         (policy_digest, policy_id, event_count, head_digest)
                         VALUES (?1, ?2, 0, ?3)",
                        params![policy.policy_digest, policy.policy_id, genesis_digest()],
                    )
                    .map_err(|error| error.to_string())?;
                (1, genesis_digest())
            }
        };
        let event_json = serde_json::to_string(&event).map_err(|error| error.to_string())?;
        let head = chain_digest(&predecessor, &event.event_id, sequence)?;
        transaction
            .execute(
                "INSERT INTO project_predicate_attention_events
                 (policy_digest, sequence, event_id, predecessor_digest, recurrence_id, event_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    policy.policy_digest,
                    sequence,
                    event.event_id,
                    predecessor,
                    event.recurrence_id,
                    event_json
                ],
            )
            .map_err(|error| error.to_string())?;
        transaction
            .execute(
                "UPDATE project_predicate_attention_lineages
                 SET event_count = ?2, head_digest = ?3 WHERE policy_digest = ?1",
                params![policy.policy_digest, sequence, head],
            )
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(IngestResultV1 {
            schema: INGEST_SCHEMA_V1.into(),
            disposition: IngestDispositionV1::Accepted,
            policy_digest: policy.policy_digest.clone(),
            event_id: event.event_id,
            recurrence_id: event.recurrence_id,
            pulse_receipt_digest: event.pulse_receipt.receipt_digest,
            history_event_count: sequence,
            history_head_digest: head,
        })
    }

    pub fn history(&self, policy: &AttentionPolicyV1) -> Result<Vec<AttentionEventV1>, String> {
        policy.validate()?;
        let lineage: Option<(u64, String, String)> = self
            .connection
            .query_row(
                "SELECT event_count, head_digest, policy_id
                 FROM project_predicate_attention_lineages WHERE policy_digest = ?1",
                params![policy.policy_digest],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let Some((expected_count, expected_head, policy_id)) = lineage else {
            return Ok(Vec::new());
        };
        if policy_id != policy.policy_id {
            return Err("stored attention lineage policy identity mismatch".into());
        }
        let mut statement = self
            .connection
            .prepare(
                "SELECT sequence, event_id, predecessor_digest, event_json
                 FROM project_predicate_attention_events
                 WHERE policy_digest = ?1 ORDER BY sequence ASC",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(params![policy.policy_digest], |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        let mut events = Vec::new();
        let mut predecessor = genesis_digest();
        for row in rows {
            let (sequence, event_id, stored_predecessor, event_json) =
                row.map_err(|error| error.to_string())?;
            if sequence != events.len() as u64 + 1 || stored_predecessor != predecessor {
                return Err("attention history sequence/predecessor custody is incomplete".into());
            }
            let event: AttentionEventV1 = serde_json::from_str(&event_json)
                .map_err(|error| format!("stored attention event JSON: {error}"))?;
            event.validate(policy)?;
            if event.event_id != event_id {
                return Err("stored attention event identity mismatch".into());
            }
            predecessor = chain_digest(&predecessor, &event_id, sequence)?;
            events.push(event);
        }
        if events.len() as u64 != expected_count || predecessor != expected_head {
            return Err("attention history truncation or head mismatch detected".into());
        }
        Ok(events)
    }
}

pub fn evaluate(
    policy: &AttentionPolicyV1,
    history: &[AttentionEventV1],
    evaluated_at: DateTime<Utc>,
) -> Result<AttentionReplayBundleV1, String> {
    policy.validate()?;
    let mut by_recurrence = BTreeMap::new();
    for event in history {
        event.validate(policy)?;
        if by_recurrence
            .insert(event.recurrence_id.clone(), event.clone())
            .is_some()
        {
            return Err("attention history repeats an evidence recurrence identity".into());
        }
    }
    let mut canonical_history: Vec<_> = by_recurrence.into_values().collect();
    canonical_history.sort_by(|left, right| {
        left.occurrence_at
            .cmp(&right.occurrence_at)
            .then_with(|| left.recurrence_id.cmp(&right.recurrence_id))
    });
    for event in &canonical_history {
        if parse_time(&event.occurrence_at)? > evaluated_at {
            return Err("attention history contains a future evidence occurrence".into());
        }
    }
    let within = i64::try_from(policy.recurrence.within_seconds)
        .map_err(|_| "attention horizon exceeds i64 seconds")?;
    let window_start = evaluated_at
        .checked_sub_signed(ChronoDuration::seconds(within))
        .ok_or_else(|| "attention horizon underflow".to_string())?;
    let reset_at = match (&policy.trigger, policy.reset) {
        (AttentionTriggerV1::AssuranceAttention { .. }, ResetPolicyV1::SupportedCurrent) => {
            canonical_history
                .iter()
                .filter(|event| {
                    event.pulse_receipt.disposition == PulseDispositionV1::SupportedCurrent
                })
                .map(|event| parse_time(&event.pulse_receipt.qualification_at))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter(|at| *at <= evaluated_at)
                .max()
        }
        _ => None,
    };
    let mut matching_before_currentness = 0_u32;
    let mut expired_supported = false;
    let mut qualifying = Vec::new();
    for event in &canonical_history {
        let at = parse_time(&event.occurrence_at)?;
        if at < window_start || at > evaluated_at || reset_at.is_some_and(|reset| at <= reset) {
            continue;
        }
        let trigger_match = match &policy.trigger {
            AttentionTriggerV1::PropositionAttention => {
                event.pulse_receipt.disposition == PulseDispositionV1::SupportedCurrent
            }
            AttentionTriggerV1::AssuranceAttention { dispositions } => {
                dispositions.contains(&event.pulse_receipt.disposition)
            }
        };
        if !trigger_match {
            continue;
        }
        matching_before_currentness += 1;
        if matches!(policy.trigger, AttentionTriggerV1::PropositionAttention) {
            let deadline = event.pulse_receipt.current_until_unix_ms.ok_or_else(|| {
                "SUPPORTED_CURRENT event lacks Pulse currentness boundary".to_string()
            })?;
            if unix_ms(evaluated_at)? >= deadline {
                expired_supported = true;
                continue;
            }
        }
        qualifying.push(event.clone());
    }
    let count = u32::try_from(qualifying.len()).map_err(|_| "too many attention events")?;
    let (disposition, reason_class, detail) = if count
        >= policy.recurrence.required_distinct_occurrences
    {
        let reason = match policy.trigger {
            AttentionTriggerV1::PropositionAttention => {
                AttentionReasonClassV1::PropositionAttention
            }
            AttentionTriggerV1::AssuranceAttention { .. } => {
                AttentionReasonClassV1::AssuranceAttention
            }
        };
        (
            AttentionDispositionV1::AttentionRequired,
            reason,
            format!(
                "{} distinct governed evidence occurrences satisfy the operator attention policy",
                count
            ),
        )
    } else if count > 0 {
        (
            AttentionDispositionV1::WaitingForRecurrence,
            AttentionReasonClassV1::None,
            format!(
                "{} of {} required distinct governed evidence occurrences are present",
                count, policy.recurrence.required_distinct_occurrences
            ),
        )
    } else if expired_supported && matching_before_currentness > 0 {
        (
            AttentionDispositionV1::InputNotCurrent,
            AttentionReasonClassV1::None,
            "historical Pulse support exists but its exclusive currentness boundary does not cover this evaluation".into(),
        )
    } else {
        (
            AttentionDispositionV1::NoAttention,
            AttentionReasonClassV1::None,
            "no governed attention trigger currently satisfies the policy".into(),
        )
    };
    let history_digest = digest_value(&canonical_history)?;
    let mut upstream: BTreeSet<_> = BTreeSet::new();
    for event in &qualifying {
        upstream.insert(event.pulse_receipt.disposition);
    }
    let mut receipt = AttentionReceiptV1 {
        schema: RECEIPT_SCHEMA_V1.into(),
        receipt_digest: String::new(),
        policy_id: policy.policy_id.clone(),
        policy_digest: policy.policy_digest.clone(),
        project: policy.target.project.clone(),
        concern: policy.target.concern.clone(),
        question: policy.target.question.clone(),
        declaration_profile: policy.target.declaration_profile.clone(),
        predicate_profile: policy.target.predicate_profile.clone(),
        nq_catalog_digest: policy.target.nq_catalog_digest.clone(),
        nq_profile_digest: policy.target.nq_profile_digest.clone(),
        nq_input_schema_digest: policy.target.nq_input_schema_digest.clone(),
        pulse_support_policy_id: policy.target.pulse_support_policy_id.clone(),
        pulse_support_policy_digest: policy.target.pulse_support_policy_digest.clone(),
        subject_id: policy.target.subject_id.clone(),
        evaluated_at: timestamp(evaluated_at),
        window_start_inclusive: timestamp(window_start),
        window_end_inclusive: timestamp(evaluated_at),
        required_distinct_occurrences: policy.recurrence.required_distinct_occurrences,
        qualifying_distinct_occurrences: count,
        qualifying_event_ids: qualifying.iter().map(|event| event.event_id.clone()).collect(),
        qualifying_recurrence_ids: qualifying
            .iter()
            .map(|event| event.recurrence_id.clone())
            .collect(),
        pulse_receipt_digests: qualifying
            .iter()
            .map(|event| event.pulse_receipt.receipt_digest.clone())
            .collect(),
        upstream_dispositions: upstream.into_iter().collect(),
        history_digest,
        attention_reason_class: reason_class,
        disposition,
        detail,
        recurrence_basis: "distinct primary/support observation coordinates; Pulse/Nightshift requalification and exact replay do not advance recurrence/v1".into(),
        currentness_basis: "for proposition attention only, evaluated_at must be strictly before Pulse current_until_unix_ms; Nightshift does not recompute Pulse freshness/v1".into(),
        reset_basis: match policy.reset {
            ResetPolicyV1::HorizonExpiry => "qualifying occurrences cease to count only outside the inclusive governed horizon; no failure receipt proves a domain clear/v1".into(),
            ResetPolicyV1::SupportedCurrent => "a later SUPPORTED_CURRENT Pulse qualification resets assurance-failure recurrence only/v1".into(),
        },
        validated: vec![
            "exact attention policy content custody and target binding".into(),
            "distinct recurrence identity, governed ordering, and inclusive horizon".into(),
            "Pulse disposition preservation and Pulse-owned exclusive support deadline".into(),
        ],
        not_validated: vec![
            "project proposition truth, NQ semantic correctness, or producer testimony truth".into(),
            "Pulse source independence beyond the verified Pulse receipt claim".into(),
            "uninterrupted truth, causality, whole-project health, remediation, publication, or notification delivery".into(),
        ],
    };
    receipt.receipt_digest = digest_without_field(&receipt, "receipt_digest")?;
    Ok(AttentionReplayBundleV1 {
        schema: BUNDLE_SCHEMA_V1.into(),
        policy: policy.clone(),
        history: canonical_history,
        receipt,
    })
}

pub fn replay_attention(
    bundle: &AttentionReplayBundleV1,
) -> Result<AttentionReplayResultV1, String> {
    if bundle.schema != BUNDLE_SCHEMA_V1 {
        return Err("unsupported attention replay bundle schema".into());
    }
    let at = parse_time(&bundle.receipt.evaluated_at)?;
    let recomputed = evaluate(&bundle.policy, &bundle.history, at)?;
    Ok(AttentionReplayResultV1 {
        schema: REPLAY_SCHEMA_V1.into(),
        matches: recomputed.receipt == bundle.receipt,
        expected_receipt_digest: bundle.receipt.receipt_digest.clone(),
        recomputed_receipt_digest: recomputed.receipt.receipt_digest,
    })
}

pub fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let bytes = read_bounded(path, MAX_INPUT_BYTES)?;
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    let value = T::deserialize(&mut deserializer).map_err(|error| error.to_string())?;
    deserializer.end().map_err(|error| error.to_string())?;
    Ok(value)
}

pub fn write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let mut file = File::create(path).map_err(|error| error.to_string())?;
    file.write_all(&canonical_bytes(value)?)
        .map_err(|error| error.to_string())
}

pub fn executable_digest(path: &Path) -> Result<String, String> {
    file_digest(path, MAX_EXECUTABLE_BYTES)
}

fn recurrence_id(receipt: &PulseQualifiedSupportReceiptV1) -> Result<String, String> {
    #[derive(Serialize)]
    struct Basis<'a> {
        schema: &'static str,
        pulse_policy_digest: &'a str,
        nq_receipt_digest: &'a str,
        subject_id: &'a str,
        disposition: PulseDispositionV1,
        primary_observed_at: &'a Option<String>,
        support_observed_at: &'a Option<String>,
        support_producer_id: &'a Option<String>,
        support_source_id: &'a Option<String>,
        support_vantage_id: &'a Option<String>,
        no_evidence_qualification_at: Option<&'a str>,
    }
    digest_value(&Basis {
        schema: "nightshift.project-predicate-evidence-occurrence/v1",
        pulse_policy_digest: &receipt.policy_digest,
        nq_receipt_digest: &receipt.nq_receipt_digest,
        subject_id: &receipt.subject_id,
        disposition: receipt.disposition,
        primary_observed_at: &receipt.primary_observed_at,
        support_observed_at: &receipt.support_observed_at,
        support_producer_id: &receipt.support_producer_id,
        support_source_id: &receipt.support_source_id,
        support_vantage_id: &receipt.support_vantage_id,
        no_evidence_qualification_at: receipt
            .support_observed_at
            .is_none()
            .then_some(receipt.qualification_at.as_str()),
    })
}

fn chain_digest(predecessor: &str, event_id: &str, sequence: u64) -> Result<String, String> {
    #[derive(Serialize)]
    struct Chain<'a> {
        schema: &'static str,
        predecessor: &'a str,
        event_id: &'a str,
        sequence: u64,
    }
    digest_value(&Chain {
        schema: "nightshift.project-predicate-attention-history-link/v1",
        predecessor,
        event_id,
        sequence,
    })
}

fn genesis_digest() -> String {
    format!(
        "sha256:{:x}",
        Sha256::digest(b"nightshift/project-predicate-attention-history/genesis/v1\0")
    )
}

fn require_token(name: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.chars().any(char::is_whitespace) {
        return Err(format!("{name} must be a non-empty token"));
    }
    Ok(())
}

fn require_digest(name: &str, value: &str) -> Result<(), String> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(format!("{name} must use sha256:<64 lowercase hex>"));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{name} must use sha256:<64 lowercase hex>"));
    }
    Ok(())
}

fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>, String> {
    serde_jcs::to_vec(value).map_err(|error| error.to_string())
}

fn digest_value(value: &impl Serialize) -> Result<String, String> {
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(canonical_bytes(value)?)
    ))
}

fn digest_without_field(value: &impl Serialize, field: &str) -> Result<String, String> {
    let mut value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    value
        .as_object_mut()
        .ok_or_else(|| "digest-bearing value is not an object".to_string())?
        .remove(field);
    digest_value(&value)
}

fn parse_time(value: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| format!("invalid RFC3339 occurrence {value:?}: {error}"))
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn unix_ms(value: DateTime<Utc>) -> Result<i64, String> {
    let seconds = value.timestamp();
    let millis = i64::from(value.timestamp_subsec_millis());
    seconds
        .checked_mul(1000)
        .and_then(|base| base.checked_add(millis))
        .ok_or_else(|| "Unix millisecond occurrence overflow".into())
}

fn file_digest(path: &Path, limit: u64) -> Result<String, String> {
    let bytes = read_bounded(path, limit)?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|error| format!("open exact input {}: {error}", path.display()))?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(format!("{} is not a bounded regular file", path.display()));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > limit {
        return Err(format!("{} exceeds its byte bound", path.display()));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;
    use std::os::unix::fs::PermissionsExt as _;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn policy(trigger: AttentionTriggerV1, count: u32) -> AttentionPolicyV1 {
        let mut policy = AttentionPolicyV1 {
            schema: POLICY_SCHEMA_V1.into(),
            policy_id: "nightshift.policy.unfamiliar/v1".into(),
            policy_digest: String::new(),
            target: AttentionTargetV1 {
                project: "unfamiliar-project".into(),
                concern: "unfamiliar.queue.high".into(),
                question: "unfamiliar.question.queue-high/v1".into(),
                declaration_profile: "unfamiliar.profile.queue-high-18/v1".into(),
                predicate_profile: "nq.profile.unfamiliar-queue-high-18/v1".into(),
                nq_catalog_digest: digest('a'),
                nq_profile_digest: digest('b'),
                nq_input_schema_digest: digest('c'),
                pulse_support_policy_id: "pulse.policy.unfamiliar/v1".into(),
                pulse_support_policy_digest: digest('d'),
                subject_id: "deployment:unfamiliar".into(),
            },
            pulse_verifier_executable_digest: digest('e'),
            trigger,
            recurrence: RecurrencePolicyV1 {
                required_distinct_occurrences: count,
                within_seconds: 900,
            },
            reset: ResetPolicyV1::HorizonExpiry,
        };
        policy.seal().unwrap();
        policy
    }

    fn pulse(
        policy: &AttentionPolicyV1,
        disposition: PulseDispositionV1,
        minute: u32,
    ) -> PulseQualifiedSupportReceiptV1 {
        let observed = format!("2026-08-25T12:{minute:02}:00Z");
        let mut receipt = PulseQualifiedSupportReceiptV1 {
            schema: PULSE_RECEIPT_SCHEMA_V1.into(),
            receipt_digest: String::new(),
            policy_id: policy.target.pulse_support_policy_id.clone(),
            policy_digest: policy.target.pulse_support_policy_digest.clone(),
            project: policy.target.project.clone(),
            concern: policy.target.concern.clone(),
            question: policy.target.question.clone(),
            declaration_profile: policy.target.declaration_profile.clone(),
            predicate_profile: policy.target.predicate_profile.clone(),
            nq_catalog_digest: policy.target.nq_catalog_digest.clone(),
            nq_profile_digest: policy.target.nq_profile_digest.clone(),
            nq_input_schema_digest: policy.target.nq_input_schema_digest.clone(),
            nq_receipt_digest: digest('f'),
            nq_verifier_executable_digest: digest('9'),
            primary_observed_at: Some(observed.clone()),
            support_evidence_id: Some(digest(char::from_digit(minute % 10, 10).unwrap_or('1'))),
            support_evidence_digest: Some(digest('8')),
            support_observed_at: Some(observed),
            support_producer_id: Some("pulse-producer:independent".into()),
            support_source_id: Some("source:direct".into()),
            support_vantage_id: Some("vantage:sidecar".into()),
            subject_id: policy.target.subject_id.clone(),
            qualification_at: format!("2026-08-25T12:{minute:02}:10Z"),
            current_until_unix_ms: Some(1_787_660_000_000_i64 + i64::from(minute) * 60_000),
            primary_support_skew_ms: Some(0),
            independence_basis:
                "operator_bound_distinct_signed_producer_and_exact_dependency_closure/v1".into(),
            disposition,
            detail: "fixture".into(),
            validated: vec![],
            not_validated: vec![],
        };
        if disposition != PulseDispositionV1::SupportedCurrent {
            receipt.current_until_unix_ms = None;
        }
        receipt.receipt_digest = digest_without_field(&receipt, "receipt_digest").unwrap();
        receipt
    }

    fn at(value: &str) -> DateTime<Utc> {
        parse_time(value).unwrap()
    }

    #[test]
    fn distinct_evidence_recurrence_and_exact_replay() {
        let policy = policy(AttentionTriggerV1::PropositionAttention, 3);
        let one = AttentionEventV1::from_verified(
            &policy,
            pulse(&policy, PulseDispositionV1::SupportedCurrent, 1),
        )
        .unwrap();
        let two = AttentionEventV1::from_verified(
            &policy,
            pulse(&policy, PulseDispositionV1::SupportedCurrent, 2),
        )
        .unwrap();
        let three = AttentionEventV1::from_verified(
            &policy,
            pulse(&policy, PulseDispositionV1::SupportedCurrent, 3),
        )
        .unwrap();
        assert_eq!(
            evaluate(
                &policy,
                std::slice::from_ref(&one),
                at("2026-08-25T12:01:20Z")
            )
            .unwrap()
            .receipt
            .disposition,
            AttentionDispositionV1::WaitingForRecurrence
        );
        assert_eq!(
            evaluate(&policy, &[one.clone(), two], at("2026-08-25T12:02:20Z"))
                .unwrap()
                .receipt
                .disposition,
            AttentionDispositionV1::WaitingForRecurrence
        );
        let bundle = evaluate(&policy, &[three, one], at("2026-08-25T12:03:20Z")).unwrap();
        assert_eq!(
            bundle.receipt.disposition,
            AttentionDispositionV1::WaitingForRecurrence
        );
        let bundle = evaluate(
            &policy,
            &[
                AttentionEventV1::from_verified(
                    &policy,
                    pulse(&policy, PulseDispositionV1::SupportedCurrent, 1),
                )
                .unwrap(),
                AttentionEventV1::from_verified(
                    &policy,
                    pulse(&policy, PulseDispositionV1::SupportedCurrent, 2),
                )
                .unwrap(),
                AttentionEventV1::from_verified(
                    &policy,
                    pulse(&policy, PulseDispositionV1::SupportedCurrent, 3),
                )
                .unwrap(),
            ],
            at("2026-08-25T12:03:20Z"),
        )
        .unwrap();
        assert_eq!(
            bundle.receipt.disposition,
            AttentionDispositionV1::AttentionRequired
        );
        assert_eq!(
            bundle.receipt.attention_reason_class,
            AttentionReasonClassV1::PropositionAttention
        );
        assert!(replay_attention(&bundle).unwrap().matches);
    }

    #[test]
    fn replay_and_requalification_of_same_occurrence_do_not_advance_recurrence() {
        let policy = policy(AttentionTriggerV1::PropositionAttention, 2);
        let first = pulse(&policy, PulseDispositionV1::SupportedCurrent, 1);
        let mut requalified = first.clone();
        requalified.qualification_at = "2026-08-25T12:01:20Z".into();
        requalified.receipt_digest = digest_without_field(&requalified, "receipt_digest").unwrap();
        let a = AttentionEventV1::from_verified(&policy, first).unwrap();
        let b = AttentionEventV1::from_verified(&policy, requalified).unwrap();
        assert_eq!(a.recurrence_id, b.recurrence_id);
        assert!(evaluate(&policy, &[a, b], at("2026-08-25T12:01:30Z")).is_err());
    }

    #[test]
    fn irrelevant_pulse_wrapper_changes_do_not_create_an_occurrence() {
        let policy = policy(AttentionTriggerV1::PropositionAttention, 2);
        let first = pulse(&policy, PulseDispositionV1::SupportedCurrent, 1);
        let mut changed_wrapper = first.clone();
        changed_wrapper.support_evidence_id = Some(digest('4'));
        changed_wrapper.support_evidence_digest = Some(digest('5'));
        changed_wrapper.detail = "opaque producer state and envelope changed".into();
        changed_wrapper.receipt_digest =
            digest_without_field(&changed_wrapper, "receipt_digest").unwrap();
        let first = AttentionEventV1::from_verified(&policy, first).unwrap();
        let changed = AttentionEventV1::from_verified(&policy, changed_wrapper).unwrap();
        assert_ne!(first.event_id, changed.event_id);
        assert_eq!(first.recurrence_id, changed.recurrence_id);
    }

    #[test]
    fn currentness_is_exclusive_and_nightshift_does_not_refresh_it() {
        let policy = policy(AttentionTriggerV1::PropositionAttention, 1);
        let event = AttentionEventV1::from_verified(
            &policy,
            pulse(&policy, PulseDispositionV1::SupportedCurrent, 1),
        )
        .unwrap();
        let deadline = event.pulse_receipt.current_until_unix_ms.unwrap();
        let before = Utc.timestamp_millis_opt(deadline - 1).unwrap();
        let exact = Utc.timestamp_millis_opt(deadline).unwrap();
        assert_eq!(
            evaluate(&policy, std::slice::from_ref(&event), before)
                .unwrap()
                .receipt
                .disposition,
            AttentionDispositionV1::AttentionRequired
        );
        assert_eq!(
            evaluate(&policy, &[event], exact)
                .unwrap()
                .receipt
                .disposition,
            AttentionDispositionV1::InputNotCurrent
        );
    }

    #[test]
    fn assurance_attention_preserves_failure_meaning_and_can_reset() {
        let mut policy = policy(
            AttentionTriggerV1::AssuranceAttention {
                dispositions: vec![PulseDispositionV1::MissingSupport],
            },
            2,
        );
        let mut missing_one = pulse(&policy, PulseDispositionV1::MissingSupport, 1);
        missing_one.support_observed_at = None;
        missing_one.support_evidence_id = None;
        missing_one.support_evidence_digest = None;
        missing_one.support_producer_id = None;
        missing_one.support_source_id = None;
        missing_one.support_vantage_id = None;
        missing_one.receipt_digest = digest_without_field(&missing_one, "receipt_digest").unwrap();
        let mut missing_two = missing_one.clone();
        missing_two.qualification_at = "2026-08-25T12:02:10Z".into();
        missing_two.receipt_digest = digest_without_field(&missing_two, "receipt_digest").unwrap();
        let events = vec![
            AttentionEventV1::from_verified(&policy, missing_one).unwrap(),
            AttentionEventV1::from_verified(&policy, missing_two).unwrap(),
        ];
        let result = evaluate(&policy, &events, at("2026-08-25T12:03:00Z")).unwrap();
        assert_eq!(
            result.receipt.disposition,
            AttentionDispositionV1::AttentionRequired
        );
        assert_eq!(
            result.receipt.attention_reason_class,
            AttentionReasonClassV1::AssuranceAttention
        );
        assert!(result.receipt.detail.contains("evidence occurrences"));
        policy.reset = ResetPolicyV1::SupportedCurrent;
        policy.seal().unwrap();
        let restored = AttentionEventV1::from_verified(
            &policy,
            pulse(&policy, PulseDispositionV1::SupportedCurrent, 3),
        )
        .unwrap();
        let result = evaluate(&policy, &[restored], at("2026-08-25T12:03:30Z")).unwrap();
        assert_eq!(
            result.receipt.disposition,
            AttentionDispositionV1::NoAttention
        );
    }

    #[test]
    fn contradiction_attention_is_assurance_not_a_world_claim() {
        let policy = policy(
            AttentionTriggerV1::AssuranceAttention {
                dispositions: vec![PulseDispositionV1::Contradictory],
            },
            1,
        );
        let event = AttentionEventV1::from_verified(
            &policy,
            pulse(&policy, PulseDispositionV1::Contradictory, 1),
        )
        .unwrap();
        let result = evaluate(&policy, &[event], at("2026-08-25T12:01:30Z")).unwrap();
        assert_eq!(
            result.receipt.attention_reason_class,
            AttentionReasonClassV1::AssuranceAttention
        );
        assert!(result
            .receipt
            .not_validated
            .iter()
            .any(|claim| claim.contains("project proposition truth")));
    }

    #[test]
    fn order_is_canonical_and_horizon_boundary_is_inclusive() {
        let mut policy = policy(
            AttentionTriggerV1::AssuranceAttention {
                dispositions: vec![PulseDispositionV1::Contradictory],
            },
            2,
        );
        policy.recurrence.within_seconds = 120;
        policy.seal().unwrap();
        let one = AttentionEventV1::from_verified(
            &policy,
            pulse(&policy, PulseDispositionV1::Contradictory, 1),
        )
        .unwrap();
        let three = AttentionEventV1::from_verified(
            &policy,
            pulse(&policy, PulseDispositionV1::Contradictory, 3),
        )
        .unwrap();
        let ordered = evaluate(
            &policy,
            &[one.clone(), three.clone()],
            at("2026-08-25T12:03:00Z"),
        )
        .unwrap();
        let reordered =
            evaluate(&policy, &[three.clone(), one], at("2026-08-25T12:03:00Z")).unwrap();
        assert_eq!(ordered.receipt, reordered.receipt);
        assert_eq!(
            ordered.receipt.disposition,
            AttentionDispositionV1::AttentionRequired
        );
        assert_eq!(
            evaluate(&policy, &[three], at("2026-08-25T12:05:00.001Z"))
                .unwrap()
                .receipt
                .disposition,
            AttentionDispositionV1::NoAttention
        );
    }

    #[test]
    fn durable_history_is_idempotent_and_restart_preserves_without_refresh() {
        let policy = policy(AttentionTriggerV1::PropositionAttention, 2);
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("nightshift.sqlite");
        let receipt = pulse(&policy, PulseDispositionV1::SupportedCurrent, 1);
        {
            let mut store = AttentionStoreV1::open(&database).unwrap();
            assert_eq!(
                store
                    .ingest_verified(&policy, receipt.clone())
                    .unwrap()
                    .disposition,
                IngestDispositionV1::Accepted
            );
            assert_eq!(
                store.ingest_verified(&policy, receipt).unwrap().disposition,
                IngestDispositionV1::DuplicateEvidenceOccurrence
            );
        }
        let store = AttentionStoreV1::open(&database).unwrap();
        let history = store.history(&policy).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(
            evaluate(&policy, &history, at("2026-08-25T12:01:30Z"))
                .unwrap()
                .receipt
                .disposition,
            AttentionDispositionV1::WaitingForRecurrence
        );
    }

    #[test]
    fn policy_subject_and_receipt_mutation_are_refused() {
        let policy = policy(AttentionTriggerV1::PropositionAttention, 1);
        let mut receipt = pulse(&policy, PulseDispositionV1::SupportedCurrent, 1);
        receipt.subject_id = "deployment:other".into();
        receipt.receipt_digest = digest_without_field(&receipt, "receipt_digest").unwrap();
        assert!(AttentionEventV1::from_verified(&policy, receipt).is_err());
        let mut changed = policy.clone();
        changed.recurrence.required_distinct_occurrences = 2;
        assert!(changed.validate().is_err());
    }

    #[test]
    fn exact_pulse_replay_is_required_and_substitution_refuses() {
        let directory = tempfile::tempdir().unwrap();
        let pulse_program = directory.path().join("pulse-project-predicate-support");
        let pulse_receipt_path = directory.path().join("pulse-receipt.json");
        let mut policy = policy(AttentionTriggerV1::PropositionAttention, 1);
        let receipt = pulse(&policy, PulseDispositionV1::SupportedCurrent, 1);
        write_json(&pulse_receipt_path, &receipt).unwrap();
        let script = format!(
            "#!/bin/sh\nout=\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = \"--output\" ]; then out=$2; shift 2; else shift; fi\ndone\nprintf '%s' '{{\"schema\":\"pulse.project-predicate-support-replay/v1\",\"matches\":true,\"expected_receipt_digest\":\"{0}\",\"recomputed_receipt_digest\":\"{0}\"}}' > \"$out\"\n",
            receipt.receipt_digest
        );
        std::fs::write(&pulse_program, script).unwrap();
        let mut permissions = std::fs::metadata(&pulse_program).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&pulse_program, permissions).unwrap();
        policy.pulse_verifier_executable_digest = executable_digest(&pulse_program).unwrap();
        policy.seal().unwrap();
        // Reseal the receipt against the policy target, which did not change.
        let inputs = PulseReplayInputsV1 {
            pulse_executable: pulse_program.clone(),
            pulse_policy: directory.path().join("policy.json"),
            nq_executable: directory.path().join("nq"),
            nq_receipt: directory.path().join("nq-receipt.json"),
            inventory: directory.path().join("inventory.json"),
            catalog: directory.path().join("catalog.json"),
            support_evidence: Some(directory.path().join("support.json")),
        };
        verify_pulse_receipt(&policy, &pulse_receipt_path, &inputs).unwrap();

        let mut forged = receipt;
        forged.subject_id = "deployment:forged".into();
        forged.receipt_digest = digest_without_field(&forged, "receipt_digest").unwrap();
        write_json(&pulse_receipt_path, &forged).unwrap();
        assert!(verify_pulse_receipt(&policy, &pulse_receipt_path, &inputs).is_err());

        let mut substituted_policy = policy.clone();
        substituted_policy.pulse_verifier_executable_digest = digest('7');
        substituted_policy.seal().unwrap();
        assert!(verify_pulse_receipt(&substituted_policy, &pulse_receipt_path, &inputs).is_err());
    }

    #[test]
    fn corrupt_or_truncated_history_fails_safely() {
        let policy = policy(AttentionTriggerV1::PropositionAttention, 1);
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("nightshift.sqlite");
        {
            let mut store = AttentionStoreV1::open(&database).unwrap();
            store
                .ingest_verified(
                    &policy,
                    pulse(&policy, PulseDispositionV1::SupportedCurrent, 1),
                )
                .unwrap();
        }
        Connection::open(&database)
            .unwrap()
            .execute(
                "DELETE FROM project_predicate_attention_events WHERE policy_digest = ?1",
                params![policy.policy_digest],
            )
            .unwrap();
        let store = AttentionStoreV1::open(&database).unwrap();
        assert!(store.history(&policy).is_err());
    }

    #[test]
    fn benign_supported_proposition_does_not_trigger_assurance_attention() {
        let policy = policy(
            AttentionTriggerV1::AssuranceAttention {
                dispositions: vec![PulseDispositionV1::MissingSupport],
            },
            1,
        );
        let event = AttentionEventV1::from_verified(
            &policy,
            pulse(&policy, PulseDispositionV1::SupportedCurrent, 1),
        )
        .unwrap();
        let result = evaluate(&policy, &[event], at("2026-08-25T12:01:30Z")).unwrap();
        assert_eq!(
            result.receipt.disposition,
            AttentionDispositionV1::NoAttention
        );
        assert_eq!(
            result.receipt.attention_reason_class,
            AttentionReasonClassV1::None
        );
    }

    #[test]
    fn changed_policy_or_history_breaks_replay() {
        let policy = policy(AttentionTriggerV1::PropositionAttention, 1);
        let event = AttentionEventV1::from_verified(
            &policy,
            pulse(&policy, PulseDispositionV1::SupportedCurrent, 1),
        )
        .unwrap();
        let mut bundle = evaluate(&policy, &[event], at("2026-08-25T12:01:30Z")).unwrap();
        bundle.receipt.detail.push_str(" mutated");
        assert!(!replay_attention(&bundle).unwrap().matches);

        let mut changed = bundle.clone();
        changed.policy.recurrence.required_distinct_occurrences = 2;
        assert!(replay_attention(&changed).is_err());
    }

    #[test]
    fn checked_in_schema_identities_are_exact() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas");
        for (file, identity) in [
            (
                "nightshift.project-predicate-attention-policy.v1.schema.json",
                POLICY_SCHEMA_V1,
            ),
            (
                "nightshift.project-predicate-attention.v1.schema.json",
                RECEIPT_SCHEMA_V1,
            ),
            (
                "nightshift.project-predicate-attention-replay-bundle.v1.schema.json",
                BUNDLE_SCHEMA_V1,
            ),
        ] {
            let value: serde_json::Value =
                serde_json::from_slice(&std::fs::read(root.join(file)).unwrap()).unwrap();
            assert_eq!(value["$id"], identity);
            assert_eq!(value["additionalProperties"], false);
        }
    }
}

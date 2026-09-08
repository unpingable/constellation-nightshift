//! Distinct ingress and applicability resolver for NQ repository-stage
//! qualification receipts.
//!
//! This module does not use generic attention or local-Compose claim types.
//! NQ owns the historical qualification judgment. Nightshift retains that
//! exact judgment and owns only its applicability/freshness relative to an
//! exact, currently settled AG predecessor. It grants no continuation or
//! effect authority.

use std::path::{Path, PathBuf};
use std::process::Command;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::canonical_store::{AgOccurrenceReferenceV1, AgProgramCounterV1};

pub const QUALIFICATION_APPLICABILITY_PROFILE_SCHEMA_V1: &str =
    "nightshift.repository-qualification-applicability-profile/v1";
pub const QUALIFICATION_APPLICABILITY_SCHEMA_V1: &str =
    "nightshift.repository-qualification-applicability/v1";
pub const AG_OBSERVATION_RESOLUTION_SCHEMA_V3: &str = "ag.governed-loop.observation-resolution/v3";
pub const AG_TYPED_OBSERVATION_BASIS_SCHEMA_V1: &str =
    "ag.governed-loop.typed-observation-basis/v1";
pub const NQ_PROFILE_SCHEMA_V1: &str = "nq-ng.campaign-stage-qualification-profile/v1";
pub const NQ_EVIDENCE_SCHEMA_V1: &str = "nq-ng.campaign-stage-qualification-evidence/v1";
pub const NQ_RECEIPT_SCHEMA_V1: &str = "nq-ng.campaign-stage-qualification/v1";
pub const NQ_REPLAY_SCHEMA_V1: &str = "nq-ng.campaign-stage-qualification-replay/v1";

const NONCLAIMS: [&str; 6] = [
    "standing",
    "authorization",
    "successor choice",
    "continuation",
    "effect authority",
    "freshness or present applicability",
];

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

fn require_token(name: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.chars().any(char::is_whitespace) {
        return Err(format!("{name} must be a non-empty token"));
    }
    Ok(())
}

fn jcs_sha256<T: Serialize + ?Sized>(value: &T) -> Result<String, String> {
    let bytes = serde_jcs::to_vec(value).map_err(|error| error.to_string())?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn object_id<T: Serialize>(value: &T, identity_field: &str) -> Result<String, String> {
    let mut value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    value
        .as_object_mut()
        .ok_or_else(|| "identity preimage must be an object".to_owned())?
        .remove(identity_field);
    jcs_sha256(&value)
}

fn ag_domain_digest<T: Serialize>(domain: &str, value: &T) -> Result<String, String> {
    let payload = serde_jcs::to_vec(value).map_err(|error| error.to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(b"ag-ng\0digest\0v1\0");
    hasher.update((domain.len() as u128).to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update((payload.len() as u128).to_be_bytes());
    hasher.update(payload);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitObjectBindingV1 {
    pub object_format: String,
    pub digest: String,
}

impl GitObjectBindingV1 {
    fn validate(&self) -> Result<(), String> {
        let expected = match self.object_format.as_str() {
            "sha1" => 40,
            "sha256" => 64,
            _ => return Err("unsupported Git object format".into()),
        };
        if self.digest.len() != expected
            || !self
                .digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("malformed Git object identity".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationApplicabilityProfileV1 {
    pub schema: String,
    pub profile_id: String,
    pub expected_nq_profile_id: String,
    pub expected_nq_profile_sha256: String,
    pub expected_nq_evaluator_id: String,
    pub expected_nq_evaluator_version: String,
    pub expected_nq_evaluator_executable_sha256: String,
    pub source_campaign_id: String,
    pub source_occurrence_id: String,
    pub source_attempt_id: String,
    pub source_settlement_id: String,
    pub expected_result_head: GitObjectBindingV1,
    pub expected_result_tree: GitObjectBindingV1,
    pub subject_digest: String,
    pub resolver_id: String,
    pub max_age_ms: u64,
}

impl QualificationApplicabilityProfileV1 {
    pub fn seal(mut self) -> Result<Self, String> {
        self.schema = QUALIFICATION_APPLICABILITY_PROFILE_SCHEMA_V1.into();
        self.profile_id.clear();
        self.profile_id = object_id(&self, "profile_id")?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != QUALIFICATION_APPLICABILITY_PROFILE_SCHEMA_V1 {
            return Err("unsupported qualification-applicability profile schema".into());
        }
        for (name, value) in [
            ("profile_id", &self.profile_id),
            (
                "expected_nq_profile_sha256",
                &self.expected_nq_profile_sha256,
            ),
            (
                "expected_nq_evaluator_executable_sha256",
                &self.expected_nq_evaluator_executable_sha256,
            ),
            ("source_campaign_id", &self.source_campaign_id),
            ("subject_digest", &self.subject_digest),
        ] {
            require_digest(name, value)?;
        }
        for (name, value) in [
            ("expected_nq_profile_id", &self.expected_nq_profile_id),
            ("expected_nq_evaluator_id", &self.expected_nq_evaluator_id),
            (
                "expected_nq_evaluator_version",
                &self.expected_nq_evaluator_version,
            ),
            ("source_occurrence_id", &self.source_occurrence_id),
            ("source_attempt_id", &self.source_attempt_id),
            ("source_settlement_id", &self.source_settlement_id),
            ("resolver_id", &self.resolver_id),
        ] {
            require_token(name, value)?;
        }
        uuid::Uuid::parse_str(&self.source_occurrence_id)
            .map_err(|_| "source_occurrence_id must be a UUID".to_owned())?;
        self.expected_result_head.validate()?;
        self.expected_result_tree.validate()?;
        if self.expected_nq_evaluator_id != "nq-ng.campaign-stage-qualification-evaluator/v1"
            || self.max_age_ms == 0
            || self.profile_id != object_id(self, "profile_id")?
        {
            return Err("qualification-applicability profile is not the closed v1 profile".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NqQualificationStatusV1 {
    Qualified,
    Failed,
    Indeterminate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NqReceiptV1 {
    schema: String,
    receipt_id: String,
    evaluator_id: String,
    evaluator_version: String,
    evaluator_executable_sha256: String,
    evaluated_at_unix_ms: u64,
    profile_id: String,
    profile_sha256: String,
    evidence_id: String,
    evidence_sha256: String,
    campaign_packet_sha256: String,
    stage_id: String,
    repository_id: String,
    repository_ref: String,
    predecessor_head: GitObjectBindingV1,
    predecessor_tree: GitObjectBindingV1,
    result_head: GitObjectBindingV1,
    result_tree: GitObjectBindingV1,
    status: NqQualificationStatusV1,
    reasons: Vec<serde_json::Value>,
    does_not_establish: Vec<String>,
    receipt_sha256: String,
}

impl NqReceiptV1 {
    fn validate_integrity(&self) -> Result<(), String> {
        if self.schema != NQ_RECEIPT_SCHEMA_V1 {
            return Err("unsupported NQ qualification receipt schema".into());
        }
        for (name, value) in [
            ("receipt_sha256", &self.receipt_sha256),
            ("profile_sha256", &self.profile_sha256),
            ("evidence_sha256", &self.evidence_sha256),
            ("campaign_packet_sha256", &self.campaign_packet_sha256),
            (
                "evaluator_executable_sha256",
                &self.evaluator_executable_sha256,
            ),
        ] {
            require_digest(name, value)?;
        }
        let mut unsigned = self.clone();
        unsigned.receipt_sha256.clear();
        if self.receipt_sha256 != jcs_sha256(&unsigned)? {
            return Err("NQ qualification receipt digest mismatch".into());
        }
        if self.does_not_establish != NONCLAIMS.map(str::to_owned) {
            return Err("NQ qualification receipt nonclaims changed".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NqReplayV1 {
    schema: String,
    matches: bool,
    expected_receipt_sha256: String,
    recomputed_receipt_sha256: String,
}

pub trait QualificationReceiptVerifierV1 {
    fn executable_sha256(&self) -> Result<String, String>;
    fn replay(
        &mut self,
        profile: &serde_json::Value,
        evidence: &serde_json::Value,
        receipt: &serde_json::Value,
    ) -> Result<(), String>;
}

pub struct NqNgQualificationVerifierV1 {
    program: PathBuf,
}

impl NqNgQualificationVerifierV1 {
    pub fn new(program: impl Into<PathBuf>) -> Result<Self, String> {
        let program = program.into();
        if program.file_name().and_then(|name| name.to_str()) != Some("nq") {
            return Err("qualification verifier accepts only nq".into());
        }
        Ok(Self { program })
    }

    fn write_value(value: &serde_json::Value) -> Result<tempfile::NamedTempFile, String> {
        let mut file = tempfile::NamedTempFile::new().map_err(|error| error.to_string())?;
        use std::io::Write as _;
        file.write_all(&serde_jcs::to_vec(value).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
        Ok(file)
    }
}

impl QualificationReceiptVerifierV1 for NqNgQualificationVerifierV1 {
    fn executable_sha256(&self) -> Result<String, String> {
        let bytes = std::fs::read(&self.program)
            .map_err(|error| format!("reading NQ evaluator executable: {error}"))?;
        Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
    }

    fn replay(
        &mut self,
        profile: &serde_json::Value,
        evidence: &serde_json::Value,
        receipt: &serde_json::Value,
    ) -> Result<(), String> {
        let profile = Self::write_value(profile)?;
        let evidence = Self::write_value(evidence)?;
        let receipt = Self::write_value(receipt)?;
        let output = Command::new(&self.program)
            .args([
                "campaign-stage-qualification",
                "replay",
                "--profile",
                &profile.path().to_string_lossy(),
                "--evidence",
                &evidence.path().to_string_lossy(),
                "--receipt",
                &receipt.path().to_string_lossy(),
                "--output",
                "-",
            ])
            .output()
            .map_err(|error| format!("NQ qualification replay failed to start: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "NQ qualification replay refused: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let replay: NqReplayV1 = serde_json::from_slice(&output.stdout)
            .map_err(|error| format!("NQ qualification replay returned invalid JSON: {error}"))?;
        if replay.schema != NQ_REPLAY_SCHEMA_V1
            || !replay.matches
            || replay.expected_receipt_sha256 != replay.recomputed_receipt_sha256
        {
            return Err("NQ qualification replay did not reproduce the receipt".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RetainedQualificationReceiptV1 {
    pub receipt_id: String,
    pub receipt_sha256: String,
    pub status: NqQualificationStatusV1,
    pub evaluated_at_unix_ms: u64,
}

pub struct QualificationReceiptStoreV1 {
    connection: Connection,
}

impl QualificationReceiptStoreV1 {
    pub fn open(path: &Path) -> Result<Self, String> {
        let connection = Connection::open(path).map_err(|error| error.to_string())?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE IF NOT EXISTS repository_qualification_receipts (
                   receipt_id TEXT PRIMARY KEY,
                   receipt_sha256 TEXT NOT NULL UNIQUE,
                   status TEXT NOT NULL,
                   evaluated_at_unix_ms INTEGER NOT NULL,
                   applicability_profile_id TEXT NOT NULL,
                   source_campaign_id TEXT NOT NULL,
                   source_occurrence_id TEXT NOT NULL,
                   exact_profile_json BLOB NOT NULL,
                   exact_evidence_json BLOB NOT NULL,
                   exact_receipt_json BLOB NOT NULL
                 );",
            )
            .map_err(|error| error.to_string())?;
        Ok(Self { connection })
    }

    /// Open an already-initialized receipt store without write or migration
    /// capability. Applicability resolution cannot create retained evidence.
    pub fn open_read_only(path: &Path) -> Result<Self, String> {
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|error| error.to_string())?;
        Ok(Self { connection })
    }

    pub fn ingest<V: QualificationReceiptVerifierV1>(
        &mut self,
        applicability: &QualificationApplicabilityProfileV1,
        nq_profile: &serde_json::Value,
        nq_evidence: &serde_json::Value,
        nq_receipt: &serde_json::Value,
        verifier: &mut V,
    ) -> Result<RetainedQualificationReceiptV1, String> {
        applicability.validate()?;
        let profile_schema = nq_profile
            .get("schema")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "NQ profile schema is absent".to_owned())?;
        let profile_id = nq_profile
            .get("profile_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "NQ profile identity is absent".to_owned())?;
        let evidence_schema = nq_evidence
            .get("schema")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "NQ evidence schema is absent".to_owned())?;
        let receipt: NqReceiptV1 = serde_json::from_value(nq_receipt.clone())
            .map_err(|error| format!("invalid NQ qualification receipt: {error}"))?;
        receipt.validate_integrity()?;
        let profile_sha256 = jcs_sha256(nq_profile)?;
        let evidence_sha256 = jcs_sha256(nq_evidence)?;
        if profile_schema != NQ_PROFILE_SCHEMA_V1
            || evidence_schema != NQ_EVIDENCE_SCHEMA_V1
            || profile_id != applicability.expected_nq_profile_id
            || profile_sha256 != applicability.expected_nq_profile_sha256
            || receipt.profile_id != profile_id
            || receipt.profile_sha256 != profile_sha256
            || receipt.evidence_sha256 != evidence_sha256
            || receipt.evaluator_id != applicability.expected_nq_evaluator_id
            || receipt.evaluator_version != applicability.expected_nq_evaluator_version
            || receipt.evaluator_executable_sha256
                != applicability.expected_nq_evaluator_executable_sha256
            || receipt.result_head != applicability.expected_result_head
            || receipt.result_tree != applicability.expected_result_tree
            || verifier.executable_sha256()?
                != applicability.expected_nq_evaluator_executable_sha256
        {
            return Err("qualification profile/evidence/evaluator identity mismatch".into());
        }
        verifier.replay(nq_profile, nq_evidence, nq_receipt)?;
        let retained = RetainedQualificationReceiptV1 {
            receipt_id: receipt.receipt_id.clone(),
            receipt_sha256: receipt.receipt_sha256.clone(),
            status: receipt.status,
            evaluated_at_unix_ms: receipt.evaluated_at_unix_ms,
        };
        let profile_bytes = serde_jcs::to_vec(nq_profile).map_err(|error| error.to_string())?;
        let evidence_bytes = serde_jcs::to_vec(nq_evidence).map_err(|error| error.to_string())?;
        let receipt_bytes = serde_jcs::to_vec(nq_receipt).map_err(|error| error.to_string())?;
        let status = match retained.status {
            NqQualificationStatusV1::Qualified => "QUALIFIED",
            NqQualificationStatusV1::Failed => "FAILED",
            NqQualificationStatusV1::Indeterminate => "INDETERMINATE",
        };
        let changed = self
            .connection
            .execute(
                "INSERT OR IGNORE INTO repository_qualification_receipts
                 (receipt_id, receipt_sha256, status, evaluated_at_unix_ms,
                  applicability_profile_id, source_campaign_id, source_occurrence_id,
                  exact_profile_json, exact_evidence_json, exact_receipt_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    retained.receipt_id,
                    retained.receipt_sha256,
                    status,
                    retained.evaluated_at_unix_ms,
                    applicability.profile_id,
                    applicability.source_campaign_id,
                    applicability.source_occurrence_id,
                    profile_bytes,
                    evidence_bytes,
                    receipt_bytes,
                ],
            )
            .map_err(|error| error.to_string())?;
        if changed == 0 {
            let existing: (String, Vec<u8>, Vec<u8>, Vec<u8>) = self
                .connection
                .query_row(
                    "SELECT receipt_sha256, exact_profile_json, exact_evidence_json,
                            exact_receipt_json
                     FROM repository_qualification_receipts WHERE receipt_id = ?1",
                    [&retained.receipt_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .map_err(|error| error.to_string())?;
            if existing
                != (
                    retained.receipt_sha256.clone(),
                    serde_jcs::to_vec(nq_profile).map_err(|error| error.to_string())?,
                    serde_jcs::to_vec(nq_evidence).map_err(|error| error.to_string())?,
                    serde_jcs::to_vec(nq_receipt).map_err(|error| error.to_string())?,
                )
            {
                return Err("immutable qualification receipt identity conflicts".into());
            }
        }
        Ok(retained)
    }

    fn load_receipt(&self, receipt_id: &str) -> Result<Option<NqReceiptV1>, String> {
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT exact_receipt_json FROM repository_qualification_receipts
                 WHERE receipt_id = ?1",
                [receipt_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        bytes
            .map(|bytes| serde_json::from_slice(&bytes).map_err(|error| error.to_string()))
            .transpose()
    }

    fn latest_receipt_id(
        &self,
        profile: &QualificationApplicabilityProfileV1,
    ) -> Result<Option<String>, String> {
        self.connection
            .query_row(
                "SELECT receipt_id FROM repository_qualification_receipts
                 WHERE applicability_profile_id = ?1 AND source_campaign_id = ?2
                   AND source_occurrence_id = ?3
                 ORDER BY evaluated_at_unix_ms DESC, receipt_sha256 DESC LIMIT 1",
                params![
                    profile.profile_id,
                    profile.source_campaign_id,
                    profile.source_occurrence_id
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())
    }

    pub fn exact_retained_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<serde_json::Value>, String> {
        self.load_receipt(receipt_id)?
            .map(|receipt| serde_json::to_value(receipt).map_err(|error| error.to_string()))
            .transpose()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn resolve_applicability(
        &self,
        profile: &QualificationApplicabilityProfileV1,
        source: &AgOccurrenceReferenceV1,
        receipt_id: &str,
        target_campaign_id: &str,
        target_occurrence_id: &str,
        requested_observation: &str,
        requested_subject: &str,
        now_unix_ms: u64,
    ) -> Result<QualificationApplicabilityOutcomeV1, String> {
        profile.validate()?;
        source.validate().map_err(|error| error.to_string())?;
        require_digest("target_campaign_id", target_campaign_id)?;
        uuid::Uuid::parse_str(target_occurrence_id)
            .map_err(|_| "target_occurrence_id must be a UUID".to_owned())?;
        require_digest("requested_observation", requested_observation)?;
        require_digest("requested_subject", requested_subject)?;
        if source.campaign_id != profile.source_campaign_id
            || source.occurrence_id != profile.source_occurrence_id
            || source.program_counter != AgProgramCounterV1::SettledObservationRequired
            || source.docket_attempt_id.as_deref() != Some(profile.source_attempt_id.as_str())
            || source.settlement_id.as_deref() != Some(profile.source_settlement_id.as_str())
            || requested_subject != profile.subject_digest
        {
            return Err(
                "qualification is not applicable to the exact live settled predecessor".into(),
            );
        }
        let receipt = self
            .load_receipt(receipt_id)?
            .ok_or_else(|| "qualification receipt is not retained".to_owned())?;
        if receipt.status != NqQualificationStatusV1::Qualified {
            return Ok(QualificationApplicabilityOutcomeV1::RetainedOnly {
                receipt_id: receipt.receipt_id,
                status: receipt.status,
            });
        }
        let expected_observation = qualification_observation_id(profile, &receipt)?;
        if requested_observation != expected_observation {
            return Err("requested observation substitutes a different qualification".into());
        }
        let status = if self.latest_receipt_id(profile)?.as_deref() != Some(receipt_id) {
            AgTypedObservationStatusV1::Superseded
        } else if now_unix_ms
            >= receipt
                .evaluated_at_unix_ms
                .checked_add(profile.max_age_ms)
                .ok_or_else(|| "qualification freshness horizon overflow".to_owned())?
        {
            AgTypedObservationStatusV1::Stale
        } else {
            AgTypedObservationStatusV1::Current
        };
        let applicability = QualificationApplicabilityV1 {
            schema: QUALIFICATION_APPLICABILITY_SCHEMA_V1.into(),
            applicability_profile_id: profile.profile_id.clone(),
            nq_receipt_id: receipt.receipt_id.clone(),
            nq_receipt_sha256: receipt.receipt_sha256.clone(),
            source_campaign_id: source.campaign_id.clone(),
            source_occurrence_id: source.occurrence_id.clone(),
            source_state_digest: source.state_digest.clone(),
            source_snapshot_digest: source.snapshot_digest.clone(),
            source_attempt_id: profile.source_attempt_id.clone(),
            source_settlement_id: profile.source_settlement_id.clone(),
            result_head: receipt.result_head,
            result_tree: receipt.result_tree,
            subject_digest: requested_subject.to_owned(),
        };
        let basis = AgTypedObservationBasisV1 {
            schema: AG_TYPED_OBSERVATION_BASIS_SCHEMA_V1.into(),
            basis_type: QUALIFICATION_APPLICABILITY_SCHEMA_V1.into(),
            basis_identity: jcs_sha256(&applicability)?,
        };
        let normalized_preconditions =
            ag_domain_digest(AG_TYPED_OBSERVATION_BASIS_SCHEMA_V1, &basis)?;
        let natural_horizon = receipt
            .evaluated_at_unix_ms
            .checked_add(profile.max_age_ms)
            .ok_or_else(|| "qualification freshness horizon overflow".to_owned())?;
        let fresh_until_unix_ms = if status == AgTypedObservationStatusV1::Current {
            natural_horizon
        } else {
            now_unix_ms.saturating_add(1)
        };
        let currentness = jcs_sha256(&serde_json::json!({
            "schema": "nightshift.repository-qualification-currentness/v1",
            "receipt": receipt.receipt_sha256,
            "source_state": source.state_digest,
            "source_snapshot": source.snapshot_digest,
            "status": status,
            "resolved_at_unix_ms": now_unix_ms,
        }))?;
        Ok(QualificationApplicabilityOutcomeV1::Observation(Box::new(
            AgQualificationObservationResolutionV3 {
                schema: AG_OBSERVATION_RESOLUTION_SCHEMA_V3.into(),
                key: AgOccurrenceKeyV1 {
                    campaign: target_campaign_id.into(),
                    occurrence: target_occurrence_id.into(),
                },
                observation: requested_observation.into(),
                currentness,
                normalized_preconditions,
                basis,
                resolver_id: profile.resolver_id.clone(),
                subject: requested_subject.into(),
                status,
                resolved_at_unix_ms: now_unix_ms,
                fresh_until_unix_ms,
            },
        )))
    }
}

fn qualification_observation_id(
    profile: &QualificationApplicabilityProfileV1,
    receipt: &NqReceiptV1,
) -> Result<String, String> {
    jcs_sha256(&serde_json::json!({
        "schema": "nightshift.repository-qualification-observation/v1",
        "applicability_profile": profile.profile_id,
        "receipt": receipt.receipt_sha256,
        "subject": profile.subject_digest,
    }))
}

pub fn retained_qualification_observation_id(
    profile: &QualificationApplicabilityProfileV1,
    receipt_json: &serde_json::Value,
) -> Result<String, String> {
    let receipt: NqReceiptV1 = serde_json::from_value(receipt_json.clone())
        .map_err(|error| format!("invalid NQ qualification receipt: {error}"))?;
    qualification_observation_id(profile, &receipt)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationApplicabilityV1 {
    pub schema: String,
    pub applicability_profile_id: String,
    pub nq_receipt_id: String,
    pub nq_receipt_sha256: String,
    pub source_campaign_id: String,
    pub source_occurrence_id: String,
    pub source_state_digest: String,
    pub source_snapshot_digest: String,
    pub source_attempt_id: String,
    pub source_settlement_id: String,
    pub result_head: GitObjectBindingV1,
    pub result_tree: GitObjectBindingV1,
    pub subject_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgOccurrenceKeyV1 {
    pub campaign: String,
    pub occurrence: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgTypedObservationBasisV1 {
    pub schema: String,
    pub basis_type: String,
    pub basis_identity: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgTypedObservationStatusV1 {
    Current,
    Stale,
    Superseded,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgQualificationObservationResolutionV3 {
    pub schema: String,
    pub key: AgOccurrenceKeyV1,
    pub observation: String,
    pub currentness: String,
    pub normalized_preconditions: String,
    pub basis: AgTypedObservationBasisV1,
    pub resolver_id: String,
    pub subject: String,
    pub status: AgTypedObservationStatusV1,
    pub resolved_at_unix_ms: u64,
    pub fresh_until_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "disposition", rename_all = "snake_case")]
pub enum QualificationApplicabilityOutcomeV1 {
    Observation(Box<AgQualificationObservationResolutionV3>),
    RetainedOnly {
        receipt_id: String,
        status: NqQualificationStatusV1,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_store::AG_REFERENCE_SCHEMA_V1;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn git(byte: char) -> GitObjectBindingV1 {
        GitObjectBindingV1 {
            object_format: "sha1".into(),
            digest: byte.to_string().repeat(40),
        }
    }

    struct FakeVerifier {
        executable: String,
        replays: usize,
        refuse: bool,
    }

    impl QualificationReceiptVerifierV1 for FakeVerifier {
        fn executable_sha256(&self) -> Result<String, String> {
            Ok(self.executable.clone())
        }

        fn replay(
            &mut self,
            _: &serde_json::Value,
            _: &serde_json::Value,
            _: &serde_json::Value,
        ) -> Result<(), String> {
            self.replays += 1;
            if self.refuse {
                Err("replay mismatch".into())
            } else {
                Ok(())
            }
        }
    }

    fn source(profile: &QualificationApplicabilityProfileV1) -> AgOccurrenceReferenceV1 {
        let snapshot = serde_json::json!({"exact": "settled"});
        AgOccurrenceReferenceV1 {
            schema: AG_REFERENCE_SCHEMA_V1.into(),
            campaign_id: profile.source_campaign_id.clone(),
            occurrence_id: profile.source_occurrence_id.clone(),
            state_digest: digest('1'),
            snapshot_digest: jcs_sha256(&snapshot).unwrap(),
            program_counter: AgProgramCounterV1::SettledObservationRequired,
            docket_attempt_id: Some(profile.source_attempt_id.clone()),
            settlement_id: Some(profile.source_settlement_id.clone()),
            external_decision_request_id: None,
            exact_snapshot: snapshot,
        }
    }

    fn inputs(
        status: NqQualificationStatusV1,
        evaluated_at: u64,
        suffix: &str,
    ) -> (
        QualificationApplicabilityProfileV1,
        serde_json::Value,
        serde_json::Value,
        serde_json::Value,
        FakeVerifier,
    ) {
        let nq_profile = serde_json::json!({
            "schema": NQ_PROFILE_SCHEMA_V1,
            "profile_id": "nq-profile-1",
            "closed_fixture": true
        });
        let nq_evidence = serde_json::json!({
            "schema": NQ_EVIDENCE_SCHEMA_V1,
            "evidence_id": format!("evidence-{suffix}"),
            "facts": ["exact"]
        });
        let executable = digest('e');
        let mut receipt = NqReceiptV1 {
            schema: NQ_RECEIPT_SCHEMA_V1.into(),
            receipt_id: format!("receipt-{suffix}"),
            evaluator_id: "nq-ng.campaign-stage-qualification-evaluator/v1".into(),
            evaluator_version: "0.1.0".into(),
            evaluator_executable_sha256: executable.clone(),
            evaluated_at_unix_ms: evaluated_at,
            profile_id: "nq-profile-1".into(),
            profile_sha256: jcs_sha256(&nq_profile).unwrap(),
            evidence_id: format!("evidence-{suffix}"),
            evidence_sha256: jcs_sha256(&nq_evidence).unwrap(),
            campaign_packet_sha256: digest('c'),
            stage_id: "stage-1".into(),
            repository_id: "repo-1".into(),
            repository_ref: "refs/heads/campaign".into(),
            predecessor_head: git('2'),
            predecessor_tree: git('3'),
            result_head: git('4'),
            result_tree: git('5'),
            status,
            reasons: vec![serde_json::json!("fixture")],
            does_not_establish: NONCLAIMS.map(str::to_owned).to_vec(),
            receipt_sha256: String::new(),
        };
        let mut unsigned = receipt.clone();
        unsigned.receipt_sha256.clear();
        receipt.receipt_sha256 = jcs_sha256(&unsigned).unwrap();
        let profile = QualificationApplicabilityProfileV1 {
            schema: String::new(),
            profile_id: String::new(),
            expected_nq_profile_id: "nq-profile-1".into(),
            expected_nq_profile_sha256: jcs_sha256(&nq_profile).unwrap(),
            expected_nq_evaluator_id: "nq-ng.campaign-stage-qualification-evaluator/v1".into(),
            expected_nq_evaluator_version: "0.1.0".into(),
            expected_nq_evaluator_executable_sha256: executable.clone(),
            source_campaign_id: digest('a'),
            source_occurrence_id: "00000000-0000-4000-8000-000000000001".into(),
            source_attempt_id: "attempt-1".into(),
            source_settlement_id: "settlement-1".into(),
            expected_result_head: receipt.result_head.clone(),
            expected_result_tree: receipt.result_tree.clone(),
            subject_digest: digest('b'),
            resolver_id: "nightshift.repository-qualification-resolver/v1".into(),
            max_age_ms: 100,
        }
        .seal()
        .unwrap();
        (
            profile,
            nq_profile,
            nq_evidence,
            serde_json::to_value(receipt).unwrap(),
            FakeVerifier {
                executable,
                replays: 0,
                refuse: false,
            },
        )
    }

    fn store() -> (tempfile::TempDir, QualificationReceiptStoreV1) {
        let directory = tempfile::tempdir().unwrap();
        let store =
            QualificationReceiptStoreV1::open(&directory.path().join("qualification.db")).unwrap();
        (directory, store)
    }

    #[test]
    fn qualified_exact_receipt_becomes_current_typed_basis() {
        let (_directory, mut store) = store();
        let (profile, nq_profile, evidence, receipt, mut verifier) =
            inputs(NqQualificationStatusV1::Qualified, 1_000, "qualified");
        let retained = store
            .ingest(&profile, &nq_profile, &evidence, &receipt, &mut verifier)
            .unwrap();
        assert_eq!(verifier.replays, 1);
        assert_eq!(
            store.exact_retained_receipt(&retained.receipt_id).unwrap(),
            Some(receipt.clone())
        );
        let observation = retained_qualification_observation_id(&profile, &receipt).unwrap();
        let outcome = store
            .resolve_applicability(
                &profile,
                &source(&profile),
                &retained.receipt_id,
                &digest('d'),
                "00000000-0000-4000-8000-000000000002",
                &observation,
                &profile.subject_digest,
                1_050,
            )
            .unwrap();
        let QualificationApplicabilityOutcomeV1::Observation(resolution) = outcome else {
            panic!("qualified current receipt must create an observation")
        };
        assert_eq!(resolution.status, AgTypedObservationStatusV1::Current);
        assert_eq!(resolution.schema, AG_OBSERVATION_RESOLUTION_SCHEMA_V3);
        assert_eq!(
            resolution.basis.basis_type,
            QUALIFICATION_APPLICABILITY_SCHEMA_V1
        );
        assert_eq!(
            resolution.normalized_preconditions,
            ag_domain_digest(AG_TYPED_OBSERVATION_BASIS_SCHEMA_V1, &resolution.basis).unwrap()
        );
    }

    #[test]
    fn failed_and_indeterminate_are_retained_but_never_current() {
        for status in [
            NqQualificationStatusV1::Failed,
            NqQualificationStatusV1::Indeterminate,
        ] {
            let (_directory, mut store) = store();
            let (profile, nq_profile, evidence, receipt, mut verifier) =
                inputs(status, 1_000, "negative");
            let retained = store
                .ingest(&profile, &nq_profile, &evidence, &receipt, &mut verifier)
                .unwrap();
            let outcome = store
                .resolve_applicability(
                    &profile,
                    &source(&profile),
                    &retained.receipt_id,
                    &digest('d'),
                    "00000000-0000-4000-8000-000000000002",
                    &digest('f'),
                    &profile.subject_digest,
                    1_050,
                )
                .unwrap();
            assert!(matches!(
                outcome,
                QualificationApplicabilityOutcomeV1::RetainedOnly { status: actual, .. }
                    if actual == status
            ));
            assert_eq!(
                store.exact_retained_receipt(&retained.receipt_id).unwrap(),
                Some(receipt)
            );
        }
    }

    #[test]
    fn stale_applicability_does_not_invalidate_historical_receipt() {
        let (_directory, mut store) = store();
        let (profile, nq_profile, evidence, receipt, mut verifier) =
            inputs(NqQualificationStatusV1::Qualified, 1_000, "stale");
        let retained = store
            .ingest(&profile, &nq_profile, &evidence, &receipt, &mut verifier)
            .unwrap();
        let observation = retained_qualification_observation_id(&profile, &receipt).unwrap();
        let outcome = store
            .resolve_applicability(
                &profile,
                &source(&profile),
                &retained.receipt_id,
                &digest('d'),
                "00000000-0000-4000-8000-000000000002",
                &observation,
                &profile.subject_digest,
                1_100,
            )
            .unwrap();
        assert!(matches!(
            outcome,
            QualificationApplicabilityOutcomeV1::Observation(resolution)
                if resolution.status == AgTypedObservationStatusV1::Stale
        ));
        assert_eq!(
            store.exact_retained_receipt(&retained.receipt_id).unwrap(),
            Some(receipt)
        );
    }

    #[test]
    fn substitution_and_unreplayed_evidence_refuse_ingress() {
        let cases = ["profile", "evidence", "evaluator", "replay"];
        for case in cases {
            let (_directory, mut store) = store();
            let (mut profile, mut nq_profile, mut evidence, receipt, mut verifier) =
                inputs(NqQualificationStatusV1::Qualified, 1_000, case);
            match case {
                "profile" => nq_profile["profile_id"] = serde_json::json!("substituted"),
                "evidence" => evidence["facts"] = serde_json::json!(["substituted"]),
                "evaluator" => profile.expected_nq_evaluator_executable_sha256 = digest('f'),
                "replay" => verifier.refuse = true,
                _ => unreachable!(),
            }
            assert!(store
                .ingest(&profile, &nq_profile, &evidence, &receipt, &mut verifier)
                .is_err());
        }
    }

    #[test]
    fn wrong_live_predecessor_and_observation_substitution_refuse() {
        let (_directory, mut store) = store();
        let (profile, nq_profile, evidence, receipt, mut verifier) =
            inputs(NqQualificationStatusV1::Qualified, 1_000, "binding");
        let retained = store
            .ingest(&profile, &nq_profile, &evidence, &receipt, &mut verifier)
            .unwrap();
        let mut wrong_source = source(&profile);
        wrong_source.settlement_id = Some("other-settlement".into());
        assert!(store
            .resolve_applicability(
                &profile,
                &wrong_source,
                &retained.receipt_id,
                &digest('d'),
                "00000000-0000-4000-8000-000000000002",
                &digest('f'),
                &profile.subject_digest,
                1_050,
            )
            .is_err());
        assert!(store
            .resolve_applicability(
                &profile,
                &source(&profile),
                &retained.receipt_id,
                &digest('d'),
                "00000000-0000-4000-8000-000000000002",
                &digest('f'),
                &profile.subject_digest,
                1_050,
            )
            .is_err());
    }
}

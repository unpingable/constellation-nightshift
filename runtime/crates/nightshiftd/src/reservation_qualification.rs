//! Applicability for an exact NQ realization of an external evidence reservation.
//!
//! Nightshift retains the complete NQ-qualified runtime chain and alone states
//! whether that one realization is presently applicable. A reservation by
//! itself is never Current. Conflicting realizations are retained and never
//! resolved by choosing a winner. This module grants no continuation authority.

use std::path::{Path, PathBuf};
use std::process::Command;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::canonical_store::{AgOccurrenceReferenceV1, AgProgramCounterV1};
use crate::repository_qualification::{
    AgOccurrenceKeyV1, AgQualificationObservationResolutionV3, AgTypedObservationBasisV1,
    AgTypedObservationStatusV1, GitObjectBindingV1, NqQualificationStatusV1,
    AG_OBSERVATION_RESOLUTION_SCHEMA_V3, AG_TYPED_OBSERVATION_BASIS_SCHEMA_V1,
};

pub const RESERVATION_APPLICABILITY_PROFILE_SCHEMA_V1: &str =
    "nightshift.repository-qualification-reservation-applicability-profile/v1";
pub const RESERVATION_APPLICABILITY_BASIS_TYPE_V1: &str =
    "nightshift.repository-qualification-reservation-applicability/v1";
pub const NQ_REALIZATION_PROFILE_SCHEMA_V2: &str = "nq-ng.campaign-stage-realization-profile/v2";
pub const NQ_REALIZATION_EVIDENCE_SCHEMA_V2: &str = "nq-ng.campaign-stage-realization-evidence/v2";
pub const NQ_REALIZATION_RECEIPT_SCHEMA_V2: &str =
    "nq-ng.campaign-stage-realization-qualification/v2";
pub const NQ_REALIZATION_REPLAY_SCHEMA_V2: &str = "nq-ng.campaign-stage-realization-replay/v2";

const NONCLAIMS: [&str; 7] = [
    "standing",
    "authorization",
    "successor choice",
    "continuation",
    "effect authority",
    "freshness or present applicability",
    "reservation validity outside this exact profile",
];

type RetainedRealizationRow = (String, Vec<u8>, Vec<u8>, Vec<u8>, i64);

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
pub struct ReservationApplicabilityProfileV1 {
    pub schema: String,
    pub profile_id: String,
    pub evidence_reservation: String,
    pub expected_nq_profile_id: String,
    pub expected_nq_profile_sha256: String,
    pub expected_nq_evaluator_id: String,
    pub expected_nq_evaluator_version: String,
    pub expected_nq_evaluator_executable_sha256: String,
    pub source_campaign_id: String,
    pub source_occurrence_id: String,
    pub source_attempt_id: String,
    pub source_settlement_id: String,
    pub subject_digest: String,
    pub resolver_id: String,
    pub max_age_ms: u64,
}

impl ReservationApplicabilityProfileV1 {
    pub fn seal(mut self) -> Result<Self, String> {
        self.schema = RESERVATION_APPLICABILITY_PROFILE_SCHEMA_V1.into();
        self.profile_id.clear();
        self.profile_id = object_id(&self, "profile_id")?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != RESERVATION_APPLICABILITY_PROFILE_SCHEMA_V1 {
            return Err("unsupported reservation-applicability profile schema".into());
        }
        for (name, value) in [
            ("profile_id", &self.profile_id),
            ("evidence_reservation", &self.evidence_reservation),
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
        if self.expected_nq_evaluator_id != "nq-ng.campaign-stage-realization-evaluator/v2"
            || self.max_age_ms == 0
            || self.profile_id != object_id(self, "profile_id")?
        {
            return Err("reservation-applicability profile is not the closed v1 profile".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExactRealizationChainV2 {
    evidence_reservation: String,
    docket_attempt: String,
    executor_plan_template: String,
    executor_plan: String,
    docket_settlement: String,
    porter_run_id: String,
    porter_record_sha256: String,
    executor_receipt: String,
    predecessor_head: GitObjectBindingV1,
    predecessor_tree: GitObjectBindingV1,
    result_head: GitObjectBindingV1,
    result_tree: GitObjectBindingV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NqRealizationReceiptV2 {
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
    evidence_reservation: String,
    campaign_packet_sha256: String,
    stage_id: String,
    repository_id: String,
    repository_ref: String,
    realizations: Vec<ExactRealizationChainV2>,
    status: NqQualificationStatusV1,
    reasons: Vec<serde_json::Value>,
    does_not_establish: Vec<String>,
    receipt_sha256: String,
}

impl NqRealizationReceiptV2 {
    fn validate_integrity(&self) -> Result<(), String> {
        if self.schema != NQ_REALIZATION_RECEIPT_SCHEMA_V2 {
            return Err("unsupported NQ realization receipt schema".into());
        }
        for (name, value) in [
            ("receipt_sha256", &self.receipt_sha256),
            ("profile_sha256", &self.profile_sha256),
            ("evidence_sha256", &self.evidence_sha256),
            ("campaign_packet_sha256", &self.campaign_packet_sha256),
            ("evidence_reservation", &self.evidence_reservation),
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
            return Err("NQ realization receipt digest mismatch".into());
        }
        if self.does_not_establish != NONCLAIMS.map(str::to_owned) {
            return Err("NQ realization receipt nonclaims changed".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NqReplayV2 {
    schema: String,
    matches: bool,
    expected_receipt_sha256: String,
    recomputed_receipt_sha256: String,
}

pub trait ReservationQualificationVerifierV1 {
    fn executable_sha256(&self) -> Result<String, String>;
    fn replay(
        &mut self,
        profile: &serde_json::Value,
        evidence: &serde_json::Value,
        receipt: &serde_json::Value,
    ) -> Result<(), String>;
}

pub struct NqNgReservationVerifierV1 {
    program: PathBuf,
}

impl NqNgReservationVerifierV1 {
    pub fn new(program: impl Into<PathBuf>) -> Result<Self, String> {
        let program = program.into();
        if program.file_name().and_then(|name| name.to_str()) != Some("nq") {
            return Err("reservation verifier accepts only nq".into());
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

impl ReservationQualificationVerifierV1 for NqNgReservationVerifierV1 {
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
                "campaign-stage-realization",
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
            .map_err(|error| format!("NQ realization replay failed to start: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "NQ realization replay refused: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let replay: NqReplayV2 = serde_json::from_slice(&output.stdout)
            .map_err(|error| format!("NQ realization replay returned invalid JSON: {error}"))?;
        if replay.schema != NQ_REALIZATION_REPLAY_SCHEMA_V2
            || !replay.matches
            || replay.expected_receipt_sha256 != replay.recomputed_receipt_sha256
        {
            return Err("NQ realization replay did not reproduce the receipt".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RetainedReservationRealizationV1 {
    pub evidence_reservation: String,
    pub receipt_id: String,
    pub receipt_sha256: String,
    pub status: NqQualificationStatusV1,
    pub evaluated_at_unix_ms: u64,
    pub conflict: bool,
}

pub struct ReservationRealizationStoreV1 {
    connection: Connection,
}

impl ReservationRealizationStoreV1 {
    pub fn open(path: &Path) -> Result<Self, String> {
        let connection = Connection::open(path).map_err(|error| error.to_string())?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE IF NOT EXISTS reservation_realizations (
                   evidence_reservation TEXT PRIMARY KEY,
                   receipt_id TEXT NOT NULL,
                   receipt_sha256 TEXT NOT NULL,
                   status TEXT NOT NULL,
                   evaluated_at_unix_ms INTEGER NOT NULL,
                   applicability_profile_id TEXT NOT NULL,
                   conflict INTEGER NOT NULL DEFAULT 0,
                   exact_profile_json BLOB NOT NULL,
                   exact_evidence_json BLOB NOT NULL,
                   exact_receipt_json BLOB NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS reservation_realization_conflicts (
                   evidence_reservation TEXT NOT NULL,
                   receipt_sha256 TEXT NOT NULL,
                   exact_profile_json BLOB NOT NULL,
                   exact_evidence_json BLOB NOT NULL,
                   exact_receipt_json BLOB NOT NULL,
                   PRIMARY KEY(evidence_reservation, receipt_sha256)
                 );",
            )
            .map_err(|error| error.to_string())?;
        Ok(Self { connection })
    }

    pub fn open_read_only(path: &Path) -> Result<Self, String> {
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|error| error.to_string())?;
        Ok(Self { connection })
    }

    pub fn ingest<V: ReservationQualificationVerifierV1>(
        &mut self,
        applicability: &ReservationApplicabilityProfileV1,
        nq_profile: &serde_json::Value,
        nq_evidence: &serde_json::Value,
        nq_receipt: &serde_json::Value,
        verifier: &mut V,
    ) -> Result<RetainedReservationRealizationV1, String> {
        applicability.validate()?;
        let receipt: NqRealizationReceiptV2 = serde_json::from_value(nq_receipt.clone())
            .map_err(|error| format!("invalid NQ realization receipt: {error}"))?;
        receipt.validate_integrity()?;
        let profile_schema = nq_profile.get("schema").and_then(|v| v.as_str());
        let evidence_schema = nq_evidence.get("schema").and_then(|v| v.as_str());
        let profile_id = nq_profile.get("profile_id").and_then(|v| v.as_str());
        let profile_sha256 = jcs_sha256(nq_profile)?;
        let evidence_sha256 = jcs_sha256(nq_evidence)?;
        if profile_schema != Some(NQ_REALIZATION_PROFILE_SCHEMA_V2)
            || evidence_schema != Some(NQ_REALIZATION_EVIDENCE_SCHEMA_V2)
            || profile_id != Some(applicability.expected_nq_profile_id.as_str())
            || profile_sha256 != applicability.expected_nq_profile_sha256
            || receipt.profile_id != applicability.expected_nq_profile_id
            || receipt.profile_sha256 != profile_sha256
            || receipt.evidence_sha256 != evidence_sha256
            || receipt.evidence_reservation != applicability.evidence_reservation
            || receipt.evaluator_id != applicability.expected_nq_evaluator_id
            || receipt.evaluator_version != applicability.expected_nq_evaluator_version
            || receipt.evaluator_executable_sha256
                != applicability.expected_nq_evaluator_executable_sha256
            || verifier.executable_sha256()?
                != applicability.expected_nq_evaluator_executable_sha256
        {
            return Err("reservation realization profile/evidence/evaluator mismatch".into());
        }
        if receipt
            .realizations
            .iter()
            .any(|chain| chain.evidence_reservation != applicability.evidence_reservation)
            || (receipt.status == NqQualificationStatusV1::Qualified
                && receipt.realizations.len() != 1)
        {
            return Err(
                "NQ receipt does not retain one exact qualified reservation realization".into(),
            );
        }
        verifier.replay(nq_profile, nq_evidence, nq_receipt)?;
        let profile_bytes = serde_jcs::to_vec(nq_profile).map_err(|error| error.to_string())?;
        let evidence_bytes = serde_jcs::to_vec(nq_evidence).map_err(|error| error.to_string())?;
        let receipt_bytes = serde_jcs::to_vec(nq_receipt).map_err(|error| error.to_string())?;
        let status = match receipt.status {
            NqQualificationStatusV1::Qualified => "QUALIFIED",
            NqQualificationStatusV1::Failed => "FAILED",
            NqQualificationStatusV1::Indeterminate => "INDETERMINATE",
        };
        let prior: Option<RetainedRealizationRow> = self
            .connection
            .query_row(
                "SELECT receipt_sha256, exact_profile_json, exact_evidence_json,
                        exact_receipt_json, conflict FROM reservation_realizations
                 WHERE evidence_reservation=?1",
                [&applicability.evidence_reservation],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let conflict = if let Some((
            prior_sha,
            prior_profile,
            prior_evidence,
            prior_receipt,
            prior_conflict,
        )) = prior
        {
            if prior_sha == receipt.receipt_sha256
                && prior_profile == profile_bytes
                && prior_evidence == evidence_bytes
                && prior_receipt == receipt_bytes
            {
                prior_conflict != 0
            } else {
                self.connection.execute(
                    "INSERT OR IGNORE INTO reservation_realization_conflicts
                     (evidence_reservation,receipt_sha256,exact_profile_json,exact_evidence_json,exact_receipt_json)
                     VALUES(?1,?2,?3,?4,?5)",
                    params![applicability.evidence_reservation, receipt.receipt_sha256, profile_bytes, evidence_bytes, receipt_bytes],
                ).map_err(|error| error.to_string())?;
                self.connection.execute(
                    "UPDATE reservation_realizations SET conflict=1 WHERE evidence_reservation=?1",
                    [&applicability.evidence_reservation],
                ).map_err(|error| error.to_string())?;
                true
            }
        } else {
            self.connection.execute(
                "INSERT INTO reservation_realizations
                 (evidence_reservation,receipt_id,receipt_sha256,status,evaluated_at_unix_ms,
                  applicability_profile_id,conflict,exact_profile_json,exact_evidence_json,exact_receipt_json)
                 VALUES(?1,?2,?3,?4,?5,?6,0,?7,?8,?9)",
                params![applicability.evidence_reservation, receipt.receipt_id, receipt.receipt_sha256,
                    status, receipt.evaluated_at_unix_ms, applicability.profile_id,
                    profile_bytes, evidence_bytes, receipt_bytes],
            ).map_err(|error| error.to_string())?;
            false
        };
        Ok(RetainedReservationRealizationV1 {
            evidence_reservation: applicability.evidence_reservation.clone(),
            receipt_id: receipt.receipt_id,
            receipt_sha256: receipt.receipt_sha256,
            status: receipt.status,
            evaluated_at_unix_ms: receipt.evaluated_at_unix_ms,
            conflict,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn resolve_applicability(
        &self,
        profile: &ReservationApplicabilityProfileV1,
        source: &AgOccurrenceReferenceV1,
        target_campaign_id: &str,
        target_occurrence_id: &str,
        requested_observation: &str,
        requested_subject: &str,
        now_unix_ms: u64,
    ) -> Result<ReservationApplicabilityOutcomeV1, String> {
        profile.validate()?;
        source.validate().map_err(|error| error.to_string())?;
        require_digest("target_campaign_id", target_campaign_id)?;
        uuid::Uuid::parse_str(target_occurrence_id)
            .map_err(|_| "target_occurrence_id must be a UUID".to_owned())?;
        if source.campaign_id != profile.source_campaign_id
            || source.occurrence_id != profile.source_occurrence_id
            || source.program_counter != AgProgramCounterV1::SettledObservationRequired
            || source.docket_attempt_id.as_deref() != Some(profile.source_attempt_id.as_str())
            || source.settlement_id.as_deref() != Some(profile.source_settlement_id.as_str())
            || requested_subject != profile.subject_digest
            || requested_observation != profile.evidence_reservation
        {
            return Err(
                "reservation realization is not applicable to the exact settled predecessor".into(),
            );
        }
        let row: Option<(Vec<u8>, i64)> = self.connection.query_row(
            "SELECT exact_receipt_json, conflict FROM reservation_realizations WHERE evidence_reservation=?1",
            [&profile.evidence_reservation],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().map_err(|error| error.to_string())?;
        let Some((receipt_bytes, conflict)) = row else {
            return Ok(ReservationApplicabilityOutcomeV1::Absent);
        };
        let receipt: NqRealizationReceiptV2 =
            serde_json::from_slice(&receipt_bytes).map_err(|error| error.to_string())?;
        if conflict != 0 || receipt.status != NqQualificationStatusV1::Qualified {
            return Ok(ReservationApplicabilityOutcomeV1::RetainedOnly {
                receipt_id: receipt.receipt_id,
                status: receipt.status,
                conflict: conflict != 0,
            });
        }
        let natural_horizon = receipt
            .evaluated_at_unix_ms
            .checked_add(profile.max_age_ms)
            .ok_or_else(|| "reservation qualification freshness horizon overflow".to_owned())?;
        let status = if now_unix_ms >= natural_horizon {
            AgTypedObservationStatusV1::Stale
        } else {
            AgTypedObservationStatusV1::Current
        };
        let basis = AgTypedObservationBasisV1 {
            schema: AG_TYPED_OBSERVATION_BASIS_SCHEMA_V1.into(),
            basis_type: RESERVATION_APPLICABILITY_BASIS_TYPE_V1.into(),
            basis_identity: profile.evidence_reservation.clone(),
        };
        let normalized_preconditions =
            ag_domain_digest(AG_TYPED_OBSERVATION_BASIS_SCHEMA_V1, &basis)?;
        let currentness = jcs_sha256(&serde_json::json!({
            "schema": "nightshift.repository-qualification-reservation-currentness/v1",
            "reservation": profile.evidence_reservation,
            "receipt": receipt.receipt_sha256,
            "realizations": receipt.realizations,
            "source_state": source.state_digest,
            "source_snapshot": source.snapshot_digest,
            "status": status,
            "resolved_at_unix_ms": now_unix_ms,
        }))?;
        Ok(ReservationApplicabilityOutcomeV1::Observation(Box::new(
            AgQualificationObservationResolutionV3 {
                schema: AG_OBSERVATION_RESOLUTION_SCHEMA_V3.into(),
                key: AgOccurrenceKeyV1 {
                    campaign: target_campaign_id.into(),
                    occurrence: target_occurrence_id.into(),
                },
                observation: profile.evidence_reservation.clone(),
                currentness,
                normalized_preconditions,
                basis,
                resolver_id: profile.resolver_id.clone(),
                subject: requested_subject.into(),
                status,
                resolved_at_unix_ms: now_unix_ms,
                fresh_until_unix_ms: if status == AgTypedObservationStatusV1::Current {
                    natural_horizon
                } else {
                    now_unix_ms.saturating_add(1)
                },
            },
        )))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "disposition", rename_all = "snake_case")]
pub enum ReservationApplicabilityOutcomeV1 {
    Observation(Box<AgQualificationObservationResolutionV3>),
    RetainedOnly {
        receipt_id: String,
        status: NqQualificationStatusV1,
        conflict: bool,
    },
    Absent,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_store::AG_REFERENCE_SCHEMA_V1;
    use tempfile::TempDir;

    fn digest(value: char) -> String {
        format!("sha256:{}", value.to_string().repeat(64))
    }

    fn git(value: char) -> GitObjectBindingV1 {
        GitObjectBindingV1 {
            object_format: "sha1".into(),
            digest: value.to_string().repeat(40),
        }
    }

    struct FakeVerifier {
        executable: String,
        replays: usize,
    }

    impl ReservationQualificationVerifierV1 for FakeVerifier {
        fn executable_sha256(&self) -> Result<String, String> {
            Ok(self.executable.clone())
        }

        fn replay(
            &mut self,
            _profile: &serde_json::Value,
            _evidence: &serde_json::Value,
            _receipt: &serde_json::Value,
        ) -> Result<(), String> {
            self.replays += 1;
            Ok(())
        }
    }

    fn fixture(
        status: NqQualificationStatusV1,
    ) -> (
        TempDir,
        ReservationApplicabilityProfileV1,
        serde_json::Value,
        serde_json::Value,
        serde_json::Value,
        FakeVerifier,
        AgOccurrenceReferenceV1,
    ) {
        let temporary = TempDir::new().unwrap();
        let reservation = digest('1');
        let nq_profile = serde_json::json!({
            "schema": NQ_REALIZATION_PROFILE_SCHEMA_V2,
            "profile_id": "velvet-pigeon/stage-1"
        });
        let nq_evidence = serde_json::json!({
            "schema": NQ_REALIZATION_EVIDENCE_SCHEMA_V2,
            "evidence_id": "runtime-evidence-1"
        });
        let executable = digest('2');
        let applicability = ReservationApplicabilityProfileV1 {
            schema: String::new(),
            profile_id: String::new(),
            evidence_reservation: reservation.clone(),
            expected_nq_profile_id: "velvet-pigeon/stage-1".into(),
            expected_nq_profile_sha256: jcs_sha256(&nq_profile).unwrap(),
            expected_nq_evaluator_id: "nq-ng.campaign-stage-realization-evaluator/v2".into(),
            expected_nq_evaluator_version: "0.1.0".into(),
            expected_nq_evaluator_executable_sha256: executable.clone(),
            source_campaign_id: digest('3'),
            source_occurrence_id: "00000000-0000-0000-0000-000000000001".into(),
            source_attempt_id: digest('4'),
            source_settlement_id: digest('5'),
            subject_digest: digest('6'),
            resolver_id: "nightshift.reservation-qualification-resolver/v1".into(),
            max_age_ms: 1_000,
        }
        .seal()
        .unwrap();
        let chain = ExactRealizationChainV2 {
            evidence_reservation: reservation.clone(),
            docket_attempt: digest('4'),
            executor_plan_template: digest('7'),
            executor_plan: digest('8'),
            docket_settlement: digest('5'),
            porter_run_id: "fresh-runtime-run".into(),
            porter_record_sha256: digest('9'),
            executor_receipt: digest('a'),
            predecessor_head: git('b'),
            predecessor_tree: git('c'),
            result_head: git('d'),
            result_tree: git('e'),
        };
        let mut receipt = NqRealizationReceiptV2 {
            schema: NQ_REALIZATION_RECEIPT_SCHEMA_V2.into(),
            receipt_id: "reservation-qualification:stage-1:evidence-1".into(),
            evaluator_id: applicability.expected_nq_evaluator_id.clone(),
            evaluator_version: applicability.expected_nq_evaluator_version.clone(),
            evaluator_executable_sha256: executable.clone(),
            evaluated_at_unix_ms: 100,
            profile_id: applicability.expected_nq_profile_id.clone(),
            profile_sha256: jcs_sha256(&nq_profile).unwrap(),
            evidence_id: "runtime-evidence-1".into(),
            evidence_sha256: jcs_sha256(&nq_evidence).unwrap(),
            evidence_reservation: reservation,
            campaign_packet_sha256: digest('f'),
            stage_id: "stage-1".into(),
            repository_id: "fixture/repository".into(),
            repository_ref: "refs/heads/main".into(),
            realizations: vec![chain],
            status,
            reasons: vec![],
            does_not_establish: NONCLAIMS.map(str::to_owned).to_vec(),
            receipt_sha256: String::new(),
        };
        receipt.receipt_sha256 = jcs_sha256(&receipt).unwrap();
        let exact_snapshot = serde_json::json!({"state":"settled-observation-required"});
        let source = AgOccurrenceReferenceV1 {
            schema: AG_REFERENCE_SCHEMA_V1.into(),
            campaign_id: applicability.source_campaign_id.clone(),
            occurrence_id: applicability.source_occurrence_id.clone(),
            state_digest: digest('0'),
            snapshot_digest: jcs_sha256(&exact_snapshot).unwrap(),
            program_counter: AgProgramCounterV1::SettledObservationRequired,
            docket_attempt_id: Some(applicability.source_attempt_id.clone()),
            settlement_id: Some(applicability.source_settlement_id.clone()),
            external_decision_request_id: None,
            exact_snapshot,
        };
        (
            temporary,
            applicability,
            nq_profile,
            nq_evidence,
            serde_json::to_value(receipt).unwrap(),
            FakeVerifier {
                executable,
                replays: 0,
            },
            source,
        )
    }

    #[test]
    fn exact_replay_is_idempotent_and_basis_identity_is_reservation() {
        let (temporary, applicability, profile, evidence, receipt, mut verifier, source) =
            fixture(NqQualificationStatusV1::Qualified);
        let mut store =
            ReservationRealizationStoreV1::open(&temporary.path().join("store.db")).unwrap();
        let first = store
            .ingest(&applicability, &profile, &evidence, &receipt, &mut verifier)
            .unwrap();
        let replay = store
            .ingest(&applicability, &profile, &evidence, &receipt, &mut verifier)
            .unwrap();
        assert_eq!(first, replay);
        assert!(!replay.conflict);
        let outcome = store
            .resolve_applicability(
                &applicability,
                &source,
                &digest('a'),
                "00000000-0000-0000-0000-000000000002",
                &applicability.evidence_reservation,
                &applicability.subject_digest,
                200,
            )
            .unwrap();
        let ReservationApplicabilityOutcomeV1::Observation(resolution) = outcome else {
            panic!("qualified exact realization must resolve");
        };
        assert_eq!(resolution.status, AgTypedObservationStatusV1::Current);
        assert_eq!(
            resolution.basis.basis_type,
            RESERVATION_APPLICABILITY_BASIS_TYPE_V1
        );
        assert_eq!(
            resolution.basis.basis_identity,
            applicability.evidence_reservation
        );
        assert_eq!(verifier.replays, 2);
    }

    #[test]
    fn different_realization_is_retained_conflict_and_never_current() {
        let (temporary, applicability, profile, evidence, receipt, mut verifier, source) =
            fixture(NqQualificationStatusV1::Qualified);
        let mut store =
            ReservationRealizationStoreV1::open(&temporary.path().join("store.db")).unwrap();
        store
            .ingest(&applicability, &profile, &evidence, &receipt, &mut verifier)
            .unwrap();
        let mut conflicting: NqRealizationReceiptV2 = serde_json::from_value(receipt).unwrap();
        conflicting.receipt_id.push_str("-different");
        conflicting.realizations[0].porter_run_id = "different-runtime-run".into();
        conflicting.receipt_sha256.clear();
        conflicting.receipt_sha256 = jcs_sha256(&conflicting).unwrap();
        let conflicting = serde_json::to_value(conflicting).unwrap();
        let retained = store
            .ingest(
                &applicability,
                &profile,
                &evidence,
                &conflicting,
                &mut verifier,
            )
            .unwrap();
        assert!(retained.conflict);
        let outcome = store
            .resolve_applicability(
                &applicability,
                &source,
                &digest('a'),
                "00000000-0000-0000-0000-000000000002",
                &applicability.evidence_reservation,
                &applicability.subject_digest,
                200,
            )
            .unwrap();
        assert!(matches!(
            outcome,
            ReservationApplicabilityOutcomeV1::RetainedOnly { conflict: true, .. }
        ));
    }

    #[test]
    fn failed_or_absent_reservation_never_becomes_current() {
        let (temporary, applicability, profile, evidence, receipt, mut verifier, source) =
            fixture(NqQualificationStatusV1::Failed);
        let mut store =
            ReservationRealizationStoreV1::open(&temporary.path().join("store.db")).unwrap();
        let absent = store
            .resolve_applicability(
                &applicability,
                &source,
                &digest('a'),
                "00000000-0000-0000-0000-000000000002",
                &applicability.evidence_reservation,
                &applicability.subject_digest,
                200,
            )
            .unwrap();
        assert_eq!(absent, ReservationApplicabilityOutcomeV1::Absent);
        store
            .ingest(&applicability, &profile, &evidence, &receipt, &mut verifier)
            .unwrap();
        let failed = store
            .resolve_applicability(
                &applicability,
                &source,
                &digest('a'),
                "00000000-0000-0000-0000-000000000002",
                &applicability.evidence_reservation,
                &applicability.subject_digest,
                200,
            )
            .unwrap();
        assert!(matches!(
            failed,
            ReservationApplicabilityOutcomeV1::RetainedOnly {
                status: NqQualificationStatusV1::Failed,
                conflict: false,
                ..
            }
        ));
    }
}

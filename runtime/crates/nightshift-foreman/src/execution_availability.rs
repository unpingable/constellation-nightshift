//! Provider-neutral provider-execution availability and deferred-dispatch contracts.
//!
//! These records describe mechanism evidence only. They grant no target-effect,
//! approval-response, semantic-retry, provider-account, or production authority.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};
use serde::{
    de::{DeserializeOwned, Error as _, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::contract::{ContractError, ExecutionProfileV2, WorkerStartRequestV2};

#[path = "provider_snapshot_translation.rs"]
mod provider_snapshot_translation;
pub use provider_snapshot_translation::derive_provider_deferral;
pub use provider_snapshot_translation::derive_provider_snapshot_evidence;

pub const EXECUTION_AVAILABILITY_OBSERVATION_SCHEMA_V1: &str =
    "nightshift.provider-execution-availability-observation/v1";
pub const EXECUTION_AVAILABILITY_POLICY_SCHEMA_V1: &str =
    "nightshift.provider-execution-availability-policy/v1";
pub const FOREMAN_EXECUTION_AVAILABILITY_REQUIREMENT_SCHEMA_V1: &str =
    "nightshift.foreman-execution-availability-requirement/v1";
pub const PROVIDER_DISPATCH_OCCURRENCE_SCHEMA_V1: &str =
    "nightshift.provider-dispatch-occurrence/v1";
pub const PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V1: &str =
    "nightshift.provider-admission-disposition/v1";
pub const PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V2: &str =
    "nightshift.provider-admission-disposition/v2";
pub const PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V3: &str =
    "nightshift.provider-admission-disposition/v3";
pub const DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V1: &str =
    "nightshift.holding-deterministic-provider-admission-evidence/v1";
pub const DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V2: &str =
    "nightshift.holding-deterministic-provider-admission-evidence/v2";
pub const DEFERRED_PROVIDER_DISPATCH_SCHEMA_V1: &str = "nightshift.deferred-provider-dispatch/v1";
pub const WORKER_START_REQUEST_SCHEMA_V3: &str = "nightshift.worker-start-request/v3";

pub const ACCEPTED_CODEX_PROVIDER_ADMISSION_OWNER_HEAD: &str =
    "c36a8137638decf8b04a49611354a90f32c5a945";
pub const ACCEPTED_SWITCHYARD_PROVIDER_ADMISSION_OWNER_HEAD: &str =
    "2ba25db66d8b29dd215bd87e05f4ea794024b3b7";
// Explicit integration candidate enrollment; not inherited qualification.
const FINAL_CODEX_OWNER_HEAD: &str = "97b0acd5ce2ccb3c87a763606696c35a450947f6";
const PRIOR_FINAL_SWITCHYARD_OWNER_HEAD: &str = "4f85615ef6ebe5483ab96afe6e046b4ea10566c6";
const FINAL_SWITCHYARD_OWNER_HEAD: &str = "c01fb1ee586d33a5031d1d928ce40fcabfb4f4f2";
// Corrected source-export candidate: every exported blob is read from this
// immutable revision and the export manifest verifies the complete closure.
const SOURCE_EXPORT_VERIFIED_SWITCHYARD_OWNER_HEAD: &str =
    "3ba607c950a28c922b26d6dfa66ee06095158dc9";
// Packaging successor: runner body is unchanged from the source-export
// candidate while its install metadata and public-safe smoke checks are closed.
const PACKAGED_RUNTIME_SWITCHYARD_OWNER_HEAD: &str = "7df43b4e15cb1465f434e072b4233a2e5825c0ca";
// Independently frozen bounded-custody successor; selection needs new route approval.
const BOUNDED_TURN_SWITCHYARD_OWNER_HEAD: &str = "8479cb77dc76632e64b66e84c4f75c9765e421a6";
// Candidate only; finalized from the independently frozen Switchyard successor.
const BOUNDED_TURN_ECHO_SWITCHYARD_OWNER_HEAD: &str = "805e84d777eaab57c2108919ce43b09828e6e1ef";
const PRIOR_BOUNDED_TURN_ECHO_SWITCHYARD_OWNER_HEAD: &str =
    "6fe1084dc1a0e8e39a5a6c2bc108b39ace682724";
const EARLIER_BOUNDED_TURN_ECHO_SWITCHYARD_OWNER_HEAD: &str =
    "ce5a3a0be8f90162581c820b85b2a785557aae24";
const BOUNDED_TURN_ECHO_SWITCHYARD_SCHEMA_SHA256: &str =
    "sha256:c851fb5dd157ebb70896da06db50a07b968b3c0d357b2defc73ca267b9d82f93";
const BOUNDED_TURN_ECHO_SWITCHYARD_SCHEMA_BYTES: &[u8] = include_bytes!(
    "../../../schemas/vendor/switchyard.codex-provider-admission.bounded-turn-echo.v2.schema.json"
);
#[path = "bounded_turn_echo.rs"]
mod bounded_turn_echo;
const BOUNDED_TURN_SWITCHYARD_SCHEMA_SHA256: &str =
    "sha256:4e4eac904735c570f3fe7332765fffe4608cc3987fee9c1ef4b8db3ffdf03376";
const BOUNDED_TURN_SWITCHYARD_SCHEMA_BYTES: &[u8] = include_bytes!(
    "../../../schemas/vendor/switchyard.codex-provider-admission.bounded-turn.v1.schema.json"
);
const FINAL_SWITCHYARD_SCHEMA_SHA256: &str =
    "sha256:0e9c851cc9fad9538408ab44d84737d5f4d4d7ef39f2fd5db20c6f88fc7fbb9e";
const FINAL_SWITCHYARD_SCHEMA_BYTES: &[u8] = include_bytes!(
    "../../../schemas/vendor/switchyard.codex-provider-admission.beta-final.v1.schema.json"
);
const BETA_CODEX_OWNER_HEAD: &str = "6893ae42233aa95b1c1623497405681d99a589da";
const BETA_SWITCHYARD_OWNER_HEAD: &str = "2207bb6ca19690a2c218fffe6c69e429eee24eb5";
pub const ACCEPTED_SWITCHYARD_PROVIDER_ADMISSION_SCHEMA_SHA256: &str =
    "sha256:131f1f6e0cf8cb0aea26ed225c584440c81ffedd443c68ace23adecbe493cf93";
const BETA_SWITCHYARD_SCHEMA_SHA256: &str =
    "sha256:448c2535c9c9586754d222912bbc86bc09fadb3c98059dc134141aff08efb8ba";
pub const ACCEPTED_SWITCHYARD_DETERMINISTIC_FIXTURE_SHA256: &str =
    "sha256:cafa673ac58f60029fd6c1de229b4f57d9f42ba918b7ecb2a3bfb20cb2b41a31";
pub const MAXIMUM_AVAILABILITY_EVIDENCE_BYTES: usize = 16 * 1024;
pub const MAXIMUM_TURN_START_REQUEST_EVIDENCE_BYTES: usize = 256 * 1024;
pub const MAXIMUM_SWITCHYARD_MAPPER_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;
pub const MAXIMUM_DISPATCH_OCCURRENCES: u16 = 16;
pub const MAXIMUM_TOTAL_DEFERRAL_SECONDS: u64 = 7 * 24 * 60 * 60;

const OBSERVATION_DOMAIN: &[u8] =
    b"nightshift.provider-execution-availability-observation.digest/v1\0";
const POLICY_DOMAIN: &[u8] = b"nightshift.provider-execution-availability-policy.digest/v1\0";
const REQUIREMENT_DOMAIN: &[u8] =
    b"nightshift.foreman-execution-availability-requirement.digest/v1\0";
const DISPATCH_DOMAIN: &[u8] = b"nightshift.provider-dispatch-occurrence.digest/v1\0";
const DISPOSITION_DOMAIN: &[u8] = b"nightshift.provider-admission-disposition.digest/v1\0";
const DISPOSITION_DOMAIN_V2: &[u8] = b"nightshift.provider-admission-disposition.digest/v2\0";
const DISPOSITION_DOMAIN_V3: &[u8] = b"nightshift.provider-admission-disposition.digest/v3\0";
const QUALIFICATION_EVIDENCE_DOMAIN: &[u8] =
    b"nightshift.holding-deterministic-provider-admission-evidence.digest/v1\0";
const QUALIFICATION_EVIDENCE_DOMAIN_V2: &[u8] =
    b"nightshift.holding-deterministic-provider-admission-evidence.digest/v2\0";
const DEFERRED_DOMAIN: &[u8] = b"nightshift.deferred-provider-dispatch.digest/v1\0";
const WORKER_START_REQUEST_DOMAIN_V3: &[u8] = b"nightshift.worker-start-request.digest/v3\0";
const SWITCHYARD_PROVIDER_ADMISSION_SCHEMA_BYTES: &[u8] =
    include_bytes!("../../../schemas/vendor/switchyard.codex-provider-admission.v1.schema.json");
const BETA_SWITCHYARD_SCHEMA_BYTES: &[u8] = include_bytes!(
    "../../../schemas/vendor/switchyard.codex-provider-admission.beta.v1.schema.json"
);

pub const HOLDING_QUALIFICATION_PRODUCER_ID: &str =
    "nightshift:holding-pattern-deterministic-fake-adapter";
pub const HOLDING_QUALIFICATION_PRODUCER_VERSION: &str = "v1";
pub const HOLDING_QUALIFICATION_EXECUTABLE_ID: &str =
    "campaign:holding-pattern:deterministic-fake-adapter:v1";
pub const HOLDING_QUALIFICATION_EXECUTABLE_SHA256: &str =
    "sha256:e8a310d46cb40b0aef6399a8da6c97ac99f0fc5eab6a78c5e7007600d5cbfa82";
pub const SECOND_WATCH_QUALIFICATION_PRODUCER_VERSION: &str = "v2";
pub const SECOND_WATCH_QUALIFICATION_EXECUTABLE_ID: &str =
    "campaign:second-watch:deterministic-fake-adapter:v2";
pub const SECOND_WATCH_QUALIFICATION_EXECUTABLE_SHA256: &str =
    "sha256:bcfea17f0aff021d6b69f2b3d924e7606bf74941671a5a7af13e2d1e3d43edd4";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactAvailabilityEvidenceV1 {
    pub representation: String,
    pub byte_length: u64,
    pub sha256: String,
    pub encoding: String,
    pub bytes_hex: String,
}

impl ExactAvailabilityEvidenceV1 {
    pub fn from_bytes(
        representation: impl Into<String>,
        raw: &[u8],
    ) -> Result<Self, ContractError> {
        if raw.is_empty() || raw.len() > MAXIMUM_AVAILABILITY_EVIDENCE_BYTES {
            return Err(ContractError::InvalidField("availability evidence bytes"));
        }
        let value = Self {
            representation: representation.into(),
            byte_length: raw.len() as u64,
            sha256: plain_sha256(raw),
            encoding: "hex".to_owned(),
            bytes_hex: hex::encode(raw),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<Vec<u8>, ContractError> {
        if !matches!(
            self.representation.as_str(),
            "EXACT_PROVIDER_AVAILABILITY_SOURCE_BYTES"
                | "EXACT_WIRE_BYTES_INCLUDING_LINE_TERMINATOR"
                | "EXACT_ACQUIRED_FRAME_BYTES_INCLUDING_LINE_TERMINATOR"
        ) {
            return Err(ContractError::InvalidField(
                "availability evidence representation",
            ));
        }
        digest("evidence sha256", &self.sha256)?;
        if self.encoding != "hex"
            || self.byte_length == 0
            || self.byte_length as usize > MAXIMUM_AVAILABILITY_EVIDENCE_BYTES
            || self.bytes_hex.len() != self.byte_length as usize * 2
            || self
                .bytes_hex
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(ContractError::InvalidField(
                "availability evidence encoding",
            ));
        }
        let raw = hex::decode(&self.bytes_hex)
            .map_err(|_| ContractError::InvalidField("availability evidence hex"))?;
        if plain_sha256(&raw) != self.sha256 {
            return Err(ContractError::DigestMismatch(
                "availability evidence sha256",
            ));
        }
        Ok(raw)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeterministicProviderAdmissionOutcomeV1 {
    RateLimited,
    ProviderUnavailable,
    AuthenticationRefused,
    TransportError,
    ProtocolError,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeterministicProviderAdmissionEvidenceV1 {
    pub schema: String,
    pub evidence_digest: String,
    pub producer_id: String,
    pub producer_version: String,
    pub executable_id: String,
    pub executable_sha256: String,
    pub work_attempt_id: String,
    pub dispatch_occurrence_id: String,
    pub provider_request_occurrence_id: String,
    pub provider_id: String,
    pub model_id: String,
    pub outcome: DeterministicProviderAdmissionOutcomeV1,
    pub response_created: bool,
    pub non_admission_proven: bool,
    pub retry_after: Option<DateTime<Utc>>,
    pub observed_at: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
    pub raw_evidence: ExactAvailabilityEvidenceV1,
    pub authority_effect: String,
}

impl DeterministicProviderAdmissionEvidenceV1 {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ContractError> {
        let value: Value = parse(bytes)?;
        for field in ["observed_at", "received_at"] {
            canonical_timestamp(&value, field)?;
        }
        canonical_optional_timestamp(&value, "retry_after")?;
        serde_json::from_value(value).map_err(json_error)
    }

    pub fn seal(&mut self) -> Result<(), ContractError> {
        self.evidence_digest =
            digest_without(self, "evidence_digest", QUALIFICATION_EVIDENCE_DOMAIN)?;
        self.validate()
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        schema(
            &self.schema,
            DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V1,
        )?;
        sealed_digest(
            self,
            "evidence_digest",
            &self.evidence_digest,
            QUALIFICATION_EVIDENCE_DOMAIN,
        )?;
        for (field, value) in [
            ("producer_id", &self.producer_id),
            ("producer_version", &self.producer_version),
            ("executable_id", &self.executable_id),
            ("work_attempt_id", &self.work_attempt_id),
            ("dispatch_occurrence_id", &self.dispatch_occurrence_id),
            (
                "provider_request_occurrence_id",
                &self.provider_request_occurrence_id,
            ),
            ("provider_id", &self.provider_id),
            ("model_id", &self.model_id),
        ] {
            id(field, value)?;
        }
        digest("executable_sha256", &self.executable_sha256)?;
        let raw = self.raw_evidence.validate()?;
        if self.producer_id != HOLDING_QUALIFICATION_PRODUCER_ID
            || self.producer_version != HOLDING_QUALIFICATION_PRODUCER_VERSION
            || self.executable_id != HOLDING_QUALIFICATION_EXECUTABLE_ID
            || self.executable_sha256 != HOLDING_QUALIFICATION_EXECUTABLE_SHA256
            || self.raw_evidence.representation != "EXACT_PROVIDER_AVAILABILITY_SOURCE_BYTES"
            || self.observed_at > self.received_at
            || self
                .retry_after
                .is_some_and(|value| value < self.received_at)
            || self.authority_effect != "QUALIFICATION_MECHANISM_EVIDENCE_ONLY"
        {
            return Err(ContractError::InvalidField(
                "deterministic provider evidence boundary",
            ));
        }
        let raw_value: Value = parse(&raw)?;
        if serde_jcs::to_vec(&raw_value).map_err(json_error)? != raw {
            return Err(ContractError::InvalidField(
                "deterministic provider raw canonical bytes",
            ));
        }
        let raw_object = raw_value.as_object().ok_or(ContractError::InvalidField(
            "deterministic provider raw object",
        ))?;
        let expected_keys = [
            "outcome",
            "response_created",
            "non_admission_proven",
            "retry_after",
            "observed_at",
        ];
        if raw_object.len() != expected_keys.len()
            || expected_keys
                .iter()
                .any(|key| !raw_object.contains_key(*key))
            || raw_object.get("outcome")
                != Some(&serde_json::to_value(self.outcome).map_err(json_error)?)
            || raw_object.get("response_created") != Some(&Value::Bool(self.response_created))
            || raw_object.get("non_admission_proven")
                != Some(&Value::Bool(self.non_admission_proven))
            || raw_object.get("retry_after")
                != Some(&serde_json::to_value(self.retry_after).map_err(json_error)?)
            || raw_object.get("observed_at")
                != Some(&serde_json::to_value(self.observed_at).map_err(json_error)?)
        {
            return Err(ContractError::InvalidField(
                "deterministic provider raw binding",
            ));
        }
        match self.outcome {
            DeterministicProviderAdmissionOutcomeV1::RateLimited
            | DeterministicProviderAdmissionOutcomeV1::ProviderUnavailable => {
                if self.response_created || !self.non_admission_proven {
                    return Err(ContractError::InvalidField(
                        "qualified explicit non-admission",
                    ));
                }
            }
            DeterministicProviderAdmissionOutcomeV1::AuthenticationRefused => {
                if self.response_created || !self.non_admission_proven || self.retry_after.is_some()
                {
                    return Err(ContractError::InvalidField(
                        "qualified authentication refusal",
                    ));
                }
            }
            DeterministicProviderAdmissionOutcomeV1::TransportError
            | DeterministicProviderAdmissionOutcomeV1::ProtocolError => {
                if self.non_admission_proven || self.retry_after.is_some() {
                    return Err(ContractError::InvalidField(
                        "qualified indeterminate admission",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeterministicProviderAdmissionOutcomeV2 {
    ProviderUnavailable,
    ExecutionCompleted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeterministicProviderAdmissionEvidenceV2 {
    pub schema: String,
    pub evidence_digest: String,
    pub producer_id: String,
    pub producer_version: String,
    pub executable_id: String,
    pub executable_sha256: String,
    pub work_attempt_id: String,
    pub dispatch_occurrence_id: String,
    pub provider_request_occurrence_id: String,
    pub provider_id: String,
    pub model_id: String,
    pub outcome: DeterministicProviderAdmissionOutcomeV2,
    pub response_created: bool,
    pub non_admission_proven: bool,
    pub retry_after: Option<DateTime<Utc>>,
    pub observed_at: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
    pub provider_execution: Option<ProviderExecutionIdentityV1>,
    pub raw_evidence: ExactAvailabilityEvidenceV1,
    pub authority_effect: String,
}

impl DeterministicProviderAdmissionEvidenceV2 {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ContractError> {
        let value: Value = parse(bytes)?;
        for field in ["observed_at", "received_at"] {
            canonical_timestamp(&value, field)?;
        }
        canonical_optional_timestamp(&value, "retry_after")?;
        serde_json::from_value(value).map_err(json_error)
    }

    pub fn seal(&mut self) -> Result<(), ContractError> {
        self.evidence_digest =
            digest_without(self, "evidence_digest", QUALIFICATION_EVIDENCE_DOMAIN_V2)?;
        self.validate()
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        schema(
            &self.schema,
            DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V2,
        )?;
        sealed_digest(
            self,
            "evidence_digest",
            &self.evidence_digest,
            QUALIFICATION_EVIDENCE_DOMAIN_V2,
        )?;
        for (field, value) in [
            ("producer_id", &self.producer_id),
            ("producer_version", &self.producer_version),
            ("executable_id", &self.executable_id),
            ("work_attempt_id", &self.work_attempt_id),
            ("dispatch_occurrence_id", &self.dispatch_occurrence_id),
            (
                "provider_request_occurrence_id",
                &self.provider_request_occurrence_id,
            ),
            ("provider_id", &self.provider_id),
            ("model_id", &self.model_id),
        ] {
            id(field, value)?;
        }
        digest("executable_sha256", &self.executable_sha256)?;
        let raw = self.raw_evidence.validate()?;
        if self.producer_id != HOLDING_QUALIFICATION_PRODUCER_ID
            || self.producer_version != SECOND_WATCH_QUALIFICATION_PRODUCER_VERSION
            || self.executable_id != SECOND_WATCH_QUALIFICATION_EXECUTABLE_ID
            || self.executable_sha256 != SECOND_WATCH_QUALIFICATION_EXECUTABLE_SHA256
            || self.raw_evidence.representation != "EXACT_PROVIDER_AVAILABILITY_SOURCE_BYTES"
            || self.observed_at > self.received_at
            || self
                .retry_after
                .is_some_and(|value| value < self.received_at)
            || self.authority_effect != "QUALIFICATION_MECHANISM_EVIDENCE_ONLY"
        {
            return Err(ContractError::InvalidField(
                "deterministic provider execution evidence boundary",
            ));
        }
        let raw_value: Value = parse(&raw)?;
        if serde_jcs::to_vec(&raw_value).map_err(json_error)? != raw {
            return Err(ContractError::InvalidField(
                "deterministic provider execution raw canonical bytes",
            ));
        }
        let raw_object = raw_value.as_object().ok_or(ContractError::InvalidField(
            "deterministic provider execution raw object",
        ))?;
        let expected_keys = [
            "outcome",
            "response_created",
            "non_admission_proven",
            "retry_after",
            "observed_at",
            "provider_execution",
        ];
        if raw_object.len() != expected_keys.len()
            || expected_keys
                .iter()
                .any(|key| !raw_object.contains_key(*key))
            || raw_object.get("outcome")
                != Some(&serde_json::to_value(self.outcome).map_err(json_error)?)
            || raw_object.get("response_created") != Some(&Value::Bool(self.response_created))
            || raw_object.get("non_admission_proven")
                != Some(&Value::Bool(self.non_admission_proven))
            || raw_object.get("retry_after")
                != Some(&serde_json::to_value(self.retry_after).map_err(json_error)?)
            || raw_object.get("observed_at")
                != Some(&serde_json::to_value(self.observed_at).map_err(json_error)?)
            || raw_object.get("provider_execution")
                != Some(&serde_json::to_value(&self.provider_execution).map_err(json_error)?)
        {
            return Err(ContractError::InvalidField(
                "deterministic provider execution raw binding",
            ));
        }
        match self.outcome {
            DeterministicProviderAdmissionOutcomeV2::ProviderUnavailable => {
                if self.response_created
                    || !self.non_admission_proven
                    || self.provider_execution.is_some()
                    || self.retry_after.is_none()
                {
                    return Err(ContractError::InvalidField(
                        "qualified v2 explicit non-admission",
                    ));
                }
            }
            DeterministicProviderAdmissionOutcomeV2::ExecutionCompleted => {
                let execution =
                    self.provider_execution
                        .as_ref()
                        .ok_or(ContractError::InvalidField(
                            "qualified v2 execution identity",
                        ))?;
                execution.validate()?;
                if !self.response_created
                    || self.non_admission_proven
                    || self.retry_after.is_some()
                    || execution.provider_id != self.provider_id
                    || execution.model_id != self.model_id
                {
                    return Err(ContractError::InvalidField(
                        "qualified v2 completed execution",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactMapperSnapshotV1 {
    pub representation: String,
    pub byte_length: u64,
    pub sha256: String,
    pub encoding: String,
    pub bytes_hex: String,
}

impl ExactMapperSnapshotV1 {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, ContractError> {
        if raw.is_empty() || raw.len() > MAXIMUM_SWITCHYARD_MAPPER_SNAPSHOT_BYTES {
            return Err(ContractError::InvalidField("mapper snapshot bytes"));
        }
        let value = Self {
            representation: "RFC8785_SWITCHYARD_MAPPER_SNAPSHOT".to_owned(),
            byte_length: raw.len() as u64,
            sha256: plain_sha256(raw),
            encoding: "hex".to_owned(),
            bytes_hex: hex::encode(raw),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn from_qualification_evidence_bytes(raw: &[u8]) -> Result<Self, ContractError> {
        if raw.is_empty() || raw.len() > MAXIMUM_SWITCHYARD_MAPPER_SNAPSHOT_BYTES {
            return Err(ContractError::InvalidField("mapper snapshot bytes"));
        }
        let value = Self {
            representation: "RFC8785_NIGHTSHIFT_QUALIFICATION_FAKE_ADAPTER_EVIDENCE".to_owned(),
            byte_length: raw.len() as u64,
            sha256: plain_sha256(raw),
            encoding: "hex".to_owned(),
            bytes_hex: hex::encode(raw),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<Vec<u8>, ContractError> {
        digest("mapper snapshot sha256", &self.sha256)?;
        if !matches!(
            self.representation.as_str(),
            "RFC8785_SWITCHYARD_MAPPER_SNAPSHOT"
                | "RFC8785_NIGHTSHIFT_QUALIFICATION_FAKE_ADAPTER_EVIDENCE"
        ) || self.encoding != "hex"
            || self.byte_length == 0
            || self.byte_length as usize > MAXIMUM_SWITCHYARD_MAPPER_SNAPSHOT_BYTES
            || self.bytes_hex.len() != self.byte_length as usize * 2
            || self
                .bytes_hex
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(ContractError::InvalidField("mapper snapshot encoding"));
        }
        let raw = hex::decode(&self.bytes_hex)
            .map_err(|_| ContractError::InvalidField("mapper snapshot hex"))?;
        if plain_sha256(&raw) != self.sha256 {
            return Err(ContractError::DigestMismatch("mapper snapshot sha256"));
        }
        Ok(raw)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionAvailabilityStateV1 {
    Available,
    ModelAtCapacity,
    ProviderUnavailable,
    RateLimited,
    AuthenticationRefused,
    TransportError,
    ProtocolError,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAvailabilityObservationV1 {
    pub schema: String,
    pub observation_digest: String,
    pub provider_id: String,
    pub model_id: String,
    pub model_class: String,
    pub observed_at: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub state: ExecutionAvailabilityStateV1,
    pub source_identity: String,
    pub source_version: String,
    pub provider_retry_after: Option<DateTime<Utc>>,
    pub exact_evidence: Option<ExactAvailabilityEvidenceV1>,
    pub authority_effect: String,
}

impl ExecutionAvailabilityObservationV1 {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ContractError> {
        let value: Value = parse(bytes)?;
        for field in ["observed_at", "received_at", "expires_at"] {
            canonical_timestamp(&value, field)?;
        }
        canonical_optional_timestamp(&value, "provider_retry_after")?;
        serde_json::from_value(value).map_err(json_error)
    }
    pub fn seal(&mut self) -> Result<(), ContractError> {
        self.observation_digest = digest_without(self, "observation_digest", OBSERVATION_DOMAIN)?;
        self.validate()
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        schema(&self.schema, EXECUTION_AVAILABILITY_OBSERVATION_SCHEMA_V1)?;
        sealed_digest(
            self,
            "observation_digest",
            &self.observation_digest,
            OBSERVATION_DOMAIN,
        )?;
        for (field, value) in [
            ("provider_id", &self.provider_id),
            ("model_id", &self.model_id),
            ("model_class", &self.model_class),
            ("source_identity", &self.source_identity),
            ("source_version", &self.source_version),
        ] {
            id(field, value)?;
        }
        if self.observed_at > self.received_at || self.received_at >= self.expires_at {
            return Err(ContractError::InvalidField(
                "availability observation time order",
            ));
        }
        if self
            .provider_retry_after
            .is_some_and(|retry_after| retry_after < self.received_at)
        {
            return Err(ContractError::InvalidField("provider_retry_after"));
        }
        match (&self.state, &self.exact_evidence) {
            (ExecutionAvailabilityStateV1::Unknown, None) => {}
            (_, Some(evidence)) => {
                evidence.validate()?;
            }
            _ => return Err(ContractError::InvalidField("availability evidence absence")),
        }
        if self.authority_effect != "SCHEDULING_MECHANISM_EVIDENCE_ONLY" {
            return Err(ContractError::InvalidField("availability authority effect"));
        }
        Ok(())
    }
    pub fn is_current_at(&self, evaluated_at: DateTime<Utc>) -> bool {
        self.received_at <= evaluated_at && evaluated_at < self.expires_at
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ParkedResourceLockPolicyV1 {
    ReleaseAndReacquire,
    RetainWhileParked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAvailabilityPolicyV1 {
    pub schema: String,
    pub policy_digest: String,
    pub policy_id: String,
    pub maximum_dispatch_occurrences_per_attempt: u16,
    pub backoff_seconds: Vec<u64>,
    pub maximum_total_deferral_seconds: u64,
    pub parked_resource_lock_policy: ParkedResourceLockPolicyV1,
    pub provider_capacity_released_while_parked: bool,
    pub reconcile_indeterminate: bool,
    pub allow_ordered_model_fallback: bool,
    pub automatic_semantic_retry: bool,
    pub approval_response_authorized: bool,
    pub authority_effect: String,
}

impl ExecutionAvailabilityPolicyV1 {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ContractError> {
        parse(bytes)
    }
    pub fn seal(&mut self) -> Result<(), ContractError> {
        self.policy_digest = digest_without(self, "policy_digest", POLICY_DOMAIN)?;
        self.validate()
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        schema(&self.schema, EXECUTION_AVAILABILITY_POLICY_SCHEMA_V1)?;
        sealed_digest(self, "policy_digest", &self.policy_digest, POLICY_DOMAIN)?;
        id("policy_id", &self.policy_id)?;
        let total = self
            .backoff_seconds
            .iter()
            .try_fold(0_u64, |sum, value| sum.checked_add(*value));
        if !(1..=MAXIMUM_DISPATCH_OCCURRENCES)
            .contains(&self.maximum_dispatch_occurrences_per_attempt)
            || self.backoff_seconds.is_empty()
            || self.backoff_seconds.len()
                > usize::from(self.maximum_dispatch_occurrences_per_attempt)
            || self
                .backoff_seconds
                .iter()
                .any(|seconds| *seconds == 0 || *seconds > 86_400)
            || self.maximum_total_deferral_seconds == 0
            || self.maximum_total_deferral_seconds > MAXIMUM_TOTAL_DEFERRAL_SECONDS
            || total.is_none_or(|sum| sum > self.maximum_total_deferral_seconds)
            || !self.provider_capacity_released_while_parked
            || !self.reconcile_indeterminate
            || self.automatic_semantic_retry
            || self.approval_response_authorized
            || self.authority_effect != "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY"
        {
            return Err(ContractError::InvalidField("availability policy boundary"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAdmissionOwnerPinsV1 {
    pub codex_owner_head: String,
    pub switchyard_owner_head: String,
    pub switchyard_schema_sha256: String,
    pub deterministic_fixture_sha256: String,
}

impl ProviderAdmissionOwnerPinsV1 {
    /// Closed user echo and 32KiB output custody; separately enrolled, never fallback.
    pub fn bounded_turn_echo_candidate() -> Self {
        Self {
            codex_owner_head: FINAL_CODEX_OWNER_HEAD.to_owned(),
            switchyard_owner_head: BOUNDED_TURN_ECHO_SWITCHYARD_OWNER_HEAD.to_owned(),
            switchyard_schema_sha256: BOUNDED_TURN_ECHO_SWITCHYARD_SCHEMA_SHA256.to_owned(),
            ..Self::accepted()
        }
    }
    /// Prior echo tuple retained for exact prelaunch-closure reconciliation.
    pub fn prior_bounded_turn_echo_candidate() -> Self {
        Self {
            codex_owner_head: FINAL_CODEX_OWNER_HEAD.to_owned(),
            switchyard_owner_head: PRIOR_BOUNDED_TURN_ECHO_SWITCHYARD_OWNER_HEAD.to_owned(),
            switchyard_schema_sha256:
                "sha256:2bcf795c753a08d3c7e2ef8b521b44b155054fccbd50452662230d59ddd3f293".to_owned(),
            ..Self::accepted()
        }
    }
    pub fn earlier_bounded_turn_echo_candidate() -> Self {
        Self {
            codex_owner_head: FINAL_CODEX_OWNER_HEAD.to_owned(),
            switchyard_owner_head: EARLIER_BOUNDED_TURN_ECHO_SWITCHYARD_OWNER_HEAD.to_owned(),
            switchyard_schema_sha256:
                "sha256:2bcf795c753a08d3c7e2ef8b521b44b155054fccbd50452662230d59ddd3f293".to_owned(),
            ..Self::accepted()
        }
    }

    fn is_bounded_turn_echo(&self) -> bool {
        self == &Self::bounded_turn_echo_candidate()
            || self == &Self::prior_bounded_turn_echo_candidate()
            || self == &Self::earlier_bounded_turn_echo_candidate()
    }
    /// Separately selected bounded-request-custody source; never an automatic fallback.
    pub fn bounded_turn_candidate() -> Self {
        Self {
            codex_owner_head: FINAL_CODEX_OWNER_HEAD.to_owned(),
            switchyard_owner_head: BOUNDED_TURN_SWITCHYARD_OWNER_HEAD.to_owned(),
            switchyard_schema_sha256: BOUNDED_TURN_SWITCHYARD_SCHEMA_SHA256.to_owned(),
            ..Self::accepted()
        }
    }
    /// Candidate with the runner's declared installation closure.
    pub fn packaged_runtime_candidate() -> Self {
        Self {
            codex_owner_head: FINAL_CODEX_OWNER_HEAD.to_owned(),
            switchyard_owner_head: PACKAGED_RUNTIME_SWITCHYARD_OWNER_HEAD.to_owned(),
            switchyard_schema_sha256: FINAL_SWITCHYARD_SCHEMA_SHA256.to_owned(),
            ..Self::accepted()
        }
    }

    /// Candidate whose Switchyard source export is bound to one immutable revision.
    pub fn source_export_verified_candidate() -> Self {
        Self {
            codex_owner_head: FINAL_CODEX_OWNER_HEAD.to_owned(),
            switchyard_owner_head: SOURCE_EXPORT_VERIFIED_SWITCHYARD_OWNER_HEAD.to_owned(),
            switchyard_schema_sha256: FINAL_SWITCHYARD_SCHEMA_SHA256.to_owned(),
            ..Self::accepted()
        }
    }

    /// Historical pre-precision-correction tuple, retained for exact replay.
    pub fn prior_final_beta_candidate() -> Self {
        Self {
            switchyard_owner_head: PRIOR_FINAL_SWITCHYARD_OWNER_HEAD.to_owned(),
            ..Self::final_beta_candidate()
        }
    }

    /// Explicit final candidate; prior tuples remain historical replay inputs.
    pub fn final_beta_candidate() -> Self {
        Self {
            codex_owner_head: FINAL_CODEX_OWNER_HEAD.to_owned(),
            switchyard_owner_head: FINAL_SWITCHYARD_OWNER_HEAD.to_owned(),
            switchyard_schema_sha256: FINAL_SWITCHYARD_SCHEMA_SHA256.to_owned(),
            ..Self::accepted()
        }
    }

    /// Exact beta integration candidate; never selected as an automatic fallback.
    pub fn beta_candidate() -> Self {
        Self {
            codex_owner_head: BETA_CODEX_OWNER_HEAD.to_owned(),
            switchyard_owner_head: BETA_SWITCHYARD_OWNER_HEAD.to_owned(),
            switchyard_schema_sha256: BETA_SWITCHYARD_SCHEMA_SHA256.to_owned(),
            ..Self::accepted()
        }
    }
    pub fn accepted() -> Self {
        Self {
            codex_owner_head: ACCEPTED_CODEX_PROVIDER_ADMISSION_OWNER_HEAD.to_owned(),
            switchyard_owner_head: ACCEPTED_SWITCHYARD_PROVIDER_ADMISSION_OWNER_HEAD.to_owned(),
            switchyard_schema_sha256: ACCEPTED_SWITCHYARD_PROVIDER_ADMISSION_SCHEMA_SHA256
                .to_owned(),
            deterministic_fixture_sha256: ACCEPTED_SWITCHYARD_DETERMINISTIC_FIXTURE_SHA256
                .to_owned(),
        }
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        if self != &Self::accepted()
            && self != &Self::bounded_turn_echo_candidate()
            && self != &Self::prior_bounded_turn_echo_candidate()
            && self != &Self::earlier_bounded_turn_echo_candidate()
            && self != &Self::bounded_turn_candidate()
            && self != &Self::beta_candidate()
            && self != &Self::prior_final_beta_candidate()
            && self != &Self::final_beta_candidate()
            && self != &Self::source_export_verified_candidate()
            && self != &Self::packaged_runtime_candidate()
        {
            return Err(ContractError::InvalidField("provider admission owner pins"));
        }
        Ok(())
    }

    pub fn adapter_owner_head(&self) -> &str {
        &self.switchyard_owner_head
    }

    pub fn adapter_schema_sha256(&self) -> &str {
        &self.switchyard_schema_sha256
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderModelSelectionV1 {
    pub provider_id: String,
    pub model_id: String,
    pub model_class: String,
}

impl ProviderModelSelectionV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        id("selection provider_id", &self.provider_id)?;
        id("selection model_id", &self.model_id)?;
        id("selection model_class", &self.model_class)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForemanExecutionAvailabilityRequirementV1 {
    pub schema: String,
    pub requirement_digest: String,
    pub packet_digest: String,
    pub admission_digest: String,
    pub profile_digest: String,
    pub run_id: String,
    pub adapter_id: String,
    pub adapter_protocol: String,
    pub adapter_version: String,
    pub adapter_executable_identity: String,
    pub owner_pins: ProviderAdmissionOwnerPinsV1,
    pub policy_id: String,
    pub policy_digest: String,
    pub work_item_model_selections: BTreeMap<String, Vec<ProviderModelSelectionV1>>,
    pub admitted_at: DateTime<Utc>,
    pub authority_effect: String,
}

impl ForemanExecutionAvailabilityRequirementV1 {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ContractError> {
        let value: Value = parse(bytes)?;
        canonical_timestamp(&value, "admitted_at")?;
        serde_json::from_value(value).map_err(json_error)
    }
    pub fn seal(&mut self) -> Result<(), ContractError> {
        self.requirement_digest = digest_without(self, "requirement_digest", REQUIREMENT_DOMAIN)?;
        self.validate()
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        schema(
            &self.schema,
            FOREMAN_EXECUTION_AVAILABILITY_REQUIREMENT_SCHEMA_V1,
        )?;
        sealed_digest(
            self,
            "requirement_digest",
            &self.requirement_digest,
            REQUIREMENT_DOMAIN,
        )?;
        for (field, value) in [
            ("packet_digest", &self.packet_digest),
            ("admission_digest", &self.admission_digest),
            ("profile_digest", &self.profile_digest),
            (
                "adapter_executable_identity",
                &self.adapter_executable_identity,
            ),
            ("policy_digest", &self.policy_digest),
        ] {
            digest(field, value)?;
        }
        for (field, value) in [
            ("run_id", &self.run_id),
            ("adapter_id", &self.adapter_id),
            ("adapter_protocol", &self.adapter_protocol),
            ("adapter_version", &self.adapter_version),
            ("policy_id", &self.policy_id),
        ] {
            id(field, value)?;
        }
        self.owner_pins.validate()?;
        if self.work_item_model_selections.is_empty()
            || self.work_item_model_selections.len() > 1024
        {
            return Err(ContractError::InvalidField("work-item model selections"));
        }
        for (work_item, selections) in &self.work_item_model_selections {
            id("work_item_id", work_item)?;
            if selections.is_empty() || selections.len() > 16 {
                return Err(ContractError::InvalidField("model selection count"));
            }
            let mut exact = BTreeSet::new();
            for selection in selections {
                selection.validate()?;
                if !exact.insert((
                    selection.provider_id.as_str(),
                    selection.model_id.as_str(),
                    selection.model_class.as_str(),
                )) {
                    return Err(ContractError::InvalidField("duplicate model selection"));
                }
            }
        }
        if self.authority_effect != "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY" {
            return Err(ContractError::InvalidField("requirement authority effect"));
        }
        Ok(())
    }
}

/// HOLDING-only start request. V3 does not replace or reinterpret V2: it
/// retains the exact canonical V2 request as an immutable predecessor and adds
/// the fresh dispatch occurrence and provider-selection boundary required by
/// provider-execution admission accounting.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerStartRequestV3 {
    pub schema: String,
    pub request_digest: String,
    pub predecessor_schema: String,
    pub predecessor_request_digest: String,
    pub predecessor_sha256: String,
    pub predecessor_encoding: String,
    pub predecessor_bytes_hex: String,
    pub packet_digest: String,
    pub profile_digest: String,
    pub run_id: String,
    pub work_item_id: String,
    pub attempt_id: String,
    pub work_attempt_id: String,
    pub dispatch_occurrence_id: String,
    pub adapter_id: String,
    pub adapter_version: String,
    pub adapter_protocol: String,
    pub worker_brief_digest: String,
    pub workspace_identity: String,
    pub provider_model_class: String,
    pub timeout_seconds: u64,
    pub maximum_output_bytes: u64,
    pub recursive_worker_swarms_forbidden: bool,
    pub approval_policy: String,
    pub expected_receipt_schema: String,
    pub provider_id: String,
    pub model_id: String,
    pub model_class: String,
    pub selected_model_ordinal: u16,
    pub provider_admission_adapter_protocol: String,
    pub provider_admission_binding_schema: String,
    pub provider_admission_evidence_schema: String,
    pub provider_admission_snapshot_schema: String,
    pub codex_owner_head: String,
    pub switchyard_owner_head: String,
    pub switchyard_schema_sha256: String,
    pub switchyard_deterministic_fixture_sha256: String,
    pub provider_execution_id: Option<String>,
    pub internal_provider_retry_count: u16,
    pub semantic_retry: bool,
    pub approval_response_authorized: bool,
    pub authority_effect: String,
}

impl WorkerStartRequestV3 {
    pub fn from_v2_for_dispatch(
        predecessor_bytes: &[u8],
        profile: &ExecutionProfileV2,
        requirement: &ForemanExecutionAvailabilityRequirementV1,
        dispatch_occurrence_id: impl Into<String>,
        selected_model_ordinal: u16,
    ) -> Result<Self, ContractError> {
        profile.validate()?;
        requirement.validate()?;
        if predecessor_bytes.is_empty() || predecessor_bytes.len() > 64 * 1024 {
            return Err(ContractError::InvalidField("V2 predecessor bytes"));
        }
        let predecessor: WorkerStartRequestV2 = parse(predecessor_bytes)?;
        predecessor.validate()?;
        if serde_jcs::to_vec(&predecessor).map_err(json_error)? != predecessor_bytes {
            return Err(ContractError::InvalidField(
                "canonical V2 predecessor bytes",
            ));
        }
        let selections = requirement
            .work_item_model_selections
            .get(&predecessor.work_item_id)
            .ok_or(ContractError::InvalidField("V3 work-item selection"))?;
        let selection = selections
            .get(usize::from(selected_model_ordinal))
            .ok_or(ContractError::InvalidField("V3 selected model ordinal"))?;
        let qualification_protocol = if predecessor.adapter_id == HOLDING_QUALIFICATION_PRODUCER_ID
            && predecessor.adapter_version == HOLDING_QUALIFICATION_PRODUCER_VERSION
            && predecessor.adapter_protocol == DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V1
        {
            Some(DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V1)
        } else if predecessor.adapter_id == HOLDING_QUALIFICATION_PRODUCER_ID
            && predecessor.adapter_version == SECOND_WATCH_QUALIFICATION_PRODUCER_VERSION
            && predecessor.adapter_protocol == DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V2
        {
            Some(DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V2)
        } else {
            None
        };
        let (admission_protocol, binding_schema, evidence_schema, snapshot_schema) =
            if let Some(protocol) = qualification_protocol {
                (protocol, protocol, protocol, protocol)
            } else {
                (
                    "switchyard.codex-app-server/v2",
                    "switchyard.codex-provider-admission-binding/v1",
                    "switchyard.codex-provider-admission-evidence/v1",
                    "switchyard.codex-provider-admission-snapshot/v1",
                )
            };
        let mut request = Self {
            schema: WORKER_START_REQUEST_SCHEMA_V3.to_owned(),
            request_digest: format!("sha256:{}", "0".repeat(64)),
            predecessor_schema: predecessor.schema.clone(),
            predecessor_request_digest: predecessor.request_digest.clone(),
            predecessor_sha256: plain_sha256(predecessor_bytes),
            predecessor_encoding: "hex".to_owned(),
            predecessor_bytes_hex: hex::encode(predecessor_bytes),
            packet_digest: predecessor.packet_digest.clone(),
            profile_digest: profile.profile_digest.clone(),
            run_id: predecessor.run_id.clone(),
            work_item_id: predecessor.work_item_id.clone(),
            attempt_id: predecessor.attempt_id.clone(),
            work_attempt_id: predecessor.attempt_id.clone(),
            dispatch_occurrence_id: dispatch_occurrence_id.into(),
            adapter_id: predecessor.adapter_id.clone(),
            adapter_version: predecessor.adapter_version.clone(),
            adapter_protocol: predecessor.adapter_protocol.clone(),
            worker_brief_digest: predecessor.worker_brief_digest.clone(),
            workspace_identity: predecessor.workspace_identity.clone(),
            provider_model_class: predecessor.provider_model_class.clone(),
            timeout_seconds: predecessor.timeout_seconds,
            maximum_output_bytes: predecessor.maximum_output_bytes,
            recursive_worker_swarms_forbidden: predecessor.recursive_worker_swarms_forbidden,
            approval_policy: predecessor.approval_policy.clone(),
            expected_receipt_schema: predecessor.expected_receipt_schema.clone(),
            provider_id: selection.provider_id.clone(),
            model_id: selection.model_id.clone(),
            model_class: selection.model_class.clone(),
            selected_model_ordinal,
            provider_admission_adapter_protocol: admission_protocol.to_owned(),
            provider_admission_binding_schema: binding_schema.to_owned(),
            provider_admission_evidence_schema: evidence_schema.to_owned(),
            provider_admission_snapshot_schema: snapshot_schema.to_owned(),
            codex_owner_head: requirement.owner_pins.codex_owner_head.clone(),
            switchyard_owner_head: requirement.owner_pins.switchyard_owner_head.clone(),
            switchyard_schema_sha256: requirement.owner_pins.switchyard_schema_sha256.clone(),
            switchyard_deterministic_fixture_sha256: requirement
                .owner_pins
                .deterministic_fixture_sha256
                .clone(),
            provider_execution_id: None,
            internal_provider_retry_count: 0,
            semantic_retry: false,
            approval_response_authorized: false,
            authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".to_owned(),
        };
        request.seal()?;
        request.validate_pre_dispatch_graph(profile, requirement)?;
        Ok(request)
    }

    fn validate_pre_dispatch_graph(
        &self,
        profile: &ExecutionProfileV2,
        requirement: &ForemanExecutionAvailabilityRequirementV1,
    ) -> Result<(), ContractError> {
        self.validate()?;
        profile.validate()?;
        requirement.validate()?;
        let predecessor = self.predecessor_v2()?;
        let execution = profile
            .work_items
            .get(&self.work_item_id)
            .ok_or(ContractError::InvalidField("V3 profile work item"))?;
        let adapter = profile
            .adapters
            .get(&execution.adapter_id)
            .ok_or(ContractError::InvalidField("V3 profile adapter"))?;
        let qualification_adapter = self.adapter_id == HOLDING_QUALIFICATION_PRODUCER_ID;
        let exact_qualification_executable = match self.adapter_version.as_str() {
            HOLDING_QUALIFICATION_PRODUCER_VERSION => {
                adapter.executable_identity == HOLDING_QUALIFICATION_EXECUTABLE_SHA256
            }
            SECOND_WATCH_QUALIFICATION_PRODUCER_VERSION => {
                adapter.executable_identity == SECOND_WATCH_QUALIFICATION_EXECUTABLE_SHA256
            }
            _ => false,
        };
        if qualification_adapter
            && (!exact_qualification_executable || !adapter.bounded_arguments.is_empty())
        {
            return Err(ContractError::InvalidField(
                "V3 qualification adapter executable binding",
            ));
        }
        let selection = requirement
            .work_item_model_selections
            .get(&self.work_item_id)
            .and_then(|selections| selections.get(usize::from(self.selected_model_ordinal)))
            .ok_or(ContractError::InvalidField("V3 selected model ordinal"))?;
        if self.work_attempt_id == self.dispatch_occurrence_id
            || self.owner_pins() != requirement.owner_pins
            || self.profile_digest != profile.profile_digest
            || self.packet_digest != profile.packet_digest
            || self.packet_digest != requirement.packet_digest
            || profile.admission_digest != requirement.admission_digest
            || profile.profile_digest != requirement.profile_digest
            || self.run_id != requirement.run_id
            || self.adapter_id != requirement.adapter_id
            || self.adapter_version != requirement.adapter_version
            || self.adapter_protocol != requirement.adapter_protocol
            || self.adapter_id != execution.adapter_id
            || self.adapter_id != adapter.adapter_id
            || self.adapter_version != adapter.adapter_version
            || self.adapter_protocol != adapter.protocol
            || requirement.adapter_executable_identity != adapter.executable_identity
            || self.workspace_identity != execution.workspace_identity
            || self.provider_model_class != execution.provider_model_class
            || self.timeout_seconds != profile.adapter_timeout_seconds
            || self.maximum_output_bytes != profile.worker_output_bound()
            || self.provider_id != selection.provider_id
            || self.model_id != selection.model_id
            || self.model_class != selection.model_class
            || predecessor.request_digest != self.predecessor_request_digest
            || predecessor.worker_brief_digest != self.worker_brief_digest
        {
            return Err(ContractError::InvalidField(
                "worker start V3 pre-dispatch graph",
            ));
        }
        Ok(())
    }

    pub fn validate_dispatch_graph(
        &self,
        profile: &ExecutionProfileV2,
        requirement: &ForemanExecutionAvailabilityRequirementV1,
        dispatch: &ProviderDispatchOccurrenceV1,
    ) -> Result<(), ContractError> {
        self.validate_pre_dispatch_graph(profile, requirement)?;
        dispatch.validate()?;
        if dispatch.requirement_digest != requirement.requirement_digest
            || dispatch.policy_digest != requirement.policy_digest
            || dispatch.packet_digest != requirement.packet_digest
            || dispatch.run_id != requirement.run_id
            || dispatch.work_item_id != self.work_item_id
            || dispatch.work_attempt_id != self.work_attempt_id
            || dispatch.dispatch_occurrence_id != self.dispatch_occurrence_id
            || dispatch.selected_model_ordinal != self.selected_model_ordinal
            || dispatch.selection.provider_id != self.provider_id
            || dispatch.selection.model_id != self.model_id
            || dispatch.selection.model_class != self.model_class
            || dispatch.adapter_id != self.adapter_id
            || dispatch.adapter_version != self.adapter_version
            || dispatch.adapter_protocol != self.adapter_protocol
            || dispatch.worker_start_request_schema != self.schema
            || dispatch.worker_start_request_digest != self.request_digest
            || dispatch.worker_brief_digest != self.worker_brief_digest
            || dispatch.opened_at < requirement.admitted_at
            || dispatch.provider_execution_id.is_some()
        {
            return Err(ContractError::InvalidField(
                "worker start V3 dispatch graph",
            ));
        }
        Ok(())
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, ContractError> {
        let request: Self = parse(bytes)?;
        if serde_jcs::to_vec(&request).map_err(json_error)? != bytes {
            return Err(ContractError::InvalidField("canonical V3 request bytes"));
        }
        request.validate()?;
        Ok(request)
    }

    pub fn seal(&mut self) -> Result<(), ContractError> {
        self.request_digest =
            digest_without(self, "request_digest", WORKER_START_REQUEST_DOMAIN_V3)?;
        self.validate()
    }

    pub fn predecessor_v2(&self) -> Result<WorkerStartRequestV2, ContractError> {
        if self.predecessor_encoding != "hex"
            || self
                .predecessor_bytes_hex
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !matches!(byte, b'a'..=b'f'))
        {
            return Err(ContractError::InvalidField("V2 predecessor encoding"));
        }
        let bytes = hex::decode(&self.predecessor_bytes_hex)
            .map_err(|_| ContractError::InvalidField("V2 predecessor hex"))?;
        if bytes.is_empty()
            || bytes.len() > 64 * 1024
            || plain_sha256(&bytes) != self.predecessor_sha256
        {
            return Err(ContractError::InvalidField("V2 predecessor custody"));
        }
        let predecessor: WorkerStartRequestV2 = parse(&bytes)?;
        predecessor.validate()?;
        if serde_jcs::to_vec(&predecessor).map_err(json_error)? != bytes
            || predecessor.request_digest != self.predecessor_request_digest
        {
            return Err(ContractError::InvalidField(
                "canonical V2 predecessor bytes",
            ));
        }
        Ok(predecessor)
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        schema(&self.schema, WORKER_START_REQUEST_SCHEMA_V3)?;
        sealed_digest(
            self,
            "request_digest",
            &self.request_digest,
            WORKER_START_REQUEST_DOMAIN_V3,
        )?;
        for (field, value) in [
            (
                "predecessor_request_digest",
                &self.predecessor_request_digest,
            ),
            ("predecessor_sha256", &self.predecessor_sha256),
            ("packet_digest", &self.packet_digest),
            ("profile_digest", &self.profile_digest),
            ("worker_brief_digest", &self.worker_brief_digest),
            ("switchyard_schema_sha256", &self.switchyard_schema_sha256),
            (
                "switchyard_deterministic_fixture_sha256",
                &self.switchyard_deterministic_fixture_sha256,
            ),
        ] {
            digest(field, value)?;
        }
        for (field, value) in [
            ("run_id", &self.run_id),
            ("work_item_id", &self.work_item_id),
            ("attempt_id", &self.attempt_id),
            ("work_attempt_id", &self.work_attempt_id),
            ("dispatch_occurrence_id", &self.dispatch_occurrence_id),
            ("adapter_id", &self.adapter_id),
            ("adapter_version", &self.adapter_version),
            ("adapter_protocol", &self.adapter_protocol),
            ("workspace_identity", &self.workspace_identity),
            ("provider_model_class", &self.provider_model_class),
            ("provider_id", &self.provider_id),
            ("model_id", &self.model_id),
            ("model_class", &self.model_class),
            (
                "provider_admission_adapter_protocol",
                &self.provider_admission_adapter_protocol,
            ),
            (
                "provider_admission_binding_schema",
                &self.provider_admission_binding_schema,
            ),
            (
                "provider_admission_evidence_schema",
                &self.provider_admission_evidence_schema,
            ),
            (
                "provider_admission_snapshot_schema",
                &self.provider_admission_snapshot_schema,
            ),
        ] {
            id(field, value)?;
        }
        let predecessor = self.predecessor_v2()?;
        let switchyard_binding = self.adapter_id != HOLDING_QUALIFICATION_PRODUCER_ID
            && self.adapter_protocol == "switchyard.codex-app-server/v2"
            && self.provider_admission_adapter_protocol == self.adapter_protocol
            && self.provider_admission_binding_schema
                == "switchyard.codex-provider-admission-binding/v1"
            && self.provider_admission_evidence_schema
                == "switchyard.codex-provider-admission-evidence/v1"
            && self.provider_admission_snapshot_schema
                == "switchyard.codex-provider-admission-snapshot/v1";
        let qualification_binding_v1 = self.adapter_id == HOLDING_QUALIFICATION_PRODUCER_ID
            && self.adapter_version == HOLDING_QUALIFICATION_PRODUCER_VERSION
            && self.adapter_protocol == DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V1
            && self.provider_admission_adapter_protocol == self.adapter_protocol
            && self.provider_admission_binding_schema == self.adapter_protocol
            && self.provider_admission_evidence_schema == self.adapter_protocol
            && self.provider_admission_snapshot_schema == self.adapter_protocol;
        let qualification_binding_v2 = self.adapter_id == HOLDING_QUALIFICATION_PRODUCER_ID
            && self.adapter_version == SECOND_WATCH_QUALIFICATION_PRODUCER_VERSION
            && self.adapter_protocol == DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V2
            && self.provider_admission_adapter_protocol == self.adapter_protocol
            && self.provider_admission_binding_schema == self.adapter_protocol
            && self.provider_admission_evidence_schema == self.adapter_protocol
            && self.provider_admission_snapshot_schema == self.adapter_protocol;
        if self.predecessor_schema != crate::WORKER_START_REQUEST_SCHEMA_V2
            || predecessor.schema != self.predecessor_schema
            || self.packet_digest != predecessor.packet_digest
            || self.run_id != predecessor.run_id
            || self.work_item_id != predecessor.work_item_id
            || self.attempt_id != predecessor.attempt_id
            || self.work_attempt_id != predecessor.attempt_id
            || self.adapter_id != predecessor.adapter_id
            || self.adapter_version != predecessor.adapter_version
            || self.adapter_protocol != predecessor.adapter_protocol
            || self.worker_brief_digest != predecessor.worker_brief_digest
            || self.workspace_identity != predecessor.workspace_identity
            || self.provider_model_class != predecessor.provider_model_class
            || self.timeout_seconds != predecessor.timeout_seconds
            || self.maximum_output_bytes != predecessor.maximum_output_bytes
            || self.recursive_worker_swarms_forbidden
                != predecessor.recursive_worker_swarms_forbidden
            || self.approval_policy != predecessor.approval_policy
            || self.expected_receipt_schema != predecessor.expected_receipt_schema
            || self.model_class != self.provider_model_class
            || self.selected_model_ordinal >= 16
            || !(switchyard_binding || qualification_binding_v1 || qualification_binding_v2)
            || self.owner_pins().validate().is_err()
            || self.provider_execution_id.is_some()
            || self.internal_provider_retry_count != 0
            || self.semantic_retry
            || self.approval_response_authorized
            || self.authority_effect != "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY"
        {
            return Err(ContractError::InvalidField("worker start V3 binding"));
        }
        Ok(())
    }

    fn owner_pins(&self) -> ProviderAdmissionOwnerPinsV1 {
        ProviderAdmissionOwnerPinsV1 {
            codex_owner_head: self.codex_owner_head.clone(),
            switchyard_owner_head: self.switchyard_owner_head.clone(),
            switchyard_schema_sha256: self.switchyard_schema_sha256.clone(),
            deterministic_fixture_sha256: self.switchyard_deterministic_fixture_sha256.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDispatchOccurrenceV1 {
    pub schema: String,
    pub dispatch_digest: String,
    pub requirement_digest: String,
    pub policy_digest: String,
    pub packet_digest: String,
    pub run_id: String,
    pub work_item_id: String,
    pub work_attempt_id: String,
    pub dispatch_occurrence_id: String,
    pub dispatch_ordinal: u16,
    pub selected_model_ordinal: u16,
    pub selection: ProviderModelSelectionV1,
    pub adapter_id: String,
    pub adapter_version: String,
    pub adapter_protocol: String,
    pub adapter_process_occurrence_id: String,
    pub app_server_session_identity: String,
    pub worker_start_request_schema: String,
    pub worker_start_request_digest: String,
    pub worker_brief_digest: String,
    pub opened_at: DateTime<Utc>,
    pub internal_provider_retry_count: u16,
    pub provider_execution_id: Option<String>,
    pub authority_effect: String,
}

impl ProviderDispatchOccurrenceV1 {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ContractError> {
        let value: Value = parse(bytes)?;
        canonical_timestamp(&value, "opened_at")?;
        serde_json::from_value(value).map_err(json_error)
    }
    pub fn seal(&mut self) -> Result<(), ContractError> {
        self.dispatch_digest = digest_without(self, "dispatch_digest", DISPATCH_DOMAIN)?;
        self.validate()
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        schema(&self.schema, PROVIDER_DISPATCH_OCCURRENCE_SCHEMA_V1)?;
        sealed_digest(
            self,
            "dispatch_digest",
            &self.dispatch_digest,
            DISPATCH_DOMAIN,
        )?;
        for (field, value) in [
            ("requirement_digest", &self.requirement_digest),
            ("policy_digest", &self.policy_digest),
            ("packet_digest", &self.packet_digest),
            (
                "worker_start_request_digest",
                &self.worker_start_request_digest,
            ),
            ("worker_brief_digest", &self.worker_brief_digest),
        ] {
            digest(field, value)?;
        }
        for (field, value) in [
            ("run_id", &self.run_id),
            ("work_item_id", &self.work_item_id),
            ("work_attempt_id", &self.work_attempt_id),
            ("dispatch_occurrence_id", &self.dispatch_occurrence_id),
            ("adapter_id", &self.adapter_id),
            ("adapter_version", &self.adapter_version),
            ("adapter_protocol", &self.adapter_protocol),
            (
                "adapter_process_occurrence_id",
                &self.adapter_process_occurrence_id,
            ),
            (
                "app_server_session_identity",
                &self.app_server_session_identity,
            ),
        ] {
            id(field, value)?;
        }
        self.selection.validate()?;
        if self.dispatch_ordinal == 0
            || self.dispatch_ordinal > MAXIMUM_DISPATCH_OCCURRENCES
            || self.selected_model_ordinal >= 16
            || self.worker_start_request_schema != "nightshift.worker-start-request/v3"
            || self.internal_provider_retry_count != 0
            || self.provider_execution_id.is_some()
            || self.authority_effect != "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY"
        {
            return Err(ContractError::InvalidField("dispatch occurrence boundary"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProviderAdmissionDispositionKindV1 {
    NotAdmittedModelAtCapacity,
    NotAdmittedProviderUnavailable,
    NotAdmittedRateLimited,
    AuthenticationRefused,
    QuotaExhaustedFuelOwned,
    AdmissionIndeterminate,
    ExecutionAdmitted,
}

impl ProviderAdmissionDispositionKindV1 {
    pub fn permits_automatic_park(self) -> bool {
        matches!(self, Self::NotAdmittedModelAtCapacity)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderExecutionIdentityV1 {
    pub provider_id: String,
    pub model_id: String,
    pub app_server_session_identity: String,
    pub thread_id: String,
    pub turn_id: String,
    pub first_response_id: String,
}

impl ProviderExecutionIdentityV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        for (field, value) in [
            ("execution provider_id", &self.provider_id),
            ("execution model_id", &self.model_id),
            ("execution session", &self.app_server_session_identity),
            ("execution thread", &self.thread_id),
            ("execution turn", &self.turn_id),
            ("execution first_response_id", &self.first_response_id),
        ] {
            id(field, value)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProviderMechanismStateV1 {
    ParkedNotAdmitted,
    AdmissionIndeterminate,
    ExecutionAdmitted,
    PostAdmissionInterrupted,
    WaitingApproval,
    ProviderCompleted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAdmissionDispositionV1 {
    pub schema: String,
    pub disposition_digest: String,
    pub dispatch_digest: String,
    pub requirement_digest: String,
    pub policy_digest: String,
    pub packet_digest: String,
    pub run_id: String,
    pub work_item_id: String,
    pub work_attempt_id: String,
    pub dispatch_occurrence_id: String,
    pub provider_id: String,
    pub model_id: String,
    pub provider_request_occurrence_id: String,
    pub adapter_process_occurrence_id: String,
    pub app_server_session_identity: String,
    pub thread_id: String,
    pub turn_id: String,
    pub disposition: ProviderAdmissionDispositionKindV1,
    pub mechanism_state: ProviderMechanismStateV1,
    pub received_at: DateTime<Utc>,
    pub response_created: bool,
    pub will_retry: bool,
    pub acquisition_complete: bool,
    pub provider_retry_after: Option<DateTime<Utc>>,
    pub provider_execution: Option<ProviderExecutionIdentityV1>,
    pub mapper_snapshot_schema: String,
    pub mapper_snapshot_digest: String,
    pub mapper_snapshot: ExactMapperSnapshotV1,
    pub approval_response_sent: bool,
    pub protected_effect_absent: bool,
    pub authority_effect: String,
}

impl ProviderAdmissionDispositionV1 {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ContractError> {
        let value: Value = parse(bytes)?;
        canonical_timestamp(&value, "received_at")?;
        canonical_optional_timestamp(&value, "provider_retry_after")?;
        serde_json::from_value(value).map_err(json_error)
    }
    pub fn seal(&mut self) -> Result<(), ContractError> {
        let domain = match self.schema.as_str() {
            PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V1 => DISPOSITION_DOMAIN,
            PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V2 => DISPOSITION_DOMAIN_V2,
            PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V3 => DISPOSITION_DOMAIN_V3,
            _ => return Err(ContractError::ForeignSchema(self.schema.clone())),
        };
        self.disposition_digest = digest_without(self, "disposition_digest", domain)?;
        self.validate()
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        let domain = match self.schema.as_str() {
            PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V1 => DISPOSITION_DOMAIN,
            PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V2 => DISPOSITION_DOMAIN_V2,
            PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V3 => DISPOSITION_DOMAIN_V3,
            _ => return Err(ContractError::ForeignSchema(self.schema.clone())),
        };
        sealed_digest(self, "disposition_digest", &self.disposition_digest, domain)?;
        for (field, value) in [
            ("dispatch_digest", &self.dispatch_digest),
            ("requirement_digest", &self.requirement_digest),
            ("policy_digest", &self.policy_digest),
            ("packet_digest", &self.packet_digest),
            ("mapper_snapshot_digest", &self.mapper_snapshot_digest),
        ] {
            digest(field, value)?;
        }
        for (field, value) in [
            ("run_id", &self.run_id),
            ("work_item_id", &self.work_item_id),
            ("work_attempt_id", &self.work_attempt_id),
            ("dispatch_occurrence_id", &self.dispatch_occurrence_id),
            ("provider_id", &self.provider_id),
            ("model_id", &self.model_id),
            (
                "provider_request_occurrence_id",
                &self.provider_request_occurrence_id,
            ),
            (
                "adapter_process_occurrence_id",
                &self.adapter_process_occurrence_id,
            ),
            (
                "app_server_session_identity",
                &self.app_server_session_identity,
            ),
            ("thread_id", &self.thread_id),
            ("turn_id", &self.turn_id),
        ] {
            id(field, value)?;
        }
        let raw = self.mapper_snapshot.validate()?;
        match self.schema.as_str() {
            PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V1 => {
                if self.mapper_snapshot_schema != "switchyard.codex-provider-admission-snapshot/v1"
                    || self.mapper_snapshot.representation != "RFC8785_SWITCHYARD_MAPPER_SNAPSHOT"
                {
                    return Err(ContractError::InvalidField("mapper snapshot schema"));
                }
                validate_switchyard_snapshot_complete(self, &raw)?;
            }
            PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V2 => {
                if self.mapper_snapshot_schema
                    != DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V1
                    || self.mapper_snapshot.representation
                        != "RFC8785_NIGHTSHIFT_QUALIFICATION_FAKE_ADAPTER_EVIDENCE"
                {
                    return Err(ContractError::InvalidField("qualification evidence schema"));
                }
                let evidence = DeterministicProviderAdmissionEvidenceV1::from_slice(&raw)?;
                evidence.validate()?;
                if self.mapper_snapshot_digest != evidence.evidence_digest
                    || self.work_attempt_id != evidence.work_attempt_id
                    || self.dispatch_occurrence_id != evidence.dispatch_occurrence_id
                    || self.provider_request_occurrence_id
                        != evidence.provider_request_occurrence_id
                    || self.provider_id != evidence.provider_id
                    || self.model_id != evidence.model_id
                    || self.received_at != evidence.received_at
                    || self.response_created != evidence.response_created
                    || self.provider_retry_after != evidence.retry_after
                    || self.provider_execution.is_some()
                    || !self.acquisition_complete
                {
                    return Err(ContractError::InvalidField(
                        "qualification evidence disposition binding",
                    ));
                }
                let expected = match evidence.outcome {
                    DeterministicProviderAdmissionOutcomeV1::RateLimited => (
                        ProviderAdmissionDispositionKindV1::NotAdmittedRateLimited,
                        ProviderMechanismStateV1::ParkedNotAdmitted,
                    ),
                    DeterministicProviderAdmissionOutcomeV1::ProviderUnavailable => (
                        ProviderAdmissionDispositionKindV1::NotAdmittedProviderUnavailable,
                        ProviderMechanismStateV1::ParkedNotAdmitted,
                    ),
                    DeterministicProviderAdmissionOutcomeV1::AuthenticationRefused => (
                        ProviderAdmissionDispositionKindV1::AuthenticationRefused,
                        ProviderMechanismStateV1::AdmissionIndeterminate,
                    ),
                    DeterministicProviderAdmissionOutcomeV1::TransportError
                    | DeterministicProviderAdmissionOutcomeV1::ProtocolError => (
                        ProviderAdmissionDispositionKindV1::AdmissionIndeterminate,
                        ProviderMechanismStateV1::AdmissionIndeterminate,
                    ),
                };
                if (self.disposition, self.mechanism_state) != expected {
                    return Err(ContractError::InvalidField(
                        "qualification evidence outcome binding",
                    ));
                }
            }
            PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V3 => {
                if self.mapper_snapshot_schema
                    != DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V2
                    || self.mapper_snapshot.representation
                        != "RFC8785_NIGHTSHIFT_QUALIFICATION_FAKE_ADAPTER_EVIDENCE"
                {
                    return Err(ContractError::InvalidField(
                        "qualification execution evidence schema",
                    ));
                }
                validate_qualification_v2_disposition(self, &raw)?;
            }
            _ => unreachable!(),
        }
        if self.will_retry || self.approval_response_sent || !self.protected_effect_absent {
            return Err(ContractError::InvalidField(
                "provider admission authority boundary",
            ));
        }
        match self.disposition {
            ProviderAdmissionDispositionKindV1::ExecutionAdmitted => {
                let execution =
                    self.provider_execution
                        .as_ref()
                        .ok_or(ContractError::InvalidField(
                            "provider execution identity absence",
                        ))?;
                execution.validate()?;
                if !self.response_created
                    || execution.provider_id != self.provider_id
                    || execution.model_id != self.model_id
                    || execution.app_server_session_identity != self.app_server_session_identity
                    || execution.thread_id != self.thread_id
                    || execution.turn_id != self.turn_id
                {
                    return Err(ContractError::InvalidField("execution admission binding"));
                }
            }
            ProviderAdmissionDispositionKindV1::NotAdmittedModelAtCapacity
            | ProviderAdmissionDispositionKindV1::NotAdmittedProviderUnavailable
            | ProviderAdmissionDispositionKindV1::NotAdmittedRateLimited
            | ProviderAdmissionDispositionKindV1::AuthenticationRefused => {
                if self.provider_execution.is_some()
                    || self.response_created
                    || !self.acquisition_complete
                {
                    return Err(ContractError::InvalidField("pre-admission refusal binding"));
                }
            }
            ProviderAdmissionDispositionKindV1::QuotaExhaustedFuelOwned => {
                return Err(ContractError::InvalidField("FUEL-owned quota disposition"));
            }
            ProviderAdmissionDispositionKindV1::AdmissionIndeterminate => {
                if self.provider_execution.is_some() && !self.response_created {
                    return Err(ContractError::InvalidField(
                        "indeterminate execution binding",
                    ));
                }
            }
        }
        if self
            .provider_retry_after
            .is_some_and(|retry_after| retry_after < self.received_at)
            || self.authority_effect != "SCHEDULING_MECHANISM_EVIDENCE_ONLY"
        {
            return Err(ContractError::InvalidField(
                "admission disposition boundary",
            ));
        }
        Ok(())
    }

    pub fn permits_automatic_park(&self) -> bool {
        self.disposition.permits_automatic_park()
            || (matches!(
                self.schema.as_str(),
                PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V2 | PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V3
            ) && matches!(
                self.disposition,
                ProviderAdmissionDispositionKindV1::NotAdmittedProviderUnavailable
                    | ProviderAdmissionDispositionKindV1::NotAdmittedRateLimited
            ))
    }
}

fn validate_qualification_v2_disposition(
    disposition: &ProviderAdmissionDispositionV1,
    raw: &[u8],
) -> Result<(), ContractError> {
    let evidence = DeterministicProviderAdmissionEvidenceV2::from_slice(raw)?;
    evidence.validate()?;
    if disposition.mapper_snapshot_digest != evidence.evidence_digest
        || disposition.work_attempt_id != evidence.work_attempt_id
        || disposition.dispatch_occurrence_id != evidence.dispatch_occurrence_id
        || disposition.provider_request_occurrence_id != evidence.provider_request_occurrence_id
        || disposition.provider_id != evidence.provider_id
        || disposition.model_id != evidence.model_id
        || disposition.received_at != evidence.received_at
        || disposition.response_created != evidence.response_created
        || disposition.provider_retry_after != evidence.retry_after
        || disposition.provider_execution != evidence.provider_execution
        || !disposition.acquisition_complete
    {
        return Err(ContractError::InvalidField(
            "qualification execution evidence disposition binding",
        ));
    }
    let expected = match evidence.outcome {
        DeterministicProviderAdmissionOutcomeV2::ProviderUnavailable => (
            ProviderAdmissionDispositionKindV1::NotAdmittedProviderUnavailable,
            ProviderMechanismStateV1::ParkedNotAdmitted,
        ),
        DeterministicProviderAdmissionOutcomeV2::ExecutionCompleted => (
            ProviderAdmissionDispositionKindV1::ExecutionAdmitted,
            ProviderMechanismStateV1::ProviderCompleted,
        ),
    };
    if (disposition.disposition, disposition.mechanism_state) != expected {
        return Err(ContractError::InvalidField(
            "qualification execution evidence outcome binding",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeferredWakeBasisV1 {
    ProviderRetryAfter,
    PolicyBackoff,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeferredProviderDispatchV1 {
    pub schema: String,
    pub deferred_dispatch_digest: String,
    pub requirement_digest: String,
    pub policy_digest: String,
    pub disposition_digest: String,
    pub packet_digest: String,
    pub run_id: String,
    pub work_item_id: String,
    pub work_attempt_id: String,
    pub last_dispatch_occurrence_id: String,
    pub provider_id: String,
    pub model_id: String,
    pub selected_model_ordinal: u16,
    pub remaining_model_ordinals: Vec<u16>,
    pub refusal_received_at: DateTime<Utc>,
    pub wake_basis: DeferredWakeBasisV1,
    pub backoff_ordinal: u16,
    pub backoff_seconds: u64,
    pub provider_retry_after: Option<DateTime<Utc>>,
    pub wake_at: DateTime<Utc>,
    pub parked_resource_lock_policy: ParkedResourceLockPolicyV1,
    pub provider_capacity_released: bool,
    pub semantic_retry: bool,
    pub authority_effect: String,
}

/// Exact typed history needed to admit a later dispatch occurrence.  The wrapper
/// is deliberately not a separately sealed receipt: its three owner receipts
/// retain their own digest laws and are reopened together by the graph validator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDeferralHistoryEntryV1 {
    pub dispatch: ProviderDispatchOccurrenceV1,
    pub disposition: ProviderAdmissionDispositionV1,
    pub deferred: DeferredProviderDispatchV1,
}

impl ProviderDeferralHistoryEntryV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.dispatch.validate()?;
        self.disposition.validate()?;
        self.deferred.validate()
    }
}

impl DeferredProviderDispatchV1 {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ContractError> {
        let value: Value = parse(bytes)?;
        for field in ["refusal_received_at", "wake_at"] {
            canonical_timestamp(&value, field)?;
        }
        canonical_optional_timestamp(&value, "provider_retry_after")?;
        serde_json::from_value(value).map_err(json_error)
    }
    pub fn seal(&mut self) -> Result<(), ContractError> {
        self.deferred_dispatch_digest =
            digest_without(self, "deferred_dispatch_digest", DEFERRED_DOMAIN)?;
        self.validate()
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        schema(&self.schema, DEFERRED_PROVIDER_DISPATCH_SCHEMA_V1)?;
        sealed_digest(
            self,
            "deferred_dispatch_digest",
            &self.deferred_dispatch_digest,
            DEFERRED_DOMAIN,
        )?;
        for (field, value) in [
            ("requirement_digest", &self.requirement_digest),
            ("policy_digest", &self.policy_digest),
            ("disposition_digest", &self.disposition_digest),
            ("packet_digest", &self.packet_digest),
        ] {
            digest(field, value)?;
        }
        for (field, value) in [
            ("run_id", &self.run_id),
            ("work_item_id", &self.work_item_id),
            ("work_attempt_id", &self.work_attempt_id),
            (
                "last_dispatch_occurrence_id",
                &self.last_dispatch_occurrence_id,
            ),
            ("provider_id", &self.provider_id),
            ("model_id", &self.model_id),
        ] {
            id(field, value)?;
        }
        if self.selected_model_ordinal >= 16
            || self.backoff_ordinal >= MAXIMUM_DISPATCH_OCCURRENCES
            || self.backoff_seconds == 0
            || self.backoff_seconds > 86_400
            || self.remaining_model_ordinals.len() > 16
            || self
                .remaining_model_ordinals
                .iter()
                .any(|ordinal| *ordinal >= 16 || *ordinal <= self.selected_model_ordinal)
            || self
                .remaining_model_ordinals
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || !self.provider_capacity_released
            || self.semantic_retry
            || self.authority_effect != "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY"
        {
            return Err(ContractError::InvalidField("deferred dispatch boundary"));
        }
        let expected_wake = match self.wake_basis {
            DeferredWakeBasisV1::ProviderRetryAfter => self
                .provider_retry_after
                .ok_or(ContractError::InvalidField("provider_retry_after"))?,
            DeferredWakeBasisV1::PolicyBackoff => {
                if self.provider_retry_after.is_some() {
                    return Err(ContractError::InvalidField(
                        "unexpected provider_retry_after",
                    ));
                }
                self.refusal_received_at
                    .checked_add_signed(Duration::seconds(self.backoff_seconds as i64))
                    .ok_or(ContractError::InvalidField("wake_at"))?
            }
        };
        if self.wake_at != expected_wake || self.wake_at <= self.refusal_received_at {
            return Err(ContractError::InvalidField("wake_at"));
        }
        Ok(())
    }
}

fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ContractError> {
    serde_json::from_slice(bytes).map_err(json_error)
}

fn digest_without<T: Serialize>(
    record: &T,
    field: &'static str,
    domain: &[u8],
) -> Result<String, ContractError> {
    let mut value = serde_json::to_value(record).map_err(json_error)?;
    value
        .as_object_mut()
        .ok_or(ContractError::InvalidField("record"))?
        .remove(field);
    let canonical = serde_jcs::to_vec(&value).map_err(json_error)?;
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(canonical);
    Ok(format!("sha256:{:x}", digest.finalize()))
}

fn sealed_digest<T: Serialize>(
    value: &T,
    field: &'static str,
    observed: &str,
    domain: &[u8],
) -> Result<(), ContractError> {
    digest(field, observed)?;
    if digest_without(value, field, domain)? != observed {
        return Err(ContractError::DigestMismatch(field));
    }
    Ok(())
}

fn plain_sha256(raw: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(raw))
}

fn schema(actual: &str, expected: &str) -> Result<(), ContractError> {
    if actual != expected {
        return Err(ContractError::ForeignSchema(actual.to_owned()));
    }
    Ok(())
}

fn digest(field: &'static str, value: &str) -> Result<(), ContractError> {
    if value.len() != 71
        || !value.starts_with("sha256:")
        || !value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ContractError::InvalidField(field));
    }
    Ok(())
}

fn id(field: &'static str, value: &str) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > 512
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        })
    {
        return Err(ContractError::InvalidField(field));
    }
    Ok(())
}

fn canonical_timestamp(value: &Value, field: &'static str) -> Result<(), ContractError> {
    let raw = value
        .as_object()
        .and_then(|object| object.get(field))
        .and_then(Value::as_str)
        .ok_or(ContractError::InvalidField(field))?;
    let parsed = DateTime::parse_from_rfc3339(raw)
        .map_err(|_| ContractError::InvalidField(field))?
        .with_timezone(&Utc);
    if serde_json::to_value(parsed).map_err(json_error)?.as_str() != Some(raw) {
        return Err(ContractError::InvalidField(field));
    }
    Ok(())
}

fn canonical_optional_timestamp(value: &Value, field: &'static str) -> Result<(), ContractError> {
    match value.as_object().and_then(|object| object.get(field)) {
        Some(Value::Null) => Ok(()),
        Some(Value::String(_)) => canonical_timestamp(value, field),
        _ => Err(ContractError::InvalidField(field)),
    }
}

fn json_error(error: impl std::fmt::Display) -> ContractError {
    ContractError::Json(error.to_string())
}

fn validate_switchyard_snapshot(
    disposition: &ProviderAdmissionDispositionV1,
    raw: &[u8],
) -> Result<(), ContractError> {
    let snapshot: Value = serde_json::from_slice(raw).map_err(json_error)?;
    // A disposition alone is a structural union, not source/route admission.
    validate_vendored_switchyard_schema(&snapshot, SwitchyardCaptureSchema::BoundedTurnEcho)?;
    if serde_jcs::to_vec(&snapshot).map_err(json_error)? != raw {
        return Err(ContractError::InvalidField(
            "mapper snapshot canonical bytes",
        ));
    }
    exact_object_keys(
        &snapshot,
        &[
            "schema",
            "snapshot_digest",
            "binding",
            "admission_disposition",
            "mechanism_state",
            "provider_execution_identity",
            "acquisition_cut",
            "records",
        ],
        "mapper snapshot closure",
    )?;
    if string(&snapshot, "schema")? != disposition.mapper_snapshot_schema
        || string(&snapshot, "snapshot_digest")? != disposition.mapper_snapshot_digest
        || canonical_value_digest(
            &snapshot,
            "snapshot_digest",
            b"switchyard.codex-provider-admission-snapshot.digest/v1\0",
        )? != disposition.mapper_snapshot_digest
    {
        return Err(ContractError::DigestMismatch("mapper snapshot digest"));
    }

    // HOLDING decisions admit only the accepted ordered-acquisition surface.
    // This deliberately precedes binding inspection, evidence digest replay,
    // raw-frame decoding, and all mechanism/disposition derivation.  Legacy
    // unordered owner output remains exact raw compatibility evidence, but it
    // cannot enter the scheduling decision graph.
    let records = snapshot
        .get("records")
        .and_then(Value::as_array)
        .ok_or(ContractError::InvalidField("mapper records"))?;
    if records.len() > 4096 {
        return Err(ContractError::InvalidField("mapper record count"));
    }
    if records.iter().any(|record| {
        // The ordered owner may also record local acquisition loss without a
        // provider frame or fabricated stream ordinal. This exact rawless
        // discrepancy is still fully replayed below and cannot admit execution.
        let local_loss = record.get("kind").and_then(Value::as_str)
            == Some("ADMISSION_DISCREPANCY")
            && record.get("method").and_then(Value::as_str) == Some("adapter/acquisition")
            && record.get("raw") == Some(&Value::Null)
            && record.get("acquisition_ordinal") == Some(&Value::Null)
            && record.get("acquisition_kind") == Some(&Value::Null);
        record.get("kind").and_then(Value::as_str) != Some("ACQUISITION_CUT")
            && !local_loss
            && (record.get("acquisition_ordinal").is_none_or(Value::is_null)
                || record.get("acquisition_kind").is_none_or(Value::is_null))
    }) {
        return Err(ContractError::InvalidField(
            "decision-bearing mapper evidence requires strict ordered acquisition",
        ));
    }

    let binding = snapshot
        .get("binding")
        .ok_or(ContractError::InvalidField("mapper binding"))?;
    exact_object_keys(
        binding,
        &[
            "schema",
            "binding_digest",
            "work_attempt_id",
            "dispatch_occurrence_id",
            "adapter_process_occurrence_id",
            "app_server_session_identity",
            "thread_id",
            "turn_id",
            "provider",
            "model",
            "codex_source_head",
            "executable_kind",
            "app_server_executable_identity",
            "app_server_executable_sha256",
            "internal_provider_request_retries",
        ],
        "mapper binding closure",
    )?;
    if string(binding, "schema")? != "switchyard.codex-provider-admission-binding/v1"
        || ![
            ACCEPTED_CODEX_PROVIDER_ADMISSION_OWNER_HEAD,
            BETA_CODEX_OWNER_HEAD,
            FINAL_CODEX_OWNER_HEAD,
        ]
        .contains(&string(binding, "codex_source_head")?)
        || integer(binding, "internal_provider_request_retries")? != 0
        || canonical_value_digest(
            binding,
            "binding_digest",
            b"switchyard.codex-provider-admission-binding.digest/v1\0",
        )? != string(binding, "binding_digest")?
    {
        return Err(ContractError::InvalidField("mapper binding owner law"));
    }
    for (field, expected) in [
        ("work_attempt_id", disposition.work_attempt_id.as_str()),
        (
            "dispatch_occurrence_id",
            disposition.dispatch_occurrence_id.as_str(),
        ),
        (
            "adapter_process_occurrence_id",
            disposition.adapter_process_occurrence_id.as_str(),
        ),
        (
            "app_server_session_identity",
            disposition.app_server_session_identity.as_str(),
        ),
        ("thread_id", disposition.thread_id.as_str()),
        ("turn_id", disposition.turn_id.as_str()),
        ("provider", disposition.provider_id.as_str()),
        ("model", disposition.model_id.as_str()),
    ] {
        if string(binding, field)? != expected {
            return Err(ContractError::InvalidField("mapper binding substitution"));
        }
    }
    digest(
        "mapper executable sha256",
        string(binding, "app_server_executable_sha256")?,
    )?;

    let mut response_identity: Option<ProviderExecutionIdentityV1> = None;
    let mut refusal_occurrence: Option<String> = None;
    let mut saw_waiting_approval = false;
    for (sequence, record) in records.iter().enumerate() {
        exact_object_keys(
            record,
            &[
                "schema",
                "evidence_digest",
                "sequence",
                "acquisition_ordinal",
                "acquisition_kind",
                "binding_digest",
                "work_attempt_id",
                "dispatch_occurrence_id",
                "adapter_process_occurrence_id",
                "app_server_session_identity",
                "thread_id",
                "turn_id",
                "provider",
                "model",
                "kind",
                "method",
                "normalized",
                "raw",
            ],
            "mapper evidence closure",
        )?;
        if string(record, "schema")? != "switchyard.codex-provider-admission-evidence/v1"
            || integer(record, "sequence")? != sequence as i64
            || string(record, "binding_digest")? != string(binding, "binding_digest")?
            || canonical_value_digest(
                record,
                "evidence_digest",
                b"switchyard.codex-provider-admission-evidence.digest/v1\0",
            )? != string(record, "evidence_digest")?
        {
            return Err(ContractError::InvalidField("mapper evidence owner law"));
        }
        for (field, expected) in [
            ("work_attempt_id", disposition.work_attempt_id.as_str()),
            (
                "dispatch_occurrence_id",
                disposition.dispatch_occurrence_id.as_str(),
            ),
            (
                "adapter_process_occurrence_id",
                disposition.adapter_process_occurrence_id.as_str(),
            ),
            (
                "app_server_session_identity",
                disposition.app_server_session_identity.as_str(),
            ),
            ("thread_id", disposition.thread_id.as_str()),
            ("turn_id", disposition.turn_id.as_str()),
            ("provider", disposition.provider_id.as_str()),
            ("model", disposition.model_id.as_str()),
        ] {
            if string(record, field)? != expected {
                return Err(ContractError::InvalidField("mapper evidence substitution"));
            }
        }
        if let Some(raw_evidence) = record.get("raw").filter(|raw_value| !raw_value.is_null()) {
            validate_switchyard_raw(raw_evidence, switchyard_record_raw_bound(record))?;
        }
        let normalized = record
            .get("normalized")
            .ok_or(ContractError::InvalidField("mapper normalized evidence"))?;
        match string(record, "kind")? {
            "PROVIDER_EXECUTION_STEP" => {
                let identity = normalized
                    .get("provider_execution_identity")
                    .ok_or(ContractError::InvalidField("mapper execution identity"))?;
                let observed = ProviderExecutionIdentityV1 {
                    provider_id: string(identity, "provider")?.to_owned(),
                    model_id: string(identity, "model")?.to_owned(),
                    app_server_session_identity: string(identity, "app_server_session_identity")?
                        .to_owned(),
                    thread_id: string(identity, "thread_id")?.to_owned(),
                    turn_id: string(identity, "turn_id")?.to_owned(),
                    first_response_id: string(identity, "first_response_id")?.to_owned(),
                };
                observed.validate()?;
                if response_identity
                    .as_ref()
                    .is_some_and(|prior| prior != &observed)
                {
                    return Err(ContractError::InvalidField("mapper execution substitution"));
                }
                response_identity = Some(observed);
            }
            "PROVIDER_ADMISSION_REFUSED" => {
                if normalized.get("response_created").and_then(Value::as_bool) != Some(false)
                    || normalized.get("will_retry").and_then(Value::as_bool) != Some(false)
                    || string(normalized, "refusal_kind")? != "MODEL_AT_CAPACITY"
                    || string(normalized, "codex_error_info")? != "serverOverloaded"
                    || !normalized
                        .get("provider_execution_identity")
                        .is_some_and(Value::is_null)
                {
                    return Err(ContractError::InvalidField("mapper refusal owner law"));
                }
                refusal_occurrence = Some(string(normalized, "request_occurrence_id")?.to_owned());
            }
            "WAITING_APPROVAL" => {
                if normalized
                    .get("approval_response_sent")
                    .and_then(Value::as_bool)
                    != Some(false)
                    || normalized
                        .get("protected_effect_absent")
                        .and_then(Value::as_bool)
                        != Some(true)
                {
                    return Err(ContractError::InvalidField("mapper approval boundary"));
                }
                saw_waiting_approval = true;
            }
            _ => {}
        }
    }

    let snapshot_execution = snapshot.get("provider_execution_identity");
    let cut = snapshot.get("acquisition_cut");
    let clean_cut = cut
        .filter(|value| !value.is_null())
        .and_then(|value| value.get("clean"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if clean_cut != disposition.acquisition_complete {
        return Err(ContractError::InvalidField(
            "mapper acquisition-cut binding",
        ));
    }
    if saw_waiting_approval
        && (disposition.approval_response_sent || !disposition.protected_effect_absent)
    {
        return Err(ContractError::InvalidField("mapper approval substitution"));
    }
    match disposition.disposition {
        ProviderAdmissionDispositionKindV1::ExecutionAdmitted => {
            if string(&snapshot, "admission_disposition")? != "EXECUTION_ADMITTED"
                || response_identity.as_ref() != disposition.provider_execution.as_ref()
                || snapshot_execution.is_none_or(Value::is_null)
            {
                return Err(ContractError::InvalidField("mapper execution disposition"));
            }
        }
        ProviderAdmissionDispositionKindV1::NotAdmittedModelAtCapacity => {
            if string(&snapshot, "admission_disposition")? != "NOT_ADMITTED_MODEL_AT_CAPACITY"
                || refusal_occurrence.as_deref()
                    != Some(disposition.provider_request_occurrence_id.as_str())
                || response_identity.is_some()
                || snapshot_execution.is_some_and(|value| !value.is_null())
            {
                return Err(ContractError::InvalidField("mapper refusal disposition"));
            }
        }
        ProviderAdmissionDispositionKindV1::AdmissionIndeterminate => {
            if string(&snapshot, "admission_disposition")? != "ADMISSION_INDETERMINATE" {
                return Err(ContractError::InvalidField(
                    "mapper indeterminate disposition",
                ));
            }
        }
        _ => {
            return Err(ContractError::InvalidField(
                "disposition is not emitted by accepted Switchyard V1",
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum SwitchyardCaptureSchema {
    Legacy,
    BoundedTurn,
    BoundedTurnEcho,
}

fn validate_vendored_switchyard_schema(
    instance: &Value,
    capture: SwitchyardCaptureSchema,
) -> Result<(), ContractError> {
    // Closed source/schema pairs. Historical replay does not enroll an older
    // executable for a new provider run; the full graph binds requirement pins.
    let (bytes, expected) = match instance["binding"]["codex_source_head"].as_str() {
        Some(ACCEPTED_CODEX_PROVIDER_ADMISSION_OWNER_HEAD) => (
            SWITCHYARD_PROVIDER_ADMISSION_SCHEMA_BYTES,
            ACCEPTED_SWITCHYARD_PROVIDER_ADMISSION_SCHEMA_SHA256,
        ),
        Some(FINAL_CODEX_OWNER_HEAD)
            if matches!(capture, SwitchyardCaptureSchema::BoundedTurnEcho) =>
        {
            (
                BOUNDED_TURN_ECHO_SWITCHYARD_SCHEMA_BYTES,
                BOUNDED_TURN_ECHO_SWITCHYARD_SCHEMA_SHA256,
            )
        }
        Some(FINAL_CODEX_OWNER_HEAD) if matches!(capture, SwitchyardCaptureSchema::BoundedTurn) => {
            (
                BOUNDED_TURN_SWITCHYARD_SCHEMA_BYTES,
                BOUNDED_TURN_SWITCHYARD_SCHEMA_SHA256,
            )
        }
        Some(FINAL_CODEX_OWNER_HEAD) => (
            FINAL_SWITCHYARD_SCHEMA_BYTES,
            FINAL_SWITCHYARD_SCHEMA_SHA256,
        ),
        Some(BETA_CODEX_OWNER_HEAD) => {
            (BETA_SWITCHYARD_SCHEMA_BYTES, BETA_SWITCHYARD_SCHEMA_SHA256)
        }
        _ => return Err(ContractError::InvalidField("snapshot schema owner")),
    };
    if plain_sha256(bytes) != expected {
        return Err(ContractError::DigestMismatch(
            "vendored Switchyard schema sha256",
        ));
    }
    let root: Value = serde_json::from_slice(bytes).map_err(json_error)?;
    validate_schema_node(&root, &root, instance, 0)?;
    Ok(())
}

fn validate_schema_node(
    root: &Value,
    node: &Value,
    instance: &Value,
    depth: usize,
) -> Result<BTreeSet<String>, ContractError> {
    if depth > 64 {
        return Err(ContractError::InvalidField("Switchyard schema depth"));
    }
    let schema = node
        .as_object()
        .ok_or(ContractError::InvalidField("Switchyard schema node"))?;
    let mut evaluated = BTreeSet::new();

    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let name = reference
            .strip_prefix("#/$defs/")
            .ok_or(ContractError::InvalidField("Switchyard schema ref"))?;
        let target = root
            .get("$defs")
            .and_then(|defs| defs.get(name))
            .ok_or(ContractError::InvalidField("Switchyard schema ref"))?;
        evaluated.extend(validate_schema_node(root, target, instance, depth + 1)?);
    }
    if let Some(all) = schema.get("allOf").and_then(Value::as_array) {
        for branch in all {
            evaluated.extend(validate_schema_node(root, branch, instance, depth + 1)?);
        }
    }
    if let Some(branches) = schema.get("oneOf").and_then(Value::as_array) {
        let matches: Vec<_> = branches
            .iter()
            .filter_map(|branch| validate_schema_node(root, branch, instance, depth + 1).ok())
            .collect();
        if matches.len() != 1 {
            return Err(ContractError::InvalidField("Switchyard schema oneOf"));
        }
        evaluated.extend(matches.into_iter().next().expect("one exact match"));
    }
    if let Some(expected) = schema.get("const") {
        if expected != instance {
            return Err(ContractError::InvalidField("Switchyard schema const"));
        }
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        if !values.contains(instance) {
            return Err(ContractError::InvalidField("Switchyard schema enum"));
        }
    }
    if let Some(expected_type) = schema.get("type").and_then(Value::as_str) {
        let type_matches = match expected_type {
            "null" => instance.is_null(),
            "boolean" => instance.is_boolean(),
            "string" => instance.is_string(),
            "integer" => instance.as_i64().is_some() || instance.as_u64().is_some(),
            "object" => instance.is_object(),
            "array" => instance.is_array(),
            _ => false,
        };
        if !type_matches {
            return Err(ContractError::InvalidField("Switchyard schema type"));
        }
    }

    if let Some(text) = instance.as_str() {
        let length = text.chars().count() as u64;
        if schema
            .get("minLength")
            .and_then(Value::as_u64)
            .is_some_and(|minimum| length < minimum)
            || schema
                .get("maxLength")
                .and_then(Value::as_u64)
                .is_some_and(|maximum| length > maximum)
        {
            return Err(ContractError::InvalidField(
                "Switchyard schema string bound",
            ));
        }
        if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
            let matches = match pattern {
                "^[0-9a-f]+$" => {
                    !text.is_empty()
                        && text
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                }
                "^sha256:[0-9a-f]{64}$" => {
                    text.len() == 71
                        && text.starts_with("sha256:")
                        && text[7..]
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                }
                _ => false,
            };
            if !matches {
                return Err(ContractError::InvalidField("Switchyard schema pattern"));
            }
        }
    }
    if instance.as_i64().is_some() || instance.as_u64().is_some() {
        let value = instance
            .as_i64()
            .map(|value| value as i128)
            .or_else(|| instance.as_u64().map(|value| value as i128))
            .ok_or(ContractError::InvalidField("Switchyard schema integer"))?;
        if schema
            .get("minimum")
            .and_then(Value::as_i64)
            .is_some_and(|minimum| value < minimum as i128)
            || schema
                .get("maximum")
                .and_then(Value::as_i64)
                .is_some_and(|maximum| value > maximum as i128)
        {
            return Err(ContractError::InvalidField(
                "Switchyard schema numeric bound",
            ));
        }
    }
    if let Some(items) = instance.as_array() {
        if schema
            .get("maxItems")
            .and_then(Value::as_u64)
            .is_some_and(|maximum| items.len() as u64 > maximum)
        {
            return Err(ContractError::InvalidField("Switchyard schema array bound"));
        }
        if let Some(item_schema) = schema.get("items") {
            for item in items {
                validate_schema_node(root, item_schema, item, depth + 1)?;
            }
        }
    }
    if let Some(object) = instance.as_object() {
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            if required.iter().any(|field| {
                field
                    .as_str()
                    .is_none_or(|field| !object.contains_key(field))
            }) {
                return Err(ContractError::InvalidField("Switchyard schema required"));
            }
        }
        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            for (name, property_schema) in properties {
                evaluated.insert(name.clone());
                if let Some(value) = object.get(name) {
                    validate_schema_node(root, property_schema, value, depth + 1)?;
                }
            }
            if schema.get("additionalProperties").and_then(Value::as_bool) == Some(false)
                && object.keys().any(|name| !properties.contains_key(name))
            {
                return Err(ContractError::InvalidField(
                    "Switchyard schema additional property",
                ));
            }
        }
        if schema.get("unevaluatedProperties").and_then(Value::as_bool) == Some(false)
            && object.keys().any(|name| !evaluated.contains(name))
        {
            return Err(ContractError::InvalidField(
                "Switchyard schema unevaluated property",
            ));
        }
    }
    Ok(evaluated)
}

fn switchyard_record_raw_bound(record: &Value) -> usize {
    if record["acquisition_kind"].as_str() == Some("CLIENT_REQUEST")
        && record["method"].as_str() == Some("client-request/turn/start")
        || record["acquisition_kind"].as_str() == Some("NOTIFICATION")
            && matches!(
                record["method"].as_str(),
                Some(
                    "item/started"
                        | "item/completed"
                        | "item/agentMessage/delta"
                        | "turn/completed"
                )
            )
    {
        MAXIMUM_TURN_START_REQUEST_EVIDENCE_BYTES
    } else {
        MAXIMUM_AVAILABILITY_EVIDENCE_BYTES
    }
}

fn validate_switchyard_raw(value: &Value, maximum: usize) -> Result<(), ContractError> {
    exact_object_keys(
        value,
        &[
            "representation",
            "byte_length",
            "sha256",
            "encoding",
            "bytes_hex",
        ],
        "mapper raw closure",
    )?;
    let representation = string(value, "representation")?;
    if !matches!(
        representation,
        "EXACT_WIRE_BYTES_INCLUDING_LINE_TERMINATOR"
            | "EXACT_ACQUIRED_FRAME_BYTES_INCLUDING_LINE_TERMINATOR"
    ) || string(value, "encoding")? != "hex"
    {
        return Err(ContractError::InvalidField("mapper raw representation"));
    }
    let bytes_hex = string(value, "bytes_hex")?;
    if bytes_hex
        .bytes()
        .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(ContractError::InvalidField("mapper raw lowercase hex"));
    }
    let bytes =
        hex::decode(bytes_hex).map_err(|_| ContractError::InvalidField("mapper raw hex"))?;
    if bytes.is_empty()
        || bytes.len() > maximum
        || bytes.last() != Some(&b'\n')
        || integer(value, "byte_length")? != bytes.len() as i64
        || string(value, "sha256")? != plain_sha256(&bytes)
    {
        return Err(ContractError::InvalidField("mapper raw custody"));
    }
    Ok(())
}

struct UniqueJson(Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJson;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("unique-key JSON")
    }
    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Bool(value)))
    }
    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Number(value.into())))
    }
    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Number(value.into())))
    }
    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueJson)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }
    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::String(value.to_owned())))
    }
    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::String(value)))
    }
    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Null))
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson(Value::Null))
    }
    fn visit_seq<A>(self, mut values: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut result = Vec::new();
        while let Some(value) = values.next_element::<UniqueJson>()? {
            result.push(value.0);
        }
        Ok(UniqueJson(Value::Array(result)))
    }
    fn visit_map<A>(self, mut values: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut result = serde_json::Map::new();
        while let Some(key) = values.next_key::<String>()? {
            if result.contains_key(&key) {
                return Err(A::Error::custom("duplicate JSON object key"));
            }
            result.insert(key, values.next_value::<UniqueJson>()?.0);
        }
        Ok(UniqueJson(Value::Object(result)))
    }
}

fn decode_switchyard_raw(value: &Value, maximum: usize) -> Result<Value, ContractError> {
    validate_switchyard_raw(value, maximum)?;
    let bytes = hex::decode(string(value, "bytes_hex")?)
        .map_err(|_| ContractError::InvalidField("mapper raw hex"))?;
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    let decoded = UniqueJson::deserialize(&mut deserializer)
        .map_err(|_| ContractError::InvalidField("unique mapper raw JSON"))?;
    deserializer
        .end()
        .map_err(|_| ContractError::InvalidField("mapper raw JSON framing"))?;
    Ok(decoded.0)
}

fn exact_object_keys(
    value: &Value,
    expected: &[&str],
    field: &'static str,
) -> Result<(), ContractError> {
    let object = value
        .as_object()
        .ok_or(ContractError::InvalidField(field))?;
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err(ContractError::InvalidField(field));
    }
    Ok(())
}

fn string<'a>(value: &'a Value, field: &'static str) -> Result<&'a str, ContractError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(ContractError::InvalidField(field))
}

fn integer(value: &Value, field: &'static str) -> Result<i64, ContractError> {
    value
        .get(field)
        .and_then(Value::as_i64)
        .ok_or(ContractError::InvalidField(field))
}

fn canonical_value_digest(
    value: &Value,
    field: &'static str,
    domain: &[u8],
) -> Result<String, ContractError> {
    let mut basis = value.clone();
    basis
        .as_object_mut()
        .ok_or(ContractError::InvalidField(field))?
        .remove(field);
    let canonical = serde_jcs::to_vec(&basis).map_err(json_error)?;
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(canonical);
    Ok(format!("sha256:{:x}", hash.finalize()))
}

fn validate_switchyard_snapshot_complete(
    disposition: &ProviderAdmissionDispositionV1,
    raw: &[u8],
) -> Result<(), ContractError> {
    validate_switchyard_snapshot(disposition, raw)?;
    let snapshot: Value = serde_json::from_slice(raw).map_err(json_error)?;
    if serde_jcs::to_vec(&snapshot).map_err(json_error)? != raw {
        return Err(ContractError::InvalidField(
            "mapper snapshot RFC8785 representation",
        ));
    }
    validate_safe_json(&snapshot)?;
    let echo_errors = bounded_turn_echo::validate_snapshot(&snapshot, false)?;
    let records = snapshot["records"]
        .as_array()
        .ok_or(ContractError::InvalidField("mapper records"))?;
    if records.is_empty() {
        return Err(ContractError::InvalidField("empty mapper evidence"));
    }

    let mut next_acquisition_ordinal = 0_i64;
    let mut pending_request: Option<(String, i64, i64, i64)> = None;
    let mut completed_request_occurrences = BTreeSet::new();
    let mut last_boundary_ms: Option<i64> = None;
    let mut client_requests: BTreeMap<i64, (String, String)> = BTreeMap::new();
    let mut execution: Option<ProviderExecutionIdentityV1> = None;
    let mut open_response: Option<String> = None;
    let mut completed_responses = BTreeSet::new();
    let mut refusal: Option<(String, Option<i64>, i64)> = None;
    let mut saw_turn_completed = false;
    let mut saw_approval = false;
    let mut saw_discrepancy = false;
    let mut cut_value: Option<&Value> = None;

    for (index, record) in records.iter().enumerate() {
        let kind = string(record, "kind")?;
        let method = string(record, "method")?;
        let acquisition_ordinal = record
            .get("acquisition_ordinal")
            .ok_or(ContractError::InvalidField("acquisition ordinal"))?;
        let acquisition_kind = record
            .get("acquisition_kind")
            .ok_or(ContractError::InvalidField("acquisition kind"))?;
        let normalized = record
            .get("normalized")
            .ok_or(ContractError::InvalidField("mapper normalized evidence"))?;
        let raw_evidence = record
            .get("raw")
            .ok_or(ContractError::InvalidField("mapper raw evidence"))?;

        if kind == "ACQUISITION_CUT" {
            if index + 1 != records.len()
                || !acquisition_ordinal.is_null()
                || !acquisition_kind.is_null()
                || !raw_evidence.is_null()
                || method != "adapter/acquisition-cut"
            {
                return Err(ContractError::InvalidField(
                    "terminal acquisition-cut order",
                ));
            }
            exact_object_keys(
                normalized,
                &[
                    "adapter_process_occurrence_id",
                    "app_server_session_identity",
                    "stream_quiesced",
                    "loss_generation",
                    "process_disposition",
                    "ordered_high_water",
                    "consumed_ordinal_count",
                    "outstanding_client_request_count",
                    "clean",
                ],
                "acquisition-cut closure",
            )?;
            cut_value = Some(normalized);
            continue;
        }
        if cut_value.is_some() {
            return Err(ContractError::InvalidField("evidence after terminal cut"));
        }
        let client_lane = matches!(
            acquisition_kind.as_str(),
            Some("CLIENT_REQUEST" | "CLIENT_RESPONSE")
        );
        if (saw_discrepancy || (saw_turn_completed && execution.is_some()))
            && kind != "ADMISSION_DISCREPANCY"
            && !client_lane
        {
            return Err(ContractError::InvalidField(
                "owner mechanism transition bypass",
            ));
        }

        validate_switchyard_raw_replay(
            record,
            &snapshot["binding"],
            &SwitchyardReplayState {
                current_execution: execution.as_ref(),
                pending_request: pending_request.as_ref(),
                open_response: open_response.as_deref(),
                saw_turn_completed,
                saw_approval,
                saw_discrepancy,
                refusal_closed: refusal.is_some(),
                last_boundary_ms,
                completed_request_count: completed_request_occurrences.len(),
                completed_request_occurrences: &completed_request_occurrences,
                completed_responses: &completed_responses,
                client_requests: &client_requests,
                echo_error: echo_errors[index],
            },
        )?;

        if let Some(ordinal) = acquisition_ordinal.as_i64() {
            if ordinal != next_acquisition_ordinal {
                if kind != "ADMISSION_DISCREPANCY"
                    || method != "adapter/acquisition"
                    || normalized.get("detail").and_then(Value::as_str)
                        != Some("ordered acquisition ordinal gap, duplicate, or reorder")
                {
                    return Err(ContractError::InvalidField(
                        "acquisition ordinal continuity",
                    ));
                }
                next_acquisition_ordinal = next_acquisition_ordinal.max(
                    ordinal
                        .checked_add(1)
                        .ok_or(ContractError::InvalidField("acquisition ordinal overflow"))?,
                );
            } else {
                next_acquisition_ordinal += 1;
            }
            let lane = acquisition_kind
                .as_str()
                .ok_or(ContractError::InvalidField("acquisition kind"))?;
            if !matches!(
                lane,
                "LOSS"
                    | "NOTIFICATION"
                    | "SERVER_REQUEST"
                    | "CLIENT_REQUEST"
                    | "CLIENT_RESPONSE"
                    | "UNKNOWN"
            ) {
                return Err(ContractError::InvalidField("acquisition kind"));
            }
            if let Some(raw_value) = raw_evidence.as_object() {
                let representation = raw_value
                    .get("representation")
                    .and_then(Value::as_str)
                    .ok_or(ContractError::InvalidField("mapper raw representation"))?;
                let expected = if lane == "LOSS" {
                    "EXACT_ACQUIRED_FRAME_BYTES_INCLUDING_LINE_TERMINATOR"
                } else {
                    "EXACT_WIRE_BYTES_INCLUDING_LINE_TERMINATOR"
                };
                if representation != expected {
                    return Err(ContractError::InvalidField(
                        "mapper raw lane representation",
                    ));
                }
            } else if !matches!(lane, "LOSS" | "UNKNOWN") && kind != "ADMISSION_DISCREPANCY" {
                return Err(ContractError::InvalidField("mapper raw evidence absence"));
            }
            validate_kind_lane(kind, method, lane)?;
        } else if !acquisition_kind.is_null() {
            return Err(ContractError::InvalidField("partial acquisition identity"));
        }

        match kind {
            "PROVIDER_REQUEST_STARTED" => {
                exact_object_keys(
                    normalized,
                    &[
                        "request_occurrence_id",
                        "sampling_ordinal",
                        "request_order",
                        "started_at_ms",
                        "proves_provider_admission",
                    ],
                    "provider request normalized closure",
                )?;
                if normalized
                    .get("proves_provider_admission")
                    .and_then(Value::as_bool)
                    != Some(false)
                    || pending_request.is_some()
                    || open_response.is_some()
                    || saw_approval
                    || refusal.is_some()
                {
                    return Err(ContractError::InvalidField("provider request transition"));
                }
                let occurrence = string(normalized, "request_occurrence_id")?.to_owned();
                let sampling_ordinal = integer(normalized, "sampling_ordinal")?;
                let request_order = integer(normalized, "request_order")?;
                let started_at_ms = integer(normalized, "started_at_ms")?;
                let expected_order = completed_request_occurrences.len() as i64;
                if sampling_ordinal != expected_order
                    || request_order != expected_order
                    || completed_request_occurrences.contains(&occurrence)
                    || last_boundary_ms.is_some_and(|boundary| started_at_ms < boundary)
                    || (sampling_ordinal > 0 && execution.is_none())
                {
                    return Err(ContractError::InvalidField(
                        "provider request exact owner ordering",
                    ));
                }
                pending_request =
                    Some((occurrence, sampling_ordinal, request_order, started_at_ms));
            }
            "PROVIDER_EXECUTION_STEP" => {
                exact_object_keys(
                    normalized,
                    &[
                        "provider_execution_identity",
                        "provider_execution_step_identity",
                        "first_admission_boundary",
                        "observed_at_ms",
                    ],
                    "provider step normalized closure",
                )?;
                let step = normalized
                    .get("provider_execution_step_identity")
                    .ok_or(ContractError::InvalidField("provider step identity"))?;
                if saw_approval {
                    return Err(ContractError::InvalidField(
                        "provider activity followed unanswered approval",
                    ));
                }
                let (pending, sampling_ordinal, request_order, started_at_ms) =
                    pending_request.take().ok_or(ContractError::InvalidField(
                        "response without provider request",
                    ))?;
                if string(step, "request_occurrence_id")? != pending
                    || string(step, "provider")? != disposition.provider_id
                    || string(step, "model")? != disposition.model_id
                    || string(step, "thread_id")? != disposition.thread_id
                    || string(step, "turn_id")? != disposition.turn_id
                    || integer(step, "sampling_ordinal")? != sampling_ordinal
                    || integer(step, "request_order")? != request_order
                {
                    return Err(ContractError::InvalidField("provider step request binding"));
                }
                if execution.is_none() && pending != disposition.provider_request_occurrence_id {
                    return Err(ContractError::InvalidField(
                        "admitted provider request occurrence",
                    ));
                }
                let identity = normalized
                    .get("provider_execution_identity")
                    .ok_or(ContractError::InvalidField("provider execution identity"))?;
                let observed = ProviderExecutionIdentityV1 {
                    provider_id: string(identity, "provider")?.to_owned(),
                    model_id: string(identity, "model")?.to_owned(),
                    app_server_session_identity: string(identity, "app_server_session_identity")?
                        .to_owned(),
                    thread_id: string(identity, "thread_id")?.to_owned(),
                    turn_id: string(identity, "turn_id")?.to_owned(),
                    first_response_id: string(identity, "first_response_id")?.to_owned(),
                };
                observed.validate()?;
                if provider_execution_from_switchyard(identity)? != observed
                    || provider_execution_from_switchyard(
                        normalized
                            .get("provider_execution_identity")
                            .ok_or(ContractError::InvalidField("provider execution identity"))?,
                    )? != observed
                {
                    return Err(ContractError::InvalidField(
                        "nested provider execution identity",
                    ));
                }
                if execution.as_ref().is_some_and(|prior| prior != &observed)
                    || open_response.is_some()
                {
                    return Err(ContractError::InvalidField("provider execution continuity"));
                }
                let response_id = string(step, "response_id")?.to_owned();
                let observed_at_ms = integer(normalized, "observed_at_ms")?;
                if response_id != observed.first_response_id && execution.is_none() {
                    return Err(ContractError::InvalidField("first response identity"));
                }
                if observed_at_ms < started_at_ms
                    || last_boundary_ms.is_some_and(|boundary| observed_at_ms < boundary)
                    || completed_responses.contains(&response_id)
                    || !completed_request_occurrences.insert(pending)
                {
                    return Err(ContractError::InvalidField(
                        "provider response exact owner ordering",
                    ));
                }
                last_boundary_ms = Some(observed_at_ms);
                execution = Some(observed);
                open_response = Some(response_id);
            }
            "PROVIDER_ADMISSION_REFUSED" => {
                if refusal.is_some() || execution.is_some() || pending_request.is_none() {
                    return Err(ContractError::InvalidField("refusal transition"));
                }
                let occurrence = string(normalized, "request_occurrence_id")?.to_owned();
                let pending = pending_request.take();
                if pending.as_ref().map(|value| value.0.as_str()) != Some(occurrence.as_str())
                    || pending.as_ref().map(|value| value.1)
                        != Some(integer(normalized, "sampling_ordinal")?)
                    || pending.as_ref().map(|value| value.2)
                        != Some(integer(normalized, "request_order")?)
                {
                    return Err(ContractError::InvalidField("refusal request binding"));
                }
                let observed_at_ms = integer(normalized, "observed_at_ms")?;
                if pending
                    .as_ref()
                    .is_none_or(|value| observed_at_ms < value.3)
                    || last_boundary_ms.is_some_and(|boundary| observed_at_ms < boundary)
                    || !completed_request_occurrences.insert(occurrence.clone())
                {
                    return Err(ContractError::InvalidField(
                        "provider refusal exact owner ordering",
                    ));
                }
                last_boundary_ms = Some(observed_at_ms);
                let retry_after = match normalized.get("retry_after_ms") {
                    Some(Value::Null) => None,
                    Some(value) => value.as_i64(),
                    None => return Err(ContractError::InvalidField("retry_after_ms")),
                };
                refusal = Some((
                    occurrence,
                    retry_after,
                    integer(normalized, "observed_at_ms")?,
                ));
            }
            "PROVIDER_RESPONSE_COMPLETED" => {
                exact_object_keys(
                    normalized,
                    &["response_id", "proves_new_admission"],
                    "provider completion normalized closure",
                )?;
                if normalized
                    .get("proves_new_admission")
                    .and_then(Value::as_bool)
                    != Some(false)
                {
                    return Err(ContractError::InvalidField(
                        "completion admission substitution",
                    ));
                }
                let response_id = string(normalized, "response_id")?;
                if open_response.as_deref() != Some(response_id)
                    || !completed_responses.insert(response_id.to_owned())
                {
                    return Err(ContractError::InvalidField("response completion order"));
                }
                open_response = None;
            }
            "WAITING_APPROVAL" => {
                exact_object_keys(
                    normalized,
                    &[
                        "approval_response_sent",
                        "protected_effect_absent",
                        "provider_execution_identity",
                    ],
                    "approval normalized closure",
                )?;
                if execution.is_none()
                    || open_response.is_some()
                    || saw_approval
                    || normalized
                        .get("approval_response_sent")
                        .and_then(Value::as_bool)
                        != Some(false)
                    || normalized
                        .get("protected_effect_absent")
                        .and_then(Value::as_bool)
                        != Some(true)
                {
                    return Err(ContractError::InvalidField("approval transition"));
                }
                let approval_execution = provider_execution_from_switchyard(
                    normalized
                        .get("provider_execution_identity")
                        .ok_or(ContractError::InvalidField("approval execution identity"))?,
                )?;
                if execution.as_ref() != Some(&approval_execution) {
                    return Err(ContractError::InvalidField(
                        "approval execution identity binding",
                    ));
                }
                saw_approval = true;
            }
            "LOCAL_TURN_FACT" => {
                exact_object_keys(
                    normalized,
                    &["proves_provider_admission"],
                    "local fact normalized closure",
                )?;
                if normalized
                    .get("proves_provider_admission")
                    .and_then(Value::as_bool)
                    != Some(false)
                {
                    return Err(ContractError::InvalidField("local fact admission widening"));
                }
                if method == "turn/completed" {
                    let exact_refusal_close = execution.is_none()
                        && refusal.is_some()
                        && open_response.is_none()
                        && pending_request.is_none();
                    let exact_execution_close = execution.is_some()
                        && open_response.is_none()
                        && pending_request.is_none()
                        && !saw_approval;
                    if !exact_refusal_close && !exact_execution_close {
                        return Err(ContractError::InvalidField("premature turn completion"));
                    }
                    saw_turn_completed = true;
                }
            }
            "ADMISSION_DISCREPANCY" => {
                exact_object_keys(
                    normalized,
                    &[
                        "detail",
                        "provider_execution_identity",
                        "resume_same_attempt_only",
                    ],
                    "discrepancy normalized closure",
                )?;
                if normalized
                    .get("resume_same_attempt_only")
                    .and_then(Value::as_bool)
                    != Some(execution.is_some())
                {
                    return Err(ContractError::InvalidField("discrepancy resume law"));
                }
                let discrepancy_execution = match normalized.get("provider_execution_identity") {
                    Some(Value::Null) => None,
                    Some(value) => Some(provider_execution_from_switchyard(value)?),
                    None => {
                        return Err(ContractError::InvalidField(
                            "discrepancy execution identity",
                        ));
                    }
                };
                if discrepancy_execution.as_ref() != execution.as_ref() {
                    return Err(ContractError::InvalidField(
                        "discrepancy execution identity binding",
                    ));
                }
                saw_discrepancy = true;
            }
            "CLIENT_REQUEST_ISSUED" => {
                exact_object_keys(
                    normalized,
                    &[
                        "request_id",
                        "request_method",
                        "params_sha256",
                        "proves_provider_admission",
                    ],
                    "client request normalized closure",
                )?;
                digest("client params sha256", string(normalized, "params_sha256")?)?;
                let request_id = integer(normalized, "request_id")?;
                if client_requests
                    .insert(
                        request_id,
                        (
                            string(normalized, "request_method")?.to_owned(),
                            string(normalized, "params_sha256")?.to_owned(),
                        ),
                    )
                    .is_some()
                {
                    return Err(ContractError::InvalidField("duplicate client request"));
                }
            }
            "CLIENT_RESPONSE_RETAINED" => {
                exact_object_keys(
                    normalized,
                    &[
                        "request_id",
                        "request_method",
                        "params_sha256",
                        "result_sha256",
                        "proves_provider_admission",
                    ],
                    "client response normalized closure",
                )?;
                digest("client params sha256", string(normalized, "params_sha256")?)?;
                digest("client result sha256", string(normalized, "result_sha256")?)?;
                let request_id = integer(normalized, "request_id")?;
                let expected = client_requests
                    .remove(&request_id)
                    .ok_or(ContractError::InvalidField("unmatched client response"))?;
                if expected.0 != string(normalized, "request_method")?
                    || expected.1 != string(normalized, "params_sha256")?
                {
                    return Err(ContractError::InvalidField(
                        "client request response binding",
                    ));
                }
            }
            "ACQUISITION_WATERMARK" => {
                exact_object_keys(
                    normalized,
                    &["proves_provider_admission"],
                    "watermark normalized closure",
                )?;
            }
            "ACQUISITION_CUT" => unreachable!(),
            _ => return Err(ContractError::InvalidField("mapper evidence kind")),
        }
    }

    let expected_clean = if let Some(cut) = cut_value {
        if snapshot.get("acquisition_cut") != Some(cut) {
            return Err(ContractError::InvalidField(
                "snapshot acquisition-cut record binding",
            ));
        }
        let process = string(cut, "process_disposition")?;
        let process_closed = matches!(
            process,
            "EXITED" | "EXITED_AFTER_TERMINATE" | "EXITED_AFTER_KILL"
        );
        if !matches!(
            process,
            "UNKNOWN"
                | "ABSENT"
                | "RUNNING"
                | "EXITED"
                | "EXITED_AFTER_TERMINATE"
                | "EXITED_AFTER_KILL"
                | "EXIT_UNCONFIRMED"
        ) || string(cut, "adapter_process_occurrence_id")?
            != disposition.adapter_process_occurrence_id
            || string(cut, "app_server_session_identity")?
                != disposition.app_server_session_identity
            || integer(cut, "consumed_ordinal_count")? != next_acquisition_ordinal
        {
            return Err(ContractError::InvalidField("acquisition-cut identity"));
        }
        let stream_quiesced = cut
            .get("stream_quiesced")
            .and_then(Value::as_bool)
            .ok_or(ContractError::InvalidField("stream_quiesced"))?;
        let loss_generation = integer(cut, "loss_generation")?;
        let ordered_high_water = integer(cut, "ordered_high_water")?;
        let outstanding = integer(cut, "outstanding_client_request_count")?;
        if outstanding != client_requests.len() as i64 {
            return Err(ContractError::InvalidField(
                "client request cut outstanding binding",
            ));
        }
        let semantic_closed = (refusal.is_some() && !saw_discrepancy)
            || (execution.is_some()
                && open_response.is_none()
                && saw_turn_completed
                && !saw_approval
                && !saw_discrepancy);
        let clean = stream_quiesced
            && process_closed
            && loss_generation == 0
            && ordered_high_water == next_acquisition_ordinal
            && outstanding == 0
            && semantic_closed;
        if cut.get("clean").and_then(Value::as_bool) != Some(clean)
            || disposition.acquisition_complete != clean
        {
            return Err(ContractError::InvalidField("acquisition-cut clean law"));
        }
        clean
    } else {
        if snapshot.get("acquisition_cut") != Some(&Value::Null)
            || !client_requests.is_empty()
            || disposition.acquisition_complete
            || !matches!(
                disposition.mechanism_state,
                ProviderMechanismStateV1::ExecutionAdmitted
                    | ProviderMechanismStateV1::WaitingApproval
            )
            || execution.is_none()
            || refusal.is_some()
        {
            return Err(ContractError::InvalidField("pre-cut admitted state"));
        }
        false
    };

    let snapshot_state = string(&snapshot, "mechanism_state")?;
    let expected_state = match disposition.mechanism_state {
        ProviderMechanismStateV1::ParkedNotAdmitted => "PARKED_NOT_ADMITTED",
        ProviderMechanismStateV1::AdmissionIndeterminate => "ADMISSION_INDETERMINATE",
        ProviderMechanismStateV1::ExecutionAdmitted => "EXECUTION_ADMITTED",
        ProviderMechanismStateV1::PostAdmissionInterrupted => "POST_ADMISSION_INTERRUPTED",
        ProviderMechanismStateV1::WaitingApproval => "WAITING_APPROVAL",
        ProviderMechanismStateV1::ProviderCompleted => "PROVIDER_COMPLETED",
    };
    if snapshot_state != expected_state {
        return Err(ContractError::InvalidField(
            "mapper mechanism-state binding",
        ));
    }
    let snapshot_execution = match snapshot.get("provider_execution_identity") {
        Some(Value::Null) => None,
        Some(value) => Some(provider_execution_from_switchyard(value)?),
        None => return Err(ContractError::InvalidField("snapshot execution identity")),
    };
    if snapshot_execution != execution
        || snapshot_execution != disposition.provider_execution
        || disposition.response_created != snapshot_execution.is_some()
    {
        return Err(ContractError::InvalidField(
            "snapshot disposition execution binding",
        ));
    }
    match disposition.mechanism_state {
        ProviderMechanismStateV1::ParkedNotAdmitted => {
            if refusal.is_none() || !expected_clean || execution.is_some() {
                return Err(ContractError::InvalidField("parked mechanism state"));
            }
        }
        ProviderMechanismStateV1::ProviderCompleted => {
            if execution.is_none() || !expected_clean {
                return Err(ContractError::InvalidField("completed mechanism state"));
            }
        }
        ProviderMechanismStateV1::PostAdmissionInterrupted => {
            if execution.is_none() || expected_clean {
                return Err(ContractError::InvalidField(
                    "post-admission interruption state",
                ));
            }
        }
        ProviderMechanismStateV1::WaitingApproval => {
            if !saw_approval || cut_value.is_some() {
                return Err(ContractError::InvalidField("waiting approval terminal cut"));
            }
        }
        ProviderMechanismStateV1::AdmissionIndeterminate => {
            if execution.is_some() {
                return Err(ContractError::InvalidField(
                    "indeterminate execution identity",
                ));
            }
        }
        ProviderMechanismStateV1::ExecutionAdmitted => {
            if execution.is_none() || cut_value.is_some() {
                return Err(ContractError::InvalidField("pre-cut admitted state"));
            }
        }
    }
    if let Some((occurrence, retry_after_ms, observed_at_ms)) = refusal {
        if occurrence != disposition.provider_request_occurrence_id {
            return Err(ContractError::InvalidField("refusal occurrence binding"));
        }
        let received_ms = disposition.received_at.timestamp_millis();
        if received_ms < observed_at_ms {
            return Err(ContractError::InvalidField("pre-receipt disposition time"));
        }
        let expected_retry =
            retry_after_ms.map(|delay| disposition.received_at + Duration::milliseconds(delay));
        if expected_retry != disposition.provider_retry_after {
            return Err(ContractError::InvalidField("provider retry-after binding"));
        }
    } else if disposition.provider_retry_after.is_some() {
        return Err(ContractError::InvalidField(
            "unwitnessed provider retry-after",
        ));
    }
    Ok(())
}

fn provider_execution_from_switchyard(
    value: &Value,
) -> Result<ProviderExecutionIdentityV1, ContractError> {
    Ok(ProviderExecutionIdentityV1 {
        provider_id: string(value, "provider")?.to_owned(),
        model_id: string(value, "model")?.to_owned(),
        app_server_session_identity: string(value, "app_server_session_identity")?.to_owned(),
        thread_id: string(value, "thread_id")?.to_owned(),
        turn_id: string(value, "turn_id")?.to_owned(),
        first_response_id: string(value, "first_response_id")?.to_owned(),
    })
}

fn validate_kind_lane(kind: &str, method: &str, lane: &str) -> Result<(), ContractError> {
    let valid = match kind {
        "CLIENT_REQUEST_ISSUED" => {
            lane == "CLIENT_REQUEST" && method.starts_with("client-request/")
        }
        "CLIENT_RESPONSE_RETAINED" => {
            lane == "CLIENT_RESPONSE" && method.starts_with("client-response/")
        }
        "PROVIDER_REQUEST_STARTED" => lane == "NOTIFICATION" && method == "providerRequest/started",
        "PROVIDER_EXECUTION_STEP" => lane == "NOTIFICATION" && method == "rawResponse/started",
        "PROVIDER_ADMISSION_REFUSED" => {
            lane == "NOTIFICATION" && method == "providerAdmission/refused"
        }
        "PROVIDER_RESPONSE_COMPLETED" => {
            lane == "NOTIFICATION" && method == "rawResponse/completed"
        }
        "WAITING_APPROVAL" => {
            lane == "SERVER_REQUEST"
                && matches!(
                    method,
                    "item/commandExecution/requestApproval" | "item/fileChange/requestApproval"
                )
        }
        "LOCAL_TURN_FACT" | "ACQUISITION_WATERMARK" => lane == "NOTIFICATION",
        "ADMISSION_DISCREPANCY" => matches!(
            lane,
            "LOSS"
                | "UNKNOWN"
                | "NOTIFICATION"
                | "SERVER_REQUEST"
                | "CLIENT_REQUEST"
                | "CLIENT_RESPONSE"
        ),
        _ => false,
    };
    if !valid {
        return Err(ContractError::InvalidField(
            "evidence kind/lane/method binding",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct SwitchyardReplayState<'a> {
    current_execution: Option<&'a ProviderExecutionIdentityV1>,
    pending_request: Option<&'a (String, i64, i64, i64)>,
    open_response: Option<&'a str>,
    saw_turn_completed: bool,
    saw_approval: bool,
    saw_discrepancy: bool,
    refusal_closed: bool,
    last_boundary_ms: Option<i64>,
    completed_request_count: usize,
    completed_request_occurrences: &'a BTreeSet<String>,
    completed_responses: &'a BTreeSet<String>,
    client_requests: &'a BTreeMap<i64, (String, String)>,
    echo_error: Option<&'static str>,
}

fn validate_switchyard_raw_replay(
    record: &Value,
    binding: &Value,
    state: &SwitchyardReplayState<'_>,
) -> Result<(), ContractError> {
    let SwitchyardReplayState {
        current_execution,
        pending_request,
        open_response,
        saw_turn_completed,
        saw_approval,
        saw_discrepancy,
        refusal_closed,
        last_boundary_ms,
        completed_request_count,
        completed_request_occurrences,
        completed_responses,
        client_requests,
        echo_error,
    } = *state;
    let kind = string(record, "kind")?;
    let method = string(record, "method")?;
    let normalized = record
        .get("normalized")
        .ok_or(ContractError::InvalidField("raw replay normalized"))?;
    let raw = record
        .get("raw")
        .ok_or(ContractError::InvalidField("raw replay custody"))?;
    let lane = record.get("acquisition_kind").and_then(Value::as_str);
    let validate_discrepancy = |expected_detail: Option<&str>| -> Result<(), ContractError> {
        let execution = current_execution.map(|execution| {
            serde_json::json!({
                "provider":execution.provider_id,"model":execution.model_id,
                "app_server_session_identity":execution.app_server_session_identity,
                "thread_id":execution.thread_id,"turn_id":execution.turn_id,
                "first_response_id":execution.first_response_id,
            })
        });
        exact_object_keys(
            normalized,
            &[
                "detail",
                "provider_execution_identity",
                "resume_same_attempt_only",
            ],
            "rawless acquisition loss normalized closure",
        )?;
        let expected_execution = execution.unwrap_or(Value::Null);
        let detail = string(normalized, "detail")?;
        if detail.is_empty()
            || expected_detail.is_some_and(|expected| detail != expected)
            || normalized.get("provider_execution_identity") != Some(&expected_execution)
            || normalized
                .get("resume_same_attempt_only")
                .and_then(Value::as_bool)
                != Some(current_execution.is_some())
        {
            return Err(ContractError::InvalidField(
                "acquisition discrepancy replay",
            ));
        }
        Ok(())
    };
    if lane == Some("LOSS") {
        if kind != "ADMISSION_DISCREPANCY" || method != "adapter/acquisition" {
            return Err(ContractError::InvalidField("loss evidence kind"));
        }
        if !raw.is_null() {
            validate_switchyard_raw(raw, MAXIMUM_AVAILABILITY_EVIDENCE_BYTES)?;
            if string(raw, "representation")?
                != "EXACT_ACQUIRED_FRAME_BYTES_INCLUDING_LINE_TERMINATOR"
            {
                return Err(ContractError::InvalidField("loss raw representation"));
            }
        }
        return validate_discrepancy(None);
    }
    if raw.is_null() {
        if kind == "ADMISSION_DISCREPANCY"
            && lane == Some("UNKNOWN")
            && method == "adapter/acquisition"
        {
            return validate_discrepancy(Some("unknown ordered acquisition envelope kind"));
        }
        if kind == "LOCAL_TURN_FACT"
            && record
                .get("acquisition_ordinal")
                .is_some_and(Value::is_null)
            && lane.is_none()
            && matches!(
                method,
                "thread/start" | "turn/start" | "turn/started" | "worker_started"
            )
            && normalized == &serde_json::json!({"proves_provider_admission":false})
        {
            return Ok(());
        }
        if kind == "ADMISSION_DISCREPANCY" {
            match lane {
                None => {}
                Some("NOTIFICATION" | "SERVER_REQUEST" | "CLIENT_REQUEST" | "CLIENT_RESPONSE") => {
                    let detail = string(normalized, "detail")?;
                    let ordered = method == "adapter/acquisition"
                        && matches!(
                            detail,
                            "ordered acquisition ordinal gap, duplicate, or reorder"
                                | "ordered message envelope shape mismatch"
                                | "ordered provider message unexpectedly carries a request method"
                                | "client request lacks exact bounded request method"
                                | "client response lacks exact bounded request method"
                        );
                    let raw_custody = matches!(lane, Some("NOTIFICATION" | "SERVER_REQUEST"))
                        && method != "adapter/acquisition"
                        && (matches!(
                            detail,
                            "exact App Server wire bytes are required"
                                | "App Server evidence exceeds exact byte bound"
                                | "exact App Server wire bytes lack line terminator"
                                | "retained App Server wire bytes differ from parsed message"
                        ) || detail.starts_with("invalid retained App Server wire JSON:"));
                    if !ordered && !raw_custody {
                        return Err(ContractError::InvalidField(
                            "rawless ordered discrepancy detail",
                        ));
                    }
                }
                _ => {
                    return Err(ContractError::InvalidField(
                        "rawless discrepancy acquisition kind",
                    ));
                }
            }
            return validate_discrepancy(None);
        }
        return Err(ContractError::InvalidField("raw replay evidence absence"));
    }
    let wire = decode_switchyard_raw(raw, switchyard_record_raw_bound(record))?;
    let wire_object = wire
        .as_object()
        .ok_or(ContractError::InvalidField("raw replay object"))?;

    // The separately replayed echo state derives these exact failure details;
    // this is not a free-form discrepancy exemption.
    if let Some(detail) = echo_error {
        if saw_discrepancy || saw_turn_completed && current_execution.is_some() {
            return Err(ContractError::InvalidField(
                "bounded echo failure after closed state",
            ));
        }
        return validate_discrepancy(Some(detail));
    }

    if kind == "ADMISSION_DISCREPANCY" && matches!(lane, Some("CLIENT_REQUEST" | "CLIENT_RESPONSE"))
    {
        let request_method = method
            .strip_prefix(if lane == Some("CLIENT_REQUEST") {
                "client-request/"
            } else {
                "client-response/"
            })
            .ok_or(ContractError::InvalidField(
                "client discrepancy retained method",
            ))?;
        let request_id = wire
            .get("id")
            .and_then(Value::as_i64)
            .filter(|value| (0..=9_007_199_254_740_991).contains(value));
        let detail = if lane == Some("CLIENT_REQUEST") {
            if request_id.is_none_or(|value| value < 0) {
                "invalid client request id"
            } else {
                let expected_fields = if wire_object.contains_key("params") {
                    &["id", "method", "params"][..]
                } else {
                    &["id", "method"][..]
                };
                if wire_object.len() != expected_fields.len()
                    || expected_fields
                        .iter()
                        .any(|field| !wire_object.contains_key(*field))
                    || wire.get("method").and_then(Value::as_str) != Some(request_method)
                {
                    "client request method or closed shape substitution"
                } else if wire
                    .get("params")
                    .is_some_and(|value| !value.is_null() && !value.is_object())
                {
                    "client request params are not an object"
                } else if matches!(
                    request_method,
                    "fixture/provider-admission-positive"
                        | "fixture/provider-order-approval-before-created"
                        | "fixture/provider-order-loss-before-created"
                        | "fixture/provider-order-duplicate-key"
                        | "fixture/provider-order-nested-duplicate-key"
                ) && string(binding, "executable_kind")? != "DETERMINISTIC_FIXTURE"
                {
                    "fixture client request is not permitted for a campaign Codex build"
                } else if !matches!(
                    request_method,
                    "initialize"
                        | "thread/start"
                        | "turn/start"
                        | "thread/read"
                        | "thread/resume"
                        | "fixture/provider-admission-positive"
                        | "fixture/provider-order-approval-before-created"
                        | "fixture/provider-order-loss-before-created"
                        | "fixture/provider-order-duplicate-key"
                        | "fixture/provider-order-nested-duplicate-key"
                ) {
                    "unknown client request method"
                } else if matches!(
                    request_method,
                    "turn/start" | "thread/read" | "thread/resume"
                ) && wire
                    .get("params")
                    .and_then(|value| value.get("threadId"))
                    .and_then(Value::as_str)
                    != Some(string(binding, "thread_id")?)
                {
                    "client request thread identity substitution"
                } else if request_id.is_some_and(|value| client_requests.contains_key(&value)) {
                    "duplicate client request identity"
                } else {
                    return Err(ContractError::InvalidField(
                        "valid client request recorded as discrepancy",
                    ));
                }
            }
        } else if request_id.is_none_or(|value| value < 0) {
            "invalid client response id"
        } else if request_id.is_none_or(|value| {
            client_requests
                .get(&value)
                .is_none_or(|expected| expected.0 != request_method)
        }) {
            "client response request identity or method substitution"
        } else {
            let has_result = wire_object.contains_key("result");
            let has_error = wire_object.contains_key("error");
            let expected_fields = if has_result {
                ["id", "result"]
            } else {
                ["id", "error"]
            };
            if has_result == has_error
                || wire_object.len() != 2
                || expected_fields
                    .iter()
                    .any(|field| !wire_object.contains_key(*field))
            {
                "client response has non-closed result/error shape"
            } else if has_error {
                "client request returned an App Server error"
            } else if !wire["result"].is_object() {
                "client response result is not an object"
            } else if matches!(
                request_method,
                "thread/start" | "thread/read" | "thread/resume"
            ) && wire["result"]
                .get("thread")
                .and_then(|value| value.get("id"))
                .and_then(Value::as_str)
                != Some(string(binding, "thread_id")?)
            {
                if request_method == "thread/start" {
                    "thread/start response thread identity substitution"
                } else if request_method == "thread/read" {
                    "thread/read response thread identity substitution"
                } else {
                    "thread/resume response thread identity substitution"
                }
            } else if request_method == "turn/start"
                && wire["result"]
                    .get("turn")
                    .and_then(|value| value.get("id"))
                    .and_then(Value::as_str)
                    != Some(string(binding, "turn_id")?)
            {
                "turn/start response turn identity substitution"
            } else {
                return Err(ContractError::InvalidField(
                    "valid client response recorded as discrepancy",
                ));
            }
        };
        return validate_discrepancy(Some(detail));
    }

    if kind == "CLIENT_RESPONSE_RETAINED" {
        exact_object_keys(&wire, &["id", "result"], "client response raw closure")?;
        let request_id = integer(&wire, "id")?;
        let result = wire
            .get("result")
            .filter(|value| value.is_object())
            .ok_or(ContractError::InvalidField("client response result"))?;
        if integer(normalized, "request_id")? != request_id
            || normalized
                .get("proves_provider_admission")
                .and_then(Value::as_bool)
                != Some(false)
            || plain_sha256(&serde_jcs::to_vec(result).map_err(json_error)?)
                != string(normalized, "result_sha256")?
            || method != format!("client-response/{}", string(normalized, "request_method")?)
        {
            return Err(ContractError::InvalidField(
                "client response raw normalized binding",
            ));
        }
        let request_method = string(normalized, "request_method")?;
        if matches!(
            request_method,
            "thread/start" | "thread/read" | "thread/resume"
        ) {
            if result
                .get("thread")
                .and_then(Value::as_object)
                .and_then(|thread| thread.get("id"))
                .and_then(Value::as_str)
                != Some(string(binding, "thread_id")?)
            {
                return Err(ContractError::InvalidField(
                    "client response thread identity",
                ));
            }
        } else if request_method == "turn/start"
            && result
                .get("turn")
                .and_then(Value::as_object)
                .and_then(|turn| turn.get("id"))
                .and_then(Value::as_str)
                != Some(string(binding, "turn_id")?)
        {
            return Err(ContractError::InvalidField("client response turn identity"));
        }
        return Ok(());
    }

    let wire_method = wire_object.get("method").and_then(Value::as_str);
    if kind == "CLIENT_REQUEST_ISSUED" {
        let request_method =
            method
                .strip_prefix("client-request/")
                .ok_or(ContractError::InvalidField(
                    "client request retained method",
                ))?;
        let owner_method = matches!(
            request_method,
            "initialize" | "thread/start" | "turn/start" | "thread/read" | "thread/resume"
        );
        let fixture_method = matches!(
            request_method,
            "fixture/provider-admission-positive"
                | "fixture/provider-order-approval-before-created"
                | "fixture/provider-order-loss-before-created"
                | "fixture/provider-order-duplicate-key"
                | "fixture/provider-order-nested-duplicate-key"
        ) && string(binding, "executable_kind")? == "DETERMINISTIC_FIXTURE";
        if !owner_method && !fixture_method {
            return Err(ContractError::InvalidField("client request owner method"));
        }
        if wire_method != Some(request_method)
            || string(normalized, "request_method")? != request_method
        {
            return Err(ContractError::InvalidField("client request method binding"));
        }
        let expected_fields = if wire_object.contains_key("params") {
            &["id", "method", "params"][..]
        } else {
            &["id", "method"][..]
        };
        exact_object_keys(&wire, expected_fields, "client request raw closure")?;
        let params = wire.get("params").unwrap_or(&Value::Null);
        if !params.is_null() && !params.is_object() {
            return Err(ContractError::InvalidField("client request params"));
        }
        if matches!(
            request_method,
            "turn/start" | "thread/read" | "thread/resume"
        ) && params.get("threadId").and_then(Value::as_str)
            != Some(string(binding, "thread_id")?)
        {
            return Err(ContractError::InvalidField(
                "client request thread identity",
            ));
        }
        if integer(&wire, "id")? != integer(normalized, "request_id")?
            || normalized
                .get("proves_provider_admission")
                .and_then(Value::as_bool)
                != Some(false)
            || plain_sha256(&serde_jcs::to_vec(params).map_err(json_error)?)
                != string(normalized, "params_sha256")?
        {
            return Err(ContractError::InvalidField(
                "client request raw normalized binding",
            ));
        }
        return Ok(());
    }

    if kind != "ADMISSION_DISCREPANCY" && wire_method != Some(method) {
        return Err(ContractError::InvalidField("raw method record binding"));
    }
    let empty_params = Value::Object(serde_json::Map::new());
    let params = wire
        .get("params")
        .filter(|value| value.is_object())
        .unwrap_or(&empty_params);
    let common_request = |params: &Value, fields: &[&str]| -> Result<(), ContractError> {
        exact_object_keys(params, fields, "provider raw params closure")?;
        for (field, expected) in [
            ("threadId", string(binding, "thread_id")?),
            ("turnId", string(binding, "turn_id")?),
            ("provider", string(binding, "provider")?),
            ("model", string(binding, "model")?),
        ] {
            if string(params, field)? != expected {
                return Err(ContractError::InvalidField("provider raw identity binding"));
            }
        }
        Ok(())
    };
    match kind {
        "PROVIDER_REQUEST_STARTED" => {
            common_request(
                params,
                &[
                    "threadId",
                    "turnId",
                    "requestOccurrenceId",
                    "samplingOrdinal",
                    "requestOrder",
                    "provider",
                    "model",
                    "startedAtMs",
                ],
            )?;
            let expected = serde_json::json!({
                "request_occurrence_id": string(params, "requestOccurrenceId")?,
                "sampling_ordinal": integer(params, "samplingOrdinal")?,
                "request_order": integer(params, "requestOrder")?,
                "started_at_ms": integer(params, "startedAtMs")?,
                "proves_provider_admission": false,
            });
            if normalized != &expected {
                return Err(ContractError::InvalidField("provider request raw replay"));
            }
        }
        "PROVIDER_EXECUTION_STEP" => {
            common_request(
                params,
                &[
                    "threadId",
                    "turnId",
                    "requestOccurrenceId",
                    "samplingOrdinal",
                    "requestOrder",
                    "provider",
                    "model",
                    "responseId",
                    "observedAtMs",
                ],
            )?;
            let response_id = string(params, "responseId")?;
            let first_identity =
                current_execution
                    .cloned()
                    .unwrap_or(ProviderExecutionIdentityV1 {
                        provider_id: string(binding, "provider")?.to_owned(),
                        model_id: string(binding, "model")?.to_owned(),
                        app_server_session_identity: string(
                            binding,
                            "app_server_session_identity",
                        )?
                        .to_owned(),
                        thread_id: string(binding, "thread_id")?.to_owned(),
                        turn_id: string(binding, "turn_id")?.to_owned(),
                        first_response_id: response_id.to_owned(),
                    });
            let expected = serde_json::json!({
                "provider_execution_identity": {
                    "provider": first_identity.provider_id,
                    "model": first_identity.model_id,
                    "app_server_session_identity": first_identity.app_server_session_identity,
                    "thread_id": first_identity.thread_id,
                    "turn_id": first_identity.turn_id,
                    "first_response_id": first_identity.first_response_id,
                },
                "provider_execution_step_identity": {
                    "provider": string(params, "provider")?, "model": string(params, "model")?,
                    "thread_id": string(params, "threadId")?, "turn_id": string(params, "turnId")?,
                    "request_occurrence_id": string(params, "requestOccurrenceId")?,
                    "sampling_ordinal": integer(params, "samplingOrdinal")?,
                    "request_order": integer(params, "requestOrder")?, "response_id": response_id,
                },
                "first_admission_boundary": current_execution.is_none(),
                "observed_at_ms": integer(params, "observedAtMs")?,
            });
            if normalized != &expected {
                return Err(ContractError::InvalidField("provider step raw replay"));
            }
        }
        "PROVIDER_ADMISSION_REFUSED" => {
            common_request(
                params,
                &[
                    "threadId",
                    "turnId",
                    "requestOccurrenceId",
                    "samplingOrdinal",
                    "requestOrder",
                    "provider",
                    "model",
                    "responseCreated",
                    "willRetry",
                    "refusalKind",
                    "codexErrorInfo",
                    "retryAfterMs",
                    "diagnostic",
                    "observedAtMs",
                ],
            )?;
            let expected = serde_json::json!({
                "request_occurrence_id": string(params, "requestOccurrenceId")?,
                "sampling_ordinal": integer(params, "samplingOrdinal")?, "request_order": integer(params, "requestOrder")?,
                "response_created": params["responseCreated"], "will_retry": params["willRetry"],
                "refusal_kind": "MODEL_AT_CAPACITY", "codex_error_info": "serverOverloaded",
                "retry_after_ms": params["retryAfterMs"], "diagnostic": params["diagnostic"],
                "observed_at_ms": integer(params, "observedAtMs")?, "provider_execution_identity": null,
            });
            if params["refusalKind"] != "modelAtCapacity"
                || params["codexErrorInfo"] != "serverOverloaded"
                || params["responseCreated"] != false
                || params["willRetry"] != false
                || normalized != &expected
            {
                return Err(ContractError::InvalidField("provider refusal raw replay"));
            }
        }
        "PROVIDER_RESPONSE_COMPLETED" => {
            exact_object_keys(
                params,
                &["threadId", "turnId", "responseId", "usage"],
                "completion params closure",
            )?;
            if string(params, "threadId")? != string(binding, "thread_id")?
                || string(params, "turnId")? != string(binding, "turn_id")?
                || normalized
                    != &serde_json::json!({"response_id":string(params,"responseId")?,"proves_new_admission":false})
            {
                return Err(ContractError::InvalidField("completion raw replay"));
            }
        }
        "WAITING_APPROVAL" => {
            if !matches!(
                method,
                "item/commandExecution/requestApproval" | "item/fileChange/requestApproval"
            ) || string(params, "threadId")? != string(binding, "thread_id")?
                || string(params, "turnId")? != string(binding, "turn_id")?
            {
                return Err(ContractError::InvalidField("approval raw replay"));
            }
            let execution = current_execution
                .ok_or(ContractError::InvalidField("approval before execution"))?;
            let expected = serde_json::json!({"approval_response_sent":false,"protected_effect_absent":true,"provider_execution_identity":{
                "provider":execution.provider_id,"model":execution.model_id,"app_server_session_identity":execution.app_server_session_identity,
                "thread_id":execution.thread_id,"turn_id":execution.turn_id,"first_response_id":execution.first_response_id,
            }});
            if normalized != &expected {
                return Err(ContractError::InvalidField("approval normalized replay"));
            }
        }
        "LOCAL_TURN_FACT" => {
            let identities_match = if method == "thread/started" {
                params
                    .get("thread")
                    .and_then(|thread| thread.get("id"))
                    .and_then(Value::as_str)
                    == Some(string(binding, "thread_id")?)
            } else if matches!(method, "turn/started" | "turn/completed") {
                params.get("threadId").and_then(Value::as_str)
                    == Some(string(binding, "thread_id")?)
                    && params
                        .get("turn")
                        .and_then(|turn| turn.get("id"))
                        .and_then(Value::as_str)
                        == Some(string(binding, "turn_id")?)
            } else {
                false
            };
            if !identities_match {
                return Err(ContractError::InvalidField("local turn raw identity"));
            }
            if normalized != &serde_json::json!({"proves_provider_admission":false}) {
                return Err(ContractError::InvalidField("local fact normalized replay"));
            }
        }
        "ACQUISITION_WATERMARK" => {
            if method == "error"
                || matches!(method, "thread/started" | "turn/started" | "turn/completed")
                || method.starts_with("providerAdmission/")
                || method.starts_with("providerRequest/")
                || method.starts_with("rawResponse/")
                || normalized != &serde_json::json!({"proves_provider_admission":false})
            {
                return Err(ContractError::InvalidField("watermark normalized replay"));
            }
        }
        "ADMISSION_DISCREPANCY" => {
            let lane = record.get("acquisition_kind").and_then(Value::as_str);
            let object = params.as_object();
            let thread_matches = object
                .and_then(|value| value.get("threadId"))
                .and_then(Value::as_str)
                == Some(string(binding, "thread_id")?);
            let turn_matches = object
                .and_then(|value| value.get("turnId"))
                .and_then(Value::as_str)
                == Some(string(binding, "turn_id")?);
            let bounded_identity = |field: &str| {
                params
                    .get(field)
                    .and_then(Value::as_str)
                    .is_some_and(|value| (1..=512).contains(&value.chars().count()))
            };
            let bounded_integer = |field: &str, minimum: i64, maximum: i64| {
                params
                    .get(field)
                    .and_then(Value::as_i64)
                    .is_some_and(|value| (minimum..=maximum).contains(&value))
            };
            let safe_integer =
                |field: &str| bounded_integer(field, -9_007_199_254_740_991, 9_007_199_254_740_991);
            let detail = if wire_method.is_none() {
                if method != "unknown" {
                    return Err(ContractError::InvalidField(
                        "malformed method retained identity",
                    ));
                }
                "App Server method is not a string"
            } else if wire_method.is_some_and(|value| value.chars().count() > 512) {
                if method != "unknown" {
                    return Err(ContractError::InvalidField(
                        "overbound method retained identity",
                    ));
                }
                "App Server method exceeds identity bound"
            } else if wire_method != Some(method) {
                return Err(ContractError::InvalidField(
                    "discrepancy raw method record binding",
                ));
            } else if saw_discrepancy {
                if current_execution.is_some() {
                    "provider evidence followed a post-admission interruption"
                } else {
                    "provider evidence followed an indeterminate dispatch"
                }
            } else if saw_turn_completed && current_execution.is_some() {
                "App Server activity followed completed turn"
            } else if saw_approval
                && (lane == Some("SERVER_REQUEST")
                    || method.starts_with("providerAdmission/")
                    || method.starts_with("providerRequest/")
                    || method.starts_with("rawResponse/"))
            {
                "provider activity followed unanswered approval"
            } else if method == "error" {
                "coarse or unclassified App Server error cannot establish admission"
            } else if lane == Some("SERVER_REQUEST")
                || (lane.is_none()
                    && matches!(
                        method,
                        "item/commandExecution/requestApproval" | "item/fileChange/requestApproval"
                    ))
                || (lane.is_none()
                    && normalized.get("detail").and_then(Value::as_str)
                        == Some("unknown App Server server request"))
            {
                if !matches!(
                    method,
                    "item/commandExecution/requestApproval" | "item/fileChange/requestApproval"
                ) {
                    "unknown App Server server request"
                } else if !thread_matches || !turn_matches {
                    "approval identity substitution"
                } else if current_execution.is_none() {
                    "approval request preceded provider admission"
                } else if open_response.is_some() {
                    "approval request preceded exact response completion"
                } else {
                    return Err(ContractError::InvalidField(
                        "valid approval recorded as discrepancy",
                    ));
                }
            } else if matches!(method, "thread/started" | "turn/started" | "turn/completed") {
                if object.is_none() {
                    "local fact params are not an object"
                } else {
                    let local_thread_matches = if method == "thread/started" {
                        object
                            .and_then(|value| value.get("thread"))
                            .and_then(|thread| thread.get("id"))
                            .and_then(Value::as_str)
                            == Some(string(binding, "thread_id")?)
                    } else {
                        thread_matches
                    };
                    let local_turn_matches = method == "thread/started"
                        || object
                            .and_then(|value| value.get("turn"))
                            .and_then(|turn| turn.get("id"))
                            .and_then(Value::as_str)
                            == Some(string(binding, "turn_id")?);
                    if !local_thread_matches {
                        "local fact thread identity substitution"
                    } else if !local_turn_matches {
                        "local fact turn identity substitution"
                    } else if method == "turn/completed"
                        && current_execution.is_none()
                        && !(refusal_closed && pending_request.is_none() && open_response.is_none())
                    {
                        "turn completed without exact provider execution identity"
                    } else if method == "turn/completed"
                        && current_execution.is_some()
                        && (pending_request.is_some() || open_response.is_some() || saw_approval)
                    {
                        "turn completed before exact response/approval sequence closed"
                    } else {
                        return Err(ContractError::InvalidField(
                            "valid local fact recorded as discrepancy",
                        ));
                    }
                }
            } else if method == "providerRequest/started"
                && object.is_none_or(|value| {
                    let fields = [
                        "threadId",
                        "turnId",
                        "requestOccurrenceId",
                        "samplingOrdinal",
                        "requestOrder",
                        "provider",
                        "model",
                        "startedAtMs",
                    ];
                    value.len() != fields.len()
                        || fields.iter().any(|field| !value.contains_key(*field))
                })
            {
                "closed provider notification fields do not match"
            } else if method == "providerRequest/started" && !thread_matches {
                "provider notification threadId substitution"
            } else if method == "providerRequest/started" && !turn_matches {
                "provider notification turnId substitution"
            } else if method == "providerRequest/started"
                && string(params, "provider").ok() != Some(string(binding, "provider")?)
            {
                "provider notification provider substitution"
            } else if method == "providerRequest/started"
                && string(params, "model").ok() != Some(string(binding, "model")?)
            {
                "provider notification model substitution"
            } else if method == "providerRequest/started"
                && !bounded_identity("requestOccurrenceId")
            {
                "invalid requestOccurrenceId"
            } else if method == "providerRequest/started"
                && !bounded_integer("samplingOrdinal", 0, u32::MAX.into())
            {
                "invalid samplingOrdinal"
            } else if method == "providerRequest/started"
                && !bounded_integer("requestOrder", 0, u32::MAX.into())
            {
                "invalid requestOrder"
            } else if method == "providerRequest/started" && !safe_integer("startedAtMs") {
                "invalid startedAtMs"
            } else if method == "providerRequest/started"
                && last_boundary_ms.is_some_and(|boundary| {
                    integer(params, "startedAtMs").is_ok_and(|value| value < boundary)
                })
            {
                "provider request time precedes retained boundary"
            } else if method == "providerRequest/started" && pending_request.is_some() {
                "new provider request hides an unresolved request occurrence"
            } else if method == "providerRequest/started" && open_response.is_some() {
                "new provider request precedes exact response completion"
            } else if method == "providerRequest/started" && refusal_closed {
                "provider request follows closed dispatch disposition"
            } else if method == "providerRequest/started"
                && (integer(params, "samplingOrdinal").ok() != Some(completed_request_count as i64)
                    || integer(params, "requestOrder").ok() != Some(completed_request_count as i64))
            {
                "provider request ordering or hidden retry discrepancy"
            } else if method == "providerRequest/started"
                && string(params, "requestOccurrenceId")
                    .ok()
                    .is_some_and(|id| completed_request_occurrences.contains(id))
            {
                "duplicate provider request occurrence identity"
            } else if method == "providerRequest/started"
                && integer(params, "samplingOrdinal").is_ok_and(|value| value > 0)
                && current_execution.is_none()
            {
                "multiple pre-admission sampling requests are not allowed"
            } else if method == "providerRequest/started" {
                return Err(ContractError::InvalidField(
                    "valid provider request recorded as discrepancy",
                ));
            } else if method == "rawResponse/started"
                && object.is_none_or(|value| {
                    let fields = [
                        "threadId",
                        "turnId",
                        "requestOccurrenceId",
                        "samplingOrdinal",
                        "requestOrder",
                        "provider",
                        "model",
                        "responseId",
                        "observedAtMs",
                    ];
                    value.len() != fields.len()
                        || fields.iter().any(|field| !value.contains_key(*field))
                })
            {
                "closed provider notification fields do not match"
            } else if method == "rawResponse/started" && !thread_matches {
                "provider notification threadId substitution"
            } else if method == "rawResponse/started" && !turn_matches {
                "provider notification turnId substitution"
            } else if method == "rawResponse/started"
                && string(params, "provider").ok() != Some(string(binding, "provider")?)
            {
                "provider notification provider substitution"
            } else if method == "rawResponse/started"
                && string(params, "model").ok() != Some(string(binding, "model")?)
            {
                "provider notification model substitution"
            } else if method == "rawResponse/started" && !bounded_identity("requestOccurrenceId") {
                "invalid requestOccurrenceId"
            } else if method == "rawResponse/started"
                && !bounded_integer("samplingOrdinal", 0, u32::MAX.into())
            {
                "invalid samplingOrdinal"
            } else if method == "rawResponse/started"
                && !bounded_integer("requestOrder", 0, u32::MAX.into())
            {
                "invalid requestOrder"
            } else if method == "rawResponse/started"
                && pending_request.is_none_or(|pending| {
                    string(params, "requestOccurrenceId").ok() != Some(pending.0.as_str())
                        || integer(params, "samplingOrdinal").ok() != Some(pending.1)
                        || integer(params, "requestOrder").ok() != Some(pending.2)
                })
            {
                "provider boundary has no exact pending request"
            } else if method == "rawResponse/started" && !bounded_identity("responseId") {
                "invalid responseId"
            } else if method == "rawResponse/started" && !safe_integer("observedAtMs") {
                "invalid observedAtMs"
            } else if method == "rawResponse/started"
                && pending_request.is_some_and(|pending| {
                    integer(params, "observedAtMs").is_err()
                        || integer(params, "observedAtMs")
                            .is_ok_and(|observed| observed < pending.3)
                })
            {
                "response-created time precedes request start"
            } else if method == "rawResponse/started"
                && string(params, "responseId")
                    .ok()
                    .is_some_and(|id| completed_responses.contains(id) || open_response == Some(id))
            {
                "duplicate upstream response identity"
            } else if method == "rawResponse/started" {
                return Err(ContractError::InvalidField(
                    "valid response-created boundary recorded as discrepancy",
                ));
            } else if method == "providerAdmission/refused"
                && object.is_none_or(|value| {
                    let fields = [
                        "threadId",
                        "turnId",
                        "requestOccurrenceId",
                        "samplingOrdinal",
                        "requestOrder",
                        "provider",
                        "model",
                        "responseCreated",
                        "willRetry",
                        "refusalKind",
                        "codexErrorInfo",
                        "retryAfterMs",
                        "diagnostic",
                        "observedAtMs",
                    ];
                    value.len() != fields.len()
                        || fields.iter().any(|field| !value.contains_key(*field))
                })
            {
                "closed provider notification fields do not match"
            } else if method == "providerAdmission/refused" && !thread_matches {
                "provider notification threadId substitution"
            } else if method == "providerAdmission/refused" && !turn_matches {
                "provider notification turnId substitution"
            } else if method == "providerAdmission/refused"
                && string(params, "provider").ok() != Some(string(binding, "provider")?)
            {
                "provider notification provider substitution"
            } else if method == "providerAdmission/refused"
                && string(params, "model").ok() != Some(string(binding, "model")?)
            {
                "provider notification model substitution"
            } else if method == "providerAdmission/refused"
                && !bounded_identity("requestOccurrenceId")
            {
                "invalid requestOccurrenceId"
            } else if method == "providerAdmission/refused"
                && !bounded_integer("samplingOrdinal", 0, u32::MAX.into())
            {
                "invalid samplingOrdinal"
            } else if method == "providerAdmission/refused"
                && !bounded_integer("requestOrder", 0, u32::MAX.into())
            {
                "invalid requestOrder"
            } else if method == "providerAdmission/refused"
                && pending_request.is_none_or(|pending| {
                    string(params, "requestOccurrenceId").ok() != Some(pending.0.as_str())
                        || integer(params, "samplingOrdinal").ok() != Some(pending.1)
                        || integer(params, "requestOrder").ok() != Some(pending.2)
                })
            {
                "provider boundary has no exact pending request"
            } else if method == "providerAdmission/refused" && current_execution.is_some() {
                "provider refusal follows admitted execution"
            } else if method == "providerAdmission/refused"
                && (params.get("responseCreated") != Some(&Value::Bool(false))
                    || params.get("willRetry") != Some(&Value::Bool(false)))
            {
                "provider refusal does not prove terminal pre-created state"
            } else if method == "providerAdmission/refused"
                && params.get("refusalKind") != Some(&Value::String("modelAtCapacity".to_owned()))
            {
                "unknown provider refusal kind"
            } else if method == "providerAdmission/refused"
                && params.get("codexErrorInfo")
                    != Some(&Value::String("serverOverloaded".to_owned()))
            {
                "provider refusal typed error mismatch"
            } else if method == "providerAdmission/refused"
                && !matches!(params.get("retryAfterMs"), Some(Value::Null))
                && !bounded_integer("retryAfterMs", 0, 9_007_199_254_740_991)
            {
                "invalid retryAfterMs"
            } else if method == "providerAdmission/refused"
                && params
                    .get("diagnostic")
                    .and_then(Value::as_str)
                    .is_none_or(|value| value.chars().count() > 4096)
            {
                "provider refusal diagnostic exceeds bound"
            } else if method == "providerAdmission/refused" && !safe_integer("observedAtMs") {
                "invalid observedAtMs"
            } else if method == "providerAdmission/refused"
                && pending_request.is_some_and(|pending| {
                    integer(params, "observedAtMs").is_err()
                        || integer(params, "observedAtMs")
                            .is_ok_and(|observed| observed < pending.3)
                })
            {
                "provider refusal time precedes request start"
            } else if method == "providerAdmission/refused" {
                return Err(ContractError::InvalidField(
                    "valid provider refusal recorded as discrepancy",
                ));
            } else if method == "rawResponse/completed"
                && object.is_none_or(|value| {
                    let fields = ["threadId", "turnId", "responseId", "usage"];
                    value.len() != fields.len()
                        || fields.iter().any(|field| !value.contains_key(*field))
                })
            {
                "closed response-completed fields do not match"
            } else if method == "rawResponse/completed" && current_execution.is_none() {
                "response completion lacks an exact response-created boundary"
            } else if method == "rawResponse/completed" && (!thread_matches || !turn_matches) {
                "response completion identity substitution"
            } else if method == "rawResponse/completed"
                && string(params, "responseId").ok() != open_response
            {
                "response completion has no exact admitted response identity"
            } else if method == "rawResponse/completed" {
                return Err(ContractError::InvalidField(
                    "valid response completion recorded as discrepancy",
                ));
            } else if method.starts_with("providerAdmission/")
                || method.starts_with("providerRequest/")
                || method.starts_with("rawResponse/")
            {
                "unknown provider-boundary notification"
            } else {
                return Err(ContractError::InvalidField(
                    "non-derivable discrepancy raw replay",
                ));
            };
            validate_discrepancy(Some(detail))?;
        }
        _ => return Err(ContractError::InvalidField("raw replay evidence kind")),
    }
    Ok(())
}

fn validate_safe_json(value: &Value) -> Result<(), ContractError> {
    const SAFE: i64 = 9_007_199_254_740_991;
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Number(number) => {
            let valid = number
                .as_i64()
                .is_some_and(|value| (-SAFE..=SAFE).contains(&value))
                || number.as_u64().is_some_and(|value| value <= SAFE as u64)
                || number
                    .as_f64()
                    .is_some_and(|value| value.is_finite() && value.abs() <= SAFE as f64);
            if valid {
                Ok(())
            } else {
                Err(ContractError::InvalidField("RFC8785 safe number"))
            }
        }
        Value::Array(values) => {
            for value in values {
                validate_safe_json(value)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            for value in values.values() {
                validate_safe_json(value)?;
            }
            Ok(())
        }
    }
}

/// Validate one complete provider-execution availability graph before journal admission.
///
/// This function is pure. It grants no authority and performs no store, adapter,
/// provider, lock, timer, or process operation.
fn exact_deferral_seconds(
    policy: &ExecutionAvailabilityPolicyV1,
    disposition: &ProviderAdmissionDispositionV1,
    deferred: &DeferredProviderDispatchV1,
) -> Result<u64, ContractError> {
    let (expected_wake, expected_seconds) = match deferred.wake_basis {
        DeferredWakeBasisV1::ProviderRetryAfter => {
            let wake = disposition
                .provider_retry_after
                .ok_or(ContractError::InvalidField("provider retry-after absence"))?;
            let milliseconds = (wake - disposition.received_at).num_milliseconds();
            if milliseconds <= 0 || milliseconds % 1_000 != 0 {
                return Err(ContractError::InvalidField(
                    "exact provider retry-after duration",
                ));
            }
            (wake, milliseconds as u64 / 1_000)
        }
        DeferredWakeBasisV1::PolicyBackoff => {
            if disposition.provider_retry_after.is_some() || deferred.provider_retry_after.is_some()
            {
                return Err(ContractError::InvalidField(
                    "policy backoff retry-after absence",
                ));
            }
            let seconds = *policy
                .backoff_seconds
                .get(usize::from(deferred.backoff_ordinal))
                .ok_or(ContractError::InvalidField("backoff ordinal"))?;
            (
                disposition.received_at + Duration::seconds(seconds as i64),
                seconds,
            )
        }
    };
    if deferred.refusal_received_at != disposition.received_at
        || deferred.provider_retry_after != disposition.provider_retry_after
        || deferred.wake_at != expected_wake
        || deferred.backoff_seconds != expected_seconds
    {
        return Err(ContractError::InvalidField(
            "exact deferred wake derivation",
        ));
    }
    Ok(expected_seconds)
}

fn validate_dispatch_disposition_owner_family(
    dispatch: &ProviderDispatchOccurrenceV1,
    disposition: &ProviderAdmissionDispositionV1,
) -> Result<(), ContractError> {
    let matches = match disposition.schema.as_str() {
        PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V1 => {
            dispatch.adapter_id != HOLDING_QUALIFICATION_PRODUCER_ID
                && dispatch.adapter_protocol == "switchyard.codex-app-server/v2"
        }
        PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V2 => {
            dispatch.adapter_id == HOLDING_QUALIFICATION_PRODUCER_ID
                && dispatch.adapter_version == HOLDING_QUALIFICATION_PRODUCER_VERSION
                && dispatch.adapter_protocol == DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V1
        }
        PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V3 => {
            dispatch.adapter_id == HOLDING_QUALIFICATION_PRODUCER_ID
                && dispatch.adapter_version == SECOND_WATCH_QUALIFICATION_PRODUCER_VERSION
                && dispatch.adapter_protocol == DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V2
        }
        _ => false,
    };
    if !matches {
        return Err(ContractError::InvalidField(
            "dispatch disposition owner-family graph",
        ));
    }
    Ok(())
}

pub fn validate_execution_availability_graph(
    requirement: &ForemanExecutionAvailabilityRequirementV1,
    policy: &ExecutionAvailabilityPolicyV1,
    dispatch: &ProviderDispatchOccurrenceV1,
    observation: &ExecutionAvailabilityObservationV1,
    disposition: &ProviderAdmissionDispositionV1,
    prior_history: &[ProviderDeferralHistoryEntryV1],
    deferred: Option<&DeferredProviderDispatchV1>,
) -> Result<(), ContractError> {
    requirement.validate()?;
    policy.validate()?;
    dispatch.validate()?;
    observation.validate()?;
    disposition.validate()?;
    if disposition.mapper_snapshot_schema == "switchyard.codex-provider-admission-snapshot/v1" {
        let snapshot: Value =
            serde_json::from_slice(&disposition.mapper_snapshot.validate()?).map_err(json_error)?;
        // Historical owner/schema tuples retain their original frame limits.
        validate_vendored_switchyard_schema(
            &snapshot,
            if requirement.owner_pins.is_bounded_turn_echo() {
                SwitchyardCaptureSchema::BoundedTurnEcho
            } else if requirement.owner_pins
                == ProviderAdmissionOwnerPinsV1::bounded_turn_candidate()
            {
                SwitchyardCaptureSchema::BoundedTurn
            } else {
                SwitchyardCaptureSchema::Legacy
            },
        )?;
        if requirement.owner_pins.is_bounded_turn_echo() {
            bounded_turn_echo::validate_snapshot(&snapshot, true)?;
        }
        if snapshot["binding"]["codex_source_head"].as_str()
            != Some(requirement.owner_pins.codex_owner_head.as_str())
        {
            return Err(ContractError::InvalidField(
                "requirement mapper owner graph",
            ));
        }
    }
    if requirement.admitted_at > dispatch.opened_at
        || dispatch.opened_at > disposition.received_at
        || requirement.policy_id != policy.policy_id
        || requirement.policy_digest != policy.policy_digest
        || dispatch.requirement_digest != requirement.requirement_digest
        || dispatch.policy_digest != policy.policy_digest
        || dispatch.packet_digest != requirement.packet_digest
        || dispatch.run_id != requirement.run_id
        || dispatch.adapter_id != requirement.adapter_id
        || dispatch.adapter_version != requirement.adapter_version
        || dispatch.adapter_protocol != requirement.adapter_protocol
        || dispatch.dispatch_ordinal > policy.maximum_dispatch_occurrences_per_attempt
    {
        return Err(ContractError::InvalidField(
            "requirement policy dispatch graph",
        ));
    }
    let selections = requirement
        .work_item_model_selections
        .get(&dispatch.work_item_id)
        .ok_or(ContractError::InvalidField("dispatch work-item selection"))?;
    if selections.get(usize::from(dispatch.selected_model_ordinal)) != Some(&dispatch.selection) {
        return Err(ContractError::InvalidField("selected model ordinal"));
    }
    if disposition.dispatch_digest != dispatch.dispatch_digest
        || disposition.requirement_digest != requirement.requirement_digest
        || disposition.policy_digest != policy.policy_digest
        || disposition.packet_digest != requirement.packet_digest
        || disposition.run_id != requirement.run_id
        || disposition.work_item_id != dispatch.work_item_id
        || disposition.work_attempt_id != dispatch.work_attempt_id
        || disposition.dispatch_occurrence_id != dispatch.dispatch_occurrence_id
        || disposition.provider_id != dispatch.selection.provider_id
        || disposition.model_id != dispatch.selection.model_id
        || disposition.adapter_process_occurrence_id != dispatch.adapter_process_occurrence_id
        || disposition.app_server_session_identity != dispatch.app_server_session_identity
    {
        return Err(ContractError::InvalidField("dispatch disposition graph"));
    }
    validate_dispatch_disposition_owner_family(dispatch, disposition)?;
    let source = disposition_source_observation(disposition)?;
    if observation.provider_id != dispatch.selection.provider_id
        || observation.model_id != dispatch.selection.model_id
        || observation.model_class != dispatch.selection.model_class
        || observation.received_at != disposition.received_at
        || observation.observed_at != source.observed_at
        || observation.provider_retry_after != disposition.provider_retry_after
        || observation.source_identity != source.identity
        || observation.source_version != source.version
        || !observation.is_current_at(disposition.received_at)
    {
        return Err(ContractError::InvalidField(
            "availability observation graph",
        ));
    }
    let expected_observation_state = match disposition.disposition {
        ProviderAdmissionDispositionKindV1::NotAdmittedModelAtCapacity => {
            ExecutionAvailabilityStateV1::ModelAtCapacity
        }
        ProviderAdmissionDispositionKindV1::NotAdmittedProviderUnavailable => {
            ExecutionAvailabilityStateV1::ProviderUnavailable
        }
        ProviderAdmissionDispositionKindV1::NotAdmittedRateLimited => {
            ExecutionAvailabilityStateV1::RateLimited
        }
        ProviderAdmissionDispositionKindV1::AuthenticationRefused => {
            ExecutionAvailabilityStateV1::AuthenticationRefused
        }
        ProviderAdmissionDispositionKindV1::AdmissionIndeterminate => {
            if !matches!(
                observation.state,
                ExecutionAvailabilityStateV1::Unknown
                    | ExecutionAvailabilityStateV1::TransportError
                    | ExecutionAvailabilityStateV1::ProtocolError
            ) {
                return Err(ContractError::InvalidField(
                    "indeterminate observation state",
                ));
            }
            observation.state
        }
        ProviderAdmissionDispositionKindV1::ExecutionAdmitted => {
            ExecutionAvailabilityStateV1::Available
        }
        ProviderAdmissionDispositionKindV1::QuotaExhaustedFuelOwned => {
            return Err(ContractError::InvalidField("quota is FUEL-owned"));
        }
    };
    if observation.state != expected_observation_state {
        return Err(ContractError::InvalidField("disposition observation state"));
    }
    if observation.exact_evidence.as_ref() != source.evidence.as_ref() {
        return Err(ContractError::InvalidField(
            "exact observation source binding",
        ));
    }

    if usize::from(dispatch.dispatch_ordinal) != prior_history.len() + 1
        || prior_history.len() >= usize::from(policy.maximum_dispatch_occurrences_per_attempt)
    {
        return Err(ContractError::InvalidField(
            "dispatch ordinal prior deferral continuity",
        ));
    }
    let mut cumulative_deferral_seconds = 0_u64;
    let mut prior_dispatch_ids = BTreeSet::new();
    let mut prior_refusal_time: Option<DateTime<Utc>> = None;
    let mut prior_wake_time: Option<DateTime<Utc>> = None;
    let mut prior_model_ordinal: Option<u16> = None;
    for (index, entry) in prior_history.iter().enumerate() {
        entry.validate()?;
        let prior_dispatch = &entry.dispatch;
        let prior_disposition = &entry.disposition;
        let prior = &entry.deferred;
        validate_dispatch_disposition_owner_family(prior_dispatch, prior_disposition)?;
        let prior_selection = selections
            .get(usize::from(prior.selected_model_ordinal))
            .ok_or(ContractError::InvalidField("prior deferred model ordinal"))?;
        let expected_remaining: Vec<u16> = if policy.allow_ordered_model_fallback {
            ((prior.selected_model_ordinal + 1)..(selections.len() as u16)).collect()
        } else {
            Vec::new()
        };
        if prior_dispatch.requirement_digest != requirement.requirement_digest
            || prior_dispatch.policy_digest != policy.policy_digest
            || prior_dispatch.packet_digest != requirement.packet_digest
            || prior_dispatch.run_id != requirement.run_id
            || prior_dispatch.work_item_id != dispatch.work_item_id
            || prior_dispatch.work_attempt_id != dispatch.work_attempt_id
            || prior_dispatch.adapter_id != requirement.adapter_id
            || prior_dispatch.adapter_version != requirement.adapter_version
            || prior_dispatch.adapter_protocol != requirement.adapter_protocol
            || prior_dispatch.adapter_id != dispatch.adapter_id
            || prior_dispatch.adapter_version != dispatch.adapter_version
            || prior_dispatch.adapter_protocol != dispatch.adapter_protocol
            || usize::from(prior_dispatch.dispatch_ordinal) != index + 1
            || prior_dispatch.selected_model_ordinal != prior.selected_model_ordinal
            || prior_dispatch.selection != *prior_selection
            || prior_dispatch.dispatch_occurrence_id != prior.last_dispatch_occurrence_id
            || prior_disposition.dispatch_digest != prior_dispatch.dispatch_digest
            || prior_disposition.requirement_digest != requirement.requirement_digest
            || prior_disposition.policy_digest != policy.policy_digest
            || prior_disposition.packet_digest != requirement.packet_digest
            || prior_disposition.run_id != requirement.run_id
            || prior_disposition.work_item_id != dispatch.work_item_id
            || prior_disposition.work_attempt_id != dispatch.work_attempt_id
            || prior_disposition.dispatch_occurrence_id != prior_dispatch.dispatch_occurrence_id
            || prior_disposition.provider_id != prior_dispatch.selection.provider_id
            || prior_disposition.model_id != prior_dispatch.selection.model_id
            || prior_disposition.adapter_process_occurrence_id
                != prior_dispatch.adapter_process_occurrence_id
            || prior_disposition.app_server_session_identity
                != prior_dispatch.app_server_session_identity
            || prior.disposition_digest != prior_disposition.disposition_digest
            || !prior_disposition.permits_automatic_park()
            || requirement.admitted_at > prior_dispatch.opened_at
            || prior_dispatch.opened_at > prior_disposition.received_at
            || prior_wake_time.is_some_and(|wake| prior_dispatch.opened_at < wake)
            || prior_wake_time.is_some_and(|wake| prior_disposition.received_at < wake)
            || prior.requirement_digest != requirement.requirement_digest
            || prior.policy_digest != policy.policy_digest
            || prior.packet_digest != requirement.packet_digest
            || prior.run_id != requirement.run_id
            || prior.work_item_id != dispatch.work_item_id
            || prior.work_attempt_id != dispatch.work_attempt_id
            || prior.provider_id != prior_selection.provider_id
            || prior.model_id != prior_selection.model_id
            || prior.backoff_ordinal != index as u16
            || prior.remaining_model_ordinals != expected_remaining
            || prior.parked_resource_lock_policy != policy.parked_resource_lock_policy
            || !prior_dispatch_ids.insert(prior.last_dispatch_occurrence_id.clone())
            || prior_refusal_time.is_some_and(|time| prior.refusal_received_at < time)
            || (!policy.allow_ordered_model_fallback && prior.selected_model_ordinal != 0)
            || prior_model_ordinal.is_some_and(|ordinal| {
                prior.selected_model_ordinal < ordinal
                    || prior.selected_model_ordinal > ordinal.saturating_add(1)
            })
        {
            return Err(ContractError::InvalidField("prior deferral graph"));
        }
        let exact_seconds = exact_deferral_seconds(policy, prior_disposition, prior)?;
        prior_refusal_time = Some(prior.refusal_received_at);
        prior_wake_time = Some(prior.wake_at);
        prior_model_ordinal = Some(prior.selected_model_ordinal);
        cumulative_deferral_seconds = cumulative_deferral_seconds
            .checked_add(exact_seconds)
            .ok_or(ContractError::InvalidField("cumulative deferral overflow"))?;
    }
    if prior_wake_time.is_some_and(|wake| dispatch.opened_at < wake)
        || prior_wake_time.is_some_and(|wake| disposition.received_at < wake)
        || (!policy.allow_ordered_model_fallback && dispatch.selected_model_ordinal != 0)
        || cumulative_deferral_seconds > policy.maximum_total_deferral_seconds
    {
        return Err(ContractError::InvalidField(
            "prior wake dispatch progression",
        ));
    }
    if prior_model_ordinal.is_some_and(|ordinal| {
        dispatch.selected_model_ordinal < ordinal
            || dispatch.selected_model_ordinal > ordinal.saturating_add(1)
    }) {
        return Err(ContractError::InvalidField(
            "ordered model deferral continuity",
        ));
    }

    if disposition.permits_automatic_park() {
        let parked = deferred.ok_or(ContractError::InvalidField("deferred dispatch absence"))?;
        parked.validate()?;
        if parked.requirement_digest != requirement.requirement_digest
            || parked.policy_digest != policy.policy_digest
            || parked.disposition_digest != disposition.disposition_digest
            || parked.packet_digest != requirement.packet_digest
            || parked.run_id != requirement.run_id
            || parked.work_item_id != dispatch.work_item_id
            || parked.work_attempt_id != dispatch.work_attempt_id
            || parked.last_dispatch_occurrence_id != dispatch.dispatch_occurrence_id
            || parked.provider_id != dispatch.selection.provider_id
            || parked.model_id != dispatch.selection.model_id
            || parked.selected_model_ordinal != dispatch.selected_model_ordinal
            || parked.refusal_received_at != disposition.received_at
            || parked.backoff_ordinal + 1 != dispatch.dispatch_ordinal
            || parked.parked_resource_lock_policy != policy.parked_resource_lock_policy
            || !parked.provider_capacity_released
            || parked.semantic_retry
        {
            return Err(ContractError::InvalidField("deferred dispatch graph"));
        }
        let expected_remaining: Vec<u16> = if policy.allow_ordered_model_fallback {
            ((dispatch.selected_model_ordinal + 1)..(selections.len() as u16)).collect()
        } else {
            Vec::new()
        };
        if parked.remaining_model_ordinals != expected_remaining {
            return Err(ContractError::InvalidField("ordered fallback suffix"));
        }
        let exact_seconds = exact_deferral_seconds(policy, disposition, parked)?;
        cumulative_deferral_seconds = cumulative_deferral_seconds
            .checked_add(exact_seconds)
            .ok_or(ContractError::InvalidField("cumulative deferral overflow"))?;
        if cumulative_deferral_seconds > policy.maximum_total_deferral_seconds {
            return Err(ContractError::InvalidField("maximum cumulative deferral"));
        }
    } else if deferred.is_some() {
        return Err(ContractError::InvalidField("unlawful automatic park"));
    }
    if matches!(
        disposition.mechanism_state,
        ProviderMechanismStateV1::PostAdmissionInterrupted
    ) && (disposition.provider_execution.is_none() || deferred.is_some())
    {
        return Err(ContractError::InvalidField(
            "post-admission resume-only law",
        ));
    }
    Ok(())
}

struct DispositionSourceObservation {
    evidence: Option<ExactAvailabilityEvidenceV1>,
    observed_at: DateTime<Utc>,
    identity: &'static str,
    version: &'static str,
}

fn disposition_source_observation(
    disposition: &ProviderAdmissionDispositionV1,
) -> Result<DispositionSourceObservation, ContractError> {
    let raw = disposition.mapper_snapshot.validate()?;
    if disposition.schema == PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V3 {
        let evidence = DeterministicProviderAdmissionEvidenceV2::from_slice(&raw)?;
        evidence.validate()?;
        return Ok(DispositionSourceObservation {
            evidence: Some(evidence.raw_evidence),
            observed_at: evidence.observed_at,
            identity: HOLDING_QUALIFICATION_PRODUCER_ID,
            version: SECOND_WATCH_QUALIFICATION_PRODUCER_VERSION,
        });
    }
    if disposition.schema == PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V2 {
        let evidence = DeterministicProviderAdmissionEvidenceV1::from_slice(&raw)?;
        evidence.validate()?;
        return Ok(DispositionSourceObservation {
            evidence: Some(evidence.raw_evidence),
            observed_at: evidence.observed_at,
            identity: HOLDING_QUALIFICATION_PRODUCER_ID,
            version: HOLDING_QUALIFICATION_PRODUCER_VERSION,
        });
    }
    let snapshot: Value = serde_json::from_slice(&raw).map_err(json_error)?;
    let kind = match disposition.disposition {
        ProviderAdmissionDispositionKindV1::NotAdmittedModelAtCapacity => {
            "PROVIDER_ADMISSION_REFUSED"
        }
        ProviderAdmissionDispositionKindV1::ExecutionAdmitted => "PROVIDER_EXECUTION_STEP",
        ProviderAdmissionDispositionKindV1::AdmissionIndeterminate => "ADMISSION_DISCREPANCY",
        _ => {
            return Ok(DispositionSourceObservation {
                evidence: None,
                observed_at: disposition.received_at,
                identity: "switchyard:provider-admission",
                version: "v1",
            })
        }
    };
    let record = snapshot["records"]
        .as_array()
        .and_then(|records| {
            records
                .iter()
                .find(|record| record.get("kind").and_then(Value::as_str) == Some(kind))
        })
        .ok_or(ContractError::InvalidField("observation source evidence"))?;
    let observed_at = match record["normalized"].get("observed_at_ms") {
        None => disposition.received_at,
        Some(value) => value
            .as_i64()
            .and_then(DateTime::<Utc>::from_timestamp_millis)
            .ok_or(ContractError::InvalidField("source observed_at_ms"))?,
    };
    let evidence = match record.get("raw") {
        Some(Value::Null)
            if matches!(
                disposition.disposition,
                ProviderAdmissionDispositionKindV1::AdmissionIndeterminate
            ) =>
        {
            None
        }
        Some(value) => Some(serde_json::from_value(value.clone()).map_err(json_error)?),
        None => return Err(ContractError::InvalidField("observation source raw")),
    };
    Ok(DispositionSourceObservation {
        evidence,
        observed_at,
        identity: "switchyard:provider-admission",
        version: "v1",
    })
}

//! Strict, read-only consumer types for `nq.diagnostic_execution.v2`.
//!
//! V2 adds exact governed refusals and an explicit clock-qualification tag.
//! Nightshift retains those objects without projecting them back into the v1
//! code/reason or numeric-uncertainty surfaces. This module does not acquire
//! evidence, authorize action, or execute anything.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::diagnostic_posture::{
    AcquisitionIntervalV1, AdmittedInputV1, ClaimV1, CoherenceV1, ConditionV1, CoverageV1,
    DerivationV1, DiagnosticExecutionSchema, DiagnosticExecutionV1, DiagnosticKey,
    EvidenceAvailabilityV1, ExcludedInputV1, ExpectedInputV1, FailedInputKindV1, FailedInputV1,
    InputAccountingV1, LimitationV1, OutcomeV1, ProducerV1, ProjectionV1, RawCaptureModeV1,
    ReceivedInputV1, RefusalV1, RefusedInputV1, SelectedInputV1, SemanticIdentityV1,
    StateBindingV1, SubjectV1,
};

pub const NQ_DIAGNOSTIC_EXECUTION_V2_SCHEMA: &str = "nq.diagnostic_execution.v2";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DiagnosticExecutionSchemaV2 {
    #[serde(rename = "nq.diagnostic_execution.v2")]
    V2,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClockQualificationV2 {
    Bounded {
        maximum_error_ms: u64,
        basis: SemanticIdentityV1,
    },
    Unqualified {
        code: String,
        detail: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcquisitionIntervalV2 {
    pub started_at: String,
    pub ended_at: String,
    pub clock: SemanticIdentityV1,
    pub qualification: ClockQualificationV2,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceivedInputV2 {
    pub input_id: String,
    pub expectation_id: String,
    pub provider_intake_id: String,
    pub raw_artifact_id: String,
    pub capture_mode: RawCaptureModeV1,
    pub capture_policy: SemanticIdentityV1,
    pub availability_at_derivation: EvidenceAvailabilityV1,
    pub acquisition: AcquisitionIntervalV2,
    pub received_at: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryDispositionV1 {
    Retriable,
    NonRetriable,
    Unspecified,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquisitionFailureClassV1 {
    SpawnFailed,
    RequestWriteFailed,
    Timeout,
    OutputTooLarge,
    StderrTooLarge,
    Eof,
    MalformedFraming,
    MalformedJson,
    ExitNonzero,
    HelperExited,
    Disconnect,
    CarrierStartupFailed,
    NotRunning,
    IoFailed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExchangeTimeoutPhaseV1 {
    WriteRequest,
    ReadResponse,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum AcquisitionOutcomeV1 {
    Response,
    SpawnFailed { message: String },
    RequestWriteFailed { message: String },
    Timeout,
    ExchangeTimeout { phase: ExchangeTimeoutPhaseV1 },
    OutputTooLarge,
    StderrTooLarge,
    Eof,
    MalformedFraming { message: String },
    MalformedJson { message: String },
    ExitNonzero { code: Option<i32> },
    HelperExited { code: Option<i32> },
    Disconnect { message: String },
    CarrierStartupFailed { message: String },
    NotRunning,
    IoFailed { message: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcquisitionFailureV1 {
    pub class: AcquisitionFailureClassV1,
    pub retry: RetryDispositionV1,
    pub outcome: AcquisitionOutcomeV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcquisitionRefusalV1 {
    pub responsible_instance_id: String,
    pub failure: AcquisitionFailureV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolRejectionBoundaryV1 {
    Response,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolRejectionCodeV1 {
    InvalidResponse,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JsonErrorCategoryV1 {
    Io,
    Syntax,
    Data,
    Eof,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredJsonErrorV1 {
    pub category: JsonErrorCategoryV1,
    pub line: usize,
    pub column: usize,
    pub diagnostic: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProtocolCanonicalizationFailureV1 {
    Serialization { error: StructuredJsonErrorV1 },
    UnsafeInteger { value: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProtocolValidationFailureV1 {
    InvalidSchema {
        document: String,
        expected: String,
        actual: String,
    },
    InvalidProtocolVersion {
        expected: String,
        actual: String,
    },
    InvalidField {
        field: String,
        reason: String,
    },
    BoundExceeded {
        field: String,
        limit: usize,
        actual: usize,
    },
    Duplicate {
        field: String,
        value: String,
    },
    EchoMismatch {
        field: String,
    },
    CapabilityEscape {
        capability: String,
    },
    Canonicalization {
        field: String,
        source: ProtocolCanonicalizationFailureV1,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProtocolRejectionFailureV1 {
    FrameTooLarge {
        limit: usize,
        actual: usize,
    },
    InvalidFraming,
    InvalidJson {
        error: StructuredJsonErrorV1,
    },
    Validation {
        error: ProtocolValidationFailureV1,
    },
    Canonicalization {
        error: ProtocolCanonicalizationFailureV1,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolRejectionV1 {
    pub responsible_instance_id: String,
    pub boundary: ProtocolRejectionBoundaryV1,
    pub code: ProtocolRejectionCodeV1,
    pub failure: ProtocolRejectionFailureV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HelperRefusalBoundaryV1 {
    Protocol,
    Profile,
    Scope,
    Vantage,
    Capability,
    Deadline,
    Checkpoint,
    Collection,
    Resource,
    Internal,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HelperRefusalCodeV1 {
    UnsupportedProtocol,
    UnknownProfile,
    ProfileDigestMismatch,
    UnsupportedScope,
    UnsupportedVantage,
    CapabilityDenied,
    DeadlineExpired,
    BoundsUnsupported,
    CheckpointInvalid,
    CollectionFailed,
    ResourceExhausted,
    InternalError,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HelperRefusalV1 {
    pub responsible_instance_id: String,
    pub boundary: HelperRefusalBoundaryV1,
    pub code: HelperRefusalCodeV1,
    pub message: String,
    pub retriable: bool,
    pub details: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileKeyV1 {
    pub id: String,
    pub version: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileRefusalBoundaryV1 {
    Profile,
    Report,
    Coverage,
    Observation,
    Detector,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileRefusalCodeV1 {
    UnknownProfile,
    UnknownObservationKind,
    UnknownCoverage,
    DuplicateCoverage,
    MissingCoverage,
    CoverageStatusMismatch,
    ReportStatusOverclaim,
    ObservationLimitExceeded,
    PayloadLimitExceeded,
    InvalidOrdinal,
    SubjectEscape,
    ScopeEscape,
    VantageEscape,
    CapabilityEscape,
    UnknownAccessPath,
    UnknownBasis,
    UnknownRegime,
    FutureObservation,
    InvalidPayload,
    InconsistentReport,
    ForbiddenHelperAssertion,
    CannotEvaluate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRefusalV1 {
    pub instance_id: String,
    pub profile: ProfileKeyV1,
    pub boundary: ProfileRefusalBoundaryV1,
    pub code: ProfileRefusalCodeV1,
    pub message: String,
    pub details: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedProfileRefusalV1 {
    pub profile_semantic_id: String,
    pub refusal: ProfileRefusalV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum GovernedRefusalOriginV1 {
    Acquisition(AcquisitionRefusalV1),
    Protocol(ProtocolRejectionV1),
    Helper(HelperRefusalV1),
    Profile(GovernedProfileRefusalV1),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum GovernedRefusalSchemaV1 {
    #[serde(rename = "nq.governed_refusal.v1")]
    V1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedRefusalV1 {
    pub schema: GovernedRefusalSchemaV1,
    pub refusal_id: String,
    pub origin: GovernedRefusalOriginV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "scope", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProfileRefusalBindingV2 {
    ArtifactProfile,
    ForeignInputRole { role: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RefusedInputV2 {
    pub input_id: String,
    pub refusal: GovernedRefusalV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_binding: Option<ProfileRefusalBindingV2>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailedAcquisitionCustodyV2 {
    NoBytesRetained,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsupportedCodeV2 {
    QuestionUnsupported,
    ProviderCapabilityUnavailable,
    PlatformCapabilityUnavailable,
    ContractVersionUnsupported,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "scope", rename_all = "snake_case", deny_unknown_fields)]
pub enum UnsupportedOriginV2 {
    DiagnosticProfile,
    ExpectedInput { failure_id: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnsupportedCauseV2 {
    pub unsupported_id: String,
    pub origin: UnsupportedOriginV2,
    pub code: UnsupportedCodeV2,
    pub capability: SemanticIdentityV1,
    pub detail: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FailedInputCauseV2 {
    Missing {
        reason: String,
    },
    ProviderNoResponse {
        provider_intake_id: String,
        attempt: AcquisitionIntervalV2,
        raw_custody: FailedAcquisitionCustodyV2,
        failure: AcquisitionFailureV1,
    },
    AcquisitionFailed {
        provider_intake_id: String,
        attempt: AcquisitionIntervalV2,
        raw_custody: FailedAcquisitionCustodyV2,
        failure: AcquisitionFailureV1,
    },
    Unsupported {
        unsupported: UnsupportedCauseV2,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FailedInputV2 {
    pub expectation_id: String,
    pub failure_id: String,
    pub cause: FailedInputCauseV2,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InputAccountingV2 {
    pub selection_rule: SemanticIdentityV1,
    pub expected: Vec<ExpectedInputV1>,
    pub received: Vec<ReceivedInputV2>,
    pub admitted: Vec<AdmittedInputV1>,
    pub refused: Vec<RefusedInputV2>,
    pub failed: Vec<FailedInputV2>,
    pub excluded: Vec<ExcludedInputV1>,
    pub selected: Vec<SelectedInputV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimV2 {
    pub claim_id: String,
    pub proposition: String,
    pub status: crate::diagnostic_posture::ClaimStatusV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition_effect: Option<crate::diagnostic_posture::ConditionV1>,
    pub dependency_input_ids: Vec<String>,
    pub dependency_refusal_ids: Vec<String>,
    pub dependency_failure_ids: Vec<String>,
    pub state_binding_ids: Vec<String>,
    pub required_distinctions: Vec<String>,
    pub limitations: Vec<String>,
    pub nonclaims: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeV2 {
    pub derivation: DerivationV1,
    pub condition: crate::diagnostic_posture::ConditionV1,
    pub coherence: crate::diagnostic_posture::CoherenceV1,
    pub coverage: crate::diagnostic_posture::CoverageV1,
    pub summary: String,
    pub refusals: Vec<GovernedRefusalV1>,
    pub unsupported: Vec<UnsupportedCauseV2>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticExecutionV2 {
    pub schema: DiagnosticExecutionSchemaV2,
    pub artifact_id: String,
    pub canonicalization: SemanticIdentityV1,
    pub producer: ProducerV1,
    pub request_id: String,
    pub run_id: String,
    pub question: SemanticIdentityV1,
    pub subject: SubjectV1,
    pub profile: SemanticIdentityV1,
    pub profile_semantic_id: String,
    pub vantage: SemanticIdentityV1,
    pub state_model: SemanticIdentityV1,
    pub evaluator: SemanticIdentityV1,
    pub threshold_policy: SemanticIdentityV1,
    pub projection: ProjectionV1,
    pub execution_clock: SemanticIdentityV1,
    pub started_at: String,
    pub completed_at: String,
    pub attempt_interval: AcquisitionIntervalV2,
    pub inputs: InputAccountingV2,
    pub state_bindings: Vec<StateBindingV1>,
    pub claims: Vec<ClaimV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_claim_id: Option<String>,
    pub outcome: OutcomeV2,
    pub limitations: Vec<LimitationV1>,
    pub nonclaims: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum DiagnosticExecution {
    V1(DiagnosticExecutionV1),
    V2(DiagnosticExecutionV2),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticInputFailureKind {
    Missing,
    ProviderNoResponse,
    AcquisitionFailed,
    Unsupported,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticInputFailureTrace {
    pub expectation_id: String,
    pub failure_id: String,
    pub kind: DiagnosticInputFailureKind,
    pub detail: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum AcquisitionInterval {
    V1(AcquisitionIntervalV1),
    V2(AcquisitionIntervalV2),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum DiagnosticOutcome {
    V1(OutcomeV1),
    V2(OutcomeV2),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum DiagnosticClaim {
    V1(ClaimV1),
    V2(ClaimV2),
}

impl AcquisitionFailureV1 {
    fn validate(&self) -> Result<(), String> {
        let class_matches = matches!(
            (&self.class, &self.outcome),
            (
                AcquisitionFailureClassV1::SpawnFailed,
                AcquisitionOutcomeV1::SpawnFailed { .. }
            ) | (
                AcquisitionFailureClassV1::RequestWriteFailed,
                AcquisitionOutcomeV1::RequestWriteFailed { .. }
            ) | (
                AcquisitionFailureClassV1::Timeout,
                AcquisitionOutcomeV1::Timeout | AcquisitionOutcomeV1::ExchangeTimeout { .. }
            ) | (
                AcquisitionFailureClassV1::OutputTooLarge,
                AcquisitionOutcomeV1::OutputTooLarge
            ) | (
                AcquisitionFailureClassV1::StderrTooLarge,
                AcquisitionOutcomeV1::StderrTooLarge
            ) | (AcquisitionFailureClassV1::Eof, AcquisitionOutcomeV1::Eof)
                | (
                    AcquisitionFailureClassV1::MalformedFraming,
                    AcquisitionOutcomeV1::MalformedFraming { .. }
                )
                | (
                    AcquisitionFailureClassV1::MalformedJson,
                    AcquisitionOutcomeV1::MalformedJson { .. }
                )
                | (
                    AcquisitionFailureClassV1::ExitNonzero,
                    AcquisitionOutcomeV1::ExitNonzero { .. }
                )
                | (
                    AcquisitionFailureClassV1::HelperExited,
                    AcquisitionOutcomeV1::HelperExited { .. }
                )
                | (
                    AcquisitionFailureClassV1::Disconnect,
                    AcquisitionOutcomeV1::Disconnect { .. }
                )
                | (
                    AcquisitionFailureClassV1::CarrierStartupFailed,
                    AcquisitionOutcomeV1::CarrierStartupFailed { .. }
                )
                | (
                    AcquisitionFailureClassV1::NotRunning,
                    AcquisitionOutcomeV1::NotRunning
                )
                | (
                    AcquisitionFailureClassV1::IoFailed,
                    AcquisitionOutcomeV1::IoFailed { .. }
                )
        );
        if !class_matches {
            return Err("acquisition failure class disagrees with exact outcome".into());
        }
        if self.retry != RetryDispositionV1::Unspecified {
            return Err("acquisition failure retry projection disagrees with exact outcome".into());
        }
        if matches!(self.outcome, AcquisitionOutcomeV1::Response) {
            return Err("response cannot be carried as an acquisition failure".into());
        }
        Ok(())
    }
}

impl GovernedRefusalV1 {
    fn validate(&self) -> Result<(), String> {
        require_token("governed_refusal.refusal_id", &self.refusal_id)?;
        match &self.origin {
            GovernedRefusalOriginV1::Acquisition(origin) => {
                require_token(
                    "governed_refusal.acquisition.responsible_instance_id",
                    &origin.responsible_instance_id,
                )?;
                origin.failure.validate()
            }
            GovernedRefusalOriginV1::Protocol(origin) => {
                require_token(
                    "governed_refusal.protocol.responsible_instance_id",
                    &origin.responsible_instance_id,
                )?;
                validate_protocol_rejection_failure(&origin.failure)
            }
            GovernedRefusalOriginV1::Helper(origin) => {
                validate_protocol_token(
                    "governed_refusal.helper.responsible_instance_id",
                    &origin.responsible_instance_id,
                )?;
                require_token("governed_refusal.helper.message", &origin.message)?;
                let expected = match origin.code {
                    HelperRefusalCodeV1::UnsupportedProtocol => HelperRefusalBoundaryV1::Protocol,
                    HelperRefusalCodeV1::UnknownProfile
                    | HelperRefusalCodeV1::ProfileDigestMismatch => {
                        HelperRefusalBoundaryV1::Profile
                    }
                    HelperRefusalCodeV1::UnsupportedScope => HelperRefusalBoundaryV1::Scope,
                    HelperRefusalCodeV1::UnsupportedVantage => HelperRefusalBoundaryV1::Vantage,
                    HelperRefusalCodeV1::CapabilityDenied => HelperRefusalBoundaryV1::Capability,
                    HelperRefusalCodeV1::DeadlineExpired => HelperRefusalBoundaryV1::Deadline,
                    HelperRefusalCodeV1::BoundsUnsupported
                    | HelperRefusalCodeV1::ResourceExhausted => HelperRefusalBoundaryV1::Resource,
                    HelperRefusalCodeV1::CheckpointInvalid => HelperRefusalBoundaryV1::Checkpoint,
                    HelperRefusalCodeV1::CollectionFailed => HelperRefusalBoundaryV1::Collection,
                    HelperRefusalCodeV1::InternalError => HelperRefusalBoundaryV1::Internal,
                };
                if origin.boundary != expected {
                    return Err("helper refusal code and boundary disagree".into());
                }
                Ok(())
            }
            GovernedRefusalOriginV1::Profile(origin) => {
                validate_digest(
                    &origin.profile_semantic_id,
                    "governed_refusal.profile_semantic_id",
                )?;
                require_token(
                    "governed_refusal.profile.instance_id",
                    &origin.refusal.instance_id,
                )?;
                require_token(
                    "governed_refusal.profile.profile.id",
                    &origin.refusal.profile.id,
                )?;
                require_token("governed_refusal.profile.message", &origin.refusal.message)
            }
        }
    }
}

fn validate_protocol_rejection_failure(failure: &ProtocolRejectionFailureV1) -> Result<(), String> {
    if let ProtocolRejectionFailureV1::Validation {
        error: ProtocolValidationFailureV1::CapabilityEscape { capability },
    } = failure
    {
        validate_protocol_token("governed_refusal.protocol.failure.capability", capability)?;
    }
    Ok(())
}

impl DiagnosticExecutionV2 {
    pub fn validate(&self) -> Result<(), String> {
        validate_digest(&self.profile_semantic_id, "profile_semantic_id")?;
        validate_canonical_utc_timestamp(&self.started_at, "started_at")?;
        validate_canonical_utc_timestamp(&self.completed_at, "completed_at")?;
        validate_interval(&self.attempt_interval)?;
        let mut provider_intake_ids = std::collections::BTreeSet::new();
        for received in &self.inputs.received {
            require_token("received.provider_intake_id", &received.provider_intake_id)?;
            if !provider_intake_ids.insert(received.provider_intake_id.as_str()) {
                return Err("duplicate provider_intake_id".into());
            }
            validate_interval(&received.acquisition)?;
            validate_contributing_attempt_interval(
                &received.acquisition,
                &self.attempt_interval,
                "received",
            )?;
            let received_at =
                validate_canonical_utc_timestamp(&received.received_at, "received.received_at")?;
            let acquisition_end =
                chrono::DateTime::parse_from_rfc3339(&received.acquisition.ended_at)
                    .map_err(|error| error.to_string())?;
            let completed_at = chrono::DateTime::parse_from_rfc3339(&self.completed_at)
                .map_err(|error| error.to_string())?;
            if received_at < acquisition_end || received_at > completed_at {
                return Err(
                    "received_at falls before acquisition completion or after diagnostic completion"
                        .into(),
                );
            }
        }
        for refused in &self.inputs.refused {
            refused.refusal.validate()?;
            validate_input_refusal_binding(self, refused)?;
        }
        let mut input_unsupported_ids = BTreeSet::new();
        for failed in &self.inputs.failed {
            validate_failed_cause(
                &failed.cause,
                &failed.failure_id,
                &self.attempt_interval,
                &mut provider_intake_ids,
            )?;
            if let FailedInputCauseV2::Unsupported { unsupported } = &failed.cause {
                if !input_unsupported_ids.insert(unsupported.unsupported_id.as_str()) {
                    return Err("duplicate unsupported_id".into());
                }
            }
        }
        validate_claim_frontiers(self)?;
        validate_exact_outcome_frontiers(self)?;

        // Reuse the already-qualified v1 structural validator for fields that
        // v2 deliberately retained unchanged. This surrogate never leaves the
        // validator and does not project or replace the v2 artifact.
        let mut surrogate = self.v1_structural_surrogate();
        surrogate.artifact_id = computed_id(&surrogate, "artifact_id")?;
        surrogate.validate()?;

        validate_digest(&self.artifact_id, "artifact_id")?;
        if self.artifact_id != computed_id(self, "artifact_id")? {
            return Err("NQ v2 artifact identity mismatch".into());
        }
        Ok(())
    }

    fn v1_structural_surrogate(&self) -> DiagnosticExecutionV1 {
        let claims: Vec<_> = self.claims.iter().map(claim_v1).collect();
        let coherence = if self.outcome.coherence == CoherenceV1::Contradictory
            && !claims.iter().any(|claim| {
                claim.status == crate::diagnostic_posture::ClaimStatusV1::Contradictory
            }) {
            // V2 permits a claim to depend only on an exact refusal/failure
            // frontier. The v1 surrogate cannot represent those dependencies,
            // so such claims are normalized to unknown below. V2's own
            // validator has already checked the real contradiction relation.
            CoherenceV1::NotEvaluated
        } else {
            self.outcome.coherence
        };
        DiagnosticExecutionV1 {
            schema: DiagnosticExecutionSchema::V1,
            artifact_id: String::new(),
            canonicalization: self.canonicalization.clone(),
            producer: self.producer.clone(),
            request_id: self.request_id.clone(),
            run_id: self.run_id.clone(),
            question: self.question.clone(),
            subject: self.subject.clone(),
            profile: self.profile.clone(),
            vantage: self.vantage.clone(),
            state_model: self.state_model.clone(),
            evaluator: self.evaluator.clone(),
            threshold_policy: self.threshold_policy.clone(),
            projection: self.projection.clone(),
            execution_clock: self.execution_clock.clone(),
            started_at: self.started_at.clone(),
            completed_at: self.completed_at.clone(),
            attempt_interval: interval_v1(&self.attempt_interval),
            inputs: InputAccountingV1 {
                selection_rule: self.inputs.selection_rule.clone(),
                expected: self.inputs.expected.clone(),
                received: self
                    .inputs
                    .received
                    .iter()
                    .map(|item| ReceivedInputV1 {
                        input_id: item.input_id.clone(),
                        expectation_id: item.expectation_id.clone(),
                        raw_artifact_id: item.raw_artifact_id.clone(),
                        capture_mode: item.capture_mode,
                        capture_policy: item.capture_policy.clone(),
                        availability_at_derivation: item.availability_at_derivation,
                        acquisition: interval_v1(&item.acquisition),
                        received_at: item.received_at.clone(),
                    })
                    .collect(),
                admitted: self.inputs.admitted.clone(),
                refused: self
                    .inputs
                    .refused
                    .iter()
                    .map(|item| RefusedInputV1 {
                        input_id: item.input_id.clone(),
                        refusal_id: item.refusal.refusal_id.clone(),
                        code: refusal_origin_name(&item.refusal).into(),
                        reason: "exact governed refusal retained by v2".into(),
                    })
                    .collect(),
                failed: self.inputs.failed.iter().map(failed_input_v1).collect(),
                excluded: self.inputs.excluded.clone(),
                selected: self.inputs.selected.clone(),
            },
            state_bindings: self.state_bindings.clone(),
            claims,
            primary_claim_id: self.primary_claim_id.clone(),
            outcome: OutcomeV1 {
                derivation: self.outcome.derivation,
                condition: self.outcome.condition,
                coherence,
                coverage: self.outcome.coverage,
                summary: self.outcome.summary.clone(),
                refusal: self.outcome.refusals.first().map(|refusal| RefusalV1 {
                    code: refusal_origin_name(refusal).into(),
                    reason: refusal.refusal_id.clone(),
                }),
            },
            limitations: self.limitations.clone(),
            nonclaims: self.nonclaims.clone(),
        }
    }
}

impl DiagnosticExecution {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::V1(value) => value.validate(),
            Self::V2(value) => value.validate(),
        }
    }

    pub fn schema_name(&self) -> &'static str {
        match self {
            Self::V1(_) => crate::diagnostic_posture::NQ_DIAGNOSTIC_EXECUTION_SCHEMA,
            Self::V2(_) => NQ_DIAGNOSTIC_EXECUTION_V2_SCHEMA,
        }
    }

    pub fn artifact_id(&self) -> &str {
        match self {
            Self::V1(value) => &value.artifact_id,
            Self::V2(value) => &value.artifact_id,
        }
    }

    pub fn producer(&self) -> &ProducerV1 {
        match self {
            Self::V1(value) => &value.producer,
            Self::V2(value) => &value.producer,
        }
    }

    pub fn request_id(&self) -> &str {
        match self {
            Self::V1(value) => &value.request_id,
            Self::V2(value) => &value.request_id,
        }
    }

    pub fn run_id(&self) -> &str {
        match self {
            Self::V1(value) => &value.run_id,
            Self::V2(value) => &value.run_id,
        }
    }

    pub fn completed_at(&self) -> &str {
        match self {
            Self::V1(value) => &value.completed_at,
            Self::V2(value) => &value.completed_at,
        }
    }

    pub fn question(&self) -> &SemanticIdentityV1 {
        match self {
            Self::V1(value) => &value.question,
            Self::V2(value) => &value.question,
        }
    }

    pub fn subject(&self) -> &SubjectV1 {
        match self {
            Self::V1(value) => &value.subject,
            Self::V2(value) => &value.subject,
        }
    }

    pub fn profile(&self) -> &SemanticIdentityV1 {
        match self {
            Self::V1(value) => &value.profile,
            Self::V2(value) => &value.profile,
        }
    }

    pub fn profile_semantic_id(&self) -> Option<&str> {
        match self {
            Self::V1(_) => None,
            Self::V2(value) => Some(&value.profile_semantic_id),
        }
    }

    /// Exact provider-intake identities retained by the artifact. V1 did not
    /// expose this proof-bearing acquisition coordinate.
    pub fn provider_intake_ids(&self) -> Vec<&str> {
        match self {
            Self::V1(_) => Vec::new(),
            Self::V2(value) => value
                .inputs
                .received
                .iter()
                .map(|input| input.provider_intake_id.as_str())
                .collect(),
        }
    }

    pub fn vantage(&self) -> &SemanticIdentityV1 {
        match self {
            Self::V1(value) => &value.vantage,
            Self::V2(value) => &value.vantage,
        }
    }

    pub fn state_model(&self) -> &SemanticIdentityV1 {
        match self {
            Self::V1(value) => &value.state_model,
            Self::V2(value) => &value.state_model,
        }
    }

    pub fn evaluator(&self) -> &SemanticIdentityV1 {
        match self {
            Self::V1(value) => &value.evaluator,
            Self::V2(value) => &value.evaluator,
        }
    }

    pub fn threshold_policy(&self) -> &SemanticIdentityV1 {
        match self {
            Self::V1(value) => &value.threshold_policy,
            Self::V2(value) => &value.threshold_policy,
        }
    }

    pub fn projection(&self) -> &ProjectionV1 {
        match self {
            Self::V1(value) => &value.projection,
            Self::V2(value) => &value.projection,
        }
    }

    pub fn attempt_interval(&self) -> AcquisitionInterval {
        match self {
            Self::V1(value) => AcquisitionInterval::V1(value.attempt_interval.clone()),
            Self::V2(value) => AcquisitionInterval::V2(value.attempt_interval.clone()),
        }
    }

    pub fn claim(&self, claim_id: &str) -> Option<DiagnosticClaim> {
        match self {
            Self::V1(value) => value
                .claims
                .iter()
                .find(|claim| claim.claim_id == claim_id)
                .cloned()
                .map(DiagnosticClaim::V1),
            Self::V2(value) => value
                .claims
                .iter()
                .find(|claim| claim.claim_id == claim_id)
                .cloned()
                .map(DiagnosticClaim::V2),
        }
    }

    pub fn claim_count(&self, claim_id: &str) -> usize {
        match self {
            Self::V1(value) => value
                .claims
                .iter()
                .filter(|claim| claim.claim_id == claim_id)
                .count(),
            Self::V2(value) => value
                .claims
                .iter()
                .filter(|claim| claim.claim_id == claim_id)
                .count(),
        }
    }

    pub fn primary_claim_id(&self) -> Option<&str> {
        match self {
            Self::V1(value) => value.primary_claim_id.as_deref(),
            Self::V2(value) => value.primary_claim_id.as_deref(),
        }
    }

    pub fn state_bindings(&self) -> &[StateBindingV1] {
        match self {
            Self::V1(value) => &value.state_bindings,
            Self::V2(value) => &value.state_bindings,
        }
    }

    pub fn outcome(&self) -> DiagnosticOutcome {
        match self {
            Self::V1(value) => DiagnosticOutcome::V1(value.outcome.clone()),
            Self::V2(value) => DiagnosticOutcome::V2(value.outcome.clone()),
        }
    }

    pub fn outcome_derivation(&self) -> DerivationV1 {
        match self {
            Self::V1(value) => value.outcome.derivation,
            Self::V2(value) => value.outcome.derivation,
        }
    }

    pub fn outcome_condition(&self) -> ConditionV1 {
        match self {
            Self::V1(value) => value.outcome.condition,
            Self::V2(value) => value.outcome.condition,
        }
    }

    pub fn outcome_coherence(&self) -> CoherenceV1 {
        match self {
            Self::V1(value) => value.outcome.coherence,
            Self::V2(value) => value.outcome.coherence,
        }
    }

    pub fn outcome_coverage(&self) -> CoverageV1 {
        match self {
            Self::V1(value) => value.outcome.coverage,
            Self::V2(value) => value.outcome.coverage,
        }
    }

    pub fn limitations(&self) -> &[LimitationV1] {
        match self {
            Self::V1(value) => &value.limitations,
            Self::V2(value) => &value.limitations,
        }
    }

    pub fn nonclaims(&self) -> &[String] {
        match self {
            Self::V1(value) => &value.nonclaims,
            Self::V2(value) => &value.nonclaims,
        }
    }

    pub fn key(&self) -> DiagnosticKey {
        DiagnosticKey {
            question_id: self.question().id.clone(),
            subject_id: self.subject().id.clone(),
            profile_id: self.profile().id.clone(),
            vantage_id: self.vantage().id.clone(),
        }
    }

    pub fn received_acquisition(&self, input_id: &str) -> Option<AcquisitionInterval> {
        match self {
            Self::V1(value) => value
                .inputs
                .received
                .iter()
                .find(|input| input.input_id == input_id)
                .map(|input| AcquisitionInterval::V1(input.acquisition.clone())),
            Self::V2(value) => value
                .inputs
                .received
                .iter()
                .find(|input| input.input_id == input_id)
                .map(|input| AcquisitionInterval::V2(input.acquisition.clone())),
        }
    }

    pub fn refusal_acquisition(&self, refusal_id: &str) -> Option<AcquisitionInterval> {
        let Self::V2(value) = self else {
            return None;
        };
        let refused = value
            .inputs
            .refused
            .iter()
            .find(|input| input.refusal.refusal_id == refusal_id)?;
        value
            .inputs
            .received
            .iter()
            .find(|input| input.input_id == refused.input_id)
            .map(|input| AcquisitionInterval::V2(input.acquisition.clone()))
    }

    pub fn has_refusal_id(&self, refusal_id: &str) -> bool {
        matches!(self, Self::V2(value) if value
            .inputs
            .refused
            .iter()
            .any(|input| input.refusal.refusal_id == refusal_id))
    }

    pub fn failure_acquisition(&self, failure_id: &str) -> Option<AcquisitionInterval> {
        let Self::V2(value) = self else {
            return None;
        };
        let failed = value
            .inputs
            .failed
            .iter()
            .find(|input| input.failure_id == failure_id)?;
        match &failed.cause {
            FailedInputCauseV2::ProviderNoResponse { attempt, .. }
            | FailedInputCauseV2::AcquisitionFailed { attempt, .. } => {
                Some(AcquisitionInterval::V2(attempt.clone()))
            }
            FailedInputCauseV2::Missing { .. } | FailedInputCauseV2::Unsupported { .. } => None,
        }
    }

    pub fn has_failure_id(&self, failure_id: &str) -> bool {
        matches!(self, Self::V2(value) if value
            .inputs
            .failed
            .iter()
            .any(|input| input.failure_id == failure_id))
    }

    pub fn v1_has_unqualified_clock_limitation(&self) -> bool {
        matches!(self, Self::V1(value) if value.limitations.iter().any(|limitation| {
            limitation.code == "absolute_clock_quality_unqualified"
        }))
    }

    pub fn has_provider_no_response(&self) -> bool {
        match self {
            Self::V1(value) => value
                .inputs
                .failed
                .iter()
                .any(|input| input.kind == FailedInputKindV1::NoResponse),
            Self::V2(value) => {
                value.inputs.failed.iter().any(|input| {
                    matches!(input.cause, FailedInputCauseV2::ProviderNoResponse { .. })
                })
            }
        }
    }

    pub fn input_failure_traces(&self) -> Vec<DiagnosticInputFailureTrace> {
        match self {
            Self::V1(value) => value
                .inputs
                .failed
                .iter()
                .map(|input| DiagnosticInputFailureTrace {
                    expectation_id: input.expectation_id.clone(),
                    failure_id: input.failure_id.clone(),
                    kind: match input.kind {
                        FailedInputKindV1::Missing => DiagnosticInputFailureKind::Missing,
                        FailedInputKindV1::NoResponse => {
                            DiagnosticInputFailureKind::ProviderNoResponse
                        }
                        FailedInputKindV1::AcquisitionFailed => {
                            DiagnosticInputFailureKind::AcquisitionFailed
                        }
                        FailedInputKindV1::Unsupported => DiagnosticInputFailureKind::Unsupported,
                    },
                    detail: input.reason.clone(),
                })
                .collect(),
            Self::V2(value) => value
                .inputs
                .failed
                .iter()
                .map(|input| {
                    let (kind, detail) = match &input.cause {
                        FailedInputCauseV2::Missing { reason } => {
                            (DiagnosticInputFailureKind::Missing, reason.clone())
                        }
                        FailedInputCauseV2::ProviderNoResponse { failure, .. } => (
                            DiagnosticInputFailureKind::ProviderNoResponse,
                            serde_json::to_string(failure)
                                .expect("typed acquisition failure is serializable"),
                        ),
                        FailedInputCauseV2::AcquisitionFailed { failure, .. } => (
                            DiagnosticInputFailureKind::AcquisitionFailed,
                            serde_json::to_string(failure)
                                .expect("typed acquisition failure is serializable"),
                        ),
                        FailedInputCauseV2::Unsupported { unsupported } => (
                            DiagnosticInputFailureKind::Unsupported,
                            unsupported.detail.clone(),
                        ),
                    };
                    DiagnosticInputFailureTrace {
                        expectation_id: input.expectation_id.clone(),
                        failure_id: input.failure_id.clone(),
                        kind,
                        detail,
                    }
                })
                .collect(),
        }
    }
}

impl From<DiagnosticExecutionV1> for DiagnosticExecution {
    fn from(value: DiagnosticExecutionV1) -> Self {
        Self::V1(value)
    }
}

impl From<DiagnosticExecutionV2> for DiagnosticExecution {
    fn from(value: DiagnosticExecutionV2) -> Self {
        Self::V2(value)
    }
}

impl From<AcquisitionIntervalV1> for AcquisitionInterval {
    fn from(value: AcquisitionIntervalV1) -> Self {
        Self::V1(value)
    }
}

impl From<AcquisitionIntervalV2> for AcquisitionInterval {
    fn from(value: AcquisitionIntervalV2) -> Self {
        Self::V2(value)
    }
}

impl AcquisitionInterval {
    pub fn schema_name(&self) -> &'static str {
        match self {
            Self::V1(_) => crate::diagnostic_posture::NQ_DIAGNOSTIC_EXECUTION_SCHEMA,
            Self::V2(_) => NQ_DIAGNOSTIC_EXECUTION_V2_SCHEMA,
        }
    }

    pub fn started_at(&self) -> &str {
        match self {
            Self::V1(value) => &value.started_at,
            Self::V2(value) => &value.started_at,
        }
    }

    pub fn ended_at(&self) -> &str {
        match self {
            Self::V1(value) => &value.ended_at,
            Self::V2(value) => &value.ended_at,
        }
    }

    pub fn maximum_error_ms(&self) -> Option<u64> {
        match self {
            Self::V1(value) => Some(value.clock_uncertainty_ms),
            Self::V2(value) => match value.qualification {
                ClockQualificationV2::Bounded {
                    maximum_error_ms, ..
                } => Some(maximum_error_ms),
                ClockQualificationV2::Unqualified { .. } => None,
            },
        }
    }

    pub fn unqualified_reason(&self) -> Option<(&str, &str)> {
        match self {
            Self::V1(_) => None,
            Self::V2(value) => match &value.qualification {
                ClockQualificationV2::Bounded { .. } => None,
                ClockQualificationV2::Unqualified { code, detail } => Some((code, detail)),
            },
        }
    }
}

impl DiagnosticOutcome {
    pub fn derivation(&self) -> DerivationV1 {
        match self {
            Self::V1(value) => value.derivation,
            Self::V2(value) => value.derivation,
        }
    }

    pub fn condition(&self) -> ConditionV1 {
        match self {
            Self::V1(value) => value.condition,
            Self::V2(value) => value.condition,
        }
    }

    pub fn coherence(&self) -> CoherenceV1 {
        match self {
            Self::V1(value) => value.coherence,
            Self::V2(value) => value.coherence,
        }
    }

    pub fn coverage(&self) -> CoverageV1 {
        match self {
            Self::V1(value) => value.coverage,
            Self::V2(value) => value.coverage,
        }
    }

    pub fn refusal_display(&self) -> Option<(String, String)> {
        match self {
            Self::V1(value) => value
                .refusal
                .as_ref()
                .map(|refusal| (refusal.code.clone(), refusal.reason.clone())),
            Self::V2(value) => value.refusals.first().map(|refusal| {
                let suffix = if value.refusals.len() == 1 {
                    String::new()
                } else {
                    format!(" (+{} more)", value.refusals.len() - 1)
                };
                (
                    refusal.refusal_id.clone(),
                    format!(
                        "exact {} governed refusal{}",
                        refusal_origin_name(refusal),
                        suffix
                    ),
                )
            }),
        }
    }
}

impl DiagnosticClaim {
    pub fn schema_name(&self) -> &'static str {
        match self {
            Self::V1(_) => crate::diagnostic_posture::NQ_DIAGNOSTIC_EXECUTION_SCHEMA,
            Self::V2(_) => NQ_DIAGNOSTIC_EXECUTION_V2_SCHEMA,
        }
    }

    pub fn claim_id(&self) -> &str {
        match self {
            Self::V1(value) => &value.claim_id,
            Self::V2(value) => &value.claim_id,
        }
    }

    pub fn status(&self) -> crate::diagnostic_posture::ClaimStatusV1 {
        match self {
            Self::V1(value) => value.status,
            Self::V2(value) => value.status,
        }
    }

    pub fn condition_effect(&self) -> Option<ConditionV1> {
        match self {
            Self::V1(value) => value.condition_effect,
            Self::V2(value) => value.condition_effect,
        }
    }

    pub fn dependency_input_ids(&self) -> &[String] {
        match self {
            Self::V1(value) => &value.dependency_input_ids,
            Self::V2(value) => &value.dependency_input_ids,
        }
    }

    pub fn dependency_refusal_ids(&self) -> &[String] {
        match self {
            Self::V1(_) => &[],
            Self::V2(value) => &value.dependency_refusal_ids,
        }
    }

    pub fn dependency_failure_ids(&self) -> &[String] {
        match self {
            Self::V1(_) => &[],
            Self::V2(value) => &value.dependency_failure_ids,
        }
    }

    pub fn state_binding_ids(&self) -> &[String] {
        match self {
            Self::V1(value) => &value.state_binding_ids,
            Self::V2(value) => &value.state_binding_ids,
        }
    }
}

fn validate_interval(interval: &AcquisitionIntervalV2) -> Result<(), String> {
    require_token("acquisition.clock.id", &interval.clock.id)?;
    require_token("acquisition.clock.version", &interval.clock.version)?;
    validate_digest(&interval.clock.digest, "acquisition.clock.digest")?;
    let start = validate_canonical_utc_timestamp(&interval.started_at, "acquisition.started_at")?;
    let end = validate_canonical_utc_timestamp(&interval.ended_at, "acquisition.ended_at")?;
    if start > end {
        return Err("acquisition interval starts after it ends".into());
    }
    match &interval.qualification {
        ClockQualificationV2::Bounded { basis, .. } => {
            require_token("acquisition.qualification.basis.id", &basis.id)?;
            require_token("acquisition.qualification.basis.version", &basis.version)?;
            validate_digest(&basis.digest, "acquisition.qualification.basis.digest")
        }
        ClockQualificationV2::Unqualified { code, detail } => {
            require_token("acquisition.qualification.code", code)?;
            require_token("acquisition.qualification.detail", detail)
        }
    }
}

fn validate_canonical_utc_timestamp(
    value: &str,
    field: &str,
) -> Result<chrono::DateTime<chrono::FixedOffset>, String> {
    let parsed = chrono::DateTime::parse_from_rfc3339(value)
        .map_err(|error| format!("{field} must be RFC3339: {error}"))?;
    let canonical = parsed
        .with_timezone(&chrono::Utc)
        .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true);
    if canonical != value {
        return Err(format!(
            "{field} is not the canonical UTC representation emitted by NQ"
        ));
    }
    Ok(parsed)
}

fn validate_failed_cause<'a>(
    cause: &'a FailedInputCauseV2,
    failure_id: &str,
    diagnostic_attempt: &AcquisitionIntervalV2,
    provider_intake_ids: &mut BTreeSet<&'a str>,
) -> Result<(), String> {
    match cause {
        FailedInputCauseV2::Missing { reason } => require_token("failed.reason", reason),
        FailedInputCauseV2::ProviderNoResponse {
            provider_intake_id,
            attempt,
            failure,
            ..
        } => {
            validate_failed_attempt(
                provider_intake_id,
                attempt,
                diagnostic_attempt,
                provider_intake_ids,
            )?;
            failure.validate()?;
            if !matches!(
                failure.class,
                AcquisitionFailureClassV1::Timeout
                    | AcquisitionFailureClassV1::Eof
                    | AcquisitionFailureClassV1::HelperExited
                    | AcquisitionFailureClassV1::Disconnect
            ) {
                return Err(
                    "provider_no_response carries a different acquisition failure class".into(),
                );
            }
            Ok(())
        }
        FailedInputCauseV2::AcquisitionFailed {
            provider_intake_id,
            attempt,
            failure,
            ..
        } => {
            validate_failed_attempt(
                provider_intake_id,
                attempt,
                diagnostic_attempt,
                provider_intake_ids,
            )?;
            failure.validate()?;
            if matches!(
                failure.class,
                AcquisitionFailureClassV1::Timeout
                    | AcquisitionFailureClassV1::Eof
                    | AcquisitionFailureClassV1::HelperExited
                    | AcquisitionFailureClassV1::Disconnect
            ) {
                return Err(
                    "acquisition_failed carries a provider-no-response failure class".into(),
                );
            }
            Ok(())
        }
        FailedInputCauseV2::Unsupported { unsupported } => {
            validate_unsupported(unsupported)?;
            match &unsupported.origin {
                UnsupportedOriginV2::ExpectedInput {
                    failure_id: referenced,
                } if referenced == failure_id => Ok(()),
                UnsupportedOriginV2::ExpectedInput { .. } => {
                    Err("unsupported input cause references a different failure_id".into())
                }
                UnsupportedOriginV2::DiagnosticProfile => Err(
                    "failed-input unsupported cause cannot claim diagnostic-profile scope".into(),
                ),
            }
        }
    }
}

fn validate_failed_attempt<'a>(
    provider_intake_id: &'a str,
    attempt: &AcquisitionIntervalV2,
    diagnostic_attempt: &AcquisitionIntervalV2,
    provider_intake_ids: &mut BTreeSet<&'a str>,
) -> Result<(), String> {
    require_token("failed.provider_intake_id", provider_intake_id)?;
    if !provider_intake_ids.insert(provider_intake_id) {
        return Err("duplicate provider_intake_id".into());
    }
    validate_interval(attempt)?;
    validate_contributing_attempt_interval(attempt, diagnostic_attempt, "failed")
}

fn validate_contributing_attempt_interval(
    attempt: &AcquisitionIntervalV2,
    diagnostic_attempt: &AcquisitionIntervalV2,
    kind: &str,
) -> Result<(), String> {
    if attempt.clock != diagnostic_attempt.clock {
        return Err(format!(
            "{kind} acquisition attempt does not use the diagnostic execution clock"
        ));
    }
    if attempt.qualification != diagnostic_attempt.qualification {
        return Err(format!(
            "{kind} acquisition attempt changes the diagnostic clock qualification"
        ));
    }
    let attempt_start = chrono::DateTime::parse_from_rfc3339(&attempt.started_at)
        .map_err(|error| error.to_string())?;
    let attempt_end = chrono::DateTime::parse_from_rfc3339(&attempt.ended_at)
        .map_err(|error| error.to_string())?;
    let diagnostic_start = chrono::DateTime::parse_from_rfc3339(&diagnostic_attempt.started_at)
        .map_err(|error| error.to_string())?;
    let diagnostic_end = chrono::DateTime::parse_from_rfc3339(&diagnostic_attempt.ended_at)
        .map_err(|error| error.to_string())?;
    if attempt_start < diagnostic_start || attempt_end > diagnostic_end {
        return Err(format!(
            "{kind} acquisition attempt falls outside the diagnostic attempt"
        ));
    }
    Ok(())
}

fn validate_unsupported(cause: &UnsupportedCauseV2) -> Result<(), String> {
    require_token("unsupported.unsupported_id", &cause.unsupported_id)?;
    require_token("unsupported.capability.id", &cause.capability.id)?;
    require_token("unsupported.capability.version", &cause.capability.version)?;
    validate_digest(&cause.capability.digest, "unsupported.capability.digest")?;
    require_token("unsupported.detail", &cause.detail)?;
    if let UnsupportedOriginV2::ExpectedInput { failure_id } = &cause.origin {
        require_token("unsupported.failure_id", failure_id)?;
    }
    Ok(())
}

fn validate_input_refusal_binding(
    artifact: &DiagnosticExecutionV2,
    input: &RefusedInputV2,
) -> Result<(), String> {
    let occurrence = artifact
        .inputs
        .received
        .iter()
        .find(|received| received.input_id == input.input_id)
        .ok_or_else(|| "refused input references an unknown received input".to_string())?;
    let role = artifact
        .inputs
        .expected
        .iter()
        .find(|expected| expected.expectation_id == occurrence.expectation_id)
        .map(|expected| expected.role.as_str())
        .ok_or_else(|| "refused input references an unknown expectation".to_string())?;
    match (&input.refusal.origin, &input.profile_binding) {
        (
            GovernedRefusalOriginV1::Profile(profile),
            Some(ProfileRefusalBindingV2::ArtifactProfile),
        ) => {
            if profile.profile_semantic_id != artifact.profile_semantic_id
                || profile.refusal.profile.id != artifact.profile.id
                || profile.refusal.profile.version.to_string() != artifact.profile.version
                || profile.refusal.boundary == ProfileRefusalBoundaryV1::Detector
            {
                return Err("artifact-profile input refusal binding is invalid".into());
            }
            Ok(())
        }
        (
            GovernedRefusalOriginV1::Profile(profile),
            Some(ProfileRefusalBindingV2::ForeignInputRole { role: bound_role }),
        ) => {
            require_token("refused.profile_binding.role", bound_role)?;
            if bound_role != role {
                return Err("foreign-profile refusal role differs from expected role".into());
            }
            if profile.profile_semantic_id == artifact.profile_semantic_id
                && profile.refusal.profile.id == artifact.profile.id
                && profile.refusal.profile.version.to_string() == artifact.profile.version
            {
                return Err("artifact-profile refusal is mislabeled as foreign".into());
            }
            Ok(())
        }
        (GovernedRefusalOriginV1::Profile(_), None) => {
            Err("profile-origin input refusal lacks an explicit binding".into())
        }
        (_, Some(_)) => Err("non-profile input refusal carries a profile binding".into()),
        (_, None) => Ok(()),
    }
}

fn validate_claim_frontiers(artifact: &DiagnosticExecutionV2) -> Result<(), String> {
    let selected: BTreeMap<&str, &SelectedInputV1> = artifact
        .inputs
        .selected
        .iter()
        .map(|input| (input.input_id.as_str(), input))
        .collect();
    let refusal_ids: BTreeSet<&str> = artifact
        .inputs
        .refused
        .iter()
        .map(|input| input.refusal.refusal_id.as_str())
        .collect();
    let failure_ids: BTreeSet<&str> = artifact
        .inputs
        .failed
        .iter()
        .map(|input| input.failure_id.as_str())
        .collect();
    let bindings: BTreeMap<&str, &StateBindingV1> = artifact
        .state_bindings
        .iter()
        .map(|binding| (binding.binding_id.as_str(), binding))
        .collect();
    let omitted_distinctions: BTreeSet<&str> = artifact
        .projection
        .omitted_distinctions
        .iter()
        .map(|distinction| distinction.code.as_str())
        .collect();
    require_sorted_unique(
        "claims",
        artifact.claims.iter().map(|claim| claim.claim_id.as_str()),
    )?;
    let mut claim_ids = BTreeSet::new();
    let mut any_contradictory = false;
    for claim in &artifact.claims {
        require_token("claim.claim_id", &claim.claim_id)?;
        require_token("claim.proposition", &claim.proposition)?;
        if !claim_ids.insert(claim.claim_id.as_str()) {
            return Err("duplicate claim_id".into());
        }
        any_contradictory |=
            claim.status == crate::diagnostic_posture::ClaimStatusV1::Contradictory;
        if claim.dependency_input_ids.is_empty()
            && claim.dependency_refusal_ids.is_empty()
            && claim.dependency_failure_ids.is_empty()
        {
            return Err("v2 claim has no exact dependency".into());
        }
        require_sorted_unique(
            "claim.dependency_input_ids",
            claim.dependency_input_ids.iter().map(String::as_str),
        )?;
        require_sorted_unique(
            "claim.dependency_refusal_ids",
            claim.dependency_refusal_ids.iter().map(String::as_str),
        )?;
        require_sorted_unique(
            "claim.dependency_failure_ids",
            claim.dependency_failure_ids.iter().map(String::as_str),
        )?;
        let dependencies: BTreeSet<&str> = claim
            .dependency_input_ids
            .iter()
            .map(String::as_str)
            .collect();
        if dependencies.iter().any(|id| !selected.contains_key(*id)) {
            return Err("v2 claim references a non-selected input".into());
        }
        if claim
            .dependency_refusal_ids
            .iter()
            .any(|id| !refusal_ids.contains(id.as_str()))
        {
            return Err("v2 claim references an unknown refused-input carrier".into());
        }
        if claim
            .dependency_failure_ids
            .iter()
            .any(|id| !failure_ids.contains(id.as_str()))
        {
            return Err("v2 claim references an unknown failed-input occurrence".into());
        }
        require_sorted_unique(
            "claim.state_binding_ids",
            claim.state_binding_ids.iter().map(String::as_str),
        )?;
        for binding_id in &claim.state_binding_ids {
            let binding = bindings
                .get(binding_id.as_str())
                .ok_or_else(|| "v2 claim references an unknown state binding".to_string())?;
            if binding
                .supporting_input_ids
                .iter()
                .any(|input_id| !dependencies.contains(input_id.as_str()))
            {
                return Err(
                    "claim state binding depends on input outside the claim dependency frontier"
                        .into(),
                );
            }
        }
        require_sorted_unique(
            "claim.required_distinctions",
            claim.required_distinctions.iter().map(String::as_str),
        )?;
        for distinction in &claim.required_distinctions {
            require_token("claim.required_distinction", distinction)?;
            if omitted_distinctions.contains(distinction.as_str()) {
                return Err("claim requires a distinction omitted by the projection".into());
            }
        }
        require_sorted_unique(
            "claim.limitations",
            claim.limitations.iter().map(String::as_str),
        )?;
        for limitation in &claim.limitations {
            require_token("claim.limitation", limitation)?;
        }
        require_sorted_unique(
            "claim.nonclaims",
            claim.nonclaims.iter().map(String::as_str),
        )?;
        for nonclaim in &claim.nonclaims {
            require_token("claim.nonclaim", nonclaim)?;
        }
        if claim.condition_effect.is_some_and(|effect| {
            matches!(
                effect,
                ConditionV1::Present
                    | ConditionV1::Clean
                    | ConditionV1::ExplicitlyAbsent
                    | ConditionV1::NotApplicable
            )
        }) && claim.status != crate::diagnostic_posture::ClaimStatusV1::Established
        {
            return Err("determinate condition effect requires an established claim".into());
        }
        if matches!(
            claim.status,
            crate::diagnostic_posture::ClaimStatusV1::Unknown
                | crate::diagnostic_posture::ClaimStatusV1::Contradictory
                | crate::diagnostic_posture::ClaimStatusV1::Refuted
        ) && claim
            .condition_effect
            .is_some_and(|effect| effect != ConditionV1::Unresolved)
        {
            return Err("non-established claim may only leave the condition unresolved".into());
        }
        if claim.condition_effect.is_some()
            && artifact.primary_claim_id.as_deref() != Some(claim.claim_id.as_str())
        {
            return Err("non-primary claim carries a condition effect".into());
        }
    }
    match artifact.primary_claim_id.as_deref() {
        Some(primary) if !claim_ids.contains(primary) => {
            return Err("primary_claim_id does not identify an exported claim".into());
        }
        None if matches!(
            artifact.outcome.derivation,
            DerivationV1::Completed | DerivationV1::Partial
        ) =>
        {
            return Err("completed or partial outcome has no primary claim".into());
        }
        Some(_)
            if matches!(
                artifact.outcome.derivation,
                DerivationV1::Refused | DerivationV1::Unsupported
            ) =>
        {
            return Err("refused or unsupported outcome exports a primary claim".into());
        }
        _ => {}
    }
    if matches!(
        artifact.outcome.derivation,
        DerivationV1::Refused | DerivationV1::Unsupported
    ) && !artifact.claims.is_empty()
    {
        return Err("refused or unsupported outcome exports claims".into());
    }
    if let Some(primary_id) = artifact.primary_claim_id.as_deref() {
        let primary = artifact
            .claims
            .iter()
            .find(|claim| claim.claim_id == primary_id)
            .expect("primary identity checked above");
        if primary.condition_effect != Some(artifact.outcome.condition) {
            return Err("primary claim condition effect differs from outcome condition".into());
        }
        let determinate = matches!(
            artifact.outcome.condition,
            ConditionV1::Present
                | ConditionV1::Clean
                | ConditionV1::ExplicitlyAbsent
                | ConditionV1::NotApplicable
        );
        if determinate && primary.state_binding_ids.is_empty() {
            return Err("primary determinate claim has no state binding".into());
        }
        if (primary.status == crate::diagnostic_posture::ClaimStatusV1::Contradictory)
            != (artifact.outcome.coherence == CoherenceV1::Contradictory)
        {
            return Err("primary contradiction differs from outcome coherence".into());
        }
    } else if artifact.outcome.coherence == CoherenceV1::Contradictory {
        return Err("contradictory outcome has no primary contradictory claim".into());
    }
    if any_contradictory != (artifact.outcome.coherence == CoherenceV1::Contradictory) {
        return Err("exported claim dissent differs from outcome coherence".into());
    }
    Ok(())
}

fn validate_exact_outcome_frontiers(artifact: &DiagnosticExecutionV2) -> Result<(), String> {
    require_sorted_unique(
        "outcome.refusals",
        artifact
            .outcome
            .refusals
            .iter()
            .map(|refusal| refusal.refusal_id.as_str()),
    )?;
    for refusal in &artifact.outcome.refusals {
        refusal.validate()?;
    }
    require_sorted_unique(
        "outcome.unsupported",
        artifact
            .outcome
            .unsupported
            .iter()
            .map(|cause| cause.unsupported_id.as_str()),
    )?;
    for unsupported in &artifact.outcome.unsupported {
        validate_unsupported(unsupported)?;
    }
    match artifact.outcome.derivation {
        DerivationV1::Refused => {
            if artifact.outcome.refusals.is_empty() || !artifact.outcome.unsupported.is_empty() {
                return Err("refused outcome has an invalid exact frontier".into());
            }
            validate_refusal_correspondence(artifact)
        }
        DerivationV1::Unsupported => {
            if artifact.outcome.unsupported.is_empty() || !artifact.outcome.refusals.is_empty() {
                return Err("unsupported outcome has an invalid exact frontier".into());
            }
            validate_unsupported_correspondence(artifact)
        }
        DerivationV1::Completed | DerivationV1::Partial => {
            if !artifact.outcome.refusals.is_empty() || !artifact.outcome.unsupported.is_empty() {
                return Err(
                    "completed/partial outcome carries refusal or unsupported frontier".into(),
                );
            }
            Ok(())
        }
    }
}

fn validate_refusal_correspondence(artifact: &DiagnosticExecutionV2) -> Result<(), String> {
    if artifact.inputs.refused.is_empty() {
        if artifact.outcome.refusals.len() != 1 {
            return Err("detector refusal must carry exactly one refusal".into());
        }
        let refusal = &artifact.outcome.refusals[0];
        let GovernedRefusalOriginV1::Profile(profile) = &refusal.origin else {
            return Err("detector refusal must be profile-origin".into());
        };
        if profile.profile_semantic_id != artifact.profile_semantic_id
            || profile.refusal.profile.id != artifact.profile.id
            || profile.refusal.profile.version.to_string() != artifact.profile.version
            || profile.refusal.boundary != ProfileRefusalBoundaryV1::Detector
            || profile.refusal.code != ProfileRefusalCodeV1::CannotEvaluate
            || profile.refusal.message != artifact.outcome.summary
        {
            return Err("detector refusal disagrees with artifact profile or outcome".into());
        }
        return Ok(());
    }
    let inputs: BTreeMap<_, _> = artifact
        .inputs
        .refused
        .iter()
        .map(|input| (input.refusal.refusal_id.as_str(), &input.refusal))
        .collect();
    let outcome: BTreeMap<_, _> = artifact
        .outcome
        .refusals
        .iter()
        .map(|refusal| (refusal.refusal_id.as_str(), refusal))
        .collect();
    if inputs != outcome {
        return Err("outcome does not preserve the exact input-refusal frontier".into());
    }
    Ok(())
}

fn validate_unsupported_correspondence(artifact: &DiagnosticExecutionV2) -> Result<(), String> {
    let inputs: BTreeMap<_, _> = artifact
        .inputs
        .failed
        .iter()
        .filter_map(|input| match &input.cause {
            FailedInputCauseV2::Unsupported { unsupported } => {
                Some((unsupported.unsupported_id.as_str(), unsupported))
            }
            _ => None,
        })
        .collect();
    if inputs.is_empty() {
        if artifact.outcome.unsupported.len() != 1 {
            return Err("profile unsupported must carry exactly one cause".into());
        }
        let cause = &artifact.outcome.unsupported[0];
        if cause.origin != UnsupportedOriginV2::DiagnosticProfile
            || cause.code != UnsupportedCodeV2::QuestionUnsupported
            || cause.capability != artifact.question
        {
            return Err("profile unsupported cause disagrees with bounded question".into());
        }
        return Ok(());
    }
    let outcome: BTreeMap<_, _> = artifact
        .outcome
        .unsupported
        .iter()
        .map(|cause| (cause.unsupported_id.as_str(), cause))
        .collect();
    if inputs != outcome {
        return Err("outcome does not preserve the exact unsupported frontier".into());
    }
    Ok(())
}

fn require_sorted_unique<'a>(
    field: &str,
    values: impl IntoIterator<Item = &'a str>,
) -> Result<(), String> {
    let mut previous: Option<&str> = None;
    for value in values {
        if previous.is_some_and(|prior| prior.as_bytes() >= value.as_bytes()) {
            return Err(format!("{field} must be strictly ordered and unique"));
        }
        previous = Some(value);
    }
    Ok(())
}

fn claim_v1(claim: &ClaimV2) -> ClaimV1 {
    let status = if claim.dependency_input_ids.is_empty() {
        // V1 has no refusal/failure dependency frontier and therefore cannot
        // structurally represent this otherwise-valid v2 claim. The v2
        // validator has already checked the exact claim; normalize only the
        // private structural surrogate rather than inventing a selected input.
        crate::diagnostic_posture::ClaimStatusV1::Unknown
    } else {
        claim.status
    };
    ClaimV1 {
        claim_id: claim.claim_id.clone(),
        proposition: claim.proposition.clone(),
        status,
        condition_effect: claim.condition_effect,
        dependency_input_ids: claim.dependency_input_ids.clone(),
        state_binding_ids: claim.state_binding_ids.clone(),
        required_distinctions: claim.required_distinctions.clone(),
        limitations: claim.limitations.clone(),
        nonclaims: claim.nonclaims.clone(),
    }
}

fn interval_v1(interval: &AcquisitionIntervalV2) -> AcquisitionIntervalV1 {
    AcquisitionIntervalV1 {
        started_at: interval.started_at.clone(),
        ended_at: interval.ended_at.clone(),
        clock: interval.clock.clone(),
        clock_uncertainty_ms: match interval.qualification {
            ClockQualificationV2::Bounded {
                maximum_error_ms, ..
            } => maximum_error_ms,
            ClockQualificationV2::Unqualified { .. } => 0,
        },
    }
}

fn failed_input_v1(item: &FailedInputV2) -> FailedInputV1 {
    let (kind, reason) = match &item.cause {
        FailedInputCauseV2::Missing { reason } => (FailedInputKindV1::Missing, reason.clone()),
        FailedInputCauseV2::ProviderNoResponse { .. } => (
            FailedInputKindV1::NoResponse,
            "exact provider no-response failure retained by v2".into(),
        ),
        FailedInputCauseV2::AcquisitionFailed { .. } => (
            FailedInputKindV1::AcquisitionFailed,
            "exact acquisition failure retained by v2".into(),
        ),
        FailedInputCauseV2::Unsupported { unsupported } => {
            (FailedInputKindV1::Unsupported, unsupported.detail.clone())
        }
    };
    FailedInputV1 {
        expectation_id: item.expectation_id.clone(),
        failure_id: item.failure_id.clone(),
        kind,
        reason,
    }
}

fn refusal_origin_name(refusal: &GovernedRefusalV1) -> &'static str {
    match refusal.origin {
        GovernedRefusalOriginV1::Acquisition(_) => "acquisition",
        GovernedRefusalOriginV1::Protocol(_) => "protocol",
        GovernedRefusalOriginV1::Helper(_) => "helper",
        GovernedRefusalOriginV1::Profile(_) => "profile",
    }
}

fn computed_id<T: Serialize>(value: &T, identity_field: &str) -> Result<String, String> {
    let mut value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    value
        .as_object_mut()
        .ok_or_else(|| "self-identified contract must serialize as an object".to_string())?
        .remove(identity_field);
    let canonical = serde_jcs::to_vec(&value).map_err(|error| error.to_string())?;
    Ok(format!("sha256:{:x}", Sha256::digest(canonical)))
}

fn require_token(field: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{field} is empty"))
    } else {
        Ok(())
    }
}

fn validate_protocol_token(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{field} is empty"));
    }
    if value.len() > 255 {
        return Err(format!("{field} exceeds the 255-byte protocol token bound"));
    }
    if value.chars().any(|character| {
        !(character.is_ascii_alphanumeric()
            || matches!(character, '.' | '_' | '-' | ':' | '/' | '@'))
    }) {
        return Err(format!(
            "{field} contains a character outside the protocol token alphabet"
        ));
    }
    Ok(())
}

fn validate_digest(value: &str, field: &str) -> Result<(), String> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(format!("{field} must use sha256:<64 lowercase hex>"));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{field} must use sha256:<64 lowercase hex>"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        validate_canonical_utc_timestamp, validate_contributing_attempt_interval,
        validate_protocol_token, AcquisitionIntervalV2, ClockQualificationV2, SemanticIdentityV1,
    };

    fn identity(id: &str) -> SemanticIdentityV1 {
        SemanticIdentityV1 {
            id: id.into(),
            version: "1".into(),
            digest: format!("sha256:{}", "a".repeat(64)),
        }
    }

    #[test]
    fn v2_timestamp_strings_must_match_the_nq_datetime_wire_form() {
        validate_canonical_utc_timestamp("2026-07-27T12:00:00Z", "timestamp").unwrap();
        validate_canonical_utc_timestamp("2026-07-27T12:00:00.125Z", "timestamp").unwrap();

        assert!(
            validate_canonical_utc_timestamp("2026-07-27T13:00:00+01:00", "timestamp").is_err()
        );
        assert!(validate_canonical_utc_timestamp("2026-07-27T12:00:00.000Z", "timestamp").is_err());
    }

    #[test]
    fn embedded_protocol_tokens_match_the_nq_newtype_alphabet() {
        validate_protocol_token("token", "nq.helper/host:1").unwrap();
        assert!(validate_protocol_token("token", "helper with spaces").is_err());
        assert!(validate_protocol_token("token", "helper+alias").is_err());
        assert!(validate_protocol_token("token", &"a".repeat(256)).is_err());
    }

    #[test]
    fn contributing_intervals_cannot_change_clock_qualification() {
        let diagnostic = AcquisitionIntervalV2 {
            started_at: "2026-07-27T12:00:00Z".into(),
            ended_at: "2026-07-27T12:00:10Z".into(),
            clock: identity("clock:execution"),
            qualification: ClockQualificationV2::Unqualified {
                code: "not_qualified".into(),
                detail: "no bound".into(),
            },
        };
        let mut contributing = diagnostic.clone();
        contributing.started_at = "2026-07-27T12:00:01Z".into();
        contributing.ended_at = "2026-07-27T12:00:09Z".into();
        validate_contributing_attempt_interval(&contributing, &diagnostic, "received").unwrap();

        contributing.qualification = ClockQualificationV2::Bounded {
            maximum_error_ms: 1,
            basis: identity("clock:basis"),
        };
        assert!(
            validate_contributing_attempt_interval(&contributing, &diagnostic, "received")
                .unwrap_err()
                .contains("changes the diagnostic clock qualification")
        );
    }
}

//! Typed, read-only operational posture over immutable NQ diagnostic artifacts.
//!
//! This module is deliberately parallel to the historical Watchbill runtime.
//! It does not reinterpret NQ's diagnostic result, persist state, prepare an
//! action, authorize anything, or execute anything.  Nightshift contributes
//! only its closed inventory, current-applicability, recurrence, delivery and
//! operator-projection assessments.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::currentness::{delivered_artifact_ids, QualifiedSupportV1, SupportStandingV1};
use crate::diagnostic_execution_v2::{
    AcquisitionInterval, DiagnosticClaim, DiagnosticExecution, DiagnosticInputFailureTrace,
    DiagnosticOutcome,
};

pub const NQ_DIAGNOSTIC_EXECUTION_SCHEMA: &str = "nq.diagnostic_execution.v1";
pub const POSTURE_POLICY_SCHEMA_V1: &str = "nightshift.diagnostic_posture_policy.v1";
pub const POSTURE_POLICY_SCHEMA_V2: &str = "nightshift.diagnostic_posture_policy.v2";
pub const POSTURE_POLICY_SCHEMA: &str = POSTURE_POLICY_SCHEMA_V2;
pub const INPUTS_SCHEMA_V1: &str = "nightshift.diagnostic_inputs.v1";
pub const INPUTS_SCHEMA_V2: &str = "nightshift.diagnostic_inputs.v2";
pub const INPUTS_SCHEMA: &str = INPUTS_SCHEMA_V2;
pub const RECURRENCE_SCHEMA_V1: &str = "nightshift.recurrence_evidence.v1";
pub const RECURRENCE_SCHEMA_V2: &str = "nightshift.recurrence_evidence.v2";
pub const RECURRENCE_SCHEMA: &str = RECURRENCE_SCHEMA_V2;
pub const POSTURE_SCHEMA: &str = "nightshift.operational_posture.v2";
pub const OPERATOR_PROJECTION_SCHEMA: &str = "nightshift.operator_projection.v2";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DiagnosticExecutionSchema {
    #[serde(rename = "nq.diagnostic_execution.v1")]
    V1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticIdentityV1 {
    pub id: String,
    pub version: String,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerV1 {
    pub node_id: String,
    pub build: SemanticIdentityV1,
    pub cohort: SemanticIdentityV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectV1 {
    pub id: String,
    pub scope: SemanticIdentityV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedInputV1 {
    pub expectation_id: String,
    pub role: String,
    pub required: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RawCaptureModeV1 {
    ExactSource,
    EarliestBoundaryRedacted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceAvailabilityV1 {
    Online,
    ArchivedRetrievable,
    CommittedUnavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceivedInputV1 {
    pub input_id: String,
    pub expectation_id: String,
    pub raw_artifact_id: String,
    pub capture_mode: RawCaptureModeV1,
    pub capture_policy: SemanticIdentityV1,
    pub availability_at_derivation: EvidenceAvailabilityV1,
    pub acquisition: AcquisitionIntervalV1,
    pub received_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedInputV1 {
    pub input_id: String,
    pub admission_rule: SemanticIdentityV1,
    pub normalized_artifact_id: String,
    pub normalization_rule: SemanticIdentityV1,
    pub projected_artifact_id: String,
    pub projection_rule: SemanticIdentityV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RefusedInputV1 {
    pub input_id: String,
    pub refusal_id: String,
    pub code: String,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailedInputKindV1 {
    Missing,
    NoResponse,
    AcquisitionFailed,
    Unsupported,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FailedInputV1 {
    pub expectation_id: String,
    pub failure_id: String,
    pub kind: FailedInputKindV1,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExcludedInputV1 {
    pub input_id: String,
    pub projected_artifact_id: String,
    pub code: String,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedInputV1 {
    pub input_id: String,
    pub projected_artifact_id: String,
    pub role: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InputAccountingV1 {
    pub selection_rule: SemanticIdentityV1,
    pub expected: Vec<ExpectedInputV1>,
    pub received: Vec<ReceivedInputV1>,
    pub admitted: Vec<AdmittedInputV1>,
    pub refused: Vec<RefusedInputV1>,
    pub failed: Vec<FailedInputV1>,
    pub excluded: Vec<ExcludedInputV1>,
    pub selected: Vec<SelectedInputV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateBindingV1 {
    pub binding_id: String,
    pub kind: String,
    pub value: String,
    pub supporting_input_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcquisitionIntervalV1 {
    pub started_at: String,
    pub ended_at: String,
    pub clock: SemanticIdentityV1,
    pub clock_uncertainty_ms: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatusV1 {
    Established,
    Refuted,
    Unknown,
    Contradictory,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimV1 {
    pub claim_id: String,
    pub proposition: String,
    pub status: ClaimStatusV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition_effect: Option<ConditionV1>,
    pub dependency_input_ids: Vec<String>,
    pub state_binding_ids: Vec<String>,
    pub required_distinctions: Vec<String>,
    pub limitations: Vec<String>,
    pub nonclaims: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivationV1 {
    Completed,
    Partial,
    Refused,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionV1 {
    Present,
    Clean,
    ExplicitlyAbsent,
    Unresolved,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoherenceV1 {
    JointlyEstablished,
    PairwiseOnly,
    Contradictory,
    StateIncompatible,
    Insufficient,
    NotEvaluated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageV1 {
    Complete,
    Partial,
    Missing,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RefusalV1 {
    pub code: String,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeV1 {
    pub derivation: DerivationV1,
    pub condition: ConditionV1,
    pub coherence: CoherenceV1,
    pub coverage: CoverageV1,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<RefusalV1>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitationKindV1 {
    ProjectionLoss,
    MissingEvidence,
    StaleEvidence,
    StateMismatch,
    Contradiction,
    CoverageGap,
    UnverifiedSeparation,
    UnavailableEvidence,
    Other,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LimitationV1 {
    pub kind: LimitationKindV1,
    pub code: String,
    pub detail: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OmittedDistinctionV1 {
    pub code: String,
    pub detail: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionV1 {
    pub identity: SemanticIdentityV1,
    pub omitted_distinctions: Vec<OmittedDistinctionV1>,
}

/// Strict mirror of NQ's immutable `nq.diagnostic_execution.v1` contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticExecutionV1 {
    pub schema: DiagnosticExecutionSchema,
    pub artifact_id: String,
    pub canonicalization: SemanticIdentityV1,
    pub producer: ProducerV1,
    pub request_id: String,
    pub run_id: String,
    pub question: SemanticIdentityV1,
    pub subject: SubjectV1,
    pub profile: SemanticIdentityV1,
    pub vantage: SemanticIdentityV1,
    pub state_model: SemanticIdentityV1,
    pub evaluator: SemanticIdentityV1,
    pub threshold_policy: SemanticIdentityV1,
    pub projection: ProjectionV1,
    pub execution_clock: SemanticIdentityV1,
    pub started_at: String,
    pub completed_at: String,
    pub attempt_interval: AcquisitionIntervalV1,
    pub inputs: InputAccountingV1,
    pub state_bindings: Vec<StateBindingV1>,
    pub claims: Vec<ClaimV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_claim_id: Option<String>,
    pub outcome: OutcomeV1,
    pub limitations: Vec<LimitationV1>,
    pub nonclaims: Vec<String>,
}

impl DiagnosticExecutionV1 {
    /// Consumer-side structural validation of the complete NQ v1 contract.
    ///
    /// This does not authenticate the producer, admit evidence, or grant
    /// Nightshift reliance.
    pub fn validate(&self) -> Result<(), String> {
        validate_digest(&self.artifact_id, "artifact_id")?;
        validate_semantic_identity(&self.canonicalization, "canonicalization")?;
        let expected_canonicalization = SemanticIdentityV1 {
            id: "rfc8785-jcs".into(),
            version: "1".into(),
            digest: "sha256:e49d92d4e86052e66ed2a481b9386d3b214ce3d2df5fd109a6491ccb9ffb24f3"
                .into(),
        };
        if self.canonicalization != expected_canonicalization {
            return Err("unknown diagnostic canonicalization identity".into());
        }
        require_token("producer.node_id", &self.producer.node_id)?;
        validate_semantic_identity(&self.producer.build, "producer.build")?;
        validate_semantic_identity(&self.producer.cohort, "producer.cohort")?;
        require_token("request_id", &self.request_id)?;
        require_token("run_id", &self.run_id)?;
        validate_semantic_identity(&self.question, "question")?;
        require_token("subject.id", &self.subject.id)?;
        validate_semantic_identity(&self.subject.scope, "subject.scope")?;
        validate_semantic_identity(&self.profile, "profile")?;
        validate_semantic_identity(&self.vantage, "vantage")?;
        validate_semantic_identity(&self.state_model, "state_model")?;
        validate_semantic_identity(&self.evaluator, "evaluator")?;
        validate_semantic_identity(&self.threshold_policy, "threshold_policy")?;
        validate_projection(&self.projection)?;
        validate_semantic_identity(&self.execution_clock, "execution_clock")?;
        let started_at = parse_nq_time(&self.started_at, "started_at")?;
        let completed_at = parse_nq_time(&self.completed_at, "completed_at")?;
        if started_at > completed_at {
            return Err("started_at is after completed_at".into());
        }
        validate_interval(&self.attempt_interval, "attempt_interval")?;
        if self.attempt_interval.clock != self.execution_clock {
            return Err("attempt interval does not use execution_clock".into());
        }
        let attempt_start = parse_time(
            &self.attempt_interval.started_at,
            "attempt_interval.started_at",
        )?;
        let attempt_end = parse_time(&self.attempt_interval.ended_at, "attempt_interval.ended_at")?;
        if attempt_start < started_at || attempt_end > completed_at {
            return Err("attempt interval falls outside diagnostic execution".into());
        }
        validate_inputs(self)?;
        validate_state_bindings(&self.state_bindings, &self.inputs)?;
        validate_claims(self)?;
        validate_outcome(self)?;
        require_utf8_byte_sorted_unique(
            "limitations",
            self.limitations
                .iter()
                .map(|limitation| limitation.code.as_str()),
        )?;
        for limitation in &self.limitations {
            require_token("limitation.code", &limitation.code)?;
            require_token("limitation.detail", &limitation.detail)?;
        }
        require_utf8_byte_sorted_unique("nonclaims", self.nonclaims.iter().map(String::as_str))?;
        for nonclaim in &self.nonclaims {
            require_token("nonclaim", nonclaim)?;
        }
        let mut value = serde_json::to_value(self).map_err(|e| e.to_string())?;
        value
            .as_object_mut()
            .expect("serialized struct is an object")
            .remove("artifact_id");
        let canonical = serde_jcs::to_vec(&value).map_err(|e| e.to_string())?;
        let expected = sha256_id(&canonical);
        if self.artifact_id != expected {
            return Err(format!(
                "NQ artifact identity mismatch: declared {}, computed {expected}",
                self.artifact_id
            ));
        }
        Ok(())
    }
}

fn validate_projection(projection: &ProjectionV1) -> Result<(), String> {
    validate_semantic_identity(&projection.identity, "projection.identity")?;
    require_utf8_byte_sorted_unique(
        "projection.omitted_distinctions",
        projection
            .omitted_distinctions
            .iter()
            .map(|distinction| distinction.code.as_str()),
    )?;
    for distinction in &projection.omitted_distinctions {
        require_token("projection.omitted_distinction.code", &distinction.code)?;
        require_token("projection.omitted_distinction.detail", &distinction.detail)?;
    }
    Ok(())
}

fn validate_inputs(artifact: &DiagnosticExecutionV1) -> Result<(), String> {
    let inputs = &artifact.inputs;
    validate_semantic_identity(&inputs.selection_rule, "inputs.selection_rule")?;
    require_utf8_byte_sorted_unique(
        "inputs.expected",
        inputs
            .expected
            .iter()
            .map(|item| item.expectation_id.as_str()),
    )?;
    let mut expected = BTreeSet::new();
    for item in &inputs.expected {
        require_token("expectation_id", &item.expectation_id)?;
        require_token("expected.role", &item.role)?;
        insert_unique(&mut expected, &item.expectation_id, "expectation_id")?;
    }

    require_utf8_byte_sorted_unique(
        "inputs.received",
        inputs.received.iter().map(|item| item.input_id.as_str()),
    )?;
    let completed_at = parse_nq_time(&artifact.completed_at, "completed_at")?;
    let mut received = BTreeMap::new();
    let mut response_count: BTreeMap<&str, usize> = BTreeMap::new();
    for item in &inputs.received {
        require_token("input_id", &item.input_id)?;
        require_token("received.expectation_id", &item.expectation_id)?;
        validate_digest(&item.raw_artifact_id, "received.raw_artifact_id")?;
        if !expected.contains(item.expectation_id.as_str()) {
            return Err("received input references an unknown expectation".into());
        }
        validate_semantic_identity(&item.capture_policy, "received.capture_policy")?;
        validate_interval(&item.acquisition, "received.acquisition")?;
        let received_at = parse_nq_time(&item.received_at, "received.received_at")?;
        if received_at > completed_at {
            return Err("received_at is later than diagnostic completion".into());
        }
        if received.insert(item.input_id.as_str(), item).is_some() {
            return Err("duplicate input_id".into());
        }
        *response_count.entry(&item.expectation_id).or_default() += 1;
    }

    require_utf8_byte_sorted_unique(
        "inputs.failed",
        inputs
            .failed
            .iter()
            .map(|item| item.expectation_id.as_str()),
    )?;
    let mut failed_expectations = BTreeSet::new();
    let mut failure_ids = BTreeSet::new();
    for item in &inputs.failed {
        require_token("failed.expectation_id", &item.expectation_id)?;
        require_token("failure_id", &item.failure_id)?;
        require_token("failed.reason", &item.reason)?;
        if !expected.contains(item.expectation_id.as_str()) {
            return Err("failed input references an unknown expectation".into());
        }
        insert_unique(
            &mut failed_expectations,
            &item.expectation_id,
            "failed expectation",
        )?;
        insert_unique(&mut failure_ids, &item.failure_id, "failure_id")?;
        *response_count.entry(&item.expectation_id).or_default() += 1;
    }
    for expectation in &expected {
        if response_count.get(expectation).copied() != Some(1) {
            return Err(
                "each expectation must have exactly one received occurrence or failure".into(),
            );
        }
    }
    validate_admission_partition(inputs, &received)
}

fn validate_admission_partition(
    inputs: &InputAccountingV1,
    received: &BTreeMap<&str, &ReceivedInputV1>,
) -> Result<(), String> {
    require_utf8_byte_sorted_unique(
        "inputs.admitted",
        inputs.admitted.iter().map(|item| item.input_id.as_str()),
    )?;
    let mut admitted = BTreeMap::new();
    for item in &inputs.admitted {
        validate_semantic_identity(&item.admission_rule, "admitted.admission_rule")?;
        validate_digest(
            &item.normalized_artifact_id,
            "admitted.normalized_artifact_id",
        )?;
        validate_semantic_identity(&item.normalization_rule, "admitted.normalization_rule")?;
        validate_digest(
            &item.projected_artifact_id,
            "admitted.projected_artifact_id",
        )?;
        validate_semantic_identity(&item.projection_rule, "admitted.projection_rule")?;
        if !received.contains_key(item.input_id.as_str()) {
            return Err("admitted input references an unknown received input".into());
        }
        if admitted.insert(item.input_id.as_str(), item).is_some() {
            return Err("duplicate admitted input".into());
        }
    }

    require_utf8_byte_sorted_unique(
        "inputs.refused",
        inputs.refused.iter().map(|item| item.input_id.as_str()),
    )?;
    let mut refused = BTreeSet::new();
    let mut refusal_ids = BTreeSet::new();
    for item in &inputs.refused {
        require_token("refused.input_id", &item.input_id)?;
        require_token("refused.refusal_id", &item.refusal_id)?;
        require_token("refused.code", &item.code)?;
        require_token("refused.reason", &item.reason)?;
        if !received.contains_key(item.input_id.as_str()) {
            return Err("refused input references an unknown received input".into());
        }
        insert_unique(&mut refused, &item.input_id, "refused input")?;
        insert_unique(&mut refusal_ids, &item.refusal_id, "refusal_id")?;
    }
    for input_id in received.keys() {
        let outcomes =
            usize::from(admitted.contains_key(input_id)) + usize::from(refused.contains(*input_id));
        if outcomes != 1 {
            return Err("each received input must be exactly admitted or refused".into());
        }
    }
    validate_selection_partition(inputs, &admitted, received)
}

fn validate_selection_partition(
    inputs: &InputAccountingV1,
    admitted: &BTreeMap<&str, &AdmittedInputV1>,
    received: &BTreeMap<&str, &ReceivedInputV1>,
) -> Result<(), String> {
    let expected: BTreeMap<&str, &ExpectedInputV1> = inputs
        .expected
        .iter()
        .map(|item| (item.expectation_id.as_str(), item))
        .collect();
    require_utf8_byte_sorted_unique(
        "inputs.selected",
        inputs.selected.iter().map(|item| item.input_id.as_str()),
    )?;
    let mut selected = BTreeMap::new();
    for item in &inputs.selected {
        require_token("selected.role", &item.role)?;
        validate_digest(
            &item.projected_artifact_id,
            "selected.projected_artifact_id",
        )?;
        let Some(admission) = admitted.get(item.input_id.as_str()) else {
            return Err("selected input is not admitted".into());
        };
        if item.projected_artifact_id != admission.projected_artifact_id {
            return Err("selected input substitutes projected identity".into());
        }
        let occurrence = received
            .get(item.input_id.as_str())
            .expect("admitted inputs were checked against received");
        let expectation = expected
            .get(occurrence.expectation_id.as_str())
            .expect("received inputs were checked against expected");
        if item.role != expectation.role {
            return Err("selected input role differs from its expected role".into());
        }
        if selected.insert(item.input_id.as_str(), item).is_some() {
            return Err("duplicate selected input".into());
        }
    }

    require_utf8_byte_sorted_unique(
        "inputs.excluded",
        inputs.excluded.iter().map(|item| item.input_id.as_str()),
    )?;
    let mut excluded = BTreeMap::new();
    for item in &inputs.excluded {
        require_token("excluded.code", &item.code)?;
        require_token("excluded.reason", &item.reason)?;
        validate_digest(
            &item.projected_artifact_id,
            "excluded.projected_artifact_id",
        )?;
        let Some(admission) = admitted.get(item.input_id.as_str()) else {
            return Err("excluded input is not admitted".into());
        };
        if item.projected_artifact_id != admission.projected_artifact_id {
            return Err("excluded input substitutes projected identity".into());
        }
        if excluded.insert(item.input_id.as_str(), item).is_some() {
            return Err("duplicate excluded input".into());
        }
    }
    for input_id in admitted.keys() {
        let outcomes = usize::from(selected.contains_key(input_id))
            + usize::from(excluded.contains_key(input_id));
        if outcomes != 1 {
            return Err("each admitted input must be exactly selected or excluded".into());
        }
    }
    Ok(())
}

fn validate_state_bindings(
    bindings: &[StateBindingV1],
    inputs: &InputAccountingV1,
) -> Result<(), String> {
    let selected: BTreeSet<&str> = inputs
        .selected
        .iter()
        .map(|item| item.input_id.as_str())
        .collect();
    require_utf8_byte_sorted_unique(
        "state_bindings",
        bindings.iter().map(|binding| binding.binding_id.as_str()),
    )?;
    let mut ids = BTreeSet::new();
    for binding in bindings {
        require_token("binding_id", &binding.binding_id)?;
        require_token("state_binding.kind", &binding.kind)?;
        require_token("state_binding.value", &binding.value)?;
        insert_unique(&mut ids, &binding.binding_id, "binding_id")?;
        if binding.supporting_input_ids.is_empty() {
            return Err("state binding has no supporting input".into());
        }
        require_utf8_byte_sorted_unique(
            "state_binding.supporting_input_ids",
            binding.supporting_input_ids.iter().map(String::as_str),
        )?;
        let mut supporting = BTreeSet::new();
        for input_id in &binding.supporting_input_ids {
            if !selected.contains(input_id.as_str()) {
                return Err("state binding references a non-selected input".into());
            }
            insert_unique(&mut supporting, input_id, "state supporting input")?;
        }
    }
    Ok(())
}

fn validate_claims(artifact: &DiagnosticExecutionV1) -> Result<(), String> {
    let selected: BTreeMap<&str, &SelectedInputV1> = artifact
        .inputs
        .selected
        .iter()
        .map(|item| (item.input_id.as_str(), item))
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
    require_utf8_byte_sorted_unique(
        "claims",
        artifact.claims.iter().map(|claim| claim.claim_id.as_str()),
    )?;
    let mut claims = BTreeSet::new();
    let mut any_contradictory = false;
    for claim in &artifact.claims {
        require_token("claim_id", &claim.claim_id)?;
        require_token("claim.proposition", &claim.proposition)?;
        insert_unique(&mut claims, &claim.claim_id, "claim_id")?;
        any_contradictory |= claim.status == ClaimStatusV1::Contradictory;
        if matches!(
            claim.status,
            ClaimStatusV1::Established | ClaimStatusV1::Refuted | ClaimStatusV1::Contradictory
        ) && claim.dependency_input_ids.is_empty()
        {
            return Err("determinate or contradictory claim has no selected dependency".into());
        }
        require_utf8_byte_sorted_unique(
            "claim.dependency_input_ids",
            claim.dependency_input_ids.iter().map(String::as_str),
        )?;
        let mut dependencies = BTreeSet::new();
        for input_id in &claim.dependency_input_ids {
            if !selected.contains_key(input_id.as_str()) {
                return Err("claim references a non-selected input".into());
            }
            insert_unique(&mut dependencies, input_id, "claim dependency")?;
        }
        require_utf8_byte_sorted_unique(
            "claim.state_binding_ids",
            claim.state_binding_ids.iter().map(String::as_str),
        )?;
        let mut state_ids = BTreeSet::new();
        for binding_id in &claim.state_binding_ids {
            let Some(binding) = bindings.get(binding_id.as_str()) else {
                return Err("claim references an unknown state binding".into());
            };
            insert_unique(&mut state_ids, binding_id, "claim state binding")?;
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
        require_utf8_byte_sorted_unique(
            "claim.required_distinctions",
            claim.required_distinctions.iter().map(String::as_str),
        )?;
        for distinction in &claim.required_distinctions {
            require_token("claim.required_distinction", distinction)?;
            if omitted_distinctions.contains(distinction.as_str()) {
                return Err("claim requires a distinction omitted by the projection".into());
            }
        }
        require_utf8_byte_sorted_unique(
            "claim.limitations",
            claim.limitations.iter().map(String::as_str),
        )?;
        for limitation in &claim.limitations {
            require_token("claim limitation", limitation)?;
        }
        require_utf8_byte_sorted_unique(
            "claim.nonclaims",
            claim.nonclaims.iter().map(String::as_str),
        )?;
        for nonclaim in &claim.nonclaims {
            require_token("claim nonclaim", nonclaim)?;
        }
        if claim.condition_effect.is_some_and(|effect| {
            matches!(
                effect,
                ConditionV1::Present
                    | ConditionV1::Clean
                    | ConditionV1::ExplicitlyAbsent
                    | ConditionV1::NotApplicable
            )
        }) && claim.status != ClaimStatusV1::Established
        {
            return Err("determinate condition effect requires an established claim".into());
        }
        if matches!(
            claim.status,
            ClaimStatusV1::Unknown | ClaimStatusV1::Contradictory | ClaimStatusV1::Refuted
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
        Some(primary) if !claims.contains(primary) => {
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
        if (primary.status == ClaimStatusV1::Contradictory)
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

fn validate_outcome(artifact: &DiagnosticExecutionV1) -> Result<(), String> {
    let outcome = &artifact.outcome;
    require_token("outcome.summary", &outcome.summary)?;
    match (&outcome.derivation, &outcome.refusal) {
        (DerivationV1::Refused, Some(refusal)) => {
            require_token("outcome.refusal.code", &refusal.code)?;
            require_token("outcome.refusal.reason", &refusal.reason)?;
        }
        (DerivationV1::Refused, None) => return Err("refused outcome has no refusal".into()),
        (_, Some(_)) => return Err("non-refused outcome carries a refusal".into()),
        (_, None) => {}
    }
    if outcome.condition == ConditionV1::ExplicitlyAbsent
        && (outcome.derivation != DerivationV1::Completed
            || outcome.coverage != CoverageV1::Complete
            || outcome.coherence != CoherenceV1::JointlyEstablished)
    {
        return Err(
            "explicit absence requires completed derivation, complete coverage, and joint coherence"
                .into(),
        );
    }
    if outcome.condition == ConditionV1::Clean
        && (outcome.derivation != DerivationV1::Completed
            || outcome.coverage != CoverageV1::Complete
            || outcome.coherence != CoherenceV1::JointlyEstablished)
    {
        return Err(
            "clean condition requires completed derivation, complete coverage, and joint coherence"
                .into(),
        );
    }
    if outcome.derivation == DerivationV1::Refused && outcome.condition != ConditionV1::Unresolved {
        return Err("refused outcome must have unresolved condition".into());
    }
    if outcome.derivation == DerivationV1::Unsupported
        && outcome.condition != ConditionV1::Unresolved
    {
        return Err("unsupported outcome must have unresolved condition".into());
    }
    if matches!(
        outcome.coherence,
        CoherenceV1::Contradictory | CoherenceV1::StateIncompatible
    ) && outcome.condition != ConditionV1::Unresolved
    {
        return Err("contradictory/state-incompatible evidence cannot clear a condition".into());
    }
    if outcome.coverage == CoverageV1::Complete {
        let received_expectations: BTreeMap<&str, &str> = artifact
            .inputs
            .received
            .iter()
            .map(|input| (input.expectation_id.as_str(), input.input_id.as_str()))
            .collect();
        let admitted: BTreeSet<&str> = artifact
            .inputs
            .admitted
            .iter()
            .map(|input| input.input_id.as_str())
            .collect();
        let selected: BTreeSet<&str> = artifact
            .inputs
            .selected
            .iter()
            .map(|input| input.input_id.as_str())
            .collect();
        let required: Vec<&ExpectedInputV1> = artifact
            .inputs
            .expected
            .iter()
            .filter(|expectation| expectation.required)
            .collect();
        if required.is_empty() {
            return Err("complete coverage has no required expectation".into());
        }
        for expectation in required {
            let Some(input_id) = received_expectations.get(expectation.expectation_id.as_str())
            else {
                return Err("complete coverage omits a required expected input".into());
            };
            if !admitted.contains(input_id) {
                return Err("complete coverage includes refused required testimony".into());
            }
            if !selected.contains(input_id) {
                return Err("complete coverage excludes required testimony".into());
            }
        }
    }
    Ok(())
}

fn validate_interval(interval: &AcquisitionIntervalV1, name: &str) -> Result<(), String> {
    validate_semantic_identity(&interval.clock, &format!("{name}.clock"))?;
    checked_milliseconds(
        interval.clock_uncertainty_ms,
        &format!("{name}.clock_uncertainty_ms"),
    )?;
    let start = parse_nq_time(&interval.started_at, &format!("{name}.started_at"))?;
    let end = parse_nq_time(&interval.ended_at, &format!("{name}.ended_at"))?;
    if start > end {
        return Err(format!("{name} ends before it starts"));
    }
    Ok(())
}

fn validate_projection_interval(interval: &AcquisitionInterval, name: &str) -> Result<(), String> {
    match interval {
        AcquisitionInterval::V1(value) => validate_interval(value, name),
        AcquisitionInterval::V2(value) => {
            validate_semantic_identity(&value.clock, &format!("{name}.clock"))?;
            let start = parse_nq_time(&value.started_at, &format!("{name}.started_at"))?;
            let end = parse_nq_time(&value.ended_at, &format!("{name}.ended_at"))?;
            if start > end {
                return Err(format!("{name} ends before it starts"));
            }
            match &value.qualification {
                crate::diagnostic_execution_v2::ClockQualificationV2::Bounded {
                    maximum_error_ms,
                    basis,
                } => {
                    checked_milliseconds(
                        *maximum_error_ms,
                        &format!("{name}.qualification.maximum_error_ms"),
                    )?;
                    validate_semantic_identity(basis, &format!("{name}.qualification.basis"))
                }
                crate::diagnostic_execution_v2::ClockQualificationV2::Unqualified {
                    code,
                    detail,
                } => {
                    require_token(&format!("{name}.qualification.code"), code)?;
                    require_token(&format!("{name}.qualification.detail"), detail)
                }
            }
        }
    }
}

fn require_token(field: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{field} is empty"))
    } else {
        Ok(())
    }
}

fn insert_unique<'a>(
    values: &mut BTreeSet<&'a str>,
    value: &'a str,
    field: &str,
) -> Result<(), String> {
    if values.insert(value) {
        Ok(())
    } else {
        Err(format!("duplicate {field}"))
    }
}

fn require_utf8_byte_sorted_unique<'a>(
    field: &str,
    values: impl IntoIterator<Item = &'a str>,
) -> Result<(), String> {
    let mut previous: Option<&str> = None;
    for value in values {
        if previous.is_some_and(|prior| prior.as_bytes() >= value.as_bytes()) {
            return Err(format!(
                "{field} must be strictly ordered by unsigned UTF-8 bytes and unique"
            ));
        }
        previous = Some(value);
    }
    Ok(())
}

fn validate_semantic_identity(identity: &SemanticIdentityV1, name: &str) -> Result<(), String> {
    if identity.id.trim().is_empty() || identity.version.trim().is_empty() {
        return Err(format!("{name} id and version must be non-empty"));
    }
    validate_digest(&identity.digest, &format!("{name}.digest"))
}

fn validate_digest(value: &str, name: &str) -> Result<(), String> {
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

fn parse_time(value: &str, name: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| format!("{name} must be RFC3339: {error}"))
}

fn parse_nq_time(value: &str, name: &str) -> Result<DateTime<Utc>, String> {
    let parsed = parse_time(value, name)?;
    let canonical = parsed.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true);
    if value != canonical {
        return Err(format!(
            "{name} is not the canonical UTC representation emitted by the NQ v1 DateTime contract"
        ));
    }
    Ok(parsed)
}

fn sha256_id(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn computed_object_id<T: Serialize>(value: &T, identity_field: &str) -> Result<String, String> {
    let mut value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    value
        .as_object_mut()
        .ok_or_else(|| "self-identified contract must serialize as an object".to_string())?
        .remove(identity_field);
    let canonical = serde_jcs::to_vec(&value).map_err(|error| error.to_string())?;
    Ok(sha256_id(&canonical))
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticKey {
    pub question_id: String,
    pub subject_id: String,
    pub profile_id: String,
    pub vantage_id: String,
}

impl DiagnosticKey {
    fn validate(&self, field: &str) -> Result<(), String> {
        require_token(&format!("{field}.question_id"), &self.question_id)?;
        require_token(&format!("{field}.subject_id"), &self.subject_id)?;
        require_token(&format!("{field}.profile_id"), &self.profile_id)?;
        require_token(&format!("{field}.vantage_id"), &self.vantage_id)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Requirement {
    Mandatory,
    Optional,
    Excluded,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredStateBinding {
    pub kind: String,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContractBinding {
    pub producer_node_id: String,
    pub producer_build: SemanticIdentityV1,
    pub producer_cohort: SemanticIdentityV1,
    pub question: SemanticIdentityV1,
    pub profile: SemanticIdentityV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_semantic_id: Option<String>,
    pub vantage: SemanticIdentityV1,
    pub state_model: SemanticIdentityV1,
    pub evaluator: SemanticIdentityV1,
    pub threshold_policy: SemanticIdentityV1,
    pub projection: ProjectionV1,
    pub subject: SubjectV1,
    pub claim_id: String,
}

impl ContractBinding {
    fn key(&self) -> DiagnosticKey {
        DiagnosticKey {
            question_id: self.question.id.clone(),
            subject_id: self.subject.id.clone(),
            profile_id: self.profile.id.clone(),
            vantage_id: self.vantage.id.clone(),
        }
    }

    fn matches(&self, artifact: &DiagnosticExecution) -> bool {
        self.producer_node_id == artifact.producer().node_id
            && self.producer_build == artifact.producer().build
            && self.producer_cohort == artifact.producer().cohort
            && self.question == *artifact.question()
            && self.profile == *artifact.profile()
            && self.profile_semantic_id.as_deref() == artifact.profile_semantic_id()
            && self.vantage == *artifact.vantage()
            && self.state_model == *artifact.state_model()
            && self.evaluator == *artifact.evaluator()
            && self.threshold_policy == *artifact.threshold_policy()
            && self.projection == *artifact.projection()
            && self.subject == *artifact.subject()
    }

    fn validate(&self) -> Result<(), String> {
        require_token("binding.producer_node_id", &self.producer_node_id)?;
        for (name, identity) in [
            ("binding.producer_build", &self.producer_build),
            ("binding.producer_cohort", &self.producer_cohort),
            ("binding.question", &self.question),
            ("binding.profile", &self.profile),
            ("binding.vantage", &self.vantage),
            ("binding.state_model", &self.state_model),
            ("binding.evaluator", &self.evaluator),
            ("binding.threshold_policy", &self.threshold_policy),
            ("binding.subject.scope", &self.subject.scope),
        ] {
            validate_semantic_identity(identity, name)?;
        }
        if let Some(profile_semantic_id) = &self.profile_semantic_id {
            validate_digest(profile_semantic_id, "binding.profile_semantic_id")?;
        }
        validate_projection(&self.projection)?;
        require_token("binding.subject.id", &self.subject.id)?;
        require_token("binding.claim_id", &self.claim_id)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryEntry {
    pub binding: ContractBinding,
    pub requirement: Requirement,
    pub required_state_bindings: Vec<RequiredStateBinding>,
    pub max_age_seconds: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStanding {
    Qualified,
    PartialDelivery,
    Failed,
    NotConfigured,
    NotRequired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PosturePolicy {
    pub schema: String,
    pub policy_id: String,
    pub generation: String,
    pub subject: SubjectV1,
    pub role: SemanticIdentityV1,
    pub delivery_required: bool,
    pub inventory: Vec<InventoryEntry>,
}

impl PosturePolicy {
    pub fn computed_policy_id(&self) -> Result<String, String> {
        computed_object_id(self, "policy_id")
    }

    pub fn validate(&self) -> Result<(), String> {
        if !matches!(
            self.schema.as_str(),
            POSTURE_POLICY_SCHEMA_V1 | POSTURE_POLICY_SCHEMA_V2
        ) {
            return Err(format!(
                "policy schema must be {POSTURE_POLICY_SCHEMA_V1} or {POSTURE_POLICY_SCHEMA_V2}, got {}",
                self.schema
            ));
        }
        validate_digest(&self.policy_id, "policy_id")?;
        require_token("generation", &self.generation)?;
        if self.subject.id.trim().is_empty() {
            return Err("policy subject id must be non-empty".into());
        }
        validate_semantic_identity(&self.subject.scope, "policy.subject.scope")?;
        validate_semantic_identity(&self.role, "policy.role")?;
        if !self
            .inventory
            .iter()
            .any(|entry| entry.requirement == Requirement::Mandatory)
        {
            return Err("closed inventory must contain at least one mandatory entry".into());
        }
        let mut keys = BTreeSet::new();
        let mut previous_key: Option<DiagnosticKey> = None;
        for entry in &self.inventory {
            entry.binding.validate()?;
            if self.schema == POSTURE_POLICY_SCHEMA_V1
                && entry.binding.profile_semantic_id.is_some()
            {
                return Err(
                    "diagnostic_posture_policy.v1 cannot bind a v2 profile semantic identity"
                        .into(),
                );
            }
            if entry.binding.subject != self.subject {
                return Err(format!(
                    "inventory entry {:?} does not bind the policy subject",
                    entry.binding.key()
                ));
            }
            if !keys.insert(entry.binding.key()) {
                return Err(format!(
                    "duplicate closed-inventory key {:?}",
                    entry.binding.key()
                ));
            }
            let key = entry.binding.key();
            if previous_key
                .as_ref()
                .is_some_and(|previous| previous >= &key)
            {
                return Err(
                    "closed inventory must be strictly ordered by diagnostic key and unique".into(),
                );
            }
            previous_key = Some(key);
            if entry.requirement != Requirement::Excluded && entry.max_age_seconds == 0 {
                return Err(format!(
                    "inventory entry {:?} max_age_seconds must be positive",
                    entry.binding.key()
                ));
            }
            checked_seconds(entry.max_age_seconds, "inventory max_age_seconds")?;
            let mut previous_state: Option<(&str, &str)> = None;
            for binding in &entry.required_state_bindings {
                require_token("required_state_binding.kind", &binding.kind)?;
                require_token("required_state_binding.value", &binding.value)?;
                let current = (binding.kind.as_str(), binding.value.as_str());
                if previous_state.is_some_and(|previous| previous >= current) {
                    return Err(
                        "required_state_bindings must be strictly ordered and unique".into(),
                    );
                }
                previous_state = Some(current);
            }
        }
        if self.policy_id != self.computed_policy_id()? {
            return Err("policy_id does not match the canonical policy preimage".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum DiagnosticInputStatus {
    Delivered { artifact: Box<DiagnosticExecution> },
    NoResponse,
    AcquisitionFailed { reason: String },
    NotConfigured,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiagnosticInput {
    pub key: DiagnosticKey,
    #[serde(flatten)]
    pub status: DiagnosticInputStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticInputs {
    pub schema: String,
    pub inputs_id: String,
    pub inputs: Vec<DiagnosticInput>,
}

impl DiagnosticInputs {
    pub fn computed_inputs_id(&self) -> Result<String, String> {
        computed_object_id(self, "inputs_id")
    }

    pub fn validate(&self) -> Result<(), String> {
        if !matches!(self.schema.as_str(), INPUTS_SCHEMA_V1 | INPUTS_SCHEMA_V2) {
            return Err(format!(
                "inputs schema must be {INPUTS_SCHEMA_V1} or {INPUTS_SCHEMA_V2}, got {}",
                self.schema
            ));
        }
        for input in &self.inputs {
            input.key.validate("input.key")?;
            match &input.status {
                DiagnosticInputStatus::Delivered { artifact } => {
                    artifact.validate()?;
                    if self.schema == INPUTS_SCHEMA_V1
                        && artifact.schema_name()
                            != crate::diagnostic_posture::NQ_DIAGNOSTIC_EXECUTION_SCHEMA
                    {
                        return Err("diagnostic_inputs.v1 cannot carry an NQ v2 artifact".into());
                    }
                }
                DiagnosticInputStatus::AcquisitionFailed { reason } => {
                    require_token("input.acquisition_failed.reason", reason)?;
                }
                DiagnosticInputStatus::NoResponse | DiagnosticInputStatus::NotConfigured => {}
            }
        }
        validate_digest(&self.inputs_id, "inputs_id")?;
        if self.inputs_id != self.computed_inputs_id()? {
            return Err("inputs_id does not match the canonical receiver-input preimage".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Standing {
    Current,
    SupportExpired,
    SupportUnknown,
    SupportUnsupported,
    SupportContradictory,
    SupportBlind,
    ClockUnqualified,
    FutureDated,
    Stale,
    StateMismatch,
    BindingMismatch,
    NoResponse,
    AcquisitionFailed,
    NotConfigured,
    Missing,
    DuplicateInput,
    Excluded,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorStatus {
    Clean,
    ConditionPresent,
    ExplicitlyAbsent,
    PartialEvidence,
    Refused,
    Unsupported,
    Contradictory,
    PairwiseOnly,
    StateIncompatible,
    InsufficientCoherence,
    CoverageNarrowed,
    CoverageMissing,
    Unknown,
    NotApplicable,
    ClockUnqualified,
    Stale,
    FutureDated,
    StateMismatch,
    BindingMismatch,
    NoResponse,
    AcquisitionFailed,
    NotConfigured,
    Missing,
    DuplicateInput,
    Excluded,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRef {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_schema: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_semantic_id: Option<String>,
    pub artifact_id: String,
    pub request_id: String,
    pub run_id: String,
    pub attempt_interval: AcquisitionInterval,
    pub key: DiagnosticKey,
    pub claim_id: Option<String>,
    pub claim: Option<DiagnosticClaim>,
    pub dependency_acquisitions: Vec<AcquisitionInterval>,
}

impl ArtifactRef {
    fn effective_contract_schema(&self) -> Result<&'static str, String> {
        let inferred = self.attempt_interval.schema_name();
        if self
            .dependency_acquisitions
            .iter()
            .any(|interval| interval.schema_name() != inferred)
            || self
                .claim
                .as_ref()
                .is_some_and(|claim| claim.schema_name() != inferred)
        {
            return Err(
                "artifact reference mixes fields from incompatible NQ contract schemas".into(),
            );
        }
        if let Some(declared) = &self.contract_schema {
            if declared != inferred {
                return Err(
                    "artifact reference contract_schema does not match its typed fields".into(),
                );
            }
        } else if inferred != NQ_DIAGNOSTIC_EXECUTION_SCHEMA {
            return Err(
                "v2 artifact reference requires an explicit contract_schema binding".into(),
            );
        }
        match (inferred, self.profile_semantic_id.as_deref()) {
            (NQ_DIAGNOSTIC_EXECUTION_SCHEMA, None) => {}
            (crate::diagnostic_execution_v2::NQ_DIAGNOSTIC_EXECUTION_V2_SCHEMA, Some(value)) => {
                validate_digest(value, "artifact.profile_semantic_id")?;
            }
            (NQ_DIAGNOSTIC_EXECUTION_SCHEMA, Some(_)) => {
                return Err(
                    "v1 artifact reference cannot carry a v2 profile semantic identity".into(),
                );
            }
            (crate::diagnostic_execution_v2::NQ_DIAGNOSTIC_EXECUTION_V2_SCHEMA, None) => {
                return Err(
                    "v2 artifact reference requires the exact profile semantic identity".into(),
                );
            }
            _ => unreachable!("artifact reference schema is closed"),
        }
        Ok(inferred)
    }

    fn validate(&self) -> Result<(), String> {
        if let Some(schema) = &self.contract_schema {
            if !matches!(
                schema.as_str(),
                NQ_DIAGNOSTIC_EXECUTION_SCHEMA
                    | crate::diagnostic_execution_v2::NQ_DIAGNOSTIC_EXECUTION_V2_SCHEMA
            ) {
                return Err("artifact reference carries an unknown NQ contract schema".into());
            }
        }
        self.effective_contract_schema()?;
        validate_digest(&self.artifact_id, "artifact.artifact_id")?;
        require_token("artifact.request_id", &self.request_id)?;
        require_token("artifact.run_id", &self.run_id)?;
        self.key.validate("artifact.key")?;
        if self
            .claim_id
            .as_ref()
            .is_some_and(|id| id.trim().is_empty())
        {
            return Err("artifact.claim_id is empty".into());
        }
        if self.claim.as_ref().map(DiagnosticClaim::claim_id) != self.claim_id.as_deref() {
            return Err("artifact claim and claim_id differ".into());
        }
        validate_projection_interval(&self.attempt_interval, "artifact.attempt_interval")?;
        for interval in &self.dependency_acquisitions {
            validate_projection_interval(interval, "artifact.dependency_acquisition")?;
        }
        Ok(())
    }
}

fn artifact_refs_match(expected: &ArtifactRef, actual: &ArtifactRef) -> bool {
    if expected == actual {
        return true;
    }
    let (Ok(expected_schema), Ok(actual_schema)) = (
        expected.effective_contract_schema(),
        actual.effective_contract_schema(),
    ) else {
        return false;
    };
    if expected_schema != actual_schema {
        return false;
    }
    let mut expected = expected.clone();
    let mut actual = actual.clone();
    expected.contract_schema = Some(expected_schema.to_owned());
    actual.contract_schema = Some(actual_schema.to_owned());
    expected == actual
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NqClaimTrace {
    pub artifact_id: String,
    pub evaluator: SemanticIdentityV1,
    pub threshold_policy: SemanticIdentityV1,
    pub projection: ProjectionV1,
    pub primary_claim: Option<DiagnosticClaim>,
    pub primary_state_bindings: Vec<StateBindingV1>,
    pub outcome: DiagnosticOutcome,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub input_failures: Vec<DiagnosticInputFailureTrace>,
    pub limitations: Vec<LimitationV1>,
    pub nonclaims: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EntryAssessment {
    pub key: DiagnosticKey,
    pub requirement: Requirement,
    pub standing: Standing,
    pub status: OperatorStatus,
    pub artifact: Option<ArtifactRef>,
    pub nq_trace: Option<NqClaimTrace>,
    pub reason: String,
}

fn artifact_ref(artifact: &DiagnosticExecution) -> ArtifactRef {
    let claim = artifact
        .primary_claim_id()
        .and_then(|claim_id| artifact.claim(claim_id));
    let dependency_acquisitions =
        dependency_acquisitions(artifact, claim.as_ref()).unwrap_or_else(|_| Vec::new());
    ArtifactRef {
        contract_schema: Some(artifact.schema_name().into()),
        profile_semantic_id: artifact.profile_semantic_id().map(ToOwned::to_owned),
        artifact_id: artifact.artifact_id().to_owned(),
        request_id: artifact.request_id().to_owned(),
        run_id: artifact.run_id().to_owned(),
        attempt_interval: artifact.attempt_interval(),
        key: artifact.key(),
        claim_id: claim.as_ref().map(|claim| claim.claim_id().to_owned()),
        claim,
        dependency_acquisitions,
    }
}

fn nq_claim_trace(artifact: &DiagnosticExecution) -> NqClaimTrace {
    let primary_claim = artifact
        .primary_claim_id()
        .and_then(|claim_id| artifact.claim(claim_id));
    let primary_state_bindings = primary_claim
        .as_ref()
        .map(|claim| {
            claim
                .state_binding_ids()
                .iter()
                .filter_map(|binding_id| {
                    artifact
                        .state_bindings()
                        .iter()
                        .find(|binding| binding.binding_id == *binding_id)
                        .cloned()
                })
                .collect()
        })
        .unwrap_or_default();
    NqClaimTrace {
        artifact_id: artifact.artifact_id().to_owned(),
        evaluator: artifact.evaluator().clone(),
        threshold_policy: artifact.threshold_policy().clone(),
        projection: artifact.projection().clone(),
        primary_claim,
        primary_state_bindings,
        outcome: artifact.outcome(),
        input_failures: artifact.input_failure_traces(),
        limitations: artifact.limitations().to_vec(),
        nonclaims: artifact.nonclaims().to_vec(),
    }
}

fn status_from_artifact(artifact: &DiagnosticExecution) -> OperatorStatus {
    match artifact.outcome_derivation() {
        DerivationV1::Partial => OperatorStatus::PartialEvidence,
        DerivationV1::Refused => OperatorStatus::Refused,
        DerivationV1::Unsupported => OperatorStatus::Unsupported,
        DerivationV1::Completed => match artifact.outcome_coherence() {
            CoherenceV1::Contradictory => OperatorStatus::Contradictory,
            CoherenceV1::PairwiseOnly => OperatorStatus::PairwiseOnly,
            CoherenceV1::StateIncompatible => OperatorStatus::StateIncompatible,
            CoherenceV1::Insufficient | CoherenceV1::NotEvaluated => {
                OperatorStatus::InsufficientCoherence
            }
            CoherenceV1::JointlyEstablished => match artifact.outcome_coverage() {
                CoverageV1::Partial => OperatorStatus::CoverageNarrowed,
                CoverageV1::Missing => OperatorStatus::CoverageMissing,
                CoverageV1::Complete => match artifact.outcome_condition() {
                    ConditionV1::Present => OperatorStatus::ConditionPresent,
                    ConditionV1::Clean => OperatorStatus::Clean,
                    ConditionV1::ExplicitlyAbsent => OperatorStatus::ExplicitlyAbsent,
                    ConditionV1::Unresolved => OperatorStatus::Unknown,
                    ConditionV1::NotApplicable => OperatorStatus::NotApplicable,
                },
            },
        },
    }
}

fn primary_claim_for(
    entry: &InventoryEntry,
    artifact: &DiagnosticExecution,
) -> Result<Option<DiagnosticClaim>, String> {
    let Some(primary_claim_id) = artifact.primary_claim_id() else {
        return if matches!(
            artifact.outcome_derivation(),
            DerivationV1::Refused | DerivationV1::Unsupported
        ) {
            Ok(None)
        } else {
            Err("non-refused diagnostic has no primary_claim_id".into())
        };
    };
    if primary_claim_id != entry.binding.claim_id {
        return Err(format!(
            "primary claim {primary_claim_id} does not match required claim {}",
            entry.binding.claim_id
        ));
    }
    let claim = artifact
        .claim(primary_claim_id)
        .ok_or_else(|| "primary claim is absent from the exported claim surface".to_string())?;
    if artifact.claim_count(primary_claim_id) > 1 {
        Err("primary claim is duplicated".into())
    } else {
        Ok(Some(claim))
    }
}

fn dependency_acquisitions(
    artifact: &DiagnosticExecution,
    claim: Option<&DiagnosticClaim>,
) -> Result<Vec<AcquisitionInterval>, String> {
    let Some(claim) = claim else {
        return Ok(Vec::new());
    };
    let mut intervals = Vec::with_capacity(claim.dependency_input_ids().len());
    for input_id in claim.dependency_input_ids() {
        let interval = artifact
            .received_acquisition(input_id)
            .ok_or_else(|| format!("primary claim dependency {input_id} has no received input"))?;
        intervals.push(interval);
    }
    for refusal_id in claim.dependency_refusal_ids() {
        let interval = artifact.refusal_acquisition(refusal_id).ok_or_else(|| {
            format!("primary claim dependency {refusal_id} has no refused-input acquisition")
        })?;
        intervals.push(interval);
    }
    for failure_id in claim.dependency_failure_ids() {
        if let Some(interval) = artifact.failure_acquisition(failure_id) {
            intervals.push(interval);
        } else if !artifact.has_failure_id(failure_id) {
            return Err(format!(
                "primary claim dependency {failure_id} has no failed input"
            ));
        }
    }
    Ok(intervals)
}

fn claim_state_bindings(
    artifact: &DiagnosticExecution,
    claim: &DiagnosticClaim,
) -> Option<BTreeSet<(String, String)>> {
    let by_id: BTreeMap<_, _> = artifact
        .state_bindings()
        .iter()
        .map(|binding| (binding.binding_id.as_str(), binding))
        .collect();
    claim
        .state_binding_ids()
        .iter()
        .map(|id| {
            by_id
                .get(id.as_str())
                .map(|binding| (binding.kind.clone(), binding.value.clone()))
        })
        .collect()
}

fn expected_state_bindings(entry: &InventoryEntry) -> BTreeSet<(String, String)> {
    entry
        .required_state_bindings
        .iter()
        .map(|binding| (binding.kind.clone(), binding.value.clone()))
        .collect()
}

fn assess_delivered(
    entry: &InventoryEntry,
    evaluated_at: DateTime<Utc>,
    artifact: &DiagnosticExecution,
    qualified_support: Option<&QualifiedSupportV1>,
) -> EntryAssessment {
    let key = entry.binding.key();
    let reference = Some(artifact_ref(artifact));
    let trace = Some(nq_claim_trace(artifact));
    let claim = match primary_claim_for(entry, artifact) {
        Ok(claim) => claim,
        Err(reason) => {
            return EntryAssessment {
                key,
                requirement: entry.requirement,
                standing: Standing::BindingMismatch,
                status: OperatorStatus::BindingMismatch,
                artifact: reference,
                nq_trace: trace,
                reason,
            }
        }
    };
    let intervals = match dependency_acquisitions(artifact, claim.as_ref()) {
        Ok(intervals) => intervals,
        Err(reason) => {
            return EntryAssessment {
                key,
                requirement: entry.requirement,
                standing: Standing::BindingMismatch,
                status: OperatorStatus::BindingMismatch,
                artifact: reference,
                nq_trace: trace,
                reason,
            }
        }
    };
    if !entry.binding.matches(artifact) {
        return EntryAssessment {
            key,
            requirement: entry.requirement,
            standing: Standing::BindingMismatch,
            status: OperatorStatus::BindingMismatch,
            artifact: reference.clone(),
            nq_trace: trace.clone(),
            reason:
                "delivered artifact does not match the exact declared producer/semantic binding"
                    .into(),
        };
    }
    if let Some(claim) = &claim {
        let Some(actual_states) = claim_state_bindings(artifact, claim) else {
            return EntryAssessment {
                key,
                requirement: entry.requirement,
                standing: Standing::BindingMismatch,
                status: OperatorStatus::BindingMismatch,
                artifact: reference.clone(),
                nq_trace: trace.clone(),
                reason: "claim references an unknown or duplicate state binding".into(),
            };
        };
        if actual_states != expected_state_bindings(entry) {
            return EntryAssessment {
                key,
                requirement: entry.requirement,
                standing: Standing::StateMismatch,
                status: OperatorStatus::StateMismatch,
                artifact: reference.clone(),
                nq_trace: trace.clone(),
                reason: "claim state bindings do not exactly match the inventory obligation".into(),
            };
        }
    }
    if let Some(support) = qualified_support {
        let (standing, status, reason) = match support.standing {
            SupportStandingV1::Current => (
                Standing::Current,
                status_from_artifact(artifact),
                "the exact diagnostic basis has authority-owned present support",
            ),
            SupportStandingV1::Expired => (
                Standing::SupportExpired,
                OperatorStatus::Stale,
                "the evidence authority reports support expired",
            ),
            SupportStandingV1::Unknown => (
                Standing::SupportUnknown,
                OperatorStatus::Unknown,
                "present support is unknown",
            ),
            SupportStandingV1::Unsupported => (
                Standing::SupportUnsupported,
                OperatorStatus::Unsupported,
                "the evidence authority reports the basis unsupported",
            ),
            SupportStandingV1::Contradictory => (
                Standing::SupportContradictory,
                OperatorStatus::Contradictory,
                "the evidence authority retains unresolved contradiction custody",
            ),
            SupportStandingV1::Blind => (
                Standing::SupportBlind,
                OperatorStatus::Unknown,
                "the evidence authority reports receiver blindness",
            ),
        };
        return EntryAssessment {
            key,
            requirement: entry.requirement,
            standing,
            status,
            artifact: reference,
            nq_trace: trace,
            reason: format!("{reason} (support {})", support.support_id),
        };
    }
    let attempt_fallback;
    let freshness_intervals: &[AcquisitionInterval] = if intervals.is_empty() {
        // Missing/refused/unsupported/unknown testimony has no source interval
        // that Nightshift may invent. Its attributable NQ attempt may still
        // age as an operational result, while the row remains non-clean.
        attempt_fallback = vec![artifact.attempt_interval()];
        &attempt_fallback
    } else {
        &intervals
    };
    let invalid_time = |reason: String| EntryAssessment {
        key: key.clone(),
        requirement: entry.requirement,
        standing: Standing::BindingMismatch,
        status: OperatorStatus::BindingMismatch,
        artifact: reference.clone(),
        nq_trace: trace.clone(),
        reason,
    };
    let max_age = match checked_seconds(entry.max_age_seconds, "inventory max_age_seconds") {
        Ok(value) => value,
        Err(reason) => return invalid_time(reason),
    };
    if artifact.v1_has_unqualified_clock_limitation() {
        return EntryAssessment {
            key,
            requirement: entry.requirement,
            standing: Standing::ClockUnqualified,
            status: clock_unqualified_status(artifact),
            artifact: reference,
            nq_trace: trace,
            reason: "NQ v1 explicitly reports absolute clock quality as unqualified".into(),
        };
    }
    for interval in std::iter::once(artifact.attempt_interval()).chain(intervals.iter().cloned()) {
        if let Some((code, detail)) = interval.unqualified_reason() {
            return EntryAssessment {
                key,
                requirement: entry.requirement,
                standing: Standing::ClockUnqualified,
                status: clock_unqualified_status(artifact),
                artifact: reference,
                nq_trace: trace,
                reason: format!(
                    "a verdict-relevant NQ or dependency clock is unqualified ({code}): {detail}"
                ),
            };
        }
    }
    if artifact.schema_name() == crate::diagnostic_execution_v2::NQ_DIAGNOSTIC_EXECUTION_V2_SCHEMA {
        return EntryAssessment {
            key,
            requirement: entry.requirement,
            standing: Standing::ClockUnqualified,
            status: clock_unqualified_status(artifact),
            artifact: reference,
            nq_trace: trace,
            reason: "the Nightshift evaluation instant has no identified, qualified clock or admitted comparison relation; v2 source freshness is not established"
                .into(),
        };
    }
    for interval in freshness_intervals {
        let start = match parse_nq_time(interval.started_at(), "dependency.acquisition.started_at")
        {
            Ok(value) => value,
            Err(reason) => return invalid_time(reason),
        };
        let end = match parse_nq_time(interval.ended_at(), "dependency.acquisition.ended_at") {
            Ok(value) => value,
            Err(reason) => return invalid_time(reason),
        };
        let maximum_error_ms = interval
            .maximum_error_ms()
            .expect("unqualified verdict-relevant intervals were rejected above");
        let uncertainty = match checked_milliseconds(maximum_error_ms, "clock maximum error") {
            Ok(value) => value,
            Err(reason) => return invalid_time(reason),
        };
        let latest = match end.checked_add_signed(uncertainty) {
            Some(value) => value,
            None => return invalid_time("clock-uncertainty addition overflow".into()),
        };
        if latest > evaluated_at {
            return EntryAssessment {
                key,
                requirement: entry.requirement,
                standing: Standing::FutureDated,
                status: OperatorStatus::FutureDated,
                artifact: reference,
                nq_trace: trace,
                reason: "at least one exact dependency interval (including its own clock uncertainty) extends beyond evaluation time".into(),
            };
        }
        let earliest = match start.checked_sub_signed(uncertainty) {
            Some(value) => value,
            None => return invalid_time("clock-uncertainty subtraction overflow".into()),
        };
        let freshness_boundary = match earliest.checked_add_signed(max_age) {
            Some(value) => value,
            None => return invalid_time("freshness-boundary arithmetic overflow".into()),
        };
        if freshness_boundary < evaluated_at {
            return EntryAssessment {
                key,
                requirement: entry.requirement,
                standing: Standing::Stale,
                status: OperatorStatus::Stale,
                artifact: reference,
                nq_trace: trace,
                reason: "at least one exact dependency interval exceeds the declared maximum age"
                    .into(),
            };
        }
    }
    EntryAssessment {
        key,
        requirement: entry.requirement,
        standing: Standing::Current,
        status: status_from_artifact(artifact),
        artifact: reference,
        nq_trace: trace,
        reason: "exact binding and current-applicability checks passed".into(),
    }
}

fn clock_unqualified_status(artifact: &DiagnosticExecution) -> OperatorStatus {
    match status_from_artifact(artifact) {
        status @ (OperatorStatus::Refused
        | OperatorStatus::Unsupported
        | OperatorStatus::PartialEvidence
        | OperatorStatus::Contradictory
        | OperatorStatus::StateIncompatible
        | OperatorStatus::InsufficientCoherence) => status,
        _ => OperatorStatus::ClockUnqualified,
    }
}

fn assess_entry(
    entry: &InventoryEntry,
    evaluated_at: DateTime<Utc>,
    inputs: &[DiagnosticInput],
    qualified_support: Option<&QualifiedSupportV1>,
) -> EntryAssessment {
    let key = entry.binding.key();
    if entry.requirement == Requirement::Excluded {
        return EntryAssessment {
            key,
            requirement: entry.requirement,
            standing: Standing::Excluded,
            status: OperatorStatus::Excluded,
            artifact: None,
            nq_trace: None,
            reason: "inventory policy explicitly excludes this diagnostic".into(),
        };
    }
    let matching: Vec<_> = inputs.iter().filter(|input| input.key == key).collect();
    match matching.as_slice() {
        [] => EntryAssessment {
            key,
            requirement: entry.requirement,
            standing: Standing::Missing,
            status: OperatorStatus::Missing,
            artifact: None,
            nq_trace: None,
            reason: "no receiver-side input record exists for the required diagnostic".into(),
        },
        [input] => match &input.status {
            DiagnosticInputStatus::Delivered { artifact } => {
                assess_delivered(entry, evaluated_at, artifact, qualified_support)
            }
            DiagnosticInputStatus::NoResponse => EntryAssessment {
                key,
                requirement: entry.requirement,
                standing: Standing::NoResponse,
                status: OperatorStatus::NoResponse,
                artifact: None,
                nq_trace: None,
                reason: "Nightshift received no response; this is not an NQ refusal".into(),
            },
            DiagnosticInputStatus::AcquisitionFailed { reason } => EntryAssessment {
                key,
                requirement: entry.requirement,
                standing: Standing::AcquisitionFailed,
                status: OperatorStatus::AcquisitionFailed,
                artifact: None,
                nq_trace: None,
                reason: format!("receiver-side acquisition failed: {reason}"),
            },
            DiagnosticInputStatus::NotConfigured => EntryAssessment {
                key,
                requirement: entry.requirement,
                standing: Standing::NotConfigured,
                status: OperatorStatus::NotConfigured,
                artifact: None,
                nq_trace: None,
                reason: "the diagnostic input is not configured".into(),
            },
        },
        _ => EntryAssessment {
            key,
            requirement: entry.requirement,
            standing: Standing::DuplicateInput,
            status: OperatorStatus::DuplicateInput,
            artifact: None,
            nq_trace: None,
            reason: "more than one input record matched one closed-inventory key".into(),
        },
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulePolicy {
    pub schedule_id: String,
    pub first_due_at: String,
    pub cadence_seconds: u64,
    pub jitter_bound_seconds: u64,
    pub max_execution_budget_seconds: u64,
    pub standing_window_seconds: u64,
}

impl SchedulePolicy {
    fn validate(&self) -> Result<(), String> {
        if self.schedule_id.trim().is_empty() {
            return Err("schedule_id must be non-empty".into());
        }
        parse_time(&self.first_due_at, "schedule.first_due_at")?;
        if self.cadence_seconds == 0
            || self.max_execution_budget_seconds == 0
            || self.standing_window_seconds == 0
        {
            return Err(
                "cadence_seconds, max_execution_budget_seconds, and standing_window_seconds must be positive"
                    .into(),
            );
        }
        checked_seconds(self.cadence_seconds, "schedule cadence_seconds")?;
        checked_seconds(self.jitter_bound_seconds, "schedule jitter_bound_seconds")?;
        checked_seconds(
            self.max_execution_budget_seconds,
            "schedule max_execution_budget_seconds",
        )?;
        checked_seconds(
            self.standing_window_seconds,
            "schedule standing_window_seconds",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleObligation {
    pub key: DiagnosticKey,
    pub policy: SchedulePolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunSlot {
    pub slot_id: String,
    pub schedule_id: String,
    pub occurrence: u64,
    pub key: DiagnosticKey,
    pub due_at: String,
    pub budget_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationAttempt {
    pub attempt_id: String,
    pub slot_id: String,
    pub request_id: String,
    pub started_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RunSlotEvidence {
    Completed {
        attempt: InvocationAttempt,
        completed_at: String,
        artifact: Box<ArtifactRef>,
    },
    Active {
        attempt: InvocationAttempt,
    },
    Blocked {
        reason: String,
    },
    Missed {
        reason: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecurrenceRecord {
    pub key: DiagnosticKey,
    pub policy: SchedulePolicy,
    pub slot: RunSlot,
    pub evidence: RunSlotEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecurrenceEvidence {
    pub schema: String,
    pub recurrence_id: String,
    pub obligations: Vec<ScheduleObligation>,
    pub records: Vec<RecurrenceRecord>,
    pub delivery: DeliveryStanding,
}

impl RecurrenceEvidence {
    pub fn computed_recurrence_id(&self) -> Result<String, String> {
        computed_object_id(self, "recurrence_id")
    }

    pub fn validate(&self) -> Result<(), String> {
        if !matches!(
            self.schema.as_str(),
            RECURRENCE_SCHEMA_V1 | RECURRENCE_SCHEMA_V2
        ) {
            return Err(format!(
                "recurrence schema must be {RECURRENCE_SCHEMA_V1} or {RECURRENCE_SCHEMA_V2}, got {}",
                self.schema
            ));
        }
        for obligation in &self.obligations {
            obligation.key.validate("obligation.key")?;
            obligation.policy.validate()?;
        }
        for record in &self.records {
            record.key.validate("record.key")?;
            record.policy.validate()?;
            record.slot.key.validate("record.slot.key")?;
            validate_digest(&record.slot.slot_id, "record.slot.slot_id")?;
            let expected_slot = make_run_slot(&record.policy, &record.key, record.slot.occurrence)?;
            if record.slot != expected_slot {
                return Err(
                    "retained recurrence record does not bind its exact deterministic slot".into(),
                );
            }
            let due_at = parse_time(&record.slot.due_at, "slot.due_at")?;
            let budget = checked_seconds(record.slot.budget_seconds, "record.slot budget")?;
            match &record.evidence {
                RunSlotEvidence::Completed {
                    attempt,
                    completed_at,
                    artifact,
                } => {
                    require_token("attempt.attempt_id", &attempt.attempt_id)?;
                    require_token("attempt.slot_id", &attempt.slot_id)?;
                    require_token("attempt.request_id", &attempt.request_id)?;
                    let started = parse_time(&attempt.started_at, "attempt.started_at")?;
                    let completed = parse_time(completed_at, "completed_at")?;
                    artifact.validate()?;
                    if self.schema == RECURRENCE_SCHEMA_V1 {
                        if artifact.contract_schema.is_some()
                            || artifact.profile_semantic_id.is_some()
                        {
                            return Err(
                                "recurrence_evidence.v1 cannot carry v2 artifact-reference fields"
                                    .into(),
                            );
                        }
                        if !matches!(&artifact.attempt_interval, AcquisitionInterval::V1(_))
                            || artifact
                                .dependency_acquisitions
                                .iter()
                                .any(|interval| !matches!(interval, AcquisitionInterval::V1(_)))
                        {
                            return Err(
                                "recurrence_evidence.v1 cannot carry v2 acquisition intervals"
                                    .into(),
                            );
                        }
                    }
                    let budget_end = started.checked_add_signed(budget).ok_or_else(|| {
                        "recurrence attempt budget arithmetic overflow".to_string()
                    })?;
                    if attempt.slot_id != record.slot.slot_id
                        || attempt.request_id != artifact.request_id
                        || artifact.key != record.key
                        || started < due_at
                        || completed < started
                        || completed > budget_end
                    {
                        return Err(
                            "retained completion does not bind its slot, request, artifact, or budget"
                                .into(),
                        );
                    }
                    if matches!(&artifact.attempt_interval, AcquisitionInterval::V1(_)) {
                        // Preserve the frozen v1 recurrence rule. V2 makes the
                        // NQ clock and its qualification explicit, while this
                        // Nightshift v2 carrier does not yet qualify its own
                        // invocation clock. Comparing those wall-clock values
                        // would silently invent a cross-clock relation.
                        let nq_attempt_start = parse_nq_time(
                            artifact.attempt_interval.started_at(),
                            "artifact.attempt_interval.started_at",
                        )?;
                        let nq_attempt_end = parse_nq_time(
                            artifact.attempt_interval.ended_at(),
                            "artifact.attempt_interval.ended_at",
                        )?;
                        if nq_attempt_start < started || nq_attempt_end > completed {
                            return Err(
                                "NQ attempt interval falls outside the bound Nightshift invocation"
                                    .into(),
                            );
                        }
                    }
                }
                RunSlotEvidence::Active { attempt } => {
                    require_token("attempt.attempt_id", &attempt.attempt_id)?;
                    require_token("attempt.slot_id", &attempt.slot_id)?;
                    require_token("attempt.request_id", &attempt.request_id)?;
                    let started = parse_time(&attempt.started_at, "attempt.started_at")?;
                    if attempt.slot_id != record.slot.slot_id || started < due_at {
                        return Err("active attempt does not bind its deterministic slot".into());
                    }
                }
                RunSlotEvidence::Blocked { reason } | RunSlotEvidence::Missed { reason } => {
                    if reason.trim().is_empty() {
                        return Err("blocked/missed recurrence reason must be non-empty".into());
                    }
                }
            }
        }
        validate_digest(&self.recurrence_id, "recurrence_id")?;
        if self.recurrence_id != self.computed_recurrence_id()? {
            return Err("recurrence_id does not match the canonical recurrence preimage".into());
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct JitterPreimage<'a> {
    schedule_id: &'a str,
    key: &'a DiagnosticKey,
}

/// Stable subject/profile/schedule jitter. It is derived, not freshly
/// randomized by each worker invocation.
pub fn deterministic_jitter(policy: &SchedulePolicy, key: &DiagnosticKey) -> u64 {
    let preimage = JitterPreimage {
        schedule_id: &policy.schedule_id,
        key,
    };
    let canonical = serde_jcs::to_vec(&preimage).expect("serializable jitter preimage");
    let digest = Sha256::digest(canonical);
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(prefix) % policy.jitter_bound_seconds.saturating_add(1)
}

fn checked_seconds(value: u64, field: &str) -> Result<Duration, String> {
    let value =
        i64::try_from(value).map_err(|_| format!("{field} exceeds supported duration range"))?;
    Duration::try_seconds(value).ok_or_else(|| format!("{field} exceeds supported duration range"))
}

fn checked_milliseconds(value: u64, field: &str) -> Result<Duration, String> {
    let value =
        i64::try_from(value).map_err(|_| format!("{field} exceeds supported duration range"))?;
    Duration::try_milliseconds(value)
        .ok_or_else(|| format!("{field} exceeds supported duration range"))
}

pub fn slot_due_at(
    policy: &SchedulePolicy,
    key: &DiagnosticKey,
    occurrence: u64,
) -> Result<DateTime<Utc>, String> {
    policy.validate()?;
    let first = parse_time(&policy.first_due_at, "schedule.first_due_at")?;
    let cadence = policy
        .cadence_seconds
        .checked_mul(occurrence)
        .ok_or_else(|| "schedule occurrence overflow".to_string())?;
    let with_cadence = first
        .checked_add_signed(checked_seconds(cadence, "cadence offset")?)
        .ok_or_else(|| "schedule cadence arithmetic overflow".to_string())?;
    with_cadence
        .checked_add_signed(checked_seconds(
            deterministic_jitter(policy, key),
            "jitter",
        )?)
        .ok_or_else(|| "schedule jitter arithmetic overflow".to_string())
}

pub fn make_run_slot(
    policy: &SchedulePolicy,
    key: &DiagnosticKey,
    occurrence: u64,
) -> Result<RunSlot, String> {
    let due_at = slot_due_at(policy, key, occurrence)?;
    let value = serde_json::json!({
        "schedule_id": policy.schedule_id,
        "occurrence": occurrence,
        "key": key,
        "due_at": due_at.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
        "budget_seconds": policy.max_execution_budget_seconds,
    });
    let canonical = serde_jcs::to_vec(&value).map_err(|error| error.to_string())?;
    let slot_id = sha256_id(&canonical);
    Ok(RunSlot {
        slot_id,
        schedule_id: policy.schedule_id.clone(),
        occurrence,
        key: key.clone(),
        due_at: due_at.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
        budget_seconds: policy.max_execution_budget_seconds,
    })
}

fn expected_occurrence_at(
    policy: &SchedulePolicy,
    key: &DiagnosticKey,
    evaluated_at: DateTime<Utc>,
) -> Result<Option<u64>, String> {
    let first = slot_due_at(policy, key, 0)?;
    if evaluated_at < first {
        return Ok(None);
    }
    let elapsed = evaluated_at.signed_duration_since(first).num_seconds();
    let elapsed = u64::try_from(elapsed)
        .map_err(|_| "negative or unsupported schedule elapsed time".to_string())?;
    Ok(Some(elapsed / policy.cadence_seconds))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecurrenceStanding {
    Current,
    Active,
    Overdue,
    Blocked,
    Missed,
    Invalid,
    ObligationMissing,
    ObligationDuplicate,
    RecordMissing,
    RecordDuplicate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecurrenceAssessment {
    pub key: DiagnosticKey,
    pub requirement: Requirement,
    pub standing: RecurrenceStanding,
    pub slot_id: Option<String>,
    pub records: Vec<RecurrenceRecord>,
    pub reason: String,
}

fn assess_recurrence_record(
    evaluated_at: DateTime<Utc>,
    obligation: &ScheduleObligation,
    record: &RecurrenceRecord,
    expected_artifact: Option<&ArtifactRef>,
) -> (RecurrenceStanding, String) {
    if record.key != obligation.key || record.policy != obligation.policy {
        return (
            RecurrenceStanding::Invalid,
            "record key or policy does not match the exact schedule obligation".into(),
        );
    }
    let expected_occurrence =
        match expected_occurrence_at(&obligation.policy, &obligation.key, evaluated_at) {
            Ok(Some(value)) => value,
            Ok(None) => {
                return (
                    RecurrenceStanding::Invalid,
                    "no schedule occurrence is due at the evaluation time".into(),
                )
            }
            Err(error) => return (RecurrenceStanding::Invalid, error),
        };
    let expected_slot =
        match make_run_slot(&obligation.policy, &obligation.key, expected_occurrence) {
            Ok(value) => value,
            Err(error) => return (RecurrenceStanding::Invalid, error),
        };
    if record.slot != expected_slot {
        return (
            RecurrenceStanding::Invalid,
            "record does not bind the exact deterministic current run slot".into(),
        );
    }
    let due_at = match parse_time(&record.slot.due_at, "slot.due_at") {
        Ok(value) => value,
        Err(error) => return (RecurrenceStanding::Invalid, error),
    };
    let budget = match checked_seconds(record.slot.budget_seconds, "slot budget") {
        Ok(value) => value,
        Err(error) => return (RecurrenceStanding::Invalid, error),
    };
    match &record.evidence {
        RunSlotEvidence::Completed {
            attempt,
            completed_at,
            artifact,
        } => {
            let started = match parse_time(&attempt.started_at, "attempt.started_at") {
                Ok(value) => value,
                Err(error) => return (RecurrenceStanding::Invalid, error),
            };
            let completed = match parse_time(completed_at, "completed_at") {
                Ok(value) => value,
                Err(error) => return (RecurrenceStanding::Invalid, error),
            };
            let Some(budget_end) = started.checked_add_signed(budget) else {
                return (
                    RecurrenceStanding::Invalid,
                    "recurrence budget arithmetic overflow".into(),
                );
            };
            if attempt.slot_id != record.slot.slot_id
                || attempt.request_id != artifact.request_id
                || started < due_at
                || completed < started
                || completed > evaluated_at
                || completed > budget_end
                || artifact.key != record.key
                || !expected_artifact
                    .is_some_and(|expected| artifact_refs_match(expected, artifact))
            {
                return (
                    RecurrenceStanding::Invalid,
                    "completion, Nightshift attempt, NQ request/run/artifact/attempt reference, or budget binding is invalid"
                        .into(),
                );
            }
            let standing =
                match checked_seconds(record.policy.standing_window_seconds, "standing window") {
                    Ok(value) => value,
                    Err(error) => return (RecurrenceStanding::Invalid, error),
                };
            let Some(standing_end) = completed.checked_add_signed(standing) else {
                return (
                    RecurrenceStanding::Invalid,
                    "recurrence standing-window arithmetic overflow".into(),
                );
            };
            if evaluated_at <= standing_end {
                (
                    RecurrenceStanding::Current,
                    "the exact completed current slot remains within its standing window".into(),
                )
            } else {
                (
                    RecurrenceStanding::Overdue,
                    "the completed slot's standing window has expired".into(),
                )
            }
        }
        RunSlotEvidence::Active { attempt } => {
            let started = match parse_time(&attempt.started_at, "attempt.started_at") {
                Ok(value) => value,
                Err(error) => return (RecurrenceStanding::Invalid, error),
            };
            let Some(budget_end) = started.checked_add_signed(budget) else {
                return (
                    RecurrenceStanding::Invalid,
                    "recurrence budget arithmetic overflow".into(),
                );
            };
            if attempt.slot_id != record.slot.slot_id
                || started < due_at
                || started > evaluated_at
                || evaluated_at > budget_end
            {
                (
                    RecurrenceStanding::Invalid,
                    "active attempt is not exactly bound to the current slot or budget".into(),
                )
            } else {
                (
                    RecurrenceStanding::Active,
                    "current run slot has one active in-budget attempt".into(),
                )
            }
        }
        RunSlotEvidence::Blocked { reason } => (
            RecurrenceStanding::Blocked,
            format!("current run slot was blocked: {reason}"),
        ),
        RunSlotEvidence::Missed { reason } => (
            RecurrenceStanding::Missed,
            format!("current run slot was missed: {reason}"),
        ),
    }
}

fn assess_recurrence_entry(
    evaluated_at: DateTime<Utc>,
    entry: &InventoryEntry,
    obligations: &[ScheduleObligation],
    records: &[RecurrenceRecord],
    artifact: Option<&ArtifactRef>,
) -> RecurrenceAssessment {
    let key = entry.binding.key();
    if entry.requirement == Requirement::Excluded {
        return RecurrenceAssessment {
            key,
            requirement: entry.requirement,
            standing: RecurrenceStanding::Current,
            slot_id: None,
            records: vec![],
            reason: "excluded inventory entry has no recurrence obligation".into(),
        };
    }
    let matching_obligations: Vec<_> = obligations
        .iter()
        .filter(|value| value.key == key)
        .collect();
    let obligation = match matching_obligations.as_slice() {
        [] => {
            return RecurrenceAssessment {
                key,
                requirement: entry.requirement,
                standing: RecurrenceStanding::ObligationMissing,
                slot_id: None,
                records: vec![],
                reason: "no exact schedule obligation exists".into(),
            }
        }
        [value] => *value,
        _ => {
            return RecurrenceAssessment {
                key,
                requirement: entry.requirement,
                standing: RecurrenceStanding::ObligationDuplicate,
                slot_id: None,
                records: vec![],
                reason: "more than one schedule obligation matches the diagnostic key".into(),
            }
        }
    };
    let matching_records: Vec<_> = records.iter().filter(|value| value.key == key).collect();
    let expected_slot = match expected_occurrence_at(&obligation.policy, &key, evaluated_at)
        .and_then(|occurrence| {
            occurrence
                .ok_or_else(|| "no schedule occurrence is due at the evaluation time".to_string())
        })
        .and_then(|occurrence| make_run_slot(&obligation.policy, &key, occurrence))
    {
        Ok(slot) => slot,
        Err(reason) => {
            return RecurrenceAssessment {
                key,
                requirement: entry.requirement,
                standing: RecurrenceStanding::Invalid,
                slot_id: None,
                records: vec![],
                reason,
            }
        }
    };
    let matching_records: Vec<_> = matching_records
        .into_iter()
        .filter(|value| value.slot == expected_slot)
        .collect();
    let record = match matching_records.as_slice() {
        [] => {
            return RecurrenceAssessment {
                key,
                requirement: entry.requirement,
                standing: RecurrenceStanding::RecordMissing,
                slot_id: None,
                records: vec![],
                reason: "no recurrence record exists for the current obligation".into(),
            }
        }
        [value] => *value,
        _ => {
            return RecurrenceAssessment {
                key,
                requirement: entry.requirement,
                standing: RecurrenceStanding::RecordDuplicate,
                slot_id: Some(expected_slot.slot_id),
                records: matching_records
                    .iter()
                    .map(|record| (*record).clone())
                    .collect(),
                reason: "more than one recurrence record binds the exact current run slot".into(),
            }
        }
    };
    let (standing, reason) = assess_recurrence_record(evaluated_at, obligation, record, artifact);
    RecurrenceAssessment {
        key,
        requirement: entry.requirement,
        standing,
        slot_id: Some(record.slot.slot_id.clone()),
        records: vec![record.clone()],
        reason,
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletenessAxis {
    Complete,
    Incomplete,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionAxis {
    Clean,
    ConditionPresent,
    Unresolved,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageAxis {
    Complete,
    Narrowed,
    Absent,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecurrenceAxis {
    Current,
    Incomplete,
}

/// Operator-facing summary of a posture, not a currentness predicate.
///
/// This projection is intentionally lossy: `Incomplete` covers both a posture
/// whose evidence is current but whose required delivery is unqualified and a
/// posture whose recurrence/evidence is not current. Consumers deciding
/// currentness must use `OperationalPosture.current` or the retained
/// completeness, coverage, and recurrence axes. They must not infer it from
/// this enum alone.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Headline {
    Clean,
    ConditionPresent,
    Incomplete,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InputTrace {
    pub key: DiagnosticKey,
    pub receiver_status: String,
    pub artifact_id: Option<String>,
}

fn input_trace(input: &DiagnosticInput) -> InputTrace {
    match &input.status {
        DiagnosticInputStatus::Delivered { artifact } => InputTrace {
            key: input.key.clone(),
            receiver_status: "delivered".into(),
            artifact_id: Some(artifact.artifact_id().to_owned()),
        },
        DiagnosticInputStatus::NoResponse => InputTrace {
            key: input.key.clone(),
            receiver_status: "no_response".into(),
            artifact_id: None,
        },
        DiagnosticInputStatus::AcquisitionFailed { .. } => InputTrace {
            key: input.key.clone(),
            receiver_status: "acquisition_failed".into(),
            artifact_id: None,
        },
        DiagnosticInputStatus::NotConfigured => InputTrace {
            key: input.key.clone(),
            receiver_status: "not_configured".into(),
            artifact_id: None,
        },
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalPosture {
    pub schema: String,
    pub posture_id: String,
    pub evaluator: SemanticIdentityV1,
    pub policy: PosturePolicy,
    pub schedule_obligations: Vec<ScheduleObligation>,
    pub input_evidence: DiagnosticInputs,
    /// Exact authority-owned support result used by the canonical runtime.
    /// Persisting this field preserves evidence only; it never recreates
    /// currentness after restart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub present_support: Option<QualifiedSupportV1>,
    pub recurrence_evidence: RecurrenceEvidence,
    pub evaluated_at: String,
    pub inventory_valid: bool,
    pub all_inputs: Vec<InputTrace>,
    pub unexpected_inputs: Vec<InputTrace>,
    pub assessments: Vec<EntryAssessment>,
    pub recurrence: Vec<RecurrenceAssessment>,
    pub completeness: CompletenessAxis,
    pub condition: ConditionAxis,
    pub coverage: CoverageAxis,
    pub recurrence_axis: RecurrenceAxis,
    pub delivery: DeliveryStanding,
    pub current: bool,
    /// Lossy operator summary. Use `current` or the retained axes for
    /// currentness decisions; see [`Headline`].
    pub headline: Headline,
}

pub fn posture_evaluator_identity() -> SemanticIdentityV1 {
    SemanticIdentityV1 {
        id: "nightshift.operational_posture_evaluator".into(),
        version: "2".into(),
        // sha256("nightshift.operational_posture_evaluator.v2")
        digest: "sha256:493c4bd1e728e139f3e6a34732dc1728e6c868947cc55d7277aedefe23e99e4c".into(),
    }
}

impl OperationalPosture {
    fn seal_identity(&mut self) -> Result<(), String> {
        self.posture_id.clear();
        let mut value = serde_json::to_value(&*self).map_err(|error| error.to_string())?;
        value
            .as_object_mut()
            .expect("serialized posture is an object")
            .remove("posture_id");
        let canonical = serde_jcs::to_vec(&value).map_err(|error| error.to_string())?;
        self.posture_id = sha256_id(&canonical);
        Ok(())
    }

    /// A truth-preserving projection retains every item and marks omission.
    /// Any omission forces the headline to incomplete.
    pub fn project(&self, visible: &BTreeSet<DiagnosticKey>) -> OperatorProjection {
        let slots: Vec<_> = self
            .assessments
            .iter()
            .cloned()
            .map(|item| OperatorProjectionSlot {
                visibility: if visible.contains(&item.key) {
                    ProjectionVisibility::Shown
                } else {
                    ProjectionVisibility::Omitted
                },
                item,
            })
            .collect();
        let headline = if slots
            .iter()
            .any(|slot| slot.visibility == ProjectionVisibility::Omitted)
        {
            Headline::Incomplete
        } else {
            self.headline
        };
        let mut projection = OperatorProjection {
            schema: OPERATOR_PROJECTION_SCHEMA.into(),
            projection_id: String::new(),
            source_posture_id: self.posture_id.clone(),
            source_generation: self.policy.generation.clone(),
            source_evaluated_at: self.evaluated_at.clone(),
            slots,
            recurrence: self.recurrence.clone(),
            completeness: self.completeness,
            condition: self.condition,
            coverage: self.coverage,
            recurrence_axis: self.recurrence_axis,
            delivery: self.delivery,
            headline,
        };
        let mut value = serde_json::to_value(&projection).expect("projection is serializable");
        value
            .as_object_mut()
            .expect("serialized projection is an object")
            .remove("projection_id");
        projection.projection_id =
            sha256_id(&serde_jcs::to_vec(&value).expect("projection has a JCS representation"));
        projection
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionVisibility {
    Shown,
    Omitted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorProjectionSlot {
    pub visibility: ProjectionVisibility,
    pub item: EntryAssessment,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorProjection {
    pub schema: String,
    pub projection_id: String,
    pub source_posture_id: String,
    pub source_generation: String,
    pub source_evaluated_at: String,
    pub slots: Vec<OperatorProjectionSlot>,
    pub recurrence: Vec<RecurrenceAssessment>,
    pub completeness: CompletenessAxis,
    pub condition: ConditionAxis,
    pub coverage: CoverageAxis,
    pub recurrence_axis: RecurrenceAxis,
    pub delivery: DeliveryStanding,
    /// Lossy operator summary. This projection intentionally omits a standalone
    /// `current` flag; currentness is recoverable from the retained
    /// completeness, coverage, and recurrence axes, not from this field alone.
    pub headline: Headline,
}

fn artifact_established(assessment: &EntryAssessment) -> bool {
    assessment.standing == Standing::Current
        && matches!(
            assessment.status,
            OperatorStatus::ConditionPresent
                | OperatorStatus::Clean
                | OperatorStatus::ExplicitlyAbsent
        )
}

pub fn evaluate_posture(
    policy: &PosturePolicy,
    inputs: &DiagnosticInputs,
    recurrence: &RecurrenceEvidence,
    evaluated_at: DateTime<Utc>,
) -> Result<OperationalPosture, String> {
    evaluate_posture_internal(policy, inputs, recurrence, evaluated_at, None)
}

/// Canonical runtime evaluator. Present support is decided by Pulse (or an
/// equivalent qualified observation authority), exactly binds the complete NQ
/// input basis, and replaces every raw producer-time freshness inference.
pub fn evaluate_posture_with_support(
    policy: &PosturePolicy,
    inputs: &DiagnosticInputs,
    recurrence: &RecurrenceEvidence,
    evaluated_at: DateTime<Utc>,
    support: &QualifiedSupportV1,
) -> Result<OperationalPosture, String> {
    support.validate_shape()?;
    let artifact_ids = delivered_artifact_ids(inputs);
    if support.diagnostic_inputs_id != inputs.inputs_id
        || support.subject_id != policy.subject.id
        || support.scope_id != policy.subject.scope.digest
        || support.artifact_ids != artifact_ids
    {
        return Err("qualified support does not exactly bind the complete diagnostic basis".into());
    }
    evaluate_posture_internal(policy, inputs, recurrence, evaluated_at, Some(support))
}

fn evaluate_posture_internal(
    policy: &PosturePolicy,
    inputs: &DiagnosticInputs,
    recurrence: &RecurrenceEvidence,
    evaluated_at: DateTime<Utc>,
    qualified_support: Option<&QualifiedSupportV1>,
) -> Result<OperationalPosture, String> {
    policy.validate()?;
    inputs.validate()?;
    recurrence.validate()?;

    let inventory_keys: BTreeSet<_> = policy
        .inventory
        .iter()
        .filter(|entry| entry.requirement != Requirement::Excluded)
        .map(|entry| entry.binding.key())
        .collect();
    let unexpected_inputs: Vec<_> = inputs
        .inputs
        .iter()
        .filter(|input| !inventory_keys.contains(&input.key))
        .map(input_trace)
        .collect();
    let assessments: Vec<_> = policy
        .inventory
        .iter()
        .map(|entry| assess_entry(entry, evaluated_at, &inputs.inputs, qualified_support))
        .collect();
    let recurrence_assessments: Vec<_> = policy
        .inventory
        .iter()
        .map(|entry| {
            let artifact = assessments
                .iter()
                .find(|assessment| assessment.key == entry.binding.key())
                .and_then(|assessment| assessment.artifact.as_ref());
            assess_recurrence_entry(
                evaluated_at,
                entry,
                &recurrence.obligations,
                &recurrence.records,
                artifact,
            )
        })
        .collect();

    let mandatory: Vec<_> = assessments
        .iter()
        .filter(|assessment| assessment.requirement == Requirement::Mandatory)
        .collect();
    let all_mandatory_established = mandatory
        .iter()
        .all(|assessment| artifact_established(assessment));
    let completeness = if all_mandatory_established {
        CompletenessAxis::Complete
    } else {
        CompletenessAxis::Incomplete
    };
    let condition = if assessments.iter().any(|assessment| {
        assessment.standing == Standing::Current
            && assessment.nq_trace.as_ref().is_some_and(|trace| {
                trace.outcome.derivation() == DerivationV1::Completed
                    && trace.outcome.condition() == ConditionV1::Present
            })
    }) {
        ConditionAxis::ConditionPresent
    } else if completeness == CompletenessAxis::Complete
        && mandatory.iter().all(|assessment| {
            matches!(
                assessment.status,
                OperatorStatus::Clean | OperatorStatus::ExplicitlyAbsent
            )
        })
    {
        ConditionAxis::Clean
    } else {
        ConditionAxis::Unresolved
    };
    let current_mandatory_coverage: Vec<_> = mandatory
        .iter()
        .filter(|assessment| assessment.standing == Standing::Current)
        .filter_map(|assessment| {
            assessment
                .nq_trace
                .as_ref()
                .map(|trace| trace.outcome.coverage())
        })
        .collect();
    let coverage = if current_mandatory_coverage.len() == mandatory.len()
        && current_mandatory_coverage
            .iter()
            .all(|coverage| *coverage == CoverageV1::Complete)
    {
        CoverageAxis::Complete
    } else if current_mandatory_coverage
        .iter()
        .any(|coverage| matches!(coverage, CoverageV1::Complete | CoverageV1::Partial))
    {
        CoverageAxis::Narrowed
    } else {
        CoverageAxis::Absent
    };
    let recurrence_current = policy.inventory.iter().all(|entry| {
        entry.requirement != Requirement::Mandatory
            || recurrence_assessments.iter().any(|assessment| {
                assessment.key == entry.binding.key()
                    && assessment.standing == RecurrenceStanding::Current
            })
    });
    let recurrence_axis = if recurrence_current {
        RecurrenceAxis::Current
    } else {
        RecurrenceAxis::Incomplete
    };
    let current = completeness == CompletenessAxis::Complete
        && coverage == CoverageAxis::Complete
        && recurrence_axis == RecurrenceAxis::Current;
    let delivery_accepted = if policy.delivery_required {
        recurrence.delivery == DeliveryStanding::Qualified
    } else {
        true
    };
    let headline = if current && condition == ConditionAxis::Clean && delivery_accepted {
        Headline::Clean
    } else if current && condition == ConditionAxis::ConditionPresent {
        Headline::ConditionPresent
    } else {
        Headline::Incomplete
    };
    let mut posture = OperationalPosture {
        schema: POSTURE_SCHEMA.into(),
        posture_id: String::new(),
        evaluator: posture_evaluator_identity(),
        policy: policy.clone(),
        schedule_obligations: recurrence.obligations.clone(),
        input_evidence: inputs.clone(),
        present_support: qualified_support.cloned(),
        recurrence_evidence: recurrence.clone(),
        evaluated_at: evaluated_at.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
        inventory_valid: true,
        all_inputs: inputs.inputs.iter().map(input_trace).collect(),
        unexpected_inputs,
        assessments,
        recurrence: recurrence_assessments,
        completeness,
        condition,
        coverage,
        recurrence_axis,
        delivery: recurrence.delivery,
        current,
        headline,
    };
    posture.seal_identity()?;
    Ok(posture)
}

pub fn render_text(posture: &OperationalPosture) -> String {
    let all_visible = posture
        .assessments
        .iter()
        .map(|assessment| assessment.key.clone())
        .collect();
    let projection = posture.project(&all_visible);
    let mut output = String::new();
    output.push_str(&format!("projection: {}\n", projection.projection_id));
    output.push_str(&format!(
        "source_posture: {}\n",
        projection.source_posture_id
    ));
    output.push_str(&format!(
        "source_generation: {}\n",
        escaped_inline(&projection.source_generation)
    ));
    output.push_str(&format!(
        "evaluated_at: {}\n",
        projection.source_evaluated_at
    ));
    output.push_str(&format!("headline: {:?}\n", projection.headline));
    output.push_str(&format!("completeness: {:?}\n", projection.completeness));
    output.push_str(&format!("condition: {:?}\n", projection.condition));
    output.push_str(&format!("coverage: {:?}\n", projection.coverage));
    output.push_str(&format!("recurrence: {:?}\n", projection.recurrence_axis));
    output.push_str(&format!("delivery: {:?}\n", projection.delivery));
    for slot in &projection.slots {
        let item = &slot.item;
        output.push_str(&format!(
            "diagnostic: {}/{}/{}/{} standing={:?} status={:?} requirement={:?} visibility={:?}\n",
            escaped_inline(&item.key.question_id),
            escaped_inline(&item.key.subject_id),
            escaped_inline(&item.key.profile_id),
            escaped_inline(&item.key.vantage_id),
            item.standing,
            item.status,
            item.requirement,
            slot.visibility
        ));
        output.push_str(&format!("  reason: {}\n", escaped_inline(&item.reason)));
        if let Some(artifact) = &item.artifact {
            output.push_str(&format!(
                "  source: contract={} profile_semantic={} artifact={} request={} run={} claim={}\n",
                escaped_inline(
                    artifact
                        .contract_schema
                        .as_deref()
                        .unwrap_or(NQ_DIAGNOSTIC_EXECUTION_SCHEMA)
                ),
                escaped_inline(artifact.profile_semantic_id.as_deref().unwrap_or("n/a")),
                artifact.artifact_id,
                escaped_inline(&artifact.request_id),
                escaped_inline(&artifact.run_id),
                escaped_inline(artifact.claim_id.as_deref().unwrap_or("none"))
            ));
        }
        if let Some(trace) = &item.nq_trace {
            output.push_str(&format!(
                "  nq_outcome: derivation={:?} condition={:?} coherence={:?} coverage={:?}\n",
                trace.outcome.derivation(),
                trace.outcome.condition(),
                trace.outcome.coherence(),
                trace.outcome.coverage()
            ));
            if let Some((code, reason)) = trace.outcome.refusal_display() {
                output.push_str(&format!(
                    "  nq_refusal: code={} reason={}\n",
                    escaped_inline(&code),
                    escaped_inline(&reason)
                ));
            }
            for failure in &trace.input_failures {
                output.push_str(&format!(
                    "  nq_input_failure: id={} expectation={} kind={:?} detail={}\n",
                    escaped_inline(&failure.failure_id),
                    escaped_inline(&failure.expectation_id),
                    failure.kind,
                    escaped_inline(&failure.detail)
                ));
            }
            for binding in &trace.primary_state_bindings {
                output.push_str(&format!(
                    "  state_binding: {} {}={}\n",
                    escaped_inline(&binding.binding_id),
                    escaped_inline(&binding.kind),
                    escaped_inline(&binding.value)
                ));
            }
        }
    }
    for recurrence in &projection.recurrence {
        output.push_str(&format!(
            "recurrence_slot: {}/{}/{}/{} standing={:?} requirement={:?} slot={}\n",
            escaped_inline(&recurrence.key.question_id),
            escaped_inline(&recurrence.key.subject_id),
            escaped_inline(&recurrence.key.profile_id),
            escaped_inline(&recurrence.key.vantage_id),
            recurrence.standing,
            recurrence.requirement,
            escaped_inline(recurrence.slot_id.as_deref().unwrap_or("none"))
        ));
        output.push_str(&format!(
            "  reason: {}\n",
            escaped_inline(&recurrence.reason)
        ));
    }
    if !posture.unexpected_inputs.is_empty() {
        output.push_str("unexpected_inputs:\n");
        for input in &posture.unexpected_inputs {
            output.push_str(&format!(
                "  - {:?} ({})\n",
                input.key, input.receiver_status
            ));
        }
    }
    output
}

fn escaped_inline(value: &str) -> String {
    let encoded = serde_json::to_string(value).expect("operator text value is serializable");
    encoded[1..encoded.len() - 1].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn semantic(id: &str, byte: char) -> SemanticIdentityV1 {
        SemanticIdentityV1 {
            id: id.into(),
            version: "1".into(),
            digest: digest(byte),
        }
    }

    fn base_artifact() -> DiagnosticExecutionV1 {
        let mut artifact = DiagnosticExecutionV1 {
            schema: DiagnosticExecutionSchema::V1,
            artifact_id: String::new(),
            canonicalization: SemanticIdentityV1 {
                id: "rfc8785-jcs".into(),
                version: "1".into(),
                digest: "sha256:e49d92d4e86052e66ed2a481b9386d3b214ce3d2df5fd109a6491ccb9ffb24f3"
                    .into(),
            },
            producer: ProducerV1 {
                node_id: "nq-node:test".into(),
                build: semantic("nq-build", 'a'),
                cohort: semantic("host-cohort", 'b'),
            },
            request_id: "request:1".into(),
            run_id: "run:1".into(),
            question: semantic("host.storage", 'c'),
            subject: SubjectV1 {
                id: "host:test".into(),
                scope: semantic("host", '4'),
            },
            profile: semantic("host.storage.v1", 'd'),
            vantage: semantic("host-local", 'e'),
            state_model: semantic("host-boot", 'f'),
            evaluator: semantic("nq-evaluator", '1'),
            threshold_policy: semantic("thresholds", '2'),
            projection: ProjectionV1 {
                identity: semantic("full-host-storage", '3'),
                omitted_distinctions: vec![],
            },
            execution_clock: semantic("clock:nightshift", '9'),
            started_at: "2026-07-27T12:00:00Z".into(),
            completed_at: "2026-07-27T12:00:20Z".into(),
            attempt_interval: AcquisitionIntervalV1 {
                started_at: "2026-07-27T12:00:00Z".into(),
                ended_at: "2026-07-27T12:00:20Z".into(),
                clock: semantic("clock:nightshift", '9'),
                clock_uncertainty_ms: 0,
            },
            inputs: InputAccountingV1 {
                selection_rule: semantic("storage-selection", '5'),
                expected: vec![ExpectedInputV1 {
                    expectation_id: "expected:1".into(),
                    role: "mount-observation".into(),
                    required: true,
                }],
                received: vec![ReceivedInputV1 {
                    input_id: "input:1".into(),
                    expectation_id: "expected:1".into(),
                    raw_artifact_id: digest('6'),
                    capture_mode: RawCaptureModeV1::ExactSource,
                    capture_policy: semantic("capture:exact", '6'),
                    availability_at_derivation: EvidenceAvailabilityV1::Online,
                    acquisition: AcquisitionIntervalV1 {
                        started_at: "2026-07-27T12:00:10Z".into(),
                        ended_at: "2026-07-27T12:00:15Z".into(),
                        clock: semantic("clock:provider", '0'),
                        clock_uncertainty_ms: 0,
                    },
                    received_at: "2026-07-27T12:00:16Z".into(),
                }],
                admitted: vec![AdmittedInputV1 {
                    input_id: "input:1".into(),
                    admission_rule: semantic("storage-admission", '8'),
                    normalized_artifact_id: digest('7'),
                    normalization_rule: semantic("storage-normalization", '7'),
                    projected_artifact_id: digest('8'),
                    projection_rule: semantic("storage-projection", '8'),
                }],
                refused: vec![],
                failed: vec![],
                excluded: vec![],
                selected: vec![SelectedInputV1 {
                    input_id: "input:1".into(),
                    projected_artifact_id: digest('8'),
                    role: "mount-observation".into(),
                }],
            },
            state_bindings: vec![StateBindingV1 {
                binding_id: "state:boot".into(),
                kind: "boot_epoch".into(),
                value: "boot:1".into(),
                supporting_input_ids: vec!["input:1".into()],
            }],
            claims: vec![ClaimV1 {
                claim_id: "claim:storage".into(),
                proposition: "required storage condition absent".into(),
                status: ClaimStatusV1::Established,
                condition_effect: Some(ConditionV1::ExplicitlyAbsent),
                dependency_input_ids: vec!["input:1".into()],
                state_binding_ids: vec!["state:boot".into()],
                required_distinctions: vec![],
                limitations: vec![],
                nonclaims: vec!["does not authorize repair".into()],
            }],
            primary_claim_id: Some("claim:storage".into()),
            outcome: OutcomeV1 {
                derivation: DerivationV1::Completed,
                condition: ConditionV1::ExplicitlyAbsent,
                coherence: CoherenceV1::JointlyEstablished,
                coverage: CoverageV1::Complete,
                summary: "storage condition explicitly absent".into(),
                refusal: None,
            },
            limitations: vec![],
            nonclaims: vec!["does not establish authorization".into()],
        };
        seal_artifact(&mut artifact);
        artifact
    }

    fn v2_artifact(
        qualification: crate::diagnostic_execution_v2::ClockQualificationV2,
    ) -> crate::diagnostic_execution_v2::DiagnosticExecutionV2 {
        use crate::diagnostic_execution_v2::{
            AcquisitionIntervalV2, ClaimV2, DiagnosticExecutionSchemaV2, InputAccountingV2,
            OutcomeV2, ReceivedInputV2,
        };

        let v1 = base_artifact();
        let attempt_interval = AcquisitionIntervalV2 {
            started_at: v1.attempt_interval.started_at.clone(),
            ended_at: v1.attempt_interval.ended_at.clone(),
            clock: v1.execution_clock.clone(),
            qualification: qualification.clone(),
        };
        let received = v1.inputs.received[0].clone();
        let claim = v1.claims[0].clone();
        let mut artifact = crate::diagnostic_execution_v2::DiagnosticExecutionV2 {
            schema: DiagnosticExecutionSchemaV2::V2,
            artifact_id: String::new(),
            canonicalization: v1.canonicalization,
            producer: v1.producer,
            request_id: v1.request_id,
            run_id: v1.run_id,
            question: v1.question,
            subject: v1.subject,
            profile: v1.profile,
            profile_semantic_id: digest('a'),
            vantage: v1.vantage,
            state_model: v1.state_model,
            evaluator: v1.evaluator,
            threshold_policy: v1.threshold_policy,
            projection: v1.projection,
            execution_clock: v1.execution_clock.clone(),
            started_at: v1.started_at,
            completed_at: v1.completed_at,
            attempt_interval,
            inputs: InputAccountingV2 {
                selection_rule: v1.inputs.selection_rule,
                expected: v1.inputs.expected,
                received: vec![ReceivedInputV2 {
                    input_id: received.input_id,
                    expectation_id: received.expectation_id,
                    provider_intake_id: "provider-intake:1".into(),
                    raw_artifact_id: received.raw_artifact_id,
                    capture_mode: received.capture_mode,
                    capture_policy: received.capture_policy,
                    availability_at_derivation: received.availability_at_derivation,
                    acquisition: AcquisitionIntervalV2 {
                        started_at: received.acquisition.started_at,
                        ended_at: received.acquisition.ended_at,
                        clock: v1.execution_clock.clone(),
                        qualification,
                    },
                    received_at: received.received_at,
                }],
                admitted: v1.inputs.admitted,
                refused: vec![],
                failed: vec![],
                excluded: v1.inputs.excluded,
                selected: v1.inputs.selected,
            },
            state_bindings: v1.state_bindings,
            claims: vec![ClaimV2 {
                claim_id: claim.claim_id,
                proposition: claim.proposition,
                status: claim.status,
                condition_effect: claim.condition_effect,
                dependency_input_ids: claim.dependency_input_ids,
                dependency_refusal_ids: vec![],
                dependency_failure_ids: vec![],
                state_binding_ids: claim.state_binding_ids,
                required_distinctions: claim.required_distinctions,
                limitations: claim.limitations,
                nonclaims: claim.nonclaims,
            }],
            primary_claim_id: v1.primary_claim_id,
            outcome: OutcomeV2 {
                derivation: v1.outcome.derivation,
                condition: v1.outcome.condition,
                coherence: v1.outcome.coherence,
                coverage: v1.outcome.coverage,
                summary: v1.outcome.summary,
                refusals: vec![],
                unsupported: vec![],
            },
            limitations: v1.limitations,
            nonclaims: v1.nonclaims,
        };
        artifact.artifact_id = computed_object_id(&artifact, "artifact_id").unwrap();
        artifact.validate().unwrap();
        artifact
    }

    fn v2_policy(
        artifact: &crate::diagnostic_execution_v2::DiagnosticExecutionV2,
    ) -> PosturePolicy {
        let mut policy = PosturePolicy {
            schema: POSTURE_POLICY_SCHEMA.into(),
            policy_id: String::new(),
            generation: "generation:v2".into(),
            subject: artifact.subject.clone(),
            role: semantic("nightshift-role:host", 'b'),
            delivery_required: false,
            inventory: vec![InventoryEntry {
                binding: ContractBinding {
                    producer_node_id: artifact.producer.node_id.clone(),
                    producer_build: artifact.producer.build.clone(),
                    producer_cohort: artifact.producer.cohort.clone(),
                    question: artifact.question.clone(),
                    profile: artifact.profile.clone(),
                    profile_semantic_id: Some(artifact.profile_semantic_id.clone()),
                    vantage: artifact.vantage.clone(),
                    state_model: artifact.state_model.clone(),
                    evaluator: artifact.evaluator.clone(),
                    threshold_policy: artifact.threshold_policy.clone(),
                    projection: artifact.projection.clone(),
                    subject: artifact.subject.clone(),
                    claim_id: "claim:storage".into(),
                },
                requirement: Requirement::Mandatory,
                required_state_bindings: vec![RequiredStateBinding {
                    kind: "boot_epoch".into(),
                    value: "boot:1".into(),
                }],
                max_age_seconds: 120,
            }],
        };
        policy.policy_id = policy.computed_policy_id().unwrap();
        policy
    }

    fn delivered_v2(
        artifact: crate::diagnostic_execution_v2::DiagnosticExecutionV2,
    ) -> DiagnosticInputs {
        let key = DiagnosticKey {
            question_id: artifact.question.id.clone(),
            subject_id: artifact.subject.id.clone(),
            profile_id: artifact.profile.id.clone(),
            vantage_id: artifact.vantage.id.clone(),
        };
        let mut inputs = DiagnosticInputs {
            schema: INPUTS_SCHEMA.into(),
            inputs_id: String::new(),
            inputs: vec![DiagnosticInput {
                key,
                status: DiagnosticInputStatus::Delivered {
                    artifact: Box::new(DiagnosticExecution::V2(artifact)),
                },
            }],
        };
        reseal_inputs(&mut inputs);
        inputs
    }

    fn empty_recurrence() -> RecurrenceEvidence {
        let mut recurrence = RecurrenceEvidence {
            schema: RECURRENCE_SCHEMA.into(),
            recurrence_id: String::new(),
            obligations: vec![],
            records: vec![],
            delivery: DeliveryStanding::NotRequired,
        };
        reseal_recurrence(&mut recurrence);
        recurrence
    }

    fn seal_artifact(artifact: &mut DiagnosticExecutionV1) {
        artifact.artifact_id.clear();
        let mut value = serde_json::to_value(&*artifact).unwrap();
        value.as_object_mut().unwrap().remove("artifact_id");
        artifact.artifact_id = sha256_id(&serde_jcs::to_vec(&value).unwrap());
    }

    fn key(artifact: &DiagnosticExecutionV1) -> DiagnosticKey {
        DiagnosticKey {
            question_id: artifact.question.id.clone(),
            subject_id: artifact.subject.id.clone(),
            profile_id: artifact.profile.id.clone(),
            vantage_id: artifact.vantage.id.clone(),
        }
    }

    fn policy(artifact: &DiagnosticExecutionV1) -> PosturePolicy {
        let mut policy = PosturePolicy {
            schema: POSTURE_POLICY_SCHEMA.into(),
            policy_id: String::new(),
            generation: "generation:1".into(),
            subject: artifact.subject.clone(),
            role: semantic("nightshift-role:host", 'b'),
            delivery_required: false,
            inventory: vec![InventoryEntry {
                binding: ContractBinding {
                    producer_node_id: artifact.producer.node_id.clone(),
                    producer_build: artifact.producer.build.clone(),
                    producer_cohort: artifact.producer.cohort.clone(),
                    question: artifact.question.clone(),
                    profile: artifact.profile.clone(),
                    profile_semantic_id: None,
                    vantage: artifact.vantage.clone(),
                    state_model: artifact.state_model.clone(),
                    evaluator: artifact.evaluator.clone(),
                    threshold_policy: artifact.threshold_policy.clone(),
                    projection: artifact.projection.clone(),
                    subject: artifact.subject.clone(),
                    claim_id: "claim:storage".into(),
                },
                requirement: Requirement::Mandatory,
                required_state_bindings: vec![RequiredStateBinding {
                    kind: "boot_epoch".into(),
                    value: "boot:1".into(),
                }],
                max_age_seconds: 120,
            }],
        };
        policy.policy_id = policy.computed_policy_id().unwrap();
        policy
    }

    fn reseal_policy(policy: &mut PosturePolicy) {
        policy.policy_id.clear();
        policy.policy_id = policy.computed_policy_id().unwrap();
    }

    fn reseal_recurrence(recurrence: &mut RecurrenceEvidence) {
        recurrence.recurrence_id.clear();
        recurrence.recurrence_id = recurrence.computed_recurrence_id().unwrap();
    }

    fn reseal_inputs(inputs: &mut DiagnosticInputs) {
        inputs.inputs_id.clear();
        inputs.inputs_id = inputs.computed_inputs_id().unwrap();
    }

    fn delivered(artifact: DiagnosticExecutionV1) -> DiagnosticInputs {
        let mut inputs = DiagnosticInputs {
            schema: INPUTS_SCHEMA.into(),
            inputs_id: String::new(),
            inputs: vec![DiagnosticInput {
                key: key(&artifact),
                status: DiagnosticInputStatus::Delivered {
                    artifact: Box::new(artifact.into()),
                },
            }],
        };
        reseal_inputs(&mut inputs);
        inputs
    }

    fn recurrence(
        artifact: &DiagnosticExecutionV1,
        evidence: Option<RunSlotEvidence>,
    ) -> RecurrenceEvidence {
        let key = key(artifact);
        let policy = SchedulePolicy {
            schedule_id: "schedule:test".into(),
            first_due_at: "2026-07-27T12:00:00Z".into(),
            cadence_seconds: 60,
            jitter_bound_seconds: 0,
            max_execution_budget_seconds: 30,
            standing_window_seconds: 130,
        };
        let slot = make_run_slot(&policy, &key, 0).unwrap();
        let artifact_ref = artifact_ref(&DiagnosticExecution::V1(artifact.clone()));
        let evidence = evidence.unwrap_or_else(|| RunSlotEvidence::Completed {
            attempt: InvocationAttempt {
                attempt_id: "attempt:1".into(),
                slot_id: slot.slot_id.clone(),
                request_id: artifact.request_id.clone(),
                started_at: "2026-07-27T12:00:00Z".into(),
            },
            completed_at: artifact.completed_at.clone(),
            artifact: Box::new(artifact_ref),
        });
        let mut recurrence = RecurrenceEvidence {
            schema: RECURRENCE_SCHEMA.into(),
            recurrence_id: String::new(),
            obligations: vec![ScheduleObligation {
                key: key.clone(),
                policy: policy.clone(),
            }],
            records: vec![RecurrenceRecord {
                key,
                policy,
                slot,
                evidence,
            }],
            delivery: DeliveryStanding::NotRequired,
        };
        reseal_recurrence(&mut recurrence);
        recurrence
    }

    fn at(value: &str) -> DateTime<Utc> {
        parse_time(value, "test").unwrap()
    }

    #[test]
    fn exact_current_clean_path_is_deterministic() {
        let artifact = base_artifact();
        let posture_a = evaluate_posture(
            &policy(&artifact),
            &delivered(artifact.clone()),
            &recurrence(&artifact, None),
            at("2026-07-27T12:00:30Z"),
        )
        .unwrap();
        let posture_b = evaluate_posture(
            &policy(&artifact),
            &delivered(artifact.clone()),
            &recurrence(&artifact, None),
            at("2026-07-27T12:00:30Z"),
        )
        .unwrap();
        assert_eq!(posture_a, posture_b);
        assert_eq!(posture_a.headline, Headline::Clean);
        assert_eq!(posture_a.completeness, CompletenessAxis::Complete);
        assert!(posture_a.current);
        assert_eq!(posture_a.evaluator, posture_evaluator_identity());
        assert_eq!(posture_a.policy, policy(&artifact));
        assert_eq!(
            posture_a.schedule_obligations,
            recurrence(&artifact, None).obligations
        );
    }

    #[test]
    fn nq_clean_and_explicit_absence_are_both_resolved_but_remain_distinct_rows() {
        let explicit_absence = base_artifact();
        let explicit_posture = evaluate_posture(
            &policy(&explicit_absence),
            &delivered(explicit_absence.clone()),
            &recurrence(&explicit_absence, None),
            at("2026-07-27T12:00:30Z"),
        )
        .unwrap();
        assert_eq!(
            explicit_posture.assessments[0].status,
            OperatorStatus::ExplicitlyAbsent
        );

        let mut clean = explicit_absence;
        clean.outcome.condition = ConditionV1::Clean;
        clean.claims[0].condition_effect = Some(ConditionV1::Clean);
        seal_artifact(&mut clean);
        let clean_posture = evaluate_posture(
            &policy(&clean),
            &delivered(clean.clone()),
            &recurrence(&clean, None),
            at("2026-07-27T12:00:30Z"),
        )
        .unwrap();
        assert_eq!(clean_posture.assessments[0].status, OperatorStatus::Clean);
        assert_eq!(clean_posture.condition, ConditionAxis::Clean);
        assert_eq!(clean_posture.headline, Headline::Clean);
        assert_ne!(explicit_posture.posture_id, clean_posture.posture_id);
    }

    #[test]
    fn posture_identity_commits_policy_inventory_and_schedule_obligations() {
        let artifact = base_artifact();
        let base_policy = policy(&artifact);
        let base_recurrence = recurrence(&artifact, None);
        let base = evaluate_posture(
            &base_policy,
            &delivered(artifact.clone()),
            &base_recurrence,
            at("2026-07-27T12:00:30Z"),
        )
        .unwrap();

        let mut changed_policy = base_policy.clone();
        changed_policy.role = semantic("nightshift-role:host-revised", 'c');
        reseal_policy(&mut changed_policy);
        let changed = evaluate_posture(
            &changed_policy,
            &delivered(artifact.clone()),
            &base_recurrence,
            at("2026-07-27T12:00:30Z"),
        )
        .unwrap();
        assert_ne!(base.posture_id, changed.posture_id);

        let mut changed_recurrence = base_recurrence;
        changed_recurrence.obligations[0]
            .policy
            .standing_window_seconds += 1;
        reseal_recurrence(&mut changed_recurrence);
        let changed = evaluate_posture(
            &base_policy,
            &delivered(artifact),
            &changed_recurrence,
            at("2026-07-27T12:00:30Z"),
        )
        .unwrap();
        assert_ne!(base.posture_id, changed.posture_id);
    }

    #[test]
    fn nq_refusal_is_distinct_from_nightshift_no_response() {
        let mut artifact = base_artifact();
        artifact.outcome.derivation = DerivationV1::Refused;
        artifact.outcome.condition = ConditionV1::Unresolved;
        artifact.outcome.coherence = CoherenceV1::NotEvaluated;
        artifact.outcome.coverage = CoverageV1::Missing;
        artifact.outcome.refusal = Some(RefusalV1 {
            code: "insufficient_projection".into(),
            reason: "required dimension was projected away".into(),
        });
        artifact.claims.clear();
        artifact.primary_claim_id = None;
        artifact.state_bindings.clear();
        artifact.inputs.admitted.clear();
        artifact.inputs.selected.clear();
        artifact.inputs.refused.push(RefusedInputV1 {
            input_id: "input:1".into(),
            refusal_id: "refusal:1".into(),
            code: "schema_mismatch".into(),
            reason: "provider response was not admitted".into(),
        });
        seal_artifact(&mut artifact);
        let refused = evaluate_posture(
            &policy(&artifact),
            &delivered(artifact.clone()),
            &recurrence(&artifact, None),
            at("2026-07-27T12:00:30Z"),
        )
        .unwrap();
        let mut no_response_inputs = DiagnosticInputs {
            schema: INPUTS_SCHEMA.into(),
            inputs_id: String::new(),
            inputs: vec![DiagnosticInput {
                key: key(&artifact),
                status: DiagnosticInputStatus::NoResponse,
            }],
        };
        reseal_inputs(&mut no_response_inputs);
        let no_response = evaluate_posture(
            &policy(&artifact),
            &no_response_inputs,
            &recurrence(&artifact, None),
            at("2026-07-27T12:00:30Z"),
        )
        .unwrap();
        assert_eq!(refused.assessments[0].status, OperatorStatus::Refused);
        assert_eq!(
            no_response.assessments[0].status,
            OperatorStatus::NoResponse
        );
        assert_ne!(refused.posture_id, no_response.posture_id);
    }

    #[test]
    fn explicit_v1_unqualified_clock_limitation_never_becomes_current() {
        let mut artifact = base_artifact();
        artifact.limitations = vec![LimitationV1 {
            kind: LimitationKindV1::Other,
            code: "absolute_clock_quality_unqualified".into(),
            detail: "no finite UTC-error bound was established".into(),
        }];
        seal_artifact(&mut artifact);

        let result = evaluate_posture(
            &policy(&artifact),
            &delivered(artifact.clone()),
            &recurrence(&artifact, None),
            at("2026-07-27T12:00:30Z"),
        )
        .unwrap();

        assert_eq!(result.assessments[0].standing, Standing::ClockUnqualified);
        assert_eq!(
            result.assessments[0].status,
            OperatorStatus::ClockUnqualified
        );
        assert!(!result.current);
        assert_eq!(result.headline, Headline::Incomplete);
    }

    #[test]
    fn bounded_v2_source_clock_cannot_earn_current_against_bare_evaluation_time() {
        let artifact = v2_artifact(
            crate::diagnostic_execution_v2::ClockQualificationV2::Bounded {
                maximum_error_ms: 1,
                basis: semantic("clock-basis:test", 'c'),
            },
        );
        let result = evaluate_posture(
            &v2_policy(&artifact),
            &delivered_v2(artifact),
            &empty_recurrence(),
            at("2026-07-27T12:00:30Z"),
        )
        .unwrap();

        assert_eq!(result.assessments[0].standing, Standing::ClockUnqualified);
        assert_eq!(
            result.assessments[0].status,
            OperatorStatus::ClockUnqualified
        );
        assert!(result.assessments[0]
            .reason
            .contains("Nightshift evaluation instant"));
        assert!(!result.current);
        assert_eq!(result.headline, Headline::Incomplete);
    }

    #[test]
    fn unqualified_v2_source_clock_preserves_the_producer_reason() {
        let artifact = v2_artifact(
            crate::diagnostic_execution_v2::ClockQualificationV2::Unqualified {
                code: "clock_not_qualified".into(),
                detail: "no bounded source clock error was established".into(),
            },
        );
        let result = evaluate_posture(
            &v2_policy(&artifact),
            &delivered_v2(artifact),
            &empty_recurrence(),
            at("2026-07-27T12:00:30Z"),
        )
        .unwrap();

        assert_eq!(result.assessments[0].standing, Standing::ClockUnqualified);
        assert!(result.assessments[0].reason.contains("clock_not_qualified"));
        assert!(result.assessments[0]
            .reason
            .contains("no bounded source clock error was established"));
        assert!(!result.assessments[0]
            .reason
            .contains("Nightshift evaluation instant"));
        assert!(!result.current);
    }

    #[test]
    fn v1_receiver_contract_remains_decodable_and_unknown_versions_refuse() {
        let artifact = base_artifact();
        let mut legacy_policy = policy(&artifact);
        legacy_policy.schema = POSTURE_POLICY_SCHEMA_V1.into();
        reseal_policy(&mut legacy_policy);
        legacy_policy.validate().unwrap();

        legacy_policy.inventory[0].binding.profile_semantic_id =
            Some(format!("sha256:{}", "a".repeat(64)));
        reseal_policy(&mut legacy_policy);
        assert!(
            legacy_policy.validate().is_err(),
            "the v1 policy schema must not acquire a v2-only identity field"
        );

        let mut legacy_inputs = delivered(artifact.clone());
        legacy_inputs.schema = INPUTS_SCHEMA_V1.into();
        reseal_inputs(&mut legacy_inputs);
        legacy_inputs.validate().unwrap();

        let mut legacy_recurrence = recurrence(&artifact, None);
        legacy_recurrence.schema = RECURRENCE_SCHEMA_V1.into();
        {
            let RunSlotEvidence::Completed {
                artifact: legacy_ref,
                ..
            } = &mut legacy_recurrence.records[0].evidence
            else {
                panic!("fixture must contain one completed recurrence");
            };
            legacy_ref.contract_schema = None;
            legacy_ref.profile_semantic_id = None;
        }
        reseal_recurrence(&mut legacy_recurrence);
        legacy_recurrence.validate().unwrap();

        let RunSlotEvidence::Completed {
            artifact: legacy_ref,
            ..
        } = &mut legacy_recurrence.records[0].evidence
        else {
            panic!("fixture must contain one completed recurrence");
        };
        legacy_ref.contract_schema = Some(NQ_DIAGNOSTIC_EXECUTION_SCHEMA.into());
        reseal_recurrence(&mut legacy_recurrence);
        assert!(
            legacy_recurrence.validate().is_err(),
            "the v1 recurrence schema must not acquire v2 artifact-reference fields"
        );

        let result = evaluate_posture(
            &policy(&artifact),
            &legacy_inputs,
            &recurrence(&artifact, None),
            at("2026-07-27T12:00:30Z"),
        )
        .unwrap();
        assert_eq!(result.assessments[0].standing, Standing::Current);

        let mut unknown_inputs = delivered(artifact.clone());
        unknown_inputs.schema = "nightshift.diagnostic_inputs.v99".into();
        reseal_inputs(&mut unknown_inputs);
        assert!(unknown_inputs.validate().is_err());

        let mut unknown_artifact = serde_json::to_value(&artifact).unwrap();
        unknown_artifact["schema"] = serde_json::json!("nq.diagnostic_execution.v99");
        assert!(serde_json::from_value::<DiagnosticExecution>(unknown_artifact).is_err());
    }

    #[test]
    fn stale_future_and_state_mismatch_remain_distinct() {
        let artifact = base_artifact();
        let stale = evaluate_posture(
            &policy(&artifact),
            &delivered(artifact.clone()),
            &recurrence(&artifact, None),
            at("2026-07-27T12:03:00Z"),
        )
        .unwrap();
        assert_eq!(stale.assessments[0].standing, Standing::Stale);

        let future_artifact = artifact.clone();
        let future = evaluate_posture(
            &policy(&future_artifact),
            &delivered(future_artifact.clone()),
            &recurrence(
                &future_artifact,
                Some(RunSlotEvidence::Missed {
                    reason: "not run".into(),
                }),
            ),
            at("2026-07-27T12:00:12Z"),
        )
        .unwrap();
        assert_eq!(future.assessments[0].standing, Standing::FutureDated);

        let mut state_policy = policy(&artifact);
        state_policy.inventory[0].required_state_bindings[0].value = "boot:2".into();
        reseal_policy(&mut state_policy);
        let mismatch = evaluate_posture(
            &state_policy,
            &delivered(artifact.clone()),
            &recurrence(&artifact, None),
            at("2026-07-27T12:00:30Z"),
        )
        .unwrap();
        assert_eq!(mismatch.assessments[0].standing, Standing::StateMismatch);
    }

    #[test]
    fn favorable_subset_and_visual_omission_cannot_yield_clean() {
        let artifact = base_artifact();
        let mut policy = policy(&artifact);
        let mut second = policy.inventory[0].clone();
        second.binding.question = semantic("host.network", '9');
        second.binding.profile = semantic("host.network.v1", '0');
        second.binding.claim_id = "claim:network".into();
        policy.inventory.push(second);
        policy.inventory.sort_by_key(|entry| entry.binding.key());
        reseal_policy(&mut policy);
        let posture = evaluate_posture(
            &policy,
            &delivered(artifact.clone()),
            &recurrence(&artifact, None),
            at("2026-07-27T12:00:30Z"),
        )
        .unwrap();
        assert_eq!(posture.completeness, CompletenessAxis::Incomplete);
        assert_eq!(posture.headline, Headline::Incomplete);

        let clean = evaluate_posture(
            &super::tests::policy(&artifact),
            &delivered(artifact.clone()),
            &recurrence(&artifact, None),
            at("2026-07-27T12:00:30Z"),
        )
        .unwrap();
        let omitted = clean.project(&BTreeSet::new());
        assert_eq!(omitted.headline, Headline::Incomplete);
        assert_eq!(omitted.slots[0].visibility, ProjectionVisibility::Omitted);
        assert_eq!(omitted.source_posture_id, clean.posture_id);
    }

    #[test]
    fn duplicate_blocks_while_unexpected_input_stays_visible_without_minting_obligation() {
        let artifact = base_artifact();
        let mut duplicate = delivered(artifact.clone());
        duplicate.inputs.push(duplicate.inputs[0].clone());
        reseal_inputs(&mut duplicate);
        let duplicate_posture = evaluate_posture(
            &policy(&artifact),
            &duplicate,
            &recurrence(&artifact, None),
            at("2026-07-27T12:00:30Z"),
        )
        .unwrap();
        assert_eq!(
            duplicate_posture.assessments[0].standing,
            Standing::DuplicateInput
        );

        let mut unexpected = delivered(artifact.clone());
        unexpected.inputs.push(DiagnosticInput {
            key: DiagnosticKey {
                question_id: "unexpected".into(),
                subject_id: "host:test".into(),
                profile_id: "unexpected.v1".into(),
                vantage_id: "host-local".into(),
            },
            status: DiagnosticInputStatus::NotConfigured,
        });
        reseal_inputs(&mut unexpected);
        let unexpected_posture = evaluate_posture(
            &policy(&artifact),
            &unexpected,
            &recurrence(&artifact, None),
            at("2026-07-27T12:00:30Z"),
        )
        .unwrap();
        assert_eq!(unexpected_posture.unexpected_inputs.len(), 1);
        assert_eq!(unexpected_posture.headline, Headline::Clean);
        assert_eq!(unexpected_posture.assessments.len(), 1);
    }

    #[test]
    fn contradiction_and_partial_coverage_do_not_strengthen() {
        let mut contradictory = base_artifact();
        contradictory.outcome.coherence = CoherenceV1::Contradictory;
        contradictory.outcome.condition = ConditionV1::Unresolved;
        contradictory.claims[0].status = ClaimStatusV1::Contradictory;
        contradictory.claims[0].condition_effect = Some(ConditionV1::Unresolved);
        seal_artifact(&mut contradictory);
        let result = evaluate_posture(
            &policy(&contradictory),
            &delivered(contradictory.clone()),
            &recurrence(&contradictory, None),
            at("2026-07-27T12:00:30Z"),
        )
        .unwrap();
        assert_eq!(result.assessments[0].status, OperatorStatus::Contradictory);
        assert_eq!(result.coverage, CoverageAxis::Complete);
        assert_eq!(result.condition, ConditionAxis::Unresolved);
        assert_eq!(result.headline, Headline::Incomplete);

        let mut partial = base_artifact();
        partial.outcome.coverage = CoverageV1::Partial;
        partial.outcome.condition = ConditionV1::Present;
        partial.claims[0].condition_effect = Some(ConditionV1::Present);
        seal_artifact(&mut partial);
        let result = evaluate_posture(
            &policy(&partial),
            &delivered(partial.clone()),
            &recurrence(&partial, None),
            at("2026-07-27T12:00:30Z"),
        )
        .unwrap();
        assert_eq!(
            result.assessments[0].status,
            OperatorStatus::CoverageNarrowed
        );
        assert_eq!(
            result.assessments[0]
                .nq_trace
                .as_ref()
                .unwrap()
                .outcome
                .condition(),
            ConditionV1::Present
        );
        assert_eq!(result.condition, ConditionAxis::ConditionPresent);
        assert_eq!(result.coverage, CoverageAxis::Narrowed);
        assert_eq!(result.headline, Headline::Incomplete);
    }

    #[test]
    fn headline_does_not_determine_currentness() {
        // Current evidence under a delivery-required policy can still have an
        // Incomplete display headline when delivery was not qualified.
        let artifact = base_artifact();
        let mut delivery_required = policy(&artifact);
        delivery_required.delivery_required = true;
        reseal_policy(&mut delivery_required);
        let mut delivery_failed = recurrence(&artifact, None);
        delivery_failed.delivery = DeliveryStanding::Failed;
        reseal_recurrence(&mut delivery_failed);
        let current_but_incomplete = evaluate_posture(
            &delivery_required,
            &delivered(artifact.clone()),
            &delivery_failed,
            at("2026-07-27T12:00:30Z"),
        )
        .unwrap();

        // A missed exact run slot is genuinely non-current and also renders
        // Incomplete. The shared headline therefore cannot replace the axes.
        let noncurrent = evaluate_posture(
            &policy(&artifact),
            &delivered(artifact.clone()),
            &recurrence(
                &artifact,
                Some(RunSlotEvidence::Missed {
                    reason: "prior slot remained active".into(),
                }),
            ),
            at("2026-07-27T12:00:30Z"),
        )
        .unwrap();

        assert_eq!(current_but_incomplete.headline, Headline::Incomplete);
        assert_eq!(noncurrent.headline, Headline::Incomplete);
        assert!(current_but_incomplete.current);
        assert!(!noncurrent.current);
    }

    #[test]
    fn missed_recurrence_changes_posture_without_mutating_nq_artifact() {
        let artifact = base_artifact();
        let bytes_before = serde_jcs::to_vec(&artifact).unwrap();
        let current_recurrence = recurrence(&artifact, None);
        let current = evaluate_posture(
            &policy(&artifact),
            &delivered(artifact.clone()),
            &current_recurrence,
            at("2026-07-27T12:00:30Z"),
        )
        .unwrap();
        let missed = recurrence(
            &artifact,
            Some(RunSlotEvidence::Missed {
                reason: "prior slot remained active".into(),
            }),
        );
        let missed_posture = evaluate_posture(
            &policy(&artifact),
            &delivered(artifact.clone()),
            &missed,
            at("2026-07-27T12:00:30Z"),
        )
        .unwrap();
        let bytes_after = serde_jcs::to_vec(&artifact).unwrap();
        assert_eq!(bytes_before, bytes_after);
        assert_eq!(current.recurrence_axis, RecurrenceAxis::Current);
        assert_eq!(current.headline, Headline::Clean);
        assert_eq!(missed_posture.recurrence_axis, RecurrenceAxis::Incomplete);
        assert_eq!(
            missed_posture.recurrence[0].standing,
            RecurrenceStanding::Missed
        );
        assert_eq!(missed_posture.headline, Headline::Incomplete);
        assert_ne!(current.posture_id, missed_posture.posture_id);
    }

    #[test]
    fn recurrence_selects_only_the_exact_due_slot_from_retained_history() {
        let artifact = base_artifact();
        let mut recurrence = recurrence(&artifact, None);
        let key = key(&artifact);
        let mut schedule = recurrence.obligations[0].policy.clone();
        schedule.first_due_at = "2026-07-27T11:59:00Z".into();
        recurrence.obligations[0].policy = schedule.clone();

        let current_slot = make_run_slot(&schedule, &key, 1).unwrap();
        let current = RecurrenceRecord {
            key: key.clone(),
            policy: schedule.clone(),
            slot: current_slot.clone(),
            evidence: RunSlotEvidence::Completed {
                attempt: InvocationAttempt {
                    attempt_id: "attempt:current".into(),
                    slot_id: current_slot.slot_id,
                    request_id: artifact.request_id.clone(),
                    started_at: "2026-07-27T12:00:00Z".into(),
                },
                completed_at: artifact.completed_at.clone(),
                artifact: Box::new(artifact_ref(&DiagnosticExecution::V1(artifact.clone()))),
            },
        };
        let historical_slot = make_run_slot(&schedule, &key, 0).unwrap();
        let historical = RecurrenceRecord {
            key,
            policy: schedule,
            slot: historical_slot,
            evidence: RunSlotEvidence::Missed {
                reason: "historical slot was missed".into(),
            },
        };
        recurrence.records = vec![historical, current];
        reseal_recurrence(&mut recurrence);

        let posture = evaluate_posture(
            &policy(&artifact),
            &delivered(artifact),
            &recurrence,
            at("2026-07-27T12:00:30Z"),
        )
        .unwrap();
        assert_eq!(posture.recurrence[0].standing, RecurrenceStanding::Current);
        assert_eq!(posture.recurrence_axis, RecurrenceAxis::Current);
    }

    #[test]
    fn source_acquisition_may_predate_nightshift_invocation() {
        let mut artifact = base_artifact();
        artifact.inputs.received[0].acquisition.started_at = "2026-07-27T11:59:50Z".into();
        artifact.inputs.received[0].acquisition.ended_at = "2026-07-27T11:59:55Z".into();
        seal_artifact(&mut artifact);

        let recurrence = recurrence(&artifact, None);
        let posture = evaluate_posture(
            &policy(&artifact),
            &delivered(artifact.clone()),
            &recurrence,
            at("2026-07-27T12:00:30Z"),
        )
        .unwrap();
        assert_eq!(posture.assessments[0].standing, Standing::Current);
        assert_eq!(posture.recurrence[0].standing, RecurrenceStanding::Current);
        assert_eq!(
            posture.recurrence[0].slot_id,
            Some(recurrence.records[0].slot.slot_id.clone())
        );
        assert_eq!(
            posture.assessments[0]
                .artifact
                .as_ref()
                .unwrap()
                .attempt_interval,
            AcquisitionInterval::V1(artifact.attempt_interval)
        );
    }

    #[test]
    fn deterministic_jitter_and_run_slot_survive_recomputation() {
        let artifact = base_artifact();
        let recurrence = recurrence(&artifact, None);
        let policy = &recurrence.obligations[0].policy;
        let key = key(&artifact);
        assert_eq!(
            deterministic_jitter(policy, &key),
            deterministic_jitter(policy, &key)
        );
        assert_eq!(
            make_run_slot(policy, &key, 0).unwrap(),
            make_run_slot(policy, &key, 0).unwrap()
        );
        assert_ne!(
            make_run_slot(policy, &key, 0).unwrap().slot_id,
            make_run_slot(policy, &key, 1).unwrap().slot_id
        );
    }

    #[test]
    fn fractional_schedule_does_not_advance_a_slot_early() {
        let artifact = base_artifact();
        let key = key(&artifact);
        let schedule = SchedulePolicy {
            schedule_id: "schedule:fractional".into(),
            first_due_at: "2026-07-27T12:00:00.900Z".into(),
            cadence_seconds: 60,
            jitter_bound_seconds: 0,
            max_execution_budget_seconds: 30,
            standing_window_seconds: 130,
        };
        assert_eq!(
            expected_occurrence_at(&schedule, &key, at("2026-07-27T12:01:00.100Z")).unwrap(),
            Some(0)
        );
        assert_eq!(
            expected_occurrence_at(&schedule, &key, at("2026-07-27T12:01:00.900Z")).unwrap(),
            Some(1)
        );
    }

    #[test]
    fn recurrence_attempt_identity_and_fractional_evaluation_time_affect_posture_identity() {
        let artifact = base_artifact();
        let policy = policy(&artifact);
        let inputs = delivered(artifact.clone());
        let original_recurrence = recurrence(&artifact, None);
        let original = evaluate_posture(
            &policy,
            &inputs,
            &original_recurrence,
            at("2026-07-27T12:00:30.100Z"),
        )
        .unwrap();

        let later_fraction = evaluate_posture(
            &policy,
            &inputs,
            &original_recurrence,
            at("2026-07-27T12:00:30.200Z"),
        )
        .unwrap();
        assert_ne!(original.evaluated_at, later_fraction.evaluated_at);
        assert_ne!(original.posture_id, later_fraction.posture_id);

        let mut changed_recurrence = original_recurrence.clone();
        if let RunSlotEvidence::Completed { attempt, .. } =
            &mut changed_recurrence.records[0].evidence
        {
            attempt.attempt_id = "attempt:2".into();
        } else {
            panic!("test fixture must contain a completion");
        }
        reseal_recurrence(&mut changed_recurrence);
        let changed = evaluate_posture(
            &policy,
            &inputs,
            &changed_recurrence,
            at("2026-07-27T12:00:30.100Z"),
        )
        .unwrap();
        assert_ne!(
            original_recurrence.recurrence_id,
            changed_recurrence.recurrence_id
        );
        assert_ne!(original.posture_id, changed.posture_id);
    }

    #[test]
    fn oversized_time_policy_is_refused_without_arithmetic_panic() {
        let artifact = base_artifact();
        let mut policy = policy(&artifact);
        policy.inventory[0].max_age_seconds = u64::MAX;
        reseal_policy(&mut policy);
        assert!(policy.validate().is_err());

        let mut recurrence = recurrence(&artifact, None);
        recurrence.obligations[0].policy.cadence_seconds = u64::MAX;
        recurrence.records[0].policy.cadence_seconds = u64::MAX;
        reseal_recurrence(&mut recurrence);
        assert!(recurrence.validate().is_err());
    }

    #[test]
    fn malformed_policy_and_refused_claim_laundering_are_rejected() {
        let artifact = base_artifact();
        let mut bad_digest = policy(&artifact);
        bad_digest.policy_id = digest('f');
        assert!(bad_digest.validate().is_err());

        let mut empty_claim = policy(&artifact);
        empty_claim.inventory[0].binding.claim_id.clear();
        reseal_policy(&mut empty_claim);
        assert!(empty_claim.validate().is_err());

        let mut unsorted_state = policy(&artifact);
        unsorted_state.inventory[0].required_state_bindings = vec![
            RequiredStateBinding {
                kind: "z".into(),
                value: "1".into(),
            },
            RequiredStateBinding {
                kind: "a".into(),
                value: "1".into(),
            },
        ];
        reseal_policy(&mut unsorted_state);
        assert!(unsorted_state.validate().is_err());

        let mut refused_with_claim = artifact;
        refused_with_claim.primary_claim_id = None;
        refused_with_claim.claims[0].condition_effect = None;
        refused_with_claim.outcome = OutcomeV1 {
            derivation: DerivationV1::Refused,
            condition: ConditionV1::Unresolved,
            coherence: CoherenceV1::Insufficient,
            coverage: CoverageV1::Complete,
            summary: "refused".into(),
            refusal: Some(RefusalV1 {
                code: "policy_refusal".into(),
                reason: "test refusal".into(),
            }),
        };
        seal_artifact(&mut refused_with_claim);
        assert_eq!(
            refused_with_claim.validate().unwrap_err(),
            "refused or unsupported outcome exports claims"
        );
    }

    #[test]
    fn strict_nq_mirror_rejects_unknown_fields_and_wrong_self_id() {
        let artifact = base_artifact();
        let mut value = serde_json::to_value(&artifact).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("authority".into(), serde_json::json!(true));
        assert!(serde_json::from_value::<DiagnosticExecutionV1>(value).is_err());

        let mut substituted = artifact.clone();
        substituted.request_id = "request:substituted".into();
        assert!(substituted.validate().is_err());

        let mut receiver = serde_json::to_value(delivered(artifact)).unwrap();
        receiver["inputs"][0]["authority"] = serde_json::json!(true);
        assert!(serde_json::from_value::<DiagnosticInputs>(receiver).is_err());
    }

    #[test]
    fn operator_text_escapes_line_breaks_from_bounded_source_strings() {
        assert_eq!(
            escaped_inline("unqualified\nheadline: Clean"),
            "unqualified\\nheadline: Clean"
        );
    }
}

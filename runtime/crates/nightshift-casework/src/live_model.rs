use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const CASEWORK_LIVE_RUN_SCHEMA_V1: &str = "nightshift.casework-live-run/v1";
pub const CASEWORK_LIVE_PROVIDER_EXECUTION_SCHEMA_V1: &str =
    "nightshift.casework-live-provider-execution/v1";
pub const CASEWORK_LIVE_PROVIDER_EXECUTION_DIGEST_DOMAIN_V1: &[u8] =
    b"nightshift.casework-live-provider-execution.digest/v1\0";
pub const CASEWORK_LIVE_RUN_INDEX_SCHEMA_V1: &str = "nightshift.casework-live-run-index/v1";
pub const CASEWORK_LIVE_RUN_DIGEST_DOMAIN_V1: &[u8] = b"nightshift.casework-live-run.digest/v1\0";
pub const CASEWORK_LIVE_NAVIGATION_DOMAIN_V1: &[u8] =
    b"nightshift.casework-live-run.navigation/v1\0";
pub const CASEWORK_LIVE_QUESTION_NAVIGATION_DOMAIN_V1: &[u8] =
    b"nightshift.casework-live-question.navigation/v1\0";
pub const FOREMAN_JOURNAL_FRAMING_V1: &[u8] = b"NIGHTSHIFT-FOREMAN-JOURNAL-FRAMING-V1\0";
pub const FOREMAN_ACCEPTED_RECEIPTS_FRAMING_V1: &[u8] =
    b"NIGHTSHIFT-FOREMAN-ACCEPTED-RECEIPTS-FRAMING-V1\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseworkLiveRunV1 {
    pub schema: String,
    pub projection_digest: String,
    pub navigation_id: String,
    pub run_id: String,
    pub evaluated_at: String,
    pub packet: LivePacketV1,
    pub admission: LiveAdmissionV1,
    pub execution_profile: LiveExecutionProfileV1,
    pub foreman: LiveForemanV1,
    pub work_items: Vec<LiveWorkItemV1>,
    pub resource_claims: Vec<LiveResourceClaimV1>,
    pub events: Vec<LiveEventV1>,
    pub raw_sources: LiveRawSourcesV1,
    pub sealed_case_run_id: Option<String>,
    pub provider_capacity: LiveProviderCapacityV1,
    pub authority_effect: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LivePacketV1 {
    pub packet_id: String,
    pub packet_digest: String,
    pub exact_bytes_sha256: String,
    pub integrity: String,
    pub created_at: String,
    pub current_until: String,
    pub currentness: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveAdmissionV1 {
    pub admission_digest: String,
    pub exact_bytes_sha256: String,
    pub admitted_at: String,
    pub expires_at: String,
    pub currentness: String,
    pub maximum_concurrent_workers: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveExecutionProfileV1 {
    pub profile_digest: String,
    pub exact_bytes_sha256: String,
    pub budget_policy_ref: String,
    pub capacity_binding_status: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveForemanV1 {
    pub source_schema: String,
    pub lifecycle: String,
    pub scheduler_state_counts: BTreeMap<String, usize>,
    pub terminal_receipt_count: usize,
    pub not_started_receipt_count: usize,
    pub closed_final_receipts_digest: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveWorkItemV1 {
    pub work_item_id: String,
    pub track: String,
    pub campaign_codename: String,
    pub campaign_slug: String,
    pub dependencies: Vec<String>,
    pub entry_predicates: Vec<String>,
    pub stop_conditions: Vec<String>,
    pub scheduler_state: String,
    pub scheduler_state_recognized: bool,
    pub dependency_terminality: BTreeMap<String, bool>,
    pub resource_lock_keys: Vec<String>,
    pub active_attempt_id: Option<String>,
    pub adapter_id: String,
    pub adapter_version: String,
    pub provider_model_class: String,
    pub provider_identity: Option<String>,
    pub model_identity: Option<String>,
    pub session_identity: Option<String>,
    pub thread_identity: Option<String>,
    pub turn_identity: Option<String>,
    pub queue_identity: Option<String>,
    pub last_event_sequence: Option<u64>,
    pub last_event_digest: Option<String>,
    pub human_questions: Vec<LiveQuestionV1>,
    pub accepted_receipt_kind: Option<String>,
    pub accepted_outcome: Option<LiveAcceptedOutcomeV1>,
    pub accepted_outcome_absent_reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveQuestionV1 {
    pub navigation_id: String,
    pub question_id: String,
    pub question: String,
    pub exhausted_evidence: String,
    pub safe_default: String,
    pub consequences: String,
    pub resume_point: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveAcceptedOutcomeV1 {
    pub state: String,
    pub result_classification: String,
    pub receipt_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveResourceClaimV1 {
    pub resource_lock_key: String,
    pub work_item_id: String,
    pub attempt_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveEventV1 {
    pub sequence: u64,
    pub event_id: String,
    pub work_item_id: Option<String>,
    pub attempt_id: Option<String>,
    pub kind: String,
    pub recorded_at: String,
    pub retained_raw_digest: String,
    pub exact_bytes_sha256: String,
    pub raw_length: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveRawSourcesV1 {
    pub packet_sha256: String,
    pub admission_sha256: String,
    pub profile_sha256: String,
    pub journal_framing_sha256: String,
    pub accepted_receipts_framing_sha256: String,
    pub final_snapshot_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveProviderCapacityV1 {
    pub status: String,
    pub requirement: Option<LiveProviderCapacityRequirementV1>,
    pub attempts: Vec<LiveProviderCapacityAttemptV1>,
    pub explanation: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveProviderCapacityRequirementV1 {
    pub capacity_requirement_digest: String,
    pub exact_bytes_sha256: String,
    pub recorded_at: String,
    pub policy_id: String,
    pub provider_id: String,
    pub model_cost_classes: BTreeMap<String, String>,
    pub authority_effect: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveProviderCapacityAttemptV1 {
    pub journal_sequence: u64,
    pub work_item_id: String,
    pub attempt_id: String,
    pub recorded_at: String,
    pub provider_id: String,
    pub packet_model_class: String,
    pub profile_model_class: String,
    pub cost_class: String,
    pub capacity_state: String,
    pub admission_disposition: String,
    pub source_class: String,
    pub confidence: String,
    pub observation_disposition: String,
    pub observed_at: String,
    pub expires_at: String,
    pub decision_at: String,
    pub evaluated_at: String,
    pub currentness: String,
    pub capacity_admission_digest: String,
    pub observation_digest: String,
    pub policy_digest: String,
    pub decision_digest: String,
    pub admission_exact_bytes_sha256: String,
    pub observation_exact_bytes_sha256: String,
    pub policy_exact_bytes_sha256: String,
    pub decision_exact_bytes_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveProviderDeferralV1 {
    pub journal_sequence: u64,
    pub journal_event_id: String,
    pub journal_exact_bytes_sha256: String,
    pub disposition_digest: String,
    pub deferred_dispatch_digest: String,
    pub work_item_id: String,
    pub work_attempt_id: String,
    pub last_dispatch_occurrence_id: String,
    pub provider_id: String,
    pub model_id: String,
    pub selected_model_ordinal: u16,
    pub remaining_model_ordinals: Vec<u16>,
    pub refusal_received_at: String,
    pub wake_basis: String,
    pub backoff_ordinal: u16,
    pub backoff_seconds: u64,
    pub provider_retry_after: Option<String>,
    pub wake_at: String,
    pub parked_resource_lock_policy: String,
    pub provider_capacity_released: bool,
    pub deferred_exact_bytes_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveProviderWakeV1 {
    pub journal_sequence: u64,
    pub journal_event_id: String,
    pub journal_exact_bytes_sha256: String,
    pub work_item_id: String,
    pub work_attempt_id: String,
    pub wake_occurrence_id: String,
    pub deferred_dispatch_digest: String,
    pub next_dispatch_digest: String,
    pub recorded_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveProviderResumeV1 {
    pub journal_sequence: u64,
    pub journal_event_id: String,
    pub journal_exact_bytes_sha256: String,
    pub work_item_id: String,
    pub work_attempt_id: String,
    pub resume_occurrence_id: String,
    pub disposition_digest: String,
    pub adapter_process_occurrence_id: String,
    pub execution_identity: LiveProviderExecutionIdentityV1,
    pub recorded_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveProviderResourceTransitionV1 {
    pub journal_sequence: u64,
    pub journal_event_id: String,
    pub journal_exact_bytes_sha256: String,
    pub transition: String,
    pub work_item_id: String,
    pub work_attempt_id: String,
    pub dispatch_digest: String,
    pub disposition_digest: Option<String>,
    pub deferred_dispatch_digest: Option<String>,
    pub policy_digest: String,
    pub wake_occurrence_id: Option<String>,
    pub resource_lock_keys: Vec<String>,
    pub recorded_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveProviderModelSelectionV1 {
    pub provider_id: String,
    pub model_id: String,
    pub model_class: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveProviderDispositionV1 {
    pub journal_sequence: u64,
    pub journal_event_id: String,
    pub journal_exact_bytes_sha256: String,
    pub journal_retained_raw_digest: String,
    pub work_item_id: String,
    pub work_attempt_id: String,
    pub dispatch_occurrence_id: String,
    pub dispatch_digest: String,
    pub disposition_digest: String,
    pub reconciles_disposition_digest: Option<String>,
    pub provider_id: String,
    pub model_id: String,
    pub availability_state: String,
    pub admission_disposition: String,
    pub mechanism_state: String,
    pub observed_at: String,
    pub evidence_received_at: String,
    pub expires_at: String,
    pub disposition_received_at: String,
    pub currentness: String,
    pub source_identity: String,
    pub source_version: String,
    pub response_created: bool,
    pub acquisition_complete: bool,
    pub provider_retry_after: Option<String>,
    pub provider_request_occurrence_id: String,
    pub provider_execution: Option<LiveProviderExecutionIdentityV1>,
    pub mapper_snapshot_schema: String,
    pub mapper_snapshot_digest: String,
    pub approval_response_sent: bool,
    pub protected_effect_absent: bool,
    pub observation_digest: String,
    pub observation_exact_bytes_sha256: String,
    pub disposition_exact_bytes_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveProviderExecutionIdentityV1 {
    pub provider_id: String,
    pub model_id: String,
    pub app_server_session_identity: String,
    pub thread_id: String,
    pub turn_id: String,
    pub first_response_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveProviderDispatchV1 {
    pub journal_sequence: u64,
    pub journal_event_id: String,
    pub journal_exact_bytes_sha256: String,
    pub journal_retained_raw_digest: String,
    pub work_item_id: String,
    pub work_attempt_id: String,
    pub dispatch_occurrence_id: String,
    pub dispatch_ordinal: u16,
    pub selected_model_ordinal: u16,
    pub provider_id: String,
    pub model_id: String,
    pub model_class: String,
    pub adapter_id: String,
    pub adapter_version: String,
    pub adapter_protocol: String,
    pub adapter_process_occurrence_id: String,
    pub app_server_session_identity: String,
    pub worker_start_request_digest: String,
    pub worker_brief_digest: String,
    pub dispatch_digest: String,
    pub opened_at: String,
    pub start_request_exact_bytes_sha256: String,
    pub dispatch_exact_bytes_sha256: String,
    pub provider_execution_identity_absent_at_start: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveProviderExecutionRequirementV1 {
    pub journal_sequence: u64,
    pub requirement_digest: String,
    pub policy_id: String,
    pub policy_digest: String,
    pub provider_id: String,
    pub work_item_model_selections: BTreeMap<String, Vec<LiveProviderModelSelectionV1>>,
    pub adapter_id: String,
    pub adapter_protocol: String,
    pub adapter_version: String,
    pub adapter_executable_identity: String,
    pub codex_owner_head: String,
    pub provider_admission_owner_head: String,
    pub provider_admission_schema_sha256: String,
    pub deterministic_fixture_sha256: String,
    pub admitted_at: String,
    pub requirement_exact_bytes_sha256: String,
    pub policy_exact_bytes_sha256: String,
    pub parked_resource_lock_policy: String,
    pub allow_ordered_model_fallback: bool,
    pub automatic_semantic_retry: bool,
    pub approval_response_authorized: bool,
    pub authority_effect: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseworkLiveProviderExecutionV1 {
    pub schema: String,
    pub projection_digest: String,
    pub run_id: String,
    pub packet_digest: String,
    pub evaluated_at: String,
    pub status: String,
    pub requirement: Option<LiveProviderExecutionRequirementV1>,
    pub dispatches: Vec<LiveProviderDispatchV1>,
    pub dispositions: Vec<LiveProviderDispositionV1>,
    pub deferrals: Vec<LiveProviderDeferralV1>,
    pub wakes: Vec<LiveProviderWakeV1>,
    pub resumes: Vec<LiveProviderResumeV1>,
    pub resource_transitions: Vec<LiveProviderResourceTransitionV1>,
    pub independent_provider_capacity_status: String,
    pub explanation: String,
    pub authority_effect: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseworkLiveRunIndexV1 {
    pub schema: String,
    pub runs: Vec<CaseworkLiveRunIndexEntryV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseworkLiveRunIndexEntryV1 {
    pub navigation_id: String,
    pub run_id: String,
    pub projection_digest: String,
    pub packet_id: String,
    pub packet_digest: String,
    pub lifecycle: String,
    pub sealed_case_run_id: Option<String>,
    pub scheduler_state_counts: BTreeMap<String, usize>,
}

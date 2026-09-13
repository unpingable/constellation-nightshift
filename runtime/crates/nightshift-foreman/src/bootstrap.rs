//! Closed, non-authorizing contract for one bounded self-hosted foreman bootstrap.
//!
//! This module freezes the SECOND-WATCH admission graph. It deliberately does
//! not start a scheduler, adapter, provider, timer, browser, or service.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use nightshift_provider_capacity::CapacityPolicyV1;
use nightshiftd::packet::NightshiftPacketV1;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::{
    ContractError, ExecutionAvailabilityPolicyV1, ExecutionProfileV2, ForemanAdmissionV1,
    ForemanCapacityRequirementV1, ForemanExecutionAvailabilityRequirementV1,
    ACCEPTED_CODEX_PROVIDER_ADMISSION_OWNER_HEAD,
    ACCEPTED_SWITCHYARD_PROVIDER_ADMISSION_OWNER_HEAD,
    DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V1,
    DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V2, HOLDING_QUALIFICATION_EXECUTABLE_SHA256,
    HOLDING_QUALIFICATION_PRODUCER_ID, HOLDING_QUALIFICATION_PRODUCER_VERSION,
    SECOND_WATCH_QUALIFICATION_EXECUTABLE_SHA256, SECOND_WATCH_QUALIFICATION_PRODUCER_VERSION,
};

pub const SELF_HOSTED_FOREMAN_BOOTSTRAP_SCHEMA_V1: &str =
    "nightshift.self-hosted-foreman-bootstrap/v1";
pub const SELF_HOSTED_FOREMAN_DRIVER_STEP_SCHEMA_V1: &str =
    "nightshift.self-hosted-foreman-driver-step/v1";
pub const SELF_HOSTED_FOREMAN_BOOTSTRAP_DIGEST_PREIMAGE_V1: &str =
    "domain prefix nightshift.self-hosted-foreman-bootstrap.digest/v1 NUL, then the bootstrap object with bootstrap_digest omitted as RFC8785-JCS";
pub const SECOND_WATCH_CANONICAL_SLUG: &str = "nightshift-self-hosted-foreman-bootstrap-v1";
pub const SECOND_WATCH_HOLDING_RESULT_HEAD: &str = "0dff82fa3522e59a6ce8e8161f6aed92cbacc061";
pub const SECOND_WATCH_HOLDING_QUALIFIED_SUBJECT: &str = "57c165fb246a530bc9448afbe3a26c17a5118ebd";
pub const SECOND_WATCH_DURABLE_ROADMAP_HEAD: &str = "70e3b734e979173ae552efb322b48bf7fb0c028b";
pub const SECOND_WATCH_MIDNIGHT_RESULT_HEAD: &str = "6160a7fac9845aaefefbc11847e55786b35749e6";
pub const SECOND_WATCH_SILICON_RESULT_HEAD: &str = "f6e95c8a51982a9381c27c4792c8d9fd6f1daf47";
pub const SECOND_WATCH_PREDECESSOR_V2_PACKET_DIGEST: &str =
    "sha256:1df7f47bb3ea70d0f987e756f34aaa62f7187a659ef0bcc8d7c8aa2e645431fc";

const BOOTSTRAP_DOMAIN: &[u8] = b"nightshift.self-hosted-foreman-bootstrap.digest/v1\0";
const DRIVER_STEP_DOMAIN: &[u8] = b"nightshift.self-hosted-foreman-driver-step.digest/v1\0";

/// One exact, bounded operator invocation admitted to hand scheduling custody
/// to the durable foreman. The record is mechanism input, not authority or a
/// campaign classification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfHostedForemanBootstrapV1 {
    pub schema: String,
    pub bootstrap_digest: String,
    pub digest_preimage: String,
    pub campaign_codename: String,
    pub canonical_slug: String,
    pub track: String,
    pub holding_result_head: String,
    pub holding_qualified_subject: String,
    pub durable_roadmap_head: String,
    pub midnight_result_head: String,
    pub silicon_result_head: String,
    pub codex_owner_head: String,
    pub switchyard_owner_head: String,
    pub bootstrap_occurrence_id: String,
    pub run_id: String,
    pub packet_id: String,
    pub packet_digest: String,
    pub predecessor_v2_packet_digest: String,
    pub admission_digest: String,
    pub profile_digest: String,
    pub capacity_requirement_digest: String,
    pub capacity_policy_digest: String,
    pub execution_availability_requirement_digest: String,
    pub execution_availability_policy_digest: String,
    pub local_runtime_identity: String,
    pub evaluated_at: DateTime<Utc>,
    pub expected_work_item_count: u16,
    pub initially_runnable_lane_count: u16,
    pub presentation_only_question_work_item_id: String,
    pub maximum_driver_steps: u32,
    pub maximum_wall_seconds: u32,
    pub bootstrap_depth: u8,
    pub parent_bootstrap_occurrence_id: Option<String>,
    pub scheduler_owner: String,
    pub worker_adapter_mode: String,
    pub wake_source_policy: String,
    pub closeout_policy: String,
    pub authority_effect: String,
    pub target_effects_authorized: bool,
    pub approval_response_authorized: bool,
    pub protected_effect_authorized: bool,
    pub semantic_retry_authorized: bool,
    pub bootstrap_may_nest: bool,
    pub worker_may_invoke_bootstrap: bool,
    pub outer_conversation_scheduler: bool,
    pub timer_or_service_activation_authorized: bool,
    pub production_activation_authorized: bool,
    pub aggregate_result_created: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SelfHostedDriverDispositionV1 {
    ReadyWorkPresent,
    WaitingForExactOwnerEvidence,
    AllItemsExplicitTerminal,
    BoundReached,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfHostedForemanDriverStepV1 {
    pub schema: String,
    pub step_digest: String,
    pub bootstrap_digest: String,
    pub bootstrap_occurrence_id: String,
    pub run_id: String,
    pub step_ordinal: u32,
    pub scheduler_process_occurrence_id: String,
    pub observed_projection_digest: String,
    pub disposition: SelfHostedDriverDispositionV1,
    pub recorded_at: DateTime<Utc>,
    pub worker_dispatch_authorized: bool,
    pub approval_response_authorized: bool,
    pub protected_effect_authorized: bool,
    pub semantic_retry_authorized: bool,
    pub aggregate_result_created: bool,
}

impl SelfHostedForemanBootstrapV1 {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ContractError> {
        let value: Value = serde_json::from_slice(bytes)
            .map_err(|error| ContractError::Json(error.to_string()))?;
        canonical_timestamp(&value, "evaluated_at")?;
        let record: Self = serde_json::from_value(value)
            .map_err(|error| ContractError::Json(error.to_string()))?;
        if serde_jcs::to_vec(&record).map_err(|error| ContractError::Json(error.to_string()))?
            != bytes
        {
            return Err(ContractError::InvalidField("bootstrap canonical bytes"));
        }
        Ok(record)
    }

    pub fn seal(&mut self) -> Result<(), ContractError> {
        self.bootstrap_digest = digest_without(self, "bootstrap_digest", BOOTSTRAP_DOMAIN)?;
        self.validate()
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema != SELF_HOSTED_FOREMAN_BOOTSTRAP_SCHEMA_V1 {
            return Err(ContractError::ForeignSchema(self.schema.clone()));
        }
        for (field, value) in [
            ("bootstrap_digest", self.bootstrap_digest.as_str()),
            ("packet_digest", self.packet_digest.as_str()),
            (
                "predecessor_v2_packet_digest",
                self.predecessor_v2_packet_digest.as_str(),
            ),
            ("admission_digest", self.admission_digest.as_str()),
            ("profile_digest", self.profile_digest.as_str()),
            (
                "capacity_requirement_digest",
                self.capacity_requirement_digest.as_str(),
            ),
            (
                "capacity_policy_digest",
                self.capacity_policy_digest.as_str(),
            ),
            (
                "execution_availability_requirement_digest",
                self.execution_availability_requirement_digest.as_str(),
            ),
            (
                "execution_availability_policy_digest",
                self.execution_availability_policy_digest.as_str(),
            ),
        ] {
            digest(field, value)?;
        }
        if digest_without(self, "bootstrap_digest", BOOTSTRAP_DOMAIN)? != self.bootstrap_digest {
            return Err(ContractError::DigestMismatch("bootstrap_digest"));
        }
        for (field, value) in [
            (
                "bootstrap_occurrence_id",
                self.bootstrap_occurrence_id.as_str(),
            ),
            ("run_id", self.run_id.as_str()),
            ("packet_id", self.packet_id.as_str()),
            (
                "local_runtime_identity",
                self.local_runtime_identity.as_str(),
            ),
            (
                "presentation_only_question_work_item_id",
                self.presentation_only_question_work_item_id.as_str(),
            ),
        ] {
            id(field, value)?;
        }
        if self.bootstrap_occurrence_id == self.run_id {
            return Err(ContractError::InvalidField(
                "bootstrap/run identity separation",
            ));
        }
        for (field, value) in [
            ("holding_result_head", self.holding_result_head.as_str()),
            (
                "holding_qualified_subject",
                self.holding_qualified_subject.as_str(),
            ),
            ("durable_roadmap_head", self.durable_roadmap_head.as_str()),
            ("midnight_result_head", self.midnight_result_head.as_str()),
            ("silicon_result_head", self.silicon_result_head.as_str()),
            ("codex_owner_head", self.codex_owner_head.as_str()),
            ("switchyard_owner_head", self.switchyard_owner_head.as_str()),
        ] {
            commit(field, value)?;
        }
        if self.digest_preimage != SELF_HOSTED_FOREMAN_BOOTSTRAP_DIGEST_PREIMAGE_V1
            || self.campaign_codename != "SECOND-WATCH"
            || self.canonical_slug != SECOND_WATCH_CANONICAL_SLUG
            || self.track != "nightshift-self-hosting"
            || self.holding_result_head != SECOND_WATCH_HOLDING_RESULT_HEAD
            || self.holding_qualified_subject != SECOND_WATCH_HOLDING_QUALIFIED_SUBJECT
            || self.durable_roadmap_head != SECOND_WATCH_DURABLE_ROADMAP_HEAD
            || self.midnight_result_head != SECOND_WATCH_MIDNIGHT_RESULT_HEAD
            || self.silicon_result_head != SECOND_WATCH_SILICON_RESULT_HEAD
            || self.codex_owner_head != ACCEPTED_CODEX_PROVIDER_ADMISSION_OWNER_HEAD
            || self.switchyard_owner_head != ACCEPTED_SWITCHYARD_PROVIDER_ADMISSION_OWNER_HEAD
            || self.predecessor_v2_packet_digest != SECOND_WATCH_PREDECESSOR_V2_PACKET_DIGEST
            || self.packet_digest == self.predecessor_v2_packet_digest
        {
            return Err(ContractError::InvalidField("bootstrap predecessor custody"));
        }
        if !(3..=1024).contains(&self.expected_work_item_count)
            || !(2..=self.expected_work_item_count).contains(&self.initially_runnable_lane_count)
            || self.maximum_driver_steps == 0
            || self.maximum_driver_steps > 1_000_000
            || self.maximum_wall_seconds == 0
            || self.maximum_wall_seconds > 86_400
        {
            return Err(ContractError::InvalidField("bootstrap bounds"));
        }
        if self.bootstrap_depth != 0
            || self.parent_bootstrap_occurrence_id.is_some()
            || self.scheduler_owner != "NIGHTSHIFT_DURABLE_FOREMAN"
            || self.worker_adapter_mode != "CAMPAIGN_QUALIFICATION_DETERMINISTIC_FAKE"
            || self.wake_source_policy != "QUALIFIED_LOCAL_REEVALUATION_NO_EVIDENCE_OR_AUTHORITY"
            || self.closeout_policy != "ALL_EXPLICIT_TERMINAL_OR_NOT_STARTED"
            || self.authority_effect != "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY"
            || self.target_effects_authorized
            || self.approval_response_authorized
            || self.protected_effect_authorized
            || self.semantic_retry_authorized
            || self.bootstrap_may_nest
            || self.worker_may_invoke_bootstrap
            || self.outer_conversation_scheduler
            || self.timer_or_service_activation_authorized
            || self.production_activation_authorized
            || self.aggregate_result_created
        {
            return Err(ContractError::InvalidField(
                "bootstrap authority and recursion boundary",
            ));
        }
        Ok(())
    }

    /// Reopen and cross-bind every exact input before any runtime store may be
    /// created or mutated. This function performs no I/O and has no scheduler
    /// or provider side effect.
    #[allow(clippy::too_many_arguments)]
    pub fn validate_graph(
        &self,
        packet_bytes: &[u8],
        admission_bytes: &[u8],
        profile_bytes: &[u8],
        capacity_requirement_bytes: &[u8],
        capacity_policy_bytes: &[u8],
        availability_requirement_bytes: &[u8],
        availability_policy_bytes: &[u8],
    ) -> Result<(), ContractError> {
        self.validate()?;
        let packet = NightshiftPacketV1::from_slice(packet_bytes)
            .map_err(|_| ContractError::InvalidField("bootstrap packet"))?;
        packet
            .validate_at(self.evaluated_at)
            .map_err(|_| ContractError::InvalidField("bootstrap packet"))?;
        canonical_bytes("bootstrap packet bytes", &packet, packet_bytes)?;
        let admission = ForemanAdmissionV1::from_slice(admission_bytes)?;
        admission.validate_at(self.evaluated_at)?;
        canonical_bytes("bootstrap admission bytes", &admission, admission_bytes)?;
        let profile = ExecutionProfileV2::from_slice(profile_bytes)?;
        profile.validate()?;
        canonical_bytes("bootstrap profile bytes", &profile, profile_bytes)?;
        let capacity_requirement =
            ForemanCapacityRequirementV1::from_slice(capacity_requirement_bytes)?;
        capacity_requirement.validate()?;
        canonical_bytes(
            "bootstrap capacity requirement bytes",
            &capacity_requirement,
            capacity_requirement_bytes,
        )?;
        let capacity_policy: CapacityPolicyV1 = serde_json::from_slice(capacity_policy_bytes)
            .map_err(|error| ContractError::Json(error.to_string()))?;
        capacity_policy
            .validate()
            .map_err(|_| ContractError::InvalidField("bootstrap capacity policy"))?;
        canonical_bytes(
            "bootstrap capacity policy bytes",
            &capacity_policy,
            capacity_policy_bytes,
        )?;
        let availability_requirement =
            ForemanExecutionAvailabilityRequirementV1::from_slice(availability_requirement_bytes)?;
        availability_requirement.validate()?;
        canonical_bytes(
            "bootstrap availability requirement bytes",
            &availability_requirement,
            availability_requirement_bytes,
        )?;
        let availability_policy =
            ExecutionAvailabilityPolicyV1::from_slice(availability_policy_bytes)?;
        availability_policy.validate()?;
        canonical_bytes(
            "bootstrap availability policy bytes",
            &availability_policy,
            availability_policy_bytes,
        )?;

        if self.packet_id != packet.packet_id
            || self.packet_digest != packet.packet_digest
            || self.run_id != admission.run_id
            || self.packet_digest != admission.packet_digest
            || self.admission_digest != admission.admission_digest
            || self.local_runtime_identity != admission.local_runtime_identity
            || self.packet_digest != profile.packet_digest
            || self.admission_digest != profile.admission_digest
            || self.profile_digest != profile.profile_digest
            || self.capacity_requirement_digest != capacity_requirement.capacity_requirement_digest
            || self.capacity_policy_digest != capacity_policy.policy_digest
            || self.execution_availability_requirement_digest
                != availability_requirement.requirement_digest
            || self.execution_availability_policy_digest != availability_policy.policy_digest
        {
            return Err(ContractError::InvalidField("bootstrap exact input binding"));
        }
        if capacity_requirement.packet_digest != self.packet_digest
            || capacity_requirement.admission_digest != self.admission_digest
            || capacity_requirement.profile_digest != self.profile_digest
            || capacity_requirement.run_id != self.run_id
            || capacity_requirement.policy_id != capacity_policy.policy_id
            || profile.budget_policy_ref != capacity_policy.policy_id
            || availability_requirement.packet_digest != self.packet_digest
            || availability_requirement.admission_digest != self.admission_digest
            || availability_requirement.profile_digest != self.profile_digest
            || availability_requirement.run_id != self.run_id
            || availability_requirement.policy_id != availability_policy.policy_id
            || availability_requirement.policy_digest != availability_policy.policy_digest
            || availability_requirement.admitted_at != admission.admitted_at
        {
            return Err(ContractError::InvalidField("bootstrap mechanism graph"));
        }
        let packet_items: BTreeSet<&str> = packet
            .work_items
            .iter()
            .map(|item| item.id.as_str())
            .collect();
        let profile_items: BTreeSet<&str> = profile.work_items.keys().map(String::as_str).collect();
        let availability_items: BTreeSet<&str> = availability_requirement
            .work_item_model_selections
            .keys()
            .map(String::as_str)
            .collect();
        let profile_model_classes: BTreeSet<&str> = profile
            .work_items
            .values()
            .map(|work| work.provider_model_class.as_str())
            .collect();
        let admitted_model_classes: BTreeSet<&str> = admission
            .allowed_provider_model_classes
            .iter()
            .map(String::as_str)
            .collect();
        let capacity_model_classes: BTreeSet<&str> = capacity_requirement
            .model_cost_classes
            .keys()
            .map(String::as_str)
            .collect();
        let runnable = packet
            .work_items
            .iter()
            .filter(|item| item.dependencies.is_empty())
            .count();
        if packet.work_items.len() != usize::from(self.expected_work_item_count)
            || runnable != usize::from(self.initially_runnable_lane_count)
            || packet_items != profile_items
            || packet_items != availability_items
            || profile_model_classes != admitted_model_classes
            || profile_model_classes != capacity_model_classes
            || !packet_items.contains(self.presentation_only_question_work_item_id.as_str())
            || packet
                .work_items
                .iter()
                .any(|item| item.campaign.canonical_slug == SECOND_WATCH_CANONICAL_SLUG)
            || !packet.worker_budget.recursive_worker_swarms_forbidden
            || packet.worker_budget.maximum_concurrent_mutating_workers < 2
            || admission.maximum_concurrent_workers < 2
            || admission.maximum_concurrent_workers
                > packet.worker_budget.maximum_concurrent_mutating_workers
        {
            return Err(ContractError::InvalidField("bootstrap packet topology"));
        }
        if profile.adapters.len() != 1
            || admission.allowed_adapter_ids != [availability_requirement.adapter_id.clone()]
        {
            return Err(ContractError::InvalidField("bootstrap adapter closure"));
        }
        let adapter = profile
            .adapters
            .get(&availability_requirement.adapter_id)
            .ok_or(ContractError::InvalidField("bootstrap adapter closure"))?;
        if adapter.protocol != availability_requirement.adapter_protocol
            || adapter.adapter_version != availability_requirement.adapter_version
            || adapter.executable_identity != availability_requirement.adapter_executable_identity
            || profile
                .work_items
                .values()
                .any(|work| work.adapter_id != adapter.adapter_id)
        {
            return Err(ContractError::InvalidField("bootstrap adapter closure"));
        }
        let exact_v1 = adapter.adapter_id == HOLDING_QUALIFICATION_PRODUCER_ID
            && adapter.protocol == DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V1
            && adapter.adapter_version == HOLDING_QUALIFICATION_PRODUCER_VERSION
            && adapter.executable_identity == HOLDING_QUALIFICATION_EXECUTABLE_SHA256;
        let exact_v2 = adapter.adapter_id == HOLDING_QUALIFICATION_PRODUCER_ID
            && adapter.protocol == DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V2
            && adapter.adapter_version == SECOND_WATCH_QUALIFICATION_PRODUCER_VERSION
            && adapter.executable_identity == SECOND_WATCH_QUALIFICATION_EXECUTABLE_SHA256;
        if !(exact_v1 || exact_v2) || !adapter.bounded_arguments.is_empty() {
            return Err(ContractError::InvalidField(
                "bootstrap accepted qualification adapter",
            ));
        }
        for item in &packet.work_items {
            let work = &profile.work_items[&item.id];
            if work.provider_model_class != item.model_routing.class
                || !capacity_requirement
                    .model_cost_classes
                    .contains_key(&work.provider_model_class)
                || availability_requirement.work_item_model_selections[&item.id]
                    .iter()
                    .any(|selection| {
                        selection.provider_id != capacity_requirement.provider_id
                            || selection.model_class != work.provider_model_class
                    })
            {
                return Err(ContractError::InvalidField("bootstrap model graph"));
            }
        }
        Ok(())
    }
}

impl SelfHostedForemanDriverStepV1 {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ContractError> {
        let value: Value = serde_json::from_slice(bytes)
            .map_err(|error| ContractError::Json(error.to_string()))?;
        canonical_timestamp(&value, "recorded_at")?;
        let record: Self = serde_json::from_value(value)
            .map_err(|error| ContractError::Json(error.to_string()))?;
        canonical_bytes("driver step canonical bytes", &record, bytes)?;
        record.validate()?;
        Ok(record)
    }

    pub fn seal(&mut self) -> Result<(), ContractError> {
        self.step_digest = digest_without(self, "step_digest", DRIVER_STEP_DOMAIN)?;
        self.validate()
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema != SELF_HOSTED_FOREMAN_DRIVER_STEP_SCHEMA_V1 {
            return Err(ContractError::ForeignSchema(self.schema.clone()));
        }
        digest("step_digest", &self.step_digest)?;
        digest("bootstrap_digest", &self.bootstrap_digest)?;
        digest(
            "observed_projection_digest",
            &self.observed_projection_digest,
        )?;
        id("bootstrap_occurrence_id", &self.bootstrap_occurrence_id)?;
        id("run_id", &self.run_id)?;
        id(
            "scheduler_process_occurrence_id",
            &self.scheduler_process_occurrence_id,
        )?;
        if self.step_ordinal == 0
            || self.step_ordinal > 1_000_000
            || self.worker_dispatch_authorized
            || self.approval_response_authorized
            || self.protected_effect_authorized
            || self.semantic_retry_authorized
            || self.aggregate_result_created
            || digest_without(self, "step_digest", DRIVER_STEP_DOMAIN)? != self.step_digest
        {
            return Err(ContractError::InvalidField("driver step boundary"));
        }
        Ok(())
    }
}
fn canonical_bytes<T: Serialize>(
    field: &'static str,
    record: &T,
    raw: &[u8],
) -> Result<(), ContractError> {
    if serde_jcs::to_vec(record).map_err(|error| ContractError::Json(error.to_string()))? != raw {
        return Err(ContractError::InvalidField(field));
    }
    Ok(())
}

fn digest_without<T: Serialize>(
    record: &T,
    field: &'static str,
    domain: &[u8],
) -> Result<String, ContractError> {
    let mut value =
        serde_json::to_value(record).map_err(|error| ContractError::Json(error.to_string()))?;
    value
        .as_object_mut()
        .ok_or(ContractError::InvalidField("bootstrap record"))?
        .remove(field);
    let canonical =
        serde_jcs::to_vec(&value).map_err(|error| ContractError::Json(error.to_string()))?;
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(canonical);
    Ok(format!("sha256:{:x}", digest.finalize()))
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
    if serde_json::to_value(parsed)
        .map_err(|error| ContractError::Json(error.to_string()))?
        .as_str()
        != Some(raw)
    {
        return Err(ContractError::InvalidField(field));
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

fn commit(field: &'static str, value: &str) -> Result<(), ContractError> {
    if value.len() != 40
        || !value
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

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use nightshiftd::packet::{GlobalConstraintsV1, NightshiftPacketV1, WorkItemV1};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    FOREMAN_ADMISSION_SCHEMA_V1, FOREMAN_CAPACITY_ADMISSION_SCHEMA_V1,
    FOREMAN_CAPACITY_REQUIREMENT_SCHEMA_V1, FOREMAN_EXECUTION_PROFILE_SCHEMA_V2,
    FOREMAN_EXECUTION_PROFILE_SCHEMA_V3, MAXIMUM_ADAPTER_TIMEOUT_SECONDS,
    MAXIMUM_PREDECESSOR_RECEIPTS, MAXIMUM_WORKER_BRIEF_BYTES, MAXIMUM_WORKER_OUTPUT_BYTES,
    WORKER_ADAPTER_CAPABILITIES_SCHEMA_V1, WORKER_ADAPTER_EVENT_SCHEMA_V1,
    WORKER_ATTEMPT_BINDING_SCHEMA_V1, WORKER_BRIEF_BASIS_SCHEMA_V2, WORKER_START_REQUEST_SCHEMA_V2,
    WORKER_TERMINAL_RECEIPT_SCHEMA_V1, WORK_ITEM_NOT_STARTED_RECEIPT_SCHEMA_V1,
};

const ADMISSION_DOMAIN: &[u8] = b"nightshift.foreman-admission.digest/v1\0";
const CAPACITY_ADMISSION_DOMAIN: &[u8] = b"nightshift.foreman-capacity-admission.digest/v1\0";
const CAPACITY_REQUIREMENT_DOMAIN: &[u8] = b"nightshift.foreman-capacity-requirement.digest/v1\0";
const PROFILE_DOMAIN_V2: &[u8] = b"nightshift.foreman-execution-profile.digest/v2\0";
const PROFILE_DOMAIN_V3: &[u8] = b"nightshift.foreman-execution-profile.digest/v3\0";
const START_DOMAIN_V2: &[u8] = b"nightshift.worker-start-request.digest/v2\0";
const EVENT_DOMAIN: &[u8] = b"nightshift.worker-adapter-event.digest/v1\0";
const TERMINAL_DOMAIN: &[u8] = b"nightshift.worker-terminal-receipt.digest/v1\0";
const NOT_STARTED_DOMAIN: &[u8] = b"nightshift.work-item-not-started-receipt.digest/v1\0";
const RETAINED_RAW_DOMAIN: &[u8] = b"nightshift.foreman-retained-raw.digest/v1\0";
const CAPABILITIES_RAW_DOMAIN: &[u8] = b"nightshift.worker-adapter-capabilities.raw/v1\0";
const WORKER_BRIEF_DOMAIN_V2: &[u8] = b"nightshift.worker-brief.digest/v2\0";

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum ContractError {
    #[error("invalid JSON: {0}")]
    Json(String),
    #[error("foreign schema: {0}")]
    ForeignSchema(String),
    #[error("invalid field: {0}")]
    InvalidField(&'static str),
    #[error("digest mismatch: {0}")]
    DigestMismatch(&'static str),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForemanAdmissionV1 {
    pub schema: String,
    pub admission_digest: String,
    pub run_id: String,
    pub packet_digest: String,
    pub operator_basis_digest: String,
    pub admitted_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub local_runtime_identity: String,
    pub maximum_concurrent_workers: u16,
    pub allowed_adapter_ids: Vec<String>,
    pub allowed_provider_model_classes: Vec<String>,
    pub maximum_new_attempts_per_work_item: u16,
    pub authority_effect: String,
    pub target_effects_authorized: bool,
}

impl ForemanAdmissionV1 {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ContractError> {
        parse(bytes)
    }
    pub fn seal(&mut self) -> Result<(), ContractError> {
        self.admission_digest = digest_without(self, "admission_digest", ADMISSION_DOMAIN)?;
        self.validate()
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        schema(&self.schema, FOREMAN_ADMISSION_SCHEMA_V1)?;
        digest("admission_digest", &self.admission_digest)?;
        if digest_without(self, "admission_digest", ADMISSION_DOMAIN)? != self.admission_digest {
            return Err(ContractError::DigestMismatch("admission_digest"));
        }
        id("run_id", &self.run_id)?;
        digest("packet_digest", &self.packet_digest)?;
        digest("operator_basis_digest", &self.operator_basis_digest)?;
        id("local_runtime_identity", &self.local_runtime_identity)?;
        if self.admitted_at >= self.expires_at
            || self.maximum_concurrent_workers == 0
            || self.maximum_concurrent_workers > 4
            || self.maximum_new_attempts_per_work_item != 1
        {
            return Err(ContractError::InvalidField("admission bounds"));
        }
        unique_ids("allowed_adapter_ids", &self.allowed_adapter_ids)?;
        unique_ids(
            "allowed_provider_model_classes",
            &self.allowed_provider_model_classes,
        )?;
        if self.authority_effect != "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY"
            || self.target_effects_authorized
        {
            return Err(ContractError::InvalidField("authority boundary"));
        }
        Ok(())
    }
    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<(), ContractError> {
        self.validate()?;
        if now < self.admitted_at || now > self.expires_at {
            return Err(ContractError::InvalidField("admission expired"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapacityCostClassV1 {
    Cheap,
    Expensive,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForemanCapacityRequirementV1 {
    pub schema: String,
    pub capacity_requirement_digest: String,
    pub packet_digest: String,
    pub admission_digest: String,
    pub profile_digest: String,
    pub run_id: String,
    pub policy_id: String,
    pub provider_id: String,
    pub model_cost_classes: BTreeMap<String, CapacityCostClassV1>,
    pub authority_effect: String,
}

impl ForemanCapacityRequirementV1 {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ContractError> {
        parse(bytes)
    }

    pub fn seal(&mut self) -> Result<(), ContractError> {
        self.capacity_requirement_digest = digest_without(
            self,
            "capacity_requirement_digest",
            CAPACITY_REQUIREMENT_DOMAIN,
        )?;
        self.validate()
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        schema(&self.schema, FOREMAN_CAPACITY_REQUIREMENT_SCHEMA_V1)?;
        for (name, value) in [
            (
                "capacity_requirement_digest",
                self.capacity_requirement_digest.as_str(),
            ),
            ("packet_digest", self.packet_digest.as_str()),
            ("admission_digest", self.admission_digest.as_str()),
            ("profile_digest", self.profile_digest.as_str()),
        ] {
            digest(name, value)?;
        }
        for (name, value) in [
            ("run_id", self.run_id.as_str()),
            ("policy_id", self.policy_id.as_str()),
            ("provider_id", self.provider_id.as_str()),
        ] {
            id(name, value)?;
        }
        if self.model_cost_classes.is_empty() || self.model_cost_classes.len() > 16 {
            return Err(ContractError::InvalidField("capacity model-class map"));
        }
        for (model, cost) in &self.model_cost_classes {
            id("capacity model class", model)?;
            if capacity_cost_class(model)? != *cost {
                return Err(ContractError::InvalidField("capacity model-class map"));
            }
        }
        if self.authority_effect != "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY" {
            return Err(ContractError::InvalidField("capacity authority effect"));
        }
        if digest_without(
            self,
            "capacity_requirement_digest",
            CAPACITY_REQUIREMENT_DOMAIN,
        )? != self.capacity_requirement_digest
        {
            return Err(ContractError::DigestMismatch("capacity_requirement_digest"));
        }
        Ok(())
    }
}

fn capacity_cost_class(value: &str) -> Result<CapacityCostClassV1, ContractError> {
    match value {
        "small" | "bounded" => Ok(CapacityCostClassV1::Cheap),
        "medium" | "large" => Ok(CapacityCostClassV1::Expensive),
        _ => Err(ContractError::InvalidField("capacity model-class mapping")),
    }
}

/// Exact local scheduling admission under one retained capacity decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForemanCapacityAdmissionV1 {
    pub schema: String,
    pub capacity_admission_digest: String,
    pub packet_digest: String,
    pub admission_digest: String,
    pub profile_digest: String,
    pub capacity_requirement_digest: String,
    pub run_id: String,
    pub work_item_id: String,
    pub adapter_id: String,
    pub provider_id: String,
    pub packet_model_class: String,
    pub profile_model_class: String,
    pub cost_class: CapacityCostClassV1,
    pub policy_id: String,
    pub observation_digest: String,
    pub policy_digest: String,
    pub decision_digest: String,
    pub evaluated_at: DateTime<Utc>,
    pub speculative_requested: bool,
    pub authority_effect: String,
}

impl ForemanCapacityAdmissionV1 {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ContractError> {
        let value: Value = parse(bytes)?;
        canonical_timestamp_value("evaluated_at", &value)?;
        serde_json::from_value(value).map_err(json_error)
    }

    pub fn seal(&mut self) -> Result<(), ContractError> {
        self.capacity_admission_digest =
            digest_without(self, "capacity_admission_digest", CAPACITY_ADMISSION_DOMAIN)?;
        self.validate()
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        schema(&self.schema, FOREMAN_CAPACITY_ADMISSION_SCHEMA_V1)?;
        for (name, value) in [
            ("packet_digest", self.packet_digest.as_str()),
            ("admission_digest", self.admission_digest.as_str()),
            ("profile_digest", self.profile_digest.as_str()),
            (
                "capacity_requirement_digest",
                self.capacity_requirement_digest.as_str(),
            ),
            ("observation_digest", self.observation_digest.as_str()),
            ("policy_digest", self.policy_digest.as_str()),
            ("decision_digest", self.decision_digest.as_str()),
            (
                "capacity_admission_digest",
                self.capacity_admission_digest.as_str(),
            ),
        ] {
            digest(name, value)?;
        }
        for (name, value) in [
            ("run_id", self.run_id.as_str()),
            ("work_item_id", self.work_item_id.as_str()),
            ("adapter_id", self.adapter_id.as_str()),
            ("provider_id", self.provider_id.as_str()),
            ("packet_model_class", self.packet_model_class.as_str()),
            ("profile_model_class", self.profile_model_class.as_str()),
            ("policy_id", self.policy_id.as_str()),
        ] {
            id(name, value)?;
        }
        if self.packet_model_class != self.profile_model_class {
            return Err(ContractError::InvalidField("capacity model-class binding"));
        }
        let expected = capacity_cost_class(&self.packet_model_class)?;
        if self.cost_class != expected {
            return Err(ContractError::InvalidField("capacity cost class"));
        }
        if self.speculative_requested {
            return Err(ContractError::InvalidField(
                "speculative capacity admission is unbound",
            ));
        }
        if self.authority_effect != "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY" {
            return Err(ContractError::InvalidField("capacity authority effect"));
        }
        if digest_without(self, "capacity_admission_digest", CAPACITY_ADMISSION_DOMAIN)?
            != self.capacity_admission_digest
        {
            return Err(ContractError::DigestMismatch("capacity_admission_digest"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionProfileV2 {
    pub schema: String,
    pub profile_digest: String,
    pub packet_digest: String,
    pub admission_digest: String,
    pub adapters: BTreeMap<String, AdapterRegistrationV2>,
    pub work_items: BTreeMap<String, WorkItemExecutionV1>,
    pub budget_policy_ref: String,
    pub log_custody_root: String,
    pub receipt_custody_root: String,
    pub maximum_event_bytes: u64,
    /// V3 separates model output from journal custody. V2 must omit this field.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_output_bound"
    )]
    pub maximum_worker_output_bytes: Option<u64>,
    pub maximum_receipt_bytes: u64,
    pub adapter_timeout_seconds: u64,
    pub closeout_policy: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterRegistrationV2 {
    pub adapter_id: String,
    pub protocol: String,
    pub adapter_version: String,
    pub executable_identity: String,
    pub bounded_arguments: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkItemExecutionV1 {
    pub adapter_id: String,
    pub workspace_identity: String,
    pub resource_lock_keys: Vec<String>,
    pub provider_model_class: String,
}

fn present_output_bound<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u64>, D::Error> {
    // The field may be absent for V2, but explicit null is never its spelling.
    u64::deserialize(deserializer).map(Some)
}

impl ExecutionProfileV2 {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ContractError> {
        let value: Value = parse(bytes)?;
        if value.get("schema").and_then(Value::as_str) == Some(FOREMAN_EXECUTION_PROFILE_SCHEMA_V2)
            && value.get("maximum_worker_output_bytes").is_some()
        {
            return Err(ContractError::InvalidField("V2 profile output field"));
        }
        serde_json::from_value(value).map_err(|error| ContractError::Json(error.to_string()))
    }
    pub fn seal(&mut self) -> Result<(), ContractError> {
        self.profile_digest = digest_without(self, "profile_digest", self.profile_domain()?)?;
        self.validate()
    }
    fn profile_domain(&self) -> Result<&'static [u8], ContractError> {
        match (self.schema.as_str(), self.maximum_worker_output_bytes) {
            (FOREMAN_EXECUTION_PROFILE_SCHEMA_V2, None) => Ok(PROFILE_DOMAIN_V2),
            (FOREMAN_EXECUTION_PROFILE_SCHEMA_V3, Some(bound))
                if (1024..=MAXIMUM_WORKER_OUTPUT_BYTES).contains(&bound) =>
            {
                Ok(PROFILE_DOMAIN_V3)
            }
            _ => Err(ContractError::InvalidField("profile schema/output bounds")),
        }
    }
    pub fn worker_output_bound(&self) -> u64 {
        self.maximum_worker_output_bytes
            .unwrap_or(self.maximum_event_bytes)
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        let domain = self.profile_domain()?;
        digest("profile_digest", &self.profile_digest)?;
        if digest_without(self, "profile_digest", domain)? != self.profile_digest {
            return Err(ContractError::DigestMismatch("profile_digest"));
        }
        digest("packet_digest", &self.packet_digest)?;
        digest("admission_digest", &self.admission_digest)?;
        if self.adapters.is_empty() || self.work_items.is_empty() {
            return Err(ContractError::InvalidField("profile mappings"));
        }
        for (key, adapter) in &self.adapters {
            id("adapter key", key)?;
            if key != &adapter.adapter_id {
                return Err(ContractError::InvalidField("adapter key binding"));
            }
            id("adapter_id", &adapter.adapter_id)?;
            id("adapter protocol", &adapter.protocol)?;
            id("adapter_version", &adapter.adapter_version)?;
            digest("executable_identity", &adapter.executable_identity)?;
            if adapter.bounded_arguments.len() > 32
                || adapter.bounded_arguments.iter().any(|arg| arg.len() > 1024)
            {
                return Err(ContractError::InvalidField("bounded_arguments"));
            }
        }
        for (work_item, execution) in &self.work_items {
            id("work item key", work_item)?;
            if !self.adapters.contains_key(&execution.adapter_id) {
                return Err(ContractError::InvalidField("work item adapter"));
            }
            id("workspace_identity", &execution.workspace_identity)?;
            id("provider_model_class", &execution.provider_model_class)?;
            unique_ids("resource_lock_keys", &execution.resource_lock_keys)?;
        }
        id("budget_policy_ref", &self.budget_policy_ref)?;
        custody_root(&self.log_custody_root)?;
        custody_root(&self.receipt_custody_root)?;
        if !(1024..=16 * 1024 * 1024).contains(&self.maximum_event_bytes)
            || !(1024..=16 * 1024 * 1024).contains(&self.maximum_receipt_bytes)
            || self.adapter_timeout_seconds == 0
            || self.adapter_timeout_seconds > 86_400
            || self.closeout_policy != "ALL_EXPLICIT_TERMINAL_OR_NOT_STARTED"
        {
            return Err(ContractError::InvalidField("profile bounds"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerAdapterCapabilitiesV1 {
    pub schema: String,
    pub adapter_id: String,
    pub adapter_protocol: String,
    pub adapter_version: String,
    pub adapter_executable_identity: String,
    pub provider_kind: String,
    pub commands: Vec<String>,
    pub approval_policy: String,
    pub expected_start_request_schema: String,
    pub event_schema: String,
    pub terminal_receipt_schema: String,
    pub target_effects_authorized: bool,
}

impl WorkerAdapterCapabilitiesV1 {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ContractError> {
        parse(bytes)
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        schema(&self.schema, WORKER_ADAPTER_CAPABILITIES_SCHEMA_V1)?;
        for (field, value) in [
            ("adapter_id", &self.adapter_id),
            ("adapter_protocol", &self.adapter_protocol),
            ("adapter_version", &self.adapter_version),
            ("provider_kind", &self.provider_kind),
        ] {
            id(field, value)?;
        }
        digest(
            "adapter_executable_identity",
            &self.adapter_executable_identity,
        )?;
        let expected = ["capabilities", "start", "resume", "status", "collect"];
        if self.commands.iter().map(String::as_str).collect::<Vec<_>>() != expected
            || self.approval_policy != "SURFACE_ONLY_NO_RESPONSE"
            || self.expected_start_request_schema != WORKER_START_REQUEST_SCHEMA_V2
            || self.event_schema != WORKER_ADAPTER_EVENT_SCHEMA_V1
            || self.terminal_receipt_schema != WORKER_TERMINAL_RECEIPT_SCHEMA_V1
            || self.target_effects_authorized
        {
            return Err(ContractError::InvalidField("adapter capabilities boundary"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterContractVerificationV1 {
    pub schema: String,
    pub capabilities_raw_digest: String,
    pub profile_digest: String,
    pub request_digest: String,
    pub adapter_id: String,
    pub adapter_protocol: String,
    pub adapter_version: String,
    pub adapter_executable_identity: String,
    pub disposition: String,
}

pub fn verify_adapter_contract(
    profile: &ExecutionProfileV2,
    work_item_id: &str,
    capabilities_raw: &[u8],
    start: &WorkerStartRequestV2,
) -> Result<AdapterContractVerificationV1, ContractError> {
    profile.validate()?;
    start.validate()?;
    let capabilities = WorkerAdapterCapabilitiesV1::from_slice(capabilities_raw)?;
    capabilities.validate()?;
    if serde_jcs::to_vec(&capabilities).map_err(json_error)? != capabilities_raw {
        return Err(ContractError::InvalidField("capabilities canonical bytes"));
    }
    let execution = profile
        .work_items
        .get(work_item_id)
        .ok_or(ContractError::InvalidField("capability work item"))?;
    let registration =
        profile
            .adapters
            .get(&execution.adapter_id)
            .ok_or(ContractError::InvalidField(
                "capability adapter registration",
            ))?;
    if registration.adapter_id != capabilities.adapter_id
        || registration.protocol != capabilities.adapter_protocol
        || registration.adapter_version != capabilities.adapter_version
        || registration.executable_identity != capabilities.adapter_executable_identity
        || start.packet_digest != profile.packet_digest
        || start.work_item_id != work_item_id
        || start.adapter_id != registration.adapter_id
        || start.adapter_protocol != registration.protocol
        || start.adapter_version != registration.adapter_version
        || start.workspace_identity != execution.workspace_identity
        || start.provider_model_class != execution.provider_model_class
        || start.timeout_seconds != profile.adapter_timeout_seconds
        || start.maximum_output_bytes != profile.worker_output_bound()
    {
        return Err(ContractError::InvalidField(
            "profile capability start binding",
        ));
    }
    Ok(AdapterContractVerificationV1 {
        schema: "nightshift.adapter-contract-verification/v1".to_owned(),
        capabilities_raw_digest: domain_digest_bytes(CAPABILITIES_RAW_DOMAIN, capabilities_raw),
        profile_digest: profile.profile_digest.clone(),
        request_digest: start.request_digest.clone(),
        adapter_id: registration.adapter_id.clone(),
        adapter_protocol: registration.protocol.clone(),
        adapter_version: registration.adapter_version.clone(),
        adapter_executable_identity: registration.executable_identity.clone(),
        disposition: "EXACT_PROFILE_CAPABILITIES_START_BINDING_VERIFIED".to_owned(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerAttemptBindingV1 {
    pub schema: String,
    pub request_digest: String,
    pub packet_digest: String,
    pub run_id: String,
    pub work_item_id: String,
    pub attempt_id: String,
    pub adapter_id: String,
    pub adapter_version: String,
}

impl WorkerAttemptBindingV1 {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ContractError> {
        parse(bytes)
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        schema(&self.schema, WORKER_ATTEMPT_BINDING_SCHEMA_V1)?;
        digest("request_digest", &self.request_digest)?;
        digest("packet_digest", &self.packet_digest)?;
        for (field, value) in [
            ("run_id", &self.run_id),
            ("work_item_id", &self.work_item_id),
            ("attempt_id", &self.attempt_id),
            ("adapter_id", &self.adapter_id),
            ("adapter_version", &self.adapter_version),
        ] {
            id(field, value)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SchedulerStateV1 {
    WaitingDependencies,
    ReadyEntryEvaluation,
    WaitingResource,
    Dispatching,
    Running,
    WaitingProvider,
    WaitingApproval,
    WaitingHuman,
    Checkpointed,
    TerminalReceiptAccepted,
    TerminalReceiptRefused,
    NotStarted,
    IndeterminateMechanismState,
}

impl SchedulerStateV1 {
    pub fn is_explicit_terminal(&self) -> bool {
        matches!(self, Self::TerminalReceiptAccepted | Self::NotStarted)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedRawBytesV1 {
    pub retained_raw_digest: String,
    pub encoding: String,
    pub bytes_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedPredecessorReceiptV1 {
    pub receipt_kind: String,
    pub retained_raw_digest: String,
    pub encoding: String,
    pub bytes_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecognizedContractJsonV1 {
    pub contract: String,
    pub canonical_json: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerBriefV2 {
    pub schema: String,
    pub packet_digest: String,
    pub packet_source: RetainedRawBytesV1,
    pub work_item: RecognizedContractJsonV1,
    pub predecessor_receipts: BTreeMap<String, RetainedPredecessorReceiptV1>,
    pub global_constraints: RecognizedContractJsonV1,
    pub execution: RecognizedContractJsonV1,
}

impl WorkerBriefV2 {
    pub fn from_slice_for_start(
        bytes: &[u8],
        start: &WorkerStartRequestV2,
    ) -> Result<Self, ContractError> {
        if bytes.len() > MAXIMUM_WORKER_BRIEF_BYTES {
            return Err(ContractError::InvalidField("worker brief size"));
        }
        let brief: Self = parse(bytes)?;
        if serde_jcs::to_vec(&brief).map_err(json_error)? != bytes {
            return Err(ContractError::InvalidField("worker brief canonical bytes"));
        }
        schema(&brief.schema, WORKER_BRIEF_BASIS_SCHEMA_V2)?;
        digest("packet_digest", &brief.packet_digest)?;
        if brief.packet_digest != start.packet_digest
            || domain_digest_bytes(WORKER_BRIEF_DOMAIN_V2, bytes) != start.worker_brief_digest
        {
            return Err(ContractError::DigestMismatch("worker brief binding"));
        }
        if brief.predecessor_receipts.len() > MAXIMUM_PREDECESSOR_RECEIPTS {
            return Err(ContractError::InvalidField("predecessor receipt count"));
        }
        let packet_raw = decode_retained(
            &brief.packet_source.retained_raw_digest,
            &brief.packet_source.encoding,
            &brief.packet_source.bytes_hex,
        )?;
        let packet = NightshiftPacketV1::from_slice(&packet_raw)
            .map_err(|_| ContractError::InvalidField("retained packet"))?;
        packet
            .validate_integrity()
            .map_err(|_| ContractError::InvalidField("retained packet integrity"))?;
        if packet.packet_digest != brief.packet_digest {
            return Err(ContractError::DigestMismatch("retained packet"));
        }
        let selected = packet
            .work_items
            .iter()
            .find(|item| item.id == start.work_item_id)
            .ok_or(ContractError::InvalidField("retained work item"))?;
        let recognized_work: WorkItemV1 = recognized(
            &brief.work_item,
            "nightshift.orientation-packet/v1#work-item",
        )?;
        if &recognized_work != selected {
            return Err(ContractError::InvalidField("recognized work item"));
        }
        let recognized_global: GlobalConstraintsV1 = recognized(
            &brief.global_constraints,
            "nightshift.orientation-packet/v1#global-constraints",
        )?;
        if recognized_global != packet.global_constraints {
            return Err(ContractError::InvalidField("recognized global constraints"));
        }
        let execution: WorkItemExecutionV1 = recognized(
            &brief.execution,
            "nightshift.foreman-execution-profile/v2#work-item",
        )?;
        if execution.adapter_id != start.adapter_id
            || execution.workspace_identity != start.workspace_identity
            || execution.provider_model_class != start.provider_model_class
        {
            return Err(ContractError::InvalidField("recognized execution binding"));
        }
        let expected: BTreeSet<_> = selected.dependencies.iter().cloned().collect();
        let observed: BTreeSet<_> = brief.predecessor_receipts.keys().cloned().collect();
        if expected != observed {
            return Err(ContractError::InvalidField("predecessor receipt set"));
        }
        for (dependency, retained) in &brief.predecessor_receipts {
            let raw = decode_retained(
                &retained.retained_raw_digest,
                &retained.encoding,
                &retained.bytes_hex,
            )?;
            match retained.receipt_kind.as_str() {
                "terminal" => {
                    let receipt = TerminalReceiptV1::from_slice(&raw)?;
                    receipt.validate()?;
                    if receipt.packet_digest != brief.packet_digest
                        || receipt.run_id != start.run_id
                        || receipt.work_item_id != *dependency
                    {
                        return Err(ContractError::InvalidField("predecessor terminal binding"));
                    }
                }
                "not_started" => {
                    let receipt = NotStartedReceiptV1::from_slice(&raw)?;
                    receipt.validate()?;
                    if receipt.packet_digest != brief.packet_digest
                        || receipt.run_id != start.run_id
                        || receipt.work_item_id != *dependency
                    {
                        return Err(ContractError::InvalidField(
                            "predecessor not-started binding",
                        ));
                    }
                }
                _ => return Err(ContractError::InvalidField("predecessor receipt kind")),
            }
        }
        Ok(brief)
    }
}

fn decode_retained(
    retained_raw_digest: &str,
    encoding: &str,
    bytes_hex: &str,
) -> Result<Vec<u8>, ContractError> {
    digest("retained_raw_digest", retained_raw_digest)?;
    if encoding != "hex"
        || bytes_hex.len() > MAXIMUM_WORKER_BRIEF_BYTES.saturating_mul(2)
        || bytes_hex.len() % 2 != 0
    {
        return Err(ContractError::InvalidField("retained raw encoding"));
    }
    let raw =
        hex::decode(bytes_hex).map_err(|_| ContractError::InvalidField("retained raw hex"))?;
    if domain_digest_bytes(RETAINED_RAW_DOMAIN, &raw) != retained_raw_digest {
        return Err(ContractError::DigestMismatch("retained raw"));
    }
    Ok(raw)
}

fn recognized<T: DeserializeOwned + Serialize>(
    wrapper: &RecognizedContractJsonV1,
    expected_contract: &str,
) -> Result<T, ContractError> {
    if wrapper.contract != expected_contract {
        return Err(ContractError::InvalidField("recognized contract"));
    }
    let value: T = serde_json::from_str(&wrapper.canonical_json).map_err(json_error)?;
    if serde_jcs::to_string(&value).map_err(json_error)? != wrapper.canonical_json {
        return Err(ContractError::InvalidField("recognized canonical JSON"));
    }
    Ok(value)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerStartRequestV2 {
    pub schema: String,
    pub request_digest: String,
    pub adapter_id: String,
    pub adapter_version: String,
    pub adapter_protocol: String,
    pub packet_digest: String,
    pub run_id: String,
    pub work_item_id: String,
    pub attempt_id: String,
    pub worker_brief_digest: String,
    pub workspace_identity: String,
    pub provider_model_class: String,
    pub timeout_seconds: u64,
    pub maximum_output_bytes: u64,
    pub recursive_worker_swarms_forbidden: bool,
    pub approval_policy: String,
    pub expected_receipt_schema: String,
}

impl WorkerStartRequestV2 {
    pub fn seal(&mut self) -> Result<(), ContractError> {
        self.request_digest = digest_without(self, "request_digest", START_DOMAIN_V2)?;
        self.validate()
    }
    pub fn attempt_binding(&self) -> WorkerAttemptBindingV1 {
        WorkerAttemptBindingV1 {
            schema: WORKER_ATTEMPT_BINDING_SCHEMA_V1.to_owned(),
            request_digest: self.request_digest.clone(),
            packet_digest: self.packet_digest.clone(),
            run_id: self.run_id.clone(),
            work_item_id: self.work_item_id.clone(),
            attempt_id: self.attempt_id.clone(),
            adapter_id: self.adapter_id.clone(),
            adapter_version: self.adapter_version.clone(),
        }
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        schema(&self.schema, WORKER_START_REQUEST_SCHEMA_V2)?;
        digest("request_digest", &self.request_digest)?;
        if digest_without(self, "request_digest", START_DOMAIN_V2)? != self.request_digest {
            return Err(ContractError::DigestMismatch("request_digest"));
        }
        digest("packet_digest", &self.packet_digest)?;
        for (field, value) in [
            ("adapter_id", &self.adapter_id),
            ("adapter_version", &self.adapter_version),
            ("adapter_protocol", &self.adapter_protocol),
            ("run_id", &self.run_id),
            ("work_item_id", &self.work_item_id),
            ("attempt_id", &self.attempt_id),
            ("workspace_identity", &self.workspace_identity),
            ("provider_model_class", &self.provider_model_class),
        ] {
            id(field, value)?;
        }
        digest("worker_brief_digest", &self.worker_brief_digest)?;
        if self.timeout_seconds == 0
            || self.timeout_seconds > MAXIMUM_ADAPTER_TIMEOUT_SECONDS
            || self.maximum_output_bytes < 1024
            || self.maximum_output_bytes > MAXIMUM_WORKER_OUTPUT_BYTES
            || !self.recursive_worker_swarms_forbidden
            || self.approval_policy != "SURFACE_ONLY_NO_RESPONSE"
            || self.expected_receipt_schema != WORKER_TERMINAL_RECEIPT_SCHEMA_V1
        {
            return Err(ContractError::InvalidField("worker start boundary"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterEventKindV1 {
    AdapterAccepted,
    ProviderIdentity,
    WorkerStarted,
    Checkpoint,
    WaitingApproval,
    HumanQuestion,
    ProviderCompletionObservation,
    AdapterDiagnostic,
    MechanismIndeterminate,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterEventV1 {
    pub schema: String,
    pub event_digest: String,
    pub event_id: String,
    pub packet_digest: String,
    pub run_id: String,
    pub work_item_id: String,
    pub attempt_id: String,
    pub adapter_id: String,
    pub adapter_version: String,
    pub occurred_at: DateTime<Utc>,
    pub kind: AdapterEventKindV1,
    pub provider_identity: Option<String>,
    pub model_identity: Option<String>,
    pub session_identity: Option<String>,
    pub thread_identity: Option<String>,
    pub turn_identity: Option<String>,
    pub queue_identity: Option<String>,
    pub message: Option<String>,
    pub human_question: Option<HumanQuestionV1>,
    pub extensions: BTreeMap<String, Value>,
}

impl AdapterEventV1 {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ContractError> {
        parse(bytes)
    }
    pub fn seal(&mut self) -> Result<(), ContractError> {
        self.event_digest = digest_without(self, "event_digest", EVENT_DOMAIN)?;
        self.validate()
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        schema(&self.schema, WORKER_ADAPTER_EVENT_SCHEMA_V1)?;
        digest("event_digest", &self.event_digest)?;
        if digest_without(self, "event_digest", EVENT_DOMAIN)? != self.event_digest {
            return Err(ContractError::DigestMismatch("event_digest"));
        }
        digest("packet_digest", &self.packet_digest)?;
        for (field, value) in [
            ("event_id", &self.event_id),
            ("run_id", &self.run_id),
            ("work_item_id", &self.work_item_id),
            ("attempt_id", &self.attempt_id),
            ("adapter_id", &self.adapter_id),
            ("adapter_version", &self.adapter_version),
        ] {
            id(field, value)?;
        }
        if matches!(self.kind, AdapterEventKindV1::HumanQuestion) != self.human_question.is_some() {
            return Err(ContractError::InvalidField("human_question"));
        }
        if let Some(question) = &self.human_question {
            question.validate()?;
        }
        if self
            .message
            .as_ref()
            .is_some_and(|value| value.chars().count() > 65_536)
        {
            return Err(ContractError::InvalidField("adapter event bounds"));
        }
        extensions(&self.extensions)?;
        for (field, value) in [
            ("provider_identity", &self.provider_identity),
            ("model_identity", &self.model_identity),
            ("session_identity", &self.session_identity),
            ("thread_identity", &self.thread_identity),
            ("turn_identity", &self.turn_identity),
            ("queue_identity", &self.queue_identity),
        ] {
            if let Some(value) = value {
                id(field, value)?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanQuestionV1 {
    pub question_id: String,
    pub question: String,
    pub exhausted_evidence: String,
    pub safe_default: String,
    pub consequences: String,
    pub resume_point: String,
}

impl HumanQuestionV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        id("question_id", &self.question_id)?;
        for value in [
            &self.question,
            &self.exhausted_evidence,
            &self.safe_default,
            &self.consequences,
            &self.resume_point,
        ] {
            text("human question", value)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptRepositoryV1 {
    pub repository: String,
    pub branch: String,
    pub head: String,
    pub push_status: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeardownDeclarationV1 {
    pub live_runtime: String,
    pub secrets: String,
    pub teardown: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalReceiptV1 {
    pub schema: String,
    pub receipt_digest: String,
    pub packet_digest: String,
    pub run_id: String,
    pub work_item_id: String,
    pub attempt_id: String,
    pub adapter_id: String,
    pub adapter_version: String,
    pub provider_identity: String,
    pub model_identity: String,
    pub session_identity: Option<String>,
    pub thread_identity: Option<String>,
    pub turn_identity: Option<String>,
    pub queue_identity: Option<String>,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub state: String,
    pub result_classification: String,
    pub repositories: Vec<ReceiptRepositoryV1>,
    pub tests: Vec<String>,
    pub evidence: Vec<String>,
    pub live_or_production_mutations: Vec<String>,
    pub remaining_trigger: String,
    pub next_lawful_action: String,
    pub human_questions: Vec<HumanQuestionV1>,
    pub teardown: TeardownDeclarationV1,
    pub extensions: BTreeMap<String, Value>,
}

impl TerminalReceiptV1 {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ContractError> {
        let value: Value = parse(bytes)?;
        canonical_timestamp_value("started_at", &value)?;
        canonical_timestamp_value("ended_at", &value)?;
        serde_json::from_value(value).map_err(json_error)
    }
    pub fn seal(&mut self) -> Result<(), ContractError> {
        self.receipt_digest = digest_without(self, "receipt_digest", TERMINAL_DOMAIN)?;
        self.validate()
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        schema(&self.schema, WORKER_TERMINAL_RECEIPT_SCHEMA_V1)?;
        digest("receipt_digest", &self.receipt_digest)?;
        if digest_without(self, "receipt_digest", TERMINAL_DOMAIN)? != self.receipt_digest {
            return Err(ContractError::DigestMismatch("receipt_digest"));
        }
        digest("packet_digest", &self.packet_digest)?;
        for (field, value) in [
            ("run_id", &self.run_id),
            ("work_item_id", &self.work_item_id),
            ("attempt_id", &self.attempt_id),
            ("adapter_id", &self.adapter_id),
            ("adapter_version", &self.adapter_version),
            ("provider_identity", &self.provider_identity),
            ("model_identity", &self.model_identity),
        ] {
            id(field, value)?;
        }
        if self.started_at > self.ended_at {
            return Err(ContractError::InvalidField("receipt timestamps"));
        }
        for (field, value) in [
            ("state", &self.state),
            ("result_classification", &self.result_classification),
            ("remaining_trigger", &self.remaining_trigger),
            ("next_lawful_action", &self.next_lawful_action),
        ] {
            text(field, value)?;
        }
        for (field, value) in [
            ("session_identity", &self.session_identity),
            ("thread_identity", &self.thread_identity),
            ("turn_identity", &self.turn_identity),
            ("queue_identity", &self.queue_identity),
        ] {
            if let Some(value) = value {
                id(field, value)?;
            }
        }
        for question in &self.human_questions {
            question.validate()?;
        }
        extensions(&self.extensions)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotStartedReceiptV1 {
    pub schema: String,
    pub receipt_digest: String,
    pub packet_digest: String,
    pub run_id: String,
    pub work_item_id: String,
    pub recorded_at: DateTime<Utc>,
    pub state: String,
    pub result_classification: String,
    pub evidence: Vec<String>,
    pub remaining_trigger: String,
    pub next_lawful_action: String,
    pub human_questions: Vec<HumanQuestionV1>,
    pub extensions: BTreeMap<String, Value>,
}

impl NotStartedReceiptV1 {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ContractError> {
        let value: Value = parse(bytes)?;
        canonical_timestamp_value("recorded_at", &value)?;
        serde_json::from_value(value).map_err(json_error)
    }
    pub fn seal(&mut self) -> Result<(), ContractError> {
        self.receipt_digest = digest_without(self, "receipt_digest", NOT_STARTED_DOMAIN)?;
        self.validate()
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        schema(&self.schema, WORK_ITEM_NOT_STARTED_RECEIPT_SCHEMA_V1)?;
        digest("receipt_digest", &self.receipt_digest)?;
        if digest_without(self, "receipt_digest", NOT_STARTED_DOMAIN)? != self.receipt_digest {
            return Err(ContractError::DigestMismatch("receipt_digest"));
        }
        digest("packet_digest", &self.packet_digest)?;
        id("run_id", &self.run_id)?;
        id("work_item_id", &self.work_item_id)?;
        for (field, value) in [
            ("state", &self.state),
            ("result_classification", &self.result_classification),
            ("remaining_trigger", &self.remaining_trigger),
            ("next_lawful_action", &self.next_lawful_action),
        ] {
            text(field, value)?;
        }
        for question in &self.human_questions {
            question.validate()?;
        }
        extensions(&self.extensions)?;
        Ok(())
    }
}

fn extensions(values: &BTreeMap<String, Value>) -> Result<(), ContractError> {
    if values.len() > 64 {
        return Err(ContractError::InvalidField("extensions"));
    }
    for (key, value) in values {
        id("RFC8785 object key", key)?;
        interoperable_json(value)?;
    }
    Ok(())
}

fn interoperable_json(value: &Value) -> Result<(), ContractError> {
    const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Number(number) => {
            let admitted = if let Some(value) = number.as_i64() {
                (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value)
            } else if let Some(value) = number.as_u64() {
                value <= MAX_SAFE_INTEGER as u64
            } else {
                number.as_f64().is_some_and(|value| {
                    value.is_finite() && value.abs() <= MAX_SAFE_INTEGER as f64
                })
            };
            if admitted {
                Ok(())
            } else {
                Err(ContractError::InvalidField("RFC8785 number"))
            }
        }
        Value::Array(values) => {
            for value in values {
                interoperable_json(value)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            if values.len() > 64 {
                return Err(ContractError::InvalidField("extensions"));
            }
            for (key, value) in values {
                id("RFC8785 object key", key)?;
                interoperable_json(value)?;
            }
            Ok(())
        }
    }
}

fn json_error(error: impl std::fmt::Display) -> ContractError {
    ContractError::Json(error.to_string())
}

fn canonical_timestamp_value(field: &'static str, object: &Value) -> Result<(), ContractError> {
    let raw = object
        .as_object()
        .and_then(|values| values.get(field))
        .and_then(Value::as_str)
        .ok_or(ContractError::InvalidField(field))?;
    let parsed = DateTime::parse_from_rfc3339(raw)
        .map_err(|_| ContractError::InvalidField(field))?
        .with_timezone(&Utc);
    let canonical = serde_json::to_value(parsed).map_err(json_error)?;
    if canonical.as_str() != Some(raw) {
        return Err(ContractError::InvalidField(field));
    }
    Ok(())
}

fn domain_digest_bytes(domain: &[u8], bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    format!("sha256:{:x}", digest.finalize())
}

fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ContractError> {
    serde_json::from_slice(bytes).map_err(|error| ContractError::Json(error.to_string()))
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
        .ok_or(ContractError::InvalidField("record"))?
        .remove(field);
    let canonical =
        serde_jcs::to_vec(&value).map_err(|error| ContractError::Json(error.to_string()))?;
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(canonical);
    Ok(format!("sha256:{:x}", digest.finalize()))
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
        || !value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
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

fn unique_ids(field: &'static str, values: &[String]) -> Result<(), ContractError> {
    if values.is_empty() {
        return Err(ContractError::InvalidField(field));
    }
    let mut unique = BTreeSet::new();
    for value in values {
        id(field, value)?;
        if !unique.insert(value) {
            return Err(ContractError::InvalidField(field));
        }
    }
    Ok(())
}

fn custody_root(value: &str) -> Result<(), ContractError> {
    if !value.starts_with('/') || value.contains('\0') || value.contains("/../") {
        return Err(ContractError::InvalidField("custody root"));
    }
    Ok(())
}

fn text(field: &'static str, value: &str) -> Result<(), ContractError> {
    if value.trim().is_empty() || value.chars().count() > 65_536 {
        return Err(ContractError::InvalidField(field));
    }
    Ok(())
}

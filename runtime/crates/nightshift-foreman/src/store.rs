use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    os::fd::AsRawFd,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
};

use chrono::{DateTime, SecondsFormat, Utc};
use nightshift_provider_capacity::{
    decide_capacity, AdmissionDisposition as CapacityAdmissionDisposition, CapacityDecisionV1,
    CapacityObservationV1, CapacityPolicyV1,
};
use nightshiftd::packet::NightshiftPacketV1;
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    contract::{ContractError, TeardownDeclarationV1},
    scheduler::{AcceptedOutcomeV1, ReplayEvent, ReplayKind},
    validate_execution_availability_graph, AdapterEventV1, CapacityCostClassV1,
    DeferredProviderDispatchV1, ExecutionAvailabilityObservationV1, ExecutionAvailabilityPolicyV1,
    ExecutionProfileV2, ForemanAdmissionV1, ForemanCapacityAdmissionV1,
    ForemanCapacityRequirementV1, ForemanExecutionAvailabilityRequirementV1, HumanQuestionV1,
    LiveRunProjectionV1, NotStartedReceiptV1, ParkedResourceLockPolicyV1, PrelaunchClosureV1,
    ProviderAdmissionDispositionV1, ProviderDeferralHistoryEntryV1, ProviderDispatchOccurrenceV1,
    ProviderExecutionIdentityV1, ProviderMechanismStateV1, ReceiptRepositoryV1, Scheduler,
    SchedulerStateV1, SelfHostedDriverDispositionV1, SelfHostedForemanBootstrapV1,
    SelfHostedForemanDriverStepV1, TerminalReceiptV1, WorkerBriefV2, WorkerStartRequestV2,
    WorkerStartRequestV3, MAXIMUM_CAPACITY_HISTORY_BYTES, MAXIMUM_PREDECESSOR_RECEIPTS,
    MAXIMUM_WORKER_BRIEF_BYTES, PROVIDER_DISPATCH_OCCURRENCE_SCHEMA_V1,
    SELF_HOSTED_FOREMAN_DRIVER_STEP_SCHEMA_V1, WORKER_BRIEF_BASIS_SCHEMA_V2,
    WORKER_START_REQUEST_SCHEMA_V2, WORKER_TERMINAL_RECEIPT_SCHEMA_V1,
};

const INTERNAL_EVENT_SCHEMA: &str = "nightshift.foreman-journal-event/v1";
const BRIEF_DIGEST_DOMAIN: &[u8] = b"nightshift.worker-brief.digest/v2\0";
const RAW_DIGEST_DOMAIN: &[u8] = b"nightshift.foreman-retained-raw.digest/v1\0";
const MAXIMUM_CAPACITY_RECORD_BYTES: usize = 1024 * 1024;
const MAXIMUM_SELF_HOSTED_DRIVER_STEP_BYTES: usize = 16 * 1024;
const MAXIMUM_SELF_HOSTED_HISTORY_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_EXECUTION_AVAILABILITY_HISTORY_BYTES: u64 = 16 * 1024 * 1024;
const MAXIMUM_EXECUTION_AVAILABILITY_ROWS: usize = 16_384;

#[derive(Debug, Error)]
pub enum ForemanError {
    #[error("SQLite store error: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("contract refused: {0}")]
    Contract(#[from] ContractError),
    #[error("packet refused: {0}")]
    Packet(String),
    #[error("run already exists: {0}")]
    DuplicateRun(String),
    #[error("unknown run: {0}")]
    UnknownRun(String),
    #[error("unknown work item: {0}")]
    UnknownWorkItem(String),
    #[error("identity mismatch: {0}")]
    IdentityMismatch(&'static str),
    #[error("scheduler transition refused: {0}")]
    Transition(String),
    #[error("resource unavailable: {0}")]
    ResourceUnavailable(String),
    #[error("duplicate event: {0}")]
    DuplicateEvent(String),
    #[error("bounded input exceeded: {0}")]
    InputTooLarge(&'static str),
    #[error("closeout refused; nonterminal work items: {0}")]
    IncompleteCloseout(String),
    #[error("read-only store refused: {0}")]
    ReadOnlyStore(String),
    #[error("serialization failed: {0}")]
    Serialization(String),
}

enum StoreAccess {
    ReadWrite,
    ReadOnly { descriptor: File },
}

pub struct ForemanStore {
    path: PathBuf,
    access: StoreAccess,
}

pub struct CapacityAdmissionEvidenceV1<'a> {
    pub admission_bytes: &'a [u8],
    pub observation_bytes: &'a [u8],
    pub policy_bytes: &'a [u8],
    pub decision_bytes: &'a [u8],
}

/// Exact owner bytes accepted for one provider-dispatch disposition.
pub struct ProviderDispositionEvidenceV1<'a> {
    pub observation_bytes: &'a [u8],
    pub disposition_bytes: &'a [u8],
    pub deferred_bytes: Option<&'a [u8]>,
}

/// Independent immutable run-level mechanism requirements admitted together.
/// Either owner may be absent; neither record derives or overwrites the other.
pub struct RunMechanismRequirementsV1<'a> {
    pub capacity_requirement_bytes: Option<&'a [u8]>,
    pub execution_availability_requirement_bytes: Option<&'a [u8]>,
    pub execution_availability_policy_bytes: Option<&'a [u8]>,
}

pub struct SelfHostedBootstrapInputsV1<'a> {
    pub bootstrap_bytes: &'a [u8],
    pub packet_bytes: &'a [u8],
    pub admission_bytes: &'a [u8],
    pub profile_bytes: &'a [u8],
    pub capacity_requirement_bytes: &'a [u8],
    pub capacity_policy_bytes: &'a [u8],
    pub execution_availability_requirement_bytes: &'a [u8],
    pub execution_availability_policy_bytes: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReadOnlySelfHostedBootstrapV1 {
    pub bootstrap: SelfHostedForemanBootstrapV1,
    pub bootstrap_bytes: Vec<u8>,
    pub capacity_policy_bytes: Vec<u8>,
    pub steps: Vec<SelfHostedForemanDriverStepV1>,
    pub step_bytes: Vec<Vec<u8>>,
}

#[derive(Default)]
struct ValidatedRunMechanisms {
    capacity_requirement: Option<(ForemanCapacityRequirementV1, Vec<u8>)>,
    execution_availability: Option<ValidatedExecutionAvailabilityConfiguration>,
    self_hosted: Option<ValidatedSelfHostedBootstrap>,
}

struct ValidatedSelfHostedBootstrap {
    bootstrap: SelfHostedForemanBootstrapV1,
    bootstrap_bytes: Vec<u8>,
    capacity_policy_bytes: Vec<u8>,
}

/// Exact records produced by one atomic provider-dispatch opening.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenedProviderDispatchV1 {
    pub worker_start_request: WorkerStartRequestV3,
    pub dispatch: ProviderDispatchOccurrenceV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadOnlyProviderResourceTransitionV1 {
    pub transition: String,
    pub work_item_id: String,
    pub work_attempt_id: String,
    pub dispatch_digest: String,
    pub disposition_digest: Option<String>,
    pub deferred_dispatch_digest: Option<String>,
    pub policy_digest: String,
    pub wake_occurrence_id: Option<String>,
    pub resource_lock_keys: Vec<String>,
    pub recorded_at: DateTime<Utc>,
}

/// Query-only exact HOLDING journal history. Each byte vector is the canonical
/// owner record retained inside its enclosing canonical append-only event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadOnlyExecutionAvailabilityHistoryV1 {
    pub requirement: ForemanExecutionAvailabilityRequirementV1,
    pub requirement_bytes: Vec<u8>,
    pub policy: ExecutionAvailabilityPolicyV1,
    pub policy_bytes: Vec<u8>,
    pub worker_start_requests: Vec<WorkerStartRequestV3>,
    pub dispatches: Vec<ProviderDispatchOccurrenceV1>,
    pub observations: Vec<ExecutionAvailabilityObservationV1>,
    pub dispositions: Vec<ProviderAdmissionDispositionV1>,
    pub deferred: Vec<DeferredProviderDispatchV1>,
    pub wake_occurrence_ids: Vec<String>,
    pub wake_work_attempt_ids: Vec<String>,
    pub wake_next_dispatch_digests: Vec<String>,
    pub resume_occurrence_ids: Vec<String>,
    pub resume_work_item_ids: Vec<String>,
    pub resume_work_attempt_ids: Vec<String>,
    pub resume_adapter_process_occurrence_ids: Vec<String>,
    pub resume_execution_identities: Vec<ProviderExecutionIdentityV1>,
    pub resume_disposition_digests: Vec<String>,
    pub resume_recorded_at: Vec<DateTime<Utc>>,
    pub resource_transitions: Vec<ReadOnlyProviderResourceTransitionV1>,
}

struct ValidatedCapacityAdmission {
    admission: ForemanCapacityAdmissionV1,
    observation: CapacityObservationV1,
    policy: CapacityPolicyV1,
    decision: CapacityDecisionV1,
    admission_bytes: Vec<u8>,
    observation_bytes: Vec<u8>,
    policy_bytes: Vec<u8>,
    decision_bytes: Vec<u8>,
}

struct ProviderDispatchPreparation<'a> {
    dispatch_occurrence_id: &'a str,
    adapter_process_occurrence_id: &'a str,
    app_server_session_identity: &'a str,
    selected_model_ordinal: u16,
}

struct ValidatedProviderDispositionEvidence {
    observation: ExecutionAvailabilityObservationV1,
    observation_bytes: Vec<u8>,
    disposition: ProviderAdmissionDispositionV1,
    disposition_bytes: Vec<u8>,
    deferred: Option<DeferredProviderDispatchV1>,
    deferred_bytes: Option<Vec<u8>>,
}

struct ValidatedExecutionAvailabilityConfiguration {
    requirement: ForemanExecutionAvailabilityRequirementV1,
    requirement_bytes: Vec<u8>,
    policy: ExecutionAvailabilityPolicyV1,
    policy_bytes: Vec<u8>,
}

/// One exact event row retained by the append-only foreman journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadOnlyEventRowV1 {
    pub sequence: u64,
    pub event_id: String,
    pub work_item_id: Option<String>,
    pub attempt_id: Option<String>,
    pub kind: String,
    pub recorded_at: String,
    pub raw_bytes: Vec<u8>,
    pub raw_digest: String,
}

/// One exact accepted terminal or not-started receipt row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadOnlyTerminalReceiptRowV1 {
    pub work_item_id: String,
    pub attempt_id: Option<String>,
    pub receipt_digest: String,
    pub raw_bytes: Vec<u8>,
    pub receipt_kind: String,
    pub state: String,
    pub result_classification: String,
}

/// A transaction-consistent read snapshot for read-only operator projections.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadOnlyCapacityRequirementV1 {
    pub recorded_at: String,
    pub requirement: ForemanCapacityRequirementV1,
    pub requirement_bytes: Vec<u8>,
}

/// One exact capacity-admission event retained by the append-only journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadOnlyCapacityAdmissionV1 {
    pub work_item_id: String,
    pub attempt_id: String,
    pub recorded_at: String,
    pub capacity_admission: ForemanCapacityAdmissionV1,
    pub admission_bytes: Vec<u8>,
    pub observation_bytes: Vec<u8>,
    pub policy_bytes: Vec<u8>,
    pub decision_bytes: Vec<u8>,
}

///
/// Every byte vector is copied exactly from the existing SQLite BLOB. Creating
/// this value performs no schema initialization, journal-mode assignment, or
/// write transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadOnlyRunSnapshotV1 {
    pub run_id: String,
    pub packet_bytes: Vec<u8>,
    pub admission_bytes: Vec<u8>,
    pub profile_bytes: Vec<u8>,
    pub projection: LiveRunProjectionV1,
    pub events: Vec<ReadOnlyEventRowV1>,
    pub capacity_requirement: Option<ReadOnlyCapacityRequirementV1>,
    pub capacity_admissions: Vec<ReadOnlyCapacityAdmissionV1>,
    pub execution_availability: Option<ReadOnlyExecutionAvailabilityHistoryV1>,
    pub terminal_receipts: Vec<ReadOnlyTerminalReceiptRowV1>,
    pub final_snapshot_bytes: Option<Vec<u8>>,
}

pub fn read_only_run_snapshot(
    path: impl AsRef<Path>,
    run_id: &str,
) -> Result<ReadOnlyRunSnapshotV1, ForemanError> {
    ForemanStore::open_read_only(path)?.read_only_run_snapshot(run_id)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum InternalPayload {
    RunAdmitted,
    CapacityRequirementAdmitted {
        requirement: Box<ForemanCapacityRequirementV1>,
        requirement_bytes: Vec<u8>,
    },
    AttemptCreated {
        resource_lock_keys: Vec<String>,
        start_request: Box<WorkerStartRequestV2>,
    },
    DispatchRequested,
    ResumeRequested,
    CapacityAdmissionAccepted {
        capacity_admission: Box<ForemanCapacityAdmissionV1>,
        admission_bytes: Vec<u8>,
        observation_bytes: Vec<u8>,
        policy_bytes: Vec<u8>,
        decision_bytes: Vec<u8>,
    },
    ExecutionAvailabilityConfigured {
        requirement: Box<ForemanExecutionAvailabilityRequirementV1>,
        requirement_bytes: Vec<u8>,
        policy: Box<ExecutionAvailabilityPolicyV1>,
        policy_bytes: Vec<u8>,
    },
    ProviderDispatchOpened {
        start_request: Box<WorkerStartRequestV3>,
        start_request_bytes: Vec<u8>,
        dispatch: Box<ProviderDispatchOccurrenceV1>,
        dispatch_bytes: Vec<u8>,
    },
    ProviderDispositionRecorded {
        observation: Box<ExecutionAvailabilityObservationV1>,
        observation_bytes: Vec<u8>,
        disposition: Box<ProviderAdmissionDispositionV1>,
        disposition_bytes: Vec<u8>,
        deferred: Option<Box<DeferredProviderDispatchV1>>,
        deferred_bytes: Option<Vec<u8>>,
        reconciles_disposition_digest: Option<String>,
    },
    ProviderWakeOpened {
        wake_occurrence_id: String,
        deferred_dispatch_digest: String,
        next_dispatch_digest: String,
    },
    ProviderExecutionResumeRequested {
        resume_occurrence_id: String,
        disposition_digest: String,
        adapter_process_occurrence_id: String,
        execution_identity: Box<ProviderExecutionIdentityV1>,
    },
    ProviderResourcesReleased {
        disposition_digest: String,
        dispatch_digest: String,
        policy_digest: String,
        resource_lock_keys: Vec<String>,
    },
    ProviderResourcesReacquired {
        wake_occurrence_id: String,
        deferred_dispatch_digest: String,
        next_dispatch_digest: String,
        policy_digest: String,
        resource_lock_keys: Vec<String>,
    },
    TerminalAccepted {
        outcome: AcceptedOutcomeV1,
    },
    TerminalRefused {
        reason: String,
    },
    NotStartedAccepted {
        outcome: AcceptedOutcomeV1,
    },
    PrelaunchClosureAccepted {
        closure: Box<PrelaunchClosureV1>,
        receipt: Box<NotStartedReceiptV1>,
    },
    ResourcesReleased,
    RunClosed {
        final_receipts_digest: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InternalEvent {
    schema: String,
    event_id: String,
    run_id: String,
    work_item_id: Option<String>,
    attempt_id: Option<String>,
    recorded_at: DateTime<Utc>,
    payload: InternalPayload,
}

/// One exact capacity event reopened from its retained canonical journal bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadOnlyCapacityJournalEventV1 {
    Requirement {
        sequence: u64,
        record: Box<ReadOnlyCapacityRequirementV1>,
    },
    Admission {
        sequence: u64,
        record: Box<ReadOnlyCapacityAdmissionV1>,
    },
}

/// One exact execution-availability event reopened from retained canonical
/// journal bytes. This query-only view grants no transition authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadOnlyExecutionAvailabilityJournalEventV1 {
    Requirement {
        requirement: Box<ForemanExecutionAvailabilityRequirementV1>,
        requirement_bytes: Vec<u8>,
        policy: Box<ExecutionAvailabilityPolicyV1>,
        policy_bytes: Vec<u8>,
    },
    Dispatch {
        start_request: Box<WorkerStartRequestV3>,
        start_request_bytes: Vec<u8>,
        dispatch: Box<ProviderDispatchOccurrenceV1>,
        dispatch_bytes: Vec<u8>,
    },
    Disposition {
        observation: Box<ExecutionAvailabilityObservationV1>,
        observation_bytes: Vec<u8>,
        disposition: Box<ProviderAdmissionDispositionV1>,
        disposition_bytes: Vec<u8>,
        deferred: Option<Box<DeferredProviderDispatchV1>>,
        deferred_bytes: Option<Vec<u8>>,
        reconciles_disposition_digest: Option<String>,
    },
    Wake {
        wake_occurrence_id: String,
        deferred_dispatch_digest: String,
        next_dispatch_digest: String,
    },
    Resume {
        resume_occurrence_id: String,
        disposition_digest: String,
        adapter_process_occurrence_id: String,
        execution_identity: Box<ProviderExecutionIdentityV1>,
    },
    ResourcesReleased {
        disposition_digest: String,
        dispatch_digest: String,
        policy_digest: String,
        resource_lock_keys: Vec<String>,
    },
    ResourcesReacquired {
        wake_occurrence_id: String,
        deferred_dispatch_digest: String,
        next_dispatch_digest: String,
        policy_digest: String,
        resource_lock_keys: Vec<String>,
    },
}

/// Reopen a capacity journal row without interpreting non-capacity events.
///
/// The returned nested typed record and exact nested bytes have been proved
/// equal to one another and to the enclosing canonical event bytes. This is a
/// query-only parsing operation and performs no store access or mutation.
pub fn reopen_capacity_journal_event(
    row: &ReadOnlyEventRowV1,
    expected_run_id: &str,
) -> Result<ReadOnlyCapacityJournalEventV1, ForemanError> {
    if row.sequence == 0 || row.raw_digest != raw_digest(&row.raw_bytes) {
        return Err(ForemanError::ReadOnlyStore(
            "capacity journal sequence or retained-raw digest mismatch".to_owned(),
        ));
    }
    let event: InternalEvent = serde_json::from_slice(&row.raw_bytes)
        .map_err(|error| ForemanError::Serialization(error.to_string()))?;
    if event.schema != INTERNAL_EVENT_SCHEMA
        || event.run_id != expected_run_id
        || event.event_id != row.event_id
        || event.work_item_id != row.work_item_id
        || event.attempt_id != row.attempt_id
        || event.recorded_at.to_rfc3339() != row.recorded_at
        || serde_jcs::to_vec(&event)
            .map_err(|error| ForemanError::Serialization(error.to_string()))?
            != row.raw_bytes
    {
        return Err(ForemanError::ReadOnlyStore(
            "capacity internal event row identity or canonical bytes mismatch".to_owned(),
        ));
    }
    match (row.kind.as_str(), event.payload) {
        (
            "capacity_requirement",
            InternalPayload::CapacityRequirementAdmitted {
                requirement,
                requirement_bytes,
            },
        ) => {
            if event.work_item_id.is_some() || event.attempt_id.is_some() {
                return Err(ForemanError::ReadOnlyStore(
                    "capacity requirement event carries lane identity".to_owned(),
                ));
            }
            requirement.validate()?;
            let reopened = ForemanCapacityRequirementV1::from_slice(&requirement_bytes)?;
            reopened.validate()?;
            if reopened != *requirement
                || serde_jcs::to_vec(&reopened)
                    .map_err(|error| ForemanError::Serialization(error.to_string()))?
                    != requirement_bytes
            {
                return Err(ForemanError::ReadOnlyStore(
                    "capacity requirement nested typed/raw split".to_owned(),
                ));
            }
            Ok(ReadOnlyCapacityJournalEventV1::Requirement {
                sequence: row.sequence,
                record: Box::new(ReadOnlyCapacityRequirementV1 {
                    recorded_at: row.recorded_at.clone(),
                    requirement: reopened,
                    requirement_bytes,
                }),
            })
        }
        (
            "capacity_admission",
            InternalPayload::CapacityAdmissionAccepted {
                capacity_admission,
                admission_bytes,
                observation_bytes,
                policy_bytes,
                decision_bytes,
            },
        ) => {
            let work_item_id = event.work_item_id.ok_or_else(|| {
                ForemanError::ReadOnlyStore(
                    "capacity admission event lacks work-item identity".to_owned(),
                )
            })?;
            let attempt_id = event.attempt_id.ok_or_else(|| {
                ForemanError::ReadOnlyStore(
                    "capacity admission event lacks attempt identity".to_owned(),
                )
            })?;
            capacity_admission.validate()?;
            let reopened = ForemanCapacityAdmissionV1::from_slice(&admission_bytes)?;
            reopened.validate()?;
            if reopened != *capacity_admission
                || serde_jcs::to_vec(&reopened)
                    .map_err(|error| ForemanError::Serialization(error.to_string()))?
                    != admission_bytes
            {
                return Err(ForemanError::ReadOnlyStore(
                    "capacity admission nested typed/raw split".to_owned(),
                ));
            }
            Ok(ReadOnlyCapacityJournalEventV1::Admission {
                sequence: row.sequence,
                record: Box::new(ReadOnlyCapacityAdmissionV1 {
                    work_item_id,
                    attempt_id,
                    recorded_at: row.recorded_at.clone(),
                    capacity_admission: reopened,
                    admission_bytes,
                    observation_bytes,
                    policy_bytes,
                    decision_bytes,
                }),
            })
        }
        _ => Err(ForemanError::ReadOnlyStore(
            "row is not an exact recognized capacity journal event".to_owned(),
        )),
    }
}

/// Reopen one exact execution-availability journal row without changing store
/// or scheduler state.
pub fn reopen_execution_availability_journal_event(
    row: &ReadOnlyEventRowV1,
    expected_run_id: &str,
) -> Result<ReadOnlyExecutionAvailabilityJournalEventV1, ForemanError> {
    if row.sequence == 0 || row.raw_digest != raw_digest(&row.raw_bytes) {
        return Err(ForemanError::ReadOnlyStore(
            "execution-availability retained-raw identity mismatch".to_owned(),
        ));
    }
    let event: InternalEvent = serde_json::from_slice(&row.raw_bytes)
        .map_err(|error| ForemanError::Serialization(error.to_string()))?;
    if event.schema != INTERNAL_EVENT_SCHEMA
        || event.run_id != expected_run_id
        || event.event_id != row.event_id
        || event.work_item_id != row.work_item_id
        || event.attempt_id != row.attempt_id
        || event.recorded_at.to_rfc3339() != row.recorded_at
        || serde_jcs::to_vec(&event)
            .map_err(|error| ForemanError::Serialization(error.to_string()))?
            != row.raw_bytes
    {
        return Err(ForemanError::ReadOnlyStore(
            "execution-availability event row identity mismatch".to_owned(),
        ));
    }
    reopen_execution_availability_payload(row.kind.as_str(), event.payload)
}

fn reopen_execution_availability_payload(
    kind: &str,
    payload: InternalPayload,
) -> Result<ReadOnlyExecutionAvailabilityJournalEventV1, ForemanError> {
    match payload {
        InternalPayload::ExecutionAvailabilityConfigured {
            requirement,
            requirement_bytes,
            policy,
            policy_bytes,
        } if kind == "execution_availability_requirement" => {
            let reopened =
                validate_execution_availability_configuration(&requirement_bytes, &policy_bytes)?;
            if reopened.requirement != *requirement || reopened.policy != *policy {
                return Err(ForemanError::ReadOnlyStore(
                    "execution-availability requirement typed/raw split".to_owned(),
                ));
            }
            Ok(ReadOnlyExecutionAvailabilityJournalEventV1::Requirement {
                requirement: Box::new(reopened.requirement),
                requirement_bytes: reopened.requirement_bytes,
                policy: Box::new(reopened.policy),
                policy_bytes: reopened.policy_bytes,
            })
        }
        InternalPayload::ProviderDispatchOpened {
            start_request,
            start_request_bytes,
            dispatch,
            dispatch_bytes,
        } if kind == "provider_dispatch" => {
            start_request.validate()?;
            dispatch.validate()?;
            if serde_jcs::to_vec(&*start_request)
                .map_err(|error| ForemanError::Serialization(error.to_string()))?
                != start_request_bytes
                || serde_jcs::to_vec(&*dispatch)
                    .map_err(|error| ForemanError::Serialization(error.to_string()))?
                    != dispatch_bytes
            {
                return Err(ForemanError::ReadOnlyStore(
                    "provider dispatch typed/raw split".to_owned(),
                ));
            }
            Ok(ReadOnlyExecutionAvailabilityJournalEventV1::Dispatch {
                start_request,
                start_request_bytes,
                dispatch,
                dispatch_bytes,
            })
        }
        other => reopen_execution_availability_payload_tail(kind, other),
    }
}

fn reopen_execution_availability_payload_tail(
    kind: &str,
    payload: InternalPayload,
) -> Result<ReadOnlyExecutionAvailabilityJournalEventV1, ForemanError> {
    match payload {
        InternalPayload::ProviderDispositionRecorded {
            observation,
            observation_bytes,
            disposition,
            disposition_bytes,
            deferred,
            deferred_bytes,
            reconciles_disposition_digest,
        } if kind == "provider_disposition" => {
            observation.validate()?;
            disposition.validate()?;
            if serde_jcs::to_vec(&*observation)
                .map_err(|error| ForemanError::Serialization(error.to_string()))?
                != observation_bytes
                || serde_jcs::to_vec(&*disposition)
                    .map_err(|error| ForemanError::Serialization(error.to_string()))?
                    != disposition_bytes
                || deferred.is_some() != deferred_bytes.is_some()
            {
                return Err(ForemanError::ReadOnlyStore(
                    "provider disposition typed/raw split".to_owned(),
                ));
            }
            if let (Some(record), Some(bytes)) = (&deferred, &deferred_bytes) {
                record.validate()?;
                if serde_jcs::to_vec(&**record)
                    .map_err(|error| ForemanError::Serialization(error.to_string()))?
                    != *bytes
                {
                    return Err(ForemanError::ReadOnlyStore(
                        "provider deferral typed/raw split".to_owned(),
                    ));
                }
            }
            Ok(ReadOnlyExecutionAvailabilityJournalEventV1::Disposition {
                observation,
                observation_bytes,
                disposition,
                disposition_bytes,
                deferred,
                deferred_bytes,
                reconciles_disposition_digest,
            })
        }
        other => reopen_execution_availability_payload_occurrence(kind, other),
    }
}

fn reopen_execution_availability_payload_occurrence(
    kind: &str,
    payload: InternalPayload,
) -> Result<ReadOnlyExecutionAvailabilityJournalEventV1, ForemanError> {
    match payload {
        InternalPayload::ProviderWakeOpened {
            wake_occurrence_id,
            deferred_dispatch_digest,
            next_dispatch_digest,
        } if kind == "provider_wake" => Ok(ReadOnlyExecutionAvailabilityJournalEventV1::Wake {
            wake_occurrence_id,
            deferred_dispatch_digest,
            next_dispatch_digest,
        }),
        InternalPayload::ProviderExecutionResumeRequested {
            resume_occurrence_id,
            disposition_digest,
            adapter_process_occurrence_id,
            execution_identity,
        } if kind == "provider_resume" => {
            execution_identity.validate()?;
            Ok(ReadOnlyExecutionAvailabilityJournalEventV1::Resume {
                resume_occurrence_id,
                disposition_digest,
                adapter_process_occurrence_id,
                execution_identity,
            })
        }
        other => reopen_execution_availability_payload_resource(kind, other),
    }
}

fn reopen_execution_availability_payload_resource(
    kind: &str,
    payload: InternalPayload,
) -> Result<ReadOnlyExecutionAvailabilityJournalEventV1, ForemanError> {
    match (kind, payload) {
        (
            "provider_resources_released",
            InternalPayload::ProviderResourcesReleased {
                disposition_digest,
                dispatch_digest,
                policy_digest,
                resource_lock_keys,
            },
        ) => Ok(
            ReadOnlyExecutionAvailabilityJournalEventV1::ResourcesReleased {
                disposition_digest,
                dispatch_digest,
                policy_digest,
                resource_lock_keys,
            },
        ),
        (
            "provider_resources_reacquired",
            InternalPayload::ProviderResourcesReacquired {
                wake_occurrence_id,
                deferred_dispatch_digest,
                next_dispatch_digest,
                policy_digest,
                resource_lock_keys,
            },
        ) => Ok(
            ReadOnlyExecutionAvailabilityJournalEventV1::ResourcesReacquired {
                wake_occurrence_id,
                deferred_dispatch_digest,
                next_dispatch_digest,
                policy_digest,
                resource_lock_keys,
            },
        ),
        _ => Err(ForemanError::ReadOnlyStore(
            "row is not an exact execution-availability event".to_owned(),
        )),
    }
}
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct FinalReceiptDocument {
    schema: String,
    packet_digest: String,
    updated_at: String,
    work_items: Vec<FinalWorkItem>,
    human_questions: Vec<FinalQuestion>,
    repository_custody: Vec<FinalCustody>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct FinalWorkItem {
    id: String,
    state: String,
    result_classification: String,
    repositories: Vec<ReceiptRepositoryV1>,
    tests: Vec<String>,
    evidence: Vec<String>,
    live_or_production_mutations: Vec<String>,
    remaining_trigger: String,
    next_lawful_action: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct FinalQuestion {
    work_item: String,
    exact_question: String,
    evidence_exhausted: String,
    safe_default: String,
    consequences: String,
    resume_point: String,
}

#[derive(Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct FinalCustody {
    repository: String,
    branch_head: String,
    push_custody: String,
    dirty: String,
    live_runtime: String,
    secrets: String,
    teardown: String,
}

impl ForemanStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ForemanError> {
        let store = Self {
            path: path.as_ref().to_owned(),
            access: StoreAccess::ReadWrite,
        };
        let connection = store.connection()?;
        initialize(&connection)?;
        Ok(store)
    }

    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, ForemanError> {
        let supplied = path.as_ref();
        let descriptor = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(supplied)
            .map_err(|error| {
                ForemanError::ReadOnlyStore(format!(
                    "existing no-follow database required at {}: {error}",
                    supplied.display()
                ))
            })?;
        if !descriptor
            .metadata()
            .map_err(|error| ForemanError::ReadOnlyStore(error.to_string()))?
            .is_file()
        {
            return Err(ForemanError::ReadOnlyStore(format!(
                "existing regular database required at {}",
                supplied.display()
            )));
        }
        let descriptor_path = PathBuf::from(format!("/proc/self/fd/{}", descriptor.as_raw_fd()));
        if fs::read_link(&descriptor_path).is_err() {
            return Err(ForemanError::ReadOnlyStore(
                "descriptor-relative SQLite access is unavailable".to_owned(),
            ));
        }
        let store = Self {
            path: supplied.to_owned(),
            access: StoreAccess::ReadOnly { descriptor },
        };
        let connection = store.connection()?;
        require_existing_schema(&connection)?;
        Ok(store)
    }
    pub fn admit(
        &self,
        packet_bytes: &[u8],
        admission_bytes: &[u8],
        profile_bytes: &[u8],
        evaluated_at: DateTime<Utc>,
    ) -> Result<String, ForemanError> {
        self.admit_internal(
            packet_bytes,
            admission_bytes,
            profile_bytes,
            evaluated_at,
            ValidatedRunMechanisms::default(),
        )
    }

    pub fn admit_with_capacity_requirement(
        &self,
        packet_bytes: &[u8],
        admission_bytes: &[u8],
        profile_bytes: &[u8],
        capacity_requirement_bytes: &[u8],
        evaluated_at: DateTime<Utc>,
    ) -> Result<String, ForemanError> {
        let requirement = validate_capacity_requirement_bytes(capacity_requirement_bytes)?;
        self.admit_internal(
            packet_bytes,
            admission_bytes,
            profile_bytes,
            evaluated_at,
            ValidatedRunMechanisms {
                capacity_requirement: Some((requirement, capacity_requirement_bytes.to_vec())),
                ..ValidatedRunMechanisms::default()
            },
        )
    }

    pub fn admit_with_execution_availability(
        &self,
        packet_bytes: &[u8],
        admission_bytes: &[u8],
        profile_bytes: &[u8],
        requirement_bytes: &[u8],
        policy_bytes: &[u8],
        evaluated_at: DateTime<Utc>,
    ) -> Result<String, ForemanError> {
        let configuration =
            validate_execution_availability_configuration(requirement_bytes, policy_bytes)?;
        self.admit_internal(
            packet_bytes,
            admission_bytes,
            profile_bytes,
            evaluated_at,
            ValidatedRunMechanisms {
                execution_availability: Some(configuration),
                ..ValidatedRunMechanisms::default()
            },
        )
    }

    pub fn admit_with_mechanism_requirements(
        &self,
        packet_bytes: &[u8],
        admission_bytes: &[u8],
        profile_bytes: &[u8],
        requirements: RunMechanismRequirementsV1<'_>,
        evaluated_at: DateTime<Utc>,
    ) -> Result<String, ForemanError> {
        let capacity_requirement = requirements
            .capacity_requirement_bytes
            .map(validate_capacity_requirement_bytes)
            .transpose()?
            .map(|value| {
                (
                    value,
                    requirements.capacity_requirement_bytes.unwrap().to_vec(),
                )
            });
        let execution_availability = match (
            requirements.execution_availability_requirement_bytes,
            requirements.execution_availability_policy_bytes,
        ) {
            (None, None) => None,
            (Some(requirement), Some(policy)) => Some(
                validate_execution_availability_configuration(requirement, policy)?,
            ),
            _ => {
                return Err(ForemanError::Transition(
                    "execution-availability requirement and policy must be supplied together"
                        .to_owned(),
                ))
            }
        };
        self.admit_internal(
            packet_bytes,
            admission_bytes,
            profile_bytes,
            evaluated_at,
            ValidatedRunMechanisms {
                capacity_requirement,
                execution_availability,
                self_hosted: None,
            },
        )
    }

    /// Validate the complete canonical bootstrap graph before the database path
    /// is opened or initialized, then retain bootstrap and run custody in one
    /// immediate transaction.
    pub fn admit_self_hosted_at_path(
        path: impl AsRef<Path>,
        inputs: SelfHostedBootstrapInputsV1<'_>,
    ) -> Result<String, ForemanError> {
        for (field, bytes) in [
            ("bootstrap plan", inputs.bootstrap_bytes),
            ("bootstrap packet", inputs.packet_bytes),
            ("bootstrap admission", inputs.admission_bytes),
            ("bootstrap profile", inputs.profile_bytes),
            (
                "bootstrap capacity requirement",
                inputs.capacity_requirement_bytes,
            ),
            ("bootstrap capacity policy", inputs.capacity_policy_bytes),
            (
                "bootstrap availability requirement",
                inputs.execution_availability_requirement_bytes,
            ),
            (
                "bootstrap availability policy",
                inputs.execution_availability_policy_bytes,
            ),
        ] {
            if bytes.is_empty() || bytes.len() > MAXIMUM_WORKER_BRIEF_BYTES {
                return Err(ForemanError::InputTooLarge(field));
            }
        }
        let bootstrap = SelfHostedForemanBootstrapV1::from_slice(inputs.bootstrap_bytes)?;
        bootstrap.validate_graph(
            inputs.packet_bytes,
            inputs.admission_bytes,
            inputs.profile_bytes,
            inputs.capacity_requirement_bytes,
            inputs.capacity_policy_bytes,
            inputs.execution_availability_requirement_bytes,
            inputs.execution_availability_policy_bytes,
        )?;
        let capacity_requirement =
            validate_capacity_requirement_bytes(inputs.capacity_requirement_bytes)?;
        let execution_availability = validate_execution_availability_configuration(
            inputs.execution_availability_requirement_bytes,
            inputs.execution_availability_policy_bytes,
        )?;
        let run_admitted_at = ForemanAdmissionV1::from_slice(inputs.admission_bytes)?.admitted_at;
        let validated = ValidatedSelfHostedBootstrap {
            bootstrap,
            bootstrap_bytes: inputs.bootstrap_bytes.to_vec(),
            capacity_policy_bytes: inputs.capacity_policy_bytes.to_vec(),
        };
        let store = Self::open(path)?;
        store.admit_internal(
            inputs.packet_bytes,
            inputs.admission_bytes,
            inputs.profile_bytes,
            run_admitted_at,
            ValidatedRunMechanisms {
                capacity_requirement: Some((
                    capacity_requirement,
                    inputs.capacity_requirement_bytes.to_vec(),
                )),
                execution_availability: Some(execution_availability),
                self_hosted: Some(validated),
            },
        )
    }

    fn admit_internal(
        &self,
        packet_bytes: &[u8],
        admission_bytes: &[u8],
        profile_bytes: &[u8],
        evaluated_at: DateTime<Utc>,
        mechanisms: ValidatedRunMechanisms,
    ) -> Result<String, ForemanError> {
        let ValidatedRunMechanisms {
            capacity_requirement,
            execution_availability,
            self_hosted,
        } = mechanisms;
        let packet = NightshiftPacketV1::from_slice(packet_bytes)
            .map_err(|error| ForemanError::Packet(error.to_string()))?;
        packet
            .validate_at(evaluated_at)
            .map_err(|error| ForemanError::Packet(error.to_string()))?;
        let admission = ForemanAdmissionV1::from_slice(admission_bytes)?;
        admission.validate_at(evaluated_at)?;
        let profile = ExecutionProfileV2::from_slice(profile_bytes)?;
        profile.validate()?;
        validate_bindings(&packet, &admission, &profile)?;
        if let Some((requirement, _)) = &capacity_requirement {
            validate_capacity_requirement(requirement, &packet, &admission, &profile)?;
        }
        if let Some(configuration) = &execution_availability {
            validate_execution_availability_configuration_bindings(
                configuration,
                &packet,
                &admission,
                &profile,
                evaluated_at,
            )?;
        }

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM runs WHERE run_id = ?1)",
            [&admission.run_id],
            |row| row.get(0),
        )?;
        if exists {
            return Err(ForemanError::DuplicateRun(admission.run_id));
        }
        transaction.execute(
            "INSERT INTO runs
             (run_id, packet_digest, admission_digest, profile_digest, packet_bytes,
              admission_bytes, profile_bytes, admitted_at, expires_at, maximum_concurrent_workers,
              execution_availability_required)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                admission.run_id,
                packet.packet_digest,
                admission.admission_digest,
                profile.profile_digest,
                packet_bytes,
                admission_bytes,
                profile_bytes,
                admission.admitted_at.to_rfc3339(),
                admission.expires_at.to_rfc3339(),
                admission.maximum_concurrent_workers,
                execution_availability.is_some(),
            ],
        )?;
        for item in &packet.work_items {
            transaction.execute(
                "INSERT INTO work_items (run_id, work_item_id, packet_ordinal, dependencies_json)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    admission.run_id,
                    item.id,
                    packet
                        .work_items
                        .iter()
                        .position(|candidate| candidate.id == item.id)
                        .unwrap_or_default(),
                    serde_jcs::to_vec(&item.dependencies)
                        .map_err(|error| ForemanError::Serialization(error.to_string()))?,
                ],
            )?;
        }
        let event = InternalEvent {
            schema: INTERNAL_EVENT_SCHEMA.to_owned(),
            event_id: format!("run-admitted-{}", Uuid::new_v4()),
            run_id: admission.run_id.clone(),
            work_item_id: None,
            attempt_id: None,
            recorded_at: evaluated_at,
            payload: InternalPayload::RunAdmitted,
        };
        append_internal(&transaction, &event)?;
        if let Some((requirement, requirement_bytes)) = capacity_requirement {
            let requirement_event = InternalEvent {
                schema: INTERNAL_EVENT_SCHEMA.to_owned(),
                event_id: format!("capacity-required-{}", Uuid::new_v4()),
                run_id: admission.run_id.clone(),
                work_item_id: None,
                attempt_id: None,
                recorded_at: evaluated_at,
                payload: InternalPayload::CapacityRequirementAdmitted {
                    requirement: Box::new(requirement),
                    requirement_bytes,
                },
            };
            append_internal_bounded(
                &transaction,
                &requirement_event,
                profile.maximum_event_bytes,
                packet.work_items.len().saturating_add(1),
            )?;
        }
        if let Some(configuration) = execution_availability {
            transaction.execute(
                "INSERT INTO run_mechanism_requirements
                 (run_id, execution_availability_required) VALUES (?1, 1)",
                [&admission.run_id],
            )?;
            let configuration_event = InternalEvent {
                schema: INTERNAL_EVENT_SCHEMA.to_owned(),
                event_id: format!("execution-availability-required-{}", Uuid::new_v4()),
                run_id: admission.run_id.clone(),
                work_item_id: None,
                attempt_id: None,
                recorded_at: evaluated_at,
                payload: InternalPayload::ExecutionAvailabilityConfigured {
                    requirement: Box::new(configuration.requirement),
                    requirement_bytes: configuration.requirement_bytes,
                    policy: Box::new(configuration.policy),
                    policy_bytes: configuration.policy_bytes,
                },
            };
            append_execution_availability_bounded(
                &transaction,
                &configuration_event,
                profile.maximum_event_bytes,
            )?;
        }
        if let Some(custody) = self_hosted {
            if custody.bootstrap.run_id != admission.run_id
                || custody.bootstrap.packet_digest != packet.packet_digest
                || custody.bootstrap.admission_digest != admission.admission_digest
                || custody.bootstrap.profile_digest != profile.profile_digest
            {
                return Err(ForemanError::IdentityMismatch(
                    "self-hosted bootstrap admission",
                ));
            }
            let deadline_at = custody
                .bootstrap
                .evaluated_at
                .checked_add_signed(chrono::Duration::seconds(i64::from(
                    custody.bootstrap.maximum_wall_seconds,
                )))
                .ok_or_else(|| {
                    ForemanError::Transition("self-hosted deadline overflow".to_owned())
                })?;
            transaction.execute(
                "INSERT INTO self_hosted_bootstraps
                 (run_id, bootstrap_digest, bootstrap_occurrence_id, bootstrap_bytes,
                  capacity_policy_bytes, admitted_at, deadline_at, maximum_driver_steps)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    admission.run_id,
                    custody.bootstrap.bootstrap_digest,
                    custody.bootstrap.bootstrap_occurrence_id,
                    custody.bootstrap_bytes,
                    custody.capacity_policy_bytes,
                    custody.bootstrap.evaluated_at.to_rfc3339(),
                    deadline_at.to_rfc3339(),
                    custody.bootstrap.maximum_driver_steps,
                ],
            )?;
        }
        load_execution_availability_history(
            &transaction,
            &admission.run_id,
            &packet,
            &admission,
            &profile,
        )?;
        transaction.commit()?;
        Ok(admission.run_id)
    }

    pub fn projection(&self, run_id: &str) -> Result<LiveRunProjectionV1, ForemanError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let projection = load_projection(&transaction, run_id)?;
        transaction.commit()?;
        Ok(projection)
    }

    pub fn self_hosted_bootstrap(
        &self,
        run_id: &str,
    ) -> Result<ReadOnlySelfHostedBootstrapV1, ForemanError> {
        if !matches!(self.access, StoreAccess::ReadOnly { .. }) {
            return Err(ForemanError::ReadOnlyStore(
                "self-hosted bootstrap projection requires an explicitly read-only store"
                    .to_owned(),
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let custody = load_self_hosted_bootstrap(&transaction, run_id)?;
        transaction.commit()?;
        Ok(custody)
    }

    /// Atomically retain one deterministic observation of the durable scheduler.
    ///
    /// Callers name the expected ordinal; concurrent writers for the same
    /// ordinal converge on the first exact retained record. The record itself
    /// authorizes no dispatch or effect.
    pub fn advance_self_hosted_driver(
        &self,
        run_id: &str,
        bootstrap_digest: &str,
        expected_step_ordinal: u32,
        scheduler_process_occurrence_id: &str,
        recorded_at: DateTime<Utc>,
    ) -> Result<SelfHostedForemanDriverStepV1, ForemanError> {
        validate_local_occurrence_id(
            scheduler_process_occurrence_id,
            "scheduler_process_occurrence_id",
        )?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let custody = load_self_hosted_bootstrap(&transaction, run_id)?;
        if custody.bootstrap.bootstrap_digest != bootstrap_digest {
            return Err(ForemanError::IdentityMismatch("bootstrap_digest"));
        }
        if let Some(existing) = custody
            .steps
            .iter()
            .find(|step| step.step_ordinal == expected_step_ordinal)
        {
            transaction.commit()?;
            return Ok(existing.clone());
        }
        let prior_step = custody.steps.last();
        let terminal_closed = prior_step.is_some_and(|step| {
            matches!(
                step.disposition,
                SelfHostedDriverDispositionV1::BoundReached
                    | SelfHostedDriverDispositionV1::AllItemsExplicitTerminal
            )
        });
        let next_ordinal = u32::try_from(custody.steps.len() + 1)
            .map_err(|_| ForemanError::Transition("driver step ordinal overflow".to_owned()))?;
        if expected_step_ordinal != next_ordinal
            || expected_step_ordinal > custody.bootstrap.maximum_driver_steps
            || recorded_at < custody.bootstrap.evaluated_at
            || prior_step.is_some_and(|step| recorded_at < step.recorded_at)
            || terminal_closed
        {
            return Err(ForemanError::Transition(
                "driver step ordinal, bound, or time is not admissible".to_owned(),
            ));
        }
        let deadline_at = custody
            .bootstrap
            .evaluated_at
            .checked_add_signed(chrono::Duration::seconds(i64::from(
                custody.bootstrap.maximum_wall_seconds,
            )))
            .ok_or_else(|| ForemanError::Transition("driver deadline overflow".to_owned()))?;
        let projection = load_projection(&transaction, run_id)?;
        let projection_bytes = serde_jcs::to_vec(&projection)
            .map_err(|error| ForemanError::Serialization(error.to_string()))?;
        let disposition = if projection
            .work_items
            .iter()
            .all(|item| item.scheduler_state.is_explicit_terminal())
        {
            SelfHostedDriverDispositionV1::AllItemsExplicitTerminal
        } else if recorded_at >= deadline_at
            || expected_step_ordinal == custody.bootstrap.maximum_driver_steps
        {
            SelfHostedDriverDispositionV1::BoundReached
        } else if projection.work_items.iter().any(|item| {
            matches!(
                item.scheduler_state,
                SchedulerStateV1::ReadyEntryEvaluation | SchedulerStateV1::WaitingResource
            )
        }) {
            SelfHostedDriverDispositionV1::ReadyWorkPresent
        } else {
            SelfHostedDriverDispositionV1::WaitingForExactOwnerEvidence
        };
        let mut step = SelfHostedForemanDriverStepV1 {
            schema: SELF_HOSTED_FOREMAN_DRIVER_STEP_SCHEMA_V1.to_owned(),
            step_digest: placeholder_digest(),
            bootstrap_digest: custody.bootstrap.bootstrap_digest,
            bootstrap_occurrence_id: custody.bootstrap.bootstrap_occurrence_id,
            run_id: run_id.to_owned(),
            step_ordinal: expected_step_ordinal,
            scheduler_process_occurrence_id: scheduler_process_occurrence_id.to_owned(),
            observed_projection_digest: domain_digest(
                b"nightshift.self-hosted-foreman-observed-projection.digest/v1\0",
                &projection_bytes,
            ),
            disposition,
            recorded_at,
            worker_dispatch_authorized: false,
            approval_response_authorized: false,
            protected_effect_authorized: false,
            semantic_retry_authorized: false,
            aggregate_result_created: false,
        };
        step.seal()?;
        let raw = serde_jcs::to_vec(&step)
            .map_err(|error| ForemanError::Serialization(error.to_string()))?;
        if raw.is_empty() || raw.len() > MAXIMUM_SELF_HOSTED_DRIVER_STEP_BYTES {
            return Err(ForemanError::InputTooLarge("self-hosted driver step"));
        }
        let retained_bytes: i64 = transaction.query_row(
            "SELECT COALESCE(SUM(length(raw_bytes)), 0)
             FROM self_hosted_driver_steps WHERE run_id = ?1",
            [run_id],
            |row| row.get(0),
        )?;
        let retained_bytes = usize::try_from(retained_bytes).map_err(|_| {
            ForemanError::ReadOnlyStore("self-hosted history length is invalid".to_owned())
        })?;
        if retained_bytes
            .checked_add(raw.len())
            .is_none_or(|total| total > MAXIMUM_SELF_HOSTED_HISTORY_BYTES)
        {
            return Err(ForemanError::InputTooLarge("self-hosted driver history"));
        }
        transaction.execute(
            "INSERT INTO self_hosted_driver_steps
             (run_id, step_ordinal, step_digest, scheduler_process_occurrence_id,
              recorded_at, raw_bytes) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                run_id,
                step.step_ordinal,
                step.step_digest,
                step.scheduler_process_occurrence_id,
                step.recorded_at.to_rfc3339(),
                raw,
            ],
        )?;
        transaction.commit()?;
        Ok(step)
    }

    pub fn worker_brief(&self, run_id: &str, work_item_id: &str) -> Result<Vec<u8>, ForemanError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let (packet, _, profile, _) = load_contracts(&transaction, run_id)?;
        let brief = worker_brief_bytes(&transaction, &packet, &profile, run_id, work_item_id)?;
        transaction.commit()?;
        Ok(brief)
    }
    pub fn prepare_attempt(
        &self,
        run_id: &str,
        work_item_id: &str,
        recorded_at: DateTime<Utc>,
    ) -> Result<WorkerStartRequestV2, ForemanError> {
        self.prepare_attempt_internal(run_id, work_item_id, recorded_at, None, None)
            .map(|(request, _)| request)
    }

    /// Atomically retain one exact FUEL decision and create the attempt it admitted.
    pub fn prepare_attempt_with_capacity(
        &self,
        run_id: &str,
        work_item_id: &str,
        evidence: CapacityAdmissionEvidenceV1<'_>,
        recorded_at: DateTime<Utc>,
    ) -> Result<WorkerStartRequestV2, ForemanError> {
        let capacity = validate_capacity_bundle(
            evidence.admission_bytes,
            evidence.observation_bytes,
            evidence.policy_bytes,
            evidence.decision_bytes,
        )?;
        self.prepare_attempt_internal(run_id, work_item_id, recorded_at, Some(capacity), None)
            .map(|(request, _)| request)
    }

    // The exact dispatch identity fields remain explicit at this owner boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_provider_attempt(
        &self,
        run_id: &str,
        work_item_id: &str,
        dispatch_occurrence_id: &str,
        adapter_process_occurrence_id: &str,
        app_server_session_identity: &str,
        selected_model_ordinal: u16,
        recorded_at: DateTime<Utc>,
    ) -> Result<OpenedProviderDispatchV1, ForemanError> {
        self.prepare_attempt_internal(
            run_id,
            work_item_id,
            recorded_at,
            None,
            Some(ProviderDispatchPreparation {
                dispatch_occurrence_id,
                adapter_process_occurrence_id,
                app_server_session_identity,
                selected_model_ordinal,
            }),
        )?
        .1
        .ok_or_else(|| {
            ForemanError::Transition("provider attempt lacks atomic V3 dispatch".to_owned())
        })
    }

    // FUEL admission and HOLDING dispatch are independently validated in one transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_provider_attempt_with_capacity(
        &self,
        run_id: &str,
        work_item_id: &str,
        capacity_evidence: CapacityAdmissionEvidenceV1<'_>,
        dispatch_occurrence_id: &str,
        adapter_process_occurrence_id: &str,
        app_server_session_identity: &str,
        selected_model_ordinal: u16,
        recorded_at: DateTime<Utc>,
    ) -> Result<OpenedProviderDispatchV1, ForemanError> {
        let capacity = validate_capacity_bundle(
            capacity_evidence.admission_bytes,
            capacity_evidence.observation_bytes,
            capacity_evidence.policy_bytes,
            capacity_evidence.decision_bytes,
        )?;
        self.prepare_attempt_internal(
            run_id,
            work_item_id,
            recorded_at,
            Some(capacity),
            Some(ProviderDispatchPreparation {
                dispatch_occurrence_id,
                adapter_process_occurrence_id,
                app_server_session_identity,
                selected_model_ordinal,
            }),
        )?
        .1
        .ok_or_else(|| {
            ForemanError::Transition("provider attempt lacks atomic V3 dispatch".to_owned())
        })
    }

    fn prepare_attempt_internal(
        &self,
        run_id: &str,
        work_item_id: &str,
        recorded_at: DateTime<Utc>,
        capacity: Option<ValidatedCapacityAdmission>,
        provider_dispatch: Option<ProviderDispatchPreparation<'_>>,
    ) -> Result<(WorkerStartRequestV2, Option<OpenedProviderDispatchV1>), ForemanError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let projection = load_projection(&transaction, run_id)?;
        let item = projection
            .work_items
            .iter()
            .find(|item| item.work_item_id == work_item_id)
            .ok_or_else(|| ForemanError::UnknownWorkItem(work_item_id.to_owned()))?;
        if !matches!(
            item.scheduler_state,
            SchedulerStateV1::ReadyEntryEvaluation | SchedulerStateV1::WaitingResource
        ) {
            return Err(ForemanError::Transition(format!(
                "{work_item_id} is {:?}, not entry-evaluation eligible",
                item.scheduler_state
            )));
        }
        if prior_attempt_exists(&transaction, run_id, work_item_id)? {
            return Err(ForemanError::Transition(
                "V1 admits no automatic or implicit second attempt".to_owned(),
            ));
        }
        for lock in &item.resource_lock_keys {
            let holder: Option<String> = transaction
                .query_row(
                    "SELECT work_item_id FROM resource_claims
                     WHERE run_id = ?1 AND resource_lock_key = ?2",
                    params![run_id, lock],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(holder) = holder {
                return Err(ForemanError::ResourceUnavailable(format!(
                    "{lock} held by {holder}"
                )));
            }
        }
        let (packet, admission, profile, _) = load_contracts(&transaction, run_id)?;
        let capacity_requirement = load_capacity_requirement(&transaction, run_id)?;
        let execution_availability = load_execution_availability_history(
            &transaction,
            run_id,
            &packet,
            &admission,
            &profile,
        )?;
        match (execution_availability.as_ref(), provider_dispatch.as_ref()) {
            (Some(_), None) => {
                return Err(ForemanError::Transition(
                    "availability-required run refuses legacy V2 start path".to_owned(),
                ))
            }
            (None, Some(_)) => {
                return Err(ForemanError::Transition(
                    "legacy run has no execution-availability requirement".to_owned(),
                ))
            }
            _ => {}
        }
        let mut slot_released_attempts = BTreeSet::new();
        if let Some(history) = &execution_availability {
            for transition in &history.resource_transitions {
                match transition.transition.as_str() {
                    "RELEASED" => {
                        slot_released_attempts.insert(transition.work_attempt_id.clone());
                    }
                    "REACQUIRED" => {
                        slot_released_attempts.remove(&transition.work_attempt_id);
                    }
                    _ => {
                        return Err(ForemanError::ReadOnlyStore(
                            "unknown resource transition projection".to_owned(),
                        ))
                    }
                }
            }
        }
        let active = projection
            .work_items
            .iter()
            .filter(|item| {
                item.active_attempt_id.as_ref().is_some_and(|attempt_id| {
                    !item.scheduler_state.is_explicit_terminal()
                        && !slot_released_attempts.contains(attempt_id)
                })
            })
            .count();
        if active >= usize::from(projection.maximum_concurrent_workers) {
            return Err(ForemanError::ResourceUnavailable(
                "maximum concurrent workers reached".to_owned(),
            ));
        }
        match (capacity_requirement.as_ref(), capacity.as_ref()) {
            (Some(_), None) => {
                return Err(ForemanError::Transition(
                    "capacity-required run refuses legacy attempt preparation".to_owned(),
                ))
            }
            (None, Some(_)) => {
                return Err(ForemanError::Transition(
                    "legacy run has no immutable capacity requirement".to_owned(),
                ))
            }
            _ => {}
        }
        let attempt_id = format!("attempt-{}", Uuid::new_v4());
        let execution = profile
            .work_items
            .get(work_item_id)
            .ok_or_else(|| ForemanError::UnknownWorkItem(work_item_id.to_owned()))?;
        let adapter = &profile.adapters[&execution.adapter_id];
        let worker_brief_digest =
            worker_brief_digest(&transaction, &packet, &profile, run_id, work_item_id)?;
        let mut request = WorkerStartRequestV2 {
            schema: WORKER_START_REQUEST_SCHEMA_V2.to_owned(),
            adapter_id: adapter.adapter_id.clone(),
            adapter_version: adapter.adapter_version.clone(),
            request_digest: placeholder_digest(),
            adapter_protocol: adapter.protocol.clone(),
            packet_digest: packet.packet_digest.clone(),
            run_id: run_id.to_owned(),
            work_item_id: work_item_id.to_owned(),
            attempt_id: attempt_id.clone(),
            worker_brief_digest,
            workspace_identity: execution.workspace_identity.clone(),
            provider_model_class: execution.provider_model_class.clone(),
            timeout_seconds: profile.adapter_timeout_seconds,
            maximum_output_bytes: profile.worker_output_bound(),
            recursive_worker_swarms_forbidden: true,
            approval_policy: "SURFACE_ONLY_NO_RESPONSE".to_owned(),
            expected_receipt_schema: WORKER_TERMINAL_RECEIPT_SCHEMA_V1.to_owned(),
        };
        request.seal()?;
        let brief = worker_brief_bytes(&transaction, &packet, &profile, run_id, work_item_id)?;
        WorkerBriefV2::from_slice_for_start(&brief, &request)?;
        if let Some(capacity) = capacity {
            validate_capacity_bindings(
                &capacity,
                &packet,
                &admission,
                &profile,
                capacity_requirement.as_ref().ok_or_else(|| {
                    ForemanError::Transition("capacity requirement missing".to_owned())
                })?,
                work_item_id,
                recorded_at,
            )?;
            let capacity_event = InternalEvent {
                schema: INTERNAL_EVENT_SCHEMA.to_owned(),
                event_id: format!("capacity-admitted-{}", Uuid::new_v4()),
                run_id: run_id.to_owned(),
                work_item_id: Some(work_item_id.to_owned()),
                attempt_id: Some(attempt_id.clone()),
                recorded_at,
                payload: InternalPayload::CapacityAdmissionAccepted {
                    capacity_admission: Box::new(capacity.admission),
                    admission_bytes: capacity.admission_bytes,
                    observation_bytes: capacity.observation_bytes,
                    policy_bytes: capacity.policy_bytes,
                    decision_bytes: capacity.decision_bytes,
                },
            };
            append_internal_bounded(
                &transaction,
                &capacity_event,
                profile.maximum_event_bytes,
                packet.work_items.len().saturating_add(1),
            )?;
        }
        for lock in &execution.resource_lock_keys {
            transaction.execute(
                "INSERT INTO resource_claims
                 (run_id, resource_lock_key, work_item_id, attempt_id)
                 VALUES (?1, ?2, ?3, ?4)",
                params![run_id, lock, work_item_id, attempt_id],
            )?;
        }
        append_internal(
            &transaction,
            &InternalEvent {
                schema: INTERNAL_EVENT_SCHEMA.to_owned(),
                event_id: format!("attempt-created-{}", Uuid::new_v4()),
                run_id: run_id.to_owned(),
                work_item_id: Some(work_item_id.to_owned()),
                attempt_id: Some(attempt_id.clone()),
                recorded_at,
                payload: InternalPayload::AttemptCreated {
                    resource_lock_keys: execution.resource_lock_keys.clone(),
                    start_request: Box::new(request.clone()),
                },
            },
        )?;
        let opened = if let Some(provider_dispatch) = provider_dispatch {
            let requirement = &execution_availability
                .as_ref()
                .ok_or_else(|| {
                    ForemanError::Transition(
                        "execution-availability requirement disappeared".to_owned(),
                    )
                })?
                .requirement;
            let opened = build_provider_dispatch(
                &request,
                &profile,
                requirement,
                provider_dispatch.dispatch_occurrence_id,
                provider_dispatch.adapter_process_occurrence_id,
                provider_dispatch.app_server_session_identity,
                provider_dispatch.selected_model_ordinal,
                1,
                recorded_at,
            )?;
            append_provider_dispatch(
                &transaction,
                run_id,
                work_item_id,
                &attempt_id,
                &opened,
                profile.maximum_event_bytes,
            )?;
            Some(opened)
        } else {
            None
        };
        load_execution_availability_history(&transaction, run_id, &packet, &admission, &profile)?;
        transaction.commit()?;
        Ok((request, opened))
    }

    // The recovery seam receives each independently retained dispatch identity.
    #[allow(clippy::too_many_arguments)]
    pub fn open_provider_dispatch(
        &self,
        run_id: &str,
        work_item_id: &str,
        attempt_id: &str,
        dispatch_occurrence_id: &str,
        adapter_process_occurrence_id: &str,
        app_server_session_identity: &str,
        selected_model_ordinal: u16,
        opened_at: DateTime<Utc>,
    ) -> Result<OpenedProviderDispatchV1, ForemanError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        exact_active_attempt(&transaction, run_id, work_item_id, attempt_id)?;
        let (packet, admission, profile, _) = load_contracts(&transaction, run_id)?;
        let history = load_execution_availability_history(
            &transaction,
            run_id,
            &packet,
            &admission,
            &profile,
        )?
        .ok_or_else(|| {
            ForemanError::Transition(
                "run has no immutable execution-availability requirement".to_owned(),
            )
        })?;
        if history
            .dispatches
            .iter()
            .any(|dispatch| dispatch.work_attempt_id == attempt_id)
        {
            return Err(ForemanError::Transition(
                "initial provider dispatch already exists for work attempt".to_owned(),
            ));
        }
        require_attempt_resource_claims(&transaction, &profile, run_id, work_item_id, attempt_id)?;
        let predecessor =
            load_attempt_start_request(&transaction, run_id, work_item_id, attempt_id)?;
        let opened = build_provider_dispatch(
            &predecessor,
            &profile,
            &history.requirement,
            dispatch_occurrence_id,
            adapter_process_occurrence_id,
            app_server_session_identity,
            selected_model_ordinal,
            1,
            opened_at,
        )?;
        append_provider_dispatch(
            &transaction,
            run_id,
            work_item_id,
            attempt_id,
            &opened,
            profile.maximum_event_bytes,
        )?;
        load_execution_availability_history(&transaction, run_id, &packet, &admission, &profile)?;
        transaction.commit()?;
        Ok(opened)
    }

    pub fn record_provider_disposition(
        &self,
        run_id: &str,
        work_item_id: &str,
        attempt_id: &str,
        evidence: ProviderDispositionEvidenceV1<'_>,
        predecessor_disposition_digest: Option<&str>,
    ) -> Result<ProviderAdmissionDispositionV1, ForemanError> {
        let accepted = validate_provider_disposition_evidence(evidence)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        exact_active_attempt(&transaction, run_id, work_item_id, attempt_id)?;
        let (packet, admission, profile, _) = load_contracts(&transaction, run_id)?;
        let history = load_execution_availability_history(
            &transaction,
            run_id,
            &packet,
            &admission,
            &profile,
        )?
        .ok_or_else(|| {
            ForemanError::Transition(
                "run has no immutable execution-availability requirement".to_owned(),
            )
        })?;
        let dispatch = history
            .dispatches
            .iter()
            .find(|dispatch| {
                dispatch.work_attempt_id == attempt_id
                    && dispatch.dispatch_digest == accepted.disposition.dispatch_digest
            })
            .ok_or_else(|| ForemanError::IdentityMismatch("dispatch_digest"))?;
        let lane_dispositions: Vec<&_> = history
            .dispositions
            .iter()
            .filter(|disposition| disposition.dispatch_digest == dispatch.dispatch_digest)
            .collect();
        match (lane_dispositions.last(), predecessor_disposition_digest) {
            (None, None) => {}
            (Some(previous), Some(expected)) if previous.disposition_digest == expected => {
                validate_provider_disposition_transition(previous, &accepted.disposition)?;
            }
            (None, Some(_)) | (Some(_), None) | (Some(_), Some(_)) => {
                return Err(ForemanError::Transition(
                    "provider disposition predecessor mismatch".to_owned(),
                ))
            }
        }
        let prior_history =
            provider_deferral_history(&history, attempt_id, dispatch.dispatch_ordinal)?;
        validate_execution_availability_graph(
            &history.requirement,
            &history.policy,
            dispatch,
            &accepted.observation,
            &accepted.disposition,
            &prior_history,
            accepted.deferred.as_ref(),
        )?;
        append_provider_disposition(
            &transaction,
            run_id,
            work_item_id,
            attempt_id,
            &accepted,
            predecessor_disposition_digest,
            profile.maximum_event_bytes,
        )?;
        if accepted.disposition.permits_automatic_park()
            && history.policy.parked_resource_lock_policy
                == ParkedResourceLockPolicyV1::ReleaseAndReacquire
        {
            let resource_lock_keys = profile
                .work_items
                .get(work_item_id)
                .ok_or_else(|| ForemanError::UnknownWorkItem(work_item_id.to_owned()))?
                .resource_lock_keys
                .clone();
            append_execution_availability_bounded(
                &transaction,
                &InternalEvent {
                    schema: INTERNAL_EVENT_SCHEMA.to_owned(),
                    event_id: format!(
                        "provider-resources-released-{}",
                        accepted.disposition.disposition_digest
                    ),
                    run_id: run_id.to_owned(),
                    work_item_id: Some(work_item_id.to_owned()),
                    attempt_id: Some(attempt_id.to_owned()),
                    recorded_at: accepted.disposition.received_at,
                    payload: InternalPayload::ProviderResourcesReleased {
                        disposition_digest: accepted.disposition.disposition_digest.clone(),
                        dispatch_digest: accepted.disposition.dispatch_digest.clone(),
                        policy_digest: history.policy.policy_digest.clone(),
                        resource_lock_keys,
                    },
                },
                profile.maximum_event_bytes,
            )?;
            transaction.execute(
                "DELETE FROM resource_claims
                 WHERE run_id = ?1 AND work_item_id = ?2 AND attempt_id = ?3",
                params![run_id, work_item_id, attempt_id],
            )?;
        }
        load_execution_availability_history(&transaction, run_id, &packet, &admission, &profile)?;
        transaction.commit()?;
        Ok(accepted.disposition)
    }

    // Wake and fresh-dispatch occurrence identities are intentionally separate.
    #[allow(clippy::too_many_arguments)]
    pub fn wake_provider_dispatch(
        &self,
        run_id: &str,
        work_item_id: &str,
        attempt_id: &str,
        wake_occurrence_id: &str,
        dispatch_occurrence_id: &str,
        adapter_process_occurrence_id: &str,
        app_server_session_identity: &str,
        selected_model_ordinal: u16,
        opened_at: DateTime<Utc>,
    ) -> Result<OpenedProviderDispatchV1, ForemanError> {
        validate_local_occurrence_id(wake_occurrence_id, "wake_occurrence_id")?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        exact_active_attempt(&transaction, run_id, work_item_id, attempt_id)?;
        let (packet, admission, profile, _) = load_contracts(&transaction, run_id)?;
        let history = load_execution_availability_history(
            &transaction,
            run_id,
            &packet,
            &admission,
            &profile,
        )?
        .ok_or_else(|| {
            ForemanError::Transition(
                "run has no immutable execution-availability requirement".to_owned(),
            )
        })?;
        if let Some(position) = history
            .wake_occurrence_ids
            .iter()
            .position(|value| value == wake_occurrence_id)
        {
            if history
                .wake_work_attempt_ids
                .get(position)
                .map(String::as_str)
                != Some(attempt_id)
            {
                return Err(ForemanError::DuplicateEvent(wake_occurrence_id.to_owned()));
            }
            let next_digest = history
                .wake_next_dispatch_digests
                .get(position)
                .ok_or_else(|| {
                    ForemanError::ReadOnlyStore(
                        "wake occurrence lacks exact next dispatch digest".to_owned(),
                    )
                })?;
            let global_index = history
                .dispatches
                .iter()
                .position(|dispatch| &dispatch.dispatch_digest == next_digest)
                .ok_or_else(|| {
                    ForemanError::ReadOnlyStore(
                        "wake occurrence lacks exact next dispatch".to_owned(),
                    )
                })?;
            let dispatch = &history.dispatches[global_index];
            let start_request = history.worker_start_requests[global_index].clone();
            if dispatch.dispatch_occurrence_id != dispatch_occurrence_id
                || dispatch.adapter_process_occurrence_id != adapter_process_occurrence_id
                || dispatch.app_server_session_identity != app_server_session_identity
                || dispatch.selected_model_ordinal != selected_model_ordinal
                || dispatch.opened_at != opened_at
            {
                return Err(ForemanError::DuplicateEvent(wake_occurrence_id.to_owned()));
            }
            transaction.commit()?;
            return Ok(OpenedProviderDispatchV1 {
                worker_start_request: start_request,
                dispatch: dispatch.clone(),
            });
        }
        if history.policy.parked_resource_lock_policy
            == ParkedResourceLockPolicyV1::ReleaseAndReacquire
        {
            let projection = load_projection(&transaction, run_id)?;
            let mut released_attempts = BTreeSet::new();
            for transition in &history.resource_transitions {
                match transition.transition.as_str() {
                    "RELEASED" => {
                        released_attempts.insert(transition.work_attempt_id.clone());
                    }
                    "REACQUIRED" => {
                        released_attempts.remove(&transition.work_attempt_id);
                    }
                    _ => {
                        return Err(ForemanError::ReadOnlyStore(
                            "unknown resource transition projection".to_owned(),
                        ))
                    }
                }
            }
            let active = projection
                .work_items
                .iter()
                .filter(|item| {
                    item.active_attempt_id
                        .as_ref()
                        .is_some_and(|active_attempt_id| {
                            !item.scheduler_state.is_explicit_terminal()
                                && !released_attempts.contains(active_attempt_id)
                        })
                })
                .count();
            if active >= usize::from(projection.maximum_concurrent_workers) {
                return Err(ForemanError::ResourceUnavailable(
                    "maximum concurrent workers reached while waking parked dispatch".to_owned(),
                ));
            }
        }
        let lane_dispatches: Vec<&_> = history
            .dispatches
            .iter()
            .filter(|dispatch| dispatch.work_attempt_id == attempt_id)
            .collect();
        let last_dispatch = lane_dispatches.last().copied().ok_or_else(|| {
            ForemanError::Transition("wake requires a prior provider dispatch".to_owned())
        })?;
        let last_disposition = history
            .dispositions
            .iter()
            .rev()
            .find(|disposition| disposition.dispatch_digest == last_dispatch.dispatch_digest)
            .ok_or_else(|| {
                ForemanError::Transition("wake requires a prior provider disposition".to_owned())
            })?;
        let deferred = history
            .deferred
            .iter()
            .find(|deferred| deferred.disposition_digest == last_disposition.disposition_digest)
            .ok_or_else(|| {
                ForemanError::Transition("wake requires exact parked deferral".to_owned())
            })?;
        if last_disposition.mechanism_state != ProviderMechanismStateV1::ParkedNotAdmitted
            || opened_at < deferred.wake_at
        {
            return Err(ForemanError::Transition(
                "parked dispatch is not yet wake eligible".to_owned(),
            ));
        }
        let selected_is_lawful = selected_model_ordinal == deferred.selected_model_ordinal
            || (history.policy.allow_ordered_model_fallback
                && deferred.remaining_model_ordinals.first().copied()
                    == Some(selected_model_ordinal));
        if !selected_is_lawful
            || lane_dispatches.len()
                >= usize::from(history.policy.maximum_dispatch_occurrences_per_attempt)
            || history.dispatches.iter().any(|dispatch| {
                dispatch.adapter_process_occurrence_id == adapter_process_occurrence_id
            })
        {
            return Err(ForemanError::Transition(
                "wake model, dispatch bound, or process occurrence is not lawful".to_owned(),
            ));
        }
        let predecessor =
            load_attempt_start_request(&transaction, run_id, work_item_id, attempt_id)?;
        let dispatch_ordinal = u16::try_from(lane_dispatches.len() + 1)
            .map_err(|_| ForemanError::Transition("dispatch ordinal overflow".to_owned()))?;
        let opened = build_provider_dispatch(
            &predecessor,
            &profile,
            &history.requirement,
            dispatch_occurrence_id,
            adapter_process_occurrence_id,
            app_server_session_identity,
            selected_model_ordinal,
            dispatch_ordinal,
            opened_at,
        )?;
        match history.policy.parked_resource_lock_policy {
            ParkedResourceLockPolicyV1::ReleaseAndReacquire => {
                reacquire_attempt_resource_claims(
                    &transaction,
                    &profile,
                    run_id,
                    work_item_id,
                    attempt_id,
                )?;
                append_execution_availability_bounded(
                    &transaction,
                    &InternalEvent {
                        schema: INTERNAL_EVENT_SCHEMA.to_owned(),
                        event_id: format!("provider-resources-reacquired-{wake_occurrence_id}"),
                        run_id: run_id.to_owned(),
                        work_item_id: Some(work_item_id.to_owned()),
                        attempt_id: Some(attempt_id.to_owned()),
                        recorded_at: opened_at,
                        payload: InternalPayload::ProviderResourcesReacquired {
                            wake_occurrence_id: wake_occurrence_id.to_owned(),
                            deferred_dispatch_digest: deferred.deferred_dispatch_digest.clone(),
                            next_dispatch_digest: opened.dispatch.dispatch_digest.clone(),
                            policy_digest: history.policy.policy_digest.clone(),
                            resource_lock_keys: profile.work_items[work_item_id]
                                .resource_lock_keys
                                .clone(),
                        },
                    },
                    profile.maximum_event_bytes,
                )?;
            }
            ParkedResourceLockPolicyV1::RetainWhileParked => require_attempt_resource_claims(
                &transaction,
                &profile,
                run_id,
                work_item_id,
                attempt_id,
            )?,
        }
        append_execution_availability_bounded(
            &transaction,
            &InternalEvent {
                schema: INTERNAL_EVENT_SCHEMA.to_owned(),
                event_id: format!("provider-wake-{wake_occurrence_id}"),
                run_id: run_id.to_owned(),
                work_item_id: Some(work_item_id.to_owned()),
                attempt_id: Some(attempt_id.to_owned()),
                recorded_at: opened_at,
                payload: InternalPayload::ProviderWakeOpened {
                    wake_occurrence_id: wake_occurrence_id.to_owned(),
                    deferred_dispatch_digest: deferred.deferred_dispatch_digest.clone(),
                    next_dispatch_digest: opened.dispatch.dispatch_digest.clone(),
                },
            },
            profile.maximum_event_bytes,
        )?;
        append_provider_dispatch(
            &transaction,
            run_id,
            work_item_id,
            attempt_id,
            &opened,
            profile.maximum_event_bytes,
        )?;
        load_execution_availability_history(&transaction, run_id, &packet, &admission, &profile)?;
        transaction.commit()?;
        Ok(opened)
    }

    // Resume binds every exact prior execution and fresh process occurrence field.
    #[allow(clippy::too_many_arguments)]
    pub fn resume_provider_execution(
        &self,
        run_id: &str,
        work_item_id: &str,
        attempt_id: &str,
        resume_occurrence_id: &str,
        disposition_digest: &str,
        adapter_process_occurrence_id: &str,
        execution_identity: &ProviderExecutionIdentityV1,
        recorded_at: DateTime<Utc>,
    ) -> Result<(), ForemanError> {
        validate_local_occurrence_id(resume_occurrence_id, "resume_occurrence_id")?;
        validate_local_occurrence_id(
            adapter_process_occurrence_id,
            "adapter_process_occurrence_id",
        )?;
        execution_identity.validate()?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        exact_active_attempt(&transaction, run_id, work_item_id, attempt_id)?;
        let (packet, admission, profile, _) = load_contracts(&transaction, run_id)?;
        let history = load_execution_availability_history(
            &transaction,
            run_id,
            &packet,
            &admission,
            &profile,
        )?
        .ok_or_else(|| {
            ForemanError::Transition(
                "run has no immutable execution-availability requirement".to_owned(),
            )
        })?;
        if let Some(position) = history
            .resume_occurrence_ids
            .iter()
            .position(|value| value == resume_occurrence_id)
        {
            if history
                .resume_work_item_ids
                .get(position)
                .map(String::as_str)
                != Some(work_item_id)
                || history
                    .resume_work_attempt_ids
                    .get(position)
                    .map(String::as_str)
                    != Some(attempt_id)
                || history
                    .resume_disposition_digests
                    .get(position)
                    .map(String::as_str)
                    != Some(disposition_digest)
                || history
                    .resume_adapter_process_occurrence_ids
                    .get(position)
                    .map(String::as_str)
                    != Some(adapter_process_occurrence_id)
                || history.resume_execution_identities.get(position) != Some(execution_identity)
                || history.resume_recorded_at.get(position) != Some(&recorded_at)
            {
                return Err(ForemanError::DuplicateEvent(
                    resume_occurrence_id.to_owned(),
                ));
            }
            transaction.commit()?;
            return Ok(());
        }
        let disposition = history
            .dispositions
            .iter()
            .rev()
            .find(|value| value.work_attempt_id == attempt_id)
            .ok_or_else(|| {
                ForemanError::Transition(
                    "resume requires exact post-admission disposition".to_owned(),
                )
            })?;
        if history
            .resume_disposition_digests
            .iter()
            .any(|value| value == disposition_digest)
            || history.dispatches.iter().any(|dispatch| {
                dispatch.adapter_process_occurrence_id == adapter_process_occurrence_id
            })
            || history
                .resume_adapter_process_occurrence_ids
                .iter()
                .any(|value| value == adapter_process_occurrence_id)
        {
            return Err(ForemanError::Transition(
                "resume disposition or adapter process occurrence is already retained".to_owned(),
            ));
        }
        if disposition.disposition_digest != disposition_digest
            || disposition.mechanism_state != ProviderMechanismStateV1::PostAdmissionInterrupted
            || disposition.provider_execution.as_ref() != Some(execution_identity)
            || execution_identity.app_server_session_identity
                != disposition.app_server_session_identity
            || recorded_at < disposition.received_at
        {
            return Err(ForemanError::Transition(
                "resume is not bound to exact interrupted execution".to_owned(),
            ));
        }
        require_attempt_resource_claims(&transaction, &profile, run_id, work_item_id, attempt_id)?;
        append_execution_availability_bounded(
            &transaction,
            &InternalEvent {
                schema: INTERNAL_EVENT_SCHEMA.to_owned(),
                event_id: format!("provider-resume-{resume_occurrence_id}"),
                run_id: run_id.to_owned(),
                work_item_id: Some(work_item_id.to_owned()),
                attempt_id: Some(attempt_id.to_owned()),
                recorded_at,
                payload: InternalPayload::ProviderExecutionResumeRequested {
                    resume_occurrence_id: resume_occurrence_id.to_owned(),
                    disposition_digest: disposition_digest.to_owned(),
                    adapter_process_occurrence_id: adapter_process_occurrence_id.to_owned(),
                    execution_identity: Box::new(execution_identity.clone()),
                },
            },
            profile.maximum_event_bytes,
        )?;
        load_execution_availability_history(&transaction, run_id, &packet, &admission, &profile)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn record_dispatch_requested(
        &self,
        run_id: &str,
        work_item_id: &str,
        attempt_id: &str,
        recorded_at: DateTime<Utc>,
    ) -> Result<(), ForemanError> {
        self.record_attempt_transition(
            run_id,
            work_item_id,
            attempt_id,
            recorded_at,
            InternalPayload::DispatchRequested,
            "dispatch-requested",
        )
    }

    pub fn record_resume_requested(
        &self,
        run_id: &str,
        work_item_id: &str,
        attempt_id: &str,
        recorded_at: DateTime<Utc>,
    ) -> Result<(), ForemanError> {
        self.record_attempt_transition(
            run_id,
            work_item_id,
            attempt_id,
            recorded_at,
            InternalPayload::ResumeRequested,
            "resume-requested",
        )
    }

    fn record_attempt_transition(
        &self,
        run_id: &str,
        work_item_id: &str,
        attempt_id: &str,
        recorded_at: DateTime<Utc>,
        payload: InternalPayload,
        prefix: &str,
    ) -> Result<(), ForemanError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        exact_active_attempt(&transaction, run_id, work_item_id, attempt_id)?;
        validate_complete_execution_availability_history(&transaction, run_id)?;
        refuse_holding_legacy_transition(&transaction, run_id, work_item_id, attempt_id)?;
        append_internal(
            &transaction,
            &InternalEvent {
                schema: INTERNAL_EVENT_SCHEMA.to_owned(),
                event_id: format!("{prefix}-{}", Uuid::new_v4()),
                run_id: run_id.to_owned(),
                work_item_id: Some(work_item_id.to_owned()),
                attempt_id: Some(attempt_id.to_owned()),
                recorded_at,
                payload,
            },
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn accept_adapter_event(&self, raw: &[u8]) -> Result<(), ForemanError> {
        let event = AdapterEventV1::from_slice(raw)?;
        event.validate()?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (_, admission, profile, _) = load_contracts(&transaction, &event.run_id)?;
        if raw.len() as u64 > profile.maximum_event_bytes {
            return Err(ForemanError::InputTooLarge("adapter event"));
        }
        if event.packet_digest != admission.packet_digest {
            return Err(ForemanError::IdentityMismatch("packet_digest"));
        }
        exact_active_attempt(
            &transaction,
            &event.run_id,
            &event.work_item_id,
            &event.attempt_id,
        )?;
        validate_holding_adapter_event_transition(&transaction, &event)?;
        let expected_adapter = &profile.work_items[&event.work_item_id].adapter_id;
        if &event.adapter_id != expected_adapter {
            return Err(ForemanError::IdentityMismatch("adapter_id"));
        }
        let adapter = &profile.adapters[expected_adapter];
        if event.adapter_version != adapter.adapter_version {
            return Err(ForemanError::IdentityMismatch("adapter_version"));
        }
        let projection = load_projection(&transaction, &event.run_id)?;
        let item = projection
            .work_items
            .iter()
            .find(|item| item.work_item_id == event.work_item_id)
            .ok_or_else(|| ForemanError::UnknownWorkItem(event.work_item_id.clone()))?;
        validate_incremental_identity(
            item.provider_identity.as_deref(),
            event.provider_identity.as_deref(),
            "provider_identity",
        )?;
        validate_incremental_identity(
            item.model_identity.as_deref(),
            event.model_identity.as_deref(),
            "model_identity",
        )?;
        validate_incremental_identity(
            item.session_identity.as_deref(),
            event.session_identity.as_deref(),
            "session_identity",
        )?;
        validate_incremental_identity(
            item.thread_identity.as_deref(),
            event.thread_identity.as_deref(),
            "thread_identity",
        )?;
        validate_incremental_identity(
            item.turn_identity.as_deref(),
            event.turn_identity.as_deref(),
            "turn_identity",
        )?;
        validate_incremental_identity(
            item.queue_identity.as_deref(),
            event.queue_identity.as_deref(),
            "queue_identity",
        )?;
        let duplicate: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM events WHERE run_id = ?1 AND event_id = ?2)",
            params![event.run_id, event.event_id],
            |row| row.get(0),
        )?;
        if duplicate {
            return Err(ForemanError::DuplicateEvent(event.event_id));
        }
        transaction.execute(
            "INSERT INTO events
             (event_id, run_id, work_item_id, attempt_id, kind, recorded_at, raw_bytes, raw_digest)
             VALUES (?1, ?2, ?3, ?4, 'adapter_event', ?5, ?6, ?7)",
            params![
                event.event_id,
                event.run_id,
                event.work_item_id,
                event.attempt_id,
                event.occurred_at.to_rfc3339(),
                raw,
                raw_digest(raw),
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn accept_terminal_receipt(&self, raw: &[u8]) -> Result<(), ForemanError> {
        let receipt = TerminalReceiptV1::from_slice(raw)?;
        receipt.validate()?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (_, admission, profile, _) = load_contracts(&transaction, &receipt.run_id)?;
        if raw.len() as u64 > profile.maximum_receipt_bytes {
            return Err(ForemanError::InputTooLarge("terminal receipt"));
        }
        if receipt.packet_digest != admission.packet_digest {
            return Err(ForemanError::IdentityMismatch("packet_digest"));
        }
        exact_active_attempt(
            &transaction,
            &receipt.run_id,
            &receipt.work_item_id,
            &receipt.attempt_id,
        )?;
        validate_holding_terminal_transition(&transaction, &receipt)?;
        let expected_adapter = &profile.work_items[&receipt.work_item_id].adapter_id;
        if expected_adapter != &receipt.adapter_id {
            return Err(ForemanError::IdentityMismatch("adapter_id"));
        }
        if profile.adapters[expected_adapter].adapter_version != receipt.adapter_version {
            return Err(ForemanError::IdentityMismatch("adapter_version"));
        }
        let projection = load_projection(&transaction, &receipt.run_id)?;
        let item = projection
            .work_items
            .iter()
            .find(|item| item.work_item_id == receipt.work_item_id)
            .ok_or_else(|| ForemanError::UnknownWorkItem(receipt.work_item_id.clone()))?;
        validate_receipt_identity(
            item.provider_identity.as_deref(),
            Some(receipt.provider_identity.as_str()),
            "provider_identity",
        )?;
        validate_receipt_identity(
            item.model_identity.as_deref(),
            Some(receipt.model_identity.as_str()),
            "model_identity",
        )?;
        validate_receipt_identity(
            item.session_identity.as_deref(),
            receipt.session_identity.as_deref(),
            "session_identity",
        )?;
        validate_receipt_identity(
            item.thread_identity.as_deref(),
            receipt.thread_identity.as_deref(),
            "thread_identity",
        )?;
        validate_receipt_identity(
            item.turn_identity.as_deref(),
            receipt.turn_identity.as_deref(),
            "turn_identity",
        )?;
        validate_receipt_identity(
            item.queue_identity.as_deref(),
            receipt.queue_identity.as_deref(),
            "queue_identity",
        )?;
        transaction.execute(
            "INSERT INTO terminal_receipts
             (run_id, work_item_id, attempt_id, receipt_digest, raw_bytes, receipt_kind)
             VALUES (?1, ?2, ?3, ?4, ?5, 'terminal')",
            params![
                receipt.run_id,
                receipt.work_item_id,
                receipt.attempt_id,
                receipt.receipt_digest,
                raw,
            ],
        )?;
        append_internal(
            &transaction,
            &InternalEvent {
                schema: INTERNAL_EVENT_SCHEMA.to_owned(),
                event_id: format!("terminal-accepted-{}", Uuid::new_v4()),
                run_id: receipt.run_id.clone(),
                work_item_id: Some(receipt.work_item_id.clone()),
                attempt_id: Some(receipt.attempt_id.clone()),
                recorded_at: receipt.ended_at,
                payload: InternalPayload::TerminalAccepted {
                    outcome: AcceptedOutcomeV1 {
                        state: receipt.state,
                        result_classification: receipt.result_classification,
                        receipt_digest: receipt.receipt_digest,
                    },
                },
            },
        )?;
        release_resources(
            &transaction,
            &receipt.run_id,
            &receipt.work_item_id,
            &receipt.attempt_id,
            receipt.ended_at,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn record_terminal_refusal(
        &self,
        run_id: &str,
        work_item_id: &str,
        attempt_id: &str,
        reason: &str,
        recorded_at: DateTime<Utc>,
    ) -> Result<(), ForemanError> {
        if reason.trim().is_empty() || reason.len() > 4096 {
            return Err(ForemanError::Transition(
                "invalid refusal reason".to_owned(),
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        exact_active_attempt(&transaction, run_id, work_item_id, attempt_id)?;
        validate_complete_execution_availability_history(&transaction, run_id)?;
        refuse_holding_legacy_transition(&transaction, run_id, work_item_id, attempt_id)?;
        append_internal(
            &transaction,
            &InternalEvent {
                schema: INTERNAL_EVENT_SCHEMA.to_owned(),
                event_id: format!("terminal-refused-{}", Uuid::new_v4()),
                run_id: run_id.to_owned(),
                work_item_id: Some(work_item_id.to_owned()),
                attempt_id: Some(attempt_id.to_owned()),
                recorded_at,
                payload: InternalPayload::TerminalRefused {
                    reason: reason.to_owned(),
                },
            },
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Accept mechanism-owned local closure testimony for an exact prepared
    /// attempt. The trusted local caller obtains these bytes from Switchyard's
    /// retained tombstone; a digest alone is not issuer authentication.
    pub fn accept_prelaunch_closure(&self, raw: &[u8]) -> Result<Vec<u8>, ForemanError> {
        let closure = PrelaunchClosureV1::from_slice(raw)?;
        let binding = &closure.binding;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (packet, admission, profile, _) = load_contracts(&transaction, &binding.run_id)?;
        let receipt = prelaunch_not_started_receipt(&closure)?;
        let receipt_bytes =
            serde_jcs::to_vec(&receipt).map_err(|e| ForemanError::Serialization(e.to_string()))?;
        if receipt_bytes.len() as u64 > profile.maximum_receipt_bytes {
            return Err(ForemanError::InputTooLarge("prelaunch receipt"));
        }
        let prior: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT raw_bytes FROM terminal_receipts WHERE run_id=?1 AND work_item_id=?2",
                params![binding.run_id, binding.work_item_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(prior) = prior {
            if prior != receipt_bytes {
                return Err(ForemanError::Transition(
                    "conflicting prelaunch closure".to_owned(),
                ));
            }
            load_projection(&transaction, &binding.run_id)?;
            return Ok(prior);
        }
        let projection = load_projection(&transaction, &binding.run_id)?;
        let item = projection
            .work_items
            .iter()
            .find(|item| item.work_item_id == binding.work_item_id)
            .ok_or_else(|| ForemanError::UnknownWorkItem(binding.work_item_id.clone()))?;
        if item.scheduler_state != SchedulerStateV1::Dispatching
            || item.active_attempt_id.as_deref() != Some(binding.work_attempt_id.as_str())
        {
            return Err(ForemanError::Transition(
                "prelaunch closure requires exact DISPATCHING attempt".to_owned(),
            ));
        }
        exact_active_attempt(
            &transaction,
            &binding.run_id,
            &binding.work_item_id,
            &binding.work_attempt_id,
        )?;
        let history = load_execution_availability_history(
            &transaction,
            &binding.run_id,
            &packet,
            &admission,
            &profile,
        )?
        .ok_or_else(|| {
            ForemanError::Transition(
                "prelaunch closure requires provider dispatch custody".to_owned(),
            )
        })?;
        let index = history
            .dispatches
            .iter()
            .rposition(|dispatch| dispatch.work_attempt_id == binding.work_attempt_id)
            .ok_or(ForemanError::IdentityMismatch("prelaunch dispatch"))?;
        if history
            .dispositions
            .iter()
            .any(|value| value.work_attempt_id == binding.work_attempt_id)
        {
            return Err(ForemanError::Transition(
                "prelaunch closure refuses observed provider disposition".to_owned(),
            ));
        }
        let brief = worker_brief_bytes(
            &transaction,
            &packet,
            &profile,
            &binding.run_id,
            &binding.work_item_id,
        )?;
        closure.validate_prepared(
            &history.worker_start_requests[index],
            &history.dispatches[index],
            &brief,
        )?;
        transaction.execute(
            "INSERT INTO terminal_receipts (run_id,work_item_id,attempt_id,receipt_digest,raw_bytes,receipt_kind)
             VALUES (?1,?2,NULL,?3,?4,'not_started')",
            params![binding.run_id, binding.work_item_id, receipt.receipt_digest, receipt_bytes])?;
        let event = InternalEvent {
            schema: INTERNAL_EVENT_SCHEMA.to_owned(),
            event_id: format!("prelaunch-closed-{}", closure.closure_digest),
            run_id: binding.run_id.clone(),
            work_item_id: Some(binding.work_item_id.clone()),
            attempt_id: Some(binding.work_attempt_id.clone()),
            recorded_at: closure.closed_at,
            payload: InternalPayload::PrelaunchClosureAccepted {
                closure: Box::new(closure.clone()),
                receipt: Box::new(receipt),
            },
        };
        if serde_jcs::to_vec(&event)
            .map_err(|e| ForemanError::Serialization(e.to_string()))?
            .len() as u64
            > profile.maximum_event_bytes
        {
            return Err(ForemanError::InputTooLarge("prelaunch journal event"));
        }
        append_internal(&transaction, &event)?;
        release_resources(
            &transaction,
            &binding.run_id,
            &binding.work_item_id,
            &binding.work_attempt_id,
            closure.closed_at,
        )?;
        load_projection(&transaction, &binding.run_id)?;
        transaction.commit()?;
        Ok(receipt_bytes)
    }

    pub fn accept_not_started(&self, raw: &[u8]) -> Result<(), ForemanError> {
        let receipt = NotStartedReceiptV1::from_slice(raw)?;
        receipt.validate()?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let projection = load_projection(&transaction, &receipt.run_id)?;
        let item = projection
            .work_items
            .iter()
            .find(|item| item.work_item_id == receipt.work_item_id)
            .ok_or_else(|| ForemanError::UnknownWorkItem(receipt.work_item_id.clone()))?;
        if !matches!(
            item.scheduler_state,
            SchedulerStateV1::ReadyEntryEvaluation | SchedulerStateV1::WaitingResource
        ) || item.active_attempt_id.is_some()
        {
            return Err(ForemanError::Transition(
                "not-started receipt requires an eligible item with no attempt".to_owned(),
            ));
        }
        let (_, admission, profile, _) = load_contracts(&transaction, &receipt.run_id)?;
        if raw.len() as u64 > profile.maximum_receipt_bytes {
            return Err(ForemanError::InputTooLarge("not-started receipt"));
        }
        if receipt.packet_digest != admission.packet_digest {
            return Err(ForemanError::IdentityMismatch("packet_digest"));
        }
        transaction.execute(
            "INSERT INTO terminal_receipts
             (run_id, work_item_id, attempt_id, receipt_digest, raw_bytes, receipt_kind)
             VALUES (?1, ?2, NULL, ?3, ?4, 'not_started')",
            params![
                receipt.run_id,
                receipt.work_item_id,
                receipt.receipt_digest,
                raw,
            ],
        )?;
        append_internal(
            &transaction,
            &InternalEvent {
                schema: INTERNAL_EVENT_SCHEMA.to_owned(),
                event_id: format!("not-started-accepted-{}", Uuid::new_v4()),
                run_id: receipt.run_id.clone(),
                work_item_id: Some(receipt.work_item_id.clone()),
                attempt_id: None,
                recorded_at: receipt.recorded_at,
                payload: InternalPayload::NotStartedAccepted {
                    outcome: AcceptedOutcomeV1 {
                        state: receipt.state,
                        result_classification: receipt.result_classification,
                        receipt_digest: receipt.receipt_digest,
                    },
                },
            },
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn close(&self, run_id: &str, updated_at: DateTime<Utc>) -> Result<Vec<u8>, ForemanError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(bytes) = transaction
            .query_row(
                "SELECT raw_bytes FROM final_snapshots WHERE run_id = ?1",
                [run_id],
                |row| row.get(0),
            )
            .optional()?
        {
            return Ok(bytes);
        }
        let projection = load_projection(&transaction, run_id)?;
        let incomplete: Vec<_> = projection
            .work_items
            .iter()
            .filter(|item| !item.scheduler_state.is_explicit_terminal())
            .map(|item| item.work_item_id.clone())
            .collect();
        if !incomplete.is_empty() {
            return Err(ForemanError::IncompleteCloseout(incomplete.join(", ")));
        }
        let latest_evidence = latest_terminal_evidence_at(&transaction, run_id)?;
        if updated_at < latest_evidence {
            return Err(ForemanError::Transition(format!(
                "closeout snapshot time {updated_at} precedes retained terminal evidence {latest_evidence}"
            )));
        }
        let (packet, _, _, _) = load_contracts(&transaction, run_id)?;
        let document = build_final_document(&transaction, &packet, run_id, updated_at)?;
        let raw = serde_jcs::to_vec(&document)
            .map_err(|error| ForemanError::Serialization(error.to_string()))?;
        let digest = raw_digest(&raw);
        transaction.execute(
            "INSERT INTO final_snapshots (run_id, updated_at, raw_digest, raw_bytes)
             VALUES (?1, ?2, ?3, ?4)",
            params![run_id, updated_at.to_rfc3339(), digest, raw],
        )?;
        append_internal(
            &transaction,
            &InternalEvent {
                schema: INTERNAL_EVENT_SCHEMA.to_owned(),
                event_id: format!("run-closed-{}", Uuid::new_v4()),
                run_id: run_id.to_owned(),
                work_item_id: None,
                attempt_id: None,
                recorded_at: updated_at,
                payload: InternalPayload::RunClosed {
                    final_receipts_digest: digest,
                },
            },
        )?;
        transaction.commit()?;
        Ok(raw)
    }

    pub fn export_final(&self, run_id: &str) -> Result<Vec<u8>, ForemanError> {
        self.connection()?
            .query_row(
                "SELECT raw_bytes FROM final_snapshots WHERE run_id = ?1",
                [run_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| ForemanError::Transition("run has no final snapshot".to_owned()))
    }

    pub fn raw_terminal_receipt(
        &self,
        run_id: &str,
        work_item_id: &str,
    ) -> Result<Vec<u8>, ForemanError> {
        self.connection()?
            .query_row(
                "SELECT raw_bytes FROM terminal_receipts
                 WHERE run_id = ?1 AND work_item_id = ?2",
                params![run_id, work_item_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| ForemanError::Transition("work item has no accepted receipt".to_owned()))
    }

    pub fn export_events(&self, run_id: &str) -> Result<Vec<Value>, ForemanError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        load_projection(&transaction, run_id)?;
        let events = {
            let mut statement = transaction
                .prepare("SELECT raw_bytes FROM events WHERE run_id = ?1 ORDER BY sequence ASC")?;
            let rows = statement.query_map([run_id], |row| row.get::<_, Vec<u8>>(0))?;
            rows.map(|row| {
                let bytes = row?;
                serde_json::from_slice(&bytes)
                    .map_err(|error| ForemanError::Serialization(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?
        };
        transaction.commit()?;
        Ok(events)
    }

    pub fn read_only_run_snapshot(
        &self,
        run_id: &str,
    ) -> Result<ReadOnlyRunSnapshotV1, ForemanError> {
        if !matches!(self.access, StoreAccess::ReadOnly { .. }) {
            return Err(ForemanError::ReadOnlyStore(
                "operator snapshot requires an explicitly read-only store".to_owned(),
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let (packet_bytes, admission_bytes, profile_bytes): (Vec<u8>, Vec<u8>, Vec<u8>) =
            transaction
                .query_row(
                    "SELECT packet_bytes, admission_bytes, profile_bytes
                     FROM runs WHERE run_id = ?1",
                    [run_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?
                .ok_or_else(|| ForemanError::UnknownRun(run_id.to_owned()))?;
        let projection = load_projection(&transaction, run_id)?;
        let packet = NightshiftPacketV1::from_slice(&packet_bytes)
            .map_err(|error| ForemanError::Packet(error.to_string()))?;
        packet
            .validate_integrity()
            .map_err(|error| ForemanError::Packet(error.to_string()))?;
        let admission = ForemanAdmissionV1::from_slice(&admission_bytes)?;
        admission.validate()?;
        let profile = ExecutionProfileV2::from_slice(&profile_bytes)?;
        profile.validate()?;
        validate_capacity_history_size(
            &transaction,
            run_id,
            profile.maximum_event_bytes,
            packet.work_items.len().saturating_add(1),
        )?;
        validate_execution_availability_history_size(
            &transaction,
            run_id,
            profile.maximum_event_bytes,
            false,
        )?;
        let events = {
            let mut statement = transaction.prepare(
                "SELECT sequence, event_id, work_item_id, attempt_id, kind, recorded_at,
                        raw_bytes, raw_digest
                 FROM events WHERE run_id = ?1 ORDER BY sequence ASC",
            )?;
            let rows = statement.query_map([run_id], |row| {
                Ok(ReadOnlyEventRowV1 {
                    sequence: row.get(0)?,
                    event_id: row.get(1)?,
                    work_item_id: row.get(2)?,
                    attempt_id: row.get(3)?,
                    kind: row.get(4)?,
                    recorded_at: row.get(5)?,
                    raw_bytes: row.get(6)?,
                    raw_digest: row.get(7)?,
                })
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let capacity_history =
            validate_capacity_history(&transaction, &events, &packet, &admission, &profile)?;
        let execution_availability = validate_execution_availability_history_rows(
            &transaction,
            &events,
            &packet,
            &admission,
            &profile,
        )?;
        let capacity_requirement = capacity_history.requirement;
        let capacity_admissions = capacity_history.admissions;
        let run_closed = validate_read_only_run_closed_binding(&events)?;
        let terminal_receipts = {
            let mut statement = transaction.prepare(
                "SELECT work_item_id, attempt_id, receipt_digest, raw_bytes, receipt_kind
                 FROM terminal_receipts WHERE run_id = ?1 ORDER BY work_item_id ASC",
            )?;
            let rows = statement.query_map([run_id], |row| {
                Ok(ReadOnlyTerminalReceiptRowV1 {
                    work_item_id: row.get(0)?,
                    attempt_id: row.get(1)?,
                    receipt_digest: row.get(2)?,
                    raw_bytes: row.get(3)?,
                    receipt_kind: row.get(4)?,
                    state: String::new(),
                    result_classification: String::new(),
                })
            })?;
            let rows = rows.collect::<Result<Vec<_>, _>>()?;
            let mut validated = Vec::with_capacity(rows.len());
            for row in rows {
                validated.push(validate_read_only_receipt_row(
                    run_id,
                    row,
                    &projection.packet_digest,
                    &profile,
                )?);
            }
            validated
        };
        validate_read_only_projection_receipts(&projection, &terminal_receipts)?;
        let final_snapshot_row = transaction
            .query_row(
                "SELECT updated_at, raw_digest, raw_bytes
                 FROM final_snapshots WHERE run_id = ?1",
                [run_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()?;
        let final_snapshot_bytes = match (
            final_snapshot_row,
            run_closed,
            projection.closed_final_receipts_digest.as_deref(),
        ) {
            (None, None, None) => None,
            (
                Some((updated_at, retained_digest, bytes)),
                Some((run_closed_sequence, run_closed_at, run_closed_digest)),
                Some(replayed_digest),
            ) => {
                if retained_digest != raw_digest(&bytes)
                    || retained_digest != replayed_digest
                    || retained_digest != run_closed_digest
                    || events.last().map(|event| event.sequence) != Some(run_closed_sequence)
                {
                    return Err(ForemanError::ReadOnlyStore(
                        "final snapshot digest and RunClosed replay disagree".to_owned(),
                    ));
                }
                let updated_at = DateTime::parse_from_rfc3339(&updated_at)
                    .map_err(|error| ForemanError::Serialization(error.to_string()))?
                    .with_timezone(&Utc);
                if updated_at != run_closed_at
                    || updated_at < latest_terminal_evidence_at(&transaction, run_id)?
                {
                    return Err(ForemanError::ReadOnlyStore(
                        "final snapshot and RunClosed time custody disagree".to_owned(),
                    ));
                }
                let rebuilt = build_final_document(&transaction, &packet, run_id, updated_at)?;
                let rebuilt = serde_jcs::to_vec(&rebuilt)
                    .map_err(|error| ForemanError::Serialization(error.to_string()))?;
                if rebuilt != bytes {
                    return Err(ForemanError::ReadOnlyStore(
                        "final snapshot bytes do not reproduce from exact accepted receipts"
                            .to_owned(),
                    ));
                }
                Some(bytes)
            }
            _ => {
                return Err(ForemanError::ReadOnlyStore(
                    "final snapshot presence and RunClosed replay disagree".to_owned(),
                ));
            }
        };
        transaction.commit()?;
        Ok(ReadOnlyRunSnapshotV1 {
            run_id: run_id.to_owned(),
            packet_bytes,
            admission_bytes,
            profile_bytes,
            projection,
            events,
            capacity_requirement,
            capacity_admissions,
            execution_availability,
            terminal_receipts,
            final_snapshot_bytes,
        })
    }

    pub fn journal_mode(&self) -> Result<String, ForemanError> {
        Ok(self
            .connection()?
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))?)
    }

    fn connection(&self) -> Result<Connection, ForemanError> {
        match &self.access {
            StoreAccess::ReadWrite => {
                let connection = Connection::open(&self.path)?;
                connection.pragma_update(None, "journal_mode", "WAL")?;
                connection.pragma_update(None, "foreign_keys", "ON")?;
                connection.busy_timeout(std::time::Duration::from_secs(5))?;
                Ok(connection)
            }
            StoreAccess::ReadOnly { descriptor } => {
                let descriptor_path =
                    PathBuf::from(format!("/proc/self/fd/{}", descriptor.as_raw_fd()));
                let resolved = fs::read_link(&descriptor_path).map_err(|error| {
                    ForemanError::ReadOnlyStore(format!(
                        "cannot resolve retained database descriptor: {error}"
                    ))
                })?;
                let resolved = resolved.to_str().ok_or_else(|| {
                    ForemanError::ReadOnlyStore(
                        "resolved database path must be valid UTF-8".to_owned(),
                    )
                })?;
                if resolved.ends_with(" (deleted)") {
                    return Err(ForemanError::ReadOnlyStore(
                        "retained database has been unlinked".to_owned(),
                    ));
                }
                let wal_path = PathBuf::from(format!("{resolved}-wal"));
                let shm_path = PathBuf::from(format!("{resolved}-shm"));
                let wal = open_read_only_sidecar(&wal_path)?;
                let shm = open_read_only_sidecar(&shm_path)?;
                let immutable = match (&wal, &shm) {
                    (None, None) => true,
                    (Some(_), Some(_)) => false,
                    _ => {
                        return Err(ForemanError::ReadOnlyStore(
                            "WAL and SHM sidecars must both be absent or both be regular files"
                                .to_owned(),
                        ));
                    }
                };
                let suffix = if immutable {
                    "?mode=ro&immutable=1"
                } else {
                    "?mode=ro"
                };
                let uri = format!("file:/proc/self/fd/{}{suffix}", descriptor.as_raw_fd());
                let connection = Connection::open_with_flags(
                    uri,
                    OpenFlags::SQLITE_OPEN_READ_ONLY
                        | OpenFlags::SQLITE_OPEN_URI
                        | OpenFlags::SQLITE_OPEN_NO_MUTEX,
                )
                .map_err(ForemanError::Sql)?;
                connection.pragma_update(None, "query_only", "ON")?;
                let query_only: u8 =
                    connection.query_row("PRAGMA query_only", [], |row| row.get(0))?;
                if query_only != 1 {
                    return Err(ForemanError::ReadOnlyStore(
                        "SQLite query_only was not enabled".to_owned(),
                    ));
                }
                if let (Some(wal), Some(shm)) = (&wal, &shm) {
                    require_same_file(wal, &wal_path, "WAL")?;
                    require_same_file(shm, &shm_path, "SHM")?;
                } else if wal_path.exists() || shm_path.exists() {
                    return Err(ForemanError::ReadOnlyStore(
                        "sidecar state changed during query-only connection open".to_owned(),
                    ));
                }
                Ok(connection)
            }
        }
    }
}

fn load_self_hosted_bootstrap(
    connection: &Connection,
    run_id: &str,
) -> Result<ReadOnlySelfHostedBootstrapV1, ForemanError> {
    let table_exists: bool = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM sqlite_schema
            WHERE type = 'table' AND name = 'self_hosted_bootstraps'
         )",
        [],
        |row| row.get(0),
    )?;
    if !table_exists {
        return Err(ForemanError::ReadOnlyStore(
            "store has no self-hosted bootstrap custody table".to_owned(),
        ));
    }
    let bootstrap_lengths: Option<(i64, i64)> = connection
        .query_row(
            "SELECT length(bootstrap_bytes), length(capacity_policy_bytes)
             FROM self_hosted_bootstraps WHERE run_id = ?1",
            [run_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (bootstrap_length, capacity_policy_length) = bootstrap_lengths.ok_or_else(|| {
        ForemanError::Transition("run has no self-hosted bootstrap custody".to_owned())
    })?;
    if bootstrap_length <= 0
        || capacity_policy_length <= 0
        || usize::try_from(bootstrap_length)
            .ok()
            .is_none_or(|size| size > MAXIMUM_WORKER_BRIEF_BYTES)
        || usize::try_from(capacity_policy_length)
            .ok()
            .is_none_or(|size| size > MAXIMUM_WORKER_BRIEF_BYTES)
    {
        return Err(ForemanError::InputTooLarge("self-hosted bootstrap custody"));
    }
    let (step_count, maximum_step_length, total_step_length): (i64, i64, i64) = connection
        .query_row(
            "SELECT COUNT(*), COALESCE(MAX(length(raw_bytes)), 0),
                    COALESCE(SUM(length(raw_bytes)), 0)
             FROM self_hosted_driver_steps WHERE run_id = ?1",
            [run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
    if !(0..=1_000_000).contains(&step_count)
        || maximum_step_length < 0
        || total_step_length < 0
        || usize::try_from(maximum_step_length)
            .ok()
            .is_none_or(|size| size > MAXIMUM_SELF_HOSTED_DRIVER_STEP_BYTES)
        || usize::try_from(total_step_length)
            .ok()
            .is_none_or(|size| size > MAXIMUM_SELF_HOSTED_HISTORY_BYTES)
    {
        return Err(ForemanError::InputTooLarge("self-hosted driver history"));
    }
    let row: (String, String, Vec<u8>, Vec<u8>, String, String, u32) = connection
        .query_row(
            "SELECT bootstrap_digest, bootstrap_occurrence_id, bootstrap_bytes,
                    capacity_policy_bytes, admitted_at, deadline_at, maximum_driver_steps
             FROM self_hosted_bootstraps WHERE run_id = ?1",
            [run_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| {
            ForemanError::Transition("run has no self-hosted bootstrap custody".to_owned())
        })?;
    let bootstrap = SelfHostedForemanBootstrapV1::from_slice(&row.2)?;
    let deadline = bootstrap
        .evaluated_at
        .checked_add_signed(chrono::Duration::seconds(i64::from(
            bootstrap.maximum_wall_seconds,
        )))
        .ok_or_else(|| ForemanError::ReadOnlyStore("bootstrap deadline overflow".to_owned()))?;
    if bootstrap.run_id != run_id
        || bootstrap.bootstrap_digest != row.0
        || bootstrap.bootstrap_occurrence_id != row.1
        || bootstrap.evaluated_at.to_rfc3339() != row.4
        || deadline.to_rfc3339() != row.5
        || bootstrap.maximum_driver_steps != row.6
    {
        return Err(ForemanError::ReadOnlyStore(
            "bootstrap custody columns disagree with exact record".to_owned(),
        ));
    }
    let (packet_bytes, admission_bytes, profile_bytes): (Vec<u8>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT packet_bytes, admission_bytes, profile_bytes FROM runs WHERE run_id = ?1",
            [run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
    let (packet, admission, profile, _) = load_contracts(connection, run_id)?;
    if serde_jcs::to_vec(&packet).map_err(|error| ForemanError::Serialization(error.to_string()))?
        != packet_bytes
        || serde_jcs::to_vec(&admission)
            .map_err(|error| ForemanError::Serialization(error.to_string()))?
            != admission_bytes
        || serde_jcs::to_vec(&profile)
            .map_err(|error| ForemanError::Serialization(error.to_string()))?
            != profile_bytes
    {
        return Err(ForemanError::ReadOnlyStore(
            "self-hosted run contracts are not exact canonical row bytes".to_owned(),
        ));
    }
    validate_capacity_history_size(
        connection,
        run_id,
        profile.maximum_event_bytes,
        packet.work_items.len().saturating_add(1),
    )?;
    validate_execution_availability_history_size(
        connection,
        run_id,
        profile.maximum_event_bytes,
        false,
    )?;
    let mut statement = connection.prepare(
        "SELECT sequence, event_id, work_item_id, attempt_id, kind, recorded_at,
                raw_bytes, raw_digest
         FROM events WHERE run_id = ?1 ORDER BY sequence ASC",
    )?;
    let events = statement
        .query_map([run_id], |row| {
            Ok(ReadOnlyEventRowV1 {
                sequence: row.get(0)?,
                event_id: row.get(1)?,
                work_item_id: row.get(2)?,
                attempt_id: row.get(3)?,
                kind: row.get(4)?,
                recorded_at: row.get(5)?,
                raw_bytes: row.get(6)?,
                raw_digest: row.get(7)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let capacity_history =
        validate_capacity_history(connection, &events, &packet, &admission, &profile)?;
    let capacity_requirement = capacity_history.requirement.ok_or_else(|| {
        ForemanError::ReadOnlyStore("bootstrap capacity requirement is absent".to_owned())
    })?;
    let availability_history = validate_execution_availability_history_rows(
        connection, &events, &packet, &admission, &profile,
    )?
    .ok_or_else(|| {
        ForemanError::ReadOnlyStore("bootstrap availability configuration is absent".to_owned())
    })?;
    bootstrap.validate_graph(
        &packet_bytes,
        &admission_bytes,
        &profile_bytes,
        &capacity_requirement.requirement_bytes,
        &row.3,
        &availability_history.requirement_bytes,
        &availability_history.policy_bytes,
    )?;
    let mut steps = Vec::new();
    let mut step_bytes = Vec::new();
    let mut previous_recorded_at = None;
    let mut terminal_closed = false;
    let mut statement = connection.prepare(
        "SELECT step_ordinal, step_digest, scheduler_process_occurrence_id,
                recorded_at, raw_bytes
         FROM self_hosted_driver_steps WHERE run_id = ?1 ORDER BY step_ordinal",
    )?;
    let rows = statement.query_map([run_id], |row| {
        Ok((
            row.get::<_, u32>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Vec<u8>>(4)?,
        ))
    })?;
    for (index, candidate) in rows.enumerate() {
        let candidate = candidate?;
        let step = SelfHostedForemanDriverStepV1::from_slice(&candidate.4)?;
        let expected_ordinal = u32::try_from(index + 1)
            .map_err(|_| ForemanError::ReadOnlyStore("driver ordinal overflow".to_owned()))?;
        if terminal_closed
            || previous_recorded_at.is_some_and(|previous| step.recorded_at < previous)
            || step.run_id != run_id
            || step.bootstrap_digest != bootstrap.bootstrap_digest
            || step.bootstrap_occurrence_id != bootstrap.bootstrap_occurrence_id
            || step.step_ordinal != expected_ordinal
            || step.step_ordinal != candidate.0
            || step.step_digest != candidate.1
            || step.scheduler_process_occurrence_id != candidate.2
            || step.recorded_at.to_rfc3339() != candidate.3
            || step.recorded_at < bootstrap.evaluated_at
            || step.step_ordinal > bootstrap.maximum_driver_steps
        {
            return Err(ForemanError::ReadOnlyStore(
                "driver step columns or bootstrap binding disagree".to_owned(),
            ));
        }
        previous_recorded_at = Some(step.recorded_at);
        terminal_closed = matches!(
            &step.disposition,
            SelfHostedDriverDispositionV1::BoundReached
                | SelfHostedDriverDispositionV1::AllItemsExplicitTerminal
        );
        steps.push(step);
        step_bytes.push(candidate.4);
    }
    Ok(ReadOnlySelfHostedBootstrapV1 {
        bootstrap,
        bootstrap_bytes: row.2,
        capacity_policy_bytes: row.3,
        steps,
        step_bytes,
    })
}

fn validate_read_only_event_row(
    row: &ReadOnlyEventRowV1,
    expected_run_id: &str,
    expected_packet_digest: &str,
    profile: &ExecutionProfileV2,
) -> Result<(), ForemanError> {
    if row.sequence == 0 || row.raw_digest != raw_digest(&row.raw_bytes) {
        return Err(ForemanError::ReadOnlyStore(
            "journal sequence or retained-raw digest mismatch".to_owned(),
        ));
    }
    if row.kind == "adapter_event" {
        let event = AdapterEventV1::from_slice(&row.raw_bytes)?;
        event.validate()?;
        if event.event_id != row.event_id
            || event.run_id != expected_run_id
            || event.packet_digest != expected_packet_digest
            || row.work_item_id.as_deref() != Some(event.work_item_id.as_str())
            || row.attempt_id.as_deref() != Some(event.attempt_id.as_str())
            || event.occurred_at.to_rfc3339() != row.recorded_at
            || profile
                .work_items
                .get(&event.work_item_id)
                .map(|work| work.adapter_id.as_str())
                != Some(event.adapter_id.as_str())
            || profile
                .adapters
                .get(&event.adapter_id)
                .map(|adapter| adapter.adapter_version.as_str())
                != Some(event.adapter_version.as_str())
        {
            return Err(ForemanError::ReadOnlyStore(
                "adapter event row identity mismatch".to_owned(),
            ));
        }
    } else if matches!(
        row.kind.as_str(),
        "internal"
            | "capacity_requirement"
            | "capacity_admission"
            | "execution_availability_requirement"
            | "provider_dispatch"
            | "provider_disposition"
            | "provider_wake"
            | "provider_resume"
            | "provider_resources_released"
            | "provider_resources_reacquired"
    ) {
        let event: InternalEvent = serde_json::from_slice(&row.raw_bytes)
            .map_err(|error| ForemanError::Serialization(error.to_string()))?;
        let kind_matches_payload = matches!(
            (row.kind.as_str(), &event.payload),
            ("internal", InternalPayload::RunAdmitted)
                | ("internal", InternalPayload::AttemptCreated { .. })
                | ("internal", InternalPayload::DispatchRequested)
                | ("internal", InternalPayload::ResumeRequested)
                | ("internal", InternalPayload::TerminalAccepted { .. })
                | ("internal", InternalPayload::TerminalRefused { .. })
                | ("internal", InternalPayload::NotStartedAccepted { .. })
                | ("internal", InternalPayload::PrelaunchClosureAccepted { .. })
                | ("internal", InternalPayload::ResourcesReleased)
                | ("internal", InternalPayload::RunClosed { .. })
                | (
                    "capacity_requirement",
                    InternalPayload::CapacityRequirementAdmitted { .. }
                )
                | (
                    "capacity_admission",
                    InternalPayload::CapacityAdmissionAccepted { .. }
                )
                | (
                    "execution_availability_requirement",
                    InternalPayload::ExecutionAvailabilityConfigured { .. }
                )
                | (
                    "provider_dispatch",
                    InternalPayload::ProviderDispatchOpened { .. }
                )
                | (
                    "provider_disposition",
                    InternalPayload::ProviderDispositionRecorded { .. }
                )
                | ("provider_wake", InternalPayload::ProviderWakeOpened { .. })
                | (
                    "provider_resume",
                    InternalPayload::ProviderExecutionResumeRequested { .. }
                )
                | (
                    "provider_resources_released",
                    InternalPayload::ProviderResourcesReleased { .. }
                )
                | (
                    "provider_resources_reacquired",
                    InternalPayload::ProviderResourcesReacquired { .. }
                )
        );
        if !kind_matches_payload
            || event.schema != INTERNAL_EVENT_SCHEMA
            || event.event_id != row.event_id
            || event.run_id != expected_run_id
            || event.work_item_id != row.work_item_id
            || event.attempt_id != row.attempt_id
            || event.recorded_at.to_rfc3339() != row.recorded_at
        {
            return Err(ForemanError::ReadOnlyStore(
                "internal event row identity mismatch".to_owned(),
            ));
        }
        if serde_jcs::to_vec(&event)
            .map_err(|error| ForemanError::Serialization(error.to_string()))?
            != row.raw_bytes
        {
            return Err(ForemanError::ReadOnlyStore(
                "internal event exact bytes are not canonical".to_owned(),
            ));
        }
        if let InternalPayload::AttemptCreated { start_request, .. } = &event.payload {
            start_request.validate()?;
            if start_request.run_id != expected_run_id
                || start_request.packet_digest != expected_packet_digest
                || event.work_item_id.as_deref() != Some(start_request.work_item_id.as_str())
                || event.attempt_id.as_deref() != Some(start_request.attempt_id.as_str())
            {
                return Err(ForemanError::ReadOnlyStore(
                    "attempt-created start request mismatch".to_owned(),
                ));
            }
        }
    } else {
        return Err(ForemanError::ReadOnlyStore(
            "unknown journal row kind".to_owned(),
        ));
    }
    Ok(())
}

fn read_only_capacity_admissions(
    events: &[ReadOnlyEventRowV1],
    packet: &NightshiftPacketV1,
    admission: &ForemanAdmissionV1,
    profile: &ExecutionProfileV2,
) -> Result<
    (
        Option<ReadOnlyCapacityRequirementV1>,
        Vec<ReadOnlyCapacityAdmissionV1>,
    ),
    ForemanError,
> {
    let mut requirement = None;
    let mut attempts = BTreeSet::new();
    let mut capacity_by_attempt = BTreeMap::new();
    for row in events {
        if row.kind == "adapter_event" {
            continue;
        }
        let event: InternalEvent = serde_json::from_slice(&row.raw_bytes)
            .map_err(|error| ForemanError::Serialization(error.to_string()))?;
        match event.payload {
            InternalPayload::CapacityRequirementAdmitted {
                requirement: candidate,
                requirement_bytes,
            } => {
                if requirement.is_some()
                    || event.work_item_id.is_some()
                    || event.attempt_id.is_some()
                    || serde_jcs::to_vec(&*candidate)
                        .map_err(|error| ForemanError::Serialization(error.to_string()))?
                        != requirement_bytes
                {
                    return Err(ForemanError::ReadOnlyStore(
                        "capacity requirement event custody is invalid".to_owned(),
                    ));
                }
                candidate.validate()?;
                validate_capacity_requirement(&candidate, packet, admission, profile)?;
                requirement = Some(ReadOnlyCapacityRequirementV1 {
                    recorded_at: event.recorded_at.to_rfc3339(),
                    requirement: *candidate,
                    requirement_bytes,
                });
            }
            InternalPayload::CapacityAdmissionAccepted {
                capacity_admission,
                admission_bytes,
                observation_bytes,
                policy_bytes,
                decision_bytes,
            } => {
                let work_item_id = event.work_item_id.ok_or_else(|| {
                    ForemanError::ReadOnlyStore(
                        "capacity admission lacks work item identity".to_owned(),
                    )
                })?;
                let attempt_id = event.attempt_id.ok_or_else(|| {
                    ForemanError::ReadOnlyStore(
                        "capacity admission lacks attempt identity".to_owned(),
                    )
                })?;
                let bundle = validate_capacity_bundle(
                    &admission_bytes,
                    &observation_bytes,
                    &policy_bytes,
                    &decision_bytes,
                )?;
                if bundle.admission != *capacity_admission
                    || capacity_by_attempt.contains_key(&attempt_id)
                {
                    return Err(ForemanError::ReadOnlyStore(
                        "capacity admission event exact bytes or identity disagree".to_owned(),
                    ));
                }
                let exact_requirement = requirement.as_ref().ok_or_else(|| {
                    ForemanError::ReadOnlyStore(
                        "capacity admission precedes immutable requirement".to_owned(),
                    )
                })?;
                validate_capacity_bindings(
                    &bundle,
                    packet,
                    admission,
                    profile,
                    &exact_requirement.requirement,
                    &work_item_id,
                    event.recorded_at,
                )?;
                capacity_by_attempt.insert(
                    attempt_id.clone(),
                    ReadOnlyCapacityAdmissionV1 {
                        work_item_id,
                        attempt_id,
                        recorded_at: event.recorded_at.to_rfc3339(),
                        capacity_admission: *capacity_admission,
                        admission_bytes,
                        observation_bytes,
                        policy_bytes,
                        decision_bytes,
                    },
                );
            }
            InternalPayload::AttemptCreated { .. } => {
                let attempt_id = event.attempt_id.ok_or_else(|| {
                    ForemanError::ReadOnlyStore("attempt-created lacks identity".to_owned())
                })?;
                attempts.insert(attempt_id);
            }
            _ => {}
        }
    }
    if requirement.is_some()
        && (attempts != capacity_by_attempt.keys().cloned().collect::<BTreeSet<_>>())
    {
        return Err(ForemanError::ReadOnlyStore(
            "capacity-required attempt graph is incomplete".to_owned(),
        ));
    }
    if requirement.is_none() && !capacity_by_attempt.is_empty() {
        return Err(ForemanError::ReadOnlyStore(
            "legacy run carries capacity admission evidence".to_owned(),
        ));
    }
    Ok((requirement, capacity_by_attempt.into_values().collect()))
}

struct ValidatedCapacityHistory {
    requirement: Option<ReadOnlyCapacityRequirementV1>,
    admissions: Vec<ReadOnlyCapacityAdmissionV1>,
}

fn validate_capacity_history(
    connection: &Connection,
    events: &[ReadOnlyEventRowV1],
    packet: &NightshiftPacketV1,
    admission: &ForemanAdmissionV1,
    profile: &ExecutionProfileV2,
) -> Result<ValidatedCapacityHistory, ForemanError> {
    validate_capacity_history_size(
        connection,
        &admission.run_id,
        profile.maximum_event_bytes,
        packet.work_items.len().saturating_add(1),
    )?;
    for row in events {
        validate_read_only_event_row(row, &admission.run_id, &packet.packet_digest, profile)?;
    }
    let (requirement, admissions) =
        read_only_capacity_admissions(events, packet, admission, profile)?;
    let parsed = events
        .iter()
        .map(|row| {
            if row.kind != "adapter_event" {
                serde_json::from_slice::<InternalEvent>(&row.raw_bytes)
                    .map(Some)
                    .map_err(|error| ForemanError::Serialization(error.to_string()))
            } else {
                Ok(None)
            }
        })
        .collect::<Result<Vec<_>, ForemanError>>()?;

    let run_positions = parsed
        .iter()
        .enumerate()
        .filter_map(|(index, event)| {
            event.as_ref().and_then(|event| {
                matches!(event.payload, InternalPayload::RunAdmitted).then_some(index)
            })
        })
        .collect::<Vec<_>>();
    if run_positions.len() != 1 {
        return Err(ForemanError::ReadOnlyStore(
            "journal must contain one exact run-admitted event".to_owned(),
        ));
    }
    if requirement.is_some() {
        let index = run_positions[0];
        let next = parsed
            .get(index + 1)
            .and_then(Option::as_ref)
            .ok_or_else(|| {
                ForemanError::ReadOnlyStore(
                    "capacity-required run lacks adjacent requirement event".to_owned(),
                )
            })?;
        if !matches!(
            next.payload,
            InternalPayload::CapacityRequirementAdmitted { .. }
        ) || events[index + 1].sequence != events[index].sequence + 1
            || next.recorded_at != parsed[index].as_ref().unwrap().recorded_at
        {
            return Err(ForemanError::ReadOnlyStore(
                "capacity requirement is not adjacent to exact run admission".to_owned(),
            ));
        }
    }

    for (index, event) in parsed.iter().enumerate() {
        let Some(event) = event else { continue };
        match &event.payload {
            InternalPayload::CapacityRequirementAdmitted { .. } => {
                if requirement.is_none() || index == 0 || run_positions[0] + 1 != index {
                    return Err(ForemanError::ReadOnlyStore(
                        "capacity requirement placement is invalid".to_owned(),
                    ));
                }
            }
            InternalPayload::CapacityAdmissionAccepted {
                capacity_admission, ..
            } => {
                let next = parsed
                    .get(index + 1)
                    .and_then(Option::as_ref)
                    .ok_or_else(|| {
                        ForemanError::ReadOnlyStore(
                            "capacity admission lacks adjacent attempt creation".to_owned(),
                        )
                    })?;
                let InternalPayload::AttemptCreated { start_request, .. } = &next.payload else {
                    return Err(ForemanError::ReadOnlyStore(
                        "capacity admission is not followed by attempt creation".to_owned(),
                    ));
                };
                if events[index + 1].sequence != events[index].sequence + 1
                    || next.run_id != event.run_id
                    || next.work_item_id != event.work_item_id
                    || next.attempt_id != event.attempt_id
                    || next.recorded_at != event.recorded_at
                    || capacity_admission.packet_digest != start_request.packet_digest
                    || capacity_admission.run_id != start_request.run_id
                    || capacity_admission.work_item_id != start_request.work_item_id
                    || capacity_admission.adapter_id != start_request.adapter_id
                    || capacity_admission.profile_model_class != start_request.provider_model_class
                    || event.attempt_id.as_deref() != Some(start_request.attempt_id.as_str())
                {
                    return Err(ForemanError::ReadOnlyStore(
                        "capacity admission and attempt creation identities disagree".to_owned(),
                    ));
                }
            }
            InternalPayload::AttemptCreated { .. } if requirement.is_some() => {
                let previous = index
                    .checked_sub(1)
                    .and_then(|previous| parsed[previous].as_ref());
                if !previous.is_some_and(|previous| {
                    matches!(
                        previous.payload,
                        InternalPayload::CapacityAdmissionAccepted { .. }
                    )
                }) {
                    return Err(ForemanError::ReadOnlyStore(
                        "capacity-required attempt lacks adjacent admission".to_owned(),
                    ));
                }
            }
            _ => {}
        }
    }
    Ok(ValidatedCapacityHistory {
        requirement,
        admissions,
    })
}

fn validate_read_only_receipt_row(
    expected_run_id: &str,
    mut row: ReadOnlyTerminalReceiptRowV1,
    expected_packet_digest: &str,
    profile: &ExecutionProfileV2,
) -> Result<ReadOnlyTerminalReceiptRowV1, ForemanError> {
    let (state, result_classification) = if row.receipt_kind == "terminal" {
        let receipt = TerminalReceiptV1::from_slice(&row.raw_bytes)?;
        receipt.validate()?;
        if receipt.run_id != expected_run_id
            || receipt.packet_digest != expected_packet_digest
            || receipt.work_item_id != row.work_item_id
            || row.attempt_id.as_deref() != Some(receipt.attempt_id.as_str())
            || receipt.receipt_digest != row.receipt_digest
            || profile
                .work_items
                .get(&receipt.work_item_id)
                .map(|work| work.adapter_id.as_str())
                != Some(receipt.adapter_id.as_str())
            || profile
                .adapters
                .get(&receipt.adapter_id)
                .map(|adapter| adapter.adapter_version.as_str())
                != Some(receipt.adapter_version.as_str())
        {
            return Err(ForemanError::ReadOnlyStore(
                "terminal receipt row identity mismatch".to_owned(),
            ));
        }
        (receipt.state, receipt.result_classification)
    } else if row.receipt_kind == "not_started" {
        let receipt = NotStartedReceiptV1::from_slice(&row.raw_bytes)?;
        receipt.validate()?;
        if receipt.run_id != expected_run_id
            || receipt.packet_digest != expected_packet_digest
            || receipt.work_item_id != row.work_item_id
            || row.attempt_id.is_some()
            || receipt.receipt_digest != row.receipt_digest
        {
            return Err(ForemanError::ReadOnlyStore(
                "not-started receipt row identity mismatch".to_owned(),
            ));
        }
        (receipt.state, receipt.result_classification)
    } else {
        return Err(ForemanError::ReadOnlyStore(
            "unknown accepted receipt kind".to_owned(),
        ));
    };
    row.state = state;
    row.result_classification = result_classification;
    Ok(row)
}

fn validate_read_only_run_closed_binding(
    events: &[ReadOnlyEventRowV1],
) -> Result<Option<(u64, DateTime<Utc>, String)>, ForemanError> {
    let mut binding = None;
    for row in events {
        if row.kind != "internal" {
            continue;
        }
        let event: InternalEvent = serde_json::from_slice(&row.raw_bytes)
            .map_err(|error| ForemanError::Serialization(error.to_string()))?;
        if let InternalPayload::RunClosed {
            final_receipts_digest,
        } = event.payload
        {
            if binding
                .replace((row.sequence, event.recorded_at, final_receipts_digest))
                .is_some()
            {
                return Err(ForemanError::ReadOnlyStore(
                    "multiple RunClosed events are not an exact terminal history".to_owned(),
                ));
            }
        }
    }
    Ok(binding)
}

fn validate_read_only_projection_receipts(
    projection: &LiveRunProjectionV1,
    receipts: &[ReadOnlyTerminalReceiptRowV1],
) -> Result<(), ForemanError> {
    let by_item: BTreeMap<_, _> = receipts
        .iter()
        .map(|receipt| (receipt.work_item_id.as_str(), receipt))
        .collect();
    if by_item.len() != receipts.len() {
        return Err(ForemanError::ReadOnlyStore(
            "duplicate accepted receipt work item".to_owned(),
        ));
    }
    if by_item.keys().any(|work_item_id| {
        !projection
            .work_items
            .iter()
            .any(|item| item.work_item_id == *work_item_id)
    }) {
        return Err(ForemanError::ReadOnlyStore(
            "accepted receipt references an unknown projected work item".to_owned(),
        ));
    }
    for item in &projection.work_items {
        match (
            by_item.get(item.work_item_id.as_str()),
            &item.accepted_terminal_outcome,
        ) {
            (None, None) if !item.scheduler_state.is_explicit_terminal() => {}
            (Some(receipt), Some(outcome))
                if receipt.receipt_digest == outcome.receipt_digest
                    && receipt.state == outcome.state
                    && receipt.result_classification == outcome.result_classification
                    && ((receipt.receipt_kind == "terminal"
                        && matches!(
                            item.scheduler_state,
                            SchedulerStateV1::TerminalReceiptAccepted
                        ))
                        || (receipt.receipt_kind == "not_started"
                            && matches!(item.scheduler_state, SchedulerStateV1::NotStarted))) => {}
            _ => {
                return Err(ForemanError::ReadOnlyStore(
                    "accepted receipt and replay projection disagree".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn open_read_only_sidecar(path: &Path) -> Result<Option<File>, ForemanError> {
    match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => {
            if !file
                .metadata()
                .map_err(|error| ForemanError::ReadOnlyStore(error.to_string()))?
                .is_file()
            {
                return Err(ForemanError::ReadOnlyStore(format!(
                    "sidecar is not a regular file: {}",
                    path.display()
                )));
            }
            Ok(Some(file))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(ForemanError::ReadOnlyStore(format!(
            "cannot retain sidecar {}: {error}",
            path.display()
        ))),
    }
}

fn require_same_file(file: &File, path: &Path, kind: &str) -> Result<(), ForemanError> {
    let retained = file
        .metadata()
        .map_err(|error| ForemanError::ReadOnlyStore(error.to_string()))?;
    let current = fs::symlink_metadata(path).map_err(|error| {
        ForemanError::ReadOnlyStore(format!("{kind} sidecar changed during open: {error}"))
    })?;
    if !current.is_file() || retained.dev() != current.dev() || retained.ino() != current.ino() {
        return Err(ForemanError::ReadOnlyStore(format!(
            "{kind} sidecar identity changed during query-only connection open"
        )));
    }
    Ok(())
}

fn require_existing_schema(connection: &Connection) -> Result<(), ForemanError> {
    const REQUIRED_TABLES: [&str; 6] = [
        "runs",
        "work_items",
        "events",
        "resource_claims",
        "terminal_receipts",
        "final_snapshots",
    ];
    for table in REQUIRED_TABLES {
        let exists: bool = connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1
             )",
            [table],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(ForemanError::ReadOnlyStore(format!(
                "database is missing required table {table}"
            )));
        }
    }
    Ok(())
}

fn initialize(connection: &Connection) -> Result<(), ForemanError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            packet_digest TEXT NOT NULL,
            admission_digest TEXT NOT NULL,
            profile_digest TEXT NOT NULL,
            packet_bytes BLOB NOT NULL,
            admission_bytes BLOB NOT NULL,
            profile_bytes BLOB NOT NULL,
            admitted_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            maximum_concurrent_workers INTEGER NOT NULL,
            execution_availability_required INTEGER NOT NULL DEFAULT 0
                CHECK (execution_availability_required IN (0, 1))
        );
        CREATE TABLE IF NOT EXISTS work_items (
            run_id TEXT NOT NULL REFERENCES runs(run_id),
            work_item_id TEXT NOT NULL,
            packet_ordinal INTEGER NOT NULL,
            dependencies_json BLOB NOT NULL,
            PRIMARY KEY (run_id, work_item_id)
        );
        CREATE TABLE IF NOT EXISTS events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL,
            run_id TEXT NOT NULL REFERENCES runs(run_id),
            work_item_id TEXT,
            attempt_id TEXT,
            kind TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            raw_bytes BLOB NOT NULL,
            raw_digest TEXT NOT NULL,
            UNIQUE (run_id, event_id)
        );
        CREATE TABLE IF NOT EXISTS resource_claims (
            run_id TEXT NOT NULL REFERENCES runs(run_id),
            resource_lock_key TEXT NOT NULL,
            work_item_id TEXT NOT NULL,
            attempt_id TEXT NOT NULL,
            PRIMARY KEY (run_id, resource_lock_key)
        );
        CREATE TABLE IF NOT EXISTS execution_availability_event_metadata (
            run_id TEXT NOT NULL REFERENCES runs(run_id),
            event_id TEXT NOT NULL,
            sequence INTEGER NOT NULL,
            event_kind TEXT NOT NULL CHECK (event_kind IN (
                'execution_availability_requirement', 'provider_dispatch',
                'provider_disposition', 'provider_wake', 'provider_resume',
                'provider_resources_released', 'provider_resources_reacquired'
            )),
            raw_byte_length INTEGER NOT NULL CHECK (raw_byte_length > 0),
            PRIMARY KEY (run_id, event_id),
            UNIQUE (run_id, sequence),
            FOREIGN KEY (sequence) REFERENCES events(sequence)
        );
        CREATE TABLE IF NOT EXISTS execution_availability_event_anchors (
            run_id TEXT NOT NULL REFERENCES runs(run_id),
            event_id TEXT NOT NULL,
            sequence INTEGER NOT NULL,
            PRIMARY KEY (run_id, event_id),
            UNIQUE (run_id, sequence),
            FOREIGN KEY (sequence) REFERENCES events(sequence)
        );
        CREATE TABLE IF NOT EXISTS run_mechanism_requirements (
            run_id TEXT PRIMARY KEY REFERENCES runs(run_id),
            execution_availability_required INTEGER NOT NULL
                CHECK (execution_availability_required = 1)
        );
        CREATE TABLE IF NOT EXISTS terminal_receipts (
            run_id TEXT NOT NULL REFERENCES runs(run_id),
            work_item_id TEXT NOT NULL,
            attempt_id TEXT,
            receipt_digest TEXT NOT NULL,
            raw_bytes BLOB NOT NULL,
            receipt_kind TEXT NOT NULL CHECK (receipt_kind IN ('terminal', 'not_started')),
            PRIMARY KEY (run_id, work_item_id)
        );
        CREATE TABLE IF NOT EXISTS final_snapshots (
            run_id TEXT PRIMARY KEY REFERENCES runs(run_id),
            updated_at TEXT NOT NULL,
            raw_digest TEXT NOT NULL,
            raw_bytes BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS self_hosted_bootstraps (
            run_id TEXT PRIMARY KEY REFERENCES runs(run_id),
            bootstrap_digest TEXT NOT NULL UNIQUE,
            bootstrap_occurrence_id TEXT NOT NULL UNIQUE,
            bootstrap_bytes BLOB NOT NULL,
            capacity_policy_bytes BLOB NOT NULL,
            admitted_at TEXT NOT NULL,
            deadline_at TEXT NOT NULL,
            maximum_driver_steps INTEGER NOT NULL CHECK (maximum_driver_steps > 0)
        );
        CREATE TABLE IF NOT EXISTS self_hosted_driver_steps (
            run_id TEXT NOT NULL REFERENCES self_hosted_bootstraps(run_id),
            step_ordinal INTEGER NOT NULL CHECK (step_ordinal > 0),
            step_digest TEXT NOT NULL UNIQUE,
            scheduler_process_occurrence_id TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            raw_bytes BLOB NOT NULL,
            PRIMARY KEY (run_id, step_ordinal)
        );
        CREATE TRIGGER IF NOT EXISTS self_hosted_bootstraps_no_update
            BEFORE UPDATE ON self_hosted_bootstraps
            BEGIN SELECT RAISE(ABORT, 'self-hosted bootstrap custody is append-only'); END;
        CREATE TRIGGER IF NOT EXISTS self_hosted_bootstraps_no_delete
            BEFORE DELETE ON self_hosted_bootstraps
            BEGIN SELECT RAISE(ABORT, 'self-hosted bootstrap custody is append-only'); END;
        CREATE TRIGGER IF NOT EXISTS self_hosted_driver_steps_no_update
            BEFORE UPDATE ON self_hosted_driver_steps
            BEGIN SELECT RAISE(ABORT, 'self-hosted driver steps are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS self_hosted_driver_steps_no_delete
            BEFORE DELETE ON self_hosted_driver_steps
            BEGIN SELECT RAISE(ABORT, 'self-hosted driver steps are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS runs_no_update BEFORE UPDATE ON runs
            BEGIN SELECT RAISE(ABORT, 'runs are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS runs_no_delete BEFORE DELETE ON runs
            BEGIN SELECT RAISE(ABORT, 'runs are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS work_items_no_update BEFORE UPDATE ON work_items
            BEGIN SELECT RAISE(ABORT, 'work items are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS work_items_no_delete BEFORE DELETE ON work_items
            BEGIN SELECT RAISE(ABORT, 'work items are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
            BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
            BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS execution_availability_metadata_no_update
            BEFORE UPDATE ON execution_availability_event_metadata
            BEGIN SELECT RAISE(ABORT, 'execution availability metadata is append-only'); END;
        CREATE TRIGGER IF NOT EXISTS execution_availability_metadata_no_delete
            BEFORE DELETE ON execution_availability_event_metadata
            BEGIN SELECT RAISE(ABORT, 'execution availability metadata is append-only'); END;
        CREATE TRIGGER IF NOT EXISTS execution_availability_anchors_no_update
            BEFORE UPDATE ON execution_availability_event_anchors
            BEGIN SELECT RAISE(ABORT, 'execution availability anchors are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS execution_availability_anchors_no_delete
            BEFORE DELETE ON execution_availability_event_anchors
            BEGIN SELECT RAISE(ABORT, 'execution availability anchors are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS run_mechanism_requirements_no_update
            BEFORE UPDATE ON run_mechanism_requirements
            BEGIN SELECT RAISE(ABORT, 'run mechanism requirements are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS run_mechanism_requirements_no_delete
            BEFORE DELETE ON run_mechanism_requirements
            BEGIN SELECT RAISE(ABORT, 'run mechanism requirements are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS terminal_receipts_no_update BEFORE UPDATE ON terminal_receipts
            BEGIN SELECT RAISE(ABORT, 'terminal receipts are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS terminal_receipts_no_delete BEFORE DELETE ON terminal_receipts
            BEGIN SELECT RAISE(ABORT, 'terminal receipts are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS final_snapshots_no_update BEFORE UPDATE ON final_snapshots
            BEGIN SELECT RAISE(ABORT, 'final snapshots are append-only'); END;
        CREATE TRIGGER IF NOT EXISTS final_snapshots_no_delete BEFORE DELETE ON final_snapshots
            BEGIN SELECT RAISE(ABORT, 'final snapshots are append-only'); END;",
    )?;
    let mut columns = connection.prepare("PRAGMA table_info(runs)")?;
    let has_execution_availability_anchor = columns
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .any(|name| name == "execution_availability_required");
    drop(columns);
    if !has_execution_availability_anchor {
        connection.execute(
            "ALTER TABLE runs ADD COLUMN execution_availability_required INTEGER NOT NULL DEFAULT 0 CHECK (execution_availability_required IN (0, 1))",
            [],
        )?;
    }
    Ok(())
}

fn validate_execution_availability_configuration(
    requirement_bytes: &[u8],
    policy_bytes: &[u8],
) -> Result<ValidatedExecutionAvailabilityConfiguration, ForemanError> {
    if requirement_bytes.is_empty()
        || policy_bytes.is_empty()
        || requirement_bytes.len() > MAXIMUM_CAPACITY_RECORD_BYTES
        || policy_bytes.len() > MAXIMUM_CAPACITY_RECORD_BYTES
    {
        return Err(ForemanError::InputTooLarge(
            "execution availability configuration",
        ));
    }
    let requirement = ForemanExecutionAvailabilityRequirementV1::from_slice(requirement_bytes)?;
    let policy = ExecutionAvailabilityPolicyV1::from_slice(policy_bytes)?;
    requirement.validate()?;
    policy.validate()?;
    if serde_jcs::to_vec(&requirement)
        .map_err(|error| ForemanError::Serialization(error.to_string()))?
        != requirement_bytes
        || serde_jcs::to_vec(&policy)
            .map_err(|error| ForemanError::Serialization(error.to_string()))?
            != policy_bytes
    {
        return Err(ForemanError::Transition(
            "execution availability configuration is not exact canonical owner bytes".to_owned(),
        ));
    }
    Ok(ValidatedExecutionAvailabilityConfiguration {
        requirement,
        requirement_bytes: requirement_bytes.to_vec(),
        policy,
        policy_bytes: policy_bytes.to_vec(),
    })
}

fn validate_capacity_requirement_bytes(
    bytes: &[u8],
) -> Result<ForemanCapacityRequirementV1, ForemanError> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_CAPACITY_RECORD_BYTES {
        return Err(ForemanError::InputTooLarge("capacity requirement"));
    }
    let requirement = ForemanCapacityRequirementV1::from_slice(bytes)?;
    requirement.validate()?;
    if serde_jcs::to_vec(&requirement)
        .map_err(|error| ForemanError::Serialization(error.to_string()))?
        != bytes
    {
        return Err(ForemanError::Transition(
            "capacity requirement bytes are not exact canonical owner bytes".to_owned(),
        ));
    }
    Ok(requirement)
}

fn validate_execution_availability_configuration_bindings(
    configuration: &ValidatedExecutionAvailabilityConfiguration,
    packet: &NightshiftPacketV1,
    admission: &ForemanAdmissionV1,
    profile: &ExecutionProfileV2,
    recorded_at: DateTime<Utc>,
) -> Result<(), ForemanError> {
    let requirement = &configuration.requirement;
    let policy = &configuration.policy;
    if requirement.packet_digest != packet.packet_digest
        || requirement.admission_digest != admission.admission_digest
        || requirement.profile_digest != profile.profile_digest
        || requirement.run_id != admission.run_id
        || requirement.admitted_at != recorded_at
        || requirement.admitted_at != admission.admitted_at
        || requirement.policy_id != policy.policy_id
        || requirement.policy_digest != policy.policy_digest
    {
        return Err(ForemanError::IdentityMismatch(
            "execution availability run requirement",
        ));
    }
    let adapter =
        profile
            .adapters
            .get(&requirement.adapter_id)
            .ok_or(ForemanError::IdentityMismatch(
                "execution availability adapter",
            ))?;
    if requirement.adapter_id != adapter.adapter_id
        || requirement.adapter_protocol != adapter.protocol
        || requirement.adapter_version != adapter.adapter_version
        || requirement.adapter_executable_identity != adapter.executable_identity
    {
        return Err(ForemanError::IdentityMismatch(
            "execution availability adapter registration",
        ));
    }
    let packet_items: BTreeSet<&_> = packet.work_items.iter().map(|item| &item.id).collect();
    let selection_items: BTreeSet<&_> = requirement.work_item_model_selections.keys().collect();
    if packet_items != selection_items {
        return Err(ForemanError::IdentityMismatch(
            "execution availability work-item domain",
        ));
    }
    let mut provider_id: Option<&str> = None;
    for item in &packet.work_items {
        let execution = profile
            .work_items
            .get(&item.id)
            .ok_or_else(|| ForemanError::UnknownWorkItem(item.id.clone()))?;
        let selections = requirement.work_item_model_selections.get(&item.id).ok_or(
            ForemanError::IdentityMismatch("execution availability selection"),
        )?;
        if execution.adapter_id != requirement.adapter_id
            || item.model_routing.class != execution.provider_model_class
            || selections
                .iter()
                .any(|selection| selection.model_class != execution.provider_model_class)
        {
            return Err(ForemanError::IdentityMismatch(
                "execution availability profile selection",
            ));
        }
        for selection in selections {
            match provider_id {
                None => provider_id = Some(&selection.provider_id),
                Some(expected) if expected == selection.provider_id => {}
                Some(_) => {
                    return Err(ForemanError::IdentityMismatch(
                        "execution availability provider identity",
                    ))
                }
            }
        }
    }
    Ok(())
}

fn validate_bindings(
    packet: &NightshiftPacketV1,
    admission: &ForemanAdmissionV1,
    profile: &ExecutionProfileV2,
) -> Result<(), ForemanError> {
    if admission.packet_digest != packet.packet_digest
        || profile.packet_digest != packet.packet_digest
    {
        return Err(ForemanError::IdentityMismatch("packet_digest"));
    }
    if profile.admission_digest != admission.admission_digest {
        return Err(ForemanError::IdentityMismatch("admission_digest"));
    }
    if admission.maximum_concurrent_workers
        > packet.worker_budget.maximum_concurrent_mutating_workers
    {
        return Err(ForemanError::Transition(
            "admission exceeds packet worker budget".to_owned(),
        ));
    }
    let packet_items: BTreeSet<_> = packet.work_items.iter().map(|item| &item.id).collect();
    let profile_items: BTreeSet<_> = profile.work_items.keys().collect();
    if packet_items != profile_items {
        return Err(ForemanError::IdentityMismatch("profile work items"));
    }
    let allowed_adapters: BTreeSet<_> = admission.allowed_adapter_ids.iter().collect();
    let allowed_classes: BTreeSet<_> = admission.allowed_provider_model_classes.iter().collect();
    for execution in profile.work_items.values() {
        if !allowed_adapters.contains(&execution.adapter_id) {
            return Err(ForemanError::Transition(
                "profile adapter not admitted".to_owned(),
            ));
        }
        if !allowed_classes.contains(&execution.provider_model_class) {
            return Err(ForemanError::Transition(
                "provider/model class not admitted".to_owned(),
            ));
        }
    }
    Ok(())
}

fn load_capacity_requirement(
    connection: &Connection,
    run_id: &str,
) -> Result<Option<ForemanCapacityRequirementV1>, ForemanError> {
    let mut statement = connection.prepare(
        "SELECT raw_bytes FROM events WHERE run_id = ?1 AND kind IN ('internal', 'capacity_requirement') ORDER BY sequence",
    )?;
    let rows = statement.query_map([run_id], |row| row.get::<_, Vec<u8>>(0))?;
    let mut found = None;
    for row in rows {
        let raw = row?;
        let event: InternalEvent = serde_json::from_slice(&raw)
            .map_err(|error| ForemanError::Serialization(error.to_string()))?;
        if let InternalPayload::CapacityRequirementAdmitted {
            requirement,
            requirement_bytes,
        } = event.payload
        {
            if found.is_some()
                || serde_jcs::to_vec(&*requirement)
                    .map_err(|error| ForemanError::Serialization(error.to_string()))?
                    != requirement_bytes
            {
                return Err(ForemanError::ReadOnlyStore(
                    "capacity requirement history is not singular exact custody".to_owned(),
                ));
            }
            requirement.validate()?;
            found = Some(*requirement);
        }
    }
    Ok(found)
}

fn validate_capacity_requirement(
    requirement: &ForemanCapacityRequirementV1,
    packet: &NightshiftPacketV1,
    admission: &ForemanAdmissionV1,
    profile: &ExecutionProfileV2,
) -> Result<(), ForemanError> {
    let packet_classes = packet
        .work_items
        .iter()
        .map(|work| work.model_routing.class.as_str())
        .collect::<BTreeSet<_>>();
    let requirement_classes = requirement
        .model_cost_classes
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if requirement.packet_digest != packet.packet_digest
        || requirement.admission_digest != admission.admission_digest
        || requirement.profile_digest != profile.profile_digest
        || requirement.run_id != admission.run_id
        || requirement.policy_id != profile.budget_policy_ref
        || packet_classes != requirement_classes
        || packet.work_items.iter().any(|work| {
            profile
                .work_items
                .get(&work.id)
                .is_none_or(|execution| execution.provider_model_class != work.model_routing.class)
        })
    {
        return Err(ForemanError::IdentityMismatch(
            "capacity requirement binding",
        ));
    }
    Ok(())
}

fn validate_capacity_bundle(
    admission_bytes: &[u8],
    observation_bytes: &[u8],
    policy_bytes: &[u8],
    decision_bytes: &[u8],
) -> Result<ValidatedCapacityAdmission, ForemanError> {
    for (name, bytes) in [
        ("capacity admission", admission_bytes),
        ("capacity observation", observation_bytes),
        ("capacity policy", policy_bytes),
        ("capacity decision", decision_bytes),
    ] {
        if bytes.is_empty() || bytes.len() > MAXIMUM_CAPACITY_RECORD_BYTES {
            return Err(ForemanError::InputTooLarge(name));
        }
    }
    let admission = ForemanCapacityAdmissionV1::from_slice(admission_bytes)?;
    admission.validate()?;
    let observation: CapacityObservationV1 = serde_json::from_slice(observation_bytes)
        .map_err(|error| ForemanError::Serialization(error.to_string()))?;
    let policy: CapacityPolicyV1 = serde_json::from_slice(policy_bytes)
        .map_err(|error| ForemanError::Serialization(error.to_string()))?;
    let decision: CapacityDecisionV1 = serde_json::from_slice(decision_bytes)
        .map_err(|error| ForemanError::Serialization(error.to_string()))?;
    observation
        .validate()
        .map_err(|error| ForemanError::Transition(error.to_string()))?;
    policy
        .validate()
        .map_err(|error| ForemanError::Transition(error.to_string()))?;
    decision
        .validate()
        .map_err(|error| ForemanError::Transition(error.to_string()))?;
    let reproduced_decision = decide_capacity(&observation, &policy, decision.decision_at)
        .map_err(|error| ForemanError::Transition(error.to_string()))?;
    if reproduced_decision != decision {
        return Err(ForemanError::Transition(
            "capacity decision is not the exact deterministic FUEL outcome".to_owned(),
        ));
    }
    for (name, expected, value) in [
        (
            "capacity admission",
            admission_bytes,
            serde_jcs::to_vec(&admission)
                .map_err(|error| ForemanError::Serialization(error.to_string()))?,
        ),
        (
            "capacity observation",
            observation_bytes,
            serde_jcs::to_vec(&observation)
                .map_err(|error| ForemanError::Serialization(error.to_string()))?,
        ),
        (
            "capacity policy",
            policy_bytes,
            serde_jcs::to_vec(&policy)
                .map_err(|error| ForemanError::Serialization(error.to_string()))?,
        ),
        (
            "capacity decision",
            decision_bytes,
            serde_jcs::to_vec(&decision)
                .map_err(|error| ForemanError::Serialization(error.to_string()))?,
        ),
    ] {
        if expected != value {
            return Err(ForemanError::Transition(format!(
                "{name} bytes are not exact canonical owner bytes"
            )));
        }
    }
    Ok(ValidatedCapacityAdmission {
        admission,
        observation,
        policy,
        decision,
        admission_bytes: admission_bytes.to_vec(),
        observation_bytes: observation_bytes.to_vec(),
        policy_bytes: policy_bytes.to_vec(),
        decision_bytes: decision_bytes.to_vec(),
    })
}

fn validate_capacity_bindings(
    capacity: &ValidatedCapacityAdmission,
    packet: &NightshiftPacketV1,
    foreman_admission: &ForemanAdmissionV1,
    profile: &ExecutionProfileV2,
    requirement: &ForemanCapacityRequirementV1,
    work_item_id: &str,
    recorded_at: DateTime<Utc>,
) -> Result<(), ForemanError> {
    let binding = &capacity.admission;
    let work = packet
        .work_items
        .iter()
        .find(|work| work.id == work_item_id)
        .ok_or_else(|| ForemanError::UnknownWorkItem(work_item_id.to_owned()))?;
    let execution = profile
        .work_items
        .get(work_item_id)
        .ok_or_else(|| ForemanError::UnknownWorkItem(work_item_id.to_owned()))?;
    if binding.capacity_requirement_digest != requirement.capacity_requirement_digest
        || binding.provider_id != requirement.provider_id
        || binding.policy_id != requirement.policy_id
        || requirement
            .model_cost_classes
            .get(&binding.packet_model_class)
            != Some(&binding.cost_class)
    {
        return Err(ForemanError::IdentityMismatch(
            "capacity requirement identity",
        ));
    }
    if binding.packet_digest != packet.packet_digest
        || binding.admission_digest != foreman_admission.admission_digest
        || binding.profile_digest != profile.profile_digest
        || binding.run_id != foreman_admission.run_id
        || binding.work_item_id != work_item_id
        || binding.adapter_id != execution.adapter_id
        || binding.packet_model_class != work.model_routing.class
        || binding.profile_model_class != execution.provider_model_class
    {
        return Err(ForemanError::IdentityMismatch("capacity admission binding"));
    }
    if capacity
        .observation
        .model_family
        .as_deref()
        .is_some_and(|model_family| model_family != binding.packet_model_class)
    {
        return Err(ForemanError::IdentityMismatch(
            "capacity observation model family",
        ));
    }
    if binding.provider_id != capacity.observation.provider_id
        || binding.provider_id != capacity.decision.provider_id
        || binding.policy_id != capacity.policy.policy_id
        || binding.policy_id != profile.budget_policy_ref
        || binding.observation_digest != capacity.observation.observation_digest
        || binding.policy_digest != capacity.policy.policy_digest
        || binding.decision_digest != capacity.decision.decision_digest
        || capacity.decision.observation_digest != capacity.observation.observation_digest
        || capacity.decision.policy_digest != capacity.policy.policy_digest
    {
        return Err(ForemanError::IdentityMismatch("capacity owner identity"));
    }
    if binding.evaluated_at != recorded_at
        || capacity.decision.decision_at != recorded_at
        || recorded_at < capacity.observation.observed_at
        || recorded_at >= capacity.observation.expires_at
    {
        return Err(ForemanError::Transition(
            "capacity decision is not current at exact attempt admission".to_owned(),
        ));
    }
    match capacity.decision.admission {
        CapacityAdmissionDisposition::NoNewWork => Err(ForemanError::Transition(
            "capacity decision admits no new work".to_owned(),
        )),
        CapacityAdmissionDisposition::CheapBoundedOnly
            if binding.cost_class != CapacityCostClassV1::Cheap =>
        {
            Err(ForemanError::Transition(
                "capacity decision admits only closed cheap model classes".to_owned(),
            ))
        }
        CapacityAdmissionDisposition::OrdinaryBounded
            if binding.cost_class == CapacityCostClassV1::Expensive
                && !capacity.decision.allow_new_expensive_work =>
        {
            Err(ForemanError::Transition(
                "capacity decision does not admit new expensive work".to_owned(),
            ))
        }
        _ => Ok(()),
    }
}

fn validate_provider_disposition_evidence(
    evidence: ProviderDispositionEvidenceV1<'_>,
) -> Result<ValidatedProviderDispositionEvidence, ForemanError> {
    let lengths = [
        evidence.observation_bytes.len(),
        evidence.disposition_bytes.len(),
        evidence.deferred_bytes.map_or(0, <[u8]>::len),
    ];
    let total = lengths
        .iter()
        .try_fold(0_usize, |sum, value| sum.checked_add(*value));
    if lengths[0] == 0
        || lengths[1] == 0
        || total.is_none_or(|value| value > MAXIMUM_EXECUTION_AVAILABILITY_HISTORY_BYTES as usize)
    {
        return Err(ForemanError::InputTooLarge("provider disposition evidence"));
    }
    let observation = ExecutionAvailabilityObservationV1::from_slice(evidence.observation_bytes)?;
    let disposition = ProviderAdmissionDispositionV1::from_slice(evidence.disposition_bytes)?;
    let deferred = evidence
        .deferred_bytes
        .map(DeferredProviderDispatchV1::from_slice)
        .transpose()?;
    observation.validate()?;
    disposition.validate()?;
    if let Some(value) = &deferred {
        value.validate()?;
    }
    if serde_jcs::to_vec(&observation)
        .map_err(|error| ForemanError::Serialization(error.to_string()))?
        != evidence.observation_bytes
        || serde_jcs::to_vec(&disposition)
            .map_err(|error| ForemanError::Serialization(error.to_string()))?
            != evidence.disposition_bytes
        || match (&deferred, evidence.deferred_bytes) {
            (None, None) => false,
            (Some(value), Some(bytes)) => {
                serde_jcs::to_vec(value)
                    .map_err(|error| ForemanError::Serialization(error.to_string()))?
                    != bytes
            }
            _ => true,
        }
    {
        return Err(ForemanError::Transition(
            "provider disposition evidence is not exact canonical owner bytes".to_owned(),
        ));
    }
    Ok(ValidatedProviderDispositionEvidence {
        observation,
        observation_bytes: evidence.observation_bytes.to_vec(),
        disposition,
        disposition_bytes: evidence.disposition_bytes.to_vec(),
        deferred,
        deferred_bytes: evidence.deferred_bytes.map(<[u8]>::to_vec),
    })
}

// Construction keeps the V2/profile/requirement and fresh dispatch identities explicit.
#[allow(clippy::too_many_arguments)]
fn build_provider_dispatch(
    predecessor: &WorkerStartRequestV2,
    profile: &ExecutionProfileV2,
    requirement: &ForemanExecutionAvailabilityRequirementV1,
    dispatch_occurrence_id: &str,
    adapter_process_occurrence_id: &str,
    app_server_session_identity: &str,
    selected_model_ordinal: u16,
    dispatch_ordinal: u16,
    opened_at: DateTime<Utc>,
) -> Result<OpenedProviderDispatchV1, ForemanError> {
    validate_local_occurrence_id(dispatch_occurrence_id, "dispatch_occurrence_id")?;
    validate_local_occurrence_id(
        adapter_process_occurrence_id,
        "adapter_process_occurrence_id",
    )?;
    validate_local_occurrence_id(app_server_session_identity, "app_server_session_identity")?;
    let predecessor_bytes = serde_jcs::to_vec(predecessor)
        .map_err(|error| ForemanError::Serialization(error.to_string()))?;
    let start = WorkerStartRequestV3::from_v2_for_dispatch(
        &predecessor_bytes,
        profile,
        requirement,
        dispatch_occurrence_id,
        selected_model_ordinal,
    )?;
    let mut dispatch = ProviderDispatchOccurrenceV1 {
        schema: PROVIDER_DISPATCH_OCCURRENCE_SCHEMA_V1.to_owned(),
        dispatch_digest: placeholder_digest(),
        requirement_digest: requirement.requirement_digest.clone(),
        policy_digest: requirement.policy_digest.clone(),
        packet_digest: requirement.packet_digest.clone(),
        run_id: start.run_id.clone(),
        work_item_id: start.work_item_id.clone(),
        work_attempt_id: start.work_attempt_id.clone(),
        dispatch_occurrence_id: dispatch_occurrence_id.to_owned(),
        dispatch_ordinal,
        selected_model_ordinal,
        selection: crate::ProviderModelSelectionV1 {
            provider_id: start.provider_id.clone(),
            model_id: start.model_id.clone(),
            model_class: start.model_class.clone(),
        },
        adapter_id: start.adapter_id.clone(),
        adapter_version: start.adapter_version.clone(),
        adapter_protocol: start.adapter_protocol.clone(),
        adapter_process_occurrence_id: adapter_process_occurrence_id.to_owned(),
        app_server_session_identity: app_server_session_identity.to_owned(),
        worker_start_request_schema: start.schema.clone(),
        worker_start_request_digest: start.request_digest.clone(),
        worker_brief_digest: start.worker_brief_digest.clone(),
        opened_at,
        internal_provider_retry_count: 0,
        provider_execution_id: None,
        authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".to_owned(),
    };
    dispatch.seal()?;
    start.validate_dispatch_graph(profile, requirement, &dispatch)?;
    Ok(OpenedProviderDispatchV1 {
        worker_start_request: start,
        dispatch,
    })
}

fn append_provider_dispatch(
    transaction: &Transaction<'_>,
    run_id: &str,
    work_item_id: &str,
    attempt_id: &str,
    opened: &OpenedProviderDispatchV1,
    maximum_event_bytes: u64,
) -> Result<(), ForemanError> {
    let start_request_bytes = serde_jcs::to_vec(&opened.worker_start_request)
        .map_err(|error| ForemanError::Serialization(error.to_string()))?;
    let dispatch_bytes = serde_jcs::to_vec(&opened.dispatch)
        .map_err(|error| ForemanError::Serialization(error.to_string()))?;
    append_execution_availability_bounded(
        transaction,
        &InternalEvent {
            schema: INTERNAL_EVENT_SCHEMA.to_owned(),
            event_id: format!(
                "provider-dispatch-{}",
                opened.dispatch.dispatch_occurrence_id
            ),
            run_id: run_id.to_owned(),
            work_item_id: Some(work_item_id.to_owned()),
            attempt_id: Some(attempt_id.to_owned()),
            recorded_at: opened.dispatch.opened_at,
            payload: InternalPayload::ProviderDispatchOpened {
                start_request: Box::new(opened.worker_start_request.clone()),
                start_request_bytes,
                dispatch: Box::new(opened.dispatch.clone()),
                dispatch_bytes,
            },
        },
        maximum_event_bytes,
    )
}

fn append_provider_disposition(
    transaction: &Transaction<'_>,
    run_id: &str,
    work_item_id: &str,
    attempt_id: &str,
    evidence: &ValidatedProviderDispositionEvidence,
    predecessor_disposition_digest: Option<&str>,
    maximum_event_bytes: u64,
) -> Result<(), ForemanError> {
    append_execution_availability_bounded(
        transaction,
        &InternalEvent {
            schema: INTERNAL_EVENT_SCHEMA.to_owned(),
            event_id: format!(
                "provider-disposition-{}",
                evidence.disposition.disposition_digest
            ),
            run_id: run_id.to_owned(),
            work_item_id: Some(work_item_id.to_owned()),
            attempt_id: Some(attempt_id.to_owned()),
            recorded_at: evidence.disposition.received_at,
            payload: InternalPayload::ProviderDispositionRecorded {
                observation: Box::new(evidence.observation.clone()),
                observation_bytes: evidence.observation_bytes.clone(),
                disposition: Box::new(evidence.disposition.clone()),
                disposition_bytes: evidence.disposition_bytes.clone(),
                deferred: evidence.deferred.clone().map(Box::new),
                deferred_bytes: evidence.deferred_bytes.clone(),
                reconciles_disposition_digest: predecessor_disposition_digest.map(str::to_owned),
            },
        },
        maximum_event_bytes,
    )
}

fn load_attempt_start_request(
    connection: &Connection,
    run_id: &str,
    work_item_id: &str,
    attempt_id: &str,
) -> Result<WorkerStartRequestV2, ForemanError> {
    let mut statement = connection.prepare(
        "SELECT raw_bytes FROM events
         WHERE run_id = ?1 AND work_item_id = ?2 AND attempt_id = ?3 AND kind = \x27internal\x27
         ORDER BY sequence ASC",
    )?;
    let rows = statement.query_map(params![run_id, work_item_id, attempt_id], |row| {
        row.get::<_, Vec<u8>>(0)
    })?;
    let mut found = None;
    for raw in rows {
        let event: InternalEvent = serde_json::from_slice(&raw?)
            .map_err(|error| ForemanError::Serialization(error.to_string()))?;
        if let InternalPayload::AttemptCreated { start_request, .. } = event.payload {
            if found.replace(*start_request).is_some() {
                return Err(ForemanError::ReadOnlyStore(
                    "duplicate exact work-attempt start request".to_owned(),
                ));
            }
        }
    }
    found.ok_or_else(|| {
        ForemanError::Transition("work attempt lacks exact V2 start predecessor".to_owned())
    })
}

fn require_attempt_resource_claims(
    connection: &Connection,
    profile: &ExecutionProfileV2,
    run_id: &str,
    work_item_id: &str,
    attempt_id: &str,
) -> Result<(), ForemanError> {
    let execution = profile
        .work_items
        .get(work_item_id)
        .ok_or_else(|| ForemanError::UnknownWorkItem(work_item_id.to_owned()))?;
    for lock in &execution.resource_lock_keys {
        let owner: Option<(String, String)> = connection
            .query_row(
                "SELECT work_item_id, attempt_id FROM resource_claims
                 WHERE run_id = ?1 AND resource_lock_key = ?2",
                params![run_id, lock],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if owner
            .as_ref()
            .map(|(work, attempt)| (work.as_str(), attempt.as_str()))
            != Some((work_item_id, attempt_id))
        {
            return Err(ForemanError::ResourceUnavailable(format!(
                "required lock {lock} is not held by exact work attempt"
            )));
        }
    }
    Ok(())
}

fn reacquire_attempt_resource_claims(
    transaction: &Transaction<'_>,
    profile: &ExecutionProfileV2,
    run_id: &str,
    work_item_id: &str,
    attempt_id: &str,
) -> Result<(), ForemanError> {
    let execution = profile
        .work_items
        .get(work_item_id)
        .ok_or_else(|| ForemanError::UnknownWorkItem(work_item_id.to_owned()))?;
    for lock in &execution.resource_lock_keys {
        let owner: Option<(String, String)> = transaction
            .query_row(
                "SELECT work_item_id, attempt_id FROM resource_claims
                 WHERE run_id = ?1 AND resource_lock_key = ?2",
                params![run_id, lock],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        match owner {
            Some((owner_work, owner_attempt))
                if owner_work == work_item_id && owner_attempt == attempt_id => {}
            Some((owner_work, _)) => {
                return Err(ForemanError::ResourceUnavailable(format!(
                    "{lock} held by {owner_work}"
                )))
            }
            None => {
                transaction.execute(
                    "INSERT INTO resource_claims
                     (run_id, resource_lock_key, work_item_id, attempt_id)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![run_id, lock, work_item_id, attempt_id],
                )?;
            }
        }
    }
    Ok(())
}

fn validate_local_occurrence_id(value: &str, field: &'static str) -> Result<(), ForemanError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(ForemanError::Transition(format!("invalid {field}")));
    }
    Ok(())
}

fn append_internal(
    transaction: &Transaction<'_>,
    event: &InternalEvent,
) -> Result<(), ForemanError> {
    let raw =
        serde_jcs::to_vec(event).map_err(|error| ForemanError::Serialization(error.to_string()))?;
    append_internal_raw(transaction, event, "internal", &raw)
}

fn append_internal_bounded(
    transaction: &Transaction<'_>,
    event: &InternalEvent,
    maximum_event_bytes: u64,
    maximum_capacity_rows: usize,
) -> Result<(), ForemanError> {
    let raw =
        serde_jcs::to_vec(event).map_err(|error| ForemanError::Serialization(error.to_string()))?;
    if raw.len() > maximum_event_bytes as usize {
        return Err(ForemanError::InputTooLarge("capacity journal event"));
    }
    let kind = match event.payload {
        InternalPayload::CapacityRequirementAdmitted { .. } => "capacity_requirement",
        InternalPayload::CapacityAdmissionAccepted { .. } => "capacity_admission",
        _ => {
            return Err(ForemanError::Transition(
                "bounded capacity append received non-capacity event".to_owned(),
            ))
        }
    };
    let (retained, retained_count) = validate_capacity_history_size(
        transaction,
        &event.run_id,
        maximum_event_bytes,
        maximum_capacity_rows,
    )?;
    if retained_count
        .checked_add(1)
        .is_none_or(|count| count > maximum_capacity_rows)
        || retained
            .checked_add(raw.len() as u64)
            .is_none_or(|total| total > MAXIMUM_CAPACITY_HISTORY_BYTES)
    {
        return Err(ForemanError::InputTooLarge("capacity journal history"));
    }
    append_internal_raw(transaction, event, kind, &raw)
}

fn execution_availability_row_kind(payload: &InternalPayload) -> Option<&'static str> {
    match payload {
        InternalPayload::ExecutionAvailabilityConfigured { .. } => {
            Some("execution_availability_requirement")
        }
        InternalPayload::ProviderDispatchOpened { .. } => Some("provider_dispatch"),
        InternalPayload::ProviderDispositionRecorded { .. } => Some("provider_disposition"),
        InternalPayload::ProviderWakeOpened { .. } => Some("provider_wake"),
        InternalPayload::ProviderExecutionResumeRequested { .. } => Some("provider_resume"),
        InternalPayload::ProviderResourcesReleased { .. } => Some("provider_resources_released"),
        InternalPayload::ProviderResourcesReacquired { .. } => {
            Some("provider_resources_reacquired")
        }
        _ => None,
    }
}

fn append_execution_availability_bounded(
    transaction: &Transaction<'_>,
    event: &InternalEvent,
    maximum_event_bytes: u64,
) -> Result<(), ForemanError> {
    let kind = execution_availability_row_kind(&event.payload).ok_or_else(|| {
        ForemanError::Transition(
            "bounded execution-availability append received unrelated event".to_owned(),
        )
    })?;
    let raw =
        serde_jcs::to_vec(event).map_err(|error| ForemanError::Serialization(error.to_string()))?;
    if raw.is_empty() || raw.len() > maximum_event_bytes as usize {
        return Err(ForemanError::InputTooLarge(
            "execution availability journal event",
        ));
    }
    let (retained, retained_count) = validate_execution_availability_history_size(
        transaction,
        &event.run_id,
        maximum_event_bytes,
        kind == "execution_availability_requirement",
    )?;
    if retained_count
        .checked_add(1)
        .is_none_or(|count| count > MAXIMUM_EXECUTION_AVAILABILITY_ROWS)
        || retained
            .checked_add(raw.len() as u64)
            .is_none_or(|total| total > MAXIMUM_EXECUTION_AVAILABILITY_HISTORY_BYTES)
    {
        return Err(ForemanError::InputTooLarge(
            "execution availability journal history",
        ));
    }
    append_internal_raw(transaction, event, kind, &raw)?;
    transaction.execute(
        "INSERT INTO execution_availability_event_metadata
         (run_id, event_id, sequence, event_kind, raw_byte_length)
         SELECT run_id, event_id, sequence, kind, length(raw_bytes)
         FROM events WHERE run_id = ?1 AND event_id = ?2",
        params![event.run_id, event.event_id],
    )?;
    transaction.execute(
        "INSERT INTO execution_availability_event_anchors
         (run_id, event_id, sequence)
         SELECT run_id, event_id, sequence
         FROM events WHERE run_id = ?1 AND event_id = ?2",
        params![event.run_id, event.event_id],
    )?;
    Ok(())
}

fn append_internal_raw(
    transaction: &Transaction<'_>,
    event: &InternalEvent,
    kind: &str,
    raw: &[u8],
) -> Result<(), ForemanError> {
    transaction.execute(
        "INSERT INTO events
         (event_id, run_id, work_item_id, attempt_id, kind, recorded_at, raw_bytes, raw_digest)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            event.event_id,
            event.run_id,
            event.work_item_id,
            event.attempt_id,
            kind,
            event.recorded_at.to_rfc3339(),
            raw,
            raw_digest(raw),
        ],
    )?;
    Ok(())
}

type RawContractRow = (
    String,
    String,
    String,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    String,
    String,
    u16,
);

fn load_contracts(
    connection: &Connection,
    run_id: &str,
) -> Result<
    (
        NightshiftPacketV1,
        ForemanAdmissionV1,
        ExecutionProfileV2,
        u16,
    ),
    ForemanError,
> {
    let row: Option<RawContractRow> = connection
        .query_row(
            "SELECT packet_digest, admission_digest, profile_digest,
                    packet_bytes, admission_bytes, profile_bytes,
                    admitted_at, expires_at, maximum_concurrent_workers
             FROM runs WHERE run_id = ?1",
            [run_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )
        .optional()?;
    let (
        packet_digest,
        admission_digest,
        profile_digest,
        packet_raw,
        admission_raw,
        profile_raw,
        admitted_at,
        expires_at,
        maximum,
    ) = row.ok_or_else(|| ForemanError::UnknownRun(run_id.to_owned()))?;
    let packet = NightshiftPacketV1::from_slice(&packet_raw)
        .map_err(|error| ForemanError::Packet(error.to_string()))?;
    packet
        .validate_integrity()
        .map_err(|error| ForemanError::Packet(error.to_string()))?;
    let admission = ForemanAdmissionV1::from_slice(&admission_raw)?;
    admission.validate()?;
    let profile = ExecutionProfileV2::from_slice(&profile_raw)?;
    profile.validate()?;
    validate_bindings(&packet, &admission, &profile)?;
    if admission.run_id != run_id
        || packet_digest != packet.packet_digest
        || admission_digest != admission.admission_digest
        || profile_digest != profile.profile_digest
        || admitted_at != admission.admitted_at.to_rfc3339()
        || expires_at != admission.expires_at.to_rfc3339()
        || maximum != admission.maximum_concurrent_workers
    {
        return Err(ForemanError::ReadOnlyStore(
            "run row and exact contract bytes disagree".to_owned(),
        ));
    }
    Ok((packet, admission, profile, maximum))
}

fn validate_capacity_history_size(
    connection: &Connection,
    run_id: &str,
    maximum_event_bytes: u64,
    maximum_capacity_rows: usize,
) -> Result<(u64, usize), ForemanError> {
    let mut statement = connection.prepare(
        "SELECT sequence, length(raw_bytes) FROM events
         WHERE run_id = ?1 AND kind IN ('capacity_requirement', 'capacity_admission')
         ORDER BY sequence ASC",
    )?;
    let rows = statement.query_map([run_id], |row| {
        Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?))
    })?;
    let mut total = 0_u64;
    let mut count = 0_usize;
    for row in rows {
        count = count
            .checked_add(1)
            .ok_or(ForemanError::InputTooLarge("capacity journal history"))?;
        if count > maximum_capacity_rows {
            return Err(ForemanError::InputTooLarge("capacity journal history"));
        }
        let (_sequence, length) = row?;
        if length == 0 || length > maximum_event_bytes {
            return Err(ForemanError::InputTooLarge("capacity journal event"));
        }
        total = total
            .checked_add(length)
            .ok_or(ForemanError::InputTooLarge("capacity journal history"))?;
        if total > MAXIMUM_CAPACITY_HISTORY_BYTES {
            return Err(ForemanError::InputTooLarge("capacity journal history"));
        }
    }
    Ok((total, count))
}

fn validate_execution_availability_history_size(
    connection: &Connection,
    run_id: &str,
    maximum_event_bytes: u64,
    allow_initial_requirement_append: bool,
) -> Result<(u64, usize), ForemanError> {
    let table_exists = |name: &str| -> Result<bool, ForemanError> {
        Ok(connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
            [name],
            |row| row.get(0),
        )?)
    };
    let mut run_columns = connection.prepare("PRAGMA table_info(runs)")?;
    let has_run_anchor = run_columns
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .any(|name| name == "execution_availability_required");
    drop(run_columns);
    let availability_required = if has_run_anchor {
        connection.query_row(
            "SELECT execution_availability_required FROM runs WHERE run_id = ?1",
            [run_id],
            |row| row.get::<_, bool>(0),
        )?
    } else {
        false
    };
    let metadata_exists = table_exists("execution_availability_event_metadata")?;
    let anchors_exist = table_exists("execution_availability_event_anchors")?;
    let marker_exists = table_exists("run_mechanism_requirements")?;
    let marker_count: usize = if marker_exists {
        connection.query_row(
            "SELECT count(*) FROM run_mechanism_requirements
             WHERE run_id = ?1 AND execution_availability_required = 1",
            [run_id],
            |row| row.get(0),
        )?
    } else {
        0
    };
    let provider_row_count: usize = connection.query_row(
        "SELECT count(*) FROM events
         WHERE run_id = ?1 AND kind IN (
             'execution_availability_requirement', 'provider_dispatch',
             'provider_disposition', 'provider_wake', 'provider_resume',
             'provider_resources_released', 'provider_resources_reacquired'
         )",
        [run_id],
        |row| row.get(0),
    )?;
    if !has_run_anchor
        && (provider_row_count != 0 || marker_count != 0 || metadata_exists != anchors_exist)
    {
        return Err(ForemanError::ReadOnlyStore(
            "HOLDING history lacks immutable run-level requirement anchor".to_owned(),
        ));
    }
    if availability_required
        && (!metadata_exists || !anchors_exist || !marker_exists || marker_count != 1)
    {
        return Err(ForemanError::ReadOnlyStore(
            "availability-required run is missing exact marker or metadata-first custody tables"
                .to_owned(),
        ));
    }
    if !availability_required && marker_count != 0 {
        return Err(ForemanError::ReadOnlyStore(
            "run-level HOLDING requirement and marker disagree".to_owned(),
        ));
    }
    if availability_required && provider_row_count == 0 && !allow_initial_requirement_append {
        return Err(ForemanError::ReadOnlyStore(
            "availability-required run has no retained provider history".to_owned(),
        ));
    }
    if !metadata_exists || !anchors_exist {
        if provider_row_count != 0 || metadata_exists != anchors_exist {
            return Err(ForemanError::ReadOnlyStore(
                "execution availability custody tables and provider rows disagree".to_owned(),
            ));
        }
        return Ok((0, 0));
    }
    let metadata_count: usize = connection.query_row(
        "SELECT count(*) FROM execution_availability_event_metadata WHERE run_id = ?1",
        [run_id],
        |row| row.get(0),
    )?;
    let anchor_count: usize = connection.query_row(
        "SELECT count(*) FROM execution_availability_event_anchors WHERE run_id = ?1",
        [run_id],
        |row| row.get(0),
    )?;
    let mut statement = connection.prepare(
        "SELECT metadata.sequence, metadata.event_id, metadata.event_kind,
                metadata.raw_byte_length, anchors.event_id,
                events.event_id, events.kind, length(events.raw_bytes)
         FROM execution_availability_event_metadata AS metadata
         JOIN execution_availability_event_anchors AS anchors
           ON anchors.sequence = metadata.sequence AND anchors.run_id = metadata.run_id
         JOIN events ON events.sequence = metadata.sequence
                    AND events.run_id = metadata.run_id
         WHERE metadata.run_id = ?1 ORDER BY metadata.sequence ASC",
    )?;
    let rows = statement.query_map([run_id], |row| {
        Ok((
            row.get::<_, u64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, u64>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, u64>(7)?,
        ))
    })?;
    let mut total = 0_u64;
    let mut count = 0_usize;
    for row in rows {
        count = count.checked_add(1).ok_or(ForemanError::InputTooLarge(
            "execution availability journal history",
        ))?;
        if count > MAXIMUM_EXECUTION_AVAILABILITY_ROWS {
            return Err(ForemanError::InputTooLarge(
                "execution availability journal history",
            ));
        }
        let (
            _sequence,
            metadata_event_id,
            metadata_kind,
            metadata_length,
            anchor_event_id,
            event_id,
            event_kind,
            length,
        ) = row?;
        if length == 0 || length > maximum_event_bytes {
            return Err(ForemanError::InputTooLarge(
                "execution availability journal event",
            ));
        }
        if metadata_event_id != event_id
            || anchor_event_id != event_id
            || metadata_length != length
            || metadata_kind != event_kind
        {
            return Err(ForemanError::ReadOnlyStore(
                "execution availability metadata/event identity mismatch".to_owned(),
            ));
        }
        total = total
            .checked_add(length)
            .ok_or(ForemanError::InputTooLarge(
                "execution availability journal history",
            ))?;
        if total > MAXIMUM_EXECUTION_AVAILABILITY_HISTORY_BYTES {
            return Err(ForemanError::InputTooLarge(
                "execution availability journal history",
            ));
        }
    }
    if count != metadata_count || count != anchor_count || count != provider_row_count {
        return Err(ForemanError::ReadOnlyStore(
            "execution availability metadata/event row set mismatch".to_owned(),
        ));
    }
    Ok((total, count))
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AvailabilityLaneEvent {
    Dispatch(String),
    PrelaunchClosed,
    Disposition(String),
    Reacquired {
        wake_occurrence_id: String,
        next_dispatch_digest: String,
        sequence: u64,
        recorded_at: DateTime<Utc>,
    },
    Wake {
        next_dispatch_digest: String,
        sequence: u64,
        recorded_at: DateTime<Utc>,
    },
    Resume,
}

fn load_execution_availability_history(
    connection: &Connection,
    run_id: &str,
    packet: &NightshiftPacketV1,
    admission: &ForemanAdmissionV1,
    profile: &ExecutionProfileV2,
) -> Result<Option<ReadOnlyExecutionAvailabilityHistoryV1>, ForemanError> {
    validate_execution_availability_history_size(
        connection,
        run_id,
        profile.maximum_event_bytes,
        false,
    )?;
    let mut statement = connection.prepare(
        "SELECT sequence, event_id, work_item_id, attempt_id, kind, recorded_at,
                raw_bytes, raw_digest
         FROM events WHERE run_id = ?1 ORDER BY sequence ASC",
    )?;
    let rows = statement.query_map([run_id], |row| {
        Ok(ReadOnlyEventRowV1 {
            sequence: row.get(0)?,
            event_id: row.get(1)?,
            work_item_id: row.get(2)?,
            attempt_id: row.get(3)?,
            kind: row.get(4)?,
            recorded_at: row.get(5)?,
            raw_bytes: row.get(6)?,
            raw_digest: row.get(7)?,
        })
    })?;
    let rows = rows.collect::<Result<Vec<_>, _>>()?;
    validate_execution_availability_history_rows(connection, &rows, packet, admission, profile)
}

fn validate_complete_execution_availability_history(
    connection: &Connection,
    run_id: &str,
) -> Result<(), ForemanError> {
    let (packet, admission, profile, _) = load_contracts(connection, run_id)?;
    load_execution_availability_history(connection, run_id, &packet, &admission, &profile)?;
    Ok(())
}

fn validate_execution_availability_history_rows(
    connection: &Connection,
    rows: &[ReadOnlyEventRowV1],
    packet: &NightshiftPacketV1,
    admission: &ForemanAdmissionV1,
    profile: &ExecutionProfileV2,
) -> Result<Option<ReadOnlyExecutionAvailabilityHistoryV1>, ForemanError> {
    let mut run_admitted: Option<(u64, DateTime<Utc>)> = None;
    let mut attempts: BTreeMap<(String, String), (WorkerStartRequestV2, u64, DateTime<Utc>)> =
        BTreeMap::new();
    let mut lane_last: BTreeMap<(String, String), AvailabilityLaneEvent> = BTreeMap::new();
    let mut history: Option<ReadOnlyExecutionAvailabilityHistoryV1> = None;
    let mut dispatch_ids = BTreeSet::new();
    let mut dispatch_digests = BTreeSet::new();
    let mut wake_ids = BTreeSet::new();
    let mut resume_ids = BTreeSet::new();
    let mut adapter_process_ids = BTreeSet::new();
    let mut app_server_session_ids = BTreeSet::new();
    let mut disposition_rows: BTreeMap<String, (u64, DateTime<Utc>)> = BTreeMap::new();
    let mut released_disposition_digests = BTreeSet::new();
    let mut expected_claims: BTreeMap<String, (String, String)> = BTreeMap::new();

    for row in rows {
        validate_read_only_event_row(row, &admission.run_id, &packet.packet_digest, profile)?;
        if row.kind == "adapter_event" {
            continue;
        }
        let event: InternalEvent = serde_json::from_slice(&row.raw_bytes)
            .map_err(|error| ForemanError::Serialization(error.to_string()))?;
        match event.payload {
            InternalPayload::RunAdmitted => {
                if run_admitted
                    .replace((row.sequence, event.recorded_at))
                    .is_some()
                {
                    return Err(ForemanError::ReadOnlyStore(
                        "execution availability history has duplicate run admission".to_owned(),
                    ));
                }
            }
            InternalPayload::AttemptCreated {
                resource_lock_keys,
                start_request,
            } => {
                let work_item_id = event.work_item_id.ok_or_else(|| {
                    ForemanError::ReadOnlyStore("attempt lacks work-item identity".to_owned())
                })?;
                let attempt_id = event.attempt_id.ok_or_else(|| {
                    ForemanError::ReadOnlyStore("attempt lacks attempt identity".to_owned())
                })?;
                if attempts
                    .insert(
                        (work_item_id.clone(), attempt_id.clone()),
                        (*start_request, row.sequence, event.recorded_at),
                    )
                    .is_some()
                {
                    return Err(ForemanError::ReadOnlyStore(
                        "duplicate work-attempt identity".to_owned(),
                    ));
                }
                for key in resource_lock_keys {
                    if expected_claims
                        .insert(key, (work_item_id.clone(), attempt_id.clone()))
                        .is_some()
                    {
                        return Err(ForemanError::ReadOnlyStore(
                            "resource claim history has overlapping attempt creation".to_owned(),
                        ));
                    }
                }
            }
            InternalPayload::ExecutionAvailabilityConfigured {
                requirement,
                requirement_bytes,
                policy,
                policy_bytes,
            } => {
                if history.is_some() || event.work_item_id.is_some() || event.attempt_id.is_some() {
                    return Err(ForemanError::ReadOnlyStore(
                        "execution availability requirement is not singular run-level state"
                            .to_owned(),
                    ));
                }
                let (run_sequence, run_time) = run_admitted.ok_or_else(|| {
                    ForemanError::ReadOnlyStore(
                        "execution availability requirement precedes run admission".to_owned(),
                    )
                })?;
                let capacity_predecessor = rows.iter().any(|candidate| {
                    candidate.sequence == run_sequence + 1
                        && candidate.kind == "capacity_requirement"
                });
                let expected_sequence = run_sequence + 1 + u64::from(capacity_predecessor);
                if row.sequence != expected_sequence || event.recorded_at != run_time {
                    return Err(ForemanError::ReadOnlyStore(
                        "execution availability requirement is not adjacent to run admission"
                            .to_owned(),
                    ));
                }
                let configuration = validate_execution_availability_configuration(
                    &requirement_bytes,
                    &policy_bytes,
                )?;
                if configuration.requirement != *requirement || configuration.policy != *policy {
                    return Err(ForemanError::ReadOnlyStore(
                        "execution availability typed/raw configuration split".to_owned(),
                    ));
                }
                validate_execution_availability_configuration_bindings(
                    &configuration,
                    packet,
                    admission,
                    profile,
                    event.recorded_at,
                )?;
                history = Some(ReadOnlyExecutionAvailabilityHistoryV1 {
                    requirement: configuration.requirement,
                    requirement_bytes: configuration.requirement_bytes,
                    policy: configuration.policy,
                    policy_bytes: configuration.policy_bytes,
                    worker_start_requests: Vec::new(),
                    dispatches: Vec::new(),
                    observations: Vec::new(),
                    dispositions: Vec::new(),
                    deferred: Vec::new(),
                    wake_occurrence_ids: Vec::new(),
                    wake_work_attempt_ids: Vec::new(),
                    wake_next_dispatch_digests: Vec::new(),
                    resume_occurrence_ids: Vec::new(),
                    resume_work_item_ids: Vec::new(),
                    resume_work_attempt_ids: Vec::new(),
                    resume_adapter_process_occurrence_ids: Vec::new(),
                    resume_execution_identities: Vec::new(),
                    resume_disposition_digests: Vec::new(),
                    resume_recorded_at: Vec::new(),
                    resource_transitions: Vec::new(),
                });
            }
            InternalPayload::ProviderDispatchOpened {
                start_request,
                start_request_bytes,
                dispatch,
                dispatch_bytes,
            } => {
                let history = history.as_mut().ok_or_else(|| {
                    ForemanError::ReadOnlyStore(
                        "provider dispatch lacks immutable availability requirement".to_owned(),
                    )
                })?;
                start_request.validate()?;
                dispatch.validate()?;
                if serde_jcs::to_vec(&*start_request)
                    .map_err(|error| ForemanError::Serialization(error.to_string()))?
                    != start_request_bytes
                    || serde_jcs::to_vec(&*dispatch)
                        .map_err(|error| ForemanError::Serialization(error.to_string()))?
                        != dispatch_bytes
                {
                    return Err(ForemanError::ReadOnlyStore(
                        "provider dispatch typed/raw custody split".to_owned(),
                    ));
                }
                start_request.validate_dispatch_graph(profile, &history.requirement, &dispatch)?;
                if event.work_item_id.as_deref() != Some(dispatch.work_item_id.as_str())
                    || event.attempt_id.as_deref() != Some(dispatch.work_attempt_id.as_str())
                    || event.recorded_at != dispatch.opened_at
                    || event.event_id
                        != format!("provider-dispatch-{}", dispatch.dispatch_occurrence_id)
                    || !dispatch_ids.insert(dispatch.dispatch_occurrence_id.clone())
                    || !dispatch_digests.insert(dispatch.dispatch_digest.clone())
                {
                    return Err(ForemanError::ReadOnlyStore(
                        "provider dispatch journal identity mismatch".to_owned(),
                    ));
                }
                let key = (
                    dispatch.work_item_id.clone(),
                    dispatch.work_attempt_id.clone(),
                );
                let (predecessor, attempt_sequence, attempt_recorded_at) =
                    attempts.get(&key).ok_or_else(|| {
                        ForemanError::ReadOnlyStore(
                            "provider dispatch lacks exact work-attempt predecessor".to_owned(),
                        )
                    })?;
                if start_request.predecessor_v2()? != *predecessor
                    || (dispatch.dispatch_ordinal == 1
                        && (row.sequence != attempt_sequence + 1
                            || event.recorded_at != *attempt_recorded_at))
                    || usize::from(dispatch.dispatch_ordinal)
                        != history
                            .dispatches
                            .iter()
                            .filter(|value| value.work_attempt_id == dispatch.work_attempt_id)
                            .count()
                            + 1
                {
                    return Err(ForemanError::ReadOnlyStore(
                        "provider dispatch attempt or ordinal discontinuity".to_owned(),
                    ));
                }
                match lane_last.get(&key) {
                    None if dispatch.dispatch_ordinal == 1 => {}
                    Some(AvailabilityLaneEvent::Wake {
                        next_dispatch_digest,
                        sequence,
                        recorded_at,
                    }) if next_dispatch_digest == &dispatch.dispatch_digest
                        && row.sequence == sequence + 1
                        && event.recorded_at == *recorded_at => {}
                    _ => {
                        return Err(ForemanError::ReadOnlyStore(
                            "provider dispatch lacks exact attempt/wake predecessor".to_owned(),
                        ))
                    }
                }
                if !adapter_process_ids.insert(dispatch.adapter_process_occurrence_id.clone()) {
                    return Err(ForemanError::ReadOnlyStore(
                        "adapter process occurrence is not globally unique".to_owned(),
                    ));
                }
                if !app_server_session_ids.insert(dispatch.app_server_session_identity.clone()) {
                    return Err(ForemanError::ReadOnlyStore(
                        "App Server session identity is not globally unique per dispatch"
                            .to_owned(),
                    ));
                }
                lane_last.insert(
                    key,
                    AvailabilityLaneEvent::Dispatch(dispatch.dispatch_digest.clone()),
                );
                history.worker_start_requests.push(*start_request);
                history.dispatches.push(*dispatch);
            }
            InternalPayload::PrelaunchClosureAccepted { closure, receipt } => {
                let history = history.as_ref().ok_or_else(|| {
                    ForemanError::ReadOnlyStore(
                        "prelaunch closure lacks provider history".to_owned(),
                    )
                })?;
                let binding = &closure.binding;
                let key = (
                    binding.work_item_id.clone(),
                    binding.work_attempt_id.clone(),
                );
                if lane_last.get(&key)
                    != Some(&AvailabilityLaneEvent::Dispatch(
                        binding.dispatch_digest.clone(),
                    ))
                    || history
                        .dispositions
                        .iter()
                        .any(|value| value.work_attempt_id == binding.work_attempt_id)
                    || event.work_item_id.as_deref() != Some(binding.work_item_id.as_str())
                    || event.attempt_id.as_deref() != Some(binding.work_attempt_id.as_str())
                    || event.recorded_at != closure.closed_at
                    || event.event_id != format!("prelaunch-closed-{}", closure.closure_digest)
                {
                    return Err(ForemanError::ReadOnlyStore(
                        "prelaunch closure history mismatch".to_owned(),
                    ));
                }
                let index = history
                    .dispatches
                    .iter()
                    .position(|dispatch| dispatch.dispatch_digest == binding.dispatch_digest)
                    .ok_or(ForemanError::IdentityMismatch("prelaunch dispatch"))?;
                let brief = worker_brief_bytes(
                    connection,
                    packet,
                    profile,
                    &binding.run_id,
                    &binding.work_item_id,
                )?;
                closure.validate_prepared(
                    &history.worker_start_requests[index],
                    &history.dispatches[index],
                    &brief,
                )?;
                let expected_receipt = prelaunch_not_started_receipt(&closure)?;
                if *receipt != expected_receipt {
                    return Err(ForemanError::ReadOnlyStore(
                        "prelaunch receipt custody differs".to_owned(),
                    ));
                }
                let (raw, kind, attempt): (Vec<u8>, String, Option<String>) = connection.query_row(
                    "SELECT raw_bytes,receipt_kind,attempt_id FROM terminal_receipts WHERE run_id=?1 AND work_item_id=?2",
                    params![binding.run_id, binding.work_item_id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?;
                if raw
                    != serde_jcs::to_vec(&expected_receipt)
                        .map_err(|e| ForemanError::Serialization(e.to_string()))?
                    || kind != "not_started"
                    || attempt.is_some()
                {
                    return Err(ForemanError::ReadOnlyStore(
                        "prelaunch receipt row differs".to_owned(),
                    ));
                }
                lane_last.insert(key, AvailabilityLaneEvent::PrelaunchClosed);
            }
            InternalPayload::ProviderDispositionRecorded {
                observation,
                observation_bytes,
                disposition,
                disposition_bytes,
                deferred,
                deferred_bytes,
                reconciles_disposition_digest,
            } => {
                let history = history.as_mut().ok_or_else(|| {
                    ForemanError::ReadOnlyStore(
                        "provider disposition lacks immutable availability requirement".to_owned(),
                    )
                })?;
                let accepted =
                    validate_provider_disposition_evidence(ProviderDispositionEvidenceV1 {
                        observation_bytes: &observation_bytes,
                        disposition_bytes: &disposition_bytes,
                        deferred_bytes: deferred_bytes.as_deref(),
                    })?;
                if accepted.observation != *observation
                    || accepted.disposition != *disposition
                    || accepted.deferred.as_ref() != deferred.as_deref()
                {
                    return Err(ForemanError::ReadOnlyStore(
                        "provider disposition nested typed/raw custody split".to_owned(),
                    ));
                }
                let dispatch = history
                    .dispatches
                    .iter()
                    .find(|value| value.dispatch_digest == disposition.dispatch_digest)
                    .ok_or_else(|| {
                        ForemanError::ReadOnlyStore(
                            "provider disposition lacks exact dispatch".to_owned(),
                        )
                    })?;
                if event.work_item_id.as_deref() != Some(disposition.work_item_id.as_str())
                    || event.attempt_id.as_deref() != Some(disposition.work_attempt_id.as_str())
                    || event.recorded_at != disposition.received_at
                    || event.event_id
                        != format!("provider-disposition-{}", disposition.disposition_digest)
                {
                    return Err(ForemanError::ReadOnlyStore(
                        "provider disposition journal identity mismatch".to_owned(),
                    ));
                }
                let key = (
                    disposition.work_item_id.clone(),
                    disposition.work_attempt_id.clone(),
                );
                let previous = history
                    .dispositions
                    .iter()
                    .rev()
                    .find(|value| value.dispatch_digest == disposition.dispatch_digest);
                match (previous, reconciles_disposition_digest.as_deref()) {
                    (None, None) => match lane_last.get(&key) {
                        Some(AvailabilityLaneEvent::Dispatch(expected))
                            if expected == &disposition.dispatch_digest => {}
                        _ => {
                            return Err(ForemanError::ReadOnlyStore(
                                "provider disposition lacks exact dispatch predecessor".to_owned(),
                            ))
                        }
                    },
                    (Some(prior), Some(expected)) if prior.disposition_digest == expected => {
                        validate_provider_disposition_transition(prior, &disposition)?;
                    }
                    _ => {
                        return Err(ForemanError::ReadOnlyStore(
                            "provider disposition predecessor mismatch".to_owned(),
                        ))
                    }
                }
                let prior_history = provider_deferral_history(
                    history,
                    &disposition.work_attempt_id,
                    dispatch.dispatch_ordinal,
                )?;
                validate_execution_availability_graph(
                    &history.requirement,
                    &history.policy,
                    dispatch,
                    &observation,
                    &disposition,
                    &prior_history,
                    deferred.as_deref(),
                )?;
                lane_last.insert(
                    key,
                    AvailabilityLaneEvent::Disposition(disposition.disposition_digest.clone()),
                );
                history.observations.push(*observation);
                disposition_rows.insert(
                    disposition.disposition_digest.clone(),
                    (row.sequence, event.recorded_at),
                );
                history.dispositions.push(*disposition);
                if let Some(deferred) = deferred {
                    history.deferred.push(*deferred);
                }
            }
            InternalPayload::ProviderWakeOpened {
                wake_occurrence_id,
                deferred_dispatch_digest,
                next_dispatch_digest,
            } => {
                let history = history.as_mut().ok_or_else(|| {
                    ForemanError::ReadOnlyStore(
                        "provider wake lacks immutable availability requirement".to_owned(),
                    )
                })?;
                validate_local_occurrence_id(&wake_occurrence_id, "wake_occurrence_id")?;
                let work_item_id = event.work_item_id.ok_or_else(|| {
                    ForemanError::ReadOnlyStore("provider wake lacks work item".to_owned())
                })?;
                let attempt_id = event.attempt_id.ok_or_else(|| {
                    ForemanError::ReadOnlyStore("provider wake lacks attempt".to_owned())
                })?;
                let key = (work_item_id, attempt_id.clone());
                let deferred = history
                    .deferred
                    .iter()
                    .find(|value| {
                        value.deferred_dispatch_digest == deferred_dispatch_digest
                            && value.work_attempt_id == attempt_id
                    })
                    .ok_or_else(|| {
                        ForemanError::ReadOnlyStore(
                            "provider wake deferred binding mismatch".to_owned(),
                        )
                    })?;
                if event.recorded_at < deferred.wake_at
                    || !wake_ids.insert(wake_occurrence_id.clone())
                    || event.event_id != format!("provider-wake-{wake_occurrence_id}")
                {
                    return Err(ForemanError::ReadOnlyStore(
                        "provider wake time or identity mismatch".to_owned(),
                    ));
                }
                match history.policy.parked_resource_lock_policy {
                    ParkedResourceLockPolicyV1::ReleaseAndReacquire => match lane_last.get(&key) {
                        Some(AvailabilityLaneEvent::Reacquired {
                            wake_occurrence_id: expected_wake,
                            next_dispatch_digest: expected_dispatch,
                            sequence,
                            recorded_at,
                        }) if expected_wake == &wake_occurrence_id
                            && expected_dispatch == &next_dispatch_digest
                            && row.sequence == sequence + 1
                            && event.recorded_at == *recorded_at => {}
                        _ => {
                            return Err(ForemanError::ReadOnlyStore(
                                "provider wake resource reacquisition binding mismatch".to_owned(),
                            ))
                        }
                    },
                    ParkedResourceLockPolicyV1::RetainWhileParked => match lane_last.get(&key) {
                        Some(AvailabilityLaneEvent::Disposition(value))
                            if value == &deferred.disposition_digest => {}
                        _ => {
                            return Err(ForemanError::ReadOnlyStore(
                                "provider wake lacks exact parked disposition predecessor"
                                    .to_owned(),
                            ))
                        }
                    },
                }
                lane_last.insert(
                    key,
                    AvailabilityLaneEvent::Wake {
                        next_dispatch_digest: next_dispatch_digest.clone(),
                        sequence: row.sequence,
                        recorded_at: event.recorded_at,
                    },
                );
                history.wake_occurrence_ids.push(wake_occurrence_id);
                history.wake_work_attempt_ids.push(attempt_id);
                history
                    .wake_next_dispatch_digests
                    .push(next_dispatch_digest);
            }
            InternalPayload::ProviderExecutionResumeRequested {
                resume_occurrence_id,
                disposition_digest,
                adapter_process_occurrence_id,
                execution_identity,
            } => {
                let history = history.as_mut().ok_or_else(|| {
                    ForemanError::ReadOnlyStore(
                        "provider resume lacks immutable availability requirement".to_owned(),
                    )
                })?;
                validate_local_occurrence_id(&resume_occurrence_id, "resume_occurrence_id")?;
                validate_local_occurrence_id(
                    &adapter_process_occurrence_id,
                    "adapter_process_occurrence_id",
                )?;
                execution_identity.validate()?;
                let work_item_id = event.work_item_id.ok_or_else(|| {
                    ForemanError::ReadOnlyStore("provider resume lacks work item".to_owned())
                })?;
                let attempt_id = event.attempt_id.ok_or_else(|| {
                    ForemanError::ReadOnlyStore("provider resume lacks attempt".to_owned())
                })?;
                let key = (work_item_id, attempt_id.clone());
                let disposition = history
                    .dispositions
                    .iter()
                    .rev()
                    .find(|value| value.work_attempt_id == attempt_id)
                    .ok_or_else(|| {
                        ForemanError::ReadOnlyStore(
                            "provider resume lacks exact disposition".to_owned(),
                        )
                    })?;
                if disposition.disposition_digest != disposition_digest
                    || disposition.mechanism_state
                        != ProviderMechanismStateV1::PostAdmissionInterrupted
                    || disposition.provider_execution.as_ref() != Some(&execution_identity)
                    || event.recorded_at < disposition.received_at
                    || event.event_id != format!("provider-resume-{resume_occurrence_id}")
                    || !resume_ids.insert(resume_occurrence_id.clone())
                    || !adapter_process_ids.insert(adapter_process_occurrence_id.clone())
                    || history
                        .resume_disposition_digests
                        .iter()
                        .any(|value| value == &disposition_digest)
                {
                    return Err(ForemanError::ReadOnlyStore(
                        "provider resume exact execution binding mismatch".to_owned(),
                    ));
                }
                lane_last.insert(key.clone(), AvailabilityLaneEvent::Resume);
                history.resume_occurrence_ids.push(resume_occurrence_id);
                history.resume_work_item_ids.push(key.0.clone());
                history.resume_work_attempt_ids.push(key.1.clone());
                history
                    .resume_adapter_process_occurrence_ids
                    .push(adapter_process_occurrence_id);
                history
                    .resume_execution_identities
                    .push(*execution_identity);
                history.resume_disposition_digests.push(disposition_digest);
                history.resume_recorded_at.push(event.recorded_at);
            }
            InternalPayload::ProviderResourcesReleased {
                disposition_digest,
                dispatch_digest,
                policy_digest,
                resource_lock_keys,
            } => {
                let history = history.as_mut().ok_or_else(|| {
                    ForemanError::ReadOnlyStore(
                        "resource release lacks immutable availability requirement".to_owned(),
                    )
                })?;
                let work_item_id = event.work_item_id.ok_or_else(|| {
                    ForemanError::ReadOnlyStore("resource release lacks work item".to_owned())
                })?;
                let attempt_id = event.attempt_id.ok_or_else(|| {
                    ForemanError::ReadOnlyStore("resource release lacks attempt".to_owned())
                })?;
                let disposition = history
                    .dispositions
                    .iter()
                    .find(|value| value.disposition_digest == disposition_digest)
                    .ok_or_else(|| {
                        ForemanError::ReadOnlyStore(
                            "resource release lacks exact parked disposition".to_owned(),
                        )
                    })?;
                let (disposition_sequence, disposition_time) =
                    disposition_rows.get(&disposition_digest).ok_or_else(|| {
                        ForemanError::ReadOnlyStore("missing disposition row".to_owned())
                    })?;
                if history.policy.parked_resource_lock_policy
                    != ParkedResourceLockPolicyV1::ReleaseAndReacquire
                    || disposition.mechanism_state != ProviderMechanismStateV1::ParkedNotAdmitted
                    || disposition.dispatch_digest != dispatch_digest
                    || history.policy.policy_digest != policy_digest
                    || resource_lock_keys != profile.work_items[&work_item_id].resource_lock_keys
                    || disposition.work_attempt_id != attempt_id
                    || event.event_id != format!("provider-resources-released-{disposition_digest}")
                    || row.sequence != disposition_sequence + 1
                    || event.recorded_at != *disposition_time
                {
                    return Err(ForemanError::ReadOnlyStore(
                        "provider resource release binding mismatch".to_owned(),
                    ));
                }
                if !released_disposition_digests.insert(disposition_digest.clone()) {
                    return Err(ForemanError::ReadOnlyStore(
                        "duplicate provider resource release".to_owned(),
                    ));
                }
                for key in &resource_lock_keys {
                    if expected_claims.remove(key)
                        != Some((work_item_id.clone(), attempt_id.clone()))
                    {
                        return Err(ForemanError::ReadOnlyStore(
                            "resource release history disagrees with retained claim".to_owned(),
                        ));
                    }
                }
                history
                    .resource_transitions
                    .push(ReadOnlyProviderResourceTransitionV1 {
                        transition: "RELEASED".to_owned(),
                        work_item_id,
                        work_attempt_id: attempt_id,
                        dispatch_digest,
                        disposition_digest: Some(disposition_digest),
                        deferred_dispatch_digest: None,
                        policy_digest,
                        wake_occurrence_id: None,
                        resource_lock_keys,
                        recorded_at: event.recorded_at,
                    });
            }
            InternalPayload::ProviderResourcesReacquired {
                wake_occurrence_id,
                deferred_dispatch_digest,
                next_dispatch_digest,
                policy_digest,
                resource_lock_keys,
            } => {
                let history = history.as_mut().ok_or_else(|| {
                    ForemanError::ReadOnlyStore(
                        "resource reacquisition lacks immutable availability requirement"
                            .to_owned(),
                    )
                })?;
                let work_item_id = event.work_item_id.ok_or_else(|| {
                    ForemanError::ReadOnlyStore("resource reacquisition lacks work item".to_owned())
                })?;
                let attempt_id = event.attempt_id.ok_or_else(|| {
                    ForemanError::ReadOnlyStore("resource reacquisition lacks attempt".to_owned())
                })?;
                let deferred = history
                    .deferred
                    .iter()
                    .find(|value| value.deferred_dispatch_digest == deferred_dispatch_digest)
                    .ok_or_else(|| {
                        ForemanError::ReadOnlyStore(
                            "resource reacquisition lacks exact deferral".to_owned(),
                        )
                    })?;
                let key = (work_item_id.clone(), attempt_id.clone());
                if history.policy.parked_resource_lock_policy
                    != ParkedResourceLockPolicyV1::ReleaseAndReacquire
                    || history.policy.policy_digest != policy_digest
                    || deferred.work_attempt_id != attempt_id
                    || resource_lock_keys != profile.work_items[&work_item_id].resource_lock_keys
                    || event.event_id
                        != format!("provider-resources-reacquired-{wake_occurrence_id}")
                    || event.recorded_at < deferred.wake_at
                    || lane_last.get(&key)
                        != Some(&AvailabilityLaneEvent::Disposition(
                            deferred.disposition_digest.clone(),
                        ))
                {
                    return Err(ForemanError::ReadOnlyStore(
                        "provider resource reacquisition binding mismatch".to_owned(),
                    ));
                }
                for key in &resource_lock_keys {
                    if expected_claims
                        .insert(key.clone(), (work_item_id.clone(), attempt_id.clone()))
                        .is_some()
                    {
                        return Err(ForemanError::ReadOnlyStore(
                            "resource reacquisition overlaps a retained claim".to_owned(),
                        ));
                    }
                }
                lane_last.insert(
                    key,
                    AvailabilityLaneEvent::Reacquired {
                        wake_occurrence_id: wake_occurrence_id.clone(),
                        next_dispatch_digest: next_dispatch_digest.clone(),
                        sequence: row.sequence,
                        recorded_at: event.recorded_at,
                    },
                );
                history
                    .resource_transitions
                    .push(ReadOnlyProviderResourceTransitionV1 {
                        transition: "REACQUIRED".to_owned(),
                        work_item_id,
                        work_attempt_id: attempt_id,
                        dispatch_digest: next_dispatch_digest,
                        disposition_digest: None,
                        deferred_dispatch_digest: Some(deferred_dispatch_digest),
                        policy_digest,
                        wake_occurrence_id: Some(wake_occurrence_id),
                        resource_lock_keys,
                        recorded_at: event.recorded_at,
                    });
            }
            InternalPayload::ResourcesReleased => {
                if let (Some(work_item_id), Some(attempt_id)) =
                    (event.work_item_id.as_deref(), event.attempt_id.as_deref())
                {
                    expected_claims
                        .retain(|_, holder| holder.0 != work_item_id || holder.1 != attempt_id);
                }
            }
            _ => {}
        }
    }
    if lane_last.values().any(|value| {
        matches!(
            value,
            AvailabilityLaneEvent::Reacquired { .. } | AvailabilityLaneEvent::Wake { .. }
        )
    }) {
        return Err(ForemanError::ReadOnlyStore(
            "provider resource reacquisition or wake lacks atomic successor".to_owned(),
        ));
    }
    if let Some(history) = &history {
        if attempts.keys().any(|(work_item_id, attempt_id)| {
            !history.dispatches.iter().any(|dispatch| {
                dispatch.work_item_id == *work_item_id
                    && dispatch.work_attempt_id == *attempt_id
                    && dispatch.dispatch_ordinal == 1
            })
        }) {
            return Err(ForemanError::ReadOnlyStore(
                "availability-required attempt lacks adjacent initial dispatch".to_owned(),
            ));
        }
        if history.policy.parked_resource_lock_policy
            == ParkedResourceLockPolicyV1::ReleaseAndReacquire
            && history.dispositions.iter().any(|disposition| {
                disposition.mechanism_state == ProviderMechanismStateV1::ParkedNotAdmitted
                    && !released_disposition_digests.contains(&disposition.disposition_digest)
            })
        {
            return Err(ForemanError::ReadOnlyStore(
                "parked disposition lacks mandatory resource release".to_owned(),
            ));
        }
    }
    if history.is_some() {
        let mut statement = connection.prepare(
            "SELECT resource_lock_key, work_item_id, attempt_id
             FROM resource_claims WHERE run_id = ?1 ORDER BY resource_lock_key ASC",
        )?;
        let actual = statement
            .query_map([&admission.run_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    (row.get::<_, String>(1)?, row.get::<_, String>(2)?),
                ))
            })?
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        if actual != expected_claims {
            return Err(ForemanError::ReadOnlyStore(
                "mutable resource claims disagree with exact journal history".to_owned(),
            ));
        }
    }
    Ok(history)
}

fn provider_deferral_history(
    history: &ReadOnlyExecutionAvailabilityHistoryV1,
    attempt_id: &str,
    before_dispatch_ordinal: u16,
) -> Result<Vec<ProviderDeferralHistoryEntryV1>, ForemanError> {
    let mut result = Vec::new();
    for dispatch in history.dispatches.iter().filter(|value| {
        value.work_attempt_id == attempt_id && value.dispatch_ordinal < before_dispatch_ordinal
    }) {
        let disposition = history
            .dispositions
            .iter()
            .rev()
            .find(|value| value.dispatch_digest == dispatch.dispatch_digest)
            .ok_or_else(|| {
                ForemanError::ReadOnlyStore(
                    "prior dispatch lacks exact terminal admission disposition".to_owned(),
                )
            })?;
        let deferred = history
            .deferred
            .iter()
            .find(|value| value.disposition_digest == disposition.disposition_digest)
            .ok_or_else(|| {
                ForemanError::ReadOnlyStore(
                    "prior not-admitted dispatch lacks exact deferral".to_owned(),
                )
            })?;
        result.push(ProviderDeferralHistoryEntryV1 {
            dispatch: dispatch.clone(),
            disposition: disposition.clone(),
            deferred: deferred.clone(),
        });
    }
    result.sort_by_key(|entry| entry.dispatch.dispatch_ordinal);
    Ok(result)
}

fn validate_provider_disposition_transition(
    previous: &ProviderAdmissionDispositionV1,
    next: &ProviderAdmissionDispositionV1,
) -> Result<(), ForemanError> {
    if previous.dispatch_digest != next.dispatch_digest
        || previous.work_attempt_id != next.work_attempt_id
        || previous.dispatch_occurrence_id != next.dispatch_occurrence_id
        || next.received_at < previous.received_at
    {
        return Err(ForemanError::IdentityMismatch(
            "provider disposition transition identity",
        ));
    }
    match previous.mechanism_state {
        ProviderMechanismStateV1::AdmissionIndeterminate => Ok(()),
        ProviderMechanismStateV1::ExecutionAdmitted
        | ProviderMechanismStateV1::WaitingApproval
        | ProviderMechanismStateV1::PostAdmissionInterrupted => {
            if previous.provider_execution.is_none()
                || next.provider_execution != previous.provider_execution
                || !matches!(
                    next.mechanism_state,
                    ProviderMechanismStateV1::ExecutionAdmitted
                        | ProviderMechanismStateV1::WaitingApproval
                        | ProviderMechanismStateV1::PostAdmissionInterrupted
                        | ProviderMechanismStateV1::ProviderCompleted
                )
            {
                return Err(ForemanError::Transition(
                    "post-admission state may retain only the exact execution".to_owned(),
                ));
            }
            Ok(())
        }
        ProviderMechanismStateV1::ParkedNotAdmitted
        | ProviderMechanismStateV1::ProviderCompleted => Err(ForemanError::Transition(
            "closed provider disposition cannot transition".to_owned(),
        )),
    }
}

fn load_projection(
    connection: &Connection,
    run_id: &str,
) -> Result<LiveRunProjectionV1, ForemanError> {
    let (packet, admission, profile, maximum) = load_contracts(connection, run_id)?;
    validate_capacity_history_size(
        connection,
        run_id,
        profile.maximum_event_bytes,
        packet.work_items.len().saturating_add(1),
    )?;
    validate_execution_availability_history_size(
        connection,
        run_id,
        profile.maximum_event_bytes,
        false,
    )?;
    let mut statement = connection.prepare(
        "SELECT sequence, event_id, work_item_id, attempt_id, kind, recorded_at,
                raw_bytes, raw_digest
         FROM events WHERE run_id = ?1 ORDER BY sequence ASC",
    )?;
    let rows = statement.query_map([run_id], |row| {
        Ok(ReadOnlyEventRowV1 {
            sequence: row.get(0)?,
            event_id: row.get(1)?,
            work_item_id: row.get(2)?,
            attempt_id: row.get(3)?,
            kind: row.get(4)?,
            recorded_at: row.get(5)?,
            raw_bytes: row.get(6)?,
            raw_digest: row.get(7)?,
        })
    })?;
    let rows = rows.collect::<Result<Vec<_>, _>>()?;
    validate_capacity_history(connection, &rows, &packet, &admission, &profile)?;
    validate_execution_availability_history_rows(connection, &rows, &packet, &admission, &profile)?;

    let mut events = Vec::with_capacity(rows.len());
    for row in rows {
        let replay_kind = if row.kind == "adapter_event" {
            ReplayKind::Adapter(Box::new(AdapterEventV1::from_slice(&row.raw_bytes)?))
        } else {
            let event: InternalEvent = serde_json::from_slice(&row.raw_bytes)
                .map_err(|error| ForemanError::Serialization(error.to_string()))?;
            match event.payload {
                InternalPayload::RunAdmitted => ReplayKind::RunAdmitted,
                InternalPayload::CapacityRequirementAdmitted { .. }
                | InternalPayload::CapacityAdmissionAccepted { .. } => ReplayKind::CapacityEvidence,
                InternalPayload::ExecutionAvailabilityConfigured { .. } => {
                    ReplayKind::ExecutionAvailabilityConfigured
                }
                InternalPayload::ProviderDispatchOpened { .. } => {
                    ReplayKind::ProviderDispatchOpened
                }
                InternalPayload::ProviderDispositionRecorded { disposition, .. } => {
                    ReplayKind::ProviderDispositionRecorded {
                        mechanism_state: disposition.mechanism_state,
                        execution_identity: disposition.provider_execution.clone(),
                    }
                }
                InternalPayload::ProviderWakeOpened { .. } => ReplayKind::ProviderWakeOpened,
                InternalPayload::ProviderExecutionResumeRequested { .. } => {
                    ReplayKind::ProviderExecutionResumeRequested
                }
                InternalPayload::ProviderResourcesReleased { .. } => {
                    ReplayKind::ProviderResourcesReleased
                }
                InternalPayload::ProviderResourcesReacquired {
                    resource_lock_keys, ..
                } => ReplayKind::ProviderResourcesReacquired { resource_lock_keys },
                InternalPayload::AttemptCreated {
                    resource_lock_keys, ..
                } => ReplayKind::AttemptCreated { resource_lock_keys },
                InternalPayload::DispatchRequested => ReplayKind::DispatchRequested,
                InternalPayload::ResumeRequested => ReplayKind::ResumeRequested,
                InternalPayload::TerminalAccepted { outcome } => {
                    ReplayKind::TerminalAccepted(outcome)
                }
                InternalPayload::TerminalRefused { .. } => ReplayKind::TerminalRefused,
                InternalPayload::NotStartedAccepted { outcome } => {
                    ReplayKind::NotStartedAccepted(outcome)
                }
                InternalPayload::PrelaunchClosureAccepted { receipt, .. } => {
                    ReplayKind::NotStartedAccepted(AcceptedOutcomeV1 {
                        state: receipt.state,
                        result_classification: receipt.result_classification,
                        receipt_digest: receipt.receipt_digest,
                    })
                }
                InternalPayload::ResourcesReleased => ReplayKind::ResourcesReleased,
                InternalPayload::RunClosed {
                    final_receipts_digest,
                } => ReplayKind::RunClosed {
                    final_receipts_digest,
                },
            }
        };
        events.push(ReplayEvent {
            sequence: row.sequence,
            work_item_id: row.work_item_id,
            attempt_id: row.attempt_id,
            kind: replay_kind,
            raw_digest: row.raw_digest,
        });
    }
    Ok(Scheduler::replay(
        &packet,
        run_id,
        &admission.admission_digest,
        &profile,
        maximum,
        &events,
    ))
}

fn prior_attempt_exists(
    connection: &Connection,
    run_id: &str,
    work_item_id: &str,
) -> Result<bool, ForemanError> {
    let mut statement = connection.prepare(
        "SELECT raw_bytes FROM events
         WHERE run_id = ?1 AND work_item_id = ?2 AND kind = 'internal'",
    )?;
    let rows = statement.query_map(params![run_id, work_item_id], |row| {
        row.get::<_, Vec<u8>>(0)
    })?;
    for row in rows {
        let event: InternalEvent = serde_json::from_slice(&row?)
            .map_err(|error| ForemanError::Serialization(error.to_string()))?;
        if matches!(event.payload, InternalPayload::AttemptCreated { .. }) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn exact_active_attempt(
    connection: &Connection,
    run_id: &str,
    work_item_id: &str,
    attempt_id: &str,
) -> Result<(), ForemanError> {
    let projection = load_projection(connection, run_id)?;
    let item = projection
        .work_items
        .iter()
        .find(|item| item.work_item_id == work_item_id)
        .ok_or_else(|| ForemanError::UnknownWorkItem(work_item_id.to_owned()))?;
    if item.scheduler_state.is_explicit_terminal() {
        return Err(ForemanError::Transition(
            "terminal attempt cannot be resumed or reused".to_owned(),
        ));
    }
    if item.active_attempt_id.as_deref() != Some(attempt_id) {
        return Err(ForemanError::IdentityMismatch("attempt_id"));
    }
    Ok(())
}

fn prelaunch_not_started_receipt(
    closure: &PrelaunchClosureV1,
) -> Result<NotStartedReceiptV1, ForemanError> {
    closure.validate()?;
    let mut receipt = NotStartedReceiptV1 {
        schema: crate::WORK_ITEM_NOT_STARTED_RECEIPT_SCHEMA_V1.to_owned(),
        receipt_digest: placeholder_digest(), packet_digest: closure.binding.packet_digest.clone(),
        run_id: closure.binding.run_id.clone(), work_item_id: closure.binding.work_item_id.clone(),
        recorded_at: closure.closed_at, state: "NOT_STARTED".to_owned(),
        result_classification: "LOCAL_PRELAUNCH_FAILURE".to_owned(),
        evidence: vec![closure.closure_digest.clone()],
        remaining_trigger: "Prepared attempt retained; backend launch failed before provider claim. No worker result exists.".to_owned(),
        next_lawful_action: "Review the local failure and obtain separately admitted successor work; this closure grants no retry.".to_owned(),
        human_questions: Vec::new(),
        extensions: BTreeMap::from([
            ("prelaunch_closure".to_owned(), serde_json::to_value(closure)
                .map_err(|e| ForemanError::Serialization(e.to_string()))?),
            ("prepared_attempt_id".to_owned(), Value::String(closure.binding.work_attempt_id.clone())),
        ]),
    };
    receipt.seal()?;
    Ok(receipt)
}

#[derive(Clone)]
struct CurrentHoldingAttemptState {
    disposition: Option<ProviderAdmissionDispositionV1>,
    resumed_current_disposition: bool,
}

fn current_holding_attempt_state(
    connection: &Connection,
    run_id: &str,
    work_item_id: &str,
    attempt_id: &str,
) -> Result<Option<CurrentHoldingAttemptState>, ForemanError> {
    let (packet, admission, profile, _) = load_contracts(connection, run_id)?;
    let Some(history) =
        load_execution_availability_history(connection, run_id, &packet, &admission, &profile)?
    else {
        return Ok(None);
    };
    let current_dispatch = history.dispatches.iter().rev().find(|dispatch| {
        dispatch.work_item_id == work_item_id && dispatch.work_attempt_id == attempt_id
    });
    let disposition = current_dispatch.and_then(|dispatch| {
        history
            .dispositions
            .iter()
            .rev()
            .find(|disposition| disposition.dispatch_digest == dispatch.dispatch_digest)
            .cloned()
    });
    let resumed_current_disposition = disposition.as_ref().is_some_and(|disposition| {
        history
            .resume_disposition_digests
            .iter()
            .any(|digest| digest == &disposition.disposition_digest)
    });
    Ok(Some(CurrentHoldingAttemptState {
        disposition,
        resumed_current_disposition,
    }))
}

fn refuse_holding_legacy_transition(
    connection: &Connection,
    run_id: &str,
    work_item_id: &str,
    attempt_id: &str,
) -> Result<(), ForemanError> {
    if current_holding_attempt_state(connection, run_id, work_item_id, attempt_id)?.is_some() {
        return Err(ForemanError::Transition(
            "HOLDING attempt requires an exact mechanism-owned transition".to_owned(),
        ));
    }
    Ok(())
}

fn validate_holding_adapter_event_transition(
    connection: &Connection,
    event: &AdapterEventV1,
) -> Result<(), ForemanError> {
    if current_holding_attempt_state(
        connection,
        &event.run_id,
        &event.work_item_id,
        &event.attempt_id,
    )?
    .is_some()
    {
        return Err(ForemanError::Transition(
            "HOLDING mechanism state is accepted only through exact owner dispositions".to_owned(),
        ));
    }
    Ok(())
}

fn validate_holding_terminal_transition(
    connection: &Connection,
    receipt: &TerminalReceiptV1,
) -> Result<(), ForemanError> {
    let Some(state) = current_holding_attempt_state(
        connection,
        &receipt.run_id,
        &receipt.work_item_id,
        &receipt.attempt_id,
    )?
    else {
        return Ok(());
    };
    let disposition = state.disposition.ok_or_else(|| {
        ForemanError::Transition(
            "terminal receipt requires exact admitted provider execution".to_owned(),
        )
    })?;
    if matches!(
        disposition.mechanism_state,
        ProviderMechanismStateV1::ParkedNotAdmitted
            | ProviderMechanismStateV1::AdmissionIndeterminate
            | ProviderMechanismStateV1::WaitingApproval
    ) || (disposition.mechanism_state == ProviderMechanismStateV1::PostAdmissionInterrupted
        && !state.resumed_current_disposition)
    {
        return Err(ForemanError::Transition(
            "terminal receipt is not admissible in the exact HOLDING state".to_owned(),
        ));
    }
    let execution = disposition.provider_execution.ok_or_else(|| {
        ForemanError::Transition(
            "terminal receipt requires exact admitted provider execution".to_owned(),
        )
    })?;
    for (field, actual, expected) in [
        (
            "provider_identity",
            Some(receipt.provider_identity.as_str()),
            execution.provider_id.as_str(),
        ),
        (
            "model_identity",
            Some(receipt.model_identity.as_str()),
            execution.model_id.as_str(),
        ),
        (
            "session_identity",
            receipt.session_identity.as_deref(),
            execution.app_server_session_identity.as_str(),
        ),
        (
            "thread_identity",
            receipt.thread_identity.as_deref(),
            execution.thread_id.as_str(),
        ),
        (
            "turn_identity",
            receipt.turn_identity.as_deref(),
            execution.turn_id.as_str(),
        ),
    ] {
        if actual != Some(expected) {
            return Err(ForemanError::IdentityMismatch(field));
        }
    }
    Ok(())
}

fn validate_incremental_identity(
    frozen: Option<&str>,
    observed: Option<&str>,
    field: &'static str,
) -> Result<(), ForemanError> {
    if frozen.is_some() && observed.is_some() && frozen != observed {
        return Err(ForemanError::IdentityMismatch(field));
    }
    Ok(())
}

fn validate_receipt_identity(
    frozen: Option<&str>,
    receipt: Option<&str>,
    field: &'static str,
) -> Result<(), ForemanError> {
    if frozen.is_some() && frozen != receipt {
        return Err(ForemanError::IdentityMismatch(field));
    }
    Ok(())
}

fn latest_terminal_evidence_at(
    transaction: &Transaction<'_>,
    run_id: &str,
) -> Result<DateTime<Utc>, ForemanError> {
    let mut statement = transaction
        .prepare("SELECT receipt_kind, raw_bytes FROM terminal_receipts WHERE run_id = ?1")?;
    let rows = statement.query_map([run_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    let mut latest = None;
    for row in rows {
        let (kind, raw) = row?;
        let observed_at = if kind == "terminal" {
            TerminalReceiptV1::from_slice(&raw)?.ended_at
        } else {
            NotStartedReceiptV1::from_slice(&raw)?.recorded_at
        };
        latest = Some(latest.map_or(observed_at, |current: DateTime<Utc>| {
            current.max(observed_at)
        }));
    }
    latest.ok_or_else(|| ForemanError::IncompleteCloseout("no terminal evidence".to_owned()))
}

fn release_resources(
    transaction: &Transaction<'_>,
    run_id: &str,
    work_item_id: &str,
    attempt_id: &str,
    recorded_at: DateTime<Utc>,
) -> Result<(), ForemanError> {
    transaction.execute(
        "DELETE FROM resource_claims
         WHERE run_id = ?1 AND work_item_id = ?2 AND attempt_id = ?3",
        params![run_id, work_item_id, attempt_id],
    )?;
    append_internal(
        transaction,
        &InternalEvent {
            schema: INTERNAL_EVENT_SCHEMA.to_owned(),
            event_id: format!("resources-released-{}", Uuid::new_v4()),
            run_id: run_id.to_owned(),
            work_item_id: Some(work_item_id.to_owned()),
            attempt_id: Some(attempt_id.to_owned()),
            recorded_at,
            payload: InternalPayload::ResourcesReleased,
        },
    )
}

fn worker_brief_digest(
    connection: &Connection,
    packet: &NightshiftPacketV1,
    profile: &ExecutionProfileV2,
    run_id: &str,
    work_item_id: &str,
) -> Result<String, ForemanError> {
    let canonical = worker_brief_bytes(connection, packet, profile, run_id, work_item_id)?;
    Ok(domain_digest(BRIEF_DIGEST_DOMAIN, &canonical))
}

fn worker_brief_bytes(
    connection: &Connection,
    packet: &NightshiftPacketV1,
    profile: &ExecutionProfileV2,
    run_id: &str,
    work_item_id: &str,
) -> Result<Vec<u8>, ForemanError> {
    let item = packet
        .work_items
        .iter()
        .find(|item| item.id == work_item_id)
        .ok_or_else(|| ForemanError::UnknownWorkItem(work_item_id.to_owned()))?;
    if item.dependencies.len() > MAXIMUM_PREDECESSOR_RECEIPTS {
        return Err(ForemanError::InputTooLarge("predecessor receipt count"));
    }
    let packet_len: i64 = connection.query_row(
        "SELECT length(packet_bytes) FROM runs WHERE run_id = ?1",
        [run_id],
        |row| row.get(0),
    )?;
    let mut retained_lengths = Vec::new();
    let mut preflight_predecessors = BTreeMap::new();
    for dependency in &item.dependencies {
        let (receipt_kind, raw_len): (String, i64) = connection.query_row(
            "SELECT receipt_kind, length(raw_bytes) FROM terminal_receipts \
             WHERE run_id = ?1 AND work_item_id = ?2",
            params![run_id, dependency],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        retained_lengths.push(raw_len);
        preflight_predecessors.insert(
            dependency.clone(),
            serde_json::json!({
                "receipt_kind": receipt_kind,
                "retained_raw_digest": format!("sha256:{}", "0".repeat(64)),
                "encoding": "hex",
                "bytes_hex": "",
            }),
        );
    }
    let preflight_value = serde_json::json!({
        "schema": WORKER_BRIEF_BASIS_SCHEMA_V2,
        "packet_digest": packet.packet_digest,
        "packet_source": {
            "retained_raw_digest": format!("sha256:{}", "0".repeat(64)),
            "encoding": "hex",
            "bytes_hex": "",
        },
        "work_item": {
            "contract": "nightshift.orientation-packet/v1#work-item",
            "canonical_json": serde_jcs::to_string(item)
                .map_err(|error| ForemanError::Serialization(error.to_string()))?,
        },
        "predecessor_receipts": preflight_predecessors,
        "global_constraints": {
            "contract": "nightshift.orientation-packet/v1#global-constraints",
            "canonical_json": serde_jcs::to_string(&packet.global_constraints)
                .map_err(|error| ForemanError::Serialization(error.to_string()))?,
        },
        "execution": {
            "contract": "nightshift.foreman-execution-profile/v2#work-item",
            "canonical_json": serde_jcs::to_string(&profile.work_items[work_item_id])
                .map_err(|error| ForemanError::Serialization(error.to_string()))?,
        },
    });
    let baseline = serde_jcs::to_vec(&preflight_value)
        .map_err(|error| ForemanError::Serialization(error.to_string()))?
        .len();
    let raw_total = retained_lengths
        .into_iter()
        .try_fold(packet_len, |total, length| {
            total
                .checked_add(length)
                .ok_or(ForemanError::InputTooLarge("worker brief"))
        })?;
    let expanded = usize::try_from(raw_total)
        .ok()
        .and_then(|length| length.checked_mul(2))
        .ok_or(ForemanError::InputTooLarge("worker brief"))?;
    if baseline
        .checked_add(expanded)
        .is_none_or(|size| size > MAXIMUM_WORKER_BRIEF_BYTES)
    {
        return Err(ForemanError::InputTooLarge("worker brief"));
    }
    let packet_raw: Vec<u8> = connection.query_row(
        "SELECT packet_bytes FROM runs WHERE run_id = ?1",
        [run_id],
        |row| row.get(0),
    )?;
    let mut predecessors = BTreeMap::new();
    for dependency in &item.dependencies {
        let (receipt_kind, raw): (String, Vec<u8>) = connection.query_row(
            "SELECT receipt_kind, raw_bytes FROM terminal_receipts \
             WHERE run_id = ?1 AND work_item_id = ?2",
            params![run_id, dependency],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        predecessors.insert(
            dependency.clone(),
            serde_json::json!({
                "receipt_kind": receipt_kind,
                "retained_raw_digest": raw_digest(&raw),
                "encoding": "hex",
                "bytes_hex": hex::encode(&raw),
            }),
        );
    }
    let value = serde_json::json!({
        "schema": WORKER_BRIEF_BASIS_SCHEMA_V2,
        "packet_digest": packet.packet_digest,
        "packet_source": {
            "retained_raw_digest": raw_digest(&packet_raw),
            "encoding": "hex",
            "bytes_hex": hex::encode(&packet_raw),
        },
        "work_item": {
            "contract": "nightshift.orientation-packet/v1#work-item",
            "canonical_json": serde_jcs::to_string(item)
                .map_err(|error| ForemanError::Serialization(error.to_string()))?,
        },
        "predecessor_receipts": predecessors,
        "global_constraints": {
            "contract": "nightshift.orientation-packet/v1#global-constraints",
            "canonical_json": serde_jcs::to_string(&packet.global_constraints)
                .map_err(|error| ForemanError::Serialization(error.to_string()))?,
        },
        "execution": {
            "contract": "nightshift.foreman-execution-profile/v2#work-item",
            "canonical_json": serde_jcs::to_string(&profile.work_items[work_item_id])
                .map_err(|error| ForemanError::Serialization(error.to_string()))?,
        },
    });
    let bytes = serde_jcs::to_vec(&value)
        .map_err(|error| ForemanError::Serialization(error.to_string()))?;
    if bytes.len() > MAXIMUM_WORKER_BRIEF_BYTES {
        return Err(ForemanError::InputTooLarge("worker brief"));
    }
    Ok(bytes)
}

fn build_final_document(
    connection: &Connection,
    packet: &NightshiftPacketV1,
    run_id: &str,
    updated_at: DateTime<Utc>,
) -> Result<FinalReceiptDocument, ForemanError> {
    let mut work_items = Vec::new();
    let mut questions = Vec::new();
    let mut custody = Vec::new();
    for item in &packet.work_items {
        let (kind, raw): (String, Vec<u8>) = connection.query_row(
            "SELECT receipt_kind, raw_bytes FROM terminal_receipts
             WHERE run_id = ?1 AND work_item_id = ?2",
            params![run_id, item.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if kind == "terminal" {
            let receipt = TerminalReceiptV1::from_slice(&raw)?;
            for question in &receipt.human_questions {
                questions.push(final_question(&item.id, question));
            }
            for repository in &receipt.repositories {
                custody.push(FinalCustody {
                    repository: repository.repository.clone(),
                    branch_head: format!("{}@{}", repository.branch, repository.head),
                    push_custody: repository.push_status.clone(),
                    dirty: "declared by exact worker receipt; no inference".to_owned(),
                    live_runtime: receipt.teardown.live_runtime.clone(),
                    secrets: receipt.teardown.secrets.clone(),
                    teardown: receipt.teardown.teardown.clone(),
                });
            }
            work_items.push(FinalWorkItem {
                id: item.id.clone(),
                state: receipt.state,
                result_classification: receipt.result_classification,
                repositories: receipt.repositories,
                tests: receipt.tests,
                evidence: receipt.evidence,
                live_or_production_mutations: receipt.live_or_production_mutations,
                remaining_trigger: receipt.remaining_trigger,
                next_lawful_action: receipt.next_lawful_action,
            });
        } else {
            let receipt = NotStartedReceiptV1::from_slice(&raw)?;
            for question in &receipt.human_questions {
                questions.push(final_question(&item.id, question));
            }
            work_items.push(FinalWorkItem {
                id: item.id.clone(),
                state: receipt.state,
                result_classification: receipt.result_classification,
                repositories: Vec::new(),
                tests: Vec::new(),
                evidence: receipt.evidence,
                live_or_production_mutations: Vec::new(),
                remaining_trigger: receipt.remaining_trigger,
                next_lawful_action: receipt.next_lawful_action,
            });
        }
    }
    Ok(FinalReceiptDocument {
        schema: "nightshift.run-receipts/v1".to_owned(),
        packet_digest: packet.packet_digest.clone(),
        updated_at: updated_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        work_items,
        human_questions: questions,
        repository_custody: custody,
    })
}

fn final_question(work_item_id: &str, question: &HumanQuestionV1) -> FinalQuestion {
    FinalQuestion {
        work_item: work_item_id.to_owned(),
        exact_question: question.question.clone(),
        evidence_exhausted: question.exhausted_evidence.clone(),
        safe_default: question.safe_default.clone(),
        consequences: question.consequences.clone(),
        resume_point: question.resume_point.clone(),
    }
}

fn placeholder_digest() -> String {
    format!("sha256:{}", "0".repeat(64))
}

fn raw_digest(bytes: &[u8]) -> String {
    domain_digest(RAW_DIGEST_DOMAIN, bytes)
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    format!("sha256:{:x}", digest.finalize())
}

#[allow(dead_code)]
fn _teardown_contract_is_retained(_: TeardownDeclarationV1) {}

#[cfg(test)]
mod read_only_tests {
    use super::*;

    #[test]
    fn read_only_connection_enforces_query_only() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("query-only.sqlite");
        let writer = Connection::open(&database).unwrap();
        initialize(&writer).unwrap();
        drop(writer);

        let store = ForemanStore::open_read_only(&database).unwrap();
        let connection = store.connection().unwrap();
        let enabled: u8 = connection
            .query_row("PRAGMA query_only", [], |row| row.get(0))
            .unwrap();
        assert_eq!(enabled, 1);
        assert!(connection
            .execute("CREATE TABLE forbidden_read_side_effect (id INTEGER)", [])
            .is_err());
    }
}

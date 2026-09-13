//! Durable, non-authorizing local agent-compute scheduling for one exact packet.
//!
//! This operator-tool crate is outside canonical `nightshiftd`. Scheduler state
//! is mechanism evidence and never a campaign result or target-effect authority.

pub mod bootstrap;
pub mod contract;
pub mod execution_availability;
pub mod prelaunch;
pub mod scheduler;
pub mod store;

pub use bootstrap::*;
pub use contract::*;
pub use execution_availability::*;
pub use prelaunch::*;
pub use scheduler::{LiveRunProjectionV1, LiveWorkItemV1, Scheduler};
pub use store::{
    read_only_run_snapshot, reopen_capacity_journal_event,
    reopen_execution_availability_journal_event, CapacityAdmissionEvidenceV1, ForemanError,
    ForemanStore, OpenedProviderDispatchV1, ProviderDispositionEvidenceV1,
    ReadOnlyCapacityAdmissionV1, ReadOnlyCapacityJournalEventV1, ReadOnlyCapacityRequirementV1,
    ReadOnlyEventRowV1, ReadOnlyExecutionAvailabilityHistoryV1,
    ReadOnlyExecutionAvailabilityJournalEventV1, ReadOnlyProviderResourceTransitionV1,
    ReadOnlyRunSnapshotV1, ReadOnlySelfHostedBootstrapV1, ReadOnlyTerminalReceiptRowV1,
    RunMechanismRequirementsV1, SelfHostedBootstrapInputsV1,
};

pub const FOREMAN_ADMISSION_SCHEMA_V1: &str = "nightshift.foreman-admission/v1";
pub const FOREMAN_CAPACITY_ADMISSION_SCHEMA_V1: &str = "nightshift.foreman-capacity-admission/v1";
pub const FOREMAN_CAPACITY_REQUIREMENT_SCHEMA_V1: &str =
    "nightshift.foreman-capacity-requirement/v1";
pub const FOREMAN_EXECUTION_PROFILE_SCHEMA_V2: &str = "nightshift.foreman-execution-profile/v2";
pub const WORKER_START_REQUEST_SCHEMA_V2: &str = "nightshift.worker-start-request/v2";
pub const WORKER_BRIEF_BASIS_SCHEMA_V2: &str = "nightshift.worker-brief-basis/v2";
pub const MAXIMUM_ADAPTER_TIMEOUT_SECONDS: u64 = 86_400;
pub const MAXIMUM_WORKER_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;
/// Maximum cumulative canonical journal bytes retained for one run's provider-capacity history.
///
/// This is independent of the execution profile's per-event ceiling. It covers only the exact
/// capacity-requirement and capacity-admission journal rows introduced by GAUGE-LATCH; predecessor
/// non-capacity journal rows retain their original admission law.
pub const MAXIMUM_CAPACITY_HISTORY_BYTES: u64 = 16 * 1024 * 1024;
pub const MAXIMUM_PREDECESSOR_RECEIPTS: usize = 1024;
pub const MAXIMUM_WORKER_BRIEF_BYTES: usize = 16 * 1024 * 1024;
pub const WORKER_ADAPTER_CAPABILITIES_SCHEMA_V1: &str = "nightshift.worker-adapter-capabilities/v1";
pub const WORKER_ATTEMPT_BINDING_SCHEMA_V1: &str = "nightshift.worker-attempt-binding/v1";
pub const WORKER_ADAPTER_EVENT_SCHEMA_V1: &str = "nightshift.worker-adapter-event/v1";
pub const WORKER_TERMINAL_RECEIPT_SCHEMA_V1: &str = "nightshift.worker-terminal-receipt/v1";
pub const WORK_ITEM_NOT_STARTED_RECEIPT_SCHEMA_V1: &str =
    "nightshift.work-item-not-started-receipt/v1";
pub const LIVE_RUN_PROJECTION_SCHEMA_V1: &str = "nightshift.foreman-live-run/v1";

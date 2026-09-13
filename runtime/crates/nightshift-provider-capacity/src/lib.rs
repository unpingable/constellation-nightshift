//! Provider-capacity testimony and deterministic scheduling policy.
//!
//! Capacity observation is not provider scheduling authority. Source class,
//! confidence, freshness, and policy disposition remain separate.

mod model;
mod probe;

pub use model::{
    decide_capacity, AdmissionDisposition, CapacityDecisionV1, CapacityError,
    CapacityObservationV1, CapacityPolicyV1, CapacityState, CapacityWindow, Confidence,
    ObservationDisposition, ObservationEvidence, RemainingUnits, SourceClass, WindowType,
    CAPACITY_DECISION_SCHEMA_V1, CAPACITY_OBSERVATION_SCHEMA_V1, CAPACITY_POLICY_SCHEMA_V1,
};
pub use probe::{
    normalize_codex_response, probe_codex_app_server, unknown_observation, CodexProbeOptions,
};

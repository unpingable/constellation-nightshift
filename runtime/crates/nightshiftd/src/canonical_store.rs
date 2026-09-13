//! Transactional store for canonical Nightshift recurrence and observation cycles.
//!
//! This is a temporal/run lifecycle, not an effect campaign FSM. AG remains the
//! sole owner of occurrence governance. The store retains complete evidence and
//! exact external references while deliberately retaining no reconstructible
//! live-currentness token.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use chrono::{DateTime, Utc};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension as _, Transaction, TransactionBehavior,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::authoring_context::{
    ag_proposal_identity, exact_work_identity, AuthoringContextExportV1,
    AuthoringContextProvenanceV1, AuthoringContextQueryV1,
};
use crate::authoring_custody::{
    AuthoringContextCustodyExportV1, AuthoringContextCustodyProvenanceV1, CUSTODY_EXPORT_SCHEMA_V1,
};
use crate::continuity_authority::ContinuityApplicabilityV1;
use crate::currentness::{
    QualifiedSupportV1, RecurrenceLatestAdmissibleV1, SupportStandingV1, TemporalHoldExpiryV1,
};
use crate::diagnostic_posture::{Headline, OperationalPosture};
use crate::external_evidence_composition::{
    ComposedExternalEvidenceV1, ExternalEvidenceReferenceV1, EXTERNAL_EVIDENCE_REFERENCE_SCHEMA_V1,
};
use crate::external_observation::{
    evidence_age, ExternalObservationCustodyProvenanceV1, ExternalObservationExportMatchV1,
    ExternalObservationExportV1, ExternalObservationQueryV1, LocalComposeWorldObservationV1,
    VerifiedExternalObservationHandoffV1, EXTERNAL_OBSERVATION_EXPORT_SCHEMA_V1,
};
use crate::nq_admission::{validate_admission_cover, NqAdmissionProvenance};
use crate::steady_state_evidence::{
    ArtifactQualificationEvidenceV1, ComposedDecisionRelativeEvidenceV1,
    DecisionRelativeEvidenceReferenceV1, LocalComposeSteadyStateObservationV1,
    SteadyStateEvidenceProfileV1, SteadyStateObservationCustodyV1, SteadyStateReobservationBasisV1,
    VerifiedSteadyStateObservationHandoffV1, DECISION_EVIDENCE_REFERENCE_SCHEMA_V1,
};
use crate::substrate_origin::{
    SubstrateOriginApplicabilityStatusV1, SubstrateOriginApplicabilityV1,
};

pub const SLOT_SCHEMA_V1: &str = "nightshift.recurrence_slot.v1";
pub const CYCLE_SCHEMA_V1: &str = "nightshift.observation_cycle.v1";
pub const OBSERVATION_RECORD_SCHEMA_V1: &str = "nightshift.observation_record.v1";
pub const OBSERVATION_RECORD_SCHEMA_V2: &str = "nightshift.observation_record.v2";
pub const OBSERVATION_RECORD_SCHEMA_V3: &str = "nightshift.observation_record.v3";
pub const OBSERVATION_RECORD_SCHEMA_V4: &str = "nightshift.observation_record.v4";
pub const OBSERVATION_RECORD_SCHEMA_V5: &str = "nightshift.observation_record.v5";
pub const OBSERVATION_RECORD_SCHEMA_V6: &str = "nightshift.observation_record.v6";
pub const OBSERVATION_RECORD_SCHEMA: &str = OBSERVATION_RECORD_SCHEMA_V2;
pub const TYPED_INTENT_SCHEMA_V2: &str = "nightshift.typed_coarse_intent.v2";
pub const AG_REFERENCE_SCHEMA_V1: &str = "nightshift.ag_occurrence_reference.v1";
pub const AG_REFUSAL_SCHEMA_V1: &str = "nightshift.ag_refusal_reference.v1";
pub const PREPARED_AG_REQUEST_SCHEMA_V1: &str = "nightshift.prepared_ag_request.v1";

fn require_token(name: &str, value: &str) -> Result<(), CanonicalStoreError> {
    if value.trim().is_empty() || value.chars().any(char::is_whitespace) {
        return Err(CanonicalStoreError::Invalid(format!(
            "{name} must be a non-empty token"
        )));
    }
    Ok(())
}

fn require_digest(name: &str, value: &str) -> Result<(), CanonicalStoreError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(CanonicalStoreError::Invalid(format!(
            "{name} must use sha256:<64 lowercase hex>"
        )));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CanonicalStoreError::Invalid(format!(
            "{name} must use sha256:<64 lowercase hex>"
        )));
    }
    Ok(())
}

fn object_id<T: Serialize>(value: &T, field: &str) -> Result<String, CanonicalStoreError> {
    let mut value = serde_json::to_value(value)?;
    value
        .as_object_mut()
        .ok_or_else(|| CanonicalStoreError::Invalid("identity preimage is not an object".into()))?
        .remove(field);
    let canonical = serde_jcs::to_vec(&value)
        .map_err(|error| CanonicalStoreError::Invalid(error.to_string()))?;
    Ok(format!("sha256:{:x}", Sha256::digest(canonical)))
}

fn canonical_json<T: Serialize>(value: &T) -> Result<String, CanonicalStoreError> {
    String::from_utf8(
        serde_jcs::to_vec(value)
            .map_err(|error| CanonicalStoreError::Invalid(error.to_string()))?,
    )
    .map_err(|error| CanonicalStoreError::Invalid(error.to_string()))
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
}

#[derive(Debug, thiserror::Error)]
pub enum CanonicalStoreError {
    #[error("canonical store SQL error: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("canonical store JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid canonical record: {0}")]
    Invalid(String),
    #[error("recurrence slot already has an authoritative attempt: {0}")]
    DuplicateSlot(String),
    #[error("AG campaign/occurrence is already bound to another observation cycle: {0}/{1}")]
    DuplicateAgOccurrence(String, String),
    #[error("recurrence slot is not due: {0}")]
    NotDue(String),
    #[error("recurrence slot is outside its latest-admissible instant: {0}")]
    Missed(String),
    #[error("observation cycle not found: {0}")]
    CycleNotFound(String),
    #[error("stale predecessor digest")]
    StalePredecessor,
    #[error("illegal observation-cycle transition: {0}")]
    IllegalTransition(String),
    #[error("live cycle lease does not bind this cycle")]
    WrongLiveLease,
    #[error("deterministic replay failed: {0}")]
    Replay(String),
    #[error("external observation conflicts with canonical custody: {0}")]
    ExternalObservationConflict(String),
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ObservationCycleId(String);

impl ObservationCycleId {
    pub fn fresh() -> Self {
        Self(format!("cycle:{}", Uuid::new_v4()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn parse(value: String) -> Result<Self, CanonicalStoreError> {
        require_token("observation_cycle_id", &value)?;
        let Some(uuid) = value.strip_prefix("cycle:") else {
            return Err(CanonicalStoreError::Invalid(
                "observation_cycle_id must use the cycle:<uuid> namespace".into(),
            ));
        };
        uuid::Uuid::parse_str(uuid).map_err(|_| {
            CanonicalStoreError::Invalid("observation_cycle_id contains an invalid UUID".into())
        })?;
        Ok(Self(value))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RecurrenceSlotId(String);

impl RecurrenceSlotId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecurrenceTriggerV1 {
    Scheduled,
    Manual,
    Event,
    CatchUp,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotTimingV1 {
    OnTime,
    Late,
    CatchUp,
    Missed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecurrenceSlotV1 {
    pub schema: String,
    pub slot_id: RecurrenceSlotId,
    pub policy_id: String,
    pub configuration_version: String,
    pub subject_id: String,
    pub scope_id: String,
    pub scheduler_clock_id: String,
    pub nominal_due_at: DateTime<Utc>,
    pub latest_admissible: RecurrenceLatestAdmissibleV1,
    pub occurrence: u64,
    pub trigger: RecurrenceTriggerV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catch_up_of: Option<RecurrenceSlotId>,
}

impl RecurrenceSlotV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy_id: String,
        configuration_version: String,
        subject_id: String,
        scope_id: String,
        scheduler_clock_id: String,
        nominal_due_at: DateTime<Utc>,
        latest_admissible: DateTime<Utc>,
        occurrence: u64,
        trigger: RecurrenceTriggerV1,
        catch_up_of: Option<RecurrenceSlotId>,
    ) -> Result<Self, CanonicalStoreError> {
        let mut value = Self {
            schema: SLOT_SCHEMA_V1.into(),
            slot_id: RecurrenceSlotId(String::new()),
            policy_id,
            configuration_version,
            subject_id,
            scope_id,
            scheduler_clock_id: scheduler_clock_id.clone(),
            nominal_due_at,
            latest_admissible: RecurrenceLatestAdmissibleV1 {
                scheduler_clock_id,
                at: latest_admissible,
            },
            occurrence,
            trigger,
            catch_up_of,
        };
        value.slot_id = RecurrenceSlotId(object_id(&value, "slot_id")?);
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), CanonicalStoreError> {
        if self.schema != SLOT_SCHEMA_V1 {
            return Err(CanonicalStoreError::Invalid(format!(
                "unsupported recurrence slot schema {}",
                self.schema
            )));
        }
        require_digest("slot_id", self.slot_id.as_str())?;
        for (name, value) in [
            ("policy_id", &self.policy_id),
            ("configuration_version", &self.configuration_version),
            ("subject_id", &self.subject_id),
            ("scope_id", &self.scope_id),
            ("scheduler_clock_id", &self.scheduler_clock_id),
        ] {
            require_token(name, value)?;
        }
        if self.latest_admissible.scheduler_clock_id != self.scheduler_clock_id {
            return Err(CanonicalStoreError::Invalid(
                "slot due/latest instants use different scheduler clocks".into(),
            ));
        }
        if self.latest_admissible.at < self.nominal_due_at {
            return Err(CanonicalStoreError::Invalid(
                "latest-admissible instant precedes nominal due instant".into(),
            ));
        }
        if matches!(self.trigger, RecurrenceTriggerV1::CatchUp) != self.catch_up_of.is_some() {
            return Err(CanonicalStoreError::Invalid(
                "catch-up trigger and catch_up_of linkage must appear together".into(),
            ));
        }
        if self.slot_id.0 != object_id(self, "slot_id")? {
            return Err(CanonicalStoreError::Invalid(
                "slot_id does not match exact recurrence-slot basis".into(),
            ));
        }
        Ok(())
    }

    pub fn timing_at(
        &self,
        scheduler_clock_id: &str,
        now: DateTime<Utc>,
    ) -> Result<SlotTimingV1, CanonicalStoreError> {
        self.validate()?;
        if scheduler_clock_id != self.scheduler_clock_id {
            return Err(CanonicalStoreError::Invalid(
                "runtime scheduler clock does not match slot clock".into(),
            ));
        }
        if now < self.nominal_due_at {
            return Err(CanonicalStoreError::NotDue(self.slot_id.0.clone()));
        }
        if !self
            .latest_admissible
            .admits(scheduler_clock_id, now)
            .map_err(CanonicalStoreError::Invalid)?
        {
            return Ok(SlotTimingV1::Missed);
        }
        if self.trigger == RecurrenceTriggerV1::CatchUp {
            Ok(SlotTimingV1::CatchUp)
        } else if now == self.nominal_due_at {
            Ok(SlotTimingV1::OnTime)
        } else {
            Ok(SlotTimingV1::Late)
        }
    }
}

/// Deliberately non-serializable process-local witness returned by the unique
/// slot claim. A restart cannot reconstruct it from database representation.
#[derive(Debug)]
pub struct LiveCycleLeaseV1 {
    cycle_id: ObservationCycleId,
    slot_id: RecurrenceSlotId,
    process_nonce: Uuid,
}

impl LiveCycleLeaseV1 {
    pub fn cycle_id(&self) -> &ObservationCycleId {
        &self.cycle_id
    }

    pub fn slot_id(&self) -> &RecurrenceSlotId {
        &self.slot_id
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CycleStatusV1 {
    Observing,
    PostureRecorded,
    AwaitingAg,
    AwaitingAgReconciliation,
    ObservationRequired,
    Halted,
    Closed,
    Missed,
    RecoveryRequired,
}

impl CycleStatusV1 {
    fn as_db(self) -> &'static str {
        match self {
            Self::Observing => "observing",
            Self::PostureRecorded => "posture_recorded",
            Self::AwaitingAg => "awaiting_ag",
            Self::AwaitingAgReconciliation => "awaiting_ag_reconciliation",
            Self::ObservationRequired => "observation_required",
            Self::Halted => "halted",
            Self::Closed => "closed",
            Self::Missed => "missed",
            Self::RecoveryRequired => "recovery_required",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationRecordV1 {
    pub schema: String,
    pub observation_id: String,
    /// Exact upstream NQ-NG admission provenance for every delivered
    /// diagnostic. This establishes evidence eligibility only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_admissions: Vec<NqAdmissionProvenance>,
    /// Nightshift's exact verification result for every continuity-bearing NQ
    /// source admission. V5 only. These are attribution predicates, not
    /// currentness or authority.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub continuity_applicability: Vec<ContinuityApplicabilityV1>,
    /// Exact append-only origin-chain verdicts for V3 NQ admissions. V6 only.
    /// These establish attribution applicability, not evidence truth,
    /// currentness, standing, or authority.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub substrate_origin_applicability: Vec<SubstrateOriginApplicabilityV1>,
    /// Optional Nightshift-owned admission of authenticated application/world
    /// evidence. V3 alone may carry this relation. It constrains the
    /// observation's freshness horizon but is neither NQ testimony nor
    /// authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_evidence: Option<ComposedExternalEvidenceV1>,
    /// Decision-relative combination of historical exact-artifact
    /// qualification and a separately current passive observation. V4 only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_external_evidence: Option<ComposedDecisionRelativeEvidenceV1>,
    pub support: QualifiedSupportV1,
    pub posture: OperationalPosture,
}

impl ObservationRecordV1 {
    pub fn validate_for_cycle(
        &self,
        cycle: &ObservationCycleId,
    ) -> Result<(), CanonicalStoreError> {
        match self.schema.as_str() {
            OBSERVATION_RECORD_SCHEMA_V1
                if self.source_admissions.is_empty()
                    && self.continuity_applicability.is_empty()
                    && self.substrate_origin_applicability.is_empty()
                    && self.external_evidence.is_none()
                    && self.decision_external_evidence.is_none() => {}
            OBSERVATION_RECORD_SCHEMA_V1 => {
                return Err(CanonicalStoreError::Invalid(
                    "v1 observation record cannot carry NQ admission provenance".into(),
                ));
            }
            OBSERVATION_RECORD_SCHEMA_V2
                if self.continuity_applicability.is_empty()
                    && self.substrate_origin_applicability.is_empty()
                    && self.external_evidence.is_none()
                    && self.decision_external_evidence.is_none() =>
            {
                validate_admission_cover(
                    &self.posture.input_evidence,
                    &self.source_admissions,
                    &self.continuity_applicability,
                    &self.substrate_origin_applicability,
                )
                .map_err(CanonicalStoreError::Invalid)?
            }
            OBSERVATION_RECORD_SCHEMA_V2 => {
                return Err(CanonicalStoreError::Invalid(
                    "v2 observation record cannot carry composed external evidence".into(),
                ));
            }
            OBSERVATION_RECORD_SCHEMA_V3 => {
                if !self.continuity_applicability.is_empty()
                    || !self.substrate_origin_applicability.is_empty()
                    || self.decision_external_evidence.is_some()
                {
                    return Err(CanonicalStoreError::Invalid(
                        "v3 observation record cannot carry decision-relative evidence".into(),
                    ));
                }
                validate_admission_cover(
                    &self.posture.input_evidence,
                    &self.source_admissions,
                    &self.continuity_applicability,
                    &self.substrate_origin_applicability,
                )
                .map_err(CanonicalStoreError::Invalid)?;
                let composition = self.external_evidence.as_ref().ok_or_else(|| {
                    CanonicalStoreError::Invalid(
                        "v3 observation record requires composed external evidence".into(),
                    )
                })?;
                composition
                    .validate()
                    .map_err(CanonicalStoreError::Invalid)?;
                if composition
                    .canonical_observation_id()
                    .map_err(CanonicalStoreError::Invalid)?
                    != self.observation_id
                    || composition.subject_id != self.posture.policy.subject.id
                    || composition.scope_digest != self.posture.policy.subject.scope.digest
                    || composition
                        .admitted_at
                        .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
                        != self.posture.evaluated_at
                {
                    return Err(CanonicalStoreError::Invalid(
                        "composed external evidence does not bind the canonical observation".into(),
                    ));
                }
            }
            OBSERVATION_RECORD_SCHEMA_V4 => {
                if !self.continuity_applicability.is_empty()
                    || !self.substrate_origin_applicability.is_empty()
                    || self.external_evidence.is_some()
                {
                    return Err(CanonicalStoreError::Invalid(
                        "v4 observation record cannot carry legacy single-source evidence".into(),
                    ));
                }
                validate_admission_cover(
                    &self.posture.input_evidence,
                    &self.source_admissions,
                    &self.continuity_applicability,
                    &self.substrate_origin_applicability,
                )
                .map_err(CanonicalStoreError::Invalid)?;
                let composition = self.decision_external_evidence.as_ref().ok_or_else(|| {
                    CanonicalStoreError::Invalid(
                        "v4 observation record requires decision-relative evidence".into(),
                    )
                })?;
                composition
                    .validate()
                    .map_err(CanonicalStoreError::Invalid)?;
                if composition
                    .canonical_observation_id()
                    .map_err(CanonicalStoreError::Invalid)?
                    != self.observation_id
                    || composition.subject_id != self.posture.policy.subject.id
                    || composition.scope_digest != self.posture.policy.subject.scope.digest
                    || composition
                        .admitted_at
                        .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
                        != self.posture.evaluated_at
                {
                    return Err(CanonicalStoreError::Invalid(
                        "decision-relative evidence does not bind canonical observation".into(),
                    ));
                }
            }
            OBSERVATION_RECORD_SCHEMA_V5 => {
                if self.continuity_applicability.is_empty() {
                    return Err(CanonicalStoreError::Invalid(
                        "v5 observation record requires continuity applicability".into(),
                    ));
                }
                if !self.substrate_origin_applicability.is_empty() {
                    return Err(CanonicalStoreError::Invalid(
                        "v5 observation record cannot carry substrate-origin applicability".into(),
                    ));
                }
                validate_admission_cover(
                    &self.posture.input_evidence,
                    &self.source_admissions,
                    &self.continuity_applicability,
                    &self.substrate_origin_applicability,
                )
                .map_err(CanonicalStoreError::Invalid)?;
                match (&self.external_evidence, &self.decision_external_evidence) {
                    (None, None) => {}
                    (Some(composition), None) => {
                        composition
                            .validate()
                            .map_err(CanonicalStoreError::Invalid)?;
                        if composition
                            .canonical_observation_id()
                            .map_err(CanonicalStoreError::Invalid)?
                            != self.observation_id
                            || composition.subject_id != self.posture.policy.subject.id
                            || composition.scope_digest != self.posture.policy.subject.scope.digest
                            || composition
                                .admitted_at
                                .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
                                != self.posture.evaluated_at
                        {
                            return Err(CanonicalStoreError::Invalid(
                                "composed external evidence does not bind the canonical observation"
                                    .into(),
                            ));
                        }
                    }
                    (None, Some(composition)) => {
                        composition
                            .validate()
                            .map_err(CanonicalStoreError::Invalid)?;
                        if composition
                            .canonical_observation_id()
                            .map_err(CanonicalStoreError::Invalid)?
                            != self.observation_id
                            || composition.subject_id != self.posture.policy.subject.id
                            || composition.scope_digest != self.posture.policy.subject.scope.digest
                            || composition
                                .admitted_at
                                .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
                                != self.posture.evaluated_at
                        {
                            return Err(CanonicalStoreError::Invalid(
                                "decision-relative evidence does not bind the canonical observation"
                                    .into(),
                            ));
                        }
                    }
                    (Some(_), Some(_)) => {
                        return Err(CanonicalStoreError::Invalid(
                            "v5 observation cannot combine legacy and decision-relative evidence"
                                .into(),
                        ));
                    }
                }
            }
            OBSERVATION_RECORD_SCHEMA_V6 => {
                if self.substrate_origin_applicability.is_empty() {
                    return Err(CanonicalStoreError::Invalid(
                        "v6 observation record requires substrate-origin applicability".into(),
                    ));
                }
                validate_admission_cover(
                    &self.posture.input_evidence,
                    &self.source_admissions,
                    &self.continuity_applicability,
                    &self.substrate_origin_applicability,
                )
                .map_err(CanonicalStoreError::Invalid)?;
                if self
                    .substrate_origin_applicability
                    .iter()
                    .any(|value| value.status != SubstrateOriginApplicabilityStatusV1::Applicable)
                {
                    return Err(CanonicalStoreError::Invalid(
                        "v6 observation record cannot persist a relied-on non-applicable origin"
                            .into(),
                    ));
                }
                match (&self.external_evidence, &self.decision_external_evidence) {
                    (None, None) => {}
                    (Some(composition), None) => {
                        composition
                            .validate()
                            .map_err(CanonicalStoreError::Invalid)?;
                        if composition
                            .canonical_observation_id()
                            .map_err(CanonicalStoreError::Invalid)?
                            != self.observation_id
                            || composition.subject_id != self.posture.policy.subject.id
                            || composition.scope_digest != self.posture.policy.subject.scope.digest
                            || composition
                                .admitted_at
                                .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
                                != self.posture.evaluated_at
                        {
                            return Err(CanonicalStoreError::Invalid(
                                "composed external evidence does not bind the canonical observation"
                                    .into(),
                            ));
                        }
                    }
                    (None, Some(composition)) => {
                        composition
                            .validate()
                            .map_err(CanonicalStoreError::Invalid)?;
                        if composition
                            .canonical_observation_id()
                            .map_err(CanonicalStoreError::Invalid)?
                            != self.observation_id
                            || composition.subject_id != self.posture.policy.subject.id
                            || composition.scope_digest != self.posture.policy.subject.scope.digest
                            || composition
                                .admitted_at
                                .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
                                != self.posture.evaluated_at
                        {
                            return Err(CanonicalStoreError::Invalid(
                                "decision-relative evidence does not bind canonical observation"
                                    .into(),
                            ));
                        }
                    }
                    (Some(_), Some(_)) => {
                        return Err(CanonicalStoreError::Invalid(
                            "v6 observation cannot combine legacy and decision-relative evidence"
                                .into(),
                        ));
                    }
                }
            }
            _ => {
                return Err(CanonicalStoreError::Invalid(
                    "unsupported observation record schema".into(),
                ));
            }
        }
        require_digest("observation_id", &self.observation_id)?;
        self.support
            .validate_shape()
            .map_err(CanonicalStoreError::Invalid)?;
        if self.support.observation_cycle_id != cycle.as_str()
            || self.support.observation_id != self.observation_id
            || self.support.diagnostic_inputs_id != self.posture.input_evidence.inputs_id
            || self.posture.present_support.as_ref() != Some(&self.support)
        {
            return Err(CanonicalStoreError::Invalid(
                "observation/support/posture basis is not exact".into(),
            ));
        }
        if self.posture.current
            != (self.support.standing == SupportStandingV1::Current
                && self.posture.completeness
                    == crate::diagnostic_posture::CompletenessAxis::Complete
                && self.posture.coverage == crate::diagnostic_posture::CoverageAxis::Complete
                && self.posture.recurrence_axis
                    == crate::diagnostic_posture::RecurrenceAxis::Current)
        {
            return Err(CanonicalStoreError::Invalid(
                "posture currentness does not correspond to exact support and retained axes".into(),
            ));
        }
        Ok(())
    }
}

/// Observation lineage/domain identity, derived only from persisted canonical
/// slot data. Per-occurrence fields (`nominal_due_at`, `latest_admissible`,
/// `occurrence`, `trigger`, `catch_up_of`, `slot_id`) identify individual
/// slots; they are deliberately not part of the family.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationFamilyKeyV1 {
    pub policy_id: String,
    pub configuration_version: String,
    pub subject_id: String,
    pub scope_id: String,
    pub scheduler_clock_id: String,
}

impl ObservationFamilyKeyV1 {
    pub fn of_slot(slot: &RecurrenceSlotV1) -> Self {
        Self {
            policy_id: slot.policy_id.clone(),
            configuration_version: slot.configuration_version.clone(),
            subject_id: slot.subject_id.clone(),
            scope_id: slot.scope_id.clone(),
            scheduler_clock_id: slot.scheduler_clock_id.clone(),
        }
    }
}

/// Logical observation order within one family. This is the supersession
/// order substrate: lexicographic over slot occurrence, the slot's declared
/// nominal due instant, then exact slot identity. It never uses `updated_at`,
/// completion order, caller-supplied `evaluated_at`, or process time.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationOrderKeyV1 {
    pub occurrence: u64,
    pub nominal_due_at: DateTime<Utc>,
    pub slot_id: String,
}

impl ObservationOrderKeyV1 {
    pub fn of_slot(slot: &RecurrenceSlotV1) -> Self {
        Self {
            occurrence: slot.occurrence,
            nominal_due_at: slot.nominal_due_at,
            slot_id: slot.slot_id.as_str().to_owned(),
        }
    }
}

pub const OBSERVATION_EXPORT_SCHEMA_V1: &str = "nightshift.observation_export.v1";

/// One persisted cycle carrying the requested observation identity, with its
/// derived lineage position. Multiple matches are reported, never collapsed.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationExportMatchV1 {
    pub cycle_id: String,
    pub slot_id: String,
    pub family: ObservationFamilyKeyV1,
    pub order_key: ObservationOrderKeyV1,
    pub family_latest_cycle_id: Option<String>,
    pub family_latest_order_key: Option<ObservationOrderKeyV1>,
    pub observation: ObservationRecordV1,
}

/// Read-only export of every persisted observation with one exact
/// `observation_id`. Zero, one, or several matches are all faithful results;
/// ambiguity is preserved for the caller to classify.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationExportV1 {
    pub schema: String,
    pub observation_id: String,
    pub matches: Vec<ObservationExportMatchV1>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttentionClassV1 {
    Display,
    AttentionRequired,
    EscalationRequested,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionRecordV1 {
    pub class: AttentionClassV1,
    pub source_posture_id: String,
    pub reason_code: String,
    /// Presentation only. It is excluded from every proposal/authority type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_text: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TemporalDecisionV1 {
    Observe,
    Hold,
    Attention,
}

/// Durable non-authorizing Nightshift temporal/tolerability posture.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalPostureV1 {
    pub policy_id: String,
    pub basis_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold_expiry: Option<TemporalHoldExpiryV1>,
    pub evaluated_at: DateTime<Utc>,
    pub decision: TemporalDecisionV1,
}

impl TemporalPostureV1 {
    pub fn evaluate(
        policy_id: String,
        basis_digest: String,
        hold_expiry: Option<TemporalHoldExpiryV1>,
        scheduler_clock_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Self, CanonicalStoreError> {
        require_token("temporal policy_id", &policy_id)?;
        require_digest("temporal basis_digest", &basis_digest)?;
        let decision = match &hold_expiry {
            Some(expiry)
                if expiry
                    .is_active(scheduler_clock_id, now)
                    .map_err(CanonicalStoreError::Invalid)? =>
            {
                TemporalDecisionV1::Hold
            }
            Some(_) => TemporalDecisionV1::Attention,
            None => TemporalDecisionV1::Observe,
        };
        Ok(Self {
            policy_id,
            basis_digest,
            hold_expiry,
            evaluated_at: now,
            decision,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TypedCoarseIntentV2 {
    pub schema: String,
    pub intent_id: String,
    pub workflow_id: String,
    pub intent_kind: String,
    pub subject_id: String,
    /// Workflow-supplied exact AG subject digest. This is never inferred by
    /// hashing the display subject identifier.
    pub subject_digest: String,
    pub scope_id: String,
    pub source_observation_id: String,
    pub source_support_id: String,
    pub source_posture_id: String,
    pub immutable_parameters: serde_json::Value,
    /// Nightshift-domain identity of the immutable compiled payload
    /// (`sha256(JCS({parameters, schema}))`). Provenance only; it is not the
    /// AG executable-work identity.
    pub compiled_work: String,
    /// The AG/Docket-domain executable-work identity deterministically
    /// derived from the exact sealed executor plan at proposal-compilation
    /// time. AG's `record_proposal` requires the submitted proposal's work to
    /// equal this identity.
    pub expected_ag_work: String,
}

impl TypedCoarseIntentV2 {
    pub fn seal(mut self) -> Result<Self, CanonicalStoreError> {
        self.schema = TYPED_INTENT_SCHEMA_V2.into();
        self.intent_id.clear();
        self.intent_id = object_id(&self, "intent_id")?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), CanonicalStoreError> {
        if self.schema != TYPED_INTENT_SCHEMA_V2 {
            return Err(CanonicalStoreError::Invalid(
                "unsupported typed intent schema".into(),
            ));
        }
        require_digest("intent_id", &self.intent_id)?;
        require_digest("compiled_work", &self.compiled_work)?;
        require_digest("expected_ag_work", &self.expected_ag_work)?;
        for (name, value) in [
            ("workflow_id", &self.workflow_id),
            ("intent_kind", &self.intent_kind),
            ("subject_id", &self.subject_id),
            ("source_observation_id", &self.source_observation_id),
            ("source_support_id", &self.source_support_id),
            ("source_posture_id", &self.source_posture_id),
        ] {
            require_token(name, value)?;
        }
        require_digest("subject_digest", &self.subject_digest)?;
        require_digest("scope_id", &self.scope_id)?;
        if !self.immutable_parameters.is_object() {
            return Err(CanonicalStoreError::Invalid(
                "immutable_parameters must be a typed JSON object, never prose".into(),
            ));
        }
        if self.intent_id != object_id(self, "intent_id")? {
            return Err(CanonicalStoreError::Invalid(
                "intent_id does not match typed intent preimage".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_for_observation(
        &self,
        observation: &ObservationRecordV1,
    ) -> Result<(), CanonicalStoreError> {
        self.validate()?;
        if self.subject_id != observation.posture.policy.subject.id
            || self.scope_id != observation.posture.policy.subject.scope.digest
            || self.source_observation_id != observation.observation_id
            || self.source_support_id != observation.support.support_id
            || self.source_posture_id != observation.posture.posture_id
        {
            return Err(CanonicalStoreError::Invalid(
                "typed intent does not exactly bind the complete live posture basis".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgProgramCounterV1 {
    ObservationRequired,
    ProposalRecorded,
    StandingRequired,
    AdmissiblePendingAuthorization,
    AuthorizationConsumed,
    Dispatched,
    ReconciliationRequired,
    SettledObservationRequired,
    Halted,
    Completed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgOccurrenceReferenceV1 {
    pub schema: String,
    pub campaign_id: String,
    pub occurrence_id: String,
    pub state_digest: String,
    pub snapshot_digest: String,
    pub program_counter: AgProgramCounterV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docket_attempt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_decision_request_id: Option<String>,
    pub exact_snapshot: serde_json::Value,
}

/// Exact durable AG refusal evidence. It is not an AG program-counter state
/// and grants no Nightshift or AG authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgRefusalReferenceV1 {
    pub schema: String,
    pub refusal_digest: String,
    pub campaign_id: String,
    pub occurrence_id: String,
    pub at_state_digest: String,
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    pub exact_outcome: serde_json::Value,
}

impl AgRefusalReferenceV1 {
    pub fn validate(&self) -> Result<(), CanonicalStoreError> {
        if self.schema != AG_REFUSAL_SCHEMA_V1 {
            return Err(CanonicalStoreError::Invalid(
                "unsupported AG refusal reference schema".into(),
            ));
        }
        require_digest("refusal_digest", &self.refusal_digest)?;
        require_digest("campaign_id", &self.campaign_id)?;
        require_token("occurrence_id", &self.occurrence_id)?;
        require_digest("at_state_digest", &self.at_state_digest)?;
        require_token("refusal code", &self.code)?;
        if let Some(evidence) = &self.evidence {
            require_digest("refusal evidence", evidence)?;
        }
        if !self.exact_outcome.is_object() {
            return Err(CanonicalStoreError::Invalid(
                "AG refusal exact outcome must be an object".into(),
            ));
        }
        let digest = format!(
            "sha256:{:x}",
            Sha256::digest(
                serde_jcs::to_vec(&self.exact_outcome)
                    .map_err(|error| CanonicalStoreError::Invalid(error.to_string()))?
            )
        );
        if digest != self.refusal_digest {
            return Err(CanonicalStoreError::Invalid(
                "AG refusal digest does not bind the exact outcome".into(),
            ));
        }
        Ok(())
    }
}

/// Exact, non-authorizing request made durable before calling AG. Its bytes
/// are retained for identity and audit after a crash, but Nightshift never
/// treats them as permission to resubmit, spend AG authorization, or call
/// Docket.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedAgRequestV1 {
    pub schema: String,
    pub request_digest: String,
    pub campaign_id: String,
    pub occurrence_id: String,
    pub source_intent_id: String,
    pub exact_request: serde_json::Value,
}

/// Optional inert authoring lineage and its separately authenticated custody
/// evidence, committed atomically with the prepared AG request.
pub(crate) struct PreparedAuthoringEvidenceV1 {
    pub(crate) lineage: Option<AuthoringContextProvenanceV1>,
    pub(crate) custody: Option<AuthoringContextCustodyProvenanceV1>,
}

impl PreparedAgRequestV1 {
    pub fn validate(&self) -> Result<(), CanonicalStoreError> {
        if self.schema != PREPARED_AG_REQUEST_SCHEMA_V1 {
            return Err(CanonicalStoreError::Invalid(
                "unsupported prepared AG request schema".into(),
            ));
        }
        require_digest("request_digest", &self.request_digest)?;
        require_digest("campaign_id", &self.campaign_id)?;
        require_digest("source_intent_id", &self.source_intent_id)?;
        uuid::Uuid::parse_str(&self.occurrence_id).map_err(|_| {
            CanonicalStoreError::Invalid(
                "prepared AG occurrence_id must be an independently allocated UUID".into(),
            )
        })?;
        if !self.exact_request.is_object() {
            return Err(CanonicalStoreError::Invalid(
                "prepared AG request must retain an exact object".into(),
            ));
        }
        let expected = format!(
            "sha256:{:x}",
            Sha256::digest(
                serde_jcs::to_vec(&self.exact_request)
                    .map_err(|error| CanonicalStoreError::Invalid(error.to_string()))?
            )
        );
        if self.request_digest != expected {
            return Err(CanonicalStoreError::Invalid(
                "prepared AG request digest mismatch".into(),
            ));
        }
        Ok(())
    }
}

impl AgOccurrenceReferenceV1 {
    pub fn validate(&self) -> Result<(), CanonicalStoreError> {
        if self.schema != AG_REFERENCE_SCHEMA_V1 {
            return Err(CanonicalStoreError::Invalid(
                "unsupported AG occurrence reference schema".into(),
            ));
        }
        require_digest("campaign_id", &self.campaign_id)?;
        require_digest("state_digest", &self.state_digest)?;
        require_digest("snapshot_digest", &self.snapshot_digest)?;
        uuid::Uuid::parse_str(&self.occurrence_id).map_err(|_| {
            CanonicalStoreError::Invalid(
                "AG occurrence_id must be an independently allocated UUID".into(),
            )
        })?;
        for (name, value) in [
            ("docket_attempt_id", &self.docket_attempt_id),
            ("settlement_id", &self.settlement_id),
            (
                "external_decision_request_id",
                &self.external_decision_request_id,
            ),
        ] {
            if let Some(value) = value {
                require_token(name, value)?;
            }
        }
        if !self.exact_snapshot.is_object() {
            return Err(CanonicalStoreError::Invalid(
                "AG exact snapshot must be an object".into(),
            ));
        }
        let digest = format!(
            "sha256:{:x}",
            Sha256::digest(
                serde_jcs::to_vec(&self.exact_snapshot)
                    .map_err(|error| CanonicalStoreError::Invalid(error.to_string()))?
            )
        );
        if digest != self.snapshot_digest {
            return Err(CanonicalStoreError::Invalid(
                "AG snapshot digest does not match exact snapshot".into(),
            ));
        }
        Ok(())
    }
}

fn ag_status_can_follow(prior: AgProgramCounterV1, next: AgProgramCounterV1) -> bool {
    use AgProgramCounterV1 as Pc;
    if prior == next {
        return true;
    }
    match prior {
        Pc::ObservationRequired => !matches!(next, Pc::ObservationRequired),
        Pc::ProposalRecorded => !matches!(next, Pc::ObservationRequired | Pc::ProposalRecorded),
        Pc::StandingRequired => !matches!(
            next,
            Pc::ObservationRequired | Pc::ProposalRecorded | Pc::StandingRequired
        ),
        Pc::AdmissiblePendingAuthorization => matches!(
            next,
            Pc::AuthorizationConsumed
                | Pc::Dispatched
                | Pc::ReconciliationRequired
                | Pc::SettledObservationRequired
                | Pc::Halted
                | Pc::Completed
        ),
        Pc::AuthorizationConsumed => matches!(
            next,
            Pc::Dispatched
                | Pc::ReconciliationRequired
                | Pc::SettledObservationRequired
                | Pc::Halted
                | Pc::Completed
        ),
        Pc::Dispatched => matches!(
            next,
            Pc::ReconciliationRequired
                | Pc::SettledObservationRequired
                | Pc::Halted
                | Pc::Completed
        ),
        Pc::ReconciliationRequired => matches!(
            next,
            Pc::SettledObservationRequired | Pc::Halted | Pc::Completed
        ),
        Pc::SettledObservationRequired => matches!(next, Pc::Halted | Pc::Completed),
        Pc::Halted => matches!(next, Pc::Completed),
        Pc::Completed => false,
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationCycleV1 {
    pub schema: String,
    pub cycle_id: ObservationCycleId,
    pub slot: RecurrenceSlotV1,
    pub timing: SlotTimingV1,
    pub status: CycleStatusV1,
    pub version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_state_digest: Option<String>,
    pub state_digest: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation: Option<ObservationRecordV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attention: Option<AttentionRecordV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temporal_posture: Option<TemporalPostureV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<TypedCoarseIntentV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepared_ag_request: Option<PreparedAgRequestV1>,
    /// Immutable plan/session lineage minted at exact proposal preparation.
    /// It is retained as evidence only and is absent from AG authority inputs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authoring_context_provenance: Option<AuthoringContextProvenanceV1>,
    /// Authenticated delivery evidence for newly linked Maude contexts.
    /// Historical lineage predating custody remains valid with this absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authoring_context_custody: Option<AuthoringContextCustodyProvenanceV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ag: Option<AgOccurrenceReferenceV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ag_refusal: Option<AgRefusalReferenceV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_reason: Option<String>,
}

impl ObservationCycleV1 {
    fn seal(&mut self) -> Result<(), CanonicalStoreError> {
        self.state_digest.clear();
        self.state_digest = object_id(self, "state_digest")?;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), CanonicalStoreError> {
        if self.schema != CYCLE_SCHEMA_V1 {
            return Err(CanonicalStoreError::Invalid(
                "unsupported observation-cycle schema".into(),
            ));
        }
        require_token("cycle_id", self.cycle_id.as_str())?;
        self.slot.validate()?;
        require_digest("state_digest", &self.state_digest)?;
        if let Some(prior) = &self.prior_state_digest {
            require_digest("prior_state_digest", prior)?;
        }
        if let Some(observation) = &self.observation {
            observation.validate_for_cycle(&self.cycle_id)?;
        }
        if let Some(intent) = &self.intent {
            let observation = self.observation.as_ref().ok_or_else(|| {
                CanonicalStoreError::Invalid("intent exists without observation basis".into())
            })?;
            intent.validate_for_observation(observation)?;
        }
        if let Some(temporal) = &self.temporal_posture {
            require_token("temporal policy_id", &temporal.policy_id)?;
            require_digest("temporal basis_digest", &temporal.basis_digest)?;
            let expected = match &temporal.hold_expiry {
                Some(expiry)
                    if expiry
                        .is_active(&expiry.scheduler_clock_id, temporal.evaluated_at)
                        .map_err(CanonicalStoreError::Invalid)? =>
                {
                    TemporalDecisionV1::Hold
                }
                Some(_) => TemporalDecisionV1::Attention,
                None => TemporalDecisionV1::Observe,
            };
            if temporal.decision != expected {
                return Err(CanonicalStoreError::Invalid(
                    "temporal posture does not match its distinct hold-expiry law".into(),
                ));
            }
        }
        if let Some(ag) = &self.ag {
            ag.validate()?;
            if self.intent.is_none() {
                return Err(CanonicalStoreError::Invalid(
                    "AG occurrence exists without an exact typed intent".into(),
                ));
            }
        }
        if let Some(refusal) = &self.ag_refusal {
            refusal.validate()?;
            let request = self.prepared_ag_request.as_ref().ok_or_else(|| {
                CanonicalStoreError::Invalid("AG refusal exists without prepared request".into())
            })?;
            if request.campaign_id != refusal.campaign_id
                || request.occurrence_id != refusal.occurrence_id
            {
                return Err(CanonicalStoreError::Invalid(
                    "AG refusal names the wrong prepared occurrence".into(),
                ));
            }
        }
        if let Some(request) = &self.prepared_ag_request {
            request.validate()?;
            let intent = self.intent.as_ref().ok_or_else(|| {
                CanonicalStoreError::Invalid("prepared AG request exists without intent".into())
            })?;
            if request.source_intent_id != intent.intent_id {
                return Err(CanonicalStoreError::Invalid(
                    "prepared AG request does not bind the exact intent".into(),
                ));
            }
        }
        match (
            &self.authoring_context_provenance,
            &self.prepared_ag_request,
            &self.intent,
        ) {
            (None, _, _) => {}
            (Some(provenance), Some(request), Some(intent)) => {
                let proposal_input =
                    request.exact_request.get("proposal_input").ok_or_else(|| {
                        CanonicalStoreError::Invalid(
                            "prepared AG request has no exact proposal_input".into(),
                        )
                    })?;
                provenance
                    .validate_relationship(
                        &request.campaign_id,
                        &request.occurrence_id,
                        &ag_proposal_identity(proposal_input)
                            .map_err(CanonicalStoreError::Invalid)?,
                        &exact_work_identity(proposal_input)
                            .map_err(CanonicalStoreError::Invalid)?,
                        &intent.intent_id,
                    )
                    .map_err(CanonicalStoreError::Invalid)?;
            }
            (Some(_), _, _) => {
                return Err(CanonicalStoreError::Invalid(
                    "authoring-context provenance exists without its exact prepared request".into(),
                ));
            }
        }
        match (
            &self.authoring_context_custody,
            &self.authoring_context_provenance,
        ) {
            (None, _) => {}
            (Some(custody), Some(provenance)) => custody
                .validate_for_authoring(provenance)
                .map_err(CanonicalStoreError::Invalid)?,
            (Some(_), None) => {
                return Err(CanonicalStoreError::Invalid(
                    "authoring custody exists without authoring-context lineage".into(),
                ));
            }
        }
        let structural = match self.status {
            CycleStatusV1::Observing => {
                self.observation.is_none()
                    && self.intent.is_none()
                    && self.prepared_ag_request.is_none()
                    && self.ag.is_none()
            }
            CycleStatusV1::PostureRecorded => {
                self.observation.is_some()
                    && self.intent.is_none()
                    && self.prepared_ag_request.is_none()
                    && self.ag.is_none()
            }
            CycleStatusV1::AwaitingAg => {
                self.observation.is_some()
                    && self.intent.is_some()
                    && self.prepared_ag_request.is_some()
            }
            CycleStatusV1::AwaitingAgReconciliation => self
                .ag
                .as_ref()
                .is_some_and(|ag| ag.program_counter == AgProgramCounterV1::ReconciliationRequired),
            CycleStatusV1::ObservationRequired => self.ag.as_ref().is_some_and(|ag| {
                ag.program_counter == AgProgramCounterV1::SettledObservationRequired
            }),
            CycleStatusV1::Halted => self
                .ag
                .as_ref()
                .is_some_and(|ag| ag.program_counter == AgProgramCounterV1::Halted),
            CycleStatusV1::Closed => {
                (self.observation.is_some()
                    && self.intent.is_none()
                    && self.prepared_ag_request.is_none()
                    && self.ag.is_none())
                    || self
                        .ag
                        .as_ref()
                        .is_some_and(|ag| ag.program_counter == AgProgramCounterV1::Completed)
                    || self.ag_refusal.is_some()
            }
            CycleStatusV1::Missed => {
                self.timing == SlotTimingV1::Missed
                    && self.observation.is_none()
                    && self.intent.is_none()
                    && self.ag.is_none()
            }
            CycleStatusV1::RecoveryRequired => match &self.prepared_ag_request {
                Some(_) => self.observation.is_some() && self.intent.is_some(),
                None => self.intent.is_none() && self.ag.is_none() && self.ag_refusal.is_none(),
            },
        };
        if !structural {
            return Err(CanonicalStoreError::Invalid(
                "cycle status and retained semantic facts are inconsistent".into(),
            ));
        }
        if self.state_digest != object_id(self, "state_digest")? {
            return Err(CanonicalStoreError::Invalid(
                "observation-cycle state digest mismatch".into(),
            ));
        }
        Ok(())
    }

    pub fn headline(&self) -> Option<Headline> {
        self.observation
            .as_ref()
            .map(|value| value.posture.headline)
    }
}

fn unique_substrate_origin_head(
    nodes: BTreeMap<String, SubstrateOriginApplicabilityV1>,
) -> Result<SubstrateOriginApplicabilityV1, CanonicalStoreError> {
    let mut referenced = BTreeSet::new();
    for verdict in nodes.values() {
        if let Some(predecessor_id) = &verdict.predecessor_applicability_id {
            let predecessor = nodes.get(predecessor_id).ok_or_else(|| {
                CanonicalStoreError::Invalid(
                    "substrate-origin chain references unknown predecessor verdict".into(),
                )
            })?;
            if verdict.predecessor_coordinate_ref.as_deref()
                != Some(predecessor.observed_coordinate_ref.as_str())
            {
                return Err(CanonicalStoreError::Invalid(
                    "substrate-origin chain substitutes predecessor coordinate".into(),
                ));
            }
            if !referenced.insert(predecessor_id.clone()) {
                return Err(CanonicalStoreError::Invalid(
                    "substrate-origin history forks from one predecessor".into(),
                ));
            }
        }
    }
    let heads: Vec<_> = nodes
        .iter()
        .filter(|(identity, _)| !referenced.contains(*identity))
        .map(|(_, verdict)| verdict)
        .collect();
    if heads.len() != 1 {
        return Err(CanonicalStoreError::Invalid(
            "substrate-origin history has no unique append-only chain head".into(),
        ));
    }
    let roots = nodes
        .values()
        .filter(|value| value.predecessor_applicability_id.is_none())
        .count();
    if roots != 1 || referenced.len() + 1 != nodes.len() {
        return Err(CanonicalStoreError::Invalid(
            "substrate-origin history is disconnected or cyclic".into(),
        ));
    }
    Ok((*heads[0]).clone())
}

pub struct CanonicalStore {
    connection: Connection,
}

impl CanonicalStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CanonicalStoreError> {
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS canonical_recurrence_slots (
                slot_id TEXT PRIMARY KEY,
                cycle_id TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL,
                basis_json TEXT NOT NULL,
                state_digest TEXT NOT NULL,
                updated_at TEXT NOT NULL
            ) STRICT;
            CREATE TABLE IF NOT EXISTS canonical_observation_cycles (
                cycle_id TEXT PRIMARY KEY,
                slot_id TEXT NOT NULL UNIQUE,
                version INTEGER NOT NULL,
                status TEXT NOT NULL,
                state_digest TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(slot_id) REFERENCES canonical_recurrence_slots(slot_id)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS canonical_cycle_events (
                cycle_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                event_kind TEXT NOT NULL,
                prior_state_digest TEXT,
                resulting_state_digest TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                PRIMARY KEY(cycle_id, sequence),
                UNIQUE(cycle_id, resulting_state_digest),
                FOREIGN KEY(cycle_id) REFERENCES canonical_observation_cycles(cycle_id)
            ) STRICT;
            CREATE UNIQUE INDEX IF NOT EXISTS canonical_one_successor_per_predecessor
            ON canonical_cycle_events(cycle_id, prior_state_digest)
            WHERE prior_state_digest IS NOT NULL;
            CREATE TABLE IF NOT EXISTS canonical_ag_occurrence_claims (
                campaign_id TEXT NOT NULL,
                occurrence_id TEXT NOT NULL,
                cycle_id TEXT NOT NULL UNIQUE,
                request_digest TEXT NOT NULL,
                claimed_at TEXT NOT NULL,
                PRIMARY KEY(campaign_id, occurrence_id),
                FOREIGN KEY(cycle_id) REFERENCES canonical_observation_cycles(cycle_id)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS canonical_authoring_context_provenance (
                provenance_id TEXT PRIMARY KEY,
                cycle_id TEXT NOT NULL UNIQUE,
                campaign_id TEXT NOT NULL,
                occurrence_id TEXT NOT NULL,
                proposal_id TEXT NOT NULL,
                exact_work_id TEXT NOT NULL,
                source_intent_id TEXT NOT NULL,
                maude_plan_ref TEXT NOT NULL,
                maude_session_id TEXT NOT NULL,
                record_json TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                UNIQUE(campaign_id, occurrence_id),
                FOREIGN KEY(cycle_id) REFERENCES canonical_observation_cycles(cycle_id)
            ) STRICT;
            CREATE INDEX IF NOT EXISTS canonical_authoring_by_proposal
            ON canonical_authoring_context_provenance(proposal_id);
            CREATE INDEX IF NOT EXISTS canonical_authoring_by_maude_context
            ON canonical_authoring_context_provenance(maude_plan_ref, maude_session_id);
            CREATE TABLE IF NOT EXISTS canonical_authoring_context_custody (
                custody_id TEXT PRIMARY KEY,
                cycle_id TEXT NOT NULL UNIQUE,
                handoff_id TEXT NOT NULL UNIQUE,
                session_record_id TEXT NOT NULL,
                authoring_context_provenance_id TEXT NOT NULL UNIQUE,
                campaign_id TEXT NOT NULL,
                occurrence_id TEXT NOT NULL,
                proposal_id TEXT NOT NULL,
                exact_work_id TEXT NOT NULL,
                producer_principal_id TEXT NOT NULL,
                producer_key_id TEXT NOT NULL,
                session_issuer_principal_id TEXT NOT NULL,
                session_issuer_key_id TEXT NOT NULL,
                target_runtime_id TEXT NOT NULL,
                target_request_id TEXT NOT NULL,
                maude_plan_ref TEXT NOT NULL,
                maude_session_id TEXT NOT NULL,
                record_json TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                FOREIGN KEY(cycle_id) REFERENCES canonical_observation_cycles(cycle_id),
                FOREIGN KEY(authoring_context_provenance_id)
                    REFERENCES canonical_authoring_context_provenance(provenance_id)
            ) STRICT;
            CREATE INDEX IF NOT EXISTS canonical_authoring_custody_by_maude_context
            ON canonical_authoring_context_custody(maude_plan_ref, maude_session_id);
            CREATE TABLE IF NOT EXISTS canonical_external_observations (
                observation_id TEXT PRIMARY KEY,
                handoff_id TEXT NOT NULL UNIQUE,
                custody_id TEXT NOT NULL UNIQUE,
                campaign_id TEXT NOT NULL,
                occurrence_id TEXT NOT NULL,
                attempt_id TEXT NOT NULL UNIQUE,
                executor_evidence_receipt TEXT NOT NULL UNIQUE,
                observation_json TEXT NOT NULL,
                custody_json TEXT NOT NULL,
                received_at TEXT NOT NULL,
                UNIQUE(campaign_id, occurrence_id)
            ) STRICT;
            CREATE INDEX IF NOT EXISTS canonical_external_observations_by_governed_occurrence
            ON canonical_external_observations(campaign_id, occurrence_id);
            CREATE TABLE IF NOT EXISTS canonical_steady_state_observations (
                observation_id TEXT PRIMARY KEY,
                handoff_id TEXT NOT NULL UNIQUE,
                custody_id TEXT NOT NULL UNIQUE,
                qualification_observation_id TEXT NOT NULL,
                plan_document_digest TEXT NOT NULL,
                compilation_id TEXT NOT NULL,
                evidence_receipt TEXT NOT NULL UNIQUE,
                observed_at_unix_ms INTEGER NOT NULL,
                observation_json TEXT NOT NULL,
                custody_json TEXT NOT NULL,
                received_at TEXT NOT NULL
            ) STRICT;
            CREATE INDEX IF NOT EXISTS canonical_steady_state_by_qualification
            ON canonical_steady_state_observations(
                qualification_observation_id, observed_at_unix_ms
            );
            ",
        )?;
        // Narrow migration: older databases predate the queryable
        // observation_id column. Historical rows stay NULL; they are
        // historical evidence only and are not backfilled.
        let has_observation_id = connection
            .prepare("PRAGMA table_info(canonical_observation_cycles)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .any(|name| {
                name.map(|column| column == "observation_id")
                    .unwrap_or(false)
            });
        if !has_observation_id {
            connection.execute_batch(
                "ALTER TABLE canonical_observation_cycles
                 ADD COLUMN observation_id TEXT",
            )?;
        }
        connection.execute_batch(
            "CREATE INDEX IF NOT EXISTS canonical_cycles_observation_id
             ON canonical_observation_cycles(observation_id)",
        )?;
        Ok(Self { connection })
    }

    /// Opens the store strictly read-only: no schema creation, no migration,
    /// no writes. This is the observation resolver's open path, which must be
    /// provably non-mutating at the SQLite level. A database predating the
    /// `observation_id` projection is refused rather than migrated; the
    /// runtime's migrating `open` remains the only schema owner.
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, CanonicalStoreError> {
        let connection =
            Connection::open_with_flags(path.as_ref(), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        let has_observation_id = connection
            .prepare("PRAGMA table_info(canonical_observation_cycles)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .any(|name| {
                name.map(|column| column == "observation_id")
                    .unwrap_or(false)
            });
        if !has_observation_id {
            return Err(CanonicalStoreError::Invalid(
                "canonical store predates the observation_id projection".into(),
            ));
        }
        Ok(Self { connection })
    }

    pub fn claim_slot(
        &mut self,
        slot: RecurrenceSlotV1,
        scheduler_clock_id: &str,
        now: DateTime<Utc>,
    ) -> Result<(ObservationCycleV1, LiveCycleLeaseV1), CanonicalStoreError> {
        let timing = slot.timing_at(scheduler_clock_id, now)?;
        if timing == SlotTimingV1::Missed {
            return Err(CanonicalStoreError::Missed(slot.slot_id.0));
        }
        let cycle_id = ObservationCycleId::fresh();
        let now_text = timestamp(now);
        let mut cycle = ObservationCycleV1 {
            schema: CYCLE_SCHEMA_V1.into(),
            cycle_id: cycle_id.clone(),
            slot: slot.clone(),
            timing,
            status: CycleStatusV1::Observing,
            version: 0,
            prior_state_digest: None,
            state_digest: String::new(),
            created_at: now_text.clone(),
            updated_at: now_text.clone(),
            observation: None,
            attention: None,
            temporal_posture: None,
            intent: None,
            prepared_ag_request: None,
            authoring_context_provenance: None,
            authoring_context_custody: None,
            ag: None,
            ag_refusal: None,
            recovery_reason: None,
        };
        cycle.seal()?;
        cycle.validate()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO canonical_recurrence_slots
             (slot_id, cycle_id, status, basis_json, state_digest, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                slot.slot_id.as_str(),
                cycle_id.as_str(),
                CycleStatusV1::Observing.as_db(),
                canonical_json(&slot)?,
                &cycle.state_digest,
                &now_text,
            ],
        )?;
        if inserted != 1 {
            return Err(CanonicalStoreError::DuplicateSlot(slot.slot_id.0));
        }
        insert_initial_cycle(&tx, &cycle, "slot_claimed")?;
        tx.commit()?;
        let lease = LiveCycleLeaseV1 {
            cycle_id,
            slot_id: slot.slot_id,
            process_nonce: Uuid::new_v4(),
        };
        Ok((cycle, lease))
    }

    pub fn record_missed(
        &mut self,
        slot: RecurrenceSlotV1,
        scheduler_clock_id: &str,
        now: DateTime<Utc>,
        reason: String,
    ) -> Result<ObservationCycleV1, CanonicalStoreError> {
        if slot.timing_at(scheduler_clock_id, now)? != SlotTimingV1::Missed {
            return Err(CanonicalStoreError::IllegalTransition(
                "only an actually missed slot may be recorded missed".into(),
            ));
        }
        require_token("missed reason", &reason)?;
        let cycle_id = ObservationCycleId::fresh();
        let now_text = timestamp(now);
        let mut cycle = ObservationCycleV1 {
            schema: CYCLE_SCHEMA_V1.into(),
            cycle_id: cycle_id.clone(),
            slot: slot.clone(),
            timing: SlotTimingV1::Missed,
            status: CycleStatusV1::Missed,
            version: 0,
            prior_state_digest: None,
            state_digest: String::new(),
            created_at: now_text.clone(),
            updated_at: now_text.clone(),
            observation: None,
            attention: None,
            temporal_posture: None,
            intent: None,
            prepared_ag_request: None,
            authoring_context_provenance: None,
            authoring_context_custody: None,
            ag: None,
            ag_refusal: None,
            recovery_reason: Some(reason),
        };
        cycle.seal()?;
        cycle.validate()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO canonical_recurrence_slots
             (slot_id, cycle_id, status, basis_json, state_digest, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                slot.slot_id.as_str(),
                cycle_id.as_str(),
                CycleStatusV1::Missed.as_db(),
                canonical_json(&slot)?,
                &cycle.state_digest,
                &now_text,
            ],
        )?;
        if inserted != 1 {
            return Err(CanonicalStoreError::DuplicateSlot(slot.slot_id.0));
        }
        insert_initial_cycle(&tx, &cycle, "slot_missed")?;
        tx.commit()?;
        Ok(cycle)
    }

    pub fn record_observation(
        &mut self,
        lease: &LiveCycleLeaseV1,
        expected_digest: &str,
        observation: ObservationRecordV1,
        attention: AttentionRecordV1,
        temporal_posture: Option<TemporalPostureV1>,
        now: DateTime<Utc>,
    ) -> Result<ObservationCycleV1, CanonicalStoreError> {
        observation.validate_for_cycle(&lease.cycle_id)?;
        if let Some(composition) = &observation.external_evidence {
            self.validate_external_composition_source(composition)?;
        }
        if attention.source_posture_id != observation.posture.posture_id {
            return Err(CanonicalStoreError::Invalid(
                "attention record does not bind the exact posture".into(),
            ));
        }
        self.transition(
            &lease.cycle_id,
            Some(lease),
            expected_digest,
            "observation_recorded",
            now,
            move |cycle| {
                if cycle.status != CycleStatusV1::Observing {
                    return Err(CanonicalStoreError::IllegalTransition(
                        "observation may be recorded only while observing".into(),
                    ));
                }
                cycle.observation = Some(observation);
                cycle.attention = Some(attention);
                cycle.temporal_posture = temporal_posture;
                cycle.status = CycleStatusV1::PostureRecorded;
                Ok(())
            },
        )
    }

    pub(crate) fn prepare_ag_occurrence(
        &mut self,
        lease: &LiveCycleLeaseV1,
        expected_digest: &str,
        intent: TypedCoarseIntentV2,
        request: PreparedAgRequestV1,
        authoring: PreparedAuthoringEvidenceV1,
        now: DateTime<Utc>,
    ) -> Result<ObservationCycleV1, CanonicalStoreError> {
        let PreparedAuthoringEvidenceV1 {
            lineage: authoring_context_provenance,
            custody: authoring_context_custody,
        } = authoring;
        request.validate()?;
        if let Some(provenance) = &authoring_context_provenance {
            let proposal_input = request.exact_request.get("proposal_input").ok_or_else(|| {
                CanonicalStoreError::Invalid(
                    "prepared AG request has no exact proposal_input".into(),
                )
            })?;
            provenance
                .validate_relationship(
                    &request.campaign_id,
                    &request.occurrence_id,
                    &ag_proposal_identity(proposal_input).map_err(CanonicalStoreError::Invalid)?,
                    &exact_work_identity(proposal_input).map_err(CanonicalStoreError::Invalid)?,
                    &intent.intent_id,
                )
                .map_err(CanonicalStoreError::Invalid)?;
        }
        match (&authoring_context_custody, &authoring_context_provenance) {
            (None, _) => {}
            (Some(custody), Some(provenance)) => custody
                .validate_for_authoring(provenance)
                .map_err(CanonicalStoreError::Invalid)?,
            (Some(_), None) => {
                return Err(CanonicalStoreError::Invalid(
                    "authoring custody exists without authoring-context lineage".into(),
                ));
            }
        }
        self.transition(
            &lease.cycle_id,
            Some(lease),
            expected_digest,
            "ag_occurrence_prepared",
            now,
            move |cycle| {
                if cycle.status != CycleStatusV1::PostureRecorded {
                    return Err(CanonicalStoreError::IllegalTransition(
                        "AG occurrence may be attached only after exact posture recording".into(),
                    ));
                }
                let observation = cycle.observation.as_ref().ok_or_else(|| {
                    CanonicalStoreError::IllegalTransition("observation basis is absent".into())
                })?;
                if !observation.posture.current
                    || observation.support.standing != SupportStandingV1::Current
                {
                    return Err(CanonicalStoreError::IllegalTransition(
                        "non-current posture cannot originate an AG proposal".into(),
                    ));
                }
                intent.validate_for_observation(observation)?;
                if request.source_intent_id != intent.intent_id {
                    return Err(CanonicalStoreError::Invalid(
                        "prepared AG request does not bind the exact intent".into(),
                    ));
                }
                cycle.intent = Some(intent);
                cycle.prepared_ag_request = Some(request);
                cycle.authoring_context_provenance = authoring_context_provenance;
                cycle.authoring_context_custody = authoring_context_custody;
                cycle.status = CycleStatusV1::AwaitingAg;
                Ok(())
            },
        )
    }

    pub fn attach_ag_occurrence(
        &mut self,
        lease: &LiveCycleLeaseV1,
        expected_digest: &str,
        ag: AgOccurrenceReferenceV1,
        now: DateTime<Utc>,
    ) -> Result<ObservationCycleV1, CanonicalStoreError> {
        ag.validate()?;
        self.transition(
            &lease.cycle_id,
            Some(lease),
            expected_digest,
            "ag_occurrence_attached",
            now,
            move |cycle| {
                if cycle.status != CycleStatusV1::AwaitingAg || cycle.ag.is_some() {
                    return Err(CanonicalStoreError::IllegalTransition(
                        "AG occurrence may attach only to one prepared request".into(),
                    ));
                }
                let request = cycle.prepared_ag_request.as_ref().ok_or_else(|| {
                    CanonicalStoreError::IllegalTransition("prepared AG request is absent".into())
                })?;
                if request.campaign_id != ag.campaign_id
                    || request.occurrence_id != ag.occurrence_id
                {
                    return Err(CanonicalStoreError::Invalid(
                        "AG response names the wrong prepared occurrence".into(),
                    ));
                }
                if matches!(
                    ag.program_counter,
                    AgProgramCounterV1::AuthorizationConsumed
                        | AgProgramCounterV1::Dispatched
                        | AgProgramCounterV1::ReconciliationRequired
                        | AgProgramCounterV1::SettledObservationRequired
                        | AgProgramCounterV1::Halted
                        | AgProgramCounterV1::Completed
                ) {
                    return Err(CanonicalStoreError::Invalid(
                        "Nightshift adapter crossed an AG consequence boundary".into(),
                    ));
                }
                cycle.ag = Some(ag);
                Ok(())
            },
        )
    }

    /// Consume a read-only AG status. This never changes diagnostic posture and
    /// can never create a new intent or occurrence.
    pub fn record_ag_status(
        &mut self,
        cycle_id: &ObservationCycleId,
        expected_digest: &str,
        ag: AgOccurrenceReferenceV1,
        now: DateTime<Utc>,
    ) -> Result<ObservationCycleV1, CanonicalStoreError> {
        ag.validate()?;
        let current = self.get_cycle(cycle_id)?;
        if current.state_digest != expected_digest {
            return Err(CanonicalStoreError::StalePredecessor);
        }
        if current.ag.as_ref() == Some(&ag) {
            return Ok(current);
        }
        self.transition(
            cycle_id,
            None,
            expected_digest,
            "ag_status_observed",
            now,
            move |cycle| {
                if !matches!(
                    cycle.status,
                    CycleStatusV1::AwaitingAg
                        | CycleStatusV1::AwaitingAgReconciliation
                        | CycleStatusV1::ObservationRequired
                        | CycleStatusV1::Halted
                        | CycleStatusV1::RecoveryRequired
                ) {
                    return Err(CanonicalStoreError::IllegalTransition(
                        "AG status cannot be attached from this cycle state".into(),
                    ));
                }
                let prior = cycle.ag.as_ref().ok_or_else(|| {
                    CanonicalStoreError::IllegalTransition("cycle has no AG occurrence".into())
                })?;
                if prior.campaign_id != ag.campaign_id || prior.occurrence_id != ag.occurrence_id {
                    return Err(CanonicalStoreError::Invalid(
                        "AG status names the wrong campaign or occurrence".into(),
                    ));
                }
                if !ag_status_can_follow(prior.program_counter, ag.program_counter) {
                    return Err(CanonicalStoreError::Invalid(
                        "stale or regressive AG program-counter observation".into(),
                    ));
                }
                cycle.status = match ag.program_counter {
                    AgProgramCounterV1::ReconciliationRequired => {
                        CycleStatusV1::AwaitingAgReconciliation
                    }
                    AgProgramCounterV1::SettledObservationRequired => {
                        CycleStatusV1::ObservationRequired
                    }
                    AgProgramCounterV1::Halted => CycleStatusV1::Halted,
                    AgProgramCounterV1::Completed => CycleStatusV1::Closed,
                    _ => CycleStatusV1::AwaitingAg,
                };
                cycle.ag = Some(ag);
                Ok(())
            },
        )
    }

    pub fn record_ag_refusal(
        &mut self,
        cycle_id: &ObservationCycleId,
        expected_digest: &str,
        refusal: AgRefusalReferenceV1,
        now: DateTime<Utc>,
    ) -> Result<ObservationCycleV1, CanonicalStoreError> {
        refusal.validate()?;
        self.transition(
            cycle_id,
            None,
            expected_digest,
            "ag_refusal_observed",
            now,
            move |cycle| {
                if !matches!(
                    cycle.status,
                    CycleStatusV1::AwaitingAg | CycleStatusV1::RecoveryRequired
                ) {
                    return Err(CanonicalStoreError::IllegalTransition(
                        "AG refusal can close only its exact pending cycle".into(),
                    ));
                }
                let request = cycle.prepared_ag_request.as_ref().ok_or_else(|| {
                    CanonicalStoreError::IllegalTransition("prepared AG request is absent".into())
                })?;
                if request.campaign_id != refusal.campaign_id
                    || request.occurrence_id != refusal.occurrence_id
                {
                    return Err(CanonicalStoreError::Invalid(
                        "AG refusal names the wrong campaign or occurrence".into(),
                    ));
                }
                let ag = cycle.ag.as_ref().ok_or_else(|| {
                    CanonicalStoreError::IllegalTransition(
                        "AG refusal requires the exact observed AG predecessor state".into(),
                    )
                })?;
                if ag.state_digest != refusal.at_state_digest {
                    return Err(CanonicalStoreError::Invalid(
                        "AG refusal names a substituted predecessor state".into(),
                    ));
                }
                cycle.ag_refusal = Some(refusal);
                cycle.status = CycleStatusV1::Closed;
                Ok(())
            },
        )
    }

    /// Reattach an AG occurrence discovered by a read-only status query after
    /// a crash between AG acceptance and local reference persistence. This is
    /// evidence reconciliation only; it cannot call AG or create an occurrence.
    pub fn recover_ag_occurrence(
        &mut self,
        cycle_id: &ObservationCycleId,
        expected_digest: &str,
        ag: AgOccurrenceReferenceV1,
        now: DateTime<Utc>,
    ) -> Result<ObservationCycleV1, CanonicalStoreError> {
        ag.validate()?;
        self.transition(
            cycle_id,
            None,
            expected_digest,
            "ag_occurrence_recovered_read_only",
            now,
            move |cycle| {
                if !matches!(
                    cycle.status,
                    CycleStatusV1::AwaitingAg | CycleStatusV1::RecoveryRequired
                ) || cycle.ag.is_some()
                {
                    return Err(CanonicalStoreError::IllegalTransition(
                        "AG occurrence recovery requires an unresolved prepared request".into(),
                    ));
                }
                let request = cycle.prepared_ag_request.as_ref().ok_or_else(|| {
                    CanonicalStoreError::IllegalTransition("prepared AG request is absent".into())
                })?;
                if request.campaign_id != ag.campaign_id
                    || request.occurrence_id != ag.occurrence_id
                {
                    return Err(CanonicalStoreError::Invalid(
                        "recovered AG response names the wrong occurrence".into(),
                    ));
                }
                cycle.status = match ag.program_counter {
                    AgProgramCounterV1::ReconciliationRequired => {
                        CycleStatusV1::AwaitingAgReconciliation
                    }
                    AgProgramCounterV1::SettledObservationRequired => {
                        CycleStatusV1::ObservationRequired
                    }
                    AgProgramCounterV1::Halted => CycleStatusV1::Halted,
                    AgProgramCounterV1::Completed => CycleStatusV1::Closed,
                    _ => CycleStatusV1::AwaitingAg,
                };
                cycle.ag = Some(ag);
                cycle.recovery_reason = None;
                Ok(())
            },
        )
    }

    pub fn mark_recovery_required(
        &mut self,
        cycle_id: &ObservationCycleId,
        expected_digest: &str,
        reason: String,
        now: DateTime<Utc>,
    ) -> Result<ObservationCycleV1, CanonicalStoreError> {
        require_token("recovery reason", &reason)?;
        self.transition(
            cycle_id,
            None,
            expected_digest,
            "recovery_required",
            now,
            move |cycle| {
                if matches!(cycle.status, CycleStatusV1::Closed | CycleStatusV1::Missed) {
                    return Err(CanonicalStoreError::IllegalTransition(
                        "terminal cycle cannot enter recovery".into(),
                    ));
                }
                cycle.status = CycleStatusV1::RecoveryRequired;
                cycle.recovery_reason = Some(reason);
                Ok(())
            },
        )
    }

    pub fn close_without_proposal(
        &mut self,
        lease: &LiveCycleLeaseV1,
        expected_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<ObservationCycleV1, CanonicalStoreError> {
        self.transition(
            &lease.cycle_id,
            Some(lease),
            expected_digest,
            "cycle_closed_without_proposal",
            now,
            |cycle| {
                if cycle.status != CycleStatusV1::PostureRecorded || cycle.intent.is_some() {
                    return Err(CanonicalStoreError::IllegalTransition(
                        "only a posture-only cycle may close without a proposal".into(),
                    ));
                }
                cycle.status = CycleStatusV1::Closed;
                Ok(())
            },
        )
    }

    pub fn get_cycle(
        &self,
        cycle_id: &ObservationCycleId,
    ) -> Result<ObservationCycleV1, CanonicalStoreError> {
        let json: Option<String> = self
            .connection
            .query_row(
                "SELECT snapshot_json FROM canonical_observation_cycles WHERE cycle_id=?1",
                [cycle_id.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        let cycle: ObservationCycleV1 = serde_json::from_str(
            &json.ok_or_else(|| CanonicalStoreError::CycleNotFound(cycle_id.0.clone()))?,
        )?;
        cycle.validate()?;
        self.validate_ag_occurrence_claim(&cycle)?;
        self.validate_authoring_context_claim(&cycle)?;
        self.validate_authoring_custody_claim(&cycle)?;
        Ok(cycle)
    }

    pub fn list_cycles(&self) -> Result<Vec<ObservationCycleV1>, CanonicalStoreError> {
        let mut statement = self.connection.prepare(
            "SELECT snapshot_json FROM canonical_observation_cycles ORDER BY updated_at, cycle_id",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut values = Vec::new();
        for row in rows {
            let cycle: ObservationCycleV1 = serde_json::from_str(&row?)?;
            cycle.validate()?;
            values.push(cycle);
        }
        drop(statement);
        for cycle in &values {
            self.validate_ag_occurrence_claim(cycle)?;
            self.validate_authoring_context_claim(cycle)?;
            self.validate_authoring_custody_claim(cycle)?;
        }
        Ok(values)
    }

    /// Reconstruct the unique append-only substrate-origin chain head for one
    /// subject from admitted V6 observation records. No mutable
    /// `current_substrate` field or request-supplied predecessor participates.
    pub fn substrate_origin_head(
        &self,
        subject_ref: &str,
    ) -> Result<Option<SubstrateOriginApplicabilityV1>, CanonicalStoreError> {
        require_token("substrate-origin subject", subject_ref)?;
        let mut nodes = BTreeMap::new();
        for cycle in self.list_cycles()? {
            let Some(observation) = cycle.observation else {
                continue;
            };
            for verdict in observation.substrate_origin_applicability {
                if verdict.subject_ref != subject_ref
                    || verdict.status != SubstrateOriginApplicabilityStatusV1::Applicable
                {
                    continue;
                }
                verdict.validate().map_err(CanonicalStoreError::Invalid)?;
                if nodes
                    .insert(verdict.applicability_id.clone(), verdict.clone())
                    .is_some()
                {
                    return Err(CanonicalStoreError::Invalid(
                        "duplicate substrate-origin applicability identity".into(),
                    ));
                }
            }
        }
        if nodes.is_empty() {
            return Ok(None);
        }
        unique_substrate_origin_head(nodes).map(Some)
    }

    /// Every persisted cycle carrying this exact `observation_id`. Zero, one,
    /// or several matches are all faithful results; multiple matches are
    /// returned, never collapsed. Classifying ambiguity (for example as
    /// contradictory evidence) is caller policy, not store policy.
    pub fn find_cycles_by_observation_id(
        &self,
        observation_id: &str,
    ) -> Result<Vec<ObservationCycleV1>, CanonicalStoreError> {
        let mut statement = self.connection.prepare(
            "SELECT snapshot_json FROM canonical_observation_cycles
             WHERE observation_id=?1 ORDER BY cycle_id",
        )?;
        let rows = statement.query_map([observation_id], |row| row.get::<_, String>(0))?;
        let mut values = Vec::new();
        for row in rows {
            let cycle: ObservationCycleV1 = serde_json::from_str(&row?)?;
            cycle.validate()?;
            values.push(cycle);
        }
        drop(statement);
        for cycle in &values {
            self.validate_ag_occurrence_claim(cycle)?;
            self.validate_authoring_context_claim(cycle)?;
            self.validate_authoring_custody_claim(cycle)?;
        }
        Ok(values)
    }

    /// The logically latest qualified observation in one lineage. A cycle is
    /// qualified exactly when it contains a persisted `ObservationRecordV1`
    /// (`Missed` and unrecovered cycles never qualify, whatever their support
    /// or status). Ordering is the logical slot `ObservationOrderKeyV1`; slot
    /// identity is unique, so no tie is ever broken by write time.
    pub fn latest_qualified_observation_in_family(
        &self,
        family: &ObservationFamilyKeyV1,
    ) -> Result<Option<ObservationCycleV1>, CanonicalStoreError> {
        let mut latest: Option<ObservationCycleV1> = None;
        for cycle in self.list_cycles()? {
            if ObservationFamilyKeyV1::of_slot(&cycle.slot) != *family
                || cycle.observation.is_none()
            {
                continue;
            }
            let newer = match &latest {
                None => true,
                Some(current) => {
                    ObservationOrderKeyV1::of_slot(&cycle.slot)
                        > ObservationOrderKeyV1::of_slot(&current.slot)
                }
            };
            if newer {
                latest = Some(cycle);
            }
        }
        Ok(latest)
    }

    /// Exact immutable authoring-context relations selected by one closed
    /// identity query. This is a read projection only; absence remains an
    /// empty match set and never changes proposal validity or authority.
    pub fn export_authoring_context(
        &self,
        query: AuthoringContextQueryV1,
    ) -> Result<AuthoringContextExportV1, CanonicalStoreError> {
        query.validate().map_err(CanonicalStoreError::Invalid)?;
        let has_projection = self.connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_master
                WHERE type='table' AND name='canonical_authoring_context_provenance'
             )",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        if !has_projection {
            return Err(CanonicalStoreError::Invalid(
                "canonical store predates the authoring-context provenance projection".into(),
            ));
        }
        let durable_rows = match &query {
            AuthoringContextQueryV1::GovernedOccurrence {
                campaign_id,
                occurrence_id,
            } => {
                let mut statement = self.connection.prepare(
                    "SELECT cycle_id, record_json FROM canonical_authoring_context_provenance
                     WHERE campaign_id=?1 AND occurrence_id=?2 ORDER BY provenance_id",
                )?;
                let rows = statement
                    .query_map(params![campaign_id, occurrence_id], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                rows
            }
            AuthoringContextQueryV1::Proposal { proposal_id } => {
                let mut statement = self.connection.prepare(
                    "SELECT cycle_id, record_json FROM canonical_authoring_context_provenance
                     WHERE proposal_id=?1 ORDER BY occurrence_id, provenance_id",
                )?;
                let rows = statement
                    .query_map([proposal_id], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                rows
            }
            AuthoringContextQueryV1::MaudeContext {
                plan_ref,
                session_id,
            } => {
                let mut statement = self.connection.prepare(
                    "SELECT cycle_id, record_json FROM canonical_authoring_context_provenance
                     WHERE maude_plan_ref=?1 AND maude_session_id=?2
                     ORDER BY campaign_id, occurrence_id, provenance_id",
                )?;
                let rows = statement
                    .query_map(params![plan_ref, session_id], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                rows
            }
        };
        let matches = durable_rows
            .into_iter()
            .map(|(cycle_id, json)| {
                let record = serde_json::from_str::<AuthoringContextProvenanceV1>(&json)?;
                let cycle = self.get_cycle(&ObservationCycleId(cycle_id))?;
                if cycle.authoring_context_provenance.as_ref() != Some(&record) {
                    return Err(CanonicalStoreError::Replay(
                        "authoring-context projection differs from its authoritative cycle".into(),
                    ));
                }
                Ok(record)
            })
            .collect::<Result<Vec<_>, _>>()?;
        AuthoringContextExportV1::new(query, matches).map_err(CanonicalStoreError::Invalid)
    }

    /// Exact authenticated custody records for one authoring identity query.
    /// Historical authoring lineage predating custody returns an empty set.
    pub fn export_authoring_custody(
        &self,
        query: AuthoringContextQueryV1,
    ) -> Result<AuthoringContextCustodyExportV1, CanonicalStoreError> {
        query.validate().map_err(CanonicalStoreError::Invalid)?;
        let has_projection = self.connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_master
                WHERE type='table' AND name='canonical_authoring_context_custody'
             )",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        if !has_projection {
            return Err(CanonicalStoreError::Invalid(
                "canonical store predates the authoring-context custody projection".into(),
            ));
        }
        let durable_rows = match &query {
            AuthoringContextQueryV1::GovernedOccurrence {
                campaign_id,
                occurrence_id,
            } => {
                let mut statement = self.connection.prepare(
                    "SELECT c.cycle_id, c.record_json
                     FROM canonical_authoring_context_custody c
                     JOIN canonical_authoring_context_provenance p
                       ON p.provenance_id=c.authoring_context_provenance_id
                     WHERE p.campaign_id=?1 AND p.occurrence_id=?2
                     ORDER BY c.custody_id",
                )?;
                let rows = statement
                    .query_map(params![campaign_id, occurrence_id], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                rows
            }
            AuthoringContextQueryV1::Proposal { proposal_id } => {
                let mut statement = self.connection.prepare(
                    "SELECT c.cycle_id, c.record_json
                     FROM canonical_authoring_context_custody c
                     JOIN canonical_authoring_context_provenance p
                       ON p.provenance_id=c.authoring_context_provenance_id
                     WHERE p.proposal_id=?1 ORDER BY c.custody_id",
                )?;
                let rows = statement
                    .query_map([proposal_id], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                rows
            }
            AuthoringContextQueryV1::MaudeContext {
                plan_ref,
                session_id,
            } => {
                let mut statement = self.connection.prepare(
                    "SELECT cycle_id, record_json FROM canonical_authoring_context_custody
                     WHERE maude_plan_ref=?1 AND maude_session_id=?2
                     ORDER BY custody_id",
                )?;
                let rows = statement
                    .query_map(params![plan_ref, session_id], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                rows
            }
        };
        let matches = durable_rows
            .into_iter()
            .map(|(cycle_id, json)| {
                let record = serde_json::from_str::<AuthoringContextCustodyProvenanceV1>(&json)?;
                let cycle = self.get_cycle(&ObservationCycleId(cycle_id))?;
                if cycle.authoring_context_custody.as_ref() != Some(&record) {
                    return Err(CanonicalStoreError::Replay(
                        "authoring custody projection differs from its authoritative cycle".into(),
                    ));
                }
                Ok(record)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let export = AuthoringContextCustodyExportV1 {
            schema: CUSTODY_EXPORT_SCHEMA_V1.into(),
            query,
            matches,
        };
        export.validate().map_err(CanonicalStoreError::Invalid)?;
        Ok(export)
    }

    /// Persist one authenticated application/world observation candidate.
    ///
    /// This is a custody journal independent of canonical observation cycles.
    /// Insertion cannot create an `ObservationRecordV1`, currentness, a
    /// proposal, or an AG transition. Exact replay returns the first durable
    /// custody receipt; any attempt/occurrence/source substitution refuses.
    pub fn record_external_observation(
        &mut self,
        verified: &VerifiedExternalObservationHandoffV1,
        received_at: DateTime<Utc>,
    ) -> Result<ExternalObservationCustodyProvenanceV1, CanonicalStoreError> {
        let handoff = verified.handoff();
        if received_at < handoff.created_at
            || handoff.observation.observed_at_unix_ms > handoff.created_at.timestamp_millis()
        {
            return Err(CanonicalStoreError::Invalid(
                "external-observation custody time precedes source or handoff".into(),
            ));
        }
        let custody = ExternalObservationCustodyProvenanceV1::mint(verified, received_at)
            .map_err(CanonicalStoreError::Invalid)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(String, String)> = tx
            .query_row(
                "SELECT observation_json, custody_json
                 FROM canonical_external_observations
                 WHERE observation_id=?1 OR handoff_id=?2 OR attempt_id=?3
                    OR executor_evidence_receipt=?4
                    OR (campaign_id=?5 AND occurrence_id=?6)",
                params![
                    &handoff.observation.observation_id,
                    &handoff.handoff_id,
                    &handoff.observation.attempt_id,
                    &handoff.observation.executor_evidence_receipt,
                    &handoff.observation.campaign_id,
                    &handoff.observation.occurrence_id,
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((observation_json, custody_json)) = existing {
            let observation =
                serde_json::from_str::<LocalComposeWorldObservationV1>(&observation_json)?;
            let existing_custody =
                serde_json::from_str::<ExternalObservationCustodyProvenanceV1>(&custody_json)?;
            observation
                .validate()
                .map_err(CanonicalStoreError::Invalid)?;
            existing_custody
                .validate()
                .map_err(CanonicalStoreError::Invalid)?;
            if observation == handoff.observation
                && existing_custody.handoff_id == custody.handoff_id
                && existing_custody.observation_id == custody.observation_id
                && existing_custody.producer_principal_id == custody.producer_principal_id
                && existing_custody.producer_key_id == custody.producer_key_id
                && existing_custody.target_runtime_id == custody.target_runtime_id
            {
                // Receipt time belongs to first durable acceptance. A timeout
                // resend never rewrites it or creates a second candidate.
                return Ok(existing_custody);
            }
            return Err(CanonicalStoreError::ExternalObservationConflict(
                "attempt, occurrence, handoff, or source receipt is already bound".into(),
            ));
        }
        tx.execute(
            "INSERT INTO canonical_external_observations
             (observation_id, handoff_id, custody_id, campaign_id, occurrence_id,
              attempt_id, executor_evidence_receipt, observation_json, custody_json,
              received_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                &handoff.observation.observation_id,
                &handoff.handoff_id,
                &custody.custody_id,
                &handoff.observation.campaign_id,
                &handoff.observation.occurrence_id,
                &handoff.observation.attempt_id,
                &handoff.observation.executor_evidence_receipt,
                canonical_json(&handoff.observation)?,
                canonical_json(&custody)?,
                timestamp(received_at),
            ],
        )?;
        tx.commit()?;
        Ok(custody)
    }

    /// Persist one authenticated read-only steady-state observation. Unlike
    /// the qualification custody slot, multiple exact acquisitions may bind
    /// one qualification; observation/evidence identities remain unique.
    pub fn record_steady_state_observation(
        &mut self,
        verified: &VerifiedSteadyStateObservationHandoffV1,
        received_at: DateTime<Utc>,
    ) -> Result<SteadyStateObservationCustodyV1, CanonicalStoreError> {
        let handoff = verified.handoff();
        if received_at < handoff.created_at
            || handoff.observation.observed_at_unix_ms > handoff.created_at.timestamp_millis()
        {
            return Err(CanonicalStoreError::Invalid(
                "steady-state custody time precedes source or handoff".into(),
            ));
        }
        let custody = SteadyStateObservationCustodyV1::mint(verified, received_at)
            .map_err(CanonicalStoreError::Invalid)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(String, String)> = tx
            .query_row(
                "SELECT observation_json, custody_json
                 FROM canonical_steady_state_observations
                 WHERE observation_id=?1 OR handoff_id=?2 OR evidence_receipt=?3",
                params![
                    &handoff.observation.observation_id,
                    &handoff.handoff_id,
                    &handoff.observation.evidence_receipt,
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((observation_json, custody_json)) = existing {
            let observation =
                serde_json::from_str::<LocalComposeSteadyStateObservationV1>(&observation_json)?;
            let existing_custody =
                serde_json::from_str::<SteadyStateObservationCustodyV1>(&custody_json)?;
            observation
                .validate()
                .map_err(CanonicalStoreError::Invalid)?;
            existing_custody
                .validate()
                .map_err(CanonicalStoreError::Invalid)?;
            if observation == handoff.observation
                && existing_custody.handoff_id == custody.handoff_id
                && existing_custody.producer_principal_id == custody.producer_principal_id
                && existing_custody.producer_key_id == custody.producer_key_id
                && existing_custody.target_runtime_id == custody.target_runtime_id
            {
                return Ok(existing_custody);
            }
            return Err(CanonicalStoreError::ExternalObservationConflict(
                "steady-state observation, handoff, or evidence receipt is already bound".into(),
            ));
        }
        tx.execute(
            "INSERT INTO canonical_steady_state_observations
             (observation_id, handoff_id, custody_id, qualification_observation_id,
              plan_document_digest, compilation_id, evidence_receipt,
              observed_at_unix_ms, observation_json, custody_json, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                &handoff.observation.observation_id,
                &handoff.handoff_id,
                &custody.custody_id,
                &handoff.observation.qualification_observation_id,
                &handoff.observation.plan_document_digest,
                &handoff.observation.compilation_id,
                &handoff.observation.evidence_receipt,
                handoff.observation.observed_at_unix_ms,
                canonical_json(&handoff.observation)?,
                canonical_json(&custody)?,
                timestamp(received_at),
            ],
        )?;
        tx.commit()?;
        Ok(custody)
    }

    pub(crate) fn steady_state_observation_for_composition(
        &self,
        observation_id: &str,
    ) -> Result<
        Option<(
            LocalComposeSteadyStateObservationV1,
            SteadyStateObservationCustodyV1,
        )>,
        CanonicalStoreError,
    > {
        require_digest("steady-state observation_id", observation_id)?;
        let row = self
            .connection
            .query_row(
                "SELECT observation_json, custody_json
                 FROM canonical_steady_state_observations WHERE observation_id=?1",
                [observation_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let Some((observation_json, custody_json)) = row else {
            return Ok(None);
        };
        let observation =
            serde_json::from_str::<LocalComposeSteadyStateObservationV1>(&observation_json)?;
        let custody = serde_json::from_str::<SteadyStateObservationCustodyV1>(&custody_json)?;
        observation
            .validate()
            .map_err(CanonicalStoreError::Replay)?;
        custody.validate().map_err(CanonicalStoreError::Replay)?;
        if custody.observation_id != observation.observation_id
            || custody.qualification_observation_id != observation.qualification_observation_id
            || custody.plan_document_digest != observation.plan_document_digest
            || custody.compilation_id != observation.compilation_id
            || custody.evidence_receipt != observation.evidence_receipt
        {
            return Err(CanonicalStoreError::Replay(
                "steady-state observation custody projection is contradictory".into(),
            ));
        }
        Ok(Some((observation, custody)))
    }

    fn latest_steady_state_for_qualification(
        &self,
        qualification_observation_id: &str,
    ) -> Result<
        Option<(
            LocalComposeSteadyStateObservationV1,
            SteadyStateObservationCustodyV1,
        )>,
        CanonicalStoreError,
    > {
        require_digest("qualification_observation_id", qualification_observation_id)?;
        let observation_id = self
            .connection
            .query_row(
                "SELECT observation_id FROM canonical_steady_state_observations
                 WHERE qualification_observation_id=?1
                 ORDER BY observed_at_unix_ms DESC, observation_id DESC LIMIT 1",
                [qualification_observation_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        match observation_id {
            Some(observation_id) => self.steady_state_observation_for_composition(&observation_id),
            None => Ok(None),
        }
    }

    pub fn steady_state_reobservation_basis(
        &self,
        qualification_observation_id: &str,
        profile: &SteadyStateEvidenceProfileV1,
        evaluated_at_unix_ms: u64,
    ) -> Result<SteadyStateReobservationBasisV1, CanonicalStoreError> {
        profile.validate().map_err(CanonicalStoreError::Invalid)?;
        let (source, source_custody) = self
            .external_observation_for_composition(qualification_observation_id)?
            .ok_or_else(|| {
                CanonicalStoreError::Invalid(
                    "qualification source is absent from authenticated canonical custody".into(),
                )
            })?;
        let qualification = ArtifactQualificationEvidenceV1::from_source(
            &profile.qualification_profile,
            &source,
            &source_custody,
        )
        .map_err(CanonicalStoreError::Invalid)?;
        let prior = self.latest_steady_state_for_qualification(qualification_observation_id)?;
        SteadyStateReobservationBasisV1::create(
            profile,
            &qualification,
            prior
                .as_ref()
                .map(|(observation, custody)| (observation, custody)),
            evaluated_at_unix_ms,
        )
        .map_err(CanonicalStoreError::Invalid)
    }

    /// Read-only exact candidate/custody lookup with an explicit age
    /// projection. `fresh_at_evaluation` says only that source evidence falls
    /// inside this caller-supplied age window; it is not Nightshift currentness.
    pub fn export_external_observation(
        &self,
        query: ExternalObservationQueryV1,
        evaluated_at_unix_ms: i64,
        evidence_ttl_ms: u64,
    ) -> Result<ExternalObservationExportV1, CanonicalStoreError> {
        query.validate().map_err(CanonicalStoreError::Invalid)?;
        if evaluated_at_unix_ms < 0 {
            return Err(CanonicalStoreError::Invalid(
                "external-observation evaluation time is invalid".into(),
            ));
        }
        let has_projection = self.connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_master
                WHERE type='table' AND name='canonical_external_observations'
             )",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        if !has_projection {
            return Err(CanonicalStoreError::Invalid(
                "canonical store predates the external-observation custody projection".into(),
            ));
        }
        let rows = match &query {
            ExternalObservationQueryV1::Observation { observation_id } => {
                let mut statement = self.connection.prepare(
                    "SELECT observation_json, custody_json
                     FROM canonical_external_observations WHERE observation_id=?1",
                )?;
                let rows = statement
                    .query_map([observation_id], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                rows
            }
            ExternalObservationQueryV1::GovernedOccurrence {
                campaign_id,
                occurrence_id,
            } => {
                let mut statement = self.connection.prepare(
                    "SELECT observation_json, custody_json
                     FROM canonical_external_observations
                     WHERE campaign_id=?1 AND occurrence_id=?2",
                )?;
                let rows = statement
                    .query_map(params![campaign_id, occurrence_id], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                rows
            }
            ExternalObservationQueryV1::Attempt { attempt_id } => {
                let mut statement = self.connection.prepare(
                    "SELECT observation_json, custody_json
                     FROM canonical_external_observations WHERE attempt_id=?1",
                )?;
                let rows = statement
                    .query_map([attempt_id], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                rows
            }
        };
        let matches = rows
            .into_iter()
            .map(|(observation_json, custody_json)| {
                let observation =
                    serde_json::from_str::<LocalComposeWorldObservationV1>(&observation_json)?;
                let custody =
                    serde_json::from_str::<ExternalObservationCustodyProvenanceV1>(&custody_json)?;
                observation
                    .validate()
                    .map_err(CanonicalStoreError::Replay)?;
                custody.validate().map_err(CanonicalStoreError::Replay)?;
                if custody.observation_id != observation.observation_id
                    || custody.campaign_id != observation.campaign_id
                    || custody.occurrence_id != observation.occurrence_id
                    || custody.exact_work_id != observation.exact_work_id
                    || custody.attempt_id != observation.attempt_id
                    || custody.settlement_id != observation.settlement_id
                    || custody.executor_evidence_receipt != observation.executor_evidence_receipt
                {
                    return Err(CanonicalStoreError::Replay(
                        "external-observation custody projection is contradictory".into(),
                    ));
                }
                Ok(ExternalObservationExportMatchV1 {
                    evidence_age: evidence_age(
                        observation.observed_at_unix_ms,
                        evaluated_at_unix_ms,
                        evidence_ttl_ms,
                    ),
                    observation,
                    custody,
                    evaluated_at_unix_ms,
                    evidence_ttl_ms,
                })
            })
            .collect::<Result<Vec<_>, CanonicalStoreError>>()?;
        Ok(ExternalObservationExportV1 {
            schema: EXTERNAL_OBSERVATION_EXPORT_SCHEMA_V1.into(),
            query,
            matches,
        })
    }

    /// Owner-internal exact lookup used by composition. Unlike the export
    /// path, this returns no caller-selected age classification; eligibility
    /// and currentness policy belong to the composition profile and canonical
    /// resolver respectively.
    pub(crate) fn external_observation_for_composition(
        &self,
        observation_id: &str,
    ) -> Result<
        Option<(
            LocalComposeWorldObservationV1,
            ExternalObservationCustodyProvenanceV1,
        )>,
        CanonicalStoreError,
    > {
        require_digest("external observation_id", observation_id)?;
        let row = self
            .connection
            .query_row(
                "SELECT observation_json, custody_json
                 FROM canonical_external_observations WHERE observation_id=?1",
                [observation_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let Some((observation_json, custody_json)) = row else {
            return Ok(None);
        };
        let observation =
            serde_json::from_str::<LocalComposeWorldObservationV1>(&observation_json)?;
        let custody =
            serde_json::from_str::<ExternalObservationCustodyProvenanceV1>(&custody_json)?;
        observation
            .validate()
            .map_err(CanonicalStoreError::Replay)?;
        custody.validate().map_err(CanonicalStoreError::Replay)?;
        if observation.observation_id != custody.observation_id
            || observation.campaign_id != custody.campaign_id
            || observation.occurrence_id != custody.occurrence_id
            || observation.exact_work_id != custody.exact_work_id
            || observation.attempt_id != custody.attempt_id
            || observation.settlement_id != custody.settlement_id
            || observation.executor_evidence_receipt != custody.executor_evidence_receipt
        {
            return Err(CanonicalStoreError::Replay(
                "external-observation composition source is contradictory".into(),
            ));
        }
        Ok(Some((observation, custody)))
    }

    /// Every durable use of one exact source observation. This prevents a
    /// historical predecessor observation from being silently rebound to a
    /// different successor occurrence.
    pub(crate) fn external_compositions_for_source(
        &self,
        source_observation_id: &str,
    ) -> Result<Vec<ComposedExternalEvidenceV1>, CanonicalStoreError> {
        require_digest("source_observation_id", source_observation_id)?;
        let mut statement = self.connection.prepare(
            "SELECT snapshot_json FROM canonical_observation_cycles
             WHERE observation_id IS NOT NULL ORDER BY cycle_id",
        )?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let mut matches = Vec::new();
        for json in rows {
            let cycle: ObservationCycleV1 = serde_json::from_str(&json)?;
            cycle.validate()?;
            if let Some(composition) = cycle
                .observation
                .as_ref()
                .and_then(|observation| observation.external_evidence.as_ref())
                .filter(|composition| composition.source_observation_id == source_observation_id)
            {
                matches.push(composition.clone());
            }
        }
        Ok(matches)
    }

    /// Re-resolve and recompose the exact source record. A persisted
    /// composition is contradictory if its custody source disappeared,
    /// changed, or no longer reproduces the same owner-produced receipt.
    pub(crate) fn validate_external_composition_source(
        &self,
        composition: &ComposedExternalEvidenceV1,
    ) -> Result<(), CanonicalStoreError> {
        composition
            .validate()
            .map_err(CanonicalStoreError::Invalid)?;
        let (observation, custody) = self
            .external_observation_for_composition(&composition.source_observation_id)?
            .ok_or_else(|| {
                CanonicalStoreError::Replay("composed external-evidence source is absent".into())
            })?;
        let rebuilt = ComposedExternalEvidenceV1::compose(
            &ExternalEvidenceReferenceV1 {
                schema: EXTERNAL_EVIDENCE_REFERENCE_SCHEMA_V1.into(),
                source_observation_id: composition.source_observation_id.clone(),
                source_custody_id: composition.source_custody_id.clone(),
                profile_id: composition.profile.profile_id.clone(),
            },
            &composition.profile,
            &observation,
            &custody,
            composition.admitted_at,
            &composition.target_campaign_id,
            &composition.target_occurrence_id,
            &composition.subject_id,
            &composition.subject_digest,
            &composition.scope_digest,
        )
        .map_err(CanonicalStoreError::Replay)?;
        if rebuilt != *composition {
            return Err(CanonicalStoreError::Replay(
                "composed external evidence does not reproduce from canonical custody".into(),
            ));
        }
        Ok(())
    }

    /// Reconstruct a decision-relative composition from both independently
    /// custodied sources. Neither historical qualification nor passive
    /// evidence can remain applicable if its exact source projection changes.
    pub(crate) fn validate_decision_composition_source(
        &self,
        composition: &ComposedDecisionRelativeEvidenceV1,
    ) -> Result<(), CanonicalStoreError> {
        composition
            .validate()
            .map_err(CanonicalStoreError::Invalid)?;
        let (qualification, qualification_custody) = self
            .external_observation_for_composition(&composition.qualification.source_observation_id)?
            .ok_or_else(|| {
                CanonicalStoreError::Replay(
                    "decision composition qualification source is absent".into(),
                )
            })?;
        let (steady, steady_custody) = self
            .steady_state_observation_for_composition(&composition.steady_state_observation_id)?
            .ok_or_else(|| {
                CanonicalStoreError::Replay("decision composition passive source is absent".into())
            })?;
        let reference = DecisionRelativeEvidenceReferenceV1 {
            schema: DECISION_EVIDENCE_REFERENCE_SCHEMA_V1.into(),
            qualification_observation_id: qualification.observation_id.clone(),
            qualification_custody_id: qualification_custody.custody_id.clone(),
            steady_state_observation_id: steady.observation_id.clone(),
            steady_state_custody_id: steady_custody.custody_id.clone(),
            profile_id: composition.profile.profile_id.clone(),
        };
        let rebuilt = ComposedDecisionRelativeEvidenceV1::compose(
            &reference,
            &composition.profile,
            &qualification,
            &qualification_custody,
            &steady,
            &steady_custody,
            composition.admitted_at,
            &composition.target_campaign_id,
            &composition.target_occurrence_id,
            &composition.subject_id,
            &composition.subject_digest,
            &composition.scope_digest,
        )
        .map_err(CanonicalStoreError::Replay)?;
        if rebuilt != *composition {
            return Err(CanonicalStoreError::Replay(
                "decision composition does not reproduce from exact custody".into(),
            ));
        }
        Ok(())
    }

    /// Read-only export of every persisted observation with one exact
    /// `observation_id`, including each match's derived lineage position and
    /// its family's latest qualified observation.
    pub fn export_observation(
        &self,
        observation_id: &str,
    ) -> Result<ObservationExportV1, CanonicalStoreError> {
        let mut matches = Vec::new();
        for cycle in self.find_cycles_by_observation_id(observation_id)? {
            let family = ObservationFamilyKeyV1::of_slot(&cycle.slot);
            let latest = self.latest_qualified_observation_in_family(&family)?;
            matches.push(ObservationExportMatchV1 {
                cycle_id: cycle.cycle_id.as_str().to_owned(),
                slot_id: cycle.slot.slot_id.as_str().to_owned(),
                family,
                order_key: ObservationOrderKeyV1::of_slot(&cycle.slot),
                family_latest_cycle_id: latest
                    .as_ref()
                    .map(|value| value.cycle_id.as_str().to_owned()),
                family_latest_order_key: latest
                    .as_ref()
                    .map(|value| ObservationOrderKeyV1::of_slot(&value.slot)),
                observation: cycle.observation.ok_or_else(|| {
                    CanonicalStoreError::Invalid(
                        "observation_id index names a cycle without an observation".into(),
                    )
                })?,
            });
        }
        Ok(ObservationExportV1 {
            schema: OBSERVATION_EXPORT_SCHEMA_V1.into(),
            observation_id: observation_id.into(),
            matches,
        })
    }

    /// Classify restart without recreating freshness. Local in-flight cycles
    /// become `RecoveryRequired`; AG-bound cycles remain exact references that
    /// must be queried through AG.
    pub fn recover_after_restart(
        &mut self,
        now: DateTime<Utc>,
    ) -> Result<Vec<ObservationCycleV1>, CanonicalStoreError> {
        let cycles = self.list_cycles()?;
        let mut recovered = Vec::new();
        for cycle in cycles {
            match cycle.status {
                CycleStatusV1::Observing | CycleStatusV1::PostureRecorded => {
                    let id = cycle.cycle_id.clone();
                    recovered.push(self.transition(
                        &id,
                        None,
                        &cycle.state_digest,
                        "restart_local_currentness_erased",
                        now,
                        |value| {
                            value.status = CycleStatusV1::RecoveryRequired;
                            value.recovery_reason = Some(
                                "restart erased live observation support; start a fresh cycle"
                                    .into(),
                            );
                            Ok(())
                        },
                    )?);
                }
                CycleStatusV1::AwaitingAg | CycleStatusV1::AwaitingAgReconciliation => {
                    // Exact AG reference is returned for a read-only AG status query.
                    recovered.push(cycle);
                }
                CycleStatusV1::RecoveryRequired if cycle.prepared_ag_request.is_some() => {
                    // A crash or lost response after durable preparation is resolved only
                    // by querying the exact occurrence through AG. Never resubmit here.
                    recovered.push(cycle);
                }
                _ => {}
            }
        }
        Ok(recovered)
    }

    pub fn replay(
        &self,
        cycle_id: &ObservationCycleId,
    ) -> Result<Vec<ObservationCycleV1>, CanonicalStoreError> {
        let mut statement = self.connection.prepare(
            "SELECT sequence, prior_state_digest, resulting_state_digest, snapshot_json
             FROM canonical_cycle_events WHERE cycle_id=?1 ORDER BY sequence",
        )?;
        let rows = statement.query_map([cycle_id.as_str()], |row| {
            Ok((
                row.get::<_, u64>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        let mut result = Vec::new();
        let mut expected_prior: Option<String> = None;
        for row in rows {
            let (sequence, prior, resulting, json) = row?;
            if sequence != result.len() as u64 || prior != expected_prior {
                return Err(CanonicalStoreError::Replay(
                    "event sequence or predecessor chain diverged".into(),
                ));
            }
            let cycle: ObservationCycleV1 = serde_json::from_str(&json)?;
            cycle.validate()?;
            if cycle.state_digest != resulting || cycle.prior_state_digest != prior {
                return Err(CanonicalStoreError::Replay(
                    "event digest does not bind stored snapshot".into(),
                ));
            }
            expected_prior = Some(resulting);
            result.push(cycle);
        }
        let current = self.get_cycle(cycle_id)?;
        if result.last() != Some(&current) {
            return Err(CanonicalStoreError::Replay(
                "authoritative row differs from replay tail".into(),
            ));
        }
        Ok(result)
    }

    fn transition<F>(
        &mut self,
        cycle_id: &ObservationCycleId,
        lease: Option<&LiveCycleLeaseV1>,
        expected_digest: &str,
        event_kind: &str,
        now: DateTime<Utc>,
        mutate: F,
    ) -> Result<ObservationCycleV1, CanonicalStoreError>
    where
        F: FnOnce(&mut ObservationCycleV1) -> Result<(), CanonicalStoreError>,
    {
        if let Some(lease) = lease {
            if lease.cycle_id != *cycle_id || lease.process_nonce.is_nil() {
                return Err(CanonicalStoreError::WrongLiveLease);
            }
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let json: Option<String> = tx
            .query_row(
                "SELECT snapshot_json FROM canonical_observation_cycles WHERE cycle_id=?1",
                [cycle_id.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        let mut cycle: ObservationCycleV1 = serde_json::from_str(
            &json.ok_or_else(|| CanonicalStoreError::CycleNotFound(cycle_id.0.clone()))?,
        )?;
        cycle.validate()?;
        let durable_claim: Option<(String, String, String)> = tx
            .query_row(
                "SELECT campaign_id, occurrence_id, request_digest
                 FROM canonical_ag_occurrence_claims WHERE cycle_id=?1",
                [cycle_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        match (&cycle.prepared_ag_request, durable_claim) {
            (None, None) => {}
            (Some(request), Some((campaign, occurrence, digest)))
                if campaign == request.campaign_id
                    && occurrence == request.occurrence_id
                    && digest == request.request_digest => {}
            _ => {
                return Err(CanonicalStoreError::Replay(
                    "AG occurrence claim diverged before transition".into(),
                ));
            }
        }
        let durable_authoring: Option<String> = tx
            .query_row(
                "SELECT record_json FROM canonical_authoring_context_provenance
                 WHERE cycle_id=?1",
                [cycle_id.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        let durable_authoring = durable_authoring
            .map(|json| serde_json::from_str::<AuthoringContextProvenanceV1>(&json))
            .transpose()?;
        if cycle.authoring_context_provenance != durable_authoring {
            return Err(CanonicalStoreError::Replay(
                "authoring-context claim diverged before transition".into(),
            ));
        }
        let durable_custody: Option<String> = tx
            .query_row(
                "SELECT record_json FROM canonical_authoring_context_custody
                 WHERE cycle_id=?1",
                [cycle_id.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        let durable_custody = durable_custody
            .map(|json| serde_json::from_str::<AuthoringContextCustodyProvenanceV1>(&json))
            .transpose()?;
        if cycle.authoring_context_custody != durable_custody {
            return Err(CanonicalStoreError::Replay(
                "authoring-context custody claim diverged before transition".into(),
            ));
        }
        if cycle.state_digest != expected_digest {
            return Err(CanonicalStoreError::StalePredecessor);
        }
        let prior = cycle.state_digest.clone();
        let had_prepared_ag_request = cycle.prepared_ag_request.is_some();
        let had_authoring_context = cycle.authoring_context_provenance.is_some();
        let had_authoring_custody = cycle.authoring_context_custody.is_some();
        mutate(&mut cycle)?;
        cycle.version = cycle
            .version
            .checked_add(1)
            .ok_or_else(|| CanonicalStoreError::Invalid("cycle version overflow".into()))?;
        cycle.prior_state_digest = Some(prior.clone());
        cycle.updated_at = timestamp(now);
        cycle.seal()?;
        cycle.validate()?;
        if !had_prepared_ag_request {
            if let Some(request) = &cycle.prepared_ag_request {
                let inserted = tx.execute(
                    "INSERT OR IGNORE INTO canonical_ag_occurrence_claims
                     (campaign_id, occurrence_id, cycle_id, request_digest, claimed_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        &request.campaign_id,
                        &request.occurrence_id,
                        cycle_id.as_str(),
                        &request.request_digest,
                        &cycle.updated_at,
                    ],
                )?;
                if inserted != 1 {
                    return Err(CanonicalStoreError::DuplicateAgOccurrence(
                        request.campaign_id.clone(),
                        request.occurrence_id.clone(),
                    ));
                }
            }
        }
        if !had_authoring_context {
            if let Some(provenance) = &cycle.authoring_context_provenance {
                let inserted = tx.execute(
                    "INSERT OR IGNORE INTO canonical_authoring_context_provenance
                     (provenance_id, cycle_id, campaign_id, occurrence_id, proposal_id,
                      exact_work_id, source_intent_id, maude_plan_ref, maude_session_id,
                      record_json, recorded_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                    params![
                        &provenance.provenance_id,
                        cycle_id.as_str(),
                        &provenance.campaign_id,
                        &provenance.occurrence_id,
                        &provenance.proposal_id,
                        &provenance.exact_work_id,
                        &provenance.source_intent_id,
                        &provenance.maude_plan_ref,
                        &provenance.maude_session_id,
                        canonical_json(provenance)?,
                        timestamp(provenance.recorded_at),
                    ],
                )?;
                if inserted != 1 {
                    return Err(CanonicalStoreError::Invalid(
                        "governed occurrence already has a different authoring-context relation"
                            .into(),
                    ));
                }
            }
        }
        if !had_authoring_custody {
            if let Some(custody) = &cycle.authoring_context_custody {
                let inserted = tx.execute(
                    "INSERT OR IGNORE INTO canonical_authoring_context_custody
                     (custody_id, cycle_id, handoff_id, session_record_id,
                      authoring_context_provenance_id, campaign_id, occurrence_id,
                      proposal_id, exact_work_id, producer_principal_id,
                      producer_key_id, session_issuer_principal_id,
                      session_issuer_key_id, target_runtime_id, target_request_id,
                      maude_plan_ref, maude_session_id, record_json, recorded_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                             ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
                    params![
                        &custody.custody_id,
                        cycle_id.as_str(),
                        &custody.handoff_id,
                        &custody.session_record_id,
                        &custody.authoring_context_provenance_id,
                        &custody.campaign_id,
                        &custody.occurrence_id,
                        &custody.proposal_id,
                        &custody.exact_work_id,
                        &custody.producer_principal_id,
                        &custody.producer_key_id,
                        &custody.session_issuer_principal_id,
                        &custody.session_issuer_key_id,
                        &custody.target_runtime_id,
                        &custody.target_request_id,
                        &custody.maude_plan_ref,
                        &custody.maude_session_id,
                        canonical_json(custody)?,
                        timestamp(custody.recorded_at),
                    ],
                )?;
                if inserted != 1 {
                    return Err(CanonicalStoreError::Invalid(
                        "governed occurrence already has different authoring custody".into(),
                    ));
                }
            }
        }
        let changed = tx.execute(
            "UPDATE canonical_observation_cycles
             SET version=?1, status=?2, state_digest=?3, snapshot_json=?4, updated_at=?5,
                 observation_id=?8
             WHERE cycle_id=?6 AND state_digest=?7",
            params![
                cycle.version,
                cycle.status.as_db(),
                &cycle.state_digest,
                canonical_json(&cycle)?,
                &cycle.updated_at,
                cycle_id.as_str(),
                &prior,
                cycle
                    .observation
                    .as_ref()
                    .map(|record| record.observation_id.as_str()),
            ],
        )?;
        if changed != 1 {
            return Err(CanonicalStoreError::StalePredecessor);
        }
        let slot_changed = tx.execute(
            "UPDATE canonical_recurrence_slots
             SET status=?1, state_digest=?2, updated_at=?3
             WHERE slot_id=?4 AND state_digest=?5",
            params![
                cycle.status.as_db(),
                &cycle.state_digest,
                &cycle.updated_at,
                cycle.slot.slot_id.as_str(),
                &prior,
            ],
        )?;
        if slot_changed != 1 {
            return Err(CanonicalStoreError::StalePredecessor);
        }
        tx.execute(
            "INSERT INTO canonical_cycle_events
             (cycle_id, sequence, event_kind, prior_state_digest, resulting_state_digest,
              snapshot_json, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                cycle_id.as_str(),
                cycle.version,
                event_kind,
                &prior,
                &cycle.state_digest,
                canonical_json(&cycle)?,
                &cycle.updated_at,
            ],
        )?;
        tx.commit()?;
        Ok(cycle)
    }

    fn validate_ag_occurrence_claim(
        &self,
        cycle: &ObservationCycleV1,
    ) -> Result<(), CanonicalStoreError> {
        let claim: Option<(String, String, String)> = self
            .connection
            .query_row(
                "SELECT campaign_id, occurrence_id, request_digest
                 FROM canonical_ag_occurrence_claims WHERE cycle_id=?1",
                [cycle.cycle_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        match (&cycle.prepared_ag_request, claim) {
            (None, None) => Ok(()),
            (Some(request), Some((campaign, occurrence, digest)))
                if campaign == request.campaign_id
                    && occurrence == request.occurrence_id
                    && digest == request.request_digest =>
            {
                Ok(())
            }
            _ => Err(CanonicalStoreError::Replay(
                "AG occurrence claim does not match the authoritative cycle snapshot".into(),
            )),
        }
    }

    fn validate_authoring_context_claim(
        &self,
        cycle: &ObservationCycleV1,
    ) -> Result<(), CanonicalStoreError> {
        let has_projection = self.connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_master
                WHERE type='table' AND name='canonical_authoring_context_provenance'
             )",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        if !has_projection {
            return if cycle.authoring_context_provenance.is_none() {
                Ok(())
            } else {
                Err(CanonicalStoreError::Replay(
                    "authoring-context snapshot exists without its durable projection".into(),
                ))
            };
        }
        let claim: Option<String> = self
            .connection
            .query_row(
                "SELECT record_json FROM canonical_authoring_context_provenance
                 WHERE cycle_id=?1",
                [cycle.cycle_id.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        let claim = claim
            .map(|json| serde_json::from_str::<AuthoringContextProvenanceV1>(&json))
            .transpose()?;
        match (&cycle.authoring_context_provenance, claim) {
            (None, None) => Ok(()),
            (Some(snapshot), Some(durable)) if snapshot == &durable => {
                durable.validate().map_err(CanonicalStoreError::Invalid)
            }
            _ => Err(CanonicalStoreError::Replay(
                "authoring-context claim does not match the authoritative cycle snapshot".into(),
            )),
        }
    }

    fn validate_authoring_custody_claim(
        &self,
        cycle: &ObservationCycleV1,
    ) -> Result<(), CanonicalStoreError> {
        let has_projection = self.connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_master
                WHERE type='table' AND name='canonical_authoring_context_custody'
             )",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        if !has_projection {
            return if cycle.authoring_context_custody.is_none() {
                Ok(())
            } else {
                Err(CanonicalStoreError::Replay(
                    "authoring custody snapshot exists without its durable projection".into(),
                ))
            };
        }
        let claim: Option<String> = self
            .connection
            .query_row(
                "SELECT record_json FROM canonical_authoring_context_custody
                 WHERE cycle_id=?1",
                [cycle.cycle_id.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        let claim = claim
            .map(|json| serde_json::from_str::<AuthoringContextCustodyProvenanceV1>(&json))
            .transpose()?;
        match (&cycle.authoring_context_custody, claim) {
            (None, None) => Ok(()),
            (Some(snapshot), Some(durable)) if snapshot == &durable => {
                durable.validate().map_err(CanonicalStoreError::Invalid)
            }
            _ => Err(CanonicalStoreError::Replay(
                "authoring custody claim does not match the authoritative cycle snapshot".into(),
            )),
        }
    }
}

fn insert_initial_cycle(
    tx: &Transaction<'_>,
    cycle: &ObservationCycleV1,
    event_kind: &str,
) -> Result<(), CanonicalStoreError> {
    let json = canonical_json(cycle)?;
    tx.execute(
        "INSERT INTO canonical_observation_cycles
         (cycle_id, slot_id, version, status, state_digest, snapshot_json, updated_at,
          observation_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            cycle.cycle_id.as_str(),
            cycle.slot.slot_id.as_str(),
            cycle.version,
            cycle.status.as_db(),
            &cycle.state_digest,
            &json,
            &cycle.updated_at,
            cycle
                .observation
                .as_ref()
                .map(|record| record.observation_id.as_str()),
        ],
    )?;
    tx.execute(
        "INSERT INTO canonical_cycle_events
         (cycle_id, sequence, event_kind, prior_state_digest, resulting_state_digest,
          snapshot_json, recorded_at)
         VALUES (?1, 0, ?2, NULL, ?3, ?4, ?5)",
        params![
            cycle.cycle_id.as_str(),
            event_kind,
            &cycle.state_digest,
            &json,
            &cycle.updated_at,
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;

    fn time(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&Utc)
    }

    fn origin_node(
        tag: &str,
        predecessor: Option<&SubstrateOriginApplicabilityV1>,
    ) -> SubstrateOriginApplicabilityV1 {
        let mut value = SubstrateOriginApplicabilityV1 {
            schema: crate::substrate_origin::APPLICABILITY_SCHEMA_V1.into(),
            applicability_id: String::new(),
            status: SubstrateOriginApplicabilityStatusV1::Applicable,
            reason: if predecessor.is_some() {
                crate::substrate_origin::SubstrateOriginApplicabilityReasonV1::StableExactOrigin
            } else {
                crate::substrate_origin::SubstrateOriginApplicabilityReasonV1::BootstrapOriginEstablished
            },
            profile_id: "profile-origin-v3".into(),
            diagnostic_artifact_id: digest(tag.chars().next().unwrap()),
            subject_ref: "observer:test-office".into(),
            predecessor_applicability_id: predecessor.map(|item| item.applicability_id.clone()),
            predecessor_coordinate_ref: predecessor
                .map(|item| item.observed_coordinate_ref.clone()),
            observed_coordinate_ref: format!("substrate:attester-key:v1:{tag}"),
            attestation_occurrence_ref: format!("attestation:{tag}"),
            acquisition_id: format!("acquisition:{tag}"),
            provider_intake_ref: format!("intake:{tag}"),
            authority_occurrence_ref: None,
        };
        value.applicability_id = object_id(&value, "applicability_id").unwrap();
        value.validate().unwrap();
        value
    }

    #[test]
    fn substrate_origin_history_has_one_exact_append_only_head() {
        let first = origin_node(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            None,
        );
        let second = origin_node(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            Some(&first),
        );
        let nodes = BTreeMap::from([
            (first.applicability_id.clone(), first),
            (second.applicability_id.clone(), second.clone()),
        ]);
        assert_eq!(
            unique_substrate_origin_head(nodes)
                .unwrap()
                .applicability_id,
            second.applicability_id
        );
    }

    #[test]
    fn substrate_origin_history_refuses_forks_and_predecessor_substitution() {
        let first = origin_node(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            None,
        );
        let second = origin_node(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            Some(&first),
        );
        let third = origin_node(
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            Some(&first),
        );
        let fork = BTreeMap::from([
            (first.applicability_id.clone(), first.clone()),
            (second.applicability_id.clone(), second),
            (third.applicability_id.clone(), third),
        ]);
        assert!(unique_substrate_origin_head(fork)
            .unwrap_err()
            .to_string()
            .contains("forks"));

        let mut substituted = origin_node(
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            Some(&first),
        );
        substituted.predecessor_coordinate_ref = Some(
            "substrate:attester-key:v1:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                .into(),
        );
        substituted.applicability_id = object_id(&substituted, "applicability_id").unwrap();
        let nodes = BTreeMap::from([
            (first.applicability_id.clone(), first),
            (substituted.applicability_id.clone(), substituted),
        ]);
        assert!(unique_substrate_origin_head(nodes)
            .unwrap_err()
            .to_string()
            .contains("substitutes predecessor"));
    }

    fn slot(trigger: RecurrenceTriggerV1) -> RecurrenceSlotV1 {
        RecurrenceSlotV1::new(
            "policy-1".into(),
            "config-1".into(),
            "subject-1".into(),
            "scope-1".into(),
            "nightshift-scheduler-1".into(),
            time("2026-08-11T12:00:00Z"),
            time("2026-08-11T12:05:00Z"),
            7,
            trigger,
            None,
        )
        .unwrap()
    }

    #[test]
    fn exact_slot_identity_does_not_use_nq_generation() {
        let first = slot(RecurrenceTriggerV1::Scheduled);
        let mut second = first.clone();
        second.occurrence += 1;
        second.slot_id = RecurrenceSlotId(object_id(&second, "slot_id").unwrap());
        assert_ne!(first.slot_id, second.slot_id);
    }

    #[test]
    fn duplicate_slot_claim_fails_closed_across_connections() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("nightshift.sqlite");
        let mut first = CanonicalStore::open(&database).unwrap();
        first
            .claim_slot(
                slot(RecurrenceTriggerV1::Scheduled),
                "nightshift-scheduler-1",
                time("2026-08-11T12:00:00Z"),
            )
            .unwrap();
        let mut second = CanonicalStore::open(&database).unwrap();
        assert!(matches!(
            second.claim_slot(
                slot(RecurrenceTriggerV1::Scheduled),
                "nightshift-scheduler-1",
                time("2026-08-11T12:00:01Z")
            ),
            Err(CanonicalStoreError::DuplicateSlot(_))
        ));
    }

    #[test]
    fn concurrent_slot_claim_has_one_winner() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("nightshift.sqlite");
        CanonicalStore::open(&database).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let database = database.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let mut store = CanonicalStore::open(database).unwrap();
                    barrier.wait();
                    store
                        .claim_slot(
                            slot(RecurrenceTriggerV1::Scheduled),
                            "nightshift-scheduler-1",
                            time("2026-08-11T12:00:00Z"),
                        )
                        .is_ok()
                })
            })
            .collect();
        assert_eq!(
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .filter(|won| *won)
                .count(),
            1
        );
    }

    #[test]
    fn equality_is_slot_valid_and_after_latest_is_missed() {
        let value = slot(RecurrenceTriggerV1::Scheduled);
        assert_eq!(
            value
                .timing_at("nightshift-scheduler-1", time("2026-08-11T12:05:00Z"))
                .unwrap(),
            SlotTimingV1::Late
        );
        assert_eq!(
            value
                .timing_at("nightshift-scheduler-1", time("2026-08-11T12:05:01Z"))
                .unwrap(),
            SlotTimingV1::Missed
        );
    }

    #[test]
    fn missed_slot_is_durable_and_catch_up_is_a_distinct_slot() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("nightshift.sqlite");
        let mut store = CanonicalStore::open(&database).unwrap();
        let missed_slot = slot(RecurrenceTriggerV1::Scheduled);
        let missed = store
            .record_missed(
                missed_slot.clone(),
                "nightshift-scheduler-1",
                time("2026-08-11T12:05:01Z"),
                "scheduler_observed_missed_slot".into(),
            )
            .unwrap();
        assert_eq!(missed.status, CycleStatusV1::Missed);
        let catch_up = RecurrenceSlotV1::new(
            "policy-1".into(),
            "config-1".into(),
            "subject-1".into(),
            "scope-1".into(),
            "nightshift-scheduler-1".into(),
            time("2026-08-11T12:06:00Z"),
            time("2026-08-11T12:07:00Z"),
            8,
            RecurrenceTriggerV1::CatchUp,
            Some(missed_slot.slot_id.clone()),
        )
        .unwrap();
        assert_ne!(catch_up.slot_id, missed_slot.slot_id);
        let (caught_up, _) = store
            .claim_slot(
                catch_up,
                "nightshift-scheduler-1",
                time("2026-08-11T12:06:00Z"),
            )
            .unwrap();
        assert_eq!(caught_up.timing, SlotTimingV1::CatchUp);
    }

    #[test]
    fn restart_erases_local_currentness_and_replay_is_exact() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("nightshift.sqlite");
        let cycle_id = {
            let mut store = CanonicalStore::open(&database).unwrap();
            let (cycle, _lease) = store
                .claim_slot(
                    slot(RecurrenceTriggerV1::Scheduled),
                    "nightshift-scheduler-1",
                    time("2026-08-11T12:00:00Z"),
                )
                .unwrap();
            cycle.cycle_id
        };
        let mut restarted = CanonicalStore::open(&database).unwrap();
        let recovered = restarted
            .recover_after_restart(time("2026-08-11T12:01:00Z"))
            .unwrap();
        assert_eq!(recovered[0].status, CycleStatusV1::RecoveryRequired);
        assert_eq!(restarted.replay(&cycle_id).unwrap().len(), 2);
    }

    #[test]
    fn stale_predecessor_cannot_create_two_successors() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("nightshift.sqlite");
        let mut store = CanonicalStore::open(&database).unwrap();
        let (cycle, _lease) = store
            .claim_slot(
                slot(RecurrenceTriggerV1::Scheduled),
                "nightshift-scheduler-1",
                time("2026-08-11T12:00:00Z"),
            )
            .unwrap();
        let first = store
            .transition(
                &cycle.cycle_id,
                None,
                &cycle.state_digest,
                "test_recovery",
                time("2026-08-11T12:01:00Z"),
                |value| {
                    value.status = CycleStatusV1::RecoveryRequired;
                    Ok(())
                },
            )
            .unwrap();
        assert!(matches!(
            store.transition(
                &cycle.cycle_id,
                None,
                &cycle.state_digest,
                "stale",
                time("2026-08-11T12:02:00Z"),
                |_| Ok(())
            ),
            Err(CanonicalStoreError::StalePredecessor)
        ));
        assert_eq!(store.replay(&cycle.cycle_id).unwrap().last(), Some(&first));
    }

    #[test]
    fn concurrent_reconcilers_have_one_cas_winner() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("nightshift.sqlite");
        let cycle = {
            let mut store = CanonicalStore::open(&database).unwrap();
            store
                .claim_slot(
                    slot(RecurrenceTriggerV1::Scheduled),
                    "nightshift-scheduler-1",
                    time("2026-08-11T12:00:00Z"),
                )
                .unwrap()
                .0
        };
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|index| {
                let database = database.clone();
                let barrier = Arc::clone(&barrier);
                let cycle_id = cycle.cycle_id.clone();
                let digest = cycle.state_digest.clone();
                thread::spawn(move || {
                    let mut store = CanonicalStore::open(database).unwrap();
                    barrier.wait();
                    store
                        .mark_recovery_required(
                            &cycle_id,
                            &digest,
                            format!("reconciler_{index}"),
                            time("2026-08-11T12:01:00Z"),
                        )
                        .is_ok()
                })
            })
            .collect();
        assert_eq!(
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .filter(|won| *won)
                .count(),
            1
        );
    }

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn example_policy_inputs_recurrence() -> (
        crate::diagnostic_posture::PosturePolicy,
        crate::diagnostic_posture::DiagnosticInputs,
        crate::diagnostic_posture::RecurrenceEvidence,
    ) {
        (
            serde_json::from_str(include_str!(
                "../../../docs/operator/examples/diagnostic-posture-v1/policy.json"
            ))
            .unwrap(),
            serde_json::from_str(include_str!(
                "../../../docs/operator/examples/diagnostic-posture-v1/inputs.json"
            ))
            .unwrap(),
            serde_json::from_str(include_str!(
                "../../../docs/operator/examples/diagnostic-posture-v1/recurrence.json"
            ))
            .unwrap(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn slot_with_ids(
        policy_id: &str,
        configuration_version: &str,
        subject_id: &str,
        scope_id: &str,
        scheduler_clock_id: &str,
        occurrence: u64,
        trigger: RecurrenceTriggerV1,
        catch_up_of: Option<RecurrenceSlotId>,
    ) -> RecurrenceSlotV1 {
        let nominal = time("2026-08-11T12:00:00Z") + chrono::Duration::minutes(occurrence as i64);
        RecurrenceSlotV1::new(
            policy_id.into(),
            configuration_version.into(),
            subject_id.into(),
            scope_id.into(),
            scheduler_clock_id.into(),
            nominal,
            nominal + chrono::Duration::minutes(5),
            occurrence,
            trigger,
            catch_up_of,
        )
        .unwrap()
    }

    fn example_slot(occurrence: u64) -> RecurrenceSlotV1 {
        let (policy, _, _) = example_policy_inputs_recurrence();
        slot_with_ids(
            &policy.policy_id,
            "config-v1",
            &policy.subject.id,
            &policy.subject.scope.digest,
            "nightshift-scheduler-1",
            occurrence,
            RecurrenceTriggerV1::Scheduled,
            None,
        )
    }

    fn support_for(
        cycle_id: &ObservationCycleId,
        observation_id: &str,
        inputs: &crate::diagnostic_posture::DiagnosticInputs,
        policy: &crate::diagnostic_posture::PosturePolicy,
    ) -> crate::currentness::QualifiedSupportV1 {
        let mut support = crate::currentness::QualifiedSupportV1 {
            schema: crate::currentness::QUALIFIED_SUPPORT_SCHEMA_V1.into(),
            support_id: String::new(),
            authority_id: "pulse-receiver-1".into(),
            query_id: digest('e'),
            observation_cycle_id: cycle_id.as_str().into(),
            request_nonce: "support-query:test-nonce".into(),
            observation_id: observation_id.into(),
            diagnostic_inputs_id: inputs.inputs_id.clone(),
            subject_id: policy.subject.id.clone(),
            scope_id: policy.subject.scope.digest.clone(),
            artifact_ids: crate::currentness::delivered_artifact_ids(inputs),
            evaluated_at: crate::currentness::SupportReceiverInstantV1 {
                clock_id: "pulse-receiver-clock-1".into(),
                tick: 100,
            },
            expiry: Some(crate::currentness::SupportExpiryV1 {
                clock_id: "pulse-receiver-clock-1".into(),
                tick: 101,
            }),
            standing: crate::currentness::SupportStandingV1::Current,
            evidence_refs: vec![digest('9')],
            contradiction_refs: Vec::new(),
        };
        support.support_id = support.computed_support_id().unwrap();
        support
    }

    fn observation_for(cycle_id: &ObservationCycleId, observation_id: &str) -> ObservationRecordV1 {
        let (policy, inputs, recurrence) = example_policy_inputs_recurrence();
        let support = support_for(cycle_id, observation_id, &inputs, &policy);
        let posture = crate::diagnostic_posture::evaluate_posture_with_support(
            &policy,
            &inputs,
            &recurrence,
            time("2026-07-27T20:00:10Z"),
            &support,
        )
        .unwrap();
        ObservationRecordV1 {
            schema: OBSERVATION_RECORD_SCHEMA_V1.into(),
            observation_id: observation_id.into(),
            source_admissions: Vec::new(),
            continuity_applicability: Vec::new(),
            substrate_origin_applicability: Vec::new(),
            external_evidence: None,
            decision_external_evidence: None,
            support,
            posture,
        }
    }

    fn record_test_observation(
        store: &mut CanonicalStore,
        slot: RecurrenceSlotV1,
        clock: &str,
        observation_id: &str,
        now: DateTime<Utc>,
    ) -> ObservationCycleV1 {
        let (cycle, lease) = store.claim_slot(slot, clock, now).unwrap();
        let observation = observation_for(&cycle.cycle_id, observation_id);
        let attention = AttentionRecordV1 {
            class: AttentionClassV1::Display,
            source_posture_id: observation.posture.posture_id.clone(),
            reason_code: "posture_observed".into(),
            display_text: None,
        };
        store
            .record_observation(
                &lease,
                &cycle.state_digest,
                observation,
                attention,
                None,
                now,
            )
            .unwrap()
    }

    #[test]
    fn record_observation_populates_the_queryable_observation_id() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        let recorded = record_test_observation(
            &mut store,
            example_slot(1),
            "nightshift-scheduler-1",
            &digest('a'),
            time("2026-08-11T12:01:00Z"),
        );
        let matches = store.find_cycles_by_observation_id(&digest('a')).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].cycle_id, recorded.cycle_id);
        assert_eq!(
            matches[0].observation.as_ref().unwrap().observation_id,
            digest('a')
        );
    }

    #[test]
    fn observation_lookup_miss_returns_zero_matches() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        record_test_observation(
            &mut store,
            example_slot(1),
            "nightshift-scheduler-1",
            &digest('a'),
            time("2026-08-11T12:01:00Z"),
        );
        assert!(store
            .find_cycles_by_observation_id(&digest('b'))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn observation_lookup_preserves_ambiguous_shared_ids() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        let first = record_test_observation(
            &mut store,
            example_slot(1),
            "nightshift-scheduler-1",
            &digest('a'),
            time("2026-08-11T12:01:00Z"),
        );
        let second = record_test_observation(
            &mut store,
            example_slot(2),
            "nightshift-scheduler-1",
            &digest('a'),
            time("2026-08-11T12:02:00Z"),
        );
        let matches = store.find_cycles_by_observation_id(&digest('a')).unwrap();
        assert_eq!(matches.len(), 2);
        let ids: Vec<_> = matches.iter().map(|cycle| cycle.cycle_id.clone()).collect();
        assert!(ids.contains(&first.cycle_id));
        assert!(ids.contains(&second.cycle_id));
    }

    #[test]
    fn family_latest_uses_logical_occurrence_order_not_write_order() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        // Write the logically later observation first.
        let later = record_test_observation(
            &mut store,
            example_slot(2),
            "nightshift-scheduler-1",
            &digest('b'),
            time("2026-08-11T12:02:00Z"),
        );
        record_test_observation(
            &mut store,
            example_slot(1),
            "nightshift-scheduler-1",
            &digest('a'),
            time("2026-08-11T12:01:00Z"),
        );
        let family = ObservationFamilyKeyV1::of_slot(&later.slot);
        let latest = store
            .latest_qualified_observation_in_family(&family)
            .unwrap()
            .unwrap();
        assert_eq!(latest.cycle_id, later.cycle_id);
        assert_eq!(latest.slot.occurrence, 2);
    }

    #[test]
    fn family_latest_excludes_other_lineages() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        let base = record_test_observation(
            &mut store,
            example_slot(3),
            "nightshift-scheduler-1",
            &digest('a'),
            time("2026-08-11T12:03:00Z"),
        );
        let (policy, _, _) = example_policy_inputs_recurrence();
        let variants = [
            slot_with_ids(
                "policy-other",
                "config-v1",
                &policy.subject.id,
                &policy.subject.scope.digest,
                "nightshift-scheduler-1",
                9,
                RecurrenceTriggerV1::Scheduled,
                None,
            ),
            slot_with_ids(
                &policy.policy_id,
                "config-v2",
                &policy.subject.id,
                &policy.subject.scope.digest,
                "nightshift-scheduler-1",
                9,
                RecurrenceTriggerV1::Scheduled,
                None,
            ),
            slot_with_ids(
                &policy.policy_id,
                "config-v1",
                &policy.subject.id,
                "scope-other",
                "nightshift-scheduler-1",
                9,
                RecurrenceTriggerV1::Scheduled,
                None,
            ),
            slot_with_ids(
                &policy.policy_id,
                "config-v1",
                &policy.subject.id,
                &policy.subject.scope.digest,
                "nightshift-scheduler-2",
                9,
                RecurrenceTriggerV1::Scheduled,
                None,
            ),
        ];
        for (index, variant) in variants.into_iter().enumerate() {
            let clock = variant.scheduler_clock_id.clone();
            record_test_observation(
                &mut store,
                variant,
                &clock,
                &digest(char::from(b'b' + index as u8)),
                time("2026-08-11T12:09:00Z"),
            );
        }
        let family = ObservationFamilyKeyV1::of_slot(&base.slot);
        let latest = store
            .latest_qualified_observation_in_family(&family)
            .unwrap()
            .unwrap();
        assert_eq!(latest.cycle_id, base.cycle_id);
        assert_eq!(latest.slot.occurrence, 3);
    }

    #[test]
    fn a_different_vantage_changes_policy_and_cannot_supersede_the_local_family() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        let (local_policy, _, _) = example_policy_inputs_recurrence();
        let local_slot = slot_with_ids(
            &local_policy.policy_id,
            "config-v1",
            &local_policy.subject.id,
            &local_policy.subject.scope.digest,
            "nightshift-scheduler-1",
            1,
            RecurrenceTriggerV1::Scheduled,
            None,
        );
        let local = record_test_observation(
            &mut store,
            local_slot,
            "nightshift-scheduler-1",
            &digest('a'),
            time("2026-08-11T12:01:00Z"),
        );

        let mut remote_policy = local_policy.clone();
        remote_policy.inventory[0].binding.vantage.id = "nq.vantage.remote.fixture".into();
        remote_policy.inventory[0].binding.vantage.digest = digest('f');
        remote_policy.policy_id.clear();
        remote_policy.policy_id = remote_policy.computed_policy_id().unwrap();
        remote_policy.validate().unwrap();
        assert_ne!(remote_policy.policy_id, local_policy.policy_id);

        let remote_slot = slot_with_ids(
            &remote_policy.policy_id,
            "config-v1",
            &remote_policy.subject.id,
            &remote_policy.subject.scope.digest,
            "nightshift-scheduler-1",
            99,
            RecurrenceTriggerV1::Scheduled,
            None,
        );
        record_test_observation(
            &mut store,
            remote_slot,
            "nightshift-scheduler-1",
            &digest('b'),
            time("2026-08-11T13:39:00Z"),
        );

        let family = ObservationFamilyKeyV1::of_slot(&local.slot);
        let latest = store
            .latest_qualified_observation_in_family(&family)
            .unwrap()
            .unwrap();
        assert_eq!(latest.cycle_id, local.cycle_id);
        assert_eq!(latest.slot.occurrence, 1);
    }

    #[test]
    fn missed_and_recovery_cycles_never_qualify_as_latest() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        let observed = record_test_observation(
            &mut store,
            example_slot(1),
            "nightshift-scheduler-1",
            &digest('a'),
            time("2026-08-11T12:01:00Z"),
        );
        let missed_slot = example_slot(2);
        store
            .record_missed(
                missed_slot,
                "nightshift-scheduler-1",
                time("2026-08-11T12:07:01Z"),
                "scheduler_observed_missed_slot".into(),
            )
            .unwrap();
        let (recovering, _) = store
            .claim_slot(
                example_slot(3),
                "nightshift-scheduler-1",
                time("2026-08-11T12:03:00Z"),
            )
            .unwrap();
        store
            .mark_recovery_required(
                &recovering.cycle_id,
                &recovering.state_digest,
                "restart_local_currentness_erased".into(),
                time("2026-08-11T12:04:00Z"),
            )
            .unwrap();
        let family = ObservationFamilyKeyV1::of_slot(&observed.slot);
        let latest = store
            .latest_qualified_observation_in_family(&family)
            .unwrap()
            .unwrap();
        assert_eq!(latest.cycle_id, observed.cycle_id);
        assert_eq!(latest.slot.occurrence, 1);
    }

    #[test]
    fn catch_up_completion_order_does_not_override_logical_order() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        let missed_slot = example_slot(1);
        store
            .record_missed(
                missed_slot.clone(),
                "nightshift-scheduler-1",
                time("2026-08-11T12:06:01Z"),
                "scheduler_observed_missed_slot".into(),
            )
            .unwrap();
        // The logically later observation completes first.
        let later = record_test_observation(
            &mut store,
            example_slot(2),
            "nightshift-scheduler-1",
            &digest('b'),
            time("2026-08-11T12:02:00Z"),
        );
        // The catch-up keeps the earlier occurrence and completes last.
        let mut catch_up = slot_with_ids(
            &missed_slot.policy_id,
            &missed_slot.configuration_version,
            &missed_slot.subject_id,
            &missed_slot.scope_id,
            &missed_slot.scheduler_clock_id,
            1,
            RecurrenceTriggerV1::CatchUp,
            Some(missed_slot.slot_id.clone()),
        );
        catch_up.nominal_due_at = time("2026-08-11T12:08:00Z");
        catch_up.latest_admissible = crate::currentness::RecurrenceLatestAdmissibleV1 {
            scheduler_clock_id: "nightshift-scheduler-1".into(),
            at: time("2026-08-11T12:13:00Z"),
        };
        catch_up.slot_id = RecurrenceSlotId(object_id(&catch_up, "slot_id").unwrap());
        catch_up.validate().unwrap();
        record_test_observation(
            &mut store,
            catch_up,
            "nightshift-scheduler-1",
            &digest('c'),
            time("2026-08-11T12:08:00Z"),
        );
        let family = ObservationFamilyKeyV1::of_slot(&later.slot);
        let latest = store
            .latest_qualified_observation_in_family(&family)
            .unwrap()
            .unwrap();
        assert_eq!(latest.cycle_id, later.cycle_id);
        assert_eq!(latest.slot.occurrence, 2);
    }

    #[test]
    fn export_reports_every_match_with_lineage_position() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        let first = record_test_observation(
            &mut store,
            example_slot(1),
            "nightshift-scheduler-1",
            &digest('a'),
            time("2026-08-11T12:01:00Z"),
        );
        let second = record_test_observation(
            &mut store,
            example_slot(2),
            "nightshift-scheduler-1",
            &digest('a'),
            time("2026-08-11T12:02:00Z"),
        );
        let export = store.export_observation(&digest('a')).unwrap();
        assert_eq!(export.schema, OBSERVATION_EXPORT_SCHEMA_V1);
        assert_eq!(export.matches.len(), 2);
        for entry in &export.matches {
            assert_eq!(entry.observation.observation_id, digest('a'));
            assert_eq!(
                entry.family_latest_cycle_id.as_deref(),
                Some(second.cycle_id.as_str())
            );
            assert_eq!(
                entry.family_latest_order_key.as_ref().unwrap().occurrence,
                2
            );
        }
        let first_export = export
            .matches
            .iter()
            .find(|entry| entry.cycle_id == first.cycle_id.as_str())
            .unwrap();
        assert_eq!(first_export.order_key.occurrence, 1);
        assert_eq!(
            first_export.family,
            ObservationFamilyKeyV1::of_slot(&first.slot)
        );
    }

    #[test]
    fn migration_adds_observation_id_column_and_preserves_rows() {
        let scratch_directory = tempfile::tempdir().unwrap();
        let scratch_database = scratch_directory.path().join("scratch.sqlite");
        let cycle_id = {
            let mut scratch = CanonicalStore::open(&scratch_database).unwrap();
            scratch
                .claim_slot(
                    example_slot(1),
                    "nightshift-scheduler-1",
                    time("2026-08-11T12:01:00Z"),
                )
                .unwrap()
                .0
                .cycle_id
        };
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("nightshift.sqlite");
        {
            let legacy = rusqlite::Connection::open(&database).unwrap();
            legacy
                .execute_batch(
                    "CREATE TABLE canonical_recurrence_slots (
                        slot_id TEXT PRIMARY KEY,
                        cycle_id TEXT NOT NULL UNIQUE,
                        status TEXT NOT NULL,
                        basis_json TEXT NOT NULL,
                        state_digest TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    ) STRICT;
                    CREATE TABLE canonical_observation_cycles (
                        cycle_id TEXT PRIMARY KEY,
                        slot_id TEXT NOT NULL UNIQUE,
                        version INTEGER NOT NULL,
                        status TEXT NOT NULL,
                        state_digest TEXT NOT NULL,
                        snapshot_json TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        FOREIGN KEY(slot_id) REFERENCES canonical_recurrence_slots(slot_id)
                    ) STRICT;",
                )
                .unwrap();
            let source = rusqlite::Connection::open(&scratch_database).unwrap();
            let slot_row: (String, String, String, String, String, String) = source
                .query_row(
                    "SELECT slot_id, cycle_id, status, basis_json, state_digest, updated_at
                     FROM canonical_recurrence_slots",
                    [],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                        ))
                    },
                )
                .unwrap();
            legacy
                .execute(
                    "INSERT INTO canonical_recurrence_slots
                     (slot_id, cycle_id, status, basis_json, state_digest, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![
                        slot_row.0, slot_row.1, slot_row.2, slot_row.3, slot_row.4, slot_row.5,
                    ],
                )
                .unwrap();
            let cycle_row: (String, String, i64, String, String, String, String) = source
                .query_row(
                    "SELECT cycle_id, slot_id, version, status, state_digest, snapshot_json,
                            updated_at
                     FROM canonical_observation_cycles",
                    [],
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
                .unwrap();
            legacy
                .execute(
                    "INSERT INTO canonical_observation_cycles
                     (cycle_id, slot_id, version, status, state_digest, snapshot_json, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    rusqlite::params![
                        cycle_row.0,
                        cycle_row.1,
                        cycle_row.2,
                        cycle_row.3,
                        cycle_row.4,
                        cycle_row.5,
                        cycle_row.6,
                    ],
                )
                .unwrap();
        }
        let store = CanonicalStore::open(&database).unwrap();
        let inspector = rusqlite::Connection::open(&database).unwrap();
        let columns: Vec<String> = inspector
            .prepare("PRAGMA table_info(canonical_observation_cycles)")
            .unwrap()
            .query_map([], |row| row.get(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(columns.iter().any(|column| column == "observation_id"));
        let index_count: i64 = inspector
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type='index' AND name='canonical_cycles_observation_id'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(index_count, 1);
        let cycles = store.list_cycles().unwrap();
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0].cycle_id, cycle_id);
        // A pre-migration row has a NULL observation_id and never matches.
        assert!(store
            .find_cycles_by_observation_id(&digest('a'))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn generic_read_only_open_does_not_require_the_new_authoring_projection() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("nightshift.sqlite");
        drop(CanonicalStore::open(&database).unwrap());
        let connection = rusqlite::Connection::open(&database).unwrap();
        connection
            .execute_batch("DROP TABLE canonical_authoring_context_provenance")
            .unwrap();
        drop(connection);

        let store = CanonicalStore::open_read_only(&database).unwrap();
        assert!(store.list_cycles().unwrap().is_empty());
        let error = store
            .export_authoring_context(AuthoringContextQueryV1::GovernedOccurrence {
                campaign_id: digest('a'),
                occurrence_id: "00000000-0000-4000-8000-000000000000".into(),
            })
            .unwrap_err();
        assert!(matches!(error, CanonicalStoreError::Invalid(_)));
        assert!(error
            .to_string()
            .contains("predates the authoring-context provenance projection"));
    }
}

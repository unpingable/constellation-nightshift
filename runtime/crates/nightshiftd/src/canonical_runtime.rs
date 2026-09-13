//! One canonical Nightshift observation-cycle runtime.
//!
//! The runtime obtains qualified support, evaluates the complete NQ basis,
//! records non-authorizing posture/attention, and may ask AG to open one new
//! exact occurrence. It has no effect, standing, authorization, retry, Docket,
//! executor, or human-disposition API.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::ag_port::{
    AgOccurrencePortV1, AgOpenModeV1, AgOpenOccurrenceRequestV1, AG_OPEN_REQUEST_SCHEMA_V1,
};
use crate::authoring_context::{
    ag_proposal_identity, exact_work_identity, AuthoringContextProvenanceV1,
};
use crate::authoring_custody::{
    AuthoringContextCustodyProvenanceV1, MaudeAuthoringContextHandoffV1, MaudeCustodyVerifierV1,
    VerifiedMaudeHandoffV1,
};
use crate::canonical_store::{
    AgProgramCounterV1, AttentionClassV1, AttentionRecordV1, CanonicalStore, CanonicalStoreError,
    CycleStatusV1, ObservationCycleId, ObservationCycleV1, ObservationFamilyKeyV1,
    ObservationOrderKeyV1, ObservationRecordV1, RecurrenceSlotV1, SlotTimingV1, TemporalDecisionV1,
    TemporalPostureV1, TypedCoarseIntentV2,
};
use crate::currentness::{
    delivered_artifact_ids, PresentEvidencePortV1, PresentEvidenceQueryV1, SupportStandingV1,
    TemporalHoldExpiryV1,
};
use crate::diagnostic_posture::{
    evaluate_posture_with_support, ConditionAxis, DiagnosticInputs, PosturePolicy,
    RecurrenceEvidence,
};
use crate::external_evidence_composition::{
    ComposedExternalEvidenceV1, ExternalEvidenceProfileV1, ExternalEvidenceReferenceV1,
};
use crate::nq_admission::{qualify_delivered_inputs_with_origin_history, NqAdmissionPortV1};
use crate::steady_state_evidence::{
    ComposedDecisionRelativeEvidenceV1, DecisionRelativeEvidenceReferenceV1,
    SteadyStateEvidenceProfileV1,
};

pub const CYCLE_REQUEST_SCHEMA_V1: &str = "nightshift.canonical_cycle_request.v1";
pub const PRECOMPILED_PROPOSAL_SCHEMA_V2: &str = "nightshift.precompiled_workflow_proposal.v2";
/// The AG/Docket executable-work identity domain: the executor-plan schema
/// string is the digest domain of the plan identity. The digest construction
/// below mirrors `ag_primitives::Digest::hash_domain` byte-exactly and is
/// pinned cross-repository by an exact test vector.
pub const AG_EXECUTOR_PLAN_IDENTITY_DOMAIN_V1: &str = "ag-effectd.docket-executor-plan/v1";

fn digest_value(value: &serde_json::Value) -> Result<String, String> {
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(serde_jcs::to_vec(value).map_err(|error| error.to_string())?)
    ))
}

fn ag_hash_domain(domain: &str, payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ag-ng\0digest\0v1\0");
    hasher.update((domain.len() as u128).to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update((payload.len() as u128).to_be_bytes());
    hasher.update(payload);
    format!("sha256:{:x}", hasher.finalize())
}

/// The AG/Docket executable-work identity of one exact executor-plan
/// document: AG's domain-separated digest of the plan's canonical JCS.
/// Nightshift derives this at proposal-compilation time so the persisted
/// binding is verified, never caller-asserted.
pub fn ag_executor_plan_identity(plan: &serde_json::Value) -> Result<String, String> {
    if !plan.is_object() {
        return Err("AG executor plan must be an exact typed object".into());
    }
    let canonical = serde_jcs::to_vec(plan).map_err(|error| error.to_string())?;
    Ok(ag_hash_domain(
        AG_EXECUTOR_PLAN_IDENTITY_DOMAIN_V1,
        &canonical,
    ))
}

fn require_token(name: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.chars().any(char::is_whitespace) {
        return Err(format!("{name} must be a non-empty token"));
    }
    Ok(())
}

fn require_digest(name: &str, value: &str) -> Result<(), String> {
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

#[derive(Debug, thiserror::Error)]
pub enum CanonicalRuntimeError {
    #[error(transparent)]
    Store(#[from] CanonicalStoreError),
    #[error("canonical cycle input is invalid: {0}")]
    Invalid(String),
    #[error("present-evidence authority refused or was unavailable: {0}")]
    PresentEvidence(String),
    #[error("NQ-NG admission provenance refused or was unavailable: {0}")]
    NqAdmission(String),
    #[error("diagnostic posture evaluation refused: {0}")]
    Diagnostic(String),
    #[error("external application evidence refused: {0}")]
    ExternalEvidence(String),
    #[error("AG boundary refused or was unavailable: {0}")]
    Ag(String),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalPolicyRequestV1 {
    pub policy_id: String,
    pub basis_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold_expiry: Option<TemporalHoldExpiryV1>,
}

/// Already-compiled workflow-specific exact work. This adapter binds the
/// complete live Nightshift basis; it never interprets free text.
///
/// Version 2 carries the exact AG/Docket executor-plan document and seals
/// the cross-domain work binding: the exact AG proposal's `work` must equal
/// the AG executable-work identity deterministically derived from that plan.
/// The Nightshift-domain compiled-payload identity is a distinct digest
/// sealed into the typed intent as `compiled_work`; the two identity domains
/// are deliberately not equal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrecompiledWorkflowProposalV2 {
    pub schema: String,
    pub workflow_id: String,
    pub intent_kind: String,
    pub subject_digest: String,
    pub immutable_parameters: serde_json::Value,
    /// The exact sealed AG/Docket executor plan whose derived identity is the
    /// expected AG executable-work digest.
    pub ag_executor_plan: serde_json::Value,
    pub campaign_id: String,
    pub occurrence_id: String,
    pub mode: AgOpenModeV1,
    pub proposal_input: serde_json::Value,
}

impl PrecompiledWorkflowProposalV2 {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != PRECOMPILED_PROPOSAL_SCHEMA_V2 {
            return Err("unsupported precompiled workflow proposal schema".into());
        }
        require_token("workflow_id", &self.workflow_id)?;
        require_token("intent_kind", &self.intent_kind)?;
        require_digest("subject_digest", &self.subject_digest)?;
        require_digest("campaign_id", &self.campaign_id)?;
        uuid::Uuid::parse_str(&self.occurrence_id)
            .map_err(|_| "occurrence_id must be an independently allocated UUID".to_string())?;
        if !self.immutable_parameters.is_object() {
            return Err("immutable_parameters must be an exact typed object".into());
        }
        if !self.proposal_input.is_object() {
            return Err("proposal_input must be an exact typed object".into());
        }
        let expected_ag_work = ag_executor_plan_identity(&self.ag_executor_plan)?;
        let proposal = self
            .proposal_input
            .get("proposal")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| "proposal_input must contain one exact proposal object".to_string())?;
        let work = proposal
            .get("work")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "exact proposal work must be a digest".to_string())?;
        if work != expected_ag_work {
            return Err("exact proposal work does not bind the sealed AG executor plan".into());
        }
        Ok(())
    }

    fn compile(
        &self,
        observation: &ObservationRecordV1,
    ) -> Result<(TypedCoarseIntentV2, AgOpenOccurrenceRequestV1), String> {
        self.validate()?;
        let work_schema = self
            .proposal_input
            .get("proposal")
            .and_then(|proposal| proposal.get("work_schema"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "exact proposal work_schema must be a string".to_string())?;
        let compiled_work = digest_value(&serde_json::json!({
            "parameters": &self.immutable_parameters,
            "schema": work_schema,
        }))?;
        let intent = TypedCoarseIntentV2 {
            schema: String::new(),
            intent_id: String::new(),
            workflow_id: self.workflow_id.clone(),
            intent_kind: self.intent_kind.clone(),
            subject_id: observation.posture.policy.subject.id.clone(),
            subject_digest: self.subject_digest.clone(),
            scope_id: observation.posture.policy.subject.scope.digest.clone(),
            source_observation_id: observation.observation_id.clone(),
            source_support_id: observation.support.support_id.clone(),
            source_posture_id: observation.posture.posture_id.clone(),
            immutable_parameters: self.immutable_parameters.clone(),
            compiled_work,
            expected_ag_work: ag_executor_plan_identity(&self.ag_executor_plan)?,
        }
        .seal()
        .map_err(|error| error.to_string())?;
        let request = AgOpenOccurrenceRequestV1 {
            schema: AG_OPEN_REQUEST_SCHEMA_V1.into(),
            request_id: String::new(),
            campaign_id: self.campaign_id.clone(),
            occurrence_id: self.occurrence_id.clone(),
            subject_digest: self.subject_digest.clone(),
            scope_digest: observation.posture.policy.subject.scope.digest.clone(),
            source_observation_id: observation.observation_id.clone(),
            source_support_id: observation.support.support_id.clone(),
            source_posture_id: observation.posture.posture_id.clone(),
            source_intent_id: intent.intent_id.clone(),
            mode: self.mode.clone(),
            proposal_input: self.proposal_input.clone(),
        }
        .seal()?;
        request.validate_for(observation, &intent)?;
        Ok((intent, request))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalCycleRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub slot: RecurrenceSlotV1,
    pub scheduler_clock_id: String,
    pub evaluated_at: DateTime<Utc>,
    pub observation_id: String,
    pub policy: PosturePolicy,
    pub inputs: DiagnosticInputs,
    pub recurrence: RecurrenceEvidence,
    /// Optional exact reference to separately authenticated application/world
    /// evidence. The deployment-owned profile is supplied independently at
    /// ingress; this reference cannot choose its own TTL or claim policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_evidence: Option<ExternalEvidenceReferenceV1>,
    /// Optional exact qualification + passive observation reference. It is
    /// mutually exclusive with the legacy strong single-source reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_external_evidence: Option<DecisionRelativeEvidenceReferenceV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temporal_policy: Option<TemporalPolicyRequestV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal: Option<PrecompiledWorkflowProposalV2>,
    /// Optional exact authoring context presented at the real proposal
    /// handoff. It is lineage input only and is not sent to AG or consulted by
    /// any currentness, standing, admissibility, or authorization gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authoring_context: Option<MaudeAuthoringContextHandoffV1>,
}

impl CanonicalCycleRequestV1 {
    pub fn seal(mut self) -> Result<Self, String> {
        self.schema = CYCLE_REQUEST_SCHEMA_V1.into();
        self.request_id.clear();
        let mut value = serde_json::to_value(&self).map_err(|error| error.to_string())?;
        value
            .as_object_mut()
            .expect("cycle request is an object")
            .remove("request_id");
        self.request_id = digest_value(&value)?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != CYCLE_REQUEST_SCHEMA_V1 {
            return Err("unsupported canonical cycle request schema".into());
        }
        require_digest("request_id", &self.request_id)?;
        require_digest("observation_id", &self.observation_id)?;
        require_token("scheduler_clock_id", &self.scheduler_clock_id)?;
        self.slot.validate().map_err(|error| error.to_string())?;
        self.policy.validate()?;
        self.inputs.validate()?;
        self.recurrence.validate()?;
        if let Some(reference) = &self.external_evidence {
            reference.validate()?;
            let proposal = self.proposal.as_ref().ok_or_else(|| {
                "external application evidence requires an exact successor proposal".to_owned()
            })?;
            if !matches!(proposal.mode, AgOpenModeV1::Continuation { .. }) {
                return Err(
                    "external application evidence v1 applies only to a successor occurrence"
                        .into(),
                );
            }
        }
        if let Some(reference) = &self.decision_external_evidence {
            reference.validate()?;
            if self.external_evidence.is_some() {
                return Err(
                    "cycle request cannot combine legacy and decision-relative evidence".into(),
                );
            }
            let proposal = self.proposal.as_ref().ok_or_else(|| {
                "decision-relative evidence requires an exact successor proposal".to_owned()
            })?;
            if !matches!(proposal.mode, AgOpenModeV1::Continuation { .. }) {
                return Err(
                    "decision-relative evidence applies only to a successor occurrence".into(),
                );
            }
        }
        if self.slot.scheduler_clock_id != self.scheduler_clock_id
            || self.slot.subject_id != self.policy.subject.id
            || self.slot.scope_id != self.policy.subject.scope.digest
            || self.slot.policy_id != self.policy.policy_id
        {
            return Err("cycle slot does not exactly bind scheduler/policy/subject/scope".into());
        }
        if let Some(proposal) = &self.proposal {
            proposal.validate()?;
        }
        if let Some(authoring_context) = &self.authoring_context {
            authoring_context.validate_untrusted()?;
            if self.proposal.is_none() {
                return Err(
                    "Maude authoring context cannot exist without an exact governed proposal"
                        .into(),
                );
            }
            if authoring_context.target_request_id != self.authoring_custody_target_request_id()? {
                return Err(
                    "Maude authoring-context handoff targets a different cycle request".into(),
                );
            }
        }
        let mut value = serde_json::to_value(self).map_err(|error| error.to_string())?;
        value
            .as_object_mut()
            .expect("cycle request is an object")
            .remove("request_id");
        if self.request_id != digest_value(&value)? {
            return Err("request_id does not match exact cycle preimage".into());
        }
        Ok(())
    }

    /// Identity of the exact request before custody material is attached.
    /// This avoids a recursive self-hash while binding every governed input,
    /// including campaign, occurrence, proposal, evidence, and exact work.
    pub fn authoring_custody_target_request_id(&self) -> Result<String, String> {
        let mut value = serde_json::to_value(self).map_err(|error| error.to_string())?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| "cycle request is not an object".to_owned())?;
        object.remove("request_id");
        object.remove("authoring_context");
        digest_value(&value)
    }
}

/// Prepare the exact canonical cycle bytes that will later be admitted by the
/// runtime. This is a deterministic packaging operation only: it performs no
/// currentness decision, slot claim, proposal submission, or AG transition.
pub fn prepare_external_evidence_cycle_request(
    store: &CanonicalStore,
    mut request: CanonicalCycleRequestV1,
    profile: &ExternalEvidenceProfileV1,
) -> Result<CanonicalCycleRequestV1, CanonicalRuntimeError> {
    if request.authoring_context.is_some() {
        return Err(CanonicalRuntimeError::ExternalEvidence(
            "prepare external evidence before attaching authoring custody".into(),
        ));
    }
    profile
        .validate()
        .map_err(CanonicalRuntimeError::ExternalEvidence)?;
    let reference = request.external_evidence.as_ref().ok_or_else(|| {
        CanonicalRuntimeError::ExternalEvidence(
            "cycle request lacks an external-evidence reference".into(),
        )
    })?;
    let proposal = request.proposal.as_ref().ok_or_else(|| {
        CanonicalRuntimeError::ExternalEvidence(
            "external evidence requires an exact successor proposal".into(),
        )
    })?;
    request
        .policy
        .validate()
        .map_err(CanonicalRuntimeError::Invalid)?;
    proposal
        .validate()
        .map_err(CanonicalRuntimeError::Invalid)?;
    let (source, custody) = store
        .external_observation_for_composition(&reference.source_observation_id)?
        .ok_or_else(|| {
            CanonicalRuntimeError::ExternalEvidence(
                "referenced authenticated application evidence is absent".into(),
            )
        })?;
    let composition = ComposedExternalEvidenceV1::compose(
        reference,
        profile,
        &source,
        &custody,
        request.evaluated_at,
        &proposal.campaign_id,
        &proposal.occurrence_id,
        &request.policy.subject.id,
        &proposal.subject_digest,
        &request.policy.subject.scope.digest,
    )
    .map_err(CanonicalRuntimeError::ExternalEvidence)?;
    request.observation_id = composition
        .canonical_observation_id()
        .map_err(CanonicalRuntimeError::ExternalEvidence)?;
    request
        .proposal
        .as_mut()
        .and_then(|proposal| proposal.proposal_input.as_object_mut())
        .ok_or_else(|| {
            CanonicalRuntimeError::Invalid("successor proposal input is not an exact object".into())
        })?
        .insert(
            "observation".into(),
            serde_json::Value::String(request.observation_id.clone()),
        );
    request.seal().map_err(CanonicalRuntimeError::Invalid)
}

/// Deterministically bind one exact historical qualification source and one
/// exact passive observation to a cycle request. This packages representation
/// only; the runtime independently revalidates predecessor state and passive
/// currentness at consequence time.
pub fn prepare_decision_evidence_cycle_request(
    store: &CanonicalStore,
    mut request: CanonicalCycleRequestV1,
    profile: &SteadyStateEvidenceProfileV1,
) -> Result<CanonicalCycleRequestV1, CanonicalRuntimeError> {
    if request.authoring_context.is_some() {
        return Err(CanonicalRuntimeError::ExternalEvidence(
            "prepare decision evidence before attaching authoring custody".into(),
        ));
    }
    profile
        .validate()
        .map_err(CanonicalRuntimeError::ExternalEvidence)?;
    let reference = request.decision_external_evidence.as_ref().ok_or_else(|| {
        CanonicalRuntimeError::ExternalEvidence(
            "cycle request lacks a decision-relative evidence reference".into(),
        )
    })?;
    let proposal = request.proposal.as_ref().ok_or_else(|| {
        CanonicalRuntimeError::ExternalEvidence(
            "decision-relative evidence requires an exact successor proposal".into(),
        )
    })?;
    let (qualification, qualification_custody) = store
        .external_observation_for_composition(&reference.qualification_observation_id)?
        .ok_or_else(|| {
            CanonicalRuntimeError::ExternalEvidence(
                "referenced historical qualification is absent".into(),
            )
        })?;
    require_qualification_target_artifact(proposal, &qualification.plan_document_digest)?;
    let (steady, steady_custody) = store
        .steady_state_observation_for_composition(&reference.steady_state_observation_id)?
        .ok_or_else(|| {
            CanonicalRuntimeError::ExternalEvidence(
                "referenced passive steady-state evidence is absent".into(),
            )
        })?;
    let composition = ComposedDecisionRelativeEvidenceV1::compose(
        reference,
        profile,
        &qualification,
        &qualification_custody,
        &steady,
        &steady_custody,
        request.evaluated_at,
        &proposal.campaign_id,
        &proposal.occurrence_id,
        &request.policy.subject.id,
        &proposal.subject_digest,
        &request.policy.subject.scope.digest,
    )
    .map_err(CanonicalRuntimeError::ExternalEvidence)?;
    require_decision_evidence_target_artifact(proposal, &composition)?;
    request.observation_id = composition
        .canonical_observation_id()
        .map_err(CanonicalRuntimeError::ExternalEvidence)?;
    request
        .proposal
        .as_mut()
        .and_then(|proposal| proposal.proposal_input.as_object_mut())
        .ok_or_else(|| {
            CanonicalRuntimeError::Invalid("successor proposal input is not an exact object".into())
        })?
        .insert(
            "observation".into(),
            serde_json::Value::String(request.observation_id.clone()),
        );
    request.seal().map_err(CanonicalRuntimeError::Invalid)
}

fn require_decision_evidence_target_artifact(
    proposal: &PrecompiledWorkflowProposalV2,
    composition: &ComposedDecisionRelativeEvidenceV1,
) -> Result<(), CanonicalRuntimeError> {
    require_qualification_target_artifact(proposal, &composition.qualification.plan_document_digest)
}

fn require_qualification_target_artifact(
    proposal: &PrecompiledWorkflowProposalV2,
    qualification_plan_document_digest: &str,
) -> Result<(), CanonicalRuntimeError> {
    let target = proposal
        .immutable_parameters
        .get("plan_document")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            CanonicalRuntimeError::ExternalEvidence(
                "decision-relative work lacks an exact target PlanDocument digest".into(),
            )
        })?;
    require_digest("target plan_document", target)
        .map_err(CanonicalRuntimeError::ExternalEvidence)?;
    if target != qualification_plan_document_digest {
        return Err(CanonicalRuntimeError::ExternalEvidence(
            "historical qualification does not apply to the target PlanDocument".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CycleRunOutcomeV1 {
    Missed { cycle: ObservationCycleV1 },
    PostureOnly { cycle: ObservationCycleV1 },
    AgOccurrenceOpened { cycle: ObservationCycleV1 },
}

pub struct CanonicalRuntime<'a, N, P, A>
where
    N: NqAdmissionPortV1,
    P: PresentEvidencePortV1,
    A: AgOccurrencePortV1,
{
    store: &'a mut CanonicalStore,
    nq_admission: N,
    present_evidence: &'a mut P,
    ag: &'a mut A,
    external_evidence_profile: Option<ExternalEvidenceProfileV1>,
    decision_evidence_profile: Option<SteadyStateEvidenceProfileV1>,
}

impl<'a, N, P, A> CanonicalRuntime<'a, N, P, A>
where
    N: NqAdmissionPortV1,
    P: PresentEvidencePortV1,
    A: AgOccurrencePortV1,
{
    pub fn new(
        store: &'a mut CanonicalStore,
        nq_admission: N,
        present_evidence: &'a mut P,
        ag: &'a mut A,
    ) -> Self {
        Self {
            store,
            nq_admission,
            present_evidence,
            ag,
            external_evidence_profile: None,
            decision_evidence_profile: None,
        }
    }

    /// Construct the same canonical runtime with one deployment-owned,
    /// non-authorizing external-evidence profile.
    pub fn new_with_external_evidence_profile(
        store: &'a mut CanonicalStore,
        nq_admission: N,
        present_evidence: &'a mut P,
        ag: &'a mut A,
        profile: ExternalEvidenceProfileV1,
    ) -> Result<Self, CanonicalRuntimeError> {
        profile
            .validate()
            .map_err(CanonicalRuntimeError::ExternalEvidence)?;
        Ok(Self {
            store,
            nq_admission,
            present_evidence,
            ag,
            external_evidence_profile: Some(profile),
            decision_evidence_profile: None,
        })
    }

    pub fn new_with_decision_evidence_profile(
        store: &'a mut CanonicalStore,
        nq_admission: N,
        present_evidence: &'a mut P,
        ag: &'a mut A,
        profile: SteadyStateEvidenceProfileV1,
    ) -> Result<Self, CanonicalRuntimeError> {
        profile
            .validate()
            .map_err(CanonicalRuntimeError::ExternalEvidence)?;
        Ok(Self {
            store,
            nq_admission,
            present_evidence,
            ag,
            external_evidence_profile: None,
            decision_evidence_profile: Some(profile),
        })
    }

    pub fn run_cycle(
        &mut self,
        request: CanonicalCycleRequestV1,
    ) -> Result<CycleRunOutcomeV1, CanonicalRuntimeError> {
        self.run_cycle_inner(request, None)
    }

    /// Production authoring-context ingress. Authentication occurs before NQ
    /// qualification, slot claim, observation persistence, or AG contact.
    pub fn run_cycle_with_authoring_custody(
        &mut self,
        request: CanonicalCycleRequestV1,
        verifier: &MaudeCustodyVerifierV1,
    ) -> Result<CycleRunOutcomeV1, CanonicalRuntimeError> {
        let expected = request
            .authoring_custody_target_request_id()
            .map_err(CanonicalRuntimeError::Invalid)?;
        let verified = request
            .authoring_context
            .as_ref()
            .ok_or_else(|| {
                CanonicalRuntimeError::Invalid(
                    "authenticated authoring-context ingress requires a handoff".into(),
                )
            })
            .and_then(|handoff| {
                verifier
                    .verify(handoff, &expected)
                    .map_err(CanonicalRuntimeError::Invalid)
            })?;
        self.run_cycle_inner(request, Some(verified))
    }

    fn compose_external_evidence(
        &mut self,
        request: &CanonicalCycleRequestV1,
    ) -> Result<Option<ComposedExternalEvidenceV1>, CanonicalRuntimeError> {
        let Some(reference) = request.external_evidence.as_ref() else {
            return Ok(None);
        };
        let profile = self.external_evidence_profile.as_ref().ok_or_else(|| {
            CanonicalRuntimeError::ExternalEvidence(
                "cycle references external evidence but ingress has no configured profile".into(),
            )
        })?;
        if reference.profile_id != profile.profile_id {
            return Err(CanonicalRuntimeError::ExternalEvidence(
                "cycle selected a different external-evidence profile".into(),
            ));
        }
        let (source, custody) = self
            .store
            .external_observation_for_composition(&reference.source_observation_id)?
            .ok_or_else(|| {
                CanonicalRuntimeError::ExternalEvidence(
                    "referenced authenticated application evidence is absent".into(),
                )
            })?;
        let proposal = request.proposal.as_ref().ok_or_else(|| {
            CanonicalRuntimeError::ExternalEvidence(
                "external evidence requires an exact successor proposal".into(),
            )
        })?;
        if !matches!(proposal.mode, AgOpenModeV1::Continuation { .. }) {
            return Err(CanonicalRuntimeError::ExternalEvidence(
                "external evidence v1 cannot create a genesis occurrence".into(),
            ));
        }
        let composition = ComposedExternalEvidenceV1::compose(
            reference,
            profile,
            &source,
            &custody,
            request.evaluated_at,
            &proposal.campaign_id,
            &proposal.occurrence_id,
            &request.policy.subject.id,
            &proposal.subject_digest,
            &request.policy.subject.scope.digest,
        )
        .map_err(CanonicalRuntimeError::ExternalEvidence)?;
        let target_family = ObservationFamilyKeyV1::of_slot(&request.slot);
        let target_order = ObservationOrderKeyV1::of_slot(&request.slot);
        let latest_predecessor = self
            .store
            .list_cycles()?
            .into_iter()
            .filter(|cycle| {
                ObservationFamilyKeyV1::of_slot(&cycle.slot) == target_family
                    && ObservationOrderKeyV1::of_slot(&cycle.slot) < target_order
                    && cycle.observation.is_some()
                    && cycle.ag.is_some()
            })
            .max_by_key(|cycle| ObservationOrderKeyV1::of_slot(&cycle.slot))
            .ok_or_else(|| {
                CanonicalRuntimeError::ExternalEvidence(
                    "external evidence has no exact prior Nightshift observation in this lineage"
                        .into(),
                )
            })?;
        let predecessor_ag = latest_predecessor.ag.as_ref().ok_or_else(|| {
            CanonicalRuntimeError::ExternalEvidence(
                "latest prior Nightshift observation has no governed occurrence relation".into(),
            )
        })?;
        if predecessor_ag.campaign_id != source.campaign_id
            || predecessor_ag.occurrence_id != source.occurrence_id
        {
            return Err(CanonicalRuntimeError::ExternalEvidence(
                "external evidence does not bind the latest exact governed predecessor".into(),
            ));
        }
        if request.observation_id
            != composition
                .canonical_observation_id()
                .map_err(CanonicalRuntimeError::ExternalEvidence)?
        {
            return Err(CanonicalRuntimeError::ExternalEvidence(
                "cycle observation identity does not bind the exact external-evidence composition"
                    .into(),
            ));
        }
        for existing in self
            .store
            .external_compositions_for_source(&source.observation_id)?
        {
            if existing.target_campaign_id != composition.target_campaign_id
                || existing.target_occurrence_id != composition.target_occurrence_id
            {
                return Err(CanonicalRuntimeError::ExternalEvidence(
                    "historical application evidence is already composed for another exact target"
                        .into(),
                ));
            }
        }
        let predecessor = self
            .ag
            .status(&source.campaign_id, &source.occurrence_id)
            .map_err(CanonicalRuntimeError::Ag)?;
        if predecessor.campaign_id != source.campaign_id
            || predecessor.occurrence_id != source.occurrence_id
            || predecessor.program_counter != AgProgramCounterV1::SettledObservationRequired
            || predecessor.docket_attempt_id.as_deref() != Some(source.attempt_id.as_str())
            || predecessor.settlement_id.as_deref() != Some(source.settlement_id.as_str())
        {
            return Err(CanonicalRuntimeError::ExternalEvidence(
                "external evidence source is not the exact settled predecessor state".into(),
            ));
        }
        Ok(Some(composition))
    }

    fn compose_decision_external_evidence(
        &mut self,
        request: &CanonicalCycleRequestV1,
    ) -> Result<Option<ComposedDecisionRelativeEvidenceV1>, CanonicalRuntimeError> {
        let Some(reference) = request.decision_external_evidence.as_ref() else {
            return Ok(None);
        };
        let profile = self.decision_evidence_profile.as_ref().ok_or_else(|| {
            CanonicalRuntimeError::ExternalEvidence(
                "cycle references decision evidence but ingress has no configured profile".into(),
            )
        })?;
        if reference.profile_id != profile.profile_id {
            return Err(CanonicalRuntimeError::ExternalEvidence(
                "cycle selected a different decision-evidence profile".into(),
            ));
        }
        let (qualification, qualification_custody) = self
            .store
            .external_observation_for_composition(&reference.qualification_observation_id)?
            .ok_or_else(|| {
                CanonicalRuntimeError::ExternalEvidence(
                    "referenced historical qualification is absent".into(),
                )
            })?;
        let proposal = request.proposal.as_ref().ok_or_else(|| {
            CanonicalRuntimeError::ExternalEvidence(
                "decision evidence requires an exact successor proposal".into(),
            )
        })?;
        require_qualification_target_artifact(proposal, &qualification.plan_document_digest)?;
        let (steady, steady_custody) = self
            .store
            .steady_state_observation_for_composition(&reference.steady_state_observation_id)?
            .ok_or_else(|| {
                CanonicalRuntimeError::ExternalEvidence(
                    "referenced passive steady-state evidence is absent".into(),
                )
            })?;
        let composition = ComposedDecisionRelativeEvidenceV1::compose(
            reference,
            profile,
            &qualification,
            &qualification_custody,
            &steady,
            &steady_custody,
            request.evaluated_at,
            &proposal.campaign_id,
            &proposal.occurrence_id,
            &request.policy.subject.id,
            &proposal.subject_digest,
            &request.policy.subject.scope.digest,
        )
        .map_err(CanonicalRuntimeError::ExternalEvidence)?;
        require_decision_evidence_target_artifact(proposal, &composition)?;
        let target_family = ObservationFamilyKeyV1::of_slot(&request.slot);
        let target_order = ObservationOrderKeyV1::of_slot(&request.slot);
        let latest_predecessor = self
            .store
            .list_cycles()?
            .into_iter()
            .filter(|cycle| {
                ObservationFamilyKeyV1::of_slot(&cycle.slot) == target_family
                    && ObservationOrderKeyV1::of_slot(&cycle.slot) < target_order
                    && cycle.observation.is_some()
                    && cycle.ag.is_some()
            })
            .max_by_key(|cycle| ObservationOrderKeyV1::of_slot(&cycle.slot))
            .ok_or_else(|| {
                CanonicalRuntimeError::ExternalEvidence(
                    "decision evidence has no exact governed predecessor".into(),
                )
            })?;
        let predecessor_ag = latest_predecessor.ag.as_ref().ok_or_else(|| {
            CanonicalRuntimeError::ExternalEvidence(
                "latest prior observation has no governed occurrence relation".into(),
            )
        })?;
        if predecessor_ag.campaign_id != qualification.campaign_id
            || predecessor_ag.occurrence_id != qualification.occurrence_id
        {
            return Err(CanonicalRuntimeError::ExternalEvidence(
                "qualification does not bind the latest exact governed predecessor".into(),
            ));
        }
        if request.observation_id
            != composition
                .canonical_observation_id()
                .map_err(CanonicalRuntimeError::ExternalEvidence)?
        {
            return Err(CanonicalRuntimeError::ExternalEvidence(
                "cycle observation identity does not bind decision-relative composition".into(),
            ));
        }
        let predecessor = self
            .ag
            .status(&qualification.campaign_id, &qualification.occurrence_id)
            .map_err(CanonicalRuntimeError::Ag)?;
        if predecessor.program_counter != AgProgramCounterV1::SettledObservationRequired
            || predecessor.docket_attempt_id.as_deref() != Some(qualification.attempt_id.as_str())
            || predecessor.settlement_id.as_deref() != Some(qualification.settlement_id.as_str())
        {
            return Err(CanonicalRuntimeError::ExternalEvidence(
                "historical qualification source is not the exact settled predecessor".into(),
            ));
        }
        Ok(Some(composition))
    }

    fn run_cycle_inner(
        &mut self,
        request: CanonicalCycleRequestV1,
        verified_handoff: Option<VerifiedMaudeHandoffV1>,
    ) -> Result<CycleRunOutcomeV1, CanonicalRuntimeError> {
        request.validate().map_err(CanonicalRuntimeError::Invalid)?;
        match (&request.authoring_context, &verified_handoff) {
            (None, None) => {}
            (Some(_), Some(_)) => {}
            (Some(_), None) => {
                return Err(CanonicalRuntimeError::Invalid(
                    "Maude authoring context requires authenticated custody ingress".into(),
                ));
            }
            (None, Some(_)) => {
                return Err(CanonicalRuntimeError::Invalid(
                    "verified Maude custody has no authoring-context handoff".into(),
                ));
            }
        }
        let composed_external_evidence = self.compose_external_evidence(&request)?;
        let composed_decision_evidence = self.compose_decision_external_evidence(&request)?;
        if request
            .slot
            .timing_at(&request.scheduler_clock_id, request.evaluated_at)?
            == SlotTimingV1::Missed
        {
            let cycle = self.store.record_missed(
                request.slot,
                &request.scheduler_clock_id,
                request.evaluated_at,
                "slot_passed_exact_latest_admissible_instant".into(),
            )?;
            return Ok(CycleRunOutcomeV1::Missed { cycle });
        }
        let mut origin_history = BTreeMap::new();
        if let Some(head) = self
            .store
            .substrate_origin_head(&request.policy.subject.id)?
        {
            origin_history.insert(request.policy.subject.id.clone(), head);
        }
        let qualified_sources = qualify_delivered_inputs_with_origin_history(
            &mut self.nq_admission,
            &request.inputs,
            &origin_history,
        )
        .map_err(CanonicalRuntimeError::NqAdmission)?;
        let (claimed, lease) = self.store.claim_slot(
            request.slot,
            &request.scheduler_clock_id,
            request.evaluated_at,
        )?;
        let query = PresentEvidenceQueryV1 {
            schema: String::new(),
            query_id: String::new(),
            observation_cycle_id: claimed.cycle_id.as_str().into(),
            request_nonce: format!("support-query:{}", uuid::Uuid::new_v4()),
            observation_id: request.observation_id.clone(),
            diagnostic_inputs_id: request.inputs.inputs_id.clone(),
            subject_id: request.policy.subject.id.clone(),
            scope_id: request.policy.subject.scope.digest.clone(),
            artifact_ids: delivered_artifact_ids(&request.inputs),
        }
        .seal()
        .map_err(CanonicalRuntimeError::Invalid)?;
        let support = match self.present_evidence.resolve(&query) {
            Ok(value) => value,
            Err(error) => {
                let _ = self.store.mark_recovery_required(
                    &claimed.cycle_id,
                    &claimed.state_digest,
                    "present_evidence_unavailable".into(),
                    request.evaluated_at,
                );
                return Err(CanonicalRuntimeError::PresentEvidence(error));
            }
        };
        let posture = match evaluate_posture_with_support(
            &request.policy,
            &request.inputs,
            &request.recurrence,
            request.evaluated_at,
            &support,
        ) {
            Ok(value) => value,
            Err(error) => {
                let _ = self.store.mark_recovery_required(
                    &claimed.cycle_id,
                    &claimed.state_digest,
                    "diagnostic_posture_refused".into(),
                    request.evaluated_at,
                );
                return Err(CanonicalRuntimeError::Diagnostic(error));
            }
        };
        let observation = ObservationRecordV1 {
            schema: if !qualified_sources.substrate_origins.is_empty() {
                crate::canonical_store::OBSERVATION_RECORD_SCHEMA_V6.into()
            } else if !qualified_sources.continuity.is_empty() {
                crate::canonical_store::OBSERVATION_RECORD_SCHEMA_V5.into()
            } else if composed_decision_evidence.is_some() {
                crate::canonical_store::OBSERVATION_RECORD_SCHEMA_V4.into()
            } else if composed_external_evidence.is_some() {
                crate::canonical_store::OBSERVATION_RECORD_SCHEMA_V3.into()
            } else {
                crate::canonical_store::OBSERVATION_RECORD_SCHEMA.into()
            },
            observation_id: request.observation_id,
            source_admissions: qualified_sources.provenance,
            continuity_applicability: qualified_sources.continuity,
            substrate_origin_applicability: qualified_sources.substrate_origins,
            external_evidence: composed_external_evidence,
            decision_external_evidence: composed_decision_evidence,
            support,
            posture,
        };
        let temporal = request
            .temporal_policy
            .map(|policy| {
                TemporalPostureV1::evaluate(
                    policy.policy_id,
                    policy.basis_digest,
                    policy.hold_expiry,
                    &request.scheduler_clock_id,
                    request.evaluated_at,
                )
            })
            .transpose()?;
        let attention = attention_for(&observation, temporal.as_ref());
        let temporal_hold = temporal
            .as_ref()
            .is_some_and(|value| value.decision == TemporalDecisionV1::Hold);
        let recorded = self.store.record_observation(
            &lease,
            &claimed.state_digest,
            observation.clone(),
            attention,
            temporal,
            request.evaluated_at,
        )?;
        let authoring_handoff = verified_handoff;
        let Some(precompiled) = request.proposal else {
            let cycle = self.store.close_without_proposal(
                &lease,
                &recorded.state_digest,
                request.evaluated_at,
            )?;
            return Ok(CycleRunOutcomeV1::PostureOnly { cycle });
        };
        if temporal_hold
            || !observation.posture.current
            || observation.support.standing != SupportStandingV1::Current
        {
            let cycle = self.store.close_without_proposal(
                &lease,
                &recorded.state_digest,
                request.evaluated_at,
            )?;
            return Ok(CycleRunOutcomeV1::PostureOnly { cycle });
        }
        let (intent, ag_request) = precompiled
            .compile(&observation)
            .map_err(CanonicalRuntimeError::Invalid)?;
        let authoring_context = authoring_handoff
            .as_ref()
            .map(|verified| {
                AuthoringContextProvenanceV1::mint(
                    &verified.handoff().authoring_context,
                    ag_request.campaign_id.clone(),
                    ag_request.occurrence_id.clone(),
                    ag_proposal_identity(&ag_request.proposal_input)?,
                    exact_work_identity(&ag_request.proposal_input)?,
                    intent.intent_id.clone(),
                    request.evaluated_at,
                )
            })
            .transpose()
            .map_err(CanonicalRuntimeError::Invalid)?;
        let authoring_custody = authoring_handoff
            .as_ref()
            .zip(authoring_context.as_ref())
            .map(|(verified, provenance)| {
                AuthoringContextCustodyProvenanceV1::mint(
                    verified,
                    provenance,
                    request.evaluated_at,
                )
            })
            .transpose()
            .map_err(CanonicalRuntimeError::Invalid)?;
        let prepared = ag_request.prepared()?;
        let pending = self.store.prepare_ag_occurrence(
            &lease,
            &recorded.state_digest,
            intent,
            prepared,
            crate::canonical_store::PreparedAuthoringEvidenceV1 {
                lineage: authoring_context,
                custody: authoring_custody,
            },
            request.evaluated_at,
        )?;
        let ag = match self.ag.open_occurrence(&ag_request) {
            Ok(value) => value,
            Err(error) => {
                let _ = self.store.mark_recovery_required(
                    &claimed.cycle_id,
                    &pending.state_digest,
                    "ag_status_required_no_resubmit".into(),
                    request.evaluated_at,
                );
                return Err(CanonicalRuntimeError::Ag(error));
            }
        };
        let cycle = self.store.attach_ag_occurrence(
            &lease,
            &pending.state_digest,
            ag,
            request.evaluated_at,
        )?;
        Ok(CycleRunOutcomeV1::AgOccurrenceOpened { cycle })
    }

    /// Read AG status only. A missing local AG response is reconciled by exact
    /// campaign/occurrence identity; the stored request is never resubmitted.
    pub fn sync_ag(
        &mut self,
        cycle_id: &ObservationCycleId,
        now: DateTime<Utc>,
    ) -> Result<ObservationCycleV1, CanonicalRuntimeError> {
        let cycle = self.store.get_cycle(cycle_id)?;
        let request = cycle.prepared_ag_request.as_ref().ok_or_else(|| {
            CanonicalRuntimeError::Invalid("cycle has no prepared AG request".into())
        })?;
        let status = match self.ag.status(&request.campaign_id, &request.occurrence_id) {
            Ok(value) => value,
            Err(error) => {
                if cycle.status != CycleStatusV1::RecoveryRequired {
                    let _ = self.store.mark_recovery_required(
                        cycle_id,
                        &cycle.state_digest,
                        "ag_status_unavailable_no_resubmit".into(),
                        now,
                    );
                }
                return Err(CanonicalRuntimeError::Ag(error));
            }
        };
        if cycle.ag.is_some() {
            Ok(self
                .store
                .record_ag_status(cycle_id, &cycle.state_digest, status, now)?)
        } else {
            Ok(self
                .store
                .recover_ag_occurrence(cycle_id, &cycle.state_digest, status, now)?)
        }
    }
}

fn attention_for(
    observation: &ObservationRecordV1,
    temporal: Option<&TemporalPostureV1>,
) -> AttentionRecordV1 {
    let (class, reason_code) = if matches!(
        observation.support.standing,
        SupportStandingV1::Contradictory | SupportStandingV1::Blind
    ) {
        (
            AttentionClassV1::EscalationRequested,
            "support_not_decidable",
        )
    } else if observation.support.standing != SupportStandingV1::Current {
        (AttentionClassV1::AttentionRequired, "support_not_current")
    } else if temporal.is_some_and(|value| {
        value.decision == crate::canonical_store::TemporalDecisionV1::Attention
    }) {
        (AttentionClassV1::AttentionRequired, "temporal_hold_expired")
    } else if observation.posture.condition == ConditionAxis::ConditionPresent {
        (AttentionClassV1::AttentionRequired, "condition_present")
    } else {
        (AttentionClassV1::Display, "posture_observed")
    };
    AttentionRecordV1 {
        class,
        source_posture_id: observation.posture.posture_id.clone(),
        reason_code: reason_code.into(),
        display_text: Some(format!("{:?}", observation.posture.headline)),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::*;
    use crate::ag_port::parse_ag_refusal;
    use crate::authoring_context::{
        AuthoringContextQueryV1, MaudeAuthoringContextInputV1, AUTHORING_CONTEXT_INPUT_SCHEMA_V1,
    };
    use crate::authoring_custody::{
        sign_handoff_for_test, sign_session_for_test, MaudeCustodyVerifierV1,
    };
    use crate::canonical_store::{
        AgOccurrenceReferenceV1, AgProgramCounterV1, AttentionClassV1, RecurrenceTriggerV1,
        AG_REFERENCE_SCHEMA_V1,
    };
    use crate::currentness::{
        PresentEvidenceQueryV1, QualifiedSupportV1, SupportExpiryV1, SupportReceiverInstantV1,
    };
    use crate::diagnostic_execution_v2::{DiagnosticClaim, DiagnosticExecution};
    use crate::diagnostic_posture::{
        ConditionV1, DeliveryStanding, DiagnosticExecutionV1, DiagnosticInputStatus, Headline,
        RunSlotEvidence,
    };
    use crate::external_evidence_composition::{
        ExternalEvidencePurposeV1, EXTERNAL_EVIDENCE_PROFILE_SCHEMA_V1,
        EXTERNAL_EVIDENCE_REFERENCE_SCHEMA_V1,
    };
    use crate::external_observation::{
        tests::{reseal_handoff, signed_handoff},
        ExternalObservationVerifierV1, LocalComposeActionV1, LocalComposeClaimKindV1,
    };
    use crate::nq_admission::{
        NqAdmissionArtifactV1, NqAdmissionJudgmentV1, NqAdmissionOriginV1, NqAdmissionPortV1,
        NqAdmissionProvenance, NqAdmissionProvenanceV1, NqAdmissionProviderV1, NqAdmissionQueryV1,
        NqAdmissionSourceV1, NqSourceDispositionV1,
    };
    use crate::steady_state_evidence::{
        tests::steady_handoff, DecisionRelativeEvidenceReferenceV1, SteadyStateClaimKindV1,
        SteadyStateEvidencePurposeV1, SteadyStateObservationVerifierV1,
        DECISION_EVIDENCE_REFERENCE_SCHEMA_V1, STEADY_STATE_ADAPTER_ID_V1,
        STEADY_STATE_ADAPTER_VERSION_V1,
    };

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn time(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&Utc)
    }

    #[derive(Clone, Copy)]
    struct TestNqAdmissionPort;

    impl NqAdmissionPortV1 for TestNqAdmissionPort {
        fn qualify(&mut self, query: &NqAdmissionQueryV1) -> Result<NqAdmissionProvenance, String> {
            NqAdmissionProvenanceV1 {
                schema: String::new(),
                provenance_id: String::new(),
                source: NqAdmissionSourceV1 {
                    kind: "local_nq_store".into(),
                    source_id: query.source_id.clone(),
                },
                artifact: NqAdmissionArtifactV1 {
                    artifact_id: query.artifact_id.clone(),
                    contract_schema: query.contract_schema.clone(),
                    canonical_bytes_sha256: query.canonical_bytes_sha256.clone(),
                    canonical_bytes_length: query.canonical_bytes_length,
                },
                origin: NqAdmissionOriginV1 {
                    run_id: query.run_id.clone(),
                    evaluation_id: Some("evaluation:test".into()),
                    completed_at: query.completed_at.clone(),
                    committed_at: query.completed_at.clone(),
                },
                provider: NqAdmissionProviderV1 {
                    provider_intake_id: "provider-intake:test".into(),
                    raw_sha256: digest('1'),
                    provider_admission_id: digest('2'),
                    source_admission_id: "source-admission:test".into(),
                    admission_context_digest: digest('3'),
                    profile_semantic_id: query
                        .profile_semantic_id
                        .clone()
                        .unwrap_or_else(|| digest('4')),
                },
                disposition: NqSourceDispositionV1::AdmittedReport,
                judgment: Some(NqAdmissionJudgmentV1 {
                    report_id: "report:test".into(),
                    judgment_schema: "nq-ng.judgment.v1".into(),
                    judgment_digest: digest('5'),
                }),
                nonclaims: Vec::new(),
            }
            .seal()
            .map(Box::new)
            .map(NqAdmissionProvenance::V1)
        }
    }

    fn policy_inputs_recurrence() -> (PosturePolicy, DiagnosticInputs, RecurrenceEvidence) {
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

    /// Pinned cross-repository vector: the AG executable-work identity of
    /// `test_executor_plan()`, asserted identically in ag_ng.
    const AG_EXECUTOR_PLAN_VECTOR_DIGEST: &str =
        "sha256:c938048c15ac6ebe40053d6137924cd60e75c649e4239b318901a5be77517ca6";

    /// One fixed executor-plan document used for the cross-repository
    /// identity vector and for the in-crate proposal fixtures.
    fn hex_digest(byte: &str) -> String {
        format!("sha256:{}", byte.repeat(32))
    }

    fn test_executor_plan() -> serde_json::Value {
        serde_json::json!({
            "schema": "ag-effectd.docket-executor-plan/v1",
            "attempt_store": "/tmp/wo9-1-vector/effect-attempts.sqlite",
            "subject": hex_digest("62"),
            "scope": hex_digest("31"),
            "effect_index": 0,
            "effect": {
                "kind": "managed_file_put",
                "target": "wo9-1-vector",
                "path": "/tmp/wo9-1-vector/target",
                "expected_content": null,
                "content": hex_digest("35"),
                "mode": 384,
                "uid": 1000,
                "gid": 1000
            },
            "artifacts": [{"digest": hex_digest("35"), "path": "/tmp/wo9-1-vector/artifact"}],
            "file_policy": {
                "max_content_bytes": 1024,
                "trusted_ancestor_uid": 0,
                "trusted_parent_uid": 1000,
                "require_private_parent_writes": true
            },
            "preparation_checkpoint": null
        })
    }

    fn cycle_request(occurrence: u64, proposal: bool) -> CanonicalCycleRequestV1 {
        let (policy, inputs, recurrence) = policy_inputs_recurrence();
        sealed_cycle_request(policy, inputs, recurrence, occurrence, proposal)
    }

    fn with_authoring_context(
        request: CanonicalCycleRequestV1,
        plan: &str,
        session: &str,
    ) -> CanonicalCycleRequestV1 {
        with_authoring_context_credentials(
            request,
            plan,
            session,
            "maude-handoff:local",
            "maude-handoff-key:primary",
            &[7_u8; 32],
        )
    }

    fn with_authoring_context_credentials(
        mut request: CanonicalCycleRequestV1,
        plan: &str,
        session: &str,
        producer_principal: &str,
        producer_key_id: &str,
        producer_key: &[u8; 32],
    ) -> CanonicalCycleRequestV1 {
        const SESSION_ISSUER_KEY: [u8; 32] = [3_u8; 32];
        request.authoring_context = None;
        request = request.seal().unwrap();
        let input = MaudeAuthoringContextInputV1 {
            schema: AUTHORING_CONTEXT_INPUT_SCHEMA_V1.into(),
            plan_ref: format!("sha256:{:x}", Sha256::digest(plan.as_bytes())),
            session_id: session.into(),
            plan_text: plan.into(),
        };
        let session_custody = sign_session_for_test(
            &SESSION_ISSUER_KEY,
            "maude:supervisor",
            "maude-session-key:primary",
            session,
            &input.plan_ref,
            plan.len() as u64,
            request.evaluated_at,
        );
        request.authoring_context = Some(sign_handoff_for_test(
            producer_key,
            crate::authoring_custody::TestHandoffInput {
                principal: producer_principal,
                key_id: producer_key_id,
                runtime_id: "nightshift:local-c1",
                target_request_id: &request.request_id,
                session_custody,
                authoring_context: input,
                created_at: request.evaluated_at,
            },
        ));
        request.seal().unwrap()
    }

    fn test_custody_verifier() -> MaudeCustodyVerifierV1 {
        custody_verifier_for(
            "maude-handoff:local",
            "maude-handoff-key:primary",
            [7_u8; 32],
        )
    }

    fn custody_verifier_for(
        producer_principal: &str,
        producer_key_id: &str,
        producer_key: [u8; 32],
    ) -> MaudeCustodyVerifierV1 {
        MaudeCustodyVerifierV1::for_test(
            producer_principal,
            producer_key_id,
            "maude:supervisor",
            "maude-session-key:primary",
            "nightshift:local-c1",
            producer_key,
            [3_u8; 32],
        )
    }

    fn sealed_cycle_request(
        policy: PosturePolicy,
        inputs: DiagnosticInputs,
        recurrence: RecurrenceEvidence,
        occurrence: u64,
        proposal: bool,
    ) -> CanonicalCycleRequestV1 {
        let campaign = digest('a');
        let scope = policy.subject.scope.digest.clone();
        let occurrence_id = format!("00000000-0000-4000-8000-{occurrence:012}");
        let slot = RecurrenceSlotV1::new(
            policy.policy_id.clone(),
            "config-v1".into(),
            policy.subject.id.clone(),
            policy.subject.scope.digest.clone(),
            "nightshift-scheduler-1".into(),
            time("2026-07-27T20:00:00Z") + chrono::Duration::minutes(occurrence as i64),
            time("2026-07-27T20:00:30Z") + chrono::Duration::minutes(occurrence as i64),
            occurrence,
            RecurrenceTriggerV1::Scheduled,
            None,
        )
        .unwrap();
        let immutable_parameters = serde_json::json!({"resource_id":"resource-1"});
        let work_schema = "example.exact-work/v1";
        let plan = test_executor_plan();
        let work = ag_executor_plan_identity(&plan).unwrap();
        CanonicalCycleRequestV1 {
            schema: String::new(),
            request_id: String::new(),
            slot,
            scheduler_clock_id: "nightshift-scheduler-1".into(),
            evaluated_at: time("2026-07-27T20:00:10Z")
                + chrono::Duration::minutes(occurrence as i64),
            observation_id: digest(char::from(b'd' + occurrence as u8)),
            policy,
            inputs,
            recurrence,
            external_evidence: None,
            decision_external_evidence: None,
            temporal_policy: None,
            proposal: proposal.then(|| PrecompiledWorkflowProposalV2 {
                schema: PRECOMPILED_PROPOSAL_SCHEMA_V2.into(),
                workflow_id: "workflow:host-care".into(),
                intent_kind: "inspect_exact_resource".into(),
                subject_digest: digest('b'),
                ag_executor_plan: plan,
                immutable_parameters,
                campaign_id: campaign.clone(),
                occurrence_id: occurrence_id.clone(),
                mode: AgOpenModeV1::Genesis {
                    genesis: serde_json::json!({
                        "campaign": campaign.clone(),
                        "occurrence": occurrence_id,
                        "program": digest('2'),
                        "expected_ag_work": work.clone(),
                        "residuals": [],
                        "budget": {"retry_limit":1,"retries_used":0,"probe_limit":1,"probes_used":0,"escalation_limit":1,"escalations_used":0}
                    }),
                },
                proposal_input: serde_json::json!({
                    "observation": digest(char::from(b'd' + occurrence as u8)),
                    "proposal": {
                        "schema":"ag.governed-loop.exact-work-proposal/v1",
                        "campaign":campaign,
                        "subject":digest('b'),
                        "scope":scope,
                        "work_schema":work_schema,
                        "work":work,
                        "repair":null
                    },
                    "class":"initial"
                }),
            }),
            authoring_context: None,
        }
        .seal()
        .unwrap()
    }

    fn reseal_artifact(artifact: &mut DiagnosticExecutionV1) {
        artifact.artifact_id.clear();
        let mut value = serde_json::to_value(&*artifact).unwrap();
        value.as_object_mut().unwrap().remove("artifact_id");
        artifact.artifact_id = digest_value(&value).unwrap();
    }

    /// The example basis with the delivered mandatory artifact reporting
    /// `ConditionV1::Present`, consistently re-sealed through the artifact,
    /// inputs, and recurrence evidence.
    fn condition_present_inputs_recurrence() -> (DiagnosticInputs, RecurrenceEvidence) {
        let (_policy, mut inputs, mut recurrence) = policy_inputs_recurrence();
        let mut new_artifact_id = String::new();
        for input in &mut inputs.inputs {
            if let DiagnosticInputStatus::Delivered { artifact } = &mut input.status {
                if let DiagnosticExecution::V1(artifact) = artifact.as_mut() {
                    artifact.outcome.condition = ConditionV1::Present;
                    for claim in &mut artifact.claims {
                        claim.condition_effect = Some(ConditionV1::Present);
                    }
                    reseal_artifact(artifact);
                    new_artifact_id = artifact.artifact_id.clone();
                }
            }
        }
        assert!(!new_artifact_id.is_empty());
        inputs.inputs_id.clear();
        inputs.inputs_id = inputs.computed_inputs_id().unwrap();
        for record in &mut recurrence.records {
            if let RunSlotEvidence::Completed { artifact, .. } = &mut record.evidence {
                artifact.artifact_id = new_artifact_id.clone();
                if let Some(DiagnosticClaim::V1(claim)) = &mut artifact.claim {
                    claim.condition_effect = Some(ConditionV1::Present);
                }
            }
        }
        recurrence.recurrence_id.clear();
        recurrence.recurrence_id = recurrence.computed_recurrence_id().unwrap();
        (inputs, recurrence)
    }

    struct CurrentSupportPort {
        standing: SupportStandingV1,
    }

    struct UnavailableSupportPort;

    struct RefusingNqAdmissionPort;

    impl NqAdmissionPortV1 for RefusingNqAdmissionPort {
        fn qualify(&mut self, _: &NqAdmissionQueryV1) -> Result<NqAdmissionProvenance, String> {
            Err("artifact has no local NQ-NG admission history".into())
        }
    }

    impl PresentEvidencePortV1 for UnavailableSupportPort {
        fn resolve(&mut self, _: &PresentEvidenceQueryV1) -> Result<QualifiedSupportV1, String> {
            Err("qualified currentness unavailable".into())
        }
    }

    #[test]
    fn unadmitted_artifact_is_refused_before_a_cycle_is_claimed() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("nightshift.sqlite")).unwrap();
        let mut support = CurrentSupportPort::default();
        let mut ag = FakeAg::default();
        let error =
            CanonicalRuntime::new(&mut store, RefusingNqAdmissionPort, &mut support, &mut ag)
                .run_cycle(cycle_request(0, false))
                .expect_err("unadmitted artifact must never enter canonical observation custody");
        assert!(matches!(error, CanonicalRuntimeError::NqAdmission(_)));
        assert!(store.list_cycles().unwrap().is_empty());
        assert_eq!(ag.open_count, 0);
    }

    impl Default for CurrentSupportPort {
        fn default() -> Self {
            Self {
                standing: SupportStandingV1::Current,
            }
        }
    }

    impl PresentEvidencePortV1 for CurrentSupportPort {
        fn resolve(
            &mut self,
            query: &PresentEvidenceQueryV1,
        ) -> Result<QualifiedSupportV1, String> {
            let mut support = QualifiedSupportV1 {
                schema: crate::currentness::QUALIFIED_SUPPORT_SCHEMA_V1.into(),
                support_id: String::new(),
                authority_id: "pulse-receiver-1".into(),
                query_id: query.query_id.clone(),
                observation_cycle_id: query.observation_cycle_id.clone(),
                request_nonce: query.request_nonce.clone(),
                observation_id: query.observation_id.clone(),
                diagnostic_inputs_id: query.diagnostic_inputs_id.clone(),
                subject_id: query.subject_id.clone(),
                scope_id: query.scope_id.clone(),
                artifact_ids: query.artifact_ids.clone(),
                evaluated_at: SupportReceiverInstantV1 {
                    clock_id: "pulse-receiver-clock-1".into(),
                    tick: 100,
                },
                expiry: (self.standing == SupportStandingV1::Current).then(|| SupportExpiryV1 {
                    clock_id: "pulse-receiver-clock-1".into(),
                    tick: 101,
                }),
                standing: self.standing,
                evidence_refs: vec![digest('9')],
                contradiction_refs: Vec::new(),
            };
            support.support_id = support.computed_support_id()?;
            support.validate_for(query)?;
            Ok(support)
        }
    }

    struct FakeAg {
        open_count: usize,
        lose_open_response: bool,
        status_pc: AgProgramCounterV1,
        status_attempt: Option<String>,
        status_settlement: Option<String>,
        request: Option<AgOpenOccurrenceRequestV1>,
    }

    impl Default for FakeAg {
        fn default() -> Self {
            Self {
                open_count: 0,
                lose_open_response: false,
                status_pc: AgProgramCounterV1::ProposalRecorded,
                status_attempt: None,
                status_settlement: None,
                request: None,
            }
        }
    }

    fn fake_reference(
        campaign: &str,
        occurrence: &str,
        pc: AgProgramCounterV1,
    ) -> AgOccurrenceReferenceV1 {
        let docket_attempt_id = matches!(
            pc,
            AgProgramCounterV1::Dispatched
                | AgProgramCounterV1::ReconciliationRequired
                | AgProgramCounterV1::SettledObservationRequired
        )
        .then(|| digest('8'));
        let settlement_id =
            (pc == AgProgramCounterV1::SettledObservationRequired).then(|| digest('9'));
        let exact_snapshot = serde_json::json!({
            "fake_canonical_ag_snapshot": true,
            "campaign": campaign,
            "occurrence": occurrence,
            "program_counter": pc,
            "docket_attempt": docket_attempt_id,
            "settlement": settlement_id,
        });
        AgOccurrenceReferenceV1 {
            schema: AG_REFERENCE_SCHEMA_V1.into(),
            campaign_id: campaign.into(),
            occurrence_id: occurrence.into(),
            state_digest: digest('7'),
            snapshot_digest: digest_value(&exact_snapshot).unwrap(),
            program_counter: pc,
            docket_attempt_id,
            settlement_id,
            external_decision_request_id: None,
            exact_snapshot,
        }
    }

    impl AgOccurrencePortV1 for FakeAg {
        fn open_occurrence(
            &mut self,
            request: &AgOpenOccurrenceRequestV1,
        ) -> Result<AgOccurrenceReferenceV1, String> {
            self.open_count += 1;
            self.request = Some(request.clone());
            if self.lose_open_response {
                return Err("AG response lost after exact occurrence creation".into());
            }
            Ok(fake_reference(
                &request.campaign_id,
                &request.occurrence_id,
                AgProgramCounterV1::ProposalRecorded,
            ))
        }

        fn status(
            &mut self,
            campaign_id: &str,
            occurrence_id: &str,
        ) -> Result<AgOccurrenceReferenceV1, String> {
            let mut reference = fake_reference(campaign_id, occurrence_id, self.status_pc);
            if let Some(attempt) = &self.status_attempt {
                reference.docket_attempt_id = Some(attempt.clone());
            }
            if let Some(settlement) = &self.status_settlement {
                reference.settlement_id = Some(settlement.clone());
            }
            Ok(reference)
        }
    }

    fn external_profile(max_age_ms: u64) -> ExternalEvidenceProfileV1 {
        ExternalEvidenceProfileV1 {
            schema: EXTERNAL_EVIDENCE_PROFILE_SCHEMA_V1.into(),
            profile_id: String::new(),
            purpose: ExternalEvidencePurposeV1::PostSettlementSuccessor,
            expected_adapter_id: "maude.local-compose-observation-adapter".into(),
            expected_adapter_version: "1".into(),
            expected_producer_principal_id: "maude-observer:local".into(),
            expected_producer_key_id: "maude-observer-key:one".into(),
            expected_runtime_id: "nightshift:local".into(),
            required_action: LocalComposeActionV1::Qualify,
            required_claims: vec![
                LocalComposeClaimKindV1::FrontDoorReachable,
                LocalComposeClaimKindV1::CacheMissThenHit,
                LocalComposeClaimKindV1::SingleCacheFailureSurvived,
                LocalComposeClaimKindV1::CacheTopologyRestored,
            ],
            max_age_ms,
        }
        .seal()
        .unwrap()
    }

    fn decision_profile(max_age_ms: u64) -> SteadyStateEvidenceProfileV1 {
        SteadyStateEvidenceProfileV1 {
            schema: String::new(),
            profile_id: String::new(),
            purpose: SteadyStateEvidencePurposeV1::RoutineContinuation,
            qualification_profile: external_profile(30_000),
            expected_adapter_id: STEADY_STATE_ADAPTER_ID_V1.into(),
            expected_adapter_version: STEADY_STATE_ADAPTER_VERSION_V1.into(),
            expected_producer_principal_id: "maude-observer:local".into(),
            expected_producer_key_id: "maude-observer-key:one".into(),
            expected_runtime_id: "nightshift:local".into(),
            required_qualification_claims: vec![
                LocalComposeClaimKindV1::FrontDoorReachable,
                LocalComposeClaimKindV1::CacheMissThenHit,
                LocalComposeClaimKindV1::SingleCacheFailureSurvived,
                LocalComposeClaimKindV1::CacheTopologyRestored,
            ],
            required_steady_state_claims: vec![
                SteadyStateClaimKindV1::FrontDoorReachable,
                SteadyStateClaimKindV1::CacheAPresent,
                SteadyStateClaimKindV1::CacheBPresent,
                SteadyStateClaimKindV1::OrdinaryCacheBehaviorObserved,
            ],
            max_age_ms,
        }
        .seal()
        .unwrap()
    }

    fn next_clean_inputs_recurrence() -> (DiagnosticInputs, RecurrenceEvidence) {
        let mut inputs_value: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/operator/examples/diagnostic-posture-v1/inputs.json"
        ))
        .unwrap();
        let artifact = &mut inputs_value["inputs"][0]["artifact"];
        artifact["request_id"] = serde_json::json!("request:002");
        artifact["run_id"] = serde_json::json!("run:002");
        artifact["started_at"] = serde_json::json!("2026-07-27T20:01:03Z");
        artifact["completed_at"] = serde_json::json!("2026-07-27T20:01:04Z");
        artifact["attempt_interval"]["started_at"] = serde_json::json!("2026-07-27T20:01:03Z");
        artifact["attempt_interval"]["ended_at"] = serde_json::json!("2026-07-27T20:01:04Z");
        artifact["inputs"]["received"][0]["acquisition"]["started_at"] =
            serde_json::json!("2026-07-27T20:01:01Z");
        artifact["inputs"]["received"][0]["acquisition"]["ended_at"] =
            serde_json::json!("2026-07-27T20:01:02Z");
        artifact["inputs"]["received"][0]["received_at"] =
            serde_json::json!("2026-07-27T20:01:03Z");
        let mut artifact_preimage = artifact.clone();
        artifact_preimage
            .as_object_mut()
            .unwrap()
            .remove("artifact_id");
        let artifact_id = digest_value(&artifact_preimage).unwrap();
        artifact["artifact_id"] = serde_json::json!(artifact_id);
        let artifact_snapshot = artifact.clone();
        let mut inputs: DiagnosticInputs = serde_json::from_value(inputs_value).unwrap();
        inputs.inputs_id = inputs.computed_inputs_id().unwrap();

        let mut recurrence_value: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/operator/examples/diagnostic-posture-v1/recurrence.json"
        ))
        .unwrap();
        let base: RecurrenceEvidence = serde_json::from_value(recurrence_value.clone()).unwrap();
        let slot = crate::diagnostic_posture::make_run_slot(
            &base.records[0].policy,
            &base.records[0].key,
            1,
        )
        .unwrap();
        recurrence_value["records"][0]["slot"] = serde_json::to_value(&slot).unwrap();
        let evidence = &mut recurrence_value["records"][0]["evidence"];
        evidence["attempt"]["attempt_id"] = serde_json::json!("attempt:fixture-2");
        evidence["attempt"]["request_id"] = serde_json::json!("request:002");
        evidence["attempt"]["slot_id"] = serde_json::json!(slot.slot_id);
        evidence["attempt"]["started_at"] = serde_json::json!("2026-07-27T20:01:00Z");
        evidence["completed_at"] = serde_json::json!("2026-07-27T20:01:04Z");
        let reference = &mut evidence["artifact"];
        reference["artifact_id"] = artifact_snapshot["artifact_id"].clone();
        reference["request_id"] = artifact_snapshot["request_id"].clone();
        reference["run_id"] = artifact_snapshot["run_id"].clone();
        reference["attempt_interval"] = artifact_snapshot["attempt_interval"].clone();
        reference["dependency_acquisitions"] =
            serde_json::json!([artifact_snapshot["inputs"]["received"][0]["acquisition"].clone()]);
        reference["claim"] = artifact_snapshot["claims"][0].clone();
        let mut recurrence: RecurrenceEvidence = serde_json::from_value(recurrence_value).unwrap();
        recurrence.recurrence_id = recurrence.computed_recurrence_id().unwrap();
        (inputs, recurrence)
    }

    fn cycle_with_external_evidence(
        store: &mut CanonicalStore,
        occurrence: u64,
        max_age_ms: u64,
    ) -> (
        CanonicalCycleRequestV1,
        ExternalEvidenceProfileV1,
        String,
        String,
    ) {
        assert!(occurrence > 0, "external evidence requires a prior cycle");
        let source_occurrence_number = occurrence - 1;
        let source_request = cycle_request(source_occurrence_number, true);
        let source_occurrence = source_request
            .proposal
            .as_ref()
            .unwrap()
            .occurrence_id
            .clone();
        let mut source_support = CurrentSupportPort::default();
        let mut source_ag = FakeAg::default();
        CanonicalRuntime::new(
            store,
            TestNqAdmissionPort,
            &mut source_support,
            &mut source_ag,
        )
        .run_cycle(source_request)
        .unwrap();

        let key = [7_u8; 32];
        let mut request = cycle_request(occurrence, true);
        if occurrence == 1 {
            let (inputs, recurrence) = next_clean_inputs_recurrence();
            request.inputs = inputs;
            request.recurrence = recurrence;
        }
        let proposal = request.proposal.as_mut().unwrap();
        let target_occurrence = proposal.occurrence_id.clone();
        let expected_work = ag_executor_plan_identity(&proposal.ag_executor_plan).unwrap();
        proposal.mode = AgOpenModeV1::Continuation {
            continuation: serde_json::json!({
                "occurrence": target_occurrence,
                "expected_ag_work": expected_work,
            }),
        };
        proposal.proposal_input["class"] = serde_json::json!("successor");

        let mut handoff = signed_handoff(&key, "2026-07-27T20:00:09.950Z", &source_occurrence);
        let observed_at = request.evaluated_at.timestamp_millis() - 100;
        handoff.observation.campaign_id = proposal.campaign_id.clone();
        handoff.observation.subject_digest = proposal.subject_digest.clone();
        handoff.observation.scope_digest = request.policy.subject.scope.digest.clone();
        handoff.observation.exact_work_id = expected_work.clone();
        handoff.observation.observed_at_unix_ms = observed_at;
        handoff.observation.source_evidence["dispatch"]["subject"] =
            serde_json::json!(handoff.observation.subject_digest);
        handoff.observation.source_evidence["dispatch"]["scope"] =
            serde_json::json!(handoff.observation.scope_digest);
        handoff.observation.source_evidence["dispatch"]["work"] = serde_json::json!(expected_work);
        handoff.observation.source_evidence["observed_at_unix_ms"] = serde_json::json!(observed_at);
        handoff.created_at = request.evaluated_at;
        reseal_handoff(&mut handoff, &key);
        let verifier = ExternalObservationVerifierV1::for_test(
            "maude-observer:local",
            "maude-observer-key:one",
            "nightshift:local",
            key,
        );
        let verified = verifier.verify(&handoff).unwrap();
        let custody = store
            .record_external_observation(&verified, request.evaluated_at)
            .unwrap();
        let profile = external_profile(max_age_ms);
        request.external_evidence = Some(ExternalEvidenceReferenceV1 {
            schema: EXTERNAL_EVIDENCE_REFERENCE_SCHEMA_V1.into(),
            source_observation_id: handoff.observation.observation_id.clone(),
            source_custody_id: custody.custody_id,
            profile_id: profile.profile_id.clone(),
        });
        request = prepare_external_evidence_cycle_request(store, request, &profile).unwrap();
        (
            request,
            profile,
            handoff.observation.attempt_id,
            handoff.observation.settlement_id,
        )
    }

    #[test]
    fn external_evidence_composes_then_expires_under_canonical_resolver() {
        use crate::observation_resolver::{
            resolve_observation, AgObservationRequestV1, AgObservationStatusV1,
            ObservationResolverConfigV1,
        };

        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("nightshift.sqlite")).unwrap();
        let (request, profile, attempt, settlement) =
            cycle_with_external_evidence(&mut store, 1, 5_000);
        let observation_id = request.observation_id.clone();
        let subject = request.proposal.as_ref().unwrap().subject_digest.clone();
        let evaluated_ms = u64::try_from(request.evaluated_at.timestamp_millis()).unwrap();
        let mut support = CurrentSupportPort::default();
        let mut ag = FakeAg {
            status_pc: AgProgramCounterV1::SettledObservationRequired,
            status_attempt: Some(attempt),
            status_settlement: Some(settlement),
            ..FakeAg::default()
        };
        let outcome = CanonicalRuntime::new_with_external_evidence_profile(
            &mut store,
            TestNqAdmissionPort,
            &mut support,
            &mut ag,
            profile.clone(),
        )
        .unwrap()
        .run_cycle(request)
        .unwrap();
        let CycleRunOutcomeV1::AgOccurrenceOpened { cycle } = outcome else {
            panic!("external evidence should permit ordinary successor proposal evaluation: {outcome:?}");
        };
        let composition = cycle
            .observation
            .as_ref()
            .unwrap()
            .external_evidence
            .as_ref()
            .unwrap();
        assert_eq!(composition.claims.len(), 4);
        assert_eq!(
            composition.target_occurrence_id,
            cycle.ag.as_ref().unwrap().occurrence_id
        );

        let config = ObservationResolverConfigV1 {
            resolver_id: "nightshift-observation-resolver/v1".into(),
            default_ttl_ms: 10_000,
        };
        let request_at = |now_unix_ms| AgObservationRequestV1 {
            schema: crate::observation_resolver::AG_OBSERVATION_REQUEST_SCHEMA_V1.into(),
            key: serde_json::json!({"campaign":"test","occurrence":"test"}),
            observation: observation_id.clone(),
            subject: subject.clone(),
            now_unix_ms,
        };
        let current =
            resolve_observation(&store, &request_at(evaluated_ms + 100), &config).unwrap();
        assert_eq!(current.status, AgObservationStatusV1::Current);
        assert_eq!(current.fresh_until_unix_ms, composition.fresh_until_unix_ms);
        let stale = resolve_observation(
            &store,
            &request_at(composition.fresh_until_unix_ms),
            &config,
        )
        .unwrap();
        assert_eq!(stale.status, AgObservationStatusV1::Stale);
        assert_eq!(
            stale.normalized_preconditions, current.normalized_preconditions,
            "historical evidence retains its honest basis after currentness expires"
        );

        let mut retarget = cycle_request(2, true);
        retarget.evaluated_at = cycle
            .observation
            .as_ref()
            .unwrap()
            .external_evidence
            .as_ref()
            .unwrap()
            .admitted_at;
        let proposal = retarget.proposal.as_mut().unwrap();
        let expected_work = ag_executor_plan_identity(&proposal.ag_executor_plan).unwrap();
        proposal.mode = AgOpenModeV1::Continuation {
            continuation: serde_json::json!({
                "occurrence": proposal.occurrence_id,
                "expected_ag_work": expected_work,
            }),
        };
        let source = cycle
            .observation
            .as_ref()
            .unwrap()
            .external_evidence
            .as_ref()
            .unwrap();
        retarget.external_evidence = Some(ExternalEvidenceReferenceV1 {
            schema: EXTERNAL_EVIDENCE_REFERENCE_SCHEMA_V1.into(),
            source_observation_id: source.source_observation_id.clone(),
            source_custody_id: source.source_custody_id.clone(),
            profile_id: profile.profile_id.clone(),
        });
        let retarget = prepare_external_evidence_cycle_request(&store, retarget, &profile).unwrap();
        let mut second_support = CurrentSupportPort::default();
        let mut second_ag = FakeAg {
            status_pc: AgProgramCounterV1::SettledObservationRequired,
            status_attempt: Some(source.source_attempt_id.clone()),
            status_settlement: Some(source.source_settlement_id.clone()),
            ..FakeAg::default()
        };
        let error = CanonicalRuntime::new_with_external_evidence_profile(
            &mut store,
            TestNqAdmissionPort,
            &mut second_support,
            &mut second_ag,
            profile,
        )
        .unwrap()
        .run_cycle(retarget)
        .unwrap_err();
        assert!(matches!(error, CanonicalRuntimeError::ExternalEvidence(_)));
        assert_eq!(second_ag.open_count, 0);
        assert_eq!(store.list_cycles().unwrap().len(), 2);
        drop(store);
        let reopened =
            CanonicalStore::open_read_only(directory.path().join("nightshift.sqlite")).unwrap();
        let export = reopened.export_observation(&observation_id).unwrap();
        assert_eq!(export.matches.len(), 1);
        assert_eq!(
            export.matches[0]
                .observation
                .external_evidence
                .as_ref()
                .unwrap()
                .composition_id,
            source.composition_id
        );
        let after_restart =
            resolve_observation(&reopened, &request_at(source.fresh_until_unix_ms), &config)
                .unwrap();
        assert_eq!(after_restart.status, AgObservationStatusV1::Stale);
    }

    #[test]
    fn routine_continuation_combines_historical_qualification_with_passive_currentness() {
        use crate::observation_resolver::{
            resolve_observation, AgObservationRequestV1, AgObservationStatusV1,
            ObservationResolverConfigV1,
        };

        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("nightshift.sqlite")).unwrap();
        let (mut request, _strong_profile, attempt, settlement) =
            cycle_with_external_evidence(&mut store, 1, 30_000);
        let strong_reference = request.external_evidence.take().unwrap();
        let (qualification, _) = store
            .external_observation_for_composition(&strong_reference.source_observation_id)
            .unwrap()
            .unwrap();
        let key = [7_u8; 32];
        let passive_time = request.evaluated_at.timestamp_millis() - 200;
        let handoff = steady_handoff(&qualification, passive_time, &key);
        let verifier = SteadyStateObservationVerifierV1::for_test(
            "maude-observer:local",
            "maude-observer-key:one",
            "nightshift:local",
            key,
        );
        let verified = verifier.verify(&handoff).unwrap();
        let passive_custody = store
            .record_steady_state_observation(&verified, request.evaluated_at)
            .unwrap();
        let profile = decision_profile(5_000);
        request.decision_external_evidence = Some(DecisionRelativeEvidenceReferenceV1 {
            schema: DECISION_EVIDENCE_REFERENCE_SCHEMA_V1.into(),
            qualification_observation_id: qualification.observation_id.clone(),
            qualification_custody_id: strong_reference.source_custody_id,
            steady_state_observation_id: handoff.observation.observation_id.clone(),
            steady_state_custody_id: passive_custody.custody_id,
            profile_id: profile.profile_id.clone(),
        });
        let mut changed_artifact = request.clone();
        changed_artifact
            .proposal
            .as_mut()
            .unwrap()
            .immutable_parameters["plan_document"] = serde_json::Value::String(digest('c'));
        let refusal = prepare_decision_evidence_cycle_request(&store, changed_artifact, &profile)
            .unwrap_err();
        assert!(refusal
            .to_string()
            .contains("qualification does not apply to the target PlanDocument"));
        request.proposal.as_mut().unwrap().immutable_parameters["plan_document"] =
            serde_json::Value::String(qualification.plan_document_digest.clone());
        request = prepare_decision_evidence_cycle_request(&store, request, &profile).unwrap();
        let observation_id = request.observation_id.clone();
        let subject = request.proposal.as_ref().unwrap().subject_digest.clone();
        let evaluated_ms = u64::try_from(request.evaluated_at.timestamp_millis()).unwrap();
        let mut support = CurrentSupportPort::default();
        let mut ag = FakeAg {
            status_pc: AgProgramCounterV1::SettledObservationRequired,
            status_attempt: Some(attempt),
            status_settlement: Some(settlement),
            ..FakeAg::default()
        };
        let outcome = CanonicalRuntime::new_with_decision_evidence_profile(
            &mut store,
            TestNqAdmissionPort,
            &mut support,
            &mut ag,
            profile,
        )
        .unwrap()
        .run_cycle(request)
        .unwrap();
        let CycleRunOutcomeV1::AgOccurrenceOpened { cycle } = outcome else {
            panic!(
                "qualified artifact plus passive observation should reach ordinary AG evaluation"
            )
        };
        let observation = cycle.observation.as_ref().unwrap();
        assert_eq!(
            observation.schema,
            crate::canonical_store::OBSERVATION_RECORD_SCHEMA_V4
        );
        let composition = observation.decision_external_evidence.as_ref().unwrap();
        assert_eq!(
            composition.qualification.source_observation_id,
            qualification.observation_id
        );
        assert_eq!(
            composition.qualification.acquired_at_unix_ms,
            u64::try_from(qualification.observed_at_unix_ms).unwrap()
        );
        assert_eq!(
            composition.steady_state_observed_at_unix_ms,
            u64::try_from(passive_time).unwrap()
        );
        assert!(!serde_json::to_string(&composition.steady_state_claims)
            .unwrap()
            .contains("single_cache_failure_survived"));

        let resolver = ObservationResolverConfigV1 {
            resolver_id: "nightshift-observation-resolver/v1".into(),
            default_ttl_ms: 10_000,
        };
        let at = |now_unix_ms| AgObservationRequestV1 {
            schema: crate::observation_resolver::AG_OBSERVATION_REQUEST_SCHEMA_V1.into(),
            key: serde_json::json!({"campaign":"test","occurrence":"test"}),
            observation: observation_id.clone(),
            subject: subject.clone(),
            now_unix_ms,
        };
        assert_eq!(
            resolve_observation(&store, &at(evaluated_ms + 100), &resolver)
                .unwrap()
                .status,
            AgObservationStatusV1::Current
        );
        assert_eq!(
            resolve_observation(&store, &at(composition.fresh_until_unix_ms), &resolver,)
                .unwrap()
                .status,
            AgObservationStatusV1::Stale
        );
    }

    #[test]
    fn historical_evidence_can_recompose_for_same_target_after_inadequate_observation() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("nightshift.sqlite")).unwrap();
        let (request, profile, attempt, settlement) =
            cycle_with_external_evidence(&mut store, 1, 180_000);
        let target_proposal = request.proposal.clone().unwrap();
        let source_reference = request.external_evidence.clone().unwrap();

        let mut inadequate_support = CurrentSupportPort {
            standing: SupportStandingV1::Unknown,
        };
        let mut first_ag = FakeAg {
            status_pc: AgProgramCounterV1::SettledObservationRequired,
            status_attempt: Some(attempt.clone()),
            status_settlement: Some(settlement.clone()),
            ..FakeAg::default()
        };
        let outcome = CanonicalRuntime::new_with_external_evidence_profile(
            &mut store,
            TestNqAdmissionPort,
            &mut inadequate_support,
            &mut first_ag,
            profile.clone(),
        )
        .unwrap()
        .run_cycle(request)
        .unwrap();
        let CycleRunOutcomeV1::PostureOnly { cycle } = outcome else {
            panic!("inadequate support must close without creating governed work")
        };
        let first_composition = cycle
            .observation
            .as_ref()
            .unwrap()
            .external_evidence
            .as_ref()
            .unwrap();
        assert_eq!(first_ag.open_count, 0);

        // A later diagnostic slot may reconsider the same exact governed
        // successor target after its decision-relative basis is repaired. The
        // historical evidence is not a one-use authority token and is not
        // retargeted merely because a new Nightshift observation is composed.
        let mut reconsideration = cycle_request(2, true);
        reconsideration.proposal = Some(target_proposal);
        reconsideration.external_evidence = Some(source_reference);
        let reconsideration =
            prepare_external_evidence_cycle_request(&store, reconsideration, &profile).unwrap();
        let mut current_support = CurrentSupportPort::default();
        let mut second_ag = FakeAg {
            status_pc: AgProgramCounterV1::SettledObservationRequired,
            status_attempt: Some(attempt),
            status_settlement: Some(settlement),
            ..FakeAg::default()
        };
        let recomposed = CanonicalRuntime::new_with_external_evidence_profile(
            &mut store,
            TestNqAdmissionPort,
            &mut current_support,
            &mut second_ag,
            profile,
        )
        .unwrap()
        .compose_external_evidence(&reconsideration)
        .unwrap()
        .unwrap();

        assert_eq!(
            recomposed.target_occurrence_id,
            first_composition.target_occurrence_id
        );
        assert_ne!(recomposed.composition_id, first_composition.composition_id);
        assert_eq!(second_ag.open_count, 0);
        assert_eq!(store.list_cycles().unwrap().len(), 2);
    }

    #[test]
    fn stale_absent_and_retargeted_external_evidence_refuse_before_new_authority() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("nightshift.sqlite")).unwrap();
        let error = {
            let key = [7_u8; 32];
            let mut request = cycle_request(0, true);
            let proposal = request.proposal.as_mut().unwrap();
            proposal.mode = AgOpenModeV1::Continuation {
                continuation: serde_json::json!({
                    "occurrence": proposal.occurrence_id,
                    "expected_ag_work": ag_executor_plan_identity(&proposal.ag_executor_plan).unwrap(),
                }),
            };
            let mut handoff = signed_handoff(
                &key,
                "2026-07-27T20:00:00Z",
                "11111111-1111-4111-8111-111111111111",
            );
            handoff.observation.campaign_id = proposal.campaign_id.clone();
            handoff.observation.subject_digest = proposal.subject_digest.clone();
            handoff.observation.scope_digest = request.policy.subject.scope.digest.clone();
            handoff.observation.source_evidence["dispatch"]["subject"] =
                serde_json::json!(handoff.observation.subject_digest);
            handoff.observation.source_evidence["dispatch"]["scope"] =
                serde_json::json!(handoff.observation.scope_digest);
            reseal_handoff(&mut handoff, &key);
            let verifier = ExternalObservationVerifierV1::for_test(
                "maude-observer:local",
                "maude-observer-key:one",
                "nightshift:local",
                key,
            );
            let verified = verifier.verify(&handoff).unwrap();
            let custody = store
                .record_external_observation(&verified, request.evaluated_at)
                .unwrap();
            let profile = external_profile(1_000);
            request.external_evidence = Some(ExternalEvidenceReferenceV1 {
                schema: EXTERNAL_EVIDENCE_REFERENCE_SCHEMA_V1.into(),
                source_observation_id: handoff.observation.observation_id,
                source_custody_id: custody.custody_id,
                profile_id: profile.profile_id.clone(),
            });
            prepare_external_evidence_cycle_request(&store, request, &profile).unwrap_err()
        };
        assert!(matches!(error, CanonicalRuntimeError::ExternalEvidence(_)));
        assert!(store.list_cycles().unwrap().is_empty());

        let mut absent = cycle_request(2, true);
        let profile = external_profile(5_000);
        absent.proposal.as_mut().unwrap().mode = AgOpenModeV1::Continuation {
            continuation: serde_json::json!({
                "occurrence": absent.proposal.as_ref().unwrap().occurrence_id,
                "expected_ag_work": ag_executor_plan_identity(
                    &absent.proposal.as_ref().unwrap().ag_executor_plan
                ).unwrap(),
            }),
        };
        absent.external_evidence = Some(ExternalEvidenceReferenceV1 {
            schema: EXTERNAL_EVIDENCE_REFERENCE_SCHEMA_V1.into(),
            source_observation_id: digest('f'),
            source_custody_id: digest('e'),
            profile_id: profile.profile_id.clone(),
        });
        assert!(matches!(
            prepare_external_evidence_cycle_request(&store, absent, &profile),
            Err(CanonicalRuntimeError::ExternalEvidence(_))
        ));
        assert!(store.list_cycles().unwrap().is_empty());
    }

    #[test]
    fn authenticated_external_evidence_does_not_bypass_nq_admission() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("nightshift.sqlite")).unwrap();
        let (request, profile, attempt, settlement) =
            cycle_with_external_evidence(&mut store, 1, 5_000);
        let source_id = request
            .external_evidence
            .as_ref()
            .unwrap()
            .source_observation_id
            .clone();
        let mut support = CurrentSupportPort::default();
        let mut ag = FakeAg {
            status_pc: AgProgramCounterV1::SettledObservationRequired,
            status_attempt: Some(attempt),
            status_settlement: Some(settlement),
            ..FakeAg::default()
        };
        let error = CanonicalRuntime::new_with_external_evidence_profile(
            &mut store,
            RefusingNqAdmissionPort,
            &mut support,
            &mut ag,
            profile,
        )
        .unwrap()
        .run_cycle(request)
        .unwrap_err();
        assert!(matches!(error, CanonicalRuntimeError::NqAdmission(_)));
        assert_eq!(store.list_cycles().unwrap().len(), 1);
        assert!(store
            .external_observation_for_composition(&source_id)
            .unwrap()
            .is_some());
        assert_eq!(ag.open_count, 0);
    }

    #[test]
    fn one_cycle_preserves_complete_basis_and_closes_without_authority() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        let mut support = CurrentSupportPort::default();
        let mut ag = FakeAg::default();
        let outcome = CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag)
            .run_cycle(cycle_request(0, false))
            .unwrap();
        let CycleRunOutcomeV1::PostureOnly { cycle } = outcome else {
            panic!("expected posture-only cycle")
        };
        assert_eq!(cycle.status, CycleStatusV1::Closed);
        let observation = cycle.observation.unwrap();
        assert_eq!(
            observation.schema,
            crate::canonical_store::OBSERVATION_RECORD_SCHEMA_V2
        );
        assert_eq!(observation.source_admissions.len(), 1);
        assert!(observation.posture.present_support.is_some());
        assert_eq!(ag.open_count, 0);
    }

    #[test]
    fn exact_authoring_context_is_minted_persisted_and_reopened() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("ns.sqlite");
        let request = with_authoring_context(
            cycle_request(0, true),
            "---\nplan_version: 1\n---\nexact governed plan\n",
            "sess_0123456789ab",
        );
        let mut support = CurrentSupportPort::default();
        let mut ag = FakeAg::default();
        let cycle = {
            let mut store = CanonicalStore::open(&database).unwrap();
            let CycleRunOutcomeV1::AgOccurrenceOpened { cycle } =
                CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag)
                    .run_cycle_with_authoring_custody(request, &test_custody_verifier())
                    .unwrap()
            else {
                panic!("expected exact AG occurrence")
            };
            cycle
        };
        let provenance = cycle.authoring_context_provenance.as_ref().unwrap();
        let custody = cycle.authoring_context_custody.as_ref().unwrap();
        custody.validate_for_authoring(provenance).unwrap();
        let durable_wire = serde_json::to_string(&cycle).unwrap();
        assert!(!durable_wire.contains("hmac-sha256:"));
        assert!(!durable_wire.contains("authentication\""));
        assert_eq!(provenance.maude_session_id, "sess_0123456789ab");
        assert_eq!(provenance.campaign_id, digest('a'));
        assert_eq!(
            provenance.occurrence_id,
            "00000000-0000-4000-8000-000000000000"
        );
        assert_eq!(
            provenance.exact_work_id,
            cycle.intent.as_ref().unwrap().expected_ag_work
        );
        assert_eq!(ag.open_count, 1);

        let reopened = CanonicalStore::open_read_only(&database).unwrap();
        let export = reopened
            .export_authoring_context(AuthoringContextQueryV1::GovernedOccurrence {
                campaign_id: provenance.campaign_id.clone(),
                occurrence_id: provenance.occurrence_id.clone(),
            })
            .unwrap();
        assert_eq!(export.matches, vec![provenance.clone()]);
        let by_proposal = reopened
            .export_authoring_context(AuthoringContextQueryV1::Proposal {
                proposal_id: provenance.proposal_id.clone(),
            })
            .unwrap();
        assert_eq!(by_proposal.matches, vec![provenance.clone()]);
        let by_maude = reopened
            .export_authoring_context(AuthoringContextQueryV1::MaudeContext {
                plan_ref: provenance.maude_plan_ref.clone(),
                session_id: provenance.maude_session_id.clone(),
            })
            .unwrap();
        assert_eq!(by_maude.matches, vec![provenance.clone()]);
        let custody_export = reopened
            .export_authoring_custody(AuthoringContextQueryV1::GovernedOccurrence {
                campaign_id: provenance.campaign_id.clone(),
                occurrence_id: provenance.occurrence_id.clone(),
            })
            .unwrap();
        assert_eq!(custody_export.matches, vec![custody.clone()]);
        assert_eq!(
            reopened.replay(&cycle.cycle_id).unwrap().last(),
            Some(&cycle)
        );

        // Recomputing the record's outer self-digest cannot conceal a
        // substituted work relationship: export compares it to the
        // authoritative cycle and prepared AG request.
        drop(reopened);
        let mut substituted = provenance.clone();
        substituted.exact_work_id = digest('f');
        let mut preimage = serde_json::to_value(&substituted).unwrap();
        preimage.as_object_mut().unwrap().remove("provenance_id");
        substituted.provenance_id = digest_value(&preimage).unwrap();
        assert!(substituted.validate().is_ok());
        let connection = rusqlite::Connection::open(&database).unwrap();
        connection.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
        connection
            .execute(
                "UPDATE canonical_authoring_context_provenance
                 SET exact_work_id=?1, provenance_id=?2, record_json=?3
                 WHERE cycle_id=?4",
                rusqlite::params![
                    &substituted.exact_work_id,
                    &substituted.provenance_id,
                    String::from_utf8(serde_jcs::to_vec(&substituted).unwrap()).unwrap(),
                    cycle.cycle_id.as_str(),
                ],
            )
            .unwrap();
        drop(connection);
        let reopened = CanonicalStore::open_read_only(&database).unwrap();
        assert!(matches!(
            reopened.export_authoring_context(AuthoringContextQueryV1::GovernedOccurrence {
                campaign_id: provenance.campaign_id.clone(),
                occurrence_id: provenance.occurrence_id.clone(),
            }),
            Err(CanonicalStoreError::Replay(_)) | Err(CanonicalStoreError::Invalid(_))
        ));
    }

    #[test]
    fn conflicting_contexts_cannot_claim_one_governed_occurrence() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        let mut support = CurrentSupportPort::default();
        let mut ag = FakeAg::default();
        let first_request = with_authoring_context(
            cycle_request(0, true),
            "exact plan A\n",
            "sess_0123456789ab",
        );
        let exact_duplicate = first_request.clone();
        CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag)
            .run_cycle_with_authoring_custody(first_request, &test_custody_verifier())
            .unwrap();
        let duplicate_error =
            CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag)
                .run_cycle_with_authoring_custody(exact_duplicate, &test_custody_verifier())
                .unwrap_err();
        assert!(matches!(
            duplicate_error,
            CanonicalRuntimeError::Store(CanonicalStoreError::DuplicateSlot(_))
        ));

        let mut second_request = cycle_request(0, true);
        second_request.slot = RecurrenceSlotV1::new(
            second_request.slot.policy_id.clone(),
            "config-conflicting-authoring".into(),
            second_request.slot.subject_id.clone(),
            second_request.slot.scope_id.clone(),
            second_request.slot.scheduler_clock_id.clone(),
            second_request.slot.nominal_due_at,
            second_request.slot.latest_admissible.at,
            second_request.slot.occurrence,
            second_request.slot.trigger,
            second_request.slot.catch_up_of.clone(),
        )
        .unwrap();
        second_request =
            with_authoring_context(second_request, "substituted plan B\n", "sess_bbbbbbbbbbbb");
        let error = CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag)
            .run_cycle_with_authoring_custody(second_request, &test_custody_verifier())
            .unwrap_err();
        assert!(matches!(
            error,
            CanonicalRuntimeError::Store(CanonicalStoreError::DuplicateAgOccurrence(_, _))
        ));
        let export = store
            .export_authoring_context(AuthoringContextQueryV1::MaudeContext {
                plan_ref: format!("sha256:{:x}", Sha256::digest(b"substituted plan B\n")),
                session_id: "sess_bbbbbbbbbbbb".into(),
            })
            .unwrap();
        assert!(export.matches.is_empty());
    }

    #[test]
    fn concurrent_conflicting_contexts_produce_at_most_one_canonical_relation() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("ns.sqlite");
        drop(CanonicalStore::open(&database).unwrap());
        let first = with_authoring_context(
            cycle_request(0, true),
            "concurrent plan A\n",
            "sess_aaaaaaaaaaaa",
        );
        let mut second = cycle_request(0, true);
        second.slot = RecurrenceSlotV1::new(
            second.slot.policy_id.clone(),
            "config-concurrent-authoring".into(),
            second.slot.subject_id.clone(),
            second.slot.scope_id.clone(),
            second.slot.scheduler_clock_id.clone(),
            second.slot.nominal_due_at,
            second.slot.latest_admissible.at,
            second.slot.occurrence,
            second.slot.trigger,
            second.slot.catch_up_of.clone(),
        )
        .unwrap();
        let second = with_authoring_context(second, "concurrent plan B\n", "sess_bbbbbbbbbbbb");
        let barrier = Arc::new(Barrier::new(2));
        let workers = [first, second]
            .into_iter()
            .map(|request| {
                let database = database.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let mut store = CanonicalStore::open(&database).unwrap();
                    let mut support = CurrentSupportPort::default();
                    let mut ag = FakeAg::default();
                    barrier.wait();
                    match CanonicalRuntime::new(
                        &mut store,
                        TestNqAdmissionPort,
                        &mut support,
                        &mut ag,
                    )
                    .run_cycle_with_authoring_custody(request, &test_custody_verifier())
                    {
                        Ok(_) => "won",
                        Err(CanonicalRuntimeError::Store(
                            CanonicalStoreError::DuplicateAgOccurrence(_, _),
                        )) => "conflict",
                        Err(error) => panic!("unexpected concurrent result: {error}"),
                    }
                })
            })
            .collect::<Vec<_>>();
        let results = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| **result == "won").count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == "conflict")
                .count(),
            1
        );

        let store = CanonicalStore::open_read_only(&database).unwrap();
        let relations = [
            ("concurrent plan A\n", "sess_aaaaaaaaaaaa"),
            ("concurrent plan B\n", "sess_bbbbbbbbbbbb"),
        ]
        .into_iter()
        .map(|(plan, session_id)| {
            store
                .export_authoring_context(AuthoringContextQueryV1::MaudeContext {
                    plan_ref: format!("sha256:{:x}", Sha256::digest(plan.as_bytes())),
                    session_id: session_id.into(),
                })
                .unwrap()
                .matches
                .len()
        })
        .sum::<usize>();
        assert_eq!(relations, 1);
    }

    #[test]
    fn authoring_context_is_authority_neutral_and_never_inherited() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("linked.sqlite")).unwrap();
        let mut support = CurrentSupportPort::default();
        let mut first_ag = FakeAg::default();
        let first_request = with_authoring_context(
            cycle_request(0, true),
            "exact plan A\n",
            "sess_0123456789ab",
        );
        let CycleRunOutcomeV1::AgOccurrenceOpened { cycle: first } =
            CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut first_ag)
                .run_cycle_with_authoring_custody(first_request, &test_custody_verifier())
                .unwrap()
        else {
            panic!("expected first occurrence")
        };

        // A separately created governed occurrence without Maude context stays
        // unlinked. There is no predecessor-copy operation in the canonical
        // runtime or store.
        let mut unlinked_store =
            CanonicalStore::open(directory.path().join("unlinked.sqlite")).unwrap();
        let mut second_ag = FakeAg::default();
        let second_outcome = CanonicalRuntime::new(
            &mut unlinked_store,
            TestNqAdmissionPort,
            &mut support,
            &mut second_ag,
        )
        .run_cycle(cycle_request(0, true))
        .unwrap();
        let CycleRunOutcomeV1::AgOccurrenceOpened { cycle: second } = second_outcome else {
            panic!("expected runtime-generated successor: {second_outcome:?}")
        };

        assert_eq!(
            first_ag.request.as_ref().unwrap().proposal_input["proposal"],
            second_ag.request.as_ref().unwrap().proposal_input["proposal"]
        );
        assert!(serde_json::to_value(first_ag.request.as_ref().unwrap())
            .unwrap()
            .get("authoring_context")
            .is_none());
        assert!(first.authoring_context_provenance.is_some());
        assert!(first.authoring_context_custody.is_some());
        assert!(second.authoring_context_provenance.is_none());
        assert!(second.authoring_context_custody.is_none());
        assert_eq!(second.status, CycleStatusV1::AwaitingAg);
        let empty = unlinked_store
            .export_authoring_context(AuthoringContextQueryV1::GovernedOccurrence {
                campaign_id: digest('a'),
                occurrence_id: "00000000-0000-4000-8000-000000000000".into(),
            })
            .unwrap();
        assert!(empty.matches.is_empty());
    }

    #[test]
    fn producer_credential_choice_does_not_change_governed_proposal_or_work() {
        let directory = tempfile::tempdir().unwrap();
        let base = cycle_request(0, true);
        let first = with_authoring_context_credentials(
            base.clone(),
            "exact neutral plan\n",
            "sess_0123456789ab",
            "maude-handoff:first",
            "maude-handoff-key:first",
            &[7_u8; 32],
        );
        let second = with_authoring_context_credentials(
            base,
            "exact neutral plan\n",
            "sess_0123456789ab",
            "maude-handoff:second",
            "maude-handoff-key:second",
            &[8_u8; 32],
        );
        let mut first_support = CurrentSupportPort::default();
        let mut first_store = CanonicalStore::open(directory.path().join("first.sqlite")).unwrap();
        let mut first_ag = FakeAg::default();
        CanonicalRuntime::new(
            &mut first_store,
            TestNqAdmissionPort,
            &mut first_support,
            &mut first_ag,
        )
        .run_cycle_with_authoring_custody(
            first,
            &custody_verifier_for("maude-handoff:first", "maude-handoff-key:first", [7_u8; 32]),
        )
        .unwrap();

        let mut second_store =
            CanonicalStore::open(directory.path().join("second.sqlite")).unwrap();
        let mut second_ag = FakeAg::default();
        let mut second_support = CurrentSupportPort::default();
        CanonicalRuntime::new(
            &mut second_store,
            TestNqAdmissionPort,
            &mut second_support,
            &mut second_ag,
        )
        .run_cycle_with_authoring_custody(
            second,
            &custody_verifier_for(
                "maude-handoff:second",
                "maude-handoff-key:second",
                [8_u8; 32],
            ),
        )
        .unwrap();

        let first_ag_request = first_ag.request.as_ref().unwrap();
        let second_ag_request = second_ag.request.as_ref().unwrap();
        assert_eq!(first_ag_request.campaign_id, second_ag_request.campaign_id);
        assert_eq!(
            first_ag_request.occurrence_id,
            second_ag_request.occurrence_id
        );
        assert_eq!(
            first_ag_request.subject_digest,
            second_ag_request.subject_digest
        );
        assert_eq!(
            first_ag_request.scope_digest,
            second_ag_request.scope_digest
        );
        assert_eq!(first_ag_request.mode, second_ag_request.mode);
        assert_eq!(
            first_ag_request.proposal_input,
            second_ag_request.proposal_input
        );
        let ag_wire = serde_json::to_string(first_ag_request).unwrap();
        for forbidden in [
            "maude-handoff",
            "session_issuer",
            "authoring_context",
            "custody",
        ] {
            assert!(!ag_wire.contains(forbidden));
        }
    }

    #[test]
    fn lost_ag_response_preserves_custody_and_exact_resend_cannot_remint() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("ns.sqlite");
        let request = with_authoring_context(
            cycle_request(0, true),
            "restart-stable plan\n",
            "sess_0123456789ab",
        );
        let exact_resend = request.clone();
        let mut support = CurrentSupportPort::default();
        let mut ag = FakeAg {
            lose_open_response: true,
            ..FakeAg::default()
        };
        {
            let mut store = CanonicalStore::open(&database).unwrap();
            let error =
                CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag)
                    .run_cycle_with_authoring_custody(request, &test_custody_verifier())
                    .unwrap_err();
            assert!(matches!(error, CanonicalRuntimeError::Ag(_)));
        }

        let mut reopened = CanonicalStore::open(&database).unwrap();
        let cycles = reopened.list_cycles().unwrap();
        let [cycle] = cycles.as_slice() else {
            panic!("expected one durable cycle after lost AG response")
        };
        assert_eq!(cycle.status, CycleStatusV1::RecoveryRequired);
        let custody = cycle.authoring_context_custody.as_ref().unwrap();
        let export = reopened
            .export_authoring_custody(AuthoringContextQueryV1::GovernedOccurrence {
                campaign_id: custody.campaign_id.clone(),
                occurrence_id: custody.occurrence_id.clone(),
            })
            .unwrap();
        assert_eq!(export.matches, vec![custody.clone()]);

        let mut restarted_ag = FakeAg::default();
        let error = CanonicalRuntime::new(
            &mut reopened,
            TestNqAdmissionPort,
            &mut support,
            &mut restarted_ag,
        )
        .run_cycle_with_authoring_custody(exact_resend, &test_custody_verifier())
        .unwrap_err();
        assert!(matches!(
            error,
            CanonicalRuntimeError::Store(CanonicalStoreError::DuplicateSlot(_))
        ));
        assert_eq!(restarted_ag.open_count, 0);
    }

    #[test]
    fn malformed_or_substituted_authoring_input_refuses_before_custody() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        let mut request = with_authoring_context(
            cycle_request(0, true),
            "exact plan A\n",
            "sess_0123456789ab",
        );
        request
            .authoring_context
            .as_mut()
            .unwrap()
            .authoring_context
            .plan_text = "plan B\n".into();
        request.request_id.clear();
        let mut support = CurrentSupportPort::default();
        let mut ag = FakeAg::default();
        let error = CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag)
            .run_cycle_with_authoring_custody(request, &test_custody_verifier())
            .unwrap_err();
        assert!(matches!(error, CanonicalRuntimeError::Invalid(_)));
        assert!(store.list_cycles().unwrap().is_empty());
        assert_eq!(ag.open_count, 0);
    }

    #[test]
    fn custody_cannot_bypass_the_authenticated_runtime_entrypoint() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        let request = with_authoring_context(
            cycle_request(0, true),
            "exact plan A\n",
            "sess_0123456789ab",
        );
        let mut support = CurrentSupportPort::default();
        let mut ag = FakeAg::default();
        let error = CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag)
            .run_cycle(request)
            .unwrap_err();
        assert!(matches!(error, CanonicalRuntimeError::Invalid(_)));
        assert!(store.list_cycles().unwrap().is_empty());
        assert_eq!(ag.open_count, 0);
    }

    #[test]
    fn wrong_custody_tag_refuses_before_any_cycle_fact() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        let mut request = with_authoring_context(
            cycle_request(0, true),
            "exact plan A\n",
            "sess_0123456789ab",
        );
        request
            .authoring_context
            .as_mut()
            .unwrap()
            .authentication
            .tag = format!("hmac-sha256:{}", "0".repeat(64));
        request = request.seal().unwrap();
        let mut support = CurrentSupportPort::default();
        let mut ag = FakeAg::default();
        let error = CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag)
            .run_cycle_with_authoring_custody(request, &test_custody_verifier())
            .unwrap_err();
        assert!(matches!(error, CanonicalRuntimeError::Invalid(_)));
        assert!(store.list_cycles().unwrap().is_empty());
        assert_eq!(ag.open_count, 0);
    }

    #[test]
    fn unsupported_custody_schema_refuses_before_any_cycle_fact() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        let mut request = with_authoring_context(
            cycle_request(0, true),
            "exact plan A\n",
            "sess_0123456789ab",
        );
        request.authoring_context.as_mut().unwrap().schema =
            "nightshift.maude_authoring_context_handoff.v2".into();
        let mut support = CurrentSupportPort::default();
        let mut ag = FakeAg::default();
        let error = CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag)
            .run_cycle_with_authoring_custody(request, &test_custody_verifier())
            .unwrap_err();
        assert!(matches!(error, CanonicalRuntimeError::Invalid(_)));
        assert!(store.list_cycles().unwrap().is_empty());
        assert_eq!(ag.open_count, 0);
    }

    /// REGRESSION PIN (WO-1, pre-change semantics): the current proposal gate
    /// requires exactly `!temporal_hold && posture.current && support Current`.
    /// `posture.current` excludes the condition axis, so a ConditionPresent
    /// posture still opens an AG occurrence; the condition surfaces only as a
    /// non-authorizing attention record. Later docket work moves condition
    /// checks into per-workflow AG catalog preconditions — this pin makes that
    /// a deliberate behavioral diff, not a silent change. Do not "fix" this.
    #[test]
    fn condition_present_currently_reaches_ag_occurrence_opened() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        let (policy, _, _) = policy_inputs_recurrence();
        let (inputs, recurrence) = condition_present_inputs_recurrence();
        let mut support = CurrentSupportPort::default();
        let mut ag = FakeAg::default();
        let outcome = CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag)
            .run_cycle(sealed_cycle_request(policy, inputs, recurrence, 0, true))
            .unwrap();
        let CycleRunOutcomeV1::AgOccurrenceOpened { cycle } = outcome else {
            panic!(
                "current gate must open the AG occurrence for a current \
                 ConditionPresent posture with Current support and no hold"
            )
        };
        let observation = cycle.observation.expect("observation recorded");
        assert!(observation.posture.current);
        assert_eq!(
            observation.posture.condition,
            ConditionAxis::ConditionPresent
        );
        let attention = cycle.attention.expect("attention recorded");
        assert_eq!(attention.class, AttentionClassV1::AttentionRequired);
        assert_eq!(attention.reason_code, "condition_present");
        assert_eq!(ag.open_count, 1);
    }

    /// REGRESSION PIN (WO-1, pre-change semantics): `posture.current` also
    /// excludes the delivery axis, and the current proposal gate never
    /// consults delivery independently. Under a delivery-required policy with
    /// failed delivery, the posture is still `current` (headline Incomplete)
    /// and the AG occurrence still opens. Do not "fix" this.
    #[test]
    fn unqualified_delivery_currently_reaches_ag_occurrence_opened() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        let (mut policy, inputs, mut recurrence) = policy_inputs_recurrence();
        policy.delivery_required = true;
        policy.policy_id.clear();
        policy.policy_id = policy.computed_policy_id().unwrap();
        recurrence.delivery = DeliveryStanding::Failed;
        recurrence.recurrence_id.clear();
        recurrence.recurrence_id = recurrence.computed_recurrence_id().unwrap();
        let mut support = CurrentSupportPort::default();
        let mut ag = FakeAg::default();
        let outcome = CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag)
            .run_cycle(sealed_cycle_request(policy, inputs, recurrence, 0, true))
            .unwrap();
        let CycleRunOutcomeV1::AgOccurrenceOpened { cycle } = outcome else {
            panic!(
                "current gate must open the AG occurrence for a current \
                 posture with unqualified delivery"
            )
        };
        let observation = cycle.observation.expect("observation recorded");
        assert!(observation.posture.current);
        assert_eq!(observation.posture.delivery, DeliveryStanding::Failed);
        assert_eq!(observation.posture.headline, Headline::Incomplete);
        assert_eq!(ag.open_count, 1);
    }

    /// The runtime's own Missed branch must actually persist a Missed cycle:
    /// a slot evaluated after its exact latest-admissible instant produces
    /// `CycleRunOutcomeV1::Missed` with the stable token reason, and no
    /// observation, intent, prepared request, or AG occurrence is created.
    #[test]
    fn missed_slot_records_a_missed_cycle_without_observation_or_ag() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        let (policy, inputs, recurrence) = policy_inputs_recurrence();
        let mut support = CurrentSupportPort::default();
        let mut ag = FakeAg::default();
        let mut runtime =
            CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag);

        let mut missed_request =
            sealed_cycle_request(policy.clone(), inputs.clone(), recurrence.clone(), 1, true);
        missed_request.evaluated_at = time("2026-07-27T20:02:00Z");
        let outcome = runtime.run_cycle(missed_request.seal().unwrap()).unwrap();
        let CycleRunOutcomeV1::Missed { cycle } = outcome else {
            panic!("a slot past its latest-admissible instant must record Missed")
        };
        assert_eq!(cycle.status, CycleStatusV1::Missed);
        assert_eq!(
            cycle.recovery_reason.as_deref(),
            Some("slot_passed_exact_latest_admissible_instant")
        );
        assert!(cycle.observation.is_none());
        assert!(cycle.intent.is_none());
        assert!(cycle.prepared_ag_request.is_none());
        assert!(cycle.ag.is_none());
        let persisted = runtime.store.get_cycle(&cycle.cycle_id).unwrap();
        assert_eq!(persisted, cycle);

        // Boundary pin: equality with latest-admissible is still admitted
        // (`admits` is `now <= at`), so this cycle is not Missed.
        let mut admitted_request = sealed_cycle_request(policy, inputs, recurrence, 2, false);
        admitted_request.evaluated_at = time("2026-07-27T20:02:30Z");
        let outcome = runtime.run_cycle(admitted_request.seal().unwrap()).unwrap();
        assert!(matches!(outcome, CycleRunOutcomeV1::PostureOnly { .. }));
        assert_eq!(ag.open_count, 0);
    }

    /// A runtime-produced Missed cycle carries no observation, so it is not
    /// qualified lineage evidence: the earlier observed cycle remains the
    /// latest qualified observation in the family.
    #[test]
    fn runtime_missed_cycle_is_not_qualified_lineage_evidence() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        let (policy, inputs, recurrence) = policy_inputs_recurrence();
        let mut support = CurrentSupportPort::default();
        let mut ag = FakeAg::default();
        let mut runtime =
            CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag);

        let observed_outcome = runtime
            .run_cycle(sealed_cycle_request(
                policy.clone(),
                inputs.clone(),
                recurrence.clone(),
                0,
                true,
            ))
            .unwrap();
        let CycleRunOutcomeV1::AgOccurrenceOpened {
            cycle: observed, ..
        } = observed_outcome
        else {
            panic!("the earlier cycle must observe and open its AG occurrence")
        };

        let mut missed_request = sealed_cycle_request(policy, inputs, recurrence, 1, false);
        missed_request.evaluated_at = time("2026-07-27T20:02:00Z");
        let outcome = runtime.run_cycle(missed_request.seal().unwrap()).unwrap();
        assert!(matches!(outcome, CycleRunOutcomeV1::Missed { .. }));

        let family = crate::canonical_store::ObservationFamilyKeyV1::of_slot(&observed.slot);
        let latest = runtime
            .store
            .latest_qualified_observation_in_family(&family)
            .unwrap()
            .expect("the observed cycle is qualified");
        assert_eq!(latest.cycle_id, observed.cycle_id);
    }

    #[test]
    fn same_nq_generation_never_suppresses_a_distinct_slot() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        let mut support = CurrentSupportPort::default();
        let mut ag = FakeAg::default();
        let mut runtime =
            CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag);
        runtime.run_cycle(cycle_request(0, false)).unwrap();
        runtime.run_cycle(cycle_request(1, false)).unwrap();
        assert_eq!(runtime.store.list_cycles().unwrap().len(), 2);
    }

    #[test]
    fn recurrence_cannot_reuse_an_existing_ag_occurrence() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        let mut support = CurrentSupportPort::default();
        let mut ag = FakeAg::default();
        let mut runtime =
            CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag);
        runtime.run_cycle(cycle_request(0, true)).unwrap();

        let mut second = cycle_request(1, true);
        second.slot = RecurrenceSlotV1::new(
            second.policy.policy_id.clone(),
            "config-v1".into(),
            second.policy.subject.id.clone(),
            second.policy.subject.scope.digest.clone(),
            "nightshift-scheduler-1".into(),
            time("2026-07-27T20:00:00Z"),
            time("2026-07-27T20:00:30Z"),
            1,
            RecurrenceTriggerV1::Manual,
            None,
        )
        .unwrap();
        second.evaluated_at = time("2026-07-27T20:00:10Z");
        let first_occurrence = "00000000-0000-4000-8000-000000000000";
        let proposal = second.proposal.as_mut().unwrap();
        let expected_ag_work = proposal.proposal_input["proposal"]["work"].clone();
        proposal.occurrence_id = first_occurrence.into();
        proposal.mode = AgOpenModeV1::Genesis {
            genesis: serde_json::json!({
                "campaign": proposal.campaign_id,
                "occurrence": first_occurrence,
                "program": digest('2'),
                "expected_ag_work": expected_ag_work,
                "residuals": [],
                "budget": {"retry_limit":1,"retries_used":0,"probe_limit":1,"probes_used":0,"escalation_limit":1,"escalations_used":0}
            }),
        };
        second = second.seal().unwrap();

        assert!(runtime.run_cycle(second).is_err());
        assert_eq!(runtime.ag.open_count, 1);
    }

    #[test]
    fn settlement_changes_only_external_status_and_requires_reobservation() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        let mut support = CurrentSupportPort::default();
        let mut ag = FakeAg::default();
        let mut runtime =
            CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag);
        let outcome = runtime.run_cycle(cycle_request(0, true)).unwrap();
        let CycleRunOutcomeV1::AgOccurrenceOpened { cycle } = outcome else {
            panic!("expected AG occurrence")
        };
        let observation = cycle.observation.clone();
        runtime.ag.status_pc = AgProgramCounterV1::SettledObservationRequired;
        let settled = runtime
            .sync_ag(&cycle.cycle_id, time("2026-07-27T20:00:20Z"))
            .unwrap();
        assert_eq!(settled.status, CycleStatusV1::ObservationRequired);
        assert_eq!(settled.observation, observation);
        assert_eq!(
            settled.ag.as_ref().unwrap().docket_attempt_id,
            Some(digest('8'))
        );
        assert_eq!(
            settled.ag.as_ref().unwrap().settlement_id,
            Some(digest('9'))
        );
        let replayed = runtime
            .sync_ag(&cycle.cycle_id, time("2026-07-27T20:00:21Z"))
            .unwrap();
        assert_eq!(replayed.state_digest, settled.state_digest);
        assert_eq!(replayed.version, settled.version);
        assert_eq!(runtime.ag.open_count, 1);
    }

    #[test]
    fn indeterminate_status_never_reopens_or_repeats() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        let mut support = CurrentSupportPort::default();
        let mut ag = FakeAg::default();
        let mut runtime =
            CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag);
        let outcome = runtime.run_cycle(cycle_request(0, true)).unwrap();
        let CycleRunOutcomeV1::AgOccurrenceOpened { cycle } = outcome else {
            panic!("expected AG occurrence")
        };
        runtime.ag.status_pc = AgProgramCounterV1::ReconciliationRequired;
        let first = runtime
            .sync_ag(&cycle.cycle_id, time("2026-07-27T20:00:20Z"))
            .unwrap();
        let second = runtime
            .sync_ag(&cycle.cycle_id, time("2026-07-27T20:00:21Z"))
            .unwrap();
        assert_eq!(first.status, CycleStatusV1::AwaitingAgReconciliation);
        assert_eq!(second.status, CycleStatusV1::AwaitingAgReconciliation);
        assert_eq!(ag.open_count, 1);
    }

    #[test]
    fn stale_ag_program_counter_cannot_replace_a_settlement() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        let mut support = CurrentSupportPort::default();
        let mut ag = FakeAg::default();
        let mut runtime =
            CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag);
        let outcome = runtime.run_cycle(cycle_request(0, true)).unwrap();
        let CycleRunOutcomeV1::AgOccurrenceOpened { cycle } = outcome else {
            panic!("expected AG occurrence")
        };
        runtime.ag.status_pc = AgProgramCounterV1::SettledObservationRequired;
        runtime
            .sync_ag(&cycle.cycle_id, time("2026-07-27T20:00:20Z"))
            .unwrap();
        runtime.ag.status_pc = AgProgramCounterV1::ProposalRecorded;
        assert!(runtime
            .sync_ag(&cycle.cycle_id, time("2026-07-27T20:00:21Z"))
            .is_err());
    }

    #[test]
    fn lost_ag_open_response_recovers_by_status_without_resubmission() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("ns.sqlite");
        let cycle_id = {
            let mut store = CanonicalStore::open(&database).unwrap();
            let mut support = CurrentSupportPort::default();
            let mut ag = FakeAg {
                lose_open_response: true,
                ..FakeAg::default()
            };
            assert!(
                CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag,)
                    .run_cycle(cycle_request(0, true))
                    .is_err()
            );
            assert_eq!(ag.open_count, 1);
            let cycle = store.list_cycles().unwrap().pop().unwrap();
            assert_eq!(cycle.status, CycleStatusV1::RecoveryRequired);
            assert!(cycle.prepared_ag_request.is_some());
            assert!(cycle.ag.is_none());
            cycle.cycle_id
        };

        let mut restarted = CanonicalStore::open(&database).unwrap();
        let candidates = restarted
            .recover_after_restart(time("2026-07-27T20:00:20Z"))
            .unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].cycle_id, cycle_id);
        let mut support = UnavailableSupportPort;
        let mut ag = FakeAg::default();
        let recovered =
            CanonicalRuntime::new(&mut restarted, TestNqAdmissionPort, &mut support, &mut ag)
                .sync_ag(&cycle_id, time("2026-07-27T20:00:21Z"))
                .unwrap();
        assert_eq!(recovered.status, CycleStatusV1::AwaitingAg);
        assert!(recovered.ag.is_some());
        assert_eq!(ag.open_count, 0);
    }

    #[test]
    fn restart_after_posture_recording_erases_live_proposal_eligibility() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("ns.sqlite");
        let cycle_id = {
            let request = cycle_request(0, true);
            let mut store = CanonicalStore::open(&database).unwrap();
            let (claimed, lease) = store
                .claim_slot(
                    request.slot.clone(),
                    &request.scheduler_clock_id,
                    request.evaluated_at,
                )
                .unwrap();
            let query = PresentEvidenceQueryV1 {
                schema: String::new(),
                query_id: String::new(),
                observation_cycle_id: claimed.cycle_id.as_str().into(),
                request_nonce: "support-query:crash-cut".into(),
                observation_id: request.observation_id.clone(),
                diagnostic_inputs_id: request.inputs.inputs_id.clone(),
                subject_id: request.policy.subject.id.clone(),
                scope_id: request.policy.subject.scope.digest.clone(),
                artifact_ids: delivered_artifact_ids(&request.inputs),
            }
            .seal()
            .unwrap();
            let mut port = CurrentSupportPort::default();
            let support = port.resolve(&query).unwrap();
            let posture = evaluate_posture_with_support(
                &request.policy,
                &request.inputs,
                &request.recurrence,
                request.evaluated_at,
                &support,
            )
            .unwrap();
            assert!(posture.current);
            let observation = ObservationRecordV1 {
                schema: crate::canonical_store::OBSERVATION_RECORD_SCHEMA_V1.into(),
                observation_id: request.observation_id,
                source_admissions: Vec::new(),
                continuity_applicability: Vec::new(),
                substrate_origin_applicability: Vec::new(),
                external_evidence: None,
                decision_external_evidence: None,
                support,
                posture,
            };
            let recorded = store
                .record_observation(
                    &lease,
                    &claimed.state_digest,
                    observation.clone(),
                    attention_for(&observation, None),
                    None,
                    request.evaluated_at,
                )
                .unwrap();
            assert_eq!(recorded.status, CycleStatusV1::PostureRecorded);
            recorded.cycle_id
        };

        let mut restarted = CanonicalStore::open(&database).unwrap();
        let recovered = restarted
            .recover_after_restart(time("2026-07-27T20:00:20Z"))
            .unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].cycle_id, cycle_id);
        assert_eq!(recovered[0].status, CycleStatusV1::RecoveryRequired);
        assert!(recovered[0].prepared_ag_request.is_none());
        assert!(recovered[0].intent.is_none());
    }

    #[test]
    fn restart_preserves_reconciliation_without_repeat() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("ns.sqlite");
        let cycle_id = {
            let mut store = CanonicalStore::open(&database).unwrap();
            let mut support = CurrentSupportPort::default();
            let mut ag = FakeAg::default();
            let mut runtime =
                CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag);
            let CycleRunOutcomeV1::AgOccurrenceOpened { cycle } =
                runtime.run_cycle(cycle_request(0, true)).unwrap()
            else {
                panic!("expected AG occurrence")
            };
            runtime.ag.status_pc = AgProgramCounterV1::ReconciliationRequired;
            let reconciliating = runtime
                .sync_ag(&cycle.cycle_id, time("2026-07-27T20:00:20Z"))
                .unwrap();
            assert_eq!(
                reconciliating.status,
                CycleStatusV1::AwaitingAgReconciliation
            );
            reconciliating.cycle_id
        };

        let mut restarted = CanonicalStore::open(&database).unwrap();
        let candidates = restarted
            .recover_after_restart(time("2026-07-27T20:00:21Z"))
            .unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].status,
            CycleStatusV1::AwaitingAgReconciliation
        );
        let mut support = UnavailableSupportPort;
        let mut ag = FakeAg {
            status_pc: AgProgramCounterV1::ReconciliationRequired,
            ..FakeAg::default()
        };
        let unchanged =
            CanonicalRuntime::new(&mut restarted, TestNqAdmissionPort, &mut support, &mut ag)
                .sync_ag(&cycle_id, time("2026-07-27T20:00:22Z"))
                .unwrap();
        assert_eq!(unchanged.status, CycleStatusV1::AwaitingAgReconciliation);
        assert_eq!(ag.open_count, 0);
    }

    #[test]
    fn settled_restart_requires_a_new_observation_cycle() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("ns.sqlite");
        let cycle_id = {
            let mut store = CanonicalStore::open(&database).unwrap();
            let mut support = CurrentSupportPort::default();
            let mut ag = FakeAg::default();
            let mut runtime =
                CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag);
            let CycleRunOutcomeV1::AgOccurrenceOpened { cycle } =
                runtime.run_cycle(cycle_request(0, true)).unwrap()
            else {
                panic!("expected AG occurrence")
            };
            runtime.ag.status_pc = AgProgramCounterV1::SettledObservationRequired;
            runtime
                .sync_ag(&cycle.cycle_id, time("2026-07-27T20:00:20Z"))
                .unwrap()
                .cycle_id
        };

        let mut restarted = CanonicalStore::open(&database).unwrap();
        assert!(restarted
            .recover_after_restart(time("2026-07-27T20:00:21Z"))
            .unwrap()
            .is_empty());
        let historical = restarted.get_cycle(&cycle_id).unwrap();
        assert_eq!(historical.status, CycleStatusV1::ObservationRequired);
        assert!(historical.ag.as_ref().unwrap().settlement_id.is_some());
    }

    #[test]
    fn halted_and_completed_ag_states_remain_external_and_non_effecting() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        let mut support = CurrentSupportPort::default();
        let mut ag = FakeAg::default();
        let mut runtime =
            CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag);
        let outcome = runtime.run_cycle(cycle_request(0, true)).unwrap();
        let CycleRunOutcomeV1::AgOccurrenceOpened { cycle } = outcome else {
            panic!("expected AG occurrence")
        };
        let observation = cycle.observation.clone();

        runtime.ag.status_pc = AgProgramCounterV1::Halted;
        let halted = runtime
            .sync_ag(&cycle.cycle_id, time("2026-07-27T20:00:20Z"))
            .unwrap();
        assert_eq!(halted.status, CycleStatusV1::Halted);
        assert_eq!(halted.observation.as_ref(), observation.as_ref());

        runtime.ag.status_pc = AgProgramCounterV1::Completed;
        let completed = runtime
            .sync_ag(&cycle.cycle_id, time("2026-07-27T20:00:21Z"))
            .unwrap();
        assert_eq!(completed.status, CycleStatusV1::Closed);
        assert_eq!(completed.observation.as_ref(), observation.as_ref());
        assert_eq!(runtime.ag.open_count, 1);
    }

    #[test]
    fn ag_refusal_requires_the_exact_observed_predecessor() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        let mut support = CurrentSupportPort::default();
        let mut ag = FakeAg::default();
        let outcome = CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag)
            .run_cycle(cycle_request(0, true))
            .unwrap();
        let CycleRunOutcomeV1::AgOccurrenceOpened { cycle } = outcome else {
            panic!("expected AG occurrence")
        };
        let ag_reference = cycle.ag.as_ref().unwrap();
        let campaign_id = ag_reference.campaign_id.clone();
        let occurrence_id = ag_reference.occurrence_id.clone();
        let exact = serde_json::json!({
            "key": {
                "campaign": campaign_id,
                "occurrence": occurrence_id,
            },
            "at_state_digest": ag_reference.state_digest,
            "code": "stale_observation",
            "evidence": null,
        });
        let refusal = parse_ag_refusal(
            exact.clone(),
            &ag_reference.campaign_id,
            &ag_reference.occurrence_id,
        )
        .unwrap();
        let mut substituted_exact = exact;
        substituted_exact["at_state_digest"] = serde_json::json!(digest('6'));
        let substituted = parse_ag_refusal(
            substituted_exact,
            &ag_reference.campaign_id,
            &ag_reference.occurrence_id,
        )
        .unwrap();
        assert!(store
            .record_ag_refusal(
                &cycle.cycle_id,
                &cycle.state_digest,
                substituted,
                time("2026-07-27T20:00:20Z"),
            )
            .is_err());
        let closed = store
            .record_ag_refusal(
                &cycle.cycle_id,
                &cycle.state_digest,
                refusal,
                time("2026-07-27T20:00:21Z"),
            )
            .unwrap();
        assert_eq!(closed.status, CycleStatusV1::Closed);
        assert!(closed.ag_refusal.is_some());
    }

    #[test]
    fn attention_and_headline_never_construct_an_ag_request() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        let mut support = CurrentSupportPort::default();
        let mut ag = FakeAg::default();
        let outcome = CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag)
            .run_cycle(cycle_request(0, false))
            .unwrap();
        let CycleRunOutcomeV1::PostureOnly { cycle } = outcome else {
            panic!("expected posture-only cycle")
        };
        assert_eq!(cycle.headline(), Some(Headline::Clean));
        assert!(cycle.intent.is_none());
        assert!(cycle.prepared_ag_request.is_none());
        assert!(cycle.ag.is_none());
    }

    #[test]
    fn immutable_work_parameters_cannot_be_substituted_after_compilation() {
        // Substituting the sealed executor plan breaks the derived AG work
        // binding: the exact proposal no longer names the plan's identity.
        let mut request = cycle_request(0, true);
        request.proposal.as_mut().unwrap().ag_executor_plan["effect"]["content"] =
            serde_json::json!(digest('8'));
        assert!(request.seal().is_err());
        // Substituting the proposal's claimed work identity breaks it too.
        let mut request = cycle_request(0, true);
        request.proposal.as_mut().unwrap().proposal_input["proposal"]["work"] =
            serde_json::json!(digest('8'));
        assert!(request.seal().is_err());
    }

    #[test]
    fn nightshift_and_ag_work_identities_are_distinct_domains() {
        // The Nightshift-domain compiled-payload identity and the AG-domain
        // executable-work identity coexist in one sealed intent and are not
        // equal. Mutating Nightshift-only compilation input moves only the
        // Nightshift-domain identity.
        let request = cycle_request(0, true);
        let proposal = request.proposal.as_ref().unwrap();
        let expected_ag_work = ag_executor_plan_identity(&proposal.ag_executor_plan).unwrap();
        let compiled_work = digest_value(&serde_json::json!({
            "parameters": &proposal.immutable_parameters,
            "schema": "example.exact-work/v1",
        }))
        .unwrap();
        assert_ne!(compiled_work, expected_ag_work);
        let mut changed = cycle_request(0, true);
        changed.proposal.as_mut().unwrap().immutable_parameters["resource_id"] =
            serde_json::json!("different-resource");
        let changed = changed.proposal.unwrap();
        let changed_compiled = digest_value(&serde_json::json!({
            "parameters": &changed.immutable_parameters,
            "schema": "example.exact-work/v1",
        }))
        .unwrap();
        assert_ne!(compiled_work, changed_compiled);
        assert_eq!(
            expected_ag_work,
            ag_executor_plan_identity(&changed.ag_executor_plan).unwrap()
        );
    }

    #[test]
    fn ag_executor_plan_identity_matches_the_pinned_cross_repo_vector() {
        // The identical plan document and expected digest are pinned in ag_ng
        // against `EffectExecutorPlanV1::identity()`: the two repositories
        // compute the AG executable-work identity independently.
        assert_eq!(
            ag_executor_plan_identity(&test_executor_plan()).unwrap(),
            AG_EXECUTOR_PLAN_VECTOR_DIGEST
        );
    }

    #[test]
    fn active_temporal_hold_suppresses_work_without_minting_authority() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        let mut support = CurrentSupportPort::default();
        let mut ag = FakeAg::default();
        let mut request = cycle_request(0, true);
        request.temporal_policy = Some(TemporalPolicyRequestV1 {
            policy_id: "temporal:host-care".into(),
            basis_digest: digest('5'),
            hold_expiry: Some(TemporalHoldExpiryV1 {
                scheduler_clock_id: request.scheduler_clock_id.clone(),
                at: time("2026-07-27T20:00:11Z"),
            }),
        });
        request = request.seal().unwrap();
        let outcome = CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag)
            .run_cycle(request)
            .unwrap();
        let CycleRunOutcomeV1::PostureOnly { cycle } = outcome else {
            panic!("active temporal hold must remain posture-only")
        };
        assert_eq!(
            cycle.temporal_posture.unwrap().decision,
            TemporalDecisionV1::Hold
        );
        assert!(cycle.intent.is_none());
        assert_eq!(ag.open_count, 0);
    }

    #[test]
    fn authority_owned_unknown_support_suppresses_precompiled_work() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        let mut support = CurrentSupportPort {
            standing: SupportStandingV1::Unknown,
        };
        let mut ag = FakeAg::default();
        let outcome = CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag)
            .run_cycle(cycle_request(0, true))
            .unwrap();
        let CycleRunOutcomeV1::PostureOnly { cycle } = outcome else {
            panic!("unknown support must produce posture only")
        };
        assert_eq!(cycle.status, CycleStatusV1::Closed);
        assert!(!cycle.observation.as_ref().unwrap().posture.current);
        assert!(cycle.intent.is_none());
        assert_eq!(ag.open_count, 0);
    }

    #[test]
    fn historical_timestamps_cannot_substitute_for_qualified_currentness() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = CanonicalStore::open(directory.path().join("ns.sqlite")).unwrap();
        let mut support = UnavailableSupportPort;
        let mut ag = FakeAg::default();
        assert!(
            CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag,)
                .run_cycle(cycle_request(0, true))
                .is_err()
        );
        let cycles = store.list_cycles().unwrap();
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0].status, CycleStatusV1::RecoveryRequired);
        assert!(cycles[0].observation.is_none());
        assert_eq!(ag.open_count, 0);
    }
}

//! Read-only dispositions derived from NQ reliance testimony.
//!
//! Night Shift consumes native `nq.diagnostic-purpose-support/v1` and
//! proposes a **posture**. It does not re-evaluate evidence, resolve
//! contradictions, discharge obligations, retry, repair, or execute anything.
//!
//! # The distinction this module exists to hold
//!
//! > A fresh NQ refusal is NQ testimony.
//! > No fresh NQ response is Night Shift's own observation.
//!
//! [`SourceState`] keeps the six input cases apart. Only `Fresh` is current NQ
//! testimony. `NoResponse`, `TransportUnavailable`, and `Malformed` are Night
//! Shift orchestration or integrity observations, and **no synthetic NQ receipt
//! is ever fabricated for them**.
//!
//! Deliberately *not* reused, per the boundary audit: `bundle::RelianceClass`
//! (Night Shift's own weighting of how far a bundle input may be leaned on — a
//! different question with a different owner) and `packet::AttentionState`
//! (who is looking, not what to do).

use serde::{Deserialize, Serialize};

use crate::errors::{NightShiftError, NqContractViolationKind, Result};

/// The reliance receipt schema this consumer speaks.
pub const NQ_RELIANCE_RECEIPT_SCHEMA: &str = "nq.diagnostic-purpose-support/v1";
/// Archived donor wire; never selected as a fallback by the current parser.
pub const HISTORICAL_NQ_RELIANCE_RECEIPT_SCHEMA: &str = "nq.reliance.receipt.v1";

/// The consumer profile Night Shift is configured to be by default.
///
/// Since the supporting-evaluation extension (2026-07-26) the expected
/// profile is an explicit parameter at every parse site; this constant is the
/// base posture, not an ambient assumption baked into the parser.
pub const EXPECTED_CONSUMER_PROFILE: &str = "nightshift-readonly";

/// One supporting evaluation as NQ disclosed it on the receipt.
///
/// Mirrors NQ's `SupportingRef` — which claim was evaluated, its sealed
/// identity, its status, its subject. Disclosure carried through, never
/// authority: Night Shift records these verbatim and judges nothing about
/// them. Whether the right supporting claims were present is NQ's decided
/// law, already reflected in `decision`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportingReceiptRefDto {
    pub claim: String,
    pub content_hash: String,
    pub status: String,
    pub subject: String,
}

/// Native purpose-support projection, deserialize-only. Archived classic
/// receipts are accessible only through the explicitly historical parser.
///
/// Unknown fields are ignored so NQ can add non-breaking detail; every field
/// Night Shift acts on is required and load-bearing.
#[derive(Debug, Clone, Deserialize)]
pub struct NqRelianceReceiptDto {
    pub schema: String,
    pub decision_id: String,
    pub request_digest: String,
    pub evidence_context_digest: String,
    pub consumer_profile_id: String,
    pub caller_binding: String,
    pub caller_binding_disclosure: String,
    pub purpose: String,
    pub claim: String,
    pub receipt_content_hash: String,
    pub underlying_status: String,
    pub decision: String,
    #[serde(default)]
    pub premises: Vec<String>,
    #[serde(default)]
    pub coverage_limits: Vec<String>,
    #[serde(default)]
    pub unresolved_residuals: Vec<String>,
    #[serde(default)]
    pub retained_contradictions: Vec<String>,
    #[serde(default)]
    pub refusal_reasons: Vec<String>,
    #[serde(default)]
    pub establishes: Vec<String>,
    #[serde(default)]
    pub does_not_establish: Vec<String>,
    /// Supporting evaluations the request bound, as NQ disclosed them.
    /// Absent on pre-extension receipts; defaults keep those parsing.
    #[serde(default)]
    pub supporting_receipts: Vec<SupportingReceiptRefDto>,
    pub policy_version: String,
    pub generated_at: String,
}

impl NqRelianceReceiptDto {
    /// Parse and check the contract. Rejects before any disposition is derived.
    ///
    /// `expected_profile` is explicit at every call site: a receipt addressed
    /// to a different consumer is not ours to act on, and which consumer we
    /// are must never be an ambient assumption. The base posture passes
    /// [`EXPECTED_CONSUMER_PROFILE`].
    ///
    /// # Errors
    ///
    /// [`NightShiftError::NqContractViolation`] on schema mismatch, undecodable
    /// bytes, an unexpected consumer profile, a missing binding disclosure, or
    /// a supporting disclosure with no identity.
    pub fn parse_checked(bytes: &[u8], expected_profile: &str) -> Result<Self> {
        Self::parse_schema(bytes, expected_profile, NQ_RELIANCE_RECEIPT_SCHEMA)
    }

    /// Explicit archive inspection only. This does not qualify a modern
    /// producer or permit current-mode fallback.
    pub fn parse_historical_checked(bytes: &[u8], expected_profile: &str) -> Result<Self> {
        Self::parse_schema(
            bytes,
            expected_profile,
            HISTORICAL_NQ_RELIANCE_RECEIPT_SCHEMA,
        )
    }

    /// Current ingestion requires the exact requested consumer/purpose/subject/
    /// claim/time scope, and checks receipt expiry separately from liveness.
    /// Bytes must come from the operator-configured NQ source; hashes are
    /// integrity bindings, not authentication of an arbitrary file.
    pub fn parse_for_request(
        bytes: &[u8],
        expected_request: &serde_json::Value,
        observed_at: &str,
    ) -> Result<Self> {
        let violation = |detail: String| NightShiftError::NqContractViolation {
            kind: NqContractViolationKind::MalformedField,
            detail,
        };
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|e| violation(e.to_string()))?;
        let profile = expected_request["consumer"]
            .as_str()
            .ok_or_else(|| violation("expected consumer missing".into()))?;
        let dto = Self::parse_checked(bytes, profile)?;
        if value["request"] != *expected_request
            || value["purpose"] != expected_request["purpose"]
            || value["claim"] != expected_request["claim"]
            || value["subject_digest"] != expected_request["subject_digest"]
        {
            return Err(violation("purpose request binding mismatch".into()));
        }
        use sha2::{Digest, Sha256};
        let request_hash = format!(
            "sha256:{:x}",
            Sha256::digest(
                serde_jcs::to_vec(expected_request).map_err(|e| violation(e.to_string()))?
            )
        );
        let mut preimage = value.clone();
        preimage
            .as_object_mut()
            .ok_or_else(|| violation("receipt object".into()))?
            .remove("decision_id");
        let receipt_hash = format!(
            "sha256:{:x}",
            Sha256::digest(serde_jcs::to_vec(&preimage).map_err(|e| violation(e.to_string()))?)
        );
        if dto.request_digest != request_hash || dto.decision_id != receipt_hash {
            return Err(violation("purpose receipt digest mismatch".into()));
        }
        let now = chrono::DateTime::parse_from_rfc3339(observed_at)
            .map_err(|e| violation(e.to_string()))?;
        let generated = chrono::DateTime::parse_from_rfc3339(&dto.generated_at)
            .map_err(|e| violation(e.to_string()))?;
        let expires = chrono::DateTime::parse_from_rfc3339(
            value["expires_at"]
                .as_str()
                .ok_or_else(|| violation("expiry absent".into()))?,
        )
        .map_err(|e| violation(e.to_string()))?;
        if now < generated || (dto.decision == "supported_readonly" && now >= expires) {
            return Err(violation("purpose receipt future or expired".into()));
        }
        Ok(dto)
    }

    fn parse_schema(bytes: &[u8], expected_profile: &str, expected_schema: &str) -> Result<Self> {
        let dto: Self =
            serde_json::from_slice(bytes).map_err(|e| NightShiftError::NqContractViolation {
                kind: NqContractViolationKind::MalformedField,
                detail: format!("reliance receipt is not decodable: {e}"),
            })?;
        if dto.schema != expected_schema {
            return Err(NightShiftError::NqContractViolation {
                kind: NqContractViolationKind::SchemaMismatch,
                detail: format!(
                    "expected {NQ_RELIANCE_RECEIPT_SCHEMA}, got {:?}",
                    dto.schema
                ),
            });
        }
        // A receipt addressed to a different consumer is not ours to act on.
        if dto.consumer_profile_id != expected_profile {
            return Err(NightShiftError::NqContractViolation {
                kind: NqContractViolationKind::MalformedField,
                detail: format!(
                    "receipt is for consumer {:?}, this consumer is {expected_profile:?}",
                    dto.consumer_profile_id
                ),
            });
        }
        // An undisclosed binding is not consumable: without the disclosure a
        // reader cannot tell a configured selection from an authenticated one.
        if dto.caller_binding_disclosure.trim().is_empty() {
            return Err(NightShiftError::NqContractViolation {
                kind: NqContractViolationKind::MalformedField,
                detail: "caller_binding_disclosure is empty".into(),
            });
        }
        if dto.decision_id.is_empty() || dto.receipt_content_hash.is_empty() {
            return Err(NightShiftError::NqContractViolation {
                kind: NqContractViolationKind::MalformedField,
                detail: "decision_id and receipt_content_hash must be present".into(),
            });
        }
        // Integrity only, never sufficiency: a supporting disclosure that
        // cannot be identified is malformed. Whether the *right* supporting
        // claims are present is NQ's decided law, not re-checked here.
        for s in &dto.supporting_receipts {
            if s.claim.is_empty() || s.content_hash.is_empty() {
                return Err(NightShiftError::NqContractViolation {
                    kind: NqContractViolationKind::MalformedField,
                    detail: "a supporting receipt ref lacks claim or content_hash".into(),
                });
            }
        }
        Ok(dto)
    }
}

/// What Night Shift observed when it asked NQ.
///
/// Only [`SourceState::Fresh`] is NQ testimony. The rest are Night Shift's own
/// observations and must never be phrased as NQ conclusions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceState {
    /// NQ returned a typed decision within the freshness window. NQ testimony.
    Fresh,
    /// NQ returned a typed decision, but it is older than this consumer's
    /// freshness policy. Still NQ testimony — aged.
    Stale {
        age_seconds: i64,
        max_age_seconds: u64,
    },
    /// NQ did not answer before Night Shift's timeout. **Night Shift's own
    /// observation.** Carries both numbers, as `LivenessVerdict::Stale` does.
    NoResponse {
        elapsed_seconds: u64,
        timeout_seconds: u64,
    },
    /// The NQ transport could not be invoked at all. Night Shift's observation.
    TransportUnavailable { detail: String },
    /// NQ output failed the contract check, or the receipt did not match what
    /// was asked for. Night Shift's integrity observation.
    Malformed { detail: String },
}

impl SourceState {
    /// Whether this state carries current NQ testimony.
    #[must_use]
    pub fn is_nq_testimony(&self) -> bool {
        matches!(self, Self::Fresh | Self::Stale { .. })
    }
}

/// A read-only posture proposal. **None of these is an instruction to act.**
///
/// This enum states the bounded read-only disposition; it does not diagnose
/// why that disposition was reached. In particular, distinct integrity,
/// configuration, and policy failures may all produce `Stop`. Consumers that
/// explain or classify the cause must use the containing [`DispositionRecord`]
/// and retain its `source_state`, `source`, and `reasons` rather than treating
/// this enum as a causal summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    /// Bounded evidence is fresh and permits continued read-only consideration.
    ContinueObserving,
    /// The answer may change with newer evidence. Not a retry instruction.
    WaitForFreshEvidence,
    /// Night Shift's own observation that no fresh NQ testimony arrived.
    EvidenceUnavailable,
    /// A named further piece of evidence would resolve this.
    RequestAdditionalEvidence,
    /// A person must decide. Night Shift will not, and this sends no message.
    HumanJudgmentRequired,
    /// Do not proceed on this line.
    Stop,
}

/// The record Night Shift emits. Carries source identities verbatim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispositionRecord {
    pub schema: String,
    /// Deterministic self-identity: sha256 over the JCS form of this record
    /// with `disposition_id` set to the empty string. Defaulted so pilot-era
    /// records (which predate the field) still deserialize.
    #[serde(default)]
    pub disposition_id: String,
    /// The consumer profile this consumer was configured to expect when it
    /// parsed the source receipt. Disclosed so a reader can tell a base
    /// posture from a continuity-gated one without inspecting the source.
    #[serde(default)]
    pub expected_consumer_profile: String,
    pub observed_at: String,
    pub source_state: SourceState,
    /// Bounded read-only directive, not a diagnosis. Consumers explaining the
    /// cause must retain this record's source and reasons.
    pub disposition: Disposition,
    pub reasons: Vec<String>,
    /// Present only when NQ testimony was available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceBinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_next_evidence: Option<String>,
    pub human_judgment_required: bool,
    pub establishes: Vec<String>,
    pub does_not_establish: Vec<String>,
}

/// Exact NQ identities, carried through unmodified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceBinding {
    pub schema: String,
    pub decision_id: String,
    pub receipt_content_hash: String,
    pub request_digest: String,
    pub evidence_context_digest: String,
    pub consumer_profile_id: String,
    pub caller_binding: String,
    pub caller_binding_disclosure: String,
    pub purpose: String,
    pub claim: String,
    pub underlying_status: String,
    pub decision: String,
    pub premises: Vec<String>,
    pub coverage_limits: Vec<String>,
    pub unresolved_residuals: Vec<String>,
    pub retained_contradictions: Vec<String>,
    /// Supporting evaluations exactly as NQ disclosed them. Absent-when-empty
    /// keeps pre-extension binding bytes identical.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supporting_receipts: Vec<SupportingReceiptRefDto>,
    pub policy_version: String,
    pub generated_at: String,
}

impl From<&NqRelianceReceiptDto> for SourceBinding {
    fn from(d: &NqRelianceReceiptDto) -> Self {
        Self {
            schema: d.schema.clone(),
            decision_id: d.decision_id.clone(),
            receipt_content_hash: d.receipt_content_hash.clone(),
            request_digest: d.request_digest.clone(),
            evidence_context_digest: d.evidence_context_digest.clone(),
            consumer_profile_id: d.consumer_profile_id.clone(),
            caller_binding: d.caller_binding.clone(),
            caller_binding_disclosure: d.caller_binding_disclosure.clone(),
            purpose: d.purpose.clone(),
            claim: d.claim.clone(),
            underlying_status: d.underlying_status.clone(),
            decision: d.decision.clone(),
            premises: d.premises.clone(),
            coverage_limits: d.coverage_limits.clone(),
            unresolved_residuals: d.unresolved_residuals.clone(),
            retained_contradictions: d.retained_contradictions.clone(),
            supporting_receipts: d.supporting_receipts.clone(),
            policy_version: d.policy_version.clone(),
            generated_at: d.generated_at.clone(),
        }
    }
}

pub const DISPOSITION_SCHEMA: &str = "nightshift.readonly_disposition.v1";

/// Native factual eligibility and authority-owned present support are separate
/// axes. This record does not rewrite NQ's historical purpose receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentPurposeDisposition {
    pub schema: String,
    pub purpose: String,
    pub nq_decision_id: String,
    pub query: crate::currentness::PresentEvidenceQueryV1,
    pub support: Option<crate::currentness::QualifiedSupportV1>,
    pub disposition: Disposition,
    pub reason: String,
    pub does_not_establish: Vec<String>,
}

/// Compose an exact native retained-claim eligibility result with the existing
/// live present-evidence port. Only that port owns currentness. Neither an
/// artifact timestamp nor a file containing an old support result is Fresh.
#[allow(clippy::too_many_arguments)]
pub fn qualify_current_purpose(
    bytes: &[u8],
    expected_request: &serde_json::Value,
    observed_at: &str,
    purpose: &str,
    inputs: &crate::diagnostic_posture::DiagnosticInputs,
    cycle_id: &str,
    nonce: &str,
    expected_authority: &str,
    port: &mut dyn crate::currentness::PresentEvidencePortV1,
) -> std::result::Result<CurrentPurposeDisposition, String> {
    use crate::currentness::{delivered_artifact_ids, PresentEvidenceQueryV1, SupportStandingV1};
    use sha2::{Digest, Sha256};
    if purpose != "continue_observing" || expected_authority.trim().is_empty() {
        return Err("unsupported current purpose or absent support authority".into());
    }
    let dto = NqRelianceReceiptDto::parse_for_request(bytes, expected_request, observed_at)
        .map_err(|e| e.to_string())?;
    if dto.purpose != "historical_readonly" || dto.consumer_profile_id != "nightshift-readonly" {
        return Err("current composition requires explicit base historical eligibility; continuity prerequisites are not interchangeable".into());
    }
    inputs.validate()?;
    let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let ids = delivered_artifact_ids(inputs);
    if ids != vec![dto.receipt_content_hash.clone()] || inputs.inputs.len() != 1 {
        return Err("purpose support requires exact single-artifact input basis".into());
    }
    let crate::diagnostic_posture::DiagnosticInputStatus::Delivered { artifact } =
        &inputs.inputs[0].status
    else {
        return Err("purpose artifact not delivered".into());
    };
    if serde_json::to_value(artifact).map_err(|e| e.to_string())? != v["source_artifact"] {
        return Err("purpose artifact bytes differ from qualified NQ source".into());
    }
    let subject = &v["source_artifact"]["subject"];
    let observation_id=format!("sha256:{:x}",Sha256::digest(serde_jcs::to_vec(&serde_json::json!({"nq_decision_id":dto.decision_id,"purpose":purpose,"authority":expected_authority})).map_err(|e|e.to_string())?));
    let query = PresentEvidenceQueryV1 {
        schema: String::new(),
        query_id: String::new(),
        observation_cycle_id: cycle_id.into(),
        request_nonce: nonce.into(),
        observation_id,
        diagnostic_inputs_id: inputs.inputs_id.clone(),
        subject_id: subject["id"].as_str().ok_or("subject absent")?.into(),
        scope_id: subject["scope"]["digest"]
            .as_str()
            .ok_or("scope absent")?
            .into(),
        artifact_ids: ids,
    }
    .seal()?;
    let mut result = CurrentPurposeDisposition {
        schema: "nightshift.current-purpose-disposition/v1".into(),
        purpose: purpose.into(),
        nq_decision_id: dto.decision_id.clone(),
        query: query.clone(),
        support: None,
        disposition: Disposition::EvidenceUnavailable,
        reason: String::new(),
        does_not_establish: vec![
            "no action authorized or executed".into(),
            "NQ factual qualification and present evidence retain separate owners".into(),
            "stored support is historical; only the exact live query response applies".into(),
        ],
    };
    if dto.decision != "supported_readonly" {
        result.disposition = derive_disposition(
            &SourceState::Fresh,
            Some(&dto),
            observed_at,
            &dto.consumer_profile_id,
        )
        .disposition;
        result.reason =
            "NQ did not establish factual eligibility; present support cannot repair that refusal"
                .into();
        return Ok(result);
    }
    match port.resolve(&query) {
        Err(reason) => result.reason = format!("present evidence unavailable: {reason}"),
        Ok(support) => {
            support.validate_for(&query)?;
            if support.authority_id != expected_authority {
                return Err("present support source does not match configured authority".into());
            }
            result.disposition = match support.standing {
                SupportStandingV1::Current if !support.evidence_refs.is_empty() => {
                    Disposition::ContinueObserving
                }
                SupportStandingV1::Current => {
                    return Err("current support lacks evidence references".into())
                }
                SupportStandingV1::Expired => Disposition::WaitForFreshEvidence,
                SupportStandingV1::Contradictory => Disposition::HumanJudgmentRequired,
                _ => Disposition::EvidenceUnavailable,
            };
            result.reason = format!(
                "qualified present-evidence authority returned {:?}; no action authority",
                support.standing
            );
            result.support = Some(support);
        }
    }
    Ok(result)
}

/// Limits stamped on every record, whatever the disposition.
fn mandatory_does_not_establish() -> Vec<String> {
    vec![
        "no action was executed or authorized by this disposition".to_string(),
        "this is a read-only posture proposal, not execution authority".to_string(),
        "this disposition is Night Shift's, not an NQ claim".to_string(),
    ]
}

/// Derive a read-only disposition.
///
/// Pure: no I/O, no state mutation, no message sent to anyone.
#[must_use]
pub fn derive_disposition(
    state: &SourceState,
    receipt: Option<&NqRelianceReceiptDto>,
    observed_at: &str,
    expected_profile: &str,
) -> DispositionRecord {
    let mut reasons = Vec::new();
    let mut required_next_evidence = None;

    let disposition = match state {
        // Night Shift's own observations. No NQ conclusion is implied, and the
        // reasons say whose observation this is.
        SourceState::NoResponse {
            elapsed_seconds,
            timeout_seconds,
        } => {
            reasons.push(format!(
                "no fresh NQ response within Night Shift's {timeout_seconds}s timeout \
                 (elapsed {elapsed_seconds}s); this is Night Shift's observation, not NQ testimony"
            ));
            Disposition::EvidenceUnavailable
        }
        SourceState::TransportUnavailable { detail } => {
            reasons.push(format!(
                "NQ transport unavailable: {detail}; this is Night Shift's observation, \
                 not NQ testimony"
            ));
            Disposition::EvidenceUnavailable
        }
        SourceState::Malformed { detail } => {
            reasons.push(format!("NQ output failed the contract check: {detail}"));
            Disposition::Stop
        }
        SourceState::Stale {
            age_seconds,
            max_age_seconds,
        } => {
            reasons.push(format!(
                "NQ testimony is {age_seconds}s old, beyond Night Shift's {max_age_seconds}s \
                 freshness policy"
            ));
            required_next_evidence = Some("a fresher NQ reliance decision".to_string());
            Disposition::WaitForFreshEvidence
        }
        SourceState::Fresh => {
            let Some(r) = receipt else {
                reasons.push("source state is fresh but no receipt was supplied".to_string());
                return finish(
                    Disposition::Stop,
                    state,
                    None,
                    reasons,
                    None,
                    observed_at,
                    expected_profile,
                );
            };
            match r.decision.as_str() {
                "supported_readonly" | "authorized_reliance" => {
                    reasons.push(format!(
                        "NQ authorized reliance on {:?} for purpose {:?}",
                        r.claim, r.purpose
                    ));
                    Disposition::ContinueObserving
                }
                // Never a retry licence.
                "claim_not_verified" => {
                    reasons.push(format!(
                        "NQ did not verify {:?} (underlying status {:?}); this is not \
                         permission to retry or proceed",
                        r.claim, r.underlying_status
                    ));
                    required_next_evidence =
                        Some(format!("evidence sufficient to verify {}", r.claim));
                    Disposition::RequestAdditionalEvidence
                }
                // Inability is never success.
                "cannot_testify" => {
                    reasons.push(format!(
                        "NQ constitutionally declines to testify to {:?}; inability is not \
                         authorization",
                        r.claim
                    ));
                    Disposition::HumanJudgmentRequired
                }
                "contradiction_retained" => {
                    reasons.push(
                        "NQ retained a contradiction in the source testimony; Night Shift \
                         does not resolve contradictions"
                            .to_string(),
                    );
                    Disposition::HumanJudgmentRequired
                }
                "premise_not_accepted" => {
                    reasons.push(
                        "a source premise is not acceptable under this consumer's policy; \
                         a premise-qualified operator decision is required"
                            .to_string(),
                    );
                    Disposition::HumanJudgmentRequired
                }
                "residual_obligation_blocks" => {
                    reasons.push(
                        "an unresolved upstream obligation blocks reliance; Night Shift \
                         discharges nothing"
                            .to_string(),
                    );
                    Disposition::HumanJudgmentRequired
                }
                "stale_evidence" => {
                    reasons.push("NQ judged the underlying evidence stale".to_string());
                    required_next_evidence = Some("fresher underlying evidence".to_string());
                    Disposition::WaitForFreshEvidence
                }
                "claim_non_mintable" | "coverage_insufficient" | "custody_basis_not_accepted" => {
                    reasons.push(format!(
                        "NQ refused reliance: {}; this is a statement about reliance, not a \
                         refutation of the claim",
                        r.decision
                    ));
                    Disposition::HumanJudgmentRequired
                }
                // Configuration or policy errors: stop rather than adapt.
                "consumer_unknown"
                | "claim_not_authorized_for_consumer"
                | "purpose_not_authorized" => {
                    reasons.push(format!(
                        "configuration or policy error: {}; Night Shift does not widen its \
                         own permissions",
                        r.decision
                    ));
                    Disposition::Stop
                }
                "malformed_request" => {
                    reasons.push(
                        "NQ refused the request as malformed or substituted; integrity failure"
                            .to_string(),
                    );
                    Disposition::Stop
                }
                other => {
                    reasons.push(format!(
                        "unrecognized NQ decision {other:?}; Night Shift does not guess at \
                         an unknown outcome"
                    ));
                    Disposition::HumanJudgmentRequired
                }
            }
        }
    };

    finish(
        disposition,
        state,
        receipt,
        reasons,
        required_next_evidence,
        observed_at,
        expected_profile,
    )
}

#[allow(clippy::too_many_arguments)]
fn finish(
    disposition: Disposition,
    state: &SourceState,
    receipt: Option<&NqRelianceReceiptDto>,
    reasons: Vec<String>,
    required_next_evidence: Option<String>,
    observed_at: &str,
    expected_profile: &str,
) -> DispositionRecord {
    let mut does_not_establish = mandatory_does_not_establish();
    let mut establishes = Vec::new();

    if let Some(r) = receipt {
        does_not_establish.extend(r.does_not_establish.clone());
        // Carried facts survive the projection, whatever the disposition.
        if !r.unresolved_residuals.is_empty() {
            does_not_establish
                .push("upstream residual obligations carried here remain undischarged".to_string());
        }
        if !r.retained_contradictions.is_empty() {
            does_not_establish
                .push("a retained contradiction is preserved here and is not resolved".to_string());
        }
        if !r.premises.is_empty() {
            does_not_establish.push(
                "source premises are carried, not discharged or independently verified".to_string(),
            );
        }
        does_not_establish.push(r.caller_binding_disclosure.clone());
        if disposition == Disposition::ContinueObserving {
            establishes.push(if r.decision=="supported_readonly" {
                format!("NQ supports only the explicit {:?} consideration of retained claim {:?}; source currentness is not inferred",r.purpose,r.claim)
            } else {
                format!("Historical NQ authorized this consumer to rely on {:?} for {:?}; Night Shift may continue read-only consideration",r.claim,r.purpose)
            });
        }
    }

    if !state.is_nq_testimony() {
        does_not_establish.push(
            "no current NQ testimony was available; absence of a response is not evidence \
             of health or of failure"
                .to_string(),
        );
    }

    let mut record = DispositionRecord {
        schema: DISPOSITION_SCHEMA.to_string(),
        disposition_id: String::new(),
        expected_consumer_profile: expected_profile.to_string(),
        observed_at: observed_at.to_string(),
        source_state: state.clone(),
        disposition,
        reasons,
        source: receipt.map(SourceBinding::from),
        required_next_evidence,
        human_judgment_required: disposition == Disposition::HumanJudgmentRequired,
        establishes,
        does_not_establish,
    };
    record.disposition_id = disposition_id_for(&record);
    record
}

/// sha256 over the JCS form of the record with `disposition_id` empty.
///
/// Deterministic in the inputs alone: the same source state, receipt,
/// observation instant, and expected profile always name the same disposition.
fn disposition_id_for(record: &DispositionRecord) -> String {
    use sha2::{Digest, Sha256};
    let canonical = serde_jcs::to_string(record)
        .expect("DispositionRecord serializes: no non-string keys, no NaN");
    format!("sha256:{:x}", Sha256::digest(canonical.as_bytes()))
}

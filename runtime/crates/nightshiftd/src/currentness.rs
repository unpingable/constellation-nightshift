//! Qualified present-evidence boundary for canonical Nightshift.
//!
//! Pulse (or another qualified observation authority) owns support
//! currentness. Nightshift consumes an exact, cycle-bound result; it never
//! recomputes support from producer wall-clock timestamps.

use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const SUPPORT_QUERY_SCHEMA_V1: &str = "nightshift.present_evidence_query.v1";
pub const QUALIFIED_SUPPORT_SCHEMA_V1: &str = "nightshift.qualified_support.v1";

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

fn object_id<T: Serialize>(value: &T, identity_field: &str) -> Result<String, String> {
    let mut value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    value
        .as_object_mut()
        .ok_or_else(|| "identity-bearing value must be an object".to_string())?
        .remove(identity_field);
    let bytes = serde_jcs::to_vec(&value).map_err(|error| error.to_string())?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn strictly_ordered_unique(values: &[String], field: &str) -> Result<(), String> {
    let mut previous: Option<&str> = None;
    for value in values {
        require_token(field, value)?;
        if previous.is_some_and(|item| item >= value.as_str()) {
            return Err(format!("{field} must be strictly ordered and unique"));
        }
        previous = Some(value);
    }
    Ok(())
}

fn strictly_ordered_unique_digests(values: &[String], field: &str) -> Result<(), String> {
    strictly_ordered_unique(values, field)?;
    for value in values {
        require_digest(field, value)?;
    }
    Ok(())
}

/// An instant on the evidence authority's qualified receiver clock.
///
/// The tick has no wall-clock interpretation in Nightshift. It is comparable
/// only with another instant carrying the same `clock_id`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupportReceiverInstantV1 {
    pub clock_id: String,
    pub tick: u64,
}

impl SupportReceiverInstantV1 {
    fn validate(&self, field: &str) -> Result<(), String> {
        require_token(&format!("{field}.clock_id"), &self.clock_id)
    }
}

/// Pulse-owned support expiry. Support is current only when
/// `expiry.tick > evaluated_at.tick` on the same receiver clock.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupportExpiryV1 {
    pub clock_id: String,
    pub tick: u64,
}

impl SupportExpiryV1 {
    pub fn is_current_at(&self, evaluated_at: &SupportReceiverInstantV1) -> Result<bool, String> {
        require_token("support_expiry.clock_id", &self.clock_id)?;
        evaluated_at.validate("evaluated_at")?;
        if self.clock_id != evaluated_at.clock_id {
            return Err("support expiry and evaluation use different receiver clocks".into());
        }
        Ok(self.tick > evaluated_at.tick)
    }
}

/// Nightshift scheduler-owned end of an admissible recurrence window.
/// Equality is admitted. This type cannot be substituted for support expiry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecurrenceLatestAdmissibleV1 {
    pub scheduler_clock_id: String,
    pub at: DateTime<Utc>,
}

impl RecurrenceLatestAdmissibleV1 {
    pub fn admits(&self, scheduler_clock_id: &str, now: DateTime<Utc>) -> Result<bool, String> {
        require_token("scheduler_clock_id", scheduler_clock_id)?;
        require_token(
            "latest_admissible.scheduler_clock_id",
            &self.scheduler_clock_id,
        )?;
        if scheduler_clock_id != self.scheduler_clock_id {
            return Err("recurrence instants use different scheduler clocks".into());
        }
        Ok(now <= self.at)
    }
}

/// Nightshift-owned temporal hold/horizon expiry. A hold is active only while
/// `now < expiry`; equality is expired.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalHoldExpiryV1 {
    pub scheduler_clock_id: String,
    pub at: DateTime<Utc>,
}

impl TemporalHoldExpiryV1 {
    pub fn is_active(&self, scheduler_clock_id: &str, now: DateTime<Utc>) -> Result<bool, String> {
        require_token("scheduler_clock_id", scheduler_clock_id)?;
        require_token("hold_expiry.scheduler_clock_id", &self.scheduler_clock_id)?;
        if scheduler_clock_id != self.scheduler_clock_id {
            return Err("hold instants use different scheduler clocks".into());
        }
        Ok(now < self.at)
    }
}

/// Closed authority-owned present-support result.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportStandingV1 {
    Current,
    Expired,
    Unknown,
    Unsupported,
    Contradictory,
    Blind,
}

/// Exact request to a present-evidence authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PresentEvidenceQueryV1 {
    pub schema: String,
    pub query_id: String,
    pub observation_cycle_id: String,
    pub request_nonce: String,
    pub observation_id: String,
    pub diagnostic_inputs_id: String,
    pub subject_id: String,
    pub scope_id: String,
    pub artifact_ids: Vec<String>,
}

impl PresentEvidenceQueryV1 {
    pub fn seal(mut self) -> Result<Self, String> {
        self.schema = SUPPORT_QUERY_SCHEMA_V1.into();
        self.query_id.clear();
        self.query_id = object_id(&self, "query_id")?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != SUPPORT_QUERY_SCHEMA_V1 {
            return Err(format!("unsupported support query schema {}", self.schema));
        }
        for (name, value) in [
            ("query_id", &self.query_id),
            ("observation_id", &self.observation_id),
            ("diagnostic_inputs_id", &self.diagnostic_inputs_id),
            ("scope_id", &self.scope_id),
        ] {
            require_digest(name, value)?;
        }
        for (name, value) in [
            ("observation_cycle_id", &self.observation_cycle_id),
            ("request_nonce", &self.request_nonce),
            ("subject_id", &self.subject_id),
        ] {
            require_token(name, value)?;
        }
        strictly_ordered_unique_digests(&self.artifact_ids, "artifact_ids")?;
        if self.query_id != object_id(self, "query_id")? {
            return Err("query_id does not match the canonical query preimage".into());
        }
        Ok(())
    }
}

/// Exact qualified result returned by Pulse or another evidence authority.
///
/// Persistence makes this historical evidence only. The cycle runtime accepts
/// it solely as the response to the exact in-process query below.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedSupportV1 {
    pub schema: String,
    pub support_id: String,
    pub authority_id: String,
    pub query_id: String,
    pub observation_cycle_id: String,
    pub request_nonce: String,
    pub observation_id: String,
    pub diagnostic_inputs_id: String,
    pub subject_id: String,
    pub scope_id: String,
    pub artifact_ids: Vec<String>,
    pub evaluated_at: SupportReceiverInstantV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry: Option<SupportExpiryV1>,
    pub standing: SupportStandingV1,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contradiction_refs: Vec<String>,
}

impl QualifiedSupportV1 {
    pub fn computed_support_id(&self) -> Result<String, String> {
        object_id(self, "support_id")
    }

    /// Validate the intrinsic result, including the strict Pulse expiry law.
    /// This validates historical evidence shape only; it does not substitute
    /// for the live query binding enforced by [`Self::validate_for`].
    pub fn validate_shape(&self) -> Result<(), String> {
        if self.schema != QUALIFIED_SUPPORT_SCHEMA_V1 {
            return Err(format!(
                "unsupported qualified support schema {}",
                self.schema
            ));
        }
        for (name, value) in [
            ("support_id", &self.support_id),
            ("query_id", &self.query_id),
            ("observation_id", &self.observation_id),
            ("diagnostic_inputs_id", &self.diagnostic_inputs_id),
            ("scope_id", &self.scope_id),
        ] {
            require_digest(name, value)?;
        }
        for (name, value) in [
            ("authority_id", &self.authority_id),
            ("observation_cycle_id", &self.observation_cycle_id),
            ("request_nonce", &self.request_nonce),
            ("subject_id", &self.subject_id),
        ] {
            require_token(name, value)?;
        }
        self.evaluated_at.validate("evaluated_at")?;
        strictly_ordered_unique_digests(&self.artifact_ids, "artifact_ids")?;
        strictly_ordered_unique_digests(&self.evidence_refs, "evidence_refs")?;
        strictly_ordered_unique_digests(&self.contradiction_refs, "contradiction_refs")?;
        let expiry_current = self
            .expiry
            .as_ref()
            .map(|expiry| expiry.is_current_at(&self.evaluated_at))
            .transpose()?;
        match self.standing {
            SupportStandingV1::Current if expiry_current != Some(true) => {
                return Err("current support requires expiry strictly after evaluation".into())
            }
            SupportStandingV1::Expired if expiry_current != Some(false) => {
                return Err("expired support requires expiry at or before evaluation".into())
            }
            SupportStandingV1::Contradictory if self.contradiction_refs.is_empty() => {
                return Err("contradictory support requires exact contradiction references".into())
            }
            SupportStandingV1::Current if !self.contradiction_refs.is_empty() => {
                return Err("current support cannot carry unresolved contradictions".into())
            }
            _ => {}
        }
        if self.support_id != self.computed_support_id()? {
            return Err("support_id does not match the canonical support preimage".into());
        }
        Ok(())
    }

    pub fn validate_for(&self, query: &PresentEvidenceQueryV1) -> Result<(), String> {
        query.validate()?;
        self.validate_shape()?;
        if self.schema != QUALIFIED_SUPPORT_SCHEMA_V1 {
            return Err(format!(
                "unsupported qualified support schema {}",
                self.schema
            ));
        }
        if self.query_id != query.query_id
            || self.observation_cycle_id != query.observation_cycle_id
            || self.request_nonce != query.request_nonce
            || self.observation_id != query.observation_id
            || self.diagnostic_inputs_id != query.diagnostic_inputs_id
            || self.subject_id != query.subject_id
            || self.scope_id != query.scope_id
            || self.artifact_ids != query.artifact_ids
        {
            return Err("qualified support does not exactly bind the live query".into());
        }
        let expiry_current = self
            .expiry
            .as_ref()
            .map(|expiry| expiry.is_current_at(&self.evaluated_at))
            .transpose()?;
        match self.standing {
            SupportStandingV1::Current if expiry_current != Some(true) => {
                return Err("current support requires expiry strictly after evaluation".into())
            }
            SupportStandingV1::Expired if expiry_current != Some(false) => {
                return Err("expired support requires expiry at or before evaluation".into())
            }
            SupportStandingV1::Contradictory if self.contradiction_refs.is_empty() => {
                return Err("contradictory support requires exact contradiction references".into())
            }
            SupportStandingV1::Current if !self.contradiction_refs.is_empty() => {
                return Err("current support cannot carry unresolved contradictions".into())
            }
            _ => {}
        }
        if self.support_id != self.computed_support_id()? {
            return Err("support_id does not match the canonical support preimage".into());
        }
        Ok(())
    }
}

/// Read-only port to the authority that owns present support/currentness.
pub trait PresentEvidencePortV1 {
    fn resolve(&mut self, query: &PresentEvidenceQueryV1) -> Result<QualifiedSupportV1, String>;
}

/// Stable command adapter. The child receives one exact query on stdin and
/// must return one exact qualified result on stdout. This is an observation
/// read; it is not an effect or authority service.
#[derive(Clone, Debug)]
pub struct CommandPresentEvidencePortV1 {
    program: PathBuf,
}

impl CommandPresentEvidencePortV1 {
    pub fn new(program: impl Into<PathBuf>) -> Result<Self, String> {
        let program = program.into();
        if program.file_name().and_then(|name| name.to_str()) != Some("pulse-support-resolver") {
            return Err(
                "present-evidence adapter accepts only the pulse-support-resolver executable"
                    .into(),
            );
        }
        Ok(Self { program })
    }

    pub fn program(&self) -> &Path {
        &self.program
    }
}

impl PresentEvidencePortV1 for CommandPresentEvidencePortV1 {
    fn resolve(&mut self, query: &PresentEvidenceQueryV1) -> Result<QualifiedSupportV1, String> {
        query.validate()?;
        let mut child = Command::new(&self.program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("present-evidence resolver spawn failed: {error}"))?;
        child
            .stdin
            .take()
            .ok_or_else(|| "present-evidence resolver stdin unavailable".to_string())?
            .write_all(&serde_jcs::to_vec(query).map_err(|error| error.to_string())?)
            .map_err(|error| format!("present-evidence resolver write failed: {error}"))?;
        let output = child
            .wait_with_output()
            .map_err(|error| format!("present-evidence resolver wait failed: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "present-evidence resolver refused: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let support: QualifiedSupportV1 = serde_json::from_slice(&output.stdout)
            .map_err(|error| format!("present-evidence resolver returned invalid JSON: {error}"))?;
        support.validate_for(query)?;
        Ok(support)
    }
}

/// Test/in-process adapter that still validates exact live-query binding.
#[derive(Clone, Debug)]
pub struct FixedPresentEvidencePortV1 {
    support: QualifiedSupportV1,
}

impl FixedPresentEvidencePortV1 {
    pub fn new(support: QualifiedSupportV1) -> Self {
        Self { support }
    }
}

impl PresentEvidencePortV1 for FixedPresentEvidencePortV1 {
    fn resolve(&mut self, query: &PresentEvidenceQueryV1) -> Result<QualifiedSupportV1, String> {
        self.support.validate_for(query)?;
        Ok(self.support.clone())
    }
}

pub fn delivered_artifact_ids(inputs: &crate::diagnostic_posture::DiagnosticInputs) -> Vec<String> {
    let mut ids: BTreeSet<String> = BTreeSet::new();
    for input in &inputs.inputs {
        if let crate::diagnostic_posture::DiagnosticInputStatus::Delivered { artifact } =
            &input.status
        {
            ids.insert(artifact.artifact_id().to_owned());
        }
    }
    ids.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn query() -> PresentEvidenceQueryV1 {
        PresentEvidenceQueryV1 {
            schema: String::new(),
            query_id: String::new(),
            observation_cycle_id: "cycle-1".into(),
            request_nonce: "nonce-1".into(),
            observation_id: digest('a'),
            diagnostic_inputs_id: digest('b'),
            subject_id: "subject-1".into(),
            scope_id: digest('c'),
            artifact_ids: vec![digest('d')],
        }
        .seal()
        .unwrap()
    }

    fn support(
        query: &PresentEvidenceQueryV1,
        standing: SupportStandingV1,
        expiry: u64,
    ) -> QualifiedSupportV1 {
        let mut support = QualifiedSupportV1 {
            schema: QUALIFIED_SUPPORT_SCHEMA_V1.into(),
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
                clock_id: "pulse-rx".into(),
                tick: 10,
            },
            expiry: Some(SupportExpiryV1 {
                clock_id: "pulse-rx".into(),
                tick: expiry,
            }),
            standing,
            evidence_refs: vec![digest('e')],
            contradiction_refs: Vec::new(),
        };
        support.support_id = support.computed_support_id().unwrap();
        support
    }

    #[test]
    fn pulse_equality_is_expired() {
        let query = query();
        let expired = support(&query, SupportStandingV1::Expired, 10);
        expired.validate_for(&query).unwrap();
        let mut falsely_current = expired.clone();
        falsely_current.standing = SupportStandingV1::Current;
        falsely_current.support_id = falsely_current.computed_support_id().unwrap();
        assert!(falsely_current.validate_for(&query).is_err());
    }

    #[test]
    fn recurrence_equality_is_admitted_but_hold_equality_is_expired() {
        let now = DateTime::parse_from_rfc3339("2026-08-11T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let latest = RecurrenceLatestAdmissibleV1 {
            scheduler_clock_id: "ns".into(),
            at: now,
        };
        let hold = TemporalHoldExpiryV1 {
            scheduler_clock_id: "ns".into(),
            at: now,
        };
        assert!(latest.admits("ns", now).unwrap());
        assert!(!hold.is_active("ns", now).unwrap());
    }

    #[test]
    fn support_is_bound_to_one_live_cycle_query() {
        let query = query();
        let support = support(&query, SupportStandingV1::Current, 11);
        support.validate_for(&query).unwrap();
        let mut other = query.clone();
        other.observation_cycle_id = "cycle-2".into();
        other.query_id = object_id(&other, "query_id").unwrap();
        assert!(support.validate_for(&other).is_err());
    }

    #[test]
    fn support_from_another_observation_or_receiver_clock_refuses() {
        let query = query();
        let mut substituted = support(&query, SupportStandingV1::Current, 11);
        substituted.observation_id = digest('9');
        substituted.support_id = substituted.computed_support_id().unwrap();
        assert!(substituted.validate_for(&query).is_err());

        let mut wrong_clock = support(&query, SupportStandingV1::Current, 11);
        wrong_clock.expiry.as_mut().unwrap().clock_id = "different-clock".into();
        wrong_clock.support_id = wrong_clock.computed_support_id().unwrap();
        assert!(wrong_clock.validate_for(&query).is_err());
    }

    #[test]
    fn command_adapter_rejects_an_arbitrary_executable() {
        assert!(CommandPresentEvidencePortV1::new("sh").is_err());
        assert!(CommandPresentEvidencePortV1::new("pulse-support-resolver").is_ok());
    }
}

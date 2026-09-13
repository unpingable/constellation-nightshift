use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub const CAPACITY_OBSERVATION_SCHEMA_V1: &str = "nightshift.provider-capacity-observation/v1";
pub const CAPACITY_POLICY_SCHEMA_V1: &str = "nightshift.provider-capacity-policy/v1";
pub const CAPACITY_DECISION_SCHEMA_V1: &str = "nightshift.provider-capacity-decision/v1";

const OBSERVATION_DOMAIN: &[u8] = b"nightshift.provider-capacity-observation.digest/v1\0";
const POLICY_DOMAIN: &[u8] = b"nightshift.provider-capacity-policy.digest/v1\0";
const DECISION_DOMAIN: &[u8] = b"nightshift.provider-capacity-decision.digest/v1\0";

#[derive(Debug, Error)]
pub enum CapacityError {
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("invalid capacity record: {0}")]
    Invalid(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceClass {
    Authoritative,
    Observed,
    Inferred,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Confidence {
    Unknown,
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservationDisposition {
    Usable,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WindowType {
    FiveHour,
    Weekly,
    ProviderDefined,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemainingUnits {
    pub remaining: u64,
    pub maximum: u64,
    pub unit: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityWindow {
    pub window_id: String,
    pub window_type: WindowType,
    pub remaining_fraction: Option<f64>,
    pub remaining_units: Option<RemainingUnits>,
    pub resets_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationEvidence {
    pub probe_id: String,
    pub protocol_method: String,
    pub protocol_version: Option<String>,
    pub executable_path: Option<String>,
    pub executable_digest: Option<String>,
    pub raw_source_digest: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityObservationV1 {
    pub schema: String,
    pub provider_id: String,
    pub account_profile_locator: String,
    pub model_family: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub source_class: SourceClass,
    pub confidence: Confidence,
    pub disposition: ObservationDisposition,
    pub unknown_reasons: Vec<String>,
    pub windows: Vec<CapacityWindow>,
    pub evidence: ObservationEvidence,
    pub observation_digest: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityPolicyV1 {
    pub schema: String,
    pub policy_id: String,
    pub abundant_min_remaining: f64,
    pub normal_min_remaining: f64,
    pub conserve_min_remaining: f64,
    pub minimum_confidence: Confidence,
    pub required_window_types: Vec<WindowType>,
    pub unknown_allows_new_cheap_work: bool,
    pub policy_digest: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapacityState {
    Abundant,
    Normal,
    Conserve,
    Critical,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdmissionDisposition {
    OrdinaryBounded,
    CheapBoundedOnly,
    NoNewWork,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityDecisionV1 {
    pub schema: String,
    pub provider_id: String,
    pub decision_at: DateTime<Utc>,
    pub state: CapacityState,
    pub admission: AdmissionDisposition,
    pub allow_new_expensive_work: bool,
    pub allow_new_speculative_work: bool,
    pub allow_active_work_to_reach_custody: bool,
    pub reason_codes: Vec<String>,
    pub observation_digest: String,
    pub policy_digest: String,
    pub decision_digest: String,
}

impl Default for CapacityPolicyV1 {
    fn default() -> Self {
        let mut policy = Self {
            schema: CAPACITY_POLICY_SCHEMA_V1.to_string(),
            policy_id: "nightshift-default-provider-reserve-v1".to_string(),
            abundant_min_remaining: 0.50,
            normal_min_remaining: 0.25,
            conserve_min_remaining: 0.10,
            minimum_confidence: Confidence::Medium,
            required_window_types: vec![WindowType::FiveHour, WindowType::Weekly],
            unknown_allows_new_cheap_work: false,
            policy_digest: String::new(),
        };
        policy.policy_digest = policy.compute_digest().expect("static policy serializes");
        policy
    }
}

impl CapacityObservationV1 {
    pub fn validate(&self) -> Result<(), CapacityError> {
        if self.schema != CAPACITY_OBSERVATION_SCHEMA_V1 {
            return Err(invalid("unknown observation schema"));
        }
        nonempty("provider_id", &self.provider_id)?;
        nonempty("account_profile_locator", &self.account_profile_locator)?;
        if self.expires_at <= self.observed_at {
            return Err(invalid("expires_at must follow observed_at"));
        }
        match self.disposition {
            ObservationDisposition::Usable
                if self.windows.is_empty() || !self.unknown_reasons.is_empty() =>
            {
                return Err(invalid(
                    "usable observation needs windows and no unknown reasons",
                ));
            }
            ObservationDisposition::Unknown if self.unknown_reasons.is_empty() => {
                return Err(invalid("unknown observation needs a reason"));
            }
            _ => {}
        }
        nonempty("probe_id", &self.evidence.probe_id)?;
        nonempty("protocol_method", &self.evidence.protocol_method)?;
        if !is_sha256_digest(&self.evidence.raw_source_digest) {
            return Err(invalid("raw source digest must be an exact SHA-256 digest"));
        }
        match self.disposition {
            ObservationDisposition::Usable
                if self.evidence.protocol_version.is_none()
                    || self.evidence.executable_path.is_none()
                    || self.evidence.executable_digest.is_none() =>
            {
                return Err(invalid(
                    "usable observation requires verified executable and protocol identity",
                ));
            }
            _ => {}
        }
        if let Some(version) = &self.evidence.protocol_version {
            nonempty("protocol_version", version)?;
        }
        if let Some(path) = &self.evidence.executable_path {
            if !std::path::Path::new(path).is_absolute() {
                return Err(invalid("executable_path must be absolute"));
            }
        }
        if let Some(digest) = &self.evidence.executable_digest {
            if !is_sha256_digest(digest) {
                return Err(invalid("executable_digest must be an exact SHA-256 digest"));
            }
        }
        for window in &self.windows {
            nonempty("window_id", &window.window_id)?;
            if let Some(value) = window.remaining_fraction {
                if !value.is_finite() || !(0.0..=1.0).contains(&value) {
                    return Err(invalid(
                        "remaining_fraction must be finite and within zero and one",
                    ));
                }
            }
            if let Some(units) = &window.remaining_units {
                if units.maximum == 0 || units.remaining > units.maximum {
                    return Err(invalid("remaining units exceed a nonzero maximum"));
                }
                nonempty("unit", &units.unit)?;
            }
            if window.remaining_fraction.is_none() && window.remaining_units.is_none() {
                return Err(invalid("window has no bounded remaining measure"));
            }
        }
        check_digest(
            &self.observation_digest,
            &self.compute_digest()?,
            "observation",
        )
    }

    pub fn compute_digest(&self) -> Result<String, CapacityError> {
        digest_record(self, "observation_digest", OBSERVATION_DOMAIN)
    }
}

impl CapacityPolicyV1 {
    pub fn validate(&self) -> Result<(), CapacityError> {
        if self.schema != CAPACITY_POLICY_SCHEMA_V1 {
            return Err(invalid("unknown policy schema"));
        }
        nonempty("policy_id", &self.policy_id)?;
        let values = [
            self.abundant_min_remaining,
            self.normal_min_remaining,
            self.conserve_min_remaining,
        ];
        if values.iter().any(|value| !value.is_finite())
            || !(0.0..=1.0).contains(&self.abundant_min_remaining)
            || !(0.0..=1.0).contains(&self.conserve_min_remaining)
            || self.abundant_min_remaining <= self.normal_min_remaining
            || self.normal_min_remaining <= self.conserve_min_remaining
        {
            return Err(invalid(
                "policy thresholds must descend within zero and one",
            ));
        }
        if self.required_window_types.is_empty() {
            return Err(invalid(
                "policy must declare at least one required window type",
            ));
        }
        if self
            .required_window_types
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(invalid(
                "required window types must be unique and in canonical order",
            ));
        }
        check_digest(&self.policy_digest, &self.compute_digest()?, "policy")
    }

    pub fn compute_digest(&self) -> Result<String, CapacityError> {
        digest_record(self, "policy_digest", POLICY_DOMAIN)
    }
}

impl CapacityDecisionV1 {
    pub fn validate(&self) -> Result<(), CapacityError> {
        if self.schema != CAPACITY_DECISION_SCHEMA_V1 {
            return Err(invalid("unknown decision schema"));
        }
        nonempty("provider_id", &self.provider_id)?;
        if self.reason_codes.is_empty()
            || self
                .reason_codes
                .iter()
                .any(|reason| !is_reason_token(reason))
        {
            return Err(invalid(
                "decision reason codes must be nonempty closed tokens",
            ));
        }
        let mut unique_reasons = self.reason_codes.clone();
        unique_reasons.sort();
        unique_reasons.dedup();
        if unique_reasons.len() != self.reason_codes.len() {
            return Err(invalid("decision reason codes must be unique"));
        }
        if !is_sha256_digest(&self.observation_digest) || !is_sha256_digest(&self.policy_digest) {
            return Err(invalid(
                "decision must bind exact SHA-256 observation and policy digests",
            ));
        }
        if !self.allow_active_work_to_reach_custody {
            return Err(invalid("active work must remain able to reach custody"));
        }
        let fields_match_state = match self.state {
            CapacityState::Abundant => {
                self.admission == AdmissionDisposition::OrdinaryBounded
                    && self.allow_new_expensive_work
                    && self.allow_new_speculative_work
            }
            CapacityState::Normal => {
                self.admission == AdmissionDisposition::OrdinaryBounded
                    && self.allow_new_expensive_work
                    && !self.allow_new_speculative_work
            }
            CapacityState::Conserve => {
                self.admission == AdmissionDisposition::CheapBoundedOnly
                    && !self.allow_new_expensive_work
                    && !self.allow_new_speculative_work
            }
            CapacityState::Critical => {
                self.admission == AdmissionDisposition::NoNewWork
                    && !self.allow_new_expensive_work
                    && !self.allow_new_speculative_work
            }
            CapacityState::Unknown => {
                matches!(
                    self.admission,
                    AdmissionDisposition::CheapBoundedOnly | AdmissionDisposition::NoNewWork
                ) && !self.allow_new_expensive_work
                    && !self.allow_new_speculative_work
            }
        };
        if !fields_match_state {
            return Err(invalid(
                "decision admission fields contradict capacity state",
            ));
        }
        check_digest(&self.decision_digest, &self.compute_digest()?, "decision")
    }

    pub fn compute_digest(&self) -> Result<String, CapacityError> {
        digest_record(self, "decision_digest", DECISION_DOMAIN)
    }
}

pub fn decide_capacity(
    observation: &CapacityObservationV1,
    policy: &CapacityPolicyV1,
    decision_at: DateTime<Utc>,
) -> Result<CapacityDecisionV1, CapacityError> {
    observation.validate()?;
    policy.validate()?;

    let mut reasons = Vec::new();
    let missing_window_reasons: Vec<String> = policy
        .required_window_types
        .iter()
        .filter(|required| {
            !observation
                .windows
                .iter()
                .any(|window| window.window_type == **required)
        })
        .map(|window_type| {
            format!(
                "REQUIRED_WINDOW_MISSING_{}",
                window_type_token(*window_type)
            )
        })
        .collect();
    let state = if observation.disposition == ObservationDisposition::Unknown {
        reasons.extend(observation.unknown_reasons.iter().cloned());
        reasons.extend(missing_window_reasons.clone());
        CapacityState::Unknown
    } else if decision_at < observation.observed_at {
        reasons.push("DECISION_PRECEDES_OBSERVATION".into());
        CapacityState::Unknown
    } else if decision_at >= observation.expires_at {
        reasons.push("OBSERVATION_STALE".into());
        CapacityState::Unknown
    } else if observation
        .windows
        .iter()
        .any(|window| window.resets_at.is_some_and(|reset| decision_at >= reset))
    {
        reasons.push("RESET_ROLLOVER_REQUIRES_NEW_OBSERVATION".into());
        CapacityState::Unknown
    } else if observation.source_class == SourceClass::Unknown
        || observation.confidence < policy.minimum_confidence
    {
        reasons.push("SOURCE_OR_CONFIDENCE_INSUFFICIENT".into());
        CapacityState::Unknown
    } else if !missing_window_reasons.is_empty() {
        reasons.extend(missing_window_reasons);
        CapacityState::Unknown
    } else {
        match observation
            .windows
            .iter()
            .filter_map(|window| window.remaining_fraction)
            .reduce(f64::min)
        {
            None => {
                reasons.push("NO_FRACTIONAL_CAPACITY_MEASURE".into());
                CapacityState::Unknown
            }
            Some(v) if v >= policy.abundant_min_remaining => CapacityState::Abundant,
            Some(v) if v >= policy.normal_min_remaining => CapacityState::Normal,
            Some(v) if v >= policy.conserve_min_remaining => CapacityState::Conserve,
            Some(_) => CapacityState::Critical,
        }
    };
    if reasons.is_empty() {
        reasons.push(format!("MINIMUM_REMAINING_WINDOW_{state:?}").to_uppercase());
    }

    let (admission, expensive, speculative) = match state {
        CapacityState::Abundant => (AdmissionDisposition::OrdinaryBounded, true, true),
        CapacityState::Normal => (AdmissionDisposition::OrdinaryBounded, true, false),
        CapacityState::Conserve => (AdmissionDisposition::CheapBoundedOnly, false, false),
        CapacityState::Critical => (AdmissionDisposition::NoNewWork, false, false),
        CapacityState::Unknown if policy.unknown_allows_new_cheap_work => {
            (AdmissionDisposition::CheapBoundedOnly, false, false)
        }
        CapacityState::Unknown => (AdmissionDisposition::NoNewWork, false, false),
    };

    let mut decision = CapacityDecisionV1 {
        schema: CAPACITY_DECISION_SCHEMA_V1.to_string(),
        provider_id: observation.provider_id.clone(),
        decision_at,
        state,
        admission,
        allow_new_expensive_work: expensive,
        allow_new_speculative_work: speculative,
        allow_active_work_to_reach_custody: true,
        reason_codes: reasons,
        observation_digest: observation.observation_digest.clone(),
        policy_digest: policy.policy_digest.clone(),
        decision_digest: String::new(),
    };
    decision.decision_digest = decision.compute_digest()?;
    Ok(decision)
}

fn digest_record<T: Serialize>(
    record: &T,
    field: &str,
    domain: &[u8],
) -> Result<String, CapacityError> {
    let mut value = serde_json::to_value(record)?;
    value
        .as_object_mut()
        .ok_or_else(|| invalid("digest subject must be an object"))?
        .remove(field);
    let canonical = serde_jcs::to_vec(&value)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn check_digest(actual: &str, expected: &str, kind: &str) -> Result<(), CapacityError> {
    if actual == expected {
        Ok(())
    } else {
        Err(invalid(format!(
            "{kind} digest mismatch: expected {expected}"
        )))
    }
}

fn nonempty(field: &str, value: &str) -> Result<(), CapacityError> {
    if value.trim().is_empty() {
        Err(invalid(format!("{field} must not be empty")))
    } else {
        Ok(())
    }
}

fn window_type_token(window_type: WindowType) -> &'static str {
    match window_type {
        WindowType::FiveHour => "FIVE_HOUR",
        WindowType::Weekly => "WEEKLY",
        WindowType::ProviderDefined => "PROVIDER_DEFINED",
    }
}

fn is_reason_token(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z'))
        && bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn invalid(message: impl Into<String>) -> CapacityError {
    CapacityError::Invalid(message.into())
}

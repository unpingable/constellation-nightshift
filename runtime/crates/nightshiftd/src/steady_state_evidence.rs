//! Decision-relative composition of historical local-Compose qualification
//! and a fresh, read-only steady-state observation.
//!
//! The existing `post_settlement_successor` profile remains the sole strong
//! qualification path.  This module never renews that evidence.  It records
//! whether the exact qualified artifact is still the artifact observed by a
//! separately authenticated passive adapter, then applies a temporal horizon
//! only to that passive source.

use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::external_evidence_composition::{ExternalEvidenceProfileV1, ExternalEvidencePurposeV1};
use crate::external_observation::{
    authentication_preimage, constant_time_eq, hash_domain, hmac_text, read_protected_key,
    require_digest, require_token, semantic_id, ExecutorOutcomeV1,
    ExternalObservationCustodyProvenanceV1, HmacAuthenticationV1, LocalComposeActionV1,
    LocalComposeClaimKindV1, LocalComposeWorldObservationV1, WorldClaimStatusV1,
    HMAC_AUTH_SCHEMA_V1,
};

pub const STEADY_STATE_EVIDENCE_SCHEMA_V1: &str = "maude.local-compose-steady-state-evidence/v1";
pub const STEADY_STATE_OBSERVATION_SCHEMA_V1: &str =
    "maude.local-compose-steady-state-observation/v1";
pub const STEADY_STATE_CLAIM_SCHEMA_V1: &str = "maude.local-compose-steady-state-claim/v1";
pub const STEADY_STATE_HANDOFF_SCHEMA_V1: &str = "nightshift.steady_state_observation_handoff.v1";
pub const STEADY_STATE_CUSTODY_SCHEMA_V1: &str = "nightshift.steady_state_observation_custody.v1";
pub const STEADY_STATE_PROFILE_SCHEMA_V1: &str = "nightshift.steady_state_evidence_profile.v1";
pub const DECISION_EVIDENCE_REFERENCE_SCHEMA_V1: &str =
    "nightshift.decision_relative_evidence_reference.v1";
pub const ARTIFACT_QUALIFICATION_SCHEMA_V1: &str = "nightshift.artifact_qualification_evidence.v1";
pub const COMPOSED_DECISION_EVIDENCE_SCHEMA_V1: &str =
    "nightshift.composed_decision_relative_evidence.v1";
pub const REOBSERVATION_BASIS_SCHEMA_V1: &str = "nightshift.steady_state_reobservation_basis.v1";

pub const STEADY_STATE_ADAPTER_ID_V1: &str = "maude.local-compose-steady-state-observation-adapter";
pub const STEADY_STATE_ADAPTER_VERSION_V1: &str = "1";

const STEADY_EVIDENCE_DOMAIN_V1: &str = "maude.local-compose-steady-state-evidence/v1";
const STEADY_HANDOFF_AUTH_DOMAIN_V1: &[u8] = b"nightshift-steady-state-observation-handoff/v1\0";
const COMPOSED_OBSERVATION_DOMAIN_V1: &[u8] =
    b"nightshift.decision-relative-observation-identity.v1\0";
const MAX_EVIDENCE_BYTES: u64 = 2 * 1024 * 1024;

const STEADY_NONCLAIMS: [&str; 4] = [
    "passive observation is not effectful qualification",
    "passive observation does not prove failure survival",
    "producer authentication is not currentness or authorization",
    "observation failure does not authorize remediation",
];

const COMPOSITION_NONCLAIMS: [&str; 4] = [
    "historical qualification is not present-world currentness",
    "steady-state evidence does not renew qualification",
    "artifact applicability is exact identity, not semantic equivalence",
    "decision adequacy does not confer standing or authorization",
];

fn object_id<T: Serialize>(value: &T, identity_field: &str) -> Result<String, String> {
    let mut value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    value
        .as_object_mut()
        .ok_or_else(|| "identity preimage must be an object".to_owned())?
        .remove(identity_field);
    let bytes = serde_jcs::to_vec(&value).map_err(|error| error.to_string())?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn unix_ms(value: DateTime<Utc>) -> Result<u64, String> {
    u64::try_from(value.timestamp_millis()).map_err(|_| "time precedes the Unix epoch".to_owned())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SteadyStateClaimKindV1 {
    FrontDoorReachable,
    CacheAPresent,
    CacheBPresent,
    OrdinaryCacheBehaviorObserved,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SteadyStateClaimV1 {
    pub schema: String,
    pub claim_id: String,
    pub kind: SteadyStateClaimKindV1,
    pub status: WorldClaimStatusV1,
    pub plan_node_id: String,
    pub compiled_output_identity: String,
    pub evidence_paths: Vec<String>,
}

impl SteadyStateClaimV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != STEADY_STATE_CLAIM_SCHEMA_V1 {
            return Err("unsupported steady-state claim schema".into());
        }
        require_digest("claim_id", &self.claim_id)?;
        require_token("plan_node_id", &self.plan_node_id)?;
        require_digest("compiled_output_identity", &self.compiled_output_identity)?;
        if self.evidence_paths.is_empty()
            || self.evidence_paths.iter().any(|path| {
                !path.starts_with("/observations/") || path.chars().any(char::is_whitespace)
            })
        {
            return Err("steady-state evidence paths must be exact /observations pointers".into());
        }
        if self.claim_id != object_id(self, "claim_id")? {
            return Err("steady-state claim identity mismatch".into());
        }
        Ok(())
    }
}

/// Authenticated passive observation bound to the exact artifact previously
/// qualified by `qualification_observation_id`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalComposeSteadyStateObservationV1 {
    pub schema: String,
    pub observation_id: String,
    pub adapter_id: String,
    pub adapter_version: String,
    pub qualification_observation_id: String,
    pub plan_document_digest: String,
    pub compilation_id: String,
    pub campaign_id: String,
    pub occurrence_id: String,
    pub proposal_id: String,
    pub exact_work_id: String,
    pub issuance_id: String,
    pub attempt_id: String,
    pub settlement_id: String,
    pub subject_digest: String,
    pub scope_digest: String,
    pub evidence_receipt: String,
    pub evidence_bytes: u64,
    pub observed_at_unix_ms: i64,
    pub source_evidence: Value,
    pub claims: Vec<SteadyStateClaimV1>,
    pub nonclaims: Vec<String>,
}

impl LocalComposeSteadyStateObservationV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != STEADY_STATE_OBSERVATION_SCHEMA_V1
            || self.adapter_id != STEADY_STATE_ADAPTER_ID_V1
            || self.adapter_version != STEADY_STATE_ADAPTER_VERSION_V1
        {
            return Err("unsupported local-Compose steady-state observation".into());
        }
        for (name, value) in [
            ("observation_id", &self.observation_id),
            (
                "qualification_observation_id",
                &self.qualification_observation_id,
            ),
            ("plan_document_digest", &self.plan_document_digest),
            ("compilation_id", &self.compilation_id),
            ("campaign_id", &self.campaign_id),
            ("proposal_id", &self.proposal_id),
            ("exact_work_id", &self.exact_work_id),
            ("issuance_id", &self.issuance_id),
            ("attempt_id", &self.attempt_id),
            ("settlement_id", &self.settlement_id),
            ("subject_digest", &self.subject_digest),
            ("scope_digest", &self.scope_digest),
            ("evidence_receipt", &self.evidence_receipt),
        ] {
            require_digest(name, value)?;
        }
        require_token("occurrence_id", &self.occurrence_id)?;
        if self.observed_at_unix_ms < 0
            || self.evidence_bytes == 0
            || self.evidence_bytes > MAX_EVIDENCE_BYTES
            || self.nonclaims != STEADY_NONCLAIMS.map(str::to_owned)
        {
            return Err("steady-state observation bound, time, or nonclaims failed".into());
        }
        let source = self
            .source_evidence
            .as_object()
            .ok_or_else(|| "steady-state source evidence is not an object".to_owned())?;
        let expected_fields = [
            "schema",
            "qualification_observation_id",
            "observed_at_unix_ms",
            "observations",
        ];
        if source.len() != expected_fields.len()
            || expected_fields
                .iter()
                .any(|field| !source.contains_key(*field))
            || source.get("schema").and_then(Value::as_str) != Some(STEADY_STATE_EVIDENCE_SCHEMA_V1)
            || source
                .get("qualification_observation_id")
                .and_then(Value::as_str)
                != Some(self.qualification_observation_id.as_str())
            || source.get("observed_at_unix_ms").and_then(Value::as_i64)
                != Some(self.observed_at_unix_ms)
        {
            return Err("steady-state source evidence binding is invalid".into());
        }
        let observations = source
            .get("observations")
            .and_then(Value::as_object)
            .ok_or_else(|| "steady-state observations are not an object".to_owned())?;
        let expected_observations = ["front_door", "cache_a", "cache_b", "cache_behavior"];
        if observations.len() != expected_observations.len()
            || expected_observations
                .iter()
                .any(|field| !observations.contains_key(*field))
            || observations
                .get("front_door")
                .and_then(|value| value.get("status"))
                .and_then(Value::as_u64)
                != Some(200)
        {
            return Err("steady-state front-door evidence is not satisfied".into());
        }
        for (field, identity) in [("cache_a", "cache-a"), ("cache_b", "cache-b")] {
            let cache = observations
                .get(field)
                .and_then(Value::as_object)
                .ok_or_else(|| "steady-state cache evidence is not an object".to_owned())?;
            if cache.get("identity").and_then(Value::as_str) != Some(identity)
                || cache.get("state").and_then(Value::as_str) != Some("running")
            {
                return Err("steady-state cache identity is not present".into());
            }
        }
        let requests = observations
            .get("cache_behavior")
            .and_then(|value| value.get("requests"))
            .and_then(Value::as_array)
            .ok_or_else(|| "ordinary cache behavior is not an array".to_owned())?;
        let actual = requests
            .iter()
            .map(|request| {
                Ok((
                    request
                        .get("cache")
                        .and_then(Value::as_str)
                        .ok_or_else(|| "cache result is absent".to_owned())?,
                    request
                        .get("cache_node")
                        .and_then(Value::as_str)
                        .ok_or_else(|| "cache node is absent".to_owned())?,
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let starts_a = [
            ("MISS", "cache-a"),
            ("MISS", "cache-b"),
            ("HIT", "cache-a"),
            ("HIT", "cache-b"),
        ];
        let starts_b = [
            ("MISS", "cache-b"),
            ("MISS", "cache-a"),
            ("HIT", "cache-b"),
            ("HIT", "cache-a"),
        ];
        if actual != starts_a && actual != starts_b {
            return Err("ordinary cache behavior contradicted the closed profile".into());
        }
        let bytes = serde_jcs::to_vec(&self.source_evidence).map_err(|error| error.to_string())?;
        if u64::try_from(bytes.len()).map_err(|_| "steady-state evidence too large")?
            != self.evidence_bytes
            || hash_domain(STEADY_EVIDENCE_DOMAIN_V1, &bytes) != self.evidence_receipt
        {
            return Err("steady-state evidence receipt or length mismatch".into());
        }
        let expected = [
            (
                SteadyStateClaimKindV1::FrontDoorReachable,
                "pn_health",
                "/observations/front_door",
            ),
            (
                SteadyStateClaimKindV1::CacheAPresent,
                "pn_cache_a",
                "/observations/cache_a",
            ),
            (
                SteadyStateClaimKindV1::CacheBPresent,
                "pn_cache_b",
                "/observations/cache_b",
            ),
            (
                SteadyStateClaimKindV1::OrdinaryCacheBehaviorObserved,
                "pn_cache_behavior",
                "/observations/cache_behavior",
            ),
        ];
        if self.claims.len() != expected.len() {
            return Err("steady-state claim set is incomplete".into());
        }
        for (claim, (kind, node, path)) in self.claims.iter().zip(expected) {
            claim.validate()?;
            if claim.kind != kind
                || claim.plan_node_id != node
                || claim.evidence_paths != [path]
                || self.source_evidence.pointer(path).is_none()
            {
                return Err("steady-state claim projection mismatch".into());
            }
        }
        if self.observation_id != object_id(self, "observation_id")? {
            return Err("steady-state observation identity mismatch".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SteadyStateObservationHandoffV1 {
    pub schema: String,
    pub handoff_id: String,
    pub producer_principal_id: String,
    pub producer_key_id: String,
    pub target_runtime_id: String,
    pub observation: LocalComposeSteadyStateObservationV1,
    pub created_at: DateTime<Utc>,
    pub authentication: HmacAuthenticationV1,
}

impl SteadyStateObservationHandoffV1 {
    pub fn validate_untrusted(&self) -> Result<(), String> {
        if self.schema != STEADY_STATE_HANDOFF_SCHEMA_V1
            || self.authentication.schema != HMAC_AUTH_SCHEMA_V1
            || self.authentication.key_id != self.producer_key_id
            || !self.authentication.tag.starts_with("hmac-sha256:")
        {
            return Err("unsupported or malformed steady-state handoff".into());
        }
        require_digest("handoff_id", &self.handoff_id)?;
        require_token("producer_principal_id", &self.producer_principal_id)?;
        require_token("producer_key_id", &self.producer_key_id)?;
        require_token("target_runtime_id", &self.target_runtime_id)?;
        self.observation.validate()?;
        if self.handoff_id != semantic_id(self, "handoff_id")? {
            return Err("steady-state handoff identity mismatch".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedSteadyStateObservationHandoffV1 {
    handoff: SteadyStateObservationHandoffV1,
}

impl VerifiedSteadyStateObservationHandoffV1 {
    pub(crate) fn handoff(&self) -> &SteadyStateObservationHandoffV1 {
        &self.handoff
    }
}

pub struct SteadyStateObservationVerifierV1 {
    expected_principal_id: String,
    expected_key_id: String,
    expected_runtime_id: String,
    producer_key: [u8; 32],
}

impl SteadyStateObservationVerifierV1 {
    pub fn from_key_file(
        expected_principal_id: String,
        expected_key_id: String,
        expected_runtime_id: String,
        key_path: &Path,
    ) -> Result<Self, String> {
        Ok(Self {
            expected_principal_id,
            expected_key_id,
            expected_runtime_id,
            producer_key: read_protected_key(key_path)?,
        })
    }

    pub fn verify(
        &self,
        handoff: &SteadyStateObservationHandoffV1,
    ) -> Result<VerifiedSteadyStateObservationHandoffV1, String> {
        handoff.validate_untrusted()?;
        if handoff.producer_principal_id != self.expected_principal_id
            || handoff.producer_key_id != self.expected_key_id
            || handoff.target_runtime_id != self.expected_runtime_id
        {
            return Err("steady-state producer or runtime identity mismatch".into());
        }
        let expected = hmac_text(
            &self.producer_key,
            STEADY_HANDOFF_AUTH_DOMAIN_V1,
            &authentication_preimage(handoff)?,
        );
        if !constant_time_eq(expected.as_bytes(), handoff.authentication.tag.as_bytes()) {
            return Err("steady-state observation authentication failed".into());
        }
        Ok(VerifiedSteadyStateObservationHandoffV1 {
            handoff: handoff.clone(),
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        expected_principal_id: &str,
        expected_key_id: &str,
        expected_runtime_id: &str,
        producer_key: [u8; 32],
    ) -> Self {
        Self {
            expected_principal_id: expected_principal_id.into(),
            expected_key_id: expected_key_id.into(),
            expected_runtime_id: expected_runtime_id.into(),
            producer_key,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SteadyStateObservationCustodyV1 {
    pub schema: String,
    pub custody_id: String,
    pub handoff_id: String,
    pub observation_id: String,
    pub qualification_observation_id: String,
    pub producer_principal_id: String,
    pub producer_key_id: String,
    pub target_runtime_id: String,
    pub plan_document_digest: String,
    pub compilation_id: String,
    pub evidence_receipt: String,
    pub received_at: DateTime<Utc>,
}

impl SteadyStateObservationCustodyV1 {
    pub(crate) fn mint(
        verified: &VerifiedSteadyStateObservationHandoffV1,
        received_at: DateTime<Utc>,
    ) -> Result<Self, String> {
        let handoff = verified.handoff();
        let source = &handoff.observation;
        let mut value = Self {
            schema: STEADY_STATE_CUSTODY_SCHEMA_V1.into(),
            custody_id: String::new(),
            handoff_id: handoff.handoff_id.clone(),
            observation_id: source.observation_id.clone(),
            qualification_observation_id: source.qualification_observation_id.clone(),
            producer_principal_id: handoff.producer_principal_id.clone(),
            producer_key_id: handoff.producer_key_id.clone(),
            target_runtime_id: handoff.target_runtime_id.clone(),
            plan_document_digest: source.plan_document_digest.clone(),
            compilation_id: source.compilation_id.clone(),
            evidence_receipt: source.evidence_receipt.clone(),
            received_at,
        };
        value.custody_id = object_id(&value, "custody_id")?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != STEADY_STATE_CUSTODY_SCHEMA_V1 {
            return Err("unsupported steady-state custody schema".into());
        }
        for (name, value) in [
            ("custody_id", &self.custody_id),
            ("handoff_id", &self.handoff_id),
            ("observation_id", &self.observation_id),
            (
                "qualification_observation_id",
                &self.qualification_observation_id,
            ),
            ("plan_document_digest", &self.plan_document_digest),
            ("compilation_id", &self.compilation_id),
            ("evidence_receipt", &self.evidence_receipt),
        ] {
            require_digest(name, value)?;
        }
        for (name, value) in [
            ("producer_principal_id", &self.producer_principal_id),
            ("producer_key_id", &self.producer_key_id),
            ("target_runtime_id", &self.target_runtime_id),
        ] {
            require_token(name, value)?;
        }
        if self.custody_id != object_id(self, "custody_id")? {
            return Err("steady-state custody identity mismatch".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SteadyStateEvidencePurposeV1 {
    RoutineContinuation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SteadyStateEvidenceProfileV1 {
    pub schema: String,
    pub profile_id: String,
    pub purpose: SteadyStateEvidencePurposeV1,
    /// The exact deployment-owned strong profile used to admit historical
    /// qualification. Its temporal horizon is deliberately not reused for
    /// qualification applicability.
    pub qualification_profile: ExternalEvidenceProfileV1,
    pub expected_adapter_id: String,
    pub expected_adapter_version: String,
    pub expected_producer_principal_id: String,
    pub expected_producer_key_id: String,
    pub expected_runtime_id: String,
    pub required_qualification_claims: Vec<LocalComposeClaimKindV1>,
    pub required_steady_state_claims: Vec<SteadyStateClaimKindV1>,
    pub max_age_ms: u64,
}

impl SteadyStateEvidenceProfileV1 {
    pub fn seal(mut self) -> Result<Self, String> {
        self.schema = STEADY_STATE_PROFILE_SCHEMA_V1.into();
        self.profile_id.clear();
        self.profile_id = object_id(&self, "profile_id")?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), String> {
        let qualification_claims = [
            LocalComposeClaimKindV1::FrontDoorReachable,
            LocalComposeClaimKindV1::CacheMissThenHit,
            LocalComposeClaimKindV1::SingleCacheFailureSurvived,
            LocalComposeClaimKindV1::CacheTopologyRestored,
        ];
        let steady_claims = [
            SteadyStateClaimKindV1::FrontDoorReachable,
            SteadyStateClaimKindV1::CacheAPresent,
            SteadyStateClaimKindV1::CacheBPresent,
            SteadyStateClaimKindV1::OrdinaryCacheBehaviorObserved,
        ];
        if self.schema != STEADY_STATE_PROFILE_SCHEMA_V1
            || self.purpose != SteadyStateEvidencePurposeV1::RoutineContinuation
            || self.expected_adapter_id != STEADY_STATE_ADAPTER_ID_V1
            || self.expected_adapter_version != STEADY_STATE_ADAPTER_VERSION_V1
            || self.required_qualification_claims != qualification_claims
            || self.required_steady_state_claims != steady_claims
            || self.max_age_ms == 0
        {
            return Err("profile is not the closed local-Compose steady-state profile".into());
        }
        require_digest("profile_id", &self.profile_id)?;
        self.qualification_profile.validate()?;
        if self.qualification_profile.purpose != ExternalEvidencePurposeV1::PostSettlementSuccessor
            || self.qualification_profile.required_claims != self.required_qualification_claims
        {
            return Err(
                "steady-state profile does not bind the closed strong qualification profile".into(),
            );
        }
        for (name, value) in [
            (
                "expected_producer_principal_id",
                &self.expected_producer_principal_id,
            ),
            ("expected_producer_key_id", &self.expected_producer_key_id),
            ("expected_runtime_id", &self.expected_runtime_id),
        ] {
            require_token(name, value)?;
        }
        if self.profile_id != object_id(self, "profile_id")? {
            return Err("steady-state profile identity mismatch".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionRelativeEvidenceReferenceV1 {
    pub schema: String,
    pub qualification_observation_id: String,
    pub qualification_custody_id: String,
    pub steady_state_observation_id: String,
    pub steady_state_custody_id: String,
    pub profile_id: String,
}

impl DecisionRelativeEvidenceReferenceV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != DECISION_EVIDENCE_REFERENCE_SCHEMA_V1 {
            return Err("unsupported decision-relative evidence reference".into());
        }
        for (name, value) in [
            (
                "qualification_observation_id",
                &self.qualification_observation_id,
            ),
            ("qualification_custody_id", &self.qualification_custody_id),
            (
                "steady_state_observation_id",
                &self.steady_state_observation_id,
            ),
            ("steady_state_custody_id", &self.steady_state_custody_id),
            ("profile_id", &self.profile_id),
        ] {
            require_digest(name, value)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactQualificationEvidenceV1 {
    pub schema: String,
    pub qualification_id: String,
    pub source_observation_id: String,
    pub source_custody_id: String,
    pub source_profile_id: String,
    pub plan_document_digest: String,
    pub compilation_id: String,
    pub exact_work_id: String,
    pub campaign_id: String,
    pub occurrence_id: String,
    pub proposal_id: String,
    pub issuance_id: String,
    pub attempt_id: String,
    pub settlement_id: String,
    pub subject_digest: String,
    pub scope_digest: String,
    pub claims: Vec<LocalComposeClaimKindV1>,
    pub acquired_at_unix_ms: u64,
}

impl ArtifactQualificationEvidenceV1 {
    pub(crate) fn from_source(
        profile: &ExternalEvidenceProfileV1,
        value: &LocalComposeWorldObservationV1,
        custody: &ExternalObservationCustodyProvenanceV1,
    ) -> Result<Self, String> {
        profile.validate()?;
        value.validate()?;
        custody.validate()?;
        if profile.purpose != ExternalEvidencePurposeV1::PostSettlementSuccessor
            || value.adapter_id != profile.expected_adapter_id
            || value.adapter_version != profile.expected_adapter_version
            || value.action != LocalComposeActionV1::Qualify
            || value.outcome != ExecutorOutcomeV1::Success
            || value
                .claims
                .iter()
                .map(|claim| claim.kind)
                .collect::<Vec<_>>()
                != profile.required_claims
            || value
                .claims
                .iter()
                .any(|claim| claim.status != WorldClaimStatusV1::Satisfied)
            || custody.observation_id != value.observation_id
            || custody.campaign_id != value.campaign_id
            || custody.occurrence_id != value.occurrence_id
            || custody.exact_work_id != value.exact_work_id
            || custody.attempt_id != value.attempt_id
            || custody.settlement_id != value.settlement_id
            || custody.producer_principal_id != profile.expected_producer_principal_id
            || custody.producer_key_id != profile.expected_producer_key_id
            || custody.target_runtime_id != profile.expected_runtime_id
        {
            return Err("qualification source is not the strong successor profile".into());
        }
        let mut result = Self {
            schema: ARTIFACT_QUALIFICATION_SCHEMA_V1.into(),
            qualification_id: String::new(),
            source_observation_id: value.observation_id.clone(),
            source_custody_id: custody.custody_id.clone(),
            source_profile_id: profile.profile_id.clone(),
            plan_document_digest: value.plan_document_digest.clone(),
            compilation_id: value.compilation_id.clone(),
            exact_work_id: value.exact_work_id.clone(),
            campaign_id: value.campaign_id.clone(),
            occurrence_id: value.occurrence_id.clone(),
            proposal_id: value.proposal_id.clone(),
            issuance_id: value.issuance_id.clone(),
            attempt_id: value.attempt_id.clone(),
            settlement_id: value.settlement_id.clone(),
            subject_digest: value.subject_digest.clone(),
            scope_digest: value.scope_digest.clone(),
            claims: value.claims.iter().map(|claim| claim.kind).collect(),
            acquired_at_unix_ms: u64::try_from(value.observed_at_unix_ms)
                .map_err(|_| "qualification acquisition time is invalid".to_owned())?,
        };
        result.qualification_id = object_id(&result, "qualification_id")?;
        result.validate()?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != ARTIFACT_QUALIFICATION_SCHEMA_V1 {
            return Err("unsupported artifact qualification schema".into());
        }
        for (name, value) in [
            ("qualification_id", &self.qualification_id),
            ("source_observation_id", &self.source_observation_id),
            ("source_custody_id", &self.source_custody_id),
            ("source_profile_id", &self.source_profile_id),
            ("plan_document_digest", &self.plan_document_digest),
            ("compilation_id", &self.compilation_id),
            ("exact_work_id", &self.exact_work_id),
            ("campaign_id", &self.campaign_id),
            ("proposal_id", &self.proposal_id),
            ("issuance_id", &self.issuance_id),
            ("attempt_id", &self.attempt_id),
            ("settlement_id", &self.settlement_id),
            ("subject_digest", &self.subject_digest),
            ("scope_digest", &self.scope_digest),
        ] {
            require_digest(name, value)?;
        }
        require_token("occurrence_id", &self.occurrence_id)?;
        if self.acquired_at_unix_ms == 0
            || self.qualification_id != object_id(self, "qualification_id")?
        {
            return Err("artifact qualification identity or acquisition time failed".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComposedDecisionRelativeEvidenceV1 {
    pub schema: String,
    pub composition_id: String,
    pub profile: SteadyStateEvidenceProfileV1,
    pub qualification: ArtifactQualificationEvidenceV1,
    pub steady_state_observation_id: String,
    pub steady_state_custody_id: String,
    pub steady_state_observed_at_unix_ms: u64,
    pub steady_state_received_at: DateTime<Utc>,
    pub admitted_at: DateTime<Utc>,
    pub fresh_until_unix_ms: u64,
    pub steady_state_claims: Vec<SteadyStateClaimV1>,
    pub target_campaign_id: String,
    pub target_occurrence_id: String,
    pub subject_id: String,
    pub subject_digest: String,
    pub scope_digest: String,
    pub nonclaims: Vec<String>,
}

impl ComposedDecisionRelativeEvidenceV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn compose(
        reference: &DecisionRelativeEvidenceReferenceV1,
        profile: &SteadyStateEvidenceProfileV1,
        qualification_source: &LocalComposeWorldObservationV1,
        qualification_custody: &ExternalObservationCustodyProvenanceV1,
        steady: &LocalComposeSteadyStateObservationV1,
        custody: &SteadyStateObservationCustodyV1,
        admitted_at: DateTime<Utc>,
        target_campaign_id: &str,
        target_occurrence_id: &str,
        subject_id: &str,
        subject_digest: &str,
        scope_digest: &str,
    ) -> Result<Self, String> {
        reference.validate()?;
        profile.validate()?;
        steady.validate()?;
        custody.validate()?;
        let qualification = ArtifactQualificationEvidenceV1::from_source(
            &profile.qualification_profile,
            qualification_source,
            qualification_custody,
        )?;
        if reference.qualification_observation_id != qualification.source_observation_id
            || reference.qualification_custody_id != qualification.source_custody_id
            || reference.steady_state_observation_id != steady.observation_id
            || reference.steady_state_custody_id != custody.custody_id
            || reference.profile_id != profile.profile_id
            || profile.qualification_profile.profile_id != qualification.source_profile_id
            || qualification.claims != profile.required_qualification_claims
            || steady.qualification_observation_id != qualification.source_observation_id
            || steady.plan_document_digest != qualification.plan_document_digest
            || steady.compilation_id != qualification.compilation_id
            || steady.exact_work_id != qualification.exact_work_id
            || steady.subject_digest != qualification.subject_digest
            || steady.scope_digest != qualification.scope_digest
            || custody.observation_id != steady.observation_id
            || custody.qualification_observation_id != steady.qualification_observation_id
            || custody.plan_document_digest != steady.plan_document_digest
            || custody.compilation_id != steady.compilation_id
            || custody.evidence_receipt != steady.evidence_receipt
        {
            return Err("qualification/passive/profile exact applicability failed".into());
        }
        if steady.adapter_id != profile.expected_adapter_id
            || steady.adapter_version != profile.expected_adapter_version
            || custody.producer_principal_id != profile.expected_producer_principal_id
            || custody.producer_key_id != profile.expected_producer_key_id
            || custody.target_runtime_id != profile.expected_runtime_id
            || steady
                .claims
                .iter()
                .map(|claim| claim.kind)
                .collect::<Vec<_>>()
                != profile.required_steady_state_claims
            || steady
                .claims
                .iter()
                .any(|claim| claim.status != WorldClaimStatusV1::Satisfied)
        {
            return Err("passive evidence is inadequate for routine continuation".into());
        }
        if qualification.source_observation_id == steady.observation_id
            || steady.campaign_id != target_campaign_id
            || steady.subject_digest != subject_digest
            || steady.scope_digest != scope_digest
        {
            return Err("decision evidence target or source relation is invalid".into());
        }
        let observed = u64::try_from(steady.observed_at_unix_ms)
            .map_err(|_| "passive observation time is invalid".to_owned())?;
        let admitted = unix_ms(admitted_at)?;
        let fresh_until = observed
            .checked_add(profile.max_age_ms)
            .ok_or_else(|| "steady-state evidence horizon overflow".to_owned())?;
        if admitted < observed || admitted_at < custody.received_at || admitted >= fresh_until {
            return Err("steady-state evidence is not current at admission".into());
        }
        let mut value = Self {
            schema: COMPOSED_DECISION_EVIDENCE_SCHEMA_V1.into(),
            composition_id: String::new(),
            profile: profile.clone(),
            qualification,
            steady_state_observation_id: steady.observation_id.clone(),
            steady_state_custody_id: custody.custody_id.clone(),
            steady_state_observed_at_unix_ms: observed,
            steady_state_received_at: custody.received_at,
            admitted_at,
            fresh_until_unix_ms: fresh_until,
            steady_state_claims: steady.claims.clone(),
            target_campaign_id: target_campaign_id.into(),
            target_occurrence_id: target_occurrence_id.into(),
            subject_id: subject_id.into(),
            subject_digest: subject_digest.into(),
            scope_digest: scope_digest.into(),
            nonclaims: COMPOSITION_NONCLAIMS.map(str::to_owned).to_vec(),
        };
        value.composition_id = object_id(&value, "composition_id")?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != COMPOSED_DECISION_EVIDENCE_SCHEMA_V1 {
            return Err("unsupported decision-relative evidence composition".into());
        }
        self.profile.validate()?;
        self.qualification.validate()?;
        for (name, value) in [
            ("composition_id", &self.composition_id),
            (
                "steady_state_observation_id",
                &self.steady_state_observation_id,
            ),
            ("steady_state_custody_id", &self.steady_state_custody_id),
            ("target_campaign_id", &self.target_campaign_id),
            ("subject_digest", &self.subject_digest),
            ("scope_digest", &self.scope_digest),
        ] {
            require_digest(name, value)?;
        }
        require_token("target_occurrence_id", &self.target_occurrence_id)?;
        require_token("subject_id", &self.subject_id)?;
        if self.profile.qualification_profile.profile_id != self.qualification.source_profile_id
            || self.profile.required_qualification_claims != self.qualification.claims
            || self
                .steady_state_claims
                .iter()
                .map(|claim| claim.kind)
                .collect::<Vec<_>>()
                != self.profile.required_steady_state_claims
            || self
                .steady_state_claims
                .iter()
                .any(|claim| claim.status != WorldClaimStatusV1::Satisfied)
            || self.steady_state_observed_at_unix_ms >= self.fresh_until_unix_ms
            || self.steady_state_observed_at_unix_ms + self.profile.max_age_ms
                != self.fresh_until_unix_ms
            || unix_ms(self.admitted_at)? >= self.fresh_until_unix_ms
            || self.admitted_at < self.steady_state_received_at
            || self.nonclaims != COMPOSITION_NONCLAIMS.map(str::to_owned)
            || self.composition_id != object_id(self, "composition_id")?
        {
            return Err("decision-relative evidence composition validation failed".into());
        }
        for claim in &self.steady_state_claims {
            claim.validate()?;
        }
        Ok(())
    }

    pub fn canonical_observation_id(&self) -> Result<String, String> {
        self.validate()?;
        let bytes = serde_jcs::to_vec(self).map_err(|error| error.to_string())?;
        let mut payload = COMPOSED_OBSERVATION_DOMAIN_V1.to_vec();
        payload.extend(bytes);
        Ok(format!("sha256:{:x}", Sha256::digest(payload)))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReobservationRequirementV1 {
    Absent,
    Stale,
    Current,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SteadyStateReobservationBasisV1 {
    pub schema: String,
    pub basis_id: String,
    pub requirement: ReobservationRequirementV1,
    pub profile_id: String,
    pub qualification_id: String,
    pub qualification_observation_id: String,
    pub source_observation_id: Option<String>,
    pub source_custody_id: Option<String>,
    pub plan_document_digest: String,
    pub compilation_id: String,
    pub exact_work_id: String,
    pub campaign_id: String,
    pub occurrence_id: String,
    pub proposal_id: String,
    pub issuance_id: String,
    pub attempt_id: String,
    pub settlement_id: String,
    pub subject_digest: String,
    pub scope_digest: String,
    pub evaluated_at_unix_ms: u64,
    pub prior_fresh_until_unix_ms: Option<u64>,
}

impl SteadyStateReobservationBasisV1 {
    pub fn create(
        profile: &SteadyStateEvidenceProfileV1,
        qualification: &ArtifactQualificationEvidenceV1,
        prior: Option<(
            &LocalComposeSteadyStateObservationV1,
            &SteadyStateObservationCustodyV1,
        )>,
        evaluated_at_unix_ms: u64,
    ) -> Result<Self, String> {
        profile.validate()?;
        qualification.validate()?;
        if profile.qualification_profile.profile_id != qualification.source_profile_id {
            return Err("re-observation profile does not bind qualification profile".into());
        }
        let (requirement, source_observation_id, source_custody_id, horizon) =
            if let Some((observation, custody)) = prior {
                observation.validate()?;
                custody.validate()?;
                if observation.qualification_observation_id != qualification.source_observation_id
                    || observation.plan_document_digest != qualification.plan_document_digest
                    || observation.compilation_id != qualification.compilation_id
                    || observation.exact_work_id != qualification.exact_work_id
                    || custody.observation_id != observation.observation_id
                {
                    return Err("prior passive observation does not bind qualification".into());
                }
                let observed = u64::try_from(observation.observed_at_unix_ms)
                    .map_err(|_| "prior passive time is invalid".to_owned())?;
                let horizon = observed
                    .checked_add(profile.max_age_ms)
                    .ok_or_else(|| "prior passive horizon overflow".to_owned())?;
                (
                    if evaluated_at_unix_ms >= horizon {
                        ReobservationRequirementV1::Stale
                    } else {
                        ReobservationRequirementV1::Current
                    },
                    Some(observation.observation_id.clone()),
                    Some(custody.custody_id.clone()),
                    Some(horizon),
                )
            } else {
                (ReobservationRequirementV1::Absent, None, None, None)
            };
        let mut value = Self {
            schema: REOBSERVATION_BASIS_SCHEMA_V1.into(),
            basis_id: String::new(),
            requirement,
            profile_id: profile.profile_id.clone(),
            qualification_id: qualification.qualification_id.clone(),
            qualification_observation_id: qualification.source_observation_id.clone(),
            source_observation_id,
            source_custody_id,
            plan_document_digest: qualification.plan_document_digest.clone(),
            compilation_id: qualification.compilation_id.clone(),
            exact_work_id: qualification.exact_work_id.clone(),
            campaign_id: qualification.campaign_id.clone(),
            occurrence_id: qualification.occurrence_id.clone(),
            proposal_id: qualification.proposal_id.clone(),
            issuance_id: qualification.issuance_id.clone(),
            attempt_id: qualification.attempt_id.clone(),
            settlement_id: qualification.settlement_id.clone(),
            subject_digest: qualification.subject_digest.clone(),
            scope_digest: qualification.scope_digest.clone(),
            evaluated_at_unix_ms,
            prior_fresh_until_unix_ms: horizon,
        };
        value.basis_id = object_id(&value, "basis_id")?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != REOBSERVATION_BASIS_SCHEMA_V1 {
            return Err("unsupported steady-state re-observation basis".into());
        }
        for (name, value) in [
            ("basis_id", &self.basis_id),
            ("profile_id", &self.profile_id),
            ("qualification_id", &self.qualification_id),
            (
                "qualification_observation_id",
                &self.qualification_observation_id,
            ),
            ("plan_document_digest", &self.plan_document_digest),
            ("compilation_id", &self.compilation_id),
            ("exact_work_id", &self.exact_work_id),
            ("campaign_id", &self.campaign_id),
            ("proposal_id", &self.proposal_id),
            ("issuance_id", &self.issuance_id),
            ("attempt_id", &self.attempt_id),
            ("settlement_id", &self.settlement_id),
            ("subject_digest", &self.subject_digest),
            ("scope_digest", &self.scope_digest),
        ] {
            require_digest(name, value)?;
        }
        require_token("occurrence_id", &self.occurrence_id)?;
        match self.requirement {
            ReobservationRequirementV1::Absent => {
                if self.source_observation_id.is_some()
                    || self.source_custody_id.is_some()
                    || self.prior_fresh_until_unix_ms.is_some()
                {
                    return Err("absent basis cannot carry prior passive evidence".into());
                }
            }
            ReobservationRequirementV1::Stale | ReobservationRequirementV1::Current => {
                require_digest(
                    "source_observation_id",
                    self.source_observation_id
                        .as_deref()
                        .ok_or_else(|| "basis lacks source observation".to_owned())?,
                )?;
                require_digest(
                    "source_custody_id",
                    self.source_custody_id
                        .as_deref()
                        .ok_or_else(|| "basis lacks source custody".to_owned())?,
                )?;
                let horizon = self
                    .prior_fresh_until_unix_ms
                    .ok_or_else(|| "basis lacks passive evidence horizon".to_owned())?;
                if (self.requirement == ReobservationRequirementV1::Stale
                    && self.evaluated_at_unix_ms < horizon)
                    || (self.requirement == ReobservationRequirementV1::Current
                        && self.evaluated_at_unix_ms >= horizon)
                {
                    return Err("owner-produced passive requirement contradicts horizon".into());
                }
            }
        }
        if self.basis_id != object_id(self, "basis_id")? {
            return Err("steady-state re-observation basis identity mismatch".into());
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::canonical_store::CanonicalStore;
    use crate::external_observation::{
        tests::{reseal_handoff, signed_handoff},
        ExternalObservationVerifierV1,
    };

    fn qualification_profile() -> ExternalEvidenceProfileV1 {
        ExternalEvidenceProfileV1 {
            schema: String::new(),
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
            max_age_ms: 30_000,
        }
        .seal()
        .unwrap()
    }

    fn profile(max_age_ms: u64) -> SteadyStateEvidenceProfileV1 {
        SteadyStateEvidenceProfileV1 {
            schema: String::new(),
            profile_id: String::new(),
            purpose: SteadyStateEvidencePurposeV1::RoutineContinuation,
            qualification_profile: qualification_profile(),
            expected_adapter_id: STEADY_STATE_ADAPTER_ID_V1.into(),
            expected_adapter_version: "1".into(),
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

    fn qualification_source() -> (
        LocalComposeWorldObservationV1,
        ExternalObservationCustodyProvenanceV1,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let key = [7_u8; 32];
        let handoff = signed_handoff(
            &key,
            "1970-01-01T00:00:02Z",
            "00000000-0000-4000-8000-000000000000",
        );
        let verifier = ExternalObservationVerifierV1::for_test(
            "maude-observer:local",
            "maude-observer-key:one",
            "nightshift:local",
            key,
        );
        let verified = verifier.verify(&handoff).unwrap();
        let mut store = CanonicalStore::open(directory.path().join("nightshift.sqlite")).unwrap();
        store
            .record_external_observation(
                &verified,
                DateTime::parse_from_rfc3339("1970-01-01T00:00:02Z")
                    .unwrap()
                    .with_timezone(&Utc),
            )
            .unwrap();
        store
            .external_observation_for_composition(&handoff.observation.observation_id)
            .unwrap()
            .unwrap()
    }

    pub(crate) fn steady_handoff(
        qualification: &LocalComposeWorldObservationV1,
        observed_at_unix_ms: i64,
        key: &[u8; 32],
    ) -> SteadyStateObservationHandoffV1 {
        let source = serde_json::json!({
            "schema": STEADY_STATE_EVIDENCE_SCHEMA_V1,
            "qualification_observation_id": qualification.observation_id,
            "observed_at_unix_ms": observed_at_unix_ms,
            "observations": {
                "front_door": {"status": 200},
                "cache_a": {"identity": "cache-a", "state": "running"},
                "cache_b": {"identity": "cache-b", "state": "running"},
                "cache_behavior": {"requests": [
                    {"cache": "MISS", "cache_node": "cache-a"},
                    {"cache": "MISS", "cache_node": "cache-b"},
                    {"cache": "HIT", "cache_node": "cache-a"},
                    {"cache": "HIT", "cache_node": "cache-b"}
                ]}
            }
        });
        let source_bytes = serde_jcs::to_vec(&source).unwrap();
        let mut claims = Vec::new();
        for (kind, node, path) in [
            (
                SteadyStateClaimKindV1::FrontDoorReachable,
                "pn_health",
                "/observations/front_door",
            ),
            (
                SteadyStateClaimKindV1::CacheAPresent,
                "pn_cache_a",
                "/observations/cache_a",
            ),
            (
                SteadyStateClaimKindV1::CacheBPresent,
                "pn_cache_b",
                "/observations/cache_b",
            ),
            (
                SteadyStateClaimKindV1::OrdinaryCacheBehaviorObserved,
                "pn_cache_behavior",
                "/observations/cache_behavior",
            ),
        ] {
            let mut claim = SteadyStateClaimV1 {
                schema: STEADY_STATE_CLAIM_SCHEMA_V1.into(),
                claim_id: String::new(),
                kind,
                status: WorldClaimStatusV1::Satisfied,
                plan_node_id: node.into(),
                compiled_output_identity: format!("sha256:{:x}", Sha256::digest(node.as_bytes())),
                evidence_paths: vec![path.into()],
            };
            claim.claim_id = object_id(&claim, "claim_id").unwrap();
            claims.push(claim);
        }
        let mut observation = LocalComposeSteadyStateObservationV1 {
            schema: STEADY_STATE_OBSERVATION_SCHEMA_V1.into(),
            observation_id: String::new(),
            adapter_id: STEADY_STATE_ADAPTER_ID_V1.into(),
            adapter_version: STEADY_STATE_ADAPTER_VERSION_V1.into(),
            qualification_observation_id: qualification.observation_id.clone(),
            plan_document_digest: qualification.plan_document_digest.clone(),
            compilation_id: qualification.compilation_id.clone(),
            campaign_id: qualification.campaign_id.clone(),
            occurrence_id: qualification.occurrence_id.clone(),
            proposal_id: qualification.proposal_id.clone(),
            exact_work_id: qualification.exact_work_id.clone(),
            issuance_id: qualification.issuance_id.clone(),
            attempt_id: qualification.attempt_id.clone(),
            settlement_id: qualification.settlement_id.clone(),
            subject_digest: qualification.subject_digest.clone(),
            scope_digest: qualification.scope_digest.clone(),
            evidence_receipt: hash_domain(STEADY_EVIDENCE_DOMAIN_V1, &source_bytes),
            evidence_bytes: u64::try_from(source_bytes.len()).unwrap(),
            observed_at_unix_ms,
            source_evidence: source,
            claims,
            nonclaims: STEADY_NONCLAIMS.map(str::to_owned).to_vec(),
        };
        observation.observation_id = object_id(&observation, "observation_id").unwrap();
        let mut handoff = SteadyStateObservationHandoffV1 {
            schema: STEADY_STATE_HANDOFF_SCHEMA_V1.into(),
            handoff_id: String::new(),
            producer_principal_id: "maude-observer:local".into(),
            producer_key_id: "maude-observer-key:one".into(),
            target_runtime_id: "nightshift:local".into(),
            observation,
            created_at: DateTime::from_timestamp_millis(observed_at_unix_ms + 100).unwrap(),
            authentication: HmacAuthenticationV1 {
                schema: HMAC_AUTH_SCHEMA_V1.into(),
                key_id: "maude-observer-key:one".into(),
                tag: String::new(),
            },
        };
        handoff.handoff_id = semantic_id(&handoff, "handoff_id").unwrap();
        handoff.authentication.tag = hmac_text(
            key,
            STEADY_HANDOFF_AUTH_DOMAIN_V1,
            &authentication_preimage(&handoff).unwrap(),
        );
        handoff
    }

    fn verified_steady(
        qualification: &LocalComposeWorldObservationV1,
        observed_at_unix_ms: i64,
    ) -> (
        LocalComposeSteadyStateObservationV1,
        SteadyStateObservationCustodyV1,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let key = [7_u8; 32];
        let handoff = steady_handoff(qualification, observed_at_unix_ms, &key);
        let verifier = SteadyStateObservationVerifierV1::for_test(
            "maude-observer:local",
            "maude-observer-key:one",
            "nightshift:local",
            key,
        );
        let verified = verifier.verify(&handoff).unwrap();
        let mut store = CanonicalStore::open(directory.path().join("nightshift.sqlite")).unwrap();
        let custody = store
            .record_steady_state_observation(
                &verified,
                DateTime::from_timestamp_millis(observed_at_unix_ms + 200).unwrap(),
            )
            .unwrap();
        (handoff.observation, custody)
    }

    #[test]
    fn profile_keeps_strong_and_passive_claims_distinct() {
        let profile = profile(30_000);
        assert!(profile.validate().is_ok());
        assert!(!profile
            .required_steady_state_claims
            .iter()
            .any(|claim| format!("{claim:?}").contains("Failure")));
    }

    #[test]
    fn historical_qualification_and_fresh_passive_source_compose_independently() {
        let (qualification, qualification_custody) = qualification_source();
        let (steady, steady_custody) = verified_steady(&qualification, 50_000);
        let profile = profile(5_000);
        let reference = DecisionRelativeEvidenceReferenceV1 {
            schema: DECISION_EVIDENCE_REFERENCE_SCHEMA_V1.into(),
            qualification_observation_id: qualification.observation_id.clone(),
            qualification_custody_id: qualification_custody.custody_id.clone(),
            steady_state_observation_id: steady.observation_id.clone(),
            steady_state_custody_id: steady_custody.custody_id.clone(),
            profile_id: profile.profile_id.clone(),
        };
        let composition = ComposedDecisionRelativeEvidenceV1::compose(
            &reference,
            &profile,
            &qualification,
            &qualification_custody,
            &steady,
            &steady_custody,
            DateTime::from_timestamp_millis(51_000).unwrap(),
            &qualification.campaign_id,
            "00000000-0000-4000-8000-000000000001",
            "synthetic-cache",
            &qualification.subject_digest,
            &qualification.scope_digest,
        )
        .unwrap();
        assert_eq!(composition.qualification.acquired_at_unix_ms, 1_000);
        assert_eq!(composition.steady_state_observed_at_unix_ms, 50_000);
        assert_eq!(composition.fresh_until_unix_ms, 55_000);
        assert_eq!(composition.qualification.claims.len(), 4);
        assert_eq!(composition.steady_state_claims.len(), 4);
    }

    #[test]
    fn passive_refresh_cannot_cross_artifact_identity_or_refresh_qualification() {
        let (qualification, qualification_custody) = qualification_source();
        let (mut steady, steady_custody) = verified_steady(&qualification, 50_000);
        let profile = profile(5_000);
        steady.plan_document_digest = format!("sha256:{}", "c".repeat(64));
        steady.observation_id = object_id(&steady, "observation_id").unwrap();
        let reference = DecisionRelativeEvidenceReferenceV1 {
            schema: DECISION_EVIDENCE_REFERENCE_SCHEMA_V1.into(),
            qualification_observation_id: qualification.observation_id.clone(),
            qualification_custody_id: qualification_custody.custody_id.clone(),
            steady_state_observation_id: steady.observation_id.clone(),
            steady_state_custody_id: steady_custody.custody_id.clone(),
            profile_id: profile.profile_id.clone(),
        };
        let error = ComposedDecisionRelativeEvidenceV1::compose(
            &reference,
            &profile,
            &qualification,
            &qualification_custody,
            &steady,
            &steady_custody,
            DateTime::from_timestamp_millis(51_000).unwrap(),
            &qualification.campaign_id,
            "00000000-0000-4000-8000-000000000001",
            "synthetic-cache",
            &qualification.subject_digest,
            &qualification.scope_digest,
        )
        .unwrap_err();
        assert!(error.contains("exact applicability"));
    }

    #[test]
    fn owner_basis_uses_exclusive_passive_horizon_and_never_renews_qualification() {
        let (qualification_source, qualification_custody) = qualification_source();
        let qualification = ArtifactQualificationEvidenceV1::from_source(
            &qualification_profile(),
            &qualification_source,
            &qualification_custody,
        )
        .unwrap();
        let (steady, custody) = verified_steady(&qualification_source, 50_000);
        let profile = profile(5_000);
        let current = SteadyStateReobservationBasisV1::create(
            &profile,
            &qualification,
            Some((&steady, &custody)),
            54_999,
        )
        .unwrap();
        let stale = SteadyStateReobservationBasisV1::create(
            &profile,
            &qualification,
            Some((&steady, &custody)),
            55_000,
        )
        .unwrap();
        assert_eq!(current.requirement, ReobservationRequirementV1::Current);
        assert_eq!(stale.requirement, ReobservationRequirementV1::Stale);
        assert_eq!(current.qualification_id, stale.qualification_id);
        assert_eq!(
            current.qualification_observation_id,
            stale.qualification_observation_id
        );
    }

    #[test]
    fn repeated_qualification_of_one_exact_artifact_is_append_only_evidence() {
        let directory = tempfile::tempdir().unwrap();
        let key = [7_u8; 32];
        let verifier = ExternalObservationVerifierV1::for_test(
            "maude-observer:local",
            "maude-observer-key:one",
            "nightshift:local",
            key,
        );
        let first = signed_handoff(
            &key,
            "1970-01-01T00:00:02Z",
            "00000000-0000-4000-8000-000000000000",
        );
        let mut second = first.clone();
        second.created_at = DateTime::parse_from_rfc3339("1970-01-01T00:00:04Z")
            .unwrap()
            .with_timezone(&Utc);
        second.observation.observed_at_unix_ms = 3_000;
        second.observation.occurrence_id = "00000000-0000-4000-8000-000000000001".into();
        second.observation.proposal_id = format!("sha256:{}", "2".repeat(64));
        second.observation.issuance_id = format!("sha256:{}", "3".repeat(64));
        second.observation.attempt_id = format!("sha256:{}", "4".repeat(64));
        second.observation.settlement_id = format!("sha256:{}", "5".repeat(64));
        second.observation.source_evidence["observed_at_unix_ms"] = serde_json::json!(3_000);
        second.observation.source_evidence["dispatch"]["attempt"] =
            serde_json::json!(second.observation.attempt_id);
        second.observation.source_evidence["docket_outcome"]["attempt"] =
            serde_json::json!(second.observation.attempt_id);
        reseal_handoff(&mut second, &key);

        let mut store = CanonicalStore::open(directory.path().join("nightshift.sqlite")).unwrap();
        let first_verified = verifier.verify(&first).unwrap();
        let first_custody = store
            .record_external_observation(
                &first_verified,
                DateTime::parse_from_rfc3339("1970-01-01T00:00:02Z")
                    .unwrap()
                    .with_timezone(&Utc),
            )
            .unwrap();
        let second_verified = verifier.verify(&second).unwrap();
        let second_custody = store
            .record_external_observation(
                &second_verified,
                DateTime::parse_from_rfc3339("1970-01-01T00:00:04Z")
                    .unwrap()
                    .with_timezone(&Utc),
            )
            .unwrap();
        let profile = qualification_profile();
        let q1 = ArtifactQualificationEvidenceV1::from_source(
            &profile,
            &first.observation,
            &first_custody,
        )
        .unwrap();
        let q2 = ArtifactQualificationEvidenceV1::from_source(
            &profile,
            &second.observation,
            &second_custody,
        )
        .unwrap();

        assert_eq!(q1.plan_document_digest, q2.plan_document_digest);
        assert_eq!(q1.compilation_id, q2.compilation_id);
        assert_eq!(q1.exact_work_id, q2.exact_work_id);
        assert_ne!(q1.qualification_id, q2.qualification_id);
        assert_ne!(q1.source_observation_id, q2.source_observation_id);
        assert_ne!(q1.occurrence_id, q2.occurrence_id);
        assert!(store
            .external_observation_for_composition(&q1.source_observation_id)
            .unwrap()
            .is_some());
        assert!(store
            .external_observation_for_composition(&q2.source_observation_id)
            .unwrap()
            .is_some());
    }

    #[test]
    fn failed_effectful_attempt_remains_evidence_but_cannot_mint_qualification() {
        let directory = tempfile::tempdir().unwrap();
        let key = [7_u8; 32];
        let mut handoff = signed_handoff(
            &key,
            "1970-01-01T00:00:02Z",
            "00000000-0000-4000-8000-000000000000",
        );
        handoff.observation.outcome = ExecutorOutcomeV1::Failure;
        handoff.observation.source_evidence["outcome"] = serde_json::json!("failure");
        handoff.observation.source_evidence["docket_outcome"]["outcome"] =
            serde_json::json!("failure");
        for claim in &mut handoff.observation.claims {
            claim.status = WorldClaimStatusV1::Unknown;
            claim.claim_id = object_id(claim, "claim_id").unwrap();
        }
        reseal_handoff(&mut handoff, &key);
        let verifier = ExternalObservationVerifierV1::for_test(
            "maude-observer:local",
            "maude-observer-key:one",
            "nightshift:local",
            key,
        );
        let verified = verifier.verify(&handoff).unwrap();
        let mut store = CanonicalStore::open(directory.path().join("nightshift.sqlite")).unwrap();
        let custody = store
            .record_external_observation(
                &verified,
                DateTime::parse_from_rfc3339("1970-01-01T00:00:03Z")
                    .unwrap()
                    .with_timezone(&Utc),
            )
            .unwrap();

        let error = ArtifactQualificationEvidenceV1::from_source(
            &qualification_profile(),
            &handoff.observation,
            &custody,
        )
        .unwrap_err();
        assert!(error.contains("not the strong successor profile"));
        assert!(store
            .external_observation_for_composition(&handoff.observation.observation_id)
            .unwrap()
            .is_some());
    }
}

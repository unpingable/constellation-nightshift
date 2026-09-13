//! Nightshift-owned admission of authenticated application/world evidence
//! into one canonical observation.
//!
//! This module is deliberately narrower than a monitoring or claims engine.
//! V1 accepts only the closed local-Compose observation contract already
//! retained by [`crate::external_observation`], under one deployment-owned
//! post-settlement-successor profile. Authentication establishes custody;
//! this module separately establishes decision-relative eligibility and a
//! bounded currentness horizon for the resulting canonical observation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::external_observation::{
    ExecutorOutcomeV1, ExternalObservationCustodyProvenanceV1, LocalComposeActionV1,
    LocalComposeClaimKindV1, LocalComposeWorldObservationV1, WorldClaimStatusV1,
};

pub const EXTERNAL_EVIDENCE_PROFILE_SCHEMA_V1: &str = "nightshift.external_evidence_profile.v1";
pub const EXTERNAL_EVIDENCE_REFERENCE_SCHEMA_V1: &str = "nightshift.external_evidence_reference.v1";
pub const COMPOSED_EXTERNAL_EVIDENCE_SCHEMA_V1: &str = "nightshift.composed_external_evidence.v1";

const COMPOSED_OBSERVATION_DOMAIN_V1: &[u8] = b"nightshift.composed-observation-identity.v1\0";
const REQUIRED_NONCLAIMS: [&str; 4] = [
    "authenticated custody is not observation currentness",
    "Docket settlement is not application health",
    "evidence age is not a currentness decision",
    "composition does not confer standing or authorization",
];

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
        .ok_or_else(|| "identity preimage must be an object".to_owned())?
        .remove(identity_field);
    let bytes = serde_jcs::to_vec(&value).map_err(|error| error.to_string())?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn unix_ms(value: DateTime<Utc>) -> Result<u64, String> {
    u64::try_from(value.timestamp_millis())
        .map_err(|_| "composition time precedes the Unix epoch".to_owned())
}

/// The only v1 decision-relative use of application evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalEvidencePurposeV1 {
    /// Qualify evidence for opening a separately governed successor after an
    /// exact settled predecessor. This is not successor authority.
    PostSettlementSuccessor,
}

/// Deployment-owned evidence-admission/currentness profile.
///
/// The producer never supplies this value. The canonical Nightshift ingress
/// loads it independently and requires the request's profile identity to
/// match. V1 intentionally admits one closed workflow claim set.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalEvidenceProfileV1 {
    pub schema: String,
    pub profile_id: String,
    pub purpose: ExternalEvidencePurposeV1,
    pub expected_adapter_id: String,
    pub expected_adapter_version: String,
    pub expected_producer_principal_id: String,
    pub expected_producer_key_id: String,
    pub expected_runtime_id: String,
    pub required_action: LocalComposeActionV1,
    pub required_claims: Vec<LocalComposeClaimKindV1>,
    /// Exclusive evidence horizon measured from source acquisition time.
    pub max_age_ms: u64,
}

impl ExternalEvidenceProfileV1 {
    pub fn seal(mut self) -> Result<Self, String> {
        self.schema = EXTERNAL_EVIDENCE_PROFILE_SCHEMA_V1.into();
        self.profile_id.clear();
        self.profile_id = object_id(&self, "profile_id")?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != EXTERNAL_EVIDENCE_PROFILE_SCHEMA_V1 {
            return Err("unsupported external-evidence profile schema".into());
        }
        require_digest("profile_id", &self.profile_id)?;
        for (name, value) in [
            ("expected_adapter_id", &self.expected_adapter_id),
            ("expected_adapter_version", &self.expected_adapter_version),
            (
                "expected_producer_principal_id",
                &self.expected_producer_principal_id,
            ),
            ("expected_producer_key_id", &self.expected_producer_key_id),
            ("expected_runtime_id", &self.expected_runtime_id),
        ] {
            require_token(name, value)?;
        }
        let required = [
            LocalComposeClaimKindV1::FrontDoorReachable,
            LocalComposeClaimKindV1::CacheMissThenHit,
            LocalComposeClaimKindV1::SingleCacheFailureSurvived,
            LocalComposeClaimKindV1::CacheTopologyRestored,
        ];
        if self.purpose != ExternalEvidencePurposeV1::PostSettlementSuccessor
            || self.expected_adapter_id != "maude.local-compose-observation-adapter"
            || self.expected_adapter_version != "1"
            || self.required_action != LocalComposeActionV1::Qualify
            || self.required_claims != required
            || self.max_age_ms == 0
        {
            return Err("external-evidence v1 profile is not the closed successor profile".into());
        }
        if self.profile_id != object_id(self, "profile_id")? {
            return Err("external-evidence profile identity mismatch".into());
        }
        Ok(())
    }
}

/// Exact source/profile reference carried by a canonical cycle request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalEvidenceReferenceV1 {
    pub schema: String,
    pub source_observation_id: String,
    pub source_custody_id: String,
    pub profile_id: String,
}

impl ExternalEvidenceReferenceV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != EXTERNAL_EVIDENCE_REFERENCE_SCHEMA_V1 {
            return Err("unsupported external-evidence reference schema".into());
        }
        require_digest("source_observation_id", &self.source_observation_id)?;
        require_digest("source_custody_id", &self.source_custody_id)?;
        require_digest("profile_id", &self.profile_id)
    }
}

/// Small exact claim projection retained on the canonical observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComposedExternalClaimV1 {
    pub claim_id: String,
    pub kind: LocalComposeClaimKindV1,
    pub plan_node_id: String,
    pub compiled_output_identity: String,
}

impl ComposedExternalClaimV1 {
    fn validate(&self) -> Result<(), String> {
        require_digest("claim_id", &self.claim_id)?;
        require_token("plan_node_id", &self.plan_node_id)?;
        require_digest("compiled_output_identity", &self.compiled_output_identity)
    }
}

/// Immutable Nightshift composition receipt embedded in a v3 observation.
///
/// `fresh_until_unix_ms` is owner-produced from source acquisition time and
/// the deployment profile. The canonical observation resolver still makes
/// the actual consequence-time Current/Stale decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComposedExternalEvidenceV1 {
    pub schema: String,
    pub composition_id: String,
    pub profile: ExternalEvidenceProfileV1,
    pub source_observation_id: String,
    pub source_custody_id: String,
    pub source_campaign_id: String,
    pub source_occurrence_id: String,
    pub source_proposal_id: String,
    pub source_exact_work_id: String,
    pub source_issuance_id: String,
    pub source_attempt_id: String,
    pub source_settlement_id: String,
    pub source_plan_document_digest: String,
    pub source_compilation_id: String,
    pub producer_principal_id: String,
    pub producer_key_id: String,
    pub target_runtime_id: String,
    pub source_observed_at_unix_ms: u64,
    pub source_received_at: DateTime<Utc>,
    pub admitted_at: DateTime<Utc>,
    pub fresh_until_unix_ms: u64,
    pub target_campaign_id: String,
    pub target_occurrence_id: String,
    pub subject_id: String,
    pub subject_digest: String,
    pub scope_digest: String,
    pub claims: Vec<ComposedExternalClaimV1>,
    pub nonclaims: Vec<String>,
}

impl ComposedExternalEvidenceV1 {
    #[allow(clippy::too_many_arguments)]
    /// Construct one exact candidate composition. Production callers must
    /// still pass it through the canonical cycle runtime, which revalidates
    /// predecessor AG state and persists it atomically with the observation.
    pub fn compose(
        reference: &ExternalEvidenceReferenceV1,
        profile: &ExternalEvidenceProfileV1,
        observation: &LocalComposeWorldObservationV1,
        custody: &ExternalObservationCustodyProvenanceV1,
        admitted_at: DateTime<Utc>,
        target_campaign_id: &str,
        target_occurrence_id: &str,
        subject_id: &str,
        subject_digest: &str,
        scope_digest: &str,
    ) -> Result<Self, String> {
        reference.validate()?;
        profile.validate()?;
        observation.validate()?;
        custody.validate()?;
        if reference.source_observation_id != observation.observation_id
            || reference.source_custody_id != custody.custody_id
            || reference.profile_id != profile.profile_id
            || custody.observation_id != observation.observation_id
            || custody.campaign_id != observation.campaign_id
            || custody.occurrence_id != observation.occurrence_id
            || custody.exact_work_id != observation.exact_work_id
            || custody.attempt_id != observation.attempt_id
            || custody.settlement_id != observation.settlement_id
            || custody.executor_evidence_receipt != observation.executor_evidence_receipt
        {
            return Err("external evidence reference/custody/source binding mismatch".into());
        }
        if observation.adapter_id != profile.expected_adapter_id
            || observation.adapter_version != profile.expected_adapter_version
            || custody.producer_principal_id != profile.expected_producer_principal_id
            || custody.producer_key_id != profile.expected_producer_key_id
            || custody.target_runtime_id != profile.expected_runtime_id
        {
            return Err("external evidence does not match deployment profile".into());
        }
        if observation.action != profile.required_action
            || observation.outcome != ExecutorOutcomeV1::Success
        {
            return Err("external evidence is not adequate for the requested purpose".into());
        }
        let claim_kinds = observation
            .claims
            .iter()
            .map(|claim| claim.kind)
            .collect::<Vec<_>>();
        if claim_kinds != profile.required_claims
            || observation
                .claims
                .iter()
                .any(|claim| claim.status != WorldClaimStatusV1::Satisfied)
        {
            return Err("external evidence lacks the profile's exact satisfied claim set".into());
        }
        if observation.campaign_id != target_campaign_id
            || observation.occurrence_id == target_occurrence_id
            || observation.subject_digest != subject_digest
            || observation.scope_digest != scope_digest
        {
            return Err(
                "external evidence is not bound to the exact predecessor/subject/scope".into(),
            );
        }
        require_digest("target_campaign_id", target_campaign_id)?;
        require_token("target_occurrence_id", target_occurrence_id)?;
        require_token("subject_id", subject_id)?;
        require_digest("subject_digest", subject_digest)?;
        require_digest("scope_digest", scope_digest)?;
        let observed_at = u64::try_from(observation.observed_at_unix_ms)
            .map_err(|_| "source observation time is not representable".to_owned())?;
        let admitted_at_ms = unix_ms(admitted_at)?;
        let fresh_until_unix_ms = observed_at
            .checked_add(profile.max_age_ms)
            .ok_or_else(|| "external evidence horizon overflows Unix milliseconds".to_owned())?;
        if admitted_at_ms < observed_at {
            return Err("external evidence was admitted before its acquisition time".into());
        }
        if admitted_at < custody.received_at {
            return Err("external evidence was admitted before Nightshift custody".into());
        }
        if admitted_at_ms >= fresh_until_unix_ms {
            return Err("external evidence is stale for the configured profile".into());
        }
        let claims = observation
            .claims
            .iter()
            .map(|claim| ComposedExternalClaimV1 {
                claim_id: claim.claim_id.clone(),
                kind: claim.kind,
                plan_node_id: claim.plan_node_id.clone(),
                compiled_output_identity: claim.compiled_output_identity.clone(),
            })
            .collect();
        let mut value = Self {
            schema: COMPOSED_EXTERNAL_EVIDENCE_SCHEMA_V1.into(),
            composition_id: String::new(),
            profile: profile.clone(),
            source_observation_id: observation.observation_id.clone(),
            source_custody_id: custody.custody_id.clone(),
            source_campaign_id: observation.campaign_id.clone(),
            source_occurrence_id: observation.occurrence_id.clone(),
            source_proposal_id: observation.proposal_id.clone(),
            source_exact_work_id: observation.exact_work_id.clone(),
            source_issuance_id: observation.issuance_id.clone(),
            source_attempt_id: observation.attempt_id.clone(),
            source_settlement_id: observation.settlement_id.clone(),
            source_plan_document_digest: observation.plan_document_digest.clone(),
            source_compilation_id: observation.compilation_id.clone(),
            producer_principal_id: custody.producer_principal_id.clone(),
            producer_key_id: custody.producer_key_id.clone(),
            target_runtime_id: custody.target_runtime_id.clone(),
            source_observed_at_unix_ms: observed_at,
            source_received_at: custody.received_at,
            admitted_at,
            fresh_until_unix_ms,
            target_campaign_id: target_campaign_id.into(),
            target_occurrence_id: target_occurrence_id.into(),
            subject_id: subject_id.into(),
            subject_digest: subject_digest.into(),
            scope_digest: scope_digest.into(),
            claims,
            nonclaims: REQUIRED_NONCLAIMS.map(str::to_owned).to_vec(),
        };
        value.composition_id = object_id(&value, "composition_id")?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != COMPOSED_EXTERNAL_EVIDENCE_SCHEMA_V1 {
            return Err("unsupported composed external-evidence schema".into());
        }
        self.profile.validate()?;
        for (name, value) in [
            ("composition_id", &self.composition_id),
            ("source_observation_id", &self.source_observation_id),
            ("source_custody_id", &self.source_custody_id),
            ("source_campaign_id", &self.source_campaign_id),
            ("source_proposal_id", &self.source_proposal_id),
            ("source_exact_work_id", &self.source_exact_work_id),
            ("source_issuance_id", &self.source_issuance_id),
            ("source_attempt_id", &self.source_attempt_id),
            ("source_settlement_id", &self.source_settlement_id),
            (
                "source_plan_document_digest",
                &self.source_plan_document_digest,
            ),
            ("source_compilation_id", &self.source_compilation_id),
            ("target_campaign_id", &self.target_campaign_id),
            ("subject_digest", &self.subject_digest),
            ("scope_digest", &self.scope_digest),
        ] {
            require_digest(name, value)?;
        }
        for (name, value) in [
            ("source_occurrence_id", &self.source_occurrence_id),
            ("target_occurrence_id", &self.target_occurrence_id),
            ("subject_id", &self.subject_id),
            ("producer_principal_id", &self.producer_principal_id),
            ("producer_key_id", &self.producer_key_id),
            ("target_runtime_id", &self.target_runtime_id),
        ] {
            require_token(name, value)?;
        }
        if self.source_campaign_id != self.target_campaign_id
            || self.source_occurrence_id == self.target_occurrence_id
            || self.source_observed_at_unix_ms >= self.fresh_until_unix_ms
            || unix_ms(self.admitted_at)? < self.source_observed_at_unix_ms
            || self.admitted_at < self.source_received_at
            || unix_ms(self.admitted_at)? >= self.fresh_until_unix_ms
            || self
                .source_observed_at_unix_ms
                .checked_add(self.profile.max_age_ms)
                != Some(self.fresh_until_unix_ms)
            || self.producer_principal_id != self.profile.expected_producer_principal_id
            || self.producer_key_id != self.profile.expected_producer_key_id
            || self.target_runtime_id != self.profile.expected_runtime_id
            || self.nonclaims != REQUIRED_NONCLAIMS.map(str::to_owned)
        {
            return Err("composed external evidence binding or temporal law failed".into());
        }
        let kinds = self
            .claims
            .iter()
            .map(|claim| claim.kind)
            .collect::<Vec<_>>();
        if kinds != self.profile.required_claims {
            return Err("composed external evidence claim set differs from profile".into());
        }
        for claim in &self.claims {
            claim.validate()?;
        }
        if self.composition_id != object_id(self, "composition_id")? {
            return Err("composed external evidence identity mismatch".into());
        }
        Ok(())
    }

    /// Canonical observation identity content-bound to the exact composition.
    pub fn canonical_observation_id(&self) -> Result<String, String> {
        self.validate()?;
        let bytes = serde_jcs::to_vec(self).map_err(|error| error.to_string())?;
        let mut payload = COMPOSED_OBSERVATION_DOMAIN_V1.to_vec();
        payload.extend(bytes);
        Ok(format!("sha256:{:x}", Sha256::digest(payload)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_store::CanonicalStore;
    use crate::external_observation::{
        tests::{reseal_handoff, signed_handoff},
        ExternalObservationVerifierV1,
    };

    fn profile(max_age_ms: u64) -> ExternalEvidenceProfileV1 {
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
            max_age_ms,
        }
        .seal()
        .unwrap()
    }

    fn source() -> (
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

    fn reference(
        observation: &LocalComposeWorldObservationV1,
        custody: &ExternalObservationCustodyProvenanceV1,
        profile: &ExternalEvidenceProfileV1,
    ) -> ExternalEvidenceReferenceV1 {
        ExternalEvidenceReferenceV1 {
            schema: EXTERNAL_EVIDENCE_REFERENCE_SCHEMA_V1.into(),
            source_observation_id: observation.observation_id.clone(),
            source_custody_id: custody.custody_id.clone(),
            profile_id: profile.profile_id.clone(),
        }
    }

    fn compose_at(admitted_at: &str) -> Result<ComposedExternalEvidenceV1, String> {
        let (observation, custody) = source();
        let profile = profile(5_000);
        ComposedExternalEvidenceV1::compose(
            &reference(&observation, &custody, &profile),
            &profile,
            &observation,
            &custody,
            DateTime::parse_from_rfc3339(admitted_at)
                .unwrap()
                .with_timezone(&Utc),
            &observation.campaign_id,
            "00000000-0000-4000-8000-000000000001",
            "synthetic-cache",
            &observation.subject_digest,
            &observation.scope_digest,
        )
    }

    #[test]
    fn fresh_authenticated_source_produces_content_bound_composition() {
        let composition = compose_at("1970-01-01T00:00:03Z").unwrap();
        composition.validate().unwrap();
        assert_eq!(composition.source_observed_at_unix_ms, 1_000);
        assert_eq!(composition.fresh_until_unix_ms, 6_000);
        assert_eq!(composition.claims.len(), 4);
        assert!(composition
            .source_plan_document_digest
            .starts_with("sha256:"));
        assert!(composition.source_compilation_id.starts_with("sha256:"));
        assert_ne!(
            composition.composition_id,
            composition.canonical_observation_id().unwrap()
        );

        let mut changed = composition.clone();
        changed.claims[0].plan_node_id = "pn_substituted".into();
        changed.composition_id = object_id(&changed, "composition_id").unwrap();
        assert_ne!(
            composition.canonical_observation_id().unwrap(),
            changed.canonical_observation_id().unwrap()
        );

        let original_identity = composition.canonical_observation_id().unwrap();
        let mut changed_compilation = composition.clone();
        changed_compilation.source_compilation_id = format!("sha256:{}", "c".repeat(64));
        changed_compilation.composition_id =
            object_id(&changed_compilation, "composition_id").unwrap();
        assert_ne!(
            original_identity,
            changed_compilation.canonical_observation_id().unwrap(),
            "recomputed outer identities cannot hide compiler provenance substitution"
        );
    }

    #[test]
    fn stale_source_remains_custodied_but_cannot_compose() {
        assert_eq!(
            compose_at("1970-01-01T00:00:06Z").unwrap_err(),
            "external evidence is stale for the configured profile"
        );
        let (observation, custody) = source();
        assert_eq!(custody.observation_id, observation.observation_id);
    }

    #[test]
    fn profile_source_target_and_subject_substitution_refuse() {
        let (observation, custody) = source();
        let profile = profile(5_000);
        let mut wrong_reference = reference(&observation, &custody, &profile);
        wrong_reference.source_custody_id = format!("sha256:{}", "a".repeat(64));
        let admitted = DateTime::parse_from_rfc3339("1970-01-01T00:00:03Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(ComposedExternalEvidenceV1::compose(
            &wrong_reference,
            &profile,
            &observation,
            &custody,
            admitted,
            &observation.campaign_id,
            "00000000-0000-4000-8000-000000000001",
            "synthetic-cache",
            &observation.subject_digest,
            &observation.scope_digest,
        )
        .unwrap_err()
        .contains("binding mismatch"));
        assert!(ComposedExternalEvidenceV1::compose(
            &reference(&observation, &custody, &profile),
            &profile,
            &observation,
            &custody,
            admitted,
            &observation.campaign_id,
            "00000000-0000-4000-8000-000000000001",
            "synthetic-cache",
            &format!("sha256:{}", "b".repeat(64)),
            &observation.scope_digest,
        )
        .unwrap_err()
        .contains("predecessor/subject/scope"));
    }

    #[test]
    fn composition_types_contain_no_authority_or_display_age_fields() {
        let source = include_str!("external_evidence_composition.rs");
        for forbidden in [
            concat!("pub ", "authorization:"),
            concat!("pub ", "spend:"),
            concat!("pub ", "standing:"),
            concat!("pub ", "capability:"),
            concat!("pub ", "evidence_age:"),
        ] {
            assert!(!source.contains(forbidden), "found {forbidden}");
        }
    }

    #[test]
    fn checked_in_deployment_profile_has_an_exact_content_identity() {
        let profile: ExternalEvidenceProfileV1 = serde_json::from_str(include_str!(
            "../../../docs/operator/examples/external-evidence-profile-v1.json"
        ))
        .unwrap();
        profile.validate().unwrap();
        assert_eq!(profile.max_age_ms, 300_000);
    }

    #[test]
    fn fresh_reobservation_is_a_new_historical_source_and_observation_identity() {
        let directory = tempfile::tempdir().unwrap();
        let key = [7_u8; 32];
        let verifier = ExternalObservationVerifierV1::for_test(
            "maude-observer:local",
            "maude-observer-key:one",
            "nightshift:local",
            key,
        );
        let mut store = CanonicalStore::open(directory.path().join("nightshift.sqlite")).unwrap();
        let first = signed_handoff(
            &key,
            "1970-01-01T00:00:02Z",
            "00000000-0000-4000-8000-000000000000",
        );
        let first_verified = verifier.verify(&first).unwrap();
        let first_custody = store
            .record_external_observation(
                &first_verified,
                DateTime::parse_from_rfc3339("1970-01-01T00:00:02Z")
                    .unwrap()
                    .with_timezone(&Utc),
            )
            .unwrap();

        let mut second = signed_handoff(
            &key,
            "1970-01-01T00:00:03Z",
            "00000000-0000-4000-8000-000000000001",
        );
        second.observation.proposal_id = format!("sha256:{}", "1".repeat(64));
        second.observation.issuance_id = format!("sha256:{}", "2".repeat(64));
        second.observation.attempt_id = format!("sha256:{}", "3".repeat(64));
        second.observation.settlement_id = format!("sha256:{}", "4".repeat(64));
        second.observation.observed_at_unix_ms = 2_000;
        second.observation.source_evidence["dispatch"]["attempt"] =
            serde_json::json!(second.observation.attempt_id);
        second.observation.source_evidence["docket_outcome"]["attempt"] =
            serde_json::json!(second.observation.attempt_id);
        second.observation.source_evidence["observed_at_unix_ms"] = serde_json::json!(2_000);
        reseal_handoff(&mut second, &key);
        let second_verified = verifier.verify(&second).unwrap();
        let second_custody = store
            .record_external_observation(
                &second_verified,
                DateTime::parse_from_rfc3339("1970-01-01T00:00:03Z")
                    .unwrap()
                    .with_timezone(&Utc),
            )
            .unwrap();
        assert_ne!(
            first.observation.observation_id,
            second.observation.observation_id
        );
        assert_ne!(first_custody.custody_id, second_custody.custody_id);

        let profile = profile(10_000);
        let first_composition = ComposedExternalEvidenceV1::compose(
            &reference(&first.observation, &first_custody, &profile),
            &profile,
            &first.observation,
            &first_custody,
            DateTime::parse_from_rfc3339("1970-01-01T00:00:03Z")
                .unwrap()
                .with_timezone(&Utc),
            &first.observation.campaign_id,
            "00000000-0000-4000-8000-000000000002",
            "synthetic-cache",
            &first.observation.subject_digest,
            &first.observation.scope_digest,
        )
        .unwrap();
        let second_composition = ComposedExternalEvidenceV1::compose(
            &reference(&second.observation, &second_custody, &profile),
            &profile,
            &second.observation,
            &second_custody,
            DateTime::parse_from_rfc3339("1970-01-01T00:00:03Z")
                .unwrap()
                .with_timezone(&Utc),
            &second.observation.campaign_id,
            "00000000-0000-4000-8000-000000000002",
            "synthetic-cache",
            &second.observation.subject_digest,
            &second.observation.scope_digest,
        )
        .unwrap();
        assert_ne!(
            first_composition.canonical_observation_id().unwrap(),
            second_composition.canonical_observation_id().unwrap()
        );
    }
}

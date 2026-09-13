//! Immutable, authority-neutral provenance for the Maude-to-governed-work handoff.
//!
//! This module records lineage only.  None of its types is accepted by NQ,
//! currentness, standing, admissibility, authorization, spend, or Docket APIs.
//! The canonical runtime constructs the final record only after it has compiled
//! the exact AG proposal and occurrence request.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const AUTHORING_CONTEXT_INPUT_SCHEMA_V1: &str = "nightshift.maude_authoring_context_input.v1";
pub const AUTHORING_CONTEXT_PROVENANCE_SCHEMA_V1: &str =
    "nightshift.authoring_context_provenance.v1";
pub const AUTHORING_CONTEXT_EXPORT_SCHEMA_V1: &str = "nightshift.authoring_context_export.v1";
pub const AUTHORING_CONTEXT_PRODUCER_V1: &str = "nightshift.canonical_runtime";
pub const AG_PROPOSAL_IDENTITY_DOMAIN_V1: &str = "ag.governed-loop.proposal/v1";

const MAX_PLAN_BYTES: usize = 1024 * 1024;

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

fn plain_sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
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

fn object_id<T: Serialize>(value: &T, field: &str) -> Result<String, String> {
    let mut value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    value
        .as_object_mut()
        .ok_or_else(|| "identity preimage is not an object".to_owned())?
        .remove(field);
    let canonical = serde_jcs::to_vec(&value).map_err(|error| error.to_string())?;
    Ok(plain_sha256(&canonical))
}

/// Exact Maude context presented at the canonical Nightshift handoff.
///
/// The raw plan bytes are present so Nightshift derives and verifies
/// `plan_ref` itself; they are deliberately omitted from the durable relation.
/// This input is lineage evidence, never an authorization witness.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaudeAuthoringContextInputV1 {
    pub schema: String,
    pub plan_ref: String,
    pub session_id: String,
    pub plan_text: String,
}

impl MaudeAuthoringContextInputV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != AUTHORING_CONTEXT_INPUT_SCHEMA_V1 {
            return Err("unsupported Maude authoring-context input schema".into());
        }
        require_digest("Maude plan_ref", &self.plan_ref)?;
        require_token("Maude session_id", &self.session_id)?;
        if self.plan_text.is_empty() || self.plan_text.len() > MAX_PLAN_BYTES {
            return Err("Maude plan_text must contain 1..=1048576 UTF-8 bytes".into());
        }
        if plain_sha256(self.plan_text.as_bytes()) != self.plan_ref {
            return Err("Maude plan_ref does not bind the exact plan bytes".into());
        }
        Ok(())
    }
}

/// Immutable relation minted by Nightshift at exact AG proposal preparation.
///
/// `provenance_id` is the self-digest of every other field. `recorded_at` is
/// evidence of the handoff event, never an identity matcher or freshness fact.
/// `producer_component` identifies the software boundary, not an authenticated
/// deployment principal; deployment/source honesty remains environmental.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoringContextProvenanceV1 {
    pub schema: String,
    pub provenance_id: String,
    pub producer_component: String,
    pub maude_plan_ref: String,
    pub maude_session_id: String,
    pub source_plan_bytes: u64,
    pub campaign_id: String,
    pub occurrence_id: String,
    pub proposal_id: String,
    pub exact_work_id: String,
    pub source_intent_id: String,
    pub recorded_at: DateTime<Utc>,
}

impl AuthoringContextProvenanceV1 {
    /// Canonical constructor. Visibility confines minting to the Nightshift
    /// crate; callers and operator UIs can only supply the separately checked
    /// input or deserialize a read projection.
    pub(crate) fn mint(
        input: &MaudeAuthoringContextInputV1,
        campaign_id: String,
        occurrence_id: String,
        proposal_id: String,
        exact_work_id: String,
        source_intent_id: String,
        recorded_at: DateTime<Utc>,
    ) -> Result<Self, String> {
        input.validate()?;
        let source_plan_bytes = u64::try_from(input.plan_text.len())
            .map_err(|_| "Maude plan length does not fit u64".to_owned())?;
        let mut value = Self {
            schema: AUTHORING_CONTEXT_PROVENANCE_SCHEMA_V1.into(),
            provenance_id: String::new(),
            producer_component: AUTHORING_CONTEXT_PRODUCER_V1.into(),
            maude_plan_ref: plain_sha256(input.plan_text.as_bytes()),
            maude_session_id: input.session_id.clone(),
            source_plan_bytes,
            campaign_id,
            occurrence_id,
            proposal_id,
            exact_work_id,
            source_intent_id,
            recorded_at,
        };
        value.provenance_id = object_id(&value, "provenance_id")?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != AUTHORING_CONTEXT_PROVENANCE_SCHEMA_V1 {
            return Err("unsupported authoring-context provenance schema".into());
        }
        if self.producer_component != AUTHORING_CONTEXT_PRODUCER_V1 {
            return Err("authoring-context producer component mismatch".into());
        }
        for (name, value) in [
            ("provenance_id", &self.provenance_id),
            ("maude_plan_ref", &self.maude_plan_ref),
            ("campaign_id", &self.campaign_id),
            ("proposal_id", &self.proposal_id),
            ("exact_work_id", &self.exact_work_id),
            ("source_intent_id", &self.source_intent_id),
        ] {
            require_digest(name, value)?;
        }
        require_token("maude_session_id", &self.maude_session_id)?;
        uuid::Uuid::parse_str(&self.occurrence_id)
            .map_err(|_| "authoring-context occurrence_id must be a UUID".to_owned())?;
        if self.source_plan_bytes == 0 || self.source_plan_bytes > MAX_PLAN_BYTES as u64 {
            return Err("authoring-context source plan length is invalid".into());
        }
        if self.provenance_id != object_id(self, "provenance_id")? {
            return Err("authoring-context provenance_id does not bind the exact record".into());
        }
        Ok(())
    }

    pub fn validate_relationship(
        &self,
        campaign_id: &str,
        occurrence_id: &str,
        proposal_id: &str,
        exact_work_id: &str,
        source_intent_id: &str,
    ) -> Result<(), String> {
        self.validate()?;
        if self.campaign_id != campaign_id
            || self.occurrence_id != occurrence_id
            || self.proposal_id != proposal_id
            || self.exact_work_id != exact_work_id
            || self.source_intent_id != source_intent_id
        {
            return Err(
                "authoring-context provenance does not bind the exact governed relationship".into(),
            );
        }
        Ok(())
    }
}

/// Derives the AG proposal identity from the exact `proposal_input` object by
/// the same domain-separated JCS law as `ExactWorkProposalV1::reference`.
pub fn ag_proposal_identity(proposal_input: &serde_json::Value) -> Result<String, String> {
    let proposal = proposal_input
        .get("proposal")
        .ok_or_else(|| "proposal_input does not contain proposal".to_owned())?;
    if !proposal.is_object() {
        return Err("proposal_input.proposal must be an object".into());
    }
    let canonical = serde_jcs::to_vec(proposal).map_err(|error| error.to_string())?;
    Ok(ag_hash_domain(AG_PROPOSAL_IDENTITY_DOMAIN_V1, &canonical))
}

pub fn exact_work_identity(proposal_input: &serde_json::Value) -> Result<String, String> {
    let work = proposal_input
        .get("proposal")
        .and_then(|proposal| proposal.get("work"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "proposal_input does not contain exact proposal work".to_owned())?;
    require_digest("exact proposal work", work)?;
    Ok(work.to_owned())
}

/// Closed read projection. Query criteria are repeated verbatim so a caller
/// can detect substituted responses rather than trusting transport context.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoringContextExportV1 {
    pub schema: String,
    pub query: AuthoringContextQueryV1,
    pub matches: Vec<AuthoringContextProvenanceV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "by", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthoringContextQueryV1 {
    GovernedOccurrence {
        campaign_id: String,
        occurrence_id: String,
    },
    Proposal {
        proposal_id: String,
    },
    MaudeContext {
        plan_ref: String,
        session_id: String,
    },
}

impl AuthoringContextQueryV1 {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::GovernedOccurrence {
                campaign_id,
                occurrence_id,
            } => {
                require_digest("campaign_id", campaign_id)?;
                uuid::Uuid::parse_str(occurrence_id)
                    .map_err(|_| "occurrence_id must be a UUID".to_owned())?;
            }
            Self::Proposal { proposal_id } => require_digest("proposal_id", proposal_id)?,
            Self::MaudeContext {
                plan_ref,
                session_id,
            } => {
                require_digest("plan_ref", plan_ref)?;
                require_token("session_id", session_id)?;
            }
        }
        Ok(())
    }
}

impl AuthoringContextExportV1 {
    pub fn new(
        query: AuthoringContextQueryV1,
        matches: Vec<AuthoringContextProvenanceV1>,
    ) -> Result<Self, String> {
        query.validate()?;
        for value in &matches {
            value.validate()?;
            let bound = match &query {
                AuthoringContextQueryV1::GovernedOccurrence {
                    campaign_id,
                    occurrence_id,
                } => value.campaign_id == *campaign_id && value.occurrence_id == *occurrence_id,
                AuthoringContextQueryV1::Proposal { proposal_id } => {
                    value.proposal_id == *proposal_id
                }
                AuthoringContextQueryV1::MaudeContext {
                    plan_ref,
                    session_id,
                } => value.maude_plan_ref == *plan_ref && value.maude_session_id == *session_id,
            };
            if !bound {
                return Err("authoring-context export contains a substituted match".into());
            }
        }
        Ok(Self {
            schema: AUTHORING_CONTEXT_EXPORT_SCHEMA_V1.into(),
            query,
            matches,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(label: &str) -> String {
        plain_sha256(label.as_bytes())
    }

    fn input(plan: &str) -> MaudeAuthoringContextInputV1 {
        MaudeAuthoringContextInputV1 {
            schema: AUTHORING_CONTEXT_INPUT_SCHEMA_V1.into(),
            plan_ref: plain_sha256(plan.as_bytes()),
            session_id: "sess_0123456789ab".into(),
            plan_text: plan.into(),
        }
    }

    fn record() -> AuthoringContextProvenanceV1 {
        AuthoringContextProvenanceV1::mint(
            &input("exact plan A\n"),
            digest("campaign"),
            "00000000-0000-0000-0000-000000000001".into(),
            digest("proposal"),
            digest("work"),
            digest("intent"),
            "2026-08-21T12:00:00Z".parse().unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn plan_bytes_are_rehashed_at_the_handoff() {
        let mut value = input("exact plan A\n");
        value.plan_text = "substituted plan B\n".into();
        assert!(value.validate().is_err());
    }

    #[test]
    fn self_digest_and_exact_relationship_reject_substitution() {
        let value = record();
        assert!(value.validate().is_ok());
        assert!(value
            .validate_relationship(
                &value.campaign_id,
                &value.occurrence_id,
                &value.proposal_id,
                &value.exact_work_id,
                &value.source_intent_id,
            )
            .is_ok());

        let mut substituted = value.clone();
        substituted.exact_work_id = digest("work-b");
        assert!(substituted.validate().is_err());

        substituted.provenance_id = object_id(&substituted, "provenance_id").unwrap();
        assert!(substituted.validate().is_ok());
        assert!(substituted
            .validate_relationship(
                &value.campaign_id,
                &value.occurrence_id,
                &value.proposal_id,
                &value.exact_work_id,
                &value.source_intent_id,
            )
            .is_err());
    }

    #[test]
    fn unsupported_schema_and_producer_refuse() {
        let mut value = record();
        value.schema = "nightshift.authoring_context_provenance.v2".into();
        assert!(value.validate().is_err());
        let mut value = record();
        value.producer_component = "maude.ui".into();
        value.provenance_id = object_id(&value, "provenance_id").unwrap();
        assert!(value.validate().is_err());
    }

    /// Pinned byte-for-byte against AG-NG's `ExactWorkProposalV1::reference`.
    #[test]
    fn ag_proposal_identity_matches_cross_repository_vector() {
        let proposal_input = serde_json::json!({
            "observation": digest("observation"),
            "proposal": {
                "schema": "ag.governed-loop.exact-work-proposal/v1",
                "campaign": format!("sha256:{}", "a".repeat(64)),
                "subject": format!("sha256:{}", "b".repeat(64)),
                "scope": format!("sha256:{}", "c".repeat(64)),
                "work_schema": "test.exact-work/v1",
                "work": format!("sha256:{}", "d".repeat(64)),
                "repair": null
            },
            "class": "initial"
        });
        assert_eq!(
            ag_proposal_identity(&proposal_input).unwrap(),
            "sha256:101445d903d1c43207f5ab6bc44bd1b2b74c05d738d7afe464d22eff00704fe7"
        );
    }
}

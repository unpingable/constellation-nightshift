//! Verification-only consumer for Standing continuity-authority carriers.
//!
//! Nightshift never signs these objects. It verifies that Standing authenticated
//! one exact substrate-incarnation edge and committed that exact authority into
//! one acquisition before the provider intake named by a diagnostic artifact.
//! Timestamps remain retained evidence; no timestamp establishes causality.

use std::fs::OpenOptions;
use std::io::Read as _;
use std::path::Path;

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

pub const AUTHORITY_SCHEMA_V1: &str = "standing.continuity_authority.v1";
pub const SIGNED_AUTHORITY_SCHEMA_V1: &str = "standing.signed_continuity_authority.v1";
pub const COMMITMENT_SCHEMA_V1: &str = "standing.continuity_acquisition_commitment.v1";
pub const SIGNED_COMMITMENT_SCHEMA_V1: &str =
    "standing.signed_continuity_acquisition_commitment.v1";
pub const CARRIER_SCHEMA_V1: &str = "standing.continuity_acquisition_bundle.v1";
pub const BASIS_SCHEMA_V1: &str = "nq.continuity_acquisition_basis.v1";
pub const INTENT_SCHEMA_V1: &str = "nq.provider_acquisition_intent.v1";
pub const APPLICABILITY_SCHEMA_V1: &str = "nightshift.continuity_applicability.v1";
const MAX_PUBLIC_KEY_BYTES: u64 = 256;

fn require_token(name: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.chars().any(char::is_whitespace) {
        return Err(format!("{name} must be a non-empty token"));
    }
    Ok(())
}

fn require_hex_digest(name: &str, value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{name} must be 64 lowercase hexadecimal characters"
        ));
    }
    Ok(())
}

fn require_prefixed_digest(name: &str, value: &str) -> Result<(), String> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(format!("{name} must use sha256:<64 lowercase hex>"));
    };
    require_hex_digest(name, hex)
}

fn require_signature_hex(name: &str, value: &str) -> Result<(), String> {
    if value.len() != 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{name} must be 128 lowercase hexadecimal characters"
        ));
    }
    Ok(())
}

fn jcs<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    serde_jcs::to_vec(value).map_err(|error| error.to_string())
}

fn object_id<T: Serialize>(value: &T, field: &str) -> Result<String, String> {
    let mut value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    value
        .as_object_mut()
        .ok_or_else(|| "identity preimage is not an object".to_owned())?
        .remove(field);
    Ok(format!("sha256:{:x}", Sha256::digest(jcs(&value)?)))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    const KEY_ID: &str = "standing-continuity:test-key";
    const AUDIENCE: &str = "nq:test-office";
    const ARTIFACT: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const STANDING_BASIS: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const STANDING: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn time(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&Utc)
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    fn sign_payload<T: Serialize>(schema: &str, payload: &T) -> (String, String) {
        let canonical = jcs(payload).unwrap();
        let digest = format!("{:x}", Sha256::digest(&canonical));
        let mut input = Vec::new();
        input.extend_from_slice(schema.as_bytes());
        input.push(0);
        input.extend_from_slice(&canonical);
        let signature = hex::encode(signing_key().sign(&input).to_bytes());
        (digest, signature)
    }

    pub(crate) fn proof() -> ContinuityAcquisitionProofV1 {
        let authority_payload = ContinuityAuthorityV1 {
            schema: AUTHORITY_SCHEMA_V1.into(),
            authority_occurrence_ref: Uuid::from_u128(1),
            issuance_request_id: Uuid::from_u128(2),
            standing_instance: STANDING.into(),
            edge: ContinuityEdgeV1 {
                subject_ref: "observer:test-office".into(),
                relation: ContinuityRelationV1::SubstrateIncarnation,
                predecessor_ref: "substrate:test-a".into(),
                successor_ref: "substrate:test-b".into(),
            },
            nq_audience: AUDIENCE.into(),
            issuer_principal: "standing:test-office".into(),
            standing_basis_digest: STANDING_BASIS.into(),
            replay_identity: "authority-replay:1".into(),
            issued_at: time("2026-08-24T12:00:00Z"),
            nonclaims: authority_nonclaims(),
        };
        let (authority_digest, authority_signature) =
            sign_payload(SIGNED_AUTHORITY_SCHEMA_V1, &authority_payload);
        let authority = SignedContinuityAuthorityV1 {
            schema: SIGNED_AUTHORITY_SCHEMA_V1.into(),
            key_id: KEY_ID.into(),
            payload: authority_payload,
            payload_digest: authority_digest.clone(),
            signature: authority_signature,
        };
        let basis = ContinuityAcquisitionBasisV1 {
            schema: BASIS_SCHEMA_V1.into(),
            acquisition_id: "provider-intake:test".into(),
            nq_audience: AUDIENCE.into(),
            watcher_instance_id: "watcher:test-office".into(),
            watcher_config_digest: "d".repeat(64),
            authority_occurrence_ref: Uuid::from_u128(1).to_string(),
            authority_digest: authority_digest.clone(),
            edge: authority.payload.edge.clone(),
        };
        let basis_digest = format!("{:x}", Sha256::digest(jcs(&basis).unwrap()));
        let commitment_payload = ContinuityAcquisitionCommitmentV1 {
            schema: COMMITMENT_SCHEMA_V1.into(),
            commitment_occurrence_ref: Uuid::from_u128(3),
            request_id: Uuid::from_u128(4),
            authority_occurrence_ref: Uuid::from_u128(1),
            authority_payload_digest: authority_digest,
            acquisition_id: "provider-intake:test".into(),
            acquisition_basis_digest: basis_digest.clone(),
            nq_audience: AUDIENCE.into(),
            standing_instance: STANDING.into(),
            committed_at: time("2026-08-24T12:01:00Z"),
            replay_identity: "commitment-replay:1".into(),
            nonclaims: commitment_nonclaims(),
        };
        let (commitment_digest, commitment_signature) =
            sign_payload(SIGNED_COMMITMENT_SCHEMA_V1, &commitment_payload);
        let carrier = ContinuityAcquisitionCarrierV1 {
            schema: CARRIER_SCHEMA_V1.into(),
            authority,
            commitment: SignedContinuityAcquisitionCommitmentV1 {
                schema: SIGNED_COMMITMENT_SCHEMA_V1.into(),
                key_id: KEY_ID.into(),
                payload: commitment_payload,
                payload_digest: commitment_digest,
                signature: commitment_signature,
            },
        };
        let mut intent = ProviderAcquisitionIntentV1 {
            schema: INTENT_SCHEMA_V1.into(),
            intent_id: String::new(),
            basis,
            basis_digest,
            carrier,
            intake_id: "provider-intake:test".into(),
            attempt_id: "attempt:test".into(),
            run_id: "run:test".into(),
            request: serde_json::json!({
                "instance_id": "watcher:test-office",
                "binding": {"subject": "observer:test-office"}
            }),
            provider: serde_json::json!({"name": "fixture-provider", "version": "v1"}),
            origin_carrier: "fixture:test".into(),
            checkpoint_contract_digest: format!("sha256:{}", "e".repeat(64)),
        };
        intent.intent_id = object_id(&intent, "intent_id").unwrap();
        ContinuityAcquisitionProofV1 {
            intent_digest: format!("sha256:{:x}", Sha256::digest(jcs(&intent).unwrap())),
            intent,
            phases: vec![
                ContinuityAcquisitionPhaseV1::ProviderInvocationStarted,
                ContinuityAcquisitionPhaseV1::ProviderIntakeCompleted,
            ],
        }
    }

    pub(crate) fn verifier() -> ContinuityAuthorityVerifierV1 {
        ContinuityAuthorityVerifierV1::from_public_key_hex(
            KEY_ID.into(),
            AUDIENCE.into(),
            &hex::encode(signing_key().verifying_key().to_bytes()),
        )
        .unwrap()
    }

    pub(crate) fn resign_authority(proof: &mut ContinuityAcquisitionProofV1) {
        let (digest, signature) = sign_payload(
            SIGNED_AUTHORITY_SCHEMA_V1,
            &proof.intent.carrier.authority.payload,
        );
        proof.intent.carrier.authority.payload_digest = digest;
        proof.intent.carrier.authority.signature = signature;
    }

    pub(crate) fn resign_commitment(proof: &mut ContinuityAcquisitionProofV1) {
        let (digest, signature) = sign_payload(
            SIGNED_COMMITMENT_SCHEMA_V1,
            &proof.intent.carrier.commitment.payload,
        );
        proof.intent.carrier.commitment.payload_digest = digest;
        proof.intent.carrier.commitment.signature = signature;
    }

    pub(crate) fn reseal_intent(proof: &mut ContinuityAcquisitionProofV1) {
        proof.intent.intent_id.clear();
        proof.intent.intent_id = object_id(&proof.intent, "intent_id").unwrap();
        proof.intent_digest = format!("sha256:{:x}", Sha256::digest(jcs(&proof.intent).unwrap()));
    }

    fn rebind_authority(proof: &mut ContinuityAcquisitionProofV1) {
        proof.intent.basis.authority_occurrence_ref = proof
            .intent
            .carrier
            .authority
            .payload
            .authority_occurrence_ref
            .to_string();
        proof.intent.basis.authority_digest = proof.intent.carrier.authority.payload_digest.clone();
        proof.intent.basis.edge = proof.intent.carrier.authority.payload.edge.clone();
        proof.intent.basis_digest =
            format!("{:x}", Sha256::digest(jcs(&proof.intent.basis).unwrap()));
        proof
            .intent
            .carrier
            .commitment
            .payload
            .authority_occurrence_ref = proof
            .intent
            .carrier
            .authority
            .payload
            .authority_occurrence_ref;
        proof
            .intent
            .carrier
            .commitment
            .payload
            .authority_payload_digest = proof.intent.carrier.authority.payload_digest.clone();
        proof
            .intent
            .carrier
            .commitment
            .payload
            .acquisition_basis_digest = proof.intent.basis_digest.clone();
        resign_commitment(proof);
        reseal_intent(proof);
    }

    #[test]
    fn exact_authenticated_prerequisite_is_applicable_and_replay_converges() {
        let proof = proof();
        let first = verifier()
            .evaluate(
                &proof,
                ARTIFACT,
                "observer:test-office",
                "provider-intake:test",
                Some("substrate:test-a"),
                Some("substrate:test-b"),
            )
            .unwrap();
        let replay = verifier()
            .evaluate(
                &proof,
                ARTIFACT,
                "observer:test-office",
                "provider-intake:test",
                Some("substrate:test-a"),
                Some("substrate:test-b"),
            )
            .unwrap();
        assert_eq!(first, replay);
        assert_eq!(first.status, ContinuityApplicabilityStatusV1::Applicable);
    }

    #[test]
    fn missing_independent_substrate_coordinate_is_unresolved() {
        let proof = proof();
        let verdict = verifier()
            .evaluate(
                &proof,
                ARTIFACT,
                "observer:test-office",
                "provider-intake:test",
                None,
                None,
            )
            .unwrap();
        assert_eq!(verdict.status, ContinuityApplicabilityStatusV1::Unresolved);
        assert_eq!(
            verdict.reason,
            ContinuityApplicabilityReasonV1::ObservationSubstrateAbsent
        );
    }

    #[test]
    fn exact_subject_intake_and_edge_are_not_substitutable() {
        for (subject, intake, predecessor, successor, reason) in [
            (
                "observer:other",
                "provider-intake:test",
                "substrate:test-a",
                "substrate:test-b",
                ContinuityApplicabilityReasonV1::SubjectMismatch,
            ),
            (
                "observer:test-office",
                "provider-intake:other",
                "substrate:test-a",
                "substrate:test-b",
                ContinuityApplicabilityReasonV1::IntakeMismatch,
            ),
            (
                "observer:test-office",
                "provider-intake:test",
                "substrate:test-z",
                "substrate:test-b",
                ContinuityApplicabilityReasonV1::EdgeMismatch,
            ),
            (
                "observer:test-office",
                "provider-intake:test",
                "substrate:test-a",
                "substrate:test-c",
                ContinuityApplicabilityReasonV1::ObservationSubstrateMismatch,
            ),
        ] {
            let verdict = verifier()
                .evaluate(
                    &proof(),
                    ARTIFACT,
                    subject,
                    intake,
                    Some(predecessor),
                    Some(successor),
                )
                .unwrap();
            assert_eq!(verdict.status, ContinuityApplicabilityStatusV1::Refused);
            assert_eq!(verdict.reason, reason);
        }
    }

    #[test]
    fn ex_post_or_backdated_authority_cannot_be_retrofitted() {
        let mut candidate = proof();
        candidate
            .intent
            .carrier
            .authority
            .payload
            .authority_occurrence_ref = Uuid::from_u128(99);
        candidate.intent.carrier.authority.payload.issued_at = time("2000-01-01T00:00:00Z");
        resign_authority(&mut candidate);
        reseal_intent(&mut candidate);
        assert!(verifier()
            .evaluate(
                &candidate,
                ARTIFACT,
                "observer:test-office",
                "provider-intake:test",
                Some("substrate:test-a"),
                Some("substrate:test-b")
            )
            .unwrap_err()
            .contains("does not bind"));
    }

    #[test]
    fn acquisition_and_authority_resealing_cannot_hide_substitution() {
        let mut candidate = proof();
        candidate.intent.basis_digest = "d".repeat(64);
        reseal_intent(&mut candidate);
        assert!(verifier()
            .evaluate(
                &candidate,
                ARTIFACT,
                "observer:test-office",
                "provider-intake:test",
                Some("substrate:test-a"),
                Some("substrate:test-b"),
            )
            .unwrap_err()
            .contains("basis digest mismatch"));

        let mut candidate = proof();
        candidate
            .intent
            .carrier
            .commitment
            .payload
            .authority_payload_digest = "e".repeat(64);
        resign_commitment(&mut candidate);
        reseal_intent(&mut candidate);
        assert!(verifier()
            .evaluate(
                &candidate,
                ARTIFACT,
                "observer:test-office",
                "provider-intake:test",
                Some("substrate:test-a"),
                Some("substrate:test-b")
            )
            .is_err());
    }

    #[test]
    fn deliberate_second_authority_remains_a_distinct_occurrence() {
        let first = proof();
        let mut second = proof();
        second
            .intent
            .carrier
            .authority
            .payload
            .authority_occurrence_ref = Uuid::from_u128(20);
        resign_authority(&mut second);
        second
            .intent
            .carrier
            .commitment
            .payload
            .commitment_occurrence_ref = Uuid::from_u128(21);
        rebind_authority(&mut second);
        let first = verifier()
            .evaluate(
                &first,
                ARTIFACT,
                "observer:test-office",
                "provider-intake:test",
                Some("substrate:test-a"),
                Some("substrate:test-b"),
            )
            .unwrap();
        let second = verifier()
            .evaluate(
                &second,
                ARTIFACT,
                "observer:test-office",
                "provider-intake:test",
                Some("substrate:test-a"),
                Some("substrate:test-b"),
            )
            .unwrap();
        assert_ne!(
            first.authority_occurrence_ref,
            second.authority_occurrence_ref
        );
        assert_ne!(first.applicability_id, second.applicability_id);
    }

    #[test]
    fn late_consumer_delivery_does_not_change_historical_applicability() {
        let serialized = jcs(&proof()).unwrap();
        let delivered_late: ContinuityAcquisitionProofV1 =
            serde_json::from_slice(&serialized).unwrap();
        let verdict = verifier()
            .evaluate(
                &delivered_late,
                ARTIFACT,
                "observer:test-office",
                "provider-intake:test",
                Some("substrate:test-a"),
                Some("substrate:test-b"),
            )
            .unwrap();
        assert_eq!(verdict.status, ContinuityApplicabilityStatusV1::Applicable);
    }

    #[test]
    fn closed_relation_schema_and_phase_chain_refuse_unknown_or_incomplete_input() {
        let mut unknown_relation = serde_json::to_value(proof()).unwrap();
        unknown_relation["intent"]["basis"]["edge"]["relation"] =
            serde_json::json!("mandate_revision");
        assert!(serde_json::from_value::<ContinuityAcquisitionProofV1>(unknown_relation).is_err());

        let mut missing_phase = proof();
        missing_phase.phases.pop();
        assert!(verifier()
            .evaluate(
                &missing_phase,
                ARTIFACT,
                "observer:test-office",
                "provider-intake:test",
                Some("substrate:test-a"),
                Some("substrate:test-b"),
            )
            .unwrap_err()
            .contains("exact completed phase chain"));
    }

    #[test]
    fn signer_payload_and_provider_request_substitution_refuse_after_resealing() {
        let mut bad_signature = proof();
        bad_signature.intent.carrier.authority.signature = "0".repeat(128);
        reseal_intent(&mut bad_signature);
        assert!(verifier()
            .evaluate(
                &bad_signature,
                ARTIFACT,
                "observer:test-office",
                "provider-intake:test",
                Some("substrate:test-a"),
                Some("substrate:test-b"),
            )
            .unwrap_err()
            .contains("Ed25519 verification failed"));

        let mut wrong_request = proof();
        wrong_request.intent.request["binding"]["subject"] = serde_json::json!("observer:other");
        reseal_intent(&mut wrong_request);
        assert!(verifier()
            .evaluate(
                &wrong_request,
                ARTIFACT,
                "observer:test-office",
                "provider-intake:test",
                Some("substrate:test-a"),
                Some("substrate:test-b"),
            )
            .unwrap_err()
            .contains("substitutes its exact acquisition basis"));
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuityRelationV1 {
    SubstrateIncarnation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityEdgeV1 {
    pub subject_ref: String,
    pub relation: ContinuityRelationV1,
    pub predecessor_ref: String,
    pub successor_ref: String,
}

impl ContinuityEdgeV1 {
    fn validate(&self) -> Result<(), String> {
        require_token("continuity subject_ref", &self.subject_ref)?;
        require_token("continuity predecessor_ref", &self.predecessor_ref)?;
        require_token("continuity successor_ref", &self.successor_ref)?;
        if self.predecessor_ref == self.successor_ref {
            return Err("continuity predecessor and successor must differ".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityNonclaimV1 {
    TransitionOccurred,
    EvidenceTruth,
    CurrentAttribution,
    RoutineReliance,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentNonclaimV1 {
    ProviderInvoked,
    ObservationProduced,
    EvidenceTruth,
    CurrentAttribution,
}

fn authority_nonclaims() -> Vec<AuthorityNonclaimV1> {
    vec![
        AuthorityNonclaimV1::TransitionOccurred,
        AuthorityNonclaimV1::EvidenceTruth,
        AuthorityNonclaimV1::CurrentAttribution,
        AuthorityNonclaimV1::RoutineReliance,
    ]
}

fn commitment_nonclaims() -> Vec<CommitmentNonclaimV1> {
    vec![
        CommitmentNonclaimV1::ProviderInvoked,
        CommitmentNonclaimV1::ObservationProduced,
        CommitmentNonclaimV1::EvidenceTruth,
        CommitmentNonclaimV1::CurrentAttribution,
    ]
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityAuthorityV1 {
    pub schema: String,
    pub authority_occurrence_ref: Uuid,
    pub issuance_request_id: Uuid,
    pub standing_instance: String,
    pub edge: ContinuityEdgeV1,
    pub nq_audience: String,
    pub issuer_principal: String,
    pub standing_basis_digest: String,
    pub replay_identity: String,
    /// Evidence only; never consulted for causal precedence.
    pub issued_at: DateTime<Utc>,
    pub nonclaims: Vec<AuthorityNonclaimV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedContinuityAuthorityV1 {
    pub schema: String,
    pub key_id: String,
    pub payload: ContinuityAuthorityV1,
    pub payload_digest: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityAcquisitionCommitmentV1 {
    pub schema: String,
    pub commitment_occurrence_ref: Uuid,
    pub request_id: Uuid,
    pub authority_occurrence_ref: Uuid,
    pub authority_payload_digest: String,
    /// Preallocated NQ acquisition/provider-intake identity.
    pub acquisition_id: String,
    /// Digest of the exact immutable basis committed before provider dispatch.
    pub acquisition_basis_digest: String,
    pub nq_audience: String,
    pub standing_instance: String,
    /// Evidence only; never consulted for causal precedence.
    pub committed_at: DateTime<Utc>,
    pub replay_identity: String,
    pub nonclaims: Vec<CommitmentNonclaimV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedContinuityAcquisitionCommitmentV1 {
    pub schema: String,
    pub key_id: String,
    pub payload: ContinuityAcquisitionCommitmentV1,
    pub payload_digest: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityAcquisitionCarrierV1 {
    pub schema: String,
    pub authority: SignedContinuityAuthorityV1,
    pub commitment: SignedContinuityAcquisitionCommitmentV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityAcquisitionBasisV1 {
    pub schema: String,
    pub acquisition_id: String,
    pub nq_audience: String,
    pub watcher_instance_id: String,
    pub watcher_config_digest: String,
    pub authority_occurrence_ref: String,
    pub authority_digest: String,
    pub edge: ContinuityEdgeV1,
}

/// Exact NQ intent durably committed before the bound provider invocation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAcquisitionIntentV1 {
    pub schema: String,
    pub intent_id: String,
    pub basis: ContinuityAcquisitionBasisV1,
    pub basis_digest: String,
    pub carrier: ContinuityAcquisitionCarrierV1,
    pub intake_id: String,
    pub attempt_id: String,
    pub run_id: String,
    /// Frozen NQ helper request. Nightshift retains and hashes its exact body;
    /// the NQ protocol remains the owner of its internal vocabulary.
    pub request: serde_json::Value,
    /// Frozen NQ provider identity, likewise retained exactly.
    pub provider: serde_json::Value,
    pub origin_carrier: String,
    pub checkpoint_contract_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuityAcquisitionPhaseV1 {
    ProviderInvocationStarted,
    ProviderIntakeCompleted,
}

/// Exact V2 block exported by NQ admission qualification.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityAcquisitionProofV1 {
    pub intent: ProviderAcquisitionIntentV1,
    pub intent_digest: String,
    pub phases: Vec<ContinuityAcquisitionPhaseV1>,
}

impl ContinuityAcquisitionProofV1 {
    /// Verify every closed schema, content identity, and duplicated binding
    /// that can be checked without deployment-owned Standing trust material.
    /// Ed25519 authenticity is checked separately by the configured verifier.
    pub fn validate_shape(&self) -> Result<(), String> {
        let intent = &self.intent;
        if intent.schema != INTENT_SCHEMA_V1
            || intent.basis.schema != BASIS_SCHEMA_V1
            || intent.carrier.schema != CARRIER_SCHEMA_V1
        {
            return Err("unsupported NQ continuity acquisition schema".into());
        }
        if self.phases
            != [
                ContinuityAcquisitionPhaseV1::ProviderInvocationStarted,
                ContinuityAcquisitionPhaseV1::ProviderIntakeCompleted,
            ]
        {
            return Err("NQ continuity acquisition lacks the exact completed phase chain".into());
        }
        for (name, value) in [
            ("intent_id", intent.intent_id.as_str()),
            ("acquisition_id", intent.basis.acquisition_id.as_str()),
            (
                "watcher_instance_id",
                intent.basis.watcher_instance_id.as_str(),
            ),
            ("intake_id", intent.intake_id.as_str()),
            ("attempt_id", intent.attempt_id.as_str()),
            ("run_id", intent.run_id.as_str()),
            ("origin_carrier", intent.origin_carrier.as_str()),
        ] {
            require_token(name, value)?;
        }
        require_prefixed_digest("intent_digest", &self.intent_digest)?;
        require_prefixed_digest("intent_id", &intent.intent_id)?;
        require_hex_digest("basis_digest", &intent.basis_digest)?;
        require_hex_digest("watcher_config_digest", &intent.basis.watcher_config_digest)?;
        require_hex_digest("authority_digest", &intent.basis.authority_digest)?;
        require_prefixed_digest(
            "checkpoint_contract_digest",
            &intent.checkpoint_contract_digest,
        )?;
        intent.basis.edge.validate()?;
        if self.intent_digest != format!("sha256:{:x}", Sha256::digest(jcs(intent)?)) {
            return Err("NQ continuity intent digest mismatch".into());
        }
        if intent.intent_id != object_id(intent, "intent_id")? {
            return Err("NQ continuity intent identity mismatch".into());
        }
        if intent.basis_digest != format!("{:x}", Sha256::digest(jcs(&intent.basis)?)) {
            return Err("NQ continuity basis digest mismatch".into());
        }
        let request_subject = intent
            .request
            .pointer("/binding/subject")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "NQ continuity intent request lacks exact subject binding".to_owned())?;
        let request_instance = intent
            .request
            .pointer("/instance_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                "NQ continuity intent request lacks exact instance binding".to_owned()
            })?;
        if !intent.provider.is_object()
            || request_subject != intent.basis.edge.subject_ref
            || request_instance != intent.basis.watcher_instance_id
            || intent.intake_id != intent.basis.acquisition_id
        {
            return Err("NQ continuity intent substitutes its exact acquisition basis".into());
        }

        let authority = &intent.carrier.authority;
        let commitment = &intent.carrier.commitment;
        if authority.schema != SIGNED_AUTHORITY_SCHEMA_V1
            || authority.payload.schema != AUTHORITY_SCHEMA_V1
            || commitment.schema != SIGNED_COMMITMENT_SCHEMA_V1
            || commitment.payload.schema != COMMITMENT_SCHEMA_V1
        {
            return Err("unsupported Standing continuity envelope schema".into());
        }
        require_token("authority key_id", &authority.key_id)?;
        require_token("commitment key_id", &commitment.key_id)?;
        require_hex_digest("authority payload_digest", &authority.payload_digest)?;
        require_hex_digest("commitment payload_digest", &commitment.payload_digest)?;
        require_signature_hex("authority signature", &authority.signature)?;
        require_signature_hex("commitment signature", &commitment.signature)?;
        if authority.payload_digest != format!("{:x}", Sha256::digest(jcs(&authority.payload)?))
            || commitment.payload_digest
                != format!("{:x}", Sha256::digest(jcs(&commitment.payload)?))
        {
            return Err("Standing continuity payload digest mismatch".into());
        }
        let authority_payload = &authority.payload;
        authority_payload.edge.validate()?;
        require_hex_digest(
            "authority standing_instance",
            &authority_payload.standing_instance,
        )?;
        require_hex_digest(
            "authority standing_basis_digest",
            &authority_payload.standing_basis_digest,
        )?;
        require_token("authority nq_audience", &authority_payload.nq_audience)?;
        require_token(
            "authority issuer_principal",
            &authority_payload.issuer_principal,
        )?;
        require_token(
            "authority replay_identity",
            &authority_payload.replay_identity,
        )?;
        if authority_payload.nonclaims != authority_nonclaims() {
            return Err("Standing authority nonclaims differ from the closed v1 set".into());
        }
        let commitment_payload = &commitment.payload;
        require_hex_digest(
            "commitment authority_payload_digest",
            &commitment_payload.authority_payload_digest,
        )?;
        require_hex_digest(
            "commitment acquisition_basis_digest",
            &commitment_payload.acquisition_basis_digest,
        )?;
        require_hex_digest(
            "commitment standing_instance",
            &commitment_payload.standing_instance,
        )?;
        require_token(
            "commitment acquisition_id",
            &commitment_payload.acquisition_id,
        )?;
        require_token("commitment nq_audience", &commitment_payload.nq_audience)?;
        require_token(
            "commitment replay_identity",
            &commitment_payload.replay_identity,
        )?;
        if commitment_payload.nonclaims != commitment_nonclaims() {
            return Err("Standing commitment nonclaims differ from the closed v1 set".into());
        }
        if authority.key_id != commitment.key_id
            || commitment_payload.authority_occurrence_ref
                != authority_payload.authority_occurrence_ref
            || commitment_payload.authority_payload_digest != authority.payload_digest
            || commitment_payload.nq_audience != authority_payload.nq_audience
            || commitment_payload.standing_instance != authority_payload.standing_instance
            || commitment_payload.acquisition_id != intent.basis.acquisition_id
            || commitment_payload.acquisition_basis_digest != intent.basis_digest
            || intent.basis.authority_occurrence_ref
                != authority_payload.authority_occurrence_ref.to_string()
            || intent.basis.authority_digest != authority.payload_digest
            || intent.basis.edge != authority_payload.edge
            || intent.basis.nq_audience != authority_payload.nq_audience
        {
            return Err("Standing commitment does not bind the exact continuity authority".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuityApplicabilityStatusV1 {
    Applicable,
    Refused,
    Unresolved,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuityApplicabilityReasonV1 {
    ExactAuthenticatedPrerequisite,
    SubjectMismatch,
    IntakeMismatch,
    EdgeMismatch,
    AcquisitionBindingMismatch,
    ObservationSubstrateAbsent,
    ObservationSubstrateMismatch,
}

/// Nightshift's narrow, content-identified consumer verdict. This is neither
/// Standing authority nor Nightshift currentness.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityApplicabilityV1 {
    pub schema: String,
    pub applicability_id: String,
    pub status: ContinuityApplicabilityStatusV1,
    pub reason: ContinuityApplicabilityReasonV1,
    pub diagnostic_artifact_id: String,
    pub subject_ref: String,
    pub relation: ContinuityRelationV1,
    pub predecessor_ref: String,
    pub successor_ref: String,
    pub authority_occurrence_ref: Uuid,
    pub commitment_occurrence_ref: Uuid,
    pub acquisition_id: String,
    pub provider_intake_ref: String,
}

impl ContinuityApplicabilityV1 {
    fn new(
        proof: &ContinuityAcquisitionProofV1,
        diagnostic_artifact_id: &str,
        provider_intake_ref: &str,
        status: ContinuityApplicabilityStatusV1,
        reason: ContinuityApplicabilityReasonV1,
    ) -> Result<Self, String> {
        let edge = &proof.intent.carrier.authority.payload.edge;
        let mut result = Self {
            schema: APPLICABILITY_SCHEMA_V1.into(),
            applicability_id: String::new(),
            status,
            reason,
            diagnostic_artifact_id: diagnostic_artifact_id.into(),
            subject_ref: edge.subject_ref.clone(),
            relation: edge.relation,
            predecessor_ref: edge.predecessor_ref.clone(),
            successor_ref: edge.successor_ref.clone(),
            authority_occurrence_ref: proof
                .intent
                .carrier
                .authority
                .payload
                .authority_occurrence_ref,
            commitment_occurrence_ref: proof
                .intent
                .carrier
                .commitment
                .payload
                .commitment_occurrence_ref,
            acquisition_id: proof.intent.basis.acquisition_id.clone(),
            provider_intake_ref: provider_intake_ref.into(),
        };
        result.applicability_id = object_id(&result, "applicability_id")?;
        result.validate()?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != APPLICABILITY_SCHEMA_V1 {
            return Err("unsupported continuity applicability schema".into());
        }
        require_prefixed_digest("applicability_id", &self.applicability_id)?;
        require_prefixed_digest("diagnostic_artifact_id", &self.diagnostic_artifact_id)?;
        require_token("continuity subject_ref", &self.subject_ref)?;
        require_token("continuity predecessor_ref", &self.predecessor_ref)?;
        require_token("continuity successor_ref", &self.successor_ref)?;
        require_token("continuity acquisition_id", &self.acquisition_id)?;
        require_token("continuity provider_intake_ref", &self.provider_intake_ref)?;
        if self.applicability_id != object_id(self, "applicability_id")? {
            return Err("continuity applicability identity mismatch".into());
        }
        Ok(())
    }
}

/// Verification-only public material. This type has no signing constructor.
#[derive(Clone, Debug)]
pub struct ContinuityAuthorityVerifierV1 {
    expected_key_id: String,
    expected_nq_audience: String,
    key: VerifyingKey,
}

impl ContinuityAuthorityVerifierV1 {
    pub fn from_public_key_hex(
        expected_key_id: String,
        expected_nq_audience: String,
        public_key_hex: &str,
    ) -> Result<Self, String> {
        require_token("Standing continuity key id", &expected_key_id)?;
        require_token("Standing continuity NQ audience", &expected_nq_audience)?;
        let bytes = hex::decode(public_key_hex.trim())
            .map_err(|_| "Standing continuity public key is not hexadecimal".to_owned())?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "Standing continuity public key is not 32 bytes".to_owned())?;
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| "Standing continuity public key is invalid".to_owned())?;
        Ok(Self {
            expected_key_id,
            expected_nq_audience,
            key,
        })
    }

    pub fn from_public_key_file(
        expected_key_id: String,
        expected_nq_audience: String,
        path: &Path,
    ) -> Result<Self, String> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let file = options
            .open(path)
            .map_err(|error| format!("open Standing continuity public key: {error}"))?;
        let metadata = file
            .metadata()
            .map_err(|error| format!("inspect Standing continuity public key: {error}"))?;
        if !metadata.is_file() || metadata.len() > MAX_PUBLIC_KEY_BYTES {
            return Err("Standing continuity public key must be a bounded regular file".into());
        }
        let mut bytes = Vec::new();
        file.take(MAX_PUBLIC_KEY_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("read Standing continuity public key: {error}"))?;
        if bytes.len() as u64 > MAX_PUBLIC_KEY_BYTES {
            return Err("Standing continuity public key exceeds size bound".into());
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| "Standing continuity public key is not UTF-8".to_owned())?;
        Self::from_public_key_hex(expected_key_id, expected_nq_audience, text)
    }

    /// Verify the exact authenticated prerequisite chain and return a narrow
    /// attribution result. Asserted times are deliberately not compared.
    pub fn evaluate(
        &self,
        proof: &ContinuityAcquisitionProofV1,
        diagnostic_artifact_id: &str,
        diagnostic_subject_ref: &str,
        diagnostic_provider_intake_ref: &str,
        independently_established_predecessor_ref: Option<&str>,
        independently_established_observation_substrate_ref: Option<&str>,
    ) -> Result<ContinuityApplicabilityV1, String> {
        self.verify_proof(proof)?;
        let authority = &proof.intent.carrier.authority.payload;
        let commitment = &proof.intent.carrier.commitment.payload;
        let refused = |reason| {
            ContinuityApplicabilityV1::new(
                proof,
                diagnostic_artifact_id,
                diagnostic_provider_intake_ref,
                ContinuityApplicabilityStatusV1::Refused,
                reason,
            )
        };
        if authority.edge.subject_ref != diagnostic_subject_ref {
            return refused(ContinuityApplicabilityReasonV1::SubjectMismatch);
        }
        if proof.intent.intake_id != diagnostic_provider_intake_ref {
            return refused(ContinuityApplicabilityReasonV1::IntakeMismatch);
        }
        if commitment.acquisition_id != proof.intent.basis.acquisition_id
            || commitment.acquisition_basis_digest != proof.intent.basis_digest
        {
            return refused(ContinuityApplicabilityReasonV1::AcquisitionBindingMismatch);
        }
        let (Some(predecessor_ref), Some(observation_substrate_ref)) = (
            independently_established_predecessor_ref,
            independently_established_observation_substrate_ref,
        ) else {
            return ContinuityApplicabilityV1::new(
                proof,
                diagnostic_artifact_id,
                diagnostic_provider_intake_ref,
                ContinuityApplicabilityStatusV1::Unresolved,
                ContinuityApplicabilityReasonV1::ObservationSubstrateAbsent,
            );
        };
        if predecessor_ref != authority.edge.predecessor_ref {
            return refused(ContinuityApplicabilityReasonV1::EdgeMismatch);
        }
        if observation_substrate_ref != authority.edge.successor_ref {
            return refused(ContinuityApplicabilityReasonV1::ObservationSubstrateMismatch);
        }
        ContinuityApplicabilityV1::new(
            proof,
            diagnostic_artifact_id,
            diagnostic_provider_intake_ref,
            ContinuityApplicabilityStatusV1::Applicable,
            ContinuityApplicabilityReasonV1::ExactAuthenticatedPrerequisite,
        )
    }

    /// Verify a Standing carrier embedded in the substrate-origin V3
    /// acquisition basis. This is the same authenticated edge/commitment law
    /// as V2, without manufacturing the older NQ intent wrapper.
    pub(crate) fn verify_embedded_carrier(
        &self,
        carrier: &ContinuityAcquisitionCarrierV1,
        basis: &ContinuityAcquisitionBasisV1,
    ) -> Result<(), String> {
        basis.edge.validate()?;
        self.verify_authority(&carrier.authority)?;
        self.verify_commitment(&carrier.commitment)?;
        let authority = &carrier.authority.payload;
        let commitment = &carrier.commitment.payload;
        if commitment.authority_occurrence_ref != authority.authority_occurrence_ref
            || commitment.authority_payload_digest != carrier.authority.payload_digest
            || commitment.nq_audience != authority.nq_audience
            || authority.nq_audience != self.expected_nq_audience
            || commitment.standing_instance != authority.standing_instance
            || commitment.acquisition_id != basis.acquisition_id
            || commitment.acquisition_basis_digest != format!("{:x}", Sha256::digest(jcs(basis)?))
            || basis.authority_occurrence_ref != authority.authority_occurrence_ref.to_string()
            || basis.authority_digest != carrier.authority.payload_digest
            || basis.edge != authority.edge
            || basis.nq_audience != authority.nq_audience
        {
            return Err(
                "Standing carrier does not bind the exact substrate-origin acquisition basis"
                    .into(),
            );
        }
        Ok(())
    }

    fn verify_proof(&self, proof: &ContinuityAcquisitionProofV1) -> Result<(), String> {
        proof.validate_shape()?;
        let intent = &proof.intent;
        if intent.schema != INTENT_SCHEMA_V1
            || intent.basis.schema != BASIS_SCHEMA_V1
            || intent.carrier.schema != CARRIER_SCHEMA_V1
        {
            return Err("unsupported NQ continuity acquisition schema".into());
        }
        if proof.phases
            != [
                ContinuityAcquisitionPhaseV1::ProviderInvocationStarted,
                ContinuityAcquisitionPhaseV1::ProviderIntakeCompleted,
            ]
        {
            return Err("NQ continuity acquisition lacks the exact completed phase chain".into());
        }
        for (name, value) in [
            ("intent_id", intent.intent_id.as_str()),
            ("acquisition_id", intent.basis.acquisition_id.as_str()),
            (
                "watcher_instance_id",
                intent.basis.watcher_instance_id.as_str(),
            ),
            ("intake_id", intent.intake_id.as_str()),
            ("attempt_id", intent.attempt_id.as_str()),
            ("run_id", intent.run_id.as_str()),
            ("origin_carrier", intent.origin_carrier.as_str()),
        ] {
            require_token(name, value)?;
        }
        require_prefixed_digest("intent_digest", &proof.intent_digest)?;
        require_prefixed_digest("intent_id", &intent.intent_id)?;
        require_hex_digest("basis_digest", &intent.basis_digest)?;
        require_hex_digest("watcher_config_digest", &intent.basis.watcher_config_digest)?;
        require_hex_digest("authority_digest", &intent.basis.authority_digest)?;
        require_prefixed_digest(
            "checkpoint_contract_digest",
            &intent.checkpoint_contract_digest,
        )?;
        intent.basis.edge.validate()?;
        if proof.intent_digest != format!("sha256:{:x}", Sha256::digest(jcs(intent)?)) {
            return Err("NQ continuity intent digest mismatch".into());
        }
        let mut intent_preimage =
            serde_json::to_value(intent).map_err(|error| error.to_string())?;
        intent_preimage
            .as_object_mut()
            .ok_or_else(|| "NQ continuity intent is not an object".to_owned())?
            .remove("intent_id");
        if intent.intent_id != format!("sha256:{:x}", Sha256::digest(jcs(&intent_preimage)?)) {
            return Err("NQ continuity intent identity mismatch".into());
        }
        if intent.basis_digest != format!("{:x}", Sha256::digest(jcs(&intent.basis)?)) {
            return Err("NQ continuity basis digest mismatch".into());
        }
        let request_subject = intent
            .request
            .pointer("/binding/subject")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "NQ continuity intent request lacks exact subject binding".to_owned())?;
        let request_instance = intent
            .request
            .pointer("/instance_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                "NQ continuity intent request lacks exact instance binding".to_owned()
            })?;
        if !intent.provider.is_object()
            || request_subject != intent.basis.edge.subject_ref
            || request_instance != intent.basis.watcher_instance_id
            || intent.intake_id != intent.basis.acquisition_id
        {
            return Err("NQ continuity intent substitutes its exact acquisition basis".into());
        }
        self.verify_authority(&intent.carrier.authority)?;
        self.verify_commitment(&intent.carrier.commitment)?;
        let authority = &intent.carrier.authority.payload;
        let commitment = &intent.carrier.commitment.payload;
        if commitment.authority_occurrence_ref != authority.authority_occurrence_ref
            || commitment.authority_payload_digest != intent.carrier.authority.payload_digest
            || commitment.nq_audience != authority.nq_audience
            || authority.nq_audience != self.expected_nq_audience
            || commitment.standing_instance != authority.standing_instance
            || commitment.acquisition_id != intent.basis.acquisition_id
            || commitment.acquisition_basis_digest != intent.basis_digest
            || intent.basis.authority_occurrence_ref
                != authority.authority_occurrence_ref.to_string()
            || intent.basis.authority_digest != intent.carrier.authority.payload_digest
            || intent.basis.edge != authority.edge
            || intent.basis.nq_audience != authority.nq_audience
        {
            return Err("Standing commitment does not bind the exact continuity authority".into());
        }
        Ok(())
    }

    fn verify_authority(&self, envelope: &SignedContinuityAuthorityV1) -> Result<(), String> {
        if envelope.schema != SIGNED_AUTHORITY_SCHEMA_V1
            || envelope.key_id != self.expected_key_id
            || envelope.payload.schema != AUTHORITY_SCHEMA_V1
        {
            return Err("unsupported Standing continuity authority envelope".into());
        }
        let payload = &envelope.payload;
        payload.edge.validate()?;
        require_hex_digest("authority standing_instance", &payload.standing_instance)?;
        require_hex_digest(
            "authority standing_basis_digest",
            &payload.standing_basis_digest,
        )?;
        require_token("authority nq_audience", &payload.nq_audience)?;
        require_token("authority issuer_principal", &payload.issuer_principal)?;
        require_token("authority replay_identity", &payload.replay_identity)?;
        if payload.nonclaims != authority_nonclaims() {
            return Err("Standing authority nonclaims differ from the closed v1 set".into());
        }
        self.verify_signed_payload(
            &envelope.schema,
            &envelope.key_id,
            payload,
            &envelope.payload_digest,
            &envelope.signature,
        )
    }

    fn verify_commitment(
        &self,
        envelope: &SignedContinuityAcquisitionCommitmentV1,
    ) -> Result<(), String> {
        if envelope.schema != SIGNED_COMMITMENT_SCHEMA_V1
            || envelope.key_id != self.expected_key_id
            || envelope.payload.schema != COMMITMENT_SCHEMA_V1
        {
            return Err("unsupported Standing continuity commitment envelope".into());
        }
        let payload = &envelope.payload;
        require_hex_digest(
            "commitment authority_payload_digest",
            &payload.authority_payload_digest,
        )?;
        require_hex_digest(
            "commitment acquisition_basis_digest",
            &payload.acquisition_basis_digest,
        )?;
        require_hex_digest("commitment standing_instance", &payload.standing_instance)?;
        require_token("commitment acquisition_id", &payload.acquisition_id)?;
        require_token("commitment nq_audience", &payload.nq_audience)?;
        require_token("commitment replay_identity", &payload.replay_identity)?;
        if payload.nonclaims != commitment_nonclaims() {
            return Err("Standing commitment nonclaims differ from the closed v1 set".into());
        }
        self.verify_signed_payload(
            &envelope.schema,
            &envelope.key_id,
            payload,
            &envelope.payload_digest,
            &envelope.signature,
        )
    }

    fn verify_signed_payload<T: Serialize>(
        &self,
        schema: &str,
        key_id: &str,
        payload: &T,
        payload_digest: &str,
        signature_hex: &str,
    ) -> Result<(), String> {
        if key_id != self.expected_key_id {
            return Err("Standing continuity signing key id mismatch".into());
        }
        require_hex_digest("Standing continuity payload_digest", payload_digest)?;
        let canonical = jcs(payload)?;
        if payload_digest != format!("{:x}", Sha256::digest(&canonical)) {
            return Err("Standing continuity payload digest mismatch".into());
        }
        let signature = hex::decode(signature_hex)
            .map_err(|_| "Standing continuity signature is not hexadecimal".to_owned())?;
        let signature = Signature::from_slice(&signature)
            .map_err(|_| "Standing continuity signature length is invalid".to_owned())?;
        let mut signing_input = Vec::with_capacity(schema.len() + 1 + canonical.len());
        signing_input.extend_from_slice(schema.as_bytes());
        signing_input.push(0);
        signing_input.extend_from_slice(&canonical);
        self.key
            .verify(&signing_input, &signature)
            .map_err(|_| "Standing continuity Ed25519 verification failed".to_owned())
    }
}

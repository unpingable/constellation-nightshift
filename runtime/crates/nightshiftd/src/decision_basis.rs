//! `DecisionBasisV1` — the deterministic, versioned, canonical projection of
//! a Nightshift posture into the finite semantic facts AG uses for
//! workflow-precondition judgments.
//!
//! The basis is evidence content only. It carries no observation identity,
//! no subject identity, no timestamps or freshness, and no workflow policy.
//! It is not an authorization artifact, an observation-health verdict, a
//! standing verdict, or a workflow decision, and it deliberately does not
//! encode every distinction in the source posture. Adequacy of this
//! projection for a workflow decision family is certified separately
//! (decision-relative), not by injectivity over all source state.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::diagnostic_posture::{
    ConditionAxis, DeliveryStanding, OperationalPosture, SemanticIdentityV1,
};

pub const DECISION_BASIS_SCHEMA_V1: &str = "nightshift.decision-basis.v1";
pub const NORMALIZATION_RULE_ID_V1: &str = "nightshift.posture-normalization";
pub const NORMALIZATION_RULE_VERSION_V1: &str = "1";
pub const DECISION_BASIS_DIGEST_DOMAIN_V1: &[u8] = b"nightshift.decision-basis.v1\0";

pub const CONDITION_CLEAN_ATOM_V1: &str = "condition.clean";
pub const CONDITION_PRESENT_ATOM_V1: &str = "condition.condition_present";
pub const CONDITION_UNRESOLVED_ATOM_V1: &str = "condition.unresolved";
pub const DELIVERY_QUALIFIED_ATOM_V1: &str = "delivery.qualified";
pub const DELIVERY_PARTIAL_ATOM_V1: &str = "delivery.partial_delivery";
pub const DELIVERY_FAILED_ATOM_V1: &str = "delivery.failed";
pub const DELIVERY_NOT_CONFIGURED_ATOM_V1: &str = "delivery.not_configured";
pub const DELIVERY_NOT_REQUIRED_ATOM_V1: &str = "delivery.not_required";

/// The complete v1 wire vocabulary. v1 is limited to the two posture axes
/// the closed architecture makes decision-relevant: condition and delivery.
pub const ATOM_VOCABULARY_V1: [&str; 8] = [
    CONDITION_CLEAN_ATOM_V1,
    CONDITION_PRESENT_ATOM_V1,
    CONDITION_UNRESOLVED_ATOM_V1,
    DELIVERY_QUALIFIED_ATOM_V1,
    DELIVERY_PARTIAL_ATOM_V1,
    DELIVERY_FAILED_ATOM_V1,
    DELIVERY_NOT_CONFIGURED_ATOM_V1,
    DELIVERY_NOT_REQUIRED_ATOM_V1,
];

/// The frozen v1 normalization-rule identity. Its digest follows the
/// repository's semantic-identity convention: `sha256("{id}.v{version}")`.
pub fn normalization_rule_v1() -> SemanticIdentityV1 {
    SemanticIdentityV1 {
        id: NORMALIZATION_RULE_ID_V1.into(),
        version: NORMALIZATION_RULE_VERSION_V1.into(),
        digest: format!(
            "sha256:{:x}",
            Sha256::digest(
                format!("{NORMALIZATION_RULE_ID_V1}.v{NORMALIZATION_RULE_VERSION_V1}").as_bytes(),
            )
        ),
    }
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

/// The v1 decision basis. Parsing always validates: wrong schema, unsorted
/// or duplicate atoms, unknown atoms, wrong atom cardinality, and malformed
/// or non-v1 rule identity are all rejected at the wire boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "RawDecisionBasisV1")]
pub struct DecisionBasisV1 {
    pub schema: String,
    pub rule: SemanticIdentityV1,
    pub atoms: BTreeSet<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDecisionBasisV1 {
    schema: String,
    rule: SemanticIdentityV1,
    atoms: Vec<String>,
}

impl TryFrom<RawDecisionBasisV1> for DecisionBasisV1 {
    type Error = String;

    fn try_from(raw: RawDecisionBasisV1) -> Result<Self, String> {
        // Strictly ascending byte order rejects both duplicates and any
        // non-canonical ordering, so semantically equivalent but
        // structurally ambiguous wire documents cannot parse.
        if !raw.atoms.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err("decision basis atoms must be strictly sorted and unique".into());
        }
        let basis = Self {
            schema: raw.schema,
            rule: raw.rule,
            atoms: raw.atoms.into_iter().collect(),
        };
        basis.validate()?;
        Ok(basis)
    }
}

impl DecisionBasisV1 {
    /// The v1 wire invariants: exact schema, the frozen v1 rule identity,
    /// the finite v1 vocabulary, and exactly one `condition.*` plus one
    /// `delivery.*` atom.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != DECISION_BASIS_SCHEMA_V1 {
            return Err(format!("unsupported decision basis schema {}", self.schema));
        }
        let rule = normalization_rule_v1();
        if self.rule.id != rule.id {
            return Err("unknown decision-basis normalization rule identity".into());
        }
        if self.rule.version != rule.version {
            return Err("unsupported decision-basis normalization rule version".into());
        }
        require_digest("rule.digest", &self.rule.digest)?;
        if self.rule.digest != rule.digest {
            return Err("rule digest does not match the v1 normalization rule preimage".into());
        }
        if self.atoms.len() != 2 {
            return Err(
                "v1 decision basis must contain exactly one condition and one delivery atom".into(),
            );
        }
        let conditions = self
            .atoms
            .iter()
            .filter(|atom| atom.starts_with("condition."))
            .count();
        let deliveries = self
            .atoms
            .iter()
            .filter(|atom| atom.starts_with("delivery."))
            .count();
        if conditions != 1 || deliveries != 1 {
            return Err(
                "v1 decision basis must contain exactly one condition and one delivery atom".into(),
            );
        }
        for atom in &self.atoms {
            if !ATOM_VOCABULARY_V1.contains(&atom.as_str()) {
                return Err(format!("unknown v1 decision-basis atom {atom}"));
            }
        }
        Ok(())
    }

    /// RFC 8785 (JCS) canonical bytes of the exact basis document.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        serde_jcs::to_vec(self).map_err(|error| error.to_string())
    }

    /// Domain-separated digest: `SHA256("nightshift.decision-basis.v1\0" ||
    /// JCS(basis))`. Observation identity, subject identity, timestamps,
    /// freshness, and workflow identity are never part of this preimage;
    /// they remain separately bound elsewhere.
    pub fn digest(&self) -> Result<String, String> {
        let mut payload = DECISION_BASIS_DIGEST_DOMAIN_V1.to_vec();
        payload.extend(self.canonical_bytes()?);
        Ok(format!("sha256:{:x}", Sha256::digest(&payload)))
    }
}

/// Total v1 normalization: exactly one condition atom and one delivery atom,
/// exhaustively mapped from the current posture axes. Compiler
/// exhaustiveness forces an intentional new rule version if either source
/// enum gains a variant. No policy, workflow, resolver, identity, or time
/// input participates.
pub fn normalize_posture(posture: &OperationalPosture) -> DecisionBasisV1 {
    let condition = match posture.condition {
        ConditionAxis::Clean => CONDITION_CLEAN_ATOM_V1,
        ConditionAxis::ConditionPresent => CONDITION_PRESENT_ATOM_V1,
        ConditionAxis::Unresolved => CONDITION_UNRESOLVED_ATOM_V1,
    };
    let delivery = match posture.delivery {
        DeliveryStanding::Qualified => DELIVERY_QUALIFIED_ATOM_V1,
        DeliveryStanding::PartialDelivery => DELIVERY_PARTIAL_ATOM_V1,
        DeliveryStanding::Failed => DELIVERY_FAILED_ATOM_V1,
        DeliveryStanding::NotConfigured => DELIVERY_NOT_CONFIGURED_ATOM_V1,
        DeliveryStanding::NotRequired => DELIVERY_NOT_REQUIRED_ATOM_V1,
    };
    DecisionBasisV1 {
        schema: DECISION_BASIS_SCHEMA_V1.into(),
        rule: normalization_rule_v1(),
        atoms: BTreeSet::from([condition.into(), delivery.into()]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::currentness::{
        QualifiedSupportV1, SupportExpiryV1, SupportReceiverInstantV1, SupportStandingV1,
    };
    use crate::diagnostic_posture::{DiagnosticInputs, PosturePolicy, RecurrenceEvidence};
    use chrono::{DateTime, Utc};

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn example_policy_inputs_recurrence() -> (PosturePolicy, DiagnosticInputs, RecurrenceEvidence) {
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

    fn example_posture() -> OperationalPosture {
        let (policy, inputs, recurrence) = example_policy_inputs_recurrence();
        let mut support = QualifiedSupportV1 {
            schema: crate::currentness::QUALIFIED_SUPPORT_SCHEMA_V1.into(),
            support_id: String::new(),
            authority_id: "pulse-receiver-1".into(),
            query_id: digest('e'),
            observation_cycle_id: "cycle:test".into(),
            request_nonce: "support-query:test-nonce".into(),
            observation_id: digest('d'),
            diagnostic_inputs_id: inputs.inputs_id.clone(),
            subject_id: policy.subject.id.clone(),
            scope_id: policy.subject.scope.digest.clone(),
            artifact_ids: crate::currentness::delivered_artifact_ids(&inputs),
            evaluated_at: SupportReceiverInstantV1 {
                clock_id: "pulse-receiver-clock-1".into(),
                tick: 100,
            },
            expiry: Some(SupportExpiryV1 {
                clock_id: "pulse-receiver-clock-1".into(),
                tick: 101,
            }),
            standing: SupportStandingV1::Current,
            evidence_refs: vec![digest('9')],
            contradiction_refs: Vec::new(),
        };
        support.support_id = support.computed_support_id().unwrap();
        crate::diagnostic_posture::evaluate_posture_with_support(
            &policy,
            &inputs,
            &recurrence,
            DateTime::parse_from_rfc3339("2026-07-27T20:00:10Z")
                .unwrap()
                .with_timezone(&Utc),
            &support,
        )
        .unwrap()
    }

    /// Frozen nightshift.decision-basis.v1 cross-repo vector (also asserted
    /// independently in ag_ng).
    const EXPECTED_CANONICAL_JSON: &str = "{\"atoms\":[\"condition.clean\",\"delivery.not_required\"],\"rule\":{\"digest\":\"sha256:5f8bd1a497e034633d6fd465a6834a2ca8e9a4b20158322fd0a4bc36095f8e67\",\"id\":\"nightshift.posture-normalization\",\"version\":\"1\"},\"schema\":\"nightshift.decision-basis.v1\"}";
    const EXPECTED_CANONICAL_DIGEST: &str =
        "sha256:d67f86277b1604cad1916d01bcd5e01fc3a9002d4630cb8fdf5b749febf4b2c7";

    fn v1_vector_basis() -> DecisionBasisV1 {
        DecisionBasisV1 {
            schema: DECISION_BASIS_SCHEMA_V1.into(),
            rule: normalization_rule_v1(),
            atoms: BTreeSet::from([
                CONDITION_CLEAN_ATOM_V1.into(),
                DELIVERY_NOT_REQUIRED_ATOM_V1.into(),
            ]),
        }
    }

    #[test]
    fn fixed_vector_byte_pins_schema_rule_atoms_and_digest() {
        // Frozen nightshift.decision-basis.v1 cross-repo vector: the identical
        // literal JSON and digest are asserted independently in ag_ng.
        let basis = v1_vector_basis();
        assert_eq!(basis.schema, "nightshift.decision-basis.v1");
        assert_eq!(basis.rule.id, "nightshift.posture-normalization");
        assert_eq!(basis.rule.version, "1");
        let canonical = String::from_utf8(basis.canonical_bytes().unwrap()).unwrap();
        assert_eq!(canonical, EXPECTED_CANONICAL_JSON);
        assert_eq!(basis.digest().unwrap(), EXPECTED_CANONICAL_DIGEST);
        let reparsed: DecisionBasisV1 = serde_json::from_str(&canonical).unwrap();
        assert_eq!(reparsed, basis);
    }

    #[test]
    fn normalizing_example_posture_yields_the_same_vector() {
        let basis = normalize_posture(&example_posture());
        assert_eq!(basis, v1_vector_basis());
    }

    #[test]
    fn irrelevant_metadata_never_changes_the_basis() {
        let posture = example_posture();
        let baseline = normalize_posture(&posture);
        let mut renamed = posture.clone();
        renamed.posture_id = digest('f');
        renamed.evaluated_at = "2026-07-28T00:00:00.000Z".into();
        renamed.policy.generation = "generation:host-fixture-2".into();
        renamed.present_support = None;
        let varied = normalize_posture(&renamed);
        assert_eq!(baseline.atoms, varied.atoms);
        assert_eq!(
            baseline.canonical_bytes().unwrap(),
            varied.canonical_bytes().unwrap()
        );
        assert_eq!(baseline.digest().unwrap(), varied.digest().unwrap());
    }

    #[test]
    fn every_condition_variant_maps_to_exactly_one_condition_atom() {
        let cases = [
            (ConditionAxis::Clean, CONDITION_CLEAN_ATOM_V1),
            (ConditionAxis::ConditionPresent, CONDITION_PRESENT_ATOM_V1),
            (ConditionAxis::Unresolved, CONDITION_UNRESOLVED_ATOM_V1),
        ];
        for (variant, expected) in cases {
            let mut posture = example_posture();
            posture.condition = variant;
            let basis = normalize_posture(&posture);
            assert!(basis.atoms.contains(expected));
            assert_eq!(
                basis
                    .atoms
                    .iter()
                    .filter(|atom| atom.starts_with("condition."))
                    .count(),
                1
            );
            assert_eq!(
                basis
                    .atoms
                    .iter()
                    .filter(|atom| atom.starts_with("delivery."))
                    .count(),
                1
            );
        }
    }

    #[test]
    fn every_delivery_variant_maps_to_exactly_one_delivery_atom() {
        let cases = [
            (DeliveryStanding::Qualified, DELIVERY_QUALIFIED_ATOM_V1),
            (DeliveryStanding::PartialDelivery, DELIVERY_PARTIAL_ATOM_V1),
            (DeliveryStanding::Failed, DELIVERY_FAILED_ATOM_V1),
            (
                DeliveryStanding::NotConfigured,
                DELIVERY_NOT_CONFIGURED_ATOM_V1,
            ),
            (DeliveryStanding::NotRequired, DELIVERY_NOT_REQUIRED_ATOM_V1),
        ];
        for (variant, expected) in cases {
            let mut posture = example_posture();
            posture.delivery = variant;
            let basis = normalize_posture(&posture);
            assert!(basis.atoms.contains(expected));
            assert_eq!(
                basis
                    .atoms
                    .iter()
                    .filter(|atom| atom.starts_with("delivery."))
                    .count(),
                1
            );
            assert_eq!(
                basis
                    .atoms
                    .iter()
                    .filter(|atom| atom.starts_with("condition."))
                    .count(),
                1
            );
        }
    }

    #[test]
    fn rule_identity_changes_the_digest() {
        let basis = v1_vector_basis();
        let mut other_rule = normalization_rule_v1();
        other_rule.version = "2".into();
        other_rule.digest = format!(
            "sha256:{:x}",
            Sha256::digest(b"nightshift.posture-normalization.v2")
        );
        let other = DecisionBasisV1 {
            rule: other_rule,
            ..basis.clone()
        };
        assert_ne!(
            basis.canonical_bytes().unwrap(),
            other.canonical_bytes().unwrap()
        );
        assert_ne!(basis.digest().unwrap(), other.digest().unwrap());
    }

    #[test]
    fn atom_construction_order_cannot_change_canonical_form() {
        let forward: BTreeSet<String> = [CONDITION_CLEAN_ATOM_V1, DELIVERY_NOT_REQUIRED_ATOM_V1]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let reverse: BTreeSet<String> = [DELIVERY_NOT_REQUIRED_ATOM_V1, CONDITION_CLEAN_ATOM_V1]
            .into_iter()
            .map(str::to_owned)
            .collect();
        assert_eq!(forward, reverse);
        let first = DecisionBasisV1 {
            atoms: forward,
            ..v1_vector_basis()
        };
        let second = DecisionBasisV1 {
            atoms: reverse,
            ..v1_vector_basis()
        };
        assert_eq!(
            first.canonical_bytes().unwrap(),
            second.canonical_bytes().unwrap()
        );
        assert_eq!(first.digest().unwrap(), second.digest().unwrap());
    }

    fn parse_error(json: &str) -> String {
        match serde_json::from_str::<DecisionBasisV1>(json) {
            Ok(_) => panic!("invalid basis must not parse: {json}"),
            Err(error) => error.to_string(),
        }
    }

    fn vector_json_with(atoms: &str) -> String {
        format!(
            "{{\"atoms\":[{atoms}],\"rule\":{{\"digest\":\"{}\",\"id\":\"nightshift.posture-normalization\",\"version\":\"1\"}},\"schema\":\"nightshift.decision-basis.v1\"}}",
            normalization_rule_v1().digest
        )
    }

    #[test]
    fn wrong_schema_is_rejected() {
        let json = vector_json_with("\"condition.clean\",\"delivery.not_required\"").replace(
            "nightshift.decision-basis.v1",
            "nightshift.decision-basis.v0",
        );
        assert!(parse_error(&json).contains("schema"));
    }

    #[test]
    fn duplicate_atoms_are_rejected() {
        let json =
            vector_json_with("\"condition.clean\",\"condition.clean\",\"delivery.qualified\"");
        assert!(parse_error(&json).contains("sorted and unique"));
    }

    #[test]
    fn unsorted_atoms_are_rejected() {
        let json = vector_json_with("\"delivery.not_required\",\"condition.clean\"");
        assert!(parse_error(&json).contains("sorted and unique"));
    }

    #[test]
    fn missing_condition_atom_is_rejected() {
        let json = vector_json_with("\"delivery.not_required\"");
        assert!(parse_error(&json).contains("exactly one"));
    }

    #[test]
    fn multiple_condition_atoms_are_rejected() {
        let json = vector_json_with("\"condition.clean\",\"condition.unresolved\"");
        assert!(parse_error(&json).contains("exactly one"));
    }

    #[test]
    fn missing_delivery_atom_is_rejected() {
        let json = vector_json_with("\"condition.clean\"");
        assert!(parse_error(&json).contains("exactly one"));
    }

    #[test]
    fn multiple_delivery_atoms_are_rejected() {
        let json =
            vector_json_with("\"condition.clean\",\"delivery.failed\",\"delivery.qualified\"");
        assert!(parse_error(&json).contains("exactly one"));
    }

    #[test]
    fn unknown_atom_is_rejected() {
        let json =
            vector_json_with("\"condition.clean\",\"delivery.qualified\",\"support.current\"");
        assert!(parse_error(&json).contains("exactly one"));
        let json = vector_json_with("\"condition.unknown\",\"delivery.qualified\"");
        assert!(parse_error(&json).contains("unknown v1 decision-basis atom"));
    }

    #[test]
    fn malformed_rule_identity_is_rejected() {
        let malformed_digest = vector_json_with("\"condition.clean\",\"delivery.not_required\"")
            .replace(&normalization_rule_v1().digest, "sha256:not-hex");
        assert!(parse_error(&malformed_digest).contains("sha256:<64 lowercase hex>"));
        let wrong_digest = vector_json_with("\"condition.clean\",\"delivery.not_required\"")
            .replace(&normalization_rule_v1().digest, &digest('0'));
        assert!(parse_error(&wrong_digest).contains("preimage"));
        let wrong_id = vector_json_with("\"condition.clean\",\"delivery.not_required\"")
            .replace("nightshift.posture-normalization", "nightshift.other-rule");
        assert!(parse_error(&wrong_id).contains("identity"));
        let wrong_version = vector_json_with("\"condition.clean\",\"delivery.not_required\"")
            .replace("\"version\":\"1\"", "\"version\":\"2\"");
        assert!(parse_error(&wrong_version).contains("version"));
    }
}

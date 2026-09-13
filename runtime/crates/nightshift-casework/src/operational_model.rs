use nightshiftd::operational_lineage::{
    AcquisitionOutcomeV1, CannotTestifyV1, ContradictionV1, NextLawfulActionV1,
    OperationalObservationLineageV1, OperationalReobservationEvaluationV1, OperationalSubjectV1,
    ProducerPrincipalV1, RefusalV1, ReobservationDispositionV1, ReobservationProfileV1,
    ReobservationTriggerV1, SubjectKindV1,
};
use serde::{Deserialize, Serialize};
pub const CASEWORK_OPERATIONAL_CONDITION_SCHEMA_V1: &str =
    "nightshift.casework-operational-condition/v1";
pub const CASEWORK_OPERATIONAL_CONDITION_INDEX_SCHEMA_V1: &str =
    "nightshift.casework-operational-condition-index/v1";
pub const CASEWORK_OPERATIONAL_CONDITION_DIGEST_DOMAIN_V1: &[u8] =
    b"nightshift.casework-operational-condition.digest/v1\0";
pub const CASEWORK_OPERATIONAL_CONDITION_NAVIGATION_DOMAIN_V1: &[u8] =
    b"nightshift.casework-operational-condition.navigation/v1\0";
pub const CASEWORK_OPERATIONAL_QUESTION_NAVIGATION_DOMAIN_V1: &[u8] =
    b"nightshift.casework-operational-question.navigation/v1\0";
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseworkOperationalConditionV1 {
    pub schema: String,
    pub projection_digest: String,
    pub navigation_id: String,
    pub subject: OperationalSubjectV1,
    pub subject_identity_digest: String,
    pub producer: ProducerPrincipalV1,
    pub producer_identity_digest: String,
    pub acquisition_outcome: AcquisitionOutcomeV1,
    pub lineage: OperationalObservationLineageV1,
    pub evaluation: OperationalReobservationEvaluationV1,
    pub profile: ReobservationProfileV1,
    pub questions: Vec<OperationalQuestionV1>,
    pub raw_sources: OperationalRawSourcesV1,
    pub authority_effect: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalRawSourceV1 {
    pub exact_bytes_sha256: String,
    pub exact_bytes_length: u64,
    pub validation: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalRawSourcesV1 {
    pub monitor: OperationalRawSourceV1,
    pub nq: OperationalRawSourceV1,
    pub lineage: OperationalRawSourceV1,
    pub profile: OperationalRawSourceV1,
    pub evaluation: OperationalRawSourceV1,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "source_kind",
    content = "finding",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum OperationalQuestionSourceV1 {
    CannotTestify(CannotTestifyV1),
    Refusal(RefusalV1),
    Contradiction(ContradictionV1),
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalQuestionV1 {
    pub navigation_id: String,
    pub question_id: String,
    pub question: String,
    pub source_index: usize,
    pub source: OperationalQuestionSourceV1,
    pub next_lawful_action: NextLawfulActionV1,
    pub presentation_only: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseworkOperationalConditionIndexV1 {
    pub schema: String,
    pub conditions: Vec<CaseworkOperationalConditionIndexEntryV1>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseworkOperationalConditionIndexEntryV1 {
    pub navigation_id: String,
    pub projection_digest: String,
    pub lineage_id: String,
    pub evaluation_id: String,
    pub subject_kind: SubjectKindV1,
    pub subject_namespace: String,
    pub subject_identity_digest: String,
    pub disposition: ReobservationDispositionV1,
    pub reobservation_trigger: ReobservationTriggerV1,
    pub evaluated_at: String,
    pub question_count: usize,
}

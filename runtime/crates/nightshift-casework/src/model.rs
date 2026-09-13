use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const CASEWORK_RUN_SCHEMA_V1: &str = "nightshift.casework-run/v1";
pub const RUN_RECEIPTS_SCHEMA_V1: &str = "nightshift.run-receipts/v1";
pub const CASEWORK_RUN_DIGEST_DOMAIN_V1: &[u8] = b"nightshift.casework-run.digest/v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibleValueV1 {
    pub recognized_string: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RendererJoinedValueV1 {
    pub recognized_strings: Option<Vec<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibleTimestampV1 {
    pub recognized_string: Option<String>,
    pub recognized_rfc3339: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseworkRunV1 {
    pub schema: String,
    pub projection_digest: String,
    pub run_id: String,
    pub packet: PacketCaseV1,
    pub receipts: ReceiptSnapshotV1,
    pub summary: RunSummaryV1,
    pub work_items: Vec<CaseworkItemV1>,
    pub human_questions: Vec<HumanQuestionV1>,
    pub final_repository_custody: Vec<FinalCustodyV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketCaseV1 {
    pub packet_id: String,
    pub packet_digest: String,
    pub created_at: String,
    pub current_until: String,
    pub source_bytes_digest: String,
    pub integrity: String,
    pub currentness_at_receipt_snapshot: String,
    pub currentness_evaluated_at: String,
    pub currentness_now: String,
    pub repository_custody: Vec<StartingCustodyV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptSnapshotV1 {
    pub schema: String,
    pub updated_at: CompatibleTimestampV1,
    pub source_bytes_digest: String,
    pub validation: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunSummaryV1 {
    pub work_item_count: usize,
    pub state_counts: BTreeMap<String, usize>,
    pub unrecognized_state_count: usize,
    pub human_question_count: usize,
    pub packet_custody_discrepancy_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseworkItemV1 {
    pub derived_id: String,
    pub id: String,
    pub track: String,
    pub campaign: CampaignV1,
    pub predecessor_lineage: Vec<PredecessorV1>,
    pub dependencies: Vec<String>,
    pub exact_work_refs: Vec<ExactWorkRefV1>,
    pub entry_predicates: Vec<String>,
    pub allowed_mutation_surfaces: Vec<String>,
    pub forbidden_actions: Vec<String>,
    pub acceptance_tests: Vec<String>,
    pub stop_conditions: Vec<String>,
    pub expected_receipts: Vec<String>,
    pub closeout_requirements: Vec<String>,
    pub model_routing: ModelRoutingV1,
    pub outcome: WorkItemOutcomeV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignV1 {
    pub codename: String,
    pub canonical_slug: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PredecessorV1 {
    pub campaign: String,
    pub classification: String,
    pub commit: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactWorkRefV1 {
    pub contract_kind: String,
    pub contract_schema: String,
    pub repository: String,

    pub branch: String,
    pub commit: String,
    pub path: String,
    pub proposal_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRoutingV1 {
    pub class: String,
    pub reason: String,
    pub maximum_mutating_workers: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkItemOutcomeV1 {
    pub state: CompatibleValueV1,
    pub result_classification: CompatibleValueV1,
    pub repositories: RenderedRepositoriesV1,
    pub tests: RendererJoinedValueV1,
    pub evidence: RendererJoinedValueV1,
    pub live_or_production_mutations: RendererJoinedValueV1,
    pub remaining_trigger: CompatibleValueV1,
    pub next_lawful_action: CompatibleValueV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenderedRepositoriesV1 {
    pub recognized_rows: Option<Vec<ResultRepositoryV1>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultRepositoryV1 {
    pub repository: String,
    pub branch: String,
    pub head: String,
    pub push_status: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanQuestionV1 {
    pub derived_id: Option<String>,
    pub navigation_id: String,
    pub source_ordinal: usize,
    pub work_item: CompatibleValueV1,
    pub linked_work_item: Option<String>,
    pub exact_question: CompatibleValueV1,
    pub evidence_exhausted: CompatibleValueV1,
    pub safe_default: CompatibleValueV1,
    pub consequences: CompatibleValueV1,
    pub resume_point: CompatibleValueV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartingCustodyV1 {
    pub derived_id: String,
    pub repository: String,
    pub path: String,
    pub branch: String,
    pub commit: String,
    pub remote: Option<String>,
    pub remote_commit: Option<String>,
    pub worktree_clean: bool,
    pub discrepancy: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalCustodyV1 {
    pub derived_id: Option<String>,
    pub navigation_id: String,
    pub source_ordinal: usize,
    pub repository: CompatibleValueV1,
    pub branch_head: CompatibleValueV1,
    pub push_custody: CompatibleValueV1,
    pub dirty: CompatibleValueV1,
    pub live_runtime: CompatibleValueV1,
    pub secrets: CompatibleValueV1,
    pub teardown: CompatibleValueV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunIndexV1 {
    pub schema: String,
    pub runs: Vec<RunIndexEntryV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunIndexEntryV1 {
    pub run_id: String,
    pub projection_digest: String,
    pub packet_id: String,
    pub packet_digest: String,
    pub receipt_updated_at: CompatibleTimestampV1,
    pub summary: RunSummaryV1,
    pub packet_integrity: String,
    pub packet_currentness_at_receipt_snapshot: String,
    pub packet_currentness_now: String,
}

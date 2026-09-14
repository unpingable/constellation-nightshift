//! WO-9 cross-boundary integration: the real Nightshift canonical runtime and
//! store feed the real `nightshift-observation-resolver` subprocess, which
//! feeds the real AG governed loop driven through the production `ag-loopctl`
//! CLI, with the real `ag-standing-resolver` subprocess on the standing gate
//! and the real Docket/`ag-effectd` pair behind the one-use spend.
//!
//! No fixture stands in for a serialized boundary: observation and standing
//! resolutions are produced by the production binaries from real persisted
//! state, AG state transitions happen only through `ag-loopctl`, and the
//! effect happens only through Docket custody and the executor plan.
//!
//! These tests are `#[ignore]`d in the default suite because they need
//! adjacent-repository binaries (the normal workspace suite does not build
//! adjacent repositories). Run them with:
//!
//! ```sh
//! AG_LOOPCTL_BIN=/path/to/ag-loopctl \
//! AG_STANDING_RESOLVER_BIN=/path/to/ag-standing-resolver \
//! AG_DOCKET_BIN=/path/to/docket \
//! AG_EFFECTD_BIN=/path/to/ag-effectd \
//! cargo test -p nightshiftd --test ag_governed_integration -- --include-ignored
//! ```
//!
//! The always-on `condition_present_fixture_is_real_and_resealed` test needs
//! no external binary and runs in the default suite.

mod common;

use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use chrono::{DateTime, Utc};
use nightshiftd::ag_port::{
    AgLoopCtlPortV1, AgOccurrencePortV1, AgOpenModeV1, AgOpenOccurrenceRequestV1,
};
use nightshiftd::authoring_custody::{MaudeAuthoringContextHandoffV1, MaudeCustodyVerifierV1};
use nightshiftd::canonical_runtime::{
    ag_executor_plan_identity, prepare_decision_evidence_cycle_request,
    prepare_external_evidence_cycle_request, CanonicalCycleRequestV1, CanonicalRuntime,
    CanonicalRuntimeError, CycleRunOutcomeV1, PrecompiledWorkflowProposalV2,
};
use nightshiftd::canonical_store::{
    AgOccurrenceReferenceV1, AgProgramCounterV1, CanonicalStore, CanonicalStoreError,
    RecurrenceSlotV1, RecurrenceTriggerV1,
};
use nightshiftd::currentness::{
    PresentEvidencePortV1, PresentEvidenceQueryV1, QualifiedSupportV1, SupportExpiryV1,
    SupportReceiverInstantV1, SupportStandingV1,
};
use nightshiftd::decision_basis::normalize_posture;
use nightshiftd::diagnostic_posture::{
    ConditionAxis, DiagnosticInputs, PosturePolicy, RecurrenceEvidence,
};
use nightshiftd::external_evidence_composition::{
    ExternalEvidenceProfileV1, ExternalEvidencePurposeV1, ExternalEvidenceReferenceV1,
    EXTERNAL_EVIDENCE_PROFILE_SCHEMA_V1, EXTERNAL_EVIDENCE_REFERENCE_SCHEMA_V1,
};
use nightshiftd::external_observation::{
    ExternalObservationHandoffV1, ExternalObservationQueryV1, ExternalObservationVerifierV1,
    LocalComposeActionV1, LocalComposeClaimKindV1,
};
use nightshiftd::steady_state_evidence::{
    DecisionRelativeEvidenceReferenceV1, SteadyStateClaimKindV1, SteadyStateEvidenceProfileV1,
    SteadyStateEvidencePurposeV1, DECISION_EVIDENCE_REFERENCE_SCHEMA_V1,
};
use sha2::{Digest as _, Sha256};

use common::TestNqAdmissionPort;

/// The identity AG is configured to expect from the observation resolver.
const OBSERVATION_RESOLVER_ID: &str = "nightshift-observation-resolver/v1";
/// The identity AG is configured to expect from the standing resolver.
const STANDING_RESOLVER_ID: &str = "ag-standing-resolver/integration-v1";
/// The standing resolver's answer lease and AG's kernel maximum.
const STANDING_TTL_MS: u64 = 60_000;
/// The observation evidence window configured for the resolver. The checked-in
/// Nightshift specimen is evaluated at 2026-07-27 while `ag-loopctl` reads the
/// wall clock, so the deployment TTL must span the gap; the kernel's freshness
/// law (`now < fresh_until`) is still exercised exactly.
const OBSERVATION_TTL_MS: u64 = 1_000_000_000_000_000;
/// The AG subject digest compiled into every test proposal (`digest('b')`).
const SUBJECT_DIGEST: &str =
    "sha256:6262626262626262626262626262626262626262626262626262626262626262";
/// Test-only issuer credential for the Docket trust path. This is published
/// test data, not a deployment secret.
const ISSUER_PKCS8_HEX: &str = "3051020101300506032b657004220420c226c22f628685cd349518c28eff015fd216a106bb49534286dceed3202b1c0e81210028d8b71d122a31cfd39f26313275119934a021918f5d37d100ad2f27acbaf776";
const ISSUER_PUBLIC_KEY_B64URL: &str = "KNi3HRIqMc_TnyYxMnURmTSgIZGPXTfRAK0vJ6y693Y";
const ISSUER_PRINCIPAL: &str = "ag-wo9-integration";
const ISSUER_KEY_ID: &str = "key-1";

const WORK_SCHEMA: &str = "ag-effectd.docket-executor-work/v1";
const CATALOG_SCHEMA: &str = "ag.governed-loop.exact-work-catalog/v1";
const PROPOSAL_SCHEMA: &str = "ag.governed-loop.exact-work-proposal/v1";
const MANDATE_STORE_SCHEMA: &str = "ag.governed-loop.standing-mandate-store/v1";
const PLAN_SCHEMA: &str = "ag-effectd.docket-executor-plan/v1";
const MANDATE_DIGEST_DOMAIN: &str = "ag.governed-loop.standing-mandate/v1";
const CATALOG_DIGEST_DOMAIN: &str = "ag.governed-loop.exact-work-catalog/v1";
const PLAN_DIGEST_DOMAIN: &str = "ag-effectd.docket-executor-plan/v1";

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn campaign() -> String {
    digest('a')
}

fn program() -> String {
    digest('2')
}

fn occurrence_uuid(occurrence: u64) -> String {
    format!("00000000-0000-4000-8000-{occurrence:012}")
}

fn time(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .unwrap()
        .with_timezone(&Utc)
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// Canonical-JSON content digest, the nightshift-side sealing convention.
fn digest_value(value: &serde_json::Value) -> String {
    sha256_digest(&serde_jcs::to_vec(value).unwrap())
}

/// Byte-exact mirror of `ag_primitives::Digest::hash_domain`, reimplemented
/// here so cross-boundary agreement is proven rather than assumed.
fn ag_hash_domain(domain: &str, payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ag-ng\0digest\0v1\0");
    hasher.update((domain.len() as u128).to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update((payload.len() as u128).to_be_bytes());
    hasher.update(payload);
    format!("sha256:{:x}", hasher.finalize())
}

fn ag_digest_value(domain: &str, value: &serde_json::Value) -> String {
    ag_hash_domain(domain, &serde_jcs::to_vec(value).unwrap())
}

fn wall_now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn current_uid_gid() -> (u32, u32) {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let mut uid = None;
    let mut gid = None;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            uid = Some(rest.split_whitespace().next().unwrap().parse().unwrap());
        }
        if let Some(rest) = line.strip_prefix("Gid:") {
            gid = Some(rest.split_whitespace().next().unwrap().parse().unwrap());
        }
    }
    (uid.unwrap(), gid.unwrap())
}

// --- Nightshift store fixtures (real canonical runtime, real store) ---

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

/// The checked-in specimen with its one claim's condition flipped to
/// `present` in both the delivered artifact and the recurrence reference,
/// with every content-derived identity honestly resealed. Everything else —
/// times, slots, obligations, support binding — is byte-identical to the
/// clean specimen.
fn condition_present_inputs_recurrence() -> (DiagnosticInputs, RecurrenceEvidence) {
    let mut inputs_value: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/operator/examples/diagnostic-posture-v1/inputs.json"
    ))
    .unwrap();
    let artifact = &mut inputs_value["inputs"][0]["artifact"];
    artifact["claims"][0]["condition_effect"] = serde_json::json!("present");
    artifact["claims"][0]["proposition"] = serde_json::json!("host load pressure is present");
    artifact["outcome"]["condition"] = serde_json::json!("present");
    artifact["outcome"]["summary"] =
        serde_json::json!("complete current testimony places load above threshold");
    let mut preimage = artifact.clone();
    preimage.as_object_mut().unwrap().remove("artifact_id");
    let resealed = digest_value(&preimage);
    artifact["artifact_id"] = serde_json::json!(resealed);
    let mut inputs: DiagnosticInputs = serde_json::from_value(inputs_value).unwrap();
    inputs.inputs_id = inputs.computed_inputs_id().unwrap();

    let mut recurrence_value: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/operator/examples/diagnostic-posture-v1/recurrence.json"
    ))
    .unwrap();
    let reference = &mut recurrence_value["records"][0]["evidence"]["artifact"];
    reference["artifact_id"] = serde_json::json!(resealed);
    reference["claim"]["condition_effect"] = serde_json::json!("present");
    reference["claim"]["proposition"] = serde_json::json!("host load pressure is present");
    let mut recurrence: RecurrenceEvidence = serde_json::from_value(recurrence_value).unwrap();
    recurrence.recurrence_id = recurrence.computed_recurrence_id().unwrap();
    (inputs, recurrence)
}

/// A second independently sealed clean execution for diagnostic occurrence 1.
/// The new AG occurrence is therefore driven by genuinely fresh source and
/// recurrence evidence, not by relabelling the first observation.
fn next_clean_inputs_recurrence() -> (DiagnosticInputs, RecurrenceEvidence) {
    let mut inputs_value: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/operator/examples/diagnostic-posture-v1/inputs.json"
    ))
    .unwrap();
    let artifact = &mut inputs_value["inputs"][0]["artifact"];
    artifact["request_id"] = serde_json::json!("request:002");
    artifact["run_id"] = serde_json::json!("run:002");
    artifact["started_at"] = serde_json::json!("2026-07-27T20:01:03Z");
    artifact["completed_at"] = serde_json::json!("2026-07-27T20:01:04Z");
    artifact["attempt_interval"]["started_at"] = serde_json::json!("2026-07-27T20:01:03Z");
    artifact["attempt_interval"]["ended_at"] = serde_json::json!("2026-07-27T20:01:04Z");
    artifact["inputs"]["received"][0]["acquisition"]["started_at"] =
        serde_json::json!("2026-07-27T20:01:01Z");
    artifact["inputs"]["received"][0]["acquisition"]["ended_at"] =
        serde_json::json!("2026-07-27T20:01:02Z");
    artifact["inputs"]["received"][0]["received_at"] = serde_json::json!("2026-07-27T20:01:03Z");
    let mut artifact_preimage = artifact.clone();
    artifact_preimage
        .as_object_mut()
        .unwrap()
        .remove("artifact_id");
    let artifact_id = digest_value(&artifact_preimage);
    artifact["artifact_id"] = serde_json::json!(artifact_id);
    let artifact_snapshot = artifact.clone();
    let mut inputs: DiagnosticInputs = serde_json::from_value(inputs_value).unwrap();
    inputs.inputs_id = inputs.computed_inputs_id().unwrap();

    let mut recurrence_value: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/operator/examples/diagnostic-posture-v1/recurrence.json"
    ))
    .unwrap();
    let base: RecurrenceEvidence = serde_json::from_value(recurrence_value.clone()).unwrap();
    let slot = nightshiftd::diagnostic_posture::make_run_slot(
        &base.records[0].policy,
        &base.records[0].key,
        1,
    )
    .unwrap();
    recurrence_value["records"][0]["slot"] = serde_json::to_value(&slot).unwrap();
    let evidence = &mut recurrence_value["records"][0]["evidence"];
    evidence["attempt"]["attempt_id"] = serde_json::json!("attempt:fixture-2");
    evidence["attempt"]["request_id"] = serde_json::json!("request:002");
    evidence["attempt"]["slot_id"] = serde_json::json!(slot.slot_id);
    evidence["attempt"]["started_at"] = serde_json::json!("2026-07-27T20:01:00Z");
    evidence["completed_at"] = serde_json::json!("2026-07-27T20:01:04Z");
    let reference = &mut evidence["artifact"];
    reference["artifact_id"] = artifact_snapshot["artifact_id"].clone();
    reference["request_id"] = artifact_snapshot["request_id"].clone();
    reference["run_id"] = artifact_snapshot["run_id"].clone();
    reference["attempt_interval"] = artifact_snapshot["attempt_interval"].clone();
    reference["dependency_acquisitions"] =
        serde_json::json!([artifact_snapshot["inputs"]["received"][0]["acquisition"].clone()]);
    reference["claim"] = artifact_snapshot["claims"][0].clone();
    let mut recurrence: RecurrenceEvidence = serde_json::from_value(recurrence_value).unwrap();
    recurrence.recurrence_id = recurrence.computed_recurrence_id().unwrap();
    inputs.validate().unwrap();
    recurrence.validate().unwrap();
    (inputs, recurrence)
}

/// Fresh deterministic diagnostic evidence for the real wall-clock synthetic
/// feedback run. The schedule's first due time is shared by both calls, so
/// the two cycles remain one exact Nightshift lineage.
fn fresh_policy_inputs_recurrence(
    first_due: DateTime<Utc>,
    occurrence: u64,
    completed_at: DateTime<Utc>,
) -> (PosturePolicy, DiagnosticInputs, RecurrenceEvidence) {
    let canonical_time =
        |value: DateTime<Utc>| value.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true);
    let first_due_text = canonical_time(first_due);
    let policy_value: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/operator/examples/diagnostic-posture-v1/policy.json"
    ))
    .unwrap();
    let mut policy: PosturePolicy = serde_json::from_value(policy_value).unwrap();
    policy.policy_id = policy.computed_policy_id().unwrap();

    let started_at = completed_at - chrono::Duration::seconds(1);
    let acquired_at = completed_at - chrono::Duration::seconds(3);
    let acquired_end = completed_at - chrono::Duration::seconds(2);
    let request_id = format!("request:synthetic-feedback-{occurrence}");
    let run_id = format!("run:synthetic-feedback-{occurrence}");
    let attempt_id = format!("attempt:synthetic-feedback-{occurrence}");
    let mut inputs_value: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/operator/examples/diagnostic-posture-v1/inputs.json"
    ))
    .unwrap();
    let artifact = &mut inputs_value["inputs"][0]["artifact"];
    artifact["request_id"] = serde_json::json!(request_id);
    artifact["run_id"] = serde_json::json!(run_id);
    artifact["started_at"] = serde_json::json!(canonical_time(started_at));
    artifact["completed_at"] = serde_json::json!(canonical_time(completed_at));
    artifact["attempt_interval"]["started_at"] = serde_json::json!(canonical_time(started_at));
    artifact["attempt_interval"]["ended_at"] = serde_json::json!(canonical_time(completed_at));
    artifact["inputs"]["received"][0]["acquisition"]["started_at"] =
        serde_json::json!(canonical_time(acquired_at));
    artifact["inputs"]["received"][0]["acquisition"]["ended_at"] =
        serde_json::json!(canonical_time(acquired_end));
    artifact["inputs"]["received"][0]["received_at"] =
        serde_json::json!(canonical_time(started_at));
    let mut artifact_preimage = artifact.clone();
    artifact_preimage
        .as_object_mut()
        .unwrap()
        .remove("artifact_id");
    let artifact_id = digest_value(&artifact_preimage);
    artifact["artifact_id"] = serde_json::json!(artifact_id);
    let artifact_snapshot = artifact.clone();
    let mut inputs: DiagnosticInputs = serde_json::from_value(inputs_value).unwrap();
    inputs.inputs_id = inputs.computed_inputs_id().unwrap();

    let mut recurrence_value: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/operator/examples/diagnostic-posture-v1/recurrence.json"
    ))
    .unwrap();
    recurrence_value["obligations"][0]["policy"]["first_due_at"] =
        serde_json::json!(first_due_text);
    recurrence_value["records"][0]["policy"] = recurrence_value["obligations"][0]["policy"].clone();
    let schedule_policy: nightshiftd::diagnostic_posture::SchedulePolicy =
        serde_json::from_value(recurrence_value["records"][0]["policy"].clone()).unwrap();
    let key: nightshiftd::diagnostic_posture::DiagnosticKey =
        serde_json::from_value(recurrence_value["records"][0]["key"].clone()).unwrap();
    let slot =
        nightshiftd::diagnostic_posture::make_run_slot(&schedule_policy, &key, occurrence).unwrap();
    recurrence_value["records"][0]["slot"] = serde_json::to_value(&slot).unwrap();
    let evidence = &mut recurrence_value["records"][0]["evidence"];
    evidence["attempt"]["attempt_id"] = serde_json::json!(attempt_id);
    evidence["attempt"]["request_id"] = artifact_snapshot["request_id"].clone();
    evidence["attempt"]["slot_id"] = serde_json::json!(slot.slot_id);
    evidence["attempt"]["started_at"] = serde_json::json!(canonical_time(started_at));
    evidence["completed_at"] = serde_json::json!(canonical_time(completed_at));
    let reference = &mut evidence["artifact"];
    reference["artifact_id"] = artifact_snapshot["artifact_id"].clone();
    reference["request_id"] = artifact_snapshot["request_id"].clone();
    reference["run_id"] = artifact_snapshot["run_id"].clone();
    reference["attempt_interval"] = artifact_snapshot["attempt_interval"].clone();
    reference["dependency_acquisitions"] =
        serde_json::json!([artifact_snapshot["inputs"]["received"][0]["acquisition"].clone()]);
    reference["claim"] = artifact_snapshot["claims"][0].clone();
    let mut recurrence: RecurrenceEvidence = serde_json::from_value(recurrence_value).unwrap();
    recurrence.recurrence_id = recurrence.computed_recurrence_id().unwrap();
    policy.validate().unwrap();
    inputs.validate().unwrap();
    recurrence.validate().unwrap();
    (policy, inputs, recurrence)
}

fn scheduled_occurrence_at(
    first_due: DateTime<Utc>,
    evaluated_at: DateTime<Utc>,
    cadence_seconds: u64,
) -> u64 {
    assert!(evaluated_at >= first_due);
    let elapsed_ms = (evaluated_at - first_due).num_milliseconds();
    let cadence_ms = i64::try_from(cadence_seconds).unwrap() * 1_000;
    u64::try_from(elapsed_ms / cadence_ms).unwrap()
}

fn next_unused_scheduled_occurrence(
    store: &CanonicalStore,
    first_due: DateTime<Utc>,
    cadence_seconds: u64,
) -> (u64, DateTime<Utc>) {
    let last_persisted = store
        .list_cycles()
        .unwrap()
        .into_iter()
        .map(|cycle| cycle.slot.occurrence)
        .max();
    loop {
        let evaluated_at = Utc::now() + chrono::Duration::milliseconds(20);
        let wall_clock_occurrence =
            scheduled_occurrence_at(first_due, evaluated_at, cadence_seconds);
        if last_persisted.is_none_or(|persisted| wall_clock_occurrence > persisted) {
            return (wall_clock_occurrence, evaluated_at);
        }
        let next_occurrence = last_persisted.unwrap() + 1;
        let next_due = first_due
            + chrono::Duration::seconds(i64::try_from(next_occurrence * cadence_seconds).unwrap());
        // The retained diagnostic completion starts two seconds before the
        // evaluation instant. Enter the new slot far enough past its exact
        // due boundary that the whole retained attempt remains in-slot.
        let wait_ms = (next_due - Utc::now()).num_milliseconds().max(0) + 2_025;
        std::thread::sleep(std::time::Duration::from_millis(
            u64::try_from(wait_ms).unwrap(),
        ));
    }
}

struct SupportPort;

impl PresentEvidencePortV1 for SupportPort {
    fn resolve(&mut self, query: &PresentEvidenceQueryV1) -> Result<QualifiedSupportV1, String> {
        let mut support = QualifiedSupportV1 {
            schema: nightshiftd::currentness::QUALIFIED_SUPPORT_SCHEMA_V1.into(),
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
        support.support_id = support.computed_support_id()?;
        support.validate_for(query)?;
        Ok(support)
    }
}

struct FakeAg;

impl AgOccurrencePortV1 for FakeAg {
    fn open_occurrence(
        &mut self,
        request: &AgOpenOccurrenceRequestV1,
    ) -> Result<AgOccurrenceReferenceV1, String> {
        let exact_snapshot = serde_json::json!({
            "campaign": request.campaign_id,
            "occurrence": request.occurrence_id,
            "program_counter": AgProgramCounterV1::ProposalRecorded,
        });
        Ok(AgOccurrenceReferenceV1 {
            schema: nightshiftd::canonical_store::AG_REFERENCE_SCHEMA_V1.into(),
            campaign_id: request.campaign_id.clone(),
            occurrence_id: request.occurrence_id.clone(),
            state_digest: digest('7'),
            snapshot_digest: digest_value(&exact_snapshot),
            program_counter: AgProgramCounterV1::ProposalRecorded,
            docket_attempt_id: None,
            settlement_id: None,
            external_decision_request_id: None,
            exact_snapshot,
        })
    }

    fn status(&mut self, _: &str, _: &str) -> Result<AgOccurrenceReferenceV1, String> {
        Err("integration tests never sync AG status".into())
    }
}

/// One sealed canonical cycle request. `with_proposal` attaches the
/// precompiled workflow proposal, which makes the runtime persist the typed
/// intent binding the Nightshift subject to `SUBJECT_DIGEST` and open the AG
/// occurrence through the port.
fn cycle_request(
    policy: &PosturePolicy,
    inputs: &DiagnosticInputs,
    recurrence: &RecurrenceEvidence,
    occurrence: u64,
    observation_id: &str,
    with_proposal: bool,
    plan: &serde_json::Value,
) -> CanonicalCycleRequestV1 {
    let slot = RecurrenceSlotV1::new(
        policy.policy_id.clone(),
        "config-v1".into(),
        policy.subject.id.clone(),
        policy.subject.scope.digest.clone(),
        "nightshift-scheduler-1".into(),
        time("2026-07-27T20:00:00Z") + chrono::Duration::minutes(occurrence as i64),
        time("2026-07-27T20:00:30Z") + chrono::Duration::minutes(occurrence as i64),
        occurrence,
        RecurrenceTriggerV1::Scheduled,
        None,
    )
    .unwrap();
    let immutable_parameters = serde_json::json!({"resource_id":"resource-1"});
    CanonicalCycleRequestV1 {
        schema: String::new(),
        request_id: String::new(),
        slot,
        scheduler_clock_id: "nightshift-scheduler-1".into(),
        evaluated_at: time("2026-07-27T20:00:10Z")
            + chrono::Duration::minutes(occurrence as i64),
        observation_id: observation_id.into(),
        policy: policy.clone(),
        inputs: inputs.clone(),
        recurrence: recurrence.clone(),
        external_evidence: None,
        decision_external_evidence: None,
        temporal_policy: None,
        proposal: with_proposal.then(|| {
            let expected_ag_work = ag_executor_plan_identity(plan).unwrap();
            PrecompiledWorkflowProposalV2 {
                schema: nightshiftd::canonical_runtime::PRECOMPILED_PROPOSAL_SCHEMA_V2.into(),
                workflow_id: "workflow:host-care".into(),
                intent_kind: "inspect_exact_resource".into(),
                subject_digest: SUBJECT_DIGEST.into(),
                immutable_parameters,
                ag_executor_plan: plan.clone(),
                campaign_id: campaign(),
                occurrence_id: occurrence_uuid(0),
                mode: AgOpenModeV1::Genesis {
                    genesis: serde_json::json!({
                        "campaign": campaign(),
                        "occurrence": occurrence_uuid(0),
                        "program": program(),
                        "expected_ag_work": expected_ag_work,
                        "residuals": [],
                        "budget": {"retry_limit":1,"retries_used":0,"probe_limit":1,"probes_used":0,"escalation_limit":1,"escalations_used":0}
                    }),
                },
                proposal_input: serde_json::json!({
                    "observation": observation_id,
                    "proposal": {
                        "schema": PROPOSAL_SCHEMA,
                        "campaign": campaign(),
                        "subject": SUBJECT_DIGEST,
                        "scope": policy.subject.scope.digest,
                        "work_schema": WORK_SCHEMA,
                        "work": expected_ag_work,
                        "repair": null
                    },
                    "class":"initial"
                }),
            }
        }),
        authoring_context: None,
        reviewed_plan_binding: None,
    }
    .seal()
    .unwrap()
}

fn successor_cycle_request(
    policy: &PosturePolicy,
    inputs: &DiagnosticInputs,
    recurrence: &RecurrenceEvidence,
    occurrence: u64,
    observation_id: &str,
    plan: &serde_json::Value,
) -> CanonicalCycleRequestV1 {
    let mut request = cycle_request(
        policy,
        inputs,
        recurrence,
        occurrence,
        observation_id,
        true,
        plan,
    );
    request.schema.clear();
    request.request_id.clear();
    let proposal = request.proposal.as_mut().unwrap();
    let occurrence_id = occurrence_uuid(occurrence);
    let expected_ag_work = ag_executor_plan_identity(plan).unwrap();
    proposal.occurrence_id.clone_from(&occurrence_id);
    proposal.mode = AgOpenModeV1::Continuation {
        continuation: serde_json::json!({
            "occurrence": occurrence_id,
            "expected_ag_work": expected_ag_work,
        }),
    };
    proposal.proposal_input["class"] = serde_json::Value::String("successor".into());
    request.seal().unwrap()
}

fn run_cycle(store: &mut CanonicalStore, request: CanonicalCycleRequestV1) -> CycleRunOutcomeV1 {
    let mut support = SupportPort;
    let mut ag = FakeAg;
    CanonicalRuntime::new(store, TestNqAdmissionPort, &mut support, &mut ag)
        .run_cycle(request)
        .unwrap()
}

// --- AG-side document builders ---

fn genesis_json(expected_ag_work: &str) -> serde_json::Value {
    serde_json::json!({
        "campaign": campaign(),
        "occurrence": occurrence_uuid(0),
        "program": program(),
        "expected_ag_work": expected_ag_work,
        "residuals": [],
        "budget": {"retry_limit":1,"retries_used":0,"probe_limit":1,"probes_used":0,"escalation_limit":1,"escalations_used":0}
    })
}

fn proposal_input_json(observation_id: &str, scope: &str, work: &str) -> serde_json::Value {
    proposal_input_json_for(WORK_SCHEMA, SUBJECT_DIGEST, observation_id, scope, work)
}

fn proposal_input_json_for(
    work_schema: &str,
    subject: &str,
    observation_id: &str,
    scope: &str,
    work: &str,
) -> serde_json::Value {
    serde_json::json!({
        "observation": observation_id,
        "proposal": {
            "schema": PROPOSAL_SCHEMA,
            "campaign": campaign(),
            "subject": subject,
            "scope": scope,
            "work_schema": work_schema,
            "work": work,
            "repair": null
        },
        "class": "initial"
    })
}

fn catalog_json(scope: &str, required: &[&str]) -> serde_json::Value {
    catalog_json_for(WORK_SCHEMA, SUBJECT_DIGEST, scope, required)
}

fn catalog_json_for(
    work_schema: &str,
    subject: &str,
    scope: &str,
    required: &[&str],
) -> serde_json::Value {
    serde_json::json!({
        "schema": CATALOG_SCHEMA,
        "entries": {
            (work_schema): {
                "work_schema": work_schema,
                "subject": subject,
                "scope": scope,
                "precondition": {"required": required, "forbidden": []}
            }
        }
    })
}

fn mandate_json(scope: &str, generation: u64, status: &str, valid_until: u64) -> serde_json::Value {
    mandate_json_for(SUBJECT_DIGEST, scope, generation, status, valid_until)
}

fn mandate_json_for(
    subject: &str,
    scope: &str,
    generation: u64,
    status: &str,
    valid_until: u64,
) -> serde_json::Value {
    serde_json::json!({
        "subject": subject,
        "scope": scope,
        "generation": generation,
        "status": status,
        "valid_until_unix_ms": valid_until
    })
}

fn mandate_store_json(mut mandates: Vec<serde_json::Value>) -> serde_json::Value {
    mandates.sort_by_key(|mandate| mandate["generation"].as_u64().unwrap());
    serde_json::json!({
        "schema": MANDATE_STORE_SCHEMA,
        "mandates": mandates
    })
}

/// The content-derived mandate identity, recomputed from the mandate document
/// with the byte-exact mirror of AG's digest construction.
fn mandate_ref(mandate: &serde_json::Value) -> String {
    ag_digest_value(MANDATE_DIGEST_DOMAIN, mandate)
}

fn write_jcs(path: &Path, value: &serde_json::Value) {
    std::fs::write(path, serde_jcs::to_vec(value).unwrap()).unwrap();
}

fn write_jcs_convergent(path: &Path, value: &serde_json::Value) {
    let bytes = serde_jcs::to_vec(value).unwrap();
    if path.exists() {
        assert_eq!(
            std::fs::read(path).unwrap(),
            bytes,
            "exact replay substituted {}",
            path.display()
        );
    } else {
        std::fs::write(path, bytes).unwrap();
    }
}

fn write_wrapper(path: &Path, body: &str) {
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

// --- External binaries ---

struct Bins {
    loopctl: PathBuf,
    standing_resolver: PathBuf,
    docket: PathBuf,
    effectd: PathBuf,
}

fn bins() -> Bins {
    let bins = Bins {
        loopctl: PathBuf::from(std::env::var_os("AG_LOOPCTL_BIN").expect("AG_LOOPCTL_BIN")),
        standing_resolver: PathBuf::from(
            std::env::var_os("AG_STANDING_RESOLVER_BIN").expect("AG_STANDING_RESOLVER_BIN"),
        ),
        docket: PathBuf::from(std::env::var_os("AG_DOCKET_BIN").expect("AG_DOCKET_BIN")),
        effectd: PathBuf::from(std::env::var_os("AG_EFFECTD_BIN").expect("AG_EFFECTD_BIN")),
    };
    assert!(bins.loopctl.is_absolute());
    assert!(bins.standing_resolver.is_absolute());
    assert!(bins.docket.is_absolute());
    assert!(bins.effectd.is_absolute());
    bins
}

fn observation_wrapper(root: &Path, ns_store: &Path) -> PathBuf {
    let wrapper = root.join("observation-resolver.sh");
    write_wrapper(
        &wrapper,
        &format!(
            "#!/bin/sh\nexec \"{}\" --store \"{}\" --resolver-id \"{}\" --default-ttl-ms {}\n",
            env!("CARGO_BIN_EXE_nightshift-observation-resolver"),
            ns_store.display(),
            OBSERVATION_RESOLVER_ID,
            OBSERVATION_TTL_MS,
        ),
    );
    wrapper
}

fn standing_wrapper(bins: &Bins, root: &Path, mandate_store: &Path) -> PathBuf {
    let wrapper = root.join("standing-resolver.sh");
    write_wrapper(
        &wrapper,
        &format!(
            "#!/bin/sh\nexec \"{}\" --mandate-store \"{}\" --resolver-id \"{}\" --answer-ttl-ms {}\n",
            bins.standing_resolver.display(),
            mandate_store.display(),
            STANDING_RESOLVER_ID,
            STANDING_TTL_MS,
        ),
    );
    wrapper
}

/// One direct probe of the real standing-resolver binary, used to derive
/// expected provenance from the production component rather than from test
/// constants.
fn probe_standing_mandate_ref(
    bins: &Bins,
    mandate_store: &Path,
    scope: &str,
    proposal_ref: &str,
) -> String {
    let request = serde_json::json!({
        "schema": "ag.governed-loop.standing-request/v1",
        "key": {"campaign": campaign(), "occurrence": occurrence_uuid(0)},
        "observation": digest('d'),
        "proposal": proposal_ref,
        "subject": SUBJECT_DIGEST,
        "scope": scope,
        "now_unix_ms": wall_now_ms()
    });
    let mut child = Command::new(&bins.standing_resolver)
        .arg("--mandate-store")
        .arg(mandate_store)
        .arg("--resolver-id")
        .arg(STANDING_RESOLVER_ID)
        .arg("--answer-ttl-ms")
        .arg(STANDING_TTL_MS.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(&request).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "standing probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    body["mandate"].as_str().unwrap().to_owned()
}

fn loopctl(bins: &Bins, args: &[String]) -> Output {
    Command::new(&bins.loopctl)
        .args(args)
        .output()
        .expect("spawn ag-loopctl")
}

fn loopctl_ok(bins: &Bins, args: &[String]) -> serde_json::Value {
    let output = loopctl(bins, args);
    assert!(
        output.status.success(),
        "ag-loopctl {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("ag-loopctl stdout is one JSON document")
}

fn loopctl_fail(bins: &Bins, args: &[String]) -> Output {
    let output = loopctl(bins, args);
    assert!(
        !output.status.success(),
        "ag-loopctl {args:?} unexpectedly succeeded: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    output
}

fn str_args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

fn gate_args(catalog: &Path, observation: &Path, standing: &Path) -> Vec<String> {
    vec![
        "--catalog".to_owned(),
        catalog.display().to_string(),
        "--observation-resolver".to_owned(),
        observation.display().to_string(),
        "--expected-observation-resolver-id".to_owned(),
        OBSERVATION_RESOLVER_ID.to_owned(),
        "--standing-resolver".to_owned(),
        standing.display().to_string(),
        "--expected-standing-resolver-id".to_owned(),
        STANDING_RESOLVER_ID.to_owned(),
        "--max-standing-ttl-ms".to_owned(),
        STANDING_TTL_MS.to_string(),
    ]
}

fn docket_args(
    root: &Path,
    trust: &Path,
    docket_standing: &Path,
    plan: &Path,
    issuer_key: &Path,
    bins: &Bins,
) -> Vec<String> {
    docket_args_for_executor(
        root,
        trust,
        docket_standing,
        plan,
        issuer_key,
        &bins.effectd,
        bins,
    )
}

fn docket_args_for_executor(
    root: &Path,
    trust: &Path,
    docket_standing: &Path,
    plan: &Path,
    issuer_key: &Path,
    executor: &Path,
    bins: &Bins,
) -> Vec<String> {
    vec![
        "--docket".to_owned(),
        bins.docket.display().to_string(),
        "--docket-state".to_owned(),
        root.join("docket-state").display().to_string(),
        "--docket-trust".to_owned(),
        trust.display().to_string(),
        "--docket-standing-resolver".to_owned(),
        docket_standing.display().to_string(),
        "--executor".to_owned(),
        executor.display().to_string(),
        "--executor-config".to_owned(),
        plan.display().to_string(),
        "--issuer-principal".to_owned(),
        ISSUER_PRINCIPAL.to_owned(),
        "--issuer-key-id".to_owned(),
        ISSUER_KEY_ID.to_owned(),
        "--issuer-key".to_owned(),
        issuer_key.display().to_string(),
    ]
}

/// The program counter of one snapshot: the single key of the externally
/// tagged state sum.
fn program_counter(snapshot: &serde_json::Value) -> String {
    let state = snapshot["state"].as_object().unwrap();
    assert_eq!(state.len(), 1);
    state.keys().next().unwrap().clone()
}

fn replay(bins: &Bins, database: &Path) -> serde_json::Value {
    loopctl_ok(
        bins,
        &str_args(&["replay", "--database", &database.display().to_string()]),
    )
}

fn status(bins: &Bins, database: &Path) -> serde_json::Value {
    loopctl_ok(
        bins,
        &str_args(&["status", "--database", &database.display().to_string()]),
    )
}

struct DocketRig {
    trust: PathBuf,
    issuer_key: PathBuf,
    target: PathBuf,
    plan: PathBuf,
    plan_value: serde_json::Value,
    plan_identity: String,
}

/// The real Docket custody rig: trust config naming the embedded test issuer,
/// the issuer's pkcs8 credential, and the sealed executor plan whose identity
/// is the proposal's exact work digest.
fn docket_rig(root: &Path, scope: &str) -> DocketRig {
    let (uid, gid) = current_uid_gid();
    let artifact = root.join("artifact");
    let target = root.join("target");
    std::fs::write(&artifact, b"wo9-governed-effect\n").unwrap();
    let content = sha256_digest(b"wo9-governed-effect\n");
    let plan = serde_json::json!({
        "schema": PLAN_SCHEMA,
        "attempt_store": root.join("effect-attempts.sqlite").display().to_string(),
        "subject": SUBJECT_DIGEST,
        "scope": scope,
        "effect_index": 0,
        "effect": {
            "kind": "managed_file_put",
            "target": "wo9-integration",
            "path": target.display().to_string(),
            "expected_content": null,
            "content": content,
            "mode": 0o600,
            "uid": uid,
            "gid": gid
        },
        "artifacts": [{"digest": content, "path": artifact.display().to_string()}],
        "file_policy": {
            "max_content_bytes": 1024,
            "trusted_ancestor_uid": std::fs::metadata("/").unwrap().uid(),
            "trusted_parent_uid": uid,
            "require_private_parent_writes": true
        },
        "preparation_checkpoint": null
    });
    let plan_identity = ag_digest_value(PLAN_DIGEST_DOMAIN, &plan);
    let plan_path = root.join("effect-plan.json");
    write_jcs(&plan_path, &plan);

    let issuer_key = root.join("issuer.pk8");
    let key_bytes: Vec<u8> = (0..ISSUER_PKCS8_HEX.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&ISSUER_PKCS8_HEX[offset..offset + 2], 16).unwrap())
        .collect();
    std::fs::write(&issuer_key, key_bytes).unwrap();
    std::fs::set_permissions(&issuer_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let trust = root.join("docket-trust.json");
    write_jcs(
        &trust,
        &serde_json::json!({"issuers":[{
            "issuer_principal": ISSUER_PRINCIPAL,
            "key_id": ISSUER_KEY_ID,
            "public_key": ISSUER_PUBLIC_KEY_B64URL
        }]}),
    );
    DocketRig {
        trust,
        issuer_key,
        target,
        plan: plan_path,
        plan_value: plan,
        plan_identity,
    }
}

/// Docket trust material around an externally compiled, closed executor plan.
/// The plan bytes remain owned by the Maude compiler output; this helper adds
/// no work semantics and merely pins the existing test issuer to those bytes.
fn external_docket_rig(root: &Path, plan_path: &Path) -> DocketRig {
    let plan_bytes = std::fs::read(plan_path).unwrap();
    let plan_value: serde_json::Value = serde_json::from_slice(&plan_bytes).unwrap();
    assert_eq!(serde_jcs::to_vec(&plan_value).unwrap(), plan_bytes);
    let plan_identity = ag_digest_value(PLAN_DIGEST_DOMAIN, &plan_value);
    let issuer_key = root.join("issuer.pk8");
    let key_bytes: Vec<u8> = (0..ISSUER_PKCS8_HEX.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&ISSUER_PKCS8_HEX[offset..offset + 2], 16).unwrap())
        .collect();
    std::fs::write(&issuer_key, key_bytes).unwrap();
    std::fs::set_permissions(&issuer_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let trust = root.join("docket-trust.json");
    write_jcs(
        &trust,
        &serde_json::json!({"issuers":[{
            "issuer_principal": ISSUER_PRINCIPAL,
            "key_id": ISSUER_KEY_ID,
            "public_key": ISSUER_PUBLIC_KEY_B64URL
        }]}),
    );
    DocketRig {
        trust,
        issuer_key,
        target: root.join("no-managed-file-target"),
        plan: plan_path.to_owned(),
        plan_value,
        plan_identity,
    }
}

/// The controlled Docket execution-standing fixture (unchanged from the
/// existing governed-Docket harness; Docket's own production standing
/// authority is out of scope for WO-9).
fn docket_standing_script(root: &Path, status: &str) -> PathBuf {
    let status_path = root.join("docket-standing-status");
    std::fs::write(&status_path, status).unwrap();
    let script = root.join("docket-standing.py");
    write_wrapper(
        &script,
        &format!(
            r#"#!/usr/bin/python3
import hashlib,json,sys
r=json.load(sys.stdin); i=r["issuance"]
def d(label): return "sha256:"+hashlib.sha256(label.encode()).hexdigest()
status=open({status_path:?},encoding="utf-8").read().strip()
o={{"schema":"docket.governed-loop.execution-standing-resolution/v1","resolution":d("resolution:"+i["issuance"]),"currentness":d("currentness:"+i["issuance"]),"execution_standing":d("execution-standing:"+i["issuance"]),"issuance":i["issuance"],"campaign":i["key"]["campaign"],"occurrence":i["key"]["occurrence"],"subject":i["subject"],"scope":i["scope"],"status":status,"resolved_at_unix_ms":r["now_unix_ms"],"expires_at_unix_ms":r["now_unix_ms"]+60000}}
sys.stdout.write(json.dumps(o,sort_keys=True,separators=(",",":")))
"#,
            status_path = status_path.display().to_string()
        ),
    );
    script
}

fn pinned_file(path: &Path) -> serde_json::Value {
    serde_json::json!({
        "path": path.display().to_string(),
        "identity": sha256_digest(&std::fs::read(path).unwrap()),
    })
}

/// Seals the deployment-owned resolver, policy, and Docket coordinates that
/// later CLI arguments may repeat but may not select or alter.
#[allow(
    clippy::too_many_arguments,
    reason = "the cross-process fixture keeps every independently owned boundary visible"
)]
fn runtime_profile(
    root: &Path,
    label: &str,
    observation: &Path,
    standing: &Path,
    catalog: &Path,
    docket_standing: &Path,
    rig: &DocketRig,
    bins: &Bins,
) -> PathBuf {
    runtime_profile_for_executor(
        root,
        label,
        observation,
        standing,
        catalog,
        docket_standing,
        rig,
        &bins.effectd,
        bins,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the cross-process fixture keeps every independently owned boundary visible"
)]
fn runtime_profile_for_executor(
    root: &Path,
    label: &str,
    observation: &Path,
    standing: &Path,
    catalog: &Path,
    docket_standing: &Path,
    rig: &DocketRig,
    executor: &Path,
    bins: &Bins,
) -> PathBuf {
    let profile = root.join(format!("runtime-profile-{label}.json"));
    write_jcs(
        &profile,
        &serde_json::json!({
            "schema": "ag.governed-loop.runtime-profile/v1",
            "profile_label": label,
            "observation_resolver": pinned_file(observation),
            "observation_resolver_id": OBSERVATION_RESOLVER_ID,
            "standing_resolver": pinned_file(standing),
            "standing_resolver_id": STANDING_RESOLVER_ID,
            "max_standing_ttl_ms": STANDING_TTL_MS,
            "exact_work_catalog": pinned_file(catalog),
            "controlling_review": null,
            "docket": {
                "schema": "ag.governed-loop.docket-root/v1",
                "docket_program": pinned_file(&bins.docket),
                "state_directory": root.join("docket-state").display().to_string(),
                "trust_config": pinned_file(&rig.trust),
                "standing_resolver": pinned_file(docket_standing),
                "executor_adapter": pinned_file(executor),
                "issuer_principal": ISSUER_PRINCIPAL,
                "issuer_key_id": ISSUER_KEY_ID,
                "issuer_key": pinned_file(&rig.issuer_key),
            },
            "human_verifier": null,
        }),
    );
    profile
}

/// A minimal exact executor-plan document for store-only fixture tests: any
/// exact object has a deterministic AG executable-work identity.
fn fixture_plan() -> serde_json::Value {
    serde_json::json!({
        "schema": "ag-effectd.docket-executor-plan/v1",
        "fixture": "ag-governed-integration"
    })
}

/// Builds a real Nightshift store containing the given cycles through the
/// real canonical runtime. Returns the opened database path.
fn build_store(
    root: &Path,
    condition_present: bool,
    cycles: &[(u64, char, bool)],
    plan: &serde_json::Value,
) -> (PathBuf, String) {
    let (policy, clean_inputs, clean_recurrence) = example_policy_inputs_recurrence();
    let (inputs, recurrence) = if condition_present {
        condition_present_inputs_recurrence()
    } else {
        (clean_inputs, clean_recurrence)
    };
    let scope = policy.subject.scope.digest.clone();
    let database = root.join("ns.sqlite");
    let mut store = CanonicalStore::open(&database).unwrap();
    for &(occurrence, observation, with_proposal) in cycles {
        run_cycle(
            &mut store,
            cycle_request(
                &policy,
                &inputs,
                &recurrence,
                occurrence,
                &digest(observation),
                with_proposal,
                plan,
            ),
        );
    }
    drop(store);
    (database, scope)
}

/// Initializes one AG campaign database and records the proposal through the
/// real observation-resolver subprocess. Returns the proposal-recorded
/// snapshot.
fn init_and_record_proposal(
    bins: &Bins,
    root: &Path,
    ag_database: &Path,
    observation_wrapper_path: &Path,
    runtime_profile_path: &Path,
    scope: &str,
    work: &str,
) -> serde_json::Value {
    let genesis = root.join(format!(
        "genesis-{}.json",
        ag_database.file_name().unwrap().to_string_lossy()
    ));
    write_jcs(&genesis, &genesis_json(work));
    loopctl_ok(
        bins,
        &str_args(&[
            "init",
            "--database",
            &ag_database.display().to_string(),
            "--genesis",
            &genesis.display().to_string(),
            "--runtime-profile",
            &runtime_profile_path.display().to_string(),
        ]),
    );
    let proposal_input = root.join("proposal-input.json");
    write_jcs(
        &proposal_input,
        &proposal_input_json(&digest('d'), scope, work),
    );
    let recorded = loopctl_ok(
        bins,
        &str_args(&[
            "record-proposal",
            "--database",
            &ag_database.display().to_string(),
            "--input",
            &proposal_input.display().to_string(),
            "--observation-resolver",
            &observation_wrapper_path.display().to_string(),
            "--expected-observation-resolver-id",
            OBSERVATION_RESOLVER_ID,
        ]),
    );
    assert_eq!(program_counter(&recorded), "proposal_recorded");
    recorded
}

fn require_standing(bins: &Bins, ag_database: &Path) {
    let snapshot = loopctl_ok(
        bins,
        &str_args(&[
            "require-standing",
            "--database",
            &ag_database.display().to_string(),
        ]),
    );
    assert_eq!(program_counter(&snapshot), "standing_required");
}

fn request_for_precompiled(
    policy: &PosturePolicy,
    inputs: &DiagnosticInputs,
    recurrence: &RecurrenceEvidence,
    occurrence: u64,
    observation_id: &str,
    proposal: PrecompiledWorkflowProposalV2,
) -> CanonicalCycleRequestV1 {
    let mut request = cycle_request(
        policy,
        inputs,
        recurrence,
        occurrence,
        observation_id,
        false,
        &fixture_plan(),
    );
    request.schema.clear();
    request.request_id.clear();
    request.proposal = Some(proposal);
    request.seal().unwrap()
}

fn request_for_precompiled_fresh(
    policy: &PosturePolicy,
    inputs: &DiagnosticInputs,
    recurrence: &RecurrenceEvidence,
    occurrence: u64,
    evaluated_at: DateTime<Utc>,
    observation_id: &str,
    proposal: PrecompiledWorkflowProposalV2,
) -> CanonicalCycleRequestV1 {
    let due_at = DateTime::parse_from_rfc3339(&recurrence.records[0].slot.due_at)
        .unwrap()
        .with_timezone(&Utc);
    let latest = due_at
        + chrono::Duration::seconds(
            i64::try_from(recurrence.records[0].policy.standing_window_seconds).unwrap(),
        );
    let mut request = request_for_precompiled(
        policy,
        inputs,
        recurrence,
        occurrence,
        observation_id,
        proposal,
    );
    request.slot = RecurrenceSlotV1::new(
        policy.policy_id.clone(),
        "config-v1".into(),
        policy.subject.id.clone(),
        policy.subject.scope.digest.clone(),
        "nightshift-scheduler-1".into(),
        due_at,
        latest,
        occurrence,
        RecurrenceTriggerV1::Scheduled,
        None,
    )
    .unwrap();
    request.evaluated_at = evaluated_at;
    request.seal().unwrap()
}

#[allow(
    clippy::too_many_arguments,
    reason = "qualification keeps the two custody principals and exact inputs visible"
)]
fn attach_synthetic_maude_handoff(
    root: &Path,
    label: &str,
    mut request: CanonicalCycleRequestV1,
    locked_plan: &Path,
    custody_store: &Path,
    session_key: &Path,
    producer_key: &Path,
    session_id: &str,
) -> CanonicalCycleRequestV1 {
    let request_path = root.join(format!("cycle-request-{label}-base.json"));
    let handoff_path = root.join(format!("maude-handoff-{label}.json"));
    write_jcs(&request_path, &serde_json::to_value(&request).unwrap());
    let output = Command::new(std::env::var_os("MAUDE_PYTHON").expect("MAUDE_PYTHON"))
        .arg(
            std::env::var_os("MAUDE_SYNTHETIC_HANDOFF_HELPER")
                .expect("MAUDE_SYNTHETIC_HANDOFF_HELPER"),
        )
        .arg("--store")
        .arg(custody_store)
        .arg("--session-key")
        .arg(session_key)
        .arg("--producer-key")
        .arg(producer_key)
        .arg("--plan")
        .arg(locked_plan)
        .arg("--base-request")
        .arg(&request_path)
        .arg("--output")
        .arg(&handoff_path)
        .arg("--session-id")
        .arg(session_id)
        .arg("--runtime-id")
        .arg("nightshift:synthetic-local-v1")
        .env(
            "PYTHONPATH",
            std::env::var_os("MAUDE_SRC").expect("MAUDE_SRC"),
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Maude custody helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let handoff: MaudeAuthoringContextHandoffV1 =
        serde_json::from_slice(&std::fs::read(handoff_path).unwrap()).unwrap();
    assert_eq!(handoff.target_request_id, request.request_id);
    request.authoring_context = Some(handoff);
    request.seal().unwrap()
}

fn init_and_record_precompiled(
    bins: &Bins,
    root: &Path,
    ag_database: &Path,
    observation: &Path,
    profile: &Path,
    handoff: &serde_json::Value,
) -> serde_json::Value {
    let genesis = root.join("synthetic-genesis.json");
    write_jcs(&genesis, &handoff["mode"]["genesis"]["genesis"]);
    loopctl_ok(
        bins,
        &str_args(&[
            "init",
            "--database",
            &ag_database.display().to_string(),
            "--genesis",
            &genesis.display().to_string(),
            "--runtime-profile",
            &profile.display().to_string(),
        ]),
    );
    let proposal_input = root.join("synthetic-proposal-input.json");
    write_jcs(&proposal_input, &handoff["proposal_input"]);
    let recorded = loopctl_ok(
        bins,
        &str_args(&[
            "record-proposal",
            "--database",
            &ag_database.display().to_string(),
            "--input",
            &proposal_input.display().to_string(),
            "--observation-resolver",
            &observation.display().to_string(),
            "--expected-observation-resolver-id",
            OBSERVATION_RESOLVER_ID,
        ]),
    );
    assert_eq!(program_counter(&recorded), "proposal_recorded");
    recorded
}

// --- Tests ---

/// Always-on fixture pin: the reseal algorithm reproduces the checked-in
/// specimen identity, and the mutated specimen drives the real runtime to a
/// genuine `ConditionPresent` posture. No external binaries.
#[test]
fn condition_present_fixture_is_real_and_resealed() {
    let mut unmodified: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/operator/examples/diagnostic-posture-v1/inputs.json"
    ))
    .unwrap();
    let artifact = &mut unmodified["inputs"][0]["artifact"];
    let checked_in = artifact["artifact_id"].as_str().unwrap().to_owned();
    let mut preimage = artifact.clone();
    preimage.as_object_mut().unwrap().remove("artifact_id");
    assert_eq!(digest_value(&preimage), checked_in);

    let root = tempfile::tempdir().unwrap();
    let (database, _) = build_store(root.path(), true, &[(0, 'd', true)], &fixture_plan());
    let store = CanonicalStore::open(&database).unwrap();
    let family = store.find_cycles_by_observation_id(&digest('d')).unwrap();
    assert_eq!(family.len(), 1);
    let posture = &family[0].observation.as_ref().unwrap().posture;
    assert!(posture.current);
    assert_eq!(posture.condition, ConditionAxis::ConditionPresent);
    let basis = normalize_posture(posture);
    assert_eq!(
        basis.atoms,
        std::collections::BTreeSet::from([
            "condition.condition_present".to_owned(),
            "delivery.not_required".to_owned(),
        ])
    );
}

/// Scenario A: the full healthy chain, with the complete provenance
/// reconstruction of section 16/17.
#[test]
#[ignore = "requires adjacent AG and Docket binaries; see module documentation"]
fn healthy_chain_reaches_docket_and_executes_exactly_once() {
    let bins = bins();
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

    // The plan identity is the proposal's exact work, so the rig comes first.
    let (policy, _, _) = example_policy_inputs_recurrence();
    let scope = policy.subject.scope.digest.clone();
    let rig = docket_rig(root.path(), &scope);
    let (ns_database, _) = build_store(root.path(), false, &[(0, 'd', true)], &rig.plan_value);

    let observation = observation_wrapper(root.path(), &ns_database);
    let mandate_store = root.path().join("mandates.json");
    let mandate = mandate_json(&scope, 1, "active", wall_now_ms() + 3_600_000);
    write_jcs(&mandate_store, &mandate_store_json(vec![mandate.clone()]));
    let standing = standing_wrapper(&bins, root.path(), &mandate_store);
    let catalog = root.path().join("catalog.json");
    let rollout = catalog_json(&scope, &["condition.clean"]);
    write_jcs(&catalog, &rollout);
    let docket_standing = docket_standing_script(root.path(), "current");
    let profile = runtime_profile(
        root.path(),
        "healthy",
        &observation,
        &standing,
        &catalog,
        &docket_standing,
        &rig,
        &bins,
    );

    let ag_database = root.path().join("ag.sqlite");
    let recorded = init_and_record_proposal(
        &bins,
        root.path(),
        &ag_database,
        &observation,
        &profile,
        &scope,
        &rig.plan_identity,
    );
    // The recorded observation resolution is the real resolver's answer over
    // the real persisted record: current, clean, and digest-pinned.
    let recorded_observation = &recorded["state"]["proposal_recorded"]["observation"];
    assert_eq!(recorded_observation["status"], "current");
    assert_eq!(recorded_observation["resolver_id"], OBSERVATION_RESOLVER_ID);
    assert_eq!(recorded_observation["observation"], digest('d'));
    assert_eq!(
        recorded_observation["normalized_preconditions"],
        "sha256:d67f86277b1604cad1916d01bcd5e01fc3a9002d4630cb8fdf5b749febf4b2c7",
        "the clean specimen basis is the frozen WO-3 cross-repository vector"
    );
    let proposal_ref = recorded["state"]["proposal_recorded"]["proposal_ref"]
        .as_str()
        .unwrap()
        .to_owned();

    require_standing(&bins, &ag_database);
    let gate = gate_args(&catalog, &observation, &standing);
    let mut decide_args = str_args(&["decide", "--database", &ag_database.display().to_string()]);
    decide_args.extend(gate.clone());
    let decided = loopctl_ok(&bins, &decide_args);
    assert_eq!(
        program_counter(&decided),
        "admissible_pending_authorization"
    );
    // The recorded policy identity is recomputed here from the exact catalog
    // document, not taken on trust.
    let expected_policy_basis = ag_digest_value(CATALOG_DIGEST_DOMAIN, &rollout);
    assert_eq!(
        decided["state"]["admissible_pending_authorization"]["decision"]["policy_basis"],
        serde_json::Value::String(expected_policy_basis.clone())
    );

    let mut authorize_args = str_args(&[
        "authorize",
        "--database",
        &ag_database.display().to_string(),
    ]);
    authorize_args.extend(gate);
    let authorized = loopctl_ok(&bins, &authorize_args);
    assert_eq!(program_counter(&authorized), "authorization_consumed");

    // Section 16/17 provenance reconstruction from the persisted authority
    // state.
    let state = &authorized["state"]["authorization_consumed"];
    let admitted = &state["admitted"];
    let observation_resolution = &admitted["proposal"]["observation"];
    assert_eq!(observation_resolution["observation"], digest('d'));
    assert_eq!(
        observation_resolution["resolver_id"],
        OBSERVATION_RESOLVER_ID
    );
    assert_eq!(observation_resolution["status"], "current");
    assert_eq!(
        observation_resolution["basis"]["rule"]["id"],
        "nightshift.posture-normalization"
    );
    // The pinned basis digest is recomputed from the persisted Nightshift
    // record through Nightshift's own normalization.
    let store = CanonicalStore::open(&ns_database).unwrap();
    let cycles = store.find_cycles_by_observation_id(&digest('d')).unwrap();
    let posture = &cycles[0].observation.as_ref().unwrap().posture;
    let expected_basis = normalize_posture(posture);
    assert_eq!(
        observation_resolution["normalized_preconditions"]
            .as_str()
            .unwrap(),
        expected_basis.digest().unwrap()
    );
    // The sealed cross-domain work binding: the persisted intent carries the
    // Nightshift-domain compiled-payload identity and the AG-domain
    // executable-work identity derived from the actual executor plan, and the
    // persisted prepared request proposes exactly that AG work.
    let intent = cycles[0].intent.as_ref().unwrap();
    assert_eq!(intent.expected_ag_work, rig.plan_identity);
    assert_eq!(
        intent.compiled_work,
        digest_value(&serde_json::json!({
            "parameters": {"resource_id": "resource-1"},
            "schema": WORK_SCHEMA,
        }))
    );
    assert_ne!(intent.compiled_work, intent.expected_ag_work);
    let prepared = cycles[0].prepared_ag_request.as_ref().unwrap();
    assert_eq!(
        prepared.exact_request["proposal_input"]["proposal"]["work"]
            .as_str()
            .unwrap(),
        rig.plan_identity
    );
    drop(store);

    let standing_resolution = &admitted["standing"];
    assert_eq!(standing_resolution["resolver_id"], STANDING_RESOLVER_ID);
    assert_eq!(standing_resolution["status"], "current");
    let window = standing_resolution["expires_at_unix_ms"].as_u64().unwrap()
        - standing_resolution["resolved_at_unix_ms"].as_u64().unwrap();
    assert!(window <= STANDING_TTL_MS);
    // The mandate identity recorded at spend is the content-derived identity
    // of the exact mandate document, confirmed independently by a direct
    // probe of the production resolver binary.
    let expected_mandate = mandate_ref(&mandate);
    let probed_mandate = probe_standing_mandate_ref(&bins, &mandate_store, &scope, &proposal_ref);
    assert_eq!(expected_mandate, probed_mandate);
    assert_eq!(
        standing_resolution["mandate"],
        serde_json::Value::String(expected_mandate.clone())
    );

    let spend = &state["spend"];
    let issuance = &state["issuance"];
    assert_eq!(issuance["spend"], spend["spend"]);
    assert_eq!(issuance["observation"], digest('d'));
    assert_eq!(issuance["work"], rig.plan_identity);
    assert_eq!(issuance["work_schema"], WORK_SCHEMA);
    assert_eq!(issuance["subject"], SUBJECT_DIGEST);
    assert_eq!(issuance["scope"], scope);
    assert_eq!(
        issuance["mandate"],
        serde_json::Value::String(expected_mandate)
    );
    assert_eq!(
        issuance["standing_resolution"],
        standing_resolution["resolution"]
    );
    assert_eq!(
        spend["admission_decision"],
        admitted["decision"]["decision"]
    );
    assert_eq!(admitted["decision"]["disposition"], "admitted");
    assert_eq!(
        admitted["decision"]["policy_basis"],
        serde_json::Value::String(expected_policy_basis)
    );
    let report = replay(&bins, &ag_database);
    assert_eq!(report["ag_spends"], 1);

    // Docket custody and the safe executor: exactly one effect.
    let docket = docket_args(
        root.path(),
        &rig.trust,
        &docket_standing,
        &rig.plan,
        &rig.issuer_key,
        &bins,
    );
    let mut dispatch_args =
        str_args(&["dispatch", "--database", &ag_database.display().to_string()]);
    dispatch_args.extend(docket.clone());
    let dispatched = loopctl_ok(&bins, &dispatch_args);
    assert_eq!(program_counter(&dispatched), "dispatched");
    let mut poll_args = str_args(&["poll", "--database", &ag_database.display().to_string()]);
    poll_args.extend(docket.clone());
    let settled = loopctl_ok(&bins, &poll_args);
    assert_eq!(program_counter(&settled), "settled_observation_required");
    assert_eq!(
        std::fs::read(&rig.target).unwrap(),
        b"wo9-governed-effect\n"
    );
    let report = replay(&bins, &ag_database);
    assert_eq!(report["ag_spends"], 1);
    assert_eq!(report["docket_attempts"], 1);
    assert_eq!(report["settlements"], 1);

    // The executor does not re-run on a repeated poll.
    std::fs::write(&rig.target, b"must-not-run-again\n").unwrap();
    let repolled = loopctl_ok(&bins, &poll_args);
    assert_eq!(program_counter(&repolled), "settled_observation_required");
    assert_eq!(std::fs::read(&rig.target).unwrap(), b"must-not-run-again\n");

    // A receipt does not authorize continuation. Only a distinct fresh
    // Nightshift cycle can open occurrence 1 and record its successor
    // proposal; no second spend or Docket attempt exists at that point.
    let (inputs, recurrence) = next_clean_inputs_recurrence();
    let mut successor_plan = rig.plan_value.clone();
    successor_plan["effect_index"] = serde_json::json!(1);
    assert_ne!(
        ag_executor_plan_identity(&successor_plan).unwrap(),
        rig.plan_identity,
        "a successor proposal must name genuinely new exact work"
    );
    let successor_request = successor_cycle_request(
        &policy,
        &inputs,
        &recurrence,
        1,
        &digest('e'),
        &successor_plan,
    );
    let mut store = CanonicalStore::open(&ns_database).unwrap();
    let mut support = SupportPort;
    let mut ag = AgLoopCtlPortV1::new(
        &bins.loopctl,
        &ag_database,
        &observation,
        OBSERVATION_RESOLVER_ID,
        &profile,
    )
    .unwrap();
    let outcome = CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag)
        .run_cycle(successor_request)
        .unwrap();
    let CycleRunOutcomeV1::AgOccurrenceOpened { cycle } = outcome else {
        panic!("fresh successor observation must open an AG occurrence");
    };
    let successor = cycle.ag.unwrap();
    assert_eq!(successor.occurrence_id, occurrence_uuid(1));
    assert_eq!(
        successor.program_counter,
        AgProgramCounterV1::ProposalRecorded
    );
    let report = replay(&bins, &ag_database);
    assert_eq!(report["ag_spends"], 1);
    assert_eq!(report["docket_attempts"], 1);
}

/// Scenarios B and C over literally the same persisted Nightshift
/// observation: the rollout policy refuses the real condition-present basis
/// and the remediation policy admits it. Two independent AG campaign
/// databases read one Nightshift store.
#[test]
#[ignore = "requires adjacent AG and Docket binaries; see module documentation"]
fn rollout_refuses_and_remediation_admits_identical_condition_present_evidence() {
    let bins = bins();
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

    let (policy, _, _) = example_policy_inputs_recurrence();
    let scope = policy.subject.scope.digest.clone();
    let rig = docket_rig(root.path(), &scope);
    let (ns_database, _) = build_store(root.path(), true, &[(0, 'd', true)], &rig.plan_value);
    let observation = observation_wrapper(root.path(), &ns_database);
    let mandate_store = root.path().join("mandates.json");
    write_jcs(
        &mandate_store,
        &mandate_store_json(vec![mandate_json(
            &scope,
            1,
            "active",
            wall_now_ms() + 3_600_000,
        )]),
    );
    let standing = standing_wrapper(&bins, root.path(), &mandate_store);
    let docket_standing = docket_standing_script(root.path(), "current");

    // The honest basis of the persisted record, computed Nightshift-side.
    let store = CanonicalStore::open(&ns_database).unwrap();
    let cycles = store.find_cycles_by_observation_id(&digest('d')).unwrap();
    let posture = &cycles[0].observation.as_ref().unwrap().posture;
    let expected_basis = normalize_posture(posture);
    assert_eq!(posture.condition, ConditionAxis::ConditionPresent);
    let expected_basis_digest = expected_basis.digest().unwrap();
    drop(store);

    // B: the rollout policy (`required = {condition.clean}`) refuses this
    // evidence. The failure is catalog policy refusal, not evidence-health
    // failure: the observation resolved Current at record time.
    let rollout_database = root.path().join("ag-rollout.sqlite");
    let rollout_catalog = root.path().join("catalog-rollout.json");
    let rollout = catalog_json(&scope, &["condition.clean"]);
    write_jcs(&rollout_catalog, &rollout);
    let rollout_profile = runtime_profile(
        root.path(),
        "rollout",
        &observation,
        &standing,
        &rollout_catalog,
        &docket_standing,
        &rig,
        &bins,
    );
    let recorded = init_and_record_proposal(
        &bins,
        root.path(),
        &rollout_database,
        &observation,
        &rollout_profile,
        &scope,
        &rig.plan_identity,
    );
    let recorded_observation = &recorded["state"]["proposal_recorded"]["observation"];
    assert_eq!(recorded_observation["status"], "current");
    assert_eq!(
        recorded_observation["normalized_preconditions"]
            .as_str()
            .unwrap(),
        expected_basis_digest
    );
    require_standing(&bins, &rollout_database);
    let mut decide_args = str_args(&[
        "decide",
        "--database",
        &rollout_database.display().to_string(),
    ]);
    decide_args.extend(gate_args(&rollout_catalog, &observation, &standing));
    let refusal = loopctl_fail(&bins, &decide_args);
    assert!(
        String::from_utf8_lossy(&refusal.stderr).contains("not admissible"),
        "expected an inadmissibility refusal: {}",
        String::from_utf8_lossy(&refusal.stderr)
    );
    // State is preserved pre-decision; no spend, no issuance.
    let snapshot = status(&bins, &rollout_database);
    assert_eq!(program_counter(&snapshot), "standing_required");
    let report = replay(&bins, &rollout_database);
    assert_eq!(report["ag_spends"], 0);

    // C: the remediation policy (`required = {condition.condition_present}`)
    // admits exactly the same persisted evidence through a second independent
    // campaign. There is no universal Clean rule anywhere in the chain.
    let remediation_database = root.path().join("ag-remediation.sqlite");
    let remediation_catalog = root.path().join("catalog-remediation.json");
    let remediation = catalog_json(&scope, &["condition.condition_present"]);
    write_jcs(&remediation_catalog, &remediation);
    let remediation_profile = runtime_profile(
        root.path(),
        "remediation",
        &observation,
        &standing,
        &remediation_catalog,
        &docket_standing,
        &rig,
        &bins,
    );
    init_and_record_proposal(
        &bins,
        root.path(),
        &remediation_database,
        &observation,
        &remediation_profile,
        &scope,
        &rig.plan_identity,
    );
    require_standing(&bins, &remediation_database);
    let gate = gate_args(&remediation_catalog, &observation, &standing);
    let mut decide_args = str_args(&[
        "decide",
        "--database",
        &remediation_database.display().to_string(),
    ]);
    decide_args.extend(gate.clone());
    let decided = loopctl_ok(&bins, &decide_args);
    assert_eq!(
        program_counter(&decided),
        "admissible_pending_authorization"
    );
    // Distinct catalog policies are distinct content-derived identities.
    assert_ne!(
        ag_digest_value(CATALOG_DIGEST_DOMAIN, &rollout),
        ag_digest_value(CATALOG_DIGEST_DOMAIN, &remediation)
    );
    assert_eq!(
        decided["state"]["admissible_pending_authorization"]["decision"]["policy_basis"]
            .as_str()
            .unwrap(),
        ag_digest_value(CATALOG_DIGEST_DOMAIN, &remediation)
    );

    let mut authorize_args = str_args(&[
        "authorize",
        "--database",
        &remediation_database.display().to_string(),
    ]);
    authorize_args.extend(gate);
    let authorized = loopctl_ok(&bins, &authorize_args);
    assert_eq!(program_counter(&authorized), "authorization_consumed");
    let state = &authorized["state"]["authorization_consumed"];
    assert_eq!(
        state["admitted"]["proposal"]["observation"]["normalized_preconditions"]
            .as_str()
            .unwrap(),
        expected_basis_digest
    );
    let report = replay(&bins, &remediation_database);
    assert_eq!(report["ag_spends"], 1);

    // The admitted remediation work crosses Docket and executes once.
    let docket = docket_args(
        root.path(),
        &rig.trust,
        &docket_standing,
        &rig.plan,
        &rig.issuer_key,
        &bins,
    );
    let mut dispatch_args = str_args(&[
        "dispatch",
        "--database",
        &remediation_database.display().to_string(),
    ]);
    dispatch_args.extend(docket.clone());
    loopctl_ok(&bins, &dispatch_args);
    let mut poll_args = str_args(&[
        "poll",
        "--database",
        &remediation_database.display().to_string(),
    ]);
    poll_args.extend(docket);
    let settled = loopctl_ok(&bins, &poll_args);
    assert_eq!(program_counter(&settled), "settled_observation_required");
    assert_eq!(
        std::fs::read(&rig.target).unwrap(),
        b"wo9-governed-effect\n"
    );
}

/// Scenario D: a strictly later qualified same-family Nightshift observation
/// supersedes the cited evidence between decide and authorize. The old
/// proposal is not refreshed onto the new evidence; no spend occurs.
#[test]
#[ignore = "requires adjacent AG and Docket binaries; see module documentation"]
fn newer_same_family_evidence_supersedes_before_spend() {
    let bins = bins();
    let root = tempfile::tempdir().unwrap();

    let (policy, _, _) = example_policy_inputs_recurrence();
    let scope = policy.subject.scope.digest.clone();
    let rig = docket_rig(root.path(), &scope);
    let (ns_database, _) = build_store(root.path(), false, &[(0, 'd', true)], &rig.plan_value);
    let observation = observation_wrapper(root.path(), &ns_database);
    let mandate_store = root.path().join("mandates.json");
    write_jcs(
        &mandate_store,
        &mandate_store_json(vec![mandate_json(
            &scope,
            1,
            "active",
            wall_now_ms() + 3_600_000,
        )]),
    );
    let standing = standing_wrapper(&bins, root.path(), &mandate_store);
    let catalog_path = root.path().join("catalog.json");
    write_jcs(&catalog_path, &catalog_json(&scope, &["condition.clean"]));
    let docket_standing = docket_standing_script(root.path(), "current");
    let profile = runtime_profile(
        root.path(),
        "supersession",
        &observation,
        &standing,
        &catalog_path,
        &docket_standing,
        &rig,
        &bins,
    );

    let ag_database = root.path().join("ag.sqlite");
    init_and_record_proposal(
        &bins,
        root.path(),
        &ag_database,
        &observation,
        &profile,
        &scope,
        &rig.plan_identity,
    );
    require_standing(&bins, &ag_database);
    let gate = gate_args(&catalog_path, &observation, &standing);
    let mut decide_args = str_args(&["decide", "--database", &ag_database.display().to_string()]);
    decide_args.extend(gate.clone());
    let decided = loopctl_ok(&bins, &decide_args);
    assert_eq!(
        program_counter(&decided),
        "admissible_pending_authorization"
    );

    // A later logical slot in the same family observes successfully. The
    // pinned proposal still cites the older observation.
    let (_, inputs, recurrence) = example_policy_inputs_recurrence();
    let mut store = CanonicalStore::open(&ns_database).unwrap();
    let outcome = run_cycle(
        &mut store,
        cycle_request(
            &policy,
            &inputs,
            &recurrence,
            1,
            &digest('e'),
            false,
            &rig.plan_value,
        ),
    );
    assert!(matches!(outcome, CycleRunOutcomeV1::PostureOnly { .. }));
    drop(store);

    // The real resolver now classifies the cited observation as superseded
    // (direct probe of the production binary).
    let mut child = Command::new(env!("CARGO_BIN_EXE_nightshift-observation-resolver"))
        .arg("--store")
        .arg(&ns_database)
        .arg("--resolver-id")
        .arg(OBSERVATION_RESOLVER_ID)
        .arg("--default-ttl-ms")
        .arg(OBSERVATION_TTL_MS.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let probe = serde_json::json!({
        "schema": "ag.governed-loop.observation-request/v1",
        "key": {"campaign": campaign(), "occurrence": occurrence_uuid(0)},
        "observation": digest('d'),
        "subject": SUBJECT_DIGEST,
        "now_unix_ms": wall_now_ms()
    });
    child
        .stdin
        .take()
        .unwrap()
        .write_all(probe.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body["status"], "superseded");

    // Authorization refuses: the pinned basis is not refreshed onto O2.
    let mut authorize_args = str_args(&[
        "authorize",
        "--database",
        &ag_database.display().to_string(),
    ]);
    authorize_args.extend(gate);
    loopctl_fail(&bins, &authorize_args);
    let snapshot = status(&bins, &ag_database);
    assert_eq!(
        program_counter(&snapshot),
        "admissible_pending_authorization"
    );
    let report = replay(&bins, &ag_database);
    assert_eq!(report["ag_spends"], 0);
}

/// Scenarios E and F: standing is revoked between decide and authorize (no
/// spend), then recovers under a newer mandate generation; the same proposal
/// authorizes without new evidence, and the spend names the new mandate.
#[test]
#[ignore = "requires adjacent AG and Docket binaries; see module documentation"]
fn standing_revocation_and_recovery_across_authorize() {
    let bins = bins();
    let root = tempfile::tempdir().unwrap();

    let (policy, _, _) = example_policy_inputs_recurrence();
    let scope = policy.subject.scope.digest.clone();
    let rig = docket_rig(root.path(), &scope);
    let (ns_database, _) = build_store(root.path(), false, &[(0, 'd', true)], &rig.plan_value);
    let observation = observation_wrapper(root.path(), &ns_database);
    let mandate_store = root.path().join("mandates.json");
    let validity = wall_now_ms() + 3_600_000;
    let generation_one = mandate_json(&scope, 1, "active", validity);
    write_jcs(
        &mandate_store,
        &mandate_store_json(vec![generation_one.clone()]),
    );
    let standing = standing_wrapper(&bins, root.path(), &mandate_store);
    let catalog_path = root.path().join("catalog.json");
    write_jcs(&catalog_path, &catalog_json(&scope, &["condition.clean"]));
    let docket_standing = docket_standing_script(root.path(), "current");
    let profile = runtime_profile(
        root.path(),
        "standing-revalidation",
        &observation,
        &standing,
        &catalog_path,
        &docket_standing,
        &rig,
        &bins,
    );

    let ag_database = root.path().join("ag.sqlite");
    let recorded = init_and_record_proposal(
        &bins,
        root.path(),
        &ag_database,
        &observation,
        &profile,
        &scope,
        &rig.plan_identity,
    );
    let proposal_ref = recorded["state"]["proposal_recorded"]["proposal_ref"]
        .as_str()
        .unwrap()
        .to_owned();
    require_standing(&bins, &ag_database);
    let gate = gate_args(&catalog_path, &observation, &standing);
    let mut decide_args = str_args(&["decide", "--database", &ag_database.display().to_string()]);
    decide_args.extend(gate.clone());
    let decided = loopctl_ok(&bins, &decide_args);
    assert_eq!(
        program_counter(&decided),
        "admissible_pending_authorization"
    );

    // E: governance revokes by superseding generation 1 with a revoked
    // generation 2. The read-only resolver loads the store fresh.
    let generation_two = mandate_json(&scope, 2, "revoked", validity);
    write_jcs(
        &mandate_store,
        &mandate_store_json(vec![generation_one.clone(), generation_two.clone()]),
    );
    let mut authorize_args = str_args(&[
        "authorize",
        "--database",
        &ag_database.display().to_string(),
    ]);
    authorize_args.extend(gate.clone());
    loopctl_fail(&bins, &authorize_args);
    let snapshot = status(&bins, &ag_database);
    assert_eq!(
        program_counter(&snapshot),
        "admissible_pending_authorization"
    );
    let report = replay(&bins, &ag_database);
    assert_eq!(report["ag_spends"], 0);

    // F: governance restores standing under generation 3. The same proposal
    // authorizes with no new observation, proposal, or occurrence.
    let generation_three = mandate_json(&scope, 3, "active", validity);
    write_jcs(
        &mandate_store,
        &mandate_store_json(vec![
            generation_one,
            generation_two,
            generation_three.clone(),
        ]),
    );
    let authorized = loopctl_ok(&bins, &authorize_args);
    assert_eq!(program_counter(&authorized), "authorization_consumed");
    let state = &authorized["state"]["authorization_consumed"];
    assert_eq!(
        state["issuance"]["proposal"].as_str().unwrap(),
        proposal_ref,
        "the spent proposal is the original one"
    );
    let expected_mandate = mandate_ref(&generation_three);
    let probed_mandate = probe_standing_mandate_ref(&bins, &mandate_store, &scope, &proposal_ref);
    assert_eq!(expected_mandate, probed_mandate);
    assert_eq!(
        state["issuance"]["mandate"],
        serde_json::Value::String(expected_mandate)
    );
    assert_eq!(
        state["admitted"]["standing"]["resolver_id"],
        STANDING_RESOLVER_ID
    );
    let report = replay(&bins, &ag_database);
    assert_eq!(report["ag_spends"], 1);
}

/// Scenario G: Docket execution standing refuses after the AG spend. The
/// spend remains historically real, no executor effect occurs, and a later
/// current answer lets the same issuance through exactly once.
#[test]
#[ignore = "requires adjacent AG and Docket binaries; see module documentation"]
fn docket_refusal_after_spend_prevents_effect() {
    let bins = bins();
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

    let (policy, _, _) = example_policy_inputs_recurrence();
    let scope = policy.subject.scope.digest.clone();
    let rig = docket_rig(root.path(), &scope);
    let (ns_database, _) = build_store(root.path(), false, &[(0, 'd', true)], &rig.plan_value);
    let observation = observation_wrapper(root.path(), &ns_database);
    let mandate_store = root.path().join("mandates.json");
    write_jcs(
        &mandate_store,
        &mandate_store_json(vec![mandate_json(
            &scope,
            1,
            "active",
            wall_now_ms() + 3_600_000,
        )]),
    );
    let standing = standing_wrapper(&bins, root.path(), &mandate_store);
    let catalog_path = root.path().join("catalog.json");
    write_jcs(&catalog_path, &catalog_json(&scope, &["condition.clean"]));
    let docket_standing = docket_standing_script(root.path(), "revoked");
    let profile = runtime_profile(
        root.path(),
        "docket-standing",
        &observation,
        &standing,
        &catalog_path,
        &docket_standing,
        &rig,
        &bins,
    );

    let ag_database = root.path().join("ag.sqlite");
    init_and_record_proposal(
        &bins,
        root.path(),
        &ag_database,
        &observation,
        &profile,
        &scope,
        &rig.plan_identity,
    );
    require_standing(&bins, &ag_database);
    let gate = gate_args(&catalog_path, &observation, &standing);
    let mut decide_args = str_args(&["decide", "--database", &ag_database.display().to_string()]);
    decide_args.extend(gate.clone());
    loopctl_ok(&bins, &decide_args);
    let mut authorize_args = str_args(&[
        "authorize",
        "--database",
        &ag_database.display().to_string(),
    ]);
    authorize_args.extend(gate);
    let authorized = loopctl_ok(&bins, &authorize_args);
    assert_eq!(program_counter(&authorized), "authorization_consumed");

    // Docket's execution-standing resolver says revoked: custody is refused
    // and the executor never runs, though the AG spend is durable history.
    let docket = docket_args(
        root.path(),
        &rig.trust,
        &docket_standing,
        &rig.plan,
        &rig.issuer_key,
        &bins,
    );
    let mut dispatch_args =
        str_args(&["dispatch", "--database", &ag_database.display().to_string()]);
    dispatch_args.extend(docket.clone());
    loopctl_fail(&bins, &dispatch_args);
    assert!(!rig.target.exists(), "no executor effect on refusal");
    let report = replay(&bins, &ag_database);
    assert_eq!(
        report["ag_spends"], 1,
        "the spend remains historically real"
    );
    assert_eq!(report["docket_attempts"], 0);
    let snapshot = status(&bins, &ag_database);
    assert_eq!(program_counter(&snapshot), "authorization_consumed");

    // When execution standing is current again, the same issuance crosses
    // and executes exactly once.
    let current = docket_standing_script(root.path(), "current");
    let docket = docket_args(
        root.path(),
        &rig.trust,
        &current,
        &rig.plan,
        &rig.issuer_key,
        &bins,
    );
    let mut dispatch_args =
        str_args(&["dispatch", "--database", &ag_database.display().to_string()]);
    dispatch_args.extend(docket.clone());
    loopctl_ok(&bins, &dispatch_args);
    let mut poll_args = str_args(&["poll", "--database", &ag_database.display().to_string()]);
    poll_args.extend(docket);
    let settled = loopctl_ok(&bins, &poll_args);
    assert_eq!(program_counter(&settled), "settled_observation_required");
    assert_eq!(
        std::fs::read(&rig.target).unwrap(),
        b"wo9-governed-effect\n"
    );
    let report = replay(&bins, &ag_database);
    assert_eq!(report["ag_spends"], 1);
    assert_eq!(report["docket_attempts"], 1);
}

/// Scenario H: an AG refusal mints nothing, and Docket — even with
/// permissive execution standing — has no issuance to accept and produces no
/// effect. Docket is downstream custody, not an alternate authority source.
#[test]
#[ignore = "requires adjacent AG and Docket binaries; see module documentation"]
fn ag_refusal_cannot_be_resurrected_by_docket() {
    let bins = bins();
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

    let (policy, _, _) = example_policy_inputs_recurrence();
    let scope = policy.subject.scope.digest.clone();
    let rig = docket_rig(root.path(), &scope);
    let (ns_database, _) = build_store(root.path(), true, &[(0, 'd', true)], &rig.plan_value);
    let observation = observation_wrapper(root.path(), &ns_database);
    let mandate_store = root.path().join("mandates.json");
    write_jcs(
        &mandate_store,
        &mandate_store_json(vec![mandate_json(
            &scope,
            1,
            "active",
            wall_now_ms() + 3_600_000,
        )]),
    );
    let standing = standing_wrapper(&bins, root.path(), &mandate_store);
    let rollout_catalog = root.path().join("catalog-rollout.json");
    write_jcs(
        &rollout_catalog,
        &catalog_json(&scope, &["condition.clean"]),
    );
    let docket_standing = docket_standing_script(root.path(), "current");
    let profile = runtime_profile(
        root.path(),
        "ag-refusal",
        &observation,
        &standing,
        &rollout_catalog,
        &docket_standing,
        &rig,
        &bins,
    );

    let ag_database = root.path().join("ag.sqlite");
    init_and_record_proposal(
        &bins,
        root.path(),
        &ag_database,
        &observation,
        &profile,
        &scope,
        &rig.plan_identity,
    );
    require_standing(&bins, &ag_database);
    let mut decide_args = str_args(&["decide", "--database", &ag_database.display().to_string()]);
    decide_args.extend(gate_args(&rollout_catalog, &observation, &standing));
    loopctl_fail(&bins, &decide_args);
    let report = replay(&bins, &ag_database);
    assert_eq!(report["ag_spends"], 0);

    // A permissive Docket cannot manufacture an execution: there is no
    // issuance to present, and dispatch from a pre-spend state fails.
    let docket = docket_args(
        root.path(),
        &rig.trust,
        &docket_standing,
        &rig.plan,
        &rig.issuer_key,
        &bins,
    );
    let mut dispatch_args =
        str_args(&["dispatch", "--database", &ag_database.display().to_string()]);
    dispatch_args.extend(docket);
    loopctl_fail(&bins, &dispatch_args);
    assert!(!rig.target.exists());
    let report = replay(&bins, &ag_database);
    assert_eq!(report["ag_spends"], 0);
    assert_eq!(report["docket_attempts"], 0);
    assert_eq!(report["settlements"], 0);
}

/// A campaign's deployment inputs are genesis facts, not later CLI choices.
/// Equal bytes at a different locator cannot replace the observation resolver
/// or catalog, and a post-spend caller cannot select a different Docket.
#[test]
#[ignore = "requires adjacent AG and Docket binaries; see module documentation"]
fn genesis_profile_rejects_authority_and_execution_substitution() {
    let bins = bins();
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

    let (policy, _, _) = example_policy_inputs_recurrence();
    let scope = policy.subject.scope.digest.clone();
    let rig = docket_rig(root.path(), &scope);
    let (ns_database, _) = build_store(root.path(), false, &[(0, 'd', true)], &rig.plan_value);
    let observation = observation_wrapper(root.path(), &ns_database);
    let mandate_store = root.path().join("mandates.json");
    write_jcs(
        &mandate_store,
        &mandate_store_json(vec![mandate_json(
            &scope,
            1,
            "active",
            wall_now_ms() + 3_600_000,
        )]),
    );
    let standing = standing_wrapper(&bins, root.path(), &mandate_store);
    let catalog = root.path().join("catalog.json");
    write_jcs(&catalog, &catalog_json(&scope, &["condition.clean"]));
    let docket_standing = docket_standing_script(root.path(), "current");
    let profile = runtime_profile(
        root.path(),
        "substitution-attack",
        &observation,
        &standing,
        &catalog,
        &docket_standing,
        &rig,
        &bins,
    );

    let database = root.path().join("ag.sqlite");
    let genesis = root.path().join("genesis.json");
    write_jcs(&genesis, &genesis_json(&rig.plan_identity));
    loopctl_ok(
        &bins,
        &str_args(&[
            "init",
            "--database",
            &database.display().to_string(),
            "--genesis",
            &genesis.display().to_string(),
            "--runtime-profile",
            &profile.display().to_string(),
        ]),
    );
    let proposal_input = root.path().join("proposal-input.json");
    write_jcs(
        &proposal_input,
        &proposal_input_json(&digest('d'), &scope, &rig.plan_identity),
    );
    let foreign_observation = root.path().join("foreign-observation-resolver");
    std::fs::copy(&observation, &foreign_observation).unwrap();
    std::fs::set_permissions(&foreign_observation, std::fs::Permissions::from_mode(0o700)).unwrap();
    let refused = loopctl_fail(
        &bins,
        &str_args(&[
            "record-proposal",
            "--database",
            &database.display().to_string(),
            "--input",
            &proposal_input.display().to_string(),
            "--observation-resolver",
            &foreign_observation.display().to_string(),
            "--expected-observation-resolver-id",
            OBSERVATION_RESOLVER_ID,
        ]),
    );
    assert!(String::from_utf8_lossy(&refused.stderr).contains("substituted pinned path"));
    assert_eq!(
        program_counter(&status(&bins, &database)),
        "observation_required"
    );

    loopctl_ok(
        &bins,
        &str_args(&[
            "record-proposal",
            "--database",
            &database.display().to_string(),
            "--input",
            &proposal_input.display().to_string(),
            "--observation-resolver",
            &observation.display().to_string(),
            "--expected-observation-resolver-id",
            OBSERVATION_RESOLVER_ID,
        ]),
    );
    require_standing(&bins, &database);

    let foreign_catalog = root.path().join("foreign-catalog.json");
    std::fs::copy(&catalog, &foreign_catalog).unwrap();
    let mut foreign_decide = str_args(&["decide", "--database", &database.display().to_string()]);
    foreign_decide.extend(gate_args(&foreign_catalog, &observation, &standing));
    let refused = loopctl_fail(&bins, &foreign_decide);
    assert!(String::from_utf8_lossy(&refused.stderr).contains("substituted pinned path"));
    assert_eq!(
        program_counter(&status(&bins, &database)),
        "standing_required"
    );

    let gate = gate_args(&catalog, &observation, &standing);
    let mut decide = str_args(&["decide", "--database", &database.display().to_string()]);
    decide.extend(gate.clone());
    loopctl_ok(&bins, &decide);
    let mut authorize = str_args(&["authorize", "--database", &database.display().to_string()]);
    authorize.extend(gate);
    loopctl_ok(&bins, &authorize);

    let mut docket = docket_args(
        root.path(),
        &rig.trust,
        &docket_standing,
        &rig.plan,
        &rig.issuer_key,
        &bins,
    );
    let docket_value = docket
        .iter()
        .position(|argument| argument == "--docket")
        .unwrap()
        + 1;
    docket[docket_value] = root.path().join("foreign-docket").display().to_string();
    let mut dispatch = str_args(&["dispatch", "--database", &database.display().to_string()]);
    dispatch.extend(docket);
    let refused = loopctl_fail(&bins, &dispatch);
    assert!(String::from_utf8_lossy(&refused.stderr)
        .contains("substituted the genesis-pinned Docket boundary"));
    assert!(!rig.target.exists());
    let report = replay(&bins, &database);
    assert_eq!(report["ag_spends"], 1);
    assert_eq!(report["docket_attempts"], 0);
}

/// The WO-9.1 attack test: Nightshift prepared plan P and AG's occurrence was
/// opened expecting P's identity. A caller submitting an otherwise valid
/// proposal naming foreign work is refused at record time; the bound work
/// still records informationally.
#[test]
#[ignore = "requires adjacent AG and Docket binaries; see module documentation"]
fn submitted_work_other_than_the_prepared_binding_is_rejected() {
    let bins = bins();
    let root = tempfile::tempdir().unwrap();

    let (policy, _, _) = example_policy_inputs_recurrence();
    let scope = policy.subject.scope.digest.clone();
    let rig = docket_rig(root.path(), &scope);
    let (ns_database, _) = build_store(root.path(), false, &[(0, 'd', true)], &rig.plan_value);
    let observation = observation_wrapper(root.path(), &ns_database);
    let mandate_store = root.path().join("mandates.json");
    write_jcs(
        &mandate_store,
        &mandate_store_json(vec![mandate_json(
            &scope,
            1,
            "active",
            wall_now_ms() + 3_600_000,
        )]),
    );
    let standing = standing_wrapper(&bins, root.path(), &mandate_store);
    let catalog = root.path().join("catalog.json");
    write_jcs(&catalog, &catalog_json(&scope, &["condition.clean"]));
    let docket_standing = docket_standing_script(root.path(), "current");
    let profile = runtime_profile(
        root.path(),
        "work-binding",
        &observation,
        &standing,
        &catalog,
        &docket_standing,
        &rig,
        &bins,
    );

    let ag_database = root.path().join("ag.sqlite");
    let genesis = root.path().join("genesis.json");
    write_jcs(&genesis, &genesis_json(&rig.plan_identity));
    loopctl_ok(
        &bins,
        &str_args(&[
            "init",
            "--database",
            &ag_database.display().to_string(),
            "--genesis",
            &genesis.display().to_string(),
            "--runtime-profile",
            &profile.display().to_string(),
        ]),
    );

    // Foreign work: a validly shaped proposal naming a digest the occurrence
    // was never opened to govern.
    let proposal_input = root.path().join("proposal-input.json");
    write_jcs(
        &proposal_input,
        &proposal_input_json(&digest('d'), &scope, &digest('9')),
    );
    let record_args = str_args(&[
        "record-proposal",
        "--database",
        &ag_database.display().to_string(),
        "--input",
        &proposal_input.display().to_string(),
        "--observation-resolver",
        &observation.display().to_string(),
        "--expected-observation-resolver-id",
        OBSERVATION_RESOLVER_ID,
    ]);
    let refusal = loopctl_fail(&bins, &record_args);
    assert!(
        String::from_utf8_lossy(&refusal.stderr).contains("binding mismatch"),
        "expected an exact-binding failure: {}",
        String::from_utf8_lossy(&refusal.stderr)
    );
    let snapshot = status(&bins, &ag_database);
    assert_eq!(program_counter(&snapshot), "observation_required");
    let report = replay(&bins, &ag_database);
    assert_eq!(report["ag_spends"], 0);

    // The exact prepared work records.
    write_jcs(
        &proposal_input,
        &proposal_input_json(&digest('d'), &scope, &rig.plan_identity),
    );
    let recorded = loopctl_ok(&bins, &record_args);
    assert_eq!(program_counter(&recorded), "proposal_recorded");
}

/// The disposable cache design crosses Maude custody, Nightshift lineage, AG
/// authorization, Docket custody, exact execution, successor authority, and
/// governed teardown. Exact compiler artifacts arrive through environment
/// coordinates; this test never interprets PlanDocument prose.
#[test]
#[ignore = "requires adjacent AG/Docket binaries, Maude exact artifacts, and local Docker"]
fn synthetic_cache_design_qualifies_and_tears_down_through_governed_runtime() {
    let bins = bins();
    let root = PathBuf::from(
        std::env::var_os("SYNTHETIC_CACHE_GOVERNED_ROOT").expect("SYNTHETIC_CACHE_GOVERNED_ROOT"),
    );
    assert!(root.is_absolute());
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        !root.join("ag.sqlite").exists(),
        "governed root must be fresh"
    );

    let exact_path = |name: &str| {
        let path = PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name}")));
        assert!(
            path.is_absolute() && path.is_file(),
            "missing exact input: {path:?}"
        );
        path
    };
    let qualify_plan_path = exact_path("SYNTHETIC_CACHE_QUALIFY_PLAN");
    let teardown_plan_path = exact_path("SYNTHETIC_CACHE_TEARDOWN_PLAN");
    let qualify_handoff_path = exact_path("SYNTHETIC_CACHE_QUALIFY_HANDOFF");
    let teardown_handoff_path = exact_path("SYNTHETIC_CACHE_TEARDOWN_HANDOFF");
    let qualify_compilation_path = exact_path("SYNTHETIC_CACHE_QUALIFY_COMPILATION_RECEIPT");
    let locked_plan = exact_path("SYNTHETIC_CACHE_LOCKED_PLAN");
    let c2_qualify_plan_path = exact_path("SYNTHETIC_CACHE_C2_QUALIFY_PLAN");
    let c2_teardown_plan_path = exact_path("SYNTHETIC_CACHE_C2_TEARDOWN_PLAN");
    let c2_qualify_handoff_path = exact_path("SYNTHETIC_CACHE_C2_QUALIFY_HANDOFF");
    let c2_teardown_handoff_path = exact_path("SYNTHETIC_CACHE_C2_TEARDOWN_HANDOFF");
    let c2_qualify_compilation_path = exact_path("SYNTHETIC_CACHE_C2_QUALIFY_COMPILATION_RECEIPT");
    let c2_locked_plan = exact_path("SYNTHETIC_CACHE_C2_LOCKED_PLAN");
    let executor = exact_path("SYNTHETIC_CACHE_EXECUTOR");

    let qualify_handoff_bytes = std::fs::read(&qualify_handoff_path).unwrap();
    let qualify_handoff: serde_json::Value =
        serde_json::from_slice(&qualify_handoff_bytes).unwrap();
    assert_eq!(
        serde_jcs::to_vec(&qualify_handoff).unwrap(),
        qualify_handoff_bytes
    );
    let teardown_handoff_bytes = std::fs::read(&teardown_handoff_path).unwrap();
    let teardown_handoff: serde_json::Value =
        serde_json::from_slice(&teardown_handoff_bytes).unwrap();
    assert_eq!(
        serde_jcs::to_vec(&teardown_handoff).unwrap(),
        teardown_handoff_bytes
    );
    let qualify_proposal: PrecompiledWorkflowProposalV2 =
        serde_json::from_value(qualify_handoff.clone()).unwrap();
    let teardown_proposal: PrecompiledWorkflowProposalV2 =
        serde_json::from_value(teardown_handoff.clone()).unwrap();
    let qualify_rig = external_docket_rig(&root, &qualify_plan_path);
    let teardown_plan: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&teardown_plan_path).unwrap()).unwrap();
    let teardown_work = ag_executor_plan_identity(&teardown_plan).unwrap();
    assert_eq!(
        qualify_rig.plan_identity,
        ag_executor_plan_identity(&qualify_proposal.ag_executor_plan).unwrap()
    );
    assert_eq!(
        teardown_work,
        ag_executor_plan_identity(&teardown_proposal.ag_executor_plan).unwrap()
    );
    assert_ne!(qualify_rig.plan_identity, teardown_work);

    let session_key = root.join("maude-session.key");
    let producer_key = root.join("maude-producer.key");
    std::fs::write(&session_key, [0x31_u8; 32]).unwrap();
    std::fs::write(&producer_key, [0x62_u8; 32]).unwrap();
    std::fs::set_permissions(&session_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&producer_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let custody_store = root.join("maude-custody.sqlite");
    let verifier = MaudeCustodyVerifierV1::from_key_file(
        "maude-handoff:synthetic-local".into(),
        "maude-handoff-key:synthetic-v1".into(),
        "maude:synthetic-supervisor".into(),
        "maude-session-key:synthetic-v1".into(),
        "nightshift:synthetic-local-v1".into(),
        &producer_key,
        &session_key,
    )
    .unwrap();

    let feedback_first_due = Utc::now() - chrono::Duration::seconds(60);
    let (policy, clean_inputs, clean_recurrence) = fresh_policy_inputs_recurrence(
        feedback_first_due,
        0,
        feedback_first_due + chrono::Duration::seconds(4),
    );
    let scope = policy.subject.scope.digest.clone();
    assert_eq!(qualify_proposal.subject_digest, SUBJECT_DIGEST);
    assert_eq!(
        qualify_handoff["proposal_input"]["proposal"]["scope"],
        scope
    );
    let base = request_for_precompiled_fresh(
        &policy,
        &clean_inputs,
        &clean_recurrence,
        0,
        feedback_first_due + chrono::Duration::seconds(10),
        &digest('d'),
        qualify_proposal,
    );
    let initial_request = attach_synthetic_maude_handoff(
        &root,
        "qualify",
        base,
        &locked_plan,
        &custody_store,
        &session_key,
        &producer_key,
        "sess_synthetic_cache_qualify",
    );
    let ns_database = root.join("nightshift.sqlite");
    let first_cycle_id = {
        let mut store = CanonicalStore::open(&ns_database).unwrap();
        let mut support = SupportPort;
        let mut ag = FakeAg;
        let outcome = CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag)
            .run_cycle_with_authoring_custody(initial_request.clone(), &verifier)
            .unwrap();
        let CycleRunOutcomeV1::AgOccurrenceOpened { cycle } = outcome else {
            panic!("exact initial synthetic cycle did not open an occurrence");
        };
        assert!(cycle.authoring_context_provenance.is_some());
        assert!(cycle.authoring_context_custody.is_some());
        cycle.cycle_id
    };
    {
        let mut reopened = CanonicalStore::open(&ns_database).unwrap();
        let mut support = SupportPort;
        let mut ag = FakeAg;
        let replayed =
            CanonicalRuntime::new(&mut reopened, TestNqAdmissionPort, &mut support, &mut ag)
                .run_cycle_with_authoring_custody(initial_request, &verifier)
                .unwrap_err();
        assert!(matches!(
            replayed,
            CanonicalRuntimeError::Store(CanonicalStoreError::DuplicateSlot(_))
        ));
        let cycles = reopened.list_cycles().unwrap();
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0].cycle_id, first_cycle_id);
    }

    let observation = observation_wrapper(&root, &ns_database);
    let subject = qualify_handoff["subject_digest"].as_str().unwrap();
    let work_schema = qualify_handoff["proposal_input"]["proposal"]["work_schema"]
        .as_str()
        .unwrap();
    let mandate_store = root.join("mandates.json");
    write_jcs(
        &mandate_store,
        &mandate_store_json(vec![mandate_json_for(
            subject,
            &scope,
            1,
            "active",
            wall_now_ms() + 3_600_000,
        )]),
    );
    let standing = standing_wrapper(&bins, &root, &mandate_store);
    let catalog = root.join("catalog.json");
    write_jcs(
        &catalog,
        &catalog_json_for(work_schema, subject, &scope, &["condition.clean"]),
    );
    let docket_standing = docket_standing_script(&root, "current");
    let profile = runtime_profile_for_executor(
        &root,
        "synthetic-cache",
        &observation,
        &standing,
        &catalog,
        &docket_standing,
        &qualify_rig,
        &executor,
        &bins,
    );
    let ag_database = root.join("ag.sqlite");
    let recorded = init_and_record_precompiled(
        &bins,
        &root,
        &ag_database,
        &observation,
        &profile,
        &qualify_handoff,
    );
    assert_eq!(
        recorded["state"]["proposal_recorded"]["observation"]["status"],
        "current"
    );
    require_standing(&bins, &ag_database);
    let gate = gate_args(&catalog, &observation, &standing);
    let mut decide = str_args(&["decide", "--database", &ag_database.display().to_string()]);
    decide.extend(gate.clone());
    assert_eq!(
        program_counter(&loopctl_ok(&bins, &decide)),
        "admissible_pending_authorization"
    );
    let mut authorize = str_args(&[
        "authorize",
        "--database",
        &ag_database.display().to_string(),
    ]);
    authorize.extend(gate.clone());
    assert_eq!(
        program_counter(&loopctl_ok(&bins, &authorize)),
        "authorization_consumed"
    );
    let qualify_docket = docket_args_for_executor(
        &root,
        &qualify_rig.trust,
        &docket_standing,
        &qualify_plan_path,
        &qualify_rig.issuer_key,
        &executor,
        &bins,
    );
    let mut dispatch = str_args(&["dispatch", "--database", &ag_database.display().to_string()]);
    dispatch.extend(qualify_docket.clone());
    assert_eq!(program_counter(&loopctl_ok(&bins, &dispatch)), "dispatched");
    let mut poll = str_args(&["poll", "--database", &ag_database.display().to_string()]);
    poll.extend(qualify_docket);
    let qualify_settled = loopctl_ok(&bins, &poll);
    assert_eq!(
        program_counter(&qualify_settled),
        "settled_observation_required"
    );

    // Build the exact PlanNode -> governed execution projection needed by the
    // Maude workflow observation adapter. Every coordinate is taken from an
    // owner record; no description, timestamp, or list position is joined.
    let compilation: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&qualify_compilation_path).unwrap()).unwrap();
    let issuance = qualify_settled
        .pointer("/state/settled_observation_required/dispatch/authorized/issuance")
        .unwrap();
    let docket_custody = qualify_settled
        .pointer("/state/settled_observation_required/dispatch/custody")
        .unwrap();
    let settlement = qualify_settled
        .pointer("/state/settled_observation_required/settlement")
        .unwrap();
    let first_cycle = CanonicalStore::open(&ns_database)
        .unwrap()
        .list_cycles()
        .unwrap()
        .into_iter()
        .find(|cycle| cycle.cycle_id == first_cycle_id)
        .unwrap();
    let lineage = first_cycle.authoring_context_provenance.as_ref().unwrap();
    let authoring_custody = first_cycle.authoring_context_custody.as_ref().unwrap();
    let campaign_id = issuance["key"]["campaign"].as_str().unwrap();
    let occurrence_id = issuance["key"]["occurrence"].as_str().unwrap();
    let proposal_id = issuance["proposal"].as_str().unwrap();
    let exact_work_id = issuance["work"].as_str().unwrap();
    let attempt_id = docket_custody["attempt"].as_str().unwrap();
    let settlement_id = settlement["settlement"].as_str().unwrap();
    assert_eq!(lineage.campaign_id, campaign_id);
    assert_eq!(lineage.occurrence_id, occurrence_id);
    assert_eq!(lineage.proposal_id, proposal_id);
    assert_eq!(lineage.exact_work_id, exact_work_id);
    let inspector_path = format!(
        "/phosphor-ng/campaigns/{}/occurrences/{}/proposals/{}",
        campaign_id.replace(':', "%3A"),
        occurrence_id,
        proposal_id.replace(':', "%3A")
    );
    let bindings = compilation["node_bindings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|node| {
            let mut binding = serde_json::json!({
                "schema": "maude.plan-node-governed-binding/v1",
                "binding_id": "",
                "draft_id": compilation["draft_id"],
                "node_id": node["node_id"],
                "plan_digest": compilation["plan_digest"],
                "compilation_id": compilation["compilation_id"],
                "compiled_output_identity": node["output_identity"],
                "exact_work_identity": exact_work_id,
                "authoring_provenance_id": lineage.provenance_id,
                "handoff_id": authoring_custody.handoff_id,
                "campaign_id": campaign_id,
                "occurrence_id": occurrence_id,
                "proposal_id": proposal_id,
                "issuance_id": issuance["issuance"],
                "docket_attempt_id": attempt_id,
                "settlement_id": settlement_id,
                "outcome": settlement["outcome"],
                "inspector_path": inspector_path,
            });
            let mut preimage = binding.clone();
            preimage.as_object_mut().unwrap().remove("binding_id");
            binding["binding_id"] = serde_json::json!(digest_value(&preimage));
            binding
        })
        .collect::<Vec<_>>();
    let governed_bindings_path = root.join("qualify-governed-cross-probe.json");
    write_jcs(
        &governed_bindings_path,
        &serde_json::json!({
            "schema": "maude.plan-governed-cross-probe/v1",
            "bindings": bindings,
        }),
    );

    let observed_at_unix_ms = {
        let evidence_path = PathBuf::from(
            qualify_handoff["ag_executor_plan"]["workspace"]
                .as_str()
                .unwrap(),
        )
        .join("evidence/attempts")
        .join(format!("{}.json", attempt_id.trim_start_matches("sha256:")));
        let evidence: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&evidence_path).unwrap()).unwrap();
        let observed_at = evidence["observed_at_unix_ms"].as_i64().unwrap();
        let observer_key = root.join("maude-observer.key");
        std::fs::write(&observer_key, [0x43_u8; 32]).unwrap();
        std::fs::set_permissions(&observer_key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let external_profile = ExternalEvidenceProfileV1 {
            schema: EXTERNAL_EVIDENCE_PROFILE_SCHEMA_V1.into(),
            profile_id: String::new(),
            purpose: ExternalEvidencePurposeV1::PostSettlementSuccessor,
            expected_adapter_id: "maude.local-compose-observation-adapter".into(),
            expected_adapter_version: "1".into(),
            expected_producer_principal_id: "maude-observer:synthetic-local".into(),
            expected_producer_key_id: "maude-observer-key:synthetic-v1".into(),
            expected_runtime_id: "nightshift:synthetic-local-v1".into(),
            required_action: LocalComposeActionV1::Qualify,
            required_claims: vec![
                LocalComposeClaimKindV1::FrontDoorReachable,
                LocalComposeClaimKindV1::CacheMissThenHit,
                LocalComposeClaimKindV1::SingleCacheFailureSurvived,
                LocalComposeClaimKindV1::CacheTopologyRestored,
            ],
            max_age_ms: 120_000,
        }
        .seal()
        .unwrap();
        let external_profile_path = root.join("external-evidence-profile.json");
        write_jcs(
            &external_profile_path,
            &serde_json::to_value(&external_profile).unwrap(),
        );
        let acquisition_ledger = root.join("observation-acquisition.sqlite");
        let docket_state = root.join("docket-state");
        let output = Command::new(std::env::var_os("MAUDE_PYTHON").expect("MAUDE_PYTHON"))
            .args([
                "-m",
                "maude.plan.observation_acquisition",
                "orchestrate-post-settlement",
            ])
            .args(["--ledger", acquisition_ledger.to_str().unwrap()])
            .args(["--docket-program", bins.docket.to_str().unwrap()])
            .args(["--docket-state", docket_state.to_str().unwrap()])
            .args(["--issuance", issuance["issuance"].as_str().unwrap()])
            .args(["--executor-evidence", evidence_path.to_str().unwrap()])
            .args(["--executor-plan", qualify_plan_path.to_str().unwrap()])
            .args([
                "--compilation-receipt",
                qualify_compilation_path.to_str().unwrap(),
            ])
            .args([
                "--governed-bindings",
                governed_bindings_path.to_str().unwrap(),
            ])
            .args([
                "--external-profile",
                external_profile_path.to_str().unwrap(),
            ])
            .args(["--target-runtime-id", "nightshift:synthetic-local-v1"])
            .args(["--producer-key", observer_key.to_str().unwrap()])
            .args(["--producer-principal-id", "maude-observer:synthetic-local"])
            .args(["--producer-key-id", "maude-observer-key:synthetic-v1"])
            .args(["--nightshift-program", env!("CARGO_BIN_EXE_nightshift")])
            .args(["--nightshift-store", ns_database.to_str().unwrap()])
            .args(["--nightshift-credential", observer_key.to_str().unwrap()])
            .args(["--nightshift-runtime-id", "nightshift:synthetic-local-v1"])
            .env(
                "PYTHONPATH",
                std::env::var_os("MAUDE_SRC").expect("MAUDE_SRC"),
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "Maude observation acquisition orchestration failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let acquisition: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            acquisition["events"]
                .as_array()
                .unwrap()
                .iter()
                .map(|event| event["kind"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec![
                "trigger_recorded",
                "acquisition_scheduled",
                "adapter_invocation_started",
                "adapter_returned_evidence",
                "custody_accepted",
            ]
        );
        write_jcs(&root.join("observation-acquisition.json"), &acquisition);
        let handoff_value = acquisition
            .pointer("/evidence/handoff")
            .expect("orchestration retained exact handoff")
            .clone();
        write_jcs(
            &root.join("external-observation-qualify.json"),
            &handoff_value,
        );
        let handoff: ExternalObservationHandoffV1 = serde_json::from_value(handoff_value).unwrap();
        let external_verifier = ExternalObservationVerifierV1::from_key_file(
            "maude-observer:synthetic-local".into(),
            "maude-observer-key:synthetic-v1".into(),
            "nightshift:synthetic-local-v1".into(),
            &observer_key,
        )
        .unwrap();
        external_verifier.verify(&handoff).unwrap();
        let store = CanonicalStore::open(&ns_database).unwrap();
        let external_export = store
            .export_external_observation(
                ExternalObservationQueryV1::Observation {
                    observation_id: handoff.observation.observation_id.clone(),
                },
                observed_at + 120_000,
                120_000,
            )
            .unwrap();
        assert_eq!(external_export.matches.len(), 1);
        let external_custody = &external_export.matches[0].custody;

        // The strong effectful evidence remains Q. A separate passive adapter
        // first establishes S1 from an owner-produced `absent` basis, then S2
        // from the exact exclusive stale boundary. Neither acquisition can
        // represent or repeat the failure test.
        let steady_profile = SteadyStateEvidenceProfileV1 {
            schema: String::new(),
            profile_id: String::new(),
            purpose: SteadyStateEvidencePurposeV1::RoutineContinuation,
            qualification_profile: external_profile.clone(),
            expected_adapter_id: "maude.local-compose-steady-state-observation-adapter".into(),
            expected_adapter_version: "1".into(),
            expected_producer_principal_id: "maude-observer:synthetic-local".into(),
            expected_producer_key_id: "maude-observer-key:synthetic-v1".into(),
            expected_runtime_id: "nightshift:synthetic-local-v1".into(),
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
            max_age_ms: 5_000,
        }
        .seal()
        .unwrap();
        let steady_profile_path = root.join("steady-state-evidence-profile.json");
        write_jcs(
            &steady_profile_path,
            &serde_json::to_value(&steady_profile).unwrap(),
        );
        let absent_basis = store
            .steady_state_reobservation_basis(
                &handoff.observation.observation_id,
                &steady_profile,
                u64::try_from(external_custody.received_at.timestamp_millis()).unwrap(),
            )
            .unwrap();
        assert_eq!(
            serde_json::to_value(&absent_basis).unwrap()["requirement"],
            "absent"
        );
        let absent_basis_path = root.join("steady-state-basis-absent.json");
        write_jcs(
            &absent_basis_path,
            &serde_json::to_value(&absent_basis).unwrap(),
        );

        let run_passive = |command: &str, basis: &Path| {
            let output = Command::new(std::env::var_os("MAUDE_PYTHON").unwrap())
                .args(["-m", "maude.plan.observation_acquisition", command])
                .args(["--ledger", acquisition_ledger.to_str().unwrap()])
                .args(["--docket-program", bins.docket.to_str().unwrap()])
                .args(["--docket-state", docket_state.to_str().unwrap()])
                .args(["--issuance", issuance["issuance"].as_str().unwrap()])
                .args(["--executor-evidence", evidence_path.to_str().unwrap()])
                .args(["--executor-plan", qualify_plan_path.to_str().unwrap()])
                .args([
                    "--compilation-receipt",
                    qualify_compilation_path.to_str().unwrap(),
                ])
                .args([
                    "--governed-bindings",
                    governed_bindings_path.to_str().unwrap(),
                ])
                .args(["--external-profile", steady_profile_path.to_str().unwrap()])
                .args(["--reobservation-basis", basis.to_str().unwrap()])
                .args(["--target-runtime-id", "nightshift:synthetic-local-v1"])
                .args(["--producer-key", observer_key.to_str().unwrap()])
                .args(["--producer-principal-id", "maude-observer:synthetic-local"])
                .args(["--producer-key-id", "maude-observer-key:synthetic-v1"])
                .args(["--nightshift-program", env!("CARGO_BIN_EXE_nightshift")])
                .args(["--nightshift-store", ns_database.to_str().unwrap()])
                .args(["--nightshift-credential", observer_key.to_str().unwrap()])
                .args(["--nightshift-runtime-id", "nightshift:synthetic-local-v1"])
                .env("PYTHONPATH", std::env::var_os("MAUDE_SRC").unwrap())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "passive acquisition failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
        };
        let passive_s1 = run_passive("orchestrate-reobserve-for-successor", &absent_basis_path);
        let s1_observed_at = passive_s1
            .pointer("/evidence/handoff/observation/observed_at_unix_ms")
            .and_then(serde_json::Value::as_u64)
            .unwrap();
        let s1_observation_id = passive_s1
            .pointer("/evidence/handoff/observation/observation_id")
            .and_then(serde_json::Value::as_str)
            .unwrap()
            .to_owned();
        assert!(!passive_s1
            .pointer("/evidence/handoff/observation")
            .unwrap()
            .to_string()
            .contains("single_cache_failure_survived"));
        let stale_at = s1_observed_at + steady_profile.max_age_ms;
        let wall_now = u64::try_from(Utc::now().timestamp_millis()).unwrap();
        if wall_now < stale_at {
            std::thread::sleep(std::time::Duration::from_millis(stale_at - wall_now + 1));
        }
        let stale_basis = CanonicalStore::open(&ns_database)
            .unwrap()
            .steady_state_reobservation_basis(
                &handoff.observation.observation_id,
                &steady_profile,
                stale_at,
            )
            .unwrap();
        assert_eq!(
            serde_json::to_value(&stale_basis).unwrap()["requirement"],
            "stale"
        );
        assert_eq!(
            stale_basis.qualification_observation_id,
            absent_basis.qualification_observation_id
        );
        let stale_basis_path = root.join("steady-state-basis-stale.json");
        write_jcs(
            &stale_basis_path,
            &serde_json::to_value(&stale_basis).unwrap(),
        );
        let passive_s2 = run_passive("orchestrate-reobserve-after-stale", &stale_basis_path);
        let s2_observation_id = passive_s2
            .pointer("/evidence/handoff/observation/observation_id")
            .and_then(serde_json::Value::as_str)
            .unwrap()
            .to_owned();
        let s2_custody_id = passive_s2
            .get("events")
            .and_then(serde_json::Value::as_array)
            .and_then(|events| events.last())
            .and_then(|event| event.get("custody_id"))
            .and_then(serde_json::Value::as_str)
            .unwrap()
            .to_owned();
        assert_ne!(s1_observation_id, s2_observation_id);
        write_jcs(&root.join("passive-acquisition-s1.json"), &passive_s1);
        write_jcs(&root.join("passive-acquisition-s2.json"), &passive_s2);

        let successor_evaluated_at = Utc::now() + chrono::Duration::milliseconds(10);
        let diagnostic_occurrence = scheduled_occurrence_at(
            feedback_first_due,
            successor_evaluated_at,
            clean_recurrence.obligations[0].policy.cadence_seconds,
        );
        let (next_policy, next_inputs, next_recurrence) = fresh_policy_inputs_recurrence(
            feedback_first_due,
            diagnostic_occurrence,
            successor_evaluated_at - chrono::Duration::seconds(1),
        );
        assert_eq!(next_policy.policy_id, policy.policy_id);
        let mut successor_base = request_for_precompiled_fresh(
            &next_policy,
            &next_inputs,
            &next_recurrence,
            diagnostic_occurrence,
            successor_evaluated_at,
            &digest('e'),
            teardown_proposal.clone(),
        );
        successor_base.decision_external_evidence = Some(DecisionRelativeEvidenceReferenceV1 {
            schema: DECISION_EVIDENCE_REFERENCE_SCHEMA_V1.into(),
            qualification_observation_id: handoff.observation.observation_id.clone(),
            qualification_custody_id: external_custody.custody_id.clone(),
            steady_state_observation_id: s2_observation_id,
            steady_state_custody_id: s2_custody_id,
            profile_id: steady_profile.profile_id.clone(),
        });
        successor_base = successor_base.seal().unwrap();
        let successor_base =
            prepare_decision_evidence_cycle_request(&store, successor_base, &steady_profile)
                .unwrap();
        let successor_request = attach_synthetic_maude_handoff(
            &root,
            "teardown",
            successor_base,
            &locked_plan,
            &custody_store,
            &session_key,
            &producer_key,
            "sess_synthetic_cache_teardown",
        );
        drop(store);

        let mut store = CanonicalStore::open(&ns_database).unwrap();
        let mut support = SupportPort;
        let mut ag = AgLoopCtlPortV1::new(
            &bins.loopctl,
            &ag_database,
            &observation,
            OBSERVATION_RESOLVER_ID,
            &profile,
        )
        .unwrap();
        let outcome = CanonicalRuntime::new_with_decision_evidence_profile(
            &mut store,
            TestNqAdmissionPort,
            &mut support,
            &mut ag,
            steady_profile,
        )
        .unwrap()
        .run_cycle_with_authoring_custody(successor_request, &verifier)
        .unwrap();
        let CycleRunOutcomeV1::AgOccurrenceOpened { cycle } = outcome else {
            panic!("fresh composed teardown successor did not enter AG");
        };
        let composed = cycle
            .observation
            .as_ref()
            .unwrap()
            .decision_external_evidence
            .as_ref()
            .unwrap();
        assert_eq!(composed.qualification.occurrence_id, occurrence_uuid(0));
        assert_eq!(composed.target_occurrence_id, occurrence_uuid(1));
        assert_eq!(
            composed.qualification.acquired_at_unix_ms,
            u64::try_from(observed_at).unwrap()
        );
        assert!(composed.steady_state_claims.iter().all(|claim| claim.kind
            != SteadyStateClaimKindV1::FrontDoorReachable
            || claim.plan_node_id == "pn_health"));
        assert_eq!(cycle.ag.as_ref().unwrap().occurrence_id, occurrence_uuid(1));
        write_jcs(
            &root.join("external-composition.json"),
            &serde_json::to_value(composed).unwrap(),
        );
        observed_at
    };
    assert!(observed_at_unix_ms > 0);
    require_standing(&bins, &ag_database);
    let mut decide = str_args(&["decide", "--database", &ag_database.display().to_string()]);
    decide.extend(gate.clone());
    assert_eq!(
        program_counter(&loopctl_ok(&bins, &decide)),
        "admissible_pending_authorization"
    );
    let mut authorize = str_args(&[
        "authorize",
        "--database",
        &ag_database.display().to_string(),
    ]);
    authorize.extend(gate);
    assert_eq!(
        program_counter(&loopctl_ok(&bins, &authorize)),
        "authorization_consumed"
    );
    let teardown_docket = docket_args_for_executor(
        &root,
        &qualify_rig.trust,
        &docket_standing,
        &teardown_plan_path,
        &qualify_rig.issuer_key,
        &executor,
        &bins,
    );
    let mut dispatch = str_args(&["dispatch", "--database", &ag_database.display().to_string()]);
    dispatch.extend(teardown_docket.clone());
    assert_eq!(program_counter(&loopctl_ok(&bins, &dispatch)), "dispatched");
    let mut poll = str_args(&["poll", "--database", &ag_database.display().to_string()]);
    poll.extend(teardown_docket);
    let final_state = loopctl_ok(&bins, &poll);
    assert_eq!(
        program_counter(&final_state),
        "settled_observation_required"
    );
    let report = replay(&bins, &ag_database);
    assert_eq!(report["ag_spends"], 2);
    assert_eq!(report["docket_attempts"], 2);
    assert_eq!(report["settlements"], 2);

    let store = CanonicalStore::open(&ns_database).unwrap();
    let cycles = store.list_cycles().unwrap();
    let lineage: Vec<_> = cycles
        .iter()
        .filter_map(|cycle| cycle.authoring_context_provenance.as_ref())
        .collect();
    let custody: Vec<_> = cycles
        .iter()
        .filter_map(|cycle| cycle.authoring_context_custody.as_ref())
        .collect();
    assert_eq!(lineage.len(), 2);
    assert_eq!(custody.len(), 2);
    assert_eq!(lineage[0].maude_plan_ref, lineage[1].maude_plan_ref);
    assert_ne!(lineage[0].provenance_id, lineage[1].provenance_id);
    assert_ne!(custody[0].handoff_id, custody[1].handoff_id);
    write_jcs(
        &root.join("synthetic-governed-qualification.json"),
        &serde_json::json!({
            "schema": "nightshift.synthetic-cache-governed-qualification/v1",
            "ag_database": ag_database,
            "nightshift_database": ns_database,
            "qualify_exact_work": qualify_rig.plan_identity,
            "teardown_exact_work": teardown_work,
            "ag_replay": report,
            "authoring_lineage": lineage,
            "authoring_custody": custody,
            "final_state": final_state,
        }),
    );

    // C2 is an ordinary locked PlanDocument successor compiled for a distinct
    // exact Compose project. Stable node IDs survive, but plan, compilation,
    // work, handoff, and runtime project identities do not.
    let c2_qualify_handoff_bytes = std::fs::read(&c2_qualify_handoff_path).unwrap();
    let c2_qualify_handoff: serde_json::Value =
        serde_json::from_slice(&c2_qualify_handoff_bytes).unwrap();
    assert_eq!(
        serde_jcs::to_vec(&c2_qualify_handoff).unwrap(),
        c2_qualify_handoff_bytes
    );
    let c2_teardown_handoff: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&c2_teardown_handoff_path).unwrap()).unwrap();
    let c2_qualify_proposal: PrecompiledWorkflowProposalV2 =
        serde_json::from_value(c2_qualify_handoff.clone()).unwrap();
    let c2_teardown_proposal: PrecompiledWorkflowProposalV2 =
        serde_json::from_value(c2_teardown_handoff.clone()).unwrap();
    let c2_qualify_plan: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&c2_qualify_plan_path).unwrap()).unwrap();
    let c2_teardown_plan: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&c2_teardown_plan_path).unwrap()).unwrap();
    let c2_qualify_work = ag_executor_plan_identity(&c2_qualify_plan).unwrap();
    let c2_teardown_work = ag_executor_plan_identity(&c2_teardown_plan).unwrap();
    let c1_plan_digest = qualify_handoff["immutable_parameters"]["plan_document"]
        .as_str()
        .unwrap();
    let c2_plan_digest = c2_qualify_handoff["immutable_parameters"]["plan_document"]
        .as_str()
        .unwrap();
    assert_ne!(c1_plan_digest, c2_plan_digest);
    assert_ne!(qualify_rig.plan_identity, c2_qualify_work);
    assert_ne!(teardown_work, c2_teardown_work);
    assert_eq!(c2_qualify_plan["project_name"], "maude-cache-birthday-c2");

    // Reusing Q1/S2 with the C2 exact handoff refuses by the target artifact
    // digest before an AG occurrence or spend can be created.
    let q1_handoff: ExternalObservationHandoffV1 = serde_json::from_slice(
        &std::fs::read(root.join("external-observation-qualify.json")).unwrap(),
    )
    .unwrap();
    let c1_profile: ExternalEvidenceProfileV1 = serde_json::from_slice(
        &std::fs::read(root.join("external-evidence-profile.json")).unwrap(),
    )
    .unwrap();
    let c1_steady_profile: SteadyStateEvidenceProfileV1 = serde_json::from_slice(
        &std::fs::read(root.join("steady-state-evidence-profile.json")).unwrap(),
    )
    .unwrap();
    let passive_s2: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("passive-acquisition-s2.json")).unwrap())
            .unwrap();
    let s2_observation_id = passive_s2
        .pointer("/evidence/handoff/observation/observation_id")
        .and_then(serde_json::Value::as_str)
        .unwrap()
        .to_owned();
    let s2_custody_id = passive_s2
        .get("events")
        .and_then(serde_json::Value::as_array)
        .and_then(|events| events.last())
        .and_then(|event| event.get("custody_id"))
        .and_then(serde_json::Value::as_str)
        .unwrap()
        .to_owned();
    let c2_refusal_evaluated_at = Utc::now() + chrono::Duration::milliseconds(10);
    let c2_refusal_occurrence = scheduled_occurrence_at(
        feedback_first_due,
        c2_refusal_evaluated_at,
        clean_recurrence.obligations[0].policy.cadence_seconds,
    );
    let (refusal_policy, refusal_inputs, refusal_recurrence) = fresh_policy_inputs_recurrence(
        feedback_first_due,
        c2_refusal_occurrence,
        c2_refusal_evaluated_at - chrono::Duration::seconds(1),
    );
    let mut c2_with_q1 = request_for_precompiled_fresh(
        &refusal_policy,
        &refusal_inputs,
        &refusal_recurrence,
        c2_refusal_occurrence,
        c2_refusal_evaluated_at,
        &digest('6'),
        c2_qualify_proposal.clone(),
    );
    let c1_store = CanonicalStore::open(&ns_database).unwrap();
    let q1_export = c1_store
        .export_external_observation(
            ExternalObservationQueryV1::Observation {
                observation_id: q1_handoff.observation.observation_id.clone(),
            },
            Utc::now().timestamp_millis(),
            120_000,
        )
        .unwrap()
        .matches;
    assert_eq!(q1_export.len(), 1);
    let q1_custody = q1_export[0].custody.clone();
    c2_with_q1.decision_external_evidence = Some(DecisionRelativeEvidenceReferenceV1 {
        schema: DECISION_EVIDENCE_REFERENCE_SCHEMA_V1.into(),
        qualification_observation_id: q1_handoff.observation.observation_id.clone(),
        qualification_custody_id: q1_custody.custody_id,
        steady_state_observation_id: s2_observation_id,
        steady_state_custody_id: s2_custody_id,
        profile_id: c1_steady_profile.profile_id.clone(),
    });
    let q1_refusal =
        prepare_decision_evidence_cycle_request(&c1_store, c2_with_q1, &c1_steady_profile)
            .unwrap_err();
    assert!(q1_refusal
        .to_string()
        .contains("qualification does not apply to the target PlanDocument"));
    drop(c1_store);
    assert_eq!(replay(&bins, &ag_database)["ag_spends"], 2);

    // The qualification request originates as a new exact C2 PlanDocument
    // handoff and an ordinary fresh Nightshift proposal. Missing Q never calls
    // the effectful adapter or creates this occurrence.
    let c2_slot_store = CanonicalStore::open(&ns_database).unwrap();
    let (c2_diagnostic_occurrence, c2_evaluated_at) = next_unused_scheduled_occurrence(
        &c2_slot_store,
        feedback_first_due,
        clean_recurrence.obligations[0].policy.cadence_seconds,
    );
    drop(c2_slot_store);
    let (c2_policy, c2_inputs, c2_recurrence) = fresh_policy_inputs_recurrence(
        feedback_first_due,
        c2_diagnostic_occurrence,
        c2_evaluated_at - chrono::Duration::seconds(1),
    );
    let c2_base = request_for_precompiled_fresh(
        &c2_policy,
        &c2_inputs,
        &c2_recurrence,
        c2_diagnostic_occurrence,
        c2_evaluated_at,
        &digest('6'),
        c2_qualify_proposal.clone(),
    );
    let c2_request = attach_synthetic_maude_handoff(
        &root,
        "c2-qualify",
        c2_base,
        &c2_locked_plan,
        &custody_store,
        &session_key,
        &producer_key,
        "sess_synthetic_cache_c2_qualify",
    );
    let c2_cycle_id = {
        let mut store = CanonicalStore::open(&ns_database).unwrap();
        let mut support = SupportPort;
        let mut ag = AgLoopCtlPortV1::new(
            &bins.loopctl,
            &ag_database,
            &observation,
            OBSERVATION_RESOLVER_ID,
            &profile,
        )
        .unwrap();
        let outcome = CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag)
            .run_cycle_with_authoring_custody(c2_request, &verifier)
            .unwrap();
        let CycleRunOutcomeV1::AgOccurrenceOpened { cycle } = outcome else {
            panic!("ordinary C2 qualification work did not enter AG");
        };
        assert!(cycle
            .observation
            .as_ref()
            .unwrap()
            .decision_external_evidence
            .is_none());
        assert_eq!(cycle.ag.as_ref().unwrap().occurrence_id, occurrence_uuid(2));
        cycle.cycle_id
    };
    require_standing(&bins, &ag_database);
    let c2_gate = gate_args(&catalog, &observation, &standing);
    let mut c2_decide = str_args(&["decide", "--database", &ag_database.display().to_string()]);
    c2_decide.extend(c2_gate.clone());
    assert_eq!(
        program_counter(&loopctl_ok(&bins, &c2_decide)),
        "admissible_pending_authorization"
    );
    let mut c2_authorize = str_args(&[
        "authorize",
        "--database",
        &ag_database.display().to_string(),
    ]);
    c2_authorize.extend(c2_gate.clone());
    assert_eq!(
        program_counter(&loopctl_ok(&bins, &c2_authorize)),
        "authorization_consumed"
    );
    assert_eq!(replay(&bins, &ag_database)["ag_spends"], 3);
    let c2_qualify_docket = docket_args_for_executor(
        &root,
        &qualify_rig.trust,
        &docket_standing,
        &c2_qualify_plan_path,
        &qualify_rig.issuer_key,
        &executor,
        &bins,
    );
    let mut c2_dispatch = str_args(&["dispatch", "--database", &ag_database.display().to_string()]);
    c2_dispatch.extend(c2_qualify_docket.clone());
    assert_eq!(
        program_counter(&loopctl_ok(&bins, &c2_dispatch)),
        "dispatched"
    );
    let mut c2_poll = str_args(&["poll", "--database", &ag_database.display().to_string()]);
    c2_poll.extend(c2_qualify_docket);
    let c2_settled = loopctl_ok(&bins, &c2_poll);
    assert_eq!(program_counter(&c2_settled), "settled_observation_required");

    let c2_compilation: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&c2_qualify_compilation_path).unwrap()).unwrap();
    let c2_issuance = c2_settled
        .pointer("/state/settled_observation_required/dispatch/authorized/issuance")
        .unwrap();
    let c2_docket_custody = c2_settled
        .pointer("/state/settled_observation_required/dispatch/custody")
        .unwrap();
    let c2_settlement = c2_settled
        .pointer("/state/settled_observation_required/settlement")
        .unwrap();
    let c2_cycle = CanonicalStore::open(&ns_database)
        .unwrap()
        .list_cycles()
        .unwrap()
        .into_iter()
        .find(|cycle| cycle.cycle_id == c2_cycle_id)
        .unwrap();
    let c2_lineage = c2_cycle.authoring_context_provenance.as_ref().unwrap();
    let c2_authoring_custody = c2_cycle.authoring_context_custody.as_ref().unwrap();
    assert_eq!(c2_lineage.maude_plan_ref, c2_plan_digest);
    assert_ne!(c2_lineage.maude_plan_ref, c1_plan_digest);
    let c2_attempt_id = c2_docket_custody["attempt"].as_str().unwrap();
    let c2_settlement_id = c2_settlement["settlement"].as_str().unwrap();
    let c2_inspector_path = format!(
        "/phosphor-ng/campaigns/{}/occurrences/{}/proposals/{}",
        campaign_id.replace(':', "%3A"),
        occurrence_uuid(2),
        c2_issuance["proposal"]
            .as_str()
            .unwrap()
            .replace(':', "%3A")
    );
    let c2_bindings = c2_compilation["node_bindings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|node| {
            let mut binding = serde_json::json!({
                "schema": "maude.plan-node-governed-binding/v1",
                "binding_id": "",
                "draft_id": c2_compilation["draft_id"],
                "node_id": node["node_id"],
                "plan_digest": c2_compilation["plan_digest"],
                "compilation_id": c2_compilation["compilation_id"],
                "compiled_output_identity": node["output_identity"],
                "exact_work_identity": c2_qualify_work,
                "authoring_provenance_id": c2_lineage.provenance_id,
                "handoff_id": c2_authoring_custody.handoff_id,
                "campaign_id": campaign_id,
                "occurrence_id": occurrence_uuid(2),
                "proposal_id": c2_issuance["proposal"],
                "issuance_id": c2_issuance["issuance"],
                "docket_attempt_id": c2_attempt_id,
                "settlement_id": c2_settlement_id,
                "outcome": c2_settlement["outcome"],
                "inspector_path": c2_inspector_path,
            });
            let mut preimage = binding.clone();
            preimage.as_object_mut().unwrap().remove("binding_id");
            binding["binding_id"] = serde_json::json!(digest_value(&preimage));
            binding
        })
        .collect::<Vec<_>>();
    let c2_bindings_path = root.join("c2-qualify-governed-cross-probe.json");
    write_jcs(
        &c2_bindings_path,
        &serde_json::json!({
            "schema": "maude.plan-governed-cross-probe/v1",
            "bindings": c2_bindings,
        }),
    );

    // Only after the authorized C2 fault test settles may the ordinary
    // observation adapter package the evidence that earns Q2.
    let c2_evidence_path = PathBuf::from(c2_qualify_plan["workspace"].as_str().unwrap())
        .join("evidence/attempts")
        .join(format!(
            "{}.json",
            c2_attempt_id.trim_start_matches("sha256:")
        ));
    let acquisition_ledger = root.join("observation-acquisition.sqlite");
    let docket_state = root.join("docket-state");
    let observer_key = root.join("maude-observer.key");
    let q2_output = Command::new(std::env::var_os("MAUDE_PYTHON").unwrap())
        .args([
            "-m",
            "maude.plan.observation_acquisition",
            "orchestrate-post-settlement",
        ])
        .args(["--ledger", acquisition_ledger.to_str().unwrap()])
        .args(["--docket-program", bins.docket.to_str().unwrap()])
        .args(["--docket-state", docket_state.to_str().unwrap()])
        .args(["--issuance", c2_issuance["issuance"].as_str().unwrap()])
        .args(["--executor-evidence", c2_evidence_path.to_str().unwrap()])
        .args(["--executor-plan", c2_qualify_plan_path.to_str().unwrap()])
        .args([
            "--compilation-receipt",
            c2_qualify_compilation_path.to_str().unwrap(),
        ])
        .args(["--governed-bindings", c2_bindings_path.to_str().unwrap()])
        .args([
            "--external-profile",
            root.join("external-evidence-profile.json")
                .to_str()
                .unwrap(),
        ])
        .args(["--target-runtime-id", "nightshift:synthetic-local-v1"])
        .args(["--producer-key", observer_key.to_str().unwrap()])
        .args(["--producer-principal-id", "maude-observer:synthetic-local"])
        .args(["--producer-key-id", "maude-observer-key:synthetic-v1"])
        .args(["--nightshift-program", env!("CARGO_BIN_EXE_nightshift")])
        .args(["--nightshift-store", ns_database.to_str().unwrap()])
        .args(["--nightshift-credential", observer_key.to_str().unwrap()])
        .args(["--nightshift-runtime-id", "nightshift:synthetic-local-v1"])
        .env("PYTHONPATH", std::env::var_os("MAUDE_SRC").unwrap())
        .output()
        .unwrap();
    assert!(
        q2_output.status.success(),
        "C2 qualification evidence acquisition failed: {}",
        String::from_utf8_lossy(&q2_output.stderr)
    );
    let q2_acquisition: serde_json::Value = serde_json::from_slice(&q2_output.stdout).unwrap();
    let q2_observation_id = q2_acquisition
        .pointer("/evidence/handoff/observation/observation_id")
        .and_then(serde_json::Value::as_str)
        .unwrap()
        .to_owned();
    assert_ne!(q2_observation_id, q1_handoff.observation.observation_id);
    write_jcs(
        &root.join("c2-qualification-acquisition.json"),
        &q2_acquisition,
    );

    let q2_store = CanonicalStore::open(&ns_database).unwrap();
    let q2_export = q2_store
        .export_external_observation(
            ExternalObservationQueryV1::Observation {
                observation_id: q2_observation_id.clone(),
            },
            Utc::now().timestamp_millis(),
            120_000,
        )
        .unwrap()
        .matches;
    let q1_export = q2_store
        .export_external_observation(
            ExternalObservationQueryV1::Observation {
                observation_id: q1_handoff.observation.observation_id.clone(),
            },
            Utc::now().timestamp_millis(),
            120_000,
        )
        .unwrap()
        .matches;
    assert_eq!(q2_export.len(), 1);
    assert_eq!(q1_export.len(), 1);
    let q2_source = q2_export[0].observation.clone();
    let q2_custody = q2_export[0].custody.clone();
    let q1_source = q1_export[0].observation.clone();
    let q1_custody = q1_export[0].custody.clone();
    assert_eq!(q1_source.plan_document_digest, c1_plan_digest);
    assert_eq!(q2_source.plan_document_digest, c2_plan_digest);
    assert_ne!(q1_custody.custody_id, q2_custody.custody_id);
    let c2_steady_profile = SteadyStateEvidenceProfileV1 {
        qualification_profile: c1_profile,
        ..c1_steady_profile.clone()
    }
    .seal()
    .unwrap();
    let c2_steady_profile_path = root.join("c2-steady-state-evidence-profile.json");
    write_jcs(
        &c2_steady_profile_path,
        &serde_json::to_value(&c2_steady_profile).unwrap(),
    );
    let c2_absent_basis = q2_store
        .steady_state_reobservation_basis(
            &q2_observation_id,
            &c2_steady_profile,
            u64::try_from(q2_custody.received_at.timestamp_millis()).unwrap(),
        )
        .unwrap();
    let c2_absent_basis_path = root.join("c2-steady-state-basis-absent.json");
    write_jcs(
        &c2_absent_basis_path,
        &serde_json::to_value(&c2_absent_basis).unwrap(),
    );
    drop(q2_store);

    let s3_output = Command::new(std::env::var_os("MAUDE_PYTHON").unwrap())
        .args([
            "-m",
            "maude.plan.observation_acquisition",
            "orchestrate-reobserve-for-successor",
        ])
        .args(["--ledger", acquisition_ledger.to_str().unwrap()])
        .args(["--docket-program", bins.docket.to_str().unwrap()])
        .args(["--docket-state", docket_state.to_str().unwrap()])
        .args(["--issuance", c2_issuance["issuance"].as_str().unwrap()])
        .args(["--executor-evidence", c2_evidence_path.to_str().unwrap()])
        .args(["--executor-plan", c2_qualify_plan_path.to_str().unwrap()])
        .args([
            "--compilation-receipt",
            c2_qualify_compilation_path.to_str().unwrap(),
        ])
        .args(["--governed-bindings", c2_bindings_path.to_str().unwrap()])
        .args([
            "--external-profile",
            c2_steady_profile_path.to_str().unwrap(),
        ])
        .args([
            "--reobservation-basis",
            c2_absent_basis_path.to_str().unwrap(),
        ])
        .args(["--target-runtime-id", "nightshift:synthetic-local-v1"])
        .args(["--producer-key", observer_key.to_str().unwrap()])
        .args(["--producer-principal-id", "maude-observer:synthetic-local"])
        .args(["--producer-key-id", "maude-observer-key:synthetic-v1"])
        .args(["--nightshift-program", env!("CARGO_BIN_EXE_nightshift")])
        .args(["--nightshift-store", ns_database.to_str().unwrap()])
        .args(["--nightshift-credential", observer_key.to_str().unwrap()])
        .args(["--nightshift-runtime-id", "nightshift:synthetic-local-v1"])
        .env("PYTHONPATH", std::env::var_os("MAUDE_SRC").unwrap())
        .output()
        .unwrap();
    assert!(
        s3_output.status.success(),
        "C2 passive acquisition failed: {}",
        String::from_utf8_lossy(&s3_output.stderr)
    );
    let s3_acquisition: serde_json::Value = serde_json::from_slice(&s3_output.stdout).unwrap();
    let s3_observation_id = s3_acquisition
        .pointer("/evidence/handoff/observation/observation_id")
        .and_then(serde_json::Value::as_str)
        .unwrap()
        .to_owned();
    let s3_custody_id = s3_acquisition
        .get("events")
        .and_then(serde_json::Value::as_array)
        .and_then(|events| events.last())
        .and_then(|event| event.get("custody_id"))
        .and_then(serde_json::Value::as_str)
        .unwrap()
        .to_owned();
    assert!(!s3_acquisition
        .pointer("/evidence/handoff/observation")
        .unwrap()
        .to_string()
        .contains("single_cache_failure_survived"));
    write_jcs(
        &root.join("c2-passive-acquisition-s3.json"),
        &s3_acquisition,
    );

    // Current C2-looking S3 still cannot make Q1 applicable. Only Q2+S3 can
    // prepare the exact C2 routine-continuation proposal.
    let c2_store = CanonicalStore::open(&ns_database).unwrap();
    let (c2_successor_diagnostic_occurrence, c2_successor_evaluated_at) =
        next_unused_scheduled_occurrence(
            &c2_store,
            feedback_first_due,
            clean_recurrence.obligations[0].policy.cadence_seconds,
        );
    let (c2_successor_policy, c2_successor_inputs, c2_successor_recurrence) =
        fresh_policy_inputs_recurrence(
            feedback_first_due,
            c2_successor_diagnostic_occurrence,
            c2_successor_evaluated_at - chrono::Duration::seconds(1),
        );
    let mut c2_successor_base = request_for_precompiled_fresh(
        &c2_successor_policy,
        &c2_successor_inputs,
        &c2_successor_recurrence,
        c2_successor_diagnostic_occurrence,
        c2_successor_evaluated_at,
        &digest('7'),
        c2_teardown_proposal,
    );
    let q1_with_s3 = DecisionRelativeEvidenceReferenceV1 {
        schema: DECISION_EVIDENCE_REFERENCE_SCHEMA_V1.into(),
        qualification_observation_id: q1_source.observation_id,
        qualification_custody_id: q1_custody.custody_id,
        steady_state_observation_id: s3_observation_id.clone(),
        steady_state_custody_id: s3_custody_id.clone(),
        profile_id: c2_steady_profile.profile_id.clone(),
    };
    c2_successor_base.decision_external_evidence = Some(q1_with_s3);
    let q1_s3_refusal = prepare_decision_evidence_cycle_request(
        &c2_store,
        c2_successor_base.clone(),
        &c2_steady_profile,
    )
    .unwrap_err();
    assert!(q1_s3_refusal
        .to_string()
        .contains("qualification does not apply to the target PlanDocument"));
    c2_successor_base.decision_external_evidence = Some(DecisionRelativeEvidenceReferenceV1 {
        schema: DECISION_EVIDENCE_REFERENCE_SCHEMA_V1.into(),
        qualification_observation_id: q2_source.observation_id,
        qualification_custody_id: q2_custody.custody_id,
        steady_state_observation_id: s3_observation_id.clone(),
        steady_state_custody_id: s3_custody_id,
        profile_id: c2_steady_profile.profile_id.clone(),
    });
    c2_successor_base = c2_successor_base.seal().unwrap();
    let c2_successor_base =
        prepare_decision_evidence_cycle_request(&c2_store, c2_successor_base, &c2_steady_profile)
            .unwrap();
    let c2_teardown_request = attach_synthetic_maude_handoff(
        &root,
        "c2-teardown",
        c2_successor_base,
        &c2_locked_plan,
        &custody_store,
        &session_key,
        &producer_key,
        "sess_synthetic_cache_c2_teardown",
    );
    drop(c2_store);
    let c2_composition = {
        let mut store = CanonicalStore::open(&ns_database).unwrap();
        let mut support = SupportPort;
        let mut ag = AgLoopCtlPortV1::new(
            &bins.loopctl,
            &ag_database,
            &observation,
            OBSERVATION_RESOLVER_ID,
            &profile,
        )
        .unwrap();
        let outcome = CanonicalRuntime::new_with_decision_evidence_profile(
            &mut store,
            TestNqAdmissionPort,
            &mut support,
            &mut ag,
            c2_steady_profile,
        )
        .unwrap()
        .run_cycle_with_authoring_custody(c2_teardown_request, &verifier)
        .unwrap();
        let CycleRunOutcomeV1::AgOccurrenceOpened { cycle } = outcome else {
            panic!("Q2 plus S3 did not open C2 routine continuation");
        };
        assert_eq!(cycle.ag.as_ref().unwrap().occurrence_id, occurrence_uuid(3));
        cycle
            .observation
            .unwrap()
            .decision_external_evidence
            .unwrap()
    };
    assert_eq!(
        c2_composition.qualification.source_observation_id,
        q2_observation_id
    );
    assert_eq!(
        c2_composition.qualification.plan_document_digest,
        c2_plan_digest
    );
    write_jcs(
        &root.join("c2-routine-continuation-composition.json"),
        &serde_json::to_value(&c2_composition).unwrap(),
    );
    require_standing(&bins, &ag_database);
    let mut c2_teardown_decide =
        str_args(&["decide", "--database", &ag_database.display().to_string()]);
    c2_teardown_decide.extend(c2_gate.clone());
    assert_eq!(
        program_counter(&loopctl_ok(&bins, &c2_teardown_decide)),
        "admissible_pending_authorization"
    );
    let mut c2_teardown_authorize = str_args(&[
        "authorize",
        "--database",
        &ag_database.display().to_string(),
    ]);
    c2_teardown_authorize.extend(c2_gate);
    assert_eq!(
        program_counter(&loopctl_ok(&bins, &c2_teardown_authorize)),
        "authorization_consumed"
    );
    let c2_teardown_docket = docket_args_for_executor(
        &root,
        &qualify_rig.trust,
        &docket_standing,
        &c2_teardown_plan_path,
        &qualify_rig.issuer_key,
        &executor,
        &bins,
    );
    let mut c2_teardown_dispatch =
        str_args(&["dispatch", "--database", &ag_database.display().to_string()]);
    c2_teardown_dispatch.extend(c2_teardown_docket.clone());
    assert_eq!(
        program_counter(&loopctl_ok(&bins, &c2_teardown_dispatch)),
        "dispatched"
    );
    let mut c2_teardown_poll =
        str_args(&["poll", "--database", &ag_database.display().to_string()]);
    c2_teardown_poll.extend(c2_teardown_docket);
    assert_eq!(
        program_counter(&loopctl_ok(&bins, &c2_teardown_poll)),
        "settled_observation_required"
    );
    let c2_report = replay(&bins, &ag_database);
    assert_eq!(c2_report["ag_spends"], 4);
    assert_eq!(c2_report["docket_attempts"], 4);
    assert_eq!(c2_report["settlements"], 4);
    let c1_cross_probe: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("qualify-governed-cross-probe.json")).unwrap(),
    )
    .unwrap();
    let c2_cross_probe: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&c2_bindings_path).unwrap()).unwrap();
    let mut lifecycle_bindings = c1_cross_probe["bindings"].as_array().unwrap().clone();
    lifecycle_bindings.extend(c2_cross_probe["bindings"].as_array().unwrap().clone());
    let lifecycle_cross_probe_path = root.join("artifact-requalification-cross-probe.json");
    write_jcs(
        &lifecycle_cross_probe_path,
        &serde_json::json!({
            "schema": "maude.plan-governed-cross-probe/v1",
            "bindings": lifecycle_bindings,
        }),
    );
    write_jcs(
        &root.join("synthetic-artifact-change-requalification.json"),
        &serde_json::json!({
            "schema": "nightshift.synthetic-cache-artifact-requalification/v1",
            "c1": {
                "plan_digest": c1_plan_digest,
                "qualification_observation_id": q1_handoff.observation.observation_id,
            },
            "c2": {
                "plan_digest": c2_plan_digest,
                "qualification_compilation_id": c2_compilation["compilation_id"],
                "qualify_work": c2_qualify_work,
                "teardown_work": c2_teardown_work,
                "qualification_observation_id": q2_observation_id,
                "passive_observation_id": s3_observation_id,
                "routine_composition_id": c2_composition.composition_id,
            },
            "cross_probe": lifecycle_cross_probe_path,
            "q1_c2_refusal": q1_refusal.to_string(),
            "q1_s3_refusal": q1_s3_refusal.to_string(),
            "ag_replay": c2_report,
        }),
    );
}

/// Recovers the exact synthetic qualification after a transport/package fault
/// which happened after Docket durably settled qualification but before Maude
/// delivered application evidence. Qualification is never dispatched again;
/// the test starts from the exact owner records and performs only observation,
/// composition, successor opening, and governed teardown.
#[test]
#[ignore = "requires a retained post-qualification synthetic root and local Docker"]
fn synthetic_cache_feedback_recovers_after_observation_packaging_fault() {
    let bins = bins();
    let root = PathBuf::from(
        std::env::var_os("SYNTHETIC_CACHE_RESUME_ROOT").expect("SYNTHETIC_CACHE_RESUME_ROOT"),
    );
    assert!(root.is_absolute() && root.is_dir());
    let exact_path = |name: &str| {
        let path = PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name}")));
        assert!(
            path.is_absolute() && path.is_file(),
            "missing exact input: {path:?}"
        );
        path
    };
    let qualify_plan_path = exact_path("SYNTHETIC_CACHE_QUALIFY_PLAN");
    let teardown_plan_path = exact_path("SYNTHETIC_CACHE_TEARDOWN_PLAN");
    let qualify_compilation_path = exact_path("SYNTHETIC_CACHE_QUALIFY_COMPILATION_RECEIPT");
    let locked_plan = exact_path("SYNTHETIC_CACHE_LOCKED_PLAN");
    let executor = exact_path("SYNTHETIC_CACHE_EXECUTOR");
    let teardown_handoff: serde_json::Value = serde_json::from_slice(
        &std::fs::read(exact_path("SYNTHETIC_CACHE_TEARDOWN_HANDOFF")).unwrap(),
    )
    .unwrap();
    let teardown_proposal: PrecompiledWorkflowProposalV2 =
        serde_json::from_value(teardown_handoff).unwrap();

    let ns_database = root.join("nightshift.sqlite");
    let ag_database = root.join("ag.sqlite");
    let qualify_settled = status(&bins, &ag_database);
    assert_eq!(
        program_counter(&qualify_settled),
        "settled_observation_required"
    );
    assert_eq!(replay(&bins, &ag_database)["settlements"], 1);

    let session_key = root.join("maude-session.key");
    let producer_key = root.join("maude-producer.key");
    let custody_store = root.join("maude-custody.sqlite");
    let verifier = MaudeCustodyVerifierV1::from_key_file(
        "maude-handoff:synthetic-local".into(),
        "maude-handoff-key:synthetic-v1".into(),
        "maude:synthetic-supervisor".into(),
        "maude-session-key:synthetic-v1".into(),
        "nightshift:synthetic-local-v1".into(),
        &producer_key,
        &session_key,
    )
    .unwrap();

    let first_cycle = CanonicalStore::open(&ns_database)
        .unwrap()
        .list_cycles()
        .unwrap()
        .into_iter()
        .find(|cycle| cycle.slot.occurrence == 0)
        .expect("retained qualification Nightshift cycle");
    let posture = &first_cycle.observation.as_ref().unwrap().posture;
    let policy = posture.policy.clone();
    let feedback_first_due =
        DateTime::parse_from_rfc3339(&posture.schedule_obligations[0].policy.first_due_at)
            .unwrap()
            .with_timezone(&Utc);
    let lineage = first_cycle.authoring_context_provenance.as_ref().unwrap();
    let authoring_custody = first_cycle.authoring_context_custody.as_ref().unwrap();

    let issuance = qualify_settled
        .pointer("/state/settled_observation_required/dispatch/authorized/issuance")
        .unwrap();
    let docket_custody = qualify_settled
        .pointer("/state/settled_observation_required/dispatch/custody")
        .unwrap();
    let settlement = qualify_settled
        .pointer("/state/settled_observation_required/settlement")
        .unwrap();
    let campaign_id = issuance["key"]["campaign"].as_str().unwrap();
    let occurrence_id = issuance["key"]["occurrence"].as_str().unwrap();
    let proposal_id = issuance["proposal"].as_str().unwrap();
    let exact_work_id = issuance["work"].as_str().unwrap();
    let attempt_id = docket_custody["attempt"].as_str().unwrap();
    let settlement_id = settlement["settlement"].as_str().unwrap();
    assert_eq!(lineage.campaign_id, campaign_id);
    assert_eq!(lineage.occurrence_id, occurrence_id);
    assert_eq!(lineage.proposal_id, proposal_id);
    assert_eq!(lineage.exact_work_id, exact_work_id);

    let compilation: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&qualify_compilation_path).unwrap()).unwrap();
    let inspector_path = format!(
        "/phosphor-ng/campaigns/{}/occurrences/{}/proposals/{}",
        campaign_id.replace(':', "%3A"),
        occurrence_id,
        proposal_id.replace(':', "%3A")
    );
    let bindings = compilation["node_bindings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|node| {
            let mut binding = serde_json::json!({
                "schema": "maude.plan-node-governed-binding/v1",
                "binding_id": "",
                "draft_id": compilation["draft_id"],
                "node_id": node["node_id"],
                "plan_digest": compilation["plan_digest"],
                "compilation_id": compilation["compilation_id"],
                "compiled_output_identity": node["output_identity"],
                "exact_work_identity": exact_work_id,
                "authoring_provenance_id": lineage.provenance_id,
                "handoff_id": authoring_custody.handoff_id,
                "campaign_id": campaign_id,
                "occurrence_id": occurrence_id,
                "proposal_id": proposal_id,
                "issuance_id": issuance["issuance"],
                "docket_attempt_id": attempt_id,
                "settlement_id": settlement_id,
                "outcome": settlement["outcome"],
                "inspector_path": inspector_path,
            });
            let mut preimage = binding.clone();
            preimage.as_object_mut().unwrap().remove("binding_id");
            binding["binding_id"] = serde_json::json!(digest_value(&preimage));
            binding
        })
        .collect::<Vec<_>>();
    let governed_bindings = serde_json::json!({
        "schema": "maude.plan-governed-cross-probe/v1",
        "bindings": bindings,
    });
    let governed_bindings_path = root.join("qualify-governed-cross-probe.json");
    write_jcs_convergent(&governed_bindings_path, &governed_bindings);

    let evidence_path = PathBuf::from(
        serde_json::from_slice::<serde_json::Value>(&std::fs::read(&qualify_plan_path).unwrap())
            .unwrap()["workspace"]
            .as_str()
            .unwrap(),
    )
    .join("evidence/attempts")
    .join(format!("{}.json", attempt_id.trim_start_matches("sha256:")));
    let executor_evidence: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&evidence_path).unwrap()).unwrap();
    let observed_at = executor_evidence["observed_at_unix_ms"].as_i64().unwrap();
    let observer_key = root.join("maude-observer.key");
    let observer_key_bytes = [0x43_u8; 32];
    if observer_key.exists() {
        assert_eq!(std::fs::read(&observer_key).unwrap(), observer_key_bytes);
    } else {
        std::fs::write(&observer_key, observer_key_bytes).unwrap();
        std::fs::set_permissions(&observer_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let handoff_path = root.join("external-observation-qualify.json");
    if !handoff_path.exists() {
        let created_at = DateTime::from_timestamp_millis(observed_at + 10).unwrap();
        let created_at_text = created_at.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true);
        let output = Command::new(std::env::var_os("MAUDE_PYTHON").expect("MAUDE_PYTHON"))
            .args(["-m", "maude.plan.world_observation"])
            .args(["--executor-evidence", evidence_path.to_str().unwrap()])
            .args(["--executor-plan", qualify_plan_path.to_str().unwrap()])
            .args([
                "--compilation-receipt",
                qualify_compilation_path.to_str().unwrap(),
            ])
            .args([
                "--governed-bindings",
                governed_bindings_path.to_str().unwrap(),
            ])
            .args(["--producer-key", observer_key.to_str().unwrap()])
            .args(["--producer-principal-id", "maude-observer:synthetic-local"])
            .args(["--producer-key-id", "maude-observer-key:synthetic-v1"])
            .args(["--target-runtime-id", "nightshift:synthetic-local-v1"])
            .args(["--created-at", &created_at_text])
            .args(["--output", handoff_path.to_str().unwrap()])
            .env(
                "PYTHONPATH",
                std::env::var_os("MAUDE_SRC").expect("MAUDE_SRC"),
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "Maude observation adapter failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let handoff: ExternalObservationHandoffV1 =
        serde_json::from_slice(&std::fs::read(&handoff_path).unwrap()).unwrap();
    let external_verifier = ExternalObservationVerifierV1::from_key_file(
        "maude-observer:synthetic-local".into(),
        "maude-observer-key:synthetic-v1".into(),
        "nightshift:synthetic-local-v1".into(),
        &observer_key,
    )
    .unwrap();
    let verified = external_verifier.verify(&handoff).unwrap();
    let received_at = DateTime::from_timestamp_millis(observed_at + 20).unwrap();
    let mut store = CanonicalStore::open(&ns_database).unwrap();
    let external_custody = store
        .record_external_observation(&verified, received_at)
        .unwrap();
    let external_profile = ExternalEvidenceProfileV1 {
        schema: EXTERNAL_EVIDENCE_PROFILE_SCHEMA_V1.into(),
        profile_id: String::new(),
        purpose: ExternalEvidencePurposeV1::PostSettlementSuccessor,
        expected_adapter_id: "maude.local-compose-observation-adapter".into(),
        expected_adapter_version: "1".into(),
        expected_producer_principal_id: "maude-observer:synthetic-local".into(),
        expected_producer_key_id: "maude-observer-key:synthetic-v1".into(),
        expected_runtime_id: "nightshift:synthetic-local-v1".into(),
        required_action: LocalComposeActionV1::Qualify,
        required_claims: vec![
            LocalComposeClaimKindV1::FrontDoorReachable,
            LocalComposeClaimKindV1::CacheMissThenHit,
            LocalComposeClaimKindV1::SingleCacheFailureSurvived,
            LocalComposeClaimKindV1::CacheTopologyRestored,
        ],
        max_age_ms: 600_000,
    }
    .seal()
    .unwrap();

    // The first recovery attempt deliberately remains as a closed historical
    // observation. A new canonical composition uses a distinct admitted time
    // and the recurrence slot current at that instant; neither fact is
    // silently rewritten or refreshed on the retained record.
    let successor_evaluated_at = DateTime::from_timestamp_millis(observed_at + 40).unwrap();
    let diagnostic_occurrence = scheduled_occurrence_at(
        feedback_first_due,
        successor_evaluated_at,
        posture.schedule_obligations[0].policy.cadence_seconds,
    );
    let (next_policy, next_inputs, next_recurrence) = fresh_policy_inputs_recurrence(
        feedback_first_due,
        diagnostic_occurrence,
        successor_evaluated_at - chrono::Duration::seconds(1),
    );
    assert_eq!(next_policy.policy_id, policy.policy_id);
    let mut successor_base = request_for_precompiled_fresh(
        &next_policy,
        &next_inputs,
        &next_recurrence,
        diagnostic_occurrence,
        successor_evaluated_at,
        &digest('e'),
        teardown_proposal,
    );
    successor_base.external_evidence = Some(ExternalEvidenceReferenceV1 {
        schema: EXTERNAL_EVIDENCE_REFERENCE_SCHEMA_V1.into(),
        source_observation_id: handoff.observation.observation_id.clone(),
        source_custody_id: external_custody.custody_id.clone(),
        profile_id: external_profile.profile_id.clone(),
    });
    successor_base = successor_base.seal().unwrap();
    let successor_base =
        prepare_external_evidence_cycle_request(&store, successor_base, &external_profile).unwrap();
    let successor_request = attach_synthetic_maude_handoff(
        &root,
        "teardown-recovery",
        successor_base,
        &locked_plan,
        &custody_store,
        &session_key,
        &producer_key,
        "sess_synthetic_cache_teardown_recovery",
    );
    drop(store);

    let observation = observation_wrapper(&root, &ns_database);
    let standing = standing_wrapper(&bins, &root, &root.join("mandates.json"));
    let qualify_rig = external_docket_rig(&root, &qualify_plan_path);
    let docket_standing = docket_standing_script(&root, "current");
    let profile = runtime_profile_for_executor(
        &root,
        "synthetic-cache",
        &observation,
        &standing,
        &root.join("catalog.json"),
        &docket_standing,
        &qualify_rig,
        &executor,
        &bins,
    );
    let mut store = CanonicalStore::open(&ns_database).unwrap();
    let mut support = SupportPort;
    let mut ag = AgLoopCtlPortV1::new(
        &bins.loopctl,
        &ag_database,
        &observation,
        OBSERVATION_RESOLVER_ID,
        &profile,
    )
    .unwrap();
    let outcome = CanonicalRuntime::new_with_external_evidence_profile(
        &mut store,
        TestNqAdmissionPort,
        &mut support,
        &mut ag,
        external_profile,
    )
    .unwrap()
    .run_cycle_with_authoring_custody(successor_request, &verifier)
    .unwrap();
    let CycleRunOutcomeV1::AgOccurrenceOpened { cycle } = outcome else {
        panic!("fresh composed teardown successor did not enter AG");
    };
    let composed = cycle
        .observation
        .as_ref()
        .unwrap()
        .external_evidence
        .as_ref()
        .unwrap();
    assert_eq!(composed.source_occurrence_id, occurrence_uuid(0));
    assert_eq!(composed.target_occurrence_id, occurrence_uuid(1));
    assert_eq!(cycle.ag.as_ref().unwrap().occurrence_id, occurrence_uuid(1));
    write_jcs_convergent(
        &root.join("external-composition.json"),
        &serde_json::to_value(composed).unwrap(),
    );

    require_standing(&bins, &ag_database);
    let gate = gate_args(&root.join("catalog.json"), &observation, &standing);
    let mut decide = str_args(&["decide", "--database", &ag_database.display().to_string()]);
    decide.extend(gate.clone());
    assert_eq!(
        program_counter(&loopctl_ok(&bins, &decide)),
        "admissible_pending_authorization"
    );
    let mut authorize = str_args(&[
        "authorize",
        "--database",
        &ag_database.display().to_string(),
    ]);
    authorize.extend(gate);
    assert_eq!(
        program_counter(&loopctl_ok(&bins, &authorize)),
        "authorization_consumed"
    );
    let teardown_docket = docket_args_for_executor(
        &root,
        &qualify_rig.trust,
        &docket_standing,
        &teardown_plan_path,
        &qualify_rig.issuer_key,
        &executor,
        &bins,
    );
    let mut dispatch = str_args(&["dispatch", "--database", &ag_database.display().to_string()]);
    dispatch.extend(teardown_docket.clone());
    assert_eq!(program_counter(&loopctl_ok(&bins, &dispatch)), "dispatched");
    let mut poll = str_args(&["poll", "--database", &ag_database.display().to_string()]);
    poll.extend(teardown_docket);
    let final_state = loopctl_ok(&bins, &poll);
    assert_eq!(
        program_counter(&final_state),
        "settled_observation_required"
    );
    let report = replay(&bins, &ag_database);
    assert_eq!(report["ag_spends"], 2);
    assert_eq!(report["docket_attempts"], 2);
    assert_eq!(report["settlements"], 2);
    let stale_request = serde_json::json!({
        "schema": "ag.governed-loop.observation-request/v1",
        "key": {
            "campaign": composed.target_campaign_id,
            "occurrence": composed.target_occurrence_id,
        },
        "observation": composed.canonical_observation_id().unwrap(),
        "subject": composed.subject_digest,
        "now_unix_ms": composed.fresh_until_unix_ms,
    });
    let resolver_ttl = OBSERVATION_TTL_MS.to_string();
    let mut resolver = Command::new(env!("CARGO_BIN_EXE_nightshift-observation-resolver"))
        .args(["--store", ns_database.to_str().unwrap()])
        .args(["--resolver-id", OBSERVATION_RESOLVER_ID])
        .args(["--default-ttl-ms", &resolver_ttl])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    resolver
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_jcs::to_vec(&stale_request).unwrap())
        .unwrap();
    let stale_output = resolver.wait_with_output().unwrap();
    assert!(
        stale_output.status.success(),
        "stale resolver witness failed: {}",
        String::from_utf8_lossy(&stale_output.stderr)
    );
    let stale_resolution: serde_json::Value = serde_json::from_slice(&stale_output.stdout).unwrap();
    assert_eq!(stale_resolution["status"], "stale");
    assert_eq!(
        stale_resolution["fresh_until_unix_ms"],
        composed.fresh_until_unix_ms
    );
    assert_eq!(replay(&bins, &ag_database)["ag_spends"], 2);
    write_jcs(
        &root.join("synthetic-stale-resolution.json"),
        &stale_resolution,
    );
    write_jcs(
        &root.join("synthetic-feedback-recovery.json"),
        &serde_json::json!({
            "schema": "nightshift.synthetic-cache-feedback-recovery/v1",
            "source_external_observation": handoff.observation.observation_id,
            "source_custody": external_custody.custody_id,
            "canonical_observation": composed.canonical_observation_id().unwrap(),
            "composition": composed.composition_id,
            "source_occurrence": composed.source_occurrence_id,
            "successor_occurrence": composed.target_occurrence_id,
            "stale_resolution": stale_resolution,
            "ag_replay": report,
            "final_state": final_state,
        }),
    );
}

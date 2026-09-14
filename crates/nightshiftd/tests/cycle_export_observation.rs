//! CLI-level tests for the read-only `cycle export-observation` surface.
//! The store is populated through the real runtime path (posture-only cycle),
//! then the compiled binary is exercised as a subprocess.

mod common;

use std::process::Command;

use chrono::{DateTime, Utc};
use nightshiftd::ag_port::{AgOccurrencePortV1, AgOpenOccurrenceRequestV1};
use nightshiftd::canonical_runtime::{
    CanonicalCycleRequestV1, CanonicalRuntime, CycleRunOutcomeV1,
};
use nightshiftd::canonical_store::{
    AgOccurrenceReferenceV1, CanonicalStore, RecurrenceSlotV1, RecurrenceTriggerV1,
};
use nightshiftd::currentness::{
    PresentEvidencePortV1, PresentEvidenceQueryV1, QualifiedSupportV1, SupportExpiryV1,
    SupportReceiverInstantV1, SupportStandingV1,
};
use nightshiftd::diagnostic_posture::{DiagnosticInputs, PosturePolicy, RecurrenceEvidence};

use common::TestNqAdmissionPort;

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn time(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .unwrap()
        .with_timezone(&Utc)
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

struct CurrentSupportPort;

impl PresentEvidencePortV1 for CurrentSupportPort {
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

struct NoAgPort;

impl AgOccurrencePortV1 for NoAgPort {
    fn open_occurrence(
        &mut self,
        _request: &AgOpenOccurrenceRequestV1,
    ) -> Result<AgOccurrenceReferenceV1, String> {
        Err("posture-only cycle has no AG adapter".into())
    }

    fn status(&mut self, _: &str, _: &str) -> Result<AgOccurrenceReferenceV1, String> {
        Err("posture-only cycle has no AG adapter".into())
    }
}

fn posture_only_request(observation_id: &str) -> CanonicalCycleRequestV1 {
    let (policy, inputs, recurrence) = example_policy_inputs_recurrence();
    let slot = RecurrenceSlotV1::new(
        policy.policy_id.clone(),
        "config-v1".into(),
        policy.subject.id.clone(),
        policy.subject.scope.digest.clone(),
        "nightshift-scheduler-1".into(),
        time("2026-07-27T20:00:00Z"),
        time("2026-07-27T20:00:30Z"),
        0,
        RecurrenceTriggerV1::Scheduled,
        None,
    )
    .unwrap();
    CanonicalCycleRequestV1 {
        schema: String::new(),
        request_id: String::new(),
        slot,
        scheduler_clock_id: "nightshift-scheduler-1".into(),
        evaluated_at: time("2026-07-27T20:00:10Z"),
        observation_id: observation_id.into(),
        policy,
        inputs,
        recurrence,
        external_evidence: None,
        decision_external_evidence: None,
        temporal_policy: None,
        proposal: None,
        authoring_context: None,
        reviewed_plan_binding: None,
    }
    .seal()
    .unwrap()
}

fn export_observation(store: &std::path::Path, observation_id: &str) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_nightshift"))
        .arg("--store")
        .arg(store)
        .arg("cycle")
        .arg("export-observation")
        .arg("--observation-id")
        .arg(observation_id)
        .output()
        .expect("run nightshift cycle export-observation");
    assert!(
        output.status.success(),
        "export-observation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("export output is JSON")
}

fn export_authoring_context(
    store: &std::path::Path,
    campaign_id: &str,
    occurrence_id: &str,
) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_nightshift"))
        .arg("--store")
        .arg(store)
        .arg("cycle")
        .arg("export-authoring-context")
        .arg("--campaign-id")
        .arg(campaign_id)
        .arg("--occurrence-id")
        .arg(occurrence_id)
        .output()
        .expect("run nightshift cycle export-authoring-context");
    assert!(
        output.status.success(),
        "export-authoring-context failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("authoring-context export is JSON")
}

#[test]
fn export_observation_reports_the_unique_match_with_lineage() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("ns.sqlite");
    let observation_id = digest('a');
    let (policy, _, _) = example_policy_inputs_recurrence();
    let mut store = CanonicalStore::open(&database).unwrap();
    let mut support = CurrentSupportPort;
    let mut ag = NoAgPort;
    let outcome = CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag)
        .run_cycle(posture_only_request(&observation_id))
        .unwrap();
    let CycleRunOutcomeV1::PostureOnly { cycle } = outcome else {
        panic!("expected a posture-only cycle")
    };
    drop(store);

    let export = export_observation(&database, &observation_id);
    assert_eq!(export["schema"], "nightshift.observation_export.v1");
    assert_eq!(export["observation_id"], observation_id.as_str());
    let matches = export["matches"].as_array().unwrap();
    assert_eq!(matches.len(), 1);
    let entry = &matches[0];
    assert_eq!(entry["cycle_id"], cycle.cycle_id.as_str());
    assert_eq!(entry["slot_id"], cycle.slot.slot_id.as_str());
    assert_eq!(
        entry["observation"]["observation_id"],
        observation_id.as_str()
    );
    assert_eq!(
        entry["observation"]["schema"],
        "nightshift.observation_record.v2"
    );
    assert_eq!(
        entry["observation"]["source_admissions"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(entry["family"]["policy_id"], policy.policy_id.as_str());
    assert_eq!(entry["family"]["subject_id"], policy.subject.id.as_str());
    assert_eq!(
        entry["family"]["scheduler_clock_id"],
        "nightshift-scheduler-1"
    );
    assert_eq!(entry["order_key"]["occurrence"], 0);
    assert_eq!(entry["order_key"]["slot_id"], cycle.slot.slot_id.as_str());
    assert_eq!(entry["family_latest_cycle_id"], cycle.cycle_id.as_str());
    assert_eq!(entry["family_latest_order_key"]["occurrence"], 0);
}

#[test]
fn export_observation_reports_absent_as_zero_matches() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("ns.sqlite");
    let mut store = CanonicalStore::open(&database).unwrap();
    let mut support = CurrentSupportPort;
    let mut ag = NoAgPort;
    CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag)
        .run_cycle(posture_only_request(&digest('a')))
        .unwrap();
    drop(store);

    let export = export_observation(&database, &digest('b'));
    assert_eq!(export["schema"], "nightshift.observation_export.v1");
    assert_eq!(export["matches"].as_array().unwrap().len(), 0);
}

#[test]
fn export_observation_does_not_mutate_runtime_state() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("ns.sqlite");
    let observation_id = digest('a');
    let mut store = CanonicalStore::open(&database).unwrap();
    let mut support = CurrentSupportPort;
    let mut ag = NoAgPort;
    let outcome = CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag)
        .run_cycle(posture_only_request(&observation_id))
        .unwrap();
    let CycleRunOutcomeV1::PostureOnly { cycle } = outcome else {
        panic!("expected a posture-only cycle")
    };
    let before = store.get_cycle(&cycle.cycle_id).unwrap();
    drop(store);

    let export = export_observation(&database, &observation_id);
    assert_eq!(export["matches"].as_array().unwrap().len(), 1);

    let store = CanonicalStore::open(&database).unwrap();
    let after = store.get_cycle(&cycle.cycle_id);
    assert_eq!(before, after.expect("cycle remains readable"));
}

#[test]
fn export_authoring_context_reports_historical_unlinked_without_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("ns.sqlite");
    let mut store = CanonicalStore::open(&database).unwrap();
    let mut support = CurrentSupportPort;
    let mut ag = NoAgPort;
    let outcome = CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut support, &mut ag)
        .run_cycle(posture_only_request(&digest('a')))
        .unwrap();
    let CycleRunOutcomeV1::PostureOnly { cycle } = outcome else {
        panic!("expected a posture-only cycle")
    };
    let before = store.get_cycle(&cycle.cycle_id).unwrap();
    drop(store);

    let export = export_authoring_context(
        &database,
        &digest('c'),
        "00000000-0000-4000-8000-000000000000",
    );
    assert_eq!(export["schema"], "nightshift.authoring_context_export.v1");
    assert_eq!(export["query"]["by"], "governed_occurrence");
    assert_eq!(export["matches"].as_array().unwrap().len(), 0);

    let store = CanonicalStore::open(&database).unwrap();
    assert_eq!(store.get_cycle(&cycle.cycle_id).unwrap(), before);
}

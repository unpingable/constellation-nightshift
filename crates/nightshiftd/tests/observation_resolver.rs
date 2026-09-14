//! Subprocess tests for the read-only `nightshift-observation-resolver`
//! binary: AG observation request on stdin, frozen
//! `ag.governed-loop.observation-resolution/v2` response on stdout. Store
//! state is built through the real canonical runtime.

mod common;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

use chrono::{DateTime, Utc};
use nightshiftd::ag_port::{AgOccurrencePortV1, AgOpenModeV1, AgOpenOccurrenceRequestV1};
use nightshiftd::canonical_runtime::{
    ag_executor_plan_identity, CanonicalCycleRequestV1, CanonicalRuntime, CycleRunOutcomeV1,
    PrecompiledWorkflowProposalV2,
};
use nightshiftd::canonical_store::{
    AgOccurrenceReferenceV1, AgProgramCounterV1, CanonicalStore, RecurrenceSlotV1,
    RecurrenceTriggerV1,
};
use nightshiftd::currentness::{
    PresentEvidencePortV1, PresentEvidenceQueryV1, QualifiedSupportV1, SupportExpiryV1,
    SupportReceiverInstantV1, SupportStandingV1,
};
use nightshiftd::decision_basis::{normalize_posture, DecisionBasisV1};
use nightshiftd::diagnostic_posture::{DiagnosticInputs, PosturePolicy, RecurrenceEvidence};
use sha2::{Digest as _, Sha256};

use common::TestNqAdmissionPort;

const RESOLVER_ID: &str = "nightshift-observation-resolver/v1";
/// The AG subject digest compiled into every test proposal (`digest('b')`).
const SUBJECT_DIGEST: &str =
    "sha256:6262626262626262626262626262626262626262626262626262626262626262";
const TTL_MS: u64 = 600_000;

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn time(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .unwrap()
        .with_timezone(&Utc)
}

fn digest_value(value: &serde_json::Value) -> String {
    format!(
        "sha256:{:x}",
        Sha256::digest(serde_jcs::to_vec(value).unwrap())
    )
}

/// One fixed executor-plan document; the resolver tests never inspect work
/// semantics, but the persisted proposal must carry a verifiably derived AG
/// executable-work identity.
fn test_executor_plan() -> serde_json::Value {
    serde_json::json!({
        "schema": "ag-effectd.docket-executor-plan/v1",
        "attempt_store": "/tmp/wo9-1-vector/effect-attempts.sqlite",
        "subject": SUBJECT_DIGEST,
        "scope": digest('1'),
        "effect_index": 0,
        "effect": {
            "kind": "managed_file_put",
            "target": "wo9-1-vector",
            "path": "/tmp/wo9-1-vector/target",
            "expected_content": null,
            "content": digest('5'),
            "mode": 384,
            "uid": 1000,
            "gid": 1000
        },
        "artifacts": [{"digest": digest('5'), "path": "/tmp/wo9-1-vector/artifact"}],
        "file_policy": {
            "max_content_bytes": 1024,
            "trusted_ancestor_uid": 0,
            "trusted_parent_uid": 1000,
            "require_private_parent_writes": true
        },
        "preparation_checkpoint": null
    })
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

/// Re-seal a policy after content mutation: `policy_id` is the canonical
/// content hash of the policy preimage.
fn reseal_policy(policy: &mut PosturePolicy) {
    policy.policy_id.clear();
    policy.policy_id = policy.computed_policy_id().unwrap();
}

struct SupportPort {
    standing: SupportStandingV1,
}

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
            expiry: (self.standing == SupportStandingV1::Current).then(|| SupportExpiryV1 {
                clock_id: "pulse-receiver-clock-1".into(),
                tick: 101,
            }),
            standing: self.standing,
            evidence_refs: if self.standing == SupportStandingV1::Current {
                vec![digest('9')]
            } else {
                Vec::new()
            },
            contradiction_refs: if self.standing == SupportStandingV1::Contradictory {
                vec![digest('8')]
            } else {
                Vec::new()
            },
        };
        support.support_id = support.computed_support_id()?;
        support.validate_for(query)?;
        Ok(support)
    }
}

struct FailingSupportPort;

impl PresentEvidencePortV1 for FailingSupportPort {
    fn resolve(&mut self, _: &PresentEvidenceQueryV1) -> Result<QualifiedSupportV1, String> {
        Err("qualified currentness unavailable".into())
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
        Err("resolver tests never sync AG status".into())
    }
}

fn occurrence_uuid(occurrence: u64) -> String {
    format!("00000000-0000-4000-8000-{occurrence:012}")
}

/// One sealed canonical cycle request for `occurrence` in `policy`'s family.
/// `with_proposal` attaches the precompiled workflow proposal, which is what
/// makes the cycle prepare an AG occurrence and persist the typed intent that
/// binds the Nightshift subject to the AG subject digest.
fn cycle_request(
    policy: &PosturePolicy,
    inputs: &DiagnosticInputs,
    recurrence: &RecurrenceEvidence,
    occurrence: u64,
    observation_id: &str,
    with_proposal: bool,
) -> CanonicalCycleRequestV1 {
    cycle_request_in(
        policy,
        inputs,
        recurrence,
        occurrence,
        observation_id,
        with_proposal,
        "config-v1",
        "nightshift-scheduler-1",
    )
}

#[allow(clippy::too_many_arguments)]
fn cycle_request_in(
    policy: &PosturePolicy,
    inputs: &DiagnosticInputs,
    recurrence: &RecurrenceEvidence,
    occurrence: u64,
    observation_id: &str,
    with_proposal: bool,
    configuration_version: &str,
    scheduler_clock_id: &str,
) -> CanonicalCycleRequestV1 {
    let slot = RecurrenceSlotV1::new(
        policy.policy_id.clone(),
        configuration_version.into(),
        policy.subject.id.clone(),
        policy.subject.scope.digest.clone(),
        scheduler_clock_id.into(),
        time("2026-07-27T20:00:00Z") + chrono::Duration::minutes(occurrence as i64),
        time("2026-07-27T20:00:30Z") + chrono::Duration::minutes(occurrence as i64),
        occurrence,
        RecurrenceTriggerV1::Scheduled,
        None,
    )
    .unwrap();
    let immutable_parameters = serde_json::json!({"resource_id":"resource-1"});
    let work_schema = "example.exact-work/v1";
    let plan = test_executor_plan();
    let work = ag_executor_plan_identity(&plan).unwrap();
    CanonicalCycleRequestV1 {
        schema: String::new(),
        request_id: String::new(),
        slot,
        scheduler_clock_id: scheduler_clock_id.into(),
        evaluated_at: time("2026-07-27T20:00:10Z")
            + chrono::Duration::minutes(occurrence as i64),
        observation_id: observation_id.into(),
        policy: policy.clone(),
        inputs: inputs.clone(),
        recurrence: recurrence.clone(),
        external_evidence: None,
        decision_external_evidence: None,
        temporal_policy: None,
        proposal: with_proposal.then(|| PrecompiledWorkflowProposalV2 {
            schema: nightshiftd::canonical_runtime::PRECOMPILED_PROPOSAL_SCHEMA_V2.into(),
            workflow_id: "workflow:host-care".into(),
            intent_kind: "inspect_exact_resource".into(),
            subject_digest: SUBJECT_DIGEST.into(),
            ag_executor_plan: plan,
            immutable_parameters,
            campaign_id: digest('a'),
            occurrence_id: occurrence_uuid(occurrence),
            mode: AgOpenModeV1::Genesis {
                genesis: serde_json::json!({
                    "campaign": digest('a'),
                    "occurrence": occurrence_uuid(occurrence),
                    "program": digest('2'),
                    "expected_ag_work": work.clone(),
                    "residuals": [],
                    "budget": {"retry_limit":1,"retries_used":0,"probe_limit":1,"probes_used":0,"escalation_limit":1,"escalations_used":0}
                }),
            },
            proposal_input: serde_json::json!({
                "observation": observation_id,
                "proposal": {
                    "schema":"ag.governed-loop.exact-work-proposal/v1",
                    "campaign":digest('a'),
                    "subject":SUBJECT_DIGEST,
                    "scope":policy.subject.scope.digest,
                    "work_schema":work_schema,
                    "work":work,
                    "repair":null
                },
                "class":"initial"
            }),
        }),
        authoring_context: None,
        reviewed_plan_binding: None,
    }
    .seal()
    .unwrap()
}

fn run_cycle(store: &mut CanonicalStore, request: CanonicalCycleRequestV1) -> CycleRunOutcomeV1 {
    let mut support = SupportPort {
        standing: SupportStandingV1::Current,
    };
    let mut ag = FakeAg;
    CanonicalRuntime::new(store, TestNqAdmissionPort, &mut support, &mut ag)
        .run_cycle(request)
        .unwrap()
}

fn run_cycle_with_support(
    store: &mut CanonicalStore,
    request: CanonicalCycleRequestV1,
    standing: SupportStandingV1,
) -> CycleRunOutcomeV1 {
    let mut support = SupportPort { standing };
    let mut ag = FakeAg;
    CanonicalRuntime::new(store, TestNqAdmissionPort, &mut support, &mut ag)
        .run_cycle(request)
        .unwrap()
}

/// The cited cycle's posture evaluation instant in unix milliseconds.
fn evaluated_ms(occurrence: u64) -> u64 {
    u64::try_from(
        (time("2026-07-27T20:00:10Z") + chrono::Duration::minutes(occurrence as i64))
            .timestamp_millis(),
    )
    .unwrap()
}

fn ag_request(observation_id: &str, subject: &str, now_unix_ms: u64) -> serde_json::Value {
    serde_json::json!({
        "schema": "ag.governed-loop.observation-request/v1",
        "key": {"campaign": digest('a'), "occurrence": occurrence_uuid(0)},
        "observation": observation_id,
        "subject": subject,
        "now_unix_ms": now_unix_ms,
    })
}

struct Resolution {
    status: String,
    body: serde_json::Value,
}

fn resolve(store: &Path, request: &serde_json::Value) -> Resolution {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nightshift-observation-resolver"))
        .arg("--store")
        .arg(store)
        .arg("--resolver-id")
        .arg(RESOLVER_ID)
        .arg("--default-ttl-ms")
        .arg(TTL_MS.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn nightshift-observation-resolver");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "resolver failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("resolver stdout is one JSON document");
    Resolution {
        status: body["status"].as_str().unwrap().to_owned(),
        body,
    }
}

/// Assert every field AG's frozen v2 contract requires, and no others.
fn assert_v2_shape(body: &serde_json::Value, request: &serde_json::Value) {
    let object = body.as_object().unwrap();
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "basis",
            "currentness",
            "fresh_until_unix_ms",
            "key",
            "normalized_preconditions",
            "observation",
            "resolved_at_unix_ms",
            "resolver_id",
            "schema",
            "status",
            "subject",
        ]
    );
    assert_eq!(body["schema"], "ag.governed-loop.observation-resolution/v2");
    assert_eq!(&body["key"], &request["key"]);
    assert_eq!(&body["observation"], &request["observation"]);
    assert_eq!(&body["subject"], &request["subject"]);
    assert_eq!(body["resolver_id"], RESOLVER_ID);
    assert_eq!(body["resolved_at_unix_ms"], request["now_unix_ms"]);
    // Every response carries a well-formed basis whose digest is the pinned
    // ref; AG re-verifies this relationship independently.
    let basis: DecisionBasisV1 =
        serde_json::from_value(body["basis"].clone()).expect("basis is a valid DecisionBasisV1");
    assert_eq!(
        body["normalized_preconditions"].as_str().unwrap(),
        basis.digest().unwrap()
    );
}

fn fresh_now() -> u64 {
    evaluated_ms(0) + 300_000
}

#[test]
fn current_resolution_carries_the_exact_v2_contract() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("ns.sqlite");
    let (policy, inputs, recurrence) = example_policy_inputs_recurrence();
    let mut store = CanonicalStore::open(&database).unwrap();
    let outcome = run_cycle(
        &mut store,
        cycle_request(&policy, &inputs, &recurrence, 0, &digest('d'), true),
    );
    let CycleRunOutcomeV1::AgOccurrenceOpened { cycle } = outcome else {
        panic!("current cycle opens an AG occurrence")
    };
    drop(store);

    let now = fresh_now();
    let request = ag_request(&digest('d'), SUBJECT_DIGEST, now);
    let resolution = resolve(&database, &request);
    assert_eq!(resolution.status, "current");
    assert_v2_shape(&resolution.body, &request);
    assert_eq!(
        resolution.body["fresh_until_unix_ms"].as_u64().unwrap(),
        evaluated_ms(0) + TTL_MS
    );
    let basis: DecisionBasisV1 = serde_json::from_value(resolution.body["basis"].clone()).unwrap();
    let record = cycle.observation.as_ref().unwrap();
    assert_eq!(basis, normalize_posture(&record.posture));
    // The example posture is clean/not-required, so the emitted basis is
    // byte-identical to the frozen WO-3 cross-repository vector, whose digest
    // AG independently asserts.
    const FROZEN_VECTOR: &str = "{\"atoms\":[\"condition.clean\",\"delivery.not_required\"],\"rule\":{\"digest\":\"sha256:5f8bd1a497e034633d6fd465a6834a2ca8e9a4b20158322fd0a4bc36095f8e67\",\"id\":\"nightshift.posture-normalization\",\"version\":\"1\"},\"schema\":\"nightshift.decision-basis.v1\"}";
    assert_eq!(
        String::from_utf8(basis.canonical_bytes().unwrap()).unwrap(),
        FROZEN_VECTOR
    );
    assert_eq!(
        resolution.body["normalized_preconditions"]
            .as_str()
            .unwrap(),
        "sha256:d67f86277b1604cad1916d01bcd5e01fc3a9002d4630cb8fdf5b749febf4b2c7"
    );
    // The deterministic currentness witness binds the exact persisted record.
    let mut preimage = b"nightshift.observation-currentness.v1\0".to_vec();
    for part in [
        &record.observation_id,
        &record.support.support_id,
        &record.posture.posture_id,
    ] {
        preimage.extend_from_slice(part.as_bytes());
        preimage.push(0);
    }
    assert_eq!(
        resolution.body["currentness"].as_str().unwrap(),
        format!("sha256:{:x}", Sha256::digest(&preimage))
    );
}

#[test]
fn absent_observation_reports_absent_with_sentinel_basis() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("ns.sqlite");
    let (policy, inputs, recurrence) = example_policy_inputs_recurrence();
    let mut store = CanonicalStore::open(&database).unwrap();
    run_cycle(
        &mut store,
        cycle_request(&policy, &inputs, &recurrence, 0, &digest('d'), true),
    );
    drop(store);

    let request = ag_request(&digest('e'), SUBJECT_DIGEST, fresh_now());
    let resolution = resolve(&database, &request);
    assert_eq!(resolution.status, "absent");
    assert_v2_shape(&resolution.body, &request);
    let basis: DecisionBasisV1 = serde_json::from_value(resolution.body["basis"].clone()).unwrap();
    assert_eq!(
        basis.atoms,
        std::collections::BTreeSet::from([
            "condition.unresolved".to_owned(),
            "delivery.failed".to_owned(),
        ])
    );
}

#[test]
fn ambiguous_observation_id_is_contradictory() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("ns.sqlite");
    let (policy, inputs, recurrence) = example_policy_inputs_recurrence();
    let mut store = CanonicalStore::open(&database).unwrap();
    for occurrence in 0..2 {
        run_cycle(
            &mut store,
            cycle_request(
                &policy,
                &inputs,
                &recurrence,
                occurrence,
                &digest('d'),
                true,
            ),
        );
    }
    drop(store);

    let request = ag_request(&digest('d'), SUBJECT_DIGEST, fresh_now());
    let resolution = resolve(&database, &request);
    assert_eq!(resolution.status, "contradictory");
    assert_v2_shape(&resolution.body, &request);
}

#[test]
fn wrong_subject_request_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("ns.sqlite");
    let (policy, inputs, recurrence) = example_policy_inputs_recurrence();
    let mut store = CanonicalStore::open(&database).unwrap();
    run_cycle(
        &mut store,
        cycle_request(&policy, &inputs, &recurrence, 0, &digest('d'), true),
    );
    drop(store);

    let request = ag_request(&digest('d'), &digest('c'), fresh_now());
    let resolution = resolve(&database, &request);
    assert_eq!(resolution.status, "contradictory");
    assert_v2_shape(&resolution.body, &request);
}

#[test]
fn observation_without_an_ag_subject_binding_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("ns.sqlite");
    let (policy, inputs, recurrence) = example_policy_inputs_recurrence();
    let mut store = CanonicalStore::open(&database).unwrap();
    let outcome = run_cycle(
        &mut store,
        cycle_request(&policy, &inputs, &recurrence, 0, &digest('d'), false),
    );
    assert!(matches!(outcome, CycleRunOutcomeV1::PostureOnly { .. }));
    drop(store);

    let request = ag_request(&digest('d'), SUBJECT_DIGEST, fresh_now());
    let resolution = resolve(&database, &request);
    assert_eq!(resolution.status, "contradictory");
    assert_v2_shape(&resolution.body, &request);
}

#[test]
fn contradictory_support_is_contradictory_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("ns.sqlite");
    let (policy, inputs, recurrence) = example_policy_inputs_recurrence();
    let mut store = CanonicalStore::open(&database).unwrap();
    run_cycle_with_support(
        &mut store,
        cycle_request(&policy, &inputs, &recurrence, 0, &digest('d'), true),
        SupportStandingV1::Contradictory,
    );
    drop(store);

    let request = ag_request(&digest('d'), SUBJECT_DIGEST, fresh_now());
    let resolution = resolve(&database, &request);
    assert_eq!(resolution.status, "contradictory");
    assert_v2_shape(&resolution.body, &request);
}

#[test]
fn same_family_later_observation_supersedes() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("ns.sqlite");
    let (policy, inputs, recurrence) = example_policy_inputs_recurrence();
    let mut store = CanonicalStore::open(&database).unwrap();
    let outcome = run_cycle(
        &mut store,
        cycle_request(&policy, &inputs, &recurrence, 0, &digest('d'), true),
    );
    let CycleRunOutcomeV1::AgOccurrenceOpened { cycle } = outcome else {
        panic!("first cycle opens an AG occurrence")
    };
    run_cycle(
        &mut store,
        cycle_request(&policy, &inputs, &recurrence, 1, &digest('e'), false),
    );
    drop(store);

    let request = ag_request(&digest('d'), SUBJECT_DIGEST, fresh_now());
    let resolution = resolve(&database, &request);
    assert_eq!(resolution.status, "superseded");
    assert_v2_shape(&resolution.body, &request);
    // A superseded answer still carries the cited record's honest basis.
    let basis: DecisionBasisV1 = serde_json::from_value(resolution.body["basis"].clone()).unwrap();
    assert_eq!(
        basis,
        normalize_posture(&cycle.observation.as_ref().unwrap().posture)
    );
}

#[test]
fn unrelated_policy_observation_does_not_supersede() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("ns.sqlite");
    let (policy, inputs, recurrence) = example_policy_inputs_recurrence();
    let mut other_policy = policy.clone();
    // A distinct policy generation is a distinct lineage domain; resealing
    // keeps the policy internally exact.
    other_policy.generation = "gen-2".into();
    reseal_policy(&mut other_policy);
    let mut store = CanonicalStore::open(&database).unwrap();
    run_cycle(
        &mut store,
        cycle_request(&policy, &inputs, &recurrence, 0, &digest('d'), true),
    );
    run_cycle(
        &mut store,
        cycle_request(&other_policy, &inputs, &recurrence, 1, &digest('e'), false),
    );
    drop(store);

    let request = ag_request(&digest('d'), SUBJECT_DIGEST, fresh_now());
    let resolution = resolve(&database, &request);
    assert_eq!(resolution.status, "current");
    assert_v2_shape(&resolution.body, &request);
}

#[test]
fn family_isolation_holds_for_scope_configuration_and_clock() {
    for mutation in ["scope", "configuration", "clock"] {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("ns.sqlite");
        let (policy, inputs, recurrence) = example_policy_inputs_recurrence();
        let mut mutated_policy = policy.clone();
        if mutation == "scope" {
            // The scope digest participates in the subject binding of every
            // inventory entry; mutate it consistently and reseal.
            mutated_policy.subject.scope.digest = digest('1');
            for entry in &mut mutated_policy.inventory {
                entry.binding.subject.scope.digest = digest('1');
            }
            reseal_policy(&mut mutated_policy);
        }
        let mut store = CanonicalStore::open(&database).unwrap();
        run_cycle(
            &mut store,
            cycle_request(&policy, &inputs, &recurrence, 0, &digest('d'), true),
        );
        let second = match mutation {
            "configuration" => cycle_request_in(
                &mutated_policy,
                &inputs,
                &recurrence,
                1,
                &digest('e'),
                false,
                "config-v2",
                "nightshift-scheduler-1",
            ),
            "clock" => cycle_request_in(
                &mutated_policy,
                &inputs,
                &recurrence,
                1,
                &digest('e'),
                false,
                "config-v1",
                "nightshift-scheduler-2",
            ),
            _ => cycle_request(
                &mutated_policy,
                &inputs,
                &recurrence,
                1,
                &digest('e'),
                false,
            ),
        };
        run_cycle(&mut store, second);
        drop(store);

        let request = ag_request(&digest('d'), SUBJECT_DIGEST, fresh_now());
        let resolution = resolve(&database, &request);
        assert_eq!(
            resolution.status, "current",
            "{mutation} variation must not supersede"
        );
    }
}

#[test]
fn missed_and_recovery_cycles_do_not_supersede() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("ns.sqlite");
    let (policy, inputs, recurrence) = example_policy_inputs_recurrence();
    let mut store = CanonicalStore::open(&database).unwrap();
    run_cycle(
        &mut store,
        cycle_request(&policy, &inputs, &recurrence, 0, &digest('d'), true),
    );
    // Later logical slot missed: evaluated past its latest-admissible
    // instant. Persisted directly through the store because the runtime's
    // own Missed branch currently passes a whitespace-containing reason that
    // the store's token law rejects (latent runtime issue; out of scope).
    let mut missed = cycle_request(&policy, &inputs, &recurrence, 1, &digest('e'), false);
    missed.evaluated_at = time("2026-07-27T20:02:00Z");
    store
        .record_missed(
            missed.slot,
            "nightshift-scheduler-1",
            time("2026-07-27T20:02:00Z"),
            "slot_missed".into(),
        )
        .unwrap();
    // Later logical slot whose support authority failed: recovery required,
    // no persisted observation.
    let mut failing = FailingSupportPort;
    let mut ag = FakeAg;
    let result =
        CanonicalRuntime::new(&mut store, TestNqAdmissionPort, &mut failing, &mut ag).run_cycle(
            cycle_request(&policy, &inputs, &recurrence, 2, &digest('f'), false),
        );
    assert!(result.is_err());
    drop(store);

    let request = ag_request(&digest('d'), SUBJECT_DIGEST, fresh_now());
    let resolution = resolve(&database, &request);
    assert_eq!(resolution.status, "current");
    assert_v2_shape(&resolution.body, &request);
}

#[test]
fn later_blind_observation_still_supersedes() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("ns.sqlite");
    let (policy, inputs, recurrence) = example_policy_inputs_recurrence();
    let mut store = CanonicalStore::open(&database).unwrap();
    run_cycle(
        &mut store,
        cycle_request(&policy, &inputs, &recurrence, 0, &digest('d'), true),
    );
    // A later observation whose support is Blind is still later knowledge in
    // the same lineage: older sighted evidence must not survive it.
    run_cycle_with_support(
        &mut store,
        cycle_request(&policy, &inputs, &recurrence, 1, &digest('e'), false),
        SupportStandingV1::Blind,
    );
    drop(store);

    let request = ag_request(&digest('d'), SUBJECT_DIGEST, fresh_now());
    let resolution = resolve(&database, &request);
    assert_eq!(resolution.status, "superseded");
    assert_v2_shape(&resolution.body, &request);
}

#[test]
fn catch_up_write_order_does_not_reorder_the_lineage() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("ns.sqlite");
    let (policy, inputs, recurrence) = example_policy_inputs_recurrence();
    let mut store = CanonicalStore::open(&database).unwrap();
    // A slot due before the cited slot is missed; no observation is ever
    // persisted for it. Persisted directly through the store; see the
    // missed-cycle comment in `missed_and_recovery_cycles_do_not_supersede`.
    let mut missed = cycle_request(&policy, &inputs, &recurrence, 0, &digest('e'), false);
    missed.slot = RecurrenceSlotV1::new(
        policy.policy_id.clone(),
        "config-v1".into(),
        policy.subject.id.clone(),
        policy.subject.scope.digest.clone(),
        "nightshift-scheduler-1".into(),
        time("2026-07-27T19:59:00Z"),
        time("2026-07-27T19:59:30Z"),
        0,
        RecurrenceTriggerV1::Scheduled,
        None,
    )
    .unwrap();
    let missed_cycle = store
        .record_missed(
            missed.slot,
            "nightshift-scheduler-1",
            time("2026-07-27T19:59:45Z"),
            "slot_missed".into(),
        )
        .unwrap();
    // The cited cycle observes on its own later-due slot and opens its AG
    // occurrence.
    let outcome = run_cycle(
        &mut store,
        cycle_request(&policy, &inputs, &recurrence, 0, &digest('f'), true),
    );
    assert!(matches!(
        outcome,
        CycleRunOutcomeV1::AgOccurrenceOpened { .. }
    ));
    // The catch-up for the missed earlier-due slot completes last (latest
    // write), but its logical order stays strictly earlier.
    let mut catch_up = cycle_request(&policy, &inputs, &recurrence, 0, &digest('9'), false);
    catch_up.slot = RecurrenceSlotV1::new(
        policy.policy_id.clone(),
        "config-v1".into(),
        policy.subject.id.clone(),
        policy.subject.scope.digest.clone(),
        "nightshift-scheduler-1".into(),
        time("2026-07-27T19:59:00Z"),
        time("2026-07-27T20:10:00Z"),
        0,
        RecurrenceTriggerV1::CatchUp,
        Some(missed_cycle.slot.slot_id.clone()),
    )
    .unwrap();
    catch_up.evaluated_at = time("2026-07-27T20:04:00Z");
    let catch_up = catch_up.seal().unwrap();
    let outcome = run_cycle(&mut store, catch_up);
    assert!(matches!(outcome, CycleRunOutcomeV1::PostureOnly { .. }));
    drop(store);

    // Resolving the cited cycle must see itself as latest: the catch-up's
    // later write time cannot override logical slot order.
    let request = ag_request(&digest('f'), SUBJECT_DIGEST, fresh_now());
    let resolution = resolve(&database, &request);
    assert_eq!(
        resolution.status, "current",
        "unexpected resolution: {}",
        resolution.body
    );
    assert_v2_shape(&resolution.body, &request);
}

#[test]
fn stale_takes_precedence_over_superseded() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("ns.sqlite");
    let (policy, inputs, recurrence) = example_policy_inputs_recurrence();
    let mut store = CanonicalStore::open(&database).unwrap();
    run_cycle(
        &mut store,
        cycle_request(&policy, &inputs, &recurrence, 0, &digest('d'), true),
    );
    run_cycle(
        &mut store,
        cycle_request(&policy, &inputs, &recurrence, 1, &digest('e'), false),
    );
    drop(store);

    // Both stale (beyond the cited window) and superseded: Stale wins.
    let request = ag_request(&digest('d'), SUBJECT_DIGEST, evaluated_ms(0) + TTL_MS + 1);
    let resolution = resolve(&database, &request);
    assert_eq!(resolution.status, "stale");
    assert_v2_shape(&resolution.body, &request);
}

#[test]
fn freshness_boundary_is_exact() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("ns.sqlite");
    let (policy, inputs, recurrence) = example_policy_inputs_recurrence();
    let mut store = CanonicalStore::open(&database).unwrap();
    run_cycle(
        &mut store,
        cycle_request(&policy, &inputs, &recurrence, 0, &digest('d'), true),
    );
    drop(store);

    let fresh_until = evaluated_ms(0) + TTL_MS;
    let at_boundary = ag_request(&digest('d'), SUBJECT_DIGEST, fresh_until);
    assert_eq!(resolve(&database, &at_boundary).status, "stale");
    let just_inside = ag_request(&digest('d'), SUBJECT_DIGEST, fresh_until - 1);
    assert_eq!(resolve(&database, &just_inside).status, "current");
}

#[test]
fn crashed_in_flight_cycle_does_not_supersede_and_restart_is_deterministic() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("ns.sqlite");
    let (policy, inputs, recurrence) = example_policy_inputs_recurrence();
    let mut store = CanonicalStore::open(&database).unwrap();
    let outcome = run_cycle(
        &mut store,
        cycle_request(&policy, &inputs, &recurrence, 0, &digest('d'), true),
    );
    let CycleRunOutcomeV1::AgOccurrenceOpened { cycle } = outcome else {
        panic!("first cycle opens an AG occurrence")
    };
    // A cycle claimed but lost before its observation persisted (crash).
    let crashed_slot = RecurrenceSlotV1::new(
        policy.policy_id.clone(),
        "config-v1".into(),
        policy.subject.id.clone(),
        policy.subject.scope.digest.clone(),
        "nightshift-scheduler-1".into(),
        time("2026-07-27T20:01:00Z"),
        time("2026-07-27T20:01:30Z"),
        1,
        RecurrenceTriggerV1::Scheduled,
        None,
    )
    .unwrap();
    store
        .claim_slot(
            crashed_slot,
            "nightshift-scheduler-1",
            time("2026-07-27T20:01:10Z"),
        )
        .unwrap();
    let before = store.get_cycle(&cycle.cycle_id).unwrap();
    drop(store);

    let request = ag_request(&digest('d'), SUBJECT_DIGEST, fresh_now());
    let first = resolve(&database, &request);
    assert_eq!(first.status, "current");
    // A fresh resolver process over the reopened store returns the exact same
    // document.
    let second = resolve(&database, &request);
    assert_eq!(first.body, second.body);

    // Resolution mutated no logical cycle state.
    let store = CanonicalStore::open(&database).unwrap();
    assert_eq!(before, store.get_cycle(&cycle.cycle_id).unwrap());
}

#[test]
fn process_failures_are_never_encoded_as_statuses() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("ns.sqlite");
    let (policy, inputs, recurrence) = example_policy_inputs_recurrence();
    let mut store = CanonicalStore::open(&database).unwrap();
    run_cycle(
        &mut store,
        cycle_request(&policy, &inputs, &recurrence, 0, &digest('d'), true),
    );
    drop(store);

    let run = |stdin: &[u8], resolver_id: &str, store: &Path| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_nightshift-observation-resolver"))
            .arg("--store")
            .arg(store)
            .arg("--resolver-id")
            .arg(resolver_id)
            .arg("--default-ttl-ms")
            .arg(TTL_MS.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(stdin).unwrap();
        child.wait_with_output().unwrap()
    };

    // Malformed request JSON.
    let output = run(b"{not json", RESOLVER_ID, &database);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    // Wrong request schema.
    let mut wrong_schema = ag_request(&digest('d'), SUBJECT_DIGEST, fresh_now());
    wrong_schema["schema"] = serde_json::json!("ag.governed-loop.observation-request/v0");
    let output = run(wrong_schema.to_string().as_bytes(), RESOLVER_ID, &database);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    // Empty resolver identity is a configuration error.
    let request = ag_request(&digest('d'), SUBJECT_DIGEST, fresh_now());
    let output = run(request.to_string().as_bytes(), "", &database);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    // A missing store is a process error, not `absent`.
    let output = run(
        request.to_string().as_bytes(),
        RESOLVER_ID,
        &directory.path().join("missing.sqlite"),
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

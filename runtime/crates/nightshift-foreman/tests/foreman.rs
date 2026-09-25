use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
};

use chrono::{Duration, TimeZone as _, Utc};
use nightshift_foreman::{
    read_only_run_snapshot, verify_adapter_contract, AdapterEventKindV1, AdapterEventV1,
    AdapterRegistrationV2, CapacityAdmissionEvidenceV1, CapacityCostClassV1, ContractError,
    ExecutionProfileV2, ForemanAdmissionV1, ForemanCapacityAdmissionV1,
    ForemanCapacityRequirementV1, ForemanError, ForemanStore, HumanQuestionV1, NotStartedReceiptV1,
    ReceiptRepositoryV1, SchedulerStateV1, TeardownDeclarationV1, TerminalReceiptV1,
    WorkItemExecutionV1, WorkerAdapterCapabilitiesV1, WorkerBriefV2, WorkerStartRequestV2,
    FOREMAN_ADMISSION_SCHEMA_V1, FOREMAN_CAPACITY_ADMISSION_SCHEMA_V1,
    FOREMAN_CAPACITY_REQUIREMENT_SCHEMA_V1, FOREMAN_EXECUTION_PROFILE_SCHEMA_V2,
    MAXIMUM_CAPACITY_HISTORY_BYTES, MAXIMUM_WORKER_BRIEF_BYTES,
    WORKER_ADAPTER_CAPABILITIES_SCHEMA_V1, WORKER_ADAPTER_EVENT_SCHEMA_V1,
    WORKER_BRIEF_BASIS_SCHEMA_V2, WORKER_START_REQUEST_SCHEMA_V2,
    WORKER_TERMINAL_RECEIPT_SCHEMA_V1, WORK_ITEM_NOT_STARTED_RECEIPT_SCHEMA_V1,
};
use nightshift_foreman::{
    DeferredProviderDispatchV1, DeferredWakeBasisV1, DeterministicProviderAdmissionEvidenceV1,
    DeterministicProviderAdmissionOutcomeV1, ExactAvailabilityEvidenceV1, ExactMapperSnapshotV1,
    ExecutionAvailabilityObservationV1, ExecutionAvailabilityPolicyV1,
    ExecutionAvailabilityStateV1, ForemanExecutionAvailabilityRequirementV1,
    ParkedResourceLockPolicyV1, ProviderAdmissionDispositionKindV1, ProviderAdmissionDispositionV1,
    ProviderAdmissionOwnerPinsV1, ProviderDispatchOccurrenceV1, ProviderDispositionEvidenceV1,
    ProviderExecutionIdentityV1, ProviderMechanismStateV1, ProviderModelSelectionV1,
    RunMechanismRequirementsV1, WorkerStartRequestV3, DEFERRED_PROVIDER_DISPATCH_SCHEMA_V1,
    DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V1,
    EXECUTION_AVAILABILITY_OBSERVATION_SCHEMA_V1, EXECUTION_AVAILABILITY_POLICY_SCHEMA_V1,
    FOREMAN_EXECUTION_AVAILABILITY_REQUIREMENT_SCHEMA_V1, HOLDING_QUALIFICATION_EXECUTABLE_ID,
    HOLDING_QUALIFICATION_EXECUTABLE_SHA256, HOLDING_QUALIFICATION_PRODUCER_ID,
    HOLDING_QUALIFICATION_PRODUCER_VERSION, PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V1,
    PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V2,
};
use nightshift_provider_capacity::{
    decide_capacity, AdmissionDisposition as CapacityAdmissionDisposition, CapacityDecisionV1,
    CapacityObservationV1, CapacityPolicyV1, CapacityState, CapacityWindow, Confidence,
    ObservationDisposition, ObservationEvidence, SourceClass, WindowType,
    CAPACITY_OBSERVATION_SCHEMA_V1,
};
use nightshiftd::packet::{
    AuthoringIdentityV1, CampaignIdentityV1, CanonicalizationV1, ExactWorkRefV1,
    GlobalConstraintsV1, ModelRoutingV1, NightshiftPacketV1, RepositoryCustodyV1,
    SourceEvidenceRefV1, SwitchyardRegistrationV1, WorkItemV1, WorkerBudgetV1,
    EXACT_WORK_PROPOSAL_SCHEMA_V1, NIGHTSHIFT_PACKET_DIGEST_PREIMAGE_V1,
    NIGHTSHIFT_PACKET_SCHEMA_V1,
};
use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

#[path = "provider_cases/bounded_turn.rs"]
mod bounded_turn_cases;
#[path = "provider_cases/bounded_turn_echo.rs"]
mod bounded_turn_echo_cases;
#[path = "provider_cases/prelaunch.rs"]
mod prelaunch_cases;
#[path = "provider_cases/cli.rs"]
mod provider_cli_cases;

fn bind_predecessor_fixture(
    mut brief: Value,
    dependency: &str,
    receipt_raw: &[u8],
    request: &WorkerStartRequestV2,
) -> (Vec<u8>, WorkerStartRequestV2) {
    let mut retained = Sha256::new();
    retained.update(b"nightshift.foreman-retained-raw.digest/v1\0");
    retained.update(receipt_raw);
    brief["predecessor_receipts"][dependency]["retained_raw_digest"] =
        Value::String(format!("sha256:{:x}", retained.finalize()));
    brief["predecessor_receipts"][dependency]["bytes_hex"] =
        Value::String(hex::encode(receipt_raw));
    let raw = serde_jcs::to_vec(&brief).unwrap();
    let mut rebound = request.clone();
    let mut digest = Sha256::new();
    digest.update(b"nightshift.worker-brief.digest/v2\0");
    digest.update(&raw);
    rebound.worker_brief_digest = format!("sha256:{:x}", digest.finalize());
    rebound.seal().unwrap();
    (raw, rebound)
}

fn instant(second: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 29, 16, 0, second).unwrap()
}

fn work_item(id: &str, codename: &str, dependencies: Vec<&str>) -> WorkItemV1 {
    WorkItemV1 {
        id: id.into(),
        track: "fixture".into(),
        campaign: CampaignIdentityV1 {
            codename: codename.into(),
            canonical_slug: format!("fixture-{id}"),
        },
        predecessor_lineage: vec![],
        dependencies: dependencies.into_iter().map(str::to_owned).collect(),
        exact_work_refs: vec![ExactWorkRefV1 {
            contract_kind: "exact_work_proposal_v1".into(),
            contract_schema: EXACT_WORK_PROPOSAL_SCHEMA_V1.into(),
            repository: "fixture".into(),
            branch: "campaign/fixture".into(),
            commit: "a".repeat(40),
            path: "proposal.json".into(),
            proposal_ref: format!("sha256:{}", "b".repeat(64)),
        }],
        entry_predicates: vec!["worker inspects exact predecessor evidence".into()],
        allowed_mutation_surfaces: vec!["fixture".into()],
        forbidden_actions: vec!["target actuation".into()],
        acceptance_tests: vec!["exact receipt".into()],
        stop_conditions: vec!["entry predicate fails".into()],
        expected_receipts: vec!["terminal or not-started".into()],
        closeout_requirements: vec!["clean local fixture".into()],
        model_routing: ModelRoutingV1 {
            class: "bounded".into(),
            reason: "deterministic test".into(),
            maximum_mutating_workers: 1,
        },
    }
}

fn packet() -> NightshiftPacketV1 {
    let mut packet = NightshiftPacketV1 {
        schema: NIGHTSHIFT_PACKET_SCHEMA_V1.into(),
        packet_id: "foreman-fixture".into(),
        packet_digest: String::new(),
        created_at: instant(0),
        current_until: instant(0) + Duration::hours(2),
        authoring: AuthoringIdentityV1 {
            agent: "fixture".into(),
            session: "fixture-session".into(),
            authority_basis: "local deterministic qualification".into(),
        },
        canonicalization: CanonicalizationV1 {
            algorithm: "RFC8785-JCS".into(),
            digest_algorithm: "SHA-256".into(),
            digest_preimage: NIGHTSHIFT_PACKET_DIGEST_PREIMAGE_V1.into(),
        },
        source_evidence: vec![SourceEvidenceRefV1 {
            repository: "nightshift".into(),
            branch: "campaign/fixture".into(),
            commit: "a".repeat(40),
            path: "fixture".into(),
            file_digest: format!("sha256:{}", "c".repeat(64)),
            predecessor_classification: "EXACT-FIXTURE".into(),
        }],
        repository_custody: vec![RepositoryCustodyV1 {
            repository: "nightshift".into(),
            path: "/tmp/nightshift-fixture".into(),
            branch: "campaign/fixture".into(),
            commit: "a".repeat(40),
            remote: None,
            remote_commit: None,
            worktree_clean: true,
            discrepancy: None,
        }],
        global_constraints: GlobalConstraintsV1 {
            allowed_actions: vec!["local scheduling".into()],
            forbidden_actions: vec!["target actuation".into()],
            invariants: vec!["scheduler state is not result state".into()],
        },
        work_items: vec![
            work_item("root-a", "ROOT-A", vec![]),
            work_item("root-b", "ROOT-B", vec![]),
            work_item("root-c", "ROOT-C", vec![]),
            work_item("dependent", "DEPENDENT-D", vec!["root-a"]),
        ],
        worker_budget: WorkerBudgetV1 {
            maximum_concurrent_mutating_workers: 2,
            recursive_worker_swarms_forbidden: true,
            reserve_posture: "bounded fixture".into(),
        },
        human_question_criteria: vec!["exact operator authority missing".into()],
        switchyard: SwitchyardRegistrationV1 {
            alias: "fixture".into(),
            plan_ref: String::new(),
            transport_fields: vec!["alias".into(), "plan_ref".into(), "nonce".into()],
        },
    };
    packet.seal().unwrap();
    packet
}

fn admission(packet: &NightshiftPacketV1) -> ForemanAdmissionV1 {
    let mut admission = ForemanAdmissionV1 {
        schema: FOREMAN_ADMISSION_SCHEMA_V1.into(),
        admission_digest: format!("sha256:{}", "0".repeat(64)),
        run_id: "run-fixture".into(),
        packet_digest: packet.packet_digest.clone(),
        operator_basis_digest: format!("sha256:{}", "d".repeat(64)),
        admitted_at: instant(0),
        expires_at: instant(0) + Duration::hours(1),
        local_runtime_identity: "runtime-fixture".into(),
        maximum_concurrent_workers: 2,
        allowed_adapter_ids: vec!["fixture-adapter".into()],
        allowed_provider_model_classes: vec!["bounded".into()],
        maximum_new_attempts_per_work_item: 1,
        authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".into(),
        target_effects_authorized: false,
    };
    admission.seal().unwrap();
    admission
}

fn profile(packet: &NightshiftPacketV1, admission: &ForemanAdmissionV1) -> ExecutionProfileV2 {
    let mut work_items = BTreeMap::new();
    for item in &packet.work_items {
        let locks = match item.id.as_str() {
            "root-a" | "root-c" => vec!["repository:shared".into()],
            "root-b" => vec!["repository:other".into()],
            _ => vec!["repository:dependent".into()],
        };
        work_items.insert(
            item.id.clone(),
            WorkItemExecutionV1 {
                adapter_id: "fixture-adapter".into(),
                workspace_identity: format!("workspace:{}", item.id),
                resource_lock_keys: locks,
                provider_model_class: "bounded".into(),
            },
        );
    }
    let mut profile = ExecutionProfileV2 {
        schema: FOREMAN_EXECUTION_PROFILE_SCHEMA_V2.into(),
        profile_digest: format!("sha256:{}", "0".repeat(64)),
        packet_digest: packet.packet_digest.clone(),
        admission_digest: admission.admission_digest.clone(),
        adapters: BTreeMap::from([(
            "fixture-adapter".into(),
            AdapterRegistrationV2 {
                adapter_id: "fixture-adapter".into(),
                protocol: "fixture.adapter/v1".into(),
                adapter_version: "fixture.adapter/v1".into(),
                executable_identity: format!("sha256:{}", "e".repeat(64)),
                bounded_arguments: vec![],
            },
        )]),
        work_items,
        budget_policy_ref: "budget:fixture".into(),
        log_custody_root: "/tmp/foreman-fixture/log".into(),
        receipt_custody_root: "/tmp/foreman-fixture/receipts".into(),
        maximum_event_bytes: 65_536,
        maximum_worker_output_bytes: None,
        maximum_receipt_bytes: 131_072,
        adapter_timeout_seconds: 60,
        closeout_policy: "ALL_EXPLICIT_TERMINAL_OR_NOT_STARTED".into(),
    };
    profile.seal().unwrap();
    profile
}

fn setup() -> (
    TempDir,
    ForemanStore,
    NightshiftPacketV1,
    ForemanAdmissionV1,
    ExecutionProfileV2,
) {
    let directory = tempfile::tempdir().unwrap();
    let packet = packet();
    let admission = admission(&packet);
    let profile = profile(&packet, &admission);
    let store = ForemanStore::open(directory.path().join("foreman.sqlite")).unwrap();
    store
        .admit(
            &packet.canonical_bytes().unwrap(),
            &serde_jcs::to_vec(&admission).unwrap(),
            &serde_jcs::to_vec(&profile).unwrap(),
            instant(0),
        )
        .unwrap();
    (directory, store, packet, admission, profile)
}

fn terminal(
    packet: &NightshiftPacketV1,
    request: &nightshift_foreman::WorkerStartRequestV2,
    state: &str,
    classification: &str,
) -> TerminalReceiptV1 {
    let mut receipt = TerminalReceiptV1 {
        schema: WORKER_TERMINAL_RECEIPT_SCHEMA_V1.into(),
        receipt_digest: format!("sha256:{}", "0".repeat(64)),
        packet_digest: packet.packet_digest.clone(),
        run_id: request.run_id.clone(),
        work_item_id: request.work_item_id.clone(),
        attempt_id: request.attempt_id.clone(),
        adapter_id: "fixture-adapter".into(),
        adapter_version: "fixture.adapter/v1".into(),
        provider_identity: "provider:fixture".into(),
        model_identity: "model:fixture".into(),
        session_identity: Some("session:fixture".into()),
        thread_identity: None,
        turn_identity: None,
        queue_identity: None,
        started_at: instant(1),
        ended_at: instant(5),
        state: state.into(),
        result_classification: classification.into(),
        repositories: vec![ReceiptRepositoryV1 {
            repository: "fixture".into(),
            branch: "campaign/fixture".into(),
            head: "f".repeat(40),
            push_status: "sole-local fixture".into(),
        }],
        tests: vec!["fixture passed".into()],
        evidence: vec!["fixture evidence".into()],
        live_or_production_mutations: vec![],
        remaining_trigger: "none".into(),
        next_lawful_action: "inspect exact receipt".into(),
        human_questions: vec![],
        teardown: TeardownDeclarationV1 {
            live_runtime: "none".into(),
            secrets: "none".into(),
            teardown: "none".into(),
        },
        extensions: BTreeMap::from([(
            "future_field".into(),
            Value::String("retained raw, no semantics".into()),
        )]),
    };
    receipt.seal().unwrap();
    receipt
}

fn not_started(packet: &NightshiftPacketV1, work_item: &str) -> NotStartedReceiptV1 {
    let mut receipt = NotStartedReceiptV1 {
        schema: WORK_ITEM_NOT_STARTED_RECEIPT_SCHEMA_V1.into(),
        receipt_digest: format!("sha256:{}", "0".repeat(64)),
        packet_digest: packet.packet_digest.clone(),
        run_id: "run-fixture".into(),
        work_item_id: work_item.into(),
        recorded_at: instant(6),
        state: "ENTRY-BLOCKED-EXACT".into(),
        result_classification: "UNKNOWN-CUSTOM-CLASSIFICATION".into(),
        evidence: vec!["exact entry evidence".into()],
        remaining_trigger: "new explicit successor evidence".into(),
        next_lawful_action: "create a successor occurrence".into(),
        human_questions: vec![],
        extensions: BTreeMap::new(),
    };
    receipt.seal().unwrap();
    receipt
}

#[test]
fn admission_is_closed_bound_and_current() {
    let packet = packet();
    let admission = admission(&packet);
    let profile = profile(&packet, &admission);
    let directory = tempfile::tempdir().unwrap();
    let store = ForemanStore::open(directory.path().join("db")).unwrap();

    let mut substituted = admission.clone();
    substituted.packet_digest = format!("sha256:{}", "1".repeat(64));
    substituted.seal().unwrap();
    assert!(matches!(
        store.admit(
            &packet.canonical_bytes().unwrap(),
            &serde_jcs::to_vec(&substituted).unwrap(),
            &serde_jcs::to_vec(&profile).unwrap(),
            instant(0)
        ),
        Err(ForemanError::IdentityMismatch("packet_digest"))
            | Err(ForemanError::IdentityMismatch("admission_digest"))
    ));
    assert!(store
        .admit(
            &packet.canonical_bytes().unwrap(),
            &serde_jcs::to_vec(&admission).unwrap(),
            &serde_jcs::to_vec(&profile).unwrap(),
            instant(0) + Duration::hours(3)
        )
        .is_err());
    store
        .admit(
            &packet.canonical_bytes().unwrap(),
            &serde_jcs::to_vec(&admission).unwrap(),
            &serde_jcs::to_vec(&profile).unwrap(),
            instant(0),
        )
        .unwrap();
    assert!(matches!(
        store.admit(
            &packet.canonical_bytes().unwrap(),
            &serde_jcs::to_vec(&admission).unwrap(),
            &serde_jcs::to_vec(&profile).unwrap(),
            instant(0),
        ),
        Err(ForemanError::DuplicateRun(_))
    ));

    let mut unknown = serde_json::to_value(&admission).unwrap();
    unknown["authority"] = Value::Bool(true);
    assert!(ForemanAdmissionV1::from_slice(&serde_json::to_vec(&unknown).unwrap()).is_err());

    let mut unversioned_adapter = serde_json::to_value(&profile).unwrap();
    unversioned_adapter["adapters"]["fixture-adapter"]
        .as_object_mut()
        .unwrap()
        .remove("adapter_version");
    assert!(
        ExecutionProfileV2::from_slice(&serde_json::to_vec(&unversioned_adapter).unwrap()).is_err()
    );

    let capabilities = WorkerAdapterCapabilitiesV1 {
        schema: WORKER_ADAPTER_CAPABILITIES_SCHEMA_V1.into(),
        adapter_id: "fixture-adapter".into(),
        adapter_protocol: "fixture.adapter/v1".into(),
        adapter_version: "fixture.adapter/v1".into(),
        adapter_executable_identity: format!("sha256:{}", "e".repeat(64)),
        provider_kind: "fixture-provider".into(),
        commands: ["capabilities", "start", "resume", "status", "collect"]
            .map(str::to_owned)
            .to_vec(),
        approval_policy: "SURFACE_ONLY_NO_RESPONSE".into(),
        expected_start_request_schema: WORKER_START_REQUEST_SCHEMA_V2.into(),
        event_schema: WORKER_ADAPTER_EVENT_SCHEMA_V1.into(),
        terminal_receipt_schema: WORKER_TERMINAL_RECEIPT_SCHEMA_V1.into(),
        target_effects_authorized: false,
    };
    capabilities.validate().unwrap();
    let mut widened = capabilities;
    widened.commands.push("approve".into());
    assert!(widened.validate().is_err());
}

#[test]
fn wal_journal_locks_restart_and_classification_separation_qualify() {
    let (directory, store, packet, _, profile) = setup();
    assert_eq!(store.journal_mode().unwrap().to_ascii_lowercase(), "wal");
    let initial = store.projection("run-fixture").unwrap();
    let root_a_initial = initial
        .work_items
        .iter()
        .find(|item| item.work_item_id == "root-a")
        .unwrap();
    let dependent_initial = initial
        .work_items
        .iter()
        .find(|item| item.work_item_id == "dependent")
        .unwrap();
    assert_eq!(
        root_a_initial.scheduler_state,
        SchedulerStateV1::ReadyEntryEvaluation
    );
    assert_eq!(
        dependent_initial.scheduler_state,
        SchedulerStateV1::WaitingDependencies
    );
    assert!(initial.work_items.iter().all(|item| {
        item.accepted_terminal_outcome.is_none()
            && item.result_absent_until_terminal_receipt_acceptance
    }));
    let initial_json = serde_json::to_value(&initial).unwrap();
    assert!(initial_json.get("aggregate_result").is_none());

    let root_a = store
        .prepare_attempt("run-fixture", "root-a", instant(1))
        .unwrap();
    assert_eq!(root_a.schema, WORKER_START_REQUEST_SCHEMA_V2);
    assert_eq!(root_a.adapter_id, "fixture-adapter");
    assert_eq!(root_a.adapter_version, "fixture.adapter/v1");
    let mut excessive_timeout = root_a.clone();
    excessive_timeout.timeout_seconds = 86_401;
    assert!(matches!(
        excessive_timeout.seal(),
        Err(ContractError::InvalidField("worker start boundary"))
    ));
    let mut excessive_output = root_a.clone();
    excessive_output.maximum_output_bytes = 16 * 1024 * 1024 + 1;
    assert!(matches!(
        excessive_output.seal(),
        Err(ContractError::InvalidField("worker start boundary"))
    ));
    let registration = &profile.adapters["fixture-adapter"];
    let capabilities = WorkerAdapterCapabilitiesV1 {
        schema: WORKER_ADAPTER_CAPABILITIES_SCHEMA_V1.into(),
        adapter_id: registration.adapter_id.clone(),
        adapter_protocol: registration.protocol.clone(),
        adapter_version: registration.adapter_version.clone(),
        adapter_executable_identity: registration.executable_identity.clone(),
        provider_kind: "fixture-provider".into(),
        commands: ["capabilities", "start", "resume", "status", "collect"]
            .map(str::to_owned)
            .to_vec(),
        approval_policy: "SURFACE_ONLY_NO_RESPONSE".into(),
        expected_start_request_schema: WORKER_START_REQUEST_SCHEMA_V2.into(),
        event_schema: WORKER_ADAPTER_EVENT_SCHEMA_V1.into(),
        terminal_receipt_schema: WORKER_TERMINAL_RECEIPT_SCHEMA_V1.into(),
        target_effects_authorized: false,
    };
    let capabilities_raw = serde_jcs::to_vec(&capabilities).unwrap();
    let verified = verify_adapter_contract(&profile, "root-a", &capabilities_raw, &root_a).unwrap();
    assert_eq!(verified.adapter_version, "fixture.adapter/v1");
    assert!(verified.capabilities_raw_digest.starts_with("sha256:"));
    let mut capabilities_digest = Sha256::new();
    capabilities_digest.update(b"nightshift.worker-adapter-capabilities.raw/v1\0");
    capabilities_digest.update(&capabilities_raw);
    assert_eq!(
        verified.capabilities_raw_digest,
        format!("sha256:{:x}", capabilities_digest.finalize())
    );
    assert!(verify_adapter_contract(
        &profile,
        "root-a",
        &serde_json::to_vec_pretty(&capabilities).unwrap(),
        &root_a,
    )
    .is_err());
    let mut substituted_capabilities = capabilities.clone();
    substituted_capabilities.adapter_executable_identity = format!("sha256:{}", "f".repeat(64));
    assert!(verify_adapter_contract(
        &profile,
        "root-a",
        &serde_jcs::to_vec(&substituted_capabilities).unwrap(),
        &root_a,
    )
    .is_err());
    let mut substituted_start = root_a.clone();
    substituted_start.adapter_version = "fixture.adapter/v2".into();
    substituted_start.seal().unwrap();
    assert!(
        verify_adapter_contract(&profile, "root-a", &capabilities_raw, &substituted_start,)
            .is_err()
    );
    let binding = root_a.attempt_binding();
    binding.validate().unwrap();
    assert_eq!(binding.request_digest, root_a.request_digest);
    let brief = store.worker_brief("run-fixture", "root-a").unwrap();
    let brief_value: Value = serde_json::from_slice(&brief).unwrap();
    WorkerBriefV2::from_slice_for_start(&brief, &root_a).unwrap();
    assert_eq!(brief_value["schema"], WORKER_BRIEF_BASIS_SCHEMA_V2);
    assert_eq!(brief_value["packet_digest"], packet.packet_digest);
    assert_eq!(
        serde_json::from_str::<Value>(brief_value["work_item"]["canonical_json"].as_str().unwrap())
            .unwrap()["id"],
        "root-a"
    );
    assert_eq!(
        hex::decode(brief_value["packet_source"]["bytes_hex"].as_str().unwrap()).unwrap(),
        packet.canonical_bytes().unwrap()
    );
    let mut digest = Sha256::new();
    digest.update(b"nightshift.worker-brief.digest/v2\0");
    digest.update(&brief);
    assert_eq!(
        root_a.worker_brief_digest,
        format!("sha256:{:x}", digest.finalize())
    );
    assert!(matches!(
        store.prepare_attempt("run-fixture", "root-c", instant(1)),
        Err(ForemanError::ResourceUnavailable(_))
    ));
    let root_b = store
        .prepare_attempt("run-fixture", "root-b", instant(1))
        .unwrap();
    assert_ne!(root_a.attempt_id, root_b.attempt_id);

    drop(store);
    let store = ForemanStore::open(directory.path().join("foreman.sqlite")).unwrap();
    let after_restart = store.projection("run-fixture").unwrap();
    assert_eq!(
        after_restart
            .work_items
            .iter()
            .find(|item| item.work_item_id == "root-a")
            .unwrap()
            .active_attempt_id
            .as_deref(),
        Some(root_a.attempt_id.as_str())
    );
    store
        .record_resume_requested("run-fixture", "root-a", &root_a.attempt_id, instant(2))
        .unwrap();

    let mut event = AdapterEventV1 {
        schema: WORKER_ADAPTER_EVENT_SCHEMA_V1.into(),
        event_digest: format!("sha256:{}", "0".repeat(64)),
        event_id: "event-question".into(),
        packet_digest: packet.packet_digest.clone(),
        run_id: "run-fixture".into(),
        work_item_id: "root-a".into(),
        attempt_id: root_a.attempt_id.clone(),
        adapter_id: "fixture-adapter".into(),
        adapter_version: "fixture.adapter/v1".into(),
        occurred_at: instant(3),
        kind: AdapterEventKindV1::HumanQuestion,
        provider_identity: Some("provider:fixture".into()),
        model_identity: Some("model:fixture".into()),
        session_identity: Some("session:fixture".into()),
        thread_identity: None,
        turn_identity: None,
        queue_identity: None,
        message: None,
        human_question: Some(HumanQuestionV1 {
            question_id: "question-one".into(),
            question: "Which exact protected approval exists?".into(),
            exhausted_evidence: "No approval record is present.".into(),
            safe_default: "Do not perform the protected effect.".into(),
            consequences: "This lane remains waiting.".into(),
            resume_point: "Resume this exact attempt after evidence arrives.".into(),
        }),
        extensions: BTreeMap::from([(
            "future_observation".into(),
            Value::String("raw only".into()),
        )]),
    };
    event.seal().unwrap();
    let event_raw = serde_json::to_vec(&event).unwrap();
    store.accept_adapter_event(&event_raw).unwrap();
    assert!(matches!(
        store.accept_adapter_event(&event_raw),
        Err(ForemanError::DuplicateEvent(_))
    ));
    let projection = store.projection("run-fixture").unwrap();
    assert_eq!(
        projection
            .work_items
            .iter()
            .find(|item| item.work_item_id == "root-a")
            .unwrap()
            .scheduler_state,
        SchedulerStateV1::WaitingHuman
    );
    assert_eq!(
        projection
            .work_items
            .iter()
            .find(|item| item.work_item_id == "root-b")
            .unwrap()
            .scheduler_state,
        SchedulerStateV1::Dispatching
    );

    let receipt = terminal(
        &packet,
        &root_a,
        "CUSTOM-RAW-STATE",
        "NOT-A-SCHEDULER-SUCCESS-TOKEN",
    );
    store
        .accept_terminal_receipt(&serde_jcs::to_vec(&receipt).unwrap())
        .unwrap();
    let projection = store.projection("run-fixture").unwrap();
    let dependent = projection
        .work_items
        .iter()
        .find(|item| item.work_item_id == "dependent")
        .unwrap();
    assert_eq!(
        dependent.scheduler_state,
        SchedulerStateV1::ReadyEntryEvaluation
    );
    assert!(dependent.accepted_terminal_outcome.is_none());
    assert!(matches!(
        store.record_resume_requested("run-fixture", "root-a", &root_a.attempt_id, instant(6)),
        Err(ForemanError::Transition(_))
    ));
    assert!(matches!(
        store.prepare_attempt("run-fixture", "root-a", instant(6)),
        Err(ForemanError::Transition(_))
    ));

    let connection = Connection::open(directory.path().join("foreman.sqlite")).unwrap();
    assert!(connection
        .execute("UPDATE events SET kind = 'changed' WHERE sequence = 1", [])
        .is_err());
}

#[test]
fn exact_closeout_requires_complete_explicit_receipts_and_reproduces() {
    let (_directory, store, packet, _, _) = setup();
    let root_a = store
        .prepare_attempt("run-fixture", "root-a", instant(1))
        .unwrap();
    let root_b = store
        .prepare_attempt("run-fixture", "root-b", instant(1))
        .unwrap();
    assert!(matches!(
        store.close("run-fixture", instant(6)),
        Err(ForemanError::IncompleteCloseout(_))
    ));
    for request in [&root_a, &root_b] {
        let receipt = terminal(&packet, request, "EXACT-STATE", "ARBITRARY-CLASSIFICATION");
        let raw = serde_jcs::to_vec(&receipt).unwrap();
        store.accept_terminal_receipt(&raw).unwrap();
        assert_eq!(
            store
                .raw_terminal_receipt("run-fixture", &request.work_item_id)
                .unwrap(),
            raw
        );
    }
    for work_item in ["root-c", "dependent"] {
        let receipt = not_started(&packet, work_item);
        store
            .accept_not_started(&serde_jcs::to_vec(&receipt).unwrap())
            .unwrap();
    }
    assert!(matches!(
        store.close("run-fixture", instant(5)),
        Err(ForemanError::Transition(_))
    ));
    let first = store.close("run-fixture", instant(6)).unwrap();
    let second = store.close("run-fixture", instant(9)).unwrap();
    assert_eq!(first, second);
    assert_eq!(first, store.export_final("run-fixture").unwrap());
    let value: Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(value["schema"], "nightshift.run-receipts/v1");
    assert_eq!(value["packet_digest"], packet.packet_digest);
    assert_eq!(value["work_items"].as_array().unwrap().len(), 4);
    assert!(value.get("aggregate_result").is_none());

    let case_directory = tempfile::tempdir().unwrap();
    std::fs::write(
        case_directory.path().join("packet.v1.json"),
        packet.canonical_bytes().unwrap(),
    )
    .unwrap();
    std::fs::write(case_directory.path().join("run-receipts.v1.json"), &first).unwrap();
    let loaded = nightshift_casework::load_run_at(case_directory.path(), instant(9)).unwrap();
    assert_eq!(loaded.receipt_bytes, first);
    assert_eq!(loaded.projection.work_items.len(), 4);
}

#[test]
fn provider_completion_wrong_identity_and_receipt_bounds_fail_closed() {
    let (directory, store, packet, _, _) = setup();
    let request = store
        .prepare_attempt("run-fixture", "root-a", instant(1))
        .unwrap();
    store
        .record_dispatch_requested("run-fixture", "root-a", &request.attempt_id, instant(1))
        .unwrap();

    let mut wrong = AdapterEventV1 {
        schema: WORKER_ADAPTER_EVENT_SCHEMA_V1.into(),
        event_digest: format!("sha256:{}", "0".repeat(64)),
        event_id: "wrong-attempt-event".into(),
        packet_digest: packet.packet_digest.clone(),
        run_id: "run-fixture".into(),
        work_item_id: "root-a".into(),
        attempt_id: "attempt-substitution".into(),
        adapter_id: "fixture-adapter".into(),
        adapter_version: "fixture.adapter/v1".into(),
        occurred_at: instant(2),
        kind: AdapterEventKindV1::WorkerStarted,
        provider_identity: None,
        model_identity: None,
        session_identity: None,
        thread_identity: None,
        turn_identity: None,
        queue_identity: None,
        message: None,
        human_question: None,
        extensions: BTreeMap::new(),
    };
    wrong.seal().unwrap();
    assert!(matches!(
        store.accept_adapter_event(&serde_jcs::to_vec(&wrong).unwrap()),
        Err(ForemanError::IdentityMismatch("attempt_id"))
    ));

    let mut completed = wrong;
    completed.event_id = "provider-completed".into();
    completed.attempt_id = request.attempt_id.clone();
    completed.kind = AdapterEventKindV1::ProviderCompletionObservation;
    completed.provider_identity = Some("provider:fixture".into());
    completed.model_identity = Some("model:fixture".into());
    completed.session_identity = Some("session:fixture".into());
    completed.seal().unwrap();
    store
        .accept_adapter_event(&serde_jcs::to_vec(&completed).unwrap())
        .unwrap();

    let mut wrong_version = completed.clone();
    wrong_version.event_id = "wrong-adapter-version".into();
    wrong_version.adapter_version = "fixture.adapter/v2".into();
    wrong_version.seal().unwrap();
    assert!(matches!(
        store.accept_adapter_event(&serde_jcs::to_vec(&wrong_version).unwrap()),
        Err(ForemanError::IdentityMismatch("adapter_version"))
    ));

    let mut checkpoint = completed.clone();
    checkpoint.event_id = "incremental-provider-custody".into();
    checkpoint.kind = AdapterEventKindV1::Checkpoint;
    checkpoint.thread_identity = Some("thread:fixture".into());
    checkpoint.turn_identity = Some("turn:fixture".into());
    checkpoint.queue_identity = Some("queue:fixture".into());
    checkpoint.seal().unwrap();
    store
        .accept_adapter_event(&serde_jcs::to_vec(&checkpoint).unwrap())
        .unwrap();

    for field in [
        "provider_identity",
        "model_identity",
        "session_identity",
        "thread_identity",
        "turn_identity",
        "queue_identity",
    ] {
        let mut contradiction = checkpoint.clone();
        contradiction.event_id = format!("contradiction-{field}");
        match field {
            "provider_identity" => contradiction.provider_identity = Some("provider:other".into()),
            "model_identity" => contradiction.model_identity = Some("model:other".into()),
            "session_identity" => contradiction.session_identity = Some("session:other".into()),
            "thread_identity" => contradiction.thread_identity = Some("thread:other".into()),
            "turn_identity" => contradiction.turn_identity = Some("turn:other".into()),
            "queue_identity" => contradiction.queue_identity = Some("queue:other".into()),
            _ => unreachable!(),
        }
        contradiction.seal().unwrap();
        assert!(matches!(
            store.accept_adapter_event(&serde_jcs::to_vec(&contradiction).unwrap()),
            Err(ForemanError::IdentityMismatch(observed)) if observed == field
        ));
    }

    drop(store);
    let store = ForemanStore::open(directory.path().join("foreman.sqlite")).unwrap();
    let item = store
        .projection("run-fixture")
        .unwrap()
        .work_items
        .into_iter()
        .find(|item| item.work_item_id == "root-a")
        .unwrap();
    assert_eq!(item.scheduler_state, SchedulerStateV1::Checkpointed);
    assert_eq!(item.adapter_version, "fixture.adapter/v1");
    assert_eq!(item.provider_identity.as_deref(), Some("provider:fixture"));
    assert_eq!(item.model_identity.as_deref(), Some("model:fixture"));
    assert_eq!(item.session_identity.as_deref(), Some("session:fixture"));
    assert_eq!(item.thread_identity.as_deref(), Some("thread:fixture"));
    assert_eq!(item.turn_identity.as_deref(), Some("turn:fixture"));
    assert_eq!(item.queue_identity.as_deref(), Some("queue:fixture"));
    assert!(item.accepted_terminal_outcome.is_none());

    assert!(store.accept_terminal_receipt(b"{}").is_err());
    for number in [
        serde_json::json!(1e-7),
        serde_json::json!(1e-6),
        serde_json::json!(1.25),
        serde_json::json!(-0.0),
        serde_json::json!(9_007_199_254_740_991_i64),
        serde_json::json!(-9_007_199_254_740_991_i64),
    ] {
        let mut admitted = terminal(&packet, &request, "EXACT-STATE", "EXACT-CLASSIFICATION");
        admitted.extensions.insert("number".into(), number);
        admitted.seal().unwrap();
        let canonical = serde_jcs::to_vec(&admitted).unwrap();
        let parsed = TerminalReceiptV1::from_slice(&canonical).unwrap();
        parsed.validate().unwrap();
        assert_eq!(serde_jcs::to_vec(&parsed).unwrap(), canonical);
    }

    let mut receipt = terminal(&packet, &request, "EXACT-STATE", "EXACT-CLASSIFICATION");
    receipt.thread_identity = Some("thread:fixture".into());
    receipt.turn_identity = Some("turn:fixture".into());
    receipt.queue_identity = Some("queue:fixture".into());
    receipt.seal().unwrap();
    let mut wrong_attempt_receipt = receipt.clone();
    wrong_attempt_receipt.attempt_id = "attempt-substitution".into();
    wrong_attempt_receipt.seal().unwrap();
    assert!(matches!(
        store.accept_terminal_receipt(&serde_jcs::to_vec(&wrong_attempt_receipt).unwrap()),
        Err(ForemanError::IdentityMismatch("attempt_id"))
    ));
    for field in [
        "adapter_version",
        "provider_identity",
        "model_identity",
        "session_identity",
        "thread_identity",
        "turn_identity",
        "queue_identity",
    ] {
        let mut substitution = receipt.clone();
        match field {
            "adapter_version" => substitution.adapter_version = "fixture.adapter/v2".into(),
            "provider_identity" => substitution.provider_identity = "provider:other".into(),
            "model_identity" => substitution.model_identity = "model:other".into(),
            "session_identity" => substitution.session_identity = Some("session:other".into()),
            "thread_identity" => substitution.thread_identity = Some("thread:other".into()),
            "turn_identity" => substitution.turn_identity = Some("turn:other".into()),
            "queue_identity" => substitution.queue_identity = Some("queue:other".into()),
            _ => unreachable!(),
        }
        substitution.seal().unwrap();
        assert!(matches!(
            store.accept_terminal_receipt(&serde_jcs::to_vec(&substitution).unwrap()),
            Err(ForemanError::IdentityMismatch(observed)) if observed == field
        ));
    }
    let mut missing = serde_json::to_value(&receipt).unwrap();
    missing
        .as_object_mut()
        .unwrap()
        .remove("next_lawful_action");
    assert!(store
        .accept_terminal_receipt(&serde_json::to_vec(&missing).unwrap())
        .is_err());
    let mut oversized = serde_jcs::to_vec(&receipt).unwrap();
    oversized.resize(131_073, b' ');
    assert!(matches!(
        store.accept_terminal_receipt(&oversized),
        Err(ForemanError::InputTooLarge("terminal receipt"))
    ));
    store
        .record_terminal_refusal(
            "run-fixture",
            "root-a",
            &request.attempt_id,
            "deterministic malformed receipt fixture",
            instant(4),
        )
        .unwrap();
    assert_eq!(
        store
            .projection("run-fixture")
            .unwrap()
            .work_items
            .into_iter()
            .find(|item| item.work_item_id == "root-a")
            .unwrap()
            .scheduler_state,
        SchedulerStateV1::TerminalReceiptRefused
    );
    store
        .accept_terminal_receipt(&serde_jcs::to_vec(&receipt).unwrap())
        .unwrap();
    assert!(matches!(
        store.record_resume_requested("run-fixture", "root-a", &request.attempt_id, instant(6)),
        Err(ForemanError::Transition(_))
    ));
}

#[test]
fn worker_brief_v2_digest_has_an_independent_fixed_vector() {
    let mut v2 = Sha256::new();
    v2.update(b"nightshift.worker-brief.digest/v2\0");
    v2.update(b"{}");
    assert_eq!(
        format!("sha256:{:x}", v2.finalize()),
        "sha256:ddd2a21b47c3abf533d27d85a53eb3ac93805d5d938f612929ea410a6ec705e7"
    );
    let mut retained = Sha256::new();
    retained.update(b"nightshift.foreman-retained-raw.digest/v1\0");
    retained.update(b"{}");
    assert_eq!(
        format!("sha256:{:x}", retained.finalize()),
        "sha256:defbb1499ef874d99cdf029e5c1dc04dc253d0fc1e0f88f966278cf3934302fe"
    );
    let mut capabilities = Sha256::new();
    capabilities.update(b"nightshift.worker-adapter-capabilities.raw/v1\0");
    capabilities.update(b"{}");
    assert_eq!(
        format!("sha256:{:x}", capabilities.finalize()),
        "sha256:4dbc0996b158b29f3e54274c8fd1ccb774422f75fb38b3fd1a1aae0662ff5c4c"
    );
    let mut v1 = Sha256::new();
    v1.update(b"nightshift.worker-brief.digest/v1\0");
    v1.update(b"{}");
    assert_ne!(
        format!("sha256:{:x}", v1.finalize()),
        "sha256:ddd2a21b47c3abf533d27d85a53eb3ac93805d5d938f612929ea410a6ec705e7"
    );
}

#[test]
fn rfc8785_cross_language_vector_covers_numeric_unicode_and_escape_edges() {
    let value = serde_json::json!({
        "numbers": [
            1e-7, 1e-6, 1e20, 1e21, -0.0,
            9_007_199_254_740_991_i64, -9_007_199_254_740_991_i64
        ],
        "unicode": {"€": "euro", "\r": "cr", "דּ": "hebrew", "😀": "grin", "\u{0080}": "control"},
        "escapes": "\u{0008}\t\n\u{000c}\r\"\\\0",
    });
    let canonical = serde_json_canonicalizer::to_vec(&value).unwrap();
    let expected = "{\"escapes\":\"\\b\\t\\n\\f\\r\\\"\\\\\\u0000\",\"numbers\":[1e-7,0.000001,100000000000000000000,1e+21,0,9007199254740991,-9007199254740991],\"unicode\":{\"\\r\":\"cr\",\"\u{0080}\":\"control\",\"€\":\"euro\",\"😀\":\"grin\",\"דּ\":\"hebrew\"}}";
    assert_eq!(canonical, expected.as_bytes());
    assert_eq!(
        format!("{:x}", Sha256::digest(&canonical)),
        "3e01e561f7ea8f1c5774a2d6f5608067675a43316cb41c9d91cdcd2440b4d90f"
    );

    let admitted = serde_json::json!({
        "numbers": [
            1e-7, 1e-6, 1.25, -0.0,
            9_007_199_254_740_991_i64, -9_007_199_254_740_991_i64
        ],
        "unicode_values": ["€", "\u{0080}", "😀", "דּ"],
        "escapes": "\u{0008}\t\n\u{000c}\r\"\\\0",
    });
    assert_eq!(
        serde_jcs::to_vec(&admitted).unwrap(),
        serde_json_canonicalizer::to_vec(&admitted).unwrap()
    );
}

#[test]
fn worker_receipts_enforce_a_serialize_parse_closed_numeric_domain() {
    let (_directory, store, packet, _, _) = setup();
    let request = store
        .prepare_attempt("run-fixture", "root-a", instant(1))
        .unwrap();
    let mut receipt = terminal(&packet, &request, "EXACT-STATE", "EXACT-CLASSIFICATION");
    receipt.extensions.insert(
        "nested".into(),
        serde_json::json!({"unsafe_integer": 9_007_199_254_740_992_u64}),
    );
    assert!(matches!(
        receipt.seal(),
        Err(ContractError::InvalidField("RFC8785 number"))
    ));

    let mut integral_float = terminal(&packet, &request, "EXACT-STATE", "EXACT-CLASSIFICATION");
    integral_float.extensions.insert(
        "nested".into(),
        serde_json::json!({"unsafe_integral_float": 1e20}),
    );
    assert!(matches!(
        integral_float.seal(),
        Err(ContractError::InvalidField("RFC8785 number"))
    ));

    let mut top_level_unicode_key =
        terminal(&packet, &request, "EXACT-STATE", "EXACT-CLASSIFICATION");
    top_level_unicode_key.extensions.insert(
        "😀".into(),
        serde_json::json!("not in the admitted object-key alphabet"),
    );
    assert!(matches!(
        top_level_unicode_key.seal(),
        Err(ContractError::InvalidField("RFC8785 object key"))
    ));

    let mut nested_unicode_key = terminal(&packet, &request, "EXACT-STATE", "EXACT-CLASSIFICATION");
    nested_unicode_key.extensions.insert(
        "nested".into(),
        serde_json::json!({"😀": "not in the admitted object-key alphabet"}),
    );
    assert!(matches!(
        nested_unicode_key.seal(),
        Err(ContractError::InvalidField("RFC8785 object key"))
    ));
}

#[test]
fn worker_brief_preserves_exact_packet_and_predecessor_receipt_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let packet = packet();
    let packet_raw = serde_json::to_vec_pretty(&packet).unwrap();
    let admission = admission(&packet);
    let profile = profile(&packet, &admission);
    let store = ForemanStore::open(directory.path().join("foreman.sqlite")).unwrap();
    store
        .admit(
            &packet_raw,
            &serde_jcs::to_vec(&admission).unwrap(),
            &serde_jcs::to_vec(&profile).unwrap(),
            instant(0),
        )
        .unwrap();
    let request = store
        .prepare_attempt("run-fixture", "root-a", instant(1))
        .unwrap();
    let mut receipt = terminal(&packet, &request, "EXACT-RAW", "INDEPENDENT-RAW");
    receipt.extensions.insert(
        "raw_extension".into(),
        serde_json::json!({"unknown": ["preserve", "exact", "bytes"]}),
    );
    receipt.seal().unwrap();
    let receipt_raw = serde_json::to_vec_pretty(&receipt).unwrap();
    store.accept_terminal_receipt(&receipt_raw).unwrap();
    assert_eq!(
        store
            .projection("run-fixture")
            .unwrap()
            .work_items
            .iter()
            .find(|item| item.work_item_id == "dependent")
            .unwrap()
            .scheduler_state,
        SchedulerStateV1::ReadyEntryEvaluation
    );

    let dependent_request = store
        .prepare_attempt("run-fixture", "dependent", instant(3))
        .unwrap();
    let brief_raw = store.worker_brief("run-fixture", "dependent").unwrap();
    assert!(brief_raw.len() <= MAXIMUM_WORKER_BRIEF_BYTES);
    let brief: Value = serde_json::from_slice(&brief_raw).unwrap();
    let mut bad_digest_receipt: Value = serde_json::from_slice(&receipt_raw).unwrap();
    bad_digest_receipt["receipt_digest"] = Value::String(format!("sha256:{}", "0".repeat(64)));
    let (bad_digest_brief, bad_digest_request) = bind_predecessor_fixture(
        brief.clone(),
        "root-a",
        &serde_jcs::to_vec(&bad_digest_receipt).unwrap(),
        &dependent_request,
    );
    assert!(WorkerBriefV2::from_slice_for_start(&bad_digest_brief, &bad_digest_request,).is_err());
    let mut wrong_run_receipt = receipt.clone();
    wrong_run_receipt.run_id = "run-substituted".into();
    wrong_run_receipt.seal().unwrap();
    let (wrong_run_brief, wrong_run_request) = bind_predecessor_fixture(
        brief.clone(),
        "root-a",
        &serde_jcs::to_vec(&wrong_run_receipt).unwrap(),
        &dependent_request,
    );
    assert!(WorkerBriefV2::from_slice_for_start(&wrong_run_brief, &wrong_run_request,).is_err());
    WorkerBriefV2::from_slice_for_start(&brief_raw, &dependent_request).unwrap();
    let mut substituted_brief = brief.clone();
    let mut substituted_packet: Value = serde_json::from_slice(&packet_raw).unwrap();
    substituted_packet["work_items"][1]["track"] = Value::String("substituted-track".into());
    let substituted_packet_raw = serde_json::to_vec_pretty(&substituted_packet).unwrap();
    let mut retained_digest = Sha256::new();
    retained_digest.update(b"nightshift.foreman-retained-raw.digest/v1\0");
    retained_digest.update(&substituted_packet_raw);
    substituted_brief["packet_source"]["retained_raw_digest"] =
        Value::String(format!("sha256:{:x}", retained_digest.finalize()));
    substituted_brief["packet_source"]["bytes_hex"] =
        Value::String(hex::encode(&substituted_packet_raw));
    let substituted_raw = serde_jcs::to_vec(&substituted_brief).unwrap();
    let mut substituted_request = dependent_request.clone();
    let mut brief_digest = Sha256::new();
    brief_digest.update(b"nightshift.worker-brief.digest/v2\0");
    brief_digest.update(&substituted_raw);
    substituted_request.worker_brief_digest = format!("sha256:{:x}", brief_digest.finalize());
    substituted_request.seal().unwrap();
    assert!(WorkerBriefV2::from_slice_for_start(&substituted_raw, &substituted_request,).is_err());
    assert_eq!(brief["schema"], WORKER_BRIEF_BASIS_SCHEMA_V2);
    let recognized_item: Value =
        serde_json::from_str(brief["work_item"]["canonical_json"].as_str().unwrap()).unwrap();
    assert_eq!(recognized_item["id"], "dependent");
    assert_eq!(
        recognized_item["dependencies"],
        serde_json::json!(["root-a"])
    );
    assert_eq!(
        hex::decode(brief["packet_source"]["bytes_hex"].as_str().unwrap()).unwrap(),
        packet_raw
    );
    let predecessor = &brief["predecessor_receipts"]["root-a"];
    assert_eq!(predecessor["receipt_kind"], "terminal");
    assert_eq!(
        hex::decode(predecessor["bytes_hex"].as_str().unwrap()).unwrap(),
        receipt_raw
    );
    assert!(String::from_utf8(receipt_raw)
        .unwrap()
        .contains("raw_extension"));
}

#[test]
fn worker_brief_total_bound_refuses_oversized_exact_predecessor_custody() {
    let directory = tempfile::tempdir().unwrap();
    let packet = packet();
    let admission = admission(&packet);
    let mut profile = profile(&packet, &admission);
    profile.maximum_receipt_bytes = 16 * 1024 * 1024;
    profile.seal().unwrap();
    let store = ForemanStore::open(directory.path().join("foreman.sqlite")).unwrap();
    store
        .admit(
            &packet.canonical_bytes().unwrap(),
            &serde_jcs::to_vec(&admission).unwrap(),
            &serde_jcs::to_vec(&profile).unwrap(),
            instant(0),
        )
        .unwrap();
    let request = store
        .prepare_attempt("run-fixture", "root-a", instant(1))
        .unwrap();
    let mut receipt = terminal(&packet, &request, "EXACT-RAW", "INDEPENDENT-RAW");
    receipt.extensions.insert(
        "bounded_fixture".into(),
        Value::String("x".repeat(MAXIMUM_WORKER_BRIEF_BYTES / 2 + 4096)),
    );
    receipt.seal().unwrap();
    let raw = serde_jcs::to_vec(&receipt).unwrap();
    assert!(raw.len() < profile.maximum_receipt_bytes as usize);
    store.accept_terminal_receipt(&raw).unwrap();
    assert!(matches!(
        store.prepare_attempt("run-fixture", "dependent", instant(3)),
        Err(ForemanError::InputTooLarge("worker brief"))
    ));
    assert!(store
        .projection("run-fixture")
        .unwrap()
        .work_items
        .iter()
        .find(|item| item.work_item_id == "dependent")
        .unwrap()
        .active_attempt_id
        .is_none());
    assert!(matches!(
        store.worker_brief("run-fixture", "dependent"),
        Err(ForemanError::InputTooLarge("worker brief"))
    ));
}

fn directory_bytes(path: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let path = entry.path();
            (path.file_name().unwrap().into(), fs::read(path).unwrap())
        })
        .collect()
}

fn byte_digests(snapshot: &BTreeMap<PathBuf, Vec<u8>>) -> BTreeMap<PathBuf, String> {
    snapshot
        .iter()
        .map(|(path, bytes)| (path.clone(), format!("{:x}", Sha256::digest(bytes))))
        .collect()
}

fn retained_raw_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"nightshift.foreman-retained-raw.digest/v1\0");
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn schema_snapshot(path: &Path) -> Vec<(String, Option<String>)> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    let mut statement = connection
        .prepare(
            "SELECT name, sql FROM sqlite_schema \
             WHERE type IN ('table', 'index', 'trigger') ORDER BY type, name",
        )
        .unwrap();
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

#[test]
fn query_only_store_refuses_absent_and_symlink_paths_without_creation() {
    let directory = tempfile::tempdir().unwrap();
    let absent = directory.path().join("absent.sqlite");
    assert!(matches!(
        ForemanStore::open_read_only(&absent),
        Err(ForemanError::ReadOnlyStore(_))
    ));
    assert!(directory_bytes(directory.path()).is_empty());

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let database = directory.path().join("database.sqlite");
        drop(ForemanStore::open(&database).unwrap());
        let link = directory.path().join("database-link.sqlite");
        symlink(&database, &link).unwrap();
        let before = directory_bytes(directory.path());
        drop(ForemanStore::open_read_only(&database).unwrap());
        let after_direct = directory_bytes(directory.path());
        assert!(
            after_direct == before,
            "before={:?} after={:?}",
            byte_digests(&before),
            byte_digests(&after_direct)
        );
        assert!(matches!(
            ForemanStore::open_read_only(&link),
            Err(ForemanError::ReadOnlyStore(_))
        ));
        assert_eq!(directory_bytes(directory.path()), before);
    }
}

#[test]
fn query_only_store_refuses_partial_sidecar_custody_without_changes() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("database.sqlite");
    drop(ForemanStore::open(&database).unwrap());
    fs::write(directory.path().join("database.sqlite-wal"), b"").unwrap();
    let before = directory_bytes(directory.path());
    assert!(matches!(
        ForemanStore::open_read_only(&database),
        Err(ForemanError::ReadOnlyStore(_))
    ));
    assert_eq!(directory_bytes(directory.path()), before);
}

#[test]
fn query_only_store_keeps_original_inode_across_pathname_replacement() {
    let (directory, store, _, _, _) = setup();
    let database = directory.path().join("foreman.sqlite");
    drop(store);
    let reader = ForemanStore::open_read_only(&database).unwrap();

    let replacement = directory.path().join("replacement.sqlite");
    drop(ForemanStore::open(&replacement).unwrap());
    let admitted = directory.path().join("admitted.sqlite");
    fs::rename(&database, &admitted).unwrap();
    for suffix in ["-wal", "-shm"] {
        let old = directory.path().join(format!("foreman.sqlite{suffix}"));
        if old.exists() {
            fs::rename(
                &old,
                directory.path().join(format!("admitted.sqlite{suffix}")),
            )
            .unwrap();
        }
    }
    fs::rename(&replacement, &database).unwrap();
    for suffix in ["-wal", "-shm"] {
        let old = directory.path().join(format!("replacement.sqlite{suffix}"));
        if old.exists() {
            fs::rename(
                &old,
                directory.path().join(format!("foreman.sqlite{suffix}")),
            )
            .unwrap();
        }
    }

    assert_eq!(
        reader.projection("run-fixture").unwrap().packet_digest,
        packet().packet_digest
    );
    assert!(ForemanStore::open_read_only(&database)
        .and_then(|store| store.projection("run-fixture"))
        .is_err());
}

#[test]
fn query_only_projection_events_and_final_export_preserve_database_and_sidecar_bytes() {
    let (directory, store, packet, _, _) = setup();
    let database = directory.path().join("foreman.sqlite");

    let schema_before_live = schema_snapshot(&database);
    let files_before_live = directory_bytes(directory.path());
    let reader = ForemanStore::open_read_only(&database).unwrap();
    assert_eq!(
        reader.projection("run-fixture").unwrap().work_items.len(),
        4
    );
    assert!(!reader
        .worker_brief("run-fixture", "root-a")
        .unwrap()
        .is_empty());
    assert!(!reader.export_events("run-fixture").unwrap().is_empty());
    drop(reader);
    assert_eq!(schema_snapshot(&database), schema_before_live);
    assert_eq!(directory_bytes(directory.path()), files_before_live);

    let root_a = store
        .prepare_attempt("run-fixture", "root-a", instant(1))
        .unwrap();
    let root_b = store
        .prepare_attempt("run-fixture", "root-b", instant(1))
        .unwrap();
    for request in [&root_a, &root_b] {
        let receipt = terminal(&packet, request, "EXACT-STATE", "EXACT-CLASSIFICATION");
        store
            .accept_terminal_receipt(&serde_jcs::to_vec(&receipt).unwrap())
            .unwrap();
    }
    for work_item in ["root-c", "dependent"] {
        let receipt = not_started(&packet, work_item);
        store
            .accept_not_started(&serde_jcs::to_vec(&receipt).unwrap())
            .unwrap();
    }
    let expected = store.close("run-fixture", instant(6)).unwrap();

    let schema_before_final = schema_snapshot(&database);
    let files_before_final = directory_bytes(directory.path());
    let reader = ForemanStore::open_read_only(&database).unwrap();
    assert_eq!(reader.export_final("run-fixture").unwrap(), expected);
    drop(reader);
    assert_eq!(schema_snapshot(&database), schema_before_final);
    assert_eq!(directory_bytes(directory.path()), files_before_final);

    drop(store);
    let connection = Connection::open(&database).unwrap();
    connection
        .execute_batch(
            "DROP TRIGGER final_snapshots_no_update;
             DROP TRIGGER events_no_update;",
        )
        .unwrap();
    let mut substituted: Value = serde_json::from_slice(&expected).unwrap();
    substituted["updated_at"] =
        Value::String(instant(4).to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    let substituted = serde_jcs::to_vec(&substituted).unwrap();
    let final_digest = retained_raw_digest(&substituted);
    connection
        .execute(
            "UPDATE final_snapshots SET updated_at = ?1, raw_digest = ?2, raw_bytes = ?3
             WHERE run_id = 'run-fixture'",
            rusqlite::params![instant(4).to_rfc3339(), final_digest, substituted],
        )
        .unwrap();
    let run_closed_raw: Vec<u8> = connection
        .query_row(
            "SELECT raw_bytes FROM events WHERE run_id = 'run-fixture'
             ORDER BY sequence DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let mut run_closed: Value = serde_json::from_slice(&run_closed_raw).unwrap();
    run_closed["payload"]["final_receipts_digest"] = Value::String(final_digest);
    let run_closed = serde_jcs::to_vec(&run_closed).unwrap();
    connection
        .execute(
            "UPDATE events SET raw_bytes = ?1, raw_digest = ?2
             WHERE sequence = (SELECT MAX(sequence) FROM events)",
            rusqlite::params![run_closed, retained_raw_digest(&run_closed)],
        )
        .unwrap();
    drop(connection);
    let reader = ForemanStore::open_read_only(&database).unwrap();
    assert!(matches!(
        reader.read_only_run_snapshot("run-fixture"),
        Err(ForemanError::ReadOnlyStore(_))
    ));
}

#[test]
fn query_only_snapshot_refuses_substituted_journal_custody() {
    let (directory, store, _, _, _) = setup();
    let database = directory.path().join("foreman.sqlite");
    drop(store);

    let connection = Connection::open(&database).unwrap();
    connection
        .execute_batch(
            "DROP TRIGGER events_no_update;
             UPDATE events SET raw_digest = 'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
             WHERE sequence = (SELECT MIN(sequence) FROM events);",
        )
        .unwrap();
    drop(connection);

    let reader = ForemanStore::open_read_only(&database).unwrap();
    assert!(matches!(
        reader.read_only_run_snapshot("run-fixture"),
        Err(ForemanError::ReadOnlyStore(_))
    ));
}

#[test]
fn query_only_snapshot_refuses_substituted_accepted_receipt_custody() {
    let (directory, store, packet, _, _) = setup();
    let database = directory.path().join("foreman.sqlite");
    let request = store
        .prepare_attempt("run-fixture", "root-a", instant(1))
        .unwrap();
    let receipt = terminal(&packet, &request, "EXACT-STATE", "EXACT-CLASSIFICATION");
    store
        .accept_terminal_receipt(&serde_jcs::to_vec(&receipt).unwrap())
        .unwrap();
    drop(store);

    let connection = Connection::open(&database).unwrap();
    connection
        .execute_batch(
            "DROP TRIGGER terminal_receipts_no_update;
             UPDATE terminal_receipts SET receipt_kind = 'not_started'
             WHERE work_item_id = 'root-a';",
        )
        .unwrap();
    drop(connection);

    let reader = ForemanStore::open_read_only(&database).unwrap();
    assert!(reader.read_only_run_snapshot("run-fixture").is_err());
}

#[test]
fn query_only_snapshot_refuses_substituted_run_contract_columns() {
    let (directory, store, _, _, _) = setup();
    let database = directory.path().join("foreman.sqlite");
    drop(store);

    let connection = Connection::open(&database).unwrap();
    connection
        .execute_batch(
            "DROP TRIGGER runs_no_update;
             UPDATE runs SET maximum_concurrent_workers = 1
             WHERE run_id = 'run-fixture';",
        )
        .unwrap();
    drop(connection);

    let reader = ForemanStore::open_read_only(&database).unwrap();
    assert!(matches!(
        reader.read_only_run_snapshot("run-fixture"),
        Err(ForemanError::ReadOnlyStore(_))
    ));
}

#[test]
fn query_only_snapshot_refuses_individually_valid_cross_contract_substitution() {
    let (directory, store, _, mut admission, mut profile) = setup();
    let database = directory.path().join("foreman.sqlite");
    admission.run_id = "substituted-run".to_owned();
    admission.seal().unwrap();
    profile.admission_digest = admission.admission_digest.clone();
    profile.seal().unwrap();
    let admission_bytes = serde_jcs::to_vec(&admission).unwrap();
    let profile_bytes = serde_jcs::to_vec(&profile).unwrap();
    drop(store);

    let connection = Connection::open(&database).unwrap();
    connection
        .execute_batch("DROP TRIGGER runs_no_update;")
        .unwrap();
    connection
        .execute(
            "UPDATE runs
             SET admission_digest = ?1, admission_bytes = ?2,
                 profile_digest = ?3, profile_bytes = ?4
             WHERE run_id = 'run-fixture'",
            rusqlite::params![
                admission.admission_digest,
                admission_bytes,
                profile.profile_digest,
                profile_bytes
            ],
        )
        .unwrap();
    drop(connection);

    let reader = ForemanStore::open_read_only(&database).unwrap();
    assert!(reader.read_only_run_snapshot("run-fixture").is_err());
}

#[test]
fn receipt_and_event_text_bounds_count_unicode_codepoints() {
    let (_directory, store, packet, _, _) = setup();
    let request = store
        .prepare_attempt("run-fixture", "root-a", instant(1))
        .unwrap();
    let mut receipt = terminal(&packet, &request, "é", "EXACT-CLASSIFICATION");
    receipt.state = "é".repeat(65_536);
    receipt.seal().unwrap();
    receipt.state.push('é');
    assert!(matches!(
        receipt.seal(),
        Err(ContractError::InvalidField("state"))
    ));

    let mut event = AdapterEventV1 {
        schema: WORKER_ADAPTER_EVENT_SCHEMA_V1.into(),
        event_digest: format!("sha256:{}", "0".repeat(64)),
        event_id: "event-unicode-bound".into(),
        packet_digest: packet.packet_digest.clone(),
        run_id: request.run_id.clone(),
        work_item_id: request.work_item_id.clone(),
        attempt_id: request.attempt_id.clone(),
        adapter_id: request.adapter_id.clone(),
        adapter_version: request.adapter_version.clone(),
        occurred_at: instant(2),
        kind: AdapterEventKindV1::Checkpoint,
        provider_identity: None,
        model_identity: None,
        session_identity: None,
        thread_identity: None,
        turn_identity: None,
        queue_identity: None,
        message: Some("é".repeat(65_536)),
        human_question: None,
        extensions: BTreeMap::new(),
    };
    event.seal().unwrap();
    event.message.as_mut().unwrap().push('é');
    assert!(matches!(
        event.seal(),
        Err(ContractError::InvalidField("adapter event bounds"))
    ));
}

#[test]
fn receipt_timestamp_lexemes_are_canonical_utc_and_nanosecond_exact() {
    let (_directory, store, packet, _, _) = setup();
    let request = store
        .prepare_attempt("run-fixture", "root-a", instant(1))
        .unwrap();
    let mut receipt = terminal(&packet, &request, "EXACT-STATE", "EXACT-CLASSIFICATION");
    receipt.started_at = chrono::DateTime::parse_from_rfc3339("2026-08-29T16:00:01.000000100Z")
        .unwrap()
        .with_timezone(&Utc);
    receipt.ended_at = chrono::DateTime::parse_from_rfc3339("2026-08-29T16:00:05.123456Z")
        .unwrap()
        .with_timezone(&Utc);
    receipt.seal().unwrap();
    let raw = serde_jcs::to_vec(&receipt).unwrap();
    assert_eq!(TerminalReceiptV1::from_slice(&raw).unwrap(), receipt);

    for substituted in [
        "2026-08-29T12:00:01-04:00",
        "2026-08-29T16:00:01.1000Z",
        "2026-08-29T16:00:01.123000Z",
        "2026-08-29T16:00:01.0000001Z",
    ] {
        let mut value = serde_json::to_value(&receipt).unwrap();
        value["started_at"] = Value::String(substituted.into());
        assert!(matches!(
            TerminalReceiptV1::from_slice(&serde_json::to_vec(&value).unwrap()),
            Err(ContractError::InvalidField("started_at"))
        ));
    }

    let mut absent = not_started(&packet, "root-b");
    absent.recorded_at = chrono::DateTime::parse_from_rfc3339("2026-08-29T16:00:06.123Z")
        .unwrap()
        .with_timezone(&Utc);
    absent.seal().unwrap();
    let raw = serde_jcs::to_vec(&absent).unwrap();
    assert_eq!(NotStartedReceiptV1::from_slice(&raw).unwrap(), absent);
    let mut value = serde_json::to_value(&absent).unwrap();
    value["recorded_at"] = Value::String("2026-08-29T16:00:06.123000Z".into());
    assert!(matches!(
        NotStartedReceiptV1::from_slice(&serde_json::to_vec(&value).unwrap()),
        Err(ContractError::InvalidField("recorded_at"))
    ));
}

#[test]
fn checked_in_contract_schemas_are_closed_json_documents() {
    for bytes in [
        include_bytes!("../../../schemas/nightshift.foreman-admission.v1.schema.json").as_slice(),
        include_bytes!("../../../schemas/nightshift.foreman-capacity-requirement.v1.schema.json")
            .as_slice(),
        include_bytes!("../../../schemas/nightshift.foreman-capacity-admission.v1.schema.json")
            .as_slice(),
        include_bytes!("../../../schemas/nightshift.foreman-execution-profile.v2.schema.json")
            .as_slice(),
        include_bytes!("../../../schemas/nightshift.worker-adapter.v2.schema.json").as_slice(),
        include_bytes!(
            "../../../schemas/nightshift.holding-deterministic-provider-admission-evidence.v1.schema.json"
        )
        .as_slice(),
        include_bytes!(
            "../../../schemas/nightshift.provider-admission-disposition.v2.schema.json"
        )
        .as_slice(),
        include_bytes!(
            "../../../schemas/nightshift.holding-deterministic-provider-admission-evidence.v2.schema.json"
        )
        .as_slice(),
        include_bytes!(
            "../../../schemas/nightshift.provider-admission-disposition.v3.schema.json"
        )
        .as_slice(),
    ] {
        let schema: Value = serde_json::from_slice(bytes).unwrap();
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert!(schema.get("$id").is_some());
    }
}

fn capacity_observation(at: chrono::DateTime<Utc>, remaining: f64) -> CapacityObservationV1 {
    let mut observation = CapacityObservationV1 {
        schema: CAPACITY_OBSERVATION_SCHEMA_V1.into(),
        provider_id: "provider:fixture".into(),
        account_profile_locator: "fixture-profile".into(),
        model_family: None,
        observed_at: at - Duration::seconds(1),
        expires_at: at + Duration::minutes(10),
        source_class: SourceClass::Observed,
        confidence: Confidence::High,
        disposition: ObservationDisposition::Usable,
        unknown_reasons: vec![],
        windows: vec![
            CapacityWindow {
                window_id: "five-hour".into(),
                window_type: WindowType::FiveHour,
                remaining_fraction: Some(remaining),
                remaining_units: None,
                resets_at: Some(at + Duration::hours(1)),
            },
            CapacityWindow {
                window_id: "weekly".into(),
                window_type: WindowType::Weekly,
                remaining_fraction: Some(remaining),
                remaining_units: None,
                resets_at: Some(at + Duration::days(1)),
            },
        ],
        evidence: ObservationEvidence {
            probe_id: "gauge-latch-fixture".into(),
            protocol_method: "fixture/read".into(),
            protocol_version: Some("fixture/v1".into()),
            executable_path: Some("/fixture/provider-observer".into()),
            executable_digest: Some(format!("sha256:{}", "1".repeat(64))),
            raw_source_digest: format!("sha256:{}", "2".repeat(64)),
        },
        observation_digest: String::new(),
    };
    observation.observation_digest = observation.compute_digest().unwrap();
    observation
}

fn capacity_requirement(
    packet: &NightshiftPacketV1,
    admission: &ForemanAdmissionV1,
    profile: &ExecutionProfileV2,
    policy: &CapacityPolicyV1,
) -> ForemanCapacityRequirementV1 {
    let mut requirement = ForemanCapacityRequirementV1 {
        schema: FOREMAN_CAPACITY_REQUIREMENT_SCHEMA_V1.into(),
        capacity_requirement_digest: format!("sha256:{}", "0".repeat(64)),
        packet_digest: packet.packet_digest.clone(),
        admission_digest: admission.admission_digest.clone(),
        profile_digest: profile.profile_digest.clone(),
        run_id: admission.run_id.clone(),
        policy_id: policy.policy_id.clone(),
        provider_id: "provider:fixture".into(),
        model_cost_classes: packet
            .work_items
            .iter()
            .map(|work| {
                let cost = match work.model_routing.class.as_str() {
                    "small" | "bounded" => CapacityCostClassV1::Cheap,
                    "medium" | "large" => CapacityCostClassV1::Expensive,
                    _ => panic!("fixture model class must be closed"),
                };
                (work.model_routing.class.clone(), cost)
            })
            .collect(),
        authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".into(),
    };
    requirement.seal().unwrap();
    requirement
}

struct CapacityFixtureOwner<'a> {
    packet: &'a NightshiftPacketV1,
    admission: &'a ForemanAdmissionV1,
    profile: &'a ExecutionProfileV2,
    requirement: &'a ForemanCapacityRequirementV1,
    policy: &'a CapacityPolicyV1,
}

fn capacity_bundle(
    owner: CapacityFixtureOwner<'_>,
    work_item_id: &str,
    at: chrono::DateTime<Utc>,
    remaining: f64,
) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, CapacityDecisionV1) {
    let CapacityFixtureOwner {
        packet,
        admission,
        profile,
        requirement,
        policy,
    } = owner;
    let observation = capacity_observation(at, remaining);
    let decision = decide_capacity(&observation, policy, at).unwrap();
    let mut exact = ForemanCapacityAdmissionV1 {
        schema: FOREMAN_CAPACITY_ADMISSION_SCHEMA_V1.into(),
        capacity_admission_digest: format!("sha256:{}", "0".repeat(64)),
        packet_digest: packet.packet_digest.clone(),
        admission_digest: admission.admission_digest.clone(),
        profile_digest: profile.profile_digest.clone(),
        capacity_requirement_digest: requirement.capacity_requirement_digest.clone(),
        run_id: admission.run_id.clone(),
        work_item_id: work_item_id.into(),
        adapter_id: profile.work_items[work_item_id].adapter_id.clone(),
        provider_id: observation.provider_id.clone(),
        packet_model_class: packet
            .work_items
            .iter()
            .find(|work| work.id == work_item_id)
            .unwrap()
            .model_routing
            .class
            .clone(),
        profile_model_class: profile.work_items[work_item_id]
            .provider_model_class
            .clone(),
        cost_class: match packet
            .work_items
            .iter()
            .find(|work| work.id == work_item_id)
            .unwrap()
            .model_routing
            .class
            .as_str()
        {
            "small" | "bounded" => CapacityCostClassV1::Cheap,
            "medium" | "large" => CapacityCostClassV1::Expensive,
            _ => panic!("fixture model class must be closed"),
        },
        policy_id: policy.policy_id.clone(),
        observation_digest: observation.observation_digest.clone(),
        policy_digest: policy.policy_digest.clone(),
        decision_digest: decision.decision_digest.clone(),
        evaluated_at: at,
        speculative_requested: false,
        authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".into(),
    };
    exact.seal().unwrap();
    (
        serde_jcs::to_vec(&exact).unwrap(),
        serde_jcs::to_vec(&observation).unwrap(),
        serde_jcs::to_vec(policy).unwrap(),
        serde_jcs::to_vec(&decision).unwrap(),
        decision,
    )
}

fn capacity_evidence<'a>(
    admission_bytes: &'a [u8],
    observation_bytes: &'a [u8],
    policy_bytes: &'a [u8],
    decision_bytes: &'a [u8],
) -> CapacityAdmissionEvidenceV1<'a> {
    CapacityAdmissionEvidenceV1 {
        admission_bytes,
        observation_bytes,
        policy_bytes,
        decision_bytes,
    }
}

fn capacity_matrix_case(
    model_class: &str,
    remaining: f64,
    unknown_observation: bool,
    unknown_allows_new_cheap_work: bool,
) -> (
    CapacityState,
    CapacityAdmissionDisposition,
    Result<(), ForemanError>,
) {
    let directory = tempfile::tempdir().unwrap();
    let mut packet = packet();
    for work in &mut packet.work_items {
        work.model_routing.class = model_class.into();
    }
    packet.seal().unwrap();
    let mut admission = admission(&packet);
    admission.allowed_provider_model_classes = vec![model_class.into()];
    admission.seal().unwrap();
    let mut policy = CapacityPolicyV1::default();
    policy.unknown_allows_new_cheap_work = unknown_allows_new_cheap_work;
    policy.policy_digest = policy.compute_digest().unwrap();
    let mut profile = profile(&packet, &admission);
    for execution in profile.work_items.values_mut() {
        execution.provider_model_class = model_class.into();
    }
    profile.budget_policy_ref = policy.policy_id.clone();
    profile.seal().unwrap();
    let requirement = capacity_requirement(&packet, &admission, &profile, &policy);
    let store = ForemanStore::open(directory.path().join("foreman.sqlite")).unwrap();
    store
        .admit_with_capacity_requirement(
            &packet.canonical_bytes().unwrap(),
            &serde_jcs::to_vec(&admission).unwrap(),
            &serde_jcs::to_vec(&profile).unwrap(),
            &serde_jcs::to_vec(&requirement).unwrap(),
            instant(0),
        )
        .unwrap();
    let (
        mut capacity_admission_bytes,
        mut observation_bytes,
        policy_bytes,
        mut decision_bytes,
        mut decision,
    ) = capacity_bundle(
        CapacityFixtureOwner {
            packet: &packet,
            admission: &admission,
            profile: &profile,
            requirement: &requirement,
            policy: &policy,
        },
        "root-a",
        instant(1),
        remaining,
    );
    if unknown_observation {
        let mut observation: CapacityObservationV1 =
            serde_json::from_slice(&observation_bytes).unwrap();
        observation.source_class = SourceClass::Unknown;
        observation.confidence = Confidence::Low;
        observation.disposition = ObservationDisposition::Unknown;
        observation.unknown_reasons = vec!["FIXTURE_SOURCE_UNAVAILABLE".into()];
        observation.windows.clear();
        observation.observation_digest = observation.compute_digest().unwrap();
        decision = decide_capacity(&observation, &policy, instant(1)).unwrap();
        let mut capacity_admission =
            ForemanCapacityAdmissionV1::from_slice(&capacity_admission_bytes).unwrap();
        capacity_admission.observation_digest = observation.observation_digest.clone();
        capacity_admission.decision_digest = decision.decision_digest.clone();
        capacity_admission.seal().unwrap();
        capacity_admission_bytes = serde_jcs::to_vec(&capacity_admission).unwrap();
        observation_bytes = serde_jcs::to_vec(&observation).unwrap();
        decision_bytes = serde_jcs::to_vec(&decision).unwrap();
    }
    let state = decision.state;
    let disposition = decision.admission;
    let result = store
        .prepare_attempt_with_capacity(
            "run-fixture",
            "root-a",
            capacity_evidence(
                &capacity_admission_bytes,
                &observation_bytes,
                &policy_bytes,
                &decision_bytes,
            ),
            instant(1),
        )
        .map(|_| ());
    (state, disposition, result)
}

struct CapacityRunFixture {
    _directory: TempDir,
    path: PathBuf,
    store: ForemanStore,
    packet: NightshiftPacketV1,
    admission: ForemanAdmissionV1,
    profile: ExecutionProfileV2,
    requirement: ForemanCapacityRequirementV1,
    policy: CapacityPolicyV1,
}

fn capacity_run_fixture() -> CapacityRunFixture {
    capacity_run_fixture_with_event_maximum(65_536)
}

fn capacity_run_fixture_with_event_maximum(maximum_event_bytes: u64) -> CapacityRunFixture {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("foreman.sqlite");
    let packet = packet();
    let admission = admission(&packet);
    let policy = CapacityPolicyV1::default();
    let mut profile = profile(&packet, &admission);
    profile.budget_policy_ref = policy.policy_id.clone();
    profile.maximum_event_bytes = maximum_event_bytes;
    profile.seal().unwrap();
    let requirement = capacity_requirement(&packet, &admission, &profile, &policy);
    let store = ForemanStore::open(&path).unwrap();
    store
        .admit_with_capacity_requirement(
            &packet.canonical_bytes().unwrap(),
            &serde_jcs::to_vec(&admission).unwrap(),
            &serde_jcs::to_vec(&profile).unwrap(),
            &serde_jcs::to_vec(&requirement).unwrap(),
            instant(0),
        )
        .unwrap();
    CapacityRunFixture {
        _directory: directory,
        path,
        store,
        packet,
        admission,
        profile,
        requirement,
        policy,
    }
}

fn prepare_capacity_fixture(
    fixture: &CapacityRunFixture,
    work_item_id: &str,
    at: chrono::DateTime<Utc>,
) -> WorkerStartRequestV2 {
    let (admission, observation, policy, decision, _) = capacity_bundle(
        CapacityFixtureOwner {
            packet: &fixture.packet,
            admission: &fixture.admission,
            profile: &fixture.profile,
            requirement: &fixture.requirement,
            policy: &fixture.policy,
        },
        work_item_id,
        at,
        0.60,
    );
    fixture
        .store
        .prepare_attempt_with_capacity(
            "run-fixture",
            work_item_id,
            capacity_evidence(&admission, &observation, &policy, &decision),
            at,
        )
        .unwrap()
}

fn resize_retained_capacity_event(
    connection: &Connection,
    kind: &str,
    target_bytes: usize,
) -> usize {
    let raw: Vec<u8> = connection
        .query_row(
            "SELECT raw_bytes FROM events WHERE kind = ?1 ORDER BY sequence ASC LIMIT 1",
            [kind],
            |row| row.get(0),
        )
        .unwrap();
    let mut event: Value = serde_json::from_slice(&raw).unwrap();
    let prior_id = event["event_id"].as_str().unwrap();
    let fixed_bytes = raw.len().checked_sub(prior_id.len()).unwrap();
    assert!(target_bytes > fixed_bytes);
    let event_id = "x".repeat(target_bytes - fixed_bytes);
    event["event_id"] = Value::String(event_id.clone());
    let resized = serde_jcs::to_vec(&event).unwrap();
    assert_eq!(resized.len(), target_bytes);
    connection
        .execute(
            "UPDATE events SET event_id = ?1, raw_bytes = ?2, raw_digest = ?3 WHERE kind = ?4",
            rusqlite::params![event_id, resized, retained_raw_digest(&resized), kind],
        )
        .unwrap();
    target_bytes
}

#[test]
fn capacity_policy_disposition_matrix_is_enforced_at_attempt_admission() {
    let (state, admission, result) = capacity_matrix_case("medium", 0.60, false, false);
    assert_eq!(state, CapacityState::Abundant);
    assert_eq!(admission, CapacityAdmissionDisposition::OrdinaryBounded);
    assert!(result.is_ok());

    let (state, admission, result) = capacity_matrix_case("bounded", 0.60, false, false);
    assert_eq!(state, CapacityState::Abundant);
    assert_eq!(admission, CapacityAdmissionDisposition::OrdinaryBounded);
    assert!(result.is_ok());

    let (state, admission, result) = capacity_matrix_case("medium", 0.30, false, false);
    assert_eq!(state, CapacityState::Normal);
    assert_eq!(admission, CapacityAdmissionDisposition::OrdinaryBounded);
    assert!(result.is_ok());

    let (state, admission, result) = capacity_matrix_case("bounded", 0.30, false, false);
    assert_eq!(state, CapacityState::Normal);
    assert_eq!(admission, CapacityAdmissionDisposition::OrdinaryBounded);
    assert!(result.is_ok());

    let (state, admission, result) = capacity_matrix_case("bounded", 0.15, false, false);
    assert_eq!(state, CapacityState::Conserve);
    assert_eq!(admission, CapacityAdmissionDisposition::CheapBoundedOnly);
    assert!(result.is_ok());

    let (state, admission, result) = capacity_matrix_case("medium", 0.15, false, false);
    assert_eq!(state, CapacityState::Conserve);
    assert_eq!(admission, CapacityAdmissionDisposition::CheapBoundedOnly);
    assert!(matches!(
        result,
        Err(ForemanError::Transition(message))
            if message.contains("only closed cheap model classes")
    ));

    let (state, admission, result) = capacity_matrix_case("bounded", 0.60, true, true);
    assert_eq!(state, CapacityState::Unknown);
    assert_eq!(admission, CapacityAdmissionDisposition::CheapBoundedOnly);
    assert!(result.is_ok());

    let (state, admission, result) = capacity_matrix_case("medium", 0.60, true, true);
    assert_eq!(state, CapacityState::Unknown);
    assert_eq!(admission, CapacityAdmissionDisposition::CheapBoundedOnly);
    assert!(matches!(
        result,
        Err(ForemanError::Transition(message))
            if message.contains("only closed cheap model classes")
    ));

    let (state, admission, result) = capacity_matrix_case("bounded", 0.60, true, false);
    assert_eq!(state, CapacityState::Unknown);
    assert_eq!(admission, CapacityAdmissionDisposition::NoNewWork);
    assert!(matches!(
        result,
        Err(ForemanError::Transition(message)) if message.contains("admits no new work")
    ));

    let (state, admission, result) = capacity_matrix_case("medium", 0.60, true, false);
    assert_eq!(state, CapacityState::Unknown);
    assert_eq!(admission, CapacityAdmissionDisposition::NoNewWork);
    assert!(matches!(
        result,
        Err(ForemanError::Transition(message)) if message.contains("admits no new work")
    ));

    for model_class in ["bounded", "medium"] {
        let (state, admission, result) = capacity_matrix_case(model_class, 0.01, false, false);
        assert_eq!(state, CapacityState::Critical);
        assert_eq!(admission, CapacityAdmissionDisposition::NoNewWork);
        assert!(matches!(
            result,
            Err(ForemanError::Transition(message)) if message.contains("admits no new work")
        ));
    }
}

#[test]
fn shared_capacity_history_refuses_digest_consistent_restart_mutations() {
    {
        let fixture = capacity_run_fixture();
        let path = fixture.path.clone();
        drop(fixture.store);
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch("DROP TRIGGER events_no_update;")
            .unwrap();
        let raw: Vec<u8> = connection
            .query_row(
                "SELECT raw_bytes FROM events WHERE kind = 'capacity_requirement'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let mut event: Value = serde_json::from_slice(&raw).unwrap();
        let mut requirement: ForemanCapacityRequirementV1 =
            serde_json::from_value(event["payload"]["requirement"].clone()).unwrap();
        requirement.policy_id = "substituted-policy".into();
        requirement.seal().unwrap();
        let requirement_bytes = serde_jcs::to_vec(&requirement).unwrap();
        event["payload"]["requirement"] = serde_json::to_value(&requirement).unwrap();
        event["payload"]["requirement_bytes"] = serde_json::to_value(&requirement_bytes).unwrap();
        let substituted = serde_jcs::to_vec(&event).unwrap();
        connection
            .execute(
                "UPDATE events SET raw_bytes = ?1, raw_digest = ?2
                 WHERE kind = 'capacity_requirement'",
                rusqlite::params![substituted, retained_raw_digest(&substituted)],
            )
            .unwrap();
        drop(connection);
        assert!(ForemanStore::open(&path)
            .and_then(|store| store.projection("run-fixture"))
            .is_err());
    }

    {
        let fixture = capacity_run_fixture();
        prepare_capacity_fixture(&fixture, "root-a", instant(1));
        let (root_b_admission, root_b_observation, root_b_policy, root_b_decision, _) =
            capacity_bundle(
                CapacityFixtureOwner {
                    packet: &fixture.packet,
                    admission: &fixture.admission,
                    profile: &fixture.profile,
                    requirement: &fixture.requirement,
                    policy: &fixture.policy,
                },
                "root-b",
                instant(2),
                0.60,
            );
        let path = fixture.path.clone();
        drop(fixture.store);
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch("DROP TRIGGER events_no_update;")
            .unwrap();
        let raw: Vec<u8> = connection
            .query_row(
                "SELECT raw_bytes FROM events WHERE kind = 'capacity_admission'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let mut event: Value = serde_json::from_slice(&raw).unwrap();
        event["work_item_id"] = Value::String("root-b".into());
        let substituted = serde_jcs::to_vec(&event).unwrap();
        connection
            .execute(
                "UPDATE events SET work_item_id = 'root-b', raw_bytes = ?1, raw_digest = ?2
                 WHERE kind = 'capacity_admission'",
                rusqlite::params![substituted, retained_raw_digest(&substituted)],
            )
            .unwrap();
        let attempts_before: u64 = connection
            .query_row(
                "SELECT count(*) FROM events WHERE event_id LIKE 'attempt-created-%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        drop(connection);
        let store = ForemanStore::open(&path).unwrap();
        assert!(store
            .prepare_attempt_with_capacity(
                "run-fixture",
                "root-b",
                capacity_evidence(
                    &root_b_admission,
                    &root_b_observation,
                    &root_b_policy,
                    &root_b_decision,
                ),
                instant(2),
            )
            .is_err());
        drop(store);
        let connection = Connection::open(&path).unwrap();
        let attempts_after: u64 = connection
            .query_row(
                "SELECT count(*) FROM events WHERE event_id LIKE 'attempt-created-%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(attempts_after, attempts_before);
    }

    {
        let fixture = capacity_run_fixture();
        prepare_capacity_fixture(&fixture, "root-a", instant(1));
        let path = fixture.path.clone();
        drop(fixture.store);
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER events_no_update;
                 UPDATE events
                 SET sequence = (SELECT max(sequence) FROM events) + 100
                 WHERE event_id LIKE 'attempt-created-%';",
            )
            .unwrap();
        drop(connection);
        assert!(ForemanStore::open(&path)
            .and_then(|store| store.projection("run-fixture"))
            .is_err());
    }

    {
        let fixture = capacity_run_fixture();
        prepare_capacity_fixture(&fixture, "root-a", instant(1));
        let path = fixture.path.clone();
        drop(fixture.store);
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER events_no_delete;
                 DELETE FROM events WHERE kind = 'capacity_admission';",
            )
            .unwrap();
        drop(connection);
        assert!(ForemanStore::open(&path)
            .and_then(|store| store.projection("run-fixture"))
            .is_err());
    }
}

#[test]
fn cumulative_capacity_history_bound_refuses_two_subceiling_rows_on_reopen_and_mutation() {
    let fixture = capacity_run_fixture_with_event_maximum(MAXIMUM_CAPACITY_HISTORY_BYTES);
    prepare_capacity_fixture(&fixture, "root-a", instant(1));
    let (root_b_admission, root_b_observation, root_b_policy, root_b_decision, _) = capacity_bundle(
        CapacityFixtureOwner {
            packet: &fixture.packet,
            admission: &fixture.admission,
            profile: &fixture.profile,
            requirement: &fixture.requirement,
            policy: &fixture.policy,
        },
        "root-b",
        instant(2),
        0.60,
    );
    let path = fixture.path.clone();
    drop(fixture.store);

    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch("DROP TRIGGER events_no_update;")
        .unwrap();
    let each = usize::try_from(MAXIMUM_CAPACITY_HISTORY_BYTES / 2).unwrap() + 4_096;
    resize_retained_capacity_event(&connection, "capacity_requirement", each);
    resize_retained_capacity_event(&connection, "capacity_admission", each);
    let lengths = {
        let mut statement = connection
            .prepare(
                "SELECT length(raw_bytes) FROM events
                 WHERE kind IN ('capacity_requirement', 'capacity_admission')
                 ORDER BY sequence ASC",
            )
            .unwrap();
        statement
            .query_map([], |row| row.get::<_, u64>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    assert_eq!(lengths, vec![each as u64, each as u64]);
    assert!(lengths
        .iter()
        .all(|length| *length <= fixture.profile.maximum_event_bytes));
    assert!(lengths.iter().sum::<u64>() > MAXIMUM_CAPACITY_HISTORY_BYTES);
    let attempts_before: u64 = connection
        .query_row(
            "SELECT count(*) FROM events WHERE event_id LIKE 'attempt-created-%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    drop(connection);

    let store = ForemanStore::open(&path).unwrap();
    assert!(matches!(
        store.projection("run-fixture"),
        Err(ForemanError::InputTooLarge("capacity journal history"))
    ));
    assert!(matches!(
        store.prepare_attempt_with_capacity(
            "run-fixture",
            "root-b",
            capacity_evidence(
                &root_b_admission,
                &root_b_observation,
                &root_b_policy,
                &root_b_decision,
            ),
            instant(2),
        ),
        Err(ForemanError::InputTooLarge("capacity journal history"))
    ));
    drop(store);
    let connection = Connection::open(&path).unwrap();
    let attempts_after: u64 = connection
        .query_row(
            "SELECT count(*) FROM events WHERE event_id LIKE 'attempt-created-%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(attempts_after, attempts_before);
}

#[test]
fn cumulative_capacity_history_is_checked_atomically_before_append() {
    let fixture = capacity_run_fixture_with_event_maximum(MAXIMUM_CAPACITY_HISTORY_BYTES);
    prepare_capacity_fixture(&fixture, "root-a", instant(1));
    let (root_b_admission, root_b_observation, root_b_policy, root_b_decision, _) = capacity_bundle(
        CapacityFixtureOwner {
            packet: &fixture.packet,
            admission: &fixture.admission,
            profile: &fixture.profile,
            requirement: &fixture.requirement,
            policy: &fixture.policy,
        },
        "root-b",
        instant(2),
        0.60,
    );
    let path = fixture.path.clone();
    drop(fixture.store);

    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch("DROP TRIGGER events_no_update;")
        .unwrap();
    let requirement_bytes: u64 = connection
        .query_row(
            "SELECT length(raw_bytes) FROM events WHERE kind = 'capacity_requirement'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let retained_allowance = MAXIMUM_CAPACITY_HISTORY_BYTES
        .checked_sub(requirement_bytes)
        .unwrap()
        .checked_sub(512)
        .unwrap();
    resize_retained_capacity_event(
        &connection,
        "capacity_admission",
        usize::try_from(retained_allowance).unwrap(),
    );
    let retained_total: u64 = connection
        .query_row(
            "SELECT sum(length(raw_bytes)) FROM events
             WHERE kind IN ('capacity_requirement', 'capacity_admission')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(retained_total, MAXIMUM_CAPACITY_HISTORY_BYTES - 512);
    let attempts_before: u64 = connection
        .query_row(
            "SELECT count(*) FROM events WHERE event_id LIKE 'attempt-created-%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    drop(connection);

    let store = ForemanStore::open(&path).unwrap();
    store.projection("run-fixture").unwrap();
    assert!(matches!(
        store.prepare_attempt_with_capacity(
            "run-fixture",
            "root-b",
            capacity_evidence(
                &root_b_admission,
                &root_b_observation,
                &root_b_policy,
                &root_b_decision,
            ),
            instant(2),
        ),
        Err(ForemanError::InputTooLarge("capacity journal history"))
    ));
    drop(store);
    let connection = Connection::open(&path).unwrap();
    let attempts_after: u64 = connection
        .query_row(
            "SELECT count(*) FROM events WHERE event_id LIKE 'attempt-created-%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(attempts_after, attempts_before);
}

#[test]
fn capacity_metadata_preflight_counts_rows_before_raw_materialization() {
    let fixture = capacity_run_fixture();
    let path = fixture.path.clone();
    let maximum_capacity_rows = fixture.packet.work_items.len().saturating_add(1);
    drop(fixture.store);

    let connection = Connection::open(&path).unwrap();
    for ordinal in 0..maximum_capacity_rows {
        connection
            .execute(
                "INSERT INTO events
                 (event_id, run_id, work_item_id, attempt_id, kind, recorded_at, raw_bytes, raw_digest)
                 VALUES (?1, 'run-fixture', NULL, NULL, 'capacity_admission', ?2,
                         zeroblob(1), ?3)",
                rusqlite::params![
                    format!("extra-capacity-{ordinal}"),
                    instant(1).to_rfc3339(),
                    format!("sha256:{}", "0".repeat(64)),
                ],
            )
            .unwrap();
    }
    drop(connection);

    let store = ForemanStore::open(&path).unwrap();
    assert!(matches!(
        store.projection("run-fixture"),
        Err(ForemanError::InputTooLarge("capacity journal history"))
    ));
    drop(store);
    assert!(matches!(
        read_only_run_snapshot(&path, "run-fixture"),
        Err(ForemanError::InputTooLarge("capacity journal history"))
    ));
}

#[test]
fn capacity_metadata_preflight_refuses_huge_blob_before_raw_materialization() {
    let fixture = capacity_run_fixture_with_event_maximum(MAXIMUM_CAPACITY_HISTORY_BYTES);
    prepare_capacity_fixture(&fixture, "root-a", instant(1));
    let path = fixture.path.clone();
    drop(fixture.store);

    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch("DROP TRIGGER events_no_update;")
        .unwrap();
    connection
        .execute(
            "UPDATE events SET raw_bytes = zeroblob(?1) WHERE kind = 'capacity_admission'",
            [MAXIMUM_CAPACITY_HISTORY_BYTES + 1],
        )
        .unwrap();
    drop(connection);

    let store = ForemanStore::open(&path).unwrap();
    assert!(matches!(
        store.projection("run-fixture"),
        Err(ForemanError::InputTooLarge("capacity journal event"))
    ));
    drop(store);
    assert!(matches!(
        read_only_run_snapshot(&path, "run-fixture"),
        Err(ForemanError::InputTooLarge("capacity journal event"))
    ));
}

#[test]
fn legacy_non_capacity_internal_event_above_capacity_ceiling_remains_readable() {
    let (directory, store, _, _, profile) = setup();
    let path = directory.path().join("foreman.sqlite");
    drop(store);
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch("DROP TRIGGER events_no_update;")
        .unwrap();
    let raw: Vec<u8> = connection
        .query_row(
            "SELECT raw_bytes FROM events WHERE event_id LIKE 'run-admitted-%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let mut event: Value = serde_json::from_slice(&raw).unwrap();
    let event_id = format!(
        "run-admitted-{}",
        "x".repeat(profile.maximum_event_bytes as usize)
    );
    event["event_id"] = Value::String(event_id.clone());
    let enlarged = serde_jcs::to_vec(&event).unwrap();
    assert!(enlarged.len() > profile.maximum_event_bytes as usize);
    connection
        .execute(
            "UPDATE events SET event_id = ?1, raw_bytes = ?2, raw_digest = ?3
             WHERE event_id LIKE 'run-admitted-%'",
            rusqlite::params![event_id, enlarged, retained_raw_digest(&enlarged)],
        )
        .unwrap();
    drop(connection);
    assert_eq!(
        ForemanStore::open(&path)
            .unwrap()
            .projection("run-fixture")
            .unwrap()
            .work_items
            .len(),
        4
    );
}

#[test]
fn capacity_required_run_is_atomic_restartable_and_legacy_path_cannot_win() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("foreman.sqlite");
    let packet = packet();
    let admission = admission(&packet);
    let policy = CapacityPolicyV1::default();
    let mut profile = profile(&packet, &admission);
    profile.budget_policy_ref = policy.policy_id.clone();
    profile.seal().unwrap();
    let requirement = capacity_requirement(&packet, &admission, &profile, &policy);
    let requirement_raw = serde_jcs::to_vec(&requirement).unwrap();
    let store = ForemanStore::open(&path).unwrap();
    store
        .admit_with_capacity_requirement(
            &packet.canonical_bytes().unwrap(),
            &serde_jcs::to_vec(&admission).unwrap(),
            &serde_jcs::to_vec(&profile).unwrap(),
            &requirement_raw,
            instant(0),
        )
        .unwrap();

    assert!(matches!(
        store.prepare_attempt("run-fixture", "root-a", instant(1)),
        Err(ForemanError::Transition(message))
            if message.contains("capacity-required run refuses legacy")
    ));
    assert!(store
        .projection("run-fixture")
        .unwrap()
        .work_items
        .iter()
        .all(|work| work.active_attempt_id.is_none()));

    let (root_a_admission, root_a_observation, policy_raw, root_a_decision, decision) =
        capacity_bundle(
            CapacityFixtureOwner {
                packet: &packet,
                admission: &admission,
                profile: &profile,
                requirement: &requirement,
                policy: &policy,
            },
            "root-a",
            instant(1),
            0.60,
        );
    assert_eq!(
        decision.admission,
        CapacityAdmissionDisposition::OrdinaryBounded
    );
    let mut invalid_requirement = requirement.clone();
    invalid_requirement
        .model_cost_classes
        .insert("bounded".into(), CapacityCostClassV1::Expensive);
    assert!(matches!(
        invalid_requirement.seal(),
        Err(ContractError::InvalidField("capacity model-class map"))
    ));
    let mut speculative_admission =
        ForemanCapacityAdmissionV1::from_slice(&root_a_admission).unwrap();
    speculative_admission.speculative_requested = true;
    assert!(matches!(
        speculative_admission.seal(),
        Err(ContractError::InvalidField(
            "speculative capacity admission is unbound"
        ))
    ));
    let mut noncanonical_timestamp: Value = serde_json::from_slice(&root_a_admission).unwrap();
    noncanonical_timestamp["evaluated_at"] = Value::String("2026-08-29T12:00:01-04:00".into());
    assert!(matches!(
        ForemanCapacityAdmissionV1::from_slice(
            &serde_json::to_vec(&noncanonical_timestamp).unwrap()
        ),
        Err(ContractError::InvalidField("evaluated_at"))
    ));

    let mut scoped_mismatch_observation: CapacityObservationV1 =
        serde_json::from_slice(&root_a_observation).unwrap();
    scoped_mismatch_observation.model_family = Some("medium".into());
    scoped_mismatch_observation.observation_digest =
        scoped_mismatch_observation.compute_digest().unwrap();
    let scoped_mismatch_decision =
        decide_capacity(&scoped_mismatch_observation, &policy, instant(1)).unwrap();
    let mut scoped_mismatch_admission =
        ForemanCapacityAdmissionV1::from_slice(&root_a_admission).unwrap();
    scoped_mismatch_admission.observation_digest =
        scoped_mismatch_observation.observation_digest.clone();
    scoped_mismatch_admission.decision_digest = scoped_mismatch_decision.decision_digest.clone();
    scoped_mismatch_admission.seal().unwrap();
    assert!(matches!(
        store.prepare_attempt_with_capacity(
            "run-fixture",
            "root-a",
            capacity_evidence(
                &serde_jcs::to_vec(&scoped_mismatch_admission).unwrap(),
                &serde_jcs::to_vec(&scoped_mismatch_observation).unwrap(),
                &policy_raw,
                &serde_jcs::to_vec(&scoped_mismatch_decision).unwrap(),
            ),
            instant(1),
        ),
        Err(ForemanError::IdentityMismatch(
            "capacity observation model family"
        ))
    ));

    let mut oversized_observation: CapacityObservationV1 =
        serde_json::from_slice(&root_a_observation).unwrap();
    oversized_observation.account_profile_locator = "x".repeat(30_000);
    oversized_observation.observation_digest = oversized_observation.compute_digest().unwrap();
    let oversized_decision = decide_capacity(&oversized_observation, &policy, instant(1)).unwrap();
    let mut oversized_admission =
        ForemanCapacityAdmissionV1::from_slice(&root_a_admission).unwrap();
    oversized_admission.observation_digest = oversized_observation.observation_digest.clone();
    oversized_admission.decision_digest = oversized_decision.decision_digest.clone();
    oversized_admission.seal().unwrap();
    assert!(matches!(
        store.prepare_attempt_with_capacity(
            "run-fixture",
            "root-a",
            capacity_evidence(
                &serde_jcs::to_vec(&oversized_admission).unwrap(),
                &serde_jcs::to_vec(&oversized_observation).unwrap(),
                &policy_raw,
                &serde_jcs::to_vec(&oversized_decision).unwrap(),
            ),
            instant(1),
        ),
        Err(ForemanError::InputTooLarge("capacity journal event"))
    ));
    assert!(store
        .projection("run-fixture")
        .unwrap()
        .work_items
        .iter()
        .all(|work| work.active_attempt_id.is_none()));

    let exact_observation: CapacityObservationV1 =
        serde_json::from_slice(&root_a_observation).unwrap();
    let mut substituted_decision: CapacityDecisionV1 =
        serde_json::from_slice(&root_a_decision).unwrap();
    substituted_decision.state = CapacityState::Normal;
    substituted_decision.allow_new_speculative_work = false;
    substituted_decision.reason_codes = vec!["MINIMUM_REMAINING_WINDOW_NORMAL".into()];
    substituted_decision.decision_digest = substituted_decision.compute_digest().unwrap();
    substituted_decision.validate().unwrap();
    let mut substituted_outcome_admission =
        ForemanCapacityAdmissionV1::from_slice(&root_a_admission).unwrap();
    substituted_outcome_admission.decision_digest = substituted_decision.decision_digest.clone();
    substituted_outcome_admission.seal().unwrap();
    assert!(matches!(
        store.prepare_attempt_with_capacity(
            "run-fixture",
            "root-a",
            capacity_evidence(
                &serde_jcs::to_vec(&substituted_outcome_admission).unwrap(),
                &root_a_observation,
                &policy_raw,
                &serde_jcs::to_vec(&substituted_decision).unwrap(),
            ),
            instant(1),
        ),
        Err(ForemanError::Transition(message))
            if message.contains("not the exact deterministic FUEL outcome")
    ));

    let substituted_time_decision =
        decide_capacity(&exact_observation, &policy, instant(2)).unwrap();
    let mut substituted_time_admission =
        ForemanCapacityAdmissionV1::from_slice(&root_a_admission).unwrap();
    substituted_time_admission.evaluated_at = instant(2);
    substituted_time_admission.decision_digest = substituted_time_decision.decision_digest.clone();
    substituted_time_admission.seal().unwrap();
    assert!(matches!(
        store.prepare_attempt_with_capacity(
            "run-fixture",
            "root-a",
            capacity_evidence(
                &serde_jcs::to_vec(&substituted_time_admission).unwrap(),
                &root_a_observation,
                &policy_raw,
                &serde_jcs::to_vec(&substituted_time_decision).unwrap(),
            ),
            instant(1),
        ),
        Err(ForemanError::Transition(message)) if message.contains("not current")
    ));
    assert!(store
        .projection("run-fixture")
        .unwrap()
        .work_items
        .iter()
        .all(|work| work.active_attempt_id.is_none()));

    let mut substituted_admission =
        ForemanCapacityAdmissionV1::from_slice(&root_a_admission).unwrap();
    substituted_admission.provider_id = "provider:substituted".into();
    substituted_admission.seal().unwrap();
    assert!(matches!(
        store.prepare_attempt_with_capacity(
            "run-fixture",
            "root-a",
            capacity_evidence(
                &serde_jcs::to_vec(&substituted_admission).unwrap(),
                &root_a_observation,
                &policy_raw,
                &root_a_decision,
            ),
            instant(1),
        ),
        Err(ForemanError::IdentityMismatch(
            "capacity requirement identity"
        ))
    ));
    assert!(store
        .projection("run-fixture")
        .unwrap()
        .work_items
        .iter()
        .all(|work| work.active_attempt_id.is_none()));

    let mut stale_observation: CapacityObservationV1 =
        serde_json::from_slice(&root_a_observation).unwrap();
    stale_observation.expires_at = instant(1);
    stale_observation.observation_digest = stale_observation.compute_digest().unwrap();
    let stale_decision = decide_capacity(&stale_observation, &policy, instant(1)).unwrap();
    let mut stale_admission = ForemanCapacityAdmissionV1::from_slice(&root_a_admission).unwrap();
    stale_admission.observation_digest = stale_observation.observation_digest.clone();
    stale_admission.decision_digest = stale_decision.decision_digest.clone();
    stale_admission.seal().unwrap();
    assert!(matches!(
        store.prepare_attempt_with_capacity(
            "run-fixture",
            "root-a",
            capacity_evidence(
                &serde_jcs::to_vec(&stale_admission).unwrap(),
                &serde_jcs::to_vec(&stale_observation).unwrap(),
                &policy_raw,
                &serde_jcs::to_vec(&stale_decision).unwrap(),
            ),
            instant(1),
        ),
        Err(ForemanError::Transition(message)) if message.contains("not current")
    ));
    assert!(store
        .projection("run-fixture")
        .unwrap()
        .work_items
        .iter()
        .all(|work| work.active_attempt_id.is_none()));

    let root_a = store
        .prepare_attempt_with_capacity(
            "run-fixture",
            "root-a",
            capacity_evidence(
                &root_a_admission,
                &root_a_observation,
                &policy_raw,
                &root_a_decision,
            ),
            instant(1),
        )
        .unwrap();
    drop(store);

    let store = ForemanStore::open(&path).unwrap();
    assert_eq!(
        store
            .projection("run-fixture")
            .unwrap()
            .work_items
            .iter()
            .find(|work| work.work_item_id == "root-a")
            .unwrap()
            .active_attempt_id
            .as_deref(),
        Some(root_a.attempt_id.as_str())
    );

    let (critical_admission, critical_observation, critical_policy, critical_decision, decision) =
        capacity_bundle(
            CapacityFixtureOwner {
                packet: &packet,
                admission: &admission,
                profile: &profile,
                requirement: &requirement,
                policy: &policy,
            },
            "root-b",
            instant(2),
            0.01,
        );
    assert_eq!(decision.admission, CapacityAdmissionDisposition::NoNewWork);
    assert!(matches!(
        store.prepare_attempt_with_capacity(
            "run-fixture",
            "root-b",
            capacity_evidence(
                &critical_admission,
                &critical_observation,
                &critical_policy,
                &critical_decision,
            ),
            instant(2),
        ),
        Err(ForemanError::Transition(message)) if message.contains("admits no new work")
    ));
    store
        .accept_terminal_receipt(
            &serde_jcs::to_vec(&terminal(
                &packet,
                &root_a,
                "EXACT-CUSTODY",
                "INDEPENDENT-CAPACITY-AWARE-FIXTURE",
            ))
            .unwrap(),
        )
        .unwrap();

    let (root_b_admission, root_b_observation, root_b_policy, root_b_decision, _) = capacity_bundle(
        CapacityFixtureOwner {
            packet: &packet,
            admission: &admission,
            profile: &profile,
            requirement: &requirement,
            policy: &policy,
        },
        "root-b",
        instant(6),
        0.60,
    );
    drop(store);
    let barrier = Arc::new(Barrier::new(2));
    let legacy_barrier = barrier.clone();
    let legacy_path = path.clone();
    let legacy = std::thread::spawn(move || {
        let store = ForemanStore::open(legacy_path).unwrap();
        legacy_barrier.wait();
        store.prepare_attempt("run-fixture", "root-b", instant(6))
    });
    let capacity_barrier = barrier;
    let capacity_path = path.clone();
    let capacity = std::thread::spawn(move || {
        let store = ForemanStore::open(capacity_path).unwrap();
        capacity_barrier.wait();
        store.prepare_attempt_with_capacity(
            "run-fixture",
            "root-b",
            capacity_evidence(
                &root_b_admission,
                &root_b_observation,
                &root_b_policy,
                &root_b_decision,
            ),
            instant(6),
        )
    });
    assert!(legacy.join().unwrap().is_err());
    let root_b = capacity.join().unwrap().unwrap();

    let store = ForemanStore::open(&path).unwrap();
    assert_eq!(
        store
            .projection("run-fixture")
            .unwrap()
            .work_items
            .iter()
            .find(|work| work.work_item_id == "root-b")
            .unwrap()
            .active_attempt_id
            .as_deref(),
        Some(root_b.attempt_id.as_str())
    );
    drop(store);
    let snapshot = nightshift_foreman::read_only_run_snapshot(&path, "run-fixture").unwrap();
    let projected_requirement = snapshot.capacity_requirement.as_ref().unwrap();
    assert_eq!(projected_requirement.requirement, requirement);
    assert_eq!(projected_requirement.requirement_bytes, requirement_raw);
    assert_eq!(snapshot.capacity_admissions.len(), 2);
    let root_a_capacity = snapshot
        .capacity_admissions
        .iter()
        .find(|capacity| capacity.work_item_id == "root-a")
        .unwrap();
    assert_eq!(root_a_capacity.admission_bytes, root_a_admission);
    assert_eq!(root_a_capacity.observation_bytes, root_a_observation);
    assert_eq!(root_a_capacity.policy_bytes, policy_raw);
    assert_eq!(root_a_capacity.decision_bytes, root_a_decision);
    assert!(snapshot
        .events
        .iter()
        .all(|event| event.raw_digest.starts_with("sha256:")));
}
#[test]
fn midnight_rail_four_item_deterministic_dogfood_qualifies_without_provider() {
    fn event(
        packet: &NightshiftPacketV1,
        request: &WorkerStartRequestV2,
        event_id: &str,
        kind: AdapterEventKindV1,
        at: chrono::DateTime<Utc>,
    ) -> AdapterEventV1 {
        let mut event = AdapterEventV1 {
            schema: WORKER_ADAPTER_EVENT_SCHEMA_V1.into(),
            event_digest: format!("sha256:{}", "0".repeat(64)),
            event_id: event_id.into(),
            packet_digest: packet.packet_digest.clone(),
            run_id: request.run_id.clone(),
            work_item_id: request.work_item_id.clone(),
            attempt_id: request.attempt_id.clone(),
            adapter_id: request.adapter_id.clone(),
            adapter_version: request.adapter_version.clone(),
            occurred_at: at,
            kind,
            provider_identity: Some("provider:fixture".into()),
            model_identity: Some("model:fixture".into()),
            session_identity: Some("session:fixture".into()),
            thread_identity: None,
            turn_identity: None,
            queue_identity: None,
            message: None,
            human_question: None,
            extensions: BTreeMap::new(),
        };
        if !matches!(event.kind, AdapterEventKindV1::HumanQuestion) {
            event.seal().unwrap();
        }
        event
    }

    fn bound_terminal(
        packet: &NightshiftPacketV1,
        request: &WorkerStartRequestV2,
        state: &str,
        classification: &str,
        started_at: chrono::DateTime<Utc>,
        ended_at: chrono::DateTime<Utc>,
    ) -> TerminalReceiptV1 {
        let mut receipt = terminal(packet, request, state, classification);
        receipt.started_at = started_at;
        receipt.ended_at = ended_at;
        receipt.seal().unwrap();
        receipt
    }

    let fixture = capacity_run_fixture();
    let root_a = prepare_capacity_fixture(&fixture, "root-a", instant(1));
    let root_b = prepare_capacity_fixture(&fixture, "root-b", instant(2));
    assert_ne!(root_a.attempt_id, root_b.attempt_id);

    let root_c_bundle = capacity_bundle(
        CapacityFixtureOwner {
            packet: &fixture.packet,
            admission: &fixture.admission,
            profile: &fixture.profile,
            requirement: &fixture.requirement,
            policy: &fixture.policy,
        },
        "root-c",
        instant(3),
        0.60,
    );
    assert!(matches!(
        fixture.store.prepare_attempt_with_capacity(
            "run-fixture",
            "root-c",
            capacity_evidence(
                &root_c_bundle.0,
                &root_c_bundle.1,
                &root_c_bundle.2,
                &root_c_bundle.3,
            ),
            instant(3),
        ),
        Err(ForemanError::ResourceUnavailable(_))
    ));
    fixture
        .store
        .record_dispatch_requested("run-fixture", "root-a", &root_a.attempt_id, instant(2))
        .unwrap();
    fixture
        .store
        .record_dispatch_requested("run-fixture", "root-b", &root_b.attempt_id, instant(3))
        .unwrap();

    let before_restart =
        nightshift_casework::load_live_run_at(&fixture.path, "run-fixture", instant(3)).unwrap();
    assert_eq!(before_restart.projection.resource_claims.len(), 2);
    assert_eq!(
        before_restart.projection.provider_capacity.attempts.len(),
        2
    );
    assert_eq!(
        before_restart.projection.provider_capacity.status,
        "EXACT_RECORDED_BY_FOREMAN"
    );
    assert!(before_restart
        .projection
        .provider_capacity
        .attempts
        .windows(2)
        .all(|pair| pair[0].observed_at < pair[1].observed_at));

    let CapacityRunFixture {
        _directory: directory,
        path,
        store,
        packet,
        admission,
        profile,
        requirement,
        policy,
    } = fixture;
    drop(store);
    let store = ForemanStore::open(&path).unwrap();
    assert_eq!(
        store
            .projection("run-fixture")
            .unwrap()
            .work_items
            .iter()
            .find(|item| item.work_item_id == "root-a")
            .unwrap()
            .active_attempt_id
            .as_deref(),
        Some(root_a.attempt_id.as_str())
    );
    store
        .record_resume_requested("run-fixture", "root-a", &root_a.attempt_id, instant(4))
        .unwrap();
    store
        .accept_adapter_event(
            &serde_jcs::to_vec(&event(
                &packet,
                &root_a,
                "midnight-root-a-checkpoint",
                AdapterEventKindV1::Checkpoint,
                instant(4),
            ))
            .unwrap(),
        )
        .unwrap();
    store
        .accept_adapter_event(
            &serde_jcs::to_vec(&event(
                &packet,
                &root_b,
                "midnight-root-b-started",
                AdapterEventKindV1::WorkerStarted,
                instant(4),
            ))
            .unwrap(),
        )
        .unwrap();

    let root_a_receipt = bound_terminal(
        &packet,
        &root_a,
        "IMPLEMENTATION-EVIDENCE-RETAINED",
        "MIDNIGHT-DETERMINISTIC-IMPLEMENTATION-FIXTURE",
        instant(1),
        instant(5),
    );
    let root_a_raw = serde_jcs::to_vec(&root_a_receipt).unwrap();
    store.accept_terminal_receipt(&root_a_raw).unwrap();
    let root_b_receipt = bound_terminal(
        &packet,
        &root_b,
        "AUDIT-EVIDENCE-RETAINED",
        "MIDNIGHT-DETERMINISTIC-AUDIT-FIXTURE",
        instant(2),
        instant(6),
    );
    store
        .accept_terminal_receipt(&serde_jcs::to_vec(&root_b_receipt).unwrap())
        .unwrap();

    let dependent_bundle = capacity_bundle(
        CapacityFixtureOwner {
            packet: &packet,
            admission: &admission,
            profile: &profile,
            requirement: &requirement,
            policy: &policy,
        },
        "dependent",
        instant(8),
        0.30,
    );
    let dependent = store
        .prepare_attempt_with_capacity(
            "run-fixture",
            "dependent",
            capacity_evidence(
                &dependent_bundle.0,
                &dependent_bundle.1,
                &dependent_bundle.2,
                &dependent_bundle.3,
            ),
            instant(8),
        )
        .unwrap();
    let dependent_brief = store.worker_brief("run-fixture", "dependent").unwrap();
    WorkerBriefV2::from_slice_for_start(&dependent_brief, &dependent).unwrap();
    let brief: Value = serde_json::from_slice(&dependent_brief).unwrap();
    assert_eq!(
        hex::decode(
            brief["predecessor_receipts"]["root-a"]["bytes_hex"]
                .as_str()
                .unwrap()
        )
        .unwrap(),
        root_a_raw
    );
    store
        .accept_adapter_event(
            &serde_jcs::to_vec(&event(
                &packet,
                &dependent,
                "midnight-dependent-started",
                AdapterEventKindV1::WorkerStarted,
                instant(9),
            ))
            .unwrap(),
        )
        .unwrap();
    store
        .accept_terminal_receipt(
            &serde_jcs::to_vec(&bound_terminal(
                &packet,
                &dependent,
                "ENTRY-EVALUATED-EXACT-PREDECESSOR",
                "MIDNIGHT-DETERMINISTIC-DEPENDENT-FIXTURE",
                instant(8),
                instant(10),
            ))
            .unwrap(),
        )
        .unwrap();

    let root_c_bundle = capacity_bundle(
        CapacityFixtureOwner {
            packet: &packet,
            admission: &admission,
            profile: &profile,
            requirement: &requirement,
            policy: &policy,
        },
        "root-c",
        instant(11),
        0.60,
    );
    let root_c = store
        .prepare_attempt_with_capacity(
            "run-fixture",
            "root-c",
            capacity_evidence(
                &root_c_bundle.0,
                &root_c_bundle.1,
                &root_c_bundle.2,
                &root_c_bundle.3,
            ),
            instant(11),
        )
        .unwrap();
    store
        .record_dispatch_requested("run-fixture", "root-c", &root_c.attempt_id, instant(11))
        .unwrap();
    let question = HumanQuestionV1 {
        question_id: "midnight-fixture-authority".into(),
        question: "Is protected target-effect authority present for this fixture lane?".into(),
        exhausted_evidence: "The deterministic fixture carries no target-effect authority.".into(),
        safe_default: "Do not perform the protected effect.".into(),
        consequences: "Only this lane terminates blocked; independent lanes retain receipts."
            .into(),
        resume_point: "Create a successor occurrence after exact authority exists.".into(),
    };
    let mut question_event = event(
        &packet,
        &root_c,
        "midnight-root-c-human-question",
        AdapterEventKindV1::HumanQuestion,
        instant(12),
    );
    question_event.human_question = Some(question.clone());
    question_event.seal().unwrap();
    store
        .accept_adapter_event(&serde_jcs::to_vec(&question_event).unwrap())
        .unwrap();
    let mut lane_receipt = bound_terminal(
        &packet,
        &root_c,
        "BLOCKED-HUMAN-EXACT",
        "MIDNIGHT-LANE-LOCAL-QUESTION",
        instant(11),
        instant(13),
    );
    lane_receipt.human_questions = vec![question];
    lane_receipt.seal().unwrap();
    store
        .accept_terminal_receipt(&serde_jcs::to_vec(&lane_receipt).unwrap())
        .unwrap();

    let live = nightshift_casework::load_live_run_at(&path, "run-fixture", instant(14)).unwrap();
    assert_eq!(live.projection.work_items.len(), 4);
    assert_eq!(live.projection.provider_capacity.attempts.len(), 4);
    assert_eq!(
        live.projection
            .work_items
            .iter()
            .flat_map(|item| &item.human_questions)
            .count(),
        1
    );
    assert!(serde_json::to_value(&live.projection)
        .unwrap()
        .get("aggregate_result")
        .is_none());

    let final_receipts = store.close("run-fixture", instant(15)).unwrap();
    assert_eq!(
        final_receipts,
        store.close("run-fixture", instant(30)).unwrap()
    );
    let events = serde_jcs::to_vec(&store.export_events("run-fixture").unwrap()).unwrap();
    drop(store);
    let closed = nightshift_casework::load_live_run_at(&path, "run-fixture", instant(15)).unwrap();
    assert_eq!(
        closed.projection.foreman.lifecycle,
        "CLOSED_EXACT_FINAL_SNAPSHOT_RETAINED"
    );
    assert_eq!(closed.projection.foreman.terminal_receipt_count, 4);
    assert_eq!(closed.projection.foreman.not_started_receipt_count, 0);

    let sealed = directory.path().join("sealed-case");
    fs::create_dir(&sealed).unwrap();
    let packet_bytes = packet.canonical_bytes().unwrap();
    fs::write(sealed.join("packet.v1.json"), &packet_bytes).unwrap();
    fs::write(sealed.join("run-receipts.v1.json"), &final_receipts).unwrap();
    let final_case = nightshift_casework::load_run_at(&sealed, instant(12)).unwrap();
    assert_eq!(final_case.receipt_bytes, final_receipts);
    assert_eq!(final_case.projection.work_items.len(), 4);
    assert!(serde_json::to_value(&final_case.projection)
        .unwrap()
        .get("aggregate_result")
        .is_none());

    let approval = capacity_run_fixture();
    let waiting_request = prepare_capacity_fixture(&approval, "root-a", instant(1));
    let independent_request = prepare_capacity_fixture(&approval, "root-b", instant(2));
    approval
        .store
        .record_dispatch_requested(
            "run-fixture",
            "root-a",
            &waiting_request.attempt_id,
            instant(2),
        )
        .unwrap();
    approval
        .store
        .record_dispatch_requested(
            "run-fixture",
            "root-b",
            &independent_request.attempt_id,
            instant(2),
        )
        .unwrap();
    let mut waiting = event(
        &approval.packet,
        &waiting_request,
        "midnight-waiting-approval",
        AdapterEventKindV1::WaitingApproval,
        instant(3),
    );
    waiting.message = Some("Protected fixture effect requires authority; no response sent.".into());
    waiting.extensions = BTreeMap::from([
        ("approval_response_sent".into(), Value::Bool(false)),
        ("protected_effect_absent".into(), Value::Bool(true)),
    ]);
    waiting.seal().unwrap();
    let waiting_raw = serde_jcs::to_vec(&waiting).unwrap();
    approval.store.accept_adapter_event(&waiting_raw).unwrap();
    approval
        .store
        .accept_adapter_event(
            &serde_jcs::to_vec(&event(
                &approval.packet,
                &independent_request,
                "midnight-independent-started",
                AdapterEventKindV1::WorkerStarted,
                instant(3),
            ))
            .unwrap(),
        )
        .unwrap();
    approval
        .store
        .accept_terminal_receipt(
            &serde_jcs::to_vec(&bound_terminal(
                &approval.packet,
                &independent_request,
                "INDEPENDENT-LANE-COMPLETE",
                "MIDNIGHT-APPROVAL-INDEPENDENCE-FIXTURE",
                instant(2),
                instant(5),
            ))
            .unwrap(),
        )
        .unwrap();
    let approval_live =
        nightshift_casework::load_live_run_at(&approval.path, "run-fixture", instant(6)).unwrap();
    assert_eq!(
        approval_live
            .projection
            .work_items
            .iter()
            .find(|item| item.work_item_id == "root-a")
            .unwrap()
            .scheduler_state,
        "WAITING_APPROVAL"
    );
    assert!(approval_live
        .projection
        .work_items
        .iter()
        .find(|item| item.work_item_id == "root-b")
        .unwrap()
        .accepted_outcome
        .is_some());
    assert!(matches!(
        approval.store.close("run-fixture", instant(7)),
        Err(ForemanError::IncompleteCloseout(_))
    ));
    let retained_waiting = approval
        .store
        .export_events("run-fixture")
        .unwrap()
        .into_iter()
        .any(|record| record == serde_json::from_slice::<Value>(&waiting_raw).unwrap());
    assert!(retained_waiting);
    let approval_events =
        serde_jcs::to_vec(&approval.store.export_events("run-fixture").unwrap()).unwrap();

    if let Some(output) = std::env::var_os("NIGHTSHIFT_MIDNIGHT_FIXTURE_DIR") {
        let output = PathBuf::from(output);
        assert!(output.is_dir());
        let exact_snapshot =
            nightshift_foreman::read_only_run_snapshot(&path, "run-fixture").unwrap();
        for capacity in exact_snapshot.capacity_admissions {
            let prefix = format!("capacity-{}", capacity.work_item_id);
            fs::write(
                output.join(format!("{prefix}-admission.v1.json")),
                capacity.admission_bytes,
            )
            .unwrap();
            fs::write(
                output.join(format!("{prefix}-observation.v1.json")),
                capacity.observation_bytes,
            )
            .unwrap();
            fs::write(
                output.join(format!("{prefix}-policy.v1.json")),
                capacity.policy_bytes,
            )
            .unwrap();
            fs::write(
                output.join(format!("{prefix}-decision.v1.json")),
                capacity.decision_bytes,
            )
            .unwrap();
        }
        for receipt in exact_snapshot.terminal_receipts {
            fs::write(
                output.join(format!(
                    "accepted-{}-{}.v1.json",
                    receipt.work_item_id, receipt.receipt_kind
                )),
                receipt.raw_bytes,
            )
            .unwrap();
        }
        for (name, bytes) in [
            ("packet.v1.json", packet_bytes),
            (
                "foreman-admission.v1.json",
                serde_jcs::to_vec(&admission).unwrap(),
            ),
            (
                "foreman-execution-profile.v2.json",
                serde_jcs::to_vec(&profile).unwrap(),
            ),
            (
                "foreman-capacity-requirement.v1.json",
                serde_jcs::to_vec(&requirement).unwrap(),
            ),
            ("foreman-events.v1.json", events),
            (
                "live-before-close.v1.json",
                serde_jcs::to_vec(&live.projection).unwrap(),
            ),
            (
                "live-closed.v1.json",
                serde_jcs::to_vec(&closed.projection).unwrap(),
            ),
            ("run-receipts.v1.json", final_receipts),
            (
                "final-casework.v1.json",
                serde_jcs::to_vec(&final_case.projection).unwrap(),
            ),
            (
                "approval-waiting-live.v1.json",
                serde_jcs::to_vec(&approval_live.projection).unwrap(),
            ),
            ("approval-events.v1.json", approval_events),
            ("dependent-worker-brief.v2.json", dependent_brief),
        ] {
            fs::write(output.join(name), bytes).unwrap();
        }
    }
}
#[test]
fn final_snapshot_questions_match_sealed_casework_contract_for_terminal_and_not_started() {
    let (directory, store, packet, _, _) = setup();
    let question = HumanQuestionV1 {
        question_id: "question-rivet-terminal".into(),
        question: "What exact authority would permit this bounded continuation?".into(),
        exhausted_evidence: "No matching authority artifact is present.".into(),
        safe_default: "Do not continue the affected lane.".into(),
        consequences: "The affected lane remains blocked; independent receipts remain exact."
            .into(),
        resume_point: "Create a successor occurrence after exact authority exists.".into(),
    };
    let root_a = store
        .prepare_attempt("run-fixture", "root-a", instant(1))
        .unwrap();
    let mut terminal_question = terminal(
        &packet,
        &root_a,
        "BLOCKED-HUMAN-EXACT",
        "QUESTION-RIVET-TERMINAL-FIXTURE",
    );
    terminal_question.human_questions = vec![question.clone()];
    terminal_question.seal().unwrap();
    let terminal_raw = serde_jcs::to_vec(&terminal_question).unwrap();
    store.accept_terminal_receipt(&terminal_raw).unwrap();
    assert_eq!(
        store.raw_terminal_receipt("run-fixture", "root-a").unwrap(),
        terminal_raw
    );

    let root_b = store
        .prepare_attempt("run-fixture", "root-b", instant(1))
        .unwrap();
    store
        .accept_terminal_receipt(
            &serde_jcs::to_vec(&terminal(
                &packet,
                &root_b,
                "EXACT-STATE",
                "QUESTION-RIVET-INDEPENDENT-FIXTURE",
            ))
            .unwrap(),
        )
        .unwrap();

    let mut not_started_question = not_started(&packet, "root-c");
    not_started_question.human_questions = vec![HumanQuestionV1 {
        question_id: "question-rivet-not-started".into(),
        question: "Which exact predecessor would open this entry predicate?".into(),
        exhausted_evidence: "The retained predecessor evidence does not establish it.".into(),
        safe_default: "Keep this item not started.".into(),
        consequences: "No attempt or target effect occurs.".into(),
        resume_point: "Evaluate a successor against new exact predecessor evidence.".into(),
    }];
    not_started_question.seal().unwrap();
    store
        .accept_not_started(&serde_jcs::to_vec(&not_started_question).unwrap())
        .unwrap();
    store
        .accept_not_started(&serde_jcs::to_vec(&not_started(&packet, "dependent")).unwrap())
        .unwrap();

    let final_bytes = store.close("run-fixture", instant(10)).unwrap();
    let final_value: Value = serde_json::from_slice(&final_bytes).unwrap();
    let questions = final_value["human_questions"].as_array().unwrap();
    assert_eq!(questions.len(), 2);
    for row in questions {
        let object = row.as_object().unwrap();
        assert_eq!(
            object
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>(),
            [
                "consequences",
                "evidence_exhausted",
                "exact_question",
                "resume_point",
                "safe_default",
                "work_item",
            ]
            .map(str::to_owned)
            .into_iter()
            .collect()
        );
        assert!(row["exact_question"].as_str().is_some());
        assert!(object.get("question").is_none());
    }
    assert_eq!(
        questions[0]["exact_question"],
        "What exact authority would permit this bounded continuation?"
    );
    assert_eq!(
        questions[1]["exact_question"],
        "Which exact predecessor would open this entry predicate?"
    );

    let case = directory.path().join("question-rivet-case");
    fs::create_dir(&case).unwrap();
    fs::write(
        case.join("packet.v1.json"),
        packet.canonical_bytes().unwrap(),
    )
    .unwrap();
    fs::write(case.join("run-receipts.v1.json"), &final_bytes).unwrap();
    let loaded = nightshift_casework::load_run_at(&case, instant(10)).unwrap();
    assert_eq!(loaded.projection.human_questions.len(), 2);
    assert_eq!(
        loaded.projection.human_questions[0]
            .exact_question
            .recognized_string
            .as_deref(),
        Some("What exact authority would permit this bounded continuation?")
    );
    assert_eq!(
        loaded.projection.human_questions[1]
            .exact_question
            .recognized_string
            .as_deref(),
        Some("Which exact predecessor would open this entry predicate?")
    );

    let mut substituted = final_value;
    let first = substituted["human_questions"][0].as_object_mut().unwrap();
    let value = first.remove("exact_question").unwrap();
    first.insert("question".into(), value);
    fs::write(
        case.join("run-receipts.v1.json"),
        serde_jcs::to_vec(&substituted).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        nightshift_casework::load_run_at(&case, instant(10)),
        Err(nightshift_casework::CaseworkError::Receipt(message))
            if message.contains("exact_question")
    ));
}

fn holding_time(value: &str) -> chrono::DateTime<Utc> {
    value.parse().unwrap()
}

fn holding_placeholder() -> String {
    format!("sha256:{}", "0".repeat(64))
}

fn holding_canonical<T: serde::Serialize>(value: &T) -> Vec<u8> {
    serde_jcs::to_vec(value).unwrap()
}

fn holding_seal_value(mut value: Value, field: &str, domain: &[u8]) -> Value {
    value[field] = Value::String(holding_placeholder());
    let mut basis = value.clone();
    basis.as_object_mut().unwrap().remove(field);
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(holding_canonical(&basis));
    value[field] = Value::String(format!("sha256:{:x}", hash.finalize()));
    value
}

fn holding_replace_strings(value: &mut Value, replacements: &[(&str, &str)]) {
    match value {
        Value::String(text) => {
            if let Some((_, replacement)) =
                replacements.iter().find(|(candidate, _)| text == candidate)
            {
                *text = (*replacement).to_owned();
            }
        }
        Value::Array(values) => {
            for value in values {
                holding_replace_strings(value, replacements);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                holding_replace_strings(value, replacements);
            }
        }
        _ => {}
    }
}

fn holding_retarget_snapshot(
    mut snapshot: Value,
    opened: &nightshift_foreman::OpenedProviderDispatchV1,
) -> Vec<u8> {
    let replacements = [
        (
            "echo-vector-attempt",
            opened.dispatch.work_attempt_id.as_str(),
        ),
        (
            "echo-vector-dispatch",
            opened.dispatch.dispatch_occurrence_id.as_str(),
        ),
        (
            "echo-vector-process",
            opened.dispatch.adapter_process_occurrence_id.as_str(),
        ),
        (
            "echo-vector-session",
            opened.dispatch.app_server_session_identity.as_str(),
        ),
        (
            "beta-fixture-attempt",
            opened.dispatch.work_attempt_id.as_str(),
        ),
        (
            "beta-fixture-dispatch",
            opened.dispatch.dispatch_occurrence_id.as_str(),
        ),
        (
            "beta-fixture-process",
            opened.dispatch.adapter_process_occurrence_id.as_str(),
        ),
        (
            "beta-fixture-estate",
            opened.dispatch.app_server_session_identity.as_str(),
        ),
        ("gpt-5.6-terra", opened.dispatch.selection.model_id.as_str()),
        (
            "attempt-holding-1",
            opened.dispatch.work_attempt_id.as_str(),
        ),
        (
            "dispatch-holding-1",
            opened.dispatch.dispatch_occurrence_id.as_str(),
        ),
        (
            "adapter-process-holding-1",
            opened.dispatch.adapter_process_occurrence_id.as_str(),
        ),
        (
            "fixture-estate-holding-1",
            opened.dispatch.app_server_session_identity.as_str(),
        ),
        ("gpt-5.6-sol", opened.dispatch.selection.model_id.as_str()),
    ];
    holding_replace_strings(&mut snapshot, &replacements);
    for record in snapshot["records"].as_array_mut().unwrap() {
        if !record["raw"].is_null() {
            let bytes = hex::decode(record["raw"]["bytes_hex"].as_str().unwrap()).unwrap();
            let mut wire: Value = serde_json::from_slice(&bytes).unwrap();
            holding_replace_strings(&mut wire, &replacements);
            let mut exact = serde_json::to_vec(&wire).unwrap();
            exact.push(b"\n"[0]);
            record["raw"] = json!({
                "representation": "EXACT_WIRE_BYTES_INCLUDING_LINE_TERMINATOR",
                "byte_length": exact.len(),
                "sha256": format!("sha256:{:x}", Sha256::digest(&exact)),
                "encoding": "hex",
                "bytes_hex": hex::encode(exact),
            });
        }
    }
    snapshot["binding"] = holding_seal_value(
        snapshot["binding"].clone(),
        "binding_digest",
        b"switchyard.codex-provider-admission-binding.digest/v1\0",
    );
    let binding_digest = snapshot["binding"]["binding_digest"].clone();
    for record in snapshot["records"].as_array_mut().unwrap() {
        record["binding_digest"] = binding_digest.clone();
        *record = holding_seal_value(
            record.clone(),
            "evidence_digest",
            b"switchyard.codex-provider-admission-evidence.digest/v1\0",
        );
    }
    snapshot = holding_seal_value(
        snapshot,
        "snapshot_digest",
        b"switchyard.codex-provider-admission-snapshot.digest/v1\0",
    );
    holding_canonical(&snapshot)
}

fn holding_policy() -> ExecutionAvailabilityPolicyV1 {
    let mut value = ExecutionAvailabilityPolicyV1 {
        schema: EXECUTION_AVAILABILITY_POLICY_SCHEMA_V1.to_owned(),
        policy_digest: holding_placeholder(),
        policy_id: "holding-policy".to_owned(),
        maximum_dispatch_occurrences_per_attempt: 4,
        backoff_seconds: vec![5, 10, 20, 40],
        maximum_total_deferral_seconds: 600,
        parked_resource_lock_policy: ParkedResourceLockPolicyV1::ReleaseAndReacquire,
        provider_capacity_released_while_parked: true,
        reconcile_indeterminate: true,
        allow_ordered_model_fallback: true,
        automatic_semantic_retry: false,
        approval_response_authorized: false,
        authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".to_owned(),
    };
    value.seal().unwrap();
    value
}

fn holding_requirement(
    packet: &NightshiftPacketV1,
    admission: &ForemanAdmissionV1,
    profile: &ExecutionProfileV2,
    policy: &ExecutionAvailabilityPolicyV1,
) -> ForemanExecutionAvailabilityRequirementV1 {
    let selections = packet
        .work_items
        .iter()
        .map(|item| {
            (
                item.id.clone(),
                vec![
                    ProviderModelSelectionV1 {
                        provider_id: "openai".to_owned(),
                        model_id: "gpt-5.6-sol".to_owned(),
                        model_class: "large".to_owned(),
                    },
                    ProviderModelSelectionV1 {
                        provider_id: "openai".to_owned(),
                        model_id: "gpt-5.6-terra".to_owned(),
                        model_class: "large".to_owned(),
                    },
                ],
            )
        })
        .collect();
    let adapter_id = &profile.work_items["work-a"].adapter_id;
    let adapter = &profile.adapters[adapter_id];
    let mut value = ForemanExecutionAvailabilityRequirementV1 {
        schema: FOREMAN_EXECUTION_AVAILABILITY_REQUIREMENT_SCHEMA_V1.to_owned(),
        requirement_digest: holding_placeholder(),
        packet_digest: packet.packet_digest.clone(),
        admission_digest: admission.admission_digest.clone(),
        profile_digest: profile.profile_digest.clone(),
        run_id: admission.run_id.clone(),
        adapter_id: adapter.adapter_id.clone(),
        adapter_protocol: adapter.protocol.clone(),
        adapter_version: adapter.adapter_version.clone(),
        adapter_executable_identity: adapter.executable_identity.clone(),
        owner_pins: ProviderAdmissionOwnerPinsV1::accepted(),
        policy_id: policy.policy_id.clone(),
        policy_digest: policy.policy_digest.clone(),
        work_item_model_selections: selections,
        admitted_at: admission.admitted_at,
        authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".to_owned(),
    };
    value.seal().unwrap();
    value
}

fn holding_fixture_contracts() -> (
    TempDir,
    PathBuf,
    NightshiftPacketV1,
    ForemanAdmissionV1,
    ExecutionProfileV2,
    ExecutionAvailabilityPolicyV1,
    ForemanExecutionAvailabilityRequirementV1,
) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("holding.sqlite");
    let mut packet = packet();
    packet.packet_id = "holding-store-fixture".to_owned();
    packet.created_at = holding_time("2026-08-31T12:00:00Z");
    packet.current_until = holding_time("2026-08-31T14:00:00Z");
    let mut first = work_item("work-a", "WORK-A", vec![]);
    first.model_routing.class = "large".to_owned();
    let mut second = work_item("work-b", "WORK-B", vec![]);
    second.model_routing.class = "large".to_owned();
    packet.work_items = vec![first, second];
    packet.worker_budget.maximum_concurrent_mutating_workers = 2;
    packet.seal().unwrap();

    let mut admission = admission(&packet);
    admission.run_id = "run-holding-store".to_owned();
    admission.admitted_at = holding_time("2026-08-31T12:00:00Z");
    admission.expires_at = holding_time("2026-08-31T13:00:00Z");
    admission.maximum_concurrent_workers = 2;
    admission.allowed_adapter_ids = vec!["switchyard-codex".to_owned()];
    admission.allowed_provider_model_classes = vec!["large".to_owned()];
    admission.seal().unwrap();

    let mut work_items = BTreeMap::new();
    for (work_item_id, lock) in [("work-a", "provider-slot-a"), ("work-b", "provider-slot-b")] {
        work_items.insert(
            work_item_id.to_owned(),
            WorkItemExecutionV1 {
                adapter_id: "switchyard-codex".to_owned(),
                workspace_identity: format!("workspace-{work_item_id}"),
                resource_lock_keys: vec![lock.to_owned()],
                provider_model_class: "large".to_owned(),
            },
        );
    }
    let mut profile = ExecutionProfileV2 {
        schema: FOREMAN_EXECUTION_PROFILE_SCHEMA_V2.to_owned(),
        profile_digest: holding_placeholder(),
        packet_digest: packet.packet_digest.clone(),
        admission_digest: admission.admission_digest.clone(),
        adapters: BTreeMap::from([(
            "switchyard-codex".to_owned(),
            AdapterRegistrationV2 {
                adapter_id: "switchyard-codex".to_owned(),
                protocol: "switchyard.codex-app-server/v2".to_owned(),
                adapter_version: "2.0.0".to_owned(),
                executable_identity: format!("sha256:{}", "9".repeat(64)),
                bounded_arguments: vec![],
            },
        )]),
        work_items,
        budget_policy_ref: "fuel-policy".to_owned(),
        log_custody_root: "/tmp/nightshift-holding/log".to_owned(),
        receipt_custody_root: "/tmp/nightshift-holding/receipts".to_owned(),
        maximum_event_bytes: 1024 * 1024,
        maximum_worker_output_bytes: None,
        maximum_receipt_bytes: 1024 * 1024,
        adapter_timeout_seconds: 600,
        closeout_policy: "ALL_EXPLICIT_TERMINAL_OR_NOT_STARTED".to_owned(),
    };
    profile.seal().unwrap();
    let policy = holding_policy();
    let requirement = holding_requirement(&packet, &admission, &profile, &policy);
    (
        directory,
        path,
        packet,
        admission,
        profile,
        policy,
        requirement,
    )
}

fn holding_setup() -> (
    TempDir,
    PathBuf,
    ForemanStore,
    NightshiftPacketV1,
    ForemanAdmissionV1,
    ExecutionProfileV2,
    ExecutionAvailabilityPolicyV1,
    ForemanExecutionAvailabilityRequirementV1,
) {
    let (directory, path, packet, admission, profile, policy, requirement) =
        holding_fixture_contracts();
    let store = ForemanStore::open(&path).unwrap();
    store
        .admit_with_execution_availability(
            &packet.canonical_bytes().unwrap(),
            &holding_canonical(&admission),
            &holding_canonical(&profile),
            &holding_canonical(&requirement),
            &holding_canonical(&policy),
            admission.admitted_at,
        )
        .unwrap();
    (
        directory,
        path,
        store,
        packet,
        admission,
        profile,
        policy,
        requirement,
    )
}

fn holding_setup_qualification_v1() -> (
    TempDir,
    PathBuf,
    ForemanStore,
    NightshiftPacketV1,
    ForemanAdmissionV1,
    ExecutionProfileV2,
    ExecutionAvailabilityPolicyV1,
    ForemanExecutionAvailabilityRequirementV1,
) {
    let (directory, path, packet, mut admission, mut profile, policy, _) =
        holding_fixture_contracts();
    admission.allowed_adapter_ids = vec![HOLDING_QUALIFICATION_PRODUCER_ID.to_owned()];
    admission.seal().unwrap();
    for work in profile.work_items.values_mut() {
        work.adapter_id = HOLDING_QUALIFICATION_PRODUCER_ID.to_owned();
    }
    profile.adapters = BTreeMap::from([(
        HOLDING_QUALIFICATION_PRODUCER_ID.to_owned(),
        AdapterRegistrationV2 {
            adapter_id: HOLDING_QUALIFICATION_PRODUCER_ID.to_owned(),
            protocol: DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V1.to_owned(),
            adapter_version: HOLDING_QUALIFICATION_PRODUCER_VERSION.to_owned(),
            executable_identity: HOLDING_QUALIFICATION_EXECUTABLE_SHA256.to_owned(),
            bounded_arguments: vec![],
        },
    )]);
    profile.admission_digest = admission.admission_digest.clone();
    profile.seal().unwrap();
    let requirement = holding_requirement(&packet, &admission, &profile, &policy);
    let store = ForemanStore::open(&path).unwrap();
    store
        .admit_with_execution_availability(
            &packet.canonical_bytes().unwrap(),
            &holding_canonical(&admission),
            &holding_canonical(&profile),
            &holding_canonical(&requirement),
            &holding_canonical(&policy),
            admission.admitted_at,
        )
        .unwrap();
    (
        directory,
        path,
        store,
        packet,
        admission,
        profile,
        policy,
        requirement,
    )
}

fn holding_setup_combined() -> (
    TempDir,
    PathBuf,
    ForemanStore,
    NightshiftPacketV1,
    ForemanAdmissionV1,
    ExecutionProfileV2,
    ExecutionAvailabilityPolicyV1,
    ForemanExecutionAvailabilityRequirementV1,
    CapacityPolicyV1,
    ForemanCapacityRequirementV1,
) {
    let (directory, path, packet, admission, profile, policy, requirement) =
        holding_fixture_contracts();
    let mut capacity_policy = CapacityPolicyV1::default();
    capacity_policy.policy_id = profile.budget_policy_ref.clone();
    capacity_policy.policy_digest = capacity_policy.compute_digest().unwrap();
    let capacity_requirement =
        capacity_requirement(&packet, &admission, &profile, &capacity_policy);
    let store = ForemanStore::open(&path).unwrap();
    let capacity_requirement_bytes = holding_canonical(&capacity_requirement);
    let requirement_bytes = holding_canonical(&requirement);
    let policy_bytes = holding_canonical(&policy);
    store
        .admit_with_mechanism_requirements(
            &packet.canonical_bytes().unwrap(),
            &holding_canonical(&admission),
            &holding_canonical(&profile),
            RunMechanismRequirementsV1 {
                capacity_requirement_bytes: Some(&capacity_requirement_bytes),
                execution_availability_requirement_bytes: Some(&requirement_bytes),
                execution_availability_policy_bytes: Some(&policy_bytes),
            },
            admission.admitted_at,
        )
        .unwrap();
    (
        directory,
        path,
        store,
        packet,
        admission,
        profile,
        policy,
        requirement,
        capacity_policy,
        capacity_requirement,
    )
}

fn holding_setup_with_policy(
    maximum_concurrent_workers: u16,
    lock_policy: ParkedResourceLockPolicyV1,
    allow_ordered_model_fallback: bool,
) -> (
    TempDir,
    PathBuf,
    ForemanStore,
    NightshiftPacketV1,
    ForemanAdmissionV1,
    ExecutionProfileV2,
    ExecutionAvailabilityPolicyV1,
    ForemanExecutionAvailabilityRequirementV1,
) {
    let (directory, path, packet, mut admission, mut profile, mut policy, _) =
        holding_fixture_contracts();
    admission.maximum_concurrent_workers = maximum_concurrent_workers;
    admission.seal().unwrap();
    profile.admission_digest = admission.admission_digest.clone();
    profile.seal().unwrap();
    policy.parked_resource_lock_policy = lock_policy;
    policy.provider_capacity_released_while_parked = true;
    policy.allow_ordered_model_fallback = allow_ordered_model_fallback;
    policy.seal().unwrap();
    let requirement = holding_requirement(&packet, &admission, &profile, &policy);
    let store = ForemanStore::open(&path).unwrap();
    store
        .admit_with_execution_availability(
            &packet.canonical_bytes().unwrap(),
            &holding_canonical(&admission),
            &holding_canonical(&profile),
            &holding_canonical(&requirement),
            &holding_canonical(&policy),
            admission.admitted_at,
        )
        .unwrap();
    (
        directory,
        path,
        store,
        packet,
        admission,
        profile,
        policy,
        requirement,
    )
}

fn holding_snapshot(name: &str) -> Value {
    if name == "waiting" {
        let mut snapshot: Value = serde_json::from_slice(include_bytes!(
            "../../../qualification/provider-execution-availability-and-deferred-dispatch-v1-20260831/fixtures/switchyard-approval-interrupted.snapshot.v1.json"
        ))
        .unwrap();
        let execution = snapshot["provider_execution_identity"].clone();
        let mut wire = serde_json::to_vec(&json!({
            "method": "item/commandExecution/requestApproval",
            "params": {
                "threadId": "thread-holding-1",
                "turnId": "turn-holding-1"
            }
        }))
        .unwrap();
        wire.push(b'\n');
        let approval = &mut snapshot["records"][3];
        approval["kind"] = json!("WAITING_APPROVAL");
        approval["method"] = json!("item/commandExecution/requestApproval");
        approval["raw"] = json!({
            "representation": "EXACT_WIRE_BYTES_INCLUDING_LINE_TERMINATOR",
            "byte_length": wire.len(),
            "sha256": format!("sha256:{:x}", Sha256::digest(&wire)),
            "encoding": "hex",
            "bytes_hex": hex::encode(&wire),
        });
        approval["normalized"] = json!({
            "approval_response_sent": false,
            "protected_effect_absent": true,
            "provider_execution_identity": execution,
        });
        snapshot["records"].as_array_mut().unwrap().truncate(4);
        snapshot["acquisition_cut"] = Value::Null;
        snapshot["admission_disposition"] = json!("EXECUTION_ADMITTED");
        snapshot["mechanism_state"] = json!("WAITING_APPROVAL");
        return snapshot;
    }
    let bytes: &[u8] = match name {
        "parked" => include_bytes!(
            "../../../qualification/provider-execution-availability-and-deferred-dispatch-v1-20260831/fixtures/switchyard-parked-not-admitted.snapshot.v1.json"
        ),
        "indeterminate" => include_bytes!(
            "../../../qualification/provider-execution-availability-and-deferred-dispatch-v1-20260831/fixtures/switchyard-admission-indeterminate.snapshot.v1.json"
        ),
        "interrupted" => include_bytes!(
            "../../../qualification/provider-execution-availability-and-deferred-dispatch-v1-20260831/fixtures/switchyard-post-admission-interrupted.snapshot.v1.json"
        ),
        "approval" => include_bytes!(
            "../../../qualification/provider-execution-availability-and-deferred-dispatch-v1-20260831/fixtures/switchyard-approval-interrupted.snapshot.v1.json"
        ),
        "completed" => include_bytes!(
            "../../../qualification/provider-execution-availability-and-deferred-dispatch-v1-20260831/fixtures/switchyard-provider-completed.snapshot.v1.json"
        ),
        value => panic!("unknown holding snapshot {value}"),
    };
    serde_json::from_slice(bytes).unwrap()
}

fn holding_disposition(
    requirement: &ForemanExecutionAvailabilityRequirementV1,
    opened: &nightshift_foreman::OpenedProviderDispatchV1,
    snapshot_name: &str,
    received_at: chrono::DateTime<Utc>,
) -> (
    Vec<u8>,
    ProviderAdmissionDispositionV1,
    ExecutionAvailabilityObservationV1,
) {
    let snapshot_bytes = holding_retarget_snapshot(holding_snapshot(snapshot_name), opened);
    let snapshot: Value = serde_json::from_slice(&snapshot_bytes).unwrap();
    let execution = snapshot["provider_execution_identity"]
        .as_object()
        .map(|identity| ProviderExecutionIdentityV1 {
            provider_id: identity["provider"].as_str().unwrap().to_owned(),
            model_id: identity["model"].as_str().unwrap().to_owned(),
            app_server_session_identity: identity["app_server_session_identity"]
                .as_str()
                .unwrap()
                .to_owned(),
            thread_id: identity["thread_id"].as_str().unwrap().to_owned(),
            turn_id: identity["turn_id"].as_str().unwrap().to_owned(),
            first_response_id: identity["first_response_id"].as_str().unwrap().to_owned(),
        });
    let disposition_kind = match snapshot["admission_disposition"].as_str().unwrap() {
        "EXECUTION_ADMITTED" => ProviderAdmissionDispositionKindV1::ExecutionAdmitted,
        "NOT_ADMITTED_MODEL_AT_CAPACITY" => {
            ProviderAdmissionDispositionKindV1::NotAdmittedModelAtCapacity
        }
        "ADMISSION_INDETERMINATE" => ProviderAdmissionDispositionKindV1::AdmissionIndeterminate,
        value => panic!("unexpected fixture disposition {value}"),
    };
    let mechanism_state = match snapshot["mechanism_state"].as_str().unwrap() {
        "PARKED_NOT_ADMITTED" => ProviderMechanismStateV1::ParkedNotAdmitted,
        "ADMISSION_INDETERMINATE" => ProviderMechanismStateV1::AdmissionIndeterminate,
        "POST_ADMISSION_INTERRUPTED" => ProviderMechanismStateV1::PostAdmissionInterrupted,
        "WAITING_APPROVAL" => ProviderMechanismStateV1::WaitingApproval,
        "PROVIDER_COMPLETED" => ProviderMechanismStateV1::ProviderCompleted,
        value => panic!("unexpected fixture mechanism {value}"),
    };
    let request_occurrence = snapshot["records"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|record| record["normalized"]["request_occurrence_id"].as_str())
        .unwrap_or("request-0")
        .to_owned();
    let retry_after_ms = snapshot["records"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|record| record["normalized"]["retry_after_ms"].as_i64());
    let mut disposition = ProviderAdmissionDispositionV1 {
        schema: PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V1.to_owned(),
        disposition_digest: holding_placeholder(),
        dispatch_digest: opened.dispatch.dispatch_digest.clone(),
        requirement_digest: requirement.requirement_digest.clone(),
        policy_digest: requirement.policy_digest.clone(),
        packet_digest: requirement.packet_digest.clone(),
        run_id: requirement.run_id.clone(),
        work_item_id: opened.dispatch.work_item_id.clone(),
        work_attempt_id: opened.dispatch.work_attempt_id.clone(),
        dispatch_occurrence_id: opened.dispatch.dispatch_occurrence_id.clone(),
        provider_id: opened.dispatch.selection.provider_id.clone(),
        model_id: opened.dispatch.selection.model_id.clone(),
        provider_request_occurrence_id: request_occurrence,
        adapter_process_occurrence_id: opened.dispatch.adapter_process_occurrence_id.clone(),
        app_server_session_identity: opened.dispatch.app_server_session_identity.clone(),
        thread_id: snapshot["binding"]["thread_id"]
            .as_str()
            .unwrap()
            .to_owned(),
        turn_id: snapshot["binding"]["turn_id"].as_str().unwrap().to_owned(),
        disposition: disposition_kind,
        mechanism_state,
        received_at,
        response_created: execution.is_some(),
        will_retry: false,
        acquisition_complete: snapshot["acquisition_cut"]["clean"]
            .as_bool()
            .unwrap_or(false),
        provider_retry_after: retry_after_ms
            .map(|milliseconds| received_at + Duration::milliseconds(milliseconds)),
        provider_execution: execution,
        mapper_snapshot_schema: "switchyard.codex-provider-admission-snapshot/v1".to_owned(),
        mapper_snapshot_digest: snapshot["snapshot_digest"].as_str().unwrap().to_owned(),
        mapper_snapshot: ExactMapperSnapshotV1::from_bytes(&snapshot_bytes).unwrap(),
        approval_response_sent: false,
        protected_effect_absent: true,
        authority_effect: "SCHEDULING_MECHANISM_EVIDENCE_ONLY".to_owned(),
    };
    disposition.seal().unwrap();
    let source_kind = match disposition.disposition {
        ProviderAdmissionDispositionKindV1::NotAdmittedModelAtCapacity => {
            "PROVIDER_ADMISSION_REFUSED"
        }
        ProviderAdmissionDispositionKindV1::ExecutionAdmitted => "PROVIDER_EXECUTION_STEP",
        ProviderAdmissionDispositionKindV1::AdmissionIndeterminate => "ADMISSION_DISCREPANCY",
        _ => unreachable!(),
    };
    let source = snapshot["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["kind"] == source_kind)
        .unwrap();
    let exact_evidence = if source["raw"].is_null() {
        None
    } else {
        Some(serde_json::from_value(source["raw"].clone()).unwrap())
    };
    let observed_at = source["normalized"]["observed_at_ms"]
        .as_i64()
        .and_then(chrono::DateTime::<Utc>::from_timestamp_millis)
        .unwrap_or(received_at);
    let state = match disposition.disposition {
        ProviderAdmissionDispositionKindV1::NotAdmittedModelAtCapacity => {
            ExecutionAvailabilityStateV1::ModelAtCapacity
        }
        ProviderAdmissionDispositionKindV1::ExecutionAdmitted => {
            ExecutionAvailabilityStateV1::Available
        }
        ProviderAdmissionDispositionKindV1::AdmissionIndeterminate => {
            ExecutionAvailabilityStateV1::Unknown
        }
        _ => unreachable!(),
    };
    let mut observation = ExecutionAvailabilityObservationV1 {
        schema: EXECUTION_AVAILABILITY_OBSERVATION_SCHEMA_V1.to_owned(),
        observation_digest: holding_placeholder(),
        provider_id: disposition.provider_id.clone(),
        model_id: disposition.model_id.clone(),
        model_class: opened.dispatch.selection.model_class.clone(),
        observed_at,
        received_at,
        expires_at: received_at + Duration::seconds(60),
        state,
        source_identity: "switchyard:provider-admission".to_owned(),
        source_version: "v1".to_owned(),
        provider_retry_after: disposition.provider_retry_after,
        exact_evidence,
        authority_effect: "SCHEDULING_MECHANISM_EVIDENCE_ONLY".to_owned(),
    };
    observation.seal().unwrap();
    (snapshot_bytes, disposition, observation)
}

fn holding_deferred(
    requirement: &ForemanExecutionAvailabilityRequirementV1,
    policy: &ExecutionAvailabilityPolicyV1,
    opened: &nightshift_foreman::OpenedProviderDispatchV1,
    disposition: &ProviderAdmissionDispositionV1,
) -> DeferredProviderDispatchV1 {
    let remaining_model_ordinals = if policy.allow_ordered_model_fallback {
        ((opened.dispatch.selected_model_ordinal + 1)
            ..requirement.work_item_model_selections[&opened.dispatch.work_item_id].len() as u16)
            .collect()
    } else {
        Vec::new()
    };
    let wake_at = disposition.provider_retry_after.unwrap_or_else(|| {
        disposition.received_at
            + Duration::seconds(
                policy.backoff_seconds[opened.dispatch.dispatch_ordinal as usize - 1] as i64,
            )
    });
    let backoff_seconds = (wake_at - disposition.received_at).num_seconds() as u64;
    let mut value = DeferredProviderDispatchV1 {
        schema: DEFERRED_PROVIDER_DISPATCH_SCHEMA_V1.to_owned(),
        deferred_dispatch_digest: holding_placeholder(),
        requirement_digest: requirement.requirement_digest.clone(),
        policy_digest: policy.policy_digest.clone(),
        disposition_digest: disposition.disposition_digest.clone(),
        packet_digest: requirement.packet_digest.clone(),
        run_id: requirement.run_id.clone(),
        work_item_id: opened.dispatch.work_item_id.clone(),
        work_attempt_id: opened.dispatch.work_attempt_id.clone(),
        last_dispatch_occurrence_id: opened.dispatch.dispatch_occurrence_id.clone(),
        provider_id: opened.dispatch.selection.provider_id.clone(),
        model_id: opened.dispatch.selection.model_id.clone(),
        selected_model_ordinal: opened.dispatch.selected_model_ordinal,
        remaining_model_ordinals,
        refusal_received_at: disposition.received_at,
        wake_basis: if disposition.provider_retry_after.is_some() {
            DeferredWakeBasisV1::ProviderRetryAfter
        } else {
            DeferredWakeBasisV1::PolicyBackoff
        },
        backoff_ordinal: opened.dispatch.dispatch_ordinal - 1,
        backoff_seconds,
        provider_retry_after: disposition.provider_retry_after,
        wake_at,
        parked_resource_lock_policy: policy.parked_resource_lock_policy,
        provider_capacity_released: true,
        semantic_retry: false,
        authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".to_owned(),
    };
    value.seal().unwrap();
    value
}

fn holding_open_initial(
    store: &ForemanStore,
) -> (
    WorkerStartRequestV2,
    nightshift_foreman::OpenedProviderDispatchV1,
) {
    let opened = store
        .prepare_provider_attempt(
            "run-holding-store",
            "work-a",
            "dispatch-store-1",
            "adapter-process-store-1",
            "session-store-1",
            0,
            holding_time("2026-08-31T12:01:00Z"),
        )
        .unwrap();
    let attempt = opened.worker_start_request.predecessor_v2().unwrap();
    (attempt, opened)
}

fn holding_record(
    store: &ForemanStore,
    requirement: &ForemanExecutionAvailabilityRequirementV1,
    policy: &ExecutionAvailabilityPolicyV1,
    opened: &nightshift_foreman::OpenedProviderDispatchV1,
    snapshot_name: &str,
    received_at: chrono::DateTime<Utc>,
    predecessor: Option<&str>,
) -> ProviderAdmissionDispositionV1 {
    let (_snapshot, disposition, observation) =
        holding_disposition(requirement, opened, snapshot_name, received_at);
    let deferred = if disposition.disposition.permits_automatic_park() {
        Some(holding_deferred(requirement, policy, opened, &disposition))
    } else {
        None
    };
    let observation_bytes = holding_canonical(&observation);
    let disposition_bytes = holding_canonical(&disposition);
    let deferred_bytes = deferred.as_ref().map(holding_canonical);
    store
        .record_provider_disposition(
            &disposition.run_id,
            &disposition.work_item_id,
            &disposition.work_attempt_id,
            ProviderDispositionEvidenceV1 {
                observation_bytes: &observation_bytes,
                disposition_bytes: &disposition_bytes,
                deferred_bytes: deferred_bytes.as_deref(),
            },
            predecessor,
        )
        .unwrap()
}

fn holding_qualification_records(
    requirement: &ForemanExecutionAvailabilityRequirementV1,
    opened: &nightshift_foreman::OpenedProviderDispatchV1,
    outcome: DeterministicProviderAdmissionOutcomeV1,
    response_created: bool,
) -> (
    ProviderAdmissionDispositionV1,
    ExecutionAvailabilityObservationV1,
) {
    let observed_at = holding_time("2026-08-31T12:01:01Z");
    let received_at = holding_time("2026-08-31T12:01:02Z");
    let retry_after = matches!(
        outcome,
        DeterministicProviderAdmissionOutcomeV1::RateLimited
            | DeterministicProviderAdmissionOutcomeV1::ProviderUnavailable
    )
    .then(|| holding_time("2026-08-31T12:01:07Z"));
    let non_admission_proven = matches!(
        outcome,
        DeterministicProviderAdmissionOutcomeV1::RateLimited
            | DeterministicProviderAdmissionOutcomeV1::ProviderUnavailable
            | DeterministicProviderAdmissionOutcomeV1::AuthenticationRefused
    );
    let raw = holding_canonical(&json!({
        "outcome": outcome,
        "response_created": response_created,
        "non_admission_proven": non_admission_proven,
        "retry_after": retry_after,
        "observed_at": observed_at,
    }));
    let mut evidence = DeterministicProviderAdmissionEvidenceV1 {
        schema: DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V1.to_owned(),
        evidence_digest: holding_placeholder(),
        producer_id: HOLDING_QUALIFICATION_PRODUCER_ID.to_owned(),
        producer_version: HOLDING_QUALIFICATION_PRODUCER_VERSION.to_owned(),
        executable_id: HOLDING_QUALIFICATION_EXECUTABLE_ID.to_owned(),
        executable_sha256: HOLDING_QUALIFICATION_EXECUTABLE_SHA256.to_owned(),
        work_attempt_id: opened.dispatch.work_attempt_id.clone(),
        dispatch_occurrence_id: opened.dispatch.dispatch_occurrence_id.clone(),
        provider_request_occurrence_id: "qualification-request-store-1".to_owned(),
        provider_id: opened.dispatch.selection.provider_id.clone(),
        model_id: opened.dispatch.selection.model_id.clone(),
        outcome,
        response_created,
        non_admission_proven,
        retry_after,
        observed_at,
        received_at,
        raw_evidence: ExactAvailabilityEvidenceV1::from_bytes(
            "EXACT_PROVIDER_AVAILABILITY_SOURCE_BYTES",
            &raw,
        )
        .unwrap(),
        authority_effect: "QUALIFICATION_MECHANISM_EVIDENCE_ONLY".to_owned(),
    };
    evidence.seal().unwrap();
    let evidence_bytes = holding_canonical(&evidence);
    let (kind, mechanism, state) = match outcome {
        DeterministicProviderAdmissionOutcomeV1::RateLimited => (
            ProviderAdmissionDispositionKindV1::NotAdmittedRateLimited,
            ProviderMechanismStateV1::ParkedNotAdmitted,
            ExecutionAvailabilityStateV1::RateLimited,
        ),
        DeterministicProviderAdmissionOutcomeV1::ProviderUnavailable => (
            ProviderAdmissionDispositionKindV1::NotAdmittedProviderUnavailable,
            ProviderMechanismStateV1::ParkedNotAdmitted,
            ExecutionAvailabilityStateV1::ProviderUnavailable,
        ),
        DeterministicProviderAdmissionOutcomeV1::AuthenticationRefused => (
            ProviderAdmissionDispositionKindV1::AuthenticationRefused,
            ProviderMechanismStateV1::AdmissionIndeterminate,
            ExecutionAvailabilityStateV1::AuthenticationRefused,
        ),
        DeterministicProviderAdmissionOutcomeV1::TransportError => (
            ProviderAdmissionDispositionKindV1::AdmissionIndeterminate,
            ProviderMechanismStateV1::AdmissionIndeterminate,
            ExecutionAvailabilityStateV1::TransportError,
        ),
        DeterministicProviderAdmissionOutcomeV1::ProtocolError => (
            ProviderAdmissionDispositionKindV1::AdmissionIndeterminate,
            ProviderMechanismStateV1::AdmissionIndeterminate,
            ExecutionAvailabilityStateV1::ProtocolError,
        ),
    };
    let mut disposition = ProviderAdmissionDispositionV1 {
        schema: PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V2.to_owned(),
        disposition_digest: holding_placeholder(),
        dispatch_digest: opened.dispatch.dispatch_digest.clone(),
        requirement_digest: requirement.requirement_digest.clone(),
        policy_digest: requirement.policy_digest.clone(),
        packet_digest: requirement.packet_digest.clone(),
        run_id: requirement.run_id.clone(),
        work_item_id: opened.dispatch.work_item_id.clone(),
        work_attempt_id: opened.dispatch.work_attempt_id.clone(),
        dispatch_occurrence_id: opened.dispatch.dispatch_occurrence_id.clone(),
        provider_id: opened.dispatch.selection.provider_id.clone(),
        model_id: opened.dispatch.selection.model_id.clone(),
        provider_request_occurrence_id: evidence.provider_request_occurrence_id.clone(),
        adapter_process_occurrence_id: opened.dispatch.adapter_process_occurrence_id.clone(),
        app_server_session_identity: opened.dispatch.app_server_session_identity.clone(),
        thread_id: "qualification-thread-store-1".to_owned(),
        turn_id: "qualification-turn-store-1".to_owned(),
        disposition: kind,
        mechanism_state: mechanism,
        received_at,
        response_created,
        will_retry: false,
        acquisition_complete: true,
        provider_retry_after: retry_after,
        provider_execution: None,
        mapper_snapshot_schema: DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V1.to_owned(),
        mapper_snapshot_digest: evidence.evidence_digest.clone(),
        mapper_snapshot: ExactMapperSnapshotV1::from_qualification_evidence_bytes(&evidence_bytes)
            .unwrap(),
        approval_response_sent: false,
        protected_effect_absent: true,
        authority_effect: "SCHEDULING_MECHANISM_EVIDENCE_ONLY".to_owned(),
    };
    disposition.seal().unwrap();
    let mut observation = ExecutionAvailabilityObservationV1 {
        schema: EXECUTION_AVAILABILITY_OBSERVATION_SCHEMA_V1.to_owned(),
        observation_digest: holding_placeholder(),
        provider_id: disposition.provider_id.clone(),
        model_id: disposition.model_id.clone(),
        model_class: opened.dispatch.selection.model_class.clone(),
        observed_at,
        received_at,
        expires_at: received_at + Duration::seconds(60),
        state,
        source_identity: HOLDING_QUALIFICATION_PRODUCER_ID.to_owned(),
        source_version: HOLDING_QUALIFICATION_PRODUCER_VERSION.to_owned(),
        provider_retry_after: retry_after,
        exact_evidence: Some(evidence.raw_evidence),
        authority_effect: "SCHEDULING_MECHANISM_EVIDENCE_ONLY".to_owned(),
    };
    observation.seal().unwrap();
    (disposition, observation)
}

#[test]
fn holding_qualification_owner_uses_common_store_transition_for_closed_outcomes() {
    for (outcome, response_created, expected_state) in [
        (
            DeterministicProviderAdmissionOutcomeV1::RateLimited,
            false,
            ProviderMechanismStateV1::ParkedNotAdmitted,
        ),
        (
            DeterministicProviderAdmissionOutcomeV1::ProviderUnavailable,
            false,
            ProviderMechanismStateV1::ParkedNotAdmitted,
        ),
        (
            DeterministicProviderAdmissionOutcomeV1::AuthenticationRefused,
            false,
            ProviderMechanismStateV1::AdmissionIndeterminate,
        ),
        (
            DeterministicProviderAdmissionOutcomeV1::TransportError,
            false,
            ProviderMechanismStateV1::AdmissionIndeterminate,
        ),
        (
            DeterministicProviderAdmissionOutcomeV1::TransportError,
            true,
            ProviderMechanismStateV1::AdmissionIndeterminate,
        ),
        (
            DeterministicProviderAdmissionOutcomeV1::ProtocolError,
            false,
            ProviderMechanismStateV1::AdmissionIndeterminate,
        ),
    ] {
        let (_directory, path, store, _packet, _admission, _profile, policy, requirement) =
            holding_setup_qualification_v1();
        let (attempt, opened) = holding_open_initial(&store);
        let (disposition, observation) =
            holding_qualification_records(&requirement, &opened, outcome, response_created);
        let deferred = disposition
            .permits_automatic_park()
            .then(|| holding_deferred(&requirement, &policy, &opened, &disposition));
        let disposition_bytes = holding_canonical(&disposition);
        let observation_bytes = holding_canonical(&observation);
        let deferred_bytes = deferred.as_ref().map(holding_canonical);
        let accepted = store
            .record_provider_disposition(
                &disposition.run_id,
                &disposition.work_item_id,
                &disposition.work_attempt_id,
                ProviderDispositionEvidenceV1 {
                    observation_bytes: &observation_bytes,
                    disposition_bytes: &disposition_bytes,
                    deferred_bytes: deferred_bytes.as_deref(),
                },
                None,
            )
            .unwrap();
        assert_eq!(accepted.mechanism_state, expected_state);
        let query = ForemanStore::open_read_only(&path).unwrap();
        let history = query
            .read_only_run_snapshot(&disposition.run_id)
            .unwrap()
            .execution_availability
            .unwrap();
        assert_eq!(history.dispositions, vec![accepted]);
        assert_eq!(history.observations, vec![observation]);
        assert_eq!(history.deferred.len(), usize::from(deferred.is_some()));
        drop(query);
        if deferred.is_some() {
            let next = store
                .wake_provider_dispatch(
                    "run-holding-store",
                    "work-a",
                    &attempt.attempt_id,
                    "qualification-wake-1",
                    "dispatch-store-2",
                    "adapter-process-store-2",
                    "session-store-2",
                    1,
                    holding_time("2026-08-31T12:01:07Z"),
                )
                .unwrap();
            assert_eq!(next.dispatch.dispatch_ordinal, 2);
            assert_eq!(
                next.dispatch.adapter_protocol,
                DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V1
            );
            let history = ForemanStore::open_read_only(&path)
                .unwrap()
                .read_only_run_snapshot("run-holding-store")
                .unwrap()
                .execution_availability
                .unwrap();
            assert_eq!(history.dispositions.len(), 1);
            assert_eq!(history.dispatches.len(), 2);
        } else {
            assert_holding_generic_transitions_refuse_without_mutation(
                &path,
                &store,
                &attempt,
                "qualification owner state cannot use legacy transition",
            );
        }
    }
}

#[test]
fn holding_store_parks_restarts_wakes_falls_back_and_allows_independent_lane() {
    let (_directory, path, store, _packet, _admission, _profile, policy, requirement) =
        holding_setup();
    let (attempt, opened) = holding_open_initial(&store);
    let parked = holding_record(
        &store,
        &requirement,
        &policy,
        &opened,
        "parked",
        holding_time("2026-08-31T12:01:02Z"),
        None,
    );
    assert_eq!(
        parked.mechanism_state,
        ProviderMechanismStateV1::ParkedNotAdmitted
    );
    let projection = store.projection("run-holding-store").unwrap();
    assert_eq!(
        projection
            .work_items
            .iter()
            .find(|item| item.work_item_id == "work-a")
            .unwrap()
            .scheduler_state,
        SchedulerStateV1::WaitingProvider
    );
    assert!(store
        .prepare_attempt(
            "run-holding-store",
            "work-b",
            holding_time("2026-08-31T12:01:03Z"),
        )
        .is_err());
    let independent = store
        .prepare_provider_attempt(
            "run-holding-store",
            "work-b",
            "dispatch-independent-1",
            "adapter-process-independent-1",
            "session-independent-1",
            0,
            holding_time("2026-08-31T12:01:03Z"),
        )
        .unwrap();
    assert_eq!(independent.worker_start_request.work_item_id, "work-b");
    drop(store);

    let restarted = ForemanStore::open(&path).unwrap();
    let wake_at = parked.provider_retry_after.unwrap();
    let next = restarted
        .wake_provider_dispatch(
            "run-holding-store",
            "work-a",
            &attempt.attempt_id,
            "wake-store-1",
            "dispatch-store-2",
            "adapter-process-store-2",
            "session-store-2",
            1,
            wake_at,
        )
        .unwrap();
    assert_eq!(next.dispatch.dispatch_ordinal, 2);
    assert_eq!(next.dispatch.selected_model_ordinal, 1);
    assert_eq!(
        next.worker_start_request.work_attempt_id,
        attempt.attempt_id
    );
    let duplicate = restarted
        .wake_provider_dispatch(
            "run-holding-store",
            "work-a",
            &attempt.attempt_id,
            "wake-store-1",
            "dispatch-store-2",
            "adapter-process-store-2",
            "session-store-2",
            1,
            wake_at,
        )
        .unwrap();
    assert_eq!(duplicate, next);
    assert!(restarted
        .wake_provider_dispatch(
            "run-holding-store",
            "work-a",
            &attempt.attempt_id,
            "wake-store-1",
            "dispatch-substituted",
            "adapter-process-store-2",
            "session-store-2",
            1,
            wake_at,
        )
        .is_err());
    let query = ForemanStore::open_read_only(&path).unwrap();
    let snapshot = query.read_only_run_snapshot("run-holding-store").unwrap();
    let mechanism = snapshot.execution_availability.unwrap();
    assert_eq!(mechanism.dispatches.len(), 3);
    assert_eq!(mechanism.wake_occurrence_ids, vec!["wake-store-1"]);
}

#[test]
fn holding_wake_prepare_and_resume_refuse_after_admission_expiry() {
    // The fixture admission expires at 13:00:00Z; the packet stays current
    // until 14:00:00Z, so the admission window is the binding bound here.
    let expired = holding_time("2026-08-31T13:00:01Z");
    let (_directory, path, store, _packet, _admission, _profile, policy, requirement) =
        holding_setup();
    let (attempt, opened) = holding_open_initial(&store);
    let parked = holding_record(
        &store,
        &requirement,
        &policy,
        &opened,
        "parked",
        holding_time("2026-08-31T12:01:02Z"),
        None,
    );
    assert_eq!(
        parked.mechanism_state,
        ProviderMechanismStateV1::ParkedNotAdmitted
    );
    let wake_at = parked.provider_retry_after.unwrap();
    assert!(wake_at < expired);
    drop(store);

    let restarted = ForemanStore::open(&path).unwrap();
    let late_wake = restarted.wake_provider_dispatch(
        "run-holding-store",
        "work-a",
        &attempt.attempt_id,
        "wake-late-1",
        "dispatch-late-2",
        "adapter-process-late-2",
        "session-late-2",
        1,
        expired,
    );
    assert!(
        matches!(
            late_wake,
            Err(ForemanError::AuthorityNotCurrent("admission expired"))
        ),
        "{late_wake:?}"
    );
    let late_prepare = restarted.prepare_provider_attempt(
        "run-holding-store",
        "work-b",
        "dispatch-late-independent-1",
        "adapter-process-late-independent-1",
        "session-late-independent-1",
        0,
        expired,
    );
    assert!(
        matches!(
            late_prepare,
            Err(ForemanError::AuthorityNotCurrent("admission expired"))
        ),
        "{late_prepare:?}"
    );
    let late_legacy = restarted.prepare_attempt("run-holding-store", "work-b", expired);
    assert!(
        matches!(
            late_legacy,
            Err(ForemanError::AuthorityNotCurrent("admission expired"))
        ),
        "{late_legacy:?}"
    );

    // The refusals left no partial state: the same wake inside the window
    // still opens exactly the second dispatch.
    let next = restarted
        .wake_provider_dispatch(
            "run-holding-store",
            "work-a",
            &attempt.attempt_id,
            "wake-late-1",
            "dispatch-late-2",
            "adapter-process-late-2",
            "session-late-2",
            1,
            wake_at,
        )
        .unwrap();
    assert_eq!(next.dispatch.dispatch_ordinal, 2);
    let query = ForemanStore::open_read_only(&path).unwrap();
    let snapshot = query.read_only_run_snapshot("run-holding-store").unwrap();
    let mechanism = snapshot.execution_availability.unwrap();
    assert_eq!(mechanism.dispatches.len(), 2);
    assert_eq!(mechanism.wake_occurrence_ids, vec!["wake-late-1"]);
}

#[test]
fn holding_resume_refuses_after_admission_expiry() {
    let (_directory, path, store, _packet, _admission, _profile, policy, requirement) =
        holding_setup();
    let (attempt, opened) = holding_open_initial(&store);
    let interrupted = holding_record(
        &store,
        &requirement,
        &policy,
        &opened,
        "interrupted",
        holding_time("2026-08-31T12:01:02Z"),
        None,
    );
    assert_eq!(
        interrupted.mechanism_state,
        ProviderMechanismStateV1::PostAdmissionInterrupted
    );
    drop(store);
    let restarted = ForemanStore::open(&path).unwrap();
    let execution = interrupted.provider_execution.clone().unwrap();
    let late = restarted.resume_provider_execution(
        "run-holding-store",
        "work-a",
        &attempt.attempt_id,
        "resume-late-1",
        &interrupted.disposition_digest,
        "adapter-process-resume-late-1",
        &execution,
        holding_time("2026-08-31T13:00:01Z"),
    );
    assert!(
        matches!(
            late,
            Err(ForemanError::AuthorityNotCurrent("admission expired"))
        ),
        "{late:?}"
    );
    restarted
        .resume_provider_execution(
            "run-holding-store",
            "work-a",
            &attempt.attempt_id,
            "resume-late-1",
            &interrupted.disposition_digest,
            "adapter-process-resume-late-1",
            &execution,
            holding_time("2026-08-31T12:59:59Z"),
        )
        .unwrap();
}

#[test]
fn holding_combines_abundant_fuel_with_exact_model_capacity_without_owner_overwrite() {
    let (
        _directory,
        path,
        store,
        packet,
        admission,
        profile,
        holding_policy,
        holding_requirement,
        capacity_policy,
        capacity_requirement,
    ) = holding_setup_combined();
    let (capacity_admission, observation, policy, decision, derived) = capacity_bundle(
        CapacityFixtureOwner {
            packet: &packet,
            admission: &admission,
            profile: &profile,
            requirement: &capacity_requirement,
            policy: &capacity_policy,
        },
        "work-a",
        holding_time("2026-08-31T12:01:00Z"),
        0.99,
    );
    assert_eq!(derived.state, CapacityState::Abundant);
    assert_eq!(
        derived.admission,
        CapacityAdmissionDisposition::OrdinaryBounded
    );
    let opened = store
        .prepare_provider_attempt_with_capacity(
            "run-holding-store",
            "work-a",
            capacity_evidence(&capacity_admission, &observation, &policy, &decision),
            "dispatch-combined-1",
            "adapter-process-combined-1",
            "session-combined-1",
            0,
            holding_time("2026-08-31T12:01:00Z"),
        )
        .unwrap();
    let parked = holding_record(
        &store,
        &holding_requirement,
        &holding_policy,
        &opened,
        "parked",
        holding_time("2026-08-31T12:01:02Z"),
        None,
    );
    assert_eq!(
        parked.disposition,
        ProviderAdmissionDispositionKindV1::NotAdmittedModelAtCapacity
    );
    drop(store);

    let snapshot = read_only_run_snapshot(&path, "run-holding-store").unwrap();
    assert_eq!(snapshot.capacity_admissions.len(), 1);
    let retained_decision: CapacityDecisionV1 =
        serde_json::from_slice(&snapshot.capacity_admissions[0].decision_bytes).unwrap();
    assert_eq!(retained_decision.state, CapacityState::Abundant);
    let availability = snapshot.execution_availability.unwrap();
    assert_eq!(availability.dispositions, vec![parked]);
    assert_eq!(availability.resource_transitions.len(), 1);
    assert_eq!(availability.resource_transitions[0].transition, "RELEASED");
}

#[test]
fn holding_combined_unknown_fuel_refuses_before_dispatch_without_overwriting_either_owner() {
    let (
        _directory,
        path,
        store,
        packet,
        admission,
        profile,
        _holding_policy,
        _holding_requirement,
        capacity_policy,
        capacity_requirement,
    ) = holding_setup_combined();
    let (mut capacity_admission, mut observation, policy, _decision, _) = capacity_bundle(
        CapacityFixtureOwner {
            packet: &packet,
            admission: &admission,
            profile: &profile,
            requirement: &capacity_requirement,
            policy: &capacity_policy,
        },
        "work-a",
        holding_time("2026-08-31T12:01:00Z"),
        0.99,
    );
    let mut unknown: CapacityObservationV1 = serde_json::from_slice(&observation).unwrap();
    unknown.source_class = SourceClass::Unknown;
    unknown.confidence = Confidence::Low;
    unknown.disposition = ObservationDisposition::Unknown;
    unknown.unknown_reasons = vec!["FIXTURE_SOURCE_UNAVAILABLE".to_owned()];
    unknown.windows.clear();
    unknown.observation_digest = unknown.compute_digest().unwrap();
    let derived = decide_capacity(
        &unknown,
        &capacity_policy,
        holding_time("2026-08-31T12:01:00Z"),
    )
    .unwrap();
    assert_eq!(derived.state, CapacityState::Unknown);
    assert_eq!(derived.admission, CapacityAdmissionDisposition::NoNewWork);
    let mut exact = ForemanCapacityAdmissionV1::from_slice(&capacity_admission).unwrap();
    exact.observation_digest = unknown.observation_digest.clone();
    exact.decision_digest = derived.decision_digest.clone();
    exact.seal().unwrap();
    capacity_admission = holding_canonical(&exact);
    observation = holding_canonical(&unknown);
    let decision = holding_canonical(&derived);
    assert!(store
        .prepare_provider_attempt_with_capacity(
            "run-holding-store",
            "work-a",
            capacity_evidence(&capacity_admission, &observation, &policy, &decision),
            "dispatch-unknown-refused",
            "adapter-process-unknown-refused",
            "session-unknown-refused",
            0,
            holding_time("2026-08-31T12:01:00Z"),
        )
        .is_err());
    drop(store);

    let snapshot = read_only_run_snapshot(&path, "run-holding-store").unwrap();
    assert!(snapshot.capacity_admissions.is_empty());
    let availability = snapshot.execution_availability.unwrap();
    assert!(availability.dispatches.is_empty());
    assert!(availability.dispositions.is_empty());
}

#[test]
fn holding_release_policy_frees_worker_slot_while_retain_policy_keeps_it_consumed() {
    {
        let (_directory, _path, store, _packet, _admission, _profile, policy, requirement) =
            holding_setup_with_policy(1, ParkedResourceLockPolicyV1::ReleaseAndReacquire, true);
        let (_attempt, opened) = holding_open_initial(&store);
        holding_record(
            &store,
            &requirement,
            &policy,
            &opened,
            "parked",
            holding_time("2026-08-31T12:01:02Z"),
            None,
        );
        let independent = store
            .prepare_provider_attempt(
                "run-holding-store",
                "work-b",
                "dispatch-slot-released",
                "adapter-process-slot-released",
                "session-slot-released",
                0,
                holding_time("2026-08-31T12:01:03Z"),
            )
            .unwrap();
        assert_eq!(independent.worker_start_request.work_item_id, "work-b");
    }

    {
        let (_directory, _path, store, _packet, _admission, _profile, policy, requirement) =
            holding_setup_with_policy(1, ParkedResourceLockPolicyV1::RetainWhileParked, true);
        let (_attempt, opened) = holding_open_initial(&store);
        holding_record(
            &store,
            &requirement,
            &policy,
            &opened,
            "parked",
            holding_time("2026-08-31T12:01:02Z"),
            None,
        );
        assert!(matches!(
            store.prepare_provider_attempt(
                "run-holding-store",
                "work-b",
                "dispatch-slot-retained",
                "adapter-process-slot-retained",
                "session-slot-retained",
                0,
                holding_time("2026-08-31T12:01:03Z"),
            ),
            Err(ForemanError::ResourceUnavailable(message))
                if message.contains("maximum concurrent workers")
        ));
    }
}

#[test]
fn holding_repeated_refusal_uses_next_backoff_and_disabled_fallback_cannot_advance_model() {
    let (_directory, _path, store, _packet, _admission, _profile, policy, requirement) =
        holding_setup();
    let (attempt, first) = holding_open_initial(&store);
    let first_park = holding_record(
        &store,
        &requirement,
        &policy,
        &first,
        "parked",
        holding_time("2026-08-31T12:01:02Z"),
        None,
    );
    let second = store
        .wake_provider_dispatch(
            "run-holding-store",
            "work-a",
            &attempt.attempt_id,
            "wake-repeat-1",
            "dispatch-repeat-2",
            "adapter-process-repeat-2",
            "session-repeat-2",
            1,
            first_park.provider_retry_after.unwrap(),
        )
        .unwrap();
    let second_park = holding_record(
        &store,
        &requirement,
        &policy,
        &second,
        "parked",
        holding_time("2026-08-31T12:01:08Z"),
        None,
    );
    assert_eq!(
        second_park.provider_retry_after.unwrap() - holding_time("2026-08-31T12:01:08Z"),
        Duration::seconds(5)
    );

    let (_directory, _path, store, _packet, _admission, _profile, policy, requirement) =
        holding_setup_with_policy(2, ParkedResourceLockPolicyV1::ReleaseAndReacquire, false);
    let (attempt, first) = holding_open_initial(&store);
    let parked = holding_record(
        &store,
        &requirement,
        &policy,
        &first,
        "parked",
        holding_time("2026-08-31T12:01:02Z"),
        None,
    );
    assert!(store
        .wake_provider_dispatch(
            "run-holding-store",
            "work-a",
            &attempt.attempt_id,
            "wake-fallback-forbidden",
            "dispatch-fallback-forbidden",
            "adapter-process-fallback-forbidden",
            "session-fallback-forbidden",
            1,
            parked.provider_retry_after.unwrap(),
        )
        .is_err());
}

#[test]
fn holding_indeterminate_requires_exact_reconciliation_before_redispatch() {
    let (_directory, _path, store, _packet, _admission, _profile, policy, requirement) =
        holding_setup();
    let (attempt, opened) = holding_open_initial(&store);
    let indeterminate = holding_record(
        &store,
        &requirement,
        &policy,
        &opened,
        "indeterminate",
        holding_time("2026-08-31T12:01:02Z"),
        None,
    );
    assert_eq!(
        indeterminate.mechanism_state,
        ProviderMechanismStateV1::AdmissionIndeterminate
    );
    assert!(store
        .wake_provider_dispatch(
            "run-holding-store",
            "work-a",
            &attempt.attempt_id,
            "wake-before-reconcile",
            "dispatch-before-reconcile",
            "adapter-process-before-reconcile",
            "session-before-reconcile",
            0,
            holding_time("2026-08-31T12:01:10Z"),
        )
        .is_err());
    let parked = holding_record(
        &store,
        &requirement,
        &policy,
        &opened,
        "parked",
        holding_time("2026-08-31T12:01:03Z"),
        Some(&indeterminate.disposition_digest),
    );
    assert_eq!(
        parked.mechanism_state,
        ProviderMechanismStateV1::ParkedNotAdmitted
    );
    assert!(
        holding_disposition(
            &requirement,
            &opened,
            "parked",
            holding_time("2026-08-31T12:01:04Z"),
        )
        .1
        .disposition_digest
            != indeterminate.disposition_digest
    );
}

#[test]
fn holding_post_admission_restart_resumes_only_exact_execution() {
    let (_directory, path, store, _packet, _admission, _profile, policy, requirement) =
        holding_setup();
    let (attempt, opened) = holding_open_initial(&store);
    let interrupted = holding_record(
        &store,
        &requirement,
        &policy,
        &opened,
        "interrupted",
        holding_time("2026-08-31T12:01:02Z"),
        None,
    );
    assert_eq!(
        interrupted.mechanism_state,
        ProviderMechanismStateV1::PostAdmissionInterrupted
    );
    assert!(store
        .wake_provider_dispatch(
            "run-holding-store",
            "work-a",
            &attempt.attempt_id,
            "wake-post-admission",
            "dispatch-post-admission",
            "adapter-process-post-admission",
            "session-post-admission",
            1,
            holding_time("2026-08-31T12:01:20Z"),
        )
        .is_err());
    drop(store);
    let restarted = ForemanStore::open(&path).unwrap();
    let execution = interrupted.provider_execution.clone().unwrap();
    restarted
        .resume_provider_execution(
            "run-holding-store",
            "work-a",
            &attempt.attempt_id,
            "resume-store-1",
            &interrupted.disposition_digest,
            "adapter-process-resume-1",
            &execution,
            holding_time("2026-08-31T12:01:10Z"),
        )
        .unwrap();
    assert!(restarted
        .resume_provider_execution(
            "run-holding-store",
            "work-a",
            &attempt.attempt_id,
            "resume-store-1",
            &interrupted.disposition_digest,
            "adapter-process-resume-1",
            &execution,
            holding_time("2026-08-31T12:01:11Z"),
        )
        .is_err());
    assert!(restarted
        .resume_provider_execution(
            "run-holding-store",
            "work-a",
            &attempt.attempt_id,
            "resume-store-fresh-duplicate",
            &interrupted.disposition_digest,
            "adapter-process-resume-fresh-duplicate",
            &execution,
            holding_time("2026-08-31T12:01:11Z"),
        )
        .is_err());
    restarted
        .resume_provider_execution(
            "run-holding-store",
            "work-a",
            &attempt.attempt_id,
            "resume-store-1",
            &interrupted.disposition_digest,
            "adapter-process-resume-1",
            &execution,
            holding_time("2026-08-31T12:01:10Z"),
        )
        .unwrap();
    let mut substituted = execution.clone();
    substituted.turn_id = "turn-substituted".to_owned();
    assert!(restarted
        .resume_provider_execution(
            "run-holding-store",
            "work-a",
            &attempt.attempt_id,
            "resume-store-2",
            &interrupted.disposition_digest,
            "adapter-process-resume-2",
            &substituted,
            holding_time("2026-08-31T12:01:11Z"),
        )
        .is_err());
    let projection = restarted.projection("run-holding-store").unwrap();
    assert_eq!(
        projection
            .work_items
            .iter()
            .find(|item| item.work_item_id == "work-a")
            .unwrap()
            .scheduler_state,
        SchedulerStateV1::Dispatching
    );
}

#[test]
fn holding_fresh_dispatch_refuses_reused_process_or_session_identity_globally() {
    let (_directory, _path, store, _packet, _admission, _profile, _policy, _requirement) =
        holding_setup();
    let (_attempt, _opened) = holding_open_initial(&store);
    assert!(store
        .prepare_provider_attempt(
            "run-holding-store",
            "work-b",
            "dispatch-reused-process",
            "adapter-process-store-1",
            "session-distinct",
            0,
            holding_time("2026-08-31T12:01:01Z"),
        )
        .is_err());
    assert!(store
        .prepare_provider_attempt(
            "run-holding-store",
            "work-b",
            "dispatch-reused-session",
            "adapter-process-distinct",
            "session-store-1",
            0,
            holding_time("2026-08-31T12:01:01Z"),
        )
        .is_err());
    let snapshot = store.projection("run-holding-store").unwrap();
    assert!(snapshot
        .work_items
        .iter()
        .find(|item| item.work_item_id == "work-b")
        .unwrap()
        .active_attempt_id
        .is_none());
}

#[test]
fn holding_concurrent_writers_converge_on_one_wake_and_dispatch() {
    let (_directory, path, store, _packet, _admission, _profile, policy, requirement) =
        holding_setup();
    let (attempt, opened) = holding_open_initial(&store);
    let parked = holding_record(
        &store,
        &requirement,
        &policy,
        &opened,
        "parked",
        holding_time("2026-08-31T12:01:02Z"),
        None,
    );
    drop(store);
    let barrier = Arc::new(Barrier::new(2));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        let attempt_id = attempt.attempt_id.clone();
        let wake_at = parked.provider_retry_after.unwrap();
        workers.push(std::thread::spawn(move || {
            let store = ForemanStore::open(path).unwrap();
            barrier.wait();
            store.wake_provider_dispatch(
                "run-holding-store",
                "work-a",
                &attempt_id,
                "wake-concurrent-1",
                "dispatch-concurrent-2",
                "adapter-process-concurrent-2",
                "session-concurrent-2",
                1,
                wake_at,
            )
        }));
    }
    let first = workers.remove(0).join().unwrap().unwrap();
    let second = workers.remove(0).join().unwrap().unwrap();
    assert_eq!(first, second);
    let query = ForemanStore::open_read_only(&path).unwrap();
    let snapshot = query.read_only_run_snapshot("run-holding-store").unwrap();
    let history = snapshot.execution_availability.unwrap();
    assert_eq!(history.wake_occurrence_ids.len(), 1);
    assert_eq!(history.dispatches.len(), 2);
}

#[test]
fn holding_failed_wake_rolls_back_lock_reacquisition_and_restart_recovers() {
    let (_directory, path, store, _packet, _admission, _profile, policy, requirement) =
        holding_setup();
    let (attempt, opened) = holding_open_initial(&store);
    let parked = holding_record(
        &store,
        &requirement,
        &policy,
        &opened,
        "parked",
        holding_time("2026-08-31T12:01:02Z"),
        None,
    );
    let wake_at = parked.provider_retry_after.unwrap();
    let fault = Connection::open(&path).unwrap();
    fault
        .execute_batch(
            "CREATE TRIGGER fixture_refuse_dispatch_after_wake
             BEFORE INSERT ON events
             WHEN NEW.event_id = 'provider-dispatch-dispatch-rolled-back'
             BEGIN SELECT RAISE(ABORT, 'fixture crash after wake before dispatch append'); END;",
        )
        .unwrap();
    drop(fault);
    assert!(store
        .wake_provider_dispatch(
            "run-holding-store",
            "work-a",
            &attempt.attempt_id,
            "wake-rolled-back",
            "dispatch-rolled-back",
            "adapter-process-rolled-back",
            "session-rolled-back",
            1,
            wake_at,
        )
        .is_err());
    drop(store);
    let fault = Connection::open(&path).unwrap();
    fault
        .execute_batch("DROP TRIGGER fixture_refuse_dispatch_after_wake;")
        .unwrap();
    drop(fault);
    let restarted = ForemanStore::open(&path).unwrap();
    let opened = restarted
        .wake_provider_dispatch(
            "run-holding-store",
            "work-a",
            &attempt.attempt_id,
            "wake-after-rollback",
            "dispatch-after-rollback",
            "adapter-process-after-rollback",
            "session-after-rollback",
            1,
            wake_at,
        )
        .unwrap();
    assert_eq!(opened.dispatch.dispatch_ordinal, 2);
    let snapshot = ForemanStore::open_read_only(&path)
        .unwrap()
        .read_only_run_snapshot("run-holding-store")
        .unwrap();
    let history = snapshot.execution_availability.unwrap();
    assert_eq!(history.wake_occurrence_ids, vec!["wake-after-rollback"]);
}

#[test]
fn holding_failed_initial_dispatch_rolls_back_attempt_and_lock_then_restart_recovers() {
    let (_directory, path, store, _packet, _admission, _profile, _policy, _requirement) =
        holding_setup();
    assert!(store
        .prepare_provider_attempt(
            "run-holding-store",
            "work-a",
            "dispatch-initial-rolled-back",
            "adapter-process-initial-rolled-back",
            "invalid session identity",
            0,
            holding_time("2026-08-31T12:01:00Z"),
        )
        .is_err());
    drop(store);

    let connection = Connection::open(&path).unwrap();
    let attempt_events: u64 = connection
        .query_row(
            "SELECT count(*) FROM events WHERE attempt_id IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let resource_claims: u64 = connection
        .query_row("SELECT count(*) FROM resource_claims", [], |row| row.get(0))
        .unwrap();
    assert_eq!(attempt_events, 0);
    assert_eq!(resource_claims, 0);
    drop(connection);

    let restarted = ForemanStore::open(&path).unwrap();
    let opened = restarted
        .prepare_provider_attempt(
            "run-holding-store",
            "work-a",
            "dispatch-initial-after-rollback",
            "adapter-process-initial-after-rollback",
            "session-initial-after-rollback",
            0,
            holding_time("2026-08-31T12:01:01Z"),
        )
        .unwrap();
    assert_eq!(opened.dispatch.dispatch_ordinal, 1);
    let snapshot = ForemanStore::open_read_only(&path)
        .unwrap()
        .read_only_run_snapshot("run-holding-store")
        .unwrap();
    let history = snapshot.execution_availability.unwrap();
    assert_eq!(history.dispatches, vec![opened.dispatch]);
}

#[test]
fn holding_unanswered_approval_preserves_exact_interruption_without_redispatch() {
    let (_directory, path, store, _packet, _admission, _profile, policy, requirement) =
        holding_setup();
    let (attempt, opened) = holding_open_initial(&store);
    let approval = holding_record(
        &store,
        &requirement,
        &policy,
        &opened,
        "waiting",
        holding_time("2026-08-31T12:01:02Z"),
        None,
    );
    assert_eq!(
        approval.mechanism_state,
        ProviderMechanismStateV1::WaitingApproval
    );
    assert!(!approval.approval_response_sent);
    assert!(approval.protected_effect_absent);
    assert!(store
        .wake_provider_dispatch(
            "run-holding-store",
            "work-a",
            &attempt.attempt_id,
            "wake-approval",
            "dispatch-approval",
            "adapter-process-approval",
            "session-approval",
            1,
            holding_time("2026-08-31T12:01:20Z"),
        )
        .is_err());
    let execution = approval.provider_execution.as_ref().unwrap();
    assert!(store
        .resume_provider_execution(
            "run-holding-store",
            "work-a",
            &attempt.attempt_id,
            "resume-approval",
            &approval.disposition_digest,
            "adapter-process-resume-approval",
            execution,
            holding_time("2026-08-31T12:01:20Z"),
        )
        .is_err());
    let projection = store.projection("run-holding-store").unwrap();
    assert_eq!(
        projection
            .work_items
            .iter()
            .find(|item| item.work_item_id == "work-a")
            .unwrap()
            .scheduler_state,
        SchedulerStateV1::WaitingApproval
    );
    assert_holding_generic_transitions_refuse_without_mutation(
        &path,
        &store,
        &attempt,
        "waiting approval",
    );
}

#[test]
fn holding_metadata_preflight_refuses_huge_event_before_raw_materialization() {
    let (_directory, path, store, _packet, _admission, profile, _policy, _requirement) =
        holding_setup();
    let (_attempt, _opened) = holding_open_initial(&store);
    drop(store);

    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch("DROP TRIGGER events_no_update;")
        .unwrap();
    connection
        .execute(
            "UPDATE events SET kind = 'internal', raw_bytes = zeroblob(?1)
             WHERE kind = 'provider_dispatch'",
            [profile.maximum_event_bytes + 1],
        )
        .unwrap();
    drop(connection);

    let store = ForemanStore::open(&path).unwrap();
    assert!(matches!(
        store.projection("run-holding-store"),
        Err(ForemanError::InputTooLarge(
            "execution availability journal event"
        ))
    ));
    drop(store);
    assert!(matches!(
        read_only_run_snapshot(&path, "run-holding-store"),
        Err(ForemanError::InputTooLarge(
            "execution availability journal event"
        ))
    ));
}

#[test]
fn holding_metadata_refuses_small_provider_row_kind_alias_and_lock_table_discrepancy() {
    {
        let (_directory, path, store, _packet, _admission, _profile, _policy, _requirement) =
            holding_setup();
        let (_attempt, _opened) = holding_open_initial(&store);
        drop(store);
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER events_no_update;
                 UPDATE events SET kind = 'internal' WHERE kind = 'provider_dispatch';",
            )
            .unwrap();
        drop(connection);
        assert!(matches!(
            ForemanStore::open(&path)
                .unwrap()
                .projection("run-holding-store"),
            Err(ForemanError::ReadOnlyStore(message))
                if message.contains("metadata/event identity mismatch")
        ));
    }

    {
        let (_directory, path, store, _packet, _admission, _profile, _policy, _requirement) =
            holding_setup();
        let (_attempt, _opened) = holding_open_initial(&store);
        drop(store);
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "DELETE FROM resource_claims WHERE run_id = 'run-holding-store'",
                [],
            )
            .unwrap();
        drop(connection);
        assert!(matches!(
            read_only_run_snapshot(&path, "run-holding-store"),
            Err(ForemanError::ReadOnlyStore(message))
                if message.contains("mutable resource claims disagree")
        ));
    }
}

#[test]
fn holding_metadata_preflight_refuses_cumulative_history_before_raw_materialization() {
    let (_directory, path, store, _packet, _admission, profile, _policy, _requirement) =
        holding_setup();
    drop(store);

    let connection = Connection::open(&path).unwrap();
    let row_bytes = profile.maximum_event_bytes;
    for ordinal in 0..17_u32 {
        connection
            .execute(
                "INSERT INTO events
                 (event_id, run_id, work_item_id, attempt_id, kind, recorded_at, raw_bytes, raw_digest)
                 VALUES (?1, 'run-holding-store', 'work-a', 'attempt-bound-fixture',
                         'provider_wake', ?2, zeroblob(?3), ?4)",
                rusqlite::params![
                    format!("provider-wake-bound-{ordinal}"),
                    holding_time("2026-08-31T12:01:00Z").to_rfc3339(),
                    row_bytes,
                    format!("sha256:{}", "0".repeat(64)),
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO execution_availability_event_metadata
                 (run_id, event_id, sequence, event_kind, raw_byte_length)
                 SELECT run_id, event_id, sequence, kind, length(raw_bytes)
                 FROM events WHERE event_id = ?1",
                [format!("provider-wake-bound-{ordinal}")],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO execution_availability_event_anchors
                 (run_id, event_id, sequence)
                 SELECT run_id, event_id, sequence
                 FROM events WHERE event_id = ?1",
                [format!("provider-wake-bound-{ordinal}")],
            )
            .unwrap();
    }
    let retained: u64 = connection
        .query_row(
            "SELECT sum(length(raw_bytes)) FROM events
             WHERE kind IN (
                 'execution_availability_requirement', 'provider_dispatch',
                 'provider_disposition', 'provider_wake', 'provider_resume'
             )",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(retained > 16 * 1024 * 1024);
    drop(connection);

    let store = ForemanStore::open(&path).unwrap();
    assert!(matches!(
        store.projection("run-holding-store"),
        Err(ForemanError::InputTooLarge(
            "execution availability journal history"
        ))
    ));
    drop(store);
    assert!(matches!(
        read_only_run_snapshot(&path, "run-holding-store"),
        Err(ForemanError::InputTooLarge(
            "execution availability journal history"
        ))
    ));
}

#[test]
fn holding_restart_refuses_coherently_resealed_nested_dispatch_substitution() {
    let (_directory, path, store, _packet, _admission, _profile, _policy, _requirement) =
        holding_setup();
    let (_attempt, _opened) = holding_open_initial(&store);
    drop(store);

    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch("DROP TRIGGER events_no_update;")
        .unwrap();
    let raw: Vec<u8> = connection
        .query_row(
            "SELECT raw_bytes FROM events WHERE kind = 'provider_dispatch'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let mut event: Value = serde_json::from_slice(&raw).unwrap();
    let mut start: WorkerStartRequestV3 =
        serde_json::from_value(event["payload"]["start_request"].clone()).unwrap();
    start.provider_id = "substituted-provider".to_owned();
    start.seal().unwrap();
    let start_bytes = serde_jcs::to_vec(&start).unwrap();
    let mut dispatch: ProviderDispatchOccurrenceV1 =
        serde_json::from_value(event["payload"]["dispatch"].clone()).unwrap();
    dispatch.selection.provider_id = start.provider_id.clone();
    dispatch.worker_start_request_digest = start.request_digest.clone();
    dispatch.seal().unwrap();
    let dispatch_bytes = serde_jcs::to_vec(&dispatch).unwrap();
    event["payload"]["start_request"] = serde_json::to_value(&start).unwrap();
    event["payload"]["start_request_bytes"] = serde_json::to_value(start_bytes).unwrap();
    event["payload"]["dispatch"] = serde_json::to_value(&dispatch).unwrap();
    event["payload"]["dispatch_bytes"] = serde_json::to_value(dispatch_bytes).unwrap();
    let substituted = serde_jcs::to_vec(&event).unwrap();
    connection
        .execute(
            "UPDATE events SET raw_bytes = ?1, raw_digest = ?2
             WHERE kind = 'provider_dispatch'",
            rusqlite::params![substituted, retained_raw_digest(&substituted)],
        )
        .unwrap();
    drop(connection);

    let store = ForemanStore::open(&path).unwrap();
    assert!(store.projection("run-holding-store").is_err());
    drop(store);
    assert!(read_only_run_snapshot(&path, "run-holding-store").is_err());
}

fn holding_reseal_internal_event_row(
    connection: &Connection,
    kind: &str,
    mutate: impl FnOnce(&mut Value),
) {
    connection
        .execute_batch(
            "DROP TRIGGER events_no_update;
             DROP TRIGGER execution_availability_metadata_no_update;
             DROP TRIGGER execution_availability_anchors_no_update;",
        )
        .unwrap();
    let (sequence, raw): (u64, Vec<u8>) = connection
        .query_row(
            "SELECT sequence, raw_bytes FROM events WHERE kind = ?1 ORDER BY sequence DESC LIMIT 1",
            [kind],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let mut event: Value = serde_json::from_slice(&raw).unwrap();
    mutate(&mut event);
    let event_id = event["event_id"].as_str().unwrap().to_owned();
    let raw = serde_jcs::to_vec(&event).unwrap();
    connection
        .execute(
            "UPDATE events SET event_id = ?1, raw_bytes = ?2, raw_digest = ?3
             WHERE sequence = ?4",
            rusqlite::params![event_id, raw, retained_raw_digest(&raw), sequence],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE execution_availability_event_metadata
             SET event_id = ?1, raw_byte_length = ?2 WHERE sequence = ?3",
            rusqlite::params![event_id, raw.len(), sequence],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE execution_availability_event_anchors
             SET event_id = ?1 WHERE sequence = ?2",
            rusqlite::params![event_id, sequence],
        )
        .unwrap();
}

#[test]
fn holding_every_mutator_refuses_malformed_history_before_append() {
    let (_directory, path, store, _packet, _admission, _profile, _policy, _requirement) =
        holding_setup();
    let (attempt, _opened) = holding_open_initial(&store);
    drop(store);

    let connection = Connection::open(&path).unwrap();
    holding_reseal_internal_event_row(&connection, "provider_dispatch", |event| {
        event["event_id"] = Value::String("provider-dispatch-substituted".to_owned());
    });
    let before: u64 = connection
        .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
        .unwrap();
    drop(connection);

    let store = ForemanStore::open(&path).unwrap();
    assert!(store
        .record_dispatch_requested(
            "run-holding-store",
            "work-a",
            &attempt.attempt_id,
            holding_time("2026-08-31T12:01:02Z"),
        )
        .is_err());
    assert!(store
        .record_terminal_refusal(
            "run-holding-store",
            "work-a",
            &attempt.attempt_id,
            "deterministic fixture refusal",
            holding_time("2026-08-31T12:01:03Z"),
        )
        .is_err());
    drop(store);
    let connection = Connection::open(&path).unwrap();
    let after: u64 = connection
        .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(before, after);
}

#[test]
fn holding_resource_history_substitution_and_missing_atomic_dispatch_refuse_on_restart() {
    {
        let (_directory, path, store, _packet, _admission, _profile, policy, requirement) =
            holding_setup();
        let (_attempt, opened) = holding_open_initial(&store);
        holding_record(
            &store,
            &requirement,
            &policy,
            &opened,
            "parked",
            holding_time("2026-08-31T12:01:02Z"),
            None,
        );
        drop(store);
        let connection = Connection::open(&path).unwrap();
        holding_reseal_internal_event_row(&connection, "provider_resources_released", |event| {
            event["payload"]["resource_lock_keys"] = json!(["provider-slot-substituted"]);
        });
        drop(connection);
        assert!(read_only_run_snapshot(&path, "run-holding-store").is_err());
    }

    {
        let (_directory, path, store, _packet, _admission, _profile, policy, requirement) =
            holding_setup();
        let (attempt, opened) = holding_open_initial(&store);
        let parked = holding_record(
            &store,
            &requirement,
            &policy,
            &opened,
            "parked",
            holding_time("2026-08-31T12:01:02Z"),
            None,
        );
        store
            .wake_provider_dispatch(
                "run-holding-store",
                "work-a",
                &attempt.attempt_id,
                "wake-missing-dispatch",
                "dispatch-missing-after-wake",
                "adapter-process-missing-after-wake",
                "session-missing-after-wake",
                1,
                parked.provider_retry_after.unwrap(),
            )
            .unwrap();
        drop(store);
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER events_no_delete;
                 DROP TRIGGER execution_availability_metadata_no_delete;
                 DROP TRIGGER execution_availability_anchors_no_delete;
                 DELETE FROM execution_availability_event_anchors
                 WHERE event_id = 'provider-dispatch-dispatch-missing-after-wake';
                 DELETE FROM execution_availability_event_metadata
                 WHERE event_id = 'provider-dispatch-dispatch-missing-after-wake';
                 DELETE FROM events
                 WHERE event_id = 'provider-dispatch-dispatch-missing-after-wake';",
            )
            .unwrap();
        drop(connection);
        assert!(matches!(
            read_only_run_snapshot(&path, "run-holding-store"),
            Err(ForemanError::ReadOnlyStore(message))
                if message.contains("resource reacquisition or wake lacks atomic successor")
        ));
    }
}

#[test]
fn holding_indeterminate_reconciliation_can_only_retain_exact_admitted_execution_or_stop() {
    {
        let (_directory, _path, store, _packet, _admission, _profile, policy, requirement) =
            holding_setup();
        let (attempt, opened) = holding_open_initial(&store);
        let indeterminate = holding_record(
            &store,
            &requirement,
            &policy,
            &opened,
            "indeterminate",
            holding_time("2026-08-31T12:01:02Z"),
            None,
        );
        let interrupted = holding_record(
            &store,
            &requirement,
            &policy,
            &opened,
            "interrupted",
            holding_time("2026-08-31T12:01:03Z"),
            Some(&indeterminate.disposition_digest),
        );
        assert_eq!(
            interrupted.mechanism_state,
            ProviderMechanismStateV1::PostAdmissionInterrupted
        );
        assert!(store
            .wake_provider_dispatch(
                "run-holding-store",
                "work-a",
                &attempt.attempt_id,
                "wake-after-admitted-reconciliation",
                "dispatch-after-admitted-reconciliation",
                "adapter-process-after-admitted-reconciliation",
                "session-after-admitted-reconciliation",
                1,
                holding_time("2026-08-31T12:01:20Z"),
            )
            .is_err());
        let execution = interrupted.provider_execution.clone().unwrap();
        store
            .resume_provider_execution(
                "run-holding-store",
                "work-a",
                &attempt.attempt_id,
                "resume-after-reconciliation",
                &interrupted.disposition_digest,
                "adapter-process-resume-after-reconciliation",
                &execution,
                holding_time("2026-08-31T12:01:20Z"),
            )
            .unwrap();
    }

    {
        let (_directory, _path, store, _packet, _admission, _profile, policy, requirement) =
            holding_setup();
        let (attempt, opened) = holding_open_initial(&store);
        let first = holding_record(
            &store,
            &requirement,
            &policy,
            &opened,
            "indeterminate",
            holding_time("2026-08-31T12:01:02Z"),
            None,
        );
        let second = holding_record(
            &store,
            &requirement,
            &policy,
            &opened,
            "indeterminate",
            holding_time("2026-08-31T12:01:03Z"),
            Some(&first.disposition_digest),
        );
        assert_eq!(
            second.mechanism_state,
            ProviderMechanismStateV1::AdmissionIndeterminate
        );
        assert!(store
            .wake_provider_dispatch(
                "run-holding-store",
                "work-a",
                &attempt.attempt_id,
                "wake-after-indeterminate-reconciliation",
                "dispatch-after-indeterminate-reconciliation",
                "adapter-process-after-indeterminate-reconciliation",
                "session-after-indeterminate-reconciliation",
                0,
                holding_time("2026-08-31T12:01:20Z"),
            )
            .is_err());
    }
}

#[test]
fn holding_dispatch_occurrence_bound_stops_repeated_refusal_without_hammering() {
    let (directory, path, packet, admission, profile, mut policy, _) = holding_fixture_contracts();
    policy.maximum_dispatch_occurrences_per_attempt = 2;
    policy.backoff_seconds = vec![5, 10];
    policy.maximum_total_deferral_seconds = 20;
    policy.seal().unwrap();
    let requirement = holding_requirement(&packet, &admission, &profile, &policy);
    let store = ForemanStore::open(&path).unwrap();
    store
        .admit_with_execution_availability(
            &packet.canonical_bytes().unwrap(),
            &holding_canonical(&admission),
            &holding_canonical(&profile),
            &holding_canonical(&requirement),
            &holding_canonical(&policy),
            admission.admitted_at,
        )
        .unwrap();
    let (attempt, first) = holding_open_initial(&store);
    let first_park = holding_record(
        &store,
        &requirement,
        &policy,
        &first,
        "parked",
        holding_time("2026-08-31T12:01:02Z"),
        None,
    );
    let second = store
        .wake_provider_dispatch(
            "run-holding-store",
            "work-a",
            &attempt.attempt_id,
            "wake-bounded-2",
            "dispatch-bounded-2",
            "adapter-process-bounded-2",
            "session-bounded-2",
            1,
            first_park.provider_retry_after.unwrap(),
        )
        .unwrap();
    let second_park = holding_record(
        &store,
        &requirement,
        &policy,
        &second,
        "parked",
        holding_time("2026-08-31T12:01:08Z"),
        None,
    );
    assert!(store
        .wake_provider_dispatch(
            "run-holding-store",
            "work-a",
            &attempt.attempt_id,
            "wake-bounded-refused",
            "dispatch-bounded-refused",
            "adapter-process-bounded-refused",
            "session-bounded-refused",
            1,
            second_park.provider_retry_after.unwrap(),
        )
        .is_err());
    let history = read_only_run_snapshot(&path, "run-holding-store")
        .unwrap()
        .execution_availability
        .unwrap();
    assert_eq!(history.dispatches.len(), 2);
    assert_eq!(history.wake_occurrence_ids, vec!["wake-bounded-2"]);
    drop(directory);
}

#[test]
fn holding_resource_event_ids_are_domain_derived_in_query_and_mutating_paths() {
    {
        let (_directory, path, store, _packet, _admission, _profile, policy, requirement) =
            holding_setup();
        let (attempt, opened) = holding_open_initial(&store);
        holding_record(
            &store,
            &requirement,
            &policy,
            &opened,
            "parked",
            holding_time("2026-08-31T12:01:02Z"),
            None,
        );
        drop(store);
        let connection = Connection::open(&path).unwrap();
        holding_reseal_internal_event_row(&connection, "provider_resources_released", |event| {
            event["event_id"] = Value::String("provider-resources-released-substituted".to_owned());
        });
        let before: u64 = connection
            .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
            .unwrap();
        drop(connection);
        assert!(matches!(
            read_only_run_snapshot(&path, "run-holding-store"),
            Err(ForemanError::ReadOnlyStore(message))
                if message.contains("provider resource release binding mismatch")
        ));
        let store = ForemanStore::open(&path).unwrap();
        assert!(store
            .record_terminal_refusal(
                "run-holding-store",
                "work-a",
                &attempt.attempt_id,
                "resource event identity substitution",
                holding_time("2026-08-31T12:01:03Z"),
            )
            .is_err());
        drop(store);
        let connection = Connection::open(&path).unwrap();
        let after: u64 = connection
            .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(before, after);
    }

    {
        let (_directory, path, store, _packet, _admission, _profile, policy, requirement) =
            holding_setup();
        let (attempt, opened) = holding_open_initial(&store);
        let parked = holding_record(
            &store,
            &requirement,
            &policy,
            &opened,
            "parked",
            holding_time("2026-08-31T12:01:02Z"),
            None,
        );
        store
            .wake_provider_dispatch(
                "run-holding-store",
                "work-a",
                &attempt.attempt_id,
                "wake-resource-event-id",
                "dispatch-resource-event-id",
                "adapter-process-resource-event-id",
                "session-resource-event-id",
                1,
                parked.provider_retry_after.unwrap(),
            )
            .unwrap();
        drop(store);
        let connection = Connection::open(&path).unwrap();
        holding_reseal_internal_event_row(&connection, "provider_resources_reacquired", |event| {
            event["event_id"] =
                Value::String("provider-resources-reacquired-substituted".to_owned());
        });
        let before: u64 = connection
            .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
            .unwrap();
        drop(connection);
        assert!(matches!(
            read_only_run_snapshot(&path, "run-holding-store"),
            Err(ForemanError::ReadOnlyStore(message))
                if message.contains("provider resource reacquisition binding mismatch")
        ));
        let store = ForemanStore::open(&path).unwrap();
        assert!(store
            .record_dispatch_requested(
                "run-holding-store",
                "work-a",
                &attempt.attempt_id,
                holding_time("2026-08-31T12:01:04Z"),
            )
            .is_err());
        drop(store);
        let connection = Connection::open(&path).unwrap();
        let after: u64 = connection
            .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(before, after);
    }
}

fn holding_worker_started_event(
    packet: &NightshiftPacketV1,
    attempt: &WorkerStartRequestV2,
    event_id: &str,
) -> AdapterEventV1 {
    let mut event = AdapterEventV1 {
        schema: WORKER_ADAPTER_EVENT_SCHEMA_V1.to_owned(),
        event_digest: holding_placeholder(),
        event_id: event_id.to_owned(),
        packet_digest: packet.packet_digest.clone(),
        run_id: attempt.run_id.clone(),
        work_item_id: attempt.work_item_id.clone(),
        attempt_id: attempt.attempt_id.clone(),
        adapter_id: attempt.adapter_id.clone(),
        adapter_version: attempt.adapter_version.clone(),
        occurred_at: holding_time("2026-08-31T12:01:03Z"),
        kind: AdapterEventKindV1::WorkerStarted,
        provider_identity: None,
        model_identity: None,
        session_identity: None,
        thread_identity: None,
        turn_identity: None,
        queue_identity: None,
        message: None,
        human_question: None,
        extensions: BTreeMap::new(),
    };
    event.seal().unwrap();
    event
}

fn holding_adapter_event_for_kind(
    packet: &NightshiftPacketV1,
    attempt: &WorkerStartRequestV2,
    event_id: &str,
    kind: AdapterEventKindV1,
) -> AdapterEventV1 {
    let is_question = matches!(&kind, AdapterEventKindV1::HumanQuestion);
    let mut event = holding_worker_started_event(packet, attempt, event_id);
    event.kind = kind;
    event.message = Some("qualification event must not override owner state".to_owned());
    event.human_question = is_question.then(|| HumanQuestionV1 {
        question_id: format!("question-{event_id}"),
        question: "Which exact owner disposition permits this transition?".to_owned(),
        exhausted_evidence: "No such owner disposition is retained.".to_owned(),
        safe_default: "Do not mutate the HOLDING lane.".to_owned(),
        consequences: "The exact provider mechanism state is preserved.".to_owned(),
        resume_point: "Resume only through an exact owner transition.".to_owned(),
    });
    event.seal().unwrap();
    event
}

fn holding_event_count(path: &Path) -> u64 {
    Connection::open(path)
        .unwrap()
        .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
        .unwrap()
}

#[test]
fn holding_every_adapter_event_kind_refuses_before_and_against_owner_state_without_mutation() {
    for stage in [
        "before-disposition",
        "waiting-approval",
        "provider-completed",
    ] {
        let (_directory, path, store, packet, _admission, _profile, policy, requirement) =
            holding_setup();
        let (attempt, opened) = holding_open_initial(&store);
        match stage {
            "before-disposition" => {}
            "waiting-approval" => {
                holding_record(
                    &store,
                    &requirement,
                    &policy,
                    &opened,
                    "waiting",
                    holding_time("2026-08-31T12:01:02Z"),
                    None,
                );
            }
            "provider-completed" => {
                holding_record(
                    &store,
                    &requirement,
                    &policy,
                    &opened,
                    "completed",
                    holding_time("2026-08-31T12:01:02Z"),
                    None,
                );
            }
            _ => unreachable!(),
        }
        let expected_projection = store.projection("run-holding-store").unwrap();
        let expected_event_count = holding_event_count(&path);
        for (ordinal, kind) in [
            AdapterEventKindV1::AdapterAccepted,
            AdapterEventKindV1::ProviderIdentity,
            AdapterEventKindV1::WorkerStarted,
            AdapterEventKindV1::Checkpoint,
            AdapterEventKindV1::WaitingApproval,
            AdapterEventKindV1::HumanQuestion,
            AdapterEventKindV1::ProviderCompletionObservation,
            AdapterEventKindV1::AdapterDiagnostic,
            AdapterEventKindV1::MechanismIndeterminate,
        ]
        .into_iter()
        .enumerate()
        {
            let event = holding_adapter_event_for_kind(
                &packet,
                &attempt,
                &format!("holding-{stage}-{ordinal}"),
                kind,
            );
            assert!(matches!(
                store.accept_adapter_event(&holding_canonical(&event)),
                Err(ForemanError::Transition(message))
                    if message.contains("only through exact owner dispositions")
            ));
            assert_eq!(holding_event_count(&path), expected_event_count);
            assert_eq!(
                store.projection("run-holding-store").unwrap(),
                expected_projection
            );
        }
    }
}

fn holding_terminal_receipt(
    packet: &NightshiftPacketV1,
    attempt: &WorkerStartRequestV2,
    execution: Option<&ProviderExecutionIdentityV1>,
) -> TerminalReceiptV1 {
    let mut receipt = terminal(packet, attempt, "EXACT-STATE", "EXACT-CLASSIFICATION");
    receipt.adapter_id = attempt.adapter_id.clone();
    receipt.adapter_version = attempt.adapter_version.clone();
    receipt.provider_identity = execution
        .map(|value| value.provider_id.clone())
        .unwrap_or_else(|| "openai".to_owned());
    receipt.model_identity = execution
        .map(|value| value.model_id.clone())
        .unwrap_or_else(|| "gpt-5.6-sol".to_owned());
    receipt.session_identity = execution.map(|value| value.app_server_session_identity.clone());
    receipt.thread_identity = execution.map(|value| value.thread_id.clone());
    receipt.turn_identity = execution.map(|value| value.turn_id.clone());
    receipt.queue_identity = None;
    receipt.started_at = holding_time("2026-08-31T12:01:00Z");
    receipt.ended_at = holding_time("2026-08-31T12:01:10Z");
    receipt.seal().unwrap();
    receipt
}

fn assert_holding_generic_transitions_refuse_without_mutation(
    path: &Path,
    store: &ForemanStore,
    attempt: &WorkerStartRequestV2,
    reason: &str,
) {
    let before = fs::read(path).unwrap();
    assert!(store
        .record_dispatch_requested(
            "run-holding-store",
            "work-a",
            &attempt.attempt_id,
            holding_time("2026-08-31T12:01:30Z"),
        )
        .is_err());
    assert!(store
        .record_resume_requested(
            "run-holding-store",
            "work-a",
            &attempt.attempt_id,
            holding_time("2026-08-31T12:01:30Z"),
        )
        .is_err());
    assert!(store
        .record_terminal_refusal(
            "run-holding-store",
            "work-a",
            &attempt.attempt_id,
            reason,
            holding_time("2026-08-31T12:01:30Z"),
        )
        .is_err());
    assert_eq!(fs::read(path).unwrap(), before);
}

#[test]
fn holding_all_mechanism_states_refuse_every_generic_transition_without_mutation() {
    for snapshot_name in ["parked", "indeterminate", "interrupted", "completed"] {
        let (_directory, path, store, _packet, _admission, _profile, policy, requirement) =
            holding_setup();
        let (attempt, opened) = holding_open_initial(&store);
        holding_record(
            &store,
            &requirement,
            &policy,
            &opened,
            snapshot_name,
            holding_time("2026-08-31T12:01:02Z"),
            None,
        );
        assert_holding_generic_transitions_refuse_without_mutation(
            &path,
            &store,
            &attempt,
            snapshot_name,
        );
    }
}

#[test]
fn holding_parked_and_indeterminate_refuse_legacy_event_and_terminal_mutators_atomically() {
    for (ordinal, snapshot_name) in ["parked", "indeterminate"].into_iter().enumerate() {
        let (_directory, path, store, packet, _admission, _profile, policy, requirement) =
            holding_setup();
        let (attempt, opened) = holding_open_initial(&store);
        holding_record(
            &store,
            &requirement,
            &policy,
            &opened,
            snapshot_name,
            holding_time("2026-08-31T12:01:02Z"),
            None,
        );
        let before = fs::read(&path).unwrap();
        assert!(store
            .record_dispatch_requested(
                "run-holding-store",
                "work-a",
                &attempt.attempt_id,
                holding_time("2026-08-31T12:01:03Z"),
            )
            .is_err());
        assert!(store
            .record_resume_requested(
                "run-holding-store",
                "work-a",
                &attempt.attempt_id,
                holding_time("2026-08-31T12:01:03Z"),
            )
            .is_err());
        assert!(store
            .record_terminal_refusal(
                "run-holding-store",
                "work-a",
                &attempt.attempt_id,
                "closed HOLDING mechanism state",
                holding_time("2026-08-31T12:01:03Z"),
            )
            .is_err());
        let event = holding_worker_started_event(
            &packet,
            &attempt,
            &format!("holding-closed-worker-started-{ordinal}"),
        );
        assert!(store
            .accept_adapter_event(&holding_canonical(&event))
            .is_err());
        let receipt = holding_terminal_receipt(&packet, &attempt, None);
        assert!(store
            .accept_terminal_receipt(&holding_canonical(&receipt))
            .is_err());
        drop(store);
        assert_eq!(fs::read(&path).unwrap(), before);
        let connection = Connection::open(&path).unwrap();
        let receipts: u64 = connection
            .query_row("SELECT count(*) FROM terminal_receipts", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(receipts, 0);
    }
}

#[test]
fn holding_exact_completion_recovers_after_capacity_and_refuses_model_substitution() {
    let (_directory, path, store, packet, _admission, _profile, policy, requirement) =
        holding_setup();
    let (attempt, first) = holding_open_initial(&store);
    let parked = holding_record(
        &store,
        &requirement,
        &policy,
        &first,
        "parked",
        holding_time("2026-08-31T12:01:02Z"),
        None,
    );
    let second = store
        .wake_provider_dispatch(
            "run-holding-store",
            "work-a",
            &attempt.attempt_id,
            "wake-recovery-complete",
            "dispatch-recovery-complete",
            "adapter-process-recovery-complete",
            "session-recovery-complete",
            1,
            parked.provider_retry_after.unwrap(),
        )
        .unwrap();
    let completed = holding_record(
        &store,
        &requirement,
        &policy,
        &second,
        "completed",
        holding_time("2026-08-31T12:01:08Z"),
        None,
    );
    assert_eq!(
        completed.mechanism_state,
        ProviderMechanismStateV1::ProviderCompleted
    );
    let execution = completed.provider_execution.as_ref().unwrap();
    let mut worker_started =
        holding_worker_started_event(&packet, &attempt, "worker-after-created");
    worker_started.provider_identity = Some(execution.provider_id.clone());
    worker_started.model_identity = Some(execution.model_id.clone());
    worker_started.session_identity = Some(execution.app_server_session_identity.clone());
    worker_started.thread_identity = Some(execution.thread_id.clone());
    worker_started.turn_identity = Some(execution.turn_id.clone());
    worker_started.seal().unwrap();
    let before_event = store.projection("run-holding-store").unwrap();
    assert!(store
        .accept_adapter_event(&holding_canonical(&worker_started))
        .is_err());
    assert_eq!(store.projection("run-holding-store").unwrap(), before_event);
    let receipt = holding_terminal_receipt(&packet, &attempt, Some(execution));
    let mut substituted = receipt.clone();
    substituted.model_identity = "gpt-5.6-substituted".to_owned();
    substituted.seal().unwrap();
    assert!(matches!(
        store.accept_terminal_receipt(&holding_canonical(&substituted)),
        Err(ForemanError::IdentityMismatch("model_identity"))
    ));
    store
        .accept_terminal_receipt(&holding_canonical(&receipt))
        .unwrap();
    assert_eq!(
        store
            .projection("run-holding-store")
            .unwrap()
            .work_items
            .iter()
            .find(|item| item.work_item_id == "work-a")
            .unwrap()
            .scheduler_state,
        SchedulerStateV1::TerminalReceiptAccepted
    );
    assert_holding_generic_transitions_refuse_without_mutation(
        &path,
        &store,
        &attempt,
        "terminal HOLDING attempt",
    );
    drop(store);
    let snapshot = read_only_run_snapshot(&path, "run-holding-store").unwrap();
    assert_eq!(snapshot.terminal_receipts.len(), 1);
    assert_eq!(
        snapshot.execution_availability.unwrap().dispositions.last(),
        Some(&completed)
    );
}

#[test]
fn holding_metadata_anchor_and_table_presence_preflight_before_provider_blob_materialization() {
    {
        let (_directory, path, store, _packet, _admission, profile, _policy, _requirement) =
            holding_setup();
        let (_attempt, _opened) = holding_open_initial(&store);
        drop(store);
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER events_no_update;
                 DROP TRIGGER execution_availability_metadata_no_delete;
                 DELETE FROM execution_availability_event_metadata
                 WHERE event_kind = 'provider_dispatch';",
            )
            .unwrap();
        connection
            .execute(
                "UPDATE events SET kind = 'internal', raw_bytes = zeroblob(?1)
                 WHERE event_id = 'provider-dispatch-dispatch-store-1'",
                [profile.maximum_event_bytes + 1],
            )
            .unwrap();
        drop(connection);
        assert!(matches!(
            read_only_run_snapshot(&path, "run-holding-store"),
            Err(ForemanError::ReadOnlyStore(message))
                if message.contains("metadata/event row set mismatch")
        ));
    }

    {
        let (_directory, path, store, _packet, _admission, profile, _policy, _requirement) =
            holding_setup();
        let (_attempt, _opened) = holding_open_initial(&store);
        drop(store);
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "DROP TABLE execution_availability_event_metadata;
                 DROP TRIGGER events_no_update;",
            )
            .unwrap();
        connection
            .execute(
                "UPDATE events SET kind = 'internal', raw_bytes = zeroblob(?1)
                 WHERE event_id = 'provider-dispatch-dispatch-store-1'",
                [profile.maximum_event_bytes + 1],
            )
            .unwrap();
        drop(connection);
        let result = read_only_run_snapshot(&path, "run-holding-store");
        assert!(
            matches!(
                &result,
                Err(ForemanError::ReadOnlyStore(message))
                    if message.contains("metadata-first custody tables")
            ),
            "unexpected disposition: {result:?}"
        );
    }

    {
        let (_directory, path, store, _packet, _admission, profile, _policy, _requirement) =
            holding_setup();
        let (_attempt, _opened) = holding_open_initial(&store);
        drop(store);
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER events_no_update;
                 DROP TRIGGER execution_availability_metadata_no_delete;
                 DROP TRIGGER execution_availability_anchors_no_delete;
                 DROP TRIGGER run_mechanism_requirements_no_delete;
                 DELETE FROM execution_availability_event_metadata;
                 DELETE FROM execution_availability_event_anchors;
                 DELETE FROM run_mechanism_requirements;
                 UPDATE events SET kind = 'internal'
                 WHERE kind IN (
                     'execution_availability_requirement', 'provider_dispatch',
                     'provider_disposition', 'provider_wake', 'provider_resume',
                     'provider_resources_released', 'provider_resources_reacquired'
                 );",
            )
            .unwrap();
        connection
            .execute(
                "UPDATE events SET raw_bytes = zeroblob(?1)
                 WHERE event_id = 'provider-dispatch-dispatch-store-1'",
                [profile.maximum_event_bytes + 1],
            )
            .unwrap();
        drop(connection);
        assert!(matches!(
            read_only_run_snapshot(&path, "run-holding-store"),
            Err(ForemanError::ReadOnlyStore(message))
                if message.contains("missing exact marker")
        ));
    }

    let (_directory, store, _packet, admission, _profile) = setup();
    assert!(store.projection(&admission.run_id).is_ok());
}

#[test]
fn holding_history_refuses_missing_initial_release_and_partial_reacquisition_groups() {
    {
        let (_directory, path, store, _packet, _admission, _profile, _policy, _requirement) =
            holding_setup();
        let (_attempt, _opened) = holding_open_initial(&store);
        drop(store);
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER events_no_delete;
                 DROP TRIGGER execution_availability_metadata_no_delete;
                 DROP TRIGGER execution_availability_anchors_no_delete;
                 DELETE FROM execution_availability_event_anchors
                 WHERE event_id = 'provider-dispatch-dispatch-store-1';
                 DELETE FROM execution_availability_event_metadata
                 WHERE event_id = 'provider-dispatch-dispatch-store-1';
                 DELETE FROM events
                 WHERE event_id = 'provider-dispatch-dispatch-store-1';",
            )
            .unwrap();
        drop(connection);
        assert!(matches!(
            read_only_run_snapshot(&path, "run-holding-store"),
            Err(ForemanError::ReadOnlyStore(message))
                if message.contains("attempt lacks adjacent initial dispatch")
        ));
    }

    {
        let (_directory, path, store, _packet, _admission, _profile, policy, requirement) =
            holding_setup();
        let (attempt, opened) = holding_open_initial(&store);
        let parked = holding_record(
            &store,
            &requirement,
            &policy,
            &opened,
            "parked",
            holding_time("2026-08-31T12:01:02Z"),
            None,
        );
        drop(store);
        let release_event_id = format!("provider-resources-released-{}", parked.disposition_digest);
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER events_no_delete;
                 DROP TRIGGER execution_availability_metadata_no_delete;
                 DROP TRIGGER execution_availability_anchors_no_delete;",
            )
            .unwrap();
        connection
            .execute(
                "DELETE FROM execution_availability_event_anchors WHERE event_id = ?1",
                [&release_event_id],
            )
            .unwrap();
        connection
            .execute(
                "DELETE FROM execution_availability_event_metadata WHERE event_id = ?1",
                [&release_event_id],
            )
            .unwrap();
        connection
            .execute(
                "DELETE FROM events WHERE event_id = ?1",
                [&release_event_id],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO resource_claims
                 (run_id, resource_lock_key, work_item_id, attempt_id)
                 VALUES ('run-holding-store', 'provider-slot-a', 'work-a', ?1)",
                [&attempt.attempt_id],
            )
            .unwrap();
        drop(connection);
        assert!(matches!(
            read_only_run_snapshot(&path, "run-holding-store"),
            Err(ForemanError::ReadOnlyStore(message))
                if message.contains("mandatory resource release")
        ));
    }

    {
        let (_directory, path, store, _packet, _admission, _profile, policy, requirement) =
            holding_setup();
        let (attempt, opened) = holding_open_initial(&store);
        let parked = holding_record(
            &store,
            &requirement,
            &policy,
            &opened,
            "parked",
            holding_time("2026-08-31T12:01:02Z"),
            None,
        );
        store
            .wake_provider_dispatch(
                "run-holding-store",
                "work-a",
                &attempt.attempt_id,
                "wake-partial-group",
                "dispatch-partial-group",
                "adapter-process-partial-group",
                "session-partial-group",
                1,
                parked.provider_retry_after.unwrap(),
            )
            .unwrap();
        drop(store);
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER events_no_delete;
                 DROP TRIGGER execution_availability_metadata_no_delete;
                 DROP TRIGGER execution_availability_anchors_no_delete;
                 DELETE FROM execution_availability_event_anchors
                 WHERE event_id IN ('provider-wake-wake-partial-group',
                                    'provider-dispatch-dispatch-partial-group');
                 DELETE FROM execution_availability_event_metadata
                 WHERE event_id IN ('provider-wake-wake-partial-group',
                                    'provider-dispatch-dispatch-partial-group');
                 DELETE FROM events
                 WHERE event_id IN ('provider-wake-wake-partial-group',
                                    'provider-dispatch-dispatch-partial-group');",
            )
            .unwrap();
        drop(connection);
        assert!(matches!(
            read_only_run_snapshot(&path, "run-holding-store"),
            Err(ForemanError::ReadOnlyStore(message))
                if message.contains("reacquisition or wake lacks atomic successor")
        ));
    }
}

#[test]
fn holding_release_wake_reacquires_worker_slot_atomically_across_concurrent_writers() {
    {
        let (_directory, path, store, _packet, _admission, _profile, policy, requirement) =
            holding_setup_with_policy(1, ParkedResourceLockPolicyV1::ReleaseAndReacquire, true);
        let (attempt, opened) = holding_open_initial(&store);
        let parked = holding_record(
            &store,
            &requirement,
            &policy,
            &opened,
            "parked",
            holding_time("2026-08-31T12:01:02Z"),
            None,
        );
        store
            .prepare_provider_attempt(
                "run-holding-store",
                "work-b",
                "dispatch-worker-slot-b",
                "adapter-process-worker-slot-b",
                "session-worker-slot-b",
                0,
                holding_time("2026-08-31T12:01:03Z"),
            )
            .unwrap();
        assert!(matches!(
            store.wake_provider_dispatch(
                "run-holding-store",
                "work-a",
                &attempt.attempt_id,
                "wake-worker-slot-a",
                "dispatch-worker-slot-a",
                "adapter-process-worker-slot-a",
                "session-worker-slot-a",
                1,
                parked.provider_retry_after.unwrap(),
            ),
            Err(ForemanError::ResourceUnavailable(message))
                if message.contains("maximum concurrent workers")
        ));
        drop(store);
        let history = read_only_run_snapshot(&path, "run-holding-store")
            .unwrap()
            .execution_availability
            .unwrap();
        assert_eq!(history.dispatches.len(), 2);
        assert!(history.wake_occurrence_ids.is_empty());
    }

    let (_directory, path, store, _packet, _admission, _profile, policy, requirement) =
        holding_setup_with_policy(1, ParkedResourceLockPolicyV1::ReleaseAndReacquire, true);
    let (attempt, opened) = holding_open_initial(&store);
    let parked = holding_record(
        &store,
        &requirement,
        &policy,
        &opened,
        "parked",
        holding_time("2026-08-31T12:01:02Z"),
        None,
    );
    drop(store);
    let barrier = Arc::new(Barrier::new(2));
    let wake_path = path.clone();
    let wake_barrier = Arc::clone(&barrier);
    let attempt_id = attempt.attempt_id.clone();
    let wake_at = parked.provider_retry_after.unwrap();
    let wake = std::thread::spawn(move || {
        let store = ForemanStore::open(wake_path).unwrap();
        wake_barrier.wait();
        store.wake_provider_dispatch(
            "run-holding-store",
            "work-a",
            &attempt_id,
            "wake-concurrent-slot-a",
            "dispatch-concurrent-slot-a",
            "adapter-process-concurrent-slot-a",
            "session-concurrent-slot-a",
            1,
            wake_at,
        )
    });
    let prepare_path = path.clone();
    let prepare = std::thread::spawn(move || {
        let store = ForemanStore::open(prepare_path).unwrap();
        barrier.wait();
        store.prepare_provider_attempt(
            "run-holding-store",
            "work-b",
            "dispatch-concurrent-slot-b",
            "adapter-process-concurrent-slot-b",
            "session-concurrent-slot-b",
            0,
            holding_time("2026-08-31T12:01:03Z"),
        )
    });
    let results = [
        wake.join().unwrap().is_ok(),
        prepare.join().unwrap().is_ok(),
    ];
    assert_eq!(results.into_iter().filter(|value| *value).count(), 1);
    let connection = Connection::open(&path).unwrap();
    let claims: u64 = connection
        .query_row(
            "SELECT count(*) FROM resource_claims WHERE run_id = 'run-holding-store'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(claims, 1);
}

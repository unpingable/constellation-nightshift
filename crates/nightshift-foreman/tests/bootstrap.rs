use std::collections::BTreeMap;

use chrono::{DateTime, Duration, TimeZone as _, Utc};
use nightshift_foreman::*;
use nightshift_provider_capacity::{
    decide_capacity, CapacityObservationV1, CapacityPolicyV1, CapacityWindow, Confidence,
    ObservationDisposition, ObservationEvidence, SourceClass, WindowType,
    CAPACITY_OBSERVATION_SCHEMA_V1, CAPACITY_POLICY_SCHEMA_V1,
};
use nightshiftd::packet::{
    AuthoringIdentityV1, CampaignIdentityV1, CanonicalizationV1, ExactWorkRefV1,
    GlobalConstraintsV1, ModelRoutingV1, NightshiftPacketV1, RepositoryCustodyV1,
    SourceEvidenceRefV1, SwitchyardRegistrationV1, WorkItemV1, WorkerBudgetV1,
    EXACT_WORK_PROPOSAL_SCHEMA_V1, NIGHTSHIFT_PACKET_DIGEST_PREIMAGE_V1,
    NIGHTSHIFT_PACKET_SCHEMA_V1,
};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

fn time(second: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 31, 12, 0, second).unwrap()
}

fn placeholder() -> String {
    format!("sha256:{}", "0".repeat(64))
}

fn canonical<T: Serialize>(value: &T) -> Vec<u8> {
    serde_jcs::to_vec(value).unwrap()
}

fn work_item(id: &str, codename: &str, dependencies: Vec<&str>) -> WorkItemV1 {
    WorkItemV1 {
        id: id.to_owned(),
        track: "second-watch-fixture".to_owned(),
        campaign: CampaignIdentityV1 {
            codename: codename.to_owned(),
            canonical_slug: format!("second-watch-fixture-{id}"),
        },
        predecessor_lineage: vec![],
        dependencies: dependencies.into_iter().map(str::to_owned).collect(),
        exact_work_refs: vec![ExactWorkRefV1 {
            contract_kind: "exact_work_proposal_v1".to_owned(),
            contract_schema: EXACT_WORK_PROPOSAL_SCHEMA_V1.to_owned(),
            repository: "nightshift".to_owned(),
            branch: "campaign/second-watch-fixture".to_owned(),
            commit: "a".repeat(40),
            path: "qualification/second-watch/proposal.json".to_owned(),
            proposal_ref: format!("sha256:{}", "b".repeat(64)),
        }],
        entry_predicates: vec!["inspect exact retained inputs".to_owned()],
        allowed_mutation_surfaces: vec!["campaign-owned local fixture".to_owned()],
        forbidden_actions: vec![
            "target actuation".to_owned(),
            "approval response".to_owned(),
            "bootstrap recursion".to_owned(),
        ],
        acceptance_tests: vec!["exact terminal or not-started custody".to_owned()],
        stop_conditions: vec!["exact contract discrepancy".to_owned()],
        expected_receipts: vec!["terminal or not-started".to_owned()],
        closeout_requirements: vec!["local fixture teardown".to_owned()],
        model_routing: ModelRoutingV1 {
            class: "bounded".to_owned(),
            reason: "deterministic qualification".to_owned(),
            maximum_mutating_workers: 1,
        },
    }
}

fn packet() -> NightshiftPacketV1 {
    let mut value = NightshiftPacketV1 {
        schema: NIGHTSHIFT_PACKET_SCHEMA_V1.to_owned(),
        packet_id: "second-watch-fixture".to_owned(),
        packet_digest: String::new(),
        created_at: time(0),
        current_until: time(0) + Duration::hours(2),
        authoring: AuthoringIdentityV1 {
            agent: "second-watch-contract-test".to_owned(),
            session: "second-watch-contract-test".to_owned(),
            authority_basis: "direct operator successor authorization".to_owned(),
        },
        canonicalization: CanonicalizationV1 {
            algorithm: "RFC8785-JCS".to_owned(),
            digest_algorithm: "SHA-256".to_owned(),
            digest_preimage: NIGHTSHIFT_PACKET_DIGEST_PREIMAGE_V1.to_owned(),
        },
        source_evidence: vec![SourceEvidenceRefV1 {
            repository: "nightshift".to_owned(),
            branch: "campaign/holding-pattern".to_owned(),
            commit: SECOND_WATCH_HOLDING_RESULT_HEAD.to_owned(),
            path: "qualification/holding-pattern".to_owned(),
            file_digest: format!("sha256:{}", "c".repeat(64)),
            predecessor_classification: "EXACT-RESULT-ANCESTRY".to_owned(),
        }],
        repository_custody: vec![RepositoryCustodyV1 {
            repository: "nightshift".to_owned(),
            path: "/tmp/second-watch-fixture".to_owned(),
            branch: "campaign/second-watch-fixture".to_owned(),
            commit: "a".repeat(40),
            remote: None,
            remote_commit: None,
            worktree_clean: true,
            discrepancy: None,
        }],
        global_constraints: GlobalConstraintsV1 {
            allowed_actions: vec!["bounded local compute scheduling".to_owned()],
            forbidden_actions: vec!["target actuation".to_owned()],
            invariants: vec!["scheduler state is not authority".to_owned()],
        },
        work_items: vec![
            work_item("lane-a", "FIXTURE-LARK", vec![]),
            work_item("lane-b", "FIXTURE-TERN", vec![]),
            work_item("question", "FIXTURE-WREN", vec![]),
            work_item("closeout", "FIXTURE-OWL", vec!["lane-a", "lane-b"]),
        ],
        worker_budget: WorkerBudgetV1 {
            maximum_concurrent_mutating_workers: 2,
            recursive_worker_swarms_forbidden: true,
            reserve_posture: "bounded deterministic fixture".to_owned(),
        },
        human_question_criteria: vec!["presentation-only question".to_owned()],
        switchyard: SwitchyardRegistrationV1 {
            alias: "second-watch-fixture".to_owned(),
            plan_ref: String::new(),
            transport_fields: vec![
                "alias".to_owned(),
                "plan_ref".to_owned(),
                "nonce".to_owned(),
            ],
        },
    };
    value.seal().unwrap();
    value
}

fn admission(packet: &NightshiftPacketV1) -> ForemanAdmissionV1 {
    let mut value = ForemanAdmissionV1 {
        schema: FOREMAN_ADMISSION_SCHEMA_V1.to_owned(),
        admission_digest: placeholder(),
        run_id: "second-watch-run".to_owned(),
        packet_digest: packet.packet_digest.clone(),
        operator_basis_digest: format!("sha256:{}", "d".repeat(64)),
        admitted_at: time(0),
        expires_at: time(0) + Duration::hours(1),
        local_runtime_identity: "second-watch-local-runtime".to_owned(),
        maximum_concurrent_workers: 2,
        allowed_adapter_ids: vec![HOLDING_QUALIFICATION_PRODUCER_ID.to_owned()],
        allowed_provider_model_classes: vec!["bounded".to_owned()],
        maximum_new_attempts_per_work_item: 1,
        authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".to_owned(),
        target_effects_authorized: false,
    };
    value.seal().unwrap();
    value
}

fn capacity_policy() -> CapacityPolicyV1 {
    let mut value = CapacityPolicyV1 {
        schema: CAPACITY_POLICY_SCHEMA_V1.to_owned(),
        policy_id: "second-watch-budget".to_owned(),
        abundant_min_remaining: 0.8,
        normal_min_remaining: 0.5,
        conserve_min_remaining: 0.2,
        minimum_confidence: Confidence::High,
        required_window_types: vec![WindowType::FiveHour],
        unknown_allows_new_cheap_work: true,
        policy_digest: placeholder(),
    };
    value.policy_digest = value.compute_digest().unwrap();
    value.validate().unwrap();
    value
}

fn profile(
    packet: &NightshiftPacketV1,
    admission: &ForemanAdmissionV1,
    capacity_policy: &CapacityPolicyV1,
) -> ExecutionProfileV2 {
    let work_items = packet
        .work_items
        .iter()
        .map(|item| {
            (
                item.id.clone(),
                WorkItemExecutionV1 {
                    adapter_id: HOLDING_QUALIFICATION_PRODUCER_ID.to_owned(),
                    workspace_identity: format!("workspace:{}", item.id),
                    resource_lock_keys: vec![format!("fixture:{}", item.id)],
                    provider_model_class: "bounded".to_owned(),
                },
            )
        })
        .collect();
    let mut value = ExecutionProfileV2 {
        schema: FOREMAN_EXECUTION_PROFILE_SCHEMA_V2.to_owned(),
        profile_digest: placeholder(),
        packet_digest: packet.packet_digest.clone(),
        admission_digest: admission.admission_digest.clone(),
        adapters: BTreeMap::from([(
            HOLDING_QUALIFICATION_PRODUCER_ID.to_owned(),
            AdapterRegistrationV2 {
                adapter_id: HOLDING_QUALIFICATION_PRODUCER_ID.to_owned(),
                protocol: DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V2.to_owned(),
                adapter_version: SECOND_WATCH_QUALIFICATION_PRODUCER_VERSION.to_owned(),
                executable_identity: SECOND_WATCH_QUALIFICATION_EXECUTABLE_SHA256.to_owned(),
                bounded_arguments: vec![],
            },
        )]),
        work_items,
        budget_policy_ref: capacity_policy.policy_id.clone(),
        log_custody_root: "/tmp/second-watch-fixture/log".to_owned(),
        receipt_custody_root: "/tmp/second-watch-fixture/receipts".to_owned(),
        maximum_event_bytes: 1024 * 1024,
        maximum_worker_output_bytes: None,
        maximum_receipt_bytes: 131_072,
        adapter_timeout_seconds: 60,
        closeout_policy: "ALL_EXPLICIT_TERMINAL_OR_NOT_STARTED".to_owned(),
    };
    value.seal().unwrap();
    value
}

fn capacity_requirement(
    packet: &NightshiftPacketV1,
    admission: &ForemanAdmissionV1,
    profile: &ExecutionProfileV2,
    policy: &CapacityPolicyV1,
) -> ForemanCapacityRequirementV1 {
    let mut value = ForemanCapacityRequirementV1 {
        schema: FOREMAN_CAPACITY_REQUIREMENT_SCHEMA_V1.to_owned(),
        capacity_requirement_digest: placeholder(),
        packet_digest: packet.packet_digest.clone(),
        admission_digest: admission.admission_digest.clone(),
        profile_digest: profile.profile_digest.clone(),
        run_id: admission.run_id.clone(),
        policy_id: policy.policy_id.clone(),
        provider_id: "qualification-provider".to_owned(),
        model_cost_classes: BTreeMap::from([("bounded".to_owned(), CapacityCostClassV1::Cheap)]),
        authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".to_owned(),
    };
    value.seal().unwrap();
    value
}

fn availability_policy() -> ExecutionAvailabilityPolicyV1 {
    let mut value = ExecutionAvailabilityPolicyV1 {
        schema: EXECUTION_AVAILABILITY_POLICY_SCHEMA_V1.to_owned(),
        policy_digest: placeholder(),
        policy_id: "second-watch-availability".to_owned(),
        maximum_dispatch_occurrences_per_attempt: 3,
        backoff_seconds: vec![5, 10, 20],
        maximum_total_deferral_seconds: 60,
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

fn availability_requirement(
    packet: &NightshiftPacketV1,
    admission: &ForemanAdmissionV1,
    profile: &ExecutionProfileV2,
    policy: &ExecutionAvailabilityPolicyV1,
) -> ForemanExecutionAvailabilityRequirementV1 {
    let adapter = &profile.adapters[HOLDING_QUALIFICATION_PRODUCER_ID];
    let selections = packet
        .work_items
        .iter()
        .map(|item| {
            (
                item.id.clone(),
                vec![ProviderModelSelectionV1 {
                    provider_id: "qualification-provider".to_owned(),
                    model_id: "deterministic-model".to_owned(),
                    model_class: "bounded".to_owned(),
                }],
            )
        })
        .collect();
    let mut value = ForemanExecutionAvailabilityRequirementV1 {
        schema: FOREMAN_EXECUTION_AVAILABILITY_REQUIREMENT_SCHEMA_V1.to_owned(),
        requirement_digest: placeholder(),
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

struct Fixture {
    plan: SelfHostedForemanBootstrapV1,
    packet: NightshiftPacketV1,
    admission: ForemanAdmissionV1,
    profile: ExecutionProfileV2,
    capacity_requirement: ForemanCapacityRequirementV1,
    capacity_policy: CapacityPolicyV1,
    availability_requirement: ForemanExecutionAvailabilityRequirementV1,
    availability_policy: ExecutionAvailabilityPolicyV1,
}

impl Fixture {
    fn validate(&self) -> Result<(), ContractError> {
        self.plan.validate_graph(
            &canonical(&self.packet),
            &canonical(&self.admission),
            &canonical(&self.profile),
            &canonical(&self.capacity_requirement),
            &canonical(&self.capacity_policy),
            &canonical(&self.availability_requirement),
            &canonical(&self.availability_policy),
        )
    }
}

fn reseal_adapter_graph(value: &mut Fixture, adapter: AdapterRegistrationV2) {
    let adapter_id = adapter.adapter_id.clone();
    value.admission.allowed_adapter_ids = vec![adapter_id.clone()];
    value.admission.seal().unwrap();

    value.profile.admission_digest = value.admission.admission_digest.clone();
    for work in value.profile.work_items.values_mut() {
        work.adapter_id = adapter_id.clone();
    }
    value.profile.adapters = BTreeMap::from([(adapter_id.clone(), adapter.clone())]);
    value.profile.seal().unwrap();

    value.capacity_requirement.admission_digest = value.admission.admission_digest.clone();
    value.capacity_requirement.profile_digest = value.profile.profile_digest.clone();
    value.capacity_requirement.seal().unwrap();

    value.availability_requirement.admission_digest = value.admission.admission_digest.clone();
    value.availability_requirement.profile_digest = value.profile.profile_digest.clone();
    value.availability_requirement.adapter_id = adapter_id;
    value.availability_requirement.adapter_protocol = adapter.protocol;
    value.availability_requirement.adapter_version = adapter.adapter_version;
    value.availability_requirement.adapter_executable_identity = adapter.executable_identity;
    value.availability_requirement.seal().unwrap();

    value.plan.admission_digest = value.admission.admission_digest.clone();
    value.plan.profile_digest = value.profile.profile_digest.clone();
    value.plan.capacity_requirement_digest = value
        .capacity_requirement
        .capacity_requirement_digest
        .clone();
    value.plan.execution_availability_requirement_digest =
        value.availability_requirement.requirement_digest.clone();
    value.plan.seal().unwrap();
}

fn reseal_admission_graph(value: &mut Fixture) {
    value.admission.seal().unwrap();

    value.profile.admission_digest = value.admission.admission_digest.clone();
    value.profile.seal().unwrap();

    value.capacity_requirement.admission_digest = value.admission.admission_digest.clone();
    value.capacity_requirement.profile_digest = value.profile.profile_digest.clone();
    value.capacity_requirement.seal().unwrap();

    value.availability_requirement.admission_digest = value.admission.admission_digest.clone();
    value.availability_requirement.profile_digest = value.profile.profile_digest.clone();
    value.availability_requirement.seal().unwrap();

    value.plan.admission_digest = value.admission.admission_digest.clone();
    value.plan.profile_digest = value.profile.profile_digest.clone();
    value.plan.capacity_requirement_digest = value
        .capacity_requirement
        .capacity_requirement_digest
        .clone();
    value.plan.execution_availability_requirement_digest =
        value.availability_requirement.requirement_digest.clone();
    value.plan.seal().unwrap();
}

fn fixture() -> Fixture {
    let packet = packet();
    let admission = admission(&packet);
    let capacity_policy = capacity_policy();
    let profile = profile(&packet, &admission, &capacity_policy);
    let capacity_requirement =
        capacity_requirement(&packet, &admission, &profile, &capacity_policy);
    let availability_policy = availability_policy();
    let availability_requirement =
        availability_requirement(&packet, &admission, &profile, &availability_policy);
    let mut plan = SelfHostedForemanBootstrapV1 {
        schema: SELF_HOSTED_FOREMAN_BOOTSTRAP_SCHEMA_V1.to_owned(),
        bootstrap_digest: placeholder(),
        digest_preimage: SELF_HOSTED_FOREMAN_BOOTSTRAP_DIGEST_PREIMAGE_V1.to_owned(),
        campaign_codename: "SECOND-WATCH".to_owned(),
        canonical_slug: SECOND_WATCH_CANONICAL_SLUG.to_owned(),
        track: "nightshift-self-hosting".to_owned(),
        holding_result_head: SECOND_WATCH_HOLDING_RESULT_HEAD.to_owned(),
        holding_qualified_subject: SECOND_WATCH_HOLDING_QUALIFIED_SUBJECT.to_owned(),
        durable_roadmap_head: SECOND_WATCH_DURABLE_ROADMAP_HEAD.to_owned(),
        midnight_result_head: SECOND_WATCH_MIDNIGHT_RESULT_HEAD.to_owned(),
        silicon_result_head: SECOND_WATCH_SILICON_RESULT_HEAD.to_owned(),
        codex_owner_head: ACCEPTED_CODEX_PROVIDER_ADMISSION_OWNER_HEAD.to_owned(),
        switchyard_owner_head: ACCEPTED_SWITCHYARD_PROVIDER_ADMISSION_OWNER_HEAD.to_owned(),
        bootstrap_occurrence_id: "bootstrap-second-watch-1".to_owned(),
        run_id: admission.run_id.clone(),
        packet_id: packet.packet_id.clone(),
        packet_digest: packet.packet_digest.clone(),
        predecessor_v2_packet_digest: SECOND_WATCH_PREDECESSOR_V2_PACKET_DIGEST.to_owned(),
        admission_digest: admission.admission_digest.clone(),
        profile_digest: profile.profile_digest.clone(),
        capacity_requirement_digest: capacity_requirement.capacity_requirement_digest.clone(),
        capacity_policy_digest: capacity_policy.policy_digest.clone(),
        execution_availability_requirement_digest: availability_requirement
            .requirement_digest
            .clone(),
        execution_availability_policy_digest: availability_policy.policy_digest.clone(),
        local_runtime_identity: admission.local_runtime_identity.clone(),
        evaluated_at: time(1),
        expected_work_item_count: packet.work_items.len().try_into().unwrap(),
        initially_runnable_lane_count: 3,
        presentation_only_question_work_item_id: "question".to_owned(),
        maximum_driver_steps: 100,
        maximum_wall_seconds: 600,
        bootstrap_depth: 0,
        parent_bootstrap_occurrence_id: None,
        scheduler_owner: "NIGHTSHIFT_DURABLE_FOREMAN".to_owned(),
        worker_adapter_mode: "CAMPAIGN_QUALIFICATION_DETERMINISTIC_FAKE".to_owned(),
        wake_source_policy: "QUALIFIED_LOCAL_REEVALUATION_NO_EVIDENCE_OR_AUTHORITY".to_owned(),
        closeout_policy: "ALL_EXPLICIT_TERMINAL_OR_NOT_STARTED".to_owned(),
        authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".to_owned(),
        target_effects_authorized: false,
        approval_response_authorized: false,
        protected_effect_authorized: false,
        semantic_retry_authorized: false,
        bootstrap_may_nest: false,
        worker_may_invoke_bootstrap: false,
        outer_conversation_scheduler: false,
        timer_or_service_activation_authorized: false,
        production_activation_authorized: false,
        aggregate_result_created: false,
    };
    plan.seal().unwrap();
    Fixture {
        plan,
        packet,
        admission,
        profile,
        capacity_requirement,
        capacity_policy,
        availability_requirement,
        availability_policy,
    }
}

#[test]
fn closed_bootstrap_plan_and_exact_graph_validate() {
    let value = fixture();
    value.validate().unwrap();
    let adapter = value.profile.adapters.values().next().unwrap();
    assert_eq!(adapter.adapter_id, HOLDING_QUALIFICATION_PRODUCER_ID);
    assert_eq!(
        adapter.protocol,
        DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V2
    );
    assert_eq!(
        adapter.adapter_version,
        SECOND_WATCH_QUALIFICATION_PRODUCER_VERSION
    );
    assert_eq!(
        adapter.executable_identity,
        SECOND_WATCH_QUALIFICATION_EXECUTABLE_SHA256
    );
    assert!(adapter.bounded_arguments.is_empty());
    let raw = canonical(&value.plan);
    let reopened = SelfHostedForemanBootstrapV1::from_slice(&raw).unwrap();
    assert_eq!(reopened, value.plan);
    reopened.validate().unwrap();
}

#[test]
fn authority_recursion_and_predecessor_substitutions_refuse() {
    for mutate in [
        |plan: &mut SelfHostedForemanBootstrapV1| plan.approval_response_authorized = true,
        |plan: &mut SelfHostedForemanBootstrapV1| plan.bootstrap_may_nest = true,
        |plan: &mut SelfHostedForemanBootstrapV1| plan.bootstrap_depth = 1,
        |plan: &mut SelfHostedForemanBootstrapV1| plan.holding_result_head = "f".repeat(40),
        |plan: &mut SelfHostedForemanBootstrapV1| {
            plan.packet_digest = SECOND_WATCH_PREDECESSOR_V2_PACKET_DIGEST.to_owned()
        },
    ] {
        let mut value = fixture().plan;
        mutate(&mut value);
        value.bootstrap_digest = placeholder();
        assert!(value.seal().is_err());
    }
}

#[test]
fn graph_substitution_and_topology_cases_fail_closed() {
    let mut wrong_profile = fixture();
    wrong_profile.plan.profile_digest = format!("sha256:{}", "f".repeat(64));
    wrong_profile.plan.seal().unwrap();
    assert!(wrong_profile.validate().is_err());

    let mut wrong_policy = fixture();
    wrong_policy.capacity_requirement.policy_id = "substituted-policy".to_owned();
    wrong_policy.capacity_requirement.seal().unwrap();
    assert!(wrong_policy.validate().is_err());

    let mut wrong_count = fixture();
    wrong_count.plan.initially_runnable_lane_count = 2;
    wrong_count.plan.seal().unwrap();
    assert!(wrong_count.validate().is_err());

    let mut recursive = fixture();
    recursive.packet.work_items[0].campaign.canonical_slug = SECOND_WATCH_CANONICAL_SLUG.to_owned();
    recursive.packet.seal().unwrap();
    assert!(recursive.validate().is_err());

    let mut wrong_provider = fixture();
    for selections in wrong_provider
        .availability_requirement
        .work_item_model_selections
        .values_mut()
    {
        for selection in selections {
            selection.provider_id = "substituted-provider".to_owned();
        }
    }
    wrong_provider.availability_requirement.seal().unwrap();
    wrong_provider
        .plan
        .execution_availability_requirement_digest = wrong_provider
        .availability_requirement
        .requirement_digest
        .clone();
    wrong_provider.plan.seal().unwrap();
    assert!(wrong_provider.validate().is_err());

    let mut wrong_admission_time = fixture();
    wrong_admission_time.availability_requirement.admitted_at = time(2);
    wrong_admission_time
        .availability_requirement
        .seal()
        .unwrap();
    wrong_admission_time
        .plan
        .execution_availability_requirement_digest = wrong_admission_time
        .availability_requirement
        .requirement_digest
        .clone();
    wrong_admission_time.plan.seal().unwrap();
    assert!(wrong_admission_time.validate().is_err());

    let exact = fixture().profile.adapters.values().next().unwrap().clone();
    let mut substituted_adapters = Vec::new();
    let mut substituted = exact.clone();
    substituted.adapter_id = "substituted-adapter".to_owned();
    substituted_adapters.push(substituted);
    let mut substituted = exact.clone();
    substituted.protocol = "substituted.protocol/v1".to_owned();
    substituted_adapters.push(substituted);
    let mut substituted = exact.clone();
    substituted.adapter_version = "v3".to_owned();
    substituted_adapters.push(substituted);
    let mut substituted = exact.clone();
    substituted.executable_identity = format!("sha256:{}", "f".repeat(64));
    substituted_adapters.push(substituted);
    let mut substituted = exact;
    substituted.bounded_arguments = vec!["--substituted".to_owned()];
    substituted_adapters.push(substituted);

    for adapter in substituted_adapters {
        let mut coherent = fixture();
        reseal_adapter_graph(&mut coherent, adapter);
        assert!(coherent.validate().is_err());
    }
}

#[test]
fn noncanonical_time_and_unknown_fields_refuse() {
    let value = fixture();
    let mut json = serde_json::to_value(&value.plan).unwrap();
    json["evaluated_at"] = serde_json::json!("2026-08-31T08:00:01-04:00");
    assert!(SelfHostedForemanBootstrapV1::from_slice(&serde_json::to_vec(&json).unwrap()).is_err());
    json = serde_json::to_value(&value.plan).unwrap();
    json["approve"] = serde_json::json!(true);
    assert!(SelfHostedForemanBootstrapV1::from_slice(&serde_json::to_vec(&json).unwrap()).is_err());

    let mut noncanonical_plan = canonical(&value.plan);
    noncanonical_plan.push(b'\n');
    assert!(SelfHostedForemanBootstrapV1::from_slice(&noncanonical_plan).is_err());

    let noncanonical_packet = serde_json::to_vec_pretty(&value.packet).unwrap();
    assert!(value
        .plan
        .validate_graph(
            &noncanonical_packet,
            &canonical(&value.admission),
            &canonical(&value.profile),
            &canonical(&value.capacity_requirement),
            &canonical(&value.capacity_policy),
            &canonical(&value.availability_requirement),
            &canonical(&value.availability_policy),
        )
        .is_err());
}
fn fixture_inputs(value: &Fixture) -> [Vec<u8>; 8] {
    [
        canonical(&value.plan),
        canonical(&value.packet),
        canonical(&value.admission),
        canonical(&value.profile),
        canonical(&value.capacity_requirement),
        canonical(&value.capacity_policy),
        canonical(&value.availability_requirement),
        canonical(&value.availability_policy),
    ]
}

fn admit_fixture(path: &std::path::Path, value: &Fixture) -> String {
    let bytes = fixture_inputs(value);
    ForemanStore::admit_self_hosted_at_path(
        path,
        SelfHostedBootstrapInputsV1 {
            bootstrap_bytes: &bytes[0],
            packet_bytes: &bytes[1],
            admission_bytes: &bytes[2],
            profile_bytes: &bytes[3],
            capacity_requirement_bytes: &bytes[4],
            capacity_policy_bytes: &bytes[5],
            execution_availability_requirement_bytes: &bytes[6],
            execution_availability_policy_bytes: &bytes[7],
        },
    )
    .unwrap()
}

#[test]
fn driver_step_contract_is_closed_bounded_and_non_authorizing() {
    let value = fixture();
    let mut step = SelfHostedForemanDriverStepV1 {
        schema: SELF_HOSTED_FOREMAN_DRIVER_STEP_SCHEMA_V1.to_owned(),
        step_digest: placeholder(),
        bootstrap_digest: value.plan.bootstrap_digest.clone(),
        bootstrap_occurrence_id: value.plan.bootstrap_occurrence_id.clone(),
        run_id: value.plan.run_id.clone(),
        step_ordinal: 1,
        scheduler_process_occurrence_id: "scheduler-process-1".to_owned(),
        observed_projection_digest: format!("sha256:{}", "1".repeat(64)),
        disposition: SelfHostedDriverDispositionV1::ReadyWorkPresent,
        recorded_at: time(2),
        worker_dispatch_authorized: false,
        approval_response_authorized: false,
        protected_effect_authorized: false,
        semantic_retry_authorized: false,
        aggregate_result_created: false,
    };
    step.seal().unwrap();
    assert_eq!(
        SelfHostedForemanDriverStepV1::from_slice(&canonical(&step)).unwrap(),
        step
    );

    for ordinal in [0, 1_000_001] {
        let mut substituted = step.clone();
        substituted.step_ordinal = ordinal;
        substituted.step_digest = placeholder();
        assert!(substituted.seal().is_err());
    }
    let mut widened = step.clone();
    widened.worker_dispatch_authorized = true;
    widened.step_digest = placeholder();
    assert!(widened.seal().is_err());
}

#[test]
fn self_hosted_admission_preflights_before_store_creation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("invalid.sqlite3");
    let mut value = fixture();
    value.plan.profile_digest = format!("sha256:{}", "f".repeat(64));
    value.plan.seal().unwrap();
    let bytes = fixture_inputs(&value);
    assert!(ForemanStore::admit_self_hosted_at_path(
        &path,
        SelfHostedBootstrapInputsV1 {
            bootstrap_bytes: &bytes[0],
            packet_bytes: &bytes[1],
            admission_bytes: &bytes[2],
            profile_bytes: &bytes[3],
            capacity_requirement_bytes: &bytes[4],
            capacity_policy_bytes: &bytes[5],
            execution_availability_requirement_bytes: &bytes[6],
            execution_availability_policy_bytes: &bytes[7],
        },
    )
    .is_err());
    assert!(!path.exists());
}

#[test]
fn self_hosted_store_reopens_and_driver_step_is_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("foreman.sqlite3");
    let value = fixture();
    let run_id = admit_fixture(&path, &value);
    assert_eq!(run_id, value.plan.run_id);

    let store = ForemanStore::open(&path).unwrap();
    assert!(store.self_hosted_bootstrap(&run_id).is_err());
    let first = store
        .advance_self_hosted_driver(
            &run_id,
            &value.plan.bootstrap_digest,
            1,
            "scheduler-process-1",
            time(2),
        )
        .unwrap();
    assert_eq!(first.step_ordinal, 1);
    assert_eq!(
        first.disposition,
        SelfHostedDriverDispositionV1::ReadyWorkPresent
    );
    assert!(!first.worker_dispatch_authorized);

    let duplicate = store
        .advance_self_hosted_driver(
            &run_id,
            &value.plan.bootstrap_digest,
            1,
            "scheduler-process-losing-writer",
            time(3),
        )
        .unwrap();
    assert_eq!(duplicate, first);
    assert!(store
        .advance_self_hosted_driver(
            &run_id,
            &value.plan.bootstrap_digest,
            3,
            "scheduler-process-3",
            time(3),
        )
        .is_err());

    drop(store);
    let casework_snapshot = read_only_run_snapshot(&path, &run_id).unwrap();
    assert_eq!(casework_snapshot.run_id, run_id);
    assert_eq!(casework_snapshot.packet_bytes, canonical(&value.packet));
    let reopened = ForemanStore::open_read_only(&path)
        .unwrap()
        .self_hosted_bootstrap(&run_id)
        .unwrap();
    assert_eq!(reopened.bootstrap, value.plan);
    assert_eq!(reopened.bootstrap_bytes, canonical(&value.plan));
    assert_eq!(
        reopened.capacity_policy_bytes,
        canonical(&value.capacity_policy)
    );
    assert_eq!(reopened.steps, vec![first.clone()]);
    assert_eq!(reopened.step_bytes, vec![canonical(&first)]);
}
#[test]
fn concurrent_driver_writers_converge_on_one_custody_record() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("foreman.sqlite3");
    let value = fixture();
    let run_id = admit_fixture(&path, &value);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let mut handles = Vec::new();
    for process in ["scheduler-process-a", "scheduler-process-b"] {
        let path = path.clone();
        let run_id = run_id.clone();
        let digest = value.plan.bootstrap_digest.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            let store = ForemanStore::open(path).unwrap();
            barrier.wait();
            store
                .advance_self_hosted_driver(&run_id, &digest, 1, process, time(2))
                .unwrap()
        }));
    }
    let first = handles.remove(0).join().unwrap();
    let second = handles.remove(0).join().unwrap();
    assert_eq!(first, second);
    let reopened = ForemanStore::open_read_only(&path)
        .unwrap()
        .self_hosted_bootstrap(&run_id)
        .unwrap();
    assert_eq!(reopened.steps, vec![first]);
}

#[test]
fn failed_driver_append_rolls_back_and_restart_recovers_exact_ordinal() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("foreman.sqlite3");
    let value = fixture();
    let run_id = admit_fixture(&path, &value);
    let fixture_connection = rusqlite::Connection::open(&path).unwrap();
    fixture_connection
        .execute_batch(
            "CREATE TRIGGER qualification_driver_insert_refusal
             BEFORE INSERT ON self_hosted_driver_steps
             BEGIN SELECT RAISE(ABORT, 'qualification fixture'); END;",
        )
        .unwrap();
    let store = ForemanStore::open(&path).unwrap();
    assert!(store.self_hosted_bootstrap(&run_id).is_err());
    assert!(store
        .advance_self_hosted_driver(
            &run_id,
            &value.plan.bootstrap_digest,
            1,
            "scheduler-process-crash",
            time(2),
        )
        .is_err());
    assert!(ForemanStore::open_read_only(&path)
        .unwrap()
        .self_hosted_bootstrap(&run_id)
        .unwrap()
        .steps
        .is_empty());
    fixture_connection
        .execute_batch("DROP TRIGGER qualification_driver_insert_refusal;")
        .unwrap();
    drop(store);

    let restarted = ForemanStore::open(&path).unwrap();
    let retained = restarted
        .advance_self_hosted_driver(
            &run_id,
            &value.plan.bootstrap_digest,
            1,
            "scheduler-process-restarted",
            time(2),
        )
        .unwrap();
    assert_eq!(retained.step_ordinal, 1);
    assert_eq!(
        ForemanStore::open_read_only(&path)
            .unwrap()
            .self_hosted_bootstrap(&run_id)
            .unwrap()
            .steps,
        vec![retained]
    );
}

#[test]
fn append_only_triggers_and_content_mutation_refuse_before_next_step() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("foreman.sqlite3");
    let value = fixture();
    let run_id = admit_fixture(&path, &value);
    let store = ForemanStore::open(&path).unwrap();
    assert!(store.self_hosted_bootstrap(&run_id).is_err());
    let first = store
        .advance_self_hosted_driver(
            &run_id,
            &value.plan.bootstrap_digest,
            1,
            "scheduler-process-1",
            time(2),
        )
        .unwrap();
    drop(store);

    let fixture_connection = rusqlite::Connection::open(&path).unwrap();
    assert!(fixture_connection
        .execute(
            "UPDATE self_hosted_driver_steps SET recorded_at = recorded_at
             WHERE run_id = ?1 AND step_ordinal = 1",
            [&run_id],
        )
        .is_err());

    fixture_connection
        .execute_batch("DROP TRIGGER self_hosted_driver_steps_no_update;")
        .unwrap();
    let mut substituted = first;
    substituted.scheduler_process_occurrence_id = "scheduler-process-substituted".to_owned();
    substituted.step_digest = placeholder();
    substituted.seal().unwrap();
    fixture_connection
        .execute(
            "UPDATE self_hosted_driver_steps SET raw_bytes = ?1
             WHERE run_id = ?2 AND step_ordinal = 1",
            rusqlite::params![canonical(&substituted), run_id],
        )
        .unwrap();
    drop(fixture_connection);

    assert!(ForemanStore::open_read_only(&path)
        .unwrap()
        .self_hosted_bootstrap(&value.plan.run_id)
        .is_err());
    let writable = ForemanStore::open(&path).unwrap();
    assert!(writable
        .advance_self_hosted_driver(
            &value.plan.run_id,
            &value.plan.bootstrap_digest,
            2,
            "scheduler-process-2",
            time(3),
        )
        .is_err());
    let fixture_connection = rusqlite::Connection::open(&path).unwrap();
    let count: i64 = fixture_connection
        .query_row(
            "SELECT COUNT(*) FROM self_hosted_driver_steps WHERE run_id = ?1",
            [&value.plan.run_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}
#[test]
fn oversized_driver_history_refuses_at_metadata_preflight() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("foreman.sqlite3");
    let value = fixture();
    let run_id = admit_fixture(&path, &value);
    let store = ForemanStore::open(&path).unwrap();
    store
        .advance_self_hosted_driver(
            &run_id,
            &value.plan.bootstrap_digest,
            1,
            "scheduler-process-1",
            time(2),
        )
        .unwrap();
    drop(store);

    let fixture_connection = rusqlite::Connection::open(&path).unwrap();
    fixture_connection
        .execute_batch("DROP TRIGGER self_hosted_driver_steps_no_update;")
        .unwrap();
    fixture_connection
        .execute(
            "UPDATE self_hosted_driver_steps SET raw_bytes = zeroblob(?1)
             WHERE run_id = ?2 AND step_ordinal = 1",
            rusqlite::params![i64::from(16 * 1024 + 1), run_id],
        )
        .unwrap();
    drop(fixture_connection);

    let error = ForemanStore::open_read_only(&path)
        .unwrap()
        .self_hosted_bootstrap(&value.plan.run_id)
        .unwrap_err();
    assert!(matches!(
        error,
        ForemanError::InputTooLarge("self-hosted driver history")
    ));
}
#[test]
fn packet_budget_caps_admission_concurrency_before_store_creation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("invalid-concurrency.sqlite3");
    let mut value = fixture();
    assert_eq!(
        value
            .packet
            .worker_budget
            .maximum_concurrent_mutating_workers,
        2
    );
    value.admission.maximum_concurrent_workers = 3;
    reseal_admission_graph(&mut value);
    value.admission.validate().unwrap();
    value.profile.validate().unwrap();
    value.capacity_requirement.validate().unwrap();
    value.availability_requirement.validate().unwrap();
    assert!(value.validate().is_err());

    let bytes = fixture_inputs(&value);
    assert!(ForemanStore::admit_self_hosted_at_path(
        &path,
        SelfHostedBootstrapInputsV1 {
            bootstrap_bytes: &bytes[0],
            packet_bytes: &bytes[1],
            admission_bytes: &bytes[2],
            profile_bytes: &bytes[3],
            capacity_requirement_bytes: &bytes[4],
            capacity_policy_bytes: &bytes[5],
            execution_availability_requirement_bytes: &bytes[6],
            execution_availability_policy_bytes: &bytes[7],
        },
    )
    .is_err());
    assert!(!path.exists());
}

#[test]
fn self_hosted_query_reopens_every_authoritative_run_column() {
    let substitutions = [
        format!(
            "UPDATE runs SET packet_digest = 'sha256:{}' WHERE run_id = 'second-watch-run'",
            "f".repeat(64)
        ),
        "UPDATE runs SET admitted_at = '2026-08-31T12:00:01Z'
         WHERE run_id = 'second-watch-run'"
            .to_owned(),
        "UPDATE runs SET maximum_concurrent_workers = 1
         WHERE run_id = 'second-watch-run'"
            .to_owned(),
    ];
    for statement in substitutions {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("foreman.sqlite3");
        let value = fixture();
        let run_id = admit_fixture(&path, &value);
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute_batch("DROP TRIGGER runs_no_update;")
            .unwrap();
        connection.execute(&statement, []).unwrap();
        drop(connection);

        assert!(ForemanStore::open_read_only(&path)
            .unwrap()
            .self_hosted_bootstrap(&run_id)
            .is_err());
    }
}

#[test]
fn driver_time_is_nondecreasing_in_mutation_restart_and_replay() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("foreman.sqlite3");
    let value = fixture();
    let run_id = admit_fixture(&path, &value);
    let store = ForemanStore::open(&path).unwrap();
    let first = store
        .advance_self_hosted_driver(
            &run_id,
            &value.plan.bootstrap_digest,
            1,
            "scheduler-process-1",
            time(3),
        )
        .unwrap();
    assert!(store
        .advance_self_hosted_driver(
            &run_id,
            &value.plan.bootstrap_digest,
            2,
            "scheduler-process-time-inversion",
            time(2),
        )
        .is_err());
    let second = store
        .advance_self_hosted_driver(
            &run_id,
            &value.plan.bootstrap_digest,
            2,
            "scheduler-process-2",
            time(4),
        )
        .unwrap();
    drop(store);

    let reopened = ForemanStore::open_read_only(&path)
        .unwrap()
        .self_hosted_bootstrap(&run_id)
        .unwrap();
    assert_eq!(reopened.steps, vec![first, second.clone()]);

    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch("DROP TRIGGER self_hosted_driver_steps_no_update;")
        .unwrap();
    let mut substituted = second;
    substituted.recorded_at = time(2);
    substituted.step_digest = placeholder();
    substituted.seal().unwrap();
    connection
        .execute(
            "UPDATE self_hosted_driver_steps
             SET step_digest = ?1, recorded_at = ?2, raw_bytes = ?3
             WHERE run_id = ?4 AND step_ordinal = 2",
            rusqlite::params![
                substituted.step_digest,
                substituted.recorded_at.to_rfc3339(),
                canonical(&substituted),
                run_id
            ],
        )
        .unwrap();
    drop(connection);

    assert!(ForemanStore::open_read_only(&path)
        .unwrap()
        .self_hosted_bootstrap(&value.plan.run_id)
        .is_err());
    assert!(ForemanStore::open(&path)
        .unwrap()
        .advance_self_hosted_driver(
            &value.plan.run_id,
            &value.plan.bootstrap_digest,
            3,
            "scheduler-process-after-inversion",
            time(5),
        )
        .is_err());
}

#[test]
fn driver_terminal_dispositions_close_append_and_replay() {
    let bound_directory = tempfile::tempdir().unwrap();
    let bound_path = bound_directory.path().join("bound.sqlite3");
    let mut bounded = fixture();
    bounded.plan.maximum_wall_seconds = 1;
    bounded.plan.seal().unwrap();
    let bound_run_id = admit_fixture(&bound_path, &bounded);
    let bound_store = ForemanStore::open(&bound_path).unwrap();
    let bound = bound_store
        .advance_self_hosted_driver(
            &bound_run_id,
            &bounded.plan.bootstrap_digest,
            1,
            "scheduler-process-bound",
            time(2),
        )
        .unwrap();
    assert_eq!(
        bound.disposition,
        SelfHostedDriverDispositionV1::BoundReached
    );
    assert!(bound_store
        .advance_self_hosted_driver(
            &bound_run_id,
            &bounded.plan.bootstrap_digest,
            2,
            "scheduler-process-after-bound",
            time(3),
        )
        .is_err());
    drop(bound_store);
    assert_eq!(
        ForemanStore::open_read_only(&bound_path)
            .unwrap()
            .self_hosted_bootstrap(&bound_run_id)
            .unwrap()
            .steps,
        vec![bound]
    );

    let terminal_directory = tempfile::tempdir().unwrap();
    let terminal_path = terminal_directory.path().join("terminal.sqlite3");
    let terminal_fixture = fixture();
    let terminal_run_id = admit_fixture(&terminal_path, &terminal_fixture);
    let terminal_store = ForemanStore::open(&terminal_path).unwrap();
    let mut first = terminal_store
        .advance_self_hosted_driver(
            &terminal_run_id,
            &terminal_fixture.plan.bootstrap_digest,
            1,
            "scheduler-process-1",
            time(2),
        )
        .unwrap();
    terminal_store
        .advance_self_hosted_driver(
            &terminal_run_id,
            &terminal_fixture.plan.bootstrap_digest,
            2,
            "scheduler-process-2",
            time(3),
        )
        .unwrap();
    drop(terminal_store);

    first.disposition = SelfHostedDriverDispositionV1::AllItemsExplicitTerminal;
    first.step_digest = placeholder();
    first.seal().unwrap();
    let connection = rusqlite::Connection::open(&terminal_path).unwrap();
    connection
        .execute_batch("DROP TRIGGER self_hosted_driver_steps_no_update;")
        .unwrap();
    connection
        .execute(
            "UPDATE self_hosted_driver_steps
             SET step_digest = ?1, raw_bytes = ?2
             WHERE run_id = ?3 AND step_ordinal = 1",
            rusqlite::params![first.step_digest, canonical(&first), terminal_run_id],
        )
        .unwrap();
    drop(connection);
    assert!(ForemanStore::open_read_only(&terminal_path)
        .unwrap()
        .self_hosted_bootstrap(&terminal_fixture.plan.run_id)
        .is_err());
}

fn golden_capacity_bundle(value: &Fixture, work_item_id: &str, at: DateTime<Utc>) -> [Vec<u8>; 4] {
    let mut observation = CapacityObservationV1 {
        schema: CAPACITY_OBSERVATION_SCHEMA_V1.to_owned(),
        provider_id: value.capacity_requirement.provider_id.clone(),
        account_profile_locator: "second-watch-qualification-profile".to_owned(),
        model_family: None,
        observed_at: at - Duration::seconds(1),
        expires_at: at + Duration::minutes(10),
        source_class: SourceClass::Observed,
        confidence: Confidence::High,
        disposition: ObservationDisposition::Usable,
        unknown_reasons: vec![],
        windows: vec![
            CapacityWindow {
                window_id: "five-hour".to_owned(),
                window_type: WindowType::FiveHour,
                remaining_fraction: Some(0.9),
                remaining_units: None,
                resets_at: Some(at + Duration::hours(1)),
            },
            CapacityWindow {
                window_id: "weekly".to_owned(),
                window_type: WindowType::Weekly,
                remaining_fraction: Some(0.9),
                remaining_units: None,
                resets_at: Some(at + Duration::days(1)),
            },
        ],
        evidence: ObservationEvidence {
            probe_id: format!("second-watch-fuel-{work_item_id}"),
            protocol_method: "qualification/read".to_owned(),
            protocol_version: Some("qualification/v1".to_owned()),
            executable_path: Some("/qualification/fuel-observer".to_owned()),
            executable_digest: Some(format!("sha256:{}", "1".repeat(64))),
            raw_source_digest: format!("sha256:{}", "2".repeat(64)),
        },
        observation_digest: String::new(),
    };
    observation.observation_digest = observation.compute_digest().unwrap();
    let decision = decide_capacity(&observation, &value.capacity_policy, at).unwrap();
    let mut admission = ForemanCapacityAdmissionV1 {
        schema: FOREMAN_CAPACITY_ADMISSION_SCHEMA_V1.to_owned(),
        capacity_admission_digest: placeholder(),
        packet_digest: value.packet.packet_digest.clone(),
        admission_digest: value.admission.admission_digest.clone(),
        profile_digest: value.profile.profile_digest.clone(),
        capacity_requirement_digest: value
            .capacity_requirement
            .capacity_requirement_digest
            .clone(),
        run_id: value.admission.run_id.clone(),
        work_item_id: work_item_id.to_owned(),
        adapter_id: value.profile.work_items[work_item_id].adapter_id.clone(),
        provider_id: observation.provider_id.clone(),
        packet_model_class: value
            .packet
            .work_items
            .iter()
            .find(|work| work.id == work_item_id)
            .unwrap()
            .model_routing
            .class
            .clone(),
        profile_model_class: value.profile.work_items[work_item_id]
            .provider_model_class
            .clone(),
        cost_class: CapacityCostClassV1::Cheap,
        policy_id: value.capacity_policy.policy_id.clone(),
        observation_digest: observation.observation_digest.clone(),
        policy_digest: value.capacity_policy.policy_digest.clone(),
        decision_digest: decision.decision_digest.clone(),
        evaluated_at: at,
        speculative_requested: false,
        authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".to_owned(),
    };
    admission.seal().unwrap();
    [
        canonical(&admission),
        canonical(&observation),
        canonical(&value.capacity_policy),
        canonical(&decision),
    ]
}

fn golden_prepare(
    store: &ForemanStore,
    value: &Fixture,
    work_item_id: &str,
    dispatch_occurrence_id: &str,
    adapter_process_occurrence_id: &str,
    session_identity: &str,
    at: DateTime<Utc>,
) -> OpenedProviderDispatchV1 {
    let capacity = golden_capacity_bundle(value, work_item_id, at);
    store
        .prepare_provider_attempt_with_capacity(
            &value.plan.run_id,
            work_item_id,
            CapacityAdmissionEvidenceV1 {
                admission_bytes: &capacity[0],
                observation_bytes: &capacity[1],
                policy_bytes: &capacity[2],
                decision_bytes: &capacity[3],
            },
            dispatch_occurrence_id,
            adapter_process_occurrence_id,
            session_identity,
            0,
            at,
        )
        .unwrap()
}

fn golden_record_unavailable(
    store: &ForemanStore,
    value: &Fixture,
    opened: &OpenedProviderDispatchV1,
    received_at: DateTime<Utc>,
) -> ProviderAdmissionDispositionV1 {
    let observed_at = received_at - Duration::seconds(1);
    let retry_after = received_at + Duration::seconds(5);
    let raw = canonical(&json!({
        "outcome": "PROVIDER_UNAVAILABLE",
        "response_created": false,
        "non_admission_proven": true,
        "retry_after": retry_after,
        "observed_at": observed_at,
        "provider_execution": null,
    }));
    let mut evidence = DeterministicProviderAdmissionEvidenceV2 {
        schema: DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V2.to_owned(),
        evidence_digest: placeholder(),
        producer_id: HOLDING_QUALIFICATION_PRODUCER_ID.to_owned(),
        producer_version: SECOND_WATCH_QUALIFICATION_PRODUCER_VERSION.to_owned(),
        executable_id: SECOND_WATCH_QUALIFICATION_EXECUTABLE_ID.to_owned(),
        executable_sha256: SECOND_WATCH_QUALIFICATION_EXECUTABLE_SHA256.to_owned(),
        work_attempt_id: opened.dispatch.work_attempt_id.clone(),
        dispatch_occurrence_id: opened.dispatch.dispatch_occurrence_id.clone(),
        provider_request_occurrence_id: format!(
            "qualification-request-{}",
            opened.dispatch.dispatch_occurrence_id
        ),
        provider_id: opened.dispatch.selection.provider_id.clone(),
        model_id: opened.dispatch.selection.model_id.clone(),
        outcome: DeterministicProviderAdmissionOutcomeV2::ProviderUnavailable,
        response_created: false,
        non_admission_proven: true,
        retry_after: Some(retry_after),
        observed_at,
        received_at,
        provider_execution: None,
        raw_evidence: ExactAvailabilityEvidenceV1::from_bytes(
            "EXACT_PROVIDER_AVAILABILITY_SOURCE_BYTES",
            &raw,
        )
        .unwrap(),
        authority_effect: "QUALIFICATION_MECHANISM_EVIDENCE_ONLY".to_owned(),
    };
    evidence.seal().unwrap();
    let evidence_bytes = canonical(&evidence);
    let mut disposition = ProviderAdmissionDispositionV1 {
        schema: PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V3.to_owned(),
        disposition_digest: placeholder(),
        dispatch_digest: opened.dispatch.dispatch_digest.clone(),
        requirement_digest: value.availability_requirement.requirement_digest.clone(),
        policy_digest: value.availability_policy.policy_digest.clone(),
        packet_digest: value.packet.packet_digest.clone(),
        run_id: value.admission.run_id.clone(),
        work_item_id: opened.dispatch.work_item_id.clone(),
        work_attempt_id: opened.dispatch.work_attempt_id.clone(),
        dispatch_occurrence_id: opened.dispatch.dispatch_occurrence_id.clone(),
        provider_id: opened.dispatch.selection.provider_id.clone(),
        model_id: opened.dispatch.selection.model_id.clone(),
        provider_request_occurrence_id: evidence.provider_request_occurrence_id.clone(),
        adapter_process_occurrence_id: opened.dispatch.adapter_process_occurrence_id.clone(),
        app_server_session_identity: opened.dispatch.app_server_session_identity.clone(),
        thread_id: format!("thread-{}", opened.dispatch.dispatch_occurrence_id),
        turn_id: format!("turn-{}", opened.dispatch.dispatch_occurrence_id),
        disposition: ProviderAdmissionDispositionKindV1::NotAdmittedProviderUnavailable,
        mechanism_state: ProviderMechanismStateV1::ParkedNotAdmitted,
        received_at,
        response_created: false,
        will_retry: false,
        acquisition_complete: true,
        provider_retry_after: Some(retry_after),
        provider_execution: None,
        mapper_snapshot_schema: DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V2.to_owned(),
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
        observation_digest: placeholder(),
        provider_id: disposition.provider_id.clone(),
        model_id: disposition.model_id.clone(),
        model_class: opened.dispatch.selection.model_class.clone(),
        observed_at,
        received_at,
        expires_at: received_at + Duration::minutes(1),
        state: ExecutionAvailabilityStateV1::ProviderUnavailable,
        source_identity: HOLDING_QUALIFICATION_PRODUCER_ID.to_owned(),
        source_version: SECOND_WATCH_QUALIFICATION_PRODUCER_VERSION.to_owned(),
        provider_retry_after: Some(retry_after),
        exact_evidence: Some(evidence.raw_evidence),
        authority_effect: "SCHEDULING_MECHANISM_EVIDENCE_ONLY".to_owned(),
    };
    observation.seal().unwrap();
    let mut deferred = DeferredProviderDispatchV1 {
        schema: DEFERRED_PROVIDER_DISPATCH_SCHEMA_V1.to_owned(),
        deferred_dispatch_digest: placeholder(),
        requirement_digest: value.availability_requirement.requirement_digest.clone(),
        policy_digest: value.availability_policy.policy_digest.clone(),
        disposition_digest: disposition.disposition_digest.clone(),
        packet_digest: value.packet.packet_digest.clone(),
        run_id: value.admission.run_id.clone(),
        work_item_id: opened.dispatch.work_item_id.clone(),
        work_attempt_id: opened.dispatch.work_attempt_id.clone(),
        last_dispatch_occurrence_id: opened.dispatch.dispatch_occurrence_id.clone(),
        provider_id: opened.dispatch.selection.provider_id.clone(),
        model_id: opened.dispatch.selection.model_id.clone(),
        selected_model_ordinal: opened.dispatch.selected_model_ordinal,
        remaining_model_ordinals: vec![],
        refusal_received_at: disposition.received_at,
        wake_basis: DeferredWakeBasisV1::ProviderRetryAfter,
        backoff_ordinal: opened.dispatch.dispatch_ordinal - 1,
        backoff_seconds: 5,
        provider_retry_after: Some(retry_after),
        wake_at: retry_after,
        parked_resource_lock_policy: value.availability_policy.parked_resource_lock_policy,
        provider_capacity_released: true,
        semantic_retry: false,
        authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".to_owned(),
    };
    deferred.seal().unwrap();
    let observation_bytes = canonical(&observation);
    let disposition_bytes = canonical(&disposition);
    let deferred_bytes = canonical(&deferred);
    store
        .record_provider_disposition(
            &value.admission.run_id,
            &opened.dispatch.work_item_id,
            &opened.dispatch.work_attempt_id,
            ProviderDispositionEvidenceV1 {
                observation_bytes: &observation_bytes,
                disposition_bytes: &disposition_bytes,
                deferred_bytes: Some(&deferred_bytes),
            },
            None,
        )
        .unwrap()
}

fn golden_record_completed(
    store: &ForemanStore,
    value: &Fixture,
    opened: &OpenedProviderDispatchV1,
    received_at: DateTime<Utc>,
) -> ProviderAdmissionDispositionV1 {
    let observed_at = received_at - Duration::seconds(1);
    let execution = ProviderExecutionIdentityV1 {
        provider_id: opened.dispatch.selection.provider_id.clone(),
        model_id: opened.dispatch.selection.model_id.clone(),
        app_server_session_identity: opened.dispatch.app_server_session_identity.clone(),
        thread_id: format!("thread-{}", opened.dispatch.dispatch_occurrence_id),
        turn_id: format!("turn-{}", opened.dispatch.dispatch_occurrence_id),
        first_response_id: format!("response-{}", opened.dispatch.dispatch_occurrence_id),
    };
    let raw = canonical(&json!({
        "outcome": "EXECUTION_COMPLETED",
        "response_created": true,
        "non_admission_proven": false,
        "retry_after": null,
        "observed_at": observed_at,
        "provider_execution": execution,
    }));
    let mut evidence = DeterministicProviderAdmissionEvidenceV2 {
        schema: DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V2.to_owned(),
        evidence_digest: placeholder(),
        producer_id: HOLDING_QUALIFICATION_PRODUCER_ID.to_owned(),
        producer_version: SECOND_WATCH_QUALIFICATION_PRODUCER_VERSION.to_owned(),
        executable_id: SECOND_WATCH_QUALIFICATION_EXECUTABLE_ID.to_owned(),
        executable_sha256: SECOND_WATCH_QUALIFICATION_EXECUTABLE_SHA256.to_owned(),
        work_attempt_id: opened.dispatch.work_attempt_id.clone(),
        dispatch_occurrence_id: opened.dispatch.dispatch_occurrence_id.clone(),
        provider_request_occurrence_id: format!(
            "qualification-request-{}",
            opened.dispatch.dispatch_occurrence_id
        ),
        provider_id: opened.dispatch.selection.provider_id.clone(),
        model_id: opened.dispatch.selection.model_id.clone(),
        outcome: DeterministicProviderAdmissionOutcomeV2::ExecutionCompleted,
        response_created: true,
        non_admission_proven: false,
        retry_after: None,
        observed_at,
        received_at,
        provider_execution: Some(execution.clone()),
        raw_evidence: ExactAvailabilityEvidenceV1::from_bytes(
            "EXACT_PROVIDER_AVAILABILITY_SOURCE_BYTES",
            &raw,
        )
        .unwrap(),
        authority_effect: "QUALIFICATION_MECHANISM_EVIDENCE_ONLY".to_owned(),
    };
    evidence.seal().unwrap();
    let mut substituted_evidence = evidence.clone();
    substituted_evidence.producer_version = HOLDING_QUALIFICATION_PRODUCER_VERSION.to_owned();
    assert!(substituted_evidence.seal().is_err());
    let mut substituted_evidence = evidence.clone();
    substituted_evidence.executable_sha256 = HOLDING_QUALIFICATION_EXECUTABLE_SHA256.to_owned();
    assert!(substituted_evidence.seal().is_err());
    let evidence_bytes = canonical(&evidence);
    let mut disposition = ProviderAdmissionDispositionV1 {
        schema: PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V3.to_owned(),
        disposition_digest: placeholder(),
        dispatch_digest: opened.dispatch.dispatch_digest.clone(),
        requirement_digest: value.availability_requirement.requirement_digest.clone(),
        policy_digest: value.availability_policy.policy_digest.clone(),
        packet_digest: value.packet.packet_digest.clone(),
        run_id: value.admission.run_id.clone(),
        work_item_id: opened.dispatch.work_item_id.clone(),
        work_attempt_id: opened.dispatch.work_attempt_id.clone(),
        dispatch_occurrence_id: opened.dispatch.dispatch_occurrence_id.clone(),
        provider_id: opened.dispatch.selection.provider_id.clone(),
        model_id: opened.dispatch.selection.model_id.clone(),
        provider_request_occurrence_id: evidence.provider_request_occurrence_id.clone(),
        adapter_process_occurrence_id: opened.dispatch.adapter_process_occurrence_id.clone(),
        app_server_session_identity: opened.dispatch.app_server_session_identity.clone(),
        thread_id: execution.thread_id.clone(),
        turn_id: execution.turn_id.clone(),
        disposition: ProviderAdmissionDispositionKindV1::ExecutionAdmitted,
        mechanism_state: ProviderMechanismStateV1::ProviderCompleted,
        received_at,
        response_created: true,
        will_retry: false,
        acquisition_complete: true,
        provider_retry_after: None,
        provider_execution: Some(execution),
        mapper_snapshot_schema: DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V2.to_owned(),
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
        observation_digest: placeholder(),
        provider_id: disposition.provider_id.clone(),
        model_id: disposition.model_id.clone(),
        model_class: opened.dispatch.selection.model_class.clone(),
        observed_at,
        received_at,
        expires_at: received_at + Duration::minutes(1),
        state: ExecutionAvailabilityStateV1::Available,
        source_identity: HOLDING_QUALIFICATION_PRODUCER_ID.to_owned(),
        source_version: SECOND_WATCH_QUALIFICATION_PRODUCER_VERSION.to_owned(),
        provider_retry_after: None,
        exact_evidence: Some(evidence.raw_evidence),
        authority_effect: "SCHEDULING_MECHANISM_EVIDENCE_ONLY".to_owned(),
    };
    observation.seal().unwrap();
    let mut substituted_requirement = value.availability_requirement.clone();
    substituted_requirement.adapter_protocol = "switchyard.codex-app-server/v2".to_owned();
    substituted_requirement.seal().unwrap();
    let mut substituted_dispatch = opened.dispatch.clone();
    substituted_dispatch.requirement_digest = substituted_requirement.requirement_digest.clone();
    substituted_dispatch.adapter_protocol = "switchyard.codex-app-server/v2".to_owned();
    substituted_dispatch.seal().unwrap();
    let mut substituted_disposition = disposition.clone();
    substituted_disposition.requirement_digest = substituted_requirement.requirement_digest.clone();
    substituted_disposition.dispatch_digest = substituted_dispatch.dispatch_digest.clone();
    substituted_disposition.seal().unwrap();
    assert!(validate_execution_availability_graph(
        &substituted_requirement,
        &value.availability_policy,
        &substituted_dispatch,
        &observation,
        &substituted_disposition,
        &[],
        None,
    )
    .is_err());
    let observation_bytes = canonical(&observation);
    let disposition_bytes = canonical(&disposition);
    store
        .record_provider_disposition(
            &value.admission.run_id,
            &opened.dispatch.work_item_id,
            &opened.dispatch.work_attempt_id,
            ProviderDispositionEvidenceV1 {
                observation_bytes: &observation_bytes,
                disposition_bytes: &disposition_bytes,
                deferred_bytes: None,
            },
            None,
        )
        .unwrap()
}

fn golden_terminal(
    value: &Fixture,
    opened: &OpenedProviderDispatchV1,
    disposition: &ProviderAdmissionDispositionV1,
    started_at: DateTime<Utc>,
    ended_at: DateTime<Utc>,
    human_questions: Vec<HumanQuestionV1>,
) -> TerminalReceiptV1 {
    let execution = disposition.provider_execution.as_ref().unwrap();
    let mut receipt = TerminalReceiptV1 {
        schema: WORKER_TERMINAL_RECEIPT_SCHEMA_V1.to_owned(),
        receipt_digest: placeholder(),
        packet_digest: value.packet.packet_digest.clone(),
        run_id: value.admission.run_id.clone(),
        work_item_id: opened.dispatch.work_item_id.clone(),
        attempt_id: opened.dispatch.work_attempt_id.clone(),
        adapter_id: HOLDING_QUALIFICATION_PRODUCER_ID.to_owned(),
        adapter_version: SECOND_WATCH_QUALIFICATION_PRODUCER_VERSION.to_owned(),
        provider_identity: execution.provider_id.clone(),
        model_identity: execution.model_id.clone(),
        session_identity: Some(execution.app_server_session_identity.clone()),
        thread_identity: Some(execution.thread_id.clone()),
        turn_identity: Some(execution.turn_id.clone()),
        queue_identity: None,
        started_at,
        ended_at,
        state: if human_questions.is_empty() {
            "QUALIFICATION-COMPLETE-EXACT".to_owned()
        } else {
            "BLOCKED-HUMAN-EXACT".to_owned()
        },
        result_classification: if human_questions.is_empty() {
            "SECOND-WATCH-DETERMINISTIC-FIXTURE".to_owned()
        } else {
            "SECOND-WATCH-PRESENTATION-ONLY-QUESTION".to_owned()
        },
        repositories: vec![ReceiptRepositoryV1 {
            repository: "nightshift".to_owned(),
            branch: "campaign/second-watch-fixture".to_owned(),
            head: "f".repeat(40),
            push_status: "sole-local qualification fixture".to_owned(),
        }],
        tests: vec!["bounded deterministic fake journey".to_owned()],
        evidence: vec!["exact FUEL and HOLDING graph retained".to_owned()],
        live_or_production_mutations: vec![],
        remaining_trigger: if human_questions.is_empty() {
            "none".to_owned()
        } else {
            "explicit successor authority".to_owned()
        },
        next_lawful_action: "inspect exact retained receipt".to_owned(),
        human_questions,
        teardown: TeardownDeclarationV1 {
            live_runtime: "none".to_owned(),
            secrets: "none".to_owned(),
            teardown: "temporary directory removed by fixture owner".to_owned(),
        },
        extensions: BTreeMap::new(),
    };
    receipt.seal().unwrap();
    receipt
}

#[test]
fn second_watch_self_hosted_golden_journey_is_restartable_and_query_only() {
    let fake_v2 = include_bytes!(
        "../../../qualification/provider-execution-availability-and-deferred-dispatch-v1-20260831/fixtures/deterministic-fake-adapter-v2.py"
    );
    assert_eq!(
        format!("sha256:{:x}", Sha256::digest(fake_v2)),
        SECOND_WATCH_QUALIFICATION_EXECUTABLE_SHA256
    );
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("foreman.sqlite3");
    let value = fixture();
    let run_id = admit_fixture(&path, &value);
    let store = ForemanStore::open(&path).unwrap();

    let first_step = store
        .advance_self_hosted_driver(
            &run_id,
            &value.plan.bootstrap_digest,
            1,
            "second-watch-scheduler-process-1",
            time(2),
        )
        .unwrap();
    assert_eq!(
        first_step.disposition,
        SelfHostedDriverDispositionV1::ReadyWorkPresent
    );

    let lane_a = golden_prepare(
        &store,
        &value,
        "lane-a",
        "second-watch-dispatch-a-1",
        "second-watch-process-a-1",
        "second-watch-session-a-1",
        time(3),
    );
    let lane_b = golden_prepare(
        &store,
        &value,
        "lane-b",
        "second-watch-dispatch-b-1",
        "second-watch-process-b-1",
        "second-watch-session-b-1",
        time(4),
    );
    assert_ne!(
        lane_a.dispatch.work_attempt_id,
        lane_b.dispatch.work_attempt_id
    );
    let parked = golden_record_unavailable(&store, &value, &lane_a, time(5));
    assert_eq!(
        parked.mechanism_state,
        ProviderMechanismStateV1::ParkedNotAdmitted
    );
    assert!(!parked.response_created);
    assert!(parked.provider_execution.is_none());

    let completed_b = golden_record_completed(&store, &value, &lane_b, time(6));
    let receipt_b = golden_terminal(&value, &lane_b, &completed_b, time(4), time(7), vec![]);
    store
        .accept_terminal_receipt(&canonical(&receipt_b))
        .unwrap();
    drop(store);

    let store = ForemanStore::open(&path).unwrap();
    let second_step = store
        .advance_self_hosted_driver(
            &run_id,
            &value.plan.bootstrap_digest,
            2,
            "second-watch-scheduler-process-restarted",
            time(8),
        )
        .unwrap();
    assert_eq!(second_step.step_ordinal, 2);

    let woken_a = store
        .wake_provider_dispatch(
            &run_id,
            "lane-a",
            &lane_a.dispatch.work_attempt_id,
            "second-watch-wake-a-1",
            "second-watch-dispatch-a-2",
            "second-watch-process-a-2",
            "second-watch-session-a-2",
            0,
            parked.provider_retry_after.unwrap(),
        )
        .unwrap();
    assert_eq!(
        woken_a.dispatch.work_attempt_id,
        lane_a.dispatch.work_attempt_id
    );
    assert_ne!(
        woken_a.dispatch.dispatch_occurrence_id,
        lane_a.dispatch.dispatch_occurrence_id
    );
    let completed_a = golden_record_completed(&store, &value, &woken_a, time(11));
    let receipt_a = golden_terminal(&value, &woken_a, &completed_a, time(10), time(12), vec![]);
    store
        .accept_terminal_receipt(&canonical(&receipt_a))
        .unwrap();

    let question_lane = golden_prepare(
        &store,
        &value,
        "question",
        "second-watch-dispatch-question-1",
        "second-watch-process-question-1",
        "second-watch-session-question-1",
        time(13),
    );
    let completed_question = golden_record_completed(&store, &value, &question_lane, time(14));
    let question = HumanQuestionV1 {
        question_id: "second-watch-presentation-only-question".to_owned(),
        question: "Is protected target-effect authority present for this fixture lane?".to_owned(),
        exhausted_evidence:
            "The admitted bootstrap and deterministic fake carry no target-effect authority."
                .to_owned(),
        safe_default: "Do not perform a protected effect or answer an approval request.".to_owned(),
        consequences:
            "Only this lane retains the question; independent exact receipts remain unchanged."
                .to_owned(),
        resume_point: "Create a successor occurrence after exact external authority exists."
            .to_owned(),
    };
    let question_receipt = golden_terminal(
        &value,
        &question_lane,
        &completed_question,
        time(13),
        time(15),
        vec![question.clone()],
    );
    store
        .accept_terminal_receipt(&canonical(&question_receipt))
        .unwrap();

    let closeout = golden_prepare(
        &store,
        &value,
        "closeout",
        "second-watch-dispatch-closeout-1",
        "second-watch-process-closeout-1",
        "second-watch-session-closeout-1",
        time(16),
    );
    let completed_closeout = golden_record_completed(&store, &value, &closeout, time(17));
    let closeout_receipt = golden_terminal(
        &value,
        &closeout,
        &completed_closeout,
        time(16),
        time(18),
        vec![],
    );
    store
        .accept_terminal_receipt(&canonical(&closeout_receipt))
        .unwrap();

    let final_step = store
        .advance_self_hosted_driver(
            &run_id,
            &value.plan.bootstrap_digest,
            3,
            "second-watch-scheduler-process-restarted",
            time(19),
        )
        .unwrap();
    assert_eq!(
        final_step.disposition,
        SelfHostedDriverDispositionV1::AllItemsExplicitTerminal
    );

    let live = nightshift_casework::load_live_run_at(&path, &run_id, time(19)).unwrap();
    assert_eq!(live.projection.work_items.len(), 4);
    let questions: Vec<_> = live
        .projection
        .work_items
        .iter()
        .flat_map(|item| &item.human_questions)
        .collect();
    assert_eq!(questions.len(), 1);
    assert_eq!(questions[0].question_id, question.question_id);
    assert_eq!(questions[0].question, question.question);
    assert_eq!(questions[0].exhausted_evidence, question.exhausted_evidence);
    assert_eq!(questions[0].safe_default, question.safe_default);
    assert_eq!(questions[0].consequences, question.consequences);
    assert_eq!(questions[0].resume_point, question.resume_point);
    assert!(serde_json::to_value(&live.projection)
        .unwrap()
        .get("aggregate_result")
        .is_none());

    let final_receipts = store.close(&run_id, time(20)).unwrap();
    let final_value: Value = serde_json::from_slice(&final_receipts).unwrap();
    assert_eq!(final_value["schema"], "nightshift.run-receipts/v1");
    assert_eq!(final_value["work_items"].as_array().unwrap().len(), 4);
    drop(store);

    let read_only = ForemanStore::open_read_only(&path).unwrap();
    let bootstrap = read_only.self_hosted_bootstrap(&run_id).unwrap();
    assert_eq!(bootstrap.steps, vec![first_step, second_step, final_step]);
    let snapshot = read_only.read_only_run_snapshot(&run_id).unwrap();
    assert_eq!(snapshot.capacity_admissions.len(), 4);
    let execution = snapshot.execution_availability.unwrap();
    assert_eq!(execution.dispatches.len(), 5);
    assert_eq!(execution.dispositions.len(), 5);
    assert_eq!(execution.deferred.len(), 1);
    assert_eq!(execution.resource_transitions.len(), 2);
    assert!(execution
        .dispositions
        .iter()
        .all(|item| !item.approval_response_sent && item.protected_effect_absent));
    assert!(execution.deferred.iter().all(|item| !item.semantic_retry));
    drop(read_only);

    let sealed = directory.path().join("sealed");
    std::fs::create_dir(&sealed).unwrap();
    std::fs::write(sealed.join("packet.v1.json"), canonical(&value.packet)).unwrap();
    std::fs::write(sealed.join("run-receipts.v1.json"), &final_receipts).unwrap();
    let sealed_case = nightshift_casework::load_run_at(&sealed, time(20)).unwrap();
    assert_eq!(sealed_case.receipt_bytes, final_receipts);
    assert_eq!(sealed_case.projection.work_items.len(), 4);
    assert!(serde_json::to_value(&sealed_case.projection)
        .unwrap()
        .get("aggregate_result")
        .is_none());

    if let Some(output) = std::env::var_os("NIGHTSHIFT_SECOND_WATCH_GOLDEN_DIR") {
        let output = std::path::PathBuf::from(output);
        std::fs::create_dir_all(&output).unwrap();
        std::fs::write(output.join("packet.v1.json"), canonical(&value.packet)).unwrap();
        std::fs::write(output.join("run-receipts.v1.json"), &final_receipts).unwrap();
        std::fs::copy(&path, output.join("foreman.sqlite3")).unwrap();
    }
}

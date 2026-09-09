use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use nightshift_foreman::{
    AdapterRegistrationV2, ExecutionProfileV2, ForemanExecutionAvailabilityRequirementV1,
    ProviderAdmissionOwnerPinsV1, ProviderDispatchOccurrenceV1, ProviderModelSelectionV1,
    WorkItemExecutionV1, WorkerStartRequestV2, WorkerStartRequestV3,
    DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V1,
    FOREMAN_EXECUTION_AVAILABILITY_REQUIREMENT_SCHEMA_V1, FOREMAN_EXECUTION_PROFILE_SCHEMA_V2,
    HOLDING_QUALIFICATION_EXECUTABLE_SHA256, HOLDING_QUALIFICATION_PRODUCER_ID,
    HOLDING_QUALIFICATION_PRODUCER_VERSION, PROVIDER_DISPATCH_OCCURRENCE_SCHEMA_V1,
    SECOND_WATCH_QUALIFICATION_PRODUCER_VERSION, WORKER_START_REQUEST_SCHEMA_V2,
    WORKER_START_REQUEST_SCHEMA_V3, WORKER_TERMINAL_RECEIPT_SCHEMA_V1,
};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

type V3Substitution = Box<dyn Fn(&mut WorkerStartRequestV3)>;

#[test]
fn explicit_beta_owner_tuple_preserves_requirement_binding_without_fallback() {
    check_candidate_tuple(ProviderAdmissionOwnerPinsV1::beta_candidate());
    check_candidate_tuple(ProviderAdmissionOwnerPinsV1::final_beta_candidate());
    let mut hybrid = ProviderAdmissionOwnerPinsV1::final_beta_candidate();
    hybrid.switchyard_owner_head =
        ProviderAdmissionOwnerPinsV1::beta_candidate().switchyard_owner_head;
    assert!(hybrid.validate().is_err());
    let mut hybrid = ProviderAdmissionOwnerPinsV1::final_beta_candidate();
    hybrid.switchyard_schema_sha256 =
        ProviderAdmissionOwnerPinsV1::beta_candidate().switchyard_schema_sha256;
    assert!(hybrid.validate().is_err());
}

fn check_candidate_tuple(pins: ProviderAdmissionOwnerPinsV1) {
    let profile = profile();
    let mut requirement = requirement(&profile);
    requirement.owner_pins = pins;
    requirement.seal().unwrap();
    let request = WorkerStartRequestV3::from_v2_for_dispatch(
        &canonical(&v2()),
        &profile,
        &requirement,
        "dispatch-beta-1",
        0,
    )
    .unwrap();
    assert_eq!(
        request.codex_owner_head,
        requirement.owner_pins.codex_owner_head
    );
    assert_eq!(
        request.switchyard_owner_head,
        requirement.owner_pins.switchyard_owner_head
    );
    request
        .validate_dispatch_graph(&profile, &requirement, &dispatch(&request, &requirement))
        .unwrap();
    let mut mixed = request.clone();
    mixed.switchyard_owner_head = ProviderAdmissionOwnerPinsV1::accepted().switchyard_owner_head;
    assert!(mixed.seal().is_err() || mixed.validate().is_err());
    let mut old_requirement = requirement.clone();
    old_requirement.owner_pins = ProviderAdmissionOwnerPinsV1::accepted();
    old_requirement.seal().unwrap();
    assert!(request
        .validate_dispatch_graph(
            &profile,
            &old_requirement,
            &dispatch(&request, &old_requirement)
        )
        .is_err());
}

fn digest(fill: char) -> String {
    format!("sha256:{}", fill.to_string().repeat(64))
}

fn v2() -> WorkerStartRequestV2 {
    let mut request = WorkerStartRequestV2 {
        schema: WORKER_START_REQUEST_SCHEMA_V2.to_owned(),
        request_digest: digest('0'),
        adapter_id: "switchyard-codex".to_owned(),
        adapter_version: "2.0.0".to_owned(),
        adapter_protocol: "switchyard.codex-app-server/v2".to_owned(),
        packet_digest: digest('1'),
        run_id: "run-holding".to_owned(),
        work_item_id: "WORK-A".to_owned(),
        attempt_id: "attempt-holding-1".to_owned(),
        worker_brief_digest: digest('2'),
        workspace_identity: "workspace-holding".to_owned(),
        provider_model_class: "large".to_owned(),
        timeout_seconds: 600,
        maximum_output_bytes: 1024 * 1024,
        recursive_worker_swarms_forbidden: true,
        approval_policy: "SURFACE_ONLY_NO_RESPONSE".to_owned(),
        expected_receipt_schema: WORKER_TERMINAL_RECEIPT_SCHEMA_V1.to_owned(),
    };
    request.seal().unwrap();
    request
}

fn canonical<T: serde::Serialize>(value: &T) -> Vec<u8> {
    serde_jcs::to_vec(value).unwrap()
}

fn time(value: &str) -> DateTime<Utc> {
    value.parse().unwrap()
}

fn profile() -> ExecutionProfileV2 {
    let mut profile = ExecutionProfileV2 {
        schema: FOREMAN_EXECUTION_PROFILE_SCHEMA_V2.to_owned(),
        profile_digest: digest('0'),
        packet_digest: digest('1'),
        admission_digest: digest('8'),
        adapters: BTreeMap::from([(
            "switchyard-codex".to_owned(),
            AdapterRegistrationV2 {
                adapter_id: "switchyard-codex".to_owned(),
                protocol: "switchyard.codex-app-server/v2".to_owned(),
                adapter_version: "2.0.0".to_owned(),
                executable_identity: digest('9'),
                bounded_arguments: vec![],
            },
        )]),
        work_items: BTreeMap::from([(
            "WORK-A".to_owned(),
            WorkItemExecutionV1 {
                adapter_id: "switchyard-codex".to_owned(),
                workspace_identity: "workspace-holding".to_owned(),
                resource_lock_keys: vec!["provider-slot".to_owned()],
                provider_model_class: "large".to_owned(),
            },
        )]),
        budget_policy_ref: "fuel-policy".to_owned(),
        log_custody_root: "/tmp/nightshift-holding/log".to_owned(),
        receipt_custody_root: "/tmp/nightshift-holding/receipt".to_owned(),
        maximum_event_bytes: 1024 * 1024,
        maximum_receipt_bytes: 1024 * 1024,
        adapter_timeout_seconds: 600,
        closeout_policy: "ALL_EXPLICIT_TERMINAL_OR_NOT_STARTED".to_owned(),
    };
    profile.seal().unwrap();
    profile
}

fn requirement(profile: &ExecutionProfileV2) -> ForemanExecutionAvailabilityRequirementV1 {
    let mut requirement = ForemanExecutionAvailabilityRequirementV1 {
        schema: FOREMAN_EXECUTION_AVAILABILITY_REQUIREMENT_SCHEMA_V1.to_owned(),
        requirement_digest: digest('0'),
        packet_digest: profile.packet_digest.clone(),
        admission_digest: profile.admission_digest.clone(),
        profile_digest: profile.profile_digest.clone(),
        run_id: "run-holding".to_owned(),
        adapter_id: "switchyard-codex".to_owned(),
        adapter_protocol: "switchyard.codex-app-server/v2".to_owned(),
        adapter_version: "2.0.0".to_owned(),
        adapter_executable_identity: digest('9'),
        owner_pins: ProviderAdmissionOwnerPinsV1::accepted(),
        policy_id: "holding-policy".to_owned(),
        policy_digest: digest('a'),
        work_item_model_selections: BTreeMap::from([(
            "WORK-A".to_owned(),
            vec![ProviderModelSelectionV1 {
                provider_id: "openai".to_owned(),
                model_id: "gpt-5.6-sol".to_owned(),
                model_class: "large".to_owned(),
            }],
        )]),
        admitted_at: time("2026-08-31T12:00:00Z"),
        authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".to_owned(),
    };
    requirement.seal().unwrap();
    requirement
}

fn v3() -> WorkerStartRequestV3 {
    let profile = profile();
    let requirement = requirement(&profile);
    WorkerStartRequestV3::from_v2_for_dispatch(
        &canonical(&v2()),
        &profile,
        &requirement,
        "dispatch-holding-1",
        0,
    )
    .unwrap()
}

fn dispatch(
    request: &WorkerStartRequestV3,
    requirement: &ForemanExecutionAvailabilityRequirementV1,
) -> ProviderDispatchOccurrenceV1 {
    let mut dispatch = ProviderDispatchOccurrenceV1 {
        schema: PROVIDER_DISPATCH_OCCURRENCE_SCHEMA_V1.to_owned(),
        dispatch_digest: digest('0'),
        requirement_digest: requirement.requirement_digest.clone(),
        policy_digest: requirement.policy_digest.clone(),
        packet_digest: requirement.packet_digest.clone(),
        run_id: request.run_id.clone(),
        work_item_id: request.work_item_id.clone(),
        work_attempt_id: request.work_attempt_id.clone(),
        dispatch_occurrence_id: request.dispatch_occurrence_id.clone(),
        dispatch_ordinal: 1,
        selected_model_ordinal: request.selected_model_ordinal,
        selection: ProviderModelSelectionV1 {
            provider_id: request.provider_id.clone(),
            model_id: request.model_id.clone(),
            model_class: request.model_class.clone(),
        },
        adapter_id: request.adapter_id.clone(),
        adapter_version: request.adapter_version.clone(),
        adapter_protocol: request.adapter_protocol.clone(),
        adapter_process_occurrence_id: "adapter-process-holding-1".to_owned(),
        app_server_session_identity: "app-server-session-holding-1".to_owned(),
        worker_start_request_schema: WORKER_START_REQUEST_SCHEMA_V3.to_owned(),
        worker_start_request_digest: request.request_digest.clone(),
        worker_brief_digest: request.worker_brief_digest.clone(),
        opened_at: time("2026-08-31T12:00:01Z"),
        internal_provider_retry_count: 0,
        provider_execution_id: None,
        authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".to_owned(),
    };
    dispatch.seal().unwrap();
    dispatch
}

#[test]
fn v3_retains_exact_v2_and_has_stable_independent_digest() {
    let request = v3();
    request.validate().unwrap();
    assert_eq!(request.predecessor_v2().unwrap(), v2());
    assert_eq!(request.work_attempt_id, request.attempt_id);
    assert_ne!(request.request_digest, request.predecessor_request_digest);
    assert_eq!(
        request.predecessor_sha256,
        format!("sha256:{:x}", Sha256::digest(canonical(&v2())))
    );
    let bytes = canonical(&request);
    assert_eq!(WorkerStartRequestV3::from_slice(&bytes).unwrap(), request);
    let profile = profile();
    let requirement = requirement(&profile);
    request
        .validate_dispatch_graph(&profile, &requirement, &dispatch(&request, &requirement))
        .unwrap();
    assert_eq!(
        request.request_digest,
        "sha256:91378debdc75baea723c3a8d6b0bddac4833373bd26d86c83f4ec7d642895829"
    );
}

#[test]
fn v3_graph_refuses_profile_selection_dispatch_and_identity_substitutions() {
    let profile = profile();
    let requirement = requirement(&profile);
    let request = WorkerStartRequestV3::from_v2_for_dispatch(
        &canonical(&v2()),
        &profile,
        &requirement,
        "dispatch-holding-1",
        0,
    )
    .unwrap();
    let exact_dispatch = dispatch(&request, &requirement);
    request
        .validate_dispatch_graph(&profile, &requirement, &exact_dispatch)
        .unwrap();

    let mut changed_profile = profile.clone();
    changed_profile.maximum_event_bytes += 1;
    changed_profile.seal().unwrap();
    let mut changed_requirement = requirement.clone();
    changed_requirement.profile_digest = changed_profile.profile_digest.clone();
    changed_requirement.seal().unwrap();
    assert!(request
        .validate_dispatch_graph(&changed_profile, &changed_requirement, &exact_dispatch)
        .is_err());

    for mutate in [
        |value: &mut ProviderDispatchOccurrenceV1| {
            value.selection.provider_id = "provider-other".to_owned()
        },
        |value: &mut ProviderDispatchOccurrenceV1| {
            value.selection.model_id = "model-other".to_owned()
        },
        |value: &mut ProviderDispatchOccurrenceV1| value.selected_model_ordinal = 1,
        |value: &mut ProviderDispatchOccurrenceV1| {
            value.dispatch_occurrence_id = "dispatch-other".to_owned()
        },
    ] {
        let mut changed = exact_dispatch.clone();
        mutate(&mut changed);
        changed.seal().unwrap();
        assert!(request
            .validate_dispatch_graph(&profile, &requirement, &changed)
            .is_err());
    }

    let mut changed_request = request.clone();
    changed_request.provider_id = "provider-other".to_owned();
    changed_request.seal().unwrap();
    let mut changed_dispatch = exact_dispatch.clone();
    changed_dispatch.selection.provider_id = changed_request.provider_id.clone();
    changed_dispatch.worker_start_request_digest = changed_request.request_digest.clone();
    changed_dispatch.seal().unwrap();
    assert!(changed_request
        .validate_dispatch_graph(&profile, &requirement, &changed_dispatch)
        .is_err());

    let mut early = exact_dispatch.clone();
    early.opened_at = time("2026-08-31T11:59:59Z");
    early.seal().unwrap();
    assert!(request
        .validate_dispatch_graph(&profile, &requirement, &early)
        .is_err());

    assert!(WorkerStartRequestV3::from_v2_for_dispatch(
        &canonical(&v2()),
        &profile,
        &requirement,
        "attempt-holding-1",
        0,
    )
    .is_err());
}

#[test]
fn v3_refuses_outer_predecessor_and_owner_pin_substitutions() {
    let base = v3();
    let substitutions: Vec<V3Substitution> = vec![
        Box::new(|value| value.packet_digest = digest('4')),
        Box::new(|value| value.run_id = "run-other".to_owned()),
        Box::new(|value| value.work_item_id = "WORK-B".to_owned()),
        Box::new(|value| value.attempt_id = "attempt-other".to_owned()),
        Box::new(|value| value.work_attempt_id = "attempt-other".to_owned()),
        Box::new(|value| value.adapter_id = "adapter-other".to_owned()),
        Box::new(|value| value.adapter_version = "9.0.0".to_owned()),
        Box::new(|value| value.adapter_protocol = "switchyard.other/v1".to_owned()),
        Box::new(|value| value.worker_brief_digest = digest('5')),
        Box::new(|value| value.workspace_identity = "workspace-other".to_owned()),
        Box::new(|value| value.provider_model_class = "medium".to_owned()),
        Box::new(|value| value.model_class = "medium".to_owned()),
        Box::new(|value| value.timeout_seconds += 1),
        Box::new(|value| value.maximum_output_bytes += 1),
        Box::new(|value| value.codex_owner_head = "0".repeat(40)),
        Box::new(|value| value.switchyard_owner_head = "0".repeat(40)),
        Box::new(|value| value.switchyard_schema_sha256 = digest('6')),
        Box::new(|value| value.switchyard_deterministic_fixture_sha256 = digest('7')),
        Box::new(|value| value.provider_execution_id = Some("execution-too-early".to_owned())),
        Box::new(|value| value.internal_provider_retry_count = 1),
        Box::new(|value| value.semantic_retry = true),
        Box::new(|value| value.approval_response_authorized = true),
    ];
    for substitute in substitutions {
        let mut changed = base.clone();
        substitute(&mut changed);
        assert!(changed.seal().is_err());
    }
}

#[test]
fn v3_refuses_coherently_resealed_or_noncanonical_predecessor() {
    let mut changed_v2 = v2();
    changed_v2.workspace_identity = "workspace-substituted".to_owned();
    changed_v2.seal().unwrap();
    let changed_bytes = canonical(&changed_v2);
    let mut changed = v3();
    changed.predecessor_request_digest = changed_v2.request_digest;
    changed.predecessor_sha256 = format!("sha256:{:x}", Sha256::digest(&changed_bytes));
    changed.predecessor_bytes_hex = hex::encode(&changed_bytes);
    assert!(changed.seal().is_err());

    let pretty = serde_json::to_vec_pretty(&v2()).unwrap();
    let mut noncanonical = v3();
    noncanonical.predecessor_sha256 = format!("sha256:{:x}", Sha256::digest(&pretty));
    noncanonical.predecessor_bytes_hex = hex::encode(pretty);
    assert!(noncanonical.seal().is_err());
}

#[test]
fn v2_remains_valid_and_v3_is_recursively_closed() {
    let predecessor = v2();
    predecessor.validate().unwrap();

    let request = v3();
    let mut value: Value = serde_json::from_slice(&canonical(&request)).unwrap();
    value["invented_authority"] = json!(true);
    assert!(serde_json::from_value::<WorkerStartRequestV3>(value).is_err());

    let mut noncanonical = canonical(&request);
    noncanonical.push(b' ');
    assert!(WorkerStartRequestV3::from_slice(&noncanonical).is_err());
}

fn qualification_v3_graph() -> (
    WorkerStartRequestV2,
    ExecutionProfileV2,
    ForemanExecutionAvailabilityRequirementV1,
    WorkerStartRequestV3,
) {
    let mut predecessor = v2();
    predecessor.adapter_id = HOLDING_QUALIFICATION_PRODUCER_ID.to_owned();
    predecessor.adapter_version = HOLDING_QUALIFICATION_PRODUCER_VERSION.to_owned();
    predecessor.adapter_protocol = DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V1.to_owned();
    predecessor.seal().unwrap();

    let mut profile = profile();
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
    profile.work_items.get_mut("WORK-A").unwrap().adapter_id =
        HOLDING_QUALIFICATION_PRODUCER_ID.to_owned();
    profile.seal().unwrap();

    let mut requirement = requirement(&profile);
    requirement.adapter_id = HOLDING_QUALIFICATION_PRODUCER_ID.to_owned();
    requirement.adapter_protocol = DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V1.to_owned();
    requirement.adapter_version = HOLDING_QUALIFICATION_PRODUCER_VERSION.to_owned();
    requirement.adapter_executable_identity = HOLDING_QUALIFICATION_EXECUTABLE_SHA256.to_owned();
    requirement.seal().unwrap();

    let request = WorkerStartRequestV3::from_v2_for_dispatch(
        &canonical(&predecessor),
        &profile,
        &requirement,
        "dispatch-holding-qualification-1",
        0,
    )
    .unwrap();
    (predecessor, profile, requirement, request)
}

#[test]
fn v3_qualification_branch_is_exactly_the_accepted_fake_tuple() {
    let (predecessor, profile, requirement, request) = qualification_v3_graph();
    assert_eq!(request.predecessor_v2().unwrap(), predecessor);
    assert_eq!(
        request.provider_admission_adapter_protocol,
        DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V1
    );
    assert_eq!(
        request.provider_admission_binding_schema,
        DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V1
    );
    assert_eq!(
        request.provider_admission_evidence_schema,
        DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V1
    );
    assert_eq!(
        request.provider_admission_snapshot_schema,
        DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V1
    );
    request
        .validate_dispatch_graph(&profile, &requirement, &dispatch(&request, &requirement))
        .unwrap();

    for substitute in [
        |value: &mut WorkerStartRequestV3| value.adapter_id = "qualification-other".to_owned(),
        |value: &mut WorkerStartRequestV3| value.adapter_version = "v2".to_owned(),
        |value: &mut WorkerStartRequestV3| {
            value.adapter_protocol = "qualification.other/v1".to_owned()
        },
        |value: &mut WorkerStartRequestV3| {
            value.provider_admission_adapter_protocol = "qualification.other/v1".to_owned()
        },
        |value: &mut WorkerStartRequestV3| {
            value.provider_admission_binding_schema = "qualification.other/v1".to_owned()
        },
        |value: &mut WorkerStartRequestV3| {
            value.provider_admission_evidence_schema = "qualification.other/v1".to_owned()
        },
        |value: &mut WorkerStartRequestV3| {
            value.provider_admission_snapshot_schema = "qualification.other/v1".to_owned()
        },
    ] {
        let mut changed = request.clone();
        substitute(&mut changed);
        assert!(changed.seal().is_err());
    }

    let mut changed_profile = profile.clone();
    changed_profile
        .adapters
        .get_mut(HOLDING_QUALIFICATION_PRODUCER_ID)
        .unwrap()
        .executable_identity = digest('e');
    changed_profile.seal().unwrap();
    let mut changed_requirement = requirement.clone();
    changed_requirement.profile_digest = changed_profile.profile_digest.clone();
    changed_requirement.adapter_executable_identity = digest('e');
    changed_requirement.seal().unwrap();
    assert!(WorkerStartRequestV3::from_v2_for_dispatch(
        &canonical(&predecessor),
        &changed_profile,
        &changed_requirement,
        "dispatch-holding-qualification-2",
        0,
    )
    .is_err());

    let mut changed_profile = profile;
    changed_profile
        .adapters
        .get_mut(HOLDING_QUALIFICATION_PRODUCER_ID)
        .unwrap()
        .bounded_arguments = vec!["--not-empty".to_owned()];
    changed_profile.seal().unwrap();
    let mut changed_requirement = requirement;
    changed_requirement.profile_digest = changed_profile.profile_digest.clone();
    changed_requirement.seal().unwrap();
    assert!(WorkerStartRequestV3::from_v2_for_dispatch(
        &canonical(&predecessor),
        &changed_profile,
        &changed_requirement,
        "dispatch-holding-qualification-3",
        0,
    )
    .is_err());
}

#[test]
fn reserved_qualification_id_cannot_coherently_migrate_to_switchyard_family() {
    let (mut predecessor, mut profile, mut requirement, _) = qualification_v3_graph();
    predecessor.adapter_protocol = "switchyard.codex-app-server/v2".to_owned();
    predecessor.seal().unwrap();
    let adapter = profile
        .adapters
        .get_mut(HOLDING_QUALIFICATION_PRODUCER_ID)
        .unwrap();
    adapter.protocol = "switchyard.codex-app-server/v2".to_owned();
    profile.seal().unwrap();
    requirement.profile_digest = profile.profile_digest.clone();
    requirement.adapter_protocol = "switchyard.codex-app-server/v2".to_owned();
    requirement.seal().unwrap();
    assert!(WorkerStartRequestV3::from_v2_for_dispatch(
        &canonical(&predecessor),
        &profile,
        &requirement,
        "dispatch-reserved-switchyard-refused",
        0,
    )
    .is_err());

    predecessor.adapter_version = SECOND_WATCH_QUALIFICATION_PRODUCER_VERSION.to_owned();
    predecessor.seal().unwrap();
    let adapter = profile
        .adapters
        .get_mut(HOLDING_QUALIFICATION_PRODUCER_ID)
        .unwrap();
    adapter.adapter_version = SECOND_WATCH_QUALIFICATION_PRODUCER_VERSION.to_owned();
    profile.seal().unwrap();
    requirement.profile_digest = profile.profile_digest.clone();
    requirement.adapter_version = SECOND_WATCH_QUALIFICATION_PRODUCER_VERSION.to_owned();
    requirement.seal().unwrap();
    assert!(WorkerStartRequestV3::from_v2_for_dispatch(
        &canonical(&predecessor),
        &profile,
        &requirement,
        "dispatch-reserved-switchyard-v2-refused",
        0,
    )
    .is_err());
}

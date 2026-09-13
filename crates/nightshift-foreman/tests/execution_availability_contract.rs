use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};
use nightshift_foreman::*;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

fn time(value: &str) -> DateTime<Utc> {
    value.parse().unwrap()
}

fn placeholder() -> String {
    format!("sha256:{}", "0".repeat(64))
}

fn seal_value(mut value: Value, field: &str, domain: &[u8]) -> Value {
    value[field] = Value::String(placeholder());
    let mut basis = value.clone();
    basis.as_object_mut().unwrap().remove(field);
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(serde_jcs::to_vec(&basis).unwrap());
    value[field] = Value::String(format!("sha256:{:x}", hash.finalize()));
    value
}

fn canonical<T: Serialize>(value: &T) -> Vec<u8> {
    serde_jcs::to_vec(value).unwrap()
}

fn mapper_raw(value: Value) -> Value {
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    json!({
        "representation": "EXACT_WIRE_BYTES_INCLUDING_LINE_TERMINATOR",
        "byte_length": bytes.len(),
        "sha256": format!("sha256:{:x}", Sha256::digest(&bytes)),
        "encoding": "hex",
        "bytes_hex": hex::encode(bytes),
    })
}

fn reseal_mapper_snapshot(mut snapshot: Value) -> Value {
    for record in snapshot["records"].as_array_mut().unwrap() {
        *record = seal_value(
            record.clone(),
            "evidence_digest",
            b"switchyard.codex-provider-admission-evidence.digest/v1\0",
        );
    }
    seal_value(
        snapshot,
        "snapshot_digest",
        b"switchyard.codex-provider-admission-snapshot.digest/v1\0",
    )
}

fn retarget_snapshot_dispatch(mut snapshot: Value, dispatch_occurrence_id: &str) -> Value {
    snapshot["binding"]["dispatch_occurrence_id"] = json!(dispatch_occurrence_id);
    snapshot["binding"] = seal_value(
        snapshot["binding"].clone(),
        "binding_digest",
        b"switchyard.codex-provider-admission-binding.digest/v1\0",
    );
    let binding_digest = snapshot["binding"]["binding_digest"].clone();
    for record in snapshot["records"].as_array_mut().unwrap() {
        record["dispatch_occurrence_id"] = json!(dispatch_occurrence_id);
        record["binding_digest"] = binding_digest.clone();
    }
    reseal_mapper_snapshot(snapshot)
}

fn replace_string(value: &mut Value, from: &str, to: &str) {
    match value {
        Value::String(text) if text == from => *text = to.to_owned(),
        Value::Array(values) => {
            for value in values {
                replace_string(value, from, to);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                replace_string(value, from, to);
            }
        }
        _ => {}
    }
}

fn retarget_snapshot_model(mut snapshot: Value, model: &str) -> Value {
    replace_string(&mut snapshot, "gpt-5.6-sol", model);
    for record in snapshot["records"].as_array_mut().unwrap() {
        if let Some(raw) = record["raw"].as_object() {
            let bytes = hex::decode(raw["bytes_hex"].as_str().unwrap()).unwrap();
            let mut wire: Value = serde_json::from_slice(&bytes).unwrap();
            replace_string(&mut wire, "gpt-5.6-sol", model);
            record["raw"] = mapper_raw(wire);
        }
    }
    retarget_snapshot_dispatch(snapshot, "dispatch-holding-2")
}

type SnapshotMutation = (&'static str, fn(&mut Value));

fn policy() -> ExecutionAvailabilityPolicyV1 {
    let mut value = ExecutionAvailabilityPolicyV1 {
        schema: EXECUTION_AVAILABILITY_POLICY_SCHEMA_V1.to_owned(),
        policy_digest: placeholder(),
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

fn requirement(
    policy: &ExecutionAvailabilityPolicyV1,
) -> ForemanExecutionAvailabilityRequirementV1 {
    let mut selections = BTreeMap::new();
    selections.insert(
        "WORK-A".to_owned(),
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
    );
    let mut value = ForemanExecutionAvailabilityRequirementV1 {
        schema: FOREMAN_EXECUTION_AVAILABILITY_REQUIREMENT_SCHEMA_V1.to_owned(),
        requirement_digest: placeholder(),
        packet_digest: placeholder(),
        admission_digest: placeholder(),
        profile_digest: placeholder(),
        run_id: "run-holding".to_owned(),
        adapter_id: "switchyard-codex".to_owned(),
        adapter_protocol: "switchyard.codex-app-server/v2".to_owned(),
        adapter_version: "2.0.0".to_owned(),
        adapter_executable_identity: placeholder(),
        owner_pins: ProviderAdmissionOwnerPinsV1::accepted(),
        policy_id: policy.policy_id.clone(),
        policy_digest: policy.policy_digest.clone(),
        work_item_model_selections: selections,
        admitted_at: time("2026-08-31T12:00:00Z"),
        authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".to_owned(),
    };
    value.seal().unwrap();
    value
}

fn dispatch(
    requirement: &ForemanExecutionAvailabilityRequirementV1,
) -> ProviderDispatchOccurrenceV1 {
    let mut value = ProviderDispatchOccurrenceV1 {
        schema: PROVIDER_DISPATCH_OCCURRENCE_SCHEMA_V1.to_owned(),
        dispatch_digest: placeholder(),
        requirement_digest: requirement.requirement_digest.clone(),
        policy_digest: requirement.policy_digest.clone(),
        packet_digest: requirement.packet_digest.clone(),
        run_id: requirement.run_id.clone(),
        work_item_id: "WORK-A".to_owned(),
        work_attempt_id: "attempt-holding-1".to_owned(),
        dispatch_occurrence_id: "dispatch-holding-1".to_owned(),
        dispatch_ordinal: 1,
        selected_model_ordinal: 0,
        selection: requirement.work_item_model_selections["WORK-A"][0].clone(),
        adapter_id: requirement.adapter_id.clone(),
        adapter_version: requirement.adapter_version.clone(),
        adapter_protocol: requirement.adapter_protocol.clone(),
        adapter_process_occurrence_id: "adapter-process-holding-1".to_owned(),
        app_server_session_identity: "fixture-estate-holding-1".to_owned(),
        worker_start_request_schema: "nightshift.worker-start-request/v3".to_owned(),
        worker_start_request_digest: placeholder(),
        worker_brief_digest: placeholder(),
        opened_at: time("2026-08-31T12:01:00Z"),
        internal_provider_retry_count: 0,
        provider_execution_id: None,
        authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".to_owned(),
    };
    value.seal().unwrap();
    value
}

fn parked_snapshot() -> Value {
    serde_json::from_slice(include_bytes!(
        "../../../qualification/provider-execution-availability-and-deferred-dispatch-v1-20260831/fixtures/switchyard-parked-not-admitted.snapshot.v1.json"
    )).unwrap()
}

fn disposition(
    requirement: &ForemanExecutionAvailabilityRequirementV1,
    dispatch: &ProviderDispatchOccurrenceV1,
) -> ProviderAdmissionDispositionV1 {
    let snapshot = parked_snapshot();
    let bytes = canonical(&snapshot);
    let mut value = ProviderAdmissionDispositionV1 {
        schema: PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V1.to_owned(),
        disposition_digest: placeholder(),
        dispatch_digest: dispatch.dispatch_digest.clone(),
        requirement_digest: requirement.requirement_digest.clone(),
        policy_digest: requirement.policy_digest.clone(),
        packet_digest: requirement.packet_digest.clone(),
        run_id: requirement.run_id.clone(),
        work_item_id: dispatch.work_item_id.clone(),
        work_attempt_id: dispatch.work_attempt_id.clone(),
        dispatch_occurrence_id: dispatch.dispatch_occurrence_id.clone(),
        provider_id: dispatch.selection.provider_id.clone(),
        model_id: dispatch.selection.model_id.clone(),
        provider_request_occurrence_id: "request-0".to_owned(),
        adapter_process_occurrence_id: dispatch.adapter_process_occurrence_id.clone(),
        app_server_session_identity: dispatch.app_server_session_identity.clone(),
        thread_id: "thread-holding-1".to_owned(),
        turn_id: "turn-holding-1".to_owned(),
        disposition: ProviderAdmissionDispositionKindV1::NotAdmittedModelAtCapacity,
        mechanism_state: ProviderMechanismStateV1::ParkedNotAdmitted,
        received_at: time("2026-08-31T12:01:02Z"),
        response_created: false,
        will_retry: false,
        acquisition_complete: true,
        provider_retry_after: Some(time("2026-08-31T12:01:07Z")),
        provider_execution: None,
        mapper_snapshot_schema: "switchyard.codex-provider-admission-snapshot/v1".to_owned(),
        mapper_snapshot_digest: snapshot["snapshot_digest"].as_str().unwrap().to_owned(),
        mapper_snapshot: ExactMapperSnapshotV1::from_bytes(&bytes).unwrap(),
        approval_response_sent: false,
        protected_effect_absent: true,
        authority_effect: "SCHEDULING_MECHANISM_EVIDENCE_ONLY".to_owned(),
    };
    value.seal().unwrap();
    value
}

#[test]
fn closed_contracts_bind_independent_quota_execution_and_dispatch_identities() {
    let policy = policy();
    let requirement = requirement(&policy);
    let dispatch = dispatch(&requirement);
    let disposition = disposition(&requirement, &dispatch);

    assert!(
        disposition.mapper_snapshot.byte_length as usize
            <= MAXIMUM_SWITCHYARD_MAPPER_SNAPSHOT_BYTES
    );
    ExecutionAvailabilityPolicyV1::from_slice(&canonical(&policy))
        .unwrap()
        .validate()
        .unwrap();
    ForemanExecutionAvailabilityRequirementV1::from_slice(&canonical(&requirement))
        .unwrap()
        .validate()
        .unwrap();
    ProviderDispatchOccurrenceV1::from_slice(&canonical(&dispatch))
        .unwrap()
        .validate()
        .unwrap();
    ProviderAdmissionDispositionV1::from_slice(&canonical(&disposition))
        .unwrap()
        .validate()
        .unwrap();
    assert_ne!(dispatch.work_attempt_id, dispatch.dispatch_occurrence_id);
    assert!(dispatch.provider_execution_id.is_none());
    assert!(disposition.disposition.permits_automatic_park());

    let mut observation = ExecutionAvailabilityObservationV1 {
        schema: EXECUTION_AVAILABILITY_OBSERVATION_SCHEMA_V1.to_owned(),
        observation_digest: placeholder(),
        provider_id: "openai".to_owned(),
        model_id: "gpt-5.6-sol".to_owned(),
        model_class: "large".to_owned(),
        observed_at: time("2026-08-31T08:00:00.100Z"),
        received_at: time("2026-08-31T12:01:02Z"),
        expires_at: time("2026-08-31T12:02:02Z"),
        state: ExecutionAvailabilityStateV1::ModelAtCapacity,
        source_identity: "switchyard:provider-admission".to_owned(),
        source_version: "v1".to_owned(),
        provider_retry_after: disposition.provider_retry_after,
        exact_evidence: Some(
            serde_json::from_value(parked_snapshot()["records"][1]["raw"].clone()).unwrap(),
        ),
        authority_effect: "SCHEDULING_MECHANISM_EVIDENCE_ONLY".to_owned(),
    };
    observation.seal().unwrap();
    assert!(observation.is_current_at(time("2026-08-31T12:01:30Z")));
    assert!(!observation.is_current_at(time("2026-08-31T12:02:02Z")));

    let mut deferred = DeferredProviderDispatchV1 {
        schema: DEFERRED_PROVIDER_DISPATCH_SCHEMA_V1.to_owned(),
        deferred_dispatch_digest: placeholder(),
        requirement_digest: requirement.requirement_digest.clone(),
        policy_digest: policy.policy_digest.clone(),
        disposition_digest: disposition.disposition_digest.clone(),
        packet_digest: requirement.packet_digest.clone(),
        run_id: requirement.run_id.clone(),
        work_item_id: dispatch.work_item_id.clone(),
        work_attempt_id: dispatch.work_attempt_id.clone(),
        last_dispatch_occurrence_id: dispatch.dispatch_occurrence_id.clone(),
        provider_id: dispatch.selection.provider_id.clone(),
        model_id: dispatch.selection.model_id.clone(),
        selected_model_ordinal: 0,
        remaining_model_ordinals: vec![1],
        refusal_received_at: disposition.received_at,
        wake_basis: DeferredWakeBasisV1::ProviderRetryAfter,
        backoff_ordinal: 0,
        backoff_seconds: 5,
        provider_retry_after: disposition.provider_retry_after,
        wake_at: disposition.provider_retry_after.unwrap(),
        parked_resource_lock_policy: policy.parked_resource_lock_policy,
        provider_capacity_released: true,
        semantic_retry: false,
        authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".to_owned(),
    };
    deferred.seal().unwrap();
    DeferredProviderDispatchV1::from_slice(&canonical(&deferred))
        .unwrap()
        .validate()
        .unwrap();
    validate_execution_availability_graph(
        &requirement,
        &policy,
        &dispatch,
        &observation,
        &disposition,
        &[],
        Some(&deferred),
    )
    .unwrap();
}

#[test]
fn owner_pin_mapper_and_transition_substitutions_fail_closed() {
    let policy = policy();
    let requirement = requirement(&policy);
    let dispatch = dispatch(&requirement);
    let disposition = disposition(&requirement, &dispatch);

    let mut substituted_requirement = requirement.clone();
    substituted_requirement.owner_pins.codex_owner_head = "0".repeat(40);
    substituted_requirement.seal().unwrap_err();

    let mut retrying = dispatch.clone();
    retrying.internal_provider_retry_count = 1;
    retrying.seal().unwrap_err();

    let mut legacy_start = dispatch.clone();
    legacy_start.worker_start_request_schema = "nightshift.worker-start-request/v2".to_owned();
    legacy_start.seal().unwrap_err();

    let mut snapshot: Value =
        serde_json::from_slice(&disposition.mapper_snapshot.validate().unwrap()).unwrap();
    snapshot["binding"]["provider"] = json!("substituted");
    snapshot["binding"] = seal_value(
        snapshot["binding"].clone(),
        "binding_digest",
        b"switchyard.codex-provider-admission-binding.digest/v1\0",
    );
    let binding_digest = snapshot["binding"]["binding_digest"].clone();
    for record in snapshot["records"].as_array_mut().unwrap() {
        record["binding_digest"] = binding_digest.clone();
        *record = seal_value(
            record.clone(),
            "evidence_digest",
            b"switchyard.codex-provider-admission-evidence.digest/v1\0",
        );
    }
    snapshot = seal_value(
        snapshot,
        "snapshot_digest",
        b"switchyard.codex-provider-admission-snapshot.digest/v1\0",
    );
    let mut substituted = disposition.clone();
    substituted.mapper_snapshot_digest = snapshot["snapshot_digest"].as_str().unwrap().to_owned();
    substituted.mapper_snapshot = ExactMapperSnapshotV1::from_bytes(&canonical(&snapshot)).unwrap();
    substituted.seal().unwrap_err();

    let mut unknown = ExecutionAvailabilityObservationV1 {
        schema: EXECUTION_AVAILABILITY_OBSERVATION_SCHEMA_V1.to_owned(),
        observation_digest: placeholder(),
        provider_id: "openai".to_owned(),
        model_id: "gpt-5.6-sol".to_owned(),
        model_class: "large".to_owned(),
        observed_at: time("2026-08-31T12:00:00Z"),
        received_at: time("2026-08-31T12:00:00Z"),
        expires_at: time("2026-08-31T12:01:00Z"),
        state: ExecutionAvailabilityStateV1::Unknown,
        source_identity: "nightshift:absence".to_owned(),
        source_version: "v1".to_owned(),
        provider_retry_after: None,
        exact_evidence: None,
        authority_effect: "SCHEDULING_MECHANISM_EVIDENCE_ONLY".to_owned(),
    };
    unknown.seal().unwrap();
    unknown.state = ExecutionAvailabilityStateV1::Available;
    unknown.seal().unwrap_err();

    let mut wrong_wake = DeferredProviderDispatchV1 {
        schema: DEFERRED_PROVIDER_DISPATCH_SCHEMA_V1.to_owned(),
        deferred_dispatch_digest: placeholder(),
        requirement_digest: requirement.requirement_digest,
        policy_digest: policy.policy_digest,
        disposition_digest: disposition.disposition_digest,
        packet_digest: requirement.packet_digest,
        run_id: requirement.run_id,
        work_item_id: dispatch.work_item_id,
        work_attempt_id: dispatch.work_attempt_id,
        last_dispatch_occurrence_id: dispatch.dispatch_occurrence_id,
        provider_id: dispatch.selection.provider_id,
        model_id: dispatch.selection.model_id,
        selected_model_ordinal: 0,
        remaining_model_ordinals: vec![1],
        refusal_received_at: disposition.received_at,
        wake_basis: DeferredWakeBasisV1::PolicyBackoff,
        backoff_ordinal: 0,
        backoff_seconds: 5,
        provider_retry_after: None,
        wake_at: disposition.received_at + Duration::seconds(6),
        parked_resource_lock_policy: policy.parked_resource_lock_policy,
        provider_capacity_released: true,
        semantic_retry: false,
        authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".to_owned(),
    };
    wrong_wake.seal().unwrap_err();
}

fn disposition_candidate_from_exact_snapshot(
    requirement: &ForemanExecutionAvailabilityRequirementV1,
    dispatch: &ProviderDispatchOccurrenceV1,
    raw: &[u8],
    received_at: DateTime<Utc>,
) -> ProviderAdmissionDispositionV1 {
    let snapshot: Value = serde_json::from_slice(raw).unwrap();
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
        "EXECUTION_ADMITTED" => ProviderMechanismStateV1::ExecutionAdmitted,
        "PROVIDER_COMPLETED" => ProviderMechanismStateV1::ProviderCompleted,
        value => panic!("unexpected fixture mechanism state {value}"),
    };
    let request_occurrence = snapshot["records"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|record| {
            record["normalized"]["request_occurrence_id"]
                .as_str()
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "request-0".to_owned());
    let retry_after_ms = snapshot["records"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|record| record["normalized"]["retry_after_ms"].as_i64());
    let value = ProviderAdmissionDispositionV1 {
        schema: PROVIDER_ADMISSION_DISPOSITION_SCHEMA_V1.to_owned(),
        disposition_digest: placeholder(),
        dispatch_digest: dispatch.dispatch_digest.clone(),
        requirement_digest: requirement.requirement_digest.clone(),
        policy_digest: requirement.policy_digest.clone(),
        packet_digest: requirement.packet_digest.clone(),
        run_id: requirement.run_id.clone(),
        work_item_id: dispatch.work_item_id.clone(),
        work_attempt_id: dispatch.work_attempt_id.clone(),
        dispatch_occurrence_id: dispatch.dispatch_occurrence_id.clone(),
        provider_id: dispatch.selection.provider_id.clone(),
        model_id: dispatch.selection.model_id.clone(),
        provider_request_occurrence_id: request_occurrence,
        adapter_process_occurrence_id: dispatch.adapter_process_occurrence_id.clone(),
        app_server_session_identity: dispatch.app_server_session_identity.clone(),
        thread_id: "thread-holding-1".to_owned(),
        turn_id: "turn-holding-1".to_owned(),
        disposition: disposition_kind,
        mechanism_state,
        received_at,
        response_created: execution.is_some(),
        will_retry: false,
        acquisition_complete: snapshot["acquisition_cut"]["clean"]
            .as_bool()
            .unwrap_or(false),
        provider_retry_after: retry_after_ms.map(|ms| received_at + Duration::milliseconds(ms)),
        provider_execution: execution,
        mapper_snapshot_schema: "switchyard.codex-provider-admission-snapshot/v1".to_owned(),
        mapper_snapshot_digest: snapshot["snapshot_digest"].as_str().unwrap().to_owned(),
        mapper_snapshot: ExactMapperSnapshotV1::from_bytes(raw).unwrap(),
        approval_response_sent: false,
        protected_effect_absent: true,
        authority_effect: "SCHEDULING_MECHANISM_EVIDENCE_ONLY".to_owned(),
    };
    value
}

fn disposition_from_exact_snapshot(
    requirement: &ForemanExecutionAvailabilityRequirementV1,
    dispatch: &ProviderDispatchOccurrenceV1,
    raw: &[u8],
    received_at: DateTime<Utc>,
) -> ProviderAdmissionDispositionV1 {
    let mut value =
        disposition_candidate_from_exact_snapshot(requirement, dispatch, raw, received_at);
    value.seal().unwrap();
    value
}

fn observation_for_disposition(
    disposition: &ProviderAdmissionDispositionV1,
) -> ExecutionAvailabilityObservationV1 {
    let raw = disposition.mapper_snapshot.validate().unwrap();
    let snapshot: Value = serde_json::from_slice(&raw).unwrap();
    let source_kind = match disposition.disposition {
        ProviderAdmissionDispositionKindV1::NotAdmittedModelAtCapacity => {
            "PROVIDER_ADMISSION_REFUSED"
        }
        ProviderAdmissionDispositionKindV1::ExecutionAdmitted => "PROVIDER_EXECUTION_STEP",
        ProviderAdmissionDispositionKindV1::AdmissionIndeterminate => "ADMISSION_DISCREPANCY",
        _ => unreachable!(),
    };
    let exact_evidence = snapshot["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["kind"] == source_kind)
        .and_then(|record| {
            if record["raw"].is_null() {
                None
            } else {
                Some(serde_json::from_value(record["raw"].clone()).unwrap())
            }
        });
    let observed_at = snapshot["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["kind"] == source_kind)
        .and_then(|record| record["normalized"]["observed_at_ms"].as_i64())
        .and_then(DateTime::<Utc>::from_timestamp_millis)
        .unwrap_or(disposition.received_at);
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
    let mut value = ExecutionAvailabilityObservationV1 {
        schema: EXECUTION_AVAILABILITY_OBSERVATION_SCHEMA_V1.to_owned(),
        observation_digest: placeholder(),
        provider_id: disposition.provider_id.clone(),
        model_id: disposition.model_id.clone(),
        model_class: "large".to_owned(),
        observed_at,
        received_at: disposition.received_at,
        expires_at: disposition.received_at + Duration::seconds(60),
        state,
        source_identity: "switchyard:provider-admission".to_owned(),
        source_version: "v1".to_owned(),
        provider_retry_after: disposition.provider_retry_after,
        exact_evidence,
        authority_effect: "SCHEDULING_MECHANISM_EVIDENCE_ONLY".to_owned(),
    };
    value.seal().unwrap();
    value
}

fn deferred_for(
    requirement: &ForemanExecutionAvailabilityRequirementV1,
    policy: &ExecutionAvailabilityPolicyV1,
    dispatch: &ProviderDispatchOccurrenceV1,
    disposition: &ProviderAdmissionDispositionV1,
) -> DeferredProviderDispatchV1 {
    let mut value = DeferredProviderDispatchV1 {
        schema: DEFERRED_PROVIDER_DISPATCH_SCHEMA_V1.to_owned(),
        deferred_dispatch_digest: placeholder(),
        requirement_digest: requirement.requirement_digest.clone(),
        policy_digest: policy.policy_digest.clone(),
        disposition_digest: disposition.disposition_digest.clone(),
        packet_digest: requirement.packet_digest.clone(),
        run_id: requirement.run_id.clone(),
        work_item_id: dispatch.work_item_id.clone(),
        work_attempt_id: dispatch.work_attempt_id.clone(),
        last_dispatch_occurrence_id: dispatch.dispatch_occurrence_id.clone(),
        provider_id: dispatch.selection.provider_id.clone(),
        model_id: dispatch.selection.model_id.clone(),
        selected_model_ordinal: dispatch.selected_model_ordinal,
        remaining_model_ordinals: vec![1],
        refusal_received_at: disposition.received_at,
        wake_basis: DeferredWakeBasisV1::ProviderRetryAfter,
        backoff_ordinal: 0,
        backoff_seconds: 5,
        provider_retry_after: disposition.provider_retry_after,
        wake_at: disposition.provider_retry_after.unwrap(),
        parked_resource_lock_policy: policy.parked_resource_lock_policy,
        provider_capacity_released: true,
        semantic_retry: false,
        authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".to_owned(),
    };
    value.seal().unwrap();
    value
}

#[test]
fn graph_currentness_backoff_fallback_and_lock_substitutions_fail_closed() {
    let policy = policy();
    let requirement = requirement(&policy);
    let dispatch = dispatch(&requirement);
    let disposition = disposition(&requirement, &dispatch);
    let observation = observation_for_disposition(&disposition);
    let deferred = deferred_for(&requirement, &policy, &dispatch, &disposition);
    validate_execution_availability_graph(
        &requirement,
        &policy,
        &dispatch,
        &observation,
        &disposition,
        &[],
        Some(&deferred),
    )
    .unwrap();

    let mut late_requirement = requirement.clone();
    late_requirement.admitted_at = dispatch.opened_at + Duration::milliseconds(1);
    late_requirement.seal().unwrap();
    let late_dispatch = crate::dispatch(&late_requirement);
    let late_disposition = crate::disposition(&late_requirement, &late_dispatch);
    let late_observation = observation_for_disposition(&late_disposition);
    let late_deferred = deferred_for(
        &late_requirement,
        &policy,
        &late_dispatch,
        &late_disposition,
    );
    validate_execution_availability_graph(
        &late_requirement,
        &policy,
        &late_dispatch,
        &late_observation,
        &late_disposition,
        &[],
        Some(&late_deferred),
    )
    .unwrap_err();

    let mut after_receipt_dispatch = dispatch.clone();
    after_receipt_dispatch.opened_at = disposition.received_at + Duration::milliseconds(1);
    after_receipt_dispatch.seal().unwrap();
    let after_receipt_disposition = crate::disposition(&requirement, &after_receipt_dispatch);
    let after_receipt_observation = observation_for_disposition(&after_receipt_disposition);
    let after_receipt_deferred = deferred_for(
        &requirement,
        &policy,
        &after_receipt_dispatch,
        &after_receipt_disposition,
    );
    validate_execution_availability_graph(
        &requirement,
        &policy,
        &after_receipt_dispatch,
        &after_receipt_observation,
        &after_receipt_disposition,
        &[],
        Some(&after_receipt_deferred),
    )
    .unwrap_err();

    let mut substituted_observation = observation.clone();
    substituted_observation.received_at += Duration::seconds(1);
    substituted_observation.seal().unwrap();
    validate_execution_availability_graph(
        &requirement,
        &policy,
        &dispatch,
        &substituted_observation,
        &disposition,
        &[],
        Some(&deferred),
    )
    .unwrap_err();

    for mut substituted in [
        {
            let mut value = observation.clone();
            value.source_identity = "switchyard:other-source".to_owned();
            value
        },
        {
            let mut value = observation.clone();
            value.observed_at += Duration::milliseconds(1);
            value
        },
        {
            let mut value = observation.clone();
            value.provider_retry_after = None;
            value
        },
    ] {
        substituted.seal().unwrap();
        validate_execution_availability_graph(
            &requirement,
            &policy,
            &dispatch,
            &substituted,
            &disposition,
            &[],
            Some(&deferred),
        )
        .unwrap_err();
    }

    let mut stale = observation.clone();
    stale.expires_at = disposition.received_at;
    stale.seal().unwrap_err();

    for mut substituted in [
        {
            let mut value = deferred.clone();
            value.remaining_model_ordinals.clear();
            value
        },
        {
            let mut value = deferred.clone();
            value.refusal_received_at += Duration::seconds(1);
            value
        },
        {
            let mut value = deferred.clone();
            value.backoff_ordinal = 1;
            value
        },
        {
            let mut value = deferred.clone();
            value.parked_resource_lock_policy = ParkedResourceLockPolicyV1::RetainWhileParked;
            value
        },
        {
            let mut value = deferred.clone();
            value.backoff_seconds += 1;
            value.provider_retry_after = value
                .provider_retry_after
                .map(|time| time + Duration::seconds(1));
            value.wake_at += Duration::seconds(1);
            value
        },
    ] {
        substituted.seal().unwrap();
        validate_execution_availability_graph(
            &requirement,
            &policy,
            &dispatch,
            &observation,
            &disposition,
            &[],
            Some(&substituted),
        )
        .unwrap_err();
    }

    let completed = disposition_from_exact_snapshot(
        &requirement,
        &dispatch,
        include_bytes!("../../../qualification/provider-execution-availability-and-deferred-dispatch-v1-20260831/fixtures/switchyard-provider-completed.snapshot.v1.json"),
        disposition.received_at,
    );
    let available = observation_for_disposition(&completed);
    validate_execution_availability_graph(
        &requirement,
        &policy,
        &dispatch,
        &available,
        &completed,
        &[],
        Some(&deferred),
    )
    .unwrap_err();
}

#[test]
fn cumulative_multi_deferral_history_is_explicit_and_bounded() {
    let mut policy = policy();
    policy.maximum_total_deferral_seconds = 75;
    policy.seal().unwrap();
    let mut requirement = requirement(&policy);
    requirement.policy_digest = policy.policy_digest.clone();
    requirement.seal().unwrap();

    let first_dispatch = dispatch(&requirement);
    let first_disposition = disposition(&requirement, &first_dispatch);
    let first_deferred = deferred_for(&requirement, &policy, &first_dispatch, &first_disposition);
    let first_history = ProviderDeferralHistoryEntryV1 {
        dispatch: first_dispatch.clone(),
        disposition: first_disposition.clone(),
        deferred: first_deferred.clone(),
    };

    let mut second_dispatch = first_dispatch.clone();
    second_dispatch.dispatch_occurrence_id = "dispatch-holding-2".to_owned();
    second_dispatch.dispatch_ordinal = 2;
    second_dispatch.opened_at = first_deferred.wake_at;
    second_dispatch.seal().unwrap();

    let mut snapshot = parked_snapshot();
    snapshot["binding"]["dispatch_occurrence_id"] = json!(second_dispatch.dispatch_occurrence_id);
    snapshot["binding"] = seal_value(
        snapshot["binding"].clone(),
        "binding_digest",
        b"switchyard.codex-provider-admission-binding.digest/v1\0",
    );
    let binding_digest = snapshot["binding"]["binding_digest"].clone();
    for record in snapshot["records"].as_array_mut().unwrap() {
        record["dispatch_occurrence_id"] = json!(second_dispatch.dispatch_occurrence_id);
        record["binding_digest"] = binding_digest.clone();
        *record = seal_value(
            record.clone(),
            "evidence_digest",
            b"switchyard.codex-provider-admission-evidence.digest/v1\0",
        );
    }
    snapshot = seal_value(
        snapshot,
        "snapshot_digest",
        b"switchyard.codex-provider-admission-snapshot.digest/v1\0",
    );
    let raw = canonical(&snapshot);
    let second_disposition = disposition_from_exact_snapshot(
        &requirement,
        &second_dispatch,
        &raw,
        time("2026-08-31T12:02:00Z"),
    );
    let second_observation = observation_for_disposition(&second_disposition);
    let mut second_deferred =
        deferred_for(&requirement, &policy, &second_dispatch, &second_disposition);
    second_deferred.backoff_ordinal = 1;
    second_deferred.seal().unwrap();
    validate_execution_availability_graph(
        &requirement,
        &policy,
        &second_dispatch,
        &second_observation,
        &second_disposition,
        std::slice::from_ref(&first_history),
        Some(&second_deferred),
    )
    .unwrap();

    let completed_snapshot = retarget_snapshot_dispatch(
        serde_json::from_slice(include_bytes!(
            "../../../qualification/provider-execution-availability-and-deferred-dispatch-v1-20260831/fixtures/switchyard-provider-completed.snapshot.v1.json"
        ))
        .unwrap(),
        &second_dispatch.dispatch_occurrence_id,
    );
    let admitted_disposition = disposition_from_exact_snapshot(
        &requirement,
        &second_dispatch,
        &canonical(&completed_snapshot),
        time("2026-08-31T12:02:00Z"),
    );
    let admitted_observation = observation_for_disposition(&admitted_disposition);
    validate_execution_availability_graph(
        &requirement,
        &policy,
        &second_dispatch,
        &admitted_observation,
        &admitted_disposition,
        std::slice::from_ref(&first_history),
        None,
    )
    .unwrap();

    let (_, cross_family_disposition, _) = qualification_disposition(
        &requirement,
        &first_dispatch,
        DeterministicProviderAdmissionOutcomeV1::ProviderUnavailable,
        false,
    );
    let mut cross_family_history = first_history.clone();
    cross_family_history.disposition = cross_family_disposition;
    cross_family_history.deferred.disposition_digest =
        cross_family_history.disposition.disposition_digest.clone();
    cross_family_history.deferred.provider_retry_after =
        cross_family_history.disposition.provider_retry_after;
    cross_family_history.deferred.wake_at = cross_family_history
        .disposition
        .provider_retry_after
        .unwrap();
    cross_family_history.deferred.backoff_seconds = 5;
    cross_family_history.deferred.seal().unwrap();
    assert_eq!(
        validate_execution_availability_graph(
            &requirement,
            &policy,
            &second_dispatch,
            &admitted_observation,
            &admitted_disposition,
            &[cross_family_history],
            None,
        )
        .unwrap_err()
        .to_string(),
        "invalid field: dispatch disposition owner-family graph"
    );

    let mut mismatched_history = first_history.clone();
    mismatched_history.deferred.disposition_digest = placeholder();
    mismatched_history.deferred.seal().unwrap();
    validate_execution_availability_graph(
        &requirement,
        &policy,
        &second_dispatch,
        &admitted_observation,
        &admitted_disposition,
        &[mismatched_history],
        None,
    )
    .unwrap_err();

    let mut substituted_adapter = first_history.clone();
    substituted_adapter.dispatch.adapter_version = "2.0.1".to_owned();
    substituted_adapter.dispatch.seal().unwrap();
    validate_execution_availability_graph(
        &requirement,
        &policy,
        &second_dispatch,
        &admitted_observation,
        &admitted_disposition,
        &[substituted_adapter],
        None,
    )
    .unwrap_err();

    let mut before_wake = second_dispatch.clone();
    before_wake.opened_at = first_deferred.wake_at - Duration::milliseconds(1);
    before_wake.seal().unwrap();
    let early_disposition = disposition_from_exact_snapshot(
        &requirement,
        &before_wake,
        &canonical(&completed_snapshot),
        time("2026-08-31T12:02:00Z"),
    );
    let early_observation = observation_for_disposition(&early_disposition);
    validate_execution_availability_graph(
        &requirement,
        &policy,
        &before_wake,
        &early_observation,
        &early_disposition,
        std::slice::from_ref(&first_history),
        None,
    )
    .unwrap_err();

    let mut reversed_model = first_history.clone();
    reversed_model.deferred.selected_model_ordinal = 1;
    reversed_model.deferred.model_id = "gpt-5.6-terra".to_owned();
    reversed_model.deferred.remaining_model_ordinals.clear();
    reversed_model.deferred.seal().unwrap();
    validate_execution_availability_graph(
        &requirement,
        &policy,
        &second_dispatch,
        &second_observation,
        &second_disposition,
        &[reversed_model],
        Some(&second_deferred),
    )
    .unwrap_err();

    let mut over_budget_snapshot = snapshot;
    let refusal = &mut over_budget_snapshot["records"][1];
    refusal["normalized"]["retry_after_ms"] = json!(71_000);
    let raw_hex = refusal["raw"]["bytes_hex"].as_str().unwrap();
    let mut raw_value: Value = serde_json::from_slice(&hex::decode(raw_hex).unwrap()).unwrap();
    raw_value["params"]["retryAfterMs"] = json!(71_000);
    let mut wire = serde_json::to_vec(&raw_value).unwrap();
    wire.push(b'\n');
    refusal["raw"]["byte_length"] = json!(wire.len());
    refusal["raw"]["bytes_hex"] = json!(hex::encode(&wire));
    refusal["raw"]["sha256"] = json!(format!("sha256:{:x}", Sha256::digest(&wire)));
    *refusal = seal_value(
        refusal.clone(),
        "evidence_digest",
        b"switchyard.codex-provider-admission-evidence.digest/v1\0",
    );
    over_budget_snapshot = seal_value(
        over_budget_snapshot,
        "snapshot_digest",
        b"switchyard.codex-provider-admission-snapshot.digest/v1\0",
    );
    let over_budget_disposition = disposition_from_exact_snapshot(
        &requirement,
        &second_dispatch,
        &canonical(&over_budget_snapshot),
        time("2026-08-31T12:02:00Z"),
    );
    let over_budget_observation = observation_for_disposition(&over_budget_disposition);
    let mut current_deferred = deferred_for(
        &requirement,
        &policy,
        &second_dispatch,
        &over_budget_disposition,
    );
    current_deferred.backoff_ordinal = 1;
    current_deferred.seal().unwrap();
    validate_execution_availability_graph(
        &requirement,
        &policy,
        &second_dispatch,
        &over_budget_observation,
        &over_budget_disposition,
        &[first_history],
        Some(&current_deferred),
    )
    .unwrap_err();
}

#[test]
fn admitted_current_still_enforces_budget_and_disabled_fallback_cannot_advance() {
    for (maximum_total, fallback) in [(4, true), (10, false)] {
        let mut policy = policy();
        policy.backoff_seconds = vec![1];
        policy.maximum_total_deferral_seconds = maximum_total;
        policy.allow_ordered_model_fallback = fallback;
        policy.seal().unwrap();
        let requirement = requirement(&policy);
        let first_dispatch = dispatch(&requirement);
        let first_disposition = disposition(&requirement, &first_dispatch);
        let mut first_deferred =
            deferred_for(&requirement, &policy, &first_dispatch, &first_disposition);
        if !fallback {
            first_deferred.remaining_model_ordinals.clear();
            first_deferred.seal().unwrap();
        }
        let history = ProviderDeferralHistoryEntryV1 {
            dispatch: first_dispatch,
            disposition: first_disposition,
            deferred: first_deferred.clone(),
        };
        let mut second_dispatch = dispatch(&requirement);
        second_dispatch.dispatch_occurrence_id = "dispatch-holding-2".to_owned();
        second_dispatch.dispatch_ordinal = 2;
        second_dispatch.opened_at = first_deferred.wake_at;
        if !fallback {
            second_dispatch.selected_model_ordinal = 1;
            second_dispatch.selection = requirement.work_item_model_selections["WORK-A"][1].clone();
        }
        second_dispatch.seal().unwrap();
        let base_snapshot = serde_json::from_slice(include_bytes!(
            "../../../qualification/provider-execution-availability-and-deferred-dispatch-v1-20260831/fixtures/switchyard-provider-completed.snapshot.v1.json"
        ))
        .unwrap();
        let snapshot = if fallback {
            retarget_snapshot_dispatch(base_snapshot, &second_dispatch.dispatch_occurrence_id)
        } else {
            retarget_snapshot_model(base_snapshot, &second_dispatch.selection.model_id)
        };
        let disposition = disposition_from_exact_snapshot(
            &requirement,
            &second_dispatch,
            &canonical(&snapshot),
            time("2026-08-31T12:02:00Z"),
        );
        let observation = observation_for_disposition(&disposition);
        let result = validate_execution_availability_graph(
            &requirement,
            &policy,
            &second_dispatch,
            &observation,
            &disposition,
            &[history],
            None,
        );
        assert!(result.is_err(), "accepted budget/fallback bypass");
    }
}

#[test]
fn mapper_cut_ordinal_representation_number_and_receipt_time_substitutions_fail_closed() {
    let policy = policy();
    let requirement = requirement(&policy);
    let dispatch = dispatch(&requirement);
    let original = disposition(&requirement, &dispatch);
    let raw = original.mapper_snapshot.validate().unwrap();

    let mut uppercase_snapshot = original.mapper_snapshot.clone();
    uppercase_snapshot.bytes_hex = uppercase_snapshot.bytes_hex.to_ascii_uppercase();
    uppercase_snapshot.validate().unwrap_err();
    let mut uppercase_evidence = observation_for_disposition(&original)
        .exact_evidence
        .unwrap();
    uppercase_evidence.bytes_hex = uppercase_evidence.bytes_hex.to_ascii_uppercase();
    uppercase_evidence.validate().unwrap_err();

    let mutations: &[SnapshotMutation] = &[
        ("cut-session", |snapshot| {
            snapshot["acquisition_cut"]["app_server_session_identity"] = json!("other-session")
        }),
        ("ordinal-gap", |snapshot| {
            snapshot["records"][1]["acquisition_ordinal"] = json!(7)
        }),
        ("representation", |snapshot| {
            snapshot["records"][1]["raw"]["representation"] =
                json!("EXACT_PROVIDER_AVAILABILITY_SOURCE_BYTES")
        }),
        ("unsafe-number", |snapshot| {
            snapshot["records"][0]["normalized"]["started_at_ms"] = json!(9_007_199_254_740_992_i64)
        }),
        ("schema-string-bound", |snapshot| {
            snapshot["records"][1]["normalized"]["diagnostic"] = json!("x".repeat(4097))
        }),
        ("coherent-provider-order", |snapshot| {
            snapshot["records"][0]["normalized"]["sampling_ordinal"] = json!(1);
            snapshot["records"][0]["normalized"]["request_order"] = json!(1);
            let raw = &snapshot["records"][0]["raw"];
            let bytes = hex::decode(raw["bytes_hex"].as_str().unwrap()).unwrap();
            let mut wire: Value = serde_json::from_slice(&bytes).unwrap();
            wire["params"]["samplingOrdinal"] = json!(1);
            wire["params"]["requestOrder"] = json!(1);
            snapshot["records"][0]["raw"] = mapper_raw(wire);
        }),
    ];
    for (name, mutate) in mutations {
        let mut snapshot: Value = serde_json::from_slice(&raw).unwrap();
        mutate(&mut snapshot);
        for record in snapshot["records"].as_array_mut().unwrap() {
            *record = seal_value(
                record.clone(),
                "evidence_digest",
                b"switchyard.codex-provider-admission-evidence.digest/v1\0",
            );
        }
        snapshot = seal_value(
            snapshot,
            "snapshot_digest",
            b"switchyard.codex-provider-admission-snapshot.digest/v1\0",
        );
        let mut substituted = original.clone();
        substituted.mapper_snapshot_digest =
            snapshot["snapshot_digest"].as_str().unwrap().to_owned();
        substituted.mapper_snapshot =
            ExactMapperSnapshotV1::from_bytes(&canonical(&snapshot)).unwrap();
        assert!(substituted.seal().is_err(), "accepted {name} substitution");
    }

    let mut pre_receipt = original;
    pre_receipt.received_at = time("2026-08-31T08:00:00Z");
    pre_receipt.provider_retry_after = Some(time("2026-08-31T08:00:05Z"));
    pre_receipt.seal().unwrap_err();
}

#[test]
fn semantic_execution_identity_substitutions_fail_closed() {
    let policy = policy();
    let requirement = requirement(&policy);
    let dispatch = dispatch(&requirement);
    let completed_raw = include_bytes!("../../../qualification/provider-execution-availability-and-deferred-dispatch-v1-20260831/fixtures/switchyard-provider-completed.snapshot.v1.json");
    let completed = disposition_from_exact_snapshot(
        &requirement,
        &dispatch,
        completed_raw,
        time("2026-08-31T12:01:02Z"),
    );
    let substitutions: &[SnapshotMutation] = &[
        ("top-execution", |snapshot| {
            snapshot["provider_execution_identity"]["first_response_id"] = json!("substituted")
        }),
        ("step-request-order", |snapshot| {
            snapshot["records"][1]["normalized"]["provider_execution_step_identity"]
                ["request_order"] = json!(1)
        }),
        ("coherent-response-before-request", |snapshot| {
            snapshot["records"][1]["normalized"]["observed_at_ms"] = json!(1_788_163_199_999_i64);
            let raw = &snapshot["records"][1]["raw"];
            let bytes = hex::decode(raw["bytes_hex"].as_str().unwrap()).unwrap();
            let mut wire: Value = serde_json::from_slice(&bytes).unwrap();
            wire["params"]["observedAtMs"] = json!(1_788_163_199_999_i64);
            snapshot["records"][1]["raw"] = mapper_raw(wire);
        }),
        ("local-fact-thread", |snapshot| {
            let raw = &snapshot["records"][3]["raw"];
            let bytes = hex::decode(raw["bytes_hex"].as_str().unwrap()).unwrap();
            let mut wire: Value = serde_json::from_slice(&bytes).unwrap();
            wire["params"]["threadId"] = json!("thread-substituted");
            snapshot["records"][3]["raw"] = mapper_raw(wire);
        }),
    ];
    for (name, mutate) in substitutions {
        let mut snapshot: Value = serde_json::from_slice(completed_raw).unwrap();
        mutate(&mut snapshot);
        snapshot = reseal_mapper_snapshot(snapshot);
        let mut substituted = completed.clone();
        substituted.mapper_snapshot_digest =
            snapshot["snapshot_digest"].as_str().unwrap().to_owned();
        substituted.mapper_snapshot =
            ExactMapperSnapshotV1::from_bytes(&canonical(&snapshot)).unwrap();
        assert!(substituted.seal().is_err(), "accepted {name} substitution");
    }

    let mut response_created = completed;
    response_created.response_created = false;
    response_created.seal().unwrap_err();
}

#[test]
fn client_request_response_pairing_is_exact() {
    let policy = policy();
    let requirement = requirement(&policy);
    let dispatch = dispatch(&requirement);
    let completed_raw = include_bytes!("../../../qualification/provider-execution-availability-and-deferred-dispatch-v1-20260831/fixtures/switchyard-provider-completed.snapshot.v1.json");
    let mut snapshot: Value = serde_json::from_slice(completed_raw).unwrap();
    for record in snapshot["records"].as_array_mut().unwrap() {
        record["sequence"] = json!(record["sequence"].as_u64().unwrap() + 2);
        if let Some(ordinal) = record["acquisition_ordinal"].as_u64() {
            record["acquisition_ordinal"] = json!(ordinal + 2);
        }
    }
    snapshot["acquisition_cut"]["ordered_high_water"] = json!(6);
    snapshot["acquisition_cut"]["consumed_ordinal_count"] = json!(6);
    let last = snapshot["records"].as_array().unwrap().len() - 1;
    snapshot["records"][last]["normalized"] = snapshot["acquisition_cut"].clone();
    let mut request = snapshot["records"][0].clone();
    request["sequence"] = json!(0);
    request["acquisition_ordinal"] = json!(0);
    request["acquisition_kind"] = json!("CLIENT_REQUEST");
    request["kind"] = json!("CLIENT_REQUEST_ISSUED");
    request["method"] = json!("client-request/thread/read");
    let request_params = json!({"threadId":"thread-holding-1"});
    let params_sha256 = format!(
        "sha256:{:x}",
        Sha256::digest(serde_jcs::to_vec(&request_params).unwrap())
    );
    request["normalized"] = json!({"request_id":7,"request_method":"thread/read","params_sha256":params_sha256,"proves_provider_admission":false});
    request["raw"] = mapper_raw(json!({"id":7,"method":"thread/read","params":request_params}));
    let mut response = request.clone();
    response["sequence"] = json!(1);
    response["acquisition_ordinal"] = json!(1);
    response["acquisition_kind"] = json!("CLIENT_RESPONSE");
    response["kind"] = json!("CLIENT_RESPONSE_RETAINED");
    response["method"] = json!("client-response/thread/read");
    let result = json!({"thread":{"id":"thread-holding-1"}});
    let result_sha256 = format!(
        "sha256:{:x}",
        Sha256::digest(serde_jcs::to_vec(&result).unwrap())
    );
    response["normalized"] = json!({"request_id":7,"request_method":"thread/read","params_sha256":params_sha256,"result_sha256":result_sha256,"proves_provider_admission":false});
    response["raw"] = mapper_raw(json!({"id":7,"result":result}));
    snapshot["records"]
        .as_array_mut()
        .unwrap()
        .splice(0..0, [request, response]);
    snapshot = reseal_mapper_snapshot(snapshot);
    let disposition = disposition_from_exact_snapshot(
        &requirement,
        &dispatch,
        &canonical(&snapshot),
        time("2026-08-31T12:01:02Z"),
    );
    disposition.validate().unwrap();

    snapshot["records"][1]["normalized"]["params_sha256"] =
        json!(format!("sha256:{}", "1".repeat(64)));
    snapshot = reseal_mapper_snapshot(snapshot);
    let mut substituted = disposition;
    substituted.mapper_snapshot_digest = snapshot["snapshot_digest"].as_str().unwrap().to_owned();
    substituted.mapper_snapshot = ExactMapperSnapshotV1::from_bytes(&canonical(&snapshot)).unwrap();
    substituted.seal().unwrap_err();
}

#[test]
fn strict_ordered_owner_snapshot_reaches_true_waiting_approval_before_cut() {
    let corpus: Value = serde_json::from_slice(include_bytes!(
        "../../../qualification/provider-execution-availability-and-deferred-dispatch-v1-20260831/fixtures/switchyard-owner-terminal-corpus.v1.json"
    ))
    .unwrap();
    let mut snapshot = corpus["snapshots"]
        .as_array()
        .unwrap()
        .iter()
        .find(|candidate| {
            candidate["snapshot_digest"]
                == "sha256:2d00630ea45c82c95211def651886e6307aa9b2e5a1dabd1cae74658a2b2d7d7"
        })
        .unwrap()
        .clone();
    snapshot["records"].as_array_mut().unwrap().truncate(4);
    assert_eq!(snapshot["records"][3]["kind"], "WAITING_APPROVAL");
    assert_eq!(snapshot["records"][3]["acquisition_kind"], "SERVER_REQUEST");
    snapshot["acquisition_cut"] = Value::Null;
    snapshot["mechanism_state"] = json!("WAITING_APPROVAL");
    snapshot = reseal_mapper_snapshot(snapshot);

    let policy = policy();
    let requirement = requirement(&policy);
    let dispatch = dispatch(&requirement);
    let raw = canonical(&snapshot);
    let disposition = disposition_from_exact_snapshot(
        &requirement,
        &dispatch,
        &raw,
        time("2026-08-31T12:01:02Z"),
    );
    assert_eq!(
        disposition.mechanism_state,
        ProviderMechanismStateV1::WaitingApproval
    );
    assert_eq!(
        disposition.disposition,
        ProviderAdmissionDispositionKindV1::ExecutionAdmitted
    );
    assert!(disposition.provider_execution.is_some());
    assert!(!disposition.acquisition_complete);
    assert!(!disposition.approval_response_sent);
    assert!(disposition.protected_effect_absent);
    let observation = observation_for_disposition(&disposition);
    validate_execution_availability_graph(
        &requirement,
        &policy,
        &dispatch,
        &observation,
        &disposition,
        &[],
        None,
    )
    .unwrap();
}

#[test]
fn only_exact_model_capacity_disposition_permits_automatic_park() {
    let cases = [
        (
            ProviderAdmissionDispositionKindV1::NotAdmittedModelAtCapacity,
            true,
        ),
        (
            ProviderAdmissionDispositionKindV1::NotAdmittedProviderUnavailable,
            false,
        ),
        (
            ProviderAdmissionDispositionKindV1::NotAdmittedRateLimited,
            false,
        ),
        (
            ProviderAdmissionDispositionKindV1::AuthenticationRefused,
            false,
        ),
        (
            ProviderAdmissionDispositionKindV1::QuotaExhaustedFuelOwned,
            false,
        ),
        (
            ProviderAdmissionDispositionKindV1::AdmissionIndeterminate,
            false,
        ),
        (ProviderAdmissionDispositionKindV1::ExecutionAdmitted, false),
    ];
    for (disposition, expected) in cases {
        assert_eq!(disposition.permits_automatic_park(), expected);
    }
}

#[test]
fn fuel_owned_quota_cannot_seal_as_provider_admission_disposition() {
    let policy = policy();
    let requirement = requirement(&policy);
    let dispatch = dispatch(&requirement);
    let mut disposition = disposition(&requirement, &dispatch);
    disposition.disposition = ProviderAdmissionDispositionKindV1::QuotaExhaustedFuelOwned;

    assert_eq!(
        disposition.seal().unwrap_err().to_string(),
        "invalid field: disposition is not emitted by accepted Switchyard V1"
    );
}

#[test]
fn exact_switchyard_vectors_reopen_with_distinct_terminal_mechanism_states() {
    let policy = policy();
    let requirement = requirement(&policy);
    let dispatch = dispatch(&requirement);
    let received = time("2026-08-31T12:01:02Z");
    let cases: &[(&[u8], ProviderMechanismStateV1, bool, bool)] = &[
        (
            include_bytes!("../../../qualification/provider-execution-availability-and-deferred-dispatch-v1-20260831/fixtures/switchyard-provider-completed.snapshot.v1.json"),
            ProviderMechanismStateV1::ProviderCompleted,
            true,
            true,
        ),
        (
            include_bytes!("../../../qualification/provider-execution-availability-and-deferred-dispatch-v1-20260831/fixtures/switchyard-post-admission-interrupted.snapshot.v1.json"),
            ProviderMechanismStateV1::PostAdmissionInterrupted,
            false,
            true,
        ),
        (
            include_bytes!("../../../qualification/provider-execution-availability-and-deferred-dispatch-v1-20260831/fixtures/switchyard-approval-interrupted.snapshot.v1.json"),
            ProviderMechanismStateV1::PostAdmissionInterrupted,
            false,
            true,
        ),
        (
            include_bytes!("../../../qualification/provider-execution-availability-and-deferred-dispatch-v1-20260831/fixtures/switchyard-admission-indeterminate.snapshot.v1.json"),
            ProviderMechanismStateV1::AdmissionIndeterminate,
            false,
            false,
        ),
    ];
    for (raw, expected_state, clean, admitted) in cases {
        let disposition = disposition_from_exact_snapshot(&requirement, &dispatch, raw, received);
        assert_eq!(disposition.mechanism_state, *expected_state);
        assert_eq!(disposition.acquisition_complete, *clean);
        assert_eq!(disposition.provider_execution.is_some(), *admitted);
        let observation = observation_for_disposition(&disposition);
        validate_execution_availability_graph(
            &requirement,
            &policy,
            &dispatch,
            &observation,
            &disposition,
            &[],
            None,
        )
        .unwrap();
        if matches!(
            expected_state,
            ProviderMechanismStateV1::PostAdmissionInterrupted
        ) {
            assert!(disposition.provider_execution.is_some());
            assert!(!disposition.disposition.permits_automatic_park());
        }
    }

    let mut unrepresentable: Value = serde_json::from_slice(include_bytes!(
        "../../../qualification/provider-execution-availability-and-deferred-dispatch-v1-20260831/fixtures/switchyard-provider-completed.snapshot.v1.json"
    ))
    .unwrap();
    unrepresentable["records"][1]["normalized"]["observed_at_ms"] =
        json!(9_007_199_254_740_991_i64);
    let raw = &unrepresentable["records"][1]["raw"];
    let bytes = hex::decode(raw["bytes_hex"].as_str().unwrap()).unwrap();
    let mut wire: Value = serde_json::from_slice(&bytes).unwrap();
    wire["params"]["observedAtMs"] = json!(9_007_199_254_740_991_i64);
    unrepresentable["records"][1]["raw"] = mapper_raw(wire);
    unrepresentable = reseal_mapper_snapshot(unrepresentable);
    let unrepresentable_disposition = disposition_from_exact_snapshot(
        &requirement,
        &dispatch,
        &canonical(&unrepresentable),
        time("2026-08-31T12:01:02Z"),
    );
    let unrepresentable_observation = observation_for_disposition(&unrepresentable_disposition);
    validate_execution_availability_graph(
        &requirement,
        &policy,
        &dispatch,
        &unrepresentable_observation,
        &unrepresentable_disposition,
        &[],
        None,
    )
    .unwrap_err();
}

#[test]
fn exact_switchyard_owner_terminal_transition_corpus_reopens() {
    let policy = policy();
    let requirement = requirement(&policy);
    let dispatch = dispatch(&requirement);
    let corpus: Value = serde_json::from_slice(include_bytes!(
        "../../../qualification/provider-execution-availability-and-deferred-dispatch-v1-20260831/fixtures/switchyard-owner-terminal-corpus.v1.json"
    ))
    .unwrap();
    assert_eq!(
        corpus["owner_head"],
        json!("2ba25db66d8b29dd215bd87e05f4ea794024b3b7")
    );
    for branch in [
        "closed_response_completed_shape",
        "notification_approval_watermark",
        "waiting_approval_then_notification_watermark",
        "refusal_then_discrepancy_indeterminate",
        "turn_completed_before_boundary_discrepancy",
        "turn_completed_during_approval_discrepancy",
        "provider_activity_after_approval_discrepancy",
        "unordered_waiting_approval_then_watermark",
    ] {
        assert!(corpus["branch_inventory"][branch].as_u64().unwrap() > 0);
    }
    let snapshots = corpus["snapshots"].as_array().unwrap();
    assert_eq!(corpus["owner_generated_terminal_snapshot_count"], 126);
    assert_eq!(corpus["owner_generic_replayable_snapshot_count"], 118);
    assert_eq!(
        corpus["owner_generic_helper_exceptions"]
            .as_array()
            .unwrap()
            .len(),
        8
    );
    assert_eq!(snapshots.len(), 126);
    let generic_replayable: BTreeSet<&str> = corpus["owner_generic_replayable_snapshot_digests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|digest| digest.as_str().unwrap())
        .collect();
    assert_eq!(generic_replayable.len(), 118);
    let generic_helper_exceptions: BTreeSet<&str> = corpus["owner_generic_helper_exceptions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|exception| exception["snapshot_digest"].as_str().unwrap())
        .collect();
    assert_eq!(generic_helper_exceptions.len(), 8);
    let mut kind_shapes = BTreeMap::<String, Value>::new();
    for snapshot in snapshots {
        let records = snapshot["records"].as_array().unwrap();
        let strict_ordered = records
            .iter()
            .filter(|record| record["kind"] != "ACQUISITION_CUT")
            .all(|record| {
                let local_acquisition_loss = record["kind"] == "ADMISSION_DISCREPANCY"
                    && record["method"] == "adapter/acquisition"
                    && record["raw"].is_null()
                    && record["acquisition_ordinal"].is_null()
                    && record["acquisition_kind"].is_null();
                local_acquisition_loss
                    || (!record["acquisition_ordinal"].is_null()
                        && !record["acquisition_kind"].is_null())
            });
        if !strict_ordered {
            continue;
        }
        for record in records {
            if record["kind"] != "ACQUISITION_CUT" {
                kind_shapes
                    .entry(record["kind"].as_str().unwrap().to_owned())
                    .or_insert_with(|| record["normalized"].clone());
            }
        }
    }
    for kind in [
        "PROVIDER_REQUEST_STARTED",
        "PROVIDER_EXECUTION_STEP",
        "PROVIDER_ADMISSION_REFUSED",
        "PROVIDER_RESPONSE_COMPLETED",
        "WAITING_APPROVAL",
        "LOCAL_TURN_FACT",
        "ADMISSION_DISCREPANCY",
        "ACQUISITION_WATERMARK",
        "CLIENT_REQUEST_ISSUED",
        "CLIENT_RESPONSE_RETAINED",
    ] {
        assert!(kind_shapes.contains_key(kind), "missing owner kind {kind}");
    }
    let mut saw_gap = false;
    let mut saw_duplicate = false;
    let mut saw_reorder = false;
    let mut saw_refusal_then_discrepancy = false;
    let mut saw_unordered_approval_watermark = false;
    let mut saw_unordered_approval_discrepancy = false;
    let mut saw_strict_notification_approval_watermark = false;
    let mut saw_strict_server_request_approval = false;
    let mut strict_ordered_count = 0;
    let mut unordered_compatibility_count = 0;
    let mut unordered_generic_helper_exception_count = 0;
    let mut strict_generic_helper_exception_count = 0;
    let mut proved_semantic_replay_not_entered = false;
    for snapshot in snapshots {
        let records = snapshot["records"].as_array().unwrap();
        let strict_ordered = records
            .iter()
            .filter(|record| record["kind"] != "ACQUISITION_CUT")
            .all(|record| {
                let local_acquisition_loss = record["kind"] == "ADMISSION_DISCREPANCY"
                    && record["method"] == "adapter/acquisition"
                    && record["raw"].is_null()
                    && record["acquisition_ordinal"].is_null()
                    && record["acquisition_kind"].is_null();
                local_acquisition_loss
                    || (!record["acquisition_ordinal"].is_null()
                        && !record["acquisition_kind"].is_null())
            });
        if !strict_ordered {
            unordered_compatibility_count += 1;
            saw_unordered_approval_watermark |= records.iter().any(|record| {
                record["kind"] == "ACQUISITION_WATERMARK"
                    && record["acquisition_kind"].is_null()
                    && record["method"] == "item/commandExecution/requestApproval"
            });
            saw_unordered_approval_discrepancy |= records.iter().any(|record| {
                record["kind"] == "ADMISSION_DISCREPANCY"
                    && record["acquisition_kind"].is_null()
                    && record["method"] == "item/commandExecution/requestApproval"
                    && record["normalized"]["detail"]
                        == "provider activity followed unanswered approval"
            });
            let raw = canonical(snapshot);
            let mut candidate = disposition_candidate_from_exact_snapshot(
                &requirement,
                &dispatch,
                &raw,
                time("2026-08-31T12:01:02Z"),
            );
            assert_eq!(
                candidate.seal().unwrap_err(),
                ContractError::InvalidField(
                    "decision-bearing mapper evidence requires strict ordered acquisition"
                )
            );
            if generic_helper_exceptions.contains(snapshot["snapshot_digest"].as_str().unwrap()) {
                unordered_generic_helper_exception_count += 1;
            }
            if !proved_semantic_replay_not_entered {
                let mut poisoned = snapshot.clone();
                let first = poisoned["records"]
                    .as_array_mut()
                    .unwrap()
                    .first_mut()
                    .unwrap();
                first["evidence_digest"] = json!(placeholder());
                poisoned = seal_value(
                    poisoned,
                    "snapshot_digest",
                    b"switchyard.codex-provider-admission-snapshot.digest/v1\0",
                );
                let poisoned_raw = canonical(&poisoned);
                let mut poisoned_candidate = disposition_candidate_from_exact_snapshot(
                    &requirement,
                    &dispatch,
                    &poisoned_raw,
                    time("2026-08-31T12:01:02Z"),
                );
                assert_eq!(
                    poisoned_candidate.seal().unwrap_err(),
                    ContractError::InvalidField(
                        "decision-bearing mapper evidence requires strict ordered acquisition"
                    )
                );
                proved_semantic_replay_not_entered = true;
            }
            continue;
        }
        strict_ordered_count += 1;
        if generic_helper_exceptions.contains(snapshot["snapshot_digest"].as_str().unwrap()) {
            strict_generic_helper_exception_count += 1;
            assert_eq!(snapshot["admission_disposition"], "ADMISSION_INDETERMINATE");
            assert_eq!(snapshot["mechanism_state"], "ADMISSION_INDETERMINATE");
        }
        saw_strict_notification_approval_watermark |= records.iter().any(|record| {
            record["kind"] == "ACQUISITION_WATERMARK"
                && record["acquisition_kind"] == "NOTIFICATION"
                && matches!(
                    record["method"].as_str(),
                    Some(
                        "item/commandExecution/requestApproval" | "item/fileChange/requestApproval"
                    )
                )
        });
        saw_strict_server_request_approval |= records.iter().any(|record| {
            record["kind"] == "WAITING_APPROVAL"
                && record["acquisition_kind"] == "SERVER_REQUEST"
                && matches!(
                    record["method"].as_str(),
                    Some(
                        "item/commandExecution/requestApproval" | "item/fileChange/requestApproval"
                    )
                )
        });
        let ordered_discrepancies: Vec<i64> = snapshot["records"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|record| {
                record["normalized"]["detail"]
                    == "ordered acquisition ordinal gap, duplicate, or reorder"
            })
            .filter_map(|record| record["acquisition_ordinal"].as_i64())
            .collect();
        let consumed = snapshot["acquisition_cut"]["consumed_ordinal_count"]
            .as_i64()
            .unwrap();
        saw_gap |= ordered_discrepancies.contains(&1) && consumed == 2;
        saw_duplicate |= ordered_discrepancies.contains(&0) && consumed == 1;
        saw_reorder |= ordered_discrepancies == [1, 0] && consumed == 2;
        let raw = canonical(snapshot);
        let disposition = disposition_from_exact_snapshot(
            &requirement,
            &dispatch,
            &raw,
            time("2026-08-31T12:01:02Z"),
        );
        disposition.validate().unwrap_or_else(|error| {
            panic!(
                "owner terminal transition {} failed Nightshift replay: {error}",
                snapshot["snapshot_digest"].as_str().unwrap()
            )
        });
        for (index, record) in snapshot["records"].as_array().unwrap().iter().enumerate() {
            if record["kind"] == "ACQUISITION_CUT" {
                continue;
            }
            for (alternate_kind, normalized_shape) in &kind_shapes {
                if record["kind"] == alternate_kind.as_str() {
                    continue;
                }
                let mut alternate = snapshot.clone();
                alternate["records"][index]["kind"] = json!(alternate_kind);
                alternate["records"][index]["normalized"] = normalized_shape.clone();
                alternate = reseal_mapper_snapshot(alternate);
                let alternate_raw = canonical(&alternate);
                let mut invalid = disposition.clone();
                invalid.mapper_snapshot_digest =
                    alternate["snapshot_digest"].as_str().unwrap().to_owned();
                invalid.mapper_snapshot =
                    ExactMapperSnapshotV1::from_bytes(&alternate_raw).unwrap();
                invalid.disposition_digest = placeholder();
                if invalid.seal().is_ok() {
                    let method = record["method"].as_str().unwrap();
                    let detail = record["normalized"]["detail"].as_str();
                    let owner_can_emit_alternate = record["acquisition_kind"].is_null()
                        && alternate_kind == "ACQUISITION_WATERMARK"
                        && ((record["kind"] == "ADMISSION_DISCREPANCY"
                            && matches!(
                                detail,
                                Some(
                                    "unknown App Server server request"
                                        | "approval identity substitution"
                                        | "approval request preceded provider admission"
                                        | "approval request preceded exact response completion"
                                        | "provider activity followed unanswered approval"
                                )
                            ))
                            || record["kind"] == "WAITING_APPROVAL")
                        && method != "error"
                        && !matches!(method, "thread/started" | "turn/started" | "turn/completed")
                        && !method.starts_with("providerAdmission/")
                        && !method.starts_with("providerRequest/")
                        && !method.starts_with("rawResponse/");
                    assert!(
                        owner_can_emit_alternate,
                        "owner record {} {} at {} admitted non-owner alternate kind {alternate_kind}",
                        record["kind"].as_str().unwrap(),
                        method,
                        snapshot["snapshot_digest"].as_str().unwrap(),
                    );
                }
            }

            if matches!(
                record["kind"].as_str(),
                Some(
                    "PROVIDER_REQUEST_STARTED"
                        | "PROVIDER_EXECUTION_STEP"
                        | "PROVIDER_ADMISSION_REFUSED"
                        | "PROVIDER_RESPONSE_COMPLETED"
                )
            ) {
                let prior_execution = snapshot["records"].as_array().unwrap()[..index]
                    .iter()
                    .rev()
                    .find(|candidate| candidate["kind"] == "PROVIDER_EXECUTION_STEP")
                    .map(|candidate| candidate["normalized"]["provider_execution_identity"].clone())
                    .unwrap_or(Value::Null);
                let resume = !prior_execution.is_null();
                let mut discrepancy = snapshot.clone();
                discrepancy["records"][index]["kind"] = json!("ADMISSION_DISCREPANCY");
                discrepancy["records"][index]["normalized"] = json!({
                    "detail":"unknown provider-boundary notification",
                    "provider_execution_identity":prior_execution,
                    "resume_same_attempt_only":resume,
                });
                discrepancy = reseal_mapper_snapshot(discrepancy);
                let discrepancy_raw = canonical(&discrepancy);
                let mut invalid = disposition.clone();
                invalid.mapper_snapshot_digest =
                    discrepancy["snapshot_digest"].as_str().unwrap().to_owned();
                invalid.mapper_snapshot =
                    ExactMapperSnapshotV1::from_bytes(&discrepancy_raw).unwrap();
                invalid.disposition_digest = placeholder();
                invalid.seal().unwrap_err();
            }

            if record["kind"] == "ADMISSION_DISCREPANCY" && record["method"] == "turn/completed" {
                let mut local_substitution = snapshot.clone();
                local_substitution["records"][index]["kind"] = json!("LOCAL_TURN_FACT");
                local_substitution["records"][index]["normalized"] =
                    json!({"proves_provider_admission":false});
                local_substitution = reseal_mapper_snapshot(local_substitution);
                let local_raw = canonical(&local_substitution);
                let mut invalid = disposition.clone();
                invalid.mapper_snapshot_digest = local_substitution["snapshot_digest"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                invalid.mapper_snapshot = ExactMapperSnapshotV1::from_bytes(&local_raw).unwrap();
                invalid.disposition_digest = placeholder();
                invalid.seal().unwrap_err();
            }

            if record["kind"] == "ADMISSION_DISCREPANCY"
                && record["method"] == "rawResponse/started"
                && record["normalized"]["detail"]
                    == "provider activity followed unanswered approval"
            {
                let owner_step = snapshot["records"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|candidate| candidate["kind"] == "PROVIDER_EXECUTION_STEP")
                    .unwrap();
                let mut step_substitution = snapshot.clone();
                step_substitution["records"][index]["kind"] = json!("PROVIDER_EXECUTION_STEP");
                step_substitution["records"][index]["normalized"] =
                    owner_step["normalized"].clone();
                step_substitution = reseal_mapper_snapshot(step_substitution);
                let step_raw = canonical(&step_substitution);
                let mut invalid = disposition.clone();
                invalid.mapper_snapshot_digest = step_substitution["snapshot_digest"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                invalid.mapper_snapshot = ExactMapperSnapshotV1::from_bytes(&step_raw).unwrap();
                invalid.disposition_digest = placeholder();
                invalid.seal().unwrap_err();
            }
        }
        let has_refusal = snapshot["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["kind"] == "PROVIDER_ADMISSION_REFUSED");
        let has_discrepancy = snapshot["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["kind"] == "ADMISSION_DISCREPANCY");
        if has_refusal && has_discrepancy {
            saw_refusal_then_discrepancy = true;
            assert_eq!(snapshot["admission_disposition"], "ADMISSION_INDETERMINATE");
            assert_eq!(snapshot["acquisition_cut"]["clean"], false);

            let mut substituted = snapshot.clone();
            substituted["acquisition_cut"]["clean"] = json!(true);
            let last = substituted["records"].as_array().unwrap().len() - 1;
            substituted["records"][last]["normalized"] = substituted["acquisition_cut"].clone();
            substituted = reseal_mapper_snapshot(substituted);
            let substituted_raw = canonical(&substituted);
            let mut invalid = disposition.clone();
            invalid.mapper_snapshot_digest =
                substituted["snapshot_digest"].as_str().unwrap().to_owned();
            invalid.mapper_snapshot = ExactMapperSnapshotV1::from_bytes(&substituted_raw).unwrap();
            invalid.disposition_digest = placeholder();
            invalid.seal().unwrap_err();
        }
    }
    assert!(saw_gap && saw_duplicate && saw_reorder);
    assert!(saw_refusal_then_discrepancy);
    assert_eq!(strict_ordered_count, 67);
    assert_eq!(unordered_compatibility_count, 59);
    assert_eq!(unordered_generic_helper_exception_count, 7);
    assert_eq!(strict_generic_helper_exception_count, 1);
    assert!(proved_semantic_replay_not_entered);
    assert!(saw_unordered_approval_watermark && saw_unordered_approval_discrepancy);
    assert!(saw_strict_notification_approval_watermark);
    assert!(saw_strict_server_request_approval);
}

#[test]
fn exact_loss_unknown_and_legacy_rawless_owner_variants_reopen() {
    let policy = policy();
    let requirement = requirement(&policy);
    let dispatch = dispatch(&requirement);
    let received = time("2026-08-31T12:01:02Z");

    let mut loss: Value = serde_json::from_slice(include_bytes!(
        "../../../qualification/provider-execution-availability-and-deferred-dispatch-v1-20260831/fixtures/switchyard-admission-indeterminate.snapshot.v1.json"
    ))
    .unwrap();
    let malformed = b"{\"duplicate\":1,\"duplicate\":2}\n";
    loss["records"][1]["raw"] = json!({
        "representation":"EXACT_ACQUIRED_FRAME_BYTES_INCLUDING_LINE_TERMINATOR",
        "byte_length":malformed.len(),
        "sha256":format!("sha256:{:x}", Sha256::digest(malformed)),
        "encoding":"hex",
        "bytes_hex":hex::encode(malformed),
    });
    loss = reseal_mapper_snapshot(loss);
    disposition_from_exact_snapshot(&requirement, &dispatch, &canonical(&loss), received)
        .validate()
        .unwrap();

    let mut unknown = loss.clone();
    unknown["records"][1]["acquisition_kind"] = json!("UNKNOWN");
    unknown["records"][1]["raw"] = Value::Null;
    unknown["records"][1]["normalized"]["detail"] =
        json!("unknown ordered acquisition envelope kind");
    unknown = reseal_mapper_snapshot(unknown);
    disposition_from_exact_snapshot(&requirement, &dispatch, &canonical(&unknown), received)
        .validate()
        .unwrap();

    let valid_unknown =
        disposition_from_exact_snapshot(&requirement, &dispatch, &canonical(&unknown), received);
    for (lane, method) in [
        ("CLIENT_REQUEST", "client-request/thread/read"),
        ("CLIENT_RESPONSE", "client-response/thread/read"),
    ] {
        let mut impossible = unknown.clone();
        impossible["records"][1]["acquisition_kind"] = json!(lane);
        impossible["records"][1]["method"] = json!(method);
        impossible["records"][1]["normalized"]["detail"] =
            json!("exact App Server wire bytes are required");
        impossible = reseal_mapper_snapshot(impossible);
        let impossible_raw = canonical(&impossible);
        let mut invalid = valid_unknown.clone();
        invalid.mapper_snapshot_digest = impossible["snapshot_digest"].as_str().unwrap().to_owned();
        invalid.mapper_snapshot = ExactMapperSnapshotV1::from_bytes(&impossible_raw).unwrap();
        invalid.disposition_digest = placeholder();
        invalid.seal().unwrap_err();
    }

    let mut rawless_ordered = unknown.clone();
    rawless_ordered["records"][1]["acquisition_kind"] = json!("NOTIFICATION");
    rawless_ordered["records"][1]["normalized"]["detail"] =
        json!("ordered message envelope shape mismatch");
    rawless_ordered = reseal_mapper_snapshot(rawless_ordered);
    disposition_from_exact_snapshot(
        &requirement,
        &dispatch,
        &canonical(&rawless_ordered),
        received,
    )
    .validate()
    .unwrap();

    let mut malformed_method = unknown.clone();
    malformed_method["records"][1]["acquisition_kind"] = json!("NOTIFICATION");
    malformed_method["records"][1]["method"] = json!("unknown");
    malformed_method["records"][1]["raw"] = mapper_raw(json!({"method":1}));
    malformed_method["records"][1]["normalized"]["detail"] =
        json!("App Server method is not a string");
    malformed_method = reseal_mapper_snapshot(malformed_method);
    disposition_from_exact_snapshot(
        &requirement,
        &dispatch,
        &canonical(&malformed_method),
        received,
    )
    .validate()
    .unwrap();

    let mut legacy: Value = serde_json::from_slice(include_bytes!(
        "../../../qualification/provider-execution-availability-and-deferred-dispatch-v1-20260831/fixtures/switchyard-provider-completed.snapshot.v1.json"
    ))
    .unwrap();
    for record in legacy["records"].as_array_mut().unwrap() {
        record["sequence"] = json!(record["sequence"].as_u64().unwrap() + 1);
    }
    let mut local = legacy["records"][3].clone();
    local["sequence"] = json!(0);
    local["acquisition_ordinal"] = Value::Null;
    local["acquisition_kind"] = Value::Null;
    local["method"] = json!("thread/start");
    local["raw"] = Value::Null;
    legacy["records"].as_array_mut().unwrap().insert(0, local);
    legacy = reseal_mapper_snapshot(legacy);
    let mut legacy_candidate = disposition_candidate_from_exact_snapshot(
        &requirement,
        &dispatch,
        &canonical(&legacy),
        received,
    );
    legacy_candidate.seal().unwrap_err();
}

#[test]
fn exact_owner_provider_order_discrepancy_is_derived_from_raw() {
    let policy = policy();
    let requirement = requirement(&policy);
    let dispatch = dispatch(&requirement);
    let mut snapshot = parked_snapshot();
    let mut discrepancy = snapshot["records"][0].clone();
    let bytes = hex::decode(discrepancy["raw"]["bytes_hex"].as_str().unwrap()).unwrap();
    let mut wire: Value = serde_json::from_slice(&bytes).unwrap();
    wire["params"]["samplingOrdinal"] = json!(1);
    wire["params"]["requestOrder"] = json!(1);
    discrepancy["raw"] = mapper_raw(wire);
    discrepancy["kind"] = json!("ADMISSION_DISCREPANCY");
    discrepancy["normalized"] = json!({
        "detail":"provider request ordering or hidden retry discrepancy",
        "provider_execution_identity":null,
        "resume_same_attempt_only":false,
    });
    let mut cut = snapshot["records"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    cut["sequence"] = json!(1);
    cut["normalized"]["ordered_high_water"] = json!(1);
    cut["normalized"]["consumed_ordinal_count"] = json!(1);
    cut["normalized"]["clean"] = json!(false);
    snapshot["records"] = json!([discrepancy, cut]);
    snapshot["admission_disposition"] = json!("ADMISSION_INDETERMINATE");
    snapshot["mechanism_state"] = json!("ADMISSION_INDETERMINATE");
    snapshot["provider_execution_identity"] = Value::Null;
    snapshot["acquisition_cut"]["ordered_high_water"] = json!(1);
    snapshot["acquisition_cut"]["consumed_ordinal_count"] = json!(1);
    snapshot["acquisition_cut"]["clean"] = json!(false);
    snapshot["records"][1]["normalized"] = snapshot["acquisition_cut"].clone();
    snapshot = reseal_mapper_snapshot(snapshot);
    let disposition = disposition_from_exact_snapshot(
        &requirement,
        &dispatch,
        &canonical(&snapshot),
        time("2026-08-31T12:01:02Z"),
    );
    disposition.validate().unwrap();

    snapshot["records"][0]["normalized"]["detail"] =
        json!("unknown provider-boundary notification");
    snapshot = reseal_mapper_snapshot(snapshot);
    let mut substituted = disposition;
    substituted.mapper_snapshot_digest = snapshot["snapshot_digest"].as_str().unwrap().to_owned();
    substituted.mapper_snapshot = ExactMapperSnapshotV1::from_bytes(&canonical(&snapshot)).unwrap();
    substituted.seal().unwrap_err();
}

#[test]
fn exact_owner_approval_method_reaches_waiting_and_raw_identity_substitution_refuses() {
    let policy = policy();
    let requirement = requirement(&policy);
    let dispatch = dispatch(&requirement);
    let mut snapshot: Value = serde_json::from_slice(include_bytes!(
        "../../../qualification/provider-execution-availability-and-deferred-dispatch-v1-20260831/fixtures/switchyard-approval-interrupted.snapshot.v1.json"
    ))
    .unwrap();
    let execution = snapshot["provider_execution_identity"].clone();
    let approval = &mut snapshot["records"][3];
    approval["kind"] = json!("WAITING_APPROVAL");
    approval["method"] = json!("item/commandExecution/requestApproval");
    approval["raw"] = mapper_raw(json!({
        "method":"item/commandExecution/requestApproval",
        "params":{"threadId":"thread-holding-1","turnId":"turn-holding-1"}
    }));
    approval["normalized"] = json!({
        "approval_response_sent":false,
        "protected_effect_absent":true,
        "provider_execution_identity":execution,
    });
    snapshot = reseal_mapper_snapshot(snapshot);
    let disposition = disposition_from_exact_snapshot(
        &requirement,
        &dispatch,
        &canonical(&snapshot),
        time("2026-08-31T12:01:02Z"),
    );
    assert_eq!(
        disposition.mechanism_state,
        ProviderMechanismStateV1::PostAdmissionInterrupted
    );

    let raw = &mut snapshot["records"][1]["raw"];
    let bytes = hex::decode(raw["bytes_hex"].as_str().unwrap()).unwrap();
    let mut wire: Value = serde_json::from_slice(&bytes).unwrap();
    wire["params"]["threadId"] = json!("thread-substituted");
    snapshot["records"][1]["normalized"]["provider_execution_step_identity"]["thread_id"] =
        json!("thread-substituted");
    snapshot["records"][1]["raw"] = mapper_raw(wire);
    snapshot = reseal_mapper_snapshot(snapshot);
    let mut substituted = disposition;
    substituted.mapper_snapshot_digest = snapshot["snapshot_digest"].as_str().unwrap().to_owned();
    substituted.mapper_snapshot = ExactMapperSnapshotV1::from_bytes(&canonical(&snapshot)).unwrap();
    substituted.seal().unwrap_err();
}

fn qualification_disposition(
    requirement: &ForemanExecutionAvailabilityRequirementV1,
    dispatch: &ProviderDispatchOccurrenceV1,
    outcome: DeterministicProviderAdmissionOutcomeV1,
    response_created: bool,
) -> (
    DeterministicProviderAdmissionEvidenceV1,
    ProviderAdmissionDispositionV1,
    ExecutionAvailabilityObservationV1,
) {
    let received_at = time("2026-08-31T12:01:02Z");
    let observed_at = time("2026-08-31T12:01:01Z");
    let retry_after = matches!(
        outcome,
        DeterministicProviderAdmissionOutcomeV1::RateLimited
            | DeterministicProviderAdmissionOutcomeV1::ProviderUnavailable
    )
    .then(|| time("2026-08-31T12:01:07Z"));
    let non_admission_proven = matches!(
        outcome,
        DeterministicProviderAdmissionOutcomeV1::RateLimited
            | DeterministicProviderAdmissionOutcomeV1::ProviderUnavailable
            | DeterministicProviderAdmissionOutcomeV1::AuthenticationRefused
    );
    let raw = canonical(&json!({
        "outcome": outcome,
        "response_created": response_created,
        "non_admission_proven": non_admission_proven,
        "retry_after": retry_after,
        "observed_at": observed_at,
    }));
    let mut evidence = DeterministicProviderAdmissionEvidenceV1 {
        schema: DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V1.to_owned(),
        evidence_digest: placeholder(),
        producer_id: HOLDING_QUALIFICATION_PRODUCER_ID.to_owned(),
        producer_version: HOLDING_QUALIFICATION_PRODUCER_VERSION.to_owned(),
        executable_id: HOLDING_QUALIFICATION_EXECUTABLE_ID.to_owned(),
        executable_sha256: HOLDING_QUALIFICATION_EXECUTABLE_SHA256.to_owned(),
        work_attempt_id: dispatch.work_attempt_id.clone(),
        dispatch_occurrence_id: dispatch.dispatch_occurrence_id.clone(),
        provider_request_occurrence_id: "qualification-request-1".to_owned(),
        provider_id: dispatch.selection.provider_id.clone(),
        model_id: dispatch.selection.model_id.clone(),
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
    let evidence_bytes = canonical(&evidence);
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
        disposition_digest: placeholder(),
        dispatch_digest: dispatch.dispatch_digest.clone(),
        requirement_digest: requirement.requirement_digest.clone(),
        policy_digest: requirement.policy_digest.clone(),
        packet_digest: requirement.packet_digest.clone(),
        run_id: requirement.run_id.clone(),
        work_item_id: dispatch.work_item_id.clone(),
        work_attempt_id: dispatch.work_attempt_id.clone(),
        dispatch_occurrence_id: dispatch.dispatch_occurrence_id.clone(),
        provider_id: dispatch.selection.provider_id.clone(),
        model_id: dispatch.selection.model_id.clone(),
        provider_request_occurrence_id: evidence.provider_request_occurrence_id.clone(),
        adapter_process_occurrence_id: dispatch.adapter_process_occurrence_id.clone(),
        app_server_session_identity: dispatch.app_server_session_identity.clone(),
        thread_id: "qualification-thread-1".to_owned(),
        turn_id: "qualification-turn-1".to_owned(),
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
        observation_digest: placeholder(),
        provider_id: dispatch.selection.provider_id.clone(),
        model_id: dispatch.selection.model_id.clone(),
        model_class: dispatch.selection.model_class.clone(),
        observed_at,
        received_at,
        expires_at: time("2026-08-31T12:02:02Z"),
        state,
        source_identity: HOLDING_QUALIFICATION_PRODUCER_ID.to_owned(),
        source_version: HOLDING_QUALIFICATION_PRODUCER_VERSION.to_owned(),
        provider_retry_after: retry_after,
        exact_evidence: Some(evidence.raw_evidence.clone()),
        authority_effect: "SCHEDULING_MECHANISM_EVIDENCE_ONLY".to_owned(),
    };
    observation.seal().unwrap();
    (evidence, disposition, observation)
}

#[test]
fn qualification_only_owner_closes_outcomes_and_substitutions() {
    let executable = include_bytes!(
        "../../../qualification/provider-execution-availability-and-deferred-dispatch-v1-20260831/fixtures/deterministic-fake-adapter-v1.py"
    );
    assert_eq!(
        format!("sha256:{:x}", Sha256::digest(executable)),
        HOLDING_QUALIFICATION_EXECUTABLE_SHA256
    );
    for schema_bytes in [
        include_bytes!(
            "../../../schemas/nightshift.holding-deterministic-provider-admission-evidence.v1.schema.json"
        )
        .as_slice(),
        include_bytes!(
            "../../../schemas/nightshift.provider-admission-disposition.v2.schema.json"
        )
        .as_slice(),
    ] {
        let schema: Value = serde_json::from_slice(schema_bytes).unwrap();
        assert_eq!(schema["additionalProperties"], false);
    }
    let policy = policy();
    let mut requirement = requirement(&policy);
    requirement.adapter_id = HOLDING_QUALIFICATION_PRODUCER_ID.to_owned();
    requirement.adapter_protocol = DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V1.to_owned();
    requirement.adapter_version = HOLDING_QUALIFICATION_PRODUCER_VERSION.to_owned();
    requirement.adapter_executable_identity = HOLDING_QUALIFICATION_EXECUTABLE_SHA256.to_owned();
    requirement.seal().unwrap();
    let dispatch = dispatch(&requirement);
    for (outcome, response_created) in [
        (DeterministicProviderAdmissionOutcomeV1::RateLimited, false),
        (
            DeterministicProviderAdmissionOutcomeV1::ProviderUnavailable,
            false,
        ),
        (
            DeterministicProviderAdmissionOutcomeV1::AuthenticationRefused,
            false,
        ),
        (
            DeterministicProviderAdmissionOutcomeV1::TransportError,
            false,
        ),
        (
            DeterministicProviderAdmissionOutcomeV1::TransportError,
            true,
        ),
        (
            DeterministicProviderAdmissionOutcomeV1::ProtocolError,
            false,
        ),
    ] {
        let (evidence, disposition, observation) =
            qualification_disposition(&requirement, &dispatch, outcome, response_created);
        evidence.validate().unwrap();
        disposition.validate().unwrap();
        if disposition.permits_automatic_park() {
            let mut deferred = DeferredProviderDispatchV1 {
                schema: DEFERRED_PROVIDER_DISPATCH_SCHEMA_V1.to_owned(),
                deferred_dispatch_digest: placeholder(),
                requirement_digest: requirement.requirement_digest.clone(),
                policy_digest: policy.policy_digest.clone(),
                disposition_digest: disposition.disposition_digest.clone(),
                packet_digest: requirement.packet_digest.clone(),
                run_id: requirement.run_id.clone(),
                work_item_id: dispatch.work_item_id.clone(),
                work_attempt_id: dispatch.work_attempt_id.clone(),
                last_dispatch_occurrence_id: dispatch.dispatch_occurrence_id.clone(),
                provider_id: dispatch.selection.provider_id.clone(),
                model_id: dispatch.selection.model_id.clone(),
                selected_model_ordinal: 0,
                remaining_model_ordinals: vec![1],
                refusal_received_at: disposition.received_at,
                wake_basis: DeferredWakeBasisV1::ProviderRetryAfter,
                backoff_ordinal: 0,
                backoff_seconds: 5,
                provider_retry_after: disposition.provider_retry_after,
                wake_at: disposition.provider_retry_after.unwrap(),
                parked_resource_lock_policy: policy.parked_resource_lock_policy,
                provider_capacity_released: true,
                semantic_retry: false,
                authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".to_owned(),
            };
            deferred.seal().unwrap();
            validate_execution_availability_graph(
                &requirement,
                &policy,
                &dispatch,
                &observation,
                &disposition,
                &[],
                Some(&deferred),
            )
            .unwrap();
        } else {
            validate_execution_availability_graph(
                &requirement,
                &policy,
                &dispatch,
                &observation,
                &disposition,
                &[],
                None,
            )
            .unwrap();
        }

        let mut substituted = evidence.clone();
        substituted.dispatch_occurrence_id = "dispatch-substituted".to_owned();
        substituted.seal().unwrap();
        let bytes = canonical(&substituted);
        let mut split = disposition.clone();
        split.mapper_snapshot_digest = substituted.evidence_digest.clone();
        split.mapper_snapshot =
            ExactMapperSnapshotV1::from_qualification_evidence_bytes(&bytes).unwrap();
        split.seal().unwrap_err();
    }
}

#[test]
fn second_watch_qualification_owner_retry_after_matrix_is_exact() {
    let received_at = time("2026-08-31T12:01:02Z");
    let observed_at = time("2026-08-31T12:01:01Z");
    let retry_after = time("2026-08-31T12:01:07Z");
    let execution = ProviderExecutionIdentityV1 {
        provider_id: "fixture-provider".to_owned(),
        model_id: "fixture-model".to_owned(),
        app_server_session_identity: "fixture-session".to_owned(),
        thread_id: "fixture-thread".to_owned(),
        turn_id: "fixture-turn".to_owned(),
        first_response_id: "fixture-response".to_owned(),
    };
    let make =
        |outcome, response_created, non_admission_proven, retry_after, provider_execution| {
            let raw = canonical(&json!({
                "outcome": outcome,
                "response_created": response_created,
                "non_admission_proven": non_admission_proven,
                "retry_after": retry_after,
                "observed_at": observed_at,
                "provider_execution": provider_execution,
            }));
            let mut evidence = DeterministicProviderAdmissionEvidenceV2 {
                schema: DETERMINISTIC_PROVIDER_ADMISSION_EVIDENCE_SCHEMA_V2.to_owned(),
                evidence_digest: placeholder(),
                producer_id: HOLDING_QUALIFICATION_PRODUCER_ID.to_owned(),
                producer_version: SECOND_WATCH_QUALIFICATION_PRODUCER_VERSION.to_owned(),
                executable_id: SECOND_WATCH_QUALIFICATION_EXECUTABLE_ID.to_owned(),
                executable_sha256: SECOND_WATCH_QUALIFICATION_EXECUTABLE_SHA256.to_owned(),
                work_attempt_id: "fixture-attempt".to_owned(),
                dispatch_occurrence_id: "fixture-dispatch".to_owned(),
                provider_request_occurrence_id: "fixture-request".to_owned(),
                provider_id: "fixture-provider".to_owned(),
                model_id: "fixture-model".to_owned(),
                outcome,
                response_created,
                non_admission_proven,
                retry_after,
                observed_at,
                received_at,
                provider_execution,
                raw_evidence: ExactAvailabilityEvidenceV1::from_bytes(
                    "EXACT_PROVIDER_AVAILABILITY_SOURCE_BYTES",
                    &raw,
                )
                .unwrap(),
                authority_effect: "QUALIFICATION_MECHANISM_EVIDENCE_ONLY".to_owned(),
            };
            let result = evidence.seal();
            (evidence, result)
        };

    assert!(make(
        DeterministicProviderAdmissionOutcomeV2::ProviderUnavailable,
        false,
        true,
        Some(retry_after),
        None,
    )
    .1
    .is_ok());
    assert!(make(
        DeterministicProviderAdmissionOutcomeV2::ExecutionCompleted,
        true,
        false,
        None,
        Some(execution.clone()),
    )
    .1
    .is_ok());
    assert!(make(
        DeterministicProviderAdmissionOutcomeV2::ProviderUnavailable,
        false,
        true,
        None,
        None,
    )
    .1
    .is_err());
    assert!(make(
        DeterministicProviderAdmissionOutcomeV2::ExecutionCompleted,
        true,
        false,
        Some(retry_after),
        Some(execution),
    )
    .1
    .is_err());
}

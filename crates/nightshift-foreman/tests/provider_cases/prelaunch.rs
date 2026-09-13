use super::*;

#[test]
fn prelaunch_python_vector_round_trips_exact_fractional_instants() {
    let raw = include_bytes!("prelaunch-vector.json");
    let value = nightshift_foreman::PrelaunchClosureV1::from_slice(raw).unwrap();
    assert_eq!(value.closed_at.timestamp_subsec_nanos(), 665_056_002);
    assert_eq!(
        value
            .supervisor_attestation
            .as_ref()
            .unwrap()
            .observed_at
            .timestamp_subsec_nanos(),
        665_056_001
    );
    assert_eq!(
        holding_canonical(&value),
        raw.strip_suffix(b"\n").unwrap_or(raw)
    );
}

fn closure_fixture(
    store: &ForemanStore,
    opened: &nightshift_foreman::OpenedProviderDispatchV1,
) -> Value {
    let request = &opened.worker_start_request;
    let dispatch = &opened.dispatch;
    let sha = |raw: &[u8]| format!("sha256:{:x}", Sha256::digest(raw));
    let binding = json!({
        "packet_digest": request.packet_digest, "run_id": request.run_id,
        "work_item_id": request.work_item_id, "work_attempt_id": request.work_attempt_id,
        "dispatch_occurrence_id": request.dispatch_occurrence_id,
        "adapter_process_occurrence_id": dispatch.adapter_process_occurrence_id,
        "request_digest": request.request_digest, "request_sha256": sha(&holding_canonical(request)),
        "worker_brief_digest": request.worker_brief_digest,
        "brief_sha256": sha(&store.worker_brief(&request.run_id, &request.work_item_id).unwrap()),
        "backend_sha256": format!("sha256:{}", "6".repeat(64)),
        "dispatch_digest": dispatch.dispatch_digest, "dispatch_sha256": sha(&holding_canonical(dispatch)),
        "switchyard_owner_head": request.switchyard_owner_head, "codex_owner_head": request.codex_owner_head,
    });
    let proof = json!({
        "schema": "switchyard.prelaunch-supervisor-attestation/v1", "binding": binding,
        "supervisor_identity": "local-test-owner", "host": "local-test-host", "unit": "fixture.service",
        "invocation_id": "2".repeat(32), "active_state": "inactive", "result": "exit-code", "exit_code": 1,
        "observed_at": "2026-08-31T12:01:02Z", "original_runner_sha256": format!("sha256:{}", "3".repeat(64)),
        "unit_evidence_sha256": format!("sha256:{}", "4".repeat(64)),
        "failure_evidence_sha256": format!("sha256:{}", "5".repeat(64)),
        "boundary": "BEFORE_PROVIDER_CLAIM", "original_producer_terminated": true,
        "alternate_writers_excluded": true, "trust_basis": "OWNER_ATTESTATION_NOT_INDEPENDENT_PROCESS_PROOF",
    });
    reseal(json!({
        "schema": "switchyard.provider-prelaunch-closure/v1", "binding": binding,
        "closed_at": "2026-08-31T12:01:02Z", "evidence_mode": "SUPERVISOR_ATTESTED_PRECLAIM_FAILURE",
        "failure_code": "EXECUTABLE_CAPTURE_FAILED", "supervisor_attestation": proof,
        "observer_source_head": "1".repeat(40), "observer_runner_sha256": format!("sha256:{}", "7".repeat(64)),
        "state": "PRELAUNCH_CLOSED", "provider_claim_absent": true, "backend_started": false,
        "authority_effect": "LOCAL_PRELAUNCH_CLOSURE_ONLY",
    }))
}

fn reseal(value: Value) -> Value {
    holding_seal_value(
        value,
        "closure_digest",
        nightshift_foreman::PRELAUNCH_CLOSURE_DOMAIN,
    )
}

#[test]
fn prelaunch_closure_is_atomic_idempotent_and_keeps_prepared_attempt_history() {
    let (_directory, path, store, _packet, _admission, _profile, _policy, _requirement) =
        holding_setup();
    let (attempt, opened) = holding_open_initial(&store);
    let value = closure_fixture(&store, &opened);
    let raw = holding_canonical(&value);
    let receipt = store.accept_prelaunch_closure(&raw).unwrap();
    let events = store.export_events("run-holding-store").unwrap();
    assert_eq!(store.accept_prelaunch_closure(&raw).unwrap(), receipt);
    assert_eq!(store.export_events("run-holding-store").unwrap(), events);
    let report = NotStartedReceiptV1::from_slice(&receipt).unwrap();
    assert_eq!(report.result_classification, "LOCAL_PRELAUNCH_FAILURE");
    assert_eq!(
        report.extensions["prepared_attempt_id"],
        json!(attempt.attempt_id)
    );
    assert!(report
        .remaining_trigger
        .contains("Prepared attempt retained"));
    drop(store);
    let reopened = ForemanStore::open_read_only(&path).unwrap();
    let projection = reopened.projection("run-holding-store").unwrap();
    let item = projection
        .work_items
        .iter()
        .find(|v| v.work_item_id == "work-a")
        .unwrap();
    assert_eq!(item.scheduler_state, SchedulerStateV1::NotStarted);
    assert_eq!(
        item.active_attempt_id.as_deref(),
        Some(attempt.attempt_id.as_str())
    );
    assert!(projection
        .resource_claims
        .iter()
        .all(|claim| claim.work_item_id != "work-a"));
    read_only_run_snapshot(&path, "run-holding-store").unwrap();
    let mut conflict = value;
    conflict["supervisor_attestation"]["unit_evidence_sha256"] =
        json!(format!("sha256:{}", "f".repeat(64)));
    let store = ForemanStore::open(&path).unwrap();
    assert!(store
        .accept_prelaunch_closure(&holding_canonical(&reseal(conflict)))
        .is_err());
}

#[test]
fn preflight_failure_requires_the_same_terminal_preclaim_testimony() {
    let (_directory, _path, store, _packet, _admission, _profile, _policy, _requirement) =
        holding_setup();
    let (_, opened) = holding_open_initial(&store);
    let mut closure = closure_fixture(&store, &opened);
    closure["failure_code"] = json!("REQUEST_PREFLIGHT_FAILED");
    let receipt = store
        .accept_prelaunch_closure(&holding_canonical(&reseal(closure.clone())))
        .unwrap();
    assert_eq!(
        NotStartedReceiptV1::from_slice(&receipt).unwrap().result_classification,
        "LOCAL_PRELAUNCH_FAILURE"
    );

    let (_directory, _path, store, _packet, _admission, _profile, _policy, _requirement) =
        holding_setup();
    let (_, opened) = holding_open_initial(&store);
    let mut no_testimony = closure_fixture(&store, &opened);
    no_testimony["failure_code"] = json!("REQUEST_PREFLIGHT_FAILED");
    no_testimony["evidence_mode"] = json!("OBSERVED_CAPTURE_FAILURE");
    no_testimony["supervisor_attestation"] = Value::Null;
    assert!(store
        .accept_prelaunch_closure(&holding_canonical(&reseal(no_testimony)))
        .is_err());
}

#[test]
fn prelaunch_wrong_binding_unknown_state_and_nonterminal_supervisor_leave_attempt_unchanged() {
    let (_directory, _path, store, _packet, _admission, _profile, _policy, _requirement) =
        holding_setup();
    let (_, opened) = holding_open_initial(&store);
    let original = closure_fixture(&store, &opened);
    let before = store.export_events("run-holding-store").unwrap();
    let mutations: [fn(&mut Value); 5] = [
        |v| v["supervisor_attestation"]["active_state"] = json!("active"),
        |v| v["state"] = json!("UNKNOWN"),
        |v| v["supervisor_attestation"]["alternate_writers_excluded"] = json!(false),
        |v| v["supervisor_attestation"]["binding"]["work_attempt_id"] = json!("wrong"),
        |v| {
            v["binding"]["dispatch_digest"] = json!(format!("sha256:{}", "f".repeat(64)));
            v["supervisor_attestation"]["binding"] = v["binding"].clone();
        },
    ];
    for mutate in mutations {
        let mut changed = original.clone();
        mutate(&mut changed);
        assert!(store
            .accept_prelaunch_closure(&holding_canonical(&reseal(changed)))
            .is_err());
        assert_eq!(store.export_events("run-holding-store").unwrap(), before);
    }
    let report = store
        .accept_prelaunch_closure(&holding_canonical(&original))
        .unwrap();
    // The dedicated recovery does not relax the original no-attempt V1 ingress.
    assert!(store.accept_not_started(&report).is_err());
}

#[test]
fn prelaunch_closure_refuses_any_retained_provider_disposition() {
    let (_directory, _path, store, _packet, _admission, _profile, policy, requirement) =
        holding_setup();
    let (_, opened) = holding_open_initial(&store);
    let closure = closure_fixture(&store, &opened);
    holding_record(
        &store,
        &requirement,
        &policy,
        &opened,
        "parked",
        holding_time("2026-08-31T12:01:02Z"),
        None,
    );
    let before = store.export_events("run-holding-store").unwrap();
    assert!(store
        .accept_prelaunch_closure(&holding_canonical(&closure))
        .is_err());
    assert_eq!(store.export_events("run-holding-store").unwrap(), before);
}

#[test]
fn prelaunch_native_cli_accepts_exact_receipt_and_replays_without_a_provider() {
    let (directory, path, store, _packet, _admission, _profile, _policy, _requirement) =
        holding_setup();
    let (_, opened) = holding_open_initial(&store);
    let mut raw = holding_canonical(&closure_fixture(&store, &opened));
    raw.push(b'\n'); // Native Switchyard stdout transport has one terminal LF.
    let receipt_path = directory.path().join("closure.json");
    fs::write(&receipt_path, raw).unwrap();
    drop(store);
    let invoke = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_nightshift-foreman"))
            .args([
                "accept-prelaunch-closure",
                "--db",
                path.to_str().unwrap(),
                "--receipt",
                receipt_path.to_str().unwrap(),
            ])
            .output()
            .unwrap()
    };
    let first = invoke();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let second = invoke();
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(first.stdout, second.stdout);
    let receipt = NotStartedReceiptV1::from_slice(&first.stdout).unwrap();
    assert_eq!(receipt.result_classification, "LOCAL_PRELAUNCH_FAILURE");
    let replay = std::process::Command::new(env!("CARGO_BIN_EXE_nightshift-foreman"))
        .args([
            "replay",
            "--db",
            path.to_str().unwrap(),
            "--run-id",
            "run-holding-store",
        ])
        .output()
        .unwrap();
    assert!(
        replay.status.success(),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    read_only_run_snapshot(&path, "run-holding-store").unwrap();
}

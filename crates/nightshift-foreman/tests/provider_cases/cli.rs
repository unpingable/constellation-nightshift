use super::*;
use std::process::{Command, Output};

fn invoke(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nightshift-foreman"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn real_snapshot_translation_preserves_existing_owner_graph_and_uncertainty() {
    for name in [
        "completed",
        "parked",
        "indeterminate",
        "interrupted",
        "approval",
    ] {
        let (_directory, _path, store, _packet, admission, _profile, policy, requirement) =
            holding_setup();
        let opened = store
            .prepare_provider_attempt(
                &admission.run_id,
                "work-a",
                "derived-dispatch",
                "derived-process",
                "derived-session",
                0,
                holding_time("2026-08-31T12:00:01Z"),
            )
            .unwrap();
        let received = holding_time("2026-08-31T12:00:02Z");
        let (raw, expected, expected_observation) =
            holding_disposition(&requirement, &opened, name, received);
        let (disposition, observation) = nightshift_foreman::derive_provider_snapshot_evidence(
            &requirement,
            &opened.dispatch,
            &raw,
            received,
            received + Duration::seconds(60),
        )
        .unwrap();
        assert_eq!(disposition, expected);
        assert_eq!(observation, expected_observation);
        let deferred = disposition
            .permits_automatic_park()
            .then(|| holding_deferred(&requirement, &policy, &opened, &disposition));
        nightshift_foreman::validate_execution_availability_graph(
            &requirement,
            &policy,
            &opened.dispatch,
            &observation,
            &disposition,
            &[],
            deferred.as_ref(),
        )
        .unwrap();
        let mut substituted = opened.dispatch.clone();
        substituted.dispatch_occurrence_id = "different-dispatch".to_owned();
        substituted.seal().unwrap();
        assert!(nightshift_foreman::derive_provider_snapshot_evidence(
            &requirement,
            &substituted,
            &raw,
            received,
            received + Duration::seconds(60),
        )
        .is_err());
    }
}

#[test]
fn cli_opens_real_owner_dispatch_and_refuses_duplicate_without_launching() {
    let (directory, path, packet, admission, profile, policy, requirement) =
        holding_fixture_contracts();
    for (name, bytes) in [
        ("packet", packet.canonical_bytes().unwrap()),
        ("admission", holding_canonical(&admission)),
        ("profile", holding_canonical(&profile)),
        ("policy", holding_canonical(&policy)),
        ("requirement", holding_canonical(&requirement)),
    ] {
        fs::write(directory.path().join(name), bytes).unwrap();
    }
    let file = |name: &str| directory.path().join(name).to_str().unwrap().to_owned();
    let database = path.to_str().unwrap();
    let admitted = invoke(&[
        "provider-admit",
        "--db",
        database,
        "--packet",
        &file("packet"),
        "--admission",
        &file("admission"),
        "--profile",
        &file("profile"),
        "--requirement",
        &file("requirement"),
        "--policy",
        &file("policy"),
        "--evaluated-at",
        "2026-08-31T12:00:00Z",
    ]);
    assert!(
        admitted.status.success(),
        "{}",
        String::from_utf8_lossy(&admitted.stderr)
    );
    let arguments = [
        "provider-prepare",
        "--db",
        database,
        "--run-id",
        &admission.run_id,
        "--work-item",
        "work-a",
        "--dispatch",
        "cli-dispatch-1",
        "--adapter-process",
        "cli-adapter-1",
        "--app-server-session",
        "cli-session-1",
        "--selected-model-ordinal",
        "0",
        "--recorded-at",
        "2026-08-31T12:00:01Z",
    ];
    let prepared = invoke(&arguments);
    assert!(
        prepared.status.success(),
        "{}",
        String::from_utf8_lossy(&prepared.stderr)
    );
    let value: Value = serde_json::from_slice(&prepared.stdout).unwrap();
    let request: WorkerStartRequestV3 =
        serde_json::from_value(value["worker_start_request"].clone()).unwrap();
    let dispatch: ProviderDispatchOccurrenceV1 =
        serde_json::from_value(value["dispatch"].clone()).unwrap();
    request
        .validate_dispatch_graph(&profile, &requirement, &dispatch)
        .unwrap();
    let store = ForemanStore::open_read_only(&path).unwrap();
    let before = store.export_events(&admission.run_id).unwrap();
    assert!(!invoke(&arguments).status.success());
    assert_eq!(before, store.export_events(&admission.run_id).unwrap());
    let brief = invoke(&[
        "brief",
        "--db",
        database,
        "--run-id",
        &admission.run_id,
        "--work-item",
        "work-a",
    ]);
    assert!(brief.status.success());
    assert_eq!(
        brief.stdout,
        store.worker_brief(&admission.run_id, "work-a").unwrap()
    );
}

#[test]
fn cli_refuses_nonregular_input_before_creating_store() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("absent.sqlite");
    let result = invoke(&[
        "provider-admit",
        "--db",
        database.to_str().unwrap(),
        "--packet",
        "/dev/null",
        "--admission",
        "/dev/null",
        "--profile",
        "/dev/null",
        "--requirement",
        "/dev/null",
        "--policy",
        "/dev/null",
        "--evaluated-at",
        "2026-08-31T12:00:00Z",
    ]);
    assert!(!result.status.success());
    assert!(!database.exists());
}

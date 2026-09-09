use super::*;
use std::process::{Command, Output};

fn invoke(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nightshift-foreman"))
        .args(args)
        .output()
        .unwrap()
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

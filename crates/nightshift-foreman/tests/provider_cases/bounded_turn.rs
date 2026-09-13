//! Publication-safe synthetic custody; these cases establish no provider contact.
use super::*;
use std::process::{Command, Output};

fn invoke(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nightshift-foreman"))
        .args(args)
        .output()
        .unwrap()
}

fn expanded_vector() -> Value {
    let vector: Value =
        serde_json::from_slice(include_bytes!("bounded-turn-synthetic.json")).unwrap();
    assert_eq!(vector["qualification"], "SYNTHETIC_NO_PROVIDER_CONTACT");
    let mut snapshot = vector["compact_snapshot"].clone();
    let record = &mut snapshot["records"][0];
    let original =
        String::from_utf8(hex::decode(record["raw"]["bytes_hex"].as_str().unwrap()).unwrap())
            .unwrap();
    let count = vector["wire_size"].as_u64().unwrap() as usize - original.len();
    let wire = original
        .replacen(
            "\"text\":\"\"",
            &format!("\"text\":\"{}\"", "S".repeat(count)),
            1,
        )
        .into_bytes();
    assert_eq!(wire.len(), 118500);
    let decoded: Value = serde_json::from_slice(&wire).unwrap();
    record["normalized"]["params_sha256"] = json!(format!(
        "sha256:{:x}",
        Sha256::digest(holding_canonical(&decoded["params"]))
    ));
    record["raw"]["byte_length"] = json!(wire.len());
    record["raw"]["sha256"] = json!(format!("sha256:{:x}", Sha256::digest(&wire)));
    record["raw"]["bytes_hex"] = json!(hex::encode(wire));
    *record = holding_seal_value(
        record.clone(),
        "evidence_digest",
        b"switchyard.codex-provider-admission-evidence.digest/v1\0",
    );
    snapshot = holding_seal_value(
        snapshot,
        "snapshot_digest",
        b"switchyard.codex-provider-admission-snapshot.digest/v1\0",
    );
    assert_eq!(
        snapshot["snapshot_digest"],
        vector["expanded_snapshot_digest"]
    );
    snapshot
}

#[test]
fn bounded_turn_cross_language_vector_is_exact() {
    let snapshot = expanded_vector();
    assert_eq!(snapshot["records"][0]["raw"]["byte_length"], 118500);
}

#[test]
fn bounded_turn_native_intake_replays_full_custody_and_keeps_output_32k() {
    let (directory, path, packet, admission, mut profile, policy, _) = holding_fixture_contracts();
    profile.schema = nightshift_foreman::FOREMAN_EXECUTION_PROFILE_SCHEMA_V3.to_owned();
    profile.maximum_worker_output_bytes = Some(32768);
    profile.maximum_event_bytes = 16 * 1024 * 1024;
    profile.adapter_timeout_seconds = 120;
    profile.seal().unwrap();
    let mut requirement = holding_requirement(&packet, &admission, &profile, &policy);
    requirement.owner_pins = ProviderAdmissionOwnerPinsV1::bounded_turn_candidate();
    for selections in requirement.work_item_model_selections.values_mut() {
        selections.truncate(1);
        selections[0].model_id = "gpt-5.6-terra".to_owned();
    }
    requirement.seal().unwrap();
    let p = |name: &str| directory.path().join(name);
    for (name, bytes) in [
        ("packet.json", packet.canonical_bytes().unwrap()),
        ("admission.json", holding_canonical(&admission)),
        ("profile.json", holding_canonical(&profile)),
        ("requirement.json", holding_canonical(&requirement)),
        ("policy.json", holding_canonical(&policy)),
    ] {
        fs::write(p(name), bytes).unwrap();
    }
    let admitted = invoke(&[
        "provider-admit",
        "--db",
        path.to_str().unwrap(),
        "--packet",
        p("packet.json").to_str().unwrap(),
        "--admission",
        p("admission.json").to_str().unwrap(),
        "--profile",
        p("profile.json").to_str().unwrap(),
        "--requirement",
        p("requirement.json").to_str().unwrap(),
        "--policy",
        p("policy.json").to_str().unwrap(),
        "--evaluated-at",
        "2026-08-31T12:00:00Z",
    ]);
    assert!(
        admitted.status.success(),
        "{}",
        String::from_utf8_lossy(&admitted.stderr)
    );
    let prepared = invoke(&[
        "provider-prepare",
        "--db",
        path.to_str().unwrap(),
        "--run-id",
        &admission.run_id,
        "--work-item",
        "work-a",
        "--dispatch",
        "synthetic-size-dispatch",
        "--adapter-process",
        "synthetic-size-process",
        "--app-server-session",
        "synthetic-size-estate",
        "--selected-model-ordinal",
        "0",
        "--recorded-at",
        "2026-08-31T12:01:00Z",
    ]);
    assert!(
        prepared.status.success(),
        "{}",
        String::from_utf8_lossy(&prepared.stderr)
    );
    let prepared: Value = serde_json::from_slice(&prepared.stdout).unwrap();
    let opened = nightshift_foreman::OpenedProviderDispatchV1 {
        worker_start_request: serde_json::from_value(prepared["worker_start_request"].clone())
            .unwrap(),
        dispatch: serde_json::from_value(prepared["dispatch"].clone()).unwrap(),
    };
    assert_eq!(opened.worker_start_request.maximum_output_bytes, 32768);
    assert_eq!(opened.worker_start_request.timeout_seconds, 120);
    assert_eq!(opened.worker_start_request.internal_provider_retry_count, 0);
    fs::write(p("dispatch.json"), holding_canonical(&opened.dispatch)).unwrap();
    let raw = holding_retarget_snapshot(expanded_vector(), &opened);
    fs::write(p("snapshot.json"), &raw).unwrap();
    let derived = invoke(&[
        "provider-derive-evidence",
        "--requirement",
        p("requirement.json").to_str().unwrap(),
        "--dispatch",
        p("dispatch.json").to_str().unwrap(),
        "--policy",
        p("policy.json").to_str().unwrap(),
        "--snapshot",
        p("snapshot.json").to_str().unwrap(),
        "--received-at",
        "2026-08-31T12:01:02Z",
        "--expires-at",
        "2026-08-31T12:01:32Z",
    ]);
    assert!(
        derived.status.success(),
        "{}",
        String::from_utf8_lossy(&derived.stderr)
    );
    let derived: Value = serde_json::from_slice(&derived.stdout).unwrap();
    assert_eq!(derived["graph_validation"], "VALIDATED", "{derived}");
    assert_eq!(
        derived["disposition"]["mechanism_state"],
        "PROVIDER_COMPLETED"
    );
    for name in ["observation", "disposition"] {
        fs::write(
            p(&format!("{name}.json")),
            holding_canonical(&derived[name]),
        )
        .unwrap();
    }
    let observation_path = p("observation.json");
    let disposition_path = p("disposition.json");
    let record_args = [
        "provider-record",
        "--db",
        path.to_str().unwrap(),
        "--run-id",
        &admission.run_id,
        "--work-item",
        "work-a",
        "--attempt-id",
        &opened.worker_start_request.work_attempt_id,
        "--observation",
        observation_path.to_str().unwrap(),
        "--disposition",
        disposition_path.to_str().unwrap(),
    ];
    let recorded = invoke(&record_args);
    assert!(
        recorded.status.success(),
        "{}",
        String::from_utf8_lossy(&recorded.stderr)
    );
    let readback = invoke(&[
        "events",
        "--db",
        path.to_str().unwrap(),
        "--run-id",
        &admission.run_id,
    ]);
    assert!(readback.status.success());
    let events: Value = serde_json::from_slice(&readback.stdout).unwrap();
    let retained: Vec<_> = events
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["payload"]["kind"] == "provider_disposition_recorded")
        .collect();
    assert_eq!(retained.len(), 1);
    assert_eq!(
        retained[0]["payload"]["disposition"],
        derived["disposition"]
    );
    let event_bytes = holding_canonical(retained[0]).len();
    assert!(event_bytes > 32768 && event_bytes < 16 * 1024 * 1024);
    assert!(readback.stdout.len() < 16 * 1024 * 1024);
    println!("SYNTHETIC_NO_PROVIDER_CONTACT wire=118500 snapshot={} disposition={} journal_event={} aggregate_query={} output_bound=32768",
        raw.len(), holding_canonical(&derived["disposition"]).len(), event_bytes, readback.stdout.len());
    // Ordinary provider-record preserves its prior refusal-on-duplicate contract.
    // Response-loss recovery reads the original record, never creates a new dispatch.
    assert!(!invoke(&record_args).status.success());
    assert_eq!(
        invoke(&[
            "events",
            "--db",
            path.to_str().unwrap(),
            "--run-id",
            &admission.run_id
        ])
        .stdout,
        readback.stdout
    );
    let store = ForemanStore::open_read_only(&path).unwrap();
    store.read_only_run_snapshot(&admission.run_id).unwrap();
    let mut old = requirement.clone();
    old.owner_pins = ProviderAdmissionOwnerPinsV1::packaged_runtime_candidate();
    old.seal().unwrap();
    let mut old_dispatch = opened.dispatch.clone();
    old_dispatch.requirement_digest = old.requirement_digest.clone();
    old_dispatch.seal().unwrap();
    let (old_disposition, old_observation) = nightshift_foreman::derive_provider_snapshot_evidence(
        &old,
        &old_dispatch,
        &raw,
        holding_time("2026-08-31T12:01:02Z"),
        holding_time("2026-08-31T12:01:32Z"),
    )
    .unwrap();
    let error = nightshift_foreman::validate_execution_availability_graph(
        &old,
        &policy,
        &old_dispatch,
        &old_observation,
        &old_disposition,
        &[],
        None,
    )
    .unwrap_err();
    assert!(error.to_string().contains("Switchyard schema"), "{error}");
}

#[test]
fn bounded_turn_profile_v2_null_refuses_native_sealing() {
    let (directory, _path, packet, admission, profile, policy, requirement) =
        holding_fixture_contracts();
    let mut value = serde_json::to_value(&profile).unwrap();
    value["maximum_worker_output_bytes"] = Value::Null;
    let draft = directory.path().join("null-profile.json");
    fs::write(&draft, holding_canonical(&value)).unwrap();
    assert!(
        !invoke(&["seal-profile", "--draft", draft.to_str().unwrap()])
            .status
            .success()
    );
    let bundle = json!({"packet": packet, "admission": admission, "profile": value,
        "policy": policy, "requirement": requirement});
    fs::write(&draft, holding_canonical(&bundle)).unwrap();
    assert!(
        !invoke(&["provider-seal-inputs", "--draft", draft.to_str().unwrap()])
            .status
            .success()
    );
    if let Ok(legacy) = std::env::var("BOUNDED_TURN_LEGACY_FOREMAN") {
        let mut current = profile.clone();
        current.schema = nightshift_foreman::FOREMAN_EXECUTION_PROFILE_SCHEMA_V3.to_owned();
        current.maximum_worker_output_bytes = Some(32768);
        current.seal().unwrap();
        fs::write(&draft, holding_canonical(&current)).unwrap();
        assert!(!Command::new(legacy)
            .args(["seal-profile", "--draft", draft.to_str().unwrap()])
            .output()
            .unwrap()
            .status
            .success());
    }
}

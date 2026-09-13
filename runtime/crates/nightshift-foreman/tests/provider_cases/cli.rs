use super::*;
use std::process::{Command, Output};

fn invoke(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nightshift-foreman"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn receipt_readback_is_exact_read_only_and_distinguishes_absent_from_unknown() {
    let (directory, store, packet, _, _) = setup();
    let database = directory.path().join("foreman.sqlite");
    let query = |item: &str| {
        invoke(&[
            "terminal-receipt",
            "--db",
            database.to_str().unwrap(),
            "--run-id",
            "run-fixture",
            "--work-item",
            item,
        ])
    };
    let before = fs::read(&database).unwrap();
    let absent = query("root-a");
    assert!(absent.status.success());
    let absent: Value = serde_json::from_slice(&absent.stdout).unwrap();
    assert_eq!(absent["state"], "ABSENT");
    assert!(absent["receipt_bytes_hex"].is_null());
    assert!(!query("not-enrolled").status.success());
    assert_eq!(fs::read(&database).unwrap(), before);
    let request = store
        .prepare_attempt("run-fixture", "root-a", instant(1))
        .unwrap();
    let receipt = holding_canonical(&terminal(&packet, &request, "FIXTURE", "UNASSESSED"));
    store.accept_terminal_receipt(&receipt).unwrap();
    let before = fs::read(&database).unwrap();
    let events = store.export_events("run-fixture").unwrap();
    let present = query("root-a");
    assert!(
        present.status.success(),
        "{}",
        String::from_utf8_lossy(&present.stderr)
    );
    let present: Value = serde_json::from_slice(&present.stdout).unwrap();
    assert_eq!(present["state"], "PRESENT");
    assert_eq!(
        hex::decode(present["receipt_bytes_hex"].as_str().unwrap()).unwrap(),
        receipt
    );
    assert_eq!(fs::read(&database).unwrap(), before);
    assert_eq!(store.export_events("run-fixture").unwrap(), events);
    let missing = directory.path().join("missing.sqlite");
    assert!(!invoke(&[
        "terminal-receipt",
        "--db",
        missing.to_str().unwrap(),
        "--run-id",
        "run-fixture",
        "--work-item",
        "root-a"
    ])
    .status
    .success());
    assert!(!missing.exists());
}

#[test]
fn terminal_sealing_is_canonical_but_neither_assessment_nor_owner_intake() {
    let (directory, store, packet, _, _) = setup();
    let request = store
        .prepare_attempt("run-fixture", "root-a", instant(1))
        .unwrap();
    let expected = terminal(
        &packet,
        &request,
        "UNASSESSED-CLAIM",
        "NO-AUTOMATIC-QUALIFICATION",
    );
    let mut draft = expected.clone();
    draft.receipt_digest = holding_placeholder();
    let path = directory.path().join("draft.json");
    fs::write(&path, holding_canonical(&draft)).unwrap();
    let before = store.export_events("run-fixture").unwrap();
    let output = invoke(&["seal-terminal-receipt", "--draft", path.to_str().unwrap()]);
    assert!(output.status.success());
    assert_eq!(output.stdout, holding_canonical(&expected));
    assert_eq!(store.export_events("run-fixture").unwrap(), before);
    assert!(store.close("run-fixture", instant(6)).is_err());
    let mut foreign: Value = serde_json::from_slice(&holding_canonical(&draft)).unwrap();
    foreign["grants_authority"] = json!(true);
    fs::write(&path, holding_canonical(&foreign)).unwrap();
    assert!(
        !invoke(&["seal-terminal-receipt", "--draft", path.to_str().unwrap()])
            .status
            .success()
    );
    assert!(!invoke(&["seal-terminal-receipt", "--draft", "/dev/null"])
        .status
        .success());
    assert_eq!(store.export_events("run-fixture").unwrap(), before);
}

#[test]
fn beta_mapper_fixtures_replay_under_exact_new_owner_schema_pair() {
    mapper_fixture_family(false);
}

#[test]
fn final_mapper_fixtures_replay_under_exact_final_owner_schema_pair() {
    mapper_fixture_family(true);
}

fn mapper_fixture_family(final_pair: bool) {
    for name in [
        "completed",
        "parked",
        "indeterminate",
        "interrupted",
        "approval",
    ] {
        let (_directory, path, mut packet, mut admission, mut profile, policy, _) =
            holding_fixture_contracts();
        let fixture_time = chrono::DateTime::from_timestamp_millis(1788900000000).unwrap();
        let shift = fixture_time - admission.admitted_at;
        packet.created_at += shift;
        packet.current_until += shift;
        packet.seal().unwrap();
        admission.packet_digest = packet.packet_digest.clone();
        admission.admitted_at += shift;
        admission.expires_at += shift;
        admission.seal().unwrap();
        profile.packet_digest = packet.packet_digest.clone();
        profile.admission_digest = admission.admission_digest.clone();
        profile.seal().unwrap();
        let mut requirement = holding_requirement(&packet, &admission, &profile, &policy);
        requirement.owner_pins = if final_pair {
            nightshift_foreman::ProviderAdmissionOwnerPinsV1::final_beta_candidate()
        } else {
            nightshift_foreman::ProviderAdmissionOwnerPinsV1::beta_candidate()
        };
        for selections in requirement.work_item_model_selections.values_mut() {
            selections.truncate(1);
            selections[0].model_id = "gpt-5.6-terra".to_owned();
        }
        requirement.seal().unwrap();
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
        let opened = store
            .prepare_provider_attempt(
                &admission.run_id,
                "work-a",
                "beta-dispatch",
                "beta-process",
                "beta-session",
                0,
                fixture_time,
            )
            .unwrap();
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(if final_pair {
                "../../qualification/operator-beta-provider-20260908/final-fixtures"
            } else {
                "../../qualification/operator-beta-provider-20260908/fixtures"
            })
            .join(format!("{name}.json"));
        let snapshot: Value = serde_json::from_slice(&fs::read(fixture).unwrap()).unwrap();
        let raw = holding_retarget_snapshot(snapshot, &opened);
        let received = fixture_time + Duration::seconds(2);
        let derived = nightshift_foreman::derive_provider_snapshot_evidence(
            &requirement,
            &opened.dispatch,
            &raw,
            received,
            received + Duration::seconds(60),
        );
        let (disposition, observation) = derived.unwrap_or_else(|error| panic!("{name}: {error}"));
        if name == "approval" {
            // Existing owner semantics retain a nonterminal wait, not completed
            // work or permission to send an approval response.
            assert_eq!(
                disposition.mechanism_state,
                ProviderMechanismStateV1::WaitingApproval
            );
            assert!(!disposition.acquisition_complete);
            assert!(!disposition.approval_response_sent);
            assert!(!disposition.permits_automatic_park());
        }
        if name == "indeterminate" || name == "interrupted" {
            let source: Value = serde_json::from_slice(&raw).unwrap();
            let provider_raw = source["records"]
                .as_array()
                .unwrap()
                .iter()
                .find(|record| !record["raw"].is_null())
                .unwrap()["raw"]
                .clone();
            for (field, value) in [
                ("kind", json!("LOCAL_TURN_FACT")),
                ("method", json!("item/rawResponse/started")),
                ("raw", provider_raw),
                ("acquisition_ordinal", json!(0)),
                ("acquisition_kind", json!("NOTIFICATION")),
            ] {
                let mut changed: Value = serde_json::from_slice(&raw).unwrap();
                let local = changed["records"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|record| record["method"] == "adapter/acquisition")
                    .unwrap();
                local[field] = value;
                let changed = holding_retarget_snapshot(changed, &opened);
                assert!(nightshift_foreman::derive_provider_snapshot_evidence(
                    &requirement,
                    &opened.dispatch,
                    &changed,
                    received,
                    received + Duration::seconds(60)
                )
                .is_err());
            }
        }
        if name == "parked" {
            let directory = tempfile::tempdir().unwrap();
            let mut unrelated_policy = policy.clone();
            unrelated_policy.policy_id = "not-the-admitted-policy".to_owned();
            unrelated_policy.seal().unwrap();
            for (file, bytes) in [
                ("requirement", holding_canonical(&requirement)),
                ("policy", holding_canonical(&unrelated_policy)),
                ("dispatch", holding_canonical(&opened.dispatch)),
                ("snapshot", raw.clone()),
            ] {
                fs::write(directory.path().join(file), bytes).unwrap();
            }
            let file = |name: &str| directory.path().join(name).to_str().unwrap().to_owned();
            let output = invoke(&[
                "provider-derive-evidence",
                "--requirement",
                &file("requirement"),
                "--policy",
                &file("policy"),
                "--dispatch",
                &file("dispatch"),
                "--snapshot",
                &file("snapshot"),
                "--received-at",
                &received.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                "--expires-at",
                &(received + Duration::seconds(60))
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            ]);
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let output: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(output["graph_validation"], "REFUSED");
            assert_eq!(
                output["disposition"]["disposition"],
                "NOT_ADMITTED_MODEL_AT_CAPACITY"
            );
            assert!(output["deferred"].is_null());
        }
        nightshift_foreman::derive_provider_deferral(
            &requirement,
            &policy,
            &opened.dispatch,
            &observation,
            &disposition,
            &[],
        )
        .unwrap();
        let mut old = requirement.clone();
        old.owner_pins = nightshift_foreman::ProviderAdmissionOwnerPinsV1::accepted();
        old.seal().unwrap();
        assert!(nightshift_foreman::derive_provider_snapshot_evidence(
            &old,
            &opened.dispatch,
            &raw,
            received,
            received + Duration::seconds(60)
        )
        .is_err());
        let mut mixed = requirement.owner_pins.clone();
        mixed.switchyard_schema_sha256 = old.owner_pins.switchyard_schema_sha256;
        assert!(mixed.validate().is_err());
    }
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
        assert_eq!(
            nightshift_foreman::derive_provider_deferral(
                &requirement,
                &policy,
                &opened.dispatch,
                &observation,
                &disposition,
                &[],
            )
            .unwrap(),
            deferred
        );
        let mut wrong_policy = policy.clone();
        wrong_policy.backoff_seconds[0] += 1;
        wrong_policy.seal().unwrap();
        assert!(nightshift_foreman::derive_provider_deferral(
            &requirement,
            &wrong_policy,
            &opened.dispatch,
            &observation,
            &disposition,
            &[],
        )
        .is_err());
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

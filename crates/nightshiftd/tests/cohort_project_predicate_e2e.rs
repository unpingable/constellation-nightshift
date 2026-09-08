//! Opt-in cohort route: real producer fixtures through Monitor, NQ, Pulse, and Nightshift.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ed25519_dalek::{Signer as _, SigningKey};
use nightshiftd::project_predicate_attention::{
    evaluate, executable_digest, verify_pulse_receipt, AttentionDispositionV1, AttentionPolicyV1,
    AttentionStoreV1, AttentionTargetV1, AttentionTriggerV1, IngestDispositionV1,
    PulseReplayInputsV1, RecurrencePolicyV1, ResetPolicyV1, POLICY_SCHEMA_V1,
};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

struct Case {
    project: &'static str,
    concern: &'static str,
    now: &'static str,
    module: &'static str,
    demo: Option<&'static str>,
    db_name: &'static str,
    producer: &'static str,
}

#[test]
#[ignore = "requires ATPROTO_COHORT_ROOT and qualified Monitor, NQ, and Pulse binaries"]
fn three_observatories_traverse_existing_project_predicate_path() {
    let cohort = PathBuf::from(required("ATPROTO_COHORT_ROOT"));
    let monitor = PathBuf::from(required("MONITOR_CONCERNS_BIN"));
    let nq = PathBuf::from(required("NQ_MONITOR_BIN"));
    let pulse = PathBuf::from(required("PULSE_PROJECT_PREDICATE_SUPPORT_BIN"));
    let catalog_path = PathBuf::from(required("NQ_PROJECT_PREDICATE_CATALOG"));
    let catalog: Value = serde_json::from_slice(&fs::read(&catalog_path).unwrap()).unwrap();
    let catalog_digest = digest(&catalog);

    let cases = [
        Case {
            project: "weatherwatch",
            concern: "weatherwatch.persistence.access",
            now: "2023-11-14T22:29:00Z",
            module: "weatherwatch.visibility",
            demo: Some("scripts/demo_offline.py"),
            db_name: "weatherwatch.sqlite",
            producer: "weatherwatch.status",
        },
        Case {
            project: "labelwatch",
            concern: "labelwatch.persistence.sqlite_continuity",
            now: "2024-01-02T00:00:00Z",
            module: "labelwatch.ops_status",
            demo: Some("scripts/demo_offline.py"),
            db_name: "labelwatch.sqlite",
            producer: "labelwatch.ops-status",
        },
        Case {
            project: "driftwatch",
            concern: "driftwatch.persistence.sqlite_continuity",
            now: "2026-09-07T12:00:00Z",
            module: "labeler.ops_status",
            demo: None,
            db_name: "labeler.sqlite",
            producer: "driftwatch.ops-status",
        },
    ];

    for (index, case) in cases.iter().enumerate() {
        run_case(index as u8 + 31, case, &cohort, &monitor, &nq, &pulse, &catalog_path, &catalog, &catalog_digest);
    }
}

#[allow(clippy::too_many_arguments)]
fn run_case(
    key_byte: u8,
    case: &Case,
    cohort: &Path,
    monitor: &Path,
    nq: &Path,
    pulse: &Path,
    catalog_path: &Path,
    catalog: &Value,
    catalog_digest: &str,
) {
    let source = cohort.join(case.project);
    let root = TempDir::new().unwrap();
    let fixture = root.path().join(case.project);
    let state = root.path().join("state");
    fs::create_dir_all(fixture.join(".ops")).unwrap();
    fs::create_dir_all(&state).unwrap();
    fs::copy(source.join(".ops/concerns.toml"), fixture.join(".ops/concerns.toml")).unwrap();

    if let Some(demo) = case.demo {
        let output = Command::new("python3")
            .arg(source.join(demo))
            .arg("--output")
            .arg(&state)
            .current_dir(&source)
            .env("PYTHONPATH", source.join("src"))
            .output()
            .unwrap();
        assert_success(&format!("{} demo", case.project), &output);
    } else {
        let output = Command::new("python3")
            .args(["-c", "import sqlite3,sys; sqlite3.connect(sys.argv[1]).close()"])
            .arg(state.join(case.db_name))
            .output()
            .unwrap();
        assert_success("Driftwatch fixture database", &output);
    }

    let mut status_command = Command::new("python3");
    status_command
        .args(["-m", case.module, "--db"])
        .arg(state.join(case.db_name))
        .args(["--now", case.now, "--format", "json"])
        .current_dir(&source)
        .env("PYTHONPATH", source.join("src"));
    if case.project == "weatherwatch" {
        status_command.arg("--report-dir").arg(state.join("report"));
    } else if case.project == "driftwatch" {
        status_command.arg("--data-dir").arg(&state);
    }
    let status = status_command.output().unwrap();
    assert_success(&format!("{} status", case.project), &status);
    fs::write(fixture.join("status.json"), &status.stdout).unwrap();
    fs::write(
        fixture.join("emit.py"),
        "from pathlib import Path\nprint(Path(__file__).with_name('status.json').read_text(), end='')\n",
    )
    .unwrap();
    fs::write(
        fixture.join(".ops/observation.toml"),
        format!(
            "schema = \"project.observation-binding/v1\"\nproducer = \"{}\"\noutput_schema = \"project.ops.status/v1\"\nkind = \"exec/v1\"\nargv = [\"python3\", \"emit.py\"]\n",
            case.producer
        ),
    )
    .unwrap();

    let inventory_path = root.path().join("inventory.json");
    let collected = Command::new(monitor)
        .arg("collect")
        .arg(&fixture)
        .arg("--trusted-root")
        .arg(root.path())
        .args(["--allow-exec", "--json"])
        .output()
        .unwrap();
    assert_success(&format!("{} Monitor collect", case.project), &collected);
    fs::write(&inventory_path, &collected.stdout).unwrap();
    let inventory: Value = serde_json::from_slice(&collected.stdout).unwrap();
    let item = inventory["concerns"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["declaration"]["id"] == case.concern)
        .unwrap();
    assert_eq!(item["monitor_state"], "OBSERVED");
    assert_eq!(item["observation"]["local_state"], "PRESENT");
    let observed_at = item["observation"]["observed_at"].as_str().unwrap();
    let facts = item["observation"]["facts"].clone();
    let manifest_digest = inventory["acquisition"]["manifest_digest"].as_str().unwrap();
    let declaration_question = item["declaration"]["question"].as_str().unwrap();

    let profile = catalog["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|profile| {
            profile["subject"]["project"] == case.project
                && profile["subject"]["concern"] == case.concern
                && profile["question"] == declaration_question
        })
        .unwrap();
    assert!(profile["accepted_manifest_digests"].as_array().unwrap().iter().any(|v| v == manifest_digest));
    let profile_digest = digest(profile);
    let input_schema_digest = digest(&profile["input_schema"]);
    let nq_receipt = root.path().join("nq.json");
    let admitted = Command::new(nq)
        .args(["project-predicate", "admit", "--inventory"])
        .arg(&inventory_path)
        .arg("--profiles")
        .arg(catalog_path)
        .args(["--catalog-digest", catalog_digest, "--concern", case.concern, "--evaluated-at", observed_at, "--output"])
        .arg(&nq_receipt)
        .output()
        .unwrap();
    assert_success(&format!("{} NQ admission", case.project), &admitted);
    let nq_value: Value = serde_json::from_slice(&fs::read(&nq_receipt).unwrap()).unwrap();
    assert_eq!(nq_value["disposition"], "ADMITTED_WITH_SCOPE");

    let signing_key = SigningKey::from_bytes(&[key_byte; 32]);
    let policy_id = format!("pulse.policy.{}-cohort/v1", case.project);
    let subject_id = format!("deployment:{}-fixture", case.project);
    let producer_id = format!("pulse-producer:{}-fixture", case.project);
    let key_id = format!("pulse-key:{}-fixture", case.project);
    let source_id = format!("source:{}-fixture", case.project);
    let vantage_id = format!("vantage:{}-fixture", case.project);
    let mut pulse_policy = json!({
        "schema": "pulse.project-predicate-support-policy/v1",
        "policy_id": policy_id,
        "policy_digest": "",
        "target": {
            "project": case.project,
            "concern": case.concern,
            "question": profile["question"],
            "declaration_profile": profile["declaration_profile"],
            "predicate_profile": profile["id"],
            "catalog_digest": catalog_digest,
            "profile_digest": profile_digest,
            "input_schema_digest": input_schema_digest,
            "primary_producer": case.producer,
            "subject_id": subject_id
        },
        "support_source": {
            "producer_id": producer_id,
            "producer_key_id": key_id,
            "producer_public_key_hex": hex(signing_key.verifying_key().as_bytes()),
            "source_id": source_id,
            "vantage_id": vantage_id,
            "dependency_ids": [format!("fixture:{}", case.project)]
        },
        "currentness": {
            "maximum_primary_age_seconds": 600,
            "maximum_support_age_seconds": 600,
            "maximum_primary_support_skew_seconds": 300
        },
        "nq_verifier_executable_digest": executable_digest(nq).unwrap()
    });
    let pulse_policy_digest = digest_without(&pulse_policy, "policy_digest");
    pulse_policy["policy_digest"] = Value::String(pulse_policy_digest.clone());
    let pulse_policy_path = root.path().join("pulse-policy.json");
    fs::write(&pulse_policy_path, canonical(&pulse_policy)).unwrap();

    let mut evidence = json!({
        "schema": "pulse.project-predicate-support-evidence/v1",
        "evidence_id": "",
        "acquisition_id": format!("{}-support:1", case.project),
        "producer_id": producer_id,
        "producer_key_id": key_id,
        "source_id": source_id,
        "dependency_ids": [format!("fixture:{}", case.project)],
        "subject_id": subject_id,
        "vantage_id": vantage_id,
        "observed_at": observed_at,
        "valid_for_seconds": 600,
        "facts": facts,
        "local_state": "PRESENT"
    });
    evidence["evidence_id"] = Value::String(digest_without(&evidence, "evidence_id"));
    let mut message = b"pulse/project-predicate-support/evidence/v1\0".to_vec();
    message.extend(canonical(&evidence));
    let envelope = json!({
        "schema": "pulse.project-predicate-support-envelope/v1",
        "evidence": evidence,
        "signature_hex": hex(&signing_key.sign(&message).to_bytes())
    });
    let evidence_path = root.path().join("support.json");
    fs::write(&evidence_path, canonical(&envelope)).unwrap();

    let pulse_receipt = root.path().join("pulse.json");
    let qualified = Command::new(pulse)
        .arg("qualify")
        .arg("--policy").arg(&pulse_policy_path)
        .arg("--nq-executable").arg(nq)
        .arg("--nq-receipt").arg(&nq_receipt)
        .arg("--inventory").arg(&inventory_path)
        .arg("--catalog").arg(catalog_path)
        .arg("--support-evidence").arg(&evidence_path)
        .args(["--at", observed_at, "--output"]).arg(&pulse_receipt)
        .output().unwrap();
    assert_success(&format!("{} Pulse qualification", case.project), &qualified);

    let mut attention_policy = AttentionPolicyV1 {
        schema: POLICY_SCHEMA_V1.into(),
        policy_id: format!("nightshift.policy.{}-cohort/v1", case.project),
        policy_digest: String::new(),
        target: AttentionTargetV1 {
            project: case.project.into(),
            concern: case.concern.into(),
            question: profile["question"].as_str().unwrap().into(),
            declaration_profile: profile["declaration_profile"].as_str().unwrap().into(),
            predicate_profile: profile["id"].as_str().unwrap().into(),
            nq_catalog_digest: catalog_digest.into(),
            nq_profile_digest: profile_digest,
            nq_input_schema_digest: input_schema_digest,
            pulse_support_policy_id: pulse_policy["policy_id"].as_str().unwrap().into(),
            pulse_support_policy_digest: pulse_policy_digest,
            subject_id,
        },
        pulse_verifier_executable_digest: executable_digest(pulse).unwrap(),
        trigger: AttentionTriggerV1::PropositionAttention,
        recurrence: RecurrencePolicyV1 { required_distinct_occurrences: 1, within_seconds: 600 },
        reset: ResetPolicyV1::HorizonExpiry,
    };
    attention_policy.seal().unwrap();
    let verified = verify_pulse_receipt(
        &attention_policy,
        &pulse_receipt,
        &PulseReplayInputsV1 {
            pulse_executable: pulse.into(),
            pulse_policy: pulse_policy_path,
            nq_executable: nq.into(),
            nq_receipt,
            inventory: inventory_path,
            catalog: catalog_path.into(),
            support_evidence: Some(evidence_path),
        },
    ).unwrap();
    let mut store = AttentionStoreV1::open(&root.path().join("nightshift.sqlite")).unwrap();
    assert_eq!(store.ingest_verified(&attention_policy, verified).unwrap().disposition, IngestDispositionV1::Accepted);
    let result = evaluate(
        &attention_policy,
        &store.history(&attention_policy).unwrap(),
        chrono::DateTime::parse_from_rfc3339(observed_at).unwrap().to_utc(),
    ).unwrap();
    assert_eq!(result.receipt.disposition, AttentionDispositionV1::AttentionRequired);
}

fn required(name: &str) -> std::ffi::OsString {
    std::env::var_os(name).unwrap_or_else(|| panic!("{name} is required"))
}
fn assert_success(label: &str, output: &Output) {
    assert!(output.status.success(), "{label}: {}", String::from_utf8_lossy(&output.stderr));
}
fn canonical(value: &impl Serialize) -> Vec<u8> { serde_jcs::to_vec(value).unwrap() }
fn digest(value: &impl Serialize) -> String { format!("sha256:{:x}", Sha256::digest(canonical(value))) }
fn digest_without(value: &Value, field: &str) -> String {
    let mut value=value.clone(); value.as_object_mut().unwrap().remove(field); digest(&value)
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }

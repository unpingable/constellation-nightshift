//! Opt-in four-layer portability control.
//!
//! This test runs the qualified Monitor, NQ, and Pulse executables against a
//! project identity absent from all production code, then feeds three exact
//! independently supported evidence occurrences to Nightshift. It is ignored
//! by default because the upstream binaries live in adjacent repositories.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

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

#[test]
#[ignore = "requires MONITOR_CONCERNS_BIN, NQ_NG_BIN, and PULSE_PROJECT_PREDICATE_SUPPORT_BIN"]
fn unfamiliar_project_reaches_distinct_evidence_attention_without_project_code() {
    let monitor = required_bin("MONITOR_CONCERNS_BIN");
    let nq = required_bin("NQ_NG_BIN");
    let pulse = required_bin("PULSE_PROJECT_PREDICATE_SUPPORT_BIN");
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../qualification/project-predicate-attention/unfamiliar-project");
    let root = TempDir::new().unwrap();
    let inventory_path = root.path().join("inventory.json");
    let monitor_output = Command::new(&monitor)
        .arg("collect")
        .arg(&fixture)
        .arg("--trusted-root")
        .arg(fixture.parent().unwrap())
        .args(["--allow-exec", "--json"])
        .output()
        .unwrap();
    assert_success("Monitor collect", &monitor_output);
    fs::write(&inventory_path, &monitor_output.stdout).unwrap();
    let inventory: Value = serde_json::from_slice(&monitor_output.stdout).unwrap();
    assert_eq!(inventory["project"], "cogwheel-fixture");
    assert_eq!(inventory["concerns"][0]["monitor_state"], "OBSERVED");
    let manifest_digest = inventory["acquisition"]["manifest_digest"]
        .as_str()
        .unwrap();

    let input_schema = json!([{"path":"queue.depth","type":"u64"}]);
    let mut profile = json!({
        "schema": "nq.project-predicate-profile/v1",
        "id": "nq.profile.cogwheel-queue-high-18/v1",
        "question": "cogwheel.question.queue-high/v1",
        "declaration_profile": "cogwheel.profile.queue-high-18/v1",
        "subject": {"project":"cogwheel-fixture","concern":"cogwheel.queue.high"},
        "accepted_producers": ["cogwheel-fixture.status"],
        "accepted_manifest_digests": [manifest_digest],
        "input_schema": input_schema,
        "predicate": {"operator":"compare","fact":"queue.depth","comparator":"ge","value":{"type":"u64","value":18}},
        "max_observation_age_seconds": 600
    });
    let profile_digest = digest(&profile);
    let input_schema_digest = digest(&profile["input_schema"]);
    let catalog = json!({
        "schema": "nq.project-predicate-profile-catalog/v1",
        "profiles": [profile.take()]
    });
    let catalog_digest = digest(&catalog);
    let catalog_path = root.path().join("catalog.json");
    fs::write(&catalog_path, canonical(&catalog)).unwrap();
    let nq_receipt = root.path().join("nq-receipt.json");
    let nq_output = Command::new(&nq)
        .args(["bounded-predicate", "admit", "--inventory"])
        .arg(&inventory_path)
        .arg("--profiles")
        .arg(&catalog_path)
        .args([
            "--catalog-digest",
            &catalog_digest,
            "--concern",
            "cogwheel.queue.high",
            "--evaluated-at",
            "2026-08-25T12:00:30Z",
            "--output",
        ])
        .arg(&nq_receipt)
        .output()
        .unwrap();
    assert_success("NQ admission", &nq_output);

    let signing_key = SigningKey::from_bytes(&[77; 32]);
    let pulse_digest = executable_digest(&pulse).unwrap();
    let mut pulse_policy = json!({
        "schema": "pulse.project-predicate-support-policy/v1",
        "policy_id": "pulse.policy.cogwheel-independent/v1",
        "policy_digest": "",
        "target": {
            "project": "cogwheel-fixture",
            "concern": "cogwheel.queue.high",
            "question": "cogwheel.question.queue-high/v1",
            "declaration_profile": "cogwheel.profile.queue-high-18/v1",
            "predicate_profile": "nq.profile.cogwheel-queue-high-18/v1",
            "catalog_digest": catalog_digest,
            "profile_digest": profile_digest,
            "input_schema_digest": input_schema_digest,
            "primary_producer": "cogwheel-fixture.status",
            "subject_id": "deployment:cogwheel-e2e"
        },
        "support_source": {
            "producer_id": "pulse-producer:cogwheel-direct",
            "producer_key_id": "pulse-key:cogwheel-direct",
            "producer_public_key_hex": hex(signing_key.verifying_key().as_bytes()),
            "source_id": "source:cogwheel-direct-queue-api",
            "vantage_id": "vantage:cogwheel-sidecar",
            "dependency_ids": ["direct:cogwheel-queue-api"]
        },
        "currentness": {
            "maximum_primary_age_seconds": 600,
            "maximum_support_age_seconds": 600,
            "maximum_primary_support_skew_seconds": 300
        },
        "nq_verifier_executable_digest": executable_digest(&nq).unwrap()
    });
    let pulse_policy_digest = digest_without(&pulse_policy, "policy_digest");
    pulse_policy["policy_digest"] = Value::String(pulse_policy_digest.clone());
    let pulse_policy_path = root.path().join("pulse-policy.json");
    fs::write(&pulse_policy_path, canonical(&pulse_policy)).unwrap();

    let mut attention_policy = AttentionPolicyV1 {
        schema: POLICY_SCHEMA_V1.into(),
        policy_id: "nightshift.policy.cogwheel-high/v1".into(),
        policy_digest: String::new(),
        target: AttentionTargetV1 {
            project: "cogwheel-fixture".into(),
            concern: "cogwheel.queue.high".into(),
            question: "cogwheel.question.queue-high/v1".into(),
            declaration_profile: "cogwheel.profile.queue-high-18/v1".into(),
            predicate_profile: "nq.profile.cogwheel-queue-high-18/v1".into(),
            nq_catalog_digest: catalog_digest,
            nq_profile_digest: profile_digest,
            nq_input_schema_digest: input_schema_digest,
            pulse_support_policy_id: "pulse.policy.cogwheel-independent/v1".into(),
            pulse_support_policy_digest: pulse_policy_digest,
            subject_id: "deployment:cogwheel-e2e".into(),
        },
        pulse_verifier_executable_digest: pulse_digest,
        trigger: AttentionTriggerV1::PropositionAttention,
        recurrence: RecurrencePolicyV1 {
            required_distinct_occurrences: 3,
            within_seconds: 300,
        },
        reset: ResetPolicyV1::HorizonExpiry,
    };
    attention_policy.seal().unwrap();
    let database = root.path().join("nightshift.sqlite");
    let mut store = AttentionStoreV1::open(&database).unwrap();
    let mut first_receipt = None;
    for (index, observed_at, qualified_at) in [
        (1, "2026-08-25T12:00:40Z", "2026-08-25T12:00:50Z"),
        (2, "2026-08-25T12:01:40Z", "2026-08-25T12:01:50Z"),
        (3, "2026-08-25T12:02:40Z", "2026-08-25T12:02:50Z"),
    ] {
        let evidence_path = root.path().join(format!("support-{index}.json"));
        write_signed_evidence(&evidence_path, &signing_key, index, observed_at, 21);
        let pulse_receipt = root.path().join(format!("pulse-{index}.json"));
        let output = Command::new(&pulse)
            .arg("qualify")
            .arg("--policy")
            .arg(&pulse_policy_path)
            .arg("--nq-executable")
            .arg(&nq)
            .arg("--nq-receipt")
            .arg(&nq_receipt)
            .arg("--inventory")
            .arg(&inventory_path)
            .arg("--catalog")
            .arg(&catalog_path)
            .arg("--support-evidence")
            .arg(&evidence_path)
            .args(["--at", qualified_at, "--output"])
            .arg(&pulse_receipt)
            .output()
            .unwrap();
        assert_success("Pulse qualification", &output);
        let verified = verify_pulse_receipt(
            &attention_policy,
            &pulse_receipt,
            &PulseReplayInputsV1 {
                pulse_executable: pulse.clone(),
                pulse_policy: pulse_policy_path.clone(),
                nq_executable: nq.clone(),
                nq_receipt: nq_receipt.clone(),
                inventory: inventory_path.clone(),
                catalog: catalog_path.clone(),
                support_evidence: Some(evidence_path),
            },
        )
        .unwrap();
        let ingest = store.ingest_verified(&attention_policy, verified).unwrap();
        assert_eq!(ingest.disposition, IngestDispositionV1::Accepted);
        if index == 1 {
            first_receipt = Some((pulse_receipt, root.path().join("support-1.json")));
        }
    }
    let history = store.history(&attention_policy).unwrap();
    let result = evaluate(
        &attention_policy,
        &history,
        chrono::DateTime::parse_from_rfc3339("2026-08-25T12:03:00Z")
            .unwrap()
            .to_utc(),
    )
    .unwrap();
    assert_eq!(
        result.receipt.disposition,
        AttentionDispositionV1::AttentionRequired
    );
    assert_eq!(result.receipt.qualifying_distinct_occurrences, 3);

    let (first_receipt, first_evidence) = first_receipt.unwrap();
    let verified = verify_pulse_receipt(
        &attention_policy,
        &first_receipt,
        &PulseReplayInputsV1 {
            pulse_executable: pulse,
            pulse_policy: pulse_policy_path,
            nq_executable: nq,
            nq_receipt,
            inventory: inventory_path,
            catalog: catalog_path,
            support_evidence: Some(first_evidence),
        },
    )
    .unwrap();
    assert_eq!(
        store
            .ingest_verified(&attention_policy, verified)
            .unwrap()
            .disposition,
        IngestDispositionV1::DuplicateEvidenceOccurrence
    );
}

fn write_signed_evidence(path: &Path, key: &SigningKey, index: u64, observed_at: &str, depth: u64) {
    let mut evidence = json!({
        "schema": "pulse.project-predicate-support-evidence/v1",
        "evidence_id": "",
        "acquisition_id": format!("cogwheel-support:{index}"),
        "producer_id": "pulse-producer:cogwheel-direct",
        "producer_key_id": "pulse-key:cogwheel-direct",
        "source_id": "source:cogwheel-direct-queue-api",
        "dependency_ids": ["direct:cogwheel-queue-api"],
        "subject_id": "deployment:cogwheel-e2e",
        "vantage_id": "vantage:cogwheel-sidecar",
        "observed_at": observed_at,
        "valid_for_seconds": 600,
        "facts": {"queue":{"depth":depth}},
        "local_state": "COGWHEEL_CHATTERING"
    });
    evidence["evidence_id"] = Value::String(digest_without(&evidence, "evidence_id"));
    let mut message = b"pulse/project-predicate-support/evidence/v1\0".to_vec();
    message.extend(canonical(&evidence));
    let envelope = json!({
        "schema": "pulse.project-predicate-support-envelope/v1",
        "evidence": evidence,
        "signature_hex": hex(&key.sign(&message).to_bytes())
    });
    fs::write(path, canonical(&envelope)).unwrap();
}

fn assert_success(label: &str, output: &std::process::Output) {
    assert!(
        output.status.success(),
        "{label}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn required_bin(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name} is required")))
}

fn canonical(value: &impl Serialize) -> Vec<u8> {
    serde_jcs::to_vec(value).unwrap()
}

fn digest(value: &impl Serialize) -> String {
    format!("sha256:{:x}", Sha256::digest(canonical(value)))
}

fn digest_without(value: &Value, field: &str) -> String {
    let mut value = value.clone();
    value.as_object_mut().unwrap().remove(field);
    digest(&value)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

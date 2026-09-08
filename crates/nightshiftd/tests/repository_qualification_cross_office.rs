//! Explicit Q4 cross-office specimen. The normal suite skips when the two
//! environment paths are absent; the campaign qualification invokes it with
//! the exact freshly built NQ evaluator and an external output path.

use std::io::Write as _;
use std::process::{Command, Stdio};

use nightshiftd::canonical_store::{
    AgOccurrenceReferenceV1, AgProgramCounterV1, AG_REFERENCE_SCHEMA_V1,
};
use nightshiftd::repository_qualification::*;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

fn sha(value: char) -> String {
    format!("sha256:{}", value.to_string().repeat(64))
}

fn jcs_sha<T: Serialize>(value: &T) -> String {
    format!(
        "sha256:{:x}",
        Sha256::digest(serde_jcs::to_vec(value).unwrap())
    )
}

fn ag_digest(label: &str) -> String {
    let domain = "ag-governed-engine-test/v1";
    let payload = label.as_bytes();
    let mut hash = Sha256::new();
    hash.update(b"ag-ng\0digest\0v1\0");
    hash.update((domain.len() as u128).to_be_bytes());
    hash.update(domain.as_bytes());
    hash.update((payload.len() as u128).to_be_bytes());
    hash.update(payload);
    format!("sha256:{:x}", hash.finalize())
}

#[test]
fn factual_nq_receipt_becomes_exact_nightshift_ag_basis() {
    let (Ok(nq_program), Ok(output_path)) = (
        std::env::var("NQ_NG_BIN"),
        std::env::var("Q4_RESOLUTION_OUTPUT"),
    ) else {
        eprintln!("Q4 cross-office specimen not requested");
        return;
    };
    let temp = tempfile::tempdir().unwrap();
    let context = serde_json::json!({
        "executable_sha256": sha('5'),
        "argv_transcript_sha256": sha('6'),
        "repository_relative_cwd": ".",
        "environment_transcript_sha256": sha('7')
    });
    let git = |byte: char| {
        serde_json::json!({
            "object_format": "sha1", "digest": byte.to_string().repeat(40)
        })
    };
    let producer = serde_json::json!({
        "producer_id": "porter.repository-facts/v1",
        "producer_version": "1.0.0",
        "executable_sha256": sha('8')
    });
    let profile = serde_json::json!({
        "schema": NQ_PROFILE_SCHEMA_V1,
        "profile_id": "q4-cross-office-profile",
        "campaign_packet_sha256": sha('9'),
        "stage_id": "q4-stage",
        "repository_id": "repo/q4",
        "repository_ref": "refs/heads/q4",
        "predecessor_head": git('1'), "predecessor_tree": git('2'),
        "result_head": git('3'), "result_tree": git('4'),
        "expected_evidence_producer": producer,
        "ordered_gates": [{"ordinal": 0, "gate_id": "test", "context": context, "required_exit_code": 0}],
        "required_artifacts": [{"repository_relative_path": "evidence/q4.json", "sha256": sha('a')}],
        "required_workspace_predicates": [
            "REPOSITORY_IDENTITY_MATCHES", "PERSISTENT_WRITE_READ_ROUND_TRIP",
            "HEAD_AND_TREE_STABLE_DURING_QUALIFICATION", "WORKTREE_MATCHES_DECLARED_CLEANLINESS",
            "MUTATION_SCOPE_RESPECTED"
        ],
        "expected_clean_worktree": true
    });
    let workspace_custody = [
        "REPOSITORY_IDENTITY_MATCHES",
        "PERSISTENT_WRITE_READ_ROUND_TRIP",
        "HEAD_AND_TREE_STABLE_DURING_QUALIFICATION",
        "WORKTREE_MATCHES_DECLARED_CLEANLINESS",
        "MUTATION_SCOPE_RESPECTED",
    ]
    .into_iter()
    .map(|predicate| {
        serde_json::json!({
            "predicate": predicate, "observation_sha256": sha('e'),
            "outcome": {"outcome": "PASSED"}
        })
    })
    .collect::<Vec<_>>();
    let evidence = serde_json::json!({
        "schema": NQ_EVIDENCE_SCHEMA_V1,
        "evidence_id": "q4-factual-evidence",
        "profile_id": "q4-cross-office-profile",
        "profile_sha256": jcs_sha(&profile),
        "campaign_packet_sha256": sha('9'),
        "stage_id": "q4-stage", "repository_id": "repo/q4", "repository_ref": "refs/heads/q4",
        "predecessor_head": git('1'), "predecessor_tree": git('2'),
        "result_head": git('3'), "result_tree": git('4'),
        "producer": producer,
        "qualification_started_at_unix_ms": 1000, "qualification_finished_at_unix_ms": 1100,
        "gates": [{
            "ordinal": 0, "gate_id": "test", "context": context,
            "started_at_unix_ms": 1010, "finished_at_unix_ms": 1050,
            "outcome": {"outcome": "COMPLETED", "exit_code": 0,
                "stdout_sha256": sha('b'), "stderr_sha256": sha('c')}
        }],
        "artifacts": [{
            "repository_relative_path": "evidence/q4.json", "present": true,
            "sha256": sha('a'), "observation_sha256": sha('d')
        }],
        "workspace_custody": workspace_custody,
        "observed_clean_worktree": true
    });
    let profile_path = temp.path().join("profile.json");
    let evidence_path = temp.path().join("evidence.json");
    let receipt_path = temp.path().join("receipt.json");
    std::fs::write(&profile_path, serde_jcs::to_vec(&profile).unwrap()).unwrap();
    std::fs::write(&evidence_path, serde_jcs::to_vec(&evidence).unwrap()).unwrap();
    let evaluated = Command::new(&nq_program)
        .args(["campaign-stage-qualification", "evaluate", "--profile"])
        .arg(&profile_path)
        .arg("--evidence")
        .arg(&evidence_path)
        .args(["--evaluated-at-unix-ms", "1200", "--output"])
        .arg(&receipt_path)
        .status()
        .unwrap();
    assert!(evaluated.success());
    let receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&receipt_path).unwrap()).unwrap();
    assert_eq!(receipt["status"], "QUALIFIED");
    let nq_sha = format!(
        "sha256:{:x}",
        Sha256::digest(std::fs::read(&nq_program).unwrap())
    );
    let applicability = QualificationApplicabilityProfileV1 {
        schema: String::new(),
        profile_id: String::new(),
        expected_nq_profile_id: "q4-cross-office-profile".into(),
        expected_nq_profile_sha256: jcs_sha(&profile),
        expected_nq_evaluator_id: "nq-ng.campaign-stage-qualification-evaluator/v1".into(),
        expected_nq_evaluator_version: receipt["evaluator_version"].as_str().unwrap().into(),
        expected_nq_evaluator_executable_sha256: nq_sha,
        source_campaign_id: ag_digest("source-campaign"),
        source_occurrence_id: "00000000-0000-4000-8000-00000000000a".into(),
        source_attempt_id: "attempt-q4".into(),
        source_settlement_id: "settlement-q4".into(),
        expected_result_head: GitObjectBindingV1 {
            object_format: "sha1".into(),
            digest: "3".repeat(40),
        },
        expected_result_tree: GitObjectBindingV1 {
            object_format: "sha1".into(),
            digest: "4".repeat(40),
        },
        subject_digest: ag_digest("subject"),
        resolver_id: "nightshift.repository-qualification-resolver/v1".into(),
        max_age_ms: 100_000,
    }
    .seal()
    .unwrap();
    let snapshot = serde_json::json!({"state": "settled-q4"});
    let source = AgOccurrenceReferenceV1 {
        schema: AG_REFERENCE_SCHEMA_V1.into(),
        campaign_id: applicability.source_campaign_id.clone(),
        occurrence_id: applicability.source_occurrence_id.clone(),
        state_digest: sha('f'),
        snapshot_digest: jcs_sha(&snapshot),
        program_counter: AgProgramCounterV1::SettledObservationRequired,
        docket_attempt_id: Some("attempt-q4".into()),
        settlement_id: Some("settlement-q4".into()),
        external_decision_request_id: None,
        exact_snapshot: snapshot,
    };
    let mut store = QualificationReceiptStoreV1::open(&temp.path().join("nightshift.db")).unwrap();
    let mut verifier = NqNgQualificationVerifierV1::new(&nq_program).unwrap();
    let retained = store
        .ingest(&applicability, &profile, &evidence, &receipt, &mut verifier)
        .unwrap();
    let observation = retained_qualification_observation_id(&applicability, &receipt).unwrap();
    let outcome = store
        .resolve_applicability(
            &applicability,
            &source,
            &retained.receipt_id,
            &ag_digest("campaign"),
            "00000000-0000-0000-0000-000000000001",
            &observation,
            &ag_digest("subject"),
            1300,
        )
        .unwrap();
    let QualificationApplicabilityOutcomeV1::Observation(resolution) = outcome else {
        panic!()
    };
    assert_eq!(resolution.status, AgTypedObservationStatusV1::Current);

    let applicability_path = temp.path().join("applicability.json");
    let cli_store = temp.path().join("qualification-cli.db");
    std::fs::write(
        &applicability_path,
        serde_jcs::to_vec(&applicability).unwrap(),
    )
    .unwrap();
    let ingress = Command::new(env!("CARGO_BIN_EXE_nightshift"))
        .arg("--store")
        .arg(&cli_store)
        .args(["repository-qualification", "ingest", "--applicability"])
        .arg(&applicability_path)
        .arg("--nq-profile")
        .arg(&profile_path)
        .arg("--nq-evidence")
        .arg(&evidence_path)
        .arg("--nq-receipt")
        .arg(&receipt_path)
        .arg("--nq-executable")
        .arg(&nq_program)
        .output()
        .unwrap();
    assert!(
        ingress.status.success(),
        "Nightshift qualification ingress failed: {}",
        String::from_utf8_lossy(&ingress.stderr)
    );

    let binding_path = temp.path().join("resolver-binding.json");
    std::fs::write(
        &binding_path,
        serde_jcs::to_vec(&serde_json::json!({
            "schema": "nightshift.repository-qualification-resolver-binding/v0",
            "applicability": applicability,
            "source": source,
            "receipt_id": retained.receipt_id,
        }))
        .unwrap(),
    )
    .unwrap();
    let request = serde_jcs::to_vec(&serde_json::json!({
        "schema": "ag.governed-loop.observation-request/v1",
        "key": {"campaign": ag_digest("campaign"), "occurrence": "00000000-0000-0000-0000-000000000001"},
        "observation": observation,
        "subject": ag_digest("subject"),
        "now_unix_ms": 1300,
    }))
    .unwrap();
    let mut resolver = Command::new(env!("CARGO_BIN_EXE_nightshift-observation-resolver"))
        .arg("--store")
        .arg(&cli_store)
        .args([
            "--resolver-id",
            "nightshift.repository-qualification-resolver/v1",
        ])
        .args(["--default-ttl-ms", "1"])
        .arg("--repository-qualification-binding")
        .arg(&binding_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    resolver.stdin.take().unwrap().write_all(&request).unwrap();
    let resolved = resolver.wait_with_output().unwrap();
    assert!(
        resolved.status.success(),
        "Nightshift qualification resolver failed: {}",
        String::from_utf8_lossy(&resolved.stderr)
    );
    assert_eq!(
        resolved
            .stdout
            .strip_suffix(b"\n")
            .unwrap_or(&resolved.stdout),
        serde_jcs::to_vec(&resolution).unwrap()
    );
    std::fs::write(output_path, serde_jcs::to_vec(&resolution).unwrap()).unwrap();
}

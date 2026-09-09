//! Real modern evaluator → Nightshift retention. Explicit opt-in; no fake verifier.
use nightshiftd::{
    canonical_store::{AgOccurrenceReferenceV1, AgProgramCounterV1, AG_REFERENCE_SCHEMA_V1},
    repository_qualification::AgTypedObservationStatusV1,
    reservation_qualification::*,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{path::Path, process::Command};

fn sha(c: char) -> String {
    format!("sha256:{}", c.to_string().repeat(64))
}
fn digest(v: &Value) -> String {
    format!("sha256:{:x}", Sha256::digest(serde_jcs::to_vec(v).unwrap()))
}
fn write(path: &Path, v: &Value) {
    std::fs::write(path, serde_jcs::to_vec(v).unwrap()).unwrap();
}

#[test]
#[ignore = "requires explicit NQ_NG_BIN built from the integrated modern candidate"]
fn real_modern_realization_preserves_positive_refusal_uncertainty_and_expiry() {
    let program = std::env::var("NQ_NG_BIN").expect("explicit modern evaluator required");
    let temp = tempfile::tempdir().unwrap();
    let git = |c: char| json!({"object_format":"sha1", "digest":c.to_string().repeat(40)});
    let context = json!({"executable_sha256":sha('a'), "argv_transcript_sha256":sha('b'),
        "repository_relative_cwd":".", "environment_transcript_sha256":sha('c')});
    let producer = json!({"producer_id":"retirement.fixture-facts/v1", "producer_version":"1",
        "executable_sha256":sha('d')});
    let profile = json!({"schema":NQ_REALIZATION_PROFILE_SCHEMA_V2, "profile_id":"retirement/stage",
        "evidence_reservation":sha('1'), "campaign_packet_sha256":sha('2'), "stage_id":"stage-1",
        "repository_id":"fixture/repository", "repository_ref":"refs/heads/retirement",
        "predecessor":{"kind":"initial_git", "head":git('3'), "tree":git('4')},
        "predecessor_head":git('3'), "predecessor_tree":git('4'), "executor_plan_template":sha('5'),
        "expected_evidence_producer":producer,
        "ordered_gates":[{"ordinal":0,"gate_id":"test","context":context,"required_exit_code":0}],
        "required_artifacts":[], "required_workspace_predicates":["REPOSITORY_IDENTITY_MATCHES"],
        "expected_clean_worktree":true});
    let chain = json!({"evidence_reservation":sha('1'), "docket_attempt":sha('6'),
        "executor_plan_template":sha('5'), "executor_plan":sha('7'), "docket_settlement":sha('8'),
        "porter_run_id":"run-1", "porter_record_sha256":sha('9'), "executor_receipt":sha('a'),
        "predecessor_head":git('3'), "predecessor_tree":git('4'), "result_head":git('b'),"result_tree":git('c')});
    let evidence = json!({"schema":NQ_REALIZATION_EVIDENCE_SCHEMA_V2, "evidence_id":"evidence-1",
        "profile_id":profile["profile_id"], "profile_sha256":digest(&profile), "evidence_reservation":sha('1'),
        "campaign_packet_sha256":sha('2'), "stage_id":"stage-1", "repository_id":"fixture/repository",
        "repository_ref":"refs/heads/retirement", "predecessor_qualification":null,"realizations":[chain],
        "producer":producer, "qualification_started_at_unix_ms":100,"qualification_finished_at_unix_ms":102,
        "gates":[{"ordinal":0,"gate_id":"test","context":context,"started_at_unix_ms":100,
            "finished_at_unix_ms":101,"outcome":{"outcome":"COMPLETED","exit_code":0,
            "stdout_sha256":sha('d'),"stderr_sha256":sha('e')}}], "artifacts":[],
        "workspace_custody":[{"predicate":"REPOSITORY_IDENTITY_MATCHES", "observation_sha256":sha('f'),
            "outcome":{"outcome":"PASSED"}}], "observed_clean_worktree":true});
    let profile_path = temp.path().join("profile.json");
    write(&profile_path, &profile);
    for (index, expected) in ["QUALIFIED", "FAILED", "INDETERMINATE", "INDETERMINATE"]
        .iter()
        .enumerate()
    {
        let mut input = evidence.clone();
        input["evidence_id"] = json!(format!("evidence-{index}"));
        match index {
            1 => input["gates"][0]["outcome"]["exit_code"] = json!(1),
            2 => {
                input["gates"][0]["outcome"] =
                    json!({"outcome":"INDETERMINATE","reason":"result absent"})
            }
            3 => input["realizations"][0]["executor_plan_template"] = json!(sha('f')),
            _ => (),
        }
        let evidence_path = temp.path().join(format!("evidence-{index}.json"));
        let receipt_path = temp.path().join(format!("receipt-{index}.json"));
        write(&evidence_path, &input);
        let output = Command::new(&program)
            .args(["campaign-stage-realization", "evaluate", "--profile"])
            .arg(&profile_path)
            .arg("--evidence")
            .arg(&evidence_path)
            .args(["--evaluated-at-unix-ms", "110", "--output"])
            .arg(&receipt_path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let receipt: Value =
            serde_json::from_slice(&std::fs::read(&receipt_path).unwrap()).unwrap();
        assert_eq!(receipt["status"], *expected);
        let applicability = ReservationApplicabilityProfileV1 {
            schema: String::new(),
            profile_id: String::new(),
            evidence_reservation: sha('1'),
            expected_nq_profile_id: "retirement/stage".into(),
            expected_nq_profile_sha256: digest(&profile),
            expected_nq_evaluator_id: receipt["evaluator_id"].as_str().unwrap().into(),
            expected_nq_evaluator_version: receipt["evaluator_version"].as_str().unwrap().into(),
            expected_nq_evaluator_executable_sha256: receipt["evaluator_executable_sha256"]
                .as_str()
                .unwrap()
                .into(),
            source_campaign_id: sha('2'),
            source_occurrence_id: "00000000-0000-4000-8000-000000000001".into(),
            source_attempt_id: sha('6'),
            source_settlement_id: sha('8'),
            subject_digest: sha('b'),
            resolver_id: "nightshift.reservation-qualification-resolver/v1".into(),
            max_age_ms: 1000,
        }
        .seal()
        .unwrap();
        let mut store =
            ReservationRealizationStoreV1::open(&temp.path().join(format!("state-{index}.sqlite")))
                .unwrap();
        let mut verifier = NqNgReservationVerifierV1::new(&program).unwrap();
        store
            .ingest(&applicability, &profile, &input, &receipt, &mut verifier)
            .unwrap();
        let snapshot = json!({"state":"settled-observation-required"});
        let source = AgOccurrenceReferenceV1 {
            schema: AG_REFERENCE_SCHEMA_V1.into(),
            campaign_id: sha('2'),
            occurrence_id: applicability.source_occurrence_id.clone(),
            state_digest: sha('0'),
            snapshot_digest: digest(&snapshot),
            program_counter: AgProgramCounterV1::SettledObservationRequired,
            docket_attempt_id: Some(sha('6')),
            settlement_id: Some(sha('8')),
            external_decision_request_id: None,
            exact_snapshot: snapshot,
        };
        let resolve = |at| {
            store
                .resolve_applicability(
                    &applicability,
                    &source,
                    &sha('a'),
                    "00000000-0000-4000-8000-000000000002",
                    &applicability.evidence_reservation,
                    &applicability.subject_digest,
                    at,
                )
                .unwrap()
        };
        let is_current = |outcome| {
            matches!(outcome, ReservationApplicabilityOutcomeV1::Observation(r)
            if r.status == AgTypedObservationStatusV1::Current)
        };
        assert_eq!(is_current(resolve(111)), index == 0);
        assert!(!is_current(resolve(1110)));
        let mut changed = input.clone();
        changed["repository_id"] = json!("different/repo");
        assert!(store
            .ingest(&applicability, &profile, &changed, &receipt, &mut verifier)
            .is_err());
        let mut old = profile.clone();
        old["schema"] = json!("nq.campaign-stage-realization-profile/v2");
        assert!(store
            .ingest(&applicability, &old, &input, &receipt, &mut verifier)
            .is_err());
    }
}

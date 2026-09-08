//! Real three-stage repository/NQ/Nightshift half of the Governed Campaign
//! Loop V0 specimen. AG consumes the emitted opaque resolutions in its own
//! repository, preserving the production process boundary.

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use nightshiftd::canonical_store::{
    AgOccurrenceReferenceV1, AgProgramCounterV1, AG_REFERENCE_SCHEMA_V1,
};
use nightshiftd::repository_qualification::{
    retained_qualification_observation_id, GitObjectBindingV1, QualificationApplicabilityProfileV1,
    NQ_EVIDENCE_SCHEMA_V1, NQ_PROFILE_SCHEMA_V1,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

fn sha(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn sha_file(path: &Path) -> String {
    sha(&std::fs::read(path).unwrap())
}

fn jcs_sha<T: Serialize>(value: &T) -> String {
    sha(&serde_jcs::to_vec(value).unwrap())
}

fn ag_digest(label: &str) -> String {
    let domain = b"ag-governed-engine-test/v1";
    let payload = label.as_bytes();
    let mut hash = Sha256::new();
    hash.update(b"ag-ng\0digest\0v1\0");
    hash.update((domain.len() as u128).to_be_bytes());
    hash.update(domain);
    hash.update((payload.len() as u128).to_be_bytes());
    hash.update(payload);
    format!("sha256:{:x}", hash.finalize())
}

fn run(repo: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("GIT_AUTHOR_NAME", "GCL V0 Fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "GCL V0 Fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .env("GIT_AUTHOR_DATE", "2001-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2001-01-01T00:00:00Z")
        .output()
        .unwrap()
}

fn git_text(repo: &Path, args: &[&str]) -> String {
    let output = run(repo, args);
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn initialize(repo: &Path) {
    std::fs::create_dir_all(repo).unwrap();
    git_text(repo, &["init", "-b", "gcl-v0"]);
    std::fs::write(repo.join("README"), b"bounded fixture\n").unwrap();
    git_text(repo, &["add", "README"]);
    git_text(repo, &["commit", "-m", "fixture predecessor"]);
}

fn execute_fixed_worker(repo: &Path, stage: usize) {
    let directory = repo.join("synthetic");
    std::fs::create_dir_all(&directory).unwrap();
    let relative = format!("synthetic/stage-{stage}.txt");
    std::fs::write(
        repo.join(&relative),
        format!("governed campaign loop v0 stage {stage}\n"),
    )
    .unwrap();
    git_text(repo, &["add", &relative]);
    git_text(repo, &["commit", "-m", &format!("fixture stage {stage}")]);
}

fn git_binding(digest: &str) -> serde_json::Value {
    serde_json::json!({"object_format": "sha1", "digest": digest})
}

#[test]
fn three_real_git_stages_emit_three_exact_current_observations() {
    let (Ok(nq_program), Ok(output_path)) = (
        std::env::var("NQ_NG_BIN"),
        std::env::var("GCL_V0_RESOLUTIONS_OUTPUT"),
    ) else {
        eprintln!("GCL V0 cross-office specimen not requested");
        return;
    };
    let nq_program = std::path::PathBuf::from(nq_program);
    let temp = tempfile::tempdir().unwrap();
    let predictor = temp.path().join("predictor");
    let workspace = temp.path().join("workspace");
    initialize(&predictor);
    initialize(&workspace);
    assert_eq!(
        git_text(&predictor, &["rev-parse", "HEAD"]),
        git_text(&workspace, &["rev-parse", "HEAD"])
    );

    // All exact result identities and qualification profiles exist before
    // the first stage mutates the governed workspace.
    let repository_id = sha(git_text(&workspace, &["rev-parse", "--git-dir"]).as_bytes());
    let packet_id = sha(b"gcl-v0-three-stage-packet");
    let producer_executable = std::env::current_exe().unwrap();
    let producer = serde_json::json!({
        "producer_id": "ag.governed-campaign-factual-gate-producer/v0",
        "producer_version": "0",
        "executable_sha256": sha_file(&producer_executable)
    });
    let git_executable = std::path::PathBuf::from("/usr/bin/git");
    let git_executable_sha = sha_file(&git_executable);
    let mut profiles = Vec::new();
    for stage in 1..=3 {
        let predecessor_head = git_text(&predictor, &["rev-parse", "HEAD"]);
        let predecessor_tree = git_text(&predictor, &["rev-parse", "HEAD^{tree}"]);
        execute_fixed_worker(&predictor, stage);
        let result_head = git_text(&predictor, &["rev-parse", "HEAD"]);
        let result_tree = git_text(&predictor, &["rev-parse", "HEAD^{tree}"]);
        let artifact_path = format!("synthetic/stage-{stage}.txt");
        let artifact_sha = sha_file(&predictor.join(&artifact_path));
        let argv = vec![
            "git",
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            "HEAD",
            "--",
            artifact_path.as_str(),
        ];
        let context = serde_json::json!({
            "executable_sha256": git_executable_sha,
            "argv_transcript_sha256": jcs_sha(&argv),
            "repository_relative_cwd": ".",
            "environment_transcript_sha256": jcs_sha(&Vec::<String>::new())
        });
        profiles.push(serde_json::json!({
            "schema": NQ_PROFILE_SCHEMA_V1,
            "profile_id": format!("gcl-v0-stage-{stage}"),
            "campaign_packet_sha256": packet_id,
            "stage_id": format!("stage-{stage}"),
            "repository_id": repository_id,
            "repository_ref": "refs/heads/gcl-v0",
            "predecessor_head": git_binding(&predecessor_head),
            "predecessor_tree": git_binding(&predecessor_tree),
            "result_head": git_binding(&result_head),
            "result_tree": git_binding(&result_tree),
            "expected_evidence_producer": producer,
            "ordered_gates": [{
                "ordinal": 0, "gate_id": format!("stage-{stage}-artifact"),
                "context": context, "required_exit_code": 0
            }],
            "required_artifacts": [{
                "repository_relative_path": artifact_path, "sha256": artifact_sha
            }],
            "required_workspace_predicates": [
                "REPOSITORY_IDENTITY_MATCHES",
                "PERSISTENT_WRITE_READ_ROUND_TRIP",
                "HEAD_AND_TREE_STABLE_DURING_QUALIFICATION",
                "WORKTREE_MATCHES_DECLARED_CLEANLINESS",
                "MUTATION_SCOPE_RESPECTED"
            ],
            "expected_clean_worktree": true
        }));
    }

    let store_path = temp.path().join("nightshift.db");
    let mut resolutions = Vec::new();
    for (index, profile) in profiles.iter().enumerate() {
        let stage = index + 1;
        assert_eq!(
            git_text(&workspace, &["rev-parse", "HEAD"]),
            profile["predecessor_head"]["digest"]
        );
        execute_fixed_worker(&workspace, stage);
        let result_head = git_text(&workspace, &["rev-parse", "HEAD"]);
        let result_tree = git_text(&workspace, &["rev-parse", "HEAD^{tree}"]);
        assert_eq!(result_head, profile["result_head"]["digest"]);
        assert_eq!(result_tree, profile["result_tree"]["digest"]);

        let probe = workspace.join(".gcl-v0-persistence-probe");
        std::fs::write(&probe, b"persistent custody probe").unwrap();
        assert_eq!(std::fs::read(&probe).unwrap(), b"persistent custody probe");
        std::fs::remove_file(&probe).unwrap();
        assert!(git_text(&workspace, &["status", "--porcelain"]).is_empty());

        let artifact_path = format!("synthetic/stage-{stage}.txt");
        let gate = run(
            &workspace,
            &[
                "diff-tree",
                "--no-commit-id",
                "--name-only",
                "-r",
                "HEAD",
                "--",
                &artifact_path,
            ],
        );
        assert!(gate.status.success());
        assert_eq!(String::from_utf8_lossy(&gate.stdout).trim(), artifact_path);
        let custody = [
            "REPOSITORY_IDENTITY_MATCHES",
            "PERSISTENT_WRITE_READ_ROUND_TRIP",
            "HEAD_AND_TREE_STABLE_DURING_QUALIFICATION",
            "WORKTREE_MATCHES_DECLARED_CLEANLINESS",
            "MUTATION_SCOPE_RESPECTED",
        ]
        .into_iter()
        .map(|predicate| {
            serde_json::json!({
                "predicate": predicate,
                "observation_sha256": sha(format!("{stage}:{predicate}:passed").as_bytes()),
                "outcome": {"outcome": "PASSED"}
            })
        })
        .collect::<Vec<_>>();
        let started = 10_000 + u64::try_from(stage).unwrap() * 100;
        let evidence = serde_json::json!({
            "schema": NQ_EVIDENCE_SCHEMA_V1,
            "evidence_id": format!("gcl-v0-factual-evidence-{stage}"),
            "profile_id": profile["profile_id"],
            "profile_sha256": jcs_sha(profile),
            "campaign_packet_sha256": packet_id,
            "stage_id": profile["stage_id"],
            "repository_id": repository_id,
            "repository_ref": "refs/heads/gcl-v0",
            "predecessor_head": profile["predecessor_head"],
            "predecessor_tree": profile["predecessor_tree"],
            "result_head": profile["result_head"],
            "result_tree": profile["result_tree"],
            "producer": producer,
            "qualification_started_at_unix_ms": started,
            "qualification_finished_at_unix_ms": started + 20,
            "gates": [{
                "ordinal": 0,
                "gate_id": format!("stage-{stage}-artifact"),
                "context": profile["ordered_gates"][0]["context"],
                "started_at_unix_ms": started + 2,
                "finished_at_unix_ms": started + 10,
                "outcome": {
                    "outcome": "COMPLETED", "exit_code": 0,
                    "stdout_sha256": sha(&gate.stdout),
                    "stderr_sha256": sha(&gate.stderr)
                }
            }],
            "artifacts": [{
                "repository_relative_path": artifact_path,
                "present": true,
                "sha256": sha_file(&workspace.join(format!("synthetic/stage-{stage}.txt"))),
                "observation_sha256": sha(format!("stage-{stage}-artifact-observed").as_bytes())
            }],
            "workspace_custody": custody,
            "observed_clean_worktree": true
        });
        let profile_path = temp.path().join(format!("profile-{stage}.json"));
        let evidence_path = temp.path().join(format!("evidence-{stage}.json"));
        let receipt_path = temp.path().join(format!("receipt-{stage}.json"));
        std::fs::write(&profile_path, serde_jcs::to_vec(profile).unwrap()).unwrap();
        std::fs::write(&evidence_path, serde_jcs::to_vec(&evidence).unwrap()).unwrap();
        let evaluated = Command::new(&nq_program)
            .args(["campaign-stage-qualification", "evaluate", "--profile"])
            .arg(&profile_path)
            .arg("--evidence")
            .arg(&evidence_path)
            .arg("--evaluated-at-unix-ms")
            .arg((started + 30).to_string())
            .arg("--output")
            .arg(&receipt_path)
            .output()
            .unwrap();
        assert!(
            evaluated.status.success(),
            "NQ stage {stage}: {}",
            String::from_utf8_lossy(&evaluated.stderr)
        );
        let receipt: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&receipt_path).unwrap()).unwrap();
        assert_eq!(receipt["status"], "QUALIFIED");

        let occurrence = format!("00000000-0000-4000-8000-{stage:012}");
        let applicability = QualificationApplicabilityProfileV1 {
            schema: String::new(),
            profile_id: String::new(),
            expected_nq_profile_id: format!("gcl-v0-stage-{stage}"),
            expected_nq_profile_sha256: jcs_sha(profile),
            expected_nq_evaluator_id: receipt["evaluator_id"].as_str().unwrap().into(),
            expected_nq_evaluator_version: receipt["evaluator_version"].as_str().unwrap().into(),
            expected_nq_evaluator_executable_sha256: sha_file(&nq_program),
            source_campaign_id: ag_digest("source-campaign"),
            source_occurrence_id: occurrence.clone(),
            source_attempt_id: format!("attempt-{stage}"),
            source_settlement_id: format!("settlement-{stage}"),
            expected_result_head: GitObjectBindingV1 {
                object_format: "sha1".into(),
                digest: result_head,
            },
            expected_result_tree: GitObjectBindingV1 {
                object_format: "sha1".into(),
                digest: result_tree,
            },
            subject_digest: ag_digest("subject"),
            resolver_id: "nightshift.repository-qualification-resolver/v1".into(),
            max_age_ms: 10_000,
        }
        .seal()
        .unwrap();
        let snapshot = serde_json::json!({"stage": stage, "head": profile["result_head"]});
        let source = AgOccurrenceReferenceV1 {
            schema: AG_REFERENCE_SCHEMA_V1.into(),
            campaign_id: applicability.source_campaign_id.clone(),
            occurrence_id: occurrence,
            state_digest: sha(format!("stage-{stage}-settled-state").as_bytes()),
            snapshot_digest: jcs_sha(&snapshot),
            program_counter: AgProgramCounterV1::SettledObservationRequired,
            docket_attempt_id: Some(format!("attempt-{stage}")),
            settlement_id: Some(format!("settlement-{stage}")),
            external_decision_request_id: None,
            exact_snapshot: snapshot,
        };
        let applicability_path = temp.path().join(format!("applicability-{stage}.json"));
        std::fs::write(
            &applicability_path,
            serde_jcs::to_vec(&applicability).unwrap(),
        )
        .unwrap();
        let ingress = Command::new(env!("CARGO_BIN_EXE_nightshift"))
            .arg("--store")
            .arg(&store_path)
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
            "Nightshift ingress stage {stage}: {}",
            String::from_utf8_lossy(&ingress.stderr)
        );
        let retained: serde_json::Value = serde_json::from_slice(&ingress.stdout).unwrap();
        let receipt_id = retained["receipt_id"].as_str().unwrap();
        let observation = retained_qualification_observation_id(&applicability, &receipt).unwrap();
        let binding_path = temp.path().join(format!("binding-{stage}.json"));
        std::fs::write(
            &binding_path,
            serde_jcs::to_vec(&serde_json::json!({
                "schema": "nightshift.repository-qualification-resolver-binding/v0",
                "applicability": applicability,
                "source": source,
                "receipt_id": receipt_id
            }))
            .unwrap(),
        )
        .unwrap();
        let request = serde_jcs::to_vec(&serde_json::json!({
            "schema": "ag.governed-loop.observation-request/v1",
            "key": {
                "campaign": ag_digest("campaign"),
                "occurrence": "00000000-0000-0000-0000-000000000001"
            },
            "observation": observation,
            "subject": ag_digest("subject"),
            "now_unix_ms": started + 40
        }))
        .unwrap();
        let mut resolver = Command::new(env!("CARGO_BIN_EXE_nightshift-observation-resolver"))
            .arg("--store")
            .arg(&store_path)
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
            "Nightshift resolver stage {stage}: {}",
            String::from_utf8_lossy(&resolved.stderr)
        );
        let resolution: serde_json::Value = serde_json::from_slice(&resolved.stdout).unwrap();
        assert_eq!(resolution["status"], "current");
        resolutions.push(resolution);
    }

    std::fs::write(output_path, serde_jcs::to_vec(&resolutions).unwrap()).unwrap();
    assert_eq!(resolutions.len(), 3);
}

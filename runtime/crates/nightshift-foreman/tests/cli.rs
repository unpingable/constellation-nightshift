use std::process::Command;

use chrono::{Duration, TimeZone as _, Utc};
use nightshift_foreman::{ForemanAdmissionV1, FOREMAN_ADMISSION_SCHEMA_V1};

#[test]
fn cli_seals_admission_exactly_and_exposes_no_approval_response() {
    let admitted_at = Utc.with_ymd_and_hms(2026, 8, 29, 16, 0, 0).unwrap();
    let admission = ForemanAdmissionV1 {
        schema: FOREMAN_ADMISSION_SCHEMA_V1.into(),
        admission_digest: format!("sha256:{}", "0".repeat(64)),
        run_id: "run-cli-fixture".into(),
        packet_digest: format!("sha256:{}", "a".repeat(64)),
        operator_basis_digest: format!("sha256:{}", "b".repeat(64)),
        admitted_at,
        expires_at: admitted_at + Duration::hours(1),
        local_runtime_identity: "runtime-cli-fixture".into(),
        maximum_concurrent_workers: 2,
        allowed_adapter_ids: vec!["fixture-adapter".into()],
        allowed_provider_model_classes: vec!["bounded".into()],
        maximum_new_attempts_per_work_item: 1,
        authority_effect: "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY".into(),
        target_effects_authorized: false,
    };
    let directory = tempfile::tempdir().unwrap();
    let draft = directory.path().join("admission.draft.json");
    std::fs::write(&draft, serde_json::to_vec_pretty(&admission).unwrap()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_nightshift-foreman"))
        .args(["seal-admission", "--draft"])
        .arg(&draft)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.stdout.ends_with(b"\n"));
    let sealed = ForemanAdmissionV1::from_slice(&output.stdout).unwrap();
    sealed.validate().unwrap();
    assert_ne!(sealed.admission_digest, admission.admission_digest);

    let help = Command::new(env!("CARGO_BIN_EXE_nightshift-foreman"))
        .arg("--help")
        .output()
        .unwrap();
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("seal-admission"));
    assert!(help.contains("replay"));
    assert!(help.contains("bootstrap-admit"));
    assert!(help.contains("bootstrap-step"));
    assert!(help.contains("bootstrap-status"));
    assert!(!help.contains("approve"));
}

#[test]
fn cli_read_command_refuses_absent_database_without_creating_files() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("absent.sqlite");
    let output = Command::new(env!("CARGO_BIN_EXE_nightshift-foreman"))
        .args(["status", "--db"])
        .arg(&database)
        .args(["--run-id", "run-absent"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(std::fs::read_dir(directory.path())
        .unwrap()
        .next()
        .is_none());
}
#[test]
fn bootstrap_cli_refuses_symlinked_input_before_database_creation() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("target.json");
    let link = directory.path().join("input.json");
    let database = directory.path().join("bootstrap.sqlite3");
    std::fs::write(&target, b"{}").unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_nightshift-foreman"))
        .args(["bootstrap-admit", "--db"])
        .arg(&database)
        .args(["--bootstrap"])
        .arg(&link)
        .args(["--packet"])
        .arg(&link)
        .args(["--admission"])
        .arg(&link)
        .args(["--profile"])
        .arg(&link)
        .args(["--capacity-requirement"])
        .arg(&link)
        .args(["--capacity-policy"])
        .arg(&link)
        .args(["--availability-requirement"])
        .arg(&link)
        .args(["--availability-policy"])
        .arg(&link)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!database.exists());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot open bounded input"));
}

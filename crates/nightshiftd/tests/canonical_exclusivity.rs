//! Build-graph sentinel for the canonical Nightshift cutover.

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate lives below workspace root")
        .to_path_buf()
}

fn read(path: impl AsRef<Path>) -> String {
    let path = path.as_ref();
    fs::read_to_string(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn production_source() -> String {
    fn collect(directory: &Path, output: &mut String) {
        let mut entries: Vec<_> = fs::read_dir(directory)
            .expect("read production source directory")
            .map(|entry| entry.expect("read source entry").path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                collect(&path, output);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                output.push_str(&read(path));
                output.push('\n');
            }
        }
    }

    let mut output = String::new();
    collect(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut output,
    );
    output
}

#[test]
fn cargo_exposes_exactly_the_two_canonical_production_binaries() {
    let manifest = read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"));
    assert_eq!(manifest.matches("[[bin]]").count(), 2);
    assert!(manifest.contains("autobins = false"));
    assert!(manifest.contains("name = \"nightshift\""));
    assert!(manifest.contains("path = \"src/bin/nightshift.rs\""));
    assert!(manifest.contains("name = \"nightshift-observation-resolver\""));
    assert!(manifest.contains("path = \"src/bin/nightshift_observation_resolver.rs\""));
    assert!(!manifest.contains("nightshift-canonical"));
}

#[test]
fn observation_resolver_is_a_read_only_evidence_surface() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let resolver_sources = [
        src.join("observation_resolver.rs"),
        src.join("bin").join("nightshift_observation_resolver.rs"),
    ];
    for path in &resolver_sources {
        let source = read(path);
        assert!(
            !source.contains("Command::new"),
            "observation resolver opens a subprocess: {}",
            path.display()
        );
        assert!(
            !source.contains("CanonicalStore::open("),
            "observation resolver must use the read-only store open path: {}",
            path.display()
        );
        for mutator in [
            "claim_slot",
            "record_missed",
            "record_observation",
            "prepare_ag_occurrence",
            "attach_ag_occurrence",
            "record_ag_status",
            "record_ag_refusal",
            "recover_ag_occurrence",
            "mark_recovery_required",
            "close_without_proposal",
            "recover_after_restart",
        ] {
            assert!(
                !source.contains(mutator),
                "observation resolver references cycle-mutating {mutator}: {}",
                path.display()
            );
        }
    }
}

#[test]
fn retired_authority_stack_is_structurally_absent_from_production() {
    let workspace_manifest = read(repo_root().join("Cargo.toml"));
    let crate_manifest = read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"));
    let source = production_source();

    for dependency in ["wicket =", "wlp =", "docket ="] {
        assert!(
            !workspace_manifest.contains(dependency),
            "found {dependency}"
        );
        assert!(!crate_manifest.contains(dependency), "found {dependency}");
    }
    for retired in [
        "--no-governor",
        "ActionAuthorized",
        "AuthorityResult",
        "AuthorizationReceipt",
        "ProposedAction",
        "AuthorityLevel",
        "continuity_configured",
        "scheduled_skip",
    ] {
        assert!(!source.contains(retired), "found retired symbol {retired}");
    }
    for retired_case_insensitive in ["wicket::", "wlp::", "governor_client", "mvp_a"] {
        assert!(
            !source
                .to_ascii_lowercase()
                .contains(retired_case_insensitive),
            "found retired surface {retired_case_insensitive}"
        );
    }
}

#[test]
fn only_closed_upstream_verifiers_present_support_and_ag_are_process_boundaries() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut command_files = Vec::new();
    fn visit(directory: &Path, command_files: &mut Vec<String>) {
        for entry in fs::read_dir(directory).expect("read production source") {
            let path = entry.expect("read source entry").path();
            if path.is_dir() {
                visit(&path, command_files);
            } else if path.extension().is_some_and(|extension| extension == "rs")
                && read(&path).contains("Command::new")
            {
                command_files.push(
                    path.file_name()
                        .expect("source filename")
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
    }
    visit(&src, &mut command_files);
    command_files.sort();
    assert_eq!(
        command_files,
        [
            "ag_port.rs",
            "currentness.rs",
            "nq_admission.rs",
            "project_predicate_attention.rs",
            "repository_qualification.rs",
            "reservation_qualification.rs"
        ]
    );

    let generic_attention = read(src.join("project_predicate_attention.rs"));
    assert!(generic_attention.contains("pulse-project-predicate-support"));
    assert!(generic_attention.contains("\"replay\""));
    for forbidden in ["\"qualify\"", "--at", "monitor-concerns", "project status"] {
        assert!(
            !generic_attention.contains(forbidden),
            "generic attention verifier widened into upstream acquisition: {forbidden}"
        );
    }

    let repository_qualification = read(src.join("repository_qualification.rs"));
    assert!(repository_qualification.contains("Some(\"nq-monitor\")"));
    assert!(repository_qualification.contains("\"campaign-stage-qualification\""));
    assert!(repository_qualification.contains("\"replay\""));
    for forbidden in [
        "\"evaluate\"",
        "\"execute\"",
        "\"authorize\"",
        "\"continue\"",
    ] {
        assert!(
            !repository_qualification.contains(forbidden),
            "repository qualification widened beyond exact replay: {forbidden}"
        );
    }
    let reservation_qualification = read(src.join("reservation_qualification.rs"));
    assert!(reservation_qualification.contains("Some(\"nq-monitor\")"));
    assert!(reservation_qualification.contains("\"campaign-stage-realization\""));
    assert!(reservation_qualification.contains("\"replay\""));
    for forbidden in ["\"evaluate\"", "\"execute\"", "\"authorize\"", "\"continue\""] {
        assert!(
            !reservation_qualification.contains(forbidden),
            "reservation qualification widened beyond exact replay: {forbidden}"
        );
    }
}

#[test]
fn reference_service_refuses_an_nq_binary_without_the_qualify_contract() {
    let service = read(repo_root().join("deploy/systemd/nightshift-observation-cycle.service"));
    assert!(service.contains("ExecStartPre=/usr/bin/env ${NIGHTSHIFT_NQ_PROGRAM} --help"));
    assert!(service
        .contains("ExecStartPre=/usr/bin/env ${NIGHTSHIFT_NQ_PROGRAM} diagnostics qualify --help"));
}

#[test]
fn ag_genesis_carries_the_deployment_owned_runtime_profile() {
    let source = read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("ag_port.rs"),
    );
    assert!(source.contains("\"--runtime-profile\""));
    assert!(source.contains("\"--expected-observation-resolver-id\""));
    assert!(source.contains("runtime_profile"));
}

#[test]
fn inherited_presentation_boundaries_remain_load_bearing() {
    let root = repo_root();
    let posture = read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("diagnostic_posture.rs"),
    );
    let disposition = read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("nq_disposition.rs"),
    );
    let disposition_test = read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("nq_reliance_disposition.rs"),
    );
    let nq_doc = read(root.join("docs/NQ_RELIANCE_SOURCE.md"));
    let posture_doc = read(root.join("docs/operator/examples/diagnostic-posture-v1/README.md"));
    assert!(posture.contains("headline_does_not_determine_currentness"));
    assert!(posture.contains("Operator-facing summary of a posture, not a currentness predicate"));
    assert!(disposition
        .contains("A read-only posture proposal. **None of these is an instruction to act.**"));
    assert!(disposition
        .to_ascii_lowercase()
        .contains("this enum states the bounded read-only disposition; it does not diagnose"));
    assert!(disposition_test.contains("stop_disposition_does_not_diagnose_why"));
    assert!(nq_doc.contains("The enum is a bounded read-only directive, not"));
    assert!(posture_doc.contains("`headline` is a lossy display summary"));
}

use std::path::Path;
use std::process::{Command, Output};

use chrono::{DateTime, Utc};
use nightshiftd::canonical_store::{CanonicalStore, RecurrenceSlotV1, RecurrenceTriggerV1};
use serde_json::Value;

fn time(text: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(text)
        .unwrap()
        .with_timezone(&Utc)
}

fn slot(occurrence: u64) -> RecurrenceSlotV1 {
    RecurrenceSlotV1::new(
        "private-policy".into(),
        "private-config".into(),
        "private-subject".into(),
        "private-scope".into(),
        "clock-one".into(),
        time("2026-11-23T00:00:00Z"),
        time("2026-11-23T00:00:01Z"),
        occurrence,
        RecurrenceTriggerV1::Scheduled,
        None,
    )
    .unwrap()
}

fn summary(path: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nightshift"))
        .arg("--store")
        .arg(path)
        .args(["cycle", "summary"])
        .args(args)
        .output()
        .unwrap()
}

fn json_summary(path: &Path) -> Value {
    let output = summary(path, &[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn summary_projects_only_retained_fields_and_sorts_fractional_timestamps() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cycles.sqlite");
    let mut store = CanonicalStore::open(&path).unwrap();
    store
        .claim_slot(slot(1), "clock-one", time("2026-11-23T00:00:01Z"))
        .unwrap();
    for (occurrence, updated_at) in [
        (2, "2026-11-23T00:00:01.001Z"),
        (3, "2026-11-23T00:00:01.001001Z"),
        (4, "2026-11-23T00:00:01.001001001Z"),
    ] {
        store
            .record_missed(
                slot(occurrence),
                "clock-one",
                time(updated_at),
                "private-reason".into(),
            )
            .unwrap();
    }
    drop(store);

    let summary_json = json_summary(&path);
    assert_eq!(summary_json["schema"], "nightshift.cycle_summary.v1");
    assert_eq!(
        summary_json["latest_cycle"]["updated_at"],
        "2026-11-23T00:00:01.001001001Z"
    );
    assert_eq!(summary_json["latest_cycle"]["status"], "missed");
    assert_eq!(summary_json["latest_cycle"]["timing"], "missed");
    assert!(summary_json["latest_cycle"]["oldest_nq_admission_completed_at"].is_null());
    assert!(summary_json["last_closed_cycle_updated_at"].is_null());
    assert!(!summary_json.to_string().contains("private-"));

    let output = summary(&path, &["--format", "textfile"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metrics = String::from_utf8(output.stdout).unwrap();
    assert!(metrics.contains(
        "constellation_nightshift_latest_cycle{status=\"missed\",timing=\"missed\"} 1\n"
    ));
    assert!(!metrics.contains("last_closed_cycle_timestamp_seconds"));
    assert!(!metrics.contains("private-"));
}

#[test]
fn empty_store_is_distinct_from_missing_store_or_required_indexes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cycles.sqlite");
    let absent = summary(&path, &[]);
    assert!(!absent.status.success());
    assert!(absent.stdout.is_empty());
    assert!(!path.exists());

    drop(CanonicalStore::open(&path).unwrap());
    let before = std::fs::read(&path).unwrap();
    let empty = json_summary(&path);
    assert!(empty["latest_cycle"].is_null());
    assert!(empty["last_closed_cycle_updated_at"].is_null());
    assert_eq!(std::fs::read(&path).unwrap(), before);

    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.execute("DROP INDEX canonical_closed_cycles_latest_updated_at", [])
        .unwrap();
    drop(raw);
    let unindexed = summary(&path, &[]);
    assert!(!unindexed.status.success());
    assert!(unindexed.stdout.is_empty());
    assert!(String::from_utf8_lossy(&unindexed.stderr)
        .contains("canonical_closed_cycles_latest_updated_at"));
}

#[test]
fn unrecognized_labels_do_not_escape_and_invalid_json_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cycles.sqlite");
    let mut store = CanonicalStore::open(&path).unwrap();
    store
        .claim_slot(slot(1), "clock-one", time("2026-11-23T00:00:01Z"))
        .unwrap();
    drop(store);

    // Substitute only the fixture row to exercise future or damaged data.
    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.execute(
        "UPDATE canonical_observation_cycles SET status=?1, snapshot_json=?2",
        ("free-text-identity", r#"{"timing":"free-text-identity"}"#),
    )
    .unwrap();
    let metrics = summary(&path, &["--format", "textfile"]);
    assert!(metrics.status.success());
    let metrics = String::from_utf8(metrics.stdout).unwrap();
    assert!(metrics.contains("{status=\"other\",timing=\"other\"} 1\n"));
    assert!(!metrics.contains("free-text-identity"));

    raw.execute(
        "UPDATE canonical_observation_cycles SET snapshot_json='truncated-json'",
        [],
    )
    .unwrap();
    let invalid = summary(&path, &[]);
    assert!(!invalid.status.success());
    assert!(invalid.stdout.is_empty());
}

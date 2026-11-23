//! Operator telemetry over retained cycle fields. This projection does not
//! resolve observations or validate the evidence contracts it projects.

use std::fmt::Write as _;

use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{Connection, OptionalExtension, Statement};
use serde::{Deserialize, Serialize};

use crate::canonical_store::{CanonicalStoreError, CycleStatusV1, SlotTimingV1};
use crate::nq_admission::NqSourceDispositionV1;

// Require the #10 indexes. Old stores refuse instead of sorting history.
const LATEST_UPDATE_SQL: &str = "SELECT rowid, updated_at FROM canonical_observation_cycles
    INDEXED BY canonical_cycles_latest_updated_at
    WHERE updated_at >= ?1 AND updated_at < ?2
    ORDER BY updated_at DESC LIMIT 1";
const LATEST_CLOSED_UPDATE_SQL: &str = "SELECT rowid, updated_at FROM canonical_observation_cycles
    INDEXED BY canonical_closed_cycles_latest_updated_at
    WHERE status='closed' AND updated_at >= ?1 AND updated_at < ?2
    ORDER BY updated_at DESC LIMIT 1";

const MAX_SNAPSHOT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Serialize)]
pub struct CycleSummaryV1 {
    schema: &'static str,
    observed_at: DateTime<Utc>,
    latest_cycle: Option<LatestCycleV1>,
    last_closed_cycle_updated_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
struct LatestCycleV1 {
    status: &'static str,
    timing: &'static str,
    updated_at: DateTime<Utc>,
    oldest_nq_admission_completed_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
struct SnapshotFields {
    timing: String,
    observation: Option<ObservationFields>,
}

#[derive(Deserialize)]
struct ObservationFields {
    #[serde(default)]
    source_admissions: Vec<AdmissionFields>,
}

#[derive(Deserialize)]
struct AdmissionFields {
    disposition: NqSourceDispositionV1,
    origin: AdmissionOrigin,
}

#[derive(Deserialize)]
struct AdmissionOrigin {
    completed_at: DateTime<Utc>,
}

fn decode_closed_label<T: serde::de::DeserializeOwned>(value: String) -> Option<T> {
    serde_json::from_value(serde_json::Value::String(value)).ok()
}

fn timing_label(timing: Option<SlotTimingV1>) -> &'static str {
    match timing {
        Some(SlotTimingV1::OnTime) => "on_time",
        Some(SlotTimingV1::Late) => "late",
        Some(SlotTimingV1::CatchUp) => "catch_up",
        Some(SlotTimingV1::Missed) => "missed",
        None => "other",
    }
}

fn newest_update(
    statement: &mut Statement<'_>,
) -> Result<Option<(i64, DateTime<Utc>)>, CanonicalStoreError> {
    let seek = |statement: &mut Statement<'_>, lower: &str, upper: &str| {
        statement
            .query_row([lower, upper], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .optional()
    };
    let Some((mut rowid, mut upper)) = seek(statement, "", "~")? else {
        return Ok(None);
    };
    for _ in 0..4 {
        let parsed = DateTime::parse_from_rfc3339(&upper)
            .map_err(|_| CanonicalStoreError::Invalid("invalid cycle update timestamp".into()))?
            .with_timezone(&Utc);
        if parsed.to_rfc3339_opts(SecondsFormat::AutoSi, true) != upper {
            return Err(CanonicalStoreError::Invalid(
                "cycle update timestamp differs from canonical UTC encoding".into(),
            ));
        }
        let prefix = upper.strip_suffix('Z').expect("canonical UTC ends in Z");
        // `AutoSi` emits 0, 3, 6 or 9 fractional digits. The trailing Z
        // sorts after digits, so a lexicographic head can hide a newer
        // extension of its fractional prefix. Only that prefix can beat it.
        let lower = match prefix.split_once('.') {
            Some((_, fraction)) if fraction.len() == 9 => return Ok(Some((rowid, parsed))),
            Some(_) => prefix.to_owned(),
            None => format!("{prefix}."),
        };
        match seek(statement, &lower, &upper)? {
            Some((next_id, next_timestamp)) => (rowid, upper) = (next_id, next_timestamp),
            None => return Ok(Some((rowid, parsed))),
        }
    }
    Err(CanonicalStoreError::Invalid(
        "cycle update timestamp exceeded supported fractional precisions".into(),
    ))
}

pub(crate) fn read(connection: &Connection) -> Result<CycleSummaryV1, CanonicalStoreError> {
    let tx = connection.unchecked_transaction()?;
    let latest_cycle = newest_update(&mut tx.prepare(LATEST_UPDATE_SQL)?)?
        .map(
            |(rowid, updated_at)| -> Result<LatestCycleV1, CanonicalStoreError> {
                let (status, snapshot): (String, Option<String>) = tx.query_row(
                "SELECT status, CASE WHEN octet_length(snapshot_json) <= ?1 THEN snapshot_json END
                 FROM canonical_observation_cycles WHERE rowid=?2",
                (MAX_SNAPSHOT_BYTES, rowid),
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
                let snapshot = snapshot.ok_or_else(|| {
                    CanonicalStoreError::Invalid("cycle snapshot exceeds summary size limit".into())
                })?;
                let fields: SnapshotFields = serde_json::from_str(&snapshot)?;
                let oldest_nq_admission_completed_at = fields
                    .observation
                    .into_iter()
                    .flat_map(|observation| observation.source_admissions)
                    .filter(|entry| entry.disposition == NqSourceDispositionV1::AdmittedReport)
                    .map(|entry| entry.origin.completed_at)
                    .min();
                Ok(LatestCycleV1 {
                    status: decode_closed_label::<CycleStatusV1>(status)
                        .map_or("other", CycleStatusV1::as_db),
                    timing: timing_label(decode_closed_label(fields.timing)),
                    updated_at,
                    oldest_nq_admission_completed_at,
                })
            },
        )
        .transpose()?;
    let last_closed_cycle_updated_at =
        newest_update(&mut tx.prepare(LATEST_CLOSED_UPDATE_SQL)?)?.map(|(_, timestamp)| timestamp);
    tx.commit()?;
    Ok(CycleSummaryV1 {
        schema: "nightshift.cycle_summary.v1",
        observed_at: Utc::now(),
        latest_cycle,
        last_closed_cycle_updated_at,
    })
}

impl CycleSummaryV1 {
    /// node_exporter textfile exposition with a closed status/timing label set.
    pub fn textfile(&self) -> String {
        let mut result = String::new();
        let present = u8::from(self.latest_cycle.is_some());
        writeln!(result, "# TYPE constellation_nightshift_cycle_present gauge\nconstellation_nightshift_cycle_present {present}")
            .expect("writing to a String cannot fail");
        if let Some(latest) = &self.latest_cycle {
            writeln!(result, "# TYPE constellation_nightshift_latest_cycle gauge\nconstellation_nightshift_latest_cycle{{status=\"{}\",timing=\"{}\"}} 1", latest.status, latest.timing)
                .expect("writing to a String cannot fail");
        }
        for (name, time) in [
            (
                "cycle_summary_observed_timestamp_seconds",
                Some(self.observed_at),
            ),
            (
                "latest_cycle_updated_timestamp_seconds",
                self.latest_cycle.as_ref().map(|cycle| cycle.updated_at),
            ),
            (
                "last_closed_cycle_timestamp_seconds",
                self.last_closed_cycle_updated_at,
            ),
            (
                "oldest_nq_admission_completed_timestamp_seconds",
                self.latest_cycle
                    .as_ref()
                    .and_then(|cycle| cycle.oldest_nq_admission_completed_at),
            ),
        ] {
            if let Some(time) = time {
                let seconds = time.timestamp() as f64
                    + f64::from(time.timestamp_subsec_nanos()) / 1_000_000_000.0;
                writeln!(result, "# TYPE constellation_nightshift_{name} gauge\nconstellation_nightshift_{name} {seconds}")
                    .expect("writing to a String cannot fail");
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_store::CanonicalStore;
    use rusqlite::StatementStatus::VmStep;

    #[test]
    fn selected_updates_use_bounded_index_seeks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.sqlite");
        drop(CanonicalStore::open(&path).unwrap());
        let db = Connection::open(path).unwrap();
        db.pragma_update(None, "foreign_keys", "OFF").unwrap();
        // SQL substitution rows exercise selection cost only. Typed cycle
        // creation and JSON readback are exercised at the CLI boundary.
        db.execute_batch(
            "INSERT INTO canonical_observation_cycles
             (cycle_id,slot_id,version,status,state_digest,snapshot_json,updated_at)
             VALUES ('a','a',1,'closed','d','{}','2026-11-23T00:00:00Z'),
                    ('b','b',1,'closed','d','{}','2026-11-23T00:00:00.222Z'),
                    ('c','c',1,'observing','d','{}','2026-11-23T00:00:00.333Z');",
        )
        .unwrap();

        let measure = || {
            [LATEST_UPDATE_SQL, LATEST_CLOSED_UPDATE_SQL].map(|sql| {
                let mut statement = db.prepare(sql).unwrap();
                let result = newest_update(&mut statement).unwrap().unwrap().1;
                (result, statement.get_status(VmStep))
            })
        };
        let baseline = measure();
        assert_eq!(baseline[0].0.timestamp_subsec_millis(), 333);
        assert_eq!(baseline[1].0.timestamp_subsec_millis(), 222);

        // Interleave many newer-than-closed, nonclosed rows. A whole-history
        // sort, or a search through the wrong index, would grow with them.
        db.execute_batch(
            "WITH RECURSIVE seq(n) AS (
                SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n<5000
             )
             INSERT INTO canonical_observation_cycles
               (cycle_id,slot_id,version,status,state_digest,snapshot_json,updated_at)
             SELECT 'history' || n,'history' || n,1,'missed','d','{}',
                    printf('2026-11-23T00:00:00.%09dZ', 300000000+n)
             FROM seq;",
        )
        .unwrap();
        assert_eq!(measure(), baseline);
        assert!(baseline.into_iter().all(|(_, steps)| steps < 100));
    }
}

"""Source-only SQLite regression for Nightshift#10; no native runtime claim.

The schema is read from CanonicalStore::open, not mirrored. SQL rows are
substitution fixtures, not valid Nightshift testimony. Candidate indexes are
applied only to disposable in-memory databases by explicitly named tests.
Run with ordinary unittest; the owning-schema regression is intentionally RED
until an independently verified store migration is admitted and implemented.
"""
import datetime
import hashlib
import json
import pathlib
import re
import sqlite3
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "crates/nightshiftd/src/canonical_store.rs"
QUERIES = {
    "attention_closed16": "SELECT cycle_id, updated_at FROM canonical_observation_cycles WHERE status = 'closed' ORDER BY updated_at DESC LIMIT 16",
    "status_closed1": "SELECT cycle_id, updated_at, snapshot_json FROM canonical_observation_cycles WHERE status='closed' ORDER BY updated_at DESC LIMIT 1",
    "status_newest1": "SELECT cycle_id, status, updated_at, snapshot_json FROM canonical_observation_cycles ORDER BY updated_at DESC LIMIT 1",
}
CANDIDATE_INDEX_SQL = """
CREATE INDEX IF NOT EXISTS canonical_cycles_latest_updated_at
ON canonical_observation_cycles(updated_at DESC);
CREATE INDEX IF NOT EXISTS canonical_closed_cycles_latest_updated_at
ON canonical_observation_cycles(updated_at DESC) WHERE status='closed';
"""


def owning_schema_batches():
    source = SOURCE.read_text().split("impl CanonicalStore {", 1)[1]
    source = source.split("/// Opens the store strictly read-only:", 1)[0]
    batches = re.findall(r'connection\.execute_batch\(\s*"([^"\\]*)"\s*,?\s*\)', source)
    if len(batches) != 3:
        raise AssertionError("owning open schema extraction changed; review exact SQL")
    return batches


def store(nonclosed=0, path=":memory:"):
    con = sqlite3.connect(str(path))
    con.execute("PRAGMA foreign_keys=ON")
    for sql in owning_schema_batches():
        con.executescript(sql)
    slots, cycles, events = [], [], []
    start = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
    for i in range(32 + nonclosed):
        status = "closed" if i < 32 else "observing"
        at = (start + datetime.timedelta(seconds=i)).isoformat().replace("+00:00", "Z")
        cid, sid = f"fixture-cycle-{i:06}", f"fixture-slot-{i:06}"
        snapshot = '{ "fixture_only": true, "cycle_id": ' + json.dumps(cid) + ' }\n'
        slots.append((sid, cid, status, '{"fixture_only":true}', f"digest-{i}", at))
        cycles.append((cid, sid, 1, status, f"digest-{i}", snapshot, at))
        events.append((cid, 1, "fixture-only", None, f"digest-{i}", snapshot, at))
    con.executemany("INSERT INTO canonical_recurrence_slots VALUES (?,?,?,?,?,?)", slots)
    con.executemany("INSERT INTO canonical_observation_cycles (cycle_id,slot_id,version,status,state_digest,snapshot_json,updated_at) VALUES (?,?,?,?,?,?,?)", cycles)
    con.executemany("INSERT INTO canonical_cycle_events VALUES (?,?,?,?,?,?,?)", events)
    con.commit()
    return con



def pre_index_fixture(con):
    # Counterfactual controls must not inherit the migration they replace.
    con.executescript("""
        DROP INDEX IF EXISTS canonical_cycles_latest_updated_at;
        DROP INDEX IF EXISTS canonical_closed_cycles_latest_updated_at;
    """)


def measure(con, sql):
    steps = 0

    def progress():
        nonlocal steps
        steps += 1
        return 0

    plan = [r[3] for r in con.execute("EXPLAIN QUERY PLAN " + sql)]
    con.set_progress_handler(progress, 1)
    try:
        rows = con.execute(sql).fetchall()
    finally:
        con.set_progress_handler(None, 0)
    return {"plan": plan, "steps": steps, "rows": rows}


def retained_digest(con):
    rows = {table: con.execute(f"SELECT * FROM {table} ORDER BY 1,2").fetchall()
            for table in ("canonical_recurrence_slots", "canonical_observation_cycles", "canonical_cycle_events")}
    return hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()


class ProjectionIndexTests(unittest.TestCase):
    def test_owning_schema_bounds_actual_latest_queries(self):
        """RED before the proposed owning migration, not a timing benchmark."""
        with store(12000) as con:
            for label, sql in QUERIES.items():
                with self.subTest(query=label):
                    result = measure(con, sql)
                    self.assertFalse(any("USE TEMP B-TREE" in p for p in result["plan"]), result)
                    self.assertLess(result["steps"], 400, result)

    def test_global_index_alone_still_scans_newer_nonclosed_rows(self):
        counts = []
        for n in (1000, 12000):
            with store(n) as con:
                pre_index_fixture(con)
                con.executescript(CANDIDATE_INDEX_SQL.split("CREATE INDEX IF NOT EXISTS canonical_closed", 1)[0])
                result = measure(con, QUERIES["attention_closed16"])
                self.assertFalse(any("USE TEMP B-TREE" in p for p in result["plan"]))
                counts.append(result["steps"])
        self.assertGreater(counts[1], counts[0] * 5, counts)

    def test_two_candidate_indexes_bound_both_limits_and_preserve_results(self):
        counts = []
        for n in (1000, 12000):
            with store(n) as con:
                pre_index_fixture(con)
                before = {label: con.execute(sql).fetchall() for label, sql in QUERIES.items()}
                digest = retained_digest(con)
                con.executescript(CANDIDATE_INDEX_SQL)
                current = {}
                for label, sql in QUERIES.items():
                    result = measure(con, sql)
                    self.assertEqual(result["rows"], before[label])
                    self.assertFalse(any("USE TEMP B-TREE" in p for p in result["plan"]), result)
                    self.assertLess(result["steps"], 400, result)
                    current[label] = result["steps"]
                self.assertEqual(retained_digest(con), digest)
                counts.append(current)
        self.assertEqual(counts[0], counts[1])

    def test_candidate_migration_idempotent_reopen_and_readonly_no_ddl(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "fixture.sqlite"
            with store(32, path) as con:
                pre_index_fixture(con)
                before = retained_digest(con)
                con.executescript(CANDIDATE_INDEX_SQL)
            with sqlite3.connect(path) as writer:
                writer.executescript(CANDIDATE_INDEX_SQL)
                self.assertEqual(retained_digest(writer), before)
                self.assertEqual(len(writer.execute("SELECT name FROM sqlite_master WHERE name IN ('canonical_cycles_latest_updated_at','canonical_closed_cycles_latest_updated_at')").fetchall()), 2)
            with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as reader:
                reader.execute("PRAGMA query_only=1")
                self.assertEqual(retained_digest(reader), before)
                for sql in QUERIES.values():
                    self.assertLess(measure(reader, sql)["steps"], 400)
                with self.assertRaises(sqlite3.OperationalError):
                    reader.execute("CREATE INDEX forbidden_reader_index ON canonical_observation_cycles(status)")

    def test_ascending_index_negative_changes_existing_tied_selection(self):
        with store(0) as con:
            pre_index_fixture(con)
            con.execute("UPDATE canonical_observation_cycles SET updated_at='2100-01-01T00:00:00Z' WHERE cycle_id BETWEEN 'fixture-cycle-000003' AND 'fixture-cycle-000026'")
            con.commit()
            before = con.execute(QUERIES["status_closed1"]).fetchall()
            con.executescript(CANDIDATE_INDEX_SQL.replace("updated_at DESC", "updated_at ASC"))
            self.assertNotEqual(con.execute(QUERIES["status_closed1"]).fetchall(), before)

    def test_malformed_and_future_timestamps_are_not_filtered_or_rewritten(self):
        with store(0) as con:
            pre_index_fixture(con)
            con.execute("UPDATE canonical_observation_cycles SET updated_at='not-a-timestamp' WHERE cycle_id='fixture-cycle-000000'")
            con.execute("UPDATE canonical_observation_cycles SET updated_at='9999-12-31T23:59:59Z' WHERE cycle_id='fixture-cycle-000001'")
            con.commit()
            before = {label: con.execute(sql).fetchall() for label, sql in QUERIES.items()}
            self.assertEqual(before["attention_closed16"][0][1], "not-a-timestamp")
            digest = retained_digest(con)
            con.executescript(CANDIDATE_INDEX_SQL)
            self.assertEqual(retained_digest(con), digest)
            self.assertEqual({label: con.execute(sql).fetchall() for label, sql in QUERIES.items()}, before)

    def test_equal_timestamp_and_status_transition_selection_is_unchanged(self):
        with store(0) as con:
            # Retain equal timestamps: existing SQL has no explicit tie breaker.
            con.execute("UPDATE canonical_observation_cycles SET updated_at='2100-01-01T00:00:00Z' WHERE cycle_id BETWEEN 'fixture-cycle-000003' AND 'fixture-cycle-000026'")
            con.commit()
            before = {label: con.execute(sql).fetchall() for label, sql in QUERIES.items()}
            digest = retained_digest(con)
            con.executescript(CANDIDATE_INDEX_SQL)
            self.assertEqual(retained_digest(con), digest)
            self.assertEqual({label: con.execute(sql).fetchall() for label, sql in QUERIES.items()}, before)
            con.execute("UPDATE canonical_observation_cycles SET status='observing' WHERE cycle_id='fixture-cycle-000003'")
            con.commit()
            indexed = {label: con.execute(sql).fetchall() for label, sql in QUERIES.items()}
            con.execute("DROP INDEX canonical_cycles_latest_updated_at")
            con.execute("DROP INDEX canonical_closed_cycles_latest_updated_at")
            self.assertEqual({label: con.execute(sql).fetchall() for label, sql in QUERIES.items()}, indexed)


if __name__ == "__main__":
    unittest.main()

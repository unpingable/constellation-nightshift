# SPDX-License-Identifier: Apache-2.0
import argparse
import importlib.util
import json
import sqlite3
import sys
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "examples/saved-check-installed-local.py"
SPEC = importlib.util.spec_from_loader(
    "saved_check_local_example",
    SourceFileLoader("saved_check_local_example", str(SCRIPT)),
)
EXAMPLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXAMPLE)


class SavedCheckLocalExampleTests(unittest.TestCase):
    def arguments(self, root: Path, program: Path) -> argparse.Namespace:
        return argparse.Namespace(
            root=root,
            nightshift=program,
            nq=program,
            monitor=program,
            tick=program,
            produce=None,
        )

    def test_producer_observes_disposable_queue(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "queue.sqlite"
            with sqlite3.connect(database) as connection:
                connection.execute("CREATE TABLE pending_work(id INTEGER PRIMARY KEY)")
                connection.executemany("INSERT INTO pending_work VALUES(?)", ((1,), (2,), (3,)))
            result = EXAMPLE.queue_observation(database)
            self.assertEqual(result["schema"], "project.ops.status/v1")
            observation = result["concerns"][0]["observation"]
            self.assertEqual(observation["facts"], {"queue": {"depth": 3}})
            self.assertEqual(observation["local_state"], "OBSERVED")

    def test_existing_root_refuses_before_program_resolution(self):
        with tempfile.TemporaryDirectory(prefix="saved-check-demo-") as directory:
            args = self.arguments(Path(directory), Path("/does/not/exist"))
            with self.assertRaisesRegex(FileExistsError, "refusing existing"):
                EXAMPLE.run(args)

    def test_missing_program_refuses_without_creating_root(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "saved-check-demo-absent"
            args = self.arguments(root, Path("/does/not/exist"))
            with self.assertRaisesRegex(ValueError, "--nightshift"):
                EXAMPLE.run(args)
            self.assertFalse(root.exists())

    def test_invoke_records_bounded_result_and_expected_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = EXAMPLE.invoke(root, "json", [sys.executable, "-c", "print('{\"ok\":true}')"])
            self.assertEqual(result, {"ok": True})
            self.assertIsNone(EXAMPLE.invoke(
                root,
                "expected-refusal",
                [sys.executable, "-c", "raise SystemExit(75)"],
                expected=75,
            ))
            records = [json.loads(line) for line in (root / "commands.jsonl").read_text().splitlines()]
            self.assertEqual([item["exit_code"] for item in records], [0, 75])
            self.assertTrue(all(item["supervision_error"] is None for item in records))


if __name__ == "__main__":
    unittest.main()

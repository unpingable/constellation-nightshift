#!/usr/bin/env python3
"""Exercise desired-check selection only; no acquisition, evaluation or effects."""
import argparse
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nightshift", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    program, root = args.nightshift, args.root
    if not program.is_absolute() or not program.is_file():
        parser.error("--nightshift must name an absolute built executable")
    if not root.is_absolute() or root.exists() or not root.name.startswith("nightshift-saved-check-schedule-"):
        parser.error("--root must be an absent absolute nightshift-saved-check-schedule-* directory")
    root.mkdir(mode=0o700)
    policy = {
        "schema": "nightshift.saved-check-schedule-policy/v1",
        "policy_id": "disposable-capacity", "configuration_version": "1",
        "definition_reference": "capacity", "definition_digest": "sha256:" + "a" * 64,
        "source_identity": "disposable-sqlite", "subject_id": "queue",
        "scope_id": "local-check", "scheduler_clock_id": "operator-clock",
        "epoch": "2026-09-14T12:00:00Z", "interval_seconds": 60,
        "admissible_delay_seconds": 10,
    }
    path = root / "policy.json"
    # This restricted ASCII/integer object has no general canonicalizer needs.
    path.write_text(json.dumps(policy, sort_keys=True, separators=(",", ":")))
    transcript = root / "commands.jsonl"

    def select(at, clock="operator-clock", success=True):
        command = [str(program), "saved-check", "schedule", "--policy", str(path),
                   "--scheduler-clock-id", clock, "--at", at]
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=10, cwd=root,
                                   env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        with transcript.open("a") as stream:
            stream.write(json.dumps({"command": command, "exit_code": completed.returncode,
                                     "stdout": completed.stdout, "stderr": completed.stderr}) + "\n")
        assert (completed.returncode == 0) == success
        return json.loads(completed.stdout) if success else None

    due = select("2026-09-14T12:00:00Z")
    late = select("2026-09-14T12:00:10Z")
    assert due["selection"] == "due" and due["request"] == late["request"]
    assert due["authority"] == "none" and due["observation_created"] is False
    assert "observed_at" not in due["request"]
    before = select("2026-09-14T11:59:59Z")
    missed = select("2026-09-14T12:00:11Z")
    assert before["selection"] == "not_due" and before["request"] is None
    assert missed["selection"] == "missed" and missed["request"] is None
    next_slot = select("2026-09-14T12:01:00Z")
    assert next_slot["request"]["evaluation_id"] != due["request"]["evaluation_id"]
    select("2026-09-14T12:00:00Z", clock="wrong-clock", success=False)
    assert not (root / "nightshift.sqlite").exists()
    print(json.dumps({"result": "qualified", "scope": "selection_only",
                      "synthetic_policy": True, "transcript": str(transcript)}))


if __name__ == "__main__":
    main()

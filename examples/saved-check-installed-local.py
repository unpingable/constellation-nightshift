#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the installed saved-check profile against a disposable local queue.

This is a public newcomer example, not a service installer. It performs an
actual Monitor acquisition, NQ saved-check evaluation and local-file delivery,
and a Nightshift recurrence/attention tick. It creates only the absent
directory named by --root and configures no network or provider route. The
single-user fixture requires a debug NQ build's explicit same-identity helper
exception; an installed release build requires a distinct enrolled helper
account.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
import selectors
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

MAX_OUTPUT = 2 * 1024 * 1024


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def digest_file(path: Path) -> str:
    return digest_bytes(path.read_bytes())


def write_json(path: Path, value: object, *, newline: bool = True) -> None:
    data = canonical(value) + (b"\n" if newline else b"")
    with path.open("xb") as stream:
        stream.write(data)


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def timestamp(value: dt.datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def invoke(root: Path, label: str, argv: list[object], expected: int = 0) -> object:
    command = [str(item) for item in argv]
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=root,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        start_new_session=True,
        bufsize=0,
    )
    assert process.stdout is not None and process.stderr is not None
    output = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + 75
    failure: BaseException | None = None
    try:
        with selectors.DefaultSelector() as selector:
            for name, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, 75)
                for key, _ in selector.select(remaining):
                    block = os.read(key.fileobj.fileno(), 64 * 1024)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    output[key.data].extend(block)
                    if len(output[key.data]) > MAX_OUTPUT:
                        raise RuntimeError(f"{label} {key.data} exceeded 2 MiB")
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
    except BaseException as error:
        failure = error
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
    finally:
        process.stdout.close()
        process.stderr.close()
    record = {
        "label": label,
        "argv": command,
        "exit_code": process.returncode,
        "supervision_error": type(failure).__name__ if failure else None,
        "stdout_sha256": digest_bytes(bytes(output["stdout"])),
        "stderr_sha256": digest_bytes(bytes(output["stderr"])),
    }
    with (root / "commands.jsonl").open("ab") as stream:
        stream.write(canonical(record) + b"\n")
    if failure is not None:
        raise failure
    if process.returncode != expected:
        detail = bytes(output["stderr"])[-2000:].decode("utf-8", "replace").strip()
        raise RuntimeError(f"{label} exited {process.returncode}, expected {expected}: {detail}")
    if not output["stdout"].strip():
        return None
    return json.loads(bytes(output["stdout"]))


def queue_observation(database: Path) -> dict:
    uri = database.resolve().as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=2) as connection:
        depth = connection.execute("SELECT count(*) FROM pending_work").fetchone()[0]
    observed_at = timestamp(utc_now())
    return {
        "schema": "project.ops.status/v1",
        "project": "saved-check-local-demo",
        "generated_at": observed_at,
        "manifest": {"schema": "project.concerns/v1", "path": ".ops/concerns.toml"},
        "producer": {"id": "saved-check-local.primary"},
        "authority": {},
        "concerns": [{
            "id": "queue.needs-attention",
            "question": "queue.depth-at-least-18/v1",
            "profile": "queue.depth-high/v1",
            "required": True,
            "description": "Is the observed queue depth at least eighteen?",
            "observation": {
                "observation_present": True,
                "local_state": "OBSERVED",
                "domain_state": None,
                "observed_at": observed_at,
                "valid_for_seconds": 120,
                "reason": "Read the disposable SQLite queue",
                "facts": {"queue": {"depth": depth}},
            },
        }],
    }


def require_program(path: Path | None, flag: str) -> Path:
    if path is None or not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise ValueError(f"{flag} must name an absolute regular non-symlink file")
    if not os.access(path, os.X_OK):
        raise ValueError(f"{flag} must be executable")
    return path


def owner_state(root: Path, inbox: Path) -> tuple[str, str, tuple[str, ...]]:
    return (
        digest_file(root / "nightshift.sqlite"),
        digest_file(root / "nq.sqlite"),
        tuple(sorted(path.name for path in inbox.iterdir())),
    )


def run(args: argparse.Namespace) -> dict:
    root: Path = args.root
    if not root.is_absolute() or not root.name.startswith("saved-check-demo-"):
        raise ValueError("--root must be an absent absolute saved-check-demo-* directory")
    if root.exists():
        raise FileExistsError(f"refusing existing --root: {root}")
    nightshift = require_program(args.nightshift, "--nightshift")
    nq = require_program(args.nq, "--nq")
    monitor = require_program(args.monitor, "--monitor")
    tick = require_program(args.tick, "--tick")

    root.mkdir(mode=0o700)
    project = root / "project"
    ops = project / ".ops"
    ops.mkdir(parents=True, mode=0o700)
    database = project / "queue.sqlite"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE pending_work(id INTEGER PRIMARY KEY)")
        connection.executemany("INSERT INTO pending_work(id) VALUES(?)", ((item,) for item in range(20)))

    script = Path(__file__).resolve()
    manifest = (
        'schema = "project.concerns/v1"\nproject = "saved-check-local-demo"\n'
        '[[concerns]]\nid = "queue.needs-attention"\n'
        'question = "queue.depth-at-least-18/v1"\nprofile = "queue.depth-high/v1"\n'
        'required = true\ndescription = "Is the observed queue depth at least eighteen?"\n'
    )
    (ops / "concerns.toml").write_text(manifest, encoding="utf-8")
    (ops / "observation.toml").write_text(
        'schema = "project.observation-binding/v1"\nproducer = "saved-check-local.primary"\n'
        'output_schema = "project.ops.status/v1"\nkind = "exec/v1"\nargv = '
        + json.dumps(["/usr/bin/python3", str(script), "--produce", str(database)]) + "\n",
        encoding="utf-8",
    )

    admissions = root / "admissions"
    helpers = root / "helper-runtime"
    state = root / "state"
    inbox = state / "inbox"
    admissions.mkdir(mode=0o700)
    helpers.mkdir(mode=0o700)
    inbox.mkdir(parents=True, mode=0o711)
    state.chmod(0o700)
    inbox.chmod(0o711)

    nq_config = root / "nq.toml"
    nq_config.write_text("\n".join((
        'schema = "nq.config.v1"', f'database_path = "{root / "nq.sqlite"}"',
        f'socket_path = "{root / "nq.sock"}"', f'admissions_dir = "{admissions}"',
        f'helper_runtime_dir = "{helpers}"', "watchers = []", "notification_routes = []", "",
    )), encoding="utf-8")
    invoke(root, "nq-init", [nq, "--config", nq_config, "--json", "init"])

    definition = {
        "schema": "nq.saved-check-definition/v1",
        "reference": "saved-check-local.queue.nonempty",
        "source_identity": "saved-check-local-monitor-sqlite",
        "currentness_seconds": 120,
        "name": "disposable queue has rows",
        "sql_text": "SELECT id FROM pending_work",
        "mode": "non_empty",
        "threshold": None,
        "column": None,
        "description": "Needs attention when the disposable queue retains work.",
    }
    definition_path = root / "definition.json"
    write_json(definition_path, definition)
    installed = invoke(root, "saved-check-install", [nq, "--config", nq_config, "--json",
        "saved-check", "install", "--definition", definition_path])
    definition_digest = installed["definition_digest"]

    declared_at = utc_now()
    maintenance = {
        "schema": "nq.maintenance-declaration/v1",
        "maintenance_id": "saved-check-local-demo-001",
        "declared_by": "public-local-example",
        "start_at": timestamp(declared_at + dt.timedelta(seconds=1)),
        "end_at": timestamp(declared_at + dt.timedelta(seconds=601)),
        "component": "disposable-queue",
        "kind": "saved-check",
        "subject": "queue",
        "reason": "bounded local newcomer example",
    }
    maintenance_path = root / "maintenance.json"
    write_json(maintenance_path, maintenance)
    invoke(root, "maintenance-declare", [nq, "--config", nq_config, "--json",
        "maintenance", "declare", "--declaration", maintenance_path])
    # The declaration starts in the next second. Waiting once avoids relying on
    # a simulated maintenance state while leaving all component clocks real.
    time.sleep(max(0.0, (declared_at + dt.timedelta(seconds=1.05) - dt.datetime.now(dt.timezone.utc)).total_seconds()))

    runtime = {
        "schema": "nightshift.saved-check-runtime-config/v1",
        "monitor_program": str(monitor), "monitor_program_sha256": digest_file(monitor),
        "monitor_project": str(project), "monitor_trusted_root": str(root),
        "expected_project": "saved-check-local-demo",
        "expected_producer": "saved-check-local.primary",
        "expected_manifest_digest": digest_bytes(manifest.encode()),
        "concern_id": "queue.needs-attention",
        "nq_program": str(nq), "nq_program_sha256": digest_file(nq),
        "nq_config": str(nq_config), "nq_config_sha256": digest_file(nq_config),
        "saved_check_target": str(database), "definition_reference": definition["reference"],
        "definition_digest": definition_digest, "source_identity": definition["source_identity"],
        "definition_currentness_seconds": 120, "condition_component": "disposable-queue",
        "condition_kind": "saved-check", "condition_subject": "queue",
        "command_timeout_seconds": 15,
    }
    runtime_path = root / "runtime.json"
    write_json(runtime_path, runtime, newline=False)
    epoch = declared_at.replace(second=0)
    policy = {
        "schema": "nightshift.saved-check-schedule-policy/v1",
        "policy_id": "saved-check-local-demo", "configuration_version": "1",
        "definition_reference": definition["reference"], "definition_digest": definition_digest,
        "source_identity": definition["source_identity"], "subject_id": "queue", "scope_id": "local",
        "scheduler_clock_id": "local-example-clock", "epoch": timestamp(epoch),
        "interval_seconds": 60, "admissible_delay_seconds": 10,
    }
    policy_path = root / "schedule.json"
    write_json(policy_path, policy, newline=False)
    attention = {
        "schema": "nightshift.saved-check-attention-policy/v1",
        "policy_id": "saved-check-local-attention", "policy_digest": "",
        "max_event_age_seconds": 300,
    }
    attention["policy_digest"] = digest_bytes(canonical(attention))
    attention_path = root / "attention.json"
    write_json(attention_path, attention, newline=False)
    notification = root / "notification.toml"
    notification.write_text("\n".join((
        'schema = "nq.config.v1"', f'database_path = "{root / "nq.sqlite"}"',
        f'socket_path = "{root / "notification.sock"}"', f'admissions_dir = "{admissions}"',
        f'helper_runtime_dir = "{helpers}"', "watchers = []", "[[notification_routes]]",
        'reference = "local"', 'transport = "local_file"', f'local_inbox_directory = "{inbox}"',
        "timeout_ms = 10000", "max_response_bytes = 1024",
        "[notification_routes.nightshift_attention_replay]", f'executable = "{nightshift}"',
        f'executable_sha256 = "{digest_file(nightshift)}"',
        f'store_locator = "{root / "nightshift.sqlite"}"',
        f'approved_policy_digest = "{attention["policy_digest"]}"',
        f'execution_account = "{os.getuid()}"', "",
    )), encoding="utf-8")
    profile = {
        "schema": "nightshift.saved-check-installed-profile/v1",
        "nightshift_program": str(nightshift), "nightshift_program_sha256": digest_file(nightshift),
        "nq_program": str(nq), "nq_program_sha256": digest_file(nq),
        "nightshift_store": str(root / "nightshift.sqlite"),
        "runtime_config": str(runtime_path), "runtime_config_sha256": digest_file(runtime_path),
        "schedule_policy": str(policy_path), "schedule_policy_sha256": digest_file(policy_path),
        "scheduler_clock_id": "local-example-clock", "attention_policy": str(attention_path),
        "attention_policy_sha256": digest_file(attention_path),
        "notification_config": str(notification), "notification_config_sha256": digest_file(notification),
        "notification_route": "local", "notification_destination_identity": "local-inbox:local",
        "state_directory": str(state), "command_timeout_seconds": 60,
    }
    profile_path = root / "profile.json"
    write_json(profile_path, profile)

    at = timestamp(epoch)
    first = invoke(root, "tick-due", [tick, "--profile", profile_path, "--at", at])
    replay = invoke(root, "tick-exact-replay", [tick, "--profile", profile_path, "--at", at])
    if replay != first or len(list(inbox.iterdir())) != 1:
        raise RuntimeError("same-slot replay changed the result or repeated local delivery")

    evaluation_id = first["evaluation_id"]
    evaluation = invoke(root, "inspect-evaluation", [nightshift, "--store", root / "nightshift.sqlite",
        "saved-check", "inspect", "--evaluation-id", evaluation_id])
    attention_record = invoke(root, "inspect-attention", [nightshift, "--store", root / "nightshift.sqlite",
        "saved-check", "attention-status", "--policy", attention_path,
        "--evaluation-id", evaluation_id])
    notification_id = first["delivery"]["notification_id"]
    delivery = invoke(root, "inspect-delivery", [nq, "--config", notification, "--json",
        "notification", "inspect", "--notification-id", notification_id])
    write_json(root / "inspection-nightshift-evaluation.json", evaluation)
    write_json(root / "inspection-nightshift-attention.json", attention_record)
    write_json(root / "inspection-nq-delivery.json", delivery)

    before = owner_state(root, inbox)
    with (state / "tick.lock").open("a+b") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        overlap = invoke(root, "tick-overlap-refusal", [tick, "--profile", profile_path, "--at", at], 75)
    if overlap.get("state") != "overlap_refused" or owner_state(root, inbox) != before:
        raise RuntimeError("overlap refusal changed an owner record")
    missed = invoke(root, "tick-missed-no-catchup", [tick, "--profile", profile_path, "--at",
        timestamp(epoch + dt.timedelta(seconds=11))])
    if missed.get("state") != "missed" or owner_state(root, inbox) != before:
        raise RuntimeError("missed-slot handling changed an owner record")

    if evaluation.get("state") != "terminal":
        raise RuntimeError("Nightshift did not retain a terminal evaluation")
    if not isinstance(delivery, list) or len(delivery) != 1 or delivery[0].get("delivery_state") != "accepted":
        raise RuntimeError("NQ did not retain exactly one accepted local delivery")
    summary = {
        "schema": "nightshift.saved-check-public-example-result/v1",
        "result": "qualified", "authority": "none", "network_routes_configured": 0,
        "helper_identity": "debug_same_uid_fixture_only",
        "input": "disposable 20-row SQLite queue", "root": str(root),
        "tick_id": first["tick_id"], "evaluation_id": evaluation_id,
        "attention_receipt_digest": attention_record["receipt_digest"],
        "notification_id": notification_id, "evaluation_state": evaluation["state"],
        "delivery_state": delivery[0]["delivery_state"],
        "human_receipt": first["delivery"]["human_receipt"],
        "same_slot_replay": "exact_without_second_delivery",
        "overlap": "refused_without_owner_change", "missed": "no_catchup_without_owner_change",
        "response_loss_after_nq_acceptance": "not_exercised",
        "inspection": {
            "commands": str(root / "commands.jsonl"),
            "nightshift_store": str(root / "nightshift.sqlite"),
            "nq_store": str(root / "nq.sqlite"), "local_inbox": str(inbox),
            "nightshift_evaluation": str(root / "inspection-nightshift-evaluation.json"),
            "nightshift_attention": str(root / "inspection-nightshift-attention.json"),
            "nq_delivery": str(root / "inspection-nq-delivery.json"),
        },
    }
    write_json(root / "summary.json", summary)
    return summary


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--produce", type=Path, help=argparse.SUPPRESS)
    result.add_argument("--root", type=Path)
    result.add_argument("--nightshift", type=Path)
    result.add_argument("--nq", type=Path)
    result.add_argument("--monitor", type=Path)
    result.add_argument("--tick", type=Path, default=Path(__file__).parents[1] / "deploy/systemd/nightshift-saved-check-tick")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.produce is not None:
        print(json.dumps(queue_observation(args.produce), sort_keys=True))
        return 0
    if args.root is None:
        parser().error("--root is required")
    try:
        print(canonical(run(args)).decode())
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

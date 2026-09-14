#!/usr/bin/env python3
"""Run a disposable Monitor -> Nightshift -> NQ saved-check recurrence.

This is an explicit local operation, not an installed scheduler.  It keeps its
records under an absent --root directory and performs no network, AG, or Docket
operation.  The optional --attention-inbox adds one local-file attention
delivery; the required --project-example is the public Monitor example used
only as the bound observation producer.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import sqlite3
import subprocess
import sys
import time


PREFIX = "nightshift-saved-check-run-"
MAX_OUTPUT = 1_048_576


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical(value: object) -> bytes:
    """Sufficient for this example's ASCII strings, integers, arrays and objects."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def file_digest(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def write_json(path: Path, value: object) -> None:
    with path.open("xb") as stream:
        stream.write(canonical(value))


def require(value: bool, message: str) -> None:
    if not value:
        raise RuntimeError(message)


def invoke(
    root: Path,
    transcript: Path,
    label: str,
    argv: list[str],
    expected: int = 0,
    stdin: bytes | None = None,
) -> object:
    """Run one bounded local command; preserve enough output for recovery."""
    if stdin is not None:
        require(len(stdin) <= 32_768, "stdin contract exceeds 32 KiB")
    process = subprocess.Popen(
        argv,
        cwd=root,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    output = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + 30
    failure: BaseException | None = None
    group_cleaned = False

    def clean_process_group() -> None:
        nonlocal group_cleaned
        if not group_cleaned:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            group_cleaned = True

    try:
        pending = memoryview(stdin) if stdin is not None else None
        if stdin is not None:
            require(process.stdin is not None, "stdin pipe was not created")
            os.set_blocking(process.stdin.fileno(), False)
        with selectors.DefaultSelector() as poll:
            if pending is not None:
                poll.register(process.stdin, selectors.EVENT_WRITE, "stdin")
            for name, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
                poll.register(pipe, selectors.EVENT_READ, name)
            while poll.get_map():
                if time.monotonic() >= deadline:
                    raise RuntimeError("command time limit exceeded; do not blindly restart")
                for key, _ in poll.select(0.1):
                    if key.data == "stdin":
                        try:
                            written = os.write(key.fileobj.fileno(), pending)
                        except BlockingIOError:
                            continue
                        except BrokenPipeError as error:
                            raise RuntimeError("command stopped accepting its bounded input") from error
                        pending = pending[written:]
                        if not pending:
                            poll.unregister(key.fileobj)
                            key.fileobj.close()
                    else:
                        chunk = os.read(key.fileobj.fileno(), 8192)
                        if not chunk:
                            poll.unregister(key.fileobj)
                        elif len(output[key.data]) + len(chunk) > MAX_OUTPUT:
                            raise RuntimeError("command output exceeded 1 MiB")
                        else:
                            output[key.data].extend(chunk)
                if process.poll() is not None:
                    # The leader can exit while a helper retains an inherited
                    # descriptor. Clear the whole session before waiting for EOF.
                    clean_process_group()
        process.wait(timeout=max(0.01, deadline - time.monotonic()))
        clean_process_group()
    except BaseException as error:
        failure = error
        clean_process_group()
        process.wait()
    finally:
        if process.stdin is not None and not process.stdin.closed:
            process.stdin.close()
        process.stdout.close()
        process.stderr.close()
    record = {
        "label": label, "argv": argv, "exit_code": process.returncode,
        "supervision_error": type(failure).__name__ if failure else None,
        "stdout": output["stdout"].decode("utf-8", "replace"),
        "stderr": output["stderr"].decode("utf-8", "replace"),
    }
    with transcript.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, sort_keys=True) + "\n")
    if failure is not None:
        raise failure
    if (expected == 0 and process.returncode != 0) or (expected != 0 and process.returncode == 0):
        raise RuntimeError(f"{label} exited {process.returncode}; inspect {transcript}")
    return json.loads(record["stdout"]) if expected == 0 else None


def await_after(instant: dt.datetime) -> None:
    """Use the local clock for the next slot; never manufacture an observation time."""
    deadline = time.monotonic() + 45
    while dt.datetime.now(dt.timezone.utc) <= instant:
        if time.monotonic() >= deadline:
            raise RuntimeError("local clock did not reach the next slot within 45 seconds")
        time.sleep(0.05)


def require_file(parser: argparse.ArgumentParser, name: str, path: Path | None) -> Path:
    if path is None or not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
        parser.error(f"--{name} must name an absolute executable file")
    return path.resolve()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nightshift", type=Path, required=True)
    parser.add_argument("--monitor", type=Path, required=True)
    parser.add_argument("--nq", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--project-example", type=Path, required=True)
    parser.add_argument(
        "--attention-inbox",
        action="store_true",
        help="also retain and deliver one attention receipt to a disposable local inbox",
    )
    args = parser.parse_args()
    nightshift = require_file(parser, "nightshift", args.nightshift)
    monitor = require_file(parser, "monitor", args.monitor)
    nq = require_file(parser, "nq", args.nq)
    if not args.project_example.is_absolute() or not args.project_example.is_file():
        parser.error("--project-example must name the absolute public Monitor example")
    producer = args.project_example.resolve()
    root = args.root
    if not root.is_absolute() or root.exists() or not root.name.startswith(PREFIX):
        parser.error(f"--root must be an absent absolute {PREFIX}* directory")
    root.mkdir(mode=0o700)
    transcript = root / "commands.jsonl"
    project = root / "project"
    ops = project / ".ops"
    ops.mkdir(parents=True, mode=0o700)
    target = project / "queue.sqlite"
    with sqlite3.connect(target) as database:
        database.execute("CREATE TABLE pending_work(id INTEGER PRIMARY KEY)")
        database.executemany("INSERT INTO pending_work(id) VALUES(?)", ((item,) for item in range(20)))

    manifest = (
        'schema = "project.concerns/v1"\nproject = "local-queue-demo"\n'
        "[[concerns]]\nid = \"queue.needs-attention\"\n"
        'question = "queue.depth-at-least-18/v1"\nprofile = "queue.depth-high/v1"\n'
        "required = true\ndescription = \"Is the observed queue depth at least eighteen?\"\n"
    )
    manifest_path = ops / "concerns.toml"
    manifest_path.write_text(manifest, encoding="utf-8")
    # Monitor hashes these exact bytes; do not substitute a TOML reserialization.
    manifest_digest = sha256_bytes(manifest.encode("utf-8"))
    binding = {
        "schema": "project.observation-binding/v1",
        "producer": "local-queue.primary",
        "output_schema": "project.ops.status/v1",
        "kind": "exec/v1",
        "argv": ["/usr/bin/python3", str(producer), "--produce", str(target)],
    }
    # TOML's argv representation is intentionally simple and produced from JSON strings.
    (ops / "observation.toml").write_text(
        'schema = "project.observation-binding/v1"\nproducer = "local-queue.primary"\n'
        'output_schema = "project.ops.status/v1"\nkind = "exec/v1"\nargv = '
        + json.dumps(binding["argv"]) + "\n",
        encoding="utf-8",
    )
    admissions = root / "admissions"
    helpers = root / "helper-runtime"
    admissions.mkdir(mode=0o700)
    helpers.mkdir(mode=0o700)
    nq_config = root / "nq.toml"
    nq_config.write_text(
        "\n".join((
            'schema = "nq.config.v1"', f'database_path = "{root / "nq.db"}"',
            f'socket_path = "{root / "nq.sock"}"', f'admissions_dir = "{admissions}"',
            f'helper_runtime_dir = "{helpers}"', "watchers = []", "notification_routes = []", "",
        )), encoding="utf-8",
    )
    invoke(root, transcript, "nq-init", [str(nq), "--config", str(nq_config), "--json", "init"])
    definition = {
        "schema": "nq.saved-check-definition/v1", "reference": "disposable.queue.nonempty",
        "source_identity": "disposable-monitor-sqlite", "currentness_seconds": 120,
        "name": "disposable queue has rows", "sql_text": "SELECT id FROM pending_work",
        "mode": "non_empty", "threshold": None, "column": None,
        "description": "Fails when the real disposable queue has retained work.",
    }
    definition_path = root / "definition.json"
    write_json(definition_path, definition)
    installed = invoke(root, transcript, "saved-check-install", [
        str(nq), "--config", str(nq_config), "--json", "saved-check", "install", "--definition", str(definition_path),
    ])
    definition_digest = installed["definition_digest"]
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    maintenance = {
        "schema": "nq.maintenance-declaration/v1", "maintenance_id": "disposable-maintenance-001",
        "declared_by": "local-example", "start_at": (now + dt.timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "end_at": (now + dt.timedelta(seconds=121)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "component": "disposable-queue", "kind": "saved-check", "subject": "queue",
        "reason": "bounded local annotation example",
    }
    maintenance_path = root / "maintenance.json"
    write_json(maintenance_path, maintenance)
    invoke(root, transcript, "maintenance-declare", [
        str(nq), "--config", str(nq_config), "--json", "maintenance", "declare", "--declaration", str(maintenance_path),
    ])
    await_after(now + dt.timedelta(seconds=1))

    runtime = {
        "schema": "nightshift.saved-check-runtime-config/v1",
        "monitor_program": str(monitor), "monitor_program_sha256": file_digest(monitor),
        "monitor_project": str(project), "monitor_trusted_root": str(root),
        "expected_project": "local-queue-demo", "expected_producer": "local-queue.primary",
        "expected_manifest_digest": manifest_digest, "concern_id": "queue.needs-attention",
        "nq_program": str(nq), "nq_program_sha256": file_digest(nq),
        "nq_config": str(nq_config), "nq_config_sha256": file_digest(nq_config),
        "saved_check_target": str(target), "definition_reference": definition["reference"],
        "definition_digest": definition_digest, "source_identity": definition["source_identity"],
        "definition_currentness_seconds": definition["currentness_seconds"],
        "condition_component": maintenance["component"], "condition_kind": maintenance["kind"],
        "condition_subject": maintenance["subject"], "command_timeout_seconds": 15,
    }
    runtime_path = root / "runtime.json"
    write_json(runtime_path, runtime)
    epoch = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    policy = {
        "schema": "nightshift.saved-check-schedule-policy/v1", "policy_id": "disposable-queue-run",
        "configuration_version": "1", "definition_reference": definition["reference"],
        "definition_digest": definition_digest, "source_identity": definition["source_identity"],
        "subject_id": "queue", "scope_id": "local", "scheduler_clock_id": "local-clock",
        # Thirty seconds is enough to make a duplicate delivery explicit while
        # keeping the next real-clock slot bounded below one minute.
        "epoch": epoch.strftime("%Y-%m-%dT%H:%M:%SZ"), "interval_seconds": 30,
        "admissible_delay_seconds": 29,
    }
    policy_path = root / "policy.json"
    write_json(policy_path, policy)

    def run(label: str, at: str, expected: int = 0):
        return invoke(root, transcript, label, [
            str(nightshift), "--store", str(root / "nightshift.sqlite"), "saved-check", "run",
            "--runtime-config", str(runtime_path), "--policy", str(policy_path),
            "--scheduler-clock-id", "local-clock", "--at", at,
        ], expected)

    first_at = utc_now()
    first = run("nightshift-run", first_at)
    require(first["state"] == "terminal", "first scheduled check did not reach terminal custody")
    require(first["nq_result"]["outcome"] == "failed", "20-row target must retain a failed check result")
    require(first["condition"]["original_result"]["outcome"] == "failed", "condition changed original outcome")
    require(first["condition"]["maintenance"]["state"] == "covered", "active declaration was not an annotation")
    evaluation_id = first["evaluation_id"]
    duplicate = run("nightshift-duplicate", first_at)
    require(duplicate == first, "duplicate slot did not return exact retained custody")
    inspected = invoke(root, transcript, "nightshift-inspect", [
        str(nightshift), "--store", str(root / "nightshift.sqlite"), "saved-check", "inspect", "--evaluation-id", evaluation_id,
    ])
    require(inspected == first, "inspection differs from retained terminal record")

    # The exact replay must not read this source again.  Its terminal bytes are retained first.
    with sqlite3.connect(target) as database:
        database.execute("INSERT INTO pending_work(id) VALUES(1000)")
    target.unlink()
    replay = run("nightshift-source-removed-replay", first_at)
    require(replay == first, "removed target caused an existing occurrence to reread")

    changed_config = dict(runtime)
    changed_config["command_timeout_seconds"] = 14
    changed_config_path = root / "changed-runtime.json"
    write_json(changed_config_path, changed_config)
    invoke(root, transcript, "changed-runtime-refusal", [
        str(nightshift), "--store", str(root / "nightshift.sqlite"), "saved-check", "run",
        "--runtime-config", str(changed_config_path), "--policy", str(policy_path),
        "--scheduler-clock-id", "local-clock", "--at", first_at,
    ], expected=1)
    changed_policy = dict(policy)
    changed_policy["definition_digest"] = "sha256:" + "0" * 64
    changed_policy_path = root / "changed-policy.json"
    write_json(changed_policy_path, changed_policy)
    invoke(root, transcript, "changed-policy-refusal", [
        str(nightshift), "--store", str(root / "nightshift.sqlite"), "saved-check", "run",
        "--runtime-config", str(runtime_path), "--policy", str(changed_policy_path),
        "--scheduler-clock-id", "local-clock", "--at", utc_now(),
    ], expected=1)

    # A later slot receives a newly acquired local observation from a recreated target.
    with sqlite3.connect(target) as database:
        database.execute("CREATE TABLE pending_work(id INTEGER PRIMARY KEY)")
        database.executemany("INSERT INTO pending_work(id) VALUES(?)", ((item,) for item in range(20, 40)))
    await_after(epoch + dt.timedelta(seconds=30))
    next_run = run("nightshift-next-slot", utc_now())
    require(next_run["evaluation_id"] != evaluation_id, "later slot reused evaluation identity")
    require(next_run["state"] == "terminal" and next_run["nq_result"]["outcome"] == "failed", "next slot did not evaluate its new source")
    require(next_run["source_observed_at"] != first["source_observed_at"] or next_run["monitor_inventory_sha256"] != first["monitor_inventory_sha256"], "next slot did not retain a distinct acquisition")
    attention_result: dict[str, object] | None = None
    if args.attention_inbox:
        # This policy's digest is JCS over the same object with its digest blank.
        # Its fields are ASCII strings and an integer, so this example's compact
        # canonical encoder is the exact JCS representation for this object.
        attention_policy = {
            "schema": "nightshift.saved-check-attention-policy/v1",
            "policy_id": "disposable-queue-attention",
            "policy_digest": "",
            "max_event_age_seconds": 300,
        }
        attention_policy["policy_digest"] = sha256_bytes(canonical(attention_policy))
        attention_policy_path = root / "attention-policy.json"
        write_json(attention_policy_path, attention_policy)
        # This is the actual local decision clock. It does not modify the
        # retained condition or source-observation coordinates.
        evaluated_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds")
        bundle = invoke(root, transcript, "saved-check-attention-evaluate", [
            str(nightshift), "--store", str(root / "nightshift.sqlite"), "saved-check",
            "attention-evaluate", "--policy", str(attention_policy_path),
            "--evaluation-id", next_run["evaluation_id"], "--evaluated-at", evaluated_at,
        ])
        require(isinstance(bundle, dict), "attention evaluation did not return a bundle")
        receipt = bundle.get("receipt")
        require(isinstance(receipt, dict), "attention bundle lacks its receipt")
        require(receipt.get("schema") == "nightshift.saved-check-attention-receipt/v1", "unexpected attention receipt schema")
        require(receipt.get("disposition") == "ATTENTION_REQUIRED", "failed covered condition did not require attention")
        require(receipt.get("delivery_eligible") is True, "fresh attention receipt was not delivery eligible")
        require(receipt.get("authority") == "none", "attention receipt incorrectly grants authority")
        require(receipt.get("inspection_reference") == f"saved-check:{next_run['evaluation_id']}", "attention receipt inspection reference is not exact")
        bundle_bytes = canonical(bundle)
        require(len(bundle_bytes) <= 32_768, "attention bundle exceeds NQ intent bound")
        bundle_path = root / "attention-bundle.json"
        with bundle_path.open("xb") as stream:
            stream.write(bundle_bytes)
        replay = invoke(root, transcript, "saved-check-attention-replay", [
            str(nightshift), "--store", str(root / "nightshift.sqlite"), "saved-check",
            "attention-replay", "--bundle-stdin",
        ], stdin=bundle_bytes)
        require(replay.get("schema") == "nightshift.saved-check-attention-replay/v1", "unexpected attention replay schema")
        require(replay.get("matches") is True, "attention replay did not reproduce the exact receipt")
        require(replay.get("expected_receipt_digest") == receipt["receipt_digest"], "attention replay changed receipt identity")
        status = invoke(root, transcript, "saved-check-attention-status", [
            str(nightshift), "--store", str(root / "nightshift.sqlite"), "saved-check",
            "attention-status", "--policy", str(attention_policy_path),
            "--evaluation-id", next_run["evaluation_id"],
        ])
        require(status == receipt, "attention status differs from the retained receipt")

        inbox = root / "attention-inbox"
        inbox.mkdir(mode=0o711)
        inbox.chmod(0o711)
        notification_config = root / "notification.toml"
        notification_config.write_text(
            "\n".join((
                'schema = "nq.config.v1"', f'database_path = "{root / "nq.db"}"',
                f'socket_path = "{root / "notification.sock"}"', f'admissions_dir = "{admissions}"',
                f'helper_runtime_dir = "{helpers}"', "watchers = []", "",
                "[[notification_routes]]", 'reference = "local-attention"',
                'transport = "local_file"', f'local_inbox_directory = "{inbox}"',
                "timeout_ms = 10000", "max_response_bytes = 1024", "",
                "[notification_routes.nightshift_attention_replay]",
                f'executable = "{nightshift}"', f'executable_sha256 = "{file_digest(nightshift)}"',
                f'store_locator = "{root / "nightshift.sqlite"}"',
                f'approved_policy_digest = "{attention_policy["policy_digest"]}"',
                f'execution_account = "{os.getuid()}"', "",
            )), encoding="utf-8",
        )
        receipt_digest = receipt.get("receipt_digest")
        require(isinstance(receipt_digest, str), "attention receipt lacks its digest")
        attention_intent = {
            "schema": "nq.notification_delivery_intent.v1",
            "attention_kind": "nightshift_receipt",
            "stable_event_id": receipt_digest,
            "attention_receipt_digest": receipt_digest,
            "attention_policy_id": attention_policy["policy_id"],
            "attention_policy_digest": attention_policy["policy_digest"],
            "transition_id": receipt_digest,
            "route_reference": "local-attention",
            "destination_identity": "local-inbox:local-attention",
            "summary": "Saved check needs attention; inspect the retained record.",
            "inspection_reference": receipt["inspection_reference"],
            "owner_receipt": bundle,
        }
        attention_intent_bytes = canonical(attention_intent)
        require(len(attention_intent_bytes) <= 32_768, "attention intent exceeds NQ's 32 KiB bound")
        attention_intent_path = root / "attention-intent.json"
        with attention_intent_path.open("xb") as stream:
            stream.write(attention_intent_bytes)
        first_delivery = invoke(root, transcript, "attention-deliver-local", [
            str(nq), "--config", str(notification_config), "--json", "notification",
            "deliver-local", "--intent", str(attention_intent_path), "--route", "local-attention",
        ])
        require(first_delivery.get("delivery_state") == "accepted", "local attention delivery was not accepted")
        notification_id = first_delivery.get("notification_id")
        require(isinstance(notification_id, str), "local attention delivery lacks custody identity")
        require(first_delivery.get("human_receipt") == "not_established", "local delivery must not claim human receipt")
        files = list(inbox.iterdir())
        require(len(files) == 1 and files[0].stat().st_mode & 0o777 == 0o600, "local inbox did not retain one private message")
        duplicate_delivery = invoke(root, transcript, "attention-deliver-local-duplicate", [
            str(nq), "--config", str(notification_config), "--json", "notification",
            "deliver-local", "--intent", str(attention_intent_path), "--route", "local-attention",
        ])
        require(duplicate_delivery.get("notification_id") == notification_id, "duplicate changed delivery identity")
        require(duplicate_delivery.get("delivery_state") == "accepted", "duplicate changed accepted custody")
        require(len(list(inbox.iterdir())) == 1, "duplicate wrote a second local message")
        delivery_status = invoke(root, transcript, "attention-delivery-inspect", [
            str(nq), "--config", str(notification_config), "--json", "notification",
            "inspect", "--notification-id", notification_id,
        ])
        require(len(delivery_status) == 1 and delivery_status[0].get("delivery_state") == "accepted", "delivery inspection disagrees with custody")
        altered_bundle = json.loads(json.dumps(bundle))
        altered_bundle["receipt"]["receipt_digest"] = "sha256:" + "0" * 64
        altered_intent = dict(attention_intent)
        altered_intent["owner_receipt"] = altered_bundle
        altered_intent_path = root / "attention-altered-receipt-negative.json"
        write_json(altered_intent_path, altered_intent)
        invoke(root, transcript, "attention-altered-receipt-refusal-negative", [
            str(nq), "--config", str(notification_config), "--json", "notification",
            "deliver-local", "--intent", str(altered_intent_path), "--route", "local-attention",
        ], expected=1)
        require(len(list(inbox.iterdir())) == 1, "altered receipt created a local message")
        attention_result = {
            "receipt_digest": receipt_digest,
            "notification_id": notification_id,
            "delivery": "local_file_accepted_human_receipt_not_established",
        }
    print(json.dumps({
        "result": "qualified", "scope": "disposable_monitor_nightshift_nq_saved_check",
        "root": str(root), "transcript": str(transcript), "first_evaluation_id": evaluation_id,
        "next_evaluation_id": next_run["evaluation_id"],
        "attention": attention_result,
        "limitations": ["no Pulse", "no AG or Docket", "no HTTPS delivery or human acknowledgment", "claimed/response-loss injection remains component qualification"],
    }, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.SubprocessError) as error:
        print(f"qualification failed: {error}", file=sys.stderr)
        print("recovery artifacts are retained under --root; inspect commands.jsonl before another run", file=sys.stderr)
        raise SystemExit(1)

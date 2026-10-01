#!/usr/bin/env python3
"""Durable, model-free owner for one closed two-profile service investigation."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import socket
import subprocess
import sys
import uuid
from typing import Any

HANDOFF_SCHEMA = "maude.service-investigation-handoff/v1"
PROFILE_SCHEMA = "maude.service-investigation-profile/v1"
SUBMISSION_SCHEMA = "nightshift.service-investigation-submission/v1"
CONFIG_SCHEMA = "nightshift.service-investigation-config/v1"
RECORD_SCHEMA = "nightshift.service-investigation-record/v1"
PROFILES = ("nq.systemd_unit/v1", "nq.http_endpoint/v1")
MAX_BYTES = 16 * 1024 * 1024


class Refusal(RuntimeError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def read_json(path: pathlib.Path, limit: int = MAX_BYTES) -> dict[str, Any]:
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise Refusal(f"oversized input: {path}")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise Refusal(f"object required: {path}")
    return value


def atomic(path: pathlib.Path, value: Any, mode: int = 0o600) -> None:
    raw = value if isinstance(value, bytes) else canonical(value) + b"\n"
    temporary = path.with_name(path.name + ".new")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def exact_fields(value: dict[str, Any], names: set[str], where: str) -> None:
    if set(value) != names:
        raise Refusal(f"{where} is not the closed schema")


def sha(value: Any, where: str) -> str:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:"):
        raise Refusal(f"{where} is not a sha256 digest")
    int(value[7:], 16)
    if value[7:] != value[7:].lower():
        raise Refusal(f"{where} is not lowercase")
    return value


def validate_handoff(value: dict[str, Any]) -> None:
    exact_fields(value, {"schema", "investigation_id", "draft_id", "revision_id", "plan_digest", "profile", "handoff_digest"}, "handoff")
    if value["schema"] != HANDOFF_SCHEMA:
        raise Refusal("unsupported handoff schema")
    expected = dict(value)
    observed = sha(expected.pop("handoff_digest"), "handoff_digest")
    if digest(canonical(expected)) != observed:
        raise Refusal("handoff digest does not bind exact content")
    sha(value["investigation_id"], "investigation_id")
    sha(value["plan_digest"], "plan_digest")
    profile = value["profile"]
    exact_fields(profile, {"schema", "profile_id", "audience", "subject_label", "subject", "diagnostics"}, "profile")
    if profile["schema"] != PROFILE_SCHEMA or sha(profile["subject"], "subject") != profile["subject"]:
        raise Refusal("unsupported profile")
    if tuple(item.get("profile") for item in profile["diagnostics"]) != PROFILES:
        raise Refusal("handoff must contain systemd then HTTP diagnostics")


def validate_config(value: dict[str, Any], handoff: dict[str, Any]) -> None:
    exact_fields(value, {"schema", "artifact_root", "standing_signer", "standing_admitter", "operator_public_key", "execution_identity", "source_revisions", "bindings"}, "config")
    if value["schema"] != CONFIG_SCHEMA:
        raise Refusal("unsupported driver config")
    for name in ("artifact_root", "standing_signer", "standing_admitter", "operator_public_key"):
        if not pathlib.Path(value[name]).is_absolute():
            raise Refusal(f"{name} must be absolute")
    if not isinstance(value["execution_identity"], str) or not value["execution_identity"]:
        raise Refusal("execution_identity must be explicit")
    if set(value["source_revisions"]) != {"maude", "nightshift", "nq", "standing"} or not all(isinstance(item, str) and item for item in value["source_revisions"].values()):
        raise Refusal("exact Maude/Nightshift/NQ/Standing source revisions are required")
    bindings = value["bindings"]
    if set(bindings) != set(PROFILES):
        raise Refusal("config must bind both diagnostic profiles")
    for requested in handoff["profile"]["diagnostics"]:
        bound = bindings[requested["profile"]]
        exact_fields(bound, {"standing_store", "enrollment", "workload_secret_key", "nq_command", "config_digest", "profile_digest", "question_digest", "threshold_policy_digest", "vantage_digest", "admission_id", "instance"}, "binding")
        if bound["config_digest"] != requested["config_digest"] or bound["instance"] != requested["instance"]:
            raise Refusal("deployment binding does not match compiled diagnostic")
        for name in ("profile_digest", "question_digest", "threshold_policy_digest", "vantage_digest"):
            if bound[name] != requested[name]:
                raise Refusal(f"deployment {name} does not match compiled diagnostic")
        if not isinstance(bound["admission_id"], str) or not bound["admission_id"]:
            raise Refusal("deployment admission_id must identify the pre-admitted watcher")
        if not isinstance(bound["nq_command"], list) or not bound["nq_command"] or not pathlib.Path(bound["nq_command"][0]).is_absolute():
            raise Refusal("nq_command requires an absolute configured program")


def command(argv: list[str], *, stdin: bytes | None = None, limit: int = MAX_BYTES) -> bytes:
    result = subprocess.run(argv, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if len(result.stdout) > limit or len(result.stderr) > limit:
        raise Refusal(f"command response exceeds bound: {argv[0]}")
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", "replace").strip()
        stdout = result.stdout.decode("utf-8", "replace").strip()
        details = "\n".join(
            item
            for item in (
                f"stderr: {stderr}" if stderr else "",
                f"stdout: {stdout}" if stdout else "",
            )
            if item
        )
        raise Refusal(f"command refused ({result.returncode}): {details}")
    return result.stdout


def now() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def submission(handoff: dict[str, Any], occurrence: pathlib.Path, run_id: str) -> dict[str, Any]:
    return {
        "schema": SUBMISSION_SCHEMA,
        "investigation_id": handoff["investigation_id"],
        "handoff_digest": handoff["handoff_digest"],
        "plan_digest": handoff["plan_digest"],
        "revision_id": handoff["revision_id"],
        "run_id": run_id,
        "state": "accepted",
        "inspector_path": "/phosphor-ng/investigations/" + handoff["investigation_id"],
        "receipt_path": str(occurrence / "submission.json"),
    }


def submit(args: argparse.Namespace) -> None:
    config = read_json(args.config)
    handoff = read_json(args.handoff, 128 * 1024)
    validate_handoff(handoff)
    validate_config(config, handoff)
    root = pathlib.Path(config["artifact_root"])
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    occurrence = root / handoff["investigation_id"][7:]
    receipt_path = occurrence / "submission.json"
    if receipt_path.exists():
        sys.stdout.buffer.write(canonical(read_json(receipt_path)) + b"\n")
        return
    try:
        occurrence.mkdir(mode=0o700)
    except FileExistsError as error:
        existing = read_json(occurrence / "handoff.json", 128 * 1024)
        if canonical(existing) != canonical(handoff):
            raise Refusal("existing occurrence binds different handoff bytes") from error
        state = read_json(occurrence / "state.json")
        if state.get("state") == "not_started":
            raise Refusal("durable worker was not started; no implicit replacement launch") from error
        receipt = submission(handoff, occurrence, state["run_id"])
        atomic(receipt_path, receipt)
        sys.stdout.buffer.write(canonical(receipt) + b"\n")
        return
    atomic(occurrence / "handoff.json", canonical(handoff))
    script = pathlib.Path(__file__).resolve()
    unit = "nightshift-service-investigation-" + handoff["investigation_id"][7:23]
    run_id = str(uuid.uuid4())
    state = {
        "schema": "nightshift.service-investigation-state/v1", "run_id": run_id,
        "state": "accepted", "updated_at": now(), "next_action": "durable worker launch",
        "host": socket.gethostname(), "unit": unit, "working_directory": str(occurrence),
        "driver_digest": digest(script.read_bytes()), "config_digest": digest(args.config.read_bytes()),
        "handoff_digest": handoff["handoff_digest"], "execution_identity": config["execution_identity"],
        "source_revisions": config["source_revisions"], "log_path": str(occurrence / "worker.log"),
        "expected_terminal_record": str(occurrence / "record.json"),
    }
    atomic(occurrence / "state.json", state)
    launch = [
        str(args.launcher), "--user", "--collect", "--unit", unit,
        "--working-directory", str(occurrence), "--property", "RuntimeMaxSec=600",
        "--property", "StandardOutput=append:" + str(occurrence / "worker.log"),
        "--property", "StandardError=append:" + str(occurrence / "worker.log"),
        str(script), "work", "--config", str(args.config.resolve()), "--occurrence", str(occurrence),
    ]
    launched = subprocess.run(launch, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if launched.returncode != 0:
        state.update(state="not_started", updated_at=now(), next_action="inspect launcher refusal; do not assume acquisition")
        atomic(occurrence / "state.json", state)
        atomic(occurrence / "launcher-refusal.json", {"schema": "nightshift.service-investigation-launcher-refusal/v1", "exit_code": launched.returncode, "stdout": launched.stdout.decode("utf-8", "replace"), "stderr": launched.stderr.decode("utf-8", "replace")})
        raise Refusal("durable worker was not started")
    atomic(occurrence / "launcher.json", {
        "schema": "nightshift.service-investigation-launcher/v1", "unit": unit,
        "stdout": launched.stdout.decode("utf-8", "replace"),
        "stderr": launched.stderr.decode("utf-8", "replace"), "recorded_at": now(),
    })
    receipt = submission(handoff, occurrence, run_id)
    atomic(receipt_path, receipt)
    sys.stdout.buffer.write(canonical(receipt) + b"\n")


def request_body(handoff: dict[str, Any], binding: dict[str, Any], deployed: dict[str, Any], run_id: str) -> dict[str, Any]:
    issued = dt.datetime.now(dt.UTC)
    return {
        "schema": "standing.service-diagnostic-request/v1",
        "request_id": str(uuid.uuid4()),
        "grant_id": deployed["grant_id"],
        "operator": deployed["operator"],
        "workload": deployed["workload"],
        "audience": handoff["profile"]["audience"],
        "subject": handoff["profile"]["subject"],
        "scope": binding["scope"],
        "profile": binding["profile"],
        "config_digest": binding["config_digest"],
        "plan_digest": handoff["plan_digest"],
        "run_id": run_id,
        "node_id": binding["node_id"],
        "issued_at": issued.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "expires_at": (issued + dt.timedelta(minutes=2)).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    }


def acquire(handoff: dict[str, Any], config: dict[str, Any], binding: dict[str, Any], run_id: str, occurrence: pathlib.Path) -> dict[str, Any]:
    deployed = config["bindings"][binding["profile"]]
    enrollment = read_json(pathlib.Path(deployed["enrollment"]), 32 * 1024)["body"]
    body = request_body(handoff, binding, {"grant_id": enrollment["grant_id"], "operator": enrollment["operator"], "workload": enrollment["workload"]}, run_id)
    signed = command([config["standing_signer"], "request", "--secret-key", deployed["workload_secret_key"]], stdin=canonical(body), limit=64 * 1024)
    admission = command([config["standing_admitter"], "--store", deployed["standing_store"], "--enrollment", deployed["enrollment"], "--operator-public-key", config["operator_public_key"], "--audience", handoff["profile"]["audience"]], stdin=signed, limit=256 * 1024)
    admission_value = json.loads(admission)
    if admission_value.get("schema") != "standing.service-diagnostic-admission-result/v1" or admission_value.get("provider_invoked") is not False:
        raise Refusal("Standing returned an unexpected admission result")
    stem = binding["node_id"]
    atomic(occurrence / f"{stem}.standing.json", admission)
    nq = [str(item) for item in deployed["nq_command"]]
    execution = command([*nq, "diagnostics", "execute", deployed["instance"]])
    artifact = json.loads(execution)
    expected_profile = binding["profile"].split("/", 1)[0]
    if artifact.get("schema") != "nq.diagnostic_execution.v2" or artifact.get("profile", {}).get("id") != expected_profile or str(artifact.get("profile", {}).get("version")) != "1" or artifact.get("profile", {}).get("digest") != binding["profile_digest"]:
        raise Refusal("NQ returned a different diagnostic profile")
    if artifact.get("question", {}).get("digest") != binding["question_digest"] or artifact.get("threshold_policy", {}).get("digest") != binding["threshold_policy_digest"] or artifact.get("vantage", {}).get("digest") != binding["vantage_digest"]:
        raise Refusal("NQ question, policy, or vantage does not match the exact handoff")
    if artifact.get("vantage", {}).get("version") != deployed["admission_id"]:
        raise Refusal("NQ artifact does not use the exact pre-admitted watcher")
    if artifact.get("subject", {}).get("id") != handoff["profile"]["subject"] or artifact.get("subject", {}).get("scope", {}).get("digest") != binding["scope"]:
        raise Refusal("NQ artifact does not bind the compiled subject and scope")
    artifact_id = sha(artifact.get("artifact_id"), "artifact_id")
    exported = command([*nq, "diagnostics", "export", artifact_id])
    if exported != execution:
        raise Refusal("NQ exported bytes differ from the execution artifact")
    qualification = command([*nq, "diagnostics", "qualify", artifact_id], limit=512 * 1024)
    atomic(occurrence / f"{stem}.nq.json", execution)
    atomic(occurrence / f"{stem}.qualification.json", qualification)
    return {"node_id": binding["node_id"], "profile": binding["profile"], "artifact_id": artifact_id, "outcome": artifact.get("outcome"), "standing_receipt": admission_value["receipt"]["digest"]}


def work(args: argparse.Namespace) -> None:
    occurrence = args.occurrence
    lock = occurrence / "worker.lock"
    try:
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        os.close(fd)
    except FileExistsError as error:
        raise Refusal("worker occurrence already started; reconcile instead of reacquiring") from error
    handoff = read_json(occurrence / "handoff.json", 128 * 1024)
    config = read_json(args.config)
    validate_handoff(handoff)
    validate_config(config, handoff)
    state = read_json(occurrence / "state.json")
    state.update(state="running", updated_at=now(), next_action="consume exact Standing mandate")
    atomic(occurrence / "state.json", state)
    findings = []
    try:
        for binding in handoff["profile"]["diagnostics"]:
            state.update(state="acquiring", updated_at=now(), active_node_id=binding["node_id"], next_action="record exact NQ artifact or mark indeterminate")
            atomic(occurrence / "state.json", state)
            findings.append(acquire(handoff, config, binding, state["run_id"], occurrence))
        record = {"schema": RECORD_SCHEMA, "investigation_id": handoff["investigation_id"], "handoff_digest": handoff["handoff_digest"], "plan_digest": handoff["plan_digest"], "run_id": state["run_id"], "completed_at": now(), "findings": findings, "aggregate_verdict": None, "nonclaims": ["whole_service_health", "causal_diagnosis", "remediation_authority", "continuity_reliance"]}
        atomic(occurrence / "record.json", record)
        state.update(state="completed", updated_at=now(), active_node_id=None, next_action="inspect accountable investigation record")
        atomic(occurrence / "state.json", state)
    except Exception as error:
        state.update(state="indeterminate", updated_at=now(), next_action="reconcile recorded owner artifacts; do not reacquire", error=str(error))
        atomic(occurrence / "state.json", state)
        raise


def status(args: argparse.Namespace) -> None:
    state = read_json(args.occurrence / "state.json")
    result = {"schema": "nightshift.service-investigation-projection/v1", "state": state, "submission": read_json(args.occurrence / "submission.json") if (args.occurrence / "submission.json").exists() else None, "record": read_json(args.occurrence / "record.json") if (args.occurrence / "record.json").exists() else None}
    sys.stdout.buffer.write(canonical(result) + b"\n")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    submit_parser = commands.add_parser("submit")
    submit_parser.add_argument("--config", type=pathlib.Path, required=True)
    submit_parser.add_argument("--handoff", type=pathlib.Path, required=True)
    submit_parser.add_argument("--launcher", type=pathlib.Path, default=pathlib.Path("/usr/bin/systemd-run"))
    work_parser = commands.add_parser("work")
    work_parser.add_argument("--config", type=pathlib.Path, required=True)
    work_parser.add_argument("--occurrence", type=pathlib.Path, required=True)
    status_parser = commands.add_parser("status")
    status_parser.add_argument("--occurrence", type=pathlib.Path, required=True)
    return result


def main() -> None:
    args = parser().parse_args()
    try:
        {"submit": submit, "work": work, "status": status}[args.command](args)
    except Exception as error:
        print(f"nightshift service investigation refused: {error}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()

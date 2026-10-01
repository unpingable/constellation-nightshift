from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
DRIVER = ROOT / "tools" / "nightshift_service_investigation.py"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def executable(path, source):
    path.write_text(source)
    os.chmod(path, 0o700)
    return path


def fixture(tmp_path, admit=True):
    subject = "sha256:" + "a" * 64
    specs = []
    for node, profile, character, scope_id, vantage in (
        ("pn_systemd", "nq.systemd_unit/v1", "c", "nq.scope.systemd_unit", "target"),
        ("pn_http", "nq.http_endpoint/v1", "e", "nq.scope.http_endpoint", "controller"),
    ):
        scope = {"digest": "sha256:" + character * 64, "id": scope_id, "version": "1"}
        artifact = {
            "schema": "nq.diagnostic_execution.v2",
            "artifact_id": "sha256:" + character * 64,
            "profile": {"id": profile.split("/")[0], "version": "1", "digest": "sha256:" + "f" * 64},
            "question": {"digest": "sha256:" + "6" * 64},
            "threshold_policy": {"digest": "sha256:" + "7" * 64},
            "vantage": {"version": f"admission-{node}", "digest": "sha256:" + "9" * 64},
            "subject": {"id": subject, "scope": scope},
            "outcome": {"condition": "present" if node == "pn_systemd" else "unresolved"},
        }
        artifact_path = tmp_path / f"{node}.artifact"
        artifact_path.write_bytes(canonical(artifact))
        marker = tmp_path / f"{node}.calls"
        nq = executable(
            tmp_path / f"{node}.nq",
            "#!/usr/bin/env python3\nimport argparse,pathlib,sys\np=argparse.ArgumentParser(); p.add_argument('--artifact'); p.add_argument('--marker'); p.add_argument('words',nargs='+'); a=p.parse_args(); m=pathlib.Path(a.marker); m.write_text(m.read_text()+'x' if m.exists() else 'x'); raw=pathlib.Path(a.artifact).read_bytes(); sys.stdout.buffer.write(b'{}' if a.words[:2]==['diagnostics','qualify'] else raw if a.words[:2] in (['diagnostics','execute'],['diagnostics','export']) else b'')\n",
        )
        specs.append({
            "node_id": node, "profile": profile, "scope": scope["digest"],
            "config_digest": "sha256:" + character * 64, "instance": node,
            "profile_digest": "sha256:" + "f" * 64, "question_digest": "sha256:" + "6" * 64,
            "threshold_policy_digest": "sha256:" + "7" * 64, "vantage_digest": "sha256:" + "9" * 64,
            "vantage": vantage, "nq": [sys.executable, str(nq), "--artifact", str(artifact_path), "--marker", str(marker)],
        })
    profile = {
        "schema": "maude.service-investigation-profile/v1", "profile_id": "service-posture",
        "audience": "nightshift.service-investigation/v1", "subject_label": "fixed HTTP service",
        "subject": subject, "diagnostics": [{k: v for k, v in item.items() if k != "nq"} for item in specs],
    }
    unsigned = {
        "schema": "maude.service-investigation-handoff/v1", "investigation_id": "sha256:" + "1" * 64,
        "draft_id": "draft_service", "revision_id": "revision_fixture", "plan_digest": "sha256:" + "2" * 64,
        "profile": profile,
    }
    handoff = tmp_path / "handoff.json"
    handoff.write_bytes(canonical({**unsigned, "handoff_digest": digest(canonical(unsigned))}))
    signer = executable(tmp_path / "signer", "#!/usr/bin/env python3\nimport json,sys\nb=json.load(sys.stdin); print(json.dumps({'body':b,'signature':'fixture'}))\n")
    if admit:
        admit_source = "#!/usr/bin/env python3\nimport json,sys\njson.load(sys.stdin); print(json.dumps({'schema':'standing.service-diagnostic-admission-result/v1','receipt':{'digest':'sha256:" + "8" * 64 + "'},'provider_invoked':False}))\n"
    else:
        admit_source = "#!/usr/bin/env python3\nimport sys\nsys.stdout.write('mandate refused');sys.exit(1)\n"
    admitter = executable(tmp_path / "admitter", admit_source)
    operator_key = tmp_path / "operator.pub"
    operator_key.write_text("00" * 32)
    deployed = {}
    for index, item in enumerate(specs):
        enrollment = tmp_path / f"enrollment-{index}.json"
        enrollment.write_text(json.dumps({"body": {"grant_id": f"00000000-0000-4000-8000-00000000000{index}", "operator": "operator:fixture", "workload": "workload:nightshift"}, "signature": "fixture"}))
        secret = tmp_path / f"workload-{index}.key"
        secret.write_text("11" * 32)
        store = tmp_path / f"standing-{index}.sqlite"
        store.touch()
        deployed[item["profile"]] = {
            "standing_store": str(store), "enrollment": str(enrollment), "workload_secret_key": str(secret),
            "nq_command": item["nq"], "config_digest": item["config_digest"], "instance": item["instance"],
            "profile_digest": item["profile_digest"], "question_digest": item["question_digest"],
            "threshold_policy_digest": item["threshold_policy_digest"], "vantage_digest": item["vantage_digest"],
            "admission_id": f"admission-{item['node_id']}",
        }
    config = tmp_path / "config.json"
    config.write_bytes(canonical({
        "schema": "nightshift.service-investigation-config/v1", "artifact_root": str(tmp_path / "artifacts"),
        "standing_signer": str(signer), "standing_admitter": str(admitter),
        "operator_public_key": str(operator_key), "execution_identity": "workload:nightshift-fixture",
        "source_revisions": {"maude": "maude-fixture", "nightshift": "nightshift-fixture", "nq": "nq-fixture", "standing": "standing-fixture"},
        "bindings": deployed,
    }))
    launcher = executable(
        tmp_path / "launcher",
        "#!/usr/bin/env python3\nimport pathlib,subprocess,sys\ni=next(i for i,v in enumerate(sys.argv) if v.endswith('nightshift_service_investigation.py')); r=subprocess.run(sys.argv[i:]); pathlib.Path(sys.argv[0]+'.result').write_text(str(r.returncode)); sys.exit(0)\n",
    )
    return handoff, config, launcher, specs


def invoke(handoff, config, launcher):
    return subprocess.run(
        [sys.executable, str(DRIVER), "submit", "--config", str(config), "--handoff", str(handoff), "--launcher", str(launcher)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )


def test_completed_record_preserves_independent_findings_and_replay(tmp_path):
    handoff, config, launcher, specs = fixture(tmp_path)
    first = invoke(handoff, config, launcher)
    assert first.returncode == 0, first.stderr.decode()
    receipt = json.loads(first.stdout)
    occurrence = pathlib.Path(json.loads(config.read_bytes())["artifact_root"]) / receipt["investigation_id"][7:]
    record = json.loads((occurrence / "record.json").read_bytes())
    state = json.loads((occurrence / "state.json").read_bytes())
    assert record["aggregate_verdict"] is None
    assert state["unit"].startswith("nightshift-service-investigation-")
    assert state["source_revisions"]["standing"] == "standing-fixture"
    assert state["expected_terminal_record"] == str(occurrence / "record.json")
    assert (occurrence / "launcher.json").exists()
    assert [item["outcome"]["condition"] for item in record["findings"]] == ["present", "unresolved"]
    second = invoke(handoff, config, launcher)
    assert second.returncode == 0 and second.stdout == first.stdout
    assert all((tmp_path / f"{item['node_id']}.calls").read_text() == "xxx" for item in specs)


def test_standing_refusal_precedes_every_nq_acquisition(tmp_path):
    handoff, config, launcher, specs = fixture(tmp_path, admit=False)
    submitted = invoke(handoff, config, launcher)
    assert submitted.returncode == 0
    receipt = json.loads(submitted.stdout)
    occurrence = pathlib.Path(json.loads(config.read_bytes())["artifact_root"]) / receipt["investigation_id"][7:]
    state = json.loads((occurrence / "state.json").read_bytes())
    assert state["state"] == "indeterminate" and "mandate refused" in state["error"]
    assert not any((tmp_path / f"{item['node_id']}.calls").exists() for item in specs)
    assert invoke(handoff, config, launcher).stdout == submitted.stdout


def test_missing_or_disagreeing_owner_binding_refuses_before_launch(tmp_path):
    handoff, config, launcher, _ = fixture(tmp_path)
    value = json.loads(config.read_bytes())
    value["bindings"]["nq.systemd_unit/v1"]["vantage_digest"] = "sha256:" + "0" * 64
    config.write_bytes(canonical(value))
    refused = invoke(handoff, config, launcher)
    assert refused.returncode == 1
    assert b"vantage_digest does not match" in refused.stderr
    assert not pathlib.Path(str(launcher) + ".result").exists()


def test_rotated_watcher_is_retained_as_indeterminate_after_standing(tmp_path):
    handoff, config, launcher, specs = fixture(tmp_path)
    artifact_path = tmp_path / "pn_systemd.artifact"
    artifact = json.loads(artifact_path.read_bytes())
    artifact["vantage"]["version"] = "replacement-admission"
    artifact_path.write_bytes(canonical(artifact))
    submitted = invoke(handoff, config, launcher)
    assert submitted.returncode == 0
    receipt = json.loads(submitted.stdout)
    occurrence = pathlib.Path(json.loads(config.read_bytes())["artifact_root"]) / receipt["investigation_id"][7:]
    state = json.loads((occurrence / "state.json").read_bytes())
    assert state["state"] == "indeterminate"
    assert "exact pre-admitted watcher" in state["error"]
    assert (occurrence / "pn_systemd.standing.json").exists()
    assert (tmp_path / f"{specs[0]['node_id']}.calls").read_text() == "x"
    assert not (tmp_path / f"{specs[1]['node_id']}.calls").exists()

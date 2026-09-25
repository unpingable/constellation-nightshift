#!/usr/bin/python3
"""Clean Debian 12 gate for the Nightshift and Pulse-support release tarballs.

Runs inside the guest as root. It installs only from the uploaded artifacts,
runs every role case as the unprivileged system account `constellation`, and
prints one JSON document with a verdict per case. Inputs are synthetic.
"""

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile

ACCOUNT = "constellation"
PREFIX = pathlib.Path("/opt/constellation")
WORK = pathlib.Path("/var/lib/constellation-gate")
NIGHTSHIFT_BINARIES = ("nightshift", "nightshift-foreman", "nightshift-observation-resolver")
PULSE_BINARY = "pulse-nq-load-support"
RESULTS = []


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def sha256_file(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def run(argv, *, user=ACCOUNT, stdin=None, env=None):
    command = list(argv)
    if user is not None:
        command = ["runuser", "-u", user, "--", "/usr/bin/env", "-i",
                   "PATH=/usr/bin:/bin", "LANG=C.UTF-8"] + [f"{k}={v}" for k, v in (env or {}).items()] + command
    result = subprocess.run(command, input=stdin, capture_output=True, check=False)
    return result.returncode, result.stdout.decode(errors="replace"), result.stderr.decode(errors="replace")


def case(case_id, title):
    def wrap(function):
        def inner(*args):
            record = {"case": case_id, "title": title}
            try:
                detail = function(*args)
                record["verdict"] = "PASS"
                if detail is not None:
                    record["detail"] = detail
            except AssertionError as error:
                record["verdict"] = "FAIL"
                record["detail"] = str(error)[:4000]
            except Exception as error:  # noqa: BLE001 - record and continue
                record["verdict"] = "ERROR"
                record["detail"] = f"{type(error).__name__}: {error}"[:4000]
            RESULTS.append(record)
            return record["verdict"] == "PASS"
        return inner
    return wrap


def expect_ok(code, out, err, what):
    assert code == 0, f"{what}: exit {code}: {err.strip()[-1500:]}"
    return out


def expect_refused(code, out, err, needle, what):
    assert code != 0, f"{what}: expected refusal, exit 0: {out[-800:]}"
    assert needle in err, f"{what}: refusal lacks {needle!r}: {err.strip()[-1500:]}"
    return err.strip().splitlines()[-1] if err.strip() else ""


class Gate:
    def __init__(self, args):
        self.args = args
        self.inputs = pathlib.Path(args.inputs)
        self.commit = args.source_commit
        self.bin = {}
        self.run_id = None

    # ---------------------------------------------------------------- install
    @case("I01", "artifacts verify against SHA256SUMS; no source tree, toolchain or campaign path on the guest")
    def i01(self):
        for component in ("nightshift", "pulse"):
            directory = self.inputs / component
            result = subprocess.run(["sha256sum", "--check", "--strict", "SHA256SUMS"], cwd=directory,
                                    capture_output=True, text=True, check=False)
            assert result.returncode == 0, f"{component}: {result.stdout}{result.stderr}"
        absent = {tool: shutil.which(tool) for tool in ("cargo", "rustc", "git")}
        assert not any(absent.values()), f"toolchain present: {absent}"
        assert not pathlib.Path("/data/git").exists(), "/data/git exists on guest"
        return {"toolchain_absent": sorted(absent)}

    @case("I02", "install tarballs under /opt/constellation as root-owned read-only trees; create system account")
    def i02(self):
        subprocess.run(["useradd", "--system", "--home-dir", str(WORK), "--shell", "/usr/sbin/nologin", ACCOUNT],
                       check=True)
        for component in ("nightshift", "pulse"):
            directory = self.inputs / component
            tarballs = sorted(directory.glob("*.tar.gz"))
            assert len(tarballs) == 1, tarballs
            destination = PREFIX / component
            destination.mkdir(parents=True)
            with tarfile.open(tarballs[0]) as archive:
                members = archive.getmembers()
                top = {m.name.split("/")[0] for m in members}
                assert len(top) == 1, top
                for member in members:
                    assert member.uid == 0 and member.gid == 0, member.name
                    assert not member.issym() and not member.islnk(), member.name
                    assert not member.name.startswith("/") and ".." not in member.name.split("/"), member.name
                    assert member.isfile() or member.isdir(), member.name
                # Debian 12's Python 3.11.2 predates extraction filters; members were checked above.
                archive.extractall(destination.parent / "staging")
            staged = destination.parent / "staging" / top.pop()
            for child in staged.iterdir():
                shutil.move(str(child), destination / child.name)
            shutil.rmtree(destination.parent / "staging")
            subprocess.run(["chown", "-R", "root:root", str(destination)], check=True)
            subprocess.run(["chmod", "-R", "go-w", str(destination)], check=True)
        for name in NIGHTSHIFT_BINARIES:
            self.bin[name] = str(PREFIX / "nightshift/bin" / name)
        self.bin[PULSE_BINARY] = str(PREFIX / "pulse/bin" / PULSE_BINARY)
        WORK.mkdir(mode=0o750, exist_ok=True)
        shutil.chown(WORK, ACCOUNT, ACCOUNT)
        for name, path in self.bin.items():
            mode = os.stat(path).st_mode & 0o7777
            assert mode == 0o755, f"{name} mode {oct(mode)}"
        return {name: sha256_file(path) for name, path in sorted(self.bin.items())}

    @case("I03", "installed binaries equal BUILD-INFO.json and the build receipt; dynamic deps resolve on Debian 12")
    def i03(self):
        detail = {}
        for component in ("nightshift", "pulse"):
            info = json.loads((PREFIX / component / "BUILD-INFO.json").read_text())
            receipt = json.loads((self.inputs / component / "build-receipt.v1.json").read_text())
            assert info["source_commit"] == self.commit, info
            assert receipt["source"]["head"] == self.commit
            assert receipt["reproduction"]["binary_bytes_equal"] and receipt["reproduction"]["artifact_bytes_equal"]
            for name, fact in info["binaries"].items():
                actual = sha256_file(PREFIX / component / fact["path"])
                assert actual == fact["sha256"] == receipt["binaries"][name]["sha256"], name
                ldd = subprocess.run(["ldd", str(PREFIX / component / fact["path"])], capture_output=True, text=True)
                assert "not found" not in ldd.stdout, ldd.stdout
                detail[name] = {"sha256": actual, "libraries": sorted(
                    line.split()[0] for line in ldd.stdout.splitlines() if line.strip())}
        return detail

    @case("I04", "no build-host path leaks into shipped binaries")
    def i04(self):
        leaks = {}
        for name, path in self.bin.items():
            data = pathlib.Path(path).read_bytes()
            for needle in (b"/data/git", b"/home/jbeck", b"/tmp/claude-1000", b".cargo/registry"):
                if needle in data:
                    leaks.setdefault(name, []).append(needle.decode())
        assert not leaks, leaks
        return "none of /data/git, /home/jbeck, /tmp/claude-1000, .cargo/registry"

    # --------------------------------------------------------------- identity
    @case("G01", "every binary answers --version with component, version and the full source commit")
    def g01(self):
        detail = {}
        for name, path in self.bin.items():
            out = expect_ok(*run([path, "--version"]), f"{name} --version").strip()
            assert out == f"{name} 0.1.0 ({self.commit})", out
            detail[name] = out
        return detail

    @case("G02", "every binary answers --build-info: release profile, component, version, source commit")
    def g02(self):
        detail = {}
        for name, path in self.bin.items():
            out = expect_ok(*run([path, "--build-info"]), f"{name} --build-info")
            info = json.loads(out)
            assert info["component"] == name, info
            assert info["version"] == "0.1.0", info
            assert info["source_commit"] == self.commit, info
            assert info["debug_assertions"] is False, info
            assert re.fullmatch(r"[a-z_.]+\.build_info\.v1", info["schema"]), info
            detail[name] = info
        return detail

    @case("G03", "--build-info with any other argument is not an identity query")
    def g03(self):
        code, out, err = run([self.bin["nightshift-foreman"], "--build-info", "extra"])
        assert code != 0 and not out.startswith("{"), (code, out, err)
        code, out, err = run([self.bin[PULSE_BINARY], "--build-info", "extra"])
        assert code != 0, (code, out)
        return "refused"

    # ---------------------------------------------------------------- Foreman
    def foreman(self, *arguments):
        return run([self.bin["nightshift-foreman"], *arguments])

    @case("F01", "provider-seal-inputs seals the five-body draft deterministically and binds digests")
    def f01(self):
        root = WORK / "foreman"
        root.mkdir(exist_ok=True)
        shutil.copy(self.inputs / "fixtures/foreman-provider-draft.json", root / "draft.json")
        shutil.chown(root, ACCOUNT, ACCOUNT)
        shutil.chown(root / "draft.json", ACCOUNT, ACCOUNT)
        out = expect_ok(*self.foreman("provider-seal-inputs", "--draft", str(root / "draft.json")), "seal")
        sealed = json.loads(out)
        assert canonical(sealed) == out.encode(), "sealed output is not canonical JSON"
        draft = json.loads((root / "draft.json").read_text())
        for body, field in (("packet", "packet_digest"), ("admission", "admission_digest"),
                            ("profile", "profile_digest"), ("policy", "policy_digest"),
                            ("requirement", "requirement_digest")):
            if field in draft[body]:
                assert sealed[body][field] == draft[body][field], (body, field)
        assert sealed["admission"]["packet_digest"] == sealed["packet"]["packet_digest"]
        assert sealed["requirement"]["admission_digest"] == sealed["admission"]["admission_digest"]
        second = expect_ok(*self.foreman("provider-seal-inputs", "--draft", str(root / "draft.json")), "seal again")
        assert second == out, "sealing is not deterministic"
        for body in ("packet", "admission", "profile", "policy", "requirement"):
            (root / f"{body}.json").write_bytes(canonical(sealed[body]))
            shutil.chown(root / f"{body}.json", ACCOUNT, ACCOUNT)
        self.sealed = sealed
        return {"packet_digest": sealed["packet"]["packet_digest"],
                "admission_digest": sealed["admission"]["admission_digest"],
                "admission_window": [sealed["admission"]["admitted_at"], sealed["admission"]["expires_at"]],
                "packet_window": [sealed["packet"]["created_at"], sealed["packet"]["current_until"]]}

    def admit_args(self, db, at):
        root = WORK / "foreman"
        return ["provider-admit", "--db", str(db), "--packet", str(root / "packet.json"),
                "--admission", str(root / "admission.json"), "--profile", str(root / "profile.json"),
                "--requirement", str(root / "requirement.json"), "--policy", str(root / "policy.json"),
                "--evaluated-at", at]

    @case("F02", "provider-admit admits the sealed run inside its window")
    def f02(self):
        out = expect_ok(*self.foreman(*self.admit_args(WORK / "foreman/foreman.sqlite", "2026-08-31T12:00:00Z")),
                        "admit")
        self.run_id = json.loads(out)["run_id"]
        assert self.run_id == self.sealed["admission"]["run_id"]
        return {"run_id": self.run_id}

    def prepare(self, item, ordinal, at):
        return self.foreman("provider-prepare", "--db", str(WORK / "foreman/foreman.sqlite"), "--run-id", self.run_id,
                            "--work-item", item, "--dispatch", f"dispatch-{item}-{ordinal}",
                            "--adapter-process", f"adapter-process-{item}-{ordinal}",
                            "--app-server-session", f"session-{item}-{ordinal}",
                            "--selected-model-ordinal", "0", "--recorded-at", at)

    def events(self):
        out = expect_ok(*self.foreman("events", "--db", str(WORK / "foreman/foreman.sqlite"), "--run-id",
                                      self.run_id), "events")
        return out

    @case("F03", "provider-prepare reserves one attempt and dispatch inside the admission window")
    def f03(self):
        out = expect_ok(*self.prepare("work-a", 1, "2026-08-31T12:01:00Z"), "prepare work-a")
        opened = json.loads(out)
        assert opened["dispatch"]["dispatch_ordinal"] == 1, opened["dispatch"]
        return {"dispatch_digest": opened["dispatch"]["dispatch_digest"]}

    @case("F04", "provider-prepare after admission expiry is refused (AuthorityNotCurrent) and records nothing")
    def f04(self):
        before = self.events()
        status_before = expect_ok(*self.foreman("status", "--db", str(WORK / "foreman/foreman.sqlite"),
                                                "--run-id", self.run_id), "status")
        refusal = expect_refused(*self.prepare("work-b", 1, "2026-08-31T13:00:01Z"),
                                 "retained authority not current: admission expired", "late prepare")
        assert self.events() == before, "events changed after refused prepare"
        status_after = expect_ok(*self.foreman("status", "--db", str(WORK / "foreman/foreman.sqlite"),
                                               "--run-id", self.run_id), "status")
        assert status_after == status_before, "status changed after refused prepare"
        return refusal

    @case("F05", "the same prepare inside the window still succeeds after the refusal")
    def f05(self):
        out = expect_ok(*self.prepare("work-b", 1, "2026-08-31T12:59:59Z"), "prepare work-b in window")
        return {"dispatch_ordinal": json.loads(out)["dispatch"]["dispatch_ordinal"]}

    @case("F06", "provider-admit after admission expiry is refused")
    def f06(self):
        return expect_refused(*self.foreman(*self.admit_args(WORK / "foreman/late.sqlite", "2026-08-31T13:00:01Z")),
                              "admission expired", "late admit")

    @case("F07", "provider-admit after packet expiry is refused on the packet window")
    def f07(self):
        return expect_refused(*self.foreman(*self.admit_args(WORK / "foreman/later.sqlite", "2026-08-31T14:00:01Z")),
                              "packet refused", "admit after packet expiry")

    @case("F08", "read-only status and events refuse an absent store without creating it")
    def f08(self):
        absent = WORK / "foreman/absent.sqlite"
        code, out, err = self.foreman("status", "--db", str(absent), "--run-id", "run-absent")
        assert code != 0 and not absent.exists(), (code, err)
        return err.strip().splitlines()[-1]

    @case("F09", "a mutating Foreman command refuses a store the account cannot write")
    def f09(self):
        root = WORK / "foreman-root-owned"
        root.mkdir()
        shutil.copy(WORK / "foreman/foreman.sqlite", root / "foreman.sqlite")
        os.chmod(root / "foreman.sqlite", 0o444)
        os.chmod(root, 0o755)
        code, out, err = run([self.bin["nightshift-foreman"], "provider-prepare", "--db", str(root / "foreman.sqlite"),
                              "--run-id", self.run_id, "--work-item", "work-b", "--dispatch", "d", "--adapter-process",
                              "a", "--app-server-session", "s", "--selected-model-ordinal", "0",
                              "--recorded-at", "2026-08-31T12:30:00Z"])
        assert code != 0, (code, out)
        return err.strip().splitlines()[-1] if err.strip() else ""

    # ------------------------------------------------------------- Nightshift
    def nightshift(self, store, *arguments):
        return run([self.bin["nightshift"], "--store", str(store), *arguments])

    @case("N01", "packet validate accepts the sealed packet inside its window and refuses after it")
    def n01(self):
        packet = WORK / "foreman/packet.json"
        ok = expect_ok(*self.nightshift(WORK / "unused.sqlite", "packet", "validate", "--packet", str(packet),
                                        "--evaluated-at", "2026-08-31T12:30:00Z"), "validate")
        receipt = json.loads(ok)
        assert receipt["authority_effect"] == "NONE", receipt
        code, out, err = self.nightshift(WORK / "unused.sqlite", "packet", "validate", "--packet", str(packet),
                                         "--evaluated-at", "2026-08-31T14:00:01Z")
        assert code != 0, (code, out)
        render = expect_ok(*self.nightshift(WORK / "unused.sqlite", "packet", "render", "--packet", str(packet)),
                           "render")
        assert render.strip(), "empty render"
        return {"disposition": receipt["disposition"], "late_refusal": err.strip().splitlines()[-1]}

    def synthetic_store(self, name):
        root = WORK / "nightshift"
        root.mkdir(exist_ok=True)
        shutil.chown(root, ACCOUNT, ACCOUNT)
        target = root / name
        shutil.copy(self.inputs / "fixtures/nightshift-synthetic.sqlite", target)
        shutil.chown(target, ACCOUNT, ACCOUNT)
        return target

    @case("N02", "status inspection: cycle list/show over the synthetic Maude-handoff occurrence")
    def n02(self):
        expected = json.loads((self.inputs / "fixtures/nightshift-synthetic.sqlite.expected.json").read_text())
        store = self.synthetic_store("status.sqlite")
        listing = json.loads(expect_ok(*self.nightshift(store, "cycle", "list"), "cycle list"))
        cycles = listing if isinstance(listing, list) else listing.get("cycles", listing)
        text = json.dumps(listing)
        assert expected["cycle_id"] in text, "cycle id absent from list"
        shown = json.loads(expect_ok(*self.nightshift(store, "cycle", "show", "--cycle-id", expected["cycle_id"]),
                                     "cycle show"))
        assert shown["state_digest"] == expected["state_digest"], shown.get("state_digest")
        assert shown["status"] == expected["status"], shown.get("status")
        return {"cycle_id": expected["cycle_id"], "status": shown["status"], "count": len(cycles)}

    @case("N03", "authoring-context export binds the synthetic Maude handoff to the governed occurrence")
    def n03(self):
        expected = json.loads((self.inputs / "fixtures/nightshift-synthetic.sqlite.expected.json").read_text())
        store = self.synthetic_store("authoring.sqlite")
        out = expect_ok(*self.nightshift(store, "cycle", "export-authoring-context", "--campaign-id",
                                         expected["campaign_id"], "--occurrence-id", expected["occurrence_id"]),
                        "export authoring context")
        export = json.loads(out)
        assert export["matches"] == [expected["authoring_provenance"]], export
        by_maude = json.loads(expect_ok(*self.nightshift(store, "cycle", "export-authoring-context", "--plan-ref",
                                                         expected["maude_plan_ref"], "--maude-session-id",
                                                         expected["maude_session_id"]), "by maude"))
        assert by_maude["matches"] == export["matches"]
        return {"provenance_id": expected["authoring_provenance"]["provenance_id"]}

    @case("L01", "lineage reader returns the exact precompiled workflow lineage for the occurrence")
    def l01(self):
        expected = json.loads((self.inputs / "fixtures/nightshift-synthetic.sqlite.expected.json").read_text())
        store = self.synthetic_store("lineage.sqlite")
        before = sha256_file(store)
        out = expect_ok(*self.nightshift(store, "cycle", "export-precompiled-workflow-lineage", "--campaign-id",
                                         expected["campaign_id"], "--occurrence-id", expected["occurrence_id"]),
                        "lineage export")
        assert json.loads(out) == expected["lineage_export"], out
        assert sha256_file(store) == before, "read-only export changed the store"
        return {"lineage_id": expected["lineage_export"]["matches"][0]["lineage_id"],
                "plan_document_ref": expected["lineage_export"]["matches"][0]["plan_document_ref"]}

    @case("L02", "lineage reader returns an empty match set for an unrelated occurrence")
    def l02(self):
        expected = json.loads((self.inputs / "fixtures/nightshift-synthetic.sqlite.expected.json").read_text())
        store = self.synthetic_store("lineage-empty.sqlite")
        out = json.loads(expect_ok(*self.nightshift(store, "cycle", "export-precompiled-workflow-lineage",
                                                    "--campaign-id", expected["campaign_id"], "--occurrence-id",
                                                    "00000000-0000-4000-8000-000000000999"), "empty lineage"))
        assert out["matches"] == [], out
        return "empty"

    @case("L03", "lineage reader refuses a store whose retained plan relation was substituted")
    def l03(self):
        expected = json.loads((self.inputs / "fixtures/nightshift-synthetic.sqlite.expected.json").read_text())
        store = self.synthetic_store("lineage-tampered.sqlite")
        original = expected["lineage_export"]["matches"][0]["plan_document_ref"]
        replacement = "sha256:" + "8" * 64
        connection = sqlite3.connect(store)
        changed = connection.execute(
            "UPDATE canonical_observation_cycles SET snapshot_json = replace(snapshot_json, ?, ?)",
            (original, replacement)).rowcount
        connection.commit()
        connection.close()
        assert changed == 1, changed
        code, out, err = self.nightshift(store, "cycle", "export-precompiled-workflow-lineage", "--campaign-id",
                                         expected["campaign_id"], "--occurrence-id", expected["occurrence_id"])
        assert code != 0, f"tampered store was accepted: {out[:600]}"
        assert replacement not in out
        return err.strip().splitlines()[-1]

    @case("L04", "lineage reader refuses malformed identities")
    def l04(self):
        store = self.synthetic_store("lineage-malformed.sqlite")
        code, out, err = self.nightshift(store, "cycle", "export-precompiled-workflow-lineage", "--campaign-id",
                                         "not-a-digest", "--occurrence-id", "x")
        assert code != 0, out
        return err.strip().splitlines()[-1]

    @case("N04", "cycle run-config refuses a sealed request without a reviewed plan binding before any port runs")
    def n04(self):
        root = WORK / "nightshift"
        request = root / "base-request.json"
        shutil.copy(self.inputs / "fixtures/nightshift-synthetic.sqlite.base-request.json", request)
        shutil.chown(request, ACCOUNT, ACCOUNT)
        config = root / "missing-config.json"
        store = root / "run-config.sqlite"
        code, out, err = self.nightshift(store, "cycle", "run-config", "--config", str(config), "--request",
                                         str(request))
        assert code != 0, out
        assert "reviewed plan binding" in err, err
        assert not store.exists(), "refused run-config created a store"
        return err.strip().splitlines()[-1]

    @case("N05", "observation resolver refuses a malformed request and leaves the store unchanged")
    def n05(self):
        store = self.synthetic_store("resolver.sqlite")
        before = sha256_file(store)
        code, out, err = run([self.bin["nightshift-observation-resolver"], "--store", str(store), "--resolver-id",
                              "nightshift-observation-resolver/v1", "--default-ttl-ms", "300000"],
                             stdin=b"{\"schema\":\"not-a-request\"}")
        assert code != 0, out
        assert sha256_file(store) == before
        return err.strip().splitlines()[-1]

    # ------------------------------------------------------------------ Pulse
    def pulse_setup(self):
        root = WORK / "pulse"
        for sub in ("", "outgoing", "receipts"):
            (root / sub).mkdir(exist_ok=True)
            shutil.chown(root / sub, ACCOUNT, ACCOUNT)
        shutil.copy(self.inputs / "fixtures/pulse-config.json", root / "config.json")
        shutil.copy(self.inputs / "fixtures/pulse-producer-key.hex", root / "producer-key.hex")
        for name in ("config.json", "producer-key.hex"):
            shutil.chown(root / name, ACCOUNT, ACCOUNT)
        os.chmod(root / "producer-key.hex", 0o600)
        return root

    @case("P01", "Pulse produce writes one signed envelope; ingest retains one receipt")
    def p01(self):
        root = self.pulse_setup()
        binary = self.bin[PULSE_BINARY]
        produced = expect_ok(*run([binary, "produce", "--config", str(root / "config.json"), "--acquisition-id",
                                   "support:gate-1"]), "produce").strip()
        assert len(list((root / "outgoing").iterdir())) == 1
        assert len(list((root / "receipts").iterdir())) == 0
        ingested = expect_ok(*run([binary, "ingest", "--config", str(root / "config.json"), "--acquisition-id",
                                   "support:gate-1"]), "ingest").strip()
        assert len(list((root / "receipts").iterdir())) == 1
        self.produced = produced
        return {"produce": produced, "ingest": ingested}

    @case("P02", "Pulse refuses a relative config path and an unknown role; a replayed acquisition converges")
    def p02(self):
        root = WORK / "pulse"
        binary = self.bin[PULSE_BINARY]
        first = expect_refused(*run([binary, "produce", "--config", "config.json", "--acquisition-id", "support:x"]),
                               "absolute", "relative config")
        second = expect_refused(*run([binary, "delete", "--config", str(root / "config.json"), "--acquisition-id",
                                      "support:x"]), "only the closed produce and ingest roles exist", "role")
        replay = expect_ok(*run([binary, "produce", "--config", str(root / "config.json"), "--acquisition-id",
                                 "support:gate-1"]), "replayed produce").strip()
        assert replay == self.produced, "replayed acquisition minted a different envelope"
        assert len(list((root / "outgoing").iterdir())) == 1
        return [first, second, f"replay converged on {replay}"]

    @case("P03", "shipped sealer builds a closed resolver launcher under /usr/bin/python3.11; resolver answers a query")
    def p03(self):
        root = WORK / "pulse"
        python = pathlib.Path("/usr/bin/python3.11").resolve(strict=True)
        resolver = pathlib.Path(self.bin[PULSE_BINARY]).resolve(strict=True)
        config = root / "config.json"
        enrollment = {
            "schema": "pulse.nq_host_load_pressure.closed_resolver_launcher_enrollment.v1",
            "resolver_program": str(resolver),
            "resolver_sha256": "sha256:" + sha256_file(resolver),
            "config_path": str(config),
            "config_sha256": "sha256:" + sha256_file(config),
            "python_interpreter": str(python),
            "python_sha256": "sha256:" + sha256_file(python),
        }
        (root / "enrollment.json").write_bytes(canonical(enrollment))
        shutil.chown(root / "enrollment.json", ACCOUNT, ACCOUNT)
        sealer = PREFIX / "pulse/share/pulse-nq-load-support/seal-pulse-support-resolver-launcher.py"
        expect_ok(*run([str(python), "-I", str(sealer), "--enrollment", str(root / "enrollment.json"),
                        "--launcher", str(root / "pulse-support-resolver"), "--manifest",
                        str(root / "launcher-manifest.json")]), "seal launcher")
        configuration = json.loads(config.read_text())
        query = {
            "schema": "nightshift.present_evidence_query.v1",
            "query_id": "",
            "observation_cycle_id": "cycle:gate",
            "request_nonce": "support-query:gate",
            "observation_id": "sha256:" + "11" * 32,
            "diagnostic_inputs_id": configuration["expected_diagnostic"]["diagnostic_inputs_id"],
            "subject_id": configuration["subject_id"],
            "scope_id": configuration["scope_id"],
            "artifact_ids": configuration["expected_diagnostic"]["artifact_ids"],
        }
        preimage = dict(query)
        del preimage["query_id"]
        query["query_id"] = "sha256:" + hashlib.sha256(canonical(preimage)).hexdigest()
        receipts_before = sorted(p.name for p in (root / "receipts").iterdir())
        out = expect_ok(*run([str(root / "pulse-support-resolver")], stdin=canonical(query)), "resolve")
        support = json.loads(out)
        assert support["schema"] == "nightshift.qualified_support.v1", support
        assert support["query_id"] == query["query_id"]
        assert support["standing"] in ("current", "contradictory", "Current", "Contradictory"), support["standing"]
        assert sorted(p.name for p in (root / "receipts").iterdir()) == receipts_before
        self.query = query
        return {"standing": support["standing"], "evidence_refs": len(support.get("evidence_refs", [])),
                "contradiction_refs": len(support.get("contradiction_refs", [])),
                "python": str(python)}

    @case("P04", "closed launcher refuses arguments and a config changed after sealing")
    def p04(self):
        root = WORK / "pulse"
        launcher = str(root / "pulse-support-resolver")
        code, out, err = run([launcher, "extra"], stdin=canonical(self.query))
        assert code != 0, out
        first = err.strip().splitlines()[-1] if err.strip() else f"exit {code}"
        original = (root / "config.json").read_bytes()
        (root / "config.json").write_bytes(original.replace(b"load-pressure-v1", b"load-pressure-v2", 1))
        code, out, err = run([launcher], stdin=canonical(self.query))
        (root / "config.json").write_bytes(original)
        assert code != 0, f"changed config accepted: {out[:400]}"
        return [first, err.strip().splitlines()[-1] if err.strip() else f"exit {code}"]

    @case("P05", "resolver role refuses without its config, and sealed mode refuses a plain pathname")
    def p05(self):
        root = WORK / "pulse"
        (root / "direct").mkdir()
        link = root / "direct" / "pulse-support-resolver"
        os.symlink(self.bin[PULSE_BINARY], link)
        code, out, err = run([str(link)], stdin=canonical(self.query))
        assert code != 0, out
        assert "PULSE_LOAD_SUPPORT_CONFIG is required" in err, err
        code2, out2, err2 = run([str(link)], stdin=canonical(self.query),
                                env={"PULSE_LOAD_SUPPORT_CONFIG": str(root / "config.json"),
                                     "PULSE_LOAD_SUPPORT_CONFIG_SHA256": "sha256:" + sha256_file(root / "config.json")})
        assert code2 != 0, f"sealed-mode digest over a plain path was accepted: {out2[:300]}"
        assert "/proc/self/fd" in err2, err2
        return [err.strip().splitlines()[-1], err2.strip().splitlines()[-1] if err2.strip() else f"exit {code2}"]

    def run_all(self):
        order = [self.i01, self.i02, self.i03, self.i04, self.g01, self.g02, self.g03,
                 self.f01, self.f02, self.f03, self.f04, self.f05, self.f06, self.f07, self.f08, self.f09,
                 self.n01, self.n02, self.n03, self.l01, self.l02, self.l03, self.l04, self.n04, self.n05,
                 self.p01, self.p02, self.p03, self.p04, self.p05]
        for index, step in enumerate(order):
            ok = step()
            if not ok and index < 3:
                break


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", required=True)
    parser.add_argument("--source-commit", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        print("gate must run as root", file=sys.stderr)
        return 2
    Gate(args).run_all()
    summary = {
        "schema": "constellation.alpha_exit.nightshift_vm_gate_result.v1",
        "source_commit": args.source_commit,
        "os_release": pathlib.Path("/etc/os-release").read_text(),
        "kernel": os.uname().release,
        "python": sys.version,
        "cases": RESULTS,
        "passed": sum(1 for r in RESULTS if r["verdict"] == "PASS"),
        "failed": sum(1 for r in RESULTS if r["verdict"] != "PASS"),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

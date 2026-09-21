# SPDX-License-Identifier: Apache-2.0
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "deploy/systemd/nightshift-saved-check-tick"
SPEC = importlib.util.spec_from_loader("saved_tick", SourceFileLoader("saved_tick", str(SCRIPT)))
TICK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TICK)


def digest(path):
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_bytes(TICK.canonical(value) + b"\n")


class SavedCheckTickTests(unittest.TestCase):
    def test_utc_now_preserves_subsecond_ordering(self):
        class FixedDateTime(dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return cls(2026, 9, 21, 1, 37, 57, 600_123, tzinfo=tz)

        with mock.patch.object(TICK.dt, "datetime", FixedDateTime):
            self.assertEqual(TICK.utc_now(), "2026-09-21T01:37:57.600123Z")

    def fixture(self, root: Path, *, terminal=True, local=True, selection="due",
                event_until="2099-01-01T00:00:00Z"):
        calls = root / "calls"
        calls.mkdir()
        nightshift = root / "nightshift"
        nightshift.write_text("""#!/usr/bin/env python3
import json,sys,pathlib
p=pathlib.Path(%r); args=sys.argv[1:]
(p/(str(len(list(p.iterdir())))+'.json')).write_text(json.dumps(args))
if 'schedule' in args:
 selected=%r
 value={'schema':'nightshift.saved-check-selection/v1','selection':selected,'request':None}
 if selected == 'due': value['request']={'evaluation_id':'sha256:'+'1'*64,'slot':{'slot_id':'sha256:'+'2'*64}}
 print(json.dumps(value))
elif 'attention-evaluate' in args:
 print(json.dumps({'schema':'nightshift.saved-check-attention-replay-bundle/v1','receipt':{'evaluation_id':'sha256:'+'1'*64,'receipt_digest':'sha256:'+'3'*64,'policy_id':'p','policy_digest':'sha256:'+'4'*64,'maintenance':{'state':'covered'},'delivery_eligible':True,'event_current_until':%r,'disposition':'ATTENTION_REQUIRED','reason':'SAVED_CHECK_FAILED_COVERED','inspection_reference':'saved-check:sha256:'+'1'*64}}))
else:
 print(json.dumps({'evaluation_id':'sha256:'+'1'*64,'state':%r}))
""" % (str(calls), selection, event_until, "terminal" if terminal else "nq_started"), encoding="utf-8")
        nightshift.chmod(0o755)
        nq = root / "nq"
        nq.write_text("""#!/usr/bin/env python3
import json,sys,pathlib
p=pathlib.Path(%r); (p/('nq-'+str(len(list(p.iterdir())))+'.json')).write_text(json.dumps(sys.argv[1:]))
print(json.dumps({'delivery_state':'accepted','human_receipt':'not_established','notification_id':'sha256:'+'5'*64}))
""" % str(calls), encoding="utf-8")
        nq.chmod(0o755)
        files = {}
        for name in ("runtime.json", "attention.json"):
            files[name] = root / name
            files[name].write_text("{}", encoding="ascii")
        files["schedule.json"] = root / "schedule.json"
        files["schedule.json"].write_text(json.dumps({"schema":"nightshift.saved-check-schedule-policy/v1",
            "scheduler_clock_id":"clock","epoch":"2026-09-20T00:00:00Z",
            "interval_seconds":60,"admissible_delay_seconds":10}, separators=(",", ":"), sort_keys=True), encoding="ascii")
        state = root / "state"; state.mkdir(mode=0o700); state.chmod(0o700)
        inbox = state / "inbox"; inbox.mkdir(mode=0o711); inbox.chmod(0o711)
        notification = root / "notification.toml"
        notification.write_text('schema="nq.config.v1"\n[[notification_routes]]\nreference="local"\ntransport="%s"\nlocal_inbox_directory="%s"\n' %
                                ("local_file" if local else "https", inbox), encoding="utf-8")
        profile = {
            "schema": TICK.PROFILE_SCHEMA, "nightshift_program": str(nightshift),
            "nightshift_program_sha256": digest(nightshift), "nq_program": str(nq),
            "nq_program_sha256": digest(nq), "nightshift_store": str(root / "nightshift.sqlite"),
            "runtime_config": str(files["runtime.json"]), "runtime_config_sha256": digest(files["runtime.json"]),
            "schedule_policy": str(files["schedule.json"]), "schedule_policy_sha256": digest(files["schedule.json"]),
            "scheduler_clock_id": "clock", "attention_policy": str(files["attention.json"]),
            "attention_policy_sha256": digest(files["attention.json"]), "notification_config": str(notification),
            "notification_config_sha256": digest(notification), "notification_route": "local",
            "notification_destination_identity": "local-inbox:local", "state_directory": str(state),
            "command_timeout_seconds": 5,
        }
        profile_path = root / "profile.json"; write(profile_path, profile)
        return profile_path, state, calls

    def test_terminal_tick_is_retained_and_duplicate_launches_only_schedule(self):
        with tempfile.TemporaryDirectory() as directory:
            profile, state, calls = self.fixture(Path(directory))
            code, first = TICK.run(profile, "2026-09-20T12:00:00Z")
            self.assertEqual((code, first["state"], first["attention_reason"]),
                             (0, "complete", "SAVED_CHECK_FAILED_COVERED"))
            count = len(list(calls.iterdir()))
            code, second = TICK.run(profile, "2026-09-20T12:00:00Z")
            self.assertEqual(first, second)
            self.assertEqual(len(list(calls.iterdir())), count + 1)
            self.assertEqual(len(list((state / "ticks").glob("*/result.json"))), 1)
            intent = next((state / "ticks").glob("*/notification-intent.json"))
            self.assertEqual(intent.read_bytes(), TICK.canonical(json.loads(intent.read_bytes())))

    def test_nonterminal_is_indeterminate_and_not_delivered(self):
        with tempfile.TemporaryDirectory() as directory:
            profile, _, calls = self.fixture(Path(directory), terminal=False)
            code, result = TICK.run(profile, "2026-09-20T12:00:00Z")
            self.assertEqual((code, result["state"], result["evaluation_state"]),
                             (0, "indeterminate", "nq_started"))
            self.assertFalse(any(path.name.startswith("nq-") for path in calls.iterdir()))

    def test_elapsed_attention_is_retained_but_not_delivered(self):
        with tempfile.TemporaryDirectory() as directory:
            profile, _, calls = self.fixture(Path(directory), event_until="2020-01-01T00:00:00Z")
            code, result = TICK.run(profile, "2026-09-20T12:00:00Z")
            self.assertEqual((code, result["delivery"]["state"]), (0, "not_sent_stale"))
            self.assertEqual(result["maintenance"], {"state": "covered"})
            self.assertFalse(any(path.name.startswith("nq-") for path in calls.iterdir()))

    def test_overlap_refuses_before_component_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            profile, state, calls = self.fixture(Path(directory))
            with (state / "tick.lock").open("a+b") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                code, result = TICK.run(profile, "2026-09-20T12:00:00Z")
            self.assertEqual((code, result["state"]), (75, "overlap_refused"))
            self.assertEqual(list(calls.iterdir()), [])

    def test_missed_slot_does_not_launch_evaluation_or_delivery(self):
        with tempfile.TemporaryDirectory() as directory:
            profile, _, calls = self.fixture(Path(directory), selection="missed")
            code, result = TICK.run(profile, "2026-09-20T12:00:59Z")
            self.assertEqual((code, result["state"]), (0, "missed"))
            self.assertEqual(len(list(calls.iterdir())), 1)

    def test_nonlocal_route_refuses_before_component_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            profile, _, calls = self.fixture(Path(directory), local=False)
            with self.assertRaisesRegex(ValueError, "local_file"):
                TICK.run(profile, "2026-09-20T12:00:00Z")
            self.assertEqual(list(calls.iterdir()), [])

    def test_intermediate_symlink_inbox_refuses_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile, state, calls = self.fixture(root)
            real = state / "real"; real.mkdir()
            inbox = real / "inbox"; inbox.mkdir()
            (state / "through").symlink_to(real, target_is_directory=True)
            notification = root / "notification.toml"
            notification.write_text('schema="nq.config.v1"\n[[notification_routes]]\nreference="local"\ntransport="local_file"\nlocal_inbox_directory="%s"\n' %
                                    (state / "through" / "inbox"), encoding="utf-8")
            value = json.loads(profile.read_text())
            value["notification_config_sha256"] = digest(notification)
            write(profile, value)
            with self.assertRaisesRegex(ValueError, "ancestry contains a symlink"):
                TICK.run(profile, "2026-09-20T12:00:00Z")
            self.assertEqual(list(calls.iterdir()), [])

    def test_group_writable_state_refuses_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            profile, state, calls = self.fixture(Path(directory))
            state.chmod(0o770)
            with self.assertRaisesRegex(ValueError, "group/world writable"):
                TICK.run(profile, "2026-09-20T12:00:00Z")
            self.assertEqual(list(calls.iterdir()), [])

    def test_group_writable_ticks_directory_refuses_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            profile, state, calls = self.fixture(Path(directory))
            ticks = state / "ticks"; ticks.mkdir(mode=0o770); ticks.chmod(0o770)
            with self.assertRaisesRegex(ValueError, "group/world writable"):
                TICK.run(profile, "2026-09-20T12:00:00Z")
            self.assertEqual(list(calls.iterdir()), [])

    def test_state_path_replacement_after_lock_refuses_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile, state, calls = self.fixture(root)
            original = TICK.owned_directory
            state_checks = 0

            def replacing_check(path, label):
                nonlocal state_checks
                if label == "state_directory":
                    state_checks += 1
                    if state_checks == 2:
                        state.rename(root / "state-original")
                        state.mkdir(mode=0o700)
                        state.chmod(0o700)
                return original(path, label)

            with mock.patch.object(TICK, "owned_directory", side_effect=replacing_check):
                with self.assertRaisesRegex(ValueError, "replaced before tick custody"):
                    TICK.run(profile, "2026-09-20T12:00:00Z")
            self.assertEqual(list(calls.iterdir()), [])

    def test_opened_input_refuses_pathname_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "material"
            path.write_bytes(b"a" * (96 * 1024))
            original_read = os.read
            replaced = False

            def replacing_read(fd, count):
                nonlocal replaced
                data = original_read(fd, count)
                if not replaced:
                    replaced = True
                    path.rename(path.with_name("original"))
                    path.write_bytes(b"b" * (96 * 1024))
                return data

            with mock.patch.object(TICK.os, "read", side_effect=replacing_read):
                with self.assertRaisesRegex(ValueError, "pathname was replaced"):
                    TICK.read_regular(path, 128 * 1024)

    def test_postvalidation_executable_replacement_uses_retained_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile, _, _ = self.fixture(root)
            original_validate = TICK.validate_material

            def replace_after_validation(value, state):
                retained = original_validate(value, state)
                program = Path(value["nightshift_program"])
                program.rename(root / "nightshift-validated")
                program.write_text("#!/bin/sh\nexit 99\n", encoding="ascii")
                program.chmod(0o755)
                return retained

            with mock.patch.object(TICK, "validate_material", side_effect=replace_after_validation):
                code, result = TICK.run(profile, "2026-09-20T12:00:00Z")
            self.assertEqual((code, result["state"]), (0, "complete"))

    def test_postvalidation_executable_content_mutation_uses_sealed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile, _, _ = self.fixture(root)
            original_validate = TICK.validate_material

            def mutate_after_validation(value, state):
                retained = original_validate(value, state)
                program = Path(value["nightshift_program"])
                program.write_text("#!/bin/sh\nexit 99\n", encoding="ascii")
                program.chmod(0o755)
                return retained

            with mock.patch.object(TICK, "validate_material", side_effect=mutate_after_validation):
                code, result = TICK.run(profile, "2026-09-20T12:00:00Z")
            self.assertEqual((code, result["state"]), (0, "complete"))

    def test_postvalidation_config_replacement_uses_retained_descriptors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile, _, calls = self.fixture(root)
            value = json.loads(profile.read_text())
            original_validate = TICK.validate_material

            def replace_after_validation(profile_value, state):
                retained = original_validate(profile_value, state)
                for key in ("runtime_config", "schedule_policy", "attention_policy", "notification_config"):
                    path = Path(profile_value[key])
                    path.rename(path.with_suffix(path.suffix + ".validated"))
                    path.write_text("replacement", encoding="ascii")
                return retained

            with mock.patch.object(TICK, "validate_material", side_effect=replace_after_validation):
                code, result = TICK.run(profile, "2026-09-20T12:00:00Z")
            self.assertEqual((code, result["state"]), (0, "complete"))
            arguments = [json.loads(path.read_text()) for path in calls.iterdir()]
            self.assertTrue(any(any(str(item).startswith("/proc/self/fd/") for item in argv)
                                for argv in arguments))

    def test_repeated_invocation_rewinds_exact_input_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            path.write_text("{}", encoding="ascii")
            retained = TICK.pinned(str(path), digest(path), "input")
            command = [sys.executable, "-c",
                "import pathlib,sys; print(pathlib.Path(sys.argv[1]).read_text())",
                retained.proc_path]
            try:
                self.assertEqual(TICK.invoke(command, 5, pass_fds=(retained.fd,)), {})
                self.assertEqual(TICK.invoke(command, 5, pass_fds=(retained.fd,)), {})
            finally:
                retained.close()

    def test_component_output_limit_terminates_and_reaps_process(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_path = Path(directory) / "pid"
            command = [sys.executable, "-c", """
import os,pathlib,sys,time
pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))
os.write(2, b'bounded diagnostic marker\\n')
os.write(1, b'x' * 4096)
time.sleep(30)
""", str(pid_path)]
            with mock.patch.object(TICK, "MAX_OUTPUT", 1024):
                with self.assertRaisesRegex(RuntimeError,
                                            "stdout exceeded 2 MiB; stderr tail: bounded diagnostic marker"):
                    TICK.invoke(command, 5)
            pid = int(pid_path.read_text())
            with self.assertRaises(ChildProcessError):
                os.waitpid(pid, os.WNOHANG)

    def test_component_stderr_limit_terminates_and_reaps_process(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_path = Path(directory) / "pid"
            command = [sys.executable, "-c", """
import os,pathlib,sys,time
pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))
os.write(2, b'y' * 4096)
time.sleep(30)
""", str(pid_path)]
            with mock.patch.object(TICK, "MAX_OUTPUT", 1024):
                with self.assertRaisesRegex(RuntimeError, "stderr exceeded 2 MiB"):
                    TICK.invoke(command, 5)
            pid = int(pid_path.read_text())
            with self.assertRaises(ChildProcessError):
                os.waitpid(pid, os.WNOHANG)

    def test_component_timeout_terminates_and_reaps_process(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_path = Path(directory) / "pid"
            command = [sys.executable, "-c", """
import os,pathlib,sys,time
pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))
time.sleep(30)
""", str(pid_path)]
            with self.assertRaises(subprocess.TimeoutExpired):
                TICK.invoke(command, 0.05)
            pid = int(pid_path.read_text())
            with self.assertRaises(ChildProcessError):
                os.waitpid(pid, os.WNOHANG)

    def test_partial_material_validation_closes_accumulated_descriptors(self):
        with tempfile.TemporaryDirectory() as directory:
            profile_path, state, _ = self.fixture(Path(directory))
            profile = json.loads(profile_path.read_text())
            original = TICK.pinned
            retained = []
            calls = 0
            before = len(os.listdir("/proc/self/fd"))

            def fail_second(*args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise ValueError("deterministic later material refusal")
                item = original(*args, **kwargs)
                retained.append(item)
                return item

            with mock.patch.object(TICK, "pinned", side_effect=fail_second):
                with self.assertRaisesRegex(ValueError, "later material refusal"):
                    TICK.validate_material(profile, state)
            self.assertEqual([item.fd for item in retained], [-1])
            self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_component_refusal_releases_lock_and_all_material(self):
        with tempfile.TemporaryDirectory() as directory:
            profile, state, _ = self.fixture(Path(directory))
            original = TICK.validate_material
            retained = []

            def capture(value, state_path):
                paths = original(value, state_path)
                retained.extend(paths.values())
                return paths

            with mock.patch.object(TICK, "validate_material", side_effect=capture), \
                    mock.patch.object(TICK, "invoke", side_effect=RuntimeError("component refused")):
                with self.assertRaisesRegex(RuntimeError, "component refused"):
                    TICK.run(profile, "2026-09-20T12:00:00Z")
            self.assertTrue(retained)
            self.assertTrue(all(item.fd == -1 for item in retained))
            with (state / "tick.lock").open("a+b") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_profile_digest_change_changes_tick_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            profile, _, _ = self.fixture(Path(directory))
            _, first = TICK.run(profile, "2026-09-20T12:00:00Z")
            value = json.loads(profile.read_text())
            value["command_timeout_seconds"] = 6
            write(profile, value)
            _, second = TICK.run(profile, "2026-09-20T12:00:00Z")
            self.assertNotEqual(first["tick_id"], second["tick_id"])


if __name__ == "__main__":
    unittest.main()

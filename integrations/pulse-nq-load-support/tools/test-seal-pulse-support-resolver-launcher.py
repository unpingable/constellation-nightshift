#!/usr/bin/python3
"""Deterministic synthetic checks for the Pulse closed-launcher generator."""

import fcntl
import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import tempfile
import unittest


HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("seal", HERE / "seal-pulse-support-resolver-launcher.py")
SEAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SEAL)


class LauncherTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        resolver = pathlib.Path("/usr/bin/bash").resolve()
        config = root / "synthetic-config.json"
        config.write_bytes(b'{"synthetic":true}')
        python = pathlib.Path("/usr/bin/python3").resolve()
        enrollment = {
            "schema": SEAL.SCHEMA,
            "resolver_program": str(resolver),
            "resolver_sha256": SEAL.digest(resolver.read_bytes()),
            "config_path": str(config),
            "config_sha256": SEAL.digest(config.read_bytes()),
            "python_interpreter": str(python),
            "python_sha256": SEAL.digest(python.read_bytes()),
        }
        source = root / "enrollment.json"
        source.write_bytes(SEAL.canonical(enrollment))
        return root, resolver, config, source

    def test_generated_launcher_closes_argv_and_environment(self):
        root, _, _, enrollment = self.fixture()
        value = SEAL.load_enrollment(enrollment)
        output = SEAL.launcher_bytes(value)
        self.assertIn(b'len(sys.argv) != 1', output)
        self.assertIn(b'PULSE_LOAD_SUPPORT_CONFIG_SHA256', output)
        self.assertIn(b'F_ADD_SEALS', output)
        self.assertIn(b'["pulse-support-resolver"]', output)
        self.assertNotIn(b'os.environ', output)
        self.assertTrue(output.splitlines()[0].endswith(b' -I'))

    def test_changed_config_and_unknown_field_are_refused(self):
        _, _, config, enrollment = self.fixture()
        config.write_bytes(b'{"synthetic":false}')
        with self.assertRaisesRegex(ValueError, "config_sha256 mismatch"):
            SEAL.load_enrollment(enrollment)
        root, _, _, enrollment = self.fixture()
        value = json.loads(enrollment.read_bytes())
        value["command"] = "/bin/true"
        enrollment.write_bytes(SEAL.canonical(value))
        with self.assertRaisesRegex(ValueError, "non-closed"):
            SEAL.load_enrollment(enrollment)

    def test_post_enrollment_config_replacement_is_refused_before_execution(self):
        root, _, config, enrollment = self.fixture()
        launcher = root / "pulse-support-resolver"
        manifest = root / "manifest.json"
        subprocess.run([pathlib.Path("/usr/bin/python3"), HERE / "seal-pulse-support-resolver-launcher.py",
                        "--enrollment", enrollment, "--launcher", launcher, "--manifest", manifest],
                       check=True, timeout=5)
        config.write_bytes(b'{"synthetic":"replacement"}')
        result = subprocess.run([launcher], capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("configured config digest mismatch", result.stderr)

    def test_generated_launcher_passes_only_sealed_descriptor_environment(self):
        root, _, _, enrollment = self.fixture()
        launcher = root / "pulse-support-resolver"
        manifest = root / "manifest.json"
        subprocess.run([pathlib.Path("/usr/bin/python3"), HERE / "seal-pulse-support-resolver-launcher.py",
                        "--enrollment", enrollment, "--launcher", launcher, "--manifest", manifest],
                       check=True, timeout=5)
        result = subprocess.run([launcher], input='printf "%s|%s|%s\\n" "$0" "$PULSE_LOAD_SUPPORT_CONFIG" "$PULSE_LOAD_SUPPORT_CONFIG_SHA256"\n',
                                capture_output=True, text=True, timeout=5, check=True)
        role, config_descriptor, config_digest = result.stdout.strip().split("|")
        self.assertEqual(role, "pulse-support-resolver")
        self.assertRegex(config_descriptor, r"^/proc/self/fd/[0-9]+$")
        self.assertEqual(config_digest, SEAL.load_enrollment(enrollment)["config_sha256"])
        self.assertEqual(json.loads(manifest.read_bytes())["launcher_sha256"],
                         "sha256:" + hashlib.sha256(launcher.read_bytes()).hexdigest())

    def test_wrong_launcher_basename_is_refused(self):
        root, _, _, enrollment = self.fixture()
        result = subprocess.run([pathlib.Path("/usr/bin/python3"), HERE / "seal-pulse-support-resolver-launcher.py",
                                 "--enrollment", enrollment, "--launcher", root / "other", "--manifest", root / "manifest.json"],
                                capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("basename", result.stderr)

    def test_generated_launcher_refuses_arguments(self):
        root, _, _, enrollment = self.fixture()
        launcher = root / "pulse-support-resolver"
        manifest = root / "manifest.json"
        subprocess.run([pathlib.Path("/usr/bin/python3"), HERE / "seal-pulse-support-resolver-launcher.py",
                        "--enrollment", enrollment, "--launcher", launcher, "--manifest", manifest],
                       check=True, timeout=5)
        result = subprocess.run([launcher, "unexpected"], capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("accepts no arguments", result.stderr)

    def test_sealed_synthetic_descriptor_reopens_by_procfd(self):
        image = os.memfd_create("synthetic-pulse-config", os.MFD_ALLOW_SEALING)
        self.addCleanup(os.close, image)
        contents = b'{"synthetic":"sealed"}'
        os.write(image, contents)
        fcntl.fcntl(image, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SEAL)
        os.lseek(image, 0, os.SEEK_SET)
        duplicate = os.open(f"/proc/self/fd/{image}", os.O_RDONLY | os.O_CLOEXEC)
        self.addCleanup(os.close, duplicate)
        self.assertEqual(os.read(duplicate, len(contents) + 1), contents)


if __name__ == "__main__":
    unittest.main()

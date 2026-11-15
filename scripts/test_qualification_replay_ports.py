"""Direct controls for read-only replay and separate saved-check acquisition."""

import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

from check_qualification_replay_ports import check


ROOT = pathlib.Path(__file__).resolve().parents[1]


class SavedCheckPortTests(unittest.TestCase):
    def test_existing_acquisition_is_in_closed_graph(self):
        result = subprocess.run(
            ["bash", "scripts/check_no_actuation_surface.sh"],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_acquisition_port_refuses_widened_roles_and_missing_bounds(self):
        source = (ROOT / "crates/nightshiftd/src/saved_check_runtime.rs").read_text()
        substitutions = (
            ('"collect".into()', '"repair".into()'),
            ('"--allow-exec".into()', '"--allow-exec".into(), "--extra".into()'),
            ('"evaluate",', '"execute",'),
            ('"result",', '"export",'),
            ('"condition",', '"notify",'),
            ('"saved-check", "inspect",', '"saved-check", "admit",'),
            ('&config.monitor_program_sha256,', '&config.nq_program_sha256,'),
            ('Some((&config.nq_config, &config.nq_config_sha256))', 'None'),
            ('    let output = run_bounded(\n        &config.nq_program,',
             '    args.push("execute".into());\n    let output = run_bounded(\n        &config.nq_program,'),
            ('let args: Vec<_> = args', 'let args: Vec<_> = extra_args'),
            ('Command::new(executable_path)', 'Command::new(program)'),
            ('.args(args)', '.args(args).arg("execute")'),
            ('.process_group(0)', '.env("MODE", "execute").process_group(0)'),
            ('.stdin(Stdio::null())', '.stdin(Stdio::inherit())'),
            ('if actual != expected {', 'if actual == expected {'),
            ('libc::F_SEAL_WRITE |', ''),
            ('libc::fchmod(captured.as_raw_fd(), 0o500)', 'libc::fchmod(captured.as_raw_fd(), 0o700)'),
            ('libc::O_NOFOLLOW |', ''),
            ('if copied > max {', 'if copied < max {'),
            ('file.take(max + 1)', 'file.take(u64::MAX)'),
            ('        config.validate()?;', ''),
            ('if Instant::now() >= deadline {', 'if false {'),
            ('if stdout_len > MAX_RESULT_BYTES || stderr_len > MAX_RESULT_BYTES {', 'if false {'),
            ('kill_process_group(child.id());', '// no descendant cleanup'),
            ('read_file(stderr, MAX_RESULT_BYTES)?;', 'Vec::new();'),
            ('if !(1..=300).contains(&self.command_timeout_seconds) {', 'if false {'),
            ('mod tests {', 'mod unguarded_tests {'),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "scripts").mkdir()
            target = root / "crates/nightshiftd/src"
            target.mkdir(parents=True)
            shutil.copy2(ROOT / "scripts/check_qualification_replay_ports.py", root / "scripts")
            for name in ("repository_qualification", "reservation_qualification", "saved_check_runtime"):
                shutil.copy2(ROOT / "crates/nightshiftd/src" / f"{name}.rs", target)

            def run(changed):
                (target / "saved_check_runtime.rs").write_text(changed)
                return subprocess.run(
                    [sys.executable, "-B", str(root / "scripts/check_qualification_replay_ports.py")],
                    capture_output=True, text=True,
                )

            self.assertEqual(run(source).returncode, 0)
            for old, new in substitutions:
                with self.subTest(substitution=new):
                    changed = source.replace(old, new, 1)
                    self.assertNotEqual(changed, source)
                    result = run(changed)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("saved-check acquisition port", result.stderr)
            # Field-level cfg(test) occurs before the real spawn: it must not
            # be mistaken for the terminal test module and hide production.
            for changed in (
                source.replace('let mut child = Command::new(executable_path)',
                               'let _ = Command::new("extra");\n    let mut child = Command::new(executable_path)', 1),
                source + '\nfn extra() { let _ = Command::new("extra"); }\n',
            ):
                with self.subTest(case="extra production process"):
                    self.assertNotEqual(run(changed).returncode, 0)

    def test_unlisted_production_module_still_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for name in ("Cargo.toml", "Cargo.lock", "crates", "deploy", "docs", "scripts"):
                path = ROOT / name
                if path.is_dir():
                    shutil.copytree(path, root / name)
                else:
                    shutil.copy2(path, root / name)
            (root / "crates/nightshiftd/src/_unlisted.rs").write_text(
                'fn extra() { let _ = std::process::Command::new("extra"); }\n'
            )
            result = subprocess.run(
                ["bash", "scripts/check_no_actuation_surface.sh"],
                cwd=root, capture_output=True, text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("production subprocess files are not the exact closed port set", result.stderr)
            self.assertIn("_unlisted.rs", result.stderr)


class RestrictedReplayTests(unittest.TestCase):
    def test_exact_ports_and_negative_controls(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        for module, operation in (
            ("repository_qualification", "campaign-stage-qualification"),
            ("reservation_qualification", "campaign-stage-realization"),
        ):
            source = (root / "crates/nightshiftd/src" / f"{module}.rs").read_text()
            with self.subTest(module=module, case="current read-only port"):
                self.assertTrue(check(source, operation))
            substitutions = (
                ('"replay",', '"evaluate",'),
                ('"replay",', '"replay", "execute",'),
                ('"--output",', '"--write",'),
                ('"-",', '"result.json",'),
                ('.output()', '.arg("execute").output()'),
                ('.output()', '.env("MODE", "execute").output()'),
                ('Some("nq")', 'Some("other-evaluator")'),
                (' != Some("nq")', ' == Some("nq")'),
                ('Command::new(&self.program)', 'Command::new("other-evaluator")'),
            )
            for old, new in substitutions:
                with self.subTest(module=module, substitution=new):
                    changed = source.replace(old, new, 1)
                    self.assertNotEqual(changed, source)
                    self.assertFalse(check(changed, operation))
            with self.subTest(module=module, case="second process site"):
                self.assertFalse(check(source + '\nCommand::new("extra")', operation))


if __name__ == "__main__":
    unittest.main()

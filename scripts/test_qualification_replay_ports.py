"""Direct substitution controls for each retained read-only replay port."""

import pathlib
import unittest

from check_qualification_replay_ports import check


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

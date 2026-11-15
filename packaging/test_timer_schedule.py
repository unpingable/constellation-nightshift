"""Check shipped timer activations against the default UTC recurrence slots.

Uses systemd's calendar parser, without starting a service or contacting a bus.
The runtime still decides whether a real invocation may claim a slot.
"""

import configparser
import datetime as dt
import os
from pathlib import Path
import re
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
TIMERS = [ROOT / directory / "nightshift-observation-cycle.timer"
          for directory in ("deploy/systemd", "packaging/systemd")]
UTC = dt.timezone.utc
EPOCH = dt.datetime(2026, 10, 1, tzinfo=UTC)


def calendar_events(expression, base, timezone):
    output = subprocess.check_output(
        ["systemd-analyze", "calendar", "--iterations=24",
         # systemd 249 (Ubuntu 22.04) accepts the explicit UTC form, while
         # rejecting the ISO 8601 offset form accepted by newer releases.
         "--base-time=" + base.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"), expression],
        env={**os.environ, "TZ": timezone, "LC_ALL": "C"}, text=True,
    )
    return [dt.datetime.fromisoformat(value).replace(tzinfo=UTC)
            for value in re.findall(
                r"(?:Next elapse:|Iter(?:ation|\.) #\d+:|\(in UTC\):)\s+\w+ "
                r"(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) UTC", output)]


def seconds(value):
    output = subprocess.check_output(
        ["systemd-analyze", "timespan", value],
        env={**os.environ, "LC_ALL": "C"}, text=True,
    )
    return int(re.search(r"us:\s*(\d+)", output)[1]) / 1_000_000


@unittest.skipUnless(shutil.which("systemd-analyze"), "requires systemd-analyze")
class TimerScheduleTests(unittest.TestCase):
    def test_reactivation_and_service_duration_do_not_move_the_slot_grid(self):
        # These include midnight/year rollover, both US DST changes, an arbitrary
        # boot phase, and reactivation after work lasting beyond one or two slots.
        bases = ["2026-12-31T23:58:17+00:00", "2026-11-01T05:58:17+00:00",
                 "2026-03-08T06:58:17+00:00", "2026-11-03T12:01:31+00:00"]
        for path in TIMERS:
            config = configparser.ConfigParser(interpolation=None)
            config.read(path)
            timer = config["Timer"]
            with self.subTest(timer=str(path.relative_to(ROOT))):
                # A monotonic trigger adds activations outside the calendar grid.
                for key in ("OnBootSec", "OnStartupSec", "OnActiveSec",
                            "OnUnitActiveSec", "OnUnitInactiveSec"):
                    self.assertFalse(timer.get(key), f"{key} permits off-slot wakes")
                self.assertIn("OnCalendar", timer, "timer must select fixed recurrence slots")
                delay = (seconds(timer.get("AccuracySec", "1min"))
                         + seconds(timer.get("RandomizedDelaySec", "0")))
                self.assertLess(delay, 150, "delivery allowance consumes the slot window")
                for timezone in ("UTC", "America/New_York", "Asia/Kathmandu"):
                    for base in bases:
                        for duration in (0, 120, 301, 650):
                            ready = dt.datetime.fromisoformat(base) + dt.timedelta(seconds=duration)
                            events = calendar_events(timer["OnCalendar"], ready, timezone)
                            self.assertEqual(len(events), 24)
                            for index, event in enumerate(events):
                                self.assertGreater(event, ready)
                                self.assertEqual((event - EPOCH).total_seconds() % 300, 0)
                                self.assertLess((event - EPOCH).total_seconds() % 300 + delay, 150)
                                if index:
                                    self.assertEqual((event - events[index - 1]).total_seconds(), 300)


if __name__ == "__main__":
    unittest.main()

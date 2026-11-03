# Nightshift packaged executable identity

## Executable build identity

The packaged native tools accept `--build-info`, `--version` and `-V` as sole
arguments before configuration, stdin or state access. These probes report
compile-time source/build declarations, compiler, target and profile. Missing
development declarations remain JSON null and cannot be packaged.

Export `NIGHTSHIFT_SOURCE_COMMIT` as the full lowercase 40-digit source commit and
`NIGHTSHIFT_BUILD_IDENTITY` as a unique build label (1..256 printable ASCII bytes
without spaces) for compilation and assembly. The builder must verify the source
export and locked toolchain inputs; the probe does not independently attest them.
Malformed nonempty declarations fail compilation. Assembly probes the staged
copies, checks their declared identity, compiler/profile/architecture and version,
and embeds their SHA-256 hashes at `/usr/share/doc/` under the package name in
`build-identity.json`. A matching `.build-identity.json` sidecar accompanies the
package. Compare installed probes and hashes to those receipts.

## Observation timer

The package installs the same UTC five-minute calendar as the systemd
reference. The installed `README.md` describes the required request epoch,
cadence, site overrides, delayed invocations and persistent catch-up. Read
[`deploy/systemd/README.md`](../deploy/systemd/README.md#match-the-request-slot-policy)
before enabling it. Installation remains inert.

Run `python3 -B -m unittest discover -s packaging -p 'test_*.py'` for the
package checks. Timer checks require `systemd-analyze`; CI runs them with
systemd installed. They expand the actual shipped calendars across arbitrary
reactivation phases, service durations and clock/date boundaries. They check
the default 300-second epoch grid with a 150-second admissibility window.

Formalization consideration (Nightshift #8, 2026-11-03): source base
`c7d2ffc8791e265162fd5d14d8949827300ad502`; the changed objects are the
packaged and reference timer files. The bounded proposition is that their
ordinary calendar boundaries stay on the default UTC slot grid independently
of boot phase and preceding service duration. Systemd's calendar expansion
plus the existing runtime slot checks suffice for this configuration change;
no new temporal or currentness law is introduced. Actual dispatch delay,
clock jumps, downtime, request rotation and support freshness are outside
that proposition. The deployment operator owns the slot policy and whether
a wake is admissible; the campaign owner reviews the package change.

Run `python3 -B -m unittest discover -s packaging -p test_build_identity.py` for
package correspondence and refusal fixtures. No authority, state or core protocol
semantics change. Existing legacy version interfaces remain available.

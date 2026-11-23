# Canonical Nightshift systemd reference units

These system-level files invoke the sole production `nightshift` binary and
its exact `cycle run` interface:

| File | Role |
|---|---|
| `nightshift-observation-cycle.service` | one exact canonical observation cycle |
| `nightshift-observation-cycle.timer` | preserved five-minute wake cadence, boot delay, jitter, and `Persistent=true` catch-up |
| `observation-cycle.env.example` | site-owned store, request, NQ-NG source, present-support resolver, and optional AG paths/profile |

The timer grants permission only to attempt observation. Exact recurrence-slot
identity and overlap exclusion are durable Nightshift facts. The configured
NQ-NG source qualifies exact local admission provenance before Nightshift
claims a slot; present support is resolved separately by its evidence
authority, and any immutable exact-work proposal goes only to AG. Admission is
not authorization. The unit has no Governor, Wicket, WLP, Docket, or executor
option.

The service first requires the configured program to support NQ-NG's global
`--help`, then preflights the exact `diagnostics qualify` CLI surface before
each cycle. Both checks are required: Debian's unrelated `/usr/bin/nq` happens
to return success for some arbitrary command arguments, while rejecting
`--help`; older NQ-NG builds support global help but predate the producer
boundary. These capability checks do not establish source identity or
authorize NQ-NG deployment; the configured store-genesis identity and separate
deployment/cutover procedure remain load-bearing.

Install as reference scaffolding after replacing every site-owned path:

```sh
sudo install -d -m 0750 -o root -g nightshift /etc/nightshift
sudo install -m 0640 -o root -g nightshift \
  deploy/systemd/observation-cycle.env.example \
  /etc/nightshift/observation-cycle.env
sudo install -m 0644 deploy/systemd/nightshift-observation-cycle.service \
  /etc/systemd/system/
sudo install -m 0644 deploy/systemd/nightshift-observation-cycle.timer \
  /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nightshift-observation-cycle.timer
```

The reference unit does not grant cross-service filesystem authority. The site
must arrange narrowly read-only access for the `nightshift` service identity to
the configured NQ-NG config and SQLite snapshot (including SQLite sidecar
files when present), without granting NQ mutation rights. The configured
`NIGHTSHIFT_NQ_SOURCE_ID`, not either path, is the source identity checked at
the boundary.

## Publish recurrence telemetry

`nightshift --store /var/lib/nightshift/nightshift.sqlite cycle summary`
prints `nightshift.cycle_summary.v1` JSON. It reports the latest retained
cycle update across the store, the latest recorded update of a closed cycle,
and the time of the read. The latest cycle includes its status, slot timing and
oldest completion time among its admitted NQ reports. A store with no cycles
reports `latest_cycle: null`. An acquisition failure exits nonzero. The read
requires the two latest-cycle indexes installed by the normal Nightshift
writer. Open older stores through the normal writer before enabling export.

With `--format textfile`, the same command emits these Prometheus gauges:

| Gauge | Meaning |
|---|---|
| `constellation_nightshift_cycle_summary_observed_timestamp_seconds` | Time of the successful read |
| `constellation_nightshift_cycle_present` | 1 when the store contains a cycle, otherwise 0 |
| `constellation_nightshift_latest_cycle{status,timing}` | One sample with the latest cycle's closed status and timing labels |
| `constellation_nightshift_latest_cycle_updated_timestamp_seconds` | The latest cycle's recorded `updated_at` |
| `constellation_nightshift_last_closed_cycle_timestamp_seconds` | The most recent recorded `updated_at` of a closed cycle |
| `constellation_nightshift_oldest_nq_admission_completed_timestamp_seconds` | Oldest completion time among the latest cycle's admitted NQ reports |

An absent value omits its gauge. Unknown status and timing values use `other`.
When cycles share the same update timestamp the store supplies one of them.
Cycle timestamps describe recorded transitions, and NQ timestamps describe
retained upstream completions. Use the read timestamp and the expected
publication cadence to detect a missing or stale export. History counters,
wall-clock run durations, and Foreman metrics are outside this projection.

Run this example as the Nightshift service account in the site's existing
scheduled export job. Create the destination directories with write access for
the job and read access for the designated readers. Use the textfile directory
configured in node_exporter.

```sh
#!/bin/sh
set -eu
publish() {
    destination=$1
    format=$2
    temporary=$(mktemp "${destination}.tmp.XXXXXX")
    trap 'rm -f -- "$temporary"' EXIT
    /usr/bin/nightshift --store /var/lib/nightshift/nightshift.sqlite \
        cycle summary --format "$format" > "$temporary"
    chmod 0644 "$temporary"
    mv -fT -- "$temporary" "$destination"
    trap - EXIT
}
publish /var/lib/nightshift/cycle-summary.json json
publish /var/lib/node_exporter/textfile_collector/nightshift.prom textfile
```

Each file is replaced by a rename in its destination directory. A failed read
leaves the preceding file readable with its original timestamp. JSON and
textfile exports each take a separate store snapshot, so their sampling times
can differ. Run a single scheduled publisher per destination. If a site
uses `ExecStartPost` on the existing observation unit, arrange the specific
writable paths and allow for its runtime within the start timeout. A scrape
reads published bytes only. This projection is for operator telemetry.

## Optional Maude authoring custody

The reference timer remains suitable for cycles with no Maude authoring
context. Do not configure custody flags globally and then infer context for
ordinary cycles. A site-owned one-shot authoring invocation supplies the
separate handoff plus the complete two-role verifier arguments documented in
[`../../docs/authoring-context-custody.md`](../../docs/authoring-context-custody.md).

For system services, provision the two raw 32-byte keys through host credential
custody (for example systemd `LoadCredential=`) and pass only the resulting
read-only credential paths. The session-issuer and handoff-producer keys and
key IDs must differ. The Maude custody database and handoff/request directory
must be owned by the intended local service principal. This repository does
not provide or embed those credentials.

The request generator/rotation policy and production readiness of the external
Pulse/AG services remain site integration responsibilities. These files are not
a qualification claim.

The `user/` directory is a clearly marked historical, nonportable dogfood
specimen. It is not a supported unit set and remains only as archaeology.

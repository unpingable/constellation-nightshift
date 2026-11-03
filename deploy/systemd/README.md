# Canonical Nightshift systemd reference units

These system-level files invoke the sole production `nightshift` binary and
its exact `cycle run` interface:

| File | Role |
|---|---|
| `nightshift-observation-cycle.service` | one exact canonical observation cycle |
| `nightshift-observation-cycle.timer` | UTC five-minute slot grid and `Persistent=true` catch-up |
| `observation-cycle.env.example` | site-owned store, request, NQ-NG source, present-support resolver, and optional AG paths/profile |

The timer grants permission only to attempt observation. Exact recurrence-slot
identity and overlap exclusion are durable Nightshift facts. The configured
NQ-NG source qualifies exact local admission provenance before Nightshift
claims a slot; present support is resolved separately by its evidence
authority, and any immutable exact-work proposal goes only to AG. Admission is
not authorization. The unit has no Governor, Wicket, WLP, Docket, or executor
option.

## Match the request slot policy

Both the packaged timer and this reference fire at minutes 00, 05, 10, and so
on in UTC, with no randomized delay and a five-second coalescing allowance.
The site-owned request generator must use the same grid: a 300-second cadence
and an epoch on a UTC five-minute boundary (for example
`2026-10-01T00:00:00Z`). It must produce the request for the actual invocation's
slot; the timer does not rotate a saved request. A boot or service completion
does not move later calendar boundaries. If a service is still active when a
boundary passes, systemd does not start another instance for that boundary.

For a different epoch or cadence, install a site drop-in with a matching UTC
calendar. For example, a 600-second cadence with an epoch at
`2026-10-01T00:02:00Z` uses:

```ini
# /etc/systemd/system/nightshift-observation-cycle.timer.d/slots.conf
[Timer]
OnCalendar=
OnCalendar=*-*-* *:02/10:00 UTC
```

Clear the inherited calendar before adding its replacement. Remove any old
drop-in that adds boot-relative or service-relative triggers. Validate the
effective calendar with:

```sh
systemd-analyze calendar --iterations=12 '*-*-* *:02/10:00 UTC'
```

Then reload units and restart the timer. Inspect the
effective unit with `systemctl cat nightshift-observation-cycle.timer` and its
next activation with `systemctl list-timers --all`. If a slot policy cannot
be represented by a calendar, use the site's existing scheduler rather than
adding a second recurrence policy here.

Choose the request's latest-admissible instant to allow the timer's
coalescing and actual dispatch/request-generation delay. `AccuracySec=5s` is
not a bound on host scheduling delay. `Persistent=true` requests one immediate
activation after downtime; it does not replay every missed slot. Such a wake
can occur off-grid. The request generator and runtime must still decide
whether to record a missed slot or admit an explicit catch-up. Neither
catch-up nor calendar alignment refreshes diagnostic evidence, present
support, standing, or authorization. Follow the site's existing recurrence
and recovery policy before enabling the timer.

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

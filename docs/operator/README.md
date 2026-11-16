# Nightshift operator quick start

**Status:** canonical development runtime; not yet operationally qualified.
Nightshift observes and records posture. It does not authorize or execute an
effect.

The separate generic project-predicate attention commands consume exact
replay-verified Pulse receipts and never acquire project facts. Their policy,
history, recurrence, currentness, and replay contract is documented in
[`../GENERIC_PROJECT_PREDICATE_ATTENTION_V1.md`](../GENERIC_PROJECT_PREDICATE_ATTENTION_V1.md).

## Build contract

```sh
cargo build --locked --release --bin nightshift
./target/release/nightshift cycle --help
```

The workspace has no sibling Wicket/WLP dependency. A native C toolchain is
required for bundled SQLite.

## Required external ports

One observation cycle requires:

- a sealed `CanonicalCycleRequestV1` produced by the workflow integration;
- the NQ-NG `nq` executable, its config locator, and the stable expected
  `nq-store-genesis:<id>` source identity; the service identity needs narrowly
  read-only access to that source;
- an executable whose basename is exactly `pulse-support-resolver` and which
  returns an exact query-bound `QualifiedSupportV1`;
- an operator-owned Nightshift SQLite path.

Nightshift does not ship that resolver or a production support source. The
similarly named qualification fixture is not Pulse and must not be installed.
Before configuring this port, the deployment needs a qualified support family
whose independently produced proposition actually applies to the exact
diagnostic decision; see
[`../PRESENT_EVIDENCE_SUPPORT_SOURCE_GATE.md`](../PRESENT_EVIDENCE_SUPPORT_SOURCE_GATE.md).
Origin verification, NQ admission, and Classic NQ liveness do not satisfy this
requirement.

The NQ executable must be the NQ-NG operator CLI, not Debian's unrelated
queueing utility of the same name and not Classic NQ's `nq-monitor`. Verify the
closed read boundary before enabling a cycle:

```sh
/absolute/path/to/nq --help
/absolute/path/to/nq diagnostics qualify --help
```

Both checks are intentional. Debian's unrelated queueing utility rejects the
first even though it may return success for arbitrary trailing command words;
an older NQ-NG build passes the first but refuses the second.

NQ-NG's package intentionally conflicts with Debian's `nq` package rather
than overwriting it. Selecting and installing NQ-NG remains an explicit
deployment/cutover decision.

If the request contains exact work, the cycle additionally requires paths to
`ag-loopctl`, AG's database, AG's observation resolver and expected identity,
and AG's deployment-owned runtime profile. Those are the only
consequence-adjacent Nightshift calls. Nightshift never accepts a Docket or
executor endpoint.

```sh
nightshift \
  --store /var/lib/nightshift/nightshift.sqlite \
  cycle run \
  --request /etc/nightshift/cycles/current.json \
  --nq-program /usr/local/bin/nq \
  --nq-config /etc/nq/nq.toml \
  --nq-source-id nq-store-genesis:DEPLOYMENT_GENESIS_ID \
  --present-evidence-resolver /usr/local/bin/pulse-support-resolver
```

NQ-NG admission is checked before the recurrence slot is claimed. It makes
the exact artifact eligible for Nightshift reasoning; it does not establish
currentness or authorize the optional work proposal.

When NQ returns continuity-bearing
`nq.diagnostic_admission_provenance.v2`, pin the complete verification-only
Standing coordinate set:

```sh
  --standing-continuity-public-key /etc/nightshift/standing-continuity.pub \
  --standing-continuity-key-id standing-continuity:SITE_KEY_ID \
  --standing-continuity-nq-audience nq:SITE_AUDIENCE
```

The file contains a raw 32-byte Ed25519 public key encoded as lowercase hex.
Nightshift has no Standing private key. Omitting the complete set refuses V2
provenance. Supplying it verifies the authority/acquisition prerequisite but
does not by itself establish attribution: independently owned predecessor and
observation-substrate coordinates remain required.

For exact work, append:

```sh
  --ag-loopctl /usr/local/bin/ag-loopctl \
  --ag-database /var/lib/ag/campaign.sqlite \
  --ag-observation-resolver /usr/local/bin/ag-observation-resolver \
  --ag-observation-resolver-id nightshift-observation-resolver/v1 \
  --ag-runtime-profile /etc/ag/governed-loop-profile.json
```

AG options are forbidden on posture-only requests, and all five are mandatory
on requests containing a proposal.

## Authenticated Maude authoring context

For a newly Maude-authored proposal, the base request and its separately
sealed handoff are passed with the two distinct deployment credentials:

```sh
  --maude-authoring-handoff /run/nightshift/handoff.json \
  --maude-custody-credential /run/credentials/maude-handoff-producer.key \
  --maude-producer-principal-id maude-handoff:local \
  --maude-producer-key-id maude-handoff-key:primary \
  --maude-session-custody-credential /run/credentials/maude-session-issuer.key \
  --maude-session-issuer-principal-id maude:supervisor \
  --maude-session-issuer-key-id maude-session-key:primary \
  --nightshift-runtime-id nightshift:local-c1
```

The credential files contain exactly 32 raw bytes, are non-symlink regular
files, and must not be group-writable/executable or accessible by others.
Producer and session-issuer credentials must differ. These options are all
required together when authoring context is present and are refused when it is
absent. The full transport, replay, restart, and environmental contract is in
[`../authoring-context-custody.md`](../authoring-context-custody.md).

## Read local cycle state

```sh
nightshift --store /var/lib/nightshift/nightshift.sqlite cycle list
nightshift --store /var/lib/nightshift/nightshift.sqlite cycle show --cycle-id '<cycle-id>'
nightshift --store /var/lib/nightshift/nightshift.sqlite cycle show --slot-id 'sha256:<slot-digest>'
nightshift --store /var/lib/nightshift/nightshift.sqlite cycle replay --cycle-id '<cycle-id>'
```

Text output is presentation only. The durable cycle record retains exact
support, diagnostic, posture, AG occurrence, attempt, and settlement
references.

`cycle show` requires exactly one cycle or slot identity and opens an existing
store read-only. The slot selector uses the unique slot index and validates the
same retained cycle record. It does not scan historical cycles or establish
latest-family position, present support, completion, or authority. A claimed
cycle with no observation is returned as such; an absent slot is an error.

The first writer open of a store that predates the latest-cycle indexes builds
two indexes over retained cycle history. This one-time migration takes time,
disk space, and writer locking proportional to that history; later writes
maintain the indexes. Only the three tested latest-cycle projections (newest
cycle with `LIMIT 1`, and newest closed cycles with `LIMIT 1` or `LIMIT 16`)
avoid scanning unrelated history. Store open and full-history operations are
not generally constant-time. Read-only opens never create these indexes.

## Restart and AG status

```sh
nightshift --store /var/lib/nightshift/nightshift.sqlite cycle recover \
  --ag-loopctl /usr/local/bin/ag-loopctl \
  --ag-database /var/lib/ag/campaign.sqlite \
  --ag-observation-resolver /usr/local/bin/ag-observation-resolver \
  --ag-observation-resolver-id nightshift-observation-resolver/v1 \
  --ag-runtime-profile /etc/ag/governed-loop-profile.json \
  --observed-at 2026-08-11T12:00:00Z
```

Restart never recreates support currentness, an AG authorization, or an
execution capability. Locally in-flight observation work becomes recovery
required. Prepared AG work is queried by exact occurrence status and is never
resubmitted by Nightshift. Reconciliation and human disposition remain AG
operations.

## Settlement law

An AG settlement supplies only exact occurrence/attempt/outcome provenance.
Nightshift records it and enters observation-required posture. Success does not
mean healthy, failure does not diagnose the cause, and indeterminate never
causes a repeat.

Workflow-specific application/world evidence may be retained through the
authenticated [external-observation custody contract](../EXTERNAL_OBSERVATION_CUSTODY_V1.md).
Custody is deliberately separate from canonical observation cycles:
source-evidence age is not Nightshift currentness, and settlement remains
neither health nor recovery. The closed
[external-evidence composition contract](../EXTERNAL_EVIDENCE_COMPOSITION_V1.md)
allows one deployment-profiled record to participate in an exact successor
observation; Nightshift still evaluates currentness at consequence time.
The decision-relative
[qualification and steady-state contract](../QUALIFICATION_AND_STEADY_STATE_EVIDENCE_V1.md)
adds a separate read-only local-Compose adapter. It may refresh passive
steady-state claims after an owner-produced stale result while retaining the
original fault-test qualification as historical, exact-artifact-bound evidence.
It cannot repeat or claim a new failure test.

The deployment-owned example profile is
[`examples/steady-state-evidence-profile-v1.json`](examples/steady-state-evidence-profile-v1.json).
Nightshift produces an exact absent/current/stale acquisition basis without
mutating runtime state:

```sh
nightshift --store /var/lib/nightshift/nightshift.sqlite \
  external-observation steady-state-basis \
  --qualification-observation-id sha256:EXACT_Q \
  --profile /etc/nightshift/steady-state-evidence-profile.jcs.json \
  --evaluated-at-unix-ms 1787450848101
```

After the distinct passive handoff is admitted, the read-only packager binds
Q and S into the base request:

```sh
nightshift --store /var/lib/nightshift/nightshift.sqlite \
  external-observation prepare-decision-cycle \
  --request /bounded/successor-cycle-base.jcs.json \
  --profile /etc/nightshift/steady-state-evidence-profile.jcs.json
```

The normal cycle run receives the same profile independently with
`--decision-evidence-profile`. Packaging, import, and age arithmetic never
construct Nightshift currentness.

## Scheduling

Reference systemd files are under [`../../deploy/systemd/`](../../deploy/systemd/).
They preserve the existing boot delay, five-minute wake cadence, jitter, and
`Persistent=true`. Every firing attempts one exact recurrence slot; generation
equality never satisfies a slot.

The `deploy/systemd/user/` shelf is historical and nonportable. Do not install
it.

## Diagnostic specimen

The checked-in [diagnostic-posture fixture](examples/diagnostic-posture-v1/README.md)
documents the complete NQ/posture basis consumed inside a canonical cycle. It
is a library/conformance specimen, not a second production CLI.

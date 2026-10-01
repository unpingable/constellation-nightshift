# Nightshift newcomer guide

Nightshift keeps recurring and deferred work tied to current conditions. It
records observations, checks whether the evidence can still be relied on, and
prepares proposals for work when the configured conditions support them.
It does not grant permission or execute the work: AG decides permission,
Docket manages the attempt, and NQ supplies the diagnostic evidence.

Use Nightshift when an old observation must not silently justify a new run.
It also keeps the history needed to explain why work was proposed, deferred,
or needs another check. A completed run means checking current conditions
before proposing another one, not displaying the completed run as unfinished.

The public repository is **constellation-nightshift**. Preserve the existing
`nightshiftd` crate, executable, store, and protocol names.

## Current status

The canonical C1 production graph contains exactly two executables:
`nightshift`, the observation-cycle runtime, and
`nightshift-observation-resolver`, a one-shot read-only translator used by AG.
Historical design and Watchbill material remains for archaeology but is not a
second runtime. Wicket/WLP, classic Governor, drill paths, and prose-action
paths are absent from the production graph.

“Canonical production runtime” names the implemented boundary, not an
operational qualification claim. A deployment must provide NQ-NG and AG ports
and a real present-evidence support authority. Nightshift defines the
`pulse-support-resolver` grammar but does not ship a production support source
or resolver. Its similarly named fixture qualifies only the process boundary.
See the [canonical C1 contract](CANONICAL_RUNTIME_C1.md) and
[present-evidence source gate](PRESENT_EVIDENCE_SUPPORT_SOURCE_GATE.md).

## Build and inspect from source

From the repository root:

```sh
cargo build --locked --release --bins
./target/release/nightshift --help
./target/release/nightshift cycle --help
```

Building or displaying help creates no observation cycle and grants no
authority. Existing local state is inspected with:

```sh
./target/release/nightshift \
  --store /absolute/path/nightshift.sqlite \
  cycle list

./target/release/nightshift \
  --store /absolute/path/nightshift.sqlite \
  cycle show --cycle-id '<cycle-id>'

./target/release/nightshift \
  --store /absolute/path/nightshift.sqlite \
  cycle replay --cycle-id '<cycle-id>'
```

`cycle show`, `list`, and `replay` do not originate work. A real `cycle run`
requires a sealed request, the exact NQ executable/config/source identity, and
the deployment's present-evidence resolver. AG coordinates are additionally
required only when the request contains an exact precompiled proposal. Review
the full command and port contract in the [operator guide](operator/README.md)
before supplying those paths.

## Standalone and composed use

Nightshift is useful alone for durable observation-cycle history, recurrence,
attention evaluation, deterministic replay, and read-only external-observation
custody. Those surfaces can make temporal obligations and stale evidence
legible without authorizing or executing anything.

Composed with NQ-NG, Nightshift consumes admission provenance and a complete
diagnostic posture. It may prepare one exact proposal for AG. AG independently
resolves present evidence and standing, then may authorize that exact
occurrence. Docket independently owns custody and settlement. A settlement
moves Nightshift to `ObservationRequired`; only a fresh qualified observation
can change subject posture.

The [runtime flow](CANONICAL_RUNTIME_C1.md#runtime-flow) and
[four-office pilot](FOUR_OFFICE_PILOT_01.md) show those boundaries. The pilot
is evidence of one exercised composition, not a general deployment promise.

## Authority and trust boundary

Nightshift owns recurrence, the observation-cycle state machine, its SQLite
history, and proposal/currentness bookkeeping. It owns no effect authority and
has no executor surface. Proposal recording, AG status synchronization,
restart recovery, transport locators, and stored evidence cannot mint or renew
authorization.

The deployment still trusts the observation resolver and present-evidence
authority for their facts; the request sealer and its time coordinate; the
standing and Docket execution-standing authorities; NQ-NG deployment and
store-genesis identity; Maude session/handoff credential custody; configured
paths; and relevant clock/TTL behavior. A principal able to alter those
components or the local store remains outside Nightshift's internal checks.
Nightshift does not prove external truth or open-world completeness.

## Formal and qualification claims

Current Lean work does not prove end-to-end runtime conformance. The
observation-adequacy certificate and large source-level verdict comparison are
executable qualification evidence, not Lean theorems. Resolver designation,
standing truthfulness, host custody, and deployment correctness remain
premises. The exact nonclaims are in the
[C1 contract](CANONICAL_RUNTIME_C1.md#nonclaims); evidence-retention and
requalification rules are in
[qualification and steady-state evidence](QUALIFICATION_AND_STEADY_STATE_EVIDENCE_V1.md).

## Recovery

Restart retains historical facts but erases the non-serializable live witness
used to prepare work. Locally observing or posture-recorded cycles become
`RecoveryRequired`. A prepared AG occurrence is recovered only by exact AG
status inspection and is never resubmitted by Nightshift:

```sh
./target/release/nightshift \
  --store /absolute/path/nightshift.sqlite \
  cycle recover --help
```

Recovery, retry, and settlement do not recreate currentness or authority.
Follow [Store and recovery](CANONICAL_RUNTIME_C1.md#store-and-recovery) and the
[operator restart procedure](operator/README.md#restart-and-ag-status).

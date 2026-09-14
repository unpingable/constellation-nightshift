# Night Shift

New here? Read the [Nightshift newcomer guide](docs/PUBLIC_GUIDE.md) for the
public-main source-build, read-only inspection, and qualification boundaries.

Deferred agent work with receipts, reconciliation, and governed promotion.

> Let agents work late without giving them the keys.


## Two source workspaces

The additive [`runtime/`](runtime/) workspace is the source-pinned canonical
cycle and Foreman runtime. Its exact inputs are recorded in
[`runtime/SOURCE-PROVENANCE.json`](runtime/SOURCE-PROVENANCE.json); see the
[`runtime` custody guide](runtime/docs/BOUNDED_PROVIDER_CUSTODY_V1.md).
Build it with `cargo build --locked --manifest-path runtime/Cargo.toml`.
The distributed focused test gates cover Foreman and attention replay:

```sh
cargo test --locked --manifest-path runtime/Cargo.toml -p nightshift-foreman
cargo test --locked --manifest-path runtime/Cargo.toml -p nightshiftd --lib project_predicate_attention
cargo test --locked --manifest-path runtime/Cargo.toml -p nightshiftd --bin nightshift exact_input_tests
```

[Attention replay](runtime/docs/ATTENTION-REPLAY-STDIN.md) lets an embedding
tool check an exact retained decision through a file or bounded standard input.
It does not send a notification or refresh the underlying evidence.
Workspace-wide and Casework test suites require fixture inputs not distributed
in this source cut.

The repository-root workspace is the predecessor command set documented below.
Its Diagnostics, Watchbill, Runs, NQ, Liveness, and agenda-keyed Attention
commands are not aliases for the canonical runtime. Existing immutable
revisions continue to retain that predecessor source.

## Status (2026-07-26)

Night Shift is the **proposal and read-only orchestration office** of a
four-office governed constellation (authority: AG ng; governed execution:
Docket; testimony/claims/reliance: NQ). It owns agenda-driven review packets
(advisory proposals that bind intent only — never file lists, content bytes,
or authority), consumption of NQ's published machine contracts, read-only
dispositions, and a gate-enforced no-actuation boundary with declared bounded
diagnostics. It does **not** own authority, execution, or evidence
evaluation.

Terminology note: "Governor" in this repository names the **authority role**.
The classic Python implementation (`agent_gov`) is the legacy office —
retained here only as a bounded-diagnostic drill dependency and an optional,
disabled-by-default RPC wire; the canonical authority implementation for new
work is **AG ng** (Rust), which authorized the completed four-office pilot.

Maturity: part of an **operationally reusable governed vertical** (first
four-office pilot completed 2026-07-26 with this repository as its target);
**not operator-ready** — file-granular proposals remain a library face and
the deployment files are reference scaffolding, not a packaged service. A
supported receiver-side `nq disposition` CLI consumes externally prepared NQ
machine artifacts and emits a read-only disposition. No support promise is
made beyond what the tests and gates in this repository demonstrate.

Night Shift schedules and resumes *intent*, not commands. A cron job says
"run this command at this time." Night Shift says "resume this intention
under this policy with this context and produce this kind of artifact."

It is allowed to be useful before it is trusted with force.

Night Shift does not make incidents go away. It refuses to close the loop
until the witnesses needed for closure exist.

## Build from source

Night Shift is currently a source workspace, not an installed package. A
build requires:

- Git, to obtain this repository and its source dependencies;
- a stable Rust toolchain with Cargo, Rust 1.82 or newer;
- a native C compiler and linker for the bundled SQLite build; and
- network access to crates.io on the first build, unless the Cargo cache is
  already populated or dependencies are supplied by another approved means.

The current Cargo contract uses sibling path dependencies. Keep compatible
`wicket` and `wlp` source trees beside the Night Shift checkout:

```text
<source-parent>/
├── nightshift/
├── wicket/
└── wlp/
```

The directory names and relative placement are load-bearing today:
`nightshift/Cargo.toml` resolves `../wicket` and `../wlp`. Night Shift does
not fetch, discover, or install those repositories. From `nightshift/`:

```bash
cargo build --locked --release
./target/release/nightshift --help
```

NQ is also an external runtime dependency for live finding, liveness, and
reliance reads; it is not built by this workspace. For operational runs,
inject the installed `nq-monitor` executable with the global
`--nq-bin /absolute/path/to/nq-monitor` option or the
`NIGHTSHIFT_NQ_BIN` environment variable. `nq disposition` requires one of
those two forms. Finding/liveness reads retain a legacy fallback to an
executable named `nq` on PATH, but explicit injection is the reproducible
deployment contract.

## 30-second specimen: the refusal

A review packet is only as good as the witness it was reconciled against.
If the NQ liveness witness has gone silent, Night Shift does not produce a
slightly-worse packet — it halts before consulting any findings, and the
packet says so.

Everything below runs from this repo with no live NQ. The finding source
is the checked-in fixture manifest; the stale witness is replayed through
the documented `--nq-bin` override:

```bash
cargo build --locked --release

# A stale liveness witness: age_seconds 600 vs the 90s default threshold,
# replayed by a stub standing in for the real `nq-monitor` executable.
mkdir -p /tmp/ns-specimen
cat > /tmp/ns-specimen/stale-liveness.json <<'EOF'
{
  "schema": "nq.liveness_snapshot.v1",
  "contract_version": 1,
  "instance_id": "labelwatch-host",
  "witness": {
    "generation_id": 43755,
    "generated_at": "2026-04-20T17:38:17.064301118Z",
    "schema_version": 29,
    "status": "ok",
    "findings_observed": 9,
    "findings_suppressed": 0,
    "detectors_run": 3,
    "liveness_format_version": 1
  },
  "freshness": { "age_seconds": 600, "stale_threshold_seconds": null, "fresh": null },
  "source": { "artifact_path": "/opt/notquery/liveness.json", "artifact_kind": "file" },
  "export": { "exported_at": "2026-04-20T17:38:42.546651838Z", "source": "nq", "contract_version": 1 }
}
EOF
printf '#!/bin/sh\ncat /tmp/ns-specimen/stale-liveness.json\n' > /tmp/ns-specimen/nq-stub
chmod +x /tmp/ns-specimen/nq-stub

./target/release/nightshift \
  --store /tmp/ns-specimen/demo.sqlite \
  --nq-liveness /tmp/ns-specimen/stale-liveness.json \
  --nq-bin /tmp/ns-specimen/nq-stub \
  watchbill run \
  --finding "nq:wal_bloat:labelwatch-host:/var/lib/labelwatch.sqlite" \
  tests/fixtures/wal-bloat-review.yaml
```

The run halts at the liveness gate. The packet it emits is a refusal, not
a diagnosis:

```yaml
reconciliation_summary:
  admissible_for_authorization: []
  admissible_for_proposal: []
  admissible_for_diagnosis: []
  blocked:
  - 'liveness_gate: liveness stale: witness silent for 600s (threshold 90s)'
  ok_to_proceed: false
diagnosis:
  regime: 'stale: NQ liveness gate did not clear; no findings consulted'
proposed_action:
  kind: advisory
  steps:
  - 'revalidate the NQ liveness artifact: confirm the publisher/aggregator is healthy …'
  - if witness clock is skewed, resolve clock sync before retrying
  - rerun this watchbill once liveness is current
  risk_notes:
  - 'no remediation proposed: liveness gate failure is not a basis for action'
  - no NQ findings were consulted on this run
authority_result:
  governor_verdict: not consulted — liveness gate halted the run
```

Drop the `--nq-liveness`/`--nq-bin` flags and the same command emits a
normal packet from the fixture findings: `ok_to_proceed: true`, the finding
admissible for diagnosis, proposal, and authorization. `run_id`,
`packet_id`, and `produced_at` are run-dependent; the refusal shape is not.

## Starting point: governed ops review packets from real NQ findings

The MVP is narrow and real. Replace every placeholder with an operator-owned
path or key:

```bash
NIGHTSHIFT_NQ_BIN=/absolute/path/to/nq-monitor \
./target/release/nightshift \
  --store /absolute/path/to/nightshift.sqlite \
  --nq-db /absolute/path/to/nq.db \
  watchbill run \
  /absolute/path/to/agenda.yaml \
  --finding '<finding-key>'
```

1. Read current NQ findings
2. Assemble context bundle from captured agenda
3. Reconcile: compare captured state vs. current state
4. Run bounded diagnosis workflow
5. Emit a repair proposal packet
6. Record run events locally. **Governor receipts are emitted only when
   `--horizon-policy` *and* `--governor-socket` are both passed**; the
   default invocation is governor-blind by design (see [Authority model](#authority-model)
   below — `observe` and `advise` levels may run without Governor).
7. No mutation. No sudo. No cowboy shit.

Ops mode (Watchbill) is first because it pressure-tests the authority
boundary on low-blast-radius work before anything heavier gets built on
top of it.

## Future modes

- **Code mode**: Deferred coding sessions that produce reviewable diffs,
  branches, and reports — not automatic merges.
- **Publication mode (Atlas Runner)**: Recurring scans and candidate
  updates for public observatories (Grid Dependency Atlas, feeds, static
  sites) with claim-checked receipts.

Build order: ops → code → publication. Most Governor-demanding to most
audience-legible.

## What this is not

- Not cron. Cron executes; Night Shift intends, and the intention must
  survive a gauntlet before it touches anything real.
- Not Governor. Governor owns authority and permission boundaries.
  Night Shift owns scheduling, context, and promotion.
- Not an autonomous agent framework. The agent is the intern with
  astonishing confidence and no legal personhood.

## Core primitives

| Primitive | What it is |
|-----------|-----------|
| **Agenda** | Declared deferred intention: task, mode, cadence, owner, scope, promotion ceiling |
| **Bundle** | Captured context with admissibility: inputs, freshness, standing |
| **Reconciler** | Freshness/invalidation pass before execution begins |
| **Watchbill** | Ops-mode roster of recurring operational agendas |
| **Packet** | Reviewable output artifact (diff, report, proposal) |
| **Run ledger** | Append-only record of scheduler lifecycle events |

## The three ladders

These are distinct. Keep them distinct.

**Lifecycle phases** — where a run is:

```text
capture → reconcile → plan → review → run → verify → record
```

**Authority levels** — what a run is allowed to do:

```text
observe → advise → stage → request → apply → publish → escalate
```

**Artifact kinds** — what a run produces:

```text
receipt | packet | diff | report | page | publication_update
```

A run moves through lifecycle phases, but it cannot exceed its configured
authority level. Artifacts are recorded through both.

## Architecture

```text
NQ / Driftwatch / Labelwatch
        |
   Night Shift
        |
  agenda + context bundle
        |
  reconcile (revalidate premises)
        |
  agent/interferometry workflow
        |
  proposal / diff / repair packet
        |
  Governor hook boundary
        |
  receipted action or review artifact
```

**Night Shift** schedules and resumes intent. **Governor** authorizes
force. **NQ** provides evidence. **The agent** produces proposals under
constraint.

## Separation of concerns

- **Night Shift owns**: when, why, what context, what constitutes success;
  the run ledger records lifecycle events
- **Governor owns**: whether, under what authority, what must be recorded;
  authority receipts record permission decisions
- **NQ owns**: what is observed, failure classification, persistence
  tracking
- **Agent owns**: interpretation, proposal generation (never direct
  mutation)

Night Shift records run events; Governor emits authority receipts. A run
may contain many receipts, but Night Shift does not manufacture authority
by logging itself.

## Authority model

Governor requirement by authority level:

```text
observe     may run without Governor
advise      may run without Governor, emits unsigned/local receipts
stage       requires Governor
request     requires Governor
apply       requires Governor
publish     requires Governor
escalate    configurable, receipts through Governor when available
```

Night Shift without Governor is degraded / unsafe / demo-only. The
coupling is conceptual, not accidental: deferred intent is dangerous
because authority drifts over time. Governor exists to prevent intent
from becoming unauthorized force.

**Don't trust the agent. Trust the boundary.**

## MCP role

MCP is capability discovery and tool transport. It tells Night Shift what
tools exist and provides a normalized way to call them. **Tool
availability is not permission.**

MCP call classes:

```text
discover   list tools/resources           local policy may allow
read       fetch state                    local policy may allow
propose    produce candidate action       local policy may allow
stage      prepare mutation               requires Governor
mutate     change state                   requires Governor
publish    expose public artifact         requires Governor
page       wake human                     requires Governor (receipt)
```

Every non-local-policy call passes through an authority checkpoint:

```text
Night Shift agenda
  → reconcile context
  → choose proposed MCP tool call
  → Governor policy check
  → MCP invocation
  → result capture
  → Governor receipt
```

## Continuity role

Continuity is an optional context provider, not an authority source.

Continuity inputs enter the bundle as **observed context**. They become
**relied-upon** only after the Reconciler evaluates them against current
evidence, scope, and freshness.

> Continuity can explain why an agenda exists. It cannot prove that
> an action is allowed.

Recheck is the gate, not metadata. Every Continuity input passes through
the Reconciler by virtue of the pipe it enters on — there is no
per-input "requires_recheck" flag that can be forgotten.

Safety must not depend on Continuity. If Continuity is unavailable,
Night Shift should still be able to reconcile current evidence, respect
promotion ceilings, emit packets, and route all promoted actions through
Governor.

> Optional context, never authority.

## Dependency classes

Night Shift distinguishes **safety dependencies** from **intelligence
dependencies**.

**Safety dependencies** (hard) — constrain authority; when unavailable,
Night Shift fails closed or lowers the promotion ceiling:
- Governor (required for `stage | request | apply | publish`)
- Evidence adapter (NQ for ops; git/fs for code)
- Run ledger

**Intelligence dependencies** (soft) — improve quality; when
unavailable, Night Shift continues with degraded output:
- Continuity (prior decisions, cross-run memory)
- MCP (tool discovery/transport)
- LLM / interferometry (hypothesis generation)

> Missing intelligence dependencies must never increase authority.

## Build tiers

1. **Core** — agenda + bundle + reconciler + run ledger + packet.
   Useful, safe, boring. Cannot mutate.
2. **Governed** — Core + Governor adapter + authority receipts +
   promotion gates. The real product.
3. **Constellation** — Governed + NQ + Continuity + MCP + observatory
   adapters. Ecosystem mode.

## Language

v1 is Rust-only. The single crate `crates/nightshiftd` houses the
scheduler, agenda state machine, reconciler, run ledger, packet
emission, NQ + liveness consumption, horizon logic, and the
Governor JSON-RPC client.

The DESIGN.md Rust+Python split is preserved as the architectural
target for Code mode (deferred coding sessions that emit reviewable
diffs). When that ships, Python workflows will be invoked as
controlled subprocesses under a hardened boundary: they read
context JSON and emit proposal JSON — never production credentials,
mutable tool handles, or unrestricted shell. Night Shift and
Governor decide whether any proposed operation is staged, applied,
or published.

## NQ as a reliance source

Night Shift consumes NQ's published machine contracts — `nq.finding_snapshot.v1` and
`nq.reliance.receipt.v1` — and proposes a **read-only disposition**. NQ decides what a
configured consumer may rely upon; Night Shift decides what posture to propose next.
Neither executes anything, and Night Shift's consumer binding is locally configured, not
authenticated.

The supported receiver CLI is:

```bash
NIGHTSHIFT_NQ_BIN=/absolute/path/to/nq-monitor \
./target/release/nightshift nq disposition \
  --request /absolute/path/to/request.json \
  --receipt /absolute/path/to/receipt.json \
  --profiles /absolute/path/to/profiles.json \
  --format json
```

`--evidence` is optional and `--supporting` is repeatable. The request,
sealed primary receipt, profile catalog, evidence context, and supporting
receipts are prepared outside Night Shift. Night Shift passes their paths to
NQ; it does not create, complete, or reinterpret them. Exit zero means a
disposition record was derived and can include `stop`—the JSON record, not
the shell status, carries the result.

The distinction the integration exists to hold: **a fresh NQ refusal is NQ testimony; no
fresh NQ response is Night Shift's own timeout observation.** No synthetic NQ receipt is
ever fabricated for the second case. A typed refusal for missing supporting
testimony is likewise NQ speaking; it remains distinct from Night Shift
observing no response.

See the [operator quick start](docs/operator/README.md) and
[`docs/NQ_RELIANCE_SOURCE.md`](docs/NQ_RELIANCE_SOURCE.md).

The first governed four-office pilot (Night Shift proposal → Docket preparation →
AG authorization → Docket execution → NQ evaluation) is declared in
[`docs/FOUR_OFFICE_PILOT_01.md`](docs/FOUR_OFFICE_PILOT_01.md) and **completed
2026-07-26** — the commit adding that document was itself the pilot's governed
effect, authored by Docket's broker. The honest terminal outcome was a
read-only `stop` disposition; detailed receipts are privately retained, and
the pilot document is deliberately left exactly as written before execution.

## License

Licensed under Apache-2.0.

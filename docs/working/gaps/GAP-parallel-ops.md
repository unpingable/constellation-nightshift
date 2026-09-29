# GAP: Parallel Operations / Cross-Session Coordination

> Status: identified. Directly motivated by live and past experience:
> two agents (or humans, or mixed) acting on overlapping scope
> without shared view — even when a shared substrate exists.

## Core problem

Classic Night Shift failure mode:

> Claude executes a double live migration, updates zero memories,
> user has to audit him mid-flight.

Generalized: multiple actors (sessions, agents, operators, cron jobs)
work on overlapping scope. Each has local context. None has the
others'. A shared substrate (Continuity) may be *hooked in* and still
not be *used*. Scope changes don't propagate. Reconciliation runs
against a world that already moved.

This is different from:

- **Attention state** (`GAP-attention-state.md`): a single operator's
  intent decays without a half-life.
- **Staleness** (`GAP-escalation.md` trigger 4): captured inputs are
  no longer current against an external source of truth.

This failure mode is specifically: *another actor's work has changed
the scope, and nobody told us.*

## Ritualized recall

The failure mode this doc exists to prevent is not *forgetting*. It
is *failing to ritualize recall*.

Every operations team figured this out: channels, bridge notes, shift handoffs,
incident commander handoffs. Those primitives existed because without
them, locally-rational actors manufacture global incoherence.

> The failure is not lack of intelligence. It is lack of ritualized
> recall.

Night Shift's job is not to make the substrate smarter. It is to
make *consulting the substrate* a structural step, not an act of
operator virtue.

The motivating meta-irony is worth preserving explicitly:

> The coordination channel existed; neither agent consulted it. The
> framework that would have caught the incident was the framework
> already in place. Memory was available; it was not queried.

That is the failure mode. Memory availability does not imply memory
consultation. Night Shift promotes consultation from habit to
structure.

## Scope overlap types

```text
disjoint          no shared hosts / services / paths — no coordination required
shared_read      overlapping read scope, no mutation — coordination nice-to-have
shared_write     overlapping mutation surface — coordination required
contested        two actors attempting mutually-exclusive actions — must resolve before proceeding
```

The reconciler must classify; actors do not get to self-declare
`disjoint`.

## Reconciler protocol extension

Capture and reconciliation both grow a concurrent-activity check.

### At capture

The bundle gains an input:

```yaml
- input_id: continuity:concurrent_activity:scope:<scope_key>
  source: continuity
  kind: concurrent_scope_activity
  status: observed
  evidence_hash: sha256:...
  freshness:
    invalidates_if:
      - concurrent_actor_transitioned_state
      - concurrent_actor_opened_new_scope_overlap
  payload_ref: continuity://query:scope=<scope_key>,window=<T>
```

`<scope_key>` derives deterministically from the agenda's declared
scope (hosts × services × paths × repos).

### At reconciliation

The reconciler classifies overlap and records it:

```yaml
- input_id: continuity:concurrent_activity:scope:<scope_key>
  status: committed
  reliance_class: authoritative_for_coordination   # narrow — see two-layer model below
  scope:
    run_id: run_...
    valid_for: [coordination_gating, diagnosis, packet_context]
  concurrent_activity:
    actors:
      - actor_id: labelwatch-claude/mem_c1a452f0
        session: case:volume-migration-2026-04-17
        touched_at: 2026-04-17T13:42:00Z
        scope_overlap: shared_write
        last_breadcrumb: "nq-publish turned down; pending nq-claude"
    overlap_class: shared_write              # disjoint | shared_read | shared_write | contested
    coordination_outcome: hold_for_context   # clear | hold_for_context | coordinate |
                                             # block_for_resolution | operator_override
```

The `coordination_outcome` is not advisory. It gates promotion.

## Two-layer authority model

The concurrent-activity check is narrowly authoritative and must be
encoded carefully. Continuity cannot become a truth oracle via the
coordination channel.

Split the reliance story into two layers:

- **Coordination-gating authority (narrow):** the *fact* that
  overlapping activity exists in a given scope, and its
  *classification* (`disjoint / shared_read / shared_write /
  contested`), are authoritative **for coordination decisions only**.
  They gate whether the run may leave capture. They do not
  authorize policy, mutation, or ground truth claims.
- **Breadcrumb content (hint):** the payload of any individual
  breadcrumb — another actor's note, disposition, summary — is
  `observed` / `hint` material. It may *inform* a proposal or a
  packet but may not ground authorization or substitute for current
  evidence.

In schema terms this maps to:

```text
reliance_class: authoritative_for_coordination    # overlap existence + classification
valid_for:      [coordination_gating, diagnosis, packet_context]

breadcrumb payloads:   reliance_class: hint
                       valid_for: [diagnosis, packet_context]
```

> Continuity is authoritative about who else is here.
> Continuity is not authoritative about what is true.

Without this split, the coordination channel would smuggle
authority through the side door — exactly the failure mode
`DESIGN.md`'s Continuity rules are written to prevent.

## Risky classes of work

Default-query-on-capture is sufficient for routine scope. Some
classes of work require a stronger form — **preflight** — in which
Continuity is a gate, not a background signal.

Risky classes:

- **Shared-infrastructure ops.** Scope includes any resource other
  actors routinely touch (shared hosts, shared data paths, shared
  publishers, shared collectors).
- **Topology / config / publisher / source changes.** Anything that
  rewrites where observers look or what they can see.
- **Mode transitions.** A session crossing incident → remediation,
  remediation → architecture, or any crossing that changes the
  success condition. See `GAP-incident-modes.md`.
- **Protected-class scope.** Observation-critical or control-plane-
  critical services in read or write scope.
- **Unresolved breadcrumb in scope.** Another actor has filed a
  `run.surprise` or `run.partial` in this scope that has not been
  closed within the freshness window.

## Preflight check

Triggered at the boundary between capture and reconcile, before any
input is promoted from `observed` to `committed`. For risky classes
the run cannot leave capture without one of the following
`coordination_outcome` values:

```text
clear                   no risky concurrent activity; proceed
hold_for_context        overlap exists; surface and wait for clarity
coordinate              named actor has overlapping scope; handoff required
block_for_resolution    overlap_class = contested; cannot proceed until
                        scope is no longer contested (other actor stands
                        down, completes, or is removed)
operator_override       named operator explicitly accepts a hold_for_context
                        or coordinate outcome and continues
```

`coordination_outcome` is the single shared vocabulary used by both
reconciliation (for all runs) and preflight (the strong form for
risky classes). They are not separate enums.

Mapping from overlap class to outcome:

```text
disjoint              → clear
shared_read           → clear (ordinary) | hold_for_context (risky class)
shared_write          → hold_for_context | coordinate
contested             → block_for_resolution
```

Invariants:

- `operator_override` may override `hold_for_context` or `coordinate`.
  It **may not** override `block_for_resolution`. Contested scope is
  terminal until the contest resolves — an override cannot un-contest
  the world.
- `operator_override` must carry a named operator identity and a
  reason. It is a receipt-generating event; no silent override.
- Missing Continuity in a risky class yields `hold_for_context` at
  minimum; may be upgraded to `coordinate` if the agenda declares
  `shared_infrastructure: true`.
- Preflight outcome is audit material: `run.preflight_cleared`,
  `run.preflight_hold`, `run.preflight_coordinate`,
  `run.preflight_blocked`, `run.preflight_override` breadcrumbs are
  emitted in all cases.
- Preflight is pre-Governor. An `operator_override` at preflight
  does not authorize mutation; Governor still gates force.

## Continuity-as-substrate invariant

> Continuity availability is not Continuity use.

Parallel to *"MCP is transport, not authority."* A hooked-in substrate
that isn't queried is a silent hazard. Night Shift does not trust
workflow authors to remember to ask; the reconciler queries Continuity
for concurrent activity in the declared scope **by default**, and the
run ledger writes observational breadcrumbs to Continuity **by default**.

Practically (when Continuity is configured):

- **Read**: reconciler queries Continuity for concurrent activity
  keyed on scope. Missing Continuity is handled per standard soft-
  dependency rules for ordinary runs (never raises authority; may
  require advise-only). For risky classes, missing Continuity
  triggers `hold_for_context` — see preflight rules below.
- **Write**: run ledger emits breadcrumbs on key transitions
  (capture, surprise, partial completion, escalation, terminal
  result), not only on run completion.

When Continuity is **not** configured (standalone / Core-tier
deployments per `DESIGN.md`):

- The run ledger mirrors breadcrumbs locally. Ordinary runs proceed
  with degraded coordination posture surfaced in the packet.
- Risky-class runs cannot clear preflight without Continuity; they
  hold or downgrade unless an `operator_override` is issued.

The "by default" defaults apply only where the substrate exists.
Saying Night Shift "writes to Continuity by default" does not
retroactively make Continuity mandatory for Core-tier standalone
operation.

## Breadcrumb cadence

> File a memory after each major surprise, not just at the end.

*— labelwatch-claude, self-reflecting after the fact*

End-of-run receipts are inadequate for parallel ops. If another actor
is mid-flight, they need to see your scope change *now*, not when
your run terminates. Required breadcrumb events:

```text
run.captured              scope + agenda + intent
run.surprise              anything not in the bundle happened (layout changed,
                          service is down, a dependency moved)
run.partial               mutation attempted and partially succeeded
run.escalated             run stopped with operator-required next step
run.completed             terminal state + summary
run.attention_changed     operator touched attention state for any finding in scope
```

Breadcrumbs are observational, not authoritative. They live in
Continuity as `observed` entries. Other actors' reconcilers may
*admit* them as hints — never as authorization.

### Scope expansion on `run.surprise`

A `run.surprise` that changes **material scope** (the run discovers
it has touched or will touch a host, service, path, or repo not in
the declared scope) triggers more than a breadcrumb:

1. Recompute the scope key from the expanded scope tuple.
2. Re-run the concurrent-activity check against the new key.
3. Re-classify overlap and re-evaluate `coordination_outcome`.
4. If the new outcome is weaker than `clear` (for ordinary runs) or
   fails preflight (for risky classes), the run holds or escalates
   at the boundary.
5. Emit `run.scope_expanded` breadcrumb with both old and new
   scope keys.

A run must not continue under the old scope key after material
scope expansion. Otherwise the coordination substrate still thinks
it's watching the smaller footprint while the run is quietly touching
more.

> A surprise that changes scope is not a note. It is a re-capture.

## Breadcrumb latency

> **v2 concept.** v1 Watchbill emits breadcrumbs at fixed events
> (`run.captured`, `run.surprise`, `run.completed`, preflight
> variants) and does not track latency. The metrics and self-review
> affordances below are v2+; they are recorded here so they don't
> have to be rediscovered.

The time between *surprise-landing* and *surprise-filed* is itself a
signal. A well-behaved session files near the event. A session that
only files at end-of-run has compressed every surprise into one
retrospective blob, losing detail and losing the window where other
actors could have benefited.

Tracked per session:

```text
surprise_filed_latency_p50 / p95       for breadcrumbs of kind `run.surprise`
filed_at_end_of_run_ratio              fraction of surprises only captured in terminal summary
```

Night Shift surfaces these in operator self-review. They are not
punitive metrics; they are diagnostic — a rising latency is a signal
that in-flight reflection is decaying, which tends to precede
coordination failures.

> The failure mode is not that breadcrumbs are missing. It is that
> they are all stamped `end_of_run`.

## Natural breakpoints

> **v2 concept.** v1 does not emit breadcrumb prompts. The natural-
> breakpoint list below is specification for the active-nudging
> watcher introduced in v2.

Night Shift does not *require* operators to file breadcrumbs at
arbitrary intervals. It prompts at structurally meaningful moments —
natural breakpoints where capturing cost is low and recall is still
sharp:

```text
surprise resolved               an unexpected finding has a disposition (fixed / deferred / escalated)
service restart verified        a restart or re-point has confirmed post-condition
quiesce window reached          a pause or cooldown gate has fired
dependency interaction          an adjacent service has been touched or re-pointed
authority transition            attention state changed (acked, investigating, handed_off)
phase transition                incident state advanced (see GAP-incident-modes.md)
```

At each, Night Shift may emit a **breadcrumb prompt**: a low-friction
suggestion to file a short observation, scoped to the just-completed
event. The prompt is optional; the *prompt event* itself is logged so
the not-filed case is visible.

## Passive watching, active nudging

> **v1 is passive-only.** Active nudging (session-attached watcher
> that emits breadcrumb prompts at natural breakpoints) is v2+.
> v1 Watchbill relies entirely on the passive substrate — reconciler
> queries Continuity, run ledger writes breadcrumbs at fixed events,
> operator writes when they choose. The active mode's opt-in
> semantics below are forward-looking.

Night Shift can operate as a passive substrate (reconciler queries
Continuity; operator writes when they remember) or as an active
partner (session-attached watcher that emits breadcrumb prompts at
natural breakpoints). The active mode is opt-in per session, not
default, because:

- active nudging risks becoming interruption theatre
- the operator's judgment about "major" still governs what's worth
  capturing
- the watcher's job is to *lower the friction of filing*, not to
  enforce filing

A nudged-but-not-filed event is still a useful signal. It tells
Night Shift the operator saw the moment and declined, which is
different from the operator never seeing it.

## Invariants

- **Continuity availability is not Continuity use.** Hooked in ≠ used.
  The reconciler queries by default; the run ledger writes by default.
- **No `disjoint` self-declaration.** Overlap classification is the
  reconciler's job, grounded in declared scope.
- **`contested` is terminal until resolved.** If two actors hold
  overlapping mutation intent in the same scope, Night Shift escalates
  rather than racing.
- **Breadcrumbs are observations, not authority.** Another actor's
  run log may inform this run's proposal; it may not authorize it.
- **Missing Continuity is a soft dependency.** Follows standard rule:
  may lower promotion ceiling; never raises authority; never
  fabricates authorization.

## Failure modes this prevents

- Two sessions silently racing a migration
- One session's "this is handled" invisible to another session
- Reconciliation passing because the bundle's inputs matched, while
  the world changed between runs via a different actor
- Continuity hooked in but only written to at end-of-run, when it's
  too late to warn anyone

## Failure modes this does NOT prevent

- Actors not on Continuity at all (outside the substrate entirely)
- Actors writing breadcrumbs to Continuity but lying in them
- Operators acting directly against a host outside any Night Shift run

Those are out-of-band. Coordination only covers the actors inside the
substrate. Anyone outside it is a scope-overlap risk the reconciler
cannot see.

## Interaction with attention-state

Another actor's recent transition of attention state for a shared
finding shows up in the concurrent-activity check. If labelwatch-
claude marked `investigating` on a shared finding, nq-claude's next
Night Shift run must see that and decide: defer, coordinate, or
escalate `contested`.

Attention state in Continuity is subject to the same TTLs and ack
expiry rules as local attention state. An expired-ack breadcrumb does
not suppress re-alert.

## Interaction with Governor

Governor authorizes force in a single run. Parallel-ops coordination
is *pre*-Governor: the reconciler's scope-overlap classification
happens before any authorization request. If the overlap class is
`contested`, Night Shift does not ask Governor for authorization;
it escalates for operator resolution first.

Governor may still be asked to *log* the escalation as a receipt.

## Interaction with `--no-governor` degraded mode

Parallel-ops check is orthogonal to Governor. Without Governor,
Night Shift still queries Continuity for concurrent activity and
still writes breadcrumbs. Degradation lowers authority, not
coordination.

## Open questions

- What defines the scope key? (Canonicalized scope tuple: hosts ×
  services × paths × repos. Deterministic hash so different actors
  hash the same scope identically.)
- How long is the concurrent-activity window? (Probably agenda-
  declared, default 24h; longer for `safety`-class agendas.)
- What if Continuity disagrees with NQ about what's happening in
  scope? (Reconciler treats them as separate sources; evidence-conflict
  trigger in `GAP-escalation.md` applies.)
- Do breadcrumbs need receipts? (Probably not individually; the run
  ledger's emission of the breadcrumb is the receipt. But the ledger
  event itself must be receiptable.)
- How does this interact with multi-tenant v3 deployments? (Scope
  keys must include a tenant boundary; cross-tenant concurrent-activity
  check is a trust decision, not a coordination one.)

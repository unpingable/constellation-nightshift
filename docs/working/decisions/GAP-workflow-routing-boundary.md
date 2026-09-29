# GAP: Workflow Routing Boundary

> Status: candidate / proposed doctrine. Filed 2026-05-05 to capture
> a cross-tool routing boundary before constellation tools (NQ, Night
> Shift, Standing, Verifier, Governor, Continuity) start manufacturing
> overlapping vocabulary in private. **No implementation.** No packet
> schema. No code. This is a doctrinal record so the boundary has a
> handle for review. A record is not authorization to build.

## Why this is named now (YAGNI posture)

Cross-tool routing is exactly the kind of architectural surface where
retrofit cost rises with usage spread. If "which tool is allowed to
interpret this state, which one is allowed to bind it, and which one
is only allowed to remember that it happened" gets answered locally —
each tool inventing its own dispatch logic — the constellation grows
several almost-agreeing routers and a permanent class of "this event
should have gone to X, but Y consumed it instead" failures.

That class of failure is what operations practice calls *routing by vibes*:

> "This smells like Night Shift."
> "This feels like Governor."
> "This probably belongs in Continuity."

Routing by vibes works while a human is the router. It collapses the
moment the tools are making the calls.

This GAP names the boundary now so that, when the constellation has
enough tools online to need a router, the doctrine is already in place
and not invented under deadline. Naming the candidate is cheap;
ratifying it lazily is the discipline.

## Keeper lines

Six load-bearing lines. If the rest of this doc evolves, these stay:

> **Route by claim type, not by tool identity.**

> **Night Shift routes obligations, not authority.**

> **Deferred obligation is not deferred authorization.**

> **Verification is not permission.**

> **Memory is not testimony.**

> **Standing is necessary, not sufficient.**

Each is unpacked in a section below.

## Tool roles in the constellation

For routing purposes, each tool's *competence* is named explicitly.
A tool may be invoked outside its competence, but only as transport
or recording — never as the binding authority on the question.

```text
NQ           testifies about world state
             "what is true / what changed / what cannot testify"

Night Shift  routes obligations over time
             "what needs to be re-checked later, what is still open"

Standing     checks actor/workload authority
             "who or what has standing to act on this"

Verifier     checks evidence against claimed standard
             "did the result satisfy the acceptance criteria"

Governor     authorizes consequence
             "is this action admissible right now"

Continuity   carries durable cross-session memory
             "what lesson should survive the session boundary"
```

A single event commonly produces work for several of these. The
routing question is not "which tool owns this event" — it is "which
*claim* in this event goes to which tool."

## Same event, multiple claims

The unit being routed is the **claim**, not the event. One event
typically carries claims of several types. Each claim type is the
competence of a particular tool. The routing rule:

> The competent tool gets the claim. No tool gets a claim it is not
> competent for, even if it happens to be on the path.

Claim types Night Shift currently expects to route across the
constellation:

```text
state_claim              what is true about the world right now
                         → consumed by:    NQ
                         → recorded by:    Continuity (as durable memory)

evidence_claim           what does the captured evidence support
                         → consumed by:    Verifier
                         → contextualized by: Night Shift bundle

authorization_request    is this action admissible
                         → consumed by:    Governor
                         → preconditions:  Standing, Verifier verdicts

standing_question        who/what may act here
                         → consumed by:    Standing

deferred_obligation      this needs to be revisited later, and how
                         → consumed by:    Night Shift

reconciliation_check     are captured premises still admissible
                         → consumed by:    Night Shift's reconciler

memory_candidate         is this a durable lesson
                         → consumed by:    Continuity
```

These are not artifact types or run states. They are *typings of the
work itself* — orthogonal to which run, packet, or phase the work
shows up in.

## Claim type cuts across ladders — it is not a fourth ladder

Invariant 5 already names three distinct ladders:

```text
lifecycle    capture → reconcile → plan → review → run → verify → record
authority    observe → advise → stage → request → apply → publish → escalate
artifact     receipt | packet | diff | report | page | publication_update
```

Claim type is **not** a fourth ladder. It does not progress; it has
no ordering. It is a *property of the work* that determines which
tool is competent to bind it. A single packet at lifecycle phase
`reconcile`, authority level `advise`, artifact class `packet` may
carry several claims of different types and route them to different
tools — without changing its lifecycle phase, authority level, or
artifact class.

If we ever build the routing envelope, claim type belongs in the
packet header, not in the lifecycle ladder. Phrased as a guardrail:

> **A claim type is not a phase. Do not turn `state_claim`,
> `evidence_claim`, `deferred_obligation` into lifecycle phases.**

A run still progresses through `capture → reconcile → ... → record`.
What changes between runs is which claims the packet carries and
which tools they route to.

## Unpacking the keepers

### Route by claim type, not by tool identity

The competence vocabulary above replaces the "send it to Night Shift"
shortcut. A real routing decision names the claim type, not the
destination. "This is a `state_claim` about retention progress" is a
routing decision; "this feels like Night Shift" is not.

### Night Shift routes obligations, not authority

Restates invariant 1 ("Night Shift proposes; Governor permits")
positively, and extends it from the NS↔Governor seam to all routing
decisions Night Shift makes. Night Shift can:

- create a deferred-obligation packet
- schedule a reconciliation check
- notice that a prior premise expired
- request verdicts from Verifier, Standing, Governor

Night Shift cannot:

- silently promote "remembered next action" into "authorized action"
- substitute its own reconciler verdict for a Governor verdict
- carry forward a stale authorization across a reconciliation gap

### Deferred obligation is not deferred authorization

A Night Shift packet that says "check retention tomorrow" must not
become "run retention tomorrow" unless Standing, Verifier, and
Governor conditions are satisfied at *execution time*, not at
scheduling time. Authority captured at T0 does not survive an
intervening reconciliation gap. The packet is a *handle* for the
later check; it is not a token of authority for the later action.

This is the goblin door in the routing fabric. The agenda-reconciler
trap memo (`feedback_agenda_reconciler_trap.md`) stays one corridor
over.

### Verification is not permission

A Verifier verdict ("the change envelope's `verify_after` checks all
closed with evidence") confirms that a stated standard has been met.
It does not authorize a *next* action. A `verified_closed` incident
is closed; it does not pre-authorize the next remediation, nor does
it grant blanket authority to the actor who closed it.

`GAP-incident-modes.md` already states "Deployed ≠ verified." This
keeper extends that line: "Verified ≠ permitted-to-proceed." Both
are true; both are needed.

### Memory is not testimony

Continuity holds durable lessons and breadcrumbs. NQ holds testimony
about world state. A breadcrumb that says "we tried this and it
failed last quarter" is *useful context*; it is not *evidence about
the world right now*. Routing must not let memory smuggle authority
through the side door, and it must not let testimony substitute for
durable lesson.

`GAP-parallel-ops.md` already states "Continuity is authoritative
about who else is here. Continuity is not authoritative about what
is true." This keeper sharpens that into a routing law: a
`memory_candidate` claim routes to Continuity; a `state_claim` does
not.

### Standing is necessary, not sufficient

Standing checks who/what may act. A positive Standing verdict is a
prerequisite for proceeding. It is not, by itself, authorization to
proceed. Authorization additionally requires evidence (Verifier),
admissibility (Governor), and — for time-deferred work — a current
reconciler verdict (Night Shift).

`GAP-escalation.md` already says "drive to resolution ends where
standing begins." That line names the *boundary* at which standing
takes over. This keeper says: even past that boundary, standing is
one input among several, not a full substitute for the others.

## Later-check taxonomy

Night Shift's "schedule a recheck later" is currently one
undifferentiated operation. Different *kinds* of later-check route
to different tools. Naming them as a typed taxonomy keeps the
reconciler from collapsing them into a single queue:

```text
verify_evidence                later: did the captured evidence support the claim
                               → claim type: evidence_claim
                               → consumer:   Verifier

recheck_world_state            later: is the world still as captured
                               → claim type: state_claim
                               → consumer:   NQ

confirm_authorized_action      later: did the action that was authorized
  _completed                     actually complete, and did it complete
                                 cleanly
                               → claim type: state_claim + evidence_claim
                               → consumers:  NQ + Verifier

detect_containment_expired     later: has the silence-window / ack-TTL
                                 / mitigation lifetime expired
                               → claim type: reconciliation_check
                               → consumer:   Night Shift's reconciler

escalate_at_threshold          later: if a measured signal crosses a
                                 declared threshold, escalate
                               → claim type: reconciliation_check
                                 (with escalation handoff)
                               → consumer:   Night Shift, then
                                             escalation per GAP-escalation

write_durable_memory           later: this lesson should survive the
                                 session boundary
                               → claim type: memory_candidate
                               → consumer:   Continuity
```

Today these are not distinguished in Night Shift's surface. The
reconciler currently says "schedule recheck"; that conflates at
least four of the above. The taxonomy is the smallest vocabulary
that makes the routing visible without mandating new machinery.

> **A "later-check" is not a single operation. It is a routing
> decision typed by claim and bound by the consuming tool's
> competence.**

## Distinction from the agenda-reconciler trap

The companion memo `feedback_agenda_reconciler_trap.md` names a
related but different boundary. They run perpendicular:

```text
agenda-reconciler trap         workflow-routing boundary (this doc)

Night Shift must not grow      Night Shift must not grow sideways
*upward* into operator-pickup  into Standing / Verifier / Governor /
truth (operator agendas,       Continuity turf (cross-tool routing,
operator next-actions, what    competence binding, claim-type
operators have already         dispatch).
handled).

Direction: vertical            Direction: horizontal
Failure mode: NS becomes       Failure mode: NS routes by tool
the operator's PM tool         identity instead of claim type, and
without earning it.            ends up consuming claims it is not
                               competent for.
Resolution: don't build the    Resolution: don't build a routing
agenda-reconciler without a    envelope until a real failing case
failing case.                  forces it; until then, name the
                               competence and the claim types so
                               local dispatch doesn't drift.
```

Both are "stay in your lane" doctrines. They are compatible and
cover different lanes. Neither authorizes the other.

## Worked example (cited, not absorbed)

A neighboring project (driftwatch / labelwatch retention work, ~May
2026) hit the precise routing failure this doc names: a single
maintenance-degradation event carried `state_claim` (NQ),
`deferred_obligation` (Night Shift), `evidence_claim` (Verifier),
`standing_question` (Standing), and `authorization_request`
(Governor) cuts. Without typed routing, the temptation is to send
"the whole incident" to whichever tool happens to be on the path.

The example is **cited** here as motivation. Its specific vocabulary
(retention scheduler, rollback_lost tripwire, runway thresholds,
`/health/extended.retention` shape) is **not absorbed** into Night
Shift doctrine. Driftwatch / labelwatch keep their own vocabulary;
Night Shift's routing doctrine is generalized over the shape of the
problem, not the shape of that incident.

> A cited example is a witness for the doctrine. Absorbed
> vocabulary is doctrine that has quietly contracted to the witness.

## What this does not authorize

Per YAGNI posture and the no-implementation constraint:

- **No packet schema changes.** No `claim_types: [...]` field on
  bundles or packets. No `requires: { state_testimony: nq, ... }`
  block. The yaml-shaped sketches in this doc and in chatty's
  source draft are illustrative; they are not specifications.
- **No code.** No router crate, no claim-type enum, no dispatch
  function. The taxonomy is doctrinal vocabulary.
- **No new ledger events.** Run-ledger events stay where they are.
- **No new authority.** This doc does not raise, lower, or reroute
  any tool's authority ceiling. It clarifies competence; it does
  not grant it.
- **No CLAUDE.md invariants added** by filing this. If a routing
  invariant becomes load-bearing later, it is added when ratified.

A record is not authorization to build.

## Transport is not governance

If routing packets later move through a broker, queue, or bus, the
transport layer must remain semantically subordinate to the routing
boundary.

A broker may preserve delivery state. It does not preserve decision
state.

Delivery guarantees do not imply any of:

- current testimony
- fresh evidence
- standing
- authorization
- admissibility
- consequence ownership
- valid premises

A queued packet may be durable while its premise has expired. A
redelivered packet may be transport-valid while its authorization is
stale. An ack confirms handling at the transport layer; it is not a
Verifier verdict, a Governor authorization, or a Night Shift
reconciliation result.

Transport-safe keepers (caveat-scoped, not promoted into the doc's
top-level keepers):

> **Queue presence is not work authorization.**

> **Delivery is not admissibility.**

> **A broker preserves delivery state, not decision state.**

This does not forbid RabbitMQ, AMQP, a database queue, cron, a run
ledger, or any other carrier. It forbids treating the carrier's
delivery semantics as routing, evidence, or authority semantics. The
carrier moves bytes; the routing boundary still binds the claims.

## Trigger conditions for ratification

Ratify (and consider building the routing envelope) when one of
these happens:

1. A second Night Shift surface invents a parallel claim-type
   vocabulary (e.g. the watchbill UI grows its own dispatch
   language that doesn't match the reconciler's).
2. Standing or Verifier comes online as a real consumer with a
   wire surface, and the question "what does Night Shift hand them"
   needs an answer that is not "whatever the agenda happens to
   contain."
3. A real failing case where Night Shift consumed a claim it was
   not competent for (e.g. silently promoted a deferred obligation
   to an authorized action without re-asking Governor).
4. Cross-tool packet routing becomes a real workflow rather than
   a hand-rolled dispatch in one method.

Until one of those triggers fires, this stays a candidate. The
keeper lines and the claim-type vocabulary are the load-bearing
part; the routing-envelope shape is deliberately deferred.

## Vocabulary overlaps with existing Night Shift docs

Called out so we know what is reused vs introduced:

- **`standing`** — `GAP-escalation.md` already uses "standing" in
  "drive to resolution ends where standing begins" (the operator-
  responsibility boundary). This GAP introduces *Standing* as a
  named tool with the competence "checks actor/workload authority."
  These are the same concept at different altitudes (who-may-act),
  not a collision. The escalation line names the *boundary*; this
  doc names the *tool*. Acknowledged; no rename needed.
- **`verify_after` / verification** — `GAP-incident-modes.md`
  defines a change-envelope `verify_after` block and the line
  "Deployed ≠ verified." This GAP's keeper "Verification is not
  permission" extends, does not duplicate, that line. Verifier as
  a tool is the natural home for `verify_after` checks; the
  routing doc names it explicitly.
- **`evidence` / `authority` / `scope` / `budget`** —
  `GAP-escalation.md`'s four-axis containment for drive-to-
  resolution. The claim-type vocabulary in this doc is orthogonal:
  evidence and authority are *axes a run is bounded by*; claim
  type is *what kind of work is being routed*. Different cuts of
  the same underlying material. No collision.
- **`coordination_outcome` / `overlap_class` / `reliance_class`**
  — `GAP-parallel-ops.md`'s coordination vocabulary. This doc's
  routing language sits one level above: parallel-ops is about
  *which actors are in scope*, this doc is about *which tools
  consume which claim types*. They compose: a `state_claim`
  routes to NQ regardless of whether the run is `disjoint` or
  `shared_write` in parallel-ops terms.
- **`incident_mode` / `incident_state` ladder** —
  `GAP-incident-modes.md`'s mode and state vocabulary. Claim type
  is orthogonal to incident mode: an `incident`-mode run still
  carries `state_claim` / `evidence_claim` / `authorization_
  request` cuts. Mode shapes which actions are allowed; claim
  type shapes which tool consumes them.
- **`Slice` phases** — `GAP-slice-cycle.md` candidate vocabulary.
  Slice phases are work-cycle cadence; claim types are routing
  competence. Compose orthogonally; no collision in the candidate
  state. If slice-cycle ratifies and routing-envelope ratifies,
  the seam is "a slice phase may emit packets carrying multiple
  claim types" — same as today, just typed.

No vocabulary in this doc is renaming or replacing existing Night
Shift terminology. New introductions are: claim type taxonomy,
named tool competences, the six keeper lines, and the later-check
taxonomy.

## Open questions (not load-bearing for the record)

- **Where does the claim-type taxonomy live when it ratifies?**
  In the packet header, the bundle, the agenda, or all three?
  Probably the packet, but the bundle has the inputs and the
  agenda declares the workflow family. Defer.
- **Tool competence vs tool implementation.** A claim is routed
  to "Standing" by competence; the Standing tool may not yet
  exist. What does Night Shift do with claims whose competent
  tool is offline or absent? Probably: hold and surface, the
  same way `--no-governor` lowers ceiling. Defer to whichever
  GAP files first when Standing or Verifier comes online.
- **Multi-tool claims.** `confirm_authorized_action_completed`
  routes to NQ + Verifier in the taxonomy above. Is that a
  composite claim, or two separate claims with a join? Probably
  the latter, but the routing envelope (when built) needs to
  pick a representation.
- **Idempotency across reconciliation gaps.** A deferred
  obligation re-enters the system after a gap; the keeper line
  "deferred obligation is not deferred authorization" implies
  re-routing all the consequence-binding claims at execution
  time. What does *not* need to be re-routed? Probably memory
  candidates, but the boundary needs naming.
- **How thin is the Governor cross-reference?** Per chatty's
  framing thread, the eventual cross-reference at AG ("Night
  Shift obligation packets are not authorization") is small.
  Whether it lives in AG's existing admissibility doc or a new
  boundary doc is AG's call, not this doc's.

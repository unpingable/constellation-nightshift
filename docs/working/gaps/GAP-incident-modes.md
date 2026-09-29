# GAP: Incident Modes and Resolution Phases

> Status: identified. Motivated by past ops experience, sharpened by
> live cases. The key observation: **ops, engineering, and
> architecture are different clocks**, and flattening them into one
> agent workspace is how "handled" becomes a lie.

## Core problem

A typical agentic response to an incident collapses three distinct
concerns into one workspace:

- restore the thing
- remove the class of failure
- revise the model that let it happen

Each has a different success condition, a different appropriate pace,
and a different class of risk. Mashing them produces:

- patches that quietly rewrite the ontology
- architecture decisions made while a service is down
- "resolved" banners that mean "temporary mitigation in place"
- forgotten rollout debt
- victory essays

Traditional operations and incident-management practice solved this with
phase discipline. The load-bearing principles:

> Closing the incident is not the same as closing the architectural
> lesson.
>
> Amending the architecture is not the same as restoring service.

Night Shift must carry this explicitly, or it simply encodes the
same folklore failures in structured form.

## Three modes

Modes are bounded responsibilities. Each carries three fields:
**objective**, **allowed actions**, **exit criteria**. They are
authoritative, not decorative — a run that crosses mode bounds is an
invariant violation, not a thoughtful bonus.

### Incident / Ops mode

- **Objective**: restore truth and service.
- **Allowed actions**: verify scope, stabilize, rollback, re-point,
  restart, restore evidence path, record temporary mitigation.
- **Exit criteria**: service restored, telemetry fresh, temporary
  mitigation named as such, scope of damage known.
- **Not allowed**: silent redesign, ontology rewrite, promoting
  mitigation to permanent architecture.

### Engineering / Remediation mode

- **Objective**: remove the class of failure.
- **Allowed actions**: code changes, config hardening, detection
  additions, test coverage, rollout plan.
- **Exit criteria**: fix proposed, deployed, verified in production,
  residual risk explicit, link to originating incident preserved.
- **Not allowed**: treating "fix written" as "fix done."

### Architecture / Constitutional mode

- **Objective**: decide whether the incident exposed a bad assumption.
- **Allowed actions**: amend spec, split concepts, add invariants,
  redefine interfaces, redefine roles or phases.
- **Exit criteria**: what assumption failed is named, what law
  changes is explicit, resulting implementation work is enumerated.
- **Not allowed**: using architectural musing as a substitute for
  stabilization or remediation.

Shape in the bundle / packet (field name is `incident_mode` to
disambiguate from `workflow_family`):

```yaml
incident_mode:
  kind: incident | remediation | architecture
  objective: ...
  allowed_actions: [...]
  exit_criteria: [...]
```

## Incident state — a new ladder

Distinct from run lifecycle (`capture → reconcile → ... → record`)
and authority ceiling (`observe → ... → escalate`). Incident state
spans many runs:

```text
active                     stabilization in flight
stabilized                 service restored, root unresolved
remediation_planned        engineering fix designed
remediation_in_flight      fix being built / tested
deployed_pending_verify    fix shipped, post-deploy verification open
verified_closed            fix deployed, verified, residuals noted
architecture_followup      architectural lesson not yet processed
```

A run *affects* incident state; it does not *own* it. Multiple runs
across multiple modes collectively advance the incident through these
states.

## Closure invariants

- **Incident closure ≠ architectural closure.** An incident may be
  `verified_closed` while `architecture_followup` remains open. They
  are tracked separately.
- **Stabilization ≠ remediation.** A `stabilized` incident is not a
  resolved one. Temporary mitigation must be explicitly named as
  such, with expected remediation tracked.
- **Deployed ≠ verified.** A fix is not closed until post-deploy
  verification lands. "Shipped" is not a success condition.
- **Architecture commits require an incident anchor.** Constitutional
  amendments motivated by an incident must link back to it. No
  floating rewrites dressed as response.

## Change envelope

Before any change under `remediation` or `architecture` that touches
scope beyond the local run, the bundle must include a **change
envelope** — the pre-change declaration that the post-change
verification will close against:

```yaml
change_envelope:
  what_exists_now: [...]            # declared pre-state
  must_remain_up: [...]             # services/sources that must survive
  depends_on_this: [...]            # known dependent observers/publishers
  allowed_interruptions: [...]      # explicitly okay to disturb
  verify_after:
    - check: ...
      evidence_required: ...
      blocking: true
```

Post-change, the run emits a **verification artifact** that closes
each `verify_after` check with evidence. Unclosed blocking checks
prevent the `deployed_pending_verify → verified_closed` transition.

> A post-change checklist without teeth is a wiki checkbox cemetery.

The envelope has teeth because unclosed checks block state
advancement, not because anyone nags.

## Protected role — criticality class

Criticality (see `SCHEMA-agenda.md` and `GAP-attention-state.md`)
gets a new class:

```text
standard              normal operations
business_critical     elevated urgency / tighter TTLs
safety                safety-class policy + elevated urgency
protected             observation-critical or control-plane-critical
```

`protected` is not about urgency. It names structural role:

- **observation-critical**: if this goes down, the system stops
  knowing what is happening. (Publishers, collectors, witnesses.)
- **control-plane-critical**: if this goes down, authorization or
  coordination breaks. (Authority planes, shared-context substrates,
  schedulers.)

Reconciler behavior for `protected`:

- A proposed action that would disable a `protected` service during
  any mode requires explicit operator confirmation regardless of
  promotion ceiling.
- A `protected` service going silent raises evidence-state urgency
  independent of age.
- Casual turn-down of `protected` services is an anti-pattern the
  reconciler actively resists — not just a policy flag checked at
  the end.

This is the "don't casually turn this off" bit, explicitly named.

## Operations coordination primitives

Parallel-ops (`GAP-parallel-ops.md`) covers the substrate.
Incident-mode work layers on the primitives operations practice has carried
for decades:

```text
current_operation         what is being changed right now, by whom
claimed_responsibility    named actor on point for the change
dependencies_at_risk      observers/publishers/sources coupled to this scope
next_verification_steps   what must be checked post-change
handoff_state             what the next actor must not forget
```

These are fields in the breadcrumb cadence, not separate artifacts.
A `run.surprise` breadcrumb should populate them when applicable.

The framing worth naming directly:

> Distributed work without a coordination channel becomes folklore
> almost immediately.

Night Shift is not a notebook. It is a channel topic with receipts.

## Interaction with workflow modes

Night Shift's original modes (`ops` / `code` / `publication`) are
**workflow families** — what the packet is about. Incident modes
(`incident` / `remediation` / `architecture`) are **operational
phases of incident response** — what the work is trying to
accomplish.

They are orthogonal. A single finding may spawn:

- an `incident`-mode ops run (restart, restore evidence path)
- a `remediation`-mode code run (fix the retry loop)
- an `architecture`-mode run (revise a source-identity assumption)

All three link to the same incident anchor; each advances a different
part of its state.

## Interaction with attention-state

Incident state and attention state are distinct:

- **attention state** (`GAP-attention-state.md`): who is paying
  attention, how fresh the ack is
- **incident state**: where the problem is in its resolution arc

An `acknowledged` finding may have incident state `active`,
`stabilized`, or `remediation_in_flight`. Ack expiry does not change
incident state. Incident progression does not extend ack TTL.

## Interaction with parallel-ops

`claimed_responsibility` maps onto the `actors` section of the
concurrent-activity check in `SCHEMA-bundle.md`. Incident-state
transitions emit breadcrumbs so parallel actors can see where the
incident is without asking.

Scope overlap class plus incident state determines whether a new
actor may enter:

- overlap = `disjoint` → enter freely
- overlap = `shared_read` + incident `active|stabilized` → enter
  with notification
- overlap = `shared_write` + incident `active` → require handoff
  or coordinated entry, never silent
- overlap = `shared_write` + a `protected` service in scope →
  require operator confirmation

## Mode transitions require preflight

Any session crossing mode boundaries — incident → remediation,
remediation → architecture, or any pairing that changes the run's
success condition — is a risky class of work per `GAP-parallel-ops.md`
and triggers a Continuity preflight. The run cannot leave capture
phase without a preflight outcome (`clear`, `hold_for_context`,
`coordinate`, `contested`, or a named `operator_override`).

Rationale: mode transitions are exactly where folklore forms.
Ops-mode work that drifts into architecture-mode thinking without
re-querying coordination state is the textbook case this doc exists
to prevent.

## Interaction with Governor

- Mode declaration lives in the bundle; Governor receives it with any
  authorization request.
- Cross-mode promotion (e.g., a run that wants to both stabilize and
  remediate) is rejected by Governor by default. Explicit operator
  override required.
- The change envelope is authored by Night Shift and countersigned by
  Governor for any step above `advise`.

## Anti-patterns this exists to prevent

- "We restored service" meaning "temporary mitigation in place,
  forgotten within a week."
- Architectural insight captured during a live incident, committed as
  doctrine, not linked to the incident, not followed by
  implementation work.
- A `protected` service turned down mid-migration because the
  migrating actor didn't know it was `protected`.
- A remediation shipped, marked complete, not verified in production.
- Three runs in three sessions collectively advancing an incident
  where none of them knows the others exist.

## Open questions

- Where does incident state live — its own table, or a projection
  over the event log? (Probably a materialized view keyed on
  `incident_id`.)
- How is `incident_id` generated? (Probably: derived from originating
  finding's stable identity plus a short suffix to allow splits.)
- Can one run advance multiple incidents? (Probably no at MVP;
  one-run-one-incident keeps the model simple.)
- How do architecture-mode runs avoid being "thinking out loud with
  receipts"? (Exit criteria must enumerate implementation work;
  otherwise the run is a packet without proposal and should not
  emit.)
- Does the change envelope also apply to `incident`-mode runs?
  (Lighter form: a minimal `must_remain_up` + `verify_after` is
  still required; the full envelope applies to `remediation` and
  `architecture`.)

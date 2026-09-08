# Generic project-predicate attention v1

Status: qualified for the closed distinct-occurrence recurrence family over
exactly replay-verified `pulse.project-predicate-qualified-support/v1`
receipts.

## Layer and claim

The layers remain distinct:

```text
project declaration
!= Monitor observation
!= NQ admitted predicate
!= Pulse independent current support
!= Nightshift attention decision
```

`nightshift.project-predicate-attention/v1` means only:

> At the recorded Nightshift evaluation occurrence, this exact
> operator-owned attention policy was applied to the complete locally
> retained, content-checked history for its policy lineage. The policy's
> explicit trigger, distinct-evidence recurrence count, inclusive horizon,
> reset rule, and (for proposition attention) Pulse-owned exclusive support
> boundary produce the recorded attention disposition.

Nightshift does not establish project truth, re-evaluate NQ semantics,
re-evaluate Pulse independence or freshness, prove uninterrupted truth,
infer causality or whole-project health, authorize remediation/publication,
or deliver a notification. A human-attention decision is policy over
qualified evidence history, not another claim about world truth.

## Operator-owned policy and explicit polarity

`nightshift.project-predicate-attention-policy/v1` is operator/deployment
configuration, never project-owned `.ops` data. It content-binds:

- project, concern, question, declaration profile, predicate profile, and
  subject;
- exact NQ catalog/profile/input-schema digests;
- exact Pulse support-policy identity and digest;
- the exact Pulse verifier executable bytes;
- one explicit trigger class;
- one recurrence count/window; and
- one reset rule.

Stable names do not retarget policy. A changed semantic policy digest starts a
new recurrence lineage. V1 has no history migration rule.

The closed trigger family is:

- `PROPOSITION_ATTENTION`: the operator explicitly says that a
  `SUPPORTED_CURRENT` positive proposition is attention-worthy. Nightshift
  never guesses this from a concern name, state string, or threshold.
- `ASSURANCE_ATTENTION`: the operator lists exact non-success Pulse
  dispositions whose recurrence is attention-worthy. A benign
  `SUPPORTED_CURRENT` receipt is not an alert under this mode.

`CONTRADICTORY` and `MISSING_SUPPORT` can therefore cause assurance attention
when selected, but remain observer disagreement or absent support. They are
never rewritten as the domain proposition being true or false.

## Pulse verification and currentness

`attention ingest` first validates receipt shape, self-digest, subject, and
all NQ/Pulse target identities. It hashes the configured executable and runs
the exact policy-pinned `pulse-project-predicate-support replay` command with
direct argv, no stdin, a bounded runtime, and bounded stderr. The replay must
reproduce the same receipt digest. Nightshift does not parse a
`SUPPORTED_CURRENT` string as authority and does not duplicate NQ or Pulse
evaluation code.

For proposition attention, Nightshift uses Pulse's
`current_until_unix_ms` only as an exclusive reliance boundary:

```text
Nightshift evaluated_at < Pulse current_until_unix_ms  -> usable
Nightshift evaluated_at >= Pulse current_until_unix_ms -> INPUT_NOT_CURRENT
```

Equality is expired. Nightshift does not recalculate age, skew, or producer
validity. A later CLI invocation and process restart do not refresh the bound.
Historical receipts remain retained.

The Pulse JSON-custody control found during this campaign narrowed the two
wire integers to `i64`/`u64`. The prior `i128`/`u128` Rust fields caused the
JCS serializer to emit invalid JSON, preventing a real replay. The proposition,
deadline equation, schema identity, and accepted numeric range needed by the
contract did not change; a regression test now round-trips the canonical
receipt bytes.

## Distinct recurrence and ordering

The sole v1 recurrence family is:

```text
N distinct qualifying evidence occurrences within W seconds
```

The window is inclusive at both the recorded start and evaluation occurrence.
An occurrence one millisecond before the start does not count. Events are
ordered by their governed evidence occurrence, then their recurrence digest;
database insertion order is irrelevant.

For receipts with support evidence, the recurrence identity binds the NQ
receipt, primary and support observation occurrences, Pulse support policy,
subject, support producer/source/vantage, and disposition. It deliberately
does not bind Pulse qualification time, the Pulse receipt wrapper, or opaque
producer state. Therefore:

```text
same Pulse receipt replayed repeatedly                  -> one occurrence
same primary/support evidence requalified repeatedly   -> one occurrence
same occurrence with changed irrelevant wrapper state  -> one occurrence
distinct governed primary/support observation times    -> distinct occurrences
```

Two genuine observations with identical available occurrence/source
coordinates conservatively collapse to one. V1 prefers under-counting to
manufacturing recurrence.

For a Pulse disposition with no support observation, the exact Pulse
qualification occurrence is the failure occurrence. Replaying that receipt
does not count twice; a separately content-bound later Pulse failure
qualification may count as a separate assurance occurrence. This establishes
recurring upstream disposition, not why the support acquisition failed.

## History, restart, reset, and replay

Accepted events are idempotent on `(policy_digest, recurrence_id)`. SQLite
stores an insertion-custody predecessor chain plus a transactional lineage
count/head. Reads reject sequence gaps, changed event bytes, invalid event
digests, and count/head truncation. Evaluation independently canonicalizes by
governed evidence occurrence. Restart restores valid history but adds no
event and refreshes no time.

Reset is explicit:

- `HORIZON_EXPIRY` removes an occurrence from the active count only when it
  falls outside the inclusive horizon (or, for proposition attention, when
  Pulse support expires).
- `SUPPORTED_CURRENT` is available only for assurance policies. A later
  current supported receipt resets earlier assurance-failure recurrence. It
  does not prove a domain condition cleared.

No stale, missing, or contradictory support receipt clears proposition
attention as though it were opposite-domain evidence. V1 has no operator
acknowledgement or notification-delivery semantics.

`attention evaluate` emits a
`nightshift.project-predicate-attention-replay-bundle/v1` containing the exact
policy, canonical history, and decision receipt. `attention replay` uses the
original evaluation occurrence and is read-only. Changed policy, history, or
receipt content fails exact replay or yields a different digest. A new
present-time evaluation is not replay.

## CLI

```sh
nightshift --store nightshift.sqlite attention validate-policy \
  --policy attention-policy.json

nightshift --store nightshift.sqlite attention ingest \
  --policy attention-policy.json \
  --pulse-receipt pulse-receipt.json \
  --pulse-program /qualified/path/pulse-project-predicate-support \
  --pulse-support-policy pulse-policy.json \
  --nq-executable /qualified/path/nq \
  --nq-receipt nq-receipt.json \
  --inventory monitor-inventory.json \
  --catalog predicate-catalog.json \
  --support-evidence signed-support.json

nightshift --store nightshift.sqlite attention evaluate \
  --policy attention-policy.json \
  --evaluated-at 2026-08-25T12:03:00Z \
  --output attention-bundle.json

nightshift attention replay --bundle attention-bundle.json

nightshift --store nightshift.sqlite attention status \
  --policy attention-policy.json \
  --evaluated-at 2026-08-25T12:03:00Z
```

The CLI has no acquisition, scheduling, AG, Docket, remediation, or
notification path. Running it is not evidence.

## Genericity and controls

The opt-in control
`crates/nightshiftd/tests/project_predicate_attention_e2e.rs` uses the
previously unknown `cogwheel-fixture` and `cogwheel.queue.high` proposition.
It runs real generic Monitor collection, real NQ `queue.depth >= 18`
admission, real independently signed Pulse support/replay, and three distinct
Nightshift evidence occurrences. The first two wait; the third requires
proposition attention. Reingesting the first exact receipt is a duplicate.
No Cogwheel identity or semantic branch exists in production code.

The existing exact load-pressure path remains the narrow positive control.
Its `nightshift.qualified_support.v1` is a query/cycle-bound boot-clock
artifact, not the generic Pulse project-predicate receipt. Generic NQ/Pulse
cannot express the exact decimal load parsing/division proposition, so this
campaign neither translated nor weakened it. The narrow tests and runtime are
unchanged.

## Present real-project reachability

| Project | Concern family | Monitor | NQ | Pulse | Nightshift |
|---|---|---|---|---|---|
| Weatherwatch | `persistence.access` | acquired generically | bounded profile available | no governed independent support source | no policy installed; unreachable |
| Weatherwatch | other 9 concerns | acquired generically | no bounded profile | no support source | unreachable |
| Labelwatch | `persistence.sqlite_continuity`, `persistence.volume_capacity` | acquired generically | bounded profiles available | plausible probes are not installed/governed | no policy installed; unreachable |
| Labelwatch | other 7 concerns | acquired generically | no bounded profile | no support source | unreachable |
| Driftwatch | `persistence.sqlite_continuity`, `persistence.sqlite_slack` | acquired generically | bounded profiles available | plausible probes are not installed/governed | no policy installed; unreachable |
| Driftwatch | other 7 concerns | acquired generically | no bounded profile | no support source | unreachable |
| Cogwheel fixture | `cogwheel.queue.high` | real acquisition | real admission | three real signed current support occurrences | `ATTENTION_REQUIRED` at occurrence 3 |
| Exact load pressure | `nq.host.load_pressure/v1` | narrow diagnostic path | narrow exact semantics | narrow exact support qualified | existing narrow currentness/posture control unchanged |

No Weatherwatch, Labelwatch, or Driftwatch support producer or attention
policy was fabricated for this campaign.

## Non-goals

Nightshift does not infer polarity, page or route people, schedule checks,
acquire project facts, run project validators, broaden NQ, weaken Pulse,
perform arbitrary policy expressions, migrate histories across policy
digests, infer deployment provenance from repository HEAD, or turn attention
into authority.

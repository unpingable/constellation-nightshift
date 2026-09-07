# Generic project-predicate attention qualification

`unfamiliar-project/` is intentionally absent from Nightshift production
code. Its `project.concerns/v1` declaration and `project.ops.status/v1`
producer expose the attention-worthy bounded predicate
`queue.depth >= 18` under Cogwheel-only identities.

The opt-in Rust control
`crates/nightshiftd/tests/project_predicate_attention_e2e.rs` requires:

```sh
MONITOR_CONCERNS_BIN=/qualified/path/monitor-concerns \
NQ_MONITOR_BIN=/qualified/path/nq-monitor \
PULSE_PROJECT_PREDICATE_SUPPORT_BIN=/qualified/path/pulse-project-predicate-support \
cargo test -p nightshiftd --test project_predicate_attention_e2e -- --ignored
```

It proves real generic Monitor acquisition, real NQ semantic admission, real
Pulse qualification and exact replay, three distinct support occurrences,
Nightshift attention at the third occurrence, and duplicate refusal on replay
of the first receipt. CLI/test invocation itself is not evidence.

## Observatory cohort control

The separate opt-in test
`crates/nightshiftd/tests/cohort_project_predicate_e2e.rs` runs each
observatory's real offline status generator against temporary state and carries
one distinct, already-governed predicate through Monitor, NQ, Pulse replay, and
Nightshift attention:

    ATPROTO_COHORT_ROOT=/path/to/atproto-nutrition     MONITOR_CONCERNS_BIN=/qualified/path/monitor-concerns     NQ_MONITOR_BIN=/qualified/path/nq-monitor     PULSE_PROJECT_PREDICATE_SUPPORT_BIN=/qualified/path/pulse-project-predicate-support     NQ_PROJECT_PREDICATE_CATALOG=/path/to/specimen-profiles.json     cargo test -p nightshiftd --test cohort_project_predicate_e2e -- --ignored

Weatherwatch uses durable-access facts, Labelwatch and Driftwatch use their
separate SQLite-continuity facts. This proves fixture portability through the
existing route; it does not establish deployment identity, independent support,
or service health.

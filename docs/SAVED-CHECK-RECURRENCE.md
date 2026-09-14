# Select the next local check

`nightshift saved-check schedule` selects one desired occurrence from an exact
operator policy. It reuses the canonical recurrence-slot identity and clock
check. It does not run NQ, open a source, reserve an attempt, grant permission,
or claim that a check happened. This is an experimental integration seam, not
yet a recurring monitoring service.

The disposable selection check is `python3 examples/saved-check-schedule.py
--nightshift /absolute/path/nightshift --root
/tmp/nightshift-saved-check-schedule-example`. It uses synthetic policy material
and verifies exact replay, slot boundaries and clock refusal, not a real check.

Build the canonical runtime using its existing locked Cargo workspace. Supply
a canonical JSON policy (UTF-8, sorted keys, no trailing newline). For example:

```json
{"admissible_delay_seconds":10,"configuration_version":"1","definition_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","definition_reference":"capacity","epoch":"2026-09-14T12:00:00Z","interval_seconds":60,"policy_id":"local-capacity","scheduler_clock_id":"operator-clock","schema":"nightshift.saved-check-schedule-policy/v1","scope_id":"local-check","source_identity":"local-sqlite","subject_id":"queue"}
```

The shown digest and time are illustrative, not an installed check or a source
observation. Replace the digest/reference with NQ's actual immutable installed
definition identity, and choose the operator's clock and schedule explicitly.

```sh
nightshift saved-check schedule --policy policy.json \
  --scheduler-clock-id operator-clock --at 2026-09-14T12:00:00Z
```

Output uses `nightshift.saved-check-selection/v1`. `due` includes one
`nightshift.saved-check-due-request/v1`; `not_due` has none; `missed` retains
the missed slot for inspection but emits no executable request. Only the
current interval is considered: there is no catch-up burst. The interval is
1–86,400 seconds, delay is strictly smaller, and epoch has whole-second
precision. Unsupported schemas, malformed digests, clock mismatch and invalid
or overflowing bounds refuse with a nonzero exit status.

The exact policy digest becomes the slot's configuration identity, so changing
any policy material changes the request identity. Selecting the same slot again
does not create another evaluation ID, reserve work, or prove an earlier read
finished. A caller must inspect NQ's existing evaluation before invoking a
reader. A retained claim without a terminal result is still indeterminate.

## What remains to connect

An acquisition adapter must supply a real observation and its provenance; the
scheduled time must not be substituted as source observation time. NQ must
claim and retain the exact evaluation, then the caller must reconcile that
result before another occurrence. The attention owner must separately apply
the explicit outcome/currentness/maintenance policy. No automatic runner,
attention submission, notification, generation pruning, or production-service
installation is supplied by this command. These missing connections remain
integration work, not guarantees inferred from a successful selection.

## Durable local evaluation owner

`nightshift saved-check run` is the bounded saved-check-specific continuation
from a due slot. Its closed JCS runtime config pins the Monitor and NQ
executables and NQ config, fixes one local Monitor project/trusted root,
project/producer/manifest/concern identity, one operator-selected SQLite target,
the installed NQ definition identity, and one condition mapping. Monitor
producer execution is explicitly enrolled with `--allow-exec` and remains
constrained by Monitor's own bounds; it is not described as read-only merely
because the later NQ query is read-only.

The command durably opens one evaluation before collection, retains the exact
Monitor inventory and selected concern's `observation.observed_at`, and keeps
the separate acquisition time. It then verifies NQ's installed definition and
persists the complete NQ read binding before the one allowed evaluation. On
response loss, a later invocation asks NQ for that exact evaluation result. A
retained claim or missing result after launch remains indeterminate; Nightshift
does not repeat Monitor collection or the NQ source read automatically.

The configured relationship between the Monitor observation and saved-check
target is an operator deployment assumption. It is neither proof that the
inventory describes the SQLite bytes nor an atomic snapshot. After result
custody, Nightshift records one trusted projection coordinate and uses it for
the retained NQ condition. It never substitutes the earlier slot-selection
time or refreshes that coordinate during replay. The projection keeps original
outcome, source-assertion currentness and maintenance state separate. It does
not refresh evidence or grant authority. NQ's SQLite query has explicit row,
byte, progress and lock bounds, but those are not a universal hard
filesystem-I/O deadline.

```sh
nightshift --store /absolute/nightshift.sqlite saved-check run \
  --runtime-config /absolute/runtime-config.json \
  --policy /absolute/policy.json --scheduler-clock-id CLOCK --at RFC3339
nightshift --store /absolute/nightshift.sqlite saved-check inspect \
  --evaluation-id sha256:...
```

## Retained attention projection

`saved-check attention-evaluate` projects attention only from one retained
terminal evaluation. It does not rerun Monitor or NQ, refresh the source or
send a notification. The policy is closed
`nightshift.saved-check-attention-policy/v1` material with a self-digest and a
1–300 second event-age bound. The operator-declared `--evaluated-at` is bound
into the receipt; an exact duplicate returns the original receipt and cannot
renew eligibility.

```sh
nightshift --store /absolute/nightshift.sqlite saved-check attention-evaluate \
  --policy saved-check-attention-policy.json --evaluation-id EVALUATION \
  --evaluated-at 2026-09-14T12:00:03Z
nightshift --store /absolute/nightshift.sqlite saved-check attention-status \
  --policy saved-check-attention-policy.json --evaluation-id EVALUATION
nightshift saved-check attention-replay --bundle-stdin < replay-bundle.json
```

A failed saved check is `ATTENTION_REQUIRED`; active maintenance is retained as
`SAVED_CHECK_FAILED_COVERED`, not converted to success or silently suppressed.
Stale, future, refused, claimed, otherwise indeterminate, or maintenance-
unavailable material is `LOSS_OF_ASSURANCE`. This asks for attention without
claiming that a failed predicate is current. Delivery eligibility additionally
requires the attention event coordinate to remain within the policy age bound;
it is distinct from source currentness. `NO_ATTENTION` is reserved for an
available, fresh `passed` result.

The receipt and replay bundle carry `authority: none`. Nightshift retains and
replays them but has no notification transport. A separate explicitly enrolled
delivery owner may verify the exact replay bundle; that step neither grants
action authority nor establishes human acknowledgement.

Replay recomputes consistency of the operator-retained local evaluation and
condition. It is not independent proof of a signed owner identity, the current
source, or the truth of the caller-declared target relationship.

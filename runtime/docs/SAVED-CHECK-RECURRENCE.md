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

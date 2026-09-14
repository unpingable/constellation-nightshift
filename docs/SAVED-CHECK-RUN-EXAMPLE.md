# Disposable recurring saved-check run

[`../examples/saved-check-recurring.py`](../examples/saved-check-recurring.py)
exercises one explicitly invoked local chain:

```text
Nightshift slot selection
  -> Monitor collects a real disposable SQLite observation
  -> NQ evaluates one installed saved check
  -> NQ projects the retained result with a maintenance annotation
  -> Nightshift retains and reconciles that exact occurrence
```

It is a qualified disposable local example, not a scheduler installation. The
recorded local qualification exercised two real SQLite acquisitions, exact
duplicate and source-removed replay, and the two configuration/policy refusal
controls. It makes no network request and invokes no model provider. It does
not use Pulse, create attention, deliver a notification, request AG
authorization, or dispatch Docket work. Their absence here does not make any
of those components universally optional; this profile has no governed
external effect.

## Prerequisites

Use exact compatible built executables for Nightshift, `monitor-concerns`, and
NQ, plus Python 3 and SQLite. Supply the public Monitor queue example as the
producer input. The example is Linux-oriented because the Nightshift runtime
seals enrolled program/configuration bytes before invoking them.

```sh
python3 examples/saved-check-recurring.py \
  --nightshift /absolute/path/nightshift \
  --monitor /absolute/path/monitor-concerns \
  --nq /absolute/path/nq \
  --project-example /absolute/path/local-queue-attention.py \
  --root /tmp/nightshift-saved-check-run-demo
```

`--root` must not exist. It is intentionally retained after success or
failure: it holds the disposable target, NQ database, Nightshift store,
canonical policy/configuration material, and `commands.jsonl`. Do not rerun
against that same root. Inspect the retained Nightshift occurrence and NQ
evaluation before choosing a new local occurrence.

## What it checks

The example creates a 20-row SQLite queue and a Monitor project binding whose
producer reads that exact database. It calculates the Monitor manifest digest
from the exact TOML bytes, installs an NQ `non_empty` check, and declares a
currently active maintenance window. The expected NQ result is therefore
`failed`; the condition projection keeps `failed` as the original result while
reporting `covered` separately.

Nightshift selects a thirty-second slot with a twenty-nine-second window using
the local clock. A forty-five-second monotonic wait bound prevents a stalled
wall clock from holding the example indefinitely. Its
runtime records the due request, Monitor inventory bytes and digest, the actual
producer observation timestamp, NQ request binding, NQ terminal result, and
condition projection. A duplicate call returns that record unchanged.

The script then mutates and removes the source database and repeats the same
slot. The retained terminal occurrence must still return without reopening the
source. It also proves that changed runtime configuration and a policy whose
definition digest no longer matches enrollment refuse. Finally it recreates the
disposable target and waits for the next real local-clock slot; that distinct
occurrence must acquire and evaluate new source material.

## Scope and recovery limits

Monitor's observation time is produced by its local producer; it is not the
Nightshift slot time. The qualification is a single-operator local topology:
it demonstrates a real source read and retained cross-component bindings, not
independent-organizational evidence. The binding still relies on the
operator-enrolled relationship between the Monitor observation and the NQ
SQLite target; it is not an atomic cross-process snapshot proof.

For a retained NQ `claimed` result or a lost command response, the runtime's
supported behavior is to inspect retained custody. A claim without a terminal
result remains indeterminate and must not cause an automatic fresh source read.
The example does not inject those interruption cases; they remain focused
component qualification rather than end-to-end evidence here. It also does not
exercise recurring installation, retention/rollover, Pulse support, attention
policy, delivery, or any external effect.

The resulting failed condition is evidence only. Maintenance is an annotation,
not suppression or success. No result here authorizes attention, a notification,
or any downstream effect.

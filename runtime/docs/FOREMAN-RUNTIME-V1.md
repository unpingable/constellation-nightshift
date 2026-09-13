# Nightshift Foreman Runtime V1

Status: BOLT-LOOM corrected operator-tool contract; exact CLOCKWORK-MOTH head 30373353d4472720bf62f60d378056658d068e88 is retained but superseded as a successor base.

The Nightshift foreman admits one exact sealed orientation packet for bounded
local agent-compute scheduling. Packet possession is not admission. Admission
is an exact, current, digest-bound local record supplied to the admit command.
Its authority effect is fixed to LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY, and its
target_effects_authorized value is fixed to false.

The foreman is the separate crates/nightshift-foreman workspace package and
nightshift-foreman binary. It does not add a binary or module to canonical
nightshiftd. The canonical temporal office retains exactly nightshift and
nightshift-observation-resolver.

## Identity and contract layers

The following identities are independent:

1. packet content identity;
2. local admission identity and operator-basis digest;
3. execution-profile identity;
4. run, work-item, and fresh attempt identities;
5. adapter, provider, model, session, thread, turn, and queue identities;
6. adapter-event and terminal-receipt identities;
7. scheduler state and raw worker result strings.

The closed admission and execution-profile contracts live in
schemas/nightshift.foreman-admission.v1.schema.json and
schemas/nightshift.foreman-execution-profile.v2.schema.json. Their Rust
decoders deny unknown fields and recompute domain-separated RFC 8785/JCS
digests.

Execution profile V2 adds an exact adapter_version to each registered adapter and uses a new V2 digest domain; the historical V1 schema remains unchanged at the exact CLOCKWORK-MOTH head.

The execution profile is mechanism metadata. It maps every exact packet work
item to one admitted adapter, opaque workspace identity, opaque resource-lock
keys, and provider/model routing class. It cannot add work items or modify
packet meaning. Lock keys are never inferred from prose or path strings.

## Durable state

The SQLite store uses WAL mode. Exact packet, admission, and profile bytes;
packet work-item topology; journal events; accepted receipt bytes; and final
snapshot bytes are append-only. SQLite triggers refuse update or deletion of
those records.

Resource claims are the one mutable materialized coordination table. Claims
for all keys are inserted in one immediate transaction before dispatch and
removed only after an exact accepted terminal receipt. Every claim and release
also has an immutable journal event, so state remains reconstructible.

No event is silently overwritten. Once a provider, model, session, thread, turn, or queue identity appears for an attempt, later events may omit it but cannot substitute a different value. Terminal receipts must agree with every identity already frozen by the journal and with the profile-bound adapter ID and version. Raw adapter events and terminal receipts are
retained byte-for-byte with separate retained-byte digests. Explicit
extensions retain unknown material but do not change scheduler semantics.

## Scheduler law

Scheduler state is a closed mechanism vocabulary. It is not a work-item result
or campaign classification.

A dependency edge becomes eligible only when every predecessor has an accepted
terminal or not-started receipt. Eligibility means
READY_ENTRY_EVALUATION: the assigned worker must still inspect exact
predecessor evidence and entry predicates. The scheduler does not compare,
normalize, rank, or branch on the predecessor's raw state or
result_classification.

All configured lock keys are claimed atomically. Overlapping work waits while
disjoint work may proceed within the lower of packet and admission concurrency
bounds.

V1 admits one fresh attempt per work item. Restart resumes the same exact
attempt after adapter reconciliation. A terminal attempt cannot resume. A
second attempt has no runtime transition and requires a separately qualified
successor policy and fresh admission; it cannot be disguised as recovery.

A human question changes only its work item's scheduler state. Independent
work remains runnable unless an exact dependency or shared lock says
otherwise. The foreman has no operation that answers an approval request.

## Crash boundaries

Attempt creation and atomic lock acquisition commit before dispatch request.
After a process stop at that boundary, replay yields the same attempt_id and
held claims. Resume records a same-attempt reconciliation request; it does not
create an attempt.

An accepted adapter completion observation is not a terminal receipt. Restart
therefore reconstructs a waiting-provider/mechanism state until an exact,
identity-bound terminal receipt is accepted. Process or provider exit alone
cannot close a work item.

## Closeout

Close refuses while any packet item lacks an accepted terminal or not-started
receipt. Its requested snapshot timestamp must be at or after the latest retained terminal receipt end time or not-started receipt time. It then generates the existing nightshift.run-receipts/v1 shape in
packet order. Raw state and classification strings are copied verbatim. No
aggregate result is generated.

The first close stores exact RFC 8785/JCS bytes. Later close operations return those same bytes without refreshing timestamps or scheduler state. Active state remains a distinct nightshift.foreman-live-run/v1 projection.

Every read and export command opens an existing database through a retained no-follow file descriptor and a descriptor-relative SQLite URI. When WAL and SHM are both absent, immutable mode prevents SQLite from manufacturing them. When both are present, mode=ro preserves and reads current WAL evidence after validating both sidecar identities. Partial or changing sidecar custody is refused. It refuses absent, symlink, non-regular, or structurally incomplete stores and does not run initialization or write PRAGMAs. Projection, worker-brief export, and event export each use one deferred read transaction. Pathname replacement after admission cannot redirect later reads. Qualification compares database, schema, directory-entry, WAL, and SHM bytes before and after live and final reads.

## CLI

Mutating local-scheduler operations are admit, run, resume, accept-event,
accept-receipt, accept-not-started, and close.

Seal-admission and seal-profile deterministically content-address draft
records. They create no admission and perform no scheduler mutation.

Read-only operations are status, replay, events, export-live, and export-final.

Run emits a bound start request for an external registered adapter. The core
contains no subprocess or target-actuator implementation. Export and replay
perform no dispatch.

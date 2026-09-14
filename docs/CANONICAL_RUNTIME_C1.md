# Nightshift canonical runtime C1

**Status:** canonical production runtime; this document is the authoritative
statement of the current Nightshift → AG → Docket runtime boundary contract.
It supersedes pre-cutover runtime-correspondence claims wherever they
conflict, including the pre-2026-08-11 proposal-boundary model retired in
`docs/working/decisions/NQ-NIGHTSHIFT-LEAN-CORRESPONDENCE.md` and
`docs/working/decisions/CALCULUS-CONFORMANCE.md`. It does not issue standing,
authority, execution permission, or an operational qualification claim.

New optional Maude plan/session lineage for exact proposals is specified in
[`authoring-context-provenance.md`](authoring-context-provenance.md). It is an
immutable Nightshift-owned provenance relation, deliberately absent from every
authority gate. Historical and runtime-generated occurrences remain valid when
the relation is not recorded.

New Maude authoring inputs use the separate two-role authenticated custody
contract in
[`authoring-context-custody.md`](authoring-context-custody.md). Custody
authentication is verified before cycle admission and is persisted as audit
lineage only; it supplies no currentness, standing, authorization, or
execution predicate.

## Responsibility boundary

Nightshift owns exact recurrence-slot and observation-cycle identity,
scheduling posture, application posture over complete current diagnostic
evidence, attention, and typed non-authorizing intent. Present-evidence
currentness is supplied by its owning authority. NQ-NG supplies the complete
diagnostic basis and qualifies its historical admission provenance. AG
exclusively owns exact-work occurrence governance.
Docket and the executor remain behind AG.

The production executable surface is two binaries:

- `nightshift` — the canonical observation-cycle runtime. Its only
  consequence-adjacent port is `ag-loopctl`, restricted to `status`, `init`,
  `continue`, and `record-proposal`; protected V2 ingress additionally makes
  read-only `inspect` and `verify-runtime-profile-v2` calls to compare the
  configured profile with AG's genesis-bound profile. It has no standing, authorization,
  dispatch, retry, reconciliation, Docket, executor, or human-disposition
  command. Its separate generic `attention` surface may invoke the exact
  content-pinned `pulse-project-predicate-support replay` verifier and append
  deduplicated upstream evidence history. That verifier is read-only with
  respect to project facts and cannot acquire, qualify, authorize, or execute.
- `nightshift-observation-resolver` — a one-shot, read-only evidence
  translator answering AG's observation-resolution requests against the
  canonical store. It opens the store strictly read-only and has no
  cycle-mutation, lease, AG, Docket, or executor surface.

The structural exclusivity gate
(`scripts/check_no_actuation_surface.sh`) enforces this closed graph.

### NQ-NG admission provenance boundary

Before a non-missed cycle claims its recurrence slot, every delivered
diagnostic must be qualified through the configured `nq` executable and
stable NQ store-genesis `source_id`. NQ-NG's read-only `diagnostics qualify`
operation accepts only a locally emitted `nq.diagnostic_execution.v2` whose
artifact commitment, exact bytes, run/evaluation, provider intake, admission
context, profile semantic identity, and judgment or governed refusal/failure
history all reopen exactly. Imported custody is ineligible.

Nightshift recomputes the full canonical-byte digest and checks the returned
`nq.diagnostic_admission_provenance.v1` against the artifact ID, contract,
byte length, run, completion time, profile semantic ID, producer/source ID,
and closed nonclaims. `nightshift.observation_record.v2` persists one such
carrier per unique delivered artifact. V3 preserves the identical NQ
admission requirement while additionally binding one admitted external-
application evidence composition. A missing, refused, malformed, or
substituted carrier creates no cycle claim and no observation. Historical v1
observation records remain readable; the production NQ-NG qualifier does not
mint new provenance for v1 or imported artifacts.

This admission is evidence eligibility, not currentness, standing, AG
authorization, or permission to act. The carrier self-hash is an integrity
binding, not a signature. The configured executable and config paths are
locators; source authenticity and honesty remain deployment assumptions.

Configured executable, store, and database paths are operational locators.
They select where resolution or execution machinery is reached; they do not
establish resolver, subject, policy, work, or authority identity. Those
identities are bound separately by configured expected resolver identities,
content-derived object identities, and the exact subject/scope/occurrence/work
bindings described below.

For an exact-work cycle, Nightshift also supplies AG's deployment-owned
runtime-profile locator at campaign genesis. AG persists the exact canonical
profile and its content identity atomically with the first occurrence. The
profile, not a later caller, binds observation/standing resolver identities and
bytes, the exact-work catalog, and the Docket custody/executor root. Repeated
CLI paths are compatibility assertions; they cannot select a replacement
authority or execution boundary.

## Boundary contract: Nightshift → AG → Docket

### Proposal recording is informational

`ProposalRecorded` means the exact work proposed has been
identity/binding-validated and recorded as information. It does not mean the
workflow predicate is satisfied, standing is granted, the catalog admitted
the work, or anything is authorized or executable.

`record_proposal` performs integrity and binding checks only. It performs no
workflow-policy judgment. Binding correctness and policy admissibility are
distinct gates, and the distinction is load-bearing: a proposal may be
recorded while presently inadmissible, because admission is judged later,
under the catalog and standing in force at judgment time.

### Exact work is bound across identity domains before recording

Nightshift and AG intentionally use different work-identity domains:

- The Nightshift-domain compiled-work identity is
  `sha256(JCS({parameters, schema}))` over the immutable compiled payload.
  It is sealed into `TypedCoarseIntentV2.compiled_work` as provenance.
- The AG/Docket-domain executable-work identity is the identity of the exact
  executor plan, derived with AG's domain-separated digest
  (`hash_domain("ag-effectd.docket-executor-plan/v1", JCS(plan))`).

The two digest values need not be equal, because they identify different
semantic objects. Safety comes from the sealed cross-domain binding, not
from digest equality:

1. `PrecompiledWorkflowProposalV2` carries the exact executor plan and
   validates that the prepared AG proposal's `work` equals the identity
   Nightshift independently derives from that plan. The expected AG work is
   derived from the plan content, never caller-asserted.
2. The sealed intent persists both identities (`compiled_work` and
   `expected_ag_work`); the prepared AG occurrence request is cross-checked
   against them.
3. AG binds the expected work into occurrence metadata at occurrence
   creation (`OccurrenceMetaV1.expected_work`, via genesis or continuation
   open).
4. `record_proposal` requires `proposal.work == expected_work` and rejects a
   mismatch with an integrity error (`BindingMismatch`) before observation
   resolution, catalog judgment, or any policy evaluation.

The expected AG work is per occurrence. Continuation occurrences bind their
own expected work at open; they do not inherit a predecessor's work blindly.

### Evidence basis is pinned; new evidence requires a successor occurrence

A proposal binds exactly one `PreconditionBasisRefV1` — the canonical digest
of the observation's `DecisionBasisV1` — at record time. Every later
judgment re-resolves the cited observation and requires the same basis
digest. New evidence therefore never silently refreshes an existing
proposal; new evidence requires a successor occurrence.

### DecisionBasisV1 and the normalization rule

The evidence basis is a finite, versioned projection of the Nightshift
posture:

```text
schema: nightshift.decision-basis.v1
rule:   nightshift.posture-normalization, version 1
atoms:  exactly one condition.* and one delivery.* from the frozen vocabulary:

  condition.clean
  condition.condition_present
  condition.unresolved
  delivery.qualified
  delivery.partial_delivery
  delivery.failed
  delivery.not_configured
  delivery.not_required
```

The basis intentionally excludes observation identity, subject/scope
identity, timestamps and freshness, support standing, completeness, coverage,
recurrence, attention/headline, and workflow policy.
Completeness/coverage/recurrence remain upstream proposal-currentness
concerns: they determine whether a proposal may be prepared, not the content
of the evidence basis.

The normalization rule identity follows the repository's semantic-identity
convention. A semantic normalization change requires an explicit rule
version/identity change; the rule digest identifies the declared
normalization rule version — it does not automatically detect arbitrary
source-code semantic changes.

### Decision-relative adequacy, not injectivity

The adequacy invariant is:

> If two exportable posture states normalize to the same `DecisionBasisV1`,
> then every workflow predicate in the supported predicate family gives the
> same source-level decision for both.

Normalization is not required to be injective, and different posture states
are not required to have different bases. Collapsing a distinction no
supported predicate can observe is benign.

The executable certificate is
`crates/nightshiftd/tests/decision_basis_adequacy.rs`:

- source domain: `ConditionAxis × DeliveryStanding` (3 × 5 = 15 states);
- predicate family: every valid `required`/`forbidden` assignment over the 8
  frozen atoms (3^8 = 6561 predicates);
- 98,415 production source-level verdict comparisons, zero unsafe
  collisions;
- the source-level evaluator matches on the real source enums and never
  consults `normalize_posture`;
- self-tests prove the checker accepts a benign collision and detects a
  deliberately broken normalizer.

Maintenance rule: a new workflow predicate requires rerunning the adequacy
checker; only a predicate that distinguishes states the normalization
collapses requires a new normalization rule version. A new predicate does
not automatically require a normalization change.

External application evidence has a separate, narrower adequacy gate. The
deployment-owned `nightshift.external_evidence_profile.v1` admits one closed
claim set for one exact post-settlement successor and constrains that
observation's freshness horizon. Those claims are not NQ atoms and are not
relabeled as `condition.clean`. Their complete execution, PlanNode, producer,
and temporal provenance is content-bound through the canonical observation
identity. See
[`EXTERNAL_EVIDENCE_COMPOSITION_V1.md`](EXTERNAL_EVIDENCE_COMPOSITION_V1.md).

`nightshift.observation_record.v4` adds one separately versioned adequacy
case: exact historical fault-test qualification plus fresh passive
steady-state evidence for the same exact artifact. Only the passive component
has a renewable temporal horizon; changing the PlanDocument, compilation,
work, subject, or scope makes the historical qualification inapplicable. See
[`QUALIFICATION_AND_STEADY_STATE_EVIDENCE_V1.md`](QUALIFICATION_AND_STEADY_STATE_EVIDENCE_V1.md).

For the closed local-Compose V1 workflow, authorized deployment/effect and
qualification of the exact artifact are atomic at the workflow boundary.
There is no governed deploy-only transition that makes an unqualified
successor artifact eligible as a passive-observation target. This is an
explicit negative-reachability invariant, not a claim that future canary or
staging semantics would be invalid. See
[`ARTIFACT_CHANGE_AND_REQUALIFICATION_V1.md`](ARTIFACT_CHANGE_AND_REQUALIFICATION_V1.md).

### Observation currentness

`nightshift-observation-resolver` answers one exact question about one
already-persisted observation. It is one-shot and read-only, carries an
explicit resolver identity, retrieves and revalidates canonical persisted
evidence, and never judges workflow policy or authorizes anything.

Status meanings:

- **Current**: the cited observation resolves uniquely, passes the canonical
  store's revalidation and the resolver's subject cross-bindings, is bound
  to the requesting AG subject through the cycle's sealed typed intent, is
  inside its actionable freshness window, and is the latest qualified
  observation in its lineage family. Current does not mean clean,
  workflow-admissible, standing-granted, authorized, or that the world was
  re-observed at resolution time.
- **Stale**: the observation's actionable wall-clock evidence window has
  expired. For v1/v2 records the implemented rule is
  `fresh_until = posture.evaluated_at + configured resolver TTL`. For a v3
  composed observation it is the earlier of that deadline and the
  deployment-profile horizon measured from the external evidence acquisition
  time. For v4 decision-relative evidence it is similarly clipped by the
  passive source horizon; the historical qualification timestamp is not a
  currentness clock. Equality is stale (`now >= fresh_until → Stale`). Support expiry is not used:
  `SupportExpiryV1` lives on the external evidence authority's opaque
  receiver clock and has no valid Unix-time translation. The actionable
  window therefore inherits the deployment's existing trust in the
  caller-sealed `evaluated_at`.
- **Superseded**: a strictly later qualified observation exists in the same
  domain-scoped lineage.
- **Contradictory**: the citation is ambiguous (duplicate observation
  identities) or the persisted evidence fails integrity/cross-binding
  validation, or its support is explicitly contradictory.
- **Absent**: no persisted observation carries the cited identity.

Negative-status responses carry a syntactically valid sentinel basis only
because the wire schema requires one; it has no workflow-policy meaning. AG
refuses any non-Current resolution before the catalog decider is consulted.

### Observation lineage and supersession

The lineage family key is exactly:

```text
(policy_id, configuration_version, subject_id, scope_id, scheduler_clock_id)
```

and logical order within a family is exactly:

```text
(occurrence, nominal_due_at, slot_id)
```

There is no subject-wide "latest observation", no `updated_at` ordering, no
completion-time ordering, and no caller-supplied `evaluated_at` ordering.
Qualified for supersession means exactly `cycle.observation.is_some()`.
Consequences: a later persisted observation with weak or blind support still
supersedes earlier evidence; `Missed`, `RecoveryRequired`, and in-flight
cycles carry no observation and never supersede; catch-up completion time
cannot reorder logical recurrence.

The canonical Missed law: `now == latest_admissible` remains admitted;
`now > latest_admissible` persists a Missed cycle with reason token
`slot_passed_exact_latest_admissible_instant`. Missed cycles contain no
observation and cannot supersede.

### Workflow preconditions and their placement

Each catalog entry may declare a finite precondition over basis atoms:

```text
required ⊆ basis.atoms  AND  forbidden ∩ basis.atoms = ∅
```

An absent precondition is unconditional. Catalog validation rejects a
required/forbidden overlap and any atom outside the frozen vocabulary. There
is no general expression language, no numeric predicate, and no universal
Clean rule. The canonical example: a rollout workflow
(`required = {condition.clean}`) refuses condition-present evidence while a
remediation workflow (`required = {condition.condition_present}`) admits the
identical basis.

Placement is fixed:

- `record_proposal`: no workflow predicate;
- `decide`: the predicate is evaluated;
- `authorize`: the predicate is re-evaluated.

The predicate is owned by `CatalogAdmissibilityDeciderV1` — not by
Nightshift, the observation resolver, the kernel's observation-health layer,
the standing resolver, or Docket.

### Catalog policy identity is content-derived

`ExactWorkCatalogV1.policy_basis` is derived, not caller-asserted: the
canonical domain-separated digest of the semantic policy content (schema and
entries; per entry work schema, subject, scope, and precondition sets).
There is no self-referential policy-identity wire field, and no caller can
attach an unrelated identity. Every admission decision, spend, and issuance
identifies the actual catalog content evaluated at that judgment.

Catalog policy is present-tense: `decide` and `authorize` each evaluate the
catalog currently in force. A policy tightened between them refuses the
spend; a policy loosened between them is judged under the new policy.
Policy changes never mutate the proposal or the pinned evidence basis.

### Standing is present-tense governance, never authority

Standing answers one question: does the designated external governance
authority presently maintain a mandate under which this exact scoped
proposal context may proceed toward AG authorization? Standing is not
evidence health, not a workflow predicate, not catalog policy, not
authorization, and not a bearer capability.

AG validates each standing resolution: explicit resolver identity (the
configured expectation is never a wildcard), exact
occurrence/observation/proposal/subject/scope echoes, the resolver's answer
window against a configured maximum TTL (inclusive at the maximum), and
freshness `resolved_at <= now < expires_at`.

Standing may change without any evidence change:

- standing Absent at proposal time may later become Current;
- standing Current at `decide` may become Revoked before `authorize`;
- `authorize` re-resolves standing every time;
- recovery may allow the same proposal to be retried.

The asymmetry is intentional: an evidence change requires a successor
occurrence; a standing change does not.

Equal standing status does not erase how that status was established. When
authorization succeeds, the spend and issuance retain the exact standing
resolution and content-derived mandate identity used at that authorization;
a later Current mandate generation is not rewritten as though it were the
earlier authorization path.

### The production standing authority

`ag-standing-resolver` is a one-shot, read-only resolver over a local
mandate store. It has no networking, no write API, and no signatures, and it
is not authority. Mandates are keyed by exact `(subject, scope)` and carry
`generation`, `status`, and `valid_until_unix_ms`; mandate identity is
content-derived. The highest generation governs: no mandate yields Absent;
a highest generation expired at request time yields Expired; revoked yields
Revoked; active yields Current. `Superseded` is not emitted: the request
asks for present standing, not a historical generation, and older
generations are simply dominated by the highest.

The answer lease is
`expires_at = min(request.now + configured answer TTL, mandate.valid_until)`;
AG independently enforces its own configured maximum on top. The irreducible
environmental assumption: a correctly configured standing authority can lie.
Schema and content binding establish provenance and scope, not truth.

### The authority boundary

Standing never authorizes. The sole AG authority-minting event is
`AgAuthorizationSpendV1`, produced only after fresh observation-health
validation, pinned-basis validation, workflow/catalog judgment, and standing
validation all pass at authorize time. `AgIssuanceV1` derives from the
one-use spend. No resolver response, no mandate reference, and no proposal
is executable authority.

Subprocess location, status synchronization, recovery, retry, and Docket
execution attempts are mechanisms for resolving or realizing
an already-governed exact effect. They do not widen work or scope, refresh a
pinned evidence basis, replace authorization provenance, or mint another
spend. Changed evidence, policy, or standing can affect authority only through
the explicit gates defined above; execution machinery does not create an
implicit authorization path.

### Docket custody and execution standing

AG standing closes the revocation window between `decide` and `authorize`.
Docket execution standing independently closes the window between
`authorize` and effect. Docket receives the signed issuance; standing
artifacts are never presented to Docket as authority.

A Docket refusal after an AG spend prevents execution and effect but does
not erase the historically real spend. An AG refusal creates no issuance and
cannot be resurrected by any permissive Docket state. The two standing
concepts are distinct gates, not redundant ones.

## Frozen invariants

1. Proposal existence is not admissibility.
2. Exact work is cross-domain bound before `record_proposal`; work
   substitution fails as an integrity error.
3. The evidence basis is pinned when the proposal is recorded.
4. New evidence requires a successor occurrence; old proposals do not
   silently refresh.
5. Workflow preconditions are per-workflow catalog judgments over
   DecisionBasis atoms.
6. `decide` evaluates and `authorize` re-evaluates under the catalog policy
   currently in force.
7. Observation supersession is domain-scoped and logical-order based.
8. Standing is present-tense external governance state and never authority.
9. `AgAuthorizationSpendV1` is the sole AG authority-minting event.
10. Docket independently gates the post-spend execution/effect boundary.
11. Catalog `policy_basis` is derived from policy content.
12. Normalization adequacy is decision-relative, not injective.
13. Observation freshness is the persisted `evaluated_at` plus a deployment
    TTL, not opaque support-clock expiry.
14. Operational locators select machinery; they do not establish identity or
    authority.
15. Resolution, recovery, retry, and execution mechanisms do not widen or
    renew authorization, and authority receipts retain the exact evidence,
    policy, and standing provenance used at the spend.

## Full-chain qualification evidence

`crates/nightshiftd/tests/ag_governed_integration.rs` exercises the complete
boundary with real subprocesses — the Nightshift canonical runtime and store,
`nightshift-observation-resolver`, `ag-loopctl`, `ag-standing-resolver`,
Docket, and `ag-effectd` — using a controlled fixture only for Docket's own
execution-standing resolver. Covered scenarios: healthy execution with full
provenance reconstruction; rollout refusal of condition-present evidence;
remediation admission of the identical evidence; same-family observation
supersession before spend; standing revocation before spend; standing
recovery for the same proposal; Docket refusal after spend; non-resurrection
of an AG refusal; and exact-work substitution rejection.

The tests are opt-in because they need adjacent-repository binaries. Run:

```sh
AG_LOOPCTL_BIN=<path to ag-loopctl> \
AG_STANDING_RESOLVER_BIN=<path to ag-standing-resolver> \
AG_DOCKET_BIN=<path to docket> \
AG_EFFECTD_BIN=<path to ag-effectd> \
cargo test -p nightshiftd --test ag_governed_integration -- --include-ignored
```

Build the AG binaries from the AG workspace (`cargo build --bins` there
produces `ag-loopctl`, `ag-standing-resolver`, and `ag-effectd`) and the
Docket binary from the Docket runtime workspace; pass absolute paths.

## Environmental assumptions

The runtime does not prove external truth. The boundary contract assumes:

- honesty of the observation resolver's source evidence and of the
  present-evidence authority;
- caller/request-sealer integrity, including the caller-sealed
  `evaluated_at` the freshness window derives from;
- honesty of the configured standing authority and of Docket's
  execution-standing authority;
- revocation propagation and timeliness within the configured TTL bounds;
- honesty and correct deployment of the configured NQ-NG source that emits
  locally verified admission provenance;
- host-level custody and honest deployment of the distinct Maude session
  issuer and handoff producer credentials, service principals, custody store,
  and request/handoff directories;
- SHA-256 collision resistance;
- deployment correctness of resolver identities, store paths, and TTL
  configuration.

These are deployment assumptions, not defects.

## Nonclaims

- Current Lean does not prove end-to-end runtime conformance.
- The observation-adequacy certificate is executable CI evidence, not yet a
  Lean theorem.
- Standing truthfulness is not formally provable from AG; resolver
  designation is a deployment trust assumption.
- There is no claim of open-world enumeration of arbitrary environment or
  successor state.
- `DecisionBasisV1` does not preserve all Nightshift posture distinctions;
  it preserves exactly the distinctions the supported predicate family can
  observe.

## Runtime flow

```text
exact recurrence slot
  -> exact local NQ-NG admission provenance
  -> exact observation cycle
  -> authority-owned present-support result
  -> complete NQ diagnostic posture
  -> display/attention and optional typed intent
  -> immutable exact-work proposal
  -> new AG occurrence
  -> read-only AG status/settlement reference
  -> observation required, reconciliation display, halt display, or close
```

Recurrence permits observation only. A diagnostic headline, severity,
attention record, prior NQ generation, AG status rendering, receipt, or
persisted support record cannot originate work. The in-process live-cycle
lease is deliberately non-serializable. Restart preserves historical facts
but erases the live witness used to prepare an AG request.

Pulse-style support expiry is current only while `expiry > evaluated_at` on
the evidence authority's receiver clock. Recurrence latest-admissible time is
Nightshift-owned and inclusive at equality. A temporal hold is active only
while `now < expiry`. These are distinct semantic types.

## Store and recovery

`canonical_recurrence_slots`, `canonical_observation_cycles`, and
`canonical_cycle_events` form the authoritative SQLite state. IMMEDIATE
transactions, predecessor-digest CAS, a one-successor event constraint, and
an exact `(campaign_id, occurrence_id)` claim prevent duplicate slot work,
stale completion, and occurrence reuse.

After restart:

- local observing or posture-recorded work becomes `RecoveryRequired`;
- a prepared AG occurrence is recovered only by an exact AG status query and
  is never resubmitted by Nightshift;
- reconciliation, settlement, halt, and completion remain AG facts;
- prior support and posture remain historical evidence, never reconstructed
  currentness.

An AG settlement records only attempt-native facts and moves the Nightshift
cycle to `ObservationRequired`. Subject posture can change only after a new
qualified observation and NQ evaluation.

## Current command surface

```sh
cargo build --locked --release --bins
./target/release/nightshift cycle --help
```

`cycle run` accepts one exact sealed cycle request, an executable named
`nq` with its config locator and expected store-genesis source identity, and
an executable named `pulse-support-resolver`. AG options are required only
when the request contains an exact precompiled proposal; the complete set is
the AG CLI, database, observation-resolver locator and expected identity, and
runtime-profile locator.

`cycle run-config` and `recover-config` retain the same closed V1 cycle
configuration. The four executable byte pins (NQ, AG CLI, observation resolver,
and present-evidence resolver) are streamed through a fixed-size buffer with a
256 MiB file ceiling. Configuration and exact JSON request bytes retain their
separate 16 MiB ceiling. Executable pin verification rejects empty/nonregular
files, symlinks on Unix, digest mismatch, and observed file changes during
hashing. A verified pathname is not execution custody or authorization; this
loading check does not acquire evidence, invoke a provider, or grant an effect.

For continuity-bearing NQ V2 provenance, `cycle run` additionally accepts an
all-or-none Standing Ed25519 public-key path, key ID, and NQ audience. These
are verification coordinates only; the strict carrier and unresolved
attribution boundary are defined in
[`CONTINUITY_AUTHORITY_CARRIER_V1.md`](CONTINUITY_AUTHORITY_CARRIER_V1.md).
`cycle sync-ag` and
`cycle recover` read AG state through `ag-loopctl`; neither can resubmit a
prepared request.
`nightshift-observation-resolver` is invoked by AG as a configured
subprocess, never by operators, and takes its store, identity, and TTL from
explicit arguments.

The operator-owned generic project-predicate attention contract and its
`attention validate-policy|ingest|evaluate|replay|status` surface are defined
separately in
[`GENERIC_PROJECT_PREDICATE_ATTENTION_V1.md`](GENERIC_PROJECT_PREDICATE_ATTENTION_V1.md).
Attention ingestion accepts only a Pulse result reproduced by the exact Pulse
replay verifier; it does not rerun Monitor collection, NQ admission, Pulse
qualification, or project acquisition.

Nightshift defines the exact `pulse-support-resolver` command grammar but does
not ship a production support producer or resolver. The operational fixture
qualifies the process boundary only. A deployment must not interpret that
fixture, Classic NQ liveness, V3 origin custody, or NQ admission as present
support. The production-source gate and the unresolved Linode decision are
recorded in
[`PRESENT_EVIDENCE_SUPPORT_SOURCE_GATE.md`](PRESENT_EVIDENCE_SUPPORT_SOURCE_GATE.md).

## Production exclusivity

Cargo automatic binary discovery is disabled and the manifest declares
exactly two binary targets: `nightshift` and the read-only
`nightshift-observation-resolver`. Wicket/WLP path dependencies, MVP-A,
classic Governor, the authority ladder, prose action, same-generation skip,
and production drills are absent from production source. The structural gate
enforces this closed graph and mutation-tests representative resurrections.

Historical Watchbill test sources that retain useful archaeology are
quarantined outside Cargo discovery and are explicitly noncanonical. The old
user-level unit files were deleted. Neither can supply a production runtime or
authority path.

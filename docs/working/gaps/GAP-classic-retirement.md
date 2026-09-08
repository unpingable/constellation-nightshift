# Active classic retirement: Nightshift consumer contracts

Status: **BLOCKED ON NAMED MODERN CONTRACTS**, 2026-09-08. Integration owner:
Constellation main campaign; implementation owner: Nightshift retirement lane.
This is active release work, not an indefinite deferral. M2 remains closed;
its qualification does not transfer to this branch. No classic development,
regeneration, renamed wrapper, or automatic fallback is authorized here.

## Exact inspection boundary

Nightshift base `2db475b0bb8be5e3afa7ac6c95e2ab1f73a9ceb4`, branch
`campaign/governed-campaign-loop-v0-qualification`, was clean. This isolated
branch preserves that checkout and all historical records. SECOND-WATCH remains
separate at `ef12ac26cfc5d3bf8c977243c3dc9b17cf4b04df`, clean when inspected;
this inventory is not a claim about its runtime or deployment.

Modern evaluator inspected: NQ-ng operator-beta
`9f1b081b7fc5b2d99fb92ee6b0ac4107c7e7dfe4`, plus current source
`675e247` in `/data/git/skunkworks/nq-ng` (untracked campaign records preserved).
Neither inspected Rust source tree contains the `campaign-stage-qualification`,
`campaign-stage-realization`, or `project-predicate` command contracts below.
The NQ-ng native `qualify` seam is admission provenance for an exact artifact;
it is not these factual evaluators. See NQ-ng
`audit/classic-reconciliation/{CUTOVER_GAP_MATRIX,SEMANTIC_CROSSWALK}.md`.
The corrected scanner `12ddff81ac0866a18a4e79278fa33da2b32c06e4`
is an inventory aid, not a complete call graph or absence certificate.

## Remaining consuming paths and milestone impact

| ID | Actual consumer and exercise evidence | Responsibility and modern owner | Blocks |
| --- | --- | --- | --- |
| NS-R1 | `src/repository_qualification.rs:279-338`: fixed `nq-monitor campaign-stage-qualification replay`; production CLI `nightshift repository-qualification` calls it. `tests/repository_qualification_cross_office.rs:39` evaluates then replays real classic evidence only when `NQ_MONITOR_BIN` and `Q4_RESOLUTION_OUTPUT` are set; otherwise returns without exercise. `tests/governed_campaign_v0_cross_office.rs` similarly uses a configured classic evaluator and AG `--nq-monitor`. `scripts/check_no_actuation_surface.sh:225` and `tests/canonical_exclusivity.rs:177` actively require the old basename. | NQ-ng must independently evaluate/replay exact repository/gate/artifact facts, preserving QUALIFIED/FAILED/INDETERMINATE and explicit nonclaims. Nightshift retains receipts and derives time-relative applicability. AG-ng owns authorization; Docket owns effects, not qualification. | Modern repository-qualified campaign continuation and executable retirement. |
| NS-R2 | `src/reservation_qualification.rs:260-318`: fixed `nq-monitor campaign-stage-realization replay`; production `nightshift reservation-qualification` ingress and observation resolver retain/consume realization records. Unit tests use a verifier substitute, not the real modern evaluator. Introduced at `999a91d92b56e655906a31a1a4e914ccaf1ecbfb`. | NQ-ng must evaluate/replay `nq.campaign-stage-realization-*/v2`, binding one exact external evidence reservation, profile/evidence/executable identity, realizations and nonclaims. Nightshift owns conflicts/currentness; AG-ng owns reservation/continuation authority and Docket execution custody. | Modern reserved-evidence realization/continuation and executable retirement. |
| NS-R3 | `src/project_predicate_attention.rs:518-542` invokes Pulse replay and passes `--nq-executable`. `tests/{project_predicate_attention_e2e,cohort_project_predicate_e2e}.rs` directly run classic `project-predicate admit`, then Pulse qualification/replay; both are ignored by default. `qualification/project-predicate-attention/README.md` currently instructs classic fixture generation. Commits `2661fd8`/`2db475b` record prior cohort work; no deployment or current process is established by that history. | NQ-ng owns exact project predicate admission/check; Monitor acquisition and Pulse authenticated support/replay remain their owners. Nightshift owns temporal recurrence/attention, never authorization. Requires Monitor/Pulse lane's exact successor contract. | Classic-free observatory cohort showing and attention qualification, not accepted M2. |
| NS-R4 | Public `src/nq_disposition.rs` parses `nq.reliance.receipt.v1`; `tests/nq_reliance_{conformance,disposition}.rs` exercise read-only posture. No production-bin caller of the DTO/disposition API was found; the library is built. Golden JSON in `tests/fixtures/nq_reliance/` was historically produced by classic `reliance evaluate`, but current tests only read bytes and do not regenerate them. | A named NQ-ng diagnostic-support/consumer-purpose contract is missing; consumer-owned Nightshift posture must retain contradiction, wrong-consumer/purpose refusal, stale/unavailable uncertainty and no-action authority. Do not treat NQ artifact admission as permission or import classic reliance automatically. | Public current-support API retirement, if retained as a supported beta surface. Historical read-only compatibility tests may remain expressly archived. |

Paths above are relative to `crates/nightshiftd/` unless prefixed `scripts/` or
`qualification/`. Source presence and historical qualification are observed;
current deployment/use is **NOT_OBSERVABLE** from this repository inspection.
No classic execution was launched during this inventory. Cargo/build metadata
does not link a classic Rust dependency; the production obligations are runtime
subprocess/interface dependencies, which a Cargo-only census would miss.

## Ordered completion work (no substitute semantics)

1. **NQ-ng qualification owner, NS-R1 then NS-R2:** ratify bounded native
   evaluate/replay contracts. R1 needs exact repository/head/tree, ordered gate
   outcomes, evidence producer/executable identity, artifact digests and
   workspace predicates. R2 additionally binds external reservation and exact
   realization provenance. Specify invalid evidence versus factual failure
   versus missing/indeterminate evidence, deterministic receipt/replay, and
   refusal of profile, subject, result and executable substitutions. Existing
   classic schemas are donor requirements, not automatically modern authority.
2. **Nightshift owner:** after exact NQ-ng contract/revision acceptance, replace
   each bounded verifier and closed schema/evaluator pins, preserve retained
   classic receipts as historical only, and update the exclusivity gate and
   CLI/witness instructions. No fallback path. Qualify positive, factual failed,
   indeterminate/missing, replay mismatch, spawn failure, wrong identity,
   stale/superseded and conflicting-realization cases on the actual evaluator.
3. **AG-ng fixture owner + main integrator:** replace the older AG evaluator
   argument/adapter; rerun Q4 and governed-loop witnesses against exact integrated
   NQ-ng/Nightshift/AG-ng/Docket revisions. R1/R2 completion is not achievable by
   changing Nightshift alone or borrowing M2 acceptance.
4. **Monitor/Pulse owner, NS-R3 in parallel:** establish modern project predicate
   admission/check and support replay first. Then Nightshift owner reruns generic
   and three-observatory cohort controls on the exact modern pair, including
   admitted, refused, unknown/unavailable, duplicate, expiry and replay cases.
5. **Main integration + Nightshift/NQ-ng owners, NS-R4:** decide the named beta
   consumer-purpose supported surface; implement that bounded native contract,
   or explicitly retire the public current-use API while preserving immutable
   historical reading tests. Archival classification cannot silently preserve
   an executable generator or advertised current classic support.

These prerequisites are genuine missing capability, not merely basename work.
No direct runtime migration is currently justified in this lane. The next
authorized action is owner contract delivery for R1/R2 and the parallel
Monitor/Pulse contract for R3, followed by bounded consumer changes and witnesses.

### Observed existing gate debt

`bash scripts/check_no_actuation_surface.sh` fails at both the unchanged base
checkout and this documentation-only branch: its closed subprocess file list
does not include the already-present `reservation_qualification.rs` process
site. This is a concrete NS-R2 qualification blocker, not a failure introduced
by this note. Do not simply add the file to silence the gate; the modern
reservation verifier needs its own restricted-operation controls in that gate.
No Cargo behavior or modern replacement witness was executed in this
documentation pass. `git diff --check` passes.

## Retirement acceptance and historical custody

Completion requires no supported production/build/test/generator path needing a
classic implementation, including transitive Pulse and AG test paths; explicit
historical-only fixtures and negative substitution specimens may remain.
Re-census exact integrated revisions, record all excluded/unreadable/vendor
scope, and combine it with actual positive/refusal/uncertainty witnesses.
Zero textual findings alone cannot satisfy the gate. Original Q1-Q4 freeze,
classic receipts and prior acceptance stay attached to original subjects.

Historical `docs/working/decisions/NQ-PHASE-2-DEPENDENCY-AUDIT.md` describes an
earlier finding/liveness shape; it is not a current exhaustive inventory.
Current native `nq_admission.rs` is already NQ-ng and must not be regressed.
The broader beta can continue along that accepted native observation path while
these explicit retirement blockers close. No Docket diagnostic substitute or
new workflow engine is introduced.

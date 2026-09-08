# AGENTS.md — Working in this repo

This file is a **travel guide**, not a law.
If anything here conflicts with the user's explicit instructions, the user wins.

> Instruction files shape behavior; the user determines direction.

---

## Role

Night Shift manages admissibility across time. Its job is not to decide whether action is authorized, but to prevent old observations, stale plans, and deferred work from silently becoming current authority.

Pair with NQ (premise-movement detection) and AG (authorization decisions):
*NQ detects that the premise moved. AG decides whether the authorization fell
off. Night Shift makes that movement legible across the deferral.*

---

## Quick start

```bash
cargo build
cargo test
cargo run --bin nightshift -- --help
```

The production executable surface is two binaries: `nightshift` (the
canonical observation-cycle runtime) and `nightshift-observation-resolver`
(a one-shot, read-only evidence translator for AG's observation-resolution
boundary; it has no cycle-mutation, AG, Docket, or executor surface). The
structural gate `scripts/check_no_actuation_surface.sh` enforces the closed
production graph.

The semantic runtime boundary contract — proposal recording, exact-work
binding, evidence bases, observation currentness and lineage, workflow
preconditions, standing, authorization, and the Docket seam — is defined by
`docs/CANONICAL_RUNTIME_C1.md`.

## Tests

```bash
cargo test
```

The full Nightshift → AG → Docket integration suite
(`crates/nightshiftd/tests/ag_governed_integration.rs`) is opt-in because it
drives adjacent-repository binaries (`ag-loopctl`, `ag-standing-resolver`,
`ag-effectd`, and the Docket binary); `docs/CANONICAL_RUNTIME_C1.md` records
the exact invocation environment.

For a new or changed governance check, pair the accepting path with a direct
hostile/refusal witness that would fail if the check were bypassed. Reuse the
existing natural homes: `observation_resolver.rs` tests for freshness and
lineage, `nq_admission.rs` tests for exact upstream admission binding,
`ag_governed_integration.rs` for work/subject binding, one-use spend, and
non-resurrection, and `check_no_actuation_surface.sh --self-test-inject` for
forbidden production surfaces. Prefer a small mutated fixture or injected
source specimen; do not add a mutation-testing framework.

Always run tests before proposing commits. Never claim tests pass
without running them.

---

## Safety and irreversibility

### Do not do these without explicit user confirmation
- Push to remote, create/close PRs or issues
- Delete or rewrite git history
- Modify dependency files in ways that change the lock file
- Any action that would promote an agenda beyond `propose` stage
- Anything that touches AG catalog/policy or NQ configuration

### Preferred workflow
- Make changes in small, reviewable steps
- Run tests locally before proposing commits
- For any operation that affects external state, require explicit user confirmation

---

## Repository layout

The canonical runtime is a single Rust crate:

```
crates/nightshiftd/         Rust crate — canonical runtime + library
  src/
    canonical_runtime.rs    Observation-cycle runtime (slot → posture → intent)
    canonical_store.rs      Authoritative SQLite cycle/slot/event state
    diagnostic_posture.rs   Posture evaluation over complete NQ evidence
    decision_basis.rs       DecisionBasisV1 projection + frozen vocabulary
    currentness.rs          Qualified-support boundary
    nq_admission.rs         Read-only NQ-NG admission-provenance boundary
    observation_resolver.rs Read-only AG observation-evidence translator
    ag_port.rs              ag-loopctl adapter (status/init/continue/record-proposal)
    bin/nightshift.rs       `nightshift` CLI
    bin/nightshift_observation_resolver.rs  read-only resolver binary
  tests/                    Integration tests (incl. the opt-in full-chain
                            Nightshift → AG → Docket suite)
docs/
  CANONICAL_RUNTIME_C1.md   The authoritative runtime boundary contract
  architecture/             Ratified design (pre-C1 documents bannered as such)
  theory/                   Positioning docs
  operator/                 Operator examples and surface docs
  working/                  Working/historical tree: gaps, decisions, roadmaps
```

---

## Coding conventions

- Rust: stable toolchain, clippy clean, no unsafe without justification
- Receipts: content-addressed, append-only, deterministic
- The canonical authority office for governed work is AG ng; there is no
  production classic-Governor integration in this crate

Classic NQ retirement is separate and incomplete. The active consumer inventory,
named missing replacement contracts, and dependency order are in
`docs/working/gaps/GAP-classic-retirement.md`. Do not introduce new classic
dependencies or automatic fallback; historical qualification is not modern
replacement acceptance.

---

## Invariants

1. No mutation without AG authorization. Night Shift proposes; AG permits.
   Observation/proposal existence, binding validity, catalog admissibility,
   and current standing are distinct inputs or gates; none is authorization.
2. Context bundles must be reconciled before execution. Stale context is not evidence.
3. Every run produces receipts. If it happened without a receipt, it didn't happen correctly.
4. Promotion is explicit and sequential. No step in `observe → reconcile → propose → authorize → execute → verify → publish` may be skipped.
5. Transport and operational locators are not identity or authority. MCP tool
   availability, executable paths, and store paths are mechanism data, not
   permission; separately bound identities remain authoritative.
6. Staleness escalates to revalidation, not action. Night Shift may schedule a recheck on stale evidence; it may not propose mutation against it.
7. Witness positions are NQ's grammar, not Night Shift's. NS consumes the finding shape NQ surfaces; it does not branch behavior on substrate / application_internal / application_external / platform_internal / platform_external. If position disagreement should change scheduling, NQ encodes it into the finding shape and NS responds to the shape.
8. Recovery, retry, and execution mechanics do not widen, renew, or
   replace authorization. They may realize only the exact governed effect and
   provenance bound by the explicit AG authorization and Docket execution
   gates.

---

## What this is not

- Not cron. Cron executes blindly; Night Shift reconciles before acting.
- Not AG. AG is the authority office. Night Shift is the observation,
  scheduling, and proposal office.
- Not an autonomous operator. It reduces toil without laundering accountability.

---

## When you're unsure

Ask for clarification rather than guessing, especially around:
- Whether a change affects the AG integration boundary
- Anything involving the promotion path or escalation ladder
- Receipt schema changes (these are append-only contracts)
- Anything that changes a documented invariant

---

## Agent-specific instruction files

| Agent | File | Role |
|-------|------|------|
| Claude Code | `CLAUDE.md` | Full operational context, build details, conventions |
| Codex | `AGENTS.md` (this file) | Operating context + defaults |
| Any future agent | `AGENTS.md` (this file) | Start here |

# AGENTS.md — Working in this repo

This file is a **travel guide**, not a law.
If anything here conflicts with the user's explicit instructions, the user wins.

> Instruction files shape behavior; the user determines direction.

---

## Role

Night Shift manages admissibility across time. Its job is not to decide whether action is authorized, but to prevent old observations, stale plans, and deferred work from silently becoming current authority.

Pair with NQ (premise-movement detection) and Governor (authorization decisions): *NQ detects that the premise moved. Governor decides whether the authorization fell off. Night Shift makes that movement legible across the deferral.*

---

## Quick start

```bash
cargo build
cargo test
cargo run --bin nightshift -- --help
```

End-to-end Watchbill run against the bundled NQ fixture:

```bash
cargo run --bin nightshift -- watchbill run \
    tests/fixtures/wal-bloat-review.yaml \
    --finding nq:wal_bloat:labelwatch-host:/var/lib/db
```

The Tier-2 horizon path (cross-run tolerance lineage → Governor
receipts) activates when both `--horizon-policy <path>` and
`--governor-socket <path>` are supplied. Either flag alone is a
configuration error.

## Tests

```bash
cargo test
```

One integration test (`tests/governor_rpc_live.rs`) is opt-in — it
requires a live `agent_gov` daemon on a Unix socket and is gated by
the `NIGHTSHIFT_GOVERNOR_SOCKET` env var (the file uses env gating,
not `#[ignore]`). Note this exercises the **legacy** Governor wire
(`agent_gov`), kept optional and disabled by default; the canonical
authority office for governed work is AG ng, whose authorization
path reaches Night Shift's world through Docket, not through this
socket.

Always run tests before proposing commits. Never claim tests pass
without running them.

---

## Safety and irreversibility

### Do not do these without explicit user confirmation
- Push to remote, create/close PRs or issues
- Delete or rewrite git history
- Modify dependency files in ways that change the lock file
- Any action that would promote an agenda beyond `propose` stage
- Anything that touches Governor policy or NQ configuration

### Preferred workflow
- Make changes in small, reviewable steps
- Run tests locally before proposing commits
- For any operation that affects external state, require explicit user confirmation

---

## Repository layout

v1 is effectively Rust-only. The DESIGN.md Rust+Python split is
preserved as the architectural target for Code mode, but no Python
package exists yet — `pyproject.toml` is a placeholder.

```
crates/nightshiftd/         Rust crate — daemon + library
  src/
    agenda.rs               Agenda declaration + YAML loader
    bundle.rs               Capture + reconciliation DTOs
    reconciler.rs           Pure adjudicate over (bundle, acquisition)
    pipeline.rs             capture → reconcile → packet
    nq.rs                   NQ source (fixture + CLI-backed)
    liveness.rs             NQ liveness gate
    freshness.rs            Imported-basis freshness (Slice B)
    posture_class.rs        Silence-aware posture (Slice C.1)
    horizon.rs              Tolerability-horizon decision logic
    horizon_policy.rs       NS-local horizon declarations
    reconcile_horizon.rs    Horizon phase: policy + tolerance + receipt
    governor_client.rs      JSON-RPC client (record_receipt today)
    store/sqlite.rs         SQLite persistence
    packet.rs               Review-packet schema
    main.rs                 `nightshift` CLI entry
  tests/                    Integration tests
tests/fixtures/             Agenda + NQ fixtures
docs/                       Lifecycle-organized documentation; see docs/README.md
  architecture/             Ratified design: DESIGN, FLOW-tolerability-horizon, SCHEMA-*, GAP-reack-doctrine
  theory/                   Positioning docs: DEPLOYMENT-MATURITY
  operator/                 Placeholder; operator docs owed at MVP exit
  working/
    gaps/                   Open spec-shaped GAPs (14)
    decisions/              Candidate doctrine, working notes, FEATURE-HISTORY ledger, AUDIT-BACKLOG
```

---

## Coding conventions

- Rust: stable toolchain, clippy clean, no unsafe without justification
- Receipts: content-addressed, append-only, deterministic
- Governor integration: required for any mode above `observe`

---

## Invariants

1. No mutation without Governor authorization. Night Shift proposes; Governor permits.
2. Context bundles must be reconciled before execution. Stale context is not evidence.
3. Every run produces receipts. If it happened without a receipt, it didn't happen correctly.
4. Promotion is explicit and sequential. No step in `observe → reconcile → propose → authorize → execute → verify → publish` may be skipped.
5. MCP is tool transport, not authority. Tool availability is not permission.
6. Staleness escalates to revalidation, not action. Night Shift may schedule a recheck on stale evidence; it may not propose mutation against it.
7. Witness positions are NQ's grammar, not Night Shift's. NS consumes the finding shape NQ surfaces; it does not branch behavior on substrate / application_internal / application_external / platform_internal / platform_external. If position disagreement should change scheduling, NQ encodes it into the finding shape and NS responds to the shape.

---

## What this is not

- Not cron. Cron executes blindly; Night Shift reconciles before acting.
- Not Governor. Governor is the authority layer. Night Shift is the scheduling/promotion layer.
- Not an autonomous operator. It reduces toil without laundering accountability.

---

## When you're unsure

Ask for clarification rather than guessing, especially around:
- Whether a change affects the Governor integration boundary
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

## Campaign selection

Use Nightshift when recurrence, currentness, durable observation history, or
restart-safe proposal tracking matters; keep bounded edits on the ordinary
repository workflow. Start with `cargo run --bin nightshift -- --help` and
`docs/operator/README.md`. A composed run requires its exact, owner-approved
NQ and authority coordinates.

For prolonged work, use the campaign-approved durable producer and checkpoint.
After supervisor interruption, inspect the original cycle and its owning
occurrence before requesting a successor. Tool availability, recurrence, or a
proposal grants no authority. If the composed path is unavailable, use the
documented fallback and state the evidence limit.

# Nightshift newcomer guide

Nightshift records deferred-work context, reconciles it before producing a
review packet, and preserves receipts for its scheduling lifecycle. It does
not authorize or execute a change. On this public `main` branch, its optional
legacy Governor socket is disabled by default; it is not a replacement for
the AG authority office.

The public repository is `constellation-nightshift`; the crate, executable,
store, and protocol names remain unchanged.


## Current runtime and predecessor workspace

The additive [`runtime/`](../runtime/) workspace contains the source-pinned
canonical cycle and Foreman runtime. Its exact inputs are in
[`SOURCE-PROVENANCE.json`](../runtime/SOURCE-PROVENANCE.json), with operational
boundaries in the [custody guide](../runtime/docs/BOUNDED_PROVIDER_CUSTODY_V1.md).
Build it with `cargo build --locked --manifest-path runtime/Cargo.toml`. The
distributed focused runtime test gates are:

```sh
cargo test --locked --manifest-path runtime/Cargo.toml -p nightshift-foreman
cargo test --locked --manifest-path runtime/Cargo.toml -p nightshiftd --lib project_predicate_attention
cargo test --locked --manifest-path runtime/Cargo.toml -p nightshiftd --bin nightshift exact_input_tests
```

Workspace-wide and Casework tests require fixture inputs not distributed in
this cut.

For read-only decision verification from another process, use the
[attention replay interface](../runtime/docs/ATTENTION-REPLAY-STDIN.md).
It accepts an exact receipt bundle on standard input without pathname
substitution. The caller must close the stream and bound process duration.
Replay checks retained consistency; notification delivery and evidence
currentness remain separate checks.

The separate [Monitor/Pulse source cut](../integrations/monitor-predicate-support/)
and [local queue example](../integrations/monitor-predicate-support/docs/local-queue-attention.md)
exercise actual acquisition, NQ admission, support and attention, ending in an
intentional no-network delivery refusal. Select its own manifest when building
those components. No private sibling dependency or live notification is implied.

The additive [saved-check selector](../runtime/docs/SAVED-CHECK-RECURRENCE.md)
uses canonical recurrence slots to choose one desired local check. Its small
example tests slot identity and clock refusal only; it is not an automatic
monitoring runner or evidence acquisition. Run its focused gate with
`cargo test --locked --manifest-path runtime/Cargo.toml -p nightshiftd --lib saved_check_recurrence`.

The repository-root workspace remains the predecessor command set. Its
Diagnostics, Watchbill, Runs, NQ, Liveness, and agenda-keyed Attention commands
are not aliases for `runtime/` and remain available from existing immutable
revisions.

## Preserved predecessor: source build and inspection

This branch is a source workspace, not an installed package. It requires Git,
Rust 1.82 or newer, a native C compiler/linker for bundled SQLite, and public
Wicket and WLP source checkouts beside the Nightshift checkout. Acquire those
three public repositories together; no local private sibling is implied:

```sh
git clone https://github.com/unpingable/constellation-nightshift.git nightshift
git clone https://github.com/unpingable/wicket.git wicket
git clone https://github.com/unpingable/wlp.git wlp
```

The directory names and placement are load-bearing because `Cargo.toml` names
`../wicket` and `../wlp`. Keep revisions compatible with the checked-out
Nightshift source. Its first dependency resolution may need crates.io access
unless the required Cargo material is already available.

```sh
cargo build --locked --release
./target/release/nightshift --help
```

The [operator guide](operator/README.md) documents its current public command
surface, including read-only `nq disposition` input and the fixture-backed
Watchbill example. Live NQ reads require an externally supplied NQ executable;
the documented `--nq-bin` or `NIGHTSHIFT_NQ_BIN` coordinate is a locator, not
authority. Do not treat a fixture run as a deployment qualification.

## Authority, currentness, and recovery

Nightshift schedules and reconciles intent; a stale witness is a reason to
revalidate, not a basis for action. Its agenda, context bundle, and stored
receipt do not grant permission or make external evidence true. The main
branch's `AGENTS.md` and [operator guide](operator/README.md) describe the
current limits, including the optional legacy integration.

## Separately published qualification revision

The newer canonical-runtime qualification fixture is published separately at
[`eb20a7f`](https://github.com/unpingable/constellation-nightshift/tree/eb20a7fe7d3efc478fa17c0e351e2e20febddf5b).
It records baseline006 with four successful cache settlements using a
deterministic NQ substitution. That fixture is not a genuine NQ tutorial and did not establish current
runtime availability; `runtime/` is separately source-pinned. It also does
not establish that a full integration workflow is complete. Consult that exact revision for its
own source and qualification scope.

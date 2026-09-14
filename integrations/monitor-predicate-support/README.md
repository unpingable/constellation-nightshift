# Acquire project observations and check independent support

This source-only distribution supplies Monitor's bounded project acquisition
and Pulse's support/currentness check for public NQ bounded predicates. It is
part of the existing products, not a new component or orchestration framework.

Build with Rust/Cargo 1.94.0: `cargo build --locked --bins`. Component checks:
`cargo test --locked --all-targets`. To exercise the separately installed
public NQ executable, set `NQ_MONITOR_BIN` to its absolute path and run
`cargo test --locked -p pulse-project-predicate-support --test qualification
real_nq_sprocket_support_and_contradiction -- --exact --ignored`.

See [the actual local queue example](docs/local-queue-attention.md) for the
four-component caller, exact NQ/Nightshift pins, Python prerequisite, limits,
refusal checks and recovery. This cut alone supplies neither NQ nor Nightshift.
No live notifications, action authority or complete recurring profile is implied.

## Reproduce this cut

`SOURCE-INPUTS.json` lists the exact canonical product commit and regular Git
blobs. Copy those blobs byte-for-byte with unchanged relative names; substitute
only the distributed two-member workspace manifest and generate its locked
public crates.io dependency graph. No Rust source or test layout changes are
made. Preserve the Apache-2.0 license and third-party notices. The accompanying
`SOURCE-PROVENANCE.json` binds every distributed file except itself, including
the generated manifest and lock. A maintainer needs canonical source access to
repeat extraction; an adopter builds this complete public cut without it.

Keep build output, virtual environments and disposable example state outside
release exports. Component versions remain independent of suite/profile releases.

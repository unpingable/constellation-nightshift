# Pulse NQ host-load support

This source-only Apache-2.0 distribution contains the bounded host-load evidence
adapter used by an explicitly configured Nightshift integration. Canonical source
revision: `9f39d878be2b064a8be4153841df16c101cbf2c4`. See `SOURCE-PROVENANCE.json` for exact source and layout
bindings.

Build the provided cut with Rust 1.85 or newer using `cargo build --locked`; run
the standalone test suite with `cargo test --locked`. Rust 1.85 is the declared
MSRV; this cut was qualified with Rust 1.98. The included closed-launcher
generator and its deterministic test require Linux and a Python 3 interpreter.
The binary accepts only `produce|ingest --config ABSOLUTE_PATH --acquisition-id
TOKEN`. The separately sealed `pulse-support-resolver` role accepts no arguments
and requires its closed launcher enrollment; see
`docs/pulse-closed-resolver-launcher.md`.

Maintainers reproduce a release by reading the immutable `source_inputs` blobs
recorded in `SOURCE-PROVENANCE.json`, applying its one listed test-locator
substitution, then generating the standalone manifest, recorded lockfile,
license, notices, and README before hashing every output. Public users build this
provided cut and do not need access to the canonical source checkout.

The adapter records and resolves scoped, expiring host-load support. Evidence
custody and currentness do not authorize work, establish general host health, or
qualify a complete Constellation workflow. No configuration, key, measurement,
receipt, service, or binary is included.

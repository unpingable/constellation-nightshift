# Nightshift newcomer guide

Nightshift records deferred-work context, reconciles it before producing a
review packet, and preserves receipts for its scheduling lifecycle. It does
not authorize or execute a change. On this public `main` branch, its optional
legacy Governor socket is disabled by default; it is not a replacement for
the AG authority office.

The public repository is `constellation-nightshift`; the crate, executable,
store, and protocol names remain unchanged.

## Public main: source build and inspection

This branch is a source workspace, not an installed package. It requires Git,
Rust 1.82 or newer, a native C compiler/linker for bundled SQLite, and sibling
`wicket` and `wlp` source trees at the relative paths declared in `Cargo.toml`.
Its first dependency resolution may need crates.io access unless the required
Cargo material is already available.

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
deterministic NQ substitution. That fixture is not a genuine NQ tutorial and
does not mean this `main` branch contains the canonical runtime or that the
full publication campaign is complete. Consult that exact revision for its
own source and qualification scope.

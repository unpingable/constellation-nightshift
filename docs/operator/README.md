# Night Shift operator quick start

**Status:** supported read-only surfaces only. Night Shift is not packaged as
a general-purpose service, and these instructions do not authorize
actuation.

## Build contract

Prerequisites:

- Git;
- stable Rust and Cargo, Rust 1.82 or newer;
- a native C compiler and linker for the bundled SQLite build; and
- crates.io access for an uncached first build.

The repository-root workspace is retained predecessor material. Its manifest
still names WLP, which is retired. It is not a supported fresh-install route:
do not restore WLP or assemble historical sibling checkouts to build it. Use
the source-pinned `runtime/` workspace or a selected integration profile; the
matching profile documents its exact prerequisites and commands.

Live NQ-backed reads additionally require an independently installed
`nq-monitor` executable. Prefer an absolute path. Inject it through the
global `--nq-bin` option or `NIGHTSHIFT_NQ_BIN`. The `nq disposition`
surface requires one of those forms; finding and liveness reads retain a
legacy fallback to an executable named `nq` on PATH.

## Run one watchbill

Provide an operator-owned Night Shift store, NQ database locator, agenda
YAML, and exact finding key:

```sh
NIGHTSHIFT_NQ_BIN=/absolute/path/to/nq-monitor \
./target/release/nightshift \
  --store /absolute/path/to/nightshift.sqlite \
  --nq-db /absolute/path/to/nq.db \
  watchbill run \
  /absolute/path/to/agenda.yaml \
  --finding '<finding-key>'
```

Night Shift does not open the NQ database itself. It passes the locator to
the injected executable and consumes `nq.finding_snapshot.v1` JSONL. Add
`--nq-liveness /absolute/path/to/liveness.json` to enable the separate
liveness gate. The fixture-only specimen in the
[top-level README](../../README.md#30-second-specimen-the-refusal) needs no
live NQ.

The default path is read-only and governor-blind. The existing Tier-2
horizon path activates only when both `--horizon-policy` and
`--governor-socket` are supplied; either alone is a configuration error.

## Derive an NQ-backed disposition

Night Shift exposes the supported receiver-side interface:

```sh
./target/release/nightshift \
  --nq-bin /absolute/path/to/nq-monitor \
  nq disposition \
  --request /absolute/path/to/request.json \
  --receipt /absolute/path/to/receipt.json \
  --profiles /absolute/path/to/profiles.json \
  --format json
```

Required and optional inputs:

| option | input |
|---|---|
| `--request` | externally prepared `nq.reliance.request.v1` |
| `--receipt` | externally sealed `nq.receipt.v1` |
| `--profiles` | externally prepared `nq.reliance.profiles.v1` |
| `--evidence` | optional evidence-context document |
| `--supporting` | optional sealed supporting receipt; repeat for each receipt |
| `--expected-profile` | expected recipient of NQ's response; default `nightshift-readonly` |
| `--timeout-seconds` | Night Shift wait limit; default 30 |
| `--max-age-seconds` | Night Shift freshness limit; default 900 |

Night Shift neither produces these upstream artifacts nor judges supporting
evidence. It passes the paths to NQ, validates the returned consumer
binding, and projects NQ's decision into
`nightshift.readonly_disposition.v1`. Exit zero includes a derived `stop`;
read the record's `disposition`.

Three cases must remain separate:

- A fresh NQ refusal is NQ testimony and retains its NQ source binding.
- A fresh missing-support or `coverage_insufficient` refusal is also NQ
  testimony. Night Shift does not turn it into no-response or infer the
  absent support's truth.
- Timeout or transport silence is Night Shift's observation. It produces
  `evidence_unavailable`, has no NQ source block, and never fabricates an NQ
  receipt.

See [NQ as a reliance source](../NQ_RELIANCE_SOURCE.md) for the complete
mapping and ownership boundary.

## Derive a bounded diagnostic posture

The Stage 6 foundation exposes a separate pure, read-only posture operation
over exact canonical NQ diagnostic artifacts, a closed Nightshift inventory,
and recurrence evidence. It does not open the Nightshift store or invoke NQ:

```sh
./target/release/nightshift diagnostics posture --help
```

The checked-in
[diagnostic-posture v1-input specimen](examples/diagnostic-posture-v1/README.md)
runs both a current positive posture and a later recurrence-loss posture from
the same immutable NQ bytes. The current evaluator emits
`nightshift.operational_posture.v2`.

## Inspect local records

```sh
./target/release/nightshift \
  --store /absolute/path/to/nightshift.sqlite \
  runs list

./target/release/nightshift \
  --store /absolute/path/to/nightshift.sqlite \
  runs show <run-id>
```

The system-level files under [`../../deploy/systemd/`](../../deploy/systemd/)
are reference deployment scaffolding. They are not a package and require
site-owned absolute paths. The user-level shelf is a quarantined historical
dogfood specimen and must not be installed verbatim.

Operator coverage still owed includes a full packet-reading guide and a
general production deployment/support promise.

# Nightshift

Start with the [component guide](docs/PUBLIC_GUIDE.md) for installation
prerequisites, supported observation paths, trust boundaries, and recovery.

Nightshift is the durable temporal observation and attention office.

It decides when to look again, consumes qualified present support and complete
NQ diagnostic artifacts, computes non-authorizing posture/attention, and may
submit one immutable exact-work proposal to AG. It does not mint standing,
authorize or execute effects, own AG continuation, or call Docket/executors.

The optional Maude plan/session → exact governed proposal relation is documented
in [`docs/authoring-context-provenance.md`](docs/authoring-context-provenance.md).
It establishes lineage only and is never an authorization input.
New authoring handoffs are authenticated under the separate operational
custody contract in
[`docs/authoring-context-custody.md`](docs/authoring-context-custody.md);
producer authentication establishes custody, not permission.

## Runtime status

The production executable surface is two binaries: `nightshift` (the
canonical observation-cycle runtime) and `nightshift-observation-resolver`
(a one-shot, read-only evidence translator for AG's observation boundary).
The sole production cycle is:

```text
exact recurrence slot
  -> exact local NQ-NG admission provenance
  -> exact observation cycle
  -> qualified present-support result
  -> complete NQ diagnostic posture
  -> temporal posture and attention
  -> optional immutable exact-work proposal
  -> new AG occurrence
  -> AG status/settlement reference
  -> fresh observation required, reconciliation display, halt display, or close
```

This runtime has development and hostile-test evidence. It is not yet an
operational qualification claim.

The former Watchbill, Wicket/WLP, MVP-A, classic Governor, authority ladder,
prose action, same-generation skip, and production drill paths have been
removed from the production graph. Historical design records remain under
`docs/working/` and in explicitly marked historical shelves.

## Build

Prerequisites are stable Rust/Cargo 1.82 or newer, a native C toolchain for
bundled SQLite, and crates.io access on an uncached first build.

```sh
cargo build --locked --release --bin nightshift
./target/release/nightshift --help
./target/release/nightshift cycle --help
```

Nightshift has no sibling Wicket or WLP source dependency.

## Run one exact observation cycle

```sh
./target/release/nightshift \
  --store /var/lib/nightshift/nightshift.sqlite \
  cycle run \
  --request /etc/nightshift/cycles/current.json \
  --nq-program /usr/local/bin/nq \
  --nq-config /etc/nq/nq.toml \
  --nq-source-id nq-store-genesis:DEPLOYMENT_GENESIS_ID \
  --present-evidence-resolver /usr/local/bin/pulse-support-resolver
```

The request is a sealed `CanonicalCycleRequestV1` that binds the exact
recurrence slot, observation identity, closed diagnostic policy, complete NQ
input set, recurrence evidence, and optional temporal policy.

The resolver path is an external qualified-authority port, not an executable
shipped by Nightshift. The repository fixture with that basename is not Pulse
and is not deployable support. A site must first qualify a support family that
actually applies to its exact diagnostic decision. That boundary and the one
qualified proposition-specific production family are documented in
[`PRESENT_EVIDENCE_SUPPORT_SOURCE_GATE.md`](docs/PRESENT_EVIDENCE_SUPPORT_SOURCE_GATE.md)
and
[`EXACT_LOAD_PRESSURE_SUPPORT_DEPLOYMENT.md`](docs/EXACT_LOAD_PRESSURE_SUPPORT_DEPLOYMENT.md).

Before claiming the slot, Nightshift asks the configured NQ-NG source to
qualify every delivered artifact. NQ-NG reopens verified local v2 history and
returns `nq.diagnostic_admission_provenance.v1`; Nightshift independently
binds that carrier to the exact canonical bytes, run, profile generation, and
configured source identity, then persists it in the v2 observation record.
Imported custody and unadmitted or substituted artifacts refuse the cycle.
Admission makes evidence eligible for posture reasoning only. It does not
make the observation current or authorize work.

If—and only if—the request carries an immutable precompiled exact-work
proposal, all five AG coordinates are required:

```sh
  --ag-loopctl /usr/local/bin/ag-loopctl \
  --ag-database /var/lib/ag/campaign.sqlite \
  --ag-observation-resolver /usr/local/bin/ag-observation-resolver \
  --ag-observation-resolver-id nightshift-observation-resolver/v1 \
  --ag-runtime-profile /etc/ag/governed-loop-profile.json
```

Nightshift sends AG campaign/occurrence and exact observation/proposal basis.
It sends no standing, authorization, dispatch, retry, reconciliation mutation,
or human disposition.

## Inspect and recover

```sh
nightshift --store /var/lib/nightshift/nightshift.sqlite cycle list
nightshift --store /var/lib/nightshift/nightshift.sqlite cycle show --cycle-id '<id>'
nightshift --store /var/lib/nightshift/nightshift.sqlite cycle replay --cycle-id '<id>'
nightshift --store /var/lib/nightshift/nightshift.sqlite cycle sync-ag --help
nightshift --store /var/lib/nightshift/nightshift.sqlite cycle recover --help
```

Recovery erases local currentness. A prepared AG request is recovered by exact
AG status only and is never resubmitted. Settlement records attempt-native
facts and requires a new observation cycle before posture or work can change.

## Development gates

```sh
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
bash scripts/check_no_actuation_surface.sh
bash scripts/check_no_actuation_surface.sh --self-test-inject
```

The structural gate pins the two binaries, the exact three external process
ports (`nq` qualification, `pulse-support-resolver`, and `ag-loopctl`), and
absence of the retired authority/execution surfaces. It also requires
Nightshift to provide AG's deployment-owned runtime profile at campaign
genesis. The NQ port is pinned to the read-only `diagnostics qualify`
operation.

See [the canonical runtime record](docs/CANONICAL_RUNTIME_C1.md), the
[operator quick start](docs/operator/README.md), and the
[systemd reference units](deploy/systemd/README.md).

## License

Apache-2.0

## Beta work planning

See the [current beta work plan](docs/BETA-WORK.md) for owned requirements, exclusions, dependencies and GitHub issues. Plan publication does not start implementation or transfer qualification.

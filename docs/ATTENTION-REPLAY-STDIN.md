# Replay an attention decision from another tool

Use `attention replay` to check that an existing attention receipt can be
recomputed from its exact policy and history. Replay is read-only: it does not
refresh observations, append history, send a notification, or authorize work.

```sh
nightshift --store ./unused.sqlite attention replay --bundle ./attention.json
nightshift --store ./unused.sqlite attention replay --bundle-stdin < ./attention.json
```

Choose exactly one input option. Standard input accepts one JSON value, optional
trailing whitespace, and at most16MiB. Extra JSON, oversized input, missing input
selection and selecting both options refuse. The existing pathname option retains
its regular-file and no-symlink requirements. The store locator is a required CLI
parameter, but this replay command does not open or mutate that store.

Output has schema `nightshift.project-predicate-attention-replay/v1`, `matches`,
and expected/recomputed receipt digests. A caller must require a successful exit,
`matches: true`, and both digests equal to the receipt it intended to check. A
successful recomputation establishes internal consistency, not current conditions
or the truth/admissibility of upstream evidence.

NQ's notification adapter uses `--bundle-stdin` because its verified launcher
seals executable identity and pathname arguments. Passing a sealed descriptor as
a pathname would conflict with this reader's no-symlink rule. Standard input
preserves the exact retained bytes without relaxing either boundary. Old
Nightshift revisions lacking this option are incompatible with that adapter;
there is no automatic fallback.

Direct CLI replay does not impose a wall-clock deadline on an input stream that
never closes. Embedding callers must close stdin and provide bounded process
supervision. NQ uses its existing bounded runner, limits output, verifies the
configured executable digest/account and binds one configured policy. Notification
delivery remains a separate, explicitly enabled operation.

Focused source checks:

```sh
cargo test --locked -p nightshiftd --lib project_predicate_attention
cargo test --locked -p nightshiftd --bin nightshift exact_input_tests
```

These include input-selection, extra-JSON, oversized-stream and existing pathname
negative controls. An actual NQ/CLI adapter check additionally exercises receipt
replay, retained no-network refusal, exact duplicate convergence and changed-policy/
receipt refusal. Its upstream facts are synthetic; it does not establish live
notification delivery or a complete monitoring deployment.

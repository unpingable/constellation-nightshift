# Bounded turn echo custody candidate

`ProviderAdmissionOwnerPinsV1::bounded_turn_echo_candidate()` selects Switchyard
`6d00e125e4d54191a8034e8e6f201396cffb2c92`, Codex
`97b0acd5ce2ccb3c87a763606696c35a450947f6`, and the vendored
`switchyard.codex-provider-admission.bounded-turn-echo.v2.schema.json`
(`sha256:c851fb5dd157ebb70896da06db50a07b968b3c0d357b2defc73ca267b9d82f93`).
This is a separately enrolled `BOUNDED_TURN_ECHO_V1` capture context, not a
replacement for historical `LEGACY_V1` or `BOUNDED_TURN_V1` tuples.
The exact `6fe1084dc1a0e8e39a5a6c2bc108b39ace682724` and
`ce5a3a0be8f90162581c820b85b2a785557aae24` tuples remain explicit historical
V1 selections with digest `sha256:2bcf795c753a08d3c7e2ef8b521b44b155054fccbd50452662230d59ddd3f293`;
the new implementation never reinterprets those retained identities.

The 256KiB raw bound applies only to the selected outbound `turn/start` request
and exact source-shaped incoming user echoes, agent items/deltas, and final
turn summary. User echoes bind the retained request's one text input, with only
Codex's absent `text_elements` default materialized as `[]`, exact thread/turn,
and one same-ID start/completion pair. Agent items have a closed metadata shape
(phase null/commentary/final_answer; citation and delivery null), sequential
same-ID start/completion, no reused completed IDs, and a final summary matching
the last completion. UTF8 completed agent text totals at most 32768 bytes,
including small nonselected agent completions. Deltas and repeated summary
custody do not multiply the authorized output amount. Other small events,
including reasoning, retain their prior watermark behavior and 16KiB bound.
Unknown large forms refuse; no raw evidence is silently discarded to fit.

The source capture/mapper bound, 16MiB snapshot and aggregate queue bounds,
16MiB selected V3 journal-event/query bounds, and 32768-byte worker output
budget are distinct. Existing V2 profile bytes/digests and historical tuples
are unchanged. A standalone disposition validates a structural union plus
exact raw replay; it does not enroll a source tuple. Full-graph admission checks
the requirement's exact owner/schema tuple and repeats contextual replay.

The `events` CLI emits compact JSON followed by a newline. Its values are
unchanged, but whitespace is not an interface guarantee. Pretty-printing retained
byte arrays expands a valid journal beyond the bounded inspection reader's
allowance. Compact framing retains every value without raising the reader,
stored-event, output, or authority limits; journal bytes and digests are unchanged.

The shared prelaunch-closure validator also accepts the additive
`REQUEST_PREFLIGHT_FAILED` reason. Unlike a runner-observed executable-capture
failure, that reason requires the exact terminal supervisor testimony bound to
`BEFORE_PROVIDER_CLAIM`; Foreman still requires the retained prepared dispatch
and refuses any provider disposition before recording the local closure.

Source-shaped fixture data establishes no provider contact. The compact
cross-language vector expands to a 118500-byte request, two user echoes, and
32768 decoded NUL bytes (worst-case JSON escaping) in delta, completion, and
summary. Its exact snapshot is 1908318 bytes, digest
`sha256:2c1cc7763a5cbb3d5d74f80b84da7613836c1c648967b76cd98123107477c5b2`.

Focused qualification entrypoint (not an assertion that it has run):

```sh
cargo test --locked --offline --release -p nightshift-foreman --test foreman bounded_turn_echo -- --nocapture
```

The native cases exercise admit/prepare/derive/record/events/read-only hydration,
print exact disposition/event/aggregate sizes, retain response-loss readback,
and refuse historical source/schema substitution. Optionally set
`BOUNDED_TURN_ECHO_LEGACY_FOREMAN` to an explicitly qualified historical binary
for a read-only old-reader refusal control. Production qualification and any
new provider request require separate approval; none follows from this fixture.

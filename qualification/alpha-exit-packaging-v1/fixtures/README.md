# Synthetic gate fixtures

All identities, keys and times are synthetic. Nothing here comes from an
operator host.

| File | Produced by |
|---|---|
| `foreman-provider-draft.json` | `zz_gate_dump_provider_draft` (Foreman `holding_fixture_contracts`) |
| `nightshift-synthetic.sqlite` (+ `.expected.json`, `.base-request.json`) | `zz_gate_generate_synthetic_store`: one canonical cycle run through the library with the test NQ/Pulse/AG ports and a synthetic Maude authoring handoff (fixed test HMAC keys), converted to `journal_mode=DELETE` |
| `pulse-config.json`, `pulse-producer-key.hex` | `zz_gate_dump_synthetic_config` (the process-boundary fixture, key seed `[19; 32]`), paths rewritten to `/var/lib/constellation-gate/pulse`, then `profile_semantic_id` set to the NQ 0.2.0 id |

`generator.patch` adds those three scratch-only tests at `3707865`. Apply it to
a checkout and run them with `FOREMAN_GATE_DRAFT`, `NIGHTSHIFT_GATE_STORE` or
`PULSE_GATE_DIR` set.

# Current native NQ-ng qualification witnesses

Implementation candidate for CLASSIC-RETIREMENT. The earlier Q1–Q4 freeze and
M2 acceptance remain historical evidence attached to their original revisions.
This is not deployment or acceptance inherited from those records.

Build the exact reviewed NQ-ng candidate (`cargo build -p nq-app --bin nq`).
No classic binary, source tree, fixture generator, or fallback is required:

```
NQ_NG_BIN=/exact/nq-ng/target/debug/nq Q4_RESOLUTION_OUTPUT=/new/path/q4.json cargo test -p nightshiftd --test repository_qualification_cross_office
NQ_NG_BIN=/exact/nq-ng/target/debug/nq GCL_V0_RESOLUTIONS_OUTPUT=/new/path/gcl-v0.json cargo test -p nightshiftd --test governed_campaign_v0_cross_office
NQ_NG_BIN=/exact/nq-ng/target/debug/nq cargo test -p nightshiftd --test nq_ng_stage_realization -- --ignored
python3 scripts/test_qualification_replay_ports.py
bash scripts/check_no_actuation_surface.sh
```

Run long qualifications under the campaign's durable execution mechanism,
recording exact producer/consumer revisions, binary digest and output locations.
Omitted Q4/GCL environment variables do not establish cross-office validation.

Current ingress uses `--nq-executable /exact/path/nq`. Its only process operation
is read-only stage replay; it admits only modern `nq-ng.campaign-stage-*`
schemas and exact applicability-profile evaluator/build pins. Old records stay
retained as historical bytes; this change does not reissue or migrate them into
current acceptance. New evidence must be generated and replayed by NQ-ng.

The real realization witness covers qualified, failed, indeterminate and
mismatched realization testimony, current versus expired applicability, changed
evidence refusal and classic-schema refusal. Existing unit controls retain
conflicting realizations and refuse unrelated settled predecessors. Q4 traverses
actual modern evaluation, replay, ingress and AG-basis export; GCL V0 regenerates
three actual Git stages without classic. A fixed-path NQ-ng binary and local
trusted build environment remain prerequisites; this migration does not claim
universal executable-custody protection for arbitrary concurrent filesystem
writers, nor grant any effect authority.

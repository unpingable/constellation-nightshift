# Precompiled workflow lineage

`nightshift cycle export-precompiled-workflow-lineage` is a read-only projection
of a relationship already retained by a canonical precompiled cycle:

```sh
nightshift --store /absolute/nightshift.sqlite cycle \
  export-precompiled-workflow-lineage \
  --campaign-id sha256:... \
  --occurrence-id 00000000-0000-4000-8000-000000000000
```

For an exact campaign and occurrence, each
`nightshift.precompiled_workflow_lineage.v1` match binds the typed intent's
`immutable_parameters.plan_document`, its expected AG work, the exact proposal
identity in the prepared AG request, the source cycle request, and the
authoritative cycle state digest. The record has a content-derived `lineage_id`.
Substitution of the plan, proposal, work, intent, request, occurrence, or cycle
state therefore invalidates the projection.

This surface is intentionally narrower than Maude authoring-context custody. It
does not claim a supervised Maude session, authenticated delivery of plan text,
or historical authoring custody. It exists for closed precompiled workflows that
already placed a content-derived plan-document identity in the typed intent.
Absence remains an empty match set.

The command opens the canonical store read-only. Its result is navigation and
causal-lineage evidence only. It grants no standing, admission, authorization,
spend, execution custody, retry, continuation, or objective-completion status.

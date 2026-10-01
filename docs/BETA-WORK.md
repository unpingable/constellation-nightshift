# constellation-nightshift beta work

Planning only, recorded 2026-10-01. Work below is not started by publication of this plan. Source, package, installation, runtime and composition standing remain separate.

## Current state

Start from [`dev/operator-beta`](https://github.com/unpingable/constellation-nightshift/tree/dev/operator-beta), canonical product reconciliation at `76c1238dd5faaa999c76bf467cc3bb307a0ad116`. Documentation commits after that point do not select a different product base or transfer predecessor qualification.

Provider receipt enrollment, currentness/observation runtime, service-investigation tooling and Debian packaging are published. Site-specific request generation and deployment adapters remain outside this component.

## Scope and exclusions

This plan routes current requirements and evidence needed for future bounded work. It does not resume alpha qualification, launch providers, mutate a deployment or implement product changes. Target-specific configuration and operational facts belong in program/application records; component documentation describes abstract interfaces only.

`agent_gov`, Classic NQ (`nq-classic`), retired monorepos, predecessor product lines and historical application implementations are historical/migration evidence only. They are not forward source donors, dependencies or instructions to restore removed APIs. Retired WLP compatibility remains excluded. Record a current requirement if old evidence suggests missing functionality; require an explicit owner decision before any revival.

## NS-01: Plan reusable recurrence and currentness deployment contract

`COMPONENT_PRODUCT` · **Required for operator-beta** · Project: Ready.

Problem: Provider receipt enrollment, observation cycle/runtime and Debian packaging are published; deployed composition uses site-owned request and resolver glue.

Intended outcome: Specify the reusable request/config/read-access and recurrence-history boundary, slot-aligned cadence guidance and reopen behavior without taking ownership of a target scheduler.

Scope/exclusions: Preserve Nightshift non-actuation; no second scheduler for an owned obligation, target adapter import or generic recurrence framework.

Dependencies: NQ immutable artifacts; Monitor present-support; Cartography site-adapter ownership.

Acceptance/evidence: Fresh/stale/missing recurrence, duplicate-slot refusal, resolver substitution and restart cases; site adapter carries prior records without rewriting historical acquisition.

Owner decisions: Any reusable missing contract needs an owner-approved consumer trigger; site adapter changes remain external.

Owning issue: [NS-01](https://github.com/unpingable/constellation-nightshift/issues/4).

## NS-02: Plan Foreman provider lifecycle and supervised recovery evidence

`RELEASE_ENGINEERING` · **Required for operator-beta** · Project: Blocked.

Problem: Durable provider receipt enrollment exists; original no-NIC composition does not establish every provider termination or replacement path.

Intended outcome: Plan exact provider/model selection, caller enrollment, cancellation, interrupted supervisor replacement and same-request reconciliation against current Foreman/Switchyard.

Scope/exclusions: Limit changes to the named outcome; preserve existing semantic and authority boundaries.

Dependencies: Switchyard runtime receipt/export boundary and AG/Docket same-attempt custody.

Acceptance/evidence: Selected current receipt tuple and restart/cancellation/unknown cases, separately admitted bounded provider work; no fallback selection.

Owner decisions: Provider route, enrollment and credential custody must be supplied by caller.

Owning issue: [NS-02](https://github.com/unpingable/constellation-nightshift/issues/5).

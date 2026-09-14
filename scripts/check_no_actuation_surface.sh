#!/usr/bin/env bash
# Structural exclusivity gate for canonical Nightshift production.
#
# This gate is intentionally scoped to production manifests and source. Tests
# may construct hostile values, and clearly historical documents may describe
# retired designs; neither is a production authority surface.

set -uo pipefail

repo_root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$repo_root"

findings=0
fail() {
    printf 'nightshift-exclusivity: %s\n' "$1" >&2
    findings=$((findings + 1))
}

manifest="crates/nightshiftd/Cargo.toml"
production_src="crates/nightshiftd/src"

# Exactly two explicitly named production binaries: the canonical runtime CLI
# and the read-only observation resolver. `autobins = false` prevents an
# added src/main.rs or src/bin/*.rs file from silently becoming a target.
bin_count=$(rg -c '^\[\[bin\]\]$' "$manifest" || true)
if [ "$bin_count" -ne 2 ]; then
    fail "expected exactly two [[bin]] targets, found ${bin_count}"
fi
if ! rg -q '^autobins = false$' "$manifest"; then
    fail "Cargo automatic binary discovery is not disabled"
fi
if ! rg -q '^name = "nightshift"$' "$manifest"; then
    fail "canonical runtime binary is not named nightshift"
fi
if ! rg -q '^path = "src/bin/nightshift.rs"$' "$manifest"; then
    fail "nightshift target does not point to the canonical runtime CLI"
fi
if ! rg -q '^name = "nightshift-observation-resolver"$' "$manifest"; then
    fail "read-only observation resolver binary is not explicitly named"
fi
if ! rg -q '^path = "src/bin/nightshift_observation_resolver.rs"$' "$manifest"; then
    fail "observation resolver target does not point to its read-only source"
fi

# The casework operator is a separate workspace package, not a third
# canonical Nightshift production binary or module.
if ! rg -q '"crates/nightshift-casework"' Cargo.toml; then
    fail "separate casework operator package is not an explicit workspace member"
fi
if rg -n 'nightshift[_-]casework|casework::' "$manifest" "$production_src" \
    >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    fail "casework HTTP/operator machinery entered canonical nightshiftd:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi

# Canonical Nightshift is not a server. Protect this generically so a renamed
# HTTP stack or listener cannot enter the closed production graph.
if rg -n '^[[:space:]]*(axum|actix-web|rocket|warp|hyper|tower-http|tiny_http|rouille)[[:space:]]*=' "$manifest" >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    fail "HTTP/listener dependency entered canonical nightshiftd:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi
if rg -n '(TcpListener|UnixListener|axum::serve|hyper::server|Server::bind|(^|[^[:alnum:]_])serve\()' "$production_src" >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    fail "HTTP/listener site entered canonical nightshiftd:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi

# The observation resolver is the one permitted second binary: a read-only
# evidence translator for AG's observation-resolution boundary. It must open
# no subprocess, must not use the migrating store open path, and must call no
# cycle-mutating store method.
resolver_sources="crates/nightshiftd/src/observation_resolver.rs crates/nightshiftd/src/bin/nightshift_observation_resolver.rs"
for source in $resolver_sources; do
    if [ ! -f "$source" ]; then
        fail "observation resolver source is missing: $source"
    fi
done
if rg -n 'Command::new' $resolver_sources >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    fail "observation resolver opens a subprocess:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi
if rg -n 'CanonicalStore::open\(' $resolver_sources >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    fail "observation resolver uses the migrating store open path:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi
if rg -n '\.(claim_slot|record_missed|record_observation|prepare_ag_occurrence|attach_ag_occurrence|record_ag_status|record_ag_refusal|recover_ag_occurrence|mark_recovery_required|close_without_proposal|recover_after_restart)\(' $resolver_sources >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    fail "observation resolver calls a cycle-mutating store method:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi

# Active system-level deployment must target the same binary and cycle
# surface. The user/ shelf is explicitly historical and is not installable.
active_units=(
    deploy/systemd/nightshift-observation-cycle.service
    deploy/systemd/nightshift-observation-cycle.timer
    deploy/systemd/observation-cycle.env.example
)
for unit in "${active_units[@]}"; do
    if [ ! -f "$unit" ]; then
        fail "canonical deployment file is missing: ${unit}"
    fi
done
mapfile -t retired_user_units < <(
    find deploy/systemd/user -maxdepth 1 -type f \
        \( -name '*.service' -o -name '*.timer' \) -print 2>/dev/null | sort
)
if [ "${#retired_user_units[@]}" -ne 0 ]; then
    fail "retired user-level runtime units remain: ${retired_user_units[*]}"
fi
if ! rg -q '/nightshift[[:space:]\\]+$' deploy/systemd/nightshift-observation-cycle.service \
    || ! rg -q 'cycle run' deploy/systemd/nightshift-observation-cycle.service; then
    fail "systemd service does not invoke canonical nightshift cycle run"
fi
for nq_option in nq-program nq-config nq-source-id; do
    if ! rg -q -- "--${nq_option}" deploy/systemd/nightshift-observation-cycle.service; then
        fail "systemd service does not bind required NQ admission option --${nq_option}"
    fi
done
if ! rg -q '\$NIGHTSHIFT_CONTINUITY_FLAGS' deploy/systemd/nightshift-observation-cycle.service \
    || ! rg -q '^NIGHTSHIFT_CONTINUITY_FLAGS=$' deploy/systemd/observation-cycle.env.example; then
    fail "active deployment cannot pin optional Standing continuity verification material"
fi
if ! rg -q '\$NIGHTSHIFT_SUBSTRATE_ORIGIN_FLAGS' deploy/systemd/nightshift-observation-cycle.service \
    || ! rg -q '^NIGHTSHIFT_SUBSTRATE_ORIGIN_FLAGS=$' deploy/systemd/observation-cycle.env.example; then
    fail "active deployment cannot pin an owner-required substrate-origin V3 verifier"
fi
if rg -n -i 'watchbill|wicket|\bwlp\b|governor|no-governor|authority[_ -]?level|scheduled[_ -]?skip' \
    "${active_units[@]}" >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    fail "retired runtime vocabulary remains in active systemd deployment:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi
if rg -n 'nightshift-canonical|src/main\.rs' "$manifest" "$production_src" >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    fail "transitional or legacy binary identity remains in production:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi

# Retired authority stacks and their packet vocabulary must not re-enter any
# production module or dependency graph.
forbidden_manifest='^[[:space:]]*(wicket|wlp|docket)[[:space:]]*='
if rg -n -i "$forbidden_manifest" Cargo.toml crates/*/Cargo.toml >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    fail "retired or execution-custody dependency found in production manifest:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi

forbidden_production=(
    'wicket(::|[[:space:]]|_)'
    '(^|[^[:alnum:]_])wlp(::|[^[:alnum:]_]|$)'
    'mvp[_-]?a'
    'governor(_client)?'
    '--no-governor'
    'ActionAuthorized'
    'AuthorityResult'
    'AuthorizationReceipt'
    'ProposedAction'
    'AuthorityLevel'
    'effective[_-]?authority'
    'authority[_-]?ceiling'
    'continuity_configured'
    'scheduled[_-]?skip'
    'same[_-]?generation.*skip'
    'snapshot_generation.*skip'
    '(^|[^[:alnum:]_])drill(s|er)?([^[:alnum:]_]|$)'
)
for pattern in "${forbidden_production[@]}"; do
    if rg -n -i -- "$pattern" "$production_src" >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
        fail "retired production symbol matched /${pattern}/:"
        cat /tmp/nightshift_exclusivity_hits >&2
    fi
done

# Nightshift may observe Docket attempt and settlement identifiers received
# through AG. It may not import Docket, invoke Docket, or own an executor port.
for pattern in 'use[[:space:]]+docket(::|;)' 'docket::' 'Command::new\([^)]*docket' 'Command::new\([^)]*(effectd|executor)' 'use[[:space:]].*(effectd|executor)(::|;)' ; do
    if rg -n -i -- "$pattern" "$production_src" >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
        fail "direct execution-custody/effect surface matched /${pattern}/:"
        cat /tmp/nightshift_exclusivity_hits >&2
    fi
done

# Generic actuators and control-plane clients are never valid Nightshift ports.
actuators='ssh|salt(-call)?|ansible(-playbook)?|systemctl|kubectl|docker|podman|helm|terraform|scp|rsync|curl|wget'
if rg -n -i "Command::new\\([[:space:]]*\"(${actuators})\"" "$production_src" >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    fail "actuator subprocess found:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi
if rg -n '^[[:space:]]*(ssh2|russh|openssh|kube|k8s-openapi|bollard|reqwest|ureq|isahc)[[:space:]]*=' Cargo.toml crates/*/Cargo.toml >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    fail "actuator/control-plane dependency found:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi
if rg -n '\.(post|put|delete|patch)\(' "$production_src" >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    fail "control-plane HTTP write method found:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi

# The only process boundaries are exact, closed ports: read-only NQ admission
# qualification, present-support resolution, exact Pulse receipt replay,
# exact NQ repository-qualification replay, exact NQ reservation-realization
# replay, the retained saved-check verifier, and AG occurrence opening/status.
# Any other process site is a new runtime authority or execution surface and
# fails closed.
mapfile -t command_files < <(rg -l 'Command::new' "$production_src" | sort)
expected_command_files=(
    crates/nightshiftd/src/ag_port.rs
    crates/nightshiftd/src/currentness.rs
    crates/nightshiftd/src/nq_admission.rs
    crates/nightshiftd/src/project_predicate_attention.rs
    crates/nightshiftd/src/repository_qualification.rs
    crates/nightshiftd/src/reservation_qualification.rs
    crates/nightshiftd/src/saved_check_runtime.rs
)
if [ "${command_files[*]}" != "${expected_command_files[*]}" ]; then
    fail "production subprocess files are not the exact closed port set: ${command_files[*]:-<none>}"
fi
if [ "$(rg -c 'Command::new' crates/nightshiftd/src/ag_port.rs || true)" -ne 1 ]; then
    fail "AG port must contain exactly one subprocess site"
fi
if [ "$(rg -c 'Command::new' crates/nightshiftd/src/currentness.rs || true)" -ne 1 ]; then
    fail "present-support port must contain exactly one subprocess site"
fi
if [ "$(rg -c 'Command::new' crates/nightshiftd/src/nq_admission.rs || true)" -ne 1 ]; then
    fail "NQ admission port must contain exactly one subprocess site"
fi
if [ "$(rg -c 'Command::new' crates/nightshiftd/src/project_predicate_attention.rs || true)" -ne 1 ]; then
    fail "generic attention Pulse verifier must contain exactly one subprocess site"
fi
if [ "$(rg -c 'Command::new' crates/nightshiftd/src/repository_qualification.rs || true)" -ne 1 ]; then
    fail "repository-qualification ingress must contain exactly one subprocess site"
fi
if [ "$(rg -c 'Command::new' crates/nightshiftd/src/reservation_qualification.rs || true)" -ne 1 ]; then
    fail "reservation-realization ingress must contain exactly one subprocess site"
fi
# Preserve both the exact site count and retirement's whole command-chain
# checks for the modern NQ-ng replay consumers. Neither alone is qualification.
if ! python3 scripts/check_qualification_replay_ports.py; then
    fail "qualification replay port widened beyond its exact read-only command"
fi
if ! rg -q 'Some\("ag-loopctl"\)' crates/nightshiftd/src/ag_port.rs; then
    fail "AG port is not executable-name pinned to ag-loopctl"
fi
if ! rg -q '"--runtime-profile"' crates/nightshiftd/src/ag_port.rs; then
    fail "AG campaign genesis is not bound to a deployment-owned runtime profile"
fi
if ! rg -q '"--expected-observation-resolver-id"' crates/nightshiftd/src/ag_port.rs; then
    fail "AG proposal recording does not repeat the profile-checked resolver identity"
fi
if ! rg -q 'Some\("pulse-support-resolver"\)' crates/nightshiftd/src/currentness.rs; then
    fail "present-support port is not executable-name pinned to pulse-support-resolver"
fi
if ! rg -q 'Some\("nq"\)' crates/nightshiftd/src/nq_admission.rs; then
    fail "NQ admission port is not executable-name pinned to nq"
fi
if ! rg -q '\.arg\("qualify"\)' crates/nightshiftd/src/nq_admission.rs; then
    fail "NQ admission port lost its sole read-only qualification operation"
fi
if ! rg -q 'Some\("pulse-project-predicate-support"\)' crates/nightshiftd/src/project_predicate_attention.rs \
    || ! rg -q '\.args\(\["replay"' crates/nightshiftd/src/project_predicate_attention.rs; then
    fail "generic attention port is not pinned to exact Pulse replay"
fi
if ! rg -q 'Some\("nq"\)' crates/nightshiftd/src/repository_qualification.rs \
    || ! rg -q '"campaign-stage-qualification"' crates/nightshiftd/src/repository_qualification.rs \
    || ! rg -q '"replay"' crates/nightshiftd/src/repository_qualification.rs; then
    fail "repository-qualification port is not pinned to exact NQ-ng nq replay"
fi
if ! rg -q 'Some\("nq"\)' crates/nightshiftd/src/reservation_qualification.rs \
    || ! rg -q '"campaign-stage-realization"' crates/nightshiftd/src/reservation_qualification.rs \
    || ! rg -q '"replay"' crates/nightshiftd/src/reservation_qualification.rs; then
    fail "reservation-realization port is not pinned to exact NQ-ng nq replay"
fi
for forbidden_qualification_verb in evaluate execute import export watcher admit revoke collect; do
    if rg -n "\.arg(s)?\(.*\"${forbidden_qualification_verb}\"" crates/nightshiftd/src/repository_qualification.rs >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
        fail "repository-qualification NQ port exposes forbidden verb ${forbidden_qualification_verb}:"
        cat /tmp/nightshift_exclusivity_hits >&2
    fi
done
for forbidden_realization_verb in evaluate execute import export watcher admit revoke collect; do
    if rg -n "\.arg(s)?\(.*\"${forbidden_realization_verb}\"" crates/nightshiftd/src/reservation_qualification.rs >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
        fail "reservation-realization NQ port exposes forbidden verb ${forbidden_realization_verb}:"
        cat /tmp/nightshift_exclusivity_hits >&2
    fi
done
for forbidden_pulse_verb in qualify acquire collect produce sign; do
    if rg -n "\.arg(s)?\(.*\"${forbidden_pulse_verb}\"" crates/nightshiftd/src/project_predicate_attention.rs >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
        fail "generic attention Pulse port exposes forbidden verb ${forbidden_pulse_verb}:"
        cat /tmp/nightshift_exclusivity_hits >&2
    fi
done
for forbidden_nq_verb in execute import export watcher admit revoke collect; do
    if rg -n "\.arg\(\"${forbidden_nq_verb}\"\)" crates/nightshiftd/src/nq_admission.rs >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
        fail "Nightshift NQ admission port exposes forbidden verb ${forbidden_nq_verb}:"
        cat /tmp/nightshift_exclusivity_hits >&2
    fi
done

for forbidden_ag_verb in authorize dispatch retry reconcile standing resume halt disposition; do
    if rg -n "run(_with_input)?\\(\"${forbidden_ag_verb}\"" crates/nightshiftd/src/ag_port.rs >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
        fail "Nightshift AG port exposes forbidden verb ${forbidden_ag_verb}:"
        cat /tmp/nightshift_exclusivity_hits >&2
    fi
done
for required_ag_verb in init continue record-proposal status inspect verify-runtime-profile-v2; do
    if ! rg -q "\"${required_ag_verb}\"" crates/nightshiftd/src/ag_port.rs; then
        fail "Nightshift AG port lost required closed verb ${required_ag_verb}"
    fi
done

# Authoring-context lineage is deliberately authority-neutral. Its constructor
# is crate-private and the final mint occurs only at canonical proposal
# compilation; no field or AG wire type may carry authority material.
authoring_source="crates/nightshiftd/src/authoring_context.rs"
custody_source="crates/nightshiftd/src/authoring_custody.rs"
if rg -n 'pub (authorization|spend|issuance|signature|capability|secret|standing|admissibility):' "$authoring_source" >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    fail "authoring-context provenance contains authority-bearing fields:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi
if rg -n 'pub (authorization|spend|issuance|capability|secret|standing|admissibility|currentness):' "$custody_source" >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    fail "authoring custody contains governed authority fields:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi
if [ "$(rg -c 'AuthoringContextProvenanceV1::mint' crates/nightshiftd/src/canonical_runtime.rs || true)" -ne 1 ]; then
    fail "authoring-context provenance mint is not confined to the canonical handoff"
fi
if [ "$(rg -c 'AuthoringContextCustodyProvenanceV1::mint' crates/nightshiftd/src/canonical_runtime.rs || true)" -ne 1 ]; then
    fail "authoring custody mint is not confined to the canonical handoff"
fi

# External application/world observations are authenticated source evidence.
# Custody is inert; the separate Nightshift composition module may admit an
# exact source into a canonical observation, but neither surface may mint AG
# authority or invoke effects. The deployment profile, never the producer,
# owns the evidence horizon.
external_observation_source="crates/nightshiftd/src/external_observation.rs"
external_composition_source="crates/nightshiftd/src/external_evidence_composition.rs"
if [ ! -f "$external_observation_source" ]; then
    fail "external-observation custody source is missing"
fi
if rg -n 'Command::new|AgOccurrencePortV1|Docket|Authorization|StandingResolution|QualifiedSupportV1' \
    "$external_observation_source" >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    # Narrative comments and explicit nonclaims may name layers. Restrict the
    # actionable check to Rust paths/types/process construction.
    if rg -n 'Command::new|docket::|ag_port::|AuthorizationReceipt|StandingResolution|QualifiedSupportV1' \
        "$external_observation_source" >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
        fail "external-observation custody reaches governed authority/effect code:"
        cat /tmp/nightshift_exclusivity_hits >&2
    fi
fi
if rg -n 'pub (authorization|spend|standing|capability|currentness|admissibility):' \
    "$external_observation_source" >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    fail "external-observation record contains authority-bearing fields:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi
if [ "$(rg -c 'ExternalObservationCustodyProvenanceV1::mint' crates/nightshiftd/src/canonical_store.rs || true)" -ne 1 ]; then
    fail "external-observation custody mint is not confined to canonical store insertion"
fi
runtime_test_line=$(rg -n '^#\[cfg\(test\)\]$' crates/nightshiftd/src/canonical_runtime.rs | head -n1 | cut -d: -f1)
if rg -n 'record_external_observation' crates/nightshiftd/src/canonical_runtime.rs crates/nightshiftd/src/observation_resolver.rs \
    | awk -F: -v test_line="${runtime_test_line:-999999}" \
        '$1 != "crates/nightshiftd/src/canonical_runtime.rs" || $2 < test_line' \
        >/tmp/nightshift_exclusivity_hits 2>/dev/null \
    && [ -s /tmp/nightshift_exclusivity_hits ]; then
    fail "external-observation custody insertion leaked into cycle currentness/runtime evaluation:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi
if [ ! -f "$external_composition_source" ]; then
    fail "external-evidence composition source is missing"
fi
if rg -n 'Command::new|docket::|ag_port::|AuthorizationReceipt|StandingResolution|AgSpend|dispatch\(' \
    "$external_composition_source" >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    fail "external-evidence composition reaches governed authority/effect code:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi
if rg -n 'pub (authorization|spend|standing|capability|admissibility):' \
    "$external_composition_source" >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    fail "external-evidence composition contains authority-bearing fields:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi
if rg -n 'max_age_ms|fresh_until_unix_ms' "$external_observation_source" >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    fail "external-observation producer/custody surface chooses Nightshift currentness policy:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi
mapfile -t composition_callers < <(
    rg -l 'ComposedExternalEvidenceV1::compose' crates/nightshiftd/src \
        | rg -v 'external_evidence_composition.rs$' \
        | sort
)
expected_composition_callers=(
    crates/nightshiftd/src/canonical_runtime.rs
    crates/nightshiftd/src/canonical_store.rs
)
if [ "${composition_callers[*]}" != "${expected_composition_callers[*]}" ]; then
    fail "external-evidence composition constructor escaped canonical runtime/store revalidation: ${composition_callers[*]:-<none>}"
fi
if ! rg -q 'resolve_observation' crates/nightshiftd/src/canonical_runtime.rs \
    || ! rg -q 'fresh_until_unix_ms' crates/nightshiftd/src/observation_resolver.rs; then
    fail "external evidence is not routed through canonical observation/currentness ownership"
fi

# Passive steady-state evidence is a second source class, not a weakened
# qualification profile. Only canonical runtime/store may compose it, and the
# canonical resolver alone consumes its owner-produced horizon.
steady_source="crates/nightshiftd/src/steady_state_evidence.rs"
if [ ! -f "$steady_source" ]; then
    fail "steady-state evidence source is missing"
fi
if rg -n 'Command::new|docket::|AuthorizationReceipt|StandingResolution|AgSpend|dispatch\(' \
    "$steady_source" >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    fail "steady-state evidence reaches authority/effect code:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi
if rg -n 'pub (authorization|spend|standing|capability|admissibility):' \
    "$steady_source" >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    fail "steady-state evidence contains authority-bearing fields:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi
mapfile -t decision_composition_callers < <(
    rg -l 'ComposedDecisionRelativeEvidenceV1::compose' crates/nightshiftd/src \
        | rg -v 'steady_state_evidence.rs$' \
        | sort
)
if [ "${decision_composition_callers[*]}" != "${expected_composition_callers[*]}" ]; then
    fail "decision-evidence composition escaped canonical runtime/store: ${decision_composition_callers[*]:-<none>}"
fi
if ! rg -q 'decision_external_evidence' crates/nightshiftd/src/observation_resolver.rs; then
    fail "passive evidence horizon is not consequence-time revalidated by canonical resolver"
fi
if [ "$(rg -c 'require_qualification_target_artifact\(' crates/nightshiftd/src/canonical_runtime.rs || true)" -ne 4 ]; then
    # One definition, admission-time and consequence-time calls, plus the
    # composition-level wrapper's second defensive check.
    fail "historical qualification is not pinned to the target PlanDocument at both decision boundaries"
fi
if rg -n 'SingleCacheFailureSurvived|CacheTopologyRestored' "$steady_source" \
    | rg 'SteadyStateClaimKindV1::' >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    fail "passive claim enum can mint effectful qualification claims:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi
atomicity_doc="docs/ARTIFACT_CHANGE_AND_REQUALIFICATION_V1.md"
if ! rg -Fq 'there is no currently' "$atomicity_doc" \
    || ! rg -Fq 'governed transition to a state in which successor artifact C2 is deployed' "$atomicity_doc" \
    || ! rg -Fq 'Qualification is therefore not a mutable artifact attribute' "$atomicity_doc"; then
    fail "V1 artifact-change atomicity/negative-reachability contract is missing"
fi
if rg -n 'DeployOnly|deploy_only|UnqualifiedObservationTarget|unqualified_observation_target' \
    crates/nightshiftd/src >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    fail "Nightshift introduced a deploy-only or unqualified observation-target semantic:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi
if [ "$(rg -c 'MaudeCustodyVerifierV1::from_key_file' crates/nightshiftd/src/bin/nightshift.rs || true)" -ne 1 ]; then
    fail "production Maude custody authentication is not confined to cycle ingress"
fi
if [ "$(rg -c 'read_protected_key_path\(' "$custody_source" || true)" -ne 3 ]; then
    # One definition and exactly two calls: independently pinned producer and
    # supervised-session issuer credentials.
    fail "Maude handoff producer and session issuer are not independently authenticated"
fi
for required_role in session_issuer_principal_id session_issuer_key_id producer_principal_id producer_key_id; do
    if ! rg -q "pub ${required_role}: String" "$custody_source"; then
        fail "authoring custody lost distinct identity role ${required_role}"
    fi
done
if rg -n '^pub fn sign_|^pub\(crate\) fn sign_' "$custody_source" | rg -v '#\[cfg\(test\)\]' >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    # The cfg attributes sit on the preceding lines, so separately require
    # every crate-confined signer name to occur only in the test section.
    first_test_line=$(rg -n '^#\[cfg\(test\)\]$' "$custody_source" | head -n1 | cut -d: -f1)
    first_sign_line=$(rg -n 'pub\(crate\) fn sign_' "$custody_source" | head -n1 | cut -d: -f1)
    if [ -n "${first_sign_line:-}" ] && [ "${first_sign_line}" -lt "${first_test_line:-0}" ]; then
        fail "production Nightshift exposes a custody signer"
    fi
fi
if ! rg -q 'pub\(crate\) fn prepare_ag_occurrence' crates/nightshiftd/src/canonical_store.rs; then
    fail "canonical proposal preparation became externally callable"
fi
if rg -n 'authoring_context|AuthoringContext|authoring_custody|AuthoringCustody|MaudeCustody' crates/nightshiftd/src/ag_port.rs >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    fail "AG wire adapter consumes Maude authoring context:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi

# Continuity authority is an asymmetric verification-only ingress. Standing
# signs; NQ commits the exact prerequisite before provider invocation;
# Nightshift may only verify and record an applicability predicate.
continuity_source="crates/nightshiftd/src/continuity_authority.rs"
continuity_doc="docs/CONTINUITY_AUTHORITY_CARRIER_V1.md"
if [ ! -f "$continuity_source" ] || [ ! -f "$continuity_doc" ]; then
    fail "continuity-authority verifier or canonical contract is missing"
fi
if ! rg -q 'ed25519_dalek::.*VerifyingKey' "$continuity_source" \
    || ! rg -q 'pub struct ContinuityAuthorityVerifierV1' "$continuity_source"; then
    fail "continuity-authority ingress is not pinned to asymmetric verification"
fi
if rg -n 'pub fn (sign|mint|issue|authorize)|Command::new|AgOccurrencePortV1|Docket' \
    "$continuity_source" >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    fail "Nightshift continuity verifier exposes issuance, execution, or subprocess authority:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi
if rg -n 'issued_at[[:space:]]*(<|>|==|!=)|committed_at[[:space:]]*(<|>|==|!=)' \
    "$continuity_source" >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    fail "continuity applicability uses asserted timestamps as causal proof:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi
if rg -n -i 'hostname|dns|ip_address|current_substrate|continuity_authorized[[:space:]]*:' \
    "$continuity_source" >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    fail "continuity applicability contains a heuristic or mutable-authority shortcut:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi
if ! rg -q 'independently_established_predecessor_ref: Option<&str>' "$continuity_source" \
    || ! rg -q 'independently_established_observation_substrate_ref: Option<&str>' \
    "$continuity_source" \
    || ! rg -q 'ObservationSubstrateAbsent' "$continuity_source"; then
    fail "continuity applicability no longer fails closed without independent substrate evidence"
fi
if rg -n 'standing-continuity-(private|secret|signing)' crates/nightshiftd/src/bin/nightshift.rs \
    >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    fail "production Nightshift CLI accepts Standing private/signing material:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi

# Substrate origin is an asymmetric evidence ingress and an append-only
# relying-side chain. It neither signs, acts, nor accepts configured identity,
# DNS, IP, hostname, or a mutable current-substrate field as origin proof.
substrate_origin_source="crates/nightshiftd/src/substrate_origin.rs"
substrate_origin_doc="docs/architecture/substrate-origin-v2.md"
if [ ! -f "$substrate_origin_source" ] || [ ! -f "$substrate_origin_doc" ]; then
    fail "substrate-origin verifier or canonical contract is missing"
fi
if ! rg -q 'pub struct SubstrateOriginVerifierV1' "$substrate_origin_source" \
    || ! rg -q 'SubstrateOriginApplicabilityV1' crates/nightshiftd/src/canonical_store.rs; then
    fail "substrate-origin verification/applicability path is missing"
fi
if ! rg -q 'substrate_origin_head' crates/nightshiftd/src/canonical_store.rs \
    || ! rg -q 'V3 is required; V1 configured identity cannot establish continuity' \
    crates/nightshiftd/src/nq_admission.rs; then
    fail "append-only predecessor history or V1 downgrade refusal is missing"
fi
if ! rg -q 'LINODE_INSTANCE_METADATA_PROFILE_V1' "$substrate_origin_source" \
    || ! rg -q 'host UUID is supplemental evidence and is not part of the qualified coordinate' \
    "$substrate_origin_source" \
    || ! rg -q 'expected_linode_instance_id_sha256' \
    crates/nightshiftd/src/bin/nightshift.rs; then
    fail "closed Linode logical-instance profile or exact relying-side pin is missing"
fi
if awk '/#\[cfg\(test\)\]/{exit} {print}' "$substrate_origin_source" \
    | rg -n 'SigningKey|Command::new|pub (hostname|dns|ip|boot_id|machine_id|current_substrate):' \
      >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    fail "production substrate-origin verifier contains signing, execution, or heuristic origin material:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi
if rg -n 'substrate-origin-(private|secret|signing)' crates/nightshiftd/src/bin/nightshift.rs \
    >/tmp/nightshift_exclusivity_hits 2>/dev/null; then
    fail "production Nightshift CLI accepts origin private/signing material:"
    cat /tmp/nightshift_exclusivity_hits >&2
fi

# Self-test against a disposable copy: every representative resurrection must
# make the copied guard fail. This does not mutate the real worktree.
if [ "${1:-}" = "--self-test-inject" ]; then
    sandbox=$(mktemp -d)
    trap 'rm -rf "$sandbox" /tmp/nightshift_exclusivity_hits /tmp/nightshift_exclusivity_selftest' EXIT
    mkdir "$sandbox/repo"
    cp -a Cargo.toml Cargo.lock crates deploy docs scripts "$sandbox/repo/"

    cat >"$sandbox/repo/crates/nightshiftd/src/_legacy_resurrection.rs" <<'EOF'
use wicket::Intent;
fn bad() {
    let _ = std::process::Command::new("docket");
    let _ = std::net::TcpListener::bind("127.0.0.1:0");
    let _ = "--no-governor";
    let _ = "ProposedAction";
}
EOF
    cat >>"$sandbox/repo/crates/nightshiftd/Cargo.toml" <<'EOF'
wlp = "0.1"
EOF

    if (cd "$sandbox/repo" && bash scripts/check_no_actuation_surface.sh >/dev/null 2>/tmp/nightshift_exclusivity_selftest); then
        printf 'self-test FAILED: injected legacy authority/execution surface passed\n' >&2
        exit 1
    fi
    for marker in wicket wlp docket listener no-governor ProposedAction; do
        if ! rg -q -i -- "$marker" /tmp/nightshift_exclusivity_selftest; then
            printf 'self-test FAILED: injection %s was not reported\n' "$marker" >&2
            cat /tmp/nightshift_exclusivity_selftest >&2
            exit 1
        fi
    done
    printf 'self-test PASSED: Wicket, WLP, Docket, generic listener, Governor-mode, and prose-action resurrections were rejected.\n' >&2
    exit 0
fi

rm -f /tmp/nightshift_exclusivity_hits
if [ "$findings" -ne 0 ]; then
    printf 'nightshift-exclusivity: FAILED (%d finding(s))\n' "$findings" >&2
    exit 1
fi
printf 'nightshift-exclusivity: clean canonical production graph\n'

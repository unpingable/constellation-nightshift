#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
store="$root/crates/nightshift-foreman/src/store.rs"
contract="$root/crates/nightshift-foreman/src/contract.rs"
requirement_schema="$root/schemas/nightshift.foreman-capacity-requirement.v1.schema.json"
admission_schema="$root/schemas/nightshift.foreman-capacity-admission.v1.schema.json"

check_owner_law() {
  local checked_store="$1"
  local checked_contract="$2"
  local checked_requirement="$3"
  local checked_admission="$4"
  for marker in \
    'admit_with_capacity_requirement' \
    'prepare_attempt_with_capacity' \
    'capacity-required run refuses legacy attempt preparation' \
    'TransactionBehavior::Immediate' \
    'capacity decision is not current at exact attempt admission' \
    'capacity decision is not the exact deterministic FUEL outcome' \
    'validate_capacity_history' \
    'MAXIMUM_CAPACITY_HISTORY_BYTES' \
    'maximum_capacity_rows' \
    'length[(]raw_bytes[)]' \
    'capacity journal history' \
    'capacity observation model family' \
    '"capacity_requirement"' \
    '"capacity_admission"' \
    'CapacityRequirementAdmitted' \
    'CapacityAdmissionAccepted' \
    'capacity_admissions'; do
    rg -q "$marker" "$checked_store" || return 1
  done
  for marker in \
    'LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY' \
    'speculative capacity admission is unbound' \
    'capacity model-class binding' \
    'nightshift.foreman-capacity-requirement.digest/v1' \
    'nightshift.foreman-capacity-admission.digest/v1'; do
    rg -q "$marker" "$checked_contract" || return 1
  done
  for schema in "$checked_requirement" "$checked_admission"; do
    [[ -f "$schema" ]] || return 1
    rg -q '"additionalProperties": false' "$schema" || return 1
  done
  if rg -n 'std::process::Command|respond_approval|send_approval|automatic_retry' \
      "$checked_store" "$checked_contract" >/dev/null; then
    return 1
  fi
  # SECOND-WATCH records an explicit nonclaim on its sealed driver step.
  # Permit only that literal false field, not another aggregate expression.
  if rg --no-filename 'aggregate_result' "$checked_store" "$checked_contract" \
      | rg -v '^[[:space:]]*aggregate_result_created: false,[[:space:]]*$' >/dev/null; then
    return 1
  fi
}

if ! check_owner_law "$store" "$contract" "$requirement_schema" "$admission_schema"; then
  echo "foreman capacity-admission boundary: owner law is incomplete or widened"
  exit 1
fi

if [[ "${1:-}" == "--self-test-inject" ]]; then
  fixture="$(mktemp -d)"
  trap 'rm -rf -- "$fixture"' EXIT
  mkdir -p "$fixture/src" "$fixture/schemas"
  cp "$store" "$fixture/src/store.rs"
  cp "$contract" "$fixture/src/contract.rs"
  cp "$requirement_schema" "$fixture/schemas/requirement.json"
  cp "$admission_schema" "$fixture/schemas/admission.json"
  perl -0pi -e 's/capacity-required run refuses legacy attempt preparation/capacity path is optional/' \
    "$fixture/src/store.rs"
  if check_owner_law \
      "$fixture/src/store.rs" \
      "$fixture/src/contract.rs" \
      "$fixture/schemas/requirement.json" \
      "$fixture/schemas/admission.json"; then
    echo "foreman capacity-admission boundary negative control did not fail"
    exit 1
  fi
  cp "$store" "$fixture/src/store.rs"
  perl -0pi -e 's/aggregate_result_created: false/aggregate_result_created: true/' \
    "$fixture/src/store.rs"
  if check_owner_law "$fixture/src/store.rs" "$fixture/src/contract.rs" \
      "$fixture/schemas/requirement.json" "$fixture/schemas/admission.json"; then
    echo "foreman capacity-admission boundary accepted an aggregate assertion"
    exit 1
  fi
  echo "foreman capacity-admission boundary deterministic negative control: passed"
  exit 0
fi

echo "foreman capacity-admission boundary: passed"

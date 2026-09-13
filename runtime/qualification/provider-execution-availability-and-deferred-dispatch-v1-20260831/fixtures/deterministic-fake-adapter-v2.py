#!/usr/bin/env python3
"""SECOND-WATCH qualification-only deterministic provider execution fixture.

This campaign-owned fixture performs no network access, starts no listener,
reads no provider profile, and is never registered as a production adapter.
It canonicalizes one closed evidence object. V2 adds an exact completed
execution outcome while retaining the explicit provider-unavailable outcome.
"""

import json
import sys

EXPECTED = {
    "outcome",
    "response_created",
    "non_admission_proven",
    "retry_after",
    "observed_at",
    "provider_execution",
}
OUTCOMES = {"PROVIDER_UNAVAILABLE", "EXECUTION_COMPLETED"}
EXECUTION_FIELDS = {
    "provider_id",
    "model_id",
    "app_server_session_identity",
    "thread_id",
    "turn_id",
    "first_response_id",
}


def _closed_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def main() -> int:
    value = json.load(sys.stdin, object_pairs_hook=_closed_object)
    if not isinstance(value, dict) or set(value) != EXPECTED:
        raise ValueError("closed qualification execution evidence fields do not match")
    if value["outcome"] not in OUTCOMES:
        raise ValueError("unknown qualification execution outcome")
    if not isinstance(value["response_created"], bool):
        raise ValueError("response_created must be boolean")
    if not isinstance(value["non_admission_proven"], bool):
        raise ValueError("non_admission_proven must be boolean")
    if value["retry_after"] is not None and not isinstance(value["retry_after"], str):
        raise ValueError("retry_after must be null or string")
    if not isinstance(value["observed_at"], str):
        raise ValueError("observed_at must be string")
    execution = value["provider_execution"]
    if execution is not None and (
        not isinstance(execution, dict)
        or set(execution) != EXECUTION_FIELDS
        or any(not isinstance(item, str) or not item for item in execution.values())
    ):
        raise ValueError("closed provider execution identity does not match")
    if value["outcome"] == "PROVIDER_UNAVAILABLE":
        if (
            value["response_created"]
            or not value["non_admission_proven"]
            or value["retry_after"] is None
            or execution is not None
        ):
            raise ValueError("provider unavailable must prove exact non-admission")
    elif (
        not value["response_created"]
        or value["non_admission_proven"]
        or value["retry_after"] is not None
        or execution is None
    ):
        raise ValueError("execution completed must retain exact execution identity")
    sys.stdout.write(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

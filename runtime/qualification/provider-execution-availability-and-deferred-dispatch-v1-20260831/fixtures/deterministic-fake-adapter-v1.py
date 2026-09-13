#!/usr/bin/env python3
"""Qualification-only deterministic provider-admission evidence fixture.

This fixture performs no network access, starts no listener, reads no provider
profile, and is not registered as a production adapter. It accepts one closed
JSON object on stdin and emits the same object in canonical form for the Rust
owner contract to retain, bind, and seal.
"""

import json
import sys


EXPECTED = {
    "outcome",
    "response_created",
    "non_admission_proven",
    "retry_after",
    "observed_at",
}
OUTCOMES = {
    "RATE_LIMITED",
    "PROVIDER_UNAVAILABLE",
    "AUTHENTICATION_REFUSED",
    "TRANSPORT_ERROR",
    "PROTOCOL_ERROR",
}


def main() -> int:
    value = json.load(sys.stdin, object_pairs_hook=_closed_object)
    if not isinstance(value, dict) or set(value) != EXPECTED:
        raise ValueError("closed qualification evidence fields do not match")
    if value["outcome"] not in OUTCOMES:
        raise ValueError("unknown qualification outcome")
    if not isinstance(value["response_created"], bool):
        raise ValueError("response_created must be boolean")
    if not isinstance(value["non_admission_proven"], bool):
        raise ValueError("non_admission_proven must be boolean")
    if value["retry_after"] is not None and not isinstance(value["retry_after"], str):
        raise ValueError("retry_after must be null or string")
    if not isinstance(value["observed_at"], str):
        raise ValueError("observed_at must be string")
    sys.stdout.write(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    )
    return 0


def _closed_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


if __name__ == "__main__":
    raise SystemExit(main())

"""Executable closure and authority-boundary checks for worker start V3."""

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

ROOT = Path(__file__).resolve().parents[1]
D = "sha256:" + "0" * 64


def value():
    return {
        "schema": "nightshift.worker-start-request/v3",
        "request_digest": D,
        "predecessor_schema": "nightshift.worker-start-request/v2",
        "predecessor_request_digest": D,
        "predecessor_sha256": D,
        "predecessor_encoding": "hex",
        "predecessor_bytes_hex": "7b7d",
        "packet_digest": D,
        "profile_digest": D,
        "run_id": "run-holding",
        "work_item_id": "WORK-A",
        "attempt_id": "attempt-holding-1",
        "work_attempt_id": "attempt-holding-1",
        "dispatch_occurrence_id": "dispatch-holding-1",
        "adapter_id": "switchyard-codex",
        "adapter_version": "2.0.0",
        "adapter_protocol": "switchyard.codex-app-server/v2",
        "worker_brief_digest": D,
        "workspace_identity": "workspace-holding",
        "provider_model_class": "large",
        "timeout_seconds": 600,
        "maximum_output_bytes": 1048576,
        "recursive_worker_swarms_forbidden": True,
        "approval_policy": "SURFACE_ONLY_NO_RESPONSE",
        "expected_receipt_schema": "nightshift.worker-terminal-receipt/v1",
        "provider_id": "openai",
        "model_id": "gpt-5.6-sol",
        "model_class": "large",
        "selected_model_ordinal": 0,
        "provider_admission_adapter_protocol": "switchyard.codex-app-server/v2",
        "provider_admission_binding_schema": "switchyard.codex-provider-admission-binding/v1",
        "provider_admission_evidence_schema": "switchyard.codex-provider-admission-evidence/v1",
        "provider_admission_snapshot_schema": "switchyard.codex-provider-admission-snapshot/v1",
        "codex_owner_head": "c36a8137638decf8b04a49611354a90f32c5a945",
        "switchyard_owner_head": "2ba25db66d8b29dd215bd87e05f4ea794024b3b7",
        "switchyard_schema_sha256": "sha256:131f1f6e0cf8cb0aea26ed225c584440c81ffedd443c68ace23adecbe493cf93",
        "switchyard_deterministic_fixture_sha256": "sha256:cafa673ac58f60029fd6c1de229b4f57d9f42ba918b7ecb2a3bfb20cb2b41a31",
        "provider_execution_id": None,
        "internal_provider_retry_count": 0,
        "semantic_retry": False,
        "approval_response_authorized": False,
        "authority_effect": "LOCAL_AGENT_COMPUTE_SCHEDULING_ONLY",
    }


class WorkerStartV3SchemaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(
            (ROOT / "schemas/nightshift.worker-start-request.v3.schema.json").read_bytes()
        )
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(cls.schema)

    def test_closed_positive_and_v2_predecessor_remains_explicit(self):
        self.validator.validate(value())
        self.assertFalse(self.schema["additionalProperties"])
        self.assertEqual(
            self.schema["properties"]["predecessor_schema"]["const"],
            "nightshift.worker-start-request/v2",
        )
        self.assertEqual(
            self.schema["properties"]["provider_admission_adapter_protocol"]["enum"],
            [
                "switchyard.codex-app-server/v2",
                "nightshift.holding-deterministic-provider-admission-evidence/v1",
                "nightshift.holding-deterministic-provider-admission-evidence/v2",
            ],
        )
        self.assertEqual(
            self.schema["properties"]["provider_admission_binding_schema"]["enum"],
            [
                "switchyard.codex-provider-admission-binding/v1",
                "nightshift.holding-deterministic-provider-admission-evidence/v1",
                "nightshift.holding-deterministic-provider-admission-evidence/v2",
            ],
        )
        self.assertEqual(
            self.schema["properties"]["provider_admission_evidence_schema"]["enum"],
            [
                "switchyard.codex-provider-admission-evidence/v1",
                "nightshift.holding-deterministic-provider-admission-evidence/v1",
                "nightshift.holding-deterministic-provider-admission-evidence/v2",
            ],
        )
        self.assertEqual(
            self.schema["properties"]["provider_admission_snapshot_schema"]["enum"],
            [
                "switchyard.codex-provider-admission-snapshot/v1",
                "nightshift.holding-deterministic-provider-admission-evidence/v1",
                "nightshift.holding-deterministic-provider-admission-evidence/v2",
            ],
        )
        v2_bundle = json.loads(
            (ROOT / "schemas/nightshift.worker-adapter.v2.schema.json").read_bytes()
        )
        self.assertEqual(
            v2_bundle["$defs"]["capabilities"]["properties"][
                "expected_start_request_schema"
            ]["const"],
            "nightshift.worker-start-request/v2",
        )

    def test_owner_pins_and_no_authority_constants_are_closed(self):
        for field, replacement in (
            ("codex_owner_head", "0" * 40),
            ("switchyard_owner_head", "0" * 40),
            ("provider_execution_id", "execution-too-early"),
            ("internal_provider_retry_count", 1),
            ("semantic_retry", True),
            ("approval_response_authorized", True),
            ("recursive_worker_swarms_forbidden", False),
        ):
            changed = copy.deepcopy(value())
            changed[field] = replacement
            with self.assertRaises(ValidationError):
                self.validator.validate(changed)

    def test_bounded_context_tuple_is_exact_and_hybrids_refuse(self):
        candidate = copy.deepcopy(value())
        candidate["codex_owner_head"] = "97b0acd5ce2ccb3c87a763606696c35a450947f6"
        candidate["switchyard_owner_head"] = (
            "1407186638bdd6f90cccf887af87d85a0e114cce"
        )
        candidate["switchyard_schema_sha256"] = (
            "sha256:0e9c851cc9fad9538408ab44d84737d5f4d4d7ef39f2fd5db20c6f88fc7fbb9e"
        )
        self.validator.validate(candidate)

        for field, replacement in (
            ("codex_owner_head", value()["codex_owner_head"]),
            ("switchyard_schema_sha256", value()["switchyard_schema_sha256"]),
        ):
            hybrid = copy.deepcopy(candidate)
            hybrid[field] = replacement
            with self.assertRaises(ValidationError):
                self.validator.validate(hybrid)

    def test_lowercase_exact_predecessor_and_bounds(self):
        for field, replacement in (
            ("predecessor_bytes_hex", "7B7D"),
            ("predecessor_sha256", "sha256:" + "A" * 64),
            ("selected_model_ordinal", 16),
            ("timeout_seconds", 0),
            ("maximum_output_bytes", 16777217),
        ):
            changed = copy.deepcopy(value())
            changed[field] = replacement
            with self.assertRaises(ValidationError):
                self.validator.validate(changed)

    def test_unknown_field_refused(self):
        changed = value()
        changed["approve"] = True
        with self.assertRaises(ValidationError):
            self.validator.validate(changed)


    def test_qualification_branch_is_closed_and_mixed_branch_refuses(self):
        fake = copy.deepcopy(value())
        fake["adapter_id"] = "nightshift:holding-pattern-deterministic-fake-adapter"
        fake["adapter_version"] = "v1"
        protocol = "nightshift.holding-deterministic-provider-admission-evidence/v1"
        fake["adapter_protocol"] = protocol
        fake["provider_admission_adapter_protocol"] = protocol
        fake["provider_admission_binding_schema"] = protocol
        fake["provider_admission_evidence_schema"] = protocol
        fake["provider_admission_snapshot_schema"] = protocol
        self.validator.validate(fake)

        for field in (
            "adapter_id",
            "adapter_version",
            "adapter_protocol",
            "provider_admission_adapter_protocol",
            "provider_admission_binding_schema",
            "provider_admission_evidence_schema",
            "provider_admission_snapshot_schema",
        ):
            changed = copy.deepcopy(fake)
            changed[field] = value()[field]
            with self.assertRaises(ValidationError):
                self.validator.validate(changed)

    def test_reserved_fake_id_cannot_migrate_to_switchyard_and_v2_is_closed(self):
        reserved_switchyard = copy.deepcopy(value())
        reserved_switchyard["adapter_id"] = (
            "nightshift:holding-pattern-deterministic-fake-adapter"
        )
        reserved_switchyard["adapter_version"] = "v1"
        with self.assertRaises(ValidationError):
            self.validator.validate(reserved_switchyard)

        fake_v2 = copy.deepcopy(value())
        fake_v2["adapter_id"] = (
            "nightshift:holding-pattern-deterministic-fake-adapter"
        )
        fake_v2["adapter_version"] = "v2"
        protocol = "nightshift.holding-deterministic-provider-admission-evidence/v2"
        for field in (
            "adapter_protocol",
            "provider_admission_adapter_protocol",
            "provider_admission_binding_schema",
            "provider_admission_evidence_schema",
            "provider_admission_snapshot_schema",
        ):
            fake_v2[field] = protocol
        self.validator.validate(fake_v2)
        for field in (
            "adapter_version",
            "adapter_protocol",
            "provider_admission_adapter_protocol",
            "provider_admission_binding_schema",
            "provider_admission_evidence_schema",
            "provider_admission_snapshot_schema",
        ):
            changed = copy.deepcopy(fake_v2)
            changed[field] = value()[field]
            with self.assertRaises(ValidationError):
                self.validator.validate(changed)


if __name__ == "__main__":
    unittest.main()

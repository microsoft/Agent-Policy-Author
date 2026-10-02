# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from incident_agent.models import AgentContext
from incident_agent.orchestrator import IncidentResponseAgent
from incident_agent.state import StateStore
from incident_agent.tools import configure_runtime, shift_traffic


class IncidentPipelineTests(unittest.TestCase):
    def test_checkout_pipeline_resolves_incident_and_emits_trace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            summary = IncidentResponseAgent(output, "checkout-latency").run()

            self.assertEqual(summary["incident"]["status"], "resolved")
            self.assertGreaterEqual(summary["tool_calls"], 14)
            records = [
                json.loads(line)
                for line in (output / "agent-hooks.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(len(records), summary["tool_calls"] * 2)
            self.assertTrue(
                any(
                    record.get("tool_call", {}).get("name") == "shift_traffic"
                    for record in records
                )
            )

    def test_security_pipeline_quarantines_workload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            summary = IncidentResponseAgent(
                Path(directory),
                "credential-abuse",
            ).run()

            self.assertEqual(summary["quarantine"]["status"], "quarantined")
            self.assertEqual(summary["incident"]["status"], "investigating")

    def test_consequential_tool_rejects_invalid_approval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "state.json")
            store.data["incidents"]["INC-1001"] = {
                "incident_id": "INC-1001",
                "status": "investigating",
                "timeline": [],
            }
            context = AgentContext(
                tenant_id="tenant-test",
                environment="test",
                region="westus2",
                actor_id="test-agent",
                actor_role="tester",
                session_id="test-session",
                change_window="test",
            )
            configure_runtime(store, context)

            with self.assertRaises(PermissionError):
                shift_traffic(
                    incident_id="INC-1001",
                    service="checkout-api",
                    from_region="westus2",
                    to_region="eastus2",
                    percentage=10,
                    approval_token="INVALID",
                    expected_version=store.data["version"],
                    idempotency_key="invalid-approval",
                )

    def test_consequential_tool_rejects_expired_approval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "state.json")
            store.data["incidents"]["INC-1001"] = {
                "incident_id": "INC-1001",
                "status": "investigating",
                "timeline": [],
            }
            store.data["approvals"]["APR-CHANGE-001"]["expires_at"] = (
                "2000-01-01T00:00:00Z"
            )
            context = AgentContext(
                tenant_id="tenant-test",
                environment="test",
                region="westus2",
                actor_id="test-agent",
                actor_role="tester",
                session_id="test-session",
                change_window="test",
            )
            configure_runtime(store, context)

            with self.assertRaises(PermissionError):
                shift_traffic(
                    incident_id="INC-1001",
                    service="checkout-api",
                    from_region="westus2",
                    to_region="eastus2",
                    percentage=10,
                    approval_token="APR-CHANGE-001",
                    expected_version=store.data["version"],
                    idempotency_key="expired-approval",
                )


if __name__ == "__main__":
    unittest.main()

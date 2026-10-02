# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from incident_agent.models import AgentContext
from incident_agent.state import StateStore
from incident_agent.tools import TOOL_HANDLERS, configure_runtime
from incident_agent.tracing import TraceRecorder


class IncidentResponseAgent:
    def __init__(self, output: Path, scenario: str) -> None:
        self.output = output
        self.scenario = scenario
        self.store = StateStore(output / "state.json")
        self.context = AgentContext(
            tenant_id="tenant-synthetic-001",
            environment="production-simulation",
            region="westus2" if scenario == "checkout-latency" else "eastus2",
            actor_id="incident-agent@example.test",
            actor_role="automated-incident-commander",
            session_id=f"session-{scenario}",
            change_window="emergency",
        )
        configure_runtime(self.store, self.context)
        self.trace = TraceRecorder(
            output / "agent-hooks.jsonl",
            self.context.session_id,
        )
        self.reasoning: list[dict[str, Any]] = []

    def _record_reasoning(
        self,
        phase: str,
        observation: str,
        decision: str,
    ) -> None:
        self.reasoning.append(
            {"phase": phase, "observation": observation, "decision": decision}
        )

    def _call(self, name: str, **arguments: Any) -> Any:
        return self.trace.invoke(name, arguments, TOOL_HANDLERS[name])

    @property
    def version(self) -> int:
        return int(self.store.data["version"])

    def run(self) -> dict[str, Any]:
        if self.scenario == "credential-abuse":
            summary = self._run_credential_abuse()
        else:
            summary = self._run_checkout_latency()
        summary["reasoning"] = self.reasoning
        (self.output / "summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return summary

    def _run_checkout_latency(self) -> dict[str, Any]:
        incident_id = "INC-1001"
        approval = "APR-CHANGE-001"
        alerts = self._call(
            "search_alerts",
            scenario=self.scenario,
            severity="high",
            region="westus2",
        )
        self._record_reasoning(
            "detect",
            f"{len(alerts)} correlated alerts affect checkout in westus2",
            "investigate checkout-api and payment-router before changing traffic",
        )
        checkout = self._call(
            "get_service_health",
            service="checkout-api",
            region="westus2",
        )
        dependencies = self._call("get_dependency_map", service="checkout-api")
        payment = self._call(
            "get_service_health",
            service="payment-router",
            region="westus2",
        )
        deployments = self._call(
            "get_recent_deployments",
            service="payment-router",
            region="westus2",
            limit=5,
        )
        runbook = self._call("get_runbook", scenario=self.scenario)
        self._record_reasoning(
            "diagnose",
            (
                f"checkout p99={checkout['p99_ms']}ms; payment error rate="
                f"{payment['error_rate']}; recent deployments={len(deployments)}"
            ),
            "declare critical incident and follow regional latency runbook",
        )
        self._call(
            "create_incident",
            incident_id=incident_id,
            title="Regional checkout latency and payment timeouts",
            severity="critical",
            service="checkout-api",
            region="westus2",
            expected_version=self.version,
            idempotency_key="create-inc-1001",
        )
        self._call(
            "open_incident_bridge",
            incident_id=incident_id,
            channel="commerce-sev0",
            expected_version=self.version,
            idempotency_key="bridge-inc-1001",
        )
        self._call(
            "page_on_call",
            incident_id=incident_id,
            team="commerce-platform",
            urgency="immediate",
            approval_token=approval,
            expected_version=self.version,
            idempotency_key="page-inc-1001",
        )
        change = self._call(
            "create_change_request",
            incident_id=incident_id,
            action="shift_traffic_then_rollback",
            target="checkout-api/payment-router westus2",
            risk="high",
            expected_version=self.version,
            idempotency_key="change-inc-1001",
        )
        self._record_reasoning(
            "plan",
            (
                f"runbook has {len(runbook['steps'])} steps; "
                f"change {change['change_id']} approved"
            ),
            "shift traffic first, then rollback the correlated deployment",
        )
        self._call(
            "shift_traffic",
            incident_id=incident_id,
            service="checkout-api",
            from_region="westus2",
            to_region="eastus2",
            percentage=60,
            approval_token=approval,
            expected_version=self.version,
            idempotency_key="shift-inc-1001",
        )
        deployment = deployments[0]
        self._call(
            "rollback_deployment",
            incident_id=incident_id,
            deployment_id=deployment["deployment_id"],
            service=deployment["service"],
            region=deployment["region"],
            target_version=deployment["previous_version"],
            approval_token=approval,
            expected_version=self.version,
            idempotency_key="rollback-inc-1001",
        )
        recovery = self._call(
            "verify_recovery",
            incident_id=incident_id,
            service="payment-router",
            region="westus2",
            max_error_rate=0.03,
            max_p99_ms=600,
        )
        if not recovery["passed"]:
            raise RuntimeError("recovery verification failed; incident remains open")
        self._record_reasoning(
            "verify",
            "payment-router is within explicit error-rate and latency thresholds",
            "publish recovery status and resolve the incident",
        )
        self._call(
            "update_incident",
            incident_id=incident_id,
            status="monitoring",
            summary="Traffic shifted and payment-router rolled back; recovery passed",
            expected_version=self.version,
            idempotency_key="monitor-inc-1001",
        )
        self._call(
            "publish_status_update",
            incident_id=incident_id,
            audience="customers",
            message="Checkout performance has recovered; monitoring continues.",
            approval_token=approval,
            expected_version=self.version,
            idempotency_key="status-inc-1001",
        )
        resolved = self._call(
            "resolve_incident",
            incident_id=incident_id,
            resolution_code="deployment-regression",
            summary="Recovered through regional traffic shift and deployment rollback",
            approval_token=approval,
            expected_version=self.version,
            idempotency_key="resolve-inc-1001",
        )
        return {
            "scenario": self.scenario,
            "incident": resolved,
            "alerts_considered": len(alerts),
            "dependencies_considered": dependencies["dependencies"],
            "tool_calls": self.trace.sequence // 2,
        }

    def _run_credential_abuse(self) -> dict[str, Any]:
        incident_id = "INC-1001"
        approval = "APR-CHANGE-001"
        alerts = self._call(
            "search_alerts",
            scenario=self.scenario,
            severity="critical",
            region="eastus2",
        )
        health = self._call(
            "get_service_health",
            service="admin-console",
            region="eastus2",
        )
        dependencies = self._call("get_dependency_map", service="admin-console")
        runbook = self._call("get_runbook", scenario=self.scenario)
        self._record_reasoning(
            "detect",
            f"{len(alerts)} privileged-access anomaly; service={health['status']}",
            "declare security incident and quarantine the affected workload",
        )
        self._call(
            "create_incident",
            incident_id=incident_id,
            title="Privileged token anomaly in admin console",
            severity="critical",
            service="admin-console",
            region="eastus2",
            expected_version=self.version,
            idempotency_key="create-security-inc-1001",
        )
        self._call(
            "open_incident_bridge",
            incident_id=incident_id,
            channel="security-sev0",
            expected_version=self.version,
            idempotency_key="bridge-security-inc-1001",
        )
        self._call(
            "page_on_call",
            incident_id=incident_id,
            team="security-operations",
            urgency="immediate",
            approval_token=approval,
            expected_version=self.version,
            idempotency_key="page-security-inc-1001",
        )
        self._call(
            "create_change_request",
            incident_id=incident_id,
            action="quarantine_workload",
            target="admin-console/pod-17",
            risk="critical",
            expected_version=self.version,
            idempotency_key="change-security-inc-1001",
        )
        quarantine = self._call(
            "quarantine_workload",
            incident_id=incident_id,
            workload_id="admin-console-pod-17",
            region="eastus2",
            reason="privileged token anomaly",
            approval_token=approval,
            expected_version=self.version,
            idempotency_key="quarantine-security-inc-1001",
        )
        self._record_reasoning(
            "contain",
            (
                f"workload={quarantine['workload_id']} quarantined; "
                f"dependencies={dependencies['dependencies']}"
            ),
            f"follow remaining {len(runbook['steps']) - 1} runbook steps manually",
        )
        return {
            "scenario": self.scenario,
            "incident": self.store.get_incident(incident_id),
            "quarantine": quarantine,
            "alerts_considered": len(alerts),
            "tool_calls": self.trace.sequence // 2,
        }

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

INITIAL_STATE: dict[str, Any] = {
    "version": 1,
    "next_incident": 1002,
    "alerts": [
        {
            "alert_id": "ALT-9001",
            "scenario": "checkout-latency",
            "service": "checkout-api",
            "region": "westus2",
            "severity": "critical",
            "signal": "p99_latency_ms",
            "value": 4820,
            "threshold": 900,
            "status": "firing",
        },
        {
            "alert_id": "ALT-9002",
            "scenario": "checkout-latency",
            "service": "payment-router",
            "region": "westus2",
            "severity": "high",
            "signal": "dependency_timeout_rate",
            "value": 0.37,
            "threshold": 0.05,
            "status": "firing",
        },
        {
            "alert_id": "ALT-9101",
            "scenario": "credential-abuse",
            "service": "admin-console",
            "region": "eastus2",
            "severity": "critical",
            "signal": "privileged_token_anomaly",
            "value": 17,
            "threshold": 1,
            "status": "firing",
        },
    ],
    "services": {
        "checkout-api": {
            "westus2": {"status": "degraded", "error_rate": 0.31, "p99_ms": 4820},
            "eastus2": {"status": "healthy", "error_rate": 0.004, "p99_ms": 240},
        },
        "payment-router": {
            "westus2": {"status": "degraded", "error_rate": 0.37, "p99_ms": 3910},
            "eastus2": {"status": "healthy", "error_rate": 0.006, "p99_ms": 210},
        },
        "admin-console": {
            "eastus2": {"status": "at_risk", "error_rate": 0.02, "p99_ms": 180}
        },
    },
    "dependencies": {
        "checkout-api": ["payment-router", "inventory-api", "order-store"],
        "payment-router": ["processor-gateway", "fraud-score"],
        "admin-console": ["identity-broker", "audit-store"],
    },
    "deployments": [
        {
            "deployment_id": "DEP-7007",
            "service": "payment-router",
            "region": "westus2",
            "version": "2026.09.29.3",
            "previous_version": "2026.09.24.8",
            "completed_at": "2026-09-29T21:31:00Z",
            "risk": "elevated",
        }
    ],
    "runbooks": {
        "checkout-latency": {
            "title": "Regional checkout latency",
            "steps": [
                "compare healthy-region telemetry",
                "shift checkout traffic to healthy region",
                "rollback payment-router if errors persist",
                "verify checkout synthetic transactions",
            ],
        },
        "credential-abuse": {
            "title": "Privileged credential abuse",
            "steps": [
                "quarantine affected workload",
                "revoke active synthetic sessions",
                "preserve audit evidence",
                "verify privileged access returns to baseline",
            ],
        },
    },
    "approvals": {
        "APR-CHANGE-001": {
            "incident_id": "INC-1001",
            "allowed_actions": [
                "page_on_call",
                "shift_traffic",
                "rollback_deployment",
                "quarantine_workload",
                "publish_status_update",
                "resolve_incident",
            ],
            "approved_by": "incident-commander@example.test",
            "expires_at": "2099-01-01T00:00:00Z",
        }
    },
    "incidents": {},
    "bridges": {},
    "change_requests": {},
    "traffic": {"checkout-api": {"westus2": 70, "eastus2": 30}},
    "quarantined_workloads": [],
    "status_updates": [],
    "notifications": [],
    "idempotency": {},
    "audit_log": [],
}


class StateStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._state = deepcopy(INITIAL_STATE)
        self._write()

    @property
    def data(self) -> dict[str, Any]:
        return self._state

    def _write(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(self._state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        incident = self._state["incidents"].get(incident_id)
        if not isinstance(incident, dict):
            raise ValueError(f"unknown incident: {incident_id}")
        return incident

    def check_version(self, expected_version: int) -> None:
        actual = int(self._state["version"])
        if actual != expected_version:
            raise ValueError(
                f"state version mismatch: expected {expected_version}, actual {actual}"
            )

    def check_approval(
        self,
        approval_token: str,
        incident_id: str,
        action: str,
    ) -> dict[str, Any]:
        approval = self._state["approvals"].get(approval_token)
        if not isinstance(approval, dict):
            raise PermissionError("approval token is invalid")
        if approval.get("incident_id") != incident_id:
            raise PermissionError("approval token is bound to another incident")
        if action not in approval.get("allowed_actions", []):
            raise PermissionError(f"approval does not authorize {action}")
        expires_at = datetime.fromisoformat(
            str(approval["expires_at"]).replace("Z", "+00:00")
        )
        if expires_at <= datetime.now(UTC):
            raise PermissionError("approval token has expired")
        return approval

    def execute_idempotent(
        self,
        idempotency_key: str,
        operation: Callable[[], dict[str, Any]],
    ) -> dict[str, Any]:
        prior = self._state["idempotency"].get(idempotency_key)
        if isinstance(prior, dict):
            return deepcopy(prior)
        result = operation()
        self._state["idempotency"][idempotency_key] = deepcopy(result)
        self._write()
        return result

    def mutate(
        self,
        action: str,
        actor_id: str,
        operation: Callable[[dict[str, Any]], dict[str, Any]],
    ) -> dict[str, Any]:
        result = operation(self._state)
        self._state["version"] = int(self._state["version"]) + 1
        self._state["audit_log"].append(
            {
                "sequence": len(self._state["audit_log"]) + 1,
                "action": action,
                "actor_id": actor_id,
                "result_digest": hashlib.sha256(
                    json.dumps(result, sort_keys=True).encode("utf-8")
                ).hexdigest(),
            }
        )
        self._write()
        return result

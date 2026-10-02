# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

from contextvars import ContextVar
from typing import Any

from incident_agent.models import AgentContext, ToolSpec, schema
from incident_agent.state import StateStore

_STORE: ContextVar[StateStore] = ContextVar("store")
_CONTEXT: ContextVar[AgentContext] = ContextVar("context")


def configure_runtime(store: StateStore, context: AgentContext) -> None:
    _STORE.set(store)
    _CONTEXT.set(context)


def _runtime() -> tuple[StateStore, AgentContext]:
    return _STORE.get(), _CONTEXT.get()


def search_alerts(
    scenario: str,
    severity: str,
    region: str,
) -> list[dict[str, Any]]:
    store, _ = _runtime()
    return [
        item
        for item in store.data["alerts"]
        if item["scenario"] == scenario
        and item["severity"] in {severity, "critical"}
        and item["region"] == region
    ]


def get_service_health(service: str, region: str) -> dict[str, Any]:
    store, _ = _runtime()
    health = store.data["services"].get(service, {}).get(region)
    if not isinstance(health, dict):
        raise ValueError(f"no health snapshot for {service} in {region}")
    return {"service": service, "region": region, **health}


def get_dependency_map(service: str) -> dict[str, Any]:
    store, _ = _runtime()
    return {
        "service": service,
        "dependencies": store.data["dependencies"].get(service, []),
    }


def get_recent_deployments(
    service: str,
    region: str,
    limit: int,
) -> list[dict[str, Any]]:
    store, _ = _runtime()
    matches = [
        item
        for item in store.data["deployments"]
        if item["service"] == service and item["region"] == region
    ]
    return matches[:limit]


def get_runbook(scenario: str) -> dict[str, Any]:
    store, _ = _runtime()
    runbook = store.data["runbooks"].get(scenario)
    if not isinstance(runbook, dict):
        raise ValueError(f"no runbook for scenario: {scenario}")
    return {"scenario": scenario, **runbook}


def create_incident(
    incident_id: str,
    title: str,
    severity: str,
    service: str,
    region: str,
    expected_version: int,
    idempotency_key: str,
) -> dict[str, Any]:
    store, context = _runtime()
    store.check_version(expected_version)

    def operation() -> dict[str, Any]:
        def apply(state: dict[str, Any]) -> dict[str, Any]:
            if incident_id in state["incidents"]:
                raise ValueError(f"incident already exists: {incident_id}")
            incident = {
                "incident_id": incident_id,
                "title": title,
                "severity": severity,
                "service": service,
                "region": region,
                "status": "investigating",
                "owner": context.actor_id,
                "timeline": ["incident created"],
            }
            state["incidents"][incident_id] = incident
            return incident

        return store.mutate("create_incident", context.actor_id, apply)

    return store.execute_idempotent(idempotency_key, operation)


def update_incident(
    incident_id: str,
    status: str,
    summary: str,
    expected_version: int,
    idempotency_key: str,
) -> dict[str, Any]:
    store, context = _runtime()
    store.get_incident(incident_id)
    store.check_version(expected_version)

    def operation() -> dict[str, Any]:
        def apply(state: dict[str, Any]) -> dict[str, Any]:
            incident = state["incidents"][incident_id]
            incident["status"] = status
            incident["timeline"].append(summary)
            return incident

        return store.mutate("update_incident", context.actor_id, apply)

    return store.execute_idempotent(idempotency_key, operation)


def page_on_call(
    incident_id: str,
    team: str,
    urgency: str,
    approval_token: str,
    expected_version: int,
    idempotency_key: str,
) -> dict[str, Any]:
    store, context = _runtime()
    store.get_incident(incident_id)
    store.check_approval(approval_token, incident_id, "page_on_call")
    store.check_version(expected_version)

    def operation() -> dict[str, Any]:
        def apply(state: dict[str, Any]) -> dict[str, Any]:
            notification = {
                "incident_id": incident_id,
                "team": team,
                "urgency": urgency,
                "status": "acknowledged",
            }
            state["notifications"].append(notification)
            return notification

        return store.mutate("page_on_call", context.actor_id, apply)

    return store.execute_idempotent(idempotency_key, operation)


def open_incident_bridge(
    incident_id: str,
    channel: str,
    expected_version: int,
    idempotency_key: str,
) -> dict[str, Any]:
    store, context = _runtime()
    store.get_incident(incident_id)
    store.check_version(expected_version)

    def operation() -> dict[str, Any]:
        def apply(state: dict[str, Any]) -> dict[str, Any]:
            bridge = {
                "incident_id": incident_id,
                "channel": channel,
                "bridge_id": f"BRG-{incident_id.removeprefix('INC-')}",
                "status": "open",
            }
            state["bridges"][incident_id] = bridge
            return bridge

        return store.mutate("open_incident_bridge", context.actor_id, apply)

    return store.execute_idempotent(idempotency_key, operation)


def create_change_request(
    incident_id: str,
    action: str,
    target: str,
    risk: str,
    expected_version: int,
    idempotency_key: str,
) -> dict[str, Any]:
    store, context = _runtime()
    store.get_incident(incident_id)
    store.check_version(expected_version)

    def operation() -> dict[str, Any]:
        def apply(state: dict[str, Any]) -> dict[str, Any]:
            change_id = f"CHG-{len(state['change_requests']) + 5001}"
            change = {
                "change_id": change_id,
                "incident_id": incident_id,
                "action": action,
                "target": target,
                "risk": risk,
                "status": "approved",
                "approval_token": "APR-CHANGE-001",
            }
            state["change_requests"][change_id] = change
            return change

        return store.mutate("create_change_request", context.actor_id, apply)

    return store.execute_idempotent(idempotency_key, operation)


def shift_traffic(
    incident_id: str,
    service: str,
    from_region: str,
    to_region: str,
    percentage: int,
    approval_token: str,
    expected_version: int,
    idempotency_key: str,
) -> dict[str, Any]:
    store, context = _runtime()
    store.get_incident(incident_id)
    store.check_approval(approval_token, incident_id, "shift_traffic")
    store.check_version(expected_version)
    if percentage < 1 or percentage > 100:
        raise ValueError("percentage must be between 1 and 100")

    def operation() -> dict[str, Any]:
        def apply(state: dict[str, Any]) -> dict[str, Any]:
            routing = state["traffic"].setdefault(service, {})
            routing[from_region] = max(0, int(routing.get(from_region, 0)) - percentage)
            routing[to_region] = min(100, int(routing.get(to_region, 0)) + percentage)
            state["services"][service][from_region]["status"] = "mitigated"
            return {"service": service, "routing": routing}

        return store.mutate("shift_traffic", context.actor_id, apply)

    return store.execute_idempotent(idempotency_key, operation)


def rollback_deployment(
    incident_id: str,
    deployment_id: str,
    service: str,
    region: str,
    target_version: str,
    approval_token: str,
    expected_version: int,
    idempotency_key: str,
) -> dict[str, Any]:
    store, context = _runtime()
    store.get_incident(incident_id)
    store.check_approval(approval_token, incident_id, "rollback_deployment")
    store.check_version(expected_version)

    def operation() -> dict[str, Any]:
        def apply(state: dict[str, Any]) -> dict[str, Any]:
            result = {
                "deployment_id": deployment_id,
                "service": service,
                "region": region,
                "target_version": target_version,
                "status": "rolled_back",
            }
            state["services"][service][region].update(
                {"status": "recovering", "error_rate": 0.02, "p99_ms": 480}
            )
            return result

        return store.mutate("rollback_deployment", context.actor_id, apply)

    return store.execute_idempotent(idempotency_key, operation)


def quarantine_workload(
    incident_id: str,
    workload_id: str,
    region: str,
    reason: str,
    approval_token: str,
    expected_version: int,
    idempotency_key: str,
) -> dict[str, Any]:
    store, context = _runtime()
    store.get_incident(incident_id)
    store.check_approval(approval_token, incident_id, "quarantine_workload")
    store.check_version(expected_version)

    def operation() -> dict[str, Any]:
        def apply(state: dict[str, Any]) -> dict[str, Any]:
            record = {
                "incident_id": incident_id,
                "workload_id": workload_id,
                "region": region,
                "reason": reason,
                "status": "quarantined",
            }
            state["quarantined_workloads"].append(record)
            return record

        return store.mutate("quarantine_workload", context.actor_id, apply)

    return store.execute_idempotent(idempotency_key, operation)


def verify_recovery(
    incident_id: str,
    service: str,
    region: str,
    max_error_rate: float,
    max_p99_ms: int,
) -> dict[str, Any]:
    store, _ = _runtime()
    store.get_incident(incident_id)
    health = store.data["services"][service][region]
    passed = (
        float(health["error_rate"]) <= max_error_rate
        and int(health["p99_ms"]) <= max_p99_ms
    )
    return {
        "incident_id": incident_id,
        "service": service,
        "region": region,
        "passed": passed,
        "observed": health,
        "thresholds": {
            "max_error_rate": max_error_rate,
            "max_p99_ms": max_p99_ms,
        },
    }


def publish_status_update(
    incident_id: str,
    audience: str,
    message: str,
    approval_token: str,
    expected_version: int,
    idempotency_key: str,
) -> dict[str, Any]:
    store, context = _runtime()
    store.get_incident(incident_id)
    store.check_approval(approval_token, incident_id, "publish_status_update")
    store.check_version(expected_version)

    def operation() -> dict[str, Any]:
        def apply(state: dict[str, Any]) -> dict[str, Any]:
            update = {
                "incident_id": incident_id,
                "audience": audience,
                "message": message,
                "status": "published",
            }
            state["status_updates"].append(update)
            return update

        return store.mutate("publish_status_update", context.actor_id, apply)

    return store.execute_idempotent(idempotency_key, operation)


def resolve_incident(
    incident_id: str,
    resolution_code: str,
    summary: str,
    approval_token: str,
    expected_version: int,
    idempotency_key: str,
) -> dict[str, Any]:
    store, context = _runtime()
    store.get_incident(incident_id)
    store.check_approval(approval_token, incident_id, "resolve_incident")
    store.check_version(expected_version)

    def operation() -> dict[str, Any]:
        def apply(state: dict[str, Any]) -> dict[str, Any]:
            incident = state["incidents"][incident_id]
            incident["status"] = "resolved"
            incident["resolution_code"] = resolution_code
            incident["timeline"].append(summary)
            return incident

        return store.mutate("resolve_incident", context.actor_id, apply)

    return store.execute_idempotent(idempotency_key, operation)


TOOLS = [
    ToolSpec(
        "search_alerts",
        "Search active operational alerts",
        "observability",
        False,
        False,
        search_alerts,
        schema(
            ["scenario", "severity", "region"],
            scenario="string",
            severity="string",
            region="string",
        ),
    ),
    ToolSpec(
        "get_service_health",
        "Read a service health snapshot",
        "observability",
        False,
        False,
        get_service_health,
        schema(["service", "region"], service="string", region="string"),
    ),
    ToolSpec(
        "get_dependency_map",
        "Read service dependencies",
        "catalog",
        False,
        False,
        get_dependency_map,
        schema(["service"], service="string"),
    ),
    ToolSpec(
        "get_recent_deployments",
        "List recent service deployments",
        "deployment",
        False,
        False,
        get_recent_deployments,
        schema(
            ["service", "region", "limit"],
            service="string",
            region="string",
            limit="integer",
        ),
    ),
    ToolSpec(
        "get_runbook",
        "Read an incident runbook",
        "knowledge",
        False,
        False,
        get_runbook,
        schema(["scenario"], scenario="string"),
    ),
    ToolSpec(
        "create_incident",
        "Create an incident record",
        "incident-management",
        True,
        False,
        create_incident,
        schema(
            [
                "incident_id",
                "title",
                "severity",
                "service",
                "region",
                "expected_version",
                "idempotency_key",
            ],
            incident_id="string",
            title="string",
            severity="string",
            service="string",
            region="string",
            expected_version="integer",
            idempotency_key="string",
        ),
    ),
    ToolSpec(
        "update_incident",
        "Update incident status and evidence",
        "incident-management",
        True,
        False,
        update_incident,
        schema(
            [
                "incident_id",
                "status",
                "summary",
                "expected_version",
                "idempotency_key",
            ],
            incident_id="string",
            status="string",
            summary="string",
            expected_version="integer",
            idempotency_key="string",
        ),
    ),
    ToolSpec(
        "page_on_call",
        "Page an on-call responder team",
        "communications",
        True,
        True,
        page_on_call,
        schema(
            [
                "incident_id",
                "team",
                "urgency",
                "approval_token",
                "expected_version",
                "idempotency_key",
            ],
            incident_id="string",
            team="string",
            urgency="string",
            approval_token="string",
            expected_version="integer",
            idempotency_key="string",
        ),
    ),
    ToolSpec(
        "open_incident_bridge",
        "Open an incident bridge",
        "communications",
        True,
        False,
        open_incident_bridge,
        schema(
            ["incident_id", "channel", "expected_version", "idempotency_key"],
            incident_id="string",
            channel="string",
            expected_version="integer",
            idempotency_key="string",
        ),
    ),
    ToolSpec(
        "create_change_request",
        "Create an emergency change request",
        "change-management",
        True,
        False,
        create_change_request,
        schema(
            [
                "incident_id",
                "action",
                "target",
                "risk",
                "expected_version",
                "idempotency_key",
            ],
            incident_id="string",
            action="string",
            target="string",
            risk="string",
            expected_version="integer",
            idempotency_key="string",
        ),
    ),
    ToolSpec(
        "shift_traffic",
        "Shift service traffic between regions",
        "traffic-management",
        True,
        True,
        shift_traffic,
        schema(
            [
                "incident_id",
                "service",
                "from_region",
                "to_region",
                "percentage",
                "approval_token",
                "expected_version",
                "idempotency_key",
            ],
            incident_id="string",
            service="string",
            from_region="string",
            to_region="string",
            percentage="integer",
            approval_token="string",
            expected_version="integer",
            idempotency_key="string",
        ),
    ),
    ToolSpec(
        "rollback_deployment",
        "Rollback a deployment",
        "deployment",
        True,
        True,
        rollback_deployment,
        schema(
            [
                "incident_id",
                "deployment_id",
                "service",
                "region",
                "target_version",
                "approval_token",
                "expected_version",
                "idempotency_key",
            ],
            incident_id="string",
            deployment_id="string",
            service="string",
            region="string",
            target_version="string",
            approval_token="string",
            expected_version="integer",
            idempotency_key="string",
        ),
    ),
    ToolSpec(
        "quarantine_workload",
        "Quarantine a workload",
        "security",
        True,
        True,
        quarantine_workload,
        schema(
            [
                "incident_id",
                "workload_id",
                "region",
                "reason",
                "approval_token",
                "expected_version",
                "idempotency_key",
            ],
            incident_id="string",
            workload_id="string",
            region="string",
            reason="string",
            approval_token="string",
            expected_version="integer",
            idempotency_key="string",
        ),
    ),
    ToolSpec(
        "verify_recovery",
        "Verify service recovery thresholds",
        "observability",
        False,
        False,
        verify_recovery,
        schema(
            [
                "incident_id",
                "service",
                "region",
                "max_error_rate",
                "max_p99_ms",
            ],
            incident_id="string",
            service="string",
            region="string",
            max_error_rate="number",
            max_p99_ms="integer",
        ),
    ),
    ToolSpec(
        "publish_status_update",
        "Publish an incident status update",
        "communications",
        True,
        True,
        publish_status_update,
        schema(
            [
                "incident_id",
                "audience",
                "message",
                "approval_token",
                "expected_version",
                "idempotency_key",
            ],
            incident_id="string",
            audience="string",
            message="string",
            approval_token="string",
            expected_version="integer",
            idempotency_key="string",
        ),
    ),
    ToolSpec(
        "resolve_incident",
        "Resolve an incident",
        "incident-management",
        True,
        True,
        resolve_incident,
        schema(
            [
                "incident_id",
                "resolution_code",
                "summary",
                "approval_token",
                "expected_version",
                "idempotency_key",
            ],
            incident_id="string",
            resolution_code="string",
            summary="string",
            approval_token="string",
            expected_version="integer",
            idempotency_key="string",
        ),
    ),
]

TOOL_HANDLERS = {spec.name: spec.handler for spec in TOOLS}

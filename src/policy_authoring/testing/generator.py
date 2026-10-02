# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

from copy import deepcopy
from typing import Any

from policy_authoring.domain.evaluator import resolve_operand
from policy_authoring.domain.models import (
    CanonicalPolicy,
    Condition,
    PolicyTestCase,
    ProjectDefinition,
)


def _set_path(document: dict[str, Any], path: str, value: Any) -> None:
    if not path:
        raise ValueError("cannot set an empty context path")
    current = document
    parts = path.split(".")
    for part in parts[:-1]:
        current = current.setdefault(part, {})
    current[parts[-1]] = value


def _has_path(document: dict[str, Any], path: str) -> bool:
    current: Any = document
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return False
        current = current[part]
    return True


def _valid_value(
    condition: Condition,
    context: dict[str, Any],
    constrained_values: dict[str, Any],
) -> None:
    if condition.operator == "not_equals" and condition.left and condition.right:
        if condition.left.path is not None:
            preferred = constrained_values.get(condition.left.path)
            if preferred is not None:
                _set_path(context, condition.left.path, preferred)
                if condition.right.path is not None:
                    _set_path(context, condition.right.path, preferred)
            else:
                right = resolve_operand(context, condition.right)
                _set_path(context, condition.left.path, right)
    elif condition.operator == "not_in" and condition.left and condition.values:
        path = condition.left.path or ""
        value = constrained_values.get(path, condition.values[0])
        _set_path(context, path, value)
    elif condition.operator == "not" and condition.conditions:
        inner = condition.conditions[0]
        if (
            inner.operator == "exists"
            and inner.left
            and inner.left.path
            and not _has_path(context, inner.left.path)
        ):
            _set_path(context, inner.left.path, "present")


def _invalid_value(condition: Condition, context: dict[str, Any]) -> None:
    if condition.operator == "not_equals" and condition.left and condition.right:
        if condition.left.path is None:
            return
        right = resolve_operand(context, condition.right)
        value = not right if isinstance(right, bool) else "__mutated__"
        _set_path(context, condition.left.path, value)
    elif condition.operator == "not_in" and condition.left:
        _set_path(context, condition.left.path or "", "__unapproved__")
    elif condition.operator == "not" and condition.conditions:
        inner = condition.conditions[0]
        if inner.operator == "exists" and inner.left and inner.left.path:
            parts = inner.left.path.split(".")
            current: Any = context
            for part in parts[:-1]:
                current = current.get(part, {})
            if isinstance(current, dict):
                current.pop(parts[-1], None)


def _schema_value(schema: dict[str, Any], name: str) -> Any:
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return enum[0]
    value_type = schema.get("type")
    if value_type == "integer":
        return 1
    if value_type == "number":
        return 1.0
    if value_type == "boolean":
        return True
    if value_type == "array":
        return []
    if value_type == "object":
        return {}
    return f"example-{name.replace('_', '-')}"


def build_synthetic_context(
    project: ProjectDefinition,
    tool_name: str,
) -> dict[str, Any]:
    tool = next(item for item in project.tools if item.name == tool_name)
    properties = tool.input_schema.get("properties", {})
    required = tool.input_schema.get("required", [])
    arguments = {
        name: _schema_value(
            properties.get(name, {}) if isinstance(properties.get(name), dict) else {},
            name,
        )
        for name in required
    }
    context: dict[str, Any] = {
        "principal": {
            "user_id": "example-user",
            "tenant_id": "example-tenant",
        },
        "action": {
            "tool": tool_name,
            "arguments": arguments,
        },
        "environment": {"name": "test"},
    }
    for attribute in project.context.attributes:
        path = attribute.path
        if path == "workflow.approval.valid":
            value: Any = True
        elif attribute.type == "boolean":
            value = True
        elif attribute.type == "integer":
            value = 1
        elif attribute.type == "number":
            value = 1.0
        elif attribute.type == "array":
            value = []
        elif attribute.type == "object":
            value = {}
        elif path.endswith(".operation_id"):
            value = "example-operation"
        elif path.endswith(".idempotency_key"):
            value = "example-idempotency-key"
        else:
            value = f"example-{path.split('.')[-1].replace('_', '-')}"
        _set_path(context, path, value)
    return context


def generate_tests(
    policy: CanonicalPolicy,
    base_context: dict[str, Any],
) -> list[PolicyTestCase]:
    valid_context = deepcopy(base_context)
    blocking_rules = [
        rule for rule in policy.rules if rule.decision in {"deny", "escalate"}
    ]
    constrained_values = {
        rule.condition.left.path: rule.condition.values[0]
        for rule in blocking_rules
        if rule.condition.operator == "not_in"
        and rule.condition.left is not None
        and rule.condition.left.path is not None
        and rule.condition.values
    }
    for _ in range(2):
        for rule in blocking_rules:
            _valid_value(rule.condition, valid_context, constrained_values)

    has_allow_path = any(rule.decision == "allow" for rule in policy.rules)
    expected_default = "allow" if has_allow_path else policy.default_decision
    cases = [
        PolicyTestCase(
            id="valid-action" if has_allow_path else "default-action",
            description=(
                "All generated constraints are satisfied"
                if has_allow_path
                else "No generated allow path exists; default decision applies"
            ),
            context=valid_context,
            expected_decision=expected_default,
        )
    ]
    for rule in blocking_rules:
        mutated = deepcopy(valid_context)
        _invalid_value(rule.condition, mutated)
        cases.append(
            PolicyTestCase(
                id=f"violate-{rule.id}",
                description=f"Trigger generated rule {rule.id}",
                context=mutated,
                expected_decision=rule.decision,
            )
        )
    return cases

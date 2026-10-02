# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

from typing import Any

from policy_authoring.domain.models import (
    CanonicalPolicy,
    Condition,
    DecisionResult,
    Operand,
)

_MISSING = object()
_PRECEDENCE = {
    "deny": 5,
    "escalate": 4,
    "transform": 3,
    "warn": 2,
    "allow": 1,
}


class ConditionEvaluationError(ValueError):
    """Raised when a condition cannot be evaluated safely."""


def resolve_path(document: dict[str, Any], path: str) -> Any:
    current: Any = document
    for segment in path.split("."):
        if not isinstance(current, dict) or segment not in current:
            return _MISSING
        current = current[segment]
    return current


def resolve_operand(document: dict[str, Any], operand: Operand) -> Any:
    if operand.path is not None:
        return resolve_path(document, operand.path)
    return operand.literal


def evaluate_condition(condition: Condition, context: dict[str, Any]) -> bool:
    operator = condition.operator
    if operator == "all":
        return all(evaluate_condition(item, context) for item in condition.conditions)
    if operator == "any":
        return any(evaluate_condition(item, context) for item in condition.conditions)
    if operator == "not":
        return not evaluate_condition(condition.conditions[0], context)

    if condition.left is None:
        return False
    left = resolve_operand(context, condition.left)
    if operator == "exists":
        return left is not _MISSING
    if left is _MISSING:
        return False
    if operator == "in":
        return left in condition.values
    if operator == "not_in":
        return left not in condition.values

    if condition.right is None:
        return False
    right = resolve_operand(context, condition.right)
    if right is _MISSING:
        return False
    if operator == "equals":
        return bool(left == right)
    if operator == "not_equals":
        return bool(left != right)
    try:
        if operator == "greater_than":
            return bool(left > right)
        if operator == "greater_than_or_equal":
            return bool(left >= right)
        if operator == "less_than":
            return bool(left < right)
        if operator == "less_than_or_equal":
            return bool(left <= right)
    except TypeError as exc:
        raise ConditionEvaluationError(
            f"{operator} cannot compare {type(left).__name__} with "
            f"{type(right).__name__}"
        ) from exc
    raise ValueError(f"unsupported operator: {operator}")


def evaluate_policy(
    policy: CanonicalPolicy,
    context: dict[str, Any],
) -> DecisionResult:
    matches = []
    for rule in policy.rules:
        try:
            matched = evaluate_condition(rule.condition, context)
        except ConditionEvaluationError as exc:
            return DecisionResult(
                decision="deny",
                matched_rule_ids=[],
                reason=f"rule_evaluation_error:{rule.id}:{exc}",
            )
        if matched:
            matches.append(rule)
    if not matches:
        return DecisionResult(
            decision=policy.default_decision,
            matched_rule_ids=[],
            reason="default_decision",
        )
    highest = max(_PRECEDENCE[rule.decision] for rule in matches)
    winners = [rule for rule in matches if _PRECEDENCE[rule.decision] == highest]
    winners.sort(key=lambda rule: rule.id)
    return DecisionResult(
        decision=winners[0].decision,
        matched_rule_ids=[rule.id for rule in winners],
        reason=winners[0].reason,
    )


def complement(condition: Condition) -> Condition:
    inverse = {
        "equals": "not_equals",
        "not_equals": "equals",
        "in": "not_in",
        "not_in": "in",
        "greater_than": "less_than_or_equal",
        "greater_than_or_equal": "less_than",
        "less_than": "greater_than_or_equal",
        "less_than_or_equal": "greater_than",
    }
    if condition.operator in inverse:
        payload = condition.model_dump()
        payload["operator"] = inverse[condition.operator]
        return Condition.model_validate(payload)
    if condition.operator == "exists":
        return Condition(operator="not", conditions=[condition])
    if condition.operator == "not":
        return condition.conditions[0]
    if condition.operator == "all":
        return Condition(
            operator="any",
            conditions=[complement(item) for item in condition.conditions],
        )
    if condition.operator == "any":
        return Condition(
            operator="all",
            conditions=[complement(item) for item in condition.conditions],
        )
    return Condition(operator="not", conditions=[condition])

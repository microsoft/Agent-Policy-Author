# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

from typing import Any, Literal

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from pydantic import BaseModel

from policy_authoring.domain.evaluator import evaluate_policy
from policy_authoring.domain.models import CanonicalPolicy, Decision, ProjectDefinition


class InputGateResult(BaseModel):
    passed: bool
    gate_id: str
    detail: str


class EffectiveDecision(BaseModel):
    decision: Decision
    matched_rule_ids: list[str]
    reason: str
    evaluation_stage: Literal["schema_validation", "policy"]
    policy_evaluated: bool


def _gate_id(tool_name: str) -> str:
    return f"validate-{tool_name.replace('_', '-')}-schema"


def validate_action_input(
    schema: dict[str, Any],
    expected_tool: str,
    context: dict[str, Any],
) -> InputGateResult:
    gate_id = _gate_id(expected_tool)
    try:
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
    except SchemaError as exc:
        raise ValueError(
            f"{expected_tool}: reviewed tool schema is invalid: {exc.message}"
        ) from exc

    action = context.get("action")
    if not isinstance(action, dict):
        return InputGateResult(
            passed=False,
            gate_id=gate_id,
            detail="action must be an object",
        )
    if action.get("tool") != expected_tool:
        return InputGateResult(
            passed=False,
            gate_id=gate_id,
            detail=f"action.tool must equal {expected_tool!r}",
        )
    arguments = action.get("arguments")
    if not isinstance(arguments, dict):
        return InputGateResult(
            passed=False,
            gate_id=gate_id,
            detail="action.arguments must be an object",
        )

    errors = sorted(validator.iter_errors(arguments), key=lambda item: list(item.path))
    if errors:
        detail = "; ".join(
            f"{'.'.join(str(part) for part in error.path) or '<arguments>'}: "
            f"{error.message}"
            for error in errors
        )
        return InputGateResult(
            passed=False,
            gate_id=gate_id,
            detail=detail,
        )
    return InputGateResult(
        passed=True,
        gate_id=gate_id,
        detail="action input matches the reviewed tool schema",
    )


def validate_project_action_input(
    project: ProjectDefinition,
    target_tool: str,
    context: dict[str, Any],
) -> InputGateResult:
    tool = next(
        (item for item in project.tools if item.name == target_tool),
        None,
    )
    if tool is None:
        raise ValueError(f"project has no tool named {target_tool}")
    return validate_action_input(tool.input_schema, target_tool, context)


def evaluate_effective_policy(
    project: ProjectDefinition,
    target_tool: str,
    policy: CanonicalPolicy,
    context: dict[str, Any],
) -> EffectiveDecision:
    gate = validate_project_action_input(project, target_tool, context)
    if not gate.passed:
        return EffectiveDecision(
            decision="deny",
            matched_rule_ids=[gate.gate_id],
            reason=f"Blocked by generated schema gate: {gate.detail}",
            evaluation_stage="schema_validation",
            policy_evaluated=False,
        )
    decision = evaluate_policy(policy, context)
    return EffectiveDecision(
        decision=decision.decision,
        matched_rule_ids=decision.matched_rule_ids,
        reason=decision.reason,
        evaluation_stage="policy",
        policy_evaluated=True,
    )

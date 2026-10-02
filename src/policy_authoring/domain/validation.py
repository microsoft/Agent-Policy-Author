# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import annotations

from dataclasses import dataclass

from policy_authoring.domain.models import (
    CanonicalPolicy,
    Condition,
    PolicyTestCase,
    ProjectDefinition,
)


@dataclass(frozen=True)
class ValidationIssue:
    rule_id: str
    path: str
    message: str


def _condition_paths(condition: Condition) -> list[str]:
    paths = []
    if condition.left is not None and condition.left.path is not None:
        paths.append(condition.left.path)
    if condition.right is not None and condition.right.path is not None:
        paths.append(condition.right.path)
    for child in condition.conditions:
        paths.extend(_condition_paths(child))
    return paths


def validate_policy(
    policy: CanonicalPolicy,
    project: ProjectDefinition,
) -> list[ValidationIssue]:
    tools = {tool.name: tool for tool in project.tools}
    if policy.tool not in tools:
        return [
            ValidationIssue(
                rule_id="<policy>",
                path="tool",
                message=f"tool {policy.tool!r} is not registered",
            )
        ]
    tool = tools[policy.tool]
    if policy.tool_schema_version != tool.schema_version:
        return [
            ValidationIssue(
                rule_id="<policy>",
                path="tool_schema_version",
                message=(
                    f"policy expects {policy.tool_schema_version!r}, "
                    f"registered schema is {tool.schema_version!r}"
                ),
            )
        ]

    arguments = set(tool.input_schema.get("properties", {}))
    context = {item.path: item for item in project.context.attributes}
    issues: list[ValidationIssue] = []
    for rule in policy.rules:
        for path in _condition_paths(rule.condition):
            if path.startswith("action.arguments."):
                argument = path.removeprefix("action.arguments.").split(".")[0]
                if argument not in arguments:
                    issues.append(
                        ValidationIssue(
                            rule_id=rule.id,
                            path=path,
                            message=f"tool argument {argument!r} is not declared",
                        )
                    )
                continue
            if path.startswith(("principal.", "resource.")):
                continue
            attribute = context.get(path)
            if attribute is None:
                issues.append(
                    ValidationIssue(
                        rule_id=rule.id,
                        path=path,
                        message="path is not declared by the context contract",
                    )
                )
            elif attribute.trust in {"model_provided", "untrusted"}:
                issues.append(
                    ValidationIssue(
                        rule_id=rule.id,
                        path=path,
                        message=(
                            f"security rule cannot rely on {attribute.trust} data"
                        ),
                    )
                )
    return issues


def require_valid_policy(
    policy: CanonicalPolicy,
    project: ProjectDefinition,
) -> None:
    issues = validate_policy(policy, project)
    if issues:
        details = "; ".join(
            f"{item.rule_id}:{item.path}: {item.message}" for item in issues
        )
        raise ValueError(f"policy validation failed: {details}")


def require_unique_test_ids(cases: list[PolicyTestCase]) -> None:
    seen: set[str] = set()
    duplicates: list[str] = []
    for case in cases:
        if case.id in seen and case.id not in duplicates:
            duplicates.append(case.id)
        seen.add(case.id)
    if duplicates:
        raise ValueError(f"duplicate policy test id: {', '.join(duplicates)}")
